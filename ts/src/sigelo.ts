/**
 * sigelo v0.1 (wire `sigelo/0`) — portable agent identity.
 *
 * Public API is five functions: keygen, attest, bind, rotate, verify. Recovery is
 * `rotate({ reason: 'recovery' })` with the recovery key, not a sixth function.
 *
 * `verify` follows SPEC §9 step by step, in order, with the same names. Nothing in the
 * verification path reads a clock or the network: `now` is a parameter and everything a
 * verifier needs is inside the bundle (SPEC §1.1).
 */
import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize, JcsError, parse, parseBytes } from './jcs.js';
import { verifySigeloMoneroSigAddr } from './monero.js';

// @noble/ed25519 v3 keeps the synchronous API behind an injected hash so the package can stay
// dependency-free. One suite, no agility (SPEC §2), so this is set once, here.
ed.hashes.sha512 = sha512;

export { canonicalize, parse, parseBytes };

export const VERSION = 'sigelo/0';
const PREFIX = utf8ToBytes('sigelo\n'); // domain separation (SPEC §3, THREAT-MODEL §2.5c)
const MULTICODEC_ED25519_PUB = Uint8Array.from([0xed, 0x01]);
const ADMISSION = ['open', 'captcha', 'invite', 'payment', 'human', 'stake'] as const;
const COMMITMENT = /^sha256:[0-9a-f]{64}$/; // a recovery commitment, as it appears in a genesis
const NONCE = /^z[1-9A-HJ-NP-Za-km-z]{1,63}$/; // §2: z + base58btc, at most 64 characters

export type Admission = (typeof ADMISSION)[number];
export type Proof = 'proven' | 'unproven' | 'unsupported';
export type Reason = 'voluntary' | 'recovery';

export interface Genesis { v: string; typ: 'genesis'; key: string; recovery: string | null; created: string; nonce: string }
export interface RotationBody { v: string; typ: 'rotation'; id: string; next: string; iat: number; reason: Reason; recovery_key?: string }
export interface AttestationBody {
  v: string; typ: 'attestation'; iss: string; sub: string; iat: number; exp: number; ctx: string;
  admission: Admission; admission_by?: string; admission_cost?: string; claims: Record<string, unknown>;
}
export interface ChallengeBody { v: string; typ: 'challenge'; did: string; ctx: string; nonce: string }
export interface BindingBody { v: string; typ: 'binding'; id: string; method: string; addr: string; iat: number; exp: number; nonce: string }
export interface Rotation { body: RotationBody; sig: string; next_genesis: Genesis }
export interface Attestation { body: AttestationBody; sig: string }
export interface Challenge { body: ChallengeBody; sig: string }
export interface Binding { body: BindingBody; sig_id: string; sig_addr?: string }
export interface Bundle {
  v: string; typ: 'bundle'; genesis: Genesis;
  rotations: Rotation[]; bindings: Binding[]; attestations: Attestation[]; issuers: Genesis[];
}
export interface VerifyResult {
  did: string; chain: string[]; recovery: string | null;
  attestations: Record<string, AttestationBody[]>;
  bindings: { body: BindingBody; proof: Proof }[];
  rejected: { attestations: number; bindings: number };
}

/** Every fatal failure. The message names the check that failed, never "invalid input". */
export class SigeloError extends Error {
  override readonly name = 'SigeloError';
}

// ---------------------------------------------------------------- base58btc / multibase

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function b58encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++; // leading zero bytes become '1's
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) { const x = digits[j]! * 256 + carry; digits[j] = x % 58; carry = (x / 58) | 0; }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  return '1'.repeat(zeros) + digits.reverse().map((d) => B58[d]).join('');
}

/**
 * SPEC §2 length bounds on a multibase value, `z` included, checked BEFORE decoding: base58
 * decoding is quadratic in the length, and a 300 000-character signature took three minutes
 * here (over one in Go). 34 bytes spell at most 47 base58 digits and 64 bytes at most 88; the
 * bounds leave a margin and are the same in go/primitives.go.
 */
const MAX_KEY_CHARS = 64, MAX_SIG_CHARS = 100;

/** Only called on a string unmb has checked: every character a digit, the length bounded. */
function b58decode(s: string): Uint8Array {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  const bytes: number[] = [];
  for (const ch of s.slice(zeros)) {
    let carry = B58.indexOf(ch);
    for (let j = 0; j < bytes.length; j++) { const x = bytes[j]! * 58 + carry; bytes[j] = x & 0xff; carry = x >> 8; }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  return Uint8Array.from([...new Uint8Array(zeros), ...bytes.reverse()]);
}

const mb = (b: Uint8Array): string => 'z' + b58encode(b);

/** Multibase base58btc of at most `max` characters. The alphabet first (linear, and it makes the length ASCII in both implementations). */
function unmb(s: unknown, max: number): Uint8Array {
  if (typeof s !== 'string' || s[0] !== 'z') throw new SigeloError('multibase: not base58btc (expected a leading "z")');
  for (const ch of s.slice(1)) if (!B58.includes(ch)) throw new SigeloError(`multibase: ${JSON.stringify(ch)} is not a base58btc digit`);
  if (s.length > max) throw new SigeloError(`multibase: longer than ${max} characters`);
  return b58decode(s.slice(1));
}

/** multicodec 0xed01 + 32 raw bytes, multibase `z` (SPEC §2). */
/** `z` + base58btc of any bytes: the multibase form SPEC §2 uses for nonces. */
export function multibase(bytes: Uint8Array): string { return 'z' + b58encode(bytes); }

export function encodeKey(raw: Uint8Array): string {
  if (raw.length !== 32) throw new SigeloError(`key: expected 32 raw bytes, got ${raw.length}`);
  return mb(concatBytes(MULTICODEC_ED25519_PUB, raw));
}

/** Inverse of encodeKey. Throws unless the multicodec prefix and length are exact. */
export function decodeKey(key: unknown): Uint8Array {
  const b = unmb(key, MAX_KEY_CHARS);
  if (b.length !== 34 || b[0] !== 0xed || b[1] !== 0x01) throw new SigeloError('key: not multicodec ed25519-pub');
  return b.slice(2);
}

/**
 * decodeKey plus SPEC §2's point rule, for the slots that hold a public key (§3.1: genesis
 * `key`, rotation `recovery_key`, an `ed25519-test` binding's `addr`): the canonical encoding
 * of a curve point that is not of small order — the keys verify() with zip215:false could ever
 * accept a signature under. All-zero, the identity, y ≥ p and x = 0 with the sign bit fail
 * here, by the same rule as go/primitives.go `publicKey`.
 */
function publicKey(key: unknown): void {
  const raw = decodeKey(key);
  let ok: boolean;
  try { ok = !ed.Point.fromBytes(raw, false).isSmallOrder(); } catch { ok = false; }
  if (!ok) throw new SigeloError('key: not a valid Ed25519 point (non-canonical, off the curve or of small order)');
}

// ---------------------------------------------------------------- primitives

/** `"sigelo\n" || JCS(body)` — the bytes every sigelo signature covers (SPEC §3). */
export function signingInput(body: unknown): Uint8Array {
  return concatBytes(PREFIX, utf8ToBytes(canonicalize(body)));
}

/** `did:sigelo:` + multibase SHA-256 of the canonical genesis (SPEC §4). */
export function did(genesis: unknown): string {
  return 'did:sigelo:' + mb(sha256(utf8ToBytes(canonicalize(genesis))));
}

/** Detached signature over the §3 signing input, multibase. `secret` is the 32-byte seed. */
export function sign(secret: Uint8Array, body: unknown): string {
  return mb(ed.sign(signingInput(body), secret));
}

/** Verify a detached signature by the multibase public key. Never throws; malformed is false. */
export function verifySig(key: unknown, body: unknown, sig: unknown): boolean {
  try {
    // zip215:false selects the RFC 8032 branch, the suite SPEC §2 names.
    return ed.verify(unmb(sig, MAX_SIG_CHARS), signingInput(body), decodeKey(key), { zip215: false });
  } catch {
    return false;
  }
}

/** `sha256:` + hex of the RAW 32-byte recovery public key (SPEC §4). */
export function commitmentOf(key: string): string {
  return 'sha256:' + bytesToHex(sha256(decodeKey(key)));
}

// ---------------------------------------------------------------- §9 step 2: structure

type Slot = 'genesis' | 'rotation' | 'binding' | 'attestation' | 'challenge' | 'invoice' | 'bundle';

const REQUIRED: Record<Slot, string[]> = {
  genesis: ['v', 'typ', 'key', 'recovery', 'created', 'nonce'],
  rotation: ['v', 'typ', 'id', 'next', 'iat', 'reason'],
  binding: ['v', 'typ', 'id', 'method', 'addr', 'iat', 'exp', 'nonce'],
  attestation: ['v', 'typ', 'iss', 'sub', 'iat', 'exp', 'ctx', 'admission', 'claims'],
  challenge: ['v', 'typ', 'did', 'ctx', 'nonce'], // §5.2 — never a bundle slot
  invoice: ['v', 'typ', 'did', 'method', 'addr', 'iat', 'exp', 'nonce'], // §6.3 — never a bundle slot either
  bundle: ['v', 'typ', 'genesis', 'rotations', 'bindings', 'attestations', 'issuers'],
};
/** §3.1: the only keys beyond REQUIRED a body may carry. Everything else is malformed. */
const OPTIONAL: Record<Slot, string[]> = {
  genesis: [], rotation: ['recovery_key'], binding: [],
  attestation: ['admission_by', 'admission_cost'], challenge: [],
  // §6.3: `amount` is a STRING of atomic units — a float here would break cross-language JCS.
  invoice: ['amount', 'memo'], bundle: [],
};
/**
 * §3.1 field types. `iat`/`exp` are integer Unix seconds; every other field is a string except
 * these, which have their own checks (or, for `claims`, none). Without this, JS comparison
 * coercion let `iat: "5"` or `iat: null` verify here while Python raised on the same bytes.
 */
const NOT_STRING = ['iat', 'exp', 'recovery', 'claims', 'amount', 'genesis', 'rotations', 'bindings', 'attestations', 'issuers'];
/** §3.1: an envelope is exactly these members. Nothing outside `body` is signed, so an extra one is data no signature covers. */
const ENVELOPE: Partial<Record<Slot, string[]>> = { rotation: ['body', 'sig', 'next_genesis'], binding: ['body', 'sig_id', 'sig_addr'], attestation: ['body', 'sig'] };
function envelope(env: object, slot: Slot): void {
  for (const f of Object.keys(env)) if (!ENVELOPE[slot]!.includes(f)) throw new SigeloError(`${slot}: unknown envelope field ${JSON.stringify(f)}`);
}

/**
 * SPEC §9 step 2 for one body. Canonicalizing it is itself the float / out-of-range check,
 * so it is done first and its error is reported under the slot.
 */
export function structure(body: unknown, slot: Slot): void {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new SigeloError(`${slot}: body is not an object`);
  const b = body as Record<string, unknown>;
  try {
    // A bundle's attestations and bindings are canonicalized one by one in verify(): a float
    // or lone surrogate inside one is that item's fault, not the identity's (invariant 7).
    canonicalize(slot === 'bundle' ? { ...b, attestations: [], bindings: [] } : b);
  } catch (e) {
    throw new SigeloError(`${slot}: ${e instanceof JcsError ? e.message : String(e)}`);
  }
  for (const f of REQUIRED[slot]) if (!(f in b)) throw new SigeloError(`${slot}: missing ${f}`);
  // §3.1: no other top-level keys. An unknown field is data nobody agreed to sign over, and
  // the next implementation may treat it as meaningful; there is no safe way to ignore it.
  for (const f of Object.keys(b)) if (!REQUIRED[slot].includes(f) && !OPTIONAL[slot].includes(f)) throw new SigeloError(`${slot}: unknown field ${JSON.stringify(f)}`);
  if (b['v'] !== VERSION) throw new SigeloError(`${slot}: unknown v ${JSON.stringify(b['v'])}`);
  if (b['typ'] !== slot) throw new SigeloError(`${slot}: typ is ${JSON.stringify(b['typ'])}`);
  for (const [f, x] of Object.entries(b)) {
    if ((f === 'iat' || f === 'exp') && !(Number.isSafeInteger(x) && (x as number) >= 0)) throw new SigeloError(`${slot}: ${f} is not a non-negative integer`);
    if (!NOT_STRING.includes(f) && typeof x !== 'string') throw new SigeloError(`${slot}: ${f} is not a string`);
  }
  if ('exp' in b && !((b['exp'] as number) > (b['iat'] as number))) throw new SigeloError(`${slot}: exp is not after iat`);
  // §2: a nonce is z + base58btc, at most 64 characters — except §5.2's, the world's to choose.
  if ('nonce' in b && slot !== 'challenge' && !NONCE.test(b['nonce'] as string)) throw new SigeloError(`${slot}: nonce is not z + base58btc (at most 64 characters)`);
  if (slot === 'genesis') {
    publicKey(b['key']); // fail closed on a key that is not multicodec ed25519-pub, or no usable point
    const rec = b['recovery'];
    // §4: exactly sha256: + 64 lowercase hex. A prefix check let "sha256:", "sha256:xyz" and
    // UPPERCASE hex through — a commitment nothing hashes to, which silently disables recovery.
    if (rec !== null && !(typeof rec === 'string' && COMMITMENT.test(rec))) throw new SigeloError('genesis: recovery is neither null nor sha256: + 64 lowercase hex');
    if (!isRFC3339UTC(b['created'] as string)) throw new SigeloError('genesis: created is not RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)');
  }
  if (slot === 'rotation') {
    if (b['reason'] !== 'voluntary' && b['reason'] !== 'recovery') throw new SigeloError('rotation: unknown reason');
    if ((b['reason'] === 'recovery') !== ('recovery_key' in b)) throw new SigeloError('rotation: recovery_key present iff reason is recovery');
    if ('recovery_key' in b) publicKey(b['recovery_key']);
    if (b['next'] === b['id']) throw new SigeloError('rotation: next == id');
  }
  if (slot === 'binding' && b['method'] === 'ed25519-test') publicKey(b['addr']); // §6.1a: addr is a public key
  if (slot === 'attestation' && !(ADMISSION as readonly string[]).includes(b['admission'] as string)) throw new SigeloError(`attestation: unknown admission ${JSON.stringify(b['admission'])}`);
  // §3.1 / §6.3: `amount` is a STRING of atomic units. A JSON number would be a float in some
  // language's parser (§3 forbids those in signed objects); "0.15" and "-1" are not atomic
  // units at all. The canonicalizer cannot catch either, because both are legal JSON strings.
  if (slot === 'invoice' && 'amount' in b && !(typeof b['amount'] === 'string' && /^(0|[1-9][0-9]*)$/.test(b['amount'])))
    throw new SigeloError(`invoice: amount is not a decimal string of atomic units ${JSON.stringify(b['amount'])}`);
  if (slot === 'bundle') {
    for (const a of ['rotations', 'bindings', 'attestations', 'issuers']) if (!Array.isArray(b[a])) throw new SigeloError(`bundle: ${a} is not an array`);
  }
}

/**
 * SPEC §4's `created`: exactly YYYY-MM-DDTHH:MM:SSZ, a real Gregorian date, seconds 00–59 (no
 * leap second: no clock can check one), no fraction, no offset, uppercase T and Z. The same
 * check as go/primitives.go `isRFC3339UTC`. `Date.parse` is not it: it accepts offsets,
 * fractions and (engine-dependent) much else.
 */
function isRFC3339UTC(s: string): boolean {
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/.exec(s);
  if (m === null) return false;
  const [y, mo, d, h, mi, se] = m.slice(1).map(Number) as [number, number, number, number, number, number];
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return false;
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  return d <= (mo === 2 && leap ? 29 : [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]!);
}

// ---------------------------------------------------------------- §7.3 chain

/**
 * Walk the chain from the original genesis (SPEC §7.3). Returns the ordered DIDs and the
 * governing recovery commitment (§7.2: the one in the most recent recovery-signed genesis).
 */
function resolveChain(g0: Genesis, rotations: Rotation[]): { chain: string[]; recovery: string | null } {
  let cur = did(g0);
  const chain = [cur];
  const genesisOf = new Map<string, Genesis>([[cur, g0]]);
  for (const r of rotations) genesisOf.set(did(r.next_genesis), r.next_genesis);
  let commitment = g0.recovery;
  for (;;) {
    const candidates = rotations.filter((r) => r.body.id === cur); // 1
    const recovery = candidates.filter((r) => r.body.reason === 'recovery' && commitment !== null && // 2
      commitmentOf(r.body.recovery_key!) === commitment && verifySig(r.body.recovery_key, r.body, r.sig) &&
      did(r.next_genesis) === r.body.next);
    // §7: a voluntary rotation MUST carry the commitment forward unchanged (last clause). That
    // is what stops a thief with the hot key from installing a recovery key of their own.
    const voluntary = candidates.filter((r) => r.body.reason === 'voluntary' &&                       // 3
      verifySig(genesisOf.get(cur)!.key, r.body, r.sig) && did(r.next_genesis) === r.body.next &&
      r.next_genesis.recovery === commitment);
    let chosen: Rotation;
    if (recovery.length) {
      // §7.1 precedence. This looks wrong — it ignores `iat`, and the voluntary rotation may
      // be newer and perfectly valid — which is exactly the point: a thief can produce a
      // valid voluntary rotation, and only the operator's offline key can produce this one.
      // Ordering by timestamp would hand the identity to whoever signed last.
      // A loop, not a Math.max spread over the list: a spread passes every element as an argument, and V8
      // throws RangeError past ~125 000 of them — a crash naming no check, where go/ answers.
      let top = 0;
      for (const r of recovery) if (r.body.iat > top) top = r.body.iat;
      // Two recoveries at the same latest iat: the operator controls both, so there is no
      // rule that picks one. Operator error, and the fix is to reissue (§7.3 step 2, §7.4).
      if (recovery.filter((r) => r.body.iat === top).length > 1) throw new SigeloError(`chain: recovery tie at ${cur} (two valid recovery rotations share iat ${top})`);
      chosen = recovery.find((r) => r.body.iat === top)!;
      commitment = chosen.next_genesis.recovery; // §7.2: only a recovery may change it
    } else if (voluntary.length === 1) {
      chosen = voluntary[0]!;
    } else if (voluntary.length > 1) {
      // 3: a fork under one key is a compromise signal. The verifier does not pick a side.
      throw new SigeloError(`chain: fork at ${cur} (${voluntary.length} valid voluntary rotations)`);
    } else {
      return { chain, recovery: commitment }; // 4
    }
    // 5: a `next` already in the chain is a cycle. Only a key holder can produce one, it has
    // no legitimate meaning, and following it would hang the verifier — so reject, never loop.
    if (chain.includes(chosen.body.next)) throw new SigeloError(`chain: cycle back to ${chosen.body.next}`);
    cur = chosen.body.next;
    chain.push(cur);
  }
}

// ---------------------------------------------------------------- §9 verify

/** Indices whose envelope, body or signature slot is malformed — per-item, never fatal (§9 step 2). */
function malformed(items: readonly unknown[], slot: Slot, sigField: 'sig' | 'sig_id'): Set<number> {
  const bad = new Set<number>();
  items.forEach((it, i) => {
    const env = it as Record<string, unknown> | null | undefined; // envelope, possibly junk
    try {
      canonicalize(env); // the whole envelope: a float or lone surrogate anywhere discards the item
      structure(env?.['body'], slot);
      if (typeof env![sigField] !== 'string') throw new SigeloError(`${slot}: missing ${sigField}`);
      envelope(env!, slot);
    } catch (e) {
      if (!(e instanceof SigeloError || e instanceof JcsError)) throw e;
      bad.add(i);
    }
  });
  return bad;
}

/**
 * SPEC §9. Returns the §9.1 result. Throws SigeloError on a structural failure, a fork or a
 * cycle — those are fatal to the whole bundle. Signature, expiry and membership failures on
 * individual attestations and bindings are counted in `rejected`, not thrown.
 */
export function verify(bundle: Bundle, now: number, knownIssuers?: Record<string, Genesis>): VerifyResult {
  // 1. Genesis
  structure(bundle?.genesis, 'genesis');
  const d0 = did(bundle.genesis);
  // 2. Structure
  structure(bundle, 'bundle');
  for (const r of bundle.rotations) {
    structure(r?.body, 'rotation');
    // §3.1: the envelope is part of the same rule, and a rotation defines the identity, so a
    // missing half is fatal rather than per-item.
    if (r.next_genesis === undefined) throw new SigeloError('rotation: missing next_genesis');
    structure(r.next_genesis, 'genesis');
    if (typeof r.sig !== 'string') throw new SigeloError('rotation: missing sig');
    envelope(r, 'rotation');
  }
  for (const g of bundle.issuers) structure(g, 'genesis');
  // Everything above defines the identity, so malformation there is fatal. An attestation or
  // binding body is written by an issuer or a counterparty, not by the identity: a malformed
  // one is discarded and counted in `rejected`, exactly as a bad signature would be. One
  // world's bug must not sink its members' bundles (§9 step 2).
  const badAttestations = malformed(bundle.attestations, 'attestation', 'sig');
  const badBindings = malformed(bundle.bindings, 'binding', 'sig_id');
  // 3. Chain
  const { chain, recovery } = resolveChain(bundle.genesis, bundle.rotations);
  const genesisOf = new Map<string, Genesis>([[d0, bundle.genesis]]);
  for (const r of bundle.rotations) genesisOf.set(did(r.next_genesis), r.next_genesis);
  // 4. Issuers — derived by hashing, so no key/value pair can disagree (SPEC §8). A locally
  // known genesis wins over the presented copy; honest copies are identical anyway.
  const issuers = new Map<string, Genesis>();
  for (const [k, g] of Object.entries(knownIssuers ?? {})) issuers.set(k, g);
  for (const g of bundle.issuers) if (!issuers.has(did(g))) issuers.set(did(g), g);
  // 5. Attestations — discarded individually; one bad attestation does not sink a bundle.
  const attestations: Record<string, AttestationBody[]> = {};
  let rejectedAttestations = 0;
  for (const [i, a] of bundle.attestations.entries()) {
    const body = a?.body; // may be malformed: everything below is guarded by badAttestations
    const iss = issuers.get(body?.iss);
    if (badAttestations.has(i) || iss === undefined || !verifySig(iss.key, body, a.sig) ||
        !(body.iat <= now && now < body.exp) || !chain.includes(body.sub)) {
      rejectedAttestations++;
    } else {
      (attestations[body.iss] ??= []).push(body); // grouped by iss, in bundle order (§9.1)
    }
  }
  // 6. Bindings
  const bindings: { body: BindingBody; proof: Proof }[] = [];
  let rejectedBindings = 0;
  for (const [i, b] of bundle.bindings.entries()) {
    const body = b?.body; // as above: guarded by badBindings (so is `b` itself: it may be null)
    const g = genesisOf.get(body?.id);
    if (badBindings.has(i) || g === undefined || !chain.includes(body.id) || !verifySig(g.key, body, b.sig_id) ||
        !(body.iat <= now && now < body.exp)) {
      rejectedBindings++;
      continue;
    }
    const { sig_addr } = b;
    let proof: Proof;
    if (sig_addr === undefined) proof = 'unproven';       // a claim only — MUST NOT be paid
    else if (body.method !== 'ed25519-test' && body.method !== 'monero') proof = 'unsupported'; // no routine (§6.2)
    // §6.2: `monero` is not Ed25519 — a SigV2 wallet signature over the same §3 signing
    // input, verified by Monero's own routine against the binding's own `addr`.
    else if (body.method === 'monero' ? verifySigeloMoneroSigAddr(body, body.addr, sig_addr).good
      : verifySig(body.addr, body, sig_addr)) proof = 'proven';
    else {
      rejectedBindings++; // §6.1: a bad proof is not the same thing as no proof
      continue;
    }
    bindings.push({ body, proof });
  }
  // 7. Return. No scores, no ranking — weighting is the caller's job.
  return { did: chain[chain.length - 1]!, chain, recovery, attestations, bindings,
    rejected: { attestations: rejectedAttestations, bindings: rejectedBindings } };
}

// ---------------------------------------------------------------- constructors

const rfc3339 = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
/** A caller-supplied nonce (raw bytes or multibase), else `len` fresh random bytes. */
const asNonce = (n: Uint8Array | string | undefined, len: number): string =>
  n === undefined ? mb(randomBytes(len)) : typeof n === 'string' ? n : mb(n);

export interface Identity { did: string; genesis: Genesis; secret: Uint8Array; key: string }

/**
 * Generate an identity (SPEC §4). `recovery` is the recovery PUBLIC key — raw 32 bytes or
 * multibase — or an existing `sha256:<hex>` commitment, used verbatim: only the hash is ever
 * public (§4), so a runtime that holds a commitment and no public half can still build the
 * next_genesis for a voluntary rotation. Generate the key offline; a recovery key
 * living in the same process as the identity key protects nothing (THREAT-MODEL §5).
 * `seed`, `created` and `nonce` are accepted so a document can be reproduced exactly.
 */
export function keygen(opts: {
  recovery: Uint8Array | string | null; seed?: Uint8Array; created?: string; nonce?: Uint8Array | string;
} = { recovery: null }): Identity {
  if (opts.recovery === null) {
    console.warn('\n*** sigelo: keygen with recovery: null ***\n' +
      'This identity has NO recovery key. If the identity key is stolen — and it lives in a\n' +
      'process that reads untrusted text all day — the identity is lost PERMANENTLY. There is\n' +
      'no reset, no support, no appeal. Generate a recovery key offline and pass its public\n' +
      'key. Worlds MAY refuse attestations to identities with recovery: null.\n');
  }
  const secret = opts.seed ?? randomBytes(32);
  if (secret.length !== 32) throw new SigeloError(`keygen: seed must be 32 bytes, got ${secret.length}`);
  const genesis: Genesis = {
    v: VERSION, typ: 'genesis', key: encodeKey(ed.getPublicKey(secret)),
    // Only the HASH of the recovery key is public until it is used (SPEC §4), so a caller may
    // pass the commitment itself; any other string must still decode as a multibase key.
    recovery: opts.recovery === null ? null
      : typeof opts.recovery === 'string' && COMMITMENT.test(opts.recovery) ? opts.recovery
        : 'sha256:' + bytesToHex(sha256(typeof opts.recovery === 'string' ? decodeKey(opts.recovery) : opts.recovery)),
    created: opts.created ?? rfc3339(Date.now()), nonce: asNonce(opts.nonce, 16),
  };
  structure(genesis, 'genesis');
  return { did: did(genesis), genesis, secret, key: genesis.key };
}

/** One world's signed statement about one identity (SPEC §5). `claims` is world-defined. */
export function attest(opts: {
  secret: Uint8Array; iss: string; sub: string; iat: number; exp: number; ctx: string;
  admission: Admission; admission_by?: string; admission_cost?: string;
  claims: Record<string, unknown>;
}): Attestation {
  const body: AttestationBody = {
    v: VERSION, typ: 'attestation', iss: opts.iss, sub: opts.sub, iat: opts.iat, exp: opts.exp,
    ctx: opts.ctx, admission: opts.admission, claims: opts.claims,
    ...(opts.admission_by !== undefined && { admission_by: opts.admission_by }),
    ...(opts.admission_cost !== undefined && { admission_cost: opts.admission_cost }),
  };
  structure(body, 'attestation');
  return { body, sig: sign(opts.secret, body) };
}

/**
 * Bind a payment address to an identity (SPEC §6). Cross-signed: `sig_addr` must come from
 * the payment key over the identical signing input. `addr_secret` is only usable for
 * `ed25519-test`; a real wallet signature is passed in as `sig_addr`. Omitting both yields an
 * `unproven` binding — verifiers MUST NOT send funds to one.
 */
export function bind(opts: {
  secret: Uint8Array; id: string; method: string; addr: string; iat: number; exp: number;
  nonce?: Uint8Array | string; addr_secret?: Uint8Array; sig_addr?: string;
}): Binding {
  const body: BindingBody = {
    v: VERSION, typ: 'binding', id: opts.id, method: opts.method, addr: opts.addr,
    iat: opts.iat, exp: opts.exp,
    nonce: asNonce(opts.nonce, 16),
  };
  structure(body, 'binding');
  if (opts.addr_secret !== undefined && opts.method !== 'ed25519-test') throw new SigeloError(`bind: cannot sign addr for method ${JSON.stringify(opts.method)}`);
  const sig_addr = opts.addr_secret === undefined ? opts.sig_addr : sign(opts.addr_secret, body);
  return { body, sig_id: sign(opts.secret, body), ...(sig_addr !== undefined ? { sig_addr } : {}) };
}

/**
 * Rotate to a new genesis (SPEC §7). `reason: 'voluntary'` is signed by the current identity
 * key; `reason: 'recovery'` is signed by the recovery key, whose public half must hash to the
 * current commitment. Both `id` and `next` are derived by hashing the documents, so the
 * envelope cannot disagree with them.
 *
 * The commitment checked here is `genesis.recovery` of the node being rotated from, which is
 * the governing one: voluntary rotations carry it forward unchanged and only a recovery
 * rotation writes a new one, so the current node's genesis always holds it (§7.2).
 */
export function rotate(opts: {
  genesis: Genesis; next_genesis: Genesis; iat: number; reason: Reason; secret: Uint8Array;
}): Rotation {
  structure(opts.genesis, 'genesis');
  structure(opts.next_genesis, 'genesis');
  const id = did(opts.genesis);
  const next = did(opts.next_genesis);
  if (next === id) throw new SigeloError('rotation: next == id');
  const head = { v: VERSION, typ: 'rotation', id, next, iat: opts.iat } as const;
  let body: RotationBody;
  if (opts.reason === 'recovery') {
    const recovery_key = encodeKey(ed.getPublicKey(opts.secret));
    if (opts.genesis.recovery === null) throw new SigeloError('rotation: identity has no recovery commitment');
    if (commitmentOf(recovery_key) !== opts.genesis.recovery) throw new SigeloError('rotation: recovery_key does not hash to the current commitment');
    body = { ...head, reason: 'recovery', recovery_key };
  } else {
    if (opts.next_genesis.recovery !== opts.genesis.recovery) throw new SigeloError('rotation: voluntary rotation changes the recovery commitment');
    body = { ...head, reason: 'voluntary' };
  }
  structure(body, 'rotation');
  return { body, sig: sign(opts.secret, body), next_genesis: opts.next_genesis };
}

/**
 * Proof of control (SPEC §5.2). The world chooses `ctx` and `nonce`; `did` is taken from the
 * genesis handed in, so an agent library MUST only ever pass its own genesis — §5.2 says a
 * library should refuse to sign a challenge for someone else's DID, and taking the DID from
 * the document it signs with is how that refusal is enforced here. `typ: "challenge"` is
 * inside the signed bytes and no bundle slot accepts it, so the signature cannot be replayed
 * as an attestation, binding or rotation.
 */
export function challenge(opts: { secret: Uint8Array; genesis: Genesis; ctx: string; nonce: Uint8Array | string }): Challenge {
  structure(opts.genesis, 'genesis');
  if (encodeKey(ed.getPublicKey(opts.secret)) !== opts.genesis.key) throw new SigeloError('challenge: secret does not match genesis.key');
  const body: ChallengeBody = {
    v: VERSION, typ: 'challenge', did: did(opts.genesis), ctx: opts.ctx, nonce: asNonce(opts.nonce, 16),
  };
  structure(body, 'challenge');
  return { body, sig: sign(opts.secret, body) };
}
