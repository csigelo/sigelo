/**
 * Regenerates `../test-vectors.json` from the documented seeds, byte-for-byte.
 *
 *   node dist/gen_vectors.js                      JSON to stdout
 *   node dist/gen_vectors.js ../test-vectors.json write the file in place
 *
 * This is the only vector generator (a port of the original Python one, since removed; the
 * file format below is the one that generator fixed). CI diffs its output against the committed
 * file. Read it as documentation: every vector below is
 * built exactly the way a conforming implementation would build it, from fixed seeds, fixed
 * genesis nonces and fixed Monero signing nonces. Ed25519 is deterministic, so everything
 * else follows.
 *
 * Byte identity rests on three things a port to another language must reproduce:
 *  1. Key ORDER is insertion order, everywhere. `{ ...x, k: v }` (Python `dict(x, k=v)`) keeps
 *     `k` where it already was in `x` and appends it only if new. The top-level
 *     `monero_spend_seed` lands AFTER `negative` because it is set after the object is built.
 *  2. The output is `JSON.stringify(out, null, 2)` with NO trailing newline — what Python's
 *     `json.dump(indent=2, ensure_ascii=False)` writes. Non-ASCII (é, ～, U+2028, 🙂), `<>&`
 *     and U+007F go out raw; only `"`, `\` and C0 controls are escaped.
 *  3. A value holding a lone surrogate cannot be written to a UTF-8 file, so it travels as a
 *     `raw` string: compact JSON with every non-ASCII code unit and U+007F escaped as
 *     lowercase `\uXXXX` (Python `json.dumps(separators=(',', ':'))`, ensure_ascii on).
 */
import * as ed from '@noble/ed25519';
import { Point } from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { writeFileSync } from 'node:fs';
import { canonicalize, JcsError } from './jcs.js';
import {
  encodeAddress, hashToScalar, keccak256, keysFromSpend, moneroBase58Encode, scReduce32,
  sigeloMoneroSigAddr, subaddress, subaddressKeys,
} from './monero.js';
import { commitmentOf, did, encodeKey, sign, signingInput } from './sigelo.js';

type J = any; // the vectors file is heterogeneous JSON by design

// ---------------------------------------------------------------- encodings

const hex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
/** base58btc (Bitcoin alphabet, leading zero bytes -> '1'), multibase prefix `z`. */
function mb(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  let zeros = 0;
  while (zeros < b.length && b[zeros] === 0) zeros++;
  return 'z' + '1'.repeat(zeros) + s;
}
const MC = Uint8Array.of(0xed, 0x01); // multicodec ed25519-pub

/** Monero scalars are 32-byte little-endian, reduced mod l. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const leNum = (b: Uint8Array): bigint => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
const leBytes = (n: bigint, len = 32): Uint8Array => {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
};
const mod = (n: bigint): bigint => ((n % L) + L) % L; // Python's %, never negative

/** Python `json.dumps(v, separators=(',', ':'))`: ensure_ascii, lowercase `\uXXXX`. */
const pyDumps = (v: unknown): string =>
  JSON.stringify(v).replace(/[\u007f-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
const LONE = /[\ud800-\udfff]/u;
const hasLoneSurrogate = (v: unknown): boolean =>
  typeof v === 'string' ? LONE.test(v)
    : v !== null && typeof v === 'object'
      ? Object.entries(v).some(([k, x]) => LONE.test(k) || hasLoneSurrogate(x)) : false;

/** A copy of `o` with its keys in `o`'s order, keeping only `keep` (Python dict comprehension). */
const pick = (o: J, keep: string[]): J => Object.fromEntries(Object.entries(o).filter(([k]) => keep.includes(k)));
const omit = (o: J, drop: string): J => Object.fromEntries(Object.entries(o).filter(([k]) => k !== drop));
const clone = (o: J): J => JSON.parse(JSON.stringify(o));

// ---------------------------------------------------------------- seeds and helpers

const V = 'sigelo/0'; // wire version 0 = draft, unstable
const S: Record<string, string> = {
  agent: '00'.repeat(31) + '01', recovery: '00'.repeat(31) + '02', world: '00'.repeat(31) + '03',
  agent2: '00'.repeat(31) + '04', attacker: '00'.repeat(31) + '05', member: '00'.repeat(31) + '06',
  recovery2: '00'.repeat(31) + '07', agent3: '00'.repeat(31) + '08', paykey: '00'.repeat(31) + '09',
};
const K = Object.fromEntries(Object.entries(S).map(([n, s]) => [n, hex(s)])) as Record<string, Uint8Array>;

const key = (n: string): string => encodeKey(ed.getPublicKey(K[n]!));
const commit = (n: string): string => commitmentOf(key(n));
const sig = (n: string, body: unknown): string => sign(K[n]!, body);
const nonce = (b: string): string => mb(hex(b.repeat(16)));
const genesis = (n: string, rec: string | null, created: string, nb: string): J =>
  ({ v: V, typ: 'genesis', key: key(n), recovery: rec, created, nonce: nonce(nb) });

const DAY = 86400, T0 = 1757203200; // 2026-09-07T00:00:00Z
const NOW = T0 + 1 * DAY; // fixed clock for the bundle vector and expiry checks
const out: J = {
  spec: 'sigelo v0.1 (wire sigelo/0)', signing_input: '"sigelo\\n" || JCS(body)',
  seeds: S, now: NOW,
  note: 'Seeds are 32 bytes, all zero except the last. Genesis nonces are fixed for reproducibility; real ones are random. ' +
    '`now` is the clock every time-dependent check in this file assumes.',
  vectors: {}, negative: {},
};
const P: J = out.vectors, N: J = out.negative;

// ---------------------------------------------------------------- identities

const rec1 = commit('recovery'), rec2 = commit('recovery2');
const g0 = genesis('agent', rec1, '2026-09-07T00:00:00Z', 'a1'), d0 = did(g0);
const gw = genesis('world', null, '2026-01-01T00:00:00Z', 'b2'), dw = did(gw);
const gm = genesis('member', null, '2026-03-01T00:00:00Z', 'c3'), dm = did(gm);
P.genesis = { doc: g0, expect_did: d0 };
P.world_genesis = { doc: gw, expect_did: dw, note: 'recovery:null is legal; theft of this key is terminal' };
P.member_genesis = { doc: gm, expect_did: dm };

// ---------------------------------------------------------------- attestation

const att = {
  v: V, typ: 'attestation', iss: dw, sub: d0, iat: T0, exp: T0 + 90 * DAY, ctx: '1f916.ai',
  admission: 'invite', admission_by: dm,
  claims: { joined: '2026-04-02', posts: 412, standing: 'citizen' },
};
P.attestation = { body: att, sig: sig('world', att), signed_by: 'world' };

// Attestation exercising SPEC §3 canonical-form rules. Key order: U+1D11E (surrogates D834
// DD1E) must sort BEFORE U+FF5E under UTF-16 code units, AFTER it under code points. Escapes:
// only the ES6 set, lowercase \u00xx; U+007F, U+2028 and non-ASCII are raw UTF-8. Integers at
// both ends of the allowed range.
const attu = {
  v: V, typ: 'attestation', iss: dw, sub: d0, iat: T0, exp: T0 + 90 * DAY, ctx: '1f916.ai',
  admission: 'open',
  claims: {
    '\u{1d11e}': 'supplementary-plane key', '\uff5e': 'bmp key', '\u00e9': 'latin-1 key',
    esc: '\x01\b\t\n\f\r"\\\x7f\u2028\u2029\u00e9\u{1f642}',
    zero: 0, neg: -1, max: 2 ** 53 - 1, min: -(2 ** 53 - 1),
    nested: { b: [1, { d: null, c: true }], a: {} }, empty: [],
  },
};
P.attestation_unicode = {
  body: attu, sig: sig('world', attu),
  canonical: canonicalize(attu),
  signing_input_sha256: bytesToHex(sha256(signingInput(attu))),
  note: 'Reproduce `canonical` byte-for-byte before checking the signature. A sorted JSON.stringify or json.dumps gets the key order wrong.',
};

// ---------------------------------------------------------------- proof of control (§5.2)

const ch = { v: V, typ: 'challenge', did: d0, ctx: '1f916.ai', nonce: nonce('e9') };
P.challenge = {
  body: ch, sig: sig('agent', ch),
  note: 'Signed by the identity key of `did`. Never appears in a bundle; typ binds it out of every other slot.',
};

// ---------------------------------------------------------------- invoice (§6.3)

const inv = {
  v: V, typ: 'invoice', did: d0, method: 'monero',
  addr: '7BwuLFbUUxwUPqTZFgYoRFbjmzAQTN7MPUnyKaRe7TR35rGpixSRuuqmv4HcFcEqcRnDUYNU3xdpsKSAiWvARw9m1MCe6Ea',
  iat: T0, exp: T0 + 1 * DAY, nonce: nonce('ea'), amount: '150000000000',
};
P.invoice = { body: inv, sig: sig('agent', inv), note: 'Signed by the identity key of `did`. Never in a bundle. addr is a stagenet subaddress.' };

// ---------------------------------------------------------------- binding (cross-signed)

const b = { v: V, typ: 'binding', id: d0, method: 'ed25519-test', addr: key('paykey'), iat: T0, exp: T0 + 90 * DAY, nonce: nonce('d4') };
P.binding = {
  body: b, sig_id: sig('agent', b), sig_addr: sig('paykey', b),
  note: 'method ed25519-test exists only for vectors; sig_addr uses the same signing input',
};
const bu = { ...b, nonce: nonce('d5') };
P.binding_unproven = {
  body: bu, sig_id: sig('agent', bu),
  note: 'no sig_addr: verifier MUST report proof=unproven and MUST NOT pay to it',
};

// ---------------------------------------------------------------- monero binding (§6.2)
// XSEED is the private spend key of ts/test/monero-vectors.json, whose addresses and
// signatures were produced by monero's own C++ core (via monero-ts). Signing nonces are fixed
// here so this file regenerates byte-for-byte; signMessage defaults to random ones.

const XSEED = '0b'.repeat(31) + '01';
out.monero_spend_seed = XSEED; // appended to `out` here, hence after `negative` in the file
const mk = keysFromSpend(hex(XSEED));
const xstd = encodeAddress({ net: 'mainnet', kind: 'standard', spend: mk.B, view: mk.A });
/** §6.2 view mode: the view-only wallet (a, B) signs; nonce byte `n` repeated 32 times. */
const xsig = (body: unknown, n: string): string =>
  sigeloMoneroSigAddr(body, { mode: 'view', secret: mk.a, spendPub: mk.B, viewPub: mk.A, nonce: hex(n.repeat(32)) });
const bx = { v: V, typ: 'binding', id: d0, method: 'monero', addr: xstd, iat: T0, exp: T0 + 90 * DAY, nonce: nonce('c1') };
P.binding_monero = {
  body: bx, sig_id: sig('agent', bx), sig_addr: xsig(bx, '11'),
  expect_proof: 'proven', expect_mode: 'view',
  note: '§6.2 view mode: a view-only wallet (a, B) proves it can see the wallet without ever ' +
    'holding a spend key. addr is the MAINNET STANDARD address of monero_spend_seed. ' +
    'Signing nonce fixed at 0x11 * 32; real ones are random, so byte-equality is not the target.',
};

// §6.2 subaddress (0,1) of the same wallet, signed with its own scalars as wallet2::sign does
// for a non-zero index: m = H_s("SubAddr\0" || a || le32(0) || le32(1)), d = b + m signs spend
// mode over (D, C), a*d signs view mode. Both need b: for a subaddress, view mode does not
// imply a view-only signer.
const bxs = { ...bx, addr: subaddress({ a: mk.a, B: mk.B, major: 0, minor: 1, net: 'mainnet' }), nonce: nonce('c2') };
const m01 = leNum(hashToScalar(utf8ToBytes('SubAddr\0'), mk.a, leBytes(0n, 4), leBytes(1n, 4)));
const d01 = mod(leNum(mk.b) + m01);
const sub01 = subaddressKeys({ a: mk.a, B: mk.B, major: 0, minor: 1 });
const ssig = (body: unknown, mode: 'spend' | 'view', n: string): string => sigeloMoneroSigAddr(body, {
  mode, secret: leBytes(mode === 'spend' ? d01 : mod(leNum(mk.a) * d01)), spendPub: sub01.D, viewPub: sub01.C, nonce: hex(n.repeat(32)),
});
P.binding_monero_subaddress_spend = {
  body: bxs, sig_id: sig('agent', bxs), sig_addr: ssig(bxs, 'spend', '22'),
  expect_proof: 'proven', expect_mode: 'spend',
  note: '§6.2 subaddress: addr is MAINNET SUBADDRESS (0,1) of monero_spend_seed; sig_addr is spend mode ' +
    'over its own (D, C) with d = b + m. Signing nonce fixed at 0x22 * 32.',
};
const bxsv = { ...bxs, nonce: nonce('c7') };
P.binding_monero_subaddress_view = {
  body: bxsv, sig_id: sig('agent', bxsv), sig_addr: ssig(bxsv, 'view', '77'),
  expect_proof: 'proven', expect_mode: 'view',
  note: '§6.2 subaddress, view mode: secret a*(b + m), over (D, C). Still needs the spend key — for a ' +
    'subaddress, view mode does not imply a view-only signer. Signing nonce fixed at 0x77 * 32.',
};

// ---------------------------------------------------------------- rotations

// voluntary: recovery commitment carried forward
const g1 = genesis('agent2', rec1, '2026-10-01T00:00:00Z', 'e5'), d1 = did(g1);
const r1 = { v: V, typ: 'rotation', id: d0, next: d1, iat: T0 + 24 * DAY, reason: 'voluntary' };
P.rotation_voluntary = { body: r1, sig: sig('agent', r1), next_genesis: g1, expect_next_did: d1 };

// hostile: stolen agent2 key, later iat, valid sig, changes commitment
const ga = genesis('attacker', commit('attacker'), '2026-10-20T00:00:00Z', 'f6'), da = did(ga);
const rh = { v: V, typ: 'rotation', id: d1, next: da, iat: T0 + 45 * DAY, reason: 'voluntary' };
P.rotation_hostile = {
  body: rh, sig: sig('agent2', rh), next_genesis: ga,
  note: 'Signature VALID. next_genesis carries a DIFFERENT recovery commitment — ' +
    'that alone is grounds to REJECT a voluntary rotation (see negative.voluntary_changes_recovery). ' +
    'Even if it did not, recovery below supersedes it.',
};

// hostile, commitment carried forward: only precedence (§7.1) defeats this
const gac = genesis('attacker', rec1, '2026-10-21T00:00:00Z', 'd6'), dac = did(gac);
const rhc = { v: V, typ: 'rotation', id: d1, next: dac, iat: T0 + 50 * DAY, reason: 'voluntary' };
P.rotation_hostile_carried = {
  body: rhc, sig: sig('agent2', rhc), next_genesis: gac,
  note: 'Signature VALID, commitment UNCHANGED, latest iat at this node: a fully valid voluntary rotation. ' +
    'It loses only because a valid recovery rotation exists at the same node (SPEC §7.1). ' +
    'A verifier that picks by iat, or by "voluntary first", follows this and fails chain_precedence_only.',
};

// recovery: EARLIER iat than both hostiles, may change commitment
const g2 = genesis('agent3', rec2, '2026-10-10T00:00:00Z', 'a7'), d2 = did(g2);
const rr = { v: V, typ: 'rotation', id: d1, next: d2, iat: T0 + 35 * DAY, reason: 'recovery', recovery_key: key('recovery') };
P.rotation_recovery = {
  body: rr, sig: sig('recovery', rr), next_genesis: g2, expect_next_did: d2,
  note: 'iat EARLIER than both hostile rotations. Recovery outranks key. Chain is now d0 -> d1 -> d2. ' +
    'Recovery commitment changes to rec2; subsequent recoveries must use recovery2.',
};

// second recovery must use the NEW key
const g3 = genesis('agent', rec2, '2026-11-01T00:00:00Z', 'b8'), d3 = did(g3);
const rr2 = { v: V, typ: 'rotation', id: d2, next: d3, iat: T0 + 60 * DAY, reason: 'recovery', recovery_key: key('recovery2') };
P.rotation_recovery_second = {
  body: rr2, sig: sig('recovery2', rr2), next_genesis: g3, expect_next_did: d3,
  note: 'Verified against the commitment in g2 (most recent recovery-signed genesis), not g0.',
};

P.expected_chain = [d0, d1, d2, d3];
P.chain_precedence_only = {
  rotations: ['rotation_voluntary', 'rotation_hostile_carried', 'rotation_recovery'],
  expected_chain: [d0, d1, d2],
  note: 'At d1 both candidates are valid. rotation_hostile_carried has the later iat. The recovery wins anyway.',
};

// ---------------------------------------------------------------- full bundle, §9.1 result at `now`

const att_d2 = { v: V, typ: 'attestation', iss: dw, sub: d2, iat: T0, exp: T0 + 90 * DAY, ctx: '1f916.ai', admission: 'open', claims: { standing: 'citizen' } };
const att_exp = { ...att, exp: T0 + 1 };
const att_tamp = clone(att); att_tamp.claims.posts = 999999;
const att_unknown_iss = { v: V, typ: 'attestation', iss: da, sub: d0, iat: T0, exp: T0 + 90 * DAY, ctx: 'evil.example', admission: 'open', claims: {} };
const att_sub_off_chain = { v: V, typ: 'attestation', iss: dw, sub: da, iat: T0, exp: T0 + 90 * DAY, ctx: '1f916.ai', admission: 'open', claims: {} };
const att_bad_adm = { ...att, admission: 'vip' }; // not in §5.1: malformed, discarded per-item
const att_no_ctx = omit(att, 'ctx'); // missing required field: same
const att_m = { v: V, typ: 'attestation', iss: dm, sub: d0, iat: T0, exp: T0 + 90 * DAY, ctx: 'member.example', admission: 'human', claims: { met: true } };
const b_off = { v: V, typ: 'binding', id: da, method: 'ed25519-test', addr: key('paykey'), iat: T0, exp: T0 + 90 * DAY, nonce: nonce('d9') };
const b_bad = { ...b, nonce: nonce('d7') };
const b_opaque = { v: V, typ: 'binding', id: d0, method: 'opaque-test', addr: 'anything', iat: T0, exp: T0 + 90 * DAY, nonce: nonce('d8') };
const ENVELOPE = ['body', 'sig', 'sig_id', 'sig_addr', 'next_genesis']; // strip vector-only annotations
const bundle = {
  v: V, typ: 'bundle', genesis: g0,
  rotations: ['rotation_voluntary', 'rotation_hostile', 'rotation_hostile_carried', 'rotation_recovery', 'rotation_recovery_second']
    .map((n) => pick(P[n], ENVELOPE)),
  bindings: [
    P.binding, P.binding_unproven,
    { body: b_bad, sig_id: sig('agent', b_bad), sig_addr: sig('attacker', b_bad) },
    { body: b_opaque, sig_id: sig('agent', b_opaque), sig_addr: 'z1' },
    { body: b_off, sig_id: sig('attacker', b_off), sig_addr: sig('paykey', b_off) },
  ].map((e) => pick(e, ENVELOPE)),
  attestations: [
    P.attestation,
    { body: att_exp, sig: sig('world', att_exp) },
    P.attestation_unicode,
    { body: att_tamp, sig: P.attestation.sig },
    { body: att_unknown_iss, sig: sig('attacker', att_unknown_iss) },
    { body: att_d2, sig: sig('world', att_d2) },
    { body: att_sub_off_chain, sig: sig('world', att_sub_off_chain) },
    { body: att_bad_adm, sig: sig('world', att_bad_adm) },
    { body: att_no_ctx, sig: sig('world', att_no_ctx) },
    { body: att_m, sig: sig('member', att_m) },
  ].map((e) => pick(e, ENVELOPE)),
  issuers: [gw, gm],
};
P.bundle = {
  now: NOW, bundle,
  expect: {
    did: d3, chain: [d0, d1, d2, d3], recovery: rec2,
    attestations: { [dw]: [att, attu, att_d2], [dm]: [att_m] },
    bindings: [{ body: b, proof: 'proven' }, { body: bu, proof: 'unproven' }, { body: b_opaque, proof: 'unsupported' }],
    rejected: { attestations: 6, bindings: 2 },
  },
  note: 'verify(bundle, now) must equal `expect` as JSON. Rejected: expired, tampered, unknown issuer (genesis not in issuers), ' +
    'sub not in chain, unknown admission value, missing ctx (malformed attestation bodies are per-item, SPEC §9 step 2); ' +
    'one binding whose sig_addr is by the wrong key (discarded, not downgraded), one binding whose id is not in the chain. ' +
    'Two issuers: grouping is by iss, compared by value.',
};
P.bundle_minimal = {
  now: NOW, bundle: { v: V, typ: 'bundle', genesis: gm, rotations: [], bindings: [], attestations: [], issuers: [] },
  expect: { did: dm, chain: [dm], recovery: null, attestations: {}, bindings: [], rejected: { attestations: 0, bindings: 0 } },
  note: 'The smallest bundle that verifies. recovery: null is reported as null.',
};

// ================================================================ NEGATIVE

const bad = clone(att); bad.claims.posts = 999999;
N.tampered_claims = { body: bad, sig: P.attestation.sig, expect: 'REJECT signature mismatch' };
N.wrong_signer = { body: att, sig: sig('attacker', att), expect: 'REJECT signer is not iss' };
N.missing_prefix = { body: att, sig: mb(ed.sign(utf8ToBytes(canonicalize(att)), K.world!)), expect: 'REJECT signed without domain prefix' };
N.genesis_tampered = { doc: { ...g0, recovery: commit('attacker') }, claimed_did: d0, expect: 'REJECT DID != hash(genesis)' };
N.float_in_claims = { body: { v: V, typ: 'attestation', claims: { score: 0.1 } }, expect: 'REJECT non-integer number' };
N.int_out_of_range = { body: { v: V, typ: 'attestation', claims: { big: 2 ** 53 } }, expect: 'REJECT integer outside +-2^53-1' };
N.duplicate_key = {
  raw: '{"v":"sigelo/0","typ":"attestation","claims":{"posts":1,"posts":2}}',
  expect: 'REJECT duplicate key; the body has no canonical form. Parse `raw` with a duplicate-detecting parser.',
};
const att_as_binding = { ...att, typ: 'binding' };
N.typ_mismatch = {
  body: att_as_binding, sig: sig('world', att_as_binding),
  expect: 'REJECT valid signature but typ does not match the slot it was presented in',
};
const rk = { ...rr, recovery_key: key('attacker') };
N.recovery_key_mismatch = {
  body: rk, sig: sig('attacker', rk), next_genesis: g2, chain_with: ['rotation_voluntary'], expected_chain: [d0, d1],
  expect: 'NOT A CANDIDATE: hash(recovery_key) != commitment. With rotation_voluntary, the chain ends at d1.',
};
const stale = { ...rr2, recovery_key: key('recovery') };
N.stale_recovery_key = {
  body: stale, sig: sig('recovery', stale), next_genesis: g3, chain_with: ['rotation_voluntary', 'rotation_recovery'], expected_chain: [d0, d1, d2],
  expect: 'NOT A CANDIDATE: recovery1 no longer governs after rotation_recovery changed the commitment to rec2. Chain ends at d2.',
};
N.voluntary_changes_recovery = {
  body: rh, sig: P.rotation_hostile.sig, next_genesis: ga, chain_with: ['rotation_voluntary'], expected_chain: [d0, d1],
  expect: 'NOT A CANDIDATE: voluntary rotation whose next_genesis.recovery != current commitment. Chain ends at d1.',
};
const rb = { v: V, typ: 'rotation', id: d0, next: d1, iat: T0 + 24 * DAY, reason: 'voluntary' };
N.rotation_bad_sig = {
  body: rb, sig: sig('attacker', rb), next_genesis: g1, chain_with: [], expected_chain: [d0],
  expect: "NOT A CANDIDATE: signed by a key that is not d0's. Alone, the chain is just [d0].",
};
const att_extra = { ...att, extra: 1 };
N.unknown_field_attestation = {
  body: att_extra, sig: sig('world', att_extra),
  expect: 'DISCARD (per-item, §9 step 2): top-level key `extra` is not in the §3.1 row for attestation',
};
N.unknown_field_genesis = { doc: { ...g0, extra: 1 }, expect: 'REJECT (fatal): a genesis with a top-level key outside §3.1 is malformed' };
const gf = genesis('paykey', rec1, '2026-10-02T00:00:00Z', 'c9'), df = did(gf);
const rf = { v: V, typ: 'rotation', id: d0, next: df, iat: T0 + 25 * DAY, reason: 'voluntary' };
N.fork = {
  body: rf, sig: sig('agent', rf), next_genesis: gf,
  expect: 'REJECT chain: two valid voluntary rotations from d0 (this and rotation_voluntary). Fork = compromise signal.',
};
const rc = { v: V, typ: 'rotation', id: d1, next: d0, iat: T0 + 30 * DAY, reason: 'voluntary' };
N.cycle = {
  body: rc, sig: sig('agent2', rc), next_genesis: g0,
  expect: 'REJECT chain: valid voluntary rotation from d1 back to d0 (after rotation_voluntary). next already in chain; a naive walk never terminates.',
};
const rs = { v: V, typ: 'rotation', id: d0, next: d0, iat: T0 + 30 * DAY, reason: 'voluntary' };
N.self_rotation = { body: rs, sig: sig('agent', rs), next_genesis: g0, expect: 'REJECT structure: next == id' };
N.expired_attestation = { body: att_exp, sig: sig('world', att_exp), expect: 'REJECT (at `now`) exp in the past' };

// §3.1 / §6.3: `amount` is a STRING of atomic units, or absent. Every one of these carries a
// VALID signature — the canonicalizer cannot catch them, because a JSON number and the strings
// below are all legal JSON. The check is structural or it does not exist.
for (const [nm, amt, why] of [
  ['invoice_amount_number', 150000000000, 'a JSON number, not a string — §3.1 types `amount` as a string precisely so no parser turns it into a float'],
  ['invoice_amount_float_string', '0.15', 'a decimal fraction — `amount` is atomic units, not XMR'],
  ['invoice_amount_negative', '-1', 'negative — there is no negative atomic unit'],
  ['invoice_amount_empty', '', 'the empty string, which is not a number at all'],
] as const) {
  const ib = { ...inv, amount: amt };
  N[nm] = { body: ib, sig: sig('agent', ib), expect: 'REJECT structure (§3.1, §6.3): signature VALID, but amount is ' + why };
}

// §6.2: what a `method: "monero"` sig_addr may NOT be. Each is a genuine Monero signature (the
// first by the wrong keys; the rest verify under monero's own routine); each is discarded per-item (§6.1: a bad proof is not
// no proof), never downgraded to `unproven`.

// 1. The subaddress bindings' own (0,1) address, but sig_addr is a genuine view-mode signature
//    by the BASE address's keys (a, over (B, A)) — what a view-only wallet can make. The hash
//    names (B, A), not (D, C), so it cannot verify under the subaddress.
const bxsb = { ...bxs, nonce: nonce('c8') };
N.binding_monero_subaddress_base_sig = {
  body: bxsb, sig_id: sig('agent', bxsb), sig_addr: xsig(bxsb, '88'),
  expect: "DISCARD (per-item, §6.2): addr is subaddress (0,1) and sig_addr is a VALID SigV2 by the " +
    "BASE address's view key — the wrong keys. A subaddress binding is proven only by its own " +
    '(D, C), which needs the spend key in either mode.',
};

// 2. The integrated spelling of the same wallet, signed exactly like the standard one.
const bxi = { ...bx, addr: encodeAddress({ net: 'mainnet', kind: 'integrated', spend: mk.B, view: mk.A, paymentId: hex('0123456789abcdef') }), nonce: nonce('c3') };
N.binding_monero_integrated_addr = {
  body: bxi, sig_id: sig('agent', bxi), sig_addr: xsig(bxi, '33'),
  expect: 'DISCARD (per-item, §6.2): the integrated spelling of the SAME wallet. The message hash ' +
    "covers (B, A) and not the prefix, so the base address's signature verifies here verbatim — " +
    'which is exactly why the form must be refused: the payment id rode in unsigned.',
};

// 3. A genuine legacy SigV1 over the same signing input, by the wallet spend key:
//    h = Keccak256(data) alone — no mode, no keys; c = H_s(h || B || kG); r = k - c*b.
const bx1 = { ...bx, nonce: nonce('c4') };
const h1 = keccak256(signingInput(bx1));
const k1 = leNum(scReduce32(hex('44'.repeat(32))));
const c1 = leNum(hashToScalar(h1, mk.B, Point.BASE.multiply(k1).toBytes()));
N.binding_monero_sigv1 = {
  body: bx1, sig_id: sig('agent', bx1),
  sig_addr: 'SigV1' + moneroBase58Encode(concatBytes(leBytes(c1), leBytes(mod(k1 - c1 * leNum(mk.b))))),
  expect: 'DISCARD (per-item, §6.2): "Legacy SigV1 is not accepted." It verifies under wallet2, but ' +
    'its hash is Keccak256(data) alone — neither the mode byte nor the address keys are in it, ' +
    'so it cannot tell a view proof from a spend proof.',
};

// 4, 5. Keys Monero's own decoder refuses. get_account_address_from_str
//    (src/cryptonote_basic/cryptonote_basic_impl.cpp) runs check_key, i.e. ge_frombytes_vartime
//    (src/crypto/crypto-ops.c), on BOTH keys: it refuses y >= p, and x = 0 with the sign bit set.
//    Each sig_addr is genuine, by the wallet's real key for the mode it uses; the refused key is
//    the other one, which that mode only hashes. A decoder permissive about it (ZIP-215, or
//    edwards25519's SetBytes) therefore reads the binding as proven.
const yGeP = leBytes(2n ** 255n - 19n); // y = p, i.e. y = 0 mod p: the point (sqrt(-1), 0) spelled with y >= p
const negZero = leBytes(1n + (1n << 255n)); // y = 1, x = 0, sign bit set: the identity as "negative zero"
const bxp = { ...bx, addr: encodeAddress({ net: 'mainnet', kind: 'standard', spend: mk.B, view: yGeP }), nonce: nonce('c5') };
N.binding_monero_view_key_y_ge_p = {
  body: bxp, sig_id: sig('agent', bxp),
  sig_addr: sigeloMoneroSigAddr(bxp, { mode: 'spend', secret: mk.b, spendPub: mk.B, viewPub: yGeP, nonce: hex('55'.repeat(32)) }),
  expect: "DISCARD (per-item, §6.2): addr's VIEW key is y = p (ed ff .. ff 7f), which Monero's check_key " +
    "refuses (fe_frombytes_vartime: y >= p). sig_addr is a genuine SPEND-mode signature by the wallet's " +
    'real spend key, and spend mode never decodes the view key: only the address check stops it.',
};
const bxz = { ...bx, addr: encodeAddress({ net: 'mainnet', kind: 'standard', spend: negZero, view: mk.A }), nonce: nonce('c6') };
N.binding_monero_spend_key_x0_signbit = {
  body: bxz, sig_id: sig('agent', bxz),
  sig_addr: sigeloMoneroSigAddr(bxz, { mode: 'view', secret: mk.a, spendPub: negZero, viewPub: mk.A, nonce: hex('66'.repeat(32)) }),
  expect: "DISCARD (per-item, §6.2): addr's SPEND key is y = 1 with the sign bit set (01 00 .. 00 80), x = 0, " +
    'which Monero\'s check_key refuses ("If x = 0, the sign must be positive"). sig_addr is a genuine ' +
    "VIEW-mode signature by the wallet's real view key: only the address check stops it.",
};

N.genesis_bad_key = {
  doc: { ...g0, key: mb(concatBytes(MC, new Uint8Array(31))) },
  expect: 'REJECT (fatal): genesis.key is 33 bytes, not multicodec ed25519-pub (0xed 0x01 || 32 bytes)',
};
N.bundle_rotations_not_array = {
  bundle: { v: V, typ: 'bundle', genesis: gm, rotations: {}, bindings: [], attestations: [], issuers: [] },
  expect: 'REJECT structure (§8): all four arrays are required and MAY be empty — but they must be arrays',
};

// §3.1 field types. Each binding below carries a VALID sig_id and a genuine SigV2 sig_addr from
// the monero_spend_seed wallet over its own bytes: it must lose on structure, not crypto.
// `reject` is the substring both implementations' error carries. `n` is both the binding
// nonce byte and the Monero signing nonce byte.
function xb(nm: string, n: string, over: J, reject: string | null, why: string): void {
  const body = { ...{ ...bx, nonce: nonce(n) }, ...over };
  N[nm] = {
    body, sig_id: sig('agent', body), sig_addr: xsig(body, n),
    reject, expect: 'DISCARD (per-item, §3.1): signature and sig_addr VALID, but ' + why,
  };
}
xb('binding_addr_not_string', 'd6', { addr: [...xstd] }, 'addr is not a string', 'addr is a JSON array of one-character strings, not a string');
xb('binding_iat_string', 'd7', { iat: String(T0) }, 'iat is not a non-negative integer', `iat is the STRING "${T0}" — JS compares it as a number, Python cannot`);
xb('binding_iat_null', 'd8', { iat: null }, 'iat is not a non-negative integer', 'iat is null (JS: null <= now is true)');
xb('binding_iat_bool', 'd9', { iat: true }, 'iat is not a non-negative integer', "iat is `true` — Python's isinstance(True, int) is True");
xb('binding_iat_negative', 'da', { iat: -1 }, 'iat is not a non-negative integer', 'iat is before the Unix epoch');
xb('binding_exp_string', 'db', { exp: '99999999999' }, 'exp is not a non-negative integer', 'exp is a string');
xb('binding_exp_not_after_iat', 'dc', { exp: T0 }, 'exp is not after iat', 'exp == iat: a window no `now` can be inside');
xb('binding_nonce_number', 'dd', { nonce: 5 }, 'nonce is not a string', 'nonce is a JSON number');
// §6.2 via Monero itself: read_varint (src/common/varint.h) returns EVARINT_REPRESENT for a zero
// byte after the first, and decode_addr (src/common/base58.cpp) refuses the address. `92 00` is
// 18 (mainnet standard) in two bytes; the checksum is valid and so is the signature, because the
// message hash covers (B, A), not the prefix. Passes structure; discarded at the §6.2 check.
const nc = concatBytes(Uint8Array.of(0x92, 0x00), mk.B, mk.A);
xb('binding_monero_noncanonical_varint_addr', 'de', { addr: moneroBase58Encode(concatBytes(nc, keccak256(nc).subarray(0, 4))) }, null,
  "addr spells the wallet's mainnet prefix 18 as the non-minimal varint `92 00`, which wallet2 refuses");

// A lone surrogate cannot be written into this UTF-8 file raw, so it travels as `raw` text and is
// read with the strict parser. `sig` is over the body with U+FFFD in its place: the bytes a lossy
// UTF-8 encoder (TextEncoder) would have produced, i.e. the signature that used to verify.
N.invoice_memo_lone_surrogate = {
  raw: pyDumps({ ...inv, memo: '\ud800' }),
  sig: sig('agent', { ...inv, memo: '\ufffd' }), reject: 'lone surrogate',
  expect: 'REJECT structure (§3.1): memo is a lone surrogate. `sig` is VALID over the U+FFFD twin, ' +
    'which is exactly the collision: two different bodies, one signing input.',
};
const iv = { ...inv, memo: { x: 1 } };
N.invoice_memo_not_string = {
  body: iv, sig: sig('agent', iv), reject: 'memo is not a string',
  expect: 'REJECT structure (§3.1, §6.3): signature VALID, but memo is an object, not free text',
};
N.proto_key = {
  raw: '{"v":"sigelo/0","typ":"attestation","claims":{"__proto__":{"posts":1}}}', reject: '__proto__',
  expect: 'REJECT parse (§3.1): the key "__proto__" is forbidden at any depth. A JavaScript parser ' +
    'that assigns it swaps the prototype instead of adding a key',
};

// ---------------------------------------------------------------- parity
// Malformed objects fed to both verifiers, which must reach the SAME outcome. Every case is a
// whole bundle through verify(): `expect` is either {reject: substring} (fatal) or the
// accepted-binding proofs, accepted-attestation count and `rejected` counts.

/** Sign if the body is signable at all; JCS refuses floats, lone surrogates, "__proto__". */
const trySig = (n: string, body: unknown): string => {
  try { return sig(n, body); } catch (e) { if (e instanceof JcsError) return 'z1'; throw e; }
};
const envB = (over: J = {}): J => { const body = { ...b, ...over }; return { body, sig_id: trySig('agent', body), sig_addr: trySig('paykey', body) }; };
const envA = (over: J = {}): J => { const body = { ...att, ...over }; return { body, sig: trySig('world', body) }; };
const bnd = (bindings: J[] = [], attestations: J[] = [], over: J = {}): J =>
  ({ ...{ v: V, typ: 'bundle', genesis: g0, rotations: [], bindings, attestations, issuers: [gw] }, ...over });
const counts = (proofs: string[], attestations: number, ra: number, rb: number): J =>
  ({ proofs, attestations, rejected: { attestations: ra, bindings: rb } });
const discB = counts([], 0, 0, 1), discA = counts([], 0, 1, 0);
// "__proto__" as an OWN key: an object literal would set the prototype instead.
const protoClaims = JSON.parse('{"__proto__":{"posts":1}}');

const C: Record<string, [J, J]> = {};
C.binding_ok = [bnd([envB()]), counts(['proven'], 0, 0, 0)];
for (const [k, v] of [
  ['iat_string', String(T0)], ['iat_null', null], ['iat_negative', -1], ['iat_bool', true], ['iat_float', T0 + 0.5],
  ['exp_string', '99999999999'], ['exp_array', [T0]], ['exp_equal_iat', T0], ['exp_before_iat', T0 - 1],
  ['id_number', 7], ['method_null', null], ['addr_array', [...b.addr]], ['addr_object', { k: b.addr }],
  ['nonce_number', 5], ['nonce_bool', false],
] as [string, unknown][]) C['binding_' + k] = [bnd([envB({ [k.split('_')[0]!]: v })]), discB]; // field = up to the FIRST '_'
// Invariant 7: a float, lone surrogate or "__proto__" key inside ONE attestation or binding
// discards that item; the others still verify. The same fault in a rotation or issuer is fatal.
C.binding_good_and_float = [bnd([envB(), envB({ iat: T0 + 0.5 })]), counts(['proven'], 0, 0, 1)];
C.binding_sig_addr_float = [bnd([{ ...envB(), sig_addr: 0.5 }]), discB];
C.binding_envelope_null = [bnd([null]), discB];
C.binding_envelope_number = [bnd([5]), discB];
C.binding_envelope_array = [bnd([[]]), discB];
C.binding_body_missing = [bnd([{ sig_id: 'z1' }]), discB];
C.binding_body_string = [bnd([{ body: 'x', sig_id: 'z1' }]), discB];
C.binding_sig_id_number = [bnd([{ ...envB(), sig_id: 5 }]), discB];
C.binding_sig_id_missing = [bnd([omit(envB(), 'sig_id')]), discB];
C.binding_sig_addr_null = [bnd([{ ...envB(), sig_addr: null }]), discB];
C.binding_unknown_method_sig_addr_number = [bnd([{ ...envB({ method: 'foo' }), sig_addr: 5 }]), counts(['unsupported'], 0, 0, 0)];
// The WHOLE envelope is canonicalized, not just the body: nothing reads the sig_addr of an
// unsupported method, so only that check sees this float. A body-only verifier says `unsupported`.
C.binding_envelope_float_unsupported_method = [bnd([{ ...envB({ method: 'unsupported-method' }), sig_addr: 1.5 }]), discB];
C.attestation_ok = [bnd([], [envA()]), counts([], 1, 0, 0)];
C.attestation_claims_string = [bnd([], [envA({ claims: 'free-form' })]), counts([], 1, 0, 0)]; // claims is untyped, §3.1
for (const [k, v] of [
  ['iat_string', String(T0)], ['exp_null', null], ['ctx_number', 1], ['admission_array', ['open']],
  ['iss_array', [dw]], ['sub_number', 0], ['admission_by_number', 1], ['admission_cost_number', 100],
] as [string, unknown][]) C['attestation_' + k] = [bnd([], [envA({ [k.slice(0, k.lastIndexOf('_'))]: v })]), discA]; // field = up to the LAST '_'
C.attestation_envelope_null = [bnd([], [null]), discA];
C.attestation_sig_number = [bnd([], [{ ...envA(), sig: 5 }]), discA];
// §3.1: an envelope is exactly its defined members. Nothing outside `body` is signed, so an
// extra key is data no signature covers: it discards an attestation or binding (per item; the
// others still verify) and is fatal in a rotation envelope, which defines the identity.
C.attestation_envelope_extra_key_int = [bnd([], [{ ...envA(), note: 1 }]), discA];
C.attestation_envelope_extra_key_float = [bnd([], [{ ...envA(), note: 1.5 }]), discA];
C.attestation_good_and_envelope_extra_keys = [bnd([], [envA(), { ...envA(), now: 1767225600000, now_utc: '2026-01-01T00:00:00Z' }]), counts([], 1, 1, 0)];
C.binding_envelope_extra_key = [bnd([envB(), { ...envB(), sig_addr_mode: 'spend' }]), counts(['proven'], 0, 0, 1)];
C.binding_envelope_sig_id_only_unproven = [bnd([omit(envB(), 'sig_addr')]), counts(['unproven'], 0, 0, 0)];
C.attestation_good_and_proto_key = [bnd([], [envA(), envA({ claims: protoClaims })]), counts([], 1, 1, 0)];
C.attestation_good_and_lone_surrogate = [bnd([], [envA(), envA({ claims: { x: '\ud800' } })]), counts([], 1, 1, 0)];
// §2 length bounds, checked before the (quadratic) base58 decode. Twenty leading '1's are
// twenty leading zero bytes: the SAME digits, still a valid multibase spelling, just too long.
const pad1 = (s: string): string => 'z' + '1'.repeat(20) + s.slice(1);
C.attestation_sig_too_long = [bnd([], [envA(), { ...envA(), sig: pad1(envA().sig) }]), counts([], 1, 1, 0)];
const RV = P.rotation_voluntary;
C.fatal_bundle_is_array = [[], { reject: 'genesis: body is not an object' }];
C.fatal_genesis_nonce_number = [bnd([], [], { genesis: { ...g0, nonce: 1 } }), { reject: 'genesis: nonce is not a string' }];
C.fatal_genesis_created_number = [bnd([], [], { genesis: { ...g0, created: 0 } }), { reject: 'genesis: created is not a string' }];
C.fatal_genesis_key_too_long = [bnd([], [], { genesis: { ...g0, key: pad1(g0.key) } }), { reject: 'multibase: longer than 64 characters' }];
// §4 `created`: RFC 3339 UTC, exactly YYYY-MM-DDTHH:MM:SSZ, a real date, no leap second. Every
// genesis slot is identity-defining, so each is fatal; no attestation or binding field is a
// timestamp string (their iat/exp are integers), so there is no per-item case.
// §2 point rule: a key slot holds the canonical encoding of a point not of small order. Before,
// only the multicodec prefix and length were checked, and these made a VALID identity or issuer
// that no signature could ever verify under (or, for recovery, a recovery nobody can use).
const POINT = 'key: not a valid Ed25519 point (non-canonical, off the curve or of small order)';
const mkKey = (raw: Uint8Array): string => mb(concatBytes(MC, raw));
const zero32 = new Uint8Array(32), ident = Uint8Array.from({ length: 32 }, (_, j) => (j === 0 ? 1 : 0));
C.fatal_genesis_key_all_zero = [bnd([], [], { genesis: { ...g0, key: mkKey(zero32) } }), { reject: POINT }];
C.fatal_issuer_key_identity = [bnd([], [], { issuers: [{ ...gw, key: mkKey(ident) }] }), { reject: POINT }];
C.fatal_rotation_recovery_key_y_ge_p = [bnd([], [], { rotations: [{ ...pick(P.rotation_recovery, ENVELOPE), body: { ...P.rotation_recovery.body, recovery_key: mkKey(leBytes(2n ** 255n - 19n)) } }] }), { reject: POINT }];
// Per item: an ed25519-test binding's addr is a key (§6.1a). Unproven (no sig_addr), so before
// this check nothing ever decoded it and the binding was ACCEPTED as unproven.
{ const body = { ...b, addr: mkKey(zero32), nonce: nonce('df') }; C.binding_ed25519_test_addr_all_zero_unproven = [bnd([{ body, sig_id: sig('agent', body) }]), discB]; }
// §4 commitment: exactly sha256: + 64 lowercase hex. Uppercase hex is the same digest spelled so
// that no commitmentOf() ever equals it: recovery silently off, in an identity that looks fine.
const COMMIT = 'genesis: recovery is neither null nor sha256: + 64 lowercase hex';
C.fatal_genesis_recovery_uppercase_hex = [bnd([], [], { genesis: { ...g0, recovery: g0.recovery.toUpperCase().replace('SHA256:', 'sha256:') } }), { reject: COMMIT }];
C.fatal_genesis_recovery_prefix_only = [bnd([], [], { genesis: { ...g0, recovery: 'sha256:' } }), { reject: COMMIT }];
// §2 nonces: z + base58btc, 1 to 63 digits. "never z + hex" was prose; hex has 0, which base58
// lacks. The §5.2 challenge nonce stays opaque (the world's choice), so no challenge case.
C.fatal_genesis_nonce_z_hex = [bnd([], [], { genesis: { ...g0, nonce: 'z' + '00112233445566778899aabbccddeeff' } }), { reject: 'genesis: nonce is not z + base58btc (at most 64 characters)' }];
C.binding_nonce_not_multibase = [bnd([envB(), envB({ nonce: 'nonce-1' })]), counts(['proven'], 0, 0, 1)];
C.binding_nonce_65_characters = [bnd([envB(), envB({ nonce: 'z' + '2'.repeat(64) })]), counts(['proven'], 0, 0, 1)];
C.binding_nonce_64_characters = [bnd([envB({ nonce: 'z' + '2'.repeat(63) })]), counts(['proven'], 0, 0, 0)];
const CREATED = 'genesis: created is not RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)';
C.genesis_created_leap_day = [bnd([], [], { genesis: { ...g0, created: '2028-02-29T23:59:59Z' } }), counts([], 0, 0, 0)];
C.fatal_genesis_created_leap_second = [bnd([], [], { genesis: { ...g0, created: '2026-06-30T23:59:60Z' } }), { reject: CREATED }];
C.fatal_genesis_created_feb_29_common_year = [bnd([], [], { genesis: { ...g0, created: '2026-02-29T00:00:00Z' } }), { reject: CREATED }];
C.fatal_issuer_created_offset = [bnd([], [], { issuers: [{ ...gw, created: '2026-01-01T00:00:00+00:00' }] }), { reject: CREATED }];
C.fatal_issuer_not_object = [bnd([], [], { issuers: [5] }), { reject: 'genesis: body is not an object' }];
C.fatal_bindings_not_array = [{ ...bnd(), bindings: null }, { reject: 'bindings is not an array' }];
C.fatal_bundle_unknown_field = [bnd([], [], { extra: 1 }), { reject: 'unknown field' }];
C.fatal_rotation_envelope_null = [bnd([], [], { rotations: [null] }), { reject: 'rotation: body is not an object' }];
C.fatal_rotation_sig_number = [bnd([], [], { rotations: [{ ...RV, sig: 5 }] }), { reject: 'rotation: missing sig' }];
C.fatal_rotation_missing_next_genesis = [bnd([], [], { rotations: [{ body: RV.body, sig: RV.sig }] }), { reject: 'rotation: missing next_genesis' }];
C.fatal_rotation_envelope_extra_key = [bnd([], [], { rotations: [{ ...pick(RV, ENVELOPE), note: 'x' }] }), { reject: 'rotation: unknown envelope field "note"' }];
C.fatal_rotation_iat_string = [bnd([], [], { rotations: [{ ...RV, body: { ...RV.body, iat: '1' } }] }), { reject: 'rotation: iat is not a non-negative integer' }];
C.fatal_rotation_next_number = [bnd([], [], { rotations: [{ ...RV, body: { ...RV.body, next: 1 } }] }), { reject: 'rotation: next is not a string' }];
C.fatal_rotation_iat_float = [bnd([], [], { rotations: [{ ...RV, body: { ...RV.body, iat: T0 + 0.5 } }] }), { reject: 'bundle: non-integer number' }];
C.fatal_next_genesis_created_fraction = [bnd([], [], { rotations: [{ ...pick(RV, ENVELOPE), next_genesis: { ...RV.next_genesis, created: '2026-10-01T00:00:00.000Z' } }] }), { reject: CREATED }];
C.fatal_issuer_nonce_float = [bnd([], [], { issuers: [{ ...gw, nonce: 0.5 }] }), { reject: 'bundle: non-integer number' }];
// SPEC §7.3/§7.4: two entries are two candidates even when byte-identical; no verifier deduplicates.
C.fatal_duplicate_rotation_is_fork = [bnd([], [], { rotations: [pick(RV, ENVELOPE), pick(RV, ENVELOPE)] }), { reject: 'chain: fork at' }];
// A lone surrogate cannot be written to this UTF-8 file raw: such a case travels as escaped JSON text in `raw`.
const kase = (bd: J, e: J): J => (hasLoneSurrogate(bd) ? { raw: pyDumps(bd), expect: e } : { bundle: bd, expect: e });
// Bundle TEXT (`raw`), read with the strict parser. A duplicate key makes the text ambiguous, so
// it is fatal wherever it sits (invariant 7, first sentence). A non-integer or out-of-range
// NUMBER is not ambiguous: it sinks only the item holding it, exactly as it does as an object.
const RAW: Record<string, [string, J]> = {};
RAW.raw_binding_good_and_float = [pyDumps(bnd([envB(), envB({ iat: T0 + 0.5 })])), counts(['proven'], 0, 0, 1)];
RAW.raw_attestation_good_and_int_out_of_range = [pyDumps(bnd([], [envA(), envA({ claims: { big: 2 ** 53 } })])), counts([], 1, 1, 0)];
RAW.raw_fatal_rotation_iat_float = [pyDumps(bnd([], [], { rotations: [{ ...pick(RV, ENVELOPE), body: { ...RV.body, iat: T0 + 0.5 } }] })),
  { reject: 'bundle: non-integer number' }];
const dupText = pyDumps(bnd([], [envA(), envA({ claims: { posts: 1 } })]));
if (dupText.split('"claims":{"posts":1}').length !== 2) throw new Error('raw_fatal_attestation_duplicate_key: splice point not unique');
RAW.raw_fatal_attestation_duplicate_key = [dupText.replace('"claims":{"posts":1}', '"claims":{"posts":1,"posts":2}'), { reject: 'duplicate key' }];
// §3 nesting depth. bundle > attestations > envelope > body > claims is five levels, so `deep`
// holding k nested arrays puts the document at 5 + k. At 512 the attestation verifies; at 513
// the TEXT is refused whole, like any parse error — including where a verifier would otherwise
// have discarded only this item: the limit is on the document, not on the slot.
const nested = (k: number): J => { let v: J = []; for (let n = 1; n < k; n++) v = [v]; return v; };
RAW.raw_depth_512_in_claims = [pyDumps(bnd([], [envA({ claims: { deep: nested(507) } })])), counts([], 1, 0, 0)];
// §3.1 / I-JSON: a noncharacter in any string or key is a parse error at the string's opening
// quote. Escaped here (pyDumps), so the file stays clean; the astral one is an escaped pair.
const ncValue = pyDumps(bnd([], [envA(), envA({ claims: { x: '\uffff' } })]));
RAW.raw_fatal_noncharacter_in_claims_value = [ncValue, { reject: `noncharacter U+FFFF in string at offset ${ncValue.indexOf('"\\uffff"')}` }];
const ncKey = pyDumps(bnd([], [envA({ claims: { '\u{10ffff}': 1 } })]));
RAW.raw_fatal_noncharacter_astral_in_claims_key = [ncKey, { reject: `noncharacter U+10FFFF in string at offset ${ncKey.indexOf('"\\udbff\\udfff"')}` }];
const deepText = pyDumps(bnd([], [envA({ claims: { deep: nested(508) } })])); // ASCII: offset = index
RAW.raw_fatal_depth_513_in_claims = [deepText, { reject: `nesting deeper than 512 at offset ${deepText.indexOf('"deep":') + '"deep":'.length + 507}` }];
N.parity = {
  now: NOW, cases: {
    ...Object.fromEntries(Object.entries(C).map(([k, [bd, e]]) => [k, kase(bd, e)])),
    ...Object.fromEntries(Object.entries(RAW).map(([k, [raw, e]]) => [k, { raw, expect: e }])),
  },
  note: 'Malformed objects both verifiers must treat identically: verify(bundle, now) (`bundle`, or `raw` read with the strict parser) either raises with ' +
    '`expect.reject` in the message (a `raw` text the strict parser refuses counts as raising), or returns bindings whose proofs are `expect.proofs`, `expect.attestations` ' +
    'accepted attestations, and `expect.rejected`. Signatures are valid wherever the body can be signed at all.',
};

// ---------------------------------------------------------------- output

// JavaScript enumerates integer-like keys ("0", "42") before all others regardless of insertion
// order, which would silently reorder the file relative to Python and Go. None exist today;
// refuse to emit one rather than drift.
(function noIntegerKeys(v: unknown, path: string): void {
  if (v === null || typeof v !== 'object') return;
  for (const [k, x] of Object.entries(v)) {
    if (!Array.isArray(v) && /^(0|[1-9][0-9]*)$/.test(k)) throw new Error(`integer-like key ${JSON.stringify(k)} at ${path}: JS would reorder it`);
    noIntegerKeys(x, `${path}.${k}`);
  }
})(out, '$');

const text = JSON.stringify(out, null, 2); // no trailing newline, as Python's json.dump
if (process.argv[2]) writeFileSync(process.argv[2], text);
else process.stdout.write(text);
process.stderr.write(`chain:\n  ${P.expected_chain.join('\n  ')}\n` +
  `${Object.keys(P).length - 1} positive groups, ${Object.keys(N).length} negative cases\n`);
