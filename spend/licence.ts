// SPDX-License-Identifier: MIT
/**
 * sigelo-spend — the licence (spend/README.md "Install", "Free and paid").
 *
 * A licence is a sigelo attestation (SPEC §5): issued by the vendor's DID (`iss`) to the
 * customer's keeper DID (`sub`), `ctx: "sigelo-spend"`, `claims: {tier: "pro", seats: N}`, with
 * an `exp`. The file next to policy.json is `{attestation, issuer, rotations}`: the signed
 * attestation, the vendor's GENESIS (which must hash to `vendorDid()`: the pin is chain[0], so a
 * vendor rotation needs no release) and the vendor's rotations, an ordinary chain (SPEC §7). The
 * keeper resolves the chain with sigelo's own `verify` and accepts only an attestation by the
 * chain's CURRENT key: SPEC §5 has an attestation verify under its own `iss` whatever the issuer
 * did later, and says a verifier that knows a DID was rotated away from stops trusting it — the
 * keeper knows, from the chain, so a licence signed by a rotated-away vendor key is refused and
 * the vendor reissues after every rotation. The longest chain seen is kept in vendor-chain.json
 * beside licence.json; a licence whose chain is shorter, or forks from it, is refused unless
 * sigelo's precedence picks it (a recovery rotation supersedes a voluntary one, SPEC §7.1), so a
 * stolen-then-recovered vendor key cannot license anything to a keeper that has seen the
 * recovery. A term (`exp - iat`) above 3 × 366 days, or an `iat` beyond the clock allowance in
 * the future, is refused, so a stolen key's licences end. The legacy file `{attestation, issuer}`
 * (no chain; the issuer must be the pinned genesis) is still accepted, with a warning.
 * All of it is verified OFFLINE (SPEC §9 steps 3 and 5: chain, then signature, `iat <= now <
 * exp`, `sub` in the subject's chain): nothing here opens a socket, and nothing here can stop a payment the
 * free tier makes. Without a valid licence the keeper is the free tier — one keeper, one agent,
 * that agent's whole policy — and the paid verbs (delegation, approvals, receipts export, a
 * second keeper on one host) refuse with `licence_required`, never silently.
 *
 * This is a licence check in MIT code, not DRM: it marks the commercial terms, it does not hide
 * anything from the operator, who holds every key on their own host.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { canonicalize, did, structure, verify, verifySig, type Attestation, type Genesis, type Rotation } from 'sigelo';

/**
 * The vendor's DID, the only `iss` a licence may have. A PLACEHOLDER until D1 (ROADMAP §7): a
 * DID minted for this constant whose secret key was discarded at once, so no licence verifies
 * against it — nobody can issue one. At D1 the Owner mints the vendor identity offline and puts
 * its DID here (and in the release notes). `SIGELO_VENDOR_DID` overrides it: for tests, and for
 * whoever forks the MIT code (who can equally delete this file).
 */
export const DEV_VENDOR_DID = 'did:sigelo:z5xBk2Bp5dDptES9mNJaH68RT8Hm2oqprQdWbbrbVbFKC';
/** Read on every check, not once at load: an operator's environment, or a test's, decides. */
export const vendorDid = (): string => process.env['SIGELO_VENDOR_DID'] || DEV_VENDOR_DID;
export const LICENCE_CTX = 'sigelo-spend';
export const LICENCE_FILE = 'licence.json';
/** The keeper's record of the longest valid vendor chain it has seen (beside licence.json). */
export const CHAIN_FILE = 'vendor-chain.json';
const SEATS_MAX = 10_000;
/** The longest term sold (commercial/issue-licence.mjs DAYS_MAX): a longer `exp - iat` is refused. */
export const TERM_MAX_DAYS = 3 * 366;
/** How far in the future an `iat` may be (a vendor clock a little ahead): service.ts CLOCK_SKEW. */
export const LICENCE_SKEW = 300;
const ROTATIONS_MAX = 256;

/** `rotations` absent: the legacy single-key file (the issuer is the pinned genesis, chain length 1). */
export interface LicenceFile { attestation: Attestation; issuer: Genesis; rotations?: Rotation[] }
export type LicenceStatus =
  | { tier: 'pro'; sub: string; seats: number; iat: number; exp: number; keepers: number; chain: number; legacy: boolean }
  | { tier: 'free'; why: string };

const plain = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const iso = (t: number): string => new Date(t * 1000).toISOString().replace('.000Z', 'Z');
const why = (e: unknown): string => (e instanceof Error ? e.message : String(e));

// ---------------------------------------------------------------- the host's keepers

/**
 * The keepers `sigelo-spend init` set up on this host, in order: `{dir, did, genesis}`. The
 * installer refuses a second keeper without a licence whose `seats` cover it, and a keeper
 * accepts a licence issued to another keeper of this registry when both are in it. Set
 * `SIGELO_SPEND_REGISTRY` to keep it elsewhere (tests do).
 */
export interface KeeperEntry { dir: string; did: string; genesis: Genesis }
export const registryPath = (): string => process.env['SIGELO_SPEND_REGISTRY'] ||
  join(process.env['XDG_CONFIG_HOME'] || join(homedir(), '.config'), 'sigelo-spend', 'keepers.json');
export function readRegistry(): KeeperEntry[] {
  const p = registryPath();
  if (!existsSync(p)) return [];
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(p, 'utf-8')); } catch (e) { throw new Error(`registry: ${p} is not JSON (${why(e)})`); }
  if (!plain(raw) || !Array.isArray(raw['keepers'])) throw new Error(`registry: ${p} has no keepers list`);
  return (raw['keepers'] as unknown[]).flatMap((k) => (plain(k) && typeof k['dir'] === 'string' && typeof k['did'] === 'string' && plain(k['genesis'])
    ? [{ dir: k['dir'], did: k['did'], genesis: k['genesis'] as unknown as Genesis }] : []));
}
/** Registered keepers whose directory still holds a policy: a keeper deleted by hand frees its seat. */
export const liveKeepers = (): KeeperEntry[] => readRegistry().filter((k) => existsSync(join(k.dir, 'policy.json')));
export function register(entry: KeeperEntry): void {
  const p = registryPath();
  const list = readRegistry().filter((k) => resolve(k.dir) !== resolve(entry.dir));
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  writeFileSync(`${p}.new`, JSON.stringify({ keepers: [...list, entry] }, null, 2) + '\n', { mode: 0o600 });
  renameSync(`${p}.new`, p);
}

// ---------------------------------------------------------------- the vendor chain

interface Chain { chain: string[]; head: Genesis; rotations: Rotation[] }
const bundleOf = (genesis: Genesis, rotations: Rotation[]) =>
  ({ v: 'sigelo/0', typ: 'bundle' as const, genesis, rotations, bindings: [], attestations: [], issuers: [] });
/** SPEC §9 step 3 with the library: the chain, its current genesis, and the rotations on its path. */
function resolve0(genesis: Genesis, rotations: Rotation[], now: number): Chain {
  const r = verify(bundleOf(genesis, rotations), now);
  const path = r.chain.slice(1).map((d, i) => rotations.find((x) => x.body.id === r.chain[i] && x.body.next === d && did(x.next_genesis) === d) as Rotation);
  return { chain: r.chain, head: path.length ? path[path.length - 1]!.next_genesis : genesis, rotations: path };
}
const chainPath = (dir: string): string => join(dir, CHAIN_FILE);
/** The chain this keeper has seen, or undefined (none, or one for another vendor than the pin). Throws if unreadable. */
function seenChain(dir: string, vendor: string, now: number): Chain | undefined {
  const p = chainPath(dir);
  if (!existsSync(p)) return undefined;
  const raw = JSON.parse(readFileSync(p, 'utf-8')) as unknown;
  if (!plain(raw) || !plain(raw['genesis']) || !Array.isArray(raw['rotations'])) throw new Error('not {genesis, rotations}');
  structure(raw['genesis'], 'genesis');
  if (did(raw['genesis']) !== vendor) return undefined; // the pin changed: another vendor's record does not bind this one
  return resolve0(raw['genesis'] as unknown as Genesis, raw['rotations'] as Rotation[], now);
}

interface Checked { status: LicenceStatus; chain?: Chain }

function evaluate(raw: unknown, own: Genesis, dir: string, now: number, keepers: KeeperEntry[]): Checked {
  const free = (w: string): Checked => ({ status: { tier: 'free', why: w } });
  const vendor = vendorDid();
  const keys = plain(raw) ? Object.keys(raw).sort().join() : '';
  if (keys !== 'attestation,issuer' && keys !== 'attestation,issuer,rotations') return free('the licence file is not {attestation, issuer, rotations}');
  const r0 = raw as Record<string, unknown>;
  const legacy = !('rotations' in r0);
  const issuer = r0['issuer'], att = r0['attestation'], rots = legacy ? [] : r0['rotations'];
  try { structure(issuer, 'genesis'); } catch (e) { return free(`the licence's issuer is not a genesis (${why(e)})`); }
  const g0 = did(issuer);
  if (g0 !== vendor) return free(legacy ? `the licence is issued by ${g0}, not the vendor ${vendor}` : `the licence's vendor chain starts at ${g0}, not the vendor ${vendor}`);
  if (!Array.isArray(rots) || rots.length > ROTATIONS_MAX) return free(`the licence's rotations are not a list of at most ${ROTATIONS_MAX}`);
  // The vendor's chain, by sigelo's own rules (SPEC §7.3): a fork or a cycle in it rejects it.
  let mine: Chain;
  try { mine = resolve0(issuer as Genesis, rots as Rotation[], now); } catch (e) { return free(`the licence's vendor chain does not verify (${why(e)})`); }
  // Against the chain this keeper has seen: the union of both, resolved again, must end where the licence's does.
  let seen: Chain | undefined;
  try { seen = seenChain(dir, vendor, now); } catch (e) { return free(`${CHAIN_FILE} (the vendor chain this keeper has seen) does not verify (${why(e)}); remove it to start over`); }
  let chain = mine;
  if (seen !== undefined) {
    const have = new Set(seen.rotations.map((x) => canonicalize(x)));
    const union = [...seen.rotations, ...mine.rotations.filter((x) => !have.has(canonicalize(x)))];
    try { chain = resolve0(issuer as Genesis, union, now); } catch (e) {
      return free(`the licence's vendor chain forks from the one this keeper has seen (${why(e)}) — refused; a fork under the vendor's key is resolved by the vendor's recovery rotation`);
    }
    const head = chain.chain[chain.chain.length - 1];
    if (head !== mine.chain[mine.chain.length - 1]) {
      const prefix = mine.chain.every((d, i) => chain.chain[i] === d);
      return free(prefix
        ? `the licence carries a vendor chain of ${mine.chain.length}, shorter than the ${chain.chain.length} this keeper has seen (its key ${head} is current) — ask the vendor to reissue`
        : `the licence's vendor chain forks from the one this keeper has seen (which ends at ${head}) — refused; only a recovery rotation supersedes a seen chain (SPEC §7.1)`);
    }
  }
  const head = did(chain.head);
  if (!plain(att) || Object.keys(att).sort().join() !== 'body,sig' || typeof att['sig'] !== 'string') return free('the licence\'s attestation is not {body, sig}');
  try { structure(att['body'], 'attestation'); } catch (e) { return free(`the licence is not an attestation (${why(e)})`); }
  const body = att['body'] as Attestation['body'];
  // The signature first: a licence edited after issue (seats, exp, sub) is tampered, whatever else it says.
  const nodes = [issuer as Genesis, ...chain.rotations.map((x) => x.next_genesis), ...mine.rotations.map((x) => x.next_genesis)];
  const signer = nodes.find((g) => did(g) === body.iss);
  if (signer === undefined || !verifySig(signer.key, body, att['sig'])) return free('the licence\'s signature does not verify under the vendor key — it was altered after issue, or the vendor never signed it');
  // SPEC §5: a verifier that knows a DID was rotated away from stops trusting it. The keeper knows.
  if (body.iss !== head) return free(`the licence was signed by the vendor's key ${body.iss}, which the vendor has rotated away from (its chain of ${chain.chain.length} now ends at ${head}) — ask the vendor to reissue`);
  if (body.ctx !== LICENCE_CTX) return free(`the licence is for ${JSON.stringify(body.ctx)}, not ${LICENCE_CTX}`);
  const c = body.claims;
  if (!plain(c) || Object.keys(c).sort().join() !== 'seats,tier' || c['tier'] !== 'pro' ||
    !Number.isSafeInteger(c['seats']) || (c['seats'] as number) < 1 || (c['seats'] as number) > SEATS_MAX) return free('the licence\'s claims are not {"tier": "pro", "seats": N}');
  if (body.exp - body.iat > TERM_MAX_DAYS * 86400) return free(`the licence's term (${iso(body.iat)} to ${iso(body.exp)}) is longer than ${TERM_MAX_DAYS} days, the longest sold — refused`);
  if (body.iat > now + LICENCE_SKEW) return free(`the licence is dated ${iso(body.iat)}, more than ${LICENCE_SKEW} s ahead of this host's clock (${iso(now)}) — refused; check this host's clock`);
  if (now >= body.exp) return free(`the licence expired at ${iso(body.exp)}`);
  const me = did(own);
  const here = keepers.some((k) => resolve(k.dir) === resolve(dir));
  const subject = body.sub === me ? own : here ? keepers.find((k) => k.did === body.sub)?.genesis : undefined;
  if (subject === undefined) return free(`the licence is issued to ${body.sub}, not this keeper (${me})${here ? ' nor another keeper registered on this host' : ''}`);
  // The repository's own verifier decides, offline: the same SPEC §9 step 5 every world runs, with
  // the chain's current key as the only known issuer. An `iat` within the allowance is checked at `iat`.
  let accepted: boolean;
  try {
    const r = verify({ ...bundleOf(subject, []), attestations: [att as unknown as Attestation] }, Math.max(now, body.iat), { [head]: chain.head });
    accepted = (r.attestations[head] ?? []).length === 1;
  } catch (e) { return free(`the licence does not verify (${why(e)})`); }
  if (!accepted) return free('the licence does not verify (SPEC §9 step 5)');
  const count = new Set([...keepers.map((k) => resolve(k.dir)), resolve(dir)]).size;
  const seats = c['seats'] as number;
  if (seats < count) return free(`the licence covers ${seats} keeper${seats === 1 ? '' : 's'}; this host runs ${count}`);
  return { status: { tier: 'pro', sub: body.sub, seats, iat: body.iat, exp: body.exp, keepers: count, chain: chain.chain.length, legacy }, chain };
}

// ---------------------------------------------------------------- the check

/**
 * Whether `raw` (a parsed licence file) makes this keeper `pro` at `now`. `own` is this
 * keeper's genesis, `dir` its directory (where vendor-chain.json is read; never written here).
 * A licence names one keeper (`sub`); it covers this one when `sub` is this keeper, or another
 * keeper registered on this host while this one is too, and `seats` is at least how many
 * keepers the host runs. Every refusal says why, in words an operator can act on; the order
 * makes a tampered file read as tampered, not as expired.
 */
export function checkLicence(raw: unknown, own: Genesis, dir: string, now: number, keepers: KeeperEntry[] = liveKeepers()): LicenceStatus {
  return evaluate(raw, own, dir, now, keepers).status;
}

/**
 * Record the vendor chain of a licence that makes this keeper pro, when it is longer than (or,
 * by precedence, supersedes) the one in vendor-chain.json. Atomic; 0600. Returns the status.
 */
export function rememberVendorChain(dir: string, raw: unknown, own: Genesis, now: number, keepers: KeeperEntry[] = liveKeepers()): LicenceStatus {
  const { status, chain } = evaluate(raw, own, dir, now, keepers);
  if (status.tier !== 'pro' || chain === undefined) return status;
  const text = JSON.stringify({ note: 'the longest vendor chain this keeper has seen (spend/licence.ts); a licence with a shorter or forked one is refused', genesis: (raw as LicenceFile).issuer, rotations: chain.rotations }, null, 2) + '\n';
  const p = chainPath(dir);
  let old = '';
  try { old = readFileSync(p, 'utf-8'); } catch { /* none yet */ }
  if (old !== text) {
    try { writeFileSync(`${p}.new`, text, { mode: 0o600 }); renameSync(`${p}.new`, p); } catch { /* a read-only dir: the check still holds for this call */ }
  }
  return status;
}

/** The keeper directory's licence.json, checked (and its vendor chain remembered); no file is the free tier. */
export function readLicence(dir: string, own: Genesis, now: number): LicenceStatus {
  const p = join(dir, LICENCE_FILE);
  if (!existsSync(p)) return { tier: 'free', why: `no ${LICENCE_FILE}` };
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(p, 'utf-8')); } catch (e) { return { tier: 'free', why: `${LICENCE_FILE} is not JSON (${why(e)})` }; }
  let keepers: KeeperEntry[];
  try { keepers = liveKeepers(); } catch { keepers = []; }
  return rememberVendorChain(dir, raw, own, now, keepers);
}

/** One line for the operator: what tier, and why. */
export const describe = (s: LicenceStatus): string => (s.tier === 'pro'
  ? `tier pro (licence to ${s.sub}, ${s.seats} seat${s.seats === 1 ? '' : 's'}, ${s.keepers} in use on this host, until ${iso(s.exp)}; vendor chain length ${s.chain})` +
    (s.legacy ? '; WARNING legacy single-key licence (no vendor chain): accepted, but a vendor rotation would end it — ask the vendor to reissue it in the chain-carrying format' : '')
  : `tier free (${s.why}): one keeper, one agent and its whole policy; delegation, approvals, receipts export and more keepers need a licence`);

/**
 * The refusal of a paid verb (`code: licence_required`, HTTP 403 — every refusal by the keeper
 * is a 403 naming its check, spend/openapi.yaml). Exact, so a client and a test can rely on it.
 */
export const licenceRefusal = (feature: string, s: LicenceStatus): string =>
  `licence_required: ${feature} is a paid feature of sigelo-spend and this keeper has no valid licence (${s.tier === 'free' ? s.why : 'pro'}). ` +
  'The free tier (one keeper, one agent, its whole policy) keeps working; nothing was signed, logged or sent. Operator: sigelo-spend licence show.';
