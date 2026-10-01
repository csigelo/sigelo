/**
 * sigelo-spend — the licence (spend/README.md "Install", "Free and paid").
 *
 * A licence is a sigelo attestation (SPEC §5): issued by the vendor's DID (`iss`) to the
 * customer's keeper DID (`sub`), `ctx: "sigelo-spend"`, `claims: {tier: "pro", seats: N}`, with
 * an `exp`. The file next to policy.json is `{attestation, issuer}`: the signed attestation and
 * the vendor's genesis, which must hash to `vendorDid()`. It is verified OFFLINE, with sigelo's
 * own `verify` (SPEC §9 step 5: signature by the issuer's genesis key, `iat <= now < exp`, `sub`
 * in the subject's chain): nothing here opens a socket, and nothing here can stop a payment the
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
import { did, structure, verify, verifySig, type Attestation, type Genesis } from 'sigelo';

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
const SEATS_MAX = 10_000;

export interface LicenceFile { attestation: Attestation; issuer: Genesis }
export type LicenceStatus =
  | { tier: 'pro'; sub: string; seats: number; iat: number; exp: number; keepers: number }
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

// ---------------------------------------------------------------- the check

/**
 * Whether `raw` (a parsed licence file) makes this keeper `pro` at `now`. `own` is this
 * keeper's genesis, `dir` its directory. A licence names one keeper (`sub`); it covers this one
 * when `sub` is this keeper, or another keeper registered on this host while this one is too,
 * and `seats` is at least how many keepers the host runs. Every refusal says why, in words an
 * operator can act on; the order makes a tampered file read as tampered, not as expired.
 */
export function checkLicence(raw: unknown, own: Genesis, dir: string, now: number, keepers: KeeperEntry[] = liveKeepers()): LicenceStatus {
  const free = (w: string): LicenceStatus => ({ tier: 'free', why: w });
  const vendor = vendorDid();
  if (!plain(raw) || Object.keys(raw).sort().join() !== 'attestation,issuer') return free('the licence file is not {attestation, issuer}');
  const issuer = raw['issuer'], att = raw['attestation'];
  try { structure(issuer, 'genesis'); } catch (e) { return free(`the licence's issuer is not a genesis (${why(e)})`); }
  const iss = did(issuer);
  if (iss !== vendor) return free(`the licence is issued by ${iss}, not the vendor ${vendor}`);
  if (!plain(att) || Object.keys(att).sort().join() !== 'body,sig' || typeof att['sig'] !== 'string') return free('the licence\'s attestation is not {body, sig}');
  try { structure(att['body'], 'attestation'); } catch (e) { return free(`the licence is not an attestation (${why(e)})`); }
  const body = att['body'] as Attestation['body'];
  // The signature first: a licence edited after issue (seats, exp, sub) is tampered, whatever else it says.
  if (body.iss !== vendor || !verifySig((issuer as Genesis).key, body, att['sig'])) return free('the licence\'s signature does not verify under the vendor key — it was altered after issue, or the vendor never signed it');
  if (body.ctx !== LICENCE_CTX) return free(`the licence is for ${JSON.stringify(body.ctx)}, not ${LICENCE_CTX}`);
  const c = body.claims;
  if (!plain(c) || Object.keys(c).sort().join() !== 'seats,tier' || c['tier'] !== 'pro' ||
    !Number.isSafeInteger(c['seats']) || (c['seats'] as number) < 1 || (c['seats'] as number) > SEATS_MAX) return free('the licence\'s claims are not {"tier": "pro", "seats": N}');
  if (now >= body.exp) return free(`the licence expired at ${iso(body.exp)}`);
  if (now < body.iat) return free(`the licence is not valid before ${iso(body.iat)} (check this host's clock)`);
  const me = did(own);
  const here = keepers.some((k) => resolve(k.dir) === resolve(dir));
  const subject = body.sub === me ? own : here ? keepers.find((k) => k.did === body.sub)?.genesis : undefined;
  if (subject === undefined) return free(`the licence is issued to ${body.sub}, not this keeper (${me})${here ? ' nor another keeper registered on this host' : ''}`);
  // The repository's own verifier decides, offline: the same SPEC §9 step 5 every world runs.
  let accepted: boolean;
  try {
    const r = verify({ v: 'sigelo/0', typ: 'bundle', genesis: subject, rotations: [], bindings: [], attestations: [att as unknown as Attestation], issuers: [] }, now, { [vendor]: issuer as Genesis });
    accepted = (r.attestations[vendor] ?? []).length === 1;
  } catch (e) { return free(`the licence does not verify (${why(e)})`); }
  if (!accepted) return free('the licence does not verify (SPEC §9 step 5)');
  const count = new Set([...keepers.map((k) => resolve(k.dir)), resolve(dir)]).size;
  const seats = c['seats'] as number;
  if (seats < count) return free(`the licence covers ${seats} keeper${seats === 1 ? '' : 's'}; this host runs ${count}`);
  return { tier: 'pro', sub: body.sub, seats, iat: body.iat, exp: body.exp, keepers: count };
}

/** The keeper directory's licence.json, checked; no file is the free tier. */
export function readLicence(dir: string, own: Genesis, now: number): LicenceStatus {
  const p = join(dir, LICENCE_FILE);
  if (!existsSync(p)) return { tier: 'free', why: `no ${LICENCE_FILE}` };
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(p, 'utf-8')); } catch (e) { return { tier: 'free', why: `${LICENCE_FILE} is not JSON (${why(e)})` }; }
  let keepers: KeeperEntry[];
  try { keepers = liveKeepers(); } catch { keepers = []; }
  return checkLicence(raw, own, dir, now, keepers);
}

/** One line for the operator: what tier, and why. */
export const describe = (s: LicenceStatus): string => (s.tier === 'pro'
  ? `tier pro (licence to ${s.sub}, ${s.seats} seat${s.seats === 1 ? '' : 's'}, ${s.keepers} in use on this host, until ${iso(s.exp)})`
  : `tier free (${s.why}): one keeper, one agent and its whole policy; delegation, approvals, receipts export and more keepers need a licence`);

/**
 * The refusal of a paid verb (`code: licence_required`, HTTP 403 — every refusal by the keeper
 * is a 403 naming its check, spend/openapi.yaml). Exact, so a client and a test can rely on it.
 */
export const licenceRefusal = (feature: string, s: LicenceStatus): string =>
  `licence_required: ${feature} is a paid feature of sigelo-spend and this keeper has no valid licence (${s.tier === 'free' ? s.why : 'pro'}). ` +
  'The free tier (one keeper, one agent, its whole policy) keeps working; nothing was signed, logged or sent. Operator: sigelo-spend licence show.';
