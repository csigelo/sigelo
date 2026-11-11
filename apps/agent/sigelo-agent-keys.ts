// SPDX-License-Identifier: MIT
/**
 * Key providers (design/key-providers.md §2): where the identity key rests and which process
 * uses it. Every signature of the CLI, the MCP server, the Monero half, the contact verbs and
 * the gate's signer goes through `signer`; the core (sigelo-agent.ts) keeps only the plain-file
 * path, so an identity-only install still reads 75 lines. Counted apart in INTEGRATION.md.
 *
 *   file      `secret` is the hex seed, as in every version (a top-level `"provider": "file"` may say so),
 *             or that seed sealed under a passphrase (`sigelo-seal/1`, KEYCHAIN.md)
 *   keychain  `secret` is the seed sealed under a key in the OS store (sigelo-agent-keychain.ts)
 *   agent     `secret` is `{ "provider": "agent" }`: sigelo-key-agent holds it (sigelo-agent-keyclient.ts, K3)
 *
 * Fail closed, by name (§2.5): no provider falls back to another, an unknown one is refused
 * before anything is read or written, and every signature is checked against the head genesis
 * key before it leaves (`key_mismatch`).
 */
import { copyFileSync, existsSync, readFileSync } from 'node:fs';
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, randomBytes, scryptSync, sign as edSign, verify as edVerify } from 'node:crypto';
import type { Genesis, Rotation } from 'sigelo';
import { decodeKey, did, keygen, rotate as rotation, sign, SigeloError, verifySig, VERSION } from 'sigelo';
import { challengeDid, head, load, rotateKey, save, secretOf, type Store } from './sigelo-agent.ts';
import { withLock } from './sigelo-agent-monero.ts';
import * as keychain from './sigelo-agent-keychain.ts';
import { request, socketPath } from './sigelo-agent-keyclient.ts';

export type Env = Record<string, string | undefined>;
export type Provider = 'file' | 'keychain' | 'agent';
/**
 * One identity's signing side. `sign` takes a BODY and builds "sigelo\n" ‖ JCS(body) itself (SPEC §3).
 * `signHttp` is the one other input: an RFC 9421 signature base for Web Bot Auth
 * (apps/integrations/web-bot-auth), checked by `httpBase` first; it returns base64.
 */
export interface Signer { did: string; key: string; sign(body: object): string; signHttp(base: string): string }
const PROVIDERS: string[] = ['file', 'keychain', 'agent'];
/** The operator identity `keeper --from-words` makes (sigelo-agent-enrol.ts): seed-derived. */
type Derived = { derived?: { path: string; n: number } };

/** A refusal by its §2.5 code: the message starts with it and `.check` carries it (the MCP server's `code`). */
export function fail(code: string, detail: string): never {
  throw Object.assign(new SigeloError(`${code}: ${detail}`), { check: code });
}

/** Where this identity's key rests (§2.2): a hex `secret` is `file`, an object names its provider, and a top-level `provider` must agree. */
export function providerOf(s: Store): Provider {
  const p = typeof s.secret === 'string' ? 'file' : (s.secret as { provider?: unknown } | null)?.provider;
  if (typeof p !== 'string' || !PROVIDERS.includes(p)) fail('key_provider_unknown', `the identity file's secret names provider ${JSON.stringify(p)}; this sigelo-agent knows ${PROVIDERS.join(', ')}`);
  if (s.provider !== undefined && s.provider !== p) fail('key_provider_unknown', `the identity file says provider ${JSON.stringify(s.provider)} but holds a ${p} key`);
  return p as Provider;
}

/** The provider, refused when SIGELO_KEY_AGENT says this process holds no key but the file still holds one (§4.5). */
function using(path: string, s: Store, env: Env): Provider {
  const p = providerOf(s);
  if (env['SIGELO_KEY_AGENT'] && p !== 'agent') fail('key_agent_mismatch', `SIGELO_KEY_AGENT is set but ${path} still holds the key (${p}): move it (sigelo-agent keys to-agent), or unset SIGELO_KEY_AGENT`);
  return p;
}

// ── a sealed file (KEYCHAIN.md): provider `file`, the seed under a passphrase ─────────────
//   secret = { provider: "file", v: "sigelo-seal/1", kdf: "scrypt", n, r, p, salt, nonce, ct }
//   key = scrypt(passphrase, salt (32 bytes), N = n, r, p, 32 bytes); ct = AES-256-GCM(key, nonce
//   (12 bytes), seed, AAD "sigelo-seal/1\nscrypt <n> <r> <p>\n" ‖ head genesis key) ‖ 16-byte tag.
// The passphrase: SIGELO_IDENTITY_PASSPHRASE_FILE (a file, one trailing newline dropped: a Docker
// secret) or SIGELO_IDENTITY_PASSPHRASE (the environment: weaker, any child process inherits it).
// The scrypt key is kept per salt for this process's life (one derivation, 128 MiB, per start).
export interface SealedSecret { provider: 'file'; v: 'sigelo-seal/1'; kdf: 'scrypt'; n: number; r: number; p: number; salt: string; nonce: string; ct: string }
const SEAL_V = 'sigelo-seal/1', SCRYPT = { n: 1 << 17, r: 8, p: 1 }, PASS_MIN = 8;
const PASS_ENV = 'set SIGELO_IDENTITY_PASSPHRASE_FILE=<file> (a Docker secret) or SIGELO_IDENTITY_PASSPHRASE';
const derived = new Map<string, Buffer>();
/** Is the key of `s` a sealed file key? */
export const isSealed = (s: Store): boolean => typeof s.secret === 'object' && s.secret !== null && (s.secret as { v?: unknown }).v === SEAL_V;
/** The passphrase: `--passphrase-file` (`file`), else the environment; null when none is set. */
export function passphrase(env: Env = process.env, file?: string): Buffer | null {
  const f = file ?? env['SIGELO_IDENTITY_PASSPHRASE_FILE'], v = env['SIGELO_IDENTITY_PASSPHRASE'];
  if (file === undefined && f && v) fail('passphrase_ambiguous', 'both SIGELO_IDENTITY_PASSPHRASE_FILE and SIGELO_IDENTITY_PASSPHRASE are set: keep one');
  let b: Buffer;
  if (f) { try { b = readFileSync(f); } catch (e) { return fail('passphrase_file', `${f}: ${(e as Error).message}`); } b = b.subarray(0, b.length - (b.at(-1) === 10 ? (b.at(-2) === 13 ? 2 : 1) : 0)); }
  else if (v) b = Buffer.from(v, 'utf8');
  else return null;
  return b.length ? b : fail('passphrase_empty', `the passphrase ${f ? `in ${f} ` : ''}is empty`);
}
const needPass = (env: Env, why: string, file?: string): Buffer => passphrase(env, file) ?? fail('passphrase_required', `${why}: ${PASS_ENV}`);
const unb = (x: unknown, n: number, what: string): Buffer => {
  const b = typeof x === 'string' && /^[A-Za-z0-9_-]+$/.test(x) ? Buffer.from(x, 'base64url') : Buffer.alloc(0);
  return b.length === n ? b : fail('seal_invalid', `${what} is not ${n} bytes of base64url`);
};
function sealKey(w: Pick<SealedSecret, 'n' | 'r' | 'p' | 'salt'>, pass: Buffer): Buffer {
  const id = `${w.n} ${w.r} ${w.p} ${w.salt} ${createHash('sha256').update(pass).digest('hex')}`;
  let k = derived.get(id);
  if (!k) { k = scryptSync(pass, unb(w.salt, 32, 'salt'), 32, { N: w.n, r: w.r, p: w.p, maxmem: 256 * 1024 * 1024 }); derived.set(id, k); }
  return k;
}
const sealAad = (w: Pick<SealedSecret, 'n' | 'r' | 'p'>, s: Store): Buffer => Buffer.from(`${SEAL_V}\nscrypt ${w.n} ${w.r} ${w.p}\n${head(s).key}`, 'utf8');
/** Seal `seed` for the head key of `s`; a sealed `s` keeps its salt (a rotation re-seals under the same key). */
export function sealSeed(seed: Uint8Array, s: Store, pass: Buffer): SealedSecret {
  const prev = isSealed(s) ? (s.secret as SealedSecret) : undefined;
  const h = prev ? { n: prev.n, r: prev.r, p: prev.p, salt: prev.salt } : { ...SCRYPT, salt: randomBytes(32).toString('base64url') };
  const nonce = randomBytes(12), c = createCipheriv('aes-256-gcm', sealKey(h, pass), nonce).setAAD(sealAad(h, s));
  const out: SealedSecret = { provider: 'file', v: SEAL_V, kdf: 'scrypt', ...h, nonce: nonce.toString('base64url'), ct: Buffer.concat([c.update(seed), c.final(), c.getAuthTag()]).toString('base64url') };
  unsealSeed({ ...s, secret: out }, pass).fill(0);   // read back before anything is saved
  return out;
}
/** The seed of a sealed `s`, checked against its head key; the caller zeroes it. */
export function unsealSeed(s: Store, pass: Buffer): Uint8Array {
  const w = s.secret as Partial<SealedSecret>;
  if (w.kdf !== 'scrypt' || !Number.isSafeInteger(w.n) || w.n! < 1 << 15 || w.n! > 1 << 20 || (w.n! & (w.n! - 1)) !== 0 || w.r !== 8 || w.p !== 1) fail('seal_invalid', `a ${SEAL_V} secret with kdf ${JSON.stringify(w.kdf)} n ${w.n} r ${w.r} p ${w.p}: this sigelo-agent reads scrypt, n a power of two from 2^15 to 2^20, r 8, p 1`);
  const nonce = unb(w.nonce, 12, 'nonce'), ct = unb(w.ct, 48, 'ct'), d = createDecipheriv('aes-256-gcm', sealKey(w as SealedSecret, pass), nonce).setAAD(sealAad(w as SealedSecret, s));
  d.setAuthTag(ct.subarray(32));
  const seed = new Uint8Array(d.update(ct.subarray(0, 32)));
  try { d.final(); } catch { seed.fill(0); fail('passphrase_wrong', 'the sealed key does not open with this passphrase (or the identity file was changed)'); }
  if (!verifySig(head(s).key, { v: SEAL_V, typ: 'probe' }, sign(seed, { v: SEAL_V, typ: 'probe' }))) { seed.fill(0); fail('key_mismatch', `the unsealed seed does not sign for ${did(head(s))}`); }
  return seed;
}

/** The seed of `s` in its own form (plain, sealed, keychain); the caller zeroes it. */
export function seedOf(s: Store, env: Env = process.env): Uint8Array {
  if (providerOf(s) !== 'file') return keychain.unwrap(s);
  return isSealed(s) ? unsealSeed(s, needPass(env, 'the identity key is sealed')) : secretOf(s);
}
/** The in-process forms: the seed for one call, zeroed after; nothing is cached (a sealed file's scrypt key is, above). */
function withSeed<T>(s: Store, fn: (seed: Uint8Array) => T, env: Env = process.env): T {
  const seed = seedOf(s, env);
  try { return fn(seed); } finally { seed.fill(0); }
}
let warned = false;
/** A plain-hex key: said on stderr once per process, every start. */
function plainWarning(path: string, s: Store): void {
  if (warned || providerOf(s) !== 'file' || isSealed(s)) return;
  warned = true;
  console.error(`sigelo-agent: identity key in plain hex at ${path}; set SIGELO_KEY_PROVIDER=keychain|agent or seal it: sigelo-agent seal --passphrase-file <file>`);
}

/**
 * The only raw bytes this key signs: an RFC 9421 signature base (§2.5) whose last line is the
 * `"@signature-params"` tagged `web-bot-auth` or `http-message-signatures-directory`. Every line of
 * such a base starts with `"` (0x22), a sigelo signing input with `s` (0x73, SPEC §3), so no input
 * of one kind is ever an input of the other. Printable ASCII and LF only.
 */
export function httpBase(base: string): Buffer {
  const last = base.slice(base.lastIndexOf('\n') + 1);
  if (!/^"[\x20-\x7e\n]*$/.test(base) || !last.startsWith('"@signature-params": (') || !/;tag="(web-bot-auth|http-message-signatures-directory)"(;|$)/.test(last))
    fail('http_base', 'not an RFC 9421 signature base tagged web-bot-auth or http-message-signatures-directory: refusing to sign it');
  return Buffer.from(base, 'ascii');
}
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex'), SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const edRaw = (seed: Uint8Array, msg: Buffer): string => {
  const der = Buffer.concat([PKCS8, seed]);
  try { return edSign(null, msg, createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })).toString('base64'); } finally { der.fill(0); }
};

/** The signer for the identity `s`, read from `path`. */
export function signer(path: string, s: Store, env: Env = process.env): Signer {
  const p = using(path, s, env), g = head(s), d = did(g);
  plainWarning(path, s);
  const raw = p === 'agent' ? (body: object) => request({ op: 'sign', did: d, body }, env)['sig'] : (body: object) => withSeed(s, (seed) => sign(seed, body), env);
  const mismatch = (): never => fail('key_mismatch', `the ${p} key of ${path} does not sign for ${d}, its head genesis key: the file or its key store was changed`);
  return { did: d, key: g.key, sign: (body) => {
    const sig = raw(body);
    if (typeof sig !== 'string' || !verifySig(g.key, body, sig)) return mismatch();
    return sig;
  }, signHttp: (base) => {
    const msg = httpBase(base);
    if (p === 'agent') fail('key_provider_unbuilt', 'the key agent signs sigelo bodies only: sign-http needs a file or keychain key');
    const sig = withSeed(s, (seed) => edRaw(seed, msg), env);
    if (!edVerify(null, msg, createPublicKey({ key: Buffer.concat([SPKI, decodeKey(g.key)]), format: 'der', type: 'spki' }), Buffer.from(sig, 'base64'))) return mismatch();
    return sig;
  } };
}

/** `sign-challenge` and `sigelo_sign_challenge`: the core's checks (challengeDid), then the signer. */
export const signChallenge = (path: string, s: Store, body: Record<string, unknown>, env: Env = process.env): { did: string; sig: string } =>
  ({ did: challengeDid(s, body), sig: signer(path, s, env).sign(body) });

/**
 * A new identity in the form `provider` names (SIGELO_KEY_PROVIDER), checked before anything is
 * written. Unset (plan §8.3, decided): `keychain` where an OS store answers, else `file` with
 * `"provider": "file"` and one warning line; `keychain` named outright fails closed without one.
 * A passphrase (`passFile`, or the environment's) makes it a sealed `file`, whatever answers.
 */
export function init(path: string, recovery: string | null, provider?: string, env: Env = process.env, passFile?: string): Store {
  if (provider !== undefined && !PROVIDERS.includes(provider)) fail('key_provider_unknown', `SIGELO_KEY_PROVIDER is ${JSON.stringify(provider)}; use ${PROVIDERS.join(', ')}`);
  if (existsSync(path)) throw new SigeloError(`init: ${path} already holds an identity — refusing to overwrite it`);
  const pass = passphrase(env, passFile);
  if (pass && provider !== undefined && provider !== 'file') fail('passphrase_provider', `a passphrase seals a file key, and SIGELO_KEY_PROVIDER is ${provider}: unset one of them`);
  if (pass && pass.length < PASS_MIN) fail('passphrase_short', `a passphrase of at least ${PASS_MIN} bytes seals a new file`);
  if (pass) provider = 'file';
  provider ??= keychain.answers(keychain.systemKeychain(env)) ? 'keychain' : (console.error('sigelo-agent: no OS keychain answers here, so the key is a plain file ("provider": "file"); see `sigelo-agent keys wrap`, or `sigelo-agent seal`'), 'file');
  let store: Store;
  if (provider === 'agent') {
    const genesis = request({ op: 'create', recovery }, env)['genesis'] as Genesis;
    store = { v: VERSION, provider, secret: { provider }, genesis, rotations: [], attestations: [], issuers: [] };
  } else {
    const id = keygen({ recovery });
    store = { v: VERSION, provider, secret: '', genesis: id.genesis, rotations: [], attestations: [], issuers: [] };
    try { store.secret = provider !== 'file' ? keychain.wrap(id.secret, store, keychain.systemKeychain(env)) : pass ? sealSeed(id.secret, store, pass) : Buffer.from(id.secret).toString('hex'); } finally { id.secret.fill(0); }
  }
  save(path, store);
  return store;
}

/** Voluntary rotation in the key's own form (SPEC §7): the rotation is appended and `s.secret` becomes the new key's at-rest form; the caller saves both in one write. */
export function rotate(path: string, s: Store, now: number, env: Env = process.env): Store {
  const d = (s as Derived).derived;
  if (d) throw new SigeloError(`rotate: this identity comes from your 25 words (${d.path}): a random key would not. Its next key is rotation ${d.n + 1} of them: sigelo-agent keeper --from-words --rotate-me`);
  const p = using(path, s, env);
  if (p === 'file' && !isSealed(s)) return rotateKey(s, now);
  if (p === 'agent') { s.rotations.push(request({ op: 'rotate', did: did(head(s)), to: 'software' }, env)['rotation'] as Rotation); return s; }
  const cur = head(s), fresh = keygen({ recovery: cur.recovery });
  try {
    s.rotations.push(withSeed(s, (secret) => rotation({ genesis: cur, next_genesis: fresh.genesis, iat: now, reason: 'voluntary', secret, next_secret: fresh.secret }), env));
    s.secret = p === 'file' ? sealSeed(fresh.secret, s, needPass(env, 'rotate: the identity key is sealed')) : keychain.wrap(fresh.secret, s);
  } finally { fresh.secret.fill(0); }
  return s;
}

/** After the caller wrote an agent rotation: the agent drops the old key (§4.4). Best effort: the rotation
 *  is written, and the next request naming the new DID commits it anyway; an error here must not
 *  read as a failed rotation, which a retry would turn into a second one. */
export const commit = (s: Store, env: Env = process.env): void => { try { if (providerOf(s) === 'agent') request({ op: 'commit', did: did(head(s)) }, env); } catch { /* above */ } };

/** `keys to-agent`: the seed into the agent (a retry finds it held), checked there, then the file says `{"provider":"agent"}`. */
const toAgent = (path: string, env: Env): object => withLock(path, () => {
  const s = load(path), p = providerOf(s), g = head(s), d = did(g);
  if (p === 'agent') fail('key_provider_required', `keys to-agent: ${path} holds no key: the agent has it already`);
  withSeed(s, (seed) => { try { request({ op: 'import', genesis: g, seed: Buffer.from(seed).toString('hex') }, env); } catch (e) { if ((e as { check?: string }).check !== 'key_held') throw e; } }, env);
  if (request({ op: 'pubkey', did: d }, env)['key'] !== g.key) fail('key_mismatch', `the key agent holds another key for ${d}; ${path} is unchanged`);
  save(path, Object.assign(s, { provider: 'agent', secret: { provider: 'agent' } }));
  return { did: d, provider: 'agent', file: path, key_agent: socketPath(env), note: 'older copies of the file (backups, sync folders) still hold the key: rotate if one may have leaked' };
});

/**
 * `seal` and `unseal`: a plain file key <-> sealed under a passphrase, in place, under the file's
 * lock, one atomic write. `keepPlain` (seal) keeps the plain file as `<file>.bak` (0600) first.
 */
export function sealFile(path: string, verb: 'seal' | 'unseal', o: { passFile?: string; keepPlain?: boolean } = {}, env: Env = process.env): object {
  return withLock(path, () => {
    const s = load(path), p = providerOf(s);
    if (p !== 'file') fail('key_provider_required', `${verb}: ${path} holds a ${p} key; ${verb} moves a file key (keys unwrap --plain first)`);
    if (isSealed(s) === (verb === 'seal')) fail('key_provider_required', `${verb}: ${path} is ${verb === 'seal' ? 'sealed already' : 'not sealed'}`);
    const pass = needPass(env, `${verb} needs the passphrase: --passphrase-file <file>, or`, o.passFile);
    let bak: string | undefined;
    if (verb === 'seal') {
      if (pass.length < PASS_MIN) fail('passphrase_short', `a passphrase of at least ${PASS_MIN} bytes`);
      if (o.keepPlain) { bak = `${path}.bak`; if (existsSync(bak)) fail('backup_exists', `${bak} exists: move it away first`); copyFileSync(path, bak); }
      const seed = secretOf(s);
      try { s.secret = sealSeed(seed, s, pass); } finally { seed.fill(0); }
    } else {
      const seed = unsealSeed(s, pass);
      try { s.secret = Buffer.from(seed).toString('hex'); } finally { seed.fill(0); }
    }
    save(path, Object.assign(s, { provider: 'file' }));
    return { did: did(head(s)), provider: 'file', sealed: verb === 'seal', file: path, ...(bak && { plain_copy: bak }),
      ...(verb === 'seal' && { note: `older copies of the file (${bak ? `${bak}, ` : ''}backups, sync folders) still hold the key in plain hex: delete them, or rotate if one may have leaked` }) };
  });
}
/** `adopt --rotation` writes a plain new key: sealed again here when the file was sealed. */
export function sealAgain(s: Store, env: Env = process.env): Store {
  const seed = secretOf(s);
  try { s.secret = sealSeed(seed, s, needPass(env, 'adopt --rotation: the identity file was sealed')); } finally { seed.fill(0); }
  return Object.assign(s, { provider: 'file' });
}

export const USAGE = `Where the identity key rests (identity file field "provider"):
  keys status                            the key's form, and whether it signs for the current DID;
                                         never prints key material
  keys wrap | keys unwrap --plain        seal the key under a key in the OS store (macOS keychain,
                                         Secret Service, DPAPI) | write it back as plain hex
  keys to-agent                          move the key into sigelo-key-agent (SIGELO_KEY_AGENT, else its
                                         default socket); the file then says {"provider":"agent"}
  seal [--passphrase-file <f>] [--keep-plain]  seal a plain file key under a passphrase (scrypt,
                                         AES-256-GCM; KEYCHAIN.md); --keep-plain: <file>.bak
  unseal [--passphrase-file <f>]         write it back as plain hex
  A sealed file is read with SIGELO_IDENTITY_PASSPHRASE_FILE=<f> (a Docker secret) or
  SIGELO_IDENTITY_PASSPHRASE (weaker: inherited by every child process)`;

/** `sigelo-agent keys <verb>`. null: no such verb (usage, exit 2). */
export function main(args: string[], path: string, s: Store, env: Env = process.env): object | null {
  const verb = args[0];
  if (verb === 'status' || verb === 'show') {
    const p = providerOf(s), d = did(head(s));
    let code = 'ok';   // an agent signs no probe body (§4.3): its key for this DID must be the head key
    try { if (p !== 'agent') signer(path, s, env).sign({ v: 'sigelo-keys/0', typ: 'probe', did: d }); else if (request({ op: 'pubkey', did: d }, env)['key'] !== head(s).key) fail('key_mismatch', d); } catch (e) { code = (e as { check?: string }).check ?? 'error'; }
    return { did: d, provider: p, ...(isSealed(s) && { sealed: true }), file: path, key_agent: env['SIGELO_KEY_AGENT'] ?? null, signs: code === 'ok', ...(code !== 'ok' && { code }) };
  }
  if (verb === 'wrap' || verb === 'unwrap') return keychain.move(path, verb, args.includes('--plain'), keychain.systemKeychain(env));
  if (verb === 'to-agent') return toAgent(path, env);
  return null;
}
