// SPDX-License-Identifier: MIT
/**
 * Provider `keychain` (design/key-providers.md §3): the seed sealed in the identity file under a
 * random 32-byte file key that the OS store holds (macOS keychain, Secret Service, DPAPI).
 *
 *   ct = ChaCha20-Poly1305 (RFC 8439)(file key, 12-byte nonce, seed, AAD "sigelo-wrap/1\n" ‖ head genesis key)
 *
 * The AAD is the head genesis `key` string as UTF-8 (the multibase "z6Mk…"), so a seed sealed for
 * one key never opens for another; fixtures/wrap-v1.json is the vector. The file key is written
 * to the store once per identity (service `sigelo`, account = the original DID); a rotation
 * re-seals the new seed under it, so file and store never disagree and either alone is useless.
 * Nothing is cached; the caller zeroes the seed. Secrets cross to a store's tool on stdin and
 * stdout only, never in argv or the environment. No store falls back to another or to a plain
 * key: `keychain_unavailable`, `keychain_missing`, `wrap_auth`, by name (§2.5).
 */
import { spawnSync } from 'node:child_process';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { did, sign, SigeloError, verifySig } from 'sigelo';
import { head, load, save, secretOf, type Store } from './sigelo-agent.ts';
import { withLock } from './sigelo-agent-monero.ts';

type Env = Record<string, string | undefined>;
export type StoreName = 'macos' | 'secret-service' | 'dpapi';
/** The `secret` field of a wrapped identity file (§2.2). */
export interface WrappedSecret { provider: 'keychain'; v: 'sigelo-wrap/1'; store: StoreName; account: string; nonce: string; ct: string; dpapi?: string }
/**
 * One OS store, injectable as the ceremony injects `Age`: the file key under service `sigelo`,
 * account = the original DID. DPAPI keeps no item: `write` returns the blob the file carries in
 * `dpapi`, and `read` takes it back. A read with no item throws `keychain_missing`; a store that
 * is absent, locked or silent throws `keychain_unavailable`.
 */
export interface Keychain { store: StoreName; read(account: string, blob?: string): Uint8Array; write(account: string, key: Uint8Array): string | undefined; remove(account: string): void }
/** How a store's tool runs (the spawn spy of test-keychain.ts replaces it). */
export type Run = (cmd: string, args: string[], input: string, env: Env) => { status: number | null; stdout: string; stderr: string; error?: Error };

const V = 'sigelo-wrap/1', SERVICE = 'sigelo', PROBE = { v: 'sigelo-wrap/1', typ: 'probe' };
const refuse = (code: string, detail: string): never => { throw Object.assign(new SigeloError(`${code}: ${detail}`), { check: code }); };
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const unb64u = (s: unknown, n: number, what: string, code = 'wrap_auth'): Buffer => {
  const b = typeof s === 'string' && /^[A-Za-z0-9_-]+$/.test(s) ? Buffer.from(s, 'base64url') : Buffer.alloc(0);
  return b.length === n ? b : refuse(code, `${what} is not ${n} bytes of base64url`);
};
// An account goes into argv and into `security -i`'s command line: a DID's characters only.
const acct = (a: unknown): string => (typeof a === 'string' && /^[A-Za-z0-9:._-]{1,200}$/.test(a) ? a : refuse('wrap_auth', `account ${JSON.stringify(a)} is not a DID`));
const aad = (s: Store): Buffer => Buffer.from(`${V}\n${head(s).key}`, 'utf8');

/** RFC 8439 §2.8 AEAD: ciphertext ‖ 16-byte tag. Exported for the vector test. */
export function seal(key: Uint8Array, nonce: Uint8Array, plain: Uint8Array, ad: Uint8Array): Buffer {
  const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 }).setAAD(ad, { plaintextLength: plain.length });
  return Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
}
function open(key: Uint8Array, nonce: Uint8Array, ct: Buffer, ad: Uint8Array, what: string): Uint8Array {
  const d = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 }).setAAD(ad, { plaintextLength: ct.length - 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  const out = d.update(ct.subarray(0, ct.length - 16));
  try { d.final(); return out; } catch { out.fill(0); return refuse('wrap_auth', `the sealed seed does not open with ${what}: another item, or the identity file was changed`); }
}

const spawnRun: Run = (cmd, args, input, env) => {
  const r = spawnSync(cmd, args, { input, env, encoding: 'utf8', timeout: 60_000, windowsHide: true });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '', ...(r.error && { error: r.error }) };
};
/** One tool call; no answer at all (absent tool, timeout) is `keychain_unavailable`. Never echoes stdin or stdout. */
const caller = (store: StoreName, run: Run, env: Env) => (cmd: string, args: string[], input = '') => {
  const r = run(cmd, args, input, env);
  const down = (why = r.stderr.trim().split('\n')[0] || `exit ${r.status}`): never => refuse('keychain_unavailable', `${store}: ${cmd} ${args[0]}: ${why}`);
  if (r.error || r.status === null) down(r.error?.message ?? 'no answer');
  return { ...r, down };
};
const missing = (store: StoreName, a: string): never => refuse('keychain_missing', `${store} holds no sigelo item for ${a}: wrapped on another machine or user? unwrap it there (keys unwrap --plain)`);
const fileKey = (t: string): Uint8Array => unb64u(t.trim(), 32, 'the store\'s item');

const macos = (x: ReturnType<typeof caller>): Keychain => ({
  store: 'macos',
  read: (a) => { const r = x('security', ['find-generic-password', '-s', SERVICE, '-a', acct(a), '-w']); if (r.status === 44) missing('macos', a); return r.status === 0 ? fileKey(r.stdout) : r.down(); },
  // `security -i` reads the command from stdin: the key never reaches argv. -T "": no app is trusted to read it without asking (§6).
  write: (a, k) => { const r = x('security', ['-i'], `add-generic-password -U -s ${SERVICE} -a ${acct(a)} -T "" -w ${b64u(k)}\n`); return r.status === 0 && !/error/i.test(r.stderr) ? undefined : r.down(); },
  remove: (a) => { const r = x('security', ['delete-generic-password', '-s', SERVICE, '-a', acct(a)]); if (r.status !== 0 && r.status !== 44) r.down(); },
});
// secret-tool exits 1 and says nothing when the store answers without an item; a store that does not answer says why.
const secretService = (x: ReturnType<typeof caller>): Keychain => ({
  store: 'secret-service',
  read: (a) => { const r = x('secret-tool', ['lookup', 'service', SERVICE, 'account', acct(a)]); if (r.status === 1 && !r.stderr.trim()) missing('secret-service', a); return r.status === 0 ? fileKey(r.stdout) : r.down(); },
  write: (a, k) => { const r = x('secret-tool', ['store', '--label=sigelo key wrap', 'service', SERVICE, 'account', acct(a)], b64u(k)); return r.status === 0 ? undefined : r.down(); },
  remove: (a) => { const r = x('secret-tool', ['clear', 'service', SERVICE, 'account', acct(a)]); if (r.stderr.trim()) r.down(); },
});
// PowerShell 5.1 and 7: ConvertFrom/To-SecureString use DPAPI, current user, when given no key [S6]. The script holds no secret.
const ps = (script: string): string[] => ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')];
const PROTECT = '$k=[Console]::In.ReadToEnd(); [Console]::Out.Write((ConvertTo-SecureString $k -AsPlainText -Force | ConvertFrom-SecureString))';
const UNPROTECT = '$b=[Console]::In.ReadToEnd().Trim(); if(-not $b){exit 3}; try{$s=ConvertTo-SecureString $b -ErrorAction Stop}catch{exit 4}; $M=[Runtime.InteropServices.Marshal]; $p=$M::SecureStringToBSTR($s); try{[Console]::Out.Write($M::PtrToStringBSTR($p))}finally{$M::ZeroFreeBSTR($p)}';
const dpapi = (x: ReturnType<typeof caller>): Keychain => ({
  store: 'dpapi',
  read: (a, blob) => {
    const r = x('powershell', ps(UNPROTECT), blob ? Buffer.from(blob, 'base64').toString('hex') : '');
    if (r.status === 3 || r.status === 4) missing('dpapi', a); // no blob, or another user's or machine's
    return r.status === 0 ? fileKey(r.stdout) : r.down();
  },
  write: (_a, k) => { const r = x('powershell', ps(PROTECT), b64u(k)); return r.status === 0 && /^[0-9a-f]+$/i.test(r.stdout.trim()) ? Buffer.from(r.stdout.trim(), 'hex').toString('base64') : r.down(); },
  remove: () => {}, // the blob lives in the file: dropping the field removes it
});

let injected: Keychain | undefined;
/** The test seam: every call that names no store uses `kc`, until `inject()` clears it. */
export function inject(kc?: Keychain): void { injected = kc; }
/** The store this system has (the injected one, if any, unless `run` is given); answering is checked by its calls. */
export function systemKeychain(env: Env = process.env, run?: Run, platform: string = process.platform): Keychain {
  if (injected && !run) return injected;
  const by = { darwin: ['macos', macos], win32: ['dpapi', dpapi] } as Record<string, [StoreName, typeof macos]>;
  const [name, make] = by[platform] ?? ['secret-service', secretService];
  return make(caller(name, run ?? spawnRun, env));
}
/** Does a store answer here (init's default, plan §8.3)? A read for an account nobody writes. */
export function answers(kc: Keychain): boolean {
  try { kc.read('sigelo-probe').fill(0); return true; } catch (e) { return (e as { check?: string }).check !== 'keychain_unavailable'; }
}

/** The item `kc` already holds for `account` (another copy of this identity is wrapped, or `unwrap` could not remove it): reused, never overwritten. */
const held = (kc: Keychain, a: string): Uint8Array | undefined => {
  if (kc.store === 'dpapi') return undefined; // no items: the blob is in the file
  try { return kc.read(acct(a)); } catch (e) { if ((e as { check?: string }).check === 'keychain_missing') return undefined; throw e; }
};
/** Seal `seed` for the head key of `s`. A wrapped `s` keeps its file key (a rotation), as does an account the store already holds; else a new one goes to `kc`, read back through `unwrap` before anything is saved. */
export function wrap(seed: Uint8Array, s: Store, kc: Keychain = systemKeychain()): WrappedSecret {
  const prev = typeof s.secret === 'object' ? (s.secret as WrappedSecret) : undefined;
  if (prev && prev.store !== kc.store) missing(kc.store, prev.account);
  const account = prev?.account ?? did(s.genesis), old = prev ? kc.read(acct(account), prev.dpapi) : held(kc, account), key = old ?? randomBytes(32);
  let out: WrappedSecret;
  try {
    const dpapiBlob = prev ? prev.dpapi : old ? undefined : kc.write(account, key), nonce = randomBytes(12);
    out = { provider: 'keychain', v: V, store: kc.store, account, nonce: b64u(nonce), ct: b64u(seal(key, nonce, seed, aad(s))), ...(dpapiBlob && { dpapi: dpapiBlob }) };
  } finally { key.fill(0); }
  if (!prev) unwrap({ ...s, secret: out }, kc).fill(0);
  return out;
}
/** The seed of a wrapped `s`, checked against its head key; the caller zeroes it after use. */
export function unwrap(s: Store, kc: Keychain = systemKeychain()): Uint8Array {
  const w = s.secret as Partial<WrappedSecret>;
  if (w.v !== V) refuse('key_provider_unknown', `keychain secret ${JSON.stringify(w.v)}; this sigelo-agent reads ${V}`);
  if (w.store !== kc.store) missing(kc.store, String(w.account));
  const nonce = unb64u(w.nonce, 12, 'nonce'), ct = unb64u(w.ct, 48, 'ct'), key = kc.read(acct(w.account), w.dpapi);
  let seed: Uint8Array;
  try { seed = open(key, nonce, ct, aad(s), `the ${kc.store} item for ${w.account}`); } finally { key.fill(0); }
  if (!verifySig(head(s).key, PROBE, sign(seed, PROBE))) { seed.fill(0); refuse('key_mismatch', `the unwrapped seed does not sign for ${did(head(s))}`); }
  return seed;
}

/**
 * A keeper root K_j sealed the same way (design/devices.md §5.1, a FULL device's keeper file): under the
 * file key of `account` (the operator's original DID, the item its identity's wrap uses), AAD
 * "sigelo-wrap/1\nkeeper <j>\n<recovery commitment>", so a sealed root opens for that keeper only.
 * Read back before it is returned; nothing checks K itself (the caller derives a known worker from it).
 */
const rootAad = (j: number, recovery: string): Buffer => Buffer.from(`${V}\nkeeper ${j}\n${recovery}`, 'utf8');
export function wrapRoot(root: Uint8Array, account: string, j: number, recovery: string, kc: Keychain = systemKeychain()): WrappedSecret {
  const old = held(kc, account), key = old ?? randomBytes(32);
  let out: WrappedSecret;
  try {
    const dpapiBlob = old ? undefined : kc.write(account, key), nonce = randomBytes(12);
    out = { provider: 'keychain', v: V, store: kc.store, account, nonce: b64u(nonce), ct: b64u(seal(key, nonce, root, rootAad(j, recovery))), ...(dpapiBlob && { dpapi: dpapiBlob }) };
  } finally { key.fill(0); }
  unwrapRoot(out, j, recovery, kc).fill(0);
  return out;
}
/** The keeper root of a sealed one; the caller zeroes it after use. */
export function unwrapRoot(w: Partial<WrappedSecret>, j: number, recovery: string, kc: Keychain = systemKeychain()): Uint8Array {
  if (w.v !== V) refuse('key_provider_unknown', `keychain root ${JSON.stringify(w.v)}; this sigelo-agent reads ${V}`);
  if (w.store !== kc.store) missing(kc.store, String(w.account));
  const nonce = unb64u(w.nonce, 12, 'nonce'), ct = unb64u(w.ct, 48, 'ct'), key = kc.read(acct(w.account), w.dpapi);
  try { return open(key, nonce, ct, rootAad(j, recovery), `the ${kc.store} item for ${w.account}`); } finally { key.fill(0); }
}

/** `keys wrap` and `keys unwrap --plain`: file <-> keychain under the file's lock, one atomic write; unwrap removes the item only after the plain file is saved. */
export function move(path: string, verb: 'wrap' | 'unwrap', plain: boolean, kc: Keychain = systemKeychain()): object {
  if (verb === 'unwrap' && !plain) refuse('usage', 'keys unwrap writes the key back to the file as plain hex: say so with --plain');
  return withLock(path, () => {
    const s = load(path), from = typeof s.secret === 'string' ? s.provider ?? 'file' : s.secret.provider, want = verb === 'wrap' ? 'file' : 'keychain';
    if (from !== want) refuse('key_provider_required', `keys ${verb} moves a ${want} key; ${path} holds a ${from} key`);
    let removed = true;
    if (verb === 'wrap') {
      const seed = secretOf(s);
      try { s.secret = wrap(seed, s, kc); } finally { seed.fill(0); }
      save(path, Object.assign(s, { provider: 'keychain' }));
    } else {
      const w = s.secret as WrappedSecret, seed = unwrap(s, kc);
      try { s.secret = Buffer.from(seed).toString('hex'); } finally { seed.fill(0); }
      save(path, Object.assign(s, { provider: 'file' }));
      try { kc.remove(w.account); } catch { removed = false; } // the file is plain already: reported, not fatal
    }
    return { did: did(head(s)), provider: s.provider, store: kc.store, file: path, ...(!removed && { item_left: `${kc.store}: service sigelo, account ${did(s.genesis)}` }) };
  });
}
