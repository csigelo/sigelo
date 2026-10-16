// SPDX-License-Identifier: MIT
/**
 * Key providers (design/key-providers.md §2): where the identity key rests and which process
 * uses it. Every signature of the CLI, the MCP server, the Monero half, the contact verbs and
 * the gate's signer goes through `signer`; the core (sigelo-agent.ts) keeps only the plain-file
 * path, so an identity-only install still reads 75 lines. Counted apart in INTEGRATION.md.
 *
 *   file      `secret` is the hex seed, as in every version (a top-level `"provider": "file"` may say so)
 *   keychain  `secret` is the seed sealed under a key in the OS store (sigelo-agent-keychain.ts)
 *   agent     `secret` is `{ "provider": "agent" }`: sigelo-key-agent holds it (sigelo-agent-keyclient.ts, K3)
 *
 * Fail closed, by name (§2.5): no provider falls back to another, an unknown one is refused
 * before anything is read or written, and every signature is checked against the head genesis
 * key before it leaves (`key_mismatch`).
 */
import { existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
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
 * (integrations/web-bot-auth), checked by `httpBase` first; it returns base64.
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

/** The in-process forms: the seed for one call, zeroed after; nothing is cached. */
function withSeed<T>(s: Store, fn: (seed: Uint8Array) => T): T {
  const seed = providerOf(s) === 'file' ? secretOf(s) : keychain.unwrap(s);
  try { return fn(seed); } finally { seed.fill(0); }
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
  const raw = p === 'agent' ? (body: object) => request({ op: 'sign', did: d, body }, env)['sig'] : (body: object) => withSeed(s, (seed) => sign(seed, body));
  const mismatch = (): never => fail('key_mismatch', `the ${p} key of ${path} does not sign for ${d}, its head genesis key: the file or its key store was changed`);
  return { did: d, key: g.key, sign: (body) => {
    const sig = raw(body);
    if (typeof sig !== 'string' || !verifySig(g.key, body, sig)) return mismatch();
    return sig;
  }, signHttp: (base) => {
    const msg = httpBase(base);
    if (p === 'agent') fail('key_provider_unbuilt', 'the key agent signs sigelo bodies only: sign-http needs a file or keychain key');
    const sig = withSeed(s, (seed) => edRaw(seed, msg));
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
 */
export function init(path: string, recovery: string | null, provider?: string, env: Env = process.env): Store {
  if (provider !== undefined && !PROVIDERS.includes(provider)) fail('key_provider_unknown', `SIGELO_KEY_PROVIDER is ${JSON.stringify(provider)}; use ${PROVIDERS.join(', ')}`);
  if (existsSync(path)) throw new SigeloError(`init: ${path} already holds an identity — refusing to overwrite it`);
  provider ??= keychain.answers(keychain.systemKeychain(env)) ? 'keychain' : (console.error('sigelo-agent: no OS keychain answers here, so the key is a plain file ("provider": "file"); see `sigelo-agent keys wrap`'), 'file');
  let store: Store;
  if (provider === 'agent') {
    const genesis = request({ op: 'create', recovery }, env)['genesis'] as Genesis;
    store = { v: VERSION, provider, secret: { provider }, genesis, rotations: [], attestations: [], issuers: [] };
  } else {
    const id = keygen({ recovery });
    store = { v: VERSION, provider, secret: '', genesis: id.genesis, rotations: [], attestations: [], issuers: [] };
    try { store.secret = provider === 'file' ? Buffer.from(id.secret).toString('hex') : keychain.wrap(id.secret, store, keychain.systemKeychain(env)); } finally { id.secret.fill(0); }
  }
  save(path, store);
  return store;
}

/** Voluntary rotation in the key's own form (SPEC §7): the rotation is appended and `s.secret` becomes the new key's at-rest form; the caller saves both in one write. */
export function rotate(path: string, s: Store, now: number, env: Env = process.env): Store {
  const d = (s as Derived).derived;
  if (d) throw new SigeloError(`rotate: this identity comes from your 25 words (${d.path}): a random key would not. Its next key is rotation ${d.n + 1} of them: sigelo-agent keeper --from-words --rotate-me`);
  const p = using(path, s, env);
  if (p === 'file') return rotateKey(s, now);
  if (p === 'agent') { s.rotations.push(request({ op: 'rotate', did: did(head(s)), to: 'software' }, env)['rotation'] as Rotation); return s; }
  const cur = head(s), fresh = keygen({ recovery: cur.recovery });
  try {
    s.rotations.push(withSeed(s, (secret) => rotation({ genesis: cur, next_genesis: fresh.genesis, iat: now, reason: 'voluntary', secret })));
    s.secret = keychain.wrap(fresh.secret, s);
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
  withSeed(s, (seed) => { try { request({ op: 'import', genesis: g, seed: Buffer.from(seed).toString('hex') }, env); } catch (e) { if ((e as { check?: string }).check !== 'key_held') throw e; } });
  if (request({ op: 'pubkey', did: d }, env)['key'] !== g.key) fail('key_mismatch', `the key agent holds another key for ${d}; ${path} is unchanged`);
  save(path, Object.assign(s, { provider: 'agent', secret: { provider: 'agent' } }));
  return { did: d, provider: 'agent', file: path, key_agent: socketPath(env), note: 'older copies of the file (backups, sync folders) still hold the key: rotate if one may have leaked' };
});

export const USAGE = `Where the identity key rests (identity file field "provider"):
  keys status                            the key's form, and whether it signs for the current DID;
                                         never prints key material
  keys wrap | keys unwrap --plain        seal the key under a key in the OS store (macOS keychain,
                                         Secret Service, DPAPI) | write it back as plain hex
  keys to-agent                          move the key into sigelo-key-agent (SIGELO_KEY_AGENT, else its
                                         default socket); the file then says {"provider":"agent"}`;

/** `sigelo-agent keys <verb>`. null: no such verb (usage, exit 2). */
export function main(args: string[], path: string, s: Store, env: Env = process.env): object | null {
  const verb = args[0];
  if (verb === 'status' || verb === 'show') {
    const p = providerOf(s), d = did(head(s));
    let code = 'ok';   // an agent signs no probe body (§4.3): its key for this DID must be the head key
    try { if (p !== 'agent') signer(path, s, env).sign({ v: 'sigelo-keys/0', typ: 'probe', did: d }); else if (request({ op: 'pubkey', did: d }, env)['key'] !== head(s).key) fail('key_mismatch', d); } catch (e) { code = (e as { check?: string }).check ?? 'error'; }
    return { did: d, provider: p, file: path, key_agent: env['SIGELO_KEY_AGENT'] ?? null, signs: code === 'ok', ...(code !== 'ok' && { code }) };
  }
  if (verb === 'wrap' || verb === 'unwrap') return keychain.move(path, verb, args.includes('--plain'), keychain.systemKeychain(env));
  if (verb === 'to-agent') return toAgent(path, env);
  return null;
}
