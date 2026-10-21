// SPDX-License-Identifier: MIT
// The key agent's store (adapters/moadim/KEYS.md): a 0700 directory, one 0600 file per
// identity, written atomically (temp sibling + rename):
//   { v: "sigelo-key-agent/0", did, chain: { genesis, rotations }, secret, pending? }
// `did` is the identity's first DID here (the head genesis it was created or imported with);
// `chain` grows with each committed rotation, so every DID of it maps to the entry. `secret` is
// keychain-wrapped by default (adapters/moadim/sigelo-agent-keychain.ts) or, with --store-plain,
// the hex seed: for an agent running as its own user (§4.6), whose files the model's uid cannot read.
// `pending` is a rotation the agent signed whose caller has not yet written it: the old key keeps
// working until `commit` (or a request naming the new DID), so a rotation cannot tear.
import { randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { keychain, PROTOCOL, refuse, S } from './protocol.mjs';

/** The platform's data directory for the store (SIGELO_KEY_AGENT_STORE or --store overrides it). */
export function dataDir(env = process.env, platform = process.platform) {
  if (env.SIGELO_KEY_AGENT_STORE) return env.SIGELO_KEY_AGENT_STORE;
  if (platform === 'win32') return join(env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local'), 'sigelo-key-agent');
  if (platform === 'darwin') return join(homedir(), 'Library', 'Application Support', 'sigelo-key-agent');
  return join(env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'sigelo-key-agent');
}

/**
 * Make `dir` 0700 if absent, then refuse it (by `code`) unless it is a real directory of this uid
 * closed to group and world. Windows has no POSIX modes: there a directory inherits its parent's
 * ACL, and the named pipe is no file; its check is the manual one in README.md.
 */
export function privateDir(dir, code) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform === 'win32') return;
  const st = lstatSync(dir);
  if (!st.isDirectory()) refuse(code, `${dir} is not a directory (a symlink?)`);
  if (st.uid !== process.getuid()) refuse(code, `${dir} belongs to uid ${st.uid}, not this agent's ${process.getuid()}`);
  if (st.mode & 0o077) refuse(code, `${dir} is mode ${(st.mode & 0o777).toString(8)}: open to group or world; make it 0700`);
}

export const head = (e) => e.chain.rotations.at(-1)?.next_genesis ?? e.chain.genesis;
export const current = (e) => S.did(head(e));
export const pendingDid = (e) => (e.pending ? S.did(e.pending.rotation.next_genesis) : null);
/** The entry as the core and the keychain read an identity file: genesis, rotations (with `extra`). */
const asStore = (e, extra = []) => ({ v: S.VERSION, genesis: e.chain.genesis, rotations: [...e.chain.rotations, ...extra], attestations: [], issuers: [], secret: '' });
const fileOf = (dir, did) => join(dir, `${did.slice('did:sigelo:'.length)}.json`);

/** The store in `dir`: `plain` keeps seeds as hex, else they are keychain-wrapped. */
export function openStore(dir, { plain }) {
  privateDir(dir, 'store_dir_unsafe');
  const entries = [];
  for (const f of readdirSync(dir).filter((x) => /^z[1-9A-HJ-NP-Za-km-z]+\.json$/.test(x)).sort()) {
    const e = S.parseBytes(readFileSync(join(dir, f)));
    if (e?.v !== PROTOCOL) refuse('store_invalid', `${join(dir, f)} is not a ${PROTOCOL} entry`);
    entries.push(e);
  }
  const unlocked = new Map();   // keychain-wrapped seeds, once unwrapped: until lock, stop or --idle
  const save = (e) => {
    const tmp = join(dir, `.${randomBytes(8).toString('hex')}.tmp`);
    writeFileSync(tmp, `${JSON.stringify(e, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(tmp, fileOf(dir, e.did));
  };
  /** The at-rest form of `seed`, the key of the head of `e` (plus `extra` rotations). */
  const seal = (e, seed, extra = []) => (plain ? Buffer.from(seed).toString('hex') : keychain.wrap(seed, asStore(e, extra)));
  return {
    entries,
    asStore,
    formOf: (e) => (typeof e.secret === 'string' ? 'plain' : e.secret.provider),
    /** The entry holding `did` anywhere in its chain, or as its pending rotation's DID. */
    find: (did) => entries.find((e) => current(e) === did || pendingDid(e) === did || [e.chain.genesis, ...e.chain.rotations.map((r) => r.next_genesis)].some((g) => S.did(g) === did)),
    add(genesis, seed) {
      const e = { v: PROTOCOL, did: S.did(genesis), chain: { genesis, rotations: [] }, secret: '' };
      e.secret = seal(e, seed);
      save(e);
      entries.push(e);
      return e;
    },
    /** Run `fn` with the current seed of `e`, zeroed after unless unlocked (keychain) for reuse. */
    withSeed(e, fn) {
      if (typeof e.secret === 'string') { const seed = Uint8Array.from(Buffer.from(e.secret, 'hex')); try { return fn(seed); } finally { seed.fill(0); } }
      const k = current(e);
      if (!unlocked.has(k)) unlocked.set(k, keychain.unwrap({ ...asStore(e), secret: e.secret }));
      return fn(unlocked.get(k));
    },
    /** Keep `rotation` and the new seed as `pending`; written before the reply. */
    pend(e, rotation, seed) { e.pending = { rotation, secret: seal(e, seed, [rotation]) }; save(e); },
    /** The caller wrote the rotation: it joins the chain, the new key replaces the old. */
    commit(e) {
      this.forget(current(e));
      e.chain.rotations.push(e.pending.rotation);
      e.secret = e.pending.secret;
      delete e.pending;
      save(e);
    },
    forget(k) { unlocked.get(k)?.fill(0); unlocked.delete(k); },
    lock() { for (const k of [...unlocked.keys()]) this.forget(k); },
  };
}
