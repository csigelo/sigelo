// SPDX-License-Identifier: MIT
// Profiles (design/profiles.md P1): several identities in one app, like a wallet's list. Each profile
// has its own storage; only the active one is opened and connects to the relay (the others' messages
// wait at the relay until the next switch). The registry holds the list and the active id, no secret.
//
//   const reg = await openRegistry({ indexedDB, migrate })   the registry (IndexedDB database sigelo-app,
//                                       file profiles.json); none yet: p1 = what migrate() finds there
//   reg.list(), reg.active(), reg.byId(id), reg.full()      the list as kept (copies)
//   await reg.add(), reg.use(id), reg.rename(id, name), reg.set(id, fields), reg.drop(id)
//   await runWipes(reg, { indexedDB, storage, bridge })     the dropped profiles erased: their database,
//                                       their keys in the shell's keystore (forget-profile), their storage
//
// A profile: { id, name, kind, did, words, created }. id: p1, p2, …, never reused (next). name: the
// human's, 1 to 24 characters, "Profile n" at first. kind: 'words' (holds an identity), 'remote' (a
// computer's page, no account key) or null (not set up yet: its first run). did: the original DID once
// known (GET /api/me), words: its four words (didWords). At most LIMIT profiles.
// Storage of profile <id>: IndexedDB `sigelo` for p1 (as before profiles), `sigelo-<id>` for the others;
// localStorage keys as they were for p1, `<id>:<key>` for the others (prefixed); in the Android app its
// keystore aliases (SigeloBridge.java: p1 the three of before, `sigelo-<id>-…` for the others).
// A drop is recorded first (wipe: [ids]) and the erasing done after, at once for an inactive profile and
// at the next start for the active one, whose database is open: a crash between the two finishes it then.
import { memoryFiles, openDb } from './platform-web.mjs';
import { openComputers } from './computers.mjs';

export const LIMIT = 8, NAME_MAX = 24, REGISTRY_DB = 'sigelo-app', REGISTRY = 'profiles.json', V = 'sigelo-profiles/0';
export const ID = /^p[1-9]\d{0,2}$/;
export const dbName = (id) => (id === 'p1' ? 'sigelo' : `sigelo-${id}`);
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
const refuse = (check, message) => { throw Object.assign(new Error(message), { check, status: 400 }); };
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));

/** A profile's name as typed: trimmed, 1 to 24 characters, no control or direction characters. */
export function cleanName(v) {
  const s = typeof v === 'string' ? v.trim() : '';
  if (s === '' || [...s].length > NAME_MAX || CONTROL.test(s)) refuse('profile_name', `a name of 1 to ${NAME_MAX} characters`);
  return s;
}

/** localStorage as profile <id> sees it: p1 the keys of before, others `<id>:` before each; clear() only its own. */
export function prefixed(storage, id) {
  if (!storage) return storage;
  const other = /^p[1-9]\d{0,2}:/, pre = id === 'p1' ? '' : `${id}:`;
  const mine = (k) => (id === 'p1' ? !other.test(k) : k.startsWith(pre));
  const keys = () => { const out = []; for (let i = 0; i < storage.length; i++) { const k = storage.key(i); if (k !== null) out.push(k); } return out; };
  return {
    getItem: (k) => storage.getItem(pre + k),
    setItem: (k, v) => storage.setItem(pre + k, v),
    removeItem: (k) => storage.removeItem(pre + k),
    clear: () => { for (const k of keys()) if (mine(k)) storage.removeItem(k); },
  };
}

/**
 * The registry. migrate() → { kind } for p1, called once, when there is no registry yet: what this app
 * held before profiles (an identity: 'words'; a computer: 'remote'; nothing: null), left where it is.
 * now(): seconds.
 */
export async function openRegistry({ indexedDB = globalThis.indexedDB, migrate = async () => ({ kind: null }), now = () => Math.floor(Date.now() / 1000) } = {}) {
  const db = await openDb(indexedDB, REGISTRY_DB), store = await memoryFiles(db);
  const read = () => { const b = store.files.read(REGISTRY); if (b === null) return null; try { return JSON.parse(new TextDecoder().decode(b)); } catch { return null; } };
  let reg = read();
  const save = async () => { store.files.write(REGISTRY, enc(reg)); await store.flush(); };
  if (reg === null || reg.v !== V || !Array.isArray(reg.profiles)) {
    const { kind = null } = (await migrate()) ?? {};
    reg = { v: V, active: 'p1', next: 2, wipe: [], profiles: [{ id: 'p1', name: 'Profile 1', kind, did: null, words: null, created: now() }] };
    await save();
  }
  const copy = (p) => (p ? { ...p } : null);
  const find = (id) => reg.profiles.find((p) => p.id === id) ?? refuse('profile', `no profile ${JSON.stringify(id)}`);
  return {
    full: () => JSON.parse(JSON.stringify({ active: reg.active, limit: LIMIT, profiles: reg.profiles })),
    list: () => reg.profiles.map(copy),
    active: () => copy(reg.profiles.find((p) => p.id === reg.active)),
    byId: (id) => copy(reg.profiles.find((p) => p.id === id)),
    wipes: () => [...reg.wipe],
    /** A new profile, not set up yet, made the active one → it. Refused at LIMIT (profile_limit). */
    async add() {
      if (reg.profiles.length >= LIMIT) refuse('profile_limit', `at most ${LIMIT} profiles on this phone: remove one first`);
      const n = reg.next, p = { id: `p${n}`, name: `Profile ${n}`, kind: null, did: null, words: null, created: now() };
      reg.next = n + 1; reg.profiles.push(p); reg.active = p.id;
      await save();
      return copy(p);
    },
    async use(id) { find(id); reg.active = id; await save(); },
    async rename(id, name) { find(id).name = cleanName(name); await save(); },
    /** kind, did, words as the profile's start learned them; nothing written when nothing changed. */
    async set(id, fields) {
      const p = find(id);
      const f = Object.fromEntries(Object.entries(fields).filter(([k, v]) => ['kind', 'did', 'words'].includes(k) && v !== undefined && p[k] !== v));
      if (!Object.keys(f).length) return;
      Object.assign(p, f);
      await save();
    },
    /** Out of the list and into the wipe list; the active one → the first left (or none). */
    async drop(id) {
      find(id);
      reg.profiles = reg.profiles.filter((p) => p.id !== id);
      if (!reg.wipe.includes(id)) reg.wipe.push(id);
      if (reg.active === id) reg.active = reg.profiles[0]?.id ?? null;
      await save();
    },
    async wiped(id) { reg.wipe = reg.wipe.filter((x) => x !== id); await save(); },
  };
}

/** deleteDatabase to its end: true once deleted; false if it stays blocked (an open connection) past `ms`. */
export function deleteDb(indexedDB, name, ms = 5000) {
  return new Promise((ok) => {
    const r = indexedDB.deleteDatabase(name);
    const t = setTimeout(() => ok(false), ms);
    r.onsuccess = () => { clearTimeout(t); ok(true); };
    r.onerror = () => { clearTimeout(t); ok(false); };
  });
}

/**
 * The dropped profiles erased: the database (blocked: tried again at the next start), the storage keys,
 * and in the Android app the keystore aliases (forget-profile: crypto-erase; the sealed blobs, wherever
 * a copy went, no longer open). Each finished one leaves the wipe list. → the ids erased.
 */
export async function runWipes(reg, { indexedDB = globalThis.indexedDB, storage = globalThis.localStorage, bridge = null } = {}) {
  const done = [];
  for (const id of reg.wipes()) {
    if (!ID.test(id)) { await reg.wiped(id); continue; }
    if (bridge) await bridge.forgetProfile(id);
    // A remote profile's computers over the relay: each its own database beside the profile's (computers.mjs).
    let more = [];
    try { more = storage ? openComputers(prefixed(storage, id)).databases(dbName(id)).filter((d) => d !== dbName(id)) : []; } catch {}
    for (const d of more) await deleteDb(indexedDB, d);
    try { prefixed(storage, id)?.clear(); } catch {}
    if (!(await deleteDb(indexedDB, dbName(id)))) continue;
    await reg.wiped(id);
    done.push(id);
  }
  return done;
}
