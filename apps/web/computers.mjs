// SPDX-License-Identifier: MIT
// Several computers in a remote profile (design/profiles.md P2): each paired once, by code or scan, the one
// in use marked. All of a profile's computers serve its operator: a computer whose page is another
// identity is refused `other_operator` when it is paired (and its answers refused if it changes later).
// The list lives in the profile's own localStorage (profiles.mjs prefixed), no secret in it:
//   { v: 'sigelo-computers/0', active: 'c1', next: 2, adding: false, wipe: [databases],
//     computers: [{ id, name, via: 'lan' | 'relay', did, words, where, paired, last_used }] }
// id: c1, c2, …, never reused. did: the computer's page identity (its original DID: the operator), words its
// four words (didWords), where: host:port on the LAN or the relay's host. The control material per computer:
//   LAN    the SIGELO:UI: text sealed under the profile's control alias: c1 in `sigelo-control` (as before),
//          another in `sigelo-control:<id>`, its blob naming the computer (SigeloBridge.java blob version 2)
//   relay  { operator, relay } in `sigelo-control-relay` (c1) or `sigelo-control-relay:<id>`; its control
//          identity and carrier state in the profile's database (c1) or `<database>-<id>`, sealed naming it
// Migration: no list yet → today's one computer (relay or LAN, whichever is kept) becomes c1, its storage
// left where it is. Forget: the control material removed here (a relay computer's database at the next start,
// when nothing holds it open); the computer keeps the control until it is revoked there (REVOKE).
import { didWords } from './vendor/contact/short.mjs';

export const V = 'sigelo-computers/0', KEY = 'sigelo-computers', LIMIT = 8, CID = /^c[1-9]\d{0,2}$/;
export const REVOKE = 'sigelo-agent ui --revoke-control <name>';
export const controlKey = (cid) => (cid === 'c1' ? 'sigelo-control' : `sigelo-control:${cid}`);
export const relayKey = (cid) => (cid === 'c1' ? 'sigelo-control-relay' : `sigelo-control-relay:${cid}`);
/** A relay computer's database: the profile's for c1 (as before), `<database>-<id>` for another. */
export const computerDb = (db, cid) => (cid === 'c1' ? db : `${db}-${cid}`);
const refuse = (check, message, status = 400) => { throw Object.assign(new Error(message), { check, status }); };
const wordsOf = (did) => { try { return didWords(did); } catch { return null; } };

/** The refusal of a computer serving another operator than the profile's (expect), or null when it is the same (or nothing is known yet). */
export function otherOperator(expect, dids) {
  if (!expect) return null;
  const list = (Array.isArray(dids) ? dids : [dids]).filter((d) => typeof d === 'string');
  if (!list.length || list.includes(expect)) return null;
  const theirs = wordsOf(list[0]), ours = wordsOf(expect);
  return Object.assign(new Error(`This computer's page is another identity (${theirs ?? list[0]}), not this profile's (${ours ?? expect}): all the computers of a profile serve one operator. Add it in a profile of its own (Me → Profiles → Add a profile).`),
    { check: 'other_operator', status: 409 });
}

/**
 * The profile's computers over its storage (profiles.mjs prefixed). now(): seconds. Several of these may be open on
 * one storage at once (the page's backend, boot.mjs's computers, a page that is going away), so nothing is held
 * between calls: every call reads the list again and every change is written at once (localStorage is synchronous:
 * a read, a change and its write are one step). A copy kept from before wrote a stale list over a newer one (the
 * computer in use set back by a late GET /api/me of the page before a switch).
 */
export function openComputers(storage, { now = () => Math.floor(Date.now() / 1000) } = {}) {
  let c = null;
  const save = () => storage.setItem(KEY, JSON.stringify(c));
  const load = () => {
    c = null;
    try { c = JSON.parse(storage.getItem(KEY) ?? 'null'); } catch {}
    if (c?.v === V && Array.isArray(c.computers)) return;
    // Before P2: one computer at most, under the keys of before. It becomes c1 and stays where it is.
    let relay = null;
    try { relay = JSON.parse(storage.getItem(relayKey('c1')) ?? 'null'); } catch {}
    const lan = storage.getItem(controlKey('c1')) !== null;
    const first = relay ? { id: 'c1', name: 'Computer 1', via: 'relay', did: relay.operator ?? null, words: wordsOf(relay.operator), where: relay.relay ?? null, paired: null, last_used: null }
      : lan ? { id: 'c1', name: 'Computer 1', via: 'lan', did: null, words: null, where: null, paired: null, last_used: null } : null;
    c = { v: V, active: first ? 'c1' : null, next: first ? 2 : 1, adding: false, wipe: [], computers: first ? [first] : [] };
    save();
  };
  load();
  const find = (id) => c.computers.find((x) => x.id === id) ?? refuse('computer', `no computer ${JSON.stringify(id)}`, 404);
  const copy = (x) => (x ? { ...x } : null);
  const api = {
    full: () => JSON.parse(JSON.stringify({ active: c.active, limit: LIMIT, computers: c.computers })),
    list: () => c.computers.map(copy),
    active: () => copy(c.computers.find((x) => x.id === c.active)),
    byId: (id) => copy(c.computers.find((x) => x.id === id)),
    /** The operator these computers serve, as far as they told: the first DID known. */
    operator: () => c.computers.find((x) => x.did)?.did ?? null,
    setAdding(on) { c.adding = on === true; save(); },
    /** The next id (not taken until add()). */
    nextId: () => `c${c.next}`,
    /** A computer paired now, made the one in use. */
    add({ via, did = null, where = null, name }) {
      if (c.computers.length >= LIMIT) refuse('computer_limit', `At most ${LIMIT} computers in a profile: forget one first.`);
      const id = `c${c.next}`, t = now();
      const x = { id, name: typeof name === 'string' && name.trim() ? name.trim().slice(0, 24) : `Computer ${c.next}`, via, did, words: wordsOf(did), where, paired: t, last_used: t };
      c.next += 1; c.computers.push(x); c.active = id; c.adding = false;
      save();
      return copy(x);
    },
    use(id) { find(id); c.active = id; c.adding = false; save(); },
    /** What its page said of itself (GET /api/me), and that it was used now. */
    learn(id, { did } = {}) {
      const x = c.computers.find((y) => y.id === id);
      if (!x) return;
      if (typeof did === 'string' && x.did !== did) { x.did = did; x.words = wordsOf(did); }
      x.last_used = now();
      save();
    },
    /**
     * Out of the list, its control material removed from storage; a relay computer's database recorded for the
     * wipe (wipes()). The one in use → the first left (or none). → { computer, active: whether it was in use }.
     */
    forget(id, db) {
      const x = find(id), was = c.active === id;
      storage.removeItem(controlKey(id));
      storage.removeItem(relayKey(id));
      if (x.via === 'relay' && db && !c.wipe.includes(computerDb(db, id))) c.wipe.push(computerDb(db, id));
      c.computers = c.computers.filter((y) => y.id !== id);
      if (was) c.active = c.computers[0]?.id ?? null;
      save();
      return { computer: copy(x), active: was };
    },
    wipes: () => [...(c.wipe ?? [])],
    wiped(db) { c.wipe = (c.wipe ?? []).filter((x) => x !== db); save(); },
    /** Every database of these computers (a profile's removal deletes them all). */
    databases: (db) => [...new Set([...c.computers.filter((x) => x.via === 'relay').map((x) => computerDb(db, x.id)), ...(c.wipe ?? [])])],
  };
  // Every call on the list as it is now in storage (see above).
  const fresh = Object.fromEntries(Object.entries(api).map(([k, f]) => [k, (...a) => { load(); return f(...a); }]));
  return Object.freeze({ ...fresh, get adding() { load(); return c.adding === true; } });
}
