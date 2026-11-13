// SPDX-License-Identifier: MIT
// Transfers, the part every host shares (design/transfer.md §4, §10; apps/agent/TRANSFER.md): the
// records, the consent and the accept rule, the verbs and the Engine, with the disk, the file sent and
// Tor behind `io`. Node: transfer-node.mjs (fs, a tor daemon). The phone: transfer-web.mjs (the bridge
// holds the bytes; no Tor). The protocol is transfer.mjs's; the carrier is carrier.mjs's, in both.
//
//   const io = { lock(fn), read() → text | null, write(text),                          the records file, under its lock
//     have: { read(id) → bytes | null, write(id, bits) }, list: { read(id, side), write(id, side, bytes), drop(id, side) },
//     part: { open(id) → { write(bytes, pos), flush(), close() }, drop(id), sha256(id) → hex, exists?(id) },
//     free() → bytes free (sync; Infinity: unknown), land(r, c) → the place it was saved (a path, a content URI),
//     prepare({ path | doc }) → { file, name, size, mtimeMs, hashes, whole }, source(r) → { read(i), close() },
//     changed(r) → true when the file sent is not the one hashed (size or modification time moved),
//     tor: null | { caps(), serve(engine, side, r, a), connect(engine, side, r, x, a), close(a) },
//     flushEach: chunks between flushes (Node 8; the phone 1: the bitmap saved after every chunk) }
//
// The records file: { v, out: { id: sender's record }, in: { id: receiver's record }, direct: { DID: true|false },
// auto: { DID: MB (0: always ask) }, settings: { tor, prefer, auto_mb, keep_location } }.
//
// The accept rule (design §10.2, decided 2026-11-13): a file lands without a question up to the size set
// (settings.auto_mb, default 25 MB; per contact auto[DID]) from own agents and own contacts (tier own,
// ours) and from friends whose four words were compared (compared(did), the page's), when the disk has
// room and direct is allowed for that contact; larger, or from anyone else (words not compared, a
// public-code joiner, quiet), it is asked.
import { TRANSFER_SEND } from './carrier.mjs';
import { FILE_LABEL, safeName } from './file.mjs';
import { MsgError, fail } from './kdf.mjs';
import {
  ANSWER_WAIT, AUTO_MB, CHUNK, DAY, GATHER_MS, ICE_MS, MANIFEST_TTL, MAX_SIZE, Have, Pull, Serve, TRANSFER_LABEL, WAIT_ALL, WAIT_CONTACT,
  acceptRule, channelLabel, checkMessage, listOf, manifest, noPath, pathOrder, torRoles,
} from './transfer.mjs';

export const FILE_V = 'sigelo-transfers/1';
export { TRANSFER_LABEL };
const KEPT = 30 * DAY, RETRIES_AUTO = 3, RETRY_MS = 5000, STUN_PORT = 3478;
export const FREE_MARGIN = 64 * CHUNK;
export const STATES_LIVE_IN = ['accepted', 'offering', 'active'], STATES_LIVE_OUT = ['active'];
const nowS = (carrier) => (carrier?.clock ? carrier.clock() : Math.floor(Date.now() / 1000));
const later = (f) => setTimeout(f, 0);

// ---------------------------------------------------------------- the records

/** Load, purge, change (fn), save, under the file's lock. → fn's result. */
export function state(io, now, fn = () => undefined) {
  return io.lock(() => {
    let s = { v: FILE_V, out: {}, in: {}, direct: {}, auto: {}, settings: {} };
    const text = io.read();
    if (text !== null) {
      try { s = JSON.parse(text); } catch (e) { fail('transfer_file', `the transfers file does not parse (${e.message}): delete it to drop the transfers in progress`); }
      if (s?.v !== FILE_V || typeof s.out !== 'object' || typeof s.in !== 'object') fail('transfer_file', `the transfers file is not a ${FILE_V} file`);
      s.direct ??= {}; s.settings ??= {}; s.auto ??= {};
    }
    const before = JSON.stringify(s);
    for (const side of ['out', 'in']) for (const [k, r] of Object.entries(s[side])) if (['done', 'declined', 'cancelled', 'failed', 'expired'].includes(r.state) && r.at + KEPT < now) delete s[side][k];
    const out = fn(s);
    if (JSON.stringify(s) !== before) io.write(JSON.stringify(s, null, 2));
    return out;
  });
}

/** The live contact named (DID or name), or not_contact. */
export function contactOf(carrier, who) {
  const cs = carrier.contacts().contacts.filter((c) => !c.revoked);
  const hit = typeof who === 'string' && who.startsWith('did:sigelo:') ? cs.filter((c) => c.did === who || c.chain?.includes(who)) : cs.filter((c) => c.name === who);
  if (hit.length === 0) fail('not_contact', `${JSON.stringify(who)} is not a contact`);
  if (hit.length > 1) fail('name', `${hit.length} contacts are named ${JSON.stringify(who)}: use the DID`);
  return hit[0];
}
const own = (c) => c.tier === 'own' || c.ours === true;
/** May this contact learn this agent's addresses (direct)? true, false, or null: not asked yet (never for own). */
export const directFor = (s, c) => (Object.hasOwn(s.direct, c.did) ? s.direct[c.did] : own(c) ? true : null);
const decideDirect = (s, c, direct) => {
  if (direct === true || direct === false) { s.direct[c.did] = direct; return direct; }
  const d = directFor(s, c);
  if (d === null) fail('direct_ask', `direct shows ${c.name} this device's public and local addresses; say once whether it may (direct on or off for ${c.name}); off: Tor only`);
  return d;
};
/** How far a contact is known (the accept rule): own, compared (a friend whose words were compared), or other. */
export function trustOf(c, compared = () => false) {
  if (own(c)) return 'own';
  if (c.tier === 'quiet' || (c.via !== undefined && c.via !== null)) return 'other';
  return compared(c.did) ? 'compared' : 'other';
}
export const autoDefault = (s) => (Number.isFinite(s.settings.auto_mb) && s.settings.auto_mb >= 0 ? s.settings.auto_mb : AUTO_MB);
const settingsOf = (s) => ({ tor: s.settings.tor !== false, prefer: s.settings.prefer === 'private' ? 'private' : 'fast', auto_mb: autoDefault(s), keep_location: s.settings.keep_location === true });
const sendMsg = (carrier, to, content, local) => carrier.send(to, content, { label: TRANSFER_LABEL, internal: TRANSFER_SEND, local });

// ---------------------------------------------------------------- the verbs

/** The sender: the file hashed (io.prepare), its manifest sent. group: the gid of a group's fan-out (kept here only). */
export async function send({ carrier, io, to, path, doc, via = 'auto', direct, local = false, group = null }) {
  if (via !== 'auto' && via !== 'tor') fail('usage', 'via: auto or tor');
  const c = contactOf(carrier, to);
  state(io, nowS(carrier), (s) => decideDirect(s, c, direct));
  return sendTo({ carrier, io, to: c.did, f: await io.prepare({ path, doc }), via, direct, local, group });
}
/** The file sent, hashed once: → { file, name, size, mtimeMs, hashes, whole } (sendTo, fanOut take it). */
export const prepare = ({ io, path, doc }) => io.prepare({ path, doc });
/** A file prepared, offered to one contact (the direct switch settled first). */
export async function sendTo({ carrier, io, to, f, via = 'auto', direct, local = false, group = null }) {
  if (via !== 'auto' && via !== 'tor') fail('usage', 'via: auto or tor');
  const c = contactOf(carrier, to), now = nowS(carrier);
  state(io, now, (s) => decideDirect(s, c, direct));
  return sendPrepared({ carrier, io, c, f, via, local, group, now });
}
/**
 * A group's file (design §10.3): one transfer per member this side is paired with, the file hashed once
 * (f); members reached only through the creator are listed unpaired (they get the preview alone).
 * members: [{ did, name, contact }] (the others; contact: paired here). Before anything is sent, a member
 * whose direct switch is not set and no direct given: direct_ask naming them. → { sent, unpaired, failed }.
 */
export async function fanOut({ carrier, io, members, f, direct, via = 'auto', local = false, group }) {
  const paired = [], unpaired = [];
  for (const m of members) {
    let c = null;
    if (m.contact) { try { c = contactOf(carrier, m.did); } catch {} }
    (c ? paired : unpaired).push(c ? { did: c.did, name: c.name, c } : { did: m.did, name: m.name });
  }
  if (direct !== true && direct !== false) {
    const ask = state(io, nowS(carrier), (s) => paired.filter((p) => directFor(s, p.c) === null).map((p) => p.name));
    if (ask.length) fail('direct_ask', `direct shows ${ask.join(', ')} this device's public and local addresses; say once whether they may (direct on or off); off: Tor only`);
  }
  const sent = [], failed = [];
  for (const p of paired) {
    try { const r = await sendTo({ carrier, io, to: p.did, f, via, direct: direct ?? undefined, local, group }); sent.push({ did: p.did, name: p.name, id: r.id }); }
    catch (e) { failed.push({ did: p.did, name: p.name, check: e.check ?? 'send', detail: e.message }); }
  }
  return { sent, unpaired: unpaired.map(({ did, name }) => ({ did, name })), failed };
}
/** A file hashed once, offered to contact c (a group's members share one f). */
export async function sendPrepared({ carrier, io, c, f, via = 'auto', local = false, group = null, now = nowS(carrier) }) {
  if (f.size > MAX_SIZE) fail('transfer_too_large', `${f.size} bytes: at most ${MAX_SIZE} (16 GiB) a file`);
  const m = manifest({ name: safeName(f.name), size: f.size, sha256: f.whole, hashes: f.hashes, now });
  io.list.write(m.id, 'out', f.hashes);
  const rec = { id: m.id, to: c.did, contact: c.name, file: f.file, name: m.name, size: m.size, mtimeMs: f.mtimeMs, sha256: m.sha256, chunks: m.chunks, list: m.list, exp: m.exp, via, state: 'offered', attempt: 0, at: now, sent: 0, ...(group && { group }) };
  state(io, now, (s) => { s.out[m.id] = rec; });
  try { await sendMsg(carrier, c.did, m, local); } catch (e) {
    state(io, now, (s) => { s.out[m.id].state = 'failed'; s.out[m.id].reason = e.check ?? 'send'; s.out[m.id].detail = e.message; });
    throw e;
  }
  return rec;
}

const recIn = (s, id) => s.in[id] ?? fail('transfer_unknown', `no transfer ${id} offered here`);
/** Either side's record: → { side, r }. */
const either = (s, id) => (s.in[id] ? { side: 'in', r: s.in[id] } : s.out[id] ? { side: 'out', r: s.out[id] } : fail('transfer_unknown', `no transfer ${id}`));
const haveOf = (io, r) => { const b = io.have.read(r.id); try { return new Have(r.chunks, b ?? undefined); } catch { return new Have(r.chunks); } };
/** Free disk for a record (in s), or disk_full. */
const room = (io, r) => {
  const need = r.size - haveOf(io, r).bytes(r.size), free = io.free();
  if (free < need + FREE_MARGIN) fail('disk_full', `${r.name} needs ${need} bytes more here, ${free} are free`);
};

/** The receiver's yes to a manifest (or a resume of one that stopped): free disk checked, the direct switch settled. */
export function accept({ carrier, io, id, direct, via }) {
  const now = nowS(carrier);
  return state(io, now, (s) => {
    const r = recIn(s, id);
    if (!['asked', 'interrupted', 'failed'].includes(r.state) || (r.state === 'failed' && !['no_path', 'cancelled', 'ice_timeout', 'tor', 'land'].includes(r.reason))) fail('transfer_state', `transfer ${id} is ${r.state}${r.reason ? ` (${r.reason})` : ''}`);
    if (r.exp <= now) fail('transfer_expired', `the offer of ${r.name} expired`);
    const c = contactOf(carrier, r.from);
    decideDirect(s, c, direct);
    room(io, r);
    if (via === 'tor' || via === 'auto') r.via = via;
    r.state = 'accepted'; r.auto = 0; r.at = now; delete r.reason; delete r.detail;
    return { ...r };
  });
}
/** The receiver's no: the sender is told declined; nothing was written. */
export async function decline({ carrier, io, id, local = false }) {
  const now = nowS(carrier);
  const r = state(io, now, (s) => {
    const x = recIn(s, id);
    if (x.state !== 'asked') fail('transfer_state', `transfer ${id} is ${x.state}`);
    x.state = 'declined'; x.at = now;
    return { ...x };
  });
  await sendMsg(carrier, r.from, { typ: 'end', id, reason: 'declined' }, local).catch(() => {});
  return r;
}
/** Either side stops a transfer: the other is told cancelled; the receiver's partials go. */
export async function cancel({ carrier, io, id, local = false, engine = null }) {
  const now = nowS(carrier);
  const { side, r } = state(io, now, (s) => {
    const x = either(s, id);
    if (['done', 'declined', 'cancelled', 'expired'].includes(x.r.state)) fail('transfer_state', `transfer ${id} is ${x.r.state}`);
    x.r.state = 'cancelled'; x.r.at = now;
    return { side: x.side, r: { ...x.r } };
  });
  engine?.drop(id, 'cancelled');
  if (side === 'in') dropPartial(io, id);
  await sendMsg(carrier, side === 'in' ? r.from : r.to, { typ: 'end', id, reason: 'cancelled' }, local).catch(() => {});
  return r;
}
/** A finished, failed or unwanted record and its partials gone, here only. */
export function forget({ carrier, io, id, engine = null }) {
  const now = nowS(carrier);
  const r = state(io, now, (s) => {
    const x = either(s, id);
    if (x.side === 'in' && STATES_LIVE_IN.includes(x.r.state)) fail('transfer_state', `transfer ${id} is ${x.r.state}: cancel it first`);
    delete s[x.side][id];
    return x.r;
  });
  engine?.drop(id, 'cancelled');
  dropPartial(io, id);
  io.list.drop(id, 'out');
  return r;
}
export function dropPartial(io, id) { io.part.drop(id); io.have.write(id, null); io.list.drop(id, 'in'); }

/** Both sides' records, newest first, with what the engine of this process knows live. */
export function list({ carrier, io, engine = null }) {
  const now = nowS(carrier);
  return state(io, now, (s) => {
    const live = (r) => ({ ...r, ...(engine?.progress(r.id) ?? {}) });
    const sort = (a, b) => b.at - a.at;
    return {
      out: Object.values(s.out).map((r) => { const { file: _f, ...x } = live(r); return x; }).sort(sort),
      in: Object.values(s.in).map(live).sort(sort),
      direct: { ...s.direct },
      auto: { ...s.auto },
      settings: settingsOf(s),
    };
  });
}
export function setDirect({ carrier, io, contact, on }) {
  if (typeof on !== 'boolean') fail('usage', 'on: true or false');
  const c = contactOf(carrier, contact);
  return state(io, nowS(carrier), (s) => { s.direct[c.did] = on; return { did: c.did, name: c.name, direct: on }; });
}
const mbOk = (x) => Number.isFinite(x) && x >= 0 && x <= MAX_SIZE / 1e6;
/** A contact's own size for the accept rule: MB (0: always ask), or null: the default. */
export function setAuto({ carrier, io, contact, mb }) {
  if (mb !== null && !mbOk(mb)) fail('usage', 'mb: 0 (always ask) to 17179, or null (the default)');
  const c = contactOf(carrier, contact);
  return state(io, nowS(carrier), (s) => {
    if (mb === null) delete s.auto[c.did]; else s.auto[c.did] = mb;
    return { did: c.did, name: c.name, auto_mb: mb };
  });
}
/** The settings, patched: { tor: true|false, prefer: 'fast'|'private', auto_mb: MB (0: always ask), keep_location: camera photos keep their location tags (default false: removed) }. */
export function settings({ io, patch = {}, now = Math.floor(Date.now() / 1000) }) {
  if (patch.tor !== undefined && typeof patch.tor !== 'boolean') fail('usage', 'tor: on or off');
  if (patch.prefer !== undefined && patch.prefer !== 'fast' && patch.prefer !== 'private') fail('usage', 'prefer: fast or private');
  if (patch.auto_mb !== undefined && !mbOk(patch.auto_mb)) fail('usage', 'auto_mb: 0 (always ask) to 17179');
  if (patch.keep_location !== undefined && typeof patch.keep_location !== 'boolean') fail('usage', 'keep_location: true or false');
  return state(io, now, (s) => {
    for (const k of ['tor', 'prefer', 'auto_mb', 'keep_location']) if (patch[k] !== undefined) s.settings[k] = patch[k];
    return settingsOf(s);
  });
}

const hostOf = (relay) => (typeof relay === 'string' && relay ? relay.replace(/:\d+$/, '') : null);
/** The STUN servers for a transfer with contact c: env.SIGELO_STUN, else this agent's relay host and the contact's, port 3478. */
export function stunFor(carrier, c, env = {}) {
  if (env.SIGELO_STUN !== undefined) return env.SIGELO_STUN.split(',').map((x) => x.trim()).filter(Boolean).map((x) => (/:\d+$/.test(x) ? x : `${x}:${STUN_PORT}`));
  return [...new Set([hostOf(carrier.relay), hostOf(c?.relay)].filter(Boolean))].map((h) => `${h}:${STUN_PORT}`);
}

// ---------------------------------------------------------------- the engine

export class Engine {
  /**
   * carrier: started (it holds the session); io (above); rtc: () → the direct path's module ({ peer }) or null;
   * stun: a list, or null for stunFor(env); pro: () → whether this agent's pool is Pro; compared(did): the four
   * words of that contact were compared (the accept rule); maxServe: transfers served at once (the rest wait,
   * their offers kept); onEvent(e): {type: 'transfer', what, id, …}.
   */
  constructor({ carrier, io, rtc = async () => null, stun = null, env = {}, pro = () => false, compared = () => false, maxServe = Infinity, onEvent = () => {}, retryMs = RETRY_MS, torConnectMs = 120_000, timer = true }) {
    Object.assign(this, { carrier, io, rtcLoad: rtc, stun, env, pro, compared, maxServe, onEvent, retryMs, torConnectMs });
    this.attempts = new Map();   // id → { role, attempt, peer, channel, proto, onion, server, got, sent, path }
    this.held = [];              // offers waiting for a free slot (maxServe)
    this.chain = Promise.resolve(); this.again = false; this.running = false; this.closed = false;
    this.timer = timer ? setInterval(() => this.kick(), 2000) : null; this.timer?.unref?.();
    this.capsAt = 0; this.caps = null;
  }
  now() { return nowS(this.carrier); }
  st(fn) { return state(this.io, this.now(), fn); }
  emit(what, x) { try { this.onEvent({ type: 'transfer', what, ...x, at_ms: Date.now() }); } catch {} }
  async rtc() { if (this.rtcMod === undefined) this.rtcMod = await this.rtcLoad(); return this.rtcMod; }
  async torCaps() {
    const on = this.st((s) => settingsOf(s).tor);
    if (!on || !this.io.tor) return { serve: false, connect: false };
    if (!this.caps || Date.now() - this.capsAt > 60_000) { this.caps = await this.io.tor.caps(); this.capsAt = Date.now(); }
    return this.caps;
  }
  stunOf(c) { return this.stun ?? stunFor(this.carrier, c, this.env); }
  /** One round soon (a `transfer` event, a kick from a verb beside this process). */
  kick() {
    if (this.closed) return this.chain;
    if (this.running) { this.again = true; return this.chain; }
    this.running = true;
    this.chain = this.chain.then(async () => { do { this.again = false; await this.round(); } while (this.again && !this.closed); }).catch((e) => this.emit('error', { detail: e.message })).finally(() => { this.running = false; });
    return this.chain;
  }
  live() { return this.attempts.size > 0 || this.st((s) => Object.values(s.in).some((r) => STATES_LIVE_IN.includes(r.state)) || Object.values(s.out).some((r) => STATES_LIVE_OUT.includes(r.state))); }
  /** Resolves true when nothing is live (busy: another test), false once ms passed. */
  async idle(ms = Infinity, busy = () => this.live()) {
    const until = Date.now() + ms;
    while (Date.now() < until && !this.closed) {
      await this.kick();
      if (!busy()) return true;
      await new Promise((r) => setTimeout(r, 500));
    }
    return false;
  }
  progress(id) {
    const a = this.attempts.get(id);
    if (a) return { live: a.path ?? 'connecting', got: a.got, sent: a.sent, rate: a.rate ?? null };
    return this.held.some((h) => h.r.id === id) ? { live: 'waiting', got: 0, sent: 0, rate: null } : null;
  }
  /** An attempt of this process stopped (cancel, forget). */
  drop(id, reason) { this.held = this.held.filter((h) => h.r.id !== id); const a = this.attempts.get(id); if (!a) return; this.attempts.delete(id); a.stopped = reason; try { a.proto?.stop(reason); } catch {} this.closeAttempt(a); }
  async close() {
    this.closed = true;
    if (this.timer) clearInterval(this.timer);
    await this.chain.catch(() => {});
    for (const [id, a] of [...this.attempts]) {
      this.attempts.delete(id);
      a.stopped = 'closed';
      try { a.proto?.stop('cancelled'); } catch {}
      this.closeAttempt(a);
      // Stopped here, not refused there: the receiver may resume it later.
      this.st((s) => { const r = s.in[id] ?? s.out[id]; if (r && r.state === 'active') r.state = s.in[id] ? 'interrupted' : 'offered'; });
    }
  }
  closeAttempt(a) {
    try { a.channel?.close(); } catch {}
    try { a.peer?.close(); } catch {}
    try { this.io.tor?.close(a); } catch {}
  }

  async round(pick) {
    for (const m of this.carrier.takeTransfers(pick)) {
      try { await this.#onMessage(m); } catch (e) {
        if (!(e instanceof MsgError)) throw e;
        this.emit('refused', { from: m.from, check: e.check, detail: e.message });
      }
    }
    const now = this.now();
    const todo = this.st((s) => {
      const out = [];
      for (const r of Object.values(s.in)) {
        if (r.state === 'asked' && r.exp <= now) { r.state = 'expired'; r.at = now; }
        if (r.state === 'accepted' && !this.attempts.has(r.id)) out.push(r.id);
        if ((r.state === 'offering' || r.state === 'active') && !this.attempts.has(r.id)) { r.state = 'interrupted'; r.reason = 'drop'; r.retryAt = 0; }
        if (r.state === 'offering' && r.offerAt + ANSWER_WAIT < now) { r.state = 'interrupted'; r.reason = 'lapsed'; r.detail = 'no answer within 10 minutes: is the sender online? transfer resume'; this.drop(r.id, 'lapsed'); }
        if (r.state === 'interrupted' && r.reason === 'drop' && (r.auto ?? 0) < RETRIES_AUTO && !this.attempts.has(r.id) && (r.retryAt ?? 0) <= Date.now()) { r.auto = (r.auto ?? 0) + 1; r.state = 'accepted'; out.push(r.id); }
        if (['interrupted', 'failed', 'cancelled'].includes(r.state) && (r.last ?? r.at) + MANIFEST_TTL < now && (this.io.part.exists?.(r.id) ?? true)) { dropPartial(this.io, r.id); r.state = 'expired'; }
      }
      for (const r of Object.values(s.out)) {
        if (r.state === 'offered' && r.exp <= now) { r.state = 'expired'; r.at = now; }
        if (r.state === 'active' && !this.attempts.has(r.id)) r.state = 'offered';
      }
      return out;
    });
    if (pick) return;   // intake: no session here
    // Offers held for a free slot (maxServe), oldest first.
    while (this.held.length && this.serving() < this.maxServe) { const h = this.held.shift(); void this.#onOffer(h.r, h.x, h.m).catch((e) => this.emit('error', { id: h.r.id, detail: e.message })); }
    for (const id of todo) await this.#offer(id).catch((e) => this.fail('in', id, e.check ?? 'offer', e.message));
  }
  serving() { let n = 0; for (const a of this.attempts.values()) if (a.role === 'out') n++; return n; }

  fail(side, id, reason, detail) {
    this.st((s) => { const r = s[side][id]; if (r && !['done', 'cancelled', 'declined'].includes(r.state)) Object.assign(r, { state: 'failed', reason, detail, at: this.now() }); });
    this.emit('failed', { id, side, reason, detail });
  }

  async #onMessage(m) {
    const x = checkMessage(m.content), now = this.now();
    if (x.typ === 'manifest') {
      let c = null;
      try { c = contactOf(this.carrier, m.from); } catch {}
      const trust = c ? trustOf(c, this.compared) : 'other';
      const r = this.st((s) => {
        if (s.in[x.id]) return null;   // seen
        if (x.exp <= now) return null;
        const waiting = Object.values(s.in).filter((y) => y.state === 'asked');
        if (waiting.length >= WAIT_ALL || waiting.filter((y) => y.from === m.from).length >= WAIT_CONTACT) return 'busy';
        const rec = { id: x.id, from: m.from, contact: m.name, name: safeName(x.name), size: x.size, sha256: x.sha256, chunks: x.chunks, list: x.list, exp: x.exp, state: 'asked', attempt: 0, at: now, got: 0 };
        s.in[x.id] = rec;
        // The accept rule: a yes given by the rule, when the disk has room and direct is allowed.
        const mb = Object.hasOwn(s.auto, m.from) ? s.auto[m.from] : null;
        if (c && acceptRule({ size: x.size, trust, limitMb: mb, defaultMb: autoDefault(s), direct: directFor(s, c) === true }) === 'auto') {
          try { room(this.io, rec); rec.state = 'accepted'; rec.auto = 0; rec.by = 'rule'; } catch {}
        }
        return { ...rec };
      });
      if (r === 'busy') { await sendMsg(this.carrier, m.from, { typ: 'end', id: x.id, reason: 'busy' }, false).catch(() => {}); return; }
      if (r) this.emit(r.state === 'accepted' ? 'landing' : 'asked', { id: r.id, from: r.from, contact: r.contact, name: r.name, size: r.size });
      return;
    }
    // Any other: only from the contact the transfer is with.
    const { side, r } = this.st((s) => (s.out[x.id]?.to === m.from ? { side: 'out', r: { ...s.out[x.id] } } : s.in[x.id]?.from === m.from ? { side: 'in', r: { ...s.in[x.id] } } : { side: null, r: null }));
    if (!r) fail('transfer_unknown', `a ${x.typ} for a transfer this agent has with no such contact`);
    if (x.typ === 'end') return this.#onEnd(side, r, x);
    // Detached: ICE (30 s) and a Tor connection (up to 2 minutes) must not hold the next message.
    const bg = (p) => { void p.catch((e) => this.emit('error', { id: r.id, detail: e.message })); };
    if (side === 'out' && x.typ === 'offer') {
      // Every slot busy: the offer waits here (it lives 10 minutes there).
      if (this.serving() >= this.maxServe && !this.attempts.has(r.id)) { this.held = this.held.filter((h) => h.r.id !== r.id); this.held.push({ r, x, m }); this.emit('waiting', { id: r.id }); return; }
      return bg(this.#onOffer(r, x, m));
    }
    if (side === 'in' && x.typ === 'answer') return bg(this.#onAnswer(r, x));
    if (x.typ === 'onion') return bg(this.io.tor ? this.io.tor.connect(this, side, r, x, this.attempts.get(r.id)) : Promise.resolve());
    fail('transfer_message', `a ${x.typ} on the ${side === 'in' ? 'receiving' : 'sending'} side`);
  }

  async #onEnd(side, r, x) {
    const a = this.attempts.get(r.id);
    if (x.reason === 'try_tor') {
      if (side !== 'out' || !a || a.attempt !== x.attempt || !this.io.tor) return;
      return this.io.tor.serve(this, side, r, a);
    }
    if (x.reason === 'done' && side === 'out') {
      this.st((s) => { if (s.out[r.id]) Object.assign(s.out[r.id], { state: 'done', at: this.now(), sent: r.size }); });
      if (a) { this.attempts.delete(r.id); this.closeAttempt(a); }
      this.emit('done', { id: r.id, side, name: r.name });
      return;
    }
    if (a && x.attempt !== undefined && x.attempt !== a.attempt) return;
    if (a) { this.attempts.delete(r.id); a.stopped = x.reason; try { a.proto?.stop(x.reason); } catch {} this.closeAttempt(a); }
    this.held = this.held.filter((h) => h.r.id !== r.id);
    const st = x.reason === 'declined' ? 'declined' : x.reason === 'cancelled' ? 'cancelled' : 'failed';
    this.st((s) => { const y = s[side][r.id]; if (y && !['done'].includes(y.state)) Object.assign(y, { state: st, ...(st === 'failed' && { reason: x.reason, detail: x.reason === 'no_path' ? noPath(y.contact) : `the other side ended it: ${x.reason}` }), at: this.now() }); });
    if (side === 'in' && ['cancelled', 'chunk_hash', 'file_changed'].includes(x.reason)) dropPartial(this.io, r.id);
    this.emit(st, { id: r.id, side, reason: x.reason });
  }

  // ---- the receiver: an attempt is an offer
  async #offer(id) {
    const now = this.now();
    const prev = this.attempts.get(id);
    if (prev) { this.attempts.delete(id); this.closeAttempt(prev); }
    const r = this.st((s) => ({ ...s.in[id], directOk: directFor(s, contactOf(this.carrier, s.in[id].from)) === true, pro: this.pro(), prefer: settingsOf(s).prefer }));
    // Every chunk here already (it came whole, then could not be saved): saved again, no network.
    if (r.chunks > 0 && haveOf(this.io, r).done()) return this.#land(r, null);
    const c = contactOf(this.carrier, r.from), tor = await this.torCaps(), rtc = await this.rtc();
    // The paths this attempt may take, in order; Tor here means this side can play either part.
    const order = pathOrder({ pro: r.pro, prefer: r.prefer, via: r.via === 'tor' ? 'tor' : 'auto', direct: r.directOk && rtc !== null, tor: tor.serve || tor.connect });
    if (order.length === 0) {
      this.fail('in', id, 'no_path', r.directOk ? noPath(c.name) : `direct is off for ${c.name} and Tor is not on here: ${noPath(c.name)}`);
      await sendMsg(this.carrier, r.from, { typ: 'end', id, reason: 'no_path' }, false).catch(() => {});
      return;
    }
    const attempt = (r.attempt ?? 0) + 1, a = { role: 'in', attempt, order, tor, got: 0, sent: 0 };
    this.attempts.set(id, a);
    let sdp = null;
    if (order[0] === 'direct') {
      a.peer = await rtc.peer({ stun: this.stunOf(c), gatherMs: GATHER_MS });
      sdp = await a.peer.offer(channelLabel(id, attempt));
    }
    this.st((s) => Object.assign(s.in[id], { state: 'offering', attempt, offerAt: this.now(), path: order[0] }));
    await sendMsg(this.carrier, r.from, { typ: 'offer', id, attempt, sdp, tor, ...(order[0] === 'tor' && { via: 'tor' }) }, false);
    this.emit('offered', { id, attempt, path: order[0] });
  }
  async #onAnswer(r, x) {
    const a = this.attempts.get(r.id);
    if (!a || a.attempt !== x.attempt || a.answered) return;
    a.answered = true; a.peerTor = x.tor;
    this.st((s) => { if (s.in[r.id]) s.in[r.id].state = 'active'; });
    if (a.order[0] === 'direct' && x.sdp !== null && a.peer) {
      try {
        await a.peer.accept(x.sdp);
        a.path = 'direct';
        const ch = await a.peer.open(ICE_MS);
        if (this.attempts.get(r.id) !== a) { ch.close(); return; }
        return this.pull(r, a, ch);
      } catch (e) { if (this.attempts.get(r.id) !== a) return; a.peer?.close(); a.peer = null; this.emit('no_direct', { id: r.id, detail: e.message }); }
    }
    return this.#nextPath(r, a, a.order[0] === 'direct' ? 1 : 0);
  }
  // The receiver, after the direct path failed (or was not offered): Tor if both sides can, else the next attempt or no path.
  async #nextPath(r, a, k) {
    const rest = a.order.slice(k);
    const who = torRoles(a.peerTor, a.tor);
    if (rest[0] === 'tor' && who && this.io.tor) {
      a.path = 'tor';
      if (who === 'receiver') return this.io.tor.serve(this, 'in', r, a);
      await sendMsg(this.carrier, r.from, { typ: 'end', id: r.id, reason: 'try_tor', attempt: a.attempt }, false);
      return;
    }
    // Tor first (Pro private) and it cannot: direct as a new attempt.
    if (rest[0] === 'tor' && rest.includes('direct') && a.order[0] === 'tor') {
      this.st((s) => { s.in[r.id].via = 'auto'; s.in[r.id].state = 'accepted'; });
      this.attempts.delete(r.id); this.closeAttempt(a);
      return this.kick();
    }
    this.attempts.delete(r.id); this.closeAttempt(a);
    const c = contactOf(this.carrier, r.from);
    this.fail('in', r.id, 'no_path', noPath(c.name));
    await sendMsg(this.carrier, r.from, { typ: 'end', id: r.id, reason: 'no_path', attempt: a.attempt }, false).catch(() => {});
  }

  // ---- the sender: an offer is answered
  async #onOffer(r0, x, m) {
    // The record as it is now (a held offer waited).
    const r = this.st((s) => (s.out[r0.id] ? { ...s.out[r0.id] } : null));
    if (!r) return;
    if (['done', 'cancelled', 'declined', 'expired'].includes(r.state)) { await sendMsg(this.carrier, m.from, { typ: 'end', id: r.id, reason: r.state === 'done' ? 'done' : 'cancelled' }, false).catch(() => {}); return; }
    if (x.attempt <= (r.attempt ?? 0)) return;
    const prev = this.attempts.get(r.id);
    if (prev) { this.attempts.delete(r.id); this.closeAttempt(prev); }
    // Read in place: the file must be the one hashed (size and modification time).
    if (await this.io.changed(r)) {
      this.fail('out', r.id, 'file_changed', `${r.name} changed or went since it was offered: send it again`);
      await sendMsg(this.carrier, m.from, { typ: 'end', id: r.id, reason: 'file_changed' }, false).catch(() => {});
      return;
    }
    const c = contactOf(this.carrier, r.to), tor = await this.torCaps(), rtc = await this.rtc();
    const directOk = this.st((s) => directFor(s, c) === true) && r.via !== 'tor' && x.via !== 'tor' && x.sdp !== null && rtc !== null;
    const a = { role: 'out', attempt: x.attempt, tor, peerTor: x.tor, got: 0, sent: 0 };
    this.attempts.set(r.id, a);
    this.st((s) => Object.assign(s.out[r.id], { state: 'active', attempt: x.attempt }));
    let sdp = null;
    if (directOk) {
      a.peer = await rtc.peer({ stun: this.stunOf(c), gatherMs: GATHER_MS });
      sdp = await a.peer.answer(x.sdp, channelLabel(r.id, x.attempt));
    }
    await sendMsg(this.carrier, m.from, { typ: 'answer', id: r.id, attempt: x.attempt, sdp, tor }, false);
    if (!a.peer) return;   // the receiver says what comes next: try_tor, an onion, or end
    try {
      a.path = 'direct';
      const ch = await a.peer.open(ICE_MS);
      if (this.attempts.get(r.id) !== a) { ch.close(); return; }
      this.serve(r, a, ch);
    } catch { if (this.attempts.get(r.id) === a) { a.peer?.close(); a.peer = null; a.path = null; } }
  }

  // ---- the bytes
  serve(r, a, ch) {
    a.channel = ch;
    const hashes = this.io.list.read(r.id, 'out');
    let src = null;
    const t0 = Date.now();
    const read = async (i) => { src ??= await this.io.source(r); return src.read(i); };
    this.emit('active', { id: r.id, side: 'out', path: a.path });
    a.proto = new Serve({
      m: { ...r }, hashes, channel: ch, read,
      onProgress: (n) => { a.sent = n; a.rate = n / 1e6 / Math.max(0.001, (Date.now() - t0) / 1000); },
      onEnd: (reason, o) => {
        void src?.close().catch(() => {});
        if (this.attempts.get(r.id) !== a) return;
        this.attempts.delete(r.id); this.closeAttempt(a);
        if (reason === 'done' && o.remote) {
          this.st((s) => { if (s.out[r.id]) Object.assign(s.out[r.id], { state: 'done', at: this.now(), sent: r.size, path_used: a.path }); });
          this.emit('done', { id: r.id, side: 'out', name: r.name, via: a.path, rate: a.rate });
        } else if (reason === 'chunk_hash' || reason === 'file_changed') {
          this.fail('out', r.id, reason, `ended: ${reason}`);
        } else {
          // A drop or a stop on the channel: the receiver resumes with a new offer; a cancel comes as an end message.
          this.st((s) => { if (s.out[r.id]?.state === 'active') s.out[r.id].state = 'offered'; });
          this.emit('interrupted', { id: r.id, side: 'out' });
        }
        void this.kick();   // a slot is free: a held offer goes
      },
    });
    a.proto.start();
  }
  pull(r, a, ch) {
    a.channel = ch;
    const io = this.io, id = r.id;
    const have = haveOf(io, r);
    let known = io.list.read(id, 'in');
    if (known && listOf(known) !== r.list) known = null;
    a.got = have.bytes(r.size);
    const t0 = Date.now(), start = a.got;
    let saved = Date.now(), part = null;
    const opened = io.part.open(id).then((p) => { part = p; return p; });
    this.emit('active', { id, side: 'in', path: a.path });
    a.proto = new Pull({
      m: { ...r, chunk: CHUNK }, have, hashes: known, channel: ch, flushEach: io.flushEach ?? 8,
      write: async (i, bytes) => { await (await opened).write(bytes, i * CHUNK); },
      flush: async () => {
        await (await opened).flush();
        // The bitmap once Pull has set the bits, after the bytes are on disk: a bit means checked and flushed.
        later(() => {
          if (!a.landed) { try { io.have.write(id, have.bits); } catch {} }
          if (Date.now() - saved > 2000) { saved = Date.now(); this.st((s) => { if (s.in[id]) Object.assign(s.in[id], { got: a.got, last: this.now() }); }); }
        });
      },
      onList: (h) => { try { io.list.write(id, 'in', h); } catch {} },
      onProgress: (n) => { a.got += n; a.rate = (a.got - start) / 1e6 / Math.max(0.001, (Date.now() - t0) / 1000); },
      onEnd: (reason, o) => { void opened.then(() => this.#pulled(r, a, part, have, reason, o), (e) => this.#pulled(r, a, null, have, 'cancelled', { gone: true, error: e })); },
    });
    a.proto.start();
  }
  async #pulled(r, a, part, have, reason, o) {
    const id = r.id, io = this.io, carrier = this.carrier;
    try { io.have.write(id, have.bits); } catch {}
    if (reason !== 'complete') {
      try { await part?.close(); } catch {}
      if (this.attempts.get(id) !== a) return;
      this.attempts.delete(id); this.closeAttempt(a);
      if (o.gone || (reason === 'cancelled' && !o.remote)) return this.interrupt(id, 'drop', 'the channel went: resumed with a new offer');
      if (reason === 'cancelled') { this.st((s) => { if (s.in[id]) Object.assign(s.in[id], { state: 'cancelled', at: this.now() }); }); dropPartial(io, id); return; }
      this.fail('in', id, reason, `ended: ${reason}`);
      if (reason === 'chunk_hash' || reason === 'file_changed') dropPartial(io, id);
      if (!o.remote) await sendMsg(carrier, r.from, { typ: 'end', id, reason, attempt: a.attempt }, false).catch(() => {});
      return;
    }
    // Every chunk checked and flushed: the whole file read back from disk.
    await part.flush(); await part.close();
    if ((await io.part.sha256(id)) !== r.sha256) {
      a.proto.finish('chunk_hash');
      this.attempts.delete(id); this.closeAttempt(a);
      dropPartial(io, id);
      this.fail('in', id, 'chunk_hash', 'the file read back is not the manifest\'s: dropped');
      return;
    }
    return this.#land(r, a);
  }
  // A file read back whole: placed (io.land), one inbox item, the sender told done. Not placed (no room, no
  // permission): said in the record (failed, land), the partial kept; resume tries again without the network.
  async #land(r, a) {
    const id = r.id, io = this.io, carrier = this.carrier;
    if (!a && (await io.part.sha256(id)) !== r.sha256) {
      dropPartial(io, id);
      this.fail('in', id, 'chunk_hash', 'the file read back is not the manifest\'s: dropped');
      return;
    }
    const c = contactOf(carrier, r.from);
    let path;
    try { path = await io.land(r, c); } catch (e) {
      if (a) { this.attempts.delete(id); this.closeAttempt(a); }
      this.fail('in', id, 'land', `${r.name} came whole but could not be saved: ${e.message}`);
      return;
    }
    if (a) a.landed = true;
    io.have.write(id, null); io.list.drop(id, 'in');
    a?.proto.finish('done');
    this.st((s) => { if (s.in[id]) Object.assign(s.in[id], { state: 'done', got: r.size, at: this.now(), saved: path, path_used: a?.path ?? s.in[id].path_used ?? null }); delete s.in[id]?.reason; delete s.in[id]?.detail; });
    if (a) { this.attempts.delete(id); setTimeout(() => this.closeAttempt(a), 2000).unref?.(); }
    carrier.deliver({ type: 'file', from: c.did, contact: c.name, current_did: c.current_did, label: FILE_LABEL, name: r.name, size: r.size, sha256: r.sha256, path, transfer: id, via: a?.path ?? null });
    await sendMsg(carrier, r.from, { typ: 'end', id, reason: 'done', ...(a && { attempt: a.attempt }) }, false).catch(() => {});
    this.emit('done', { id, side: 'in', name: r.name, path, via: a?.path ?? null, rate: a?.rate ?? null });
  }
  interrupt(id, reason, detail) {
    this.st((s) => { const r = s.in[id]; if (r && STATES_LIVE_IN.includes(r.state)) Object.assign(r, { state: 'interrupted', reason, detail, retryAt: Date.now() + this.retryMs, last: this.now() }); });
    this.emit('interrupted', { id, side: 'in', reason });
  }
}

/** Without an engine (a CLI inbox, transfer list): the manifests and ends the carrier kept, filed. → the files now asked. */
export async function intake({ carrier, io, compared }) {
  const e = new Engine({ carrier, io, compared, timer: false });
  const asked = [];
  e.onEvent = (x) => { if (x.what === 'asked') asked.push(x); };
  await e.round((m) => ['manifest', 'end'].includes(m?.content?.typ) && m.content.reason !== 'try_tor');
  await e.close();
  return asked;
}
