// SPDX-License-Identifier: MIT
// Remote control over the relay (design/apps.md §6.3; apps/agent/UI-API.md "Remote"): an app
// drives the page of `sigelo-agent ui` on a computer through the relay, holding no account key.
//
// The control identity: a random Ed25519 key made where the app runs (newControlIdentity), never
// derived, never attested, never enrolled, in no device list; recovery null (lost: revoke it on the
// computer and pair a new one). It pairs with the operator by a short code the computer prints as
//   SIGELO:CTL:<short code>[:<HOST>]   (controlText; :HOST, upper case, when the relay is not the default)
// and the four words both sides show, confirmed on the computer. The computer forgets it on revoke.
//
// Messages, sigelo-device/1 (devices.md §7.2) over that pairing (control DID ↔ operator DID), sent
// with the carrier's DEVICE_SEND, kept apart by it (takeDevices), never logged:
//   request   control → operator  { v, typ: "request", id, method, path, body? }   id: 16 hex
//   response  operator → control  { v, typ: "response", id, status, body }         the UI-API JSON, as the
//                                   local listener answers it ({status, body} of the LAN path)
//   events    operator → control  { v, typ: "events", seq, since, state }          GET /api/state?since=<since>,
//                                   pushed on change while the control holds a lease (LEASE, renewed by
//                                   any request), never polled; past PUSH_MAX a summary (capState:
//                                   truncated), and the app pulls the rest (GET /api/state?full=1)
//
//   const ctl = makeControl({ operator, timeout })     the client: its carrier is attached after
//   carrier = new Carrier({ ..., onEvent: (e) => ctl.onEvent(e) }); ctl.attach(carrier)
//   await ctl.call(method, path, body) → { status, body }: GET /api/state from the last pushed state
//                                   while the lease runs (no relay message), anything else one request
//   ctl.onChange(fn)               fn() after each pushed state
//   ctl.connected                  whether the computer's lease runs (an answer to a request within LEASE)
//
// Quiet without a lease (2026-11: an app left open four days against a computer whose page was gone
// published up to its relay day's cap, 3,000 a day, every poll a request nobody read): a request goes
// only while the computer's lease runs, renewed by its ANSWER, never by the request itself. Without one
// (never answered, an answer missed, refused words or seat) one call at a time is let through as a
// probe, PROBE_MIN seconds after the last one failed, doubling to PROBE_MAX; every other call is
// answered 503 not_connected here, no relay message. Each message carries exp (now + TTL, seconds):
// the carrier drops it unsent past it, the reader drops it late, so a backlog left at the relay by a
// control gone never runs on a computer that comes back.
import { keygen } from 'sigelo';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { DEVICE_LABEL, DEVICE_SEND } from './carrier.mjs';
import { fail } from './kdf.mjs';
import { formatShort, normaliseShort } from './short.mjs';

export const CTL_PREFIX = 'SIGELO:CTL:', CONTROL_V = 'sigelo-device/1';
// A lease of pushed events: this long after the control's last request (seconds); the client renews
// it with one request (GET /api/state) once RENEW has passed, so an open app costs one request per RENEW.
export const LEASE = 600, RENEW = 300;
// An answer longer than this is refused too_large (a free reader's message cap is 256 KiB).
export const ANSWER_MAX = 192 * 1024;
export const CALL_TIMEOUT = 30_000;
// A pushed state longer than this goes as a summary (capState): the newest PUSH_KEEP contacts of each
// group and events, the counts, truncated; the app shows it and pulls the whole on demand (a request).
export const PUSH_MAX = 64 * 1024, PUSH_KEEP = 20;
// The computer's cap per control: a bucket of BURST requests, refilled at RATE a second.
export const RATE = 1, BURST = 10;
// Without a lease: the first probe PROBE_MIN seconds after a failed one, the gap doubling to PROBE_MAX
// (an hour with nobody listening: 9 probes, then 3 an hour).
export const PROBE_MIN = 15, PROBE_MAX = 1200;
// A control message's life (seconds): past now + TTL it is dropped unsent (carrier) or unread.
export const TTL = 300;
// GETs the page polls every 2 s that the pushed state does not carry (the Agents view's list): answered
// from the last answer for KEEP_GET seconds, asked again at once after any POST (Enrol, revoke) or when a
// pushed state's seq moves. An open Agents view: 120 an hour, not 1,800 (LAN and local pages keep 2 s).
export const KEEP_GET = 30, KEPT = new Set(['/api/agents/workers']);
const ID = /^[0-9a-f]{16}$/;

/** The QR text: SIGELO:CTL:K7F3-Q9ZP, with :HOST (upper case) when the relay is not the default. */
export function controlText(short, host) {
  const code = formatShort(normaliseShort(short));
  if (host === undefined || host === null) return `${CTL_PREFIX}${code}`;
  if (typeof host !== 'string' || !/^[a-z0-9.-]+(:\d{1,5})?$/i.test(host) || host.length > 40) fail('control_text', `relay ${JSON.stringify(host)}: a host name (and port)`);
  return `${CTL_PREFIX}${code}:${host.toUpperCase()}`;
}
/** SIGELO:CTL:<code>[:<HOST>] → { code (normalised), relay (lower case) | null }; else throws control_text. */
export function readControlText(text) {
  const t = typeof text === 'string' ? text.trim() : '';
  if (!t.toUpperCase().startsWith(CTL_PREFIX)) fail('control_text', 'not a SIGELO:CTL: text');
  const [code, ...host] = t.slice(CTL_PREFIX.length).split(':');
  const relay = host.length ? host.join(':').toLowerCase() : null;
  if (relay !== null && (!/^[a-z0-9.-]+(:\d{1,5})?$/.test(relay) || relay.length > 40)) fail('control_text', 'SIGELO:CTL:<code>:<HOST>: a host name');
  return { code: normaliseShort(code), relay };
}

/** A control identity, as an identity file ({ v, secret, genesis, … }): a random key, recovery null. */
export function newControlIdentity() {
  const warn = console.warn;
  let k;
  // keygen warns about recovery null for an agent's identity; a control's is thrown away, not recovered.
  console.warn = () => {};
  try { k = keygen({ recovery: null }); } finally { console.warn = warn; }
  return { v: 'sigelo/0', control: true, secret: bytesToHex(k.secret), genesis: k.genesis, rotations: [], attestations: [], issuers: [] };
}

const isObject = (x) => typeof x === 'object' && x !== null && !Array.isArray(x);

/**
 * A state to push: itself while its JSON is at most max; else a summary that fits: each group's
 * newest keep contacts (by their last message), the newest keep events, every other field as it
 * was, and truncated: { contacts: {group: count}, events: count, kept } (the counts of the whole).
 * keep halves until it fits (0: the groups and events empty).
 */
export function capState(st, max = PUSH_MAX, keep = PUSH_KEEP) {
  if (!isObject(st) || JSON.stringify(st).length <= max) return st;
  const groups = isObject(st.groups) ? st.groups : {}, events = Array.isArray(st.events) ? st.events : [];
  const newest = (xs, n) => [...xs].sort((a, b) => (b?.last?.at ?? 0) - (a?.last?.at ?? 0)).slice(0, n);
  const counts = Object.fromEntries(Object.entries(groups).map(([g, xs]) => [g, Array.isArray(xs) ? xs.length : 0]));
  for (let n = keep; ; n = n > 1 ? Math.floor(n / 2) : 0) {
    const out = { ...st, groups: Object.fromEntries(Object.entries(groups).map(([g, xs]) => [g, Array.isArray(xs) ? newest(xs, n) : xs])),
      events: events.slice(-n), truncated: { contacts: counts, events: events.length, kept: n } };
    if (n === 0 || JSON.stringify(out).length <= max) return out;
  }
}
export const newId = () => bytesToHex(randomBytes(8));
const ttl = (exp) => (exp !== undefined && { exp });
export const requestMessage = ({ id, method, path, body, exp }) => ({ v: CONTROL_V, typ: 'request', id, method, path, ...(body !== undefined && { body }), ...ttl(exp) });
export const responseMessage = ({ id, status, body, exp }) => ({ v: CONTROL_V, typ: 'response', id, status, body, ...ttl(exp) });
export const eventsMessage = ({ seq, since, state, exp }) => ({ v: CONTROL_V, typ: 'events', seq, since, state, ...ttl(exp) });
/** A message's exp (unix seconds) passed: dropped, unanswered. None (an older sender): never stale. */
export const stale = (c, nowS) => Number.isSafeInteger(c?.exp) && c.exp <= nowS;
/** A control message checked (request, response, events) → it; else throws control_message. */
export function readControl(c) {
  if (!isObject(c) || c.v !== CONTROL_V) fail('control_message', `not a ${CONTROL_V} message`);
  if (c.typ === 'request') {
    if (typeof c.id !== 'string' || !ID.test(c.id) || (c.method !== 'GET' && c.method !== 'POST') || typeof c.path !== 'string' || c.path.length > 2048) fail('control_message', 'request: id, method GET or POST, path');
    if (c.body !== undefined && !isObject(c.body)) fail('control_message', 'request: body, a JSON object');
  } else if (c.typ === 'response') {
    if (typeof c.id !== 'string' || !ID.test(c.id) || !Number.isSafeInteger(c.status)) fail('control_message', 'response: id, status');
  } else if (c.typ === 'events') {
    if (!Number.isSafeInteger(c.seq) || !Number.isSafeInteger(c.since) || !isObject(c.state)) fail('control_message', 'events: seq, since, state');
  } else fail('control_message', `typ ${JSON.stringify(c.typ)}: request, response or events`);
  if (c.exp !== undefined && !Number.isSafeInteger(c.exp)) fail('control_message', 'exp: unix seconds');
  return c;
}

/** The computer's cap per control: take() → whether a request may run now. */
export function bucket({ rate = RATE, burst = BURST, now = () => Date.now() } = {}) {
  let tokens = burst, at = now();
  return { take() { const t = now(); tokens = Math.min(burst, tokens + ((t - at) / 1000) * rate); at = t; if (tokens < 1) return false; tokens -= 1; return true; } };
}

const err = (status, check, message) => ({ status, body: { error: { check, message } } });

/** The app's side: requests out, responses matched by id, pushed states kept for GET /api/state. */
export function makeControl({ operator, timeout = CALL_TIMEOUT, now = () => Date.now(), defer = (f) => setTimeout(f, 0), after = (f, ms) => setTimeout(f, ms), cancel = (t) => clearTimeout(t) }) {
  let carrier = null, state = null, asked = -Infinity, taking = false;
  // lease: until when the computer's lease runs (ms), from the send time of the last request it answered
  // (its answer renews it, never the request alone). Without one: probeAt, the earliest the next probe
  // goes; gap, the back-off (s); probe, the one in flight, which the other calls wait for.
  let lease = -Infinity, probeAt = -Infinity, gap = 0, probe = null;
  const waiting = new Map(), watchers = new Set(), events = new Map(), kept = new Map();
  const nowS = () => Math.floor(now() / 1000);
  const quiet = () => {
    lease = -Infinity;
    if (now() < probeAt) return;   // already backing off (several calls that failed together count once)
    gap = gap ? Math.min(gap * 2, PROBE_MAX) : PROBE_MIN;
    probeAt = now() + gap * 1000;
  };
  const keep = (st) => {
    for (const e of st.events ?? []) events.set(e.n, e);
    for (const n of [...events.keys()].sort((a, b) => a - b).slice(0, Math.max(0, events.size - 200))) events.delete(n);
    state = st;
  };
  const local = (since) => ({ ...state, events: [...events.values()].filter((e) => e.n > since).sort((a, b) => a.n - b.n).slice(-50) });
  function take() {
    taking = false;
    if (carrier === null) return;
    let changed = false;
    for (const m of carrier.takeDevices()) {
      if (m.from !== operator) continue;
      let c;
      try { c = readControl(m.content); } catch { continue; }
      if (stale(c, nowS())) continue;
      const w = c.typ === 'response' ? waiting.get(c.id) : undefined;
      // The computer is there (an answer come late, a push): the next call probes at once.
      if (!w && now() >= lease) { probeAt = -Infinity; gap = 0; }
      if (w) { waiting.delete(c.id); cancel(w.timer); w.ok({ status: c.status, body: c.body }); }
      else if (c.typ === 'events') { if (c.state.seq !== state?.seq) kept.clear(); keep(c.state); changed = true; }
    }
    if (changed) for (const f of watchers) { try { f(); } catch {} }
  }
  const soon = () => { if (!taking) { taking = true; defer(take); } };
  async function request(method, path, body) {
    const id = newId(), sent = now(), exp = Math.floor(sent / 1000) + TTL;
    let answered = false;
    const answer = new Promise((ok) => { waiting.set(id, { ok: (r) => { answered = true; ok(r); }, end: ok, timer: after(() => { waiting.delete(id); ok(err(504, 'remote', `no answer from your computer within ${Math.round(timeout / 1000)} s: is sigelo-agent ui running there, and online?`)); }, timeout) }); });
    try { await carrier.send(operator, requestMessage({ id, method, path, ...(body !== undefined && { body }), exp }), { label: DEVICE_LABEL, internal: DEVICE_SEND, expires: exp }); } catch (e) {
      const w = waiting.get(id);
      if (w) { waiting.delete(id); cancel(w.timer); }
      quiet();
      return err(e.check === 'not_contact' ? 403 : 502, 'remote', e.check === 'not_contact' ? 'this app is no longer paired with your computer: pair it again' : `not sent to your computer (${e.message})`);
    }
    soon();
    const r = await answer;
    if (!answered) { quiet(); return r; }
    const c = r.body?.error?.check;
    // The seat moved, or this control is refused: what was pushed no longer stands, and no lease runs.
    if ((r.status === 409 && c === 'seat_elsewhere') || (r.status === 403 && c === 'words')) { state = null; quiet(); }
    // Over the computer's rate cap: answered, the lease as it was.
    else if (!(r.status === 429 && c === 'rate')) { lease = Math.max(lease, sent + LEASE * 1000); asked = Math.max(asked, sent); probeAt = -Infinity; gap = 0; }
    if (method === 'GET' && r.status === 200 && new URL(path, 'http://app').pathname === '/api/state' && isObject(r.body)) { if (r.body.seq !== state?.seq) kept.clear(); keep(r.body); }
    return r;
  }
  const notConnected = () => {
    const s = Math.max(0, Math.ceil((probeAt - now()) / 1000));
    return err(503, 'not_connected', `not connected to your computer: it has not answered (is sigelo-agent ui running there, and online?); trying again in ${s} s`);
  };
  // No lease: a call waits for the probe in flight; else it is the probe when one is due; else refused here.
  async function ask(method, path, body) {
    while (now() >= lease) {
      if (probe !== null) { await probe; continue; }
      if (now() < probeAt) return notConnected();
      const p = probe = request(method, path, body);
      try { return await p; } finally { if (probe === p) probe = null; }
    }
    return request(method, path, body);
  }
  return {
    attach(c) { carrier = c; soon(); },
    onEvent(e) { if (e.type === 'device' || e.type === 'connected') soon(); },
    async call(method, path, body) {
      if (carrier === null) return err(503, 'remote', 'not connected yet');
      let url;
      try { url = new URL(path, 'http://app'); } catch { return err(404, 'route', 'not a route'); }
      // A control's four words are confirmed on the computer only: never asked, no relay message.
      if (url.pathname === '/api/controls' || url.pathname.startsWith('/api/controls/')) return err(403, 'remote', 'controls are confirmed on the computer\'s own page only');
      // The pushed state stands for GET /api/state while the lease runs: no relay message. full=1
      // (a pushed summary's "pull the rest") always asks the computer.
      if (method === 'GET' && url.pathname === '/api/state' && state !== null && now() - asked < RENEW * 1000 && url.searchParams.get('full') !== '1') {
        return { status: 200, body: JSON.parse(JSON.stringify(local(Number(url.searchParams.get('since') ?? 0) || 0))) };
      }
      if (method === 'POST') kept.clear();
      const hit = method === 'GET' && KEPT.has(url.pathname) ? kept.get(path) : undefined;
      if (hit && now() - hit.at < KEEP_GET * 1000 && now() < lease) return JSON.parse(JSON.stringify(hit.r));
      const r = await ask(method, path, body);
      if (method === 'GET' && KEPT.has(url.pathname) && r.status === 200) kept.set(path, { at: now(), r: JSON.parse(JSON.stringify(r)) });
      return r;
    },
    onChange(fn) { watchers.add(fn); return () => watchers.delete(fn); },
    get state() { return state; },
    get connected() { return now() < lease; },
    stop() { for (const [, w] of waiting) { cancel(w.timer); w.end(err(503, 'remote', 'stopped')); } waiting.clear(); },
  };
}
