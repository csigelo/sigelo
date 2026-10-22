// SPDX-License-Identifier: MIT
// Remote control over the relay (design/apps.md §6.3; adapters/moadim/UI-API.md "Remote"): an app
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
//                                   any request), never polled
//
//   const ctl = makeControl({ operator, timeout })     the client: its carrier is attached after
//   carrier = new Carrier({ ..., onEvent: (e) => ctl.onEvent(e) }); ctl.attach(carrier)
//   await ctl.call(method, path, body) → { status, body }: GET /api/state from the last pushed state
//                                   while the lease runs (no relay message), anything else one request
//   ctl.onChange(fn)               fn() after each pushed state
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
// The computer's cap per control: a bucket of BURST requests, refilled at RATE a second.
export const RATE = 1, BURST = 10;
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
export const newId = () => bytesToHex(randomBytes(8));
export const requestMessage = ({ id, method, path, body }) => ({ v: CONTROL_V, typ: 'request', id, method, path, ...(body !== undefined && { body }) });
export const responseMessage = ({ id, status, body }) => ({ v: CONTROL_V, typ: 'response', id, status, body });
export const eventsMessage = ({ seq, since, state }) => ({ v: CONTROL_V, typ: 'events', seq, since, state });
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
  return c;
}

/** The computer's cap per control: take() → whether a request may run now. */
export function bucket({ rate = RATE, burst = BURST, now = () => Date.now() } = {}) {
  let tokens = burst, at = now();
  return { take() { const t = now(); tokens = Math.min(burst, tokens + ((t - at) / 1000) * rate); at = t; if (tokens < 1) return false; tokens -= 1; return true; } };
}

const err = (status, check, message) => ({ status, body: { error: { check, message } } });

/** The app's side: requests out, responses matched by id, pushed states kept for GET /api/state. */
export function makeControl({ operator, timeout = CALL_TIMEOUT, now = () => Date.now(), defer = (f) => setTimeout(f, 0) }) {
  let carrier = null, state = null, asked = -Infinity, taking = false;
  const waiting = new Map(), watchers = new Set(), events = new Map();
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
      if (c.typ === 'response') {
        const w = waiting.get(c.id);
        if (!w) continue;
        waiting.delete(c.id); clearTimeout(w.timer);
        w.ok({ status: c.status, body: c.body });
      } else if (c.typ === 'events') { keep(c.state); changed = true; }
    }
    if (changed) for (const f of watchers) { try { f(); } catch {} }
  }
  const soon = () => { if (!taking) { taking = true; defer(take); } };
  async function request(method, path, body) {
    const id = newId();
    const answer = new Promise((ok) => { waiting.set(id, { ok, timer: setTimeout(() => { waiting.delete(id); ok(err(504, 'remote', `no answer from your computer within ${Math.round(timeout / 1000)} s: is sigelo-agent ui running there, and online?`)); }, timeout) }); });
    asked = now();
    try { await carrier.send(operator, requestMessage({ id, method, path, ...(body !== undefined && { body }) }), { label: DEVICE_LABEL, internal: DEVICE_SEND }); } catch (e) {
      const w = waiting.get(id);
      if (w) { waiting.delete(id); clearTimeout(w.timer); }
      return err(e.check === 'not_contact' ? 403 : 502, 'remote', e.check === 'not_contact' ? 'this app is no longer paired with your computer: pair it again' : `not sent to your computer (${e.message})`);
    }
    soon();
    const r = await answer;
    // The seat moved, or this control is refused: what was pushed no longer stands.
    if (r.status === 409 || r.status === 403) { const c = r.body?.error?.check; if (c === 'seat_elsewhere' || c === 'words') state = null; }
    if (method === 'GET' && r.status === 200 && new URL(path, 'http://app').pathname === '/api/state' && isObject(r.body)) keep(r.body);
    return r;
  }
  return {
    attach(c) { carrier = c; soon(); },
    onEvent(e) { if (e.type === 'device' || e.type === 'connected') soon(); },
    async call(method, path, body) {
      if (carrier === null) return err(503, 'remote', 'not connected yet');
      let url;
      try { url = new URL(path, 'http://app'); } catch { return err(404, 'route', 'not a route'); }
      // The pushed state stands for GET /api/state while the lease runs: no relay message.
      if (method === 'GET' && url.pathname === '/api/state' && state !== null && now() - asked < RENEW * 1000) {
        return { status: 200, body: JSON.parse(JSON.stringify(local(Number(url.searchParams.get('since') ?? 0) || 0))) };
      }
      return request(method, path, body);
    },
    onChange(fn) { watchers.add(fn); return () => watchers.delete(fn); },
    get state() { return state; },
    stop() { for (const [, w] of waiting) { clearTimeout(w.timer); w.ok(err(503, 'remote', 'stopped')); } waiting.clear(); },
  };
}
