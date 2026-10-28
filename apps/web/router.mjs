// SPDX-License-Identifier: MIT
// The `local` backend of the page (design/apps.md §3): adapters/moadim/UI-API.md's route table in the
// page, over a carrier running in it on the browser platform (platform-web.mjs). The routes are
// contact/page.mjs's, the ones `sigelo-agent ui` serves, so every answer is the same JSON; what this
// app has not (an agents' directory, devices to add, a seat) answers as an empty list or a refusal.
//
//   const r = makeRouter({ platform, identity, mode, options })
//   await r.start()                    one owner per identity (navigator.locks), the session, the first drain
//   await r.call(method, path, body)   → { status, body }: the route's JSON, as the HTTP backend answers it
//   r.onChange(fn)                     fn() after anything that changes /api/state (events pushed; the same `since`)
//   r.mode()                           { kind: 'safe' | 'full', worker?, standby? }: the page's banner
//   await r.stop()
//
// seat: after a restore from seed (seed.mjs seatOf): { info() → {holder, epoch, here} | null, take(now),
// here() → this device {name, did, worker} | null, restored() → {on, keeper, seat} | null }. info().here false: the seat is on another device: start()
// takes the owner lock but never logs in (writes refused 409 seat_elsewhere, the page's banner), until
// POST /api/seat/take {confirm: true} signs the list naming this device (seat take --force semantics).
// identity(): the identity file as sigelo-agent writes it ({ secret, genesis, rotations,
// attestations, issuers }), read at every operation. Its files live under the name `app/me.local.json`
// in the platform's files (contacts, carrier state, history, the page's data, links).
// The relay new codes name: options.relay or the platform's env.relay when given (fixed, as SIGELO_RELAY
// is for `sigelo-agent ui`), else the page's setting (GET/POST /api/settings, in the page's data),
// else relay.sigelo.ai. presetRelay(files, host): the first-start form's choice, before any router.
// keeper: { load() → bytes | null, save(bytes) } (seed.mjs keeperOf: the sealed keeper of a restore or a create):
// the Agents list and their enrolment (contact/page.mjs); without one (an imported SAFE or FULL file) the
// list is empty and enrolling refuses `keeper`.
import { did as didOf } from 'sigelo';
import { Carrier, DEFAULT_RELAY, UNLOGGED, pathsFor } from './vendor/contact/carrier.mjs';
import { checkRelay } from './vendor/contact/invite.mjs';
import { enrolPath } from './vendor/contact/enrol.mjs';
import * as L from './vendor/contact/link.mjs';
import { makePage, refuse } from './vendor/contact/page.mjs';
import { codeKind } from './vendor/contact/short.mjs';

export const IDENTITY = 'app/me.local.json';
const unhex = (s) => {
  if (typeof s !== 'string' || !/^[0-9a-f]{64}$/.test(s)) refuse(409, 'identity', 'this app holds no usable key (secret: 32 bytes as hex)');
  return Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));
};
const bundleOf = (s) => ({ v: 'sigelo/0', typ: 'bundle', genesis: s.genesis, rotations: s.rotations ?? [], bindings: s.bindings ?? [], attestations: s.attestations ?? [], issuers: s.issuers ?? [] });
const headOf = (s) => (s.rotations ?? []).at(-1)?.next_genesis ?? s.genesis;
const utf8 = (s) => new TextEncoder().encode(s);
const text = (b) => (b === null ? null : new TextDecoder().decode(b));

const DATA_FILE = `${IDENTITY.replace(/\.json$/, '')}.ui.json`;
/** The first-start form's relay into the page's data (what POST /api/settings keeps); relay.sigelo.ai or empty: none kept. */
export function presetRelay(files, host) {
  const raw = files.read(DATA_FILE);
  let d = {};
  try { d = raw === null ? {} : JSON.parse(new TextDecoder().decode(raw)) ?? {}; } catch {}
  const h = String(host ?? '').trim().toLowerCase();
  d.settings = { ...(d.settings ?? {}) };
  if (h === '' || h === DEFAULT_RELAY) delete d.settings.relay;
  else { checkRelay(h); d.settings.relay = h; }
  files.write(DATA_FILE, utf8(JSON.stringify(d)));
}

export const FULL_IMPORT = 'an operator identity (FULL) with no signed device list naming this app the seat would log in as you beside the device that holds it (the two lose each other\'s messages): refused. Restore from your 25 words here instead (the seat here or on another device), or import the SAFE file sigelo-agent device scan wrote for this app';
const DEVICES_HERE = 'devices are added, scanned and revoked on the operator\'s computer (sigelo-agent ui), not in this app';

export function makeRouter({ platform, identity, mode: mode0 = { kind: 'safe' }, options = {}, seat = null, keeper = null }) {
  const mode = { ...mode0 };
  const { files } = platform;
  const paths = pathsFor(IDENTITY), base = IDENTITY.replace(/\.json$/, '');
  const historyFile = `${base}.history.jsonl`, dataFile = DATA_FILE, linksFile = L.linksPath(IDENTITY);
  const me = () => {
    const s = identity(), chain = [didOf(s.genesis), ...(s.rotations ?? []).map((r) => didOf(r.next_genesis))];
    return { did: didOf(headOf(s)), original: chain[0], chain };
  };
  let roster = null;
  const opened = async () => { const b = await keeper.load(); if (b === null) return null; try { return JSON.parse(text(b)); } finally { b.fill(0); } };
  const strip = (k) => { if (k === null) return null; const { root_hex: _, ...rest } = k; return rest; };
  const env = Object.fromEntries(Object.entries(platform.env ?? {}).filter(([k, v]) => v !== undefined && v !== null && ['relay', 'endpoints', 'retentionDays', 'shortRelay', 'registry'].includes(k)));
  const page = makePage({
    makeCarrier: (onEvent, kept) => new Carrier({
      identity: () => { const s = identity(); return { secret: unhex(s.secret), bundle: bundleOf(s) }; },
      ...paths, ...kept, ...env, ...options, keep: true, onEvent, platform,
    }),
    relayFixed: options.relay ?? env.relay ?? null,
    link: L, linksFile, enrolFile: enrolPath(IDENTITY), codeKind, unlogged: UNLOGGED,
    // The history and the page's data: files of the platform (IndexedDB behind them), written whole.
    store: {
      readHistory: () => text(files.read(historyFile)),
      append: (line) => { const had = files.read(historyFile); files.write(historyFile, had === null ? utf8(line) : concat(had, utf8(line))); },
      clearHistory: () => files.write(historyFile, new Uint8Array(0)),
      readData: () => text(files.read(dataFile)),
      writeData: (t) => files.write(dataFile, utf8(t)),
    },
    hooks: {
      me,
      meInfo: () => ({ identity_file: IDENTITY, recovery: headOf(identity()).recovery === null ? 'none' : 'set', key: 'browser',
        erase: 'On the machine holding the recovery key, with this identity\'s file: SIGELO_IDENTITY=<file> sigelo-agent erase-request --recovery-key <your recovery.key>',
        ...(seat?.restored() && { restored: seat.restored() }) }),
      // No agents' directory; this device itself (worker i of a restore or a create) is the one agent here.
      agents: () => { const h = seat?.here?.(); return h ? [{ name: h.name, did: h.did }] : []; },
      seat: () => seat?.info() ?? null,
      defer: (f) => { setTimeout(f, 0); },
      // The keeper sealed in the app's storage. The list reads its roster, kept here without the root after the
      // first opening; K is opened only to enrol (on Android, within the screen lock's window); a change is resealed.
      ...(keeper && { keeper: {
        read: async () => (roster ??= strip(await opened())),
        root: async () => { const k = await opened(); return { K: unhex(k.root_hex), recovery: k.recovery }; },
        update: async (fn) => {
          const k = await opened();
          fn(k);
          const out = utf8(JSON.stringify(k));
          try { await keeper.save(out); } finally { out.fill(0); }
          roster = strip(k);
        },
      } }),
    },
  });
  const { routes, serial } = page;
  // No agents' directory here: the list is empty, and naming one is naming none.
  routes['GET /api/agents'] = () => [];
  for (const r of ['POST /api/agents/enrol', 'POST /api/agents/pair']) routes[r] = (b) => refuse(404, 'agent', `no agent ${JSON.stringify(b['agent'])} in this app`);
  routes['GET /api/devices'] = () => ({ devices: [], list: null, adding: [], joining: null });
  for (const r of ['add', 'confirm', 'words', 'scan', 'revoke', 'sync']) routes[`POST /api/devices/${r}`] = () => serial(async () => refuse(409, 'not_here', DEVICES_HERE));

  // The seat on another device (a restore from seed as a standby): taken here only when the human says
  // that device is stopped or lost; then this page starts as the operator, every session afresh.
  routes['POST /api/seat/take'] = async (b) => {
    const st = seat?.info() ?? refuse(404, 'route', 'no seat in this app: it was not restored from seed');
    if (st.here) refuse(409, 'seat_here', 'this device holds the seat already');
    if (b['confirm'] !== true) refuse(400, 'body', 'confirm: true: the other device is stopped or lost (two devices logging in as you lose each other\'s messages)');
    if (owned === null) refuse(409, 'start', 'the app has not started');
    const r = await seat.take(Math.floor(Date.now() / 1000));
    page.live.seatGone = null; mode.standby = false;
    await page.start();
    return { seat: 'here', holder: r.holder, epoch: r.seat.epoch };
  };

  let owned = null;
  return {
    platform, carrier: page.carrier, page,
    async start() {
      const st = seat?.info();
      // FULL with no signed device list naming the seat (an imported operator file): it would log in as
      // you beside the seat, and the two lose each other's messages. Refused until the app can be enrolled
      // with device add --full (design/apps.md, open; review 2026-10-28, MEDIUM 7).
      if (mode.kind === 'full' && !st) refuse(409, 'full_import', FULL_IMPORT);
      owned = await platform.owner(me().original);
      // Standby: the owner lock held, nothing sent; reads answer, writes are refused seat_elsewhere.
      if (st && st.here === false) { page.live.seatGone = st.holder; return; }
      try { await page.start(); } catch (e) { owned.release(); owned = null; throw e; }
    },
    async stop() {
      await page.halt();
      try { await page.carrier.stop(); } finally { owned?.release(); owned = null; }
    },
    /** A call as ui.js makes it: → { status, body }, body the JSON value the HTTP backend would send. */
    async call(method, path, body) {
      let url;
      try { url = new URL(path, 'http://app'); } catch { return { status: 404, body: { error: { check: 'route', message: 'not a route' } } }; }
      if (url.origin !== 'http://app' || !url.pathname.startsWith('/api/')) return { status: 404, body: { error: { check: 'route', message: `no ${method} ${url.pathname}` } } };
      if (!routes[`${method} ${url.pathname}`]) return { status: 404, body: { error: { check: 'route', message: `no ${method} ${url.pathname}` } } };
      const b = body === undefined || body === null ? {} : body;
      if (method === 'POST' && (typeof b !== 'object' || Array.isArray(b))) return { status: 400, body: { error: { check: 'body', message: 'a JSON object' } } };
      const [status, value] = await page.dispatch(method, url, method === 'POST' ? JSON.parse(JSON.stringify(b)) : {});
      // As it would arrive over HTTP: JSON, nothing shared with the router's own objects.
      return { status, body: JSON.parse(JSON.stringify(value)) };
    },
    onChange: (f) => page.onChange(f),
    mode: () => ({ ...mode }),
  };
}

function concat(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }
