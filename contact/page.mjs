// SPDX-License-Identifier: MIT
// The page's routes over one carrier (adapters/moadim/UI-API.md), shared by `sigelo-agent ui`
// (adapters/moadim/sigelo-agent-ui.ts: HTTP on 127.0.0.1) and the self-contained app (apps/web/router.mjs:
// in the page). One route table, one JSON: what is the same everywhere is here; what one host has
// and the other has not (the agents' directory, devices, the seat, the HTTP and LAN listeners)
// comes in as hooks or as routes the host adds.
//
//   const p = makePage({ makeCarrier, link, codeKind, unlogged, store, hooks, relayFixed })
//   p.carrier                        the carrier makeCarrier(onEvent, { relay? }) built (keep: true); relay: the setting, when one is kept
//   p.routes                         { 'METHOD /api/…': (body, query: URLSearchParams) → value | Promise }, the host adds its own
//   await p.dispatch(method, url, b) → [status, JSON value]: the route's answer, or { error: { check, message, long? } }
//   await p.start(), await p.halt()  timers, the carrier's session, the first drain; halt: timers off, links done (then carrier.stop())
//   p.serial(fn), p.refuse(status, check, message), p.contactOf(did), p.cleanName(v, what), p.record(r), p.seen(did),
//   p.data, p.saveData(), p.live, p.recs, p.onChange(fn)       for the host's own routes and its banners
//
// store: the page's two files, the host's way: readHistory() → text | null, append(line) (a JSON
// line and "\n"), clearHistory(), readData() → text | null, writeData(text). The history is every
// message and pairing event the carrier's inbox() hands over; data is the page's own (tags, words
// checked, read marks, the host's controls). hooks: me() → { did, original, chain }, meInfo() →
// { identity_file, recovery, key, erase, restored? } (restored: the app's restore from seed, { on, keeper, seat, created? }), agents() → the agents' directory as the state shows it
// ([] where there is none), seat() → the seat or null, deviceRound() → { gave? } after each drain
// (or none), note(line), defer(fn) (setImmediate on Node), every(fn, ms) → a timer, hidden({ did, name })
// → true for what the page never shows nor names (the computer's relay controls: their contacts, their
// pairing, their codes waiting; design/apps.md §6.3), controls: { pending() → [{name, scope, words}],
// confirm(name, match) → whether one was pending } (relay controls whose four words wait: the
// Controls card; routes in no remote scope, so never asked over the relay or the LAN).
//
// Groups (adapters/moadim/GROUPS.md, design/groups.md §5): groups: group.mjs (the module) and groupsFile
// (groupsPath of the identity). Each drain hands the carrier's group messages to group.mjs handle(), here
// in code: without it the page never takes a roster, carries a copy on or files a message. The page's
// own marks in data: gread (gid → the newest item shown: {mid, at}), gnotices (a stranger added, the
// creator gone, a refusal: until dismissed). /api/groups/* (UI-API.md "Groups").
//
// Agents (ENROL.md, the app's main list): hooks.keeper, where the host has the operator's keeper root:
// { read() → the keeper file as JSON (workers, …) | null, root(k) → { K, recovery } (K zeroed after use),
// update(fn) → fn(keeper) applied and kept }. enrolFile: the pending enrolments (enrol.mjs enrolPath). The
// page issues a one-time code for worker i on its own session (enrol.mjs issue, the operator side of
// `sigelo-agent enrol --name`, which refuses busy beside a page), takes the requests that come through
// it (kept apart from the devices'), answers them with the worker's identity and files the worker
// when it pairs (complete). Worker indices are allocated at the seat only (DEVICES.md): a page whose
// seat is on another device refuses seat_elsewhere. No four words to tap: a worker that pairs as the DID
// derived from K (enrol.mjs `verified`) is words-checked here at once; the words stay to see, and the
// optional switch (`confirm_words`) holds the key until "They match" (POST /api/agents/enrol-words).
//
// Transfers (adapters/moadim/TRANSFER.md, contact/transfer-node.mjs): hooks.transfers, where the host
// moves big files ({ lib: transfer-node.mjs, make(carrier, onEvent) → its Engine }; Node only, until the
// WebView's platform.rtc): the page owns the session, so its engine answers offers and moves the bytes;
// the /api/transfers* routes; none without the hook (404 route).
//
// Proof of work (design/profiles.md §6): what the human starts here (the page's start, a code, an
// answer, "Try now") passes the carrier's `started: 'user'`; past the day's three the route answers
// 409 pow_confirm, and the same call with `pow_confirmed: true` goes on. The carrier's automatic
// retries stay capped: state's me.pow_capped {relay, next} says when the next one is.
//
// The relay setting (UI-API.md "Settings"): the relay new codes name, kept in data.settings.relay.
// Precedence: relayFixed (the host's environment: SIGELO_RELAY, or a relay the host was given) wins,
// then the setting, then relay.sigelo.ai. The carrier is made with the setting; a change applies at
// once to new codes (invite names it) and becomes the carrier's own relay at the next start. Codes
// to accept never read it: a 12-character code names its relay by its tag, an 8-character one is
// relay.sigelo.ai's (the carrier's relayForShort).
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { DEFAULT_RELAY } from './carrier.mjs';
import * as E from './enrol.mjs';
import { checkRelay } from './invite.mjs';
import { didWords } from './short.mjs';

const DAY = 86400, TAG_MAX = 20, NAME_MAX = 64, TEXT_MAX = 100_000;
// An agent's name: a contact name and, placed here, a file name (sigelo.<name>.local.json), as `enrol --name` takes it.
const AGENT_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const goodRelay = (h) => { try { checkRelay(h); return true; } catch { return false; } };
const nowS = () => Math.floor(Date.now() / 1000);
const hexOf = (n) => bytesToHex(randomBytes(n));
// A short change mark of a string (FNV-1a, 32 bits): not a check of anything, only "something changed".
const hashOf = (t) => { let x = 0x811c9dc5; for (let i = 0; i < t.length; i++) { x ^= t.charCodeAt(i); x = Math.imul(x, 0x01000193) >>> 0; } return x.toString(36); };
export const refuse = (status, check, message) => { throw Object.assign(new Error(message), { check, status }); };

export function makePage({ makeCarrier, link: L, linksFile, groups: G = null, groupsFile = null, enrolFile = null, codeKind, unlogged, store, hooks = {}, relayFixed = null }) {
  const defer = hooks.defer ?? ((f) => setTimeout(f, 0));
  const every = hooks.every ?? ((f, ms) => { const t = setInterval(f, ms); t.unref?.(); return t; });
  const watchers = new Set();
  const changed = () => { for (const f of watchers) { try { f(); } catch {} } };
  // What the page never shows: the host's (relay controls), and an enrolment's temporary pairing (its code's
  // invite, the temporary DID): the worker shows in Agents, then as itself once it has paired.
  const hidden = (x) => { try { return enrolHidden(x) || hooks.hidden?.(x) === true; } catch { return false; } };

  // ---- history: every message and pairing event, one JSON line each; status lines fold into their message
  const recs = [], outById = new Map();
  let seq = 0;
  const fold = (r) => {
    seq = Math.max(seq, r.n);
    if (r.kind !== 'status') { recs.push(r); if (r.kind === 'out' && r.id) outById.set(r.id, r); return; }
    const m = r.id ? outById.get(r.id) : undefined;
    if (m) Object.assign(m, { status: r.status, code: r.code, detail: r.detail, n: r.n });
  };
  const had = store.readHistory();
  if (had !== null) for (const l of had.split('\n')) { try { if (l) fold(JSON.parse(l)); } catch {} }
  const record = (r) => {
    const full = { n: seq + 1, at: nowS(), ...r };
    store.append(JSON.stringify(full) + '\n');
    fold(full);
    changed();
    return full;
  };
  let data;
  try { data = JSON.parse(store.readData() ?? 'null') ?? {}; } catch { data = {}; }
  for (const k of ['tags', 'checked', 'read', 'controls', 'settings', 'gread']) data[k] ??= {};
  data.gnotices ??= [];
  delete data.waiting;   // kept by an earlier page; the carrier says it now (contacts: prekeys, waiting)
  const saveData = () => store.writeData(JSON.stringify(data));

  // ---- live status, not kept
  const live = { online: new Set(), pow: null, powDone: null, error: null, seatGone: null, powCapped: null, powConfirm: null };
  // A call the human made: past the day's searches it asks (pow_confirm) unless they said go on.
  const startedBy = (b) => (b?.['pow_confirmed'] === true ? 'confirmed' : 'user');
  // Writes, one at a time. Once the seat went to another device, every write is refused.
  let chain = Promise.resolve();
  const gone = (fn) => () => (live.seatGone !== null ? refuse(409, 'seat_elsewhere', `the seat went to ${live.seatGone}: this page no longer logs in as you`) : fn());
  const serial = (f0) => { const fn = gone(f0); const p = chain.then(fn, fn); chain = p.catch(() => {}); return p; };
  const invites = new Map();
  let devices = null;
  // Enrolments this page issued (agents, below): id (the code's nonce) → { id, worker, name, short, code, exp, relay, tier,
  // state: code | words | sending | enrolled | expired | failed, words, temp, did, original, check?, detail? }.
  const enrolling = new Map();
  let agentHeld = [];
  // What the carrier's inbox() hands over, as every client takes it: messages and the events it
  // keeps (pairings, failures, rotations), into the history. Taken at once after any event, and
  // every minute for what no event announced.
  let draining = null, again = false;
  function take(b) {
    // A linked contact's messages carry the link (id, purpose): data, shown beside them.
    for (const m of (L.labelled ? L.labelled(carrier, b.messages) : b.messages)) {
      // Enrolment and device messages carry keys or codes: never in the history (the device rounds take them).
      if (typeof m['label'] === 'string' && unlogged.test(m['label'])) { if (!holdAgent(m)) devices?.hold(m); continue; }
      if (hidden({ did: m['from'], name: m['name'] })) continue;
      const link = m['link'] ? { link: m['link'] } : {};
      if (m['type'] === 'file') record({ kind: 'in', did: m['from'], name: m['contact'], label: m['label'], text: `file ${String(m['name'])} (${String(m['size'])} bytes), saved at ${String(m['path'])}`, ...link });
      else record({ kind: 'in', did: m['from'], name: m['name'], text: m['content'], label: m['label'], ...link });
    }
    const named = new Set();
    for (const e of b.events) {
      const d = e['did'] ?? e['from'] ?? e['peer'];
      if (hidden({ did: d, name: e['name'] })) continue;
      switch (e.type) {
        case 'paired': {
          const inv = [...invites.values()].find((x) => x.name === e['name'] && !x.paired);
          if (inv && d) inv.paired = d;
          record({ kind: 'event', type: 'paired', did: d, name: e['name'] });
          break;
        }
        // A refusal of one of my messages (it has an id) is its status, from onEvent.
        case 'refused': if (e['id'] === undefined) record({ kind: 'event', type: 'refused', did: d, name: e['name'], code: e['code'], detail: e['detail'] }); break;
        case 'pairing_failed': case 're_pair': case 'rotated': case 'dropped':
          if (e.type === 'dropped') named.add(String(e['check']));
          record({ kind: 'event', type: e.type, did: d, name: e['name'], code: e['code'] ?? e['check'], detail: e['detail'] });
          break;
      }
    }
    for (const [check, n] of Object.entries(b.dropped)) if (!named.has(check)) record({ kind: 'event', type: 'dropped', code: check, detail: `${n} dropped` });
  }
  function drain() {
    if (draining) { again = true; return draining; }
    draining = (async () => {
      try {
        do { again = false; take(await carrier.inbox({ local: true })); await groupRound(); } while (again);
        // Device messages: wiped answers, a standby asking for the seat (it goes, and this page stops logging in as you).
        if (live.seatGone === null && hooks.deviceRound) {
          const r = await hooks.deviceRound();
          if (r?.gave !== undefined) { live.seatGone = r.gave; await carrier.stop(); }
        }
      } catch (err) { live.error = `inbox: ${err.message}`; }
      finally { draining = null; }
      if (live.seatGone === null && devices?.busy()) void serial(() => devices.round()).catch((err) => { live.error = `devices: ${err.message}`; });
      if (live.seatGone === null && agentsBusy()) void serial(() => agentRound()).catch((err) => { live.error = `agents: ${err.message}`; });
    })();
    return draining;
  }
  // Inside the carrier's lock for some events: the inbox waits for it to be released.
  const soon = () => { defer(() => void drain()); };
  // Links: one round at a time (link.mjs handle): the messages the carrier kept apart, then the rounds.
  let linking = Promise.resolve(null);
  const linkRound = (wait = 5) => {
    linking = linking.then(async () => {
      try { return await L.handle({ carrier, file: linksFile, wait }); } catch (err) { live.error = `links: ${err.message}`; return null; }
    });
    return linking;
  };
  const onEvent = (e) => {
    if (e.type === 'transfer') defer(() => void transfers?.engine.kick());
    if (e.type === 'link' || e.type === 'paired') defer(() => void linkRound());
    try {
      const d = e['did'] ?? e['from'] ?? e['peer'];
      switch (e.type) {
        case 'sent': case 'queued': case 'refused': {
          if (e['control'] !== undefined) break;
          // Before send returns, its own result says the same: only later ones are recorded.
          const st = e.type, i = e['id'];
          if (i && outById.has(i)) { record({ kind: 'status', id: i, status: st, code: e['code'], detail: e['detail'] }); break; }
          // A message queued by a send that failed has no id here: the oldest such one to this peer.
          const orphan = recs.find((r) => r.kind === 'out' && !r.id && r.did === d && r.status === 'queued');
          if (orphan && i && st === 'sent') { orphan.id = i; outById.set(i, orphan); record({ kind: 'status', id: i, status: st }); break; }
          if (st === 'refused' && !i) soon();
          break;
        }
        case 'pow': live.pow = { bits: Number(e['bits']), since: Date.now() }; break;
        case 'pow_done': live.pow = null; live.powDone = Number(e['ms']); break;
        case 'connected':
          live.online.add(String(e['relay'])); live.error = null; void checkClock();
          if (live.powCapped?.relay === e['relay']) live.powCapped = null;
          if (live.powConfirm?.relay === e['relay']) live.powConfirm = null;
          break;
        case 'disconnected': live.online.delete(String(e['relay'])); break;
        case 'error':
          live.error = `${e['check']}: ${e['detail']}`;
          // The day's searches spent: when the next automatic try is, and "Try now" (POST /api/pow/try).
          if (e['check'] === 'pow' && Number.isSafeInteger(e['next'])) live.powCapped = { relay: String(e['relay']), next: e['next'] };
          if (e['check'] === 'pow_confirm') live.powConfirm = { relay: String(e['relay']), detail: String(e['detail']).replace(/^pow_confirm: /, '') };
          break;
        case 'notice': case 'presence': case 'group_tier': break;   // presence, the group tier: the state says it, nothing to take
        default: soon();
      }
    } catch (err) { live.error = `history: ${err.message}`; }
    changed();
  };
  const kept = () => (typeof data.settings.relay === 'string' && goodRelay(data.settings.relay) ? data.settings.relay : null);
  const carrier = makeCarrier(onEvent, kept() !== null ? { relay: kept() } : {});
  // The engine's events: a file offered, done, failed (into the history as events; the view reads GET /api/transfers).
  const onTransfer = (e) => {
    if (['asked', 'done', 'failed', 'declined', 'cancelled'].includes(e.what)) {
      try { record({ kind: 'event', type: 'transfer', what: e.what, id: e.id, did: e.from ?? null, name: e.contact ?? null, code: e.reason ?? null, detail: e.what === 'asked' ? `${e.name} (${e.size} bytes)` : e.path ?? null }); } catch {}
    }
    changed();
  };
  const transfers = hooks.transfers ? { lib: hooks.transfers.lib, engine: hooks.transfers.make(carrier, onTransfer) } : null;
  // The relay new codes name, as the precedence says.
  const newCodes = () => relayFixed ?? kept() ?? DEFAULT_RELAY;
  const settings = () => ({ relay: kept() ?? DEFAULT_RELAY, default: DEFAULT_RELAY, fixed: relayFixed, in_use: carrier.relay });
  async function checkClock() { try { await carrier.checkClock(); } catch {} }
  const seen = (d) => { let at = null; for (const r of recs) if (r.did === d && (r.kind === 'in' || r.kind === 'event')) at = r.at; return at; };
  let timers = [];
  async function start() {
    void checkClock();
    timers = [every(() => void checkClock(), 600_000), every(() => void drain().then(() => linkRound()), 60_000)];
    await carrier.start({ started: 'user' });
    await drain();
    void linkRound();
    void transfers?.engine.kick();
  }
  async function halt() {
    for (const t of timers) clearInterval(t);
    await linking.catch(() => {});
    await transfers?.engine.close().catch(() => {});
  }


  // ---- agents: the operator's workers (keeper `workers`), enrolled by a one-time code from this page
  const K = hooks.keeper ?? null;
  const pend = (fn) => E.pending(enrolFile, nowS(), fn, carrier.platform);
  const LIVE = new Set(['code', 'words', 'sending']);
  function enrolHidden(x) {
    for (const e of enrolling.values()) {
      if (x.did !== undefined && x.did !== null && (x.did === e.temp || (LIVE.has(e.state) && carrier.answeredBy(e.id) === x.did))) return true;
      if (x.name === `${e.name} (enrolling)` && LIVE.has(e.state)) return true;
    }
    return false;
  }
  // An enrolment request from the DID that answered one of this page's codes: kept for agentRound, not the devices'.
  function holdAgent(m) {
    if (m['label'] !== E.LABEL_ENROL) return false;
    for (const e of enrolling.values()) {
      if (LIVE.has(e.state) && (e.temp === m['from'] || carrier.answeredBy(e.id) === m['from'])) { agentHeld.push(m); return true; }
    }
    return false;
  }
  const agentsBusy = () => agentHeld.length > 0 || [...enrolling.values()].some((e) => LIVE.has(e.state));
  const keeperOr = async () => (K ? await K.read() : null) ?? refuse(400, 'keeper', 'no keeper root here: your 25 words make it (sigelo-agent keeper --from-words on a computer; in the app, Create or Restore from seed)');
  const seatHere = () => { const st = hooks.seat?.(); if (st && st.here === false) refuse(409, 'seat_elsewhere', `the seat is with ${st.holder}: agents are enrolled there (DEVICES.md)`); };
  const pub = (e) => ({ id: e.id, state: e.state, code: e.state === 'code' ? e.short : null, exp: e.exp, relay: e.relay, words: e.words ?? null,
    confirm_words: e.confirmWords === true, words_ok: e.wordsOk ?? null, verified: e.verified === true,
    command: e.state === 'code' ? `${e.relay !== DEFAULT_RELAY ? `SIGELO_RELAY=${e.relay} ` : ''}sigelo-agent init --enrol ${e.short}` : null, ...(e.check !== undefined && { check: e.check, detail: e.detail ?? null }) });
  // Who answered each code (its four words), codes dead unanswered (the index free again), enrolments done.
  async function look() {
    if (!enrolFile) return;
    const t = nowS(), issued = pend((st) => Object.fromEntries(Object.entries(st.issued).map(([id, e]) => [id, { done: e.done ?? null }])));
    for (const e of enrolling.values()) {
      if (!LIVE.has(e.state)) continue;
      const f = issued[e.id];
      if (f?.done) { e.state = 'enrolled'; e.at = f.done; changed(); continue; }
      if (!f) { e.state = 'expired'; changed(); continue; }
      if (e.state !== 'code') continue;
      const by = carrier.answeredBy(e.id);
      if (by) {
        e.temp = by; e.state = 'words';
        e.words = carrier.contacts().contacts.find((x) => x.did === by)?.fingerprint ?? null;
        changed();
      } else if (t > e.exp + 30) {
        e.state = 'expired';
        pend((st) => { delete st.issued[e.id]; });
        try { await carrier.cancelInvite(e.code); } catch {}
        await K?.update((k) => { if (k.workers[e.worker]?.name === e.name && k.workers[e.worker].placed === 'remote') delete k.workers[e.worker]; });
        changed();
      }
    }
  }
  // The requests kept apart, answered with the worker's identity; a worker that paired is filed (enrol.mjs complete).
  async function agentRound() {
    await look();
    const pass = agentHeld.splice(0);
    if (!pass.length && ![...enrolling.values()].some((e) => e.state === 'words' || e.state === 'sending')) return;
    const k = await K?.read();
    if (!k) return;
    const root = await K.root(k);
    // The carrier as enrolment sees it: its inbox is what the page kept apart.
    const proxy = new Proxy(carrier, { get: (x, p) => (p === 'inbox' ? async () => ({ messages: pass.splice(0), events: [], dropped: {} }) : typeof x[p] === 'function' ? x[p].bind(x) : x[p]) });
    // The optional switch: the key waits for "They match" (null: not yet, the request kept for the next round).
    const confirm = async (o) => { if (!o.ask) return true; const e = enrolling.get(o.id); if (e && !e.words) e.words = o.words; return e?.wordsOk ?? null; };
    let res;
    try { res = await E.complete({ carrier: proxy, file: enrolFile, keeper: root, wait: 0, confirm }); } finally { root.K.fill(0); }
    agentHeld.push(...(res.held ?? []));
    for (const d of res.delivered) { const e = enrolling.get(d.id); if (e) e.state = 'sending'; }
    for (const x of res.refused) {
      const e = [...enrolling.values()].find((y) => y.temp !== undefined && y.temp === x.from);
      if (e) Object.assign(e, { check: x.check, detail: x.detail });
    }
    for (const p of res.placed) {
      const e = enrolling.get(p.id);
      if (e) Object.assign(e, { state: 'enrolled', at: nowS(), did: p.did, verified: p.verified === true });
      // Worker i of these words, derived here: checked as "They match" checks a contact (no tap).
      const c = p.verified ? carrier.contacts().contacts.find((x) => x.did === p.original && !x.revoked) : null;
      if (c) { data.checked[c.did] = c.pair ?? ''; saveData(); }
    }
    changed();
  }
  const workerOf = (k, v) => {
    if (!Number.isSafeInteger(v) || v < 0) refuse(400, 'body', 'worker: its index (0, 1, 2…)');
    return k.workers[v] ?? refuse(404, 'worker', `no worker ${v} in the keeper's roster`);
  };
  // The contact holding a worker's original DID, live, or null.
  const contactOfWorker = (w) => carrier.contacts().contacts.find((x) => !x.revoked && x.chain.includes(w.original)) ?? null;
  async function workers() {
    const k = K ? await K.read() : null, st = hooks.seat?.() ?? null, seat = st ? (st.here ? 'here' : 'elsewhere') : null;
    if (!k) return { keeper: false, seat, workers: [] };
    await look();
    const local = hooks.agents?.() ?? [], waiting = enrolFile ? pend((x) => Object.values(x.issued).filter((e) => !e.done).map((e) => e.i)) : [];
    const rows = Object.entries(k.workers).map(([i, w]) => {
      const n = Number(i), c = contactOfWorker(w), here = local.find((a) => a.did === w.original), e = [...enrolling.values()].filter((x) => x.worker === n).at(-1);
      const status = w.revoked !== undefined ? 'revoked' : c || here ? 'enrolled' : (e && LIVE.has(e.state)) || waiting.includes(n) ? 'pending' : 'unplaced';
      return { worker: n, name: w.name, did: c?.current_did ?? w.did, original: w.original, rank: w.rank ?? null, placed: w.placed, at: w.at, status, revoked: w.revoked ?? null,
        seen: c ? seen(c.did) : null, tier: c?.tier ?? null, contact: c?.did ?? null, local: here?.name ?? null,
        online: c?.online ?? null, last_seen: c?.last_seen ?? null,
        attested_until: here?.mine?.exp ?? w.until ?? w.attestation?.body?.exp ?? null, enrolling: e && e.state !== 'expired' ? pub(e) : null };
    }).sort((a, b) => a.worker - b.worker);
    return { keeper: true, seat, workers: rows };
  }

  // ---- reads
  const textOf = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
  function state(since) {
    const t = nowS(), c = carrier.contacts(), local = hooks.agents?.() ?? [], clock = carrier.clockOffset();
    const live_ = c.contacts.filter((x) => !x.revoked && !hidden(x)).map((x) => {
      const pair = x.pair, agent = local.find((a) => a.did !== undefined && x.chain.includes(a.did));
      const mine = agent?.mine ?? null;
      // My agent on this machine, its attestation in its file: own, unless I chose otherwise (store.mjs observe).
      let tier = x.tier;
      if (mine && agent?.bundle && tier !== 'own' && x.tier_by !== 'owner') { try { tier = carrier.observe(agent.bundle)?.tier ?? tier; } catch {} }
      // Their keys not here yet (an invitee who has not read our reply, or a bundle run out), or why messages wait.
      const waiting = x.waiting ?? (x.prekeys ? null : 'their keys have not come: their side has not read the reply yet, or has been away');
      const msgs = recs.filter((r) => (r.kind === 'in' || r.kind === 'out') && r.did === x.did);
      const last = msgs.at(-1), read = data.read[x.did] ?? 0;
      const queued = msgs.filter((r) => r.kind === 'out' && r.status === 'queued');
      return {
        did: x.did, name: x.name, current_did: x.current_did, relay: x.relay, re_pair: x.re_pair, words: x.fingerprint, pair,
        words_checked: pair !== null && data.checked[x.did] === pair, tags: data.tags[x.did] ?? [],
        local: agent?.name ?? null, mine, unread: msgs.filter((r) => r.kind === 'in' && r.n > read).length,
        last: last ? { dir: last.kind, text: textOf(last.text).slice(0, 200), at: last.at, status: last.status ?? null } : null,
        waiting, not_collected: queued.length, queued: x.queued,
        status: x.re_pair ? 'pair_again' : waiting ? 'waiting' : queued.length ? 'not_collected' : 'ok', ours: x.ours === true || mine !== null, tier,
        link: x.link ? { id: x.link.id, purpose: x.link.purpose, linked_by: x.link.linked_by, expires: x.link.expires ?? null } : null,
        // Presence (carrier.mjs): theirs as read now (online true, false, null: not known), and what they see of mine.
        online: x.online ?? null, online_since: x.online_since ?? null, last_seen: x.last_seen ?? null, presence: x.presence ?? 'deny',
      };
    });
    // Mine: ours by key, whatever the tier (an own agent set to friend is still mine), or tier own.
    const isMine = (x) => x.ours || x.tier === 'own';
    const mineGroup = live_.filter(isMine), rest = live_.filter((x) => !isMine(x));
    const pendingInvites = c.invites.filter((p) => !hidden(p)).map((p) => {
      const ours = [...invites.values()].find((x) => x.name === p.name);
      return { name: p.name, exp: p.exp, relay: p.relay, ...(ours && { id: ours.id, short: ours.short ?? null, short_exp: ours.short_exp ?? null, code: ours.code }) };
    });
    const paired = [...invites.values()].filter((x) => x.paired).map((x) => ({ id: x.id, name: x.name, paired: x.paired }));
    const failed = recs.filter((r) => r.kind === 'event' && r.type === 'pairing_failed' && r.at > t - DAY).slice(-5).map((r) => ({ name: r.name, did: r.did, code: r.code, detail: r.detail, at: r.at }));
    const m = hooks.me();
    return {
      seq, now: t,
      me: {
        did: m.did, relay: carrier.relay, online: live.online.has(carrier.relay), clock_offset: clock?.offset ?? null, clock_checked: clock?.checked ?? null,
        retention_days: carrier.retentionDays, error: live.error, pow_done_ms: live.powDone,
        // The seat (DEVICES.md): null without one; here false = another device logs in as you: the page shows a banner.
        seat: hooks.seat?.() ?? null,
        pow: live.pow && { bits: live.pow.bits, elapsed_s: Math.round((Date.now() - live.pow.since) / 1000), expected_s: Math.ceil(2 ** live.pow.bits / 180000) },
        pow_capped: live.powCapped, pow_confirm: live.powConfirm,
      },
      groups: { mine: mineGroup, contacts: rest },
      // Chat groups (GROUPS.md): the tab's badge and its notices; the list is GET /api/groups.
      chats: chatsState(),
      pending: { invites: pendingInvites, paired, answers: c.answers, failed },
      introductions: introductions(c.contacts),
      transfers: transferCounts(),
      events: recs.filter((r) => r.kind === 'event' && r.n > since).slice(-50),
    };
  }

  // Introductions waiting for this identity's answer, introducer not quiet here: the page's banner (§6).
  function introductions(cs) {
    if (carrier.platform.files.read(linksFile) === null) return [];
    try {
      return L.list({ carrier, file: linksFile }).received.filter((x) => !x.answer && cs.find((c) => c.did === x.from)?.tier !== 'quiet')
        .map((x) => ({ id: x.id, from: x.from, name: x.name ?? x.from, purpose: x.purpose }));
    } catch { return []; }
  }

  // Files offered and waiting for a yes, and those moving: the page's badge (GET /api/transfers has the rest).
  function transferCounts() {
    if (!transfers) return null;
    try {
      const l = transfers.lib.list({ carrier, identity: hooks.transfers.identity });
      return { asked: l.in.filter((r) => r.state === 'asked').length, active: [...l.in, ...l.out].filter((r) => ['accepted', 'offering', 'active'].includes(r.state)).length };
    } catch { return null; }
  }
  // ---- groups (GROUPS.md): the inbox side by code at each drain; the lists and the verbs below
  const GROUP_NOTICES = 20;
  const gfile = () => groupsFile ?? refuse(404, 'route', 'no groups here');
  // A notice for the operator, kept until dismissed (data.gnotices): a stranger added, the creator gone, refusals.
  const gnote = (n) => { data.gnotices.push({ id: hexOf(4), at: nowS(), ...n }); if (data.gnotices.length > GROUP_NOTICES) data.gnotices.splice(0, data.gnotices.length - GROUP_NOTICES); };
  // The carrier's group messages checked and filed (handle), copies carried on and sent; every item is the
  // page's to show (taken: no inbox beside a page). Invitations wait as status pending in the list.
  async function groupRound() {
    if (!G || !groupsFile) return;
    try {
      const r = await G.handle({ carrier, file: groupsFile });
      let noted = false;
      for (const n of r.notices) if (n.why !== 'invited') { gnote(n); noted = true; }
      const by = new Map();
      for (const x of r.refused) by.set(x.check, (by.get(x.check) ?? 0) + 1);
      for (const [check, n] of by) { gnote({ type: 'group', why: 'refused', check, count: n }); noted = true; }
      if (noted) saveData();
      if (noted || r.filed || r.notices.length || r.joined.length || r.removed.length) changed();
    } catch (err) { live.error = `groups: ${err.message}`; }
  }
  // Unread in a group: the items after the newest shown (data.gread), none of mine.
  const unreadIn = (gid, items) => {
    const m = data.gread[gid];
    if (!m) return items.filter((i) => !i.mine).length;
    const at = items.findIndex((i) => i.mid === m.mid);
    return (at >= 0 ? items.slice(at + 1) : items.filter((i) => (i.received ?? 0) > m.at)).filter((i) => !i.mine).length;
  };
  const brakeQuiet = (g) => g.brake !== 'off' && g.run >= g.brake;
  function groupsList() {
    if (!G || !groupsFile) return [];
    const gs = G.list({ carrier, file: groupsFile });
    return gs.map((g) => {
      const items = ['member', 'frozen'].includes(g.status) ? G.history({ carrier, file: groupsFile, group: g.gid }) : [];
      const last = items.at(-1);
      return { ...g, unread: unreadIn(g.gid, items), quiet: brakeQuiet(g),
        last: last ? { name: last.mine ? null : last.name, text: textOf(last.content).slice(0, 200), at: last.received ?? last.iat, mine: last.mine === true } : null };
    });
  }
  function groupTier() {
    const told = carrier.groupTier ?? null, { lim, tier } = G.limitsFor(carrier);
    return { tier, groups: lim.groups, members: lim.members, told: told !== null };
  }
  // /api/state's chats: the badge (unread in all), invitations waiting, notices. Never fails the state.
  function chatsState() {
    if (!G || !groupsFile || carrier.platform.files.read(groupsFile) === null) return { unread: 0, invited: 0, notices: data.gnotices.length, rev: `0.${data.gnotices.length}` };
    try {
      const gs = groupsList();
      // rev: changes with any group's roster, status, run or newest item (the page fetches a chat again on it).
      const rev = gs.map((g) => `${g.gid.slice(0, 8)}.${g.ver}.${g.status}.${g.run}.${g.last?.at ?? 0}.${g.unread}`).join(' ');
      return { unread: gs.reduce((a, g) => a + g.unread, 0), invited: gs.filter((g) => g.status === 'pending').length, notices: data.gnotices.length, rev: `${hashOf(rev)}.${data.gnotices.length}` };
    } catch { return { unread: 0, invited: 0, notices: data.gnotices.length, rev: '' }; }
  }
  // group.mjs refusals by check: unknown → 404, usage → 400, any other (group_*, not_contact, name) → 409.
  async function groupCall(fn) {
    gfile();
    try { return await fn(); } catch (e) {
      if (e.check !== undefined && e.status === undefined) e.status = ['group_unknown', 'not_contact'].includes(e.check) ? 404 : ['group_message', 'group_text', 'group_members'].includes(e.check) ? 400 : 409;
      throw e;
    }
  }
  const gid = (b) => (typeof b['group'] === 'string' && b['group'] !== '' ? b['group'] : refuse(400, 'body', 'group: its gid'));
  const dids = (v, what, need = true) => {
    if (v === undefined && !need) return [];
    if (!Array.isArray(v) || (need && v.length === 0) || v.length > 64 || v.some((x) => typeof x !== 'string' || x === '')) refuse(400, 'body', `${what}: a list of contact DIDs`);
    return v;
  };
  // A write's answer: the group as the list shows it, and how its copies went.
  const gout = (r) => ({ ...(r.group && { group: r.group }), copies: r.copies ?? [], ...(r.offline !== undefined && { offline: r.offline }) });
  const groupRoutes = {
    'GET /api/groups': () => groupCall(() => ({ tier: groupTier(), groups: groupsList(), notices: data.gnotices.slice() })),
    'GET /api/groups/history': (_, q) => groupCall(() => {
      const g = q.get('group') ?? refuse(400, 'body', 'group: its gid'), one = groupsList().find((x) => x.gid === g) ?? refuse(404, 'group_unknown', `no group ${g} here`);
      const items = G.history({ carrier, file: groupsFile, group: g }), last = items.at(-1);
      // Read: the page has shown them.
      if (last && data.gread[g]?.mid !== last.mid) { data.gread[g] = { mid: last.mid, at: last.received ?? last.iat }; saveData(); }
      return { group: { ...one, unread: 0 }, messages: items.slice(-200).map((i) => ({ mid: i.mid, re: i.re ?? null, from: i.from, name: i.name, role: i.role, tier: i.tier ?? null, mine: i.mine === true,
        operator: i.operator === true, note: i.note ?? null, text: textOf(i.content), mentions: i.mentions ?? [], mentioned: i.mentioned === true, via: i.via ?? null, at: i.received ?? i.iat })) };
    }),
    'POST /api/groups/create': (b) => serial(() => groupCall(async () => {
      const brake = b['brake'];
      return gout(await G.create({ carrier, file: groupsFile, name: b['name'], members: dids(b['members'], 'members'), humans: dids(b['humans'], 'humans', false), ...(brake !== undefined && brake !== null && { brake }),
        ...(typeof b['role'] === 'string' && { role: b['role'] }) }));
    })),
    'POST /api/groups/add': (b) => serial(() => groupCall(async () => gout(await G.add({ carrier, file: groupsFile, group: gid(b), members: dids(b['members'], 'members'), humans: dids(b['humans'], 'humans', false) })))),
    'POST /api/groups/remove': (b) => serial(() => groupCall(async () => gout(await G.remove({ carrier, file: groupsFile, group: gid(b), members: dids(b['members'], 'members') })))),
    'POST /api/groups/rename': (b) => serial(() => groupCall(async () => gout(await G.rename({ carrier, file: groupsFile, group: gid(b), name: b['name'] })))),
    'POST /api/groups/brake': (b) => serial(() => groupCall(async () => gout(await G.setBrake({ carrier, file: groupsFile, group: gid(b), brake: b['brake'] })))),
    'POST /api/groups/role': (b) => serial(() => groupCall(async () => gout(await G.setRole({ carrier, file: groupsFile, group: gid(b), member: b['member'], role: b['role'] })))),
    'POST /api/groups/share': (b) => serial(() => groupCall(async () => gout(await G.share({ carrier, file: groupsFile, group: gid(b), member: b['member'] })))),
    'POST /api/groups/leave': (b) => serial(() => groupCall(async () => { const r = await G.leave({ carrier, file: groupsFile, group: gid(b) }); changed(); return { ...gout(r), told: r.told }; })),
    'POST /api/groups/join': (b) => serial(() => groupCall(async () => { const r = G.join({ carrier, file: groupsFile, group: gid(b) }); changed(); return gout(r); })),
    'POST /api/groups/send': (b) => serial(() => groupCall(async () => {
      const text = b['text'], re = b['re'], mentions = b['mentions'];
      if (typeof text !== 'string' || text.trim() === '') refuse(400, 'body', 'text: the message');
      if (mentions !== undefined && (!Array.isArray(mentions) || mentions.some((x) => typeof x !== 'string'))) refuse(400, 'body', 'mentions: member DIDs or names');
      const r = await G.send({ carrier, file: groupsFile, group: gid(b), text, ...(typeof re === 'string' && re !== '' && { re }), ...(mentions && { mentions }) });
      changed();
      return { gid: r.gid, mid: r.mid, copies: r.copies, via_creator: r.via_creator, unreached: r.unreached, ...(r.offline !== undefined && { offline: r.offline }) };
    })),
    'POST /api/groups/dismiss': (b) => serial(async () => {
      const id = b['id'], before = data.gnotices.length;
      data.gnotices = id === 'all' ? [] : data.gnotices.filter((n) => n.id !== id);
      if (data.gnotices.length === before && id !== 'all') refuse(404, 'notice', 'no such notice');
      saveData(); changed();
      return { dismissed: before - data.gnotices.length };
    }),
  };

  // ---- writes
  const contactOf = (d) => {
    if (typeof d !== 'string') refuse(400, 'body', 'contact: a DID');
    return carrier.contacts().contacts.find((x) => !x.revoked && x.did === d && !hidden(x)) ?? refuse(404, 'not_contact', `${String(d)} is not a contact`);
  };
  const cleanName = (v, what) => {
    if (typeof v !== 'string' || v.trim() === '' || [...v.trim()].length > NAME_MAX || /[\u0000-\u001f\u007f-\u009f]/.test(v)) refuse(400, 'body', `${what}: 1 to ${NAME_MAX} characters, no controls`);
    return v.trim();
  };
  // link.mjs refusals by check: unknown → 404, a bad tier or usage → 400, any other (link_*) → 409.
  async function linkCall(fn) {
    try { return await fn(); } catch (e) {
      if (e.check !== undefined && e.status === undefined) e.status = ['not_contact', 'link_unknown'].includes(e.check) ? 404 : ['tier', 'usage'].includes(e.check) ? 400 : 409;
      throw e;
    }
  }
  async function forget(c) {
    const r = await carrier.forget(c.did);
    delete data.tags[c.did]; delete data.checked[c.did]; saveData();
    return { forgotten: c.did, offline: r.offline ?? null };
  }
  const routes = {
    'GET /api/state': async (_, q) => { if (draining) await draining; return state(Number(q.get('since') ?? 0) || 0); },
    'GET /api/me': () => {
      const m = hooks.me(), i = hooks.meInfo();
      return { did: m.did, original: m.original, words: didWords(m.original), chain: m.chain, identity_file: i.identity_file, recovery: i.recovery, key: i.key, relay: carrier.relay, retention_days: carrier.retentionDays, erase: i.erase,
        ...(i.restored && { restored: i.restored }) };
    },
    'POST /api/invite': (b) => serial(async () => {
      const name = b['name'] === undefined || b['name'] === '' ? `contact-${hexOf(2)}` : cleanName(b['name'], 'name');
      const at = newCodes();
      const r = await carrier.invite({ name, short: b['long'] !== true, ...(at !== carrier.relay && { relay: at }), started: startedBy(b) });
      const inv = { id: hexOf(6), name, code: r.code, exp: r.exp, ...(r.short !== undefined && { short: r.short, short_exp: r.short_exp }) };
      invites.set(inv.id, inv);
      changed();
      return { ...inv, relay: r.relay };
    }),
    'POST /api/invite/cancel': (b) => serial(async () => {
      const inv = invites.get(String(b['id'])) ?? refuse(404, 'invite', 'no such invite');
      await carrier.cancelInvite(inv.code);
      invites.delete(inv.id);
      return { cancelled: true };
    }),
    'POST /api/accept': (b) => serial(async () => {
      if (typeof b['code'] !== 'string' || b['code'].trim() === '') refuse(400, 'body', 'code: the short code (K7F3-Q9ZP) or the long one (sgl1…)');
      const text = b['code'], code = codeKind(text) === 'short' ? text : text.replace(/\s+/g, '');
      const name = b['name'] === undefined || b['name'] === '' ? undefined : cleanName(b['name'], 'name');
      // friend or quiet, the human's choice; own is detected, never asked (store.mjs tiers).
      const tier = b['tier'];
      if (tier !== undefined && tier !== 'friend' && tier !== 'quiet') refuse(400, 'body', 'tier: friend or quiet');
      const r = await carrier.accept(code, { ...(name !== undefined && { name }), wait: 10, ...(tier !== undefined && { tier }), started: startedBy(b) });
      const now = r.contact ? carrier.contacts().contacts.find((x) => x.did === r.contact.did) : undefined;
      return r.contact ? { status: r.status, contact: { ...r.contact, pair: now?.pair ?? null, tier: now?.tier ?? null } }
        : { ...r, exp: carrier.contacts().answers.find((x) => x.did === r.did)?.exp ?? null };
    }),
    'POST /api/words': (b) => serial(async () => {
      const c = contactOf(b['contact']);
      if (b['match'] === true) { data.checked[c.did] = c.pair ?? ''; saveData(); return { checked: true }; }
      if (b['match'] !== false) refuse(400, 'body', 'match: true or false');
      return forget(c);
    }),
    'POST /api/rename': (b) => serial(async () => {
      // A name another live contact holds is refused (409 name_taken): `send <name>` would refuse both.
      return carrier.rename(contactOf(b['contact']).did, cleanName(b['name'], 'name'));
    }),
    'POST /api/tier': (b) => serial(async () => {
      const c = contactOf(b['contact']), tier = b['tier'];
      if (tier !== 'own' && tier !== 'friend' && tier !== 'quiet') refuse(400, 'body', 'tier: own, friend or quiet');
      return carrier.setTier(c.did, tier);
    }),
    'POST /api/presence': (b) => serial(async () => {
      const c = contactOf(b['contact']), allow = b['allow'];
      if (typeof allow !== 'boolean') refuse(400, 'body', 'allow: true or false');
      try { return carrier.setPresence(c.did, allow); } catch (e) { if (e.check === 'presence_own') e.status = 409; throw e; }
    }),
    'POST /api/tag': (b) => serial(async () => {
      const c = contactOf(b['contact']), tags = b['tags'];
      if (!Array.isArray(tags) || tags.length > 8) refuse(400, 'body', 'tags: a list of at most 8');
      const clean = [...new Set(tags.map((x) => cleanName(x, 'tag').replace(/^#/, '')))];
      if (clean.some((x) => [...x].length > TAG_MAX)) refuse(400, 'body', `a tag has at most ${TAG_MAX} characters`);
      data.tags[c.did] = clean; saveData();
      return { tags: clean };
    }),
    'POST /api/forget': (b) => serial(async () => forget(contactOf(b['contact']))),
    'POST /api/send': (b) => serial(async () => {
      const c = contactOf(b['to']), text = b['text'];
      if (typeof text !== 'string' || text.trim() === '' || text.length > TEXT_MAX) refuse(400, 'body', `text: 1 to ${TEXT_MAX} characters`);
      let r;
      try { [r] = await carrier.sendAll(c.did, [text], { label: '' }); } catch (e) {
        // The session failed: the message stays queued in the carrier and goes at a later connection.
        if (!/queued/.test(e.message)) throw e;
        return record({ kind: 'out', did: c.did, id: null, text, status: 'queued', code: e.check, detail: e.message });
      }
      return record({ kind: 'out', did: c.did, id: r.id, text, status: r.status, code: r.code, detail: r.detail });
    }),
    'GET /api/messages': (_, q) => {
      const d = contactOf(q.get('contact')).did, since = Number(q.get('since') ?? 0) || 0;
      const msgs = recs.filter((r) => (r.kind === 'in' || r.kind === 'out') && r.did === d && r.n > since).slice(-200);
      // Read: the page has shown them.
      if ((data.read[d] ?? 0) < seq) { data.read[d] = seq; saveData(); }
      return { seq, messages: msgs.map((r) => ({ n: r.n, dir: r.kind, at: r.at, text: textOf(r.text), label: r.label ?? '', status: r.status ?? null, code: r.code ?? null, detail: r.detail ?? null, link: r.link ?? null })) };
    },
    'POST /api/sync': () => serial(async () => { await carrier.sync(); return { synced: true }; }),
    'POST /api/history/clear': () => serial(async () => {
      store.clearHistory(); recs.length = 0; outById.clear(); data.read = {}; saveData();
      changed();
      return { cleared: true };
    }),
    // Settings: the relay new codes name (above). relay: a host[:port], or "" / null for relay.sigelo.ai.
    'GET /api/settings': () => settings(),
    'POST /api/settings': (b) => serial(async () => {
      const v = b['relay'];
      if (v === undefined) refuse(400, 'body', 'relay: a host[:port], or "" for the default');
      if (v === null || v === '' || v === DEFAULT_RELAY) delete data.settings.relay;
      else if (typeof v === 'string' && goodRelay(v.trim().toLowerCase())) data.settings.relay = v.trim().toLowerCase();
      else refuse(400, 'body', `relay: a host name, as relay.example.org (a port after a colon if not the usual)`);
      saveData(); changed();
      return settings();
    }),
    // The signed registry's relays (sigelo.ai/relays.json, verified; fetched at most once a day): the page's picker.
    'GET /api/relays': async () => ({ relays: await carrier.registryRelays() }),
    // The relay picker's Test (UI-API.md): does this host answer as a relay, before it is used.
    'POST /api/relays/test': async (b) => {
      const v = typeof b['relay'] === 'string' ? b['relay'].trim().toLowerCase() : '';
      if (!goodRelay(v)) refuse(400, 'body', 'relay: a host name, as relay.example.org (a port after a colon if not the usual)');
      return carrier.probeRelay(v);
    },
    // Agents (ENROL.md): the keeper's workers; a one-time code for worker i (the next free); revoke; rename.
    'GET /api/agents/workers': () => workers(),
    'POST /api/agents/enrol-code': (b) => serial(async () => {
      seatHere();
      if (!enrolFile) refuse(404, 'route', 'no enrolment here');
      const name = b['name'], tier = b['tier'], relay = b['relay'], words = b['confirm_words'], label = b['operator_name'];
      if (typeof name !== 'string' || !AGENT_NAME.test(name)) refuse(400, 'body', 'name: lowercase letters, digits, _ and -, at most 64');
      if (words !== undefined && typeof words !== 'boolean') refuse(400, 'body', 'confirm_words: true or false (default false: checked by its DID)');
      if (label !== undefined && label !== null && label !== '' && E.operatorLabel(label) === null) refuse(400, 'body', 'operator_name: how the agent files you, 1 to 64 characters');
      if (tier !== undefined && tier !== 'own' && tier !== 'friend' && tier !== 'quiet') refuse(400, 'body', 'tier: own (the default), friend or quiet');
      if (relay !== undefined && relay !== null && relay !== '' && !(typeof relay === 'string' && goodRelay(relay.trim().toLowerCase()))) refuse(400, 'body', 'relay: a host name, as relay.example.org');
      const at = relayFixed ?? (typeof relay === 'string' && relay !== '' ? relay.trim().toLowerCase() : newCodes());
      const k = await keeperOr();
      const same = Object.entries(k.workers).find(([, w]) => w.name === name && w.revoked === undefined);
      if (same) refuse(409, 'name_taken', `${name} is worker ${same[0]} already: another name`);
      const used = Object.keys(k.workers).map(Number), i = used.length ? Math.max(...used) + 1 : 0;
      const root = await K.root(k);
      let r;
      try {
        r = await E.issue({ carrier, file: enrolFile, i, n: 0, name, keeper: root, relay: at, started: startedBy(b), confirmWords: words === true,
          ...(typeof label === 'string' && label !== '' && { operatorName: label }) });
      } finally { root.K.fill(0); }
      const until = pend((x) => x.issued[r.id]?.attestation?.body?.exp ?? null);
      await K.update((x) => { x.workers[i] = { name, n: 0, did: r.did, original: r.original, placed: 'remote', at: nowS(), ...(until && { until }) }; });
      if (tier === 'friend' || tier === 'quiet') carrier.presetTier(r.original, tier);
      const e = { id: r.id, worker: i, name, short: r.short, code: r.code, exp: r.short_exp, relay: r.relay, tier: tier ?? 'own', state: 'code', did: r.did, original: r.original, confirmWords: words === true };
      enrolling.set(e.id, e);
      changed();
      return { worker: i, name, did: r.did, original: r.original, tier: e.tier, ...pub(e) };
    }),
    // The optional words switch: the human's answer for an enrolment that holds its key until it.
    'POST /api/agents/enrol-words': (b) => serial(async () => {
      const e = enrolling.get(String(b['id'])) ?? refuse(404, 'enrol', 'no such enrolment on this page');
      if (typeof b['match'] !== 'boolean') refuse(400, 'body', 'match: true (the agent\'s machine shows the same four words) or false');
      if (!LIVE.has(e.state)) refuse(409, 'enrol_state', `this enrolment is ${e.state}`);
      e.wordsOk = b['match'];
      await agentRound();
      if (!b['match']) {
        pend((x) => { delete x.issued[e.id]; });
        await K?.update((k) => { if (k.workers[e.worker]?.name === e.name && k.workers[e.worker].placed === 'remote') delete k.workers[e.worker]; });
        if (e.temp) { try { await carrier.forget(e.temp); } catch {} }
        Object.assign(e, { state: 'failed', check: 'device_words', detail: 'The four words differed: its key was not sent, and the code is dropped. Make a new one.' });
      }
      changed();
      return pub(e);
    }),
    // "Try now" (design/profiles.md §6): the automatic tries paused for the day; the human's goes now.
    'POST /api/pow/try': (b) => serial(async () => {
      const r = await carrier.tryNow({ confirmed: b['pow_confirmed'] === true });
      live.powCapped = null; live.powConfirm = null; changed();
      return r;
    }),
    'POST /api/agents/revoke': (b) => serial(async () => {
      seatHere();
      const k = await keeperOr(), i = b['worker'], w = workerOf(k, i);
      if (w.revoked !== undefined) refuse(409, 'revoked', `worker ${i} (${w.name}) is revoked already`);
      if (w.placed === 'device') refuse(409, 'device', `${w.name} is a device: revoke it under Devices (it is told to delete its keys)`);
      const e = [...enrolling.values()].filter((x) => x.worker === i).at(-1);
      // A code nobody answered: cancelled, the index free again. Anything further: the worker may hold its key: revoked.
      if (e?.state === 'code') {
        try { await carrier.cancelInvite(e.code); } catch {}
        pend((x) => { delete x.issued[e.id]; });
        await K.update((x) => { delete x.workers[i]; });
        e.state = 'expired';
        changed();
        return { worker: i, name: w.name, cancelled: true, revoked: null, forgot: null };
      }
      if (e && LIVE.has(e.state)) { pend((x) => { delete x.issued[e.id]; }); e.state = 'failed'; e.check = 'revoked'; if (e.temp) { try { await carrier.forget(e.temp); } catch {} } }
      const c = contactOfWorker(w);
      if (c) await carrier.forget(c.did);
      const t = nowS();
      await K.update((x) => { if (x.workers[i]) x.workers[i].revoked = t; });
      changed();
      return { worker: i, name: w.name, cancelled: false, revoked: t, forgot: c?.did ?? null, attested_until: w.until ?? w.attestation?.body?.exp ?? null };
    }),
    'POST /api/agents/rename': (b) => serial(async () => {
      seatHere();
      const k = await keeperOr(), i = b['worker'], w = workerOf(k, i), name = b['name'];
      if (typeof name !== 'string' || !AGENT_NAME.test(name)) refuse(400, 'body', 'name: lowercase letters, digits, _ and -, at most 64');
      const same = Object.entries(k.workers).find(([j, x]) => Number(j) !== i && x.name === name && x.revoked === undefined);
      if (same) refuse(409, 'name_taken', `${name} is worker ${same[0]} already: another name`);
      const c = contactOfWorker(w);
      if (c && c.name !== name) carrier.rename(c.did, name);
      await K.update((x) => { if (x.workers[i]) x.workers[i].name = name; });
      changed();
      return { worker: i, name };
    }),
    // Links (LINKS.md). The operator's: link, unlink, the list. This identity's introductions: answer, allow.
    'GET /api/links': () => linkCall(() => {
      const r = L.list({ carrier, file: linksFile }), cs = carrier.contacts().contacts;
      return { ...r, received: r.received.map((x) => ({ ...x, quiet: cs.find((c) => c.did === x.from)?.tier === 'quiet' })) };
    }),
    'POST /api/link': (b) => serial(() => linkCall(async () => {
      const str = (k, need = false) => {
        const v = b[k];
        if (v === undefined || v === null || (v === '' && !need)) return need ? refuse(400, 'body', `${k}: required`) : undefined;
        return typeof v === 'string' ? v : refuse(400, 'body', `${k}: a string`);
      };
      const days = b['days'];
      if (days !== undefined && days !== null && !Number.isSafeInteger(days)) refuse(400, 'body', 'days: whole days, 1 to 365');
      const tierA = str('tier_a'), tierB = str('tier_b'), note_ = str('note'), relay = str('relay'), nameA = str('name_a'), nameB = str('name_b');
      const rec = await L.link({ carrier, file: linksFile, a: str('a', true), b: str('b', true), purpose: str('purpose', true), ...(tierA && { tierA }), ...(tierB && { tierB }), ...(nameA && { nameA }), ...(nameB && { nameB }),
        ...(typeof days === 'number' && { days }), ...(note_ && { note: note_ }), ...(relay && { relay }) });
      const { code: _c, steps: _s, exp: _e, ttl: _t, ...out } = rec;
      return out;
    })),
    'POST /api/unlink': (b) => serial(() => linkCall(async () => {
      if (typeof b['id'] !== 'string' || b['id'] === '') refuse(400, 'body', 'id: a link id');
      const r = await L.unlink({ carrier, file: linksFile, id: b['id'] });
      return { id: r.id, status: r.status, role: r.role, ...(r.name !== undefined && { name: r.name, forgot: r.forgot }) };
    })),
    'POST /api/links/answer': async (b) => {
      const id = b['id'], accept = b['accept'], tell = b['tell'], tier = b['tier'];
      if (typeof id !== 'string' || id === '' || typeof accept !== 'boolean') refuse(400, 'body', 'id: an introduction; accept: true or false');
      if (tell !== undefined && typeof tell !== 'boolean') refuse(400, 'body', 'tell: true or false');
      if (tier !== undefined && tier !== 'friend' && tier !== 'quiet') refuse(400, 'body', 'tier: friend or quiet (an introduced agent is never own)');
      const r = await serial(() => linkCall(async () => L.answer({ carrier, file: linksFile, id, accept, tell: tell === true, ...(typeof tier === 'string' && { tier }) })));
      if (r.status === 'refused') return r;
      // Carried out now (it needs the session): accepted (paired, filed with the link), or the refusal told.
      const h = await linkRound(10), bad = h?.refused.find((x) => x.id === r.id && x.check !== 'link_refused');
      const filed = carrier.contacts().contacts.find((c) => !c.revoked && c.link?.id === r.id && c.link.linked_by === r.from);
      return { ...r, status: filed ? 'linked' : bad ? 'failed' : accept ? r.status : 'refused', ...(bad && !filed && { check: bad.check, detail: bad.detail }) };
    },
    'POST /api/links/allow': (b) => serial(() => linkCall(async () => {
      const contact = b['contact'], allow = b['allow'], tier = b['tier'], days = b['days'];
      if (typeof contact !== 'string' || contact === '' || typeof allow !== 'boolean') refuse(400, 'body', 'contact: a DID; allow: true or false');
      if (tier !== undefined && tier !== 'friend' && tier !== 'quiet') refuse(400, 'body', 'tier: friend or quiet');
      if (days !== undefined && days !== null && !Number.isSafeInteger(days)) refuse(400, 'body', 'days: whole days');
      return allow ? L.allow({ carrier, file: linksFile, contact, ...(typeof tier === 'string' && { tier }), ...(typeof days === 'number' && { days }) })
        : L.deny({ carrier, file: linksFile, contact });
    })),
    // Relay controls paired, their four words not confirmed (the terminal's y/N, here on the page).
    'GET /api/controls': () => ({ pending: hooks.controls?.pending() ?? [] }),
    // Not serial: a refusal forgets the control's contact through serial itself.
    'POST /api/controls/confirm': async (b) => {
      const name = b['name'], match = b['match'];
      if (typeof name !== 'string' || name === '' || typeof match !== 'boolean') refuse(400, 'body', 'name: a control\'s name; match: true (the app shows the same four words) or false');
      if (!hooks.controls || !(await hooks.controls.confirm(name, match))) refuse(404, 'control_unknown', `no control ${JSON.stringify(name)} waits for its four words`);
      return { name, confirmed: match, ...(!match && { forgotten: true }) };
    },
  };
  // Transfers: the routes exist only where the host moves files (hooks.transfers).
  if (transfers) Object.assign(routes, transferRoutes({ X: transfers.lib, engine: transfers.engine, carrier, identity: hooks.transfers.identity, serial, contactOf, changed }));
  if (G) Object.assign(routes, groupRoutes);
  // One handler for every listener: the route's answer as [status, JSON value].
  async function dispatch(method, url, b) {
    const route = routes[`${method} ${url.pathname}`];
    if (!route) return [404, { error: { check: 'route', message: `no ${method} ${url.pathname}` } }];
    try { return [200, await route(b, url.searchParams)]; } catch (e) {
      return [e.status ?? (e.check ? 409 : 500), { error: { check: e.check ?? 'internal', message: e.message, ...(e.long !== undefined && { long: e.long }) } }];
    }
  }
  return {
    carrier, routes, dispatch, start, halt, serial, refuse, contactOf, cleanName, record, seen, data, saveData, live, recs, linkRound, drain,
    setDevices: (d) => { devices = d; },
    onChange: (f) => { watchers.add(f); return () => watchers.delete(f); },
  };
}

// ---- transfers (UI-API.md "Transfers"): the verbs of contact/transfer-node.mjs over the page's session.
// Refusals by check: unknown → 404; usage → 400; direct_ask, disk_full, transfer_state and the rest → 409.
function transferRoutes({ X, engine, carrier, identity, serial, contactOf, changed }) {
  const call = async (fn) => {
    try { const r = await fn(); changed(); return r; } catch (e) {
      if (e.check !== undefined && e.status === undefined) e.status = ['transfer_unknown', 'not_contact'].includes(e.check) ? 404 : ['usage', 'body'].includes(e.check) ? 400 : 409;
      throw e;
    }
  };
  const idOf = (b) => (typeof b['id'] === 'string' && /^[0-9a-f]{32}$/.test(b['id']) ? b['id'] : refuse(400, 'body', 'id: a transfer id (32 hex digits)'));
  const directOf = (b) => (b['direct'] === undefined ? undefined : typeof b['direct'] === 'boolean' ? b['direct'] : refuse(400, 'body', 'direct: true or false'));
  const viaOf = (b) => (b['via'] === undefined || b['via'] === 'auto' || b['via'] === 'tor' ? b['via'] : refuse(400, 'body', 'via: auto or tor'));
  const strip = ({ file: _f, ...r }) => r;
  const settings = async () => ({ ...X.settings({ identity }), tor_daemon: await X.torCaps(X.torConfig()), direct_available: (await X.loadRtc()) !== null });
  return {
    'GET /api/transfers': () => X.list({ carrier, identity, engine }),
    'POST /api/transfers/send': (b) => serial(() => call(async () => {
      if (typeof b['path'] !== 'string' || b['path'] === '') refuse(400, 'body', 'path: a file on this computer');
      const c = contactOf(b['to']), d = directOf(b), via = viaOf(b);
      const r = await X.send({ carrier, identity, to: c.did, path: b['path'], ...(via && { via }), ...(d !== undefined && { direct: d }) });
      void engine.kick();
      return strip(r);
    })),
    'POST /api/transfers/accept': (b) => serial(() => call(async () => {
      const d = directOf(b), via = viaOf(b), r = X.accept({ carrier, identity, id: idOf(b), ...(via && { via }), ...(d !== undefined && { direct: d }) });
      void engine.kick();
      return r;
    })),
    'POST /api/transfers/resume': (b) => serial(() => call(async () => { const r = X.accept({ carrier, identity, id: idOf(b), ...(directOf(b) !== undefined && { direct: directOf(b) }) }); void engine.kick(); return r; })),
    'POST /api/transfers/decline': (b) => serial(() => call(async () => X.decline({ carrier, identity, id: idOf(b) }))),
    'POST /api/transfers/cancel': (b) => serial(() => call(async () => strip(await X.cancel({ carrier, identity, id: idOf(b), engine })))),
    'POST /api/transfers/forget': (b) => serial(() => call(async () => strip(X.forget({ carrier, identity, id: idOf(b), engine })))),
    'POST /api/transfers/direct': (b) => serial(() => call(async () => {
      if (typeof b['on'] !== 'boolean') refuse(400, 'body', 'on: true or false');
      return X.setDirect({ carrier, identity, contact: contactOf(b['contact']).did, on: b['on'] });
    })),
    'GET /api/transfers/settings': () => settings(),
    'POST /api/transfers/settings': (b) => serial(() => call(async () => {
      const patch = {};
      if (b['tor'] !== undefined) { if (typeof b['tor'] !== 'boolean') refuse(400, 'body', 'tor: true or false'); patch.tor = b['tor']; }
      if (b['prefer'] !== undefined) { if (b['prefer'] !== 'fast' && b['prefer'] !== 'private') refuse(400, 'body', 'prefer: fast or private'); patch.prefer = b['prefer']; }
      X.settings({ identity, patch });
      return settings();
    })),
  };
}
