// SPDX-License-Identifier: MIT
// Voice calls (design/calls.md): 1:1 audio between two paired people, the media WebRTC (Opus, DTLS-SRTP) in the page's
// own RTCPeerConnection, the signalling `sigelo-call/0` messages inside the pairing's signed envelopes. No import: the
// computer's page loads this file as it is (`/call.mjs`, beside ui.js), the phone app through its import map.
//
// Two halves:
//   Line   the host's, where the carrier runs (page.mjs: Node under `sigelo-agent ui`, the page itself in the phone
//          app): what comes and goes over the relay, who may ring here, the ring's timers, glare, busy, "unavailable"
//          with no page to ring, the chat lines ("Call · 3:12", "Missed call"); the /api/calls* routes (callRoutes).
//   Phone  the page's (ui.js): the microphone, the RTCPeerConnection (a fresh DTLS certificate per call), batched
//          candidates, the ICE timers and restarts, mute; it reaches its Line only through /api/calls*.
//
// The messages (design §2), content {typ, id, …}, id 32 hex, kept apart by the carrier (CALL_LABEL, CALL_SEND: never in
// the inbox, the log, MCP; `watch` answers a ring `end unavailable`):
//   ring     caller   {attempt: 1, sdp (the offer), exp (iat + 60 s), text (what an older app shows), pad}
//   ringing  callee   {}   (only to a contact this side shares presence with: it says "online")
//   answer   callee   {attempt, sdp, pad}   (attempt 1: the ring accepted; n > 1: a restart answered)
//   cands    either   {attempt, cands: ["candidate:…"]}   the candidates gathered after the offer or answer left, once
//   restart  caller   {attempt n + 1, sdp (an ICE-restart offer), pad}
//   end      either   {reason}   hangup declined busy no_answer cancelled lost no_path unavailable
// ring, answer and restart are padded to PAD characters of JSON, so their size tells nothing. Every field is checked
// exactly (an unknown key, a wrong type: dropped); an SDP must hold one audio stream and exactly one sha-256 DTLS
// fingerprint, which the envelope's signature binds to the pairing's identities: a relay cannot stand in the middle.
//
// Timers: the caller gives up at RING_S (end no_answer); a ring past its exp is a "Missed call"; a ring with no page
// here that can take it (none polled GET /api/calls?rtc=1 within PAGE_MS) gets `end unavailable`; ICE has ICE_MS after
// the answer, else end no_path ("Could not connect directly from these two networks.", or with a TURN server offered
// "Could not connect, not even through the relay host."). TURN (2026-11-26, for everyone): the Line's host asks its relay
// for a credential (carrier.turnServer, relay/turn.mjs) at each connection (GET /api/calls/turn), again at a restart once
// within TURN_FRESH_S of its expiry; the policy stays "all" (a direct pair preferred); the screen says "Via relay" while
// the selected pair has a relayed candidate (getStats);
// roaming (Wi-Fi to mobile data, a new address): disconnected DISCONNECTED_MS (2 s), or failed, or the shell's network
// change → the caller restarts ICE with a fresh offer, again every RETRY_MS while it does not connect; both screens say
// "Reconnecting…"; LOST_MS (30 s) after the drop → end lost, "Connection lost" on the screen and in the chat. Weak links:
// Opus asked mono, DTX, in-band FEC, ptime 20, at most MAX_BPS (16 kbit/s); every STATS_MS the far end's RTCP (loss,
// round trip) steps this side's bitrate down to MIN_BPS (8 kbit/s) under loss, back up once clean, and sets the screen's
// three bars. Signalling late or out of order: candidates wait for their description, a repeat is dropped, a restart's
// candidates that come before it wait for it, an end that comes before its ring makes that ring a missed call. Glare (two rings crossing): the call
// of the smaller original DID stands, the other side drops its own and takes the ring at once (both wanted the call).
// A second call while one is live gets `end busy`. busy and unavailable, like ringing, go only to a contact shown this
// side's presence (each says the carrier runs): another one hears nothing and its call rings out ("No answer").
//
// Ringing with the app closed (design §5): not here. A ring waits at the relay; whatever wakes the app within its 60 s
// (the push build, design/push.md) finds it in the first drain and rings through Line's `alert` hook; later than that
// it is a "Missed call". That hook is the seam: alert({on, id, did, name}) — the phone app's ringtone and heads-up today.

export const CALL_LABEL = 'sigelo-call/0';
export const TYPS = Object.freeze(['ring', 'ringing', 'answer', 'cands', 'restart', 'end']);
export const REASONS = Object.freeze(['hangup', 'declined', 'busy', 'no_answer', 'cancelled', 'lost', 'no_path', 'unavailable']);
/** Seconds: the caller's wait, a ring's life. */
export const RING_S = 45, EXP_S = 60;
/** Milliseconds: gathering before the offer goes, before the late candidates go; ICE after the answer; a disconnection
 *  before the restart, then before the call is lost; a page's last poll for a ring to wait for it; an ended call shown. */
export const GATHER_MS = 1000, LATE_MS = 5000, ICE_MS = 15000, DISCONNECTED_MS = 2000, RETRY_MS = 8000, LOST_MS = 30000, PAGE_MS = 10000, KEEP_MS = 30000;
/** Weak links (2026-11-24): Opus at most MAX_BPS, at least MIN_BPS, stepped by the far end's RTCP every STATS_MS. */
export const MAX_BPS = 16000, MIN_BPS = 8000, STEP_BPS = 4000, STATS_MS = 3000;
/** A contact's busy or unavailable answers: at most one per REPLY_MS (a flood of rings costs this side one message a while). */
export const REPLY_MS = 30000;
export const PAD = 8192, SDP_MAX = 6144, CANDS_MAX = 16, CAND_MAX = 512, ATTEMPT_MAX = 100, TEXT_MAX = 200;
export const OLD_TEXT = 'Calling you on sigelo: update to answer';
export const NO_PATH = 'Could not connect directly from these two networks.';
export const NO_PATH_RELAYED = 'Could not connect, not even through the relay host.';
/** Seconds: a TURN credential this close to its expiry is fetched again before an ICE restart gathers. */
export const TURN_FRESH_S = 600;
export const STUN_PORT = 3478;

const ID = /^[0-9a-f]{32}$/;
const bad = (check, message, status = 400) => { throw Object.assign(new Error(message), { check, status }); };
const isInt = (v) => Number.isSafeInteger(v);
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const newCallId = () => { const b = new Uint8Array(16); globalThis.crypto.getRandomValues(b); return hex(b); };
export const mss = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;
/** STUN as transfers use it (transfer-engine.mjs stunFor): this side's relay host and the contact's, port 3478. */
export const stunOf = (...relays) => [...new Set(relays.filter((r) => typeof r === 'string' && r !== '').map((r) => r.replace(/:\d+$/, '')))].map((h) => `${h}:${STUN_PORT}`);
/** STUN ['host:port', …] and TURN ({ urls, username, credential } | null) → RTCIceServer[] (as rtc-web.mjs iceServers). */
export const iceServersOf = (stun, turn = null) => [...(stun.length ? [{ urls: stun.map((s) => `stun:${s}`) }] : []),
  ...(turn ? [{ urls: [...turn.urls], username: turn.username, credential: turn.credential }] : [])];
/** getStats() → true when the selected candidate pair has a relayed (TURN) candidate on either side, false when it has
 *  none, null when no pair is selected yet. */
export function relayedOf(report) {
  const by = new Map(), pairs = [];
  let selected = null;
  report.forEach((x) => { by.set(x.id, x); if (x.type === 'transport' && x.selectedCandidatePairId) selected = x.selectedCandidatePairId; if (x.type === 'candidate-pair') pairs.push(x); });
  const pair = (selected && by.get(selected)) || pairs.find((x) => x.selected) || pairs.find((x) => x.nominated && x.state === 'succeeded');
  if (!pair) return null;
  return [by.get(pair.localCandidateId), by.get(pair.remoteCandidateId)].some((c) => c?.candidateType === 'relay');
}
/** A `.local` (multicast DNS) candidate dropped, as rtc-web.mjs does: resolving one would put an mDNS socket on the LAN. */
export const noMdns = (sdp) => sdp.split(/\r?\n/).filter((l) => !/^a=candidate:.* [0-9a-f-]+\.local /i.test(l)).join('\r\n');
const candsIn = (sdp) => (String(sdp).match(/^a=candidate:.*$/gm) ?? []).map((l) => l.slice(2).trim());

/** An SDP as a call takes it: ASCII, one audio stream, exactly one sha-256 DTLS fingerprint; else refused. */
export function checkSdp(sdp) {
  if (typeof sdp !== 'string' || sdp.length === 0 || sdp.length > SDP_MAX) bad('sdp', `an SDP of 1 to ${SDP_MAX} characters`);
  if (!sdp.startsWith('v=0') || /[^\x20-\x7e\r\n\t]/.test(sdp)) bad('sdp', 'not an SDP');
  const fp = sdp.match(/^a=fingerprint:.*$/gim) ?? [];
  if (fp.length !== 1) bad('sdp_fingerprint', `exactly one DTLS fingerprint, not ${fp.length}`);
  if (!/^a=fingerprint:sha-256 ([0-9a-f]{2}:){31}[0-9a-f]{2}\s*$/i.test(fp[0])) bad('sdp_fingerprint', 'the fingerprint is not sha-256');
  const m = sdp.match(/^m=\S+/gm) ?? [];
  if (m.length !== 1 || m[0] !== 'm=audio') bad('sdp_media', 'one audio stream, nothing else');
  return sdp;
}
const checkCands = (l) => {
  if (!Array.isArray(l) || l.length === 0 || l.length > CANDS_MAX) bad('cands', `1 to ${CANDS_MAX} candidates`);
  for (const c of l) if (typeof c !== 'string' || c.length > CAND_MAX || !/^candidate:[\x20-\x7e]+$/.test(c)) bad('cands', 'a candidate line');
  return l;
};
const KEYS = { ring: ['attempt', 'sdp', 'exp', 'text'], ringing: [], answer: ['attempt', 'sdp'], cands: ['attempt', 'cands'], restart: ['attempt', 'sdp'], end: ['reason'] };
const PADDED = new Set(['ring', 'answer', 'restart']);

/** A sigelo-call/0 content checked exactly → the same object; refused (check call, sdp…) otherwise. */
export function checkSignal(x) {
  if (x === null || typeof x !== 'object' || Array.isArray(x)) bad('call', 'an object');
  if (!TYPS.includes(x.typ)) bad('call', 'typ: one of ' + TYPS.join(', '));
  if (typeof x.id !== 'string' || !ID.test(x.id)) bad('call', 'id: 32 hex digits');
  const want = new Set(['typ', 'id', ...KEYS[x.typ], ...(PADDED.has(x.typ) ? ['pad'] : [])]);
  for (const k of Object.keys(x)) if (!want.has(k)) bad('call', `${x.typ}: no member ${JSON.stringify(k).slice(0, 40)}`);
  for (const k of KEYS[x.typ]) if (x[k] === undefined) bad('call', `${x.typ}: ${k} missing`);
  if (x.pad !== undefined && (typeof x.pad !== 'string' || x.pad.length > PAD || /[^.]/.test(x.pad))) bad('call', 'pad: dots');
  if (x.attempt !== undefined && (!isInt(x.attempt) || x.attempt < 1 || x.attempt > ATTEMPT_MAX)) bad('call', `attempt: 1 to ${ATTEMPT_MAX}`);
  if (x.typ === 'ring' && x.attempt !== 1) bad('call', 'ring: attempt 1');
  if (x.typ === 'restart' && x.attempt < 2) bad('call', 'restart: attempt 2 or more');
  if (x.sdp !== undefined) checkSdp(x.sdp);
  if (x.typ === 'ring' && (!isInt(x.exp) || x.exp < 0)) bad('call', 'exp: unix seconds');
  if (x.typ === 'ring' && (typeof x.text !== 'string' || x.text.length > TEXT_MAX)) bad('call', 'text: a line');
  if (x.typ === 'cands') checkCands(x.cands);
  if (x.typ === 'end' && !REASONS.includes(x.reason)) bad('call', 'reason: one of ' + REASONS.join(', '));
  return x;
}

/** content padded with dots to PAD characters of JSON (ring, answer, restart). */
export function padded(content) {
  const len = JSON.stringify({ ...content, pad: '' }).length;
  return { ...content, pad: '.'.repeat(Math.max(0, PAD - len)) };
}

/** The chat line a call leaves: { text, state } (design §4: "Call · 4:12", "Missed call", "Declined"). */
export function lineOf(call, nowMs) {
  if (call.connected !== null) {
    const s = Math.max(0, Math.floor(((call.ended ?? nowMs) - call.connected) / 1000));
    return call.reason === 'lost' ? { text: `Connection lost · ${mss(s)}`, state: 'lost', secs: s } : { text: `Call · ${mss(s)}`, state: 'done', secs: s };
  }
  if (call.answered !== null) return { text: 'Could not connect', state: 'failed', secs: 0 };
  if (call.dir === 'in') return call.reason === 'declined' && call.by === 'me' ? { text: 'Declined', state: 'declined', secs: 0 } : { text: 'Missed call', state: 'missed', secs: 0 };
  const r = call.reason;
  return r === 'declined' ? { text: 'Declined', state: 'declined', secs: 0 } : r === 'busy' ? { text: 'Busy', state: 'busy', secs: 0 }
    : r === 'cancelled' || r === 'hangup' ? { text: 'Cancelled', state: 'cancelled', secs: 0 } : r === 'no_path' ? { text: 'Could not connect', state: 'failed', secs: 0 }
      : { text: 'No answer', state: 'no_answer', secs: 0 };
}

// ================================================================ the host's half
/**
 * new Line({ send, contact, allowed, shares, me, line, alert?, audio?, changed?, now?, timers?, o? })
 *   send(did, content) → Promise      the carrier's send, label CALL_LABEL, internal CALL_SEND
 *   contact(did) → { did, name, online, … } | null    a live contact by its (original) DID
 *   allowed(c) → may that contact ring here ("Can call me"); shares(c) → may it see this side online (presence)
 *   me() → this identity's original DID (glare)
 *   line({ did, dir, text, call: { id, state, secs } })   a chat line kept in the history
 *   alert({ on, id, did, name }) the ring here (the seam above); audio({ on, id, name }) the call's audio mode (the
 *   phone app's CallService); changed() after anything the page shows moved
 *   o: { ringS, expS, pageMs, keepMs } (tests shorten them)
 */
export class Line {
  #t = new Map();   // id → [timer]
  constructor({ send, contact, allowed, shares = () => false, me, line, alert = () => {}, audio = () => {}, changed = () => {}, now = () => Date.now(), timers = globalThis, o = {} }) {
    Object.assign(this, { send, contact, allowed, shares, me, line, alert, audio, changed, now, timers });
    this.o = { ringS: RING_S, expS: EXP_S, pageMs: PAGE_MS, keepMs: KEEP_MS, ...o };
    this.calls = new Map();
    this.live = null;
    this.pageAt = -Infinity;
    this.seen = new Set();
    this.gone = new Set();     // ends that came before their ring (signalling out of order)
    this.replied = new Map();  // did → when a busy or unavailable answer last went
    this.dropped = 0;
  }
  /** A busy or unavailable answer, at most one per contact per REPLY_MS. */
  #reply(did, content) {
    const now = this.now(), at = this.replied.get(did);
    if (at !== undefined && now - at < REPLY_MS) return;
    this.replied.set(did, now);
    if (this.replied.size > 256) this.replied.delete(this.replied.keys().next().value);
    void this.send(did, content).catch(() => {});
  }
  #after(call, ms, f) { const t = this.timers.setTimeout(() => { try { f(); } catch {} }, ms); (this.#t.get(call.id) ?? this.#t.set(call.id, []).get(call.id)).push(t); }
  #clear(call) { for (const t of this.#t.get(call.id) ?? []) this.timers.clearTimeout(t); this.#t.delete(call.id); }
  #say(call, content) { return this.send(call.did, PADDED.has(content.typ) ? padded(content) : content); }
  #signal(call, s) {
    // A repeat (the relay delivered it twice, a retry): dropped.
    const key = JSON.stringify(s);
    if ((call.keys ??= new Set()).has(key)) return;
    call.keys.add(key);
    call.signals.push({ n: ++call.n, ...s }); this.changed();
  }
  #mine(id, dir) {
    const c = typeof id === 'string' ? this.calls.get(id) : undefined;
    if (!c || c.state === 'ended' || (dir && c.dir !== dir)) bad('call_unknown', 'no such call going on here', 404);
    return c;
  }
  #seen(id) { this.seen.add(id); if (this.seen.size > 512) this.seen.delete(this.seen.values().next().value); }
  #missed(c, id) { this.line({ did: c.did, dir: 'in', text: 'Missed call', call: { id, state: 'missed', secs: 0 } }); }
  /** The live call, or null. */
  current() { const c = this.live ? this.calls.get(this.live) : null; return c && c.state !== 'ended' ? c : null; }

  /** GET /api/calls: the live call (or the last, KEEP_MS after its end) as the page draws it; rtc: a page that can take one polled. */
  view({ rtc = false } = {}) {
    const now = this.now();
    if (rtc) this.pageAt = now;
    let c = this.current();
    if (!c) { for (const x of this.calls.values()) if (x.ended !== null && now - x.ended < this.o.keepMs && (!c || x.ended > c.ended)) c = x; }
    for (const [id, x] of this.calls) if (x.ended !== null && now - x.ended >= this.o.keepMs) this.calls.delete(id);
    if (!c) return null;
    const secs = c.connected === null ? 0 : Math.max(0, Math.floor(((c.ended ?? now) - c.connected) / 1000));
    return { id: c.id, did: c.did, name: c.name, dir: c.dir, state: c.state, reason: c.reason, glare: c.glare, attempt: c.attempt, secs,
      ...(c.dir === 'in' && c.offer && { offer: c.offer }), signals: c.signals.map((s) => ({ ...s })) };
  }

  /** The caller's Call: the ring goes, padded, with its offer. → the view. */
  async start(c, sdp) {
    if (this.current()) bad('call_busy', 'a call is going on already', 409);
    checkSdp(sdp);
    const id = newCallId(), now = this.now();
    const call = { id, did: c.did, name: c.name, dir: 'out', state: 'calling', at: now, answered: null, connected: null, ended: null, reason: null, by: null, glare: false, attempt: 1, n: 0, signals: [], audio: true };
    this.calls.set(id, call); this.live = id; this.#seen(id);
    this.audio({ on: true, id, name: c.name });
    try { await this.#say(call, { typ: 'ring', id, attempt: 1, sdp, exp: Math.floor(now / 1000) + this.o.expS, text: OLD_TEXT }); } catch (e) {
      this.#finish(call, 'unsent', 'me', { quiet: true });
      throw e;
    }
    this.#after(call, this.o.ringS * 1000, () => { if (call.state === 'calling' || call.state === 'ringing') void this.end(id, 'no_answer').catch(() => {}); });
    this.changed();
    return this.view();
  }
  /** Accept (attempt 1) or a restart answered (attempt n): the answer goes. */
  async accept(id, sdp, attempt = 1) {
    const call = this.#mine(id, 'in');
    checkSdp(sdp);
    if (attempt === 1) {
      if (call.state !== 'incoming') bad('call_state', 'that call is not ringing here', 409);
      call.state = 'connecting'; call.answered = this.now();
      this.alert({ on: false, id, did: call.did, name: call.name });
      if (!call.audio) { call.audio = true; this.audio({ on: true, id, name: call.name }); }
    } else if (attempt !== call.attempt || call.state === 'incoming') bad('call_state', `no restart ${attempt} to answer`, 409);
    await this.#say(call, { typ: 'answer', id, attempt, sdp });
    this.changed();
    return this.view();
  }
  async decline(id) {
    const call = this.#mine(id, 'in');
    if (call.state !== 'incoming') bad('call_state', 'that call is not ringing here', 409);
    this.#finish(call, 'declined', 'me');
    await this.#say(call, { typ: 'end', id, reason: 'declined' }).catch(() => {});
    return this.view();
  }
  async cands(id, attempt, list) {
    const call = this.#mine(id);
    if (attempt !== call.attempt) bad('call_state', `attempt ${call.attempt} is the current one`, 409);
    await this.#say(call, { typ: 'cands', id, attempt, cands: checkCands(list) });
    return { sent: list.length };
  }
  async restart(id, attempt, sdp) {
    const call = this.#mine(id, 'out');
    checkSdp(sdp);
    if (call.answered === null || attempt !== call.attempt + 1) bad('call_state', `the next restart is ${call.attempt + 1}`, 409);
    call.attempt = attempt;
    await this.#say(call, { typ: 'restart', id, attempt, sdp });
    this.changed();
    return this.view();
  }
  /** The page's media flows (ICE connected): the call's time starts. */
  connected(id) {
    const call = this.#mine(id);
    if (call.answered === null) bad('call_state', 'not answered yet', 409);
    if (call.connected === null) { call.connected = this.now(); call.state = 'active'; this.changed(); }
    return this.view();
  }
  /** Hang up, cancel, or the page's verdict (no_path, lost): the end goes, then the line. */
  async end(id, reason = 'hangup') {
    const call = this.#mine(id);
    if (!REASONS.includes(reason)) bad('body', 'reason: one of ' + REASONS.join(', '));
    const r = call.dir === 'out' && call.answered === null && reason === 'hangup' ? 'cancelled' : reason;
    if (call.dir === 'in' && call.state === 'incoming' && r === 'hangup') return this.decline(id);
    this.#finish(call, r, 'me');
    await this.#say(call, { typ: 'end', id, reason: r }).catch(() => {});
    return this.view();
  }
  /** The live call ended from outside the page (the phone's notification's Hang up). */
  async hangup() { const c = this.current(); return c ? this.end(c.id, 'hangup') : null; }

  #finish(call, reason, by, { quiet = false } = {}) {
    if (call.state === 'ended') return;
    this.#clear(call);
    const was = call.state;
    call.state = 'ended'; call.reason = reason; call.by = by; call.ended = this.now();
    if (this.live === call.id) this.live = null;
    if (was === 'incoming') this.alert({ on: false, id: call.id, did: call.did, name: call.name });
    if (call.audio) { call.audio = false; this.audio({ on: false, id: call.id, name: call.name }); }
    if (!quiet) { const l = lineOf(call, call.ended); this.line({ did: call.did, dir: call.dir, text: l.text, call: { id: call.id, state: l.state, secs: l.secs } }); }
    this.changed();
  }

  /** A sigelo-call/0 message from the carrier ({ from, name, content }): checked, then acted on. */
  receive({ from, content }) {
    let x;
    try { x = checkSignal(content); } catch { this.dropped++; return; }
    const c = this.contact(from);
    if (!c) { this.dropped++; return; }
    if (x.typ === 'ring') return this.#ring(c, x);
    const call = this.calls.get(x.id);
    if (!call && x.typ === 'end' && !this.seen.has(x.id)) { this.gone.add(`${c.did} ${x.id}`); if (this.gone.size > 256) this.gone.delete(this.gone.values().next().value); return; }
    if (!call || call.did !== c.did || call.state === 'ended') return;
    switch (x.typ) {
      case 'ringing': if (call.dir === 'out' && call.state === 'calling') { call.state = 'ringing'; this.changed(); } break;
      case 'answer':
        if (call.dir !== 'out') break;
        if (x.attempt === 1 && (call.state === 'calling' || call.state === 'ringing')) { call.state = 'connecting'; call.answered = this.now(); this.#clear(call); this.#signal(call, { typ: 'answer', attempt: 1, sdp: x.sdp }); }
        else if (x.attempt > 1 && x.attempt === call.attempt) this.#signal(call, { typ: 'answer', attempt: x.attempt, sdp: x.sdp });
        break;
      case 'cands':
        if (x.attempt === call.attempt) this.#signal(call, { typ: 'cands', attempt: x.attempt, cands: x.cands });
        // A restart's candidates that came before the restart itself: kept for it (one batch).
        else if (call.dir === 'in' && x.attempt === call.attempt + 1) call.early = { attempt: x.attempt, cands: x.cands };
        break;
      case 'restart':
        if (call.dir === 'in' && call.answered !== null && x.attempt === call.attempt + 1) {
          call.attempt = x.attempt; this.#signal(call, { typ: 'restart', attempt: x.attempt, sdp: x.sdp });
          if (call.early?.attempt === x.attempt) this.#signal(call, { typ: 'cands', attempt: x.attempt, cands: call.early.cands });
          call.early = null;
        }
        break;
      case 'end': this.#finish(call, x.reason, 'them'); break;
    }
  }
  #ring(c, x) {
    if (this.seen.has(x.id)) return;   // a repeat of one already taken
    this.#seen(x.id);
    const now = this.now(), nowS = Math.floor(now / 1000);
    // Not allowed to ring here (a quiet contact, the switch off) or past its life: a line, nothing said back.
    if (!this.allowed(c) || x.exp <= nowS || this.gone.has(`${c.did} ${x.id}`)) return this.#missed(c, x.id);
    let glare = false;
    const live = this.current();
    if (live) {
      if (live.did === c.did && live.dir === 'out' && (live.state === 'calling' || live.state === 'ringing')) {
        // Glare: the smaller original DID's call stands. Mine stands: theirs is dropped here (mine is taken there).
        if (this.me() < c.did) return;
        // Theirs stands: mine goes without a word (it is dropped there) and theirs is taken at once.
        this.#finish(live, 'glare', 'me', { quiet: true });
        glare = true;
      } else {
        // "Busy" says this side is online, in a call: only to a contact that may see it (as "Ringing…"); else it rings out.
        if (this.shares(c)) this.#reply(c.did, { typ: 'end', id: x.id, reason: 'busy' });
        return this.#missed(c, x.id);
      }
    }
    const exp = Math.min(x.exp, nowS + this.o.expS);
    const call = { id: x.id, did: c.did, name: c.name, dir: 'in', state: 'incoming', at: now, answered: null, connected: null, ended: null, reason: null, by: null, glare, attempt: 1, n: 0, signals: [], offer: x.sdp, exp, audio: false };
    this.calls.set(x.id, call); this.live = x.id;
    // "Ringing…" says this side is online: only to a contact that may see it (decision 2026-11-17).
    if (this.shares(c)) void this.send(c.did, { typ: 'ringing', id: x.id }).catch(() => {});
    if (!glare) this.alert({ on: true, id: x.id, did: c.did, name: c.name });
    this.#after(call, Math.max(0, exp * 1000 - now), () => { if (call.state === 'incoming') this.#finish(call, 'no_answer', 'them'); });
    // No page here that can take a call (none polled with rtc lately): unavailable, once the page had its chance.
    const check = () => {
      if (call.state !== 'incoming') return;
      if (this.now() - this.pageAt <= this.o.pageMs) return;
      this.#finish(call, 'unavailable', 'me');
      // Its quick answer says this side's carrier runs: only to a contact shown this side's presence; else it rings out.
      if (this.shares(c)) this.#reply(c.did, { typ: 'end', id: x.id, reason: 'unavailable' });
    };
    if (now - this.pageAt > this.o.pageMs) this.#after(call, this.o.pageMs, check);
    this.changed();
  }
  close() { for (const c of this.calls.values()) this.#clear(c); }
}

/**
 * The /api/calls* routes over one Line (UI-API.md "Calls"). contactOf(did) → the contact (refuses an unknown one);
 * callable(c) → whether this side may call it now (a person, present); stun(c) → the STUN list; turn() → { urls, username,
 * credential, exp } | null (the relay's TURN credential: carrier.turnServer); can: { speaker, mic, ring }
 * (ring: the host rings itself, the page plays no tone);
 * hooks: { speaker(on), mic(), micSettings() } where the host has them (the phone app); allow(c, on) / allowOf(c) the
 * "Can call me" switch.
 */
export function callRoutes({ line, contactOf, callable, stun, turn = async () => null, can = {}, hooks = {}, allow, allowOf }) {
  const idOf = (b) => (typeof b['id'] === 'string' && ID.test(b['id']) ? b['id'] : bad('body', 'id: a call id (32 hex digits)'));
  const attemptOf = (b, d) => (b['attempt'] === undefined ? d : isInt(b['attempt']) && b['attempt'] >= 1 && b['attempt'] <= ATTEMPT_MAX ? b['attempt'] : bad('body', 'attempt: a whole number'));
  return {
    'GET /api/calls': (_, q) => {
      const to = q?.get?.('to'), c = to ? contactOf(to) : null, call = line.view({ rtc: q?.get?.('rtc') === '1' });
      const peer = c ?? (call ? contactOf(call.did) : null);
      return { call, stun: stun(peer), can: { speaker: can.speaker === true, mic: can.mic === true, ring: can.ring === true } };
    },
    // A TURN server for a connection starting now; null: STUN alone. Asked at each connection, never in the poll.
    'GET /api/calls/turn': async () => {
      let t = null;
      try { t = (await turn()) ?? null; } catch {}
      return { turn: t ? { urls: t.urls, username: t.username, credential: t.credential, exp: t.exp } : null };
    },
    'POST /api/calls/start': async (b) => {
      const c = contactOf(b['to']);
      const why = callable(c);
      if (why !== true) bad(why.check, why.message, 409);
      return { call: await line.start(c, b['sdp']) };
    },
    'POST /api/calls/accept': async (b) => ({ call: await line.accept(idOf(b), b['sdp'], attemptOf(b, 1)) }),
    'POST /api/calls/decline': async (b) => ({ call: await line.decline(idOf(b)) }),
    'POST /api/calls/cands': async (b) => line.cands(idOf(b), attemptOf(b, 0), b['cands']),
    'POST /api/calls/restart': async (b) => ({ call: await line.restart(idOf(b), attemptOf(b, 0), b['sdp']) }),
    'POST /api/calls/connected': (b) => ({ call: line.connected(idOf(b)) }),
    'POST /api/calls/end': async (b) => ({ call: await line.end(idOf(b), b['reason'] ?? 'hangup') }),
    ...(typeof hooks.speaker === 'function' && { 'POST /api/calls/speaker': async (b) => { if (typeof b['on'] !== 'boolean') bad('body', 'on: true or false'); await hooks.speaker(b['on']); return { speaker: b['on'] }; } }),
    ...(typeof hooks.mic === 'function' && { 'POST /api/calls/mic': async () => ({ granted: await hooks.mic() }) }),
    ...(typeof hooks.micSettings === 'function' && { 'POST /api/calls/mic-settings': async () => { await hooks.micSettings(); return { opened: true }; } }),
    'POST /api/calls/allow': (b) => {
      const c = contactOf(b['contact']), on = b['on'];
      if (on !== true && on !== false && on !== null) bad('body', 'on: true, false, or null (the default again)');
      allow(c, on);
      return { did: c.did, can_call: allowOf(c), set: on !== null };
    },
  };
}

// ================================================================ the page's half
/**
 * Opus for weak links (design §3, 2026-11-24), asked of the far end's encoder through the SDP it is given: mono,
 * DTX (no packets in silence), in-band FEC, at most MAX_BPS, 20 ms frames (a=ptime:20). Applied to every remote description.
 */
export function opusTune(sdp) {
  const pt = /^a=rtpmap:(\d+) opus\/48000/im.exec(sdp)?.[1];
  if (!pt) return sdp;
  if (!/^a=ptime:/m.test(sdp)) sdp = sdp.replace(new RegExp(`^(a=rtpmap:${pt} opus/48000[^\r\n]*)`, 'im'), '$1\r\na=ptime:20');
  const want = { useinbandfec: '1', usedtx: '1', stereo: '0', 'sprop-stereo': '0', maxaveragebitrate: String(MAX_BPS) };
  const lines = sdp.split(/\r\n|\n/);
  const at = lines.findIndex((l) => l.startsWith(`a=fmtp:${pt} `));
  if (at < 0) { const r = lines.findIndex((l) => l.toLowerCase().startsWith(`a=rtpmap:${pt} opus`)); lines.splice(r + 1, 0, `a=fmtp:${pt} ` + Object.entries(want).map(([k, v]) => `${k}=${v}`).join(';')); return lines.join('\r\n'); }
  const kv = new Map(lines[at].slice(`a=fmtp:${pt} `.length).split(';').map((x) => x.trim()).filter(Boolean).map((x) => { const i = x.indexOf('='); return i < 0 ? [x, ''] : [x.slice(0, i), x.slice(i + 1)]; }));
  for (const [k, v] of Object.entries(want)) kv.set(k, v);
  lines[at] = `a=fmtp:${pt} ` + [...kv].map(([k, v]) => (v === '' ? k : `${k}=${v}`)).join(';');
  return lines.join('\r\n');
}
/** The screen's bars from loss (0 to 1) and round trip (s): 3 good, 2 fair, 1 poor; null not known yet. */
export function barsOf(loss, rtt) {
  if (loss === null && rtt === null) return null;
  const l = loss ?? 0, r = rtt ?? 0;
  return l < 0.03 && r < 0.3 ? 3 : l < 0.1 && r < 0.6 ? 2 : 1;
}
/** The next bitrate: down a step under loss (≥ 10 %) or a long round trip (≥ 0.5 s), up a step after two clean reads. */
export function nextBps(bps, loss, rtt, clean) {
  if ((loss ?? 0) >= 0.1 || (rtt ?? 0) >= 0.5) return { bps: Math.max(MIN_BPS, bps - STEP_BPS), clean: 0 };
  if ((loss ?? 0) < 0.02 && (rtt ?? 0) < 0.3) { const c = clean + 1; return c >= 2 ? { bps: Math.min(MAX_BPS, bps + STEP_BPS), clean: 0 } : { bps, clean: c }; }
  return { bps, clean: 0 };
}
export const AUDIO = Object.freeze({ echoCancellation: true, noiseSuppression: true, autoGainControl: true, channelCount: 1 });

/**
 * new Phone({ api, RTC, media, onState, onStream, timers, now, o })
 *   api(method, path, body?) → the route's JSON, or throws { check, message, status }
 *   RTC: the RTCPeerConnection constructor (generateCertificate on it when the browser has it: a fresh key per call)
 *   media() → a MediaStream with one audio track (getUserMedia({audio: AUDIO})); refused: mic_permission, no_mic
 *   onState(view) at every change (the call screen); onStream(stream | null) the far end's audio
 *   o: { gatherMs, lateMs, iceMs, disconnectedMs, lostMs, pollMs }
 * phone.tick() reads GET /api/calls?rtc=1 and acts on it (the page's poll calls it; while a call is live it polls itself).
 * phone.place(did), accept(), decline(), hangup(), mute(on), speaker(on); phone.view() → what the screen shows.
 */
export class Phone {
  constructor({ api, RTC = globalThis.RTCPeerConnection, media, onState = () => {}, onStream = () => {}, timers = globalThis, now = () => Date.now(), o = {} }) {
    Object.assign(this, { api, RTC, media, onState, onStream, timers, now });
    this.o = { gatherMs: GATHER_MS, lateMs: LATE_MS, iceMs: ICE_MS, disconnectedMs: DISCONNECTED_MS, retryMs: RETRY_MS, lostMs: LOST_MS, statsMs: STATS_MS, pollMs: 500, ...o };
    this.call = null;        // the Line's view
    this.stun = [];
    this.turn = null;        // the TURN server of this connection (GET /api/calls/turn), or null
    this.can = { speaker: false, mic: false };
    this.#reset();
  }
  #reset() {
    this.pc = null; this.stream = null; this.id = null; this.attempt = 1; this.applied = 0; this.pending = []; this.remote = false;
    this.ever = false; this.muted = false; this.speakerOn = false; this.phase = null; this.error = null; this.place_ = null;
    this.reconnecting = false; this.quality = null; this.bps = MAX_BPS; this.clean = 0; this.prevIn = null; this.loss = null; this.rtt = null; this.relayed = null; this.turn = null;
    for (const k of ['ice', 'disc', 'retry', 'lost', 'stats', 'poll']) this.#stop(k);
  }
  #tm = {};
  #q = Promise.resolve();
  #stop(k) { if (this.#tm[k] !== undefined) { this.timers.clearTimeout(this.#tm[k]); delete this.#tm[k]; } }
  #start(k, ms, f) { this.#stop(k); this.#tm[k] = this.timers.setTimeout(() => { delete this.#tm[k]; void f(); }, ms); }
  static available(env = globalThis) { return typeof env.RTCPeerConnection === 'function' && typeof env.navigator?.mediaDevices?.getUserMedia === 'function'; }

  /** What the screen shows: the Line's view and this page's own (the phase, an error, mute and speaker). */
  view() {
    const c = this.call;
    return { call: c, phase: this.phase, error: this.error, muted: this.muted, speaker: this.speakerOn, can: this.can, reconnecting: this.reconnecting,
      quality: this.reconnecting ? 0 : this.quality, relayed: this.relayed === true, bps: this.bps, loss: this.loss, rtt: this.rtt, live: Boolean(c && c.state !== 'ended') || this.phase === 'mic' || this.phase === 'placing' };
  }
  #changed() { try { this.onState(this.view()); } catch {} }

  async tick(extra = '') {
    let r;
    try { r = await this.api('GET', `/api/calls?rtc=1${extra}`); } catch (e) { return null; }
    this.stun = Array.isArray(r.stun) ? r.stun : [];
    this.can = r.can ?? this.can;
    // One view acted on at a time, in order: a signal is applied once (a second setRemoteDescription would throw).
    const run = this.#q.then(() => this.#sync(r.call ?? null));
    this.#q = run.catch(() => {});
    await run;
    return r;
  }
  #loop() {
    if (this.#tm.poll !== undefined) return;
    const go = async () => { await this.tick(); if (this.view().live) this.#start('poll', this.o.pollMs, go); };
    this.#start('poll', this.o.pollMs, go);
  }

  async #pc() {
    let certificates;
    try { if (typeof this.RTC.generateCertificate === 'function') certificates = [await this.RTC.generateCertificate({ name: 'ECDSA', namedCurve: 'P-256' })]; } catch {}
    this.turn = await this.#turnNow();
    const pc = new this.RTC({ iceServers: iceServersOf(this.stun, this.turn), bundlePolicy: 'max-bundle', rtcpMuxPolicy: 'require', ...(certificates && { certificates }) });
    for (const t of this.stream.getAudioTracks()) pc.addTrack(t, this.stream);
    this.prevIn = null;
    pc.addEventListener('track', (ev) => { try { this.onStream(ev.streams?.[0] ?? null); } catch {} });
    pc.addEventListener('iceconnectionstatechange', () => void this.#ice(pc));
    return pc;
  }
  async #turnNow() {
    try { const r = await this.api('GET', '/api/calls/turn'); return r?.turn && Array.isArray(r.turn.urls) ? r.turn : null; } catch { return null; }
  }
  /** Before an ICE restart gathers: a TURN credential near its expiry is replaced (coturn refuses an expired one at a new allocation). */
  async #freshTurn(pc) {
    if (!this.turn || !Number.isSafeInteger(this.turn.exp) || this.turn.exp - TURN_FRESH_S > this.now() / 1000) return;
    const t = await this.#turnNow();
    if (!t || this.pc !== pc) return;
    this.turn = t;
    try { pc.setConfiguration?.({ ...(pc.getConfiguration?.() ?? {}), iceServers: iceServersOf(this.stun, t) }); } catch {}
  }
  async #mic() {
    this.phase = 'mic'; this.#changed();
    if (this.can.mic) await this.api('POST', '/api/calls/mic');
    this.stream = await this.media();
  }
  async #gathered(pc, ms) {
    if (pc.iceGatheringState !== 'complete') {
      await new Promise((r) => {
        const t = this.timers.setTimeout(r, ms);
        pc.addEventListener('icegatheringstatechange', () => { if (pc.iceGatheringState === 'complete') { this.timers.clearTimeout(t); r(); } });
      });
    }
    return pc.localDescription.sdp;
  }
  /** The candidates found after the SDP left, once (gathering done, or lateMs). */
  async #late(pc, attempt, sent) {
    await this.#gathered(pc, this.o.lateMs);
    if (this.pc !== pc || this.attempt !== attempt || !this.id) return;
    const had = new Set(candsIn(sent)), more = candsIn(pc.localDescription?.sdp ?? '').filter((c) => !had.has(c)).slice(0, CANDS_MAX);
    if (more.length) await this.api('POST', '/api/calls/cands', { id: this.id, attempt, cands: more }).catch(() => {});
  }
  async #remote(pc, type, sdp) {
    await pc.setRemoteDescription({ type, sdp: opusTune(noMdns(sdp)) });
    this.remote = true;
    for (const c of this.pending.splice(0)) await this.#add(pc, c);
  }
  async #add(pc, c) {
    if (/ [0-9a-f-]+\.local /i.test(c)) return;
    if (!this.remote) { this.pending.push(c); return; }
    try { await pc.addIceCandidate({ candidate: c, sdpMLineIndex: 0 }); } catch {}
  }
  #fail(e) { this.error = { check: e?.check ?? 'call', message: String(e?.message ?? e) }; }

  /** Call: the microphone, a fresh connection, the offer after GATHER_MS, the ring. */
  async place(did) {
    if (this.view().live) throw Object.assign(new Error('a call is going on already'), { check: 'call_busy' });
    this.#reset();
    this.place_ = did; this.call = null;
    try {
      await this.tick(`&to=${encodeURIComponent(did)}`);
      await this.#mic();
      this.phase = 'placing'; this.#changed();
      const pc = this.pc = await this.#pc();
      await pc.setLocalDescription(await pc.createOffer());
      const sdp = await this.#gathered(pc, this.o.gatherMs);
      const r = await this.api('POST', '/api/calls/start', { to: did, sdp });
      this.id = r.call.id; this.call = r.call; this.phase = null;
      void this.#late(pc, 1, sdp);
      this.#changed(); this.#loop();
      return r.call;
    } catch (e) {
      this.#fail(e); this.#close(); this.phase = 'failed'; this.#changed();
      throw e;
    }
  }
  /** Accept the ringing call: the microphone, a connection, the answer. Nothing is gathered before this. */
  async accept() {
    const c = this.call;
    if (!c || c.dir !== 'in' || c.state !== 'incoming' || this.pc) return;
    // A fresh call here: nothing of the last one carried over (its connection's flags, bitrate, timers).
    const applied = this.applied;
    this.#reset();
    this.call = c; this.id = c.id; this.applied = applied;
    try {
      await this.#mic();
      const pc = this.pc = await this.#pc();
      await this.#remote(pc, 'offer', c.offer);
      await pc.setLocalDescription(await pc.createAnswer());
      const sdp = await this.#gathered(pc, this.o.gatherMs);
      const r = await this.api('POST', '/api/calls/accept', { id: c.id, sdp });
      this.call = r.call; this.phase = null;
      this.#start('ice', this.o.iceMs, () => this.#noPath());
      void this.#late(pc, 1, sdp);
      this.#changed(); this.#loop();
    } catch (e) {
      this.#fail(e); this.phase = 'failed';
      await this.api('POST', '/api/calls/end', { id: c.id, reason: 'hangup' }).catch(() => {});
      this.#close(); this.#changed();
    }
  }
  async decline() { const c = this.call; if (c?.dir === 'in' && c.state === 'incoming') { const r = await this.api('POST', '/api/calls/decline', { id: c.id }).catch(() => null); if (r) this.call = r.call; this.#close(); this.#changed(); } }
  async hangup(reason = 'hangup') {
    const id = this.id ?? this.call?.id;
    if (!id) { this.#close(); this.phase = null; this.#changed(); return; }
    const r = await this.api('POST', '/api/calls/end', { id, reason }).catch(() => null);
    if (r?.call) this.call = r.call;
    this.#close(); this.#changed();
  }
  mute(on) { this.muted = on === true; for (const t of this.stream?.getAudioTracks() ?? []) t.enabled = !this.muted; this.#changed(); }
  async speaker(on) { if (!this.can.speaker) return; await this.api('POST', '/api/calls/speaker', { on: on === true }); this.speakerOn = on === true; this.#changed(); }
  /** The page leaves the call screen for good (Close on the ended state). */
  dismiss() { if (!this.view().live) { this.call = null; this.phase = null; this.error = null; this.#changed(); } }

  async #noPath() { if (!this.ever && this.id) { this.error = { check: 'no_path', message: this.turn ? NO_PATH_RELAYED : NO_PATH }; await this.hangup('no_path'); } }
  async #ice(pc) {
    if (this.pc !== pc) return;
    const s = pc.iceConnectionState;
    if (s === 'connected' || s === 'completed') {
      for (const k of ['ice', 'disc', 'retry', 'lost']) this.#stop(k);
      if (this.reconnecting) { this.reconnecting = false; this.#changed(); }
      if (!this.ever) {
        this.ever = true;
        try { this.relayed = relayedOf(await pc.getStats()); } catch {}
        await this.#bitrate(pc);
        this.#start('stats', this.o.statsMs, () => this.#stats(pc));
        const r = await this.api('POST', '/api/calls/connected', { id: this.id }).catch(() => null);
        if (r?.call) this.call = r.call;
        this.#changed();
      }
    } else if (s === 'disconnected' || s === 'failed') {
      if (!this.ever) { if (s === 'failed') await this.#noPath(); return; }
      this.#drop(s === 'failed' ? 0 : this.o.disconnectedMs);
    }
  }
  /** The path dropped (or the network changed): "Reconnecting…"; the caller restarts ICE after ms (one side only: no restart
   *  glare), again every RETRY_MS while it does not connect; either side gives up LOST_MS after the drop ("Connection lost"). */
  #drop(ms) {
    if (!this.reconnecting) { this.reconnecting = true; this.#changed(); }
    if (this.call?.dir === 'out' && this.#tm.disc === undefined) this.#start('disc', ms, () => this.#restart());
    if (this.#tm.lost === undefined) this.#start('lost', this.o.lostMs, () => this.hangup('lost'));
  }
  /** The shell saw the network change (Android's default network: Wi-Fi to mobile data, a new address): the caller
   *  restarts at once, before ICE notices; the callee waits for the caller's restart. */
  networkChanged() {
    if (!this.ever || !this.pc || this.call?.state !== 'active') return;
    if (this.call.dir === 'out') { this.#stop('disc'); this.#drop(0); }
  }
  async #restart() {
    const pc = this.pc;
    if (!pc || !this.id || !this.reconnecting) return;
    const attempt = this.attempt + 1;
    // Not connected again within RETRY_MS: another restart (a later network may be up by then).
    this.#start('retry', this.o.retryMs, () => { if (this.reconnecting && this.pc === pc) { this.#stop('disc'); this.#start('disc', 0, () => this.#restart()); } });
    try {
      await this.#freshTurn(pc);
      await pc.setLocalDescription(await pc.createOffer({ iceRestart: true }));
      this.remote = false;
      const sdp = await this.#gathered(pc, this.o.gatherMs);
      if (this.pc !== pc) return;
      const r = await this.api('POST', '/api/calls/restart', { id: this.id, attempt, sdp });
      this.attempt = attempt; this.call = r.call;
      void this.#late(pc, attempt, sdp);
    } catch {}
  }
  /** The far end's RTCP every STATS_MS: loss and round trip → the bars, and this side's bitrate stepped (MIN_BPS to MAX_BPS). */
  async #stats(pc) {
    if (this.pc !== pc) return;
    try {
      const r = await pc.getStats();
      let loss = null, rtt = null, inLost = null, inRecv = null;
      r.forEach((x) => {
        if (x.type === 'remote-inbound-rtp' && (x.kind ?? 'audio') === 'audio') {
          if (typeof x.fractionLost === 'number') loss = Math.max(loss ?? 0, x.fractionLost);
          if (typeof x.roundTripTime === 'number') rtt = x.roundTripTime;
        } else if (x.type === 'inbound-rtp' && (x.kind ?? 'audio') === 'audio') { inLost = x.packetsLost ?? 0; inRecv = x.packetsReceived ?? 0; }
        else if (x.type === 'candidate-pair' && x.nominated && typeof x.currentRoundTripTime === 'number' && rtt === null) rtt = x.currentRoundTripTime;
      });
      this.relayed = relayedOf(r);
      // What reaches this side: the loss since the last read.
      const p = this.prevIn;
      if (inLost !== null) {
        this.prevIn = { lost: inLost, recv: inRecv };
        if (p) { const dl = Math.max(0, inLost - p.lost), dr = Math.max(0, inRecv - p.recv); if (dl + dr > 0) loss = Math.max(loss ?? 0, dl / (dl + dr)); }
      }
      this.loss = loss; this.rtt = rtt;
      if (!this.reconnecting) this.quality = barsOf(loss, rtt);
      const n = nextBps(this.bps, loss, rtt, this.clean);
      this.clean = n.clean;
      if (n.bps !== this.bps) { this.bps = n.bps; await this.#bitrate(pc); }
      this.#changed();
    } catch {}
    if (this.pc === pc) this.#start('stats', this.o.statsMs, () => this.#stats(pc));
  }
  async #bitrate(pc) {
    for (const snd of pc.getSenders?.() ?? []) {
      if (snd.track && snd.track.kind !== 'audio') continue;
      try {
        const p = snd.getParameters();
        if (!p.encodings || p.encodings.length === 0) p.encodings = [{}];
        p.encodings[0].maxBitrate = this.bps;
        await snd.setParameters(p);
      } catch {}
    }
  }
  async #sync(call) {
    const was = this.call;
    if (call === null) {
      // Gone from the host (KEEP_MS after its end, or the page started before it): nothing live here either.
      if (was && was.state !== 'ended' && !this.place_) { this.#close(); this.call = null; this.#changed(); }
      else if (this.call && this.call.state === 'ended' && !this.pc) { /* kept on the screen until dismissed */ }
      return;
    }
    if (this.place_ && call.dir === 'out' && this.id === null) return;   // placing: its own answer says the id
    if (this.id && call.id !== this.id) {
      // Ours ended, another one came (a glare's ring, a new call): this page's connection goes.
      if (this.pc) this.#close();
    }
    const fresh = !was || was.id !== call.id;
    this.call = call;
    if (fresh) { this.applied = 0; if (call.dir === 'in') { this.id = null; this.attempt = 1; } }
    if (call.state === 'ended') { if (this.pc || this.stream) this.#close(); this.#changed(); return; }
    // Glare: theirs stands and this side wanted the call too: taken at once.
    if (call.dir === 'in' && call.state === 'incoming' && call.glare && !this.pc) { this.#changed(); return this.accept(); }
    const pc = this.pc;
    for (const s of call.signals) {
      if (!pc || this.pc !== pc) break;
      if (s.n <= this.applied) continue;
      this.applied = s.n;
      try {
        if (s.typ === 'answer' && call.dir === 'out' && s.attempt === this.attempt) {
          await this.#remote(pc, 'answer', s.sdp);
          if (s.attempt === 1) this.#start('ice', this.o.iceMs, () => this.#noPath());
          // A restart whose path never dropped (the shell's network event came first): ICE stays connected, no event comes.
          else if (['connected', 'completed'].includes(pc.iceConnectionState)) void this.#ice(pc);
        } else if (s.typ === 'cands' && s.attempt === this.attempt) {
          for (const c of s.cands) await this.#add(pc, c);
        } else if (s.typ === 'restart' && call.dir === 'in') {
          this.attempt = s.attempt; this.remote = false;
          await this.#freshTurn(pc);
          await this.#remote(pc, 'offer', s.sdp);
          await pc.setLocalDescription(await pc.createAnswer());
          const sdp = await this.#gathered(pc, this.o.gatherMs);
          await this.api('POST', '/api/calls/accept', { id: this.id, attempt: s.attempt, sdp });
          void this.#late(pc, s.attempt, sdp);
        }
      } catch (e) { this.#fail(e); }
    }
    this.#changed();
    if (call.state !== 'ended') this.#loop();
  }
  #close() {
    for (const k of ['ice', 'disc', 'retry', 'lost', 'stats']) this.#stop(k);
    this.reconnecting = false;
    try { this.pc?.close(); } catch {}
    for (const t of this.stream?.getTracks?.() ?? []) { try { t.stop(); } catch {} }
    this.pc = null; this.stream = null; this.place_ = null; this.remote = false; this.pending = [];
    try { this.onStream(null); } catch {}
  }
}
