// SPDX-License-Identifier: MIT
// Voice calls (call.mjs, design/calls.md): the sigelo-call/0 messages and their checks (exact members, one sha-256
// fingerprint, one audio stream, the padding), the chat lines, Opus asked mono with FEC at 32 kbit/s; then two hosts'
// Lines wired to each other as the relay would carry them, each with a page's Phone over a fake RTCPeerConnection
// (test-fake-rtc.mjs): a call accepted and hung up, declined, no answer, busy, glare, a contact not allowed to ring,
// no page to ring (unavailable), an expired ring, no direct path, an ICE restart and a call lost, a fresh certificate
// per call, a swapped fingerprint refused; then, with the relay checkout beside apps/contact/, two carriers: the label
// kept apart (CALL_SEND only, never in inbox() nor the log, a `call` event without content).
//   node apps/contact/test-call.mjs   → ALL PASS (n)
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { CALL_LABEL, MAX_BPS, MIN_BPS, NO_PATH, NO_PATH_RELAYED, OLD_TEXT, RELAY_ONLY, policyOf, relayOnly, TURN_FRESH_S, iceServersOf, relayedOf, PAD, REASONS, TYPS, Line, Phone, barsOf, callRoutes, checkSdp, checkSignal, lineOf, nextBps, opusTune, padded, stunOf } from './call.mjs';
import { fakeNet } from './test-fake-rtc.mjs';

let count = 0;
const fails = [];
const ok = (cond, what, more) => { count++; if (!cond) fails.push(more === undefined ? what : `${what} (${String(more).slice(0, 600)})`); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const failure = async (f) => { try { await f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.message}`; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (f, ms = 5000) => { const t = Date.now() + ms; while (Date.now() < t) { if (await f()) return true; await sleep(10); } return false; };
const report = () => { for (const f of fails) console.log('FAIL ' + f); if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); } };
setTimeout(() => { console.log(`FAIL the run did not finish in 300 s (${count} checks so far)`); for (const f of fails) console.log('FAIL ' + f); process.exit(1); }, 300000).unref();
const HERE = dirname(fileURLToPath(import.meta.url));

// ================================================================ the messages
const net0 = fakeNet();
const pc0 = new net0.RTC({});
const SDP = (await pc0.createOffer()).sdp;
ok(CALL_LABEL === 'sigelo-call/0' && TYPS.join() === 'ring,ringing,answer,cands,restart,end' && REASONS.length === 8, 'the label sigelo-call/0, six typs, eight reasons');
ok(checkSdp(SDP) === SDP, 'an audio SDP with one sha-256 fingerprint: accepted');
const fp = /^a=fingerprint:.*$/m.exec(SDP)[0];
for (const [s, why, check] of [
  [SDP.replace(fp + '\r\n', ''), 'no fingerprint', 'sdp_fingerprint'], [SDP.replace(fp, fp + '\r\n' + fp), 'two fingerprints', 'sdp_fingerprint'],
  [SDP.replace(/sha-256 \S+/, 'sha-1 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01'), 'a sha-1 fingerprint', 'sdp_fingerprint'],
  [SDP + 'm=video 9 UDP/TLS/RTP/SAVPF 96\r\n', 'a video stream beside it', 'sdp_media'], [SDP.replace('m=audio', 'm=application'), 'a data channel instead', 'sdp_media'],
  ['x' + SDP, 'not an SDP', 'sdp'], [SDP + 'a=x:é\r\n', 'non-ASCII', 'sdp'], [SDP + 'a=x:' + 'y'.repeat(7000) + '\r\n', 'past 6144 characters', 'sdp'],
]) ok(checkOf(() => checkSdp(s)) === check, `an SDP with ${why}: refused ${check}`, checkOf(() => checkSdp(s)));
const ID = 'ab'.repeat(16);
const ring = padded({ typ: 'ring', id: ID, attempt: 1, sdp: SDP, exp: 1800000000, text: OLD_TEXT });
ok(JSON.stringify(ring).length === PAD && JSON.stringify(padded({ typ: 'answer', id: ID, attempt: 1, sdp: SDP })).length === PAD && checkOf(() => checkSignal(ring)) === 'accepted',
  `ring and answer padded to ${PAD} characters of JSON, and accepted`);
ok(checkOf(() => checkSignal({ typ: 'ringing', id: ID })) === 'accepted' && checkOf(() => checkSignal({ typ: 'end', id: ID, reason: 'busy' })) === 'accepted'
  && checkOf(() => checkSignal({ typ: 'cands', id: ID, attempt: 1, cands: ['candidate:1 1 udp 1 192.0.2.1 5000 typ host'] })) === 'accepted', 'ringing, end, cands: accepted');
for (const [x, why] of [
  [{ ...ring, extra: 1 }, 'an extra member'], [{ ...ring, id: 'AB'.repeat(16) }, 'an id in capitals'], [{ ...ring, attempt: 2 }, 'a ring of attempt 2'], [{ ...ring, exp: 1.5 }, 'a float exp'],
  [{ typ: 'end', id: ID, reason: 'bored' }, 'an unknown reason'], [{ typ: 'dial', id: ID }, 'an unknown typ'], [{ typ: 'restart', id: ID, attempt: 1, sdp: SDP }, 'a restart of attempt 1'],
  [{ typ: 'cands', id: ID, attempt: 1, cands: [] }, 'no candidate'], [{ typ: 'cands', id: ID, attempt: 1, cands: ['a=candidate:x'] }, 'a candidate line with its a='],
  [{ ...ring, pad: 'xx' }, 'padding not dots'], [{ typ: 'ringing', id: ID, pad: '' }, 'padding on a ringing'], [{ ...ring, sdp: SDP.replace(fp + '\r\n', '') }, 'an SDP with no fingerprint'], [[ring], 'an array'],
]) ok(checkOf(() => checkSignal(x)) !== 'accepted', `refused: ${why}`);
ok(stunOf('relay.sigelo.ai', 'relay.example.org:8883', 'relay.sigelo.ai', null).join() === 'relay.sigelo.ai:3478,relay.example.org:3478', 'STUN: both relay hosts, port 3478, once each');
const tuned = opusTune(SDP);
ok(/^a=fmtp:111 minptime=10;useinbandfec=1;usedtx=1;stereo=0;sprop-stereo=0;maxaveragebitrate=16000$/m.test(tuned) && /^a=ptime:20$/m.test(tuned)
  && opusTune(SDP.replace(/a=fmtp:111.*\r\n/, '')).includes('a=fmtp:111 useinbandfec=1;usedtx=1;stereo=0;sprop-stereo=0;maxaveragebitrate=16000'),
  'Opus asked of the far end for weak links: in-band FEC, DTX, mono, 16 kbit/s at most, 20 ms frames (an fmtp line added where none was)');
ok(barsOf(null, null) === null && barsOf(0, 0.05) === 3 && barsOf(0.05, 0.1) === 2 && barsOf(0, 0.45) === 2 && barsOf(0.15, 0.1) === 1 && barsOf(0, 0.9) === 1,
  'the bars: 3 under 3 % loss and 300 ms, 2 under 10 % and 600 ms, else 1; none before a read');
{
  let b = MAX_BPS, c = 0; const seq = [];
  for (const l of [0.15, 0.15, 0.15, 0.15, 0, 0, 0, 0, 0.05]) { ({ bps: b, clean: c } = nextBps(b, l, 0.05, c)); seq.push(b); }
  ok(seq.join() === '12000,8000,8000,8000,8000,12000,12000,16000,16000' && MIN_BPS === 8000 && MAX_BPS === 16000, `the bitrate: down a step under loss to 8 kbit/s, up a step after two clean reads to 16 (${seq})`);
}
const L = (o) => lineOf({ dir: 'out', connected: null, answered: null, ended: 0, reason: null, by: null, ...o }, 0).text;
ok(L({ connected: 0, ended: 192000 }) === 'Call · 3:12' && L({ dir: 'in', reason: 'no_answer' }) === 'Missed call' && L({ dir: 'in', reason: 'declined', by: 'me' }) === 'Declined'
  && L({ reason: 'declined' }) === 'Declined' && L({ reason: 'busy' }) === 'Busy' && L({ reason: 'no_answer' }) === 'No answer' && L({ reason: 'unavailable' }) === 'No answer'
  && L({ reason: 'cancelled' }) === 'Cancelled' && L({ answered: 1, reason: 'no_path' }) === 'Could not connect',
  'the chat lines: "Call · 3:12", "Missed call", "Declined", "Busy", "No answer", "Cancelled", "Could not connect"');

// ================================================================ two hosts and their pages
const DIDS = { alice: 'did:sigelo:zAlice', bob: 'did:sigelo:zBob', carol: 'did:sigelo:zCarol' };
const FAST = { ringS: 1, expS: 3, pageMs: 600, keepMs: 800 };
const PFAST = { gatherMs: 30, lateMs: 200, iceMs: 3000, disconnectedMs: 300, retryMs: 500, lostMs: 1500, statsMs: 60, pollMs: 20 };
/** A host: its Line, its contacts, its chat lines, the page's api over callRoutes, and its Phone. */
function host(name, net, world, { turn = undefined, policy = undefined } = {}) {
  const H = { name, did: DIDS[name], lines: [], alerts: [], audio: [], allow: {}, sent: [], offline: false, world };
  H.contacts = Object.fromEntries(Object.entries(DIDS).filter(([n]) => n !== name).map(([n, d]) => [d, { did: d, name: n, online: true, tier: 'friend', presence: 'allow', relay: 'relay.test' }]));
  H.line = new Line({
    send: async (to, content) => { H.sent.push(content); const x = JSON.parse(JSON.stringify(content)); setTimeout(() => world[to]?.line.receive({ from: H.did, content: x }), 2); return { status: 'sent' }; },
    contact: (d) => H.contacts[d] ?? null, allowed: (c) => H.allow[c.did] ?? c.tier !== 'quiet', shares: (c) => c.presence === 'allow', me: () => H.did,
    line: (l) => H.lines.push(l), alert: (x) => H.alerts.push(x), audio: (x) => H.audio.push(x), o: FAST,
  });
  const routes = callRoutes({ line: H.line, contactOf: (d) => H.contacts[d] ?? (() => { throw Object.assign(new Error('not a contact'), { check: 'not_contact', status: 404 }); })(),
    callable: (c) => (c.online === true ? true : { check: 'call_offline', message: 'not online' }), stun: (c) => stunOf('relay.test', c?.relay), ...(turn && { turn }), ...(policy && { policy }), allow: () => {}, allowOf: () => true });
  H.api = async (method, path, body) => {
    const u = new URL(path, 'http://x'), f = routes[`${method} ${u.pathname}`];
    if (!f) throw Object.assign(new Error('no route'), { check: 'route', status: 404 });
    return JSON.parse(JSON.stringify(await f(JSON.parse(JSON.stringify(body ?? {})), u.searchParams)));
  };
  H.states = [];
  H.phone = new Phone({ api: H.api, RTC: net.RTC, media: net.media, onState: (v) => H.states.push(v), onStream: (s) => { H.stream = s; }, o: PFAST });
  // The page's own poll (ui.js: every 2 s; here faster).
  H.poll = setInterval(() => { if (!H.offline) void H.phone.tick(); }, 25);
  world[H.did] = H;
  return H;
}
const stop = (...hs) => { for (const h of hs) { clearInterval(h.poll); h.line.close(); } };
const state = (H) => H.line.view()?.state ?? null;
/** Ringing at H, and its page has seen it (the Accept button is drawn from the page's view). */
const rings = (H) => until(() => state(H) === 'incoming' && H.phone.call?.id === H.line.view()?.id && H.phone.call?.state === 'incoming');

// 1. A call accepted, talked over, hung up by the caller.
{
  const net = fakeNet(), world = {}, A = host('alice', net, world), B = host('bob', net, world);
  await sleep(60);
  const placed = await A.phone.place(DIDS.bob);
  ok(placed.dir === 'out' && ['calling', 'ringing'].includes(placed.state) && /^[0-9a-f]{32}$/.test(placed.id), 'Call: the ring goes, the call is the caller\'s, calling', JSON.stringify(placed));
  const ringMsg = A.sent.find((x) => x.typ === 'ring');
  ok(ringMsg && JSON.stringify(ringMsg).length === PAD && ringMsg.text === OLD_TEXT && ringMsg.exp > Date.now() / 1000 && checkSdp(ringMsg.sdp)
    && !/candidate/.test(ringMsg.sdp) && /^c=IN IP4 0\.0\.0\.0\r?$/m.test(ringMsg.sdp) && /^m=audio 9 /m.test(ringMsg.sdp) && !/192\.0\.2\.|203\.0\.113\./.test(ringMsg.sdp),
    'the ring: padded, the text for older apps, exp ahead, its offer with no address (no candidate, c= 0.0.0.0, port 9)');
  ok(await until(() => state(B) === 'incoming' && B.alerts.some((x) => x.on && x.did === DIDS.alice)), 'the callee: incoming, and its host rings (the alert seam)');
  ok(await until(() => state(A) === 'ringing'), '"Ringing…" back to the caller (presence shared)');
  ok(B.phone.pc === null && net.made === 1, 'the callee gathers nothing before Accept (no address leaves it)');
  await sleep(250);   // the caller's gathering done (fake: 60 ms)
  ok(!A.sent.some((x) => x.typ === 'cands') && !B.line.view().signals.some((x) => x.typ === 'cands'), 'the caller\'s candidates wait for the answer: none reached the ringing callee');
  ok(await failure(() => A.api('POST', '/api/calls/cands', { id: placed.id, attempt: 1, cands: ['candidate:1 1 udp 1 192.0.2.1 5000 typ host'] })) === 'call_state',
    'the Line refuses the caller\'s candidates before the answer (an older page)');
  const t0 = Date.now();
  await B.phone.accept();
  ok(B.sent.some((x) => x.typ === 'answer' && JSON.stringify(x).length === PAD) && B.alerts.some((x) => !x.on) && B.audio.some((x) => x.on), 'Accept: the answer goes padded, the ring stops, the audio mode on');
  ok(await until(() => state(A) === 'active' && state(B) === 'active'), 'both connected: active');
  const setup = Date.now() - t0;
  ok(setup < 1000, `Accept to active with the caller's candidates trickled after the answer: ${setup} ms (fake network, polls every 20-25 ms)`);
  ok(A.sent.some((x) => x.typ === 'cands' && x.cands.some((c) => / typ host/.test(c)) ) && A.sent.some((x) => x.typ === 'cands' && x.cands.some((c) => / typ srflx/.test(c)))
    && B.line.view().signals.some((x) => x.typ === 'cands'), 'after the answer: the caller\'s candidates (host and srflx) go in cands');
  ok(A.stream?.id && B.stream?.id, 'each page gets the far end\'s audio');
  const peerA = [...net.pcs].find((p) => p.type === 'offer');
  ok(peerA && /useinbandfec=1;usedtx=1;stereo=0;sprop-stereo=0;maxaveragebitrate=16000/.test(peerA.tuned), 'the answer applied with Opus tuned (mono, FEC, DTX, 16 kbit/s)');
  ok([...net.pcs].every((p) => p.senders[0]?.bps === MAX_BPS), 'the sender capped at 16 kbit/s once connected');
  A.phone.mute(true);
  ok(A.phone.stream?.getAudioTracks()[0].enabled === false && A.phone.view().muted, 'Mute: the track off');
  await sleep(1100);
  ok(A.line.view().secs >= 1, 'the timer counts from the connection', A.line.view().secs);
  await A.phone.hangup();
  ok(await until(() => state(B) === 'ended' && B.phone.pc === null && A.phone.pc === null), 'Hang up: both ended, both connections closed');
  ok(A.lines.at(-1)?.text.startsWith('Call · 0:0') && B.lines.at(-1)?.text.startsWith('Call · 0:0') && A.lines.at(-1).dir === 'out' && B.lines.at(-1).dir === 'in',
    'a chat line on each side: "Call · 0:01"', JSON.stringify([A.lines, B.lines]));
  ok(A.audio.at(-1)?.on === false && B.audio.at(-1)?.on === false, 'the audio mode off at the end');
  ok(A.phone.stream === null && net.pcs.size === 0, 'the microphone let go');
  // A second call: a fresh certificate (a fresh DTLS key) each time.
  const certs = net.certs;
  await A.phone.place(DIDS.bob);
  ok(net.certs === certs + 1, 'a second call: a fresh certificate');
  await A.phone.hangup();
  ok(await until(() => A.lines.at(-1)?.text === 'Cancelled' && B.lines.at(-1)?.text === 'Missed call'), 'cancelled before an answer: "Cancelled" here, "Missed call" there');
  stop(A, B);
}

// 2. Declined; no answer; busy; not allowed; unavailable; expired.
{
  const net = fakeNet(), world = {}, A = host('alice', net, world), B = host('bob', net, world), C = host('carol', net, world);
  await sleep(60);
  await A.phone.place(DIDS.bob);
  ok(await rings(B), 'ring');
  await B.phone.decline();
  ok(await until(() => A.lines.at(-1)?.text === 'Declined' && B.lines.at(-1)?.text === 'Declined' && A.line.view()?.reason === 'declined'), 'Decline: "Declined" on both sides, the caller told');
  await sleep(850);
  await A.phone.place(DIDS.bob);
  ok(await until(() => A.lines.at(-1)?.text === 'No answer' && B.lines.at(-1)?.text === 'Missed call', 3000), 'no answer within the ring time: "No answer", "Missed call"', JSON.stringify([A.lines.at(-1), B.lines.at(-1)]));
  ok(A.sent.some((x) => x.typ === 'end' && x.reason === 'no_answer'), 'the caller ends it no_answer');
  await sleep(850);
  // Busy: Alice talks with Bob; Carol rings Alice.
  await A.phone.place(DIDS.bob);
  await rings(B);
  await B.phone.accept();
  ok(await until(() => state(A) === 'active'), 'a call going on');
  await C.phone.place(DIDS.alice);
  ok(await until(() => C.line.view()?.reason === 'busy' && C.lines.at(-1)?.text === 'Busy' && A.lines.at(-1)?.text === 'Missed call'), 'a second call: busy for the caller, a "Missed call" line here');
  ok(state(A) === 'active', 'and the first call goes on');
  await B.phone.hangup();
  await until(() => state(A) === 'ended');
  await sleep(850);
  // Not allowed ("Can call me" off, a quiet contact): a line here, nothing said back, no ring.
  B.allow[DIDS.alice] = false;
  const alerts = B.alerts.length, said = B.sent.length;
  await A.phone.place(DIDS.bob);
  ok(await until(() => B.lines.at(-1)?.text === 'Missed call') && B.alerts.length === alerts && B.sent.length === said && state(A) === 'calling', 'not allowed to ring: a "Missed call" line only, no ring, no "Ringing…", nothing said');
  await A.phone.hangup();
  delete B.allow[DIDS.alice];
  await sleep(850);
  // No presence shared: no "Ringing…" (it would say online), the call rings all the same.
  B.contacts[DIDS.alice].presence = 'deny';
  await A.phone.place(DIDS.bob);
  ok(await until(() => state(B) === 'incoming') && (await sleep(100), state(A) === 'calling') && !B.sent.some((x) => x.typ === 'ringing' && x.id === A.line.view().id), 'presence not shared: no "Ringing…" back, it rings there');
  await A.phone.hangup();
  B.contacts[DIDS.alice].presence = 'allow';
  await sleep(850);
  // Unavailable: Bob's host has no page that can take a call (none polls with rtc).
  B.offline = true; B.line.pageAt = -Infinity;
  await A.phone.place(DIDS.bob);
  ok(await until(() => A.line.view()?.reason === 'unavailable' && A.lines.at(-1)?.text === 'No answer' && B.lines.at(-1)?.text === 'Missed call', 3000), 'no page to ring: end unavailable after PAGE_MS ("No answer", "Missed call")');
  B.offline = false;
  await sleep(850);
  // Unavailable is presence too: a contact not shown it hears nothing; its call rings out ("No answer").
  B.offline = true; B.line.pageAt = -Infinity; B.line.replied.clear(); B.contacts[DIDS.alice].presence = 'deny';
  const u0 = B.sent.length, a0 = A.lines.length;
  await A.phone.place(DIDS.bob);
  ok(await until(() => B.lines.at(-1)?.text === 'Missed call' && state(B) === 'ended', 3000) && B.sent.length === u0
    && await until(() => A.lines.length > a0 && A.lines.at(-1).text === 'No answer' && A.lines.at(-1).call.state === 'no_answer', 3000) && A.sent.some((x) => x.typ === 'end' && x.reason === 'no_answer' && x.id === A.lines.at(-1).call.id),
    'no page to ring, presence not shared: nothing said back, the call rings out ("No answer")', JSON.stringify([B.lines.at(-1), state(B), B.sent.slice(u0), A.lines.at(-1)]));
  B.offline = false; B.contacts[DIDS.alice].presence = 'allow';
  await sleep(850);
  // An expired ring (the app opened after its exp): a "Missed call" line, no ring.
  const n = B.lines.length, al = B.alerts.length;
  B.line.receive({ from: DIDS.alice, content: padded({ typ: 'ring', id: 'cd'.repeat(16), attempt: 1, sdp: SDP, exp: Math.floor(Date.now() / 1000) - 1, text: OLD_TEXT }) });
  ok(B.lines.length === n + 1 && B.lines.at(-1).text === 'Missed call' && B.alerts.length === al && state(B) !== 'incoming', 'a ring past its exp: "Missed call", no ring');
  B.line.receive({ from: DIDS.alice, content: padded({ typ: 'ring', id: 'cd'.repeat(16), attempt: 1, sdp: SDP, exp: Math.floor(Date.now() / 1000) + 50, text: OLD_TEXT }) });
  ok(B.lines.length === n + 1, 'the same ring again: nothing more');
  // Strangers and forgeries: a ring from no contact, an answer to a call that is not theirs.
  const d = B.line.dropped;
  B.line.receive({ from: 'did:sigelo:zNobody', content: padded({ typ: 'ring', id: 'ef'.repeat(16), attempt: 1, sdp: SDP, exp: Math.floor(Date.now() / 1000) + 50, text: OLD_TEXT }) });
  B.line.receive({ from: DIDS.alice, content: { typ: 'ring', id: 'ef'.repeat(16), x: 1 } });
  ok(B.line.dropped === d + 2 && state(B) !== 'incoming', 'a ring from no contact, a malformed one: dropped');
  await A.phone.place(DIDS.bob);
  await rings(B);
  const id = A.line.view().id;
  A.line.receive({ from: DIDS.carol, content: padded({ typ: 'answer', id, attempt: 1, sdp: SDP }) });
  ok(state(A) !== 'connecting' && state(A) !== 'active', 'an answer from another contact to my call: ignored');
  await A.phone.hangup();
  ok(await failure(() => A.api('POST', '/api/calls/start', { to: DIDS.bob, sdp: SDP.replace(fp + '\r\n', '') })) === 'sdp_fingerprint', 'the page\'s own offer is checked too');
  A.contacts[DIDS.bob].online = false;
  ok(await failure(() => A.api('POST', '/api/calls/start', { to: DIDS.bob, sdp: SDP })) === 'call_offline', 'a contact not online: no call (presence-gated)');
  stop(A, B, C);
}

// 2b. Calls are between people (design §1): a ring from a contact this host takes for an agent: refused silently.
{
  const net = fakeNet(), world = {}, A = host('alice', net, world), B = host('bob', net, world);
  const refused = [];
  B.line.person = (c) => c.did !== DIDS.alice; B.line.refused = (x) => refused.push(x);
  await sleep(60);
  await A.phone.place(DIDS.bob);
  await sleep(300);
  ok(refused.length === 1 && refused[0].did === DIDS.alice && refused[0].check === 'call_agent' && B.line.view() === null && B.lines.length === 0 && B.alerts.length === 0
    && B.sent.length === 0, 'a ring from an agent: no call, no line, no alert, nothing said back; refused() once for the log', JSON.stringify([refused, B.lines, B.sent]));
  ok(['calling', 'ringing'].includes(state(A)) && state(A) !== 'ringing', 'the agent side hears nothing (it rings out)');
  await A.phone.hangup();
  stop(A, B);
}

// 3. Glare: both call at once; the smaller DID's call stands, the other side takes it at once.
{
  const net = fakeNet(), world = {}, A = host('alice', net, world), B = host('bob', net, world);
  await sleep(60);
  // Both rings leave before either arrives: the relay holds them a moment.
  const hold = [];
  for (const H of [A, B]) { const s = H.line.send; H.line.send = (to, c) => (c.typ === 'ring' ? (hold.push(() => s(to, c)), Promise.resolve({ status: 'sent' })) : s(to, c)); }
  await Promise.all([A.phone.place(DIDS.bob), B.phone.place(DIDS.alice)]);
  const [aId, bId] = [A.line.view().id, B.line.view().id];
  for (const f of hold.splice(0)) await f();
  const stands = DIDS.alice < DIDS.bob ? aId : bId;
  ok(await until(() => state(A) === 'active' && state(B) === 'active'), 'glare: one call, connected on both sides');
  ok(A.line.view().id === stands && B.line.view().id === stands, 'the call of the smaller DID stands');
  ok(!A.sent.concat(B.sent).some((x) => x.typ === 'end'), 'nothing ended over the relay: the dropped ring is dropped quietly');
  ok(B.alerts.filter((x) => x.on).length === 0 && A.alerts.filter((x) => x.on).length === 0, 'and neither phone rang');
  await B.phone.hangup();
  ok(await until(() => state(A) === 'ended' && A.lines.at(-1)?.text.startsWith('Call · ') && B.lines.at(-1)?.text.startsWith('Call · ')), 'hung up by the callee: "Call · …" on both sides');
  ok(A.lines.length === 1 && B.lines.length === 1, 'one line each: the dropped call leaves none', JSON.stringify([A.lines, B.lines]));
  stop(A, B);
}

// 4. No direct path; an ICE restart; a call lost; a swapped certificate.
{
  const net = fakeNet(), world = {}, A = host('alice', net, world), B = host('bob', net, world);
  await sleep(60);
  net.direct = false;
  await A.phone.place(DIDS.bob);
  await rings(B);
  await B.phone.accept();
  ok(await until(() => A.lines.at(-1)?.text === 'Could not connect' && B.lines.at(-1)?.text === 'Could not connect', 8000), 'no pair of candidates answers within ICE_MS: "Could not connect" on both sides');
  ok([A.phone.error?.message, B.phone.error?.message].includes(NO_PATH) && [A.line.view()?.reason, B.line.view()?.reason].includes('no_path'), `the screen says "${NO_PATH}" (the relay offered no TURN)`);
  net.direct = true;
  await sleep(850);
  await A.phone.place(DIDS.bob);
  await rings(B);
  await B.phone.accept();
  ok(await until(() => state(A) === 'active' && state(B) === 'active'), 'connected again for the restart');
  await sleep(300);
  net.cut();
  ok(await until(() => A.sent.some((x) => x.typ === 'restart' && x.attempt === 2 && JSON.stringify(x).length === PAD), 2000), 'disconnected: the caller restarts ICE (attempt 2, padded)');
  ok(!B.sent.some((x) => x.typ === 'restart'), 'only the caller restarts');
  ok(await until(() => B.sent.some((x) => x.typ === 'answer' && x.attempt === 2) && [...net.pcs].every((p) => p.iceConnectionState === 'connected'), 2000), 'the callee answers the restart; connected again');
  await sleep(500);
  ok(state(A) === 'active' && state(B) === 'active', 'the call goes on after the restart');
  net.blocked = true; net.cut();
  ok(await until(() => A.phone.view().reconnecting && B.phone.view().reconnecting && A.phone.view().quality === 0, 1000), 'cut: both screens "Reconnecting…", no bars');
  ok(await until(() => A.sent.filter((x) => x.typ === 'restart').length >= 3, 3000), 'still cut: the caller restarts again every RETRY_MS', A.sent.filter((x) => x.typ === 'restart').map((x) => x.attempt));
  ok(await until(() => state(A) === 'ended' && state(B) === 'ended', 4000) && [A.line.view()?.reason, B.line.view()?.reason].includes('lost'), 'cut for good: lost LOST_MS after the drop', JSON.stringify([A.line.view(), B.line.view()]));
  ok(A.lines.at(-1)?.text.startsWith('Connection lost · ') && B.lines.at(-1)?.text.startsWith('Connection lost · ') && A.lines.at(-1).call.state === 'lost', 'the chat line: "Connection lost · m:ss"', JSON.stringify([A.lines.at(-1), B.lines.at(-1)]));
  net.blocked = false;
  await sleep(850);
  // A relay that swaps the answer's fingerprint for its own: DTLS refuses, no media.
  await A.phone.place(DIDS.bob);
  await rings(B);
  const real = B.line.send;
  B.line.send = (to, c) => real(to, c.typ === 'answer' ? padded({ ...c, pad: undefined, sdp: c.sdp.replace(/sha-256 \S+/, 'sha-256 ' + '00:'.repeat(31) + '00') }) : c);
  await B.phone.accept();
  await sleep(300);
  ok(state(A) !== 'active' && ![...net.pcs].some((p) => p.iceConnectionState === 'connected'), 'an answer whose fingerprint is not the callee\'s certificate: no connection');
  B.line.send = real;
  await A.phone.hangup();
  stop(A, B);
}

// 5. Roaming and weak links (2026-11-24): a network change (failed → restart → connected), the shell's network
// event, a lossy link (bitrate down, back up), signalling late, repeated and out of order.
{
  const net = fakeNet(), world = {}, A = host('alice', net, world), B = host('bob', net, world);
  await sleep(60);
  await A.phone.place(DIDS.bob); await rings(B); await B.phone.accept();
  ok(await until(() => state(A) === 'active' && state(B) === 'active'), 'roaming: a call');
  await sleep(200);
  // Wi-Fi to mobile data: the old path fails at once.
  const before = A.sent.filter((x) => x.typ === 'restart').length, seen = [];
  const watchA = setInterval(() => seen.push(A.phone.view().reconnecting), 5);
  net.fail();
  ok(await until(() => A.sent.filter((x) => x.typ === 'restart').length > before, 1000), 'roaming: failed → the caller restarts ICE at once (a fresh offer over the signalling path)');
  ok(await until(() => [...net.pcs].every((p) => p.iceConnectionState === 'connected') && !A.phone.view().reconnecting && !B.phone.view().reconnecting, 3000), 'roaming: connected again, "Reconnecting…" gone');
  clearInterval(watchA);
  ok(seen.includes(true) && state(A) === 'active' && state(B) === 'active', 'roaming: the screen said "Reconnecting…" meanwhile; the call stays up');
  // The shell's network change (Android's default network): the caller restarts before ICE notices.
  const b2 = A.sent.filter((x) => x.typ === 'restart').length;
  A.phone.networkChanged(); B.phone.networkChanged();
  ok(await until(() => A.sent.filter((x) => x.typ === 'restart').length === b2 + 1, 1000) && !B.sent.some((x) => x.typ === 'restart'), 'network event: the caller restarts at once; the callee waits for it');
  ok(await until(() => !A.phone.view().reconnecting && [...net.pcs].every((p) => p.iceConnectionState === 'connected'), 3000), 'network event: connected again');
  // A lossy link: 15 % loss → down to 8 kbit/s and one bar; clean → back to 16 and three bars.
  net.loss = 0.15;
  ok(await until(() => A.phone.view().bps === MIN_BPS && [...net.pcs].every((p) => p.senders[0]?.bps === MIN_BPS) && A.phone.view().quality === 1, 3000), 'lossy link (15 %): the bitrate down to 8 kbit/s (sender parameters), one bar', JSON.stringify(A.phone.view()).slice(0, 200));
  net.loss = 0; net.rtt = 0.05;
  ok(await until(() => A.phone.view().bps === MAX_BPS && [...net.pcs].every((p) => p.senders[0]?.bps === MAX_BPS) && A.phone.view().quality === 3, 3000), 'clean again: back up to 16 kbit/s, three bars');
  net.rtt = 0.45;
  ok(await until(() => A.phone.view().quality === 2, 2000), 'a long round trip (450 ms): two bars');
  net.rtt = 0.05;
  await A.phone.hangup();
  await sleep(850);
  // Out of order and repeated: every message twice, the answer held back behind its candidates.
  const twice = (H, hold) => { const s0 = H.line.send; H.line.send = async (to, c) => { if (hold?.(c)) { setTimeout(() => { void s0(to, c); void s0(to, c); }, 250); return { status: 'sent' }; } await s0(to, c); await s0(to, c); return { status: 'sent' }; }; return () => { H.line.send = s0; }; };
  const ua = twice(A), ub = twice(B, (c) => c.typ === 'answer');
  await A.phone.place(DIDS.bob); await rings(B); await B.phone.accept();
  ok(await until(() => state(A) === 'active' && state(B) === 'active', 4000), 'slow signalling: the answer after its candidates, everything twice: connected');
  const sig = A.line.view().signals;
  ok(sig.filter((x) => x.typ === 'answer').length === 1 && new Set(sig.map((x) => JSON.stringify({ ...x, n: 0 }))).size === sig.length && B.lines.length === A.lines.length, 'repeats dropped: one answer, no signal twice', sig.map((x) => x.typ));
  await A.phone.hangup(); ua(); ub();
  await sleep(850);
  // A restart's candidates before the restart (callee side), straight into the Line.
  await A.phone.place(DIDS.bob); await rings(B); await B.phone.accept();
  await until(() => state(B) === 'active');
  const id = B.line.view().id, att = B.line.view().attempt + 1, rs = (await new net.RTC({}).createOffer({ iceRestart: true })).sdp;
  B.line.receive({ from: DIDS.alice, content: { typ: 'cands', id, attempt: att, cands: ['candidate:9 1 udp 1 198.51.100.9 7000 typ srflx raddr 0.0.0.0 rport 0'] } });
  ok(!B.line.view().signals.some((x) => x.attempt === att), 'a restart\'s candidates before the restart: held');
  B.line.receive({ from: DIDS.alice, content: padded({ typ: 'restart', id, attempt: att, sdp: rs }) });
  const tail = B.line.view().signals.filter((x) => x.attempt === att).map((x) => x.typ).join();
  ok(tail === 'restart,cands', `then given after it, in order (${tail})`);
  await A.phone.hangup();
  await sleep(850);
  // An end that comes before its ring (the relay's order): that ring is a missed call, it never rings.
  const al = B.alerts.length, eid = '9a'.repeat(16);
  B.line.receive({ from: DIDS.alice, content: { typ: 'end', id: eid, reason: 'cancelled' } });
  B.line.receive({ from: DIDS.alice, content: padded({ typ: 'ring', id: eid, attempt: 1, sdp: SDP, exp: Math.floor(Date.now() / 1000) + 50, text: OLD_TEXT }) });
  ok(B.alerts.length === al && state(B) !== 'incoming' && B.lines.at(-1)?.text === 'Missed call', 'an end before its ring: the ring a missed call, no ring');
  stop(A, B);
}

// 7. TURN (2026-11-26): the ICE servers, GET /api/calls/turn, the connection built with the relay's credential, "Via relay",
// the no-path message when even the relay could not connect, a credential near its expiry fetched again at a restart.
{
  const T = { urls: ['turn:relay.test:3478?transport=udp', 'turn:relay.test:3478?transport=tcp'], username: '1764200000:abcdefghijklmnop', credential: 'Y3JlZGVudGlhbA==', exp: 1764200000 };
  ok(JSON.stringify(iceServersOf(['relay.test:3478'], null)) === JSON.stringify([{ urls: ['stun:relay.test:3478'] }]), 'ICE servers without TURN: STUN alone, as before');
  ok(JSON.stringify(iceServersOf(['relay.test:3478'], T)) === JSON.stringify([{ urls: ['stun:relay.test:3478'] }, { urls: T.urls, username: T.username, credential: T.credential }]), 'with TURN: STUN, then the relay\'s turn: URIs with username and credential');
  const stats = (local, remote, how = 'transport') => new Map([
    ...(how === 'transport' ? [['t', { id: 't', type: 'transport', selectedCandidatePairId: 'p' }]] : []),
    ['p', { id: 'p', type: 'candidate-pair', localCandidateId: 'l', remoteCandidateId: 'r', nominated: true, state: 'succeeded' }],
    ['l', { id: 'l', type: 'local-candidate', candidateType: local }], ['r', { id: 'r', type: 'remote-candidate', candidateType: remote }]]);
  ok(relayedOf(stats('relay', 'srflx')) === true && relayedOf(stats('host', 'relay', 'nominated')) === true && relayedOf(stats('srflx', 'prflx')) === false && relayedOf(new Map()) === null,
    'relayedOf: a relayed candidate on either side of the selected pair (transport\'s selectedCandidatePairId, else the nominated pair); none selected: null');
  const R = callRoutes({ line: new Line({ send: async () => ({}), contact: () => null, allowed: () => true, shares: () => false, me: () => 'did:x', o: FAST }), contactOf: () => null, callable: () => true, stun: () => [] });
  ok(JSON.stringify(await R['GET /api/calls/turn']()) === '{"turn":null,"policy":"all"}', 'GET /api/calls/turn with no TURN hook: {turn: null}, policy all');
  const R2 = callRoutes({ line: new Line({ send: async () => ({}), contact: () => null, allowed: () => true, shares: () => false, me: () => 'did:x', o: FAST }), contactOf: () => null, callable: () => true, stun: () => [], turn: async () => { throw new Error('down'); } });
  ok(JSON.stringify(await R2['GET /api/calls/turn']()) === '{"turn":null,"policy":"all"}', 'a TURN hook that fails: {turn: null} (the call goes on with STUN)');
  let asked = 0, cred = T;
  const net = fakeNet(), world = {}, A = host('alice', net, world, { turn: async () => { asked++; return cred; } }), B = host('bob', net, world, { turn: async () => cred });
  await sleep(60);
  net.direct = false;
  await A.phone.place(DIDS.bob);
  const pcA = [...net.pcs].find((p) => p.type === 'offer');
  ok(asked === 1 && pcA && JSON.stringify(pcA.cfg.iceServers) === JSON.stringify(iceServersOf(['relay.test:3478'], T)) && pcA.cfg.iceTransportPolicy === undefined,
    'the caller\'s connection: STUN and the relay\'s TURN, fetched once at connection start; the policy stays "all"', JSON.stringify(pcA?.cfg));
  ok(!A.sent.some((x) => JSON.stringify(x).includes(T.credential)), 'the credential never leaves in a call message');
  await rings(B);
  await B.phone.accept();
  const pcB = [...net.pcs].find((p) => p.type === 'answer');
  ok(pcB && pcB.cfg.iceServers.length === 2 && A.phone.view().turn === undefined, 'the callee\'s connection has its own relay\'s TURN too (fetched at Accept)');
  ok(await until(() => A.lines.at(-1)?.text === 'Could not connect' && B.lines.at(-1)?.text === 'Could not connect', 8000) && [A.phone.error?.message, B.phone.error?.message].includes(NO_PATH_RELAYED)
    && ![A.phone.error?.message, B.phone.error?.message].includes(NO_PATH), `no path even with TURN: "${NO_PATH_RELAYED}" (not "${NO_PATH}", which section 4 shows without TURN)`, JSON.stringify([A.phone.error, B.phone.error]));
  net.direct = true;
  await sleep(850);
  // Connected through the relay: the selected pair has a relayed candidate.
  const real = net.RTC.prototype.getStats;
  net.RTC.prototype.getStats = async function () { const m = await real.call(this); for (const [k, v] of stats('relay', 'srflx')) m.set(k, v); return m; };
  await A.phone.place(DIDS.bob); await rings(B); await B.phone.accept();
  ok(await until(() => state(A) === 'active' && A.phone.view().relayed === true), 'connected, the pair relayed: the view says relayed (the screen: "Via relay")');
  net.RTC.prototype.getStats = real;
  ok(await until(() => A.phone.view().relayed === false, 2000), 'a direct pair: relayed false (the screen: "Direct")');
  // A restart with a credential within TURN_FRESH_S of its expiry: fetched again and set on the connection.
  const n0 = asked, pcR = A.phone.pc;
  cred = { ...T, username: '1764203600:qrstuvwxyzabcdef', exp: 1764203600 };
  A.phone.turn = { ...T, exp: Math.floor(Date.now() / 1000) + TURN_FRESH_S - 5 };
  let setTo = null;
  pcR.getConfiguration = () => pcR.cfg; pcR.setConfiguration = (c) => { setTo = c; };
  net.cut();
  ok(await until(() => A.sent.some((x) => x.typ === 'restart'), 2000) && asked === n0 + 1 && setTo && setTo.iceServers[1]?.username === cred.username, 'a restart near the credential\'s expiry: a fresh one, set on the connection before it gathers', JSON.stringify(setTo));
  await A.phone.hangup();
  stop(A, B);
}

// 8. "Always relay my media" (design §6, 2026-11-26): the policy from the setting or SIGELO_ICE_POLICY; the connection
// relay-only, only relayed candidates leave, raddr zeroed; no TURN: RELAY_ONLY at once, nothing rung.
{
  const T = { urls: ['turn:relay.test:3478?transport=udp'], username: '1764200000:abcdefghijklmnop', credential: 'Y3JlZGVudGlhbA==', exp: 1764200000 };
  ok(policyOf(true) === 'relay' && policyOf(false, 'relay') === 'relay' && policyOf(false, undefined) === 'all' && policyOf(false, 'all') === 'all' && policyOf(false, 'RELAY') === 'all',
    'config → policy: the setting on, or SIGELO_ICE_POLICY=relay: relay; else all (only the exact word)');
  const sdp = ['v=0', 'a=candidate:1 1 udp 2122260223 192.0.2.7 5000 typ host', 'a=candidate:2 1 udp 1686052607 203.0.113.9 6000 typ srflx raddr 192.0.2.7 rport 5000',
    'a=candidate:3 1 udp 41885439 198.51.100.4 49200 typ relay raddr 203.0.113.9 rport 6000', 'a=end-of-candidates', ''].join('\r\n');
  const kept = relayOnly(sdp);
  ok(!/192\.0\.2\.7|203\.0\.113\.9/.test(kept) && /typ relay raddr 0\.0\.0\.0 rport 0/.test(kept) && kept.includes('198.51.100.4') && kept.endsWith('\r\n'),
    'relayOnly: host and srflx candidates gone, the relayed one kept with its related address zeroed (no address of this device left)', kept);
  ok(JSON.stringify(relayOnly(['candidate:1 1 udp 1 192.0.2.7 5000 typ host', 'candidate:3 1 udp 1 198.51.100.4 49200 typ relay raddr 203.0.113.9 rport 6000']))
    === JSON.stringify(['candidate:3 1 udp 1 198.51.100.4 49200 typ relay raddr 0.0.0.0 rport 0']), 'relayOnly on cands lines: the same');
  const RP = callRoutes({ line: new Line({ send: async () => ({}), contact: () => null, allowed: () => true, shares: () => false, me: () => 'did:x', o: FAST }), contactOf: () => null, callable: () => true, stun: () => [], policy: () => 'relay' });
  ok((await RP['GET /api/calls/turn']()).policy === 'relay', 'GET /api/calls/turn says policy relay with the setting on');
  // No TURN offered: the caller fails at once with the sentence, no connection made, nothing rung.
  {
    const net = fakeNet(), world = {}, A = host('alice', net, world, { policy: () => 'relay' }), B = host('bob', net, world);
    await sleep(60);
    const made = net.made;
    let err = null;
    try { await A.phone.place(DIDS.bob); } catch (e) { err = e; }
    ok(err?.check === 'relay_only' && err.message === RELAY_ONLY && A.phone.view().error?.message === RELAY_ONLY && A.phone.view().phase === 'failed',
      `relay only, no TURN: the call fails at once, "${RELAY_ONLY}"`, JSON.stringify(A.phone.view().error));
    await sleep(100);
    ok(net.made === made && !A.sent.some((x) => x.typ === 'ring') && state(B) === null, 'no connection made (nothing gathered), no ring sent');
    // The callee with relay only and no TURN: Accept fails with the sentence; the caller hears no_path.
    const C = host('carol', net, world, { policy: () => 'relay' });
    await sleep(60);
    await B.phone.place(DIDS.carol); await rings(C); await C.phone.accept();
    ok(C.phone.view().error?.message === RELAY_ONLY && await until(() => B.line.view()?.reason === 'no_path' || B.lines.at(-1)?.text === 'Could not connect', 3000),
      'the callee with relay only and no TURN: its Accept fails with the sentence, the caller is told no_path', JSON.stringify([C.phone.view().error, B.line.view()]));
    stop(A, B, C);
  }
  // With TURN: iceTransportPolicy relay, no STUN, and what leaves holds no host or srflx candidate.
  {
    const net = fakeNet(), world = {}, A = host('alice', net, world, { turn: async () => T, policy: () => 'relay' }), B = host('bob', net, world, { turn: async () => T, policy: () => 'relay' });
    await sleep(60);
    await A.phone.place(DIDS.bob);
    const pcA = [...net.pcs].find((p) => p.type === 'offer');
    ok(pcA?.cfg.iceTransportPolicy === 'relay' && pcA.cfg.iceServers.length === 1 && pcA.cfg.iceServers[0].username === T.username, 'the caller\'s connection: iceTransportPolicy relay, the TURN server alone (no STUN)', JSON.stringify(pcA?.cfg));
    await rings(B); await B.phone.accept();
    const pcB = [...net.pcs].find((p) => p.type === 'answer');
    ok(pcB?.cfg.iceTransportPolicy === 'relay', 'the callee\'s connection: relay too');
    await sleep(400);
    const out = JSON.stringify([...A.sent, ...B.sent]);
    ok(!/typ host|typ srflx|192\.0\.2\.|203\.0\.113\./.test(out), 'no host or srflx candidate, no address of either device in any call message', out.slice(0, 400));
    await A.phone.hangup();
    stop(A, B);
  }
}

// 6. A flood of rings while busy: one busy answer per contact per REPLY_MS.
{
  const net = fakeNet(), world = {}, A = host('alice', net, world), B = host('bob', net, world), C = host('carol', net, world);
  await sleep(60);
  await A.phone.place(DIDS.bob); await rings(B);
  const n0 = B.sent.filter((x) => x.typ === 'end' && x.reason === 'busy').length;
  for (let i = 0; i < 5; i++) B.line.receive({ from: DIDS.carol, content: padded({ typ: 'ring', id: `${i}b`.repeat(16), attempt: 1, sdp: SDP, exp: Math.floor(Date.now() / 1000) + 50, text: OLD_TEXT }) });
  ok(B.sent.filter((x) => x.typ === 'end' && x.reason === 'busy').length === n0 + 1 && B.lines.filter((l) => l.text === 'Missed call').length === 5, 'five rings while busy: five missed-call lines, one busy answer');
  // Busy is presence: a contact not shown it hears nothing (its call rings out), a missed-call line all the same.
  B.contacts[DIDS.carol].presence = 'deny'; B.line.replied.clear();
  const n1 = B.sent.length;
  B.line.receive({ from: DIDS.carol, content: padded({ typ: 'ring', id: '7c'.repeat(16), attempt: 1, sdp: SDP, exp: Math.floor(Date.now() / 1000) + 50, text: OLD_TEXT }) });
  ok(B.sent.length === n1 && B.lines.filter((l) => l.text === 'Missed call').length === 6, 'busy, presence not shared: nothing said back (no probe of "online, in a call"), a missed-call line');
  await A.phone.hangup();
  stop(A, B, C);
}

// ================================================================ two carriers: the label kept apart
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs')) || !existsSync(join(RELAY_DIR, 'node_modules'))) {
  report();
  console.log(`ALL PASS (${count}): SKIP the carrier part, no relay checkout with its dependencies beside apps/contact/: set SIGELO_RELAY_DIR`);
  process.exit(0);
}
{
  const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
  const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
  const { Carrier, CALL_SEND, pathsFor } = await import('./carrier.mjs');
  const require_ = (await import('node:module')).createRequire(import.meta.url);
  const HOST = 'relay.test', dir = mkdtempSync(join(tmpdir(), 'sigelo-call-'));
  const TURN_SECRET = 'f0'.repeat(32);
  const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1, turnSecret: TURN_SECRET,
    log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 4, loadBits: 8, loadPerHour: 1000, cost: { m: 8, t: 1, p: 1 } } }) });
  const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
  const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-call-test/0 ${l}`).digest());
  const agent = (label) => {
    const k = keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: '2026-10-01T00:00:00Z', nonce: seed(`${label} nonce`).slice(0, 16) });
    const a = { did: k.did, events: [] }, bundle = { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
    a.c = new Carrier({ identity: () => ({ secret: k.secret, bundle }), ...pathsFor(join(dir, `${label}.local.json`)), relay: HOST, endpoints, keep: true, backoff: [100, 400], retentionDays: 7, onEvent: (e) => a.events.push(e) });
    return a;
  };
  const A = agent('alice'), B = agent('bob');
  try {
    const inv = await A.c.invite({ name: 'bob' });
    await B.c.accept(inv.code, { name: 'alice', wait: 0.3 });
    await A.c.inbox(); await B.c.inbox(); await A.c.inbox();
    await A.c.start(); await B.c.start();
    ok(await failure(() => A.c.send('bob', { typ: 'ringing', id: ID }, { label: CALL_LABEL })) === 'body', 'sigelo-call/0 without CALL_SEND: refused (the calls\' own label)');
    const r = await A.c.send('bob', ring, { label: CALL_LABEL, internal: CALL_SEND });
    ok(r.status === 'sent', 'with CALL_SEND: sent', JSON.stringify(r));
    ok(await until(() => B.events.some((e) => e.type === 'call'), 20000), 'a `call` event at the callee');
    const ev = B.events.find((e) => e.type === 'call');
    ok(ev.from === A.did && ev.content === undefined, 'the event names the sender, without the content');
    // The state file holds no call signalling (no SDP: addresses, the DTLS fingerprint), before or after it is taken.
    const stateOf = () => { const { readFileSync, existsSync } = require_('node:fs'); return existsSync(B.c.statePath) ? readFileSync(B.c.statePath, 'utf8') : ''; };
    const s0 = stateOf();
    ok(s0.length > 0 && !/a=candidate|fingerprint|"calls"/.test(s0) && !s0.includes(ID), 'the callee\'s state file: no call message (no candidate, no fingerprint, no call id) while it waits to be taken');
    const took = B.c.takeCalls(), sorted = (o) => JSON.stringify(Object.fromEntries(Object.entries(o).sort()));
    ok(took.length === 1 && took[0].from === A.did && sorted(took[0].content) === sorted(ring) && B.c.takeCalls().length === 0, 'takeCalls(): the message, once');
    ok(!(await B.c.inbox()).messages.some((m) => m.label === CALL_LABEL) && !B.c.history({ since: 0 }).messages.some((m) => m.label === CALL_LABEL), 'never in inbox() nor the log');
    ok(!/a=candidate|fingerprint|"calls"/.test(stateOf()) && !stateOf().includes(ID), 'nor in the state file after it was taken');
    // TURN (relay/turn.mjs): the carrier asks its own relay over the session; the credential is coturn's for that secret.
    const { createHmac } = await import('node:crypto');
    const t1 = await A.c.turnServer();
    ok(t1 && t1.urls.join() === 'turn:relay.test:3478?transport=udp,turn:relay.test:3478?transport=tcp' && t1.credential === createHmac('sha1', TURN_SECRET).update(t1.username).digest('base64')
      && /^\d+:[A-Za-z0-9_-]{16}$/.test(t1.username) && t1.exp > Date.now() / 1000 + 3000, 'carrier.turnServer(): the relay\'s TURN URIs and a credential coturn accepts for its secret (base64 HMAC-SHA1 of "<exp>:<tag>")', JSON.stringify(t1));
    const t2 = await A.c.turnServer();
    ok(t2.username === t1.username && !A.events.some((e) => e.type === 'notice' && e.code === 'turn'), 'asked again: the same credential, kept (no notice event)');
    const tb = await B.c.turnServer();
    ok(tb && tb.username !== t1.username, 'another identity: another username');
  } finally {
    await A.c.stop().catch(() => {}); await B.c.stop().catch(() => {});
    await relay.close?.(); rmSync(dir, { recursive: true, force: true });
  }
}
report();
console.log(`ALL PASS (${count})`);
process.exit(0);
