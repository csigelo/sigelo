// SPDX-License-Identifier: MIT
// Transfers in the phone app (design/transfer.md §10; transfer-engine.mjs, transfer-web.mjs, rtc-web.mjs,
// photo.mjs): the accept rule's table and who counts as known; a group's fan-out (paired, through the
// creator, offline, direct asked first) over a fake carrier; the preview's checks; the page's data
// channel over a fake RTCDataChannel (the 1 MiB low mark, binary frames only); then, with the relay
// checkout beside apps/contact/ and sigelo-transfer installed, a page engine (webIo over a fake shell:
// the bytes in the shell, the bitmap saved after every chunk) against a Node agent on a loopback relay,
// both ways, a drop midway resumed, and a Downloads write that fails said in the record.
//   node apps/contact/test-transfer-web.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { CHUNK, LOW, acceptRule, chunkLength, chunksOf, noPath } from './transfer.mjs';
import * as E from './transfer-engine.mjs';
import { webIo, webTransfers } from './transfer-web.mjs';
import { channelOf, iceServers, noMdns, peer as webPeer } from './rtc-web.mjs';
import * as W from './rtc-web.mjs';
import { PHOTO_LABEL, PHOTO_MAX, checkPhoto, imageType } from './photo.mjs';

let count = 0;
const fails = [];
const ok = (cond, what, more) => { count++; if (!cond) fails.push(more === undefined ? what : `${what} (${String(more).slice(0, 600)})`); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const failure = async (f) => { try { await f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};
const HERE = dirname(fileURLToPath(import.meta.url));
const sha = (b) => createHash('sha256').update(b).digest('hex');
const seeded = (seed, n) => {
  const out = Buffer.alloc(n);
  for (let i = 0, off = 0; off < n; i++, off += 32) createHash('sha256').update(`${seed}\n${i}`).digest().copy(out, off, 0, Math.min(32, n - off));
  return new Uint8Array(out.buffer, out.byteOffset, n);
};

/** The platform's files (sync, in memory) and a fake shell's big-file bridge, the bytes in memory as the shell keeps them on disk. */
export function fakeShell({ landFails = null } = {}) {
  const m = new Map();
  const files = { read: (n) => m.get(n) ?? null, write: (n, b) => { m.set(n, Uint8Array.from(b)); }, remove: (n) => { m.delete(n); }, names: () => [...m.keys()] };
  const docs = new Map(), parts = new Map(), landed = [], ops = [];
  let docN = 0;
  const big = {
    ops, docs, parts, landed, free: async () => 1e12,
    add(name, bytes, mtime = 1000) { const doc = `d${++docN}`; docs.set(doc, { name, bytes, mtime }); return { doc, name, size: bytes.length, mtime }; },
    pick: async () => null,
    async hash(doc) {
      const d = docs.get(doc); if (!d) throw Object.assign(new Error('no such doc'), { check: 'file' });
      const n = chunksOf(d.bytes.length), hashes = new Uint8Array(n * 32);
      for (let i = 0; i < n; i++) hashes.set(createHash('sha256').update(d.bytes.subarray(i * CHUNK, i * CHUNK + chunkLength(d.bytes.length, i))).digest(), i * 32);
      return { name: d.name, size: d.bytes.length, mtime: d.mtime, sha256: sha(d.bytes), hashes };
    },
    async stat(doc) { const d = docs.get(doc); if (!d) throw Object.assign(new Error('gone'), { check: 'file_changed' }); return { size: d.bytes.length, mtime: d.mtime }; },
    async read(doc, offset, length, want) {
      ops.push('read');
      const d = docs.get(doc);
      if (!d || d.bytes.length !== want.size || d.mtime !== want.mtime) throw Object.assign(new Error('file_changed: moved'), { check: 'file_changed' });
      return d.bytes.slice(offset, offset + length);
    },
    async write(part, offset, b) {
      ops.push('write');
      const p = parts.get(part) ?? new Uint8Array(0);
      const need = offset + b.length, q = p.length >= need ? p : (() => { const x = new Uint8Array(need); x.set(p); return x; })();
      q.set(b, offset); parts.set(part, q);
    },
    async flush() { ops.push('flush'); },
    async sha256(part) { return sha(parts.get(part) ?? new Uint8Array(0)); },
    async drop(part) { parts.delete(part); },
    async land(part, name) {
      if (landFails) throw Object.assign(new Error(landFails), { check: 'land' });
      const bytes = parts.get(part); parts.delete(part);
      landed.push({ name, bytes });
      return { uri: `content://media/external/downloads/${landed.length}`, name };
    },
  };
  return { files, big };
}

// ================================================================ the accept rule
{
  const t = (o) => acceptRule({ size: 3e6, trust: 'own', ...o });
  ok(t({}) === 'auto' && t({ trust: 'compared' }) === 'auto', 'own and compared, 3 MB under 25 MB: auto');
  ok(t({ trust: 'other' }) === 'ask', 'words not compared, a public joiner, quiet (other): always asked');
  ok(t({ size: 25e6 }) === 'auto' && t({ size: 25e6 + 1 }) === 'ask', '25 MB exactly lands; one byte more asks (MB = 10^6)');
  ok(t({ limitMb: 0 }) === 'ask' && t({ limitMb: 2 }) === 'ask' && t({ limitMb: 4 }) === 'auto', 'the contact\'s own size wins: 0 always asks');
  ok(t({ defaultMb: 0 }) === 'ask' && t({ defaultMb: 1, limitMb: 5 }) === 'auto', 'the default 0: always ask, unless the contact has its own');
  ok(t({ direct: null }) === 'auto' && t({ direct: false }) === 'auto', 'the direct switch is not the rule\'s (2026-11-25): off or not asked, still auto (the lane falls to Tor or the relay)');
  const c = (x) => ({ did: 'did:sigelo:zA', tier: 'friend', ...x });
  ok(E.trustOf(c({ tier: 'own' })) === 'own' && E.trustOf(c({ ours: true })) === 'own', 'trustOf: own tier and ours are own');
  ok(E.trustOf(c({}), () => true) === 'compared' && E.trustOf(c({}), () => false) === 'other', 'trustOf: a friend is known once the words were compared');
  ok(E.trustOf(c({ via: { public: 'x' } }), () => true) === 'other' && E.trustOf(c({ tier: 'quiet' }), () => true) === 'other', 'trustOf: a public-code joiner and quiet are always other');
}

// ================================================================ the preview
{
  const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]), b64 = (b) => Buffer.from(b).toString('base64');
  const p = { type: 'image/jpeg', data: b64(jpeg), w: 640, h: 480, sha256: 'ab'.repeat(32), size: 3_200_000, name: 'IMG_1.jpg' };
  ok(PHOTO_LABEL === 'sigelo-photo/0' && PHOTO_MAX === 65536, 'label sigelo-photo/0, 64 KB at most');
  ok(checkOf(() => checkPhoto(p)) === 'accepted' && imageType(jpeg) === 'image/jpeg', 'a JPEG preview: accepted');
  ok(checkOf(() => checkPhoto({ ...p, type: 'image/webp' })) === 'photo', 'the type must be the bytes\' (JPEG called WebP): photo');
  ok(checkOf(() => checkPhoto({ ...p, data: b64(new Uint8Array(PHOTO_MAX + 1).fill(0xff)) })) === 'photo', 'more than 64 KB: photo');
  ok(checkOf(() => checkPhoto({ ...p, w: 0 })) === 'photo' && checkOf(() => checkPhoto({ ...p, extra: 1 })) === 'photo' && checkOf(() => checkPhoto({ ...p, sha256: 'x' })) === 'photo', 'w, unknown keys, sha256: photo');
  ok(checkOf(() => checkPhoto({ ...p, type: 'image/png', data: b64(new Uint8Array([0x89, 0x50, 0x4e, 0x47])) })) === 'photo', 'PNG (or any other type): photo');
}

// ================================================================ the page's data channel (fake RTCDataChannel)
{
  const on = {}, sent = [];
  const dc = { readyState: 'open', bufferedAmount: 0, addEventListener: (e, f) => { (on[e] ??= []).push(f); }, send: (f) => sent.push(f), close() { this.readyState = 'closed'; for (const f of on.close ?? []) f(); } };
  const pcOn = {}, pc = { connectionState: 'connected', addEventListener: (e, f) => { (pcOn[e] ??= []).push(f); } };
  const ch = channelOf(dc, pc), got = [], low = [], closed = [];
  ch.on('frame', (f) => got.push(f)); ch.on('low', () => low.push(1)); ch.on('close', () => closed.push(1));
  ok(dc.binaryType === 'arraybuffer' && dc.bufferedAmountLowThreshold === LOW && LOW === CHUNK, 'binary frames as ArrayBuffer; the low mark at 1 MiB');
  on.message[0]({ data: new Uint8Array([1, 2, 3]).buffer }); on.message[0]({ data: 'text' });
  ok(got.length === 1 && got[0] instanceof Uint8Array && got[0][2] === 3, 'a binary message is a frame; text is dropped');
  on.bufferedamountlow[0](); ch.send(new Uint8Array([9]));
  ok(low.length === 1 && sent.length === 1, 'bufferedamountlow → low; send goes to the channel');
  pc.connectionState = 'failed'; pcOn.connectionstatechange[0]();
  ok(closed.length === 1 && checkOf(() => ch.send(new Uint8Array(1))) !== 'accepted', 'the connection failed: closed once, send throws');
  const sdp = 'v=0\r\na=candidate:1 1 udp 1 1f2e3d4c-aaaa.local 5000 typ host\r\na=candidate:2 1 udp 1 203.0.113.5 5000 typ srflx\r\n';
  ok(!noMdns(sdp).includes('.local') && noMdns(sdp).includes('203.0.113.5'), 'a .local candidate is dropped, the public one kept');
}

// ================================================================ a group's fan-out over a fake carrier
{
  const sh = fakeShell(), io = webIo({ files: sh.files, big: sh.big }), X = webTransfers(io);
  const contacts = [{ did: 'did:sigelo:zBob', name: 'bob', tier: 'own' }, { did: 'did:sigelo:zDan', name: 'dan', tier: 'friend' }, { did: 'did:sigelo:zEve', name: 'eve', tier: 'own' }];
  const out = [];
  const carrier = { clock: () => 1_800_000_000, contacts: () => ({ contacts }), async send(to, content, o) { out.push({ to, content, label: o.label }); return { status: to === 'did:sigelo:zEve' ? 'queued' : 'sent' }; } };
  const f = await X.prepare({ doc: sh.big.add('IMG.jpg', seeded('photo', 3 * CHUNK + 7)).doc });
  const members = [{ did: 'did:sigelo:zBob', name: 'bob', contact: true }, { did: 'did:sigelo:zDan', name: 'dan', contact: true }, { did: 'did:sigelo:zCarol', name: 'carol', contact: false }, { did: 'did:sigelo:zEve', name: 'eve', contact: true }];
  ok(await failure(() => X.fanOut({ carrier, members, f, group: 'cd'.repeat(16) })) === 'direct_ask' && out.length === 0, 'dan\'s direct switch not set: direct_ask before anything is sent');
  const r = await X.fanOut({ carrier, members, f, direct: true, group: 'cd'.repeat(16) });
  ok(r.sent.map((x) => x.name).join() === 'bob,dan,eve' && r.unpaired.map((x) => x.name).join() === 'carol' && r.failed.length === 0, 'one transfer per paired member; carol (through the creator) unpaired', JSON.stringify(r));
  const ms = out.filter((x) => x.content.typ === 'manifest');
  ok(ms.length === 3 && new Set(ms.map((x) => x.content.id)).size === 3 && ms.every((x) => x.content.sha256 === f.whole && x.label === 'sigelo-transfer/0'), 'three manifests: own ids, one sha256');
  const L = X.list({ carrier });
  ok(L.out.length === 3 && L.out.every((x) => x.state === 'offered' && x.group === 'cd'.repeat(16)), 'eve offline (queued): her manifest waits at the relay; every record offered, named by the group');
  ok(!sh.files.names().some((n) => n.endsWith('.part')) && sh.big.ops.length === 0, 'nothing read nor written yet: the bytes go when each member offers');
  ok(X.settings({ patch: { keep_location: true } }).keep_location === true && X.settings({}).auto_mb === 25, 'settings: keep_location kept, auto_mb 25 by default');
  ok(X.setAuto({ carrier, contact: 'bob', mb: 0 }).auto_mb === 0 && X.list({ carrier }).auto['did:sigelo:zBob'] === 0, 'setAuto: per contact, in the list');
}

// ================================================================ TURN (2026-11-26): the relay's credential at each attempt
const TURN = { urls: ['turn:relay.test:3478?transport=udp', 'turn:relay.test:3478?transport=tcp'], username: '1764200000:abcdefghijklmnop', credential: 'Y3JlZGVudGlhbA==', exp: 1764200000 };
{
  ok(JSON.stringify(iceServers(['relay.test:3478'])) === '[{"urls":["stun:relay.test:3478"]}]' && JSON.stringify(iceServers([], null)) === '[]', 'the page\'s ICE servers without TURN: STUN alone, as before');
  ok(JSON.stringify(iceServers(['relay.test:3478'], TURN)) === JSON.stringify([{ urls: ['stun:relay.test:3478'] }, { urls: TURN.urls, username: TURN.username, credential: TURN.credential }]), 'with TURN: the relay\'s turn: URIs, username, credential after STUN');
  let cfg = null;
  class R { constructor(c) { cfg = c; } addEventListener() {} close() {} }
  const p = await webPeer({ stun: ['relay.test:3478'], turn: TURN, RTC: R });
  ok(cfg.iceServers.length === 2 && cfg.iceServers[1].credential === TURN.credential && cfg.iceTransportPolicy === undefined, 'rtc-web peer(): the connection gets STUN and TURN; the policy stays "all" (a direct pair preferred)');
  p.close();
  const eng = (o, carrier) => new E.Engine({ carrier, io: {}, timer: false, ...o });
  const asked = [];
  const c1 = { turnServer: async () => { asked.push(1); return TURN; } };
  ok((await eng({}, c1).turnOf(W))?.username === TURN.username && asked.length === 1, 'the engine asks carrier.turnServer() at each attempt');
  ok(await eng({ turn: false }, c1).turnOf(W) === null && await eng({ env: { SIGELO_TURN: 'off' } }, c1).turnOf(W) === null && asked.length === 1, 'turn: false, or SIGELO_TURN=off: none, nothing asked');
  ok(await eng({}, { turnServer: async () => { throw new Error('down'); } }).turnOf(W) === null && await eng({}, {}).turnOf(W) === null && await eng({}, { turnServer: async () => null }).turnOf(W) === null,
    'a carrier that fails, has no turnServer, or whose relay gives none: null (STUN alone)');
  ok(await eng({}, c1).turnOf({ peer() {} }) === null && await eng({}, c1).turnOf({ TURN_OK: false }) === null && asked.length === 1,
    'a module that does not say TURN_OK true (werift without its handshake checks): no credential asked');
  ok((await eng({}, c1).turnOf(await import('../transfer/rtc.mjs')))?.username === TURN.username && asked.length === 2,
    'werift (apps/transfer/rtc.mjs) with its handshake checks in place: TURN_OK true, a credential asked');
  // "Always relay my media" (design/calls.md §6): the policy, the page's peer under it, the engine's.
  ok(eng({}, {}).policyNow() === 'all' && eng({ policy: () => 'relay' }, {}).policyNow() === 'relay' && eng({ env: { SIGELO_ICE_POLICY: 'relay' } }, {}).policyNow() === 'relay'
    && eng({ policy: () => { throw new Error('x'); } }, {}).policyNow() === 'all', 'the engine\'s policy: the setting (policy()) or SIGELO_ICE_POLICY=relay; else all');
  ok(await failure(() => webPeer({ stun: ['relay.test:3478'], turn: null, RTC: R, policy: 'relay' })) === 'relay_only', 'rtc-web peer(): relay only without TURN: refused relay_only, no connection made');
  cfg = null;
  class RS { constructor(c) { cfg = c; this.iceGatheringState = 'complete'; this.localDescription = null; } addEventListener() {} createDataChannel() { return { readyState: 'connecting', addEventListener() {} }; }
    async createOffer() { return { type: 'offer', sdp: '' }; } async setLocalDescription() { this.localDescription = { sdp: 'v=0\r\na=candidate:1 1 udp 1 192.0.2.7 5000 typ host\r\na=candidate:3 1 udp 1 198.51.100.4 49200 typ relay raddr 203.0.113.9 rport 6000\r\n' }; }
    async getStats() { return new Map([['t', { id: 't', type: 'transport', selectedCandidatePairId: 'p' }], ['p', { id: 'p', type: 'candidate-pair', localCandidateId: 'l', remoteCandidateId: 'r' }], ['l', { id: 'l', candidateType: 'relay' }], ['r', { id: 'r', candidateType: 'srflx' }]]); } close() {} }
  const pr = await webPeer({ stun: ['relay.test:3478'], turn: TURN, RTC: RS, policy: 'relay' }), o = await pr.offer('sigelo-transfer/0 x 1');
  ok(cfg.iceTransportPolicy === 'relay' && cfg.iceServers.length === 1 && !/192\.0\.2\.7|203\.0\.113\.9/.test(o) && /typ relay raddr 0\.0\.0\.0 rport 0/.test(o),
    'rtc-web peer() relay only: iceTransportPolicy relay, TURN alone, the SDP with the relayed candidate only, raddr zeroed', o);
  ok(await pr.relayed() === true, 'rtc-web relayed(): the selected pair has a relayed candidate (call.mjs relayedOf, as the call screen)');
  pr.close();
  const W2 = await import('../transfer/rtc.mjs');
  ok(await failure(() => W2.peer({ turn: null, policy: 'relay' })) === 'relay_only', 'werift peer(): relay only without TURN: relay_only');
  const wr = await W2.peer({ turn: { ...TURN, urls: ['turn:127.0.0.1:9?transport=udp'] }, gatherMs: 300, policy: 'relay' }), wo = await wr.offer('sigelo-transfer/0 y 1');
  ok(typeof wo === 'string' && !/typ (host|srflx)/.test(wo) && wr.pc.config?.iceTransportPolicy === 'relay', 'werift relay only (a TURN that answers nothing): no host or srflx candidate in the offer', wo);
  ok(await wr.relayed() === null, 'werift relayed(): no pair selected yet: null');
  wr.close();
  ok(noPath('bob').startsWith('No direct path to bob from these two networks') && noPath('bob', true).startsWith('No path to bob from these two networks, not even through the relay host'),
    'no path: the old words without TURN; "not even through the relay host" with it');
}

// ================================================================ a page engine against a Node agent on a loopback relay
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs')) || !existsSync(join(HERE, '..', 'transfer', 'node_modules', 'werift'))) {
  report();
  console.log(`ALL PASS (${count}): the unit part; SKIP the flows (the relay checkout or sigelo-transfer's node_modules missing)`);
  process.exit(0);
}
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, pathsFor } = await import('./carrier.mjs');
const X = await import('./transfer-node.mjs');
const rtc = await import(pathToFileURL(join(HERE, '..', 'transfer', 'rtc.mjs')).href);
setTimeout(() => { console.log(`FAIL the run did not finish in 900 s (${count} checks so far)`); process.exit(1); }, 900_000).unref();
const HOST = 'relay.test', now = Date.parse('2026-11-13T12:00:00Z') / 1000;
const dir = mkdtempSync(join(tmpdir(), 'sigelo-transfer-web-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 4, loadBits: 8, loadPerHour: 1000, cost: { m: 8, t: 1, p: 1 } } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-transfer-web-test/0 ${l}`).digest());
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (f, ms = 60000) => { const t = Date.now() + ms; while (Date.now() < t) { if (await f()) return true; await sleep(100); } return false; };
function carrierOf(label, onEvent) {
  const k = keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: '2026-10-01T00:00:00Z', nonce: seed(`${label} nonce`).slice(0, 16) });
  const identity = join(dir, `${label}.local.json`);
  const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
  return { did: k.did, identity, c: new Carrier({ identity: () => ({ secret: k.secret, bundle }), ...pathsFor(identity), relay: HOST, endpoints, clock: () => now, keep: true, backoff: [100, 400], retentionDays: 7, onEvent }) };
}
let P = null, N = null;
const pEvents = [], nEvents = [];
const phone = carrierOf('phone', (e) => { if (e.type === 'transfer') P?.e.kick(); });
const node = carrierOf('node', (e) => { if (e.type === 'transfer') N?.e.kick(); });
const sh = fakeShell(), pio = webIo({ files: sh.files, big: sh.big }), PX = webTransfers(pio, { rtc });
// The page's peers recorded: this loopback relay gives no TURN, so every attempt goes with STUN alone, as before TURN.
const peers = [], rtcSeen = { ...rtc, peer: (o) => { peers.push(o); return rtc.peer(o); } };
{
  ok(rtc.TURN_OK === true && JSON.stringify(rtc.iceServers([], TURN)) === JSON.stringify(iceServers([], TURN)), 'sigelo-transfer (werift, handshake checks in place): TURN_OK true, the same ICE servers as the page');
  const w = await rtc.peer({ stun: [], turn: { ...TURN, urls: ['turn:127.0.0.1:9?transport=udp'] }, gatherMs: 200 });
  ok(w.pc && typeof (await w.offer('sigelo-transfer/0 t 1')) === 'string', 'werift takes a TURN server (one that answers nothing: host candidates still offered)');
  w.close();
}
P = { ...phone, X: PX, e: new E.Engine({ carrier: phone.c, io: pio, rtc: async () => rtcSeen, stun: [], maxServe: 2, retryMs: 300, onEvent: (e) => pEvents.push(e) }) };
N = { ...node, e: new X.Engine({ carrier: node.c, identity: node.identity, stun: [], tor: null, retryMs: 300, onEvent: (e) => nEvents.push(e) }) };
try {
  const inv = await P.c.invite({ name: 'node' });
  await N.c.accept(inv.code, { name: 'phone', wait: 0.3 });
  await P.c.inbox(); await N.c.inbox(); await P.c.inbox();
  P.c.setTier('node', 'own'); N.c.setTier('phone', 'own');
  await P.c.start(); await N.c.start();
  const pRec = (side, id) => PX.list({ carrier: P.c })[side].find((r) => r.id === id);
  const nRec = (side, id) => X.list({ carrier: N.c, identity: N.identity })[side].find((r) => r.id === id);

  // Phone → computer: a photo of 3 MB picked in the shell, read by range; under the computer's 25 MB: it lands unasked.
  const shot = seeded('shot', 3 * CHUNK + 123), d1 = sh.big.add('IMG_20261113.jpg', shot);
  const r1 = await PX.send({ carrier: P.c, to: 'node', doc: d1.doc });
  ok(r1.state === 'offered' && r1.file === d1.doc && r1.sha256 === sha(shot), 'the phone offers a picked file by its doc, hashed in the shell');
  ok(await until(() => nRec('in', r1.id)?.state === 'done', 120000), 'phone → computer, own contact, 3 MB: landed by the rule', JSON.stringify(nRec('in', r1.id)));
  ok(sha(readFileSync(nRec('in', r1.id).saved)) === sha(shot) && nRec('in', r1.id).path_used === 'direct', 'whole, over the direct path (the page\'s engine, werift in this test)');
  ok(await until(() => pRec('out', r1.id)?.state === 'done'), 'the phone\'s record: done');
  ok(nRec('in', r1.id).relayed === false && pRec('out', r1.id).relayed === false, 'both records: relayed false (the selected pair is direct: the transfers list says "direct")', JSON.stringify([nRec('in', r1.id).relayed, pRec('out', r1.id).relayed]));
  ok(sh.big.ops.filter((x) => x === 'read').length === 4, `read by range, one per chunk (${sh.big.ops.filter((x) => x === 'read').length})`);

  // Computer → phone: 6 MB; it lands in Downloads through the shell; the bitmap saved after every chunk.
  sh.big.ops.length = 0;
  const film = seeded('film', 6 * CHUNK + 5);
  writeFileSync(join(dir, 'film.bin'), film);
  const r2 = await X.send({ carrier: N.c, identity: N.identity, to: 'phone', path: join(dir, 'film.bin') });
  ok(await until(() => pRec('in', r2.id)?.state === 'done', 120000), 'computer → phone: landed', JSON.stringify(pRec('in', r2.id)));
  ok(sh.big.landed.length === 1 && sha(sh.big.landed[0].bytes) === sha(film) && pRec('in', r2.id).saved === 'content://media/external/downloads/1', 'in Downloads whole (MediaStore\'s URI kept as saved)');
  ok(sh.big.ops.filter((x) => x === 'flush').length >= 7, `a flush after every chunk (${sh.big.ops.filter((x) => x === 'flush').length} for 7 chunks)`);
  ok(!sh.files.names().some((n) => n.includes(r2.id)), 'no bitmap nor list left in the page\'s files');
  const item = (await P.c.inbox()).messages.find((m) => m.type === 'file' && m.transfer === r2.id);
  ok(item?.path === pRec('in', r2.id).saved, 'one inbox item, its path the Downloads URI');

  // A drop midway into the phone: interrupted, resumed with only the rest.
  X.settings({ identity: N.identity });
  const mid = seeded('mid', 12 * CHUNK); writeFileSync(join(dir, 'mid.bin'), mid);
  const r3 = await X.send({ carrier: N.c, identity: N.identity, to: 'phone', path: join(dir, 'mid.bin') });
  ok(await until(() => (P.e.progress(r3.id)?.got ?? 0) >= 3 * CHUNK, 120000), 'the third transfer is under way');
  P.e.attempts.get(r3.id)?.channel?.close();
  ok(await until(() => pRec('in', r3.id)?.state === 'done', 120000), 'cut midway: resumed and done', JSON.stringify(pRec('in', r3.id)));
  ok(pRec('in', r3.id).attempt >= 2 && sha(sh.big.landed.at(-1).bytes) === sha(mid), 'a new attempt; the file whole');

  // Downloads refuses (no storage permission, a full disk): said in the record, the partial kept; resume tries again.
  const sh2 = sh.big.land;
  sh.big.land = async () => { throw Object.assign(new Error('no permission to write to Downloads'), { check: 'land' }); };
  const small = seeded('small', CHUNK + 1); writeFileSync(join(dir, 'small.bin'), small);
  const r4 = await X.send({ carrier: N.c, identity: N.identity, to: 'phone', path: join(dir, 'small.bin') });
  ok(await until(() => pRec('in', r4.id)?.reason === 'land', 120000), 'Downloads refused: failed, reason land', JSON.stringify(pRec('in', r4.id)));
  ok(/could not be saved: no permission/.test(pRec('in', r4.id).detail) && sh.big.parts.has(r4.id), 'the reason said; the partial kept');
  sh.big.land = sh2;
  PX.resume({ carrier: P.c, id: r4.id }); P.e.kick();
  ok(await until(() => pRec('in', r4.id)?.state === 'done', 60000), 'resume: saved again without the network', JSON.stringify(pRec('in', r4.id)));
  ok(await until(() => nRec('out', r4.id)?.state === 'done', 60000), 'and the sender told done');

  // The sender's file moved before the offer: file_changed.
  const d5 = sh.big.add('moved.jpg', seeded('m5', 2000));
  X.settings({ identity: N.identity, patch: { auto_mb: 0 } });
  const r5 = await PX.send({ carrier: P.c, to: 'node', doc: d5.doc });
  await until(() => nRec('in', r5.id)?.state === 'asked');
  sh.big.docs.get(d5.doc).mtime = 2000;
  X.accept({ carrier: N.c, identity: N.identity, id: r5.id }); N.e.kick();
  ok(await until(() => pRec('out', r5.id)?.reason === 'file_changed' && nRec('in', r5.id)?.reason === 'file_changed'), 'the picked file changed after the offer: file_changed both sides');

  // "Always relay my media" on the phone, and this relay offers no TURN: its direct lane left out at once, no peer made
  // (nothing gathered), the record says the sentence; the sender is told no_path (its relay lane or Tor, as ever).
  X.settings({ identity: N.identity, patch: { auto_mb: 25 } });
  P.e.policy = () => 'relay';
  const n0 = peers.length, ro = seeded('relayonly', 2000); writeFileSync(join(dir, 'ro.bin'), ro);
  const r6 = await X.send({ carrier: N.c, identity: N.identity, to: 'phone', path: join(dir, 'ro.bin') });
  ok(await until(() => pRec('in', r6.id)?.reason === 'relay_only' || pRec('in', r6.id)?.state === 'relayed', 60000) && peers.length === n0,
    'relay only, no TURN: no peer made on the phone; failed relay_only (or relayed by the sender\'s relay lane)', JSON.stringify(pRec('in', r6.id)));
  ok(pEvents.some((e) => e.what === 'no_direct' && e.id === r6.id && e.detail === E.RELAY_ONLY), `the phone's event says "${E.RELAY_ONLY}"`);
  ok(await until(() => ['failed', 'relaying', 'done'].includes(nRec('out', r6.id)?.state), 60000) && nRec('out', r6.id)?.path_used !== 'direct', 'the sender told: not over the direct lane', JSON.stringify(nRec('out', r6.id)));
  P.e.policy = () => 'all';
} finally {
  await P.e.close().catch(() => {}); await N.e.close().catch(() => {});
  await P.c.stop().catch(() => {}); await N.c.stop().catch(() => {});
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
ok(peers.length > 0 && peers.every((o) => o.turn === null), `the relay gives no TURN: every attempt with STUN alone (${peers.length} peers)`);
report();
console.log(`ALL PASS (${count})`);
