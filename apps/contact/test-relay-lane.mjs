// SPDX-License-Identifier: MIT
// The relay lane for transfers (0.1.19; transfer-engine.mjs "The relay lane", apps/agent/TRANSFER.md): the units first
// (the end `relay`, who may fall back and up to what size, resume on a stuck transfer, a stalled channel, a record stuck
// for 10 minutes listed as interrupted), then, with the relay checkout beside apps/contact/ (SIGELO_RELAY_DIR, else
// ../../relay), two agents on a loopback relay with a fake direct path: blocked (ICE never connects) the file lands over
// sigelo-file/0 and the receiver's record is relayed, then done by the file; a channel that drops and does not come back
// within the window goes over the relay too; 8 MiB + 1 byte is not fallen back, and the relay lane refuses it.
//   node apps/contact/test-relay-lane.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { CHUNK, LOW, REASONS, checkMessage, readFrame, frames, manifest } from './transfer.mjs';
import * as E from './transfer-engine.mjs';
import { FILE_LABEL, MAX_FILE } from './file.mjs';

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

/** The engine's io in memory: the records and bitmaps as strings and bytes, the files sent by name. */
function memIo(docs = new Map()) {
  let text = null;
  const m = new Map();
  return {
    flushEach: 1, docs,
    lock: (fn) => fn(), read: () => text, write: (t) => { text = t; },
    have: { read: (id) => m.get(`h${id}`) ?? null, write: (id, b) => { if (b === null) m.delete(`h${id}`); else m.set(`h${id}`, Uint8Array.from(b)); } },
    list: { read: (id, side) => m.get(`l${id}${side}`) ?? null, write: (id, side, b) => m.set(`l${id}${side}`, b), drop: (id, side) => m.delete(`l${id}${side}`) },
    part: { open: async () => ({ write: async () => {}, flush: async () => {}, close: async () => {} }), drop: (id) => m.delete(`p${id}`), sha256: async () => '0'.repeat(64), exists: () => false },
    free: () => Infinity, land: async () => 'saved', changed: async () => false,
    prepare: async ({ path }) => { const b = docs.get(path); const n = Math.ceil(b.length / CHUNK), hashes = new Uint8Array(n * 32); for (let i = 0; i < n; i++) hashes.set(createHash('sha256').update(b.subarray(i * CHUNK, (i + 1) * CHUNK)).digest(), i * 32); return { file: path, name: path, size: b.length, mtimeMs: 1, hashes, whole: sha(b) }; },
    source: async (r) => ({ read: async (i) => docs.get(r.file).subarray(i * CHUNK, (i + 1) * CHUNK), close: async () => {} }),
    tor: null,
  };
}
const NOW = 1_800_000_000;
function fakeCarrier(contacts) {
  const sent = [], files = [];
  return { sent, files, clock: () => NOW, contacts: () => ({ contacts }), takeTransfers: () => [], deliver: () => {},
    async send(to, content, o) { sent.push({ to, content, label: o.label }); return { status: 'sent' }; },
    async sendFile(to, f) { files.push({ to, name: f.name, size: f.bytes.length, sha256: sha(f.bytes) }); return { status: 'sent', file: { id: '0'.repeat(32), name: f.name, size: f.bytes.length, sha256: sha(f.bytes) } }; } };
}
const OWN = { did: 'did:sigelo:zOwn', name: 'own', tier: 'own' }, PAL = { did: 'did:sigelo:zPal', name: 'pal', tier: 'friend' }, NEW = { did: 'did:sigelo:zNew', name: 'new', tier: 'friend' };

// ================================================================ units
{
  ok(REASONS.at(-1) === 'relay' && checkOf(() => checkMessage({ typ: 'end', id: 'ab'.repeat(16), reason: 'relay' })) === 'accepted' && readFrame(frames.end('relay')).reason === 'relay',
    'the end reason relay: last in the list (the frames\' indices stay), a well-formed end');
  ok(E.RELAY_MAX === MAX_FILE && MAX_FILE === 8 * 1024 * 1024 && E.FALLBACK_MS === 20_000 && E.STALE_S === 600, 'the relay lane carries send-file\'s 8 MiB; the window 20 s; stuck after 10 minutes');
  const e = new E.Engine({ carrier: fakeCarrier([OWN, PAL, NEW]), io: memIo(), compared: (d) => d === PAL.did, timer: false });
  const rec = (x) => ({ id: 'ab'.repeat(16), size: MAX_FILE, state: 'failed', reason: 'no_path', to: OWN.did, ...x });
  ok(e.relayable(rec({})) && e.relayable(rec({ to: PAL.did })), 'exactly 8 MiB to an own agent, or to a friend whose words were compared: falls back (no dead end at the limit)');
  ok(!e.relayable(rec({ size: MAX_FILE + 1 })), '8 MiB + 1 byte: not fallen back');
  ok(!e.relayable(rec({ to: NEW.did })) && !e.relayable(rec({ relay: 1 })) && !e.relayable(rec({ state: 'done' })), 'words not compared, gone over the relay once already, done: not by itself');
  await e.close();

  // The sender: a no_path end → over the relay, once; the receiver told first; the bytes checked against the manifest.
  {
    const docs = new Map([['a.apk', seeded('apk', CHUNK + 77)], ['big.bin', seeded('big', MAX_FILE + 1)]]), io = memIo(docs), car = fakeCarrier([OWN]);
    const r = await E.send({ carrier: car, io, to: 'own', path: 'a.apk' }), big = await E.send({ carrier: car, io, to: 'own', path: 'big.bin' });
    const x = new E.Engine({ carrier: car, io, timer: false });
    car.takeTransfers = () => { const l = car.inbound ?? []; car.inbound = []; return l; };
    car.inbound = [{ from: OWN.did, name: 'own', content: { typ: 'end', id: r.id, reason: 'no_path' } }, { from: OWN.did, name: 'own', content: { typ: 'end', id: big.id, reason: 'no_path' } }];
    await x.round();
    for (let i = 0; i < 50 && E.list({ carrier: car, io }).out.find((y) => y.id === r.id)?.state !== 'done'; i++) await new Promise((ok_) => setTimeout(ok_, 20));
    const L = E.list({ carrier: car, io }), a = L.out.find((y) => y.id === r.id), b = L.out.find((y) => y.id === big.id);
    ok(a.state === 'done' && a.path_used === 'relay' && a.relay === 1 && car.files.length === 1 && car.files[0].sha256 === r.sha256 && car.files[0].name === 'a.apk', `no path: over sigelo-file/0, whole, by itself (${JSON.stringify(a)})`);
    ok(car.sent.some((m) => m.content.typ === 'end' && m.content.reason === 'relay' && m.content.id === r.id), 'the receiver told end relay first');
    ok(b.state === 'failed' && b.reason === 'no_path' && !b.relay && car.files.length === 1, '8 MiB + 1 byte: failed no_path as before, nothing over the relay (the page offers Retry)');
    ok(await failure(() => x.relay(big.id, { manual: true })) === 'file_too_large' && await failure(() => x.relay(r.id, { manual: true })) === 'transfer_state', 'Send over the relay: refused past 8 MiB (file_too_large), and on one done');
    const rt = await E.retry({ carrier: car, io, id: big.id, engine: x }), L2 = E.list({ carrier: car, io });
    ok(rt.id !== big.id && rt.state === 'offered' && rt.sha256 === big.sha256 && L2.out.find((y) => y.id === big.id).state === 'cancelled' && car.sent.some((m) => m.content.typ === 'end' && m.content.id === big.id && m.content.reason === 'cancelled'),
      'Retry: the old one cancelled (the receiver told), the file offered afresh under a new id');
    // An offer that crossed the end relay: answered relay again, never served.
    car.inbound = [{ from: OWN.did, name: 'own', content: { typ: 'offer', id: r.id, attempt: 2, sdp: null, tor: { serve: false, connect: false } } }];
    car.sent.length = 0; await x.round();
    ok(car.sent.length === 1 && car.sent[0].content.reason === 'relay' && E.list({ carrier: car, io }).out.find((y) => y.id === r.id).state === 'done', 'a late offer: told relay again, the record stays done');
    await x.close();
  }

  // The receiver: resume on a stuck transfer; listed interrupted after 10 minutes; the end relay; a stalled channel.
  {
    const io = memIo(), car = fakeCarrier([OWN]), id = 'cd'.repeat(16), id2 = 'ce'.repeat(16), id3 = 'cf'.repeat(16);
    const base = { from: OWN.did, contact: 'own', name: 'app.apk', size: 1_000_000, sha256: 'ab'.repeat(32), chunks: 1, list: 'ab'.repeat(32), exp: NOW + 86400, attempt: 1, got: 0 };
    E.state(io, NOW, (s) => {
      s.in[id] = { ...base, id, state: 'active', reason: 'drop', detail: 'the channel went: resumed with a new offer', at: NOW - 3600, offerAt: NOW - 3600 };
      s.in[id2] = { ...base, id: id2, state: 'active', at: NOW - 60, offerAt: NOW - 60 };
      s.in[id3] = { ...base, id: id3, state: 'active', at: NOW - 60, offerAt: NOW - 60 };
    });
    ok(checkOf(() => E.accept({ carrier: car, io, id })) === 'transfer_state', 'accept on an active-but-dropped transfer: still refused (it is resume\'s)');
    const L = E.list({ carrier: car, io }), st = L.in.find((r) => r.id === id), fresh = L.in.find((r) => r.id === id2);
    ok(st.state === 'interrupted' && st.reason === 'stalled' && /resume it/.test(st.detail) && fresh.state === 'active', `active with nothing for over 10 minutes: listed interrupted, the resume hint (${st.state}: ${st.detail}); a minute: still active`);
    const rs = E.resume({ carrier: car, io, id });
    ok(rs.state === 'accepted' && rs.restart === true && rs.reason === undefined, `resume on it: accepted again, restart (${JSON.stringify(rs)})`);
    // The engine drops what it holds of it and offers again, attempt 2.
    const rtc = { peer: async () => ({ offer: async () => 'v=0 fake', close() {} }) };
    const x = new E.Engine({ carrier: car, io, rtc: async () => rtc, stun: [], timer: false, stallMs: 1000 });
    x.attempts.set(id, { role: 'in', attempt: 1, got: 0, sent: 0, order: ['direct'] });
    // A channel that moved nothing for longer than stallMs: dropped here, interrupted (resumed by itself).
    x.attempts.set(id2, { role: 'in', attempt: 1, got: 0, sent: 0, channel: { close() {} }, moved: Date.now() - 5000 });
    await x.round();
    const sent = car.sent.find((m) => m.content.typ === 'offer' && m.content.id === id), r2 = E.list({ carrier: car, io }).in.find((r) => r.id === id2);
    ok(sent?.content.attempt === 2 && E.list({ carrier: car, io }).in.find((r) => r.id === id).state === 'offering', `the engine offers it again (attempt ${sent?.content.attempt})`);
    ok(r2.state === 'interrupted' && r2.reason === 'drop' && /nothing came for 1 s/.test(r2.detail) && !x.attempts.has(id2), `a channel stalled past stallMs: dropped, interrupted drop (${r2.state}: ${r2.detail})`);
    // The sender's end relay: the record relayed, no ghost left live.
    car.takeTransfers = () => { const l = car.inbound ?? []; car.inbound = []; return l; };
    car.inbound = [{ from: OWN.did, name: 'own', content: { typ: 'end', id: id3, reason: 'relay' } }];
    await x.round();
    const r3 = E.list({ carrier: car, io }).in.find((r) => r.id === id3);
    ok(r3.state === 'relayed' && /relay lane/.test(r3.detail) && !E.STATES_LIVE_IN.includes(r3.state), `end relay: the receiver's record relayed (${r3.state})`);
    const sup = x.superseded({ type: 'file', from: OWN.did, sha256: base.sha256, path: '/files/own/app.apk', label: FILE_LABEL });
    const r4 = E.list({ carrier: car, io }).in.find((r) => r.id === id3);
    ok(sup.includes(id3) && r4.state === 'done' && r4.path_used === 'relay' && r4.saved === '/files/own/app.apk', `the file over sigelo-file/0 came: the record done, via relay (${JSON.stringify(sup)})`);
    ok(x.superseded({ type: 'file', from: OWN.did, sha256: base.sha256, transfer: id, path: 'x' }).length === 0 && x.superseded({ type: 'file', from: PAL.did, sha256: base.sha256, path: 'x' }).length === 0, 'superseded: never by a transfer\'s own item, nor by another contact\'s file');
    await x.close();
  }
}

// ================================================================ the accept rule, whatever the lane (2026-11-25)
// On the phone, with direct off, every file waited for a manual accept. The rule (transfer auto <contact> <MB>)
// says yes under the size; the direct switch only picks the lane: off, no Tor, the receiver ends no_path at once and the
// sender's relay lane carries it (up to 8 MiB).
{
  const io = memIo(), car = fakeCarrier([OWN, PAL, NEW]), x = new E.Engine({ carrier: car, io, compared: (d) => d === PAL.did, timer: false });
  car.takeTransfers = () => { const l = car.inbound ?? []; car.inbound = []; return l; };
  const offer = async (from, size) => {
    const n = Math.ceil(size / CHUNK), m = manifest({ name: 'f.bin', size, sha256: 'ab'.repeat(32), hashes: new Uint8Array(n * 32), now: NOW });
    car.inbound = [{ from: from.did, name: from.name, content: m }];
    await x.round();
    return E.list({ carrier: car, io }).in.find((r) => r.id === m.id);
  };
  E.setDirect({ carrier: car, io, contact: 'own', on: false });
  E.setAuto({ carrier: car, io, contact: 'own', mb: 100 });
  const r1 = await offer(OWN, 3_000_000);
  ok(r1.by === 'rule' && r1.state === 'failed' && r1.reason === 'no_path', `direct off, auto 100 MB, 3 MB: accepted by the rule, no question (${r1.state}${r1.reason ? `: ${r1.reason}` : ''})`);
  ok(car.sent.some((m) => m.content.typ === 'end' && m.content.id === r1.id && m.content.reason === 'no_path') && !car.sent.some((m) => m.content.typ === 'offer' && m.content.id === r1.id),
    'no direct and no Tor here: no_path to the sender at once (its relay lane takes it), no offer with addresses');
  const r12 = await offer(OWN, 12_000_000);
  ok(r12.state === 'asked' && !r12.by, `direct off, no Tor, 12 MB (over the relay lane's 8 MiB): asked, not accepted to fail no_path unseen (${r12.state})`);
  io.tor = { caps: async () => ({ serve: false, connect: false }), close() {} };
  const r13 = await offer(OWN, 13_000_000);
  ok(r13.by === 'rule', `direct off, Tor on here, 13 MB: accepted by the rule (Tor may carry it) (${r13.state})`);
  io.tor = null;
  const r2 = await offer(OWN, 101_000_000);
  ok(r2.state === 'asked' && !r2.by, 'the size cap kept: 101 MB over 100 MB is asked');
  E.setAuto({ carrier: car, io, contact: 'own', mb: 0 });
  ok((await offer(OWN, 10)).state === 'asked', 'auto 0 for the contact: always asked, direct off or not');
  E.setAuto({ carrier: car, io, contact: 'own', mb: null });
  const r3 = await offer(PAL, 1000);
  ok(r3.by === 'rule' && E.list({ carrier: car, io }).direct[PAL.did] === undefined, 'a compared friend, direct never asked: accepted by the rule, the switch left unset (no address shown)');
  E.setAuto({ carrier: car, io, contact: 'new', mb: 100 });
  ok((await offer(NEW, 10)).state === 'asked', 'words not compared: asked, whatever its size');
  // Direct on: the rule's yes is followed by an offer (the direct lane), as before.
  E.setDirect({ carrier: car, io, contact: 'own', on: true });
  const rtc = { peer: async () => ({ offer: async () => 'v=0 fake', close() {} }) };
  const y = new E.Engine({ carrier: car, io, rtc: async () => rtc, stun: [], timer: false });
  car.inbound = [{ from: OWN.did, name: 'own', content: manifest({ name: 'g.bin', size: 10, sha256: 'cd'.repeat(32), hashes: new Uint8Array(32), now: NOW }) }];
  await y.round();
  const r4 = E.list({ carrier: car, io }).in.find((r) => r.name === 'g.bin');
  ok(r4.by === 'rule' && r4.state === 'offering' && car.sent.some((m) => m.content.typ === 'offer' && m.content.id === r4.id), `direct on: the rule's yes, then an offer (${r4.state})`);
  // The rule's yeses add up: the disk must hold every file still coming, and at most 8 a contact (WAIT_CONTACT) come
  // unasked at once; past either, asked (a sender sending more than its 8, or many large ones, cannot fill the disk).
  const offerY = async (name, size) => {
    const n = Math.ceil(size / CHUNK), m = manifest({ name, size, sha256: createHash('sha256').update(name).digest('hex'), hashes: new Uint8Array(n * 32), now: NOW });
    car.inbound = [{ from: OWN.did, name: 'own', content: m }];
    await y.round();
    return E.list({ carrier: car, io }).in.find((r) => r.id === m.id);
  };
  const freeWas = io.free;
  io.free = () => E.FREE_MARGIN + 12_000_000;
  const d1 = await offerY('d1.bin', 5_000_000), d2 = await offerY('d2.bin', 5_000_000), d3 = await offerY('d3.bin', 5_000_000);
  ok(d1.by === 'rule' && d2.by === 'rule' && d3.state === 'asked' && !d3.by,
    `12 MB free, three 5 MB files: two by the rule, the third asked (10 MB promised + 5 > 12) (${[d1, d2, d3].map((r) => r.by ?? r.state)})`);
  io.free = freeWas;
  const many = [];
  for (let i = 0; i < 6; i++) many.push(await offerY(`m${i}.bin`, 10));
  const nRule = [r4, d1, d2, ...many].filter((r) => E.list({ carrier: car, io }).in.find((z) => z.id === r.id)?.by === 'rule').length;
  ok(nRule === 8 && many.at(-1).state === 'asked' && many.slice(0, -1).every((r) => r.by === 'rule'),
    `3 files from one contact already coming, 6 more: 5 by the rule (8 at once), the 6th asked (${many.map((r) => r.by ?? r.state)})`);
  for (const r of [r4, d1, d2, ...many]) y.drop(r.id, 'cancelled');
  await x.close(); await y.close();
}

// ================================================================ two agents on a loopback relay, a fake direct path
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) {
  report();
  console.log(`ALL PASS (${count}): the unit part; SKIP the flows (no relay checkout)`);
  process.exit(0);
}
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, pathsFor } = await import('./carrier.mjs');
const X = await import('./transfer-node.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 600 s (${count} checks so far)`); process.exit(1); }, 600_000).unref();

/** A fake direct path: two ends of a channel in this process; blocked: ICE never connects; dropAfter: frames, then it goes. */
const net = { blocked: false, dropAfter: Infinity, pairs: new Map(), n: 0 };
function pairOf() {
  const mk = () => ({ handlers: { frame: [], low: [], close: [] }, buffered: 0, closed: false });
  const a = mk(), b = mk();
  let shut = false, sent = 0;
  const close = () => { if (shut) return; shut = true; a.closed = b.closed = true; setImmediate(() => { for (const fn of [...a.handlers.close, ...b.handlers.close]) fn(); }); };
  const end = (me, other) => ({
    send(f) {
      if (me.closed) throw new Error('closed');
      if (++sent > net.dropAfter) { close(); return; }
      me.buffered += f.length;
      setImmediate(() => { me.buffered -= f.length; if (me.buffered < LOW) for (const fn of me.handlers.low) fn(); if (!other.closed) for (const fn of other.handlers.frame) fn(f); });
    },
    buffered: () => me.buffered, close, on(ev, fn) { me.handlers[ev].push(fn); },
  });
  return [end(a, b), end(b, a)];
}
const fakeRtc = {
  async peer() {
    let mine = null;
    const open = async () => { if (net.blocked || !mine) throw new Error('ICE failed: no path between these networks (blocked in this test)'); return mine; };
    return {
      async offer() { const k = ++net.n, p = pairOf(); net.pairs.set(k, p); mine = p[0]; return `fake ${k}`; },
      async answer(sdp) { mine = net.pairs.get(Number(sdp.split(' ')[1]))?.[1] ?? null; return 'fake answer'; },
      async accept() {}, open, close() {},
    };
  },
};

const HOST = 'relay.test', now = Date.parse('2026-11-19T12:00:00Z') / 1000;
const dir = mkdtempSync(join(tmpdir(), 'sigelo-relay-lane-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 4, loadBits: 8, loadPerHour: 1000, cost: { m: 8, t: 1, p: 1 } } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-relay-lane-test/0 ${l}`).digest());
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (f, ms = 60000) => { const t = Date.now() + ms; while (Date.now() < t) { if (await f()) return true; await sleep(100); } return false; };
function agentOf(label, onEvent) {
  const k = keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: '2026-10-01T00:00:00Z', nonce: seed(`${label} nonce`).slice(0, 16) });
  const identity = join(dir, `${label}.local.json`);
  const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
  return { did: k.did, identity, c: new Carrier({ identity: () => ({ secret: k.secret, bundle }), ...pathsFor(identity), relay: HOST, endpoints, clock: () => now, keep: true, backoff: [100, 400], retentionDays: 7, onEvent }) };
}
let A = null, B = null;
const aEv = [], bEv = [];
const alice = agentOf('alice', (e) => { if (e.type === 'transfer') A?.kick(); });
const bob = agentOf('bob', (e) => { if (e.type === 'transfer') B?.kick(); });
const engineOf = (x, ev, o = {}) => new X.Engine({ carrier: x.c, identity: x.identity, rtc: async () => fakeRtc, stun: [], tor: null, retryMs: 300, fallbackMs: 1000, onEvent: (e) => ev.push(e), ...o });
try {
  const inv = await alice.c.invite({ name: 'bob' });
  await bob.c.accept(inv.code, { name: 'alice', wait: 0.3 });
  await alice.c.inbox(); await bob.c.inbox(); await alice.c.inbox();
  alice.c.setTier('bob', 'own'); bob.c.setTier('alice', 'own');
  await alice.c.start(); await bob.c.start();
  A = engineOf(alice, aEv); B = engineOf(bob, bEv);
  const aRec = (id) => X.list({ carrier: alice.c, identity: alice.identity }).out.find((r) => r.id === id);
  const bRec = (id) => X.list({ carrier: bob.c, identity: bob.identity }).in.find((r) => r.id === id);
  const bFiles = [];
  const bFile = async (sum) => { bFiles.push(...(await bob.c.inbox({ wait: 0.3 })).messages.filter((m) => m.type === 'file')); return bFiles.find((m) => m.sha256 === sum); };

  // 1. The direct path blocked (two phones, no path, no Tor): the 1 MB APK lands over the relay lane.
  net.blocked = true;
  const apk = seeded('apk', 1_000_000 + 3); writeFileSync(join(dir, 'sigelo.apk'), apk);
  const r1 = await X.send({ carrier: alice.c, identity: alice.identity, to: 'bob', path: join(dir, 'sigelo.apk') });
  ok(await until(() => aRec(r1.id)?.state === 'done', 60000), 'blocked: the sender\'s record done', JSON.stringify(aRec(r1.id)));
  ok(aRec(r1.id).path_used === 'relay' && aEv.some((e) => e.what === 'done' && e.id === r1.id && e.via === 'relay'), 'the sender\'s record and event name the lane: via relay');
  let item = null;
  ok(await until(async () => (item = await bFile(sha(apk))) !== undefined, 60000), 'the receiver has the file, over sigelo-file/0');
  ok(item?.label === FILE_LABEL && !item.transfer && sha(readFileSync(item.path)) === sha(apk), 'whole, its own inbox item (no transfer id: the relay lane)');
  ok(await until(() => bRec(r1.id)?.state === 'relayed'), 'the receiver\'s transfer record: relayed, not active', JSON.stringify(bRec(r1.id)));
  B.superseded(item);
  ok(bRec(r1.id).state === 'done' && bRec(r1.id).path_used === 'relay' && bRec(r1.id).saved === item.path && !B.live(), 'and done by the file that came (a page does it as the item arrives): no ghost, nothing live');

  // 2. Direct, then the channel drops midway and nothing comes back within the window: over the relay lane too.
  net.blocked = false; net.dropAfter = 20;
  await B.close(); B = engineOf(bob, bEv, { retryMs: 1e9 });   // the receiver does not come back (a lock, the app gone)
  const film = seeded('film', 3 * CHUNK + 9); writeFileSync(join(dir, 'film.bin'), film);
  const r2 = await X.send({ carrier: alice.c, identity: alice.identity, to: 'bob', path: join(dir, 'film.bin') });
  ok(await until(() => aEv.some((e) => e.what === 'interrupted' && e.id === r2.id), 60000), 'the channel dropped midway (after 20 frames)');
  ok(await until(() => aRec(r2.id)?.state === 'done', 30000) && aRec(r2.id).path_used === 'relay', 'no reconnection within the window: done over the relay lane', JSON.stringify(aRec(r2.id)));
  ok(await until(async () => (await bFile(sha(film))) !== undefined, 60000), 'the receiver has the file whole');
  ok(await until(() => bRec(r2.id)?.state === 'relayed'), 'and its record is relayed, not "active: drop"', JSON.stringify(bRec(r2.id)));

  // 3. 8 MiB + 1 byte, blocked: no fallback; the relay lane refuses it.
  net.blocked = true; net.dropAfter = Infinity;
  await B.close(); B = engineOf(bob, bEv);
  const big = seeded('big', MAX_FILE + 1); writeFileSync(join(dir, 'big.bin'), big);
  const r3 = await X.send({ carrier: alice.c, identity: alice.identity, to: 'bob', path: join(dir, 'big.bin') });
  ok(await until(() => aRec(r3.id)?.state === 'failed', 60000) && aRec(r3.id).reason === 'no_path', 'blocked, 8 MiB + 1 byte: failed no_path', JSON.stringify(aRec(r3.id)));
  await sleep(1500);
  ok(aRec(r3.id).state === 'failed' && !aRec(r3.id).relay && !aRec(r3.id).path_used, 'not fallen back to the relay lane');
  ok(await failure(() => A.relay(r3.id, { manual: true })) === 'file_too_large', 'Send over the relay is refused past 8 MiB (the bubble offers Retry)');

  // 4. Direct off at the receiver (2026-11-25), its rule "transfer auto alice 100": no question, over the relay lane.
  net.blocked = false;
  X.setDirect({ carrier: bob.c, identity: bob.identity, contact: 'alice', on: false });
  X.setAuto({ carrier: bob.c, identity: bob.identity, contact: 'alice', mb: 100 });
  const pdf = seeded('pdf', 2 * CHUNK + 5); writeFileSync(join(dir, 'notes.pdf'), pdf);
  const r4 = await X.send({ carrier: alice.c, identity: alice.identity, to: 'bob', path: join(dir, 'notes.pdf') });
  ok(await until(() => aRec(r4.id)?.state === 'done', 60000) && aRec(r4.id).path_used === 'relay', 'direct off, auto 100 MB: done over the relay lane', JSON.stringify(aRec(r4.id)));
  ok(await until(async () => (await bFile(sha(pdf))) !== undefined, 60000), 'the receiver has it whole, no accept given');
  ok(bRec(r4.id)?.by === 'rule' && !bEv.some((e) => e.what === 'asked' && e.id === r4.id), 'accepted by the rule: never asked', JSON.stringify(bRec(r4.id)));
} finally {
  await A?.close().catch(() => {}); await B?.close().catch(() => {});
  await alice.c.stop().catch(() => {}); await bob.c.stop().catch(() => {});
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
report();
console.log(`ALL PASS (${count})`);
