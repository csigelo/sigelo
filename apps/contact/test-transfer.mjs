// SPDX-License-Identifier: MIT
// Transfers (transfer.mjs, transfer-node.mjs, sigelo-transfer; design/transfer.md): the messages and
// frames; the chunk protocol over a fake channel (a whole file, a drop and the resume, a chunk altered
// once and always, the list altered, the 16 GiB cap, back-pressure); the path order; then with the
// relay checkout beside apps/contact/ (SIGELO_RELAY_DIR, else ../../relay) two agents on a loopback relay:
// consent (nothing written before yes; decline; busy past the caps), the direct switch, a 50 MB file
// over werift (MB/s printed), a drop and a resume, file_changed; and the Tor path against a fake tor
// (a control port that answers PROTOCOLINFO, AUTHENTICATE, ADD_ONION, ONION_CLIENT_AUTH_ADD and
// DEL_ONION, and a SOCKS5 port that connects the onion to the service's local port), or the real one
// when SIGELO_TEST_TOR names its control port. SIGELO_TEST_MB: the size of the direct file (default 50).
//   node apps/contact/test-transfer.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  CHUNK, DATA_MAX, FRAME, HIGH, LOW, MAX_SIZE, OUTSTANDING, REASONS, T, TRANSFER_LABEL, Have, Pull, Serve, channelLabel, checkMessage, chunkLength, chunksOf,
  deframer, enframe, frames, listOf, manifest, newId, pathOrder, readFrame, torRoles,
} from './transfer.mjs';

let count = 0;
const fails = [];
const ok = (cond, what, more) => { count++; if (!cond) fails.push(more === undefined ? what : `${what} (${String(more).slice(0, 600)})`); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};
export const seeded = (seed, n) => {
  const out = Buffer.alloc(n);
  for (let i = 0, off = 0; off < n; i++, off += 32) createHash('sha256').update(`${seed}\n${i}`).digest().copy(out, off, 0, Math.min(32, n - off));
  return new Uint8Array(out.buffer, out.byteOffset, n);
};
const hashesOf = (bytes) => {
  const n = chunksOf(bytes.length), out = new Uint8Array(n * 32);
  for (let i = 0; i < n; i++) out.set(sha256(bytes.subarray(i * CHUNK, (i + 1) * CHUNK)), i * 32);
  return out;
};
const HERE = dirname(fileURLToPath(import.meta.url));
const NOW = Date.parse('2026-11-03T12:00:00Z') / 1000;

// ================================================================ the messages and the frames
{
  ok(TRANSFER_LABEL === 'sigelo-transfer/0' && CHUNK === 1048576 && FRAME === 65536 && OUTSTANDING === 8 && MAX_SIZE === 16 * 2 ** 30, 'label sigelo-transfer/0, 1 MiB chunks, 64 KiB frames, 8 outstanding, 16 GiB');
  const bytes = seeded('m', 3 * CHUNK + 5), hashes = hashesOf(bytes);
  const m = manifest({ id: 'ab'.repeat(16), name: 'film.mkv', size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), hashes, now: NOW });
  ok(m.chunks === 4 && m.chunk === CHUNK && m.list === listOf(hashes) && m.exp === NOW + 7 * 86400 && checkOf(() => checkMessage(m)) === 'accepted', 'manifest: 4 chunks, the list, 7 days; checkMessage accepts it');
  ok(JSON.stringify(m).length < 1024, `a manifest is under 1 KiB (${JSON.stringify(m).length})`);
  ok(checkOf(() => manifest({ name: 'x', size: MAX_SIZE + 1, sha256: 'a', hashes: new Uint8Array(0), now: NOW })) === 'transfer_too_large', 'manifest of 16 GiB + 1: transfer_too_large');
  ok(checkOf(() => checkMessage({ ...m, size: MAX_SIZE + 1, chunks: chunksOf(MAX_SIZE + 1) })) === 'transfer_too_large', 'a received manifest past 16 GiB: transfer_too_large');
  const big = { ...m, size: MAX_SIZE, chunks: MAX_SIZE / CHUNK };
  ok(checkOf(() => checkMessage(big)) === 'accepted', 'a manifest of exactly 16 GiB (16,384 chunks): accepted');
  const id = 'cd'.repeat(16), tor = { serve: false, connect: true };
  const offer = { typ: 'offer', id, attempt: 1, sdp: 'v=0\r\n', tor }, answer = { typ: 'answer', id, attempt: 1, sdp: null, tor };
  const onion = { typ: 'onion', id, attempt: 2, onion: 'a'.repeat(56), port: 4242, auth: 'A'.repeat(43) + '=', token: 'ef'.repeat(32) };
  for (const x of [offer, { ...offer, via: 'tor', sdp: null }, answer, onion, { ...onion, auth: null }, { typ: 'end', id, reason: 'try_tor', attempt: 1 }, { typ: 'end', id, reason: 'busy' }]) ok(checkOf(() => checkMessage(x)) === 'accepted', `checkMessage: a well-formed ${x.typ}`);
  const bad = [
    [{ ...m, typ: 'hello' }, 'an unknown typ'], [{ ...m, id: 'AB'.repeat(16) }, 'an id in capitals'], [{ ...m, extra: 1 }, 'an extra key'], [{ ...m, chunk: 65536 }, 'chunk 64 KiB'],
    [{ ...m, chunks: 3 }, 'chunks not the size\'s'], [{ ...m, name: '' }, 'an empty name'], [{ ...m, name: 'n'.repeat(1025) }, 'a name past 1024'], [{ ...m, sha256: 'x' }, 'sha256 not hex'],
    [{ ...offer, attempt: 0 }, 'attempt 0'], [{ ...offer, sdp: 's'.repeat(16385) }, 'an sdp past 16 KiB'], [{ ...offer, tor: { serve: 1, connect: true } }, 'tor.serve not a boolean'],
    [{ ...offer, via: 'turn' }, 'via turn'], [{ ...answer, via: 'tor' }, 'via on an answer'], [{ ...onion, onion: 'a'.repeat(56) + '.onion' }, 'an onion with .onion'], [{ ...onion, port: 0 }, 'port 0'],
    [{ ...onion, token: 'ef' }, 'a short token'], [{ typ: 'end', id, reason: 'bored' }, 'reason bored'], [(({ tor: _t, ...x }) => x)(offer), 'an offer without tor'],
  ];
  for (const [x, what] of bad) ok(checkOf(() => checkMessage(x)) === 'transfer_message', `checkMessage, ${what}: transfer_message`, checkOf(() => checkMessage(x)));
  ok(channelLabel(id, 3) === `sigelo-transfer/0 ${id} 3` && /^[0-9a-f]{32}$/.test(newId()), 'channel label names id and attempt; ids are 32 hex');

  // Frames round trip, and their shapes refused.
  const d = readFrame(frames.data(7, 65527, new Uint8Array([1, 2, 3])));
  ok(d.type === T.DATA && d.index === 7 && d.offset === 65527 && d.bytes.length === 3, 'DATA round trip');
  const w = readFrame(frames.want(4000000000, 8));
  ok(w.type === T.WANT && w.from === 4000000000 && w.n === 8, 'WANT round trip (u32 from)');
  ok(readFrame(frames.end('file_changed')).reason === 'file_changed' && REASONS.every((r) => readFrame(frames.end(r)).reason === r), 'END round trip for every reason');
  ok(readFrame(frames.list(5, new Uint8Array(64))).first === 5 && readFrame(frames.token(new Uint8Array(32))).type === T.TOKEN, 'LIST and TOKEN round trip');
  for (const [f, what] of [[new Uint8Array([9, 0]), 'type 9'], [new Uint8Array([T.WANT, 0, 0]), 'a short WANT'], [new Uint8Array(FRAME + 1), 'past 64 KiB'], [new Uint8Array([T.END, 99]), 'an END reason past the list'], [new Uint8Array([T.LIST, 0, 0, 0, 0, 1]), 'a LIST of part of a hash']]) {
    ok(checkOf(() => readFrame(f)) === 'transfer_frame', `readFrame, ${what}: transfer_frame`);
  }
  ok(frames.data(0, 0, new Uint8Array(DATA_MAX)).length === FRAME && Math.ceil(CHUNK / DATA_MAX) === 17, 'a full DATA frame is 64 KiB; a chunk goes in 17');
  const df = deframer(), parts = [enframe(frames.want(1, 2)), enframe(frames.end('done'))], all = new Uint8Array([...parts[0], ...parts[1]]);
  const got = [...df(all.subarray(0, 5)), ...df(all.subarray(5, 12)), ...df(all.subarray(12))];
  ok(got.length === 2 && readFrame(got[0]).n === 2 && readFrame(got[1]).reason === 'done', 'stream frames: split anywhere, read whole');
  ok(checkOf(() => deframer()(new Uint8Array([0, 1, 0, 1]))) === 'transfer_frame', 'a stream frame length past 64 KiB: transfer_frame');

  // The bitmap.
  const h = new Have(10);
  h.set(0); h.set(9);
  ok(h.has(0) && h.has(9) && !h.has(5) && h.count() === 2 && !h.done() && new Have(10, h.bits).count() === 2 && h.bits.length === 2, 'Have: a bit a chunk, kept as bytes');
  ok(checkOf(() => new Have(10, new Uint8Array(3))) === 'transfer_have', 'Have of the wrong length: transfer_have');
  ok(chunkLength(3 * CHUNK + 5, 3) === 5 && chunkLength(3 * CHUNK + 5, 2) === CHUNK, 'chunkLength: the last chunk is the rest');

  // The path order (design §2, §9).
  ok(JSON.stringify(pathOrder({ direct: true, tor: true })) === '["direct","tor"]', 'free: direct, then Tor');
  ok(JSON.stringify(pathOrder({ direct: false, tor: true })) === '["tor"]' && JSON.stringify(pathOrder({ direct: true, tor: false })) === '["direct"]' && pathOrder({ direct: false, tor: false }).length === 0, 'free: what is allowed only; nothing: refused');
  ok(JSON.stringify(pathOrder({ pro: true, prefer: 'fast', direct: true, tor: true })) === '["direct","tor"]', 'Pro fast without TURN yet: direct, then Tor (TURN is T4)');
  ok(JSON.stringify(pathOrder({ pro: true, prefer: 'fast', direct: true, tor: true, turn: true })) === '["direct","turn","tor"]', 'Pro fast with TURN: direct, TURN, Tor');
  ok(JSON.stringify(pathOrder({ pro: true, prefer: 'private', direct: true, tor: true })) === '["tor","direct"]', 'Pro private: Tor first');
  ok(JSON.stringify(pathOrder({ via: 'tor', direct: true, tor: true })) === '["tor"]' && pathOrder({ via: 'tor', direct: true, tor: false }).length === 0, '--via tor: Tor only, never direct');
  ok(torRoles({ serve: true, connect: true }, { serve: true, connect: true }) === 'sender' && torRoles({ serve: false, connect: true }, { serve: true, connect: true }) === 'receiver'
    && torRoles({ serve: false, connect: true }, { serve: false, connect: true }) === null, 'Tor: the sender serves if it can, else the receiver; two connect-only sides: none');
}

// ================================================================ the chunk protocol over a fake channel

/** Two ends of a fake channel: frames arrive in order, asynchronously; buffered counts what the other side has not read. */
export function fakePair({ dropAfter = Infinity, alter = () => null } = {}) {
  const mk = () => ({ handlers: { frame: [], low: [], close: [] }, buffered: 0, closed: false, sent: 0 });
  const a = mk(), b = mk();
  const end = (me, other) => ({
    send(f) {
      if (me.closed) throw new Error('closed');
      me.sent++;
      if (me.sent + other.sent > dropAfter) { close(); return; }
      const g = alter(f, me === a ? 'a' : 'b') ?? f;
      me.buffered += g.length;
      setImmediate(() => {
        me.buffered -= g.length;
        if (me.buffered < LOW) for (const fn of me.handlers.low) fn();
        if (!other.closed) for (const fn of other.handlers.frame) fn(g);
      });
    },
    buffered: () => me.buffered,
    close,
    on(e, fn) { me.handlers[e].push(fn); },
  });
  let shut = false;
  function close() { if (shut) return; shut = true; a.closed = b.closed = true; setImmediate(() => { for (const fn of [...a.handlers.close, ...b.handlers.close]) fn(); }); }
  return [end(a, b), end(b, a), { a, b }];
}
/** One attempt: the sender serving bytes, the receiver pulling into disk (a Map). → { reason, disk, have, hashes, maxOut }. */
export function attempt(bytes, m, hashes, { have, known = null, drop, alter, readHook, disk = new Map() } = {}) {
  return new Promise((resolve) => {
    const [ca, cb, raw] = fakePair({ dropAfter: drop, alter });
    let ends = 0, result = {}, maxBuf = 0, out = 0, maxOut = 0;
    const done = () => { if (++ends === 2) resolve({ ...result, disk, have, maxBuf, maxOut }); };
    const serve = new Serve({ m, hashes, channel: ca, read: async (i) => { await readHook?.(i); maxBuf = Math.max(maxBuf, raw.a.buffered); return bytes.subarray(i * CHUNK, (i + 1) * CHUNK); }, onEnd: (r, o) => { result.sender = r; result.senderRemote = o.remote; done(); } });
    const pull = new Pull({
      m, have, hashes: known, channel: cb,
      write: async (i, b) => { disk.set(i, b); out--; },
      flush: async () => {},
      onList: (h) => { result.hashes = h; },
      onEnd: (r) => {
        result.receiver = r;
        if (r === 'complete') {
          const whole = Buffer.concat([...Array(m.chunks).keys()].map((i) => disk.get(i)));
          const good = createHash('sha256').update(whole).digest('hex') === m.sha256;
          result.receiver = good ? 'done' : 'chunk_hash';
          pull.finish(result.receiver);
        }
        done();
      },
    });
    // Outstanding: asked and not yet written.
    const send = cb.send.bind(cb);
    cb.send = (f) => { if (f[0] === T.WANT) { out += readFrame(f).n; maxOut = Math.max(maxOut, out); } send(f); };
    serve.start(); pull.start();
  });
}
{
  const bytes = seeded('fake', 20 * CHUNK + 777), hashes = hashesOf(bytes);
  const m = manifest({ name: 'f.bin', size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), hashes, now: NOW });
  const r1 = await attempt(bytes, m, hashes, { have: new Have(m.chunks) });
  ok(r1.receiver === 'done' && r1.sender === 'done' && r1.senderRemote && r1.have.done() && r1.disk.size === m.chunks, 'a whole file: every chunk checked and written, done on both sides', JSON.stringify({ r: r1.receiver, s: r1.sender }));
  ok(r1.maxOut <= OUTSTANDING, `at most ${OUTSTANDING} chunks outstanding (${r1.maxOut})`);
  ok(r1.maxBuf <= HIGH + CHUNK + 17 * 9, `the sender stops above 4 MiB buffered (${r1.maxBuf})`);

  // A drop midway, then the resume: a new attempt asks only for what the bitmap lacks.
  const r2 = await attempt(bytes, m, hashes, { have: new Have(m.chunks), drop: 200 });
  const had = r2.have.count();
  ok(r2.receiver === 'cancelled' && had > 0 && had < m.chunks, `a drop: cancelled, ${had} of ${m.chunks} chunks kept`, r2.receiver);
  const asked = [];
  const r3 = await attempt(bytes, m, hashes, { have: r2.have, known: r2.hashes, disk: new Map(r2.disk), readHook: (i) => asked.push(i) });
  ok(r3.receiver === 'done' && r3.have.done() && asked.length === m.chunks - had, `the resume: only the ${m.chunks - had} missing chunks asked, done`, `${asked.length} asked`);
  const keptBefore = [...Array(m.chunks).keys()].filter((i) => r2.disk.has(i));
  ok(keptBefore.every((i) => !asked.includes(i)), 'the resume never asks for a chunk the bitmap holds');

  // A chunk altered once in transit: asked again, done. Always: chunk_hash.
  let altered = 0;
  const once = (f) => { if (f[0] === T.DATA && readFrame(f).index === 3 && readFrame(f).offset === 0 && altered++ === 0) { const g = f.slice(); g[20] ^= 1; return g; } return null; };
  const r4 = await attempt(bytes, m, hashes, { have: new Have(m.chunks), alter: once });
  ok(r4.receiver === 'done' && altered === 2, 'a chunk altered once: asked again, then done', `${r4.receiver}, ${altered}`);
  const always = (f) => { if (f[0] === T.DATA && readFrame(f).index === 5 && readFrame(f).offset === 0) { const g = f.slice(); g[20] ^= 1; return g; } return null; };
  const r5 = await attempt(bytes, m, hashes, { have: new Have(m.chunks), alter: always });
  ok(r5.receiver === 'chunk_hash' && r5.sender === 'chunk_hash' && !r5.disk.has(5), 'a chunk altered every time: chunk_hash on both sides, never written', `${r5.receiver}/${r5.sender}`);
  // The list altered: chunk_hash before any chunk is asked.
  const list = (f) => { if (f[0] === T.LIST) { const g = f.slice(); g[10] ^= 1; return g; } return null; };
  const r6 = await attempt(bytes, m, hashes, { have: new Have(m.chunks), alter: list });
  ok(r6.receiver === 'chunk_hash' && r6.disk.size === 0, 'the list altered: chunk_hash, nothing written');
  // The file changed under the sender: file_changed.
  const r7 = await attempt(bytes, m, hashes, { have: new Have(m.chunks), readHook: (i) => { if (i === 4) throw Object.assign(new Error('moved'), { check: 'file_changed' }); } });
  ok(r7.sender === 'file_changed' && r7.receiver === 'file_changed', 'the file changed at the sender: file_changed on both sides', `${r7.sender}/${r7.receiver}`);
  // An empty file, and one of one byte.
  for (const n of [0, 1]) {
    const b = seeded('tiny', n), hs = hashesOf(b), mm = manifest({ name: 'e', size: n, sha256: createHash('sha256').update(b).digest('hex'), hashes: hs, now: NOW });
    const r = await attempt(b, mm, hs, { have: new Have(mm.chunks) });
    ok(r.receiver === 'done', `a file of ${n} bytes: done`, r.receiver);
  }
  // A receiver that asks past the file, or more than 8 at once: the sender stops (cancelled).
  const [ca, cb] = fakePair();
  const ended = new Promise((res) => new Serve({ m, hashes, channel: ca, read: async () => new Uint8Array(1), onEnd: (r) => res(r) }).start());
  cb.send(frames.want(m.chunks - 1, 2));
  ok(await ended === 'cancelled', 'a WANT past the file: the sender ends it');
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs')) || !existsSync(join(RELAY_DIR, 'node_modules'))) {
  report();
  console.log(`ALL PASS (${count}): the unit part; SKIP the flows, no relay checkout with its dependencies beside apps/contact/: set SIGELO_RELAY_DIR`);
  process.exit(0);
}

// The direct path needs sigelo-transfer installed beside apps/contact/ (npm ci in apps/transfer/).
if (!existsSync(join(HERE, '..', 'transfer', 'node_modules', 'werift'))) {
  report();
  console.log(`ALL PASS (${count}): the unit part; SKIP the flows, sigelo-transfer has no node_modules: npm ci in apps/transfer/`);
  process.exit(0);
}

// ================================================================ two agents on a loopback relay
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, pathsFor } = await import('./carrier.mjs');
const X = await import('./transfer-node.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 1500 s (${count} checks so far)`); process.exit(1); }, 1_500_000).unref();

const HOST = 'relay.test', now = NOW;
const dir = mkdtempSync(join(tmpdir(), 'sigelo-transfer-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-transfer-test/0 ${l}`).digest());
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (f, ms = 60000) => { const t = Date.now() + ms; while (Date.now() < t) { if (await f()) return true; await sleep(100); } return false; };
const failure = async (f) => { try { await f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.message}`; } };
function agent(label, { tor = null, rtc } = {}) {
  const k = keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: '2026-10-01T00:00:00Z', nonce: seed(`${label} nonce`).slice(0, 16) });
  const a = { label, did: k.did, identity: join(dir, `${label}.local.json`), events: [] };
  const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
  a.c = new Carrier({ identity: () => ({ secret: k.secret, bundle }), ...pathsFor(a.identity), relay: HOST, endpoints, clock: () => now, keep: true, backoff: [100, 400], retentionDays: 7,
    onEvent: (e) => { if (e.type === 'transfer') a.e?.kick(); } });
  a.newEngine = (o = {}) => { a.e = new X.Engine({ carrier: a.c, identity: a.identity, stun: [], tor, retryMs: 300, torConnectMs: 20000, onEvent: (e) => a.events.push(e), ...(rtc && { rtc }), ...o }); return a.e; };
  a.newEngine();
  a.rec = (side, id) => X.list({ carrier: a.c, identity: a.identity })[side].find((r) => r.id === id);
  return a;
}
const A = agent('alice'), B = agent('bob');
try {
  const inv = await A.c.invite({ name: 'bob' });
  await B.c.accept(inv.code, { name: 'alice', wait: 0.3 });
  await A.c.inbox(); await B.c.inbox(); await A.c.inbox();
  await A.c.start(); await B.c.start();
  const file = (name, bytes) => { const f = join(dir, name); writeFileSync(f, bytes); return f; };
  const send = (path, o = {}) => X.send({ carrier: A.c, identity: A.identity, to: 'bob', path, ...o });

  // The direct switch: friend contacts are asked once; own ones are on.
  ok(await failure(() => send(file('small.bin', seeded('s', 1000)))) === 'direct_ask', 'send to a friend contact, the direct switch not set: direct_ask');
  ok(X.list({ carrier: A.c, identity: A.identity }).out.length === 0, 'and nothing was sent');
  A.c.setTier('bob', 'own'); B.c.setTier('alice', 'own');
  ok(X.directFor({ direct: {} }, { tier: 'own' }) === true && X.directFor({ direct: {} }, { tier: 'friend' }) === null && X.directFor({ direct: { d: false } }, { did: 'd', tier: 'own' }) === false, 'directFor: own on, others asked (null), a kept choice wins');

  // Consent: a manifest is a question; nothing is written before the yes; decline tells the sender.
  const r1 = await send(file('small.bin', seeded('s', 1000)));
  ok(await until(() => B.rec('in', r1.id)?.state === 'asked'), 'the manifest reaches bob: asked');
  ok(!existsSync(join(B.c.filesDir, '.transfer', `${r1.id}.part`)), 'nothing is written before the yes');
  ok(B.events.some((e) => e.what === 'asked' && e.id === r1.id && e.name === 'small.bin' && e.size === 1000), 'an asked event: name and size, for the page, watch and MCP');
  const hist = B.c.history({ since: 0 }).messages;
  ok(!hist.some((m) => m.label === TRANSFER_LABEL) && !(await B.c.inbox()).messages.some((m) => m.label === TRANSFER_LABEL), 'transfer messages never reach inbox() nor the log');
  await X.decline({ carrier: B.c, identity: B.identity, id: r1.id });
  ok(await until(() => A.rec('out', r1.id)?.state === 'declined'), 'decline: the sender\'s record says declined');

  // Busy: past 8 waiting from one contact, the next gets busy.
  const many = [];
  for (let i = 0; i < 9; i++) many.push(await send(file(`m${i}.bin`, seeded(`m${i}`, 10))));
  ok(await until(() => A.rec('out', many[8].id)?.state === 'failed' && A.rec('out', many[8].id)?.reason === 'busy'), 'a ninth manifest waiting from one contact: busy', JSON.stringify(A.rec('out', many[8].id)));
  for (const r of many.slice(0, 8)) await X.decline({ carrier: B.c, identity: B.identity, id: r.id });

  // A 50 MB file, direct over werift: done, saved as send-file saves, one inbox item, MB/s.
  const MB = Number(process.env.SIGELO_TEST_MB ?? 50), big = seeded('big', MB * 1000 * 1000), bigPath = file('big.bin', big);
  const want = createHash('sha256').update(big).digest('hex');
  const r2 = await send(bigPath);
  ok(await until(() => B.rec('in', r2.id)?.state === 'asked'), `the ${MB} MB manifest: asked`);
  X.accept({ carrier: B.c, identity: B.identity, id: r2.id }); B.e.kick();
  ok(await until(() => B.rec('in', r2.id)?.state === 'done', 900000), `${MB} MB direct: done`, JSON.stringify(B.rec('in', r2.id)));
  // From the channel open to the file read back and placed.
  const at = (w) => B.events.find((e) => e.id === r2.id && e.what === w)?.at_ms;
  await until(() => at('done') !== undefined);
  const secs = (at('done') - at('active')) / 1000, rate = (MB / secs).toFixed(2);
  console.log(`direct over werift, both agents in this process: ${MB} MB in ${secs.toFixed(1)} s = ${rate} MB/s`);
  const doneIn = B.rec('in', r2.id);
  ok(doneIn.path_used === 'direct' && existsSync(doneIn.saved) && createHash('sha256').update(readFileSync(doneIn.saved)).digest('hex') === want && (statSync(doneIn.saved).mode & 0o777) === 0o600, 'saved whole, 0600, the SHA-256 of the file sent');
  ok(doneIn.saved.startsWith(join(B.c.filesDir, '')) && basename(doneIn.saved) === `${want.slice(0, 8)}-big.bin`, 'placed as send-file places one: <files>/<contact>-<hex>/<sha8>-<name>');
  ok(await until(() => A.rec('out', r2.id)?.state === 'done'), 'the sender: done');
  const box = (await B.c.inbox()).messages.filter((m) => m.type === 'file' && m.transfer === r2.id);
  ok(box.length === 1 && box[0].path === doneIn.saved && box[0].size === big.length, 'one inbox item {type: "file", transfer}');
  ok(readdirSync(join(B.c.filesDir, '.transfer')).filter((n) => n.startsWith(r2.id)).length === 0, 'no partials left');

  // A drop midway: interrupted, resumed by a new offer, only the rest asked; done.
  const mid = seeded('mid', 24 * CHUNK + 3), r3 = await send(file('mid.bin', mid));
  await until(() => B.rec('in', r3.id)?.state === 'asked');
  X.accept({ carrier: B.c, identity: B.identity, id: r3.id }); B.e.kick();
  ok(await until(() => (B.e.progress(r3.id)?.got ?? 0) >= 4 * CHUNK, 300000), 'the second transfer is under way');
  B.e.attempts.get(r3.id)?.channel?.close();
  ok(await until(() => B.rec('in', r3.id)?.state === 'done', 300000), 'cut midway: resumed and done', JSON.stringify(B.rec('in', r3.id)));
  ok(B.rec('in', r3.id).attempt >= 2 && B.events.some((e) => e.what === 'interrupted' && e.id === r3.id), `the resume was a new attempt (${B.rec('in', r3.id).attempt})`);
  ok(createHash('sha256').update(readFileSync(B.rec('in', r3.id).saved)).digest('hex') === createHash('sha256').update(mid).digest('hex'), 'the resumed file is whole');

  // The file changed after it was offered: file_changed on both sides.
  const chPath = file('ch.bin', seeded('ch', 3000)), r4 = await send(chPath);
  await until(() => B.rec('in', r4.id)?.state === 'asked');
  writeFileSync(chPath, seeded('ch2', 3001));
  X.accept({ carrier: B.c, identity: B.identity, id: r4.id }); B.e.kick();
  ok(await until(() => A.rec('out', r4.id)?.reason === 'file_changed' && B.rec('in', r4.id)?.reason === 'file_changed'), 'changed after the offer: file_changed on both sides', JSON.stringify([A.rec('out', r4.id), B.rec('in', r4.id)]));

  // Cancel by the sender while waiting: the receiver's record says cancelled.
  const r5 = await send(file('c.bin', seeded('c', 10)));
  await until(() => B.rec('in', r5.id)?.state === 'asked');
  await X.cancel({ carrier: A.c, identity: A.identity, id: r5.id, engine: A.e });
  ok(await until(() => B.rec('in', r5.id)?.state === 'cancelled'), 'the sender cancels: cancelled at the receiver');
  ok(await failure(() => X.accept({ carrier: B.c, identity: B.identity, id: r5.id })) === 'transfer_state', 'a cancelled transfer cannot be accepted');

  // No path: direct off on the receiver, no Tor: no_path, the free refusal's words.
  X.setDirect({ carrier: B.c, identity: B.identity, contact: 'alice', on: false });
  X.settings({ identity: B.identity, patch: { tor: false } });
  const r6 = await send(file('np.bin', seeded('np', 10)));
  await until(() => B.rec('in', r6.id)?.state === 'asked');
  X.accept({ carrier: B.c, identity: B.identity, id: r6.id }); B.e.kick();
  ok(await until(() => B.rec('in', r6.id)?.reason === 'no_path' && A.rec('out', r6.id)?.reason === 'no_path'), 'direct off and no Tor: no_path on both sides');
  ok(/No direct path to alice .* and no Tor\. Up to 8 MiB: send-file/.test(B.rec('in', r6.id).detail ?? ''), 'the refusal names send-file', B.rec('in', r6.id).detail);
  X.settings({ identity: B.identity, patch: { tor: true } });

  // ============================================================ Tor, against a fake tor (or a real one: SIGELO_TEST_TOR)
  const fake = await fakeTor();
  for (const x of [A, B]) { await x.e.close(); x.newEngine({ tor: { control: ['127.0.0.1', fake.control], socks: ['127.0.0.1', fake.socks], password: null } }); }
  ok(JSON.stringify(await X.torCaps({ control: ['127.0.0.1', fake.control], socks: ['127.0.0.1', fake.socks], password: null })) === '{"serve":true,"connect":true}', 'torCaps: the fake tor serves and connects');
  ok(JSON.stringify(await X.torCaps({ control: ['127.0.0.1', 1], socks: ['127.0.0.1', 1], password: null })) === '{"serve":false,"connect":false}', 'torCaps: no daemon: off');
  const tf = seeded('tor', 5 * CHUNK + 9), r7 = await send(file('tor.bin', tf));
  await until(() => B.rec('in', r7.id)?.state === 'asked');
  X.accept({ carrier: B.c, identity: B.identity, id: r7.id }); B.e.kick();   // direct is off at bob: Tor
  ok(await until(() => B.rec('in', r7.id)?.state === 'done', 120000), 'direct off at the receiver: over Tor, done', JSON.stringify(B.rec('in', r7.id)));
  ok(B.rec('in', r7.id)?.path_used === 'tor' && createHash('sha256').update(readFileSync(B.rec('in', r7.id).saved)).digest('hex') === createHash('sha256').update(tf).digest('hex'), 'the file came over the onion stream, whole');
  ok(fake.log.some((l) => /^ADD_ONION NEW:ED25519-V3 Flags=DiscardPK,V3Auth Port=\d+,127\.0\.0\.1:\d+ ClientAuthV3=[A-Z2-7]{52}$/.test(l)), 'ADD_ONION: a fresh key discarded, client authorization', fake.log.join(' | '));
  ok(fake.log.some((l) => /^ONION_CLIENT_AUTH_ADD [a-z2-7]{56} x25519:/.test(l)) && fake.authOk > 0, 'the connector adds the client key, and it is the service\'s');
  ok(await until(() => fake.log.some((l) => l.startsWith('DEL_ONION '))), 'DEL_ONION when done');
  ok(fake.wrongToken === 0, 'the stream proved its token');
  // A stream without the token: closed, nothing served.
  fake.stranger = true;
  X.setDirect({ carrier: B.c, identity: B.identity, contact: 'alice', on: true });
  const r8 = await send(file('via.bin', seeded('via', 2 * CHUNK)), { via: 'tor' });
  await until(() => B.rec('in', r8.id)?.state === 'asked');
  X.accept({ carrier: B.c, identity: B.identity, id: r8.id }); B.e.kick();
  ok(await until(() => B.rec('in', r8.id)?.state === 'done', 120000), '--via tor with direct on: Tor all the same, done', JSON.stringify(B.rec('in', r8.id)));
  ok(B.rec('in', r8.id)?.path_used === 'tor', 'via tor: never direct');
  ok(fake.strangerClosed === true, 'a connection to the onion without the token is closed');
  // The real tor, when one runs here.
  if (process.env.SIGELO_TEST_TOR) console.log('SIGELO_TEST_TOR set: see the real-tor run in test-transfer-tor (not in this file)');
  await fake.close();
} finally {
  await A.e?.close().catch(() => {}); await B.e?.close().catch(() => {});
  await A.c.stop().catch(() => {}); await B.c.stop().catch(() => {});
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}

/**
 * A fake tor: a control port (PROTOCOLINFO with METHODS=NULL, AUTHENTICATE, ADD_ONION, DEL_ONION,
 * ONION_CLIENT_AUTH_ADD, ONION_CLIENT_AUTH_REMOVE) and a SOCKS5 port that connects <service>.onion:port to
 * the target ADD_ONION named, once the client key that matches the service's ClientAuthV3 was added.
 */
async function fakeTor() {
  const services = new Map(), auth = new Map(), log = [];
  const t = { log, authOk: 0, wrongToken: 0, stranger: false, strangerClosed: false };
  const control = net.createServer((s) => {
    let buf = '';
    s.on('error', () => {});
    s.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        log.push(line);
        const [cmd] = line.split(' ');
        if (cmd === 'PROTOCOLINFO') s.write('250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250-VERSION Tor="0.4.8.0"\r\n250 OK\r\n');
        else if (cmd === 'AUTHENTICATE') s.write('250 OK\r\n');
        else if (cmd === 'ADD_ONION') {
          const port = /Port=(\d+),127\.0\.0\.1:(\d+)/.exec(line), key = /ClientAuthV3=([A-Z2-7]+)/.exec(line)?.[1] ?? null;
          const id = createHash('sha256').update(line + Math.random()).digest('hex').replace(/[^a-z2-7]/g, '').padEnd(56, 'a').slice(0, 56).replace(/[0189]/g, 'q');
          services.set(id, { virt: Number(port[1]), local: Number(port[2]), key, at: Date.now() });
          s.write(`250-ServiceID=${id}\r\n250 OK\r\n`);
        } else if (cmd === 'DEL_ONION') { services.delete(line.split(' ')[1]); s.write('250 OK\r\n'); }
        else if (cmd === 'ONION_CLIENT_AUTH_ADD') { const [, id, k] = line.split(' '); auth.set(id, k.replace(/^x25519:/, '')); s.write('250 OK\r\n'); }
        else if (cmd === 'ONION_CLIENT_AUTH_REMOVE') { auth.delete(line.split(' ')[1]); s.write('250 OK\r\n'); }
        else if (cmd === 'QUIT') s.end('250 closing connection\r\n');
        else s.write('510 Unrecognized command\r\n');
      }
    });
  });
  const socks = net.createServer((s) => {
    s.on('error', () => {});
    let stage = 0, buf = Buffer.alloc(0);
    s.on('data', function on(d) {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 3) { buf = buf.subarray(3); stage = 1; s.write(Buffer.from([5, 0])); }
      if (stage === 1 && buf.length >= 5 && buf.length >= 5 + buf[4] + 2) {
        const host = buf.subarray(5, 5 + buf[4]).toString(), port = buf.readUInt16BE(5 + buf[4]), rest = buf.subarray(7 + buf[4]);
        const id = host.replace(/\.onion$/, ''), sv = services.get(id);
        // Published after a second, as a real onion takes its time; client auth checked.
        const okAuth = sv && (!sv.key || (auth.has(id) && X.clientPub(auth.get(id)) === sv.key));
        if (sv && okAuth) t.authOk++;
        if (!sv || sv.virt !== port || !okAuth || Date.now() - sv.at < 1000) { s.end(Buffer.from([5, 4, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
        s.off('data', on);
        const up = net.connect(sv.local, '127.0.0.1', () => {
          s.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
          if (rest.length) up.write(rest);
          s.pipe(up); up.pipe(s);
          if (t.stranger) {
            // A second connection to the same service without the token: it must be closed.
            t.stranger = false;
            const x = net.connect(sv.local, '127.0.0.1', () => { x.write(Buffer.from([0, 0, 0, 33, 5, ...new Uint8Array(32)])); });
            x.on('close', () => { t.strangerClosed = true; }); x.on('error', () => {});
          }
        });
        up.on('error', () => s.destroy());
        stage = 2;
      }
    });
  });
  await new Promise((r) => control.listen(0, '127.0.0.1', r));
  await new Promise((r) => socks.listen(0, '127.0.0.1', r));
  return Object.assign(t, { control: control.address().port, socks: socks.address().port, close: () => { control.close(); socks.close(); } });
}

report();
console.log(`ALL PASS (${count})`);
