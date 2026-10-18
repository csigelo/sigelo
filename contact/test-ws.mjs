// SPDX-License-Identifier: MIT
// The carrier (carrier.mjs) over MQTT over WebSocket, against a loopback relay (relay/server.mjs)
// whose only listener is its HTTP port: two agents pair, write and read with 8883 unreachable,
// with transport "wss" and with "auto" (the default), which falls back once, after the probe when
// 8883 is silent, and keeps to WebSocket for the rest of the process. Then, in a child process with only an HTTP CONNECT proxy to reach the relay
// (HTTPS_PROXY; the relay's name resolves nowhere, its certificate trusted by NODE_EXTRA_CA_CERTS),
// the same through a stand-in nginx with TLS, whose relay.json names the WebSocket endpoint. Also:
// endpointOf and proxyFor (NO_PROXY), SIGELO_RELAY_TRANSPORT, and a message refused because the
// reader's queue is full, told as the reader's side (quota_storage, side "reader").
//   node contact/test-ws.mjs   → ALL PASS (n)
// The relay is its own AGPL package: SIGELO_RELAY_DIR, else ../relay; without it, SKIP after the
// part that needs none.
import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { connect as netConnect, createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { Carrier, PROBE_MS, endpointOf, optionsFromEnv, pathsFor, proxyFor } from './carrier.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const HOST = 'relay.test', CREATED = '2026-10-01T00:00:00Z';
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-ws-test/0 ${l}`).digest());
function agent(label) {
  const recovery = keygen({ seed: seed(`${label} recovery`), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} rn`).slice(0, 16) }).key;
  const k = keygen({ seed: seed(label), recovery, created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, original: k.did, did: k.did, secret: k.secret, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
const make = (dir, a, extra = {}) => {
  const events = [];
  const c = new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, `${a.label}.local.json`)), relay: HOST,
    onEvent: (e) => events.push(e), keep: true, backoff: [100, 400], retentionDays: 7, ...extra });
  c.events = events;
  return c;
};
// Pair x and y by code, each reading in turn, then one message each way. → what each read.
async function pairAndTalk(x, y, tag) {
  const inv = await x.invite({ name: 'y' });
  const acc = await y.accept(inv.code, { name: 'x', wait: 0.3 });
  await x.inbox(); await y.inbox(); await x.inbox();
  const s1 = await x.send('y', `hello from x ${tag}`), s2 = await y.send('x', `hello from y ${tag}`);
  const ry = await y.inbox(), rx = await x.inbox();
  return { accepted: acc.status, sent: [s1.status, s2.status], gotY: ry.messages.map((m) => m.content), gotX: rx.messages.map((m) => m.content) };
}

// ================================================================ the child: behind a proxy only
if (process.argv[2] === '--child') {
  const [, , , dir] = process.argv;
  const out = {};
  try {
    const x = make(dir, agent('px'), optionsFromEnv()), y = make(dir, agent('py'), optionsFromEnv());
    Object.assign(out, await pairAndTalk(x, y, 'via proxy'));
    out.transport = [x, y].map((c) => c.events.find((e) => e.type === 'transport')?.transport ?? null);
    out.fellBack = x.events.find((e) => e.type === 'transport')?.detail ?? null;
  } catch (e) { out.error = `${e.check ?? e.name}: ${e.message}`; }
  console.log(JSON.stringify(out));
  process.exit(0);
}

let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const report = (skip = '') => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
  console.log(`ALL PASS (${count})${skip}`);
  process.exit(0);
};
setTimeout(() => { console.log(`FAIL the run did not finish in 240 s (${count} checks so far)`); process.exit(1); }, 240000).unref();
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? e.message; } };

// ================================================================ endpoints, proxies, the setting
{
  const d = endpointOf('relay.sigelo.ai');
  ok(d.mqtt === 'mqtts://relay.sigelo.ai:8883' && d.ws === 'wss://relay.sigelo.ai/mqtt' && d.http === 'https://relay.sigelo.ai', `a relay string: mqtts on 8883, wss at /mqtt on 443 (${JSON.stringify(d)})`);
  ok(endpointOf('r', { r: { mqtt: 'wss://r.example/mqtt', http: 'https://r.example' } }).mqtt === 'wss://r.example/mqtt', 'endpoints: mqtt may be wss://');
  ok(endpointOf('r', { r: { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:2' } }).ws === 'ws://127.0.0.1:2/mqtt', 'endpoints: ws defaults to the http origin at /mqtt (ws:// for a loopback http://)');
  ok(checkOf(() => endpointOf('r', { r: { mqtt: 'ws://r.example/mqtt', http: 'https://r.example' } })) === 'relay'
    && checkOf(() => endpointOf('r', { r: { mqtt: 'mqtts://r.example', http: 'https://r.example', ws: 'ws://r.example/mqtt' } })) === 'relay',
  'endpoints: ws:// only to a loopback address, as mqtt:// and http://');
  const env = { HTTPS_PROXY: 'http://user:pw@proxy.example:3128', NO_PROXY: 'internal.example, .corp.example,10.1.2.3,*.lab.example,api.example:8443' };
  const via = (u, e = env) => proxyFor(u, e)?.host ?? null;
  ok(via('https://relay.sigelo.ai/challenge') === 'proxy.example:3128' && via('wss://relay.sigelo.ai/mqtt') === 'proxy.example:3128', 'proxyFor: HTTPS_PROXY carries https:// and wss://');
  ok(via('http://127.0.0.1:1/') === null && via('ws://127.0.0.1:1/mqtt') === null, 'proxyFor: never plain http:// or ws://');
  ok(['https://internal.example', 'https://a.internal.example', 'https://x.corp.example', 'https://corp.example', 'https://10.1.2.3', 'https://b.lab.example', 'https://api.example:8443'].every((u) => via(u) === null),
    'proxyFor: NO_PROXY by name and its subdomains, a leading "." or "*.", an address, a name with its port');
  ok(via('https://api.example') === 'proxy.example:3128' && via('https://notinternal.example') === 'proxy.example:3128', 'proxyFor: a port that differs, or a name that only ends alike: proxied');
  ok(via('https://x', { https_proxy: 'proxy:8080' }) === 'proxy:8080' && via('https://x', { HTTPS_PROXY: 'http://p:1', NO_PROXY: '*' }) === null && via('https://x', {}) === null,
    'proxyFor: https_proxy too, a bare host:port as http://; NO_PROXY=* and no proxy at all: none');
  ok(checkOf(() => proxyFor('https://x', { HTTPS_PROXY: 'socks5://p:1080' })) === 'connect', 'proxyFor: a proxy that is not http:// is refused by name');
  ok(optionsFromEnv({}).transport === undefined && optionsFromEnv({ SIGELO_RELAY_TRANSPORT: 'auto' }).transport === 'auto' && checkOf(() => optionsFromEnv({ SIGELO_RELAY_TRANSPORT: 'tcp' })) === 'relay',
    'SIGELO_RELAY_TRANSPORT: unset leaves the default; mqtts, wss or auto; anything else refused');
  ok(checkOf(() => new Carrier({ identity: () => ({}), store: 'a', state: 'b', transport: 'ws' })).includes('transport'), 'the constructor refuses another transport');
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) report(': the part without a relay; SKIP the rest, no relay checkout beside contact/ (set SIGELO_RELAY_DIR)');
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy, TIERS } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);

const dir = mkdtempSync(join(tmpdir(), 'sigelo-ws-'));
const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
// An MQTT port that answers nothing: each connection closed at once, counted.
const dead = { n: 0 };
const deadServer = createNetServer((s) => { dead.n++; s.destroy(); });
const deadPort = await listen(deadServer);
const relayLines = [];
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), httpPort: 0, loginRate: 100000, verifyBudget: 1e9, log: (l) => relayLines.push(l) });
const httpBase = `http://127.0.0.1:${relay.ports.http}`;
try {
  // ================================================================ wss, 8883 unreachable
  {
    // No MQTT listener at all: mqtt names a port that closes every connection.
    const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${deadPort}`, http: httpBase } };
    const x = make(dir, agent('wx'), { endpoints, transport: 'wss' }), y = make(dir, agent('wy'), { endpoints, transport: 'wss' });
    const r = await pairAndTalk(x, y, 'wss');
    ok(r.accepted === 'waiting' && r.sent.join() === 'sent,sent' && r.gotY.join() === 'hello from x wss' && r.gotX.join() === 'hello from y wss',
      `transport wss: login, claim, send and receive over WebSocket only (${JSON.stringify(r)})`);
    ok(dead.n === 0, `and 8883 was never dialled (${dead.n})`);
  }
  // ================================================================ auto: 8883 first, then WebSocket, kept
  {
    const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${deadPort}`, http: httpBase } };
    const x = make(dir, agent('ax'), { endpoints, transport: 'auto' }), y = make(dir, agent('ay'), { endpoints, transport: 'auto' });
    const t0 = Date.now(), inv = await x.invite({ name: 'y' });
    const fell = x.events.find((e) => e.type === 'transport');
    ok(dead.n === 1 && fell?.transport === 'wss' && /ws:\/\/127\.0\.0\.1:\d+\/mqtt/.test(fell.detail) && Date.now() - t0 < PROBE_MS + 5000,
      `transport auto: the MQTT port tried once, then WebSocket, said by a "transport" event (${dead.n} dial; ${fell?.detail})`);
    await y.accept(inv.code, { name: 'x', wait: 0.3 });
    await x.inbox(); await y.inbox(); await x.inbox();
    const s = await x.send('y', 'auto hello'), got = await y.inbox();
    ok(s.status === 'sent' && got.messages.map((m) => m.content).join() === 'auto hello', `transport auto: paired, sent and read over WebSocket (${s.status})`);
    ok(dead.n === 1, `every later connection, of both agents, went straight to WebSocket: the fallback is kept for the process (${dead.n} dial in all)`);
    // Transport mqtts: the MQTT port only, no fallback.
    const m = make(dir, agent('mx'), { endpoints, transport: 'mqtts' });
    let why = null;
    try { await m.invite(); } catch (e) { why = e.check; }
    ok(why === 'connect' && dead.n === 2 && !m.events.some((e) => e.type === 'transport'), `transport mqtts: the MQTT port only, no fallback (${why})`);
  }
  // ================================================================ the default (auto), 8883 dropped
  {
    // An MQTT port that takes the connection and never answers: a firewall that drops, not refuses.
    const held = [];
    const silent = createNetServer((s) => { held.push(s); s.on('error', () => {}); });
    const silentPort = await listen(silent);
    try {
      const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${silentPort}`, http: httpBase } };
      const x = make(dir, agent('dx'), { endpoints });
      ok(x.transport === 'auto', `no transport option and no SIGELO_RELAY_TRANSPORT: the carrier's transport is auto (${x.transport})`);
      const t0 = Date.now(), inv = await x.invite({ name: 'y' }), ms = Date.now() - t0;
      const fell = x.events.find((e) => e.type === 'transport');
      ok(typeof inv.code === 'string' && held.length === 1 && fell?.transport === 'wss' && ms >= PROBE_MS - 100 && ms < PROBE_MS + 5000,
        `the default, 8883 silent: connected over WebSocket after the ${PROBE_MS / 1000} s probe (${ms} ms, ${held.length} dial; ${fell?.detail})`);
    } finally { for (const s of held) s.destroy(); silent.close(); }
  }

  // ================================================================ only an HTTP CONNECT proxy
  {
    // A self-signed certificate for relay.test (relay/test/fixtures.mjs builds one per run).
    const { selfSigned } = await import(pathToFileURL(join(RELAY_DIR, 'test', 'fixtures.mjs')).href);
    const cert = selfSigned(HOST), caFile = join(dir, 'ca.pem');
    writeFileSync(caFile, cert.cert);
    // The stand-in nginx, TLS on 443's behalf: relay.json naming the WebSocket endpoint at another
    // path (/mqtt-alt), which it passes to the relay's /mqtt with X-Real-IP; /mqtt itself it does not
    // serve, so a client that ignored relay.json fails. Every other call passed on as it came.
    const front = createHttpsServer({ cert: cert.cert, key: cert.key }, (req, res) => {
      if (req.url === '/relay.json') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ endpoints: { mqtt: `mqtts://${HOST}:8883`, mqtt_ws: `wss://${HOST}/mqtt-alt` } })); return; }
      const up = httpRequest(`${httpBase}${req.url}`, { method: req.method, headers: { ...req.headers, 'x-real-ip': '198.51.100.7' } }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      up.on('error', () => res.destroy());
      req.pipe(up);
    });
    front.on('upgrade', (req, sock, head) => {
      if (req.url !== '/mqtt-alt') return sock.end('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n');
      const up = netConnect(relay.ports.http, '127.0.0.1', () => {
        const h = Object.entries({ ...req.headers, 'x-real-ip': '198.51.100.7' }).map(([k, v]) => `${k}: ${v}`).join('\r\n');
        up.write(`GET /mqtt HTTP/1.1\r\n${h}\r\n\r\n`); up.write(head); up.pipe(sock); sock.pipe(up);
      });
      for (const s of [up, sock]) { s.on('error', () => { up.destroy(); sock.destroy(); }); s.on('close', () => { up.destroy(); sock.destroy(); }); }
    });
    const frontPort = await listen(front);
    // The proxy: CONNECT relay.test:443 only, to the front; anything else 403. Counted.
    const asked = [];
    const proxy = createServer((req, res) => { res.writeHead(405); res.end(); });
    proxy.on('connect', (req, sock, head) => {
      asked.push(req.url);
      if (req.url !== `${HOST}:443`) return sock.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      const up = netConnect(frontPort, '127.0.0.1', () => { sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); up.write(head); up.pipe(sock); sock.pipe(up); });
      for (const s of [up, sock]) s.on('error', () => { up.destroy(); sock.destroy(); });
    });
    const proxyPort = await listen(proxy);
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, NODE_EXTRA_CA_CERTS: caFile, HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`, SIGELO_RELAY_TRANSPORT: 'auto' };
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), '--child', dir], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', (b) => { out += b; }); child.stderr.on('data', (b) => { err += b; });
    await new Promise((resolve) => child.once('exit', resolve));
    let r = {};
    try { r = JSON.parse(out.trim().split('\n').at(-1)); } catch { r = { error: `no result: ${out}${err}`.slice(0, 600) }; }
    ok(!r.error && r.accepted === 'waiting' && r.sent?.join() === 'sent,sent' && r.gotY?.join() === 'hello from x via proxy' && r.gotX?.join() === 'hello from y via proxy',
      `behind an HTTP CONNECT proxy only (8883 unreachable, the name resolving nowhere): login, claim, send and receive (${JSON.stringify(r)})`);
    ok(r.transport?.join() === 'wss,' && /wss:\/\/relay\.test\/mqtt-alt/.test(r.fellBack ?? ''), `auto fell back once, to the WebSocket endpoint relay.json names; the second agent of the process went there directly (${r.transport}; ${r.fellBack})`);
    ok(asked.length > 0 && asked.every((u) => u === `${HOST}:443`), `every HTTPS call and the WebSocket went through the proxy as CONNECT ${HOST}:443 (${asked.length} tunnels)`);
    ok(relayLines.filter((l) => l === 'login 198.51.100.0/24').length >= 2, 'the relay counted those WebSocket logins under the network the front sent as X-Real-IP, not its own loopback');
    for (const s of [front, proxy]) { s.closeAllConnections?.(); s.close(); }
  }

  // ================================================================ the reader's quota, told as such
  {
    // A relay whose free tier holds 200,000 bytes per reader: y, offline, fills; x is told the
    // refusal is y's side (quota_storage, side "reader"), not its relay or its own allowance.
    const tiny = { ...TIERS.free, storage: 200000, maxMessage: 64 * 1024, retentionDays: 7 };
    const q = await startRelay({ host: HOST, db: join(dir, 'quota.db'), httpPort: 0, tcpPort: 0, loginRate: 100000, verifyBudget: 1e9, log: () => {},
      policy: (ctx) => relayPolicy(ctx, { pow: { bits: 4, loadBits: 8, loadPerHour: 1000 }, freeQueue: 64 * 1024 * 1024, tiers: { free: tiny, pro: TIERS.pro } }) });
    const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${q.ports.tcp}`, http: `http://127.0.0.1:${q.ports.http}` } };
    const x = make(dir, agent('qx'), { endpoints }), y = make(dir, agent('qy'), { endpoints });
    const r = await pairAndTalk(x, y, 'quota');
    ok(r.gotY.length === 1, 'two agents paired on a relay with a 200,000-byte free reader');
    let s = null, thrown = null;
    for (let i = 0; i < 8 && !thrown; i++) { try { await x.send('y', 'z'.repeat(40000)); } catch (e) { thrown = e; } }
    ok(thrown?.check === 'quota_storage' && thrown.side === 'reader' && /refused \(y's side is over its storage quota/.test(thrown.message) && /nothing is wrong with your relay/.test(thrown.message) && /reader over quota/.test(thrown.message),
      `y's queue full: send refuses quota_storage, side "reader", told as y's side, the relay's words quoted (${thrown?.message})`);
    [s] = await x.sendAll('y', ['z'.repeat(40000)]);
    ok(s?.status === 'refused' && s.code === 'quota_storage' && s.side === 'reader' && /^y's side/.test(s.detail), `sendAll: the same, as a result (${JSON.stringify(s).slice(0, 200)})`);
    ok(x.events.some((e) => e.type === 'refused' && e.code === 'quota_storage' && e.side === 'reader'), 'the refused event carries side "reader" too');
    await q.close();
  }
} catch (e) {
  fails.push(`exception: ${e.stack}`);
} finally {
  await relay.close();
  deadServer.close();
  rmSync(dir, { recursive: true, force: true });
}
report();
