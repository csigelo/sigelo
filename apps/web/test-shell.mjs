// SPDX-License-Identifier: MIT
// The Android app's page side in Node (design/apps.md §14 A5): what runs in the WebView, over a fake
// shell that keeps SigeloBridge.java's protocol (sigelo-bridge/0, platform-android.mjs) with Node's
// net, tls and https. The Java itself is built and run only on CI (apps/android/README.md). Parts:
//   1. ws-over-stream.mjs, RFC 6455 client framing: against `ws` (handshake, masking, sizes up to
//      200 KB, fragments both ways, ping/pong, close both ways) and a raw server for what must fail
//      (accept, status, extension, masked or reserved frames, control frames, UTF-8, sizes, close
//      frames, abrupt end, a close never answered); streamSocket (mqtts) over an echo server.
//   1c. MQTT.js as a page loads it (its keepalive on worker-timers, a blob: Worker the CSP refuses): the CONNACK acted on.
//   2. platform-android.mjs over the fake shell: the bridge, https (no Origin, no redirect, the
//      LAN rule), tls (a wrong certificate name refused), the keystore seal, the proof of work and
//      its fallback, the identity sealed; then two apps against the in-process relay behind a
//      stand-in nginx that refuses browser requests (Origin, Sec-Fetch-Site), as relay/deploy does:
//      one over mqtts:8883, one over wss:443 (the framing above), paired with a Node agent, messages
//      both ways, and none refused as a browser's.
//   3. The remote form (shell.mjs): a computer's `sigelo-agent ui --remote`, sealed calls carried by
//      the shell's http to the LAN; scope; the computer gone.
//   3b. Several computers (computers.mjs, design/profiles.md P2): three computers' pages on the LAN, two of
//      one operator, one of another; today's one migrated as c1, add (Cancel), other_operator, switch, forget.
//   4. The remote form over the relay: a computer's `ui --remote --relay` in this process, the app's
//      control identity paired by SIGELO:CTL: and four words, requests answered, state pushed (the
//      poll sends nothing), scope, seat elsewhere, revoked; a second computer of another operator refused.
//   node apps/web/test-shell.mjs   → ALL PASS (n); without the relay checkout, part 2's relay half SKIPs
import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { createServer as httpsServer, request as httpsRequest } from 'node:https';
import { registerHooks } from 'node:module';
import { createServer as netServer, connect as netConnect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url)), REPO = join(HERE, '..', '..');
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
let skipped = '';
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
  console.log(`ALL PASS (${count})${skipped}`);
  process.exit(0);
};
setTimeout(() => { console.log(`FAIL the run did not finish in 400 s (${count} checks so far)`); for (const f of fails) console.log('FAIL ' + f); process.exit(1); }, 400000).unref();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (f, ms = 20000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await f()) return true; await sleep(50); } return false; };
const checkOf = async (f) => { try { await f(); return 'accepted'; } catch (e) { return e.check ?? e.name ?? e.message; } };
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));

// The page's modules through index.html's import map, as test-web.mjs loads them.
try { execFileSync(process.execPath, [join(HERE, 'copy.mjs')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { process.stdout.write(`${e.stdout ?? ''}${e.stderr ?? ''}`); throw e; } // copy.mjs's FAIL lines shown
const C = await import(pathToFileURL(join(HERE, 'copy.mjs')).href);
const map = C.importMap(), WEB = pathToFileURL(HERE + '/').href;
registerHooks({
  resolve(spec, ctx, next) {
    if (!ctx.parentURL?.startsWith(WEB) || /\/(test-[a-z]+|copy)\.mjs$/.test(ctx.parentURL)) return next(spec, ctx);
    const page = C.resolve(spec.startsWith(WEB) ? C.PAGE + spec.slice(WEB.length) : spec, C.PAGE + ctx.parentURL.slice(WEB.length), map);
    return { url: WEB + page.slice(C.PAGE.length), format: 'module', shortCircuit: true };
  },
});
const WS = await import(pathToFileURL(join(HERE, 'ws-over-stream.mjs')).href);
const A = await import(pathToFileURL(join(HERE, 'platform-android.mjs')).href);
const W = await import(pathToFileURL(join(HERE, 'platform-web.mjs')).href);
const mqttEsm = (await import(pathToFileURL(join(HERE, 'vendor', 'mqtt.esm.js')).href)).default;
const { FakeIDB, FakeWorker } = await import(pathToFileURL(join(HERE, 'test-fakes.mjs')).href);
const { WebSocketServer } = await import(pathToFileURL(join(REPO, 'apps', 'contact', 'node_modules', 'ws', 'wrapper.mjs')).href);
const nodePow = (await import(pathToFileURL(join(REPO, 'apps', 'contact', 'platform-node.mjs')).href)).pow;

// A Node socket as the shell's stream (write → Promise, close, ondata, onclose).
const streamOf = (sock) => {
  const st = { ondata: null, onclose: null, write: (b) => new Promise((y, n) => sock.write(b, (e) => (e ? n(e) : y()))), close: () => sock.destroy() };
  sock.on('data', (b) => st.ondata?.(new Uint8Array(b))); sock.on('close', () => st.onclose?.(null)); sock.on('error', () => {});
  return st;
};
const dial = (port) => new Promise((y, n) => { const s = netConnect(port, '127.0.0.1', () => y(streamOf(s))); s.once('error', n); });
const watch = (sock) => { const e = { open: 0, messages: [], errors: [], close: null }; sock.onopen = () => e.open++; sock.onmessage = (m) => e.messages.push(m.data); sock.onerror = (x) => e.errors.push(x.message); sock.onclose = (c) => { e.close = c; }; return e; };
const bytes = (n, seed = 7) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 0xff);
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));

// ================================================================ 1. ws-over-stream.mjs
{
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1', perMessageDeflate: false, handleProtocols: (ps) => (ps.has('mqtt') ? 'mqtt' : false) });
  await new Promise((r) => wss.once('listening', r));
  const port = wss.address().port, seen = [];
  let pongs = [], closedAt = null, server = null;
  wss.on('connection', (ws, req) => {
    seen.push(req); server = ws;
    ws.on('pong', (d) => pongs.push(d.toString()));
    ws.on('close', (code, reason) => { closedAt = { code, reason: reason.toString() }; });
    ws.on('message', (d, binary) => {
      const t = binary ? null : d.toString();
      if (t === 'frag') { ws.send(Buffer.from('ab'), { fin: false, binary: true }); ws.send(Buffer.from('cd'), { fin: false, binary: true }); ws.send(Buffer.from('ef'), { fin: true, binary: true }); }
      else if (t === 'ping') ws.ping('abc');
      else if (t === 'bye') ws.close(4001, 'go');
      else ws.send(d, { binary });
    });
  });
  const open = async () => { const s = WS.wsOverStream(dial(port), { url: `ws://127.0.0.1:${port}/mqtt?x=1`, protocols: ['mqtt'] }); const e = watch(s); await until(() => e.open || e.close, 5000); return [s, e]; };
  const [s, e] = await open();
  const h = seen[0]?.headers ?? {};
  ok(e.open === 1 && s.readyState === 1 && s.protocol === 'mqtt' && seen[0]?.url === '/mqtt?x=1', `ws: the handshake: open, subprotocol mqtt, the path (${seen[0]?.url})`);
  ok(h.origin === undefined && !Object.keys(h).some((k) => k.startsWith('sec-fetch') || k === 'cookie' || k === 'sec-websocket-extensions') && h['sec-websocket-version'] === '13' && h.host === `127.0.0.1:${port}`,
    `ws: the request carries no Origin, no Sec-Fetch-*, no cookie, no extension (${Object.keys(h)})`);
  let ok1 = true;
  for (const n of [0, 1, 125, 126, 65535, 65536, 200000]) {
    const before = e.messages.length;
    s.send(bytes(n, n));
    await until(() => e.messages.length > before, 5000);
    const got = e.messages.at(-1);
    if (!(got instanceof ArrayBuffer) || !same(new Uint8Array(got), bytes(n, n))) ok1 = false;
  }
  ok(ok1, 'ws: binary messages of 0, 1, 125, 126, 65535, 65536 and 200,000 bytes (7-bit, 16-bit and 64-bit lengths) echoed whole, masked (ws refuses an unmasked one)');
  s.send('héllo ✓'); await until(() => e.messages.at(-1) === 'héllo ✓', 3000);
  ok(e.messages.at(-1) === 'héllo ✓', 'ws: a text message, UTF-8, both ways');
  s.send('frag'); await until(() => e.messages.at(-1) instanceof ArrayBuffer && e.messages.at(-1).byteLength === 6, 3000);
  ok(new TextDecoder().decode(e.messages.at(-1)) === 'abcdef', 'ws: a message in three fragments from the server, one message here');
  s.send(bytes(5000), { frameMax: 1000 }); await until(() => e.messages.at(-1)?.byteLength === 5000, 3000);
  ok(same(new Uint8Array(e.messages.at(-1)), bytes(5000)), 'ws: a message sent in five fragments arrives whole at the server');
  s.send('ping'); await until(() => pongs.length > 0, 3000);
  ok(pongs.join() === 'abc', `ws: a ping answered with a pong of the same payload (${pongs})`);
  s.send(bytes(300000));
  const buffered = s.bufferedAmount;
  await until(() => s.bufferedAmount === 0, 5000);
  ok(buffered >= 300000 && s.bufferedAmount === 0, `ws: bufferedAmount counts what is not written yet (${buffered}, then 0)`);
  s.close(1000, 'bye');
  ok(s.readyState === 2, 'ws: close() → CLOSING');
  await until(() => e.close && closedAt, 5000);
  ok(closedAt?.code === 1000 && closedAt.reason === 'bye' && e.close?.wasClean === true && e.close.code === 1000 && e.errors.length === 0 && s.readyState === 3,
    `ws: closed by this side: the server got 1000 "bye", the close event clean (${JSON.stringify(closedAt)}, ${e.close?.code})`);
  const [s2, e2] = await open();
  s2.send('bye'); await until(() => e2.close, 5000);
  ok(e2.close?.code === 4001 && e2.close.reason === 'go' && e2.close.wasClean === true && e2.errors.length === 0, `ws: closed by the server (4001 "go"): answered, the close event clean (${JSON.stringify(e2.close)})`);
  const pending = WS.wsOverStream(new Promise(() => {}), { url: 'wss://relay.test/mqtt' });
  ok(await checkOf(() => pending.send('x')) === 'InvalidStateError' && await checkOf(() => s.close(1005)) === 'InvalidAccessError' && await checkOf(() => WS.wsOverStream(dial(port), { url: 'https://x/' })) === 'SyntaxError',
    'ws: send before open, a close code a client may not send, a URL not ws(s): refused');
  await new Promise((r) => wss.close(r));

  // A raw server: the handshake answered as each case says, then frames as written; what the client sends is kept.
  const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  const acceptOf = (k) => createHash('sha1').update(k + GUID).digest('base64');
  const frame = (op, payload, { fin = true, rsv = 0, mask = false } = {}) => {
    const p = Buffer.from(payload), n = p.length, head = [(fin ? 0x80 : 0) | rsv | op];
    if (n < 126) head.push((mask ? 0x80 : 0) | n); else if (n < 65536) head.push((mask ? 0x80 : 0) | 126, n >> 8, n & 255); else head.push((mask ? 0x80 : 0) | 127, 0, 0, 0, 0, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255);
    return Buffer.concat([Buffer.from(head), mask ? Buffer.from([1, 2, 3, 4]) : Buffer.alloc(0), mask ? Buffer.from(p.map((b, i) => b ^ [1, 2, 3, 4][i & 3])) : p]);
  };
  // The client's frames, unmasked: [{ op, fin, masked, key, payload }].
  const framesOf = (buf) => {
    const out = [];
    for (let i = 0; i + 2 <= buf.length;) {
      let n = buf[i + 1] & 0x7f, at = i + 2;
      if (n === 126) { n = buf.readUInt16BE(at); at += 2; } else if (n === 127) { n = Number(buf.readBigUInt64BE(at)); at += 8; }
      const masked = (buf[i + 1] & 0x80) !== 0, key = masked ? buf.subarray(at, at + 4) : null;
      if (masked) at += 4;
      out.push({ op: buf[i] & 0x0f, fin: (buf[i] & 0x80) !== 0, masked, key: key && Buffer.from(key), payload: Buffer.from(buf.subarray(at, at + n).map((b, j) => (masked ? b ^ key[j & 3] : b))) });
      i = at + n;
    }
    return out;
  };
  async function raw(answer, { after = [], maxPayload, closeMs, split = false, end = false } = {}) {
    let got = Buffer.alloc(0), sock = null;
    const srv = netServer((c) => {
      sock = c; c.on('error', () => {});
      let head = '';
      c.on('data', (d) => {
        if (!head.includes('\r\n\r\n')) {
          head += d.toString('latin1');
          if (!head.includes('\r\n\r\n')) return;
          const key = /sec-websocket-key: (\S+)/i.exec(head)?.[1] ?? '';
          const out = Buffer.concat([Buffer.from(answer(key), 'latin1'), ...after]);
          if (split) { let k = 0; const drip = () => { if (k < out.length && !c.destroyed) { c.write(out.subarray(k, k + 1)); k++; setImmediate(drip); } else if (end) c.end(); }; drip(); }
          else { c.write(out); if (end) c.end(); }
          return;
        }
        got = Buffer.concat([got, d]);
      });
    });
    const p = await listen(srv);
    const s = WS.wsOverStream(dial(p), { url: `wss://relay.test:${p}/mqtt`, protocols: ['mqtt'], ...(maxPayload && { maxPayload }), ...(closeMs && { closeMs }) });
    const e = watch(s);
    return { s, e, srv, sent: () => framesOf(got), request: () => null, done: async (ms = 3000) => { await until(() => e.close, ms); sock?.destroy(); srv.close(); return e; } };
  }
  const head = (key, extra = '') => `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptOf(key)}\r\nSec-WebSocket-Protocol: mqtt\r\n${extra}\r\n`;
  const fails1 = async (name, answer, o, want = 1006, sentCode) => {
    const r = await raw(answer, o);
    if (o?.act) await o.act(r.s, r.e);
    const e = await r.done();
    const closeSent = r.sent().find((f) => f.op === 8);
    const okSent = sentCode === undefined || (closeSent && closeSent.payload.readUInt16BE(0) === sentCode);
    ok(e.close?.code === want && e.close.wasClean === false && e.errors.length === 1 && r.s.readyState === 3 && okSent, `ws fails: ${name} (${JSON.stringify(e.close)}, ${e.errors}, sent ${closeSent?.payload.readUInt16BE(0)})`);
    return e;
  };
  await fails1('a wrong Sec-WebSocket-Accept, never open', (k) => head('x' + k));
  const e403 = await fails1('403 (a relay refusing a browser), never open', () => 'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
  ok(/403/.test(e403.close.reason) && e403.open === 0, `ws fails: the status is in the reason (${e403.close.reason})`);
  await fails1('an extension none asked for', (k) => head(k, 'Sec-WebSocket-Extensions: permessage-deflate\r\n'));
  await fails1('a subprotocol none asked for', (k) => head(k).replace('Protocol: mqtt', 'Protocol: xmpp'));
  await fails1('a masked frame from the server', head, { after: [frame(2, 'x', { mask: true })] }, 1006, 1002);
  await fails1('RSV1 set', head, { after: [frame(2, 'x', { rsv: 0x40 })] }, 1006, 1002);
  await fails1('a ping of 126 bytes', head, { after: [frame(9, Buffer.alloc(126))] }, 1006, 1002);
  await fails1('a fragmented ping', head, { after: [frame(9, 'a', { fin: false })] }, 1006, 1002);
  await fails1('a continuation with no message begun', head, { after: [frame(0, 'a')] }, 1006, 1002);
  await fails1('a new message inside a fragmented one', head, { after: [frame(2, 'a', { fin: false }), frame(2, 'b')] }, 1006, 1002);
  await fails1('reserved opcode 3', head, { after: [frame(3, 'a')] }, 1006, 1002);
  await fails1('a text message that is not UTF-8', head, { after: [frame(1, Buffer.from([0xc3, 0x28]))] }, 1006, 1007);
  await fails1('a message over maxPayload (in fragments)', head, { after: [frame(2, Buffer.alloc(600), { fin: false }), frame(0, Buffer.alloc(600))], maxPayload: 1000 }, 1006, 1009);
  await fails1('a close frame of one byte', head, { after: [frame(8, Buffer.from([3]))] }, 1006, 1002);
  await fails1('close code 1005 sent by the server', head, { after: [frame(8, Buffer.from([0x03, 0xed]))] }, 1006, 1002);
  {
    const r = await raw(head, { end: true }), e = await r.done();
    ok(e.open === 1 && e.close?.code === 1006 && e.close.wasClean === false && e.errors.length === 0, `ws: the stream ends with no close frame: close 1006, not clean, no error (${JSON.stringify(e.close)})`);
  }
  {
    // Handshake and frames in one byte at a time; a ping inside a fragmented message.
    const r = await raw(head, { split: true, after: [frame(2, 'he', { fin: false }), frame(9, 'pp'), frame(0, 'llo'), frame(2, bytes(70000)), frame(8, Buffer.from([0x03, 0xe8, 0x6f, 0x6b]))] });
    const e = await r.done(10000), sent = r.sent();
    const pong = sent.find((f) => f.op === 0xa), close = sent.find((f) => f.op === 8);
    ok(e.messages.length === 2 && new TextDecoder().decode(e.messages[0]) === 'hello' && same(new Uint8Array(e.messages[1]), bytes(70000)), 'ws: a byte at a time: the handshake, a fragmented message around a ping, a 70,000-byte frame');
    ok(pong?.payload.toString() === 'pp' && pong.masked && close?.payload.readUInt16BE(0) === 1000 && e.close?.code === 1000 && e.close.reason === 'ok' && e.close.wasClean,
      `ws: the ping answered (pong "pp"), the server's close (1000 "ok") echoed, clean (${JSON.stringify(e.close)})`);
    ok(sent.every((f) => f.masked) && new Set(sent.map((f) => f.key.toString('hex'))).size === sent.length, `ws: every frame sent is masked, each with its own key (${sent.length} frames)`);
  }
  {
    const r = await raw(head, { closeMs: 300 });
    await until(() => r.e.open, 3000);
    r.s.close();
    const e = await r.done(3000), close = r.sent().find((f) => f.op === 8);
    ok(close?.payload.length === 0 && e.close?.code === 1006 && e.close.wasClean === false, `ws: a close the server never answers: ended after closeMs, not clean (${JSON.stringify(e.close)})`);
  }
  {
    const echo = netServer((c) => { c.on('error', () => {}); c.pipe(c); }), p = await listen(echo);
    const t = WS.streamSocket(dial(p)), e = watch(t);
    await until(() => e.open, 3000);
    t.send(bytes(100000));
    await until(() => e.messages.reduce((n, m) => n + m.byteLength, 0) >= 100000, 5000);
    const all = Buffer.concat(e.messages.map((m) => Buffer.from(m)));
    ok(t.readyState === 1 && same(all, bytes(100000)), `streamSocket (mqtts): the bytes as they are, no framing (${e.messages.length} chunks)`);
    t.close();
    ok(t.readyState === 3 && e.close?.wasClean === true, 'streamSocket: close');
    const f = WS.streamSocket(Promise.reject(new Error('refused'))), ef = watch(f);
    await until(() => ef.close, 2000);
    ok(ef.errors.length === 1 && ef.close?.code === 1006, 'streamSocket: a stream that never opened: error, close 1006');
    echo.close();
  }
}

// ================================================================ the fake shell (SigeloBridge.java in Node)
// What SigeloBridge.java does, over a MessageChannel: https (https:// anywhere, http:// only to a
// private or loopback IPv4 address, no redirect followed, no header but Content-Type), tls (the
// certificate and name checked against `ca`), streams, the keystore (AES-256-GCM, a key per alias;
// "full" can be locked: cancelled), the form and the wipe, the app lock's settings, notifications (shown: state.notes) and
// their open event (open(tag) now; pendingOpen: posted once right after the next connect, as a start by a tap).
// hosts: name → { port: local port }.
const PRIVATE = (h) => { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h); if (!m) return false; const [a, b] = [Number(m[1]), Number(m[2])]; return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254); };
function fakeShell({ mode = 'self', wipe = false, hosts = {}, ca } = {}) {
  const target = new EventTarget(), keys = new Map(), log = { ops: [], streams: [], seals: [] };
  const state = { mode, wipe, locked: false, secure: false, door: false, secureLog: [], clipCleared: 0, clip: null,
    lock: { on: true, after: 1, secure: true }, granted: true, asked: 0, notes: new Map(), pendingOpen: null, forced: [] };
  let current = null;
  const ALIASES = { 'identity:false': 0, 'identity:true': 1, control: 2 };
  // Per profile, as SigeloBridge.java: p1 the aliases and blob version 1 of before; another its own aliases,
  // blob version 2 naming it ([2][alias][n][id][IV][ct ‖ tag]), the AAD naming kind and profile.
  const aliasOf = (profile, a) => (profile === 'p1' ? ['sigelo-identity', 'sigelo-identity-full', 'sigelo-control'][a] : `sigelo-${profile}${['-identity', '-identity-full', '-control'][a]}`);
  // A computer other than a profile's first (P2): version 2 naming "<profile>:<computer>", the AAD naming both.
  const aadOf = (kind, profile, computer = 'c1') => `sigelo-app ${kind}/0${computer === 'c1' ? (profile === 'p1' ? '' : ` ${profile}`) : ` ${profile} ${computer}`}`;
  const profileOf = (m) => { const p = m.profile ?? 'p1'; if (typeof p !== 'string' || !/^p[1-9]\d{0,2}$/.test(p)) throw Object.assign(new Error('a profile id'), { check: 'profile' }); return p; };
  const computerOf = (m) => { const c = m.computer ?? 'c1'; if (typeof c !== 'string' || !/^c[1-9]\d{0,2}$/.test(c)) throw Object.assign(new Error('a computer id'), { check: 'computer' }); return c; };
  const route = (host, port) => { const p = hosts[host]?.[port]; if (!p) throw Object.assign(new Error(`${host}:${port}: unreachable`), { check: 'connect' }); return p; };
  const shell = {
    info: () => JSON.stringify({ v: 'sigelo-shell/0', mode: state.mode, wipe: state.wipe, version: 'test' }),
    connect() {
      const { port1, port2 } = new MessageChannel(), streams = new Map();
      let sid = 0;
      const post = (m) => port1.postMessage(JSON.stringify(m));
      current = port1;
      port1.onmessage = async (ev) => {
        const m = JSON.parse(ev.data);
        log.ops.push(m.op);
        try {
          if (m.op === 'https') {
            const u = new URL(m.url), body = m.body === undefined ? undefined : Buffer.from(m.body, 'base64');
            const headers = body ? { 'content-type': m.type, 'content-length': body.length } : {};
            let req;
            if (u.protocol === 'https:') req = httpsRequest({ host: '127.0.0.1', port: route(u.hostname, Number(u.port || 443)), servername: u.hostname, ca, method: m.method, path: u.pathname + u.search, headers: { host: u.host, ...headers } });
            else if (u.protocol === 'http:' && PRIVATE(u.hostname)) req = httpRequest(u, { method: m.method, headers });
            else throw Object.assign(new Error(`${u.protocol}//${u.host}: https, or http to this network only`), { check: 'connect' });
            const r = await new Promise((y, n) => { req.once('response', y); req.once('error', n); req.setTimeout(20000, () => req.destroy(new Error('timeout'))); req.end(body); });
            const chunks = []; for await (const c of r) chunks.push(c);
            const keep = Object.fromEntries(['date', 'content-length', 'retry-after', 'content-type'].filter((k) => r.headers[k] !== undefined).map((k) => [k, String(r.headers[k])]));
            post({ id: m.id, status: r.statusCode, headers: keep, body: Buffer.concat(chunks).toString('base64') });
          } else if (m.op === 'tls') {
            const sock = tlsConnect({ host: '127.0.0.1', port: route(m.host, m.port), servername: m.host, ca });
            await new Promise((y, n) => { sock.once('secureConnect', y); sock.once('error', n); });
            const s = ++sid; streams.set(s, sock); log.streams.push(`${m.host}:${m.port}`);
            post({ id: m.id, stream: s });
            sock.on('data', (d) => post({ s, data: d.toString('base64') }));
            sock.on('error', (e) => { sock.err = e.message; });
            sock.on('close', () => { if (streams.delete(s)) post({ s, end: true, ...(sock.err && { error: sock.err }) }); });
          } else if (m.op === 'write') {
            const sock = streams.get(m.s);
            if (!sock) throw Object.assign(new Error('no such stream'), { check: 'stream' });
            await new Promise((y, n) => sock.write(Buffer.from(m.data, 'base64'), (e) => (e ? n(e) : y())));
            post({ id: m.id });
          } else if (m.op === 'close') { const sock = streams.get(m.s); streams.delete(m.s); sock?.destroy(); }
          else if (m.op === 'seal' || m.op === 'open') {
            const kind = ['identity', 'keeper', 'words', 'control'].includes(m.kind) ? m.kind : null;
            if (!kind) throw Object.assign(new Error('kind'), { check: 'kind' });
            const data = Buffer.from(m.data, 'base64'), profile = profileOf(m), computer = computerOf(m);
            if (m.op === 'seal') {
              // The keeper root of a restore and the kept words: under the FULL key (alias 1), each its own AAD, as SigeloBridge.java.
              const a = kind === 'identity' ? ALIASES[`identity:${Boolean(m.full)}`] : kind === 'keeper' || kind === 'words' ? 1 : 2, al = aliasOf(profile, a);
              log.seals.push({ kind, full: Boolean(m.full), alias: a, profile, computer, name: al });
              if (a === 1 && state.locked) throw Object.assign(new Error('not unlocked'), { check: 'cancelled' });
              if (!keys.has(al)) keys.set(al, randomBytes(32));
              const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', keys.get(al), iv);
              c.setAAD(Buffer.from(aadOf(kind, profile, computer)));
              const owner = computer === 'c1' ? (profile === 'p1' ? '' : profile) : `${profile}:${computer}`;
              const head = owner === '' ? Buffer.from([1, a]) : Buffer.concat([Buffer.from([2, a, owner.length]), Buffer.from(owner, 'ascii')]);
              post({ id: m.id, data: Buffer.concat([head, iv, c.update(data), c.final(), c.getAuthTag()]).toString('base64') });
            } else {
              const a = data[1];
              let at;
              if (data[0] === 1) { if (profile !== 'p1' || computer !== 'c1') throw Object.assign(new Error('sealed for another profile'), { check: 'sealed' }); at = 2; }
              else if (data[0] === 2) {
                const n = data[2] ?? -1, want = computer === 'c1' ? profile : `${profile}:${computer}`;
                if (n < 2 || n > 9 || (profile === 'p1' && computer === 'c1') || data.subarray(3, 3 + n).toString('ascii') !== want) throw Object.assign(new Error('sealed for another profile or computer'), { check: 'sealed' });
                at = 3 + n;
              } else throw Object.assign(new Error('not sealed here'), { check: 'sealed' });
              const al = aliasOf(profile, a);
              if (data.length < at + 28 || (kind === 'identity' ? a > 1 : kind === 'keeper' || kind === 'words' ? a !== 1 : a !== 2) || !keys.has(al)) throw Object.assign(new Error('not sealed here'), { check: 'sealed' });
              if (a === 1 && state.locked) throw Object.assign(new Error('not unlocked'), { check: 'cancelled' });
              const d = createDecipheriv('aes-256-gcm', keys.get(al), data.subarray(at, at + 12));
              d.setAAD(Buffer.from(aadOf(kind, profile, computer))); d.setAuthTag(data.subarray(data.length - 16));
              let out;
              try { out = Buffer.concat([d.update(data.subarray(at + 12, data.length - 16)), d.final()]); } catch { throw Object.assign(new Error('does not open'), { check: 'sealed' }); }
              post({ id: m.id, data: out.toString('base64') });
            }
          } else if (m.op === 'forget-profile') {
            const profile = profileOf(m);
            for (let a = 0; a < 3; a++) keys.delete(aliasOf(profile, a));
            log.forgot = [...(log.forgot ?? []), profile];
            post({ id: m.id });
          } else if (m.op === 'mode') {
            if (m.mode !== 'self' && m.mode !== 'remote') throw Object.assign(new Error('mode'), { check: 'mode' });
            state.mode = m.mode; post({ id: m.id, mode: state.mode });
          } else if (m.op === 'wiped') { state.wipe = false; post({ id: m.id }); }
          else if (m.op === 'secure') { state.secure = m.on === true; state.door = state.secure && m.door === true; state.secureLog.push(`${state.secure}${state.door ? '+door' : ''}`); post({ id: m.id }); }
          else if (m.op === 'clip-clear') { state.clipCleared++; state.clip = null; post({ id: m.id }); }
          else if (m.op === 'clip-copy') { state.clip = { text: m.text, clear: m.clear }; post({ id: m.id }); }
          else if (m.op === 'share') { state.shared = m.text; post({ id: m.id }); }
          else if (m.op === 'lock') {
            if ('on' in m && typeof m.on !== 'boolean') throw Object.assign(new Error('on'), { check: 'lock' });
            if ('after' in m && ![1, 5, 15, 60].includes(m.after)) throw Object.assign(new Error('after'), { check: 'lock' });
            if ('on' in m) state.lock.on = m.on;
            if ('after' in m) state.lock.after = m.after;
            post({ id: m.id, ...state.lock });
          } else if (m.op === 'notify') {
            if (m.ask === true) { state.asked++; post({ id: m.id, granted: state.granted }); return; }
            if (typeof m.tag !== 'string' || !/^(chat|group|pay):[A-Za-z0-9:._-]{1,200}$/.test(m.tag)) throw Object.assign(new Error('tag'), { check: 'notify' });
            if (m.cancel === true) { state.notes.delete(m.tag); post({ id: m.id }); return; }
            if (![m.title, m.text].every((x) => typeof x === 'string' && x.length >= 1 && x.length <= 100)) throw Object.assign(new Error('title, text'), { check: 'notify' });
            if (!state.granted) throw Object.assign(new Error('not allowed'), { check: 'notify_permission' });
            state.notes.set(m.tag, { title: m.title, text: m.text, keys: Object.keys(m).sort().join() });
            post({ id: m.id });
          }
          else if (m.op === 'unlock') { state.forced.push(m.force === true); state.unlocks = (state.unlocks ?? 0) + 1; if (state.locked) throw Object.assign(new Error('the screen lock was not confirmed'), { check: 'cancelled' }); post({ id: m.id }); }
          else throw Object.assign(new Error(`no op ${m.op}`), { check: 'op' });
        } catch (e) { if (m.id !== undefined) post({ id: m.id, error: { check: e.check ?? 'connect', message: e.message } }); }
      };
      setTimeout(() => {
        target.dispatchEvent(new MessageEvent('message', { data: 'sigelo-bridge/0', ports: [port2] }));
        if (state.pendingOpen) { post({ ev: 'open', tag: state.pendingOpen }); state.pendingOpen = null; }
      });
    },
  };
  const open = (tag) => current?.postMessage(JSON.stringify({ ev: 'open', tag }));
  return { shell, target, state, log, keys, open, connect: () => A.connectBridge({ shell, target }) };
}



// ================================================================ 1c. MQTT.js as a page runs it: the relay's CONNACK acted on
// In a page (window and document there when it loads) MQTT.js's browser build keeps its keepalive on
// worker-timers: a Worker from a blob: URL, which the page's CSP (worker-src 'self') refuses, thrown
// inside the CONNACK's handling. On the phone: the CONNECT out, the relay's answer in within 100 ms,
// then nothing from the client, and "the relay closed the connection". Here: the bundle loaded as in a
// page, a Worker refusing blob: as that CSP does, and a scripted shell answering the CONNECT with a
// CONNACK in three posts a few ms apart (mqtts through the bridge), or one message (a page's wss).
{
  const saved = { window: Object.getOwnPropertyDescriptor(globalThis, 'window'), document: Object.getOwnPropertyDescriptor(globalThis, 'document'), Worker: Object.getOwnPropertyDescriptor(globalThis, 'Worker') };
  const restore = (k) => { if (saved[k]) Object.defineProperty(globalThis, k, saved[k]); else delete globalThis[k]; };
  globalThis.window = globalThis; globalThis.document = {};
  globalThis.Worker = class { constructor(u) { if (/^blob:/.test(String(u))) throw new DOMException(`Failed to construct 'Worker': access to the script at '${u}' is denied by the document's Content Security Policy`, 'SecurityError'); throw new Error('no Worker here'); } };
  const pageMqtt = (await import(pathToFileURL(join(HERE, 'vendor', 'mqtt.esm.js')).href + '?as-a-page')).default;
  restore('window'); restore('document');
  const thrown = [], catcher = (e) => thrown.push(e?.message ?? String(e));
  process.on('uncaughtException', catcher); process.on('unhandledRejection', catcher);
  const CONNACK = [[0x20], [0x02, 0x00], [0x00]];
  const scripted = () => {
    const target = new EventTarget(), log = { writes: 0, closed: 0 };
    const shell = {
      info: () => JSON.stringify({ v: 'sigelo-shell/0', mode: 'self', wipe: false, version: 'test' }),
      connect() {
        const { port1, port2 } = new MessageChannel(), post = (x) => port1.postMessage(JSON.stringify(x));
        port1.onmessage = (ev) => {
          const m = JSON.parse(ev.data);
          if (m.op === 'tls') post({ id: m.id, stream: 7 });
          else if (m.op === 'write') { post({ id: m.id }); if (log.writes++ === 0) CONNACK.forEach((c, i) => setTimeout(() => post({ s: 7, data: Buffer.from(c).toString('base64') }), 5 + 10 * i)); }
          else if (m.op === 'close') log.closed++;
        };
        setTimeout(() => target.dispatchEvent(new MessageEvent('message', { data: 'sigelo-bridge/0', ports: [port2] })));
      },
    };
    return { log, connect: () => A.connectBridge({ shell, target }) };
  };
  const opts = { protocolVersion: 4, clean: false, clientId: 'c'.repeat(40), username: 'did:sigelo:z' + 'u'.repeat(48), password: 'p'.repeat(1100), reconnectPeriod: 0, connectTimeout: 3000, keepalive: 60, resubscribe: false, wsOptions: { maxPayload: 1 << 20 } };
  const outcome = (client) => new Promise((y) => { client.once('connect', () => y('connect')); client.once('error', (e) => y(`error: ${e.message}`)); client.once('close', () => y('close')); setTimeout(() => y('nothing in 3.5 s'), 3500); });
  const S1 = scripted(), b1 = await S1.connect(), c1 = A.bridgeMqtt(b1, pageMqtt)('mqtts://relay.test:8883', opts), r1 = await outcome(c1);
  ok(r1 === 'connect' && c1.connected && thrown.length === 0, `mqtts in a page: a CONNACK in three posts after the CONNECT is acted on, keepalive and all (${r1}; ${thrown.join('; ') || 'nothing thrown'})`);
  c1.end(true);
  thrown.length = 0;
  const fakeWs = () => { const s = { readyState: 0, OPEN: 1, CONNECTING: 0, CLOSING: 2, CLOSED: 3, bufferedAmount: 0, binaryType: 'arraybuffer', onopen: null, onmessage: null, onclose: null, onerror: null, close() {},
    send() { setTimeout(() => s.onmessage?.({ data: Uint8Array.of(0x20, 2, 0, 0).buffer })); } };
    setTimeout(() => { s.readyState = 1; s.onopen?.({}); }); return s; };
  const c2 = W.pageMqtt(pageMqtt, { createWebsocket: fakeWs })('wss://relay.test/mqtt', opts), r2 = await outcome(c2);
  ok(r2 === 'connect' && c2.connected && thrown.length === 0, `wss in a page (platform-web.mjs): the CONNACK acted on (${r2}; ${thrown.join('; ') || 'nothing thrown'})`);
  c2.end(true);
  await sleep(50);
  process.off('uncaughtException', catcher); process.off('unhandledRejection', catcher);
  restore('Worker');
}

// ================================================================ 1b. restore from seed in the Android app (seed.mjs), no relay needed
{
  const SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href);
  const { mnemonicFromRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
  const S0 = new Uint8Array(32).fill(5); S0[31] = 0x0f;
  const words = mnemonicFromRoot(S0), list = words.split(' '), sHex = Buffer.from(S0).toString('hex');
  // Any 3 words of the seed in a row, anywhere: the seed or a part of it.
  const leaks = (text) => { const t = String(text).toLowerCase(); for (let i = 0; i + 3 <= list.length; i++) if (t.includes(list.slice(i, i + 3).join(' '))) return true; return t.includes(sHex); };
  const F = fakeShell({ mode: 'self' }), bridge = await F.connect(), idb = new FakeIDB();
  const p = await A.androidPlatform({ bridge, mqtt: mqttEsm, indexedDB: idb, pow: A.androidPow(W.workerPow(() => new FakeWorker())) });
  const tries = [], ops0 = F.log.ops.length, said = [];
  // The flush, watched: while the restore runs, the shell's network refuses before anything reaches the shell.
  const watched = { ...p, flush: async () => { tries.push(await checkOf(() => bridge.https('https://relay.test/x')), await checkOf(() => bridge.tls('relay.test', 8883)), await checkOf(() => p.fetch('https://relay.test/y'))); return p.flush(); } };
  const keep = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  for (const k of Object.keys(keep)) console[k] = (...a) => { said.push(a.map(String).join(' ')); };
  let r;
  try { r = await SD.restoreInto(watched, { words, name: 'phone', relay: 'relay.sigelo.ai', net: 'stagenet', restore: {}, seat: 'here', now: 1761400000 }); } finally { Object.assign(console, keep); }
  const during = F.log.ops.slice(ops0);
  ok(tries.length >= 3 && tries.every((x) => x === 'restoring'), `restore: the network held while it runs: the shell's https and tls and the page's fetch refused restoring (${tries})`);
  ok(!during.includes('https') && !during.includes('tls') && during.filter((o) => o === 'seal').length === 2, `restore: nothing reached the network; two seals (${during})`);
  ok(F.log.seals.length === 2 && F.log.seals.every((x) => x.full === true && x.alias === 1) && F.log.seals.map((x) => x.kind).join() === 'identity,keeper',
    'restore: the identity and the keeper sealed by the shell under the FULL key (screen lock or biometric), the keeper as its own kind');
  ok(await checkOf(() => bridge.https('https://relay.test/z')) !== 'restoring' && W.network.held === 0, 'restore: the network free again after the last commit');
  const files = idb.dbs.get('sigelo').stores.get('files'), stored = [...files.values()].map((v) => Buffer.from(v).toString('latin1')).join('\n');
  ok(files.has('identity.keystore') && files.has('keeper.keystore') && !files.has('identity.sealed') && !leaks(stored) && !stored.includes('root_hex') && !stored.includes('"secret"'),
    'restore: the words, S, the key and K_1 are nowhere in the app\'s storage in the clear (only identity.keystore, keeper.keystore)');
  ok(!said.some(leaks) && said.length === 0, `restore: nothing logged at all (${said.length} lines)`);
  const id = JSON.parse(new TextDecoder().decode(await W.loadIdentity(p))), kp = JSON.parse(new TextDecoder().decode(await W.loadSealed(p, 'keeper')));
  ok(id.derived?.n === 0 && kp.v === 'sigelo-keeper-hot/0' && kp.keeper === 1 && kp.net === 'stagenet' && kp.restore_height === 0 && kp.me.did === r.did && r.seat === 'here',
    'restore: the sealed files open again: the operator (derived n 0) and K_1 (stagenet, no height or date given → restore_height 0)');
  F.state.locked = true;
  ok(await checkOf(() => W.loadSealed(p, 'keeper')) === 'cancelled' && await checkOf(() => bridge.open(p.files.read('keeper.keystore'), { kind: 'identity' })) === 'cancelled', 'restore: K_1 opens only after the screen lock (cancelled: asked again)');
  F.state.locked = false;
  ok(await checkOf(() => bridge.open(p.files.read('keeper.keystore'), { kind: 'control' })) === 'sealed', 'restore: the keeper never opens as another kind');
  const seat = SD.seatOf(p, () => id), info = seat.info();
  ok(info?.here === true && info.holder === 'phone' && info.epoch === 1 && seat.restored()?.on === '2025-10-25' && seat.restored().keeper === 1 && seat.restored().seat === 'here',
    'restore: this phone is the first FULL device and holds the seat (epoch 1); Me: restored on the day, keeper 1, seat here');
  const set = JSON.parse(new TextDecoder().decode(p.files.read(SD.SETTINGS)));
  ok(set.mode.kind === 'full' && set.mode.standby === false && !leaks(JSON.stringify(set)), 'restore: settings: FULL, not standby');
  // The screen: FLAG_SECURE and the clipboard through the shell.
  await bridge.secure(true);
  const on = F.state.secure;
  await bridge.secure(false); await bridge.clipClear();
  ok(on === true && F.state.secure === false && F.state.clipCleared === 1, 'shell: FLAG_SECURE on and off (secure), the clipboard cleared (clip-clear)');
  const WM = await import(pathToFileURL(join(HERE, 'welcome.mjs')).href);
  ok(WM.WORDS_ATTRS.autocomplete === 'off' && WM.WORDS_ATTRS.autocorrect === 'off' && WM.WORDS_ATTRS.autocapitalize === 'none' && WM.WORDS_ATTRS.spellcheck === 'false',
    'welcome.mjs: the words\' boxes without autocomplete, autocorrect, capitals or spellcheck');
  // The code, not its comments: no way from a root to its 25 words anywhere; the words shown again only by Settings → Backup and recovery
  // (design/apps-seed.md §8), from what the words password opens (WORDS.reveal), nowhere else.
  const uiSrc = readFileSync(join(REPO, 'apps', 'agent', 'ui.js'), 'utf8'), secAt = uiSrc.indexOf('// ---- SECURITY'), secEnd = uiSrc.indexOf('const WORDS_VIEWS');
  const pages = ['app.mjs', 'boot.mjs', 'profiles.mjs', 'computers.mjs', 'shell.mjs', 'seed.mjs', 'router.mjs', 'create.mjs', 'setup.mjs', 'welcome.mjs', 'words.mjs'].map((f) => readFileSync(join(HERE, f), 'utf8')).join('\n') + uiSrc.slice(0, secAt) + uiSrc.slice(secEnd);
  // The lock rule's sentence (the mock's: "… pay above your limit or show your 25 words") names the words; it shows none.
  const code = pages.split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n').replace(/Asked only when you open the app[^']*'/g, "'"), sec = uiSrc.slice(secAt, secEnd);
  ok(secAt > 0 && secEnd > secAt && !/show (the |your )?(seed|25 words)|show seed|mnemonicFromRoot|encodeMoneroWords|newRoot/i.test(code) && !/mnemonicFromRoot|encodeMoneroWords|newRoot|clipboard|copy\(/.test(sec)
    && (sec.match(/WORDS\.reveal\(/g) ?? []).length === 1 && /const r = await WORDS\.reveal\(pw\.value\)/.test(sec),
    'no "show seed" outside Settings → Backup and recovery; there, the words only from what the password opens (WORDS.reveal), nothing turns a root into words, nothing copied');
  // Seat elsewhere: a standby; the seat taken later signs the list naming this phone.
  const F2 = fakeShell({ mode: 'self' }), b2 = await F2.connect(), p2 = await A.androidPlatform({ bridge: b2, mqtt: mqttEsm, indexedDB: new FakeIDB(), pow: A.androidPow(W.workerPow(() => new FakeWorker())) });
  await SD.restoreInto(p2, { words, name: 'tab', relay: '', restore: { restore_date: '2024-02-29' }, seat: 'elsewhere', now: 1761400000 });
  const id2 = JSON.parse(new TextDecoder().decode(await W.loadIdentity(p2))), s2 = SD.seatOf(p2, () => id2);
  ok(s2.info().here === false && p2.files.read(SD.LIST) === null && JSON.parse(new TextDecoder().decode(await W.loadSealed(p2, 'keeper'))).restore_date === '2024-02-29' && JSON.parse(new TextDecoder().decode(p2.files.read(SD.SETTINGS))).mode.standby === true,
    'restore, seat elsewhere: a standby, no list here, restore_date kept');
  const t = await s2.take(1761400100);
  ok(t.holder === 'tab' && t.seat.epoch === 1 && s2.info().here === true && s2.restored().seat === 'here' && JSON.parse(new TextDecoder().decode(p2.files.read(SD.SETTINGS))).mode.standby === false, 'seat take: the list signed naming this phone, the seat here');
  ok(await checkOf(() => SD.restoreInto(p2, { words: list.slice(0, 24).join(' '), name: 'tab', relay: '', seat: 'here', now: 1761400000 })) === 'restore_words' && W.network.held === 0, 'restore: 24 words refused restore_words, the network released');
}

// ================================================================ 1c. the first run in the Android app (welcome.mjs over setup.mjs), its
// screens driven through a minimal DOM (the mock's words): the welcome, Back, create (Keep it safe: the 25 words once, FLAG_SECURE,
// Back swallowed, the check; or a password), the lock, You're set, restore, connect, join, and the form set only when a path commits.
class FakeEl {
  constructor(tag) { Object.assign(this, { tagName: tag.toUpperCase(), kids: [], attrs: {}, style: {}, on: {}, text: '', value: '', checked: false, disabled: false, hidden: false, className: '', parent: null }); }
  get textContent() { return this.text + this.kids.map((k) => (typeof k === 'string' ? k : k.textContent)).join(''); }
  set textContent(t) { this.kids = []; this.text = String(t); }
  append(...k) { for (const x of k) { if (x === '') continue; this.kids.push(x); if (typeof x === 'object') x.parent = this; } }
  replaceChildren(...k) { this.kids = []; this.text = ''; this.append(...k); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { (this.on[t] ??= []).push(f); }
  contains(x) { return this.all().includes(x); }
  focus() {}
  getContext() { return {}; }   // a canvas (the scan's), never drawn on here
  get firstChild() { return this.kids.find((k) => typeof k === 'object') ?? null; }
  all() { return [this, ...this.kids.filter((k) => typeof k === 'object').flatMap((k) => k.all())]; }
}
{
  const WM = await import(pathToFileURL(join(HERE, 'welcome.mjs')).href), SU = await import(pathToFileURL(join(HERE, 'setup.mjs')).href);
  const saved = Object.fromEntries(['document', 'location', 'history', 'addEventListener', 'removeEventListener'].map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
  const restoreGlobals = () => { for (const [k, d] of Object.entries(saved)) { if (d) Object.defineProperty(globalThis, k, d); else delete globalThis[k]; } };
  const listeners = new Map(), pushed = [];
  const pop = () => listeners.get('popstate')?.();
  Object.assign(globalThis, {
    document: { createElement: (t) => new FakeEl(t) },
    location: { hash: '', href: 'https://appassets.androidplatform.net/index.html', reload() {} },
    history: { pushState: (...a) => { pushed.push(a); }, back: () => pop() },
    addEventListener: (t, f) => listeners.set(`${t}`, f), removeEventListener: (t) => listeners.delete(`${t}`),
  });
  const said = [], keep = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  const F = fakeShell({ mode: null }), bridge = await F.connect(), idb = new FakeIDB();
  const p = await A.androidPlatform({ bridge, mqtt: mqttEsm, indexedDB: idb, pow: A.androidPow(W.workerPow(() => new FakeWorker())) });
  const box = new FakeEl('div'), buttons = () => box.all().filter((e) => e.tagName === 'BUTTON'), button = (t) => buttons().find((e) => e.textContent === t);
  const title = () => box.all().find((e) => e.tagName === 'H1')?.textContent;
  let reloaded = 0;
  for (const k of Object.keys(keep)) console[k] = (...a) => { said.push(a.map(String).join(' ')); };
  try {
    const api = SU.setupApi(p, { bridge, mqtt: mqttEsm, storage: new Map(), reload: () => { reloaded++; } });
    const fr = WM.firstRun(box, api);
    const welcome = buttons().filter((b) => b.parent?.className === 'choices').map((b) => b.textContent);
    ok(welcome.join('|') === 'Create my identity|Restore from 25 words|Use my computer instead' && !box.all().some((e) => ['INPUT', 'TEXTAREA'].includes(e.tagName))
      && box.textContent.includes('One identity for you and your agents.') && box.textContent.includes('Chat with people and agents, privately. Let your agents act for you, within limits you set.')
      && box.all().some((e) => e.tagName === 'DETAILS' && e.textContent.includes('Import a device file')) && F.state.mode === null,
      'welcome (the mock\'s words): sigelo, what it is, Create my identity, Restore from 25 words, Use my computer instead (no invite code where the shell keeps none); no field; the import under Advanced; no form set yet');
    button('Create my identity').onclick();
    ok(title() === 'Name this phone' && button('‹') && button('Next') && box.textContent.includes('Step 1 of 3') && box.all().some((e) => e.tagName === 'DETAILS' && /More options/.test(e.textContent) && /Monero network/.test(e.textContent) && /Relay/.test(e.textContent)),
      'create 1: Name this phone, Step 1 of 3, Next, Back; the network and the relay under More options');
    button('‹').onclick();
    ok(title() === 'sigelo' && button('Create my identity') && pushed.length === 1, 'Back: one step, to the welcome (one history entry per screen)');
    button('Create my identity').onclick();
    box.all().find((e) => e.tagName === 'SELECT').value = 'stagenet';
    await button('Next').onclick();
    const card = (t) => buttons().find((e) => e.textContent.startsWith(t));
    ok(title() === 'Keep it safe' && box.textContent.includes('Step 2 of 3') && box.textContent.includes('Choose how to protect your identity') && card('Write down 25 words') && card('Set a password')
      && box.textContent.includes('On paper. They bring everything back on any phone. Safest.') && box.textContent.includes('The words stay on this phone, locked by it. Lose the phone and they are gone.') && W.network.held === 0,
      'create 2: Keep it safe, the mock\'s two ways (25 words on paper, or a password); nothing drawn yet');
    await card('Write down 25 words').onclick();
    await sleep(50);
    const ol = box.all().find((e) => e.tagName === 'OL'), list = ol?.kids.map((li) => li.textContent) ?? [];
    const leaks = (text) => { const t = String(text).toLowerCase(); for (let i = 0; i + 3 <= list.length; i++) if (t.includes(list.slice(i, i + 3).join(' '))) return true; return false; };
    ok(list.length === 25 && /seed-list/.test(ol.className) && W.network.held >= 1 && title() === 'Your 25 words' && box.textContent.includes('Write these words on paper, in order.'), 'create 2: the 25 words once, in an ordered list (numbered by the list); the network held');
    const before = pushed.length;
    pop();
    ok(F.state.secure === true && F.state.door === true && !button('‹') && title() === 'Your 25 words' && pushed.length === before + 1 && button('I wrote them down'),
      'create 2: FLAG_SECURE on, the system Back swallowed (door), the page\'s Back held too; no Back button, one way on');
    const vault = box.all().find((e) => e.tagName === 'P' && /^5\w{94}$/.test(e.textContent))?.textContent;
    await button('Copy (test network only)').onclick();
    ok(typeof vault === 'string' && F.state.clip?.text === list.join(' ') && F.state.clip.clear === 60, 'create 2, test network: the wallet\'s address (folded); copy through the shell, emptied by it after 60 s');
    button('I wrote them down').onclick();
    await sleep(50);
    const asked = () => box.all().filter((e) => e.tagName === 'LABEL').map((e) => Number(/^Word (\d+)$/.exec(e.textContent)?.[1])).filter(Boolean), inputs = () => box.all().filter((e) => e.tagName === 'INPUT');
    const q1 = asked();
    ok(F.state.clipCleared >= 1 && F.state.clip === null && !box.all().some((e) => e.tagName === 'OL') && title() === 'Check your paper' && q1.length === 3 && !button('‹')
      && box.textContent.includes('Type these three words from your paper. You can\'t go on without them.')
      && inputs().every((x) => x.attrs.autocomplete === 'off' && x.attrs.spellcheck === 'false'), `create 2, check: the clipboard emptied, the words gone, three asked by number (${q1}), no Back`);
    inputs().forEach((x, i) => { x.value = i === 0 ? (list[q1[0] % 25] === list[q1[0] - 1] ? 'zzz' : list[q1[0] % 25]) : list[q1[i] - 1]; });
    await button('Check').onclick();
    await sleep(50);
    ok(title() === 'Check your paper' && !box.all().some((e) => e.tagName === 'OL') && box.textContent.includes(`Word ${q1[0]} did not match`) && p.files.read('identity.keystore') === null && F.state.mode === null,
      'create 2, check: a wrong word named by its number, asked again; the 25 not shown again unasked; nothing sealed, no form set');
    button('Show the words again').onclick();
    ok(box.all().some((e) => e.tagName === 'OL') && F.state.secure === true, 'create 2, check: "Show the words again" (asked for) shows them, still behind FLAG_SECURE');
    button('I wrote them down').onclick();
    await sleep(50);
    const q2 = asked();
    inputs().forEach((x, i) => { x.value = list[q2[i] - 1]; });
    await button('Check').onclick();
    // Step 3, the lock: the phone's screen lock asked once; no Back (the identity is made).
    await until(() => title() === 'Lock', 5000);
    await until(() => F.state.secure === false, 2000);
    const u0 = F.log.ops.filter((o) => o === 'unlock').length, back0 = pushed.length;
    pop();
    ok(box.textContent.includes('Step 3 of 3') && box.textContent.includes('Lock sigelo with your fingerprint or PIN') && box.textContent.includes('Asked only when you open the app, switch profile, pay above your limit or show your 25 words.')
      && button('Use my phone\'s lock') && !button('‹') && pushed.length === back0 + 1 && reloaded === 0, 'create 3: Lock (the mock\'s words), Use my phone\'s lock; Back held (the identity is made)');
    await button('Use my phone\'s lock').onclick();
    await until(() => title() === 'You\'re set', 3000);
    const chips = box.all().find((e) => e.className === 'words4');
    ok(F.log.ops.filter((o) => o === 'unlock').length === u0 + 1 && chips?.kids.length === 4 && box.textContent.includes('Your four words') && button('Open sigelo') && button('×'),
      'create 3 → You\'re set: the screen lock asked once (bridge unlock), the four words, Open sigelo, Close');
    await button('Open sigelo').onclick();
    await until(() => reloaded === 1, 5000);
    await sleep(100);
    ok(p.files.read('words.keystore') === null && p.files.read('words.sealed') === null && !F.log.seals.some((x) => x.kind === 'words'), 'create, paper: no password asked, no words kept (the mock\'s gate: one or the other)');
    ok(reloaded === 1 && F.state.mode === 'self' && F.log.seals.length === 2 && F.log.seals.every((x) => x.full === true && x.alias === 1) && F.state.secure === false && F.state.door === false && W.network.held === 0,
      `create: the form set to self at the commit, identity and keeper sealed under the FULL key, FLAG_SECURE off, the network released, the page restarts (${F.state.secureLog})`);
    const files = idb.dbs.get('sigelo').stores.get('files'), stored = [...files.values()].map((v) => Buffer.from(v).toString('latin1')).join('\n');
    const kp = JSON.parse(new TextDecoder().decode(await W.loadSealed(p, 'keeper')));
    ok(files.has('identity.keystore') && files.has('keeper.keystore') && !leaks(stored) && said.length === 0 && kp.made === 'here' && kp.net === 'stagenet' && kp.restore_date === kp.created
      && !leaks(JSON.stringify(box.all().map((e) => [e.textContent, e.value]))),
      `create: no word in storage or left on the screen, nothing logged (${said.length}); the keeper made here, stagenet, the wallet's birth its creation day`);
    fr.stop();
  } finally { Object.assign(console, keep); }

  // Mainnet: no copy, the list not selectable, a copy refused; leaving drops the words.
  {
    const F2 = fakeShell({ mode: null }), b2 = await F2.connect(), p2 = await A.androidPlatform({ bridge: b2, mqtt: mqttEsm, indexedDB: new FakeIDB(), pow: A.androidPow(W.workerPow(() => new FakeWorker())) });
    const box2 = new FakeEl('div'), fr2 = WM.firstRun(box2, SU.setupApi(p2, { bridge: b2, mqtt: mqttEsm, storage: new Map(), reload() {} }));
    const b = (t) => box2.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith(t));
    b('Create my identity').onclick();
    await b('Next').onclick();
    await b('Write down 25 words').onclick();
    const g = box2.all().find((e) => e.tagName === 'OL');
    let prevented = false;
    g.on.copy?.forEach((f) => f({ preventDefault: () => { prevented = true; } }));
    ok(!box2.all().some((e) => e.tagName === 'BUTTON' && /Copy/.test(e.textContent)) && box2.textContent.includes('No copy, no screenshot: write them by hand. Never type them into a website.') && /nocopy/.test(g.className) && prevented,
      'create 2, main network: no copy button, the words not selectable, a copy refused, the mock\'s line');
    fr2.stop();
    await sleep(50);
    ok(W.network.held === 0 && F2.state.secure === false && F2.state.mode === null, 'leaving: the words dropped, the network released, FLAG_SECURE off, no form set');
  }

  // Keep it safe → Set a password: the words drawn and kept here under it, never shown; the identity made; the lock; done.
  {
    const F6 = fakeShell({ mode: null }), b6 = await F6.connect(), p6 = await A.androidPlatform({ bridge: b6, mqtt: mqttEsm, indexedDB: new FakeIDB(), pow: A.androidPow(W.workerPow(() => new FakeWorker())) });
    let reloads = 0;
    const box6 = new FakeEl('div'), fr6 = WM.firstRun(box6, SU.setupApi(p6, { bridge: b6, mqtt: mqttEsm, storage: new Map(), reload: () => { reloads++; } }));
    const b = (t) => box6.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith(t)), t6 = () => box6.all().find((e) => e.tagName === 'H1')?.textContent;
    b('Create my identity').onclick();
    await b('Next').onclick();
    b('Set a password').onclick();
    const pws = box6.all().filter((e) => e.tagName === 'INPUT' && e.type === 'password');
    ok(t6() === 'Set a password' && pws.length === 2 && pws.every((x) => x.attrs.autocomplete === 'new-password') && box6.textContent.includes('It locks your 25 words on this phone. You need it to see them again in Settings.')
      && b('Set password') && b('‹'), 'Set a password (the mock\'s words): the password and its repeat, Set password, Back to the choice');
    pws[0].value = 'short'; pws[1].value = 'short';
    await b('Set password').onclick();
    const tooShort = /at least 8 characters/.test(box6.textContent) && t6() === 'Set a password';
    pws[0].value = 'long enough'; pws[1].value = 'long enougj';
    await b('Set password').onclick();
    const differ = /not the same/.test(box6.textContent) && p6.files.read('words.keystore') === null;
    pws[0].value = 'correct horse'; pws[1].value = 'correct horse';
    await b('Set password').onclick();
    await until(() => t6() === 'Lock', 15000);
    const wseal = F6.log.seals.find((x) => x.kind === 'words');
    ok(tooShort && differ && wseal?.full === true && wseal.alias === 1 && F6.state.mode === 'self' && !box6.all().some((e) => e.tagName === 'OL'),
      'Set password: too short or not the same said; then the identity made and its words kept as kind words under the FULL key, never on the screen; then the lock');
    await b('Use my phone').onclick();
    await until(() => t6() === 'You\'re set', 3000);
    await b('Open sigelo').onclick();
    await until(() => reloads === 1, 5000);
    const WL = await import(pathToFileURL(join(HERE, 'vendor', 'contact', 'words-lock.mjs')).href);
    const kept = await W.loadSealed(p6, 'words');
    ok(reloads === 1 && (await WL.openWords(kept, 'correct horse')).words.length === 25 && await checkOf(() => WL.openWords(kept, 'correct horsf')) === 'words_password' && W.network.held === 0,
      'Set password: the 25 words kept, opened by that password only; the page restarts');
    fr6.stop();
  }

  // Restore: one screen (the words checked as typed, when they were made, main or spare), the network and the form set at the commit.
  {
    const { mnemonicFromRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
    const S0 = new Uint8Array(32).fill(7); S0[31] = 0x0e;
    const words = mnemonicFromRoot(S0);
    const F3 = fakeShell({ mode: null }), b3 = await F3.connect(), p3 = await A.androidPlatform({ bridge: b3, mqtt: mqttEsm, indexedDB: new FakeIDB(), pow: A.androidPow(W.workerPow(() => new FakeWorker())) });
    let reloads = 0;
    const box3 = new FakeEl('div'), fr3 = WM.firstRun(box3, SU.setupApi(p3, { bridge: b3, mqtt: mqttEsm, storage: new Map(), reload: () => { reloads++; } }));
    const b = (t) => box3.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith(t)), t3 = () => box3.all().find((e) => e.tagName === 'H1')?.textContent;
    b('Restore from 25 words').onclick();
    const ta = box3.all().find((e) => e.tagName === 'TEXTAREA'), count = () => box3.all().find((e) => e.id === 'seed-count')?.textContent;
    const type = (v) => { ta.value = v; ta.on.input.forEach((f) => f()); };
    type(words.split(' ').slice(0, 24).join(' ') + ' zzzz');
    const bad = count(), off = b('Restore').disabled;
    type(words);
    await sleep(50);
    const seatRadios = box3.all().filter((e) => e.tagName === 'INPUT' && e.name === 'seed-seat');
    ok(t3() === 'Restore' && /word 25 is not in the Monero word list/.test(bad) && off && count() === '25 words, checked' && !b('Restore').disabled && F3.state.secure === true
      && box3.textContent.includes('Your 25 words, in order') && box3.textContent.includes('When were they made? (optional)') && box3.textContent.includes('Makes the wallet ready faster. Empty: it reads from the start.')
      && box3.textContent.includes('Is this identity already in use on another device?') && box3.textContent.includes('No, make this phone the main one') && box3.textContent.includes('Yes, keep this phone as a spare')
      && seatRadios.length === 2 && seatRadios.find((e) => e.value === 'here')?.checked === true && box3.all().some((e) => e.tagName === 'DETAILS' && /More options/.test(e.textContent) && /Relay/.test(e.textContent)),
      `restore (one screen, the mock's words): the words checked as typed (${bad}), Restore only on a good checksum; when they were made; main or spare (main the default); More options; FLAG_SECURE on`);
    b('‹').onclick();
    ok(box3.all().find((e) => e.tagName === 'H1')?.textContent === 'sigelo', 'Back from Restore: to the welcome');
    await sleep(20);
    ok(F3.state.secure === false, 'Back from Restore: the words dropped, FLAG_SECURE off');
    b('Restore from 25 words').onclick();
    const ta2 = box3.all().find((e) => e.tagName === 'TEXTAREA');
    ok(ta2.value === '', 'Restore again: the box empty (the words were dropped at Back)');
    ta2.value = words; ta2.on.input.forEach((f) => f());
    box3.all().find((e) => e.tagName === 'INPUT' && e.type === 'month').value = '2024-02';
    await b('Restore').onclick();
    await until(() => t3() === 'Lock', 10000);
    await b('Use my phone').onclick();
    await until(() => t3() === 'Restored', 3000);
    ok(box3.all().find((e) => e.className === 'words4')?.kids.length === 4 && box3.textContent.includes('Your identity is back'), 'restore → the lock → done: the four words');
    await b('Open sigelo').onclick();
    await until(() => reloads === 1, 10000);
    await sleep(100);
    const kp = JSON.parse(new TextDecoder().decode(await W.loadSealed(p3, 'keeper')));
    ok(reloads === 1 && F3.state.mode === 'self' && kp.restore_date === '2024-02-01' && F3.state.secure === false && W.network.held === 0 && !F3.log.seals.some((x) => x.kind === 'words'),
      `restore: sealed, the month as its first day (${kp.restore_date}), the form set to self at the commit, FLAG_SECURE off, the page restarts; no words kept`);
    fr3.stop();
  }
  // Connect: an 8-character code is all the first screen asks; a plain tab says it needs the app.
  {
    const box4 = new FakeEl('div'), fr4 = WM.firstRun(box4, SU.setupApi(p, { bridge: null, mqtt: mqttEsm, storage: new Map(), reload() {} }));
    const b = (t) => box4.all().find((e) => e.tagName === 'BUTTON' && e.textContent === t);
    b('Use my computer instead').onclick();
    const code = box4.all().find((e) => e.className === 'code-in');
    code.value = 'k7f3q9zp'; code.on.input.forEach((f) => f());
    await b('Connect').onclick();
    ok(code.value === 'K7F3-Q9ZP' && box4.all().find((e) => e.tagName === 'H1')?.textContent === 'Use my computer' && box4.textContent.includes('Or type its code')
      && box4.textContent.includes('Your identity stays on your computer. This phone becomes its remote: it holds no key of yours.') && /needs the app/.test(box4.textContent),
      'Use my computer (the mock\'s words): its code formatted as typed; without the shell, a message, not a blank');
    fr4.stop();
  }
  // Join (I have an invite code; the Add sheet's way): the code first, kept (api.join), then the name and Join.
  {
    const box5 = new FakeEl('div'), joined = [], fr5 = WM.firstRun(box5, { ...SU.setupApi(p, { bridge: null, mqtt: mqttEsm, storage: new Map(), reload() {} }), join: (c) => joined.push(c) });
    const t5 = () => box5.all().find((e) => e.tagName === 'H1')?.textContent, b = (t) => box5.all().find((e) => e.tagName === 'BUTTON' && e.textContent === t);
    ok(b('I have an invite code'), 'welcome: I have an invite code, where the shell keeps one (api.join)');
    fr5.start('join');
    const code = box5.all().find((e) => e.className === 'code-in');
    ok(t5() === 'Join from an invite' && code && b('Next') && b('‹') && box5.textContent.includes('Invite code') && box5.textContent.includes('Enter it, and you\'ll be chatting with them in a minute.'),
      'Join from an invite: its first screen, the code (Back to the welcome)');
    code.value = 'nope'; await b('Next').onclick();
    ok(t5() === 'Join from an invite' && /8 letters and digits/.test(box5.textContent) && joined.length === 0, 'Join: not a code → said, nothing kept');
    code.value = 'k7f3-q9zp'; await b('Next').onclick();
    ok(joined.join() === 'K7F3-Q9ZP' && t5() === 'Name this phone' && b('Join') && /Then you protect it with 25 words or a password/.test(box5.textContent), 'Join: the code kept for the new page (api.join), then Name this phone and Join');
    fr5.stop();
    for (const [path, want] of [['restore', 'Restore'], ['computer', 'Use my computer'], ['create', 'Name this phone']]) {
      const bx = new FakeEl('div'), f = WM.firstRun(bx, SU.setupApi(p, { bridge: null, mqtt: mqttEsm, storage: new Map(), reload() {} }));
      f.start(path);
      ok(bx.all().find((e) => e.tagName === 'H1')?.textContent === want, `Add → ${path}: the first run opens at ${want}`);
      f.stop();
    }
  }
  restoreGlobals();
  const src = readFileSync(join(HERE, 'setup.mjs'), 'utf8').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
  ok(!/mnemonicFromRoot|encodeMoneroWords|newRoot\b|localStorage\.setItem|sessionStorage|console\./.test(src) && /session\.words\(\)/.test(src), 'setup.mjs: the words only from the session (apps/contact/create.mjs), never stored or logged');
}

// ================================================================ 1d. profiles (profiles.mjs, boot.mjs; design/profiles.md P1) over the fake shell:
// a single-profile install migrated as p1 (nothing resealed), add, the picker and the lock, the switch (the lock once,
// none at the new profile's start), rename, the limit of 8, remove (the words ticked, the name typed, the lock, the wipe:
// database, keystore aliases, storage), and the proof-of-work counts per profile (each its own carrier state).
{
  const SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href), B = await import(pathToFileURL(join(HERE, 'boot.mjs')).href);
  const PR = await import(pathToFileURL(join(HERE, 'profiles.mjs')).href);
  const { mnemonicFromRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
  const { did: didOf } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href);
  const wordsOf = (b) => { const S = new Uint8Array(32).fill(b); S[31] = 0x0f; return mnemonicFromRoot(S); };
  const saved = Object.fromEntries(['document', 'location', 'history', 'addEventListener', 'removeEventListener'].map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
  Object.assign(globalThis, { document: { createElement: (t) => new FakeEl(t) }, location: { hash: '', reload() {} }, history: { pushState() {}, back() {} }, addEventListener() {}, removeEventListener() {} });
  const memStore = () => { const m = new Map(); return { m, get length() { return m.size; }, key: (i) => [...m.keys()][i] ?? null, getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
  const F = fakeShell({ mode: 'self' }), idb = new FakeIDB(), storage = memStore(), pow = A.androidPow(W.workerPow(() => new FakeWorker()));
  const unlocks = () => F.log.ops.filter((o) => o === 'unlock').length;
  let reloads = 0, app = null;
  const page = (session = memStore()) => {
    const box = new FakeEl('section'), main = new FakeEl('main');
    app = B.boot({ shell: F.shell, target: F.target, box, main, mqtt: mqttEsm, indexedDB: idb, storage, session, reload: () => { reloads++; }, pow });
    return { box, main, session, app };
  };
  const stopApp = async () => { try { await (await app.ready).stop?.(); } catch {} };
  const title = (box) => box.all().find((e) => e.tagName === 'H1')?.textContent;
  const regOf = () => JSON.parse(new TextDecoder().decode(idb.dbs.get(PR.REGISTRY_DB).stores.get('files').get(PR.REGISTRY)));
  try {
    // ---- a single-profile install, as before profiles: an identity restored into `sigelo`, sealed with no profile named
    const b0 = await F.connect(), p0 = await A.androidPlatform({ bridge: b0, mqtt: mqttEsm, indexedDB: idb, pow });
    await SD.restoreInto(p0, { words: wordsOf(5), name: 'tab', relay: 'relay.test', restore: {}, seat: 'here', now: 1761400000 });
    const blob1 = Buffer.from(p0.files.read('identity.keystore')), did1 = didOf(JSON.parse(new TextDecoder().decode(await W.loadIdentity(p0))).genesis);
    storage.setItem('kept-before', 'x');
    const seals0 = F.log.seals.length;
    let pg = page();
    const r1 = await pg.app.ready;
    ok(await until(() => regOf().profiles[0].did === did1, 5000) && regOf().profiles.length === 1 && regOf().active === 'p1' && regOf().profiles[0].kind === 'words' && regOf().profiles[0].name === 'Profile 1'
      && /^\w+ \w+ \w+ \w+$/.test(regOf().profiles[0].words) && F.log.seals.length === seals0 && blob1[0] === 1 && Buffer.from(idb.dbs.get('sigelo').stores.get('files').get('identity.keystore')).equals(blob1)
      && storage.getItem('kept-before') === 'x' && r1.mode().kind === 'full' && unlocks() === 0,
      `profiles: a single-profile install migrated as p1, Profile 1, words, its DID and four words learned; nothing resealed (blob version 1 kept), storage untouched, no lock asked (${JSON.stringify(regOf().profiles[0])})`);
    ok(title(pg.box) === undefined && pg.main.hidden === false, 'profiles: one profile: no picker, the page at once');
    // ---- add: the lock, a new profile not set up yet, its first run with a way back
    let u = unlocks();
    let r = await pg.app.local.profiles.add();
    ok(r.reload === true && reloads === 1 && unlocks() === u + 1 && regOf().active === 'p2' && regOf().profiles.map((p) => `${p.id}:${p.name}:${p.kind}`).join() === 'p1:Profile 1:words,p2:Profile 2:null',
      `profiles: add → Profile 2 (not set up), active, the lock once, a reload (${JSON.stringify(regOf().profiles)})`);
    await stopApp();
    const s2 = pg.session; pg = page(s2);
    ok(await checkOf(() => pg.app.ready) === 'identity' && title(pg.box) === 'sigelo' && pg.box.all().some((e) => e.tagName === 'BUTTON' && e.attrs?.['aria-label'] === 'Back to my profiles') && pg.main.hidden === true,
      'profiles: the new profile opens on its first run (the welcome) with its Close, "Back to my profiles"; no picker (just chosen)');
    // Its identity (restored here as the welcome would): sealed under its own aliases, blob version 2 naming p2.
    const b2 = A.profileBridge(await F.connect(), 'p2'), p2 = await A.androidPlatform({ bridge: b2, mqtt: mqttEsm, indexedDB: idb, pow, name: PR.dbName('p2') });
    await SD.restoreInto(p2, { words: wordsOf(6), name: 'tab', relay: 'relay.test', restore: {}, seat: 'here', now: 1761400000 });
    const blob2 = Buffer.from(p2.files.read('identity.keystore')), did2 = didOf(JSON.parse(new TextDecoder().decode(await W.loadIdentity(p2))).genesis);
    const s2seals = F.log.seals.slice(-2);
    ok(blob2[0] === 2 && blob2.subarray(3, 5).toString() === 'p2' && s2seals.every((x) => x.profile === 'p2' && x.name === 'sigelo-p2-identity-full') && did2 !== did1 && idb.dbs.has('sigelo-p2')
      && await checkOf(() => b0.open(new Uint8Array(blob2), { kind: 'identity' })) === 'sealed' && await checkOf(() => b2.open(new Uint8Array(blob1), { kind: 'identity' })) === 'sealed'
      && await checkOf(() => A.profileBridge(b0, 'p3').open(new Uint8Array(blob2), { kind: 'identity' })) === 'sealed' && await checkOf(() => b2.open(new Uint8Array(blob2), { kind: 'identity' })) === 'accepted',
      'profiles: p2 sealed under sigelo-p2-identity-full in database sigelo-p2, blob version 2 naming p2; p1\'s blob never opens as p2\'s nor p2\'s as p1\'s or p3\'s');
    // ---- a cold start with two profiles: the picker, then the lock, then the chosen one
    u = unlocks();
    pg = page();
    await until(() => title(pg.box) === 'Profiles', 3000);
    const rows = pg.box.all().filter((e) => e.attrs?.['data-profile']);
    ok(rows.length === 2 && rows[1].textContent.includes('Profile 2') && rows[0].textContent.includes('Profile 1') && rows[0].textContent.includes(regOf().profiles[0].words) && rows[0].textContent.includes('Your identity')
      && rows[1].className.includes('current') && pg.main.hidden === true && unlocks() === u, 'picker: a row per profile (name, four words, what it holds), the last used marked, the page hidden, no lock yet');
    rows[0].onclick();
    const rp = await pg.app.ready;
    ok(unlocks() === u + 1 && regOf().active === 'p1' && pg.main.hidden === false && pg.box.hidden === true && (await rp.call('GET', '/api/me')).body.original === did1,
      'picker: a tap → the lock once → that profile\'s page (p1\'s DID)');
    // ---- switch: the lock once; the new profile's start asks nothing more
    u = unlocks();
    r = await pg.app.local.profiles.use('p2');
    ok(r.reload === true && unlocks() === u + 1 && regOf().active === 'p2', 'switch: the lock once, the active id kept, a reload');
    await stopApp();
    const ops = F.log.ops.length;
    pg = page(pg.session);
    const r2 = await pg.app.ready;
    ok((await r2.call('GET', '/api/me')).body.original === did2 && unlocks() === u + 1 && F.log.ops.slice(ops).includes('open') && title(pg.box) === undefined && await until(() => regOf().profiles[1].did === did2, 3000),
      `switch: p2 starts (its DID) with no second lock (its FULL key opened inside the lock's window); its DID learned (${F.log.ops.slice(ops)})`);
    // ---- proof-of-work counts per profile: each profile's carrier state is its own database's
    const st = (db) => idb.dbs.get(db)?.stores.get('files');
    const stateOf = (db) => { const b = st(db)?.get('app/me.local.carrier.json'); return b ? JSON.parse(new TextDecoder().decode(b)) : null; };
    const c1 = stateOf('sigelo'), c2 = stateOf('sigelo-p2');
    ok(c1 && c2 && JSON.stringify(c1).includes(did1) && !JSON.stringify(c1).includes(did2) && JSON.stringify(c2).includes(did2) && !JSON.stringify(c2).includes(did1),
      'proof of work: each profile\'s carrier state (where its searches are counted, per relay) is its own, in its own database: never shared');
    // ---- rename
    const rn = await pg.app.local.profiles.rename('p2', '  Work  ');
    ok(rn.profiles.find((p) => p.id === 'p2').name === 'Work' && await checkOf(() => pg.app.local.profiles.rename('p2', ' ')) === 'profile_name' && await checkOf(() => pg.app.local.profiles.rename('p2', 'x'.repeat(25))) === 'profile_name'
      && await checkOf(() => pg.app.local.profiles.rename('p2', 'a\u202eb')) === 'profile_name' && await checkOf(() => pg.app.local.profiles.rename('p9', 'x')) === 'profile',
      'rename: trimmed, kept; empty, over 24 characters, a direction override, an unknown profile refused');
    // ---- the limit: 8 profiles; the ninth refused before any lock
    for (let i = 0; i < 6; i++) await pg.app.local.profiles.add();
    u = unlocks();
    ok(regOf().profiles.length === 8 && await checkOf(() => pg.app.local.profiles.add()) === 'profile_limit' && unlocks() === u && regOf().profiles.length === 8 && regOf().next === 9,
      `limit: 8 profiles; the ninth refused profile_limit, no lock asked (${regOf().profiles.map((p) => p.id)})`);
    // ---- remove an inactive profile not set up yet: no lock, wiped at once
    await pg.app.local.profiles.use('p2'); await stopApp(); pg = page(pg.session); await pg.app.ready;
    u = unlocks();
    storage.setItem('p3:sigelo-control', 'x');
    const rm3 = await pg.app.local.profiles.remove('p3', {});
    ok(!rm3.profiles.some((p) => p.id === 'p3') && unlocks() === u && idb.deleted.includes('sigelo-p3') && storage.getItem('p3:sigelo-control') === null && storage.getItem('kept-before') === 'x' && F.log.forgot.includes('p3') && regOf().wipe.length === 0,
      'remove: a profile not set up yet goes at once, no lock: its database, its storage keys, its aliases (forget-profile); p1\'s storage kept');
    // ---- remove the active words profile: the words ticked and the name typed, the lock, then the wipe at the next start
    const pr = pg.app.local.profiles;
    ok(await checkOf(() => pr.remove('p2', { name: 'Work' })) === 'profile_words' && await checkOf(() => pr.remove('p2', { name: 'work', words: true })) === 'profile_name' && unlocks() === u && regOf().profiles.some((p) => p.id === 'p2'),
      'remove a words profile: refused without "I have the 25 words" (profile_words) or its name typed exactly (profile_name); nothing asked, nothing dropped');
    storage.setItem('p2:sigelo-control-relay', 'y');
    r = await pr.remove('p2', { name: 'Work', words: true });
    ok(r.reload === true && unlocks() === u + 1 && !regOf().profiles.some((p) => p.id === 'p2') && regOf().wipe.includes('p2') && regOf().active === 'p1', 'remove the active one: the lock, out of the list, its wipe recorded, p1 active, a reload');
    await stopApp();
    pg = page(pg.session); await pg.app.ready.catch(() => {});
    ok(regOf().wipe.length === 0 && idb.deleted.includes('sigelo-p2') && !idb.dbs.has('sigelo-p2') && ![...F.keys.keys()].some((k) => k.startsWith('sigelo-p2-')) && [...F.keys.keys()].includes('sigelo-identity-full')
      && storage.getItem('p2:sigelo-control-relay') === null && await checkOf(() => b2.open(new Uint8Array(blob2), { kind: 'identity' })) === 'sealed' && (await (await pg.app.ready).call('GET', '/api/me')).body.original === did1,
      'remove: at the next start p2 is wiped: its database deleted, its keystore aliases gone (its blob never opens again), its storage keys; p1 untouched, open');
    // ---- the welcome's way back: an added profile left before its first run → the one it was added from, no lock
    // Added by the Add sheet's "Join from an invite code" (ui.js addProfile): the first run opens there, the code kept for the new page.
    ok(await checkOf(() => pr.add('nowhere')) === 'profile_path', 'add: an unknown way → profile_path');
    await pr.add('join'); await stopApp(); pg = page(pg.session); await pg.app.ready.catch(() => {});
    ok(title(pg.box) === 'Join from an invite' && pg.app.local.joinCode() === null, `add("join"): its first run opens at Join from an invite (${title(pg.box)}); no code kept yet`);
    pg.box.all().find((e) => e.className === 'code-in').value = 'K7F3-Q9ZP';
    await pg.box.all().find((e) => e.tagName === 'BUTTON' && e.textContent === 'Next').onclick();
    ok(title(pg.box) === 'Name this phone' && pg.app.local.joinCode() === 'K7F3-Q9ZP' && pg.app.local.joinCode() === null, 'Join: the code kept for the new page once (local.joinCode), then Create');
    // Started again (the way is asked once): the welcome, with its way back.
    await stopApp(); pg = page(pg.session); await pg.app.ready.catch(() => {});
    const added = regOf().active;
    u = unlocks();
    await pg.box.all().find((e) => e.tagName === 'BUTTON' && e.attrs?.['aria-label'] === 'Back to my profiles').onclick();
    await until(() => regOf().active === 'p1', 3000);
    ok(regOf().active === 'p1' && !regOf().profiles.some((p) => p.id === added) && unlocks() === u, `welcome: "Back to my profiles" drops the empty ${added} and returns to p1, no lock`);
    await stopApp(); pg = page(pg.session); await pg.app.ready;
    // ---- remote p1 migrated as remote
    const FR = fakeShell({ mode: 'remote' }), idbR = new FakeIDB();
    const boxR = new FakeEl('section'), appR = B.boot({ shell: FR.shell, target: FR.target, box: boxR, main: new FakeEl('main'), mqtt: mqttEsm, indexedDB: idbR, storage: memStore(), session: memStore(), reload() {}, pow });
    await appR.ready.catch(() => {});
    const regR = JSON.parse(new TextDecoder().decode(idbR.dbs.get(PR.REGISTRY_DB).stores.get('files').get(PR.REGISTRY)));
    ok(regR.profiles.length === 1 && regR.profiles[0].kind === 'remote', 'profiles: a single-profile install of the remote form migrated as p1, remote');
    const ps = PR.prefixed(storage, 'p2'), p1s = PR.prefixed(storage, 'p1');
    ps.setItem('a', '1'); p1s.setItem('a', '2');
    ok(storage.getItem('p2:a') === '1' && storage.getItem('a') === '2' && ps.getItem('a') === '1' && p1s.getItem('a') === '2' && (ps.clear(), storage.getItem('a') === '2' && storage.getItem('p2:a') === null),
      'storage: p1 keeps its keys as before, p2 under p2:, each clear() its own');
  } finally {
    await stopApp();
    for (const [k, d] of Object.entries(saved)) { if (d) Object.defineProperty(globalThis, k, d); else delete globalThis[k]; }
  }
}

// ================================================================ 1e. the words password (words.mjs, boot.mjs local.words; design/apps-seed.md §8)
// over the fake shell: kept as kind words under the FULL key; Show after the lock and the password; a wrong password
// said after 2 s, then 4 (no lockout); change (the old one asked); remove (the words deleted); removing a profile
// whose words are kept needs that password (another profile's, opened under its own aliases).
{
  const SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href), B = await import(pathToFileURL(join(HERE, 'boot.mjs')).href);
  const PR = await import(pathToFileURL(join(HERE, 'profiles.mjs')).href), WD = await import(pathToFileURL(join(HERE, 'words.mjs')).href);
  const { mnemonicFromRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
  const wordsOf = (b) => { const S = new Uint8Array(32).fill(b); S[31] = 0x0d; return mnemonicFromRoot(S); };
  const saved = Object.fromEntries(['document', 'location', 'history', 'addEventListener', 'removeEventListener'].map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
  Object.assign(globalThis, { document: { createElement: (t) => new FakeEl(t) }, location: { hash: '', reload() {} }, history: { pushState() {}, back() {} }, addEventListener() {}, removeEventListener() {} });
  const memStore = () => { const m = new Map(); return { m, get length() { return m.size; }, key: (i) => [...m.keys()][i] ?? null, getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
  const F = fakeShell({ mode: 'self' }), idb = new FakeIDB(), storage = memStore(), pow = A.androidPow(W.workerPow(() => new FakeWorker()));
  const unlocks = () => F.log.ops.filter((o) => o === 'unlock').length;
  let app = null;
  const page = (picked) => { const session = memStore(); if (picked) session.setItem('sigelo-picked', picked); app = B.boot({ shell: F.shell, target: F.target, box: new FakeEl('section'), main: new FakeEl('main'), mqtt: mqttEsm, indexedDB: idb, storage, session, reload() {}, pow }); return app; };
  const stopApp = async () => { try { await (await app.ready).stop?.(); } catch {} };
  const timed = async (f) => { const t = Date.now(); const c = await checkOf(f); return [c, Date.now() - t]; };
  try {
    // The gate alone: 2 s doubling to 256 s at most, one attempt at a time (taps in parallel wait), reset by a right one.
    const WL = await import(pathToFileURL(join(HERE, 'vendor', 'contact', 'words-lock.mjs')).href), slept = [], g = WL.wrongGate({ sleep: async (ms) => { slept.push(ms); await sleep(1); } });
    const bad = () => Promise.reject(Object.assign(new Error('Wrong password.'), { check: 'words_password' })), order = [];
    await Promise.allSettled([1, 2, 3].map((i) => g.run(async () => { order.push(i); return bad(); })));
    for (let i = 0; i < 7; i++) await g.run(bad).catch(() => {});
    const capped = slept.slice(-2).join(), f10 = g.fails;
    await g.run(async () => 1);
    ok(slept.slice(0, 4).join() === '2000,4000,8000,16000' && capped === '256000,256000' && order.join() === '1,2,3' && f10 === 10 && g.fails === 0 && await checkOf(() => g.run(async () => { throw Object.assign(new Error('x'), { check: 'other' }); })) === 'other' && slept.length === 10,
      `gate: 2 s, doubling per wrong password to 256 s at most, attempts one at a time, reset by a right one, other errors not delayed; never a lockout (${slept.join(' ')})`);
    const wa = wordsOf(3), wb = wordsOf(4);
    const b0 = await F.connect(), p0 = await A.androidPlatform({ bridge: b0, mqtt: mqttEsm, indexedDB: idb, pow });
    await SD.restoreInto(p0, { words: wa, name: 'tab', relay: 'relay.test', restore: {}, seat: 'here', now: 1761400000 });
    const tk = Date.now();
    await WD.keepWords(p0, wa, 'correct horse');
    const keepMs = Date.now() - tk, ws = F.log.seals.at(-1);
    ok(ws.kind === 'words' && ws.full === true && ws.alias === 1 && ws.name === 'sigelo-identity-full' && p0.files.read('words.keystore')?.[0] === 1 && p0.files.read('words.sealed') === null,
      `words: kept as kind words under p1's FULL alias (blob version 1), no WebCrypto copy (PBKDF2 1,000,000 rounds + seal: ${keepMs} ms here)`);
    const L = page().local;
    await app.ready;
    const st = await L.words.status();
    ok(st.here === true && st.kept === true && st.iterations === 1_000_000, `local.words.status: an identity from the words, kept (${JSON.stringify(st)})`);
    F.state.locked = true;
    let u = unlocks();
    ok(await checkOf(() => L.words.reveal('correct horse')) === 'cancelled' && unlocks() === u + 1, 'Show: the screen lock first; not confirmed → cancelled, nothing opened');
    F.state.locked = false;
    const [c1, t1] = await timed(() => L.words.reveal('correct horsf')), [c2, t2] = await timed(() => L.words.reveal('Correct horse'));
    ok(c1 === 'words_password' && c2 === 'words_password' && t1 >= 2000 && t2 >= 4000 && t2 > t1 + 1500, `Show: a wrong password → words_password after 2 s, then 4 s (${t1}, ${t2} ms); no lockout`);
    u = unlocks();
    const tr = Date.now(), r = await L.words.reveal('correct horse'), revealMs = Date.now() - tr;
    ok(r.words.join(' ') === wa && unlocks() === u + 1 && revealMs < 5000, `Show: the lock, then the right password → the 25 words; the delay reset (${revealMs} ms)`);
    ok(await checkOf(() => L.words.change('correct horse', 'battery staple', 'battery stapler')) === 'words_password_rule' && await checkOf(() => L.words.change('correct horse', 'short', 'short')) === 'words_password_rule',
      'Change: the new password and its repeat checked (the same, at least 8 characters)');
    await L.words.change('correct horse', 'battery staple', 'battery staple');
    const [c3, t3] = await timed(() => L.words.reveal('correct horse'));
    ok(c3 === 'words_password' && t3 >= 2000 && (await L.words.reveal('battery staple')).words.join(' ') === wa && F.log.seals.at(-1).kind === 'words', 'Change: resealed under the new password; the old one refused');
    // ---- a second profile: p1's words guard p1's removal from there (its database and aliases opened for the check)
    await L.profiles.add();
    await stopApp();
    const b2 = A.profileBridge(await F.connect(), 'p2'), p2 = await A.androidPlatform({ bridge: b2, mqtt: mqttEsm, indexedDB: idb, pow, name: PR.dbName('p2') });
    await SD.restoreInto(p2, { words: wb, name: 'tab', relay: 'relay.test', restore: {}, seat: 'here', now: 1761400000 });
    await WD.keepWords(p2, wb, 'p2 password', { iterations: 1000 });
    const L2 = page('p2').local;
    await app.ready;
    ok((await L2.words.status('p1')).kept === true && (await L2.words.status()).kept === true, 'status of another profile: p1\'s words kept (read from its database)');
    const need = await checkOf(() => L2.profiles.remove('p1', { name: 'Profile 1', words: true }));
    const [c4] = await timed(() => L2.profiles.remove('p1', { name: 'Profile 1', words: true, password: 'p2 password' }));
    ok(need === 'words_password_needed' && c4 === 'words_password' && JSON.parse(new TextDecoder().decode(idb.dbs.get(PR.REGISTRY_DB).stores.get('files').get(PR.REGISTRY))).profiles.some((p) => p.id === 'p1'),
      'Remove a profile with kept words: no password → words_password_needed; another profile\'s password → words_password; kept');
    const rm = await L2.profiles.remove('p1', { name: 'Profile 1', words: true, password: 'battery staple' });
    ok(!rm.profiles.some((p) => p.id === 'p1') && idb.deleted.includes('sigelo') && F.log.forgot.includes('p1'), 'Remove a profile: its words password right → removed, its database deleted, its aliases forgotten (the kept words with them)');
    // ---- remove the password: the old one asked, then the words deleted
    const [c5] = await timed(() => L2.words.remove('battery staple'));
    ok(c5 === 'words_password' && (await L2.words.status()).kept === true, 'Remove the password: a wrong one refused, the words kept');
    await L2.words.remove('p2 password');
    ok((await L2.words.status()).kept === false && (await checkOf(() => L2.words.reveal('p2 password'))) === 'words_none', 'Remove the password: the kept words deleted; Show says none are kept');
    await stopApp();
    const p2b = await A.androidPlatform({ bridge: b2, mqtt: mqttEsm, indexedDB: idb, pow, name: PR.dbName('p2') });
    ok(p2b.files.read('words.keystore') === null && p2b.files.read('identity.keystore') !== null, 'Remove the password: words.keystore gone from storage, the identity kept');
  } finally { for (const [k, d] of Object.entries(saved)) { if (d) Object.defineProperty(globalThis, k, d); else delete globalThis[k]; } }
}

// ================================================================ 1f. notifications, the app lock's settings, unlock force (platform-android.mjs,
// boot.mjs local.notify, local.onOpen, local.lock, local.unlock; words.mjs check) over the fake shell
{
  const B = await import(pathToFileURL(join(HERE, 'boot.mjs')).href), SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href);
  const WD = await import(pathToFileURL(join(HERE, 'words.mjs')).href), WL = await import(pathToFileURL(join(HERE, 'vendor', 'contact', 'words-lock.mjs')).href);
  const { mnemonicFromRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
  const memStore = () => { const m = new Map(); return { m, get length() { return m.size; }, key: (i) => [...m.keys()][i] ?? null, getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
  const pow = A.androidPow(W.workerPow(() => new FakeWorker()));
  const apps = [];
  const boot = (F) => { const a = B.boot({ shell: F?.shell ?? null, target: F?.target, mqtt: mqttEsm, indexedDB: new FakeIDB(), storage: memStore(), session: memStore(), reload() {}, pow }); a.ready.catch(() => {}); apps.push(a); return a.local; };
  try {
    // ---- notify over the bridge
    const F = fakeShell({ mode: 'self' }), bridge = await F.connect(), ops = () => F.log.ops.length;
    await bridge.notify({ tag: 'chat:did:sigelo:zAbc', title: 'Ana', text: 'New message' });
    await bridge.notify({ tag: 'group:g_1.x', title: 'Team', text: 'New message' });
    const n = F.state.notes.get('chat:did:sigelo:zAbc');
    ok(n?.title === 'Ana' && n.text === 'New message' && n.keys === 'id,op,tag,text,title' && F.state.notes.get('group:g_1.x')?.title === 'Team', `notify: tag, title and text sent as given, nothing else (${n?.keys})`);
    const o0 = ops();
    const badTags = await Promise.all(['chat:', 'mail:x', 'chat:a b', 'chat:é', `chat:${'x'.repeat(201)}`, 42, undefined].map((tag) => checkOf(() => bridge.notify({ tag, title: 'A', text: 'B' }))));
    const badLines = await Promise.all([['', 'x'], ['x'.repeat(101), 'x'], ['x', undefined], ['x', 7], ['x', 'y'.repeat(101)]].map(([title, text]) => checkOf(() => bridge.notify({ tag: 'group:g1', title, text }))));
    const badCancel = await checkOf(() => bridge.notify({ tag: 'mail:x', cancel: true }));
    ok(badTags.every((c) => c === 'notify') && badLines.every((c) => c === 'notify') && badCancel === 'notify' && ops() === o0, `notify: a bad tag, title or text refused "notify" before the shell sees it (${badTags} / ${badLines})`);
    ok(await checkOf(() => bridge.notify({ tag: 'chat:did:sigelo:zAbc', cancel: true })) === 'accepted' && !F.state.notes.has('chat:did:sigelo:zAbc') && F.state.notes.has('group:g_1.x'), 'notify: cancel removes that tag\'s notification only');
    F.state.granted = false;
    const denied = await checkOf(() => bridge.notify({ tag: 'pay:k1:n1', title: 'Bot', text: 'Payment request' })), a1 = await bridge.notify({ ask: true });
    F.state.granted = true;
    const a2 = await bridge.notify({ ask: true });
    ok(denied === 'notify_permission' && a1.granted === false && a2.granted === true && F.state.asked === 2 && !F.state.notes.has('pay:k1:n1'), 'notify: not allowed → notify_permission; ask → { granted } as the shell answers');
    // ---- the open event: to its listeners, kept until there is one, never to a request waiting (same id or not)
    {
      const target = new EventTarget(), sent = [];
      let p1 = null;
      const shell = { info: () => JSON.stringify({ v: 'sigelo-shell/0', mode: 'self', wipe: false, version: 'test' }),
        connect() { const { port1, port2 } = new MessageChannel(); p1 = port1; port1.onmessage = (e) => sent.push(JSON.parse(e.data)); setTimeout(() => target.dispatchEvent(new MessageEvent('message', { data: 'sigelo-bridge/0', ports: [port2] }))); } };
      const br = await A.connectBridge({ shell, target });
      let answered = null;
      const req = br.lockGet().then((r) => { answered = r; }, (e) => { answered = e; });
      await until(() => sent.length === 1, 2000);
      p1.postMessage(JSON.stringify({ ev: 'open', tag: 'chat:did:sigelo:zEarly', id: sent[0].id }));
      await sleep(50);
      const got = [];
      br.onEvent((m) => got.push(m.tag));
      const early = got.join();
      p1.postMessage(JSON.stringify({ ev: 'open', tag: 'group:g2', id: sent[0].id }));
      await until(() => got.length === 2, 2000);
      const stillWaiting = answered === null;
      p1.postMessage(JSON.stringify({ id: sent[0].id, on: true, after: 5, secure: false }));
      await req;
      ok(early === 'chat:did:sigelo:zEarly' && got.join() === 'chat:did:sigelo:zEarly,group:g2' && stillWaiting && answered?.after === 5,
        `open event: {ev:"open"} reaches the listener (one that came before it: when it is set), never the request waiting on that id (${got}; ${JSON.stringify(answered)})`);
      p1.close();
    }
    // ---- local (boot.mjs): onOpen at a start by a tap (registered before and after the connect), a tap while running, a bad tag dropped
    const F1 = fakeShell({ mode: 'self' }), F2 = fakeShell({ mode: 'self' });
    F1.state.pendingOpen = 'pay:keeper1:nonce.7'; F2.state.pendingOpen = 'chat:did:sigelo:zCold';
    const L1 = boot(F1), opened1 = [];
    L1.onOpen((t) => opened1.push(t));
    const L2 = boot(F2), opened2 = [];
    await sleep(300);
    L2.onOpen((t) => opened2.push(t));
    await until(() => opened1.length && opened2.length, 3000);
    F1.open('mail:not-ours'); F1.open('group:g9');
    await until(() => opened1.length === 2, 3000);
    await sleep(50);
    ok(opened1.join() === 'pay:keeper1:nonce.7,group:g9' && opened2.join() === 'chat:did:sigelo:zCold',
      `onOpen: a start by a tap gives its tag once the bridge is connected (fn set before or after), a tap while running at once, a tag not ours dropped (${opened1} / ${opened2})`);
    // ---- local.notify, local.lock, local.unlock force
    const o1 = F1.log.ops.length;
    await L1.notify({ tag: 'chat:did:sigelo:zAbc', title: 'Ana', text: 'New message' });
    ok(typeof L1.notify === 'function' && F1.state.notes.get('chat:did:sigelo:zAbc')?.title === 'Ana' && await checkOf(() => L1.notify({ tag: 'x', title: 'a', text: 'b' })) === 'notify' && F1.log.ops.length === o1 + 1
      && (await L1.notify({ ask: true })).granted === true, 'local.notify: through the shell as given; a bad tag refused before it; ask');
    const g0 = await L1.lock.get(), o2 = F1.log.ops.length;
    const afters = [];
    for (const after of [1, 5, 15, 60]) afters.push((await L1.lock.set({ after })).after);
    const refused = await Promise.all([7, 0, '5', 5.5, null].map((after) => checkOf(() => L1.lock.set({ after })))), offR = await checkOf(() => L1.lock.set({ on: 'no' }));
    const off = await L1.lock.set({ on: false }), g1 = await L1.lock.get();
    ok(L1.lock.kind === 'screen' && g0.on === true && g0.after === 1 && g0.secure === true && afters.join() === '1,5,15,60' && refused.every((c) => c === 'lock') && offR === 'lock'
      && F1.log.ops.length === o2 + 6 && off.on === false && g1.on === false && g1.after === 60 && typeof g1.secure === 'boolean',
      `local.lock: get → { on, after, secure }; after 1, 5, 15, 60 accepted, 7 (and others) refused "lock" before the shell; on false kept (${refused})`);
    const f0 = F1.state.forced.length;
    await L1.unlock({ force: true }); await L1.unlock(); await L1.unlock({ force: 'yes' });
    ok(F1.state.forced.slice(f0).join() === 'true,false,false', `local.unlock: { force: true } passed through, anything else not (${F1.state.forced.slice(f0)})`);
    // ---- without the shell: no lock, no notify, onOpen a no-op, unlock at once
    const L0 = boot(null);
    let t0 = Date.now();
    L0.onOpen(() => {});
    await L0.unlock({ force: true });
    ok(L0.lock === undefined && L0.notify === undefined && Date.now() - t0 < 500, 'local without the shell: lock and notify undefined, onOpen nothing, unlock resolves at once');
    // ---- words check: the password through the gate, no screen lock
    const S = new Uint8Array(32).fill(9); S[31] = 0x0d;
    const pw = await A.androidPlatform({ bridge, mqtt: mqttEsm, indexedDB: new FakeIDB(), pow });
    await SD.restoreInto(pw, { words: mnemonicFromRoot(S), name: 'tab', relay: 'relay.test', restore: {}, seat: 'here', now: 1761400000 });
    await WD.keepWords(pw, mnemonicFromRoot(S), 'correct horse', { iterations: 1000 });
    const slept = [], gate = WL.wrongGate({ sleep: async (ms) => { slept.push(ms); } });
    let unlocked = 0;
    const api = WD.wordsApi(pw, { unlock: async () => { unlocked++; }, gate }), none = WD.wordsApi(await A.androidPlatform({ bridge, mqtt: mqttEsm, indexedDB: new FakeIDB(), pow }), { gate });
    const u0 = F.log.ops.filter((x) => x === 'unlock').length;
    const right = await api.check('correct horse'), wrong = await checkOf(() => api.check('correct horsf')), empty = await checkOf(() => api.check(''));
    ok(right === true && wrong === 'words_password' && empty === 'words_password' && slept.join() === '2000,4000' && unlocked === 0 && F.log.ops.filter((x) => x === 'unlock').length === u0
      && await checkOf(() => none.check('correct horse')) === 'words_none', `words.check: the right password → true, a wrong one the same refusal and delay (${slept}); no screen lock asked; none kept → words_none`);
  } finally {
    for (const a of apps) { try { await (await a.ready).stop?.(); } catch {} }
  }
}

// ================================================================ 2. platform-android.mjs
const HOST = 'relay.test';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-shell-'));
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(REPO, 'relay');
const haveRelay = existsSync(join(RELAY_DIR, 'server.mjs'));
const { selfSigned } = haveRelay ? await import(pathToFileURL(join(RELAY_DIR, 'test', 'fixtures.mjs')).href) : {};
let relay = null, front = null;
const browser = { refused: 0, headers: [] };
try {
  {
    // The bridge alone: a front with a certificate for relay.test, and one more name it does not hold.
    const cert = haveRelay ? selfSigned(HOST) : null;
    if (!cert) { skipped = ': SKIP part 2 and 3 (no relay checkout: SIGELO_RELAY_DIR)'; report(); }
    writeFileSync(join(dir, 'cert.pem'), cert.cert); writeFileSync(join(dir, 'key.pem'), cert.key);
    const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
    const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
    relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, tlsCert: join(dir, 'cert.pem'), tlsKey: join(dir, 'key.pem'), tlsPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1,
      log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
    // The stand-in nginx on 443: browser requests (Origin, Sec-Fetch-Site) refused as relay/deploy/nginx.conf
    // refuses them; relay.json; the rest and the upgrade at /mqtt passed to the relay with X-Real-IP.
    const isBrowser = (h) => h.origin !== undefined || h['sec-fetch-site'] !== undefined;
    front = httpsServer({ cert: cert.cert, key: cert.key }, (req, res) => {
      browser.headers.push(req.headers);
      if (isBrowser(req.headers)) { browser.refused++; res.writeHead(403); res.end(); return; }
      if (req.url === '/relay.json') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ endpoints: { mqtt: `mqtts://${HOST}:8883`, mqtt_ws: `wss://${HOST}/mqtt` } })); return; }
      if (req.url === '/moved') { res.writeHead(302, { location: 'https://elsewhere.test/' }); res.end(); return; }
      const up = httpRequest(`http://127.0.0.1:${relay.ports.http}${req.url}`, { method: req.method, headers: { ...req.headers, 'x-real-ip': '198.51.100.9' } }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      up.on('error', () => res.destroy());
      req.pipe(up);
    });
    front.on('upgrade', (req, sock, head) => {
      browser.headers.push(req.headers);
      sock.on('error', () => {});
      if (isBrowser(req.headers)) { browser.refused++; return sock.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'); }
      const up = netConnect(relay.ports.http, '127.0.0.1', () => {
        const h = Object.entries({ ...req.headers, 'x-real-ip': '198.51.100.9' }).map(([k, v]) => `${k}: ${v}`).join('\r\n');
        up.write(`GET ${req.url} HTTP/1.1\r\n${h}\r\n\r\n`); up.write(head); up.pipe(sock); sock.pipe(up);
      });
      for (const x of [up, sock]) { x.on('error', () => { up.destroy(); sock.destroy(); }); x.on('close', () => { up.destroy(); sock.destroy(); }); }
    });
    const frontPort = await listen(front);
    globalThis.HOSTS = { [HOST]: { 443: frontPort, 8883: relay.ports.tls }, 'other.test': { 443: frontPort } };
    globalThis.CA = cert.cert;
  }
  const F = fakeShell({ hosts: globalThis.HOSTS, ca: globalThis.CA }), bridge = await F.connect();
  ok(bridge.info.mode === 'self' && bridge.info.v === 'sigelo-shell/0' && A.OPS.every((o) => typeof o === 'string'), 'bridge: SigeloShell.info(), then the port posted to the page');
  ok(await checkOf(() => A.connectBridge({ shell: { info: () => '{"v":"other"}', connect() {} }, target: new EventTarget() })) === 'TypeError'
    && await checkOf(() => A.connectBridge({ shell: undefined })) === 'TypeError', 'bridge: no SigeloShell, or another shell version: refused');
  const fetchA = A.bridgeFetch(bridge);
  const rj = await fetchA(`https://${HOST}/relay.json`);
  let body = ''; for await (const c of rj.body) body += new TextDecoder().decode(c);
  ok(rj.status === 200 && JSON.parse(body).endpoints.mqtt_ws === `wss://${HOST}/mqtt` && rj.headers.get('Date') !== null && rj.headers.get('content-type') === 'application/json',
    'https: GET through the shell: status, headers (Date, Content-Type), the body as chunks');
  const post = await fetchA(`https://${HOST}/check`, { method: 'POST', body: '{"a":1}' });
  const last = browser.headers.at(-1);
  ok(post.status >= 400 && last['content-type'] === 'text/plain;charset=UTF-8' && last.origin === undefined && last.cookie === undefined && !Object.keys(last).some((k) => k.startsWith('sec-fetch')) && last.referer === undefined,
    `https: a POST carries its body and Content-Type, and no Origin, cookie, referrer or Sec-Fetch-* (${Object.keys(last)})`);
  ok((await fetchA(`https://${HOST}/moved`)).status === 302, 'https: a redirect is answered as it is, not followed');
  ok(await checkOf(() => fetchA('http://198.51.100.7/r')) === 'connect' && await checkOf(() => fetchA(`http://${HOST}/relay.json`)) === 'connect', 'https: http:// to a public address or a name refused (the LAN rule)');
  ok(await checkOf(() => fetchA('https://other.test/relay.json')) === 'connect', 'https: a certificate that does not name the host refused');
  ok(await checkOf(() => bridge.tls('other.test', 443)) === 'connect', 'tls: a certificate that does not name the host refused');
  const ac = new AbortController(); ac.abort(new DOMException('t', 'TimeoutError'));
  ok(await checkOf(() => fetchA(`https://${HOST}/relay.json`, { signal: ac.signal })) === 'TimeoutError', 'https: an aborted signal ends the call with its reason (the carrier\'s timeout)');

  // The keystore seal.
  const idf = new TextEncoder().encode(JSON.stringify({ v: 'sigelo/0', secret: 'cd'.repeat(32) }));
  const sealed = await bridge.seal(idf, { kind: 'identity' });
  ok(sealed[0] === 1 && sealed[1] === 0 && !Buffer.from(sealed).includes(Buffer.from('cdcd')) && same(await bridge.open(sealed, { kind: 'identity' }), idf), 'seal: the identity sealed under the keystore key and opened again');
  const bad = sealed.slice(); bad[20] ^= 1;
  ok(await checkOf(() => bridge.open(bad, { kind: 'identity' })) === 'sealed' && await checkOf(() => bridge.open(sealed, { kind: 'control' })) === 'sealed', 'seal: changed, or opened as another kind: refused');
  // The platform: transports, the identity through the sealer, the proof of work and its fallback.
  const idb = new FakeIDB(), p = await A.androidPlatform({ bridge, mqtt: mqttEsm, indexedDB: idb, pow: A.androidPow(W.workerPow(() => new FakeWorker())) });
  ok(p.transports.join() === 'mqtts,wss' && p.env.transport === 'auto' && Object.isFrozen(p) && typeof p.sealer?.seal === 'function', 'platform: transports mqtts and wss, auto, the keystore sealer');
  ok(await W.loadIdentity(p) === null, 'platform: no identity yet');
  await W.saveIdentity(p, idf, undefined, { full: false });
  ok(p.files.read('identity.keystore')?.[1] === 0 && p.files.read('identity.sealed') === null && !idb.dbs.get('sigelo').stores.get('keys').has('identity'), 'platform: the identity sealed by the shell (identity.keystore); no WebCrypto key made');
  ok(same(await W.loadIdentity(p), idf), 'platform: and opened again');
  await W.saveIdentity(p, idf, undefined, { full: true });
  ok(p.files.read('identity.keystore')?.[1] === 1, 'platform: FULL under the key that asks for the screen lock');
  F.state.locked = true;
  ok(await checkOf(() => W.loadIdentity(p)) === 'cancelled', 'platform: FULL not unlocked: cancelled (asked again at the next start), not "import it again"');
  ok(await checkOf(() => bridge.unlock()) === 'cancelled', 'app lock: unlock with the screen lock not confirmed: cancelled');
  F.state.locked = false;
  ok(await checkOf(() => bridge.unlock()) === 'accepted' && F.state.unlocks === 2, 'app lock: unlock confirmed: resolves (MainActivity.unlock asks the screen lock)');
  const prefix = 'sigelo-relay-pow/0\nrelay.testdid:sigelo:zA5';
  ok(await p.pow(prefix, 9) === await nodePow(prefix, 9), 'pow: in the Worker, the counter Node finds');
  let tried = 0;
  const fallback = A.androidPow(() => Promise.reject(new Error('proof of work: the worker failed')));
  ok(await fallback(prefix, 10, { onProgress: (n) => { tried = n; } }) === await nodePow(prefix, 10) && await A.slicedPow(prefix, 40, { deadline: Date.now() + 300 }) === null,
    'pow: a Worker that does not start: in the page, in slices, the same counter; past the deadline null');
  const ac2 = new AbortController(); ac2.abort();
  ok(await A.slicedPow(prefix, 40, { signal: ac2.signal }) === null && await checkOf(() => A.androidPow(() => Promise.reject(new Error('other')))(prefix, 1)) === 'Error', 'pow: aborted null; another error is not a fallback');
  ok(await checkOf(() => p.mqtt('mqtt://relay.test:1883', {})) === 'connect' && await checkOf(() => p.mqtt('ws://relay.test/mqtt', {})) === 'connect', 'mqtt: plain mqtt:// and ws:// refused (connect)');
  ok(tried >= 0, 'pow: progress is optional');

  // ---- two apps against the relay behind the stand-in nginx, and a Node agent
  const { keygen } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href);
  const nodeLib = await import(pathToFileURL(join(REPO, 'apps', 'contact', 'carrier.mjs')).href);
  const { makeRouter } = await import(pathToFileURL(join(HERE, 'router.mjs')).href);
  const CREATED = '2026-10-01T00:00:00Z';
  const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-shell-test/0 ${l}`).digest());
  const agent = (label) => {
    const recovery = keygen({ seed: seed(`${label} recovery`), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} rn`).slice(0, 16) }).key;
    const k = keygen({ seed: seed(label), recovery, created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
    return { label, did: k.did, secret: k.secret, store: { v: 'sigelo/0', secret: Buffer.from(k.secret).toString('hex'), genesis: k.genesis, rotations: [], attestations: [], issuers: [] } };
  };
  const appEnds = { [HOST]: { mqtt: `mqtts://${HOST}:8883`, http: `https://${HOST}` } };
  const relayOpts = { relay: HOST, shortRelay: HOST, registry: false, retentionDays: 7, backoff: [100, 400] };
  async function app(a, transport) {
    const sh = fakeShell({ hosts: globalThis.HOSTS, ca: globalThis.CA }), b = await sh.connect();
    const platform = await A.androidPlatform({ bridge: b, mqtt: mqttEsm, indexedDB: new FakeIDB(), pow: A.androidPow(W.workerPow(() => new FakeWorker())), env: { relay: HOST } });
    const router = makeRouter({ platform, identity: () => a.store, options: { ...relayOpts, endpoints: appEnds, ...(transport && { transport }) } });
    return { sh, router, call: (m, path, body) => router.call(m, path, body) };
  }
  const ADA = agent('ada'), BO = agent('bo'), CY = agent('cy');
  const node = new nodeLib.Carrier({ identity: () => ({ secret: CY.secret, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: CY.store.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } }),
    ...nodeLib.pathsFor(join(dir, 'cy.local.json')), ...relayOpts, endpoints: { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } }, keep: true });
  const X = await app(ADA), Y = await app(BO, 'wss');
  try {
    await X.router.start(); await Y.router.start();
    ok(X.router.carrier.transport === 'auto' && Y.router.carrier.transport === 'wss', `the carriers: auto (mqtts first) and wss (${X.router.carrier.transport}, ${Y.router.carrier.transport})`);
    // X invites (a short code parked through the shell's https), the Node agent accepts.
    const inv = await X.call('POST', '/api/invite', { name: 'cy' });
    ok(inv.status === 200 && /^[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(inv.body.short), `mqtts app: POST /api/invite parks a short code at the relay (${inv.status} ${inv.body.short ?? JSON.stringify(inv.body)})`);
    await node.accept(inv.body.short, { name: 'ada', wait: 5 });
    await node.inbox({ wait: 1 });
    ok(await until(async () => (await X.call('GET', '/api/state')).body.groups.contacts.some((c) => c.did === CY.did)), 'mqtts app: paired with the Node agent');
    ok(await until(async () => (await X.call('GET', '/api/state')).body.me.online), 'mqtts app: online, the session up over the shell\'s TLS stream to 8883');
    await X.call('POST', '/api/send', { to: CY.did, text: 'over mqtts' });
    let read = [];
    ok(await until(async () => { read.push(...(await node.inbox({ wait: 0.5 })).messages); return read.some((m) => m.content === 'over mqtts'); }), 'mqtts app → Node agent: read');
    await node.send('ada', 'back over mqtts');
    ok(await until(async () => (await X.call('GET', `/api/messages?contact=${encodeURIComponent(CY.did)}`)).body.messages.some((m) => m.dir === 'in' && m.text === 'back over mqtts')), 'Node agent → mqtts app: read');
    // Y (wss): the Node agent invites, Y accepts; then both ways.
    const inv2 = await node.invite({ name: 'bo' });
    const acc = await Y.call('POST', '/api/accept', { code: inv2.code, name: 'cy' });
    ok(acc.status === 200, `wss app: POST /api/accept (${acc.status} ${JSON.stringify(acc.body).slice(0, 120)})`);
    ok(await until(async () => { await node.inbox({ wait: 0.2 }); return (await Y.call('GET', '/api/state')).body.groups.contacts.some((c) => c.did === CY.did); }), 'wss app: paired with the Node agent');
    await Y.call('POST', '/api/send', { to: CY.did, text: 'over wss' });
    read = [];
    ok(await until(async () => { read.push(...(await node.inbox({ wait: 0.5 })).messages); return read.some((m) => m.content === 'over wss'); }), 'wss app → Node agent: read (RFC 6455 framing in the page over the shell\'s TLS to 443)');
    await node.send('bo', 'back over wss');
    ok(await until(async () => (await Y.call('GET', `/api/messages?contact=${encodeURIComponent(CY.did)}`)).body.messages.some((m) => m.dir === 'in' && m.text === 'back over wss')), 'Node agent → wss app: read');
    ok(X.sh.log.streams.every((s) => s === `${HOST}:8883`) && X.sh.log.streams.length >= 1 && Y.sh.log.streams.every((s) => s === `${HOST}:443`) && Y.sh.log.streams.length >= 1,
      `the shell's streams: mqtts to 8883 only, wss to 443 only (${X.sh.log.streams.length}, ${Y.sh.log.streams.length})`);
    ok(browser.refused === 0 && browser.headers.length > 3 && browser.headers.every((h) => h.origin === undefined && h['sec-fetch-site'] === undefined),
      `the relay's browser rule (Origin, Sec-Fetch-Site → 403) never hit: ${browser.headers.length} requests, ${browser.refused} refused`);
  } finally {
    try { await X.router.stop(); } catch {}
    try { await Y.router.stop(); } catch {}
    await node.stop?.();
  }

  // ================================================================ 3. the remote form (shell.mjs)
  {
    const S = await import(pathToFileURL(join(HERE, 'shell.mjs')).href);
    const CLI = join(REPO, 'apps', 'agent', 'cli.ts'), H = join(dir, 'home');
    mkdirSync(H, { recursive: true, mode: 0o700 });
    const { newRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
    const env = { PATH: process.env.PATH, HOME: H, SIGELO_KEY_PROVIDER: 'file', SIGELO_RELAY: HOST, SIGELO_RELAY_ENDPOINTS: JSON.stringify({ [HOST]: { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:1' } }) };
    const human = join(H, 'me.local.json');
    spawnSync(process.execPath, [CLI, 'keeper', '--from-words', '--identity', human], { env, input: newRoot(), encoding: 'utf8' });
    const c = spawn(process.execPath, [CLI, 'ui', '--identity', human, '--no-open', '--remote', '--listen', '127.0.0.1', '--name', 'phone', '--scope', 'read'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let so = ''; c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', () => {});
    await until(() => /SIGELO:UI:[^\n]+\n/.test(so), 30000);
    const line = /SIGELO:UI:[^\n]+/.exec(so)?.[0] ?? '';
    const R = fakeShell({ mode: 'remote' }), rb = await R.connect();
    const kept = new Map(), storage = { getItem: (k) => kept.get(k) ?? null, setItem: (k, v) => kept.set(k, String(v)), removeItem: (k) => kept.delete(k), clear: () => kept.clear() };
    storage.setItem('sigelo-control', A.b64(await rb.seal(new TextEncoder().encode(line), { kind: 'control' })));
    const be = await S.remoteBackend(rb, { storage });
    const me = await be.call('GET', '/api/me'), st = await be.call('GET', '/api/state'), forget = await be.call('POST', '/api/forget', { contact: 'did:sigelo:zNope' }), dv = await be.call('GET', '/api/devices');
    ok(line !== '' && me.status === 200 && me.body.did?.startsWith('did:sigelo:') && st.status === 200 && be.mode().kind === 'remote',
      `remote: the computer's text kept sealed (control key); sealed GET /api/me and /api/state over the shell's http to the LAN (${me.status} ${st.status})`);
    ok(forget.status === 403 && dv.status === 403, `remote: outside the scope (read) and the device routes refused by the computer (${forget.status}, ${dv.status})`);
    const wk = await be.call('GET', '/api/agents/workers'), ec = await be.call('POST', '/api/agents/enrol-code', { name: 'vps' });
    ok(wk.status === 200 && wk.body.keeper === true && Array.isArray(wk.body.workers) && ec.status === 403 && ec.body.error.check === 'scope',
      `remote: the computer's Agents list read through the shell (scope read); enrolling is scope all (403 scope) (${wk.status}, ${ec.status})`);
    ok(kept.get('sigelo-control') && !kept.get('sigelo-control').includes('SIGELO') && R.log.ops.filter((o) => o === 'https').length >= 4, 'remote: the text is kept only sealed; every call through the shell');
    await new Promise((r) => { c.on('close', r); c.kill('SIGTERM'); });
    const gone = await be.call('GET', '/api/state');
    ok(gone.status === 502 && /No answer from 127\.0\.0\.1/.test(gone.body.error.message), `remote: the computer's page stopped → 502, "No answer" (${gone.body.error?.message})`);
    // After a switch: the page clears its storage once, and tells the shell.
    const Wp = fakeShell({ mode: 'remote', wipe: true }), wb = await Wp.connect();
    let deleted = null;
    const wiped = await S.wipeIfAsked(wb, { indexedDB: { deleteDatabase: (n) => { deleted = n; const r = {}; setTimeout(() => r.onsuccess?.()); return r; } }, storage });
    ok(wiped === true && deleted === 'sigelo' && kept.size === 0 && Wp.state.wipe === false && await S.wipeIfAsked(await fakeShell({ mode: 'self' }).connect()) === false,
      'switch: the page deletes its IndexedDB and localStorage once, then tells the shell (wiped)');
    const M = fakeShell({ mode: null }), mb = await M.connect();
    ok(mb.info.mode === null && (await mb.request('mode', { mode: 'self' })).mode === 'self' && (await mb.request('mode', { mode: 'remote' })).mode === 'remote' && await checkOf(() => mb.request('mode', { mode: 'x' })) === 'mode',
      'the form: set by each profile\'s first run, self then remote (no refusal: profiles differ); anything else refused');
  }
  // ================================================================ 3b. several computers (computers.mjs, boot.mjs; design/profiles.md P2) over the
  // fake shell: three computers' `ui --remote` on the LAN, two of one operator (one identity's copies), one of another. Today's
  // one computer migrated as c1 (nothing resealed); add by the pairing screens (Cancel), the second's text sealed naming it;
  // another operator refused other_operator, nothing kept; switch (the lock once); forget (the lock, the reminder to revoke).
  {
    const S = await import(pathToFileURL(join(HERE, 'shell.mjs')).href), B = await import(pathToFileURL(join(HERE, 'boot.mjs')).href);
    const CM = await import(pathToFileURL(join(HERE, 'computers.mjs')).href), PR = await import(pathToFileURL(join(HERE, 'profiles.mjs')).href);
    const CLI = join(REPO, 'apps', 'agent', 'cli.ts'), H = join(dir, 'home-computers');
    mkdirSync(join(H, 'a'), { recursive: true, mode: 0o700 }); mkdirSync(join(H, 'b'), { recursive: true, mode: 0o700 }); mkdirSync(join(H, 'other'), { recursive: true, mode: 0o700 });
    const { newRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
    const env = { PATH: process.env.PATH, HOME: H, SIGELO_KEY_PROVIDER: 'file', SIGELO_RELAY: HOST, SIGELO_RELAY_ENDPOINTS: JSON.stringify({ [HOST]: { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:1' } }) };
    const ida = join(H, 'a', 'me.local.json'), idb2 = join(H, 'b', 'me.local.json'), ido = join(H, 'other', 'me.local.json');
    spawnSync(process.execPath, [CLI, 'keeper', '--from-words', '--identity', ida], { env, input: newRoot(), encoding: 'utf8' });
    spawnSync(process.execPath, [CLI, 'keeper', '--from-words', '--identity', ido], { env, input: newRoot(), encoding: 'utf8' });
    writeFileSync(idb2, readFileSync(ida), { mode: 0o600 });   // the operator's identity on a second computer
    const lan = async (identity) => {
      const c = spawn(process.execPath, [CLI, 'ui', '--identity', identity, '--no-open', '--remote', '--listen', '127.0.0.1', '--name', 'phone', '--scope', 'chat'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
      let so = ''; c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', () => {});
      await until(() => /SIGELO:UI:[^\n]+\n/.test(so), 30000);
      return { line: /SIGELO:UI:[^\n]+/.exec(so)?.[0] ?? '', stop: () => new Promise((r) => { c.on('close', r); c.kill('SIGTERM'); }) };
    };
    const [ca, cb, co] = await Promise.all([lan(ida), lan(idb2), lan(ido)]);
    const saved = Object.fromEntries(['document', 'location', 'history', 'addEventListener', 'removeEventListener'].map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
    Object.assign(globalThis, { document: { createElement: (t) => new FakeEl(t) }, location: { hash: '', reload() {} }, history: { pushState() {}, back() {} }, addEventListener() {}, removeEventListener() {} });
    const memStore = () => { const m = new Map(); return { m, get length() { return m.size; }, key: (i) => [...m.keys()][i] ?? null, getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
    const F = fakeShell({ mode: 'remote' }), idb = new FakeIDB(), storage = memStore(), session = memStore();
    const unlocks = () => F.log.ops.filter((o) => o === 'unlock').length;
    let reloads = 0, app = null;
    const page = () => { const box = new FakeEl('section'), main = new FakeEl('main'); app = B.boot({ shell: F.shell, target: F.target, box, main, mqtt: mqttEsm, indexedDB: idb, storage, session, reload: () => { reloads++; } }); return { box, main, app }; };
    const title = (box) => box.all().find((e) => e.tagName === 'H1')?.textContent;
    const btn = (box, t) => box.all().find((e) => e.tagName === 'BUTTON' && e.textContent === t);
    const pasteIn = async (box, text) => { box.all().find((e) => e.tagName === 'TEXTAREA').value = text; await btn(box, 'Connect').onclick(); };
    const said = (box) => box.all().find((e) => /\bsay\b/.test(e.className))?.textContent ?? '';
    const listOf = () => JSON.parse(storage.getItem('sigelo-computers'));
    const regOf = () => JSON.parse(new TextDecoder().decode(idb.dbs.get(PR.REGISTRY_DB).stores.get('files').get(PR.REGISTRY)));
    try {
      const rb = await F.connect();
      // ---- today's one computer (before P2): its text sealed under the control alias, no computer named
      storage.setItem('sigelo-control', A.b64(await rb.seal(new TextEncoder().encode(ca.line), { kind: 'control' })));
      const blob1 = storage.getItem('sigelo-control'), seals0 = F.log.seals.length;
      let pg = page(), be = await pg.app.ready;
      const meA = await be.call('GET', '/api/me');
      ok(meA.status === 200 && be.cid === 'c1' && await until(() => listOf().computers[0]?.did === meA.body.original, 3000) && listOf().active === 'c1' && listOf().computers.length === 1 && listOf().computers[0].via === 'lan'
        && storage.getItem('sigelo-control') === blob1 && F.log.seals.length === seals0 && await until(() => regOf().profiles[0].did === meA.body.original, 3000),
        `computers: today's one computer migrated as c1 (LAN), its sealed text left where it was (nothing resealed); its page's DID learned, the profile's operator (${JSON.stringify(listOf().computers[0])})`);
      let l = await pg.app.local.computers.list();
      ok(l.active === 'c1' && l.computers.length === 1 && l.computers[0].words === meA.body.words && l.computers[0].last_used > 0 && l.profile.did === meA.body.original, 'computers: list → the one in use, its four words, last used, the profile\'s operator');
      // ---- add: the lock, then the pairing screens (Cancel back), the second computer's text sealed naming it
      let u = unlocks(), r0 = reloads;
      let r = await pg.app.local.computers.add();
      ok(r.reload === true && unlocks() === u + 1 && reloads === r0 + 1 && listOf().adding === true, 'add: the lock once, a reload into the pairing screens');
      await be.stop?.();
      pg = page();
      ok(await checkOf(() => pg.app.ready) === 'connect' && title(pg.box) === 'Use my computer' && btn(pg.box, 'Cancel') && pg.main.hidden === true, 'add: the pairing screens (code, or a SIGELO:UI: / SIGELO:CTL: text pasted or scanned) with Cancel, the page hidden');
      r0 = reloads;
      await pasteIn(pg.box, cb.line);
      const blob2 = Buffer.from(storage.getItem('sigelo-control:c2') ?? '', 'base64');
      ok(reloads === r0 + 1 && listOf().active === 'c2' && listOf().computers.map((c) => `${c.id}:${c.via}`).join() === 'c1:lan,c2:lan' && listOf().adding === false
        && blob2[0] === 2 && blob2.subarray(3, 3 + blob2[2]).toString() === 'p1:c2' && F.log.seals.at(-1).computer === 'c2' && F.log.seals.at(-1).name === 'sigelo-control' && listOf().computers[1].did === meA.body.original,
        `add: the second computer of the same operator paired on the LAN, in use; its text sealed under the profile's control alias, blob version 2 naming p1:c2 (${JSON.stringify(listOf().computers[1])})`);
      ok(await checkOf(() => rb.open(new Uint8Array(blob2), { kind: 'control' })) === 'sealed' && await checkOf(() => A.computerBridge(rb, 'c3').open(new Uint8Array(blob2), { kind: 'control' })) === 'sealed'
        && await checkOf(() => A.computerBridge(A.profileBridge(rb, 'p2'), 'c2').open(new Uint8Array(blob2), { kind: 'control' })) === 'sealed' && await checkOf(() => A.computerBridge(rb, 'c2').open(new Uint8Array(blob2), { kind: 'control' })) === 'accepted'
        && await checkOf(() => A.computerBridge(rb, 'c2').open(new Uint8Array(Buffer.from(blob1, 'base64')), { kind: 'control' })) === 'sealed',
        'blobs: c2\'s opens as p1\'s c2 only (not as c1, c3, nor p2\'s c2); c1\'s never as c2');
      pg = page(); be = await pg.app.ready;
      const meB = await be.call('GET', '/api/me');
      ok(be.cid === 'c2' && meB.status === 200 && meB.body.original === meA.body.original && (await be.call('GET', '/api/state')).status === 200, 'switch by add: the second computer\'s page, the same operator');
      // ---- another operator: refused other_operator at pairing time, nothing kept; Cancel back
      await pg.app.local.computers.add(); pg = page(); await pg.app.ready.catch(() => {});
      await pasteIn(pg.box, co.line);
      ok(/another identity/.test(said(pg.box)) && /Add it in a profile of its own/.test(said(pg.box)) && storage.getItem('sigelo-control:c3') === null && listOf().computers.length === 2 && listOf().next === 3 && title(pg.box) === 'Use my computer',
        `other_operator: a computer whose page is another identity refused at pairing, said, nothing kept (${said(pg.box)})`);
      const st0 = (await (await S.remoteBackend(rb, { storage: memStore() }).catch((e) => e)));
      ok(st0.check === 'connect', 'remote form: no computer → the pairing screens (connect)');
      const direct = await checkOf(() => S.connectLan(rb, co.line, { storage: memStore(), cid: 'c3', expect: meA.body.original }));
      ok(direct === 'other_operator', `connectLan: another operator → other_operator (${direct})`);
      r0 = reloads;
      await btn(pg.box, 'Cancel').onclick();
      ok(reloads === r0 + 1 && listOf().adding === false && listOf().active === 'c2', 'Cancel: back to the computer in use, nothing added');
      // ---- switch: the lock once, that computer's page
      pg = page(); be = await pg.app.ready;
      u = unlocks();
      r = await pg.app.local.computers.use('c1');
      ok(r.reload === true && unlocks() === u + 1 && listOf().active === 'c1' && await checkOf(() => pg.app.local.computers.use('c9')) === 'computer', 'switch: the lock once, c1 in use, a reload; an unknown computer refused');
      await be.stop?.();
      pg = page(); be = await pg.app.ready;
      ok(be.cid === 'c1' && (await be.call('GET', '/api/me')).body.original === meA.body.original && (await pg.app.local.computers.use('c1')).reload === undefined, 'switch: c1\'s page; switching to the one in use does nothing');
      // ---- the race CI showed (0.1.14 export): a list opened before the switch (the page going away, its late GET /api/me)
      // wrote its stale copy back, the computer in use set back to c2. Each call reads the list again: the switch stands.
      {
        const other = CM.openComputers(storage);
        other.use('c2');
        const stale = CM.openComputers(storage), lists = Array.from({ length: 20 }, () => CM.openComputers(storage));   // opened while c2 is in use
        other.use('c1');   // the switch
        stale.learn('c2', {});
        await Promise.all(lists.map(async (l, i) => { await sleep(i % 3); l.learn(i % 2 ? 'c1' : 'c2', {}); }));
        ok(listOf().active === 'c1' && listOf().computers.length === 2 && stale.active().id === 'c1' && !stale.adding,
          `computers: lists open at once on one storage never write a stale copy over a newer one (the switch to c1 stands after 21 late writes) (${listOf().active})`);
      }
      // ---- forget: the lock, its control key gone here, the reminder to revoke it on the computer
      const shaped = (x) => Array.isArray(x?.computers) && typeof x.active !== 'undefined' && typeof x.revoke === 'string' && typeof x.reload === 'boolean';
      u = unlocks();
      r = await pg.app.local.computers.forget('c2');
      ok(shaped(r) && unlocks() === u + 1 && /sigelo-agent ui --revoke-control/.test(r.revoke) && r.computers.map((c) => c.id).join() === 'c1' && storage.getItem('sigelo-control:c2') === null && r.reload === false,
        'forget (not in use): the lock, its sealed text gone, the reminder: revoke it on the computer (ui --revoke-control)');
      r0 = reloads;
      r = await pg.app.local.computers.forget('c1');
      ok(shaped(r) && r.computers.length === 0 && r.reload === true && reloads === r0 + 1 && listOf().computers.length === 0 && listOf().active === null && storage.getItem('sigelo-control') === null, 'forget (in use): gone, a reload');
      await be.stop?.();
      pg = page();
      ok(await checkOf(() => pg.app.ready) === 'connect' && title(pg.box) === 'Use my computer' && !btn(pg.box, 'Cancel') && !btn(pg.box, 'Back to my computers'), 'no computer left: the pairing screens, nothing to go back to');
      // ---- the computer keeps the control until revoked there: its text still opens its page (another phone that kept it)
      const still = await (await import(pathToFileURL(join(REPO, 'apps', 'agent', 'remote-client.mjs')).href)).remoteClient(cb.line).then((c) => c.call('GET', '/api/me')).catch((e) => ({ status: e.status }));
      ok(still.status === 200, 'forgetting does not revoke: the computer answers that text until ui --revoke-control there (THREAT-MODEL)');
      // ---- list on a words profile: refused not_remote (Me shows no Computers)
      ok(await checkOf(() => CM.openComputers(memStore()).use('c1')) === 'computer' && CM.otherOperator(null, 'did:sigelo:zX') === null && CM.otherOperator('did:sigelo:zA', ['did:sigelo:zB', 'did:sigelo:zA']) === null
        && CM.otherOperator('did:sigelo:zA', 'did:sigelo:zB')?.check === 'other_operator', 'computers.mjs: unknown id refused; other_operator only when the profile\'s operator is known and not in the chain');
    } finally {
      try { await (await app?.ready)?.stop?.(); } catch {}
      for (const [k, d] of Object.entries(saved)) { if (d) Object.defineProperty(globalThis, k, d); else delete globalThis[k]; }
      await Promise.all([ca.stop(), cb.stop(), co.stop()]);
    }
  }
  // ================================================================ 4. the remote form over the relay (shell.mjs, apps/contact/control.mjs)
  {
    const S = await import(pathToFileURL(join(HERE, 'shell.mjs')).href);
    const U = await import(pathToFileURL(join(REPO, 'apps', 'agent', 'sigelo-agent-ui.ts')).href);
    const CLI = join(REPO, 'apps', 'agent', 'cli.ts'), H = join(dir, 'home-relay');
    mkdirSync(join(H, 'agents'), { recursive: true, mode: 0o700 });
    const { newRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
    const human = join(H, 'me.local.json');
    spawnSync(process.execPath, [CLI, 'keeper', '--from-words', '--identity', human], { env: { PATH: process.env.PATH, HOME: H, SIGELO_KEY_PROVIDER: 'file' }, input: newRoot(), encoding: 'utf8' });
    const computer = { relay: HOST, shortRelay: HOST, registry: false, endpoints: { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } } };
    const pg = await U.startUi({ identity: human, agents: join(H, 'agents'), carrier: computer, remote: { relay: true, name: 'phone', scope: 'chat' } });
    const R = fakeShell({ mode: 'remote', hosts: globalThis.HOSTS, ca: globalThis.CA }), rb = await R.connect();
    const kept = new Map(), storage = { getItem: (k) => kept.get(k) ?? null, setItem: (k, v) => kept.set(k, String(v)), removeItem: (k) => kept.delete(k), clear: () => kept.clear() };
    // The control's relay comes from its code, never from the page's relay setting (kept here first) nor a relay of its own.
    const { relay: _own, ...codeNamesIt } = relayOpts;
    const idb = new FakeIDB(), shellOpts = { storage, mqtt: mqttEsm, indexedDB: idb, pow: A.androidPow(W.workerPow(() => new FakeWorker())), options: { ...codeNamesIt, endpoints: appEnds } };
    const { presetRelay } = await import(pathToFileURL(join(HERE, 'router.mjs')).href), { readControlText } = await import(pathToFileURL(join(HERE, 'vendor', 'contact', 'control.mjs')).href);
    const pre = await W.webPlatform({ name: 'sigelo', indexedDB: idb, mqtt: mqttEsm });
    presetRelay(pre.files, 'corp.example.com'); await pre.flush();
    let be = null;
    try {
      const line = pg.relay.line ?? '';
      const pr = await S.pairRelay(rb, line, shellOpts), seen = await pg.relay.paired();
      ok(/^SIGELO:CTL:[0-9A-Z-]+:RELAY\.TEST$/.test(line) && typeof pr.words === 'string' && pr.words === seen.words && seen.name === 'phone',
        `relay: the app pairs by the SIGELO:CTL: code through the shell; the same four words on both sides (${line} ${pr.words} / ${seen.words})`);
      const held = JSON.parse(kept.get('sigelo-control-relay') ?? '{}');
      ok(held.operator === pr.operator && !JSON.stringify([...kept.values()]).includes('secret') && idb.dbs.get('sigelo').stores.get('files').has('identity.keystore'),
        'relay: the control identity sealed by the shell (identity.keystore), the operator\'s DID kept, no key in localStorage');
      be = await S.remoteBackend(rb, { ...shellOpts, timeout: 8000 });
      ok(be.carrier.relay === HOST && readControlText('SIGELO:CTL:K7F3-Q9ZP').relay === null && (await be.carrier.relayForShort('K7F3-Q9ZP')).from === 'short',
        `relay: the control's relay is the one its code names (${be.carrier.relay}), not the page's setting; an 8-character code is the public relay's (shortRelay)`);
      const early = await be.call('GET', '/api/me');
      ok(early.status === 403 && early.body.error.check === 'words' && be.mode().kind === 'remote' && be.mode().via === 'relay', `relay: before the words are confirmed on the computer: 403 words (${early.status})`);
      await pg.relay.confirm('phone', true);
      // 403 words opened no lease (apps/contact/control.mjs): not_connected, unsent, until the next probe (PROBE_MIN, 15 s).
      const held2 = await be.call('GET', '/api/me');
      ok(held2.status === 503 && held2.body.error.check === 'not_connected', `relay: after 403 words, no lease: not_connected here until the next probe (${held2.status})`);
      let me = held2;
      for (const end = Date.now() + 25_000; me.body?.error?.check === 'not_connected' && Date.now() < end;) { await new Promise((r) => setTimeout(r, 250)); me = await be.call('GET', '/api/me'); }
      const st = await be.call('GET', '/api/state');
      ok(me.status === 200 && me.body.did === pr.operator && st.status === 200 && Array.isArray(st.body.groups.contacts), `relay: confirmed: GET /api/me and /api/state over the relay (${me.status} ${st.status})`);
      let sends = 0, pushes = 0;
      const send0 = be.carrier.send.bind(be.carrier);
      be.carrier.send = (...a) => { sends++; return send0(...a); };
      be.onChange(() => { pushes++; });
      for (let i = 0; i < 5; i++) await be.call('GET', `/api/state?since=${st.body.seq}`);
      ok(sends === 0, `relay: the page's 2 s poll (GET /api/state) read from the pushed state: no relay message (${sends})`);
      const T = { 'X-Sigelo-Token': pg.token, Origin: `http://127.0.0.1:${pg.port}`, 'Content-Type': 'application/json' };
      await new Promise((y) => { const r = httpRequest({ host: '127.0.0.1', port: pg.port, method: 'POST', path: '/api/invite', headers: { ...T, Host: `127.0.0.1:${pg.port}` } }, (res) => { res.resume(); res.on('end', y); }); r.end(JSON.stringify({ name: 'erin' })); });
      ok(await until(() => pushes > 0, 15000) && (await be.call('GET', '/api/state')).body.pending.invites.some((x) => x.name === 'erin') && sends === 0,
        `relay: a change on the computer pushed (events), the next poll shows it, still no request (${pushes} pushed)`);
      const fg = await be.call('POST', '/api/forget', { contact: 'did:sigelo:zNope' }), sd = await be.call('POST', '/api/send', { to: 'did:sigelo:zNope', text: 'x' });
      ok(fg.status === 403 && fg.body.error.check === 'scope' && sd.status === 404 && sends === 2, `relay: scope chat: forget refused (403 scope), send in scope (404 not_contact): one request each (${fg.status} ${sd.status} ${sends})`);
      const lp = human.replace(/\.json$/, '.devices.json'), t0 = Math.floor(Date.now() / 1000);
      writeFileSync(lp, JSON.stringify({ v: 'sigelo-devices/1', operator: 'did:sigelo:zOp', seq: 1, iat: t0, devices: [{ name: 'laptop', worker: 0, did: 'did:sigelo:zL', rank: 'full', added: t0, by: 'did:sigelo:zOp' }], seat: { holder: 'did:sigelo:zL', epoch: 1, iat: t0 }, sig: 'x' }), { mode: 0o600 });
      const se = await be.call('POST', '/api/sync');
      rmSync(lp);
      ok(se.status === 409 && se.body.error.check === 'seat_elsewhere' && /laptop/.test(se.body.error.message), `relay: the seat elsewhere → 409 seat_elsewhere (the page's banner) (${se.status})`);
      await pg.relay.revoke('phone');
      const after = await be.call('GET', '/api/me');
      ok(after.status !== 200, `relay: revoked on the computer → the app's requests unanswered (${after.status})`);
      // A second computer over the relay whose page is not this profile's operator: refused other_operator, nothing kept.
      const again = await pg.relay.issue('phone2', 'chat'), other = 'did:sigelo:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
      const no = await checkOf(() => S.pairRelay(rb, again?.line ?? '', { ...shellOpts, cid: 'c2', expect: other }));
      ok(no === 'other_operator' && kept.get('sigelo-control-relay:c2') === undefined && idb.deleted.includes('sigelo-c2') && !idb.dbs.has('sigelo-c2'),
        `relay: a computer of another operator refused other_operator after the code: its contact forgotten, its database deleted, nothing kept (${no})`);
    } finally {
      await be?.stop?.();
      await pg.close();
    }
  }
} finally {
  front?.close();
  await relay?.close?.();
  rmSync(dir, { recursive: true, force: true });
}
report();
