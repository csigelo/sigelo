// SPDX-License-Identifier: MIT
// The Android app's page side in Node (design/apps.md §14 A5): what runs in the WebView, over a fake
// shell that keeps SigeloBridge.java's protocol (sigelo-bridge/0, platform-android.mjs) with Node's
// net, tls and https. The Java itself is built and run only on CI (apps/android/README.md). Parts:
//   1. ws-over-stream.mjs, RFC 6455 client framing: against `ws` (handshake, masking, sizes up to
//      200 KB, fragments both ways, ping/pong, close both ways) and a raw server for what must fail
//      (accept, status, extension, masked or reserved frames, control frames, UTF-8, sizes, close
//      frames, abrupt end, a close never answered); streamSocket (mqtts) over an echo server.
//   2. platform-android.mjs over the fake shell: the bridge, https (no Origin, no redirect, the
//      LAN rule), tls (a wrong certificate name refused), the keystore seal, the proof of work and
//      its fallback, the identity sealed; then two apps against the in-process relay behind a
//      stand-in nginx that refuses browser requests (Origin, Sec-Fetch-Site), as relay/deploy does:
//      one over mqtts:8883, one over wss:443 (the framing above), paired with a Node agent, messages
//      both ways, and none refused as a browser's.
//   3. The remote form (shell.mjs): a computer's `sigelo-agent ui --remote`, sealed calls carried by
//      the shell's http to the LAN; scope; the computer gone.
//   4. The remote form over the relay: a computer's `ui --remote --relay` in this process, the app's
//      control identity paired by SIGELO:CTL: and four words, requests answered, state pushed (the
//      poll sends nothing), scope, seat elsewhere, revoked.
//   node apps/web/test-shell.mjs   → ALL PASS (n); without the relay checkout, part 2's relay half SKIPs
import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
const { WebSocketServer } = await import(pathToFileURL(join(REPO, 'contact', 'node_modules', 'ws', 'wrapper.mjs')).href);
const nodePow = (await import(pathToFileURL(join(REPO, 'contact', 'platform-node.mjs')).href)).pow;

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
// "full" can be locked: cancelled), the form and the wipe. hosts: name → { port: local port }.
const PRIVATE = (h) => { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h); if (!m) return false; const [a, b] = [Number(m[1]), Number(m[2])]; return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254); };
function fakeShell({ mode = 'self', wipe = false, hosts = {}, ca } = {}) {
  const target = new EventTarget(), keys = new Map(), log = { ops: [], streams: [] };
  const state = { mode, wipe, locked: false };
  const ALIASES = { 'identity:false': 0, 'identity:true': 1, control: 2 };
  const AAD = { identity: 'sigelo-app identity/0', control: 'sigelo-app control/0' };
  const route = (host, port) => { const p = hosts[host]?.[port]; if (!p) throw Object.assign(new Error(`${host}:${port}: unreachable`), { check: 'connect' }); return p; };
  const shell = {
    info: () => JSON.stringify({ v: 'sigelo-shell/0', mode: state.mode, wipe: state.wipe, version: 'test' }),
    connect() {
      const { port1, port2 } = new MessageChannel(), streams = new Map();
      let sid = 0;
      const post = (m) => port1.postMessage(JSON.stringify(m));
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
            const kind = m.kind === 'identity' ? 'identity' : m.kind === 'control' ? 'control' : null;
            if (!kind) throw Object.assign(new Error('kind'), { check: 'kind' });
            const data = Buffer.from(m.data, 'base64');
            if (m.op === 'seal') {
              const a = kind === 'identity' ? ALIASES[`identity:${Boolean(m.full)}`] : 2;
              if (a === 1 && state.locked) throw Object.assign(new Error('not unlocked'), { check: 'cancelled' });
              if (!keys.has(a)) keys.set(a, randomBytes(32));
              const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', keys.get(a), iv);
              c.setAAD(Buffer.from(AAD[kind]));
              post({ id: m.id, data: Buffer.concat([Buffer.from([1, a]), iv, c.update(data), c.final(), c.getAuthTag()]).toString('base64') });
            } else {
              const a = data[1];
              if (data[0] !== 1 || data.length < 30 || (kind === 'identity' ? a > 1 : a !== 2) || !keys.has(a)) throw Object.assign(new Error('not sealed here'), { check: 'sealed' });
              if (a === 1 && state.locked) throw Object.assign(new Error('not unlocked'), { check: 'cancelled' });
              const d = createDecipheriv('aes-256-gcm', keys.get(a), data.subarray(2, 14));
              d.setAAD(Buffer.from(AAD[kind])); d.setAuthTag(data.subarray(data.length - 16));
              let out;
              try { out = Buffer.concat([d.update(data.subarray(14, data.length - 16)), d.final()]); } catch { throw Object.assign(new Error('does not open'), { check: 'sealed' }); }
              post({ id: m.id, data: out.toString('base64') });
            }
          } else if (m.op === 'mode') {
            if (m.mode !== 'self' && m.mode !== 'remote') throw Object.assign(new Error('mode'), { check: 'mode' });
            if (state.mode !== null && state.mode !== m.mode) throw Object.assign(new Error('switch from the menu'), { check: 'mode' });
            state.mode = m.mode; post({ id: m.id, mode: state.mode });
          } else if (m.op === 'wiped') { state.wipe = false; post({ id: m.id }); }
          else throw Object.assign(new Error(`no op ${m.op}`), { check: 'op' });
        } catch (e) { if (m.id !== undefined) post({ id: m.id, error: { check: e.check ?? 'connect', message: e.message } }); }
      };
      setTimeout(() => target.dispatchEvent(new MessageEvent('message', { data: 'sigelo-bridge/0', ports: [port2] })));
    },
  };
  return { shell, target, state, log, keys, connect: () => A.connectBridge({ shell, target }) };
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
  F.state.locked = false;
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
  const nodeLib = await import(pathToFileURL(join(REPO, 'contact', 'carrier.mjs')).href);
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
    const CLI = join(REPO, 'adapters', 'moadim', 'cli.ts'), H = join(dir, 'home');
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
    const kept = new Map(), storage = { getItem: (k) => kept.get(k) ?? null, setItem: (k, v) => kept.set(k, String(v)), clear: () => kept.clear() };
    storage.setItem('sigelo-control', A.b64(await rb.seal(new TextEncoder().encode(line), { kind: 'control' })));
    const be = await S.remoteBackend(rb, null, { storage });
    const me = await be.call('GET', '/api/me'), st = await be.call('GET', '/api/state'), forget = await be.call('POST', '/api/forget', { contact: 'did:sigelo:zNope' }), dv = await be.call('GET', '/api/devices');
    ok(line !== '' && me.status === 200 && me.body.did?.startsWith('did:sigelo:') && st.status === 200 && be.mode().kind === 'remote',
      `remote: the computer's text kept sealed (control key); sealed GET /api/me and /api/state over the shell's http to the LAN (${me.status} ${st.status})`);
    ok(forget.status === 403 && dv.status === 403, `remote: outside the scope (read) and the device routes refused by the computer (${forget.status}, ${dv.status})`);
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
    ok(mb.info.mode === null && (await mb.request('mode', { mode: 'self' })).mode === 'self' && await checkOf(() => mb.request('mode', { mode: 'remote' })) === 'mode', 'first start: the form is set once; a switch only through the shell (its menu, with a confirmation)');
  }
  // ================================================================ 4. the remote form over the relay (shell.mjs, contact/control.mjs)
  {
    const S = await import(pathToFileURL(join(HERE, 'shell.mjs')).href);
    const U = await import(pathToFileURL(join(REPO, 'adapters', 'moadim', 'sigelo-agent-ui.ts')).href);
    const CLI = join(REPO, 'adapters', 'moadim', 'cli.ts'), H = join(dir, 'home-relay');
    mkdirSync(join(H, 'agents'), { recursive: true, mode: 0o700 });
    const { newRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
    const human = join(H, 'me.local.json');
    spawnSync(process.execPath, [CLI, 'keeper', '--from-words', '--identity', human], { env: { PATH: process.env.PATH, HOME: H, SIGELO_KEY_PROVIDER: 'file' }, input: newRoot(), encoding: 'utf8' });
    const computer = { relay: HOST, shortRelay: HOST, registry: false, endpoints: { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } } };
    const pg = await U.startUi({ identity: human, agents: join(H, 'agents'), carrier: computer, remote: { relay: true, name: 'phone', scope: 'chat' } });
    const R = fakeShell({ mode: 'remote', hosts: globalThis.HOSTS, ca: globalThis.CA }), rb = await R.connect();
    const kept = new Map(), storage = { getItem: (k) => kept.get(k) ?? null, setItem: (k, v) => kept.set(k, String(v)), clear: () => kept.clear() };
    const idb = new FakeIDB(), shellOpts = { storage, mqtt: mqttEsm, indexedDB: idb, pow: A.androidPow(W.workerPow(() => new FakeWorker())), options: { ...relayOpts, endpoints: appEnds } };
    let be = null;
    try {
      const line = pg.relay.line ?? '';
      const pr = await S.pairRelay(rb, line, shellOpts), seen = await pg.relay.paired();
      ok(/^SIGELO:CTL:[0-9A-Z-]+:RELAY\.TEST$/.test(line) && typeof pr.words === 'string' && pr.words === seen.words && seen.name === 'phone',
        `relay: the app pairs by the SIGELO:CTL: code through the shell; the same four words on both sides (${line} ${pr.words} / ${seen.words})`);
      const held = JSON.parse(kept.get('sigelo-control-relay') ?? '{}');
      ok(held.operator === pr.operator && !JSON.stringify([...kept.values()]).includes('secret') && idb.dbs.get('sigelo').stores.get('files').has('identity.keystore'),
        'relay: the control identity sealed by the shell (identity.keystore), the operator\'s DID kept, no key in localStorage');
      be = await S.remoteBackend(rb, null, { ...shellOpts, timeout: 8000 });
      const early = await be.call('GET', '/api/me');
      ok(early.status === 403 && early.body.error.check === 'words' && be.mode().kind === 'remote' && be.mode().via === 'relay', `relay: before the words are confirmed on the computer: 403 words (${early.status})`);
      await pg.relay.confirm('phone', true);
      const me = await be.call('GET', '/api/me'), st = await be.call('GET', '/api/state');
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
