// SPDX-License-Identifier: MIT
// Transfers on Node (design/transfer.md, apps/agent/TRANSFER.md): transfer-engine.mjs's records, verbs
// and Engine over this machine's disk, the file sent read in place, and the Tor path (a tor daemon's
// control and SOCKS ports; nothing is ever installed for it); the direct path is sigelo-transfer,
// loaded only when a transfer starts. The protocol is transfer.mjs's.
//
// Two layers. The verbs change the transfers file and queue messages; they run anywhere (a CLI beside
// a watcher queues with local: true and kicks it). The Engine runs in the one process that holds the
// identity's relay session (watch, ui, the MCP server, or a CLI transfer verb with no holder): it takes
// the TRANSFER_LABEL messages the carrier kept apart, makes and answers offers, and moves the bytes.
//
//   send({ carrier, identity, to, path, via, direct, local })  → the record: the file hashed in place, its manifest sent
//   accept({ carrier, identity, id, direct, via, local })      the receiver's yes (free disk checked); the engine offers
//   decline / cancel / resume / forget({ carrier, identity, id, local })
//   intake({ carrier, identity, compared }) → the files asked: manifests and ends filed by a process with no engine (inbox)
//   list({ carrier, identity }) → { out, in, direct, auto, settings }; setDirect({ carrier, identity, contact, on });
//   setAuto({ carrier, identity, contact, mb }); settings({ identity, patch })
//   const e = new Engine({ carrier, identity, rtc, tor, stun, pro, compared, onEvent }); e.kick(); await e.idle(); e.live(); await e.close()
//
// The file, 0600, beside the identity (x.json → x.transfers.json), under its own lock (transfer-engine.mjs
// says what it holds). Partials: <identity>.files/.transfer/<id>.part (0600, written at offsets), <id>.have
// (a bit a chunk: checked and flushed), <id>.in.list (the chunk hashes); the sender's <id>.out.list beside
// them. A finished file is placed as send-file places one (<identity>.files/<contact>-<16 hex>/<sha256[0..8]>-<name>),
// never opened, and given to inbox as one item {type: "file", …, transfer: id}.
//
// The direct switch (design §7): direct gives the contact this agent's public and LAN addresses. On
// for own contacts (tier own or ours), asked once for the others (direct_ask until a yes or a no is
// kept); off: Tor, else no path. The accept rule (design §10.2): transfer-engine.mjs. Tor: settings.tor
// (default on), effective only when a tor daemon answers (SIGELO_TOR: "<control host:port>[,<socks
// host:port>]", default 127.0.0.1:9051,127.0.0.1:9050; "off": none; SIGELO_TOR_PASSWORD for a
// HashedControlPassword). STUN: SIGELO_STUN, host:port, comma-separated ("" = host candidates only),
// default port 3478 of this agent's relay host and the contact's (coturn there, relay/deploy/README.md).
import { createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { closeSync, createReadStream, existsSync, fdatasyncSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, statfsSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { open as openFile } from 'node:fs/promises';
import net from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TRANSFER_SEND, contactDir } from './carrier.mjs';
import { fail } from './kdf.mjs';
import { sendable, transact } from './platform-node.mjs';
import * as E from './transfer-engine.mjs';
import { CHUNK, MAX_SIZE, T, TRANSFER_LABEL, chunkLength, chunksOf, deframer, enframe, frames, readFrame } from './transfer.mjs';

export const { FILE_V, contactOf, directFor, trustOf } = E;
export { TRANSFER_LABEL };
const TOR_CONNECT_MS = 120_000, TOR_PROBE_MS = 1500;

export const transfersPath = (identity) => identity.replace(/\.json$/, '') + '.transfers.json';
const writeAtomic = (file, bytes) => { const tmp = `${file}.tmp`; rmSync(tmp, { force: true }); writeFileSync(tmp, bytes, { mode: 0o600, flag: 'wx' }); renameSync(tmp, file); };
const folder = (d) => mkdirSync(d, { recursive: true, mode: 0o700 });
const datasync = (fd) => { try { fdatasyncSync(fd); } catch {} };
const u8 = (b) => new Uint8Array(b.buffer, b.byteOffset, b.length);

// ---------------------------------------------------------------- this machine's io (transfer-engine.mjs)

const ios = new Map();
/** The io of an identity file, its carrier's files directory (filesDir: carrier.filesDir, or <identity>.files). */
export function nodeIo(identity, filesDir = identity.replace(/\.json$/, '') + '.files', torCfg = null, logPath = null) {
  const key = `${identity}\n${filesDir}\n${torCfg ? JSON.stringify(torCfg) : ''}\n${logPath ?? ''}`;
  if (ios.has(key)) return ios.get(key);
  const file = transfersPath(identity), dir = join(filesDir, '.transfer');
  const partOf = (id) => join(dir, `${id}.part`), haveOf = (id) => join(dir, `${id}.have`), listOf = (id, side) => join(dir, `${id}.${side}.list`);
  const io = {
    flushEach: 8,
    lock: (fn) => transact(file, fn, 'sigelo transfer'),
    read: () => (existsSync(file) ? readFileSync(file, 'utf8') : null),
    write: (text) => writeAtomic(file, text),
    have: {
      read: (id) => { try { return u8(readFileSync(haveOf(id))); } catch { return null; } },
      write: (id, bits) => { if (bits === null) rmSync(haveOf(id), { force: true }); else { folder(dir); writeAtomic(haveOf(id), bits); } },
    },
    list: {
      read: (id, side) => { try { return u8(readFileSync(listOf(id, side))); } catch { return null; } },
      write: (id, side, bytes) => { folder(dir); writeAtomic(listOf(id, side), bytes); },
      drop: (id, side) => rmSync(listOf(id, side), { force: true }),
    },
    part: {
      exists: (id) => existsSync(partOf(id)),
      drop: (id) => rmSync(partOf(id), { force: true }),
      async open(id) {
        folder(dir);
        closeSync(openSync(partOf(id), 'a', 0o600));
        const fd = openSync(partOf(id), 'r+');
        return {
          async write(b, pos) { let o = 0; while (o < b.length) o += writeSync(fd, b, o, b.length - o, pos + o); },
          async flush() { datasync(fd); },
          async close() { try { closeSync(fd); } catch {} },
        };
      },
      sha256: (id) => new Promise((ok, no) => {
        const h = createHash('sha256');
        createReadStream(partOf(id)).on('data', (d) => h.update(d)).on('end', () => ok(h.digest('hex'))).on('error', no);
      }),
    },
    free() { folder(dir); const st = statfsSync(dir); return st.bavail * st.bsize; },
    async land(r, c) {
      const to = join(filesDir, contactDir(c));
      folder(to);
      for (let i = 0; i < 64; i++) {
        const p = join(to, `${r.sha256.slice(0, 8)}-${i === 0 ? '' : `${i + 1}-`}${r.name}`);
        try { linkSync(partOf(r.id), p); unlinkSync(partOf(r.id)); return p; } catch (e) {
          if (e.code === 'EEXIST') continue;
          if (!existsSync(p)) { renameSync(partOf(r.id), p); return p; }
        }
      }
      fail('file_exists', `64 files of that name and hash are in ${to} already`);
    },
    async prepare({ path }) {
      const f = sendable(path, { base: identity.replace(/\.json$/, ''), files: filesDir, log: logPath }, MAX_SIZE);
      const { hashes, whole } = await hashFile(f.real, f.size);
      // The file must still be the one hashed.
      const s2 = statSync(f.real);
      if (s2.size !== f.size || s2.mtimeMs !== f.mtimeMs) fail('file_changed', `${path} changed while it was read: send it again`);
      return { file: f.real, name: f.name, size: f.size, mtimeMs: f.mtimeMs, hashes, whole };
    },
    async changed(r) { let st; try { st = statSync(r.file); } catch { return true; } return st.size !== r.size || st.mtimeMs !== r.mtimeMs; },
    async source(r) {
      const fh = await openFile(r.file, 'r');
      return {
        async read(i) {
          const s = await fh.stat();
          if (s.size !== r.size || s.mtimeMs !== r.mtimeMs) fail('file_changed', `${r.file} changed`);
          const len = chunkLength(r.size, i), buf = Buffer.alloc(len);
          const { bytesRead } = await fh.read(buf, 0, len, i * CHUNK);
          if (bytesRead !== len) fail('file_changed', `${r.file} is shorter`);
          return u8(buf);
        },
        close: () => fh.close(),
      };
    },
    tor: torCfg ? torOf(torCfg) : null,
  };
  ios.set(key, io);
  return io;
}
async function hashFile(file, size) {
  const n = chunksOf(size), hashes = new Uint8Array(n * 32), whole = createHash('sha256'), fh = await openFile(file, 'r'), buf = Buffer.alloc(CHUNK);
  try {
    for (let i = 0; i < n; i++) {
      const len = chunkLength(size, i);
      const { bytesRead } = await fh.read(buf, 0, len, i * CHUNK);
      if (bytesRead !== len) fail('file_changed', `${file} is shorter than it was`);
      const b = buf.subarray(0, len);
      hashes.set(createHash('sha256').update(b).digest(), i * 32);
      whole.update(b);
    }
  } finally { await fh.close(); }
  return { hashes, whole: whole.digest('hex') };
}
const ioOf = (o) => nodeIo(o.identity, o.carrier?.filesDir, null, o.carrier?.logPath ?? null);

// ---------------------------------------------------------------- the verbs (transfer-engine.mjs's, on this machine)

/** Load, purge, change (fn), save, under the file's lock. → fn's result. */
export const state = (identity, now, fn) => E.state(nodeIo(identity), now, fn);
export const send = (o) => E.send({ ...o, io: ioOf(o) });
export const prepare = (o) => E.prepare({ ...o, io: ioOf(o) });
export const sendTo = (o) => E.sendTo({ ...o, io: ioOf(o) });
export const fanOut = (o) => E.fanOut({ ...o, io: ioOf(o) });
export const accept = (o) => E.accept({ ...o, io: ioOf(o) });
/** A verb's resume: a stopped transfer offered again (the engine makes the offer; only what .have lacks is asked). */
export const resume = accept;
export const decline = (o) => E.decline({ ...o, io: ioOf(o) });
export const cancel = (o) => E.cancel({ ...o, io: ioOf(o) });
export const forget = (o) => E.forget({ ...o, io: ioOf(o) });
export const list = (o) => E.list({ ...o, io: ioOf(o) });
export const setDirect = (o) => E.setDirect({ ...o, io: ioOf(o) });
export const setAuto = (o) => E.setAuto({ ...o, io: ioOf(o) });
export const settings = ({ identity, patch, now }) => E.settings({ io: nodeIo(identity), patch, ...(now !== undefined && { now }) });
/** The STUN servers for a transfer with contact c: SIGELO_STUN, else this agent's relay host and the contact's, port 3478. */
export const stunFor = (carrier, c, env = process.env) => E.stunFor(carrier, c, env);
/**
 * Without an engine (a CLI inbox, transfer list): the manifests and ends the carrier kept, taken and
 * filed; offers, answers and onions stay for the engine of the next session. → the files now asked.
 */
export const intake = ({ carrier, identity, compared }) => E.intake({ carrier, io: nodeIo(identity, carrier.filesDir), compared });

/** The engine on this machine: E.Engine over nodeIo, with Tor when a tor daemon is configured. */
export class Engine extends E.Engine {
  constructor({ carrier, identity, rtc = loadRtc, tor = torConfig(), stun = null, pro, compared, maxServe, onEvent, retryMs, torConnectMs = TOR_CONNECT_MS, timer }) {
    super({ carrier, io: nodeIo(identity, carrier.filesDir, tor, carrier.logPath ?? null), rtc, stun, env: process.env, pro, compared, maxServe, onEvent, retryMs, torConnectMs, timer });
    this.identity = identity; this.torCfg = tor;
  }
}

// ---------------------------------------------------------------- Tor (design §5a)

/** SIGELO_TOR → { control: [host, port], socks: [host, port], password } | null ("off"). */
export function torConfig(env = process.env) {
  const v = (env.SIGELO_TOR ?? '').trim();
  if (v === 'off') return null;
  const [c, s] = (v || '127.0.0.1:9051,127.0.0.1:9050').split(',').map((x) => x.trim());
  const hp = (x, d) => { const m = /^(.+):(\d{1,5})$/.exec(x ?? ''); return m ? [m[1], Number(m[2])] : d; };
  return { control: hp(c, ['127.0.0.1', 9051]), socks: hp(s, ['127.0.0.1', 9050]), password: env.SIGELO_TOR_PASSWORD ?? null };
}
const connectTcp = (host, port, ms) => new Promise((ok, no) => {
  const s = net.connect({ host, port });
  const t = setTimeout(() => { s.destroy(); no(Object.assign(new Error(`tor: ${host}:${port} did not answer`), { check: 'tor' })); }, ms);
  s.once('connect', () => { clearTimeout(t); ok(s); });
  s.once('error', (e) => { clearTimeout(t); no(Object.assign(new Error(`tor: ${host}:${port}: ${e.code ?? e.message}`), { check: 'tor' })); });
});
/** An authenticated control connection: cmd(line) → the reply's lines (2xx), else throws check tor. */
export async function torControl(cfg, ms = TOR_PROBE_MS) {
  const s = await connectTcp(cfg.control[0], cfg.control[1], ms);
  let buf = '', waiting = [];
  const replies = [];
  s.setEncoding('utf8');
  s.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\r\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      replies.push(line);
      if (/^\d{3} /.test(line)) { const lines = replies.splice(0); const w = waiting.shift(); w?.(lines); }
    }
  });
  s.on('error', () => {});
  const cmd = (line) => new Promise((ok, no) => {
    const t = setTimeout(() => no(Object.assign(new Error(`tor: no answer to ${line.split(' ')[0]}`), { check: 'tor' })), 15000);
    waiting.push((lines) => {
      clearTimeout(t);
      const last = lines.at(-1);
      if (!last.startsWith('2')) no(Object.assign(new Error(`tor: ${line.split(' ')[0]}: ${last}`), { check: 'tor' })); else ok(lines);
    });
    s.write(`${line}\r\n`);
  });
  try {
    const info = (await cmd('PROTOCOLINFO 1')).join('\n');
    const methods = /METHODS=([A-Z,]+)/.exec(info)?.[1].split(',') ?? [], cookieFile = /COOKIEFILE="((?:[^"\\]|\\.)*)"/.exec(info)?.[1]?.replace(/\\(.)/g, '$1');
    let cookie = null;
    if (cookieFile && (methods.includes('SAFECOOKIE') || methods.includes('COOKIE'))) { try { cookie = readFileSync(cookieFile); } catch {} }
    if (methods.includes('NULL')) await cmd('AUTHENTICATE');
    else if (cookie && methods.includes('SAFECOOKIE')) {
      const cn = randomBytes(32), r = (await cmd(`AUTHCHALLENGE SAFECOOKIE ${cn.toString('hex')}`)).join(' ');
      const sh = /SERVERHASH=([0-9A-Fa-f]{64})/.exec(r)?.[1], sn = /SERVERNONCE=([0-9A-Fa-f]{64})/.exec(r)?.[1];
      if (!sh || !sn) fail('tor', 'tor: AUTHCHALLENGE answer unreadable');
      const msg = Buffer.concat([cookie, cn, Buffer.from(sn, 'hex')]);
      if (createHmac('sha256', 'Tor safe cookie authentication server-to-controller hash').update(msg).digest('hex') !== sh.toLowerCase()) fail('tor', 'tor: the control port did not prove it holds the cookie');
      await cmd(`AUTHENTICATE ${createHmac('sha256', 'Tor safe cookie authentication controller-to-server hash').update(msg).digest('hex')}`);
    } else if (cookie && methods.includes('COOKIE')) await cmd(`AUTHENTICATE ${cookie.toString('hex')}`);
    else if (cfg.password !== null && methods.includes('HASHEDPASSWORD')) await cmd(`AUTHENTICATE "${cfg.password.replace(/[\\"]/g, '\\$&')}"`);
    else fail('tor', `tor: cannot authenticate to the control port (methods ${methods.join(',') || 'none'}; set SIGELO_TOR_PASSWORD, or make the cookie readable)`);
  } catch (e) { s.destroy(); throw e; }
  return { cmd, close: () => { try { s.end('QUIT\r\n'); } catch {} s.destroy(); } };
}
/** What this side can do with Tor: { serve: a control port that authenticates, connect: a SOCKS port that answers }. */
export async function torCaps(cfg) {
  if (!cfg) return { serve: false, connect: false };
  const serve = await torControl(cfg).then((c) => { c.close(); return true; }, () => false);
  const connect = await connectTcp(cfg.socks[0], cfg.socks[1], TOR_PROBE_MS).then((s) => { s.destroy(); return true; }, () => false);
  return { serve, connect };
}
const b32 = (b) => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, v = 0, o = ''; for (const x of b) { v = (v << 8) | x; bits += 8; while (bits >= 5) { o += A[(v >>> (bits - 5)) & 31]; bits -= 5; } } if (bits) o += A[(v << (5 - bits)) & 31]; return o; };
/** A fresh x25519 client key for onion client authorization: { pub (base32, ADD_ONION's), priv (base64, ONION_CLIENT_AUTH_ADD's) }. */
export function clientKey() {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const x = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url'), d = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  return { pub: b32(x), priv: d.toString('base64') };
}
/** The base32 public key of a base64 x25519 private key (the fake tor of the tests checks client auth with it). */
export function clientPub(priv) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(priv, 'base64')]);
  return b32(Buffer.from(createPublicKey(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })).export({ format: 'jwk' }).x, 'base64url'));
}
/** SOCKS5 CONNECT to host:port through tor, tried until ms passed (a new onion takes 10 to 60 s to be reachable). */
export async function socksConnect(cfg, host, port, ms = TOR_CONNECT_MS) {
  const until = Date.now() + ms;
  for (;;) {
    try { return await socksOnce(cfg, host, port); } catch (e) {
      if (Date.now() + 3000 > until) throw e;
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
}
async function socksOnce(cfg, host, port) {
  const s = await connectTcp(cfg.socks[0], cfg.socks[1], 10000);
  // Everything the proxy sent, read n bytes at a time; what follows the reply is the stream's (kept for it).
  let acc = Buffer.alloc(0), want = null, gone = false;
  const onData = (d) => { acc = Buffer.concat([acc, d]); want?.(); };
  const onClose = () => { gone = true; want?.(); };
  s.on('data', onData); s.once('close', onClose);
  const read = (n) => new Promise((ok, no) => {
    const t = setTimeout(() => { want = null; no(Object.assign(new Error('tor: SOCKS gave no answer'), { check: 'tor' })); }, 60000);
    want = () => {
      if (acc.length >= n) { clearTimeout(t); want = null; const x = acc.subarray(0, n); acc = acc.subarray(n); ok(x); }
      else if (gone) { clearTimeout(t); want = null; no(Object.assign(new Error('tor: SOCKS closed'), { check: 'tor' })); }
    };
    want();
  });
  try {
    s.write(Buffer.from([5, 1, 0]));
    const g = await read(2);
    if (g[0] !== 5 || g[1] !== 0) fail('tor', 'tor: SOCKS refused the greeting');
    const h = Buffer.from(host);
    s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([port >> 8, port & 255])]));
    const r = await read(4);
    if (r[1] !== 0) fail('tor', `tor: SOCKS could not reach ${host} (reply ${r[1]})`);
    await read(r[3] === 1 ? 6 : r[3] === 4 ? 18 : (await read(1))[0] + 2);
    s.pause(); s.off('data', onData); s.off('close', onClose);
    s.removeAllListeners('error'); s.on('error', () => {});
    if (acc.length) s.unshift(acc);   // before any 'data' listener: read again by the stream's own
    return s;
  } catch (e) { s.destroy(); throw e; }
}
/** A net.Socket as transfer.mjs's channel: frames behind a u32 length. */
export function streamChannel(sock, first = []) {
  const on = { frame: [], low: [], close: [] }, take = deframer();
  let closed = false;
  const shut = () => { if (closed) return; closed = true; for (const f of on.close) { try { f(); } catch {} } };
  const feed = (d) => { let fs; try { fs = take(new Uint8Array(d.buffer, d.byteOffset, d.length)); } catch { sock.destroy(); return; } for (const f of fs) for (const g of on.frame) g(f); };
  // Paused by whoever handed it over: nothing is read before the frame handlers are on.
  setImmediate(() => { for (const d of first) feed(d); sock.on('data', feed); sock.resume(); });
  sock.on('drain', () => { for (const f of on.low) f(); });
  sock.on('close', shut);
  sock.on('error', () => {});
  return {
    send(f) { if (closed) throw new Error('closed'); sock.write(enframe(f)); },
    buffered: () => sock.writableLength,
    close() { sock.destroy(); shut(); },
    on(e, fn) { on[e].push(fn); },
  };
}

// The Tor path as transfer-engine.mjs's io.tor: the side that serves makes a one-shot onion; the other connects and proves the token.
function torOf(cfg) {
  return {
    caps: () => torCaps(cfg),
    close(a) {
      try { a.server?.close(); } catch {}
      if (a.onion) { const o = a.onion; void torControl(cfg).then(async (c) => { try { await c.cmd(`DEL_ONION ${o}`); } finally { c.close(); } }, () => {}); a.onion = null; }
      if (a.authAdded) { const o = a.authAdded; void torControl(cfg).then(async (c) => { try { await c.cmd(`ONION_CLIENT_AUTH_REMOVE ${o}`); } finally { c.close(); } }, () => {}); a.authAdded = null; }
    },
    async serve(e, side, r, a) {
      if (!a.tor.serve) return;
      const token = randomBytes(32), key = a.peerTor?.serve ? clientKey() : null;
      a.path = 'tor';
      const server = net.createServer();
      a.server = server;
      await new Promise((ok, no) => { server.once('error', no); server.listen(0, '127.0.0.1', ok); });
      const local = server.address().port, port = 1024 + (randomBytes(2).readUInt16BE() % 60000);
      const ctl = await torControl(cfg);
      let onion;
      try {
        const lines = await ctl.cmd(`ADD_ONION NEW:ED25519-V3 Flags=DiscardPK${key ? ',V3Auth' : ''} Port=${port},127.0.0.1:${local}${key ? ` ClientAuthV3=${key.pub}` : ''}`);
        onion = /ServiceID=([a-z2-7]{56})/.exec(lines.join('\n'))?.[1] ?? fail('tor', 'tor: ADD_ONION gave no ServiceID');
      } finally { ctl.close(); }
      a.onion = onion;
      server.on('connection', (sock) => {
        // One stream, the one that proves the token first; any other is closed.
        if (a.channel) { sock.destroy(); return; }
        let got = Buffer.alloc(0);
        const t = setTimeout(() => sock.destroy(), 30000);
        const on = (d) => {
          got = Buffer.concat([got, d]);
          if (got.length < 4 + 33) return;
          sock.pause(); sock.off('data', on); clearTimeout(t);
          let f;
          try { f = readFrame(new Uint8Array(got.subarray(4, 4 + 33))); } catch { sock.destroy(); return; }
          if (got.readUInt32BE(0) !== 33 || f.type !== T.TOKEN || !Buffer.from(f.token).equals(token) || a.channel || e.attempts.get(r.id) !== a) { sock.destroy(); return; }
          server.close();
          const ch = streamChannel(sock, got.length > 37 ? [got.subarray(37)] : []);
          a.channel = ch;
          if (side === 'in') e.pull(r, a, ch); else e.serve(r, a, ch);
        };
        sock.on('data', on); sock.on('error', () => {});
      });
      await e.carrier.send(side === 'in' ? r.from : r.to, { typ: 'onion', id: r.id, attempt: a.attempt, onion, port, auth: key?.priv ?? null, token: token.toString('hex') }, { label: TRANSFER_LABEL, internal: TRANSFER_SEND, local: false });
      e.emit('onion', { id: r.id });
    },
    async connect(e, side, r, x, a) {
      if (!a || a.attempt !== x.attempt || a.channel || !a.tor.connect) return;
      a.path = 'tor';
      try {
        if (x.auth !== null && a.tor.serve) {
          const ctl = await torControl(cfg);
          try { await ctl.cmd(`ONION_CLIENT_AUTH_ADD ${x.onion} x25519:${x.auth}`); a.authAdded = x.onion; } finally { ctl.close(); }
        }
        const sock = await socksConnect(cfg, `${x.onion}.onion`, x.port, e.torConnectMs);
        if (e.attempts.get(r.id) !== a) { sock.destroy(); return; }
        sock.write(enframe(frames.token(Buffer.from(x.token, 'hex'))));
        const ch = streamChannel(sock);
        a.channel = ch;
        if (side === 'in') e.pull(r, a, ch); else e.serve(r, a, ch);
      } catch (err) {
        if (e.attempts.get(r.id) !== a) return;
        e.attempts.delete(r.id); e.closeAttempt(a);
        if (side === 'in') {
          e.interrupt(r.id, 'tor', err.message);
          await e.carrier.send(r.from, { typ: 'end', id: r.id, reason: 'no_path', attempt: a.attempt }, { label: TRANSFER_LABEL, internal: TRANSFER_SEND, local: false }).catch(() => {});
          e.fail('in', r.id, 'no_path', `Tor: ${err.message}`);
        }
      }
    },
  };
}

// ---------------------------------------------------------------- the direct path's library

const HERE = dirname(fileURLToPath(import.meta.url));
/** sigelo-transfer's rtc.mjs, from beside sigelo-contact (an install's node_modules, or the repository's
 *  apps/transfer/, beside apps/contact/), or null: then transfers go over Tor only. Only a package named sigelo-transfer loads. */
export async function loadRtc() {
  for (const d of [join(HERE, '..', 'transfer'), join(HERE, '..', 'sigelo-transfer'), join(HERE, 'node_modules', 'sigelo-transfer')]) {
    try {
      const m = JSON.parse(readFileSync(join(d, 'package.json'), 'utf8'));
      if (m?.name !== 'sigelo-transfer') continue;
      return await import(pathToFileURL(join(d, 'rtc.mjs')).href);
    } catch {}
  }
  return null;
}
