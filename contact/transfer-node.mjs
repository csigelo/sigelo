// SPDX-License-Identifier: MIT
// Transfers on Node (design/transfer.md, adapters/moadim/TRANSFER.md): the files, the consent, the
// signalling over the carrier, the direct path (sigelo-transfer, loaded only when a transfer starts)
// and the Tor path (a tor daemon's control and SOCKS ports; nothing is ever installed for it). The
// protocol is transfer.mjs's.
//
// Two layers. The verbs change the transfers file and queue messages; they run anywhere (a CLI beside
// a watcher queues with local: true and kicks it). The Engine runs in the one process that holds the
// identity's relay session (watch, ui, the MCP server, or a CLI transfer verb with no holder): it takes
// the TRANSFER_LABEL messages the carrier kept apart, makes and answers offers, and moves the bytes.
//
//   send({ carrier, identity, to, path, via, direct, local })  → the record: the file hashed in place, its manifest sent
//   accept({ carrier, identity, id, direct, via, local })      the receiver's yes (free disk checked); the engine offers
//   decline / cancel / resume / forget({ carrier, identity, id, local })
//   intake({ carrier, identity }) → the files asked: manifests and ends filed by a process with no engine (inbox)
//   list({ carrier, identity }) → { out, in }; setDirect({ carrier, identity, contact, on }); settings({ identity, patch })
//   const e = new Engine({ carrier, identity, rtc, tor, stun, pro, onEvent }); e.kick(); await e.idle(); e.live(); await e.close()
//
// The file, 0600, beside the identity (x.json → x.transfers.json), under its own lock:
//   { v, out: { id: sender's record }, in: { id: receiver's record }, direct: { contact's DID: true|false }, settings: { tor, prefer } }
// Partials: <identity>.files/.transfer/<id>.part (0600, written at offsets), <id>.have (a bit a chunk:
// checked and flushed), <id>.list (the chunk hashes); the sender's <id>.list beside them. A finished
// file is placed as send-file places one (<identity>.files/<contact>-<16 hex>/<sha256[0..8]>-<name>),
// never opened, and given to inbox as one item {type: "file", …, transfer: id}.
//
// The direct switch (design §7): direct gives the contact this agent's public and LAN addresses. On
// for own contacts (tier own or ours), asked once for the others (direct_ask until a yes or a no is
// kept); off: Tor, else no path. Tor: settings.tor (default on), effective only when a tor daemon
// answers (SIGELO_TOR: "<control host:port>[,<socks host:port>]", default 127.0.0.1:9051,127.0.0.1:9050;
// "off": none; SIGELO_TOR_PASSWORD for a HashedControlPassword). STUN: SIGELO_STUN, host:port,
// comma-separated ("" = host candidates only), default port 3478 of this agent's relay host and the
// contact's (coturn there, relay/deploy/README.md).
import { createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { closeSync, createReadStream, existsSync, fdatasyncSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, statfsSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { open as openFile } from 'node:fs/promises';
import net from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TRANSFER_SEND, contactDir } from './carrier.mjs';
import { FILE_LABEL, safeName } from './file.mjs';
import { MsgError, fail } from './kdf.mjs';
import { sendable, transact } from './platform-node.mjs';
import {
  ANSWER_WAIT, CHUNK, DAY, GATHER_MS, Have, ICE_MS, MANIFEST_TTL, MAX_SIZE, Pull, Serve, TRANSFER_LABEL, T, WAIT_ALL, WAIT_CONTACT,
  channelLabel, checkMessage, chunkLength, chunksOf, deframer, enframe, frames, listOf, manifest, noPath, pathOrder, readFrame, torRoles,
} from './transfer.mjs';

export const FILE_V = 'sigelo-transfers/1';
export { TRANSFER_LABEL };
const KEPT = 30 * DAY, RETRIES_AUTO = 3, RETRY_MS = 5000, TOR_CONNECT_MS = 120_000, TOR_PROBE_MS = 1500, STUN_PORT = 3478;
const FREE_MARGIN = 64 * CHUNK;
const STATES_LIVE_IN = ['accepted', 'offering', 'active'], STATES_LIVE_OUT = ['active'];

export const transfersPath = (identity) => identity.replace(/\.json$/, '') + '.transfers.json';
const nowS = (carrier) => carrier?.clock ? carrier.clock() : Math.floor(Date.now() / 1000);
const dirOf = (carrier) => join(carrier.filesDir, '.transfer');
const partOf = (carrier, id) => join(dirOf(carrier), `${id}.part`);
const haveOf = (carrier, id) => join(dirOf(carrier), `${id}.have`);
const listPath = (carrier, id, side) => join(dirOf(carrier), `${id}.${side}.list`);
const writeAtomic = (file, bytes) => { const tmp = `${file}.tmp`; rmSync(tmp, { force: true }); writeFileSync(tmp, bytes, { mode: 0o600, flag: 'wx' }); renameSync(tmp, file); };
const folder = (d) => mkdirSync(d, { recursive: true, mode: 0o700 });

// ---------------------------------------------------------------- the file

/** Load, purge, change (fn), save, under the file's lock. → fn's result. */
export function state(identity, now, fn = () => undefined) {
  const file = transfersPath(identity);
  return transact(file, () => {
    let s = { v: FILE_V, out: {}, in: {}, direct: {}, settings: {} };
    if (existsSync(file)) {
      try { s = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { fail('transfer_file', `${file} does not parse (${e.message}): delete it to drop the transfers in progress`); }
      if (s?.v !== FILE_V || typeof s.out !== 'object' || typeof s.in !== 'object') fail('transfer_file', `${file} is not a ${FILE_V} file`);
      s.direct ??= {}; s.settings ??= {};
    }
    const before = JSON.stringify(s);
    for (const side of ['out', 'in']) for (const [k, r] of Object.entries(s[side])) if (['done', 'declined', 'cancelled', 'failed', 'expired'].includes(r.state) && r.at + KEPT < now) delete s[side][k];
    const out = fn(s);
    if (JSON.stringify(s) !== before) writeAtomic(file, JSON.stringify(s, null, 2));
    return out;
  }, 'sigelo transfer');
}

/** The live contact named (DID or name), or not_contact. */
export function contactOf(carrier, who) {
  const cs = carrier.contacts().contacts.filter((c) => !c.revoked);
  const hit = typeof who === 'string' && who.startsWith('did:sigelo:') ? cs.filter((c) => c.did === who || c.chain?.includes(who)) : cs.filter((c) => c.name === who);
  if (hit.length === 0) fail('not_contact', `${JSON.stringify(who)} is not a contact`);
  if (hit.length > 1) fail('name', `${hit.length} contacts are named ${JSON.stringify(who)}: use the DID`);
  return hit[0];
}
const own = (c) => c.tier === 'own' || c.ours === true;
/** May this contact learn this agent's addresses (direct)? true, false, or null: not asked yet (never for own). */
export const directFor = (s, c) => (Object.hasOwn(s.direct, c.did) ? s.direct[c.did] : own(c) ? true : null);
const decideDirect = (s, c, direct) => {
  if (direct === true || direct === false) { s.direct[c.did] = direct; return direct; }
  const d = directFor(s, c);
  if (d === null) fail('direct_ask', `direct shows ${c.name} this computer's public and local addresses; say once whether it may (direct on or off for ${c.name}); off: Tor only`);
  return d;
};
const sendMsg = (carrier, to, content, local) => carrier.send(to, content, { label: TRANSFER_LABEL, internal: TRANSFER_SEND, local });

// ---------------------------------------------------------------- the verbs

/** The sender: hashes the file in place (each chunk, the whole), keeps its list, sends the manifest. */
export async function send({ carrier, identity, to, path, via = 'auto', direct, local = false }) {
  if (via !== 'auto' && via !== 'tor') fail('usage', 'via: auto or tor');
  const c = contactOf(carrier, to);
  const f = sendable(path, { base: identity.replace(/\.json$/, ''), files: carrier.filesDir, log: carrier.logPath }, MAX_SIZE);
  const now = nowS(carrier);
  state(identity, now, (s) => decideDirect(s, c, direct));
  const { hashes, whole } = await hashFile(f.real, f.size);
  const m = manifest({ name: safeName(f.name), size: f.size, sha256: whole, hashes, now });
  folder(dirOf(carrier));
  writeAtomic(listPath(carrier, m.id, 'out'), hashes);
  // The file must still be the one hashed.
  const s2 = statSync(f.real);
  if (s2.size !== f.size || s2.mtimeMs !== f.mtimeMs) fail('file_changed', `${path} changed while it was read: send it again`);
  const rec = { id: m.id, to: c.did, contact: c.name, file: f.real, name: m.name, size: m.size, mtimeMs: f.mtimeMs, sha256: m.sha256, chunks: m.chunks, list: m.list, exp: m.exp, via, state: 'offered', attempt: 0, at: now, sent: 0 };
  state(identity, now, (s) => { s.out[m.id] = rec; });
  try { await sendMsg(carrier, c.did, m, local); } catch (e) {
    state(identity, now, (s) => { s.out[m.id].state = 'failed'; s.out[m.id].reason = e.check ?? 'send'; s.out[m.id].detail = e.message; });
    throw e;
  }
  return rec;
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
const sha = (b) => createHash('sha256').update(b).digest();

const recIn = (s, id) => s.in[id] ?? fail('transfer_unknown', `no transfer ${id} offered to this agent`);
const recOut = (s, id) => s.out[id] ?? fail('transfer_unknown', `no transfer ${id} of this agent's`);
/** Either side's record: → { side, r }. */
const either = (s, id) => (s.in[id] ? { side: 'in', r: s.in[id] } : s.out[id] ? { side: 'out', r: s.out[id] } : fail('transfer_unknown', `no transfer ${id}`));

/** The receiver's yes to a manifest (or a resume of one that stopped): free disk checked, the direct switch settled. */
export function accept({ carrier, identity, id, direct, via }) {
  const now = nowS(carrier);
  return state(identity, now, (s) => {
    const r = recIn(s, id);
    if (!['asked', 'interrupted', 'failed'].includes(r.state) || (r.state === 'failed' && !['no_path', 'cancelled', 'ice_timeout', 'tor'].includes(r.reason))) fail('transfer_state', `transfer ${id} is ${r.state}${r.reason ? ` (${r.reason})` : ''}`);
    if (r.exp <= now) fail('transfer_expired', `the offer of ${r.name} expired`);
    const c = contactOf(carrier, r.from);
    decideDirect(s, c, direct);
    folder(dirOf(carrier));
    const have = readHave(carrier, r), need = r.size - have.bytes(r.size), st = statfsSync(dirOf(carrier)), free = st.bavail * st.bsize;
    if (free < need + FREE_MARGIN) fail('disk_full', `${r.name} needs ${need} bytes more here, ${free} are free`);
    if (via === 'tor' || via === 'auto') r.via = via;
    r.state = 'accepted'; r.auto = 0; r.at = now; delete r.reason; delete r.detail;
    return { ...r };
  });
}
/** The receiver's no: the sender is told declined; nothing was written. */
export async function decline({ carrier, identity, id, local = false }) {
  const now = nowS(carrier);
  const r = state(identity, now, (s) => {
    const x = recIn(s, id);
    if (x.state !== 'asked') fail('transfer_state', `transfer ${id} is ${x.state}`);
    x.state = 'declined'; x.at = now;
    return { ...x };
  });
  await sendMsg(carrier, r.from, { typ: 'end', id, reason: 'declined' }, local).catch(() => {});
  return r;
}
/** Either side stops a transfer: the other is told cancelled; the receiver's partials go. */
export async function cancel({ carrier, identity, id, local = false, engine = null }) {
  const now = nowS(carrier);
  const { side, r } = state(identity, now, (s) => {
    const x = either(s, id);
    if (['done', 'declined', 'cancelled', 'expired'].includes(x.r.state)) fail('transfer_state', `transfer ${id} is ${x.r.state}`);
    x.r.state = 'cancelled'; x.r.at = now;
    return { side: x.side, r: { ...x.r } };
  });
  engine?.drop(id, 'cancelled');
  if (side === 'in') dropPartial(carrier, id);
  await sendMsg(carrier, side === 'in' ? r.from : r.to, { typ: 'end', id, reason: 'cancelled' }, local).catch(() => {});
  return r;
}
/** A finished, failed or unwanted record and its partials gone, here only. */
export function forget({ carrier, identity, id, engine = null }) {
  const now = nowS(carrier);
  const r = state(identity, now, (s) => {
    const x = either(s, id);
    if (x.side === 'in' && STATES_LIVE_IN.includes(x.r.state)) fail('transfer_state', `transfer ${id} is ${x.r.state}: cancel it first`);
    delete s[x.side][id];
    return x.r;
  });
  engine?.drop(id, 'cancelled');
  dropPartial(carrier, id);
  rmSync(listPath(carrier, id, 'out'), { force: true });
  return r;
}
function dropPartial(carrier, id) { for (const f of [partOf(carrier, id), haveOf(carrier, id), listPath(carrier, id, 'in')]) rmSync(f, { force: true }); }

/** Both sides' records, newest first, with what the engine of this process knows live. */
export function list({ carrier, identity, engine = null }) {
  const now = nowS(carrier);
  return state(identity, now, (s) => {
    const live = (r) => ({ ...r, ...(engine?.progress(r.id) ?? {}) });
    const sort = (a, b) => b.at - a.at;
    return {
      out: Object.values(s.out).map((r) => { const { file: _f, ...x } = live(r); return x; }).sort(sort),
      in: Object.values(s.in).map(live).sort(sort),
      direct: { ...s.direct },
      settings: settingsOf(s),
    };
  });
}
export function setDirect({ carrier, identity, contact, on }) {
  if (typeof on !== 'boolean') fail('usage', 'on: true or false');
  const c = contactOf(carrier, contact);
  return state(identity, nowS(carrier), (s) => { s.direct[c.did] = on; return { did: c.did, name: c.name, direct: on }; });
}
const settingsOf = (s) => ({ tor: s.settings.tor !== false, prefer: s.settings.prefer === 'private' ? 'private' : 'fast' });
/** The settings, patched: { tor: true|false, prefer: 'fast'|'private' }. */
export function settings({ identity, patch = {}, now = Math.floor(Date.now() / 1000) }) {
  if (patch.tor !== undefined && typeof patch.tor !== 'boolean') fail('usage', 'tor: on or off');
  if (patch.prefer !== undefined && patch.prefer !== 'fast' && patch.prefer !== 'private') fail('usage', 'prefer: fast or private');
  return state(identity, now, (s) => { if (patch.tor !== undefined) s.settings.tor = patch.tor; if (patch.prefer !== undefined) s.settings.prefer = patch.prefer; return settingsOf(s); });
}

function readHave(carrier, r) {
  const f = haveOf(carrier, r.id);
  try { return new Have(r.chunks, readFileSync(f)); } catch { return new Have(r.chunks); }
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

// ---------------------------------------------------------------- the direct path's library

const HERE = dirname(fileURLToPath(import.meta.url));
/** sigelo-transfer's rtc.mjs, from beside sigelo-contact (an install's node_modules, or the repository's
 *  sigelo-transfer/), or null: then transfers go over Tor only. Only a package named sigelo-transfer loads. */
export async function loadRtc() {
  for (const d of [join(HERE, '..', 'sigelo-transfer'), join(HERE, 'node_modules', 'sigelo-transfer')]) {
    try {
      const m = JSON.parse(readFileSync(join(d, 'package.json'), 'utf8'));
      if (m?.name !== 'sigelo-transfer') continue;
      return await import(pathToFileURL(join(d, 'rtc.mjs')).href);
    } catch {}
  }
  return null;
}
const hostOf = (relay) => (typeof relay === 'string' && relay ? relay.replace(/:\d+$/, '') : null);
/** The STUN servers for a transfer with contact c: SIGELO_STUN, else this agent's relay host and the contact's, port 3478. */
export function stunFor(carrier, c, env = process.env) {
  if (env.SIGELO_STUN !== undefined) return env.SIGELO_STUN.split(',').map((x) => x.trim()).filter(Boolean).map((x) => (/:\d+$/.test(x) ? x : `${x}:${STUN_PORT}`));
  return [...new Set([hostOf(carrier.relay), hostOf(c?.relay)].filter(Boolean))].map((h) => `${h}:${STUN_PORT}`);
}

/**
 * Without an engine (a CLI inbox, transfer list): the manifests and ends the carrier kept, taken and
 * filed; offers, answers and onions stay for the engine of the next session. → the files now asked.
 */
export async function intake({ carrier, identity }) {
  const e = new Engine({ carrier, identity, rtc: async () => null, tor: null, timer: false });
  const asked = [];
  e.onEvent = (x) => { if (x.what === 'asked') asked.push(x); };
  await e.round((m) => ['manifest', 'end'].includes(m?.content?.typ) && m.content.reason !== 'try_tor');
  await e.close();
  return asked;
}

// ---------------------------------------------------------------- the engine

export class Engine {
  /**
   * carrier: started (it holds the session); identity: the identity file; rtc: () → sigelo-transfer or null
   * (loadRtc); tor: torConfig(); stun: a list, or null for stunFor; pro: () → whether this agent's pool is Pro
   * (T4 knows it; until then false: the free order); onEvent(e): {type: 'transfer', what, id, …}.
   */
  constructor({ carrier, identity, rtc = loadRtc, tor = torConfig(), stun = null, pro = () => false, onEvent = () => {}, retryMs = RETRY_MS, torConnectMs = TOR_CONNECT_MS, timer = true }) {
    Object.assign(this, { carrier, identity, rtcLoad: rtc, torCfg: tor, stun, pro, onEvent, retryMs, torConnectMs });
    this.attempts = new Map();   // id → { role, attempt, peer, channel, proto, onion, server, got, sent, path }
    this.chain = Promise.resolve(); this.again = false; this.running = false; this.closed = false;
    this.timer = timer ? setInterval(() => this.kick(), 2000) : null; this.timer?.unref?.();
    this.capsAt = 0; this.caps = null;
  }
  now() { return nowS(this.carrier); }
  emit(what, x) { try { this.onEvent({ type: 'transfer', what, ...x, at_ms: Date.now() }); } catch {} }
  async rtc() { if (this.rtcMod === undefined) this.rtcMod = await this.rtcLoad(); return this.rtcMod; }
  async torCaps() {
    const on = state(this.identity, this.now(), (s) => settingsOf(s).tor);
    if (!on || !this.torCfg) return { serve: false, connect: false };
    if (!this.caps || Date.now() - this.capsAt > 60_000) { this.caps = await torCaps(this.torCfg); this.capsAt = Date.now(); }
    return this.caps;
  }
  /** One round soon (a `transfer` event, a kick from a verb beside this process). */
  kick() {
    if (this.closed) return this.chain;
    if (this.running) { this.again = true; return this.chain; }
    this.running = true;
    this.chain = this.chain.then(async () => { do { this.again = false; await this.round(); } while (this.again && !this.closed); }).catch((e) => this.emit('error', { detail: e.message })).finally(() => { this.running = false; });
    return this.chain;
  }
  live() { return this.attempts.size > 0 || state(this.identity, this.now(), (s) => Object.values(s.in).some((r) => STATES_LIVE_IN.includes(r.state)) || Object.values(s.out).some((r) => STATES_LIVE_OUT.includes(r.state))); }
  /** Resolves true when nothing is live (busy: another test, e.g. a transfer's record not finished), false once ms passed. */
  async idle(ms = Infinity, busy = () => this.live()) {
    const until = Date.now() + ms;
    while (Date.now() < until && !this.closed) {
      await this.kick();
      if (!busy()) return true;
      await new Promise((r) => setTimeout(r, 500));
    }
    return false;
  }
  progress(id) { const a = this.attempts.get(id); return a ? { live: a.path ?? 'connecting', got: a.got, sent: a.sent, rate: a.rate ?? null } : null; }
  /** An attempt of this process stopped (cancel, forget). */
  drop(id, reason) { const a = this.attempts.get(id); if (!a) return; this.attempts.delete(id); a.stopped = reason; try { a.proto?.stop(reason); } catch {} this.#closeAttempt(a); }
  async close() {
    this.closed = true;
    if (this.timer) clearInterval(this.timer);
    await this.chain.catch(() => {});
    for (const [id, a] of [...this.attempts]) {
      this.attempts.delete(id);
      a.stopped = 'closed';
      try { a.proto?.stop('cancelled'); } catch {}
      this.#closeAttempt(a);
      // Stopped here, not refused there: the receiver may resume it later.
      state(this.identity, this.now(), (s) => { const r = s.in[id] ?? s.out[id]; if (r && r.state === 'active') r.state = s.in[id] ? 'interrupted' : 'offered'; });
    }
  }
  #closeAttempt(a) {
    try { a.channel?.close(); } catch {}
    try { a.peer?.close(); } catch {}
    try { a.server?.close(); } catch {}
    if (a.onion) { const o = a.onion; void torControl(this.torCfg).then(async (c) => { try { await c.cmd(`DEL_ONION ${o}`); } finally { c.close(); } }, () => {}); a.onion = null; }
    if (a.authAdded) { const o = a.authAdded; void torControl(this.torCfg).then(async (c) => { try { await c.cmd(`ONION_CLIENT_AUTH_REMOVE ${o}`); } finally { c.close(); } }, () => {}); a.authAdded = null; }
  }

  async round(pick) {
    for (const m of this.carrier.takeTransfers(pick)) {
      try { await this.#onMessage(m); } catch (e) {
        if (!(e instanceof MsgError)) throw e;
        this.emit('refused', { from: m.from, check: e.check, detail: e.message });
      }
    }
    const now = this.now();
    const todo = state(this.identity, now, (s) => {
      const out = [];
      for (const r of Object.values(s.in)) {
        if (r.state === 'asked' && r.exp <= now) { r.state = 'expired'; r.at = now; }
        if (r.state === 'accepted' && !this.attempts.has(r.id)) out.push(r.id);
        if ((r.state === 'offering' || r.state === 'active') && !this.attempts.has(r.id)) { r.state = 'interrupted'; r.reason = 'drop'; r.retryAt = 0; }
        if (r.state === 'offering' && r.offerAt + ANSWER_WAIT < now) { r.state = 'interrupted'; r.reason = 'lapsed'; r.detail = 'no answer within 10 minutes: is the sender online? transfer resume'; this.drop(r.id, 'lapsed'); }
        if (r.state === 'interrupted' && r.reason === 'drop' && (r.auto ?? 0) < RETRIES_AUTO && !this.attempts.has(r.id) && (r.retryAt ?? 0) <= Date.now()) { r.auto = (r.auto ?? 0) + 1; r.state = 'accepted'; out.push(r.id); }
        if (['interrupted', 'failed', 'cancelled'].includes(r.state) && (r.last ?? r.at) + MANIFEST_TTL < now && existsSync(partOf(this.carrier, r.id))) { dropPartial(this.carrier, r.id); r.state = 'expired'; }
      }
      for (const r of Object.values(s.out)) {
        if (r.state === 'offered' && r.exp <= now) { r.state = 'expired'; r.at = now; }
        if (r.state === 'active' && !this.attempts.has(r.id)) r.state = 'offered';
      }
      return out;
    });
    if (pick) return;   // intake: no session here
    for (const id of todo) await this.#offer(id).catch((e) => this.#fail('in', id, e.check ?? 'offer', e.message));
  }

  #fail(side, id, reason, detail) {
    state(this.identity, this.now(), (s) => { const r = s[side][id]; if (r && !['done', 'cancelled', 'declined'].includes(r.state)) Object.assign(r, { state: 'failed', reason, detail, at: this.now() }); });
    this.emit('failed', { id, reason, detail });
  }

  async #onMessage(m) {
    const x = checkMessage(m.content), now = this.now();
    if (x.typ === 'manifest') {
      const r = state(this.identity, now, (s) => {
        if (s.in[x.id]) return null;   // seen
        if (x.exp <= now) return null;
        const waiting = Object.values(s.in).filter((y) => y.state === 'asked');
        if (waiting.length >= WAIT_ALL || waiting.filter((y) => y.from === m.from).length >= WAIT_CONTACT) return 'busy';
        s.in[x.id] = { id: x.id, from: m.from, contact: m.name, name: safeName(x.name), size: x.size, sha256: x.sha256, chunks: x.chunks, list: x.list, exp: x.exp, state: 'asked', attempt: 0, at: now, got: 0 };
        return { ...s.in[x.id] };
      });
      if (r === 'busy') { await sendMsg(this.carrier, m.from, { typ: 'end', id: x.id, reason: 'busy' }, false).catch(() => {}); return; }
      if (r) this.emit('asked', { id: r.id, from: r.from, contact: r.contact, name: r.name, size: r.size });
      return;
    }
    // Any other: only from the contact the transfer is with.
    const { side, r } = state(this.identity, now, (s) => (s.out[x.id]?.to === m.from ? { side: 'out', r: { ...s.out[x.id] } } : s.in[x.id]?.from === m.from ? { side: 'in', r: { ...s.in[x.id] } } : { side: null, r: null }));
    if (!r) fail('transfer_unknown', `a ${x.typ} for a transfer this agent has with no such contact`);
    if (x.typ === 'end') return this.#onEnd(side, r, x);
    // Detached: ICE (30 s) and a Tor connection (up to 2 minutes) must not hold the next message.
    const bg = (p) => { void p.catch((e) => this.emit('error', { id: r.id, detail: e.message })); };
    if (side === 'out' && x.typ === 'offer') return bg(this.#onOffer(r, x, m));
    if (side === 'in' && x.typ === 'answer') return bg(this.#onAnswer(r, x));
    if (x.typ === 'onion') return bg(this.#onOnion(side, r, x));
    fail('transfer_message', `a ${x.typ} on the ${side === 'in' ? 'receiving' : 'sending'} side`);
  }

  async #onEnd(side, r, x) {
    const a = this.attempts.get(r.id);
    if (x.reason === 'try_tor') {
      if (side !== 'out' || !a || a.attempt !== x.attempt) return;
      return this.#serveTor(side, r, a);
    }
    if (x.reason === 'done' && side === 'out') {
      state(this.identity, this.now(), (s) => { if (s.out[r.id]) Object.assign(s.out[r.id], { state: 'done', at: this.now(), sent: r.size }); });
      if (a) { this.attempts.delete(r.id); this.#closeAttempt(a); }
      this.emit('done', { id: r.id, side, name: r.name });
      return;
    }
    if (a && x.attempt !== undefined && x.attempt !== a.attempt) return;
    if (a) { this.attempts.delete(r.id); a.stopped = x.reason; try { a.proto?.stop(x.reason); } catch {} this.#closeAttempt(a); }
    const st = x.reason === 'declined' ? 'declined' : x.reason === 'cancelled' ? 'cancelled' : 'failed';
    state(this.identity, this.now(), (s) => { const y = s[side][r.id]; if (y && !['done'].includes(y.state)) Object.assign(y, { state: st, ...(st === 'failed' && { reason: x.reason, detail: x.reason === 'no_path' ? noPath(y.contact) : `the other side ended it: ${x.reason}` }), at: this.now() }); });
    if (side === 'in' && ['cancelled', 'chunk_hash', 'file_changed'].includes(x.reason)) dropPartial(this.carrier, r.id);
    this.emit(st, { id: r.id, side, reason: x.reason });
  }

  // ---- the receiver: an attempt is an offer
  async #offer(id) {
    const now = this.now();
    const prev = this.attempts.get(id);
    if (prev) { this.attempts.delete(id); this.#closeAttempt(prev); }
    const r = state(this.identity, now, (s) => ({ ...s.in[id], directOk: directFor(s, contactOf(this.carrier, s.in[id].from)) === true, pro: this.pro(), prefer: settingsOf(s).prefer }));
    const c = contactOf(this.carrier, r.from), tor = await this.torCaps(), rtc = await this.rtc();
    // The paths this attempt may take, in order; Tor here means this side can play either part.
    const order = pathOrder({ pro: r.pro, prefer: r.prefer, via: r.via === 'tor' ? 'tor' : 'auto', direct: r.directOk && rtc !== null, tor: tor.serve || tor.connect });
    if (order.length === 0) {
      this.#fail('in', id, 'no_path', r.directOk ? noPath(c.name) : `direct is off for ${c.name} and Tor is not on here: ${noPath(c.name)}`);
      await sendMsg(this.carrier, r.from, { typ: 'end', id, reason: 'no_path' }, false).catch(() => {});
      return;
    }
    const attempt = (r.attempt ?? 0) + 1, a = { role: 'in', attempt, order, tor, got: 0, sent: 0 };
    this.attempts.set(id, a);
    let sdp = null;
    if (order[0] === 'direct') {
      a.peer = await rtc.peer({ stun: this.stun ?? stunFor(this.carrier, c), gatherMs: GATHER_MS });
      sdp = await a.peer.offer(channelLabel(id, attempt));
    }
    state(this.identity, now, (s) => Object.assign(s.in[id], { state: 'offering', attempt, offerAt: this.now(), path: order[0] }));
    await sendMsg(this.carrier, r.from, { typ: 'offer', id, attempt, sdp, tor, ...(order[0] === 'tor' && { via: 'tor' }) }, false);
    this.emit('offered', { id, attempt, path: order[0] });
  }
  async #onAnswer(r, x) {
    const a = this.attempts.get(r.id);
    if (!a || a.attempt !== x.attempt || a.answered) return;
    a.answered = true; a.peerTor = x.tor;
    state(this.identity, this.now(), (s) => { if (s.in[r.id]) s.in[r.id].state = 'active'; });
    if (a.order[0] === 'direct' && x.sdp !== null && a.peer) {
      try {
        await a.peer.accept(x.sdp);
        a.path = 'direct';
        const ch = await a.peer.open(ICE_MS);
        if (this.attempts.get(r.id) !== a) { ch.close(); return; }
        return this.#pull(r, a, ch);
      } catch (e) { if (this.attempts.get(r.id) !== a) return; a.peer?.close(); a.peer = null; this.emit('no_direct', { id: r.id, detail: e.message }); }
    }
    return this.#nextPath(r, a, a.order[0] === 'direct' ? 1 : 0);
  }
  // The receiver, after the direct path failed (or was not offered): Tor if both sides can, else the next attempt or no path.
  async #nextPath(r, a, k) {
    const rest = a.order.slice(k);
    const who = torRoles(a.peerTor, a.tor);
    if (rest[0] === 'tor' && who) {
      a.path = 'tor';
      if (who === 'receiver') return this.#serveTor('in', r, a);
      await sendMsg(this.carrier, r.from, { typ: 'end', id: r.id, reason: 'try_tor', attempt: a.attempt }, false);
      return;
    }
    // Tor first (Pro private) and it cannot: direct as a new attempt.
    if (rest[0] === 'tor' && rest.includes('direct') && a.order[0] === 'tor') {
      state(this.identity, this.now(), (s) => { s.in[r.id].via = 'auto'; s.in[r.id].state = 'accepted'; });
      this.attempts.delete(r.id); this.#closeAttempt(a);
      return this.kick();
    }
    this.attempts.delete(r.id); this.#closeAttempt(a);
    const c = contactOf(this.carrier, r.from);
    this.#fail('in', r.id, 'no_path', noPath(c.name));
    await sendMsg(this.carrier, r.from, { typ: 'end', id: r.id, reason: 'no_path', attempt: a.attempt }, false).catch(() => {});
  }

  // ---- the sender: an offer is answered
  async #onOffer(r, x, m) {
    if (['done', 'cancelled', 'declined', 'expired'].includes(r.state)) { await sendMsg(this.carrier, m.from, { typ: 'end', id: r.id, reason: r.state === 'done' ? 'done' : 'cancelled' }, false).catch(() => {}); return; }
    if (x.attempt <= (r.attempt ?? 0)) return;
    const prev = this.attempts.get(r.id);
    if (prev) { this.attempts.delete(r.id); this.#closeAttempt(prev); }
    // Read in place: the file must be the one hashed.
    let st;
    try { st = statSync(r.file); } catch { st = null; }
    if (!st || st.size !== r.size || st.mtimeMs !== r.mtimeMs) {
      this.#fail('out', r.id, 'file_changed', `${r.file} changed or went since it was offered: send it again`);
      await sendMsg(this.carrier, m.from, { typ: 'end', id: r.id, reason: 'file_changed' }, false).catch(() => {});
      return;
    }
    const c = contactOf(this.carrier, r.to), tor = await this.torCaps(), rtc = await this.rtc();
    const directOk = state(this.identity, this.now(), (s) => directFor(s, c) === true) && r.via !== 'tor' && x.via !== 'tor' && x.sdp !== null && rtc !== null;
    const a = { role: 'out', attempt: x.attempt, tor, peerTor: x.tor, got: 0, sent: 0 };
    this.attempts.set(r.id, a);
    state(this.identity, this.now(), (s) => Object.assign(s.out[r.id], { state: 'active', attempt: x.attempt }));
    let sdp = null;
    if (directOk) {
      a.peer = await rtc.peer({ stun: this.stun ?? stunFor(this.carrier, c), gatherMs: GATHER_MS });
      sdp = await a.peer.answer(x.sdp, channelLabel(r.id, x.attempt));
    }
    await sendMsg(this.carrier, m.from, { typ: 'answer', id: r.id, attempt: x.attempt, sdp, tor }, false);
    if (!a.peer) return;   // the receiver says what comes next: try_tor, an onion, or end
    try {
      a.path = 'direct';
      const ch = await a.peer.open(ICE_MS);
      if (this.attempts.get(r.id) !== a) { ch.close(); return; }
      this.#serve(r, a, ch);
    } catch (e) { if (this.attempts.get(r.id) === a) { a.peer?.close(); a.peer = null; a.path = null; } }
  }

  // ---- Tor: the side that serves makes a one-shot onion; the other connects and proves the token
  async #serveTor(side, r, a) {
    if (!a.tor.serve || !this.torCfg) return;
    const token = randomBytes(32), key = a.peerTor?.serve ? clientKey() : null;
    a.path = 'tor';
    const server = net.createServer();
    a.server = server;
    await new Promise((ok, no) => { server.once('error', no); server.listen(0, '127.0.0.1', ok); });
    const local = server.address().port, port = 1024 + (randomBytes(2).readUInt16BE() % 60000);
    const ctl = await torControl(this.torCfg);
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
        if (got.readUInt32BE(0) !== 33 || f.type !== T.TOKEN || !Buffer.from(f.token).equals(token) || a.channel || this.attempts.get(r.id) !== a) { sock.destroy(); return; }
        server.close();
        const ch = streamChannel(sock, got.length > 37 ? [got.subarray(37)] : []);
        a.channel = ch;
        if (side === 'in') this.#pull(r, a, ch); else this.#serve(r, a, ch);
      };
      sock.on('data', on); sock.on('error', () => {});
    });
    await sendMsg(this.carrier, side === 'in' ? r.from : r.to, { typ: 'onion', id: r.id, attempt: a.attempt, onion, port, auth: key?.priv ?? null, token: token.toString('hex') }, false);
    this.emit('onion', { id: r.id });
  }
  async #onOnion(side, r, x) {
    const a = this.attempts.get(r.id);
    if (!a || a.attempt !== x.attempt || a.channel || !a.tor.connect || !this.torCfg) return;
    a.path = 'tor';
    try {
      if (x.auth !== null && a.tor.serve) {
        const ctl = await torControl(this.torCfg);
        try { await ctl.cmd(`ONION_CLIENT_AUTH_ADD ${x.onion} x25519:${x.auth}`); a.authAdded = x.onion; } finally { ctl.close(); }
      }
      const sock = await socksConnect(this.torCfg, `${x.onion}.onion`, x.port, this.torConnectMs);
      if (this.attempts.get(r.id) !== a) { sock.destroy(); return; }
      sock.write(enframe(frames.token(Buffer.from(x.token, 'hex'))));
      const ch = streamChannel(sock);
      a.channel = ch;
      if (side === 'in') this.#pull(r, a, ch); else this.#serve(r, a, ch);
    } catch (e) {
      if (this.attempts.get(r.id) !== a) return;
      this.attempts.delete(r.id); this.#closeAttempt(a);
      if (side === 'in') {
        this.#interrupt(r.id, 'tor', e.message);
        await sendMsg(this.carrier, r.from, { typ: 'end', id: r.id, reason: 'no_path', attempt: a.attempt }, false).catch(() => {});
        this.#fail('in', r.id, 'no_path', `Tor: ${e.message}`);
      }
    }
  }

  // ---- the bytes
  #serve(r, a, ch) {
    a.channel = ch;
    const hashes = new Uint8Array(readFileSync(listPath(this.carrier, r.id, 'out')));
    let fh = null;
    const t0 = Date.now();
    const read = async (i) => {
      fh ??= await openFile(r.file, 'r');
      const s = await fh.stat();
      if (s.size !== r.size || s.mtimeMs !== r.mtimeMs) fail('file_changed', `${r.file} changed`);
      const len = chunkLength(r.size, i), buf = Buffer.alloc(len);
      const { bytesRead } = await fh.read(buf, 0, len, i * CHUNK);
      if (bytesRead !== len) fail('file_changed', `${r.file} is shorter`);
      return new Uint8Array(buf.buffer, buf.byteOffset, len);
    };
    const m = { ...r };
    this.emit('active', { id: r.id, side: 'out', path: a.path });
    a.proto = new Serve({
      m, hashes, channel: ch, read,
      onProgress: (n) => { a.sent = n; a.rate = n / 1e6 / Math.max(0.001, (Date.now() - t0) / 1000); },
      onEnd: (reason, o) => {
        void fh?.close().catch(() => {});
        if (this.attempts.get(r.id) !== a) return;
        this.attempts.delete(r.id); this.#closeAttempt(a);
        if (reason === 'done' && o.remote) {
          state(this.identity, this.now(), (s) => { if (s.out[r.id]) Object.assign(s.out[r.id], { state: 'done', at: this.now(), sent: r.size, path_used: a.path }); });
          this.emit('done', { id: r.id, side: 'out', name: r.name, via: a.path, rate: a.rate });
        } else if (reason === 'chunk_hash' || reason === 'file_changed') {
          this.#fail('out', r.id, reason, `ended: ${reason}`);
        } else {
          // A drop or a stop on the channel: the receiver resumes with a new offer; a cancel comes as an end message.
          state(this.identity, this.now(), (s) => { if (s.out[r.id]?.state === 'active') s.out[r.id].state = 'offered'; });
          this.emit('interrupted', { id: r.id, side: 'out' });
        }
      },
    });
    a.proto.start();
  }
  #pull(r, a, ch) {
    a.channel = ch;
    const carrier = this.carrier, id = r.id;
    folder(dirOf(carrier));
    const part = partOf(carrier, id);
    closeSync(openSync(part, 'a', 0o600));
    const fd = openSync(part, 'r+');
    const have = readHave(carrier, r);
    let known = null;
    try { known = new Uint8Array(readFileSync(listPath(carrier, id, 'in'))); if (listOf(known) !== r.list) known = null; } catch {}
    a.got = have.bytes(r.size);
    const t0 = Date.now(), start = a.got;
    let saved = Date.now();
    this.emit('active', { id, side: 'in', path: a.path });
    const write = (b, pos) => { let o = 0; while (o < b.length) o += writeSync(fd, b, o, b.length - o, pos + o); };
    a.proto = new Pull({
      m: { ...r, chunk: CHUNK }, have, hashes: known, channel: ch,
      write: async (i, bytes) => { write(bytes, i * CHUNK); },
      flush: async () => {
        datasync(fd);
        // .have once Pull has set the bits, after the bytes are on disk: a bit means checked and flushed.
        setImmediate(() => {
          try { writeAtomic(haveOf(carrier, id), have.bits); } catch {}
          if (Date.now() - saved > 2000) { saved = Date.now(); state(this.identity, this.now(), (s) => { if (s.in[id]) Object.assign(s.in[id], { got: a.got, last: this.now() }); }); }
        });
      },
      onList: (h) => { try { writeAtomic(listPath(carrier, id, 'in'), h); } catch {} },
      onProgress: (n) => { a.got += n; a.rate = (a.got - start) / 1e6 / Math.max(0.001, (Date.now() - t0) / 1000); },
      onEnd: (reason, o) => { void this.#pulled(r, a, fd, have, reason, o); },
    });
    a.proto.start();
  }
  async #pulled(r, a, fd, have, reason, o) {
    const id = r.id, carrier = this.carrier;
    try { writeAtomic(haveOf(carrier, id), have.bits); } catch {}
    if (reason !== 'complete') {
      try { closeSync(fd); } catch {}
      if (this.attempts.get(id) !== a) return;
      this.attempts.delete(id); this.#closeAttempt(a);
      if (o.gone || (reason === 'cancelled' && !o.remote)) return this.#interrupt(id, 'drop', 'the channel went: resumed with a new offer');
      if (reason === 'cancelled') { state(this.identity, this.now(), (s) => { if (s.in[id]) Object.assign(s.in[id], { state: 'cancelled', at: this.now() }); }); dropPartial(carrier, id); return; }
      this.#fail('in', id, reason, `ended: ${reason}`);
      if (reason === 'chunk_hash' || reason === 'file_changed') dropPartial(carrier, id);
      if (!o.remote) await sendMsg(carrier, r.from, { typ: 'end', id, reason, attempt: a.attempt }, false).catch(() => {});
      return;
    }
    // Every chunk checked and flushed: the whole file read back from disk.
    datasync(fd); closeSync(fd);
    const whole = await new Promise((ok, no) => {
      const h = createHash('sha256');
      createReadStream(partOf(carrier, id)).on('data', (d) => h.update(d)).on('end', () => ok(h.digest('hex'))).on('error', no);
    });
    if (whole !== r.sha256) {
      a.proto.finish('chunk_hash');
      this.attempts.delete(id); this.#closeAttempt(a);
      dropPartial(carrier, id);
      this.#fail('in', id, 'chunk_hash', 'the file read back is not the manifest\'s: dropped');
      return;
    }
    const c = contactOf(carrier, r.from), dir = join(carrier.filesDir, contactDir(c));
    folder(dir);
    let path = null;
    for (let i = 0; i < 64 && path === null; i++) {
      const p = join(dir, `${r.sha256.slice(0, 8)}-${i === 0 ? '' : `${i + 1}-`}${r.name}`);
      try { linkSync(partOf(carrier, id), p); unlinkSync(partOf(carrier, id)); path = p; } catch (e) {
        if (e.code === 'EEXIST') continue;
        if (!existsSync(p)) { renameSync(partOf(carrier, id), p); path = p; }
      }
    }
    if (path === null) { this.#fail('in', id, 'file_exists', `64 files of that name and hash are in ${dir} already`); return; }
    for (const f of [haveOf(carrier, id), listPath(carrier, id, 'in')]) rmSync(f, { force: true });
    a.proto.finish('done');
    state(this.identity, this.now(), (s) => { if (s.in[id]) Object.assign(s.in[id], { state: 'done', got: r.size, at: this.now(), saved: path, path_used: a.path }); });
    this.attempts.delete(id);
    setTimeout(() => this.#closeAttempt(a), 2000).unref?.();
    carrier.deliver({ type: 'file', from: c.did, contact: c.name, current_did: c.current_did, label: FILE_LABEL, name: r.name, size: r.size, sha256: r.sha256, path, transfer: id, via: a.path });
    await sendMsg(carrier, r.from, { typ: 'end', id, reason: 'done', attempt: a.attempt }, false).catch(() => {});
    this.emit('done', { id, side: 'in', name: r.name, path, via: a.path, rate: a.rate });
  }
  #interrupt(id, reason, detail) {
    state(this.identity, this.now(), (s) => { const r = s.in[id]; if (r && STATES_LIVE_IN.includes(r.state)) Object.assign(r, { state: 'interrupted', reason, detail, retryAt: Date.now() + this.retryMs, last: this.now() }); });
    this.emit('interrupted', { id, side: 'in', reason });
  }
}

/** A verb's resume: a stopped transfer offered again (the engine makes the offer; only what .have lacks is asked). */
export const resume = (o) => accept(o);

const datasync = (fd) => { try { fdatasyncSync(fd); } catch {} };
