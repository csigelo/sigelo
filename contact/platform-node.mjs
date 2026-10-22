// SPDX-License-Identifier: MIT
// The Node platform of sigelo-contact (design/apps.md §4.2): every call the carrier, the contact
// store and the enrolment file make to the file system, the network, the lock and the CPU, as one
// object. new Carrier({ ..., platform }) takes another (a browser's, a test's in-memory one); without
// one it is this, and the behaviour is the one these calls had inside carrier.mjs.
//
//   platform = {
//     files: { read(name) → Uint8Array | null, write(name, bytes, { how }), remove(name), list(folder) → names,
//              folder(name, private = []), add(names, bytes) → name | null },   // sync
//     path:  { join, dirname, resolve },   // names are paths here: the separator is the system's
//     flush: async () => {},               // a rename is durable: nothing to wait for
//     transact: (name, fn, who) → fn(),    // fn under the lock file `<name>.lock`
//     owner: async (identity, kind) → { release },   // `<identity>.ui.pid` (sigelo-agent ui / watch)
//     fetch: async (url, { method, body, signal }) → { status, type, headers.get, body },   // fetch, or a tunnel
//     mqtt:  (url, opts) → an MQTT.js client (mqtts:// or wss://; HTTPS_PROXY for wss)
//     transports: ['mqtts', 'wss'],
//     pow:   async (prefix, bits, { deadline, signal }) → the counter as a string, or null past deadline
//     env:   optionsFromEnv(process.env) and proxy (HTTPS_PROXY), read when asked
//     openPath(path, own) → { bytes, name }: a file named by path, for sendFile (its checks)
//   }
//
// files.write: how "replace" (the default) writes a fresh 0600 temporary name exclusively, then
// renames it over name, so a reader sees the old file or the new one; "new" creates name, 0600,
// and throws (code EEXIST) if it exists; "plain" writes name in place, 0600. files.folder: name
// and its parents created 0700, and each of `private` set 0700. files.add: bytes saved under the
// first of names not taken (a hard link of one temporary copy, else an exclusive write), never
// over a file; → the name, or null when all are taken. files.remove: a file or a folder, absent or not.
import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { chmodSync, closeSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { connect } from 'mqtt';
import { MsgError, fail } from './kdf.mjs';
import { MAX_FILE } from './file.mjs';
import { optionsFromEnv } from './carrier.mjs';

// Milliseconds an HTTP CONNECT through the proxy may take (carrier.mjs HTTP_MS).
const HTTP_MS = 15000;

// ---------------------------------------------------------------- files

const tmpName = (path) => join(dirname(path), `.${basename(path)}.${randomBytes(8).toString('hex')}.tmp`);

export const files = {
  read(name) {
    try { return readFileSync(name); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  },
  write(name, bytes, { how = 'replace' } = {}) {
    if (how === 'new') return writeFileSync(name, bytes, { mode: 0o600, flag: 'wx' });
    if (how === 'plain') return writeFileSync(name, bytes, { mode: 0o600 });
    const tmp = tmpName(name);
    writeFileSync(tmp, bytes, { mode: 0o600, flag: 'wx' });
    renameSync(tmp, name);
  },
  remove(name) { rmSync(name, { recursive: true, force: true }); },
  list(folder) { try { return readdirSync(folder); } catch { return []; } },
  folder(name, priv = []) {
    mkdirSync(name, { recursive: true, mode: 0o700 });
    for (const p of priv) chmodSync(p, 0o700);
  },
  add(names, bytes) {
    const tmp = join(dirname(names[0]), `.${randomBytes(8).toString('hex')}.tmp`);
    writeFileSync(tmp, bytes, { mode: 0o600, flag: 'wx' });
    try {
      for (const at of names) {
        try { linkSync(tmp, at); return at; } catch (e) {
          if (e.code === 'EEXIST') continue;
          // No hard links here (FAT, some network file systems): written again, exclusively.
          if (!['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'EXDEV', 'ENOSYS'].includes(e.code)) throw e;
          try { writeFileSync(at, bytes, { mode: 0o600, flag: 'wx' }); return at; } catch (e2) { if (e2.code !== 'EEXIST') throw e2; }
        }
      }
      return null;
    } finally { rmSync(tmp, { force: true }); }
  },
};

export const path = { join, dirname, resolve };

// One lock file per name: every change is load, change, save inside it, so a CLI verb and a
// long-running carrier on the same identity cannot undo each other. As
// adapters/moadim/sigelo-agent-monero.ts withLock. who: the processes named in the refusal.
const LOCK_TRIES = 200, LOCK_MS = 25;
export function transact(name, fn, who = 'sigelo-contact') {
  const lock = `${name}.lock`, idle = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; ; i++) {
    try { closeSync(openSync(lock, 'wx', 0o600)); break; } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (i === LOCK_TRIES) fail('lock', `${lock} is still held after ${(LOCK_TRIES * LOCK_MS) / 1000} s: another ${who} process holds it, or one was killed holding it; delete the file to continue`);
      Atomics.wait(idle, 0, 0, LOCK_MS);
    }
  }
  try { return fn(); } finally { rmSync(lock, { force: true }); }
}

// ---------------------------------------------------------------- one owner per identity

// The pid lock beside an identity file, as adapters/moadim/sigelo-agent-ui.ts takeLock writes it:
// "<pid>" for a page (kind ui), "<pid> watch" for a watcher. A lock whose process is gone is taken over.
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };
function holder(f) {
  try {
    const m = /^(\d+)( watch)?$/.exec(readFileSync(f, 'utf8').trim()), pid = Number(m?.[1]);
    return m && Number.isSafeInteger(pid) && pid > 0 && alive(pid) ? { pid, kind: m[2] ? 'watch' : 'ui' } : null;
  } catch { return null; }
}
export async function owner(identity, kind = 'ui') {
  const f = resolve(identity).replace(/\.json$/, '') + '.ui.pid', mine = kind === 'ui' ? String(process.pid) : `${process.pid} watch`;
  for (let i = 0; i < 3; i++) {
    try {
      const fd = openSync(f, 'wx', 0o600);
      writeSync(fd, mine); closeSync(fd);
      return { release: () => { try { if (readFileSync(f, 'utf8').trim() === mine) rmSync(f, { force: true }); } catch {} } };
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      const h = holder(f);
      if (h !== null) throw Object.assign(new MsgError('busy', `${identity} is held by sigelo-agent ${h.kind} (pid ${h.pid})`), { holder: h });
      rmSync(f, { force: true });   // left by a process that is gone
    }
  }
  throw new Error(`cannot take ${f}`);
}

// ---------------------------------------------------------------- the network

/**
 * The HTTP CONNECT proxy for url (https: or wss:), from HTTPS_PROXY or https_proxy, unless NO_PROXY
 * (or no_proxy) names its host: "*", a name (its subdomains too; a leading "." or "*." the same), an
 * address, each with an optional :port. → a URL, or null. Only an http:// proxy; TLS to the relay
 * runs inside the tunnel, verified as without one (NODE_EXTRA_CA_CERTS included).
 */
export function proxyFor(url, env = process.env) {
  const u = new URL(url);
  const raw = env.HTTPS_PROXY || env.https_proxy;
  if ((u.protocol !== 'https:' && u.protocol !== 'wss:') || !raw) return null;
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase(), port = u.port || '443';
  for (const e of String(env.NO_PROXY || env.no_proxy || '').toLowerCase().split(/[\s,]+/).filter(Boolean)) {
    if (e === '*') return null;
    const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(e) ?? (e.split(':').length === 2 ? /^([^:]+):(\d+)$/.exec(e) : null);
    const name = (m ? m[1] : e).replace(/^\*?\./, '.'), p = m?.[2];
    if (p && p !== port) continue;
    if (name.startsWith('.') ? host.endsWith(name) || host === name.slice(1) : host === name || host.endsWith(`.${name}`)) return null;
  }
  let p;
  try { p = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`); } catch { fail('connect', 'HTTPS_PROXY is not a URL: want http://host:port'); }
  if (p.protocol !== 'http:') fail('connect', `HTTPS_PROXY: ${p.protocol}// proxies are not supported; want http://host:port (HTTP CONNECT)`);
  return p;
}

// An https.Agent whose every connection is a tunnel through proxy (HTTP CONNECT host:port), with
// TLS to the relay inside it: for the HTTP calls (fetch) and for MQTT over WebSocket (ws's agent).
class Tunnel extends HttpsAgent {
  constructor(proxy) { super({ keepAlive: false }); this.proxy = proxy; }
  createConnection(options, cb) {
    const p = this.proxy, host = options.host.includes(':') ? `[${options.host}]` : options.host, target = `${host}:${options.port || 443}`;
    const auth = p.username ? { 'proxy-authorization': `Basic ${Buffer.from(`${decodeURIComponent(p.username)}:${decodeURIComponent(p.password)}`).toString('base64')}` } : {};
    const req = httpRequest({ host: p.hostname.replace(/^\[|\]$/g, ''), port: p.port || 80, method: 'CONNECT', path: target, agent: false, headers: { host: target, ...auth } });
    req.setTimeout(HTTP_MS, () => req.destroy(new Error(`no answer within ${HTTP_MS / 1000} s`)));
    req.once('connect', (res, sock) => {
      req.setTimeout(0);
      if (res.statusCode !== 200) { sock.destroy(); return cb(new Error(`the proxy ${p.host} answered ${res.statusCode} to CONNECT ${target}`)); }
      cb(null, tlsConnect({ ...options, socket: sock, servername: options.servername || options.host }));
    });
    req.once('error', (e) => cb(new Error(`the proxy ${p.host}: ${e.code ?? e.message}`)));
    req.end();
  }
}
const tunnelFor = (url) => { const p = proxyFor(url); return p ? new Tunnel(p) : null; };

// An HTTPS request through a tunnel, answered in the shape of fetch's Response as the carrier reads it.
function viaTunnel(url, init, agent) {
  return new Promise((resolve, reject) => {
    const body = init.body === undefined ? undefined : Buffer.from(init.body);
    const req = httpsRequest(url, { method: init.method ?? 'GET', agent, signal: init.signal, headers: body ? { 'content-type': 'text/plain;charset=UTF-8', 'content-length': body.length } : {} }, (res) => {
      resolve({ status: res.statusCode, type: 'basic', body: res, headers: { get: (k) => { const v = res.headers[k.toLowerCase()]; return v === undefined ? null : String(v); } } });
    });
    req.once('error', (e) => reject(Object.assign(new Error(e.message), { cause: e })));
    req.end(body);
  });
}

/** An HTTP request, redirects not followed: → { status, type, headers: { get }, body: chunks as they come }. */
async function nodeFetch(url, init = {}) {
  const agent = tunnelFor(url);
  return agent ? viaTunnel(url, init, agent) : fetch(url, { ...init, redirect: 'manual' });
}

/** An MQTT.js client for url (mqtts://, or wss:// through the HTTPS proxy when one applies). opts:
 *  MQTT.js's, the password a string; payloads published are Uint8Array. */
function mqtt(url, opts) {
  const agent = /^wss?:/.test(url) ? tunnelFor(url) : null;
  const client = connect(url, { ...opts, password: Buffer.from(opts.password, 'utf8'), wsOptions: { ...opts.wsOptions, ...(agent && { agent }) } });
  const publish = client.publish.bind(client);
  client.publish = (topic, message, o, cb) => publish(topic, typeof message === 'string' ? message : Buffer.from(message), o, cb);
  return client;
}

// ---------------------------------------------------------------- the CPU

const zeroBits = (d) => { let n = 0; for (const x of d) { if (x !== 0) return n + Math.clz32(x) - 24; n += 8; } return n; };

/** The first c (0, 1, 2, …) with SHA-256(prefix ‖ c) starting with `bits` zero bits, or null once
 *  Date.now() passes deadline (or signal aborts). Yields to the event loop every 4,096 hashes. */
export async function pow(prefix, bits, { deadline = Infinity, signal } = {}) {
  for (let i = 0; ; i++) {
    if (zeroBits(createHash('sha256').update(prefix + i, 'utf8').digest()) >= bits) return String(i);
    if ((i & 0xfff) === 0xfff) {
      if (Date.now() > deadline || signal?.aborted) return null;
      await new Promise((r) => setImmediate(r));
    }
  }
}

// ---------------------------------------------------------------- sendFile's path

/**
 * The file at path, read whole for sendFile: a regular file of at most MAX_FILE, and none of this
 * identity's own (own: { base: the identity file less .json, files: its folder of files received,
 * log: its inbox log }): x.* beside it, any profile's (*.local.*), files received, the log.
 * → { bytes, name }.
 */
export function openPath(file, own) {
  let real, bytes;
  try {
    real = realpathSync(file);
    const s = statSync(real);
    if (!s.isFile()) fail('file', `${file} is not a regular file`);
    if (s.size > MAX_FILE) fail('file_too_large', `${file} is ${s.size} bytes, at most ${MAX_FILE} (8 MiB) a file`);
  } catch (e) {
    if (e instanceof MsgError) throw e;
    fail('file', `cannot read ${file}: ${e.code === 'ENOENT' ? 'no such file' : e.code ?? e.message}`, { cause: e });
  }
  // Beside the identity: its own files (x.*) and any profile's (*.local.*, sigelo-agent's pattern).
  const base = resolve(own.base), received = (() => { try { return realpathSync(own.files); } catch { return own.files; } })();
  let ownDir;
  try { ownDir = realpathSync(dirname(base)); } catch { ownDir = dirname(base); }
  const leaf = basename(real);
  if (real.startsWith(received + sep) || real === own.log || (dirname(real) === ownDir && (leaf.startsWith(`${basename(base)}.`) || leaf.includes('.local.')))) {
    fail('file', `${file} is one of this agent's identity files (key, contacts, state, files received, inbox log): not sent`);
  }
  try { bytes = readFileSync(real); } catch (e) { fail('file', `cannot read ${file}: ${e.code ?? e.message}`, { cause: e }); }
  return { bytes, name: basename(real) };
}

// ---------------------------------------------------------------- the platform

/** The Node platform (design/apps.md §4.2), the carrier's default. */
export const platform = Object.freeze({
  files, path, flush: async () => {}, transact, owner, fetch: nodeFetch, mqtt, transports: Object.freeze(['mqtts', 'wss']), pow, openPath,
  get env() {
    return { ...optionsFromEnv(process.env), proxy: process.env.HTTPS_PROXY || process.env.https_proxy || null };
  },
});
