// SPDX-License-Identifier: MIT
// The browser platform of sigelo-contact (design/apps.md §4.2): what platform-node.mjs is to Node,
// for a carrier that runs in a page (the self-contained app, apps/web/).
//
//   const p = await webPlatform({ name, indexedDB, locks, mqtt, fetch, pow, env, createWebsocket })
//   new Carrier({ ..., platform: p })
//
// files:    an in-memory Map, loaded whole from IndexedDB at start and written behind: every write
//           is queued and committed in one readwrite transaction (durability "strict") soon after;
//           flush() resolves once everything written before it is committed, and rejects (for good)
//           if a commit failed. The carrier awaits flush() before every PUBLISH and every PUBACK, so
//           nothing leaves and nothing is acknowledged before the state that sent or saved it is on
//           disk (a lost ratchet step would be a replay at the reader).
// transact: in-process: the carrier's functions are synchronous and one page owns the identity.
// owner:    navigator.locks.request(<id>, { ifAvailable: true }), held for the app's life: a second
//           tab or window of the same origin is refused (busy).
// fetch:    the page's fetch, no redirect followed, no credentials, no referrer; the body as chunks.
// mqtt:     mqtt.esm (MQTT.js's browser build, given as `mqtt`) over the runtime's WebSocket, wss://
//           only (ws:// to a loopback address, for tests); transports ['wss']. createWebsocket: a
//           shell's own socket (design/apps.md §4.3), passed to MQTT.js as is.
// pow:      the proof-of-work search in a Worker (pow-worker.mjs, @noble SHA-256), progress events.
// The Android app's platform (platform-android.mjs) is this one with the shell's fetch, mqtt and sealer.
// env:      what the page says: { relay, endpoints, retentionDays, transport, proxy: null }.
// No openPath: a page sends files as { bytes, name }.
import { MsgError, fail } from './vendor/contact/kdf.mjs';

const STORE = 'files', KEYS = 'keys';

// No network while a restore from seed runs (seed.mjs): from the first word to the last sealed write,
// the page's fetch and MQTT (and the Android shell's https and tls, platform-android.mjs) refuse.
export const network = { held: 0 };
/** Hold the network until the returned release() (counted: holds nest). */
export function holdNetwork() { network.held++; let done = false; return () => { if (!done) { done = true; network.held--; } }; }
export const checkNetwork = () => { if (network.held > 0) fail('restoring', 'no network until the restored keys are sealed'); };
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const eexist = (n) => Object.assign(new Error(`EEXIST: ${n} exists`), { code: 'EEXIST' });
const req = (r) => new Promise((ok, no) => { r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error); });

/** The database: one store of files (name → bytes), one of keys (CryptoKey objects, never exported). */
export function openDb(indexedDB, name) {
  const r = indexedDB.open(name, 1);
  r.onupgradeneeded = () => { const db = r.result; for (const s of [STORE, KEYS]) if (!db.objectStoreNames.contains(s)) db.createObjectStore(s); };
  return req(r);
}

/** Names as paths with "/": join, dirname, resolve (a name is already whole). */
export const path = {
  join: (...p) => p.filter((x) => x !== '').join('/').replace(/\/+/g, '/'),
  dirname: (p) => { const i = p.lastIndexOf('/'); return i <= 0 ? (i === 0 ? '/' : '.') : p.slice(0, i); },
  resolve: (p) => p,
};

/** The files of a database: a Map in memory, IndexedDB behind it (the write-behind rule above). */
export async function memoryFiles(db) {
  const m = new Map();
  await new Promise((ok, no) => {
    const tx = db.transaction(STORE, 'readonly'), st = tx.objectStore(STORE), c = st.openCursor();
    c.onsuccess = () => { const cur = c.result; if (cur) { m.set(String(cur.key), new Uint8Array(cur.value)); cur.continue(); } };
    tx.oncomplete = () => ok(); tx.onerror = tx.onabort = () => no(tx.error ?? new Error('IndexedDB: the files could not be read'));
  });
  let pending = new Map(), last = Promise.resolve(), timer = null, commits = 0;
  const commit = () => {
    if (timer !== null) { clearTimeout(timer); timer = null; }
    if (pending.size === 0) return last;
    const ops = pending;
    pending = new Map();
    last = last.then(() => new Promise((ok, no) => {
      const tx = db.transaction(STORE, 'readwrite', { durability: 'strict' }), st = tx.objectStore(STORE);
      for (const [k, v] of ops) { if (v === null) st.delete(k); else st.put(v, k); }
      tx.oncomplete = () => { commits++; ok(); };
      tx.onerror = tx.onabort = () => no(tx.error ?? new Error('IndexedDB: a write was not committed'));
    }));
    return last;
  };
  const later = (n, v) => { pending.set(n, v); if (timer === null) timer = setTimeout(() => { timer = null; void commit().catch(() => {}); }, 0); };
  const files = {
    read: (n) => (m.has(n) ? m.get(n).slice() : null),
    write(n, b, { how = 'replace' } = {}) {
      if (how === 'new' && m.has(n)) throw eexist(n);
      const v = Uint8Array.from(b);
      m.set(n, v); later(n, v);
    },
    remove(n) { for (const k of [...m.keys()]) if (k === n || k.startsWith(`${n}/`)) { m.delete(k); later(k, null); } },
    list(dir) {
      const pre = `${dir.replace(/\/+$/, '')}/`;
      return [...new Set([...m.keys()].filter((k) => k.startsWith(pre)).map((k) => k.slice(pre.length).split('/')[0]))];
    },
    folder() {},
    add(names, b) { const n = names.find((x) => !m.has(x)) ?? null; if (n !== null) files.write(n, b); return n; },
  };
  return { files, flush: commit, get commits() { return commits; }, get pending() { return pending.size; } };
}

// The page's fetch, in the shape the carrier reads (platform-node.mjs nodeFetch): status, type,
// headers.get, and the body as an async iterable of Uint8Array chunks (WebKit has no async
// iteration of a ReadableStream), cancelled when the reader leaves early.
export function pageFetch(fetchFn) {
  return async (url, { method = 'GET', body, signal } = {}) => {
    checkNetwork();
    const res = await fetchFn(url, { method, body, signal, redirect: 'manual', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
      ...(body !== undefined && { headers: { 'content-type': 'text/plain;charset=UTF-8' } }) });
    const stream = res.body;
    const chunks = stream && {
      async *[Symbol.asyncIterator]() {
        const r = stream.getReader();
        let done = false;
        try { for (;;) { const x = await r.read(); if (x.done) { done = true; return; } yield x.value; } }
        finally { if (!done) try { await r.cancel(); } catch {} }
      },
      cancel: () => stream.cancel(),
    };
    return { status: res.status, type: res.type, headers: res.headers, body: chunks };
  };
}

/** MQTT over the runtime's WebSocket (MQTT.js's browser build): wss://, or ws:// to a loopback address. */
export function pageMqtt(mqttLib, { createWebsocket } = {}) {
  const connect = mqttLib?.connect ?? mqttLib?.default?.connect;
  if (typeof connect !== 'function') throw new TypeError('mqtt: MQTT.js\'s browser build (mqtt.esm.js)');
  return (url, opts) => {
    checkNetwork();
    const u = new URL(url);
    if (u.protocol !== 'wss:' && !(u.protocol === 'ws:' && LOOPBACK.has(u.hostname))) fail('connect', `${u.protocol}// is not carried in a page: MQTT over WebSocket (wss://) only`);
    const { wsOptions: _w, ...rest } = opts;
    const client = connect(url, { ...rest, forceNativeWebSocket: true, ...(createWebsocket && { createWebsocket }) });
    // Payloads go out as the bytes given; MQTT.js's browser build takes them as its own Buffer.
    return client;
  };
}

// ---------------------------------------------------------------- proof of work in a Worker

/**
 * pow(prefix, bits, { deadline, signal, onProgress }) → the counter as a string, or null past the
 * deadline or on abort. worker(): a Worker running pow-worker.mjs (a module worker beside this
 * file by default). It answers { tried } every so often (onProgress) and { found } once.
 */
export function workerPow(worker = () => new Worker(new URL('./pow-worker.mjs', import.meta.url), { type: 'module' })) {
  return (prefix, bits, { deadline = Infinity, signal, onProgress } = {}) => new Promise((resolve, reject) => {
    const w = worker();
    let timer = null;
    const end = (f, v) => { if (timer !== null) clearTimeout(timer); signal?.removeEventListener?.('abort', aborted); try { w.terminate(); } catch {} f(v); };
    const aborted = () => end(resolve, null);
    if (signal?.aborted) return aborted();
    signal?.addEventListener?.('abort', aborted, { once: true });
    if (deadline !== Infinity) timer = setTimeout(() => end(resolve, null), Math.max(0, deadline - Date.now()));
    w.onmessage = (e) => {
      const d = e.data ?? {};
      if (typeof d.found === 'string') end(resolve, d.found);
      else if (typeof d.tried === 'number') onProgress?.(d.tried);
      else if (typeof d.error === 'string') end(reject, new Error(`proof of work: ${d.error}`));
    };
    w.onerror = (e) => end(reject, new Error(`proof of work: ${e.message ?? 'the worker failed'}`));
    w.postMessage({ prefix, bits });
  });
}

// ---------------------------------------------------------------- one owner per identity

/** owner(id) → { release }: navigator.locks, held until released (the app's life); busy when held. */
export function lockOwner(locks) {
  return (id) => new Promise((ok, no) => {
    if (!locks || typeof locks.request !== 'function') return no(new MsgError('busy', 'this browser has no Web Locks: one page per identity cannot be checked'));
    locks.request(`sigelo-owner ${id}`, { ifAvailable: true }, (lock) => {
      if (lock === null) { no(new MsgError('busy', `${id} is open in another window or tab of this app`)); return undefined; }
      return new Promise((release) => ok({ release: () => release() }));
    }).catch(no);
  });
}

// ---------------------------------------------------------------- the platform

/**
 * The browser platform. indexedDB, locks, fetch: the page's own unless given (tests pass shims);
 * mqtt: the MQTT.js browser build's module; pow: workerPow() unless given; env: from the page.
 */
export async function webPlatform({ name = 'sigelo', indexedDB = globalThis.indexedDB, locks = globalThis.navigator?.locks, mqtt, fetch = globalThis.fetch?.bind(globalThis),
  pow = workerPow(), env = {}, createWebsocket } = {}) {
  if (!indexedDB) throw new TypeError('webPlatform: no IndexedDB in this runtime');
  const db = await openDb(indexedDB, name), store = await memoryFiles(db);
  return Object.freeze({
    files: store.files, path, flush: store.flush,
    transact: (_name, fn) => fn(),
    owner: lockOwner(locks),
    fetch: pageFetch(fetch),
    mqtt: pageMqtt(mqtt, { createWebsocket }),
    transports: Object.freeze(['wss']),
    pow,
    env: Object.freeze({ relay: undefined, endpoints: {}, retentionDays: undefined, transport: 'wss', ...env, proxy: null }),
    db,
    get commits() { return store.commits; },
  });
}

// ---------------------------------------------------------------- the identity and the keeper, sealed

// The identity file (sigelo-agent's JSON: secret, genesis, rotations, attestations, issuers) and, after a
// restore from seed, the keeper file (K_j: sigelo-agent-enrol.ts's me.local.keeper.json) are kept
// sealed: AES-256-GCM under a WebCrypto key made here, non-extractable, kept in IndexedDB's key store
// (design/apps.md §5, PWA row), the kind in the AAD so one never opens as the other. That protects a
// copy of the files, not the seed from a script running in this origin, which can ask the key to
// decrypt (THREAT-MODEL §3.12).
const KEY_ID = 'identity', KINDS = Object.freeze({ identity: 'identity', keeper: 'keeper' });
const aadOf = (kind) => new TextEncoder().encode(`sigelo-app ${kind}/0`);
const kindOf = (kind) => KINDS[kind] ?? fail('kind', 'identity or keeper');
async function keyOf(db, subtle, make) {
  const tx = db.transaction(KEYS, 'readonly'), had = await req(tx.objectStore(KEYS).get(KEY_ID));
  if (had || !make) return had ?? null;
  const k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  await new Promise((ok, no) => { const t = db.transaction(KEYS, 'readwrite'); t.objectStore(KEYS).put(k, KEY_ID); t.oncomplete = () => ok(); t.onerror = t.onabort = () => no(t.error); });
  return k;
}
// A platform with a sealer (the Android app's: AndroidKeyStore, platform-android.mjs) seals with it
// instead, into <kind>.keystore; the WebCrypto key is then never made.
/** A file's bytes sealed into the platform's files as <kind>.sealed | <kind>.keystore (committed before this resolves). full: the shell's key asks for the user. */
export async function saveSealed(p, kind, bytes, subtle = globalThis.crypto.subtle, { full = false } = {}) {
  kindOf(kind);
  if (p.sealer) {
    p.files.write(`${kind}.keystore`, await p.sealer.seal(bytes, { full, kind }));
    await p.flush();
    return;
  }
  const key = await keyOf(p.db, subtle, true), iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aadOf(kind) }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  p.files.write(`${kind}.sealed`, out);
  await p.flush();
}
/** A sealed file's bytes, or null when this app holds none. */
export async function loadSealed(p, kind, subtle = globalThis.crypto.subtle) {
  kindOf(kind);
  if (p.sealer) {
    const k = p.files.read(`${kind}.keystore`);
    if (k === null) return null;
    try { return await p.sealer.open(k, { kind }); } catch (e) {
      // Not unlocked (the user cancelled, no screen lock): ask again at the next start; else it is gone.
      if (e.check === 'cancelled' || e.check === 'locked') throw e;
      return fail(kind, `the ${kind} does not open under this app's key (${e.message}): import it again`);
    }
  }
  const c = p.files.read(`${kind}.sealed`);
  if (c === null) return null;
  const key = await keyOf(p.db, subtle, false);
  if (key === null) fail(kind, `the ${kind} is here but its key is gone (the browser's storage was partly cleared): import it again`);
  try {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: c.subarray(0, 12), additionalData: aadOf(kind) }, key, c.subarray(12)));
  } catch { return fail(kind, `the ${kind} does not open under this app's key`); }
}
/** The identity file's bytes sealed (saveSealed, kind identity). */
export const saveIdentity = (p, bytes, subtle = globalThis.crypto.subtle, o = {}) => saveSealed(p, 'identity', bytes, subtle, o);
/** The identity file's bytes, or null when this app holds none. */
export const loadIdentity = (p, subtle = globalThis.crypto.subtle) => loadSealed(p, 'identity', subtle);
