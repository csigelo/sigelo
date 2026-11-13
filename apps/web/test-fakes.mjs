// SPDX-License-Identifier: MIT
// What test-web.mjs and test-shell.mjs share: an in-memory IndexedDB and a Worker as a Node thread.
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker as NodeWorker } from 'node:worker_threads';

const HERE = dirname(fileURLToPath(import.meta.url));
// What platform-web.mjs asks of IndexedDB and nothing more: open (upgradeneeded once), object
// stores, readonly and readwrite transactions committed whole at oncomplete (or aborted: failNext),
// get, put, delete, a cursor. Values are copied in (bytes) or kept (a CryptoKey).
export class FakeIDB {
  constructor() { this.dbs = new Map(); this.failNext = 0; this.commits = 0; this.deleted = []; }
  deleteDatabase(name) { const r = {}; setTimeout(() => { this.dbs.delete(name); this.deleted.push(name); r.onsuccess?.(); }); return r; }
  open(name) {
    const r = {};
    setTimeout(() => {
      let db = this.dbs.get(name);
      const fresh = !db;
      if (fresh) { db = { stores: new Map(), idb: this }; this.dbs.set(name, db); }
      const api = {
        objectStoreNames: { contains: (n) => db.stores.has(n) },
        createObjectStore: (n) => { db.stores.set(n, new Map()); },
        transaction: (_n, mode) => new FakeTx(db, mode),
        close() {},
      };
      r.result = api;
      if (fresh) r.onupgradeneeded?.();
      r.onsuccess?.();
    });
    return r;
  }
}
class FakeTx {
  constructor(db, mode) {
    Object.assign(this, { db, mode, ops: [], pending: 0, ended: false });
    this.fail = mode === 'readwrite' && db.idb.failNext > 0 ? (db.idb.failNext--, true) : false;
    this.check();
  }
  check() { setTimeout(() => { if (this.pending === 0 && !this.ended) this.finish(); }); }
  finish() {
    this.ended = true;
    if (this.fail) { this.error = Object.assign(new Error('QuotaExceededError: the disk is full'), { name: 'QuotaExceededError' }); this.onabort?.(); return; }
    for (const [op, s, k, v] of this.ops) { if (op === 'put') this.db.stores.get(s).set(k, v); else this.db.stores.get(s).delete(k); }
    if (this.ops.length) this.db.idb.commits++;
    this.oncomplete?.();
  }
  objectStore(n) {
    const st = this.db.stores.get(n), tx = this;
    const later = (fill) => { const r = {}; tx.pending++; setTimeout(() => { fill(r); r.onsuccess?.(); tx.pending--; tx.check(); }); return r; };
    return {
      put: (v, k) => { tx.ops.push(['put', n, k, v instanceof Uint8Array ? v.slice() : v]); return {}; },
      delete: (k) => { tx.ops.push(['del', n, k]); return {}; },
      get: (k) => later((r) => { r.result = st.get(k); }),
      openCursor() {
        const entries = [...st.entries()], r = {};
        let i = 0;
        const step = () => { tx.pending++; setTimeout(() => { r.result = i < entries.length ? { key: entries[i][0], value: entries[i][1], continue: () => { i++; step(); } } : null; r.onsuccess?.(); tx.pending--; tx.check(); }); };
        step();
        return r;
      },
    };
  }
}
// A Worker running pow-worker.mjs: a Node thread speaking the page's Worker interface (postMessage,
// onmessage, terminate), so the search runs beside this thread as in a page.
const POW_URL = pathToFileURL(join(HERE, 'pow-worker.mjs')).href;
export class FakeWorker {
  constructor() {
    this.w = new NodeWorker(`const { parentPort } = require('node:worker_threads'); import(${JSON.stringify(POW_URL)}).then(({ handle }) => parentPort.on('message', (d) => handle(d, (m) => parentPort.postMessage(m))));`, { eval: true });
    this.w.on('message', (data) => this.onmessage?.({ data }));
    this.w.on('error', (e) => this.onerror?.(e));
  }
  postMessage(data) { this.w.postMessage(data); }
  terminate() { void this.w.terminate(); }
}

/** The Android shell's big-file bridge (platform.big, SigeloBridge "big-*"), in memory: docs to pick or shoot, parts, Downloads. */
export class FakeBig {
  constructor({ sha256 }) { this.sha = sha256; this.docs = new Map(); this.parts = new Map(); this.landed = []; this.opened = []; this.awakes = []; this.n = 0; this.next = null; }
  add(name, bytes, mtime = 1000) { const doc = `d${++this.n}`; this.docs.set(doc, { name, bytes, mtime }); return { doc, name, size: bytes.length, mtime, url: `https://app.invalid/.big/${doc}` }; }
  async pick() { return this.next ? this.add(...this.next) : null; }
  async photo(o) { this.photoAsked = o; return this.next ? this.add(...this.next) : null; }
  async hash(doc) {
    const d = this.docs.get(doc), n = Math.ceil(d.bytes.length / 1048576), hashes = new Uint8Array(n * 32);
    for (let i = 0; i < n; i++) hashes.set(this.sha(d.bytes.subarray(i * 1048576, (i + 1) * 1048576)), i * 32);
    return { name: d.name, size: d.bytes.length, mtime: d.mtime, sha256: Buffer.from(this.sha(d.bytes)).toString('hex'), hashes };
  }
  async stat(doc) { const d = this.docs.get(doc); return { size: d.bytes.length, mtime: d.mtime }; }
  async read(doc, offset, length) { return this.docs.get(doc).bytes.slice(offset, offset + length); }
  async write(part, offset, b) { const p = this.parts.get(part) ?? new Uint8Array(0), q = new Uint8Array(Math.max(p.length, offset + b.length)); q.set(p); q.set(b, offset); this.parts.set(part, q); }
  async flush() {}
  async sha256(part) { return Buffer.from(this.sha(this.parts.get(part) ?? new Uint8Array(0))).toString('hex'); }
  async drop(part) { this.parts.delete(part); }
  async free() { return 1e12; }
  async land(part, name) { this.landed.push({ name, bytes: this.parts.get(part) }); this.parts.delete(part); return { uri: `content://media/external/downloads/${this.landed.length}`, name }; }
  async open(uri, name) { this.opened.push({ uri, name }); }
  async awake(on) { this.awakes.push(on); }
}
