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
  constructor() { this.dbs = new Map(); this.failNext = 0; this.commits = 0; }
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
