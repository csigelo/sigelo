// SPDX-License-Identifier: MIT
// A client of `sigelo-agent ui --remote` (sigelo-remote/0, UI-API.md "Remote"), written apart from the
// server (sigelo-agent-remote.ts) so each checks the other. Used by the tests and by phone shells.
//   const r = await remoteClient(text);   // text: SIGELO:UI:<ip>:<port>:<base45 of id ‖ key>
//   const { status, body } = await r.call('GET', '/api/state');
// Calls go one at a time (a later ctr arriving first would refuse the earlier one). `ctr` starts at
// the clock in microseconds, so a client that lost its count still counts above the last one kept.
// deps: { xchacha20poly1305, canonicalize, fetch, randomBytes }; in Node they are found by default.
const LABEL = 'sigelo-remote/0';
const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

export function base45Decode(s) {
  const out = [];
  for (let i = 0; i < s.length; i += 3) {
    const k = Math.min(3, s.length - i), v = [...s.slice(i, i + k)].map((c) => B45.indexOf(c));
    if (k === 1 || v.includes(-1)) throw new Error('not base45');
    const n = v[0] + v[1] * 45 + (k === 3 ? v[2] * 2025 : 0);
    if (k === 3) { if (n > 0xffff) throw new Error('not base45'); out.push(n >> 8, n & 0xff); } else { if (n > 0xff) throw new Error('not base45'); out.push(n); }
  }
  return Uint8Array.from(out);
}

/** SIGELO:UI:<ip>:<port>:<base45> → {host, port, id (8 bytes), key (32 bytes)}. */
export function parseControl(text) {
  const m = /^SIGELO:UI:(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5}):(.+)$/.exec(String(text).replace(/[\r\n]+$/, ''));
  if (!m) throw new Error('not a SIGELO:UI: text');
  const b = base45Decode(m[3]);
  if (b.length !== 40) throw new Error('SIGELO:UI: wants an 8-byte id and a 32-byte key');
  return { host: m[1], port: Number(m[2]), id: b.slice(0, 8), key: b.slice(8) };
}

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const b64u = (b) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
function aad(dir, id, ctr) {
  const label = new TextEncoder().encode(`${LABEL} ${dir}`), a = new Uint8Array(label.length + 16);
  a.set(label); a.set(id, label.length);
  new DataView(a.buffer).setBigUint64(label.length + 8, BigInt(ctr));
  return a;
}

async function nodeDeps() {
  const { createRequire } = await import('node:module'), { pathToFileURL } = await import('node:url');
  const req = createRequire(import.meta.resolve('sigelo-contact/package.json'));
  const { xchacha20poly1305 } = await import(pathToFileURL(req.resolve('@noble/ciphers/chacha.js')).href);
  const { canonicalize } = await import('sigelo');
  return { xchacha20poly1305, canonicalize, fetch: globalThis.fetch, randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)) };
}

/** The request body for one call (also for tests that replay or tamper with it). */
export function sealRequest(deps, ctl, ctr, msg) {
  const nonce = deps.randomBytes(24), plain = new TextEncoder().encode(deps.canonicalize(msg));
  const box = deps.xchacha20poly1305(ctl.key, nonce, aad('req', ctl.id, ctr)).encrypt(plain);
  return JSON.stringify({ id: hex(ctl.id), ctr, nonce: b64u(nonce), box: b64u(box) });
}
export function openAnswer(deps, ctl, ctr, text) {
  const { nonce, box } = JSON.parse(text);
  return JSON.parse(new TextDecoder().decode(deps.xchacha20poly1305(ctl.key, unb64u(nonce), aad('res', ctl.id, ctr)).decrypt(unb64u(box))));
}

export async function remoteClient(text, o = {}) {
  const deps = { ...(o.deps ?? await nodeDeps()) }, ctl = parseControl(text), url = `http://${ctl.host}:${ctl.port}/r`;
  let last = o.ctr ?? 0, chain = Promise.resolve();
  const one = async (method, path, body) => {
    const ctr = Math.max(last + 1, Date.now() * 1000);
    last = ctr;
    const r = await deps.fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: sealRequest(deps, ctl, ctr, { method, path, ...(body !== undefined && { body }) }) });
    const t = await r.text();
    if (r.status !== 200) throw Object.assign(new Error(`remote: HTTP ${r.status}`), { status: r.status, body: t });
    return openAnswer(deps, ctl, ctr, t);   // {status, body}: the local listener's answer
  };
  return {
    ...ctl, deps, get ctr() { return last; },
    call(method, path, body) { const p = chain.then(() => one(method, path, body)); chain = p.catch(() => {}); return p; },
  };
}
