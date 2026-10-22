// SPDX-License-Identifier: MIT
// The relay login's proof of work in a Worker (platform-web.mjs workerPow; carrier.mjs solvePow):
// the first c (0, 1, 2, …) with SHA-256(prefix ‖ c) starting with `bits` zero bits, as
// platform-node.mjs pow finds it, with @noble's SHA-256. Asked { prefix, bits }; answers
// { tried } every 65,536 hashes and { found: String(c) } once. The page ends it (terminate) at
// its deadline or on abort. A module worker gets no import map: the import is by path.
import { sha256 } from './vendor/@noble/hashes/sha2.js';

const zeroBits = (d) => { let n = 0; for (const x of d) { if (x !== 0) return n + Math.clz32(x) - 24; n += 8; } return n; };
const enc = new TextEncoder();

/** The search, from 0, posting progress through post; → the counter as a string. */
export function search(prefix, bits, post = () => {}) {
  if (typeof prefix !== 'string' || !Number.isInteger(bits) || bits < 0 || bits > 64) throw new TypeError('{ prefix: a string, bits: 0 to 64 }');
  for (let i = 0; ; i++) {
    if (zeroBits(sha256(enc.encode(prefix + i))) >= bits) return String(i);
    if ((i & 0xffff) === 0xffff) post({ tried: i + 1 });
  }
}

/** One request: { prefix, bits } → post({ found }) or post({ error }). */
export function handle(data, post) {
  try { post({ found: search(data?.prefix, data?.bits, post) }); } catch (e) { post({ error: e.message }); }
}

// In a Worker (not in a page, not in Node): answer the page.
if (typeof WorkerGlobalScope !== 'undefined' && globalThis instanceof WorkerGlobalScope) {
  globalThis.onmessage = (e) => handle(e.data, (m) => globalThis.postMessage(m));
}
