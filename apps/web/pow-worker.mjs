// SPDX-License-Identifier: MIT
// The relay login's proof of work in a Worker (platform-web.mjs workerPow; carrier.mjs solvePow):
// the first c (0, 1, 2, …) with Argon2id(password = prefix ‖ c, salt, m KiB, t passes, p lanes, 32
// bytes) starting with `bits` zero bits, as platform-node.mjs pow finds it (relay/pow.mjs,
// sigelo-relay-pow/1). With hash-wasm's WebAssembly Argon2id (its UMD build sets
// globalThis.hashwasm): ~0.5 s an evaluation at 64 MiB on a phone. Where WebAssembly may not run
// here (a content security policy without 'wasm-unsafe-eval' reaching the worker), @noble's
// JavaScript Argon2id, the same output ~11 times slower. Asked { prefix, salt, m, t, p, bits };
// answers { tried } after each evaluation and { found: String(c) } once. The page ends it
// (terminate) at its deadline or on abort. A module worker gets no import map: imports are by path.
import './vendor/hash-wasm/argon2.umd.min.js';
import { argon2id as jsArgon2id } from './vendor/@noble/hashes/argon2.js';

const zeroBits = (d) => { let n = 0; for (const x of d) { if (x !== 0) return n + Math.clz32(x) - 24; n += 8; } return n; };
let wasm = typeof globalThis.hashwasm?.argon2id === 'function';

/** One evaluation → the 32-byte output: WebAssembly while it runs, then JavaScript for good. */
async function evaluate(password, { salt, m, t, p }) {
  if (wasm) {
    try { return await globalThis.hashwasm.argon2id({ password, salt, parallelism: p, iterations: t, memorySize: m, hashLength: 32, outputType: 'binary' }); } catch { wasm = false; }
  }
  return jsArgon2id(password, salt, { t, m, p, dkLen: 32 });
}

/** The search, from 0, posting progress through post; → the counter as a string. */
export async function search(job, bits, post = () => {}) {
  const { prefix, salt, m, t, p } = job ?? {};
  if (typeof prefix !== 'string' || !(salt instanceof Uint8Array) || ![m, t, p].every(Number.isInteger) || !Number.isInteger(bits) || bits < 0 || bits > 64) {
    throw new TypeError('{ prefix: a string, salt: bytes, m, t, p: whole numbers, bits: 0 to 64 }');
  }
  for (let i = 0; ; i++) {
    if (zeroBits(await evaluate(prefix + i, job)) >= bits) return String(i);
    post({ tried: i + 1 });
  }
}

/** One request: { prefix, salt, m, t, p, bits } → post({ found }) or post({ error }). */
export async function handle(data, post) {
  try { post({ found: await search(data, data?.bits, post) }); } catch (e) { post({ error: e.message }); }
}

// In a Worker (not in a page, not in Node): answer the page.
if (typeof WorkerGlobalScope !== 'undefined' && globalThis instanceof WorkerGlobalScope) {
  globalThis.onmessage = (e) => { void handle(e.data, (m) => globalThis.postMessage(m)); };
}
