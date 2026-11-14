// SPDX-License-Identifier: MIT
// The relay login's proof of work in a Worker (platform-web.mjs workerPow; carrier.mjs solvePow):
// the first c (0, 1, 2, …) with Argon2id(password = prefix ‖ c, salt, m KiB, t passes, p lanes, 32
// bytes) starting with `bits` zero bits, as platform-node.mjs pow finds it (relay/pow.mjs,
// sigelo-relay-pow/1). Never in the page's thread: 64 MiB an evaluation starves a phone's WebView.
//
// The engines, loaded by import() so that one failing leaves the other (load()): hash-wasm's
// WebAssembly Argon2id (~0.5 s an evaluation at 64 MiB on a phone; its UMD build, run as a module,
// sets globalThis.hashwasm, or is a CommonJS export in Node), checked once against @noble's on a
// small cost (a policy that refuses WebAssembly fails there); else @noble's JavaScript Argon2id,
// the same output ~11 times slower, still off the page's thread.
//
// The protocol: first { ready: true, engine: 'wasm' | 'js' } (or { ready: false, error }: no
// engine here), then, asked { prefix, salt, m, t, p, bits }, { tried } after each evaluation and
// { found: String(c) } once, or { error }; { engine: 'js' } if WebAssembly fails mid-search. The
// page ends it (terminate) at its deadline or on abort. A module worker gets no import map: imports
// are by path.

const zeroBits = (d) => { let n = 0; for (const x of d) { if (x !== 0) return n + Math.clz32(x) - 24; n += 8; } return n; };
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const PROBE = { salt: new Uint8Array(16).fill(1), m: 8, t: 1, p: 1 };

let loading = null;
/** The best engine here → { engine: 'wasm' | 'js', evaluate(password, { salt, m, t, p }) → 32 bytes, js? }; throws when none runs. */
export function load() {
  loading ??= (async () => {
    const why = [];
    let js = null;
    try {
      const { argon2id } = await import('./vendor/@noble/hashes/argon2.js');
      js = (password, { salt, m, t, p }) => argon2id(password, salt, { t, m, p, dkLen: 32 });
    } catch (e) { why.push(`JavaScript: ${e.message}`); }
    try {
      const mod = await import('./vendor/hash-wasm/argon2.umd.min.js');
      const hw = [globalThis.hashwasm, mod?.default, mod].find((x) => typeof x?.argon2id === 'function');
      if (!hw) throw new Error('hash-wasm did not load');
      const wasm = (password, { salt, m, t, p }) => hw.argon2id({ password, salt, parallelism: p, iterations: t, memorySize: m, hashLength: 32, outputType: 'binary' });
      const a = await wasm('sigelo-pow-probe', PROBE);
      if (js && !same(a, js('sigelo-pow-probe', PROBE))) throw new Error('hash-wasm and @noble disagree');
      return { engine: 'wasm', evaluate: wasm, js };
    } catch (e) { why.push(`WebAssembly: ${e.message}`); }
    if (js) return { engine: 'js', evaluate: js };
    throw new Error(`no Argon2id here (${why.join('; ')})`);
  })();
  return loading;
}

/** The search, from 0, posting progress through post; → the counter as a string. engine: load()'s. */
export async function search(job, bits, post = () => {}, engine = undefined) {
  const { prefix, salt, m, t, p } = job ?? {};
  if (typeof prefix !== 'string' || !(salt instanceof Uint8Array) || ![m, t, p].every(Number.isInteger) || !Number.isInteger(bits) || bits < 0 || bits > 64) {
    throw new TypeError('{ prefix: a string, salt: bytes, m, t, p: whole numbers, bits: 0 to 64 }');
  }
  let e = engine ?? await load();
  for (let i = 0; ; i++) {
    let d;
    try { d = await e.evaluate(prefix + i, job); } catch (err) {
      // WebAssembly failing at this cost (its memory not granted, say): JavaScript for the rest of this search.
      if (e.engine !== 'wasm' || !e.js) throw err;
      e = { engine: 'js', evaluate: e.js };
      post({ engine: 'js' });
      d = await e.evaluate(prefix + i, job);
    }
    if (zeroBits(d) >= bits) return String(i);
    post({ tried: i + 1 });
  }
}

/** The worker's side: post({ ready, engine } | { ready: false, error }) once loaded; → answer(request), each request → post({ found }) or post({ error }). */
export function serve(post) {
  const loaded = load().then((e) => { post({ ready: true, engine: e.engine }); return e; }, (err) => { post({ ready: false, error: err.message }); return null; });
  return async (data) => {
    const e = await loaded;
    if (!e) return;
    try { post({ found: await search(data, data?.bits, post, e) }); } catch (err) { post({ error: err.message }); }
  };
}

// In a Worker (not in a page, not in Node): answer the page.
if (typeof WorkerGlobalScope !== 'undefined' && globalThis instanceof WorkerGlobalScope) {
  const answer = serve((m) => globalThis.postMessage(m));
  globalThis.onmessage = (e) => { void answer(e.data); };
}
