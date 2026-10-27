// SPDX-License-Identifier: MIT
// The Android app's platform (design/apps.md §4.3, §8): platform-web.mjs (files in IndexedDB, the
// flush rule, the owner lock, the proof of work) with the network and the key of the shell
// (apps/android, SigeloBridge.java) instead of the page's. The relay refuses a page's requests (an
// Origin header, CORS); the shell's are native, so it is reached as from a Node agent.
//
//   const bridge = await connectBridge()              the shell: SigeloShell (a @JavascriptInterface) + a WebMessagePort
//   const p = await androidPlatform({ bridge, mqtt }) → the platform: fetch and mqtt through the shell,
//                                                       transports ['mqtts', 'wss'], sealer (AndroidKeyStore)
//
// The bridge (sigelo-bridge/0). SigeloShell.info() → {"v":"sigelo-shell/0","mode":"self"|"remote"|null,
// "wipe":bool,"version":…}; SigeloShell.connect() → the shell posts the message "sigelo-bridge/0" to
// this origin with one port. Over the port, JSON text both ways, bytes as base64:
//   → {op:"https", id, method, url, type?, body?}  ← {id, status, headers:{date, content-length, retry-after, content-type}, body}
//   → {op:"tls", id, host, port}                   ← {id, stream}; then ← {s, data} … ← {s, end:true, error?}
//   → {op:"write", id, s, data}                    ← {id} once written;   → {op:"close", s}
//   → {op:"seal", id, kind, full?, data}           ← {id, data}   kind "identity" | "keeper" | "control" (AES-256-GCM, AndroidKeyStore;
//                                                                 keeper: K_j of a restore from seed, under the FULL key)
//   → {op:"open", id, kind, data}                  ← {id, data}
//   → {op:"mode", id, mode}                        ← {id, mode}   the form at first start ("self" | "remote")
//   → {op:"wiped", id}                             ← {id}         the page has cleared its storage after a switch
//   → {op:"secure", id, on, door?}                 ← {id}         FLAG_SECURE on the window (no screenshot, no recents
//                                                                 thumbnail) while a seed screen is up; door: the system
//                                                                 Back swallowed too (a new identity's words, create.mjs)
//   → {op:"clip-clear", id}                        ← {id}         the clipboard cleared (after the words were pasted)
//   → {op:"clip-copy", id, text, clear}            ← {id}         text on the clipboard marked sensitive (no preview), cleared
//                                                                 by the shell after `clear` seconds (stagenet words only)
//   any ← {id, error:{check, message}}
// https: https:// to any host; http:// only to a private IPv4 address (a computer's `ui --remote`
// on the LAN, sealed in the page). tls: certificate and host name checked by the system's trust
// store. Nothing is sent but what the request names: no Origin, no cookie, no redirect followed.
// While a restore from seed holds the network (platform-web.mjs holdNetwork), https and tls refuse here
// before anything reaches the shell.
import { sha256 } from '@noble/hashes/sha2.js';
import { MsgError, fail } from './vendor/contact/kdf.mjs';
import { checkNetwork, webPlatform, workerPow } from './platform-web.mjs';
import { streamSocket, wsOverStream } from './ws-over-stream.mjs';

export const BRIDGE = 'sigelo-bridge/0';
export const OPS = Object.freeze(['https', 'tls', 'write', 'close', 'seal', 'open', 'mode', 'wiped', 'secure', 'clip-clear', 'clip-copy']);
export const b64 = (b) => { let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s); };
export const unb64 = (s) => { const t = atob(s), o = new Uint8Array(t.length); for (let i = 0; i < t.length; i++) o[i] = t.charCodeAt(i); return o; };

/**
 * The shell's bridge: → { info, request(op, fields), https(url, init), tls(host, port), seal, open }.
 * shell: SigeloShell (the @JavascriptInterface object); target: where the port's message arrives (window).
 */
export function connectBridge({ shell = globalThis.SigeloShell, target = globalThis, timeout = 10000 } = {}) {
  if (!shell || typeof shell.info !== 'function' || typeof shell.connect !== 'function') return Promise.reject(new TypeError('connectBridge: not in the Android app (no SigeloShell)'));
  const info = JSON.parse(shell.info());
  if (info?.v !== 'sigelo-shell/0') return Promise.reject(new TypeError(`connectBridge: shell ${info?.v}, not sigelo-shell/0`));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { target.removeEventListener('message', got); reject(new Error('the app\'s bridge did not answer')); }, timeout);
    const got = (e) => {
      if (e.data !== BRIDGE || e.ports?.length !== 1) return;
      clearTimeout(timer); target.removeEventListener('message', got);
      resolve(makeBridge(info, e.ports[0]));
    };
    target.addEventListener('message', got);
    shell.connect();
  });
}

function makeBridge(info, port) {
  let next = 1;
  const waiting = new Map(), streams = new Map();
  port.onmessage = (e) => {
    let m;
    try { m = JSON.parse(e.data); } catch { return; }
    if (typeof m?.s === 'number') { streams.get(m.s)?.got(m); return; }
    const w = waiting.get(m?.id);
    if (!w) return;
    waiting.delete(m.id);
    if (m.error) w.no(new MsgError(String(m.error.check ?? 'bridge'), String(m.error.message ?? 'the app refused')));
    else w.ok(m);
  };
  port.start?.();
  const request = (op, fields = {}) => new Promise((ok, no) => {
    const id = next++;
    waiting.set(id, { ok, no });
    port.postMessage(JSON.stringify({ op, id, ...fields }));
  });
  /** A duplex stream of the shell's (see ws-over-stream.mjs): data read before ondata is set waits. */
  function stream(s) {
    const early = [];
    let ondata = null, ended = null;
    const st = {
      write: (bytes) => request('write', { s, data: b64(bytes) }).then(() => {}),
      close: () => { if (streams.delete(s)) port.postMessage(JSON.stringify({ op: 'close', s })); },
      get ondata() { return ondata; },
      set ondata(f) { ondata = f; while (early.length && ondata) ondata(early.shift()); },
      onclose: null,
      got(m) {
        if (m.data !== undefined) { const b = unb64(m.data); if (ondata) ondata(b); else early.push(b); }
        if (m.end && ended === null) { ended = m.error ? new Error(m.error) : true; streams.delete(s); st.onclose?.(ended === true ? null : ended); }
      },
    };
    streams.set(s, st);
    return st;
  }
  return Object.freeze({
    info, request, port,
    async https(url, { method = 'GET', body, type } = {}) {
      checkNetwork();
      const b = body === undefined ? undefined : typeof body === 'string' ? new TextEncoder().encode(body) : body;
      const r = await request('https', { method, url, ...(b !== undefined && { body: b64(b), type: type ?? 'text/plain;charset=UTF-8' }) });
      return { status: r.status, headers: r.headers ?? {}, body: unb64(r.body ?? '') };
    },
    async tls(host, port) { checkNetwork(); const r = await request('tls', { host, port }); return stream(r.stream); },
    async seal(bytes, { kind, full = false }) { return unb64((await request('seal', { kind, full, data: b64(bytes) })).data); },
    async open(bytes, { kind }) { return unb64((await request('open', { kind, data: b64(bytes) })).data); },
    /** FLAG_SECURE on (a seed screen is up) or off; door: the system Back does nothing while on. */
    async secure(on, { door = false } = {}) { await request('secure', { on: on === true, door: on === true && door === true }); },
    /** The system clipboard emptied. */
    async clipClear() { await request('clip-clear'); },
    /** Text on the clipboard, marked sensitive, emptied by the shell after `clear` seconds (1 to 300). */
    async clipCopy(text, { clear = 60 } = {}) { await request('clip-copy', { text: String(text), clear }); },
  });
}

/** The carrier's fetch (platform-node.mjs nodeFetch's shape) and remote-client.mjs's, through the shell. */
export function bridgeFetch(bridge) {
  return async (url, { method = 'GET', body, signal, headers } = {}) => {
    if (signal?.aborted) throw signal.reason;
    const type = headers?.['Content-Type'] ?? headers?.['content-type'];
    const call = bridge.https(url, { method, body, type });
    const r = await (signal ? Promise.race([call, new Promise((_, no) => signal.addEventListener('abort', () => no(signal.reason ?? new Error('aborted')), { once: true }))]) : call);
    const h = new Map(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), String(v)]));
    return {
      status: r.status, type: 'basic',
      headers: { get: (k) => h.get(String(k).toLowerCase()) ?? null },
      body: { async *[Symbol.asyncIterator]() { if (r.body.length) yield r.body; }, cancel: async () => {} },
      text: async () => new TextDecoder().decode(r.body),
    };
  };
}

/**
 * MQTT through the shell: mqtts://host[:8883] is the TLS stream itself, wss://host[:443]/path the
 * WebSocket framing over it (ws-over-stream.mjs). MQTT.js's browser build takes either as its
 * WebSocket (createWebsocket). Nothing else: no plain MQTT, no ws://.
 */
export function bridgeMqtt(bridge, mqttLib) {
  const connect = mqttLib?.connect ?? mqttLib?.default?.connect;
  if (typeof connect !== 'function') throw new TypeError('mqtt: MQTT.js\'s browser build (mqtt.esm.js)');
  return (url, opts) => {
    const u = new URL(url), host = u.hostname.replace(/^\[|\]$/g, '');
    const { wsOptions, ...rest } = opts;
    let createWebsocket, at;
    if (u.protocol === 'mqtts:') {
      const port = Number(u.port || 8883);
      at = `wss://${u.host.includes(':') ? u.host : `${u.host}:${port}`}/`;
      createWebsocket = () => streamSocket(bridge.tls(host, port), { url });
    } else if (u.protocol === 'wss:') {
      at = url;
      createWebsocket = (_url, protocols) => wsOverStream(bridge.tls(host, Number(u.port || 443)), { url, protocols, maxPayload: wsOptions?.maxPayload });
    } else fail('connect', `${u.protocol}// is not carried by this app: mqtts:// or wss:// only`);
    return connect(at, { ...rest, forceNativeWebSocket: true, createWebsocket });
  };
}

/** The proof of work in the page, in slices of 4,096 hashes (a WebView that cannot start the Worker). */
export async function slicedPow(prefix, bits, { deadline = Infinity, signal, onProgress } = {}) {
  const e = new TextEncoder(), zero = (d) => { let n = 0; for (const x of d) { if (x !== 0) return n + Math.clz32(x) - 24; n += 8; } return n; };
  for (let i = 0; ; i++) {
    if (zero(sha256(e.encode(prefix + i))) >= bits) return String(i);
    if ((i & 0xfff) === 0xfff) {
      if (Date.now() > deadline || signal?.aborted) return null;
      if ((i & 0xffff) === 0xffff) onProgress?.(i + 1);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
}
/** The Worker's search, and the page's when the Worker does not start (once failed, for the app's life). */
export function androidPow(inWorker = workerPow()) {
  let broken = false;
  return async (prefix, bits, o = {}) => {
    if (!broken) {
      try { return await inWorker(prefix, bits, o); } catch (e) { if (!/^proof of work: /.test(e.message)) throw e; broken = true; }
    }
    return slicedPow(prefix, bits, o);
  };
}

/** The identity (and a restored keeper) sealed by the shell: AES-256-GCM under a key in AndroidKeyStore (FULL and keeper: unlocked by the user). */
export const keystoreSealer = (bridge) => Object.freeze({
  seal: (bytes, { full = false, kind = 'identity' } = {}) => bridge.seal(bytes, { kind, full }),
  open: (bytes, { kind = 'identity' } = {}) => bridge.open(bytes, { kind }),
});

/** The platform: webPlatform's files, flush, owner and proof of work; the shell's network and key. */
export async function androidPlatform({ bridge, mqtt, name = 'sigelo', indexedDB, locks, pow = androidPow(), env = {} } = {}) {
  if (!bridge) throw new TypeError('androidPlatform: a bridge (connectBridge)');
  const p = await webPlatform({ name, ...(indexedDB && { indexedDB }), ...(locks && { locks }), mqtt, pow, env, fetch: () => Promise.reject(new Error('fetch: through the shell')) });
  return Object.freeze({
    files: p.files, path: p.path, flush: p.flush, transact: p.transact, owner: p.owner, pow: p.pow, db: p.db,
    fetch: bridgeFetch(bridge),
    mqtt: bridgeMqtt(bridge, mqtt),
    transports: Object.freeze(['mqtts', 'wss']),
    env: Object.freeze({ ...p.env, transport: 'auto' }),
    sealer: keystoreSealer(bridge),
    get commits() { return p.commits; },
  });
}
