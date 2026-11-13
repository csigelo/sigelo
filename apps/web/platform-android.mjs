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
//   → {op:"seal", id, kind, full?, profile?, computer?, data} ← {id, data}   kind "identity" | "keeper" | "words" | "control" (AES-256-GCM, AndroidKeyStore;
//                                                                 keeper: K_j of a restore from seed, words: the kept words (words.mjs),
//                                                                 both under the FULL key); profile
//                                                                 (profiles.mjs, "p1" when absent): p1 under the three aliases of before,
//                                                                 blob version 1; another under its own aliases, version 2 naming it;
//                                                                 computer (computers.mjs, "c1" when absent): another computer's blob
//                                                                 is version 2 naming profile and computer, under the profile's aliases
//   → {op:"open", id, kind, profile?, computer?, data} ← {id, data} a blob of another profile or computer refused (sealed)
//   → {op:"forget-profile", id, profile}           ← {id}         that profile's keystore aliases deleted (its blobs never open again)
//   → {op:"mode", id, mode}                        ← {id, mode}   the active profile's form, once its first run commits ("self" | "remote")
//   → {op:"wiped", id}                             ← {id}         the page has cleared its storage after a switch
//   → {op:"secure", id, on, door?}                 ← {id}         FLAG_SECURE on the window (no screenshot, no recents
//                                                                 thumbnail) while a seed screen is up; door: the system
//                                                                 Back swallowed too (a new identity's words, create.mjs)
//   → {op:"clip-clear", id}                        ← {id}         the clipboard cleared (after the words were pasted)
//   → {op:"clip-copy", id, text, clear}            ← {id}         text on the clipboard marked sensitive (no preview), cleared
//                                                                 by the shell after `clear` seconds (stagenet words only)
//   → {op:"share", id, text}                       ← {id}         the system's share sheet with a ready-to-send message
//                                                                 (a pairing or enrol code and its instructions link)
//   → {op:"unlock", id, force?}                    ← {id}         the screen lock confirmed, before a screen that shows or
//                                                                 spends the identity (not asked again within a minute of
//                                                                 the last unless force: a payment above the pay limit; no
//                                                                 screen lock set: at once), else cancelled
//   → {op:"lock", id, on?, after?}                 ← {id, on, after, secure}  the app lock's settings, kept by the shell: on (default
//                                                                 true) the screen lock at a start and at a return after `after`
//                                                                 minutes away (1, 5, 15 or 60; default 1); secure: the phone has a
//                                                                 screen lock. A weaker setting (off, or longer) asks the screen lock
//                                                                 first (cancelled). Anything else refused (check "lock")
//   → {op:"notify", id, tag, title, text}          ← {id}         a system notification: title and text exactly as given (a name and a
//                                                                 generic line: never a message's text), one channel "messages", the lock
//                                                                 screen's version without them ("sigelo", "New message"); tag
//                                                                 chat:… | group:… | pay:… (TAG) names it and comes back in "open";
//                                                                 refused "notify" (a bad tag, title or text) or "notify_permission"
//   → {op:"notify", id, tag, cancel:true}          ← {id}         that tag's notification removed
//   → {op:"notify", id, ask:true}                  ← {id, granted} POST_NOTIFICATIONS asked when not granted (Android 13+)
//   → {op:"big-pick", id, profile} | {op:"big-photo", id, profile, keepLocation}  ← {id, doc, name, size, mtime, url} | {id, cancelled:true}
//                                                 the system's picker (the read grant kept) or camera (the location tags removed unless kept;
//                                                 CAMERA asked at the first); doc: 32 hex, this profile's; refused no_camera_app, camera_permission
//   → {op:"big-hash"|"big-stat", id, profile, doc} ← {id, name, size, mtime, sha256, hashes (base64)} | {id, size, mtime}
//   GET ORIGIN/.big/<doc>?size=&mtime=&profile= with Range: bytes=a-b (≤ 1 MiB) ← 206 those bytes, 409 when size or mtime moved (fetch, no base64)
//   → {op:"big-write", id, profile, part, offset, data} | big-flush | big-digest | big-drop {part} | big-free ← {id} | {id, sha256} | {id, free}
//   → {op:"big-land", id, profile, part, name}    ← {id, uri, name}  the partial moved into Downloads (MediaStore; Android 9: the storage
//                                                 permission asked at the first); refused "land" with why (no permission, no room)
//   → {op:"big-open", id, uri, name}              ← {id}         a file that landed, in the system's viewer
//   → {op:"big-awake", id, on}                    ← {id}         FLAG_KEEP_SCREEN_ON while a transfer moves
//   any ← {id, error:{check, message}}
// Events, the shell's own (no id; never an answer): ← {ev:"open", tag} one of our notifications tapped (the app running: at
// once; started by the tap: kept by the shell until the page's port is open, then posted once). Kept here until a listener
// is set (bridge.onEvent).
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
export const OPS = Object.freeze(['https', 'tls', 'write', 'close', 'seal', 'open', 'mode', 'wiped', 'secure', 'clip-clear', 'clip-copy', 'share', 'unlock', 'forget-profile', 'lock', 'notify',
  'big-pick', 'big-photo', 'big-hash', 'big-stat', 'big-write', 'big-flush', 'big-digest', 'big-drop', 'big-free', 'big-land', 'big-open', 'big-awake']);
/** A notification's tag (SigeloBridge.TAG): what it is about, given back when it is tapped. */
export const TAG = /^(chat|group|pay):[A-Za-z0-9:._-]{1,200}$/;
/** The app lock's choices of minutes away (SigeloBridge.LOCK_AFTER). */
export const LOCK_AFTER = Object.freeze([1, 5, 15, 60]);
export const NOTE_MAX = 100;
const line = (v, what) => { if (typeof v !== 'string' || v.length === 0 || v.length > NOTE_MAX) throw new MsgError('notify', `${what}: 1 to ${NOTE_MAX} characters`); return v; };
const tagOf = (t) => { if (typeof t !== 'string' || !TAG.test(t)) throw new MsgError('notify', 'tag: chat:, group: or pay: and up to 200 letters, digits or : . _ -'); return t; };
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
  const waiting = new Map(), streams = new Map(), listeners = new Set(), early = [];
  port.onmessage = (e) => {
    let m;
    try { m = JSON.parse(e.data); } catch { return; }
    if (typeof m?.s === 'number') { streams.get(m.s)?.got(m); return; }
    // The shell's own events go to their listeners (kept until there is one), never to a request waiting.
    if (typeof m?.ev === 'string') { if (listeners.size) for (const f of listeners) { try { f(m); } catch {} } else if (early.length < 16) early.push(m); return; }
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
    async seal(bytes, { kind, full = false, profile = 'p1', computer }) { return unb64((await request('seal', { kind, full, profile, ...(computer && computer !== 'c1' && { computer }), data: b64(bytes) })).data); },
    async open(bytes, { kind, profile = 'p1', computer }) { return unb64((await request('open', { kind, profile, ...(computer && computer !== 'c1' && { computer }), data: b64(bytes) })).data); },
    /** A profile's keystore aliases deleted (profiles.mjs runWipes). */
    async forgetProfile(profile) { await request('forget-profile', { profile }); },
    /** FLAG_SECURE on (a seed screen is up) or off; door: the system Back does nothing while on. */
    async secure(on, { door = false } = {}) { await request('secure', { on: on === true, door: on === true && door === true }); },
    /** The system clipboard emptied. */
    async clipClear() { await request('clip-clear'); },
    /** Text on the clipboard, marked sensitive, emptied by the shell after `clear` seconds (1 to 300). */
    async clipCopy(text, { clear = 60 } = {}) { await request('clip-copy', { text: String(text), clear }); },
    async share(text) { await request('share', { text: String(text) }); },
    /** The screen lock (MainActivity.unlock): resolves once confirmed; refused `cancelled`. force: asked even if confirmed a moment ago. */
    async unlock({ force = false } = {}) { await request('unlock', force === true ? { force: true } : {}); },
    /** The app lock's settings → { on, after (minutes), secure (the phone has a screen lock) }. */
    async lockGet() { const r = await request('lock'); return { on: r.on === true, after: Number(r.after), secure: r.secure === true }; },
    /** Change them (on: boolean, after: 1, 5, 15 or 60) → as lockGet. Anything else refused (check "lock"), here and in the shell. */
    async lockSet({ on, after } = {}) {
      if (on !== undefined && typeof on !== 'boolean') throw new MsgError('lock', 'on: true or false');
      if (after !== undefined && !LOCK_AFTER.includes(after)) throw new MsgError('lock', `after: ${LOCK_AFTER.join(', ')} minutes`);
      const r = await request('lock', { ...(on !== undefined && { on }), ...(after !== undefined && { after }) });
      return { on: r.on === true, after: Number(r.after), secure: r.secure === true };
    },
    /**
     * A system notification ({ tag, title, text }: shown as given), its removal ({ tag, cancel: true }) or the permission
     * asked ({ ask: true } → { granted }). Checked here before the shell sees it: a bad tag, title or text refused "notify".
     */
    async notify({ tag, title, text, cancel = false, ask = false } = {}) {
      if (ask === true) return { granted: (await request('notify', { ask: true })).granted === true };
      if (cancel === true) { await request('notify', { tag: tagOf(tag), cancel: true }); return {}; }
      await request('notify', { tag: tagOf(tag), title: line(title, 'title'), text: line(text, 'text') });
      return {};
    },
    /** fn(event) for the shell's events ({ ev: "open", tag }); those that came before the first listener, at once. → stop(). */
    onEvent(fn) {
      listeners.add(fn);
      while (early.length) { const m = early.shift(); try { fn(m); } catch {} }
      return () => listeners.delete(fn);
    },
  });
}

/**
 * Big files through the shell (design/transfer.md §10, SigeloBridge "big-*", BigFiles.java): platform.big as
 * apps/contact/transfer-web.mjs takes it. The page never holds a file whole: a doc names one the system's
 * picker or camera gave, read by range from the app's origin (fetch, no base64); what is received is written
 * at offsets into a partial in the shell, then moved into Downloads. Every call names this profile.
 */
export function bigFiles(bridge, { profile = bridge.profile ?? 'p1', fetch: get = globalThis.fetch?.bind(globalThis), origin = globalThis.location?.origin ?? 'https://appassets.androidplatform.net' } = {}) {
  const req = (op, x = {}) => bridge.request(op, { profile, ...x });
  const HEX = /^[0-9a-f]{32}$/;
  const id = (v, what) => { if (typeof v !== 'string' || !HEX.test(v)) throw new MsgError('big', `${what}: 32 hex digits`); return v; };
  const desc = (x) => (x.cancelled ? null : { doc: id(x.doc, 'doc'), name: String(x.name), size: Number(x.size), mtime: Number(x.mtime), url: String(x.url) });
  return Object.freeze({
    profile,
    /** The system's document picker → { doc, name, size, mtime, url } | null (cancelled). */
    async pick() { return desc(await req('big-pick')); },
    /** The system's camera → as pick; keepLocation false: the location tags removed in the shell. */
    async photo({ keepLocation = false } = {}) { return desc(await req('big-photo', { keepLocation: keepLocation === true })); },
    async hash(doc) { const x = await req('big-hash', { doc: id(doc, 'doc') }); return { name: String(x.name), size: Number(x.size), mtime: Number(x.mtime), sha256: String(x.sha256), hashes: unb64(x.hashes) }; },
    async stat(doc) { const x = await req('big-stat', { doc: id(doc, 'doc') }); return { size: Number(x.size), mtime: Number(x.mtime) }; },
    /** length bytes at offset, read by the shell from the file itself; file_changed when its size or time moved. */
    async read(doc, offset, length, { size, mtime }) {
      if (length === 0) return new Uint8Array(0);
      const r = await get(`${origin}/.big/${id(doc, 'doc')}?size=${size}&mtime=${mtime}&profile=${profile}`, { headers: { Range: `bytes=${offset}-${offset + length - 1}` }, cache: 'no-store' });
      if (r.status === 409) throw new MsgError('file_changed', 'the file changed since it was offered: send it again');
      if (r.status !== 206 && r.status !== 200) throw new MsgError('file', `the app could not read the file (${r.status})`);
      const b = new Uint8Array(await r.arrayBuffer());
      if (b.length !== length) throw new MsgError('file_changed', 'the file is shorter than it was');
      return b;
    },
    async write(part, offset, bytes) { await req('big-write', { part: id(part, 'part'), offset, data: b64(bytes) }); },
    async flush(part) { await req('big-flush', { part: id(part, 'part') }); },
    async sha256(part) { return String((await req('big-digest', { part: id(part, 'part') })).sha256); },
    async drop(part) { await req('big-drop', { part: id(part, 'part') }); },
    async free() { return Number((await req('big-free')).free); },
    /** The partial moved into Downloads → { uri, name }; refused `land` with why (no permission, no room). */
    async land(part, name) { const x = await req('big-land', { part: id(part, 'part'), name: String(name) }); return { uri: String(x.uri), name: String(x.name) }; },
    async open(uri, name) { await req('big-open', { uri: String(uri), name: String(name ?? '') }); },
    async awake(on) { await req('big-awake', { on: on === true }); },
  });
}

/** The bridge as profile <id> uses it: every seal and open names that profile (its aliases, its blobs only). */
export const profileBridge = (bridge, profile) => Object.freeze({
  ...bridge, profile,
  seal: (bytes, o = {}) => bridge.seal(bytes, { ...o, profile }),
  open: (bytes, o = {}) => bridge.open(bytes, { ...o, profile }),
});

/** The bridge as computer <cid> of a profile uses it (computers.mjs): its blobs name that computer too (c1: as before). */
export const computerBridge = (bridge, computer) => (computer === 'c1' ? bridge : Object.freeze({
  ...bridge, computer,
  seal: (bytes, o = {}) => bridge.seal(bytes, { ...o, computer }),
  open: (bytes, o = {}) => bridge.open(bytes, { ...o, computer }),
}));

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
 * WebSocket (createWebsocket). Nothing else: no plain MQTT, no ws://. Timers native (platform-web.mjs pageMqtt says why).
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
    return connect(at, { ...rest, forceNativeWebSocket: true, timerVariant: 'native', createWebsocket });
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
    // Big files (design/transfer.md §10): the bytes in the shell, this profile's.
    big: bigFiles(bridge),
    get commits() { return p.commits; },
  });
}
