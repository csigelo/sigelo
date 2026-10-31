// SPDX-License-Identifier: MIT
// The Android app's forms (design/apps.md §8), for app.mjs: at first start the user picks one; a
// switch (the app's menu) asks, then wipes the other form's storage and keys.
//   self:    this phone holds an identity (SAFE or FULL): the carrier in the page, platform-android.mjs.
//   remote:  this phone drives a computer's `sigelo-agent ui --remote`, holding no account key:
//            over the LAN (SIGELO:UI:), every call sealed here (sigelo-remote/0, remote-client.mjs) and
//            carried by the shell's HTTP, the text sealed under an AndroidKeyStore key; or over the relay
//            (SIGELO:CTL:, design/apps.md §6.3): a control identity made here (a random key, sealed as an
//            identity is, never attested), paired with the operator by the code and four words checked
//            on the computer; calls are sigelo-device/1 requests (contact/control.mjs), the state comes
//            pushed (events), so the page's 2 s poll reads it here and sends nothing.
// Scanning (design/apps.md §9): the camera (getUserMedia; the app asks for CAMERA at the first scan),
// an image (the system picker), a pasted image, or the text. What is scanned stays in memory until used.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { canonicalize } from 'sigelo';
import { parseControl, remoteClient } from './vendor/remote-client.mjs';
import { Carrier, pathsFor } from './vendor/contact/carrier.mjs';
import { makeControl, newControlIdentity, readControlText } from './vendor/contact/control.mjs';
import { androidPlatform, b64, bridgeFetch, unb64 } from './platform-android.mjs';
import { loadIdentity, saveIdentity } from './platform-web.mjs';

// CONTROL: the LAN text, sealed. RELAY: { operator, relay } of the relay form (the control identity is the platform's).
const CONTROL = 'sigelo-control', RELAY = 'sigelo-control-relay', CONTROL_FILE = 'app/control.local.json';
const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids); return e; };
const stop = (check, message) => Object.assign(new Error(message), { status: 403, check });

/** After a switch the shell asks the page to clear what it kept (IndexedDB, localStorage), once. */
export async function wipeIfAsked(bridge, { indexedDB = globalThis.indexedDB, storage = globalThis.localStorage } = {}) {
  if (!bridge.info.wipe) return false;
  await new Promise((ok) => { const r = indexedDB.deleteDatabase('sigelo'); r.onsuccess = r.onerror = r.onblocked = () => ok(); });
  try { storage.clear(); } catch {}
  await bridge.request('wiped');
  return true;
}

const bundleOf = (s) => ({ v: 'sigelo/0', typ: 'bundle', genesis: s.genesis, rotations: [], bindings: [], attestations: [], issuers: [] });
const hexBytes = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
/** The control's carrier on the shell's platform: its own identity, the operator's relay. */
function controlCarrier(platform, idf, relay, options, onEvent) {
  return new Carrier({ identity: () => ({ secret: hexBytes(idf.secret), bundle: bundleOf(idf) }), ...pathsFor(CONTROL_FILE), ...(relay && { relay }), ...options, onEvent, platform });
}

/**
 * Over the relay, first time: a control identity made here and sealed, the SIGELO:CTL: code accepted
 * with it. → { words, operator }: the four words the computer must confirm. o: { mqtt, storage, indexedDB, pow, options }.
 */
export async function pairRelay(bridge, text, { mqtt, storage = globalThis.localStorage, indexedDB, pow, options = {} } = {}) {
  const t = readControlText(text);
  const platform = await androidPlatform({ bridge, mqtt, ...(indexedDB && { indexedDB }), ...(pow && { pow }) });
  const idf = newControlIdentity();
  await saveIdentity(platform, new TextEncoder().encode(JSON.stringify(idf)), undefined, { full: false });
  const car = controlCarrier(platform, idf, t.relay, options);
  try {
    const r = await car.accept(t.code, { name: 'computer', wait: 20, ...(t.relay && { relay: t.relay }) });
    if (!r.contact) throw Object.assign(new Error(`the computer did not answer (${r.status}): is sigelo-agent ui --remote --relay still running, its code under 10 minutes old?`), { check: 'remote' });
    const words = car.contacts().contacts.find((c) => c.did === r.contact.did)?.fingerprint ?? null;
    storage.setItem(RELAY, JSON.stringify({ operator: r.contact.did, relay: t.relay }));
    await platform.flush();
    return { words, operator: r.contact.did };
  } finally { await car.stop(); }
}

/** Over the relay: the backend, its carrier started on the control identity; GET /api/state from the pushed events. */
async function relayBackend(bridge, kept, { mqtt, indexedDB, pow, options = {}, timeout }) {
  const platform = await androidPlatform({ bridge, mqtt, ...(indexedDB && { indexedDB }), ...(pow && { pow }) });
  const raw = await loadIdentity(platform);
  if (raw === null) throw stop('connect', 'This app\'s control key is gone: forget the computer (menu) and pair again.');
  const idf = JSON.parse(new TextDecoder().decode(raw)), ctl = makeControl({ operator: kept.operator, ...(timeout && { timeout }) });
  const car = controlCarrier(platform, idf, kept.relay, options, (e) => ctl.onEvent(e));
  await car.start();
  ctl.attach(car);
  globalThis.addEventListener?.('pagehide', () => { ctl.stop(); void car.stop(); });
  return {
    call: (method, path, body) => ctl.call(method, path, body),
    onChange: (fn) => ctl.onChange(fn),
    mode: () => ({ kind: 'remote', via: 'relay' }),
    carrier: car, stop: async () => { ctl.stop(); await car.stop(); },
  };
}

/** The remote form: the backend ui.js calls ({ call, onChange, mode }), or the connect view and a refusal. */
export async function remoteBackend(bridge, box, { storage = globalThis.localStorage, mqtt, indexedDB, pow, options, timeout } = {}) {
  const viaRelay = storage.getItem(RELAY);
  if (viaRelay !== null) return relayBackend(bridge, JSON.parse(viaRelay), { mqtt, indexedDB, pow, options, timeout });
  const deps = { xchacha20poly1305, canonicalize, fetch: bridgeFetch(bridge), randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)) };
  const kept = storage.getItem(CONTROL);
  if (kept === null) { connectView(box, bridge, deps, storage, mqtt); throw stop('connect', 'Connect to a computer below.'); }
  let text;
  try { text = new TextDecoder().decode(await bridge.open(unb64(kept), { kind: 'control' })); } catch (e) {
    connectView(box, bridge, deps, storage, mqtt);
    throw stop('connect', `The computer's text kept here does not open (${e.message}): scan it again.`);
  }
  const client = await remoteClient(text, { deps });
  const where = `${client.host}:${client.port}`;
  return {
    async call(method, path, body) {
      try { return await client.call(method, path, body); } catch (e) {
        const message = e.status === 403 ? `The computer at ${where} refused this phone's text (revoked there, or another page): forget it (menu) and scan its text again.`
          : e.status ? `The computer at ${where} answered HTTP ${e.status}.`
            : `No answer from ${where}: is \`sigelo-agent ui --remote\` running there, on this network?`;
        return { status: e.status === 403 ? 403 : 502, body: { error: { check: 'remote', message } } };
      }
    },
    onChange() {},   // the page polls /api/state, as over HTTP
    mode: () => ({ kind: 'remote', via: 'lan' }),
  };
}

/** A computer's SIGELO:UI: text on the LAN: checked with one sealed call, then kept sealed for the next start. */
export async function connectLan(bridge, text, { storage = globalThis.localStorage } = {}) {
  // base45 has spaces: never trimmed at the end, cut at the 60 characters of 40 bytes.
  const t = /SIGELO:UI:\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}:[0-9A-Z $%*+\-./:]{60}/.exec(text)?.[0] ?? text;
  try { parseControl(t); } catch { throw new Error(t.startsWith('SIGELO:') ? 'This is not a computer\'s page (SIGELO:UI: or SIGELO:CTL:).' : 'Not a SIGELO:UI: or SIGELO:CTL: text.'); }
  const deps = { xchacha20poly1305, canonicalize, fetch: bridgeFetch(bridge), randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)) };
  let r;
  try { r = await (await remoteClient(t, { deps })).call('GET', '/api/me'); } catch (e) {
    throw new Error(e.status === 403 ? 'The computer refused this text (revoked, or another computer\'s).' : `No answer: is sigelo-agent ui --remote running there, on this network? (${e.message})`);
  }
  if (r.status !== 200) throw new Error(r.body?.error?.message ?? `HTTP ${r.status}`);
  storage.setItem(CONTROL, b64(await bridge.seal(new TextEncoder().encode(t), { kind: 'control' })));
}

/** The connect view: scan, an image, or the text (SIGELO:UI: on the LAN, SIGELO:CTL: over the relay); then the page starts again. */
function connectView(box, bridge, deps, storage, mqtt) {
  const status = el('p', { className: 'muted' }), text = el('textarea', { rows: 2, autocomplete: 'off', spellcheck: false });
  const video = el('video', { muted: true, playsInline: true, hidden: true });
  const pickFile = el('input', { type: 'file', accept: 'image/*', hidden: true });
  const camera = el('button', { textContent: 'Scan its QR' }), image = el('button', { textContent: 'From an image' }), go = el('button', { className: 'primary', textContent: 'Connect' });
  let jsQR = null, stream = null, timer = 0;
  const say = (t) => { status.textContent = t ?? ''; };
  const stopCamera = () => { clearInterval(timer); timer = 0; stream?.getTracks().forEach((t) => t.stop()); stream = null; video.hidden = true; camera.textContent = 'Scan its QR'; };
  async function connect(t) {
    stopCamera();
    if (/^\s*SIGELO:CTL:/i.test(t)) return overRelay(t.trim());
    // base45 has spaces: never trimmed at the end, cut at the 60 characters of 40 bytes.
    t = /SIGELO:UI:\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}:[0-9A-Z $%*+\-./:]{60}/.exec(t)?.[0] ?? t;
    try { parseControl(t); } catch { say(t.startsWith('SIGELO:') ? 'This QR is not a computer\'s page (SIGELO:UI: or SIGELO:CTL:).' : 'Not a SIGELO:UI: or SIGELO:CTL: text.'); return; }
    say('Connecting…');
    try {
      const c = await remoteClient(t, { deps }), r = await c.call('GET', '/api/me');
      if (r.status !== 200) { say(r.body?.error?.message ?? `HTTP ${r.status}`); return; }
      storage.setItem(CONTROL, b64(await bridge.seal(new TextEncoder().encode(t), { kind: 'control' })));
      location.reload();
    } catch (e) { say(e.status === 403 ? 'The computer refused this text (revoked, or another computer\'s).' : `No answer: is sigelo-agent ui --remote running there, on this network? (${e.message})`); }
  }
  async function overRelay(t) {
    say('Pairing through the relay…');
    try {
      const r = await pairRelay(bridge, t, { mqtt, storage });
      box.replaceChildren(el('div', { className: 'card' }, el('h2', { textContent: 'Check the four words' }),
        el('p', { className: 'words', textContent: r.words ?? '(none)' }),
        el('p', { textContent: 'The computer shows four words too. Answer y there only if they are the same; it answers this phone after that.' }),
        el('div', { className: 'bar' }, el('button', { className: 'primary', textContent: 'Done', onclick: () => location.reload() }))));
    } catch (e) { say(`Not paired: ${e.message}`); }
  }
  const canvas = document.createElement('canvas'), g = canvas.getContext('2d', { willReadFrequently: true });
  const decode = (src, w, h, max) => {
    const k = Math.min(1, max / Math.max(w, h));
    canvas.width = Math.round(w * k); canvas.height = Math.round(h * k);
    g.drawImage(src, 0, 0, canvas.width, canvas.height);
    const px = g.getImageData(0, 0, canvas.width, canvas.height);
    try { return jsQR(px.data, px.width, px.height)?.data ?? null; } catch { return null; }
  };
  async function fromImage(blob) {
    say('Reading the image…');
    let bm;
    try { bm = await createImageBitmap(blob); } catch { say('Not an image this app can read.'); return; }
    const t = decode(bm, bm.width, bm.height, 1600) ?? decode(bm, bm.width, bm.height, 800);
    bm.close();
    if (t) await connect(t); else say('No QR code found in that image.');
  }
  camera.onclick = async () => {
    if (stream) { stopCamera(); say(''); return; }
    try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false }); } catch (e) {
      say(`No camera (${e.name}): allow it in the app's settings, or use "From an image".`); return;
    }
    video.srcObject = stream; video.hidden = false; camera.textContent = 'Stop the camera';
    await video.play().catch(() => {});
    say('Point the camera at the QR the computer shows.');
    timer = setInterval(() => { if (video.readyState >= 2) { const t = decode(video, video.videoWidth, video.videoHeight, 640); if (t) connect(t); } }, 200);
  };
  image.onclick = () => pickFile.click();
  pickFile.onchange = () => { const f = pickFile.files?.[0]; pickFile.value = ''; if (f) fromImage(f); };
  text.addEventListener('paste', (ev) => {
    const img = [...(ev.clipboardData?.items ?? [])].find((i) => i.type.startsWith('image/'));
    if (img && jsQR) { ev.preventDefault(); fromImage(img.getAsFile()); }
  });
  go.onclick = () => { const t = text.value.replace(/^\s+/, ''); text.value = ''; connect(t); };
  import('/qr-decode.mjs').then((m) => { jsQR = m.jsQR; }, () => { camera.disabled = image.disabled = true; say('QR reading is not in this build: paste the text.'); });
  box.replaceChildren(el('div', { className: 'card' }, el('h2', { textContent: 'Connect to a computer' }),
    el('p', { className: 'muted', textContent: 'On the computer, on this network: sigelo-agent ui --remote --name phone (SIGELO:UI:); from anywhere, over the relay: sigelo-agent ui --remote --relay --name phone (SIGELO:CTL:, then compare four words). Scan the QR it prints, or paste its text.' }),
    el('div', { className: 'bar' }, camera, image), video, pickFile, el('label', { textContent: 'Or paste the text (or a screenshot of the QR)' }), text,
    el('div', { className: 'bar' }, go), status));
  box.hidden = false;
}
