// SPDX-License-Identifier: MIT
// The self-contained app's start (index.html): the browser platform (platform-web.mjs), the identity
// this app holds (sealed in its storage), the router (router.mjs) and, for ui.js, the `local`
// backend: globalThis.sigeloLocal = { call, onChange, mode }. Set before anything is awaited, so
// ui.js (a deferred script after this module) finds it. Without an identity: a form to import one
// (the file `sigelo-agent device scan` wrote on a computer, or the operator's for FULL), then a reload.
// In the Android app (SigeloShell, apps/android): the shell's platform (platform-android.mjs), and
// the form picked at first start (shell.mjs): this phone's identity, or a computer's page (remote).
import mqtt from './vendor/mqtt.esm.js';
import { parseBytes } from 'sigelo';
import { loadIdentity, saveIdentity, webPlatform } from './platform-web.mjs';
import { androidPlatform, connectBridge } from './platform-android.mjs';
import { DEFAULT_RELAY } from './vendor/contact/carrier.mjs';
import { makeRouter, presetRelay } from './router.mjs';
import { pickMode, remoteBackend, wipeIfAsked } from './shell.mjs';

const SETTINGS = 'app/settings.json';
let router = null;
const ready = (async () => {
  let platform;
  if (globalThis.SigeloShell) {
    const bridge = await connectBridge(), box = document.getElementById('setup');
    await wipeIfAsked(bridge);
    if (bridge.info.mode === null) { pickMode(box, bridge); throw Object.assign(new Error('Pick what this phone does, below.'), { status: 403, check: 'mode' }); }
    if (bridge.info.mode === 'remote') return (router = await remoteBackend(bridge, box, { mqtt }));
    platform = await androidPlatform({ bridge, mqtt });
  } else platform = await webPlatform({ mqtt });
  const raw = await loadIdentity(platform);
  if (raw === null) {
    setup(platform);
    throw Object.assign(new Error('This app holds no identity yet: import one below.'), { status: 403, check: 'identity' });
  }
  const s = platform.files.read(SETTINGS), settings = s === null ? {} : JSON.parse(new TextDecoder().decode(s));
  const identity = parseBytes(raw);
  router = makeRouter({ platform, identity: () => identity, mode: settings.mode ?? { kind: 'safe' } });
  await router.start();
  addEventListener('pagehide', () => { void router.stop(); });
  return router;
})();
ready.catch(() => {});

globalThis.sigeloLocal = Object.freeze({
  async call(method, path, body) {
    let r;
    try { r = await ready; } catch (e) { return { status: e.status ?? 503, body: { error: { check: e.check ?? 'start', message: e.message } } }; }
    return r.call(method, path, body);
  },
  onChange(fn) { ready.then((r) => r.onChange(fn), () => {}); },
  mode: () => router?.mode() ?? null,
});

// ---- no identity yet: import one (nothing leaves the page; it is sealed into this app's storage)
function setup(platform) {
  const box = document.getElementById('setup');
  if (!box) return;
  const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids); return e; };
  const file = el('input', { type: 'file', accept: '.json,application/json' });
  const full = el('input', { type: 'checkbox' });
  // The relay new codes name (the page's setting, changed later under Me): a self-hoster's before pairing.
  const relay = el('input', { value: DEFAULT_RELAY, autocomplete: 'off', spellcheck: false, ariaLabel: 'Relay' });
  const say = el('p', { className: 'muted' });
  const go = el('button', { className: 'primary', textContent: 'Import' });
  go.addEventListener('click', async () => {
    const f = file.files?.[0];
    if (!f) { say.textContent = 'Choose the identity file first.'; return; }
    try {
      const bytes = new Uint8Array(await f.arrayBuffer()), s = parseBytes(bytes);
      if (typeof s?.secret !== 'string' || !/^[0-9a-f]{64}$/.test(s.secret) || typeof s.genesis !== 'object') throw new Error('not a sigelo identity file with its key in it');
      presetRelay(platform.files, relay.value);
      await saveIdentity(platform, bytes, undefined, { full: full.checked });
      platform.files.write(SETTINGS, new TextEncoder().encode(JSON.stringify({ mode: full.checked ? { kind: 'full', standby: true } : { kind: 'safe' } })));
      await platform.flush();
      location.reload();
    } catch (e) { say.textContent = `Not imported: ${e.message}`; }
  });
  box.replaceChildren(el('div', { className: 'card' },
    el('h2', { textContent: 'Import an identity' }),
    el('p', { textContent: `The file a computer wrote for this device (sigelo-agent device scan). It is sealed into this app's storage under a key ${platform.sealer ? 'of this phone\'s keystore (FULL: unlocked with your screen lock)' : 'the app cannot export'}.` }),
    file, el('label', {}, full, ' This is the operator (FULL, standby)'),
    el('label', { textContent: 'Relay for new codes' }), relay,
    el('p', { className: 'muted', textContent: 'Keep relay.sigelo.ai unless you run your own. A 12-character code always names its own relay.' }),
    el('div', { className: 'bar' }, go), say));
  box.hidden = false;
}
