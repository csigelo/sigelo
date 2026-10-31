// SPDX-License-Identifier: MIT
// The self-contained app's start (index.html): the browser platform (platform-web.mjs), the identity
// this app holds (sealed in its storage), the router (router.mjs) and, for ui.js, the `local`
// backend: globalThis.sigeloLocal = { call, onChange, mode }. Set before anything is awaited, so
// ui.js (a deferred script after this module) finds it. Without an identity: a form to import one
// the first run (welcome.mjs, its work in setup.mjs): create, restore from the 25 words, or connect to an
// agent elsewhere (remote); an import of a device file under Advanced. Then a reload.
// In the Android app (SigeloShell, apps/android): the shell's platform (platform-android.mjs); the form
// (self or remote) is set when a first-run path commits, and a remote form starts shell.mjs's backend.
import mqtt from './vendor/mqtt.esm.js';
import { parseBytes } from 'sigelo';
import { loadIdentity, webPlatform } from './platform-web.mjs';
import { androidPlatform, connectBridge } from './platform-android.mjs';
import { makeRouter } from './router.mjs';
import { remoteBackend, wipeIfAsked } from './shell.mjs';
import { keeperOf, seatOf } from './seed.mjs';
import { firstRun } from './welcome.mjs';
import { setupApi } from './setup.mjs';

const SETTINGS = 'app/settings.json';
let router = null, bridge = null;
const ready = (async () => {
  let platform;
  if (globalThis.SigeloShell) {
    bridge = await connectBridge();
    const box = document.getElementById('setup');
    await wipeIfAsked(bridge);
    if (bridge.info.mode === 'remote') return (router = await remoteBackend(bridge, box, { mqtt }));
    platform = await androidPlatform({ bridge, mqtt });
  } else platform = await webPlatform({ mqtt });
  const raw = await loadIdentity(platform);
  if (raw === null) {
    setup(platform);
    throw Object.assign(new Error('This app holds no identity yet.'), { status: 403, check: 'identity' });
  }
  const s = platform.files.read(SETTINGS), settings = s === null ? {} : JSON.parse(new TextDecoder().decode(s));
  const identity = parseBytes(raw);
  router = makeRouter({ platform, identity: () => identity, mode: settings.mode ?? { kind: 'safe' }, seat: seatOf(platform, () => identity), keeper: keeperOf(platform) });
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
  // A ready-to-send message through the Android share sheet; without the shell, ui.js copies it.
  async share(text) { if (!bridge) throw new Error('no share sheet'); await bridge.share(text); },
});

// ---- no identity yet: the first run, alone on the screen (ui.js's page hidden until there is one)
function setup(platform) {
  const box = document.getElementById('setup');
  if (!box) return;
  const main = document.getElementById('app');
  if (main) main.hidden = true;
  firstRun(box, setupApi(platform, { bridge, mqtt }));
}
