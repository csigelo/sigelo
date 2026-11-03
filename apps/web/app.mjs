// SPDX-License-Identifier: MIT
// The self-contained app's start (index.html): boot.mjs with the page's globals. It sets
// globalThis.sigeloLocal = { call, onChange, mode, share, unlock, profiles } for ui.js before anything
// is awaited, so ui.js (a deferred script after this module) finds it. The profiles (profiles.mjs), the
// picker, the first run and the forms: boot.mjs's header.
import mqtt from './vendor/mqtt.esm.js';
import { boot } from './boot.mjs';

const app = boot({
  shell: globalThis.SigeloShell ?? null, box: document.getElementById('setup'), main: document.getElementById('app'), mqtt,
  storage: globalThis.localStorage, session: globalThis.sessionStorage,
  reload: () => { location.hash = ''; location.reload(); },
});
globalThis.sigeloLocal = app.local;
