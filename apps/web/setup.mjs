// SPDX-License-Identifier: MIT
// The first run's work in this page (welcome.mjs's api): the Android app (a bridge) or a browser tab.
// The form (the shell's mode) is set only when a path commits: self just before a new or restored
// identity is sealed, remote once a computer answered. Until then the welcome's three choices stay open
// and Back can go anywhere among them.
//   create   contact/create.mjs newSeed (S drawn here, the network held from the draw to the end),
//            the three words checked here, then createInto (create.mjs): sealed under the FULL key
//   restore  restoreInto (seed.mjs), the same seal
//   connect  SIGELO:CTL: pairRelay (shell.mjs, the four words), SIGELO:UI: connectLan (shell.mjs)
//   import   Advanced: the file a computer wrote for this device (SAFE); the operator's is refused
import { parseBytes } from 'sigelo';
import { DEFAULT_RELAY } from './vendor/contact/carrier.mjs';
import { checkWords, parseRestore } from './vendor/contact/restore.mjs';
import { newSeed } from './vendor/contact/create.mjs';
import { holdNetwork, saveIdentity } from './platform-web.mjs';
import { presetRelay } from './router.mjs';
import { createInto } from './create.mjs';
import { restoreInto } from './seed.mjs';
import { connectLan, pairRelay } from './shell.mjs';
import { scanner } from './welcome.mjs';

export const SETTINGS = 'app/settings.json';
let jsQR = null;   // the QR decoder, when this build has it (the import map's /qr-decode.mjs)
if (globalThis.document) import('/qr-decode.mjs').then((m) => { jsQR = m.jsQR; }, () => {});
const gone = (e) => Object.assign(e instanceof Error ? e : new Error(String(e)), { gone: true });

/** welcome.mjs's api over this page's platform. o: { bridge (Android) | null, mqtt, storage, reload, seal } */
export function setupApi(platform, { bridge = null, mqtt, storage = globalThis.localStorage, reload = () => { location.hash = ''; location.reload(); }, seal = './vendor/icon.svg' } = {}) {
  let session = null, release = null;
  const drop = () => { session?.discard(); session = null; release?.(); release = null; };
  const mode = async (m) => { if (bridge) await bridge.request('mode', { mode: m }); };
  return {
    seal,
    async newWords(net) {
      drop();
      release = holdNetwork();
      session = newSeed(net);
      return { words: session.words(), vault: session.vault };
    },
    async quiz() { if (!session) throw new Error('No words drawn: start again.'); return session.quiz(); },
    async confirm(answers, { name, relay }) {
      if (!session) throw gone(new Error('No words drawn: start again.'));
      const r = session.check(answers);
      if (!r.ok) return { wrong: r.wrong };
      try {
        await mode('self');
        await createInto(platform, session, { name, relay });
      } catch (e) { throw gone(e); } finally { session = null; release?.(); release = null; }
      return { ok: true };
    },
    discard: drop,
    checkWords,
    async restore({ words, name, height, net, elsewhere, relay }) {
      const restore = parseRestore(height, Math.floor(Date.now() / 1000));
      await mode('self');
      await restoreInto(platform, { words, name, relay, net, restore, seat: elsewhere ? 'elsewhere' : 'here' });
      return { ok: true };
    },
    async connect(text) {
      if (!bridge) throw new Error('Connecting to a computer needs the app: a browser tab cannot reach the relay or the LAN.');
      if (/^\s*SIGELO:CTL:/i.test(text)) {
        const r = await pairRelay(bridge, text.trim(), { mqtt, storage });
        await mode('remote');
        return { words: r.words };
      }
      await connectLan(bridge, text, { storage });
      await mode('remote');
      reload();
      return { opened: true };
    },
    async open() { reload(); },
    async done() { reload(); },
    secure: (on, door) => bridge?.secure(on, { door }),
    clipCopy: (text, clear) => (bridge ? bridge.clipCopy(text, { clear }) : navigator.clipboard.writeText(text)),
    clipClear: () => (bridge ? bridge.clipClear() : navigator.clipboard?.writeText?.('')),
    scan: bridge ? (onText) => scanner(onText, jsQR) : undefined,
    advanced: [{ label: 'Import a device file', run: (ui) => importScreen(ui, platform, { mode, reload }) }],
  };
}

/** Advanced: the identity file `sigelo-agent device scan` wrote for this device on a computer (SAFE). */
function importScreen({ screen, button, el }, platform, { mode, reload }) {
  const file = el('input', { type: 'file', accept: '.json,application/json', attrs: { 'aria-label': 'The identity file' } });
  const relay = el('input', { value: DEFAULT_RELAY, attrs: { autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none', 'aria-label': 'Relay' } });
  const go = button('Import', null, true);
  const s = screen({ title: 'Import a device file', lead: `The file a computer made for this phone (sigelo-agent device scan). It is sealed under ${platform.sealer ? 'a key of this phone\'s keystore' : 'a key this app cannot export'}. Your own identity (FULL) comes from your 25 words instead.`,
    body: [file, el('label', { textContent: 'Relay' }), relay], primary: go });
  go.onclick = async () => {
    const f = file.files?.[0];
    if (!f) { s.say('Choose the file first.'); return; }
    go.disabled = true;
    try {
      const bytes = new Uint8Array(await f.arrayBuffer()), id = parseBytes(bytes);
      if (typeof id?.secret !== 'string' || !/^[0-9a-f]{64}$/.test(id.secret) || typeof id.genesis !== 'object') throw new Error('not a sigelo identity file with its key in it');
      await mode('self');
      presetRelay(platform.files, relay.value);
      await saveIdentity(platform, bytes, undefined, { full: false });
      platform.files.write(SETTINGS, new TextEncoder().encode(JSON.stringify({ mode: { kind: 'safe' } })));
      await platform.flush();
      reload();
    } catch (e) { s.say(`Not imported: ${e.message}`); go.disabled = false; }
  };
}
