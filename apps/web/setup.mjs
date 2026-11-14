// SPDX-License-Identifier: MIT
// The first run's work in this page (welcome.mjs's api): the Android app (a bridge) or a browser tab.
// The form (the shell's mode) is set only when a path commits: self just before a new or restored
// identity is sealed, remote once a computer answered. Until then the welcome's three choices stay open
// and Back can go anywhere among them.
//   create   apps/contact/create.mjs newSeed (S drawn here, the network held from the draw to the end),
//            the three words checked here, then createInto (create.mjs): sealed under the FULL key
//   restore  restoreInto (seed.mjs), the same seal
//   or       Keep it safe → Set a password (keepWords: words.mjs, sealed as a third kind): the words kept, never shown
//   then     the Lock step (the Android app: bridge.unlock, the screen lock once), then You're set (the four words)
//   backup   restoreBackup (backup.mjs): a backup file and its password, the same identity as on the old phone (same
//            keys, same pairings); one another profile here holds refused before anything is written
//   connect  pairComputer (shell.mjs): SIGELO:CTL: over the relay (the four words), SIGELO:UI: on the LAN; the profile's first computer
//   import   Advanced: the file a computer wrote for this device (SAFE); the operator's is refused
import { parseBytes } from 'sigelo';
import { DEFAULT_RELAY } from './vendor/contact/carrier.mjs';
import { checkWords, parseRestore } from './vendor/contact/restore.mjs';
import { newSeed } from './vendor/contact/create.mjs';
import { holdNetwork, saveIdentity } from './platform-web.mjs';
import { presetRelay } from './router.mjs';
import { createInto } from './create.mjs';
import { restoreInto } from './seed.mjs';
import { keepWords } from './words.mjs';
import { restoreBackup } from './backup.mjs';
import { pairComputer } from './shell.mjs';
import { scanner } from './welcome.mjs';
import { didWords } from './vendor/contact/short.mjs';

export const SETTINGS = 'app/settings.json';
let jsQR = null;   // the QR decoder, when this build has it (the import map's /qr-decode.mjs)
if (globalThis.document) import('/qr-decode.mjs').then((m) => { jsQR = m.jsQR; }, () => {});
const gone = (e) => Object.assign(e instanceof Error ? e : new Error(String(e)), { gone: true });
const wordsOf = (did) => { try { return didWords(did); } catch { return null; } };

/**
 * welcome.mjs's api over this page's platform. o: { bridge (Android) | null, mqtt, storage, reload, seal,
 * profile: { name (its database), kind(k) (the registry's kind once a path commits: 'words' | 'remote'), leave?, others?, rename? } }
 * (profiles.mjs; leave: the welcome's way back to the other profiles, for one added and not set up yet; others(): the
 * original DIDs of the other profiles; rename(name): this one named as in a restored backup)
 */
export function setupApi(platform, { bridge = null, mqtt, storage = globalThis.localStorage, reload = () => { location.hash = ''; location.reload(); }, seal = './vendor/icon.svg', profile = {}, words = {} } = {}) {
  let session = null, release = null;
  const drop = () => { session?.discard(); session = null; release?.(); release = null; };
  const mode = async (m) => { if (bridge) await bridge.request('mode', { mode: m }); await profile.kind?.(m === 'remote' ? 'remote' : 'words'); };
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
      let made;
      try {
        await mode('self');
        made = await createInto(platform, session, { name, relay });
      } catch (e) { throw gone(e); } finally { session = null; release?.(); release = null; }
      return { ok: true, words: wordsOf(made?.did) };
    },
    discard: drop,
    // Keep it safe → Set a password (welcome.mjs): the words kept behind the password (words.mjs).
    keepWords: (list, password) => keepWords(platform, list, password, words),
    checkWords,
    async restore({ words, name, height, net, elsewhere, relay }) {
      const restore = parseRestore(height, Math.floor(Date.now() / 1000));
      await mode('self');
      const r = await restoreInto(platform, { words, name, relay, net, restore, seat: elsewhere ? 'elsewhere' : 'here' });
      return { ok: true, words: wordsOf(r?.did) };
    },
    /** A backup file (bytes) and its password → { ok, words }; refused: words_password (after the gate's delay), backup_*. */
    async restoreBackup(bytes, password) {
      const r = await restoreBackup(platform, bytes, password, { dids: profile.others?.() ?? [], commit: () => mode('self'), ...(words.gate && { gate: words.gate }) });
      if (r.name) await profile.rename?.(r.name);
      return { ok: true, words: r.words };
    },
    async connect(text) {
      if (!bridge) throw new Error('Connecting to a computer needs the app: a browser tab cannot reach the relay or the LAN.');
      // The profile's first computer (computers.mjs c1): over the relay the four words to compare, on the LAN opened.
      const r = await pairComputer(bridge, text, { mqtt, storage, ...(profile.name && { name: profile.name }) });
      await mode('remote');
      if (r.opened) reload();
      return r;
    },
    async open() { reload(); },
    async done() { reload(); },
    secure: (on, door) => bridge?.secure(on, { door }),
    // The first run's Lock step (the Android app: the phone's screen lock, asked once); a browser tab has none.
    ...(bridge && { lock: () => bridge.unlock() }),
    clipCopy: (text, clear) => (bridge ? bridge.clipCopy(text, { clear }) : navigator.clipboard.writeText(text)),
    clipClear: () => (bridge ? bridge.clipClear() : navigator.clipboard?.writeText?.('')),
    scan: bridge ? (onText) => scanner(onText, jsQR) : undefined,
    advanced: [{ label: 'Import a device file', run: (ui) => importScreen(ui, platform, { mode, reload }) }],
    ...(profile.leave && { leave: profile.leave }),
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
