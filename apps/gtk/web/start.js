// SPDX-License-Identifier: MIT
// The app's start page (sigelo-app.js). With an identity on this phone it opens this phone's page at once
// (the main screen); a standby says so and offers "Take the seat here"; a computer kept from before is
// reconnected. Else the first run (welcome.mjs, the screens the Android app shows too): create, restore
// from 25 words, or connect to an agent elsewhere. Each step is an op of the app's bridge:
//   create   newwords (keeper --new-words draws the words), quiz (three positions drawn by the app),
//            create (the app checks the three, then keeper --from-words --keychain --made-here, seat init)
//   restore  restore (the words once on stdin to keeper --from-words --keychain, then seat init)
//   connect  pair (SIGELO:CTL:, control pair: the four words), relay (control ui --app); connect (SIGELO:UI:)
// then self (this phone's page). The words are dropped from this page once used; nothing here stores them.
// The scan (design/apps.md §9): camera (getUserMedia) or an image → pixels → jsQR (contact/qr-decode.mjs).
import { DEFAULT_RELAY, firstRun, scanner } from './welcome.mjs';

const app = document.getElementById('app');
const shell = globalThis.webkit?.messageHandlers?.sigelo;
const ask = (op, o = {}) => shell ? shell.postMessage({ op, ...o }) : Promise.resolve({ ok: false, message: 'Open this page in the sigelo app.' });
const must = async (op, o) => { const r = await ask(op, o); if (!r?.ok) throw Object.assign(new Error(r?.message ?? `${op}: no answer`), { r }); return r; };
const note = location.hash.length > 1 ? decodeURIComponent(location.hash.slice(1)) : null;
if (note) history.replaceState(null, '', location.pathname);

let checkWords = null;
try { ({ checkWords } = await import('./seed-check.mjs')); } catch {}
let jsQR = null;
try { ({ jsQR } = await import('./qr-decode.mjs')); } catch {}
const scan = (onText) => scanner(onText, jsQR);

let relay = DEFAULT_RELAY, clipTimer = 0;
const openSelf = async () => must('self', relay !== DEFAULT_RELAY ? { relay } : {});

const api = {
  seal: 'icon.svg',
  async newWords(net) { const r = await must('newwords', { net }); return { words: r.words, vault: r.vault }; },
  async quiz() { return (await must('quiz')).asked; },
  async confirm(answers, o) {
    relay = o.relay;
    const r = await ask('create', { answers, name: o.name });
    if (r?.wrong) return { wrong: r.wrong };
    if (!r?.ok) throw Object.assign(new Error(r?.message ?? 'not made'), { gone: false });
    return { ok: true, message: r.seat === 'here' ? null : r.message };
  },
  discard: () => ask('discard'),
  checkWords: (t) => checkWords?.(t) ?? { count: 0, ok: false, error: 'the word check is not installed (install.sh)' },
  async restore(o) {
    relay = o.relay;
    const r = await must('restore', { words: o.words, name: o.name, height: o.height, net: o.net, elsewhere: o.elsewhere });
    return { ok: true, standby: r.seat === 'elsewhere', message: r.seat === 'pending' ? r.message : null };
  },
  async connect(text) {
    if (/^\s*SIGELO:CTL:/i.test(text)) { const r = await must('pair', { text: text.trim() }); return { words: r.words }; }
    if (!/^SIGELO:UI:/.test(text)) throw new Error('Not a SIGELO:UI: or SIGELO:CTL: text.');
    await must('connect', { text });
    return { opened: true };
  },
  open: () => must('relay'),
  async done() {
    const s = await ask('saved');
    if (s.standby) { standby(); return; }
    await openSelf();
  },
  async clipCopy(text, seconds) {
    await navigator.clipboard.writeText(text);
    clearTimeout(clipTimer); clipTimer = setTimeout(() => { void ask('clipclear'); }, seconds * 1000);
  },
  clipClear() { clearTimeout(clipTimer); clipTimer = 0; return ask('clipclear'); },
  scan,
};

let fr = null;
/** Restored while another device keeps the seat: this phone waits until the human takes it. */
function standby() {
  const take = Object.assign(document.createElement('button'), { className: 'primary', textContent: 'Take the seat here' });
  const s = fr.screen({ title: 'Standby', back: false, lead: 'Another device holds your seat, so this phone does not log in as you. Take the seat here only if that device is stopped or lost: two devices logging in as you lose each other\'s messages.', primary: take });
  take.onclick = async () => {
    if (!confirm('Take the seat here? Only if the other device is stopped or lost.')) return;
    take.disabled = true; s.say('Taking the seat…', false);
    try { await must('take'); await openSelf(); } catch (e) { s.say(e.message); take.disabled = false; }
  };
}

fr = firstRun(app, api, { show: false });
const saved = await ask('saved');
if (note) {
  // The page stopped, or a step failed: say it, then the welcome (or try the page again).
  const again = Object.assign(document.createElement('button'), { className: 'primary', textContent: saved.identity ? 'Open again' : 'OK' });
  const s = fr.screen({ title: 'Something stopped', back: false, lead: note, primary: again });
  again.onclick = async () => { if (!saved.identity) { location.reload(); return; } again.disabled = true; try { await openSelf(); } catch (e) { s.say(e.message); again.disabled = false; } };
} else if (saved.standby) standby();
else if (saved.identity) {
  const s = fr.screen({ title: 'Opening…', back: false, body: [], busy: true });
  try { await openSelf(); } catch (e) { s.say(e.message); }
} else if (saved.text) {
  const s = fr.screen({ title: 'Connecting…', back: false, lead: 'To the computer this phone controls.', busy: true });
  const r = await ask('resume');
  if (!r.ok) {
    const forget = Object.assign(document.createElement('button'), { textContent: 'Forget it', onclick: async () => { await ask('forget'); location.reload(); } });
    const retry = Object.assign(document.createElement('button'), { className: 'primary', textContent: 'Try again', onclick: () => location.reload() });
    fr.screen({ title: 'No answer', back: false, lead: r.message, primary: retry, secondary: forget });
    void s;
  }
} else fr.welcome();
