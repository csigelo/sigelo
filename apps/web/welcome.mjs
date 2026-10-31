// SPDX-License-Identifier: MIT
// First run, shared by the shells (the Android app's page: app.mjs with setup.mjs; the GTK phone app's
// start page: apps/gtk/web/start.js): one decision per screen, in the order of the reference wallet's screens.
//
//   Welcome   the seal and three choices: Create a new identity, Restore from 25 words, Connect to my
//             agent elsewhere. Advanced (folded, only where a shell adds something): an import.
//   Create    1. Name this phone (Advanced: network, relay)  2. Your 25 words, once: a one-way door (no
//             Back; FLAG_SECURE on Android; copy on stagenet only)  3. Check your paper: three words by
//             number (wrong: which, try again; the 25 again only on "Show the words again")  4. setting up
//   Restore   1. Your 25 words, checked as typed  2. When were they made? (optional) and the network;
//             Advanced: name, another device keeps the seat, relay  3. setting up
//   Connect   1. The code the computer shows (8 characters; Advanced: its relay, a SIGELO:UI: or
//             SIGELO:CTL: text, a QR)  2. Compare four words  then the computer's page
// Back (the screen's button, the browser's, the system's: one history entry per screen) goes one screen
// back, never past the welcome; the words and the check have none. The shell does the work (api) and
// holds the words between the draw and the check; this page drops them once used.
//
// api (a call may throw an Error; its message is shown under the button):
//   seal                               the icon's URL
//   advanced                           [{ label, run(ui) }] on the welcome's fold (ui: { screen, go, button, el })
//   newWords(net)                      → { words: [25], vault }
//   quiz()                             → [three positions, 1 to 25]
//   confirm(answers, { name, relay })  → { wrong: [positions] } | { ok, message? }: right → the identity made;
//                                        a throw with e.gone: checked but not saved, the words dropped
//   discard()                          the drawn words dropped (the app stopped before the check)
//   checkWords(text)                   → { count, ok, error }
//   restore({ words, name, height, net, elsewhere, relay })  → { ok, message? }
//   connect(text)                      → { words } (over the relay: compare, then open()) | { opened: true }
//   open()                             the computer's page, once the words match
//   done(message?)                     the main screen (the shell loads it)
//   scan(onText)                       optional: a node with the camera and image buttons
//   secure(on, door), clipCopy(text, seconds), clipClear()   where the shell has them
export const DEFAULT_RELAY = 'relay.sigelo.ai', CLIP_SECONDS = 60, NAME = /^[a-z0-9][a-z0-9_-]{0,19}$/;
export const NAME_RULE = 'Lowercase letters, digits, _ and -, at most 20.';
export const WORDS_ATTRS = Object.freeze({ autocomplete: 'off', autocorrect: 'off', autocapitalize: 'none', spellcheck: 'false', 'data-lpignore': 'true', 'data-1p-ignore': 'true' });
const CODE = /^[0-9A-Z]{4}-?[0-9A-Z]{4}$/;

export function el(tag, props = {}, ...kids) {
  const { attrs, ...rest } = props, e = Object.assign(document.createElement(tag), rest);
  for (const [k, v] of Object.entries(attrs ?? {})) e.setAttribute(k, v);
  e.append(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false && k !== ''));
  return e;
}
const fold = (label, ...kids) => el('details', { className: 'advanced' }, el('summary', { textContent: label }), ...kids);
/** Radio buttons as large rows → { node, value() }. */
function radios(name, opts, value) {
  const inputs = opts.map(([v]) => el('input', { type: 'radio', name, value: v, checked: v === value }));
  return { node: el('div', { className: 'choice', attrs: { role: 'radiogroup' } }, opts.map(([, label], i) => el('label', { className: 'opt' }, inputs[i], el('span', { textContent: label })))),
    value: () => inputs.find((x) => x.checked)?.value ?? value };
}
/** A pairing failure in the app's words (the CLI's and the carrier's name their flags). */
function plain(e, relay) {
  const m = String(e?.message ?? e), check = e?.check ?? /\b(park_unknown|code_expired|mailbox_taken|short_code|connect)\b/.exec(m)?.[1];
  if (check === 'park_unknown') return `No computer waits under this code at ${relay}. A code lasts 10 minutes and works once: check it, or start sigelo-agent ui --remote --relay again for a new one.`;
  if (check === 'code_expired') return 'The code expired: start sigelo-agent ui --remote --relay again for a new one.';
  if (check === 'mailbox_taken') return 'This code was used already: ask the computer for a new one.';
  if (check === 'connect') return `Cannot reach ${relay}: check this phone's connection, then try again.`;
  return m;
}
const text = (o) => el('input', { ...o, attrs: { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', ...(o.attrs ?? {}) } });

/** The scan for the connect screen's Advanced fold: the camera (getUserMedia) or an image → jsQR → onText. jsQR null: off, said. */
export function scanner(onText, jsQR) {
  const mk = (t, p = {}) => Object.assign(document.createElement(t), p);
  const say = mk('p', { className: 'muted' }), video = mk('video', { className: 'scan', muted: true, playsInline: true, hidden: true });
  const pick = mk('input', { type: 'file', accept: 'image/*', hidden: true });
  const cam = mk('button', { textContent: 'Scan its QR', disabled: !jsQR }), img = mk('button', { textContent: 'From an image', disabled: !jsQR });
  const canvas = mk('canvas'), g = canvas.getContext('2d', { willReadFrequently: true });
  let stream = null, timer = 0;
  const decode = (src, w, h, max) => {
    const k = Math.min(1, max / Math.max(w, h));
    canvas.width = Math.round(w * k); canvas.height = Math.round(h * k);
    g.drawImage(src, 0, 0, canvas.width, canvas.height);
    const px = g.getImageData(0, 0, canvas.width, canvas.height);
    try { return jsQR(px.data, px.width, px.height)?.data ?? null; } catch { return null; }
  };
  const stop = () => { clearInterval(timer); timer = 0; stream?.getTracks().forEach((t) => t.stop()); stream = null; video.hidden = true; cam.textContent = 'Scan its QR'; };
  cam.onclick = async () => {
    if (stream) { stop(); return; }
    try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false }); } catch (e) {
      say.textContent = `No camera here (${e.name}). Take a photo with the Camera app, then use "From an image".`; return;
    }
    video.srcObject = stream; video.hidden = false; cam.textContent = 'Stop the camera';
    await video.play().catch(() => {});
    timer = setInterval(() => { if (video.readyState >= 2) { const t = decode(video, video.videoWidth, video.videoHeight, 640); if (t) { stop(); onText(t); } } }, 200);
  };
  img.onclick = () => pick.click();
  pick.onchange = async () => {
    const f = pick.files?.[0]; pick.value = '';
    if (!f) return;
    let bm;
    try { bm = await createImageBitmap(f); } catch { say.textContent = 'Not an image this app can read.'; return; }
    const t = decode(bm, bm.width, bm.height, 1600) ?? decode(bm, bm.width, bm.height, 800);
    bm.close();
    if (t) onText(t); else say.textContent = 'No QR code found in that image.';
  };
  if (!jsQR) say.textContent = 'QR reading is not installed: type the code.';
  const box = mk('div');
  box.append(Object.assign(mk('div', { className: 'bar' }), {}), video, pick, say);
  box.firstChild.append(cam, img);
  return box;
}

/** The first run in `box` (show false: nothing drawn until welcome()) → { welcome, screen, go, button, stop }. */
export function firstRun(box, api, { show = true } = {}) {
  const stack = [];   // the screens behind this one, for Back
  let current = null, door = false, leave = null;
  const secure = (on, d = false) => { try { void Promise.resolve(api.secure?.(on, d)).catch(() => {}); } catch {} };
  const quiet = (p) => { try { void Promise.resolve(p?.()).catch(() => {}); } catch {} };

  /** One screen: a title, a lead line, the body, one primary button and maybe a second; Back unless back: false. → { say(t, warn) } */
  function screen({ title, lead, body = [], primary, secondary, back = true }) {
    const say = el('p', { className: 'muted say', attrs: { role: 'status', 'aria-live': 'polite' } });
    const head = el('header', {}, back && stack.length ? el('button', { className: 'back', textContent: '‹', attrs: { 'aria-label': 'Back' }, onclick: () => history.back() }) : null, el('h1', { textContent: title }));
    box.replaceChildren(el('div', { className: 'welcome' }, head, lead ? el('p', { textContent: lead }) : null, ...body, el('div', { className: 'bar' }, primary ?? null, secondary ?? null), say));
    box.hidden = false;
    globalThis.scrollTo?.(0, 0);
    return { say: (t, warn = true) => { say.textContent = t ?? ''; say.className = `${warn && t ? 'warn' : 'muted'} say`; } };
  }
  const button = (label, onclick, primary = false) => el('button', { className: primary ? 'primary' : '', textContent: label, onclick });
  /** fn with the button off, its error under it. */
  const busy = (btn, s, fn) => async () => {
    btn.disabled = true; s.say('', false);
    try { await fn(); } catch (e) { s.say(e?.message ?? String(e)); } finally { btn.disabled = false; }
  };

  // ---- navigation: a screen is a function; go() keeps the one before it for Back (one history entry each)
  function go(next, { replace = false } = {}) {
    if (current && !replace) { stack.push(current); history.pushState({ firstRun: stack.length }, ''); }
    current = next;
    return next();
  }
  function home() { stack.length = 0; current = welcome; door = false; secure(false); welcome(); }
  const onPop = () => {
    if (door) { history.pushState({ firstRun: stack.length }, ''); return; }   // the words and the check: no way back
    const prev = stack.pop();
    if (!prev) return;
    const l = leave; leave = null; l?.();
    current = prev; prev();
  };
  addEventListener('popstate', onPop);

  // ---- the welcome
  function welcome() {
    const ui = { screen, go, button, el };
    const adv = api.advanced?.length ? fold('Advanced', ...api.advanced.map((a) => el('div', { className: 'bar' }, button(a.label, () => go(() => a.run(ui)))))) : null;
    box.replaceChildren(el('div', { className: 'welcome home' },
      el('img', { className: 'seal', src: api.seal ?? 'icon.svg', alt: '' }),
      el('h1', { textContent: 'sigelo' }),
      el('p', { className: 'muted', textContent: 'One identity for you and your agents.' }),
      el('div', { className: 'choices' },
        button('Create a new identity', () => go(createName), true),
        button('Restore from 25 words', () => go(restoreWords)),
        button('Connect to my agent elsewhere', () => go(connectCode))),
      adv));
    box.hidden = false;
  }

  // ---- create
  const C = { name: 'phone', net: 'mainnet', relay: DEFAULT_RELAY, words: null, vault: null };
  function createName() {
    const name = text({ value: C.name, attrs: { maxlength: '20', 'aria-label': 'Name for this phone' } });
    const relay = text({ value: C.relay, attrs: { 'aria-label': 'Relay' } });
    const nets = radios('create-net', [['mainnet', 'Mainnet'], ['stagenet', 'Stagenet (test coins, worth nothing)']], C.net);
    const next = button('Make my 25 words', null, true);
    const s = screen({ title: 'Name this phone', lead: 'Your agents see this name.', primary: next,
      body: [name, el('p', { className: 'muted', textContent: NAME_RULE }), fold('Advanced', el('label', { textContent: 'Monero network' }), nets.node, el('label', { textContent: 'Relay' }), relay)] });
    next.onclick = busy(next, s, async () => {
      const n = name.value.trim();
      if (!NAME.test(n)) throw new Error(`Name: ${NAME_RULE}`);
      C.name = n; C.relay = relay.value.trim().toLowerCase() || DEFAULT_RELAY; C.net = nets.value();
      const w = await api.newWords(C.net);
      C.words = w.words; C.vault = w.vault;
      go(createWords);
    });
  }
  function createWords() {
    door = true; secure(true, true);
    const list = el('ol', { className: `seed-list${C.net === 'mainnet' ? ' nocopy' : ''}`, attrs: { 'aria-label': 'Your 25 words, in order' } }, C.words.map((w) => el('li', { textContent: w })));
    if (C.net === 'mainnet') list.addEventListener('copy', (e) => e.preventDefault());
    const copy = C.net === 'stagenet' ? button('Copy (stagenet only)', null) : null;
    const s = screen({ title: 'Your 25 words', back: false,
      body: [el('p', { className: 'warn', textContent: 'Write them on paper, in order. They are shown once. Whoever has them owns this identity and its wallet.' }),
        list, el('label', { textContent: 'Their wallet\'s address, to check your paper later' }), el('p', { className: 'mono', textContent: C.vault }),
        C.net === 'mainnet' ? el('p', { className: 'muted', textContent: 'No copy on mainnet: write them by hand.' }) : null],
      primary: button('I have written them down', () => go(() => createCheck(), { replace: true }), true), secondary: copy });
    if (copy) copy.onclick = async () => {
      try { await api.clipCopy(C.words.join(' '), CLIP_SECONDS); s.say(`Copied. The clipboard is emptied in ${CLIP_SECONDS} s.`, false); } catch (e) { s.say(`Not copied: ${e.message}`); }
    };
  }
  async function createCheck(note = '') {
    door = true;
    quiet(api.clipClear);
    let asked;
    try { asked = await api.quiz(); } catch (e) { screen({ title: 'Check your paper', back: false, primary: button('Back to the start', home, true) }).say(e.message); return; }
    const inputs = asked.map((n) => el('input', { attrs: { ...WORDS_ATTRS, 'aria-label': `Word ${n}` } }));
    const ok = button('Check', null, true);
    const s = screen({ title: 'Check your paper', lead: 'Type these words from your paper.', back: false,
      body: asked.flatMap((n, i) => [el('label', { textContent: `Word ${n}` }), inputs[i]]),
      primary: ok, secondary: button('Show the words again', () => go(createWords, { replace: true })) });
    if (note) s.say(note);
    inputs[0]?.focus?.();
    ok.onclick = busy(ok, s, async () => {
      const answers = inputs.map((x) => x.value);
      if (answers.some((a) => !a.trim())) throw new Error('Type all three words.');
      for (const x of inputs) x.value = '';
      settingUp('Making your identity');
      let r;
      try { r = await api.confirm(answers, { name: C.name, relay: C.relay }); } catch (e) {
        const f = e?.gone
          ? screen({ title: 'Not saved', back: false, lead: 'Your 25 words are on your paper: restore from them.', primary: button('Restore from 25 words', () => { home(); go(restoreWords); }, true), secondary: button('Back to the start', home) })
          : screen({ title: 'Not made', back: false, lead: 'Nothing was kept.', primary: button('Try again', () => go(() => createCheck(), { replace: true }), true) });
        if (e?.gone) { C.words = null; C.vault = null; door = false; secure(false); }
        f.say(e?.message ?? String(e));
        return;
      }
      if (r?.wrong) { go(() => createCheck(`Word${r.wrong.length > 1 ? 's' : ''} ${r.wrong.join(', ')} did not match. Check your paper, then try again.`), { replace: true }); return; }
      C.words = null; C.vault = null; door = false; secure(false);
      await api.done?.(r?.message);
    });
  }

  // ---- restore
  const R = { words: '', height: '', net: 'mainnet', name: 'phone', elsewhere: false, relay: DEFAULT_RELAY };
  function restoreWords() {
    secure(true);
    const words = el('textarea', { rows: 6, value: R.words, attrs: { ...WORDS_ATTRS, 'aria-label': 'Your 25 words', 'aria-describedby': 'seed-count' } });
    const count = el('p', { className: 'muted', id: 'seed-count', textContent: '0 of 25 words' });
    const next = button('Next', null, true);
    const live = () => {
      const c = api.checkWords(words.value);
      count.textContent = c.error ? `${c.count} of 25: ${c.error}` : c.ok ? '25 of 25, checksum ok' : `${c.count} of 25 words`;
      count.className = c.error ? 'warn' : c.ok ? 'good' : 'muted';
      next.disabled = !c.ok;
    };
    words.addEventListener('input', live);
    words.addEventListener('paste', () => setTimeout(() => { quiet(api.clipClear); live(); }, 0));
    leave = () => { R.words = ''; words.value = ''; secure(false); };   // Back to the welcome: the words dropped
    screen({ title: 'Restore from 25 words', lead: 'Type or paste your 25 words, in order. They are checked as you type and kept nowhere.', body: [words, count], primary: next });
    live();
    next.onclick = () => { R.words = words.value; words.value = ''; leave = null; go(restoreBirth); };
    words.focus?.();
  }
  function restoreBirth() {
    const height = text({ value: R.height, placeholder: '2024-02-29 or 3100000', attrs: { 'aria-label': 'Restore date or height' } });
    const nets = radios('seed-net', [['mainnet', 'Mainnet'], ['stagenet', 'Stagenet (test coins)']], R.net);
    const name = text({ value: R.name, attrs: { maxlength: '20', 'aria-label': 'Name for this phone' } });
    const elsewhere = el('input', { type: 'checkbox', checked: R.elsewhere });
    const relay = text({ value: R.relay, attrs: { 'aria-label': 'Relay' } });
    const start = button('Restore', null, true);
    const s = screen({ title: 'When were the words made?', lead: 'The day or block height your wallet started. Empty: from the first block (slower).',
      body: [height, el('label', { textContent: 'Monero network' }), nets.node,
        fold('Advanced', el('label', { textContent: 'Name for this phone' }), name, el('p', { className: 'muted', textContent: NAME_RULE }),
          el('label', { className: 'opt' }, elsewhere, el('span', { textContent: 'sigelo already runs as me on another device: this phone waits (standby)' })),
          el('label', { textContent: 'Relay' }), relay)],
      primary: start });
    start.onclick = busy(start, s, async () => {
      const h = height.value.trim(), n = name.value.trim();
      if (h !== '' && !/^\d{1,10}$/.test(h) && !/^\d{4}-\d{2}-\d{2}$/.test(h)) throw new Error('A date as YYYY-MM-DD, a block height (digits), or empty.');
      if (!NAME.test(n)) throw new Error(`Name: ${NAME_RULE}`);
      Object.assign(R, { height: h, net: nets.value(), name: n, elsewhere: elsewhere.checked, relay: relay.value.trim().toLowerCase() || DEFAULT_RELAY });
      settingUp('Restoring your identity');
      let r;
      try { r = await api.restore({ words: R.words, name: R.name, height: R.height, net: R.net, elsewhere: R.elsewhere, relay: R.relay }); } catch (e) {
        current = restoreBirth; restoreBirth().say(`Not restored: ${e?.message ?? e}`); return;
      }
      R.words = ''; secure(false);
      await api.done?.(r?.message);
    });
    return s;
  }

  // ---- connect: this phone controls an agent on another machine
  function connectCode() {
    const code = el('input', { className: 'code-in', placeholder: 'K7F3-Q9ZP', attrs: { autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', maxlength: '9', 'aria-label': 'The code' } });
    const relay = text({ placeholder: DEFAULT_RELAY, attrs: { 'aria-label': 'Its relay' } });
    const pasted = el('textarea', { rows: 2, attrs: { autocomplete: 'off', spellcheck: 'false', 'aria-label': 'A SIGELO:UI: or SIGELO:CTL: text' } });
    const next = button('Connect', null, true);
    code.addEventListener('input', () => {
      const v = code.value.toUpperCase().replace(/[^0-9A-Z]/g, '').slice(0, 8);
      code.value = v.length > 4 ? `${v.slice(0, 4)}-${v.slice(4)}` : v;
    });
    const s = screen({ title: 'Connect to my agent', lead: 'On the computer that runs your agent: sigelo-agent ui --remote --relay. Type the code it shows.',
      body: [code, fold('Advanced', el('label', { textContent: 'Its relay, if not the default' }), relay,
        el('label', { textContent: 'Or paste its SIGELO:UI: text (same network) or SIGELO:CTL: text' }), pasted, api.scan ? api.scan((t) => { pasted.value = t; void next.onclick(); }) : null)],
      primary: next });
    next.onclick = busy(next, s, async () => {
      const t = pasted.value.replace(/^\s+/, ''), c = code.value.trim().toUpperCase(), host = relay.value.trim().toLowerCase();
      let what;
      if (t) what = t;   // base45 has spaces: never trimmed at the end
      else if (CODE.test(c)) what = `SIGELO:CTL:${c.replace(/^(.{4})-?/, '$1-')}${host && host !== DEFAULT_RELAY ? `:${host.toUpperCase()}` : ''}`;
      else throw new Error('The code has 8 letters and digits, like K7F3-Q9ZP.');
      s.say('Connecting… The first time, a one-time proof of work: up to 2 minutes.', false);
      let r;
      try { r = await api.connect(what); } catch (e) { throw new Error(plain(e, host || DEFAULT_RELAY)); }
      if (!r?.opened) go(() => connectWords(r?.words));
    });
    code.focus?.();
  }
  function connectWords(words) {
    const open = button('They match: open', null, true);
    const s = screen({ title: 'Compare four words', lead: 'The computer shows four words too. Answer y there only if they are the same, then open.',
      body: [el('p', { className: 'words', textContent: words ?? '(none)' })], primary: open });
    open.onclick = busy(open, s, async () => { await api.open(); });
  }

  // ---- the work after the last decision
  function settingUp(what) {
    const t0 = Date.now(), n = el('p', { className: 'muted', textContent: '0 s' });
    screen({ title: `${what}…`, lead: 'The first connection to the relay does a one-time proof of work: up to 2 minutes. Keep the app open.',
      body: [el('div', { className: 'progress indeterminate' }, el('div')), n], back: false });
    const tick = setInterval(() => { if (!box.contains?.(n)) { clearInterval(tick); return; } n.textContent = `${Math.round((Date.now() - t0) / 1000)} s`; }, 1000);
  }

  current = welcome;
  if (show) welcome();
  return {
    welcome: home, screen, go, button,
    stop() { removeEventListener('popstate', onPop); if (C.words) quiet(api.discard); C.words = null; R.words = ''; secure(false); },
  };
}
