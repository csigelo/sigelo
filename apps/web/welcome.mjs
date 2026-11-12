// SPDX-License-Identifier: MIT
// First run, shared by the shells (the Android app's page: app.mjs with setup.mjs; the GTK phone app's
// start page: apps/gtk/web/start.js), in the words of design/ux1/mock.html: one decision per screen.
//
//   Welcome   sigelo, what it is, four ways: Create my identity, I have an invite code (where the shell keeps
//             one: api.join), Restore from 25 words, Use my computer instead. Advanced (folded, only where a
//             shell adds something): an import. Close: back to the other profiles (api.leave).
//   Create    1. Name this phone (More options: network, relay)  2. Keep it safe: write down 25 words (the words
//             once: a one-way door, no Back, FLAG_SECURE on Android, copy on the test network only; then Check
//             your paper: three words by number, wrong: which, try again) or set a password (api.keepWords: the
//             words stay on this phone, locked by it, never shown)  3. Lock (api.lock: the phone's screen lock);
//             then You're set (the four words), Open sigelo. Without api.keepWords no choice: the words on paper.
//   Restore   one screen: the 25 words checked as typed, when they were made (a month, optional), is this
//             identity in use on another device (main or spare); More options: network, block height, name,
//             relay; then Restoring, Lock, done
//   Join      the code they gave (or a scan), kept (api.join), then Name this phone, Join, and Create's step 2;
//             the app pairs with it once the identity is made (the four words are compared in that chat)
//   Connect   Use my computer: scan its QR or type its code (Advanced: its relay, a SIGELO:UI: or SIGELO:CTL:
//             text), then Compare four words, then the computer's page
// Back (the screen's button, the browser's, the system's: one history entry per screen) goes one screen back,
// never past the welcome; the words, the check and every screen once the identity is made have none. The shell
// does the work (api) and holds the words between the draw and the check; this page drops them once used.
//
// api (a call may throw an Error; its message is shown under the button):
//   seal                               the icon's URL (the profile picker)
//   advanced                           [{ label, run(ui) }] on the welcome's fold (ui: { screen, go, button, el })
//   newWords(net)                      → { words: [25], vault }
//   quiz()                             → [three positions, 1 to 25]
//   confirm(answers, { name, relay })  → { wrong: [positions] } | { ok, message?, words? }: right → the identity
//                                        made (words: its four words, for You're set); a throw with e.gone:
//                                        checked but not saved, the words dropped
//   discard()                          the drawn words dropped (the app stopped before the check)
//   checkWords(text)                   → { count, ok, error }
//   restore({ words, name, height, net, elsewhere, relay })  → { ok, message?, words? }
//   join(code)                         optional: the invite code kept until the new identity's page opens
//   keepWords(words, password)         optional: Keep it safe → Set a password: the words kept encrypted under it
//   lock()                             optional: the phone's screen lock, asked once (Lock → Use my phone's lock)
//   connect(text)                      → { words } (over the relay: compare, then open()) | { opened: true }
//   open()                             the computer's page, once the words match
//   done(message?)                     the main screen (the shell loads it)
//   scan(onText)                       optional: a node with the camera and image buttons
//   secure(on, door), clipCopy(text, seconds), clipClear()   where the shell has them
//   leave                              optional { label, run() }: a profile added and not set up yet, back to the others
//   cancel                             optional { label, run() }: on the connect screen, a computer being added (connect())
// pickProfile(box, o): the picker at a start with more than one profile (design/profiles.md §3), below.
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

/** The mock's icons the first run draws (24 × 24, stroked); text where the page has no SVG. */
const ICON = { back: ['M15 5l-7 7 7 7'], x: ['M6 6l12 12M18 6L6 18'], check: ['M5 12l5 5 9-10'], scan: ['M4 8V4h4M16 4h4v4M20 16v4h-4M8 20H4v-4M4 12h16'],
  finger: ['M12 11v4M8.5 9a4 4 0 017 0v6M6 8.5a7 7 0 0112 0v5M9 13v3a3 3 0 006 0'] };
function icon(name) {
  if (!document.createElementNS) return null;
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const [k, v] of [['class', 'ic'], ['viewBox', '0 0 24 24'], ['aria-hidden', 'true'], ['focusable', 'false']]) s.setAttribute(k, v);
  for (const d of ICON[name]) { const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', d); s.append(p); }
  return s;
}
let fid = 0;
/** A labelled control (the label tied to it by id), a help line under it. */
function field(label, control, help) {
  if (!control.id) control.id = `fr${++fid}`;
  return el('div', { className: 'field' }, el('label', { textContent: label, htmlFor: control.id, attrs: { for: control.id } }), control, help ? el('p', { className: 'help', textContent: help }) : null);
}
const monthOk = (v) => /^\d{4}-(0[1-9]|1[0-2])$/.test(v);

/** The first run in `box` (show false: nothing drawn until welcome()) → { welcome, screen, go, button, stop }. */
export function firstRun(box, api, { show = true } = {}) {
  const stack = [];   // the screens behind this one, for Back
  let current = null, door = false, leave = null;
  const secure = (on, d = false) => { try { void Promise.resolve(api.secure?.(on, d)).catch(() => {}); } catch {} };
  const quiet = (p) => { try { void Promise.resolve(p?.()).catch(() => {}); } catch {} };

  /**
   * One screen: a title (the top bar's; hidden on a hero screen), a step line, a heading, a lead, the body, one
   * primary button and maybe a second; Back unless back: false, or Close (close: fn). → { say(t, warn) }
   */
  function screen({ title, steps, h2, lead, body = [], primary, secondary, back = true, close, hero = false }) {
    const say = el('p', { className: 'muted say', attrs: { role: 'status', 'aria-live': 'polite' } });
    const nav = close ? el('button', { className: 'ib', attrs: { 'aria-label': 'Close', title: 'Close' }, onclick: close }, icon('x') ?? '×')
      : back && stack.length ? el('button', { className: 'ib back', attrs: { 'aria-label': 'Back', title: 'Back' }, onclick: () => history.back() }, icon('back') ?? '‹') : null;
    const head = el('header', { className: hero ? 'plain' : '' }, nav, el('h1', { className: hero ? 'sr' : '', textContent: title }));
    box.replaceChildren(el('div', { className: `welcome${hero ? ' hero-run' : ''}` }, head,
      steps ? el('p', { className: 'steps', textContent: steps }) : null, h2 ? el('h2', { className: 'big', textContent: h2 }) : null,
      lead ? el('p', { className: 'lead', textContent: lead }) : null, ...body, el('div', { className: 'bar' }, primary ?? null, secondary ?? null), say));
    box.hidden = false;
    globalThis.scrollTo?.(0, 0);
    return { say: (t, warn = true) => { say.textContent = t ?? ''; say.className = `${warn && t ? 'warn' : 'muted'} say`; } };
  }
  /** A button: primary (true), 'ghost', or plain; an icon before the label. */
  const button = (label, onclick, kind = false, ic) => el('button', { className: kind === true ? 'primary' : kind || '', onclick }, ic ? icon(ic) : null, label);
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
    if (door) { history.pushState({ firstRun: stack.length }, ''); return; }   // the words, the check, what follows the identity: no way back
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
      api.leave ? el('header', { className: 'plain' }, el('button', { className: 'ib', attrs: { 'aria-label': api.leave.label, title: api.leave.label }, onclick: () => api.leave.run() }, icon('x') ?? '×')) : null,
      el('h1', { className: 'wordmark', textContent: 'sigelo' }),
      el('p', { className: 'lead strong', textContent: 'One identity for you and your agents.' }),
      el('p', { className: 'lead', textContent: 'Chat with people and agents, privately. Let your agents act for you, within limits you set.' }),
      el('div', { className: 'choices' },
        button('Create my identity', () => { C.join = null; go(createName); }, true),
        api.join ? button('I have an invite code', () => go(joinCode)) : null,
        button('Restore from 25 words', () => go(restoreWords)),
        button('Use my computer instead', () => go(connectCode), 'ghost')),
      adv));
    box.hidden = false;
  }

  // ---- join (I have an invite code; the Add sheet's "Join from an invite code"): the code first, then the name and Create's
  // step 2; the page pairs with the code once the identity is made, and the four words are compared in that chat
  const JOIN_CODE = /^([0-9A-Z]{4}-?[0-9A-Z]{4}(-?[0-9A-Z]{4})?|sgl1[1-9A-HJ-NP-Za-km-z]{20,})$/;
  function joinCode() {
    const code = el('input', { className: 'code-in', placeholder: 'K7F3-Q9ZP', attrs: { autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false' } });
    const next = button('Next', null, true), scanBox = el('div');
    const s = screen({ title: 'Join from an invite', lead: 'Someone gave you a code or a QR. Enter it, and you\'ll be chatting with them in a minute.',
      body: [field('Invite code', code, '8 letters and digits. A shop\'s public code works too.'),
        api.scan ? el('div', { className: 'bar' }, button('Scan a QR instead', () => { scanBox.replaceChildren(api.scan((t) => { code.value = t.trim(); void next.onclick(); })); }, false, 'scan')) : null, scanBox], primary: next });
    next.onclick = busy(next, s, async () => {
      const c = code.value.trim();
      const v = /^sgl1/i.test(c) ? c.replace(/\s+/g, '') : c.toUpperCase();
      if (!JOIN_CODE.test(v)) throw new Error('The code has 8 letters and digits, like K7F3-Q9ZP, or starts with sgl1.');
      api.join?.(v);
      C.join = v;
      go(createName);
    });
    code.focus?.();
  }

  // ---- create: 1 the name, 2 keep it safe (the words on paper, or a password), 3 the lock; then You're set
  const C = { name: 'phone', net: 'mainnet', relay: DEFAULT_RELAY, words: null, vault: null, join: null, made: null };
  const total = () => (api.lock ? 3 : 2);
  const step = (n) => `Step ${n} of ${total()}`;
  /** The network select of More options: the mock's two choices. */
  const netSelect = (v) => {
    const sel = el('select', {}, el('option', { value: 'mainnet', textContent: 'Main network' }), el('option', { value: 'stagenet', textContent: 'Test network (coins worth nothing)' }));
    sel.value = v;
    return sel;
  };
  function createName() {
    const name = text({ value: C.name, attrs: { maxlength: '20' } });
    const relay = text({ value: C.relay }), net = netSelect(C.net);
    const next = button(C.join ? 'Join' : 'Next', null, true);
    const s = screen({ title: 'Name this phone', steps: C.join ? null : step(1), h2: C.join ? null : 'What should your agents call this phone?',
      lead: C.join ? 'We make your identity on this phone now. Then you protect it with 25 words or a password.' : null, primary: next,
      body: [field('Name', name, `${NAME_RULE} People you pair with name you themselves.`), fold('More options', field('Monero network', net), field('Relay', relay))] });
    next.onclick = busy(next, s, async () => {
      const n = name.value.trim();
      if (!NAME.test(n)) throw new Error(`Name: ${NAME_RULE}`);
      C.name = n; C.relay = relay.value.trim().toLowerCase() || DEFAULT_RELAY; C.net = net.value === 'stagenet' ? 'stagenet' : 'mainnet';
      if (api.keepWords) { go(gate); return; }
      await draw();
      go(createWords);
    });
    name.focus?.();
  }
  const draw = async () => { const w = await api.newWords(C.net); C.words = w.words; C.vault = w.vault; };
  /** Keep it safe (the mock's words gate): the words on paper, or a password; one before going on. */
  function gate() {
    const card = (title, sub, run) => el('button', { className: 'card tap', onclick: run }, el('b', { textContent: title }), el('span', { className: 'help', textContent: sub }));
    let s = null;
    const paper = card('Write down 25 words', 'On paper. They bring everything back on any phone. Safest.', async () => {
      s.say('', false);
      try { await draw(); go(createWords); } catch (e) { s.say(e?.message ?? String(e)); }
    });
    const pass = card('Set a password', 'The words stay on this phone, locked by it. Lose the phone and they are gone.', () => go(wordsPassword));
    s = screen({ title: 'Keep it safe', steps: step(2), h2: 'Choose how to protect your identity', lead: 'Your identity and money come from 25 words. Pick one before you go on.', body: [el('div', { className: 'stack' }, paper, pass)] });
  }
  /** Set a password: the words drawn and kept here under it (never shown), checked by this page, the identity made. */
  function wordsPassword() {
    const attrs = { autocomplete: 'new-password', autocapitalize: 'none', spellcheck: 'false' };
    const pw = el('input', { type: 'password', attrs }), again = el('input', { type: 'password', attrs });
    const set = button('Set password', null, true);
    const s = screen({ title: 'Set a password', steps: step(2), lead: 'It locks your 25 words on this phone. You need it to see them again in Settings.',
      body: [field('Password', pw, 'At least 8 characters.'), field('Repeat it', again)], primary: set });
    set.onclick = busy(set, s, async () => {
      if ([...pw.value].length < 8) throw new Error('A password of at least 8 characters.');
      if (pw.value !== again.value) throw new Error('The two passwords are not the same.');
      const password = pw.value;
      pw.value = ''; again.value = '';
      await draw();
      const words = C.words, asked = await api.quiz();
      door = true;
      settingUp('Making your identity');
      let r;
      try { r = await api.confirm(asked.map((n) => words[n - 1]), { name: C.name, relay: C.relay }); } catch (e) { return failed(e); }
      if (r?.wrong) return failed(new Error('The words did not check: start again.'));
      C.made = r;
      try { await api.keepWords(words, password); } catch (e) {
        // Made, but not kept: the words now, once, on paper (the only copy).
        C.words = words;
        go(() => createWords({ made: true, note: `Not kept on this phone (${e?.message ?? e}): write these words down now. They are the only copy.` }), { replace: true });
        return undefined;
      }
      C.words = null; C.vault = null;
      return afterMade();
    });
    pw.focus?.();
  }
  function createWords({ made = false, note = '' } = {}) {
    door = true; secure(true, true);
    const list = el('ol', { className: `seed-list${C.net === 'mainnet' ? ' nocopy' : ''}`, attrs: { 'aria-label': 'Your 25 words, in order' } }, C.words.map((w) => el('li', { textContent: w })));
    if (C.net === 'mainnet') list.addEventListener('copy', (e) => e.preventDefault());
    const copy = C.net === 'stagenet' ? button('Copy (test network only)', null) : null;
    const s = screen({ title: 'Your 25 words', steps: made ? null : step(2), back: false,
      lead: 'Write these words on paper, in order. They are the only way to get your identity and money back if you lose this phone.',
      body: [list, el('p', { className: 'help', textContent: C.net === 'mainnet' ? 'No copy, no screenshot: write them by hand. Never type them into a website.' : 'Test network: Copy works. On the main network: no copy, no screenshot.' }),
        C.vault ? fold('Their wallet\'s address', el('p', { className: 'help', textContent: 'To check your paper later: a Monero wallet restored from these words shows this address.' }), el('p', { className: 'mono', textContent: C.vault })) : null],
      primary: button('I wrote them down', () => (made ? afterMade({ shown: true }) : go(() => createCheck(), { replace: true })), true), secondary: copy });
    if (note) s.say(note);
    if (copy) copy.onclick = async () => {
      try { await api.clipCopy(C.words.join(' '), CLIP_SECONDS); s.say(`Copied. The clipboard is emptied in ${CLIP_SECONDS} s.`, false); } catch (e) { s.say(`Not copied: ${e.message}`); }
    };
  }
  async function createCheck(note = '') {
    door = true;
    quiet(api.clipClear);
    let asked;
    try { asked = await api.quiz(); } catch (e) { screen({ title: 'Check your paper', back: false, primary: button('Back to the start', home, true) }).say(e.message); return; }
    const inputs = asked.map(() => el('input', { attrs: { ...WORDS_ATTRS } }));
    const ok = button('Check', null, true);
    const s = screen({ title: 'Check your paper', steps: step(2), lead: 'Type these three words from your paper. You can\'t go on without them.', back: false,
      body: [...asked.map((n, i) => field(`Word ${n}`, inputs[i])), el('div', { className: 'bar' }, button('Show the words again', () => go(createWords, { replace: true }), 'ghost'))],
      primary: ok });
    if (note) s.say(note);
    inputs[0]?.focus?.();
    ok.onclick = busy(ok, s, async () => {
      const answers = inputs.map((x) => x.value);
      if (answers.some((a) => !a.trim())) throw new Error('Type all three words.');
      for (const x of inputs) x.value = '';
      settingUp('Making your identity');
      let r;
      try { r = await api.confirm(answers, { name: C.name, relay: C.relay }); } catch (e) { return failed(e); }
      if (r?.wrong) { go(() => createCheck(`Word${r.wrong.length > 1 ? 's' : ''} ${r.wrong.join(', ')} did not match. Check your paper, then try again.`), { replace: true }); return undefined; }
      C.made = r;
      return afterMade();
    });
  }
  /** confirm refused: checked but not saved (gone: restore from the paper), or nothing made (try again). */
  function failed(e) {
    const f = e?.gone
      ? screen({ title: 'Not saved', back: false, lead: 'Your 25 words are on your paper: restore from them.', primary: button('Restore from 25 words', () => { home(); go(restoreWords); }, true), secondary: button('Back to the start', home) })
      : screen({ title: 'Not made', back: false, lead: 'Nothing was kept.', primary: button('Try again', () => go(() => createCheck(), { replace: true }), true) });
    if (e?.gone) { C.words = null; C.vault = null; door = false; secure(false); }
    f.say(e?.message ?? String(e));
  }
  /** The identity is made: the words leave this page; the lock (where the shell has one), then You're set. No way back. */
  function afterMade() {
    C.words = null; C.vault = null; door = true; secure(false);
    if (api.lock) return go(newLock, { replace: true });
    return go(newDone, { replace: true });
  }
  function newLock() {
    const use = button('Use my phone\'s lock', null, true, 'finger');
    const s = screen({ title: 'Lock', steps: C.restored ? null : step(3), back: false,
      body: [el('div', { className: 'lockicon' }, icon('finger')), el('h2', { className: 'big center', textContent: 'Lock sigelo with your fingerprint or PIN' }),
        el('p', { className: 'lead center', textContent: 'Asked only when you open the app, switch profile, pay above your limit or show your 25 words.' })], primary: use });
    use.onclick = busy(use, s, async () => { await api.lock(); go(newDone, { replace: true }); });
  }
  function newDone() {
    const finish = async () => { door = false; await api.done?.(C.made?.message); };
    const words = String(C.made?.words ?? '').split(/\s+/).filter(Boolean).slice(0, 4);
    screen({ title: C.restored ? 'Restored' : 'You\'re set', hero: true, back: false, close: () => void finish(),
      body: [el('div', { className: 'center' }, el('div', { className: 'lockicon' }, icon('check')), el('h2', { className: 'big', textContent: C.restored ? 'Your identity is back' : 'You\'re set' }),
        words.length ? [el('p', { className: 'lead', textContent: 'Your four words' }), el('div', { className: 'words4', attrs: { 'aria-label': `Four words: ${words.join(' ')}` } }, words.map((w) => el('span', { textContent: w })))] : null,
        el('p', { className: 'lead', textContent: 'They are your identity\'s fingerprint. They never change, and people you pair with see them.' }))],
      primary: button('Open sigelo', () => void finish(), true) });
  }

  // ---- restore: one screen (the words, when they were made, main or spare), then Restoring, the lock, done
  const R = { words: '', month: '', height: '', net: 'mainnet', name: 'phone', elsewhere: false, relay: DEFAULT_RELAY };
  function restoreWords() {
    secure(true);
    const words = el('textarea', { rows: 6, value: R.words, attrs: { ...WORDS_ATTRS, 'aria-describedby': 'seed-count' } });
    const count = el('p', { className: 'help', id: 'seed-count', textContent: '0 of 25 words' });
    const month = el('input', { type: 'month', value: R.month, attrs: { autocomplete: 'off' } });
    const height = text({ value: R.height, placeholder: '3100000', attrs: { inputmode: 'numeric' } });
    const net = netSelect(R.net), name = text({ value: R.name, attrs: { maxlength: '20' } }), relay = text({ value: R.relay });
    const seat = radios('seed-seat', [['here', 'No, make this phone the main one'], ['elsewhere', 'Yes, keep this phone as a spare']], R.elsewhere ? 'elsewhere' : 'here');
    const start = button('Restore', null, true);
    const live = () => {
      const c = api.checkWords(words.value);
      count.textContent = c.error ? `${c.count} of 25: ${c.error}` : c.ok ? '25 words, checked' : `${c.count} of 25 words`;
      count.className = `help ${c.error ? 'warn' : c.ok ? 'good' : ''}`.trim();
      start.disabled = !c.ok;
      return c.ok;
    };
    words.addEventListener('input', live);
    words.addEventListener('paste', () => setTimeout(() => { quiet(api.clipClear); live(); }, 0));
    leave = () => { R.words = ''; words.value = ''; secure(false); };   // Back to the welcome: the words dropped
    const s = screen({ title: 'Restore',
      body: [el('div', { className: 'field' }, el('label', { textContent: 'Your 25 words, in order', htmlFor: 'seed-words', attrs: { for: 'seed-words' } }), Object.assign(words, { id: 'seed-words' }), count),
        field('When were they made? (optional)', month, 'Makes the wallet ready faster. Empty: it reads from the start.'),
        el('p', { className: 'flabel', textContent: 'Is this identity already in use on another device?' }), seat.node,
        el('p', { className: 'help', textContent: 'Your identity acts from one device at a time. You can make the spare the main one later.' }),
        fold('More options', field('Monero network', net), field('Or the block height it started', height, 'Digits; it wins over the month.'), field('Name this phone', name, NAME_RULE), field('Relay', relay))],
      primary: start });
    live();
    words.focus?.();
    start.onclick = busy(start, s, async () => {
      if (!live()) throw new Error('Type all 25 words first.');
      const m = month.value.trim(), hgt = height.value.trim(), n = name.value.trim();
      if (m !== '' && !monthOk(m)) throw new Error('A month as YYYY-MM, or empty.');
      if (hgt !== '' && !/^\d{1,10}$/.test(hgt)) throw new Error('A block height is digits only, or empty.');
      if (!NAME.test(n)) throw new Error(`Name: ${NAME_RULE}`);
      Object.assign(R, { words: words.value, month: m, height: hgt, net: net.value === 'stagenet' ? 'stagenet' : 'mainnet', name: n, elsewhere: seat.value() === 'elsewhere', relay: relay.value.trim().toLowerCase() || DEFAULT_RELAY });
      words.value = ''; leave = null;
      const when = hgt || (m ? `${m}-01` : '');
      settingUp('Restoring your identity');
      let r;
      try { r = await api.restore({ words: R.words, name: R.name, height: when, net: R.net, elsewhere: R.elsewhere, relay: R.relay }); } catch (e) {
        current = restoreWords; restoreWords().say(`Not restored: ${e?.message ?? e}`);
        return;
      }
      R.words = ''; secure(false);
      C.made = r; C.restored = true;
      afterMade();
    });
    return s;
  }

  // ---- connect: this phone controls an agent on another machine
  function connectCode() {
    const code = el('input', { className: 'code-in', placeholder: 'K7F3-Q9ZP', attrs: { autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', maxlength: '9' } });
    const relay = text({ placeholder: DEFAULT_RELAY });
    const pasted = el('textarea', { rows: 2, attrs: { autocomplete: 'off', spellcheck: 'false' } });
    const next = button('Connect', null), scanBox = el('div');
    code.addEventListener('input', () => {
      const v = code.value.toUpperCase().replace(/[^0-9A-Z]/g, '').slice(0, 8);
      code.value = v.length > 4 ? `${v.slice(0, 4)}-${v.slice(4)}` : v;
    });
    const scan = api.scan ? button('Scan the computer\'s QR', () => { scanBox.replaceChildren(api.scan((t) => { pasted.value = t; void next.onclick(); })); }, true, 'scan') : null;
    const s = screen({ title: 'Use my computer', lead: 'Your identity stays on your computer. This phone becomes its remote: it holds no key of yours.',
      body: [el('p', { className: 'help', textContent: 'On the computer, run sigelo-agent ui --remote --relay. It shows a QR and a code.' }), scan ? el('div', { className: 'bar' }, scan) : null, scanBox,
        field('Or type its code', code), fold('Advanced', field('Its relay, if not the default', relay), field('Or paste its SIGELO:UI: text (same network) or SIGELO:CTL: text', pasted))],
      primary: next, secondary: api.cancel ? button(api.cancel.label, () => api.cancel.run()) : undefined });
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
    const open = button('They match', null, true);
    const w = String(words ?? '').split(/\s+/).filter(Boolean);
    const s = screen({ title: 'Compare four words', lead: 'The computer shows four words too. Same words: it\'s really yours. Answer yes there, then here.',
      body: [el('div', { className: 'card center' }, w.length ? el('div', { className: 'words4', attrs: { 'aria-label': `Four words: ${w.join(' ')}` } }, w.map((x) => el('span', { textContent: x }))) : el('p', { textContent: '(none)' })),
        el('p', { className: 'help', textContent: 'Different words? Someone else used the code. Choose "They don\'t match", answer no on the computer, and make a new code there.' })],
      primary: open, secondary: button('They don\'t match', () => { history.back(); }) });
    open.onclick = busy(open, s, async () => { await api.open(); });
  }

  // ---- the work after the last decision (the mock's restore-busy)
  function settingUp(what) {
    screen({ title: what, hero: true, back: false,
      body: [el('div', { className: 'center' }, el('h2', { className: 'big', textContent: what }), el('div', { className: 'progress indeterminate', attrs: { role: 'progressbar', 'aria-label': what } }, el('div')),
        el('p', { className: 'lead', textContent: 'About 1 minute. The network stays off until it\'s done. Keep the app open.' }))] });
  }

  current = welcome;
  if (show) welcome();
  return {
    welcome: home, screen, go, button,
    /** The connect screens alone, as the first screen (a remote profile adding a computer: design/profiles.md P2). */
    connect() { stack.length = 0; current = connectCode; door = false; connectCode(); },
    /** One of the Add sheet's ways as the first step, the welcome behind it (Back): create, join, restore, computer. */
    start(path) { const f = { create: createName, join: joinCode, restore: restoreWords, computer: connectCode }[path]; if (f) go(f); },
    stop() { removeEventListener('popstate', onPop); if (C.words) quiet(api.discard); C.words = null; R.words = ''; secure(false); },
  };
}

// ---- profiles (design/profiles.md §3): the picker at a start with more than one
export const KIND_LABEL = Object.freeze({ words: 'Your identity', remote: 'A computer\'s page' });
/** A profile's second line: its four words (or not set up yet), what it holds. */
export const profileSub = (p) => [p.words ?? (p.kind ? null : 'Not set up yet'), KIND_LABEL[p.kind] ?? null].filter(Boolean).join(' · ');
/**
 * The picker: the seal, a row per profile (name, four words, what it holds; the last used marked), one tap
 * → resolves with its id. o: { profiles: [{id, name, kind, words}], active, seal }.
 */
export function pickProfile(box, { profiles, active, seal = 'icon.svg' }) {
  return new Promise((resolve) => {
    const rows = profiles.map((p) => el('button', { className: `row${p.id === active ? ' current' : ''}`, onclick: () => resolve(p.id), attrs: { 'data-profile': p.id } },
      el('span', { className: 'main' }, el('div', { className: 'name', textContent: p.name }), el('div', { className: 'sub', textContent: profileSub(p) }),
        p.id === active ? el('div', { className: 'sub', textContent: 'Last used' }) : null)));
    box.replaceChildren(el('div', { className: 'welcome' }, el('header', {}, el('img', { className: 'seal small', src: seal, alt: '' }), el('h1', { textContent: 'Profiles' })),
      el('p', { className: 'muted', textContent: 'Which one?' }), el('div', { className: 'list' }, rows)));
    box.hidden = false;
    globalThis.scrollTo?.(0, 0);
  });
}
