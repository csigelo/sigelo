// SPDX-License-Identifier: MIT
// The page of `sigelo-agent ui` and of the apps (sigelo-agent-ui.ts; API: UI-API.md). Plain browser JS, one
// classic script, no framework, no build step. Its look and its words are design/ux1/mock.html; how it is built
// (screens, sheets, the shared pieces, how the tests fake the API) is design/ux1/build.md.
// Every string from a contact, a relay or a file goes in by textContent, its controls and bidi overrides escaped
// (safeText), never as HTML. The token comes in the fragment and goes back as X-Sigelo-Token; no cookie; the
// token in this tab's sessionStorage (it survives a reload); localStorage only for this device's look and a mirror
// of each profile's Wallet switch for the Profiles sheet (prefs; the switch itself is in GET /api/settings).
// The seam: every call goes through backend.call(method, path, body) → the UI-API.md answer, or throws
// {message, check, long, status}. `http`: fetch to this server with the token. `shell`: the page served by the
// GTK phone app (apps/gtk, sigelo-app:), which seals each call to a computer's `ui --remote` (sigelo-remote/0)
// and answers {status, body}; the page never sees the control's key. `local`: the self-contained app
// (apps/web): an in-page router over a carrier running in the page (globalThis.sigeloLocal), the same routes
// and JSON, its changes pushed (onChange).
'use strict';
(() => {
  // The version: apps/agent/package.json, the one source a release bumps, beside this script wherever it is served (the
  // `ui` server's /package.json, apps/web/vendor/package.json in the phone apps, the GTK app's web/package.json). No hand edit.
  const ME_URL = (() => { try { return document.currentScript?.src || location.href; } catch { return ''; } })();
  let VERSION = '';
  const versionNow = async () => {
    if (VERSION || typeof fetch !== 'function') return VERSION;
    try { const r = await fetch(new URL('package.json', ME_URL).href, { cache: 'no-store', credentials: 'omit' }); const v = (await r.json())?.version; if (r.ok && /^\d+\.\d+\.\d+$/.test(v ?? '')) VERSION = v; } catch {}
    return VERSION;
  };
  const versionLine = () => (VERSION ? `Version ${VERSION}` : 'Version');
  const TOKEN = (() => {
    const m = /[#&]t=([0-9a-f]{32})\b/.exec(location.hash);
    if (m) { sessionStorage.setItem('sigelo-t', m[1]); history.replaceState(null, '', location.pathname); return m[1]; }
    return sessionStorage.getItem('sigelo-t');
  })();
  const app = document.getElementById('app');
  const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
  const safeText = (s) => String(s ?? '').replace(UNSAFE, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));

  // ================================================================ CORE: elements, icons, the backend
  /** h('tag', {class, onclick, disabled, …}, ...children): strings become escaped text nodes. */
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props ?? {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'value') el.value = String(v);
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k in el && typeof v !== 'string') el[k] = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of kids.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(safeText(c)));
    }
    return el;
  }
  /**
   * el's children replaced: lists flattened, strings as escaped text, empties dropped. A screen is drawn
   * again at every poll, its fields reused; the child of el that holds the focus (a field being typed
   * in, or a card around it) is never taken out, only the others around it: a field taken out of the
   * page loses the focus, and a phone's keyboard closes with it. → el.
   */
  const put = (el, ...kids) => {
    const nodes = kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false && k !== '')
      .map((k) => (k instanceof Node ? k : document.createTextNode(safeText(k))));
    const f = document.activeElement;
    const keep = f && f !== el && el.contains?.(f) ? nodes.find((n) => n.parentNode === el && (n === f || n.contains?.(f))) : undefined;
    if (!keep) { el.replaceChildren(...nodes); return el; }
    for (const c of [...el.childNodes]) if (c !== keep) c.remove();
    const i = nodes.indexOf(keep);
    keep.before(...nodes.slice(0, i));
    keep.after(...nodes.slice(i + 1));
    return el;
  };
  // The mock's icons (24 × 24, stroked): a path's d, or [tag, attributes].
  const ICONS = {
    back: ['M15 5l-7 7 7 7'], chev: ['M9 5l7 7-7 7'], down: ['M6 9l6 6 6-6'], chat: ['M4 5h16v11H9l-5 4z'],
    agent: [['rect', { x: 5, y: 8, width: 14, height: 11, rx: 3 }], 'M12 4v4M9 13h.01M15 13h.01M9.5 16h5'],
    wallet: [['rect', { x: 3, y: 6, width: 18, height: 13, rx: 2 }], 'M3 10h18M16 14.5h2'],
    me: [['circle', { cx: 12, cy: 8, r: 4 }], 'M4 20c1.5-4 4.5-6 8-6s6.5 2 8 6'], plus: ['M12 5v14M5 12h14'],
    qr: [['rect', { x: 4, y: 4, width: 6, height: 6 }], ['rect', { x: 14, y: 4, width: 6, height: 6 }], ['rect', { x: 4, y: 14, width: 6, height: 6 }], 'M14 14h2v2M18 14h2M14 18h2M18 18h2v2'],
    scan: ['M4 8V4h4M16 4h4v4M20 16v4h-4M8 20H4v-4M4 12h16'], info: [['circle', { cx: 12, cy: 12, r: 9 }], 'M12 11v5M12 8h.01'],
    send: ['M4 12l16-8-6 16-2-7z'], coin: [['circle', { cx: 12, cy: 12, r: 9 }], 'M8 15V9l4 4 4-4v6'],
    lock: [['rect', { x: 5, y: 11, width: 14, height: 9, rx: 2 }], 'M8 11V8a4 4 0 018 0v3'], check: ['M5 12l5 5 9-10'], x: ['M6 6l12 12M18 6L6 18'],
    shield: ['M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z', 'M9 12l2 2 4-4'],
    people: [['circle', { cx: 9, cy: 8, r: 3 }], ['circle', { cx: 17, cy: 9, r: 2.5 }], 'M3 19c1-3 3.5-5 6-5s5 2 6 5M15 14.5c2.5 0 4.5 1.5 5.5 4'],
    device: [['rect', { x: 3, y: 5, width: 18, height: 11, rx: 1.5 }], 'M8 20h8M12 16v4'],
    link: ['M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1'],
    clock: [['circle', { cx: 12, cy: 12, r: 9 }], 'M12 7v5l3 2'], pen: ['M4 20l4-1 11-11-3-3L5 16z'],
    gear: [['circle', { cx: 12, cy: 12, r: 3 }], 'M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1'],
    file: ['M6 3h8l4 4v14H6z', 'M14 3v4h4'], 'arrow-in': ['M12 4v12M6 11l6 6 6-6M5 20h14'], 'arrow-out': ['M12 20V8M6 13l6-6 6 6M5 4h14'],
    finger: ['M12 11v4M8.5 9a4 4 0 017 0v6M6 8.5a7 7 0 0112 0v5M9 13v3a3 3 0 006 0'],
  };
  const SVG = 'http://www.w3.org/2000/svg';
  /** An icon as inline SVG (aria-hidden: the control around it carries the label); null where there is no SVG. */
  function icon(name) {
    if (!document.createElementNS || !ICONS[name]) return null;
    const s = document.createElementNS(SVG, 'svg');
    for (const [k, v] of [['class', 'ic'], ['viewBox', '0 0 24 24'], ['aria-hidden', 'true'], ['focusable', 'false']]) s.setAttribute(k, v);
    for (const part of ICONS[name]) {
      const [tag, attrs] = typeof part === 'string' ? ['path', { d: part }] : part, e = document.createElementNS(SVG, tag);
      for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
      s.append(e);
    }
    return s;
  }

  const http = {
    async call(method, path, body) {
      const r = await fetch(path, {
        method, credentials: 'omit', cache: 'no-store',
        headers: { 'X-Sigelo-Token': TOKEN ?? '', ...(method === 'POST' && { 'Content-Type': 'application/json' }) },
        ...(method === 'POST' && { body: JSON.stringify(body ?? {}) }),
      });
      let data = null;
      try { data = await r.json(); } catch {}
      if (!r.ok) throw Object.assign(new Error(data?.error?.message ?? `HTTP ${r.status}`), { check: data?.error?.check, long: data?.error?.long, status: r.status });
      return data;
    },
  };
  const SHELL = location.protocol === 'sigelo-app:' ? globalThis.webkit?.messageHandlers?.sigelo : undefined;
  const shell = {
    async call(method, path, body) {
      const r = await SHELL.postMessage({ op: 'call', method, path, ...(body !== undefined && { body }) });
      if (r.status >= 200 && r.status < 300) return r.body;
      const e = r.body?.error;
      throw Object.assign(new Error(e?.message ?? `HTTP ${r.status}`), { check: e?.check, long: e?.long, status: r.status });
    },
    mode: () => ({ kind: 'remote' }),
  };
  const LOCAL = SHELL ? undefined : globalThis.sigeloLocal;
  const local = {
    async call(method, path, body) {
      const r = await LOCAL.call(method, path, body);
      if (r.status >= 200 && r.status < 300) return r.body;
      const e = r.body?.error;
      throw Object.assign(new Error(e?.message ?? `HTTP ${r.status}`), { check: e?.check, long: e?.long, status: r.status });
    },
    mode: () => LOCAL.mode(),
  };
  const backend = SHELL ? shell : LOCAL ? local : http;
  const lazy = (path) => { let m; return async () => { if (m === undefined) { try { m = await import(path); } catch { m = null; } } return m; }; };
  const qrLib = lazy('/qr.mjs'), qrDec = lazy('/qr-decode.mjs');
  const qrCache = new Map();
  /** A QR symbol of text on a canvas (level M, a quiet zone of 4), or null without qr.mjs. */
  async function qrCanvas(text, max = 280) {
    const key = `${max} ${text}`;
    if (qrCache.has(key)) return qrCache.get(key);
    const lib = await qrLib();
    if (!lib) return null;
    const m = lib.encode(text, { ecc: 'M', maxVersion: 20 }), q = 4, n = m.size + 2 * q, k = Math.max(3, Math.floor(Math.min(max, (window.innerWidth ?? 400) - 32) / n));
    const cv = h('canvas', { class: 'qr', width: n * k, height: n * k, role: 'img', 'aria-label': 'QR code' }), g = cv.getContext('2d');
    if (!g) return null;
    g.fillStyle = '#fff'; g.fillRect(0, 0, n * k, n * k); g.fillStyle = '#000';
    m.modules.forEach((row, y) => row.forEach((dark, x) => { if (dark) g.fillRect((x + q) * k, (y + q) * k, k, k); }));
    if (qrCache.size > 32) qrCache.clear();
    qrCache.set(key, cv);
    return cv;
  }
  /** A QR box: the canvas drawn when qr.mjs loads, else nothing (the code beside it is the fallback). */
  function qrBox(text) {
    const box = h('div', { class: 'center' });
    qrCanvas(text).then((cv) => { if (cv) put(box, cv); }, () => {});
    return box;
  }

  // ================================================================ STATE and small helpers
  const S = { snap: null, me: null, prof: null, profiles: null, stack: [{ view: 'chats' }], view: null, update: () => {}, note: null, fatal: null,
    sheet: null, workers: null, groups: null, groupsRev: null, made: null, controls: null, msgsSeq: -1 };
  /** This device's settings (look; a mirror of each profile's Wallet switch): localStorage when the page has it, else nothing kept. */
  const prefs = {
    get(k) { try { return globalThis.localStorage?.getItem(`sigelo-ui:${k}`) ?? null; } catch { return null; } },
    set(k, v) { try { if (v === null) globalThis.localStorage?.removeItem(`sigelo-ui:${k}`); else globalThis.localStorage?.setItem(`sigelo-ui:${k}`, v); } catch {} },
  };
  const relayNow = () => Date.now() / 1000 + (S.snap?.me?.clock_offset ?? 0);
  const left = (exp) => {
    const s = Math.max(0, Math.round(exp - relayNow()));
    return s >= 3600 ? `${Math.floor(s / 3600)} h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')} min` : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
  };
  const countdown = (exp) => h('b', { class: 'countdown', 'data-exp': String(exp) }, left(exp));
  // A code's time left in words ("8 minutes left"), an end in days ("in 7 days"): the mock's Requests.
  const minutesLeft = (exp) => { const m = Math.max(0, Math.ceil((exp - relayNow()) / 60)); return m <= 1 ? 'Under a minute left' : `${m} minutes left`; };
  const inDays = (exp) => { const d = Math.round((exp - relayNow()) / 86400); return d <= 0 ? 'today' : d === 1 ? 'tomorrow' : `in ${d} days`; };
  const hhmm = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const day = (t) => new Date(t * 1000).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
  const when = (t) => (new Date().toDateString() === new Date(t * 1000).toDateString() ? hhmm(t) : new Date(t * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }));
  /** A list's time column: 18:42 today, Mon this week, else 2 Nov. */
  const short = (t) => {
    if (!t) return '';
    const d = new Date(t * 1000), now = new Date();
    if (d.toDateString() === now.toDateString()) return hhmm(t);
    if (now - d < 6 * 86400000) return d.toLocaleDateString([], { weekday: 'short' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  };
  const dayLabel = (t) => {
    const d = new Date(t * 1000), now = new Date(), y = new Date(now - 86400000);
    return d.toDateString() === now.toDateString() ? 'Today' : d.toDateString() === y.toDateString() ? 'Yesterday' : d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
  };
  const ago = (t) => {
    const s = Math.max(0, Math.round(relayNow() - t));
    return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`;
  };
  // Presence (UI-API.md): online, or "last seen 5 min ago" once the relay said offline; nothing when not known.
  const presenceText = (x) => (x.online === true ? 'online' : x.online === false && x.last_seen ? `last seen ${ago(x.last_seen)}` : '');
  const allContacts = () => (S.snap ? [...S.snap.groups.mine, ...S.snap.groups.contacts] : []);
  const contactBy = (did) => allContacts().find((c) => c.did === did) ?? null;
  const workerOf = (did) => S.workers?.workers?.find((w) => w.contact === did && w.status !== 'revoked') ?? null;
  /** A contact's kind for its mark: the API's (UI-API.md "Kinds": derived, or the human's choice), else mine are agents. */
  const kindOf = (c) => (c.kind === 'agent' || c.kind === 'person' ? c.kind : c.ours || c.local || workerOf(c.did) ? 'agent' : 'person');
  const unreadOf = (c) => (c.tier === 'quiet' ? 0 : c.unread);
  // A chat's notifications off (POST /api/notify): its count stays in the list, grey, and leaves the tab's.
  const muted = (x) => x?.notify === false;
  const countBadge = (n, x) => (n ? h('span', { class: `count${muted(x) ? ' muted' : ''}`, 'aria-label': `${n} unread` }, String(n)) : null);
  /** The Chats tab's count (the page's own notification): unread in chats whose notifications are on, and the requests to answer. */
  function chatsUnread() {
    if (!S.snap) return 0;
    const people = allContacts().filter((c) => !muted(c)).reduce((a, c) => a + (unreadOf(c) || 0), 0);
    const groups = S.groups ? S.groups.groups.filter((g) => liveGroup(g) && !muted(g)).reduce((a, g) => a + (g.unread || 0), 0) : S.snap.chats?.unread ?? 0;
    return people + groups + requestCount().answer;
  }
  const words4 = (w) => (Array.isArray(w) ? w : String(w ?? '').split(/\s+/)).filter(Boolean).slice(0, 4);
  const plain = (e) => {
    const m = String(e?.message ?? e ?? '');
    return /^HTTP \d+$/.test(m) || !m ? 'Something went wrong. Try again.' : m;
  };
  /** A call the human started that may spend a proof-of-work search: past the day's three the backend asks (409 pow_confirm); yes goes on with pow_confirmed. */
  async function started(method, path, body = {}) {
    try { return await backend.call(method, path, body); } catch (e) {
      if (e?.check !== 'pow_confirm') throw e;
      if (!(await ask({ title: 'Go on?', text: String(e.message).replace(/^pow_confirm: /, ''), yes: 'Go on', danger: false }))) throw e;
      return backend.call(method, path, { ...body, pow_confirmed: true });
    }
  }
  /** fn, its refusal kept in S.note (shown by the screen), then the state again. */
  async function act(fn, after) {
    try { S.note = null; const r = await fn(); if (after) await after(r); } catch (e) { S.note = e; }
    await poll();
  }
  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); toast('Copied'); } catch { window.prompt?.('Copy this:', text); }
    void btn;
  }
  /** A ready-to-send message: the shell's share sheet (Android), the page's (navigator.share), else the clipboard. */
  async function share(text) {
    for (const via of [LOCAL?.share, navigator.share && ((t) => navigator.share({ text: t }))]) {
      if (!via) continue;
      try { await via(text); return; } catch (e) { if (e?.name === 'AbortError') return; }
    }
    try { await navigator.clipboard.writeText(text); toast('Message copied: paste it into any chat or mail.'); } catch { window.prompt?.('Copy this message:', text); }
  }
  const PAIR_HOW = 'https://sigelo.io/pair.html', ENROL_HOW = 'https://sigelo.io/enrol.html';
  const pairMessage = (code, exp) => `Pair with me on sigelo: code ${code}, once, until ${hhmm(exp)}. How: ${PAIR_HOW}`;
  const enrolMessage = (code, exp, command) => `Enrol as my agent on sigelo: code ${code}, once, until ${hhmm(exp)}. On the agent's machine: ${command}  How: ${ENROL_HOW}`;

  // ================================================================ SHARED PIECES (design/ux1/build.md lists them)
  /** A button: kind '' (secondary), 'pri', 'danger' or 'ghost'; an icon before the label. */
  const btn = (label, onclick, { kind = '', ic, disabled, auto, label: aria } = {}) =>
    h('button', { type: 'button', class: `btn${kind ? ' ' + kind : ''}${auto ? ' auto' : ''}`, onclick, disabled, 'aria-label': aria }, ic ? icon(ic) : null, label);
  /** A 44 px icon button: its label is said, not shown. */
  const ibtn = (ic, label, onclick, cls = '') => h('button', { type: 'button', class: `ib${cls ? ' ' + cls : ''}`, 'aria-label': label, title: label, onclick }, icon(ic));
  /** A text button (the link colour), for a top bar or a row's end. */
  const tbtn = (label, onclick) => h('button', { type: 'button', class: 'tb', onclick }, label);
  /** A list row: [start] title / sub [end]; a button when it has onclick, else a div. */
  function row({ start, title, sub, subCls, end, onclick, chev, compact, cls = '', attrs = {} }) {
    const kids = [start ?? null, h('span', { class: 'mid' }, h('b', null, title), sub ? h('small', { class: subCls ?? null }, sub) : null),
      end !== undefined && end !== null ? h('span', { class: 'end' }, end) : null, chev ? icon('chev') : null];
    return h(onclick ? 'button' : 'div', { type: onclick ? 'button' : null, class: `row${compact ? ' compact' : ''}${cls ? ' ' + cls : ''}`, onclick, ...attrs }, kids);
  }
  /** A bordered inset list of rows (nothing when empty). */
  const list = (...rows) => { const r = rows.flat(Infinity).filter(Boolean); return r.length ? h('div', { class: 'list' }, r) : null; };
  /** A section header above a list. */
  const sec = (text) => h('p', { class: 'sec' }, text);
  let fid = 0;
  /** A labelled control: the label tied to it by id, a help line under it. */
  function field(label, control, help) {
    if (!control.id) control.id = `f${++fid}`;
    return h('div', { class: 'field' }, h('label', { for: control.id }, label), control, help ? h('p', { class: 'help' }, help) : null);
  }
  const input = (attrs = {}) => h('input', { autocomplete: 'off', spellcheck: 'false', ...attrs });
  /** A row with a switch: the label is the row's text; onchange(checked). */
  function toggle(title, sub, checked, onchange, { disabled } = {}) {
    const box = h('input', { type: 'checkbox', role: 'switch', checked: !!checked, disabled, 'aria-label': title });
    box.addEventListener('change', () => onchange(box.checked, box));
    return h('label', { class: 'row' }, h('span', { class: 'mid' }, h('b', null, title), sub ? h('small', { class: 'wrap' }, sub) : null), h('span', { class: 'switch' }, box, h('span')));
  }
  /** One choice of several as radio rows: [[value, title, sub?]]; onchange(value). */
  function radios(name, options, value, onchange) {
    return h('div', { class: 'list', role: 'radiogroup', 'aria-label': name }, options.map(([v, title, sub]) => {
      const r = h('input', { type: 'radio', name, value: v, checked: v === value, 'aria-label': title });
      r.addEventListener('change', () => { if (r.checked) onchange(v); });
      return h('label', { class: 'row compact' }, r, h('span', { class: 'mid' }, h('b', null, title), sub ? h('small', { class: 'wrap' }, sub) : null));
    }));
  }
  /** An empty state: a title, one sentence, one verb (a second at most). */
  const empty = (title, text, ...actions) => h('div', { class: 'empty' }, h('h3', null, title), text ? h('p', null, text) : null, actions);
  /** A screen or part a later pass of UX1 fills (design/ux1/build.md "Placeholders"): said plainly, marked in the code. */
  const later = (title, text) => h('div', { class: 'empty todo', 'data-later': title }, h('h3', null, title), h('p', null, text ?? 'Not in this version yet.'));
  /** An error said in place, in plain words. */
  const inlineError = (e) => (e ? h('p', { class: 'err', role: 'alert' }, plain(e)) : null);
  // The last refusal, unless the seat banner already says it.
  const noteCard = () => (S.note && S.note.check !== 'seat_elsewhere' ? h('div', { class: 'card warn' }, inlineError(S.note)) : null);
  /** The four words: large chips (a check), or one line "a · b · c · d" (a label). */
  const fourWords = (w) => h('div', { class: 'words4', 'aria-label': `Four words: ${words4(w).join(' ')}` }, words4(w).map((x) => h('span', null, x)));
  const wordsLine = (w) => words4(w).join(' · ');
  /**
   * An avatar: people round with their initial, agents square, groups ringed; size 'lg' for a page's head. pic: whose picture
   * ('me', a contact's DID, a group's gid): shown when it has one (UI-API.md "Pictures"), else the initial or the mark.
   */
  function avatar(kind, name, size, pic) {
    const cls = `av${kind === 'agent' ? ' ag' : kind === 'group' ? ' grp' : ''}${size ? ' ' + size : ''}`, url = pic ? picUrl(pic) : null;
    if (url) return h('span', { class: `${cls} pic`, 'aria-hidden': 'true' }, h('img', { src: url, alt: '', decoding: 'async' }));
    if (kind === 'agent') return h('span', { class: cls, 'aria-hidden': 'true' }, icon('agent'));
    if (kind === 'group') return h('span', { class: cls, 'aria-hidden': 'true' }, icon('people'));
    const first = [...String(name ?? '').trim()][0];
    return h('span', { class: cls, 'aria-hidden': 'true' }, first ? first.toUpperCase() : '?');
  }
  // Pictures (UI-API.md "Pictures"): the state names each one's rev (me.picture, a contact's picture, a group's); the bytes come
  // once per rev (GET /api/picture) and are shown as a blob: URL. A page without Blob or URL.createObjectURL shows initials.
  const PICS = new Map();   // whose → { rev, url, busy }
  const picRevOf = (whose) => (whose === 'me' ? S.snap?.me?.picture : contactBy(whose)?.picture ?? groupBy(whose)?.picture) ?? null;
  function picUrl(whose) {
    const rev = picRevOf(whose), had = PICS.get(whose);
    if (!rev) { if (had?.url) { try { URL.revokeObjectURL?.(had.url); } catch {} PICS.delete(whose); } return null; }
    if (had?.rev === rev) return had.url;
    if (had?.busy === rev || typeof Blob !== 'function' || typeof URL?.createObjectURL !== 'function') return had?.url ?? null;
    PICS.set(whose, { ...(had ?? {}), busy: rev });
    void backend.call('GET', `/api/picture?of=${encodeURIComponent(whose)}`).then((r) => {
      const url = URL.createObjectURL(new Blob([unb64(r.data)], { type: r.type }));
      if (had?.url) { try { URL.revokeObjectURL(had.url); } catch {} }
      PICS.set(whose, { rev, url });   // the state's rev: one fetch per rev, whatever the answer names
      return refresh();
    }, () => { PICS.set(whose, { rev, url: null }); });
    return had?.url ?? null;
  }
  const unb64 = (t) => Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
  const b64 = (bytes) => { let t = ''; for (let i = 0; i < bytes.length; i += 0x8000) t += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(t); };
  const PIC_MAX = 64 * 1024, PIC_SIDE = 256;
  /** An image (a file, a camera frame) as a picture: the middle square, at most 256 px, WebP or JPEG of at most 64 KB. */
  async function shrinkPicture(src) {
    const bm = await createImageBitmap(src);
    const side = Math.min(bm.width, bm.height), out = Math.min(PIC_SIDE, side);
    const cv = h('canvas', { width: out, height: out }), g = cv.getContext?.('2d');
    if (!g || !side) { bm.close?.(); throw new Error('This page can\'t read pictures.'); }
    g.drawImage(bm, (bm.width - side) / 2, (bm.height - side) / 2, side, side, 0, 0, out, out);
    bm.close?.();
    for (const [type, q] of [['image/webp', 0.85], ['image/webp', 0.7], ['image/jpeg', 0.85], ['image/jpeg', 0.7], ['image/jpeg', 0.5], ['image/jpeg', 0.35]]) {
      const b = await new Promise((r) => cv.toBlob(r, type, q));
      if (b && b.type === type && b.size <= PIC_MAX) return { type, data: b64(new Uint8Array(await b.arrayBuffer())) };
    }
    throw new Error('This picture stays too large: try another one.');
  }
  /**
   * The picture sheet: of 'me' (yours, sent end to end to the people you chat with) or a contact's DID or a group's gid (a
   * local one, on this device only). Take a picture (the camera, where there is one), choose one (a file: the gallery on a
   * phone), remove it.
   */
  function pictureSheet(of, name) {
    const mine = of === 'me', c = mine ? null : contactBy(of), local = mine ? Boolean(S.snap?.me?.picture) : c ? c.picture_local === true : Boolean(groupBy(of)?.picture);
    const say = h('div'), pick = h('input', { type: 'file', accept: 'image/*', hidden: true, 'aria-label': 'A picture' }), cam = h('div');
    let stream = null;
    const stop = () => { stream?.getTracks().forEach((t) => t.stop()); stream = null; };
    const save = async (body, done) => {
      put(say, h('p', { class: 'help', role: 'status' }, 'Saving…'));
      try { await backend.call('POST', '/api/picture', { of, ...body }); stop(); await closeSheet(); toast(done); await poll(); } catch (e) { put(say, inlineError(e)); }
    };
    const use = async (src) => { let p; try { p = await shrinkPicture(src); } catch (e) { put(say, inlineError(e.message ? e : { message: 'Not a picture this page can read.' })); return; } await save(p, mine ? 'Your picture is set.' : `Picture set for ${name}.`); };
    pick.addEventListener('change', () => { const f = pick.files?.[0]; pick.value = ''; if (f) void use(f); });
    const camera = async () => {
      let video;
      try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' }, audio: false }); } catch (e) { put(say, inlineError({ message: `No camera here (${e?.name ?? 'refused'}): choose a picture instead.` })); return; }
      video = h('video', { class: 'scan', muted: true, playsInline: true, 'aria-label': 'Camera' });
      video.srcObject = stream;
      put(cam, video, h('div', { class: 'btns' }, btn('Take it', () => use(video), { kind: 'pri' }), btn('Cancel', () => { stop(); put(cam); })));
      await video.play?.().catch(() => {});
    };
    const hasCam = Boolean(navigator.mediaDevices?.getUserMedia);
    sheet({ title: mine ? 'Your picture' : `Picture for ${name}`, onClose: stop,
      lead: mine ? 'Only the people you chat with see it: it goes to them end to end, never to the relay in the clear.' : 'On this device only. Theirs, if they sent one, shows again when you remove this one.',
      body: [cam, list(hasCam ? row({ compact: true, start: icon('scan'), title: 'Take a picture', onclick: camera }) : null,
        row({ compact: true, start: icon('file'), title: 'Choose a picture', sub: 'From your gallery or files', onclick: () => pick.click() }),
        local ? row({ compact: true, start: icon('x'), title: mine ? 'Remove my picture' : c ? 'Remove this picture' : 'Remove the picture', sub: mine ? 'Your initial shows again' : c ? 'Theirs or the initial shows again' : 'The mark shows again',
          onclick: () => save({ remove: true }, 'Picture removed.') }) : null), pick, say] });
  }
  /** An avatar that opens the picture sheet (a page's head): its label says what it does. */
  const picButton = (kind, name, of, label) => h('button', { type: 'button', class: 'avbtn', 'aria-label': label, title: label, onclick: () => pictureSheet(of, name) }, avatar(kind, name, 'lg', of));

  /** A sent message's ticks (Telegram's): ✓ at the relay, ✓✓ seen (their seen receipt, UI-API.md); waiting or refused said in words. */
  function ticks(m) {
    if (m.dir !== 'out') return null;
    if (m.status === 'seen') return h('span', { class: 'seen', 'aria-label': 'Seen', title: 'Seen' }, ' ✓✓');
    if (m.status === 'sent') return h('span', { 'aria-label': 'Delivered to the relay', title: 'Delivered to the relay' }, ' ✓');
    if (m.status === 'queued') return h('span', null, m.code === 'no_reader' ? ' · not collected yet' : ' · waiting to send');
    if (m.status === 'refused') return h('span', { class: 'warn' }, ` · not sent: ${m.code ?? 'refused'}`);
    return null;
  }
  // Toasts: one live region (polite), each message for 3 s.
  const toasts = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
  document.body?.append?.(toasts);
  const toast = (t) => { const x = h('div', { class: 'toast' }, t); toasts.append(x); setTimeout(() => x.remove?.(), 3000); };

  // ================================================================ FRAME: look, screens, Back, tabs, sheets
  // The look (Settings → Appearance): seal or teal, the system's day and night or one kept; this device only.
  const look = () => ({ theme: prefs.get('theme') ?? 'system', colour: prefs.get('colour') ?? 'seal' });
  function applyLook() {
    const root = document.documentElement, L = look();
    if (!root) return;
    if (L.theme === 'light' || L.theme === 'dark') root.setAttribute('data-theme', L.theme); else root.removeAttribute?.('data-theme');
    if (L.colour === 'teal') root.setAttribute('data-pal', 'teal'); else root.removeAttribute?.('data-pal');
  }
  applyLook();
  // Wallet is opt-in per profile (this identity), in its settings (GET /api/state me.wallet, POST /api/settings {wallet});
  // off hides the tab and stops every wallet call. This device keeps a mirror per DID for the Profiles sheet only.
  const walletKey = () => `wallet:${S.snap?.me?.did ?? S.me?.original ?? 'here'}`;
  const walletOn = () => S.snap?.me?.wallet?.on === true;
  /** Pass 4 moved the switch from this device into the profile's settings: a device that had it on turns it on there, once. */
  async function walletMirror() {
    const w = S.snap?.me?.wallet;
    if (!w) return;
    const keys = [...new Set([walletKey(), S.me?.original ? `wallet:${S.me.original}` : null].filter(Boolean))];
    if (prefs.get(`wallet-moved:${keys[0]}`) === null) {
      prefs.set(`wallet-moved:${keys[0]}`, '1');   // once per identity on this device, whatever it finds
      if (!w.on && keys.some((k) => prefs.get(k) === 'on')) { try { await backend.call('POST', '/api/settings', { wallet: true }); S.snap.me.wallet = { ...w, on: true }; } catch {} }
    }
    for (const k of keys) prefs.set(k, S.snap.me.wallet.on ? 'on' : 'off');
  }
  /** Turn this profile's Wallet on or off (Settings → Wallet). */
  async function setWallet(on) {
    await backend.call('POST', '/api/settings', { wallet: on });
    if (S.snap?.me) S.snap.me.wallet = { ...(S.snap.me.wallet ?? {}), on };
    S.wallet = null; S.walletAt = 0;
    for (const k of [walletKey(), S.me?.original ? `wallet:${S.me.original}` : null].filter(Boolean)) prefs.set(k, on ? 'on' : 'off');
  }

  /**
   * Screens: screen(name, {tab, guard}, build) where build(arg) draws the screen once (mount(page(…))) and returns
   * its update(), run again at every poll. One screen per history entry: S.stack mirrors the entries this page
   * pushed ({sigelo: 1, d, view, arg, sheet?}); Back (the screen's, the browser's, the system's) goes one entry.
   * The tab roots: Chats is the base (d 0); Agents, Wallet and Me replace each other at d 1.
   */
  const SCREENS = new Map();
  const screen = (name, opts, build) => { SCREENS.set(name, { ...opts, build }); };
  const H = globalThis.history;
  const ours = () => H?.state?.sigelo === 1;
  const top = () => S.stack[S.stack.length - 1];
  const stateOf = (i, sheet) => ({ sigelo: 1, d: i, view: S.stack[i].view, ...(S.stack[i].arg !== undefined && { arg: S.stack[i].arg }), ...(sheet && { sheet: true }) });
  function render() {
    if (L.locked) { dropSheet(); drawLocked(); return refresh(); }
    const e = top(), def = SCREENS.get(e.view) ?? SCREENS.get('chats');
    S.leave?.(); S.leave = null;   // a screen that showed the words hides them
    dropSheet();
    S.view = e.view; S.note = null; S.msgsSeq = -1; S.chip = null; S.tabs = null;
    S.update = def.build(e.arg) ?? (() => {});
    window.scrollTo?.(0, 0);
    // A new screen: the focus on its heading (said first by a screen reader), unless its update puts it in a field.
    const head = app.querySelector?.('h1');
    if (head) { head.setAttribute('tabindex', '-1'); head.focus?.({ preventScroll: true }); }
    return refresh();
  }
  /**
   * The screen drawn again now (its update), a failure of it kept from the page. A control that had the focus and was
   * drawn anew (a row, a radio, a switch) gets it back on its new self, found by what it says: a keyboard or a screen
   * reader keeps its place across the poll.
   */
  async function refresh() {
    fillChip();
    const was = document.activeElement, k = was && was !== document.body && app.contains?.(was) ? keyOf(was) : null;
    try { await S.update(); } catch (e) { S.note = e; }
    try { fillTabs(); S.sheet?.update?.(); } catch {}
    if (k && !app.contains?.(was)) [...(app.querySelectorAll?.('button, input, select, textarea, summary') ?? [])].find((e) => keyOf(e) === k)?.focus?.({ preventScroll: true });
  }
  const keyOf = (el) => [el.tagName, el.getAttribute?.('aria-label') ?? '', el.type === 'radio' ? `${el.name}=${el.value}` : '', el.labels?.[0]?.textContent ?? '', String(el.textContent ?? '').slice(0, 80)].join('|');
  /** A screen on top of this one (its own history entry); a guarded one asks the screen lock first. */
  async function go(view, arg) {
    const def = SCREENS.get(view);
    if (def?.guard && typeof LOCAL?.unlock === 'function') {
      try { await LOCAL.unlock(); } catch (e) { S.note = e; await refresh(); return; }
    }
    const fromSheet = S.sheet && H?.state?.sheet;   // the sheet's entry becomes the new screen's
    S.stack.push({ view, ...(arg !== undefined && { arg }) });
    const st = stateOf(S.stack.length - 1);
    if (fromSheet) H.replaceState(st, ''); else H?.pushState?.(st, '');
    await render();
  }
  /** This screen replaced by another (the same entry): a step that is done (a group made, a pairing). */
  function swap(view, arg) {
    S.stack[S.stack.length - 1] = { view, ...(arg !== undefined && { arg }) };
    if (ours() && !H.state.sheet) H.replaceState(stateOf(S.stack.length - 1), '');
    return render();
  }
  /** One step back: a sheet closes; else the screen before. */
  function back() {
    if (S.sheet) return closeSheet();
    if (S.stack.length <= 1) return undefined;
    if (ours() && H.state.d > 0) { H.back(); return undefined; }
    S.stack.pop();
    return render();
  }
  /** Back to the tab root's list (Done on a finished flow). */
  function home(view = 'chats') {
    const n = S.stack.length - 1;
    // Back through the history to the first entry (none left behind: Back from a tab root is Chats), then the tab on it.
    if (n > 0 && ours() && H.state.d === n) { if (view !== 'chats') S.pendingTab = view; H.go(-n); return; }
    S.stack = view === 'chats' ? [{ view }] : [S.stack[0], { view }];
    if (ours()) H.replaceState(stateOf(S.stack.length - 1), '');
    void render();
  }
  /** A bottom tab: Chats is the base; the others sit on it, one at a time. */
  function tab(view) {
    if (S.stack.length === 1 && view === 'chats') { window.scrollTo?.(0, 0); return; }
    if (view === 'chats') { home('chats'); return; }
    if (S.stack.length === 1) { S.stack.push({ view }); H?.pushState?.(stateOf(1), ''); }
    else { S.stack = [S.stack[0], { view }]; if (ours()) H.replaceState(stateOf(1), ''); }
    void render();
  }
  globalThis.addEventListener?.('popstate', (ev) => {
    const st = ev?.state ?? H?.state;
    if (S.sheet) {
      const was = S.sheet;
      dropSheet();
      was.popped?.();
      if (st?.sigelo === 1 && st.d === S.stack.length - 1 && st.view === top().view && !st.sheet) return;
    }
    if (st?.sigelo !== 1) { if (S.stack.length > 1) { S.stack = [S.stack[0]]; void render(); } return; }
    if (st.sheet) { H.back(); return; }   // forward into a closed sheet: not opened again
    S.stack = S.stack.slice(0, st.d);
    while (S.stack.length < st.d) S.stack.push({ view: 'chats' });
    S.stack.push({ view: st.view, ...(st.arg !== undefined && { arg: st.arg }) });
    if (S.pendingTab && st.d === 0) { const v = S.pendingTab; S.pendingTab = null; tab(v); return; }   // home(tab): at the first entry now
    void render();
  });

  // The profile chip (the tab roots' top bar): the profile's name and four words; it opens the Profiles sheet.
  const PROFILE_SHELL = globalThis.webkit?.messageHandlers?.sigelo;
  function shellAsk(wk) {
    return async (op, o = {}) => {
      const r = await wk.postMessage({ op, ...o });
      if (!r?.ok) throw Object.assign(new Error(r?.message ?? `${op}: no answer`), { check: r?.check });
      return r;
    };
  }
  /** The GTK phone app's profile operations over its bridge: {ok, …} answers, a refusal thrown. */
  function shellProfiles(wk) {
    const ask = shellAsk(wk);
    return { list: () => ask('profiles'), use: (id) => ask('profile-use', { id }), rename: (id, name) => ask('profile-rename', { id, name }),
      add: (path) => ask('profile-add', path ? { path } : {}), remove: (id, o) => ask('profile-remove', { id, ...o }) };
  }
  const PROFILES = LOCAL?.profiles ?? (PROFILE_SHELL ? shellProfiles(PROFILE_SHELL) : null);
  async function loadProfiles() {
    if (!PROFILES) return null;
    try { S.profiles = await PROFILES.list(); S.prof = S.profiles.profiles.find((p) => p.id === S.profiles.active) ?? null; } catch (e) { S.profiles = { error: e, profiles: [] }; }
    return S.profiles;
  }
  async function loadMe() { try { S.me = await backend.call('GET', '/api/me'); } catch (e) { S.me = S.me ?? null; } return S.me; }
  const profileName = () => S.prof?.name ?? (backend === http ? 'This computer' : 'sigelo');
  const myWords = () => S.prof?.words ?? S.me?.words ?? '';
  function chip() {
    S.chip = h('button', { type: 'button', class: 'pchip', onclick: openProfiles });
    fillChip();
    return S.chip;
  }
  function fillChip() {
    if (!S.chip) return;
    const me = S.snap?.me, online = me?.online, sub = !me ? 'Connecting…' : online ? wordsLine(myWords()) : 'Not connected';
    S.chip.setAttribute('aria-label', `${profileName()}. Switch profile`);
    put(S.chip, h('span', { class: `dot${!me ? ' off' : online ? '' : ' warn'}` }), h('span', { class: 't' }, h('b', null, profileName()), h('small', null, sub)), icon('down'));
  }
  const TABS = [['chats', 'Chats', 'chat'], ['agents', 'Agents', 'agent'], ['wallet', 'Wallet', 'wallet'], ['me', 'Me', 'me']];
  /** The bottom tabs; the Chats tab carries the unread count (drawn again at every poll, fillTabs). */
  function tabs(current) {
    const badge = h('span', { class: 'count tabcount', 'aria-hidden': 'true', hidden: true });
    const el = h('nav', { class: 'tabs', 'aria-label': 'Main' });
    S.tabs = { el, badge, current, wallet: null, chats: null };
    fillTabs();
    return el;
  }
  // The buttons again only when the Wallet tab comes or goes; else the count only, in place (a tab being tapped stays the same button).
  function fillTabs() {
    if (!S.tabs) return;
    if (S.tabs.wallet !== walletOn()) {
      const { el, badge, current } = S.tabs;
      S.tabs.wallet = walletOn();
      put(el, TABS.filter(([t]) => t !== 'wallet' || walletOn()).map(([t, label, ic]) =>
        h('button', { type: 'button', 'aria-current': t === current ? 'page' : null, 'data-tab': t, onclick: () => tab(t) }, h('i', null, icon(ic), t === 'chats' ? badge : null), h('span', null, label))));
      S.tabs.chats = [...el.childNodes].find((b) => b.getAttribute?.('data-tab') === 'chats') ?? null;
    }
    const n = chatsUnread(), { badge, chats } = S.tabs;
    badge.hidden = !n;
    badge.textContent = !n ? '' : n > 99 ? '99+' : String(n);
    if (n) chats?.setAttribute('aria-label', `Chats, ${n} unread`); else chats?.removeAttribute?.('aria-label');
  }
  /**
   * A screen's frame: the top bar (the profile chip on a tab root; else Back or Close, the title or `who`, and
   * `actions`), the body, `after` it (a chat's composer), a foot (its primary action), and on a tab root the tabs and the FAB. → the element.
   */
  function page({ title, tab: t, close, onBack, who, actions = [], body = [], after, foot, fab }) {
    const bar = t ? [chip(), h('h1', { class: 'sr' }, title), h('span', { class: 'sp' }), actions]
      : [S.backBtn = ibtn(close ? 'x' : 'back', close ? 'Close' : 'Back', () => (onBack ? onBack() : back())), who ?? h('h1', null, title), actions];
    return h('div', { class: `screen${t ? ' tabbed' : ''}`, 'data-screen': S.view },
      h('header', { class: 'top' }, bar), h('div', { class: 'body' }, body), after ?? null, foot ? h('div', { class: 'foot' }, foot) : null,
      fab ?? null, t ? tabs(t) : null);
  }
  /** The floating button of a tab root (New chat, Enrol agent). */
  const fabBtn = (label, onclick) => h('button', { type: 'button', class: 'fab', onclick }, icon('plus'), label);
  const mount = (el) => { S.screenEl = el; return put(app, el); };

  // Sheets: a panel from the bottom over the screen, its own history entry (Back closes it), a visible Close.
  function dropSheet() {
    const s = S.sheet;
    if (!s) return;
    S.sheet = null;
    s.el.remove?.();
    s.under?.removeAttribute?.('inert');
    s.onClose?.();
    if (s.opener && app.contains?.(s.opener)) s.opener.focus?.({ preventScroll: true });   // back where it was opened from
  }
  /** The sheet closed (one entry back when it pushed one); resolves once it is gone. */
  function closeSheet() {
    if (!S.sheet) return Promise.resolve();
    if (H?.state?.sheet && ours()) return new Promise((resolve) => { S.sheet.popped = resolve; H.back(); });
    dropSheet();
    return Promise.resolve();
  }
  /** sheet({title, lead, body, onClose, update}) → {panel, close}: a dialog over the screen. */
  function sheet({ title, lead, body = [], onClose, update, bare }) {
    dropSheet();
    const panel = h('div', { class: 'panel', role: 'dialog', 'aria-modal': 'true', 'aria-label': title, tabindex: '-1' },
      h('div', { class: 'phead' }, h('h1', { class: bare ? 'sr' : null }, title ?? ''), bare ? h('span', { class: 'sp' }) : null, ibtn('x', 'Close', () => closeSheet())), lead ? h('p', { class: 'lead' }, lead) : null, body);
    const el = h('div', { class: 'sheet', onkeydown: (ev) => { if (ev.key === 'Escape') closeSheet(); } },
      h('button', { type: 'button', class: 'scrim', 'aria-label': 'Close', tabindex: '-1', onclick: () => closeSheet() }), panel);
    const opener = document.activeElement;
    app.append(el);
    // The screen under it out of reach (focus, a screen reader, taps) while the sheet is up: the focus stays in the dialog.
    const under = S.screenEl && S.screenEl !== el ? S.screenEl : null;
    under?.setAttribute?.('inert', '');
    S.sheet = { el, panel, onClose, opener, update, under };   // update: run at every poll while it is open
    if (ours() && !H.state.sheet) H.pushState({ ...H.state, sheet: true }, '');
    panel.focus?.();
    return { panel, close: closeSheet };
  }
  /** The confirm dialog (a sheet naming the thing and the verb): resolves true for yes, false for no or Close. */
  function ask({ title, text, yes, no = 'Cancel', danger = true, extra = [], check }) {
    return new Promise((resolve) => {
      let done = false;
      const end = async (v) => { if (done) return; if (v && check && !check()) return; done = true; await closeSheet(); resolve(v); };
      const s = sheet({ title, lead: text, onClose: () => { if (!done) { done = true; resolve(false); } },
        body: [h('div', { class: 'pad stack' }, extra, btn(yes, () => end(true), { kind: danger ? 'danger' : 'pri' }), btn(no, () => end(false)))] });
      void s;
    });
  }

  // What the page holds and what it waits for, said once above a tab's list (only when it needs the human).
  function statusCards() {
    const me = S.snap?.me, out = [];
    if (S.fatal && !S.snap) out.push(h('div', { class: 'card warn' }, inlineError(S.fatal)));
    if (!me) return out;
    if (!me.online && !me.pow) out.push(h('div', { class: 'card warn' }, row({ title: 'Not connected', sub: 'Your messages wait here and go when you\'re back online.', subCls: 'wrap', end: tbtn('Retry', () => act(() => backend.call('POST', '/api/sync'))) })));
    const off = me.clock_offset;
    if (off !== null && off !== undefined && Math.abs(off) > 60) out.push(h('div', { class: 'card warn' }, h('p', null, `Your clock is ${Math.abs(off)} s ${off < 0 ? 'ahead of' : 'behind'} the relay's. Set it right, or codes fail.`)));
    if (me.pow) {
      const pct = Math.min(95, Math.round((100 * me.pow.elapsed_s) / Math.max(30, 2 * me.pow.expected_s)));
      const bar = h('i'); bar.style.width = `${pct}%`;
      out.push(h('div', { class: 'card' }, h('p', null, 'One-time setup, up to 2 minutes'), h('div', { class: 'meter', role: 'progressbar', 'aria-valuenow': String(pct), 'aria-valuemin': '0', 'aria-valuemax': '100' }, bar), h('p', { class: 'help' }, `${me.pow.elapsed_s} s`)));
    } else if (me.pow_capped) {
      out.push(h('div', { class: 'card' }, h('p', null, `Setup paused at ${me.pow_capped.relay}: 3 tries today. Next automatic try at ${hhmm(me.pow_capped.next)}.`),
        h('div', { class: 'btns' }, btn('Try now', () => act(() => started('POST', '/api/pow/try')), { kind: 'pri' }))));
    } else if (me.pow_confirm) {
      out.push(h('div', { class: 'card' }, h('p', null, me.pow_confirm.detail),
        h('div', { class: 'btns' }, btn('Go on', () => act(() => backend.call('POST', '/api/pow/try', { pow_confirmed: true })), { kind: 'pri' }))));
    }
    const seat = seatBanner();
    if (seat) out.push(seat);
    const t = S.snap?.transfers;
    if (t?.asked && S.transfersSeen !== t.asked) {
      out.push(h('div', { class: 'card' }, h('p', null, t.asked === 1 ? 'A contact offers you a file.' : `${t.asked} files are offered to you.`),
        h('div', { class: 'btns' }, btn('See', () => go('files'), { kind: 'pri' }), btn('Later', () => { S.transfersSeen = t.asked; void refresh(); }))));
    }
    return out;
  }
  // The seat (one device logs in as you at a time): the spare made the main one (the mock's restore wording), after a warning
  // (POST /api/seat/take); with the words kept behind the password, its own screen asks it.
  async function seatTake() {
    if (SEC.st?.kept) { void go('seat-take'); return; }
    if (await ask({ title: 'Make this phone the main one?', text: 'Only if that other device is stopped or lost: two devices signing in as you lose each other\'s messages.', yes: 'Make this phone the main one', no: 'Keep it a spare' })) {
      void act(() => backend.call('POST', '/api/seat/take', { confirm: true }));
    }
  }
  // The seat: another device holding it, or a refusal seat_elsewhere.
  function seatBanner() {
    const seat = S.snap?.me?.seat, e = [S.note, S.fatal].find((x) => x?.check === 'seat_elsewhere');
    // In the app restored from seed (LOCAL): the seat is taken here, after a warning (POST /api/seat/take).
    if (seat && !seat.here) {
      return h('div', { class: 'card warn' }, h('p', null, `${seat.holder} signs in as you now: this ${LOCAL ? 'phone is a spare' : 'page doesn\'t'}.`),
        LOCAL ? h('div', { class: 'btns' }, btn('Make this phone the main one', seatTake)) : h('p', { class: 'help' }, 'To move it here: sigelo-agent device seat take.'));
    }
    return e ? h('div', { class: 'card warn' }, h('p', null, 'Another device holds your seat: '), inlineError(e)) : null;
  }

  // ================================================================ CHATS: the list, requests, new chat, pairing, a chat
  async function workersNow(force = false) {
    if (!force && S.workers && Date.now() - S.workersAt < 30000) return S.workers;
    try { S.workers = await backend.call('GET', '/api/agents/workers'); } catch (e) { S.workers = { keeper: false, seat: null, workers: [], error: e }; }
    S.workersAt = Date.now();
    return S.workers;
  }
  async function loadGroups() {
    try { S.groups = await backend.call('GET', '/api/groups'); } catch (e) { S.groups = { tier: null, groups: [], notices: [], error: e }; }
    return S.groups;
  }
  // The groups again only when the state says something changed (chats.rev), or when asked.
  async function groupsNow(force = false) {
    const rev = S.snap?.chats?.rev ?? null;
    if (force || !S.groups || S.groupsRev !== rev) { S.groupsRev = rev; await loadGroups(); }
    return S.groups;
  }
  const groupBy = (gid) => S.groups?.groups.find((g) => g.gid === gid) ?? null;
  /** A team: a group whose roster has people besides me and agents (each person brings theirs). */
  const isTeam = (g) => g.members.some((m) => m.role === 'agent') && g.members.some((m) => m.role !== 'agent' && !m.me);
  const liveGroup = (g) => g.status !== 'left' && g.status !== 'removed';

  /** What a chat's row says under its name: the tier decides (own: the text; friend: a count; quiet: nothing). */
  function contactLine(c) {
    const unread = unreadOf(c), agent = kindOf(c) === 'agent';
    const lead = agent ? [h('span', { class: 'kind' }, 'Agent'), ' · '] : [];
    if (c.status === 'pair_again') return [lead, h('span', { class: 'warn' }, 'Pair again')];
    if (!c.words_checked && c.words && !c.local) return [lead, h('span', { class: 'warn' }, 'Compare four words')];
    if (c.status === 'waiting') return [lead, 'Waiting for their side'];
    if (c.not_collected) return [lead, 'Not collected yet'];
    if (c.tier === 'quiet') return agent ? h('span', { class: 'kind' }, 'Agent') : '';
    if (c.tier === 'friend') return unread ? [lead, `${unread} new message${unread === 1 ? '' : 's'}`] : agent ? h('span', { class: 'kind' }, 'Agent') : '';
    // Mine waiting (offline, or no reader yet): said after it, as the mock's offline list does.
    const wait = c.last?.dir === 'out' && c.last.status === 'queued' ? ' · waiting to send' : '';
    return c.last ? [lead, `${c.last.dir === 'out' ? 'You: ' : ''}${c.last.text}${wait}`] : agent ? h('span', { class: 'kind' }, 'Agent') : '';
  }
  function chatRows() {
    const items = allContacts().map((c) => ({ at: c.last?.at ?? 0, name: c.name, row: () => row({
      start: avatar(kindOf(c), c.name, null, c.did), title: c.name, sub: contactLine(c), attrs: { 'data-chat': c.did },
      end: [short(c.last?.at), countBadge(unreadOf(c), c)],
      onclick: () => go('chat', c.did) }) }));
    for (const g of (S.groups?.groups ?? []).filter(liveGroup)) {
      const sub = g.status === 'pending' ? `${g.creator_name ?? 'Someone'} adds you · Join or leave`
        : g.quiet && g.status === 'member' ? 'Agents paused: write to let them go on'
          : g.last ? `${g.last.mine ? 'You' : g.last.name}: ${g.last.text}` : `${g.members.length} members`;
      // A team (People and teams): a group where people bring their agents, people and agents both in its roster.
      items.push({ at: g.last?.at ?? 0, name: g.name, row: () => row({
        start: avatar('group', g.name, null, g.gid), title: g.name, sub: [h('span', { class: 'kind' }, isTeam(g) ? 'Team' : 'Group'), ' · ', sub], attrs: { 'data-chat': g.gid },
        end: [short(g.last?.at), countBadge(g.unread, g)],
        onclick: () => go('group', g.gid) }) });
    }
    return items.sort((a, b) => b.at - a.at || String(a.name).localeCompare(String(b.name))).map((x) => x.row());
  }
  const controlsWaiting = () => (Array.isArray(S.controls) ? S.controls : []);
  /** What waits for the human under Requests: introductions, controls to confirm (a computer's page), codes made. */
  function requestCount() {
    const intro = (S.snap?.introductions ?? []).length, ctl = controlsWaiting().length;
    const codes = (S.snap?.pending.invites ?? []).filter((i) => i.short && i.short_exp > relayNow()).length + (S.snap?.pending.answers ?? []).length + (S.snap?.pending.failed ?? []).length;
    const notices = (S.groups?.notices ?? []).length;
    return { answer: intro + ctl, any: intro + ctl + codes + notices };
  }
  screen('chats', { tab: 'chats' }, () => {
    const head = h('div'), lst = h('div');
    mount(page({ title: 'Chats', tab: 'chats', actions: [ibtn('scan', 'Scan a QR', () => go('scan'))], body: [head, lst], fab: fabBtn('New chat', openNewChat) }));
    return async () => {
      put(head, statusCards(), noteCard());
      if (!S.snap) { put(lst, S.fatal ? null : h('p', { class: 'pad muted' }, 'Loading…')); return; }
      await Promise.all([groupsNow(), workersNow()]);
      const rq = requestCount(), rows = chatRows(), first = (S.snap.introductions ?? [])[0];
      const cut = S.snap.truncated;
      // The mock's hint, once: dismissed for good on this device.
      const hint = PROFILES && rows.length && prefs.get('hint-switch') !== 'off' ? h('div', { class: 'hint' }, h('p', null, 'Tap your name at the top to switch profiles.'),
        ibtn('x', 'Dismiss', () => { prefs.set('hint-switch', 'off'); void refresh(); })) : null;
      put(lst, hint,
        rq.any ? h('div', { class: 'list' }, row({ compact: true, start: h('span', { class: 'av', 'aria-hidden': 'true' }, icon('people')), title: 'Requests', cls: 'requests',
          sub: first ? `${first.name} wants to introduce ${first.purpose ? `an agent: ${first.purpose}` : 'an agent'}` : rq.answer ? 'Waiting for your answer' : 'Your codes and answers',
          end: rq.answer ? h('span', { class: 'count' }, String(rq.answer)) : null, onclick: () => go('requests') })) : null,
        rows.length ? h('div', { class: 'list' }, rows)
          : empty('No chats yet', 'Pair with a person, or enrol your first agent, and talk to it here.', btn('Start a chat', openNewChat, { kind: 'pri' }), btn('Enrol an agent', () => go('enrol'))),
        cut ? h('div', { class: 'pad center' }, h('p', { class: 'help' }, `The newest ${cut.kept} of each list are shown.`),
          btn('Show all', () => act(async () => { S.snap = await backend.call('GET', '/api/state?since=0&full=1'); }), { kind: 'ghost' })) : null);
    };
  });

  screen('requests', {}, () => {
    const body = h('div', { class: 'pad stack' });
    mount(page({ title: 'Requests', body: [body] }));
    let links = null, at = 0;
    return async () => {
      if (!S.snap) return;
      if (S.snap.introductions?.length && (!links || Date.now() - at > 5000)) { links = await backend.call('GET', '/api/links').catch(() => links); at = Date.now(); }
      const cards = [];
      for (const x of links?.received ?? S.snap.introductions ?? []) {
        const answer = (b) => act(() => backend.call('POST', '/api/links/answer', { id: x.id, ...b }));
        cards.push(h('div', { class: 'card' }, h('p', null, h('b', null, x.name ?? x.from), ' wants to introduce ', h('b', null, x.peer_name ?? 'an agent'), '.'),
          h('p', { class: 'help' }, `"${x.purpose}"${x.note ? ` · ${x.note}` : ''}${x.exp ? ` · Ends ${inDays(x.exp)}` : ''}`),
          x.answer ? h('p', { class: 'help' }, x.answer === 'accepting' ? 'Accepting…' : 'Declining…')
            : [h('div', { class: 'btns' }, btn('Accept', () => answer({ accept: true }), { kind: 'pri' }), btn('Decline', () => answer({ accept: false }))),
              h('details', { class: 'more' }, h('summary', null, 'More'), h('div', { class: 'stack' },
                btn('Accept, show their messages', () => answer({ accept: true, tier: 'friend' })), btn('Decline and tell them', () => answer({ accept: false, tell: true })),
                btn(`Always accept from ${x.name ?? x.from}`, async () => { if (await ask({ title: `Always accept from ${x.name ?? x.from}?`, text: 'Their introductions are accepted by themselves, quiet.', yes: 'Always accept', danger: false })) void act(() => backend.call('POST', '/api/links/allow', { contact: x.from, allow: true })); })))]));
      }
      // Relay controls paired, their four words not confirmed yet (ui --remote --relay): confirmed here as in the terminal.
      for (const c of controlsWaiting()) {
        const answer = (match) => act(() => backend.call('POST', '/api/controls/confirm', { name: c.name, match }));
        cards.push(h('div', { class: 'card' }, h('p', null, h('b', null, c.name), ` wants to control this computer (${c.scope}). Does it show these four words?`),
          h('div', { class: 'pad' }, fourWords(c.words ?? '')), h('div', { class: 'btns' }, btn('Confirm', () => answer(true), { kind: 'pri' }), btn('Refuse', () => answer(false)))));
      }
      for (const i of S.snap.pending.invites) {
        const live = i.short && i.short_exp > relayNow();
        if (!live && !i.id) continue;
        const gname = i.group ? groupBy(i.group)?.name ?? 'a group' : null;
        cards.push(h('div', { class: 'card' }, h('p', null, h('b', null, `Your ${gname ? 'group ' : ''}code ${live ? i.short : ''}`.trim()), live ? ` is waiting for someone to use it${gname ? `: they join ${gname}` : ''}.` : ` for ${i.name} has run out.`),
          live ? h('p', { class: 'help' }, minutesLeft(i.short_exp)) : h('p', { class: 'help' }, 'Its long code works until ', when(i.exp)),
          h('div', { class: 'btns' }, i.id ? btn('Show it', () => go('my-code', { id: i.id })) : null,
            i.id ? btn('Cancel it', () => act(() => backend.call('POST', '/api/invite/cancel', { id: i.id })), { kind: 'ghost' }) : null)));
      }
      for (const a of S.snap.pending.answers) cards.push(h('div', { class: 'card' }, h('p', null, `Your answer to ${a.name} waits for them to come online once, until `, when(a.exp), '.')));
      for (const f of S.snap.pending.failed) cards.push(h('div', { class: 'card' }, h('p', null, h('b', null, f.name ?? f.did), ': ', f.code === 'code_expired' ? 'the code ran out before they replied. Ask for a new one.' : `${f.code}: ${f.detail ?? ''}`)));
      for (const n of S.groups?.notices ?? []) cards.push(groupNotice(n));
      put(body, noteCard(), cards.length ? cards : empty('Nothing waiting', 'Introductions and the codes you made show here.'));
    };
  });

  // New chat (Telegram's button): make my code, or type theirs; scan; a group; or enrol my own agent instead.
  function openNewChat() {
    const mine = h('div', { class: 'card' }), theirs = input({ autocapitalize: 'characters', placeholder: 'M4QX-8T2B', class: 'big', 'aria-label': 'Their code' });
    const M = { inv: null, busy: false, error: null };
    const draw = () => {
      if (M.inv) {
        put(mine, h('div', { class: 'row' }, h('span', { class: 'mid' }, h('b', { class: 'code sm' }, M.inv.short ?? 'Long code made'), h('small', null, 'Works once, for ', countdown(M.inv.short_exp ?? M.inv.exp))),
          btn('Share', () => share(pairMessage(M.inv.short ?? M.inv.code, M.inv.short_exp ?? M.inv.exp)), { kind: 'pri', auto: true })),
        tbtn('Show as QR', () => go('my-code', { id: M.inv.id })));
        return;
      }
      put(mine, h('div', { class: 'row' }, h('span', { class: 'mid' }, h('b', null, 'Your code'), h('small', { class: 'wrap' }, 'Works once, for 10 minutes')),
        btn(M.busy ? 'Making…' : 'Make my code', make, { kind: 'pri', auto: true, disabled: M.busy })), inlineError(M.error));
    };
    const make = async () => {
      M.busy = true; M.error = null; draw();
      try { M.inv = await started('POST', '/api/invite', {}); } catch (e) { M.error = e; }
      M.busy = false; draw();
    };
    draw();
    const pair = () => { const code = theirs.value.trim(); if (code) void go('enter-code', { code }); };
    theirs.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') pair(); });
    // My code used while the sheet is open: the four words to compare, in place of it (My code shows them).
    const update = () => { if (M.inv && S.snap?.pending.paired.some((x) => x.id === M.inv.id)) void go('my-code', { id: M.inv.id }); };
    sheet({ title: 'New chat', lead: 'Give them your code, or type theirs. Then compare four words.', update, body: [mine,
      h('div', { class: 'pad btns end' }, field('Their code', theirs), btn('Pair', pair, { auto: true })),
      list(row({ compact: true, start: icon('scan'), title: 'Scan their QR', onclick: () => go('scan') }),
        row({ compact: true, start: icon('people'), title: 'New group', sub: 'People and agents together', onclick: () => go('group-new') })),
      list(row({ compact: true, start: icon('agent'), title: 'Your own agent?', sub: 'Enrol it instead: it acts as you', chev: true, onclick: () => go('enrol') }))] });
  }

  /** Compare four words with a new contact: They match (checked) or They don't (forgotten and blocked). */
  function compareBlock(c, foot) {
    const yes = () => act(() => backend.call('POST', '/api/words', { contact: c.did, match: true }));
    const no = async () => {
      if (await ask({ title: `Block ${c.name}?`, text: 'Different words mean someone else used the code. They are forgotten and can never pair with you again. Make a new code.', yes: 'They don\'t match: block' })) {
        void act(() => backend.call('POST', '/api/words', { contact: c.did, match: false }), () => { home(); setTimeout(openNewChat, 0); });
      }
    };
    put(foot, btn('They match', yes, { kind: 'pri' }), btn('They don\'t match', no));
    return [h('p', { class: 'lead' }, `Read these to ${c.name}, by voice or another app. They see four words too.`), h('div', { class: 'card center' }, fourWords(c.words)),
      h('p', { class: 'help' }, 'Different words? Someone else used the code. Choose "They don\'t match" and make a new one.')];
  }
  /** After a pairing: the words to compare, then paired (its own screen, the mock's); null while the contact has not come yet. */
  function afterPairing(c, body, foot) {
    if (!c) return [h('p', { class: 'lead' }, 'Finishing the pairing…')];
    if (c.words_checked || c.local || !c.words) { put(foot); if (S.view !== 'paired') setTimeout(() => { if (S.view !== 'paired') void swap('paired', c.did); }, 0); return [h('p', { class: 'lead', role: 'status' }, 'Paired.')]; }
    return compareBlock(c, foot);
  }
  // Paired (the mock's): Close to Chats, Say hello into the chat.
  screen('paired', {}, (did) => {
    const c = contactBy(did) ?? { did, name: 'them' };
    mount(page({ close: true, onBack: () => home(), who: h('h1', { class: 'sr' }, 'Paired'), body: [h('div', { class: 'hero center stack' }, h('div', { class: 'badge-ic' }, icon('check')),
      h('h2', { class: 'big' }, `You and ${c.name} are paired`), h('p', { class: 'lead' }, 'Only the two of you can read this chat.'))],
    foot: [btn('Say hello', () => swap('chat', did), { kind: 'pri' })] }));
  });

  // My code: one person starts a chat with me; once, 10 minutes; then the four words (UI-API.md /api/invite).
  screen('my-code', {}, (arg) => {
    const M = { id: arg?.id ?? null, inv: null, busy: false, error: null }, body = h('div', { class: 'pad stack' }), foot = h('div');
    const title = h('h1', null, 'My code');
    mount(page({ who: title, body: [body], foot: [foot] }));
    const make = async (o = {}) => {
      M.busy = true; M.error = null; await refresh();
      try { const r = await started('POST', '/api/invite', o); M.id = r.id; M.inv = r; S.stack[S.stack.length - 1].arg = { id: r.id }; if (ours()) H.replaceState(stateOf(S.stack.length - 1), ''); } catch (e) { M.error = e; }
      M.busy = false; await poll();
    };
    return () => {
      put(foot);
      if (!M.id) {
        put(body, h('p', { class: 'lead' }, 'A code lets one person start a chat with you. It works once, for 10 minutes. Then you both compare four words.'),
          btn(M.busy ? 'Making a code…' : 'Make a code', () => make(), { kind: 'pri', disabled: M.busy }), btn('I have their code', () => go('enter-code'), { kind: 'ghost' }),
          M.error ? [inlineError(M.error), h('p', { class: 'help' }, 'Their agent on another relay? Make a long code instead.'), btn('Make a long code', () => make({ long: true }))] : null);
        return;
      }
      const pend = S.snap?.pending.invites.find((x) => x.id === M.id), paired = S.snap?.pending.paired.find((x) => x.id === M.id);
      const inv = M.inv ?? (pend ? { id: pend.id, short: pend.short, short_exp: pend.short_exp, code: pend.code, exp: pend.exp, relay: pend.relay } : null);
      if (paired) { title.textContent = 'Compare four words'; put(body, afterPairing(contactBy(paired.paired), body, foot)); return; }
      title.textContent = 'My code';
      if (!pend || !inv) { put(body, empty('This code is gone', 'It was used or cancelled.', btn('Make a new code', () => { M.id = null; M.inv = null; return make(); }, { kind: 'pri' }))); return; }
      const live = inv.short && inv.short_exp > relayNow();
      if (inv.short && !live) { put(body, empty('This code has run out', 'Codes work for 10 minutes, once. Make a new one.', btn('Make a new code', () => { M.id = null; M.inv = null; return make(); }, { kind: 'pri' }))); return; }
      const shown = inv.short ?? inv.code;
      put(body, h('div', { class: 'center stack' }, qrBox(shown), h('p', { class: inv.short ? 'code' : 'mono' }, shown),
        h('p', { class: 'lead' }, 'Works once, for ', countdown(inv.short ? inv.short_exp : inv.exp), '.'),
        h('div', { class: 'btns' }, btn('Share', () => share(pairMessage(shown, inv.short ? inv.short_exp : inv.exp)), { kind: 'pri' }), btn('Copy', (ev) => copy(shown, ev?.target))),
        inv.short && inv.code ? h('details', { class: 'more' }, h('summary', null, 'Their agent on another relay?'), h('p', { class: 'help' }, 'Give them the long code instead:'), h('p', { class: 'mono card' }, inv.code), btn('Copy the long code', () => copy(inv.code))) : null,
        btn('Cancel this code', () => act(() => backend.call('POST', '/api/invite/cancel', { id: inv.id }), () => back()), { kind: 'ghost' })));
    };
  });

  // Their code: accept it (UI-API.md /api/accept), then the words.
  screen('enter-code', {}, (arg) => {
    const P = { busy: false, error: null, result: null }, body = h('div', { class: 'pad stack' }), foot = h('div');
    const code = input({ autocapitalize: 'characters', class: 'big', value: arg?.code ?? '', placeholder: 'M4QX-8T2B' }), name = input({ autocomplete: 'off', placeholder: 'Optional' });
    const title = h('h1', null, 'Enter their code');
    mount(page({ who: title, body: [body], foot: [foot] }));
    const form = [field('Their code', code, 'Upper or lower case, with or without the dash.'), field('Their name, as you\'ll see it', name)];
    const enter = async (c = code.value) => {
      if (!c.trim() || P.busy) return;
      P.busy = true; P.error = null; P.result = null; await refresh();
      try { P.result = await started('POST', '/api/accept', { code: c.trim(), name: name.value.trim() }); } catch (e) { P.error = e; }
      P.busy = false; await poll();
    };
    if (arg?.code) setTimeout(() => enter(), 0);
    return () => {
      const me = S.snap?.me, r = P.result, came = r?.did ? contactBy(r.did) : r?.contact ? contactBy(r.contact.did) ?? { ...r.contact, words: r.contact.fingerprint } : null;
      if (came && came.status !== 'waiting' && (r.status === 'connected' || came.words)) { title.textContent = 'Compare four words'; put(body, afterPairing(came, body, foot)); return; }
      title.textContent = 'Enter their code';
      put(foot, btn(P.busy ? 'Pairing…' : 'Pair', () => enter(), { kind: 'pri', disabled: P.busy }));
      const out = [];
      if (r?.status === 'waiting') out.push(h('div', { class: 'card' }, h('p', null, 'Your answer is at the relay. It waits for their side to come online once', r.exp ? [', until ', when(r.exp)] : '', '. They show in Chats, with the four words, once they answer.')));
      else if (r?.status === 'pending') out.push(h('div', { class: 'card' }, h('p', null, 'Your answer has not reached the relay yet: it goes at the next connection.')));
      const e = P.error;
      if (e?.check === 'code_expired') {
        title.textContent = 'Code expired'; put(foot);
        put(body, empty('This code has run out', 'Codes work for 10 minutes, once. Ask for a new one, or make yours.', btn('Make my code', () => swap('my-code'), { kind: 'pri' }),
          btn('Enter another code', () => { P.error = null; code.value = ''; void refresh(); })));
        return;
      }
      if (e) {
        const why = {
          park_unknown: `No invite waits under this code at ${me?.relay ?? 'your relay'}. It ran out (10 minutes), was used (once only), or is mistyped: ask for a new code.`,
          code_expired: 'This code has run out. Codes work for 10 minutes, once. Ask for a new one.',
          mailbox_taken: 'This code was answered already, by someone else. Ask for a new one.',
          short_code: 'Not a code sigelo knows. Check it with whoever gave it to you.',
        }[e.check];
        out.push(h('div', { class: 'card warn' }, why ? h('p', null, why) : inlineError(e)));
        if (e.long) out.push(h('div', { class: 'card' }, h('p', null, 'The short code is used up. Its long code:'), h('p', { class: 'mono' }, e.long), h('div', { class: 'btns' }, btn('Use the long code', () => { code.value = e.long; return enter(e.long); }, { kind: 'pri' }))));
      }
      if (P.busy && me?.pow) out.push(...statusCards().filter((x) => x));
      put(body, form, out);
    };
  });

  // Compare four words with a contact (a pairing not checked yet).
  screen('compare', {}, (did) => {
    const body = h('div', { class: 'pad stack' }), foot = h('div');
    mount(page({ title: 'Compare four words', body: [body], foot: [foot] }));
    return () => { const c = contactBy(did); put(body, c ? afterPairing(c, body, foot) : empty('Not a contact', 'It was forgotten.')); };
  });

  // Scan a sigelo QR: a pairing code opens Enter their code; the camera, an image or pasted text (scanner()).
  screen('scan', {}, () => {
    const say = h('p', { class: 'help', role: 'status' });
    const sc = scanner(async (t) => {
      const text = t.trim();
      if (/^[0-9a-z]{4}-?[0-9a-z]{4}$/i.test(text) || /^sgl1/i.test(text)) { sc.stop(); await swap('enter-code', { code: text }); return true; }
      say.textContent = /^SIGELO:(DEV|CTL|UI):/.test(text) ? 'A device or computer code: use it under Me → Devices and computers.' : 'Not a sigelo code this app reads.';
      return false;
    });
    S.leave = () => sc.stop();
    mount(page({ title: 'Scan', body: [h('div', { class: 'pad stack' }, h('p', { class: 'lead center' }, 'Point at a sigelo QR: a person, an agent, a shop or your computer.'), sc, say, btn('Type a code instead', () => swap('enter-code')))] }));
    return () => {};
  });

  // ---- a chat with a contact
  const kb = (n) => (n < 1024 ? `${n} bytes` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  // A file received (sigelo-file/0): the carrier's line "file <name> (<n> bytes), saved at <path>": the name and size, the place small.
  function fileText(t) {
    const m = /^file (.+) \((\d+) bytes\), saved at (.+)$/s.exec(String(t ?? ''));
    if (!m) return h('div', { class: 'text' }, t);
    return h('div', null, h('div', { class: 'text' }, h('b', null, m[1]), ` · ${kb(Number(m[2]))}`), h('div', { class: 'path' }, 'Saved on this machine: ', m[3]));
  }
  /** Messages with a day line between days; mine on the right. */
  function threadOf(msgs, bubble) {
    let last = '';
    const out = [];
    for (const m of msgs) {
      const d = dayLabel(m.at);
      if (d !== last) { out.push(h('span', { class: 'day' }, d)); last = d; }
      out.push(bubble(m));
    }
    return out;
  }
  const atEnd = () => (window.innerHeight ?? 0) + (window.scrollY ?? 0) >= (document.body?.scrollHeight ?? 0) - 80;
  const toEnd = () => window.scrollTo?.(0, document.body?.scrollHeight ?? 0);
  function composer(placeholder, onSend, lead) {
    const text = h('textarea', { rows: 1, placeholder, 'aria-label': 'Message' });
    // The box grows with what is typed, up to a third of the screen (ui.css), and back after Send.
    const fit = () => { if (!text.style) return; text.style.height = 'auto'; if (text.scrollHeight) text.style.height = `${text.scrollHeight + 2}px`; };
    const sendBtn = ibtn('send', 'Send', async () => {
      const t = text.value;
      if (!t.trim()) return;
      sendBtn.disabled = true;
      try { await onSend(t, () => { text.value = ''; fit(); }); } finally { sendBtn.disabled = false; }
    }, 'send');
    text.addEventListener('input', fit);
    text.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); sendBtn.click?.(); } });
    return { el: h('div', { class: 'composer' }, lead, text, sendBtn), text, fit, sendBtn };
  }
  /** Pay from a chat: the Wallet when it is on, else the sheet that turns it on. */
  function pay(did) {
    if (walletOn()) { void go('pay', did); return; }
    sheet({ title: 'Turn on Wallet to pay', lead: 'Pay people and agents right from a chat. Wallet is off for this profile; your agents\' allowances work either way.',
      body: [h('div', { class: 'pad stack' }, btn('Turn on Wallet', () => go('set-wallet'), { kind: 'pri' }), btn('Not now', () => closeSheet(), { kind: 'ghost' }))] });
  }
  function attach(did) {
    // The mock's attach sheet has no title (Close only): said to a screen reader, not shown. A group's has no Pay (one payee).
    sheet({ title: 'Attach', bare: true, body: [list(
      did ? row({ compact: true, start: icon('coin'), title: 'Pay', onclick: () => { void closeSheet().then(() => pay(did)); } }) : null,
      S.snap?.transfers ? row({ compact: true, start: icon('file'), title: 'Send a file', sub: 'Up to 16 GB, they\'re asked first', onclick: () => go('files', { to: did }) }) : null,
      did ? row({ compact: true, start: icon('pen'), title: 'Send a signed message', sub: 'Proves it\'s from you', onclick: () => go('sign', { to: did }) }) : null)] });
  }
  screen('chat', {}, (did) => {
    const who = h('button', { type: 'button', class: 'who', onclick: () => { const w = workerOf(did); void (w ? go('agent', w.worker) : go('chat-info', did)); } });
    const alerts = h('div'), thread = h('div', { class: 'thread' });
    const mine = () => kindOf(contactBy(did) ?? {}) === 'agent' && workerOf(did);
    const lead = h('span');
    const C = composer('Message', (t, clear) => act(() => backend.call('POST', '/api/send', { to: did, text: t }), () => { clear(); S.msgsSeq = -1; }), lead);
    const heading = h('h1', { class: 'sr' });
    mount(page({ who, actions: [tbtn('Pay', () => pay(did))], body: [heading, alerts, thread], after: C.el }));
    notifyOut({ tag: tagOfChat(did), cancel: true });   // its notification, if one is up: read now
    let first = true;
    const asked = new Map();   // a payment request answered in this chat: what it says after (the mock's "Done. scout was told.")
    return async () => {
      const c = contactBy(did);
      await workersNow();
      if (!c) { put(who, h('span', { class: 'mid' }, h('b', null, 'Gone'))); put(alerts, h('div', { class: 'card' }, h('p', null, 'Not a contact any more (forgotten).'))); return; }
      const w = mine(), k = kindOf(c), seen = presenceText(c);
      heading.textContent = safeText(c.name);
      put(who, avatar(k, c.name, null, c.did), h('span', { class: 'mid' }, h('b', null, c.name), h('small', { class: c.online ? 'ok' : null }, w ? `your agent${seen ? ` · ${seen}` : ''}` : seen)));
      put(lead, w ? ibtn('gear', 'Agent settings', () => go('agent', w.worker)) : ibtn('plus', 'Attach', () => attach(did)));
      C.text.placeholder = w ? `Message ${c.name}` : 'Message';
      const al = [noteCard()];
      // My agent's payment requests (the mock's chat-scout): in its chat, Allow once or Decline; the request screen has the details.
      if (w) {
        if (S.keeper?.state !== 'elsewhere') await keeperNow().catch(() => null);
        for (const r of requestsOf(w.worker)) {
          const key = `${r.keeper} ${r.nonce}`, a = policyOf(r.worker), cap = a?.approval_above ?? null;
          if (asked.has(key)) continue;
          const answer = (route, word) => act(() => backend.call('POST', route, { keeper: r.keeper, nonce: r.nonce }), (x) => { asked.set(key, word); S.keeperAt = 0; void x; toast(`Done. ${c.name} was told.`); });
          al.push(h('div', { class: 'card ask', 'data-request': key }, h('p', null, h('b', null, `${c.name} wants to pay ${xmr(r.amount)} XMR`), r.purpose ? ` for ${r.purpose}.` : '.',
            cap !== null && cap !== '0' ? ` That's above the ${xmr(cap)} XMR it may spend without asking.` : ''),
          h('div', { class: 'btns' }, btn('Allow once', () => answer('/api/keeper/approve', 'allowed'), { kind: 'pri' }), btn('Decline', () => answer('/api/keeper/refuse', 'declined'))),
          tbtn('Who it pays, and why', () => go('approve', { keeper: r.keeper, nonce: r.nonce }))));
        }
        for (const [key, word] of asked) if (!requestsOf(w.worker).some((r) => `${r.keeper} ${r.nonce}` === key)) asked.delete(key); else al.push(h('div', { class: 'card soft' }, h('p', null, `Done (${word}). ${c.name} was told.`)));
      }
      if (c.status === 'pair_again') al.push(h('div', { class: 'card warn' }, h('p', null, c.re_pair === 'own_recovery' ? 'You recovered your identity: pair again.' : 'They recovered their identity: pair again.'), h('div', { class: 'btns' }, btn('Pair again', () => go('my-code'), { kind: 'pri' }))));
      else if (c.status === 'waiting') al.push(h('div', { class: 'card' }, h('p', null, 'Waiting for their side: messages go once their keys come.')));
      if (c.not_collected) al.push(h('div', { class: 'card' }, h('p', null, 'Not collected yet: their side has not been online since.'), h('div', { class: 'btns' }, btn('Retry now', () => act(() => backend.call('POST', '/api/sync'))))));
      if (!c.words_checked && c.words && !c.local) al.push(h('div', { class: 'card warn' }, h('p', null, 'Compare four words with them to know it\'s really them.'), h('div', { class: 'btns' }, btn('Compare four words', () => go('compare', did), { kind: 'pri' }))));
      put(alerts, ...al.filter(Boolean));
      // Again when the history moved, or their seen receipt did (the ticks).
      const mark = `${S.snap.seq} ${c.seen_upto ?? ''}`;
      if (mark === S.msgsSeq) return;
      S.msgsSeq = mark;
      const r = await backend.call('GET', `/api/messages?contact=${encodeURIComponent(did)}`).catch(() => null);
      if (!r) return;
      const end = first || atEnd();
      first = false;
      // A message of theirs, tapped: who signed it (task 11: the chat, then the message). Every one is signed by
      // their key inside the envelope, checked before it was shown.
      const check = (m) => () => (String(globalThis.getSelection?.() ?? '') ? undefined : go('signed', { did, n: m.n }));
      // A payment of mine told in this chat (UI-API.md "Wallet": `pay` on my message): shown as the payment, its state from History.
      const payState = (p) => { const t = S.hist?.entries?.find((x) => x.txid === p.txid); return t ? (txStatus(t) ?? 'confirmed') : 'sent'; };
      const payBubble = (m) => h('div', { class: 'msg out pay', 'data-pay': m.pay.txid }, h('span', { class: 'tag' }, 'You paid'), h('b', null, `${xmr(m.pay.amount)} XMR`),
        h('span', { class: 'tag' }, [m.pay.note, payState(m.pay)].filter(Boolean).join(' · ')), h('span', { class: 'meta' }, hhmm(m.at), ticks(m)));
      if (r.messages.some((m) => m.pay) && walletOn() && !S.hist && !S.histAsked) { S.histAsked = true; void walletNow().then(() => historyNow()).then((x) => { if (x) { S.msgsSeq = -1; void refresh(); } }); }
      // A signed statement (UI-API.md "Signed statements"): the text as signed, and "Signed by … · check" (task 11: the chat, the link).
      const stBubble = (m) => {
        const v = m.statement, by = v?.by, who = !v?.valid ? null : by?.kind === 'me' ? 'you' : by?.name ? by.name.split(' ')[0] : 'someone you don\'t know';
        return h('div', { class: `msg ${m.dir}`, 'data-statement': String(m.n) }, h('div', { class: 'text' }, v?.valid ? v.text : m.text),
          h('button', { type: 'button', class: `sig${v?.valid ? '' : ' bad'}`, onclick: () => go('statement', { text: m.text }) }, icon('shield'), v?.valid ? `Signed by ${who} · check` : 'Signature not valid · check'),
          h('span', { class: 'meta' }, hhmm(m.at), ticks(m)));
      };
      put(thread, r.messages.length ? threadOf(r.messages, (m) => m.pay ? payBubble(m) : m.statement ? stBubble(m) : h('div', { class: `msg ${m.dir}`, ...(m.dir === 'in' && { role: 'button', tabindex: '0', title: 'Check who signed it', onclick: check(m), onkeydown: (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault?.(); void check(m)(); } } }) },
        m.label && m.label !== 'sigelo-file/0' ? h('span', { class: 'who' }, m.label) : null,
        m.label === 'sigelo-file/0' ? fileText(m.text) : h('div', { class: 'text' }, m.text),
        m.link ? h('span', { class: 'help' }, `Introduced: ${m.link.purpose}`) : null,
        h('span', { class: 'meta' }, hhmm(m.at), ticks(m)))) : h('span', { class: 'day' }, 'No messages yet. Say hello.'));
      if (end) toEnd();
    };
  });

  // Signed message (the mock's verify-result): who signed a message of theirs, from what the carrier checked on arrival
  // (the envelope's signature, by the key their chain ends at) and the four words compared. arg: {did, n}.
  screen('signed', {}, (arg) => {
    const body = h('div', { class: 'pad stack' });
    mount(page({ title: 'Signed message', body: [body] }));
    let r = null;
    return async () => {
      const c = contactBy(arg?.did);
      if (!c) { put(body, empty('Not a contact', 'It was forgotten.')); return; }
      if (!r) r = await backend.call('GET', `/api/messages?contact=${encodeURIComponent(c.did)}`).catch((e) => ({ error: e }));
      const m = r.messages?.find((x) => x.n === arg.n && x.dir === 'in');
      if (!m) { put(body, inlineError(r.error), empty('Not here any more', 'This message was cleared from this device.')); return; }
      const t = m.iat ?? m.at, at = new Date(t * 1000).toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      const kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', null, v));
      put(body, h('div', { class: 'card soft' }, h('p', { class: 'ok big-ok' }, `✓ Signed by ${c.name}`),
        h('p', { class: 'help' }, c.words_checked ? 'Their four words match the ones you compared. Not changed since they signed it.'
          : 'Not changed since they signed it. Compare four words with them to know the key is theirs.')),
        c.words_checked || !c.words || c.local ? null : btn('Compare four words', () => go('compare', c.did), { kind: 'pri' }),
        h('div', { class: 'list' }, kv('Signed', at), kv('By', [c.name, c.words ? ` · ${words4(c.words).join(' ')}` : ''].join(''))),
        h('div', { class: 'card' }, m.label === 'sigelo-file/0' ? fileText(m.text) : h('p', { class: 'text' }, m.text)),
        btn('Check another message', () => go('check')));
    };
  });

  const TIERS = [['own', 'Show them'], ['friend', 'Just a count', 'A notice, read when you open the chat'], ['quiet', 'Quiet', 'Nothing until you open the chat']];
  /** Rename in a sheet: one field, Save. */
  function renameSheet(title, value, save, help) {
    const name = input({ value, maxlength: '64' }), say = h('div');
    const go_ = async () => { try { await save(name.value.trim()); await closeSheet(); await poll(); } catch (e) { put(say, inlineError(e)); } };
    sheet({ title, body: [h('div', { class: 'pad stack' }, field('Name', name, help), say, btn('Save', go_, { kind: 'pri' }))] });
    name.focus?.();
  }
  screen('chat-info', {}, (did) => {
    const body = h('div');
    mount(page({ title: 'Chat settings', body: [body] }));
    return () => {
      const c = contactBy(did);
      if (!c) { put(body, empty('Not a contact', 'It was forgotten.')); return; }
      const block = async () => {
        if (await ask({ title: `Block ${c.name}?`, text: 'This is permanent: they can never pair with you again, and their agents are removed too.', yes: `Block ${c.name}`, no: `Keep ${c.name}` })) {
          void act(() => backend.call('POST', '/api/forget', { contact: did }), () => home());
        }
      };
      const clear = async () => {
        if (await ask({ title: `Clear this chat?`, text: `Every message with ${c.name} kept on this ${LOCAL || SHELL ? 'phone' : 'computer'} is deleted. ${c.name} stays a contact.`, yes: 'Clear this chat', no: 'Keep the messages' })) {
          void act(() => backend.call('POST', '/api/history/clear', { contact: did }), () => toast('Chat cleared.'));
        }
      };
      put(body, noteCard(),
        h('div', { class: 'pad ident' }, picButton(kindOf(c), c.name, did, `Picture for ${c.name}`), h('h3', null, c.name), c.words ? fourWords(c.words) : null,
          c.words_checked ? h('p', { class: 'ok' }, '✓ Words compared') : c.words && !c.local ? btn('Compare four words', () => go('compare', did), { auto: true }) : null),
        list(row({ compact: true, start: icon('chat'), title: 'Message', onclick: () => back() }),
          walletOn() ? row({ compact: true, start: icon('coin'), title: 'Pay', onclick: () => pay(did) }) : null,
          // Their agents (People and teams): the ones they introduced to you, paired or waiting for your answer.
          kindOf(c) === 'person' ? row({ compact: true, start: icon('agent'), title: 'Their agents', sub: agentsLine(c), chev: true, onclick: () => go('person', did) }) : null,
          row({ compact: true, start: icon('link'), title: 'Introduce to someone', chev: true, onclick: () => go('introduce', did) })),
        sec('Their messages'),
        radios('Their messages', TIERS, c.tier, (t) => act(() => backend.call('POST', '/api/tier', { contact: did, tier: t }))),
        h('div', { class: 'list' },
          toggle('Sees when I\'m online', c.presence === 'own' ? 'Your own agent always sees it.' : null, c.presence !== 'deny', (allow) => act(() => backend.call('POST', '/api/presence', { contact: did, allow })), { disabled: c.presence === 'own' }),
          // This chat's system notifications (NOTIFICATIONS below: the sender's name only, never the text) and its count.
          toggle('Notifications', muted(c) ? 'Off: no count on the Chats tab' : 'The sender\'s name only, never the text', !muted(c), (on) => act(() => backend.call('POST', '/api/notify', { chat: did, on }))),
          // Its kind (UI-API.md "Kinds"): the agent mark in the lists; derived by the page, or set here.
          toggle('This is an agent', c.kind_set ? 'You set this' : kindOf(c) === 'agent' ? 'Known from its pairing' : 'Shows the agent mark in your chats', kindOf(c) === 'agent',
            (on) => act(() => backend.call('POST', '/api/kind', { contact: did, kind: on ? 'agent' : 'person' }))),
          row({ compact: true, title: 'Rename', sub: c.name, chev: true, onclick: () => renameSheet(`Rename ${c.name}`, c.name, (name) => backend.call('POST', '/api/rename', { contact: did, name })) }),
          row({ compact: true, title: 'Clear this chat', onclick: clear })),
        h('div', { class: 'pad' }, btn(`Block ${c.name}…`, block, { kind: 'danger' }), h('p', { class: 'help center' }, 'Permanent: they can never pair with you again.')));
    };
  });

  // ---- Introduce to someone (LINKS.md): two contacts, one of them yours; the links made; who is accepted without asking
  const DAYS = [['', 'No end'], ['1', '1 day'], ['7', '7 days'], ['30', '30 days'], ['90', '90 days']];
  const select = (label, options, value) => { const el = h('select', { 'aria-label': label }, options.map(([v, t]) => h('option', { value: v }, t))); el.value = value; return el; };
  screen('introduce', {}, (first) => {
    const made = h('div'), mine = h('div'), rules = h('div'), say = h('div'), extra = h('div');
    const aSel = h('select', { 'aria-label': 'First' }), bSel = h('select', { 'aria-label': 'Second' });
    const purpose = input({ maxlength: '120', placeholder: 'review the pull requests' }), note = h('textarea', { rows: 2, maxlength: '280', placeholder: 'Optional' });
    const days = select('Ends', DAYS, '30'), tierA = select('How yours files the other', [['', 'As usual'], ['friend', 'Just a count'], ['quiet', 'Quiet']], '');
    const tierB = select('How the second files the first', [['', 'As usual'], ['friend', 'Just a count'], ['quiet', 'Quiet']], '');
    const nameB = input({ autocapitalize: 'none', maxlength: '64' }), nameA = input({ autocapitalize: 'none', maxlength: '64' });
    let names = '';
    const pick = () => [contactBy(aSel.value), contactBy(bSel.value)];
    // External (one of them not yours): a note, their tier is theirs to choose; both yours: both tiers.
    const shape = () => {
      const [a, b] = pick(), external = a && b && a.ours !== b.ours, none = a && b && !a.ours && !b.ours;
      nameB.placeholder = b?.name ?? ''; nameA.placeholder = a?.name ?? '';
      put(extra, h('div', { class: 'stack' }, none ? h('p', { class: 'warn' }, 'One of the two must be yours (run by you).') : null,
        field('What the first calls the second', nameB, 'Blank: your name for it.'), field('What the second calls the first', nameA), field('How yours files the other', tierA),
        external ? field('Note for them (they see it, with your agent\'s identity)', note) : field('How the second files the first', tierB)));
    };
    aSel.addEventListener('change', shape); bSel.addEventListener('change', shape);
    const link = async () => {
      const [a, b] = pick();
      if (!a || !b || a.did === b.did || !purpose.value.trim()) { put(say, inlineError({ message: 'Pick two different contacts and say what for.' })); return; }
      const external = a.ours !== b.ours, theirs = external ? (a.ours ? b : a) : null, yours = external ? (a.ours ? a : b) : null;
      if (!(await ask({ title: `Introduce ${a.name} and ${b.name}?`, text: `For: ${purpose.value.trim()}.${theirs ? ` ${theirs.name} learns ${yours.name}'s identity, the purpose and your note.` : ''}`, yes: 'Introduce them', danger: false }))) return;
      await act(() => backend.call('POST', '/api/link', { a: a.did, b: b.did, purpose: purpose.value.trim(), ...(days.value && { days: Number(days.value) }),
        ...(tierA.value && { tier_a: tierA.value }), ...(!external && tierB.value && { tier_b: tierB.value }), ...(external && note.value.trim() && { note: note.value.trim() }),
        ...(nameA.value.trim() && { name_a: nameA.value.trim() }), ...(nameB.value.trim() && { name_b: nameB.value.trim() }) }),
      (r) => { purpose.value = ''; note.value = ''; nameA.value = ''; nameB.value = ''; put(say, h('p', { class: 'ok' }, `Asked ${r.a_name} for a one-use code for ${r.b_name}. It shows below as it goes.`)); });
    };
    mount(page({ title: 'Introduce to someone', body: [h('div', { class: 'pad stack' }, field('First', aSel), field('Second', bSel), field('What for', purpose, 'Up to 120 characters.'), field('Ends', days), extra, say),
      sec('Introductions you made'), made, sec('Introduced to you'), mine, sec('Accepted without asking'), rules], foot: [btn('Introduce them', link, { kind: 'pri' })] }));
    return async () => {
      const cs = allContacts(), now = cs.map((c) => c.did + c.name).join();
      if (now !== names) {
        names = now;
        const opts = cs.map((c) => h('option', { value: c.did }, `${c.name}${c.ours ? ' (yours)' : ''}`));
        const [va, vb] = [aSel.value, bSel.value];
        put(aSel, opts); put(bSel, opts.map((o) => o.cloneNode?.(true) ?? h('option', { value: o.value }, o.textContent)));
        aSel.value = va || first || cs.find((c) => c.ours)?.did || ''; bSel.value = vb || cs.find((c) => c.did !== aSel.value)?.did || '';
        shape();
      }
      const L = await backend.call('GET', '/api/links').catch((e) => { S.note = e; return null; });
      if (!L) { put(say, noteCard()); return; }
      const until = (t) => (t ? `until ${when(t)}` : 'no end');
      const step = (l) => (l.status !== 'pending' ? l.status : l.step === 'ask' ? `waiting for ${l.a_name}` : `waiting for ${l.b_name}`);
      put(made, list(L.made.map((l) => row({ title: `${l.a_name} and ${l.b_name}`, sub: `${l.purpose} · ${step(l)} · ${until(l.expires)}`,
        end: l.status === 'pending' || l.status === 'linked' ? tbtn('Undo', async () => { if (await ask({ title: `Undo ${l.a_name} and ${l.b_name}?`, text: 'Both forget each other.', yes: 'Undo the introduction' })) void act(() => backend.call('POST', '/api/unlink', { id: l.id })); }) : null })))
        ?? h('p', { class: 'help pad' }, 'None yet.'));
      put(mine, list(L.links.map((l) => row({ title: l.name, sub: `${l.purpose} · ${until(l.expires)}`,
        end: tbtn('End', async () => { if (await ask({ title: `End the introduction with ${l.name}?`, text: 'You both forget each other.', yes: 'End it' })) void act(() => backend.call('POST', '/api/unlink', { id: l.id })); }) }))) ?? h('p', { class: 'help pad' }, 'None.'));
      put(rules, list(L.allow.map((r) => row({ title: r.name ?? r.contact, sub: `${r.tier}, ${until(r.until)}`, end: tbtn('Stop', () => act(() => backend.call('POST', '/api/links/allow', { contact: r.contact, allow: false }))) })))
        ?? h('p', { class: 'help pad' }, 'None: each introduction waits for your answer.'));
    };
  });

  // ---- Files (TRANSFER.md): big files with a contact, direct or over Tor; the relay carries only the introduction.
  // Where the page's host moves files (state.transfers not null). Sending takes a path on this computer (never remote).
  const mbOf = (n) => `${(n / 1e6).toFixed(1)} MB`;
  // An answer that needs the direct question (direct_ask): asked here, once for that contact, then sent again.
  async function transferCall(path, body, who) {
    try { return await backend.call('POST', path, body); } catch (e) {
      if (e?.check !== 'direct_ask') throw e;
      const yes = await ask({ title: `Direct with ${who}?`, text: `A direct transfer shows ${who} this computer's public and local network addresses (faster). Tor only is slower, the address hidden.`, yes: 'Allow direct', no: 'Tor only', danger: false });
      return backend.call('POST', path, { ...body, direct: yes });
    }
  }
  const TSTATE = { asked: 'waiting for your answer', offered: 'waiting for their answer', accepted: 'starting', offering: 'connecting', active: 'moving', interrupted: 'stopped', done: 'done', declined: 'declined', cancelled: 'cancelled', failed: 'failed', expired: 'expired' };
  function transferCard(r, side) {
    const got = side === 'in' ? r.got ?? 0 : r.sent ?? 0, pct = r.size ? Math.min(100, Math.round((100 * got) / r.size)) : 100;
    const bar = h('i'); bar.style.width = `${pct}%`;
    const live = r.live && r.state !== 'done', btns = [];
    if (side === 'in' && r.state === 'asked') {
      btns.push(btn('Accept', () => act(() => transferCall('/api/transfers/accept', { id: r.id }, r.contact)), { kind: 'pri' }), btn('Decline', () => act(() => backend.call('POST', '/api/transfers/decline', { id: r.id }))));
    }
    if (side === 'in' && (r.state === 'interrupted' || (r.state === 'failed' && ['no_path', 'tor'].includes(r.reason)))) btns.push(btn('Resume', () => act(() => transferCall('/api/transfers/resume', { id: r.id }, r.contact))));
    if (['asked', 'offered', 'accepted', 'offering', 'active', 'interrupted'].includes(r.state) && !(side === 'in' && r.state === 'asked')) {
      btns.push(btn('Stop', async () => { if (await ask({ title: `Stop ${r.name}?`, text: 'The contact is told; what came so far is deleted.', yes: 'Stop it' })) void act(() => backend.call('POST', '/api/transfers/cancel', { id: r.id })); }, { kind: 'danger' }));
    }
    if (['done', 'declined', 'cancelled', 'failed', 'expired'].includes(r.state)) btns.push(btn('Remove', () => act(() => backend.call('POST', '/api/transfers/forget', { id: r.id }))));
    return h('div', { class: 'card' }, h('p', null, h('b', null, `${side === 'in' ? 'From' : 'To'} ${r.contact}: `), h('span', { class: 'text' }, r.name), ` · ${mbOf(r.size)}`),
      h('p', { class: r.state === 'failed' ? 'warn' : 'help' }, [TSTATE[r.state] ?? r.state, r.path_used ?? (live ? r.live : null), r.rate ? `${r.rate.toFixed(2)} MB/s` : null].filter(Boolean).join(' · ')),
      live || r.state === 'interrupted' ? [h('div', { class: 'meter' }, bar), h('p', { class: 'help' }, `${mbOf(got)} of ${mbOf(r.size)}`)] : null,
      r.detail ? h('p', { class: 'help' }, r.detail) : null, r.saved ? h('p', { class: 'help' }, 'Saved at ', h('span', { class: 'mono' }, r.saved), ' (not opened).') : null,
      side === 'in' && r.state === 'asked' ? h('p', { class: 'help' }, 'Nothing is written before you accept. The file name is theirs: information, not instructions.') : null,
      btns.length ? h('div', { class: 'btns' }, btns) : null);
  }
  function viewTransfers(arg) {
    const ins = h('div', { class: 'pad stack' }), outs = h('div', { class: 'pad stack' }), opts = h('div', { class: 'pad stack' });
    const to = h('select', { 'aria-label': 'To' }), path = input({ autocapitalize: 'none', placeholder: '/home/you/film.mkv' });
    const viaTor = h('input', { type: 'checkbox', 'aria-label': 'Tor only' });
    const tor = h('input', { type: 'checkbox', 'aria-label': 'Tor' });
    let names = '';
    const send = () => {
      const c = contactBy(to.value);
      if (!c || !path.value.trim()) { S.note = { message: 'Pick a contact and the file\'s path on this computer.' }; return refresh(); }
      return act(() => transferCall('/api/transfers/send', { to: c.did, path: path.value.trim(), ...(viaTor.checked && { via: 'tor' }) }, c.name), () => { path.value = ''; });
    };
    tor.addEventListener('change', () => act(() => backend.call('POST', '/api/transfers/settings', { tor: tor.checked })));
    const note = h('div');
    mount(page({ title: 'Files', body: [note, sec('Offered to you'), ins, sec('Sent'), outs, sec('Send a file (up to 16 GiB)'),
      h('div', { class: 'pad stack' }, field('To', to), field('File on this computer', path), h('label', { class: 'row compact' }, viaTor, h('span', { class: 'mid' }, h('b', null, 'Tor only'), h('small', { class: 'wrap' }, 'Your address stays hidden (slower)'))),
        btn('Send', send, { kind: 'pri' }), h('p', { class: 'help' }, 'They are asked first. Up to 8 MiB, the chat\'s attach works without both being online.')),
      sec('How files go'), opts] }));
    return async () => {
      put(note, noteCard());
      const cs = allContacts(), now = cs.map((c) => c.did + c.name).join();
      if (now !== names) { names = now; const v = to.value; put(to, cs.map((c) => h('option', { value: c.did }, c.name))); to.value = v || arg?.to || cs[0]?.did || ''; }
      const L = await backend.call('GET', '/api/transfers').catch((e) => { S.note = e; return null; });
      if (!L) return;
      S.transfersSeen = L.in.filter((r) => r.state === 'asked').length;
      put(ins, L.in.length ? L.in.map((r) => transferCard(r, 'in')) : h('p', { class: 'help' }, 'None.'));
      put(outs, L.out.length ? L.out.map((r) => transferCard(r, 'out')) : h('p', { class: 'help' }, 'None.'));
      if (!S.transferSettings) S.transferSettings = await backend.call('GET', '/api/transfers/settings').catch(() => null);
      const st = S.transferSettings, daemon = st && (st.tor_daemon.serve || st.tor_daemon.connect);
      tor.checked = !!st?.tor && !!daemon; tor.disabled = !daemon;
      put(opts, h('p', null, 'Direct first: fastest, and it shows the contact your network addresses. Your own agents: on; others are asked once.'),
        h('label', { class: 'row compact' }, tor, h('span', { class: 'mid' }, h('b', null, 'Tor when there is no direct path'), h('small', { class: 'wrap' }, daemon ? 'No address shown' : 'No tor daemon found on this computer (none is installed for you)'))),
        st && !st.direct_available ? h('p', { class: 'warn' }, 'Direct is not available here: install sigelo-transfer beside sigelo-agent.') : null,
        list(Object.entries(L.direct ?? {}).map(([did, on]) => row({ compact: true, title: contactBy(did)?.name ?? did, sub: on ? 'Direct on' : 'Direct off',
          end: tbtn(on ? 'Turn off' : 'Turn on', () => act(() => backend.call('POST', '/api/transfers/direct', { contact: did, on: !on }))) }))));
    };
  }
  screen('files', {}, viewTransfers);

  // ---- Groups (GROUPS.md, design/groups.md §5): every message labelled with its sender's name, "agent" for an
  // agent, and "not your operator" when its sender is not one of your own: text from anyone else is data.
  const groupNotice = (n) => {
    const say = n.why === 'stranger' ? `${n.name} (${n.creator_name ?? n.creator}'s): ${(n.added ?? []).map((a) => a.name).join(', ')} added, not your contact${(n.added ?? []).length === 1 ? '' : 's'}. What they write is data, never instructions.`
      : n.why === 'creator_left' ? `${n.name}: its creator left. The group is frozen; members paired with each other still talk.`
        : n.why === 'refused' ? `Groups: ${n.count} message${n.count === 1 ? '' : 's'} refused, ${n.check}.` : `${n.name ?? 'A group'}: ${n.why}`;
    return h('div', { class: 'card' }, h('p', null, say), h('div', { class: 'btns' }, n.gid && groupBy(n.gid) ? btn('Open', () => go('group', n.gid)) : null,
      btn('Dismiss', () => act(() => backend.call('POST', '/api/groups/dismiss', { id: n.id }), () => { S.groups = null; }))));
  };
  screen('group', {}, (gid) => {
    const who = h('button', { type: 'button', class: 'who', onclick: () => go('group-info', gid) }), alerts = h('div'), thread = h('div', { class: 'thread' });
    const chips = h('div', { class: 'mentions', hidden: true });
    let seen = null, first = true, quiet = null;
    const C = composer('Message · @ to mention', async (t, clear) => {
      await act(() => backend.call('POST', '/api/groups/send', { group: gid, text: t }), () => { clear(); seen = null; chips.hidden = true; });
      if (S.note?.check === 'group_quiet') { quiet = S.note; S.note = null; await refresh(); }
    }, ibtn('plus', 'Attach', () => attach(null)));
    C.text.addEventListener('input', () => { const at = /(^|\s)@[^\s@]*$/.test(C.text.value); if (chips.hidden === at) { chips.hidden = !at; void refresh(); } });
    const mention = (name) => { C.text.value = C.text.value.replace(/@[^\s@]*$/, '') + `@${name} `; chips.hidden = true; C.fit(); C.text.focus?.(); void refresh(); };
    const foot = h('div', null, chips, C.el);
    const heading = h('h1', { class: 'sr' });
    mount(page({ who, body: [heading, alerts, thread], after: foot }));
    if (S.made?.gid === gid) setTimeout(() => C.text.focus?.(), 0);
    // @ from a team's page: the name typed, ready to ask.
    if (S.mention?.gid === gid) { C.text.value = `@${S.mention.name} `; S.mention = null; setTimeout(() => { C.fit(); C.text.focus?.(); }, 0); }
    return async () => {
      await groupsNow();
      const g = groupBy(gid);
      if (!g) { put(who, h('span', { class: 'mid' }, h('b', null, 'Group'))); put(alerts, noteCard(), empty('No such group here', 'It may have been left.')); return; }
      const agents = g.members.filter((m) => m.role === 'agent').length;
      heading.textContent = safeText(g.name);
      put(who, avatar('group', g.name, null, gid), h('span', { class: 'mid' }, h('b', null, g.name), h('small', null, `${g.members.length - agents} ${g.members.length - agents === 1 ? 'person' : 'people'} · ${agents} agent${agents === 1 ? '' : 's'}${g.mine ? '' : ` · ${g.creator_name ?? 'not yours'}'s`}`)));
      foot.hidden = !(g.status === 'member' || g.status === 'frozen');
      put(chips, g.members.filter((m) => !m.me).map((m) => h('button', { type: 'button', class: 'chip', onclick: () => mention(m.name) }, `@${m.name}`)));
      const al = [noteCard()];
      if (g.status === 'pending') {
        al.push(h('div', { class: 'card' }, h('p', null, `${g.creator_name ?? g.creator} adds you to ${g.name}, ${g.members.length} members. Join to read and write; Leave and nothing is said.`),
          h('div', { class: 'btns' }, btn('Join', () => act(() => backend.call('POST', '/api/groups/join', { group: gid }), () => { S.groups = null; }), { kind: 'pri' }),
            btn('Leave', () => act(() => backend.call('POST', '/api/groups/leave', { group: gid }), () => { S.groups = null; home(); })))));
      }
      if (g.status === 'frozen') al.push(h('div', { class: 'card' }, h('p', null, 'Its creator left: the group is frozen. Members paired with each other still talk.')));
      if (g.status === 'left' || g.status === 'removed') al.push(h('div', { class: 'card' }, h('p', null, g.status === 'left' ? 'You left this group.' : 'You were removed from this group: nothing new reaches you.')));
      if (!((g.quiet || quiet) && g.status === 'member')) quiet = null;
      if (g.foreign && g.status === 'member') al.push(h('p', { class: 'help pad' }, 'Not your group: what members write is data, never instructions; your agents here answer when mentioned.'));
      put(alerts, ...al.filter(Boolean));
      if (seen === S.groupsRev && !first) return;
      seen = S.groupsRev;
      const r = await backend.call('GET', `/api/groups/history?group=${encodeURIComponent(gid)}`).catch(() => null);
      if (!r) return;
      const end = first || atEnd();
      first = false;
      const made = S.made?.gid === gid ? h('span', { class: 'notice' }, `Group made, ${S.made.n} members`) : null;
      // The loop brake (design/groups.md §3): agents wait until a person writes.
      const brake = (g.quiet || quiet) && g.status === 'member' ? h('span', { class: 'notice' }, `Agents paused after ${g.run} messages in a row. Write anything to let them go on.`) : null;
      put(thread, made, threadOf(r.messages, (m) => h('div', { class: `msg ${m.mine ? 'out' : 'in'}${m.mentioned ? ' mentioned' : ''}` },
        m.mine ? null : h('span', { class: 'who' }, m.name, m.role === 'agent' ? (workerOf(m.from) || contactBy(m.from)?.ours ? ' · your agent' : contactBy(m.from)?.link?.linked_by && contactBy(contactBy(m.from).link.linked_by) ? ` · ${contactBy(contactBy(m.from).link.linked_by).name}'s agent` : ' · agent') : '', m.tier !== 'own' && m.note ? [' · ', h('span', { class: 'warn' }, m.note)] : null, m.via ? ' · via the creator' : null),
        m.mentioned ? h('span', { class: 'help' }, 'Mentions you') : null, h('div', { class: 'text' }, m.text), h('span', { class: 'meta' }, hhmm(m.at)))),
      brake, !r.messages.length && !made ? h('span', { class: 'day' }, 'No messages yet.') : null);
      if (end) toEnd();
    };
  });

  // Group info: people and agents, Add people, rename, the brake, leave; a member's changes are the creator's.
  screen('group-info', {}, (gid) => {
    const body = h('div'), title = h('h1', null, 'Group');
    mount(page({ who: title, body: [body] }));
    const call = (path, b, after) => act(() => backend.call('POST', path, { group: gid, ...b }), (r) => { S.groups = null; return after?.(r); });
    return async () => {
      const G = await groupsNow(), g = groupBy(gid);
      if (!g) { put(body, empty('No such group here', 'It may have been left.')); return; }
      title.textContent = safeText(g.name);
      const mine = g.mine && g.status === 'member', max = G.tier?.members ?? 8;
      const memberSheet = (m) => sheet({ title: m.name, body: [list(
        row({ compact: true, title: m.role === 'agent' ? 'Count it as a person' : 'Count it as an agent', sub: 'The pause counts agents in a row', onclick: () => closeSheet().then(() => call('/api/groups/role', { member: m.did, role: m.role === 'agent' ? 'human' : 'agent' })) }),
        row({ compact: true, title: 'Send the group to it again', sub: 'A new device, a lost copy', onclick: () => closeSheet().then(() => call('/api/groups/share', { member: m.did }, () => toast(`Sent to ${m.name}`))) }),
        row({ compact: true, title: h('span', { class: 'danger' }, `Remove ${m.name}…`), onclick: async () => { await closeSheet(); if (await ask({ title: `Remove ${m.name} from ${g.name}?`, text: 'They keep what was said before.', yes: `Remove ${m.name}` })) void call('/api/groups/remove', { members: [m.did] }); } }))] });
      const member = (m) => {
        const c = contactBy(m.did), by = c?.link?.linked_by ? contactBy(c.link.linked_by) : null, w = workerOf(m.did);
        const sub = m.me ? null : m.did === g.creator ? 'made it' : !m.contact ? `not paired with you · added by ${g.creator_name ?? 'the creator'}` : c?.ours || w ? 'yours' : by ? `${by.name}'s` : null;
        // The mock's: a person opens their page, an agent of mine its page; the creator's changes (role, remove) in the member's sheet.
        const open = m.me ? undefined : mine ? () => memberSheet(m) : w ? () => go('agent', w.worker) : m.contact && c ? () => go(kindOf(c) === 'agent' ? 'chat-info' : 'person', m.did) : undefined;
        return row({ compact: true, start: avatar(m.role === 'agent' ? 'agent' : 'person', m.name, null, m.me ? 'me' : m.contact ? m.did : null), title: m.me ? 'You' : m.name, sub, attrs: { 'data-member': m.did },
          onclick: open, chev: Boolean(open) });
      };
      const people = g.members.filter((m) => m.role !== 'agent'), agents = g.members.filter((m) => m.role === 'agent');
      const brakeOn = g.brake !== 'off', n = brakeOn ? g.brake : 20;
      put(body, noteCard(),
        h('div', { class: 'pad ident' }, picButton('group', g.name, gid, `Picture for ${g.name}`), h('h3', null, g.name), h('p', { class: 'help' }, isTeam(g) ? 'A team: people and their agents' : 'A group')),
        sec('People'), list(people.map(member)) ?? h('p', { class: 'help pad' }, 'None.'),
        sec('Agents'), list(agents.map(member)) ?? h('p', { class: 'help pad' }, 'None.'),
        h('p', { class: 'help pad' }, `${g.members.length} of ${max} · ${g.mine ? 'made by you' : `made by ${g.creator_name ?? g.creator}`}`),
        mine ? h('div', { class: 'pad' }, btn('Add people', () => go('group-new', gid), { ic: 'plus', disabled: g.members.length >= max })) : null,
        h('div', { class: 'list' },
          toggle(`Pause agents after ${n} in a row`, mine ? 'Stops agents talking in circles until a person writes.' : 'Set by the group\'s creator.', brakeOn,
            (on) => call('/api/groups/brake', { brake: on ? n : 'off' }), { disabled: !mine }),
          toggle('Notifications', muted(g) ? 'Off: no count on the Chats tab' : 'The sender\'s name only, never the text', !muted(g), (on) => act(() => backend.call('POST', '/api/notify', { chat: gid, on }), () => { S.groups = null; })),
          mine ? row({ compact: true, title: 'Rename', sub: g.name, chev: true, onclick: () => renameSheet(`Rename ${g.name}`, g.name, (name) => backend.call('POST', '/api/groups/rename', { group: gid, name }).then(() => { S.groups = null; })) }) : null),
        g.status === 'member' || g.status === 'frozen' || g.status === 'pending' ? h('div', { class: 'pad' }, btn('Leave group', async () => {
          if (await ask({ title: `Leave ${g.name}?`, text: g.mine ? 'You made it: it freezes for everyone. You stop getting its messages.' : 'You stop getting its messages. Someone in it can add you again.', yes: 'Leave group', no: 'Stay' })) void call('/api/groups/leave', {}, () => home());
        }, { kind: 'danger' })) : null);
    };
  });

  // New group, and the same screen as Add people (arg: a gid): a name (new only), then the contacts with a tick
  // each: own agents first (preselected when at most three), people, quiet ones last and unticked; "n of 8".
  // Roles are preset (own agents agent, everyone else a person), the pause at its default: both under the group's info.
  screen('group-new', {}, (addTo) => {
    const adding = typeof addTo === 'string', ticked = new Set(), boxes = new Map();
    const nameIn = input({ maxlength: '40', placeholder: 'Trip to Porto' }), body = h('div'), counter = h('div', { class: 'help center', 'aria-live': 'polite' });
    const peopleList = h('div', { class: 'list' }), agentList = h('div', { class: 'list' }), rowsOf = new Map();
    let filled = false;
    // Add people: someone not in my contacts pairs through a group code and joins (POST /api/invite {group}).
    const GC = { inv: null, busy: false, error: null }, codeCard = h('div', { class: 'card' });
    const makeGroupCode = async () => {
      GC.busy = true; GC.error = null; await refresh();
      try { GC.inv = await started('POST', '/api/invite', { group: addTo }); } catch (e) { GC.error = e; }
      GC.busy = false; await refresh();
    };
    const drawCode = () => {
      const inv = GC.inv, live = inv && (inv.short_exp ?? inv.exp) > relayNow(), shown = inv?.short ?? inv?.code;
      if (live) {
        put(codeCard, h('div', { class: 'center stack' }, h('p', { class: inv.short ? 'code' : 'mono' }, shown), h('p', { class: 'help' }, 'Works once, for ', countdown(inv.short_exp ?? inv.exp)),
          h('div', { class: 'btns' }, btn('Share', () => share(pairMessage(shown, inv.short_exp ?? inv.exp)), { kind: 'pri' }), btn('Copy', () => copy(shown)))));
        return;
      }
      put(codeCard, h('p', null, 'Make a group code. Whoever uses it pairs with you and joins the group.'), inlineError(GC.error),
        h('div', { class: 'btns' }, btn(GC.busy ? 'Making…' : inv ? 'Make a new group code' : 'Make a group code', makeGroupCode, { disabled: GC.busy })));
    };
    const goBtn = btn(adding ? 'Add' : 'Create group', null, { kind: 'pri' });
    mount(page({ title: adding ? 'Add people' : 'New group', body: [adding ? null : h('div', { class: 'pad' }, field('Group name', nameIn)), body], foot: [counter, goBtn] }));
    const contactsOf = () => {
      const { mine, contacts } = S.snap.groups;
      return [...mine.map((c) => ({ c, own: true })), ...contacts.filter((c) => c.tier !== 'quiet').map((c) => ({ c, own: false })), ...contacts.filter((c) => c.tier === 'quiet').map((c) => ({ c, own: false }))];
    };
    nameIn.addEventListener('input', () => refresh());
    goBtn.addEventListener('click', () => {
      const all = contactsOf(), members = [...ticked], humans = members.filter((d) => !all.find((x) => x.c.did === d)?.own);
      goBtn.disabled = true;
      void act(() => (adding ? backend.call('POST', '/api/groups/add', { group: addTo, members, humans }) : backend.call('POST', '/api/groups/create', { name: nameIn.value.trim(), members, humans })),
        (r) => {
          S.groups = null;
          if (adding) return back();
          // The chat at once, in place of this screen: Back from it goes to the list.
          S.made = { gid: r.group.gid, n: r.group.members.length };
          return swap('group', r.group.gid);
        });
    });
    return async () => {
      put(counter, noteCard());
      if (!S.snap) return;
      const G = await groupsNow(), t = G.tier ?? { members: 8, groups: 3 }, g = adding ? groupBy(addTo) : null;
      if (adding && !g) { put(body, empty('No such group here', 'It may have been left.')); return; }
      const inIt = new Set(g ? g.members.map((m) => m.did) : []), have = g ? g.members.length : 1;
      const all = contactsOf().filter(({ c }) => !c.revoked);
      if (!filled) {
        filled = true;
        const own = all.filter((x) => x.own && !inIt.has(x.c.did));
        if (!adding && own.length <= 3) for (const x of own) ticked.add(x.c.did);
        if (!adding) nameIn.focus?.();
      }
      const pick = ({ c, own }) => {
        const was = inIt.has(c.did);
        let box = boxes.get(c.did);
        if (!box) {
          box = h('input', { type: 'checkbox', 'aria-label': c.name });
          box.addEventListener('change', () => { if (box.checked) ticked.add(c.did); else ticked.delete(c.did); void refresh(); });
          boxes.set(c.did, box);
        }
        box.checked = was || ticked.has(c.did);
        box.disabled = was;
        const key = `${c.did} ${c.name} ${was}`;
        if (rowsOf.get(c.did)?.key !== key) rowsOf.set(c.did, { key, el: h('label', { class: 'row compact' }, avatar(own ? 'agent' : kindOf(c), c.name, null, c.did), h('span', { class: 'mid' }, h('b', null, c.name), h('small', null, was ? 'in it' : own ? [h('span', { class: 'kind' }, 'Agent'), ' · yours'] : kindOf(c) === 'agent' ? [h('span', { class: 'kind' }, 'Agent'), c.link?.linked_by && contactBy(c.link.linked_by) ? ` · ${contactBy(c.link.linked_by).name}'s` : ''] : c.tier === 'quiet' ? 'quiet' : '')), box) });
        return rowsOf.get(c.did).el;
      };
      const own = all.filter((x) => x.own), others = all.filter((x) => !x.own);
      put(peopleList, others.map(pick)); put(agentList, own.map(pick));
      if (adding) drawCode();
      put(body, all.length === 0 && !adding ? empty('No contacts yet', 'A group is made of your contacts. Pair with someone first.', btn('Start a chat', openNewChat, { kind: 'pri' })) : null,
        adding && all.length ? sec('From your contacts') : null,
        others.length ? [adding ? null : sec('People'), peopleList] : null, own.length ? [sec('Agents'), agentList] : null,
        adding ? [sec('Someone not in your contacts'), codeCard] : null);
      const n = have + ticked.size;
      put(counter, noteCard(), h('span', { class: n > t.members ? 'warn' : null }, `${n} of ${t.members}`));
      goBtn.disabled = ticked.size === 0 || n > t.members || (!adding && nameIn.value.trim() === '');
      if (adding) goBtn.textContent = ticked.size === 0 ? 'Add people' : ticked.size === 1 ? 'Add 1 person' : `Add ${ticked.size} people`;
    };
  });

  // ================================================================ AGENTS (ENROL.md): the keeper's workers; enrol one; its page
  const WHERE = { remote: 'on another machine', here: 'on this machine', device: 'a device' };
  // Enrol is ready when there is a keeper root and the seat is here (worker indices are given there).
  const canEnrol = (W) => W?.keeper === true && W.seat !== 'elsewhere';
  // ---- the keeper (UI-API.md "Keeper"): the allowances, the limits per agent and the payment requests, where sigelo-spend
  // runs. `here`: this computer's keeper, read and written; `elsewhere` (this app), `none`, `unreadable`: set on that computer.
  async function keeperNow(force = false) {
    if (!force && S.keeper && Date.now() - S.keeperAt < 10000) return S.keeper;
    try { S.keeper = await backend.call('GET', '/api/keeper'); } catch (e) { S.keeper = { state: e.status === 404 ? 'elsewhere' : 'error', error: e }; }
    S.keeperAt = Date.now();
    return S.keeper;
  }
  const keeperHere = () => (S.keeper?.state === 'here' ? S.keeper : null);
  const policyOf = (i) => keeperHere()?.agents.find((a) => a.worker === i) ?? null;
  const keeperById = (id) => keeperHere()?.keepers.find((k) => k.id === id) ?? null;
  const requestsOf = (i) => (keeperHere()?.requests ?? []).filter((r) => i === undefined || r.worker === i);
  // Amounts: the keeper's atomic units (12 decimals) as XMR, at least two decimals ("0.12", "0.004"); typed XMR back to atomic.
  const PICO = 10n ** 12n;
  function xmr(a) {
    let n;
    try { n = BigInt(a); } catch { return '?'; }
    const f = (n % PICO).toString().padStart(12, '0').replace(/0+$/, '');
    return `${n / PICO}.${f.length < 2 ? f.padEnd(2, '0') : f}`;
  }
  const atomicOf = (s) => {
    const m = /^\s*(\d{1,7})(?:[.,](\d{0,12}))?\s*$/.exec(String(s ?? ''));
    return m ? String(BigInt(m[1]) * PICO + BigInt((m[2] ?? '').padEnd(12, '0') || '0')) : null;
  };
  const PERIODS = [[86400, 'A day', 'today'], [604800, 'A week', 'this week'], [2592000, 'A month (30 days)', 'this month'], [3600, 'An hour', 'this hour']];
  const periodWord = (s) => PERIODS.find(([v]) => v === s)?.[2] ?? `in ${Math.round(s / 3600)} h`;
  const allowanceText = (a) => `${xmr(a.spent)} of ${xmr(a.per_period_max)} XMR ${periodWord(a.period_seconds)}`;
  const asksText = (a) => (a.approval_above === null ? 'Never asks you' : a.approval_above === '0' ? 'Asks you every time' : `Asks you above ${xmr(a.approval_above)} XMR`);
  const meter = (spent, cap) => {
    let pct = 0;
    try { const c = BigInt(cap); pct = c > 0n ? Number((BigInt(spent) * 100n) / c) : 0; } catch {}
    const bar = h('i'); bar.style.width = `${Math.min(100, pct)}%`;
    return h('div', { class: 'meter', role: 'progressbar', 'aria-valuenow': String(Math.min(100, pct)), 'aria-valuemin': '0', 'aria-valuemax': '100' }, bar);
  };
  /** Where the limits are when this page cannot set them: said once, plainly (the keeper's state). */
  function keeperAway(K) {
    if (K?.state === 'elsewhere') return h('div', { class: 'card' }, h('p', null, 'Set this on the computer that runs the keeper.'), h('p', { class: 'help' }, 'Allowances and limits live with the keeper (sigelo-spend), not in this app.'));
    if (K?.state === 'none') return h('div', { class: 'card' }, h('p', null, 'No keeper on this computer.'), h('p', { class: 'help' }, 'Set allowances on the computer that runs the keeper (sigelo-spend).'));
    if (K?.state === 'unreadable') return h('div', { class: 'card warn' }, h('p', null, 'This page can\'t read the keeper here.'), h('p', { class: 'help' }, K.detail));
    if (K?.state === 'error') return h('div', { class: 'card warn' }, inlineError(K.error));
    return null;
  }
  // An agent's last activity, newest first, from what the page already has: requests waiting, its last message, presence.
  function activityOf(w) {
    const c = w.contact ? contactBy(w.contact) : null, out = [];
    for (const r of requestsOf(w.worker)) out.push({ at: r.iat, title: `Asked to pay ${xmr(r.amount)} XMR`, sub: `${r.purpose || 'no reason given'} · waiting for you`, go: () => go('approve', { keeper: r.keeper, nonce: r.nonce }) });
    if (c?.last) out.push({ at: c.last.at, title: c.last.dir === 'out' ? 'You wrote to it' : 'Messaged you', sub: c.last.text, go: () => go('chat', c.did) });
    const seen = w.online ? null : w.last_seen ?? c?.last_seen ?? null;
    if (seen) out.push({ at: seen, title: 'Last seen online', sub: ago(seen) });
    if (w.at) out.push({ at: w.at, title: 'Enrolled', sub: WHERE[w.placed] ?? w.placed });
    return out.sort((a, b) => b.at - a.at);
  }
  const lastAt = (w) => Math.max(0, ...activityOf(w).filter((x) => x.title !== 'Enrolled').map((x) => x.at)) || null;
  function workerRow(w) {
    const en = w.enrolling, waiting = w.status === 'pending' && en?.state === 'code' && en.exp > relayNow();
    const state = w.status === 'revoked' ? `Revoked ${w.revoked ? day(w.revoked) : ''}`.trim()
      : waiting ? ['Waiting for its code · ', countdown(en.exp), ' left']
        : w.status === 'pending' ? 'Not finished' : w.online ? 'Online' : w.last_seen ? `Last seen ${ago(w.last_seen)}` : 'Enrolled';
    const where = w.placed === 'device' ? `a device${w.rank === 'full' ? ' that holds your identity' : ''}` : WHERE[w.placed] ?? w.placed;
    // With Wallet on, the allowance on a line of its own, with the wallet's sync state as the Wallet tab says it (Decided).
    const a = walletOn() && w.status === 'enrolled' ? policyOf(w.worker) : null, sw = a ? syncWords() : null;
    return row({ start: waiting ? h('span', { class: 'av ag', 'aria-hidden': 'true' }, icon('clock')) : avatar('agent', w.name, null, w.contact), title: w.name, attrs: { 'data-worker': String(w.worker) },
      sub: [w.status === 'enrolled' ? [h('span', { class: `dot sm${w.online ? '' : ' off'}` }), ' '] : null, state, w.status === 'revoked' || waiting ? '' : ` · ${where}`,
        a ? h('span', { class: 'line' }, allowanceText(a)) : null, a && sw ? h('span', { class: `line${synced() ? '' : ' stale'}`, 'data-sync': walletReady()?.sync?.state }, sw) : null],
      end: w.status === 'enrolled' ? short(lastAt(w)) : null, chev: waiting,
      onclick: () => (w.status === 'pending' && en ? go('enrol', { id: en.id }) : go('agent', w.worker)) });
  }
  screen('agents', { tab: 'agents' }, () => {
    S.keeperAt = 0;   // a screen opened reads the keeper afresh
    const head = h('div'), lst = h('div'), fab = fabBtn('Enrol agent', () => go('enrol'));
    mount(page({ title: 'Agents', tab: 'agents', body: [head, lst], fab }));
    return async () => {
      put(head, statusCards(), noteCard());
      const [W] = await Promise.all([workersNow(true), keeperNow(), walletNow()]), all = W.workers ?? [], K = keeperHere();
      fab.disabled = !canEnrol(W);
      const live = all.filter((w) => w.status !== 'revoked'), gone = all.filter((w) => w.status === 'revoked');
      const name = (r) => all.find((w) => w.worker === r.worker)?.name ?? r.agent;
      // Needs you: a payment above its limit waiting for Approve or Refuse; an enrolment waiting for its four words.
      const asks = (K?.requests ?? []).map((r) => row({ start: avatar('agent', name(r)), title: name(r), sub: [`Asks to pay ${xmr(r.amount)} XMR`, r.purpose ? ` · ${r.purpose}` : ''], subCls: 'warn',
        end: [short(r.iat), h('span', { class: 'count', 'aria-label': 'Waiting for you' }, '1')], attrs: { 'data-request': r.nonce }, onclick: () => go('approve', { keeper: r.keeper, nonce: r.nonce }) }));
      const words = live.filter((w) => w.enrolling?.state === 'words' && w.enrolling.confirm_words && w.enrolling.words_ok === null && w.enrolling.words)
        .map((w) => row({ start: avatar('agent', w.name), title: w.name, sub: 'Compare its four words to finish', subCls: 'warn', chev: true, onclick: () => go('enrol', { id: w.enrolling.id }) }));
      // The allowances (Wallet on): what the agents spent of what they may, this period, the wallet's sync state; the card opens
      // Agents' allowances (Top up).
      const mine = walletOn() && K ? live.map((w) => policyOf(w.worker)).filter(Boolean) : [], sw = syncWords();
      const sum = (f) => mine.reduce((t, a) => { try { return t + BigInt(a[f]); } catch { return t; } }, 0n);
      const periods = [...new Set(mine.map((a) => a.period_seconds))];
      put(lst,
        W.error ? h('div', { class: 'card warn' }, h('p', null, W.error.check === 'scope' ? 'This control may not list the agents.' : plain(W.error))) : null,
        !W.error && !W.keeper ? h('div', { class: 'card' }, h('p', null, h('b', null, 'Your agents come from your 25 words')),
          h('p', { class: 'help' }, LOCAL ? 'Create a new identity or restore from your 25 words to enrol agents from this app.' : 'Make the keeper once on this computer: sigelo-agent keeper --from-words')) : null,
        W.seat === 'elsewhere' ? h('div', { class: 'card' }, h('p', null, 'Another device signs in as you: enrol agents there.')) : null,
        mine.length ? h('button', { type: 'button', class: 'card soft tap', 'data-allowances': '', onclick: () => go('allowances') }, h('p', null, h('b', null, `Allowances ${periods.length === 1 ? periodWord(periods[0]) : 'this period'}`)),
          h('p', { class: 'help' }, `${xmr(sum('spent'))} of ${xmr(sum('per_period_max'))} XMR spent by your agents`), meter(sum('spent'), sum('per_period_max')),
          sw ? h('p', { class: `help${synced() ? '' : ' stale'}`, 'data-sync': walletReady()?.sync?.state }, sw) : null) : null,
        asks.length || words.length ? [sec('Needs you'), list(asks, words)] : null,
        live.length ? [sec('Your agents'), list(live.map(workerRow))]
          : W.keeper ? empty('No agents yet', 'Enrol an AI agent to let it act as you: chat, book, pay from an allowance you set.', btn('Enrol an agent', () => go('enrol'), { kind: 'pri', disabled: !canEnrol(W) })) : null,
        gone.length ? [sec('Revoked'), list(gone.map(workerRow))] : null);
    };
  });

  // Enrol an agent (ENROL.md; the mock's four taps): a name and how much to trust it, then one code for the agent,
  // ten minutes, once; then the four words (its key waits for "They match"), then ready.
  const TRUST = [['own', 'Works for me', 'Its messages shown in full. For agents you run.'], ['quiet', 'Reads the web', 'Low trust: you read it when you choose.']];
  screen('enrol', {}, (arg) => {
    const E = { id: arg?.id ?? null, first: null, busy: false, error: null, tier: 'own' };
    const nameIn = input({ autocapitalize: 'none', maxlength: '64', placeholder: 'notes' });
    const body = h('div', { class: 'pad stack' }), foot = h('div'), title = h('h1', null, 'Enrol an agent'), say = h('div');
    const trust = radios('Trust', TRUST, 'own', (t) => { E.tier = t; trustLine.textContent = `Trust: ${TRUST.find(([v]) => v === t)[1].toLowerCase()}`; });
    const trustLine = h('summary', null, 'Trust: works for me');
    const form = h('div', { class: 'stack' }, h('p', { class: 'lead' }, 'Enrolling gives an AI agent its own key under your identity. It then acts as you, within the limits you set.'),
      field('Agent name', nameIn, 'Lowercase letters, digits, - and _.'), h('details', { class: 'more' }, trustLine, trust), say);
    mount(page({ who: title, body: [body], foot: [foot] }));
    const keep = (id) => { S.stack[S.stack.length - 1].arg = id ? { id } : undefined; if (ours()) H.replaceState(stateOf(S.stack.length - 1), ''); };
    const reset = () => { E.id = null; E.first = null; keep(null); return refresh(); };
    const make = async () => {
      E.busy = true; E.error = null; await refresh();
      try {
        const r = await started('POST', '/api/agents/enrol-code', { name: nameIn.value.trim(), ...(E.tier !== 'own' && { tier: E.tier }), confirm_words: true });
        E.id = r.id; E.first = r; keep(r.id);
      } catch (e) { E.error = e; }
      E.busy = false;
      await poll();
    };
    return async () => {
      if (!E.id) {
        title.textContent = 'Enrol an agent';
        put(say, inlineError(E.error));
        put(body, form);
        put(foot, btn(E.busy ? 'Making a code…' : 'Make a code', make, { kind: 'pri', disabled: E.busy }));
        return;
      }
      const W = await workersNow(true), w = W.workers?.find((x) => x.enrolling?.id === E.id), en = w?.enrolling ?? E.first;
      const name = w?.name ?? E.first?.name ?? '', enrolled = w?.status === 'enrolled' || en?.state === 'enrolled';
      put(foot);
      if (!en) { title.textContent = 'Enrol an agent'; put(body, empty('This code is gone', 'It was used or cancelled.', btn('Make a new code', reset, { kind: 'pri' }))); return; }
      if (enrolled) {
        // Its own screen (the mock's enrol-done: Close to Agents), once.
        put(body, h('p', { class: 'lead', role: 'status' }, `${name} is ready.`));
        if (!E.done) { E.done = true; setTimeout(() => void swap('enrolled', { worker: w?.worker ?? E.first?.worker, name, contact: w?.contact ?? null }), 0); }
        return;
      }
      if (en.state === 'code') {
        title.textContent = `Code for ${name}`;
        const cancel = async () => {
          if (await ask({ title: `Cancel the code for ${name}?`, text: 'It stops working at once.', yes: 'Cancel this code', no: 'Keep it' })) void act(() => backend.call('POST', '/api/agents/revoke', { worker: w?.worker ?? E.first?.worker }), () => back());
        };
        put(body, h('div', { class: 'center stack' }, qrBox(en.code), h('p', { class: 'code' }, en.code), h('p', { class: 'lead' }, `Waiting for ${name}. Works once, for `, countdown(en.exp), '.'),
          h('div', { class: 'btns' }, btn('Share', () => share(enrolMessage(en.code, en.exp, en.command)), { kind: 'pri' }), btn('Copy', () => copy(en.code))),
          h('p', { class: 'lead' }, `Give it to ${name}: share it, or let it scan the QR.`)),
        h('details', { class: 'more' }, h('summary', null, 'Agent on a computer?'), h('p', { class: 'help' }, 'Run this there:'), h('p', { class: 'mono card' }, en.command), btn('Copy the command', () => copy(en.command))),
        h('p', { class: 'help center' }, 'This screen moves on by itself once the agent uses the code.'), btn('Cancel this code', cancel, { kind: 'danger' }));
        return;
      }
      if (en.state === 'expired') { title.textContent = 'Code expired'; put(body, empty('This code has run out', 'Codes work for 10 minutes, once. Make a new one.', btn('Make a new code', reset, { kind: 'pri' }))); return; }
      if (en.state === 'failed') { title.textContent = 'Not enrolled'; put(body, empty('Not enrolled', plain({ message: en.detail ?? en.check }), btn('Try again', reset, { kind: 'pri' }))); return; }
      if (en.state === 'words' && en.confirm_words && en.words_ok === null) {
        title.textContent = `Is this ${name}?`;
        if (!en.words) { put(body, h('p', { class: 'lead' }, 'The agent entered the code. Waiting for its four words…')); return; }
        const no = async () => {
          if (await ask({ title: `Drop the code for ${name}?`, text: 'Different words mean someone else may have used it. Its key is not sent.', yes: 'They don\'t match: drop it', no: 'Back' })) {
            void act(() => backend.call('POST', '/api/agents/enrol-words', { id: en.id, match: false }));
          }
        };
        put(body, h('p', { class: 'lead' }, 'The agent shows four words. Same words here?'), h('div', { class: 'card center' }, fourWords(en.words)));
        put(foot, btn('They match', () => act(() => backend.call('POST', '/api/agents/enrol-words', { id: en.id, match: true })), { kind: 'pri' }), btn('They don\'t match', no));
        return;
      }
      title.textContent = `Enrolling ${name}`;
      put(body, h('div', { class: 'hero center stack' }, h('p', { class: 'lead' }, en.state === 'sending' ? 'Sending its key, end to end, once…' : 'The agent entered the code…'),
        h('div', { class: 'meter busy' }, h('i')), en.words ? h('details', { class: 'more' }, h('summary', null, 'Its four words'), fourWords(en.words)) : null, en.check ? inlineError({ message: en.detail ?? en.check }) : null));
    };
  });

  // An agent's page: how it is, its allowance (Wallet on), what it did last, what it may do, about it; rename; revoke.
  // Enrolled (the mock's enrol-done): Close to Agents; Decided (notes.md): no first chat started for it, Done is the way on.
  screen('enrolled', {}, (arg) => {
    const foot = h('div'), name = arg?.name ?? 'Your agent';
    mount(page({ close: true, onBack: () => home('agents'), who: h('h1', { class: 'sr' }, `${name} is ready`), body: [h('div', { class: 'hero center stack' }, h('div', { class: 'badge-ic' }, icon('check')),
      h('h2', { class: 'big' }, `${name} is ready`), h('p', { class: 'lead' }, 'It acts as you, within the limits you set. Revoke it any time.'))], foot: [foot] }));
    return async () => {
      const c = arg?.contact ?? (await workersNow()).workers?.find((x) => x.worker === arg?.worker)?.contact ?? null;
      put(foot, btn('Done', () => home('agents'), { kind: 'pri' }), c ? btn(`Message ${name}`, () => swap('chat', c), { kind: 'ghost' }) : null);
    };
  });
  screen('agent', {}, (i) => {
    S.keeperAt = 0;   // a screen opened reads the keeper afresh
    const body = h('div'), title = h('h1', null, 'Agent'), acts = h('span');
    mount(page({ who: title, actions: [acts], body: [body] }));
    return async () => {
      const [W] = await Promise.all([workersNow(true), keeperNow(), walletNow()]), w = W.workers?.find((x) => x.worker === i);
      if (!w) { title.textContent = 'Agent'; put(acts); put(body, empty('No such agent', 'Its code ran out or was cancelled.')); return; }
      title.textContent = safeText(w.name);
      const c = w.contact ? contactBy(w.contact) : null;
      put(acts, c ? tbtn('Message', () => go('chat', c.did)) : null);
      const revoke = async () => {
        const code = w.status === 'pending' && w.enrolling?.state === 'code';
        const yes = await ask(code ? { title: `Cancel the code for ${w.name}?`, text: 'It stops working at once.', yes: 'Cancel this code', no: 'Keep it' }
          : { title: `Revoke ${w.name}?`, text: `It can no longer message as you or spend.${w.attested_until ? ` Places that already checked it still see it as yours until ${day(w.attested_until)}.` : ''}`, yes: `Revoke ${w.name}`, no: `Keep ${w.name}` });
        if (yes) void act(() => backend.call('POST', '/api/agents/revoke', { worker: i }), (r) => { S.workersAt = 0; if (r.cancelled) home('agents'); });
      };
      const status = w.status === 'revoked' ? h('span', { class: 'warn' }, 'Revoked') : w.status === 'pending' ? 'Not finished'
        : w.online ? h('span', { class: 'ok' }, '● Online') : w.last_seen ? `Last seen ${ago(w.last_seen)}` : 'Enrolled';
      // The allowance (Wallet on): this computer's keeper, else where it is set; the wallet's sync state with it (Decided).
      let allowance = null;
      if (walletOn() && w.status === 'enrolled') {
        const a = policyOf(i), K = S.keeper, sw = syncWords();
        allowance = [sec('Allowance'), a ? h('button', { type: 'button', class: 'card tap', 'data-allowance': '', onclick: () => go('agent-allowance', i) },
          h('p', null, h('b', null, `${xmr(a.spent)} of ${xmr(a.per_period_max)} XMR`), ` ${periodWord(a.period_seconds)}`), meter(a.spent, a.per_period_max),
          h('p', { class: 'help' }, `${asksText(a)} · Change`), sw ? h('p', { class: `help${synced() ? '' : ' stale'}`, 'data-sync': walletReady()?.sync?.state }, sw) : null)
          : keeperHere() ? h('div', { class: 'card' }, h('p', null, `${w.name} has no allowance in this computer's keeper.`), h('p', { class: 'help' }, `Give it one there with sigelo-spend: an agent entry with its own account and token, its did ${w.original}.`))
            : keeperAway(K)];
      }
      const acts_ = activityOf(w).slice(0, 5);
      put(body, noteCard(),
        h('div', { class: 'pad' }, h('div', { class: 'row' }, c ? picButton('agent', w.name, c.did, `Picture for ${w.name}`) : avatar('agent', w.name, 'lg'), h('span', { class: 'mid' }, h('h3', null, w.name), h('p', { class: 'lead' }, status, ` · ${WHERE[w.placed] ?? w.placed}`)))),
        w.status === 'pending' && w.enrolling ? h('div', { class: 'card' }, h('p', null, 'It has not used its code yet.'), h('div', { class: 'btns' }, btn('Show the code', () => go('enrol', { id: w.enrolling.id }), { kind: 'pri' }))) : null,
        allowance,
        w.status !== 'revoked' && acts_.length ? [sec('Last activity'), list(acts_.map((x) => row({ compact: true, title: x.title, sub: x.sub, end: when(x.at), onclick: x.go })))] : null,
        c && w.status !== 'revoked' ? [sec('What it may do'),
          radios('What it may do', c.tier === 'friend' ? [...TRUST, ['friend', 'Just a count', 'A notice, read when you open the chat']] : TRUST, c.tier, (t) => act(() => backend.call('POST', '/api/tier', { contact: c.did, tier: t }))),
          h('div', { class: 'list' }, toggle('Sees when I\'m online', c.presence === 'own' ? 'Your own agents always see it.' : null, c.presence !== 'deny',
            (allow) => act(() => backend.call('POST', '/api/presence', { contact: c.did, allow })), { disabled: c.presence === 'own' }))] : null,
        sec('About'),
        h('div', { class: 'list' },
          h('div', { class: 'kv' }, h('span', null, 'Enrolled'), h('span', null, day(w.at))),
          w.attested_until && w.status !== 'revoked' ? h('div', { class: 'kv' }, h('span', null, 'Vouched for until'), h('span', null, `${day(w.attested_until)}${w.placed === 'here' ? ' · renews itself' : ''}`)) : null,
          w.words ? h('div', { class: 'kv' }, h('span', null, 'Its four words'), h('span', null, wordsLine(w.words))) : null,
          w.revoked ? h('div', { class: 'kv' }, h('span', null, 'Revoked'), h('span', null, day(w.revoked))) : null,
          w.revoked ? null : row({ compact: true, title: 'Rename', sub: w.name, chev: true, onclick: () => renameSheet(`Rename ${w.name}`, w.name, (name) => backend.call('POST', '/api/agents/rename', { worker: i, name }).then(() => { S.workersAt = 0; }), 'Lowercase letters, digits, - and _.') })),
        w.revoked ? null : w.placed === 'device' ? h('p', { class: 'help pad' }, 'A device: revoke it under Devices on the computer that added it.')
          : h('div', { class: 'pad' }, btn(w.enrolling?.state === 'code' ? 'Cancel this code' : `Revoke ${w.name}`, revoke, { kind: 'danger' })));
    };
  });

  // An agent's allowance and limits (notes.md "Decided": the four common ones first, then Advanced), written to the keeper's
  // policy on this computer (POST /api/keeper/agent); the keeper takes them at its next start (Restart the keeper).
  // Validation on leaving a field and on Save, the message under the field; Save is never disabled.
  screen('agent-allowance', {}, (i) => {
    S.keeperAt = 0;   // a screen opened reads the keeper afresh
    const body = h('div'), foot = h('div'), title = h('h1', null, 'Allowance'), say = h('div');
    mount(page({ who: title, body: [body], foot: [foot] }));
    const F = { built: null, rules: null, saved: null, busy: false };
    const amount = (label, help, opt) => {
      const el = input({ inputmode: 'decimal', autocomplete: 'off' }), err = h('p', { class: 'err', role: 'alert', hidden: true });
      const check = () => { const v = el.value.trim(), okv = (opt && v === '') || atomicOf(v) !== null; err.hidden = okv; err.textContent = okv ? '' : 'Enter an amount in XMR, like 0.25'; el.setAttribute('aria-invalid', okv ? 'false' : 'true'); return okv; };
      el.addEventListener('blur', check);
      el.addEventListener('input', () => { if (!err.hidden) { err.hidden = true; el.setAttribute('aria-invalid', 'false'); } });
      return { el, check, node: h('div', null, field(label, el, help), err) };
    };
    const whole = (label, help, min, max) => {
      const el = input({ inputmode: 'numeric', autocomplete: 'off' }), err = h('p', { class: 'err', role: 'alert', hidden: true });
      const check = () => { const n = Number(el.value.trim()), okv = /^\d+$/.test(el.value.trim()) && n >= min && n <= max; err.hidden = okv; err.textContent = okv ? '' : `Enter a whole number from ${min} to ${max}`; return okv; };
      el.addEventListener('blur', check);
      el.addEventListener('input', () => { err.hidden = true; });
      return { el, check, node: h('div', null, field(label, el, help), err) };
    };
    function build(a, k, w) {
      const perTx = amount('Per payment', 'XMR. The most one payment may be.');
      const perPeriod = amount('Per period', `XMR. Left ${periodWord(a.period_seconds)}: ${xmr(a.remaining)}.`);
      const period = select('Period', PERIODS.map(([v, t]) => [String(v), t]), String(a.period_seconds));
      if (![...PERIODS.map(([v]) => String(v))].includes(String(a.period_seconds))) period.append(h('option', { value: String(a.period_seconds) }, `${Math.round(a.period_seconds / 3600)} hours`));
      period.value = String(a.period_seconds);
      const asks = amount('Ask me before paying more than', 'XMR per payment. You answer in its chat. Empty: it never asks; 0: every time.', true);
      const rate = whole('Payments per minute', 'Asking counts too.', 1, 600), dele = whole('Agents it may add under itself', '0: none.', 0, 1000);
      perTx.el.value = xmr(a.per_tx_max); perPeriod.el.value = xmr(a.per_period_max); asks.el.value = a.approval_above === null ? '' : xmr(a.approval_above);
      rate.el.value = String(a.rate_per_minute); dele.el.value = String(a.max_delegates);
      const rulesBox = h('div'), apprBox = h('div');
      F.rules = a.allow.map((r) => ({ ...r }));
      F.built = { perTx, perPeriod, period, asks, rate, dele, rulesBox, apprBox, nodes: [
        perTx.node, perPeriod.node, field('Each', period),
        h('div', null, h('p', { class: 'sec flush' }, 'Who it may pay'), rulesBox),
        asks.node,
        h('details', { class: 'more' }, h('summary', null, 'Advanced'), h('div', { class: 'stack' }, rate.node, dele.node, h('div', null, h('p', { class: 'sec flush' }, 'Approvers'), apprBox))),
        h('p', { class: 'help' }, `Paid from your agents' allowance money on the keeper, not your wallet. Top it up from Wallet. ${RECOVERY}`)] };
      void w; void k;
    }
    const ruleTitle = (r) => {
      if (r.kind === 'addr') return [r.label ?? 'An address', h('small', { class: 'mono' }, ` ${r.addr.slice(0, 6)}…${r.addr.slice(-6)}`)];
      const who = (d) => (d === S.me?.original || d === S.snap?.me?.did ? 'you' : contactBy(d)?.name ?? `${d.slice(0, 16)}…`);
      return r.did ? `${who(r.did)}, vouched for by ${who(r.issuer)}` : `Anyone vouched for by ${who(r.issuer)}${r.ctx ? ` (${r.ctx})` : ''}`;
    };
    // Who it may pay: a contact and their address, typed, or one the keeper has seen (paid, asked to pay, invoiced: spend.log).
    const addRule = (k) => {
      const people = allContacts().filter((c) => !c.local);
      const addr = input({ autocapitalize: 'none', spellcheck: 'false', placeholder: 'Paste their address', class: 'mono' }), err = h('div');
      const seen = (k?.seen ?? []).filter((x) => !F.rules.some((r) => r.kind === 'addr' && r.addr === x.addr));
      let pick = null, from = null;
      const pickRows = h('div'), seenRows = h('div');
      const draw = () => {
        put(pickRows, list(people.map((c) => row({ compact: true, start: avatar(kindOf(c), c.name, null, c.did), title: c.name, end: pick === c ? icon('check') : null, attrs: { 'aria-pressed': pick === c ? 'true' : 'false' }, onclick: () => { pick = c; draw(); } }))));
        put(seenRows, list(seen.map((x) => row({ compact: true, title: h('span', { class: 'mono' }, `${x.addr.slice(0, 6)}…${x.addr.slice(-6)}`), attrs: { 'data-seen': x.addr, 'aria-pressed': from === x ? 'true' : 'false' },
          sub: [x.paid ? 'Paid' : x.invoice ? 'Invoiced' : 'Asked', x.agent ? ` by ${x.agent}` : '', x.purpose ? ` · ${x.purpose}` : '', x.last ? ` · ${short(x.last)}` : ''].join(''),
          end: from === x ? icon('check') : null, onclick: () => { from = x; addr.value = x.addr; const c = x.did ? contactBy(x.did) ?? allContacts().find((y) => y.current_did === x.did) : null; if (c) pick = c; draw(); } }))));
      };
      draw();
      const add = async () => {
        const v = addr.value.trim();
        if (!/^[1-9A-HJ-NP-Za-km-z]{90,110}$/.test(v)) { put(err, inlineError({ message: 'Paste their whole Monero address, or choose one the keeper has seen.' })); return; }
        if (!pick && !(from && from.addr === v)) { put(err, inlineError({ message: 'Choose who it may pay.' })); return; }
        const name = pick?.name ?? (from?.purpose || 'payee');
        const label = String(name).normalize('NFKD').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[^A-Za-z0-9]+|-+$/g, '').slice(0, 64) || 'payee';
        F.rules = [...F.rules.filter((r) => r.label !== label), { kind: 'addr', addr: v, label }];
        await closeSheet(); await refresh();
      };
      sheet({ title: 'Who it may pay', lead: 'A contact and their Monero address. The keeper pays only addresses on this list.', body: [h('div', { class: 'pad stack' },
        people.length ? pickRows : h('p', { class: 'help' }, 'No contacts yet: pair with them first.'), field('Their Monero address', addr, 'Ask them for it. Standard addresses and subaddresses work.'),
        seen.length ? [h('p', { class: 'sec flush' }, 'Seen by the keeper'), seenRows] : null, err, btn('Add', add, { kind: 'pri' }))] });
    };
    const save = async (a, k) => {
      const B = F.built, okAll = [B.perTx, B.perPeriod, B.asks, B.rate, B.dele].map((x) => x.check()).every(Boolean);
      if (!okAll) { put(say, inlineError({ message: 'Fix the fields marked above, then save.' })); return; }
      const next = { per_tx_max: atomicOf(B.perTx.el.value), per_period_max: atomicOf(B.perPeriod.el.value), period_seconds: Number(B.period.value),
        approval_above: B.asks.el.value.trim() === '' ? null : atomicOf(B.asks.el.value), rate_per_minute: Number(B.rate.el.value), max_delegates: Number(B.dele.el.value),
        allow: F.rules.map(({ kind, ...r }) => Object.fromEntries(Object.entries(kind === 'addr' ? { addr: r.addr, label: r.label ?? undefined } : { did: r.did ?? undefined, issuer: r.issuer, ctx: r.ctx ?? undefined }).filter(([, v]) => v !== undefined && v !== null))) };
      F.busy = true; put(say); await refresh();
      try { F.saved = await backend.call('POST', '/api/keeper/agent', { keeper: k.id, agent: a.name, ...next }); toast('Saved'); } catch (e) { put(say, inlineError(e)); }
      F.busy = false; S.keeperAt = 0; await keeperNow(true); await refresh();
    };
    return async () => {
      const [W] = await Promise.all([workersNow(), keeperNow()]), w = W.workers?.find((x) => x.worker === i);
      title.textContent = w ? `${w.name}'s allowance` : 'Allowance';
      const a = policyOf(i), k = a ? keeperById(a.keeper) : null;
      if (!w || !a || !k) { put(foot); put(body, h('div', { class: 'pad stack' }, keeperAway(S.keeper) ?? empty('No allowance here', w ? `${w.name} has no allowance in this computer's keeper.` : 'This agent is not here.'))); return; }
      if (!F.built) build(a, k, w);
      const B = F.built, meApprover = k.me_approver;
      put(B.rulesBox, list(F.rules.map((r, n) => row({ compact: true, title: ruleTitle(r), end: tbtn('Remove', () => { F.rules = F.rules.filter((_, j) => j !== n); void refresh(); }) }))),
        F.rules.length ? null : h('p', { class: 'help pad0' }, 'Nobody yet: it can pay no one.'), btn('Add someone', () => addRule(k), { ic: 'plus' }));
      put(B.apprBox, h('div', { class: 'list' }, toggle('I approve its payments', 'For every agent of this keeper. You answer under Agents → Needs you.', meApprover,
        (on) => act(() => backend.call('POST', '/api/keeper/approvers', { keeper: k.id, me: on }), async (r) => { F.saved = r; S.keeperAt = 0; await keeperNow(true); }))),
      k.approvers.filter((d) => d !== S.snap?.me?.did).length ? list(k.approvers.filter((d) => d !== S.snap?.me?.did).map((d) => row({ compact: true, title: contactBy(d)?.name ?? `${d.slice(0, 20)}…`, sub: 'Another approver' }))) : null);
      const warnAsk = a.approval_above !== null && !meApprover ? h('p', { class: 'help warn' }, 'You aren\'t an approver yet: turn on "I approve its payments" under Advanced.') : null;
      // The keeper re-reads its policy on its next request (0.1.15); one installed before that reads it at its next start:
      // only then the Restart (live false), or both said when the page can't tell (live null: a keeper run by hand).
      const r = F.saved?.restart, live = F.saved?.live;
      put(body, h('div', { class: 'pad stack' }, noteCard(), B.nodes, warnAsk,
        F.saved ? h('div', { class: 'card soft', 'data-saved': '' }, h('p', null, h('b', null, 'Saved.'),
          live === true ? ' The keeper uses it from its next payment.' : live === false ? ' This keeper is from before 0.1.15: it uses it after a restart.' : ' A keeper from 0.1.15 uses it from its next payment; an older one after a restart.'),
          live === true ? null : r?.can ? h('div', { class: 'btns' }, btn('Restart the keeper', () => act(() => backend.call('POST', '/api/keeper/restart', { keeper: k.id }), () => { F.saved = null; toast('Keeper restarted'); }), { kind: live === false ? 'pri' : '' }))
            : h('p', { class: 'help mono' }, r?.command ?? '')) : null, say));
      put(foot, btn(F.busy ? 'Saving…' : 'Save', () => save(a, k), { kind: 'pri' }));
    };
  });

  // A payment request (task 4: the request, then Approve: 2 taps; the push lands here in pass 6): amount, who, why;
  // Approve signs it with your key and hands it to the keeper (POST /api/keeper/approve); Refuse keeps it unpaid.
  screen('approve', {}, (arg) => {
    S.keeperAt = 0;   // a screen opened reads the keeper afresh
    const body = h('div'), foot = h('div');
    mount(page({ title: 'Payment request', body: [body], foot: [foot] }));
    let done = null;
    return async () => {
      const [W] = await Promise.all([workersNow(), keeperNow()]);
      const k = keeperById(arg?.keeper), r = (keeperHere()?.requests ?? []).find((x) => x.keeper === arg?.keeper && x.nonce === arg?.nonce);
      if (done) {
        put(foot, btn('Done', () => back(), { kind: 'pri' }));
        put(body, h('div', { class: 'hero center stack' }, h('div', { class: 'badge-ic' }, icon(done.ok ? 'check' : 'x')), h('h2', { class: 'big' }, done.title), h('p', { class: 'lead' }, done.text)));
        return;
      }
      if (!r || !k) { put(foot); put(body, h('div', { class: 'pad' }, keeperAway(S.keeper) ?? empty('Not waiting any more', 'This request was answered, paid or ran out.'))); return; }
      const w = W.workers?.find((x) => x.worker === r.worker), name = w?.name ?? r.agent, a = policyOf(r.worker);
      const rule = a?.allow.find((x) => x.kind === 'addr' && x.addr === r.to);
      const kv = (x, v) => h('div', { class: 'kv' }, h('span', null, x), h('span', null, v));
      const approve = () => act(() => backend.call('POST', '/api/keeper/approve', { keeper: k.id, nonce: r.nonce }), () => {
        done = { ok: true, title: 'Approved', text: `${name} pays it the next time it asks. Nothing else can use this approval.` }; S.keeperAt = 0;
      });
      // Refuse (pass 4): why, optional; the keeper keeps the no (its signed refused line: the agent's same pay is refused) and the
      // agent is told in its chat, "Payment refused: <why>".
      const why = input({ maxlength: '200', placeholder: 'Optional' });
      const refuse_ = async () => {
        if (!(await ask({ title: `Refuse ${xmr(r.amount)} XMR?`, text: `${name} is told in its chat, with your reason. It can ask again after ${hhmm(r.exp)}.`, yes: 'Refuse', no: 'Back', danger: false,
          extra: [field(`Why (${name} reads it)`, why)] }))) return;
        void act(() => backend.call('POST', '/api/keeper/refuse', { keeper: k.id, nonce: r.nonce, ...(why.value.trim() && { reason: why.value.trim() }) }), (x) => {
          const told = x?.told ? ` ${name} was told in its chat.` : '';
          done = { ok: false, title: 'Refused', text: x?.logged ? `Not paid. The keeper refuses this payment until ${hhmm(r.exp)}.${told}` : `Not paid. ${name}'s request ends at ${hhmm(r.exp)}.${told}` }; S.keeperAt = 0;
        });
      };
      put(body, noteCard(),
        h('div', { class: 'pad ident' }, avatar('agent', name, 'lg'), h('p', { class: 'lead' }, `${name} asks to pay`), h('h2', { class: 'big' }, `${xmr(r.amount)} XMR`)),
        h('div', { class: 'list' }, kv('To', rule?.label ?? `${r.to.slice(0, 8)}…${r.to.slice(-8)}`), kv('For', r.purpose || 'No reason given'), kv('Asked', when(r.iat)), kv('Ends', hhmm(r.exp)),
          a ? kv('Its limit', `${asksText(a)}`) : null),
        k.me_approver ? null : h('div', { class: 'card warn' }, h('p', null, 'You aren\'t one of this keeper\'s approvers.'), h('p', { class: 'help' }, 'Add yourself, restart the keeper, then approve.'),
          h('div', { class: 'btns' }, btn('Make me an approver', () => act(() => backend.call('POST', '/api/keeper/approvers', { keeper: k.id, me: true }), () => { S.keeperAt = 0; toast('Saved. Restart the keeper, then approve.'); })))));
      put(foot, btn('Approve', approve, { kind: 'pri' }), btn('Refuse', refuse_));
    };
  });

  // ================================================================ WALLET (opt-in per profile; Settings → Wallet; UI-API.md "Wallet")
  // Which wallet: the computer's page shows this computer's wallet-rpc (a keeper's, or one set by hand: sigelo-agent-wallet.ts);
  // the phone connected to a computer shows the computer's (the same routes over the control); the phone on its own has no
  // wallet (where: "none") and says so. Sync (Decided): reading GET /api/wallet is the sync, started when the tab or a balance
  // is shown; its state said plainly; a balance out of sync greyed "as of"; Send only once synced.
  const RECOVERY = 'Your 25 words restore the vault and every keeper wallet; keeper settings are re-entered.';
  async function walletNow(force = false) {
    if (!walletOn()) { S.wallet = null; return null; }
    if (!force && S.wallet && Date.now() - S.walletAt < 10000) return S.wallet;
    try { S.wallet = await backend.call(force ? 'POST' : 'GET', force ? '/api/wallet/sync' : '/api/wallet'); } catch (e) { S.wallet = { on: true, error: e }; }
    S.walletAt = Date.now();
    void priceNow();
    return S.wallet;
  }
  const walletReady = () => (S.wallet?.ready === true ? S.wallet : null);
  const synced = () => walletReady()?.sync?.state === 'synced';
  // The price (opt-in): through the page's server (GET /api/price), at most every 10 minutes here too.
  async function priceNow() {
    const w = S.snap?.me?.wallet;
    if (!w?.on || !w.prices) { S.price = null; return null; }
    if (S.price && S.price.currency === w.currency && Date.now() - S.priceAt < 600000) return S.price;
    S.priceAt = Date.now();
    try { S.price = await backend.call('GET', '/api/price'); } catch { S.price = null; }
    void refresh();
    return S.price;
  }
  /** "≈ 136.80 EUR" beside an amount, only with prices on and a price known; nothing otherwise. */
  function fiat(atomic, { prefix = '', suffix = '' } = {}) {
    const p = S.price, w = S.snap?.me?.wallet;
    if (!w?.prices || !p?.on || typeof p.rate !== 'number' || p.currency !== (w.currency ?? p.currency)) return null;
    let v;
    try { v = (Number(BigInt(atomic) / 10000n) / 1e8) * p.rate; } catch { return null; }
    let s;
    try { s = new Intl.NumberFormat(undefined, { style: 'currency', currency: p.currency }).format(v); } catch { s = `${v.toFixed(2)} ${p.currency}`; }
    return `${prefix}≈ ${s}${suffix}`;
  }
  /** A balance or an amount: 4 decimals (cut, never rounded up), e.g. 0.9120; the whole amount where it matters (xmr()). */
  const xmr4 = (a) => {
    let n;
    try { n = BigInt(a); } catch { return '?'; }
    const neg = n < 0n; if (neg) n = -n;
    const f = (n % PICO).toString().padStart(12, '0');
    return `${neg ? '−' : ''}${n / PICO}.${f.slice(0, 4)}`;
  };
  const behindText = (s) => {
    const t = s.behind_s ?? 0;
    return t >= 2 * 86400 ? `${Math.round(t / 86400)} days behind` : t >= 5400 ? `${Math.round(t / 3600)} hours behind` : `${Math.max(1, Math.round(t / 60))} min behind`;
  };
  const syncedAgo = (t) => { const s = Math.max(0, Math.round(relayNow() - t)); return s < 60 ? 'Synced just now' : s < 3600 ? `Synced ${Math.floor(s / 60)} min ago` : s < 86400 ? `Synced ${Math.floor(s / 3600)} h ago` : `Synced ${day(t)}`; };
  /** The sync state in words, one line (the allowance lines): "Synced 2 min ago", "Syncing… 3 days behind", "Can't reach the node". */
  function syncWords(v = walletReady()) {
    const s = v?.sync;
    if (!s) return null;
    if (s.state === 'synced') return syncedAgo(s.synced_at ?? s.checked_at);
    if (s.state === 'syncing') return `Syncing… ${behindText(s)}`;
    if (s.state === 'node') return 'Can\'t reach the node';
    return 'Can\'t reach the wallet service';
  }
  /** The sync state as the Wallet shows it: the words, the progress while it syncs, Retry when it can't. */
  function syncState(v) {
    const s = v.sync, retry = () => act(() => walletNow(true));
    if (s.state === 'synced') return h('p', { class: 'help center', 'data-sync': 'synced' }, h('span', { class: 'ok' }, '● '), syncWords(v), fiat(v.balance?.total, { prefix: ' · ' }));
    if (s.state === 'syncing') {
      const pct = s.progress === null || s.progress === undefined ? null : Math.round(s.progress * 100), bar = h('i');
      if (pct !== null) bar.style.width = `${pct}%`;
      return h('div', { class: 'pad center', 'data-sync': 'syncing' }, h('p', { class: 'help', role: 'status' }, `Syncing… ${behindText(s)}`),
        h('div', { class: `meter${pct === null ? ' busy' : ''}`, role: 'progressbar', 'aria-label': 'Syncing', ...(pct !== null && { 'aria-valuenow': String(pct), 'aria-valuemin': '0', 'aria-valuemax': '100' }) }, bar));
    }
    const why = s.state === 'node' ? (v.node ? `Your wallet's node (${v.node}) doesn't answer, or sends no new blocks.` : 'No Monero node is set: add one in Settings → Wallet → Monero node.')
      : 'The wallet program on this computer (monero-wallet-rpc) doesn\'t answer. Start it, then retry.';
    return h('div', { class: 'card warn', 'data-sync': s.state, role: 'alert' }, row({ title: s.state === 'node' ? 'Can\'t reach the node' : 'Can\'t reach the wallet service', sub: why, subCls: 'wrap', end: tbtn('Retry', retry) }));
  }
  /** The balance: current when synced; else greyed, "as of <time>", never as current. */
  function balanceBlock(v) {
    const b = v.balance;
    if (!b) return h('div', { class: 'pad center' }, h('p', { class: 'lead' }, 'Balance'), h('p', { class: 'big-num stale' }, '—'), h('p', { class: 'help' }, 'Not known yet: the wallet hasn\'t answered.'));
    const locked = (() => { try { return BigInt(b.total) - BigInt(b.unlocked); } catch { return 0n; } })();
    return h('div', { class: 'pad center', 'data-balance': b.current ? 'current' : 'stale' }, h('p', { class: 'lead' }, 'Balance'),
      h('p', { class: `big-num${b.current ? '' : ' stale'}`, 'aria-label': `${xmr(b.total)} XMR${b.current ? '' : ', not up to date'}` }, xmr4(b.total), ' ', h('small', null, 'XMR')),
      b.current ? null : h('p', { class: 'help' }, b.at ? `as of ${when(b.at)}` : 'as of its last sync (not known)'),
      locked > 0n ? h('p', { class: 'help' }, `${xmr4(String(locked))} XMR arriving or locked for about ${Math.max(2, (b.blocks_to_unlock || 10) * 2)} min`) : null);
  }
  /** Why there is no wallet to show, said once, with the way on. */
  function walletAway(v) {
    if (v?.error) return h('div', { class: 'card warn' }, inlineError(v.error), h('div', { class: 'btns' }, btn('Retry', () => act(() => walletNow(true)))));
    if (v?.where === 'none') return empty('This phone has no wallet yet', 'Use the computer\'s page: its Wallet shows your balance, Receive and Send. Your agents\' allowances work either way.');
    const say = {
      no_service: ['No wallet on this computer yet', 'The Wallet uses a Monero wallet program on this computer: your keeper\'s, or one you run.'],
      no_account: ['Choose your account', 'Account 0 of the keeper\'s wallet is an agent\'s allowance. Make an account of your own in it, or choose another wallet.'],
      account_held: ['Choose your account', `That account is ${v?.detail}'s allowance: an agent's money, not yours.`],
      keeper_gone: ['Your wallet\'s keeper is gone', 'The keeper this Wallet used is no longer on this computer. Choose another wallet.'],
      unreadable: ['This page can\'t read the keeper here', v?.detail ?? ''],
    }[v?.why] ?? ['Wallet not ready', plain(v?.detail)];
    return empty(say[0], say[1], btn('Choose a wallet', () => go('set-service'), { kind: 'pri' }));
  }
  const historyNow = async (force = false) => {
    if (!walletReady()) return null;
    if (!force && S.hist && Date.now() - S.histAt < 30000) return S.hist;
    try { S.hist = await backend.call('GET', '/api/wallet/history?n=50'); } catch (e) { S.hist = { entries: [], error: e }; }
    S.histAt = Date.now();
    return S.hist;
  };
  const txWho = (t) => (t.contact_name ? `${t.dir === 'in' ? 'From' : 'To'} ${t.contact_name}` : t.dir === 'in' ? 'Received' : t.address ? `To ${t.address.slice(0, 4)}…${t.address.slice(-4)}` : 'Sent');
  const txStatus = (t) => (t.status === 'pending' ? 'Waiting for confirmation' : t.status === 'confirming' ? `Waiting for confirmation · ${t.confirmations ?? 0} of 10` : t.status === 'failed' ? 'Failed' : null);
  function txRow(t) {
    const st = txStatus(t), signed = t.dir === 'in' ? '+' : '−';
    return row({ start: h('span', { class: 'av', 'aria-hidden': 'true' }, icon(st ? 'clock' : t.dir === 'in' ? 'arrow-in' : 'arrow-out')), title: txWho(t),
      sub: st ?? (t.note || (t.dir === 'in' ? 'Monero' : '')), subCls: st ? 'warn' : null, attrs: { 'data-tx': t.txid },
      end: [h('b', { class: t.dir === 'in' && !st ? 'ok' : null }, `${signed}${xmr4(t.amount)}`), short(t.at ?? 0) || 'Now'], onclick: () => go('tx', t.txid) });
  }
  // The agents' allowances (the keeper of this computer): what is left this period, and the wallet's sync state with it.
  function allowanceSum() {
    const K = keeperHere(), live = (S.workers?.workers ?? []).filter((w) => w.status === 'enrolled');
    const mine = K ? live.map((w) => policyOf(w.worker)).filter(Boolean) : [];
    if (!mine.length) return null;
    const sum = (f) => mine.reduce((t, a) => { try { return t + BigInt(a[f]); } catch { return t; } }, 0n), periods = [...new Set(mine.map((a) => a.period_seconds))];
    return { mine, left: sum('remaining'), cap: sum('per_period_max'), spent: sum('spent'), when: periods.length === 1 ? periodWord(periods[0]) : 'this period' };
  }
  screen('wallet', { tab: 'wallet' }, () => {
    S.walletAt = 0; S.histAt = 0;   // the tab shown starts a sync (Decided)
    const head = h('div'), body = h('div');
    mount(page({ title: 'Wallet', tab: 'wallet', body: [head, body] }));
    return async () => {
      put(head, statusCards(), noteCard());
      if (!walletOn()) { put(body, empty('Wallet is off', 'Turn it on to see your balance, receive and send Monero, and pay in chats. Your agents\' allowances work either way.', btn('Turn on Wallet', () => go('set-wallet'), { kind: 'pri' }))); return; }
      const [v] = await Promise.all([walletNow(), keeperNow(), workersNow()]);
      if (!walletReady()) { put(body, walletAway(v)); return; }
      const hist = await historyNow(), A = allowanceSum(), can = synced();
      put(body, balanceBlock(v), syncState(v),
        h('div', { class: 'pad btns' }, btn('Receive', () => go('receive'), { kind: 'pri', ic: 'arrow-in' }), btn('Send', () => go('send'), { kind: 'pri', ic: 'arrow-out', disabled: !can })),
        can ? null : h('p', { class: 'help center' }, 'Send works once your wallet is synced.'),
        A ? h('button', { type: 'button', class: 'card tap flex', 'data-allowances': '', onclick: () => go('allowances') }, h('span', { class: 'mid' }, h('b', null, 'Agents\' allowances'),
          h('small', null, `${xmr(String(A.left))} XMR left of ${xmr(String(A.cap))} ${A.when}`)), icon('chev')) : null,
        sec('History'),
        hist?.error ? h('div', { class: 'card warn' }, inlineError(hist.error)) : hist?.entries?.length ? list(hist.entries.slice(0, 20).map(txRow))
          : empty('No payments yet', 'Receive shows an address to be paid at.'));
    };
  });

  // Receive (task 8: Wallet, Receive): a new address each time, its QR, Share and Copy; an amount and a note to ask with.
  const uriOf = (addr, amount, note) => {
    const q = [amount ? `tx_amount=${amount}` : null, note ? `tx_description=${encodeURIComponent(note)}` : null].filter(Boolean);
    return `monero:${addr}${q.length ? `?${q.join('&')}` : ''}`;
  };
  screen('receive', {}, () => {
    const R = { addr: null, index: null, error: null, labelled: '' };
    const body = h('div', { class: 'pad stack center' }), qr = h('div'), amount = input({ inputmode: 'decimal', placeholder: '0.10' }), note = input({ maxlength: '100', placeholder: 'Optional' });
    const amountErr = h('p', { class: 'err', role: 'alert', hidden: true });
    const okAmount = () => { const v = amount.value.trim(), good = v === '' || (atomicOf(v) !== null && atomicOf(v) !== '0'); amountErr.hidden = good; amountErr.textContent = good ? '' : 'Enter an amount in XMR, like 0.25'; return good; };
    amount.addEventListener('blur', okAmount); amount.addEventListener('input', () => { amountErr.hidden = true; drawQr(); }); note.addEventListener('input', () => drawQr());
    const uri = () => uriOf(R.addr, okAmount() && amount.value.trim() ? xmr(atomicOf(amount.value.trim())).replace(/\.?0+$/, '') : '', note.value.trim());
    let lastUri = '';
    const drawQr = () => { if (!R.addr) return; const u = uri(); if (u !== lastUri) { lastUri = u; put(qr, qrBox(u)); } };
    // The note goes with the address in the wallet too (its label), so History says what it was for.
    const keepNote = async () => { const n = note.value.trim(); if (R.index !== null && n !== R.labelled) { try { await backend.call('POST', '/api/wallet/label', { index: R.index, note: n }); R.labelled = n; } catch {} } };
    const make = async () => {
      R.error = null;
      try { const r = await backend.call('POST', '/api/wallet/receive', {}); R.addr = r.address; R.index = r.index; } catch (e) { R.error = e; }
      await refresh();
    };
    mount(page({ title: 'Receive', body: [body] }));
    void make();
    const form = h('div', { class: 'stack', style: 'text-align:left' }, h('div', null, field('Ask for an amount (optional)', amount, 'XMR'), amountErr), field('Note (optional)', note, 'Goes with the address: the payer\'s wallet shows it.'));
    return () => {
      if (R.error) { put(body, inlineError(R.error), btn('Try again', make, { kind: 'pri' })); return; }
      if (!R.addr) { put(body, h('p', { class: 'lead', role: 'status' }, 'Making a new address…')); return; }
      drawQr();
      put(body, qr, h('p', { class: 'mono card', 'data-address': '' }, R.addr),
        h('div', { class: 'btns' }, btn('Share', async () => { await keepNote(); await share(uri()); }, { kind: 'pri' }), btn('Copy', async () => { await keepNote(); await copy(uri()); })),
        form, h('p', { class: 'help' }, 'A new address each time keeps payers from linking you. People you chat with can just use Pay.'));
    };
  });

  // Send (task 9: Wallet, Send, Review, Send): to a contact (their address from your chat) or to an address; review; send.
  // Only once synced (Decided); the button says why when it can't.
  const ADDR_RE = /\b(?:monero:)?([48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?|[57][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?|[9AB][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?)\b/;
  /** The address a monero: URI or a pasted text names, and its amount (tx_amount), or null. */
  const addrOf = (t) => {
    const m = ADDR_RE.exec(String(t ?? ''));
    if (!m) return null;
    const amt = /[?&]tx_amount=([0-9.]+)/.exec(String(t))?.[1] ?? null;
    return { addr: m[1], amount: amt };
  };
  function amountField(label, help) {
    const el = input({ inputmode: 'decimal', autocomplete: 'off', class: 'big' }), err = h('p', { class: 'err', role: 'alert', hidden: true });
    const check = () => { const v = el.value.trim(), good = v === 'all' || (atomicOf(v) !== null && atomicOf(v) !== '0'); err.hidden = good; err.textContent = good ? '' : 'Enter an amount in XMR, like 0.25'; el.setAttribute('aria-invalid', good ? 'false' : 'true'); return good; };
    el.addEventListener('blur', check); el.addEventListener('input', () => { if (!err.hidden) { err.hidden = true; el.setAttribute('aria-invalid', 'false'); } });
    return { el, check, err, help: h('p', { class: 'help' }), node: (helpNode) => h('div', null, field(label, el, help), helpNode, err) };
  }
  const haveLine = (v) => (v?.balance ? ['You have ', h('span', { class: v.balance.current ? null : 'stale' }, xmr4(v.balance.unlocked)), ' XMR', v.balance.current ? '' : ` (as of ${v.balance.at ? when(v.balance.at) : 'its last sync'})`, ' spendable'] : null);
  async function reviewIt(to, amountIn, note, F) {
    if (!amountIn.check()) { put(F.say, inlineError({ message: 'Fix the amount, then review.' })); return; }
    F.busy = true; put(F.say); await refresh();
    const v = amountIn.el.value.trim();
    try {
      const r = await backend.call('POST', '/api/wallet/review', { to, amount: v === 'all' ? 'all' : atomicOf(v), ...(note && { note }) });
      await go('send-review', r);
    } catch (e) { put(F.say, inlineError(e)); }
    F.busy = false; await refresh();
  }
  screen('send', {}, (arg) => {
    const F = { busy: false, say: h('div') }, body = h('div'), foot = h('div');
    const addr = input({ autocapitalize: 'none', spellcheck: 'false', class: 'mono', placeholder: 'Paste or scan', value: arg?.addr ?? '' }), addrErr = h('p', { class: 'err', role: 'alert', hidden: true });
    const okAddr = () => { const good = addrOf(addr.value) !== null; addrErr.hidden = good; addrErr.textContent = good ? '' : 'Paste their whole Monero address (95 or 106 characters).'; return good; };
    addr.addEventListener('blur', () => { if (addr.value.trim()) okAddr(); }); addr.addEventListener('input', () => { addrErr.hidden = true; });
    const amt = amountField('Amount (XMR)'), note = input({ maxlength: '100', placeholder: 'Optional' }), have = h('p', { class: 'help' });
    if (arg?.amount) amt.el.value = arg.amount;
    const scan = () => {
      const sc = scanner((t) => { const a = addrOf(t); if (!a) return false; addr.value = a.addr; if (a.amount) amt.el.value = a.amount; sc.stop(); void closeSheet(); return true; });
      sheet({ title: 'Scan an address', body: [h('div', { class: 'pad stack' }, sc)], onClose: () => sc.stop() });
    };
    const agentTo = arg?.agent ? { agent: arg.agent, keeper: arg.keeper } : null;
    const form = h('div', { class: 'pad stack' }, agentTo ? null : [field('Monero address', addr), addrErr, btn('Scan', scan, { ic: 'scan' })],
      amt.node(h('div', null, have, tbtn('Send all', () => { amt.el.value = 'all'; amt.check(); }))), field('Note (optional)', note, 'Kept with the payment in your History.'));
    mount(page({ title: agentTo ? `Top up ${arg.agent}` : 'Send', body: [body], foot: [foot] }));
    return async () => {
      const v = await walletNow();
      if (!walletReady()) { put(foot); put(body, walletAway(v)); return; }
      put(have, haveLine(v));
      const people = allContacts().filter((c) => !c.local && kindOf(c) === 'person');
      put(body, noteCard(), agentTo ? h('div', { class: 'pad' }, h('p', { class: 'lead' }, `To ${arg.agent}'s allowance account in the keeper's wallet.`)) : null,
        !agentTo && people.length ? [sec('To a contact'), list(people.slice(0, 8).map((c) => row({ compact: true, start: avatar('person', c.name, null, c.did), title: c.name, onclick: () => swap('pay', c.did) })))] : null,
        agentTo ? null : sec('Or to an address'), form, F.say, synced() ? null : syncState(v));
      put(foot, btn(F.busy ? 'Checking…' : 'Review', () => {
        if (agentTo) return reviewIt(agentTo, amt, note.value.trim(), F);
        if (!okAddr()) { put(F.say, inlineError({ message: 'Fix the address, then review.' })); return undefined; }
        return reviewIt({ addr: addrOf(addr.value).addr }, amt, note.value.trim(), F);
      }, { kind: 'pri', disabled: !synced() || F.busy }));
    };
  });

  // Check and send: what goes, to whom, the fee; then Send (the second tap that moves money). arg: the review.
  screen('send-review', {}, (r) => {
    const body = h('div', { class: 'pad stack' }), foot = h('div'), F = { busy: false, error: null };
    mount(page({ title: 'Check and send', body: [body], foot: [foot] }));
    const kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', null, v));
    const sendIt = async () => {
      F.busy = true; F.error = null; await refresh();
      // Above the pay limit (Settings → Lock): the lock again, the screen's or the words password.
      if (aboveLimit(r.amount)) { try { await askLock(`Send ${xmr(r.amount)} XMR`); } catch (e) { F.error = e; F.busy = false; await refresh(); return; } }
      try { const done = await backend.call('POST', '/api/wallet/send', { id: r.id }); S.walletAt = 0; S.histAt = 0; S.msgsSeq = -1; await swap('send-done', { ...done, from: r.contact && S.stack.some((e) => e.view === 'chat' && e.arg === r.contact) ? 'chat' : 'wallet' }); return; } catch (e) { F.error = e; }
      F.busy = false; await refresh();
    };
    return () => {
      const c = r?.contact ? contactBy(r.contact) : null, to = r?.agent ? `${r.agent}'s allowance` : c ? `${c.name} ✓` : null;
      if (!r?.id) { put(foot); put(body, empty('Nothing to send', 'Start again from Send.')); return; }
      const gone = r.exp <= Date.now() / 1000;
      put(body, h('div', { class: 'list' }, kv('To', to ?? h('span', { class: 'mono' }, `${r.to.slice(0, 4)}…${r.to.slice(-4)}`)),
        kv('Amount', [`${xmr(r.amount)} XMR`, fiat(r.amount, { prefix: ' ' })]), kv('Network fee', `${xmr(r.fee)} XMR`), r.note ? kv('Note', r.note) : null,
        to ? h('div', { class: 'kv' }, h('span', null, 'Address'), h('span', { class: 'mono' }, `${r.to.slice(0, 4)}…${r.to.slice(-4)}`)) : null),
        h('p', { class: 'help' }, c ? `Sent to the address ${c.name}'s identity gave in your chat, so nobody can swap it. Monero payments can't be undone.`
          : r.agent ? 'Moves money from your account to the agent\'s, in the keeper\'s wallet. Monero payments can\'t be undone.'
            : 'Check the first and last 4 characters with the person. Monero payments can\'t be undone.'),
        gone ? h('div', { class: 'card warn' }, h('p', null, 'This check ran out (10 minutes): go back and review again.')) : null, inlineError(F.error));
      const lim = lockKind() ? xmr(payLimit()) : null, above = aboveLimit(r.amount);
      put(foot, btn(F.busy ? 'Sending…' : `Send ${xmr(r.amount)} XMR`, sendIt, { kind: 'pri', disabled: F.busy || gone }),
        lim === null ? null : h('p', { class: 'help center' }, payLimit() === '0' ? 'Every payment asks your lock.' : above ? `Above your ${lim} XMR limit: Send asks your lock.` : `Under your ${lim} XMR limit, so no lock.`));
    };
  });
  screen('send-done', {}, (d) => {
    const c = d?.contact ? contactBy(d.contact) : null, chat = d?.from === 'chat';
    const lead = c ? (d.told ? `${c.name} sees it in your chat. Confirmed in about 2 minutes.` : `It shows in History. ${c.name} wasn't told: the message didn't go.`) : 'It shows in History. Confirmed in about 2 minutes.';
    mount(page({ close: true, onBack: () => (chat ? backTo('chat') : home('wallet')), who: h('h1', { class: 'sr' }, 'Sent'), body: [h('div', { class: 'hero center stack' }, h('div', { class: 'badge-ic' }, icon('check')), h('h2', { class: 'big' }, `Sent ${xmr(d?.amount ?? '0')} XMR`), h('p', { class: 'lead' }, lead))],
      foot: [chat ? btn('Back to the chat', () => backTo('chat'), { kind: 'pri' }) : btn('Back to Wallet', () => home('wallet'), { kind: 'pri' })] }));
  });
  /** Back to the last screen of this view on the stack (a finished payment back to its chat). */
  function backTo(view) {
    const i = S.stack.map((e) => e.view).lastIndexOf(view);
    if (i < 0) { home(); return; }
    const n = S.stack.length - 1 - i;
    if (ours() && H.state?.d === S.stack.length - 1 && n > 0) { H.go(-n); return; }
    S.stack = S.stack.slice(0, i + 1);
    if (ours()) H.replaceState(stateOf(i), '');
    void render();
  }

  // Pay in a chat (task 5: the chat, Pay, Review, Send): to the address the contact sent in this chat (signed by their key), or
  // one pasted; an own agent's allowance account in the keeper's wallet. arg: the contact's DID.
  screen('pay', {}, (did) => {
    const F = { busy: false, say: h('div'), found: undefined }, body = h('div'), foot = h('div'), title = h('h1', null, 'Pay');
    const amt = amountField('Amount (XMR)'), note = input({ maxlength: '100', placeholder: 'Optional' }), have = h('p', { class: 'help' }), money = h('p', { class: 'help' });
    const paste = input({ autocapitalize: 'none', spellcheck: 'false', class: 'mono', placeholder: 'Paste their address' });
    amt.el.addEventListener('input', () => { const a = atomicOf(amt.el.value.trim()); put(money, a ? fiat(a, { prefix: `${amt.el.value.trim()} XMR ` }) : null); });
    mount(page({ who: title, body: [body], foot: [foot] }));
    // Their address: the newest a message of theirs in this chat names (it came signed by their key), else the one used last.
    const lookUp = async () => {
      const r = await backend.call('GET', `/api/messages?contact=${encodeURIComponent(did)}`).catch(() => null);
      const theirs = (r?.messages ?? []).filter((m) => m.dir === 'in').map((m) => ({ ...addrOf(m.text), at: m.at })).filter((x) => x.addr).at(-1) ?? null;
      F.found = theirs;
    };
    void lookUp().then(refresh);
    return async () => {
      const c = contactBy(did), v = await walletNow();
      title.textContent = c ? `Pay ${c.name}` : 'Pay';
      if (!c) { put(foot); put(body, empty('Not a contact', 'It was forgotten.')); return; }
      if (!walletReady()) { put(foot); put(body, walletAway(v)); return; }
      put(have, haveLine(v));
      const w = workerOf(did), a = w ? policyOf(w.worker) : null;
      const saved = v.payees?.[did] ?? null, theirs = F.found?.addr ?? null, addr = theirs ?? saved;
      const to = a ? { agent: a.name, keeper: a.keeper } : addr ? { contact: did, addr } : null;
      put(body, noteCard(), h('div', { class: 'pad stack' },
        amt.node(h('div', null, have, money)),
        field(`Note (${c.name} sees it)`, note),
        a ? h('p', { class: 'help' }, `To ${a.name}'s allowance account in the keeper's wallet.`)
          : addr ? h('p', { class: 'help' }, theirs ? `To the address ${c.name} sent you in this chat (${addr.slice(0, 4)}…${addr.slice(-4)}).` : `To the address you paid ${c.name} at before (${addr.slice(0, 4)}…${addr.slice(-4)}).`)
            : F.found === undefined ? h('p', { class: 'help', role: 'status' }, 'Looking for their address in your chat…')
              : [h('div', { class: 'card' }, h('p', null, `${c.name} hasn't sent you a Monero address in this chat.`), h('p', { class: 'help' }, 'Ask them for one, or paste one they gave you.'),
                h('div', { class: 'btns' }, btn('Ask in the chat', () => act(() => backend.call('POST', '/api/send', { to: did, text: 'Could you send me your Monero address, so I can pay you?' }), () => toast('Asked.'))))),
              field('Their Monero address', paste)],
        F.say, synced() ? null : syncState(v)));
      put(foot, btn(F.busy ? 'Checking…' : 'Review', () => {
        const t = to ?? (addrOf(paste.value) ? { contact: did, addr: addrOf(paste.value).addr } : null);
        if (!t) { put(F.say, inlineError({ message: 'Paste their whole Monero address, then review.' })); return undefined; }
        return reviewIt(t, amt, note.value.trim(), F);
      }, { kind: 'pri', disabled: !synced() || F.busy }));
    };
  });

  // A payment (History → tap): how much, with whom, when, its state; the transaction for whoever wants it.
  screen('tx', {}, (txid) => {
    const body = h('div', { class: 'pad stack' }), title = h('h1', null, 'Payment');
    mount(page({ who: title, body: [body] }));
    let t = null, error = null;
    const load = async () => { try { t = await backend.call('GET', `/api/wallet/tx?txid=${encodeURIComponent(txid)}`); } catch (e) { error = e; } await refresh(); };
    void load();
    const kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', null, v));
    return () => {
      if (error) { put(body, inlineError(error)); return; }
      if (!t) { put(body, h('p', { class: 'lead', role: 'status' }, 'Reading the wallet…')); return; }
      title.textContent = t.dir === 'in' ? 'Received' : 'Sent';
      const st = txStatus(t), c = t.contact ? contactBy(t.contact) : null;
      put(body, h('div', { class: 'center' }, h('p', { class: `big-num${t.dir === 'in' ? ' ok' : ''}` }, `${t.dir === 'in' ? '+' : '−'}${xmr(t.amount)} `, h('small', null, 'XMR')),
        h('p', { class: 'help' }, fiat(t.amount, { suffix: ' at today\'s price' })), h('p', { class: 'lead' }, [txWho(t), t.note ? ` · ${t.note}` : ''].join(''))),
        h('div', { class: 'list' }, kv('Date', t.at ? new Date(t.at * 1000).toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Not in a block yet'),
          kv('Status', st ? h('span', { class: 'warn' }, st) : h('span', { class: 'ok' }, 'Confirmed')),
          kv('Network fee', t.dir === 'in' ? 'paid by the sender' : `${xmr(t.fee)} XMR`), t.address ? kv(t.dir === 'in' ? 'At your address' : 'To', h('span', { class: 'mono' }, `${t.address.slice(0, 6)}…${t.address.slice(-6)}`)) : null),
        h('details', { class: 'more' }, h('summary', null, 'Technical details'), h('p', { class: 'mono' }, `Transaction ${t.txid}${t.height ? ` · block ${t.height.toLocaleString()}` : ''}`)),
        c ? btn(`Open chat with ${c.name}`, () => go('chat', c.did)) : null);
    };
  });

  // The agents' allowances (mock "allowances"): what each may spend this period, and Top up from the wallet.
  screen('allowances', {}, () => {
    S.keeperAt = 0;
    const body = h('div');
    mount(page({ title: 'Agents\' allowances', body: [body] }));
    return async () => {
      const [W] = await Promise.all([workersNow(), keeperNow(), walletNow()]), A = allowanceSum(), live = (W.workers ?? []).filter((w) => w.status === 'enrolled');
      if (!A) { put(body, h('div', { class: 'pad' }, keeperAway(S.keeper) ?? empty('No allowances yet', 'Give an agent an allowance in its keeper entry; it shows here.'))); return; }
      const sw = syncWords();
      const top = (a) => go('send', { agent: a.name, keeper: a.keeper });
      const pickTop = () => (A.mine.length === 1 ? top(A.mine[0]) : sheet({ title: 'Top up which agent?', body: [list(A.mine.map((a) => row({ compact: true, start: avatar('agent', a.name), title: a.name, sub: `${xmr(a.remaining)} XMR left`, onclick: () => { void closeSheet().then(() => top(a)); } })))] }));
      put(body, h('div', { class: 'pad' }, h('p', { class: 'lead' }, 'Money your agents may spend, kept apart from your wallet. ', h('b', null, `${xmr(String(A.left))} XMR`), ` left ${A.when}.`),
        sw ? h('p', { class: `help${synced() ? '' : ' stale'}` }, sw) : null),
        list(A.mine.map((a) => { const w = live.find((x) => x.worker === a.worker); return row({ start: avatar('agent', a.name), title: w?.name ?? a.name, sub: `${xmr(a.spent)} of ${xmr(a.per_period_max)} · ${a.approval_above === null ? 'never asks' : a.approval_above === '0' ? 'asks every time' : `asks above ${xmr(a.approval_above)}`}`, chev: true, onclick: () => go('agent-allowance', a.worker) }); })),
        h('div', { class: 'pad stack' }, walletReady() ? btn('Top up allowances', pickTop, { kind: 'pri', disabled: !synced() }) : null, h('p', { class: 'help' }, RECOVERY)));
    };
  });

  // ================================================================ ME: who I am, people, devices
  screen('me', { tab: 'me' }, () => {
    const head = h('div'), body = h('div');
    mount(page({ title: 'Me', tab: 'me', actions: [ibtn('gear', 'Settings', () => go('settings'))], body: [head, body] }));
    void loadMe().then(refresh);
    return async () => {
      await groupsNow();
      put(head, statusCards(), noteCard());
      const people = allContacts().filter((c) => kindOf(c) === 'person').length, gs = (S.groups?.groups ?? []).filter(liveGroup), teams = gs.filter(isTeam).length, others = gs.length - teams;
      const pub = S.snap?.pending?.public, has = Boolean(S.snap?.me?.picture);
      put(body,
        h('div', { class: 'card me-card' }, picButton('person', profileName(), 'me', has ? 'Change your picture' : 'Add your picture'),
          h('span', { class: 'mid' }, h('h3', null, profileName()), h('p', { class: 'wline' }, wordsLine(myWords())))),
        h('div', { class: 'pad btns' }, btn('My code and QR', () => go('my-code'), { kind: 'pri', ic: 'qr' }), btn('Scan', () => go('scan'), { ic: 'scan' })),
        sec('You and others'),
        list(row({ compact: true, start: icon('people'), title: 'People and teams', chev: true, onclick: () => go('people'),
          sub: [`${people} ${people === 1 ? 'person' : 'people'}`, `${teams} ${teams === 1 ? 'team' : 'teams'}`, others ? `${others} ${others === 1 ? 'group' : 'groups'}` : null].filter(Boolean).join(' · ') }),
          row({ compact: true, start: icon('link'), title: 'Public invite', sub: `For your website or shop · ${pub ? `on until ${day(pub.exp)}` : 'off'}`, chev: true, onclick: () => go('invite') }),
          row({ compact: true, start: icon('pen'), title: 'Sign or check a message', chev: true, onclick: () => go('sign') }),
          row({ compact: true, start: icon('clock'), title: 'Proof of age', sub: 'Show since when this identity exists', chev: true, onclick: () => go('age') })),
        sec('Your things'),
        list(row({ compact: true, start: icon('device'), title: 'Devices and computers', sub: holdsLine(), chev: true, onclick: () => go('devices') }),
          row({ compact: true, start: icon('gear'), title: 'Settings', sub: 'Wallet, lock, backup, relay', chev: true, onclick: () => go('settings') })));
    };
  });
  /** What this page holds, in words (the old mode banner): the identity here, a spare, an agent, or a computer's remote. */
  function holdsLine() {
    const mode = backend.mode?.(), seat = S.snap?.me?.seat;
    if (!mode) return 'This computer holds your identity';
    if (mode.kind === 'remote') return `Controls a computer${mode.via === 'relay' ? ', over the relay' : ''}: no key of yours here`;
    if (mode.kind === 'full') return seat?.here === false ? 'A spare: another device signs in as you' : 'This phone holds your identity';
    return `An agent of yours${Number.isInteger(mode.worker) ? ` (worker ${mode.worker})` : ''}`;
  }

  // ---- People and teams (notes.md H1): people with their agents, teams by owner, @ from a team. A person's agents are the
  // ones they introduced to you (UI-API.md "Links": a contact's link.linked_by), paired, or waiting for your answer.
  function theirAgents(c) {
    return { paired: allContacts().filter((x) => x.link?.linked_by === c.did && x.did !== c.did), offered: (S.snap?.introductions ?? []).filter((x) => x.from === c.did) };
  }
  function agentsLine(c) {
    const A = theirAgents(c), n = A.paired.length, m = A.offered.length;
    if (!n && !m) return 'None introduced to you yet';
    return [n ? `${n} paired` : null, m ? `${m} ${n ? 'more ' : ''}offered` : null].filter(Boolean).join(' · ');
  }
  /** An agent of mine (as the lists mark it): ours by key, of this machine, or a worker of my keeper. */
  const myAgent = (did) => { const c = contactBy(did); return Boolean(c && kindOf(c) === 'agent' && (c.ours || c.local || workerOf(did))); };
  screen('people', {}, () => {
    const body = h('div');
    mount(page({ title: 'People and teams', body: [body] }));
    return async () => {
      await Promise.all([groupsNow(), workersNow()]);
      const all = allContacts(), people = all.filter((c) => kindOf(c) === 'person'), gs = (S.groups?.groups ?? []).filter(liveGroup);
      const owned = new Set(people.flatMap((c) => theirAgents(c).paired.map((a) => a.did)));
      const loose = all.filter((c) => kindOf(c) === 'agent' && !myAgent(c.did) && !owned.has(c.did));
      const sub = (c) => {
        if (!c.words_checked && c.words && !c.local) return h('span', { class: 'warn' }, 'Compare words');
        const n = theirAgents(c).paired.length;
        return [n ? `${n} agent${n === 1 ? '' : 's'}` : 'no agents', c.words_checked ? 'words ✓' : null].filter(Boolean).join(' · ');
      };
      const roles = (g) => { const a = g.members.filter((m) => m.role === 'agent').length, p = g.members.length - a; return `${p} ${p === 1 ? 'person' : 'people'} · ${a} agent${a === 1 ? '' : 's'}`; };
      put(body, sec('People'),
        list(people.map((c) => row({ start: avatar('person', c.name, null, c.did), title: c.name, sub: sub(c), chev: true, attrs: { 'data-person': c.did }, onclick: () => go('person', c.did) })))
          ?? h('p', { class: 'help pad' }, 'Nobody yet: add a person with their code, or give them yours.'),
        loose.length ? [sec('Other agents'), list(loose.map((c) => row({ start: avatar('agent', c.name, null, c.did), title: c.name, sub: 'Not introduced by anyone you know', chev: true, onclick: () => go('chat-info', c.did) })))] : null,
        sec('Teams'),
        list(gs.filter(isTeam).map((g) => row({ start: avatar('group', g.name, null, g.gid), title: g.name, sub: roles(g), chev: true, attrs: { 'data-team': g.gid }, onclick: () => go('team', g.gid) })))
          ?? h('p', { class: 'help pad' }, 'No team yet. A team is a group where people bring their agents.'),
        gs.some((g) => !isTeam(g)) ? [sec('Groups'), list(gs.filter((g) => !isTeam(g)).map((g) => row({ start: avatar('group', g.name, null, g.gid), title: g.name, sub: roles(g), chev: true, onclick: () => go('group-info', g.gid) })))] : null,
        h('div', { class: 'pad stack' }, btn('Add a person', openNewChat, { kind: 'pri', ic: 'plus' }), btn('New team', () => go('group-new'))));
    };
  });
  // A person's page (the mock's person-ana): their picture (a local one, here), four words, their agents, the groups you share.
  screen('person', {}, (did) => {
    const body = h('div'), title = h('h1', null, 'Person'), acts = h('span');
    mount(page({ who: title, actions: [acts], body: [body] }));
    return async () => {
      await groupsNow();
      const c = contactBy(did);
      if (!c) { title.textContent = 'Person'; put(acts); put(body, empty('Not a contact', 'It was forgotten.')); return; }
      title.textContent = safeText(c.name);
      put(acts, tbtn('Message', () => go('chat', did)));
      const A = theirAgents(c), tog = (S.groups?.groups ?? []).filter((g) => liveGroup(g) && g.members.some((m) => m.did === did));
      put(body, noteCard(),
        h('div', { class: 'pad ident' }, picButton(kindOf(c), c.name, did, `Picture for ${c.name}`),
          c.words ? h('p', { class: 'wline' }, wordsLine(c.words), c.words_checked ? h('span', { class: 'ok', 'aria-label': 'compared' }, ' ✓') : null) : null,
          !c.words_checked && c.words && !c.local ? btn('Compare four words', () => go('compare', did), { auto: true }) : null),
        kindOf(c) === 'person' ? [sec('Their agents'),
          list(A.paired.map((a) => row({ start: avatar('agent', a.name, null, a.did), title: a.name, sub: ['paired with you', a.link?.purpose].filter(Boolean).join(' · '), end: h('span', { class: 'ok', 'aria-label': 'paired' }, '✓'), onclick: () => go('chat', a.did) })),
            A.offered.map((x) => row({ start: avatar('agent', x.peer_name ?? 'agent'), title: x.peer_name ?? 'An agent', sub: `they offer it${x.purpose ? `: ${x.purpose}` : ''}`, end: tbtn('Add', () => go('requests')) })))
            ?? h('p', { class: 'help pad' }, 'None yet. An agent of theirs shows here once they introduce it to you.'),
          h('p', { class: 'help pad' }, 'Their agents act for them, not for you. You choose how much of their messages reach you.')] : null,
        tog.length ? [sec('Together in'), list(tog.map((g) => row({ compact: true, start: avatar('group', g.name, null, g.gid), title: g.name, chev: true, onclick: () => go(isTeam(g) ? 'team' : 'group', g.gid) })))] : null,
        h('div', { class: 'pad' }, btn('Chat settings', () => go('chat-info', did))));
    };
  });
  // A team (the mock's team-studio): you and your agents, then each person with the agents they introduced to you; @ opens the
  // chat with the name typed. Agents whose person is not known here are listed apart, said so.
  screen('team', {}, (gid) => {
    const body = h('div'), title = h('h1', null, 'Team'), acts = h('span');
    mount(page({ who: title, actions: [acts], body: [body] }));
    const at = (name) => tbtn('@', () => { S.mention = { gid, name }; void go('group', gid); });
    return async () => {
      await Promise.all([groupsNow(), workersNow()]);
      const g = groupBy(gid);
      if (!g) { title.textContent = 'Team'; put(acts); put(body, empty('No such team here', 'It may have been left.')); return; }
      title.textContent = safeText(g.name);
      put(acts, tbtn('Open chat', () => go('group', gid)));
      const agents = g.members.filter((m) => m.role === 'agent'), people = g.members.filter((m) => m.role !== 'agent' && !m.me), used = new Set();
      const mem = (m, sub) => { used.add(m.did); const ag = m.role === 'agent'; return h('div', { class: 'row', 'data-member': m.did }, avatar(ag ? 'agent' : 'person', m.name, null, m.me ? 'me' : m.contact ? m.did : null),
        h('span', { class: 'mid' }, h('b', null, m.me ? profileName() : m.name), sub ? h('small', null, sub) : null), m.me ? null : h('span', { class: 'end' }, h('span', { 'aria-label': `Mention ${m.name}` }, at(m.name)))); };
      const mine = agents.filter((m) => myAgent(m.did)), me = g.members.find((m) => m.me);
      const groupsOf = people.map((p) => ({ p, ags: agents.filter((a) => !mine.includes(a) && contactBy(a.did)?.link?.linked_by === p.did) }));
      const rest = agents.filter((a) => !mine.includes(a) && !groupsOf.some((x) => x.ags.includes(a)));
      put(body, h('div', { class: 'pad' }, h('p', { class: 'lead' }, 'A team is a group where each person brings their agents. Type @ and a name to ask someone.')),
        sec('You'), h('div', { class: 'list' }, me ? mem(me) : null, mine.map((m) => mem(m, 'your agent'))),
        groupsOf.map(({ p, ags }) => [sec(p.name), h('div', { class: 'list' }, mem(p), ags.map((a) => mem(a, `${p.name}'s agent`)))]),
        rest.length ? [sec('Other agents'), h('div', { class: 'list' }, rest.map((a) => mem(a, 'whose agent is not known here')))] : null,
        g.mine && g.status === 'member' ? h('div', { class: 'pad' }, btn('Add people or agents', () => go('group-new', gid), { ic: 'plus' })) : null,
        h('div', { class: 'pad' }, btn('Team settings', () => go('group-info', gid))));
    };
  });

  // ---- Public invite (the mock's invite, invite-new, invite-on): a long code anyone can use, up to 7 days; it works once
  // (pairing is one to one: a code that pairs many is not in sigelo yet). UI-API.md "Public invite".
  const publicMessage = (code, exp) => `Start a chat with me on sigelo: ${code} (works once, until ${day(exp)}). How: ${PAIR_HOW}`;
  screen('invite', {}, () => {
    const body = h('div');
    mount(page({ title: 'Public invite', body: [body] }));
    const stop = async (p) => {
      if (await ask({ title: 'Stop this public invite?', text: 'The code stops working everywhere it is posted. Chats already started stay.', yes: 'Stop it', no: 'Keep it' })) {
        void act(() => backend.call('POST', '/api/invite/cancel', { id: p.id }), () => toast('Public invite stopped.'));
      }
    };
    return () => {
      const p = S.snap?.pending?.public;
      if (!p) {
        put(body, noteCard(), h('div', { class: 'empty left' }, h('h3', null, 'One code to post'),
          h('p', null, 'Put it on your website, shop window or card. Whoever uses it first starts a chat with you. It lasts up to 7 days, and you can stop it any time.'),
          btn('Make a public invite', () => go('invite-new'), { kind: 'pri' }),
          h('p', { class: 'help' }, 'For one person, use My code instead: it works once, for 10 minutes.')));
        return;
      }
      const c = p.paired ? contactBy(p.paired) : null, kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', null, v));
      put(body, noteCard(), h('div', { class: 'pad stack center' }, p.waiting ? qrBox(p.code) : null, h('p', { class: 'mono code-long', 'data-public': '' }, p.code),
        h('p', { class: 'lead' }, `Answered by you · until ${day(p.exp)}`),
        p.waiting ? h('div', { class: 'btns' }, btn('Share', () => share(publicMessage(p.code, p.exp)), { kind: 'pri' }), btn('Copy', () => copy(p.code))) : null),
        h('div', { class: 'list' }, kv('Used', c ? `by ${c.name}` : p.waiting ? 'not yet' : 'once: it works no more'),
          c ? row({ compact: true, title: `Open the chat with ${c.name}`, chev: true, onclick: () => go('chat', c.did) }) : null),
        h('p', { class: 'help pad' }, 'A code works for one person. Once it is used, make a new one.'),
        h('div', { class: 'pad stack' }, p.waiting ? null : btn('Make a new one', () => go('invite-new'), { kind: 'pri' }), btn('Stop for good', () => stop(p), { kind: 'danger' })));
    };
  });
  screen('invite-new', {}, () => {
    const body = h('div', { class: 'pad stack' }), V = { busy: false, say: null };
    const valid = select('Valid for', [['604800', '7 days'], ['259200', '3 days'], ['86400', '1 day']], '604800');
    const make = async () => {
      if (V.busy) return;
      V.busy = true; V.say = null; await refresh();
      try { await started('POST', '/api/invite', { long: true, public: true, ttl: Number(valid.value) }); await poll(); V.busy = false; await swap('invite'); return; } catch (e) { V.say = e; }
      V.busy = false; await refresh();
    };
    const kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', null, v));
    const makeBtn = btn('Make it', make, { kind: 'pri' });
    mount(page({ title: 'Public invite', body: [body], foot: [makeBtn] }));
    const form = [field('Valid for', valid), h('div', { class: 'list' }, kv('Who answers', 'You'), kv('New chats', 'one: the first person who uses it'))];
    return () => { makeBtn.textContent = V.busy ? 'Making it…' : 'Make it'; put(body, form, inlineError(V.say), S.snap?.pending?.public ? h('p', { class: 'help' }, 'Your public invite now stops: the new code replaces it.') : null); };
  });

  // ---- Sign or check a message (notes.md S2; UI-API.md "Signed statements"): a text signed with your key, portable (copy,
  // share, send in a chat); checked offline against the identity it carries. A file: its SHA-256 signed, checked against it.
  async function fileHashText(f) {
    const d = await crypto.subtle.digest('SHA-256', await f.arrayBuffer()), hx = Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('');
    return `File: ${f.name}\nSize: ${f.size} bytes\nSHA-256: ${hx}`;
  }
  const FILE_SIGNED = /^File: (.+)\nSize: (\d+) bytes\nSHA-256: ([0-9a-f]{64})$/;
  screen('sign', {}, (arg) => {
    const text = h('textarea', { rows: 5, maxlength: '10000', placeholder: 'I agree to share the flat costs, 4 ways.' }), say = h('div'), V = { busy: false };
    const pick = h('input', { type: 'file', hidden: true, 'aria-label': 'A file to sign' });
    pick.addEventListener('change', async () => { const f = pick.files?.[0]; pick.value = ''; if (!f) return; try { text.value = await fileHashText(f); put(say); } catch { put(say, inlineError({ message: 'This page can\'t read that file.' })); } });
    const sign = async () => {
      if (V.busy) return;
      if (!text.value.trim()) { put(say, h('p', { class: 'err', role: 'alert' }, 'Write what you want to sign, or pick a file.')); text.focus?.(); return; }
      V.busy = true; signBtn.textContent = 'Signing…';
      try { const r = await backend.call('POST', '/api/statement/sign', { text: text.value }); V.busy = false; await swap('signed-mine', { statement: r.statement, to: arg?.to ?? null }); return; } catch (e) { put(say, inlineError(e)); }
      V.busy = false; signBtn.textContent = 'Sign';
    };
    const signBtn = btn('Sign', sign, { kind: 'pri', ic: 'pen' });
    const to = arg?.to ? contactBy(arg.to) : null;
    mount(page({ title: 'Sign a message', body: [h('div', { class: 'pad stack' }, to ? h('p', { class: 'lead' }, `For ${to.name}: signed, then sent in your chat.`) : null,
      field('What you want to sign', text, 'Anyone can check it came from you and was not changed.'), say,
      btn('Pick a file instead', () => pick.click()), pick, to ? null : btn('Check someone\'s message instead', () => swap('check'), { kind: 'ghost' }))], foot: [signBtn] }));
    setTimeout(() => text.focus?.(), 0);
    return () => {};
  });
  // Signed (the mock's sign-done): yours, ready to send in a chat, copy or share. arg: {statement, to}.
  screen('signed-mine', {}, (arg) => {
    const body = h('div', { class: 'pad stack' }), say = h('div');
    mount(page({ title: 'Signed', body: [body] }));
    const st = String(arg?.statement ?? ''), shown = st.split('\n-- Signed with sigelo')[0];
    const sendTo = async (did) => {
      put(say, h('p', { class: 'help', role: 'status' }, 'Sending…'));
      try { await backend.call('POST', '/api/send', { to: did, statement: st }); if (S.sheet) await closeSheet(); if (arg?.to === did) back(); else await swap('chat', did); } catch (e) { put(say, inlineError(e)); }
    };
    const pickChat = () => {
      const people = allContacts().filter((c) => c.status !== 'pair_again');
      sheet({ title: 'Send in which chat?', body: [list(people.map((c) => row({ compact: true, start: avatar(kindOf(c), c.name, null, c.did), title: c.name, onclick: () => sendTo(c.did) })))
        ?? h('p', { class: 'help pad' }, 'No chats yet: copy it instead.')] });
    };
    const to = arg?.to ? contactBy(arg.to) : null;
    put(body, h('div', { class: 'card soft' }, h('p', { class: 'ok big-ok' }, '✓ Signed by you'), h('p', { class: 'text' }, shown)),
      say, btn(to ? `Send to ${to.name}` : 'Send in a chat', () => (to ? sendTo(to.did) : pickChat()), { kind: 'pri' }),
      btn('Copy signed text', () => copy(st)), btn('Share', () => share(st), { kind: 'ghost' }),
      h('p', { class: 'help' }, 'The signed text carries your four words and a check line: keep them with it.'));
    return () => {};
  });
  screen('check', {}, (arg) => {
    const text = h('textarea', { rows: 6, value: arg?.text ?? '' }), say = h('div');
    const pick = h('input', { type: 'file', accept: 'text/*,.txt', hidden: true, 'aria-label': 'A file with a signed message' });
    pick.addEventListener('change', async () => { const f = pick.files?.[0]; pick.value = ''; if (!f) return; try { text.value = (await f.text()).slice(0, 400000); put(say); } catch { put(say, inlineError({ message: 'This page can\'t read that file.' })); } });
    const check = () => {
      if (!text.value.trim()) { put(say, h('p', { class: 'err', role: 'alert' }, 'Paste the signed message first, all of it.')); text.focus?.(); return undefined; }
      return go('statement', { text: text.value });
    };
    mount(page({ title: 'Check a message', body: [h('div', { class: 'pad stack' }, field('Paste a signed message', text, 'All of it, the last line too.'), say, btn('Pick a file', () => pick.click()), pick)],
      foot: [btn('Check', check, { kind: 'pri' })] }));
    return () => {};
  });
  // A statement checked (the mock's verify-result): who signed it, when, the text as signed. arg: {text} (the portable form).
  screen('statement', {}, (arg) => {
    const body = h('div', { class: 'pad stack' }), say = h('div');
    mount(page({ title: 'Signed message', body: [body] }));
    let r = null;
    const kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', null, v));
    const pick = h('input', { type: 'file', hidden: true, 'aria-label': 'The file it names' });
    pick.addEventListener('change', async () => {
      const f = pick.files?.[0]; pick.value = '';
      if (!f) return;
      let same = false;
      try { same = (await fileHashText(f)).split('\n')[2] === r.text.split('\n')[2]; } catch { put(say, inlineError({ message: 'This page can\'t read that file.' })); return; }
      put(say, same ? h('p', { class: 'ok', role: 'status' }, '✓ The same file: not one byte changed.') : h('p', { class: 'err', role: 'alert' }, 'Not the same file: its bytes differ from the ones signed.'));
    });
    backend.call('POST', '/api/statement/check', { statement: String(arg?.text ?? '') }).then((x) => { r = x; }, (e) => { r = { valid: false, message: plain(e) }; }).then(() => refresh());
    return () => {
      if (!r) { put(body, h('p', { class: 'help' }, 'Checking…')); return; }
      if (!r.valid) {
        put(body, h('div', { class: 'card warn' }, h('p', { class: 'danger big-ok' }, '✗ Not a valid signature'), h('p', null, r.message ?? 'It does not check.')),
          h('p', { class: 'help' }, 'Do not trust what it says. Ask the sender to sign it again.'), btn('Check another message', () => go('check'), { kind: 'pri' }));
        return;
      }
      const by = r.by ?? { kind: 'unknown' }, name = by.kind === 'me' ? 'you' : by.name ?? 'an identity you don\'t know';
      const what = by.kind === 'me' ? 'Not changed since you signed it.'
        : by.kind === 'contact' ? (by.words_checked ? 'Their four words match the ones you compared. Not changed since they signed it.' : 'Not changed since they signed it. Compare four words with them to know the key is theirs.')
          : 'Not changed since it was signed. Ask the signer which four words they see: the same four words, it\'s them.';
      const at = new Date(r.iat * 1000).toLocaleString([], { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      const file = FILE_SIGNED.exec(r.text);
      put(body, h('div', { class: 'card soft' }, h('p', { class: 'ok big-ok' }, `✓ Signed by ${name}`), h('p', { class: 'help' }, what)),
        by.kind === 'contact' && !by.words_checked ? btn('Compare four words', () => go('compare', by.did), { kind: 'pri' }) : null,
        h('div', { class: 'list' }, kv('Signed', at), kv('By', `${by.kind === 'me' ? 'You' : by.name ?? 'Not a contact'} · ${r.words}`),
          r.created ? kv('Identity since', `${day(Date.parse(r.created) / 1000)} (its own date, not proven)`) : null,
          r.current ? null : kv('Key', 'an earlier key of theirs, since replaced')),
        r.edited ? h('div', { class: 'card warn' }, h('p', null, 'The text shown with it was changed. What was signed is this:')) : null,
        h('div', { class: 'card' }, h('p', { class: 'text' }, r.text)),
        file ? [btn('Compare with the file', () => pick.click()), pick, say] : null,
        btn('Check another message', () => go('check')));
    };
  });

  // ---- Proof of age (notes.md E1): what shows this identity's age today, from its own bundle (GET /api/attestations): the
  // day its genesis names (its own word) and each service that vouches for it, signed with a date. The Monero record the
  // mock draws needs a wallet transaction this version cannot make: said so, nothing pretended.
  const ADMISSION = { open: 'open to anyone', captcha: 'after a captcha', invite: 'invited by a member', payment: 'after a payment', human: 'a person checked', stake: 'a bond held' };
  screen('age', {}, () => {
    const body = h('div', { class: 'pad stack' }), A = { r: null, e: null };
    mount(page({ title: 'Proof of age', body: [body] }));
    backend.call('GET', '/api/attestations').then((r) => { A.r = r; }, (e) => { A.e = e; }).then(() => refresh());
    const kv = (k, v) => h('div', { class: 'kv' }, h('span', null, k), h('span', null, v));
    return () => {
      const r = A.r, list_ = r?.attestations ?? [];
      put(body, h('h3', null, 'Prove your identity is not new'),
        h('p', { class: 'lead' }, 'Some services only trust identities older than a few weeks. A service that vouches for yours signs the day it does; anyone can check it later.'),
        sec('What shows its age today'),
        !r ? (A.e ? inlineError(A.e) : h('p', { class: 'help' }, 'Loading…')) : [
          h('div', { class: 'list' }, r.created ? kv('Made on', `${day(Date.parse(r.created) / 1000)} · its own date, not proven`) : null,
            list_.map((a) => row({ compact: true, title: a.ctx, sub: [`vouched for it on ${day(a.iat)}`, ADMISSION[a.admission] ?? a.admission, `until ${day(a.exp)}`].join(' · '), subCls: 'wrap', attrs: { 'data-attestation': a.iss } }))),
          list_.length ? null : h('p', { class: 'help' }, 'No service vouches for this identity yet. When one does, the day it signed shows here.')],
        h('div', { class: 'card' }, h('p', null, h('b', null, 'Recording it on the Monero chain: not in this version.')),
          h('p', { class: 'help' }, 'One small transaction would record that this identity exists from that day, public and permanent. This version can\'t make it.')));
    };
  });

  /** Camera (where the browser has one), an image file or a pasted image, or the text: each text read goes to onText; true stops the camera. */
  function scanner(onText) {
    const status = h('p', { class: 'help', role: 'status' }), video = h('video', { class: 'scan', muted: true, playsInline: true, 'aria-label': 'Camera', hidden: true });
    const pick = h('input', { type: 'file', accept: 'image/*', 'aria-label': 'An image of the QR', hidden: true }), text = h('textarea', { rows: 2, autocomplete: 'off', spellcheck: 'false' });
    const say = (t) => { status.textContent = t ?? ''; };
    const canvas = document.createElement('canvas'), g = canvas.getContext('2d', { willReadFrequently: true });
    let detector = null, stream = null, timer = 0, busy = false;
    try { if ('BarcodeDetector' in window) detector = new window.BarcodeDetector({ formats: ['qr_code'] }); } catch {}
    async function decode(src, w, ht, max) {
      if (detector) { try { const r = await detector.detect(src); if (r[0]?.rawValue) return r[0].rawValue; } catch {} }
      const d = await qrDec();
      if (!d || !g) return null;
      const k = Math.min(1, max / Math.max(w, ht));
      canvas.width = Math.max(1, Math.round(w * k)); canvas.height = Math.max(1, Math.round(ht * k));
      g.drawImage(src, 0, 0, canvas.width, canvas.height);
      const px = g.getImageData(0, 0, canvas.width, canvas.height);
      try { return d.jsQR(px.data, px.width, px.height)?.data ?? null; } catch { return null; }
    }
    const stop = () => { clearInterval(timer); timer = 0; stream?.getTracks().forEach((t) => t.stop()); stream = null; video.hidden = true; cam.textContent = 'Camera'; };
    const give = async (t) => { if (await onText(t)) stop(); };
    async function fromImage(blob) {
      say('Reading the image…');
      let bm;
      try { bm = await createImageBitmap(blob); } catch { say('Not an image this page can read.'); return; }
      const t = (await decode(bm, bm.width, bm.height, 1600)) ?? (await decode(bm, bm.width, bm.height, 800));
      bm.close?.();
      if (t) { say(''); await give(t); } else say('No QR code found in that image.');
    }
    const cam = btn('Camera', async () => {
      if (stream) { stop(); say(''); return; }
      try { stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false }); } catch (e) { say(`No camera here (${e.name}): use an image, or paste the text.`); return; }
      video.srcObject = stream; video.hidden = false; cam.textContent = 'Stop the camera';
      await video.play().catch(() => {});
      say('Point the camera at the QR.');
      timer = setInterval(async () => {
        if (busy || video.readyState < 2) return;
        busy = true;
        try { const t = await decode(video, video.videoWidth, video.videoHeight, 640); if (t) await give(t); } finally { busy = false; }
      }, 200);
    }, { kind: 'pri', ic: 'scan' });
    // Feature detection: no getUserMedia, or no camera listed (WebKitGTK on some phones): image and paste only.
    if (!navigator.mediaDevices?.getUserMedia) cam.hidden = true;
    else navigator.mediaDevices.enumerateDevices?.().then((ds) => { if (!ds.some((d) => d.kind === 'videoinput')) { cam.hidden = true; say('No camera found: take a photo or a screenshot and use "From an image", or paste the text.'); } }).catch(() => {});
    pick.onchange = () => { const f = pick.files?.[0]; pick.value = ''; if (f) fromImage(f); };
    text.addEventListener('paste', (ev) => {
      const img = [...(ev.clipboardData?.items ?? [])].find((i) => i.type.startsWith('image/'));
      if (img) { ev.preventDefault(); fromImage(img.getAsFile()); }
    });
    const use = () => { const t = text.value; text.value = ''; if (t.trim()) give(t); };
    const el = h('div', { class: 'stack' }, cam, video, btn('From an image', () => pick.click()), pick,
      field('Or paste its text, a code, or a screenshot of it', text), btn('Use the text', use), status);
    el.stop = stop; el.say = say;
    return el;
  }

  // Devices and computers: this device's place; a remote profile's computers (the apps); on a computer's page the
  // devices it added (DEVICES.md: SAFE here, the device an agent of yours; FULL only in a terminal), and this
  // computer as a new device (by QR). Never remote: moving keys needs a human at that computer.
  function shellComputers(wk) {
    const ask_ = shellAsk(wk);
    return { list: () => ask_('computers'), use: (id) => ask_('computer-use', { id }), add: () => ask_('computer-add'), forget: (id) => ask_('computer-forget', { id }) };
  }
  const COMPUTERS = LOCAL?.computers ?? (PROFILE_SHELL ? shellComputers(PROFILE_SHELL) : null);
  const REVOKE_CONTROL = 'sigelo-agent ui --revoke-control <name>';
  const computerSub = (c) => [c.words ? wordsLine(c.words) : null, c.via === 'relay' ? `over the relay${c.where ? ` ${c.where}` : ''}` : `on the LAN${c.where ? ` ${c.where}` : ''}`,
    c.last_used ? `used ${ago(c.last_used)}` : null].filter(Boolean).join(' · ');
  const STATE_SAYS = { code: 'waiting for the device to scan the code', words: 'compare the four words', sending: 'sending its key, end to end', done: 'added', refused: 'not added', expired: 'the code ran out: add it again' };
  /** This device's row (the mock's devices): it holds your identity, it is a spare, an agent of yours, or a computer's remote. */
  function hereRow() {
    const mode = backend.mode?.(), seat = S.snap?.me?.seat;
    if (!mode) return row({ start: icon('check'), title: 'Holds your identity', sub: 'Signs in as you. Your key is in this computer\'s identity file.', subCls: 'wrap' });
    if (mode.kind === 'remote') return row({ start: icon('device'), title: 'Controls a computer', sub: `${mode.via === 'relay' ? 'Over the relay. ' : ''}No key of yours on this phone.`, subCls: 'wrap' });
    if (mode.kind === 'full' && seat?.here === false) return row({ start: icon('device'), title: 'A spare', sub: `${seat.holder} signs in as you now. Make this phone the main one only if that one is stopped or lost.`, subCls: 'wrap' });
    if (mode.kind === 'full') return row({ start: icon('check'), title: 'Holds your identity', sub: 'Signs in as you. Your key is sealed by the phone.', subCls: 'wrap' });
    return row({ start: icon('agent'), title: 'An agent of yours', sub: `It holds its own key${Number.isInteger(mode.worker) ? ` (worker ${mode.worker})` : ''}, vouched for by yours.`, subCls: 'wrap' });
  }
  screen('devices', {}, () => {
    const here = h('div'), comp = h('div'), devs = h('div'), C = { r: null, say: null, done: null, asked: false };
    const D = devicesPart();
    mount(page({ title: 'Devices and computers', body: [here, comp, devs] }));
    S.leave = () => D.stop();
    const load = () => COMPUTERS.list().then((r) => { C.r = r; return refresh(); }, (e) => { C.r = null; C.say = e.check === 'not_remote' ? null : e; return refresh(); });
    const run = async (fn, after) => { C.say = null; C.done = null; try { const r = await fn(); if (!r?.reload) { after?.(r); await load(); } } catch (e) { C.say = e; await refresh(); } };
    return async () => {
      put(here, sec(backend === http ? 'This computer' : 'This phone'), list(hereRow()),
        LOCAL && S.snap?.me?.seat?.here === false ? h('div', { class: 'pad' }, btn('Make this phone the main one', () => seatTake(), { kind: 'pri' })) : null);
      if (COMPUTERS && !C.asked) { C.asked = true; void load(); }
      if (COMPUTERS && C.r) {
        const { active, limit, computers } = C.r;
        const forget = async (c) => {
          if (!(await ask({ title: `Forget ${c.name}?`, text: `This phone drops its control key for it. The computer keeps the control until you revoke it there: ${REVOKE_CONTROL}`, yes: `Forget ${c.name}` }))) return;
          await run(() => COMPUTERS.forget(c.id), (r) => { C.done = `${c.name} forgotten on this phone. Revoke it on the computer too: ${r?.revoke ?? REVOKE_CONTROL}`; });
        };
        put(comp, sec('Computers this phone can control'), C.done ? h('div', { class: 'card warn' }, h('p', null, C.done)) : null, inlineError(C.say),
          list(computers.map((c) => row({ start: icon('device'), title: c.name, sub: computerSub(c), attrs: { 'data-computer': c.id },
            end: [c.id === active ? h('span', { class: 'ok' }, 'In use') : tbtn('Use', () => run(() => COMPUTERS.use(c.id))), tbtn('Forget', () => forget(c))] }))) ?? h('p', { class: 'help pad' }, 'No computer yet.'),
          h('div', { class: 'pad stack' }, btn('Connect a computer', () => run(() => COMPUTERS.add()), { ic: 'plus', disabled: computers.length >= limit }),
            h('p', { class: 'help' }, computers.length >= limit ? `At most ${limit} computers: forget one to add another.` : 'Each computer is paired once, by its code or QR.')));
      } else put(comp, C.say ? inlineError(C.say) : null);
      const move = h('details', { class: 'more pad' }, h('summary', null, 'Move signing in to another device'), h('p', { class: 'help' }, 'Only one device signs in as you at a time. To move it, open sigelo there: on a phone restored from your 25 words as a spare, "Make this phone the main one".'));
      if (backend === http) { put(devs, D.el, move); await D.update(); } else if (backend.mode?.()?.kind === 'full') put(devs, move);
    };
  });
  /** A computer's devices (DEVICES.md), carried from the old page: add online or offline, the list, this computer as the new device. */
  function devicesPart() {
    const adding = h('div', { class: 'pad stack' }), offline = h('div', { class: 'pad' }), lst = h('div'), joining = h('div', { class: 'pad stack' }), words = h('div');
    const name = input({ autocapitalize: 'none', maxlength: '20', placeholder: 'phone' }), myName = input({ autocapitalize: 'none', maxlength: '20', placeholder: 'device' });
    const D = { got: new Map(), count: 0, need: false, offline: null, timer: 0, result: null };
    const addDevice = (off) => act(() => backend.call('POST', '/api/devices/add', { name: name.value.trim(), ...(off && { offline: true }) }), (r) => { name.value = ''; if (off) showFrames(r); });
    function showFrames(r) {
      clearInterval(D.timer);
      D.offline = { ...r, at: 0 };
      const cv = h('div'), label = h('p', { class: 'help center' });
      const draw = async () => { const o = D.offline; if (!o?.frames) return; const c = await qrCanvas(o.frames[o.at]); put(cv, c ?? h('p', { class: 'mono' }, o.frames[o.at])); label.textContent = `Frame ${o.at + 1} of ${o.frames.length}`; };
      const next = () => { if (!D.offline?.frames) return; D.offline.at = (D.offline.at + 1) % D.offline.frames.length; void draw(); };
      put(offline, h('div', { class: 'card stack' }, h('p', null, `${r.name}: scan every frame on the device, any order (worker ${r.worker}).`), cv, label,
        h('div', { class: 'btns' }, btn('Next frame', next), btn('All scanned: show the words', wordsNow, { kind: 'pri' }))));
      void draw();
      if (r.frames.length > 1) D.timer = setInterval(next, 1000);
    }
    // The words never share the screen with the frames: those go first, and the words come once.
    async function wordsNow() {
      clearInterval(D.timer);
      const o = D.offline;
      D.offline = null;
      put(offline, h('p', { class: 'help' }, 'Getting the words…'));
      let w = null;
      try { w = (await backend.call('POST', '/api/devices/words', { id: o.id })).words; } catch (e) { put(offline, inlineError(e)); return; }
      put(offline, h('div', { class: 'card stack' }, h('p', null, `Type these on ${o.name} (shown once; never photograph them with the frames):`), fourWords(w.split(' ')),
        h('p', { class: 'mono' }, `It shows worker ${o.worker}, ${o.did}`), h('p', { class: 'help' }, 'Its invite lives 7 days: keep this page open (or come back) once the device is online, so its answer is read.'),
        btn('Typed: hide them', () => put(offline), { kind: 'pri' })));
      w = null;
    }
    const send = async (texts, typed) => {
      D.result = null;
      try {
        const r = await backend.call('POST', '/api/devices/scan', { texts, name: myName.value.trim() || 'device', ...(typed !== undefined && { words: typed }) });
        if (r.kind === 'offline' && r.state === 'frames') { D.count = r.count; scan.say(`${r.have} of ${r.count} frames; still missing ${r.missing.join(', ')}`); return false; }
        if (r.kind === 'offline' && r.state === 'words') { D.count = r.count; D.need = true; scan.say(`All ${r.count} frame(s) read.`); askWords(); return true; }
        D.result = r; D.got.clear(); D.need = false; put(words); scan.say('');
        if (r.kind === 'online') scan.say('Pairing with the giving side…');
        await poll();
        return true;
      } catch (e) { scan.say(''); S.note = e; await refresh(); return e.check !== 'device_frame'; }
    };
    const scan = scanner(async (t) => {
      const text = t.trim();
      if (!/^SGD1/.test(text)) { D.got.clear(); return send([text]); }
      const k = text.slice(4, 8);   // frame index and count: keep each once
      if (D.got.get(k) === text) return false;
      D.got.set(k, text);
      return send([...D.got.values()]);
    });
    function askWords() {
      const w = h('input', { type: 'password', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
      const go_ = async () => { const typed = w.value; w.value = ''; await send([...D.got.values()], typed); if (D.need) w.focus(); };
      w.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') void go_(); });
      put(words, h('div', { class: 'card stack' }, field('Type the words the giving screen shows (not shown here)', w), btn('Open', go_, { kind: 'pri' })));
      w.focus();
    }
    const el = h('div', null, sec('Add a device'),
      h('div', { class: 'pad stack' }, field('Its name', name, 'a-z, 0-9, _ and -. It becomes an agent of yours with its own key, vouched for 14 days and renewed. To give it your identity too, use a terminal: sigelo-agent device add --name <n> --full.'),
        h('div', { class: 'btns' }, btn('Add (online)', () => addDevice(false), { kind: 'pri' }), btn('Add offline', () => addDevice(true)))),
      adding, offline, sec('Your devices'), lst, h('div', { class: 'pad' }, btn('Send the list to every device', () => act(() => backend.call('POST', '/api/devices/sync')))),
      sec('This is the new device'), h('div', { class: 'pad stack' }, field('Name for this device', myName, 'Scan the QR the other screen shows: the online code, or every frame of an offline one.'), scan, words), joining);
    const update = async () => {
      const L = await backend.call('GET', '/api/devices').catch((e) => { S.note = e; return null; });
      if (!L) return;
      const cards = [];
      for (const a of L.adding) {
        const kids = [h('p', null, h('b', null, a.name), ` · worker ${a.worker} · ${STATE_SAYS[a.state] ?? a.state}`)];
        if (a.state === 'code') kids.push((await qrCanvas(a.qr)) ?? '', h('p', { class: 'mono' }, a.qr), h('p', null, 'or type ', h('b', { class: 'code sm' }, a.short), ' · ', countdown(a.exp), ' left, once'));
        else if (a.state === 'words') {
          kids.push(h('p', null, 'Do the device\'s four words read:'), a.words ? fourWords(a.words) : h('p', { class: 'help' }, '(not known yet)'),
            h('div', { class: 'btns' }, btn('They match: send its key', () => act(() => backend.call('POST', '/api/devices/confirm', { id: a.id, match: true })), { kind: 'pri' }),
              btn('They don\'t match', () => act(() => backend.call('POST', '/api/devices/confirm', { id: a.id, match: false })), { kind: 'danger' })));
        }
        if (a.check) kids.push(h('p', { class: 'warn' }, a.detail ?? a.check));
        cards.push(h('div', { class: 'card stack' }, kids));
      }
      put(adding, cards);
      const revoke = async (d, lost) => {
        const yes = await ask(lost ? { title: `${d.name} lost or stolen?`, text: `It is revoked and forgotten now${d.rank === 'full' ? '; it held your identity: the steps with your 25 words follow' : ''}.`, yes: `Revoke ${d.name} now` }
          : { title: `Revoke ${d.name}?`, text: 'It is told to delete its keys, and forgotten here when it answers.', yes: `Revoke ${d.name}` });
        if (!yes) return;
        void act(() => backend.call('POST', '/api/devices/revoke', { name: d.name, ...(lost && { lost: true }) }), (r) => {
          if (r.steps) S.note = { message: [...r.steps.now.map((x) => `Done: ${x}`), 'With your 25 words:', ...r.steps.words.map((x, i) => `${i + 1}. ${x}`)].join('\n') };
        });
      };
      put(lst, list(L.devices.map((d) => row({ start: icon('device'), title: d.name, attrs: { 'data-device': d.name },
        sub: [`worker ${d.worker}`, d.via === 'here' ? 'this machine' : null, d.rank === 'full' ? 'holds your identity' : null, d.revoked ? `revoked ${when(d.revoked)}` : d.paired ? 'paired' : 'not paired yet', `added ${when(d.added)}`].filter(Boolean).join(' · '),
        end: d.revoked || d.via === 'here' ? null : [tbtn('Revoke', () => revoke(d, false)), tbtn('Lost', () => revoke(d, true))] })))
        ?? h('p', { class: 'help pad' }, L.list ? 'None left.' : 'None yet: Add a device.'));
      const j = L.joining, r = D.result, out = [];
      if (j) {
        if (j.state === 'joining') out.push(h('p', null, 'Pairing with the giving side…'));
        if (j.state === 'words') out.push(h('div', { class: 'card stack' }, h('p', null, 'The giving screen asks whether its words read:'), j.words ? fourWords(j.words) : h('p', { class: 'help' }, '(waiting for the pairing)'), h('p', { class: 'help' }, 'Answer there; this device gets its key once you do.')));
        if (j.state === 'done') out.push(h('p', { class: 'ok' }, `✓ This device is worker ${j.worker ?? '?'} (${j.did}), in ${j.file}`));
        if (j.state === 'failed') out.push(h('div', { class: 'card warn' }, inlineError({ message: `${j.check}: ${j.message}` }), j.long ? h('p', { class: 'mono' }, j.long) : null));
      }
      if (r?.kind === 'offline' && r.state === 'done') out.push(h('p', { class: 'ok' }, `✓ This device is worker ${r.worker} (${r.did}) of ${r.operator}, in ${r.file}${r.paired ? ', paired' : '; it pairs once the giving side is online'}. Check the DID against the giving screen.`));
      put(joining, out);
    };
    return { el, update, stop: () => { scan.stop(); clearInterval(D.timer); } };
  }

  // ================================================================ SETTINGS: this profile, this phone
  screen('settings', {}, () => {
    const body = h('div');
    mount(page({ title: 'Settings', body: [body] }));
    void loadMe().then(versionNow).then(lockState).then(refresh);
    return () => {
      const me = S.snap?.me, n = S.profiles?.profiles?.length;
      put(body, sec(`This profile: ${profileName()}`),
        list(row({ compact: true, start: icon('wallet'), title: 'Wallet', sub: walletOn() ? 'On' : 'Off', chev: true, onclick: () => go('set-wallet') }),
          row({ compact: true, start: icon('shield'), title: 'Backup and recovery', sub: backupLine(), chev: true, onclick: () => go('set-backup') }),
          row({ compact: true, start: icon('send'), title: 'Relay', sub: me ? `${me.relay} · ${me.online ? 'connected' : 'not connected'}` : null, chev: true, onclick: () => go('set-relay') }),
          row({ compact: true, start: icon('chat'), title: 'Chats and history', chev: true, onclick: () => go('set-chats') })),
        sec(LOCAL || SHELL ? 'This phone' : 'This computer'),
        list(row({ compact: true, start: icon('lock'), title: 'Lock', sub: lockLine(), chev: true, onclick: () => go('set-lock') }),
          PROFILES ? row({ compact: true, start: icon('people'), title: 'Profiles', sub: n ? `${n} on this phone` : null, chev: true, onclick: () => go('profiles-manage') }) : null,
          row({ compact: true, start: icon('pen'), title: 'Appearance', sub: 'Theme and colour', chev: true, onclick: () => go('set-appearance') }),
          row({ compact: true, start: icon('info'), title: 'About', sub: versionLine(), chev: true, onclick: () => go('about') })));
    };
  });
  const backupLine = () => [SEC.st?.kept ? '25 words kept here, locked' : '25 words on paper', S.me?.recovery === 'set' ? 'recovery key set' : S.me ? 'no recovery key' : null].filter(Boolean).join(' · ');

  // Settings → Wallet (notes.md "Decided"): the switch (this profile's, in its settings), a local price (opt-in, with what
  // it tells whom) and its currency, the Monero node, the wallet service, the approvers; the recovery fact.
  screen('set-wallet', {}, () => {
    const body = h('div');
    mount(page({ title: 'Wallet', body: [body] }));
    const cur = select('Currency', CURRENCIES.map(([c, n]) => [c, `${c} · ${n}`]), 'EUR');
    cur.addEventListener('change', () => act(() => backend.call('POST', '/api/settings', { currency: cur.value }), () => { S.priceAt = 0; if (S.snap?.me?.wallet) S.snap.me.wallet.currency = cur.value; void priceNow(); }));
    let say = null;
    return async () => {
      const on = walletOn(), w = S.snap?.me?.wallet, v = on ? await walletNow() : null, here = v && v.where !== 'none';
      if (on && !w?.currency) cur.value = regionCurrency(); else if (w?.currency && document.activeElement !== cur) cur.value = w.currency;
      const K = on && here ? await keeperNow() : null, ks = keeperHere()?.keepers ?? [];
      const svc = walletReady()?.service, svcText = !here ? null : svc ? (svc.kind === 'keeper' ? `The keeper's wallet${ks.length > 1 ? ` (${svc.keeper})` : ''} · account ${svc.account}` : `${svc.url} · account ${svc.account}`) : 'Not chosen';
      const nodeText = !here ? null : v?.node ? `${v.node} · ${syncWords() ?? ''}` : 'None set';
      const appr = ks.length ? (ks.some((k) => k.me_approver) ? `You${ks.reduce((n, k) => n + k.approvers.filter((d) => d !== S.snap?.me?.did).length, 0) ? ' and others' : ''}` : `${ks.reduce((n, k) => n + k.approvers.length, 0)} · not you`) : null;
      put(body, inlineError(say), h('div', { class: 'list' }, toggle(`Wallet for ${profileName()}`, on ? 'On' : 'Off', on, (x) => { say = null; void setWallet(x).catch((e) => { say = e; }).then(refresh); })),
        h('div', { class: 'pad' }, h('p', { class: 'help' }, LOCAL && !SHELL && v?.where === 'none' ? 'On: a Wallet tab and Pay in chats. This phone has no wallet yet: your balance, Receive and Send are on the computer\'s page.'
          : 'On: a Wallet tab with your balance, receive, send and history, and Pay in chats. The page keeps your wallet up to date while it shows it.'),
          h('p', { class: 'help' }, 'Off: no wallet tab and no wallet syncing. Your agents\' allowances keep working.')),
        on && here ? [h('div', { class: 'list' },
          toggle('Show a local price', 'Fetches the Monero price from the network. Off keeps the app fully private.', w?.prices === true,
            (x) => act(() => backend.call('POST', '/api/settings', { prices: x, ...(x && !w?.currency && { currency: cur.value }) }), () => { S.priceAt = 0; S.price = null; if (S.snap?.me?.wallet) Object.assign(S.snap.me.wallet, { prices: x, currency: w?.currency ?? cur.value }); void priceNow(); })),
          w?.prices ? h('div', { class: 'row' }, h('span', { class: 'mid' }, h('label', { for: cur.id || (cur.id = `f${++fid}`) }, h('b', null, 'Currency')), h('small', null, w.currency ? 'Your choice' : LOCAL || SHELL ? 'From your phone\'s region' : 'From your region')), cur) : null),
          w?.prices ? h('p', { class: 'help pad' }, `Prices come from ${S.price?.source ?? 'CoinGecko'} through this ${backend === http ? 'computer' : 'computer\'s page'}: it learns that a price was asked, and from which address on the internet; never your wallet, balance or payments. Asked at most every 10 minutes.`,
            S.price?.at ? ` Last price ${hhmm(S.price.at)}${S.price.stale ? ' (it didn\'t answer since)' : ''}.` : S.price?.error ? ' It doesn\'t answer right now.' : '') : null,
          list(row({ compact: true, title: 'Monero node', sub: nodeText, chev: true, onclick: () => go('set-node') }),
            row({ compact: true, title: 'Wallet service', sub: svcText, chev: true, onclick: () => go('set-service') }),
            appr !== null ? row({ compact: true, title: 'Approvers', sub: appr, chev: true, onclick: () => go('set-approvers') }) : null),
          lockKind() ? list(row({ compact: true, title: 'Ask for the lock above', sub: payLimit() === '0' ? 'Every payment' : `${xmr(payLimit())} XMR`, chev: true, onclick: () => go('set-lock') })) : null,
          h('div', { class: 'pad stack' }, h('p', { class: 'help' }, RECOVERY), btn('Open Wallet', () => { S.stack = [S.stack[0], { view: 'wallet' }]; if (ours()) H.replaceState(stateOf(1), ''); void render(); }, { kind: 'pri' }))]
          : on ? [walletAway(v)] : null);
      void K;
    };
  });
  // The 16 currencies of the mock; the first choice follows the region of the page's language (EUR when it names none).
  const CURRENCIES = [['EUR', 'Euro'], ['USD', 'US dollar'], ['GBP', 'Pound sterling'], ['CHF', 'Swiss franc'], ['RON', 'Romanian leu'], ['JPY', 'Japanese yen'], ['CAD', 'Canadian dollar'], ['AUD', 'Australian dollar'],
    ['SEK', 'Swedish krona'], ['NOK', 'Norwegian krone'], ['DKK', 'Danish krone'], ['PLN', 'Polish złoty'], ['CZK', 'Czech koruna'], ['HUF', 'Hungarian forint'], ['BRL', 'Brazilian real'], ['INR', 'Indian rupee']];
  const REGION = { US: 'USD', GB: 'GBP', CH: 'CHF', LI: 'CHF', RO: 'RON', JP: 'JPY', CA: 'CAD', AU: 'AUD', SE: 'SEK', NO: 'NOK', DK: 'DKK', PL: 'PLN', CZ: 'CZK', HU: 'HUF', BR: 'BRL', IN: 'INR' };
  const regionCurrency = () => REGION[String(globalThis.navigator?.language ?? '').split('-')[1]?.toUpperCase() ?? ''] ?? 'EUR';

  // Settings → Wallet → Monero node (the relay picker's look): the node your wallet reads the chain from; tap to use, hold to remove.
  screen('set-node', {}, () => {
    const N = { list: null, say: null, busy: null };
    const body = h('div'), addIn = input({ autocapitalize: 'none', maxlength: '255', placeholder: 'node.example.org:18089' });
    mount(page({ title: 'Monero node', body: [body] }));
    const load = async () => { try { N.list = await backend.call('GET', '/api/wallet/nodes'); } catch (e) { N.say = e; } await refresh(); };
    const run = async (b, what) => { N.busy = what; N.say = null; await refresh(); try { N.list = await backend.call('POST', '/api/wallet/node', b); S.walletAt = 0; } catch (e) { N.say = e; } N.busy = null; await refresh(); };
    const add = () => { const v = addIn.value.trim(); if (!v) return; sheetDone = true; void closeSheet().then(() => run({ add: v }, v)); };
    let sheetDone = false;
    const addSheet = () => { sheetDone = false; addIn.value = ''; sheet({ title: 'Add a node', lead: 'host:port of a Monero node, yours or one you trust. It is tested before it is added.', body: [h('div', { class: 'pad stack' }, field('Node', addIn), btn('Add', add, { kind: 'pri' }))] }); addIn.focus?.(); };
    void load();
    return () => {
      if (!walletOn()) { put(body, empty('Wallet is off', 'Turn it on in Settings → Wallet.')); return; }
      const rows = (N.list?.nodes ?? []).map((n) => longPress(row({ compact: true, start: h('span', { class: `dot${n.ok ? (n.behind > 2 ? ' warn' : '') : ' off'}` }), title: n.url, attrs: { 'data-node': n.url },
        sub: [n.ok ? (n.behind > 2 ? `${n.behind} blocks behind` : 'up to date') : 'doesn\'t answer', n.in_use ? 'in use' : null, n.from === 'keeper' ? 'the keeper\'s' : null, N.busy === n.url ? 'checking…' : null].filter(Boolean).join(' · '),
        end: n.in_use ? icon('check') ?? '✓' : null, onclick: () => (n.in_use ? undefined : run({ use: n.url }, n.url)) }),
        () => { if (n.from === 'added') void ask({ title: `Remove ${n.url}?`, text: 'It leaves this list. Your wallet keeps the node it uses until you choose another.', yes: 'Remove', no: 'Keep' }).then((y) => y && run({ remove: n.url }, n.url)); }));
      put(body, h('div', { class: 'pad' }, h('p', { class: 'lead' }, 'The server your wallet reads the Monero chain from. Tap to use, hold to remove one you added.')), inlineError(N.say),
        N.list ? (rows.length ? h('div', { class: 'list' }, rows) : h('p', { class: 'help pad' }, 'No node yet: add one.')) : h('p', { class: 'help pad', role: 'status' }, 'Asking the nodes…'),
        h('div', { class: 'pad' }, btn('Add a node', addSheet, { ic: 'plus' })));
    };
  });

  // Settings → Wallet → Wallet service: the wallet program (monero-wallet-rpc) on this computer and your account in it:
  // a keeper's (never an agent's account), or another one on this computer.
  screen('set-service', {}, () => {
    const V = { s: null, say: null, busy: false };
    const body = h('div'), url = input({ autocapitalize: 'none', placeholder: 'http://127.0.0.1:18083/json_rpc' }), login = input({ autocapitalize: 'none', type: 'password', placeholder: 'user:password' }), acct = input({ inputmode: 'numeric', value: '0' });
    mount(page({ title: 'Wallet service', body: [body] }));
    const load = async () => { try { V.s = await backend.call('GET', '/api/wallet/services'); } catch (e) { V.say = e; } await refresh(); };
    const run = async (b) => { V.busy = true; V.say = null; await refresh(); try { V.s = await backend.call('POST', '/api/wallet/service', b); S.wallet = null; S.walletAt = 0; toast('Saved'); } catch (e) { V.say = e; } V.busy = false; await refresh(); };
    void load();
    return () => {
      if (!walletOn()) { put(body, empty('Wallet is off', 'Turn it on in Settings → Wallet.')); return; }
      if (!V.s) { put(body, inlineError(V.say), V.say ? null : h('p', { class: 'help pad', role: 'status' }, 'Asking the wallets on this computer…')); return; }
      const c = V.s.current;
      const keeperBlock = (k) => [sec(V.s.keepers.length > 1 ? `The keeper's wallet (${k.keeper})` : 'The keeper\'s wallet'),
        k.error ? h('div', { class: 'card warn' }, h('p', null, 'It doesn\'t answer.'), h('p', { class: 'help' }, k.error)) : null,
        k.accounts.length ? h('div', { class: 'list', role: 'radiogroup', 'aria-label': `Accounts of ${k.keeper}` }, k.accounts.map((a) => {
          const r = h('input', { type: 'radio', name: `acct-${k.keeper}`, value: String(a.index), checked: c?.keeper === k.keeper && c.account === a.index, disabled: a.held !== null, 'aria-label': `Account ${a.index}` });
          r.addEventListener('change', () => { if (r.checked) void run({ keeper: k.keeper, account: a.index }); });
          return h('label', { class: 'row compact' }, r, h('span', { class: 'mid' }, h('b', null, `Account ${a.index}${a.label ? ` · ${a.label}` : ''}`), h('small', null, a.held ? `${a.held}'s allowance: not yours` : `${xmr4(a.balance)} XMR`)));
        })) : null,
        k.error ? null : h('div', { class: 'pad' }, btn('Make an account for you', () => run({ keeper: k.keeper, new_account: true }), { ic: 'plus', disabled: V.busy }),
          h('p', { class: 'help' }, 'A new account in the keeper\'s wallet: the same 25 words restore it with every agent\'s.'))];
      put(body, h('div', { class: 'pad' }, h('p', { class: 'lead' }, 'The Monero wallet program on this computer your Wallet uses, and your account in it. An agent\'s account is its allowance, never yours.')),
        inlineError(V.say), V.s.unreadable ? h('div', { class: 'card warn' }, h('p', null, 'This page can\'t read the keeper here.'), h('p', { class: 'help' }, V.s.unreadable)) : null,
        V.s.keepers.map(keeperBlock),
        sec('Another wallet program'), h('div', { class: 'pad stack' }, h('p', { class: 'help' }, V.s.rpc ? `In use: ${V.s.rpc.url}` : 'A monero-wallet-rpc you run on this computer, with your own wallet.'),
          field('Its address', url, 'On this computer only: 127.0.0.1.'), field('Its login (optional)', login, 'As --rpc-login: user:password.'), field('Your account', acct),
          btn(V.busy ? 'Checking…' : 'Use it', () => run({ url: url.value.trim(), login: login.value, account: Number(acct.value) || 0 }), { disabled: V.busy })),
        c?.chosen ? h('div', { class: 'pad' }, btn('Back to the default', () => run({ default: true }), { kind: 'ghost' })) : null);
    };
  });

  // Settings → Wallet → Approvers (pass 3's list, here for every keeper): who may approve an agent's payment above its limit.
  screen('set-approvers', {}, () => {
    S.keeperAt = 0;
    const body = h('div');
    mount(page({ title: 'Approvers', body: [body] }));
    const save = (k, list_) => act(() => backend.call('POST', '/api/keeper/approvers', { keeper: k.id, approvers: list_ }), () => { S.keeperAt = 0; toast('Saved'); });
    const addSheet = (k) => {
      const people = allContacts().filter((c) => !c.local && !k.approvers.includes(c.current_did ?? c.did));
      sheet({ title: 'Add an approver', lead: 'They answer your agents\' payments above a limit, with their own key.', body: [list(people.map((c) => row({ compact: true, start: avatar(kindOf(c), c.name), title: c.name,
        onclick: () => { void closeSheet().then(() => save(k, [...k.approvers, c.current_did ?? c.did])); } }))) ?? h('p', { class: 'help pad' }, 'No contacts yet: pair with them first.')] });
    };
    return async () => {
      await keeperNow();
      const ks = keeperHere()?.keepers ?? [];
      if (!ks.length) { put(body, h('div', { class: 'pad' }, keeperAway(S.keeper) ?? empty('No keeper here', 'Approvers belong to a keeper on this computer.'))); return; }
      put(body, noteCard(), ks.map((k) => [ks.length > 1 ? sec(`Keeper ${k.id}`) : null, h('div', { class: 'list' },
        toggle('I approve its agents\' payments', 'You answer under Agents → Needs you.', k.me_approver, (on) => act(() => backend.call('POST', '/api/keeper/approvers', { keeper: k.id, me: on }), () => { S.keeperAt = 0; }))),
        list(k.approvers.filter((d) => d !== S.snap?.me?.did).map((d) => row({ compact: true, title: contactBy(d)?.name ?? allContacts().find((c) => c.current_did === d)?.name ?? `${d.slice(0, 20)}…`, sub: 'Another approver',
          end: tbtn('Remove', () => save(k, k.approvers.filter((x) => x !== d))) }))),
        h('div', { class: 'pad' }, btn('Add from contacts', () => addSheet(k), { ic: 'plus' }))]),
        h('p', { class: 'help pad' }, 'Kept by the keeper on this computer, which uses a change from its next payment.'));
    };
  });

  // The relay (Monerujo's node picker): the relays known, the one in use marked; tap to use, hold to edit; a typed one
  // is tested (POST /api/relays/test) before it is taken.
  function longPress(el, fn) {
    let t = 0, fired = false;
    const stop = () => { clearTimeout(t); t = 0; };
    el.addEventListener('pointerdown', () => { fired = false; t = setTimeout(() => { fired = true; fn(); }, 600); });
    for (const ev of ['pointerup', 'pointerleave', 'pointercancel']) el.addEventListener(ev, stop);
    el.addEventListener('contextmenu', (ev) => { ev.preventDefault(); stop(); if (!fired) { fired = true; fn(); } });
    // The click after a long press is not a tap.
    el.addEventListener('click', (ev) => { if (fired) { ev.stopImmediatePropagation(); fired = false; } }, true);
    return el;
  }
  screen('set-relay', {}, () => {
    const R = { s: null, list: null, tests: new Map(), say: null, adding: false };
    const body = h('div'), custom = input({ autocapitalize: 'none', maxlength: '255', placeholder: 'relay.example.org' }), addBox = h('div', { class: 'pad stack' });
    const customField = field('Another relay', custom, 'A host name, or its wss:// or mqtts:// address.'), tested = h('p', { class: 'help' });
    mount(page({ title: 'Relay', body: [body, addBox] }));
    // A relay is named by its host[:port], so a URL pasted is read as that name: mqtts://host[:port], or wss:// and
    // https:// on 443 (the carrier picks the transport). A WebSocket off 443 has no relay name: kept as typed, and refused.
    const norm = () => {
      const v = custom.value.trim().toLowerCase(), m = /^(mqtts|wss|https):\/\/([a-z0-9.-]+)(?::(\d{1,5}))?(?:[/?#].*)?$/.exec(v);
      if (!m) return v;
      const [, scheme, hostName, port] = m;
      if (scheme === 'mqtts') return port && port !== '8883' ? `${hostName}:${port}` : hostName;
      return port && port !== '443' ? v : hostName;
    };
    const test = async (host) => {
      if (!host) return { ok: false };
      R.tests.set(host, { busy: true }); await refresh();
      let r;
      try { r = await backend.call('POST', '/api/relays/test', { relay: host }); } catch (e) { r = { ok: false, detail: e.message }; }
      R.tests.set(host, r); await refresh();
      return r;
    };
    const use = async (host) => {
      R.say = null;
      try { R.s = await backend.call('POST', '/api/settings', { relay: host }); toast('Saved. New codes use it; your own connection moves at the next start.'); } catch (e) { R.say = e; }
      await refresh();
    };
    const said = (host) => {
      const t = R.tests.get(host);
      if (!t) return null;
      if (t.busy) return 'testing…';
      return t.ok ? h('span', { class: 'ok' }, `answers · ${t.ms} ms${t.retention_days ? ` · keeps messages ${t.retention_days} days` : ''}`) : h('span', { class: 'warn' }, `No answer: ${t.detail ?? ''}`);
    };
    backend.call('GET', '/api/settings').then((x) => { R.s = x; return refresh(); }, (e) => { R.say = e; return refresh(); });
    const erase = () => sheet({ title: 'Delete my data at the relay', body: [h('div', { class: 'pad stack' }, h('p', { class: 'mono' }, S.me?.erase ?? ''), btn('Done', () => closeSheet(), { kind: 'pri' }))] });
    return () => {
      const s = R.s, me = S.snap?.me;
      if (!s) { put(body, inlineError(R.say) ?? h('p', { class: 'pad help' }, 'Loading…')); return; }
      const current = s.fixed ?? s.relay, seen = new Set(), rows = [];
      const add = (host, sub) => {
        if (!host || seen.has(host)) return;
        seen.add(host);
        const inUse = host === current, t = said(host);
        rows.push(longPress(row({ compact: true, start: h('span', { class: `dot${inUse ? '' : ' off'}` }), title: host, attrs: { 'aria-pressed': String(inUse), 'data-relay': host },
          sub: [inUse ? (me?.online ? 'connected · in use' : 'in use') : sub, t ? [' · ', t] : null], end: inUse ? icon('check') : null,
          onclick: s.fixed ? undefined : () => (inUse ? undefined : use(host)) }), () => { custom.value = host; R.adding = true; void refresh(); custom.focus?.(); }));
      };
      add(current, 'in use'); add(s.default, 'the default');
      for (const x of R.list ?? []) add(x.host, [x.tier, x.note].filter(Boolean).join(' · '));
      put(body, h('div', { class: 'pad' }, h('p', { class: 'lead' }, `The server that passes on your messages. It can't read them. It keeps undelivered ones for ${me?.retention_days ?? S.me?.retention_days ?? 14} days.`)),
        s.fixed ? h('div', { class: 'card' }, h('p', null, `SIGELO_RELAY on this computer sets ${s.fixed}: it wins over the choice here.`)) : null,
        h('div', { class: 'list' }, rows), inlineError(R.say),
        s.fixed ? null : h('div', { class: 'pad stack' },
          R.list === null ? btn('Show the public list', async () => { try { R.list = (await backend.call('GET', '/api/relays')).relays; } catch (e) { R.list = []; R.say = e; } await refresh(); }) : null,
          R.adding ? null : btn('Add a relay', () => { R.adding = true; void refresh(); custom.focus?.(); }, { ic: 'plus' }),
          btn('Delete my data at the relay', erase, { kind: 'ghost' }),
          h('p', { class: 'help' }, 'Tap a relay to use it; hold one to edit it. A 12-character code names its own relay, whatever this says.')));
      put(tested, said(norm()));
      put(addBox, R.adding && !s.fixed ? [customField, tested,
        h('div', { class: 'btns' }, btn('Test', () => test(norm())), btn('OK', async () => { const host = norm(), t = R.tests.get(host); if ((t?.ok ? t : await test(host)).ok) { custom.value = ''; R.adding = false; await use(host); } }, { kind: 'pri' }))] : null);
    };
  });

  screen('set-chats', {}, () => {
    const body = h('div');
    mount(page({ title: 'Chats and history', body: [body] }));
    const clear = async () => {
      if (await ask({ title: 'Clear all chat history?', text: `Every message kept on this ${LOCAL || SHELL ? 'phone' : 'computer'} is deleted. Your contacts stay.`, yes: 'Clear history', no: 'Keep history' })) {
        void act(() => backend.call('POST', '/api/history/clear'), () => toast('History cleared.'));
      }
    };
    // The chat defaults (GET/POST /api/settings): new people's tier and presence at their pairing, seen receipts, notifications.
    const C = { s: null, say: null };
    const load = () => backend.call('GET', '/api/settings').then((x) => { C.s = x; }, (e) => { C.say = e; });
    const set = async (patch) => {
      C.say = null;
      try { C.s = await backend.call('POST', '/api/settings', patch); if ('notify' in patch) { N.global = C.s.notify !== false; N.globalAt = Date.now(); if (N.global) void notifyAsk(true); } } catch (e) { C.say = e; }
      await refresh();
    };
    void load().then(refresh);
    return () => {
      const st = C.s;
      put(body, noteCard(),
        st ? [sec('New people\'s messages'), radios('New people\'s messages', TIERS, st.new_tier ?? 'friend', (v) => set({ new_tier: v })),
          h('div', { class: 'list' }, toggle('Show when I\'m online', 'to new people', st.new_presence === true, (v) => set({ new_presence: v }))),
          h('div', { class: 'list' }, toggle('Send seen receipts', st.seen_receipts !== false ? 'They see ✓✓ once you have read their messages' : 'Off: they see one tick, never when you read', st.seen_receipts !== false, (v) => set({ seen_receipts: v })),
            // System notifications (NOTIFICATIONS below): the sender's name only; off, none at all.
            toggle('Notifications', 'The sender\'s name only, never the text', st.notify !== false, (v) => set({ notify: v })))]
          : C.say ? null : h('p', { class: 'pad help' }, 'Loading…'),
        inlineError(C.say),
        h('div', { class: 'pad' }, btn('Clear all chat history…', clear, { kind: 'danger' })));
    };
  });

  screen('set-appearance', {}, () => {
    const body = h('div');
    mount(page({ title: 'Appearance', body: [body] }));
    const set = (k, v) => { prefs.set(k, v); applyLook(); void refresh(); };
    return () => {
      const L = look();
      put(body, h('div', { class: 'pad' }, h('div', { class: 'preview', 'aria-hidden': 'true' }, avatar('agent', 'scout'), h('span', { class: 'mid' }, h('b', null, 'scout'), h('small', null, 'Found 3 flights')), h('span', { class: 'count' }, '2'), h('span', { class: 'tb' }, 'Open'))),
        sec('Theme'), radios('Theme', [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']], L.theme, (v) => set('theme', v === 'system' ? null : v)),
        sec('Colour'), radios('Colour', [['teal', 'Teal'], ['seal', 'Seal (the sigelo.io colours)']], L.colour, (v) => set('colour', v === 'seal' ? null : v)));
    };
  });

  screen('about', {}, () => {
    const body = h('div');
    mount(page({ title: 'About', body: [body] }));
    void loadMe().then(versionNow).then(refresh);
    return () => {
      const m = S.me, me = S.snap?.me, off = me?.clock_offset;
      const kv = (k, v) => (v === null || v === undefined || v === '' ? null : h('div', { class: 'kv' }, h('span', null, k), h('span', null, v)));
      put(body, h('div', { class: 'pad' }, h('p', { class: 'wordmark' }, 'sigelo'), h('p', { class: 'lead' }, `${versionLine()} · experimental`)),
        h('details', { class: 'more pad', open: true }, h('summary', null, 'Technical details'), h('div', { class: 'list' },
          m ? h('div', { class: 'kv' }, h('span', null, 'Identity'), h('span', { class: 'mono' }, m.did)) : null,
          m ? row({ compact: true, title: 'Copy the identity', onclick: () => copy(m.did) }) : null,
          kv('Held as', holdsLine()),
          kv('Key', !m ? null : m.key === 'browser' ? 'sealed in this app\'s storage' : m.key === 'keychain' ? 'sealed in this machine\'s keyring' : 'in the identity file, not sealed'),
          kv('Clock', off === null || off === undefined ? 'not checked' : Math.abs(off) > 60 ? `${Math.abs(off)} s ${off < 0 ? 'ahead' : 'behind'}` : 'right'),
          kv('Relay keeps messages', m ? `${m.retention_days} days` : null),
          m?.restored ? kv(m.restored.created ? 'Created' : 'Restored from 25 words', m.restored.on) : null)),
        sec('Licence and links'),
        h('div', { class: 'list' }, kv('Licence', 'MIT: free to use, change and share'),
          h('a', { class: 'row compact', href: 'https://sigelo.io/', target: '_blank', rel: 'noopener noreferrer' }, h('span', { class: 'mid' }, h('b', null, 'sigelo.io'), h('small', null, 'How it works'))),
          h('a', { class: 'row compact', href: 'https://github.com/csigelo/sigelo', target: '_blank', rel: 'noopener noreferrer' }, h('span', { class: 'mid' }, h('b', null, 'Source code'), h('small', null, 'github.com/csigelo/sigelo')))));
    };
  });

  // Profiles (design/profiles.md §3): several identities in one app, the active one open; the chip's sheet switches.
  async function openProfiles() {
    if (!PROFILES) {
      sheet({ title: 'Profiles', lead: 'This page is one identity. Profiles are in the phone app.', body: [list(row({ start: h('span', { class: 'dot' }), title: profileName(), sub: wordsLine(myWords()), end: icon('check') }))] });
      return;
    }
    await Promise.all([loadProfiles(), walletNow()]);
    const P = S.profiles, say = h('div', { class: 'pad' });
    // The balance of the profile in use (Wallet on: its sync, greyed out of sync); another profile's wallet is its own page's, said on or off only.
    const walletEnd = (p) => {
      if (p.id !== P.active) return prefs.get(`wallet:${p.did}`) === 'on' ? 'Wallet on' : 'Wallet off';
      if (!walletOn()) return 'Wallet off';
      const b = walletReady()?.balance;
      return b ? h('span', { class: b.current ? null : 'stale', 'data-bal': '' }, `${xmr4(b.total)} XMR`) : 'Wallet on';
    };
    const run = async (fn) => { put(say); try { await fn(); } catch (e) { put(say, inlineError(e)); } };
    const full = P.profiles.length >= (P.limit ?? 8);
    sheet({ title: 'Profiles', lead: 'Each one is a separate identity with its own chats, agents and wallet.', body: [inlineError(P.error),
      list(P.profiles.map((p) => row({ start: h('span', { class: `dot${p.id === P.active ? '' : ' off'}` }), title: p.name, attrs: { 'data-profile': p.id },
        sub: [p.words ? wordsLine(p.words) : p.kind ? null : 'Not set up yet', p.kind === 'remote' ? 'A computer\'s page' : null].filter(Boolean).join(' · '),
        end: [p.kind === 'words' ? walletEnd(p) : null, p.id === P.active ? h('span', { class: 'ok', 'aria-label': 'In use' }, icon('check') ?? '✓') : null],
        onclick: p.id === P.active ? () => closeSheet() : () => run(() => PROFILES.use(p.id)) }))),
      h('div', { class: 'pad btns' }, btn('Add', () => (full ? run(() => PROFILES.add('create')) : addProfile()), { ic: 'plus' }), btn('Manage', () => go('profiles-manage'))),
      full ? h('p', { class: 'help pad' }, `At most ${P.limit} profiles: remove one to add another.`) : null, say] });
  }
  /** Add a profile (the mock's profile-add): four ways in; each opens the new profile's first run at that step (the lock once). */
  function addProfile() {
    const say = h('div', { class: 'pad' });
    const way = (path, title) => row({ compact: true, title, chev: true, attrs: { 'data-add': path }, onclick: async () => { put(say); try { await PROFILES.add(path); } catch (e) { put(say, inlineError(e)); } } });
    sheet({ title: 'Add a profile', lead: `A second identity, for a shop or a project. Up to ${S.profiles?.limit ?? 8}.`,
      body: [list(way('create', 'Create a new identity'), way('join', 'Join from an invite code'), way('restore', 'Restore from 25 words'), way('computer', 'Use a computer\'s identity')), say] });
  }
  screen('profiles-manage', {}, () => {
    const body = h('div'), names = new Map(), M = { say: null }, renames = h('div', { class: 'card stack' });
    mount(page({ title: 'Manage profiles', body: [body] }));
    void loadProfiles().then(refresh);
    return () => {
      const P = S.profiles;
      if (!P) { put(body, h('p', { class: 'pad help' }, 'Loading…')); return; }
      const fieldOf = (p) => {
        let f = names.get(p.id);
        if (!f) {
          const box = input({ value: p.name, maxlength: '24' });
          box.addEventListener('change', async () => { M.say = null; try { await PROFILES.rename(p.id, box.value); await loadProfiles(); toast('Renamed.'); } catch (e) { M.say = e; } await refresh(); });
          f = field(p.name, box); names.set(p.id, f);
        }
        return f;
      };
      put(renames, P.profiles.map(fieldOf));
      put(body, inlineError(P.error), inlineError(M.say), P.profiles.length >= (P.limit ?? 8) ? h('p', { class: 'help pad' }, `At most ${P.limit ?? 8} profiles: remove one to add another.`) : null, sec('Rename'), renames,
        sec('Remove'), h('div', { class: 'card' }, h('p', null, 'Removing a profile deletes its identity, chats and wallet from this phone. Only its 25 words bring it back.'),
          h('div', { class: 'stack' }, P.profiles.map((p) => btn(`Remove ${p.name}…`, () => removeProfile(p), { kind: 'danger' })))));
    };
  });
  /** Remove a profile: a sheet naming it; a words profile needs "I have the 25 words" ticked, and its words password when kept. */
  async function removeProfile(p) {
    const tick = h('input', { type: 'checkbox', 'aria-label': 'I have the 25 words' }), pw = pwField('Its words password'), say = h('div');
    let kept = false;
    try { kept = p.kind === 'words' && (await WORDS?.status(p.id))?.kept === true; } catch {}
    const go_ = async (b) => {
      b.disabled = true; put(say);
      try {
        const auth = kept ? await WORDS.auth(p.id, pw.value) : {};
        const r = await PROFILES.remove(p.id, { name: p.name, words: tick.checked, ...auth });
        await closeSheet();
        if (!r?.reload) { await loadProfiles(); await refresh(); toast(`${p.name} removed.`); }
      } catch (e) { put(say, inlineError(e)); b.disabled = false; }
    };
    const yes = btn(`Remove ${p.name}`, () => go_(yes), { kind: 'danger' });
    sheet({ title: `Remove ${p.name}?`, lead: p.kind === 'words' ? 'Its identity, chats and wallet leave this phone. Only its 25 words bring it back.'
      : p.kind === 'remote' ? `The computers keep the pairing until you revoke it there: ${REVOKE_CONTROL}.` : 'Not set up yet: nothing in it.',
    body: [h('div', { class: 'pad stack' }, p.kind === 'words' ? h('label', { class: 'row compact' }, tick, h('span', { class: 'mid' }, h('b', null, 'I have the 25 words'))) : null,
      kept ? field('Its words password', pw) : null, say, yes, btn(`Keep ${p.name}`, () => closeSheet()))] });
  }
  const pwField = (label) => h('input', { type: 'password', autocomplete: label === 'New password' || label === 'Repeat it' ? 'new-password' : 'current-password', autocapitalize: 'none', spellcheck: 'false', 'aria-label': label });

  // ---- SECURITY (design/apps-seed.md §8): Settings → Backup and recovery, where this phone keeps its own words behind
  // the words password; Settings → Lock. Show my 25 words: the device lock, then the password, then the words as at
  // their creation (FLAG_SECURE on Android, nothing to copy, Done hides them); change or remove the password (the old
  // one asked). WORDS: the WebView app's or a tab's sigeloLocal.words (apps/web/words.mjs), or the GTK phone app's
  // bridge (the words in its keyring, the KDF here: /words-lock.mjs). A wrong password: said after a delay that doubles.
  const wordsLib = lazy('/words-lock.mjs');
  /** The GTK phone app's words over its bridge: the encrypted words fetched, opened here; a guarded op carries the proof. */
  function shellWords(wk) {
    const ask_ = shellAsk(wk);
    const lib = async () => { const L = await wordsLib(); if (!L) throw new Error('The words check is not installed here (words-lock.mjs).'); return L; };
    const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)), b64 = (b) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(''));
    const opened = async (id, password) => { const L = await lib(), r = await ask_('words-get', id ? { id } : {}); return L.gate.run(() => L.openWords(unb64(r.blob), password)); };
    return {
      async status(id) { const r = await ask_('words-status', id ? { id } : {}); return { here: r.here === true, kept: r.kept === true, iterations: r.iterations }; },
      async reveal(password) { return { words: (await opened(undefined, password)).words }; },
      async change(old, next, repeat) {
        const L = await lib();
        L.checkPassword(next, repeat);
        const o = await opened(undefined, old), n = await L.lockWords(o.words, next);
        await ask_('words-keep', { blob: b64(n.blob), check: n.check, proof: o.check });
        return { kept: true };
      },
      async remove(password) { const o = await opened(undefined, password); await ask_('words-drop', { proof: o.check }); return { kept: false }; },
      async auth(id, password) { return { proof: (await opened(id, password)).check }; },
      /** The words password checked (the stand-in lock where no screen lock exists): resolves when right. */
      async check(password) { await opened(undefined, password); return true; },
    };
  }
  const WORDS = LOCAL?.words ?? (PROFILE_SHELL ? shellWords(PROFILE_SHELL) : null);
  const SEC = { st: null };   // this phone's words: { here, kept } once asked
  const wordsStatus = () => { if (!WORDS) return Promise.resolve(null); return WORDS.status().then((r) => { SEC.st = r; return refresh().then(() => r); }, () => null); };
  /** fn once at a time (V.busy: its button drawn off), the error in V.say (a wrong password: after the gate's delay). */
  const run = (V, fn) => async () => { if (V.busy) return; V.busy = true; V.say = null; await refresh(); try { await fn(); } catch (e) { V.say = e; } finally { V.busy = false; await refresh(); } };
  screen('set-backup', {}, () => {
    const body = h('div');
    mount(page({ title: 'Backup and recovery', body: [body] }));
    void wordsStatus(); void loadMe().then(refresh);
    return () => {
      const st = SEC.st, m = S.me;
      put(body, sec('Your 25 words'),
        st?.kept ? h('div', { class: 'card' }, h('p', null, 'They bring back your identity, agents and money on any phone. Showing them always asks your lock and password.'), h('div', { class: 'btns' }, btn('Show my 25 words', () => go('words-show'))))
          : h('div', { class: 'card' }, h('p', null, 'They bring back your identity, agents and money on any phone.'), h('p', { class: 'help' }, WORDS ? 'This phone does not keep them: they are on your paper only.' : 'This computer does not keep them: they are on your paper.')),
        sec('Recovery key'),
        h('div', { class: 'card' }, m?.recovery === 'set' ? h('p', { class: 'ok' }, h('b', null, '✓ Set, kept offline')) : m ? h('p', { class: 'warn' }, h('b', null, 'None: a stolen key could not be moved.')) : h('p', { class: 'help' }, 'Loading…'),
          h('p', { class: 'help' }, 'If your key is stolen, it moves your identity to a new key and keeps your four words.')),
        st?.kept ? [sec('Words password'), list(row({ compact: true, title: 'Change the password', chev: true, onclick: () => go('words-change') }),
          row({ compact: true, title: 'Stop keeping the words here', chev: true, onclick: () => go('words-remove') }))]
          : st?.here && WORDS?.set ? [sec('Words password'), list(row({ compact: true, title: 'Set a password', sub: 'Keep the words here, to see them again with your lock and this password', subCls: 'wrap', chev: true, onclick: () => go('words-set') }))] : null,
        sec('What they restore'), h('div', { class: 'card' }, h('p', null, RECOVERY)));
    };
  });
  screen('words-show', {}, () => {
    const body = h('div', { class: 'pad stack' }), foot = h('div'), pw = pwField('Words password'), V = { say: null, words: null }, title = h('h1', null, 'Show 25 words');
    const pwBox = field('Words password', pw), lockMark = h('div', { class: 'badge-ic' }, icon('lock'));
    mount(page({ who: title, body: [body], foot: [foot] }));
    // Shown, the top bar's Back becomes Close (the mock's words-show); either hides them.
    const bar = S.backBtn, closeAs = () => { if (!bar) return; bar.setAttribute('aria-label', 'Close'); bar.setAttribute('title', 'Close'); put(bar, icon('x')); };
    const hide = () => { V.words = null; V.shown = null; void LOCAL?.secure?.(false); };
    S.leave = hide;
    const open = run(V, async () => { const r = await WORDS.reveal(pw.value); pw.value = ''; await LOCAL?.secure?.(true); V.words = r.words; });
    return () => {
      if (!V.words) {
        put(body, lockMark, h('p', { class: 'lead center' }, 'Anyone who sees them owns this identity and its money. Check nobody is looking.'), pwBox, inlineError(V.say));
        put(foot, btn('Unlock and show', open, { kind: 'pri', ic: 'finger', disabled: V.busy }));
        return;
      }
      if (V.shown === V.words) return;   // shown: not drawn again under the poll
      V.shown = V.words;
      title.textContent = 'Your 25 words';
      closeAs();
      const words = h('ol', { class: 'seed-list nocopy', 'aria-label': 'Your 25 words, in order', oncopy: (e) => e.preventDefault() }, V.words.map((w) => h('li', null, w)));
      put(body, words, h('p', { class: 'help' }, 'Hidden again when you leave this screen. No copy, no screenshot.'));
      put(foot, btn('Done', () => { hide(); back(); }, { kind: 'pri' }));
    };
  });
  screen('words-change', {}, () => {
    const body = h('div', { class: 'pad stack' }), old = pwField('Current password'), next = pwField('New password'), again = pwField('Repeat it'), V = { say: null };
    const save = run(V, async () => { await WORDS.change(old.value, next.value, again.value); for (const x of [old, next, again]) x.value = ''; await wordsStatus(); toast('Password changed.'); back(); });
    mount(page({ title: 'Change the password', body: [body], foot: [btn('Save', () => save(), { kind: 'pri' })] }));
    const boxes = [field('Current password', old), field('New password', next, 'At least 8 characters.'), field('Repeat it', again)];
    return () => put(body, inlineError(V.say), boxes);
  });
  // Set a password (Backup and recovery, none kept): the 25 words typed once more, checked to be this identity's, kept here
  // encrypted under the password (apps/web/words.mjs set); then showing them asks the lock and the password.
  screen('words-set', {}, () => {
    const body = h('div', { class: 'pad stack' }), words = h('textarea', { rows: 4, autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', 'aria-label': 'Your 25 words' });
    const next = pwField('New password'), again = pwField('Repeat it'), V = { say: null };
    words.addEventListener('copy', (e) => e.preventDefault?.());
    const save = run(V, async () => { await WORDS.set(words.value, next.value, again.value); words.value = ''; next.value = ''; again.value = ''; await wordsStatus(); toast('Password set: your words are kept here.'); back(); });
    S.leave = () => { words.value = ''; void LOCAL?.secure?.(false); };
    void LOCAL?.secure?.(true);
    mount(page({ title: 'Set a password', body: [body], foot: [btn('Save', () => save(), { kind: 'pri' })] }));
    const boxes = [h('p', { class: 'lead' }, 'Type your 25 words once more. They are kept here, encrypted under this password; nobody looking at this phone can read them without it.'),
      field('Your 25 words, in order', words, 'Checked to be this identity\'s before they are kept.'), field('New password', next, 'At least 8 characters.'), field('Repeat it', again)];
    return () => put(body, inlineError(V.say), boxes);
  });
  screen('words-remove', {}, () => {
    const body = h('div', { class: 'pad stack' }), pw = pwField('Password'), V = { say: null };
    const goBtn = btn('Stop keeping them here', () => remove(), { kind: 'danger' });
    const remove = run(V, async () => { await WORDS.remove(pw.value); pw.value = ''; await wordsStatus(); toast('The words kept here are deleted.'); back(); });
    mount(page({ title: 'Stop keeping the words here', body: [body], foot: [goBtn] }));
    const box = field('Your words password', pw);
    return () => put(body, h('p', { class: 'warn' }, 'The words kept on this phone are deleted. Your paper is then the only copy.'), inlineError(V.say), box);
  });
  /** The app's seat taken here (the seat card) when the words password guards it. */
  screen('seat-take', {}, () => {
    const body = h('div', { class: 'pad stack' }), pw = pwField('Password'), V = { say: null };
    const take = run(V, async () => { await backend.call('POST', '/api/seat/take', { confirm: true, password: pw.value }); pw.value = ''; back(); });
    mount(page({ title: 'Make this phone the main one', body: [body], foot: [btn('Make this phone the main one', () => take(), { kind: 'danger' })] }));
    const box = field('Your words password', pw);
    return () => put(body, h('p', { class: 'warn' }, 'Only if that other device is stopped or lost: two devices signing in as you lose each other\'s messages.'), inlineError(V.say), box);
  });
  // ---- The lock (Settings → Lock). The mock's rule: asked when you open the app, switch profile, pay above your limit, or show
  // your 25 words. The Android app: the phone's screen lock (sigeloLocal.lock: on or off, after how many minutes away; the shell
  // asks it at a start and at a return; sigeloLocal.unlock({force}) asks it now). A browser tab or the GTK app has no screen lock:
  // the words password stands in where one is kept (this page locks itself: lockPage), and the screen says so.
  const LOCK = LOCAL?.lock?.kind === 'screen' ? LOCAL.lock : null;
  const AFTER = [[1, '1 minute'], [5, '5 minutes'], [15, '15 minutes'], [60, '1 hour']];
  // Ask again to pay above (atomic units; this device's): every payment, or above one of these. 0.10 XMR when not set.
  const PAY_LIMITS = ['0', '10000000000', '50000000000', '100000000000', '250000000000', '500000000000', '1000000000000'];
  const L = { st: null, away: null, locked: false, say: null };
  /** 'screen' (the phone's lock), 'password' (the words password stands in), or null (nothing to ask with here). */
  const lockKind = () => (LOCK ? 'screen' : WORDS && SEC.st?.kept ? 'password' : null);
  const payLimit = () => { const v = prefs.get('pay-lock'); return v !== null && /^\d{1,20}$/.test(v) ? v : '100000000000'; };
  const pageLock = () => ({ on: prefs.get('page-lock') === 'on', after: Number(prefs.get('page-lock-after')) || 1 });
  const afterText = (m) => AFTER.find(([v]) => v === m)?.[1] ?? `${m} minutes`;
  async function lockState() { if (LOCK) { try { L.st = await LOCK.get(); } catch (e) { L.st = { error: e }; } } return L.st; }
  /** Settings' Lock line. */
  function lockLine() {
    const k = lockKind();
    if (k === 'screen') return !L.st || L.st.error ? 'Fingerprint or PIN' : L.st.on ? `Fingerprint or PIN · after ${afterText(L.st.after)}` : 'Off';
    if (k === 'password') return pageLock().on ? `Words password · after ${afterText(pageLock().after)}` : 'Words password · off';
    return LOCAL || SHELL ? 'Off' : null;
  }
  /** Above the pay limit: true when this payment (atomic) asks the lock. */
  const aboveLimit = (amount) => { try { return lockKind() !== null && BigInt(amount) > BigInt(payLimit()); } catch { return false; } };
  /** The lock asked now: the screen lock (even just after it was confirmed), or the words password; nothing where neither is. */
  async function askLock(title) {
    const k = lockKind();
    if (k === 'screen') return LOCAL.unlock({ force: true });
    if (k === 'password') return askPassword(title);
    return undefined;
  }
  /** The words password, checked here (WORDS.check: the same gate as Show my 25 words, no screen lock): resolves once right. */
  function askPassword(title, { lead } = {}) {
    return new Promise((resolve, reject) => {
      let done = false;
      const pw = pwField('Words password'), say = h('div'), go_ = btn('Unlock', () => check(), { kind: 'pri', ic: 'lock' });
      const check = async () => {
        go_.disabled = true; put(say);
        try { await WORDS.check(pw.value); pw.value = ''; done = true; await closeSheet(); resolve(); } catch (e) { put(say, inlineError(e)); go_.disabled = false; }
      };
      pw.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') void check(); });
      sheet({ title, lead: lead ?? 'This device has no screen lock: your words password stands in.', onClose: () => { if (!done) { done = true; reject(Object.assign(new Error('Not unlocked: nothing was sent.'), { check: 'cancelled' })); } },
        body: [h('div', { class: 'pad stack' }, field('Words password', pw), say, go_)] });
      pw.focus?.();
    });
  }
  // The page's own lock where the words password stands in: at the start, and at a return after the minutes set.
  function lockPage() { if (lockKind() !== 'password' || !pageLock().on || L.locked) return; L.locked = true; void render(); }
  function drawLocked() {
    const pw = pwField('Words password'), say = h('div');
    const open = async () => {
      put(say);
      try { await WORDS.check(pw.value); pw.value = ''; L.locked = false; await render(); } catch (e) { put(say, inlineError(e)); }
    };
    pw.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') void open(); });
    S.view = 'locked'; S.update = () => {};
    mount(h('div', { class: 'screen locked', 'data-screen': 'locked' },
      h('header', { class: 'top plain' }, h('span', { class: 'sp' }), PROFILES ? tbtn('Other profile', openProfiles) : null),
      h('div', { class: 'hero center stack' }, h('div', { class: 'badge-ic' }, icon('lock')), h('h1', { class: 'big' }, 'sigelo is locked'), h('p', { class: 'lead' }, profileName()),
        field('Words password', pw), say),
      h('div', { class: 'foot' }, btn('Unlock', open, { kind: 'pri', ic: 'lock' }))));
    pw.focus?.();
  }
  globalThis.document?.addEventListener?.('visibilitychange', () => {
    if (lockKind() !== 'password' || !pageLock().on) return;
    if (document.hidden) { L.away = Date.now(); return; }
    if (L.away !== null && Date.now() - L.away >= pageLock().after * 60000) lockPage();
    L.away = null;
  });
  screen('set-lock', {}, () => {
    const body = h('div');
    mount(page({ title: 'Lock', body: [body] }));
    const say = (e) => { L.say = e; return refresh(); };
    const after = select('Lock after', AFTER.map(([v, t]) => [String(v), t]), '1');
    const pay = select('Ask again to pay above', PAY_LIMITS.map((a) => [a, a === '0' ? 'Every payment' : `${xmr(a)} XMR`]), payLimit());
    after.addEventListener('change', async () => {
      L.say = null;
      if (lockKind() === 'screen') { try { L.st = await LOCK.set({ after: Number(after.value) }); } catch (e) { await say(e); return; } }
      else prefs.set('page-lock-after', after.value);
      toast('Saved.'); await refresh();
    });
    pay.addEventListener('change', () => { prefs.set('pay-lock', pay.value); toast('Saved.'); void refresh(); });
    const selRow = (label, el) => h('div', { class: 'row' }, h('span', { class: 'mid' }, h('label', { for: el.id || (el.id = `f${++fid}`) }, h('b', null, label))), el);
    void lockState().then(refresh); void wordsStatus();
    const HELP = 'Asked only when you open the app, switch profile, pay above this limit, or show your 25 words (which also asks your words password).';
    return () => {
      const k = lockKind();
      if (!LOCAL && !SHELL && !PROFILE_SHELL) { put(body, h('div', { class: 'pad' }, h('p', { class: 'lead' }, 'This page has no lock of its own: it opens with the link sigelo-agent ui printed, on this computer only.'))); return; }
      if (document.activeElement !== pay) pay.value = payLimit();
      if (k === 'screen') {
        const st = L.st;
        if (st && !st.error && document.activeElement !== after) after.value = String(st.after);
        put(body, inlineError(L.say ?? st?.error), h('div', { class: 'list' },
          toggle('Use fingerprint or PIN', st?.secure === false ? 'This phone has no screen lock set: set one in the phone\'s settings first.' : null, st ? st.on !== false : true,
            async (on) => { L.say = null; try { L.st = await LOCK.set({ on }); } catch (e) { L.say = e; } await refresh(); }),
          st?.on !== false ? selRow('Lock after', after) : null, selRow('Ask again to pay above', pay)),
        h('div', { class: 'pad' }, h('p', { class: 'help' }, HELP)));
        return;
      }
      if (k === 'password') {
        const P = pageLock();
        if (document.activeElement !== after) after.value = String(P.after);
        put(body, h('div', { class: 'list' },
          toggle('Lock with your words password', 'No screen lock here: your words password stands in.', P.on, (on) => { prefs.set('page-lock', on ? 'on' : null); void refresh(); }),
          P.on ? selRow('Lock after', after) : null, selRow('Ask again to pay above', pay)),
        h('div', { class: 'pad' }, h('p', { class: 'help' }, 'Asked only when you open the app, pay above this limit, or show your 25 words (which also asks your words password).')));
        return;
      }
      put(body, h('div', { class: 'pad stack' }, h('p', { class: 'lead' }, 'No screen lock here, and no words password kept on this device.'),
        h('p', { class: 'help' }, 'Set a password in Backup and recovery: the app then locks with it, and asks it to pay above your limit.'),
        SEC.st?.here && WORDS?.set ? btn('Backup and recovery', () => go('set-backup')) : null));
    };
  });
  const WORDS_VIEWS = new Set(['words-show', 'words-change', 'words-set', 'words-remove', 'seat-take']);
  // The screens that show or guard the words ask the screen lock first (the mock's lock rule: the app's opening,
  // a profile switch, a payment above the limit, the 25 words; nothing else).
  for (const v of WORDS_VIEWS) SCREENS.get(v).guard = true;
  // The seat card and Backup read it; the page's own lock (the words password standing in) closes at the start, until it is known.
  if (WORDS && !LOCK && prefs.get('page-lock') === 'on') L.locked = true;
  if (WORDS) Promise.resolve().then(() => wordsStatus()).then(() => { if (L.locked && lockKind() !== 'password') { L.locked = false; void render(); } });

  // ================================================================ NOTIFICATIONS (Decided: the sender's name only, never the text)
  // A new message or a payment request raises a system notification: the Android app's (sigeloLocal.notify, its bridge), the GTK
  // app's (its bridge's notify op); a browser tab and the computer's page raise none. It says who (a contact's name, a group's
  // and its sender's, an agent's) and a fixed line, never the message, an amount or a purpose. Not for: what was there when the
  // page started, a chat or group whose Notifications are off, Quiet contacts, everything when Settings → Chats and history →
  // Notifications is off, the chat on the screen while the page is seen. A tap opens that chat or the request (openTag).
  const NOTIFY = typeof LOCAL?.notify === 'function' ? (o) => LOCAL.notify(o) : PROFILE_SHELL ? (o) => shellAsk(PROFILE_SHELL)('notify', o) : null;
  const N = { seen: null, asked: false, global: null, globalAt: 0, pays: new Set(), keeperAt: 0 };
  const TAG = /^(chat|group|pay):[A-Za-z0-9:._-]{1,200}$/;
  const tagOfChat = (did) => `chat:${did}`, tagOfGroup = (gid) => `group:${gid}`;
  const clip = (t) => [...String(t ?? '')].slice(0, 100).join('');
  /** One notification (name only), or its removal; refusals (no permission, a bad tag) stay quiet. */
  function notifyOut(o) { if (!NOTIFY || !TAG.test(o.tag)) return; try { void Promise.resolve(NOTIFY(o)).catch(() => {}); } catch {} }
  const onScreen = (view, arg) => !globalThis.document?.hidden && S.view === view && top()?.arg === arg && !L.locked;
  /** After each poll: what is new since the last, raised. The first look at the state only learns what is there. */
  async function notifyNew() {
    if (!NOTIFY || !S.snap) return;
    if (Date.now() - N.globalAt > 60000) { N.globalAt = Date.now(); try { N.global = (await backend.call('GET', '/api/settings')).notify !== false; } catch {} }
    const first = N.seen === null, seen = N.seen ?? new Map(), out = [];
    for (const c of allContacts()) {
      const l = c.last, at = l?.dir === 'in' ? l.at ?? 0 : 0, was = seen.get(c.did) ?? 0;
      if (at > was) { seen.set(c.did, at); if (!first && !muted(c) && c.tier !== 'quiet' && !onScreen('chat', c.did)) out.push({ tag: tagOfChat(c.did), title: clip(c.name), text: 'New message' }); }
    }
    for (const g of (S.groups?.groups ?? []).filter(liveGroup)) {
      const l = g.last, at = l && !l.mine ? l.at ?? 0 : 0, was = seen.get(g.gid) ?? 0;
      if (at > was) { seen.set(g.gid, at); if (!first && !muted(g) && !onScreen('group', g.gid)) out.push({ tag: tagOfGroup(g.gid), title: clip(g.name), text: l.name ? clip(`New message from ${l.name}`) : 'New message' }); }
    }
    // Payment requests: the keeper's, where this page reads one (the computer's page, a phone connected to it).
    if (S.keeper?.state !== 'elsewhere' && Date.now() - N.keeperAt > 30000) { N.keeperAt = Date.now(); await keeperNow().catch(() => null); }
    for (const r of keeperHere()?.requests ?? []) {
      const tag = `pay:${r.keeper}:${r.nonce}`;
      if (N.pays.has(tag)) continue;
      N.pays.add(tag);
      const w = S.workers?.workers?.find((x) => x.worker === r.worker);
      if (!first && !onScreen('approve', undefined)) out.push({ tag, title: clip(w?.name ?? r.agent ?? 'Your agent'), text: 'Asks you to approve a payment' });
    }
    N.seen = seen;
    if (N.global === false) return;
    for (const o of out) notifyOut(o);
  }
  /** A notification tapped (the Android app: sigeloLocal.onOpen; the GTK app: globalThis.sigeloOpen): its chat or its request. */
  async function openTag(tag) {
    const m = TAG.exec(String(tag ?? ''));
    if (!m) return;
    const rest = tag.slice(m[1].length + 1);
    if (L.locked) return;
    if (m[1] === 'chat' && contactBy(rest)) { home(); await new Promise((r) => setTimeout(r, 0)); await go('chat', rest); }
    else if (m[1] === 'group') { home(); await new Promise((r) => setTimeout(r, 0)); await go('group', rest); }
    else if (m[1] === 'pay') { const i = rest.lastIndexOf(':'); await go('approve', { keeper: rest.slice(0, i), nonce: rest.slice(i + 1) }); }
  }
  LOCAL?.onOpen?.((tag) => { void openTag(tag); });
  if (PROFILE_SHELL) globalThis.sigeloOpen = (tag) => { void openTag(tag); };
  /** Android 13 and later ask the permission to notify: once, while the app is on the screen, when Notifications are on. */
  async function notifyAsk(force = false) {
    if (typeof LOCAL?.notify !== 'function' || (N.asked && !force) || globalThis.document?.hidden) return;
    N.asked = true;
    if (!force && prefs.get('notify-asked') === '1') return;
    prefs.set('notify-asked', '1');
    try { await LOCAL.notify({ ask: true }); } catch {}
  }

  // ================================================================ POLLING and the start
  let polling = false;
  async function poll() {
    if (polling) return;
    polling = true;
    try { S.snap = await backend.call('GET', `/api/state?since=${S.snap?.seq ?? 0}`); S.fatal = null; } catch (e) { S.fatal = e; }
    if (!S.fatal) await walletMirror();
    // The computer's page only (http): pending relay controls; a page that has none of it (404, 403) stops asking.
    if (backend === http && !S.fatal && S.controls !== false) { try { S.controls = (await backend.call('GET', '/api/controls')).pending; } catch (e) { if (e.status === 404 || e.status === 403) S.controls = false; } }
    polling = false;
    // A refusal with a reason (the four words not confirmed on the computer yet, say) is said as it is, and the screen
    // comes back once it passes; a bare 403 is a page opened without its key. A remote control with no answer from its
    // computer (apps/contact/control.mjs: no lease) says so, and asks nothing more over the relay until it is due.
    const held = (e) => e?.status === 403 || e?.check === 'not_connected';
    if (held(S.fatal)) {
      S.held = true;
      mount(h('div', { class: 'screen' }, h('div', { class: 'hero' }, empty(S.fatal.check === 'not_connected' ? 'Not connected' : 'Can\'t open this page',
        SHELL || LOCAL || S.fatal.check ? plain(S.fatal) : 'This page has no key: open the link sigelo-agent ui printed.'))));
      return;
    }
    if (S.held) { S.held = false; await render(); return; }
    await refresh();
    if (!S.fatal) { try { await notifyNew(); } catch {} if (N.global !== false && N.seen) void notifyAsk(); }
  }
  setInterval(() => { for (const el of document.querySelectorAll('.countdown')) el.textContent = left(Number(el.dataset.exp)); }, 1000);
  // Installable on this machine (manifest.webmanifest, sw.js: the three files, never /api/).
  if (backend === http && 'serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  if (!TOKEN && !SHELL && !LOCAL) { mount(h('div', { class: 'screen' }, h('div', { class: 'hero' }, empty('Can\'t open this page', 'This page has no key: open the link sigelo-agent ui printed.')))); return; }
  H?.replaceState?.(stateOf(0), '');
  // The tests (apps/web/test-web.mjs) reach every screen by name through this hook; a page never has it.
  globalThis.sigeloUiTest?.({ go, back, home, screens: [...SCREENS.keys()],
    sheets: { 'new-chat': openNewChat, profiles: openProfiles, 'profile-add': addProfile, attach, 'pay-off': pay, picture: pictureSheet, rename: renameSheet, confirm: ask } });
  void render();
  void poll();
  setInterval(poll, 2000);
  void loadProfiles().then(refresh);
  void loadMe().then(refresh);
  void versionNow().then((v) => (v ? refresh() : undefined));
  // A profile added by "Join from an invite code": its code, once, into Enter their code (apps/web/boot.mjs joinCode).
  try { const j = LOCAL?.joinCode?.(); if (j) setTimeout(() => void go('enter-code', { code: j }), 0); } catch {}
  // local: what changes the state is pushed; the poll still reads it with the same `since`.
  let pushed = null;
  LOCAL?.onChange?.(() => { if (pushed === null) pushed = setTimeout(() => { pushed = null; void poll(); }, 50); });
})();
