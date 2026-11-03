// SPDX-License-Identifier: MIT
// The page of `sigelo-agent ui` (sigelo-agent-ui.ts; API: UI-API.md). Vanilla JS, no framework.
// Every string from a contact, a relay or a file goes in by textContent, its controls and bidi
// overrides escaped (safeText), never as HTML. The token comes in the fragment and goes back as
// X-Sigelo-Token; no cookie, no storage but this tab's sessionStorage (it survives a reload).
// The seam: every call goes through backend.call(method, path, body) → the UI-API.md answer, or
// throws {message, check, long, status}. `http`: fetch to this server with the token. `shell`: the
// page served by the GTK phone app (apps/gtk, sigelo-app:), which seals each call to a computer's
// `ui --remote` (sigelo-remote/0) and answers {status, body}; the page never sees the control's key.
// `local`: the self-contained app (apps/web): an in-page router over a carrier running in the page
// (globalThis.sigeloLocal, apps/web/app.mjs), the same routes and JSON, its changes pushed (onChange).
// The mode banner says what this page holds: SAFE worker, FULL standby, or remote of a computer.
// The first screen is Agents (the keeper's workers, Monerujo's transaction list): a row per agent, and
// the two verbs below it, Enrol (a one-time code, Receive-like) and Invite (the contact pairing).
'use strict';
(() => {
  const TOKEN = (() => {
    const m = /[#&]t=([0-9a-f]{32})\b/.exec(location.hash);
    if (m) { sessionStorage.setItem('sigelo-t', m[1]); history.replaceState(null, '', location.pathname); return m[1]; }
    return sessionStorage.getItem('sigelo-t');
  })();
  const app = document.getElementById('app');
  const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
  const safeText = (s) => String(s ?? '').replace(UNSAFE, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));

  /** h('tag', {class, onclick, disabled, …}, ...children): strings become escaped text nodes. */
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props ?? {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') el.className = v;
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
  const badge = (text, kind) => h('span', { class: `badge${kind ? ' ' + kind : ''}` }, text);

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
  shell.mode = () => ({ kind: 'remote' });
  const backend = SHELL ? shell : LOCAL ? local : http;

  // ---- state
  const S = { snap: null, view: 'agents', home: 'agents', update: () => {}, contact: null, pair: null, msgsSeq: -1, me: null, agents: null, workers: null, note: null, fatal: null, links: null, introSeen: new Set(),
    groups: null, groupsRev: null, made: null };
  const relayNow = () => Date.now() / 1000 + (S.snap?.me?.clock_offset ?? 0);
  const left = (exp) => {
    const s = Math.max(0, Math.round(exp - relayNow()));
    return s >= 3600 ? `${Math.floor(s / 3600)} h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')} min` : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
  };
  const countdown = (exp) => h('span', { class: 'countdown', 'data-exp': String(exp) }, left(exp));
  const when = (t) => {
    const d = new Date(t * 1000), today = new Date().toDateString() === d.toDateString();
    return today ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };
  // Presence (UI-API.md): a green dot while online; grey with "last seen 5 min ago" once the relay
  // said offline; nothing when not known (not allowed to see it, or this page offline).
  const ago = (t) => {
    const s = Math.max(0, Math.round(relayNow() - t));
    return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`;
  };
  const presenceText = (x) => (x.online === true ? 'online' : x.online === false && x.last_seen ? `last seen ${ago(x.last_seen)}` : '');
  const dot = (x) => (x.online === true || (x.online === false && x.last_seen)
    ? h('span', { class: `dot ${x.online ? 'on' : 'off'}`, role: 'img', 'aria-label': presenceText(x), title: presenceText(x) }) : null);
  const allContacts = () => (S.snap ? [...S.snap.groups.mine, ...S.snap.groups.contacts] : []);
  const contactBy = (did) => allContacts().find((c) => c.did === did) ?? null;

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); const was = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = was; }, 1500); } catch { window.prompt('Copy this:', text); }
  }
  const toast = (t) => { const x = h('div', { class: 'toast', role: 'status' }, t); document.body.append?.(x); setTimeout(() => x.remove?.(), 2500); };
  /** A ready-to-send message: the shell's share sheet (Android), the page's (navigator.share), else the clipboard. */
  async function share(text, btn) {
    for (const via of [LOCAL?.share, navigator.share && ((t) => navigator.share({ text: t }))]) {
      if (!via) continue;
      try { await via(text); return; } catch (e) { if (e?.name === 'AbortError') return; }
    }
    try { await navigator.clipboard.writeText(text); toast('Message copied: paste it into any chat or mail.'); } catch { window.prompt('Copy this message:', text); }
    void btn;
  }
  const hhmm = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const PAIR_HOW = 'https://sigelo.io/pair.html', ENROL_HOW = 'https://sigelo.io/enrol.html';
  const pairMessage = (code, exp) => `Pair with me on sigelo: code ${code}, once, until ${hhmm(exp)}. How: ${PAIR_HOW}`;
  const enrolMessage = (code, exp, command) => `Enrol as my agent on sigelo: code ${code}, once, until ${hhmm(exp)}. On the agent's machine: ${command}  How: ${ENROL_HOW}`;
  // Back: one history entry per screen off the home list, so the system's or browser's Back goes one step.
  const back = () => { if (globalThis.history?.state?.sigeloView) history.back(); else show(S.home); };
  /**
   * A call the human started that may spend a proof-of-work search (a code, an answer, Try now): past the
   * day's three the backend asks (409 pow_confirm, its message the question); yes goes on with
   * pow_confirmed, no throws as before (design/profiles.md §6).
   */
  async function started(method, path, body = {}) {
    try { return await backend.call(method, path, body); } catch (e) {
      if (e?.check !== 'pow_confirm' || !confirm(String(e.message).replace(/^pow_confirm: /, ''))) throw e;
      return backend.call(method, path, { ...body, pow_confirmed: true });
    }
  }
  async function act(fn, after) {
    try { S.note = null; const r = await fn(); if (after) after(r); } catch (e) { S.note = e; }
    await poll();
  }
  const errorCard = (e) => e && h('div', { class: 'card err' }, e.message);
  // The last error, unless the seat banner (in the status line) already says it.
  const noteCard = () => (S.note?.check === 'seat_elsewhere' ? '' : errorCard(S.note) ?? '');

  // ---- the header line: relay, clock, the one-time proof of work (§3)
  function statusLine() {
    const me = S.snap?.me;
    if (!me) return h('div', { class: 'status' }, 'connecting…');
    const off = me.clock_offset, parts = [h('span', null, me.relay), h('span', { class: me.online ? 'good' : 'muted' }, me.online ? 'online' : 'not connected')];
    if (off === null) parts.push(h('span', { class: 'muted' }, 'clock not checked'));
    else if (Math.abs(off) > 60) parts.push(h('span', { class: 'warn' }, `Your clock is ${Math.abs(off)} s ${off < 0 ? 'ahead of' : 'behind'} the relay's: set it right, or codes fail`));
    else parts.push(h('span', { class: 'good' }, 'clock ok'));
    const mode = backend.mode?.(), banner = !mode ? null : mode.kind === 'remote' ? `Remote control of a computer${mode.via === 'relay' ? ', over the relay' : ''}: this phone holds no account key`
      : mode.kind === 'full' ? `This phone holds: FULL, ${me.seat?.here ? 'the seat' : 'standby'}` : `This phone holds: SAFE worker${Number.isInteger(mode.worker) ? ` ${mode.worker}` : ''}`;
    const box = h('div', null, banner ? h('div', { class: 'status mode' }, banner) : null, h('div', { class: 'status' }, parts));
    if (me.pow) box.append(powBar(me.pow));
    // The automatic tries paused for the day (3 searches at a relay): when the next is, and Try now.
    if (me.pow_capped && !me.pow) box.append(h('div', { class: 'card' }, h('p', null, `Setup paused at ${me.pow_capped.relay}: 3 tries today. Next automatic try at ${hhmm(me.pow_capped.next)}.`),
      h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => act(() => started('POST', '/api/pow/try')) }, 'Try now'))));
    // A setup this page started, past the day's three: asked once.
    else if (me.pow_confirm && !me.pow) box.append(h('div', { class: 'card' }, h('p', null, me.pow_confirm.detail),
      h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => act(() => backend.call('POST', '/api/pow/try', { pow_confirmed: true })) }, 'Go on'))));
    const seat = seatBanner();
    if (seat) box.append(seat);
    const files = transferBanner();
    if (files) box.append(files);
    // A state pushed over the relay past 64 KiB comes as a summary (contact/control.mjs capState).
    const cut = S.snap?.truncated;
    if (cut) box.append(h('div', { class: 'card' }, h('p', null, `State truncated: the newest ${cut.kept} contacts of each group and events are shown, of ${Object.values(cut.contacts ?? {}).reduce((a, b) => a + b, 0)} contacts and ${cut.events} events.`),
      h('div', { class: 'bar' }, h('button', { onclick: () => act(async () => { S.snap = await backend.call('GET', '/api/state?since=0&full=1'); }) }, 'Pull the rest'))));
    return box;
  }
  function powBar(p) {
    const bar = h('div');
    bar.style.width = `${Math.min(95, Math.round((100 * p.elapsed_s) / Math.max(30, 2 * p.expected_s)))}%`;
    return h('div', { class: 'card' }, h('div', null, 'One-time setup, up to 2 min'), h('div', { class: 'progress' }, bar), h('div', { class: 'muted' }, `${p.elapsed_s} s`));
  }

  // ---- CONTACTS
  // Tiers (store.mjs): own, their messages shown; friend, "new message" and a count only; quiet,
  // nothing until opened.
  const TIER_SAYS = { own: 'own: messages shown', friend: 'friend: a notice, read when opened', quiet: 'quiet: nothing until opened' };
  const tierChip = (t) => h('span', { class: `badge tier ${t}`, title: TIER_SAYS[t] ?? '' }, t);
  // The unread count a row shows: none for quiet.
  const unreadOf = (c) => (c.tier === 'quiet' ? 0 : c.unread);
  function contactRow(c) {
    const unread = unreadOf(c), mark = c.status === 'pair_again' ? '!' : unread ? '●' : '○';
    const badges = [tierChip(c.tier)];
    if (c.local) badges.push(badge('on this machine'));
    if (c.mine) badges.push(badge(`run by me · ${c.mine.days_left} d left`, c.mine.days_left < 4 ? 'alert' : ''));
    if (c.ours && c.tier !== 'own') badges.push(badge('mine · low trust'));
    for (const t of c.tags) badges.push(badge('#' + t));
    if (c.status === 'pair_again') badges.push(badge('Pair again', 'alert'));
    else if (c.status === 'waiting') badges.push(badge('waiting for their side'));
    else if (c.status === 'not_collected') badges.push(badge('not collected yet', 'alert'));
    // An agent on this machine was paired here, by this machine: no words to compare with anyone.
    if (c.words_checked) badges.push(badge('✓ words', 'ok'));
    else if (c.words && !c.local) badges.push(badge('check words', 'alert'));
    if (c.link) badges.push(badge(`linked: ${c.link.purpose}`));
    const sub = c.tier === 'quiet' ? '' : c.tier === 'friend' ? (unread ? `new message${unread === 1 ? '' : 's'}` : '')
      : c.last ? `${c.last.dir === 'out' ? 'me: ' : ''}${c.last.text}` : 'no messages yet';
    const seen = presenceText(c);
    return h('button', { class: 'row', onclick: () => show('chat', c.did) },
      h('span', { class: 'mark' }, mark),
      h('span', { class: 'main' }, h('div', { class: 'name' }, dot(c), c.name), seen && !c.online ? h('div', { class: 'sub seen' }, seen) : null, sub ? h('div', { class: 'sub' }, sub) : null, h('div', null, badges)),
      unread ? h('span', { class: 'count' }, String(unread)) : null);
  }
  function pendingRows(p) {
    const rows = [];
    for (const i of p.invites) {
      if (i.short && i.short_exp > relayNow()) {
        rows.push(h('button', { class: 'row', onclick: () => show('pair', { mode: 'invite', id: i.id }) }, h('span', { class: 'mark' }, '…'),
          h('span', { class: 'main' }, h('div', { class: 'name' }, `code ${i.short}`), h('div', { class: 'sub' }, countdown(i.short_exp), ' left · for ', i.name))));
      } else {
        rows.push(h('div', { class: 'row' }, h('span', { class: 'mark' }, '…'), h('span', { class: 'main' },
          h('div', { class: 'name' }, i.name), h('div', { class: 'sub' }, i.short ? 'short code expired · ' : '', 'long code open until ', when(i.exp))),
          i.id ? h('button', { onclick: () => show('pair', { mode: 'invite', id: i.id }) }, 'Open') : null));
      }
    }
    for (const a of p.answers) {
      rows.push(h('div', { class: 'row' }, h('span', { class: 'mark' }, '…'), h('span', { class: 'main' }, h('div', { class: 'name' }, `answer to ${a.name}`),
        h('div', { class: 'sub' }, 'Waiting for their side to come online once, until ', when(a.exp)))));
    }
    for (const f of p.failed) {
      rows.push(h('div', { class: 'row' }, h('span', { class: 'mark' }, '!'), h('span', { class: 'main' }, h('div', { class: 'name' }, f.name ?? f.did),
        h('div', { class: 'sub warn' }, f.code === 'code_expired' ? 'Expired before they replied: ask for a new code' : `${f.code}: ${f.detail ?? ''}`))));
    }
    return rows;
  }
  function viewContacts() {
    S.home = 'contacts';
    const top = h('div'), list = h('div');
    put(app,
      h('header', null, h('h1', null, 'Contacts'), h('nav', { class: 'tabs' }, h('button', { onclick: () => show('agents') }, 'Agents'), groupsTab(), h('button', { onclick: () => show('links') }, 'Links'), S.snap?.transfers ? h('button', { onclick: () => show('transfers') }, 'Files') : null, SHELL || LOCAL ? null : h('button', { onclick: () => show('devices') }, 'Devices'), h('button', { onclick: () => show('me') }, 'Me'))),
      top, list,
      h('div', { class: 'foot' }, h('div', { class: 'inner' }, h('button', { class: 'primary', onclick: () => show('add') }, 'Add a contact'))));
    return () => {
      put(top, statusLine(), controlsCard() ?? '', introBanner() ?? '', noteCard());
      if (!S.snap) return;
      const { mine, contacts } = S.snap.groups, pending = pendingRows(S.snap.pending);
      put(list,
        h('h2', null, `Mine (${mine.length})`), mine.length ? mine.map(contactRow) : h('p', { class: 'muted' }, 'Your own agents (yours by key, or tier own): Agents → Enrol my agent.'),
        h('h2', null, `Contacts (${contacts.length})`), contacts.length ? contacts.map(contactRow) : h('p', { class: 'muted' }, 'Nobody yet: Add a contact.'),
        pending.length ? [h('h2', null, 'Pending'), pending] : null);
    };
  }

  // ---- AGENTS (ENROL.md): the keeper's workers, one row each; Enrol and Invite below (UI-API.md /api/agents/*)
  const RING = { enrolled: '●', pending: '◌', revoked: '✕', unplaced: '○' };
  const STATUS_SAYS = { enrolled: 'enrolled', pending: 'pending code', revoked: 'revoked', unplaced: 'not placed' };
  const WHERE = { remote: 'on another machine', here: 'on this machine', device: 'a device' };
  const shortDid = (d) => (typeof d === 'string' && d.length > 24 ? `${d.slice(0, 16)}…${d.slice(-4)}` : d ?? '');
  const day = (t) => new Date(t * 1000).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
  async function loadWorkers() {
    try { S.workers = await backend.call('GET', '/api/agents/workers'); } catch (e) { S.workers = { keeper: false, seat: null, workers: [], error: e }; }
    return S.workers;
  }
  function workerRow(w) {
    return h('button', { class: 'row agent', onclick: () => show('agent', w.worker) },
      h('span', { class: `mark ${w.status}`, 'aria-label': STATUS_SAYS[w.status] ?? w.status }, RING[w.status] ?? '○'),
      h('span', { class: 'main' }, h('div', { class: 'name' }, dot(w), w.name), h('div', { class: 'sub' }, `${shortDid(w.did)} · ${WHERE[w.placed] ?? w.placed}${presenceText(w) ? ` · ${presenceText(w)}` : ''}`),
        h('div', null, badge(STATUS_SAYS[w.status] ?? w.status, w.status === 'revoked' ? 'alert' : w.status === 'enrolled' ? 'ok' : ''), w.rank ? badge(w.rank.toUpperCase(), w.rank === 'full' ? 'alert' : '') : null, w.tier ? tierChip(w.tier) : null)),
      h('span', { class: 'when' }, w.revoked ? day(w.revoked) : w.seen ? when(w.seen) : day(w.at)));
  }
  // Enrol is ready when there is a keeper root and the seat is here (worker indices are allocated there).
  const canEnrol = (W) => W?.keeper === true && W.seat !== 'elsewhere';
  function viewAgents() {
    S.home = 'agents';
    const top = h('div'), list = h('div');
    const enrolBtn = h('button', { class: 'primary', onclick: () => show('enrol') }, 'Enrol my agent');
    put(app,
      h('header', null, h('h1', null, 'Agents'), h('nav', { class: 'tabs' }, h('button', { onclick: () => show('contacts') }, 'Contacts'), groupsTab(), h('button', { onclick: () => show('links') }, 'Links'),
        SHELL || LOCAL ? null : h('button', { onclick: () => show('devices') }, 'Devices'), h('button', { onclick: () => show('me') }, 'Me'))),
      top, list,
      h('div', { class: 'foot' }, h('div', { class: 'inner two' }, enrolBtn, h('button', { onclick: () => show('add') }, 'Add a contact'))));
    return async () => {
      put(top, statusLine(), introBanner() ?? '', noteCard());
      const W = await loadWorkers();
      enrolBtn.disabled = !canEnrol(W);
      const rows = W.workers ?? [];
      put(list,
        W.error ? h('p', { class: 'muted' }, W.error.check === 'scope' ? 'This control may not list the agents.' : W.error.message) : null,
        !W.error && !W.keeper ? h('div', { class: 'card' }, h('p', null, 'No keeper root here: your agents come from your 25 words.'),
          h('p', { class: 'muted' }, LOCAL ? 'Create a new identity or restore from your 25 words to enrol agents from this app.' : 'Make it once on this computer: sigelo-agent keeper --from-words')) : null,
        W.seat === 'elsewhere' ? h('p', { class: 'muted' }, 'The seat is on another device: enrol agents there.') : null,
        h('h2', null, `Agents (${rows.filter((w) => w.status !== 'revoked').length})`),
        rows.length ? rows.map(workerRow) : W.keeper ? h('p', { class: 'muted' }, 'No agents yet: Enrol my agent. It gets a key from your 25 words, so they bring it back.') : null);
    };
  }
  function viewAgent(i) {
    const top = h('div'), body = h('div'), title = h('h1', null, 'Agent');
    const nameIn = h('input', { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', maxlength: '64', 'aria-label': 'Name' });
    let filled = null;
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), title), top, body);
    return async () => {
      put(top, statusLine(), noteCard());
      const w = (await loadWorkers()).workers?.find((x) => x.worker === i);
      if (!w) { title.textContent = 'Agent'; put(body, h('p', { class: 'muted' }, 'No such agent: its code expired or was cancelled.')); return; }
      title.textContent = safeText(w.name);
      if (filled !== w.name) { filled = w.name; nameIn.value = w.name; }
      const cp = h('button', { onclick: () => copy(w.did, cp) }, 'Copy DID');
      const line = (k, v) => (v === null || v === undefined || v === '' ? null : h('div', null, h('span', { class: 'muted' }, `${k}: `), v));
      const revoke = () => {
        const msg = w.status === 'pending' && w.enrolling?.state === 'code' ? `Cancel the code for ${w.name}?`
          : `Revoke ${w.name}? It is forgotten here and can no longer reach you.${w.attested_until ? ` Your attestation of it stays valid until ${day(w.attested_until)}: a world that checks it still sees it as yours until then.` : ''}`;
        if (confirm(msg)) act(() => backend.call('POST', '/api/agents/revoke', { worker: i }), (r) => { if (r.cancelled) show('agents'); });
      };
      put(body,
        h('div', { class: 'card' },
          h('div', null, badge(STATUS_SAYS[w.status] ?? w.status, w.status === 'revoked' ? 'alert' : w.status === 'enrolled' ? 'ok' : ''), w.rank ? badge(w.rank.toUpperCase()) : null, w.tier ? tierChip(w.tier) : null),
          h('div', { class: 'did' }, w.did), h('div', { class: 'bar' }, cp),
          line('Worker', `${w.worker} of your keeper root`), line('Where', WHERE[w.placed] ?? w.placed), w.local ? line('File', `sigelo.${w.local}.local.json`) : null,
          line('Since', day(w.at)), line('Last seen', w.seen ? when(w.seen) : null), line('Attested until', w.attested_until ? day(w.attested_until) : null),
          line('Revoked', w.revoked ? day(w.revoked) : null), w.original !== w.did ? line('First DID', h('span', { class: 'did' }, w.original)) : null),
        w.status === 'pending' && w.enrolling ? h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => show('enrol', { id: w.enrolling.id }) }, 'Show the code')) : null,
        w.contact ? h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => show('chat', w.contact) }, 'Open conversation')) : null,
        w.revoked ? null : [h('label', null, 'Name (a-z, 0-9, _ and -)'), nameIn,
          h('div', { class: 'bar' }, h('button', { onclick: () => act(() => backend.call('POST', '/api/agents/rename', { worker: i, name: nameIn.value.trim() })) }, 'Rename'))],
        w.revoked ? null : w.placed === 'device' ? h('p', { class: 'muted' }, 'A device: revoke it under Devices on the computer that added it.')
          : h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: revoke }, w.enrolling?.state === 'code' ? 'Cancel the code' : 'Revoke')));
    };
  }

  // ---- RELAY PICKER (Monerujo's node picker): the relays known, the one in use marked; tap to use, hold
  // to edit; a typed one is tested (POST /api/relays/test) before OK.
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
  function relayPicker(onUse) {
    const P = { list: null, tests: new Map(), say: '' }, card = h('div', { class: 'card' });
    const custom = h('input', { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', maxlength: '255', placeholder: 'relay.example.org', 'aria-label': 'Relay host' });
    // A relay is named by its host[:port] (codes and logins carry the name), so a URL pasted is read as
    // that name: mqtts://host[:port], or wss:// and https:// on 443. The carrier picks the transport
    // (auto: 8883, and with no answer in 5 s the WebSocket on 443, wss://host/mqtt; a page: 443 only).
    // A WebSocket off 443 has no relay name: kept as typed, and refused.
    const norm = () => {
      const v = custom.value.trim().toLowerCase(), m = /^(mqtts|wss|https):\/\/([a-z0-9.-]+)(?::(\d{1,5}))?(?:[/?#].*)?$/.exec(v);
      if (!m) return v;
      const [, scheme, host, port] = m;
      if (scheme === 'mqtts') return port && port !== '8883' ? `${host}:${port}` : host;
      return port && port !== '443' ? v : host;
    };
    async function test(host) {
      if (!host) return { ok: false };
      P.tests.set(host, { busy: true }); S.update();
      let r;
      try { r = await backend.call('POST', '/api/relays/test', { relay: host }); } catch (e) { r = { ok: false, detail: e.message }; }
      P.tests.set(host, r); S.update();
      return r;
    }
    async function load() {
      P.say = 'Reading the public registry…'; S.update();
      try { P.list = (await backend.call('GET', '/api/relays')).relays; P.say = P.list.length ? '' : 'The registry lists no relays, or could not be read.'; } catch (e) { P.list = []; P.say = e.message; }
      S.update();
    }
    const said = (host) => {
      const t = P.tests.get(host);
      if (!t) return null;
      if (t.busy) return h('div', { class: 'muted' }, 'testing…');
      return t.ok ? h('div', { class: 'good' }, `answers · ${t.ms} ms${t.retention_days ? ` · keeps messages ${t.retention_days} days` : ''}`) : h('div', { class: 'warn' }, `NO ANSWER: ${t.detail ?? ''}`);
    };
    const edit = (host) => { custom.value = host; S.update(); custom.focus?.(); };
    const row = (host, sub, current) => h('div', { class: 'pick' },
      longPress(h('button', { class: `row${current ? ' current' : ''}`, 'aria-pressed': String(current), onclick: () => onUse(host) },
        h('span', { class: 'main' }, h('div', { class: 'name' }, host), sub ? h('div', { class: 'sub' }, sub) : null, said(host))), () => edit(host)),
      h('button', { onclick: () => test(host) }, 'Test'));
    return {
      /** The picker for `current` (in use), `dflt` (relay.sigelo.ai) and the registry's, once read. */
      render(current, dflt) {
        const seen = new Set(), rows = [];
        const add = (host, sub) => { if (!host || seen.has(host)) return; seen.add(host); rows.push(row(host, sub, host === current)); };
        add(current, 'in use'); add(dflt, 'the default');
        for (const x of P.list ?? []) add(x.host, [x.tier, x.note].filter(Boolean).join(' · '));
        // One card, kept: the field in it keeps the focus while the screen is drawn again (put).
        put(card, rows,
          P.list === null ? h('div', { class: 'bar' }, h('button', { onclick: load }, 'Show the public registry')) : null,
          h('label', null, 'Another relay (hold a row to edit it here)'), custom, said(norm()),
          h('div', { class: 'bar' }, h('button', { onclick: () => test(norm()) }, 'Test'),
            h('button', { class: 'primary', onclick: async () => { const host = norm(), t = P.tests.get(host); if ((t?.ok ? t : await test(host)).ok) { custom.value = ''; onUse(host); } } }, 'OK')),
          P.say ? h('p', { class: 'muted' }, P.say) : null,
          h('p', { class: 'muted' }, 'Tap a relay to use it. One you type is tested first: OK only once it answers.'),
          h('p', { class: 'muted' }, 'A host name, or its wss:// or mqtts:// address, read as its host: the app picks the port (8883, else the WebSocket on 443).'));
        return card;
      },
    };
  }

  // ---- ENROL (ENROL.md; Monerujo's Receive): a name and a tier, then one code for the agent's machine, big,
  // ten minutes, once; then enrolled, with no further tap: its DID is checked against the one derived from
  // your words (the four words only to see, or, with the switch on, asked before its key goes).
  const LIVE_ENROL = new Set(['code', 'words', 'sending']);
  const ENROL_TIERS = [['own', 'Own: my agent'], ['friend', 'Friend: low trust, tell me'], ['quiet', 'Quiet: low trust, when I look']];
  function viewEnrol(arg) {
    const E = { id: arg?.id ?? null, first: null, busy: false, error: null, relay: null, picking: false, settings: null };
    const askWords = h('input', { type: 'checkbox', 'aria-label': 'Confirm the four words before its key goes' });
    const top = h('div'), form = h('div'), body = h('div');
    const nameIn = h('input', { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', maxlength: '64', placeholder: 'a name, like vps', 'aria-label': 'Agent name' });
    let tier = 'own';
    const picker = relayPicker((host) => { E.relay = host; E.picking = false; S.update(); });
    backend.call('GET', '/api/settings').then((x) => { E.settings = x; S.update(); }).catch(() => {});
    const make = async () => {
      E.busy = true; E.error = null; S.update();
      try {
        const r = await started('POST', '/api/agents/enrol-code', { name: nameIn.value.trim(), ...(tier !== 'own' && { tier }), ...(E.relay && { relay: E.relay }), ...(askWords.checked && { confirm_words: true }) });
        E.id = r.id; E.first = r;
      } catch (e) { E.error = e; }
      E.busy = false;
      await poll();
    };
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, 'Enrol my agent')), top, form, body);
    return async () => {
      put(top, statusLine(), noteCard());
      if (!E.id) {
        const s = E.settings, inUse = s ? s.fixed ?? E.relay ?? s.relay : null;
        const pick = (t, label) => h('button', { type: 'button', 'aria-pressed': String(t === tier), class: t === tier ? 'on' : '', onclick: () => { tier = t; S.update(); } }, label);
        put(form,
          h('p', null, 'Your own agent, on another machine, under your identity: its key comes from your 25 words.'),
          h('p', { class: 'muted' }, 'Not this? Someone else, a person or their agent: ', h('button', { onclick: () => show('add') }, 'Add a contact')),
          h('label', null, 'Name (a-z, 0-9, _ and -): its contact name, and its file name on that machine'), nameIn,
          h('label', null, 'Its messages'), h('div', { class: 'bar', role: 'group', 'aria-label': 'Tier' }, ENROL_TIERS.map(([t, l]) => pick(t, l))),
          h('p', { class: 'muted' }, tier === 'own' ? 'Own: yours by key, its messages shown in full.' : 'Yours by key but low trust (it reads the web, say): its messages wait as notices, never pushed.'),
          inUse ? [h('label', null, 'Relay'), h('div', { class: 'bar' }, h('span', null, inUse), s.fixed ? h('span', { class: 'muted' }, 'set by SIGELO_RELAY') : h('button', { onclick: () => { E.picking = !E.picking; S.update(); } }, E.picking ? 'Close' : 'Change'))] : null,
          E.picking && s && !s.fixed ? picker.render(inUse, s.default) : null,
          h('details', null, h('summary', null, 'More'), h('label', { class: 'check' }, askWords, ' Confirm the four words before its key goes'),
            h('p', { class: 'muted' }, 'Off: the agent is checked by its key, which comes from your words. The code works once, for 10 minutes.')),
          h('div', { class: 'bar' }, h('button', { class: 'primary', disabled: E.busy, onclick: make }, E.busy ? 'Making the code…' : 'Make the code')),
          E.error ? errorCard(E.error) : null);
        put(body);
        return;
      }
      put(form);
      const W = await loadWorkers(), w = W.workers?.find((x) => x.enrolling?.id === E.id), en = w?.enrolling ?? E.first;
      if (!en) { put(body, h('p', { class: 'muted' }, 'This code is gone.'), h('button', { class: 'primary', onclick: () => show('enrol') }, 'New code')); return; }
      const name = w?.name ?? E.first?.name ?? '', out = [], enrolled = w?.status === 'enrolled' || en.state === 'enrolled';
      const steps = [en.relay ? `✓ code parked at your relay (${en.relay})` : '✓ code made'];
      if (en.state !== 'code' || enrolled) steps.push('✓ the agent entered it and paired');
      if (en.state === 'sending' || enrolled) steps.push('✓ its identity sent, end to end, once');
      if (enrolled) steps.push(`✓ enrolled: worker ${w?.worker ?? E.first?.worker}${en.verified ? ', checked: its key is the one your words make' : ''}`);
      if (en.state === 'code') {
        const cp = h('button', { class: 'primary', onclick: () => copy(en.code, cp) }, 'Copy'), cc = h('button', { onclick: () => copy(en.command, cc) }, 'Copy the command');
        out.push(h('div', { class: 'card' }, h('div', { class: 'muted' }, `One-time code for ${safeText(name)}`), h('div', { class: 'code big' }, en.code),
          h('div', null, countdown(en.exp), ' left · once'),
          h('div', { class: 'bar' }, cp, h('button', { onclick: (ev) => share(enrolMessage(en.code, en.exp, en.command), ev.currentTarget) }, 'Share')),
          h('p', null, 'On the agent\'s machine:'), h('div', { class: 'long' }, en.command), h('div', { class: 'bar' }, cc)));
        steps.push('… waiting for the agent to enter it');
      }
      out.push(h('ul', { class: 'steps' }, steps.map((x) => h('li', null, x))));
      const words = en.words ? h('div', { class: 'words' }, en.words.split(' ').map((x) => h('span', null, x))) : null;
      // The switch on: its key waits for this answer. Off: the words only to see, never a step.
      if (words && en.confirm_words && en.words_ok === null && !enrolled && LIVE_ENROL.has(en.state) && en.state !== 'code') {
        out.push(h('div', { class: 'card' }, h('div', null, 'Its key goes once you confirm. The agent\'s machine shows four words. Compare:'), words, h('div', { class: 'bar' },
          h('button', { class: 'primary', onclick: () => act(() => backend.call('POST', '/api/agents/enrol-words', { id: en.id, match: true })) }, 'They match'),
          h('button', { class: 'danger', onclick: () => { if (confirm(`Drop the code for ${name}? Different words mean someone else may have used it; its key is not sent.`)) act(() => backend.call('POST', '/api/agents/enrol-words', { id: en.id, match: false })); } }, "They don't"))));
      } else if (words && en.state !== 'code') out.push(h('details', null, h('summary', null, 'Show the words'), words, h('p', { class: 'muted' }, 'Optional: the agent\'s machine printed the same four.')));
      if (enrolled) out.push(h('p', { class: 'good' }, `✓ ${safeText(name)} is your agent: worker ${w?.worker ?? E.first?.worker} (${shortDid(w?.did ?? E.first?.did)})`),
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => show('agents') }, 'Done'), w?.contact ? h('button', { onclick: () => show('chat', w.contact) }, 'Open conversation') : null));
      else if (en.state === 'expired') out.push(h('p', { class: 'warn' }, 'The code expired (10 minutes) before the agent used it.'), h('button', { class: 'primary', onclick: () => show('enrol') }, 'New code'));
      else if (en.state === 'failed') out.push(h('p', { class: 'warn' }, en.detail ?? en.check ?? 'Not enrolled.'));
      else if (en.check) out.push(h('p', { class: 'warn' }, en.detail ?? en.check));
      if (en.state === 'code') out.push(h('div', { class: 'bar' }, h('button', { onclick: () => act(() => backend.call('POST', '/api/agents/revoke', { worker: w?.worker ?? E.first?.worker }), back) }, 'Cancel')));
      put(body, ...out);
    };
  }

  // ---- PAIR
  async function invite(o = {}) {
    show('pair', { mode: 'invite', busy: true });
    try { const r = await started('POST', '/api/invite', o); S.pair = { mode: 'invite', id: r.id, inv: r }; } catch (e) { S.pair = { mode: 'invite', error: e }; }
    await poll();
  }
  function wordsBlock(c) {
    if (!c) return h('p', { class: 'muted' }, 'Finishing the pairing…');
    if (c.words_checked) return h('div', { class: 'card' }, h('p', { class: 'good' }, `✓ Words checked with ${safeText(c.name)}`), h('button', { class: 'primary', onclick: () => show('chat', c.did) }, 'Open conversation'));
    if (!c.words) return h('p', { class: 'muted' }, 'No words: this pairing is gone. Pair again.');
    return h('div', { class: 'card' },
      h('div', null, 'Compare aloud:'),
      h('div', { class: 'words' }, c.words.split(' ').map((w) => h('span', null, w))),
      h('div', { class: 'bar' },
        h('button', { class: 'primary', onclick: () => act(() => backend.call('POST', '/api/words', { contact: c.did, match: true })) }, 'They match'),
        h('button', { class: 'danger', onclick: () => { if (confirm(`Forget and block ${safeText(c.name)}? Different words mean someone else may have used the code.`)) act(() => backend.call('POST', '/api/words', { contact: c.did, match: false }), () => show('contacts')); } }, "They don't")),
      h('details', null, h('summary', null, 'more'), h('p', { class: 'did' }, `pair id ${c.pair ?? ''}`), h('p', { class: 'muted' }, 'The same 32 digits on both sides is the strong check.')));
  }
  function viewPair(arg) {
    S.pair = arg?.busy ? { mode: 'invite', busy: true } : { mode: arg?.mode ?? 'enter', id: arg?.id ?? null, inv: null, result: null, error: null };
    const body = h('div');
    let input = null, nameIn = null, tierPick = null, tier = 'friend';
    const enter = async (code) => {
      S.pair.busy = true; S.pair.error = null; S.pair.result = null; S.update();
      try { S.pair.result = await started('POST', '/api/accept', { code, name: nameIn.value.trim(), ...(tier === 'quiet' && { tier }) }); } catch (e) { S.pair.error = e; }
      S.pair.busy = false;
      await poll();
    };
    if (S.pair.mode === 'enter') {
      input = h('input', { autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', placeholder: 'K7F3-Q9ZP, or a long code sgl1…', 'aria-label': 'Their code' });
      nameIn = h('input', { autocomplete: 'off', placeholder: 'optional', 'aria-label': 'Their name' });
      // Friend or quiet; own (my agents) is detected, never asked: friend, the default, is sent as no choice.
      const pick = (t, label) => h('button', { type: 'button', 'aria-pressed': String(t === tier), class: t === tier ? 'on' : '', onclick: () => { tier = t; put(tierPick, picks()); } }, label);
      const picks = () => [pick('friend', 'Friend: tell me'), pick('quiet', 'Quiet: when I look')];
      tierPick = h('div', { class: 'bar', role: 'group', 'aria-label': 'Their messages' }, picks());
    }
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, S.pair.mode === 'enter' ? 'Their code' : 'Your code to send')),
      input ? h('div', null, h('label', null, 'Their code'), input, h('label', null, 'Their name'), nameIn,
        h('label', null, 'Their messages'), tierPick,
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => input.value.trim() && enter(input.value) }, 'Connect'))) : null,
      body);
    return () => {
      const P = S.pair, me = S.snap?.me, out = [];
      if (P.busy) out.push(h('p', null, P.mode === 'enter' ? 'Connecting…' : 'Making a code…'), me?.pow ? powBar(me.pow) : null);
      if (P.mode === 'invite' && !P.busy) {
        if (P.error) {
          out.push(errorCard(P.error), h('p', null, 'Short codes refused, or their agent on another relay? Use the long code.'),
            h('div', { class: 'bar' }, h('button', { onclick: () => invite({ long: true }) }, 'Make a long code'), h('button', { onclick: () => invite() }, 'Try again')));
        }
        const pend = S.snap?.pending.invites.find((x) => x.id === P.id), paired = S.snap?.pending.paired.find((x) => x.id === P.id), inv = P.inv;
        if (inv && paired) {
          const c = contactBy(paired.paired);
          out.push(h('ul', { class: 'steps' }, h('li', null, inv.short ? '✓ code parked at your relay' : '✓ long code made'), h('li', null, '✓ they entered it'), h('li', null, `✓ ${safeText(c?.name ?? paired.name)} answered`)), wordsBlock(c));
        } else if (inv && pend) {
          const live = inv.short && inv.short_exp > relayNow();
          if (inv.short) {
            const cs = h('button', { class: 'primary', onclick: () => copy(inv.short, cs) }, 'Copy');
            out.push(h('div', { class: 'card' }, h('div', { class: 'muted' }, 'Your code'), h('div', { class: 'code big' }, inv.short),
              live ? [h('div', null, countdown(inv.short_exp), ' left · once'),
                h('div', { class: 'bar' }, cs, h('button', { onclick: (ev) => share(pairMessage(inv.short, inv.short_exp), ev.currentTarget) }, 'Share'))]
                : h('div', { class: 'warn' }, 'Code expired. The long code still works until ', when(inv.exp), '.')));
          } else out.push(h('div', { class: 'card' }, h('div', { class: 'muted' }, 'Your long code, once, until ', when(inv.exp)), h('div', { class: 'long' }, inv.code)));
          const cp = h('button', { onclick: () => copy(inv.code, cp) }, 'Copy long code');
          out.push(h('div', { class: 'bar' }, cp, inv.short && !live ? h('button', { class: 'primary', onclick: () => invite() }, 'New code') : null,
            h('button', { onclick: () => act(() => backend.call('POST', '/api/invite/cancel', { id: inv.id }), back) }, 'Cancel')));
          out.push(h('ul', { class: 'steps' }, h('li', null, inv.short ? `✓ code parked at your relay (${safeText(inv.relay)})` : '✓ long code made'), h('li', null, '… waiting for them to enter it')),
            h('p', { class: 'muted' }, 'Their agent must use the same relay for the short code; else send them the long code.'));
        } else if (inv) out.push(h('p', { class: 'muted' }, 'This code is no longer pending.'), h('button', { class: 'primary', onclick: () => invite() }, 'New code'));
        else if (P.id) {
          const p2 = S.snap?.pending.invites.find((x) => x.id === P.id);
          if (p2) { P.inv = { id: p2.id, short: p2.short, short_exp: p2.short_exp, code: p2.code, exp: p2.exp, relay: p2.relay }; setTimeout(() => S.update()); }
        }
      }
      if (P.mode === 'enter' && !P.busy) {
        const e = P.error, came = P.result?.did ? contactBy(P.result.did) : null;
        // Waiting: their side answers later (it was offline); the contact comes in the state, so do the words.
        const r = came && came.status !== 'waiting' && P.result.status !== 'connected' ? { status: 'connected', contact: came } : P.result;
        if (r?.status === 'connected') out.push(h('p', { class: 'good' }, `✓ Paired with ${safeText(r.contact.name)}`), wordsBlock(contactBy(r.contact.did) ?? { ...r.contact, words: r.contact.fingerprint }));
        else if (r?.status === 'waiting') out.push(h('div', { class: 'card' }, 'Your answer is at the relay. Waiting for their side to come online once', r.exp ? [', until ', when(r.exp)] : '', '. You can leave this screen: they show in Contacts, with the four words, once they answer.'));
        else if (r?.status === 'pending') out.push(h('div', { class: 'card' }, 'Your answer has not reached the relay yet: it goes at the next connection.'));
        if (e) {
          const why = {
            park_unknown: `No invite waits under this code at ${me?.relay ?? 'your relay'}. It expired (10 minutes), was used (once only), or is mistyped: ask for a new code. Their agent on another relay? Ask for the long code and paste it above.`,
            code_expired: 'Expired before they replied: ask for a new code.',
            mailbox_taken: 'This code was answered already, by someone else: ask for a new one.',
            short_code: 'Not a short code: check it with whoever gave it to you.',
          }[e.check];
          out.push(h('div', { class: 'card' }, why ? h('p', null, why) : null, h('p', { class: why ? 'muted' : 'err' }, e.message)));
          if (e.long) {
            out.push(h('div', { class: 'card' }, h('p', null, 'The short code is used up. Its long code:'), h('div', { class: 'long' }, e.long),
              h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => { input.value = e.long; enter(e.long); } }, 'Use the long code'))));
          }
        }
      }
      put(body, statusLine(), ...out.filter(Boolean));
    };
  }

  // ---- CONVERSATION
  // A file received (sigelo-file/0): the carrier's line "file <name> (<n> bytes), saved at <path>", shown as
  // the name and size, the place below it small; any other line as it is.
  const kb = (n) => (n < 1024 ? `${n} bytes` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  function fileText(t) {
    const m = /^file (.+) \((\d+) bytes\), saved at (.+)$/s.exec(String(t ?? ''));
    if (!m) return h('div', { class: 'text' }, '📎 ', t);
    return h('div', { class: 'file' }, h('div', { class: 'text' }, '📎 ', h('b', null, m[1]), ` · ${kb(Number(m[2]))}`), h('div', { class: 'path' }, 'Saved on this machine: ', m[3]));
  }
  function viewChat(did) {
    S.contact = did; S.msgsSeq = -1;
    const title = h('h1'), seenLine = h('div', { class: 'sub seen' }), tags = h('div'), alerts = h('div'), list = h('div'), panel = h('div');
    panel.hidden = true;
    const text = h('textarea', { rows: 1, placeholder: 'Message', 'aria-label': 'Message' });
    // The box grows with what is typed, up to a third of the screen (ui.css), and back after Send.
    const fit = () => { if (!text.style) return; text.style.height = 'auto'; if (text.scrollHeight) text.style.height = `${text.scrollHeight + 2}px`; };
    text.addEventListener('input', fit);
    const send = async () => {
      const t = text.value;
      if (!t.trim()) return;
      sendBtn.disabled = true;
      await act(() => backend.call('POST', '/api/send', { to: did, text: t }), () => { text.value = ''; fit(); S.msgsSeq = -1; });
      sendBtn.disabled = false;
    };
    text.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send(); } });
    const sendBtn = h('button', { class: 'primary', onclick: send }, 'Send');
    let first = true;
    const rename = h('input', { autocomplete: 'off', 'aria-label': 'Name' }), tagIn = h('input', { autocomplete: 'off', placeholder: '#work #family', 'aria-label': 'Tags' }), panelCard = h('div', { class: 'card' });
    let panelFor = null;
    put(app,
      h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('div', { class: 'title' }, title, seenLine), h('button', { 'aria-label': 'More', onclick: () => { panel.hidden = !panel.hidden; S.update(); } }, '⋯')),
      tags, panel, alerts, list,
      h('div', { class: 'foot' }, h('div', { class: 'inner' }, text, sendBtn)));
    return async () => {
      const c = contactBy(did);
      if (!c) { title.textContent = 'Gone'; put(alerts, h('p', { class: 'muted' }, 'Not a contact (forgotten).')); return; }
      put(title, dot(c) ?? '', safeText(c.name));
      seenLine.textContent = presenceText(c);
      put(tags, tierChip(c.tier), ...c.tags.map((t) => badge('#' + t)), c.local ? badge('on this machine') : '', c.mine ? badge(`run by me · ${c.mine.days_left} d`) : '', c.words_checked ? badge('✓ words', 'ok') : '', c.link ? badge(`linked: ${c.link.purpose}`) : '');
      if (panelFor !== did + c.name + c.tags.join()) { panelFor = did + c.name + c.tags.join(); rename.value = c.name; tagIn.value = c.tags.map((t) => '#' + t).join(' '); }
      if (!panel.hidden) {
        put(panel, put(panelCard,
          h('label', null, 'Name'), rename, h('div', { class: 'bar' }, h('button', { onclick: () => act(() => backend.call('POST', '/api/rename', { contact: did, name: rename.value })) }, 'Rename')),
          h('label', null, 'Their messages'),
          h('div', { class: 'bar', role: 'group', 'aria-label': 'Tier' }, ['own', 'friend', 'quiet'].map((t) => h('button', { 'aria-pressed': String(c.tier === t), class: c.tier === t ? 'primary' : '',
            title: TIER_SAYS[t], onclick: () => act(() => backend.call('POST', '/api/tier', { contact: did, tier: t })) }, t))),
          h('p', { class: 'muted' }, TIER_SAYS[c.tier] ?? ''),
          h('label', null, 'When I am online'),
          c.presence === 'own' ? h('p', { class: 'muted' }, 'Your own agent: it always sees when you are online.')
            : h('div', { class: 'bar', role: 'group', 'aria-label': 'Presence' }, [[true, 'They see it'], [false, 'Hidden']].map(([allow, label]) => h('button', {
              'aria-pressed': String((c.presence === 'allow') === allow), class: (c.presence === 'allow') === allow ? 'primary' : '',
              onclick: () => act(() => backend.call('POST', '/api/presence', { contact: did, allow })) }, label))),
          h('label', null, 'Tags (up to 20 characters each)'), tagIn,
          h('div', { class: 'bar' }, h('button', { onclick: () => act(() => backend.call('POST', '/api/tag', { contact: did, tags: tagIn.value.split(/[\s,]+/).map((t) => t.replace(/^#/, '')).filter(Boolean) })) }, 'Save tags')),
          h('p', { class: 'did' }, c.did),
          h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: () => { if (confirm(`Forget and block ${safeText(c.name)}? This is permanent: they can never pair with you again.`)) act(() => backend.call('POST', '/api/forget', { contact: did }), () => show('contacts')); } }, 'Forget and block'))));
      }
      const al = [errorCard(S.note)];
      if (c.status === 'pair_again') al.push(h('div', { class: 'card' }, h('p', { class: 'warn' }, c.re_pair === 'own_recovery' ? 'You recovered your identity: pair again.' : 'They recovered their identity: pair again.'), h('button', { class: 'primary', onclick: () => invite({ name: c.name }) }, 'Pair again')));
      else if (c.status === 'waiting') al.push(h('div', { class: 'card' }, 'Waiting for their side: messages go once their keys come.'));
      if (c.not_collected) al.push(h('div', { class: 'card' }, h('p', null, 'Not collected yet: their side has not been online since.'), h('button', { onclick: () => act(() => backend.call('POST', '/api/sync')) }, 'Retry now')));
      if (!c.words_checked && c.words && !c.local) al.push(wordsBlock(c));
      put(alerts, ...al.filter(Boolean));
      if (S.snap.seq !== S.msgsSeq) {
        S.msgsSeq = S.snap.seq;
        const r = await backend.call('GET', `/api/messages?contact=${encodeURIComponent(did)}`).catch(() => null);
        if (!r) return;
        // Opened at the newest message; later, kept there only if the reader was already at the end.
        const atEnd = first || window.innerHeight + window.scrollY >= document.body.scrollHeight - 80;
        first = false;
        put(list, ...(r.messages.length ? r.messages.map((m) => {
          const st = m.dir !== 'out' ? '' : m.status === 'queued' ? (m.code === 'no_reader' ? ' (not collected yet)' : ' (queued)') : m.status === 'refused' ? ` (refused: ${m.code})` : m.status === 'sent' ? ' ✓' : '';
          return h('div', { class: `msg ${m.dir}` }, h('div', { class: 'who' }, m.dir === 'out' ? 'me' : 'them', ' · ', when(m.at), st),
            m.label && m.label !== 'sigelo-file/0' ? badge(m.label) : null,
            m.link ? badge(`link ${m.link.id}: ${m.link.purpose}`, 'link') : null, m.label === 'sigelo-file/0' ? fileText(m.text) : h('div', { class: 'text' }, m.text));
        }) : [h('p', { class: 'muted' }, 'No messages yet.')]));
        if (atEnd) window.scrollTo(0, document.body.scrollHeight);
      }
    };
  }

  // ---- LINKS (LINKS.md): introduce two contacts, one of them yours; the links made; introductions to answer
  const DAYS = [['', 'no end'], ['1', '1 day'], ['7', '7 days'], ['30', '30 days'], ['90', '90 days']];
  // A new introduction (its introducer not quiet here): a banner until opened or put off.
  // Relay controls paired, their four words not confirmed yet (ui --remote --relay): confirmed or
  // refused here as in the terminal. The computer's own page only: never asked over the relay.
  function controlsCard() {
    const pend = S.controls ?? [];
    if (!pend.length) return null;
    const answer = (name, match) => act(() => backend.call('POST', '/api/controls/confirm', { name, match }));
    return h('div', { class: 'card' }, h('h2', null, 'Controls'), ...pend.map((c) => h('div', null,
      h('p', null, `${c.name} (scope ${c.scope}) paired over the relay. Does the app show the same four words?`), h('p', { class: 'words' }, c.words ?? '(none)'),
      h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => answer(c.name, true) }, 'Confirm'), h('button', { onclick: () => answer(c.name, false) }, 'Refuse')))));
  }
  function introBanner() {
    const fresh = (S.snap?.introductions ?? []).filter((x) => !S.introSeen.has(x.id));
    if (!fresh.length || S.view === 'links') return null;
    const x = fresh[0];
    return h('div', { class: 'card' }, h('p', null, fresh.length === 1 ? `${safeText(x.name)} introduces an agent to you, for: ${safeText(x.purpose)}` : `${fresh.length} introductions wait for your answer`),
      h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => show('links') }, 'See'), h('button', { onclick: () => { for (const y of fresh) S.introSeen.add(y.id); S.update(); } }, 'Later')));
  }
  const select = (label, options, value) => {
    const el = h('select', { 'aria-label': label }, options.map(([v, t]) => h('option', { value: v }, t)));
    el.value = value;
    return el;
  };
  function viewLinks() {
    const top = h('div'), intro = h('div'), made = h('div'), mine = h('div'), rules = h('div'), result = h('div');
    const aSel = h('select', { 'aria-label': 'First' }), bSel = h('select', { 'aria-label': 'Second' });
    const purpose = h('input', { autocomplete: 'off', maxlength: '120', placeholder: 'review the pull requests', 'aria-label': 'Purpose' });
    const note = h('textarea', { rows: 2, maxlength: '280', placeholder: 'optional', 'aria-label': 'Note for them' });
    const days = select('Ends', DAYS, '30'), tierA = select('How yours files the other', [['', 'as usual'], ['friend', 'friend'], ['quiet', 'quiet']], '');
    const tierB = select('How the second files the first', [['', 'as usual'], ['friend', 'friend'], ['quiet', 'quiet']], '');
    const extra = h('div');
    // The names they file each other under (peer_name): blank, the names you gave them here.
    const nameB = h('input', { autocomplete: 'off', autocapitalize: 'none', maxlength: '64', 'aria-label': 'What the first calls the second' });
    const nameA = h('input', { autocomplete: 'off', autocapitalize: 'none', maxlength: '64', 'aria-label': 'What the second calls the first' });
    let names = '';
    const pick = () => [contactBy(aSel.value), contactBy(bSel.value)];
    // External (one of them not yours): a note, their tier is theirs to choose; own: both tiers.
    const shape = () => {
      const [a, b] = pick(), external = a && b && a.ours !== b.ours, none = a && b && !a.ours && !b.ours;
      nameB.placeholder = b?.name ?? ''; nameA.placeholder = a?.name ?? '';
      put(extra, none ? h('p', { class: 'warn' }, 'One of the two must be yours (run by you).') : null,
        h('label', null, 'What the first calls the second (blank: your name for it)'), nameB, h('label', null, 'What the second calls the first'), nameA,
        h('label', null, 'How yours files the other'), tierA,
        external ? [h('label', null, 'Note for them (they see it, with your agent\'s identity)'), note] : [h('label', null, 'How the second files the first'), tierB]);
    };
    aSel.addEventListener('change', shape); bSel.addEventListener('change', shape);
    const go = async () => {
      const [a, b] = pick();
      if (!a || !b || a.did === b.did || !purpose.value.trim()) { S.note = { message: 'Pick two different contacts and say what for.' }; S.update(); return; }
      const external = a.ours !== b.ours, theirs = external ? (a.ours ? b : a) : null, yours = external ? (a.ours ? a : b) : null;
      if (!confirm(`Link ${a.name} and ${b.name} for: ${purpose.value.trim()}?${theirs ? `\n${theirs.name} learns ${yours.name}'s identity, the purpose and your note.` : ''}`)) return;
      await act(() => backend.call('POST', '/api/link', { a: a.did, b: b.did, purpose: purpose.value.trim(), ...(days.value && { days: Number(days.value) }),
        ...(tierA.value && { tier_a: tierA.value }), ...(!external && tierB.value && { tier_b: tierB.value }), ...(external && note.value.trim() && { note: note.value.trim() }),
        ...(nameA.value.trim() && { name_a: nameA.value.trim() }), ...(nameB.value.trim() && { name_b: nameB.value.trim() }) }),
      (r) => { purpose.value = ''; note.value = ''; nameA.value = ''; nameB.value = ''; put(result, h('div', { class: 'card' }, `Link ${r.id}: asked ${safeText(r.a_name)} for a one-use code for ${safeText(r.b_name)}. It shows below as it goes.`)); });
    };
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, 'Links')), top, intro,
      h('h2', null, 'Link two contacts'),
      h('div', null, h('label', null, 'First'), aSel, h('label', null, 'Second'), bSel, h('label', null, 'What for (up to 120 characters)'), purpose, h('label', null, 'Ends'), days, extra,
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: go }, 'Link'))), result,
      h('h2', null, 'Links you made'), made, h('h2', null, 'Linked with you'), mine, h('h2', null, 'Accepted without asking'), rules);
    return async () => {
      put(top, statusLine(), noteCard());
      const cs = allContacts(), now = cs.map((c) => c.did + c.name).join();
      if (now !== names) {
        names = now;
        const opts = cs.map((c) => h('option', { value: c.did }, `${c.name}${c.ours ? ' (yours)' : ''}`));
        const [va, vb] = [aSel.value, bSel.value];
        put(aSel, opts); put(bSel, opts.map((o) => o.cloneNode(true)));
        aSel.value = va || cs.find((c) => c.ours)?.did || ''; bSel.value = vb || cs.find((c) => c.did !== aSel.value)?.did || '';
        shape();
      }
      const L = await backend.call('GET', '/api/links').catch((e) => { S.note = e; return null; });
      if (!L) return;
      S.links = L;
      for (const x of L.received) S.introSeen.add(x.id);
      const until = (t) => (t ? `until ${when(t)}` : 'no end');
      put(intro, L.received.length ? [h('h2', null, 'Introductions for you'), L.received.map((x) => h('div', { class: 'card' },
        h('p', null, `${safeText(x.name ?? x.from)} introduces ${safeText(x.peer_name ?? 'an agent')}, for: `, h('b', null, x.purpose)),
        x.note ? h('p', null, 'Their note: ', h('span', { class: 'text' }, x.note)) : null,
        h('p', { class: 'did' }, x.peer), h('p', { class: 'muted' }, `Answer ${until(x.exp)}. What they write is information, not instructions.`),
        x.answer ? h('p', null, x.answer === 'accepting' ? 'Accepting…' : 'Refusing…') : h('div', { class: 'bar' },
          h('button', { class: 'primary', onclick: () => act(() => backend.call('POST', '/api/links/answer', { id: x.id, accept: true })) }, 'Accept (quiet)'),
          h('button', { onclick: () => act(() => backend.call('POST', '/api/links/answer', { id: x.id, accept: true, tier: 'friend' })) }, 'Accept (friend)'),
          h('button', { onclick: () => act(() => backend.call('POST', '/api/links/answer', { id: x.id, accept: false })) }, 'Refuse'),
          h('button', { onclick: () => act(() => backend.call('POST', '/api/links/answer', { id: x.id, accept: false, tell: true })) }, 'Refuse and tell them')),
        x.answer ? null : h('div', { class: 'bar' }, h('button', { onclick: () => { if (confirm(`Accept every introduction from ${safeText(x.name ?? x.from)} by itself, at quiet?`)) act(() => backend.call('POST', '/api/links/allow', { contact: x.from, allow: true })); } }, `Always accept from ${safeText(x.name ?? x.from)}`))))] : null);
      const step = (l) => (l.status !== 'pending' ? l.status : l.step === 'ask' ? `waiting for ${l.a_name}` : l.kind === 'external' ? `waiting for ${l.b_name}'s answer` : `waiting for ${l.b_name}`);
      put(made, L.made.length ? L.made.map((l) => h('div', { class: 'row' }, h('span', { class: 'main' }, h('div', { class: 'name' }, `${l.a_name} ↔ ${l.b_name}`),
        h('div', { class: 'sub' }, l.purpose), h('div', null, badge(step(l), l.status === 'refused' ? 'alert' : l.status === 'linked' ? 'ok' : ''), l.check ? badge(l.check) : null, badge(until(l.expires)), badge(l.id))),
        l.status === 'pending' || l.status === 'linked' ? h('button', { class: 'danger', onclick: () => { if (confirm(`Unlink ${l.a_name} and ${l.b_name}? Both forget each other.`)) act(() => backend.call('POST', '/api/unlink', { id: l.id })); } }, 'Unlink') : null))
        : h('p', { class: 'muted' }, 'None yet.'));
      put(mine, L.links.length ? L.links.map((l) => h('div', { class: 'row' }, h('span', { class: 'main' }, h('div', { class: 'name' }, l.name), h('div', { class: 'sub' }, l.purpose),
        h('div', null, tierChip(l.tier), badge(until(l.expires)))),
        h('button', { class: 'danger', onclick: () => { if (confirm(`End the link with ${l.name}?`)) act(() => backend.call('POST', '/api/unlink', { id: l.id })); } }, 'Unlink')))
        : h('p', { class: 'muted' }, 'None.'));
      put(rules, L.allow.length ? L.allow.map((r) => h('div', { class: 'row' }, h('span', { class: 'main' }, h('div', { class: 'name' }, r.name ?? r.contact), h('div', { class: 'sub' }, `at ${r.tier}, ${until(r.until)}`)),
        h('button', { onclick: () => act(() => backend.call('POST', '/api/links/allow', { contact: r.contact, allow: false })) }, 'Stop')))
        : h('p', { class: 'muted' }, 'None: each introduction waits for your answer.'));
    };
  }

  // ---- DEVICES (DEVICES.md): this account on a phone or a second computer, by QR. SAFE here (the device
  // becomes an agent of yours); FULL moves your identity too, only in a terminal. QR codes are drawn and read
  // here: contact/qr.mjs and qr-decode.mjs (served beside this page, as they are), BarcodeDetector first
  // where the browser has it. What is scanned stays in this page's memory until it is sent.
  // Never remote (a computer's page through the app): moving keys needs a human at that computer.
  // The seat (one device logs in as you at a time): another device holding it (me.seat), or a refusal
  // seat_elsewhere, shows here, in any view, once.
  function seatBanner() {
    const seat = S.snap?.me?.seat, e = [S.note, S.fatal].find((x) => x?.check === 'seat_elsewhere');
    // In the app restored from seed (apps/web, LOCAL): the seat is taken here, after a warning (POST /api/seat/take).
    const take = () => { if (SEC.st?.kept) { show('seat-take'); return; } if (confirm('Take the seat here only if that other device is stopped or lost: two devices logging in as you lose each other\'s messages. Take it?')) act(() => backend.call('POST', '/api/seat/take', { confirm: true })); };
    if (seat && !seat.here) return h('div', { class: 'card warn' }, `The seat is with ${seat.holder}: this page no longer logs in as you. `,
      LOCAL ? h('button', { onclick: take }, 'Take the seat here') : 'Here: sigelo-agent device seat take.');
    return e ? h('div', { class: 'card warn' }, 'Another device holds your seat: ', e.message) : null;
  }
  const lazy = (path) => { let m; return async () => { if (m === undefined) { try { m = await import(path); } catch { m = null; } } return m; }; };
  const qrLib = lazy('/qr.mjs'), qrDec = lazy('/qr-decode.mjs');
  const qrCache = new Map();
  /** A QR symbol of text on a canvas (level M, a quiet zone of 4), or null without qr.mjs. */
  async function qrCanvas(text) {
    if (qrCache.has(text)) return qrCache.get(text);
    const lib = await qrLib();
    if (!lib) return null;
    const m = lib.encode(text, { ecc: 'M', maxVersion: 20 }), q = 4, n = m.size + 2 * q, k = Math.max(3, Math.floor(Math.min(360, window.innerWidth - 32) / n));
    const cv = h('canvas', { class: 'qr', width: n * k, height: n * k, role: 'img', 'aria-label': 'QR code' }), g = cv.getContext('2d');
    g.fillStyle = '#fff'; g.fillRect(0, 0, n * k, n * k); g.fillStyle = '#000';
    m.modules.forEach((row, y) => row.forEach((dark, x) => { if (dark) g.fillRect((x + q) * k, (y + q) * k, k, k); }));
    if (qrCache.size > 32) qrCache.clear();
    qrCache.set(text, cv);
    return cv;
  }
  /** Camera (where the browser has one), an image file or a pasted image, or the text: each text read goes to onText; true stops the camera. */
  function scanner(onText) {
    const status = h('p', { class: 'muted' }), video = h('video', { class: 'scan', muted: true, playsInline: true, 'aria-label': 'Camera' });
    const pick = h('input', { type: 'file', accept: 'image/*', 'aria-label': 'An image of the QR' }), text = h('textarea', { rows: 2, autocomplete: 'off', spellcheck: 'false', 'aria-label': 'The QR\'s text or a code' });
    video.hidden = pick.hidden = true;
    const say = (t) => { status.textContent = t ?? ''; };
    const canvas = document.createElement('canvas'), g = canvas.getContext('2d', { willReadFrequently: true });
    let detector = null, stream = null, timer = 0, busy = false;
    try { if ('BarcodeDetector' in window) detector = new window.BarcodeDetector({ formats: ['qr_code'] }); } catch {}
    async function decode(src, w, ht, max) {
      if (detector) { try { const r = await detector.detect(src); if (r[0]?.rawValue) return r[0].rawValue; } catch {} }
      const d = await qrDec();
      if (!d) return null;
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
    const cam = h('button', { type: 'button', onclick: async () => {
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
    } }, 'Camera');
    // Feature detection: no getUserMedia, or no camera listed (WebKitGTK on some phones): image and paste only.
    if (!navigator.mediaDevices?.getUserMedia) cam.hidden = true;
    else navigator.mediaDevices.enumerateDevices?.().then((ds) => { if (!ds.some((d) => d.kind === 'videoinput')) { cam.hidden = true; say('No camera found: take a photo or a screenshot and use "From an image", or paste the text.'); } }).catch(() => {});
    pick.onchange = () => { const f = pick.files?.[0]; pick.value = ''; if (f) fromImage(f); };
    text.addEventListener('paste', (ev) => {
      const img = [...(ev.clipboardData?.items ?? [])].find((i) => i.type.startsWith('image/'));
      if (img) { ev.preventDefault(); fromImage(img.getAsFile()); }
    });
    const use = () => { const t = text.value; text.value = ''; if (t.trim()) give(t); };
    const el = h('div', null, h('div', { class: 'bar' }, cam, h('button', { type: 'button', onclick: () => pick.click() }, 'From an image')), video, pick,
      h('label', null, 'Or paste its text, a code, or a screenshot of it'), text, h('div', { class: 'bar' }, h('button', { type: 'button', onclick: use }, 'Use the text')), status);
    el.stop = stop; el.say = say;
    return el;
  }
  const STATE_SAYS = { code: 'waiting for the device to scan the code', words: 'compare the four words', sending: 'sending its key, end to end', done: 'added', refused: 'not added', expired: 'the code expired: add it again' };
  function viewDevices() {
    const top = h('div'), adding = h('div'), offline = h('div'), list = h('div'), joining = h('div'), frames = h('div'), words = h('div');
    const name = h('input', { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', maxlength: '20', placeholder: 'phone', 'aria-label': 'Device name' });
    const myName = h('input', { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', maxlength: '20', placeholder: 'device', 'aria-label': 'This device\'s name' });
    const D = { got: new Map(), count: 0, need: false, offline: null, timer: 0, result: null };
    // ---- the giving side
    const addDevice = (off) => act(() => backend.call('POST', '/api/devices/add', { name: name.value.trim(), ...(off && { offline: true }) }), (r) => { name.value = ''; if (off) showFrames(r); });
    function showFrames(r) {
      clearInterval(D.timer);
      D.offline = { ...r, at: 0 };
      const cv = h('div'), label = h('p', { class: 'muted' });
      const draw = async () => { const o = D.offline; if (!o?.frames) return; const c = await qrCanvas(o.frames[o.at]); put(cv, c ?? h('div', { class: 'long' }, o.frames[o.at])); label.textContent = `frame ${o.at + 1} of ${o.frames.length}`; };
      const next = () => { if (!D.offline?.frames) return; D.offline.at = (D.offline.at + 1) % D.offline.frames.length; draw(); };
      put(offline, h('div', { class: 'card' }, h('p', null, `${safeText(r.name)}: scan every frame on the device, any order (worker ${r.worker}).`), cv, label,
        h('div', { class: 'bar' }, h('button', { onclick: next }, 'Next frame'), h('button', { class: 'primary', onclick: wordsNow }, 'All scanned: show the words'))));
      draw();
      if (r.frames.length > 1) D.timer = setInterval(next, 1000);
    }
    // The words never share the screen with the frames: those go first, and the words come once.
    async function wordsNow() {
      clearInterval(D.timer);
      const o = D.offline;
      D.offline = null;
      put(offline, h('p', { class: 'muted' }, 'Getting the words…'));
      let w = null;
      try { w = (await backend.call('POST', '/api/devices/words', { id: o.id })).words; } catch (e) { put(offline, errorCard(e)); return; }
      put(offline, h('div', { class: 'card' }, h('p', null, `Type these on ${safeText(o.name)} (shown once; never photograph them with the frames):`),
        h('div', { class: 'words' }, w.split(' ').map((x) => h('span', null, x))), h('p', { class: 'did' }, `It shows worker ${o.worker}, ${o.did}`),
        h('p', { class: 'muted' }, 'Its invite lives 7 days: keep this page open (or come back) once the device is online, so its answer is read.'),
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => put(offline) }, 'Typed: hide them'))));
      w = null;
    }
    // ---- this machine as the device
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
      } catch (e) { scan.say(''); S.note = e; S.update(); return e.check !== 'device_frame' ? true : false; }
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
      const w = h('input', { type: 'password', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', 'aria-label': 'The words' });
      const go = async () => { const typed = w.value; w.value = ''; await send([...D.got.values()], typed); if (D.need) w.focus(); };
      w.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') go(); });
      put(words, h('div', { class: 'card' }, h('label', null, 'Type the words the giving screen shows (not shown here)'), w, h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: go }, 'Open'))));
      w.focus();
    }
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: () => { scan.stop(); clearInterval(D.timer); back(); } }, '‹'), h('h1', null, 'Devices')), top,
      h('h2', null, 'Add a device'),
      h('div', null, h('label', null, 'Its name (a-z, 0-9, _ and -)'), name,
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => addDevice(false) }, 'Add (online)'), h('button', { onclick: () => addDevice(true) }, 'Add offline')),
        h('p', { class: 'muted' }, 'It becomes an agent of yours with its own key, attested 14 days and renewed. To give it your identity too (FULL), use a terminal: sigelo-agent device add --name <n> --full.')),
      adding, offline,
      h('h2', null, 'Your devices'), list,
      h('div', { class: 'bar' }, h('button', { onclick: () => act(() => backend.call('POST', '/api/devices/sync')) }, 'Send the list to every device')),
      h('h2', null, 'This is the new device'),
      h('div', null, h('label', null, 'Name for this device'), myName, h('p', { class: 'muted' }, 'Scan the QR the other screen shows: the online code, or every frame of an offline one.'), scan, words, joining));
    return async () => {
      put(top, statusLine(), noteCard());
      const L = await backend.call('GET', '/api/devices').catch((e) => { S.note = e; return null; });
      if (!L) return;
      const cards = [];
      for (const a of L.adding) {
        const kids = [h('p', null, h('b', null, a.name), ` · worker ${a.worker} · ${STATE_SAYS[a.state] ?? a.state}`)];
        if (a.state === 'code') {
          kids.push((await qrCanvas(a.qr)) ?? '', h('div', { class: 'long' }, a.qr), h('div', null, 'or type ', h('span', { class: 'code' }, a.short), ' · ', countdown(a.exp), ' left, once'));
        } else if (a.state === 'words') {
          kids.push(h('div', null, 'Do the device\'s four words read:'), a.words ? h('div', { class: 'words' }, a.words.split(' ').map((w) => h('span', null, w))) : h('p', { class: 'muted' }, '(not known yet)'),
            h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => act(() => backend.call('POST', '/api/devices/confirm', { id: a.id, match: true })) }, 'They match: send its key'),
              h('button', { class: 'danger', onclick: () => act(() => backend.call('POST', '/api/devices/confirm', { id: a.id, match: false })) }, 'They don\'t')));
        }
        if (a.check) kids.push(h('p', { class: 'warn' }, a.detail ?? a.check));
        cards.push(h('div', { class: 'card' }, kids));
      }
      put(adding, cards);
      put(list, L.devices.length ? L.devices.map((d) => h('div', { class: 'row' }, h('span', { class: 'main' },
        h('div', { class: 'name' }, d.name), h('div', { class: 'sub' }, `worker ${d.worker} · added ${when(d.added)}${d.seen ? ` · seen ${when(d.seen)}` : ''}`),
        h('div', null, d.via === 'here' ? badge('this machine') : null, badge(d.rank.toUpperCase(), d.rank === 'full' ? 'alert' : ''), d.revoked ? badge(`revoked ${when(d.revoked)}`, 'alert') : badge(d.paired ? 'paired' : 'not paired yet', d.paired ? 'ok' : ''), d.tier ? tierChip(d.tier) : null),
        h('div', { class: 'did' }, d.did)),
        d.revoked || d.via === 'here' ? null : h('button', { onclick: () => { if (confirm(`Revoke ${d.name}? It is told to delete its keys, and forgotten here when it answers.`)) act(() => backend.call('POST', '/api/devices/revoke', { name: d.name })); } }, 'Revoke'),
        d.via === 'here' ? null : h('button', { class: 'danger', onclick: () => { if (confirm(`${d.name} lost or stolen? It is revoked and forgotten now${d.rank === 'full' ? '; it held your identity: the steps with your 25 words follow' : ''}.`)) act(() => backend.call('POST', '/api/devices/revoke', { name: d.name, lost: true }), (r) => { if (r.steps) S.note = { message: [...r.steps.now.map((x) => `Done: ${x}`), 'With your 25 words:', ...r.steps.words.map((x, i) => `${i + 1}. ${x}`)].join('\n') }; }); } }, 'Lost')))
        : h('p', { class: 'muted' }, L.list ? 'None left.' : 'None yet: Add a device.'));
      const j = L.joining, r = D.result, out = [];
      if (j) {
        if (j.state === 'joining') out.push(h('p', null, 'Pairing with the giving side…'));
        if (j.state === 'words') out.push(h('div', { class: 'card' }, h('p', null, 'The giving screen asks whether its words read:'), j.words ? h('div', { class: 'words' }, j.words.split(' ').map((w) => h('span', null, w))) : h('p', { class: 'muted' }, '(waiting for the pairing)'), h('p', { class: 'muted' }, 'Answer there; this device gets its key once you do.')));
        if (j.state === 'done') out.push(h('p', { class: 'good' }, `✓ This device is worker ${j.worker ?? '?'} (${j.did}), in ${j.file}`));
        if (j.state === 'failed') out.push(h('div', { class: 'card err' }, `${j.check}: ${j.message}`), j.long ? h('div', { class: 'long' }, j.long) : null);
      }
      if (r?.kind === 'offline' && r.state === 'done') out.push(h('p', { class: 'good' }, `✓ This device is worker ${r.worker} (${r.did}) of ${r.operator}, in ${r.file}${r.paired ? ', paired' : '; it pairs once the giving side is online'}. Check the DID against the giving screen.`));
      put(joining, out);
    };
  }

  // ---- ME
  function viewMe() {
    const body = h('div'), how = h('p', { class: 'did' });
    how.hidden = true;
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, 'Me')), body);
    backend.call('GET', '/api/me').then((m) => { S.me = m; S.update(); }).catch((e) => { S.note = e; });
    // The relay setting (UI-API.md Settings): the picker, kept out of the redraw so typing survives the poll.
    const R = { s: null, say: '' };
    const saveRelay = async (v) => {
      try { R.s = await backend.call('POST', '/api/settings', { relay: v }); R.say = 'Saved.'; } catch (e) { R.say = e.message; }
      S.update();
    };
    const picker = relayPicker((host) => saveRelay(host));
    backend.call('GET', '/api/settings').then((x) => { R.s = x; S.update(); }).catch(() => { R.s = false; });
    const relayBlock = () => {
      if (!R.s) return null;
      const now = R.s.fixed ?? R.s.relay;
      return [h('h2', null, 'Relay for new codes'),
        h('p', null, `New codes use ${now}`),
        R.s.fixed ? h('p', { class: 'muted' }, `SIGELO_RELAY on this computer sets ${R.s.fixed}: it wins over the setting below.`) : null,
        picker.render(now, R.s.default),
        R.say ? h('p', { class: 'muted' }, R.say) : null,
        h('p', { class: 'muted' }, 'A 12-character code always names its own relay, whatever this says. Your own connection moves at the next start.')];
    };
    return async () => {
      S.agents = await backend.call('GET', '/api/agents').catch(() => S.agents);
      const m = S.me;
      if (!m) return;
      const cp = h('button', { onclick: () => copy(m.did, cp) }, 'Copy');
      how.textContent = m.erase;
      put(body, errorCard(S.note) ?? '',
        h('div', { class: 'card' }, h('div', { class: 'did' }, m.did), h('div', { class: 'bar' }, cp)),
        h('p', null, m.recovery === 'set' ? 'Recovery key: set, offline' : h('span', { class: 'warn' }, 'Recovery key: none. Theft of this key is permanent.')),
        m.restored ? h('p', null, `${m.restored.created ? `Created on ${m.restored.on}; the 25 words are on your paper` : `Restored from your 25 words on ${m.restored.on}`} · keeper ${m.restored.keeper} · ${m.restored.seat === 'here' ? 'logs in as you here (the seat)' : m.restored.seat === 'elsewhere' ? 'the seat is on another device' : 'seat not set up (device seat init)'}`) : null,
        h('p', null, m.key === 'browser' ? 'Key: in this app\'s storage, sealed under a key it cannot export' : m.key === 'keychain' ? 'Key: sealed in this machine\'s keyring' : 'Key: in the identity file, not sealed (sigelo-agent keys wrap seals it)'),
        h('p', null, `Relay: ${m.relay} · keeps messages ${m.retention_days} days`),
        relayBlock(),
        profilesEntry(),
        securityEntry(),
        computersEntry(),
        h('h2', null, 'Agents on this machine'),
        (S.agents ?? []).length ? S.agents.map((a) => h('div', { class: 'row' }, h('span', { class: 'main' }, h('div', { class: 'name' }, a.name),
          h('div', { class: 'sub' }, a.error ? a.error : a.mine ? `run by me · ${a.mine.days_left} d left` : 'not mine', a.worker !== null ? ` · worker ${a.worker}` : a.error ? '' : ' · not from your words', a.contact ? ' · paired' : '')),
          a.error ? null : a.worker !== null ? (a.renew ? h('button', { onclick: () => act(() => backend.call('POST', '/api/agents/enrol', { agent: a.name })) }, 'Renew') : null)
            : h('button', { onclick: () => { if (!a.contacts || confirm(`${a.contacts} contact(s) know its old DID and must pair again. Enrol?`)) act(() => backend.call('POST', '/api/agents/enrol', { agent: a.name }), (r) => { if (r.warning) S.note = { message: r.warning }; }); } }, 'Enrol'),
          a.error || a.contact ? null : h('button', { onclick: (ev) => { ev.target.disabled = true; ev.target.textContent = 'Pairing…'; act(() => backend.call('POST', '/api/agents/pair', { agent: a.name })); } }, 'Pair')))
          : h('p', { class: 'muted' }, 'None found.'),
        h('h2', null, 'History'),
        h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: () => { if (confirm('Clear the message history kept on this machine?')) act(() => backend.call('POST', '/api/history/clear')); } }, 'Clear history')),
        h('div', { class: 'bar' }, h('button', { onclick: () => { how.hidden = !how.hidden; } }, 'Delete my relay data: how')), how);
    };
  }

  // ---- ADD A CONTACT: someone else's identity (a person's, or an agent not yours), paired by a code
  function viewAdd() {
    const nameIn = h('input', { autocomplete: 'off', maxlength: '64', placeholder: 'optional', 'aria-label': 'Their name' });
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, 'Add a contact')),
      h('p', null, 'Pair with someone else\'s identity, a person\'s or their agent\'s. It stays theirs; you choose how much its messages reach you.'),
      h('p', { class: 'muted' }, 'Not this? Your own agent on another machine: ', h('button', { onclick: () => show('enrol') }, 'Enrol my agent')),
      h('label', null, 'Their name, as you will see it'), nameIn,
      h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => invite(nameIn.value.trim() ? { name: nameIn.value.trim() } : {}) }, 'Make a code to send')),
      h('div', { class: 'bar' }, h('button', { onclick: () => show('pair', { mode: 'enter' }) }, 'I have their code')),
      h('p', { class: 'muted' }, 'A code works once, for 10 minutes. Then you both compare four words.'));
    return () => {};
  }

  // ---- PROFILES (design/profiles.md §3): several identities in one app, the active one open. Where the shell has
  // them: the WebView app's (LOCAL.profiles, apps/web/boot.mjs) or the GTK phone app's (its bridge, apps/gtk), never
  // a computer's own page. Me → Profiles: the list, the one in use marked; switch, rename, add, remove.
  const PROFILE_SHELL = globalThis.webkit?.messageHandlers?.sigelo;
  const PROFILES = LOCAL?.profiles ?? (PROFILE_SHELL ? shellProfiles(PROFILE_SHELL) : null);
  /** The GTK phone app's profile operations over its bridge: {ok, …} answers, a refusal thrown. */
  function shellProfiles(wk) {
    const ask = async (op, o = {}) => {
      const r = await wk.postMessage({ op, ...o });
      if (!r?.ok) throw Object.assign(new Error(r?.message ?? `${op}: no answer`), { check: r?.check });
      return r;
    };
    return { list: () => ask('profiles'), use: (id) => ask('profile-use', { id }), rename: (id, name) => ask('profile-rename', { id, name }),
      add: () => ask('profile-add'), remove: (id, o) => ask('profile-remove', { id, ...o }) };
  }
  const PROFILE_KIND = { words: 'Your identity', remote: 'A computer\'s page' };
  const profileSub = (p) => [p.words ?? (p.kind ? null : 'Not set up yet'), PROFILE_KIND[p.kind] ?? null].filter(Boolean).join(' · ');
  /** Me's line to the Profiles screen, where the shell has profiles. */
  function profilesEntry() {
    if (!PROFILES) return null;
    return [h('h2', null, 'Profiles'), h('p', { class: 'muted' }, 'Other identities on this phone, each with its own contacts, agents, chats and wallet.'),
      h('div', { class: 'bar' }, h('button', { onclick: () => show('profiles') }, 'Profiles'))];
  }
  function viewProfiles() {
    const P = { r: null, edit: null, input: null, say: null };
    const body = h('div');
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, 'Profiles')), body);
    const load = () => PROFILES.list().then((r) => { P.r = r; S.update(); }, (e) => { P.say = e; S.update(); });
    const run = async (fn) => { P.say = null; try { const r = await fn(); if (!r?.reload) await load(); } catch (e) { P.say = e; S.update(); } };
    load();
    const rename = (p) => {
      P.edit = p.id;
      P.input = h('input', { value: p.name, maxlength: '24', autocomplete: 'off', 'aria-label': 'The profile\'s name' });
      S.update();
      P.input.focus?.();
    };
    return () => {
      if (!P.r) { put(body, errorCard(P.say) ?? h('p', { class: 'muted' }, 'Loading…')); return; }
      if (P.edit && document.activeElement === P.input) return;   // a name being typed: not redrawn under the keyboard
      const { active, limit, profiles } = P.r;
      const rows = profiles.map((p) => h('div', { class: `card${p.id === active ? ' current' : ''}`, 'data-profile': p.id },
        P.edit === p.id ? [P.input, h('div', { class: 'bar' },
          h('button', { class: 'primary', onclick: () => run(async () => { await PROFILES.rename(p.id, P.input.value); P.edit = null; }) }, 'Save'),
          h('button', { onclick: () => { P.edit = null; S.update(); } }, 'Cancel'))]
          : h('div', { class: 'name' }, p.name, p.id === active ? ' ' : '', p.id === active ? badge('in use', 'ok') : null),
        h('div', { class: 'sub' }, profileSub(p)),
        h('div', { class: 'bar' },
          p.id === active ? null : h('button', { class: 'primary', onclick: () => run(() => PROFILES.use(p.id)) }, 'Switch'),
          P.edit === p.id ? null : h('button', { onclick: () => rename(p) }, 'Rename'),
          h('button', { class: 'danger', onclick: () => show('profile-remove', p.id) }, 'Remove'))));
      put(body, errorCard(P.say) ?? '', rows,
        h('div', { class: 'bar' }, h('button', { disabled: profiles.length >= limit, onclick: () => run(() => PROFILES.add()) }, 'Add a profile')),
        h('p', { class: 'muted' }, profiles.length >= limit ? `At most ${limit} profiles: remove one to add another.` : 'Only the profile in use connects; the others\' messages wait at the relay until you switch.'));
    };
  }
  function viewProfileRemove(id) {
    const R = { p: null, say: null, kept: false };
    const body = h('div'), tick = h('input', { type: 'checkbox' }), name = h('input', { autocomplete: 'off', maxlength: '24', 'aria-label': 'Its name' }), pw = pwField('Its words password');
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, 'Remove a profile')), body);
    PROFILES.list().then((r) => { R.p = r.profiles.find((p) => p.id === id) ?? null; S.update(); }, (e) => { R.say = e; S.update(); });
    WORDS?.status(id).then((r) => { R.kept = r.kept; S.update(); }, () => {});   // its words kept behind a password: that password too
    const go = async (btn) => {
      btn.disabled = true; R.say = null;
      try {
        const auth = R.kept && R.p?.kind === 'words' ? await WORDS.auth(id, pw.value) : {};
        const r = await PROFILES.remove(id, { name: name.value, words: tick.checked, ...auth });
        if (!r?.reload) show('profiles');
      } catch (e) { R.say = e; btn.disabled = false; S.update(); }
    };
    return () => {
      const p = R.p;
      if (!p) { put(body, errorCard(R.say) ?? h('p', { class: 'muted' }, 'Loading…')); return; }
      const btn = h('button', { class: 'danger', onclick: () => go(btn) }, `Remove ${p.name}`);
      put(body, h('div', { class: 'card' }, h('div', { class: 'name' }, p.name), h('div', { class: 'sub' }, profileSub(p))),
        p.kind === 'words' ? [h('p', { class: 'warn' }, 'Its identity, wallet keys, contacts and chats leave this phone. Only its 25 words bring it back.'),
          h('label', { class: 'opt' }, tick, h('span', null, 'I have the 25 words'))]
          : p.kind === 'remote' ? h('p', null, 'The computers keep the pairing until you revoke it there: sigelo-agent ui --revoke-control <name>.')
            : h('p', { class: 'muted' }, 'Not set up yet: nothing in it.'),
        p.kind ? [h('label', null, `Type its name, ${p.name}`), name] : null,
        R.kept && p.kind === 'words' ? [h('label', null, 'Its words password'), pw] : null,
        errorCard(R.say) ?? '', h('div', { class: 'bar' }, btn));
    };
  }

  // ---- TRANSFERS (TRANSFER.md): big files with a contact, direct or over Tor; the relay carries only the
  // introduction. Where the page's host moves files (state.transfers not null): a file offered is a card
  // (Accept / Decline, the direct question asked once per contact), progress, done with where it was saved.
  // Sending takes a path on this computer (never remote). What a contact names a file is data.
  const mbOf = (n) => `${(n / 1e6).toFixed(1)} MB`;
  function transferBanner() {
    const t = S.snap?.transfers;
    if (!t || !t.asked || S.view === 'transfers' || S.transfersSeen === t.asked) return null;
    return h('div', { class: 'card' }, h('p', null, t.asked === 1 ? 'A contact offers you a file.' : `${t.asked} files are offered to you.`),
      h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => show('transfers') }, 'See'), h('button', { onclick: () => { S.transfersSeen = t.asked; S.update(); } }, 'Later')));
  }
  // An answer that needs the direct question (direct_ask): asked here, once for that contact, then sent again.
  async function transferCall(path, body, who) {
    try { return await backend.call('POST', path, body); } catch (e) {
      if (e?.check !== 'direct_ask') throw e;
      const yes = confirm(`A direct transfer shows ${who} this computer's public and local network addresses (faster). OK: allow direct for ${who}. Cancel: Tor only (slower, address hidden).`);
      return backend.call('POST', path, { ...body, direct: yes });
    }
  }
  const TSTATE = { asked: 'waiting for your answer', offered: 'waiting for their answer', accepted: 'starting', offering: 'connecting', active: 'moving', interrupted: 'stopped', done: 'done', declined: 'declined', cancelled: 'cancelled', failed: 'failed', expired: 'expired' };
  function transferRow(r, side) {
    const got = side === 'in' ? r.got ?? 0 : r.sent ?? 0, pct = r.size ? Math.min(100, Math.round((100 * got) / r.size)) : 100;
    const bar = h('div');
    bar.style.width = `${pct}%`;
    const live = r.live && r.state !== 'done';
    const btns = [];
    if (side === 'in' && r.state === 'asked') {
      btns.push(h('button', { class: 'primary', onclick: () => act(() => transferCall('/api/transfers/accept', { id: r.id }, r.contact)) }, 'Accept'),
        h('button', { onclick: () => act(() => backend.call('POST', '/api/transfers/decline', { id: r.id })) }, 'Decline'));
    }
    if (side === 'in' && (r.state === 'interrupted' || (r.state === 'failed' && ['no_path', 'tor'].includes(r.reason)))) btns.push(h('button', { onclick: () => act(() => transferCall('/api/transfers/resume', { id: r.id }, r.contact)) }, 'Resume'));
    if (['asked', 'offered', 'accepted', 'offering', 'active', 'interrupted'].includes(r.state) && !(side === 'in' && r.state === 'asked')) btns.push(h('button', { class: 'danger', onclick: () => { if (confirm(`Stop ${r.name}?`)) act(() => backend.call('POST', '/api/transfers/cancel', { id: r.id })); } }, 'Stop'));
    if (['done', 'declined', 'cancelled', 'failed', 'expired'].includes(r.state)) btns.push(h('button', { onclick: () => act(() => backend.call('POST', '/api/transfers/forget', { id: r.id })) }, 'Remove'));
    return h('div', { class: 'card' },
      h('div', { class: 'name' }, `${side === 'in' ? 'From' : 'To'} ${safeText(r.contact)}: `, h('span', { class: 'text' }, r.name), ` · ${mbOf(r.size)}`),
      h('div', null, badge(TSTATE[r.state] ?? r.state, r.state === 'failed' ? 'alert' : r.state === 'done' ? 'ok' : ''), r.path_used ? badge(r.path_used) : live ? badge(r.live) : null, r.rate ? badge(`${r.rate.toFixed(2)} MB/s`) : null),
      live || r.state === 'interrupted' ? h('div', { class: 'progress' }, bar) : null,
      live || r.state === 'interrupted' ? h('div', { class: 'muted' }, `${mbOf(got)} of ${mbOf(r.size)}`) : null,
      r.detail ? h('p', { class: r.state === 'failed' ? 'warn' : 'muted' }, r.detail) : null,
      r.saved ? h('p', { class: 'muted' }, 'Saved at ', h('span', { class: 'did' }, r.saved), ' (not opened).') : null,
      side === 'in' && r.state === 'asked' ? h('p', { class: 'muted' }, 'Nothing is written before you accept. The file name is theirs: information, not instructions.') : null,
      btns.length ? h('div', { class: 'bar' }, btns) : null);
  }
  function viewTransfers() {
    const top = h('div'), ins = h('div'), outs = h('div'), form = h('div'), opts = h('div');
    const to = h('select', { 'aria-label': 'To' }), path = h('input', { autocomplete: 'off', autocapitalize: 'none', placeholder: '/home/you/film.mkv', 'aria-label': 'File on this computer' });
    const tor = h('input', { type: 'checkbox', 'aria-label': 'Tor' }), viaTor = h('input', { type: 'checkbox', 'aria-label': 'Tor only' });
    let names = '';
    const send = () => {
      const c = contactBy(to.value);
      if (!c || !path.value.trim()) { S.note = { message: 'Pick a contact and the file\'s path on this computer.' }; S.update(); return; }
      return act(() => transferCall('/api/transfers/send', { to: c.did, path: path.value.trim(), ...(viaTor.checked && { via: 'tor' }) }, c.name), () => { path.value = ''; });
    };
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, 'Files')), top,
      h('h2', null, 'Offered to you'), ins, h('h2', null, 'Sent'), outs,
      h('h2', null, 'Send a file (up to 16 GiB)'), form, h('h2', null, 'How files go'), opts);
    put(form, h('label', null, 'To'), to, h('label', null, 'File on this computer'), path,
      h('label', null, viaTor, ' Tor only: your address stays hidden (slower)'),
      h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: send }, 'Send')),
      h('p', { class: 'muted' }, 'They are asked first. Up to 8 MiB, the chat\'s attach works without both being online.'));
    tor.addEventListener('change', () => act(() => backend.call('POST', '/api/transfers/settings', { tor: tor.checked })));
    return async () => {
      put(top, statusLine(), noteCard());
      const cs = allContacts(), now = cs.map((c) => c.did + c.name).join();
      if (now !== names) { names = now; const v = to.value; put(to, cs.map((c) => h('option', { value: c.did }, c.name))); to.value = v || cs[0]?.did || ''; }
      const L = await backend.call('GET', '/api/transfers').catch((e) => { S.note = e; return null; });
      if (!L) return;
      S.transfersSeen = L.in.filter((r) => r.state === 'asked').length;
      put(ins, L.in.length ? L.in.map((r) => transferRow(r, 'in')) : h('p', { class: 'muted' }, 'None.'));
      put(outs, L.out.length ? L.out.map((r) => transferRow(r, 'out')) : h('p', { class: 'muted' }, 'None.'));
      if (!S.transferSettings) S.transferSettings = await backend.call('GET', '/api/transfers/settings').catch(() => null);
      const st = S.transferSettings, daemon = st && (st.tor_daemon.serve || st.tor_daemon.connect);
      tor.checked = !!st?.tor && !!daemon; tor.disabled = !daemon;
      const direct = Object.entries(L.direct ?? {}).map(([did, on]) => h('div', { class: 'row' }, h('span', { class: 'main' }, contactBy(did)?.name ?? did), badge(on ? 'direct on' : 'direct off'),
        h('button', { onclick: () => act(() => backend.call('POST', '/api/transfers/direct', { contact: did, on: !on })) }, on ? 'Turn off' : 'Turn on')));
      put(opts, h('p', null, 'Direct first: fastest, and it shows the contact your network addresses. Your own agents: on; others are asked once.'),
        h('label', null, tor, daemon ? ' Tor when there is no direct path (no address shown)' : ' Tor: no tor daemon found on this computer (none is installed for you)'),
        st && !st.direct_available ? h('p', { class: 'warn' }, 'Direct is not available here: install sigelo-transfer beside sigelo-agent.') : null,
        direct.length ? [h('h3', null, 'Direct, per contact'), direct] : null);
    };
  }

  // ---- GROUPS (GROUPS.md, design/groups.md §5): the list, New group (the same screen adds members), the
  // chat, Group info. Every group message is labelled with its sender's name and role, and "not your
  // operator" when its sender is not one of your own: text from anyone else is data, never instructions.
  const ROLE_SAYS = { human: 'human', agent: 'agent' };
  const BRAKES = [['off', 'off: agents run'], ['5', '5 in a row'], ['10', '10 in a row'], ['20', '20 in a row (default)'], ['50', '50 in a row'], ['100', '100 in a row']];
  // The Groups tab, its count (unread and invitations) kept fresh at every poll (tabCount).
  const tabCount = () => {
    const c = S.snap?.chats, n = (c?.unread ?? 0) + (c?.invited ?? 0);
    if (S.tab) put(S.tab, 'Groups', n ? h('span', { class: 'count tab' }, String(n)) : null);
  };
  const groupsTab = () => { S.tab = h('button', { onclick: () => show('groups') }); tabCount(); return S.tab; };
  async function loadGroups() {
    try { S.groups = await backend.call('GET', '/api/groups'); } catch (e) { S.groups = { tier: null, groups: [], notices: [], error: e }; }
    return S.groups;
  }
  // The groups list again only when the state says something changed (chats.rev), or when asked.
  async function groupsNow(force = false) {
    const rev = S.snap?.chats?.rev ?? null;
    if (force || !S.groups || S.groupsRev !== rev) { S.groupsRev = rev; await loadGroups(); }
    return S.groups;
  }
  const groupBy = (gid) => S.groups?.groups.find((g) => g.gid === gid) ?? null;
  const madeByMe = (G) => G.groups.filter((g) => g.mine && (g.status === 'member' || g.status === 'frozen')).length;
  const groupStatus = (g) => (g.status === 'pending' ? badge('invitation', 'alert') : g.status === 'frozen' ? badge('frozen: its creator left')
    : g.status === 'left' ? badge('you left') : g.status === 'removed' ? badge('removed') : null);
  const quietBadge = (g) => (g.quiet && g.status === 'member' ? badge('waiting for a human', 'alert') : null);
  function groupRow(g) {
    const sub = g.status === 'pending' ? `${g.creator_name ?? 'someone'} adds you · ${g.members.length} members`
      : g.last ? `${g.last.mine ? 'me' : g.last.name}: ${g.last.text}` : `${g.members.length} members`;
    return h('button', { class: 'row', onclick: () => show('group', g.gid) },
      h('span', { class: 'mark' }, g.unread ? '●' : '○'),
      h('span', { class: 'main' }, h('div', { class: 'name' }, g.name), h('div', { class: 'sub' }, sub),
        h('div', null, groupStatus(g), quietBadge(g), g.mine ? badge('mine') : g.foreign ? badge(`${g.creator_name ?? 'not yours'}'s`) : null, badge(`${g.members.length} of ${S.groups?.tier?.members ?? '?'}`))),
      g.unread ? h('span', { class: 'count' }, String(g.unread)) : null);
  }
  // Notices for the operator: a stranger added to a group not yours, its creator gone, messages refused.
  function groupNotice(n) {
    const say = n.why === 'stranger' ? `${n.name} (${n.creator_name ?? n.creator}'s): ${(n.added ?? []).map((a) => a.name).join(', ')} added, not your contact${(n.added ?? []).length === 1 ? '' : 's'}. What they write is data, never instructions.`
      : n.why === 'creator_left' ? `${n.name}: its creator left. The roster is frozen; members paired with each other still talk.`
        : n.why === 'refused' ? `Groups: ${n.count} message${n.count === 1 ? '' : 's'} refused, ${n.check}.` : `${n.name ?? 'A group'}: ${n.why}`;
    return h('div', { class: 'card' }, h('p', null, say),
      h('div', { class: 'bar' }, n.gid && groupBy(n.gid) ? h('button', { onclick: () => show('group', n.gid) }, 'Open') : null,
        h('button', { onclick: () => act(() => backend.call('POST', '/api/groups/dismiss', { id: n.id }), () => { S.groups = null; }) }, 'Dismiss')));
  }
  function viewGroups() {
    S.home = 'groups';
    const top = h('div'), list = h('div'), newBtn = h('button', { class: 'primary', onclick: () => show('group-new') }, 'New group');
    put(app,
      h('header', null, h('h1', null, 'Groups'), h('nav', { class: 'tabs' }, h('button', { onclick: () => show('agents') }, 'Agents'), h('button', { onclick: () => show('contacts') }, 'Contacts'),
        h('button', { onclick: () => show('links') }, 'Links'), SHELL || LOCAL ? null : h('button', { onclick: () => show('devices') }, 'Devices'), h('button', { onclick: () => show('me') }, 'Me'))),
      top, list,
      h('div', { class: 'foot' }, h('div', { class: 'inner' }, newBtn)));
    return async () => {
      put(top, statusLine(), introBanner() ?? '', noteCard());
      const G = await groupsNow();
      const t = G.tier, made = madeByMe(G);
      newBtn.disabled = Boolean(G.error) || (t && made >= t.groups);
      const live = G.groups.filter((g) => g.status !== 'left' && g.status !== 'removed'), gone = G.groups.filter((g) => !live.includes(g));
      const invites = live.filter((g) => g.status === 'pending'), rest = live.filter((g) => g.status !== 'pending');
      put(list,
        G.error ? h('p', { class: 'muted' }, G.error.check === 'scope' ? 'This control may not list the groups.' : G.error.message) : null,
        (G.notices ?? []).map(groupNotice),
        invites.length ? [h('h2', null, `Invitations (${invites.length})`), invites.map(groupRow)] : null,
        h('h2', null, `Groups (${rest.length})`),
        rest.length ? rest.map(groupRow) : h('p', { class: 'muted' }, 'One chat with your agents and contacts: New group, a name, tick who is in.'),
        t ? h('p', { class: 'muted' }, `${made} of ${t.groups} groups made by you, up to ${t.members} members each (${t.tier === 'pro' ? 'Pro' : 'free'}).`) : null,
        gone.length ? [h('h2', null, 'Left'), gone.map(groupRow)] : null);
    };
  }

  // New group, and the same screen as Add members (arg: a gid): a name (new only), then the contacts
  // with a tick each: own agents first (preselected when at most three), friends, quiet ones last and
  // unticked; a live "n of 8"; Create lights with a name and one member. Roles are preset (own agents
  // agent, everyone else human), the brake is the default: both under Group info.
  function viewGroupNew(addTo) {
    const adding = typeof addTo === 'string';
    const top = h('div'), body = h('div'), title = h('h1', null, adding ? 'Add members' : 'New group');
    const nameIn = h('input', { autocomplete: 'off', maxlength: '40', placeholder: 'Group name', 'aria-label': 'Group name' });
    const ticked = new Set(), boxes = new Map();
    let filled = false;
    const go = h('button', { class: 'primary' }, adding ? 'Add' : 'Create');
    const counter = h('span', { class: 'muted count-line' });
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), title), top, adding ? null : nameIn, body,
      h('div', { class: 'foot' }, h('div', { class: 'inner' }, counter, go)));
    const contactsOf = () => {
      const { mine, contacts } = S.snap.groups;
      return [...mine.map((c) => ({ c, own: true })), ...contacts.filter((c) => c.tier !== 'quiet').map((c) => ({ c, own: false })), ...contacts.filter((c) => c.tier === 'quiet').map((c) => ({ c, own: false }))];
    };
    const refresh = (max, have) => {
      const n = have + ticked.size;
      counter.textContent = `${n} of ${max}`;
      counter.className = n > max ? 'warn count-line' : 'muted count-line';
      go.disabled = ticked.size === 0 || n > max || (!adding && nameIn.value.trim() === '');
    };
    nameIn.addEventListener('input', () => S.update());
    go.addEventListener('click', () => {
      const all = contactsOf(), members = [...ticked], humans = members.filter((d) => !all.find((x) => x.c.did === d)?.own);
      go.disabled = true;
      act(() => (adding ? backend.call('POST', '/api/groups/add', { group: addTo, members, humans }) : backend.call('POST', '/api/groups/create', { name: nameIn.value.trim(), members, humans })),
        (r) => {
          S.groups = null;
          if (adding) { back(); return; }
          // The chat at once, in place of this screen: Back from it goes to the list.
          S.made = { gid: r.group.gid, n: r.group.members.length };
          globalThis.history?.replaceState?.({ sigeloView: 'group', arg: r.group.gid }, '');
          openView('group', r.group.gid, true);
        });
    });
    return async () => {
      put(top, noteCard());
      if (!S.snap) return;
      const G = await groupsNow(), t = G.tier ?? { members: 8, groups: 3 }, g = adding ? groupBy(addTo) : null;
      if (adding && !g) { put(body, h('p', { class: 'muted' }, 'No such group here.')); return; }
      const inIt = new Set(g ? g.members.map((m) => m.did) : []), have = g ? g.members.length : 1;
      const list = contactsOf().filter(({ c }) => !c.revoked);
      if (!filled) {
        filled = true;
        const own = list.filter((x) => x.own && !inIt.has(x.c.did));
        if (!adding && own.length <= 3) for (const x of own) ticked.add(x.c.did);
        if (!adding) nameIn.focus?.();
      }
      const row = ({ c, own }) => {
        const was = inIt.has(c.did);
        let box = boxes.get(c.did);
        if (!box) {
          box = h('input', { type: 'checkbox', 'aria-label': c.name });
          box.addEventListener('change', () => { if (box.checked) ticked.add(c.did); else ticked.delete(c.did); S.update(); });
          boxes.set(c.did, box);
        }
        box.checked = was || ticked.has(c.did);
        box.disabled = was;
        return h('label', { class: 'opt pick-row' }, box, h('span', { class: 'main' }, h('span', { class: 'name' }, dot(c), c.name), ' ',
          own ? badge('my agent', 'ok') : tierChip(c.tier), was ? badge('in it') : null));
      };
      const own = list.filter((x) => x.own), others = list.filter((x) => !x.own);
      put(body,
        list.length === 0 ? h('p', { class: 'muted' }, 'No contacts yet: a group is made of your contacts (Contacts → Add a contact).') : null,
        own.length ? [h('h2', null, 'My agents'), own.map(row)] : null,
        others.length ? [h('h2', null, 'Contacts'), others.map(row)] : null,
        h('p', { class: 'muted' }, adding ? 'They get the roster from you; each sees who is in.' : `Up to ${t.members} members, you included. Roles and the loop brake: Group info, later.`));
      refresh(t.members, have);
    };
  }

  // The chat: sender name, role, and "not your operator" for a sender not of your own; @name mentions.
  function viewGroup(gid) {
    const title = h('h1'), sub = h('div', { class: 'sub seen' }), alerts = h('div'), list = h('div'), chips = h('div', { class: 'chips' });
    chips.hidden = true;
    const text = h('textarea', { rows: 1, placeholder: 'Message (@name to mention)', 'aria-label': 'Message' });
    const fit = () => { if (!text.style) return; text.style.height = 'auto'; if (text.scrollHeight) text.style.height = `${text.scrollHeight + 2}px`; };
    text.addEventListener('input', () => { fit(); const at = /(^|\s)@[^\s@]*$/.test(text.value); if (chips.hidden === at) { chips.hidden = !at; S.update(); } });
    let seen = null, first = true, quiet = null;
    const send = async () => {
      const t = text.value;
      if (!t.trim()) return;
      sendBtn.disabled = true;
      await act(() => backend.call('POST', '/api/groups/send', { group: gid, text: t }), () => { text.value = ''; fit(); seen = null; chips.hidden = true; });
      if (S.note?.check === 'group_quiet') { quiet = S.note; S.note = null; S.update(); }
      sendBtn.disabled = false;
    };
    text.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send(); } });
    const sendBtn = h('button', { class: 'primary', onclick: send }, 'Send');
    const foot = h('div', { class: 'foot' }, h('div', { class: 'inner col' }, chips, h('div', { class: 'compose' }, text, sendBtn)));
    put(app,
      h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('div', { class: 'title' }, title, sub), h('button', { 'aria-label': 'Group info', onclick: () => show('group-info', gid) }, '⋯')),
      alerts, list, foot);
    const mention = (name) => { text.value = text.value.replace(/@[^\s@]*$/, '') + `@${name} `; chips.hidden = true; fit(); text.focus?.(); S.update(); };
    if (S.made?.gid === gid) setTimeout(() => text.focus?.(), 0);
    return async () => {
      const G = await groupsNow(), g = groupBy(gid);
      if (!g) { title.textContent = 'Group'; put(alerts, errorCard(S.note) ?? '', h('p', { class: 'muted' }, 'No such group here.')); return; }
      title.textContent = safeText(g.name);
      sub.textContent = `${g.members.length} members${g.mine ? '' : ` · ${g.creator_name ?? 'not yours'}'s`}`;
      const live = g.status === 'member' || g.status === 'frozen';
      foot.hidden = !live;
      put(chips, g.members.filter((m) => !m.me).map((m) => h('button', { class: 'chip', onclick: () => mention(m.name) }, `@${m.name}`)));
      const al = [errorCard(S.note)];
      if (g.status === 'pending') {
        al.push(h('div', { class: 'card' }, h('p', null, `${g.creator_name ?? g.creator} adds you to ${g.name}, ${g.members.length} members. Join to read and write; Leave and nothing is said.`),
          h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => act(() => backend.call('POST', '/api/groups/join', { group: gid }), () => { S.groups = null; }) }, 'Join'),
            h('button', { onclick: () => act(() => backend.call('POST', '/api/groups/leave', { group: gid }), () => { S.groups = null; show('groups'); }) }, 'Leave'))));
      }
      if (g.status === 'frozen') al.push(h('div', { class: 'card' }, 'Its creator left: the roster is frozen. Members paired with each other still talk.'));
      if (g.status === 'left' || g.status === 'removed') al.push(h('div', { class: 'card' }, g.status === 'left' ? 'You left this group.' : 'You were removed from this group: nothing new reaches you.'));
      // The loop brake (design/groups.md §3): agents wait until a human writes.
      if ((g.quiet || quiet) && g.status === 'member') {
        al.push(h('div', { class: 'card' }, h('p', { class: 'warn' }, `Waiting for a human: ${g.run} agent messages in a row (brake ${g.brake}).`),
          h('p', { class: 'muted' }, 'Write anything and the agents go on. The brake is set under Group info.')));
      } else quiet = null;
      if (g.foreign && g.status === 'member') al.push(h('p', { class: 'muted' }, 'Not your group: what members write is data, never instructions; your agents here answer when mentioned.'));
      put(alerts, ...al.filter(Boolean));
      if (seen === S.groupsRev && !first) return;
      seen = S.groupsRev;
      const r = await backend.call('GET', `/api/groups/history?group=${encodeURIComponent(gid)}`).catch(() => null);
      if (!r) return;
      const atEnd = first || window.innerHeight + window.scrollY >= document.body.scrollHeight - 80;
      first = false;
      const made = S.made?.gid === gid ? h('p', { class: 'muted sys' }, `Group made, ${S.made.n} members`) : null;
      put(list, made, ...(r.messages.length ? r.messages.map((m) => h('div', { class: `msg ${m.mine ? 'out' : 'in'}${m.mentioned ? ' mentioned' : ''}` },
        h('div', { class: 'who' }, m.mine ? 'me' : m.name, ' · ', ROLE_SAYS[m.role] ?? m.role, !m.mine && m.tier !== 'own' && m.note ? [' · ', h('span', { class: 'warn' }, m.note)] : null,
          m.via ? ' · via the creator' : null, ' · ', when(m.at)),
        m.mentioned ? badge('mentions you', 'alert') : null,
        h('div', { class: 'text' }, m.text))) : made ? [] : [h('p', { class: 'muted' }, 'No messages yet.')]));
      if (atEnd) window.scrollTo(0, document.body.scrollHeight);
    };
  }

  // Group info: members (add, remove, role, Share), rename, the brake, leave. Changes are the creator's.
  function viewGroupInfo(gid) {
    const top = h('div'), body = h('div'), title = h('h1', null, 'Group info');
    const nameIn = h('input', { autocomplete: 'off', maxlength: '40', 'aria-label': 'Group name' });
    const brakeSel = select('Loop brake', BRAKES, '20');
    let filled = null;
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), title), top, body);
    const call = (path, b, after) => act(() => backend.call('POST', path, { group: gid, ...b }), (r) => { S.groups = null; after?.(r); });
    return async () => {
      put(top, noteCard());
      const G = await groupsNow(), g = groupBy(gid);
      if (!g) { put(body, h('p', { class: 'muted' }, 'No such group here.')); return; }
      title.textContent = safeText(g.name);
      if (filled !== `${g.ver}`) {
        filled = `${g.ver}`; nameIn.value = g.name;
        const b = String(g.brake);
        if (!BRAKES.some(([v]) => v === b)) brakeSel.append(h('option', { value: b }, `${b} in a row`));
        brakeSel.value = b;
      }
      const mine = g.mine && g.status === 'member', max = G.tier?.members ?? 8;
      const member = (m) => h('div', { class: 'row member' },
        h('span', { class: 'main' }, h('div', { class: 'name' }, m.me ? 'You' : m.name),
          h('div', null, badge(ROLE_SAYS[m.role] ?? m.role, m.role === 'agent' ? '' : 'ok'), m.did === g.creator ? badge('creator') : null, !m.me && !m.contact ? badge('not your contact: via the creator') : null)),
        mine && !m.me ? h('span', { class: 'acts' },
          h('button', { title: 'Role: human or agent (the brake counts agents)', onclick: () => call('/api/groups/role', { member: m.did, role: m.role === 'agent' ? 'human' : 'agent' }) }, m.role === 'agent' ? 'Make human' : 'Make agent'),
          h('button', { title: 'Send the roster to this member again (a new device, a lost copy)', onclick: () => call('/api/groups/share', { member: m.did }, () => toast(`Roster sent to ${safeText(m.name)}`)) }, 'Share'),
          h('button', { class: 'danger', onclick: () => { if (confirm(`Remove ${safeText(m.name)} from ${safeText(g.name)}? They keep what was said before.`)) call('/api/groups/remove', { members: [m.did] }); } }, 'Remove')) : null);
      put(body,
        h('div', { class: 'card' }, groupStatus(g), quietBadge(g), h('div', null, `${g.members.length} of ${max} members · ${g.mine ? 'made by you' : `made by ${g.creator_name ?? g.creator}`} · roster ${g.ver}`)),
        h('h2', null, 'Members'), g.members.map(member),
        mine ? h('div', { class: 'bar' }, h('button', { disabled: g.members.length >= max, onclick: () => show('group-new', gid) }, 'Add members')) : null,
        mine ? [h('label', null, 'Name'), nameIn, h('div', { class: 'bar' }, h('button', { onclick: () => call('/api/groups/rename', { name: nameIn.value.trim() }) }, 'Rename'))] : null,
        mine ? [h('label', null, 'Loop brake: agent messages in a row with no human between, then agents wait'), brakeSel,
          h('div', { class: 'bar' }, h('button', { onclick: () => call('/api/groups/brake', { brake: brakeSel.value === 'off' ? 'off' : Number(brakeSel.value) }) }, 'Set the brake'))]
          : h('p', { class: 'muted' }, `Loop brake: ${g.brake === 'off' ? 'off' : `${g.brake} agent messages in a row`} (the creator's setting).`),
        g.status === 'member' || g.status === 'frozen' || g.status === 'pending' ? h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: () => {
          if (confirm(g.mine ? `Leave ${safeText(g.name)}? You made it: its roster freezes for everyone.` : `Leave ${safeText(g.name)}?`)) call('/api/groups/leave', {}, () => show('groups'));
        } }, 'Leave the group')) : null,
        h('p', { class: 'did' }, g.gid));
    };
  }

  // ---- SECURITY (design/apps-seed.md §8): the words password, where this phone keeps its own words. Me → Security:
  // Show my 25 words (the device lock, then the password, then the words as at their creation: FLAG_SECURE on
  // Android, nothing to copy, "Done" hides them), change or remove the password (the old one asked). WORDS: the
  // WebView app's or a tab's sigeloLocal.words (apps/web/words.mjs), or the GTK phone app's bridge (the words in
  // its keyring, the KDF here: /words-lock.mjs). A wrong password: said after a delay that doubles (the shell's gate).
  const wordsLib = lazy('/words-lock.mjs');
  /** The GTK phone app's words over its bridge: the encrypted words fetched, opened here; a guarded op carries the proof. */
  function shellWords(wk) {
    const ask = async (op, o = {}) => {
      const r = await wk.postMessage({ op, ...o });
      if (!r?.ok) throw Object.assign(new Error(r?.message ?? `${op}: no answer`), { check: r?.check });
      return r;
    };
    const lib = async () => { const L = await wordsLib(); if (!L) throw new Error('The words check is not installed here (words-lock.mjs).'); return L; };
    const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)), b64 = (b) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(''));
    const opened = async (id, password) => { const L = await lib(), r = await ask('words-get', id ? { id } : {}); return L.gate.run(() => L.openWords(unb64(r.blob), password)); };
    return {
      async status(id) { const r = await ask('words-status', id ? { id } : {}); return { here: r.here === true, kept: r.kept === true, iterations: r.iterations }; },
      async reveal(password) { return { words: (await opened(undefined, password)).words }; },
      async change(old, next, repeat) {
        const L = await lib();
        L.checkPassword(next, repeat);
        const o = await opened(undefined, old), n = await L.lockWords(o.words, next);
        await ask('words-keep', { blob: b64(n.blob), check: n.check, proof: o.check });
        return { kept: true };
      },
      async remove(password) { const o = await opened(undefined, password); await ask('words-drop', { proof: o.check }); return { kept: false }; },
      async auth(id, password) { return { proof: (await opened(id, password)).check }; },
    };
  }
  const WORDS = LOCAL?.words ?? (PROFILE_SHELL ? shellWords(PROFILE_SHELL) : null);
  const SEC = { st: null };   // this phone's words: { here, kept } once asked
  const wordsStatus = () => { if (!WORDS) return Promise.resolve(null); return WORDS.status().then((r) => { SEC.st = r; S.update(); return r; }, () => null); };
  const pwField = (label) => h('input', { type: 'password', autocomplete: label === 'New password' || label === 'Repeat it' ? 'new-password' : 'current-password', autocapitalize: 'none', spellcheck: 'false', 'aria-label': label });
  const head = (title) => h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, title));
  /** fn once at a time (V.busy: its button drawn off), the error in V.say (a wrong password: after the gate's delay). */
  const run = (V, fn) => async () => { if (V.busy) return; V.busy = true; V.say = null; S.update(); try { await fn(); } catch (e) { V.say = e; } finally { V.busy = false; S.update(); } };
  /** Me's line to Security, where this phone holds its own words' identity. */
  function securityEntry() {
    if (!WORDS) return null;
    if (SEC.st === null) { SEC.st = false; void wordsStatus(); }
    if (!SEC.st?.here) return null;
    return [h('h2', null, 'Security'), h('p', { class: 'muted' }, SEC.st.kept ? 'Your 25 words are kept on this phone behind your password.' : 'Your 25 words are on your paper only.'),
      h('div', { class: 'bar' }, h('button', { onclick: () => show('security') }, 'Security'))];
  }
  function viewSecurity() {
    const body = h('div'), V = { say: null };
    put(app, head('Security'), body);
    void wordsStatus();
    return () => {
      const st = SEC.st;
      if (!st) { put(body, h('p', { class: 'muted' }, 'Loading…')); return; }
      if (!st.kept) { put(body, h('p', null, 'Your 25 words are not kept on this phone: they are on your paper only.'), h('p', { class: 'muted' }, 'The password was offered once, when this identity was made or restored here.')); return; }
      put(body, errorCard(V.say) ?? '', h('p', null, 'Your 25 words are kept on this phone, encrypted under your password. To see them: this phone\'s lock, then the password.'),
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => show('words-show') }, 'Show my 25 words')),
        h('h2', null, 'Password'), h('p', { class: 'muted' }, 'It also guards removing this profile and taking its seat.'),
        h('div', { class: 'bar' }, h('button', { onclick: () => show('words-change') }, 'Change the password'), h('button', { class: 'danger', onclick: () => show('words-remove') }, 'Remove the password')));
    };
  }
  function viewWordsShow() {
    const body = h('div'), pw = pwField('Password'), V = { say: null, words: null };
    put(app, head('Your 25 words'), body);
    const hide = () => { V.words = null; void LOCAL?.secure?.(false); };
    S.leave = hide;
    const open = run(V, async () => { const r = await WORDS.reveal(pw.value); pw.value = ''; await LOCAL?.secure?.(true); V.words = r.words; });
    return () => {
      if (!V.words) { put(body, errorCard(V.say) ?? '', h('label', null, 'Your words password'), pw, h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: open, disabled: V.busy }, 'Show'))); return; }
      if (body.querySelector?.('ol')) return;   // shown: not drawn again under the poll
      const list = h('ol', { class: 'seed-list nocopy', 'aria-label': 'Your 25 words, in order', oncopy: (e) => e.preventDefault() }, V.words.map((w) => h('li', null, w)));
      put(body, h('p', { class: 'warn' }, 'Whoever sees them owns this identity and its wallet. Nothing is copied.'), list,
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => { hide(); show('security'); } }, 'Done')));
    };
  }
  function viewWordsChange() {
    const body = h('div'), old = pwField('Current password'), next = pwField('New password'), again = pwField('Repeat it'), V = { say: null };
    put(app, head('Change the password'), body);
    const save = run(V, async () => { await WORDS.change(old.value, next.value, again.value); for (const x of [old, next, again]) x.value = ''; await wordsStatus(); show('security'); toast('Password changed.'); });
    return () => put(body, errorCard(V.say) ?? '', h('label', null, 'Current password'), old, h('label', null, 'New password, at least 8 characters'), next, h('label', null, 'Repeat it'), again,
      h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: save, disabled: V.busy }, 'Save')));
  }
  function viewWordsRemove() {
    const body = h('div'), pw = pwField('Password'), V = { say: null };
    put(app, head('Remove the password'), body);
    const go = run(V, async () => { await WORDS.remove(pw.value); pw.value = ''; await wordsStatus(); show('security'); toast('The words kept here are deleted.'); });
    return () => put(body, errorCard(V.say) ?? '', h('p', { class: 'warn' }, 'The words kept on this phone are deleted. Your paper is then the only copy.'),
      h('label', null, 'Your words password'), pw, h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: go, disabled: V.busy }, 'Remove the password')));
  }
  /** The app's seat taken here (seat banner) when the words password guards it. */
  function viewSeatTake() {
    const body = h('div'), pw = pwField('Password'), V = { say: null };
    put(app, head('Take the seat here'), body);
    const go = run(V, async () => { await backend.call('POST', '/api/seat/take', { confirm: true, password: pw.value }); pw.value = ''; show(S.home); });
    return () => put(body, errorCard(V.say) ?? '', h('p', { class: 'warn' }, 'Only if that other device is stopped or lost: two devices logging in as you lose each other\'s messages.'),
      h('label', null, 'Your words password'), pw, h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: go, disabled: V.busy }, 'Take the seat here')));
  }
  const WORDS_VIEWS = { security: viewSecurity, 'words-show': viewWordsShow, 'words-change': viewWordsChange, 'words-remove': viewWordsRemove, 'seat-take': viewSeatTake };
  if (WORDS) Promise.resolve().then(() => { void wordsStatus(); });   // the seat banner reads it

  // ---- COMPUTERS (design/profiles.md P2): a remote profile's computers, each paired once, the one in use marked. Where
  // the shell has them: the WebView app's (LOCAL.computers, apps/web/boot.mjs) or the GTK phone app's (its bridge,
  // apps/gtk); a profile holding an identity answers not_remote and Me shows nothing. Me → Connect → Computers:
  // switch (the lock, then that computer's page), add (the pairing screens: a code or a scan), forget (its control key
  // gone from this phone; the computer keeps the control until it is revoked there).
  const COMPUTERS = LOCAL?.computers ?? (PROFILE_SHELL ? shellComputers(PROFILE_SHELL) : null);
  const REVOKE_CONTROL = 'sigelo-agent ui --revoke-control <name>';
  function shellComputers(wk) {
    const ask = async (op, o = {}) => {
      const r = await wk.postMessage({ op, ...o });
      if (!r?.ok) throw Object.assign(new Error(r?.message ?? `${op}: no answer`), { check: r?.check });
      return r;
    };
    return { list: () => ask('computers'), use: (id) => ask('computer-use', { id }), add: () => ask('computer-add'), forget: (id) => ask('computer-forget', { id }) };
  }
  const computerSub = (c) => [c.words, c.via === 'relay' ? `over the relay${c.where ? ` ${c.where}` : ''}` : `on the LAN${c.where ? ` ${c.where}` : ''}`,
    c.last_used ? `used ${ago(c.last_used)}` : null].filter(Boolean).join(' · ');
  /** Me's Connect section, where this profile drives computers (asked once a page). */
  function computersEntry() {
    if (!COMPUTERS) return null;
    if (S.computersHere === undefined) {
      S.computersHere = null;
      COMPUTERS.list().then((r) => { S.computersHere = r.computers.length; S.update(); }, () => { S.computersHere = false; });
    }
    if (S.computersHere === null || S.computersHere === false) return null;
    return [h('h2', null, 'Connect'), h('p', { class: 'muted' }, `This phone drives ${S.computersHere === 1 ? 'one computer' : `${S.computersHere} computers`} of this profile, one at a time.`),
      h('div', { class: 'bar' }, h('button', { onclick: () => show('computers') }, 'Computers'))];
  }
  function viewComputers() {
    const C = { r: null, say: null, done: null };
    const body = h('div');
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: back }, '‹'), h('h1', null, 'Computers')), body);
    const load = () => COMPUTERS.list().then((r) => { C.r = r; S.computersHere = r.computers.length; S.update(); }, (e) => { C.say = e; S.update(); });
    const run = async (fn, after) => { C.say = null; C.done = null; try { const r = await fn(); if (!r?.reload) { after?.(r); await load(); } } catch (e) { C.say = e; S.update(); } };
    load();
    const forget = (c) => {
      if (!confirm(`Forget ${c.name}? This phone drops its control key for it. The computer keeps the control until you revoke it there: ${REVOKE_CONTROL}`)) return;
      run(() => COMPUTERS.forget(c.id), (r) => { C.done = `${c.name} forgotten on this phone. Revoke it on the computer too: ${r?.revoke ?? REVOKE_CONTROL}`; });
    };
    return () => {
      if (!C.r) { put(body, errorCard(C.say) ?? h('p', { class: 'muted' }, 'Loading…')); return; }
      const { active, limit, computers } = C.r;
      const rows = computers.map((c) => h('div', { class: `card${c.id === active ? ' current' : ''}`, 'data-computer': c.id },
        h('div', { class: 'name' }, c.name, c.id === active ? ' ' : '', c.id === active ? badge('in use', 'ok') : null),
        h('div', { class: 'sub' }, computerSub(c)),
        c.paired ? h('div', { class: 'sub' }, `paired ${when(c.paired)}`) : null,
        h('div', { class: 'bar' },
          c.id === active ? null : h('button', { class: 'primary', onclick: () => run(() => COMPUTERS.use(c.id)) }, 'Switch'),
          h('button', { class: 'danger', onclick: () => forget(c) }, 'Forget'))));
      put(body, errorCard(C.say) ?? '', C.done ? h('div', { class: 'card warn' }, C.done) : null,
        rows.length ? rows : h('p', { class: 'muted' }, 'No computer yet.'),
        h('div', { class: 'bar' }, h('button', { disabled: computers.length >= limit, onclick: () => run(() => COMPUTERS.add()) }, 'Add a computer')),
        h('p', { class: 'muted' }, computers.length >= limit ? `At most ${limit} computers: forget one to add another.`
          : 'Each computer is paired once, by its code or QR. All of them serve this profile\'s identity: another one\'s computer goes in a profile of its own.'));
    };
  }

  // ---- routing and polling
  const VIEWS = { add: viewAdd, agents: viewAgents, agent: viewAgent, enrol: viewEnrol, contacts: viewContacts, pair: viewPair, chat: viewChat, me: viewMe, links: viewLinks, devices: viewDevices,
    profiles: viewProfiles, 'profile-remove': viewProfileRemove, groups: viewGroups, 'group-new': viewGroupNew, group: viewGroup, 'group-info': viewGroupInfo, transfers: viewTransfers };
  VIEWS.computers = viewComputers;
  const HOMES = new Set(['agents', 'contacts', 'groups']);
  // Screens that show or spend the identity: the Android app asks the screen lock first (local.unlock;
  // not again within a minute of the last). Not confirmed: the screen stays, the refusal said.
  const GUARDED = new Set(['enrol', 'add', 'pair', 'me', 'devices', 'profiles']);
  for (const [k, f] of Object.entries(WORDS_VIEWS)) { VIEWS[k] = f; GUARDED.add(k); }   // Security: the lock first
  function show(view, arg, popped = false) {
    if (GUARDED.has(view) && view !== S.view && typeof LOCAL?.unlock === 'function') {
      LOCAL.unlock().then(() => openView(view, arg, popped), (e) => { if (popped) openView(S.home, undefined, true); S.note = e; S.update(); });
      return;
    }
    openView(view, arg, popped);
  }
  function openView(view, arg, popped) {
    S.tab = null;
    // A screen off a home list gets its own history entry (Back returns to the list); a home list none.
    if (!popped && !HOMES.has(view) && view !== S.view) globalThis.history?.pushState?.({ sigeloView: view, ...(arg !== undefined && typeof arg !== 'object' && { arg }) }, '');
    S.leave?.(); S.leave = null;   // a screen that showed the words hides them (viewWordsShow)
    S.view = view; S.note = null;
    S.update = VIEWS[view](arg);
    window.scrollTo(0, 0);
    S.update();
  }
  let polling = false;
  async function poll() {
    if (polling) return;
    polling = true;
    const was = S.fatal;
    try { S.snap = await backend.call('GET', `/api/state?since=${S.snap?.seq ?? 0}`); S.fatal = null; } catch (e) { S.fatal = e; }
    // The computer's page only (http): pending relay controls; a page that has none of it (404, 403) stops asking.
    if (backend === http && !S.fatal && S.controls !== false) { try { S.controls = (await backend.call('GET', '/api/controls')).pending; } catch (e) { if (e.status === 404 || e.status === 403) S.controls = false; } }
    polling = false;
    // A refusal with a reason (the four words not confirmed on the computer yet, say) is said as it is, and
    // the screen comes back once it passes; a bare 403 is a page opened without its key.
    if (S.fatal?.status === 403) { put(app, h('p', { class: 'card err' }, SHELL || LOCAL || S.fatal.check ? S.fatal.message : 'This page has no key: open the link sigelo-agent ui printed.')); return; }
    if (was?.status === 403) { show(S.view, undefined, true); return; }
    try { await S.update(); } catch {}
    tabCount();
  }
  // Back lands on the entry before: a screen with a plain argument (a contact, an agent) comes back as it was; a
  // code screen is not made twice (a second code), so Back past it lands on the screen before, or the home list.
  globalThis.addEventListener?.('popstate', (ev) => {
    const st = ev?.state ?? globalThis.history?.state, v = st?.sigeloView;
    if (v === 'pair' || v === 'enrol') { globalThis.history?.back?.(); return; }
    if (v && VIEWS[v] && !HOMES.has(v)) show(v, st.arg, true);
    else if (!HOMES.has(S.view)) show(S.home, undefined, true);
  });
  setInterval(() => { for (const el of document.querySelectorAll('.countdown')) el.textContent = left(Number(el.dataset.exp)); }, 1000);
  // Installable on this machine (manifest.webmanifest, sw.js: the three files, never /api/).
  if (backend === http && 'serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  if (!TOKEN && !SHELL && !LOCAL) { put(app, h('p', { class: 'card err' }, 'This page has no key: open the link sigelo-agent ui printed.')); return; }
  show('agents');
  poll();
  setInterval(poll, 2000);
  // local: what changes the state is pushed; the poll still reads it with the same `since`.
  let pushed = null;
  LOCAL?.onChange?.(() => { if (pushed === null) pushed = setTimeout(() => { pushed = null; poll(); }, 50); });
})();
