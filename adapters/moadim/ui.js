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
  /** el's children replaced: lists flattened, strings as escaped text, empties dropped. */
  const put = (el, ...kids) => el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false && k !== '')
    .map((k) => (k instanceof Node ? k : document.createTextNode(safeText(k)))));
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
  const S = { snap: null, view: 'contacts', update: () => {}, contact: null, pair: null, msgsSeq: -1, me: null, agents: null, note: null, fatal: null, links: null, introSeen: new Set() };
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
  const allContacts = () => (S.snap ? [...S.snap.groups.mine, ...S.snap.groups.contacts] : []);
  const contactBy = (did) => allContacts().find((c) => c.did === did) ?? null;

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); const was = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = was; }, 1500); } catch { window.prompt('Copy this:', text); }
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
      : mode.kind === 'full' ? 'This phone holds: FULL, standby' : `This phone holds: SAFE worker${Number.isInteger(mode.worker) ? ` ${mode.worker}` : ''}`;
    const box = h('div', null, banner ? h('div', { class: 'status mode' }, banner) : null, h('div', { class: 'status' }, parts));
    if (me.pow) box.append(powBar(me.pow));
    const seat = seatBanner();
    if (seat) box.append(seat);
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
    if (c.mine) badges.push(badge(`run by me · ${c.mine.days_left} d`, c.mine.days_left < 14 ? 'alert' : ''));
    if (c.ours && c.tier !== 'own') badges.push(badge('mine · low trust'));
    for (const t of c.tags) badges.push(badge('#' + t));
    if (c.status === 'pair_again') badges.push(badge('Pair again', 'alert'));
    else if (c.status === 'waiting') badges.push(badge('waiting for their side'));
    else if (c.status === 'not_collected') badges.push(badge('not collected yet', 'alert'));
    if (c.words_checked) badges.push(badge('✓ words', 'ok'));
    else if (c.words) badges.push(badge('check words', 'alert'));
    if (c.link) badges.push(badge(`linked: ${c.link.purpose}`));
    const sub = c.tier === 'quiet' ? '' : c.tier === 'friend' ? (unread ? `new message${unread === 1 ? '' : 's'}` : '')
      : c.last ? `${c.last.dir === 'out' ? 'me: ' : ''}${c.last.text}` : 'no messages yet';
    return h('button', { class: 'row', onclick: () => show('chat', c.did) },
      h('span', { class: 'mark' }, mark),
      h('span', { class: 'main' }, h('div', { class: 'name' }, c.name), sub ? h('div', { class: 'sub' }, sub) : null, h('div', null, badges)),
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
    const top = h('div'), list = h('div');
    put(app,
      h('header', null, h('h1', null, 'Contacts'), h('button', { onclick: () => show('links') }, 'Links'), SHELL || LOCAL ? null : h('button', { onclick: () => show('devices') }, 'Devices'), h('button', { onclick: () => show('me') }, 'Me'), h('button', { class: 'primary', 'aria-label': 'Invite', onclick: () => invite() }, '+')),
      top, list,
      h('div', { class: 'foot' }, h('div', { class: 'inner' }, h('button', { class: 'primary', onclick: () => invite() }, 'Invite'), h('button', { onclick: () => show('pair', { mode: 'enter' }) }, 'Enter a code'))));
    return () => {
      put(top, statusLine(), introBanner() ?? '', noteCard());
      if (!S.snap) return;
      const { mine, contacts } = S.snap.groups, pending = pendingRows(S.snap.pending);
      put(list,
        h('h2', null, `Mine (${mine.length})`), mine.length ? mine.map(contactRow) : h('p', { class: 'muted' }, 'Your own agents (yours by key, or tier own): Me → Agents on this machine.'),
        h('h2', null, `Contacts (${contacts.length})`), contacts.length ? contacts.map(contactRow) : h('p', { class: 'muted' }, 'Nobody yet: Invite, or Enter a code.'),
        pending.length ? [h('h2', null, 'Pending'), pending] : null);
    };
  }

  // ---- PAIR
  async function invite(o = {}) {
    show('pair', { mode: 'invite', busy: true });
    try { const r = await backend.call('POST', '/api/invite', o); S.pair = { mode: 'invite', id: r.id, inv: r }; } catch (e) { S.pair = { mode: 'invite', error: e }; }
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
      try { S.pair.result = await backend.call('POST', '/api/accept', { code, name: nameIn.value.trim(), ...(tier === 'quiet' && { tier }) }); } catch (e) { S.pair.error = e; }
      S.pair.busy = false;
      await poll();
    };
    if (S.pair.mode === 'enter') {
      input = h('input', { autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', placeholder: 'K7F3-Q9ZP, or a long code sgl1…', 'aria-label': 'Their code' });
      nameIn = h('input', { autocomplete: 'off', placeholder: 'optional', 'aria-label': 'Their name' });
      // Friend or quiet; own (my agents) is detected, never asked: friend, the default, is sent as no choice.
      const pick = (t, label) => h('button', { type: 'button', 'aria-pressed': String(t === tier), class: t === tier ? 'primary' : '', onclick: () => { tier = t; put(tierPick, picks()); } }, label);
      const picks = () => [pick('friend', 'Friend: tell me'), pick('quiet', 'Quiet: when I look')];
      tierPick = h('div', { class: 'bar', role: 'group', 'aria-label': 'Their messages' }, picks());
    }
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: () => show('contacts') }, '‹'), h('h1', null, S.pair.mode === 'enter' ? 'Enter a code' : 'Invite')),
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
            out.push(h('div', { class: 'card' }, h('div', { class: 'muted' }, 'Your code'), h('div', { class: 'code' }, inv.short),
              live ? h('div', null, countdown(inv.short_exp), ' left · Say it, text it. Once.') : h('div', { class: 'warn' }, 'Code expired. The long code still works until ', when(inv.exp), '.')));
          } else out.push(h('div', { class: 'card' }, h('div', { class: 'muted' }, 'Your long code, once, until ', when(inv.exp)), h('div', { class: 'long' }, inv.code)));
          const cp = h('button', { onclick: () => copy(inv.code, cp) }, 'Copy long code');
          out.push(h('div', { class: 'bar' }, cp, inv.short && !live ? h('button', { class: 'primary', onclick: () => invite() }, 'New code') : null,
            h('button', { onclick: () => act(() => backend.call('POST', '/api/invite/cancel', { id: inv.id }), () => show('contacts')) }, 'Cancel')));
          out.push(h('ul', { class: 'steps' }, h('li', null, inv.short ? `✓ code parked at your relay (${safeText(inv.relay)})` : '✓ long code made'), h('li', null, '… waiting for them to enter it')),
            h('p', { class: 'muted' }, 'Their agent must use the same relay for the short code; else send them the long code.'));
        } else if (inv) out.push(h('p', { class: 'muted' }, 'This code is no longer pending.'), h('button', { class: 'primary', onclick: () => invite() }, 'New code'));
        else if (P.id) {
          const p2 = S.snap?.pending.invites.find((x) => x.id === P.id);
          if (p2) { P.inv = { id: p2.id, short: p2.short, short_exp: p2.short_exp, code: p2.code, exp: p2.exp, relay: p2.relay }; setTimeout(() => S.update()); }
        }
      }
      if (P.mode === 'enter' && !P.busy) {
        const r = P.result, e = P.error;
        if (r?.status === 'connected') out.push(h('p', { class: 'good' }, `✓ Paired with ${safeText(r.contact.name)}`), wordsBlock(contactBy(r.contact.did) ?? { ...r.contact, words: r.contact.fingerprint }));
        else if (r?.status === 'waiting') out.push(h('div', { class: 'card' }, 'Your answer is at the relay. Waiting for their side to come online once', r.exp ? [', until ', when(r.exp)] : '', '.'));
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
  function viewChat(did) {
    S.contact = did; S.msgsSeq = -1;
    const title = h('h1'), tags = h('div'), alerts = h('div'), list = h('div'), panel = h('div');
    panel.hidden = true;
    const text = h('textarea', { rows: 1, placeholder: 'type a message', 'aria-label': 'Message' });
    const send = async () => {
      const t = text.value;
      if (!t.trim()) return;
      sendBtn.disabled = true;
      await act(() => backend.call('POST', '/api/send', { to: did, text: t }), () => { text.value = ''; S.msgsSeq = -1; });
      sendBtn.disabled = false;
    };
    text.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send(); } });
    const sendBtn = h('button', { class: 'primary', onclick: send }, 'Send');
    // Files (sigelo-file/0) are another branch's: the seam only.
    const attach = h('button', { disabled: true, title: 'coming', 'aria-label': 'Attach a file (coming)' }, '📎');
    const rename = h('input', { autocomplete: 'off', 'aria-label': 'Name' }), tagIn = h('input', { autocomplete: 'off', placeholder: '#work #family', 'aria-label': 'Tags' });
    let panelFor = null;
    put(app,
      h('header', null, h('button', { 'aria-label': 'Back', onclick: () => show('contacts') }, '‹'), title, h('button', { 'aria-label': 'More', onclick: () => { panel.hidden = !panel.hidden; S.update(); } }, '⋯')),
      tags, panel, alerts, list,
      h('div', { class: 'foot' }, h('div', { class: 'inner' }, attach, text, sendBtn)));
    return async () => {
      const c = contactBy(did);
      if (!c) { title.textContent = 'Gone'; put(alerts, h('p', { class: 'muted' }, 'Not a contact (forgotten).')); return; }
      title.textContent = safeText(c.name);
      put(tags, tierChip(c.tier), ...c.tags.map((t) => badge('#' + t)), c.local ? badge('on this machine') : '', c.mine ? badge(`run by me · ${c.mine.days_left} d`) : '', c.words_checked ? badge('✓ words', 'ok') : '', c.link ? badge(`linked: ${c.link.purpose}`) : '');
      if (panelFor !== did + c.name + c.tags.join()) { panelFor = did + c.name + c.tags.join(); rename.value = c.name; tagIn.value = c.tags.map((t) => '#' + t).join(' '); }
      if (!panel.hidden) {
        put(panel, h('div', { class: 'card' },
          h('label', null, 'Name'), rename, h('div', { class: 'bar' }, h('button', { onclick: () => act(() => backend.call('POST', '/api/rename', { contact: did, name: rename.value })) }, 'Rename')),
          h('label', null, 'Their messages'),
          h('div', { class: 'bar', role: 'group', 'aria-label': 'Tier' }, ['own', 'friend', 'quiet'].map((t) => h('button', { 'aria-pressed': String(c.tier === t), class: c.tier === t ? 'primary' : '',
            title: TIER_SAYS[t], onclick: () => act(() => backend.call('POST', '/api/tier', { contact: did, tier: t })) }, t))),
          h('p', { class: 'muted' }, TIER_SAYS[c.tier] ?? ''),
          h('label', null, 'Tags (up to 20 characters each)'), tagIn,
          h('div', { class: 'bar' }, h('button', { onclick: () => act(() => backend.call('POST', '/api/tag', { contact: did, tags: tagIn.value.split(/[\s,]+/).map((t) => t.replace(/^#/, '')).filter(Boolean) })) }, 'Save tags')),
          h('p', { class: 'did' }, c.did),
          h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: () => { if (confirm(`Forget and block ${safeText(c.name)}? This is permanent: they can never pair with you again.`)) act(() => backend.call('POST', '/api/forget', { contact: did }), () => show('contacts')); } }, 'Forget and block'))));
      }
      const al = [errorCard(S.note)];
      if (c.status === 'pair_again') al.push(h('div', { class: 'card' }, h('p', { class: 'warn' }, c.re_pair === 'own_recovery' ? 'You recovered your identity: pair again.' : 'They recovered their identity: pair again.'), h('button', { class: 'primary', onclick: () => invite({ name: c.name }) }, 'Pair again')));
      else if (c.status === 'waiting') al.push(h('div', { class: 'card' }, 'Waiting for their side: messages go once their keys come.'));
      if (c.not_collected) al.push(h('div', { class: 'card' }, h('p', null, 'Not collected yet: their side has not been online since.'), h('button', { onclick: () => act(() => backend.call('POST', '/api/sync')) }, 'Retry now')));
      if (!c.words_checked && c.words) al.push(wordsBlock(c));
      put(alerts, ...al.filter(Boolean));
      if (S.snap.seq !== S.msgsSeq) {
        S.msgsSeq = S.snap.seq;
        const r = await backend.call('GET', `/api/messages?contact=${encodeURIComponent(did)}`).catch(() => null);
        if (!r) return;
        const atEnd = window.innerHeight + window.scrollY >= document.body.scrollHeight - 80;
        put(list, ...(r.messages.length ? r.messages.map((m) => {
          const st = m.dir !== 'out' ? '' : m.status === 'queued' ? (m.code === 'no_reader' ? ' (not collected yet)' : ' (queued)') : m.status === 'refused' ? ` (refused: ${m.code})` : m.status === 'sent' ? ' ✓' : '';
          return h('div', { class: `msg ${m.dir}` }, h('div', { class: 'who' }, m.dir === 'out' ? 'me' : 'them', ' · ', when(m.at), st),
            m.label ? badge(m.label === 'sigelo-file/0' ? '📎 file (coming)' : m.label) : null, h('div', { class: 'text' }, m.text));
        }) : [h('p', { class: 'muted' }, 'No messages yet.')]));
        if (atEnd) window.scrollTo(0, document.body.scrollHeight);
      }
    };
  }

  // ---- LINKS (LINKS.md): introduce two contacts, one of them yours; the links made; introductions to answer
  const DAYS = [['', 'no end'], ['1', '1 day'], ['7', '7 days'], ['30', '30 days'], ['90', '90 days']];
  // A new introduction (its introducer not quiet here): a banner until opened or put off.
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
    let names = '';
    const pick = () => [contactBy(aSel.value), contactBy(bSel.value)];
    // External (one of them not yours): a note, their tier is theirs to choose; own: both tiers.
    const shape = () => {
      const [a, b] = pick(), external = a && b && a.ours !== b.ours, none = a && b && !a.ours && !b.ours;
      put(extra, none ? h('p', { class: 'warn' }, 'One of the two must be yours (run by you).') : null,
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
        ...(tierA.value && { tier_a: tierA.value }), ...(!external && tierB.value && { tier_b: tierB.value }), ...(external && note.value.trim() && { note: note.value.trim() }) }),
      (r) => { purpose.value = ''; note.value = ''; put(result, h('div', { class: 'card' }, `Link ${r.id}: asked ${safeText(r.a_name)} for a one-use code for ${safeText(r.b_name)}. It shows below as it goes.`)); });
    };
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: () => show('contacts') }, '‹'), h('h1', null, 'Links')), top, intro,
      h('h2', null, 'Link two contacts'),
      h('div', null, h('label', null, 'First'), aSel, h('label', null, 'Second'), bSel, h('label', null, 'What for (up to 120 characters)'), purpose, h('label', null, 'Ends'), days, extra,
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: go }, 'Link'))), result,
      h('h2', null, 'Links you made'), made, h('h2', null, 'Linked with you'), mine, h('h2', null, 'Introductions accepted by themselves'), rules);
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
    if (seat && !seat.here) return h('div', { class: 'card warn' }, `The seat is with ${seat.holder}: this page no longer logs in as you. Here: sigelo-agent device seat take.`);
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
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: () => { scan.stop(); clearInterval(D.timer); show('contacts'); } }, '‹'), h('h1', null, 'Devices')), top,
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
        h('div', null, badge(d.rank.toUpperCase(), d.rank === 'full' ? 'alert' : ''), d.revoked ? badge(`revoked ${when(d.revoked)}`, 'alert') : badge(d.paired ? 'paired' : 'not paired yet', d.paired ? 'ok' : ''), d.tier ? tierChip(d.tier) : null),
        h('div', { class: 'did' }, d.did)),
        d.revoked ? null : h('button', { onclick: () => { if (confirm(`Revoke ${d.name}? It is told to delete its keys, and forgotten here when it answers.`)) act(() => backend.call('POST', '/api/devices/revoke', { name: d.name })); } }, 'Revoke'),
        h('button', { class: 'danger', onclick: () => { if (confirm(`${d.name} lost or stolen? It is revoked and forgotten now${d.rank === 'full' ? '; it held your identity: the steps with your 25 words follow' : ''}.`)) act(() => backend.call('POST', '/api/devices/revoke', { name: d.name, lost: true }), (r) => { if (r.steps) S.note = { message: [...r.steps.now.map((x) => `Done: ${x}`), 'With your 25 words:', ...r.steps.words.map((x, i) => `${i + 1}. ${x}`)].join('\n') }; }); } }, 'Lost')))
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
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: () => show('contacts') }, '‹'), h('h1', null, 'Me')), body);
    backend.call('GET', '/api/me').then((m) => { S.me = m; S.update(); }).catch((e) => { S.note = e; });
    // The relay setting (UI-API.md Settings): kept out of the redraw so typing survives the poll.
    const R = { s: null, list: null, say: '' };
    const relayIn = h('input', { autocomplete: 'off', spellcheck: false, maxlength: '255', 'aria-label': 'Relay' });
    const saveRelay = async (v) => {
      try { R.s = await backend.call('POST', '/api/settings', { relay: v }); relayIn.value = R.s.relay; R.say = 'Saved.'; } catch (e) { R.say = e.message; }
      S.update();
    };
    const pickList = async () => {
      R.say = 'Reading the public registry…'; S.update();
      try { R.list = (await backend.call('GET', '/api/relays')).relays; R.say = R.list.length ? '' : 'The registry lists no relays, or could not be read.'; } catch (e) { R.say = e.message; }
      S.update();
    };
    backend.call('GET', '/api/settings').then((x) => { R.s = x; relayIn.value = x.relay; S.update(); }).catch(() => { R.s = false; });
    const relayBlock = () => {
      if (!R.s) return null;
      const now = R.s.fixed ?? R.s.relay;
      return [h('h2', null, 'Relay for new codes'), h('div', { class: 'card' },
        h('p', null, `New codes use ${now}`),
        R.s.fixed ? h('p', { class: 'muted' }, `SIGELO_RELAY on this computer sets ${R.s.fixed}: it wins over the setting below.`) : null,
        h('label', null, 'Relay'), relayIn,
        h('div', { class: 'bar' }, h('button', { class: 'primary', onclick: () => saveRelay(relayIn.value.trim()) }, 'Save'),
          h('button', { onclick: () => saveRelay('') }, `Back to ${R.s.default}`), h('button', { onclick: pickList }, 'Use the public registry')),
        R.list ? R.list.map((x) => h('div', { class: 'row' }, h('span', { class: 'main' }, h('div', { class: 'name' }, x.host), h('div', { class: 'sub' }, [x.tier, x.note].filter(Boolean).join(' · '))),
          h('button', { onclick: () => saveRelay(x.host) }, 'Use'))) : null,
        R.say ? h('p', { class: 'muted' }, R.say) : null,
        h('p', { class: 'muted' }, 'A 12-character code always names its own relay, whatever this says. Your own connection moves at the next start.'))];
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
        h('p', null, m.key === 'browser' ? 'Key: in this app\'s storage, sealed under a key it cannot export' : 'Key: file (keychain: not yet)'),
        h('p', null, `Relay: ${m.relay} · keeps messages ${m.retention_days} days`),
        relayBlock(),
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

  // ---- routing and polling
  const VIEWS = { contacts: viewContacts, pair: viewPair, chat: viewChat, me: viewMe, links: viewLinks, devices: viewDevices };
  function show(view, arg) {
    S.view = view; S.note = null;
    S.update = VIEWS[view](arg);
    window.scrollTo(0, 0);
    S.update();
  }
  let polling = false;
  async function poll() {
    if (polling) return;
    polling = true;
    try { S.snap = await backend.call('GET', `/api/state?since=${S.snap?.seq ?? 0}`); S.fatal = null; } catch (e) { S.fatal = e; }
    polling = false;
    if (S.fatal?.status === 403) { put(app, h('p', { class: 'card err' }, SHELL || LOCAL ? S.fatal.message : 'This page has no key: open the link sigelo-agent ui printed.')); return; }
    try { await S.update(); } catch {}
  }
  setInterval(() => { for (const el of document.querySelectorAll('.countdown')) el.textContent = left(Number(el.dataset.exp)); }, 1000);
  // Installable on this machine (manifest.webmanifest, sw.js: the three files, never /api/).
  if (backend === http && 'serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
  if (!TOKEN && !SHELL && !LOCAL) { put(app, h('p', { class: 'card err' }, 'This page has no key: open the link sigelo-agent ui printed.')); return; }
  show('contacts');
  poll();
  setInterval(poll, 2000);
  // local: what changes the state is pushed; the poll still reads it with the same `since`.
  let pushed = null;
  LOCAL?.onChange?.(() => { if (pushed === null) pushed = setTimeout(() => { pushed = null; poll(); }, 50); });
})();
