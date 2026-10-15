// SPDX-License-Identifier: MIT
// The page of `sigelo-agent ui` (sigelo-agent-ui.ts; API: UI-API.md). Vanilla JS, no framework.
// Every string from a contact, a relay or a file goes in by textContent, its controls and bidi
// overrides escaped (safeText), never as HTML. The token comes in the fragment and goes back as
// X-Sigelo-Token; no cookie, no storage but this tab's sessionStorage (it survives a reload).
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

  async function api(method, path, body) {
    const r = await fetch(path, {
      method, credentials: 'omit', cache: 'no-store',
      headers: { 'X-Sigelo-Token': TOKEN ?? '', ...(method === 'POST' && { 'Content-Type': 'application/json' }) },
      ...(method === 'POST' && { body: JSON.stringify(body ?? {}) }),
    });
    let data = null;
    try { data = await r.json(); } catch {}
    if (!r.ok) throw Object.assign(new Error(data?.error?.message ?? `HTTP ${r.status}`), { check: data?.error?.check, long: data?.error?.long, status: r.status });
    return data;
  }

  // ---- state
  const S = { snap: null, view: 'contacts', update: () => {}, contact: null, pair: null, msgsSeq: -1, me: null, agents: null, note: null, fatal: null };
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

  // ---- the header line: relay, clock, the one-time proof of work (§3)
  function statusLine() {
    const me = S.snap?.me;
    if (!me) return h('div', { class: 'status' }, 'connecting…');
    const off = me.clock_offset, parts = [h('span', null, me.relay), h('span', { class: me.online ? 'good' : 'muted' }, me.online ? 'online' : 'not connected')];
    if (off === null) parts.push(h('span', { class: 'muted' }, 'clock not checked'));
    else if (Math.abs(off) > 60) parts.push(h('span', { class: 'warn' }, `Your clock is ${Math.abs(off)} s ${off < 0 ? 'ahead of' : 'behind'} the relay's: set it right, or codes fail`));
    else parts.push(h('span', { class: 'good' }, 'clock ok'));
    const box = h('div', null, h('div', { class: 'status' }, parts));
    if (me.pow) box.append(powBar(me.pow));
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
    for (const t of c.tags) badges.push(badge('#' + t));
    if (c.status === 'pair_again') badges.push(badge('Pair again', 'alert'));
    else if (c.status === 'waiting') badges.push(badge('waiting for their side'));
    else if (c.status === 'not_collected') badges.push(badge('not collected yet', 'alert'));
    if (c.words_checked) badges.push(badge('✓ words', 'ok'));
    else if (c.words) badges.push(badge('check words', 'alert'));
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
      h('header', null, h('h1', null, 'Contacts'), h('button', { onclick: () => show('me') }, 'Me'), h('button', { class: 'primary', 'aria-label': 'Invite', onclick: () => invite() }, '+')),
      top, list,
      h('div', { class: 'foot' }, h('div', { class: 'inner' }, h('button', { class: 'primary', onclick: () => invite() }, 'Invite'), h('button', { onclick: () => show('pair', { mode: 'enter' }) }, 'Enter a code'))));
    return () => {
      put(top, statusLine(), errorCard(S.note) ?? '');
      if (!S.snap) return;
      const { mine, contacts } = S.snap.groups, pending = pendingRows(S.snap.pending);
      put(list,
        h('h2', null, `Mine (${mine.length})`), mine.length ? mine.map(contactRow) : h('p', { class: 'muted' }, 'Your own agents (tier own): Me → Agents on this machine.'),
        h('h2', null, `Contacts (${contacts.length})`), contacts.length ? contacts.map(contactRow) : h('p', { class: 'muted' }, 'Nobody yet: Invite, or Enter a code.'),
        pending.length ? [h('h2', null, 'Pending'), pending] : null);
    };
  }

  // ---- PAIR
  async function invite(o = {}) {
    show('pair', { mode: 'invite', busy: true });
    try { const r = await api('POST', '/api/invite', o); S.pair = { mode: 'invite', id: r.id, inv: r }; } catch (e) { S.pair = { mode: 'invite', error: e }; }
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
        h('button', { class: 'primary', onclick: () => act(() => api('POST', '/api/words', { contact: c.did, match: true })) }, 'They match'),
        h('button', { class: 'danger', onclick: () => { if (confirm(`Forget and block ${safeText(c.name)}? Different words mean someone else may have used the code.`)) act(() => api('POST', '/api/words', { contact: c.did, match: false }), () => show('contacts')); } }, "They don't")),
      h('details', null, h('summary', null, 'more'), h('p', { class: 'did' }, `pair id ${c.pair ?? ''}`), h('p', { class: 'muted' }, 'The same 32 digits on both sides is the strong check.')));
  }
  function viewPair(arg) {
    S.pair = arg?.busy ? { mode: 'invite', busy: true } : { mode: arg?.mode ?? 'enter', id: arg?.id ?? null, inv: null, result: null, error: null };
    const body = h('div');
    let input = null, nameIn = null, tierPick = null, tier = 'friend';
    const enter = async (code) => {
      S.pair.busy = true; S.pair.error = null; S.pair.result = null; S.update();
      try { S.pair.result = await api('POST', '/api/accept', { code, name: nameIn.value.trim(), ...(tier === 'quiet' && { tier }) }); } catch (e) { S.pair.error = e; }
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
            h('button', { onclick: () => act(() => api('POST', '/api/invite/cancel', { id: inv.id }), () => show('contacts')) }, 'Cancel')));
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
      await act(() => api('POST', '/api/send', { to: did, text: t }), () => { text.value = ''; S.msgsSeq = -1; });
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
      put(tags, tierChip(c.tier), ...c.tags.map((t) => badge('#' + t)), c.local ? badge('on this machine') : '', c.mine ? badge(`run by me · ${c.mine.days_left} d`) : '', c.words_checked ? badge('✓ words', 'ok') : '');
      if (panelFor !== did + c.name + c.tags.join()) { panelFor = did + c.name + c.tags.join(); rename.value = c.name; tagIn.value = c.tags.map((t) => '#' + t).join(' '); }
      if (!panel.hidden) {
        put(panel, h('div', { class: 'card' },
          h('label', null, 'Name'), rename, h('div', { class: 'bar' }, h('button', { onclick: () => act(() => api('POST', '/api/rename', { contact: did, name: rename.value })) }, 'Rename')),
          h('label', null, 'Their messages'),
          h('div', { class: 'bar', role: 'group', 'aria-label': 'Tier' }, ['own', 'friend', 'quiet'].map((t) => h('button', { 'aria-pressed': String(c.tier === t), class: c.tier === t ? 'primary' : '',
            title: TIER_SAYS[t], onclick: () => act(() => api('POST', '/api/tier', { contact: did, tier: t })) }, t))),
          h('p', { class: 'muted' }, TIER_SAYS[c.tier] ?? ''),
          h('label', null, 'Tags (up to 20 characters each)'), tagIn,
          h('div', { class: 'bar' }, h('button', { onclick: () => act(() => api('POST', '/api/tag', { contact: did, tags: tagIn.value.split(/[\s,]+/).map((t) => t.replace(/^#/, '')).filter(Boolean) })) }, 'Save tags')),
          h('p', { class: 'did' }, c.did),
          h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: () => { if (confirm(`Forget and block ${safeText(c.name)}? This is permanent: they can never pair with you again.`)) act(() => api('POST', '/api/forget', { contact: did }), () => show('contacts')); } }, 'Forget and block'))));
      }
      const al = [errorCard(S.note)];
      if (c.status === 'pair_again') al.push(h('div', { class: 'card' }, h('p', { class: 'warn' }, c.re_pair === 'own_recovery' ? 'You recovered your identity: pair again.' : 'They recovered their identity: pair again.'), h('button', { class: 'primary', onclick: () => invite({ name: c.name }) }, 'Pair again')));
      else if (c.status === 'waiting') al.push(h('div', { class: 'card' }, 'Waiting for their side: messages go once their keys come.'));
      if (c.not_collected) al.push(h('div', { class: 'card' }, h('p', null, 'Not collected yet: their side has not been online since.'), h('button', { onclick: () => act(() => api('POST', '/api/sync')) }, 'Retry now')));
      if (!c.words_checked && c.words) al.push(wordsBlock(c));
      put(alerts, ...al.filter(Boolean));
      if (S.snap.seq !== S.msgsSeq) {
        S.msgsSeq = S.snap.seq;
        const r = await api('GET', `/api/messages?contact=${encodeURIComponent(did)}`).catch(() => null);
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

  // ---- ME
  function viewMe() {
    const body = h('div'), how = h('p', { class: 'did' });
    how.hidden = true;
    put(app, h('header', null, h('button', { 'aria-label': 'Back', onclick: () => show('contacts') }, '‹'), h('h1', null, 'Me')), body);
    api('GET', '/api/me').then((m) => { S.me = m; S.update(); }).catch((e) => { S.note = e; });
    return async () => {
      S.agents = await api('GET', '/api/agents').catch(() => S.agents);
      const m = S.me;
      if (!m) return;
      const cp = h('button', { onclick: () => copy(m.did, cp) }, 'Copy');
      how.textContent = m.erase;
      put(body, errorCard(S.note) ?? '',
        h('div', { class: 'card' }, h('div', { class: 'did' }, m.did), h('div', { class: 'bar' }, cp)),
        h('p', null, m.recovery === 'set' ? 'Recovery key: set, offline' : h('span', { class: 'warn' }, 'Recovery key: none. Theft of this key is permanent.')),
        h('p', null, 'Key: file (keychain: not yet)'),
        h('p', null, `Relay: ${m.relay} · keeps messages ${m.retention_days} days`),
        h('h2', null, 'Agents on this machine'),
        (S.agents ?? []).length ? S.agents.map((a) => h('div', { class: 'row' }, h('span', { class: 'main' }, h('div', { class: 'name' }, a.name),
          h('div', { class: 'sub' }, a.error ? a.error : a.mine ? `run by me · ${a.mine.days_left} d left` : 'not mine', a.worker !== null ? ` · worker ${a.worker}` : a.error ? '' : ' · not from your words', a.contact ? ' · paired' : '')),
          a.error ? null : a.worker !== null ? (a.renew ? h('button', { onclick: () => act(() => api('POST', '/api/agents/enrol', { agent: a.name })) }, 'Renew') : null)
            : h('button', { onclick: () => { if (!a.contacts || confirm(`${a.contacts} contact(s) know its old DID and must pair again. Enrol?`)) act(() => api('POST', '/api/agents/enrol', { agent: a.name }), (r) => { if (r.warning) S.note = { message: r.warning }; }); } }, 'Enrol'),
          a.error || a.contact ? null : h('button', { onclick: (ev) => { ev.target.disabled = true; ev.target.textContent = 'Pairing…'; act(() => api('POST', '/api/agents/pair', { agent: a.name })); } }, 'Pair')))
          : h('p', { class: 'muted' }, 'None found.'),
        h('h2', null, 'History'),
        h('div', { class: 'bar' }, h('button', { class: 'danger', onclick: () => { if (confirm('Clear the message history kept on this machine?')) act(() => api('POST', '/api/history/clear')); } }, 'Clear history')),
        h('div', { class: 'bar' }, h('button', { onclick: () => { how.hidden = !how.hidden; } }, 'Delete my relay data: how')), how);
    };
  }

  // ---- routing and polling
  const VIEWS = { contacts: viewContacts, pair: viewPair, chat: viewChat, me: viewMe };
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
    try { S.snap = await api('GET', `/api/state?since=${S.snap?.seq ?? 0}`); S.fatal = null; } catch (e) { S.fatal = e; }
    polling = false;
    if (S.fatal?.status === 403) { put(app, h('p', { class: 'card err' }, 'This page has no key: open the link sigelo-agent ui printed.')); return; }
    try { await S.update(); } catch {}
  }
  setInterval(() => { for (const el of document.querySelectorAll('.countdown')) el.textContent = left(Number(el.dataset.exp)); }, 1000);
  if (!TOKEN) { put(app, h('p', { class: 'card err' }, 'This page has no key: open the link sigelo-agent ui printed.')); return; }
  show('contacts');
  poll();
  setInterval(poll, 2000);
})();
