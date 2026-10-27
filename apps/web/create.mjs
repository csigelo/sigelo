// SPDX-License-Identifier: MIT
// Create a new identity (pass A10a; Monerujo's create and seed review as the model, design/monerujo-ref):
// the first-start screen's first choice. Three screens, one task each:
//   1. the form: a name for this device, the network, the relay; "Create" draws S here (contact/create.mjs
//      newSeed: crypto.getRandomValues, as newRoot) and nothing else;
//   2. the words, once: a numbered 5 × 5 grid, the address of the words' own wallet; no Back (the
//      system's swallowed by the Android shell), no copy on mainnet (stagenet: copied, the clipboard
//      emptied after 60 s), no screenshot (FLAG_SECURE); one way on, "I have written down my 25 words";
//   3. the check: three words asked by number, typed from the paper. Wrong: back to the grid. Right:
//      the files of a restore from those words (operator, K_1, this device FULL holding the seat, created
//      and the wallet's birth today), sealed as seed.mjs seals them, S zeroed, the page restarts.
// Nothing is stored before the check passes: leaving earlier discards the words. They are never shown
// again (no "show seed"): Me says "Created on <day>; the 25 words are on your paper".
//
//   createInto(platform, session, o)   commit a checked session (o: name, relay, now), seal and write,
//                                      the network held → { did, worker, vault }
//   createView(box, platform, o)       the three screens; o: { bridge (Android), back() } → { discard() }
import { DEFAULT_RELAY } from './vendor/contact/carrier.mjs';
import { checkName } from './vendor/contact/device.mjs';
import { checkRelay } from './vendor/contact/invite.mjs';
import { NETS } from './vendor/contact/restore.mjs';
import { newSeed } from './vendor/contact/create.mjs';
import { holdNetwork } from './platform-web.mjs';
import { WORDS_ATTRS, writeOperator } from './seed.mjs';

export const CLIP_SECONDS = 60;
const hostOf = (relay) => String(relay ?? '').trim().toLowerCase() || DEFAULT_RELAY;

/** The checked session's files, sealed and written; S is zeroed by the commit (contact/create.mjs). */
export async function createInto(platform, session, { name, relay, now = Math.floor(Date.now() / 1000) }) {
  const release = holdNetwork();
  try {
    const host = hostOf(relay), r = session.commit({ name, relay: host, now });
    await writeOperator(platform, r, { host, net: session.net, seat: 'here', created: true });
    return { did: r.did, worker: r.worker, vault: r.vault };
  } finally { release(); }
}

const el = (tag, props = {}, ...kids) => {
  const { attrs, style, ...rest } = props, e = Object.assign(document.createElement(tag), rest);
  for (const [k, v] of Object.entries(attrs ?? {})) e.setAttribute(k, v);
  Object.assign(e.style, style ?? {});   // CSSOM, not a style attribute: the CSP allows no inline style
  e.append(...kids);
  return e;
};

/** The three screens (see the header); done → reload (the page starts as the operator, holding the seat). discard(): the words dropped, the screen free. */
export function createView(box, platform, { bridge = null, back = null } = {}) {
  let session = null, release = null, clipTimer = 0;
  const secure = (on) => { try { void bridge?.secure(on, { door: on }).catch(() => {}); } catch {} };
  const guard = () => { history.pushState(null, '', location.href); };   // the page's own Back (a browser tab): stays here
  const door = (on) => {
    secure(on);
    if (on) { guard(); addEventListener('popstate', guard); } else removeEventListener('popstate', guard);
  };
  const discard = () => { session?.discard(); session = null; release?.(); release = null; door(false); };
  const clipClear = () => {
    clearTimeout(clipTimer); clipTimer = 0;
    if (bridge) void bridge.clipClear().catch(() => {}); else void globalThis.navigator?.clipboard?.writeText?.('').catch(() => {});
  };

  // ---- 1. the form
  const name = el('input', { value: 'phone', attrs: { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', maxlength: '20' } });
  const nets = NETS.map((n, i) => el('input', { type: 'radio', name: 'create-net', value: n, checked: i === 0 }));
  const relay = el('input', { value: DEFAULT_RELAY, attrs: { autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' } });
  const say = el('p', { className: 'muted' }), create = el('button', { className: 'primary', textContent: 'Create' });
  create.onclick = () => {
    try { checkName(name.value.trim()); } catch (e) { say.textContent = `Name for this device: ${e.message}`; return; }
    try { checkRelay(hostOf(relay.value)); } catch (e) { say.textContent = `Relay: ${e.message}`; return; }
    create.disabled = true;
    release = holdNetwork();
    session = newSeed(nets.find((x) => x.checked)?.value ?? 'mainnet');
    door(true);
    words();
  };
  box.replaceChildren(el('div', { className: 'card' },
    el('h2', { textContent: 'New identity' }),
    el('p', { textContent: 'This phone makes your identity from 25 new words. The words are the only way back to it, and to its Monero wallet, if this phone is lost. Have paper and a pen ready: they are shown once.' }),
    el('label', { textContent: 'Name for this device' }), name,
    el('div', { className: 'bar' }, ...nets.flatMap((n) => [el('label', {}, n, ` ${n.value}`)])),
    el('p', { className: 'muted', textContent: 'Stagenet is Monero\'s test network: its coins are worth nothing. Pick it to try sigelo out.' }),
    el('label', { textContent: 'Relay for new codes' }), relay,
    el('div', { className: 'bar' }, create, back ? el('button', { textContent: 'Cancel', onclick: () => back() }) : ''), say));
  box.hidden = false;

  // ---- 2. the words, once (again after a wrong check)
  function words(note = '') {
    const list = session.words(), grid = el('ol', { className: 'seed-grid', attrs: { 'aria-label': 'Your 25 words, in order' },
      style: { display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: '0.4em', listStyle: 'none', padding: '0', fontFamily: 'monospace', userSelect: session.net === 'mainnet' ? 'none' : 'text' } },
    ...list.map((w, i) => el('li', {}, el('small', { className: 'muted', textContent: `${i + 1} ` }), w)));
    if (session.net === 'mainnet') grid.addEventListener('copy', (e) => e.preventDefault());
    const copied = el('p', { className: 'muted' });
    const copy = session.net === 'stagenet'
      ? el('button', { textContent: 'Copy the words (stagenet only)', onclick: async () => {
        try {
          if (bridge) await bridge.clipCopy(session.words().join(' '), { clear: CLIP_SECONDS });
          else await navigator.clipboard.writeText(session.words().join(' '));
          clearTimeout(clipTimer); clipTimer = setTimeout(clipClear, CLIP_SECONDS * 1000);
          copied.textContent = `Copied. The clipboard is emptied in ${CLIP_SECONDS} s.`;
        } catch (e) { copied.textContent = `Not copied: ${e.message}`; }
      } })
      : el('p', { className: 'muted', textContent: 'No copy on mainnet: write them by hand.' });
    const done = el('button', { className: 'primary', textContent: 'I have written down my 25 words', onclick: () => check() });
    box.replaceChildren(el('div', { className: 'card' },
      el('h2', { textContent: 'Your 25 words' }),
      note ? el('p', { className: 'warn', textContent: note }) : '',
      el('p', { className: 'warn', textContent: 'Write them on paper, in order, now. Whoever reads them owns this identity and its wallet. This is the only time this app shows them.' }),
      grid,
      el('label', { textContent: 'The address of your words\' own wallet' }),
      el('p', { textContent: session.vault, style: { fontFamily: 'monospace', overflowWrap: 'anywhere' } }),
      el('p', { className: 'muted', textContent: 'A Monero wallet app restored from these 25 words shows this same address: note its first and last characters beside the words, to check your paper later.' }),
      copy, copied,
      el('p', { className: 'muted', textContent: 'Nothing is kept until you have typed three of the words back. Leaving now discards them.' }),
      el('div', { className: 'bar' }, done)));
    box.scrollTop = 0;
  }

  // ---- 3. the check: three words by number, typed from the paper
  function check() {
    clipClear();
    const at = session.quiz(), inputs = at.map(() => el('input', { attrs: { ...WORDS_ATTRS, 'aria-describedby': '' } }));
    const msg = el('p', { className: 'muted' }), go = el('button', { className: 'primary', textContent: 'Check' });
    go.onclick = async () => {
      const r = session.check(inputs.map((x) => x.value));
      for (const x of inputs) x.value = '';
      if (!r.ok) { words(`Word${r.wrong.length > 1 ? 's' : ''} ${r.wrong.join(', ')} did not match. Look at your paper again, then check once more.`); return; }
      go.disabled = true;
      msg.textContent = platform.sealer ? 'Sealing under this phone\'s screen lock: confirm it when asked…' : 'Sealing…';
      try {
        await createInto(platform, session, { name: name.value.trim(), relay: relay.value });
        session = null;
        release?.(); release = null;
        door(false);
        location.hash = '';
        location.reload();
      } catch (e) {
        // The words were checked: whatever failed after, they restore this identity (Restore from your 25 words).
        msg.textContent = `Not saved: ${e.message}. Your 25 words are on your paper: restore from them.`;
        discard();
        if (back) msg.after(el('div', { className: 'bar' }, el('button', { textContent: 'Back to the start', onclick: () => back() })));
      }
    };
    box.replaceChildren(el('div', { className: 'card' },
      el('h2', { textContent: 'Check your paper' }),
      el('p', { textContent: 'Type these words from your paper.' }),
      ...at.flatMap((n, i) => [el('label', { textContent: `Word ${n}` }), inputs[i]]),
      el('div', { className: 'bar' }, go), msg));
    inputs[0].focus?.();
  }
  return { discard };
}
