// SPDX-License-Identifier: MIT
// site/src/join.mjs — the one script on sigelo.io, served as /join.mjs for /join only.
//
// A business prints https://sigelo.io/join#PUB-7Q4K-M2XD.word-word-word-word (apps/contact/public.mjs
// LINK_BASE, publicLink). The fragment never leaves the browser: this script reads location.hash,
// shows the code and the four words, and offers Copy. No network, no storage, no cookie: nothing is sent.
// parseJoin is pure, for site/test/run.mjs; the rest runs only in a page.

// apps/contact/short.mjs ALPHABET and FOLD (site/test/run.mjs checks they agree).
export const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const FOLD = { I: '1', L: '1', O: '0' };
const SEPARATORS = /[\s\-‐-―−]+/g;

/** "#PUB-7Q4K-M2XD.amber-otter-violin-harbor" → { code: "PUB-7Q4K-M2XD", words: ["amber", …] };
 *  words null when the link has none or they do not read as four; null for no fragment;
 *  { error } when there is one but it is no PUB code (8 characters, or 12 with a relay tag). */
export function parseJoin(hash) {
  if (typeof hash !== 'string') return null;
  let s = hash.replace(/^#/, '');
  if (s === '') return null;
  if (s.length > 200) return { error: 'too long' };
  try { s = decodeURIComponent(s); } catch { return { error: 'not readable' }; }
  const dot = s.indexOf('.');
  const codePart = dot < 0 ? s : s.slice(0, dot), wordPart = dot < 0 ? '' : s.slice(dot + 1);
  const c = codePart.replace(SEPARATORS, '').toUpperCase();
  if (!c.startsWith('PUB')) return { error: 'not a PUB code' };
  const rest = c.slice(3).replace(/[ILO]/g, (x) => FOLD[x]);
  if (!(rest.length === 8 || rest.length === 12) || ![...rest].every((x) => ALPHABET.includes(x))) return { error: 'not a PUB code' };
  const code = `PUB-${rest.match(/.{4}/g).join('-')}`;
  const w = wordPart.toLowerCase().split(/[\s,.;:\-]+/).filter(Boolean);
  return { code, words: w.length === 4 && w.every((x) => /^[a-z]{3,8}$/.test(x)) ? w : null };
}

// The page's example code and words, as in site/src/join.md.
export const EXAMPLE_CODE = 'PUB-7Q4K-M2XD', EXAMPLE_WORDS = 'word word word word';
/** An example command with a parsed link's code (and words, when it has them) in place. */
export const fillExample = (text, j) => text.split(EXAMPLE_CODE).join(j.code).split(EXAMPLE_WORDS).join(j.words ? j.words.join(' ') : EXAMPLE_WORDS);

if (typeof document !== 'undefined') {
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; };
  const show = () => {
    document.getElementById('join-card')?.remove();
    const j = parseJoin(location.hash);
    // The commands, with this link's code and words in place of the example's (back again without one).
    for (const c of document.querySelectorAll('main pre code')) {
      c.dataset.example ??= c.textContent;
      c.textContent = j && !j.error ? fillExample(c.dataset.example, j) : c.dataset.example;
    }
    if (!j) return;
    const card = el('section', 'join-card');
    card.id = 'join-card';
    card.setAttribute('aria-label', 'This link');
    if (j.error) card.append(el('p', null, 'This link does not hold a public code (PUB- and 8 characters). Ask whoever printed it.'));
    else {
      card.append(el('p', 'join-lead', 'Their code'), el('p', 'join-code', j.code));
      const copy = el('button', 'join-copy', 'Copy the code');
      copy.type = 'button';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(j.code); copy.textContent = 'Copied'; }
        catch { copy.textContent = 'Select the code to copy it'; }
      });
      if (j.words) {
        const words = el('p', 'join-words');
        for (const w of j.words) words.append(el('span', null, w));
        card.append(el('p', 'join-lead', 'Their four words'), words);
      } else card.append(el('p', null, 'This link has no four words: ask for them before you trust the chat.'));
      card.append(copy);
    }
    document.querySelector('main h1')?.after(card);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', show); else show();
  addEventListener('hashchange', show);
}
