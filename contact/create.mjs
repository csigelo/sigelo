// SPDX-License-Identifier: MIT
// A new identity made on the device (design/apps-seed.md §7, pass A10a; Monerujo's create and seed
// review as the model). The root S is drawn here, as `newRoot()` draws it (keys.ts: 253 random bits from
// crypto.getRandomValues, redrawn until 0 < S < l), and held as bytes. Its 25 words exist only while the
// review screen shows them; the identity's files are made only after the human has typed three of them
// back, then S is zeroed. No network, no storage and no clock here: the page (apps/web/create.mjs) seals
// what `commit` returns, as a restore's.
//
//   newSeed(net)          → a session:
//     .net, .vault        the network, and the primary address of S's own Monero wallet (the vault,
//                         MONERO.md §2): a Monero wallet app restored from the words shows the same
//     .words()            the 25 words, ['w1', …, 'w25']: for the review screen only; refused once spent
//     .quiz()             QUIZ (3) positions, 1 to 25, drawn afresh each time, ascending
//     .check(answers)     the words typed for the last quiz's positions (in that order) → { ok, wrong: [positions] };
//                         a wrong answer ends the quiz: back to the words, then a new quiz
//     .commit(o)          after a check that passed: restoreFromRoot(S, o) with created today and the wallet's
//                         birth as today's date (restore_date: a new wallet has nothing older), the keeper
//                         marked made: "here" (as keeper --from-words --made-here), then S zeroed
//                         → { identity, keeper, device, list, notes, did, worker, vault }
//     .discard()          S zeroed; every call after it refused (create_spent)
//   QUIZ                  how many words the human types back
//
// Words are compared as the wallet's own decoder reads them: case and blanks ignored, the whole word or
// its first three letters.
import { encodeMoneroWords, newRootBytes, vaultFromRoot } from 'sigelo/dist/keys.js';
import { fail } from './kdf.mjs';
import { NETS, WORD_COUNT, restoreFromRoot } from './restore.mjs';

export const QUIZ = 3;
const day = (now) => new Date(now * 1000).toISOString().slice(0, 10);
const norm = (w) => String(w ?? '').trim().toLowerCase();
/** An unbiased index in [0, n) from crypto.getRandomValues. */
function draw(n) {
  const lim = Math.floor(0x100000000 / n) * n, b = new Uint32Array(1);
  for (;;) { globalThis.crypto.getRandomValues(b); if (b[0] < lim) return b[0] % n; }
}

/** A fresh root for a new identity on `net` (mainnet | stagenet): see the header. */
export function newSeed(net) {
  if (!NETS.includes(net)) fail('create_net', `net: ${NETS.join(' or ')}`);
  let S = newRootBytes(), asked = null, passed = false;
  const live = () => { if (S === null) fail('create_spent', 'these words are gone: start again'); return S; };
  const v = vaultFromRoot(S, net), vault = v.address;
  v.b.fill(0); v.a.fill(0);
  return Object.freeze({
    net, vault,
    words: () => encodeMoneroWords(live()).split(' '),
    quiz() {
      live();
      const at = new Set();
      while (at.size < QUIZ) at.add(draw(WORD_COUNT) + 1);
      asked = [...at].sort((a, b) => a - b);
      passed = false;
      return [...asked];
    },
    check(answers) {
      const w = encodeMoneroWords(live()).split(' ');
      if (asked === null) fail('create_quiz', 'no words asked yet');
      if (!Array.isArray(answers) || answers.length !== asked.length) fail('create_quiz', `${asked.length} words, in the order asked`);
      const same = (typed, word) => { const t = norm(typed); return t === word || (t.length === 3 && t === word.slice(0, 3)); };
      const wrong = asked.filter((pos, i) => !same(answers[i], w[pos - 1]));
      passed = wrong.length === 0;
      if (!passed) asked = null;
      return { ok: passed, wrong };
    },
    commit({ name, relay, now, j } = {}) {
      live();
      if (!passed) fail('create_unchecked', 'type the three words from your paper first');
      const r = restoreFromRoot(S, { name, relay, net, restore: { restore_date: day(now) }, seat: 'here', now, ...(j !== undefined && { j }) });
      S.fill(0); S = null;
      r.keeper.made = 'here';   // as keeper --from-words --made-here: Me says "Created on"
      return { ...r, vault };
    },
    discard() { S?.fill(0); S = null; },
  });
}
