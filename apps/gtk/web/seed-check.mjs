// SPDX-License-Identifier: MIT
// The start page's live check of the 25 words (design/apps-seed.md rule 3), without sigelo's modules:
// the count over runs of whitespace, the first word not in the Monero English list (by position, never
// echoed), then the checksum: the 25th word repeats word crc32(the first 3 letters of each of the 24,
// joined) % 24, as ts/src/keys.ts (Monero's electrum-words.cpp). sigelo-agent keeper --from-words
// checks the words again, with the canonical-root rule; test-gtk.mjs compares this with
// contact/restore.mjs checkWords. monero-words.js: ts/dist's, copied beside it by install.sh.
import { MONERO_WORDS } from './monero-words.js';

export const WORD_COUNT = 25;
const BY_PREFIX = new Map(MONERO_WORDS.map((w) => [w.slice(0, 3), w]));
const inList = (w) => { const x = BY_PREFIX.get(w.slice(0, 3)); return x !== undefined && (w === x || w === x.slice(0, 3)); };
function crc32(s) {
  let c = 0xffffffff;
  for (let i = 0; i < s.length; i++) { c ^= s.charCodeAt(i); for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); }
  return (c ^ 0xffffffff) >>> 0;
}
/** → { count, ok, error }: ok only for 25 listed words whose checksum holds. */
export function checkWords(text) {
  const words = String(text ?? '').toLowerCase().trim().split(/\s+/).filter(Boolean), at = words.findIndex((w) => !inList(w));
  if (at >= 0) return { count: words.length, ok: false, error: `word ${at + 1} is not in the Monero word list` };
  if (words.length < WORD_COUNT) return { count: words.length, ok: false, error: null };
  if (words.length > WORD_COUNT) return { count: words.length, ok: false, error: `${words.length} words: a Monero seed has ${WORD_COUNT}` };
  const pre = words.map((w) => BY_PREFIX.get(w.slice(0, 3)).slice(0, 3)), sum = crc32(pre.slice(0, 24).join('')) % 24;
  if (pre[sum] !== pre[24]) return { count: WORD_COUNT, ok: false, error: 'the checksum (the 25th word) does not match: a word is mistyped or out of order' };
  return { count: WORD_COUNT, ok: true, error: null };
}
