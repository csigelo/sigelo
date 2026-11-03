// SPDX-License-Identifier: MIT
// The words password in the Android app and a browser tab (design/apps-seed.md §8; the crypto: contact/words-lock.mjs).
// Optional: offered once, right after the three-word check of a create and at the end of a restore (welcome.mjs
// offerWords). Skipped: the words are never stored, as before. Set: the 25 words encrypted under a key made from
// the password (PBKDF2-SHA256, 1,000,000 rounds), and that sealed like the identity (saveSealed kind "words": in
// the Android app under the FULL keystore key, which needs the screen lock; in a tab under its WebCrypto key) into
// words.keystore | words.sealed of this profile. Then the same password guards Me → Security (show the words,
// change, remove), the removal of this profile and taking the seat; without one those keep their guards of before.
// A wrong password: "Wrong password." after 2 s, doubling per failure in this page's life (the page's gate); no lockout.
//
//   kept(p)                          the profile holds kept words
//   keepWords(p, words, password, o) encrypt and seal (o.iterations: tests only)
//   openKept(p, password, gate)      → { words, check }; words_none, words_password
//   guard(p, password, gate)         none kept: nothing; else the password, refused words_password_needed when empty
//   wordsApi(p, o)                   what ui.js reads as sigeloLocal.words: status, reveal, change, remove (boot.mjs)
import { ITERATIONS, checkPassword, gate as pageGate, lockWords, openWords } from './vendor/contact/words-lock.mjs';
import { loadSealed, saveSealed } from './platform-web.mjs';

const NAMES = ['words.keystore', 'words.sealed'];
/** An identity made or restored here from the 25 words (seed.mjs's settings): only then do its words exist on this phone. */
const fromWords = (p) => { try { return Boolean(JSON.parse(new TextDecoder().decode(p.files.read('app/settings.json'))).restored); } catch { return false; } };
const refuse = (status, check, message) => { throw Object.assign(new Error(message), { status, check }); };

export const kept = (p) => Boolean(p) && NAMES.some((n) => p.files.read(n) !== null);
export async function keepWords(p, words, password, { iterations = ITERATIONS } = {}) {
  const { blob } = await lockWords(words, password, { iterations });
  try { await saveSealed(p, 'words', blob, undefined, { full: true }); } finally { blob.fill(0); }
}
export async function dropWords(p) { for (const n of NAMES) p.files.remove(n); await p.flush(); }
export async function openKept(p, password, gate = pageGate) {
  const b = await loadSealed(p, 'words');
  if (b === null) refuse(404, 'words_none', 'No words are kept on this phone.');
  try { return await gate.run(() => openWords(b, password)); } catch (e) { throw Object.assign(e, { status: e.status ?? 403 }); } finally { b.fill(0); }
}
export async function guard(p, password, gate = pageGate) {
  if (!kept(p)) return;
  if (typeof password !== 'string' || password === '') refuse(403, 'words_password_needed', 'Type your words password.');
  await openKept(p, password, gate);
}

/**
 * sigeloLocal.words over the active profile's platform (a getter; null: none yet, or a computer's page). unlock: the shell's screen
 * lock. withProfile(id, fn): fn(that profile's platform-like store) for another profile (boot.mjs; its database
 * opened and closed again).
 */
export function wordsApi(platformOf, { unlock = async () => {}, iterations = ITERATIONS, gate = pageGate, withProfile } = {}) {
  const at = () => (typeof platformOf === 'function' ? platformOf() : platformOf) ?? null;
  return Object.freeze({
    /** { here: an identity of this phone's own (its words exist), kept, iterations }; id: another profile's (kept only). */
    async status(id) {
      if (id !== undefined && withProfile) return { here: false, kept: await withProfile(id, (q) => kept(q)) };
      return { here: at() !== null && fromWords(at()), kept: kept(at()), iterations };
    },
    /** The device lock, then the password → { words: [25] }. */
    async reveal(password) { await unlock(); return { words: (await openKept(at(), password, gate)).words }; },
    async change(old, next, repeat) {
      checkPassword(next, repeat);
      await unlock();
      const { words } = await openKept(at(), old, gate);
      await keepWords(at(), words, next, { iterations });
      return { kept: true };
    },
    async remove(password) { await unlock(); await openKept(at(), password, gate); await dropWords(at()); return { kept: false }; },
    /** What a guarded call carries (boot.mjs and router.mjs check it there): the password itself, in this page. */
    auth: async (_id, password) => ({ password }),
  });
}
