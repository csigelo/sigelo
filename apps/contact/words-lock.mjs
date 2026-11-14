// SPDX-License-Identifier: MIT
// The words password (design/apps-seed.md §8): the 25 words kept on a phone, encrypted under a key made from
// a password the human chose, so Me → Security can show them again (Monerujo-style, but optional). WebCrypto
// only, no import: it runs as it is in the Android app's WebView, in the GTK app's WebKit and in Node.
//
//   lockWords(words, password, { iterations })  → { blob, check }   blob: the bytes to seal in the keystore
//   openWords(blob, password)                   → { words, check }  a wrong password throws check words_password
//   proofOf(blob, password)                     → check, the same refusal: what a shell compares (GTK)
//   wordsMeta(blob)                             → { v, kdf, iter } (no secret)
//   checkPassword(password, repeat)             → the password, or throws check words_password_rule
//   wrongGate({ base, sleep }), gate            the delay after a wrong password: 2 s, doubling per failure (at most
//                                               256 s) in this page's life, none after a right one; no lockout
//   lockBytes(label, bytes, password, o)        → { iter, salt, iv, ct, check }: any bytes, the same KDF and cipher, `label`
//   openBytes(label, sealed, password, aad)     → bytes (o.aad: what the caller binds; apps/web/backup.mjs, label sigelo-backup/0)
//
// blob: JSON { v: "sigelo-words/0", kdf: "PBKDF2-SHA256", iter, salt, iv, ct } (base64). The password (NFC)
// goes through PBKDF2-HMAC-SHA256 with a random 16-byte salt and `iter` rounds (ITERATIONS: 1,000,000; about
// 0.45 s in WebKit on a 2018 phone), 32 bytes out; HKDF-SHA256 of those makes the AES-256-GCM key (info
// "sigelo-words/0 key") and the check (info "sigelo-words/0 check", 32 bytes, hex). The AAD names the version
// and the KDF with its rounds. The check is never stored in the blob: a shell that keeps it beside the blob
// (the GTK app's keyring item) knows the password was typed without seeing the words.
export const V = 'sigelo-words/0', KDF = 'PBKDF2-SHA256', ITERATIONS = 1_000_000, MIN_ITERATIONS = 1_000, PASSWORD_MIN = 8, WORD_COUNT = 25;
const te = new TextEncoder(), td = new TextDecoder();
const refuse = (check, message) => { throw Object.assign(new Error(message), { check }); };
const b64 = (b) => { let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const subtle = () => globalThis.crypto?.subtle ?? refuse('words_crypto', 'this page has no WebCrypto');
const aad = (iter) => te.encode(`${V} ${KDF} ${iter}`);

/** The words as one line: lowercase, one space between, exactly 25 (they are checked by the restore before this). */
function cleanWords(words) {
  const w = (Array.isArray(words) ? words.join(' ') : String(words ?? '')).trim().toLowerCase().split(/\s+/);
  if (w.length !== WORD_COUNT || w.some((x) => !/^[a-z]+$/.test(x))) refuse('words', `${WORD_COUNT} words`);
  return w.join(' ');
}
/** A password as set: at least 8 characters, the repeat the same. → the password. */
export function checkPassword(password, repeat = password) {
  const p = String(password ?? '');
  if ([...p].length < PASSWORD_MIN) refuse('words_password_rule', `A password of at least ${PASSWORD_MIN} characters.`);
  if (p !== String(repeat ?? '')) refuse('words_password_rule', 'The two passwords are not the same.');
  return p;
}
async function keys(password, salt, iter, label = V) {
  const s = subtle();
  const pw = await s.importKey('raw', te.encode(String(password).normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  const master = new Uint8Array(await s.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, pw, 256));
  try {
    const h = await s.importKey('raw', master, 'HKDF', false, ['deriveKey', 'deriveBits']);
    const hk = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(`${label} ${info}`) });
    const key = await s.deriveKey(hk('key'), h, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const check = hex(new Uint8Array(await s.deriveBits(hk('check'), h, 256)));
    return { key, check };
  } finally { master.fill(0); }
}
/** The blob's fields, checked: { v, kdf, iter, salt, iv, ct } (bytes for the last three). */
function parse(blob) {
  let o;
  try { o = JSON.parse(td.decode(blob)); } catch { refuse('words_blob', 'the kept words are damaged'); }
  if (o?.v !== V || o.kdf !== KDF || !Number.isSafeInteger(o.iter) || o.iter < MIN_ITERATIONS) refuse('words_blob', 'the kept words are of an unknown kind');
  try { return { ...o, salt: unb64(o.salt), iv: unb64(o.iv), ct: unb64(o.ct) }; } catch { return refuse('words_blob', 'the kept words are damaged'); }
}
export function wordsMeta(blob) { const { v, kdf, iter } = parse(blob); return { v, kdf, iter }; }

/**
 * Bytes encrypted under the password, as the words are: PBKDF2 with a fresh 16-byte salt, HKDF info "<label> key" and
 * "<label> check", AES-256-GCM over aad → { iter, salt, iv, ct (bytes), check (hex) }.
 */
export async function lockBytes(label, bytes, password, { iterations = ITERATIONS, aad: ad = new Uint8Array(0) } = {}) {
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS) refuse('words_kdf', `at least ${MIN_ITERATIONS} rounds`);
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16)), iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const { key, check } = await keys(password, salt, iterations, label);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: ad }, key, bytes));
  return { iter: iterations, salt, iv, ct, check };
}
/** lockBytes's bytes back → { plain, check }; a wrong password (or a changed aad): check words_password. */
export async function openBytes(label, { iter, salt, iv, ct }, password, ad = new Uint8Array(0)) {
  if (!Number.isSafeInteger(iter) || iter < MIN_ITERATIONS) refuse('words_kdf', `at least ${MIN_ITERATIONS} rounds`);
  const { key, check } = await keys(String(password ?? ''), salt, iter, label);
  try { return { plain: new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv, additionalData: ad }, key, ct)), check }; } catch { return refuse('words_password', 'Wrong password.'); }
}

/** The 25 words encrypted under the password → { blob (bytes), check (hex) }. */
export async function lockWords(words, password, { iterations = ITERATIONS } = {}) {
  const line = te.encode(cleanWords(words)), p = checkPassword(password);
  try {
    const { iter, salt, iv, ct, check } = await lockBytes(V, line, p, { iterations, aad: aad(iterations) });
    return { blob: te.encode(JSON.stringify({ v: V, kdf: KDF, iter, salt: b64(salt), iv: b64(iv), ct: b64(ct) })), check };
  } finally { line.fill(0); }
}
/** The words back → { words: [25], check }; a wrong password: check words_password. */
export async function openWords(blob, password) {
  const o = parse(blob), { plain, check } = await openBytes(V, o, password, aad(o.iter));
  try { return { words: td.decode(plain).split(' '), check }; } finally { plain.fill(0); }
}
/** The check for a password, after the words opened under it (so a wrong one is refused here too). */
export async function proofOf(blob, password) { return (await openWords(blob, password)).check; }

/** A wrong password costs 2 s, then 4, 8, … up to 256 s (in this gate's life: the page's); a right one resets it. Never a lockout. */
export function wrongGate({ base = 2000, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  let fails = 0, last = Promise.resolve();
  const attempt = async (fn) => {
    try { const r = await fn(); fails = 0; return r; } catch (e) {
      if (e?.check === 'words_password') { fails++; await sleep(base * 2 ** Math.min(fails - 1, 7)); }
      throw e;
    }
  };
  return {
    get fails() { return fails; },
    /** One attempt at a time: a second tap waits for the first's delay, so taps in parallel do not skip it. */
    run(fn) { const r = last.then(() => attempt(fn)); last = r.catch(() => {}); return r; },
  };
}
/** The page's one gate: every place that asks the password counts in it. */
export const gate = wrongGate();
