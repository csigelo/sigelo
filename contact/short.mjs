// SPDX-License-Identifier: MIT
// Short invite codes and the four words of a pairing, contract sigelo-park/0 (ROADMAP §8 item 1).
// No network here; the carrier parks and fetches (carrier.mjs invite, accept). Fixture and runner:
// fixtures/short-code-v0.json, gen-short.mjs, test-short.mjs.
//
// A short code is what a person can say on the phone: 8 characters of Crockford's base32 (no I,
// L, O, U), shown as K7F3-Q9ZP, 40 bits from a CSPRNG. It names no relay and no DID: it is a key
// under which the inviter parks the long code (invite.mjs) at its relay for SHORT_TTL seconds,
// fetched once. The relay stores it under codeHash(code) = hex SHA-256("sigelo-park/0" ‖ the
// normalised code), so the code itself never reaches the relay's memory or logs. 40 bits hash in
// seconds, though: the hash hides the code from a log reader, not from the relay, which holds the
// long code anyway (THREAT-MODEL.md §2.10).
//
// Input is read the way people write: case does not matter, I and L read as 1, O as 0, and
// spaces and dashes (any of the dashes a phone's keyboard substitutes) are ignored. U is no digit
// and is refused, as is anything else outside the alphabet.
//
// The four words: once a pairing completes, both sides derive them from `pair` (kdf.pairId, which
// binds the pairing key K and so both original DIDs): HKDF-SHA256(pair's 16 bytes, salt
// "sigelo-fingerprint/0", empty info, 6 bytes); the first 44 bits, 11 at a time, index the BIP-39
// English list. The same words on both sides = no mix-up and no casual swap; a relay that invests
// GPU time in one is caught by the pair id (THREAT-MODEL.md §2.10).
import { randomBytes } from 'node:crypto';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { WORDS } from './bip39-english.mjs';
import { fail, unhex } from './kdf.mjs';

export const PARK_V = 'sigelo-park/0', FINGERPRINT_LABEL = 'sigelo-fingerprint/0';
export const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
// Seconds a parked code lives at the relay; it goes at its first fetch before that.
export const SHORT_TTL = 600, SHORT_LENGTH = 8;
const FOLD = { I: '1', L: '1', O: '0' };
// Whitespace, and the hyphen with every dash a phone or a word processor puts in its place.
const SEPARATORS = /[\s\-\u2010-\u2015\u2212]+/g, SEPARATOR = /^[\s\-\u2010-\u2015\u2212]$/;
// Longer input is no short code: refused before any work.
const MAX_INPUT = 64;
// Short or long is decided on the input's shape, before either parser runs: a short code mistyped
// (7 characters, a U, a full stop after it) read as a long code was refused as "does not start
// with sgl1", which tells the person nothing. A long code is about 126 characters and starts sgl1.
export const SHORT_MAX = 12;
/** 'short' when `text`, without spaces and dashes, is at most SHORT_MAX characters and does not
 *  start with sgl1; else 'long'. Says how the code is read, not whether it is good. */
export function codeKind(text) {
  const s = typeof text === 'string' ? text.replace(SEPARATORS, '') : '';
  return s.length <= SHORT_MAX && !/^sgl1/i.test(s) ? 'short' : 'long';
}
const READ = 'read as a short code (12 characters or fewer, no sgl1)';
const AGAIN = 'check it with whoever gave it to you';

/** The canonical form of a short code ("K7F3Q9ZP"), or throws short_code naming the character at fault. */
export function normaliseShort(text) {
  if (typeof text !== 'string' || text.length > MAX_INPUT) fail('short_code', 'not a short code');
  const shown = JSON.stringify(text.trim());
  // Positions count the characters a person typed, separators left out: "character 5" of K7F3-U9ZP is the U.
  let at = 0;
  for (const c of text) {
    if (SEPARATOR.test(c)) continue;
    at++;
    const u = c.toUpperCase();
    if (!ALPHABET.includes(FOLD[u] ?? u)) {
      fail('short_code', `${shown} ${READ}: character ${at} ${JSON.stringify(c)} is not in the alphabet; a short code uses 0-9 and A-Z without I, L, O, U${u === 'U' ? ' (a V?)' : ''}: ${AGAIN}`);
    }
  }
  const s = text.replace(SEPARATORS, '').toUpperCase().replace(/[ILO]/g, (c) => FOLD[c]);
  if (s.length !== SHORT_LENGTH) {
    fail('short_code', `${shown} ${READ}: ${s.length} characters, a short code has ${SHORT_LENGTH} (like K7F3-Q9ZP): ${Math.abs(SHORT_LENGTH - s.length)} ${s.length < SHORT_LENGTH ? 'missing' : 'too many'}; ${AGAIN}`);
  }
  return s;
}

/** Whether `text` reads as a short code (a long code starts sgl1 and runs to about 126 characters). */
export function isShort(text) {
  try { normaliseShort(text); return true; } catch { return false; }
}

/** "K7F3Q9ZP" → "K7F3-Q9ZP", how it is shown. */
export const formatShort = (norm) => `${norm.slice(0, 4)}-${norm.slice(4)}`;

/** A new short code from 5 random bytes, 5 bits a character, most significant first. → its canonical form. */
export function makeShort(rng = randomBytes) {
  const b = rng(5);
  if (!(b instanceof Uint8Array) || b.length !== 5) fail('short_code', 'the random source must give 5 bytes');
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  let out = '';
  for (let i = SHORT_LENGTH - 1; i >= 0; i--) out += ALPHABET[Number((x >> BigInt(5 * i)) & 31n)];
  return out;
}

/** The key the relay parks under: hex SHA-256("sigelo-park/0" ‖ the normalised code). */
export const codeHash = (text) => bytesToHex(sha256(concatBytes(utf8ToBytes(PARK_V), utf8ToBytes(normaliseShort(text)))));

// Gift codes (sigelo-gift/0): Pro months for an operator, sold or handed out by the vendor
// (commercial/gift-codes.mjs makes them offline; relay/gifts.mjs redeems them, POST /gift). The
// same 8 characters, alphabet and folding as a short code, shown with a prefix of their own,
// PRO-K7F3-Q9ZP, so a person cannot take one for an invite. Typed in any case, with or without
// dashes or the PRO prefix. Hashed under a label of their own: a gift's hash is never a parked
// code's. The relay holds the hash only (code_hash), and a code is in no log or error text.
export const GIFT_V = 'sigelo-gift/0', GIFT_PREFIX = 'PRO';
/** The canonical 8 characters of a gift code ("K7F3Q9ZP"), or throws gift_code. */
export function normaliseGift(text) {
  if (typeof text !== 'string' || text.length > MAX_INPUT) fail('gift_code', 'not a gift code');
  const bare = text.replace(SEPARATORS, '');
  // The prefix, its O folded as a code's is, on anything longer than a code.
  const rest = bare.length > SHORT_LENGTH && bare.slice(0, GIFT_PREFIX.length).toUpperCase().replace('0', 'O') === GIFT_PREFIX ? bare.slice(GIFT_PREFIX.length) : bare;
  try { return normaliseShort(rest); } catch (e) {
    // The short code's reason (the character at fault, the count), without the input it quotes.
    fail('gift_code', `not a gift code (like PRO-K7F3-Q9ZP: PRO, then 8 characters of 0-9 and A-Z without I, L, O, U): ${e.message.replace(/^short_code: (?:"[^"]*" read as a short code \([^)]*\): )?/, '').replaceAll('a short code', 'a gift code').replace('(like K7F3-Q9ZP)', 'after PRO')}`);
  }
}
/** "K7F3Q9ZP" → "PRO-K7F3-Q9ZP", how a gift code is shown. */
export const formatGift = (norm) => `${GIFT_PREFIX}-${formatShort(norm)}`;
/** The key the relay holds a gift under: hex SHA-256("sigelo-gift/0" ‖ the normalised code). */
export const giftHash = (text) => bytesToHex(sha256(concatBytes(utf8ToBytes(GIFT_V), utf8ToBytes(normaliseGift(text)))));

/** The four words of a pairing, from its pair id (32 lowercase hex digits, kdf.pairId). */
export function fingerprint(pair) {
  const b = hkdf(sha256, unhex(pair, 16, 'pair'), utf8ToBytes(FINGERPRINT_LABEL), new Uint8Array(0), 6);
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return [0, 1, 2, 3].map((i) => WORDS[Number((x >> BigInt(48 - 11 * (i + 1))) & 2047n)]).join(' ');
}
