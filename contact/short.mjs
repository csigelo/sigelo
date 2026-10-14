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
// English list. The same words on both sides = nobody, not even the relay, swapped the pairing.
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
const SEPARATORS = /[\s\-‐-―−]+/g;
// Longer input is no short code: refused before any work.
const MAX_INPUT = 64;

/** The canonical form of a short code ("K7F3Q9ZP"), or throws short_code. */
export function normaliseShort(text) {
  if (typeof text !== 'string' || text.length > MAX_INPUT) fail('short_code', 'not a short code');
  const s = text.replace(SEPARATORS, '').toUpperCase().replace(/[ILO]/g, (c) => FOLD[c]);
  if (s.length !== SHORT_LENGTH) fail('short_code', `${s.length} characters, a short code has ${SHORT_LENGTH}`);
  for (const ch of s) if (!ALPHABET.includes(ch)) fail('short_code', `${JSON.stringify(ch)} is not in a short code${ch === 'U' ? ' (no U: a typo?)' : ''}`);
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

/** The four words of a pairing, from its pair id (32 lowercase hex digits, kdf.pairId). */
export function fingerprint(pair) {
  const b = hkdf(sha256, unhex(pair, 16, 'pair'), utf8ToBytes(FINGERPRINT_LABEL), new Uint8Array(0), 6);
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return [0, 1, 2, 3].map((i) => WORDS[Number((x >> BigInt(48 - 11 * (i + 1))) & 2047n)]).join(' ');
}
