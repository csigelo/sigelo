// SPDX-License-Identifier: MIT
// Public codes, contract sigelo-public/0 (design/public-invite.md): one code a business or an agent
// service posts for months, each use of it a pairing request. No network here; the carrier parks,
// fetches, answers and approves (carrier.mjs invitePublic, accept, approvePublic). Runner:
// test-public.mjs; the relay side: relay/park.mjs.
//
// The long code is invite.mjs's version 2 (sgl2…, makeInvite version 2, parsePublicCode), up to
// PUBLIC_TTL_MAX. Its short form is PUB-7Q4K-M2XD: "PUB" and a short code's 8 characters (a relay
// tag after them off the public relay), parked under SHA-256("sigelo-public/0" ‖ the 8 or 12), so a
// public hash is never a one-time code's (short.mjs codeHash). An older client refuses PUB- at its U.
//
// Every joiner holds the code's secret. From it (HKDF-SHA256, no salt): the answer topic, an
// ordinary mailbox m/<32 hex> the inviter claims (an i/ topic dies at its first answer), and the
// answer key. From it and the answer's id (invite.mjs answerId), per joiner: the reply topic i/<32
// hex> and its key; the joiner claims that topic before its answer goes, and no other joiner sees the
// answer (only the inviter reads the mailbox), so none can claim it first. The answer carries iat
// (invite.mjs buildAnswer); the inviter takes it up to REQUEST_TTL old and keeps the answer ids it
// has seen SEEN_KEEP: a replay is dropped. The pairing key is pairKey(secret, KEM, …) as ever, but
// the secret is public: K rests on the hybrid KEM alone.
//
// The four words published beside the code are the inviter's didWords(original DID): known before
// pairing, one value for every joiner, kept across rotations. A joiner given them checks the paired
// contact's; the inviter compares nothing with strangers, so its joiners stay unchecked (THREAT-MODEL §2.19).
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { fail } from './kdf.mjs';
import { didWords, formatShort, normaliseShort } from './short.mjs';
import { PUBLIC_TTL_MAX, REQUEST_TTL } from './invite.mjs';

export { PUBLIC_TTL_MAX, REQUEST_TTL };
export const PUBLIC_V = 'sigelo-public/0', PUB_PREFIX = 'PUB';
// Answers a UTC day by default and at most (the relay's cap: relay/park.mjs); 3 codes per account there.
export const PUBLIC_CAP = 50, PUBLIC_CAP_MAX = 500, PUBLIC_PER_ACCOUNT = 3;
// Answer ids seen, kept this long: past REQUEST_TTL an answer is refused by its iat anyway.
export const SEEN_KEEP = 8 * 86400;
// The link a business prints: the fragment never leaves the browser.
export const LINK_BASE = 'https://sigelo.io/join#';
export const LABELS = {
  answer_topic: 'sigelo-public/0 answer topic',  // 16 bytes → "m/" + hex: joiners write, the inviter reads
  key: 'sigelo-public/0 key',                    // 32 bytes: the answers' key
  reply_topic: 'sigelo-public/0 reply topic\n',  // ‖ answer id, 16 bytes → "i/" + hex: the inviter writes, one joiner reads
  reply_key: 'sigelo-public/0 reply key\n',      // ‖ answer id, 32 bytes: that reply's key
};
const SEPARATORS = /[\s\-‐-―−]+/g;
const d = (secret, info, n) => hkdf(sha256, secret, undefined, utf8ToBytes(info), n);
const checkSecret = (s) => { if (!(s instanceof Uint8Array) || s.length !== 32) fail('secret', 'must be 32 bytes'); };

/** The code's answer topic and key. */
export function publicKeys(secret) {
  checkSecret(secret);
  return { answer_topic: 'm/' + bytesToHex(d(secret, LABELS.answer_topic, 16)), key: d(secret, LABELS.key, 32) };
}
/** One joiner's reply topic and key, from the code's secret and its answer's id. */
export function joinerKeys(secret, answerId) {
  checkSecret(secret);
  if (typeof answerId !== 'string' || answerId === '') fail('answer_id', 'an answer id (invite.mjs answerId)');
  return { reply_topic: 'i/' + bytesToHex(d(secret, LABELS.reply_topic + answerId, 16)), key: d(secret, LABELS.reply_key + answerId, 32) };
}

/** Whether text reads as a PUB code (PUB, then 8 or 12 characters, dashes and spaces ignored). */
export const isPub = (text) => typeof text === 'string' && text.length <= 64 && /^PUB/i.test(text.replace(SEPARATORS, '')) && text.replace(SEPARATORS, '').length > 3 + 7;
/** The canonical 8 or 12 characters after PUB, or throws short_code. */
export function normalisePub(text) {
  if (!isPub(text)) fail('short_code', 'not a public code (like PUB-7Q4K-M2XD)');
  return normaliseShort(text.replace(SEPARATORS, '').slice(PUB_PREFIX.length));
}
/** "7Q4KM2XD" → "PUB-7Q4K-M2XD". */
export const formatPub = (norm) => `${PUB_PREFIX}-${formatShort(norm)}`;
/** The key the relay holds a public code under: hex SHA-256("sigelo-public/0" ‖ the normalised 8 or 12). */
export const publicHash = (text) => bytesToHex(sha256(concatBytes(utf8ToBytes(PUBLIC_V), utf8ToBytes(normalisePub(text)))));

/** The four words published beside the code: the inviter's didWords(original DID). */
export const publicWords = (originalDid) => didWords(originalDid);
/** Four words as typed ("Alpha-beta  gamma, delta") → "alpha beta gamma delta", or throws words. */
export function normaliseWords(text) {
  const w = typeof text === 'string' ? text.toLowerCase().split(/[\s,.;:\-]+/).filter(Boolean) : [];
  if (w.length !== 4 || !w.every((x) => /^[a-z]{3,8}$/.test(x))) fail('words', 'four words, as printed beside the code');
  return w.join(' ');
}
/** The link: https://sigelo.io/join#PUB-7Q4K-M2XD.word-word-word-word. */
export const publicLink = (pub, words) => `${LINK_BASE}${pub}.${words.split(' ').join('-')}`;
/** A link back → { code, words } (words null when the link carries none), or null when text is no such link. */
export function readLink(text) {
  if (typeof text !== 'string' || !text.startsWith(LINK_BASE)) return null;
  const [code, w] = text.slice(LINK_BASE.length).split('.');
  return { code: decodeURIComponent(code), words: w ? normaliseWords(decodeURIComponent(w).replace(/-/g, ' ')) : null };
}
/** A cap as given: 1 to PUBLIC_CAP_MAX, or throws cap. */
export function checkCap(cap) {
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > PUBLIC_CAP_MAX) fail('cap', `new chats a day: 1 to ${PUBLIC_CAP_MAX}, not ${JSON.stringify(cap)}`);
  return cap;
}
