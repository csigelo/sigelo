// SPDX-License-Identifier: MIT
// Invite codes and the invite handshake, contract sigelo-invite/0 (design/relay-plan.md §3,
// "Invite code" and "Invite handshake"). Alice: makeInvite, store.addInvite, hand over `text`.
// Bob: parseInvite, buildAnswer, store.addAccept(code, answerId(answer), …). Alice: checkAnswer,
// buildReply. Bob: checkReply.
// No network here. The carrier encrypts answer and reply under inviteKeys(secret).key and posts
// them on its two topics; it parses what it decrypts with sigelo's parseBytes (duplicate keys).
// Fixture and runner: fixtures/invite-v0.json, test-invite.mjs, gen-invite.mjs.
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize, did as didOf, multibase, verify, verifySig } from 'sigelo';
import { MsgError, pairKey, signAs } from './kdf.mjs';

export const V = 'sigelo-invite/0';
// Each side proves its key with a signed body of its own type, never a SPEC §5.2 challenge: an
// agent's general-purpose challenge signer (sigelo-agent's signChallenge, the MCP tool) signs any
// ctx and nonce for its own DID, so a challenge got from it would let anyone pair as that agent.
// A challenge signer signs typ "challenge" only, and these typ values fit no bundle slot either.
// The body also commits to the message it travels in (`transcript`), so nothing in that message
// can be swapped on the way.
export const TYP_ANSWER = 'invite-answer', TYP_REPLY = 'invite-reply';
// SKEW: how far the answering side's clock may lag the inviter's when it checks the 7-day cap.
export const TTL = 86400, TTL_MAX = 7 * 86400, SKEW = 300, PREFIX = 'sgl1', VERSION = 0x01;
// HKDF-SHA256 and hash labels, part of the wire contract. The three from the one-time secret use
// no salt (the secret is 32 random bytes) and one info label each:
export const LABELS = {
  answer_topic: 'sigelo-invite/0 answer topic', // 16 bytes → "i/" + hex: Bob writes, Alice reads
  reply_topic: 'sigelo-invite/0 reply topic',   // 16 bytes → "i/" + hex: Alice writes, Bob reads
  key: 'sigelo-invite/0 key',                   // 32 bytes: XChaCha20-Poly1305 key for both
  answer: 'sigelo-invite/0 answer\n',           // prefix of the answer's transcript hash
  reply: 'sigelo-invite/0 reply\n',             // prefix of the reply's transcript hash
  answer_id: 'sigelo-invite/0 answer id\n',     // prefix of the whole answer's hash: the reply's nonce
  code: 'sigelo-invite/0 code\n',               // prefix of the whole code's hash: the answer's nonce
  pair_salt: 'sigelo-pair/0',                   // salt of the pairing key K
};

// Every refusal names its check (.check), as contact/kdf.mjs's MsgError: one error class for
// the whole package, invite, envelope, prekeys and carrier alike.
export const fail = (check, why) => { throw new MsgError(check, why); };
export const attempt = (check, f) => { try { return f(); } catch (e) { return fail(check, e.message); } };
export const hex = (b) => bytesToHex(b);
const isTime = (t) => Number.isSafeInteger(t) && t >= 0;
// `now` comes from the caller, never from a peer, but NaN or a string would make every expiry
// comparison false: fail open. Checked at every entry point.
export const checkTime = (now) => { if (!isTime(now)) fail('now', 'must be Unix seconds'); };
// For people reading a refusal: an instant, and a span, as words.
const iso = (t) => new Date(t * 1000).toISOString().replace('.000', '');
const ago = (s) => (s < 120 ? `${s} s` : s < 7200 ? `${Math.round(s / 60)} minutes` : s < 172800 ? `${Math.round(s / 3600)} hours` : `${Math.round(s / 86400)} days`);

// ---------------------------------------------------------------- the code

// version 1 | inviter's current DID digest 32 | secret 32 | expiry 4 (unsigned BE) |
// relay length 1 | host[:port] 1..63 | checksum 4 = SHA-256(all before)[0..4]
const AT_DID = 1, AT_SECRET = 33, AT_EXP = 65, AT_RLEN = 69, AT_RELAY = 70, FIXED = 74, RELAY_MAX = 63;
// 137 bytes at most, which base58 spells in at most 188 digits. Longer text is refused before
// decoding: base58 decoding is quadratic, the reason SPEC §2 bounds multibase values.
const MAX_DIGITS = 188;
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
// Lowercase host names and ports without leading zeros: one spelling per address, so two codes
// for the same relay are the same bytes. No IPv6 literals in version 1.
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const RELAY = new RegExp(`^${LABEL}(?:\\.${LABEL})*(?::([1-9][0-9]{0,4}))?$`);
const DID = /^did:sigelo:z([1-9A-HJ-NP-Za-km-z]{1,63})$/;

/** Only called on a string whose every character is a base58 digit and whose length is bounded. */
function b58decode(s) {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  const out = [];
  for (const ch of s.slice(zeros)) {
    let carry = B58.indexOf(ch);
    for (let j = 0; j < out.length; j++) { const x = out[j] * 58 + carry; out[j] = x & 0xff; carry = x >> 8; }
    while (carry > 0) { out.push(carry & 0xff); carry >>= 8; }
  }
  return Uint8Array.from([...new Array(zeros).fill(0), ...out.reverse()]);
}

/** A relay as a code names it: a lowercase host[:port], at most RELAY_MAX characters; else throws code_relay. */
export function checkRelay(relay) {
  const m = typeof relay === 'string' ? RELAY.exec(relay) : null;
  if (!m || relay.length > RELAY_MAX || (m[1] !== undefined && Number(m[1]) > 65535)) {
    fail('code_relay', `${JSON.stringify(relay)} is not a lowercase host[:port] of at most ${RELAY_MAX} characters`);
  }
}

function didDigest(did) {
  const m = typeof did === 'string' ? DID.exec(did) : null;
  const d = m ? b58decode(m[1]) : null;
  if (!d || d.length !== 32) fail('did', `${JSON.stringify(did)} is not a did:sigelo`);
  return d;
}

/**
 * The nonce in Bob's proof, and the key of Alice's pending invite: "z" + base58(SHA-256(labels.code
 * ‖ the code's bytes)). It covers the whole code, the inviter's DID, relay and expiry with the
 * secret. A nonce of the secret alone bound Bob's answer to no inviter: whoever held an unanswered
 * code could re-wrap its secret in a code naming themselves (the checksum is no MAC), and the
 * answer to that code landed on the inviter's answer topic and passed her checks, so she re-keyed
 * a contact who had answered someone else, or filed a stranger under a code made for another. Now
 * such an answer names a code she never made: challenge_unknown (fixture case rewrapped_code).
 */
export const inviteNonce = (bytes) => multibase(sha256(concatBytes(utf8ToBytes(LABELS.code), bytes)));

/** The three values the one-time secret yields (LABELS). */
export function inviteKeys(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) fail('secret', 'must be 32 bytes');
  const d = (label, n) => hkdf(sha256, secret, undefined, utf8ToBytes(label), n);
  return { answer_topic: 'i/' + hex(d(LABELS.answer_topic, 16)), reply_topic: 'i/' + hex(d(LABELS.reply_topic, 16)), key: d(LABELS.key, 32) };
}

/** Alice: a new code for her CURRENT DID. `secret` and `now` are parameters so a fixture fixes every byte. */
export function makeInvite({ did, relay, now, ttl = TTL, secret = new Uint8Array(randomBytes(32)) }) {
  const digest = didDigest(did);
  if (!(secret instanceof Uint8Array) || secret.length !== 32) fail('secret', 'must be 32 bytes');
  checkTime(now);
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > TTL_MAX) fail('ttl', `must be 1 to ${TTL_MAX} seconds`);
  const exp = now + ttl;
  if (exp > 0xffffffff) fail('ttl', 'the expiry does not fit 4 bytes');
  checkRelay(relay);
  const host = utf8ToBytes(relay), e = new Uint8Array(4);
  new DataView(e.buffer).setUint32(0, exp);
  const body = concatBytes(Uint8Array.of(VERSION), digest, secret, e, Uint8Array.of(host.length), host);
  const bytes = concatBytes(body, sha256(body).subarray(0, 4));
  return { did: 'did:sigelo:' + multibase(digest), secret, exp, relay, bytes, text: PREFIX + multibase(bytes).slice(1), nonce: inviteNonce(bytes) };
}

/** Bob: the code back from its text. Throws code_version, code_checksum, code_length, code_relay, code_expired or code_ttl. */
export function parseInvite(text, now) {
  checkTime(now);
  // Only another version's prefix is a version error. Any other start ("sgI1", "Sgl1", a lost
  // first character) is a typo, and reads as one, like a typo among the digits.
  if (typeof text === 'string' && /^sgl[02-9]/.test(text)) fail('code_version', `a ${text.slice(0, 4)} code; this library reads ${PREFIX}`);
  if (typeof text !== 'string' || !text.startsWith(PREFIX)) fail('code_checksum', `it does not start with ${PREFIX}: paste the whole code, from ${PREFIX} to its last character`);
  const digits = text.slice(PREFIX.length);
  if (digits.length === 0 || digits.length > MAX_DIGITS) fail('code_length', `${digits.length} characters after ${PREFIX}, ${digits.length === 0 ? 'none' : `at most ${MAX_DIGITS}`}: not the whole code, or two codes run together`);
  let at = PREFIX.length;
  for (const ch of digits) {
    at++;
    if (!B58.includes(ch)) fail('code_checksum', `character ${at} ${JSON.stringify(ch)} is not in a long code (base58: no 0, O, I or l): a typo; copy the code, do not retype it`);
  }
  const b = b58decode(digits);
  if (b.length < 5) fail('code_length', `${b.length} bytes, too short for a code: not the whole code`);
  // The checksum first: it sits at the end whatever the layout, so a typo reads as a typo even
  // when it hits the version or the length byte.
  const sum = sha256(b.subarray(0, b.length - 4));
  for (let i = 0; i < 4; i++) if (sum[i] !== b[b.length - 4 + i]) fail('code_checksum', 'its checksum does not match: a character is wrong, missing or extra; copy the whole code again, do not retype it');
  if (b[0] !== VERSION) fail('code_version', `version ${b[0]}, this library reads ${VERSION}`);
  const n = b.length > AT_RLEN ? b[AT_RLEN] : 0;
  if (n < 1 || n > RELAY_MAX || b.length !== FIXED + n) fail('code_length', `${b.length} bytes with a relay length of ${n}: not a code this library makes`);
  const relay = String.fromCharCode(...b.subarray(AT_RELAY, AT_RELAY + n));
  checkRelay(relay);
  const exp = new DataView(b.buffer, b.byteOffset).getUint32(AT_EXP);
  if (now >= exp) fail('code_expired', `it expired at ${iso(exp)}, ${ago(now - exp)} ago by this machine's clock (${iso(now)}): ask for a new code; if it was made just now, this clock is wrong (date -u)`);
  // No inviter makes a code for longer than 7 days. A longer one would keep Bob's one-time secret
  // and key in his store for as long as it says.
  if (exp - now > TTL_MAX + SKEW) fail('code_ttl', `it expires at ${iso(exp)}, ${ago(exp - now)} from now by this machine's clock (${iso(now)}), and a code lives at most 7 days: this clock is behind (date -u), or the code was not made by sigelo`);
  const secret = b.slice(AT_SECRET, AT_EXP);
  return { did: 'did:sigelo:' + multibase(b.slice(AT_DID, AT_SECRET)), secret, exp, relay, bytes: b, text, nonce: inviteNonce(b) };
}

// ---------------------------------------------------------------- handshake messages

// "z" + base58(SHA-256(label ‖ JCS(value))). The transcript of a message is this over the message
// without its proof; the answer id is this over the whole answer.
const digest = (label, value) => multibase(sha256(concatBytes(utf8ToBytes(label), utf8ToBytes(canonicalize(value)))));
const withoutProof = ({ proof, ...rest }) => rest;

/** Bob keys his pending answer by this (store.addAccept); Alice's reply proof names it as its nonce. */
export const answerId = (answer) => digest(LABELS.answer_id, answer);

const opaque = (x, what) => { if (x === undefined) throw new TypeError(`${what} is required: an opaque value from the envelope layer`); };

// SPEC §9 step 2 discards an item holding a float and the bundle still verifies, but such an item
// has no JCS, which the transcript needs. Say so to the sender, under the bundle's name.
function canonicalBundle(bundle) {
  try { canonicalize(bundle); } catch (e) { fail('bundle', `an item has no canonical form (${e.message}): drop it before pairing`); }
}

// { body: { v, typ, did: the signer's CURRENT DID, nonce, transcript }, sig }, signed "sigelo\n" ‖ JCS(body).
function prove(identity, typ, nonce, label, rest) {
  const body = { v: V, typ, did: didOf(identity.genesis), nonce, transcript: attempt('card', () => digest(label, rest)) };
  const sig = signAs(identity, body);
  if (!verifySig(identity.genesis.key, body, sig)) fail('identity', 'the secret does not match genesis.key');
  return { body, sig };
}

/**
 * Bob: the answer to a parsed code. identity = his CURRENT { sign, genesis } (or secret: kdf.mjs signAs); bundle = his bundle;
 * kem_pk = his one-time hybrid public key, prekeys = his signed prekeys: both opaque here (M2).
 * His proof binds the whole code (its nonce: the inviter it names, relay, expiry, secret) and every
 * other member of the answer (transcript).
 */
export function buildAnswer({ code, identity, bundle, kem_pk, prekeys }) {
  opaque(kem_pk, 'kem_pk'); opaque(prekeys, 'prekeys'); canonicalBundle(bundle);
  if (!(code?.bytes instanceof Uint8Array)) throw new TypeError('code is required: what parseInvite returned');
  const rest = { v: V, typ: 'answer', bundle, kem_pk, prekeys };
  return { ...rest, proof: prove(identity, TYP_ANSWER, inviteNonce(code.bytes), LABELS.answer, rest) };
}

/**
 * Alice: the reply, ONLY with the answer_id of an answer checkAnswer accepted (never a value off
 * the wire: signing an unchecked id makes Alice a signing oracle). kem_ct: the key-agreement
 * ciphertext to Bob's kem_pk; prekeys: hers. Both opaque here. Her proof binds Bob's whole answer
 * (answer_id, his kem_pk in it) and every other member of the reply (transcript), kem_ct included:
 * a code holder on the path who swaps the encapsulation, so that Bob derives a K it knows and the
 * two never meet on one topic, fails `transcript` at Bob (fixture case swapped_kem_ct).
 */
export function buildReply({ answer_id, identity, bundle, kem_ct, prekeys }) {
  opaque(kem_ct, 'kem_ct'); opaque(prekeys, 'prekeys'); canonicalBundle(bundle);
  if (typeof answer_id !== 'string') throw new TypeError('answer_id is required: the value checkAnswer returned');
  const rest = { v: V, typ: 'reply', bundle, kem_ct, prekeys };
  return { ...rest, proof: prove(identity, TYP_REPLY, answer_id, LABELS.reply, rest) };
}

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
// sigelo-pair's `card`: the message has its members and nothing else, a bundle, and a claimed DID.
function shape(m, typ, keys) {
  if (!isObj(m) || m.v !== V || m.typ !== typ) fail('card', `not a ${V} ${typ}`);
  for (const k of Object.keys(m)) if (!keys.includes(k)) fail('card', `unknown field ${JSON.stringify(k)}`);
  for (const k of keys) if (!Object.hasOwn(m, k)) fail('card', `missing ${k}`);
  if (!isObj(m.bundle) || m.bundle.typ !== 'bundle') fail('card', 'bundle is not a bundle');
  const p = m.proof;  // {body, sig}, exactly those members (SPEC §3.1)
  if (!isObj(p) || Object.keys(p).length !== 2 || !isObj(p.body) || typeof p.sig !== 'string') fail('card', 'proof is not {body, sig}');
  if (typeof p.body.did !== 'string' || typeof p.body.nonce !== 'string') fail('card', 'proof body has no did or nonce');
  // The transcript and the answer id hash JCS of the message, so one without (a float, even in an
  // item §9 would only discard) is refused here, whole.
  attempt('card', () => canonicalize(m));
}

/** The current key of DID d among the bundle's geneses, as sigelo-pair's keyOf. */
export const keyOf = (bundle, rotations, d) => [bundle.genesis, ...rotations.map((x) => x.next_genesis)].find((g) => didOf(g) === d).key;

// pair: challenge_body, then the invite's own transcript check, then pair: sig. want: the body
// this handshake implies, without its transcript, which is recomputed from the message.
function checkProof(m, want, label, r) {
  const { body, sig } = m.proof, expected = { ...want, transcript: digest(label, withoutProof(m)) };
  if (canonicalize({ ...body, transcript: expected.transcript }) !== canonicalize(expected)) fail('challenge_body', 'differs from the proof this handshake implies');
  if (body.transcript !== expected.transcript) fail('transcript', 'is not the hash of the message it came in: altered on the way');
  if (!verifySig(keyOf(m.bundle, m.bundle.rotations, r.did), expected, sig)) fail('sig', 'does not verify under the current key');
}

// The key agreement runs only once the peer's identity is proven. agree(value, kem_sk) returns
// the 32-byte shared secret, from M2: Alice encapsulates to kem_pk; Bob decapsulates kem_ct with
// the kem_sk he gave addAccept. K itself is contact/kdf.mjs's pairKey; the fixture pins its bytes.
function agreed(agree, value, secret, store, r, kem_sk) {
  if (r.chain.includes(store.self)) fail('self', 'the peer is this store\'s own identity');
  let shared;
  try { shared = agree(value, kem_sk); } catch (e) { fail('kem', e.message); }
  if (!(shared instanceof Uint8Array) || shared.length !== 32) fail('kem', 'the key agreement did not yield 32 bytes');
  return hex(pairKey(hexToBytes(secret), shared, store.self, r.chain[0]));
}

/**
 * Alice: check an answer and store Bob under his ORIGINAL DID. sigelo-pair.mjs's checks, in its
 * order and under its names (each marked "pair:"), plus the invite's own:
 *   card, challenge_unknown, challenge_expired, bundle, card_did, challenge_did (re-key codes),
 *   challenge_body, transcript (own), sig, self (own), kem (own),
 *   revoked, not_contact, bundle, stale_chain, original_did (own), revoked
 * Returns { did, current_did, current_key, attestations, rejected, rekeyed, pair_key, secret,
 * answer_id } or throws MsgError. secret (hex) is gone from the store; the caller needs it for
 * the reply's topic and key, and answer_id for buildReply. rekeyed: an existing contact's pairing
 * key and relay were replaced; show it.
 */
export function checkAnswer(answer, store, now, agree) {
  checkTime(now);
  shape(answer, 'answer', ['v', 'typ', 'bundle', 'proof', 'kem_pk', 'prekeys']);              // pair: card
  const claimed = answer.proof.body.did;
  // pair: challenge_unknown. Single use: the invite and its secret are deleted, and the file
  // saved, before anything else is checked, whatever happens next.
  const p = store.take('invites', answer.proof.body.nonce, now) ?? fail('challenge_unknown', 'not issued here, or already answered');
  if (now >= p.exp) fail('challenge_expired', `expired at ${p.exp}`);                          // pair: challenge_expired
  const r = attempt('bundle', () => verify(answer.bundle, now));                               // pair: bundle (§9, offline)
  if (r.did !== claimed) fail('card_did', `the bundle resolves to ${r.did}, the proof claims ${claimed}`);  // pair: card_did
  // pair: challenge_did. A re-key code is pinned to the contact it was made for. A new contact's
  // code goes to whoever holds it (contract sigelo-invite/0): the DID is learnt here.
  if (p.peer !== null && !r.chain.includes(p.peer)) fail('challenge_did', `this code is for ${p.peer}, answered by ${r.chain[0]}`);
  checkProof(answer, { v: V, typ: TYP_ANSWER, did: r.did, nonce: p.nonce }, LABELS.answer, r);  // pair: challenge_body, sig
  const pair_key = agreed(agree, answer.kem_pk, p.secret, store, r);                            // own: self, kem
  const a = store.admit(answer.bundle, r, p.name, { relay: p.relay, pair_key }, now);         // pair: revoked … revoked
  return { ...a, pair_key, secret: p.secret, answer_id: answerId(answer) };
}

/**
 * Bob: check Alice's reply and store her under her ORIGINAL DID. The same order; code_did stands
 * where sigelo-pair has challenge_did: Bob accepts only if the code's DID is in Alice's chain.
 *   card, challenge_unknown, challenge_expired, bundle, card_did, code_did, challenge_body,
 *   transcript, sig, self, kem, revoked, not_contact, bundle, stale_chain, original_did, revoked
 * Returns { did, current_did, current_key, attestations, rejected, rekeyed, pair_key } or throws MsgError.
 */
export function checkReply(reply, store, now, agree) {
  checkTime(now);
  shape(reply, 'reply', ['v', 'typ', 'bundle', 'proof', 'kem_ct', 'prekeys']);                // pair: card
  const claimed = reply.proof.body.did;
  const p = store.take('accepts', reply.proof.body.nonce, now) ?? fail('challenge_unknown', 'answers no pending answer of ours, or already replied');  // pair: challenge_unknown
  if (now >= p.exp) fail('challenge_expired', `the code expired at ${p.exp}`);                // pair: challenge_expired
  const r = attempt('bundle', () => verify(reply.bundle, now));                                // pair: bundle
  if (r.did !== claimed) fail('card_did', `the bundle resolves to ${r.did}, the proof claims ${claimed}`);  // pair: card_did
  if (!r.chain.includes(p.code_did)) fail('code_did', `the code names ${p.code_did}, which is not in the replier's chain`);  // pair: challenge_did's place
  checkProof(reply, { v: V, typ: TYP_REPLY, did: r.did, nonce: p.nonce }, LABELS.reply, r);    // pair: challenge_body, sig
  const pair_key = agreed(agree, reply.kem_ct, p.secret, store, r, p.kem_sk);                   // own: self, kem
  const a = store.admit(reply.bundle, r, p.name, { relay: p.relay, pair_key, ...(p.tier && { tier: p.tier, tier_by: 'owner' }) }, now);  // pair: revoked … revoked
  return { ...a, pair_key };
}
