// SPDX-License-Identifier: MIT
// sigelo-msg/0 key schedule (design/relay-plan.md §3): pairing key, mailbox topics, the epoch
// chain. HKDF-SHA256 and HMAC-SHA256 only; every label below is part of the wire contract.
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { sign } from 'sigelo';

export const MSG_V = 'sigelo-msg/0';

// Every refusal in contact/ names its check, as accept/node/sigelo-pair.mjs's PairingError does:
// one class for invite, envelope, prekeys and carrier, so a caller catches MsgError and reads .check.
// extra, for whoever debugs (SIGELO_DEBUG=1 prints it): cause, the error underneath; http, the
// relay's answer ({ url, status, body }).
export class MsgError extends Error {
  constructor(check, why, extra) {
    super(`${check}: ${why}`, extra?.cause === undefined ? undefined : { cause: extra.cause });
    this.check = check;
    if (extra?.http) this.http = extra.http;
  }
}
export const fail = (check, why, extra) => { throw new MsgError(check, why, extra); };

// The identity's signature over a body ("sigelo\n" ‖ JCS(body), SPEC §3). me.sign is the signer the
// caller hands in (sigelo-agent-keys.ts: a plain file, a keychain, a key agent), so these modules
// never see where the key rests; me.secret, the seed itself, is what callers of 0.1.7 pass.
export const signAs = (me, body) => (typeof me.sign === 'function' ? me.sign(body) : sign(me.secret, body));

export const hex = (b) => bytesToHex(b);
export function unhex(s, len, check) {
  if (typeof s !== 'string' || !new RegExp(`^[0-9a-f]{${len * 2}}$`).test(s)) fail(check, `expected ${len} bytes as lowercase hex`);
  return Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));
}
// `now` as every caller passes it: Unix seconds. A float or a string would reach a signed body
// (no floats, SPEC §3) or make a time comparison silently false.
export function checkNow(now) { if (!Number.isSafeInteger(now) || now < 0) fail('time', 'now must be Unix seconds: a safe integer, not negative'); return now; }
const bytes = (b, len, what) => { if (!(b instanceof Uint8Array) || b.length !== len) fail('kdf', `${what} must be ${len} bytes`); return b; };

// The labels concatenate DIDs without a length prefix. That is unambiguous only because a DID is
// "did:sigelo:z" + base58btc and base58btc has no ":", so a DID cannot run into the next one;
// the check keeps a caller from passing anything else.
const DID = /^did:sigelo:z[1-9A-HJ-NP-Za-km-z]{1,63}$/;
export function checkDid(d, what) { if (typeof d !== 'string' || !DID.test(d)) fail('kdf', `${what} is not a did:sigelo`); return d; }

// K = HKDF(secret ‖ shared secret, salt "sigelo-pair/0", info = the two ORIGINAL DIDs sorted).
// secret: the invite's one-time secret; shared: the handshake's X-Wing shared secret. Sorted, so
// both sides derive the same K whoever invited.
export function pairKey(secret, shared, didA, didB) {
  const [a, b] = [checkDid(didA, 'didA'), checkDid(didB, 'didB')].sort();
  if (a === b) fail('kdf', 'a pairing needs two different DIDs');
  return hkdf(sha256, concatBytes(bytes(secret, 32, 'secret'), bytes(shared, 32, 'shared')), utf8ToBytes('sigelo-pair/0'), utf8ToBytes(a + b), 32);
}

// `pair` in signed message and prekey bodies: 16 bytes of HKDF(K, salt "sigelo-pair-id/0"), hex.
// It ties a signed body to one pairing without revealing K.
export const pairId = (K) => hex(hkdf(sha256, bytes(K, 32, 'K'), utf8ToBytes('sigelo-pair-id/0'), new Uint8Array(0), 16));

// ISO 8601 week of a Unix time, UTC: "2026-W41". The week belongs to the year of its Thursday.
export function isoWeek(unix) {
  if (!Number.isSafeInteger(unix) || unix < 0) fail('kdf', 'time must be Unix seconds');
  const day = Math.floor(unix / 86400), dow = (day + 3) % 7;     // 1970-01-01 was a Thursday; 0 = Monday
  const thursday = new Date((day - dow + 3) * 86400000), year = thursday.getUTCFullYear();
  const week = Math.floor((thursday - Date.UTC(year, 0, 1)) / (7 * 86400000)) + 1;
  return `${year}-W${String(week).padStart(2, '0')}`;
}

// Mailbox topic: "m/" + hex(16 bytes of HKDF(K, salt "sigelo-topic/0",
// info = sender original DID ‖ "\n" ‖ recipient original DID ‖ "\n" ‖ ISO week)). One per direction per week.
export function topic(K, from, to, week) {
  if (typeof week !== 'string' || !/^\d{4}-W\d{2}$/.test(week)) fail('kdf', 'week must look like 2026-W41');
  const info = utf8ToBytes(`${checkDid(from, 'from')}\n${checkDid(to, 'to')}\n${week}`);
  return 'm/' + hex(hkdf(sha256, bytes(K, 32, 'K'), utf8ToBytes('sigelo-topic/0'), info, 16));
}

// The epoch id: the first 16 bytes of SHA-256(prekey id ‖ X-Wing ciphertext), the key agreement an
// envelope header carries at counter 0, and after it until a reply (envelope.mjs, "Epoch
// recovery"). A signed body names its epoch, so it can begin only the epoch of that one
// encapsulation: whoever holds K (a copy of the receiver's state) and re-seals old signed bodies
// under a fresh encapsulation, once the receiver has forgotten their epoch, gets another id, and
// the original header names a prekey spent with it (envelope.mjs open, epoch_id). A random id,
// chosen by the sender, tied the body to nothing the receiver could check.
export const epochId = (kem) => sha256(bytes(kem, 16 + 1120, 'key agreement')).slice(0, 16);

// CK0 = HKDF(X-Wing shared secret, salt K, info "sigelo-msg/0 epoch" ‖ epoch id ‖ sender DID ‖ recipient DID).
// ORIGINAL DIDs: both sides store the contact under them, and the sender's current DID can change
// mid-epoch and is only learnt after decryption.
export function epochKey(shared, K, epochId, from, to) {
  const info = concatBytes(utf8ToBytes('sigelo-msg/0 epoch'), bytes(epochId, 16, 'epoch id'), utf8ToBytes(checkDid(from, 'from') + checkDid(to, 'to')));
  return hkdf(sha256, bytes(shared, 32, 'shared'), bytes(K, 32, 'K'), info, 32);
}

// One chain step: message key HMAC(CK_i, 0x01), next chain key HMAC(CK_i, 0x02). CK_i is zeroed:
// a key that is gone cannot open an earlier message (forward secrecy inside the epoch). Zeroing in
// JavaScript is best effort: it clears this copy, not what the engine may have copied.
export function step(ck) {
  const mk = hmac(sha256, bytes(ck, 32, 'chain key'), Uint8Array.of(1)), next = hmac(sha256, ck, Uint8Array.of(2));
  ck.fill(0);
  return { mk, next };
}
