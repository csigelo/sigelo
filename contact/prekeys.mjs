// SPDX-License-Identifier: MIT
// sigelo-msg/0 prekeys (design/relay-plan.md §3 "Prekeys"). A holder hands each contact a signed
// bundle of single-use X-Wing (ML-KEM-768 + X25519) public keys; a sender starts an epoch by
// encapsulating to one. Sent only to that contact, inside the pairwise mailbox: no directory.
//   holder: const p = new Prekeys(); const signed = p.issue(me, pair, now)   → send signed; reissue when p.due(now, me)
//   sender: checkPrekeys(signed, contact, pair, now)                         → the keys, or throws MsgError
//   handshake: kemKey, kemEncapsulate, kemDecapsulate (at the end)
//
// What a copy of the holder's secrets (its state file, taken once) opens: the epochs the contact
// begins on keys the copy holds. A sender begins each epoch on the first unused key of its bundle,
// in issue order, so keys left listed until used kept a copy reading for twenty epochs, twenty
// weeks of a contact writing weekly. Every REPLACE_DAYS the holder replaces all the one-time keys
// it lists at once, and the sender ends its epoch on a bundle that lists none of the keys it held
// (envelope.mjs acceptPrekeys): a copy opens at most about one week, until the next replacement
// reaches the sender. A relay that withholds the replacement stretches that to the old bundle's
// expiry (TTL) plus an epoch. Epochs on the last-resort key (flagged) are open to a copy while that
// key is listed (LAST_RESORT_DAYS). Within an epoch there is no recovery: no step of the chain
// takes a fresh secret.
// Bounds against a contact that begins epochs to have keys retired (consume): a reissue for want
// of keys at most every REISSUE seconds, at most RETIRED_MAX retired secrets and USED_MAX used ids
// kept, the oldest going first.
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { canonicalize, verifySig } from 'sigelo';
import { MSG_V, checkNow, fail, hex, signAs } from './kdf.mjs';

export const ONE_TIME = 20, REPLENISH_BELOW = 5, LAST_RESORT_DAYS = 30, TTL = 31 * 86400, SKEW = 300;
export const REPLACE_DAYS = 7, REISSUE = 3600, RETIRED_MAX = 8 * ONE_TIME, USED_MAX = 1024;
const PK = 1216; // X-Wing public key bytes
const BODY = ['v', 'typ', 'did', 'pair', 'iat', 'exp', 'keys', 'last_resort'];

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
export const exact = (o, keys) => isObj(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
const b64u = (b) => Buffer.from(b).toString('base64url');
function unb64u(s, len, check, what) {
  // Buffer's decoder skips characters outside the alphabet; re-encoding is what makes it strict.
  const b = typeof s === 'string' ? Buffer.from(s, 'base64url') : null;
  if (b === null || b.length !== len || b.toString('base64url') !== s) fail(check, `${what}: expected ${len} bytes as unpadded base64url`);
  return new Uint8Array(b);
}

// The holder's private half, one per contact. Secret keys stay here; only ids leave after use.
export class Prekeys {
  constructor() {
    this.did = null;           // the DID the last bundle was signed as
    this.oneTime = new Map();  // id → { publicKey, secretKey, iat: when first listed }, in issue order
    this.lastResort = [];      // [{ id, iat, publicKey, secretKey }], newest first, at most two
    this.retired = new Map();  // id → { secretKey, lastResort, until, iat }: never listed again (retire), oldest first
    this.acked = 0;            // when the newest key the contact began an epoch on was first listed (consume)
    this.used = new Map();     // id consumed → until: a second envelope naming one fails prekey_reused
    this.replaced = 0;         // when the one-time keys listed were last replaced all at once (0: never)
    this.issued = 0;           // when the last bundle was issued (0: never)
  }
  get remaining() { return this.oneTime.size; }
  // Reissue after the holder's own rotation (the contact begins no epoch on a bundle signed by a
  // key the holder has left: envelope.mjs startEpoch), when the last-resort key is a month old
  // (bundles live 31 days), when the one-time keys listed are REPLACE_DAYS old (the header), or
  // below five one-time keys left, at most every REISSUE seconds: the contact decides how fast
  // keys go, and each bundle costs twenty keygens here and one of this agent's messages per day at
  // the relay. Meanwhile its epochs begin on the last-resort key. me: { current_did }.
  due(now, me) {
    checkNow(now);
    return me.current_did !== this.did || !this.lastResort.length || now - this.lastResort[0].iat >= LAST_RESORT_DAYS * 86400
      || (this.oneTime.size > 0 && now - this.replaced >= REPLACE_DAYS * 86400)
      || (this.oneTime.size < REPLENISH_BELOW && now - this.issued >= REISSUE);
  }

  // Stops listing every held key; the next issue() lists only fresh ones. issue() calls it when
  // the identity key has changed: after a recovery the thief may hold a copy of these secrets, and
  // listing them under the new key would keep him on the encryption layer. A caller may call it
  // itself on suspicion. The secrets stay, unlisted, until now + TTL: a bundle already sent that
  // lists them can begin an epoch until then, and that epoch should still open.
  retire(now) {
    this.retireOneTime(now);
    for (const k of this.lastResort) this.#unlist(k.id, k, true, now);
    this.lastResort = [];
  }
  // The same for the one-time keys alone, or for those issued before `before` (an id): the sender
  // will begin no epoch on them (envelope.mjs, "One-time keys"). Unlisted, they no longer count as
  // left (due), so the next bundle replenishes; kept until now + TTL, should a first envelope on
  // one arrive after all.
  retireOneTime(now, before = null) {
    checkNow(now);
    for (const [id, k] of this.oneTime) {
      if (id === before) break;
      this.#unlist(id, k, false, now);
      this.oneTime.delete(id);
    }
  }
  // At most RETIRED_MAX are kept, the oldest going first (an epoch begun on one then fails
  // prekey_unknown): consume retires up to nineteen at each epoch the contact begins, as fast as
  // it likes, and a forced reissue lists twenty more every REISSUE seconds.
  #unlist(id, { secretKey, iat }, lastResort, now) {
    this.retired.set(id, { secretKey, lastResort, until: now + TTL, iat });
    for (const [old, k] of this.retired) {
      if (this.retired.size <= RETIRED_MAX) break;
      k.secretKey.fill(0);
      this.retired.delete(old);
    }
  }
  // Deletes the retired secrets and used ids past their time: at each issue and at each
  // envelope.mjs expire (hourly in the carrier), so a contact that writes no more leaves none
  // behind. A used id goes TTL after its use: no bundle valid by then lists it. Ids written before
  // they had a time get one now. → whether anything changed.
  expire(now) {
    checkNow(now);
    let changed = false;
    for (const [id, k] of this.retired) if (now >= k.until) { k.secretKey.fill(0); this.retired.delete(id); changed = true; }
    for (const [id, until] of this.used) {
      if (until === undefined) { this.used.set(id, now + TTL); changed = true; } else if (now >= until) { this.used.delete(id); changed = true; }
    }
    return changed;
  }

  // Replaces every one-time key listed once they are REPLACE_DAYS old, else tops them up to
  // twenty, rotates the last-resort key if due, and returns a bundle signed by the identity key
  // ("sigelo\n" + JCS(body), SPEC §3). The bundle lists EVERY unused key and replaces the previous
  // one at the contact. me: { current_did, sign } (or secret: kdf.mjs signAs).
  // rng order, for reproducible fixtures: per new one-time key id (16) then keygen seed (32); then
  // the same for a new last-resort key.
  issue(me, pair, now, rng = randomBytes) {
    checkNow(now);
    if (me.current_did !== this.did) this.retire(now);
    this.did = me.current_did;
    // All at once, not each key at its own age: replaced one by one, keys issued at different
    // times would each bring a reissue of their own, every week from then on.
    if (this.oneTime.size > 0 && now - this.replaced >= REPLACE_DAYS * 86400) this.retireOneTime(now);
    this.expire(now);
    if (this.oneTime.size === 0) this.replaced = now;
    this.issued = now;
    const fresh = () => {
      const id = hex(rng(16));
      if (this.oneTime.has(id) || this.used.has(id) || this.retired.has(id) || this.lastResort.some((k) => k.id === id)) fail('prekeys', 'the random source repeated a prekey id');
      return { id, ...xwing.keygen(rng(32)) };
    };
    while (this.oneTime.size < ONE_TIME) { const { id, publicKey, secretKey } = fresh(); this.oneTime.set(id, { publicKey, secretKey, iat: now }); }
    if (!this.lastResort.length || now - this.lastResort[0].iat >= LAST_RESORT_DAYS * 86400) {
      // The previous last-resort key stays one more month: epochs begun on it may still be queued.
      for (const old of this.lastResort.splice(1)) old.secretKey.fill(0);
      this.lastResort.unshift({ ...fresh(), iat: now });
    }
    const lr = this.lastResort[0];
    const body = { v: MSG_V, typ: 'prekeys', did: me.current_did, pair, iat: now, exp: now + TTL,
      keys: [...this.oneTime].map(([id, k]) => ({ id, pk: b64u(k.publicKey) })), last_resort: { id: lr.id, pk: b64u(lr.publicKey) } };
    return { body, sig: signAs(me, body) };
  }

  // For the envelope that begins an epoch; nothing is consumed until it has passed every check
  // (consume), so a forged envelope cannot burn keys.
  take(id) {
    if (this.used.has(id)) fail('prekey_reused', `prekey ${id} was already used: a new epoch needs a fresh one`);
    const k = this.oneTime.get(id);
    if (k) return { secretKey: k.secretKey, lastResort: false };
    const lr = this.lastResort.find((x) => x.id === id);
    if (lr) return { secretKey: lr.secretKey, lastResort: true };  // reusable, flagged: weaker forward secrecy
    const old = this.retired.get(id);
    if (old) return { secretKey: old.secretKey, lastResort: old.lastResort };
    return fail('prekey_unknown', `prekey ${id} was never issued to this contact`);
  }
  // Whether take(id) would hand out a key: an epoch begun on it could begin again (envelope.mjs expire).
  holds(id) { return !this.used.has(id) && (this.oneTime.has(id) || this.lastResort.some((k) => k.id === id) || this.retired.has(id)); }
  // After the envelope beginning an epoch on `id` passed every check. A sender begins each epoch on
  // the first key of its bundle it has not used, and bundles list keys in issue order: the keys
  // issued before `id` and still held here are ones it believes used (their first envelopes were
  // refused, lost or withheld). It will not pick them, so they are retired, not left counting.
  // Begun on a last-resort key (not deleted: it may begin others), the sender had no key left
  // unused in the bundle it holds. That bundle was issued no earlier than this last-resort key,
  // nor than the newest key it began an epoch on (acked), and a bundle lists every key unused
  // when issued, so the keys listed by then are ones it believes used: retired. Keys first listed
  // since it may not have seen yet (a bundle in flight, as right after its rotation): they stay.
  consume(id, now) {
    const lr = this.lastResort.find((x) => x.id === id) ?? (this.retired.get(id)?.lastResort ? this.retired.get(id) : null);
    if (lr) {
      const seen = Math.max(this.acked, lr.iat ?? 0);
      for (const [k, v] of this.oneTime) if ((v.iat ?? 0) <= seen) { this.#unlist(k, v, false, now); this.oneTime.delete(k); }
      return;
    }
    if (this.oneTime.has(id)) this.retireOneTime(now, id);
    const from = this.oneTime.has(id) ? this.oneTime : this.retired.has(id) ? this.retired : null;
    if (!from) return;
    const k = from.get(id);
    this.acked = Math.max(this.acked, k.iat ?? 0);
    k.secretKey.fill(0); from.delete(id);
    // The secret is gone, so an id no longer kept here fails prekey_unknown instead: refused all
    // the same. At most USED_MAX: the contact decides how many it spends.
    this.used.set(id, now + TTL);
    for (const [old] of this.used) { if (this.used.size <= USED_MAX) break; this.used.delete(old); }
  }
}

// Sender side: a contact's bundle, checked before any key in it is used. contact: the store's
// record { did, current_did, current_key } (accept/node/sigelo-pair.mjs). Signed by the contact's
// CURRENT key only: after a recovery, the old key may be a thief's, and its prekeys would be his.
export function checkPrekeys(signed, contact, pair, now) {
  const P = 'prekeys';
  checkNow(now);
  if (!exact(signed, ['body', 'sig']) || typeof signed.sig !== 'string') fail(P, 'not exactly {body, sig}');
  const b = signed.body;
  if (!exact(b, BODY)) fail(P, `body fields are not exactly ${BODY.join(' ')}`);
  if (b.v !== MSG_V || b.typ !== 'prekeys') fail(P, `v must be "${MSG_V}" and typ "prekeys"`);
  // Unverified until the signature check below: name the check, never echo the claimed DID.
  if (b.did !== contact.current_did) fail(P, 'not signed as the contact\'s current DID');
  if (b.pair !== pair) fail(P, 'issued for another pairing');
  if (![b.iat, b.exp].every((t) => Number.isSafeInteger(t) && t >= 0) || b.exp <= b.iat || b.exp - b.iat > TTL) fail(P, `iat and exp must be Unix seconds, exp after iat by at most ${TTL}`);
  // SKEW: the holder's clock may run a little ahead of ours; expiry is what bounds a bundle.
  if (now + SKEW < b.iat || now >= b.exp) fail(P, `valid from ${b.iat} to ${b.exp}, now is ${now}`);
  if (!Array.isArray(b.keys) || b.keys.length > ONE_TIME) fail(P, `keys must be an array of at most ${ONE_TIME}`);
  const ids = new Set();
  const key = (k, what) => {
    if (!exact(k, ['id', 'pk']) || typeof k.id !== 'string' || !/^[0-9a-f]{32}$/.test(k.id)) fail(P, `${what}: not {id: 16 bytes hex, pk}`);
    if (ids.has(k.id)) fail(P, `${what}: id ${k.id} appears twice`);
    ids.add(k.id);
    return { id: k.id, pk: unb64u(k.pk, PK, P, what) };
  };
  const keys = b.keys.map((k, i) => key(k, `keys[${i}]`)), last_resort = key(b.last_resort, 'last_resort');
  try { canonicalize(b); } catch (e) { fail(P, `body is not canonical JSON: ${e.message}`); }
  if (!verifySig(contact.current_key, b, signed.sig)) fail(P, 'signature does not verify under the contact\'s current key');
  return { did: b.did, iat: b.iat, exp: b.exp, keys, last_resort };
}

// The invite handshake's one-time key agreement (relay-plan §3 "Invite handshake"; invite.mjs
// leaves kem_pk, kem_ct and agree() to this layer). Bob sends kemKey().pk in his answer; Alice
// replies with kemEncapsulate(pk).ct; both hold the same 32-byte shared secret for pairKey.
// Values travel as unpadded base64url, like prekeys. rng order: keygen seed (32); randomness (64).
export function kemKey(rng = randomBytes) {
  const k = xwing.keygen(rng(32));
  return { pk: b64u(k.publicKey), secretKey: k.secretKey };
}
export function kemEncapsulate(pk, rng = randomBytes) {
  const raw = unb64u(pk, PK, 'kem', 'kem_pk');
  let r;
  try { r = xwing.encapsulate(raw, rng(64)); } catch (e) { fail('kem', `kem_pk refused: ${e.message}`); }
  return { ct: b64u(r.cipherText), shared: r.sharedSecret };
}
// The one-time secret key is zeroed, whatever the outcome: it serves one handshake. An X25519 part
// that is a low-order point makes X-Wing throw; that is a refused kem_ct like any other.
export function kemDecapsulate(ct, secretKey) {
  try {
    const raw = unb64u(ct, 1120, 'kem', 'kem_ct');
    try { return xwing.decapsulate(raw, secretKey); } catch (e) { return fail('kem', `kem_ct refused: ${e.message}`); }
  } finally { secretKey.fill(0); }
}
