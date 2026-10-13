// SPDX-License-Identifier: MIT
// sigelo-msg/0 envelopes (design/relay-plan.md §3 "Envelope", §11 "Epoch recovery"): one
// end-to-end encrypted, signed message between two contacts, as the binary MQTT payload the relay
// stores. No network code.
//   const s = session({ me, peer, K, hold }) me: { did, current_did, secret }; peer: the store's contact record;
//                                           hold: the longest the relay keeps an envelope for this reader
//   acceptPrekeys(s, signedBundle, now)     the contact's prekeys, checked (prekeys.mjs)
//   send(s, { label, content }, now)        → { bytes, topic, epoch, n, prekey, last_resort }
//   open(s, bytes, topic, now)              → { body, sig, epoch, n, prekey, last_resort }, or throws MsgError(.check)
//   expire(s, now)                          deletes the receiving keys past their time (open does it first)
//   prekeysMissing(s, now)                  why no epoch could begin now (no usable bundle from the contact), or null
//   restartEpoch(s, refused?)               the relay refused or lost an epoch's first envelope: begin a new epoch
//
// Layout (bytes): version 0x01 (1) | kind (1) | epoch id (16) | counter, u32 big-endian (4)
//   | only when the kind byte holds CARRIES (0x80): prekey id (16) + X-Wing ciphertext (1,120)
//   | XChaCha20-Poly1305 nonce (24) | ciphertext + tag (n + 16). The "header" is everything before the nonce.
// So an envelope is its padded plaintext plus 62 bytes, or plus 1,198 while it carries. A sender
// writes none longer than MAX_ENVELOPE; a receiver refuses a padded plaintext over MAX_PADDED.
// The kind byte: the kind in its low 7 bits (0 message, 1 and 2 invite answer and reply, 3 reserved
// for groups), plus CARRIES when the header carries the key agreement that begins its epoch. Only a
// message carries one, and counter 0 always does; later counters may or may not (Epoch recovery).
// Additional data = header ‖ UTF-8 topic, so an envelope moved to another mailbox or week fails.
// Plaintext = JCS({body, sig}) then ISO/IEC 7816-4 padding: one 0x80 byte, then 0x00 up to the
// next multiple of 256 (always 1 to 256 bytes added). JCS text ends in "}", never 0x00, so the
// last non-zero byte is the marker. A receiver refuses any other padding and any plaintext that
// is not exactly the JCS of what it parses to.
// Epochs: a sender begins one by encapsulating to a contact prekey and keeps it for at most 7
// days or 1,000 messages (counters 0..999), and begins a new one as soon as either side's current
// DID changes; kdf.mjs has the chain. The epoch id is the hash of the prekey id and X-Wing
// ciphertext that begin the epoch (kdf.epochId), so a signed body, which names its epoch, can begin
// no epoch but the one its own header carries: a receiver that has forgotten an epoch (its time is
// up) cannot be made to open its signed bodies again under a fresh encapsulation by whoever holds
// K; the original header names a prekey spent with it (prekey_reused, then prekey_unknown), or one
// ended here (replay).
// Epoch recovery (Signal's rule): the sender repeats the prekey id and X-Wing ciphertext in every
// envelope of its epoch until it has opened a reply in that direction: an envelope from the
// contact signed SKEW or more after the epoch began (by the contact's clock, so SKEW makes it one
// written after). The first envelope of an epoch that reaches the receiver begins it there,
// whatever its counter, and an earlier counter that arrives later opens from the keys kept behind
// (WINDOW). A reader offline longer than the relay keeps envelopes loses those messages, not the
// rest of the epoch. Cost: 1,136 bytes more per envelope until the reply, so a message whose
// envelope is less than 1,136 bytes under the reader's size cap at the relay is refused while its
// epoch carries (MAX_ENVELOPE), and goes once a reply has stopped it. The reply is evidence,
// not proof, that the contact opened the epoch: if every envelope that carried it was lost and the
// contact wrote without reading, the next one fails epoch_unknown there, and the carrier answers
// that with a fresh bundle, on which the sender begins a new epoch (acceptPrekeys).
// One-time keys: a sender begins each epoch on the first key of its bundle it has not used, so a
// key used on an epoch the contact never opened would stay listed, and counted by the holder as
// left (Prekeys.due), while the sender never picks it again. After twenty such epochs (their
// envelopes refused by the relay, or withheld) every epoch began on the last-resort key, for
// months. So: an epoch's first envelope the relay refused puts its key back (restartEpoch with
// `refused`); and a holder retires the keys a sender has skipped, those listed before the one an
// epoch began on (Prekeys.consume), or all those listed in its bundle when an epoch begins on the
// last-resort key (Prekeys.consume, which keeps keys of a bundle the sender cannot have read yet).
// The holder also replaces all its one-time keys every REPLACE_DAYS (prekeys.mjs: what a copy of
// its state opens), and a sender ends its epoch on such a bundle (acceptPrekeys).
// Receiving keys go by time too (forward secrecy for an envelope withheld or lost on the way): a
// message key skipped over (out of order) at `hold` + SKEW after the envelope that skipped it was
// opened, since the relay keeps nothing longer than `hold` and the skipped one was written before;
// an epoch's chain key and seen-set at EPOCH_SECONDS + `hold` + SKEW after the envelope that
// began it here was opened, or once counter 999 is opened and no skipped key is left. An epoch begun on a
// last-resort prekey, which may begin others, leaves its id (`in.ended`) for as long as that key
// is held, so no envelope of it that carries the encapsulation, replayed, can begin it again: it
// fails replay. A contact begins epochs as fast as its allowance at the relay lets it (50,000
// messages a day pooled), so at most EPOCHS_MAX live epochs are kept per contact, the oldest going
// first (its later envelopes then fail epoch_unknown, prekey_reused or replay), and no ended id
// goes before its key: a contact that would hold more than ENDED_MAX epochs begun on last-resort
// keys still held is refused a new one (epoch_limit) until older ids go with their key. An honest
// sender keeps one or two epochs live, and begins one on the last-resort key only when it has run
// out of one-time keys.
// Body: {v: "sigelo-msg/0", typ: "message", from: sender's current DID, to: recipient's original
// DID, pair (kdf.pairId), epoch (hex), n, iat, label, content}; sig is Ed25519 over
// "sigelo\n" ‖ JCS(body) (SPEC §3). A receiver accepts `from` only as the contact's current DID.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize, parseBytes, sign, verifySig } from 'sigelo';
import { MSG_V, checkDid, checkNow, epochId, epochKey, fail, hex, isoWeek, pairId, step, topic, unhex } from './kdf.mjs';
import { Prekeys, SKEW, checkPrekeys, exact } from './prekeys.mjs';

export const KIND = { message: 0, invite_answer: 1, invite_reply: 2, group: 3 };
// The kind byte's high bit: this header carries the prekey id and X-Wing ciphertext that begin its
// epoch (the header's "Layout" and "Epoch recovery").
export const CARRIES = 0x80;
export const EPOCH_MESSAGES = 1000, EPOCH_SECONDS = 7 * 86400, BLOCK = 256, MAX_PADDED = 1 << 20;
// The longest envelope a sender writes: the largest message a relay stores, on any tier (relay-plan
// §3 "Allowances", 1 MB for Pro; relay/allowance.mjs). A relay closes the connection, with no
// notice, on a packet past that and its header room (relay/server.mjs MAX_FRAME), and a carrier
// sends what it queued first at every connection: an envelope over it would block every later one.
// A padded plaintext of at most a reader's cap (256 KiB free, 1 MiB Pro) less 1,198 bytes always
// fits it (the header's "Layout"); up to 1,136 bytes more fits once a reply has stopped its epoch
// carrying the encapsulation.
export const MAX_ENVELOPE = 1 << 20;
// Out of order: any counter above the highest one opened in its epoch is accepted, and one up to
// WINDOW below it if not yet opened: of the keys in between, only those WINDOW nearest are kept.
// Keys further behind are deleted; such a counter fails out_of_order, a counter already opened
// fails replay. An epoch begun at counter n (its earlier envelopes not, or not yet, delivered)
// keeps the WINDOW keys below n alike. Forward jumps are not capped because the relay may refuse
// or expire a long run of envelopes (quota, size), and a cap would leave the rest of the epoch
// unreadable. The cost: an envelope with a forged counter makes the receiver derive up to 999
// chain steps (about 30 ms on a phone) before the AEAD refuses it, keeping nothing; one that
// carries an encapsulation naming a held prekey adds a decapsulation (8 ms).
export const WINDOW = 64;
export const EPOCHS_MAX = 64, ENDED_MAX = 1024;
// The longest a relay keeps an envelope: the Pro tier's 90 days (relay/allowance.mjs, relay-plan
// §11), the hold of a session that names none. A carrier passes its reader's own retention.
export const HOLD = 90 * 86400;
const HEAD = 22, KEM = 16 + 1120, NONCE = 24, TAG = 16;
const BODY = ['v', 'typ', 'from', 'to', 'pair', 'epoch', 'n', 'iat', 'label', 'content'];

// kem: the prekey id and X-Wing ciphertext (16 + 1,120 bytes) when the header carries them, else
// null; counter 0 always carries them.
export function header(kind, epoch, n, kem = null) {
  if (n === 0 && kem === null) fail('kind', 'counter 0 must carry the encapsulation that begins its epoch');
  if (kem !== null && kind !== KIND.message) fail('kind', `kind ${kind} carries no encapsulation (flag 0x80)`);
  const h = new Uint8Array(HEAD + (kem ? KEM : 0));
  h[0] = 1; h[1] = kind | (kem ? CARRIES : 0); h.set(epoch, 2); new DataView(h.buffer).setUint32(18, n);
  if (kem) h.set(kem, HEAD);
  return h;
}

// Structure only; nothing here is authenticated until the AEAD check in open().
export function parse(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 2) fail('length', 'shorter than the header');
  if (bytes[0] !== 1) fail('version', `version byte ${bytes[0]}, this reader knows 1`);
  const kind = bytes[1] & 0x7f, carries = (bytes[1] & CARRIES) !== 0;
  if (kind === KIND.group) fail('kind', 'kind 3 is reserved for groups');
  if (kind > KIND.group) fail('kind', `unknown kind ${kind}`);
  if (carries && kind !== KIND.message) fail('kind', `kind ${kind} carries no encapsulation (flag 0x80)`);
  if (bytes.length < HEAD) fail('length', 'shorter than the header');
  const n = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(18), hl = carries ? HEAD + KEM : HEAD;
  // One spelling per message: an epoch begins only with its key agreement, so counter 0 without it
  // is no envelope any sender writes.
  if (n === 0 && !carries) fail('kind', 'counter 0 without the encapsulation flag (0x80)');
  const ct = bytes.length - hl - NONCE;
  if (ct < BLOCK + TAG || (ct - TAG) % BLOCK !== 0 || ct - TAG > MAX_PADDED) fail('length', `${bytes.length} bytes is not a header, a nonce and a padded ciphertext`);
  return { kind, carries, epoch: bytes.subarray(2, 18), n, prekey: carries ? bytes.subarray(HEAD, HEAD + 16) : null, kem: carries ? bytes.subarray(HEAD + 16, hl) : null,
    head: bytes.subarray(0, hl), nonce: bytes.subarray(hl, hl + NONCE), ct: bytes.subarray(hl + NONCE) };
}

export function pad(b) {
  const out = new Uint8Array((Math.floor(b.length / BLOCK) + 1) * BLOCK);
  out.set(b); out[b.length] = 0x80;
  return out;
}
export function unpad(p) {
  let i = p.length - 1;
  while (i >= 0 && p[i] === 0) i--;
  if (p.length % BLOCK !== 0 || i < 0 || p[i] !== 0x80 || p.length - i > BLOCK) fail('padding', 'not 0x80 then zeros up to the next multiple of 256');
  return p.subarray(0, i);
}

// One session per contact, both directions. K: the pairing key (kdf.pairKey). hold: seconds the
// relay may keep an envelope for this reader (its retention), which bounds how long receiving keys
// are kept. The caller updates s.me after its own rotation and s.peer when the store merges the
// contact's rotation.
export function session({ me, peer, K, hold = HOLD }) {
  checkDid(me.did, 'me.did'); checkDid(peer.did, 'peer.did');
  if (!Number.isSafeInteger(hold) || hold < 1) fail('time', 'hold must be whole seconds, at least 1');
  return { me, peer, K, hold, pair: pairId(K), out: { prekeys: null, used: new Set(), returned: new Set(), epoch: null }, in: { prekeys: new Prekeys(), epochs: new Map(), ended: new Map() } };
}

// Deletes what the receiver keeps past its time (the header's "Receiving keys"). → true when
// anything changed, so a caller knows to save. State written before keys had a time gets one now.
export function expire(s, now) {
  checkNow(now);
  let changed = false;
  for (const [eid, st] of s.in.epochs) {
    if (st.until === undefined) { st.until = now + EPOCH_SECONDS + s.hold + SKEW; changed = true; }
    for (const [i, k] of st.skipped) {
      if (k.until === undefined) { k.until = now + s.hold + SKEW; changed = true; }
      if (k.until <= now) { k.mk.fill(0); st.skipped.delete(i); changed = true; }
    }
    if (st.until <= now || (st.ck === null && st.skipped.size === 0)) {
      st.ck?.fill(0);
      for (const [, k] of st.skipped) k.mk.fill(0);
      s.in.epochs.delete(eid);
      if (st.prekey) s.in.ended.set(eid, st.prekey);
      changed = true;
    }
  }
  if (s.in.prekeys.expire(now)) changed = true;
  // A one-time key is spent with its epoch (prekeys.mjs consume): only a key still held could begin
  // an ended epoch again.
  for (const [eid, id] of s.in.ended) if (!s.in.prekeys.holds(id)) { s.in.ended.delete(eid); changed = true; }
  return changed;
}

// A newer bundle replaces the one held. Ids it no longer lists were consumed by the holder; ids
// it still lists may be ones we used in envelopes it has not read yet, so those stay marked used.
// An older or repeated bundle is refused: it may list ids consumed since, and the next epoch
// would begin on one (prekey_reused). A bundle from a new current DID is newer whatever its iat:
// checkPrekeys took it only from the current key, so the held one is from a key the contact left.
//
// A bundle issued after our current epoch began that still lists the one-time key it began on says
// the contact had not opened the epoch then. While our envelopes still carry its encapsulation
// (the header's "Epoch recovery") the next one begins it there, and the epoch goes on. Once they
// no longer do (a reply came), its later envelopes fail epoch_unknown there (a carrier sends such
// a bundle on seeing that): the next send begins a new epoch; the key stays marked used, in case
// an envelope that carried it arrives after all (the holder keeps it, unlisted, for that:
// consume). A bundle issued just before the epoch (within SKEW, the clocks may differ) counts as
// after it: one epoch more, nothing lost. An epoch begun `again` on a key put back after a refusal ends also when the
// bundle no longer lists that key: a relay that said it refused the first envelope and delivered
// it spent the key with that one, and this epoch's first envelope fails prekey_reused there. (If
// it was this epoch's own first envelope that spent it, ending it costs one epoch more.)
// A bundle issued after the epoch began that lists none of the one-time keys of the bundle held
// ends it too: the holder replaced them all (prekeys.mjs REPLACE_DAYS, or the carrier's answer to
// an epoch it could not open), so it may have retired the epoch's key unopened, and keys the
// epoch's chain grew from may be in a copy of its state from before (prekeys.mjs's header).
// Refused before the signature check when it claims an issue time no later than the held one's:
// nothing newer can be in it, and a replayed bundle costs no signature check.
export function acceptPrekeys(s, signed, now) {
  const held = s.out.prekeys, claimed = signed?.body;
  if (held && claimed?.did === held.did && Number.isSafeInteger(claimed?.iat) && claimed.iat <= held.iat) fail('prekeys', `issued at ${claimed.iat}, no later than the bundle held (${held.iat})`);
  const p = checkPrekeys(signed, s.peer, s.pair, now), listed = new Set(p.keys.map((k) => k.id));
  if (held && held.did === p.did && p.iat <= held.iat) fail('prekeys', `issued at ${p.iat}, older than the bundle held (${held.iat})`);
  const renewed = held !== null && !held.keys.some((k) => listed.has(k.id));
  s.out.used = new Set([...s.out.used].filter((id) => listed.has(id)));
  s.out.returned = new Set([...s.out.returned].filter((id) => listed.has(id)));
  s.out.prekeys = p;
  const cur = s.out.epoch;
  if (cur?.oneTime && p.iat + SKEW > cur.started && ((listed.has(cur.oneTime) && !cur.carry) || cur.again || renewed)) restartEpoch(s);
}

// Why a new epoch could not begin now, or null: startEpoch's conditions on the contact's bundle.
export function prekeysMissing(s, now) {
  const p = s.out.prekeys;
  if (!p) return 'no prekey bundle from this contact';
  if (p.did !== s.peer.current_did) return `the bundle is signed as ${p.did}; the contact is now ${s.peer.current_did}: ask for a fresh one`;
  if (now >= p.exp) return `the contact's bundle expired at ${p.exp}`;
  return null;
}

// A candidate epoch: nothing in the session changes here (nextSlot's commit installs it).
// rng order, for reproducible fixtures: X-Wing encapsulation randomness (64). The epoch id is the
// hash of the encapsulation (kdf.epochId), not drawn. carry: its envelopes carry the encapsulation
// until a reply is opened (open; the header's "Epoch recovery").
function startEpoch(s, now, rng) {
  const why = prekeysMissing(s, now);
  if (why) fail('prekeys', why);
  const p = s.out.prekeys, k = p.keys.find((x) => !s.out.used.has(x.id)), pick = k ?? p.last_resort;  // last resort only when every one-time key is used
  let enc;
  try { enc = xwing.encapsulate(pick.pk, rng(64)); } catch (e) { fail('prekeys', `X-Wing key ${pick.id} refused: ${e.message}`); }
  const kem = concatBytes(unhex(pick.id, 16, 'prekeys'), enc.cipherText), id = epochId(kem);
  const ck = epochKey(enc.sharedSecret, s.K, id, s.me.did, s.peer.did);
  enc.sharedSecret.fill(0);
  return { id, ck, n: 0, started: now, kem, lastResort: !k, oneTime: k ? k.id : null,
    again: k ? s.out.returned.has(k.id) : false, self: s.me.current_did, peer: s.peer.current_did, carry: true };
}

// Reserves the next counter, beginning an epoch when due, and derives its message key. Nothing in
// the session changes until slot.commit(); slot.discard() zeroes what was derived. So a message
// refused while sealing (too large, say) leaves no gap, and no epoch begun for nothing. Exported
// with seal() so a test can seal a body send() would never build; an application calls send().
export function nextSlot(s, now, rng = randomBytes) {
  if (s.peer.revoked) fail('revoked', `${s.peer.did} was revoked by this owner`);
  checkNow(now);
  const cur = s.out.epoch;
  const due = !cur || cur.n >= EPOCH_MESSAGES || now - cur.started >= EPOCH_SECONDS
    // A rotation or recovery on either side: a thief holding the state from before it holds this
    // epoch's chain key (ours, or the receiver's prekey secret and chain). Begin anew, on a bundle
    // signed by the contact's current key (startEpoch refuses any other).
    || cur.self !== s.me.current_did || cur.peer !== s.peer.current_did;
  const e = due ? startEpoch(s, now, rng) : cur, n = e.n, kem = e.carry ? e.kem : null, { mk, next } = step(e.ck.slice());
  return {
    head: header(KIND.message, e.id, n, kem), mk, epoch: e.id, n, prekey: kem ? hex(kem.subarray(0, 16)) : null, last_resort: e.lastResort,
    commit() {
      if (e !== cur) { if (e.oneTime) { s.out.used.add(e.oneTime); s.out.returned.delete(e.oneTime); } cur?.ck.fill(0); s.out.epoch = e; }
      e.ck.fill(0); e.ck = next; e.n = n + 1;
    },
    discard() { next.fill(0); if (e !== cur) e.ck.fill(0); },
  };
}

// For the carrier: the relay refused or lost the epoch's first envelope (its size limit is below
// MAX_ENVELOPE on the free tier); the next send begins a new epoch. refused: the bytes of that
// envelope when the relay refused it (it acknowledged the publish and stored nothing): if it is
// this epoch's first and only envelope, its one-time prekey goes back to the pool, since the
// contact cannot have spent it, and the next epoch begins on it again (a fresh encapsulation: a
// KEM key takes any number). Otherwise, lost or withheld on the way, the key stays marked used:
// the contact may get that envelope after all, and a second epoch on it would then fail
// prekey_reused. (Without the call, the epoch's next envelope carries the encapsulation too.)
export function restartEpoch(s, refused = null) {
  const cur = s.out.epoch;
  if (cur?.oneTime && cur.n === 1 && refused instanceof Uint8Array && refused.length >= HEAD && hex(refused.subarray(2, 18)) === hex(cur.id)
    && new DataView(refused.buffer, refused.byteOffset, refused.byteLength).getUint32(18) === 0) {
    s.out.used.delete(cur.oneTime);
    s.out.returned.add(cur.oneTime);
  }
  cur?.ck.fill(0);
  s.out.epoch = null;
}

// rng order: nonce (24).
export function seal(s, slot, signed, now, rng = randomBytes) {
  try {
    const pt = pad(utf8ToBytes(canonicalize(signed))), size = slot.head.length + NONCE + pt.length + TAG;
    // Not the relay's too_large ($sigelo/notice): this is the envelope's own bound, checked before
    // the slot is committed, so a refused message changes nothing.
    if (size > MAX_ENVELOPE) fail('message_too_large', `a ${size}-byte envelope (${pt.length} padded bytes${slot.head.length > HEAD ? ', carrying the encapsulation' : ''}), at most ${MAX_ENVELOPE}`);
    const t = topic(s.K, s.me.did, s.peer.did, isoWeek(now)), nonce = rng(NONCE);
    const ct = xchacha20poly1305(slot.mk, nonce, concatBytes(slot.head, utf8ToBytes(t))).encrypt(pt);
    return { bytes: concatBytes(slot.head, nonce, ct), topic: t, epoch: hex(slot.epoch), n: slot.n, prekey: slot.prekey, last_resort: slot.last_resort };
  } finally { slot.mk.fill(0); }
}

export function send(s, { label, content }, now, rng = randomBytes) {
  if (typeof label !== 'string') fail('body', 'label must be a string');
  if (content === undefined) fail('body', 'content is required');
  try { canonicalize({ label, content }); } catch (e) { fail('body', `label or content is not canonical JSON (no floats): ${e.message}`); }
  const slot = nextSlot(s, now, rng);
  try {
    const body = { v: MSG_V, typ: 'message', from: s.me.current_did, to: s.peer.did, pair: s.pair, epoch: hex(slot.epoch), n: slot.n, iat: now, label, content };
    const r = seal(s, slot, { body, sig: sign(s.me.secret, body) }, now, rng);
    slot.commit();
    return r;
  } catch (e) { slot.discard(); throw e; }
}

// Checks, in order: revoked, topic, length, version, kind, epoch_limit, epoch_id (a header that
// carries an encapsulation not hashing to its epoch id: the header's "Epochs"), then for a known
// epoch replay and out_of_order, for a new one epoch_unknown (no encapsulation carried), replay
// (an epoch ended here), prekey_reused, prekey_unknown, epoch_limit (too many last-resort epochs
// kept: the header's "Receiving keys"); then aead (an X-Wing ciphertext that does not decapsulate
// included), padding, plaintext, body, not_recipient, pair, from, sig. Keys past their time are
// deleted first (expire): the clock decides that, not the envelope. Otherwise state (chain keys,
// the seen-set, the prekey) changes only after every check has passed: a forgery changes nothing.
// An envelope opened that the contact signed SKEW or more after our current epoch began is a reply
// (the header's "Epoch recovery"): our later envelopes of that epoch carry no encapsulation.
export function open(s, bytes, t, now) {
  if (s.peer.revoked) fail('revoked', `${s.peer.did} was revoked by this owner`);
  expire(s, now);
  if (typeof t !== 'string') fail('topic', 'the topic the envelope arrived on is required');
  const env = parse(bytes);
  if (env.kind !== KIND.message) fail('kind', `kind ${env.kind} is not a message`);
  if (env.n >= EPOCH_MESSAGES) fail('epoch_limit', `counter ${env.n}: an epoch carries at most ${EPOCH_MESSAGES} messages`);
  const eid = hex(env.epoch), st = s.in.epochs.get(eid);
  // Before any key is looked up or decapsulated: a body signed for another encapsulation's epoch
  // (an old one, re-sealed by whoever holds K) is refused here, whatever prekey it names. Checked
  // on a known epoch too: one header, one epoch.
  if (env.carries && hex(epochId(env.head.subarray(HEAD))) !== eid) fail('epoch_id', 'the epoch id is not the hash of the prekey id and X-Wing ciphertext that begin the epoch');
  let mk, commit, discard = () => {}, lastResort;
  if (st) {
    lastResort = st.lastResort;
    if (st.seen.has(env.n)) fail('replay', `counter ${env.n} of epoch ${eid} was already opened`);
    if (env.n > st.high) {
      const a = advance(st.ck, st.high, env.n);
      mk = a.mk;
      commit = () => { st.ck.fill(0); keep(s, st, a, env.n, now); };
      discard = a.discard;
    } else {
      const kept = st.skipped.get(env.n) ?? fail('out_of_order', `counter ${env.n} is more than ${WINDOW} behind ${st.high}, or its key's time is up; its key is gone`);
      mk = kept.mk.slice();
      commit = () => { kept.mk.fill(0); st.skipped.delete(env.n); };
    }
  } else {
    if (!env.carries) fail('epoch_unknown', `epoch ${eid} has not been opened here, and this envelope does not carry its key agreement`);
    if (s.in.ended.has(eid)) fail('replay', `epoch ${eid} was opened here and has ended; no envelope of it can begin it again`);
    const id = hex(env.prekey), pk = s.in.prekeys.take(id);
    lastResort = pk.lastResort;
    if (lastResort && lastResortKept(s) >= ENDED_MAX) {
      fail('epoch_limit', `${ENDED_MAX} epochs begun on last-resort keys still held are kept for this contact: no new one until older ones go with their key`);
    }
    // A tampered ML-KEM part yields a wrong key (implicit rejection), caught by the AEAD below; an
    // X25519 part that is a low-order point makes X-Wing throw. Both are a tampered envelope: aead.
    // Each envelope naming a held prekey costs one decapsulation (8 ms on a phone): a hostile
    // relay can spend the receiver's CPU, as it can drop its traffic; a carrier may rate-limit.
    let shared;
    try { shared = xwing.decapsulate(env.kem, pk.secretKey); } catch { fail('aead', 'the X-Wing ciphertext does not decapsulate: tampered'); }
    const ck0 = epochKey(shared, s.K, env.epoch, s.peer.did, s.me.did);
    shared.fill(0);
    // Begun at counter n: the keys of counters below n are derived, and the WINDOW nearest kept.
    const a = advance(ck0, -1, env.n);
    ck0.fill(0);
    mk = a.mk;
    commit = () => {
      // Begun on the last-resort key, the one-time keys the sender ran out of are retired here too
      // (the header's "One-time keys").
      s.in.prekeys.consume(id, now);
      const fresh = { ck: null, high: -1, skipped: new Map(), seen: new Set(), lastResort, prekey: id, until: now + EPOCH_SECONDS + s.hold + SKEW };
      keep(s, fresh, a, env.n, now);
      s.in.epochs.set(eid, fresh);
      bound(s);
    };
    discard = a.discard;
  }
  try {
    const signed = check(s, env, mk, t);
    commit();
    s.in.epochs.get(eid).seen.add(env.n);
    const cur = s.out.epoch;
    if (cur?.carry && signed.body.iat >= cur.started + SKEW) cur.carry = false;
    return { body: signed.body, sig: signed.sig, epoch: eid, n: env.n, prekey: env.prekey && hex(env.prekey), last_resort: lastResort };
  } catch (e) { discard(); throw e; } finally { mk.fill(0); }
}

// The message key of counter n from ck, the chain key of counter high + 1 (left unchanged), and the
// chain key after it. Of the keys of the counters in between, the WINDOW nearest below n are
// returned (skipped), the others zeroed at once.
function advance(ck, high, n) {
  const skipped = [];
  let c = ck.slice();
  for (let i = high + 1; i < n; i++) {
    const r = step(c);
    c = r.next;
    if (i >= n - WINDOW) skipped.push([i, r.mk]); else r.mk.fill(0);
  }
  const r = step(c);
  return { mk: r.mk, next: r.next, skipped, discard: () => { r.next.fill(0); for (const [, k] of skipped) k.fill(0); } };
}

// Installs what advance() derived as the epoch's state at counter n.
function keep(s, st, a, n, now) {
  st.high = n;
  // After counter 999 the chain key opens nothing more: gone now, not with the epoch.
  if (n === EPOCH_MESSAGES - 1) { a.next.fill(0); st.ck = null; } else st.ck = a.next;
  for (const [i, k] of a.skipped) st.skipped.set(i, { mk: k, until: now + s.hold + SKEW });
  for (const [i, k] of st.skipped) if (i < st.high - WINDOW) { k.mk.fill(0); st.skipped.delete(i); }
}

// Epochs begun on a last-resort key whose id this session keeps: live, or ended while their key is
// held (the header's "Receiving keys").
function lastResortKept(s) {
  let n = s.in.ended.size;
  for (const [, st] of s.in.epochs) if (st.lastResort) n++;
  return n;
}

// EPOCHS_MAX (the header's "Receiving keys"), the oldest first. The epoch just begun is the newest:
// it stays. An epoch pushed out on a key still held leaves its id; no id goes here (open refuses a
// new last-resort epoch past ENDED_MAX instead), only with its key (expire).
function bound(s) {
  for (const [eid, st] of s.in.epochs) {
    if (s.in.epochs.size <= EPOCHS_MAX) break;
    st.ck?.fill(0);
    for (const [, k] of st.skipped) k.mk.fill(0);
    s.in.epochs.delete(eid);
    if (st.prekey && s.in.prekeys.holds(st.prekey)) s.in.ended.set(eid, st.prekey);
  }
}

function check(s, env, mk, t) {
  let pt;
  try { pt = xchacha20poly1305(mk, env.nonce, concatBytes(env.head, utf8ToBytes(t))).decrypt(env.ct); } catch {
    fail('aead', 'does not decrypt: tampered, or not for this channel, mailbox or week');
  }
  const text = unpad(pt);
  let signed;
  try { signed = parseBytes(text); } catch (e) { fail('plaintext', `not JSON: ${e.message}`); }
  if (!exact(signed, ['body', 'sig']) || typeof signed.sig !== 'string') fail('plaintext', 'not exactly {body, sig}');
  let jcs;
  try { jcs = canonicalize(signed); } catch (e) { fail('body', `not canonical JSON: ${e.message}`); }
  if (Buffer.compare(utf8ToBytes(jcs), text) !== 0) fail('plaintext', 'not the JCS form of {body, sig}');
  const b = signed.body;
  if (!exact(b, BODY)) fail('body', `fields are not exactly ${BODY.join(' ')}`);
  if (b.v !== MSG_V || b.typ !== 'message') fail('body', `v must be "${MSG_V}" and typ "message"`);
  if (!['from', 'to', 'pair', 'epoch', 'label'].every((k) => typeof b[k] === 'string')) fail('body', 'from, to, pair, epoch and label must be strings');
  if (!Number.isSafeInteger(b.iat) || b.iat < 0) fail('body', 'iat must be Unix seconds');
  if (b.epoch !== hex(env.epoch) || b.n !== env.n) fail('body', 'epoch or n differs from the header');
  // to and from are unverified until the signature check: name the check, never echo them.
  if (b.to !== s.me.did) fail('not_recipient', 'addressed to another DID');
  if (b.pair !== s.pair) fail('pair', 'signed for another pairing');
  // Only the current key: after a recovery the old key may be a thief's (SPEC §7.1).
  if (b.from !== s.peer.current_did) fail('from', 'not signed as the contact\'s current DID');
  if (!verifySig(s.peer.current_key, b, signed.sig)) fail('sig', 'does not verify under the contact\'s current key');
  return signed;
}
