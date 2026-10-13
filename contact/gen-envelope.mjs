// SPDX-License-Identifier: MIT
// Regenerates fixtures/envelope-v0.json, byte for byte, from the documented seeds below.
//   node contact/gen-envelope.mjs           write the file
//   node contact/gen-envelope.mjs --check   exit 1 if the committed file differs
// Seeds: seed(label) = SHA-256(UTF-8 "sigelo-msg/0 " + label); genesis nonces are the first 16
// bytes of SHA-256("sigelo-msg/0 nonce " + label); `created` and every time are fixed. Ed25519 is
// deterministic. X-Wing (@noble/post-quantum 0.7.1 ml_kem768_x25519) takes a 32-byte keygen seed
// and 64 bytes of encapsulation randomness from the caller, so every random input comes from
// rng(label): the stream SHA-256(seed("rng " + label) ‖ u32be(0)) ‖ SHA-256(… ‖ u32be(1)) ‖ …,
// read in order. Each prekey issue and each envelope has its own label; the read order is in
// prekeys.mjs (issue) and envelope.mjs (startEpoch, seal). Output: JSON.stringify(out, null, 2)
// + "\n", keys in insertion order. The fixture contract is in the `about` field.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { canonicalize, keygen, rotate, sign } from 'sigelo';
import { KIND, acceptPrekeys, header, nextSlot, open, pad, seal, send, session } from './envelope.mjs';
import { epochId, epochKey, isoWeek, pairKey, step, topic } from './kdf.mjs';

export const V = 'sigelo-msg/0';
export const T0 = 1791256800, CREATED = '2026-10-01T00:00:00Z'; // T0 = 2026-10-06T03:20:00Z, a Tuesday of 2026-W41
export const DAY = 86400;
// The receivers' hold: their relay keeps an envelope at most 30 days (envelope.mjs session).
export const HOLD_FIXTURE = 30 * DAY;
// e19 and e20 arrive 37 days and an hour after T0: Bob's epoch 2 (opened at T0 + 1060) is past
// its time (EPOCH_SECONDS + 30 days + SKEW), and the one-time keys he retired at e14 are still held.
export const REPLAY_AT = T0 + 37 * DAY + 3600;
export const OUT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'envelope-v0.json');

const sha = (s) => sha256(utf8ToBytes(V + ' ' + s));
export const seed = (l) => sha(l);
const nonce = (l) => sha('nonce ' + l).slice(0, 16);
export function rng(label) {
  const s = seed('rng ' + label);
  let buf = new Uint8Array(0), i = 0;
  return (n) => {
    while (buf.length < n) {
      const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, i++);
      buf = concatBytes(buf, sha256(concatBytes(s, ctr)));
    }
    const out = buf.slice(0, n); buf = buf.slice(n);
    return out;
  };
}

// Identities as accept/pairing do it: a recovery seed's public key is read through a placeholder commitment.
const ZERO = 'sha256:' + '0'.repeat(64);
export const id = (l, recovery) => keygen({ seed: seed(l), recovery, created: CREATED, nonce: nonce(l) });
const pub = (l) => id(l, ZERO).key;
export function identities() {
  const [aRec, bRec, cRec] = ['A-recovery', 'B-recovery', 'C-recovery'].map(pub);
  const A0 = id('A0', aRec), A1 = id('A1', aRec), B0 = id('B0', bRec), C0 = id('C0', cRec);
  const rA1 = rotate({ genesis: A0.genesis, next_genesis: A1.genesis, iat: T0 + 1000, reason: 'voluntary', secret: A0.secret });
  const K = { AB: pairKey(seed('invite-secret A-B'), seed('handshake-shared A-B'), A0.did, B0.did),
    AC: pairKey(seed('invite-secret A-C'), seed('handshake-shared A-C'), A0.did, C0.did) };
  return { A0, A1, B0, C0, rA1, K };
}
// The store's contact record (accept/node/sigelo-pair.mjs): keyed by the original DID.
export const contact = (original, current) => ({ did: original.did, current_did: current.did, current_key: current.key, revoked: false });
export const me = (original, current) => ({ did: original.did, current_did: current.did, secret: current.secret });

// The receivers the steps run against, rebuilt from the seeds: Bob (prekeys issued at T0 from
// rng("bob-prekeys")), Carol, Alice's contact under another pairing, who issued none, and Alice
// for Bob's reply (prekeys issued at T0 from rng("alice-prekeys")).
export function receivers(ids = identities()) {
  const { A0, B0, C0, K } = ids;
  const bob = session({ me: me(B0, B0), peer: contact(A0, A0), K: K.AB, hold: HOLD_FIXTURE });
  const bundle = bob.in.prekeys.issue(bob.me, bob.pair, T0, rng('bob-prekeys'));
  const carol = session({ me: me(C0, C0), peer: contact(A0, A0), K: K.AC, hold: HOLD_FIXTURE });
  const alice = session({ me: me(A0, A0), peer: contact(B0, B0), K: K.AB, hold: HOLD_FIXTURE });
  const aliceBundle = alice.in.prekeys.issue(alice.me, alice.pair, T0, rng('alice-prekeys'));
  return { bob, carol, alice, bundle, aliceBundle };
}

export function build() {
  const ids = identities(), { A0, A1, B0, C0, rA1, K } = ids;
  const { bundle } = receivers(ids);
  const alice = () => { const s = session({ me: me(A0, A0), peer: contact(B0, B0), K: K.AB, hold: HOLD_FIXTURE }); acceptPrekeys(s, bundle, T0); return s; };
  const a = alice(), aOld = alice(), aLR = alice();
  // Alice's own prekeys, as receivers() rebuilds them, so that she can open Bob's reply.
  const aliceBundle = a.in.prekeys.issue(a.me, a.pair, T0, rng('alice-prekeys'));
  const b = session({ me: me(B0, B0), peer: contact(A0, A0), K: K.AB, hold: HOLD_FIXTURE });
  acceptPrekeys(b, aliceBundle, T0);
  const senders = new Map([[a, 'alice'], [aOld, 'alice-restored'], [aLR, 'alice-last-resort'], [b, 'bob']]);
  const envelopes = {};
  const record = (label, s, now, r, note) => {
    envelopes[label] = { sender: senders.get(s), now, week: isoWeek(now),
      topic: r.topic, epoch: r.epoch, n: r.n, prekey: r.prekey, last_resort: r.last_resort, ...(r.signed ?? {}), note, hex: bytesToHex(r.bytes) };
  };
  const msg = (label, s, now, label_, content, note) => {
    const r = send(s, { label: label_, content }, now, rng(label));
    // send() does not return the body: rebuild it from the envelope's own fields, as the receiver will see it.
    const body = { v: V, typ: 'message', from: s.me.current_did, to: s.peer.did, pair: s.pair, epoch: r.epoch, n: r.n, iat: now, label: label_, content };
    record(label, s, now, { ...r, signed: { body, sig: sign(s.me.secret, body) } }, note);
  };
  // A body send() would never build, sealed into the real channel: what a hostile or buggy contact can do.
  const forged = (label, s, now, edit, signer, note) => {
    const g = rng(label), slot = nextSlot(s, now, g);
    const body = edit({ v: V, typ: 'message', from: s.me.current_did, to: s.peer.did, pair: s.pair, epoch: bytesToHex(slot.epoch), n: slot.n, iat: now, label: 'x', content: { text: label } });
    const signed = { body, sig: sign(signer.secret, body) };
    record(label, s, now, { ...seal(s, slot, signed, now, g), signed }, note);
    slot.commit();
  };
  // Plaintext bytes seal() would refuse to produce: the AEAD of envelope.mjs, spelled out.
  const raw = (label, s, now, plaintext, note) => {
    const g = rng(label), slot = nextSlot(s, now, g), t = topic(s.K, s.me.did, s.peer.did, isoWeek(now)), nc = g(24);
    const ct = xchacha20poly1305(slot.mk, nc, concatBytes(slot.head, utf8ToBytes(t))).encrypt(plaintext);
    record(label, s, now, { bytes: concatBytes(slot.head, nc, ct), topic: t, epoch: bytesToHex(slot.epoch), n: slot.n, prekey: slot.prekey, last_resort: slot.last_resort }, note);
    slot.mk.fill(0); slot.commit();
  };

  msg('e01', a, T0 + 60, 'tests', { text: 'run the tests' }, 'first of epoch 1: carries one-time prekey keys[0]');
  msg('e02', a, T0 + 120, 'tests', { done: 12, note: 'Grüße 𝄞' }, 'non-ASCII content, JCS order; carries the encapsulation again: no reply yet');
  msg('e03', a, T0 + 180, 'billing', { invoice: 'INV-7', amount: '1500', items: [1, 2, 3] }, 'another conversation label');
  msg('e04', a, T0 + 240, 'tests', { text: 'four' }, 'the last of epoch 1 that carries the encapsulation');
  // Bob's reply, signed more than SKEW after Alice's epoch 1 began: once she has opened it, her
  // envelopes of that epoch carry no encapsulation (envelope.mjs, "Epoch recovery").
  msg('r01', b, T0 + 400, 'tests', { text: 'running' }, 'Bob\'s reply, on his own epoch begun on Alice\'s keys[0]');
  open(a, hexToBytes(envelopes.r01.hex), envelopes.r01.topic, T0 + 410);
  msg('e05', a, T0 + 420, 'tests', { text: 'five' }, 'after Bob\'s reply: no encapsulation; the tamper target');
  forged('e06', a, T0 + 480, (b) => ({ ...b, to: C0.did }), A0, 'signed by Alice, addressed to Carol, sealed to Bob');
  forged('e07', a, T0 + 540, (b) => b, C0, 'Alice\'s body signed with Carol\'s key');
  // Alice rotates A0 -> A1 at T0 + 1000 (`rotation`). Her next message begins epoch 2: a thief
  // holding her state from before the rotation would hold epoch 1's chain key.
  a.me = me(A0, A1);
  msg('e08', a, T0 + 1060, 'tests', { text: 'new key, same contact' }, 'from Alice\'s new current DID A1: her rotation begins epoch 2, on keys[1]');
  forged('e09', a, T0 + 1120, (b) => ({ ...b, from: A0.did }), A0, 'signed with the key Alice rotated away from');
  for (let i = 0; i < 71; i++) { const lost = nextSlot(a, T0 + 1180); lost.mk.fill(0); lost.commit(); }  // counters 2..72 lost on the way
  msg('e10', a, T0 + 1200, 'tests', { text: 'seventy-three' }, 'counter 73: more than the window past what Bob opened; opens, and keys 1..8 are deleted');
  msg('e11', a, T0 + 1060 + 7 * DAY, 'tests', { text: 'a week later' }, 'epoch 2 is 7 days old: epoch 3 on keys[2], next week\'s topic');
  msg('e12', aOld, T0 + 7 * DAY + 1120, 'tests', { text: 'restored' }, 'a sender restored from state older than e01: keys[0] again');
  msg('e13', aOld, T0 + 7 * DAY + 1180, 'tests', { text: 'restored 2' }, 'the second message of that refused epoch, carrying its encapsulation too');
  // Every one-time key used: set directly, because using twenty for real takes twenty epochs.
  for (const k of aLR.out.prekeys.keys) aLR.out.used.add(k.id);
  aLR.me = me(A0, A1);
  msg('e14', aLR, T0 + 7 * DAY + 1300, 'tests', { text: 'last resort' }, 'every one-time key used: the last-resort key, flagged');
  msg('e15', aLR, T0 + 7 * DAY + 1360, 'tests', { text: 'last resort 2' }, 'later messages of that epoch are flagged too');
  forged('e16', a, T0 + 7 * DAY + 1400, (b) => ({ ...b, extra: 'x' }), A1, 'a body field outside the message row');
  const plainBody = (s, slotEpoch, n, now) => ({ v: V, typ: 'message', from: s.me.current_did, to: s.peer.did, pair: s.pair, epoch: slotEpoch, n, iat: now, label: 'x', content: {} });
  {
    // e17: JSON.stringify keeps insertion order, which is not JCS order: refused though it parses.
    const peek = a.out.epoch, body = plainBody(a, bytesToHex(peek.id), peek.n, T0 + 7 * DAY + 1420);
    raw('e17', a, T0 + 7 * DAY + 1420, pad(utf8ToBytes(JSON.stringify({ body, sig: sign(A1.secret, body) }))), 'plaintext in insertion order, not JCS');
    const body2 = plainBody(a, bytesToHex(peek.id), peek.n, T0 + 7 * DAY + 1440), p = pad(utf8ToBytes(canonicalize({ body: body2, sig: sign(A1.secret, body2) })));
    p[p.length - 1] = 1;
    raw('e18', a, T0 + 7 * DAY + 1440, p, 'padding ends in 0x01');
  }
  // Epoch 4, a week after epoch 3 began, on keys[3] (which Bob retired unopened at e14, and still
  // holds): its first envelope is held back on the way and its second, which carries the
  // encapsulation, reaches Bob first.
  msg('e21', a, T0 + 14 * DAY + 1200, 'tests', { text: 'late first' }, 'counter 0 of epoch 4, delivered after e22');
  msg('e22', a, T0 + 14 * DAY + 1260, 'tests', { text: 'second, first to arrive' }, 'counter 1 of epoch 4, carrying the encapsulation: it begins the epoch at Bob');
  // The audit's replay: whoever holds K (a copy of Bob's state) re-seals Alice's signed e08 as the
  // first envelope of a fresh encapsulation, to a one-time key Bob still holds, once Bob's epoch 2
  // is past its time: under e08's epoch id (e19), or under the id its own encapsulation gives (e20).
  // With an epoch id the sender drew at random, Bob opened e19 as a new message.
  const replayed = (label, keepId, note) => {
    const g = rng(label), k = bundle.body.keys[10], enc = xwing.encapsulate(new Uint8Array(Buffer.from(k.pk, 'base64url')), g(64));
    const kem = concatBytes(hexToBytes(k.id), enc.cipherText), eid = keepId ? hexToBytes(envelopes.e08.epoch) : epochId(kem);
    const { mk } = step(epochKey(enc.sharedSecret, K.AB, eid, A0.did, B0.did)), head = header(KIND.message, eid, 0, kem);
    const t = topic(K.AB, A0.did, B0.did, isoWeek(REPLAY_AT)), nc = g(24), signed = { body: envelopes.e08.body, sig: envelopes.e08.sig };
    const ct = xchacha20poly1305(mk, nc, concatBytes(head, utf8ToBytes(t))).encrypt(pad(utf8ToBytes(canonicalize(signed))));
    envelopes[label] = { sender: 'holder-of-K', now: REPLAY_AT, week: isoWeek(REPLAY_AT), topic: t, epoch: bytesToHex(eid), n: 0, prekey: k.id, last_resort: false, ...signed, note,
      hex: bytesToHex(concatBytes(head, nc, ct)) };
  };
  replayed('e19', true, 'Alice\'s signed e08 re-sealed by a holder of K on a fresh encapsulation to keys[10], under e08\'s epoch id');
  replayed('e20', false, 'the same under the epoch id its encapsulation gives');

  // The §3 derivations spelled out with HKDF, HMAC and SHA-256 directly, not through kdf.mjs, for e01.
  const u = utf8ToBytes, K0 = hkdf(sha256, concatBytes(seed('invite-secret A-B'), seed('handshake-shared A-B')), u('sigelo-pair/0'), u([A0.did, B0.did].sort().join('')), 32);
  const g = rng('e01'), coins = g(64), k0 = bundle.body.keys[0];
  const enc = xwing.encapsulate(new Uint8Array(Buffer.from(k0.pk, 'base64url')), coins);
  const eid = sha256(concatBytes(hexToBytes(k0.id), enc.cipherText)).slice(0, 16);
  const ck0 = hkdf(sha256, enc.sharedSecret, K0, concatBytes(u('sigelo-msg/0 epoch'), eid, u(A0.did + B0.did)), 32);
  const trace = { K: bytesToHex(K0), pair: bytesToHex(hkdf(sha256, K0, u('sigelo-pair-id/0'), new Uint8Array(0), 16)),
    topic: 'm/' + bytesToHex(hkdf(sha256, K0, u('sigelo-topic/0'), u(`${A0.did}\n${B0.did}\n${isoWeek(T0 + 60)}`), 16)),
    epoch_id: bytesToHex(eid), encapsulation_randomness: bytesToHex(coins), xwing_ciphertext_sha256: bytesToHex(sha256(enc.cipherText)),
    shared_secret: bytesToHex(enc.sharedSecret), ck0: bytesToHex(ck0), mk0: bytesToHex(hmac(sha256, ck0, Uint8Array.of(1))), ck1: bytesToHex(hmac(sha256, ck0, Uint8Array.of(2))),
    nonce: bytesToHex(g(24)) };

  const S = (envelope, extra) => ({ op: 'open', receiver: 'bob', envelope, ...extra });
  const ok = (e) => S(e, { expect: { epoch: envelopes[e].epoch, n: envelopes[e].n, prekey: envelopes[e].prekey, last_resort: envelopes[e].last_resort } });
  const steps = [
    S('e01', { xor: [38, 1], error: 'epoch_id', note: 'X-Wing ciphertext edited: it no longer hashes to the epoch id, refused before any decapsulation' }),
    S('e01', { xor: [5, 1], error: 'epoch_id', note: 'an epoch id byte of a first envelope' }),
    S('e01', { xor: [38, 1], rebind: true, error: 'aead', note: 'X-Wing ciphertext, ML-KEM part (bytes 38..1125)' }),
    S('e01', { xor: [1157, 1], rebind: true, error: 'aead', note: 'X-Wing ciphertext, X25519 part (bytes 1126..1157)' }),
    S('e01', { set: [1126, '00'.repeat(32)], rebind: true, error: 'aead', note: 'an X25519 part of zeros: a low-order point, X-Wing throws' }),
    S('e01', { set: [1126, '01' + '00'.repeat(31)], rebind: true, error: 'aead', note: 'an X25519 part of u = 1: a low-order point' }),
    S('e01', { set: [1, '00'], error: 'kind', note: 'counter 0 without the flag 0x80: an epoch begins only with its key agreement' }),
    S('e01', { set: [1, '82'], error: 'kind', note: 'kind 2 with the flag 0x80, long enough to hold the encapsulation: only a message carries one' }),
    ok('e01'), ok('e03'), ok('e02'), S('e02', { error: 'replay' }), S('e01', { error: 'replay' }), ok('e04'),
    { op: 'open', receiver: 'alice', envelope: 'r01', expect: { epoch: envelopes.r01.epoch, n: 0, prekey: envelopes.r01.prekey, last_resort: false }, note: 'Bob\'s reply, at Alice' },
    S('e05', { xor: [21, 1], error: 'aead', note: 'counter 4 -> 5: a different key and additional data' }),
    S('e05', { xor: [5, 1], error: 'epoch_unknown', note: 'an epoch id byte: no such epoch, checked before the AEAD' }),
    S('e05', { xor: [22, 1], error: 'aead', note: 'nonce' }),
    S('e05', { xor: [46, 1], error: 'aead', note: 'ciphertext' }),
    S('e05', { xor: [-1, 1], error: 'aead', note: 'tag (last byte)' }),
    S('e05', { topic: envelopes.e11.topic, error: 'aead', note: 'right channel, next week\'s topic' }),
    S('e05', { set: [1, '80'], error: 'length', note: 'the flag set on an envelope without the encapsulation' }),
    S('e05', { set: [1, '81'], error: 'kind', note: 'kind 1 with the flag 0x80: refused as the kind, before the length is read as carrying' }),
    ok('e05'), S('e06', { error: 'not_recipient' }), S('e07', { error: 'sig' }),
    S('e08', { error: 'from', note: 'Bob has not seen the rotation yet: keys[1] is not consumed' }),
    { op: 'contact', receiver: 'bob', current: 'A1', note: 'Bob\'s store merged rotation A0 -> A1' },
    ok('e08'), S('e09', { error: 'from' }), ok('e10'),
    S('e09', { error: 'out_of_order', note: 'counter 1, 72 behind counter 73: its key is gone' }), ok('e11'),
    S('e12', { error: 'prekey_reused' }), S('e13', { error: 'prekey_reused' }), ok('e14'), ok('e15'), S('e14', { error: 'replay' }),
    S('e16', { error: 'body' }), S('e17', { error: 'plaintext' }), S('e18', { error: 'padding' }),
    S('e22', { set: [1, '00'], error: 'length', note: 'the flag cleared: read without the encapsulation, the rest is no padded ciphertext' }),
    ok('e22'), ok('e21'), S('e22', { error: 'replay' }), S('e21', { error: 'replay' }),
    S('e04', { set: [0, '02'], error: 'version' }), S('e04', { set: [1, '03'], error: 'kind', note: 'reserved for groups' }),
    S('e04', { truncate: 1, error: 'length' }), S('e04', { set: [18, '000003e8'], error: 'epoch_limit', note: 'counter 1000' }),
    S('e12', { xor: [22, 1], rebind: true, error: 'prekey_unknown', note: 'a prekey id byte' }),
    S('e19', { error: 'epoch_id', note: 'epoch 2 is past its time at Bob: its signed body cannot begin it again on another encapsulation' }),
    S('e20', { error: 'body', note: 'under the id its encapsulation gives, the signed body names another epoch' }),
    { op: 'open', receiver: 'carol', envelope: 'e01', error: 'prekey_unknown', note: 'Bob\'s envelope at Carol' },
    { op: 'open', receiver: 'carol', envelope: 'e02', error: 'prekey_unknown', note: 'it carries the encapsulation: the prekey decides' },
    { op: 'open', receiver: 'carol', envelope: 'e05', error: 'epoch_unknown', note: 'no encapsulation: no epoch to open it in' },
  ];

  const out = {
    v: V,
    about: 'sigelo-msg/0 envelopes (design/relay-plan.md §3, §11 "Epoch recovery"). Rebuild the receivers from the seeds (gen-envelope.mjs receivers(), each holding envelopes `params.hold` seconds), run `steps` in order: '
      + 'open `envelope` (hex) on its `topic` at its `now`, after `xor` [offset, mask] (negative offset counts from the end), `set` [offset, hex] or `truncate` (bytes cut from the end), '
      + 'then, with `rebind`, set the epoch id (bytes 2..17) to the first 16 bytes of SHA-256 of bytes 22..1157 (prekey id and X-Wing ciphertext, as a sender derives it), '
      + 'and compare `expect` plus the envelope\'s `body` by value, or `error` by check name. `contact`: the receiver\'s store has merged `rotation`; its peer record '
      + 'becomes { did: original, current_did, current_key } as SPEC §9 resolves that chain, and `current` names the identity it must resolve to.',
    params: { epoch_messages: 1000, epoch_seconds: 7 * DAY, epoch_id: 'the first 16 bytes of SHA-256(prekey id ‖ X-Wing ciphertext)', window: 64, padding: 'ISO/IEC 7816-4: 0x80 then 0x00 to the next multiple of 256', one_time_prekeys: 20, replenish_below: 5, prekey_ttl: 31 * DAY,
      carries: '0x80 in the kind byte: the header carries the prekey id and X-Wing ciphertext (bytes 22..1157). Always at counter 0; at later counters until the sender has opened a reply, an envelope from the contact signed 300 s or more after the epoch began. A receiver begins an unknown epoch from any envelope that carries it.',
      hold: HOLD_FIXTURE },
    created: CREATED, t0: T0,
    seeds: Object.fromEntries(['A0', 'A1', 'A-recovery', 'B0', 'B-recovery', 'C0', 'C-recovery', 'invite-secret A-B', 'handshake-shared A-B', 'invite-secret A-C', 'handshake-shared A-C'].map((l) => [l, bytesToHex(seed(l))])),
    identities: Object.fromEntries(Object.entries({ A0, A1, B0, C0 }).map(([k, x]) => [k, { did: x.did, key: x.key, genesis: x.genesis }])),
    rotation: rA1,
    pairings: { 'A-B': { K: bytesToHex(K.AB), pair: a.pair }, 'A-C': { K: bytesToHex(K.AC), pair: session({ me: me(C0, C0), peer: contact(A0, A0), K: K.AC }).pair } },
    weeks: [T0, 1798761600, 1735516800, 1704067200, 1609459200, 1609545600].map((t) => [t, isoWeek(t)]),
    topics: [[A0, B0, T0], [B0, A0, T0], [A0, B0, T0 + 7 * DAY]].map(([f, t, w]) => ({ from: f.did, to: t.did, week: isoWeek(w), topic: topic(K.AB, f.did, t.did, isoWeek(w)) })),
    trace_e01: trace,
    prekeys: { bob: bundle },
    envelopes, steps,
  };
  return JSON.stringify(out, null, 2) + '\n';
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const text = build();
  if (process.argv.includes('--check')) {
    if (readFileSync(OUT, 'utf8') !== text) { console.error('envelope-v0.json differs from the seeds: run node contact/gen-envelope.mjs'); process.exit(1); }
    console.log('envelope-v0.json reproduces byte for byte');
  } else { writeFileSync(OUT, text); console.log(`wrote ${OUT.split('/').slice(-2).join('/')} (${text.length} bytes)`); }
}
