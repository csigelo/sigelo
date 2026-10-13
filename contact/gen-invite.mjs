// SPDX-License-Identifier: MIT
// Regenerates fixtures/invite-v0.json, byte for byte, from the documented seeds below.
//   node contact/gen-invite.mjs           write the file
//   node contact/gen-invite.mjs --check   exit 1 if the committed file differs
// Independent of invite.mjs on purpose: code bytes, nonces, topics, keys, proofs and expected
// results are assembled here from design/relay-plan.md §3 with node:crypto, so the fixture checks
// invite.mjs instead of echoing it. Needs ts/dist. Ed25519 is deterministic, so fixed seeds,
// genesis nonces, `created` and times fix every byte. Output: JSON.stringify(out, null, 2) + "\n".
import { createHash, hkdfSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { attest, canonicalize, challenge, keygen, multibase, rotate, sign } from 'sigelo';

const V = 'sigelo-invite/0', TYP_ANSWER = 'invite-answer', TYP_REPLY = 'invite-reply';
const T0 = 1791000000, CREATED = '2026-10-01T00:00:00Z'; // T0 = 2026-10-03T00:40:00Z
const RELAY = 'relay.example', TTL_MAX = 7 * 86400, SKEW = 300;
const OUT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'invite-v0.json');
const LABELS = { answer_topic: 'sigelo-invite/0 answer topic', reply_topic: 'sigelo-invite/0 reply topic', key: 'sigelo-invite/0 key',
  answer: 'sigelo-invite/0 answer\n', reply: 'sigelo-invite/0 reply\n', answer_id: 'sigelo-invite/0 answer id\n', code: 'sigelo-invite/0 code\n', pair_salt: 'sigelo-pair/0' };
// seed(label) = SHA-256(UTF-8 "sigelo-invite/0 " + label): identity secrets ("A0"), invite secrets
// ("secret " + case) and stand-ins for the X-Wing shared secret ("shared " + case). Genesis nonces:
// the first 16 bytes of SHA-256("sigelo-invite/0 nonce " + label).
const H = (b) => createHash('sha256').update(b).digest();
const seed = (l) => new Uint8Array(H(V + ' ' + l)), gnonce = (l) => seed('nonce ' + l).subarray(0, 16);
const hex = (b) => Buffer.from(b).toString('hex');
const LABEL_IDS = ['A0', 'A1', 'A2', 'A-recovery', 'A-recovery-2', 'B0', 'B-recovery', 'C0', 'C-recovery', 'M0', 'M-recovery', 'T', 'W', 'W-recovery', 'XA', 'XB', 'XC'];
const ZERO = 'sha256:' + '0'.repeat(64); // placeholder commitment: only to read a recovery seed's public key
const id = (l, recovery) => keygen({ seed: seed(l), recovery, created: CREATED, nonce: gnonce(l) });
const pub = (l) => id(l, ZERO).key;
const [aRec, aRec2, bRec, cRec, mRec, wRec] = ['A-recovery', 'A-recovery-2', 'B-recovery', 'C-recovery', 'M-recovery', 'W-recovery'].map(pub);
const A0 = id('A0', aRec), A1 = id('A1', aRec), T = id('T', aRec), A2 = id('A2', aRec2);
const B0 = id('B0', bRec), C0 = id('C0', cRec), M0 = id('M0', mRec), W = id('W', wRec);
// Throwaway geneses for the prefix attack: each carries the real genesis's recovery commitment
// (public), so a voluntary rotation from it into the real genesis is valid (SPEC §7).
const XA = id('XA', aRec), XB = id('XB', bRec), XC = id('XC', cRec);
const ids = { A0, A1, A2, B0, C0, M0, T, XA, XB, XC };

// Alice rotates A0 -> A1, then a thief holding A1's key rotates A1 -> T, and Alice recovers
// A1 -> A2. The recovery carries the EARLIER iat: precedence never reads timestamps (SPEC §7.1).
const rot = (from, to, iat, reason, secret) => rotate({ genesis: from.genesis, next_genesis: to.genesis, iat, reason, secret });
const rA1 = rot(A0, A1, T0 + 5000, 'voluntary', A0.secret), rA2 = rot(A1, A2, T0 + 7000, 'recovery', seed('A-recovery'));
const rT = rot(A1, T, T0 + 8000, 'voluntary', A1.secret);
const rXA = rot(XA, A0, T0 + 1, 'voluntary', XA.secret), rXB = rot(XB, B0, T0 + 1, 'voluntary', XB.secret), rXC = rot(XC, C0, T0 + 1, 'voluntary', XC.secret);
// One world W attests A0, so Alice's `attestations` is not empty (SPEC §5).
const wAtt = attest({ secret: W.secret, iss: W.did, sub: A0.did, iat: T0 - 86400, exp: T0 + 30 * 86400, ctx: 'example.world',
  admission: 'invite', admission_by: B0.did, claims: { joined: '2026-09-01', tasks: 12 } });
const bundle = (g, rotations = [], attestations = [], issuers = []) => ({ v: 'sigelo/0', typ: 'bundle', genesis: g.genesis, rotations, bindings: [], attestations, issuers });
const wa = [wAtt], wi = [W.genesis];
const bundles = {
  A0: bundle(A0, [], wa, wi), A1: bundle(A0, [rA1], wa, wi), A2_recovered: bundle(A0, [rA1, rA2], wa, wi), T_thief: bundle(A0, [rA1, rT], wa, wi),
  B0: bundle(B0), C0: bundle(C0), M0: bundle(M0),
  A2_prefixed: bundle(XA, [rXA, rA1, rA2], wa, wi), T_thief_prefixed: bundle(XA, [rXA, rA1, rT], wa, wi), B0_prefixed: bundle(XB, [rXB]), C0_prefixed: bundle(XC, [rXC]),
};

// ---------------------------------------------------------------- codes, by hand from the layout
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const digest = (who) => H(canonicalize(who.genesis)); // a DID is did:sigelo: + multibase of this digest
function raw({ version = 1, who, secret, exp, relay, rlen }) {
  const host = Buffer.from(relay, 'latin1');
  const body = Buffer.concat([Buffer.from([version]), digest(who), secret, u32(exp), Buffer.from([rlen ?? host.length]), host]);
  return Buffer.concat([body, H(body).subarray(0, 4)]);
}
const text = (bytes) => 'sgl1' + multibase(bytes).slice(1);
const derive = (secret, label, n) => Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), label, n));
const codes = {};
// secret: another code's, for a code that re-wraps it (case rewrapped_code).
function code(c, who, now, { ttl = 86400, relay = RELAY, secret = seed('secret ' + c) } = {}) {
  const exp = now + ttl, bytes = raw({ who, secret, exp, relay });
  codes[c] = { case: c, did: who.did, relay, now, ttl, exp, secret: hex(secret), length: bytes.length, bytes: hex(bytes), text: text(bytes),
    nonce: multibase(H(Buffer.concat([Buffer.from(LABELS.code), bytes]))), answer_topic: 'i/' + hex(derive(secret, LABELS.answer_topic, 16)),
    reply_topic: 'i/' + hex(derive(secret, LABELS.reply_topic, 16)), key: hex(derive(secret, LABELS.key, 32)) };
  return codes[c];
}
code('relay_sigelo_ai', A0, T0, { relay: 'relay.sigelo.ai' }); // the plan's example: 89 bytes

// ---------------------------------------------------------------- handshake messages, by hand
const shared = (c) => seed('shared ' + c);
const hashOf = (label, value) => multibase(H(Buffer.concat([Buffer.from(label), Buffer.from(canonicalize(value))])));
const idOf = (answer) => hashOf(LABELS.answer_id, answer);
// proof = {body: {v, typ, did: signer's current DID, nonce, transcript}, sig}; transcript = hash of the message without its proof.
function proofOf(signer, typ, nonce, label, rest) {
  const body = { v: V, typ, did: signer.did, nonce, transcript: hashOf(label, rest) };
  return { body, sig: sign(signer.secret, body) };
}
const opaque = (c, who) => ({ kem_pk: `opaque:kem_pk:${c}`, prekeys: { opaque: 'prekeys', of: who, case: c } });
function answerOf(cd, who, bname, { typ = TYP_ANSWER, signer = ids[who], b = bundles[bname] } = {}) {
  const o = opaque(cd.case, who), rest = { v: V, typ: 'answer', bundle: b, kem_pk: o.kem_pk, prekeys: o.prekeys };
  return { ...rest, proof: proofOf(signer, typ, cd.nonce, LABELS.answer, rest) };
}
function replyOf(c, answerId, who, bname) {
  const rest = { v: V, typ: 'reply', bundle: bundles[bname], kem_ct: `opaque:kem_ct:${c}`, prekeys: { opaque: 'prekeys', of: who, case: c } };
  return { ...rest, proof: proofOf(ids[who], TYP_REPLY, answerId, LABELS.reply, rest) };
}
// What a general-purpose challenge signer hands out: a SPEC §5.2 challenge, any ctx and nonce, for its own DID.
const laundered = (who, ctx, nonce) => challenge({ secret: who.secret, genesis: who.genesis, ctx, nonce });
const K = (cd, x, y) => hex(hkdfSync('sha256', Buffer.concat([Buffer.from(cd.secret, 'hex'), shared(cd.case)]), LABELS.pair_salt, [x.did, y.did].sort().join(''), 32));
const accepted = (original, cur, { att = false, rekeyed = false, pair_key, secret, answer_id }) => ({ did: original.did, current_did: cur.did, current_key: cur.key,
  attestations: att ? { [W.did]: [wAtt.body] } : {}, rejected: { attestations: 0, bindings: 0 }, rekeyed, pair_key, ...(secret !== undefined && { secret, answer_id }) });
const contact = (name, original, cur, pair_key, relay = RELAY, revoked = false) => ({ name, did: original.did, current_did: cur.did, current_key: cur.key, revoked, relay, pair_key });

// ---------------------------------------------------------------- steps, run in order
const steps = [];
const push = (s) => steps.push(s);
// peer: on a re-key code (name null), the contact it is for.
const invite = (c, store, cd, name, peer = null) => push({ case: c, store, op: 'invite', now: cd.now, code: cd.case, name, peer });
function answer(c, store, cd, who, now, name) {
  const a = answerOf(cd, who, who), o = opaque(cd.case, who);
  push({ case: c, store, op: 'answer', now, code: cd.text, identity: who, bundle: who, kem_pk: o.kem_pk, prekeys: o.prekeys, name, kem_sk: `opaque:kem_sk:${cd.case}`, expect: { answer: a, answer_id: idOf(a) } });
  return a;
}
const checkA = (c, store, now, a, cd, outcome) => push({ case: c, store, op: 'check_answer', now, answer: a, shared: hex(shared(cd.case)), ...outcome });
// Alice's answer for a checked answer `a`: what checkA returned as answer_id.
const aliceGot = (a, cd, original, opts = {}) => ({ expect: accepted(original, original, { ...opts, pair_key: K(cd, A0, original), secret: cd.secret, answer_id: idOf(a) }) });
function reply(c, store, cd, a, who, bname) {
  const r = replyOf(cd.case, idOf(a), who, bname);
  push({ case: c, store, op: 'reply', identity: who, bundle: bname, answer_id: idOf(a), kem_ct: r.kem_ct, prekeys: r.prekeys, expect: r });
  return r;
}
// kem_sk: what agree() must be handed back, the stand-in Bob gave addAccept for this code.
const checkR = (c, store, now, r, cd, outcome) => push({ case: c, store, op: 'check_reply', now, reply: r, shared: hex(shared(cd.case)), kem_sk: `opaque:kem_sk:${cd.case}`, ...outcome });
const lookup = (c, store, now, did, expect) => push({ case: c, store, op: 'lookup', now, did, expect });

// Both directions: Alice invites, Bob answers, Alice checks and replies, Bob checks. One K for both.
let cd = code('pair', A0, T0);
invite('pair', 'A', cd, 'bob');
const first = answer('pair', 'B', cd, 'B0', T0 + 10, 'alice');
const kPair = K(cd, A0, B0);
checkA('pair', 'A', T0 + 20, first, cd, aliceGot(first, cd, B0));
const firstReply = reply('pair', 'A', cd, first, 'A0', 'A0');
checkR('pair', 'B', T0 + 30, firstReply, cd, { expect: accepted(A0, A0, { att: true, pair_key: kPair }) });
lookup('pair', 'A', T0 + 40, B0.did, contact('bob', B0, B0, kPair));
lookup('pair', 'B', T0 + 40, A0.did, contact('alice', A0, A0, kPair));
checkA('replayed_answer', 'A', T0 + 50, first, cd, { error: 'challenge_unknown' });
checkR('replayed_reply', 'B', T0 + 60, firstReply, cd, { error: 'challenge_unknown' });

// Single use: a forged first answer (Mallory's signature on Bob's proof) burns the secret, so
// Bob's genuine answer that follows is refused.
cd = code('single_use', A0, T0 + 100);
invite('single_use', 'A', cd, 'someone');
const genuine = answer('single_use', 'B', cd, 'B0', T0 + 110, 'alice');
checkA('single_use', 'A', T0 + 120, { ...genuine, proof: { body: genuine.proof.body, sig: sign(M0.secret, genuine.proof.body) } }, cd, { error: 'sig' });
checkA('single_use', 'A', T0 + 130, genuine, cd, { error: 'challenge_unknown' });

// Expiry: Bob refuses the code once expired; Alice refuses an answer read after the expiry.
cd = code('expired', A0, T0 + 200, { ttl: 3600 });
invite('expired', 'A', cd, 'late');
const late = answer('expired', 'B', cd, 'B0', T0 + 210, 'alice');
push({ case: 'expired', store: 'B', op: 'answer', now: cd.exp, code: cd.text, identity: 'B0', bundle: 'B0', ...opaque(cd.case, 'B0'), name: 'alice', error: 'code_expired' });
checkA('expired', 'A', cd.exp, late, cd, { error: 'challenge_expired' });

// Forged answers, each against its own invite (every answer burns one).
cd = code('card_did', A0, T0 + 4000);
invite('card_did', 'A', cd, 'x');
checkA('card_did', 'A', T0 + 4010, answerOf(cd, 'B0', 'B0', { signer: M0 }), cd, { error: 'card_did' });
// The two proofs cannot stand in for each other: a reply-typed proof in an answer.
cd = code('challenge_body', A0, T0 + 4100);
invite('challenge_body', 'A', cd, 'x');
checkA('challenge_body', 'A', T0 + 4110, answerOf(cd, 'B0', 'B0', { typ: TYP_REPLY }), cd, { error: 'challenge_body' });
// Mallory holds a code Alice gave her. Bob's challenge signer signs her the old plan's §5.2
// challenge for it; she answers as Bob with her own key agreement. Bob's pairing stays as it was.
cd = code('laundered_answer', A0, T0 + 4150);
invite('laundered_answer', 'A', cd, 'mallory');
checkA('laundered_answer', 'A', T0 + 4160, { v: V, typ: 'answer', bundle: bundles.B0, ...opaque(cd.case, 'M0'), proof: laundered(B0, V, cd.nonce) }, cd, { error: 'challenge_body' });
lookup('laundered_answer', 'A', T0 + 4170, B0.did, contact('bob', B0, B0, kPair));
// Mallory holds a code Alice gave her and re-wraps its secret in a code naming herself (the
// checksum is no MAC). Bob answers it, meaning to pair with Mallory, and his answer lands on
// Alice's answer topic, which the secret alone sets. His proof's nonce is the hash of the code
// he read, so Alice finds no invite of hers under it: her contact Bob keeps his key, and her
// code for Mallory is still pending. Alike for a code whose relay someone on the way rewrote.
cd = code('rewrapped_code', A0, T0 + 4180);
invite('rewrapped_code', 'A', cd, 'mallory');
const rewrapped = code('rewrapped_code_mallory', M0, T0 + 4180, { secret: Buffer.from(cd.secret, 'hex') });
const toMalloryCode = answer('rewrapped_code', 'B', rewrapped, 'B0', T0 + 4185, 'mallory');
checkA('rewrapped_code', 'A', T0 + 4190, toMalloryCode, cd, { error: 'challenge_unknown' });
lookup('rewrapped_code', 'A', T0 + 4195, B0.did, contact('bob', B0, B0, kPair));
const relayed = code('relay_rewritten', A0, T0 + 4180, { relay: 'evil.example', secret: Buffer.from(cd.secret, 'hex') });
checkA('relay_rewritten', 'A', T0 + 4196, answer('relay_rewritten', 'C', relayed, 'C0', T0 + 4186, 'alice'), cd, { error: 'challenge_unknown' });
checkA('rewrapped_code', 'A', T0 + 4197, answerOf(cd, 'M0', 'M0'), cd, aliceGot(answerOf(cd, 'M0', 'M0'), cd, M0));
// On the path with the code: Bob's one-time key, then his prekeys, swapped; his proof kept.
cd = code('swapped_key', A0, T0 + 4200);
invite('swapped_key', 'A', cd, 'x');
checkA('swapped_key', 'A', T0 + 4210, { ...answerOf(cd, 'B0', 'B0'), kem_pk: 'opaque:kem_pk:mallory' }, cd, { error: 'transcript' });
cd = code('swapped_prekeys', A0, T0 + 4250);
invite('swapped_prekeys', 'A', cd, 'x');
checkA('swapped_prekeys', 'A', T0 + 4260, { ...answerOf(cd, 'B0', 'B0'), prekeys: { opaque: 'prekeys', of: 'M0' } }, cd, { error: 'transcript' });
cd = code('kem', A0, T0 + 4400);
invite('kem', 'A', cd, 'x');
push({ case: 'kem', store: 'A', op: 'check_answer', now: T0 + 4410, answer: answerOf(cd, 'B0', 'B0'), shared: '', error: 'kem' });
cd = code('bad_bundle', A0, T0 + 4450);
invite('bad_bundle', 'A', cd, 'x');
checkA('bad_bundle', 'A', T0 + 4460, answerOf(cd, 'C0', 'C0', { b: { ...bundles.C0, extra: 1 } }), cd, { error: 'bundle' }); // Carol: not yet a contact

// Bob answers a code from Mallory, whom he does not know, as if from a known contact (name null).
cd = code('not_contact', M0, T0 + 4300, { relay: 'relay.example:8883' });
const toMallory = answer('not_contact', 'B', cd, 'B0', T0 + 4310, null);
checkR('not_contact', 'B', T0 + 4320, replyOf(cd.case, idOf(toMallory), 'M0', 'M0'), cd, { error: 'not_contact' });

// Mallory holds the code and reads Bob's answer, then replies herself: the code's DID is not in
// her chain. A malformed reply before it fails `card`, which runs before the nonce is looked up
// (sigelo-pair's order), so it does not use up Bob's pending answer; the failed reply does, so
// Alice's genuine reply after it is refused.
cd = code('chain_lacks_code_did', A0, T0 + 4500);
invite('chain_lacks_code_did', 'A', cd, 'bob');
const intercepted = answer('chain_lacks_code_did', 'B', cd, 'B0', T0 + 4510, 'alice');
const mallory = replyOf(cd.case, idOf(intercepted), 'M0', 'M0'), { prekeys: _, ...noPrekeys } = mallory;
checkR('chain_lacks_code_did', 'B', T0 + 4515, noPrekeys, cd, { error: 'card' });
checkR('chain_lacks_code_did', 'B', T0 + 4520, mallory, cd, { error: 'code_did' });
checkR('chain_lacks_code_did', 'B', T0 + 4525, replyOf(cd.case, idOf(intercepted), 'A0', 'A0'), cd, { error: 'challenge_unknown' });

// A malformed answer fails `card` and leaves the invite in place; the genuine answer then pairs
// (a re-key code, pinned to Bob, whom Alice knows).
cd = code('malformed_answer', A0, T0 + 4600);
invite('malformed_answer', 'A', cd, null, B0.did);
const wellFormed = answer('malformed_answer', 'B', cd, 'B0', T0 + 4610, null);
checkA('malformed_answer', 'A', T0 + 4620, { ...wellFormed, extra: 1 }, cd, { error: 'card' });
checkA('malformed_answer', 'A', T0 + 4630, wellFormed, cd, aliceGot(wellFormed, cd, B0, { rekeyed: true }));

// Rotated inviter: Alice's code names A1; Carol, new to her, stores her under A0.
cd = code('rotated_inviter', A1, T0 + 6000);
invite('rotated_inviter', 'A', cd, 'carol');
const toCarol = answer('rotated_inviter', 'C', cd, 'C0', T0 + 6010, 'alice');
checkA('rotated_inviter', 'A', T0 + 6020, toCarol, cd, aliceGot(toCarol, cd, C0));
checkR('rotated_inviter', 'C', T0 + 6030, reply('rotated_inviter', 'A', cd, toCarol, 'A1', 'A1'), cd, { expect: accepted(A0, A1, { att: true, pair_key: K(cd, A0, C0) }) });
lookup('rotated_inviter', 'C', T0 + 6040, A1.did, contact('alice', A0, A1, K(cd, A0, C0)));
// The code names A0, made before Alice rotated; she replies as A1. A0 is in her chain: accepted.
cd = code('code_names_earlier_did', A0, T0 + 6100);
invite('code_names_earlier_did', 'A', cd, null, C0.did);
const fromCarol = answer('code_names_earlier_did', 'C', cd, 'C0', T0 + 6110, null);
checkA('code_names_earlier_did', 'A', T0 + 6120, fromCarol, cd, aliceGot(fromCarol, cd, C0, { rekeyed: true }));
checkR('code_names_earlier_did', 'C', T0 + 6130, reply('code_names_earlier_did', 'A', cd, fromCarol, 'A1', 'A1'), cd, { expect: accepted(A0, A1, { att: true, rekeyed: true, pair_key: K(cd, A0, C0) }) });
// A re-key code is pinned to its contact: Bob, a contact too, cannot use Carol's, and his attempt uses it up.
cd = code('rekey_pinned', A1, T0 + 6200);
invite('rekey_pinned', 'A', cd, null, C0.did);
checkA('rekey_pinned', 'A', T0 + 6210, answerOf(cd, 'B0', 'B0'), cd, { error: 'challenge_did' });
checkA('rekey_pinned', 'A', T0 + 6220, answerOf(cd, 'C0', 'C0'), cd, { error: 'challenge_unknown' });
// One original DID per peer: Carol, known from C0, answers a new contact's code with her chain
// behind a throwaway genesis XC. Keyed by its first DID, that would be a second record.
cd = code('prefixed_known', A1, T0 + 6300);
invite('prefixed_known', 'A', cd, 'carol again');
checkA('prefixed_known', 'A', T0 + 6310, answerOf(cd, 'C0', 'C0_prefixed'), cd, { error: 'original_did' });
lookup('prefixed_known', 'A', T0 + 6320, XC.did, null);

// Recovery: Alice (A2 now) re-keys with Bob, who learns the recovery; then the thief, holding
// A1's key, sends Bob a code of its own: its rotation loses to the recovery Bob has seen.
cd = code('recovered', A2, T0 + 9000);
invite('recovered', 'A', cd, null, B0.did);
const reKey = answer('recovered', 'B', cd, 'B0', T0 + 9010, null);
checkA('recovered', 'A', T0 + 9020, reKey, cd, aliceGot(reKey, cd, B0, { rekeyed: true }));
checkR('recovered', 'B', T0 + 9030, reply('recovered', 'A', cd, reKey, 'A2', 'A2_recovered'), cd, { expect: accepted(A0, A2, { att: true, rekeyed: true, pair_key: K(cd, A0, B0) }) });
lookup('recovered', 'B', T0 + 9040, A2.did, contact('alice', A0, A2, K(cd, A0, B0)));
const kRecovered = K(cd, A0, B0);
cd = code('recovery_beats_thief', T, T0 + 9100);
const toThief = answer('recovery_beats_thief', 'B', cd, 'B0', T0 + 9110, null);
checkR('recovery_beats_thief', 'B', T0 + 9120, replyOf(cd.case, idOf(toThief), 'T', 'T_thief'), cd, { error: 'stale_chain' });
lookup('recovery_beats_thief', 'B', T0 + 9130, T.did, null); // the thief's DID left the chain
lookup('recovery_beats_thief', 'B', T0 + 9130, A0.did, contact('alice', A0, A2, kRecovered));
// The thief again, on a new contact's code, with a throwaway genesis XA in front of Alice's
// chain: Bob's record is found through A0 and A1 all the same, and the recovery wins.
cd = code('prefixed_thief', T, T0 + 9150);
const toThief2 = answer('prefixed_thief', 'B', cd, 'B0', T0 + 9160, 'new friend');
checkR('prefixed_thief', 'B', T0 + 9170, replyOf(cd.case, idOf(toThief2), 'T', 'T_thief_prefixed'), cd, { error: 'stale_chain' });
lookup('prefixed_thief', 'B', T0 + 9180, XA.did, null);
// Mallory mints a code naming Alice's DID, with her own secret and relay, and Bob takes it for
// Alice's. Alice's challenge signer signs Mallory a §5.2 challenge over Bob's answer id: no reply
// proof. Bob's record of Alice keeps its key and relay.
cd = code('laundered_reply', A2, T0 + 9200, { relay: 'evil.example' });
const toFakeAlice = answer('laundered_reply', 'B', cd, 'B0', T0 + 9210, null);
const fakeReply = { v: V, typ: 'reply', bundle: bundles.A2_recovered, kem_ct: 'opaque:kem_ct:mallory', prekeys: { opaque: 'prekeys', of: 'M0' }, proof: laundered(A2, `${V} reply`, idOf(toFakeAlice)) };
checkR('laundered_reply', 'B', T0 + 9220, fakeReply, cd, { error: 'challenge_body' });
lookup('laundered_reply', 'B', T0 + 9230, A0.did, contact('alice', A0, A2, kRecovered));
// On the path with the code: each member of Alice's reply swapped or rewritten, her proof kept.
const tampers = {
  swapped_kem_ct: (r) => ({ ...r, kem_ct: 'opaque:kem_ct:mallory' }),
  swapped_reply_prekeys: (r) => ({ ...r, prekeys: { opaque: 'prekeys', of: 'M0' } }),
  stripped_reply_bundle: (r) => ({ ...r, bundle: { ...r.bundle, attestations: [], issuers: [] } }),
  prefixed_reply_bundle: (r) => ({ ...r, bundle: bundles.A2_prefixed }),
};
Object.entries(tampers).forEach(([c, tamper], i) => {
  const at = T0 + 9300 + 20 * i;
  cd = code(c, A2, at);
  const a = answer(c, 'B', cd, 'B0', at + 5, null);
  checkR(c, 'B', at + 10, tamper(replyOf(cd.case, idOf(a), 'A2', 'A2_recovered')), cd, { error: 'transcript' });
});

// Revocation is local and final: Bob's pending answer to Alice dies with it, and a later
// pairing is refused; Alice still holds Bob.
cd = code('revoke_kills_pending', A2, T0 + 9500);
invite('revoke_kills_pending', 'A', cd, null, B0.did);
const pending = answer('revoke_kills_pending', 'B', cd, 'B0', T0 + 9510, null);
push({ case: 'revoke_kills_pending', store: 'B', op: 'revoke', now: T0 + 9520, did: A0.did, expect: contact('alice', A0, A2, null, RELAY, true) });
checkA('revoke_kills_pending', 'A', T0 + 9530, pending, cd, aliceGot(pending, cd, B0, { rekeyed: true }));
checkR('revoke_kills_pending', 'B', T0 + 9540, reply('revoke_kills_pending', 'A', cd, pending, 'A2', 'A2_recovered'), cd, { error: 'challenge_unknown' });
cd = code('revoked', A2, T0 + 9600);
invite('revoked', 'A', cd, null, B0.did);
const afterRevoke = answer('revoked', 'B', cd, 'B0', T0 + 9610, null);
checkA('revoked', 'A', T0 + 9620, afterRevoke, cd, aliceGot(afterRevoke, cd, B0, { rekeyed: true }));
checkR('revoked', 'B', T0 + 9630, reply('revoked', 'A', cd, afterRevoke, 'A2', 'A2_recovered'), cd, { error: 'revoked' });
lookup('revoke_is_local', 'A', T0 + 9640, B0.did, contact('bob', B0, B0, K(cd, A0, B0)));
// Alice revokes Bob. He answers new contacts' codes: plainly, then with his chain behind a
// throwaway genesis XB. Keyed by its first DID, the second would be a fresh, live record.
push({ case: 'prefixed_revoked', store: 'A', op: 'revoke', now: T0 + 9700, did: B0.did, expect: contact('bob', B0, B0, null, RELAY, true) });
cd = code('revoked_new_code', A2, T0 + 9710);
invite('revoked_new_code', 'A', cd, 'new friend');
checkA('revoked_new_code', 'A', T0 + 9720, answerOf(cd, 'B0', 'B0'), cd, { error: 'revoked' });
cd = code('prefixed_revoked', A2, T0 + 9730);
invite('prefixed_revoked', 'A', cd, 'new friend');
checkA('prefixed_revoked', 'A', T0 + 9740, answerOf(cd, 'B0', 'B0_prefixed'), cd, { error: 'revoked' });
lookup('prefixed_revoked', 'A', T0 + 9750, XB.did, null);
lookup('prefixed_revoked', 'A', T0 + 9750, B0.did, contact('bob', B0, B0, null, RELAY, true));
for (const s of steps) if (s.op.startsWith('check') && !s.expect && !s.error) throw new Error('step without outcome');

// ---------------------------------------------------------------- parsing
const P = codes.pair, Pb = Buffer.from(P.bytes, 'hex'), Pin = { who: A0, secret: Buffer.from(P.secret, 'hex'), exp: P.exp, relay: RELAY };
const swap = (s, i, ch) => s.slice(0, i) + ch + s.slice(i + 1);
const typo = swap(P.text, 30, P.text[30] === '2' ? '3' : '2');
const parse = [
  ...Object.values(codes).map((c) => ({ case: 'round_trip_' + c.case, text: c.text, now: c.now, expect: { did: c.did, secret: c.secret, exp: c.exp, relay: c.relay } })),
  { case: 'typo', text: typo, now: T0, error: 'code_checksum' },
  { case: 'look_alike_zero', text: swap(P.text, 30, '0'), now: T0, error: 'code_checksum' },
  { case: 'truncated', text: P.text.slice(0, -1), now: T0, error: 'code_checksum' },
  // A typo in the prefix is a typo, not another version.
  { case: 'prefix_capital_i', text: swap(P.text, 2, 'I'), now: T0, error: 'code_checksum' },
  { case: 'prefix_capital_s', text: swap(P.text, 0, 'S'), now: T0, error: 'code_checksum' },
  { case: 'first_character_lost', text: P.text.slice(1), now: T0, error: 'code_checksum' },
  { case: 'expired', text: P.text, now: P.exp, error: 'code_expired' },
  { case: 'last_second', text: P.text, now: P.exp - 1, expect: { did: P.did, secret: P.secret, exp: P.exp, relay: RELAY } },
  { case: 'ttl_max_plus_skew', text: text(raw({ ...Pin, exp: T0 + TTL_MAX + SKEW })), now: T0, expect: { did: P.did, secret: P.secret, exp: T0 + TTL_MAX + SKEW, relay: RELAY } },
  { case: 'ttl_beyond_max', text: text(raw({ ...Pin, exp: T0 + TTL_MAX + SKEW + 1 })), now: T0, error: 'code_ttl' },
  { case: 'prefix', text: 'sgl2' + P.text.slice(4), now: T0, error: 'code_version' },
  { case: 'version_2', text: text(raw({ ...Pin, version: 2 })), now: T0, error: 'code_version' },
  { case: 'relay_length_byte_too_big', text: text(raw({ ...Pin, rlen: RELAY.length + 1 })), now: T0, error: 'code_length' },
  { case: 'relay_empty', text: text(raw({ ...Pin, relay: '' })), now: T0, error: 'code_length' },
  { case: 'relay_64', text: text(raw({ ...Pin, relay: 'a'.repeat(64) })), now: T0, error: 'code_length' },
  { case: 'relay_uppercase', text: text(raw({ ...Pin, relay: 'Relay.example' })), now: T0, error: 'code_relay' },
  { case: 'relay_port_65536', text: text(raw({ ...Pin, relay: 'relay.example:65536' })), now: T0, error: 'code_relay' },
  { case: 'relay_port_leading_zero', text: text(raw({ ...Pin, relay: 'relay.example:08883' })), now: T0, error: 'code_relay' },
  { case: 'too_short', text: 'sgl1' + multibase(Pb.subarray(0, 4)).slice(1), now: T0, error: 'code_length' },
  { case: 'too_long', text: 'sgl1' + '2'.repeat(189), now: T0, error: 'code_length' },
];

const out = {
  v: V,
  note: 'Invite codes and the invite handshake. `codes`: exact bytes and text from the inputs, and what the secret yields. `parse`: parseInvite(text, now) gives `expect` or fails with `error`. `steps`: run in order against empty contact stores (`stores`: name -> owner); each step gives `expect` by value or fails with `error`, the first failing check. kem_pk, kem_ct and prekeys are opaque stand-ins; `shared` stands in for the X-Wing shared secret, which agree() returns; on check_reply, agree() must be handed `kem_sk`, the value the answer step gave addAccept, keyed by its answer_id. See invite.mjs.',
  layout: 'version 0x01 (1) | inviter current DID digest (32) | secret (32) | expiry, Unix seconds, unsigned big-endian (4) | relay length (1) | relay host[:port], lowercase ASCII, 1..63 | checksum = SHA-256(all before)[0..4]; text = "sgl1" + base58btc',
  ttl: { default: 86400, max: TTL_MAX, skew: SKEW },
  typ: { answer: TYP_ANSWER, reply: TYP_REPLY },
  labels: LABELS,
  derivations: {
    nonce: '"z" + base58btc(SHA-256(labels.code ‖ the whole code\'s bytes, checksum included)): the nonce of Bob\'s proof, and the key of Alice\'s pending invite; it binds the inviter\'s DID, the relay and the expiry with the secret, so an answer to a code that re-wraps the secret fails challenge_unknown (cases rewrapped_code, relay_rewritten)',
    answer_topic: '"i/" + hex(HKDF-SHA256(secret, no salt, labels.answer_topic, 16))',
    reply_topic: '"i/" + hex(HKDF-SHA256(secret, no salt, labels.reply_topic, 16))',
    key: 'HKDF-SHA256(secret, no salt, labels.key, 32): XChaCha20-Poly1305 key of answer and reply',
    proof: '{body: {v, typ: typ.answer or typ.reply, did: the signer\'s current DID, nonce, transcript}, sig: Ed25519 over "sigelo\\n" ‖ JCS(body)}; not a SPEC §5.2 challenge',
    transcript: '"z" + base58btc(SHA-256(labels.answer or labels.reply ‖ JCS(the message without proof))): the answer\'s covers v, typ, bundle, kem_pk and prekeys; the reply\'s covers v, typ, bundle, kem_ct and prekeys, so a code holder on the path who swaps the encapsulation fails transcript (case swapped_kem_ct)',
    answer_id: '"z" + base58btc(SHA-256(labels.answer_id ‖ JCS(the whole answer))): the key of Bob\'s pending answer, and the nonce of Alice\'s proof',
    pair_key: 'HKDF-SHA256(secret ‖ shared, salt labels.pair_salt, info = the two original DIDs sorted and concatenated, 32)',
  },
  created: CREATED,
  stores: { A: 'A0', B: 'B0', C: 'C0' },
  seeds: Object.fromEntries(LABEL_IDS.map((l) => [l, hex(seed(l))])),
  geneses: Object.fromEntries(Object.entries(ids).map(([k, v]) => [k, v.genesis])),
  dids: Object.fromEntries(Object.entries({ ...ids, W }).map(([k, v]) => [k, v.did])),
  codes: Object.values(codes),
  parse,
  bundles,
  steps,
};
const json = JSON.stringify(out, null, 2) + '\n';
if (process.argv.includes('--check')) {
  let cur = ''; try { cur = readFileSync(OUT, 'utf8'); } catch {}
  if (cur !== json) { console.error('FAIL fixtures/invite-v0.json differs from what the seeds generate: run node contact/gen-invite.mjs'); process.exit(1); }
  console.log(`ok fixtures/invite-v0.json reproduces from the seeds (${out.codes.length} codes, ${parse.length} parse cases, ${steps.length} steps)`);
} else writeFileSync(OUT, json);
