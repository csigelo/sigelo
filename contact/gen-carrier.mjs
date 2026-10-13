// SPDX-License-Identifier: MIT
// Regenerates fixtures/carrier-v0.json, byte for byte, from the documented seeds below: the frames
// of contract sigelo-carrier/0 (carrier.mjs header, "Frames"), kinds 1, 2, 4 and 5.
//   node contact/gen-carrier.mjs           write the file
//   node contact/gen-carrier.mjs --check   exit 1 if the committed file differs
// Independent of carrier.mjs, invite.mjs and prekeys.mjs on purpose: headers, keys, topics,
// padding, proofs and prekey bundles are assembled here from the contract with @noble and the
// sigelo library, so the fixture checks carrier.mjs (test-carrier.mjs) instead of echoing it.
// Seeds: seed(label) = SHA-256(UTF-8 "sigelo-carrier/0 " + label); genesis nonces are the first 16
// bytes of SHA-256("sigelo-carrier/0 nonce " + label). Every other random input comes from
// rng(label): the stream SHA-256(seed("rng " + label) ‖ u32be(0)) ‖ SHA-256(… ‖ u32be(1)) ‖ …,
// read in order. Ed25519 and X-Wing (@noble/post-quantum ml_kem768_x25519 keygen(seed32),
// encapsulate(pk, rand64)) are deterministic. Output: JSON.stringify(out, null, 2) + "\n".
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { canonicalize, keygen, multibase, rotate, sign } from 'sigelo';

export const V = 'sigelo-carrier/0';
export const T0 = 1791256800, CREATED = '2026-10-01T00:00:00Z'; // T0 = 2026-10-06T03:20:00Z, 2026-W41
export const OUT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'carrier-v0.json');
const DAY = 86400, RELAY = 'relay.sigelo.ai';
// Frames whose whole bytes are written out as hex; longer ones (a prekey bundle inside) are pinned
// by their SHA-256 and length, which fix the bytes as well, and rebuild from the listed inputs.
const HEX_MAX = 4096;

const u8 = utf8ToBytes, hex = bytesToHex;
export const seed = (l) => sha256(u8(`${V} ${l}`));
const gnonce = (l) => sha256(u8(`${V} nonce ${l}`)).slice(0, 16);
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
const b64u = (b) => Buffer.from(b).toString('base64url');
const ZERO = 'sha256:' + '0'.repeat(64); // placeholder commitment: only to read a recovery seed's public key
const id = (l, recovery) => keygen({ seed: seed(l), recovery, created: CREATED, nonce: gnonce(l) });
const chainOf = (genesis, rotations = []) => ({ v: 'sigelo/0', typ: 'bundle', genesis, rotations, bindings: [], attestations: [], issuers: [] });

// ---------------------------------------------------------------- the frame, by hand
// version 0x01 | kind | 16 zero bytes | counter 1 (u32 BE) | nonce (24) | XChaCha20-Poly1305 of
// pad(JCS(value)), additional data = the 22-byte header ‖ UTF-8 topic. pad: 0x80, then 0x00 up to
// the next multiple of 256 (ISO/IEC 7816-4, always 1 to 256 bytes added).
const head = (kind) => Uint8Array.of(1, kind, ...new Uint8Array(16), 0, 0, 0, 1);
function pad(b) { const out = new Uint8Array((Math.floor(b.length / 256) + 1) * 256); out.set(b); out[b.length] = 0x80; return out; }
const frameOf = (kind, key, topic, plaintext, nonce) => concatBytes(head(kind), nonce, xchacha20poly1305(key, nonce, concatBytes(head(kind), u8(topic))).encrypt(plaintext));
const derive = (ikm, salt, info, n) => hkdf(sha256, ikm, salt === null ? undefined : u8(salt), u8(info), n);

export function build() {
  // Identities: alice (A0) invites, bob (B0) answers and later rotates to B1.
  const [aRec, bRec] = ['A-recovery', 'B-recovery'].map((l) => id(l, ZERO).key);
  const A0 = id('A0', aRec), B0 = id('B0', bRec), B1 = id('B1', bRec);
  const rB1 = rotate({ genesis: B0.genesis, next_genesis: B1.genesis, iat: T0 + 100, reason: 'voluntary', secret: B0.secret });

  // The invite secret, alice's code and what they yield (contact/invite.mjs, sigelo-invite/0). Code:
  // version 1 | SHA-256(JCS(A0's genesis)) | secret | exp, u32 BE | relay length | relay | checksum =
  // SHA-256(all before)[0..4]. Its nonce hashes the whole code, so it binds the inviter it names.
  const secret = seed('invite secret'), exp = T0 + DAY, expBytes = new Uint8Array(4);
  new DataView(expBytes.buffer).setUint32(0, exp);
  const codeBody = concatBytes(Uint8Array.of(1), sha256(u8(canonicalize(A0.genesis))), secret, expBytes, Uint8Array.of(RELAY.length), u8(RELAY));
  const code = concatBytes(codeBody, sha256(codeBody).subarray(0, 4));
  const invite = { secret: hex(secret), relay: RELAY, exp, code: hex(code), nonce: multibase(sha256(concatBytes(u8('sigelo-invite/0 code\n'), code))),
    answer_topic: 'i/' + hex(derive(secret, null, 'sigelo-invite/0 answer topic', 16)),
    reply_topic: 'i/' + hex(derive(secret, null, 'sigelo-invite/0 reply topic', 16)),
    key: hex(derive(secret, null, 'sigelo-invite/0 key', 32)) };
  const hashOf = (label, value) => multibase(sha256(concatBytes(u8(label), u8(canonicalize(value)))));
  const proof = (signer, typ, nonce, label, rest) => {
    const body = { v: 'sigelo-invite/0', typ, did: signer.did, nonce, transcript: hashOf(label, rest) };
    return { body, sig: sign(signer.secret, body) };
  };

  // Bob's answer: his chain, a one-time X-Wing key, no prekeys (they name a pairing not made yet).
  const kem = xwing.keygen(rng('kem key')(32));
  const answerRest = { v: 'sigelo-invite/0', typ: 'answer', bundle: chainOf(B0.genesis), kem_pk: b64u(kem.publicKey), prekeys: null };
  const answer = { ...answerRest, proof: proof(B0, 'invite-answer', invite.nonce, 'sigelo-invite/0 answer\n', answerRest) };
  const answerId = hashOf('sigelo-invite/0 answer id\n', answer);

  // Alice's encapsulation to it, and the pairing key both derive.
  const enc = xwing.encapsulate(kem.publicKey, rng('kem ct')(64));
  const K = derive(concatBytes(secret, enc.sharedSecret), 'sigelo-pair/0', [A0.did, B0.did].sort().join(''), 32);
  const pair = hex(derive(K, 'sigelo-pair-id/0', '', 16));

  // A prekey bundle (sigelo-msg/0 "Prekeys"): per one-time key an id (16) then a keygen seed (32),
  // twenty of them, then the same for the last-resort key.
  const bundleOf = (who, label, iat) => {
    const g = rng(label), key = () => { const kid = hex(g(16)); return { id: kid, pk: b64u(xwing.keygen(g(32)).publicKey) }; };
    const keys = Array.from({ length: 20 }, key), last_resort = key();
    const body = { v: 'sigelo-msg/0', typ: 'prekeys', did: who.did, pair, iat, exp: iat + 31 * DAY, keys, last_resort };
    return { body, sig: sign(who.secret, body) };
  };
  const replyRest = { v: 'sigelo-invite/0', typ: 'reply', bundle: chainOf(A0.genesis), kem_ct: b64u(enc.cipherText), prekeys: bundleOf(A0, 'alice prekeys', T0 + 20) };
  const reply = { ...replyRest, proof: proof(A0, 'invite-reply', answerId, 'sigelo-invite/0 reply\n', replyRest) };

  // Bob -> Alice mailbox: topic of the week, the prekeys frame's key and the notice key.
  const isoWeek = (unix) => {
    const day = Math.floor(unix / DAY), dow = (day + 3) % 7, thursday = new Date((day - dow + 3) * 86400000), year = thursday.getUTCFullYear();
    return `${year}-W${String(Math.floor((thursday - Date.UTC(year, 0, 1)) / (7 * 86400000)) + 1).padStart(2, '0')}`;
  };
  const week = isoWeek(T0), mailbox = 'm/' + hex(derive(K, 'sigelo-topic/0', `${B0.did}\n${A0.did}\n${week}`, 16));
  const prekeysKey = derive(K, 'sigelo-prekeys/0', `${B0.did}\n${A0.did}`, 32), noticeKey = derive(K, 'sigelo-notice/0', `${B0.did}\n${A0.did}`, 32);
  const noticeBody = { v: V, typ: 'contact-notice', did: B1.did, pair };
  const notice = { bundle: chainOf(B0.genesis, [rB1]), proof: { body: noticeBody, sig: sign(B1.secret, noticeBody) } };

  const frames = [];
  const counting = Uint8Array.from({ length: 24 }, (_, i) => i + 1);
  const frame = (c, kind, keyFrom, key, topic, value, note, nonce = rng(`nonce ${c}`)(24)) => {
    const bytes = frameOf(kind, key, topic, pad(u8(canonicalize(value))), nonce);
    frames.push({ case: c, kind, key_from: keyFrom, key: hex(key), topic, nonce: hex(nonce), value, note, length: bytes.length, sha256: hex(sha256(bytes)),
      ...(bytes.length <= HEX_MAX && { hex: hex(bytes) }) });
  };
  // The same small value framed as each kind under one key and topic: the framing alone. JCS
  // writes é and U+2028 raw; some JSON encoders escape U+2028, which would change every byte after.
  const generic = { v: 'sigelo-invite/0', typ: 'answer', n: 1, text: '\u00e9\u2028' }, gkey = seed('frame key'), gtopic = 'i/' + '0'.repeat(32);
  for (const kind of [1, 2, 4, 5]) frame(`generic_kind_${kind}`, kind, 'seed("frame key")', gkey, gtopic, generic, 'one value under each kind: only byte 1 and the additional data differ', counting);
  frame('answer', 1, 'invite.key', derive(secret, null, 'sigelo-invite/0 key', 32), invite.answer_topic, answer, 'bob\'s invite answer on the answer topic');
  frame('reply', 2, 'invite.key', derive(secret, null, 'sigelo-invite/0 key', 32), invite.reply_topic, reply, 'alice\'s invite reply, her prekeys inside, on the reply topic');
  frame('prekeys', 5, 'prekeys_key', prekeysKey, mailbox, { prekeys: bundleOf(B0, 'bob prekeys', T0 + 40), want: false, known: A0.did }, 'bob\'s prekeys, his first frame after the reply, on his mailbox to alice; known: alice\'s current DID as he holds it');
  frame('notice', 4, 'notice_key', noticeKey, mailbox, notice, 'bob\'s contact notice after his rotation B0 -> B1: his chain, a proof signed by B1');

  // Refusals, in unseal's order: frame, aead, padding, plaintext, the same ten for each kind, so a
  // branch of one kind cannot pass what another refuses. Each frame is read as `read_as` under the
  // generic key on `topic`. Kind 1's come first and keep their names; the others' end in _kind_N.
  const refusalsOf = (kind) => {
    const g = frames.find((x) => x.case === `generic_kind_${kind}`), flipped = Uint8Array.from(Buffer.from(g.hex, 'hex')), other = kind === 1 ? 2 : 1;
    flipped[60] ^= 1;
    const raw = (text) => hex(frameOf(kind, gkey, gtopic, text, counting)), name = (c) => (kind === 1 ? c : `${c}_kind_${kind}`);
    return [
      { case: name('another_kind'), read_as: other, topic: gtopic, hex: g.hex, error: 'frame', note: `a kind ${kind} frame read as kind ${other}: the header differs` },
      { case: name('short'), read_as: kind, topic: gtopic, hex: g.hex.slice(0, 600), error: 'frame', note: 'shorter than a header, a nonce, one padded block and a tag' },
      { case: name('flipped_bit'), read_as: kind, topic: gtopic, hex: hex(flipped), error: 'aead' },
      { case: name('other_topic'), read_as: kind, topic: 'i/' + '1'.repeat(32), hex: g.hex, error: 'aead', note: 'the topic is in the additional data' },
      { case: name('no_marker'), read_as: kind, topic: gtopic, hex: raw(new Uint8Array(256).fill(0x41)), error: 'padding' },
      { case: name('not_json'), read_as: kind, topic: gtopic, hex: raw(pad(u8('{"a":1'))), error: 'plaintext' },
      { case: name('not_jcs_order'), read_as: kind, topic: gtopic, hex: raw(pad(u8('{"b":1,"a":2}'))), error: 'plaintext' },
      { case: name('float'), read_as: kind, topic: gtopic, hex: raw(pad(u8('{"a":1.5}'))), error: 'plaintext', note: 'JSON that JCS cannot write' },
      { case: name('lone_surrogate'), read_as: kind, topic: gtopic, hex: raw(pad(u8('{"x":"\\ud800"}'))), error: 'plaintext' },
      { case: name('integer_past_2_53'), read_as: kind, topic: gtopic, hex: raw(pad(u8('{"n":9007199254740993}'))), error: 'plaintext' },
    ];
  };
  const refusals = [1, 2, 4, 5].flatMap(refusalsOf);

  const out = {
    v: V,
    about: 'sigelo-carrier/0 frames (design/relay-plan.md §11 "Wire contracts as built"; carrier.mjs header). `frames`: seal `value` as `kind` under `key` on `topic` with `nonce`; '
      + 'the result has `length` bytes and SHA-256 `sha256`, and is `hex` when given (frames of at most 4,096 bytes). Opening it gives `value` back. '
      + '`refusals`: opening `hex` as kind `read_as` under the generic key on `topic` fails with `error`, the first failing check. '
      + '`derived`: what the seeds yield, each from the formula beside it.',
    layout: 'version 0x01 (1) | kind (1) | 16 zero bytes | counter 1, u32 big-endian (4) | XChaCha20-Poly1305 nonce (24) | ciphertext + tag of pad(JCS(value)); additional data = the 22-byte header ‖ UTF-8 topic; pad: 0x80 then 0x00 to the next multiple of 256',
    kinds: { 1: 'invite answer (sigelo-invite/0), on the answer topic, key invite.key', 2: 'invite reply, on the reply topic, key invite.key', 4: 'contact notice {bundle: the chain, proof: {body: {v, typ: "contact-notice", did: the current DID, pair}, sig}}, on the mailbox topic, key notice_key', 5: 'prekeys {prekeys: a signed sigelo-msg/0 bundle, want: boolean, known: the receiver\'s current DID as the sender holds it}, on the mailbox topic, key prekeys_key' },
    checks: ['frame', 'aead', 'padding', 'plaintext'],
    created: CREATED, t0: T0,
    seeds: Object.fromEntries(['A0', 'A-recovery', 'B0', 'B1', 'B-recovery', 'invite secret', 'frame key'].map((l) => [l, hex(seed(l))])),
    identities: Object.fromEntries(Object.entries({ A0, B0, B1 }).map(([k, x]) => [k, { did: x.did, key: x.key, genesis: x.genesis }])),
    rotation: rB1,
    derived: {
      invite,
      kem_pk: 'X-Wing keygen(rng("kem key") 32 bytes): the answer\'s kem_pk',
      kem_ct: 'X-Wing encapsulate(kem_pk, rng("kem ct") 64 bytes): the reply\'s kem_ct',
      shared: hex(enc.sharedSecret),
      K: { formula: 'HKDF-SHA256(secret ‖ shared, salt "sigelo-pair/0", info = the two original DIDs sorted and concatenated, 32)', hex: hex(K) },
      pair: { formula: 'hex(HKDF-SHA256(K, salt "sigelo-pair-id/0", empty info, 16))', hex: pair },
      answer_id: { formula: '"z" + base58btc(SHA-256("sigelo-invite/0 answer id\\n" ‖ JCS(answer)))', value: answerId },
      week, mailbox: { formula: '"m/" + hex(HKDF-SHA256(K, salt "sigelo-topic/0", info = B0 ‖ "\\n" ‖ A0 ‖ "\\n" ‖ week, 16))', topic: mailbox },
      prekeys_key: { formula: 'HKDF-SHA256(K, salt "sigelo-prekeys/0", info = sender original DID ‖ "\\n" ‖ recipient original DID, 32)', hex: hex(prekeysKey) },
      notice_key: { formula: 'HKDF-SHA256(K, salt "sigelo-notice/0", info = sender original DID ‖ "\\n" ‖ recipient original DID, 32)', hex: hex(noticeKey) },
      prekey_bundles: 'per one-time key: id = 16 bytes of the rng, then X-Wing keygen of the next 32; twenty, then the last-resort key alike; rng("alice prekeys") at t0 + 20, rng("bob prekeys") at t0 + 40; exp = iat + 31 days',
      nonces: 'frame nonce = rng("nonce " + case) 24 bytes; the generic frames and the refusals use the nonce 0x01 … 0x18',
    },
    frames,
    refusals,
  };
  return JSON.stringify(out, null, 2) + '\n';
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const text = build();
  if (process.argv.includes('--check')) {
    let cur = '';
    try { cur = readFileSync(OUT, 'utf8'); } catch {}
    if (cur !== text) { console.error('carrier-v0.json differs from the seeds: run node contact/gen-carrier.mjs'); process.exit(1); }
    console.log('carrier-v0.json reproduces byte for byte');
  } else { writeFileSync(OUT, text); console.log(`wrote ${OUT.split('/').slice(-2).join('/')} (${text.length} bytes)`); }
}
