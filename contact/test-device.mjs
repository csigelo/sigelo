// SPDX-License-Identifier: MIT
// Devices (device.mjs, contract sigelo-device/1) and the QR plumbing under them (qr.mjs, qr-decode.mjs):
// base45 against RFC 9285's examples, the words, argon2id native against @noble/hashes, the
// container byte for byte against fixtures/device-v1.json (gen-device.mjs), frames in any order,
// wrong words, a tampered header or ciphertext, the SAFE material rebuilt and checked as enrolment
// checks it, the online QR text; QR symbols v1–v20 through PNG and back through the decoder, with
// errors and rotation; zbarimg on the same PNGs when it is on PATH; and UNLOGGED (carrier.mjs).
// D3: the seat in the signed list (validity, epoch monotonic, stale seats), sealed snapshots (seal,
// open, tamper, wrong K, the size path).
//   node contact/test-device.mjs   → ALL PASS (n)
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, hkdfSync, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, did, sign, verifySig } from 'sigelo';
import { keeperRoot, mnemonicFromRoot, recoveryCommitment, rootFromMnemonic, vaultFromRoot } from 'sigelo/dist/keys.js';
import { UNLOGGED } from './carrier.mjs';
import * as C from './control.mjs';
import * as D from './device.mjs';
import { operatorAttestation, operatorIdentity, workerIdentity } from './enrol.mjs';
import { makeInvite } from './invite.mjs';
import * as RS from './restore.mjs';
import * as CR from './create.mjs';
import { alnumCapacity, encode, toPng, toTerminal } from './qr.mjs';
import { jsQR, readPng, scanPng } from './qr-decode.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};
const hex = (b) => Buffer.from(b).toString('hex');
const randomBytesHex = (n) => randomBytes(n).toString('hex');
const fx = JSON.parse(readFileSync(join(HERE, 'fixtures', 'device-v1.json'), 'utf8'));

// ================================================================ base45
for (const v of fx.base45_rfc9285) {
  ok(D.base45(Buffer.from(v.in)) === v.out && Buffer.from(D.unbase45(v.out)).toString() === v.in, `base45 RFC 9285: ${JSON.stringify(v.in)} ↔ ${JSON.stringify(v.out)}`);
}
{
  let all = true;
  for (let n = 0; n < 70; n++) { const b = createHash('sha512').update(`b45 ${n}`).digest().subarray(0, n % 64); if (hex(D.unbase45(D.base45(b))) !== hex(b)) all = false; }
  ok(all, 'base45: round trip at every length 0–63');
  ok(checkOf(() => D.unbase45('GGW')) === 'base45' && checkOf(() => D.unbase45('ab')) === 'base45' && checkOf(() => D.unbase45('ABCD')) === 'base45' && checkOf(() => D.unbase45(':;')) === 'base45',
    'base45: above 65535, outside the alphabet (lower case), 3k + 1 characters: refused');
}

// ================================================================ words, argon2id
{
  const w = D.makeWords();
  ok(w.split(' ').length === 6 && D.normaliseWords(w) === w, `six words by default (${w.split(' ').length})`);
  ok(D.makeWords(8).split(' ').length === 8 && checkOf(() => D.makeWords(4)) === 'device_words' && checkOf(() => D.makeWords(9)) === 'device_words', 'makeWords: 5 to 8');
  const fixed = D.makeWords(6, () => Buffer.alloc(9, 0));
  ok(fixed === 'abandon abandon abandon abandon abandon abandon', 'makeWords: 11 bits a word, most significant first (zero bytes → abandon ×6)');
  ok(D.normaliseWords('  INPUT  boat\tshiver\nspoil when CLIP ') === fx.words, 'the words read as typed: case, spaces, tabs, newlines');
  ok(checkOf(() => D.normaliseWords('input boat shiver spoil when')) === 'accepted' && checkOf(() => D.normaliseWords('input boat')) === 'device_words', 'five words read (the minimum); two refused');
  ok(/word 3/.test((() => { try { D.normaliseWords('input boat shivr spoil when clip'); } catch (e) { return e.message; } return ''; })()), 'a misspelt word: refused naming its position');
  const salt = Buffer.from(fx.salt, 'hex'), msg = Buffer.from(fx.words);
  const t0 = Date.now(), kn = D.argon2(msg, salt, fx.kdf, { native: D.nativeArgon2 }), tn = Date.now() - t0;
  const t1 = Date.now(), kb = D.argon2(msg, salt, fx.kdf, { native: false }), tb = Date.now() - t1;
  ok(hex(kn) === fx.key && hex(kb) === fx.key, `argon2id m = 64 MiB, t = 3, p = 1: ${D.nativeArgon2 ? 'node:crypto' : 'no native argon2 here'} (${tn} ms) and @noble/hashes (${tb} ms) give the fixture's key`);
  console.log(`  argon2id 64 MiB t=3: ${D.nativeArgon2 ? `native ${tn} ms, ` : ''}@noble/hashes ${tb} ms`);
}

// ================================================================ the container, the fixture
{
  const gen = spawnSync(process.execPath, [join(HERE, 'gen-device.mjs'), '--check'], { encoding: 'utf8' });
  ok(gen.status === 0, `gen-device.mjs --check: ${(gen.stderr || gen.stdout).trim()}`);
  const c = D.seal(fx.material, fx.words, { salt: Buffer.from(fx.salt, 'hex'), nonce: Buffer.from(fx.nonce, 'hex'), deflated: Buffer.from(fx.deflated, 'hex') });
  ok(hex(c) === fx.container, `seal: the fixture's container byte for byte (${c.length} bytes)`);
  ok(D.base45(c) === fx.base45 && D.frameId(c) === fx.id, 'base45 and the frame id: the fixture\'s');
  ok(JSON.stringify(D.toFrames(c, { maxVersion: 14 })) === JSON.stringify(fx.frames_v14), `frames in version-14 symbols: the fixture's (${fx.frames_v14.length})`);
  const m = D.open(c, fx.words);
  ok(canonicalize(m) === canonicalize(fx.material) && createHash('sha256').update(canonicalize(m)).digest('hex') === fx.jcs_sha256, 'open: the material, its JCS hash the fixture\'s');
  const fresh = D.seal(fx.material, fx.words);
  ok(hex(fresh.subarray(8, 48)) !== hex(c.subarray(8, 48)) && canonicalize(D.open(fresh, fx.words.toUpperCase())) === canonicalize(fx.material), 'a fresh seal: new salt and nonce, opens the same');
  ok(c[4] === 1 && c[5] === 16 && c[6] === 3 && c[7] === 1 && hex(c.subarray(0, 4)) === hex(Buffer.from('SGD1')), 'header: SGD1, argon2id, 2^16 KiB, t 3, p 1');
  // Wrong words; every header byte tampered; the ciphertext tampered.
  ok(checkOf(() => D.open(c, D.makeWords())) === 'device_words', 'other words: device_words');
  ok(checkOf(() => D.open(c, 'input boat shiver spoil when')) === 'device_words', 'five of the six words: device_words');
  const tamper = (at, v) => { const x = Uint8Array.from(c); x[at] = v ?? x[at] ^ 1; return x; };
  ok(checkOf(() => D.open(tamper(0), fx.words)) === 'device_container', 'magic tampered: device_container');
  ok(checkOf(() => D.open(tamper(4, 2), fx.words)) === 'device_container', 'kdf 2: device_container');
  ok(checkOf(() => D.open(tamper(5, 19), fx.words)) === 'device_container' && checkOf(() => D.open(tamper(5, 14), fx.words)) === 'device_container', 'memory 2^19 or 2^14 KiB: device_container, before any work');
  ok(checkOf(() => D.open(tamper(6, 11), fx.words)) === 'device_container' && checkOf(() => D.open(tamper(6, 0), fx.words)) === 'device_container', 'passes 0 or 11: device_container');
  ok(checkOf(() => D.open(tamper(6, 2), fx.words)) === 'device_words', 'passes 3 → 2 (a header the AEAD binds): device_words');
  ok(checkOf(() => D.open(tamper(10), fx.words)) === 'device_words' && checkOf(() => D.open(tamper(30), fx.words)) === 'device_words', 'salt or nonce tampered: device_words');
  ok(checkOf(() => D.open(tamper(60), fx.words)) === 'device_words' && checkOf(() => D.open(c.subarray(0, c.length - 1), fx.words)) === 'device_words', 'ciphertext tampered or cut: device_words');
  ok(checkOf(() => D.open(c.subarray(0, 50), fx.words)) === 'device_container', 'too short: device_container');

  // Rebuild: the device's identity file, checked as enrolment checks one.
  const r = D.rebuild(m, { now: fx.now + 60 });
  ok(r.did === fx.worker && r.original === fx.worker && r.operator === fx.operator && r.worker === 0 && r.name === 'phone', 'rebuild: worker 0, its DID and the operator\'s the fixture\'s');
  ok(r.identity.secret === fx.material.worker.secret && r.identity.attestations[0].body.exp - r.identity.attestations[0].body.iat === 14 * 86400, 'rebuild: the key, the 14-day attestation');
  const S = new Uint8Array(createHash('sha256').update('sigelo-device/1 root S').digest()), K = keeperRoot(S, 1), rec = recoveryCommitment(S);
  const direct = workerIdentity({ K, i: 0, n: 0, recovery: rec });
  ok(canonicalize(r.identity.genesis) === canonicalize(direct.genesis) && canonicalize(r.identity.issuers[0]) === canonicalize(operatorIdentity(S, 0).genesis), 'the genesis and the issuer are rebuilt byte for byte (pinned)');
  ok(checkOf(() => D.rebuild({ ...m, rank: 'admin' }, { now: fx.now })) === 'device_rank' && checkOf(() => D.rebuild({ ...m, rank: 'full' }, { now: fx.now })) === 'device_material', 'rank other than safe or full: device_rank; full without the operator\'s part: device_material');
  ok(checkOf(() => D.rebuild({ ...m, worker: { ...m.worker, sig: m.worker.sig.replace(/^./, (x) => (x === 'A' ? 'B' : 'A')) } }, { now: fx.now })) !== 'accepted', 'a tampered attestation signature: refused');
  ok(checkOf(() => D.rebuild({ ...m, worker: { ...m.worker, i: 1 } }, { now: fx.now })) === 'accepted', 'the index is the operator\'s word (it is in the sealed material)');
  ok(checkOf(() => D.rebuild({ ...m, worker: { ...m.worker, aexp: m.worker.aexp + 1 } }, { now: fx.now })) !== 'accepted', 'an attestation exp changed: refused (the signature)');
  ok(checkOf(() => D.rebuild(m, { now: fx.now + 15 * 86400 })) !== 'accepted', 'after the attestation and the invite expired: refused');
  const other = makeInvite({ did: fx.worker, relay: 'relay.sigelo.ai', now: fx.now, ttl: 86400 }).text;
  ok(checkOf(() => D.rebuild({ ...m, invite: other }, { now: fx.now })) === 'enrol_invite', 'an invite naming another DID: enrol_invite');
  ok(checkOf(() => D.rebuild({ ...m, name: 'Phone!' }, { now: fx.now })) === 'device_name', 'a name outside [a-z0-9_-]{1,20}: device_name');

  // compactSafe from the worker's identity file is the material.
  const op = operatorIdentity(S, 0), a = operatorAttestation({ secret: Buffer.from(op.secret, 'hex'), iss: did(op.genesis), sub: fx.worker, relay: 'relay.sigelo.ai', now: fx.now, days: 14 });
  const id = workerIdentity({ K, i: 0, n: 0, recovery: rec, attestation: a, issuer: op.genesis });
  ok(canonicalize(D.compactSafe({ name: 'phone', identity: id, i: 0, n: 0, invite: m.invite, exp: m.exp })) === canonicalize(fx.material), 'compactSafe of the identity file: the fixture\'s material');
  const id1 = workerIdentity({ K, i: 0, n: 1, recovery: rec, attestation: a, issuer: op.genesis });
  const m1 = D.compactSafe({ name: 'phone', identity: id1, i: 0, n: 1, invite: m.invite, exp: m.exp }), r1 = D.rebuild(m1, { now: fx.now });
  ok(r1.original === fx.worker && r1.did !== fx.worker && r1.identity.rotations.length === 1, 'rotation 1: its chain travels, the original DID stays');
}

// ================================================================ FULL: the material offline, the list, the material online
{
  const F = fx.full, S = new Uint8Array(createHash('sha256').update('sigelo-device/1 root S').digest()), K = keeperRoot(S, 1), rec = recoveryCommitment(S);
  const op = operatorIdentity(S, 0), opDid = did(op.genesis), sk = Buffer.from(op.secret, 'hex'), signOp = (b) => sign(sk, b);
  const c = D.seal(F.material, fx.words, { salt: Buffer.from(F.salt, 'hex'), nonce: Buffer.from(F.nonce, 'hex'), deflated: Buffer.from(F.deflated, 'hex') });
  ok(hex(c) === F.container && D.frameId(c) === F.id && JSON.stringify(D.toFrames(c, { maxVersion: 14 })) === JSON.stringify(F.frames_v14), `FULL seal: the fixture's container byte for byte (${c.length} bytes, ${F.frames_v14.length} frames of version 14)`);
  console.log(`  FULL offline ${c.length} B → ${D.base45(c).length} chars: ${D.toFrames(c).length} frame v20, ${F.frames_v14.length} frames v14, ${D.toFrames(c, { maxVersion: 10 }).length} frames v10`);
  const m = D.open(c, fx.words);
  ok(canonicalize(m) === canonicalize(F.material) && createHash('sha256').update(canonicalize(m)).digest('hex') === F.jcs_sha256, 'FULL open: the material, its JCS hash the fixture\'s');
  ok(checkOf(() => D.open(c, D.makeWords())) === 'device_words' && checkOf(() => D.open(c, 'input boat shiver spoil when')) === 'device_words', 'FULL, wrong words or five of the six: device_words');
  ok(!D.base45(c).includes(F.material.keeper.root.toUpperCase()) && !hex(c).includes(F.material.keeper.root) && !hex(c).includes(F.material.op.secret), 'FULL sealed: neither K_1 nor the operator key in the container or its text');
  const r = D.rebuild(m, { now: fx.now + 60 });
  ok(r.rank === 'full' && r.did === fx.worker && r.operator === opDid, 'FULL rebuild: the device is worker 0, its operator the fixture\'s');
  ok(canonicalize(r.full.operator) === canonicalize(op), 'FULL rebuild: the operator identity file, byte for byte what keeper --from-words writes (rotation 0, derived)');
  ok(r.full.keeper.root_hex === hex(K) && r.full.keeper.recovery === rec && r.full.keeper.keeper === 1 && r.full.keeper.me.did === opDid && r.full.keeper.workers[0].original === fx.worker && r.full.keeper.workers[0].placed === 'device', 'FULL rebuild: the keeper file, K_1, the roster re-derived');
  ok(r.full.devices.seq === 1 && D.entryOf(r.full.devices, fx.worker).rank === 'full', 'FULL rebuild: the signed list, naming this device full');
  // compactFull from the two files and the list: the fixture's material.
  const a = operatorAttestation({ secret: sk, iss: opDid, sub: fx.worker, relay: 'relay.sigelo.ai', now: fx.now, days: 14 });
  const wid = workerIdentity({ K, i: 0, n: 0, recovery: rec, attestation: a, issuer: op.genesis });
  const keeperFile = { v: D.KEEPER_V, keeper: 1, root_hex: hex(K), recovery: rec, workers: { 0: { name: 'phone', n: 0, did: fx.worker, original: fx.worker, placed: 'device', at: fx.now } } };
  ok(canonicalize(D.compactFull({ name: 'phone', identity: wid, i: 0, n: 0, invite: m.invite, exp: m.exp, operator: op, keeper: keeperFile, devices: F.material.devices })) === canonicalize(F.material), 'compactFull of the identity, operator and keeper files: the fixture\'s material');
  ok(checkOf(() => D.compactFull({ name: 'phone', identity: wid, i: 0, n: 0, invite: m.invite, exp: m.exp, operator: operatorIdentity(S, 1), keeper: keeperFile, devices: F.material.devices })) === 'device_material', 'compactFull: an operator file that is not the attestation\'s issuer: refused');
  // Tampered material, each part: refused.
  const S2 = new Uint8Array(32).fill(7), op2 = operatorIdentity(S2, 0);
  const bad = (x, what) => ok(checkOf(() => D.rebuild({ ...m, ...x }, { now: fx.now + 60 })) === 'device_material', `FULL rebuild refused: ${what}`);
  bad({ op: { n: 0, secret: op2.secret } }, 'another operator key');
  bad({ keeper: { j: 1, root: hex(keeperRoot(S, 2)) } }, 'K_2 for K_1 (it does not derive this device)');
  bad({ keeper: { j: 0, root: hex(K) } }, 'keeper index 0');
  bad({ roster: [[0, 0]] }, 'a roster entry without its name');
  bad({ op: { n: 1, secret: op.secret } }, 'rotation 1 without its chain');
  ok(checkOf(() => D.rebuild({ ...m, devices: { ...m.devices, seq: 2 } }, { now: fx.now + 60 })) === 'device_list_sig', 'FULL rebuild: a list changed after signing: device_list_sig');
  const safeList = D.signList({ operator: opDid, seq: 2, iat: fx.now, devices: [{ ...m.devices.devices[0], rank: 'safe' }] }, signOp);
  bad({ devices: safeList }, 'a list naming this device safe');
  ok(checkOf(() => D.rebuild({ ...m, devices: D.signList({ operator: opDid, seq: 1, iat: fx.now, devices: m.devices.devices }, (b) => sign(Buffer.from(op2.secret, 'hex'), b)) }, { now: fx.now + 60 })) === 'device_list_sig', 'FULL rebuild: a list signed by another key: device_list_sig');

  // The words gate's clock: the material goes within 10 minutes of the "y".
  ok(D.gateOpen(1000, 1000) && D.gateOpen(1000, 1600) && !D.gateOpen(1000, 1601) && !D.gateOpen(1000, 999) && !D.gateOpen(undefined, 1000), 'gateOpen: from the y to 10 minutes after it; never before it, never without one');

  // The list: signed, checked, replaced only by a higher seq.
  const e0 = { name: 'phone', worker: 0, did: fx.worker, rank: 'full', added: fx.now, by: opDid }, e1 = { name: 'tab', worker: 1, did: did(workerIdentity({ K, i: 1, n: 0, recovery: rec }).genesis), rank: 'safe', added: fx.now, by: opDid };
  const l1 = D.signList({ operator: opDid, seq: 1, iat: fx.now, devices: [e0] }, signOp), l2 = D.signList({ operator: opDid, seq: 2, iat: fx.now + 1, devices: [e0, e1] }, signOp);
  ok(canonicalize(l1) === canonicalize(F.material.devices), 'signList: the fixture\'s list (the body typ device-list, the operator\'s signature)');
  ok(checkOf(() => D.checkList(l2, { keys: [op.genesis.key], operator: opDid })) === 'accepted' && D.acceptList(l1, l2, { keys: [op.genesis.key] }) === l2 && D.acceptList(null, l1, { keys: [op.genesis.key] }) === l1, 'checkList, acceptList: a higher seq replaces');
  ok(checkOf(() => D.acceptList(l2, l2, { keys: [op.genesis.key] })) === 'device_list_stale' && checkOf(() => D.acceptList(l2, l1, { keys: [op.genesis.key] })) === 'device_list_stale', 'acceptList: the same list again (a replay), or an older one: device_list_stale');
  ok(checkOf(() => D.checkList({ ...l2, devices: [e0] }, { keys: [op.genesis.key] })) === 'device_list_sig' && checkOf(() => D.checkList({ ...l2, seq: 3 }, { keys: [op.genesis.key] })) === 'device_list_sig', 'checkList: a device dropped, or the seq raised, after signing: device_list_sig');
  ok(checkOf(() => D.checkList(l2, { keys: [op2.genesis.key] })) === 'device_list_sig', 'checkList: another key: device_list_sig');
  const l2b = D.signList({ operator: did(op2.genesis), seq: 9, iat: fx.now, devices: [e0] }, (b) => sign(Buffer.from(op2.secret, 'hex'), b));
  ok(checkOf(() => D.acceptList(l1, l2b, { keys: [op2.genesis.key] })) === 'device_list_operator', 'acceptList: another operator\'s list, even well signed: device_list_operator');
  ok(checkOf(() => D.signList({ operator: opDid, seq: 3, iat: fx.now, devices: [e0, { ...e1, name: 'phone' }] }, signOp)) === 'device_list' && checkOf(() => D.signList({ operator: opDid, seq: 3, iat: fx.now, devices: [{ ...e0, seen: 1 }] }, signOp)) === 'device_list'
    && checkOf(() => D.signList({ operator: opDid, seq: 0, iat: fx.now, devices: [] }, signOp)) === 'device_list' && checkOf(() => D.checkList({ ...l1, extra: 1 }, { keys: [op.genesis.key] })) === 'device_list', 'the list\'s shape: two devices of one name, an unknown field, seq 0: device_list');
  const rv = D.revokeIn(l2.devices, 'tab', fx.now + 5);
  ok(rv[1].revoked === fx.now + 5 && rv[0].revoked === undefined && D.entryOf({ devices: rv }, e1.did) === null && D.entryOf({ devices: rv }, fx.worker) === e0, 'revokeIn: tab marked revoked, phone not; entryOf names live devices only');
  ok(checkOf(() => D.revokeIn(rv, 'tab', fx.now)) === 'device_revoked' && checkOf(() => D.revokeIn(rv, 'nope', fx.now)) === 'device_unknown', 'revokeIn: twice: device_revoked; an unknown name: device_unknown');

  // ---- D3: the seat in the signed list (devices.md §4.1, §4.3)
  const eL = { name: 'lap', worker: 2, did: did(workerIdentity({ K, i: 2, n: 0, recovery: rec }).genesis), rank: 'full', added: fx.now, by: opDid };
  const devs = [e0, e1, eL], keys = [op.genesis.key];
  const seat1 = D.nextSeat(undefined, e0.did, fx.now + 10);
  const s1 = D.signList({ operator: opDid, seq: 3, iat: fx.now + 10, devices: devs, seat: seat1 }, signOp);
  ok(seat1.epoch === 1 && seat1.holder === e0.did && D.nextSeat(seat1, eL.did, fx.now + 20).epoch === 2 && D.holdsSeat(s1, e0.did) && !D.holdsSeat(s1, eL.did) && !D.holdsSeat(l2, e0.did),
    'nextSeat: the first seat epoch 1, each move + 1; holdsSeat: only the holder (a list without a seat: nobody)');
  ok(checkOf(() => D.checkList(s1, { keys, operator: opDid })) === 'accepted' && D.listBody(s1).seat.epoch === 1 && D.listBody(l2).seat === undefined,
    'a list with a seat: signed over {…, seat}; a D2 list without one: the body as before (the fixture above still verifies)');
  ok(checkOf(() => D.checkList({ ...s1, seat: { ...seat1, epoch: 2 } }, { keys })) === 'device_list_sig' && checkOf(() => D.checkList({ ...s1, seat: { ...seat1, holder: eL.did } }, { keys })) === 'device_list_sig',
    'the seat changed after signing (epoch raised, another holder): device_list_sig');
  const badSeat = (seat) => checkOf(() => D.signList({ operator: opDid, seq: 3, iat: fx.now, devices: devs, seat }, signOp));
  ok(badSeat({ ...seat1, holder: e1.did }) === 'device_seat' && badSeat({ ...seat1, holder: 'did:sigelo:znobody' }) === 'device_seat' && badSeat({ ...seat1, epoch: 0 }) === 'device_seat'
    && badSeat({ ...seat1, extra: 1 }) === 'device_seat' && badSeat({ holder: e0.did, epoch: 1 }) === 'device_seat',
    'a seat record refused (device_seat): a SAFE holder, a holder not in the list, epoch 0, an unknown field, no iat');
  ok(checkOf(() => D.signList({ operator: opDid, seq: 3, iat: fx.now, devices: D.revokeIn(devs, 'phone', fx.now), seat: seat1 }, signOp)) === 'device_seat', 'the holder revoked: device_seat (give the seat first)');
  const s2 = D.signList({ operator: opDid, seq: 4, iat: fx.now + 20, devices: devs, seat: D.nextSeat(seat1, eL.did, fx.now + 20) }, signOp);
  const s2more = D.signList({ operator: opDid, seq: 5, iat: fx.now + 21, devices: devs, seat: s2.seat }, signOp);
  ok(D.acceptList(s1, s2, { keys }) === s2 && D.acceptList(s2, s2more, { keys }) === s2more && D.acceptList(l2, s1, { keys }) === s1, 'acceptList: a higher epoch moves the seat; the same seat with a higher seq; a first seat over a D2 list');
  ok(checkOf(() => D.acceptList(s2, s1, { keys })) === 'device_seat_stale' && checkOf(() => D.acceptList(s2more, s1, { keys })) === 'device_seat_stale', 'epoch monotonic: an older seat record, whatever its seq: device_seat_stale');
  const forced = D.signList({ operator: opDid, seq: 4, iat: fx.now + 30, devices: devs, seat: D.nextSeat(s2.seat, e0.did, fx.now + 30) }, signOp);
  ok(D.acceptList(s2more, forced, { keys }) === forced, 'a forced take (epoch + 1) stands over a list of higher seq at the epoch before');
  const noSeat = D.signList({ operator: opDid, seq: 9, iat: fx.now + 40, devices: devs }, signOp), twin = D.signList({ operator: opDid, seq: 6, iat: fx.now + 40, devices: devs, seat: { ...s2.seat, holder: e0.did } }, signOp);
  ok(checkOf(() => D.acceptList(s1, noSeat, { keys })) === 'device_seat_stale' && checkOf(() => D.acceptList(s2, twin, { keys })) === 'device_seat_stale' && checkOf(() => D.acceptList(s2, s2, { keys })) === 'device_list_stale',
    'a seat dropped, or two holders at one epoch: device_seat_stale; the same list again: device_list_stale');
  ok(checkOf(() => D.readMessage({ v: D.DEVICE_V, typ: 'seat-ask', epoch_seen: 2 })) === 'accepted' && checkOf(() => D.readMessage({ v: D.DEVICE_V, typ: 'seat-ask' })) === 'device_message'
    && checkOf(() => D.readMessage({ v: D.DEVICE_V, typ: 'seat', devices: s2 })) === 'accepted' && checkOf(() => D.readMessage({ v: D.DEVICE_V, typ: 'seat' })) === 'device_message'
    && checkOf(() => D.readMessage({ v: D.DEVICE_V, typ: 'snapshot', epoch: 1, seq: 1, sha256: '0'.repeat(64), size: 1, data: 'AA==', file: 'x' })) === 'device_message'
    && checkOf(() => D.readMessage({ v: D.DEVICE_V, typ: 'renew' })) === 'device_message' && checkOf(() => D.readMessage({ v: D.DEVICE_V, typ: 'takeover' })) === 'device_message',
    'readMessage: seat-ask {epoch_seen}, seat {devices}, snapshot inline or a file (not both), renew {attestation}; an unknown typ refused');

  // ---- D3: sealed snapshots (§4.4)
  const files = { carrier: JSON.stringify({ peers: { x: { session: 'secret ratchet 4f2a' } } }), contacts: '{"contacts":{}}', devices: JSON.stringify(s2), ui: '{"tags":{}}', history: 'a history line\n', log: 'a log line\n' };
  const body = D.snapshotBody({ operator: opDid, epoch: 2, seq: 4, iat: fx.now, files }), bodyH = D.snapshotBody({ operator: opDid, epoch: 2, seq: 4, iat: fx.now, files, history: true });
  ok(body.files.history === undefined && body.files.log === undefined && bodyH.files.history === files.history && bodyH.files.log === files.log, 'snapshotBody: history and inbox.log only with --with-history');
  ok(checkOf(() => D.snapshotBody({ operator: opDid, epoch: 2, seq: 4, iat: fx.now, files: { ...files, keeper: 'K' } })) === 'device_snapshot' && checkOf(() => D.snapshotBody({ operator: opDid, epoch: 2, seq: 4, iat: fx.now, files: { contacts: '{}', devices: '{}' } })) === 'device_snapshot'
    && checkOf(() => D.snapshotBody({ operator: opDid, epoch: 0, seq: 4, iat: fx.now, files })) === 'device_snapshot', 'snapshotBody refused: a file it does not carry (the keeper), no carrier state, epoch 0');
  const nonce = new Uint8Array(24).fill(7), sealedS = D.sealSnapshot(body, K, { nonce });
  ok(Buffer.from(sealedS.subarray(0, 4)).toString() === 'SGS1' && hex(sealedS.subarray(4, 28)) === hex(nonce) && !Buffer.from(sealedS).includes(Buffer.from('ratchet')), 'sealSnapshot: SGS1 ‖ nonce ‖ ciphertext; no plaintext in it');
  ok(canonicalize(D.openSnapshot(sealedS, K, { operator: opDid })) === canonicalize(body), 'openSnapshot: the body back, under K_j');
  ok(hex(D.snapshotKey(K)) === hex(new Uint8Array(hkdfSync('sha256', K, 'sigelo-device/1', 'snapshot', 32))), 'the key: HKDF-SHA256(K_j, salt "sigelo-device/1", info "snapshot"), as node:crypto computes it');
  ok(checkOf(() => D.openSnapshot(sealedS, keeperRoot(S, 2))) === 'device_snapshot_key' && checkOf(() => D.openSnapshot(sealedS, new Uint8Array(32))) === 'device_snapshot_key', 'another keeper root (K_2, zeros): device_snapshot_key');
  const flip = (i) => { const t = Uint8Array.from(sealedS); t[i] ^= 1; return t; };
  ok(checkOf(() => D.openSnapshot(flip(40))) !== 'accepted' && checkOf(() => D.openSnapshot(flip(40), K)) === 'device_snapshot_key' && checkOf(() => D.openSnapshot(flip(10), K)) === 'device_snapshot_key'
    && checkOf(() => D.openSnapshot(flip(sealedS.length - 1), K)) === 'device_snapshot_key', 'tampered (the ciphertext, the nonce in the header, the tag): device_snapshot_key');
  ok(checkOf(() => D.openSnapshot(flip(0), K)) === 'device_snapshot' && checkOf(() => D.openSnapshot(sealedS.subarray(0, 30), K)) === 'device_snapshot' && checkOf(() => D.openSnapshot(sealedS, K, { operator: did(op2.genesis) })) === 'device_snapshot',
    'not a snapshot (magic, too short), or another operator\'s: device_snapshot');
  ok(hex(D.sealSnapshot(body, K)) !== hex(D.sealSnapshot(body, K)), 'a fresh nonce each time');
  ok(D.snapshotRoute(D.INLINE_MAX) === 'inline' && D.snapshotRoute(D.INLINE_MAX + 1) === 'file' && D.snapshotRoute(sealedS.length) === 'inline' && D.snapshotRoute(100, 50) === 'file', `the size path: up to ${D.INLINE_MAX} sealed bytes inline (this one ${sealedS.length}), larger as sigelo-file/0`);
  const big = D.sealSnapshot(D.snapshotBody({ operator: opDid, epoch: 2, seq: 4, iat: fx.now, files: { ...files, carrier: createHash('sha512').update('x').digest('hex').repeat(1200) + randomBytesHex(60000) } }), K);
  ok(D.snapshotRoute(big.length) === 'file' && D.openSnapshot(big, K).files.carrier.length > 150000, `a large carrier state (${big.length} B sealed): the file path, and it opens`);
  ok(D.newerSnapshot({ epoch: 2, seq: 1, iat: 1 }, { epoch: 1, seq: 9, iat: 9 }) && D.newerSnapshot({ epoch: 2, seq: 5, iat: 1 }, { epoch: 2, seq: 4, iat: 9 }) && !D.newerSnapshot({ epoch: 2, seq: 4, iat: 1 }, { epoch: 2, seq: 4, iat: 2 })
    && D.newerSnapshot({ epoch: 1, seq: 1, iat: 1 }, undefined), 'newerSnapshot: epoch, then seq, then iat; anything beats none');

  // Lost: the steps without the words, and those with them (§9.2).
  const ls = D.lostSteps({ d: e1, n: 0, j: 1, opN: 0, until: '2026-11-04' }), lf = D.lostSteps({ d: e0, n: 0, j: 1, opN: 0, until: '2026-11-04' });
  ok(ls.now.length === 1 && ls.words.length === 1 && ls.words[0].includes('--agent 1 --keeper 1 --n 1') && ls.now[0].includes('2026-11-04'), 'lostSteps SAFE: revoked now; optional with the words: recover worker 1 at rotation 1');
  ok(lf.now.length === 1 && lf.words.length === 5 && lf.words[0].includes('--identity-n 1') && lf.words[0].includes('adopt --rotation') && lf.words[1].includes('--keeper 2') && lf.words[2].includes('--keeper 2 --n 0') && lf.words[3].includes('--full'), 'lostSteps FULL: contained now; with the words: recover the operator (n + 1), K_2, the workers onto it, FULL again, keeper 1 deleted');

  // The material online: within 10 minutes, from the operator, for this device.
  const kf = { ...keeperFile, me: { n: 0, did: opDid, original: opDid } };
  const mm = D.materialMessage({ operator: op, keeper: kf, devices: l1, now: fx.now });
  const from = { did: opDid, current_did: opDid };
  ok(mm.typ === 'material' && mm.exp - mm.iat === 600 && D.readMessage(mm) === mm, 'materialMessage: typ material, exp 10 minutes after iat');
  const got = D.checkMaterial(mm, { from, self: fx.worker, now: fx.now + 30 });
  ok(canonicalize(got.operator) === canonicalize(op) && got.keeper.root_hex === hex(K) && got.devices === l1, 'checkMaterial: the operator file, the keeper file and the list, as sent');
  const cm = (x, o = {}) => checkOf(() => D.checkMaterial({ ...mm, ...x }, { from, self: fx.worker, now: fx.now + 30, ...o }));
  ok(cm({}, { now: fx.now + 600 + 301 }) === 'device_expired' && cm({}, { now: fx.now + 600 + 299 }) === 'accepted', 'checkMaterial: past exp (and the clock skew): device_expired');
  ok(cm({ exp: fx.now + 601 }) === 'device_material' && cm({ iat: fx.now + 400, exp: fx.now + 1000 }, { now: fx.now }) === 'device_material', 'checkMaterial: exp more than 10 minutes after iat, or an iat in the future: device_material');
  ok(cm({}, { from: { did: did(op2.genesis), current_did: did(op2.genesis) } }) === 'device_material', 'checkMaterial: from a contact that is not the operator it names: device_material');
  ok(cm({ operator: { ...op, secret: op2.secret } }) === 'device_material', 'checkMaterial: an operator secret not its key: device_material');
  ok(cm({ keeper: { ...kf, root_hex: hex(keeperRoot(S, 2)) } }) === 'device_material' && cm({ keeper: { ...kf, recovery: 'sha256:' + '0'.repeat(64) } }) === 'device_material', 'checkMaterial: K of another index, or of another seed: device_material');
  ok(cm({}, { self: e1.did }) === 'device_material', 'checkMaterial: a list that does not name this device full: device_material');
  ok(cm({ devices: { ...l1, seq: 5 } }) === 'device_list_sig', 'checkMaterial: a list tampered: device_list_sig');
  ok(checkOf(() => D.materialMessage({ operator: { ...op, secret: { provider: 'keychain' } }, keeper: kf, devices: l1, now: fx.now })) === 'device_material', 'materialMessage: an operator file whose key is sealed: refused (the caller unseals it)');
  ok(checkOf(() => D.readMessage({ v: 'sigelo-device/1', typ: 'seat' })) === 'device_message' && checkOf(() => D.readMessage({ v: 'sigelo-device/1', typ: 'list' })) === 'device_message' && checkOf(() => D.readMessage({ v: 'sigelo-device/1', typ: 'wiped', name: 'tab', worker: 1 })) === 'accepted',
    'readMessage: typ seat (not in this version), a list without its devices: device_message; wiped: read');
}

// ================================================================ frames
{
  const pad = Array.from({ length: 24 }, (_, i) => createHash('sha512').update(`pad ${i}`).digest('hex')).join('');
  const c = D.seal({ v: 'sigelo-device/1', typ: 'offline', pad }, fx.words);
  const fr = D.toFrames(c, { maxVersion: 10 });
  ok(fr.length >= 3 && fr.every((f) => f.length <= alnumCapacity(10, 'M')) && fr.every((f, i) => f.startsWith(`SGD1${String(i + 1).padStart(2, '0')}${String(fr.length).padStart(2, '0')}`)), `toFrames: ${fr.length} frames, each fits version 10 at M`);
  const perms = (a) => (a.length <= 1 ? [a] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map((p) => [x, ...p])));
  const orders = perms(fr.slice(0, 4).map((_, i) => i)).slice(0, 24);
  ok(orders.every((o) => { const all = [...o.map((i) => fr[i]), ...fr.slice(4)]; const j = D.joinFrames(all); return j.done && hex(j.container) === hex(c); }), `joinFrames: the container, in each of ${orders.length} orders`);
  const part = D.joinFrames([fr[2], fr[0]]);
  ok(!part.done && part.have === 2 && part.count === fr.length && part.missing.join() === [2, ...Array.from({ length: fr.length - 3 }, (_, i) => i + 4)].join(), `two of ${fr.length}: not done, the missing named (${part.missing})`);
  ok(D.joinFrames([...fr, fr[0], fr[1]]).done, 'a frame scanned twice: fine');
  const alien = D.toFrames(D.seal({ v: 'sigelo-device/1', typ: 'offline' }, fx.words))[0];
  ok(checkOf(() => D.joinFrames([fr[0], alien])) === 'device_frame', 'another code\'s frame among them: device_frame');
  const bent = fr[1].slice(0, 20) + (fr[1][20] === 'A' ? 'B' : 'A') + fr[1].slice(21);
  ok(checkOf(() => D.joinFrames([fr[0], bent, ...fr.slice(2)])) !== 'accepted', 'one character of a frame changed: refused (the id, or base45)');
  ok(checkOf(() => D.readFrame('SGD10302ABCD')) === 'device_frame' && checkOf(() => D.readFrame('XYZ')) === 'device_frame' && checkOf(() => D.readFrame('SGD10102ABcd00')) === 'device_frame', 'readFrame: index past count, not a frame, lower case: device_frame');
  ok(checkOf(() => D.toFrames(new Uint8Array(200000))) === 'device_frames', 'more than 99 frames: device_frames');
}

// ================================================================ online QR text, scans
{
  ok(D.onlineText('k7f3q9zp') === fx.online.text && D.onlineText('K7F3-Q9ZP', 'relay.example.org') === fx.online.with_host, 'onlineText: SIGELO:DEV:<code>[:<HOST>]');
  ok(D.onlineText('K7F3-Q9ZP', 'relay.example.org:8883').length <= 60, 'with a host and port: at most 60 characters');
  const a = D.readScan(fx.online.with_host), b = D.readScan(' sigelo:dev:k7f3-q9zp '), c = D.readScan('K7F3 Q9ZP'), f = D.readScan(fx.frames_v14[1]);
  ok(a.kind === 'online' && a.code === 'K7F3Q9ZP' && a.relay === 'relay.example.org' && b.relay === null && c.kind === 'code' && f.kind === 'frame' && f.frame.index === 2, 'readScan: online, with a host, a typed code, a frame');
  ok(checkOf(() => D.readScan('hello world, not a code at all')) === 'scan_text' && checkOf(() => D.readScan('SIGELO:DEV:K7F3-U9ZP')) === 'short_code', 'readScan: anything else refused');
  const v = encode(fx.online.text), vh = encode(D.onlineText('K7F3-Q9ZP', 'relay.sigelo.ai'));
  ok(v.mode === 'alnum' && v.version === 1 && vh.version <= 3, `the online QR: alphanumeric, version ${v.version} (${fx.online.text.length} characters); with a host version ${vh.version}`);
  console.log(`  online QR: ${fx.online.text.length} chars v${v.version}; with relay.sigelo.ai v${vh.version}; SAFE offline ${fx.container.length / 2} B → ${fx.base45.length} chars`);
}

// ================================================================ QR: encode, PNG, decode
{
  const ALN = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  const dir = mkdtempSync(join(tmpdir(), 'sigelo-device-qr-'));
  const zbar = process.env.PATH?.split(delimiter).map((d) => join(d, 'zbarimg')).find((p) => existsSync(p));
  let all = true, zbarAll = true;
  const bad = [];
  for (let ver = 1; ver <= 20; ver++) {
    const n = alnumCapacity(ver, 'M');
    let t = ver === 1 ? 'SIGELO:DEV:K7F3-Q9ZP' : '';
    while (t.length < n) t += ALN[(t.length * 7 + ver) % 45];
    const m = encode(t, { minVersion: ver, maxVersion: ver });
    if (m.version !== ver || m.size !== 17 + 4 * ver) all = false;
    const png = toPng(m, { scale: ver < 10 ? 6 : 4 });
    const r = jsQR(readPng(png).data, readPng(png).width, readPng(png).height);
    if (r?.data !== t || r.version !== ver) { all = false; bad.push(ver); }
    if (zbar) {
      const f = join(dir, `v${ver}.png`);
      writeFileSync(f, png);
      try { if (execFileSync(zbar, ['--raw', '-q', f], { encoding: 'utf8', timeout: 10000 }).replace(/\n$/, '') !== t) zbarAll = false; } catch { zbarAll = false; }
    }
  }
  ok(all, `QR versions 1–20, full at level M: encode → PNG → readPng → jsQR gives the text back${bad.length ? ` (failed: ${bad})` : ''}`);
  if (zbar) ok(zbarAll, `zbarimg (${zbar}) reads the same 20 PNGs`);
  else console.log('  SKIP zbarimg cross-check: zbarimg is not on PATH (install zbar)');
  // The fixture's frames and a byte-mode text, with module errors, rotated, on a grey noisy ground.
  const frame = encode(fx.frames_v14[0], { maxVersion: 14 });
  ok(frame.version <= 14 && frame.mode === 'alnum', `a frame of the version-14 split: version ${frame.version}, alphanumeric (${fx.frames_v14[0].length} characters)`);
  for (let y = 10; y < frame.size - 10; y += 11) for (let x = 10; x < frame.size - 10; x += 13) frame.modules[y][x] = !frame.modules[y][x];
  const img = readPng(toPng(frame, { scale: 5 })), W = img.width, H = img.height, rot = new Uint8ClampedArray(W * H * 4);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) for (let k = 0; k < 4; k++) rot[(x * H + (H - 1 - y)) * 4 + k] = img.data[(y * W + x) * 4 + k];
  for (let i = 0; i < rot.length; i += 4) { const n = ((i * 2654435761) >>> 24) / 4 - 32; for (let k = 0; k < 3; k++) rot[i + k] = rot[i + k] * 0.7 + 40 + n; }
  ok(jsQR(rot, H, W)?.data === fx.frames_v14[0], 'a frame with 25 modules flipped, turned 90°, low contrast and noise: read');
  const utf = 'émoji 🔑 and text';
  ok(scanPng(toPng(encode(utf))) === utf && encode(utf).mode === 'byte', 'byte mode: UTF-8 text round trip');
  ok(scanPng(toPng(encode('12345678901234567890'))) === '12345678901234567890' && encode('123').mode === 'numeric', 'numeric mode round trip');
  const inv = readPng(toPng(encode('INVERTED 123'), { scale: 4 }));
  for (let i = 0; i < inv.data.length; i += 4) for (let k = 0; k < 3; k++) inv.data[i + k] = 255 - inv.data[i + k];
  ok(jsQR(inv.data, inv.width, inv.height)?.data === 'INVERTED 123', 'light modules on dark (an inverted screen): read');
  ok(checkOf(() => scanPng(toPng(encode('x'), { scale: 1, quiet: 0 }).subarray(0, 40))) === 'scan_format', 'a cut PNG: scan_format');
  ok(checkOf(() => readPng(Buffer.from('GIF89a........'))) === 'scan_format', 'not a PNG: scan_format');
  const blank = Buffer.from(toPng(encode('x')));
  ok(checkOf(() => { const p = readPng(blank); p.data.fill(255); if (!jsQR(p.data, p.width, p.height)) throw Object.assign(new Error('none'), { check: 'scan_none' }); }) === 'scan_none', 'a white image: no code');
  const t = toTerminal(encode(fx.online.text), { quiet: 2 });
  ok(t.length === Math.ceil((21 + 4) / 2) && t.every((l) => [...l].length === 25) && t[0] === '█'.repeat(25), 'toTerminal: half blocks, 21 + 2·2 columns, ⌈25/2⌉ lines, the quiet zone light');
  ok(toTerminal(encode(fx.online.text), { invert: true })[0] === ' '.repeat(25), 'toTerminal invert: the quiet zone blank');
  ok(checkOf(() => encode('x'.repeat(3000), { maxVersion: 20 })) === 'qr_too_long', 'too long for version 20: qr_too_long');
  rmSync(dir, { recursive: true, force: true });
}

// ================================================================ UNLOGGED
ok(UNLOGGED.test('sigelo-device/1') && UNLOGGED.test('sigelo-identity/0') && UNLOGGED.test('sigelo-enrol/1') && !UNLOGGED.test('sigelo-file/0') && !UNLOGGED.test('') && !UNLOGGED.test('x-sigelo-device/1'),
  'UNLOGGED: sigelo-device/, sigelo-identity/, sigelo-enrol/ (never in inbox.log); sigelo-file/0 and plain messages logged');

// ---- remote control over the relay (control.mjs, design/apps.md §6.3): the text, the messages, the identity, the cap
{
  const t = C.controlText('k7f3q9zp'), h = C.controlText('K7F3-Q9ZP-4WXN', 'relay.test:1883');
  ok(t === 'SIGELO:CTL:K7F3-Q9ZP' && h === 'SIGELO:CTL:K7F3-Q9ZP-4WXN:RELAY.TEST:1883' && h.length <= 60, 'control text: SIGELO:CTL:<short code>[:<HOST>], ≤ 60 characters');
  const r = C.readControlText(' sigelo:ctl:k7f3-q9zp:RELAY.TEST:1883 '), r0 = C.readControlText(t);
  ok(r.code === 'K7F3Q9ZP' && r.relay === 'relay.test:1883' && r0.relay === null, 'control text read back: the code normalised, the relay lower case (null: the default)');
  const bad = (f) => { try { f(); return null; } catch (e) { return e.check; } };
  ok(bad(() => C.readControlText('SIGELO:DEV:K7F3-Q9ZP')) === 'control_text' && bad(() => C.readControlText('SIGELO:CTL:K7F3-Q9ZU')) === 'short_code' && bad(() => C.controlText('K7F3Q9ZP', 'a/b')) === 'control_text',
    'control text refused: another prefix, a character outside the alphabet, a host that is not one');
  const q = C.requestMessage({ id: '0123456789abcdef', method: 'GET', path: '/api/state?since=3' }), a = C.responseMessage({ id: q.id, status: 200, body: { x: 1 } }), e = C.eventsMessage({ seq: 4, since: 3, state: { seq: 4 } });
  ok(C.readControl(q) === q && C.readControl(a) === a && C.readControl(e) === e && q.v === 'sigelo-device/1' && D.DEVICE_V === q.v, 'request, response, events: sigelo-device/1, read back');
  ok([{ ...q, method: 'PUT' }, { ...q, id: 'xyz' }, { ...q, body: [1] }, { ...a, status: '200' }, { ...e, state: null }, { ...q, typ: 'material' }, { ...q, v: 'sigelo-device/0' }].every((m) => bad(() => C.readControl(m)) === 'control_message'),
    'control messages refused: a method, an id, a body not an object, a status, a state, a typ, a version');
  const id1 = C.newControlIdentity(), id2 = C.newControlIdentity();
  ok(id1.control === true && /^[0-9a-f]{64}$/.test(id1.secret) && id1.genesis.recovery === null && id1.attestations.length === 0 && did(id1.genesis) !== did(id2.genesis),
    'control identity: a random key (two differ), recovery null, never attested');
  let clock = 0;
  const b = C.bucket({ now: () => clock }), first = Array.from({ length: 12 }, () => b.take());
  clock += 3000;
  ok(first.filter(Boolean).length === C.BURST && first.slice(0, 10).every(Boolean) && [b.take(), b.take(), b.take(), b.take()].filter(Boolean).length === 3 * C.RATE, 'the cap: a burst of 10, then one a second');
}

// ---- restore from seed in the apps (restore.mjs, design/apps-seed.md): the files keeper --from-words writes, the seat
{
  const S0 = new Uint8Array(32).fill(7); S0[31] = 0x0f;   // a canonical root (< l), fixed
  const words = mnemonicFromRoot(S0), list = words.split(' '), now = 1761400000;
  const leaks = (m) => list.some((w) => String(m).toLowerCase().split(/[^a-z]+/).includes(w));
  const cw = (t) => RS.checkWords(t);
  ok(cw('').count === 0 && cw(list.slice(0, 7).join(' ')).count === 7 && cw(list.slice(0, 7).join(' ')).ok === false && cw(list.slice(0, 7).join(' ')).error === null,
    'checkWords: a partial seed counts, no error yet');
  ok(cw(`  ${list.slice(0, 12).join('\n')}\t\t${list.slice(12).join('  ')}\n`).ok === true && cw(words.toUpperCase()).ok === true && cw(list.map((w) => w.slice(0, 3)).join(' ')).ok === true,
    'checkWords: whitespace runs, newlines, upper case and 3-letter prefixes accepted; 25 with the checksum → ok');
  const bad = cw([...list.slice(0, 6), 'zzzq', ...list.slice(7)].join(' '));
  ok(bad.ok === false && bad.bad === 7 && /word 7 /.test(bad.error) && !bad.error.includes('zzzq'), 'checkWords: the first word not in the list named by position, never echoed');
  const swapped = [list[1], list[0], ...list.slice(2)].join(' '), sw = cw(swapped);
  ok(list[0] !== list[1] && sw.ok === false && /checksum/.test(sw.error) && !leaks(sw.error), 'checkWords: two words swapped → the checksum, no word in the message');
  ok(/26 words/.test(cw(`${words} ${list[0]}`).error), 'checkWords: 26 words refused');
  const pr = (t, n) => { try { return RS.parseRestore(t, n); } catch (e) { return e.check; } };
  ok(JSON.stringify(pr('')) === '{}' && pr(' 3100000 ').restore_height === 3100000 && pr('2024-02-29', now).restore_date === '2024-02-29',
    'parseRestore: empty → nothing; digits → restore_height; YYYY-MM-DD → restore_date');
  ok(pr('2023-02-30') === 'restore_date' && pr('2014-04-17') === 'restore_date' && pr('2099-01-01', now) === 'restore_date' && pr('20240229x') === 'restore_date' && pr('99999999999') === 'restore_date' && pr('4294967296') === 'restore_height',
    'parseRestore: refused: no such day, before Monero\'s first block, the future, junk, a height past 2^31');
  const o = { name: 'phone', relay: 'relay.sigelo.ai', net: 'stagenet', restore: { restore_height: 3100000 }, now };
  const r = RS.restoreFromWords(words, o), S = rootFromMnemonic(words), K = keeperRoot(S, 1), rec = recoveryCommitment(S);
  ok(JSON.stringify(r.identity) === JSON.stringify(operatorIdentity(S, 0)) && r.identity.derived.n === 0 && r.did === did(r.identity.genesis),
    'restoreFromWords: the identity is operatorIdentity(S, 0), as keeper --from-words writes it (derived n 0)');
  ok(r.keeper.v === D.KEEPER_V && r.keeper.keeper === 1 && r.keeper.root_hex === hex(K) && r.keeper.recovery === rec && r.keeper.created === '2025-10-25' && r.keeper.net === 'stagenet' && r.keeper.restore_height === 3100000 && !('restore_date' in r.keeper)
    && JSON.stringify(r.keeper.me) === JSON.stringify({ n: 0, did: r.did, original: r.did }) && JSON.stringify(Object.keys(r.keeper)) === JSON.stringify(['v', 'keeper', 'root_hex', 'recovery', 'created', 'net', 'restore_height', 'workers', 'me']),
    'restoreFromWords: the keeper file: K_1, the recovery commitment, created (UTC day), net and restore_height, me');
  const w0 = r.keeper.workers[0], dev = workerIdentity({ K, i: 0, n: 0, recovery: rec, attestation: w0.attestation, issuer: r.identity.genesis });
  ok(JSON.stringify(r.device) === JSON.stringify(dev) && w0.rank === 'full' && w0.placed === 'device' && w0.original === did(dev.genesis) && r.worker === w0.original && w0.until === now + D.DEVICE_DAYS * 86400,
    'restoreFromWords: this device is worker 0 of K_1, FULL, attested 14 days, in the roster');
  const a = w0.attestation, opKey = r.identity.genesis.key;
  ok(a.body.iss === r.did && a.body.sub === w0.original && a.body.claims.relay === 'relay.sigelo.ai' && verifySig(opKey, a.body, a.sig), 'restoreFromWords: the device attestation is the operator\'s, over the device\'s original DID');
  ok(D.checkList(r.list, { keys: [opKey], operator: r.did }) === r.list && r.list.seq === 1 && r.list.seat.holder === w0.original && r.list.seat.epoch === 1 && r.list.devices.length === 1 && r.list.devices[0].rank === 'full' && D.holdsSeat(r.list, w0.original),
    'restoreFromWords, seat here: the list signed by the operator, this device FULL, holding the seat at epoch 1 (seat init)');
  ok(r.notes.v === RS.SEAT_LOCAL_V && r.notes.imported === 1 && r.notes.here.did === w0.original && !r.notes.elsewhere, 'restoreFromWords, seat here: the seat notes name this device');
  const e = RS.restoreFromWords(words, { ...o, seat: 'elsewhere', restore: { restore_date: '2024-02-29' } });
  ok(e.list === null && e.notes.elsewhere === true && e.notes.entry.did === w0.original && e.keeper.restore_date === '2024-02-29' && !('restore_height' in e.keeper) && e.keeper.root_hex === r.keeper.root_hex,
    'restoreFromWords, seat elsewhere: no list (the seat\'s is on the other device), the entry kept for a take; restore_date');
  const t = RS.takeSeat(e.notes, e.identity, now + 60);
  ok(D.checkList(t.list, { keys: [opKey], operator: r.did }) === t.list && t.list.seat.holder === w0.original && t.notes.imported === 1 && !t.notes.elsewhere, 'takeSeat: the standby signs the list naming itself, notes say here');
  const ck = (f) => checkOf(f);
  ok(ck(() => RS.takeSeat(r.notes, r.identity, now)) === 'seat_here' && ck(() => RS.takeSeat(e.notes, operatorIdentity(keeperRoot(S, 9), 0), now)) === 'seat_here', 'takeSeat refused: the seat is here already; another operator\'s notes');
  ok(ck(() => RS.restoreFromWords(words, { ...o, name: 'My Phone' })) === 'device_name' && ck(() => RS.restoreFromWords(words, { ...o, net: 'testnet' })) === 'restore_net'
    && ck(() => RS.restoreFromWords(words, { ...o, seat: 'maybe' })) === 'restore_seat' && ck(() => RS.restoreFromWords(words, { ...o, j: 0 })) === 'restore'
    && ck(() => RS.restoreFromWords(words, { ...o, restore: { restore_height: -1 } })) === 'restore_height' && ck(() => RS.restoreFromWords(words, { ...o, relay: 'a/b' })) !== 'accepted',
    'restoreFromWords refused: a device name, a network, a seat, keeper 0, a height, a relay');
  let msg = '';
  try { RS.restoreFromWords(swapped, o); } catch (x) { msg = `${x.check} ${x.message}`; }
  ok(/^restore_words /.test(msg) && !leaks(msg), 'restoreFromWords: wrong words refused restore_words, the message carries no word');
  S.fill(0); K.fill(0);
}

// ---- a new identity made in the apps (create.mjs, pass A10a): S drawn here, three words typed back, then the restore's files
{
  const now = 1761400000, ck = (f) => checkOf(f);
  const s = CR.newSeed('stagenet'), w = s.words(), words = w.join(' '), S = rootFromMnemonic(words);
  ok(w.length === 25 && RS.checkWords(words).ok && s.vault === vaultFromRoot(S, 'stagenet').address && s.vault.startsWith('5') && CR.newSeed('mainnet').vault.startsWith('4'),
    'newSeed: 25 words with a valid checksum, a canonical root; vault = the words\' own Monero wallet (stagenet 5…, mainnet 4…)');
  ok(ck(() => s.commit({ name: 'phone', relay: 'relay.sigelo.ai', now })) === 'create_unchecked' && ck(() => s.check(['a', 'b', 'c'])) === 'create_quiz', 'newSeed: no commit before three words are checked; no check before a quiz');
  const q = s.quiz();
  ok(q.length === CR.QUIZ && new Set(q).size === 3 && q.every((x, i) => Number.isInteger(x) && x >= 1 && x <= 25 && (i === 0 || q[i - 1] < x)), `quiz: three distinct positions 1..25, ascending (${q})`);
  const bad = s.check(q.map((x, i) => (i === 1 ? w[x % 25] === w[x - 1] ? 'zzz' : w[x % 25] : w[x - 1])));
  ok(bad.ok === false && bad.wrong.join() === String(q[1]) && ck(() => s.commit({ name: 'phone', relay: 'relay.sigelo.ai', now })) === 'create_unchecked' && ck(() => s.check(q.map((x) => w[x - 1]))) === 'create_quiz',
    'check: a wrong word named by its position; the quiz ends (back to the words), no commit');
  const q2 = s.quiz(), good = s.check(q2.map((x, i) => (i === 0 ? ` ${w[x - 1].toUpperCase()} ` : i === 1 ? w[x - 1].slice(0, 3) : w[x - 1])));
  ok(good.ok === true && good.wrong.length === 0, 'check: the right words pass, as the wallet reads them (capitals, blanks, the first three letters)');
  const r = s.commit({ name: 'phone', relay: 'relay.sigelo.ai', now }), ref = RS.restoreFromWords(words, { name: 'phone', relay: 'relay.sigelo.ai', net: 'stagenet', restore: { restore_date: '2025-10-25' }, now });
  ok(JSON.stringify({ ...r, vault: undefined }) === JSON.stringify({ ...ref, keeper: { ...ref.keeper, made: 'here' } }) && r.vault === s.vault,
    'commit: exactly the files a restore from the same 25 words makes (identity, keeper, device, list, notes), the keeper marked made here');
  ok(r.keeper.created === '2025-10-25' && r.keeper.restore_date === '2025-10-25' && r.keeper.net === 'stagenet' && r.list.seat.epoch === 1 && r.list.devices[0].rank === 'full' && r.list.seat.holder === r.list.devices[0].did,
    'commit: created today, the wallet\'s birth today (restore_date), stagenet; the first FULL device holding the seat (epoch 1)');
  ok(ck(() => s.words()) === 'create_spent' && ck(() => s.quiz()) === 'create_spent' && ck(() => s.commit({ name: 'phone', relay: 'relay.sigelo.ai', now })) === 'create_spent',
    'commit: S zeroed; the words are never given again (create_spent)');
  const d = CR.newSeed('mainnet'); d.discard();
  ok(ck(() => d.words()) === 'create_spent' && ck(() => CR.newSeed('testnet')) === 'create_net' && CR.newSeed('mainnet').words().join(' ') !== words, 'discard: S zeroed, refused after; testnet refused; a fresh root each time');
  ok(ck(() => RS.restoreFromRoot(new Uint8Array(32), { name: 'phone', relay: 'relay.sigelo.ai', now })) === 'restore' && ck(() => RS.restoreFromRoot(new Uint8Array(32).fill(0xff), { name: 'phone', relay: 'relay.sigelo.ai', now })) === 'restore',
    'restoreFromRoot: zero and S >= l refused (not canonical: a wallet would show other words)');
  S.fill(0);
}

report();
console.log(`ALL PASS (${count})`);
