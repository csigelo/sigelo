// SPDX-License-Identifier: MIT
// Regenerates fixtures/device-v1.json, byte for byte: contract sigelo-device/1 (device.mjs header).
//   node contact/gen-device.mjs           write the file
//   node contact/gen-device.mjs --check   exit 1 if the committed file differs
// Independent of device.mjs on purpose: base45, the header, argon2id (node:crypto), the AEAD and the
// frames are worked out here, so the fixture checks device.mjs (test-device.mjs) instead of echoing
// it. The material is built with enrol.mjs from a fixed seed: S = SHA-256("sigelo-device/1 root S"),
// worker 0 under K_1, the operator attestation and the invite at a fixed time; `full`, the same
// device rank FULL: the operator identity, K_1 with its roster and the signed device list beside
// (device.mjs compactFull's shape, built here by hand). deflate-raw's bytes
// are zlib's and may change with it: the committed `deflated` is kept while it inflates to the
// material, so the container stays the same bytes on any zlib.
import { argon2Sync, createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { canonicalize, did, sign } from 'sigelo';
import { keeperRoot, recoveryCommitment } from 'sigelo/dist/keys.js';
import { operatorAttestation, operatorIdentity, workerIdentity } from './enrol.mjs';
import { makeInvite } from './invite.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'device-v1.json');
const sha = (s) => createHash('sha256').update(s).digest();
const seed = (l) => new Uint8Array(sha(`sigelo-device/1 ${l}`));
const NOW = 1792000000, RELAY = 'relay.sigelo.ai', WORDS = 'input boat shiver spoil when clip';
const SALT = seed('salt').subarray(0, 16), NONCE = seed('nonce').subarray(0, 24), KDF = { logm: 16, t: 3, p: 1 };

const S = seed('root S'), K = keeperRoot(S, 1), recovery = recoveryCommitment(S);
const op = operatorIdentity(S, 0), opDid = did(op.genesis);
const w = workerIdentity({ K, i: 0, n: 0, recovery });
const attestation = operatorAttestation({ secret: Buffer.from(op.secret, 'hex'), iss: opDid, sub: did(w.genesis), relay: RELAY, now: NOW, days: 14 });
const invite = makeInvite({ did: opDid, relay: RELAY, now: NOW, ttl: 7 * 86400, secret: seed('invite secret') }).text;
const material = {
  v: 'sigelo-device/1', typ: 'offline', rank: 'safe', exp: NOW + 86400, name: 'phone', relay: RELAY, recovery,
  worker: { i: 0, n: 0, secret: w.secret, iat: attestation.body.iat, aexp: attestation.body.exp, sig: attestation.sig }, issuer: op.genesis.key, invite,
};
const jcs = canonicalize(material);
const old = existsSync(OUT) ? JSON.parse(readFileSync(OUT, 'utf8')) : {};
const pinDeflate = (text, prev) => {
  const p = Buffer.from(prev ?? '', 'hex');
  try { if (inflateRawSync(p).toString('utf8') === text) return p; } catch {}
  return deflateRawSync(Buffer.from(text, 'utf8'), { level: 9 });
};
const deflated = pinDeflate(jcs, old.deflated);
const sealWith = (salt, nonce, plain) => {
  const h = Buffer.concat([Buffer.from('SGD1'), Buffer.from([1, KDF.logm, KDF.t, KDF.p]), salt, nonce]);
  const k = argon2Sync('argon2id', { message: Buffer.from(WORDS), nonce: salt, parallelism: KDF.p, tagLength: 32, memory: 2 ** KDF.logm, passes: KDF.t });
  return { key: k, container: Buffer.concat([h, xchacha20poly1305(k, nonce, h).encrypt(plain)]) };
};
const { key, container } = sealWith(SALT, NONCE, deflated);

// FULL: the device list (signed by the operator over typ device-list), the operator file, K_1, the roster.
const listBody = { v: 'sigelo-devices/1', typ: 'device-list', operator: opDid, seq: 1, iat: NOW, devices: [{ name: 'phone', worker: 0, did: did(w.genesis), rank: 'full', added: NOW, by: opDid }] };
const list = { v: listBody.v, operator: opDid, seq: 1, iat: NOW, devices: listBody.devices, sig: sign(Buffer.from(op.secret, 'hex'), listBody) };
const fullMaterial = { ...material, rank: 'full', op: { n: 0, secret: op.secret }, keeper: { j: 1, root: Buffer.from(K).toString('hex') }, roster: [[0, 0, 'phone']], devices: list };
const fullJcs = canonicalize(fullMaterial), fullDeflated = pinDeflate(fullJcs, old.full?.deflated);
const FSALT = seed('full salt').subarray(0, 16), FNONCE = seed('full nonce').subarray(0, 24);
const full = sealWith(FSALT, FNONCE, fullDeflated);

const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const b45 = (b) => {
  let s = '';
  for (let i = 0; i < b.length; i += 2) {
    if (i + 1 === b.length) { s += B45[b[i] % 45] + B45[Math.floor(b[i] / 45)]; break; }
    const n = (b[i] << 8) | b[i + 1];
    s += B45[n % 45] + B45[Math.floor(n / 45) % 45] + B45[Math.floor(n / 2025)];
  }
  return s;
};
// Frames in version-14 symbols at level M: 14 × 4 + 17 = 73 modules, 528 alphanumeric characters
// (ISO/IEC 18004), 12 of them the frame's head; the chunk a multiple of 3 characters.
const framesOf = (c) => {
  const t = b45(c), i = b45(sha(c).subarray(0, 3)).slice(0, 4);
  const room = Math.floor((528 - 12) / 3) * 3, count = Math.ceil(t.length / room), per = Math.ceil(t.length / count / 3) * 3;
  return { text: t, id: i, frames: Array.from({ length: count }, (_, n) => `SGD1${String(n + 1).padStart(2, '0')}${String(count).padStart(2, '0')}${i}${t.slice(n * per, (n + 1) * per)}`) };
};
const { text, id, frames } = framesOf(container), ff = framesOf(full.container);

const out = {
  v: 'sigelo-device/1', note: 'gen-device.mjs; test-device.mjs checks device.mjs against it', now: NOW, words: WORDS, kdf: KDF,
  salt: Buffer.from(SALT).toString('hex'), nonce: Buffer.from(NONCE).toString('hex'), key: Buffer.from(key).toString('hex'),
  operator: opDid, worker: did(w.genesis), material, jcs_sha256: sha(jcs).toString('hex'), deflated: deflated.toString('hex'),
  container: container.toString('hex'), base45: text, id, frames_v14: frames,
  full: { salt: Buffer.from(FSALT).toString('hex'), nonce: Buffer.from(FNONCE).toString('hex'), material: fullMaterial, jcs_sha256: sha(fullJcs).toString('hex'),
    deflated: fullDeflated.toString('hex'), container: full.container.toString('hex'), id: ff.id, frames_v14: ff.frames },
  online: { short: 'K7F3Q9ZP', text: 'SIGELO:DEV:K7F3-Q9ZP', with_host: 'SIGELO:DEV:K7F3-Q9ZP:RELAY.EXAMPLE.ORG' },
  base45_rfc9285: [{ in: 'AB', out: 'BB8' }, { in: 'Hello!!', out: '%69 VD92EX0' }, { in: 'base-45', out: 'UJCLQE7W581' }, { in: 'ietf!', out: 'QED8WEX0' }],
};
const json = JSON.stringify(out, null, 2) + '\n';
if (process.argv.includes('--check')) {
  if (!existsSync(OUT) || readFileSync(OUT, 'utf8') !== json) { console.error(`${OUT} differs from what gen-device.mjs makes`); process.exit(1); }
  console.log(`ok ${OUT}`);
} else {
  writeFileSync(OUT, json);
  console.log(`wrote ${OUT}`);
}
