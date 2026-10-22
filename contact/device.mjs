// SPDX-License-Identifier: MIT
// Devices, contract sigelo-device/1 (design/devices.md §5–§7): moving a device identity to a phone
// or a second computer by QR. No network and no process here; sigelo-agent's `device` verbs drive
// it (adapters/moadim/sigelo-agent-device.ts, DEVICES.md). Two ranks: SAFE, the device becomes
// worker i of the operator's keeper root, its own DID, tier own, revocable alone; FULL, it also
// gets the operator identity and the keeper root K_j (the two files `keeper --from-words` writes).
//
//   Online (both sides connected): the QR is onlineText(code[, host]) = SIGELO:DEV:<short code>[:<HOST>],
//     at most 60 characters; the device runs enrolment (enrol.mjs) with it, and the operator sends
//     the identity only once the four words were confirmed on its side.
//   Offline: the QR is the material itself, sealed under k generated BIP-39 words (6 by default,
//     66 bits) and argon2id, in frames of at most a version-20 symbol each:
//       material  = compactSafe({...})                       the JCS object of §7.3, below
//       container = seal(material, words)                    §7.4: header ‖ XChaCha20-Poly1305
//       frames    = toFrames(container, { maxVersion })      SGD1 ‖ index ‖ count ‖ id ‖ base45 chunk
//     and back: joinFrames(any order) → open(container, words) → rebuild(material, { now }).
//
// The container (binary, then base45, RFC 9285):
//   "SGD1" (4) ‖ kdf 0x01 = argon2id (1) ‖ log2(memory KiB) (1, 16 = 64 MiB) ‖ passes (1, 3) ‖
//   lanes (1, 1) ‖ salt (16) ‖ nonce (24) ‖ XChaCha20-Poly1305(key, nonce, aad = these 48 bytes,
//   deflate-raw(JCS(material)))
//   key = argon2id(the words: NFKD, lower case, single spaces; salt; memory, passes, lanes; 32 bytes).
//   argon2id: node:crypto's (Node ≥ 24.7, native), else @noble/hashes/argon2 (the same function,
//   slower). Refused on open: magic, kdf, memory outside 2^15–2^18 KiB, passes outside 1–10, lanes
//   outside 1–4 (device_container); the AEAD (device_words: the words do not open it).
//
// SAFE material (JCS; genesis bytes are rebuilt, not carried, as enrol.mjs pins them):
//   { v, typ: "offline", rank: "safe", exp, name, relay, recovery,
//     worker: { i, n, secret, iat, aexp, sig, chain? }, issuer, invite }
//   secret: worker i's key at rotation n (hex); recovery: the seed's recovery commitment, the same
//   in the worker's and the operator's genesis; iat, aexp, sig: the operator attestation (its body
//   is rebuilt: iss = the issuer, sub = the worker's original DID, ctx sigelo-relay/operator, claims
//   {relay}); issuer: the operator's current public key (its genesis is pinned, so rebuilt from it);
//   chain: {genesis, rotations} only when n > 0 (rotation 0's genesis needs rotation 0's key);
//   invite: the operator's long invite (7 days at most) the device accepts at its first connection.
//   exp is advisory: whoever holds the image and the words can open it after (THREAT-MODEL §2.15).
//
// FULL material, offline (compactFull): the SAFE fields, rank "full", and
//   op: { n, secret, chain? }    the operator identity at rotation n (its genesis pinned, rebuilt
//                                 from the key and `recovery`; chain only when n > 0)
//   keeper: { j, root }          K_j, 64 hex; roster: [[i, n, name], …] (DIDs re-derived from K_j)
//   devices                      the signed device list, naming this device rank full
// rebuild() re-derives every DID and checks: the operator's head key is `issuer`, its secret signs
// for it, K_j derives this device's own worker, the list verifies under the operator's key.
//
// Online, end to end over the device's own pairing with the operator (label sigelo-device/1, sent
// only by sigelo-agent's `device` verbs, kept apart by the carrier, never logged):
//   material  { v, typ: "material", rank: "full", iat, exp, operator: <identity file>, keeper:
//              <keeper file>, devices: <list> }  exp = iat + 10 minutes: sent within 10 minutes of
//              the words' "y" (gateOpen), refused after (device_expired); checkMaterial
//   list      { v, typ: "list", devices: <list> }       acceptList: a higher seq, the operator's signature
//   wipe      { v, typ: "wipe", devices: <list> }       the list marks this device revoked (9.1)
//   wiped     { v, typ: "wiped", name, worker }         the device's answer, before it deletes its files
//
//   seat-ask  { v, typ: "seat-ask", epoch_seen }          a FULL device asks the seat for it (device seat take)
//   seat      { v, typ: "seat", devices: <list> }        the list whose seat moved (give, take --force)
//   snapshot  { v, typ: "snapshot", epoch, seq, sha256, size, data? | file? }  the sealed snapshot, inline
//              (base64, at most INLINE_MAX sealed bytes) or as a sigelo-file/0 file of that sha256
//   renew     { v, typ: "renew", attestation }           the device's operator attestation, renewed by the seat
//
// The device list, sigelo-devices/1 (devices.md §4.1): local inventory of the operator's own devices,
//   { v, operator, seq, iat, devices: [{ name, worker, did, rank, added, by, revoked? }], seat?, sig }
// sig = the operator's signature over "sigelo\n" ‖ JCS({ v, typ: "device-list", operator, seq, iat,
// devices, seat? }): a typ no bundle accepts. seat = { holder: a live FULL device's DID, epoch ≥ 1, iat }
// (D3; a D2 list has none, and verifies as before): the one device that logs in as the operator.
// A list replaces another when its seat epoch is higher, or, at the same epoch and holder, its seq is
// higher (device_list_stale); a lower epoch, a seat dropped, or another holder at the same epoch is
// device_seat_stale; always under a valid signature by the operator's key (device_list_sig).
//
// Snapshots (devices.md §4.4): the operator's files as the seat holds them, for FULL standbys only:
//   body   = { v, typ: "snapshot", operator, epoch, seq, iat, files: { carrier, contacts, ui?, enrol?,
//            devices, held?, roster?, history?, log? } }   each a file's text, as it is on disk
//   sealed = "SGS1" (4) ‖ nonce (24) ‖ XChaCha20-Poly1305(key, nonce, aad = these 28 bytes,
//            deflate-raw(JCS(body)))   key = HKDF-SHA256(K_j, salt "sigelo-device/1", info "snapshot")
// Opened only where K_j is; at rest on a standby only sealed. history and log only with --with-history.
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { canonicalize, decodeKey, did as didOf, multibase, parse, sign as signWith, verify as verifyBundle, verifySig } from 'sigelo';
import { WORDS } from './bip39-english.mjs';
import { IDENTITY_PATH, OPERATOR_CTX, PINNED_CREATED, checkIdentity, identityMessage, pinnedIdentity, workerChain } from './enrol.mjs';
import { fail } from './kdf.mjs';
import { ALNUM, alnumCapacity } from './qr.mjs';
import { ALPHABET, formatShort, normaliseShort } from './short.mjs';

export const DEVICE_V = 'sigelo-device/1', LABEL_DEVICE = 'sigelo-device/1';
export const MAGIC = 'SGD1', KDF_ARGON2ID = 0x01, HEADER = 48;
export const KDF_DEFAULT = Object.freeze({ logm: 16, t: 3, p: 1 });
export const WORDS_DEFAULT = 6, WORDS_MIN = 5, WORDS_MAX = 8;
// The device's attestation: 14 days, renewed while it is listed (devices.md §3).
export const DEVICE_DAYS = 14;
// Advisory life of an offline container; the invite inside lives 7 days (invite.mjs TTL_MAX).
export const OFFLINE_EXP = 86400;
export const ONLINE_PREFIX = 'SIGELO:DEV:', FRAME_PREFIX = 'SGD1', FRAME_HEAD = 12, FRAMES_MAX = 99;
// Frames default to a version-20 symbol at level M: 970 characters.
export const FRAME_VERSION = 20;

// ---------------------------------------------------------------- base45 (RFC 9285)

export const B45 = ALNUM;
/** Bytes → base45 text: two bytes, three characters (low digit first); a last odd byte, two. */
export function base45(bytes) {
  let s = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const n = bytes[i] * 256 + bytes[i + 1];
    s += B45[n % 45] + B45[Math.floor(n / 45) % 45] + B45[Math.floor(n / 2025)];
  }
  if (bytes.length % 2) { const n = bytes[bytes.length - 1]; s += B45[n % 45] + B45[Math.floor(n / 45)]; }
  return s;
}
/** Base45 text → bytes; refused (base45) outside the alphabet, at a length of 3k + 1, above 65535 or 255. */
export function unbase45(text) {
  if (typeof text !== 'string' || text.length % 3 === 1) fail('base45', `not base45: ${typeof text === 'string' ? `${text.length} characters (3k + 1 is no length)` : 'not text'}`);
  const v = [...text].map((c, i) => { const k = B45.indexOf(c); if (k < 0) fail('base45', `character ${i + 1} ${JSON.stringify(c)} is not base45`); return k; });
  const out = [];
  for (let i = 0; i < v.length; i += 3) {
    if (i + 2 < v.length) {
      const n = v[i] + v[i + 1] * 45 + v[i + 2] * 2025;
      if (n > 0xffff) fail('base45', `characters ${i + 1}–${i + 3} are above 65535`);
      out.push(n >> 8, n & 0xff);
    } else {
      const n = v[i] + v[i + 1] * 45;
      if (n > 0xff) fail('base45', 'the last two characters are above 255');
      out.push(n);
    }
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------- the words

/** k words (WORDS_MIN–WORDS_MAX) from the BIP-39 English list, 11 bits each from a CSPRNG. */
export function makeWords(k = WORDS_DEFAULT, rng = randomBytes) {
  if (!Number.isInteger(k) || k < WORDS_MIN || k > WORDS_MAX) fail('device_words', `${WORDS_MIN} to ${WORDS_MAX} words, not ${k}`);
  const b = rng(Math.ceil((k * 11) / 8));
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  const extra = BigInt(b.length * 8 - k * 11);
  return Array.from({ length: k }, (_, i) => WORDS[Number((x >> (extra + BigInt(11 * (k - 1 - i)))) & 2047n)]).join(' ');
}
/** The words as the key takes them: NFKD, lower case, single spaces; each must be on the list. */
export function normaliseWords(text) {
  if (typeof text !== 'string') fail('device_words', 'the words: text');
  const w = text.normalize('NFKD').toLowerCase().trim().split(/\s+/).filter(Boolean);
  if (w.length < WORDS_MIN || w.length > WORDS_MAX) fail('device_words', `${w.length} words: the giving side shows ${WORDS_DEFAULT} (${WORDS_MIN} to ${WORDS_MAX})`);
  w.forEach((x, i) => { if (!WORDS.includes(x)) fail('device_words', `word ${i + 1} is not one of the list: check its spelling against the giving screen`); });
  return w.join(' ');
}

// ---------------------------------------------------------------- the key

// Node's own crypto and zlib when this runs in Node (process.getBuiltinModule, no import, so a page
// loads this file); in a page: @noble's argon2id, and deflate-raw only through the async pair
// below (deflateRaw, inflateRaw: CompressionStream); seal takes its bytes as `deflated`.
const builtin = (name) => { try { return globalThis.process?.getBuiltinModule?.(name) ?? null; } catch { return null; } };
const nodeCrypto = builtin('node:crypto'), zlib = builtin('node:zlib');
const noZlib = () => fail('platform', 'deflate-raw needs node:zlib here: give the deflated bytes (deflateRaw)');
const deflateRawSync = (b, o) => (zlib ?? noZlib()).deflateRawSync(b, o);
const inflateRawSync = (b, o) => (zlib ?? noZlib()).inflateRawSync(b, o);
/** deflate-raw (level 9 on Node, the runtime's own elsewhere): → Uint8Array. */
export async function deflateRaw(bytes) {
  if (zlib) return new Uint8Array(zlib.deflateRawSync(bytes, { level: 9 }));
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'))).arrayBuffer());
}
/** inflate-raw, at most max bytes out (more: throws). */
export async function inflateRaw(bytes, max) {
  if (zlib) return new Uint8Array(zlib.inflateRawSync(bytes, { maxOutputLength: max }));
  const r = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader(), parts = [];
  let n = 0;
  for (;;) {
    const { done, value } = await r.read();
    if (done) break;
    n += value.length;
    if (n > max) { await r.cancel(); throw new RangeError(`more than ${max} bytes inflated`); }
    parts.push(value);
  }
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}
export const nativeArgon2 = typeof nodeCrypto?.argon2Sync === 'function';
/** argon2id(message, salt, memory 2^logm KiB, t passes, p lanes) → 32 bytes. native: node:crypto, else @noble/hashes. */
export function argon2(message, salt, { logm, t, p }, { native = nativeArgon2 } = {}) {
  const m = 2 ** logm;
  if (native) return new Uint8Array(nodeCrypto.argon2Sync('argon2id', { message, nonce: salt, parallelism: p, tagLength: 32, memory: m, passes: t }));
  return nobleArgon2id(message, salt, { t, m, p, dkLen: 32 });
}
const keyOf = (words, salt, kdf, o) => argon2(new TextEncoder().encode(normaliseWords(words)), salt, kdf, o);

// ---------------------------------------------------------------- the container

function header(kdf, salt, nonce) {
  const h = new Uint8Array(HEADER);
  h.set(new TextEncoder().encode(MAGIC), 0);
  h[4] = KDF_ARGON2ID; h[5] = kdf.logm; h[6] = kdf.t; h[7] = kdf.p;
  h.set(salt, 8); h.set(nonce, 24);
  return h;
}
const checkKdf = ({ logm, t, p }) => {
  if (!(Number.isInteger(logm) && logm >= 15 && logm <= 18)) fail('device_container', `argon2id memory 2^${logm} KiB: 2^15 to 2^18 (32 to 256 MiB)`);
  if (!(Number.isInteger(t) && t >= 1 && t <= 10)) fail('device_container', `argon2id passes ${t}: 1 to 10`);
  if (!(Number.isInteger(p) && p >= 1 && p <= 4)) fail('device_container', `argon2id lanes ${p}: 1 to 4`);
};

/**
 * The material sealed under the words. salt (16), nonce (24): random unless given (the fixture);
 * deflated: the deflate-raw bytes to seal, when given (the fixture: deflate's bytes are zlib's).
 */
export function seal(material, words, { kdf = KDF_DEFAULT, salt, nonce, deflated, native } = {}) {
  checkKdf(kdf);
  salt ??= randomBytes(16); nonce ??= randomBytes(24);
  if (salt.length !== 16 || nonce.length !== 24) fail('device_container', 'salt 16 bytes, nonce 24');
  const plain = deflated ?? deflateRawSync(new TextEncoder().encode(canonicalize(material)), { level: 9 });
  const h = header(kdf, salt, nonce), key = keyOf(words, salt, kdf, { native });
  try {
    const ct = xchacha20poly1305(key, nonce, h).encrypt(plain);
    const out = new Uint8Array(HEADER + ct.length);
    out.set(h); out.set(ct, HEADER);
    return out;
  } finally { key.fill(0); }
}

/** The header of a container, checked: { kdf, salt, nonce }. */
export function readHeader(c) {
  if (!(c instanceof Uint8Array) || c.length < HEADER + 16) fail('device_container', 'too short for a sigelo-device/1 container');
  if (new TextDecoder().decode(c.subarray(0, 4)) !== MAGIC) fail('device_container', `not a ${MAGIC} container`);
  if (c[4] !== KDF_ARGON2ID) fail('device_container', `kdf ${c[4]}: this version reads 1 (argon2id)`);
  const kdf = { logm: c[5], t: c[6], p: c[7] };
  checkKdf(kdf);
  return { kdf, salt: c.slice(8, 24), nonce: c.slice(24, 48) };
}

/** The material of a container, opened with the words; device_words when they do not open it. */
export function open(c, words, { native } = {}) {
  const { kdf, salt, nonce } = readHeader(c), key = keyOf(words, salt, kdf, { native });
  let plain;
  try { plain = xchacha20poly1305(key, nonce, c.subarray(0, HEADER)).decrypt(c.subarray(HEADER)); } catch { fail('device_words', 'the words do not open this: check each word against the giving screen (or the frames are of another code)'); } finally { key.fill(0); }
  let m;
  try { m = parse(new TextDecoder('utf-8', { fatal: true }).decode(inflateRawSync(plain, { maxOutputLength: 1 << 20 }))); } catch (e) { fail('device_material', `the opened material does not read (${e.message})`); }
  if (!isObject(m) || m.v !== DEVICE_V || m.typ !== 'offline') fail('device_material', `not ${DEVICE_V} offline material`);
  return m;
}

// ---------------------------------------------------------------- frames

const sha256 = (b) => nobleSha256(b);
/** The container's 4-character id: base45 of the first 3 bytes of its SHA-256, cut to 4. */
export const frameId = (c) => base45(sha256(c).subarray(0, 3)).slice(0, 4);

/** Base45 characters a frame carries in a symbol of `maxVersion` at level M, a multiple of 3. */
export const frameRoom = (maxVersion = FRAME_VERSION) => Math.floor((alnumCapacity(maxVersion, 'M') - FRAME_HEAD) / 3) * 3;

/** The container as frames of at most a `maxVersion` symbol each, all of one length but the last. */
export function toFrames(c, { maxVersion = FRAME_VERSION } = {}) {
  const text = base45(c), room = frameRoom(maxVersion);
  if (room < 3) fail('device_frames', `version ${maxVersion} holds no frame`);
  const count = Math.ceil(text.length / room);
  if (count > FRAMES_MAX) fail('device_frames', `${count} frames: at most ${FRAMES_MAX}; use larger symbols`);
  const per = Math.ceil(text.length / count / 3) * 3, id = frameId(c);
  return Array.from({ length: count }, (_, i) => `${FRAME_PREFIX}${String(i + 1).padStart(2, '0')}${String(count).padStart(2, '0')}${id}${text.slice(i * per, (i + 1) * per)}`);
}

/** One frame read: { index, count, id, chunk }, or device_frame naming what is wrong. */
export function readFrame(text) {
  const t = typeof text === 'string' ? text.trim() : '';
  const m = /^SGD1(\d\d)(\d\d)(.{4})(.*)$/s.exec(t);
  if (!m) fail('device_frame', 'not a device frame (they start SGD1)');
  const index = Number(m[1]), count = Number(m[2]);
  if (count < 1 || index < 1 || index > count) fail('device_frame', `frame ${index} of ${count}: no such frame`);
  if (![...m[3] + m[4]].every((ch) => B45.includes(ch))) fail('device_frame', 'a frame with characters outside base45: scan it again');
  return { index, count, id: m[3], chunk: m[4] };
}

/**
 * Frames in any order, repeats and other codes' frames refused: → { done: true, container } once all
 * are in, else { done: false, have, count, missing }. frames: texts, or what readFrame gave.
 */
export function joinFrames(frames) {
  const read = frames.map((f) => (typeof f === 'string' ? readFrame(f) : f));
  if (read.length === 0) fail('device_frame', 'no frame');
  const { id, count } = read[0], got = new Map();
  for (const f of read) {
    if (f.id !== id || f.count !== count) fail('device_frame', `a frame of another code (${f.id}, ${f.count} frames) among those of ${id}: scan one code's frames only`);
    if (got.has(f.index) && got.get(f.index) !== f.chunk) fail('device_frame', `frame ${f.index} twice, with different contents`);
    got.set(f.index, f.chunk);
  }
  const missing = Array.from({ length: count }, (_, i) => i + 1).filter((i) => !got.has(i));
  if (missing.length) return { done: false, have: got.size, count, missing, id };
  const c = unbase45(Array.from({ length: count }, (_, i) => got.get(i + 1)).join(''));
  if (frameId(c) !== id) fail('device_frame', 'the frames do not add up to the code they name (a frame misread): scan them again');
  return { done: true, container: c, count, id };
}

// ---------------------------------------------------------------- online QR text

/** The online QR: SIGELO:DEV:K7F3-Q9ZP, with :HOST (upper case) when the relay is not the default. */
export function onlineText(short, host) {
  const code = formatShort(normaliseShort(short));
  if (host === undefined || host === null) return `${ONLINE_PREFIX}${code}`;
  if (typeof host !== 'string' || !/^[a-z0-9.-]+(:\d{1,5})?$/i.test(host) || host.length > 40) fail('device_qr', `relay ${JSON.stringify(host)}: a host name (and port)`);
  return `${ONLINE_PREFIX}${code}:${host.toUpperCase()}`;
}

/**
 * What a scanned or pasted text is: { kind: 'online', code, relay } (relay null: this agent's own),
 * { kind: 'frame', frame }, or { kind: 'code', code } for a bare short code typed by hand.
 */
export function readScan(text) {
  const t = typeof text === 'string' ? text.trim() : '';
  if (t.toUpperCase().startsWith(ONLINE_PREFIX)) {
    const [code, ...host] = t.slice(ONLINE_PREFIX.length).split(':');
    return { kind: 'online', code: normaliseShort(code), relay: host.length ? host.join(':').toLowerCase() : null };
  }
  if (t.startsWith(FRAME_PREFIX)) return { kind: 'frame', frame: readFrame(t) };
  if (t.replace(/[\s-]/g, '').length <= 12 && [...t.replace(/[\s-]/g, '').toUpperCase()].every((c) => ALPHABET.includes(c) || 'ILO'.includes(c))) return { kind: 'code', code: normaliseShort(t) };
  return fail('scan_text', 'neither a device QR (SIGELO:DEV:…, SGD1…) nor a short code (K7F3-Q9ZP)');
}

// ---------------------------------------------------------------- SAFE material

const isObject = (x) => typeof x === 'object' && x !== null && !Array.isArray(x);
const NAME = /^[a-z0-9][a-z0-9_-]{0,19}$/;
export const checkName = (n) => (typeof n === 'string' && NAME.test(n) ? n : fail('device_name', `a device name: lowercase letters, digits, _ and -, at most 20 characters, not ${JSON.stringify(n)}`));

/**
 * The compact SAFE material from the worker's identity file (enrol.mjs workerIdentity, rotation n,
 * one operator attestation), the device's name, the operator's invite and its exp.
 */
export function compactSafe({ name, identity, i, n, invite, exp }) {
  checkName(name);
  if (!isObject(identity) || identity.attestations?.length !== 1 || identity.issuers?.length !== 1) fail('device_material', 'the identity carries one operator attestation and its issuer');
  const a = identity.attestations[0], issuer = identity.issuers[0];
  if (a.body.ctx !== OPERATOR_CTX || !isObject(a.body.claims) || typeof a.body.claims.relay !== 'string') fail('device_material', 'not an operator attestation');
  if (identity.rotations.length !== n) fail('device_material', `rotation ${n}, but the identity holds ${identity.rotations.length} rotations`);
  return {
    v: DEVICE_V, typ: 'offline', rank: 'safe', exp, name, relay: a.body.claims.relay, recovery: identity.genesis.recovery,
    worker: { i, n, secret: identity.secret, iat: a.body.iat, aexp: a.body.exp, sig: a.sig, ...(n > 0 && { chain: { genesis: identity.genesis, rotations: identity.rotations } }) },
    issuer: issuer.key, invite,
  };
}

/** A pinned genesis from a public key alone (enrol.mjs pins created and takes the nonce from the key). */
export function pinnedGenesisOf(key, recovery) {
  const nonce = sha256(decodeKey(key)).subarray(0, 16);
  return { v: 'sigelo/0', typ: 'genesis', key, recovery, created: PINNED_CREATED, nonce: multibase(nonce) };
}

/**
 * The device's identity file from SAFE material, checked as enrolment checks one received over the
 * relay (enrol.mjs checkIdentity: the chain, the key, the operator attestation, the invite naming
 * the operator). → { identity, did, original, worker, operator, invite, exp, name }.
 */
export function rebuild(m, { now }) {
  if (!isObject(m) || m.v !== DEVICE_V || m.typ !== 'offline') fail('device_material', `not ${DEVICE_V} offline material`);
  if (m.rank !== 'safe' && m.rank !== 'full') fail('device_rank', `rank ${JSON.stringify(m.rank)}: safe or full`);
  const w = m.worker;
  if (!isObject(w) || !Number.isSafeInteger(w.i) || w.i < 0 || !Number.isSafeInteger(w.n) || w.n < 0 || typeof w.secret !== 'string' || !/^[0-9a-f]{64}$/.test(w.secret)) fail('device_material', 'worker: {i, n, secret}');
  checkName(m.name);
  let genesis, rotations;
  if (w.n === 0) ({ genesis } = pinnedIdentity(hexToBytes(w.secret), m.recovery)), rotations = [];
  else {
    if (!isObject(w.chain) || !Array.isArray(w.chain.rotations) || w.chain.rotations.length !== w.n) fail('device_material', `rotation ${w.n} needs its chain`);
    ({ genesis, rotations } = w.chain);
  }
  const issuer = pinnedGenesisOf(m.issuer, m.recovery), iss = didOf(issuer);
  const body = { v: 'sigelo/0', typ: 'attestation', iss, sub: didOf(genesis), iat: w.iat, exp: w.aexp, ctx: OPERATOR_CTX, admission: 'invite', claims: { relay: m.relay }, admission_by: iss };
  const identity = { v: 'sigelo/0', secret: w.secret, genesis, rotations, attestations: [{ body, sig: w.sig }], issuers: [issuer] };
  const x = checkIdentity(identityMessage(identity, m.invite, w.i), { operator: { current_did: iss, current_key: issuer.key }, relay: m.relay, now });
  const out = { ...x, operator: iss, name: m.name, exp: m.exp, rank: m.rank };
  return m.rank === 'full' ? { ...out, full: rebuildFull(m, out, now) } : out;
}

// ---------------------------------------------------------------- FULL

export const KEEPER_V = 'sigelo-keeper-hot/0', LIST_V = 'sigelo-devices/1', LIST_TYP = 'device-list';
export const RANKS = Object.freeze(['safe', 'full']);
// The material goes within 10 minutes of the words' "y" (devices.md §5.1), and lives as long.
export const MATERIAL_TTL = 600;
const SKEW = 300, HEX64 = /^[0-9a-f]{64}$/;
// As Buffer.from(h, 'hex') reads it: byte pairs up to the first that is not hex.
const hexBytes = (h) => { const m = /^(?:[0-9a-fA-F]{2})*/.exec(String(h))[0]; return m === '' ? new Uint8Array(0) : hexToBytes(m); };
const PROBE = { v: 'sigelo/0', typ: 'challenge', did: 'did:sigelo:z1', ctx: 'sigelo-device/1 key check', nonce: 'z1' };
const signsFor = (secretHex, key) => verifySig(key, PROBE, signWith(hexBytes(secretHex), PROBE));

/** Whether the material may still go: within MATERIAL_TTL of the words' "y" (confirmedAt, unix seconds). */
export const gateOpen = (confirmedAt, now) => Number.isSafeInteger(confirmedAt) && now >= confirmedAt && now - confirmedAt <= MATERIAL_TTL;

const checkEntry = (d) => {
  if (!isObject(d)) fail('device_list', 'an entry: an object');
  checkName(d.name);
  if (!Number.isSafeInteger(d.worker) || d.worker < 0) fail('device_list', `${d.name}: worker, a whole number`);
  if (typeof d.did !== 'string' || !d.did.startsWith('did:sigelo:')) fail('device_list', `${d.name}: did`);
  if (!RANKS.includes(d.rank)) fail('device_list', `${d.name}: rank safe or full`);
  if (!Number.isSafeInteger(d.added) || typeof d.by !== 'string') fail('device_list', `${d.name}: added, by`);
  if (d.revoked !== undefined && !Number.isSafeInteger(d.revoked)) fail('device_list', `${d.name}: revoked, unix seconds`);
  const extra = Object.keys(d).filter((k) => !['name', 'worker', 'did', 'rank', 'added', 'by', 'revoked'].includes(k));
  if (extra.length) fail('device_list', `${d.name}: unknown field ${extra[0]}`);
};
/** The body the operator signs: typ device-list, a slot no bundle accepts; the seat when the list has one. */
export const listBody = (l) => ({ v: LIST_V, typ: LIST_TYP, operator: l.operator, seq: l.seq, iat: l.iat, devices: l.devices, ...(l.seat !== undefined && { seat: l.seat }) });
/** A seat record checked against its list's devices: the holder a live FULL device, epoch ≥ 1. */
function checkSeat(seat, devices) {
  if (!isObject(seat) || Object.keys(seat).some((k) => !['holder', 'epoch', 'iat'].includes(k))) fail('device_seat', 'seat: {holder, epoch, iat}');
  if (typeof seat.holder !== 'string' || !Number.isSafeInteger(seat.epoch) || seat.epoch < 1 || !Number.isSafeInteger(seat.iat)) fail('device_seat', 'seat: holder a DID, epoch ≥ 1, iat');
  const d = devices.find((x) => x.did === seat.holder && x.revoked === undefined);
  if (!d || d.rank !== 'full') fail('device_seat', 'the seat names no live FULL device of the list');
}
function checkListShape(l) {
  if (!isObject(l) || l.v !== LIST_V) fail('device_list', `not a ${LIST_V} list`);
  const extra = Object.keys(l).filter((k) => !['v', 'operator', 'seq', 'iat', 'devices', 'seat', 'sig'].includes(k));
  if (extra.length) fail('device_list', `unknown field ${extra[0]}`);
  if (typeof l.operator !== 'string' || !l.operator.startsWith('did:sigelo:') || !Number.isSafeInteger(l.seq) || l.seq < 1 || !Number.isSafeInteger(l.iat)) fail('device_list', 'operator, seq ≥ 1, iat');
  if (!Array.isArray(l.devices) || l.devices.length > 64) fail('device_list', 'devices: at most 64');
  l.devices.forEach(checkEntry);
  for (const k of ['name', 'worker']) if (new Set(l.devices.map((d) => d[k])).size !== l.devices.length) fail('device_list', `two devices with one ${k}`);
  if (l.seat !== undefined) checkSeat(l.seat, l.devices);
}
/** The list signed: { operator (its original DID), seq, iat, devices, seat? } and sign(body) → the signature. */
export function signList({ operator, seq, iat, devices, seat }, sign) {
  const l = { v: LIST_V, operator, seq, iat, devices, ...(seat !== undefined && { seat }) };
  checkListShape(l);
  return { ...l, sig: sign(listBody(l)) };
}
/** A list checked: its shape, and its signature under one of `keys` (the operator chain's keys). → the list. */
export function checkList(l, { keys, operator }) {
  checkListShape(l);
  if (operator !== undefined && l.operator !== operator) fail('device_list_operator', `a list of ${l.operator}, not of ${operator}`);
  if (typeof l.sig !== 'string' || !keys.some((k) => verifySig(k, listBody(l), l.sig))) fail('device_list_sig', `list ${l.seq}: the operator's signature does not verify`);
  return l;
}
/**
 * The list that stands after `next` came: next when it verifies and is newer than cur: a higher seat
 * epoch, or the same seat and a higher seq. A lower epoch, a seat dropped, or another holder at the
 * same epoch: device_seat_stale; the same seat, seq not higher (a replay, an older list): device_list_stale.
 */
export function acceptList(cur, next, { keys }) {
  checkList(next, { keys, operator: cur?.operator });
  if (!cur) return next;
  const ce = cur.seat?.epoch ?? 0, ne = next.seat?.epoch ?? 0;
  if ((cur.seat && !next.seat) || ne < ce) fail('device_seat_stale', `a list with seat epoch ${ne}, but epoch ${ce} is here already: an older seat record`);
  if (ne > ce) return next;
  if (cur.seat && next.seat.holder !== cur.seat.holder) fail('device_seat_stale', `two seat holders at epoch ${ne}: the one here stands`);
  if (next.seq <= cur.seq) fail('device_list_stale', `list ${next.seq}, but ${cur.seq} is here already: an older list, or a replay`);
  return next;
}
/** The seat after `cur` moved to `holder` at `now`: epoch + 1 (the first seat: epoch 1). */
export const nextSeat = (cur, holder, now) => ({ holder, epoch: (cur?.epoch ?? 0) + 1, iat: now });
/** Whether `did` holds the seat in list l (a list without a seat: nobody does). */
export const holdsSeat = (l, did) => l?.seat?.holder === did;
/** The devices with `name` marked revoked at `now`; device_unknown when no such device, device_revoked when it is already. */
export function revokeIn(devices, name, now) {
  const d = devices.find((x) => x.name === name);
  if (!d) fail('device_unknown', `no device ${JSON.stringify(name)} in the list`);
  if (d.revoked !== undefined) fail('device_revoked', `${name} was revoked already`);
  return devices.map((x) => (x.name === name ? { ...x, revoked: now } : x));
}
/** The list entry naming `did` (the device's original DID), live, or null. */
export const entryOf = (l, did) => l?.devices.find((d) => d.did === did && d.revoked === undefined) ?? null;

/**
 * What a lost device needs (devices.md §9.2): `now`, the steps without words (the caller does them),
 * and `words`, those with the 25 words, as commands. d: the list entry; n: its rotation; j: the
 * keeper; opN: the operator's rotation.
 */
export function lostSteps({ d, n, j, opN, until }) {
  if (d.rank === 'safe') return {
    now: [`${d.name} marked revoked in the list, its DID forgotten, its attestation not renewed: it leaves own by ${until}`],
    words: [`optional, to supersede the thief at once: sigelo-offline recover --genesis <its bundle> --agent ${d.worker} --keeper ${j} --n ${n + 1}, then sigelo-agent adopt --rotation on the machine that runs it`],
  };
  return {
    now: [`${d.name} marked revoked in the list, its device DID forgotten. This only contains: it may hold your identity and K_${j}, so it can still sign and log in as you`],
    words: [
      `on a clean machine, networking down: sigelo-agent bundle --operator > me.json; sigelo-offline recover --genesis me.json --identity-n ${opN + 1} (your words), then sigelo-agent adopt --rotation here: the stolen key is superseded; every contact pairs again`,
      `sigelo-agent keeper --from-words --keeper ${j + 1}: the new keeper root (K_${j} cannot be rotated)`,
      `each worker under K_${j}: sigelo-offline recover --genesis <its bundle> --agent <i> --keeper ${j + 1} --n 0, then adopt --rotation where it runs; or enrol it afresh`,
      `sigelo-agent device add --full again to each FULL device you keep, plain device add to the others`,
      `delete keeper ${j}'s file (me.local.keeper.json, or beside your --identity) everywhere`,
    ],
  };
}

const opIdentity = (secret, genesis, rotations, n) => ({ v: 'sigelo/0', secret, genesis, rotations, attestations: [], issuers: [], derived: { path: `${IDENTITY_PATH}/${n}`, n } });
const headOf = (id) => id.rotations.at(-1)?.next_genesis ?? id.genesis;

/**
 * The compact FULL material: compactSafe's, plus the operator identity file (`operator`, its secret
 * plain hex, rotation n), the hot keeper file (`keeper`, root_hex) and the signed list.
 */
export function compactFull({ operator, keeper, devices, ...safe }) {
  const m = compactSafe(safe);
  const n = operator.rotations?.length ?? -1;
  if (typeof operator.secret !== 'string' || !HEX64.test(operator.secret) || n < 0) fail('device_material', 'the operator identity: secret 64 hex, its rotations');
  if (headOf(operator).key !== m.issuer) fail('device_material', 'the operator identity is not the attestation\'s issuer');
  if (operator.genesis.recovery !== m.recovery) fail('device_material', 'the operator and the worker commit to other recovery keys');
  if (keeper?.v !== KEEPER_V || !HEX64.test(keeper.root_hex ?? '') || keeper.recovery !== m.recovery) fail('device_material', `the keeper: a ${KEEPER_V} file of this seed`);
  const roster = Object.entries(keeper.workers ?? {}).map(([i, w]) => [Number(i), w.n, w.name]).sort((a, b) => a[0] - b[0]);
  return {
    ...m, rank: 'full',
    op: { n, secret: operator.secret, ...(n > 0 && { chain: { genesis: operator.genesis, rotations: operator.rotations } }) },
    keeper: { j: keeper.keeper, root: keeper.root_hex }, roster, devices,
  };
}

// The FULL part of rebuild(): the operator identity file, the keeper file and the list, each checked.
function rebuildFull(m, x, now) {
  const op = m.op, k = m.keeper;
  if (!isObject(op) || !Number.isSafeInteger(op.n) || op.n < 0 || typeof op.secret !== 'string' || !HEX64.test(op.secret)) fail('device_material', 'op: {n, secret}');
  if (!isObject(k) || !Number.isSafeInteger(k.j) || k.j < 1 || typeof k.root !== 'string' || !HEX64.test(k.root)) fail('device_material', 'keeper: {j ≥ 1, root 64 hex}');
  let genesis, rotations;
  if (op.n === 0) ({ genesis } = pinnedIdentity(hexBytes(op.secret), m.recovery)), rotations = [];
  else {
    if (!isObject(op.chain) || !Array.isArray(op.chain.rotations) || op.chain.rotations.length !== op.n) fail('device_material', `operator rotation ${op.n} needs its chain`);
    ({ genesis, rotations } = op.chain);
  }
  const operator = opIdentity(op.secret, genesis, rotations, op.n);
  let r;
  try { r = verifyBundle({ v: 'sigelo/0', typ: 'bundle', genesis, rotations, bindings: [], attestations: [], issuers: [] }, now); } catch (e) { fail('device_material', `the operator chain does not verify (${e.message})`); }
  const head = headOf(operator);
  if (head.key !== m.issuer || r.did !== x.operator) fail('device_material', `the operator identity is ${r.did}, not ${x.operator}, the attestation's issuer`);
  if (!signsFor(op.secret, head.key)) fail('device_material', 'the operator secret is not the key of its head');
  const K = hexBytes(k.root);
  if (workerChain(K, x.worker, 0, m.recovery).original !== x.original) fail('device_material', `the keeper root does not derive this device (worker ${x.worker})`);
  if (!Array.isArray(m.roster) || !m.roster.every((e) => Array.isArray(e) && e.length === 3 && Number.isSafeInteger(e[0]) && e[0] >= 0 && Number.isSafeInteger(e[1]) && e[1] >= 0 && typeof e[2] === 'string')) fail('device_material', 'roster: [[i, n, name], …]');
  const devices = checkList(m.devices, { keys: [head.key], operator: r.chain[0] });
  const self = entryOf(devices, x.original);
  if (!self || self.rank !== 'full') fail('device_material', 'the list does not name this device rank full');
  const workers = {};
  for (const [i, n, name] of m.roster) {
    const c = workerChain(K, i, n, m.recovery), d = devices.devices.find((y) => y.worker === i);
    workers[i] = { name, n, did: c.did, original: c.original, placed: d ? 'device' : 'remote', at: d?.added ?? devices.iat, ...(d && { rank: d.rank }) };
  }
  const keeper = { v: KEEPER_V, keeper: k.j, root_hex: k.root, recovery: m.recovery, me: { n: op.n, did: r.did, original: r.chain[0] }, workers };
  return { operator, keeper, devices };
}

/** The online material (§7.2), from the operator's identity file (secret plain hex), its keeper file and the list. */
export function materialMessage({ operator, keeper, devices, now }) {
  if (typeof operator?.secret !== 'string' || !HEX64.test(operator.secret)) fail('device_material', 'the operator identity: its secret as 64 hex');
  if (keeper?.v !== KEEPER_V || !HEX64.test(keeper.root_hex ?? '')) fail('device_material', `the keeper: a ${KEEPER_V} file, root_hex`);
  return { v: DEVICE_V, typ: 'material', rank: 'full', iat: now, exp: now + MATERIAL_TTL, operator, keeper, devices };
}

/**
 * The device: a material message from `from` (the contact record of its operator: did, current_did),
 * for `self` (this device's original DID). → { operator, keeper, devices }, checked as rebuild checks
 * the offline one; device_expired past exp.
 */
export function checkMaterial(c, { from, self, now }) {
  if (!isObject(c) || c.v !== DEVICE_V || c.typ !== 'material' || c.rank !== 'full') fail('device_material', `not ${DEVICE_V} material`);
  if (!Number.isSafeInteger(c.iat) || !Number.isSafeInteger(c.exp) || c.exp - c.iat > MATERIAL_TTL || c.exp < c.iat) fail('device_material', 'iat, exp: at most 10 minutes apart');
  if (c.iat > now + SKEW) fail('device_material', 'its iat is in the future: check both clocks');
  if (now > c.exp + SKEW) fail('device_expired', 'the material came more than 10 minutes after the words were confirmed: not taken; add the device again');
  const op = c.operator, k = c.keeper;
  const keys = ['v', 'secret', 'genesis', 'rotations', 'attestations', 'issuers'];
  if (!isObject(op) || !keys.every((y) => y in op) || typeof op.secret !== 'string' || !HEX64.test(op.secret) || !Array.isArray(op.rotations)) fail('device_material', 'operator: an identity file, secret 64 hex');
  let r;
  try { r = verifyBundle({ v: 'sigelo/0', typ: 'bundle', genesis: op.genesis, rotations: op.rotations, bindings: [], attestations: op.attestations, issuers: op.issuers }, now); } catch (e) { fail('device_material', `the operator identity does not verify (${e.message})`); }
  if (r.chain[0] !== from.did || r.did !== from.current_did) fail('device_material', `the identity is ${r.did}, not the operator this device is paired with (${from.current_did})`);
  const head = headOf(op);
  if (!signsFor(op.secret, head.key)) fail('device_material', 'the operator secret is not the key of its head');
  if (!isObject(k) || k.v !== KEEPER_V || !Number.isSafeInteger(k.keeper) || k.keeper < 1 || !HEX64.test(k.root_hex ?? '') || k.recovery !== op.genesis.recovery || !isObject(k.workers)) fail('device_material', `keeper: a ${KEEPER_V} file of the operator's seed`);
  const devices = checkList(c.devices, { keys: [head.key], operator: from.did });
  const me = entryOf(devices, self);
  if (!me || me.rank !== 'full') fail('device_material', 'the list does not name this device rank full');
  if (workerChain(hexBytes(k.root_hex), me.worker, 0, k.recovery).original !== self) fail('device_material', `the keeper root does not derive this device (worker ${me.worker})`);
  const operator = Object.fromEntries(Object.entries(op).filter(([y]) => [...keys, 'derived'].includes(y)));
  return { operator, keeper: { v: KEEPER_V, keeper: k.keeper, root_hex: k.root_hex, recovery: k.recovery, ...(isObject(k.me) && { me: k.me }), workers: k.workers }, devices };
}

/** A device message's shape (§7.2): material, list, wipe, wiped, seat-ask, seat, snapshot, renew. → the message. */
export function readMessage(c) {
  if (!isObject(c) || c.v !== DEVICE_V || typeof c.typ !== 'string') fail('device_message', `not a ${DEVICE_V} message`);
  if (c.typ === 'list' || c.typ === 'wipe' || c.typ === 'seat') { if (!isObject(c.devices)) fail('device_message', `${c.typ}: devices`); }
  else if (c.typ === 'wiped') { checkName(c.name); if (!Number.isSafeInteger(c.worker)) fail('device_message', 'wiped: worker'); }
  else if (c.typ === 'seat-ask') { if (!Number.isSafeInteger(c.epoch_seen) || c.epoch_seen < 0) fail('device_message', 'seat-ask: epoch_seen'); }
  else if (c.typ === 'snapshot') {
    if (!Number.isSafeInteger(c.epoch) || !Number.isSafeInteger(c.seq) || typeof c.sha256 !== 'string' || !HEX64.test(c.sha256) || !Number.isSafeInteger(c.size)) fail('device_message', 'snapshot: epoch, seq, sha256, size');
    if ((typeof c.data === 'string') === (c.file !== undefined)) fail('device_message', 'snapshot: data inline or a file, one of them');
  } else if (c.typ === 'renew') { if (!isObject(c.attestation) || !isObject(c.attestation.body) || typeof c.attestation.sig !== 'string') fail('device_message', 'renew: attestation'); }
  else if (c.typ !== 'material') fail('device_message', `typ ${JSON.stringify(c.typ)}: material, list, wipe, wiped, seat-ask, seat, snapshot or renew`);
  return c;
}

// ---------------------------------------------------------------- snapshots (D3, devices.md §4.4)

export const SNAP_MAGIC = 'SGS1', SNAP_HEAD = 28;
// Sealed snapshots up to this size go inline in one sigelo-device/1 message; larger ones as a sigelo-file/0 file.
export const INLINE_MAX = 48 * 1024;
// The files a snapshot may carry; history and log only with --with-history.
export const SNAP_FILES = Object.freeze(['carrier', 'contacts', 'ui', 'enrol', 'devices', 'held', 'roster', 'history', 'log']);
export const SNAP_HISTORY = Object.freeze(['history', 'log']);
const SNAP_PLAIN_MAX = 64 * 1024 * 1024;
/** The snapshot key: HKDF-SHA256(K_j, salt "sigelo-device/1", info "snapshot"), 32 bytes. */
export const snapshotKey = (K) => {
  if (!(K instanceof Uint8Array) || K.length !== 32) fail('device_snapshot', 'the keeper root: 32 bytes');
  return hkdf(nobleSha256, K, new TextEncoder().encode(DEVICE_V), new TextEncoder().encode('snapshot'), 32);
};
/** Whether a sealed snapshot of n bytes goes inline ('inline') or as a sigelo-file/0 file ('file'). */
export const snapshotRoute = (n, max = INLINE_MAX) => (n <= max ? 'inline' : 'file');

function checkSnapshotBody(b) {
  if (!isObject(b) || b.v !== DEVICE_V || b.typ !== 'snapshot') fail('device_snapshot', `not a ${DEVICE_V} snapshot`);
  if (typeof b.operator !== 'string' || !b.operator.startsWith('did:sigelo:') || !Number.isSafeInteger(b.epoch) || b.epoch < 1 || !Number.isSafeInteger(b.seq) || b.seq < 1 || !Number.isSafeInteger(b.iat)) fail('device_snapshot', 'operator, epoch ≥ 1, seq ≥ 1, iat');
  if (!isObject(b.files) || Object.entries(b.files).some(([k, v]) => !SNAP_FILES.includes(k) || typeof v !== 'string')) fail('device_snapshot', `files: texts of ${SNAP_FILES.join(', ')}`);
  for (const k of ['carrier', 'contacts', 'devices']) if (typeof b.files[k] !== 'string') fail('device_snapshot', `files: ${k} is required`);
  return b;
}
/** The snapshot body: the operator's original DID, the seat epoch and list seq it goes with, the files' texts. */
export function snapshotBody({ operator, epoch, seq, iat, files, history = false }) {
  const f = Object.fromEntries(Object.entries(files).filter(([k, v]) => typeof v === 'string' && (history || !SNAP_HISTORY.includes(k))));
  return checkSnapshotBody({ v: DEVICE_V, typ: 'snapshot', operator, epoch, seq, iat, files: f });
}
/** The body sealed under K (the keeper root): SGS1 ‖ nonce ‖ XChaCha20-Poly1305. nonce: random unless given. */
export function sealSnapshot(body, K, { nonce } = {}) {
  checkSnapshotBody(body);
  nonce ??= randomBytes(24);
  if (nonce.length !== 24) fail('device_snapshot', 'nonce: 24 bytes');
  const h = new Uint8Array(SNAP_HEAD);
  h.set(new TextEncoder().encode(SNAP_MAGIC), 0); h.set(nonce, 4);
  const key = snapshotKey(K);
  try {
    const ct = xchacha20poly1305(key, nonce, h).encrypt(deflateRawSync(new TextEncoder().encode(canonicalize(body)), { level: 9 }));
    const out = new Uint8Array(SNAP_HEAD + ct.length);
    out.set(h); out.set(ct, SNAP_HEAD);
    return out;
  } finally { key.fill(0); }
}
/** A sealed snapshot opened with K: → its body. device_snapshot: not one; device_snapshot_key: K does not open it (another keeper, or tampered). */
export function openSnapshot(c, K, { operator } = {}) {
  if (!(c instanceof Uint8Array) || c.length < SNAP_HEAD + 16 || new TextDecoder().decode(c.subarray(0, 4)) !== SNAP_MAGIC) fail('device_snapshot', `not a ${SNAP_MAGIC} snapshot`);
  const key = snapshotKey(K);
  let plain;
  try { plain = xchacha20poly1305(key, c.slice(4, SNAP_HEAD), c.subarray(0, SNAP_HEAD)).decrypt(c.subarray(SNAP_HEAD)); } catch { fail('device_snapshot_key', 'this keeper root does not open the snapshot (another keeper, or it was changed on the way)'); } finally { key.fill(0); }
  let b;
  try { b = parse(new TextDecoder('utf-8', { fatal: true }).decode(inflateRawSync(plain, { maxOutputLength: SNAP_PLAIN_MAX }))); } catch (e) { fail('device_snapshot', `the opened snapshot does not read (${e.message})`); }
  checkSnapshotBody(b);
  if (operator !== undefined && b.operator !== operator) fail('device_snapshot', `a snapshot of ${b.operator}, not of ${operator}`);
  return b;
}
/** Whether snapshot a (epoch, seq, iat) is newer than b (or b is none). */
export const newerSnapshot = (a, b) => !b || a.epoch > b.epoch || (a.epoch === b.epoch && (a.seq > b.seq || (a.seq === b.seq && a.iat > b.iat)));
