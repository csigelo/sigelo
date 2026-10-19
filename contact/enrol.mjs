// SPDX-License-Identifier: MIT
// Enrolment, contract sigelo-enrol/1: the operator places worker i, an identity DERIVED from its
// keeper root K (MONERO.md §2, ts/src/keys.ts agentIdentitySeed(K, i, n)), on another machine, so
// the 25 words bring the same DID back. THREAT-MODEL §2.11, adapters/moadim/ENROL.md.
//
//   operatorIdentity(S, n) → the operator's own identity file: the root identity of S (keys.ts
//             identitySeed(S, n), genesis pinned the same way), marked `derived: {path, n}`
//   workerIdentity({ K, i, n, recovery, attestation, issuer }) → the worker's identity file
//             (sigelo-agent's Store: secret, genesis, rotations, attestations, issuers), the same
//             bytes at every call: `created` pinned, the nonce from the key (SPEC §4 `nonce`),
//             rotations m → m+1 voluntary with iat 0. A second copy of a rotation is the same
//             rotation, never a fork.
//   operator: issue({ carrier, file, i, n, name, keeper })  → a short code (short.mjs, 10 minutes,
//             once) for a normal invite, and a pending enrolment kept in `file` for 24 hours, with
//             the operator attestation signed now (≤ 90 days)
//   machine:  accept({ carrier, file, code, temp })  → `carrier` is a TEMPORARY identity (`temp`, its
//             file): it fetches the code, pairs, and once paired sends a request, label LABEL_ENROL,
//             {v, typ: "enrol-request", proof}
//   both:     complete({ carrier, file, wait, until, keeper | place, temp }) → one inbox or more:
//             the operator answers a request whose proof matches an enrolment it issued with the
//             worker's identity, label LABEL_IDENTITY, end to end, once per enrolment, with a long
//             invite the worker accepts; once the worker has paired, the operator files it (observe:
//             ours by the attestation; tier own unless the operator chose one) and forgets the
//             temporary DID. The machine takes the identity only from the DID it paired with
//             through the code, checks it (checkIdentity)
//             and hands it to place(), which writes the file and pairs as the worker; then it
//             forgets the operator on the temporary identity, which gives its mailboxes up.
//             Anything else comes back in `rest`, for the caller's own inbox.
//
// The marker. Both sides hold the invite's one-time secret (the operator made it, the machine
// fetched it once), so
//   key   = HKDF-SHA256(secret, no salt, info "sigelo-enrol/0 key", 32 bytes)
//   proof = hex HMAC-SHA256(key, "sigelo-enrol/0 request\n" ‖ pair id)
// where the pair id (kdf.pairId) is that of the pairing the request travels on. A plain `accept` of
// the code pairs and gets nothing; a proof lifted onto another pairing does not match. The secret
// alone is not enough: anyone who saw the long code (a chat it was pasted in; the relay, which
// parks it behind the short code) can compute a proof over a pairing of its own. So the operator
// answers only the DID that paired through this enrolment's own code (carrier.answeredBy(nonce),
// recorded with that pairing): enrol_unpaired while nobody has, enrol_from for any other contact.
// The relay is no contact: knowing the secret gives it no pairing to send a proof on, and that
// holds for a relay operator who is also a contact (its own pairing did not come through the code).
// What stays is the code itself: whoever ANSWERS it first (the relay, which holds it; anyone it was
// shown to) pairs through it and is answered; the machine then sees park_unknown or four words that
// differ, after the key went (THREAT-MODEL §2.11). One enrolment, one temporary DID: enrol_used
// stays as a second check, unreachable while one code pairs one DID.
//
// The private key travels once, inside a sigelo-msg/0 envelope (end to end); it is never parked
// on the relay and never encrypted under the 8-character code (40 bits).
//
// The pending file, 0600, beside the identity (x.json → x.enrol.json), under its own lock:
//   { v, issued: { invite nonce: { key, i, n, name, did, old_pair, relay, exp, attestation, issuer,
//                                   temp?, invite?, done? } },
//         joining: { invite nonce: { key, code_did, relay, exp, sent, temp } } }
// Entries go at exp, 24 hours after they were made, whatever their state.
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, existsSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize, decodeKey, did as didOf, keygen, rotate, sign, structure, verify, verifySig } from 'sigelo';
import { agentIdentitySeed, identitySeed, recoveryCommitment } from 'sigelo/dist/keys.js';
import { keepLong, readCode } from './carrier.mjs';
import { MsgError, checkNow, fail, pairId, signAs, unhex } from './kdf.mjs';
import { codeKind } from './short.mjs';

export const ENROL_V = 'sigelo-enrol/1';
export const LABEL_ENROL = 'sigelo-enrol/1', LABEL_IDENTITY = 'sigelo-identity/0';
export const TYP_REQUEST = 'enrol-request', TYP_IDENTITY = 'enrol-identity';
export const OPERATOR_CTX = 'sigelo-relay/operator', OPERATOR_DAYS = 90, DAY = 86400;
// How long an enrolment stays pending, on either side: the invite's own default life.
export const PENDING_TTL = DAY;
// A derived genesis is reproducible from K alone (SPEC §4 `nonce`: created pinned, the nonce from
// the key), and so is each rotation (iat pinned): re-deriving worker i gives the same bytes.
export const PINNED_CREATED = '1970-01-01T00:00:00Z', ROTATION_IAT = 0, MAX_N = 64;
const KEY_INFO = 'sigelo-enrol/0 key', PROOF_PREFIX = 'sigelo-enrol/0 request\n';
const SKEW = 300, WAIT_STEP = 300;

// ---------------------------------------------------------------- the worker's identity

/** A genesis pinned (SPEC §4 `nonce`): created fixed, the nonce from the key, so the same seed gives the same DID. */
function pinnedGenesis(seed, recovery) {
  if (!/^sha256:[0-9a-f]{64}$/.test(recovery ?? '')) fail('keeper', 'the recovery commitment must be sha256:<64 hex> (the seed\'s recovery key, keys.ts recoveryCommitment)');
  const key = keygen({ seed, recovery, created: PINNED_CREATED, nonce: new Uint8Array(16) }).key;
  const nonce = new Uint8Array(createHash('sha256').update(decodeKey(key)).digest().subarray(0, 16));
  return { seed, ...keygen({ seed, recovery, created: PINNED_CREATED, nonce }) };
}
// Rotations 0 → n of seedAt(m), voluntary, iat pinned: the same bytes at every derivation.
function pinnedChain(seedAt, n, recovery) {
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_N) fail('enrol', `rotation: 0 to ${MAX_N}, not ${n}`);
  const g = Array.from({ length: n + 1 }, (_, m) => pinnedGenesis(seedAt(m), recovery));
  const rotations = g.slice(1).map((x, m) => rotate({ genesis: g[m].genesis, next_genesis: x.genesis, iat: ROTATION_IAT, reason: 'voluntary', secret: g[m].seed, next_secret: x.seed }));
  return { genesis: g[0].genesis, rotations, secret: g[n].seed, original: g[0].did, did: g[n].did };
}

/** Rotation `n` of worker `i` under K: keys.ts agentIdentitySeed, its genesis pinned. */
export const workerGenesis = (K, i, n, recovery) => pinnedGenesis(agentIdentitySeed(K, i, n), recovery);

/** Worker i at rotation n: genesis 0, the rotations 0 → n, the secret of n. No attestation. */
export const workerChain = (K, i, n, recovery) => pinnedChain((m) => agentIdentitySeed(K, i, m), n, recovery);

export const IDENTITY_PATH = 'sigelo/v1/identity/ed25519';
/** The operator's own identity: the ROOT identity of S (keys.ts identitySeed(S, n)), pinned like a worker's. */
export const operatorChain = (S, n) => pinnedChain((m) => identitySeed(S, m), n, recoveryCommitment(S));

/** The operator identity file at rotation n; `derived` marks it seed-derived (no S in it). */
export function operatorIdentity(S, n) {
  const c = operatorChain(S, n);
  return { v: 'sigelo/0', secret: bytesToHex(c.secret), genesis: c.genesis, rotations: c.rotations, attestations: [], issuers: [], derived: { path: `${IDENTITY_PATH}/${n}`, n } };
}
/** The operator attestation for a worker (relay/operator.mjs's shape), sub its ORIGINAL DID. */
// Signed by sign (the operator's signer, sigelo-agent-keys.ts) or secret (kdf.mjs signAs); the body
// is the one sigelo's attest() builds.
export function operatorAttestation({ sign: signer, secret, iss, sub, relay, now, days = OPERATOR_DAYS }) {
  checkNow(now);
  if (!Number.isSafeInteger(days) || days < 1 || days > OPERATOR_DAYS) fail('enrol', `days: 1 to ${OPERATOR_DAYS}`);
  const body = { v: 'sigelo/0', typ: 'attestation', iss, sub, iat: now, exp: now + days * DAY, ctx: OPERATOR_CTX, admission: 'invite', claims: { relay }, admission_by: iss };
  structure(body, 'attestation');
  return { body, sig: signAs({ sign: signer, secret }, body) };
}

/** The identity file of worker i, rotation n, carrying the operator's attestation and genesis. */
export function workerIdentity({ K, i, n, recovery, attestation, issuer }) {
  const c = workerChain(K, i, n, recovery);
  return { v: 'sigelo/0', secret: bytesToHex(c.secret), genesis: c.genesis, rotations: c.rotations, attestations: attestation ? [attestation] : [], issuers: issuer ? [issuer] : [] };
}

// ---------------------------------------------------------------- the marker and the messages

/** The enrolment key from an invite's 32-byte one-time secret. */
export function enrolKey(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) fail('enrol', 'the invite secret must be 32 bytes');
  return hkdf(sha256, secret, undefined, utf8ToBytes(KEY_INFO), 32);
}

/** The request's proof: the key over the pair id of the pairing it travels on. */
export function proofOf(key, pair) {
  unhex(pair, 16, 'pair');
  return bytesToHex(hmac(sha256, key, utf8ToBytes(PROOF_PREFIX + pair)));
}

/** The machine's request, sent once paired. */
export const request = (key, pair) => ({ v: ENROL_V, typ: TYP_REQUEST, proof: proofOf(key, pair) });

/** Whether `content` is a request made with `key` on the pairing `pair`; false for any other shape. */
export function matches(content, key, pair) {
  if (!isObject(content) || content.v !== ENROL_V || content.typ !== TYP_REQUEST || typeof content.proof !== 'string' || !/^[0-9a-f]{64}$/.test(content.proof)) return false;
  const want = proofOf(key, pair);
  let d = 0;
  for (let i = 0; i < 64; i++) d |= want.charCodeAt(i) ^ content.proof.charCodeAt(i);
  return d === 0;
}

/** The message that carries the worker: its identity file and a long invite to pair as it. */
export const identityMessage = (identity, invite, worker = null) => ({ v: ENROL_V, typ: TYP_IDENTITY, identity, invite, worker });

/**
 * The machine: an identity message from `operator` (the contact store's record of whoever it paired
 * with through the code), naming `relay`. → { identity, did, original, invite }, or a MsgError
 * naming the check.
 */
export function checkIdentity(content, { operator, relay, now }) {
  checkNow(now);
  if (!isObject(content) || content.v !== ENROL_V || content.typ !== TYP_IDENTITY || !isObject(content.identity) || typeof content.invite !== 'string') fail('enrol_message', `not a ${ENROL_V} ${TYP_IDENTITY}`);
  const x = content.identity, keys = ['v', 'secret', 'genesis', 'rotations', 'attestations', 'issuers'];
  if (Object.keys(x).sort().join() !== [...keys].sort().join() || typeof x.secret !== 'string' || !/^[0-9a-f]{64}$/.test(x.secret)) fail('enrol_message', `the identity must be exactly {${keys.join(', ')}}, secret 64 hex`);
  if (![x.rotations, x.attestations, x.issuers].every(Array.isArray) || x.attestations.length !== 1 || x.issuers.length !== 1) fail('enrol_message', 'the identity carries rotations, and exactly one attestation and one issuer');
  let r;
  try { r = verify({ v: 'sigelo/0', typ: 'bundle', genesis: x.genesis, rotations: x.rotations, bindings: [], attestations: x.attestations, issuers: x.issuers }, now); } catch (e) { fail('enrol_identity', `the identity does not verify (${e.message})`); }
  const head = [x.genesis, ...x.rotations.map((y) => y.next_genesis)].find((g) => didOf(g) === r.did);
  const probe = { v: 'sigelo/0', typ: 'challenge', did: r.did, ctx: 'sigelo-enrol/1 key check', nonce: 'z1' };
  if (!verifySig(head.key, probe, sign(hexToBytes(x.secret), probe))) fail('enrol_identity', `the secret is not the key of ${r.did}, the chain's current DID`);
  const a = x.attestations[0], b = a.body, iss = didOf(x.issuers[0]);
  if (iss !== operator.current_did || x.issuers[0].key !== operator.current_key) fail('enrol_issuer', `attested by ${iss}, not the current key of ${operator.current_did}, the contact this machine enrolled with`);
  if (!(r.attestations[iss] ?? []).some((y) => y.ctx === OPERATOR_CTX && y.sub === b.sub)) fail('enrol_sig', 'the operator attestation does not verify in the identity\'s bundle (signature, time or subject)');
  if (b.ctx !== OPERATOR_CTX || b.admission !== 'invite' || b.admission_by !== iss) fail('enrol_shape', `not an operator attestation (ctx ${OPERATOR_CTX}, admission "invite" by its issuer)`);
  if (b.sub !== r.chain[0]) fail('enrol_shape', `it is for ${b.sub}, not the worker's original DID ${r.chain[0]}`);
  if (!isObject(b.claims) || Object.keys(b.claims).join() !== 'relay' || b.claims.relay !== relay) fail('enrol_shape', `its claims must be exactly {"relay": "${relay}"}`);
  if (b.exp - b.iat > OPERATOR_DAYS * DAY) fail('enrol_shape', `it lives more than ${OPERATOR_DAYS} days`);
  if (b.iat > now + SKEW) fail('enrol_time', 'its iat is in the future: check both clocks (date -u)');
  let code;
  try { code = readCode(content.invite, now); } catch (e) { fail('enrol_invite', `the worker's invite does not parse (${e.message})`); }
  if (code.did !== operator.current_did) fail('enrol_invite', `the worker's invite names ${code.did}, not the operator ${operator.current_did}`);
  const worker = Number.isSafeInteger(content.worker) && content.worker >= 0 ? content.worker : null;
  return { identity: { v: 'sigelo/0', secret: x.secret, genesis: x.genesis, rotations: x.rotations, attestations: [{ body: b, sig: a.sig }], issuers: x.issuers }, did: r.did, original: r.chain[0], invite: content.invite, worker, exp: b.exp };
}

// ---------------------------------------------------------------- the pending file

/** The pending file beside an identity file: x.json → x.enrol.json. */
export const enrolPath = (identityFile) => identityFile.replace(/\.json$/, '') + '.enrol.json';

const LOCK_TRIES = 200, LOCK_MS = 25;
function withLock(path, fn) {
  const lock = `${path}.lock`, idle = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; ; i++) {
    try { closeSync(openSync(lock, 'wx', 0o600)); break; } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (i === LOCK_TRIES) fail('lock', `${lock} is still held after ${(LOCK_TRIES * LOCK_MS) / 1000} s: another sigelo process holds it, or one was killed holding it; delete the file to continue`);
      Atomics.wait(idle, 0, 0, LOCK_MS);
    }
  }
  try { return fn(); } finally { rmSync(lock, { force: true }); }
}
const writeJson = (path, value) => {
  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(8).toString('hex')}.tmp`);
  writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600, flag: 'wx' });
  renameSync(tmp, path);
};

/** Load, purge what is past its 24 hours, change (fn), save: under the file's lock. → fn's result. */
export function pending(file, now, fn = () => undefined) {
  checkNow(now);
  return withLock(file, () => {
    let s = { v: ENROL_V, issued: {}, joining: {} };
    if (existsSync(file)) {
      try { s = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { fail('enrol_file', `${file} does not parse (${e.message}): delete it to drop the pending enrolments`); }
      if (s?.v !== ENROL_V || !isObject(s.issued) || !isObject(s.joining)) fail('enrol_file', `${file} is not a ${ENROL_V} file: delete it to drop the pending enrolments`);
    }
    const before = canonicalize(s);
    for (const k of ['issued', 'joining']) for (const [id, e] of Object.entries(s[k])) if (!(e.exp > now)) delete s[k][id];
    const out = fn(s);
    if (canonicalize(s) !== before) writeJson(file, s);
    return out;
  });
}

// ---------------------------------------------------------------- the flows

const isObject = (x) => typeof x === 'object' && x !== null && !Array.isArray(x);
const nowOf = (carrier) => checkNow(carrier.clock());
const readStore = (carrier) => (existsSync(carrier.storePath) ? JSON.parse(readFileSync(carrier.storePath, 'utf8')) : { contacts: {} });
const pairOf = (c) => pairId(unhex(c.pair_key, 32, 'store'));
// The carrier's identity, verified: original DID, current DID and its genesis, and sign(body).
function self(carrier, now) {
  const id = carrier.identity(), { bundle } = id;
  const r = verify({ v: 'sigelo/0', typ: 'bundle', genesis: bundle.genesis, rotations: bundle.rotations, bindings: [], attestations: [], issuers: [] }, now);
  const genesis = [bundle.genesis, ...bundle.rotations.map((x) => x.next_genesis)].find((g) => didOf(g) === r.did);
  return { original: r.chain[0], did: r.did, genesis, sign: (body) => signAs(id, body) };
}
// The contact store record holding `did` in its chain, live and paired only.
const liveHolding = (carrier, did) => Object.values(readStore(carrier).contacts).find((c) => !c.revoked && c.pair_key && c.chain.includes(did)) ?? null;
const checkKeeper = (k) => {
  if (!isObject(k) || !(k.K instanceof Uint8Array) || k.K.length !== 32 || typeof k.recovery !== 'string') fail('keeper', 'the keeper root: { K: 32 bytes, recovery: sha256:… }');
  return k;
};

/**
 * The operator: a short code for a normal invite, and the enrolment of worker i (rotation n) it
 * stands for (24 hours). The operator attestation is signed here, at derivation time.
 * → { short, short_exp, code, id, did (the worker's current DID), original }.
 */
export async function issue({ carrier, file, i, n, name, keeper }) {
  checkKeeper(keeper);
  const w = workerChain(keeper.K, i, n, keeper.recovery);
  // The temporary identity's contact, named apart from the worker's (forgotten once it has paired).
  const r = await carrier.invite({ name: `${name ?? `worker ${i}`} (enrolling)`, short: true });
  const now = nowOf(carrier), code = readCode(r.code, now), me = self(carrier, now);
  const attestation = operatorAttestation({ sign: me.sign, iss: me.did, sub: w.original, relay: code.relay, now });
  const old = liveHolding(carrier, w.original);
  pending(file, now, (s) => {
    s.issued[code.nonce] = { key: bytesToHex(enrolKey(code.secret)), i, n, name: name ?? null, did: w.did, original: w.original, old_pair: old ? pairOf(old) : null,
      relay: code.relay, exp: now + PENDING_TTL, attestation, issuer: me.genesis };
  });
  return { ...r, id: code.nonce, did: w.did, original: w.original };
}

/**
 * The machine, as its TEMPORARY identity: fetch the code (a short code is spent at once), keep the
 * enrolment, accept. The request goes once paired, here if the operator is online within `wait`,
 * else at a later complete(). temp: the temporary identity's file, kept with the entry.
 * → { status, did: the operator's DID as the code names it, contact?, id, long? }.
 */
export async function accept({ carrier, file, code: text, name, wait = 10, temp }) {
  const short = codeKind(text) === 'short', long = short ? await carrier.unpark(text) : text;
  try {
    const now = nowOf(carrier), code = readCode(long, now, short ? 'parked' : 'long');
    pending(file, now, (s) => { s.joining[code.nonce] = { key: bytesToHex(enrolKey(code.secret)), code_did: code.did, relay: code.relay, exp: now + PENDING_TTL, sent: false, temp: temp ?? null }; });
    const r = await carrier.accept(long, { name, wait });
    return { ...r, did: code.did, id: code.nonce, ...(short && { long }) };
  } catch (e) { throw short ? keepLong(e, long) : e; }
}

/**
 * Both sides: send the requests of pairings now complete, then read the inbox (until `until()` or
 * `wait` seconds) and act on enrolment messages.
 *   operator: keeper = { K, recovery } (the hot keeper root): requests are answered with the worker's
 *     identity; a worker that has paired is filed and its temporary DID forgotten.
 *   machine: temp = the temporary identity's file this carrier runs on; place(checked, { operator })
 *     writes the worker's file and pairs as it → { status, contact? }.
 * → { delivered: [{ id, name, temp, did }], placed: [{ id, name, did, original, … }], refused: [{ check, detail, from }],
 *     sent: [{ did }], rest: the batch without what was handled, offline? }
 */
export async function complete({ carrier, file, wait = 0, until = () => false, keeper = null, place = null, temp = null }) {
  if (keeper) checkKeeper(keeper);
  const out = { delivered: [], placed: [], refused: [], sent: [], rest: { messages: [], events: [], dropped: {} } };
  const end = Date.now() + wait * 1000;
  for (let first = true; ; first = false) {
    if (first && place) await sendRequests(carrier, file, temp, out, true);
    if (keeper) await settle(carrier, file, keeper, out);
    const left = Math.max(0, Math.ceil((end - Date.now()) / 1000));
    const batch = await carrier.inbox({ wait: Math.min(left, WAIT_STEP), paired: true });
    out.rest.events.push(...batch.events);
    for (const [k, n] of Object.entries(batch.dropped ?? {})) out.rest.dropped[k] = (out.rest.dropped[k] ?? 0) + n;
    for (const m of batch.messages) {
      if (m?.label === LABEL_ENROL && keeper) await onRequest(carrier, file, keeper, m, out);
      else if (m?.label === LABEL_IDENTITY && place && await onIdentity(carrier, file, temp, m, out, place)) continue;
      else out.rest.messages.push(m);
    }
    if (batch.offline !== undefined) { out.offline = batch.offline; out.lastError = carrier.lastError; break; }
    // A pairing this inbox completed sends its request now, not at the next run; a worker that
    // paired in this inbox is filed now.
    if (place && out.placed.length === 0) await sendRequests(carrier, file, temp, out, false);
    if (keeper) await settle(carrier, file, keeper, out);
    if (until(out) || Date.now() >= end) break;
  }
  return out;
}

// The machine: a request for each enrolment of this temporary identity whose pairing is complete
// and that has not sent one; at a first round, again for those sent before without an answer (the
// operator's inbox may have gone to another reader).
async function sendRequests(carrier, file, temp, out, first) {
  const todo = pending(file, nowOf(carrier), (s) => Object.entries(s.joining).filter(([, j]) => j.temp === temp && (!j.sent || first)));
  for (const [id, j] of todo) {
    const c = liveHolding(carrier, j.code_did);
    if (!c) continue;
    try {
      const r = await carrier.send(c.did, request(hexToBytes(j.key), pairOf(c)), { label: LABEL_ENROL });
      pending(file, nowOf(carrier), (s) => { if (s.joining[id]) s.joining[id].sent = true; });
      out.sent.push({ did: c.did, status: r.status });
    } catch (e) {
      out.refused.push({ check: e.check ?? 'error', detail: `the enrolment request to ${c.name} did not go (${e.message}): it goes at the next sigelo-agent enrol --finish`, from: c.did });
    }
  }
}

// The operator: a request from a contact. Answered only when its proof matches an enrolment this
// operator issued, over that contact's own pairing, and only when that contact is the DID that
// paired through the enrolment's code (the header's "The marker").
async function onRequest(carrier, file, keeper, m, out) {
  const now = nowOf(carrier), c = readStore(carrier).contacts[m.from];
  const who = `${m.name ?? m.from} (${m.from})`;
  if (!c || c.revoked || !c.pair_key) { out.refused.push({ check: 'enrol_contact', detail: `an enrolment request from ${who}, no live contact: ignored`, from: m.from }); return; }
  const pair = pairOf(c);
  // Who paired through each code, read before the pending file's lock (the carrier takes its own).
  const answered = Object.fromEntries(pending(file, now, (s) => Object.keys(s.issued)).map((id) => [id, carrier.answeredBy(id)]));
  const r = pending(file, now, (s) => {
    const hit = Object.entries(s.issued).find(([, e]) => matches(m.content, hexToBytes(e.key), pair));
    if (!hit) return { check: 'enrol_proof', detail: `${who} asked to be enrolled, but its request matches no enrolment code this operator issued in the last 24 hours (a plain contact, or an expired code): nothing sent` };
    const [id, e] = hit, by = answered[id] ?? null;
    if (!by) return { check: 'enrol_unpaired', detail: `${who} proved an enrolment code over its own pairing, but nobody has paired through that code yet (the machine pairs first): nothing sent` };
    if (by !== c.did) return { check: 'enrol_from', detail: `${who} proved an enrolment code over its own pairing, but ${by} paired through that code: only it is answered; nothing sent` };
    if (e.temp && e.temp !== c.did) return { check: 'enrol_used', detail: `${who} answered an enrolment that ${e.temp} took already: one code places one worker; nothing sent` };
    if (e.done) return { check: 'enrol_done', detail: `${who} asked again for worker ${e.i}, placed already: nothing sent` };
    e.temp = c.did;
    return { id, e };
  });
  if (r.check) { out.refused.push({ ...r, from: m.from }); return; }
  const { id, e } = r;
  try {
    // The worker's own invite, made once per enrolment: a repeated request gets the same.
    let invite = e.invite;
    if (!invite) {
      invite = (await carrier.invite({ name: e.name ?? undefined, ttl: Math.max(60, e.exp - now) })).code;
      pending(file, nowOf(carrier), (s) => { if (s.issued[id]) s.issued[id].invite = invite; });
    }
    const identity = workerIdentity({ K: keeper.K, i: e.i, n: e.n, recovery: keeper.recovery, attestation: e.attestation, issuer: e.issuer });
    if (didOf([identity.genesis, ...identity.rotations.map((x) => x.next_genesis)].at(-1)) !== e.did) fail('keeper', `worker ${e.i} derives to another DID than at enrol: the keeper root changed since (sigelo-agent keeper)`);
    const sent = await carrier.send(c.did, identityMessage(identity, invite, e.i), { label: LABEL_IDENTITY });
    out.delivered.push({ id, name: e.name, temp: c.did, did: e.did, status: sent.status });
  } catch (x) {
    if (!(x instanceof MsgError)) throw x;
    out.refused.push({ check: x.check, detail: `worker ${e.i} did not go to ${who} (${x.message}): it goes when the machine asks again (sigelo-agent enrol --finish there)`, from: m.from });
  }
}

// The operator: each enrolment whose worker has paired with this operator since it was issued
// (a new pairing key): filed own by the attestation, its temporary DID forgotten.
async function settle(carrier, file, keeper, out) {
  const todo = pending(file, nowOf(carrier), (s) => Object.entries(s.issued).filter(([, e]) => e.temp && !e.done));
  for (const [id, e] of todo) {
    const c = liveHolding(carrier, e.original);
    if (!c || pairOf(c) === e.old_pair) continue;
    const identity = workerIdentity({ K: keeper.K, i: e.i, n: e.n, recovery: keeper.recovery, attestation: e.attestation, issuer: e.issuer });
    const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: identity.genesis, rotations: identity.rotations, bindings: [], attestations: identity.attestations, issuers: identity.issuers };
    const seen = carrier.observe(bundle), tier = seen?.tier ?? null, ours = seen?.ours ?? null;
    let released = false;
    try { released = (await carrier.forget(e.temp)).released; } catch (x) { if (!(x instanceof MsgError) || x.check !== 'not_contact') throw x; }
    pending(file, nowOf(carrier), (s) => { if (s.issued[id]) s.issued[id].done = nowOf(carrier); });
    out.placed.push({ id, name: c.name, did: c.current_did, original: c.did, i: e.i, n: e.n, ours, tier, temp: e.temp, released, exp: e.attestation.body.exp });
  }
}

// The machine: an identity message. Taken only from the contact paired through an enrolment code
// this temporary identity answered; → true when handled (placed or refused), false to leave it in
// the inbox.
async function onIdentity(carrier, file, temp, m, out, place) {
  const now = nowOf(carrier), c = readStore(carrier).contacts[m.from];
  const s = pending(file, now, (x) => x);
  const hit = c && !c.revoked ? Object.entries(s.joining).find(([, j]) => j.temp === temp && c.chain.includes(j.code_did)) : undefined;
  if (!hit) {
    out.refused.push({ check: 'enrol_from', detail: `a worker identity from ${m.name ?? m.from} (${m.from}), not the DID this machine enrolled with through a code: not taken`, from: m.from });
    return false;
  }
  const [id, j] = hit;
  try {
    const x = checkIdentity(m.content, { operator: c, relay: j.relay, now }), tempDid = self(carrier, now).original;
    const r = await place(x, { operator: c, id });
    // The temporary identity is done: the operator is forgotten on it, its mailboxes given up.
    let released = false, offline;
    try { ({ released, offline } = await carrier.forget(c.did)); } catch (e) { if (!(e instanceof MsgError)) throw e; offline = e.message; }
    pending(file, nowOf(carrier), (y) => { delete y.joining[id]; });
    out.placed.push({ id, did: x.did, original: x.original, worker: x.worker, exp: x.exp, operator: c.current_did, name: c.name, status: r?.status ?? null, contact: r?.contact ?? null, temp: tempDid, temp_file: temp, released, ...(offline && { temp_offline: offline }) });
  } catch (e) {
    if (!(e instanceof MsgError)) throw e;
    out.refused.push({ check: e.check, detail: `the worker identity from ${c.name} was not taken: ${e.message.startsWith(`${e.check}: `) ? e.message.slice(e.check.length + 2) : e.message}`, from: m.from });
  }
  return true;
}
