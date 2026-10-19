// SPDX-License-Identifier: MIT
// Enrolment (enrol.mjs, contract sigelo-enrol/1): the worker's derivation from a fixed keeper root
// (keys.ts agentIdentitySeed, a pinned DID), the marker, the identity message and its checks; then,
// with the relay checkout beside contact/ (SIGELO_RELAY_DIR, else ../relay), the flow on a loopback
// relay: issue → a temporary identity joins → the worker's identity travels end to end → the
// machine places it and pairs as the worker → the operator files it own and forgets the temporary
// DID; the code a second time; a request no enrolment matches; an identity from another DID; the
// same flow lazily, one run at a time on each side.
//   node contact/test-enrol.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalize, decodeKey, did as didOf, keygen, verify } from 'sigelo';
import { agentIdentitySeed, identitySeed, keeperRoot, recoveryCommitment } from 'sigelo/dist/keys.js';
import { makeInvite } from './invite.mjs';
import {
  DAY, ENROL_V, LABEL_ENROL, LABEL_IDENTITY, OPERATOR_CTX, OPERATOR_DAYS, PENDING_TTL, PINNED_CREATED, TYP_IDENTITY, TYP_REQUEST, accept as joinEnrol, checkIdentity, complete,
  enrolKey, enrolPath, identityMessage, IDENTITY_PATH, issue, matches, operatorAttestation, operatorChain, operatorIdentity, pending, proofOf, request, workerChain, workerGenesis, workerIdentity,
} from './enrol.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};
const CREATED = '2026-10-01T00:00:00Z';
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-enrol-test/0 ${l}`).digest());
const ident = (label) => keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
const hex = (b) => Buffer.from(b).toString('hex');

// The fixed root of these tests: S, the operator's keeper root K = K_1, the seed's recovery commitment.
const S = seed('root S'), K = keeperRoot(S, 1), RECOVERY = recoveryCommitment(S), keeper = { K, recovery: RECOVERY };
// Pinned: worker 0, rotation 0, under K_1 of S = sha256("sigelo-enrol-test/0 root S"). A change here
// means every enrolled worker's DID moved: the 25 words would no longer bring them back.
const WORKER_0 = 'did:sigelo:zETjBH7kSdVN2L6R2Y3iGyEGVmfnqZeTyNTZBKtBwsLQA';
// Pinned: the operator's own identity, the root identity of the same S at rotation 0 (MONERO.md §2).
const OPERATOR_0 = 'did:sigelo:z9VfjcNZXn1QfpRguA1uZTZYMDSffUZv4VAB69E5aYGDy';

// ================================================================ derivation
{
  const w = workerChain(K, 0, 0, RECOVERY), again = workerChain(K, 0, 0, RECOVERY);
  ok(hex(w.secret) === hex(agentIdentitySeed(K, 0, 0)), 'worker 0: its key is keys.ts agentIdentitySeed(K, 0, 0)');
  ok(w.genesis.key === keygen({ seed: agentIdentitySeed(K, 0, 0), recovery: RECOVERY }).key, 'worker 0: the genesis key is that seed\'s public key');
  ok(canonicalize(w.genesis) === canonicalize(again.genesis) && w.did === again.did, 'deterministic: the same genesis, the same DID, every call');
  ok(w.genesis.recovery === RECOVERY && w.genesis.created === PINNED_CREATED, 'the genesis commits to the seed\'s recovery key; created pinned');
  ok(w.genesis.nonce === keygen({ seed: new Uint8Array(32), recovery: RECOVERY, nonce: createHash('sha256').update(decodeKey(w.genesis.key)).digest().subarray(0, 16) }).genesis.nonce,
    'the nonce: the first 16 bytes of SHA-256 of the raw public key (SPEC §4)');
  ok(w.did === WORKER_0, `worker 0's DID is pinned (${w.did})`);
  ok(workerChain(K, 1, 0, RECOVERY).did !== w.did && workerChain(keeperRoot(S, 2), 0, 0, RECOVERY).did !== w.did, 'another index, or another keeper root: another DID');
  const r1 = workerChain(K, 0, 1, RECOVERY);
  const v = verify({ v: 'sigelo/0', typ: 'bundle', genesis: r1.genesis, rotations: r1.rotations, bindings: [], attestations: [], issuers: [] }, Math.floor(Date.now() / 1000));
  ok(v.did === workerGenesis(K, 0, 1, RECOVERY).did && v.chain[0] === w.did && v.chain.length === 2, 'rotation 1: the chain from worker 0\'s genesis to agentIdentitySeed(K, 0, 1)\'s');
  ok(r1.rotations[0].body.iat === 0 && r1.rotations[0].body.reason === 'voluntary' && canonicalize(r1.rotations) === canonicalize(workerChain(K, 0, 1, RECOVERY).rotations),
    'the rotation is voluntary, iat pinned 0: re-derived, byte for byte the same (no fork)');
  ok(checkOf(() => workerChain(K, 0, 0, 'sha256:xyz')) === 'keeper', 'a malformed recovery commitment: keeper');
}
{
  const o = operatorChain(S, 0), f = operatorIdentity(S, 1);
  ok(hex(o.secret) === hex(identitySeed(S, 0)) && o.genesis.recovery === RECOVERY && o.genesis.created === PINNED_CREATED, 'operator: its key is keys.ts identitySeed(S, 0), its genesis pinned, committing to the seed\'s recovery key');
  ok(o.did === OPERATOR_0 && operatorChain(S, 0).did === o.did, `operator: the root identity's DID is pinned (${o.did})`);
  ok(o.did !== workerChain(K, 0, 0, RECOVERY).did && o.did !== workerChain(keeperRoot(S, 0), 0, 0, RECOVERY).did, 'operator: not any worker');
  const v = verify({ v: 'sigelo/0', typ: 'bundle', genesis: f.genesis, rotations: f.rotations, bindings: [], attestations: [], issuers: [] }, Math.floor(Date.now() / 1000));
  ok(v.chain[0] === OPERATOR_0 && v.did === operatorChain(S, 1).did && f.secret === hex(identitySeed(S, 1)) && f.rotations[0].body.iat === 0,
    'operator rotation 1: the chain from its genesis to identitySeed(S, 1)\'s, iat pinned 0');
  ok(f.derived.n === 1 && f.derived.path === `${IDENTITY_PATH}/1` && IDENTITY_PATH === 'sigelo/v1/identity/ed25519' && !JSON.stringify(f).includes(hex(S)), 'operatorIdentity: marked derived {path, n}, no S in it');
}

// ================================================================ the marker and the messages
{
  const secret = seed('invite secret'), key = enrolKey(secret), pair = '0123456789abcdef0123456789abcdef', other = 'f'.repeat(32);
  ok(key.length === 32 && hex(key) !== hex(enrolKey(seed('another'))), 'enrolKey: 32 bytes, one per invite secret');
  ok(checkOf(() => enrolKey(new Uint8Array(31))) === 'enrol', 'enrolKey: a secret of other than 32 bytes is refused');
  const req = request(key, pair);
  ok(req.v === ENROL_V && req.typ === TYP_REQUEST && /^[0-9a-f]{64}$/.test(req.proof) && Object.keys(req).length === 3, 'request: {v, typ, proof}, the proof 64 hex digits');
  ok(matches(req, key, pair) && !matches(req, key, other) && !matches(req, enrolKey(seed('another')), pair), 'the request matches its key on its pairing only');
  ok(!matches({ ...req, proof: req.proof.toUpperCase() }, key, pair) && !matches({ ...req, typ: 'x' }, key, pair) && !matches('text', key, pair) && !matches(null, key, pair), 'any other shape does not match');
  ok(proofOf(key, pair) === req.proof && checkOf(() => proofOf(key, 'xyz')) === 'pair', 'proofOf: the pair id must be 32 hex digits');

  const op = ident('operator'), now = Date.parse('2026-10-14T12:00:00Z') / 1000, w = workerChain(K, 0, 0, RECOVERY);
  const att = operatorAttestation({ secret: op.secret, iss: op.did, sub: w.original, relay: 'relay.test', now });
  ok(att.body.ctx === OPERATOR_CTX && att.body.exp - att.body.iat === OPERATOR_DAYS * DAY && checkOf(() => operatorAttestation({ secret: op.secret, iss: op.did, sub: w.original, relay: 'relay.test', now, days: 91 })) === 'enrol',
    'operatorAttestation: 90 days at most');
  const id = workerIdentity({ K, i: 0, n: 0, recovery: RECOVERY, attestation: att, issuer: op.genesis });
  const invite = makeInvite({ did: op.did, relay: 'relay.test', now }).text;
  const contact = { did: op.did, current_did: op.did, current_key: op.genesis.key, chain: [op.did] };
  const msg = identityMessage(id, invite), opts = { operator: contact, relay: 'relay.test', now };
  ok(msg.typ === TYP_IDENTITY && msg.v === ENROL_V, 'the identity message');
  const good = checkIdentity(msg, opts);
  ok(good.did === w.did && good.original === w.did && good.identity.secret === hex(agentIdentitySeed(K, 0, 0)) && good.invite === invite, 'checkIdentity: the operator\'s, for worker 0: taken');
  const r = verify({ v: 'sigelo/0', typ: 'bundle', genesis: good.identity.genesis, rotations: [], bindings: [], attestations: good.identity.attestations, issuers: good.identity.issuers }, now + 60);
  ok(r.attestations[op.did]?.[0]?.ctx === OPERATOR_CTX && r.attestations[op.did][0].sub === w.did, 'offline: the worker\'s bundle verifies the operator attestation');
  const mallory = ident('mallory');
  ok(checkOf(() => checkIdentity(identityMessage({ ...id, issuers: [mallory.genesis], attestations: [operatorAttestation({ secret: mallory.secret, iss: mallory.did, sub: w.original, relay: 'relay.test', now })] }, invite), opts)) === 'enrol_issuer',
    'attested by another DID than the contact enrolled with: enrol_issuer');
  ok(checkOf(() => checkIdentity(identityMessage({ ...id, secret: hex(seed('another key')) }, invite), opts)) === 'enrol_identity', 'a secret that is not the chain\'s current key: enrol_identity');
  ok(checkOf(() => checkIdentity(identityMessage({ ...id, attestations: [operatorAttestation({ secret: op.secret, iss: op.did, sub: mallory.did, relay: 'relay.test', now })] }, invite), opts)) === 'enrol_sig',
    'an attestation for another subject: it does not verify in the worker\'s bundle (enrol_sig)');
  ok(checkOf(() => checkIdentity(msg, { ...opts, relay: 'relay.other' })) === 'enrol_shape', 'naming another relay: enrol_shape');
  ok(checkOf(() => checkIdentity(identityMessage(id, makeInvite({ did: mallory.did, relay: 'relay.test', now }).text), opts)) === 'enrol_invite', 'an invite from another DID: enrol_invite');
  ok(checkOf(() => checkIdentity(identityMessage({ ...id, extra: 1 }, invite), opts)) === 'enrol_message' && checkOf(() => checkIdentity({ v: ENROL_V, typ: TYP_REQUEST }, opts)) === 'enrol_message',
    'another shape: enrol_message');

  // The pending file: 0600, entries gone after 24 hours.
  const d = mkdtempSync(join(tmpdir(), 'sigelo-enrol-unit-')), f = enrolPath(join(d, 'me.local.json'));
  try {
    ok(f === join(d, 'me.local.enrol.json'), 'enrolPath: x.json → x.enrol.json');
    pending(f, now, (s) => { s.issued.a = { key: '00', exp: now + PENDING_TTL }; s.joining.b = { key: '00', exp: now + 10 }; });
    ok((statSync(f).mode & 0o777) === 0o600 || process.platform === 'win32', 'the pending file is 0600');
    ok(pending(f, now + 11, (s) => Object.keys(s.joining).length === 0 && Object.keys(s.issued).length === 1), 'an entry past its exp is purged');
    ok(pending(f, now + PENDING_TTL, (s) => Object.keys(s.issued).length === 0), 'and an issued enrolment after 24 hours');
    writeFileSync(f, '{"v":"sigelo-enrol/0","issued":{},"joining":{}}');
    ok(checkOf(() => pending(f, now)) === 'enrol_file', 'a file of the retired fresh-key enrolment: enrol_file');
  } finally { rmSync(d, { recursive: true, force: true }); }
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs')) || !existsSync(join(RELAY_DIR, 'node_modules'))) {
  report();
  console.log(`ALL PASS (${count}): the unit part; SKIP the flow, no relay checkout with its dependencies beside contact/: set SIGELO_RELAY_DIR`);
  process.exit(0);
}

// ================================================================ the flow, on a loopback relay
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, pathsFor } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 420 s (${count} checks so far)`); process.exit(1); }, 420000).unref();

const HOST = 'relay.test';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-enrol-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => Math.floor(Date.now() / 1000), diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
// An agent in memory: its identity file's content (sigelo-agent's Store) and a carrier on it.
function agent(label, store) {
  const k = store ? null : ident(label);
  const a = { label, s: store ?? { v: 'sigelo/0', secret: hex(k.secret), genesis: k.genesis, rotations: [], attestations: [], issuers: [] } };
  a.did = didOf(a.s.genesis);
  a.carrier = new Carrier({ identity: () => ({ secret: Buffer.from(a.s.secret, 'hex'), bundle: { v: 'sigelo/0', typ: 'bundle', genesis: a.s.genesis, rotations: a.s.rotations, bindings: [], attestations: a.s.attestations, issuers: a.s.issuers } }),
    ...pathsFor(join(dir, `${label}.local.json`)), relay: HOST, endpoints, keep: true, backoff: [100, 400], retentionDays: 7 });
  return a;
}
const fileOf = (a) => enrolPath(join(dir, `${a.label}.local.json`));
const storeOf = (a) => JSON.parse(readFileSync(pathsFor(join(dir, `${a.label}.local.json`)).store, 'utf8'));
const failure = async (f) => { try { await f(); return { check: 'accepted', message: 'accepted' }; } catch (e) { return e; } };
// The machine's place(): the worker's file written (here: in memory), then the worker pairs with the
// operator through the invite the identity came with.
const workers = {};
const placer = (label, wait = 20) => async (x, { operator }) => {
  const w = workers[label] = agent(label, x.identity);
  return w.carrier.accept(x.invite, { name: operator.name, wait });
};
try {
  const owner = agent('owner'), vps = agent('vps-temp'), eve = agent('eve'), mallory = agent('mallory');
  const co = owner.carrier;

  // Live: the operator issues and waits; the machine's temporary identity joins and waits.
  const inv = await issue({ carrier: co, file: fileOf(owner), i: 0, n: 0, name: 'vps', keeper });
  const w0 = workerChain(K, 0, 0, RECOVERY);
  ok(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/.test(inv.short ?? '') && inv.did === w0.did, `issue: a short code (${inv.short}) for worker 0 (${inv.did})`);
  const e0 = pending(fileOf(owner), Math.floor(Date.now() / 1000), (s) => s.issued[inv.id]);
  ok(e0.i === 0 && e0.n === 0 && e0.attestation.body.sub === w0.original && !JSON.stringify(e0).includes(hex(w0.secret)), 'the pending enrolment: index, rotation, the attestation signed now, and no secret');
  const opDone = complete({ carrier: co, file: fileOf(owner), keeper, wait: 90, until: (o) => o.placed.some((x) => x.id === inv.id) });
  const j = await joinEnrol({ carrier: vps.carrier, file: fileOf(vps), code: inv.short.toLowerCase(), name: 'owner', wait: 20, temp: 'vps-temp' });
  ok(j.status === 'connected' && j.did === owner.did, `join: the temporary identity paired with the operator (${j.status})`);
  const mc = await complete({ carrier: vps.carrier, file: fileOf(vps), temp: 'vps-temp', wait: 90, place: placer('vps'), until: (o) => o.placed.length > 0 });
  const op = await opDone;
  ok(mc.placed.length === 1 && mc.placed[0].did === w0.did && mc.placed[0].status === 'connected' && mc.refused.length === 0, `the machine placed worker 0 and paired as it (${JSON.stringify(mc.placed)} ${JSON.stringify(mc.refused)})`);
  ok(op.delivered.length === 1 && op.delivered[0].temp === vps.did && op.placed.length === 1 && op.placed[0].did === w0.did && op.placed[0].tier === 'own' && op.refused.length === 0,
    `the operator sent worker 0 once to the temporary DID, then filed the worker own (${JSON.stringify(op.placed)} ${JSON.stringify(op.refused)})`);
  const w = workers.vps;
  ok(w.did === w0.did && w.s.secret === hex(agentIdentitySeed(K, 0, 0)), 'the machine runs as the derived DID, with the derived key');
  const vb = verify({ v: 'sigelo/0', typ: 'bundle', genesis: w.s.genesis, rotations: w.s.rotations, bindings: [], attestations: w.s.attestations, issuers: w.s.issuers }, Math.floor(Date.now() / 1000));
  ok(vb.attestations[owner.did]?.[0]?.ctx === OPERATOR_CTX && vb.attestations[owner.did][0].sub === w0.did, 'offline: the worker\'s bundle verifies the operator attestation');
  const os = storeOf(owner);
  ok(os.contacts[w0.did] && !os.contacts[w0.did].revoked && os.contacts[w0.did].tier === 'own' && os.contacts[w0.did].enrolled === undefined && os.contacts[w0.did].name === 'vps',
    'the operator\'s store: the worker, own by its attestation (no enrolled flag), named');
  ok(os.contacts[vps.did]?.revoked === true && os.contacts[vps.did].pair_key === null, 'the operator forgot the temporary DID');
  ok(storeOf(vps).contacts[owner.did]?.revoked === true, 'the temporary identity forgot the operator (its mailboxes given up)');
  const ws = storeOf(w);
  ok(Object.keys(ws.contacts).join() === owner.did && ws.contacts[owner.did].tier === 'own', 'the worker\'s contacts start with the operator, own');
  ok(pending(fileOf(vps), Math.floor(Date.now() / 1000), (s) => Object.keys(s.joining).length === 0), 'the machine\'s pending enrolment is gone');

  // The code a second time: the relay gave it once.
  const again = await failure(() => joinEnrol({ carrier: eve.carrier, file: fileOf(eve), code: inv.short, wait: 2, temp: 'eve' }));
  ok(again.check === 'park_unknown', `the enrolment code a second time: park_unknown (${again.message})`);

  // A request no enrolment matches: refused, nothing sent.
  const { pairId, unhex } = await import('./kdf.mjs');
  const pairWith = (a, peer) => pairId(unhex(storeOf(a).contacts[peer.did].pair_key, 32, 'k'));
  const inv2 = await issue({ carrier: co, file: fileOf(owner), i: 1, n: 0, name: 'eve-box', keeper });
  await co.start();
  const pa = await eve.carrier.accept(inv2.short, { name: 'owner', wait: 20 });
  await co.stop();
  const bad = complete({ carrier: co, file: fileOf(owner), keeper, wait: 30, until: (o) => o.refused.length > 0 });
  await eve.carrier.send(owner.did, request(enrolKey(seed('no such code')), pairWith(eve, owner)), { label: LABEL_ENROL });
  const bd = await bad;
  ok(pa.status === 'connected' && bd.delivered.length === 0 && bd.refused.some((x) => x.check === 'enrol_proof'), `a plain accept, then a request no enrolment matches: enrol_proof, nothing sent (${JSON.stringify(bd.refused)})`);

  // A worker identity from a DID the machine did not enrol with: not taken, left in the inbox.
  const mi = await mallory.carrier.invite({ name: 'vps2', short: true });
  const vps2 = agent('vps2-temp');
  pending(fileOf(vps2), Math.floor(Date.now() / 1000), (s) => { s.joining.x = { key: '00'.repeat(32), code_did: owner.did, relay: HOST, exp: Math.floor(Date.now() / 1000) + 600, sent: true, temp: 'vps2-temp' }; });
  await mallory.carrier.start();
  await vps2.carrier.accept(mi.short, { name: 'mallory', wait: 20 });
  await mallory.carrier.stop();
  const fake = workerIdentity({ K: seed('mallory K'), i: 0, n: 0, recovery: RECOVERY, attestation: operatorAttestation({ secret: Buffer.from(mallory.s.secret, 'hex'), iss: mallory.did, sub: workerChain(seed('mallory K'), 0, 0, RECOVERY).original, relay: HOST, now: Math.floor(Date.now() / 1000) }), issuer: mallory.s.genesis });
  await mallory.carrier.send(vps2.did, identityMessage(fake, (await mallory.carrier.invite({ name: 'w' })).code), { label: LABEL_IDENTITY });
  const wr = await complete({ carrier: vps2.carrier, file: fileOf(vps2), temp: 'vps2-temp', wait: 20, place: placer('nope'), until: (o) => o.refused.length > 0 });
  ok(wr.placed.length === 0 && wr.refused.some((x) => x.check === 'enrol_from' && x.from === mallory.did) && !workers.nope, `an identity from a DID the machine did not enrol with: enrol_from, not placed (${JSON.stringify(wr.refused)})`);
  ok(wr.rest.messages.some((m) => m.label === LABEL_IDENTITY && m.from === mallory.did), 'it stays in the inbox, as data');

  // Lazily, nobody waiting: each side's next run does its part. Worker 2.
  const inv3 = await issue({ carrier: co, file: fileOf(owner), i: 2, n: 0, name: 'lazy', keeper });
  const lz = agent('lazy-temp');
  await joinEnrol({ carrier: lz.carrier, file: fileOf(lz), code: inv3.short, name: 'owner', wait: 1, temp: 'lazy-temp' }).catch(() => {});
  const m = (o) => ({ carrier: lz.carrier, file: fileOf(lz), temp: 'lazy-temp', place: placer('lazy', 1), ...o });
  const l1 = await complete({ carrier: co, file: fileOf(owner), keeper });            // the operator pairs
  const l2 = await complete(m({ wait: 10, until: (o) => o.sent.length > 0 }));        // the reply read, the request sent
  const l3 = await complete({ carrier: co, file: fileOf(owner), keeper, wait: 10, until: (o) => o.delivered.length > 0 });   // the identity sent
  const l4 = await complete(m({ wait: 10, until: (o) => o.placed.length > 0 }));       // placed; the worker's answer at the relay
  const l5 = await complete({ carrier: co, file: fileOf(owner), keeper, wait: 10, until: (o) => o.placed.length > 0 });      // the worker paired: filed
  const l6 = await workers.lazy.carrier.inbox({ wait: 10 });                           // the worker reads the reply
  const w2 = workerChain(K, 2, 0, RECOVERY);
  ok(l1.rest.events.some((e) => e.type === 'paired' && e.did === lz.did) && l2.sent.length === 1 && l3.delivered[0]?.did === w2.did && l4.placed[0]?.did === w2.did
    && l5.placed[0]?.did === w2.did && l5.placed[0].tier === 'own' && l6.events.some((e) => e.type === 'paired' && e.did === owner.did),
    `lazily, no side waiting: paired, request, identity, placed, filed, paired as the worker; one run each (${JSON.stringify([l1.refused, l2.refused, l3.refused, l4.refused, l5.refused])})`);
  // An existing contact that learns an enrolment code's secret (the relay parks the long code; a
  // chat shows it) proves it over its OWN pairing, without using the code. The worker goes only to
  // the DID that paired through the code: before anyone has, enrol_unpaired; after, enrol_from.
  const { readCode } = await import('./carrier.mjs');
  const alice = agent('alice'), alicePeer = await co.invite({ name: 'alice' });
  await co.start();
  const pal = await alice.carrier.accept(alicePeer.code, { name: 'owner', wait: 20 });
  await co.stop();
  const inv4 = await issue({ carrier: co, file: fileOf(owner), i: 3, n: 0, name: 'stolen', keeper });
  const stolenKey = enrolKey(readCode(inv4.code, Math.floor(Date.now() / 1000)).secret);
  await alice.carrier.send(owner.did, request(stolenKey, pairWith(alice, owner)), { label: LABEL_ENROL });
  const st1 = await complete({ carrier: co, file: fileOf(owner), keeper, wait: 30, until: (o) => o.delivered.length > 0 || o.refused.length > 0 });
  const ai = await alice.carrier.inbox({ wait: 3 });
  ok(pal.status === 'connected' && st1.delivered.length === 0 && st1.refused.some((x) => x.check === 'enrol_unpaired' && x.from === alice.did) && !ai.messages.some((x) => x.label === LABEL_IDENTITY),
    `a contact proving the code over its own pairing before anyone paired through it: enrol_unpaired, no identity (${JSON.stringify(st1.delivered)} ${JSON.stringify(st1.refused)})`);
  // The real machine then pairs through the code and is placed; alice asking again is enrol_from.
  const w3 = workerChain(K, 3, 0, RECOVERY), real = agent('real-temp');
  const opReal = complete({ carrier: co, file: fileOf(owner), keeper, wait: 90, until: (o) => o.placed.some((x) => x.id === inv4.id) && o.refused.some((x) => x.from === alice.did) });
  const jr = await joinEnrol({ carrier: real.carrier, file: fileOf(real), code: inv4.short, name: 'owner', wait: 20, temp: 'real-temp' });
  await alice.carrier.send(owner.did, request(stolenKey, pairWith(alice, owner)), { label: LABEL_ENROL });
  const mr = await complete({ carrier: real.carrier, file: fileOf(real), temp: 'real-temp', wait: 90, place: placer('real'), until: (o) => o.placed.length > 0 });
  const orr = await opReal, ai2 = await alice.carrier.inbox({ wait: 3 });
  ok(jr.status === 'connected' && mr.placed[0]?.did === w3.did && orr.delivered.length === 1 && orr.delivered[0].temp === real.did && orr.placed[0]?.did === w3.did
    && orr.refused.some((x) => x.check === 'enrol_from' && x.from === alice.did) && !ai2.messages.some((x) => x.label === LABEL_IDENTITY),
    `the machine that paired through the code is placed; the contact asking after it: enrol_from, no identity (${JSON.stringify(orr.delivered)} ${JSON.stringify(orr.refused)} ${JSON.stringify(mr.refused)})`);

  // The pairing read by a plain inbox (its paired event gone to another reader): the operator still
  // knows who paired through the code, from the carrier's state, and answers that DID.
  const inv5 = await issue({ carrier: co, file: fileOf(owner), i: 4, n: 0, name: 'plain', keeper });
  const pl = agent('plain-temp'), w4 = workerChain(K, 4, 0, RECOVERY);
  await joinEnrol({ carrier: pl.carrier, file: fileOf(pl), code: inv5.short, name: 'owner', wait: 1, temp: 'plain-temp' }).catch(() => {});
  const pi = await co.inbox({ wait: 10, paired: true });
  const p2 = await complete({ carrier: pl.carrier, file: fileOf(pl), temp: 'plain-temp', place: placer('plain', 1), wait: 10, until: (o) => o.sent.length > 0 });
  const p3 = await complete({ carrier: co, file: fileOf(owner), keeper, wait: 10, until: (o) => o.delivered.length > 0 || o.refused.length > 0 });
  ok(pi.events.some((e) => e.type === 'paired' && e.did === pl.did && e.invite === inv5.id) && p2.sent.length === 1 && p3.delivered[0]?.temp === pl.did && p3.delivered[0].did === w4.did,
    `paired in a plain inbox (the event names the invite nonce only), then the request: answered (${JSON.stringify(p3.refused)})`);
  ok(!JSON.stringify(pi.events).includes(hex(readCode(inv5.code, Math.floor(Date.now() / 1000)).secret)), 'the paired event carries no invite secret');
  for (const a of [alice, real, pl]) await a.carrier.stop();
  for (const a of [owner, vps, eve, mallory, vps2, lz, ...Object.values(workers)]) await a.carrier.stop();
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
report();
console.log(`ALL PASS (${count})`);
