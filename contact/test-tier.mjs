// SPDX-License-Identifier: MIT
// Contact tiers (store.mjs "Tiers", carrier.mjs "Operator hints"): the store part first (own by an
// operator attestation from this identity or its operators, friend by default, the owner's choice
// kept through a re-pair, a merge and a rename, refusals by name); then, with the relay checkout
// beside contact/ (SIGELO_RELAY_DIR, else ../relay), on a loopback relay: two agents run by one
// operator find each other own, the operator and its agent too, a contact who knows none of the
// operators stays friend and learns nothing, accept with a tier, and inbox / peek / take by tier,
// in a session and without one (local).
//   node contact/test-tier.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { attest, keygen, rotate, verify } from 'sigelo';
import { Contacts, OPERATOR_CTX, TIERS } from './store.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};

const CREATED = '2026-10-01T00:00:00Z', DAY = 86400;
let now = Date.parse('2026-10-14T12:00:00Z') / 1000;
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-tier-test/0 ${l}`).digest());
function agent(label) {
  const k = keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, did: k.did, secret: k.secret, genesis: k.genesis, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
// The operator attestation the UI signs into its agent's file (contact/enrol.mjs operatorAttestation; the page signs it at Enrol, /api/agents/enrol).
const operate = (op, a, days = 90, iat = now - 60) => {
  a.bundle.attestations.push(attest({ secret: op.secret, iss: op.did, sub: a.did, iat, exp: iat + days * DAY, ctx: OPERATOR_CTX, admission: 'invite', admission_by: op.did, claims: { relay: 'relay.test' } }));
  if (!a.bundle.issuers.some((g) => g === op.genesis)) a.bundle.issuers.push(op.genesis);
};
const chainOnly = (a) => ({ ...a.bundle, attestations: [], issuers: [] });

// ================================================================ the store
{
  const dir = mkdtempSync(join(tmpdir(), 'sigelo-tier-store-'));
  try {
    const H = agent('store human'), A = agent('store agent'), F = agent('store friend'), S = agent('store sibling');
    ok(TIERS.join() === 'own,friend,quiet' && OPERATOR_CTX === 'sigelo-relay/operator', 'TIERS own, friend, quiet; the operator attestation\'s ctx');
    // H's store: mine is H's chain.
    const hs = new Contacts(join(dir, 'h.json'), H.did, { mine: () => ({ chain: [H.did], operators: [] }) });
    const key = (n) => n.toString(16).padStart(64, '0');
    hs.admit(chainOnly(F), verify(chainOnly(F), now), 'friend', { relay: 'relay.test', pair_key: key(1) }, now);
    const f0 = hs.load().s.contacts[F.did];
    ok(hs.tierOf(f0, now) === 'friend' && f0.tier === 'friend' && f0.tier_by === 'auto', 'a contact with no operator attestation: friend, written as auto');
    operate(H, A);
    hs.admit(A.bundle, verify(A.bundle, now), 'agent', { relay: 'relay.test', pair_key: key(2) }, now);
    const a0 = hs.load().s.contacts[A.did];
    ok(a0.tier === 'own' && a0.operator_exp === now - 60 + 90 * DAY, 'admit: a bundle carrying my unexpired operator attestation → own, until it expires');
    ok(hs.tierOf(a0, now + 91 * DAY) === 'friend', 'recomputed on read: once the attestation expired, friend');
    // The same agent seen later (observe): a pairing carries chains only.
    hs.admit(chainOnly(S), verify(chainOnly(S), now), 'sibling', { relay: 'relay.test', pair_key: key(3) }, now);
    ok(hs.tiers(now).get(S.did) === 'friend', 'paired from its chain only: friend');
    operate(H, S);
    ok(hs.observe(S.did, verify(S.bundle, now), now) === 'own' && hs.load().s.contacts[S.did].tier === 'own', 'observe its bundle with my attestation → own, written');
    const W = agent('store world'); operate(W, F);
    ok(hs.observe(F.did, verify(F.bundle, now), now) === 'friend', 'observe an operator attestation from someone else: still friend');
    ok(checkOf(() => hs.observe(F.did, verify(A.bundle, now), now)) === 'original_did', 'observe another contact\'s bundle under this one: original_did');
    // The owner's choice: by name or DID, validated, kept.
    ok(JSON.stringify(hs.setTier('friend', 'quiet', now)) === JSON.stringify({ did: F.did, name: 'friend', tier: 'quiet', ours: false }), 'setTier by name → {did, name, tier, ours}');
    ok(hs.setTier(A.did, 'friend', now).tier === 'friend' && hs.tierOf(hs.load().s.contacts[A.did], now) === 'friend', 'setTier own → friend by DID: the choice beats the attestation');
    ok(hs.oursOf(hs.load().s.contacts[A.did], now) && !hs.oursOf(hs.load().s.contacts[F.did], now), 'and it stays ours (the attestation), friend by choice; a friend is not ours');
    // presetTier: the owner's tier for a DID not yet a contact, filed by the admit that makes it one.
    const P = agent('store preset'); operate(H, P);
    ok(JSON.stringify(hs.presetTier(P.did, 'friend', now)) === JSON.stringify({ did: P.did, tier: 'friend', preset: true }) && checkOf(() => hs.presetTier(P.did, 'vip', now)) === 'tier', 'presetTier before the pairing: kept; an unknown tier: tier');
    hs.admit(P.bundle, verify(P.bundle, now), 'p', { relay: 'relay.test', pair_key: key(13) }, now);
    const p0 = hs.load().s.contacts[P.did];
    ok(p0.tier === 'friend' && p0.tier_by === 'owner' && hs.oursOf(p0, now) && hs.s.preset[P.did] === undefined, 'admitted with my attestation: ours, friend by the owner; the preset spent');
    ok(hs.presetTier(P.did, 'quiet', now).preset === false && hs.tiers(now).get(P.did) === 'quiet', 'presetTier on a contact: set at once');
    ok(checkOf(() => hs.setTier('friend', 'vip', now)) === 'tier', 'setTier to an unknown tier: tier');
    ok(checkOf(() => hs.setTier('nobody', 'quiet', now)) === 'not_contact', 'setTier of no contact: not_contact');
    ok(checkOf(() => hs.setTier('', 'quiet', now)) === 'not_contact', 'setTier of an empty name: not_contact');
    // Kept through a re-pair (admit again, a new pair_key), a merge (admit, fields without tier) and a rename.
    hs.admit(chainOnly(F), verify(chainOnly(F), now), 'other name', { relay: 'relay.test', pair_key: key(9) }, now);
    const f1 = hs.load().s.contacts[F.did];
    ok(f1.tier === 'quiet' && f1.tier_by === 'owner' && f1.pair_key === key(9) && f1.name === 'friend', 're-pair: the tier the owner chose stays (and the name)');
    f1.name = 'renamed'; f1.re_pair = 'contact_recovery'; hs.save();
    hs.admit(chainOnly(F), verify(chainOnly(F), now), null, { relay: 'relay.test', pair_key: key(10) }, now);
    ok(hs.tiers(now).get(F.did) === 'quiet' && hs.load().s.contacts[F.did].re_pair === undefined, 'renamed, marked re_pair, paired again: still quiet, the mark gone');
    ok(checkOf(() => hs.admit(chainOnly(F), verify(chainOnly(F), now), null, { relay: 'relay.test', pair_key: key(11), tier: 'vip', tier_by: 'owner' }, now)) === 'tier', 'admit with an unknown tier: tier');
    // Another writer: tier "own" without tier_by. The retired enrolled flag counts for nothing.
    const E = agent('store enrolled'), G = agent('store enrolled 2');
    hs.admit(chainOnly(E), verify(chainOnly(E), now), 'e', { relay: 'relay.test', pair_key: key(4), enrolled: true }, now);
    hs.admit(chainOnly(G), verify(chainOnly(G), now), 'g', { relay: 'relay.test', pair_key: key(5) }, now);
    const g = hs.load().s.contacts[G.did]; g.tier = 'own'; delete g.tier_by; hs.save();
    ok(hs.tiers(now).get(E.did) === 'friend' && hs.tiers(now).get(G.did) === 'own', 'enrolled: true is no mark (the attestation is); tier "own" written without tier_by: own');
    hs.admit(chainOnly(G), verify(chainOnly(G), now), null, { relay: 'relay.test', pair_key: key(6) }, now);
    ok(hs.load().s.contacts[G.did].tier === 'own', 'and kept through a re-pair');
    hs.admit(chainOnly(E), verify(chainOnly(E), now), null, { relay: 'relay.test', pair_key: key(12) }, now);
    ok(hs.load().s.contacts[E.did].enrolled === undefined, 'a re-pair drops the retired enrolled flag');
    ok(hs.setTier('e', 'quiet', now).tier === 'quiet', 'a contact made quiet by the owner: quiet');
    // An agent's store: a contact that is one of my operators is own; a sibling's attestation from my operator too.
    const as = new Contacts(join(dir, 'a.json'), A.did, { mine: () => ({ chain: [A.did], operators: [H.did] }) });
    as.admit(chainOnly(H), verify(chainOnly(H), now), 'operator', { relay: 'relay.test', pair_key: key(7) }, now);
    as.admit(chainOnly(S), verify(chainOnly(S), now), 'sibling', { relay: 'relay.test', pair_key: key(8) }, now);
    ok(as.tiers(now).get(H.did) === 'own', 'an agent\'s store: its operator is own');
    ok(as.observe(S.did, verify(S.bundle, now), now) === 'own', 'and an agent attested by its operator (a sibling) is own once seen');
    // rename: the owner's name, by name or DID; one name per live contact.
    ok(JSON.stringify(hs.rename('sibling', 'Sib')) === JSON.stringify({ did: S.did, name: 'Sib' }), 'rename by name → {did, name}');
    ok(checkOf(() => hs.rename(S.did, 'renamed')) === 'name_taken' && checkOf(() => hs.rename(S.did, 'x'.repeat(65))) === 'name', 'rename to another contact\'s name: name_taken; past 64 characters: name');
    ok(hs.rename(S.did, 'Sib').name === 'Sib' && hs.tiers(now).get(S.did) === 'own', 'renamed to its own name again; the tier stays');
    // addAccept with a tier: refused when unknown.
    const code = { secret: new Uint8Array(32), did: F.did, exp: now + 600, relay: 'relay.test' };
    ok(checkOf(() => hs.addAccept(code, 'x'.repeat(64), 'f', now, null, null, false, 'vip')) === 'tier', 'addAccept with an unknown tier: tier');
    hs.addAccept(code, 'y'.repeat(64), 'f', now, null, null, false, 'quiet');
    ok(hs.load().s.accepts['y'.repeat(64)].tier === 'quiet', 'addAccept keeps the tier chosen');
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) {
  report();
  console.log(`ALL PASS (${count}): the store part; SKIP the rest, no relay checkout beside contact/ (the relay is its own AGPL package): set SIGELO_RELAY_DIR`);
  process.exit(0);
}

// ================================================================ on a loopback relay
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, OPERATOR_LABEL, operatorHint, pathsFor } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 300 s (${count} checks so far)`); process.exit(1); }, 300000).unref();

const HOST = 'relay.test';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-tier-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const events = {};
const make = (a) => {
  events[a.label] = [];
  return new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, `${a.label}.local.json`)), relay: HOST, endpoints,
    clock: () => now, onEvent: (e) => events[a.label].push(e), keep: true, backoff: [100, 400], retentionDays: 7 });
};
const tierAt = (c, did) => c.contacts().contacts.find((x) => x.did === did)?.tier;
async function pair(ci, ca, name, back, opts = {}) {
  const inv = await ci.invite({ name });
  const r = await ca.accept(inv.code, { name: back, wait: 0.3, ...opts });
  await ci.inbox(); await ca.inbox(); await ci.inbox();
  return r;
}
// Rounds both ways, so hints, asks and proofs cross.
const rounds = async (...cs) => { for (let i = 0; i < 4; i++) for (const c of cs) { now += 5; await c.inbox(); } };
try {
  const H = agent('human'), A = agent('claude'), B = agent('hermes'), F = agent('friend'), Q = agent('hotel');
  operate(H, A); operate(H, B);
  const ch = make(H), ca = make(A), cb = make(B), cf = make(F), cq = make(Q);

  await pair(ca, cb, 'hermes', 'claude');
  ok(tierAt(ca, B.did) === 'friend' && tierAt(cb, A.did) === 'friend', 'two agents of one operator, just paired: friend (a pairing carries chains only)');
  await rounds(ca, cb);
  ok(tierAt(ca, B.did) === 'own' && tierAt(cb, A.did) === 'own', 'after their operator hints, asks and proofs cross: each is own to the other');
  ok(events.claude.some((e) => e.type === 'tier' && e.did === B.did && e.tier === 'own'), 'a tier event says so');
  const as = JSON.parse(readFileSync(pathsFor(join(dir, 'claude.local.json')).store, 'utf8')).contacts[B.did];
  ok(as.tier === 'own' && as.tier_by === 'auto' && as.operator_exp === A.bundle.attestations[0].body.exp, 'written: tier own, auto, until the attestation expires');

  await pair(ca, cf, 'friend', 'claude');
  await rounds(ca, cf);
  const fBox = await cf.inbox();
  ok(tierAt(ca, F.did) === 'friend' && tierAt(cf, A.did) === 'friend', 'a contact who knows none of the operators: friend both ways');
  const fState = JSON.parse(readFileSync(pathsFor(join(dir, 'friend.local.json')).state, 'utf8'));
  ok(fBox.messages.length === 0 && !JSON.stringify(fState).includes(H.did) && !(fState.peers[A.did]?.op_asked), 'it got hints only: no operator DID, nothing asked, nothing in its inbox');

  await pair(ch, ca, 'claude', 'operator');
  ok(tierAt(ca, H.did) === 'own', 'an agent and its operator: the operator is own at once');
  await rounds(ch, ca);
  ok(tierAt(ch, A.did) === 'own', 'and the agent is own to the operator once it proves the attestation');

  // accept with a tier: the owner's choice, filed with the contact.
  const r = await pair(ca, cq, 'hotel', 'claude', { tier: 'quiet' });
  ok(r.status === 'connected' || tierAt(cq, A.did) === 'quiet', `accept {tier: quiet} pairs (${r.status})`);
  ok(tierAt(cq, A.did) === 'quiet' && JSON.parse(readFileSync(pathsFor(join(dir, 'hotel.local.json')).store, 'utf8')).contacts[A.did].tier_by === 'owner', 'accept {tier: quiet}: the contact filed quiet, by the owner');
  let bad = 'accepted';
  try { await cq.accept('sgl1x', { tier: 'vip' }); } catch (e) { bad = e.check; }
  ok(bad === 'tier', 'accept with an unknown tier: tier, before anything is sent');
  ca.setTier('hotel', 'quiet');
  ok(tierAt(ca, Q.did) === 'quiet', 'setTier through the carrier');

  // inbox by tier: own taken, friend and quiet stay.
  await rounds(ca, cb, cf, cq);
  for (const [c, to, text] of [[cb, 'claude', 'from hermes'], [cf, 'claude', 'from friend'], [cq, 'claude', 'from hotel']]) { now += 5; await c.send(to, text); }
  now += 5;
  const own = await ca.inbox({ tiers: ['own'] });
  ok(own.messages.map((m) => m.content).join() === 'from hermes', `inbox {tiers: [own]}: the own contact's message only (${own.messages.map((m) => m.content)})`);
  const left = ca.peek();
  ok(left.map((m) => `${m.content}:${m.tier}`).sort().join() === 'from friend:friend,from hotel:quiet', 'peek: the rest stay, each with its tier');
  const taken = ca.take((m, t) => t === 'friend');
  ok(taken.length === 1 && taken[0].content === 'from friend' && ca.peek().length === 1, 'take(pick): the friend\'s taken, the quiet one stays');
  const t0 = events.claude.filter((e) => e.type === 'connected').length;
  const local = await ca.inbox({ local: true });
  ok(local.messages.map((m) => m.content).join() === 'from hotel' && local.offline === undefined && events.claude.filter((e) => e.type === 'connected').length === t0,
    'inbox {local: true}: what the state holds, no session');
  let badTiers = 'accepted';
  try { await ca.inbox({ tiers: ['vip'] }); } catch (e) { badTiers = e.check; }
  ok(badTiers === 'tier', 'inbox with an unknown tier: tier');
  ok(!events.claude.some((e) => e.type === 'message' && e.label === OPERATOR_LABEL), 'no operator message ever reached onEvent as a message');

  // H renews claude's attestation: claude hints again, hermes asks again (an hour on), claude proves
  // the renewed one, and hermes keeps it own past the first one's expiry.
  const exp0 = A.bundle.attestations[0].body.exp;
  operate(H, A, 90, now + 3600);
  now += 3600;
  await rounds(ca, cb);
  const renewed = JSON.parse(readFileSync(pathsFor(join(dir, 'hermes.local.json')).store, 'utf8')).contacts[A.did].operator_exp;
  ok(renewed === A.bundle.attestations[1].body.exp && renewed > exp0, `a renewed attestation is proved again: hermes files the new expiry (${renewed - exp0} s later)`);

  // A hostile contact (THREAT-MODEL §2.12). mallory holds its own key only. Its proof is a chain
  // that rotates from its genesis into hermes's public one (a rotation is signed by the key it
  // leaves), carrying hermes's operator attestation from H: before, claude filed mallory own.
  const M = agent('mallory'), cm = make(M);
  await pair(ca, cm, 'mallory', 'claude');
  await rounds(ca, cm);
  const mFiles = pathsFor(join(dir, 'mallory.local.json'));
  const inject = async (content) => {
    const st = JSON.parse(readFileSync(mFiles.state, 'utf8'));
    st.peers[A.did].outbox.push({ id: `x${count}`, label: OPERATOR_LABEL, content });
    writeFileSync(mFiles.state, JSON.stringify(st));
    now += 5; await cm.inbox(); now += 5; await ca.inbox();
  };
  const forged = { v: 'sigelo/0', typ: 'bundle', genesis: M.bundle.genesis, bindings: [], issuers: [H.genesis], attestations: B.bundle.attestations,
    rotations: [rotate({ genesis: M.bundle.genesis, next_genesis: B.bundle.genesis, iat: now - 30, reason: 'voluntary', secret: M.secret, next_secret: B.secret })] };
  // Since the review of 2026-10-19 the next key countersigns (SPEC §7): mallory, who holds no key of
  // B's, gets a chain that ends at her own DID. Countersigned here with B's key, so the carrier's
  // own current_did check below stays exercised.
  const byMallory = { ...forged, rotations: [{ ...forged.rotations[0], sig_next: forged.rotations[0].sig }] };
  ok(verify(byMallory, now).did === M.did, 'the chain countersigned by mallory\'s key: not a candidate, it ends at mallory');
  ok(verify(forged, now).did === B.did && verify(forged, now).attestations[H.did]?.length === 1, 'the forged chain verifies, ends at hermes, and carries H\'s attestation');
  const dropped0 = events.claude.filter((e) => e.type === 'dropped').length;
  await inject({ proof: forged });
  ok(tierAt(ca, M.did) === 'friend' && events.claude.filter((e) => e.type === 'dropped').length > dropped0, 'a proof nobody asked for: dropped, mallory stays friend');
  const K = Uint8Array.from(Buffer.from(JSON.parse(readFileSync(mFiles.store, 'utf8')).contacts[A.did].pair_key, 'hex'));
  await inject({ hints: [operatorHint(K, 'hint', M.did, H.did)] });
  ok(JSON.parse(readFileSync(pathsFor(join(dir, 'claude.local.json')).state, 'utf8')).peers[M.did].op_asked === H.did, 'mallory guesses H\'s DID in a hint: claude asks (a contact learns what it can guess)');
  await inject({ proof: forged });
  ok(tierAt(ca, M.did) === 'friend' && events.claude.some((e) => e.type === 'dropped' && e.check === 'current_did'), 'asked, the forged proof ends at another DID than mallory\'s: current_did, still friend');
  let label = 'accepted';
  try { await cm.send('claude', { hints: [] }, { label: OPERATOR_LABEL }); } catch (e) { label = e.check; }
  ok(label === 'body', 'send with the carrier\'s operator label: body');
  cm.stop();
  for (const c of [ch, ca, cb, cf, cq]) await c.stop();
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
report();
console.log(`ALL PASS (${count})`);
