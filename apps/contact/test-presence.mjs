// SPDX-License-Identifier: MIT
// Presence (carrier.mjs "Presence", design/transfer.md §8 T0): the store part first (off by default,
// allow and deny, own agents always, kept through a re-pair); then, with the relay checkout beside
// apps/contact/ (SIGELO_RELAY_DIR, else ../../relay), on a loopback relay: a started carrier's marker is
// read by an allowed contact and by its own agents, never by a denied one; a stop and a cut
// connection are the relay's offline with its time; a reconnection is online again; a deny clears
// what the contact sees.
//   node apps/contact/test-presence.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { attest, keygen, verify } from 'sigelo';
import { Contacts, OPERATOR_CTX } from './store.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (cond()) return true; await sleep(25); } return cond(); };

const CREATED = '2026-10-01T00:00:00Z', DAY = 86400;
let now = Date.parse('2026-11-02T12:00:00Z') / 1000;
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-presence-test/0 ${l}`).digest());
function agent(label) {
  const k = keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, did: k.did, secret: k.secret, genesis: k.genesis, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
const operate = (op, a, days = 90, iat = now - 60) => {
  a.bundle.attestations.push(attest({ secret: op.secret, iss: op.did, sub: a.did, iat, exp: iat + days * DAY, ctx: OPERATOR_CTX, admission: 'invite', admission_by: op.did, claims: { relay: 'relay.test' } }));
  if (!a.bundle.issuers.some((g) => g === op.genesis)) a.bundle.issuers.push(op.genesis);
};
const chainOnly = (a) => ({ ...a.bundle, attestations: [], issuers: [] });

// ================================================================ the store
{
  const dir = mkdtempSync(join(tmpdir(), 'sigelo-presence-store-'));
  try {
    const H = agent('store human'), A = agent('store agent'), F = agent('store friend');
    const hs = new Contacts(join(dir, 'h.json'), H.did, { mine: () => ({ chain: [H.did], operators: [] }) });
    const key = (n) => n.toString(16).padStart(64, '0');
    hs.admit(chainOnly(F), verify(chainOnly(F), now), 'friend', { relay: 'relay.test', pair_key: key(1) }, now);
    operate(H, A);
    hs.admit(A.bundle, verify(A.bundle, now), 'agent', { relay: 'relay.test', pair_key: key(2) }, now);
    const c = () => hs.load().s.contacts;
    ok(hs.presenceOf(c()[F.did], now) === 'deny' && hs.presenceOf(c()[A.did], now) === 'own', 'presence: a contact sees nothing by default (deny); an own agent always (own)');
    ok(JSON.stringify(hs.setPresence('friend', true, now)) === JSON.stringify({ did: F.did, name: 'friend', presence: 'allow' }) && c()[F.did].presence === true, 'setPresence allow by name → {did, name, presence: allow}, kept in the record');
    hs.admit(chainOnly(F), verify(chainOnly(F), now), 'friend', { relay: 'relay.test', pair_key: key(3) }, now);
    ok(hs.presenceOf(c()[F.did], now) === 'allow', 'a re-pair keeps the choice');
    ok(hs.setPresence(F.did, false, now).presence === 'deny' && c()[F.did].presence === undefined, 'setPresence deny by DID: off again');
    ok(checkOf(() => hs.setPresence('agent', false, now)) === 'presence_own' && hs.setPresence('agent', true, now).presence === 'own', 'deny on an own agent: presence_own (own agents always see each other)');
    ok(checkOf(() => hs.setPresence('nobody', true, now)) === 'not_contact' && checkOf(() => hs.setPresence('friend', 'yes', now)) === 'presence', 'no such contact: not_contact; allow not a boolean: presence');
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) {
  report();
  console.log(`ALL PASS (${count}): the store part; SKIP the rest, no relay checkout beside apps/contact/ (the relay is its own AGPL package): set SIGELO_RELAY_DIR`);
  process.exit(0);
}

// ================================================================ on a loopback relay
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, pathsFor, presenceTopic } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 300 s (${count} checks so far)`); process.exit(1); }, 300000).unref();

const HOST = 'relay.test';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-presence-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 4, loadBits: 8, loadPerHour: 1000, cost: { m: 8, t: 1, p: 1 } } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const events = {};
const make = (a) => {
  events[a.label] = [];
  return new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, `${a.label}.local.json`)), relay: HOST, endpoints,
    clock: () => now, onEvent: (e) => events[a.label].push(e), keep: true, backoff: [100, 400], retentionDays: 7 });
};
const of = (c, did) => c.contacts().contacts.find((x) => x.did === did);
async function pair(ci, ca, name, back) {
  const inv = await ci.invite({ name });
  await ca.accept(inv.code, { name: back, wait: 0.3 });
  await ci.inbox(); await ca.inbox(); await ci.inbox();
}
const rounds = async (...cs) => { for (let i = 0; i < 4; i++) for (const c of cs) { now += 5; await c.inbox(); } };
// The relay's session of identity a, by its client id (carrier.mjs clientIdOf).
const sessionOf = (a) => relay.broker.clients['s' + createHash('sha256').update(a.did).digest('hex').slice(0, 24)];
try {
  const H = agent('human'), A = agent('atlas'), B = agent('beacon'), F = agent('friend');
  operate(H, A); operate(H, B);
  const ca = make(A), cb = make(B), cf = make(F);
  await pair(ca, cb, 'beacon', 'atlas');
  await rounds(ca, cb);
  await pair(ca, cf, 'friend', 'atlas');
  await rounds(ca, cf);
  ok(of(ca, B.did).tier === 'own' && of(cb, A.did).tier === 'own' && of(ca, F.did).tier === 'friend', 'set-up: atlas and beacon are own to each other (one operator), friend is friend');
  ok(of(ca, B.did).presence === 'own' && of(ca, F.did).presence === 'deny' && of(ca, F.did).online === null, 'contacts(): presence own for an own agent, deny for a friend by default; online null while nothing is read');

  // A short session (inbox) is never online: no will, no marker; and it reads none (it would forget it
  // at once, and each subscribe draws on the relay's brake).
  const subscribed = [];
  relay.broker.on('subscribe', (subs) => { for (const x of subs) subscribed.push(x.topic); });
  now += 5; await ca.inbox(); await cb.inbox();
  ok(relay.presence.size === 0, 'presence: CLI-style sessions (not started) publish no marker');
  ok(!subscribed.some((t) => t.startsWith('p/')), `presence: CLI-style sessions subscribe to no presence topic (${subscribed.filter((t) => t.startsWith('p/')).length})`);

  const at0 = now;
  await ca.start(); await cb.start(); await cf.start();
  ok(await until(() => of(ca, B.did).online === true && of(cb, A.did).online === true), 'presence: two own agents, started, see each other online');
  ok(subscribed.filter((t) => t.startsWith('p/')).length >= 3, 'presence: a started carrier subscribes to its contacts\' markers');
  ok(of(ca, B.did).online_since === at0 && of(ca, B.did).last_seen === null, `online_since: when the writer connected (${of(ca, B.did).online_since})`);
  await sleep(300);
  ok(of(ca, F.did).online === null && of(cf, A.did).online === null, 'presence: neither atlas nor friend allowed the other: each reads nothing of the other (null), both started');
  ok(events.atlas.some((e) => e.type === 'presence' && e.did === B.did && e.online === true), 'a presence event says so (onEvent; never kept for inbox)');
  // The denied reader learns nothing: no marker toward it exists at the relay.
  const fK = Buffer.from(JSON.parse((await import('node:fs')).readFileSync(pathsFor(join(dir, 'friend.local.json')).store, 'utf8')).contacts[A.did].pair_key, 'hex');
  ok(!relay.presence.held([presenceTopic(fK, F.did, A.did)]).length, 'presence: no marker from friend toward atlas is held at the relay');

  // friend allows atlas: atlas sees friend.
  cf.setPresence('atlas', true);
  ok(await until(() => of(ca, F.did).online === true), 'presence: friend allows atlas (setPresence): atlas sees friend online at once (a started carrier applies it)');
  ok(of(cf, A.did).presence === 'allow', 'contacts(): presence allow');

  // A clean stop: the relay's offline, with its time.
  now += 60;
  const stopAt = now;
  await cb.stop();
  ok(await until(() => of(ca, B.did).online === false) && of(ca, B.did).last_seen === stopAt, `presence: beacon stops: atlas reads offline, last seen at the relay's time (${of(ca, B.did).last_seen})`);
  ok(events.atlas.some((e) => e.type === 'presence' && e.did === B.did && e.online === false && e.last_seen === stopAt), 'the event carries last_seen');

  // Reconnect: online again.
  now += 60;
  await cb.start();
  ok(await until(() => of(ca, B.did).online === true && of(ca, B.did).online_since === now), 'presence: beacon starts again: online, since the new connection');

  // A cut (no DISCONNECT): the will. The carrier reconnects by itself (backoff), online again.
  now += 60;
  const cutAt = now;
  sessionOf(B).conn.destroy();
  ok(await until(() => events.atlas.some((e) => e.type === 'presence' && e.did === B.did && e.online === false && e.last_seen === cutAt)), 'presence: beacon\'s connection cut: the relay\'s will says offline at the cut');
  ok(await until(() => of(ca, B.did).online === true), 'presence: beacon reconnects with backoff: online again');

  // friend denies atlas: the marker is cleared, atlas knows nothing (null), not "offline".
  cf.setPresence('atlas', false);
  ok(await until(() => of(ca, F.did).online === null), 'presence: friend denies atlas: cleared at once, atlas reads nothing (online null, no last seen)');
  ok(of(ca, F.did).last_seen === null, 'and no last seen either');
  // Nor after friend leaves: nothing toward atlas to mark offline.
  await cf.stop();
  await sleep(300);
  ok(of(ca, F.did).online === null && of(ca, F.did).last_seen === null, 'presence: a denied contact\'s stop tells atlas nothing');

  // The reader's own connection drops: what it read is forgotten (null), not left "online".
  await ca.stop();
  ok(of(ca, B.did).online === null, 'presence: once the reader is offline, it reports nothing it cannot know (null)');
  await cb.stop();
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
report();
console.log(`ALL PASS (${count})`);
