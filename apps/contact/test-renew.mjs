// SPDX-License-Identifier: MIT
// "Cancel this code" and codes that renew themselves (ROADMAP "Invite codes: auto-renew and cancel"),
// on a loopback relay (SIGELO_RELAY_DIR, else ../../relay): carrier.cancelInvite by the short code,
// the long one, the hash (another device of the same identity), at a relay that cannot cancel (an
// older one: the invite still goes here); invite({ renew: true }): a fresh short code parked once
// one is used, by a started carrier (its answer) and by a plain inbox, the codes used listed, the
// series ended by a cancel; store.mjs renew in the contact store, no other file.
//   node apps/contact/test-renew.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { codeHash } from './short.mjs';
import { platform as nodePlatform } from './platform-node.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const failure = async (f) => { try { await f(); return { check: 'accepted', message: 'accepted' }; } catch (e) { return e; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) {
  console.log('ALL PASS (0): SKIP, no relay checkout beside apps/contact/: set SIGELO_RELAY_DIR');
  process.exit(0);
}
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, pathsFor } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 120 s (${count} checks so far)`); process.exit(1); }, 120000).unref();

const HOST = 'relay.test', CREATED = '2026-10-01T00:00:00Z';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-renew-'));
let now = Date.parse('2026-11-16T12:00:00Z') / 1000;
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  // One network here (loopback): the park brakes are the relay's tests' (relay/test/run.mjs), not these.
  park: { lookups: { n: 1000, window: 600 }, parks: { n: 1000, window: 3600 }, lookupsAll: { n: 8000, window: 600 } },
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-renew-test/0 ${l}`).digest());
function agent(label) {
  const recovery = keygen({ seed: seed(`${label} recovery`), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} recovery nonce`).slice(0, 16) }).key;
  const k = keygen({ seed: seed(label), recovery, created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, did: k.did, secret: k.secret, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
const make = (a, file = `${a.label}.local.json`, platform = nodePlatform) => new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, file)), relay: HOST, shortRelay: HOST,
  registry: false, endpoints, clock: () => now, keep: true, backoff: [100, 400], retentionDays: 7, tick: 200, platform });
const until = async (f, ms = 15000) => { for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 100))) if (f()) return true; return f(); };
const started = [];
try {
  const alice = agent('alice'), bob = agent('bob'), carol = agent('carol'), dave = agent('dave');
  const ca = make(alice), cb = make(bob), cc = make(carol), cd = make(dave);
  // Cancel by the short code: gone here and at the relay.
  const i1 = await ca.invite({ name: 'one', short: true });
  ok(ca.contacts().invites.find((x) => x.name === 'one')?.short === i1.short, `contacts: a pending invite shows its short code (${JSON.stringify(ca.contacts().invites)})`);
  const c1 = await ca.cancelInvite(i1.short.toLowerCase());
  const g1 = await failure(() => cb.unpark(i1.short));
  ok(c1.cancelled === true && c1.unparked === true && c1.name === 'one' && c1.short === i1.short && !ca.contacts().invites.some((x) => x.name === 'one') && g1.check === 'park_unknown',
    `cancelInvite(short code): the invite gone here, and at the relay the next fetch is park_unknown (${JSON.stringify(c1)}; ${g1.check})`);
  // Cancel by the long code: its short code goes too.
  const i2 = await ca.invite({ name: 'two', short: true });
  const c2 = await ca.cancelInvite(i2.code), g2 = await failure(() => cb.unpark(i2.short));
  ok(c2.cancelled && c2.unparked === true && g2.check === 'park_unknown', `cancelInvite(long code): the short code parked for it is cancelled at the relay too (${JSON.stringify(c2)})`);
  const again = await failure(() => ca.cancelInvite(i2.code));
  ok(again.check === 'challenge_unknown', `a second cancel of the long code: challenge_unknown, as before (${again.check})`);
  // A long code alone: nothing at the relay.
  const i3 = await ca.invite({ name: 'three' });
  const c3 = await ca.cancelInvite(i3.code);
  ok(c3.cancelled && c3.unparked === undefined, `cancelInvite of a long code with no short one: local only (${JSON.stringify(c3)})`);
  // Another device of alice's (no invite of hers in its store) cancels by the hash; bob, not the parker, cannot.
  const i4 = await ca.invite({ name: 'four', short: true });
  const notBob = await failure(() => cb.cancelInvite(i4.short));
  ok(notBob.check === 'challenge_unknown' && (await cc.unpark(i4.short)) === i4.code, `bob cancels alice's short code: challenge_unknown, and the code still works (${notBob.message})`);
  const i5 = await ca.invite({ name: 'five', short: true });
  const ca2 = make(alice, 'alice-device2.local.json'), c5 = await ca2.cancelInvite(codeHash(i5.short)), g5 = await failure(() => cc.unpark(i5.short));
  ok(c5.cancelled && c5.unparked === true && c5.name === null && g5.check === 'park_unknown', `cancelInvite(the short code's hash) on another device of the same identity: cancelled at the relay (${JSON.stringify(c5)}; ${g5.check})`);
  await ca.cancelInvite(i5.code);
  // An older relay (no DELETE /park): the invite goes here all the same, and the answer says why.
  const oldFetch = (url, init = {}) => (init.method === 'DELETE' ? Promise.resolve(new Response(JSON.stringify({ error: 'no DELETE /park/x' }), { status: 404, headers: { 'content-type': 'application/json' } })) : nodePlatform.fetch(url, init));
  const cao = make(alice, 'alice.local.json', { ...nodePlatform, fetch: oldFetch });
  const i6 = await cao.invite({ name: 'six', short: true }), c6 = await cao.cancelInvite(i6.short);
  ok(c6.cancelled === true && c6.unparked === false && /an older relay/.test(c6.detail) && !cao.contacts().invites.some((x) => x.name === 'six'),
    `an older relay: cancelled here, unparked false, the reason given (${c6.detail})`);
  // invite({ renew }) only for a short code that is parked.
  const bad = await failure(() => ca.invite({ name: 'x', renew: true })), badLocal = await failure(() => ca.invite({ name: 'x', short: true, local: true, renew: true }));
  ok(bad.check === 'invite' && badLocal.check === 'invite', `renew needs a short code, parked: refused with the long code or local (${bad.message})`);

  // A renewing code, a started carrier: used by bob, a fresh one appears; used by carol, another.
  const r1 = await ca.invite({ name: 'friend', short: true, renew: true });
  const st = () => ca.contacts(), current = () => st().invites.find((x) => x.renew === r1.renew);
  ok(typeof r1.renew === 'string' && current()?.short === r1.short && st().renewing.length === 1 && st().renewing[0].id === r1.renew && st().renewing[0].used.length === 0,
    `invite({ renew: true }): a series id, the code its current one (${JSON.stringify(st().renewing)})`);
  await ca.start(); started.push(ca);
  const p1 = await cb.accept(r1.short, { name: 'alice', wait: 20 });
  ok(p1.status === 'connected', `bob pairs by the renewing code (${p1.status})`);
  ok(await until(() => current()?.short && current().short !== r1.short), `once it is used, a fresh code is parked for the series (${JSON.stringify(current())})`);
  const r2 = current();
  ok(r2.name === 'friend-2' && r2.short_exp > now && st().renewing[0].used.length === 1 && st().renewing[0].used[0].did === bob.did && st().renewing[0].used[0].short === r1.short,
    `the fresh code: the series' name numbered, the code used listed with who used it (${JSON.stringify(st().renewing[0])})`);
  ok((await failure(() => cd.unpark(r1.short))).check === 'park_unknown', 'the used code stays used: park_unknown');
  const p2 = await cc.accept(r2.short, { name: 'alice', wait: 20 });
  ok(p2.status === 'connected' && await until(() => current()?.short && current().short !== r2.short) && current().name === 'friend-3' && st().renewing[0].used.length === 2,
    `carol uses the fresh code: a third (${JSON.stringify(current())})`);
  // Cancel the current one: no fresh code after it, the series gone.
  const r3 = current(), cr = await ca.cancelInvite(r3.short);
  ok(cr.cancelled && cr.unparked === true && !current() && st().renewing.length === 0 && (await failure(() => cd.unpark(r3.short))).check === 'park_unknown',
    `cancelling a renewing code ends its series: none current, none listed, the code park_unknown (${JSON.stringify(st().renewing)})`);
  await ca.stop(); started.pop();

  // A renewing code, no started carrier: bob answers while alice is away; her inbox pairs and renews.
  const s1 = await ca.invite({ name: 'later', short: true, renew: true });
  const w = await cd.accept(s1.short, { name: 'alice', wait: 1 });
  ok(w.status === 'waiting' || w.status === 'pending', `dave answers the renewing code with alice away (${w.status})`);
  const box = await ca.inbox({ wait: 3 });
  const next = ca.contacts().invites.find((x) => x.renew === s1.renew);
  ok(box.events.some((e) => e.type === 'paired' && e.renew === s1.renew) && next && next.short !== s1.short && next.name === 'later-2',
    `alice's inbox: paired (the event names the series) and the fresh code parked in the same call (${JSON.stringify(next)})`);
  ok((await cc.unpark(next.short)).startsWith('sgl1'), 'the fresh code is parked at the relay: fetched');
  // Ended by a cancel: nothing of it left in the store.
  const kept = JSON.parse(readFileSyncSafe(join(dir, 'alice.local.contacts.json')) ?? '{}');
  await ca.cancelInvite(next.short);
  const ended = JSON.parse(readFileSyncSafe(join(dir, 'alice.local.contacts.json')) ?? '{}');
  ok(kept.renew?.[s1.renew]?.n === 2 && kept.invites && !('renew' in ended), `the series is kept in the contact store (renew), gone once ended (${JSON.stringify(kept.renew)})`);
  // Its code runs out unused: the series ends with it (purged at the next write).
  const x1 = await ca.invite({ name: 'idle', short: true, renew: true });
  now += 86400 + 1;
  const x2 = await ca.invite({ name: 'next', short: true });
  ok(!ca.contacts().renewing.some((x) => x.id === x1.renew) && !ca.contacts().invites.some((x) => x.renew === x1.renew), `a renewing code that runs out unused: its series ends (${JSON.stringify(ca.contacts().renewing)})`);
  await ca.cancelInvite(x2.short);
  ok(readdirSync(dir).every((f) => !/renew/i.test(f)), `no file of its own on disk (${readdirSync(dir).join(', ')})`);
} finally {
  for (const c of started) await c.stop();
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
function readFileSyncSafe(p) { try { return readFileSync(p, 'utf8'); } catch { return null; } }
report();
console.log(`ALL PASS (${count})`);
