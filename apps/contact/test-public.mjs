// SPDX-License-Identifier: MIT
// Public codes (sigelo-public/0, public.mjs, design/public-invite.md) on a loopback relay
// (SIGELO_RELAY_DIR, else ../../relay): invitePublic (Pro only), a PUB code accepted by many, each a
// request the owner approves or refuses, open (let anyone in), the four words checked by the joiner
// (a link carries them; a mismatch pairs nothing), every joiner its own pairing key, a replayed or
// stale answer dropped, the owner's cap, Pause, Revoke for all (pairings made stay), the PUB format.
//   node apps/contact/test-public.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { connect } from 'mqtt';
import { didWords } from './short.mjs';
import { KIND } from './envelope.mjs';
import { buildAnswer, makeInvite, parsePublicCode, parseInvite, screenAnswer } from './invite.mjs';
import { kemKey } from './prekeys.mjs';
import { formatPub, isPub, joinerKeys, normalisePub, normaliseWords, publicHash, publicKeys, publicLink, readLink } from './public.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) { fails.push(what); if (process.env.DBG) console.log("FAIL " + what); } };
const failure = async (f) => { try { await f(); return { check: 'accepted', message: 'accepted' }; } catch (e) { return e; } };
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) { console.log('ALL PASS (0): SKIP, no relay checkout beside apps/contact/: set SIGELO_RELAY_DIR'); process.exit(0); }
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { accountOf } = await import(pathToFileURL(join(RELAY_DIR, 'db.mjs')).href);
const fx = await import(pathToFileURL(join(RELAY_DIR, 'test', 'fixtures.mjs')).href);
const { Carrier, pathsFor, seal } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 180 s (${count} checks so far)`); process.exit(1); }, 180000).unref();

// ---- offline: the formats ----
{
  const now = 1_800_000_000, did = keygen({ seed: new Uint8Array(32).fill(7), recovery: 'sha256:' + '0'.repeat(64), created: '2026-10-01T00:00:00Z', nonce: new Uint8Array(16) }).did;
  const code = makeInvite({ did, relay: 'relay.test', now, ttl: 366 * 86400, version: 2 });
  ok(code.text.startsWith('sgl2') && parsePublicCode(code.text, now).nonce === code.nonce, 'a public code: sgl2…, a year at most, read back');
  ok((await failure(() => makeInvite({ did, relay: 'relay.test', now, ttl: 367 * 86400, version: 2 }))).check === 'ttl', 'a public code past a year: refused');
  ok((await failure(() => parseInvite(code.text, now))).check === 'code_version', 'an sgl2 code read as a one-time code: code_version (how an older client refuses it)');
  ok(isPub('pub-7q4k-m2xd') && formatPub(normalisePub('PUB 7Q4K M2XD 4WXN')) === 'PUB-7Q4K-M2XD-4WXN' && !isPub('K7F3-Q9ZP') && publicHash('PUB-7Q4K-M2XD') === createHash('sha256').update('sigelo-public/0' + '7Q4KM2XD').digest('hex'),
    'PUB codes: read in any case and spacing, a relay tag kept, hashed under sigelo-public/0');
  const w = 'abandon ability able about', l = publicLink('PUB-7Q4K-M2XD', w);
  ok(l === 'https://sigelo.io/join#PUB-7Q4K-M2XD.abandon-ability-able-about' && readLink(l).code === 'PUB-7Q4K-M2XD' && readLink(l).words === w && normaliseWords('Abandon, ability-able  ABOUT') === w,
    `the link carries the code and the four words (${l})`);
  const s = new Uint8Array(32).fill(1), a = joinerKeys(s, 'zA'), b = joinerKeys(s, 'zB');
  ok(publicKeys(s).answer_topic.startsWith('m/') && a.reply_topic.startsWith('i/') && a.reply_topic !== b.reply_topic, 'the answer topic a mailbox, each joiner\'s reply topic its own');
}

const HOST = 'relay.test', CREATED = '2026-10-01T00:00:00Z';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-public-'));
let now = Date.parse('2026-11-16T12:00:00Z') / 1000;
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-public-test/0 ${l}`).digest());
function agent(label) {
  const recovery = keygen({ seed: seed(`${label} recovery`), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} recovery nonce`).slice(0, 16) }).key;
  const k = keygen({ seed: seed(label), recovery, created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, did: k.did, secret: k.secret, genesis: k.genesis, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
const alice = agent('alice'), bob = agent('bob');
const pro = new Set([accountOf(alice.did)]);
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  park: { lookups: { n: 1000, window: 600 }, parks: { n: 1000, window: 3600 }, lookupsAll: { n: 8000, window: 600 }, publicFetches: { n: 1000, window: 600 }, pro: (a) => pro.has(a) }, log: () => {} });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const make = (a, extra = {}) => new Carrier({ ...extra, identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, `${a.label}.local.json`)), relay: HOST, shortRelay: HOST,
  registry: false, endpoints, clock: () => now, keep: true, backoff: [100, 400], retentionDays: 7, tick: 200 });
const until = async (f, ms = 15000) => { for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 100))) if (f()) return true; return f(); };
// A raw MQTT publish, as the relay (or anyone holding the code) could replay a frame.
const rawPublish = async (id, t, bytes) => {
  const { challenge } = await (await fetch(`${endpoints[HOST].http}/challenge?did=${encodeURIComponent(id.did)}`)).json();
  const c = await new Promise((resolve, reject) => {
    const x = connect({ host: '127.0.0.1', port: relay.ports.tcp, protocolVersion: 4, clean: false, clientId: fx.clientId(id), username: id.did, password: fx.password(id, challenge), reconnectPeriod: 0 });
    x.once('connect', () => resolve(x)); x.once('error', reject);
  });
  await new Promise((r) => c.publish(t, Buffer.from(bytes), { qos: 1 }, r));
  await new Promise((r) => c.end(false, {}, r));
};
try {
  const ca = make(alice), cb = make(bob);
  const notPro = await failure(() => cb.invitePublic({ name: 'bobs' }));
  ok(notPro.check === 'public_pro' && /Pro/.test(notPro.message) && cb.contacts().publics.length === 0, `without Pro: public_pro, nothing kept (${notPro.message})`);
  const p = await ca.invitePublic({ name: 'shop', cap: 3 });
  ok(/^PUB-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(p.short) && p.code.startsWith('sgl2') && p.words === didWords(alice.did) && p.link === publicLink(p.short, p.words) && p.cap === 3 && p.open === false,
    `invitePublic: a PUB code, the sgl2 code, the four words, the link (${JSON.stringify({ short: p.short, words: p.words, exp: p.exp })})`);
  const view = () => ca.contacts().publics.find((x) => x.id === p.id);
  ok(view()?.short === p.short && view().requests.length === 0, 'contacts().publics: the code, no request yet');

  // Approve each: carol's answer waits; approved, both sides paired.
  const carol = agent('carol'), cc = make(carol);
  const w1 = await cc.accept(p.short.toLowerCase(), { name: 'shop', wait: 1 });
  ok(w1.status === 'waiting_approval' && /accepts each new chat/.test(w1.detail), `a joiner: waiting for approval (${JSON.stringify(w1)})`);
  const box = await ca.inbox({ wait: 2 });
  const req = box.events.find((e) => e.type === 'public_request');
  ok(req && req.did === carol.did && req.words === didWords(carol.did) && view().requests.length === 1 && view().today === 1, `the owner: a request, with the joiner's DID and words (${JSON.stringify(req)})`);
  ok(ca.contacts().contacts.length === 0, 'nothing admitted before approval');
  const ap = await ca.approvePublic(req.id);
  ok(ap.approved === true && ap.did === carol.did && ap.name === 'shop-1' && view().requests.length === 0 && view().chats === 1, `approvePublic: paired, named after the code (${JSON.stringify(ap)})`);
  const cbox = await cc.inbox({ wait: 3 });
  const cpaired = cbox.events.find((e) => e.type === 'paired');
  const aliceAtCarol = cc.contacts().contacts.find((x) => x.did === alice.did), carolAtAlice = ca.contacts().contacts.find((x) => x.did === carol.did);
  ok(cpaired?.public === true && cpaired.words_checked === false && aliceAtCarol?.via?.public === true && aliceAtCarol.via.words === null && carolAtAlice?.via?.public === p.id,
    `carol is paired; each side marked: came by a public code, nobody compared (${JSON.stringify(aliceAtCarol?.via)}, ${JSON.stringify(carolAtAlice?.via)})`);
  ok(aliceAtCarol.fingerprint === carolAtAlice.fingerprint, 'the pairing\'s own four words agree');
  await ca.send(carol.did, 'hello');
  ok((await cc.inbox({ wait: 3 })).messages.some((m) => m.content === 'hello'), 'a message goes over the new pairing');

  // The link with the right words: checked. Another key.
  const dave = agent('dave'), cd = make(dave);
  ok((await cd.accept(p.link, { name: 'shop', wait: 1 })).status === 'waiting_approval', 'dave accepts the link');
  const r2 = (await ca.inbox({ wait: 2 })).events.find((e) => e.type === 'public_request');
  await ca.approvePublic(r2.id);
  const dbox = await cd.inbox({ wait: 3 });
  const daveSide = cd.contacts().contacts.find((x) => x.did === alice.did), daveAtAlice = ca.contacts().contacts.find((x) => x.did === dave.did);
  ok(dbox.events.some((e) => e.type === 'paired' && e.words_checked === true) && daveSide?.via?.words === 'checked', `the link's words matched: checked against the page (${JSON.stringify(daveSide?.via)})`);
  ok(daveAtAlice.fingerprint !== carolAtAlice.fingerprint && daveAtAlice.pair !== carolAtAlice.pair, 'every joiner its own pairing key (pair ids differ)');

  // Wrong words: nothing paired at the joiner.
  const erin = agent('erin'), ce = make(erin);
  ok((await ce.accept(p.short, { wait: 1, words: 'abandon ability able about' })).status === 'waiting_approval', 'erin accepts with other words');
  const r3 = (await ca.inbox({ wait: 2 })).events.find((e) => e.type === 'public_request');
  ok(r3?.did === erin.did && view().today === 3, 'the third request today (the cap is three)');
  await ca.approvePublic(r3.id);
  const ebox = await ce.inbox({ wait: 3 });
  ok(!ce.contacts().contacts.some((x) => x.did === alice.did) && JSON.stringify(ebox).includes('words'), `a words mismatch: refused words, nothing paired (${JSON.stringify(ebox)})`);

  // The cap: a fourth today is refused by the relay.
  const frank = agent("frank"), cf = make(frank);
  const over = await failure(() => cf.accept(p.short, { wait: 5 }));
  ok(over.check === 'public_cap', `a fourth joiner today: public_cap (${over.message})`);
  now += 86400;

  // Refuse: dropped; the joiner told nothing.
  ok((await cf.accept(p.short, { wait: 1 })).status === 'waiting_approval', 'next day: frank\'s request');
  await ca.inbox({ wait: 2 });
  const fr = view().requests.find((x) => x.did === frank.did);
  ok(ca.refusePublic(fr.id).refused === true && view().requests.length === 0 && (await failure(() => ca.approvePublic(fr.id))).check === 'challenge_unknown', 'refusePublic: the request gone, it cannot be approved later');

  // A stale answer and a replayed one: dropped.
  const code = parsePublicCode(p.code, now), keys = publicKeys(code.secret);
  const gina = agent('gina');
  const answerOf = (iat) => buildAnswer({ code, identity: { secret: gina.secret, genesis: gina.genesis }, bundle: gina.bundle, kem_pk: kemKey().pk, prekeys: null, iat });
  const stale = answerOf(now - 8 * 86400), fresh = answerOf(now);
  ok((await failure(() => screenAnswer(stale, { nonce: code.nonce, exp: code.exp }, { self: alice.did, load() { return { s: { contacts: {} } }; } }, now))).check === 'challenge_expired', 'screenAnswer: an answer over 7 days old is refused');
  const frame = seal(KIND.invite_answer, keys.key, keys.answer_topic, fresh);
  await rawPublish(fx.identity('replay-1'), keys.answer_topic, frame);
  await rawPublish(fx.identity('replay-2'), keys.answer_topic, frame);
  await rawPublish(fx.identity('replay-3'), keys.answer_topic, seal(KIND.invite_answer, keys.key, keys.answer_topic, stale));
  await ca.inbox({ wait: 2 });
  ok(view().requests.filter((x) => x.did === gina.did).length === 1 && view().requests.length === 1, `the same answer twice (a replay) makes one request, a stale one none (${view().requests.length})`);

  // Pause and Resume.
  const ps = await ca.setPublic(p.short, { paused: true });
  const paused = await failure(() => make(agent('hana')).accept(p.short, { wait: 1 }));
  ok(ps.paused === true && paused.check === 'public_paused', `Pause: a joiner is told public_paused (${paused.message})`);
  const rs = await ca.setPublic(p.id, { paused: false, cap: 10 });
  ok(rs.paused === false && rs.cap === 10 && view().cap === 10, 'Resume, and a new cap');

  // Open: approved at once.
  const o = await ca.invitePublic({ name: 'desk', open: true });
  const ivan = agent('ivan'), ci = make(ivan);
  await ca.start();
  const oi = await ci.accept(o.short, { wait: 15 });
  await ca.stop();
  ok(oi.status === 'connected' && ca.contacts().contacts.some((x) => x.did === ivan.did && x.via?.public === o.id), `open (let anyone in): paired at once (${oi.status})`);

  // Revoke for all: the code is gone, at the relay too; pairings made stay.
  const rv = await ca.cancelInvite(p.short);
  const gone = await failure(() => make(agent('judy')).accept(p.short, { wait: 1 }));
  ok(rv.cancelled === true && rv.public === true && rv.unparked === true && !view() && gone.check === 'park_unknown', `Revoke for all: cancelled at the relay, a joiner gets park_unknown (${gone.message})`);
  ok(ca.contacts().contacts.some((x) => x.did === carol.did) && ca.contacts().contacts.some((x) => x.did === dave.did), 'pairings made by the code stay');
  await ca.cancelInvite(o.id);
  ok(ca.contacts().publics.length === 0, 'Revoke by id');
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
for (const f of fails) console.log('FAIL ' + f);
if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
console.log(`ALL PASS (${count})`);
