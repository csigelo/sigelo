// SPDX-License-Identifier: MIT
// The carrier's push registration (carrier.mjs setPush, sigelo-push/0; design/push.md) against a loopback
// relay (relay/server.mjs, relay/push.mjs) and a fake UnifiedPush distributor over HTTPS: registered at
// every login of a started carrier, a wake POSTed when a contact writes while it is stopped (opened here
// as the phone opens it, RFC 8291), removed with null, refused by name, nothing sent to a relay that does
// not say it takes it. Prints "ALL PASS (n)".
//   node apps/contact/test-push.mjs
// The relay is its own AGPL package: SIGELO_RELAY_DIR, else ../../relay; without it: SKIP.
import { createDecipheriv, createECDH, createHash, hkdfSync } from 'node:crypto';
import { existsSync, mkdtempSync } from 'node:fs';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { Carrier, PUSH_TOPIC, PUSH_V, pathsFor } from './carrier.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'push.mjs'))) { console.log('ALL PASS (0): SKIP, no relay with push.mjs beside apps/contact/ (set SIGELO_RELAY_DIR)'); process.exit(0); }
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { WAKE } = await import(pathToFileURL(join(RELAY_DIR, 'push.mjs')).href);
const { selfSigned } = await import(pathToFileURL(join(RELAY_DIR, 'test', 'fixtures.mjs')).href);
setTimeout(() => { console.log(`FAIL the run did not finish in 180 s (${count} checks so far)`); process.exit(1); }, 180000).unref();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (cond()) return true; await sleep(20); } return cond(); };

// The phone's push keys (WebPush.java makes them on the phone): a P-256 pair and a 16-byte auth secret.
const ua = createECDH('prime256v1');
ua.generateKeys();
const AUTH = createHash('sha256').update('sigelo push test auth').digest().subarray(0, 16);
const KEYS = { p256dh: ua.getPublicKey().toString('base64url'), auth: AUTH.toString('base64url') };
// RFC 8291 §3.4, as WebPush.java opens a wake.
function open(body) {
  const salt = body.subarray(0, 16), idlen = body[20], asPublic = body.subarray(21, 21 + idlen), ct = body.subarray(21 + idlen);
  const ikm = Buffer.from(hkdfSync('sha256', ua.computeSecret(asPublic), AUTH, Buffer.concat([Buffer.from('WebPush: info\0'), ua.getPublicKey(), asPublic]), 32));
  const d = createDecipheriv('aes-128-gcm', Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16)), Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12)));
  d.setAuthTag(ct.subarray(ct.length - 16));
  const rec = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  return rec.subarray(0, rec.length - 1);
}

// The fake distributor: every POST kept.
const cert = selfSigned('localhost'), posts = [];
const dist = createServer({ cert: cert.cert, key: cert.key }, (req, res) => {
  const parts = [];
  req.on('data', (d) => parts.push(d));
  req.on('end', () => { posts.push({ url: req.url, body: Buffer.concat(parts) }); res.writeHead(201); res.end(); });
});
await new Promise((r) => dist.listen(0, '127.0.0.1', r));
const ENDPOINT = `https://localhost:${dist.address().port}/upPhone?up=1`;

const HOST = 'relay.test', dir = mkdtempSync(join(tmpdir(), 'sigelo-push-carrier-'));
let now = Date.parse('2026-11-24T12:00:00Z') / 1000;
const cfg = { host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1, log: () => {},
  push: { anyAddress: true, ca: cert.cert } };
let relay = await startRelay(cfg);
const endpointsOf = (r) => ({ [HOST]: { mqtt: `mqtt://127.0.0.1:${r.ports.tcp}`, http: `http://127.0.0.1:${r.ports.http}` } });
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-push-test/0 ${l}`).digest());
const agent = (label) => {
  const k = keygen({ seed: seed(label), recovery: 'sha256:' + '0'.repeat(64), created: '2026-10-01T00:00:00Z', nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, secret: k.secret, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
};
const events = {};
const make = (a, r = relay) => { events[a.label] = []; return new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, `${a.label}.local.json`)), relay: HOST, endpoints: endpointsOf(r),
  clock: () => now, onEvent: (e) => events[a.label].push(e), keep: true, backoff: [100, 400] }); };
const rows = () => relay.db.raw.prepare('SELECT count(*) AS n FROM push').get().n;
const A = agent('alice'), B = agent('bob');
let alice = make(A), bob = make(B);
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? e.message; } };

try {
  // Pairing, each side in turn (test-carrier.mjs's first scenario).
  const inv = await alice.invite({ name: 'bob' });
  await bob.accept(inv.code, { name: 'alice', wait: 0.3 });
  await alice.inbox(); await bob.inbox(); await alice.inbox();
  ok(alice.contacts().contacts[0]?.prekeys === true, 'alice and bob paired');

  ok(PUSH_TOPIC === '$sigelo/push' && PUSH_V === 'sigelo-push/0' && bob.pushStatus().state === 'none', 'the wire names; never set: state none, nothing sent');
  const bad = [{ endpoint: 'http://x.example/y', ...KEYS }, { endpoint: ENDPOINT, p256dh: KEYS.p256dh }, { endpoint: ENDPOINT, ...KEYS, more: 1 }, { endpoint: ENDPOINT, p256dh: 'a+b/', auth: KEYS.auth }, 'x'].map((r) => checkOf(() => bob.setPush(r)));
  ok(bad.every((c) => c === 'push'), `setPush: anything but {endpoint (https), p256dh, auth (base64url)} or null refused "push" (${bad})`);
  ok(bob.setPush({ endpoint: ENDPOINT, ...KEYS }).state === 'pending', 'setPush before a login: pending');
  await bob.start();
  ok(await until(() => bob.pushStatus().state === 'registered') && rows() === 1, `a started carrier registers at its login: state registered, one row at the relay (${JSON.stringify(bob.pushStatus())})`);
  ok(events.bob.some((e) => e.type === 'push' && e.state === 'registered' && e.relay === HOST), 'an event push {state: registered, relay}');
  await alice.send('bob', 'while bob is connected');
  await sleep(300);
  ok(posts.length === 0, 'bob connected: no wake');
  await bob.stop();
  await sleep(200);
  await alice.send('bob', 'while bob is away');
  ok(await until(() => posts.length === 1), 'bob stopped, alice writes: one POST to his endpoint');
  ok(posts[0].url === '/upPhone?up=1' && open(posts[0].body).equals(WAKE), 'the wake opens under the phone\'s keys to WAKE (RFC 8291): no sender, no text');
  await alice.send('bob', 'again');
  await sleep(300);
  ok(posts.length === 1, 'a second message before bob is back: no second wake');

  // The phone's app wakes: bob logs in, takes his mail. The same registration again changes nothing at the relay.
  bob = make(B);
  bob.setPush({ endpoint: ENDPOINT, ...KEYS });
  const box = await bob.inbox();
  ok(box.messages.map((m) => m.content).join('|') === 'while bob is connected|while bob is away|again' && bob.pushStatus().state === 'registered', 'woken, bob reads all three; registered again at that login (an inbox() session too)');

  // Off: null removes it at the relay.
  bob.setPush(null);
  await bob.inbox();
  ok(bob.pushStatus().state === 'off' && rows() === 0, 'setPush(null): removed at the relay at the next login (state off, no row)');
  await alice.send('bob', 'no wake now');
  await sleep(300);
  ok(posts.length === 1, 'removed: no wake');

  // A registration the relay refuses (a key off the curve): the notice by name, the session goes on.
  bob.setPush({ endpoint: ENDPOINT, p256dh: Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]).toString('base64url'), auth: KEYS.auth });
  const r2 = await bob.inbox();
  ok(bob.pushStatus().state === 'refused' && bob.pushStatus().code === 'push' && /p256dh/.test(bob.pushStatus().detail) && r2.messages.length === 1, `refused: state refused, code push, why (${bob.pushStatus().detail}); the mail still came`);

  // A relay without push: nothing is sent (it would close the session), state unsupported.
  await relay.close();
  relay = await startRelay({ ...cfg, db: join(dir, 'off.db'), push: false });
  const carol = make(agent('carol'), relay);
  carol.setPush({ endpoint: ENDPOINT, ...KEYS });
  await carol.inbox();
  ok(carol.pushStatus().state === 'unsupported' && !events.carol.some((e) => e.type === 'notice'), 'a relay that does not say push: nothing sent, state unsupported, no notice');
} finally {
  try { await bob.stop(); } catch {}
  await relay.close();
  dist.closeAllConnections?.();
  dist.close();
}
for (const f of fails) console.log('FAIL ' + f);
if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
console.log(`ALL PASS (${count})`);
process.exit(0);
