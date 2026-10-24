// SPDX-License-Identifier: MIT
// The self-contained app in Node (design/apps.md §14 A4): the page's files as copy.mjs vendors them,
// loaded through index.html's import map (a resolve hook does in Node what the map does in a page),
// so what runs here is what ships. Parts:
//   1. the page: index.html parses, one inline script (the import map, admitted by its hash in the
//      CSP), the static import graph resolves to files with no node: import left unmapped;
//   2. platform-web.mjs over a minimal in-memory IndexedDB: files, write-behind and flush, a failed
//      commit, a reload, navigator.locks owner, the PoW worker, the sealed identity, the transports;
//   3. router.mjs against the in-process relay (relay/server.mjs) over MQTT.js's browser build and
//      Node's WebSocket: the UI-API.md routes, a pairing each way with a Node peer, send and read,
//      links, devices, agents, pushed changes, a restart from IndexedDB, one owner, and the flush
//      rule: nothing published and nothing acknowledged while a write is not committed.
//   node apps/web/copy.mjs && node apps/web/test-web.mjs   → ALL PASS (n)
// The relay is its own AGPL package: SIGELO_RELAY_DIR, else ../../relay; without it, SKIP part 3.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url)), REPO = join(HERE, '..', '..');
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const report = (skip = '') => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
  console.log(`ALL PASS (${count})${skip}`);
  process.exit(0);
};
setTimeout(() => { console.log(`FAIL the run did not finish in 300 s (${count} checks so far)`); for (const f of fails) console.log('FAIL ' + f); process.exit(1); }, 300000).unref();
const checkOf = async (f) => { try { await f(); return 'accepted'; } catch (e) { return e.check ?? e.code ?? e.message; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (f, ms = 20000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await f()) return true; await sleep(100); } return false; };

// ================================================================ 1. the page
try { execFileSync(process.execPath, [join(HERE, 'copy.mjs')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { process.stdout.write(`${e.stdout ?? ''}${e.stderr ?? ''}`); throw e; } // copy.mjs's FAIL lines shown
const C = await import(pathToFileURL(join(HERE, 'copy.mjs')).href);
const html = readFileSync(join(HERE, 'index.html'), 'utf8'), map = C.importMap(html);
{
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  const inline = scripts.filter((s) => s[2].trim() !== '');
  ok(inline.length === 1 && /type="importmap"/.test(inline[0][1]), `index.html: one inline script, the import map (${inline.length})`);
  ok(scripts.filter((s) => s[2].trim() === '').every((s) => /src="\.\/[^"]+"/.test(s[1])), 'index.html: every other script from this origin, by a relative path');
  const { policy, want } = C.csp(html);
  ok(policy?.startsWith("default-src 'self'; script-src 'self' " + want + ';') && !/unsafe-(inline|eval)/.test(policy) && /object-src 'none'/.test(policy) && /base-uri 'none'/.test(policy),
    `index.html: CSP default-src 'self', script-src 'self' and the import map's hash only (${policy})`);
  const { files, missing } = C.walk(map);
  ok(missing.length === 0, `the import graph resolves in the page (${missing.join('; ')})`);
  const vendored = [...files].filter(([rel]) => rel.startsWith('vendor/'));
  ok(vendored.every(([rel, src]) => src && readFileSync(join(HERE, ...rel.split('/'))).equals(readFileSync(src))), 'vendor/: every file as its source, byte for byte');
  ok(!files.has('vendor/contact/platform-node.mjs') && files.has('platform-stub.mjs'), 'platform-node.mjs is never loaded in the page: the import map gives the stub');
  // remote-client.mjs imports node:module and node:url only in Node (its own dependencies), never in the page: C.NODE_ONLY.
  const nodeImports = vendored.filter(([rel]) => /\.m?js$/.test(rel)).flatMap(([rel, src]) => C.importsOf(readFileSync(src, 'utf8')).filter((s) => s.startsWith('node:') && !C.NODE_ONLY[rel]?.includes(s)).map((s) => `${rel}: ${s}`));
  ok(nodeImports.every((x) => x.endsWith('node:zlib') && /qr(-decode)?\.mjs/.test(x)), `no node: import in the page but the QR codec's node:zlib, mapped to the shim (${nodeImports})`);
  const own = ['app.mjs', 'router.mjs', 'platform-web.mjs', 'platform-stub.mjs', 'pow-worker.mjs', 'platform-android.mjs', 'ws-over-stream.mjs', 'shell.mjs'].map((f) => readFileSync(join(HERE, f), 'utf8'));
  ok(own.every((t) => !/from 'node:|innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/.test(t)), 'the app\'s modules: no node: import, no HTML strings, no eval');
  const manifest = JSON.parse(readFileSync(join(HERE, 'vendor.json'), 'utf8'));
  ok(Object.keys(manifest.files).length === vendored.length && Object.entries(manifest.files).every(([rel, f]) => f.sha256 === createHash('sha256').update(readFileSync(join(HERE, ...rel.split('/')))).digest('hex')),
    'vendor.json: exactly the files vendored, each with its SHA-256');
}

// In Node, index.html's import map by a resolve hook: a module under apps/web/ resolves as in the page.
const WEB = pathToFileURL(HERE + '/').href;
registerHooks({
  resolve(spec, ctx, next) {
    // The page's modules only: this test and copy.mjs are Node's.
    if (!ctx.parentURL?.startsWith(WEB) || /\/(test-[a-z]+|copy)\.mjs$/.test(ctx.parentURL)) return next(spec, ctx);
    const page = C.resolve(spec.startsWith(WEB) ? C.PAGE + spec.slice(WEB.length) : spec, C.PAGE + ctx.parentURL.slice(WEB.length), map);
    return { url: WEB + page.slice(C.PAGE.length), format: 'module', shortCircuit: true };
  },
});
const W = await import(pathToFileURL(join(HERE, 'platform-web.mjs')).href);
const { search } = await import(pathToFileURL(join(HERE, 'pow-worker.mjs')).href);
const mqttEsm = (await import(pathToFileURL(join(HERE, 'vendor', 'mqtt.esm.js')).href)).default;

// The in-memory IndexedDB and the Worker as a Node thread: test-fakes.mjs (test-shell.mjs uses them too).
const { FakeIDB, FakeWorker } = await import(pathToFileURL(join(HERE, 'test-fakes.mjs')).href);
const nodePow = (await import(pathToFileURL(join(REPO, 'contact', 'platform-node.mjs')).href)).pow;

// ================================================================ 2. platform-web.mjs
{
  const idb = new FakeIDB(), p = await W.webPlatform({ name: 't1', indexedDB: idb, mqtt: mqttEsm, pow: W.workerPow(() => new FakeWorker()) });
  const { files } = p, enc = (s) => new TextEncoder().encode(s), dec = (b) => new TextDecoder().decode(b);
  ok(files.read('a/x.json') === null && p.transports.join() === 'wss' && Object.isFrozen(p), 'web: an absent file is null; transports wss only; frozen');
  files.write('a/x.json', enc('{"a":1}'));
  ok(dec(files.read('a/x.json')) === '{"a":1}' && idb.dbs.get('t1').stores.get('files').size === 0, 'web: a write is read back at once, and is not in IndexedDB yet (behind)');
  await p.flush();
  ok(dec(idb.dbs.get('t1').stores.get('files').get('a/x.json')) === '{"a":1}', 'web: flush() resolves once the write is committed');
  ok(await checkOf(() => files.write('a/x.json', enc('{}'), { how: 'new' })) === 'EEXIST', 'web: write new never over a file');
  const at = ['a/in/f', 'a/in/f-2'];
  ok(files.add(at, enc('1')) === at[0] && files.add(at, enc('2')) === at[1] && files.add(at, enc('3')) === null, 'web: add takes the first name not taken, then none');
  ok(files.list('a').sort().join() === 'in,x.json' && files.list('a/in').sort().join() === 'f,f-2', `web: list gives a folder's names (${files.list('a')})`);
  const got = files.read('a/x.json'); got[0] = 0;
  ok(dec(files.read('a/x.json')) === '{"a":1}', 'web: read gives a copy');
  files.remove('a/in'); await p.flush();
  ok(files.list('a').join() === 'x.json' && ![...idb.dbs.get('t1').stores.get('files').keys()].some((k) => k.startsWith('a/in')), 'web: remove takes a folder and what it holds, in IndexedDB too');
  // Write-behind on its own: committed without a flush, soon.
  files.write('b', enc('later'));
  ok(await until(() => idb.dbs.get('t1').stores.get('files').has('b'), 2000), 'web: a write goes behind without a flush');
  // A reload: a new platform on the same database reads what was committed.
  const p2 = await W.webPlatform({ name: 't1', indexedDB: idb, mqtt: mqttEsm });
  ok(dec(p2.files.read('a/x.json')) === '{"a":1}' && dec(p2.files.read('b')) === 'later' && p2.files.read('a/in/f') === null, 'web: a reload reads the files as committed');
  // A commit that fails: flush rejects, and keeps rejecting (nothing may leave after a lost write).
  idb.failNext = 1;
  files.write('c', enc('lost'));
  ok(await checkOf(() => p.flush()) !== 'accepted', 'web: flush rejects when the commit fails');
  files.write('d', enc('after'));
  ok(await checkOf(() => p.flush()) !== 'accepted', 'web: and every flush after it');
  // The owner: navigator.locks, one per identity, until released.
  const o = await p.owner('did:sigelo:zTest');
  ok(await checkOf(() => p2.owner('did:sigelo:zTest')) === 'busy', 'web: owner: a second holder of the same identity is refused, busy');
  o.release(); await sleep(20);
  const o2 = await p2.owner('did:sigelo:zTest').catch(() => null);
  ok(o2 !== null, 'web: owner: free again once released');
  o2?.release();
  // Proof of work in the worker: the counter platform-node.mjs finds, progress, deadline, abort.
  const prefix = 'sigelo-relay-pow/0\nrelay.testdid:sigelo:zX0123';
  ok(await p.pow(prefix, 10) === await nodePow(prefix, 10) && search(prefix, 6) === await nodePow(prefix, 6), 'web: pow in the worker finds the counter Node finds');
  let tried = 0;
  const far = await p.pow(prefix, 40, { deadline: Date.now() + 4000, onProgress: (n) => { tried = n; } });
  ok(far === null && tried >= 65536, `web: pow past its deadline: null, with progress on the way (${tried})`);
  const ac = new AbortController(), aborted = p.pow(prefix, 40, { signal: ac.signal });
  ac.abort();
  ok(await aborted === null, 'web: pow aborted: null');
  // The identity, sealed: a non-extractable AES-GCM key in IndexedDB's key store.
  const idf = enc(JSON.stringify({ v: 'sigelo/0', secret: 'ab'.repeat(32) }));
  ok(await W.loadIdentity(p2) === null, 'web: no identity yet: null');
  await W.saveIdentity(p2, idf);
  const sealed = p2.files.read('identity.sealed'), key = idb.dbs.get('t1').stores.get('keys').get('identity');
  ok(sealed && !dec(sealed).includes('abab') && key?.extractable === false && key.algorithm.name === 'AES-GCM', 'web: the identity is sealed (AES-GCM), its key not extractable');
  ok(dec(await W.loadIdentity(p2)) === dec(idf), 'web: and opens again');
  const p3 = await W.webPlatform({ name: 't1', indexedDB: idb, mqtt: mqttEsm });
  ok(dec(await W.loadIdentity(p3)) === dec(idf), 'web: after a reload too');
  const bad = p3.files.read('identity.sealed'); bad[20] ^= 1; p3.files.write('identity.sealed', bad);
  ok(await checkOf(() => W.loadIdentity(p3)) === 'identity', 'web: a sealed identity changed: refused, identity');
  // The network: wss only (ws:// to a loopback address for tests), and the carrier's transport.
  ok(await checkOf(() => p.mqtt('mqtts://relay.example:8883', {})) === 'connect' && await checkOf(() => p.mqtt('ws://relay.example/mqtt', {})) === 'connect', 'web: mqtt: mqtts:// and ws:// to a host refused, connect');
  const { Carrier } = await import(pathToFileURL(join(HERE, 'vendor', 'contact', 'carrier.mjs')).href);
  const ident = () => ({}), mk = (o) => new Carrier({ identity: ident, store: 's.json', state: 't.json', platform: p, ...o });
  ok(mk({}).transport === 'wss' && await checkOf(() => mk({ transport: 'mqtts' })) === 'transport: this platform carries wss', 'web: the carrier on this platform: auto is wss, mqtts refused');
  ok((await checkOf(() => new Carrier({ identity: ident, store: 's', state: 't' }))).startsWith('platform:'), 'web: in the page a carrier without a platform is refused (no Node default)');
}

// ================================================================ 3. router.mjs against the relay
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(REPO, 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) report(': parts 1 and 2; SKIP the router, no relay checkout (set SIGELO_RELAY_DIR)');
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { keygen } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href);
const nodeLib = await import(pathToFileURL(join(REPO, 'contact', 'carrier.mjs')).href);
const { makeRouter, IDENTITY } = await import(pathToFileURL(join(HERE, 'router.mjs')).href);

const HOST = 'relay.test', CREATED = '2026-10-01T00:00:00Z';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-web-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const relayOpts = { relay: HOST, endpoints, shortRelay: HOST, registry: false, retentionDays: 7, backoff: [100, 400] };
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-web-test/0 ${l}`).digest());
const hexOf = (b) => Buffer.from(b).toString('hex');
function agent(label) {
  const recovery = keygen({ seed: seed(`${label} recovery`), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} rn`).slice(0, 16) }).key;
  const k = keygen({ seed: seed(label), recovery, created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, did: k.did, secret: k.secret, store: { v: 'sigelo/0', secret: hexOf(k.secret), genesis: k.genesis, rotations: [], attestations: [], issuers: [] } };
}
// The flush rule, watched: a flush completed between any two PUBLISH or PUBACK (each waits for one),
// and while a flush is held (gate) nothing is published and nothing acknowledged.
const watch = { publishes: 0, acks: 0, unflushed: [], tick: 0 };
async function webApp(a, idb = new FakeIDB(), name = 'app') {
  const p = await W.webPlatform({ name, indexedDB: idb, mqtt: mqttEsm, pow: W.workerPow(() => new FakeWorker()), env: { relay: HOST } });
  let flushedAt = 0, sentAt = 0;
  const app = { idb, gate: null, flushing: 0, publishes: 0, acks: 0, delivered: 0 };
  const sending = (what) => { if (flushedAt <= sentAt) watch.unflushed.push(what); sentAt = ++watch.tick; };
  const platform = {
    ...p,
    flush: async () => { app.flushing++; try { if (app.gate) await app.gate.promise; await p.flush(); flushedAt = ++watch.tick; } finally { app.flushing--; } },
    mqtt: (url, opts) => {
      const client = p.mqtt(url, opts), pub = client.publish.bind(client);
      client.publish = (...x) => { watch.publishes++; app.publishes++; sending('PUBLISH'); return pub(...x); };
      let h;
      Object.defineProperty(client, 'handleMessage', { configurable: true, get: () => h, set: (f) => {
        h = (packet, done) => { app.delivered++; f(packet, () => { watch.acks++; app.acks++; sending('PUBACK'); done(); }); };
      } });
      return client;
    },
  };
  app.platform = platform;
  app.router = makeRouter({ platform, identity: () => a.store, options: relayOpts });
  return app;
}
const gated = (x) => { let open; x.gate = { promise: new Promise((r) => { open = r; }) }; return () => { x.gate = null; open(); }; };
const nodeAgent = (a) => new nodeLib.Carrier({ identity: () => ({ secret: a.secret, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: a.store.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } }),
  ...nodeLib.pathsFor(join(dir, `${a.label}.local.json`)), ...relayOpts, keep: true });

const ADA = agent('ada'), BO = agent('bo'), CY = agent('cy');
let A, B;
try {
  A = await webApp(ADA); B = await webApp(BO);
  const call = (x, m, p, b) => x.router.call(m, p, b);
  let changes = 0;
  A.router.onChange(() => { changes++; });
  await A.router.start(); await B.router.start();
  ok(A.router.carrier.transport === 'wss' && A.router.carrier.platform === A.platform, 'router: the carrier runs on the web platform, MQTT over WebSocket');
  const st0 = await call(A, 'GET', '/api/state?since=0');
  ok(st0.status === 200 && Object.keys(st0.body).sort().join() === 'events,groups,introductions,me,now,pending,seq' && st0.body.me.did === ADA.did
    && Object.keys(st0.body.me).sort().join() === 'clock_checked,clock_offset,did,error,online,pow,pow_done_ms,relay,retention_days,seat' && st0.body.me.seat === null,
  `GET /api/state: UI-API.md's keys, me.did (${JSON.stringify(st0.body).slice(0, 200)})`);
  const me = await call(A, 'GET', '/api/me');
  ok(me.status === 200 && me.body.did === ADA.did && me.body.original === ADA.did && me.body.chain.join() === ADA.did && me.body.key === 'browser' && me.body.identity_file === IDENTITY && me.body.recovery === 'set' && me.body.relay === HOST,
    `GET /api/me: the identity, key "browser" (${JSON.stringify(me.body).slice(0, 160)})`);
  ok(JSON.stringify((await call(A, 'GET', '/api/agents')).body) === '[]' && (await call(A, 'POST', '/api/agents/enrol', { agent: 'x' })).body.error.check === 'agent', 'agents: none in the app; enrol names none (404 agent)');
  const dv = await call(A, 'GET', '/api/devices'), add = await call(A, 'POST', '/api/devices/add', { name: 'x' });
  ok(dv.status === 200 && JSON.stringify(dv.body) === '{"devices":[],"list":null,"adding":[],"joining":null}' && add.status === 409 && add.body.error.check === 'not_here', 'devices: the list empty; adding one here refused (409 not_here)');
  const nr = await call(A, 'GET', '/api/nothing'), nb = await call(A, 'POST', '/api/send', [1]), nc = await call(A, 'POST', '/api/send', { to: 'did:sigelo:zNo', text: 'x' });
  ok(nr.status === 404 && nr.body.error.check === 'route' && nb.status === 400 && nb.body.error.check === 'body' && nc.status === 404 && nc.body.error.check === 'not_contact', 'errors as over HTTP: 404 route, 400 body, 404 not_contact');

  // Pairing 1: the app invites (a short code parked at the relay), a Node agent accepts.
  const node = nodeAgent(CY);
  const inv = await call(A, 'POST', '/api/invite', { name: 'cy' });
  ok(inv.status === 200 && /^[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(inv.body.short) && inv.body.code.startsWith('sgl1') && inv.body.relay === HOST, `POST /api/invite: a short code and the long one (${inv.body.short})`);
  const st1 = (await call(A, 'GET', '/api/state')).body;
  ok(st1.pending.invites.some((x) => x.id === inv.body.id && x.short === inv.body.short), 'GET /api/state: the invite pending, with its short code');
  const acc = await node.accept(inv.body.short, { name: 'ada', wait: 5 });
  await node.inbox({ wait: 1 });
  const paired = await until(async () => (await call(A, 'GET', '/api/state')).body.groups.contacts.some((c) => c.did === CY.did));
  const cyRow = (await call(A, 'GET', '/api/state')).body.groups.contacts.find((c) => c.did === CY.did);
  ok(paired && cyRow.name === 'cy' && cyRow.words === node.contacts().contacts[0].fingerprint, `pair: the Node agent accepted the app's short code; both hold the same four words (${acc.status})`);
  ok(Object.keys(cyRow).sort().join() === 'current_did,did,last,link,local,mine,name,not_collected,ours,pair,queued,re_pair,relay,status,tags,tier,unread,waiting,words,words_checked',
    `a contact in groups: UI-API.md's keys (${Object.keys(cyRow).sort()})`);
  ok(await until(async () => (await call(A, 'GET', '/api/state')).body.me.online), 'GET /api/state: online once paired, the session up (MQTT.js over WebSocket, proof of work in the worker)');
  ok((await call(A, 'GET', '/api/state')).body.pending.paired.some((x) => x.id === inv.body.id && x.paired === CY.did), 'GET /api/state: pending.paired names the invite that paired');
  ok((await call(A, 'POST', '/api/words', { contact: CY.did, match: true })).body.checked === true
    && (await call(A, 'GET', '/api/state')).body.groups.contacts.find((c) => c.did === CY.did).words_checked === true, 'POST /api/words: checked');

  // Pairing 2: a Node agent invites, the app accepts (the long code).
  const inv2 = await node.invite({ name: 'bo' });
  const acc2 = await call(B, 'POST', '/api/accept', { code: inv2.code, name: 'cy', tier: 'quiet' });
  ok(acc2.status === 200 && ['connected', 'waiting', 'pending'].includes(acc2.body.status), `POST /api/accept: the app accepted a Node agent's code (${JSON.stringify(acc2.body).slice(0, 120)})`);
  await node.inbox({ wait: 1 });
  ok(await until(async () => { await node.inbox({ wait: 0.2 }); return (await call(B, 'GET', '/api/state')).body.groups.contacts.some((c) => c.did === CY.did && c.tier === 'quiet'); }),
    'POST /api/accept: the Node agent is a contact of the app, at the tier asked (quiet)');

  // Send and read, both ways.
  const sent = await call(A, 'POST', '/api/send', { to: CY.did, text: 'hello from the page' });
  ok(sent.status === 200 && sent.body.kind === 'out' && sent.body.did === CY.did && ['sent', 'queued'].includes(sent.body.status) && sent.body.text === 'hello from the page', `POST /api/send: the history record (${sent.body.status})`);
  let read = [];
  ok(await until(async () => { read.push(...(await node.inbox({ wait: 0.5 })).messages); return read.some((m) => m.content === 'hello from the page'); }), 'the Node agent reads the page\'s message');
  const before = changes;
  await node.send('ada', 'and back to the page');
  ok(await until(async () => (await call(A, 'GET', `/api/messages?contact=${encodeURIComponent(CY.did)}`)).body.messages.some((m) => m.dir === 'in' && m.text === 'and back to the page')),
    'GET /api/messages: the Node agent\'s answer, in');
  ok(changes > before, `onChange: the message was pushed (${changes - before} changes)`);
  const msgs = (await call(A, 'GET', `/api/messages?contact=${encodeURIComponent(CY.did)}`)).body;
  ok(msgs.messages.map((m) => m.dir).join() === 'out,in' && Object.keys(msgs.messages[0]).sort().join() === 'at,code,detail,dir,label,n,status,text' && msgs.seq >= msgs.messages.at(-1).n,
    'GET /api/messages: both, in order, UI-API.md\'s keys');
  ok((await call(A, 'GET', '/api/state')).body.groups.contacts.find((c) => c.did === CY.did).unread === 0, 'read once shown: unread 0');
  const s1 = (await call(A, 'GET', '/api/state')).body, s2 = (await call(A, 'GET', `/api/state?since=${s1.seq}`)).body;
  ok(s1.events.some((e) => e.type === 'paired') && s2.events.length === 0, 'GET /api/state?since: events after since only');
  ok((await call(A, 'POST', '/api/tag', { contact: CY.did, tags: ['#work'] })).body.tags.join() === 'work' && (await call(A, 'POST', '/api/rename', { contact: CY.did, name: 'cyrus' })).body.name === 'cyrus'
    && (await call(A, 'POST', '/api/tier', { contact: CY.did, tier: 'quiet' })).body.tier === 'quiet', 'POST /api/tag, rename, tier');
  const links = await call(A, 'GET', '/api/links');
  ok(links.status === 200 && Object.keys(links.body).sort().join() === 'allow,links,made,received' && links.body.made.length === 0, `GET /api/links: {made, links, received, allow} (${JSON.stringify(links.body)})`);
  ok((await call(A, 'POST', '/api/sync')).body.synced === true, 'POST /api/sync');

  // The flush rule: no PUBLISH and no PUBACK without a flush completed since the one before it.
  ok(watch.publishes > 0 && watch.acks > 0 && watch.unflushed.length === 0, `flush rule: ${watch.publishes} PUBLISH, ${watch.acks} PUBACK, each after a flush (${watch.unflushed.slice(0, 3)})`);
  // And with the commit held: the message waits, then goes once it is committed.
  const p0 = A.publishes, release = gated(A);
  const held = call(A, 'POST', '/api/send', { to: CY.did, text: 'held by the commit' });
  ok(await until(() => A.flushing > 0, 5000) && (await sleep(1000), A.publishes === p0), `flush held: no PUBLISH while the state is not committed (${A.publishes - p0})`);
  release();
  ok((await held).body.status === 'sent' && A.publishes > p0, `flush released: then sent (${(await held).body.status})`);
  const d0 = A.delivered, a0 = A.acks, release2 = gated(A);
  await node.send('ada', 'acknowledged after the commit');
  ok(await until(() => A.delivered > d0, 15000) && (await sleep(1000), A.acks === a0), `flush held: a delivery saved, not acknowledged (${A.delivered - d0} in, ${A.acks - a0} acked)`);
  release2();
  ok(await until(() => A.acks > a0, 10000), 'flush released: then acknowledged');
  ok(await until(async () => (await call(A, 'GET', `/api/messages?contact=${encodeURIComponent(CY.did)}`)).body.messages.some((m) => m.text === 'acknowledged after the commit')), 'and read in the page');

  // One owner per identity: a second app on the same identity is refused while the first runs.
  const A2 = await webApp(ADA, new FakeIDB(), 'other');
  ok(await checkOf(() => A2.router.start()) === 'busy', 'one owner per identity: a second window of the app is refused, busy');

  // A restart from IndexedDB: the contacts, the history and the page's data come back.
  await A.router.stop(); await A.platform.flush();
  const again = await webApp(ADA, A.idb);
  await again.router.start();
  const sr = (await call(again, 'GET', '/api/state')).body, back = sr.groups.contacts.find((c) => c.did === CY.did) ?? sr.groups.mine.find((c) => c.did === CY.did);
  ok(back?.name === 'cyrus' && back.tags.join() === 'work' && back.words_checked === true && back.last?.text === 'acknowledged after the commit', `a restart from IndexedDB: the contact, tags, words and history kept (${JSON.stringify(back).slice(0, 160)})`);
  await call(again, 'POST', '/api/send', { to: CY.did, text: 'after the restart' });
  read = [];
  ok(await until(async () => { read.push(...(await node.inbox({ wait: 0.5 })).messages); return read.some((m) => m.content === 'after the restart'); }), 'and it sends again: the ratchet state came back whole');
  ok((await call(again, 'POST', '/api/history/clear')).body.cleared === true && (await call(again, 'GET', `/api/messages?contact=${encodeURIComponent(CY.did)}`)).body.messages.length === 0, 'POST /api/history/clear');
  ok((await call(again, 'POST', '/api/forget', { contact: CY.did })).body.forgotten === CY.did, 'POST /api/forget');
  ok(!existsSync(join(dir, 'app')) && !existsSync(join(process.cwd(), 'app')), 'nothing of the app reached the disk');
  await again.router.stop(); A = null;
  await node.stop?.();
} finally {
  try { await A?.router.stop(); } catch {}
  try { await B?.router.stop(); } catch {}
  await relay.close?.();
  rmSync(dir, { recursive: true, force: true });
}
report();
