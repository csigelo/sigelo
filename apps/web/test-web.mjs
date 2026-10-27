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
import { execFileSync, spawnSync } from 'node:child_process';
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
  const own = ['app.mjs', 'router.mjs', 'platform-web.mjs', 'platform-stub.mjs', 'pow-worker.mjs', 'platform-android.mjs', 'ws-over-stream.mjs', 'shell.mjs', 'seed.mjs', 'create.mjs'].map((f) => readFileSync(join(HERE, f), 'utf8'));
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

// ================================================================ 2b. the relay setting (router.mjs, contact/page.mjs), no relay needed
{
  const { makeRouter: mk, presetRelay } = await import(pathToFileURL(join(HERE, 'router.mjs')).href);
  const { keygen: kg } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href);
  const k = kg({ seed: new Uint8Array(32).fill(3), recovery: 'sha256:' + '0'.repeat(64), created: '2026-10-01T00:00:00Z', nonce: new Uint8Array(16).fill(3) });
  const store = { v: 'sigelo/0', secret: Buffer.from(k.secret).toString('hex'), genesis: k.genesis, rotations: [], attestations: [], issuers: [] };
  const idb = new FakeIDB(), plat = () => W.webPlatform({ name: 'set', indexedDB: idb, mqtt: mqttEsm, pow: W.workerPow(() => new FakeWorker()) });
  const p1 = await plat(), r1 = mk({ platform: p1, identity: () => store, options: { registry: false } });
  const s0 = (await r1.call('GET', '/api/settings')).body;
  ok(s0.relay === 'relay.sigelo.ai' && s0.fixed === null && r1.carrier.relay === 'relay.sigelo.ai', `settings: none kept → relay.sigelo.ai, nothing fixed (${JSON.stringify(s0)})`);
  const bad = await r1.call('POST', '/api/settings', { relay: 'not a host' }), set = await r1.call('POST', '/api/settings', { relay: 'corp.example.com' });
  ok(bad.status === 400 && bad.body.error.check === 'body' && set.status === 200 && set.body.relay === 'corp.example.com' && set.body.in_use === 'relay.sigelo.ai', `settings: a bad host 400; corp.example.com kept, in use at the next start (${JSON.stringify(set.body)})`);
  // The next invite names the setting at once (the carrier's invite, watched: no relay needed).
  let asked = null;
  r1.carrier.invite = async (o) => { asked = o; return { code: 'sgl1x', did: k.did, relay: o.relay ?? r1.carrier.relay, exp: 1 }; };
  const inv = await r1.call('POST', '/api/invite', { name: 'x' });
  ok(inv.status === 200 && asked?.relay === 'corp.example.com' && inv.body.relay === 'corp.example.com', `settings: the next invite names corp.example.com at once (${JSON.stringify(asked)})`);
  await p1.flush();
  const p2 = await plat(), r2 = mk({ platform: p2, identity: () => store, options: { registry: false } });
  const s2 = (await r2.call('GET', '/api/settings')).body;
  ok(s2.relay === 'corp.example.com' && r2.carrier.relay === 'corp.example.com', `settings: kept across a reload (platform.files, IndexedDB): the carrier's own relay now (${JSON.stringify(s2)})`);
  const r3 = mk({ platform: p2, identity: () => store, options: { registry: false, relay: 'relay.test' } });
  const s3 = (await r3.call('GET', '/api/settings')).body;
  ok(s3.fixed === 'relay.test' && s3.relay === 'corp.example.com' && r3.carrier.relay === 'relay.test', `settings: options.relay (or env.relay) is fixed and wins (${JSON.stringify(s3)})`);
  const rel = await r2.call('GET', '/api/relays');
  ok(rel.status === 200 && Array.isArray(rel.body.relays) && rel.body.relays.length === 0, 'GET /api/relays: no registry and no cache → []');
  // The first-start form: presetRelay before any router.
  const idb2 = new FakeIDB(), p4 = await W.webPlatform({ name: 'pre', indexedDB: idb2, mqtt: mqttEsm });
  presetRelay(p4.files, ' Self.Example.org ');
  const r4 = mk({ platform: p4, identity: () => store, options: { registry: false } });
  ok(r4.carrier.relay === 'self.example.org' && (await r4.call('GET', '/api/settings')).body.relay === 'self.example.org', 'presetRelay: the first-start form\'s relay is the setting and the carrier\'s relay');
  presetRelay(p4.files, 'relay.sigelo.ai');
  ok(await checkOf(() => presetRelay(p4.files, 'not a host')) === 'code_relay' && (await mk({ platform: p4, identity: () => store, options: { registry: false } }).call('GET', '/api/settings')).body.relay === 'relay.sigelo.ai',
    'presetRelay: the default keeps none; not a host refused');
  const appSrc = readFileSync(join(HERE, 'app.mjs'), 'utf8');
  ok(/presetRelay\(platform\.files, relay\.value\)/.test(appSrc) && /value: DEFAULT_RELAY/.test(appSrc) && appSrc.includes('A 12-character code always names its own relay'), 'app.mjs: the import form shows the relay, relay.sigelo.ai pre-filled');
}


// ================================================================ 2c. restore from seed (seed.mjs, contact/restore.mjs), no relay needed
{
  const SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href);
  const { makeRouter: mk } = await import(pathToFileURL(join(HERE, 'router.mjs')).href);
  const { did: didOf } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href);
  const { mnemonicFromRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
  // A fixed test mnemonic (a canonical root, < l), and what `sigelo-agent keeper --from-words` makes of it.
  const S0 = new Uint8Array(32).fill(9); S0[31] = 0x0e;
  const words = mnemonicFromRoot(S0), H = mkdtempSync(join(tmpdir(), 'sigelo-seed-')), op = join(H, 'me.local.json');
  const cli = spawnSync(process.execPath, [join(REPO, 'adapters', 'moadim', 'cli.ts'), 'keeper', '--from-words', '--identity', op], { env: { PATH: process.env.PATH, HOME: H, SIGELO_KEY_PROVIDER: 'file' }, input: words, encoding: 'utf8' });
  const cMe = JSON.parse(readFileSync(op, 'utf8')), cK = JSON.parse(readFileSync(join(H, 'me.local.keeper.json'), 'utf8'));
  rmSync(H, { recursive: true, force: true });
  const idb = new FakeIDB(), p = await W.webPlatform({ name: 'seed', indexedDB: idb, mqtt: mqttEsm, pow: W.workerPow(() => new FakeWorker()) });
  const r = await SD.restoreInto(p, { words: `  ${words.toUpperCase().replace(/ /g, '\n')}  `, name: 'phone', relay: 'relay.sigelo.ai', now: 1761400000 });
  const me = JSON.parse(new TextDecoder().decode(await W.loadIdentity(p))), kp = JSON.parse(new TextDecoder().decode(await W.loadSealed(p, 'keeper')));
  ok(cli.status === 0 && r.did === didOf(cMe.genesis) && didOf(me.genesis) === didOf(cMe.genesis) && JSON.stringify(me) === JSON.stringify(cMe),
    `restore: the page derives the operator identity keeper --from-words writes for the same 25 words: the same DID, the same file (${r.did})`);
  ok(kp.root_hex === cK.root_hex && kp.recovery === cK.recovery && kp.keeper === cK.keeper && JSON.stringify(kp.me) === JSON.stringify(cK.me) && kp.v === cK.v,
    'restore: the same keeper root K_1 (hex), recovery commitment and me as keeper --from-words');
  ok(kp.created === '2025-10-25' && kp.net === 'mainnet' && kp.restore_height === 0 && kp.workers[0].rank === 'full' && kp.workers[0].placed === 'device',
    'restore: the keeper\'s metadata: created (UTC day), net, restore_height (0: no height or date given), this device worker 0 FULL');
  const stored = [...idb.dbs.get('seed').stores.get('files').values()].map((v) => Buffer.from(v).toString('latin1')).join('\n');
  ok(p.files.read('identity.sealed') !== null && p.files.read('keeper.sealed') !== null && !stored.includes(cK.root_hex) && !stored.includes(cMe.secret) && !stored.includes(words.split(' ').slice(0, 3).join(' ')) && idb.dbs.get('seed').stores.get('keys').has('identity'),
    'restore: in a browser both sealed under the WebCrypto key (non-extractable, IndexedDB); no word, key or K in the clear');
  const seat = SD.seatOf(p, () => me), router = mk({ platform: p, identity: () => me, mode: { kind: 'full', standby: false }, seat, options: { registry: false } });
  const m = (await router.call('GET', '/api/me')).body, st = (await router.call('GET', '/api/state')).body;
  ok(m.restored?.on === '2025-10-25' && m.restored.keeper === 1 && m.restored.seat === 'here' && st.me.seat?.here === true && st.me.seat.holder === 'phone' && router.mode().standby === false,
    `router: GET /api/me says restored (day, keeper 1, seat here); GET /api/state me.seat: this phone holds it (${JSON.stringify(m.restored)})`);
  ok((await router.call('POST', '/api/seat/take', { confirm: true })).body.error?.check === 'seat_here', 'router: POST /api/seat/take with the seat here → 409 seat_here');
  // Agents (the app's main list): the sealed keeper's roster; this device is worker 0, FULL, the one agent here.
  const rk = mk({ platform: p, identity: () => me, mode: { kind: 'full', standby: false }, seat, keeper: SD.keeperOf(p), options: { registry: false } });
  const wk = (await rk.call('GET', '/api/agents/workers')).body, none = (await router.call('GET', '/api/agents/workers')).body;
  ok(wk.keeper === true && wk.seat === 'here' && wk.workers.length === 1 && wk.workers[0].worker === 0 && wk.workers[0].name === 'phone' && wk.workers[0].rank === 'full' && wk.workers[0].placed === 'device'
    && wk.workers[0].status === 'enrolled' && wk.workers[0].local === 'phone' && none.keeper === false && none.workers.length === 0,
    `router: GET /api/agents/workers from the sealed keeper: this device, worker 0, FULL; without the keeper hook: none (${JSON.stringify(wk).slice(0, 200)})`);
  const bads = [await rk.call('POST', '/api/agents/enrol-code', { name: 'Bad Name' }), await rk.call('POST', '/api/agents/enrol-code', { name: 'phone' }), await rk.call('POST', '/api/agents/revoke', { worker: 0 }),
    await router.call('POST', '/api/agents/enrol-code', { name: 'vps' })];
  ok(JSON.stringify(bads.map((x) => [x.status, x.body.error?.check])) === JSON.stringify([[400, 'body'], [409, 'name_taken'], [409, 'device'], [400, 'keeper']]),
    `router: enrol-code a bad name 400, a name the roster has 409 name_taken; revoke this device 409 device (Devices); no keeper 400 keeper (${JSON.stringify(bads.map((x) => x.body.error?.check))})`);
  // Standby: the seat on another device. Started, it never logs in; writes refused seat_elsewhere; reads answer.
  const p2 = await W.webPlatform({ name: 'seed2', indexedDB: new FakeIDB(), mqtt: mqttEsm, pow: W.workerPow(() => new FakeWorker()) });
  await SD.restoreInto(p2, { words, name: 'tab', relay: 'relay.sigelo.ai', restore: { restore_height: 3100000 }, seat: 'elsewhere', now: 1761400000 });
  const me2 = JSON.parse(new TextDecoder().decode(await W.loadIdentity(p2))), r2 = mk({ platform: p2, identity: () => me2, mode: { kind: 'full', standby: true }, seat: SD.seatOf(p2, () => me2), options: { registry: false } });
  let started = 0;
  r2.carrier.start = async () => { started++; };
  r2.carrier.checkClock = async () => {};
  await r2.start();
  const st2 = await r2.call('GET', '/api/state'), w2 = await r2.call('POST', '/api/send', { to: 'did:sigelo:zX', text: 'x' }), inv = await r2.call('POST', '/api/invite', {});
  ok(started === 0 && st2.status === 200 && st2.body.me.seat?.here === false && w2.status === 409 && w2.body.error.check === 'seat_elsewhere' && inv.body.error?.check === 'seat_elsewhere',
    `standby: started without logging in; GET /api/state shows the seat elsewhere (the banner); send and invite refused seat_elsewhere (${w2.status})`);
  const r2k = mk({ platform: p2, identity: () => me2, mode: { kind: 'full', standby: true }, seat: SD.seatOf(p2, () => me2), keeper: SD.keeperOf(p2), options: { registry: false } });
  r2k.carrier.start = async () => {}; r2k.carrier.checkClock = async () => {};
  const ws2 = (await r2k.call('GET', '/api/agents/workers')).body, ec2 = await r2k.call('POST', '/api/agents/enrol-code', { name: 'vps' });
  ok(ws2.keeper === true && ws2.seat === 'elsewhere' && ec2.status === 409 && ec2.body.error.check === 'seat_elsewhere',
    `standby: the agents list reads (the seat elsewhere); enrol-code refused seat_elsewhere: indices are given at the seat only (${ec2.status})`);
  const noConfirm = await r2.call('POST', '/api/seat/take', {});
  ok(noConfirm.status === 400 && started === 0, 'standby: POST /api/seat/take without confirm → 400, nothing started');
  const tk = await r2.call('POST', '/api/seat/take', { confirm: true });
  ok(tk.status === 200 && tk.body.seat === 'here' && tk.body.holder === 'tab' && started === 1 && (await r2.call('GET', '/api/state')).body.me.seat.here === true && r2.mode().standby === false,
    `seat take: the list signed naming this device, the page starts as the operator (${JSON.stringify(tk.body)})`);
  await r2.stop();
}

// ================================================================ 2d. create a new identity (create.mjs, contact/create.mjs), no relay needed
{
  const CV = await import(pathToFileURL(join(HERE, 'create.mjs')).href);
  const CR = await import(pathToFileURL(join(HERE, 'vendor', 'contact', 'create.mjs')).href);
  const SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href);
  const { makeRouter: mk } = await import(pathToFileURL(join(HERE, 'router.mjs')).href);
  const { did: didOf } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href);
  const now = Math.floor(Date.now() / 1000), today = new Date(now * 1000).toISOString().slice(0, 10);
  const s = CR.newSeed('stagenet'), list = s.words(), words = list.join(' ');
  const leaks = (text) => { const t = String(text).toLowerCase(); for (let i = 0; i + 3 <= list.length; i++) if (t.includes(list.slice(i, i + 3).join(' '))) return true; return false; };
  // What the CLI writes for the same words: keeper --from-words --made-here, the birth today (as the GTK app runs it).
  const H = mkdtempSync(join(tmpdir(), 'sigelo-create-')), op = join(H, 'me.local.json');
  const cli = spawnSync(process.execPath, [join(REPO, 'adapters', 'moadim', 'cli.ts'), 'keeper', '--from-words', '--made-here', '--net', 'stagenet', '--restore-date', today, '--identity', op],
    { env: { PATH: process.env.PATH, HOME: H, SIGELO_KEY_PROVIDER: 'file' }, input: words, encoding: 'utf8' });
  const cMe = JSON.parse(readFileSync(op, 'utf8')), cK = JSON.parse(readFileSync(join(H, 'me.local.keeper.json'), 'utf8'));
  rmSync(H, { recursive: true, force: true });
  const idb = new FakeIDB(), p = await W.webPlatform({ name: 'create', indexedDB: idb, mqtt: mqttEsm, pow: W.workerPow(() => new FakeWorker()) });
  ok(await checkOf(() => CV.createInto(p, s, { name: 'phone', relay: 'relay.sigelo.ai', now })) === 'create_unchecked' && p.files.read('identity.sealed') === null && W.network.held === 0,
    'create: nothing made before three words are typed back (create_unchecked), nothing stored, the network released');
  const q = s.quiz(), bad = s.check(q.map((x, i) => (i === 2 ? (list[x % 25] === list[x - 1] ? 'zzz' : list[x % 25]) : list[x - 1])));
  ok(bad.ok === false && bad.wrong.join() === String(q[2]) && await checkOf(() => CV.createInto(p, s, { name: 'phone', relay: 'relay.sigelo.ai', now })) === 'create_unchecked',
    'create, the check: a wrong word refused, named by its number; still nothing made');
  const said = [], keep = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  for (const k of Object.keys(keep)) console[k] = (...a) => { said.push(a.map(String).join(' ')); };
  const q2 = s.quiz(), good = s.check(q2.map((x) => list[x - 1]));
  let r;
  try { r = await CV.createInto(p, s, { name: 'phone', relay: 'relay.sigelo.ai', now }); } finally { Object.assign(console, keep); }
  const me = JSON.parse(new TextDecoder().decode(await W.loadIdentity(p))), kp = JSON.parse(new TextDecoder().decode(await W.loadSealed(p, 'keeper')));
  ok(cli.status === 0 && good.ok && r.did === didOf(cMe.genesis) && JSON.stringify(me) === JSON.stringify(cMe),
    `create: the operator identity is the file keeper --from-words writes for the same 25 words (${r.did})`);
  ok(kp.root_hex === cK.root_hex && kp.recovery === cK.recovery && JSON.stringify(kp.me) === JSON.stringify(cK.me) && kp.made === 'here' && cK.made === 'here' && kp.net === cK.net && kp.restore_date === today && cK.restore_date === today && kp.created === cK.created,
    'create: the same K_1, recovery and me; made here, stagenet, created and the wallet\'s birth today, as keeper --from-words --made-here');
  ok(r.vault === s.vault && r.vault.startsWith('5') && kp.workers[0].rank === 'full' && kp.workers[0].placed === 'device', 'create: the vault address shown is the words\' own stagenet wallet; this device worker 0, FULL');
  const stored = [...idb.dbs.get('create').stores.get('files').values()].map((v) => Buffer.from(v).toString('latin1')).join('\n');
  ok(!leaks(stored) && !stored.includes(cK.root_hex) && !stored.includes(cMe.secret) && said.length === 0, `create: no word, key or K in the app's storage in the clear; nothing logged (${said.length})`);
  ok(await checkOf(() => s.words()) === 'create_spent' && await checkOf(() => s.quiz()) === 'create_spent', 'create: after acceptance the words are gone (create_spent): nothing gives them again');
  const router = mk({ platform: p, identity: () => me, mode: { kind: 'full', standby: false }, seat: SD.seatOf(p, () => me), options: { registry: false } });
  const m = (await router.call('GET', '/api/me')).body, st = (await router.call('GET', '/api/state')).body, set = (await router.call('GET', '/api/settings')).body;
  ok(m.restored?.created === true && m.restored.on === today && m.restored.seat === 'here' && st.me.seat?.here === true && router.mode().standby === false,
    `router: GET /api/me says created here (Me: "Created on ${today}"), the seat here (${JSON.stringify(m.restored)})`);
  ok(![m, st, set].some((x) => leaks(JSON.stringify(x))), 'router: no route answers any of the 25 words');
}

// ================================================================ 2e. ui.js (what ships, vendor/ui.js): the Agents screens over a fake backend
// in a minimal DOM: the list from GET /api/agents/workers, the two-button bar, Enrol (name, tier, the relay picker
// with its Test before OK, the code big, the four words, enrolled), an agent's details and Revoke.
{
  const vm = await import('node:vm');
  class Node_ { constructor() { this.parent = null; } }
  class Text_ extends Node_ { constructor(t) { super(); this.data = String(t); } get textContent() { return this.data; } }
  class El extends Node_ {
    constructor(tag) { super(); Object.assign(this, { tagName: tag.toUpperCase(), kids: [], attrs: {}, on: {}, style: {}, dataset: {}, className: '', value: '', disabled: false, hidden: false, checked: false }); }
    get textContent() { return this.kids.map((k) => k.textContent).join(''); }
    set textContent(t) { this.kids = [new Text_(t)]; }
    append(...k) { for (const x of k) { const n = x instanceof Node_ ? x : new Text_(x); n.parent = this; this.kids.push(n); } }
    replaceChildren(...k) { this.kids = []; this.append(...k); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(t, f) { (this.on[t] ??= []).push(f); }
    focus() {}
    getContext() { return null; }
    all() { return [this, ...this.kids.filter((k) => k instanceof El).flatMap((k) => k.all())]; }
    async click() { const ev = { preventDefault() {}, stopImmediatePropagation() {}, target: this }; for (const f of this.on.click ?? []) await f(ev); }
  }
  const root = new El('main'), intervals = [];
  const W_ = { workers: [{ worker: 0, name: 'phone', did: 'did:sigelo:zPhone000000000000000000000000000000000000000000', original: 'did:sigelo:zPhone000000000000000000000000000000000000000000', rank: 'full', placed: 'device', at: 1761400000, status: 'enrolled', revoked: null, seen: null, tier: null, contact: null, local: 'phone', attested_until: null, enrolling: null }] };
  const calls = [], now = () => Math.floor(Date.now() / 1000);
  const snap = () => ({ seq: 1, now: now(), me: { did: 'did:sigelo:zMe', relay: 'relay.sigelo.ai', online: true, clock_offset: 0, clock_checked: now(), retention_days: 7, error: null, pow: null, pow_done_ms: null, seat: { holder: 'phone', epoch: 1, here: true } },
    groups: { mine: [], contacts: [] }, pending: { invites: [], paired: [], answers: [], failed: [] }, introductions: [], events: [] });
  const routes = {
    'GET /api/state': () => snap(),
    'GET /api/agents/workers': () => ({ keeper: true, seat: 'here', workers: W_.workers }),
    'GET /api/settings': () => ({ relay: 'relay.sigelo.ai', default: 'relay.sigelo.ai', fixed: null, in_use: 'relay.sigelo.ai' }),
    'GET /api/relays': () => ({ relays: [{ tag: 'ex', host: 'relay.example.org', tier: 'community' }] }),
    'POST /api/relays/test': (b) => (b.relay === 'down.example.org' ? { relay: b.relay, ok: false, ms: 5000, retention_days: null, detail: 'cannot reach the relay' } : { relay: b.relay, ok: true, ms: 42, retention_days: 7 }),
    'POST /api/agents/enrol-code': (b) => {
      const e = { id: 'n1', state: 'code', code: 'K7F3-Q9ZP', exp: now() + 600, relay: b.relay ?? 'relay.sigelo.ai', words: null, command: `SIGELO_RELAY=${b.relay} sigelo-agent init --enrol K7F3-Q9ZP` };
      W_.workers.push({ worker: 1, name: b.name, did: 'did:sigelo:zVps0000000000000000000000000000000000000000000', original: 'did:sigelo:zVps0000000000000000000000000000000000000000000', rank: null, placed: 'remote', at: now(), status: 'pending', revoked: null, seen: null, tier: null, contact: null, local: null, attested_until: now() + 90 * 86400, enrolling: e });
      return { worker: 1, name: b.name, did: W_.workers[1].did, original: W_.workers[1].did, tier: b.tier ?? 'own', ...e };
    },
    'POST /api/words': () => ({ checked: true }),
    'POST /api/agents/revoke': (b) => { const w = W_.workers.find((x) => x.worker === b.worker); w.status = 'revoked'; w.revoked = now(); return { worker: b.worker, name: w.name, cancelled: false, revoked: w.revoked, forgot: w.contact }; },
  };
  const sandbox = {
    document: { getElementById: () => root, createElement: (t) => new El(t), createTextNode: (t) => new Text_(t), querySelectorAll: () => [], body: { scrollHeight: 0 } },
    Node: Node_, location: { hash: '', pathname: '/', protocol: 'https:' }, history: { replaceState() {} }, sessionStorage: { getItem: () => null, setItem() {} },
    window: { innerHeight: 800, innerWidth: 400, scrollY: 0, scrollTo() {} }, navigator: { clipboard: { writeText: async (t) => { sandbox.copied = t; } } }, confirm: () => true,
    setInterval: (f, ms) => { intervals.push([f, ms]); return intervals.length; }, clearInterval() {}, setTimeout: (f, ms) => setTimeout(f, Math.min(ms ?? 0, 10)), clearTimeout,
    console, Date, Promise, Object, Array, String, Number, JSON, Math, Map, Set, Error, encodeURIComponent, URL,
    sigeloLocal: {
      async call(method, path, body) { calls.push([method, path, body]); const f = routes[`${method} ${path.split('?')[0]}`]; return f ? { status: 200, body: JSON.parse(JSON.stringify(f(body ?? {}))) } : { status: 404, body: { error: { check: 'route', message: `no ${method} ${path}` } } }; },
      onChange() {}, mode: () => ({ kind: 'full' }),
    },
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(readFileSync(join(HERE, 'vendor', 'ui.js'), 'utf8'), sandbox);
  const settle = () => sleep(30);
  const poll = async () => { await intervals.find(([, ms]) => ms === 2000)[0](); await settle(); };
  const btn = (t) => root.all().find((e) => e.tagName === 'BUTTON' && e.textContent === t);
  const has = (t) => root.textContent.includes(t);
  await settle(); await poll();
  const rows = root.all().filter((e) => e.className === 'row agent');
  ok(root.all().some((e) => e.tagName === 'H1' && e.textContent === 'Agents') && rows.length === 1 && rows[0].textContent.includes('phone') && rows[0].textContent.includes('FULL') && rows[0].textContent.includes('a device')
    && calls.some(([m, p]) => m === 'GET' && p === '/api/agents/workers'), 'ui.js: the first screen is Agents, a row per worker from GET /api/agents/workers (name, rank, where)');
  const foot = root.all().find((e) => e.className === 'inner two');
  ok(foot?.kids.map((k) => k.textContent).join() === 'Enrol,Invite' && foot.kids.every((k) => k.className === 'primary' && !k.disabled), 'ui.js: the two-button bar, Enrol and Invite, equal, both ready (a keeper, the seat here)');
  await btn('Enrol').click(); await settle();
  const nameIn = root.all().find((e) => e.attrs['aria-label'] === 'Agent name');
  nameIn.value = 'vps';
  await btn('Friend: low trust, tell me').click(); await settle();
  await btn('Change').click(); await settle();
  ok(has('relay.sigelo.ai') && btn('Show the public registry') && root.all().some((e) => e.className === 'row current'), 'enrol: the relay picker: the one in use marked, the registry on demand');
  await btn('Show the public registry').click(); await settle();
  const custom = root.all().find((e) => e.attrs['aria-label'] === 'Relay host');
  custom.value = 'down.example.org';
  await btn('OK').click(); await settle();
  ok(has('NO ANSWER: cannot reach the relay') && btn('Close') && btn('OK') && !root.all().some((e) => e.tagName === 'SPAN' && e.textContent === 'down.example.org') && calls.some(([m, p, b]) => p === '/api/relays/test' && b.relay === 'down.example.org'),
    'enrol picker: OK tests first: a relay that does not answer is not taken (NO ANSWER, why)');
  custom.value = 'relay.example.org';
  await btn('OK').click(); await settle();
  ok(root.all().some((e) => e.tagName === 'SPAN' && e.textContent === 'relay.example.org') && !btn('OK'), 'enrol picker: a relay that answers is tested, then taken for this code; the picker closes');
  await btn('Make the code').click(); await settle();
  const made = calls.find(([, p]) => p === '/api/agents/enrol-code');
  const big = root.all().find((e) => e.className === 'code big');
  ok(JSON.stringify(made?.[2]) === JSON.stringify({ name: 'vps', tier: 'friend', relay: 'relay.example.org' }) && big?.textContent === 'K7F3-Q9ZP' && has('left · once') && has('sigelo-agent init --enrol K7F3-Q9ZP')
    && has('… waiting for the agent to enter it'), `enrol: POST /api/agents/enrol-code {name, tier, relay}; the code shown big with its countdown and the command (${JSON.stringify(made?.[2])})`);
  await btn('Copy').click();
  ok(sandbox.copied === 'K7F3-Q9ZP', 'enrol: Copy puts the code on the clipboard');
  Object.assign(W_.workers[1].enrolling, { state: 'words', code: null, command: null, words: 'mobile absent bone lion' });
  await poll();
  ok(!root.all().some((e) => e.className === 'code big') && root.all().find((e) => e.className === 'words')?.textContent === 'mobileabsentbonelion' && btn('They match') && btn("They don't") && has('✓ the agent entered it and paired'),
    'enrol: once the agent pairs, the code goes and the four words show (They match / They don\'t)');
  await btn('They match').click(); await settle();
  Object.assign(W_.workers[1], { status: 'enrolled', contact: 'did:sigelo:zVps0000000000000000000000000000000000000000000', tier: 'friend' });
  W_.workers[1].enrolling.state = 'enrolled';
  await poll();
  ok(has('✓ vps is your agent: worker 1') && has('✓ Words checked') && calls.some(([m, p, b]) => p === '/api/words' && b.contact === W_.workers[1].contact && b.match === true) && btn('Done') && btn('Open conversation'),
    'enrol: enrolled: said, its words marked checked on its contact (POST /api/words), Done and Open conversation');
  await btn('Done').click(); await settle(); await poll();
  const rows2 = root.all().filter((e) => e.className === 'row agent');
  ok(rows2.length === 2 && rows2[1].textContent.includes('vps') && rows2[1].textContent.includes('enrolled') && rows2[1].textContent.includes('friend') && rows2[1].textContent.includes('on another machine'),
    'agents: back on the list, vps enrolled, friend, on another machine');
  await rows2[1].click(); await settle(); await poll();
  ok(root.all().some((e) => e.tagName === 'H1' && e.textContent === 'vps') && has('Worker: 1 of your keeper root') && has(W_.workers[1].did) && btn('Rename') && btn('Revoke'), 'agent details: worker, DID, Rename, Revoke');
  await btn('Revoke').click(); await settle();
  ok(calls.some(([m, p, b]) => p === '/api/agents/revoke' && b.worker === 1) && has('revoked') && !btn('Revoke'), 'agent details: Revoke (confirmed) → POST /api/agents/revoke; shown revoked, no Revoke left');
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
  ok(msgs.messages.map((m) => m.dir).join() === 'out,in' && Object.keys(msgs.messages[0]).sort().join() === 'at,code,detail,dir,label,link,n,status,text' && msgs.seq >= msgs.messages.at(-1).n,
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

  // Enrol from the app (the operator's own: restored from seed, the seat here): a one-time code made on the app's own
  // session; a Node machine pairs through it as a temporary identity (enrol.mjs accept), is sent worker 1 and pairs
  // as it (complete, place); the app files it: the Agents list shows it enrolled.
  {
    const SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href), E = await import(pathToFileURL(join(REPO, 'contact', 'enrol.mjs')).href);
    const { mnemonicFromRoot, keeperRoot, agentIdentitySeed } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
    const S0 = new Uint8Array(32).fill(7); S0[31] = 0x0d;
    const ip = await W.webPlatform({ name: 'op', indexedDB: new FakeIDB(), mqtt: mqttEsm, pow: W.workerPow(() => new FakeWorker()), env: { relay: HOST } });
    await SD.restoreInto(ip, { words: mnemonicFromRoot(S0), name: 'phone', relay: HOST, now: Math.floor(Date.now() / 1000) });
    const opMe = JSON.parse(new TextDecoder().decode(await W.loadIdentity(ip)));
    const O = makeRouter({ platform: ip, identity: () => opMe, mode: { kind: 'full', standby: false }, seat: SD.seatOf(ip, () => opMe), keeper: SD.keeperOf(ip), options: relayOpts });
    await O.start();
    try {
      const ec = await O.call('POST', '/api/agents/enrol-code', { name: 'vps', tier: 'quiet' });
      ok(ec.status === 200 && ec.body.worker === 1 && /^[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(ec.body.code) && ec.body.state === 'code' && ec.body.command === `SIGELO_RELAY=${HOST} sigelo-agent init --enrol ${ec.body.code}`,
        `app enrol: POST /api/agents/enrol-code → worker 1 (after this device), an 8-character code, the command (${JSON.stringify(ec.body).slice(0, 160)})`);
      const tk = keygen({ recovery: 'sha256:' + '1'.repeat(64) }), tempFile = join(dir, 'vps.enrol-t.local.json'), file = E.enrolPath(join(dir, 'vps.local.json'));
      const tc = new nodeLib.Carrier({ identity: () => ({ secret: tk.secret, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: tk.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } }),
        ...nodeLib.pathsFor(tempFile), ...relayOpts, keep: true });
      let worker = null;
      const place = async (x) => {
        worker = x.identity;
        const sec = Uint8Array.from(Buffer.from(x.identity.secret, 'hex'));
        const wc = new nodeLib.Carrier({ identity: () => ({ secret: sec, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: x.identity.genesis, rotations: x.identity.rotations, bindings: [], attestations: x.identity.attestations, issuers: x.identity.issuers } }),
          ...nodeLib.pathsFor(join(dir, 'vps.local.json')), ...relayOpts, keep: true });
        try { return await wc.accept(x.invite, { name: 'operator', wait: 20 }); } finally { await wc.stop(); }
      };
      let res;
      try {
        const j = await E.accept({ carrier: tc, file, code: ec.body.code, name: 'operator', wait: 10, temp: tempFile });
        const seenWords = await until(async () => (await O.call('GET', '/api/agents/workers')).body.workers.find((w) => w.worker === 1)?.enrolling?.words);
        const words = (await O.call('GET', '/api/agents/workers')).body.workers.find((w) => w.worker === 1)?.enrolling?.words;
        ok(seenWords && words === j.contact?.fingerprint, `app enrol: the machine paired through the code; the app shows the same four words (${words})`);
        res = await E.complete({ carrier: tc, file, temp: tempFile, wait: 60, until: (o) => o.placed.length > 0, place });
      } finally { await tc.stop(); }
      const K1 = keeperRoot(S0, 1);
      ok(res.placed.length === 1 && worker?.secret === Buffer.from(agentIdentitySeed(K1, 1, 0)).toString('hex'), `app enrol: the machine received worker 1 of the app's keeper root, end to end (${JSON.stringify(res.refused)})`);
      const enrolled = await until(async () => { const w = (await O.call('GET', '/api/agents/workers')).body.workers.find((x) => x.worker === 1); return w?.status === 'enrolled' && w.contact ? w : null; }, 30000);
      const w1 = (await O.call('GET', '/api/agents/workers')).body.workers.find((x) => x.worker === 1), st = (await O.call('GET', '/api/state')).body;
      ok(enrolled && w1.placed === 'remote' && w1.tier === 'quiet' && w1.enrolling?.state === 'enrolled' && st.groups.mine.some((c) => c.did === w1.contact && c.ours === true && c.name === 'vps')
        && ![...st.groups.mine, ...st.groups.contacts].some((c) => c.name.includes('(enrolling)')) && !st.pending.invites.some((x) => x.name.includes('(enrolling)')),
        `app enrol: the list shows it enrolled (remote, quiet as chosen), in Mine as ours; nothing of the temporary pairing shows (${JSON.stringify(w1).slice(0, 240)})`);
      const kp = JSON.parse(new TextDecoder().decode(await W.loadSealed(ip, 'keeper')));
      ok(kp.workers['1']?.name === 'vps' && kp.workers['1'].placed === 'remote' && ip.files.read('keeper.sealed') !== null && !Buffer.from(ip.files.read('keeper.sealed')).toString('latin1').includes(kp.root_hex),
        'app enrol: the roster kept in the sealed keeper (resealed), worker 1 vps, remote');
      const rv = await O.call('POST', '/api/agents/revoke', { worker: 1 });
      ok(rv.status === 200 && rv.body.forgot === w1.contact && (await O.call('GET', '/api/agents/workers')).body.workers.find((x) => x.worker === 1).status === 'revoked', 'app enrol: revoke → its contact forgotten, revoked in the list');
    } finally { await O.stop(); }
  }

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
