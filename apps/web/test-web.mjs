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
  const own = ['app.mjs', 'boot.mjs', 'profiles.mjs', 'router.mjs', 'platform-web.mjs', 'platform-stub.mjs', 'pow-worker.mjs', 'platform-android.mjs', 'ws-over-stream.mjs', 'shell.mjs', 'seed.mjs', 'create.mjs'].map((f) => readFileSync(join(HERE, f), 'utf8'));
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
const nodePow = (await import(pathToFileURL(join(REPO, 'apps', 'contact', 'platform-node.mjs')).href)).pow;

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

// ================================================================ 2b. the relay setting (router.mjs, apps/contact/page.mjs), no relay needed
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
  // The Wallet settings (UI-API.md "Wallet"): per profile, checked, kept; this page holds no wallet (where: none, 409 wallet_none).
  const w0 = await r2.call('GET', '/api/wallet'), wBad = await r2.call('POST', '/api/settings', { currency: 'XYZ' }), wNot = await r2.call('POST', '/api/settings', { wallet: 'yes' });
  const wOn = await r2.call('POST', '/api/settings', { wallet: true, prices: true, currency: 'CHF' }), wSt = (await r2.call('GET', '/api/state')).body.me.wallet;
  const wRecv = await r2.call('POST', '/api/wallet/receive', {}), wPrice = await r2.call('GET', '/api/price'), w1 = await r2.call('GET', '/api/wallet');
  ok(JSON.stringify(w0.body) === JSON.stringify({ on: false, where: 'none' }) && wBad.status === 400 && wNot.status === 400 && wOn.body.wallet === true && wOn.body.prices === true && wOn.body.currency === 'CHF'
    && JSON.stringify(wSt) === JSON.stringify({ on: true, prices: true, currency: 'CHF' }) && wRecv.status === 409 && wRecv.body.error.check === 'wallet_none' && /no wallet yet/.test(wRecv.body.error.message)
    && wPrice.body.on === false && w1.body.on === true && w1.body.where === 'none',
    `settings: wallet, prices, currency kept per profile (state me.wallet); a bad currency or a non-boolean 400; this page has no wallet: where none, its routes 409 wallet_none, no price fetched (${JSON.stringify([w0.body, wSt, wRecv.body, wPrice.body])})`);
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
  const setupSrc = readFileSync(join(HERE, 'setup.mjs'), 'utf8');
  ok(/presetRelay\(platform\.files, relay\.value\)/.test(setupSrc) && /value: DEFAULT_RELAY/.test(setupSrc) && setupSrc.includes("label: 'Import a device file'"), 'setup.mjs: the import (Advanced on the welcome) shows the relay, relay.sigelo.ai pre-filled');
}


// ================================================================ 2c. restore from seed (seed.mjs, apps/contact/restore.mjs), no relay needed
{
  const SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href);
  const { makeRouter: mk } = await import(pathToFileURL(join(HERE, 'router.mjs')).href);
  const { did: didOf } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href);
  const { mnemonicFromRoot } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'keys.js')).href);
  // A fixed test mnemonic (a canonical root, < l), and what `sigelo-agent keeper --from-words` makes of it.
  const S0 = new Uint8Array(32).fill(9); S0[31] = 0x0e;
  const words = mnemonicFromRoot(S0), H = mkdtempSync(join(tmpdir(), 'sigelo-seed-')), op = join(H, 'me.local.json');
  const cli = spawnSync(process.execPath, [join(REPO, 'apps', 'agent', 'cli.ts'), 'keeper', '--from-words', '--identity', op], { env: { PATH: process.env.PATH, HOME: H, SIGELO_KEY_PROVIDER: 'file' }, input: words, encoding: 'utf8' });
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
  // The words password guards the seat (design/apps-seed.md §8): the router asks words.guard (words.mjs) before the take.
  const WD = await import(pathToFileURL(join(HERE, 'words.mjs')).href), WL = await import(pathToFileURL(join(HERE, 'vendor', 'contact', 'words-lock.mjs')).href);
  const slept = [], fastGate = WL.wrongGate({ sleep: async (ms) => { slept.push(ms); } });
  const me2 = JSON.parse(new TextDecoder().decode(await W.loadIdentity(p2))), r2 = mk({ platform: p2, identity: () => me2, mode: { kind: 'full', standby: true }, seat: SD.seatOf(p2, () => me2), options: { registry: false },
    words: { guard: (pw) => WD.guard(p2, pw, fastGate) } });
  let started = 0;
  r2.carrier.start = async () => { started++; };
  r2.carrier.checkClock = async () => {};
  await r2.start();
  const st2 = await r2.call('GET', '/api/state'), w2 = await r2.call('POST', '/api/send', { to: 'did:sigelo:zX', text: 'x' }), inv = await r2.call('POST', '/api/invite', {});
  ok(started === 0 && st2.status === 200 && st2.body.me.seat?.here === false && w2.status === 409 && w2.body.error.check === 'seat_elsewhere' && inv.body.error?.check === 'seat_elsewhere',
    `standby: started without logging in; GET /api/state shows the seat elsewhere (the banner); send and invite refused seat_elsewhere (${w2.status})`);
  // Set a password (Backup and recovery, none kept; words.mjs set): the 25 words typed again, refused when they make another
  // identity or are not words, then kept under the password (shown again with the lock and it).
  {
    const S1 = new Uint8Array(32).fill(7); S1[31] = 0x0f;
    const wa = WD.wordsApi(p2, { gate: fastGate, iterations: 1000, original: () => didOf(me2.genesis) });
    const otherWords = await checkOf(() => wa.set(mnemonicFromRoot(S1), 'correct horse', 'correct horse')), notWords = await checkOf(() => wa.set('apple pie', 'correct horse', 'correct horse'));
    const shortPw = await checkOf(() => wa.set(words, 'short', 'short')), before = WD.kept(p2);
    await wa.set(words, 'correct horse', 'correct horse');
    const shown = (await wa.reveal('correct horse')).words.join(' '), again = await checkOf(() => wa.set(words, 'correct horse', 'correct horse'));
    ok(otherWords === 'words_other' && notWords === 'words_check' && shortPw === 'words_password_rule' && before === false && WD.kept(p2) && shown === words && again === 'words_kept',
      `words: Set a password: another identity's words refused (words_other), not words (words_check), a short password; this identity's kept, shown again; set twice refused (${[otherWords, notWords, shortPw, again]})`);
    await WD.dropWords(p2);
  }
  // Review 2026-10-28, MEDIUM 7: the operator file imported as FULL (no signed list naming a seat) never runs a session.
  const p3 = await W.webPlatform({ name: 'imported-full', indexedDB: new FakeIDB(), mqtt: mqttEsm, pow: W.workerPow(() => new FakeWorker()) });
  const { keygen: kg3 } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href), k3 = kg3({ recovery: 'sha256:' + '1'.repeat(64) });
  const me3 = { v: 'sigelo/0', secret: Buffer.from(k3.secret).toString('hex'), genesis: k3.genesis, rotations: [], attestations: [], issuers: [] };
  const r3 = mk({ platform: p3, identity: () => me3, mode: { kind: 'full', standby: true }, seat: SD.seatOf(p3, () => me3), options: { registry: false } });
  let started3 = 0;
  r3.carrier.start = async () => { started3++; }; r3.carrier.checkClock = async () => {};
  const why3 = await checkOf(() => r3.start());
  ok(why3 === 'full_import' && started3 === 0, `imported FULL with no seat in a signed list: start() refused full_import, no session as you (${why3}, ${started3})`);
  const r3s = mk({ platform: p3, identity: () => me3, mode: { kind: 'safe' }, seat: null, options: { registry: false } });
  r3s.carrier.start = async () => {}; r3s.carrier.checkClock = async () => {};
  ok(await checkOf(() => r3s.start()) === 'accepted', 'an imported SAFE file still starts');
  await r3s.stop();
  const r2k = mk({ platform: p2, identity: () => me2, mode: { kind: 'full', standby: true }, seat: SD.seatOf(p2, () => me2), keeper: SD.keeperOf(p2), options: { registry: false } });
  r2k.carrier.start = async () => {}; r2k.carrier.checkClock = async () => {};
  const ws2 = (await r2k.call('GET', '/api/agents/workers')).body, ec2 = await r2k.call('POST', '/api/agents/enrol-code', { name: 'vps' });
  ok(ws2.keeper === true && ws2.seat === 'elsewhere' && ec2.status === 409 && ec2.body.error.check === 'seat_elsewhere',
    `standby: the agents list reads (the seat elsewhere); enrol-code refused seat_elsewhere: indices are given at the seat only (${ec2.status})`);
  const noConfirm = await r2.call('POST', '/api/seat/take', {});
  ok(noConfirm.status === 400 && started === 0, 'standby: POST /api/seat/take without confirm → 400, nothing started');
  ok(await checkOf(() => WD.guard(p2, undefined, fastGate)) === 'accepted', 'words guard: no words kept → no password asked (the guards of before)');
  await WD.keepWords(p2, words, 'correct horse', { iterations: 1000 });
  const tNo = await r2.call('POST', '/api/seat/take', { confirm: true }), tBad = await r2.call('POST', '/api/seat/take', { confirm: true, password: 'correct horsf' }), tBad2 = await r2.call('POST', '/api/seat/take', { confirm: true, password: 'x' });
  ok(tNo.status === 403 && tNo.body.error.check === 'words_password_needed' && tBad.status === 403 && tBad.body.error.check === 'words_password' && tBad.body.error.message === 'Wrong password.' && tBad2.status === 403
    && slept.join() === '2000,4000' && started === 0 && p2.files.read('words.sealed') !== null,
    `seat take with the words kept: no password → 403 words_password_needed; a wrong one → 403 "Wrong password." after 2 s, then 4 s (the gate doubling: ${slept}); nothing started`);
  const tk = await r2.call('POST', '/api/seat/take', { confirm: true, password: 'correct horse' });
  ok(tk.status === 200 && tk.body.seat === 'here' && tk.body.holder === 'tab' && started === 1 && (await r2.call('GET', '/api/state')).body.me.seat.here === true && r2.mode().standby === false,
    `seat take: the list signed naming this device, the page starts as the operator (${JSON.stringify(tk.body)})`);
  await r2.stop();
}

// ================================================================ 2d. create a new identity (create.mjs, apps/contact/create.mjs), no relay needed
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
  const cli = spawnSync(process.execPath, [join(REPO, 'apps', 'agent', 'cli.ts'), 'keeper', '--from-words', '--made-here', '--net', 'stagenet', '--restore-date', today, '--identity', op],
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

// ================================================================ 2e. ui.js (what ships, vendor/ui.js): the UX1 frame over a fake backend
// in a minimal DOM: Chats first, the tabs, Back; New chat; Agents, Enrol (a name and trust, the code big, the four
// words, ready), an agent's page and Revoke; the relay picker (Settings → Relay); presence; groups; the profiles
// sheet; Backup and recovery (the 25 words); computers; every screen drawn once (design/ux1/build.md "Tests").
{
  const vm = await import('node:vm');
  // The focus as a DOM keeps it: a node taken out of its parent (removed, moved, or its parent's children
  // replaced) takes the focus with it when it holds it, and the focus goes to the body.
  const focus = { el: null };
  const lost = (n) => { if (focus.el && (n === focus.el || n.contains?.(focus.el))) focus.el = body; };
  class Node_ {
    constructor() { this.parent = null; }
    get parentNode() { return this.parent; }
    remove() { const p = this.parent; if (!p) return; p.kids.splice(p.kids.indexOf(this), 1); this.parent = null; lost(this); }
    before(...n) { this.parent.insert(this, n, 0); }
    after(...n) { this.parent.insert(this, n, 1); }
  }
  class Text_ extends Node_ { constructor(t) { super(); this.data = String(t); } get textContent() { return this.data; } }
  class El extends Node_ {
    constructor(tag) { super(); Object.assign(this, { tagName: tag.toUpperCase(), kids: [], attrs: {}, on: {}, style: {}, dataset: {}, className: '', value: '', disabled: false, hidden: false, checked: false }); }
    get textContent() { return this.kids.map((k) => k.textContent).join(''); }
    set textContent(t) { this.kids = [new Text_(t)]; }
    get childNodes() { return [...this.kids]; }
    append(...k) { for (const x of k) { const n = x instanceof Node_ ? x : new Text_(x); n.remove(); n.parent = this; this.kids.push(n); } }
    replaceChildren(...k) { for (const c of this.kids.splice(0)) { c.parent = null; lost(c); } this.append(...k); }
    insert(ref, k, off) { for (const x of k) { const n = x instanceof Node_ ? x : new Text_(x); n.remove(); n.parent = this; this.kids.splice(this.kids.indexOf(ref) + off, 0, n); if (off) ref = n; } }
    contains(x) { for (let n = x; n; n = n.parent) if (n === this) return true; return false; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(t, f) { (this.on[t] ??= []).push(f); }
    focus() { focus.el = this; }
    getContext() { return null; }
    all() { return [this, ...this.kids.filter((k) => k instanceof El).flatMap((k) => k.all())]; }
    async click() { const ev = { preventDefault() {}, stopImmediatePropagation() {}, target: this }; for (const f of this.on.click ?? []) await f(ev); }
  }
  const fire = (el, t) => { for (const f of el.on[t] ?? []) f({ target: el, key: '', preventDefault() {} }); };
  // A tree's helpers: a button by its text, a control by its label, the heading, the text.
  const kit = (root) => ({
    btn: (t) => root.all().find((e) => e.tagName === 'BUTTON' && e.textContent === t),
    aria: (t, tag) => root.all().find((e) => e.attrs['aria-label'] === t && (!tag || e.tagName === tag)),
    has: (t) => root.textContent.includes(t),
    h1: () => root.all().find((e) => e.tagName === 'H1' && e.textContent)?.textContent,
    sheet: () => root.all().find((e) => e.className === 'sheet'),
    sh1: () => root.all().find((e) => e.className === 'sheet')?.all().find((e) => e.tagName === 'H1')?.textContent,
    field: (label) => { const l = root.all().find((e) => e.tagName === 'LABEL' && e.textContent === label); return l ? root.all().find((e) => (e.attrs.id ?? e.id) === l.attrs.for) : undefined; },
  });
  const PKG_VERSION = JSON.parse(readFileSync(join(HERE, '..', 'agent', 'package.json'), 'utf8')).version;
  const root = new El('main'), body = new El('body'), intervals = [];
  const W_ = { workers: [{ worker: 0, name: 'phone', did: 'did:sigelo:zPhone000000000000000000000000000000000000000000', original: 'did:sigelo:zPhone000000000000000000000000000000000000000000', rank: 'full', placed: 'device', at: 1761400000, status: 'enrolled', revoked: null, seen: null, tier: null, contact: null, local: 'phone', attested_until: null, enrolling: null }] };
  const calls = [], now = () => Math.floor(Date.now() / 1000);
  const G_ = { mine: [], contacts: [] };
  const snap = () => ({ seq: sandbox.seq ?? 1, now: now(), me: { did: 'did:sigelo:zMe', relay: 'relay.sigelo.ai', online: true, clock_offset: 0, clock_checked: now(), retention_days: 7, error: null, pow: null, pow_done_ms: null, seat: { holder: 'phone', epoch: 1, here: true }, pow_capped: sandbox.capped ?? null, pow_confirm: null,
      wallet: { on: SET.wallet === true, prices: SET.prices === true, currency: SET.currency ?? null } },
    groups: { mine: G_.mine, contacts: G_.contacts }, chats: { ...GR.chats }, pending: { invites: [], paired: [], answers: [], failed: [], public: null, ...sandbox.pending }, introductions: sandbox.intro ?? [], events: [] });
  // Groups (GROUPS.md) as GET /api/groups and /api/groups/history answer; rev bumped at each change.
  const ME = 'did:sigelo:zMe', GR = { tier: { tier: 'free', groups: 3, members: 8, told: true }, groups: [], notices: [], history: {}, chats: { unread: 0, invited: 0, notices: 0, rev: '0' } };
  const bump = () => { GR.chats.rev = String(Number(GR.chats.rev) + 1); };
  const gOf = (gid) => GR.groups.find((g) => g.gid === gid);
  const WAL = { v: null };
  const RELAY = { relay: 'relay.sigelo.ai' }, SET = { seen_receipts: true, notify: true, new_tier: 'friend', new_presence: false }, MSGS = {};
  const settingsNow = () => ({ relay: RELAY.relay, default: 'relay.sigelo.ai', fixed: null, in_use: 'relay.sigelo.ai', ...SET });
  const routes = {
    'GET /api/state': () => snap(),
    'GET /api/me': () => ({ did: ME, original: ME, words: 'amber otter violin harbor', recovery: 'set', key: 'browser', relay: 'relay.sigelo.ai', retention_days: 7, erase: 'POST /delete at the relay' }),
    'GET /api/agents/workers': () => ({ keeper: true, seat: 'here', workers: W_.workers }),
    'GET /api/settings': () => settingsNow(),
    // The wallet (UI-API.md "Wallet"): this phone has none until pass 4's block gives it a computer's (WAL.v).
    'GET /api/wallet': () => (SET.wallet !== true ? { on: false } : WAL.v ?? { on: true, where: 'none' }),
    'POST /api/settings': (b) => { const { relay, ...rest } = b; if (relay !== undefined) RELAY.relay = relay; Object.assign(SET, rest); return settingsNow(); },
    'POST /api/notify': (b) => { const c = [...G_.mine, ...G_.contacts].find((x) => x.did === b.chat) ?? gOf(b.chat); c.notify = b.on; return { chat: b.chat, notify: b.on }; },
    'POST /api/history/clear': (b) => { if (b.contact) MSGS[b.contact] = []; return { cleared: true, ...(b.contact && { contact: b.contact }) }; },
    'POST /api/invite': (b) => ({ id: b.group ? 'g1' : 'i1', name: 'contact-1a2b', code: 'sgl1example', exp: now() + 86400, short: b.group ? 'G5TR-2KXA' : 'K7F3-Q9ZP', short_exp: now() + 600, relay: 'relay.sigelo.ai' }),
    'POST /api/accept': (b) => { const d = G_.contacts.find((x) => x.name === 'eve'); return { status: 'connected', contact: { did: d.did, name: d.name, fingerprint: d.words, pair: 'p', tier: 'friend' } }; },
    'GET /api/relays': () => ({ relays: [{ tag: 'ex', host: 'relay.example.org', tier: 'community' }] }),
    'POST /api/relays/test': (b) => (b.relay === 'down.example.org' ? { relay: b.relay, ok: false, ms: 5000, retention_days: null, detail: 'cannot reach the relay' } : { relay: b.relay, ok: true, ms: 42, retention_days: 7 }),
    'POST /api/agents/enrol-code': (b) => {
      if (sandbox.powAsk && !b.pow_confirmed) return { __error: { check: 'pow_confirm', message: 'pow_confirm: Fourth setup at this relay (relay.sigelo.ai) today, up to 2 minutes. Go on?' } };
      const e = { id: `n${W_.workers.length}`, state: 'code', code: 'K7F3-Q9ZP', exp: now() + 600, relay: 'relay.sigelo.ai', words: null, confirm_words: b.confirm_words === true, words_ok: null, command: 'sigelo-agent init --enrol K7F3-Q9ZP' };
      const i = W_.workers.length, d = `did:sigelo:z${b.name.replace(/\W/g, '')}${'0'.repeat(40)}`;
      W_.workers.push({ worker: i, name: b.name, did: d, original: d, words: 'harvest ivory comet nine', rank: null, placed: 'remote', at: now(), status: 'pending', revoked: null, seen: null, tier: null, contact: null, local: null, attested_until: now() + 90 * 86400, enrolling: e });
      return { worker: i, name: b.name, did: d, original: d, tier: b.tier ?? 'own', ...e };
    },
    'POST /api/words': () => ({ checked: true }),
    'GET /api/messages': (b, path) => ({ seq: 1, messages: MSGS[decodeURIComponent(/contact=([^&]+)/.exec(path)?.[1] ?? '')] ?? [] }),
    'POST /api/presence': (b) => ({ did: b.contact, name: 'bo', presence: b.allow ? 'allow' : 'deny' }),
    'GET /api/groups': () => ({ tier: GR.tier, groups: GR.groups, notices: GR.notices }),
    'GET /api/groups/history': (b, path) => { const gid = /group=([0-9a-z]+)/.exec(path)?.[1]; return { group: gOf(gid), messages: GR.history[gid] ?? [] }; },
    'POST /api/groups/create': (b) => {
      const c = [...G_.mine, ...G_.contacts], g = { gid: 'a'.repeat(32), name: b.name, status: 'member', ver: 1, brake: 20, creator: ME, creator_name: null, mine: true, foreign: false, run: 0, unread: 0, quiet: false, last: null,
        members: [{ did: ME, name: 'creator', role: 'human', me: true, contact: false }, ...b.members.map((d) => ({ did: d, name: c.find((x) => x.did === d).name, role: b.humans.includes(d) ? 'human' : 'agent', me: false, contact: true }))] };
      GR.groups.push(g); bump();
      return { group: g, copies: [] };
    },
    'POST /api/groups/send': (b) => { (GR.history[b.group] ??= []).push({ mid: '1'.repeat(16), from: ME, name: 'creator', role: 'human', tier: null, mine: true, operator: false, note: null, text: b.text, mentions: [], mentioned: false, via: null, at: now() }); bump(); return { gid: b.group, mid: '1'.repeat(16), copies: [], via_creator: [], unreached: [] }; },
    'POST /api/groups/add': (b) => { const g = gOf(b.group), c = [...G_.mine, ...G_.contacts]; for (const d of b.members) g.members.push({ did: d, name: c.find((x) => x.did === d).name, role: b.humans.includes(d) ? 'human' : 'agent', me: false, contact: true }); g.ver++; bump(); return { group: g, copies: [] }; },
    'POST /api/groups/remove': (b) => { const g = gOf(b.group); g.members = g.members.filter((m) => !b.members.includes(m.did)); g.ver++; bump(); return { group: g, copies: [] }; },
    'POST /api/groups/role': (b) => { const g = gOf(b.group); g.members.find((m) => m.did === b.member).role = b.role; g.ver++; bump(); return { group: g, copies: [] }; },
    'POST /api/groups/rename': (b) => { const g = gOf(b.group); g.name = b.name; g.ver++; bump(); return { group: g, copies: [] }; },
    'POST /api/groups/brake': (b) => { const g = gOf(b.group); g.brake = b.brake; g.ver++; bump(); return { group: g, copies: [] }; },
    'POST /api/groups/share': (b) => ({ group: gOf(b.group), copies: [{ to: b.member, status: 'sent' }] }),
    'POST /api/groups/join': (b) => { const g = gOf(b.group); g.status = 'member'; GR.chats.invited = 0; bump(); return { group: g, copies: [] }; },
    'POST /api/groups/leave': (b) => { const g = gOf(b.group); g.status = 'left'; bump(); return { group: g, copies: [], told: true }; },
    'POST /api/groups/dismiss': (b) => { GR.notices = GR.notices.filter((n) => n.id !== b.id); bump(); return { dismissed: 1 }; },
    'POST /api/agents/enrol-words': (b) => { sandbox.wordsAnswer = b; return { id: b.id, state: 'sending' }; },
    'POST /api/pow/try': (b) => { sandbox.tried = b; return { tried: ['relay.sigelo.ai'] }; },
    'POST /api/agents/revoke': (b) => { const w = W_.workers.find((x) => x.worker === b.worker); w.status = 'revoked'; w.revoked = now(); return { worker: b.worker, name: w.name, cancelled: false, revoked: w.revoked, forgot: w.contact }; },
  };
  const docOf = (r) => ({ getElementById: () => r, createElement: (t) => new El(t), createElementNS: (_ns, t) => new El(t), createTextNode: (t) => new Text_(t), querySelectorAll: () => [], body, get activeElement() { return focus.el; } });
  const sandbox = {
    document: docOf(root),
    Node: Node_, location: { hash: '', pathname: '/', protocol: 'https:', href: 'https://app.invalid/index.html' },
    // The version beside ui.js (vendor/package.json, apps/agent/package.json as copy.mjs vendors it): About reads it.
    fetch: async (url) => { sandbox.fetched = [...(sandbox.fetched ?? []), String(url)]; return String(url) === 'https://app.invalid/package.json' ? { ok: true, json: async () => JSON.parse(readFileSync(join(HERE, 'vendor', 'package.json'), 'utf8')) } : { ok: false, json: async () => null }; }, history: { replaceState() {} }, sessionStorage: { getItem: () => null, setItem() {} },
    window: { innerHeight: 800, innerWidth: 400, scrollY: 0, scrollTo() {} }, navigator: { clipboard: { writeText: async (t) => { sandbox.copied = t; } } },
    setInterval: (f, ms) => { intervals.push([f, ms]); return intervals.length; }, clearInterval() {}, setTimeout: (f, ms) => setTimeout(f, Math.min(ms ?? 0, 10)), clearTimeout,
    console, Date, Promise, Object, Array, String, Number, JSON, Math, Map, Set, Error, encodeURIComponent, URL,
    sigeloUiTest: (t) => { sandbox.ui = t; },
    localStorage: { m: new Map(), getItem(k) { return this.m.get(k) ?? null; }, setItem(k, v) { this.m.set(k, String(v)); }, removeItem(k) { this.m.delete(k); } },
    sigeloLocal: {
      async call(method, path, body) { calls.push([method, path, body]); const f = routes[`${method} ${path.split('?')[0]}`], r = f ? f(body ?? {}, path) : null; if (r?.__error) return { status: 409, body: { error: r.__error } }; return f ? { status: 200, body: JSON.parse(JSON.stringify(r)) } : { status: 404, body: { error: { check: 'route', message: `no ${method} ${path}` } } }; },
      onChange() {}, mode: () => ({ kind: 'full' }),
      async unlock() { sandbox.unlocks = (sandbox.unlocks ?? 0) + 1; if (sandbox.refuseUnlock) throw Object.assign(new Error('the screen lock was not confirmed'), { check: 'cancelled' }); },
    },
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(readFileSync(join(HERE, 'vendor', 'ui.js'), 'utf8'), sandbox);
  const settle = () => sleep(30);
  const poll = async () => { await intervals.find(([, ms]) => ms === 2000)[0](); await settle(); };
  const { btn, aria, has, h1, sheet, sh1 } = kit(root);
  const back = async () => { await aria('Back', 'BUTTON').click(); await settle(); await poll(); };
  const tabBtn = (t) => root.all().find((e) => e.tagName === 'BUTTON' && e.attrs['data-tab'] === t);
  await settle(); await poll();
  ok(h1() === 'Chats' && has('No chats yet') && btn('Start a chat') && btn('Enrol an agent') && btn('New chat')?.className === 'fab'
    && root.all().filter((e) => e.attrs['data-tab']).map((e) => e.textContent).join() === 'Chats,Agents,Me' && tabBtn('chats').attrs['aria-current'] === 'page',
    'ui.js: the first screen is Chats (empty: No chats yet, Start a chat, Enrol an agent), the New chat button; tabs Chats, Agents, Me (Wallet off: no tab)');
  ok(root.all().some((e) => e.className === 'pchip' && e.textContent.includes('sigelo') && e.textContent.includes('amber · otter · violin · harbor')), 'top bar: the profile chip, the name and the four words (GET /api/me)');
  await tabBtn('agents').click(); await settle(); await poll();
  const rows = () => root.all().filter((e) => e.attrs['data-worker'] !== undefined);
  ok(h1() === 'Agents' && rows().length === 1 && rows()[0].textContent.includes('phone') && rows()[0].textContent.includes('a device that holds your identity') && !rows()[0].textContent.includes('FULL')
    && calls.some(([m, p]) => m === 'GET' && p === '/api/agents/workers') && btn('Enrol agent')?.className === 'fab' && !btn('Enrol agent').disabled && tabBtn('agents').attrs['aria-current'] === 'page',
    'ui.js: Agents, a row per worker from GET /api/agents/workers (its name, where it is, in words: no FULL or SAFE); Enrol agent ready (a keeper, the seat here)');
  await tabBtn('chats').click(); await settle(); await poll();
  await btn('New chat').click(); await settle();
  ok(sheet() && sh1() === 'New chat' && btn('Make my code') && aria('Their code', 'INPUT') && btn('Pair') && has('Scan their QR') && has('New group') && has('Your own agent?') && (sandbox.unlocks ?? 0) === 0,
    'New chat: a sheet (Make my code, their code and Pair, Scan, New group, "Your own agent?" pointing at Enrol); no screen lock asked (the lock rule)');
  await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Your own agent?')).click(); await settle(); await poll();
  ok(h1() === 'Enrol an agent' && !sheet() && has('Enrolling gives an AI agent its own key under your identity') && (sandbox.unlocks ?? 0) === 0, 'Enrol an agent: its own screen in place of the sheet, what it is for; no screen lock asked');
  const nameIn = kit(root).field('Agent name');
  // Typing on a phone: the field keeps the focus (and the keyboard) while the poll draws the screen again.
  nameIn.focus(); nameIn.value = 'vp';
  await poll(); await poll();
  ok(focus.el === nameIn && root.contains(nameIn) && nameIn.value === 'vp' && root.all().filter((e) => e === nameIn).length === 1,
    'enrol: the name field being typed in keeps the focus, its place and its text across the screen drawn again (the poll)');
  nameIn.value = 'vps';
  const web = root.all().find((e) => e.tagName === 'INPUT' && e.attrs.type === 'radio' && e.value === 'quiet');
  web.checked = true; fire(web, 'change');
  sandbox.powAsk = true;
  void btn('Make a code').click(); await settle();
  ok(sheet() && has('Fourth setup at this relay (relay.sigelo.ai) today, up to 2 minutes. Go on?'), 'enrol: past the day\'s 3 setups the page asks once (pow_confirm), in a sheet');
  await btn('Go on').click(); await settle(); await poll();
  const made = calls.find(([, p]) => p === '/api/agents/enrol-code'), again = calls.filter(([, p]) => p === '/api/agents/enrol-code')[1];
  sandbox.powAsk = false;
  const big = root.all().find((e) => e.className === 'code');
  ok(again?.[2]?.pow_confirmed === true && JSON.stringify(made?.[2]) === JSON.stringify({ name: 'vps', tier: 'quiet', confirm_words: true }) && big?.textContent === 'K7F3-Q9ZP' && has('Works once, for ') && has('sigelo-agent init --enrol K7F3-Q9ZP')
    && h1() === 'Code for vps' && has('This screen moves on by itself'), `enrol: POST /api/agents/enrol-code {name, tier (Reads the web: quiet), confirm_words}; Go on sends pow_confirmed; the code big, the countdown, the command (${JSON.stringify(made?.[2])})`);
  await btn('Copy').click();
  ok(sandbox.copied === 'K7F3-Q9ZP', 'enrol: Copy puts the code on the clipboard');
  await btn('Share').click(); await settle();
  ok(/^Enrol as my agent on sigelo: code K7F3-Q9ZP, once, until \d{1,2}:\d{2}.*sigelo-agent init --enrol K7F3-Q9ZP .*How: https:\/\/sigelo\.io\/enrol\.html$/.test(sandbox.copied ?? ''),
    `enrol: Share, without a share sheet, copies a ready-to-send message: the code, until when, the command, the instructions link (${sandbox.copied})`);
  Object.assign(W_.workers[1].enrolling, { state: 'words', code: null, command: null, words: 'mobile absent bone lion' });
  await poll();
  ok(h1() === 'Is this vps?' && !root.all().some((e) => e.className === 'code') && root.all().find((e) => e.className === 'words4')?.textContent === 'mobileabsentbonelion' && btn('They match') && btn('They don\'t match'),
    'enrol: once the agent pairs, the code goes: "Is this vps?", the four words, They match / They don\'t match (its key waits)');
  await btn('They match').click(); await settle();
  ok(JSON.stringify(sandbox.wordsAnswer) === JSON.stringify({ id: 'n1', match: true }), `enrol: They match → POST /api/agents/enrol-words {id, match: true} (${JSON.stringify(sandbox.wordsAnswer)})`);
  Object.assign(W_.workers[1].enrolling, { words_ok: true, verified: true, state: 'enrolled' });
  Object.assign(W_.workers[1], { status: 'enrolled', contact: 'did:sigelo:zVps0000000000000000000000000000000000000000000', tier: 'quiet' });
  await poll();
  ok(has('vps is ready') && !calls.some(([m, p]) => p === '/api/words') && btn('Done') && btn('Message vps'), 'enrol: ready with no further tap (no POST /api/words); Message vps and Done');
  await btn('Done').click(); await settle(); await poll();
  ok(h1() === 'Agents' && rows().length === 2 && rows()[1].textContent.includes('vps') && rows()[1].textContent.includes('on another machine'), 'Done: back on the Agents list, vps enrolled, on another machine');
  // The automatic tries paused for the day: when the next is, and Try now (POST /api/pow/try).
  sandbox.capped = { relay: 'relay.sigelo.ai', next: now() + 3600 };
  await poll();
  ok(has('Setup paused at relay.sigelo.ai: 3 tries today. Next automatic try at') && btn('Try now'), 'a tab\'s status card: setup paused, the next automatic try, Try now');
  await btn('Try now').click(); await settle();
  ok(sandbox.tried !== undefined, 'Try now → POST /api/pow/try');
  sandbox.capped = null; await poll();
  await rows()[1].click(); await settle(); await poll();
  ok(h1() === 'vps' && has('Enrolled') && has('Vouched for until') && has('Rename') && btn('Revoke vps') && btn('Message') === undefined, 'an agent\'s page: Enrolled, Vouched for until, Rename, Revoke vps (no Message before its contact comes)');
  void btn('Revoke vps').click(); await settle();
  ok(sheet() && sh1() === 'Revoke vps?' && has('It can no longer message as you or spend.') && btn('Keep vps'), 'Revoke: a sheet naming it, what it means, Keep vps');
  await root.all().filter((e) => e.tagName === 'BUTTON' && e.textContent === 'Revoke vps').at(-1).click(); await settle(); await poll();
  ok(calls.some(([m, p, b]) => p === '/api/agents/revoke' && b.worker === 1) && has('Revoked') && !btn('Revoke vps'), 'Revoke (confirmed) → POST /api/agents/revoke; shown revoked, no Revoke left');
  // Presence (UI-API.md): online, or "last seen …" once offline; nothing when not known.
  const person = (name, o) => ({ did: `did:sigelo:z${name}00000000000000000000000000000000000000000`, name, current_did: null, relay: 'relay.sigelo.ai', re_pair: null, words: null, pair: null, words_checked: true, tags: [], local: null,
    mine: null, unread: 0, last: null, waiting: null, not_collected: 0, queued: 0, status: 'ok', ours: false, tier: 'friend', link: null, online: null, online_since: null, last_seen: null, presence: 'deny', ...o });
  G_.mine.push(person('ana', { tier: 'own', ours: true, presence: 'own', online: true, online_since: now() - 60 }));
  G_.contacts.push(person('bo', { online: false, last_seen: now() - 300, unread: 2, last: { dir: 'in', text: 'secret', at: now() - 300 } }), person('cy'));
  W_.workers[0].online = true;
  await back(); await poll();
  const phone = rows().find((e) => e.textContent.includes('phone'));
  ok(phone?.all().some((e) => e.className === 'dot sm') && phone.textContent.includes('Online'), 'agents: an online agent\'s row has the dot and says Online');
  await tabBtn('chats').click(); await settle(); await poll();
  const chatRow = (n) => root.all().find((e) => e.tagName === 'BUTTON' && e.attrs['data-chat']?.startsWith(`did:sigelo:z${n}`));
  ok(chatRow('ana')?.textContent.includes('Agent') && chatRow('bo')?.textContent.includes('2 new messages') && !chatRow('bo').textContent.includes('secret') && chatRow('bo').all().some((e) => e.className === 'count' && e.textContent === '2') && chatRow('cy'),
    'Chats: a row per contact; my agent marked Agent; a friend\'s row a count only (2 new messages, the text not shown)');
  await chatRow('bo').click(); await settle(); await poll();
  ok(root.all().some((e) => e.className === 'who' && e.textContent.includes('bo') && e.textContent.includes('last seen 5 min ago')) && aria('Message', 'TEXTAREA') && aria('Send', 'BUTTON') && aria('Attach', 'BUTTON') && btn('Pay'),
    'a chat: the name and "last seen 5 min ago" in the top bar; the composer (Attach, Message, Send); Pay');
  await btn('Pay').click(); await settle();
  ok(sheet() && sh1() === 'Turn on Wallet to pay' && btn('Turn on Wallet'), 'Pay with Wallet off: the sheet that turns it on');
  await aria('Close', 'BUTTON').click(); await settle();
  await root.all().find((e) => e.className === 'who').click(); await settle(); await poll();
  const seesMe = aria('Sees when I\'m online', 'INPUT');
  ok(h1() === 'Chat settings' && seesMe && seesMe.checked === false && has('Show them') && has('Just a count') && has('Quiet') && btn('Block bo…'), 'Chat settings: Their messages (Show them, Just a count, Quiet), Sees when I\'m online off (deny), Block');
  seesMe.checked = true; fire(seesMe, 'change'); await settle();
  ok(calls.some(([m, p, b]) => p === '/api/presence' && b.contact === G_.contacts[0].did && b.allow === true), 'Sees when I\'m online on → POST /api/presence {contact, allow: true}');
  await back(); await back();
  ok(h1() === 'Chats', 'Back, Back: the chat, then Chats');

  // ---- pass 2 (design/ux1/build.md): the tab's count, ticks, who signed a message (task 11), the attach sheet, a chat's
  // notifications and Clear this chat, New chat to the four words both ways (tasks 2 and 12), a group code
  {
    const bo = G_.contacts[0], t = now() - 60;
    const m = (n, dir, text, status) => ({ n, dir, at: t + n, iat: dir === 'in' ? t + n : null, text, label: '', status, code: status === 'queued' ? 'offline' : null, detail: null, link: null });
    MSGS[bo.did] = [m(1, 'in', 'Dinner on Friday?', null), m(2, 'out', 'Yes! 8 o\'clock?', 'seen'), m(3, 'out', 'See you there', 'sent'), m(4, 'out', 'On my way', 'queued')];
    ok(tabBtn('chats').textContent === '2Chats' && tabBtn('chats').attrs['aria-label'] === 'Chats, 2 unread', `the Chats tab: the unread count, said (${tabBtn('chats').textContent})`);
    let taps = 0;
    await chatRow('bo').click(); taps++; await settle(); await poll();
    const outs = root.all().filter((e) => e.className === 'msg out');
    ok(outs.length === 3 && outs[0].textContent.endsWith('✓✓') && outs[0].all().some((e) => e.attrs['aria-label'] === 'Seen') && outs[1].textContent.endsWith(' ✓') && outs[1].all().some((e) => e.attrs['aria-label'] === 'Delivered to the relay')
      && outs[2].textContent.endsWith('waiting to send') && has('Today'), `a chat: a day line; ✓✓ seen, ✓ at the relay, waiting said in words (${outs.map((e) => e.textContent).join(' | ')})`);
    await aria('Attach', 'BUTTON').click(); await settle();
    ok(sheet() && sh1() === 'Attach' && has('Pay') && has('Send a signed message') && has('Proves it\'s from you') && aria('Close', 'BUTTON'), 'the attach sheet (Telegram\'s): Pay, Send a signed message; Close');
    await aria('Close', 'BUTTON').click(); await settle();
    await root.all().find((e) => e.className === 'msg in').click(); taps++; await settle(); await poll();
    ok(taps === 2 && h1() === 'Signed message' && has('✓ Signed by bo') && has('Their four words match the ones you compared. Not changed since they signed it.') && has('Dinner on Friday?') && btn('Check another message'),
      'task 11, 2 taps: the chat, then their message: Signed message (who, the words compared, not changed, the text)');
    await back();
    await root.all().find((e) => e.className === 'who').click(); await settle(); await poll();
    const nt = aria('Notifications', 'INPUT');
    ok(nt?.checked === true && has('The sender\'s name only, never the text') && btn('Clear this chat') && btn('Rename') === undefined, 'Chat settings: Notifications (on), Clear this chat');
    nt.checked = false; fire(nt, 'change'); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/notify' && b.chat === bo.did && b.on === false) && has('Off: no count on the Chats tab'), 'Notifications off → POST /api/notify {chat, on: false}');
    void btn('Clear this chat').click(); await settle();
    ok(sheet() && sh1() === 'Clear this chat?' && has('Every message with bo kept on this phone is deleted. bo stays a contact.') && btn('Keep the messages'), 'Clear this chat: a sheet naming it, Keep the messages');
    await root.all().filter((e) => e.tagName === 'BUTTON' && e.textContent === 'Clear this chat').at(-1).click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/history/clear' && b.contact === bo.did) && MSGS[bo.did].length === 0, 'Clear this chat (confirmed) → POST /api/history/clear {contact}');
    await back(); await back();
    const cnt = chatRow('bo').all().find((e) => /^count/.test(e.className));
    ok(h1() === 'Chats' && cnt?.className === 'count muted' && !tabBtn('chats').textContent.startsWith('2'), 'muted: the row\'s count grey, the Chats tab\'s count without it');
    bo.notify = true;
    // Task 12 (3 taps) and task 2, making mine (4): New chat, Make my code, Show as QR; their use of it brings the words.
    G_.contacts.push(person('dee', { words: 'falcon pepper orbit twelve', words_checked: false }), person('eve', { words: 'mobile absent bone lion', words_checked: false }));
    await btn('New chat').click(); await settle();
    await btn('Make my code').click(); await settle();
    ok(sheet() && root.all().some((e) => e.textContent === 'K7F3-Q9ZP' && /code/.test(e.className)) && btn('Share') && btn('Show as QR'), 'New chat → Make my code: the code in the sheet, Share, Show as QR');
    const mine = { name: 'contact-1a2b', exp: now() + 86400, relay: 'relay.sigelo.ai', id: 'i1', short: 'K7F3-Q9ZP', short_exp: now() + 600, code: 'sgl1example', group: null };
    sandbox.pending = { invites: [mine] };
    await btn('Show as QR').click(); await settle(); await poll();
    ok(h1() === 'My code' && !sheet() && has('K7F3-Q9ZP') && btn('Copy'), 'task 12, 3 taps: New chat, Make my code, Show as QR: My code, the QR and the code');
    await back();
    await btn('New chat').click(); await settle();
    await btn('Make my code').click(); await settle();
    const dee = G_.contacts.find((c) => c.name === 'dee');
    sandbox.pending = { invites: [mine], paired: [{ id: 'i1', name: 'contact-1a2b', paired: dee.did }] };
    await poll(); await settle(); await poll();
    ok(h1() === 'Compare four words' && !sheet() && root.all().find((e) => e.className === 'words4')?.textContent === 'falconpepperorbittwelve' && btn('They match'),
      'task 2, making mine: the code used while the sheet is open → Compare four words, their four words, They match (the 4th tap)');
    await btn('They match').click(); await settle();
    ok(calls.some(([, p, b]) => p === '/api/words' && b.contact === dee.did && b.match === true), 'They match → POST /api/words {contact, match: true}');
    sandbox.pending = undefined;
    await back();
    // Task 2, their code (3 taps): New chat, Pair (the code typed), They match.
    await btn('New chat').click(); await settle();
    aria('Their code', 'INPUT').value = 'M4QX-8T2B';
    await btn('Pair').click(); await settle(); await poll(); await settle(); await poll();
    ok(h1() === 'Compare four words' && root.all().find((e) => e.className === 'words4')?.textContent === 'mobileabsentbonelion' && btn('They match')
      && calls.some(([, p, b]) => p === '/api/accept' && b.code === 'M4QX-8T2B'), 'task 2, their code, 3 taps: New chat, Pair (POST /api/accept), the four words both sides see, They match');
    await back();
    ok(h1() === 'Chats', 'Back from the pairing: Chats');
    // A public code (PUB-…): its four words asked beside it; the answer waits for the owner's OK.
    const acceptWas = routes['POST /api/accept'];
    routes['POST /api/accept'] = (b) => (/^PUB/.test(b.code) ? { status: 'waiting_approval', did: 'did:sigelo:zShop', relay: 'relay.sigelo.ai', exp: now() + 7 * 86400 } : acceptWas(b));
    await sandbox.ui.go('enter-code'); await settle();
    ok(!kit(root).field('Their four words'), 'Enter their code: no words field for a person\'s code');
    const pc = kit(root).field('Their code'); pc.value = 'PUB-7Q4K-M2XD'; fire(pc, 'input'); await settle();
    const wf = kit(root).field('Their four words');
    ok(wf !== undefined && wf !== null, 'a PUB code: the field for the four words printed beside it');
    wf.value = 'amber otter violin harbor';
    await btn('Pair').click(); await settle(); await poll(); await settle();
    ok(calls.some(([, p, b]) => p === '/api/accept' && b.code === 'PUB-7Q4K-M2XD' && b.words === 'amber otter violin harbor') && root.all().some((e) => e.attrs['data-approval'] !== undefined) && has('They accept each new chat'),
      'Pair with a PUB code → POST /api/accept {code, words}; Sent: they accept each new chat');
    routes['POST /api/accept'] = acceptWas;
    // A contact that came by my public code: marked, not compared.
    G_.contacts.push(person('pubby', { words: 'copper lantern meadow seven', pair: 'pp', words_checked: false, via: { public: 'pub1' } }));
    await poll(); await sandbox.ui.go('chat-info', G_.contacts.at(-1).did); await settle(); await poll();
    ok(has('Came by your public code · not compared') && root.all().some((e) => e.attrs['data-via'] === 'mine'), 'chat info: a contact by my public code says so, not compared');
    G_.contacts.pop();
    await sandbox.ui.go('chats'); await settle();
    G_.contacts.splice(G_.contacts.findIndex((c) => c.name === 'dee'), 2);
  }

  // ---- Groups (design/groups.md §5): the list, New group (two taps and a name), the chat, its info, Add people, an invitation, a notice
  {
    G_.contacts.push(person('qu', { tier: 'quiet' }));
    await btn('New chat').click(); await settle();
    await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('New group')).click(); await settle(); await poll();
    const boxes = () => root.all().filter((e) => e.tagName === 'INPUT' && e.attrs.type === 'checkbox');
    const nameIn = kit(root).field('Group name'), names = boxes().map((b) => b.attrs['aria-label']);
    const counter = () => root.all().find((e) => e.className === 'help center' && /of \d/.test(e.textContent))?.textContent;
    ok(h1() === 'New group' && nameIn && focus.el === nameIn && names.join() === 'bo,cy,qu,ana' && boxes()[3].checked && !boxes()[0].checked && !boxes()[2].checked && counter() === '2 of 8' && btn('Create group').disabled,
      `new group: a name box (focused), then people, quiet last and unticked, and my agents preselected (at most three); "2 of 8"; Create dark without a name (${names}, ${counter()})`);
    nameIn.value = 'crew'; fire(nameIn, 'input'); await settle();
    ok(!btn('Create group').disabled, 'new group: a name and one member: Create group lights');
    boxes()[0].checked = true; fire(boxes()[0], 'change'); await settle();
    ok(counter() === '3 of 8', `new group: ticking bo: "3 of 8" (${counter()})`);
    await btn('Create group').click(); await settle(); await poll();
    const madeG = calls.find(([, p]) => p === '/api/groups/create')?.[2];
    ok(JSON.stringify(madeG) === JSON.stringify({ name: 'crew', members: [G_.mine[0].did, G_.contacts[0].did], humans: [G_.contacts[0].did] }) && h1() === 'crew' && has('Group made, 3 members') && focus.el?.attrs?.['aria-label'] === 'Message',
      `create: POST /api/groups/create {name, members, humans: those not my agents}; the chat opens at once: "Group made, 3 members", the composer focused (${JSON.stringify(madeG)})`);
    const g = GR.groups[0], [ana, bo] = [G_.mine[0], G_.contacts[0]];
    GR.history[g.gid] = [
      { mid: '2'.repeat(16), from: ana.did, name: 'ana', role: 'agent', tier: 'own', mine: false, operator: false, note: 'not your operator', text: 'build is green', mentions: [], mentioned: false, via: null, at: now() },
      { mid: '3'.repeat(16), from: bo.did, name: 'bo', role: 'human', tier: 'friend', mine: false, operator: false, note: 'not your operator', text: 'ship it @creator', mentions: [ME], mentioned: true, via: ana.did, at: now() }];
    Object.assign(g, { run: 20, quiet: true, last: { name: 'bo', text: 'ship it @creator', at: now(), mine: false } }); bump();
    await poll();
    const msgs = root.all().filter((e) => /^msg /.test(e.className));
    ok(msgs.length === 2 && msgs[0].textContent.includes('ana · your agent') && !msgs[0].textContent.includes('not your operator') && msgs[1].textContent.includes('bo · not your operator · via the creator')
      && msgs[1].className.includes('mentioned') && msgs[1].textContent.includes('Mentions you'),
      `group chat: each message with its sender's name, "your agent" for mine (the mock's "Mara's agent"); "not your operator" for a non-own sender (bo), not for my own agent (ana); a mention marked (${msgs.map((m) => m.textContent).join(' | ')})`);
    ok(has('Agents paused after 20 messages in a row. Write anything to let them go on.'), 'group chat: the pause reached, said in the thread');
    const text = aria('Message', 'TEXTAREA');
    text.value = 'go on @'; fire(text, 'input'); await settle();
    const chip = root.all().find((e) => e.tagName === 'BUTTON' && e.textContent === '@bo');
    ok(chip && !chip.parent.hidden, 'group chat: @ shows the members to mention');
    await chip.click(); await settle();
    ok(text.value === 'go on @bo ', `group chat: a member tapped: @bo in the text (${JSON.stringify(text.value)})`);
    await aria('Send', 'BUTTON').click(); await settle();
    ok(calls.some(([m, p, b]) => p === '/api/groups/send' && b.group === g.gid && b.text === 'go on @bo ') && text.value === '', 'group chat: Send → POST /api/groups/send {group, text}; the box empties');
    await root.all().find((e) => e.className === 'who').click(); await settle(); await poll();
    const member = (d) => root.all().find((e) => e.attrs['data-member'] === d);
    ok(h1() === 'crew' && has('People') && has('Agents') && member(ME)?.textContent.includes('You') && member(ana.did)?.tagName === 'BUTTON' && btn('Add people') && has('Pause agents after 20 in a row') && btn('Leave group') && has('3 of 8'),
      'group info: People and Agents, you marked; a member opens its actions (the creator\'s); Add people, the pause, Leave group');
    await member(ana.did).click(); await settle();
    await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Count it as a person')).click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/groups/role' && b.member === ana.did && b.role === 'human'), 'group info: a member counted as a person → POST /api/groups/role');
    await member(bo.did).click(); await settle();
    await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Send the group to it again')).click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/groups/share' && b.member === bo.did), 'group info: Send the group to it again → POST /api/groups/share {group, member}');
    const pause = aria('Pause agents after 20 in a row', 'INPUT');
    ok(pause?.checked === true, 'group info: the pause on, at 20 (the default)');
    pause.checked = false; fire(pause, 'change'); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/groups/brake' && b.brake === 'off') && GR.groups[0].brake === 'off', 'group info: the pause off → POST /api/groups/brake {brake: "off"}');
    await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Rename')).click(); await settle();
    const rn = kit(root).field('Name');
    rn.value = 'ship'; await btn('Save').click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/groups/rename' && b.name === 'ship') && h1() === 'ship', 'group info: Rename (a sheet) → POST /api/groups/rename');
    await member(bo.did).click(); await settle();
    void root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Remove bo')).click(); await settle(); await settle();
    ok(sheet() && sh1() === 'Remove bo from ship?', 'group info: Remove asks in a sheet naming both');
    await root.all().filter((e) => e.tagName === 'BUTTON' && e.textContent === 'Remove bo').at(-1).click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/groups/remove' && b.members[0] === bo.did) && !member(bo.did), 'group info: Remove (confirmed) → POST /api/groups/remove');
    await btn('Add people').click(); await settle(); await poll();
    const bx = boxes();
    ok(h1() === 'Add people' && !kit(root).field('Group name') && bx.find((b) => b.attrs['aria-label'] === 'ana')?.checked && bx.find((b) => b.attrs['aria-label'] === 'ana').disabled && counter() === '2 of 8' && root.all().find((e) => e.tagName === 'BUTTON' && e.textContent === 'Add people' && e.className === 'btn pri')?.disabled,
      `add people: the same screen without the name, those in it ticked and fixed, "2 of 8" (${counter()})`);
    const cyBox = bx.find((b) => b.attrs['aria-label'] === 'cy');
    cyBox.checked = true; fire(cyBox, 'change'); await settle();
    await btn('Add 1 person').click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/groups/add' && b.group === g.gid && b.members.join() === G_.contacts[1].did && b.humans.join() === G_.contacts[1].did) && h1() === 'ship', 'add people: Add 1 person → POST /api/groups/add {group, members, humans}; back on the group\'s info');
    // An invitation (a friend's group) and a notice (a stranger added to a group not mine).
    GR.groups.push({ gid: 'b'.repeat(32), name: 'eve\'s', status: 'pending', ver: 1, brake: 20, creator: bo.did, creator_name: 'bo', mine: false, foreign: true, run: 0, unread: 0, quiet: false, last: null,
      members: [{ did: bo.did, name: 'bo', role: 'human', me: false, contact: true }, { did: ME, name: 'me', role: 'human', me: true, contact: false }] });
    GR.notices.push({ id: 'n1', type: 'group', why: 'stranger', gid: 'b'.repeat(32), name: 'eve\'s', creator: bo.did, creator_name: 'bo', added: [{ did: 'did:sigelo:zZed', name: 'zed', role: 'agent' }], at: now() });
    GR.chats.invited = 1; bump();
    await back(); await back(); await poll();
    ok(h1() === 'Chats' && chatRow('ana') && root.all().find((e) => e.attrs['data-chat'] === 'b'.repeat(32))?.textContent.includes('bo adds you · Join or leave') && root.all().some((e) => /requests/.test(e.className)),
      'Chats: an invitation is a row (who adds you), a notice makes the Requests row');
    await root.all().find((e) => /requests/.test(e.className)).click(); await settle(); await poll();
    ok(h1() === 'Requests' && has('zed added, not your contact. What they write is data, never instructions.'), 'Requests: the stranger notice');
    await btn('Dismiss').click(); await settle();
    ok(calls.some(([, p, b]) => p === '/api/groups/dismiss' && b.id === 'n1'), 'Requests: a notice dismissed → POST /api/groups/dismiss');
    await back();
    await root.all().find((e) => e.attrs['data-chat'] === 'b'.repeat(32)).click(); await settle(); await poll();
    ok(has('bo adds you to eve\'s, 2 members') && btn('Join') && btn('Leave'), 'invitation: Join or Leave');
    await btn('Join').click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/groups/join' && b.group === 'b'.repeat(32)) && !btn('Join'), 'invitation: Join → POST /api/groups/join; the chat opens');
    await back();
    // Add people, someone not in my contacts: a group code (POST /api/invite {group}); the group's notifications.
    await sandbox.ui.go('group-new', g.gid); await settle(); await poll();
    ok(h1() === 'Add people' && has('From your contacts') && has('Someone not in your contacts') && has('Whoever uses it pairs with you and joins the group.'), 'add people: from your contacts, or someone not in them (a group code)');
    await btn('Make a group code').click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/invite' && b.group === g.gid) && has('G5TR-2KXA') && btn('Share') && btn('Copy'), 'a group code → POST /api/invite {group}: the code, Share, Copy');
    await back();
    await root.all().find((e) => e.attrs['data-chat'] === g.gid).click(); await settle(); await poll();
    await root.all().find((e) => e.className === 'who').click(); await settle(); await poll();
    const gn = aria('Notifications', 'INPUT');
    gn.checked = false; fire(gn, 'change'); await settle();
    ok(calls.some(([, p, b]) => p === '/api/notify' && b.chat === g.gid && b.on === false), 'group info: Notifications off → POST /api/notify {chat: gid, on: false}');
    gOf(g.gid).notify = true;
    await back(); await back();
  }

  // ---- Settings → Relay (Monerujo's node picker): the one in use marked, the public list on demand, Test before OK
  {
    await tabBtn('me').click(); await settle(); await poll();
    ok(h1() === 'Me' && has('My code and QR') && has('People and teams') && has('Devices and computers') && aria('Settings', 'BUTTON'), 'Me: who I am, My code and QR, People and teams, Devices and computers, Settings');
    await aria('Settings', 'BUTTON').click(); await settle(); await poll();
    ok(h1() === 'Settings' && ['Wallet', 'Backup and recovery', 'Relay', 'Chats and history', 'Lock', 'Appearance', 'About'].every(has) && has(`Version ${PKG_VERSION}`), 'Settings: Wallet, Backup and recovery, Relay, Chats and history, Lock, Appearance, About');
    await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Relay')).click(); await settle(); await poll();
    ok(h1() === 'Relay' && root.all().some((e) => e.attrs['data-relay'] === 'relay.sigelo.ai' && e.attrs['aria-pressed'] === 'true') && btn('Show the public list') && has('keeps undelivered ones for 7 days'), 'relay: the one in use marked, the public list on demand, how long it keeps messages');
    await btn('Show the public list').click(); await settle();
    ok(root.all().some((e) => e.attrs['data-relay'] === 'relay.example.org'), 'relay: the public list read (GET /api/relays)');
    await btn('Add a relay').click(); await settle();
    const custom = kit(root).field('Another relay');
    custom.focus(); custom.value = 'down.exa';
    await poll();
    ok(focus.el === custom && root.contains(custom) && custom.value === 'down.exa', 'relay: the field being typed in keeps the focus across the screen drawn again');
    custom.value = 'wss://relay.example.org/mqtt';
    await btn('Test').click(); await settle();
    ok(calls.some(([m, p, b]) => p === '/api/relays/test' && b.relay === 'relay.example.org'), 'relay: a wss:// address on 443 is read as its relay name (the host)');
    custom.value = 'down.example.org';
    await btn('OK').click(); await settle();
    ok(has('No answer: cannot reach the relay') && !calls.some(([m, p, b]) => p === '/api/settings' && m === 'POST'), 'relay: OK tests first: a relay that does not answer is not taken (No answer, why)');
    custom.value = 'relay.example.org';
    await btn('OK').click(); await settle(); await poll();
    ok(calls.some(([m, p, b]) => m === 'POST' && p === '/api/settings' && b.relay === 'relay.example.org') && root.all().some((e) => e.attrs['data-relay'] === 'relay.example.org' && e.attrs['aria-pressed'] === 'true') && !btn('OK'),
      'relay: a relay that answers is tested, then taken (POST /api/settings); the field closes');
    await back();
    await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Chats and history')).click(); await settle(); await poll();
    const rs = aria('Send seen receipts', 'INPUT');
    ok(h1() === 'Chats and history' && has('New people\'s messages') && aria('Just a count', 'INPUT')?.checked && aria('Show when I\'m online', 'INPUT')?.checked === false && rs?.checked === true
      && aria('Notifications', 'INPUT')?.checked === true && btn('Clear all chat history…'), 'Settings → Chats and history: new people\'s messages (Just a count), Show when I\'m online (off), Send seen receipts (on), Notifications (on), Clear');
    rs.checked = false; fire(rs, 'change'); await settle();
    const qu = aria('Quiet', 'INPUT'); qu.checked = true; fire(qu, 'change'); await settle();
    ok(calls.some(([m, p, b]) => m === 'POST' && p === '/api/settings' && b.seen_receipts === false) && calls.some(([m, p, b]) => m === 'POST' && p === '/api/settings' && b.new_tier === 'quiet')
      && SET.seen_receipts === false && has('Off: they see one tick, never when you read'), 'Send seen receipts off, Quiet for new people → POST /api/settings {seen_receipts: false}, {new_tier: quiet}');
    await back();
    await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Wallet')).click(); await settle(); await poll();
    const wsw = aria('Wallet for sigelo', 'INPUT');
    wsw.checked = true; fire(wsw, 'change'); await settle();
    await back(); await back();
    ok(h1() === 'Me' && root.all().filter((e) => e.attrs['data-tab']).map((e) => e.kids.at(-1).textContent).join() === 'Chats,Agents,Wallet,Me', 'Settings → Wallet on: the Wallet tab shows');
    ok(calls.some(([m, p, b]) => m === 'POST' && p === '/api/settings' && b.wallet === true) && SET.wallet === true, 'Settings → Wallet on → POST /api/settings {wallet: true} (the profile\'s setting, not this device\'s)');
    await tabBtn('wallet').click(); await settle(); await poll();
    ok(h1() === 'Wallet' && has('This phone has no wallet yet') && !has('XMR'), 'Wallet on this phone (GET /api/wallet where: none): "This phone has no wallet yet", no balance');
  }

  // ---- pass 3 (design/ux1/build.md "Pass 3"): Agents with the keeper of this computer (GET /api/keeper): the allowances
  // card and line (Wallet on only), Needs you, a payment request approved in 2 taps (task 4), an agent's page (last
  // activity, its four words, the allowance), its keeper settings (the four, then Advanced; Save, Restart), the keeper
  // elsewhere, Revoke in 4 taps (task 10), Enrol in 4 (task 3), a contact's kind (This is an agent)
  {
    const ADDR = '5' + 'B'.repeat(94), NONCE = 'ab'.repeat(16), SCOUT = 'did:sigelo:zscout' + '0'.repeat(40);
    G_.mine.push(person('scout', { did: SCOUT, tier: 'own', ours: true, presence: 'own', kind: 'agent', kind_set: false, last: { dir: 'in', text: 'Found 3 trips', at: now() - 120, status: null } }));
    W_.workers.push({ worker: W_.workers.length, name: 'scout', did: SCOUT, original: SCOUT, words: 'harvest ivory comet nine', rank: null, placed: 'remote', at: now() - 30 * 86400, status: 'enrolled', revoked: null, seen: null, tier: 'own', contact: SCOUT, local: null, online: true, last_seen: null, attested_until: now() + 40 * 86400, enrolling: null });
    const SW = W_.workers.at(-1).worker;
    const K_ = { state: 'here', keepers: [{ id: 'keeper', did: 'did:sigelo:zKeeper', net: 'stagenet', port: 38090, approvers: [ME], me_approver: true, restart: { command: 'systemctl --user restart sigelo-keeper-keeper.service', can: true } }],
      agents: [{ keeper: 'keeper', name: 'scout', worker: SW, did: SCOUT, account: 1, per_tx_max: '100000000000', per_period_max: '500000000000', period_seconds: 2592000, rate_per_minute: 3, approval_above: '20000000000', max_delegates: 0,
        allow: [{ kind: 'addr', addr: ADDR, label: 'seat-hold' }], spent: '120000000000', remaining: '380000000000', window_start: now() - 2592000 }],
      requests: [{ keeper: 'keeper', nonce: NONCE, agent: 'scout', worker: SW, amount: '30000000000', to: ADDR, purpose: 'seat-hold service', ref: 'r1', iat: now() - 60, exp: now() + 3500 }] };
    const KS = { k: K_, live: false };
    Object.assign(routes, {
      'GET /api/keeper': () => KS.k,
      'POST /api/keeper/agent': (b) => { Object.assign(K_.agents[0], Object.fromEntries(Object.entries(b).filter(([k]) => k !== 'keeper' && k !== 'agent' && k !== 'allow'))); return { saved: true, keeper: 'keeper', agent: 'scout', live: KS.live, restart: K_.keepers[0].restart }; },
      'POST /api/keeper/approvers': (b) => ({ saved: true, keeper: b.keeper, approvers: b.me ? [ME] : [], restart: K_.keepers[0].restart }),
      'POST /api/keeper/approve': (b) => { K_.requests = K_.requests.filter((r) => r.nonce !== b.nonce); return { approved: true, keeper: b.keeper, nonce: b.nonce, agent: 'scout', amount: '30000000000', next: '' }; },
      'POST /api/keeper/refuse': (b) => { K_.requests = K_.requests.filter((r) => r.nonce !== b.nonce); return { refused: true, keeper: b.keeper, nonce: b.nonce, exp: now() + 3500, logged: true, told: true }; },
      'POST /api/keeper/restart': (b) => ({ restarted: true, keeper: b.keeper }),
      'POST /api/kind': (b) => { const c = [...G_.mine, ...G_.contacts].find((x) => x.did === b.contact); Object.assign(c, { kind: b.kind, kind_set: true }); return { did: c.did, kind: b.kind, kind_set: true }; },
    });
    const walletOff = () => { SET.wallet = false; };
    await tabBtn('chats').click(); await settle(); await poll();
    await tabBtn('agents').click(); await settle(); await poll(); await poll();
    const scoutRow = () => rows().find((e) => e.textContent.includes('scout') && e.attrs['data-worker'] === String(SW));
    const reqRow = () => root.all().find((e) => e.attrs['data-request'] === NONCE);
    const card = () => root.all().find((e) => e.attrs['data-allowances'] !== undefined);
    ok(h1() === 'Agents' && card()?.textContent.includes('Allowances this month') && card().textContent.includes('0.12 of 0.50 XMR spent by your agents') && has('Needs you') && reqRow()?.textContent.includes('Asks to pay 0.03 XMR')
      && scoutRow()?.textContent.includes('0.12 of 0.50 XMR this month') && calls.some(([m, p]) => m === 'GET' && p === '/api/keeper'),
      'Agents (Wallet on): the allowances card (0.12 of 0.50 XMR spent by your agents), Needs you (scout asks to pay 0.03 XMR), the allowance line on its row (GET /api/keeper)');
    walletOff(); await poll();
    ok(!card() && !scoutRow()?.textContent.includes('XMR') && scoutRow()?.textContent.includes('on another machine') && reqRow(), 'Wallet off: no allowances card and no allowance line (where it runs instead); Needs you stays (an approval is not the wallet)');
    SET.wallet = true;
    await poll();
    // Task 4: the request, then Approve.
    let taps = 0;
    await reqRow().click(); taps++; await settle(); await poll();
    ok(h1() === 'Payment request' && has('scout asks to pay') && has('0.03 XMR') && has('seat-hold service') && has('seat-hold') && btn('Approve') && btn('Refuse'), 'a payment request: who, how much, for what, to whom (its allowlist label), Approve / Refuse');
    await btn('Approve').click(); taps++; await settle(); await poll();
    ok(taps === 2 && calls.some(([m, p, b]) => p === '/api/keeper/approve' && b.keeper === 'keeper' && b.nonce === NONCE) && has('Approved') && has('scout pays it the next time it asks'),
      'task 4, 2 taps: the Needs you row, Approve → POST /api/keeper/approve {keeper, nonce}; Approved');
    await btn('Done').click(); await settle(); await poll();
    ok(h1() === 'Agents' && !reqRow(), 'Done: back on Agents, nothing waiting');
    K_.requests.push({ keeper: 'keeper', nonce: 'cd'.repeat(16), agent: 'scout', worker: SW, amount: '40000000000', to: ADDR, purpose: 'a table', ref: 'r2', iat: now() - 30, exp: now() + 3500 });
    sandbox.ui.go('approve', { keeper: 'keeper', nonce: 'cd'.repeat(16) }); await settle(); await poll();
    void btn('Refuse').click(); await settle();
    const whyIn = kit(root).field('Why (scout reads it)');
    ok(sheet() && sh1() === 'Refuse 0.04 XMR?' && has('scout is told in its chat, with your reason.') && whyIn, 'Refuse: a sheet naming the amount, that scout is told, a reason to give');
    whyIn.value = 'not this month';
    await root.all().filter((e) => e.tagName === 'BUTTON' && e.textContent === 'Refuse').at(-1).click(); await settle(); await poll();
    ok(calls.some(([m, p, b]) => p === '/api/keeper/refuse' && b.nonce === 'cd'.repeat(16) && b.reason === 'not this month') && has('Refused') && has('Not paid. The keeper refuses this payment until') && has('scout was told in its chat.'),
      'Refuse → POST /api/keeper/refuse {keeper, nonce, reason}; Refused: the keeper refuses it, scout told in its chat');
    await btn('Done').click(); await settle(); await poll();
    // The agent's page and its keeper settings.
    await scoutRow().click(); await settle(); await poll();
    ok(h1() === 'scout' && has('Allowance') && has('0.12 of 0.50 XMR') && has('Asks you above 0.02 XMR · Change') && has('Last activity') && has('Messaged you') && has('Found 3 trips')
      && has('Its four words') && has('harvest · ivory · comet · nine') && btn('Message') && btn('Revoke scout'), 'an agent\'s page: the allowance card, Last activity (its last message), its four words, Message, Revoke');
    await root.all().find((e) => e.attrs['data-allowance'] !== undefined).click(); await settle(); await poll();
    const fld = kit(root).field;
    ok(h1() === 'scout\'s allowance' && fld('Per payment')?.value === '0.10' && fld('Per period')?.value === '0.50' && fld('Each')?.value === '2592000' && has('Who it may pay') && has('seat-hold')
      && fld('Ask me before paying more than')?.value === '0.02' && has('Advanced') && fld('Payments per minute')?.value === '3' && fld('Agents it may add under itself')?.value === '0'
      && aria('I approve its payments', 'INPUT')?.checked === true && has('keeper settings are re-entered') && btn('Save') && !btn('Save').disabled,
      'keeper settings: per payment, per period (and the period), who it may pay, ask me above; Advanced: per minute, delegates, approvers (I approve); the recovery fact; Save never disabled');
    fld('Per payment').value = 'abc'; fire(fld('Per payment'), 'blur');
    ok(has('Enter an amount in XMR, like 0.25'), 'a field left wrong says how to fix it, under it (on leaving it)');
    await btn('Save').click(); await settle();
    ok(!calls.some(([, p]) => p === '/api/keeper/agent') && has('Fix the fields marked above, then save.'), 'Save with a field wrong: nothing written, said where');
    fld('Per payment').value = '0.05'; fire(fld('Per payment'), 'input');
    await btn('Save').click(); await settle(); await poll();
    const saved = calls.find(([, p]) => p === '/api/keeper/agent')?.[2];
    ok(saved?.keeper === 'keeper' && saved.agent === 'scout' && saved.per_tx_max === '50000000000' && saved.per_period_max === '500000000000' && saved.approval_above === '20000000000' && saved.rate_per_minute === 3
      && JSON.stringify(saved.allow) === JSON.stringify([{ addr: ADDR, label: 'seat-hold' }]) && has('Saved.') && has('This keeper is from before 0.1.15: it uses it after a restart.') && btn('Restart the keeper'),
      `Save, to a keeper from before 0.1.15 → POST /api/keeper/agent in atomic units, the allowlist as the keeper writes it; Saved, Restart the keeper (${JSON.stringify(saved)})`);
    await btn('Restart the keeper').click(); await settle();
    ok(calls.some(([, p, b]) => p === '/api/keeper/restart' && b.keeper === 'keeper'), 'Restart the keeper → POST /api/keeper/restart');
    KS.live = true;
    await btn('Save').click(); await settle(); await poll();
    ok(has('Saved.') && has('The keeper uses it from its next payment.') && !btn('Restart the keeper'), 'Save, to a keeper that re-reads its policy (0.1.15): "uses it from its next payment", no Restart');
    const me_ = aria('I approve its payments', 'INPUT'); me_.checked = false; fire(me_, 'change'); await settle();
    ok(calls.some(([, p, b]) => p === '/api/keeper/approvers' && b.me === false), 'Advanced → I approve its payments off → POST /api/keeper/approvers {me: false}');
    await back();
    // The keeper on another computer (this app): said, no fake numbers.
    KS.k = { state: 'elsewhere' };
    await sandbox.ui.go('agent', SW); await settle(); await poll();
    await sandbox.ui.go('agent-allowance', SW); await settle(); await poll();
    ok(has('Set this on the computer that runs the keeper.') && !has('0.12 of') && !btn('Save'), 'keeper elsewhere: "Set this on the computer that runs the keeper", no numbers, no Save');
    KS.k = K_;
    // Task 10: revoke from Chats in 4 taps (Agents, the agent, Revoke, Revoke in the sheet).
    await sandbox.ui.go('chats'); await settle(); await poll();
    taps = 0;
    await tabBtn('agents').click(); taps++; await settle(); await poll();
    await scoutRow().click(); taps++; await settle(); await poll();
    void btn('Revoke scout').click(); taps++; await settle();
    ok(sheet() && sh1() === 'Revoke scout?' && btn('Keep scout'), 'Revoke scout: the confirm sheet names it, Keep scout');
    await root.all().filter((e) => e.tagName === 'BUTTON' && e.textContent === 'Revoke scout').at(-1).click(); taps++; await settle(); await poll();
    ok(taps === 4 && calls.some(([, p, b]) => p === '/api/agents/revoke' && b.worker === SW), 'task 10, 4 taps: Agents, scout, Revoke scout, Revoke scout (confirmed) → POST /api/agents/revoke');
    // Task 3: enrol from Chats in 4 taps (Agents, Enrol agent, Make a code, They match), the code with QR and Share, the words on both sides.
    await sandbox.ui.go('chats'); await settle(); await poll();
    taps = 0;
    await tabBtn('agents').click(); taps++; await settle(); await poll();
    await btn('Enrol agent').click(); taps++; await settle(); await poll();
    kit(root).field('Agent name').value = 'notes';
    await btn('Make a code').click(); taps++; await settle(); await poll();
    const nw = W_.workers.at(-1);
    ok(h1() === 'Code for notes' && btn('Share') && btn('Copy') && has('Give it to notes: share it, or let it scan the QR.'), 'enrol: the code, Share and Copy, the QR to scan');
    Object.assign(nw.enrolling, { state: 'words', code: null, command: null, words: 'harvest ivory comet nine' }); await poll();
    ok(h1() === 'Is this notes?' && has('The agent shows four words. Same words here?'), 'enrol: its four words, to compare with the ones the agent shows');
    await btn('They match').click(); taps++; await settle();
    Object.assign(nw.enrolling, { state: 'enrolled', words_ok: true }); Object.assign(nw, { status: 'enrolled', contact: null }); await poll();
    ok(taps === 4 && has('notes is ready') && btn('Done')?.className === 'btn pri' && !calls.some(([, p, b]) => p === '/api/send' && b.to === nw.did), 'task 3, 4 taps: Agents, Enrol agent, Make a code, They match; ready, Done first, no first message sent');
    await btn('Done').click(); await settle(); await poll();
    // A contact's kind: set by hand in Chat settings; the mark follows the API's kind.
    const cy = G_.contacts.find((c) => c.name === 'cy');
    await sandbox.ui.go('chat-info', cy.did); await settle(); await poll();
    const isAgent = aria('This is an agent', 'INPUT');
    ok(isAgent && isAgent.checked === false, 'Chat settings: "This is an agent", off for a person');
    isAgent.checked = true; fire(isAgent, 'change'); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/kind' && b.contact === cy.did && b.kind === 'agent'), 'This is an agent on → POST /api/kind {contact, kind: agent}');
    await sandbox.ui.go('chats'); await settle(); await poll();
    ok(chatRow('cy')?.textContent.includes('Agent') && chatRow('cy').all().some((e) => /\bag\b/.test(e.className)), 'Chats: cy now carries the agent mark and "Agent"');
  }

  // ---- pass 4 (design/ux1/build.md "Pass 4"): the Wallet of a computer (GET /api/wallet ready), every sync state as Decided
  // (syncing with progress, synced, can't reach the node, can't reach the wallet service; the balance greyed "as of" until
  // synced; Send only once synced), the allowance lines with the same state, Receive (task 8), Send (task 9), Pay in a chat
  // (task 5), History and a payment, Settings → Wallet with prices on, the node, the wallet service, approvers, the allowances
  // screen and Top up, the keeper's seen addresses under "Who it may pay"
  {
    const ADDR2 = '5' + 'C'.repeat(94), MINE = '7' + 'D'.repeat(94), TX1 = 'a1'.repeat(32), TX2 = 'b2'.repeat(32), TX3 = 'c3'.repeat(32);
    const bo = G_.contacts.find((c) => c.name === 'bo'), t0 = now();
    SET.wallet = true;
    const base = { on: true, where: 'here', ready: true, service: { kind: 'keeper', keeper: 'keeper', url: 'http://127.0.0.1:38083/json_rpc', account: 2 }, node: 'node.example.org:38089', net: 'stagenet', payees: {} };
    const syncing = { ...base, sync: { state: 'syncing', height: 3510000, chain: 3512160, behind: 2160, behind_s: 259200, progress: 0.4, synced_at: t0 - 3 * 86400, checked_at: t0 },
      balance: { total: '912000000000', unlocked: '912000000000', blocks_to_unlock: 0, at: t0 - 3 * 86400, current: false } };
    const syncedV = { ...base, sync: { state: 'synced', height: 3512160, chain: 3512160, behind: 0, behind_s: 0, progress: null, synced_at: t0 - 120, checked_at: t0 },
      balance: { total: '912000000000', unlocked: '812000000000', blocks_to_unlock: 6, at: t0, current: true } };
    const nodeDown = { ...base, sync: { state: 'node', height: 3512100, chain: null, behind: 0, behind_s: 0, progress: null, synced_at: t0 - 600, checked_at: t0, detail: 'timeout' },
      balance: { ...syncedV.balance, current: false, at: t0 - 600 } };
    const walletDown = { ...base, sync: { state: 'wallet', detail: 'no answer', synced_at: t0 - 600, checked_at: t0 }, balance: { total: '912000000000', unlocked: '812000000000', at: t0 - 600, current: false } };
    const HIST = { entries: [
      { txid: TX2, dir: 'in', amount: '100000000000', fee: '0', at: null, height: null, confirmations: 0, status: 'pending', address: MINE, note: '', contact: null, contact_name: null },
      { txid: TX1, dir: 'in', amount: '250000000000', fee: '0', at: t0 - 3600, height: 3512100, confirmations: 60, status: 'confirmed', address: MINE, note: 'Concert tickets', contact: null, contact_name: null },
      { txid: TX3, dir: 'out', amount: '50000000000', fee: '30000000', at: t0 - 86400, height: 3511400, confirmations: 700, status: 'confirmed', address: ADDR2, note: 'For the deposit', contact: bo.did, contact_name: 'bo' }] };
    const REV = { n: 0 };
    WAL.v = syncing;
    Object.assign(routes, {
      'POST /api/wallet/sync': () => WAL.v,
      'GET /api/wallet/history': () => HIST,
      'GET /api/wallet/tx': (b, path) => ({ ...HIST.entries.find((e) => path.includes(e.txid)), suggested: 10, double_spend: false }),
      'POST /api/wallet/receive': () => ({ address: MINE, index: 7, account: 2 }),
      'POST /api/wallet/label': (b) => ({ index: b.index, note: b.note }),
      'POST /api/wallet/review': (b) => ({ id: `r${++REV.n}`, exp: now() + 600, to: b.to.addr ?? 'agent-address', contact: b.to.contact ?? null, agent: b.to.agent ?? null, amount: b.amount === 'all' ? '812000000000' : b.amount, fee: '30000000', total: String(BigInt(b.amount === 'all' ? '812000000000' : b.amount) + 30000000n), note: b.note ?? '', all: b.amount === 'all' }),
      'POST /api/wallet/send': (b) => { const r = calls.filter(([, p]) => p === '/api/wallet/review').at(-1)[2]; return { sent: true, txids: [TX3], amount: r.amount === 'all' ? '812000000000' : r.amount, fee: '30000000', to: r.to.addr ?? 'agent-address', contact: r.to.contact ?? null, agent: r.to.agent ?? null, note: r.note ?? '', told: !!r.to.contact }; },
      'POST /api/send': (b) => ({ n: 99, at: now(), kind: 'out', did: b.to, id: 'x', text: b.text, status: 'sent' }),
      'GET /api/price': () => (SET.prices ? { on: true, currency: SET.currency ?? 'EUR', rate: { EUR: 150, CHF: 141 }[SET.currency ?? 'EUR'], at: now() - 60, source: 'CoinGecko', stale: false } : { on: false, currency: SET.currency ?? null }),
      'GET /api/wallet/nodes': () => ({ in_use: 'node.example.org:38089', nodes: [{ url: 'node.example.org:38089', ok: true, height: 3512160, ms: 80, in_use: true, behind: 0, from: 'keeper' }, { url: 'my-node.home.example:18089', ok: true, height: 3512100, ms: 300, in_use: false, behind: 60, from: 'added' }] }),
      'POST /api/wallet/node': (b) => routes['GET /api/wallet/nodes'](),
      'GET /api/wallet/services': () => ({ current: { kind: 'keeper', keeper: 'keeper', url: 'http://127.0.0.1:38083/json_rpc', account: 2, chosen: true }, why: null, unreadable: null, rpc: null,
        keepers: [{ keeper: 'keeper', url: 'http://127.0.0.1:38083/json_rpc', net: 'stagenet', error: null, accounts: [{ index: 0, label: 'Primary account', balance: '0', held: null }, { index: 1, label: 'scout', balance: '380000000000', held: 'scout' }, { index: 2, label: 'me', balance: '912000000000', held: null }] }] }),
      'POST /api/wallet/service': () => routes['GET /api/wallet/services'](),
    });
    const syncAttr = () => root.all().find((e) => e.attrs['data-sync'] !== undefined)?.attrs['data-sync'];
    const balEl = () => root.all().find((e) => e.attrs['data-balance'] !== undefined);
    await sandbox.ui.go('chats'); await settle(); await poll();
    // Task 7 (1 tap): the balance, from Chats. Syncing: the progress, the balance greyed "as of", Send disabled and why.
    let taps = 0;
    await tabBtn('wallet').click(); taps++; await settle(); await poll();
    ok(taps === 1 && h1() === 'Wallet' && syncAttr() === 'syncing' && has('Syncing… 3 days behind') && root.all().some((e) => e.attrs.role === 'progressbar' && e.attrs['aria-valuenow'] === '40')
      && balEl()?.attrs['data-balance'] === 'stale' && has('0.9120') && has('as of ') && btn('Send')?.disabled === true && has('Send works once your wallet is synced.') && calls.some(([m, p]) => m === 'GET' && p === '/api/wallet'),
      'task 7, 1 tap: Wallet; syncing: "Syncing… 3 days behind" with progress (40%), the balance greyed "as of …", Send disabled, said why (GET /api/wallet: the sync starts)');
    // The allowance lines carry the same state (Agents, the agent's page).
    const SCOUT_W = W_.workers.find((w) => w.name === 'scout');
    SCOUT_W.status = 'enrolled'; SCOUT_W.revoked = null;
    await tabBtn('agents').click(); await settle(); await poll(); await poll();
    const sRow = rows().find((e) => e.attrs['data-worker'] === String(SCOUT_W.worker));
    ok(sRow?.textContent.includes('0.12 of 0.50 XMR this monthSyncing… 3 days behind') && sRow.all().some((e) => e.attrs['data-sync'] === 'syncing') && root.all().find((e) => e.attrs['data-allowances'] !== undefined)?.textContent.includes('Syncing… 3 days behind'),
      'Agents: the allowance line and the allowances card carry the wallet\'s state (Syncing… 3 days behind)');
    await sRow.click(); await settle(); await poll();
    ok(root.all().find((e) => e.attrs['data-allowance'] !== undefined)?.textContent.includes('Syncing… 3 days behind'), 'the agent\'s page: its allowance card carries the same state');
    // Can't reach the node; can't reach the wallet service: said, Retry (POST /api/wallet/sync), the last balance greyed.
    WAL.v = nodeDown;
    await sandbox.ui.go("wallet"); await settle(); await poll();
    ok(syncAttr() === 'node' && has('Can\'t reach the node') && has('Your wallet\'s node (node.example.org:38089) doesn\'t answer') && btn('Retry') && balEl()?.attrs['data-balance'] === 'stale' && btn('Send').disabled,
      'node down: "Can\'t reach the node", which, Retry; the balance greyed; Send disabled');
    await btn('Retry').click(); await settle();
    ok(calls.some(([m, p]) => m === 'POST' && p === '/api/wallet/sync'), 'Retry → POST /api/wallet/sync');
    WAL.v = walletDown; sandbox.ui.go('wallet'); await settle(); await poll();
    ok(syncAttr() === 'wallet' && has('Can\'t reach the wallet service') && has('monero-wallet-rpc') && balEl()?.attrs['data-balance'] === 'stale', 'wallet service down: "Can\'t reach the wallet service", the last balance greyed');
    // Synced: current, Send on, History with its states.
    WAL.v = syncedV; sandbox.ui.go('wallet'); await settle(); await poll();
    const txRows = () => root.all().filter((e) => e.attrs['data-tx'] !== undefined);
    ok(syncAttr() === 'synced' && has('Synced 2 min ago') && balEl()?.attrs['data-balance'] === 'current' && !has('as of') && btn('Send')?.disabled === false && has('0.1000 XMR arriving or locked')
      && txRows().length === 3 && txRows()[0].textContent.includes('Waiting for confirmation') && txRows()[1].textContent.includes('Concert tickets') && txRows()[1].textContent.includes('+0.2500')
      && txRows()[2].textContent.includes('To bo') && txRows()[2].textContent.includes('−0.0500') && has('Agents\' allowances') && has('0.38 XMR left of 0.50 this month'),
      'synced: "Synced 2 min ago", the balance current, Send ready, what is still locked; History (waiting for confirmation, received with its note, sent to bo); the allowances card');
    await txRows()[1].click(); await settle(); await poll();
    ok(h1() === 'Received' && has('+0.25 ') && has('Concert tickets') && has('Confirmed') && has('paid by the sender') && has(`Transaction ${TX1}`), 'a payment: Received, the amount, its note, Confirmed, the fee paid by the sender, the transaction');
    await back();
    // Task 8 (2 taps from Chats): Wallet, Receive: a new address, its QR, Share, Copy; an amount and a note go in the request.
    await sandbox.ui.go('chats'); await settle(); await poll();
    taps = 0;
    await tabBtn('wallet').click(); taps++; await settle(); await poll();
    await btn('Receive').click(); taps++; await settle(); await poll();
    ok(taps === 2 && h1() === 'Receive' && root.all().some((e) => e.attrs['data-address'] !== undefined && e.textContent === MINE) && btn('Share') && btn('Copy') && has('A new address each time keeps payers from linking you.')
      && calls.some(([m, p]) => p === '/api/wallet/receive'), 'task 8, 2 taps: Wallet, Receive → POST /api/wallet/receive: the address, its QR, Share, Copy');
    kit(root).field('Ask for an amount (optional)').value = '0.1'; kit(root).field('Note (optional)').value = 'Concert tickets';
    await btn('Copy').click(); await settle();
    ok(sandbox.copied === `monero:${MINE}?tx_amount=0.1&tx_description=Concert%20tickets` && calls.some(([, p, b]) => p === '/api/wallet/label' && b.index === 7 && b.note === 'Concert tickets'),
      `Receive: Copy gives the monero: request with the amount and the note; the note kept with the address (POST /api/wallet/label) (${sandbox.copied})`);
    // Task 9 (Wallet, Send, Review, Send: 4 taps, the address pasted; Scan makes 5): review, then send.
    await sandbox.ui.go('chats'); await settle(); await poll();
    taps = 0;
    await tabBtn('wallet').click(); taps++; await settle(); await poll();
    await btn('Send').click(); taps++; await settle(); await poll();
    ok(h1() === 'Send' && has('To a contact') && has('Or to an address') && btn('Scan') && btn('Send all') && has('You have 0.8120 XMR spendable'), 'Send: to a contact, or an address (Scan), Amount with what you have, Send all');
    const fs = kit(root).field;
    fs('Monero address').value = 'nonsense'; fire(fs('Monero address'), 'blur');
    ok(has('Paste their whole Monero address (95 or 106 characters).'), 'Send: an address left wrong says how to fix it');
    fs('Monero address').value = ADDR2; fire(fs('Monero address'), 'input'); fs('Amount (XMR)').value = '0.25'; fs('Note (optional)').value = 'rent';
    await btn('Review').click(); taps++; await settle(); await poll();
    const rv = calls.filter(([, p]) => p === '/api/wallet/review').at(-1)?.[2];
    ok(h1() === 'Check and send' && rv?.to?.addr === ADDR2 && rv.amount === '250000000000' && rv.note === 'rent' && has('0.25 XMR') && has('0.00003 XMR') && has('5CCC…CCCC') && has('Check the first and last 4 characters with the person.'),
      `Review → POST /api/wallet/review {to: {addr}, amount (atomic), note}: Check and send, the amount, the network fee, the address's ends (${JSON.stringify(rv)})`);
    await btn('Send 0.25 XMR').click(); taps++; await settle(); await poll();
    ok(taps === 4 && calls.some(([, p, b]) => p === '/api/wallet/send' && b.id === `r${REV.n}`) && has('Sent 0.25 XMR') && has('It shows in History.') && btn('Back to Wallet'),
      'task 9, 4 taps (the address pasted): Wallet, Send, Review, Send 0.25 XMR → POST /api/wallet/send {id}: Sent, Back to Wallet');
    await btn('Back to Wallet').click(); await settle(); await poll();
    ok(h1() === 'Wallet', 'Back to Wallet');
    // Task 5 (4 taps from Chats: the chat, Pay, Review, Send): to the address bo sent in this chat; the payment shown in the chat.
    const tm = now() - 300;
    MSGS[bo.did] = [{ n: 10, dir: 'in', at: tm, iat: tm, text: `Here's my address: monero:${ADDR2}`, label: '', status: null, code: null, detail: null, link: null }];
    await sandbox.ui.go('chats'); await settle(); await poll();
    taps = 0;
    await chatRow('bo').click(); taps++; await settle(); await poll();
    await btn('Pay').click(); taps++; await settle(); await poll(); await poll();
    ok(h1() === 'Pay bo' && has('To the address bo sent you in this chat (5CCC…CCCC).') && kit(root).field('Note (bo sees it)'), 'Pay bo: the address bo sent in the chat (signed by their key), the amount, a note bo sees');
    kit(root).field('Amount (XMR)').value = '0.05'; kit(root).field('Note (bo sees it)').value = 'Dinner';
    await btn('Review').click(); taps++; await settle(); await poll();
    const pv = calls.filter(([, p]) => p === '/api/wallet/review').at(-1)?.[2];
    ok(h1() === 'Check and send' && pv?.to?.contact === bo.did && pv.to.addr === ADDR2 && pv.amount === '50000000000' && has('bo ✓') && has('Sent to the address bo\'s identity gave in your chat, so nobody can swap it.'),
      `Pay → POST /api/wallet/review {to: {contact, addr}}: Check and send, To bo ✓ (${JSON.stringify(pv)})`);
    await btn('Send 0.05 XMR').click(); taps++; await settle(); await poll();
    ok(taps === 4 && has('Sent 0.05 XMR') && has('bo sees it in your chat. Confirmed in about 2 minutes.') && btn('Back to the chat'), 'task 5, 4 taps: the chat, Pay, Review, Send 0.05 XMR: bo sees it in your chat');
    MSGS[bo.did].push({ n: 11, dir: 'out', at: now(), iat: null, text: `Paid you 0.05 XMR: Dinner. Transaction ${TX3.slice(0, 4)}…${TX3.slice(-4)}.`, label: '', status: 'sent', code: null, detail: null, link: null, pay: { txid: TX3, amount: '50000000000', note: 'Dinner' } });
    sandbox.seq = 2;
    await btn('Back to the chat').click(); await settle(); await poll();
    const payB = root.all().find((e) => e.attrs['data-pay'] === TX3);
    ok(h1() !== 'Check and send' && payB?.textContent.includes('You paid') && payB.textContent.includes('0.05 XMR') && payB.textContent.includes('Dinner · confirmed'), `Back to the chat: the payment in the chat, You paid 0.05 XMR, Dinner · confirmed (${payB?.textContent})`);
    // The same from the attach sheet: Attach, Pay, Review, Send (4 taps inside the chat).
    void aria('Attach', 'BUTTON').click(); await settle();
    ok(sheet() && sh1() === 'Attach' && btn('Pay'), 'the attach sheet: Pay');
    await btn('Pay').click(); await settle(); await poll(); await poll();
    ok(h1() === 'Pay bo', 'Attach → Pay: Pay bo (then Review, Send: 4 taps inside the chat)');
    // No address from them: said, Ask in the chat, or paste one.
    const cy = G_.contacts.find((c) => c.name === 'cy');
    MSGS[cy.did] = [];
    await sandbox.ui.go('pay', cy.did); await settle(); await poll(); await poll();
    ok(has('cy hasn\'t sent you a Monero address in this chat.') && btn('Ask in the chat') && kit(root).field('Their Monero address'), 'Pay with no address from them: said; Ask in the chat; or paste theirs');
    await btn('Ask in the chat').click(); await settle();
    ok(calls.some(([, p, b]) => p === '/api/send' && b.to === cy.did && /Monero address/.test(b.text)), 'Ask in the chat → POST /api/send to them, asking for an address');
    // Settings → Wallet: prices off by default; on: the note (who learns what), the currency; ≈ beside amounts; node, service, approvers.
    await sandbox.ui.go('set-wallet'); await settle(); await poll();
    const priceSw = aria('Show a local price', 'INPUT');
    ok(priceSw && priceSw.checked === false && has('Fetches the Monero price from the network. Off keeps the app fully private.') && !has('≈') && has('Monero node') && has('node.example.org:38089')
      && has('Wallet service') && has('account 2') && has('Approvers') && has('Your 25 words restore the vault and every keeper wallet; keeper settings are re-entered.') && btn('Open Wallet'),
      'Settings → Wallet: Show a local price off (the mock\'s note), the node, the wallet service, approvers, the recovery fact, Open Wallet');
    priceSw.checked = true; fire(priceSw, 'change'); await settle(); await poll(); await poll();
    const curSel = root.all().find((e) => e.tagName === 'SELECT' && e.attrs['aria-label'] === 'Currency');
    ok(calls.some(([, p, b]) => p === '/api/settings' && b?.prices === true && b.currency === 'EUR') && curSel && has('Prices come from CoinGecko through this computer') && has('never your wallet, balance or payments'),
      'prices on → POST /api/settings {prices: true, currency}; the currency; the note: CoinGecko, through the page\'s server, what it learns');
    curSel.value = 'CHF'; fire(curSel, 'change'); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/settings' && b?.currency === 'CHF') && SET.currency === 'CHF', 'a currency chosen → POST /api/settings {currency: CHF}');
    sandbox.ui.go('wallet'); await settle(); await poll(); await poll();
    ok(has('≈') && has('CHF') && calls.some(([m, p]) => m === 'GET' && p === '/api/price'), 'prices on: ≈ and the currency beside the balance (GET /api/price, through the server)');
    await sandbox.ui.go('set-node'); await settle(); await poll(); await poll();
    ok(h1() === 'Monero node' && root.all().some((e) => e.attrs['data-node'] === 'node.example.org:38089' && e.textContent.includes('in use')) && has('60 blocks behind') && btn('Add a node'),
      'Monero node: the nodes (up to date, in use; 60 blocks behind), Add a node');
    await root.all().find((e) => e.attrs['data-node'] === 'my-node.home.example:18089').click(); await settle();
    ok(calls.some(([, p, b]) => p === '/api/wallet/node' && b.use === 'my-node.home.example:18089'), 'a node tapped → POST /api/wallet/node {use}');
    await sandbox.ui.go('set-service'); await settle(); await poll(); await poll();
    const held = aria('Account 1', 'INPUT');
    ok(h1() === 'Wallet service' && aria('Account 2', 'INPUT')?.checked === true && held?.disabled === true && has('scout\'s allowance: not yours') && btn('Make an account for you') && btn('Use it'),
      'Wallet service: the keeper\'s accounts (yours chosen, an agent\'s not choosable), Make an account for you, another wallet program');
    await btn('Make an account for you').click(); await settle();
    ok(calls.some(([, p, b]) => p === '/api/wallet/service' && b.keeper === 'keeper' && b.new_account === true), 'Make an account for you → POST /api/wallet/service {keeper, new_account}');
    await sandbox.ui.go('set-approvers'); await settle(); await poll();
    ok(h1() === 'Approvers' && aria('I approve its agents\' payments', 'INPUT') && btn('Add from contacts'), 'Approvers: I approve its agents\' payments, Add from contacts');
    // The allowances screen and Top up; the keeper's seen addresses under Who it may pay.
    await sandbox.ui.go('allowances'); await settle(); await poll();
    ok(h1() === 'Agents\' allowances' && has('Money your agents may spend, kept apart from your wallet.') && has('0.38 XMR') && has('scout') && btn('Top up allowances') && has('keeper settings are re-entered'),
      'Agents\' allowances: what is left, per agent, Top up allowances, the recovery fact');
    await btn('Top up allowances').click(); await settle(); await poll();
    ok(h1() === 'Top up scout' && has('To scout\'s allowance account in the keeper\'s wallet.'), 'Top up: Send to the agent\'s allowance account');
    kit(root).field('Amount (XMR)').value = '0.1';
    await btn('Review').click(); await settle(); await poll();
    ok(calls.filter(([, p]) => p === '/api/wallet/review').at(-1)?.[2]?.to?.agent === 'scout' && has('scout\'s allowance'), 'Top up → POST /api/wallet/review {to: {agent, keeper}}: to scout\'s allowance');
    routes['GET /api/keeper']().keepers[0].seen = [{ addr: ADDR2, agent: 'scout', purpose: 'seat-hold', did: null, invoice: false, paid: true, last: now() - 3600 }];
    await sandbox.ui.go('agent-allowance', SCOUT_W.worker); await settle(); await poll();
    await btn('Add someone').click(); await settle();
    const seenRow = root.all().find((e) => e.attrs['data-seen'] === ADDR2);
    ok(sheet() && has('Seen by the keeper') && seenRow?.textContent.includes('Paid by scout · seat-hold'), 'Who it may pay: the addresses the keeper has seen (paid by scout · seat-hold), beside the contacts');
    await seenRow.click(); await settle();
    await root.all().filter((e) => e.tagName === 'BUTTON' && e.textContent === 'Add').at(-1).click(); await settle(); await poll();
    ok(!sheet() && has('seat-hold'), 'a seen address chosen and added to the list (named from its purpose)');
    // Off again: no tab, no wallet call.
    SET.wallet = false; await sandbox.ui.go('chats'); await settle(); await poll();
    const before = calls.filter(([, p]) => p.startsWith('/api/wallet')).length;
    await tabBtn('agents').click(); await settle(); await poll();
    ok(!tabBtn('wallet') && calls.filter(([, p]) => p.startsWith('/api/wallet')).length === before, 'Wallet off: no tab, and no wallet call (no sync)');
    SET.wallet = true;
  }

  // ---- Pass 5 (design/ux1/build.md "Pass 5"): Me, a picture, People and teams, a person, a team, sign and check (and the
  // signed bubble: task 11), the public invite, proof of age; task 12 from Me (3 taps)
  {
    SET.wallet = false;
    const bo = G_.contacts.find((c) => c.name === 'bo'), ST = 'sigelo-statement/0 eyJhIjoxfQ', PIC = {};
    G_.contacts.push(person('booker', { kind: 'agent', link: { id: 'l1', purpose: 'bookings', linked_by: bo.did, expires: null } }));
    sandbox.intro = [{ id: 'i9', from: bo.did, name: 'bo', purpose: 'research', peer_name: 'research' }];
    const booker = G_.contacts.at(-1), TEAM = 'c'.repeat(32);
    // A team: people and their agents in one roster (bo brings booker, introduced by him).
    GR.groups.push({ gid: TEAM, name: 'Studio', status: 'member', ver: 1, brake: 20, creator: ME, creator_name: null, mine: true, foreign: false, run: 0, unread: 0, quiet: false, notify: true, last: null,
      members: [{ did: ME, name: 'creator', role: 'human', me: true, contact: false }, { did: bo.did, name: 'bo', role: 'human', me: false, contact: true }, { did: booker.did, name: 'booker', role: 'agent', me: false, contact: true }] });
    bump();
    sandbox.pending = { ...(sandbox.pending ?? {}), invites: [{ id: 'i1', name: 'contact-1a2b', exp: now() + 86400, relay: 'relay.sigelo.ai', short: 'K7F3-Q9ZP', short_exp: now() + 600, code: 'sgl1example' }] };
    const stText = (t) => `${t}\n-- Signed with sigelo by amber otter violin harbor. Check it in the sigelo app.\n${ST}`;
    Object.assign(routes, {
      'GET /api/picture': () => ({ __error: { check: 'picture_none', message: 'no picture' } }),
      'POST /api/picture': (b) => { PIC.last = b; return { of: b.of, picture: b.remove ? null : 'r1', local: b.of !== 'me' && !b.remove }; },
      'POST /api/statement/sign': (b) => ({ statement: stText(b.text), valid: true, by: { kind: 'me' }, text: b.text, iat: now(), words: 'amber otter violin harbor' }),
      'POST /api/statement/check': (b) => (b.statement.includes(ST) ? { valid: true, text: b.statement.split('\n')[0], iat: now() - 60, did: bo.did, original: bo.did, chain: [bo.did], current: true, created: '2026-03-03T10:00:00Z',
        edited: false, words: 'copper lantern meadow seven', by: { kind: 'contact', did: bo.did, name: 'bo', words_checked: true } } : { valid: false, check: 'statement_sig', message: 'The text or its signature was changed after it was signed.' }),
      'GET /api/attestations': () => ({ created: '2026-03-03T10:00:00Z', attestations: [{ iss: 'did:sigelo:zWorld', ctx: '1f916.ai', iat: now() - 86400 * 40, exp: now() + 86400 * 50, admission: 'invite', claims: {} }], rejected: 0 }),
      'POST /api/invite/cancel': (b) => { if (sandbox.pending?.public?.id === b.id) sandbox.pending = { ...sandbox.pending, public: null }; return { cancelled: true }; },
    });
    const inviteWas = routes['POST /api/invite'];
    routes['POST /api/invite'] = (b) => {
      if (!b.public) return inviteWas(b);
      const pub = { id: 'pub1', name: 'public-1a2b', short: 'PUB-7Q4K-M2XD', words: 'amber otter violin harbor', link: 'https://sigelo.io/join#PUB-7Q4K-M2XD.amber-otter-violin-harbor', exp: now() + b.months * 30 * 86400, relay: 'relay.sigelo.ai',
        cap: b.cap, open: b.open, paused: false, today: 1, chats: 3, requests: [{ id: 'zReq1', did: 'did:sigelo:zJoiner', words: 'copper lantern meadow seven', received: now(), exp: now() + 86400 }] };
      sandbox.pending = { ...(sandbox.pending ?? {}), public: pub };
      return { ...pub, code: 'sgl2' + 'Q'.repeat(90), public: true };
    };
    routes['POST /api/public/approve'] = (b) => { sandbox.pending.public = { ...sandbox.pending.public, requests: [], chats: 4 }; return { approved: true, did: 'did:sigelo:zJoiner', name: 'public-1a2b-4', fingerprint: 'a b c d', id: b.id }; };
    routes['POST /api/public/set'] = (b) => { sandbox.pending.public = { ...sandbox.pending.public, paused: b.paused }; return sandbox.pending.public; };
    await sandbox.ui.go('chats'); await settle(); await poll();
    // Task 12 from Me (3 taps): Me, My code and QR, Make a code: the code with its QR, Share and Copy.
    let taps = 0;
    await tabBtn('me').click(); taps++; await settle(); await poll();
    ok(has('People and teams') && has('For your website or shop · off') && has('Sign or check a message') && has('Show since when this identity exists') && has('Devices and computers')
      && aria('Add your picture', 'BUTTON') && btn('My code and QR') && btn('Scan'), 'Me: who I am (the picture button, name, four words), My code and QR, Scan; People and teams, Public invite (off), Sign or check, Proof of age; Devices, Settings');
    await btn('My code and QR').click(); taps++; await settle(); await poll();
    await btn('Make a code').click(); taps++; await settle(); await poll();
    ok(taps === 3 && h1() === 'My code' && has('K7F3-Q9ZP') && btn('Share') && btn('Copy'), 'task 12 from Me, 3 taps: Me, My code and QR, Make a code: the code (and its QR), Share, Copy');
    // A code that renews itself (on by default for a person code): the note; once used, the next code in its place and who used the last; Cancel this code.
    ok(calls.some(([, p, b]) => p === '/api/invite' && b.renew === true), 'My code: "Renews itself" on by default → POST /api/invite {renew: true}');
    const rn = { name: 'contact-1a2b', exp: now() + 86400, relay: 'relay.sigelo.ai', id: 'i1', short: 'K7F3-Q9ZP', short_exp: now() + 600, code: null, group: null, renew: true, used: [], renew_error: null };
    sandbox.pending = { invites: [rn], paired: [] };
    await poll(); await settle();
    ok(h1() === 'My code' && has('K7F3-Q9ZP') && has('A new code appears when this one is used.'), 'a renewing code: "A new code appears when this one is used."');
    sandbox.pending = { invites: [{ ...rn, short: 'M4QX-8T2B', used: [{ short: 'K7F3-Q9ZP', name: 'fay', did: 'did:sigelo:zFay', at: now() }] }], paired: [] };
    await poll(); await settle();
    ok(h1() === 'My code' && has('M4QX-8T2B') && !has('K7F3-Q9ZP') && has('fay used your last code.'), 'used: the next code in its place, on the same screen, and who used the last one');
    await btn('Cancel this code').click(); await settle();
    ok(calls.some(([, p, b]) => p === '/api/invite/cancel' && b.id === 'i1'), 'Cancel this code → POST /api/invite/cancel {id}');
    sandbox.pending = undefined;
    await sandbox.ui.go('me'); await settle(); await poll();
    // The picture sheet (Decided 2026-11-11): yours, end to end, never to the relay in the clear; choose one; no camera here: not offered.
    await aria('Add your picture', 'BUTTON').click(); await settle();
    ok(sheet() && sh1() === 'Your picture' && has('never to the relay in the clear') && btn('Choose a picture') === undefined && root.all().some((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Choose a picture'))
      && !root.all().some((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Take a picture')) && root.all().some((e) => e.tagName === 'INPUT' && e.attrs.type === 'file' && e.attrs.accept === 'image/*'),
    'Me → the picture: a sheet (only people you chat with see it, end to end), Choose a picture (an image file: the gallery on a phone); no camera, no Take a picture');
    await aria('Close', 'BUTTON').click(); await settle();
    // People and teams: bo with his agent (introduced by him), the team, Add a person, New team.
    await root.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('People and teams')).click(); await settle(); await poll();
    const boRow = root.all().find((e) => e.attrs['data-person'] === bo.did);
    ok(h1() === 'People and teams' && boRow?.textContent.includes('1 agent · words ✓') && root.all().some((e) => e.attrs['data-team'] === TEAM && e.textContent.includes('2 people · 1 agent')) && btn('Add a person') && btn('New team')
      && !root.all().some((e) => e.attrs['data-person'] === G_.contacts.find((c) => c.name === 'booker').did),
    'People and teams: people with their agents (bo: 1 agent, words ✓; his agent not a person), the team (a group with agents), Add a person, New team');
    await boRow.click(); await settle(); await poll();
    ok(h1() === 'bo' && btn('Message') && has('Their agents') && has('booker') && has('paired with you · bookings') && has('research') && has('they offer it: research') && btn('Add') && has('Together in') && has('Studio')
      && aria('Picture for bo', 'BUTTON') && btn('Chat settings'), 'a person: the picture button (a local one), four words, their agents (paired: booker; offered: research, Add), Together in Studio, Chat settings');
    await btn('Chat settings').click(); await settle(); await poll();
    ok(h1() === 'Chat settings' && has('Their agents') && has('1 paired · 1 more offered') && aria('Picture for bo', 'BUTTON'), 'Chat settings: Their agents (1 paired · 1 more offered), the picture button');
    await aria('Picture for bo', 'BUTTON').click(); await settle();
    ok(sh1() === 'Picture for bo' && has('On this device only.'), 'a contact\'s picture: a local one, on this device only');
    await aria('Close', 'BUTTON').click(); await settle();
    await sandbox.ui.go('team', TEAM); await settle(); await poll();
    const at = root.all().filter((e) => e.tagName === 'BUTTON' && e.textContent === '@');
    ok(h1() === 'Studio' && has('A team is a group where each person brings their agents.') && has('You') && has('bo\'s agent') && at.length === 2 && btn('Open chat'), 'a team: You, then each person with the agents they brought (booker: bo\'s agent), @ to ask, Open chat');
    await at.at(-1).click(); await settle(); await poll();
    ok(root.all().find((e) => e.attrs['aria-label'] === 'Message · @ to mention' || (e.attrs['aria-label'] === 'Message' && e.tagName === 'TEXTAREA'))?.value === '@booker ', '@ on a team\'s page: its chat, the name typed');
    // Sign a message (S2): the text, Sign, Signed by you, Send in a chat (a contact picked) → POST /api/send {to, statement}.
    await sandbox.ui.go('sign'); await settle();
    kit(root).field('What you want to sign').value = 'I agree to share the flat costs, 4 ways.';
    await btn('Sign').click(); await settle(); await poll();
    ok(h1() === 'Signed' && has('✓ Signed by you') && has('I agree to share the flat costs, 4 ways.') && btn('Send in a chat') && btn('Copy signed text') && calls.some(([, p, b]) => p === '/api/statement/sign' && b.text === 'I agree to share the flat costs, 4 ways.'),
      'Sign → POST /api/statement/sign: Signed by you, the text, Send in a chat, Copy signed text');
    await btn('Send in a chat').click(); await settle();
    await sheet().all().find((e) => e.tagName === 'BUTTON' && e.className?.startsWith('row') && e.textContent.endsWith('bo')).click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/send' && b.to === bo.did && b.statement === stText('I agree to share the flat costs, 4 ways.')), 'Send in a chat → POST /api/send {to, statement}');
    // Task 11 with a statement (2 taps): the chat, "Signed by bo · check" → Signed message: who, compared, when, the text.
    MSGS[bo.did] = [{ n: 7, dir: 'in', at: now() - 120, iat: now() - 120, text: stText('Booking: Casa do Rio, Friday 20:00.'), label: 'sigelo-statement/0', status: null, code: null, detail: null, link: null,
      statement: { valid: true, by: { kind: 'contact', did: bo.did, name: 'bo', words_checked: true }, words: 'copper lantern meadow seven', text: 'Booking: Casa do Rio, Friday 20:00.', iat: now() - 120 } }];
    await sandbox.ui.go('chats'); await settle(); await poll();
    taps = 0;
    await root.all().find((e) => e.attrs['data-chat'] === bo.did).click(); taps++; await settle(); await poll();
    const sig = root.all().find((e) => e.tagName === 'BUTTON' && e.className === 'sig');
    ok(sig?.textContent === 'Signed by bo · check' && root.all().find((e) => e.attrs['data-statement'] === '7')?.textContent.includes('Booking: Casa do Rio, Friday 20:00.') && !has('sigelo-statement/0 eyJ'),
      'a signed message in the chat: the text as signed (not the signature line), "Signed by bo · check"');
    await sig.click(); taps++; await settle(); await poll();
    ok(taps === 2 && h1() === 'Signed message' && has('✓ Signed by bo') && has('Their four words match the ones you compared.') && has('Identity since') && has('not proven') && btn('Check another message'),
      'task 11, 2 taps (a statement): the chat, Signed by bo · check: Signed message, by bo, the words compared, when, the identity\'s date (not proven)');
    // Check a message: pasted; a tampered one refused.
    await btn('Check another message').click(); await settle();
    kit(root).field('Paste a signed message').value = 'changed\nsigelo-statement/0 eyJiIjoyfQ';
    await btn('Check').click(); await settle(); await poll();
    ok(h1() === 'Signed message' && has('✗ Not a valid signature') && has('changed after it was signed') && has('Do not trust what it says.'), 'Check: a tampered one → Not a valid signature, why, do not trust it');
    // Public invite (mock: off, new, on): off says Pro → Make → Valid for, I approve each, per day → Make it → the PUB code, its words,
    // Share, Copy, Waiting for your OK (Approve), the counts, Pause, Stop for good (confirmed) → cancel.
    await sandbox.ui.go('invite'); await settle(); await poll();
    ok(h1() === 'Public invite' && has('One code for everyone') && has('It lasts for months') && has('comes with Pro') && btn('Make a public invite'), 'Public invite, off: one code for everyone, for months, with Pro; Make a public invite');
    await btn('Make a public invite').click(); await settle(); await poll();
    ok(kit(root).field('Valid for')?.value === '6' && kit(root).field('New chats per day at most')?.value === '50' && has('I approve each new chat') && has('Who answers') && btn('Make it'),
      'Make a public invite: Valid for (6 months), I approve each new chat, at most 50 a day, who answers, Make it');
    await btn('Make it').click(); await settle(); await poll(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/invite' && b.public === true && b.months === 6 && b.cap === 50 && b.open === false) && h1() === 'Public invite' && root.all().some((e) => e.attrs['data-public'] !== undefined)
      && has('PUB-7Q4K-M2XD') && has('Answered by you · until') && btn('Share') && btn('Copy') && has('Waiting for your OK (1)') && has('1 of at most 50') && btn('Pause') && btn('Stop for good'),
      'Make it → POST /api/invite {public, months, cap, open}: the PUB code, its words, Share, Copy, one waiting, the day\'s count, Pause, Stop for good');
    await btn('Approve').click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/public/approve' && b.id === 'zReq1') && has('No new chat is waiting'), 'Approve → POST /api/public/approve {id}; none waiting');
    await btn('Pause').click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/public/set' && b.paused === true) && btn('Resume'), 'Pause → POST /api/public/set {paused: true}; Resume offered');
    void btn('Stop for good').click(); await settle();
    ok(sh1() === 'Stop this public invite?' && has('The code stops working everywhere it is posted. Chats already started stay.') && btn('Keep it'), 'Stop for good: a sheet naming it, what it does, Keep it');
    await btn('Stop it').click(); await settle(); await poll();
    ok(calls.some(([, p, b]) => p === '/api/invite/cancel' && b.id === 'pub1') && has('One code for everyone'), 'Stop it → POST /api/invite/cancel; off again');
    // Proof of age: what shows its age today (GET /api/attestations), the Monero record said to be not in this version.
    await sandbox.ui.go('age'); await settle(); await poll();
    ok(h1() === 'Proof of age' && has('1f916.ai') && has('vouched for it on') && has('invited by a member') && has('its own date, not proven') && has('not in this version') && !btn('Record it'),
      'Proof of age: the genesis date (its own word), each service that vouches for it with the day; the Monero record: not in this version (no Record it)');
    // Settings → Backup and recovery: the recovery fact; About: licence and links.
    await sandbox.ui.go('set-backup'); await settle(); await poll();
    ok(has('What they restore') && has('Your 25 words restore the vault and every keeper wallet; keeper settings are re-entered.'), 'Backup and recovery: the recovery fact');
    await sandbox.ui.go('about'); await settle(); await poll();
    ok(has('Licence') && has('MIT') && root.all().some((e) => e.tagName === 'A' && e.attrs.href === 'https://github.com/csigelo/sigelo') && has(`Version ${PKG_VERSION} · experimental`), `About: the version from apps/agent/package.json (${PKG_VERSION}, read beside ui.js), licence, links (sigelo.io, the source)`);
    sandbox.intro = []; MSGS[bo.did] = []; sandbox.pending = { ...sandbox.pending, invites: [] };
  }

  // ---- every screen drawn once, by name, with no error (the test hook)
  {
    const args = { signed: { did: G_.contacts[0].did, n: 1 }, chat: G_.contacts[1].did, person: G_.contacts[0].did, team: 'a'.repeat(32), statement: { text: 'x\nsigelo-statement/0 eyJhIjoxfQ' }, 'signed-mine': { statement: 'x' }, 'chat-info': G_.contacts[1].did, compare: G_.contacts[1].did, agent: 0, group: 'a'.repeat(32), 'group-info': 'a'.repeat(32), introduce: G_.mine[0].did,
      pay: G_.contacts[0].did, tx: 'a1'.repeat(32), 'send-review': { id: 'r9', exp: now() + 600, to: '5' + 'C'.repeat(94), amount: '1', fee: '1', note: '' }, 'send-done': { amount: '1' }, 'agent-allowance': 0 };
    const drawn = [];
    for (const s of sandbox.ui.screens) {
      let e = null;
      try { await sandbox.ui.go(s, args[s]); await settle(); await poll(); } catch (x) { e = x; }
      if (!e && root.all().some((x) => x.className === 'screen' || x.className === 'screen tabbed') && h1()) drawn.push(s);
    }
    ok(drawn.length === sandbox.ui.screens.length && sandbox.ui.screens.length >= 35, `every screen drawn once with a heading, no exception (${drawn.length} of ${sandbox.ui.screens.length}: ${sandbox.ui.screens.filter((s) => !drawn.includes(s))})`);
  }


  // ---- Pass 6: Back everywhere (the Owner: "Make sure the return/go back button works everywhere"). A page over a history as
  // a WebView keeps it (pushState, replaceState, back, go, popstate); the system Back as the Android app does it (MainActivity
  // onBackPressed: the page's history back while it can go back, else the app leaves). Every screen: opened from another
  // (Settings), the system Back, then its own top-bar Back or Close; every sheet over a screen: the system Back, then its Close.
  // Nothing leaves the app but Back on the first screen.
  {
    const rootB = new El('main'), ivB = [], lis = new Map();
    const H = { e: [{ state: null }], i: 0, left: 0,
      get state() { return this.e[this.i].state; }, get length() { return this.e.length; },
      pushState(st) { this.e.splice(this.i + 1); this.e.push({ state: JSON.parse(JSON.stringify(st)) }); this.i++; },
      replaceState(st) { this.e[this.i] = { state: JSON.parse(JSON.stringify(st)) }; },
      go(n) { const j = Math.max(0, Math.min(this.e.length - 1, this.i + n)); if (j === this.i) return; this.i = j; setTimeout(() => (lis.get('popstate') ?? []).forEach((f) => f({ state: this.state })), 0); },
      back() { this.go(-1); } };
    const sysBack = async () => { if (H.i > 0) H.back(); else H.left++; await settle(); await sleep(20); };
    const sbB = { ...sandbox, document: docOf(rootB), history: H, setInterval: (f, ms) => { ivB.push([f, ms]); return ivB.length; },
      addEventListener: (t, f) => { (lis.get(t) ?? lis.set(t, []).get(t)).push(f); }, sigeloUiTest: (t) => { sbB.ui = t; },
      localStorage: { m: new Map(), getItem(k) { return this.m.get(k) ?? null; }, setItem(k, v) { this.m.set(k, String(v)); }, removeItem(k) { this.m.delete(k); } } };
    sbB.globalThis = sbB;
    vm.runInNewContext(readFileSync(join(HERE, 'vendor', 'ui.js'), 'utf8'), sbB);
    const KB = kit(rootB), pollB = async () => { await ivB.find(([, ms]) => ms === 2000)[0](); await settle(); };
    const view = () => rootB.all().find((e) => e.attrs['data-screen'])?.attrs['data-screen'];
    const topBtn = () => rootB.all().find((e) => e.tagName === 'HEADER' && e.className === 'top')?.kids.find((k) => k.tagName === 'BUTTON' && ['Back', 'Close'].includes(k.attrs['aria-label']));
    await settle(); await pollB();
    const args = { signed: { did: G_.contacts[0].did, n: 1 }, chat: G_.contacts[1].did, person: G_.contacts[0].did, team: 'a'.repeat(32), statement: { text: 'x\nsigelo-statement/0 eyJhIjoxfQ' }, 'signed-mine': { statement: 'x' },
      'chat-info': G_.contacts[1].did, compare: G_.contacts[1].did, agent: 0, group: 'a'.repeat(32), 'group-info': 'a'.repeat(32), introduce: G_.mine[0].did, paired: G_.contacts[1].did, enrolled: { worker: 0, name: 'phone' },
      pay: G_.contacts[0].did, tx: 'a1'.repeat(32), 'send-review': { id: 'r9', exp: now() + 600, to: '5' + 'C'.repeat(94), amount: '1', fee: '1', note: '' }, 'send-done': { amount: '1' }, 'agent-allowance': 0 };
    // A Close with a fixed way out (the mock's): paired → Chats, enrolled → Agents, sent → Wallet. Every other: the screen before.
    const closesTo = { paired: 'chats', enrolled: 'agents', 'send-done': 'wallet' };
    const bad = [], roots = new Set(['chats', 'agents', 'wallet', 'me']);
    let visited = 0;
    for (const s of sbB.ui.screens) {
      for (const how of ['system', 'button']) {
        sbB.ui.home('chats'); await settle(); await sleep(20); await pollB();
        if (view() !== 'chats' || H.i !== 0) { bad.push(`${s}: not back at Chats first (${view()}, ${H.i})`); continue; }
        await sbB.ui.go('settings'); await settle(); await pollB();
        await sbB.ui.go(s, args[s]); await settle(); await pollB();
        const at = view(), depth = H.i;
        if (at !== s && !(s === 'compare' && at === 'paired')) { bad.push(`${s}: opened as ${at}`); continue; }
        if (how === 'button' && roots.has(s)) { visited++; continue; }   // a tab root has the tabs, not a Back
        if (how === 'system') await sysBack();
        else { const b = topBtn(); if (!b) { bad.push(`${s}: no Back or Close in its top bar`); continue; } await b.click(); await settle(); await sleep(20); }
        await pollB();
        const want = how === 'button' && closesTo[at] ? closesTo[at] : 'settings';
        if (view() !== want || H.left) bad.push(`${s} (${how} Back from depth ${depth}): ${view()}, not ${want}${H.left ? ', left the app' : ''}`);
        visited++;
      }
    }
    // The sheets, over Settings: the system Back closes them (one entry), as their Close does; the screen stays.
    const sheetsOf = { 'new-chat': [], profiles: [], 'profile-add': [], attach: [G_.contacts[1].did], 'pay-off': [G_.contacts[1].did], picture: ['me', 'You'], rename: ['Rename bo', 'bo', async () => {}], confirm: [{ title: 'Sure?', yes: 'Yes' }] };
    for (const [name, a] of Object.entries(sheetsOf)) {
      for (const how of ['system', 'close']) {
        sbB.ui.home('chats'); await settle(); await sleep(20);
        await sbB.ui.go('settings'); await settle(); await pollB();
        const depth = H.i;
        void sbB.ui.sheets[name](...a); await settle(); await sleep(20);
        const open = KB.sheet();
        if (!open) { bad.push(`sheet ${name}: did not open`); continue; }
        if (how === 'system') await sysBack();
        else { const c = open.all().find((e) => e.tagName === 'BUTTON' && e.attrs['aria-label'] === 'Close' && e.className !== 'scrim'); if (!c) { bad.push(`sheet ${name}: no Close`); continue; } await c.click(); await settle(); await sleep(20); }
        if (KB.sheet() || view() !== 'settings' || H.i !== depth || H.left) bad.push(`sheet ${name} (${how}): ${KB.sheet() ? 'still open' : view()} at ${H.i}, not settings at ${depth}`);
        visited++;
      }
    }
    // The tab roots sit on Chats: Back from Agents, Wallet or Me is Chats; from Chats, the first screen, Back leaves the app.
    sbB.ui.home('chats'); await settle(); await sleep(20);
    await sbB.ui.go('me'); await settle(); await pollB();
    await sysBack(); await pollB();
    const fromTab = view();
    await sysBack();
    ok(bad.length === 0 && visited >= 2 * sbB.ui.screens.length + 16 && fromTab === 'chats' && H.left === 1 && view() === 'chats',
      `Back everywhere: ${sbB.ui.screens.length} screens (the system Back and their own Back or Close) and ${Object.keys(sheetsOf).length} sheets, each back to the screen before it (the mock's Close: paired → Chats, enrolled → Agents, sent → Wallet); a tab root back to Chats; only Chats, the first screen, leaves the app (${bad.slice(0, 6).join('; ')})`);
    void roots;
  }

  // ---- Pass 6: the lock (Settings → Lock) and the pay limit, the notifications (the sender's name only), over fake shells.
  {
    const mk = (local, o = {}) => {
      const r = new El('main'), iv = [], sb = { ...sandbox, document: docOf(r), setInterval: (f, ms) => { iv.push([f, ms]); return iv.length; }, history: { replaceState() {} }, sigeloUiTest: (t) => { sb.ui = t; },
        localStorage: { m: new Map(o.prefs ?? []), getItem(k) { return this.m.get(k) ?? null; }, setItem(k, v) { this.m.set(k, String(v)); }, removeItem(k) { this.m.delete(k); } },
        sigeloLocal: { ...sandbox.sigeloLocal, ...local }, ...(o.extra ?? {}) };
      sb.globalThis = sb;
      vm.runInNewContext(readFileSync(join(HERE, 'vendor', 'ui.js'), 'utf8'), sb);
      return { r, sb, K: kit(r), poll: async () => { await iv.find(([, ms]) => ms === 2000)[0](); await settle(); } };
    };
    const SENDS = [];
    routes['POST /api/wallet/send'] = (b) => { SENDS.push(b); return { txid: 'f'.repeat(64), amount: '200000000000', fee: '1' }; };
    const review = (amount) => ({ id: `r${amount}`, exp: now() + 600, to: '5' + 'C'.repeat(94), amount, fee: '30000000', note: '' });
    // The Android app: the phone's screen lock (sigeloLocal.lock), asked again (force) above the limit.
    const LK = { st: { on: true, after: 1, secure: true }, sets: [], unlocks: [], refuse: false };
    const A6 = mk({ lock: { kind: 'screen', get: async () => ({ ...LK.st }), set: async (o) => { LK.sets.push(o); Object.assign(LK.st, o); return { ...LK.st }; } },
      async unlock(o) { LK.unlocks.push(o ?? null); if (LK.refuse) throw Object.assign(new Error('the screen lock was not confirmed'), { check: 'cancelled' }); } });
    await settle(); await A6.poll();
    await A6.sb.ui.go('settings'); await settle(); await A6.poll();
    ok(A6.K.has('Fingerprint or PIN · after 1 minute'), 'Settings: Lock says Fingerprint or PIN · after 1 minute (the shell\'s setting)');
    await A6.sb.ui.go('set-lock'); await settle(); await A6.poll();
    const sw = A6.K.aria('Use fingerprint or PIN', 'INPUT'), after = A6.K.aria('Lock after', 'SELECT'), payIn = A6.K.aria('Ask again to pay above', 'SELECT');
    ok(A6.K.h1() === 'Lock' && sw?.checked === true && after?.value === '1' && payIn?.value === '100000000000' && payIn.kids.map((x) => x.textContent).join('|') === 'Every payment|0.01 XMR|0.05 XMR|0.10 XMR|0.25 XMR|0.50 XMR|1.00 XMR'
      && A6.K.has('Asked only when you open the app, switch profile, pay above this limit, or show your 25 words (which also asks your words password).'),
      'Settings → Lock (the mock\'s): Use fingerprint or PIN (on), Lock after (1 minute), Ask again to pay above (0.10 XMR by default), the lock rule');
    after.value = '5'; fire(after, 'change'); await settle();
    payIn.value = '50000000000'; fire(payIn, 'change'); await settle();
    sw.checked = false; fire(sw, 'change'); await settle(); await A6.poll();
    ok(JSON.stringify(LK.sets) === '[{"after":5},{"on":false}]' && A6.sb.localStorage.getItem('sigelo-ui:pay-lock') === '50000000000' && !A6.K.aria('Lock after', 'SELECT'),
      `Lock after → lock.set({after: 5}); the switch off → lock.set({on: false}) (Lock after hidden); the pay limit kept on this device (${JSON.stringify(LK.sets)})`);
    await A6.sb.ui.go('send-review', review('20000000000')); await settle(); await A6.poll();
    const u0 = LK.unlocks.length;
    ok(A6.K.has('Under your 0.05 XMR limit, so no lock.'), 'Check and send under the limit: "Under your 0.05 XMR limit, so no lock."');
    await A6.K.btn('Send 0.02 XMR').click(); await settle();
    ok(LK.unlocks.length === u0 && SENDS.length === 1, 'Send under the limit: no lock asked, sent');
    await A6.sb.ui.go('send-review', review('200000000000')); await settle(); await A6.poll();
    ok(A6.K.has('Above your 0.05 XMR limit: Send asks your lock.'), 'Check and send above the limit: said before Send');
    LK.refuse = true;
    await A6.K.btn('Send 0.20 XMR').click(); await settle();
    ok(LK.unlocks.length === u0 + 1 && LK.unlocks.at(-1)?.force === true && SENDS.length === 1 && A6.K.has('the screen lock was not confirmed'), 'Send above the limit: the screen lock asked again (force); not confirmed → nothing sent, said');
    LK.refuse = false;
    await A6.K.btn('Send 0.20 XMR').click(); await settle();
    ok(LK.unlocks.length === u0 + 2 && SENDS.length === 2 && SENDS[1].id === 'r200000000000', 'Send above the limit, the lock confirmed → sent');

    // A browser tab or the GTK app: no screen lock; the words password stands in where one is kept (the page locks itself).
    const WPW = { pw: 'correct horse', checks: [] };
    const words = { status: async () => ({ here: true, kept: true, iterations: 1 }), check: async (p) => { WPW.checks.push(p); if (p !== WPW.pw) throw Object.assign(new Error('Wrong password.'), { check: 'words_password' }); return true; },
      reveal: async () => ({ words: [] }), auth: async (_i, p) => ({ password: p }) };
    const B6 = mk({ words, lock: undefined }, { prefs: [['sigelo-ui:page-lock', 'on']] });
    await settle(); await B6.poll();
    const pwL = B6.K.field('Words password');
    ok(B6.K.h1() === 'sigelo is locked' && pwL && B6.K.btn('Unlock') && !B6.K.has('No chats yet'), 'the words password standing in: the page opens locked ("sigelo is locked", the profile, Words password, Unlock), nothing of the app shown');
    pwL.value = 'nope'; await B6.K.btn('Unlock').click(); await settle();
    const stays = B6.K.h1() === 'sigelo is locked' && B6.K.has('Wrong password.');
    B6.K.field('Words password').value = 'correct horse'; await B6.K.btn('Unlock').click(); await settle(); await B6.poll();
    ok(stays && B6.K.h1() === 'Chats' && WPW.checks.join() === 'nope,correct horse', 'locked: a wrong password said, it stays locked; the right one → Chats (words.check, no screen lock)');
    await B6.sb.ui.go('set-lock'); await settle(); await B6.poll();
    ok(B6.K.aria('Lock with your words password', 'INPUT')?.checked === true && B6.K.has('No screen lock here: your words password stands in.') && B6.K.aria('Ask again to pay above', 'SELECT'),
      'Settings → Lock without a screen lock: the words password stands in, and the screen says so');
    await B6.sb.ui.go('send-review', review('200000000000')); await settle(); await B6.poll();
    void B6.K.btn('Send 0.20 XMR').click(); await settle();
    const n0 = SENDS.length, askSheet = B6.K.sheet() && B6.K.sh1() === 'Send 0.20 XMR' && B6.K.has('This device has no screen lock: your words password stands in.');
    const pwS = B6.K.sheet()?.all().find((e) => e.tagName === 'INPUT' && e.attrs.type === 'password') ?? {};
    pwS.value = 'correct horse';
    await B6.K.sheet().all().find((e) => e.tagName === 'BUTTON' && e.textContent === 'Unlock').click(); await settle(); await sleep(30);
    ok(askSheet && SENDS.length === n0 + 1, 'Send above the limit, no screen lock: the words password asked in a sheet that says why; right → sent');

    // Nothing to lock with (a tab, no words kept): said, with the way to set one.
    const C6 = mk({ words: { ...words, status: async () => ({ here: true, kept: false }), set: async () => ({}) }, lock: undefined });
    await settle(); await C6.poll();
    await C6.sb.ui.go('set-lock'); await settle(); await C6.poll();
    await C6.sb.ui.go('send-review', review('200000000000')); await settle(); await C6.poll();
    const noLine = !C6.K.has('limit');
    await C6.sb.ui.back(); await settle(); await C6.poll();
    ok(C6.K.has('No screen lock here, and no words password kept on this device.') && C6.K.btn('Backup and recovery') && noLine, 'no screen lock, no words password: Settings → Lock says so and offers Backup and recovery; Send says no limit');

    // Notifications (Decided: the sender's name only, never the text), through the Android bridge (sigeloLocal.notify, onOpen).
    const NOTES = [], OPEN = [];
    const N6 = mk({ notify: async (o) => { NOTES.push(o); return {}; }, onOpen: (f) => OPEN.push(f) });
    await settle(); await N6.poll(); await N6.poll();
    const base = NOTES.filter((x) => !x.ask && !x.cancel).length;
    const bo = G_.contacts[0], cy = G_.contacts[1];
    bo.last = { dir: 'in', text: 'the secret plan', at: now() + 5 }; bo.unread = 3;
    await N6.poll();
    const n1 = NOTES.filter((x) => !x.ask && !x.cancel);
    ok(base === 0 && n1.length === 1 && n1[0].tag === `chat:${bo.did}` && n1[0].title === bo.name && n1[0].text === 'New message' && !JSON.stringify(NOTES).includes('secret') && NOTES.some((x) => x.ask === true),
      `a new message: one notification, the sender's name and "New message", never the text; what was there at the start raises none; the permission asked once (${JSON.stringify(n1)})`);
    cy.notify = false; cy.last = { dir: 'in', text: 'muted words', at: now() + 6 };
    const q = G_.mine[0], qWas = q.tier; q.tier = 'quiet'; q.last = { dir: 'in', text: 'quiet words', at: now() + 6 };
    await N6.poll();
    ok(NOTES.filter((x) => !x.ask && !x.cancel).length === 1, 'none for a chat whose Notifications are off, none for a Quiet contact');
    cy.notify = true; q.tier = qWas;
    SET.notify = false;
    await N6.sb.ui.go('set-chats'); await settle(); await N6.poll();
    const gsw = N6.K.aria('Notifications', 'INPUT'); gsw.checked = false; fire(gsw, 'change'); await settle();
    bo.last = { dir: 'in', text: 'more', at: now() + 7 };
    await N6.poll();
    const offOk = NOTES.filter((x) => !x.ask && !x.cancel).length === 1;
    SET.notify = true; gsw.checked = true; fire(gsw, 'change'); await settle();
    // On the screen and seen: that chat raises none; opening it removes its notification.
    await N6.sb.ui.go('chat', bo.did); await settle(); await N6.poll();
    const cancelled = NOTES.some((x) => x.tag === `chat:${bo.did}` && x.cancel === true);
    bo.last = { dir: 'in', text: 'seen now', at: now() + 8 };
    await N6.poll();
    ok(offOk && cancelled && NOTES.filter((x) => !x.ask && !x.cancel).length === 1, 'none with Settings → Chats and history → Notifications off; none for the chat on the screen; opening a chat removes its notification');
    // A tap: its chat opens; a tag that is not ours is ignored.
    N6.sb.ui.home('chats'); await settle();
    OPEN.forEach((f) => f(`chat:${cy.did}`)); await settle(); await sleep(30); await N6.poll();
    const openedChat = N6.r.all().find((e) => e.attrs['data-screen'])?.attrs['data-screen'] === 'chat' && N6.r.all().some((e) => e.className === 'who' && e.textContent.includes(cy.name));
    OPEN.forEach((f) => f('javascript:alert(1)')); await settle();
    ok(OPEN.length === 1 && openedChat && N6.r.all().find((e) => e.attrs['data-screen'])?.attrs['data-screen'] === 'chat', 'a notification tapped (onOpen): its chat opens; anything not a chat, group or pay tag is ignored');
    // A group: its name, and who wrote (a name), never the text.
    GR.groups.push({ gid: 'b'.repeat(32), name: 'Porto', status: 'member', ver: 1, brake: 20, creator: ME, creator_name: null, mine: true, foreign: false, run: 0, unread: 1, quiet: false,
      last: { mine: false, name: 'Tomás', text: 'table for 5', at: now() + 9 }, members: [{ did: ME, name: 'me', role: 'human', me: true, contact: false }] });
    bump();
    N6.sb.ui.home('chats'); await settle(); await N6.poll();
    const gn = NOTES.filter((x) => !x.ask && !x.cancel).at(-1);
    ok(gn?.tag === `group:${'b'.repeat(32)}` && gn.title === 'Porto' && gn.text === 'New message from Tomás' && !JSON.stringify(gn).includes('table'), `a group message: the group's name and who wrote, never the text (${JSON.stringify(gn)})`);
    GR.groups.pop(); bump();

    // The GTK app's path: its bridge's notify op, a tap through globalThis.sigeloOpen.
    const POSTED = [];
    const G6 = mk({ notify: undefined, onOpen: undefined }, { extra: { webkit: { messageHandlers: { sigelo: { postMessage: async (m) => { POSTED.push(m); return { ok: true }; } } } } } });
    await settle(); await G6.poll(); await G6.poll();
    cy.last = { dir: 'in', text: 'gtk secret', at: now() + 10 };
    await G6.poll();
    const gp = POSTED.filter((m) => m.op === 'notify');
    G6.sb.sigeloOpen?.(`chat:${bo.did}`); await settle(); await sleep(30); await G6.poll();
    ok(gp.length === 1 && gp[0].tag === `chat:${cy.did}` && gp[0].title === cy.name && gp[0].text === 'New message' && !JSON.stringify(gp).includes('secret') && typeof G6.sb.sigeloOpen === 'function'
      && G6.r.all().some((e) => e.className === 'who' && e.textContent.includes(bo.name)), `the GTK app: the bridge's notify op (name only), a tap through sigeloOpen opens the chat (${JSON.stringify(gp)})`);
    delete routes['POST /api/wallet/send'];
  }

  // ---- the profiles sheet (design/profiles.md §3) over a fake local.profiles: the list, the one in use marked; switch, add; Manage: rename, remove
  {
    SET.wallet = false;
    const root2 = new El('main'), iv2 = [], pc = [];
    const P = { active: 'p1', limit: 8, profiles: [{ id: 'p1', name: 'Profile 1', kind: 'words', did: 'did:sigelo:zA', words: 'apple brave cider delta', created: 1 },
      { id: 'p2', name: 'Work', kind: 'remote', did: 'did:sigelo:zB', words: 'eagle fancy giant hover', created: 2 }, { id: 'p3', name: 'Profile 3', kind: null, did: null, words: null, created: 3 }] };
    const fail = (check, message) => { throw Object.assign(new Error(message), { check }); };
    const profiles = {
      list: async () => { pc.push(['list']); return JSON.parse(JSON.stringify(P)); },
      use: async (id) => { pc.push(['use', id]); return { active: id, reload: true }; },
      rename: async (id, name) => { pc.push(['rename', id, name]); if (!name.trim()) fail('profile_name', 'a name of 1 to 24 characters'); P.profiles.find((p) => p.id === id).name = name.trim(); return P; },
      add: async (path) => { pc.push(['add', path]); return { active: 'p4', reload: true }; },
      remove: async (id, o) => { pc.push(['remove', id, o]); const p = P.profiles.find((x) => x.id === id); if (p.kind === 'words' && !o.words) fail('profile_words', 'Tick "I have the 25 words": only they bring this identity back.');
        if (p.kind && o.name !== p.name) fail('profile_name', `Type the profile's name, ${p.name}, to remove it.`); P.profiles = P.profiles.filter((x) => x !== p); return P; },
    };
    const sb = { ...sandbox, document: docOf(root2), setInterval: (f, ms) => { iv2.push([f, ms]); return iv2.length; }, history: { replaceState() {}, pushState() {}, back() {} }, sigeloUiTest: undefined,
      sigeloLocal: { ...sandbox.sigeloLocal, profiles, async call(method, path) { const f = { 'GET /api/state': snap, 'GET /api/agents/workers': () => ({ keeper: true, seat: 'here', workers: [] }), 'GET /api/me': () => ({ did: 'did:sigelo:zA', original: 'did:sigelo:zA', words: 'apple brave cider delta', recovery: 'set', key: 'browser', relay: 'relay.sigelo.ai', retention_days: 7, erase: '' }),
        'GET /api/groups': () => ({ tier: GR.tier, groups: [], notices: [] }) }[`${method} ${path.split('?')[0]}`]; return f ? { status: 200, body: f() } : { status: 404, body: { error: { check: 'route', message: 'no' } } }; } } };
    sb.globalThis = sb;
    vm.runInNewContext(readFileSync(join(HERE, 'vendor', 'ui.js'), 'utf8'), sb);
    const K = kit(root2), poll2 = async () => { await iv2.find(([, ms]) => ms === 2000)[0](); await settle(); };
    await settle(); await poll2();
    const chip = root2.all().find((e) => e.className === 'pchip');
    ok(chip?.textContent.includes('Profile 1') && chip.textContent.includes('apple · brave · cider · delta'), 'the chip: the profile in use, its name and four words');
    await chip.click(); await settle();
    const cards = () => root2.all().filter((e) => e.attrs['data-profile']);
    ok(K.sheet() && K.sh1() === 'Profiles' && cards().length === 3 && cards()[0].textContent.includes('apple · brave · cider · delta') && cards()[0].textContent.includes('Wallet off') && cards()[0].all().some((e) => e.attrs['aria-label'] === 'In use')
      && cards()[1].textContent.includes('A computer\'s page') && cards()[2].textContent.includes('Not set up yet') && !cards()[1].all().some((e) => e.attrs['aria-label'] === 'In use') && K.btn('Add') && !K.btn('Add').disabled && K.btn('Manage'),
      'Profiles sheet: a row per profile (name, four words, Wallet off, or what it holds), the one in use marked; Add, Manage');
    await cards()[1].click(); await settle();
    ok(pc.some(([o, id]) => o === 'use' && id === 'p2'), 'task 6, 2 taps (then the lock): the chip, another profile → profiles.use (the shell asks the lock and reloads)');
    // Add (the mock's profile-add): a sheet of the four ways; each opens the new profile's first run at that step.
    await chip.click(); await settle();
    await K.btn('Add').click(); await settle();
    const ways = root2.all().filter((e) => e.attrs['data-add']).map((e) => `${e.attrs['data-add']}:${e.textContent}`);
    ok(K.sh1() === 'Add a profile' && K.has('A second identity, for a shop or a project. Up to 8.') && ways.join('|') === 'create:Create a new identity|join:Join from an invite code|restore:Restore from 25 words|computer:Use a computer\'s identity',
      `Add a profile: a sheet of four ways: create, join from an invite code, restore from 25 words, use a computer's identity (${ways})`);
    await root2.all().find((e) => e.attrs['data-add'] === 'join').click(); await settle();
    ok(pc.some(([o, path]) => o === 'add' && path === 'join'), 'Join from an invite code → profiles.add("join") (its first run asks the code, then pairs once the identity is made)');
    await K.aria('Close', 'BUTTON')?.click(); await settle();
    await chip.click(); await settle();
    await K.btn('Manage').click(); await settle(); await poll2();
    const nameIn = K.field('Work');
    ok(K.h1() === 'Manage profiles' && !K.sheet() && nameIn?.value === 'Work' && K.btn('Remove Profile 1…') && K.btn('Remove Work…'), 'Manage profiles: a name field each; Remove … each');
    nameIn.focus(); nameIn.value = 'Office';
    await poll2();
    ok(focus.el === nameIn && root2.contains(nameIn) && nameIn.value === 'Office', 'Manage profiles: the name being typed keeps its field and the focus across the poll');
    fire(nameIn, 'change'); await settle();
    ok(pc.some(([o, id, n]) => o === 'rename' && id === 'p2' && n === 'Office') && P.profiles[1].name === 'Office', 'Manage profiles: a name changed → profiles.rename');
    await K.btn('Remove Profile 1…').click(); await settle();
    ok(K.sheet() && K.sh1() === 'Remove Profile 1?' && K.has('Its identity, chats and wallet leave this phone. Only its 25 words bring it back.') && K.has('I have the 25 words') && K.btn('Keep Profile 1'),
      'Remove (words): a sheet naming it, the warning, "I have the 25 words", Keep');
    await K.btn('Remove Profile 1').click(); await settle();
    ok(K.has('Tick "I have the 25 words"') && P.profiles.some((p) => p.id === 'p1') && K.sheet(), 'Remove (words): not ticked → refused, said in the sheet, kept');
    K.aria('I have the 25 words', 'INPUT').checked = true;
    await K.btn('Remove Profile 1').click(); await settle(); await poll2();
    ok(pc.some(([o, id, x]) => o === 'remove' && id === 'p1' && x.words === true && x.name === 'Profile 1') && !P.profiles.some((p) => p.id === 'p1') && !K.sheet() && K.h1() === 'Manage profiles',
      'Remove (words): ticked → profiles.remove {name, words}; back on Manage profiles');
    await K.btn('Remove Office…').click(); await settle();
    ok(K.has('The computers keep the pairing until you revoke it there') && !K.has('I have the 25 words'), 'Remove (remote): the computers keep the pairing until revoked there; no words to tick');
    await K.aria('Close', 'BUTTON').click(); await settle();
    P.profiles.push(...[4, 5, 6, 7, 8, 9].map((n) => ({ id: `p${n}`, name: `Profile ${n}`, kind: null, did: null, words: null, created: n })));
    await K.aria('Back', 'BUTTON').click(); await settle(); await poll2();
    await root2.all().find((e) => e.className === 'pchip').click(); await settle();
    ok(K.btn('Add') && !K.btn('Add').disabled && K.has('At most 8 profiles'), 'Profiles: at 8, the limit said (Add stays a button: it says the refusal)');
  }
  // ---- Settings → Backup and recovery (design/apps-seed.md §8) over a fake local.words: the lock, the password, the words as at their
  // creation (FLAG_SECURE, nothing to copy, Done hides them), change, stop keeping them; removing a profile and taking the seat guarded.
  {
    const root3 = new El('main'), iv3 = [], wc = [], secure = [], posted = [];
    const PW = { kept: true, pw: 'correct horse', fails: 0 };
    const twenty5 = Array.from({ length: 25 }, (_, i) => `w${String.fromCharCode(97 + (i % 26))}ord`);
    const wrong = () => { PW.fails++; throw Object.assign(new Error('Wrong password.'), { check: 'words_password' }); };
    const words = {
      status: async (id) => { wc.push(['status', id]); return id === undefined ? { here: true, kept: PW.kept, iterations: 1000000 } : { here: false, kept: id === 'p1' && PW.kept }; },
      reveal: async (p) => { wc.push(['reveal', p]); await sb3.sigeloLocal.unlock(); if (p !== PW.pw) wrong(); return { words: twenty5 }; },
      change: async (o, n, r) => { wc.push(['change', o, n, r]); if (o !== PW.pw) wrong(); if (n !== r) throw Object.assign(new Error('The two passwords are not the same.'), { check: 'words_password_rule' }); PW.pw = n; return { kept: true }; },
      remove: async (p) => { wc.push(['remove', p]); if (p !== PW.pw) wrong(); PW.kept = false; return { kept: false }; },
      auth: async (id, p) => ({ password: p }),
    };
    const P3 = { active: 'p1', limit: 8, profiles: [{ id: 'p1', name: 'Profile 1', kind: 'words', did: 'did:sigelo:zA', words: 'apple brave cider delta', created: 1 }, { id: 'p2', name: 'Work', kind: 'remote', did: 'did:sigelo:zB', words: 'eagle fancy giant hover', created: 2 }] };
    const removed = [];
    const profiles = { list: async () => JSON.parse(JSON.stringify(P3)), remove: async (id, o) => { removed.push([id, o]); if (o.password !== PW.pw) throw Object.assign(new Error('Wrong password.'), { check: 'words_password' }); return { reload: true }; } };
    const seatSnap = () => ({ ...snap(), me: { ...snap().me, seat: { holder: 'laptop', epoch: 1, here: false } } });
    const sb3 = { ...sandbox, document: docOf(root3), setInterval: (f, ms) => { iv3.push([f, ms]); return iv3.length; }, history: { replaceState() {}, pushState() {}, back() {} }, sigeloUiTest: undefined,
      sigeloLocal: { ...sandbox.sigeloLocal, profiles, words, async secure(on) { secure.push(on); },
        async call(method, path, b) { posted.push([method, path, b]); const f = { 'GET /api/state': PW.standby ? seatSnap : snap, 'GET /api/agents/workers': () => ({ keeper: true, seat: 'here', workers: [] }), 'GET /api/me': () => ({ did: 'did:sigelo:zA', original: 'did:sigelo:zA', recovery: 'set', key: 'browser', relay: 'relay.sigelo.ai', retention_days: 7, erase: '', restored: { on: '2026-11-03', keeper: 1, seat: 'here' } }),
          'GET /api/groups': () => ({ tier: GR.tier, groups: [], notices: [] }), 'POST /api/seat/take': () => { if (b?.password !== PW.pw) throw Object.assign(new Error('Wrong password.'), { check: 'words_password' }); return { seat: 'here', holder: 'phone', epoch: 2 }; } }[`${method} ${path.split('?')[0]}`];
          try { return f ? { status: 200, body: f() } : { status: 404, body: { error: { check: 'route', message: 'no' } } }; } catch (e) { return { status: 403, body: { error: { check: e.check, message: e.message } } }; } } } };
    sb3.globalThis = sb3;
    vm.runInNewContext(readFileSync(join(HERE, 'vendor', 'ui.js'), 'utf8'), sb3);
    const K = kit(root3), b3 = K.btn, has3 = K.has, poll3 = async () => { await iv3.find(([, ms]) => ms === 2000)[0](); await settle(); };
    const backTo = async () => { await K.aria('Back', 'BUTTON').click(); await settle(); await poll3(); };
    const tab3 = (t) => root3.all().find((e) => e.tagName === 'BUTTON' && e.attrs['data-tab'] === t);
    const toBackup = async () => {
      await tab3('me').click(); await settle(); await poll3();
      await K.aria('Settings', 'BUTTON').click(); await settle(); await poll3();
      await root3.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Backup and recovery')).click(); await settle(); await poll3();
    };
    await settle(); await poll3();
    let u = sandbox.unlocks ?? 0;
    await toBackup();
    ok(K.h1() === 'Backup and recovery' && has3('Showing them always asks your lock and password.') && b3('Show my 25 words') && has3('Set, kept offline') && has3('Change the password') && has3('Stop keeping the words here') && (sandbox.unlocks ?? 0) === u,
      'Backup and recovery: Show my 25 words (kept here), the recovery key, the words password; opening it asks no lock');
    await b3('Show my 25 words').click(); await settle(); await poll3();
    const pw = K.field('Words password');
    ok(K.h1() === 'Show 25 words' && (sandbox.unlocks ?? 0) === u + 1 && pw?.attrs.type === 'password' && pw.attrs.autocomplete === 'current-password' && !root3.all().some((e) => e.tagName === 'OL'), 'Show: the screen lock first, then the password asked, nothing shown yet');
    u = sandbox.unlocks;
    pw.value = 'wrong one'; await b3('Unlock and show').click(); await settle();
    ok(has3('Wrong password.') && !root3.all().some((e) => e.tagName === 'OL') && secure.length === 0, 'Show: a wrong password said plainly, nothing shown, FLAG_SECURE not set');
    pw.value = 'correct horse'; await b3('Unlock and show').click(); await settle(); await poll3();
    const ol = root3.all().find((e) => e.tagName === 'OL');
    ok(ol && ol.kids.length === 25 && /seed-list/.test(ol.className) && /nocopy/.test(ol.className) && secure.at(-1) === true && pw.value === '' && b3('Done') && K.h1() === 'Your 25 words' && !root3.all().some((e) => e.tagName === 'BUTTON' && /Copy/.test(e.textContent)) && (sandbox.unlocks ?? 0) > u,
      'Show: after the lock and the password, the 25 words as at their creation (numbered list, not selectable, no copy), FLAG_SECURE on, the field emptied; one button, Done');
    let prevented = false; ol.on.copy?.forEach((f) => f({ preventDefault: () => { prevented = true; } }));
    await b3('Done').click(); await settle(); await poll3();
    ok(prevented && K.h1() === 'Backup and recovery' && secure.at(-1) === false && !twenty5.some((w) => root3.textContent.includes(w)), 'Show: a copy refused; Done hides them (FLAG_SECURE off, the words gone from the page), back to Backup and recovery');
    await b3('Show my 25 words').click(); await settle();
    K.field('Words password').value = 'correct horse'; await b3('Unlock and show').click(); await settle();
    const shown = root3.all().some((e) => e.tagName === 'OL') && secure.at(-1) === true && K.aria('Close', 'BUTTON') && !K.aria('Back', 'BUTTON');
    await K.aria('Close', 'BUTTON').click(); await settle(); await poll3();
    ok(shown && secure.at(-1) === false && !twenty5.some((w) => root3.textContent.includes(w)), 'Show: shown, the top bar\'s Back becomes Close (the mock\'s); leaving by it hides them too (FLAG_SECURE off)');
    await root3.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Change the password')).click(); await settle(); await poll3();
    K.field('Current password').value = 'nope'; K.field('New password').value = 'battery staple'; K.field('Repeat it').value = 'battery staple';
    await b3('Save').click(); await settle();
    ok(has3('Wrong password.') && PW.pw === 'correct horse', 'Change: the old password asked, a wrong one refused');
    K.field('Current password').value = 'correct horse';
    await b3('Save').click(); await settle(); await poll3();
    ok(PW.pw === 'battery staple' && K.h1() === 'Backup and recovery' && wc.some(([o, a, b, c]) => o === 'change' && a === 'correct horse' && b === 'battery staple' && c === 'battery staple'), 'Change: old, new and its repeat → local.words.change, back to Backup and recovery');
    // Removing the profile: its words password too; taking the seat: the same.
    await backTo();
    await root3.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Profiles')).click(); await settle(); await poll3();
    await b3('Remove Profile 1…').click(); await settle();
    const ppw = K.field('Its words password');
    ok(K.sh1() === 'Remove Profile 1?' && ppw?.attrs.type === 'password', 'Remove a profile with kept words: its words password asked beside the tick');
    K.aria('I have the 25 words', 'INPUT').checked = true; ppw.value = 'correct horse';
    await b3('Remove Profile 1').click(); await settle();
    ok(has3('Wrong password.') && removed.at(-1)?.[1].password === 'correct horse', 'Remove a profile: the password goes with the call; a wrong one refused, said');
    ppw.value = 'battery staple';
    await b3('Remove Profile 1').click(); await settle();
    ok(removed.at(-1)?.[1].password === 'battery staple' && removed.at(-1)[1].words === true && removed.at(-1)[1].name === 'Profile 1', 'Remove a profile: ticked, named and the password → profiles.remove');
    PW.standby = true; await backTo(); await backTo(); await tab3('chats').click(); await settle(); await poll3();
    await b3('Make this phone the main one').click(); await settle(); await poll3();
    ok(K.h1() === 'Make this phone the main one' && K.field('Your words password') && has3('stopped or lost'), 'Seat card with kept words (a spare): Make this phone the main one opens its screen (the warning, the password)');
    K.field('Your words password').value = 'battery staple';
    await root3.all().filter((e) => e.tagName === 'BUTTON' && e.textContent === 'Make this phone the main one').at(-1).click(); await settle();
    ok(posted.some(([m, p, b]) => m === 'POST' && p === '/api/seat/take' && b.confirm === true && b.password === 'battery staple'), 'Take the seat: POST /api/seat/take {confirm, password}');
    PW.standby = false;
    await toBackup();
    await root3.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Stop keeping the words here')).click(); await settle(); await poll3();
    ok(has3('The words kept on this phone are deleted. Your paper is then the only copy.'), 'Stop keeping the words here: the warning');
    K.field('Your words password').value = 'battery staple';
    await b3('Stop keeping them here').click(); await settle(); await poll3();
    ok(!PW.kept && K.h1() === 'Backup and recovery' && has3('they are on your paper only') && !b3('Show my 25 words'), 'Stop keeping them: local.words.remove, then Backup says the words are on paper only, nothing to show');
  }

  // ---- Me → Devices and computers (design/profiles.md P2) over a fake local.computers: the list (the one in use marked),
  // use, connect, forget with the reminder to revoke on the computer; a profile holding an identity shows no computers.
  for (const remote of [true, false]) {
    const root3 = new El('main'), iv3 = [], cc = [];
    const t0 = Math.floor(Date.now() / 1000);
    const C = { active: 'c1', limit: 8, profile: { id: 'p1', name: 'Profile 1', did: 'did:sigelo:zA', words: 'apple brave cider delta' }, computers: [
      { id: 'c1', name: 'Computer 1', via: 'lan', did: 'did:sigelo:zA', words: 'apple brave cider delta', where: '192.168.1.20:8765', paired: t0 - 86400, last_used: t0 - 120 },
      { id: 'c2', name: 'Computer 2', via: 'relay', did: 'did:sigelo:zA', words: 'apple brave cider delta', where: 'relay.sigelo.ai', paired: t0 - 3600, last_used: t0 - 7200 }] };
    const fail = (check, message) => { throw Object.assign(new Error(message), { check }); };
    const computers = {
      list: async () => { cc.push(['list']); if (!remote) fail('not_remote', 'This profile holds an identity here, not computers.'); return JSON.parse(JSON.stringify(C)); },
      use: async (id) => { cc.push(['use', id]); return { active: id, reload: true }; },
      add: async () => { cc.push(['add']); return { reload: true }; },
      forget: async (id) => { cc.push(['forget', id]); C.computers = C.computers.filter((c) => c.id !== id); return { ...JSON.parse(JSON.stringify(C)), revoke: 'sigelo-agent ui --revoke-control <name>' }; },
    };
    const sb = { ...sandbox, document: docOf(root3), setInterval: (f, ms) => { iv3.push([f, ms]); return iv3.length; }, history: { replaceState() {}, pushState() {}, back() {} }, sigeloUiTest: undefined,
      sigeloLocal: { ...sandbox.sigeloLocal, computers, async call(method, path) { const f = { 'GET /api/state': snap, 'GET /api/agents/workers': () => ({ keeper: true, seat: 'here', workers: [] }), 'GET /api/me': () => ({ did: 'did:sigelo:zA', original: 'did:sigelo:zA', recovery: 'set', key: 'file', relay: 'relay.sigelo.ai', retention_days: 7, erase: '' }),
        'GET /api/groups': () => ({ tier: GR.tier, groups: [], notices: [] }) }[`${method} ${path.split('?')[0]}`]; return f ? { status: 200, body: f() } : { status: 404, body: { error: { check: 'route', message: 'no' } } }; } } };
    sb.globalThis = sb;
    vm.runInNewContext(readFileSync(join(HERE, 'vendor', 'ui.js'), 'utf8'), sb);
    const K = kit(root3), poll3 = async () => { await iv3.find(([, ms]) => ms === 2000)[0](); await settle(); };
    const open = async () => {
      await root3.all().find((e) => e.tagName === 'BUTTON' && e.attrs['data-tab'] === 'me').click(); await settle(); await poll3();
      await root3.all().find((e) => e.tagName === 'BUTTON' && e.textContent.startsWith('Devices and computers')).click(); await settle(); await poll3(); await settle(); await poll3();
    };
    await settle(); await poll3();
    await open();
    if (!remote) { ok(K.h1() === 'Devices and computers' && !K.has('Computers this phone can control') && cc.some(([o]) => o === 'list'), 'Devices and computers: a profile holding an identity (not_remote): no computers'); continue; }
    const rowsC = () => root3.all().filter((e) => e.attrs['data-computer']);
    ok(K.has('Computers this phone can control') && rowsC().length === 2 && rowsC()[0].textContent.includes('In use') && rowsC()[0].textContent.includes('apple · brave · cider · delta · on the LAN 192.168.1.20:8765 · used 2 min ago')
      && rowsC()[1].textContent.includes('over the relay relay.sigelo.ai · used 2 h ago') && rowsC()[1].all().some((e) => e.textContent === 'Use') && !rowsC()[0].all().some((e) => e.textContent === 'Use') && K.btn('Connect a computer') && !K.btn('Connect a computer').disabled,
      `Devices and computers: a row per computer (name, four words, LAN or relay, last used), the one in use marked and without Use; Connect a computer (${rowsC().map((c) => c.textContent).join(' / ')})`);
    await rowsC()[1].all().find((e) => e.textContent === 'Use').click(); await settle();
    ok(cc.some(([o, id]) => o === 'use' && id === 'c2'), 'Computers: Use → computers.use (the shell asks the lock and opens that computer\'s page)');
    await K.btn('Connect a computer').click(); await settle();
    ok(cc.some(([o]) => o === 'add'), 'Computers: Connect a computer → computers.add (the pairing screens: code or scan)');
    void rowsC()[1].all().find((e) => e.textContent === 'Forget').click(); await settle();
    ok(K.sheet() && K.sh1() === 'Forget Computer 2?' && K.has('revoke it there: sigelo-agent ui --revoke-control <name>'), 'Computers: Forget asks first, in a sheet (the computer keeps the control until revoked there)');
    await K.btn('Forget Computer 2').click(); await settle(); await poll3();
    ok(cc.some(([o, id]) => o === 'forget' && id === 'c2') && rowsC().length === 1 && K.has('Computer 2 forgotten on this phone. Revoke it on the computer too: sigelo-agent ui --revoke-control <name>'),
      'Computers: then computers.forget, the list again and the reminder to revoke it on the computer');
    C.computers.push(...[3, 4, 5, 6, 7, 8, 9].map((n) => ({ id: `c${n}`, name: `Computer ${n}`, via: 'lan', did: 'did:sigelo:zA', words: null, where: null, paired: null, last_used: null })));
    await K.aria('Back', 'BUTTON').click(); await settle(); await open();
    ok(K.btn('Connect a computer')?.disabled === true && K.has('At most 8 computers'), 'Computers: at 8, Connect a computer off, the limit said');
  }
}

// ================================================================ 3. router.mjs against the relay
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(REPO, 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) report(': parts 1 and 2; SKIP the router, no relay checkout (set SIGELO_RELAY_DIR)');
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { keygen } = await import(pathToFileURL(join(REPO, 'ts', 'dist', 'sigelo.js')).href);
const nodeLib = await import(pathToFileURL(join(REPO, 'apps', 'contact', 'carrier.mjs')).href);
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
  ok(st0.status === 200 && Object.keys(st0.body).sort().join() === 'chats,events,groups,introductions,me,now,pending,seq,transfers' && st0.body.transfers === null && st0.body.me.did === ADA.did
    && Object.keys(st0.body.me).sort().join() === 'clock_checked,clock_offset,did,error,online,picture,pow,pow_capped,pow_confirm,pow_done_ms,relay,retention_days,seat,wallet' && st0.body.me.seat === null && st0.body.me.picture === null && st0.body.me.pow_capped === null
    && JSON.stringify(st0.body.me.wallet) === JSON.stringify({ on: false, prices: false, currency: null }),
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
  ok(Object.keys(cyRow).sort().join() === 'current_did,did,kind,kind_set,last,last_seen,link,local,mine,name,not_collected,notify,online,online_since,ours,pair,picture,picture_local,presence,queued,re_pair,relay,seen_upto,status,tags,tier,unread,via,waiting,words,words_checked',
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
  ok(msgs.messages.map((m) => m.dir).join() === 'out,in' && Object.keys(msgs.messages[0]).sort().join() === 'at,code,detail,dir,iat,label,link,n,status,text' && msgs.seq >= msgs.messages.at(-1).n,
    'GET /api/messages: both, in order, UI-API.md\'s keys');
  // Seen receipts (UI-API.md): the page read the Node agent's answer, so one first receipt went; the agent's carrier takes
  // it apart (never an inbox message) and sends none back: the page's message stays at one tick until a receipt comes.
  const leaked = [];
  for (let i = 0; i < 3; i++) leaked.push(...(await node.inbox({ wait: 0.3 })).messages);
  const nodeSide = node.contacts().contacts.find((c) => c.name === 'ada');
  ok(!leaked.some((m) => m.label === 'sigelo-seen/0') && nodeSide?.seen_peer === true && msgs.messages[0].status === 'sent',
    `seen receipts: the page's first receipt reached the agent, taken apart (no inbox message); its message one tick, sent (${JSON.stringify([leaked.map((m) => m.label), nodeSide?.seen_upto, msgs.messages[0].status])})`);
  await node.seen('ada', Math.floor(Date.now() / 1000));
  ok(await until(async () => (await call(A, 'GET', `/api/messages?contact=${encodeURIComponent(CY.did)}`)).body.messages[0].status === 'seen'),
    'seen receipts: a receipt from the agent → the page\'s message seen (✓✓)');
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
  // Groups (GROUPS.md): the page's drain runs group.mjs handle(): a roster to the Node agent, its answer filed and
  // labelled in the page, the page's message read there.
  {
    const NG = await import(pathToFileURL(join(REPO, 'apps', 'contact', 'group.mjs')).href), nf = NG.groupsPath(join(dir, `${CY.label}.local.json`));
    const g0 = await call(A, 'GET', '/api/groups');
    ok(g0.status === 200 && g0.body.groups.length === 0 && g0.body.tier.members >= 8 && typeof g0.body.tier.told === 'boolean', `GET /api/groups: none yet, the tier (${JSON.stringify(g0.body.tier)})`);
    const mk = await call(A, 'POST', '/api/groups/create', { name: 'crew', members: [CY.did], humans: [CY.did] });
    ok(mk.status === 200 && mk.body.group.members.length === 2 && mk.body.group.members.find((m) => m.did === CY.did)?.role === 'human' && mk.body.copies.length === 1,
      `POST /api/groups/create: crew, cy a human; the roster sent (${JSON.stringify(mk.body.copies)})`);
    const gid = mk.body.group.gid;
    let nh = null;
    ok(await until(async () => { nh = await NG.handle({ carrier: node, file: nf, batch: await node.inbox({ wait: 0.5 }) }); return NG.list({ carrier: node, file: nf }).some((x) => x.gid === gid); }),
      'the Node agent has the roster (a friend\'s group: an invitation)');
    NG.join({ carrier: node, file: nf, group: gid });
    await NG.send({ carrier: node, file: nf, group: gid, text: 'hi group @ada' });
    ok(await until(async () => (await call(A, 'GET', '/api/state')).body.chats.unread === 1), 'the page took it at its drain: chats.unread 1 (the Groups tab\'s count)');
    const gl = (await call(A, 'GET', '/api/groups')).body.groups[0];
    ok(gl.unread === 1 && gl.last?.text === 'hi group @ada' && gl.status === 'member' && gl.mine, `GET /api/groups: unread 1, the last message (${JSON.stringify(gl.last)})`);
    const hi = (await call(A, 'GET', `/api/groups/history?group=${gid}`)).body;
    const m = hi.messages.find((x) => x.text === 'hi group @ada');
    ok(m && m.name === 'cyrus' && m.role === 'human' && m.note === 'not your operator' && m.mine === false && m.mentioned === true && m.from === CY.did,
      `GET /api/groups/history: labelled with name, role, "not your operator", mentioned (${JSON.stringify(m)})`);
    ok((await call(A, 'GET', '/api/groups')).body.groups[0].unread === 0, 'read once shown: unread 0');
    const snd = await call(A, 'POST', '/api/groups/send', { group: gid, text: 'back to the group' });
    ok(snd.status === 200 && snd.body.copies.length === 1, `POST /api/groups/send: one copy (${JSON.stringify(snd.body.copies)})`);
    const got = [];
    ok(await until(async () => { got.push(...(await NG.handle({ carrier: node, file: nf, batch: await node.inbox({ wait: 0.5 }) })).batch.messages); return got.some((x) => x.content === 'back to the group' && x.group?.gid === gid); }),
      'the Node agent reads the page\'s group message');
    const rn = await call(A, 'POST', '/api/groups/rename', { group: gid, name: 'ship' }), bad = await call(A, 'POST', '/api/groups/rename', { group: 'nope', name: 'x' });
    ok(rn.status === 200 && rn.body.group.name === 'ship' && rn.body.group.ver === 2 && bad.status === 404 && bad.body.error.check === 'group_unknown', 'POST /api/groups/rename; an unknown group: 404 group_unknown');
    void nh;
  }

  // Enrol from the app (the operator's own: restored from seed, the seat here): a one-time code made on the app's own
  // session; a Node machine pairs through it as a temporary identity (enrol.mjs accept), is sent worker 1 and pairs
  // as it (complete, place); the app files it: the Agents list shows it enrolled.
  {
    const SD = await import(pathToFileURL(join(HERE, 'seed.mjs')).href), E = await import(pathToFileURL(join(REPO, 'apps', 'contact', 'enrol.mjs')).href);
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
      // The worker's row, the contact in Mine and the temporary pairing's removal settle in separate
      // steps after the enrolment lands; CI saw the row enrolled before the rest had settled, so the
      // whole condition is waited for, not a snapshot of it.
      const settled = (w, st) => w?.status === 'enrolled' && w.contact && w.placed === 'remote' && w.tier === 'quiet' && w.enrolling?.state === 'enrolled'
        && st.groups.mine.some((c) => c.did === w.contact && c.ours === true && c.name === 'vps')
        && ![...st.groups.mine, ...st.groups.contacts].some((c) => c.name.includes('(enrolling)')) && !st.pending.invites.some((x) => x.name.includes('(enrolling)'));
      let w1, st;
      const enrolled = await until(async () => {
        w1 = (await O.call('GET', '/api/agents/workers')).body.workers.find((x) => x.worker === 1); st = (await O.call('GET', '/api/state')).body;
        return settled(w1, st) ? w1 : null;
      }, 30000);
      ok(enrolled, `app enrol: the list shows it enrolled (remote, quiet as chosen), in Mine as ours; nothing of the temporary pairing shows (${JSON.stringify(w1).slice(0, 240)} mine=${JSON.stringify(st?.groups.mine.map((c) => [c.name, c.ours]))})`);
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
