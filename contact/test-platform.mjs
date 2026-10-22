// SPDX-License-Identifier: MIT
// The platform seam (platform-node.mjs, design/apps.md §4.2): two carriers whose files live in a
// Map, whose lock is in-process and whose owner is a Set, pair by code, write, send a file given as
// bytes and a name, read it, and read their history, against a loopback relay (relay/server.mjs in
// this process) reached through Node's fetch, MQTT and proof of work. Their names point into a
// folder that does not exist: one call past the platform to the disk would fail. Also: the Node
// platform's own files (write, new, add, list, remove) in a temporary folder.
//   node contact/test-platform.mjs   → ALL PASS (n)
// The relay is its own AGPL package: SIGELO_RELAY_DIR, else ../relay; without it, SKIP the carrier part.
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { Carrier, pathsFor } from './carrier.mjs';
import { platform as node } from './platform-node.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const report = (skip = '') => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
  console.log(`ALL PASS (${count})${skip}`);
  process.exit(0);
};
setTimeout(() => { console.log(`FAIL the run did not finish in 120 s (${count} checks so far)`); process.exit(1); }, 120000).unref();
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.code ?? e.check ?? e.message; } };

// ================================================================ the Node platform's files
{
  const dir = mkdtempSync(join(tmpdir(), 'sigelo-platform-')), { files } = node, f = join(dir, 'a.json');
  try {
    ok(files.read(f) === null, 'read: an absent file is null');
    files.write(f, new TextEncoder().encode('{"a":1}'));
    ok(new TextDecoder().decode(files.read(f)) === '{"a":1}' && ((statSync(f).mode & 0o777) === 0o600 || process.platform === 'win32'), 'write: whole, 0600');
    ok(files.list(dir).join() === 'a.json', `write: by rename, no temporary left (${files.list(dir)})`);
    ok(checkOf(() => files.write(f, new Uint8Array(1), { how: 'new' })) === 'EEXIST', 'write new: never over a file');
    const sub = join(dir, 'in', 'x');
    files.folder(sub, [join(dir, 'in')]);
    const at = [join(sub, 'f'), join(sub, 'f-2')];
    ok(files.add(at, new Uint8Array([1])) === at[0] && files.add(at, new Uint8Array([2])) === at[1] && files.add(at, new Uint8Array([3])) === null,
      'add: the first name not taken, then the next, then none');
    ok(files.list(sub).sort().join() === 'f,f-2' && files.read(at[0])[0] === 1, `add: no temporary left, nothing overwritten (${files.list(sub)})`);
    files.remove(join(dir, 'in'));
    ok(!existsSync(join(dir, 'in')) && files.list(join(dir, 'in')).length === 0, 'remove: a folder and what it holds; list of none: []');
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// ================================================================ an in-memory platform
// What a browser's platform-web.mjs keeps in IndexedDB, here a Map; the network and the CPU are Node's.
const posix = { join: (...p) => p.join('/').replace(/\/+/g, '/'), dirname: (p) => p.slice(0, p.lastIndexOf('/')) || '/', resolve: (p) => p };
function memory() {
  const m = new Map(), calls = { transact: 0, fetch: 0, mqtt: 0, pow: 0, flush: 0 };
  let depth = 0;
  const exists = Object.assign(new Error('EEXIST'), { code: 'EEXIST' });
  const files = {
    read: (n) => (m.has(n) ? m.get(n).slice() : null),
    write: (n, b, { how = 'replace' } = {}) => { if (how === 'new' && m.has(n)) throw exists; m.set(n, Uint8Array.from(b)); },
    remove: (n) => { for (const k of [...m.keys()]) if (k === n || k.startsWith(`${n}/`)) m.delete(k); },
    list: (dir) => [...new Set([...m.keys()].filter((k) => k.startsWith(`${dir}/`)).map((k) => k.slice(dir.length + 1).split('/')[0]))],
    folder: () => {},
    add: (names, b) => { const n = names.find((x) => !m.has(x)) ?? null; if (n !== null) m.set(n, Uint8Array.from(b)); return n; },
  };
  const owners = new Set();
  return {
    m, calls,
    platform: {
      files, path: posix,
      flush: async () => { calls.flush++; },
      transact: (name, fn) => { calls.transact++; if (depth > 0) throw new Error('transact re-entered'); depth++; try { return fn(); } finally { depth--; } },
      owner: async (id) => { if (owners.has(id)) throw Object.assign(new Error('busy'), { check: 'busy' }); owners.add(id); return { release: () => owners.delete(id) }; },
      fetch: (url, init) => { calls.fetch++; return node.fetch(url, init); },
      mqtt: (url, opts) => { calls.mqtt++; return node.mqtt(url, opts); },
      transports: ['mqtts', 'wss'],
      pow: (prefix, bits, o) => { calls.pow++; return node.pow(prefix, bits, o); },
      env: {},
    },
  };
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) report(': the part without a relay; SKIP the rest, no relay checkout beside contact/ (set SIGELO_RELAY_DIR)');
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);

const HOST = 'relay.test', CREATED = '2026-10-01T00:00:00Z';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-platform-relay-'));
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-platform-test/0 ${l}`).digest());
function agent(label) {
  const recovery = keygen({ seed: seed(`${label} recovery`), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} rn`).slice(0, 16) }).key;
  const k = keygen({ seed: seed(label), recovery, created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, did: k.did, secret: k.secret, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
// Names under a folder that is not there: the disk would refuse every one.
const NOWHERE = join(dir, 'not-there');
const make = (a, mem) => new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(`${NOWHERE}/${a.label}.local.json`), relay: HOST, endpoints,
  keep: true, backoff: [100, 400], retentionDays: 7, platform: mem.platform });

try {
  const A = agent('ada'), B = agent('bo'), ma = memory(), mb = memory(), a = make(A, ma), b = make(B, mb);
  ok(checkOf(() => new Carrier({ identity: () => ({}), store: 's', state: 't', platform: {} })).startsWith('platform:'), 'a platform without files or a lock is refused');
  const inv = await a.invite({ name: 'bo' });
  const acc = await b.accept(inv.code, { name: 'ada', wait: 0.3 });
  await a.inbox(); await b.inbox(); await a.inbox();
  const paired = a.contacts().contacts.map((c) => c.did).join() === B.did && b.contacts().contacts.map((c) => c.did).join() === A.did;
  ok(paired, `invite and accept pair the two (${acc.status})`);
  ok(a.contacts().contacts[0].fingerprint === b.contacts().contacts[0].fingerprint, 'both hold the same four words');
  const s1 = await a.send('bo', { text: 'hello through a Map' }), s2 = await b.send('ada', 'and back');
  const rb = await b.inbox(), ra = await a.inbox();
  ok(s1.status === 'sent' && s2.status === 'sent', `send: sent both ways (${s1.status}, ${s2.status})`);
  ok(rb.messages.map((x) => x.content?.text).join() === 'hello through a Map' && ra.messages.map((x) => x.content).join() === 'and back', 'inbox: each reads the other');
  // A file as a page has it: bytes and a name, no path.
  const bytes = new Uint8Array(300 * 1024).map((_, i) => (i * 7) & 255);
  const f = await a.sendFile('bo', { bytes, name: 'notes.bin' });
  const got = (await b.inbox()).messages.find((x) => x.type === 'file');
  ok(f.status === 'sent' && f.file.chunks === 2, `sendFile { bytes, name }: manifest and chunks sent (${f.status}, ${f.file?.chunks})`);
  ok(got?.name === 'notes.bin' && got.size === bytes.length && mb.m.has(got.path) && mb.m.get(got.path).every((x, i) => x === bytes[i]),
    `the file arrives whole, saved in the reader's files under ${got?.path}`);
  ok(![...mb.m.keys()].some((k) => k.includes('/.partial/')) && ![...ma.m.keys()].some((k) => k.includes('/.out/')), 'its parts and its spool are gone once sent and saved');
  ok(await a.sendFile('bo', '/etc/hostname').then(() => 'sent', (e) => e.check) === 'file', 'a path, on a platform that reads none: refused, file');
  ok(b.history().messages.map((x) => x.content?.text ?? x.name).join() === 'hello through a Map,notes.bin', 'history: the log, from the Map');
  const st = JSON.parse(new TextDecoder().decode(ma.m.get(pathsFor(`${NOWHERE}/ada.local.json`).state)));
  ok(st.v === 'sigelo-carrier/0' && st.self === A.did && Object.keys(st.peers).join() === B.did, 'the state is the same JSON, under its name in the Map');
  ok(ma.calls.transact > 0 && ma.calls.fetch > 0 && ma.calls.mqtt > 0 && ma.calls.pow > 0 && mb.calls.pow > 0, `every call went through the platform (${JSON.stringify(ma.calls)})`);
  ok(!existsSync(NOWHERE), 'nothing reached the disk');
  await a.forget(B.did);
  ok(a.contacts().contacts[0]?.revoked === true, 'forget: revoked, in the Map');
  const o = await ma.platform.owner('ada');
  ok(await ma.platform.owner('ada').then(() => 'taken', (e) => e.check) === 'busy', 'owner: one per identity');
  o.release();
} finally {
  await relay.close?.();
  rmSync(dir, { recursive: true, force: true });
}
report();
