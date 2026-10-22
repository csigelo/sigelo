// SPDX-License-Identifier: MIT
// File transfer (file.mjs, carrier.sendFile and its receive path; design/human-ui-plan.md §4):
// the pure part (byte-exact round trips from fixed seeds, a tampered chunk, oversize, names); then,
// with the relay checkout beside contact/ (SIGELO_RELAY_DIR, else ../relay), on a loopback relay: a
// 1 MiB file each way, saved 0600 under <identity>.files/<contact>-<16 hex of its DID hash>/, never over a file, a forged file refused, an
// incomplete one dropped at the retention.
//   node contact/test-file.mjs   → ALL PASS (n)
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalize, keygen } from 'sigelo';
import { CHUNK, FILE_LABEL, MAX_FILE, assemble, checkChunk, checkManifest, chunksOf, isManifest, safeName, sizeText, splitFile } from './file.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};
// n bytes from a fixed seed: SHA-256 in counter mode.
const seeded = (seed, n) => {
  const out = Buffer.alloc(n);
  for (let i = 0, off = 0; off < n; i++, off += 32) createHash('sha256').update(`${seed}\n${i}`).digest().copy(out, off);
  return new Uint8Array(out.buffer, out.byteOffset, n);
};
const same = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const ID = 'ab'.repeat(16);

// ================================================================ the pure part
{
  ok(FILE_LABEL === 'sigelo-file/0' && CHUNK === 262144 && MAX_FILE === 8388608, 'label sigelo-file/0, 256 KiB chunks, 8 MiB a file');
  for (const [seed, n] of [['empty', 0], ['one', 1], ['odd', 1000], ['a chunk', CHUNK], ['a chunk and a byte', CHUNK + 1], ['1 MiB', 1 << 20], ['8 MiB', MAX_FILE]]) {
    const bytes = seeded(`sigelo-file-test/0 ${seed}`, n);
    const { manifest, chunks } = splitFile(bytes, 'report.pdf', { id: ID });
    ok(isManifest(manifest) && chunks.every((c) => !isManifest(c)) && manifest.chunks === chunksOf(n) && chunks.length === manifest.chunks, `${seed}: a manifest, then ${chunksOf(n)} chunks`);
    const m = checkManifest(JSON.parse(canonicalize(manifest)));
    const back = assemble(m, chunks.map((c) => checkChunk(JSON.parse(canonicalize(c)), m)));
    ok(same(back, bytes) && m.size === n && m.sha256 === createHash('sha256').update(bytes).digest('hex'), `${seed} (${n} bytes): byte-exact round trip through canonical JSON`);
  }
  // Each chunk message fits the free tier's 512 KiB less an epoch's 1,198 bytes, with room for the
  // signed body around it (from, to, pair, iat, label, sig: under 1 KiB).
  const full = splitFile(seeded('sigelo-file-test/0 full', CHUNK), 'x', { id: ID }).chunks[0];
  const size = canonicalize({ label: FILE_LABEL, content: full }).length;
  ok(size + 1024 < 512 * 1024 - 1198, `a full chunk is ${size} bytes of JSON: under the free cap less the epoch header`);
  // A known vector: the manifest of three fixed bytes.
  const v = splitFile(new Uint8Array([1, 2, 3]), 'abc', { id: ID });
  ok(canonicalize(v.manifest) === `{"chunks":1,"id":"${ID}","name":"abc","sha256":"039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81","size":3}`
    && v.chunks[0].data === 'AQID', 'the manifest and chunk of [1,2,3]: fixed');

  // Tampered: one byte of one chunk flipped, still canonical base64 → file_hash.
  const bytes = seeded('sigelo-file-test/0 tamper', CHUNK * 2 + 77);
  const { manifest, chunks } = splitFile(bytes, 'a.bin', { id: ID });
  const m = checkManifest(manifest), raw = Buffer.from(chunks[1].data, 'base64');
  raw[1000] ^= 1;
  const bad = { ...chunks[1], data: raw.toString('base64') };
  ok(checkOf(() => assemble(m, [chunks[0], bad, chunks[2]].map((c) => checkChunk(c, m)))) === 'file_hash', 'a chunk with one bit flipped: file_hash');
  ok(checkOf(() => assemble(m, [0, 2, 1].map((i) => checkChunk(chunks[i], m)))) === 'file_hash', 'chunks out of order: file_hash');
  ok(checkOf(() => checkChunk({ ...chunks[2], data: chunks[2].data.slice(0, -4) }, m)) === 'file_chunk', 'a short last chunk: file_chunk');
  ok(checkOf(() => checkChunk({ ...chunks[0], data: chunks[0].data.replace(/.$/, ' ') }, m)) === 'file_chunk', 'non-canonical base64: file_chunk');
  ok(checkOf(() => checkChunk({ ...chunks[0], i: 3 }, m)) === 'file_chunk', 'an index past the manifest\'s chunks: file_chunk');
  ok(checkOf(() => checkChunk({ ...chunks[0], id: 'cd'.repeat(16) }, m)) === 'file_chunk', 'another file\'s chunk: file_chunk');
  ok(checkOf(() => checkChunk({ ...chunks[0], extra: 1 }, m)) === 'file_chunk', 'a chunk with an extra key: file_chunk');

  // Oversize: refused when split, and a manifest saying so is refused when received.
  ok(checkOf(() => splitFile(new Uint8Array(MAX_FILE + 1), 'big')) === 'file_too_large', 'splitting 8 MiB and a byte: file_too_large');
  ok(checkOf(() => checkManifest({ ...manifest, size: MAX_FILE + 1, chunks: chunksOf(MAX_FILE + 1) })) === 'file_too_large', 'a manifest of 8 MiB and a byte: file_too_large');
  ok(checkOf(() => checkManifest({ ...manifest, chunks: 2 })) === 'file', 'a manifest whose chunks do not match its size: file');
  ok(checkOf(() => checkManifest({ ...manifest, sha256: 'AB'.repeat(32) })) === 'file', 'a manifest with an uppercase hash: file');
  ok(checkOf(() => checkManifest({ ...manifest, size: 1.5 })) === 'file', 'a manifest with a fractional size: file');
  ok(checkOf(() => checkManifest({ ...manifest, name: 'x'.repeat(1025) })) === 'file', 'a manifest name past 1,024 characters: file');

  // Names: the last segment, no controls, nothing NTFS refuses (":" streams), no leading dots, no
  // trailing dots or spaces, no device names, at most 200 bytes, never empty.
  for (const [raw, want] of [['report.pdf', 'report.pdf'], ['../../etc/passwd', 'passwd'], ['..\\..\\boot.ini', 'boot.ini'], ['/abs/path/x.txt', 'x.txt'],
    ['.bashrc', 'bashrc'], ['...hidden', 'hidden'], ['..', 'file'], ['', 'file'], ['dir/', 'file'], ['a\u0000b\u001bc\u007fd\u0085e.txt', 'abcde.txt'],
    ['evil\u202Etxt.exe', 'eviltxt.exe'], ['line\nbreak.md', 'linebreak.md'], [' \t.x', 'x'], ['naïve café.txt', 'naïve café.txt'],
    ['notes.txt:secret', 'notes.txtsecret'], ['C:evil.exe', 'Cevil.exe'], ['a<b>c"d|e?f*g.txt', 'abcdefg.txt'], ['trail. . ', 'trail'],
    ['CON', '_CON'], ['nul.txt', '_nul.txt'], ['com1.log', '_com1.log'], ['Lpt9', '_Lpt9'], ['console.txt', 'console.txt'], [':', 'file']]) {
    ok(safeName(raw) === want, `safeName ${JSON.stringify(raw)} → ${JSON.stringify(safeName(raw))}, expected ${JSON.stringify(want)}`);
  }
  const long = safeName('é'.repeat(150) + '.txt');
  ok(Buffer.byteLength(long) <= 200 && long === 'é'.repeat(100), `a 304-byte name: cut to 200 bytes on a character boundary (${Buffer.byteLength(long)})`);
  ok(splitFile(new Uint8Array(1), '../.secret').manifest.name === 'secret', 'the sender sends safeName of the name too');
  ok(checkManifest({ ...manifest, name: '../../.ssh/authorized_keys' }).name === 'authorized_keys', 'a received manifest\'s name is reduced to safeName');
  ok(sizeText(812) === '812 B' && sizeText(12 * 1024) === '12.0 KiB' && sizeText(1 << 20) === '1.0 MiB', 'sizes for people');
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) {
  report();
  console.log(`ALL PASS (${count}): the pure part; SKIP the flow, no relay checkout beside contact/: set SIGELO_RELAY_DIR`);
  process.exit(0);
}

// ================================================================ the flow, on a loopback relay
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, DEVICE_LABEL, DEVICE_SEND, LOG_MAX, contactDir, pathsFor } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 300 s (${count} checks so far)`); process.exit(1); }, 300000).unref();

const HOST = 'relay.test', CREATED = '2026-10-01T00:00:00Z';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-file-'));
let now = Date.parse('2026-10-14T12:00:00Z') / 1000;
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: () => {}, policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-file-test/0 ${l}`).digest());
function agent(label) {
  const recovery = keygen({ seed: seed(`${label} recovery`), recovery: 'sha256:' + '0'.repeat(64), created: CREATED, nonce: seed(`${label} recovery nonce`).slice(0, 16) }).key;
  const k = keygen({ seed: seed(label), recovery, created: CREATED, nonce: seed(`${label} nonce`).slice(0, 16) });
  return { label, did: k.did, secret: k.secret, bundle: { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } };
}
const events = {};
const make = (a) => {
  events[a.label] = [];
  return new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, `${a.label}.local.json`)), relay: HOST, endpoints,
    clock: () => now, onEvent: (e) => events[a.label].push(e), keep: true, backoff: [100, 400], retentionDays: 7 });
};
const refused = async (f) => { try { await f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.message}`; } };
const mode = (p) => statSync(p).mode & 0o777;
// alice's files, through a carrier that reaches no relay: what a send queues while offline.
const offline = (a) => new Carrier({ identity: () => ({ secret: a.secret, bundle: a.bundle }), ...pathsFor(join(dir, `${a.label}.local.json`)), relay: HOST,
  endpoints: { [HOST]: { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:1' } }, clock: () => now, keep: true, retentionDays: 7 });
const spool = join(dir, 'alice.local.files', '.out'), spooled = () => (existsSync(spool) ? readdirSync(spool) : []);
try {
  const alice = agent('alice'), bob = agent('bob');
  const ca = make(alice), cb = make(bob);
  ok(pathsFor(join(dir, 'alice.local.json')).files === join(dir, 'alice.local.files') && ca.filesDir === join(dir, 'alice.local.files'), 'pathsFor names <identity>.files beside the identity');
  // Pairing, each side offline in turn (test-carrier.mjs "pairing by code").
  const inv = await ca.invite({ name: 'bob' });
  await cb.accept(inv.code, { name: 'alice', wait: 0.3 });
  await ca.inbox(); await cb.inbox(); await ca.inbox();
  ok(ca.contacts().contacts.length === 1 && cb.contacts().contacts.length === 1, 'alice and bob paired');

  // 1 MiB each way.
  for (const [from, to, cFrom, cTo, toName, fromName] of [['alice', 'bob', ca, cb, 'bob', 'alice'], ['bob', 'alice', cb, ca, 'alice', 'bob']]) {
    now += 60;
    const bytes = seeded(`sigelo-file-test/0 ${from} to ${to}`, 1 << 20), src = join(dir, `${from}-photo.jpg`);
    writeFileSync(src, bytes);
    const sent = await cFrom.sendFile(toName, src);
    const sum = createHash('sha256').update(bytes).digest('hex');
    ok(sent.status === 'sent' && sent.name === toName && sent.file.name === `${from}-photo.jpg` && sent.file.size === 1 << 20 && sent.file.sha256 === sum && sent.file.chunks === 4,
      `${from} → ${to}: sendFile sent, 4 chunks (${JSON.stringify(sent)})`);
    now += 60;
    const box = await cTo.inbox();
    const f = box.messages.find((m) => m.type === 'file');
    const want = join(dir, `${to}.local.files`, contactDir({ name: fromName, did: (from === 'alice' ? alice : bob).did }), `${sum.slice(0, 8)}-${from}-photo.jpg`);
    ok(box.messages.length === 1 && f && f.name === `${from}-photo.jpg` && f.size === 1 << 20 && f.sha256 === sum && f.path === want && f.contact === fromName && f.label === FILE_LABEL,
      `${to}'s inbox: one item {type: file, name, size, sha256, path} (${JSON.stringify(box.messages.map((m) => ({ ...m, content: undefined })))}; dropped ${JSON.stringify(box.dropped)})`);
    ok(f && existsSync(f.path) && same(readFileSync(f.path), bytes), `${to}: the saved file is byte-exact`);
    ok(f && mode(f.path) === 0o600 && mode(dirname(f.path)) === 0o700 && mode(dirname(dirname(f.path))) === 0o700, `${to}: the file 0600, its directories 0700`);
    ok(events[to].filter((e) => e.type === 'file' && e.sha256 === sum).length === 1 && !events[to].some((e) => e.type === 'message' && e.label === FILE_LABEL),
      `${to}: onEvent got one file event, no chunk as a message`);
    ok(!existsSync(join(dir, `${to}.local.files`, '.partial')) || readdirSync(join(dir, `${to}.local.files`, '.partial')).length === 0, `${to}: no parts left behind`);
  }

  // Folders by contact: two names that reduce alike, two DIDs, two folders; the name stays readable.
  ok(contactDir({ name: 'bo:b', did: alice.did }) !== contactDir({ name: 'bob', did: bob.did }) && contactDir({ name: 'bo:b', did: alice.did }).startsWith('bob-')
    && /^bob-[0-9a-f]{16}$/.test(contactDir({ name: 'bob', did: bob.did })), 'contactDir: name-<16 hex of the DID hash>, distinct for two DIDs whose names reduce alike');
  // The same file again: never written over; the second is saved beside it, the first unchanged.
  now += 60;
  const again = join(dir, 'alice-photo.jpg'), aBytes = readFileSync(again);
  await ca.sendFile('bob', again);
  now += 60;
  const a2 = (await cb.inbox()).messages.find((m) => m.type === 'file');
  const aDir = join(dir, 'bob.local.files', contactDir({ name: 'alice', did: alice.did })), aSum = createHash('sha256').update(aBytes).digest('hex');
  ok(a2?.path === join(aDir, `${aSum.slice(0, 8)}-2-alice-photo.jpg`) && same(readFileSync(a2.path), aBytes) && same(readFileSync(join(aDir, `${aSum.slice(0, 8)}-alice-photo.jpg`)), aBytes),
    `a name taken already: saved as <sha8>-2-<name>, the first kept (${a2?.path})`);
  // A file planted where the next copy would go (another process, a user): left alone.
  writeFileSync(join(aDir, `${aSum.slice(0, 8)}-3-alice-photo.jpg`), 'planted');
  now += 60;
  await ca.sendFile('bob', again);
  now += 60;
  const a4 = (await cb.inbox()).messages.find((m) => m.type === 'file');
  ok(a4?.path === join(aDir, `${aSum.slice(0, 8)}-4-alice-photo.jpg`) && readFileSync(join(aDir, `${aSum.slice(0, 8)}-3-alice-photo.jpg`), 'utf8') === 'planted',
    `a planted file is not written over: the next free name (${a4?.path})`);
  // The inbox log holds the file items' metadata, not the bytes, 0600.
  const logFile = pathsFor(join(dir, 'bob.local.json')).log, logText = readFileSync(logFile, 'utf8');
  ok(mode(logFile) === 0o600 && cb.history().messages.filter((m) => m.type === 'file').length === 3 && logText.length < 20000,
    `bob's inbox log: 0600, the three file items, no file bytes (${logText.length} bytes)`);

  // Queued while offline: the chunks wait in <identity>.files/.out, not in the state; another
  // process (a restart) sends them; the spool is gone once they went.
  now += 60;
  const qBytes = seeded('sigelo-file-test/0 queued', 1 << 20), qSrc = join(dir, 'queued.bin'), qSum = createHash('sha256').update(qBytes).digest('hex');
  writeFileSync(qSrc, qBytes);
  const qErr = await refused(() => offline(alice).sendFile('bob', qSrc));
  const stateFile = pathsFor(join(dir, 'alice.local.json')).state, qState = readFileSync(stateFile, 'utf8');
  ok(qErr === 'connect' && spooled().length === 4 && spooled().every((n) => mode(join(spool, n)) === 0o600) && mode(spool) === 0o700,
    `offline: sendFile throws (${qErr}), its 4 chunks spooled 0600 in a 0700 directory (${spooled().join()})`);
  const qOut = JSON.parse(qState).peers[bob.did].outbox;
  ok(qOut.length === 5 && qOut.slice(1).every((x) => x.spool === true && x.content === undefined) && !qState.includes(Buffer.from(qBytes.subarray(0, 300)).toString('base64').slice(0, 200)),
    `the state keeps the manifest and four pointers, no chunk (${JSON.stringify(qOut.map((x) => Object.keys(x)))})`);
  now += 60;
  await ca.inbox();
  now += 60;
  const qf = (await cb.inbox()).messages.find((m) => m.type === 'file');
  ok(qf?.sha256 === qSum && same(readFileSync(qf.path), qBytes) && spooled().length === 0, 'after a restart the queue goes: bob gets it byte-exact, and the spool is empty');

  // A plain message keeps its shape beside files.
  now += 60;
  await ca.send('bob', 'plain');
  const plain = (await cb.inbox()).messages[0];
  ok(plain && plain.type === undefined && plain.content === 'plain' && plain.name === 'alice', 'a plain message: as before (no type, name = the contact)');

  // The inbox log (carrier.mjs log): inbox and take append before they give out; history reads it
  // again with no session; enrolment's labels never; a failed write leaves the messages in the state;
  // the newest LOG_MAX only; log: false keeps none.
  const bobLog = pathsFor(join(dir, 'bob.local.json')).log;
  ok(cb.logPath === bobLog && cb.history().messages.at(-1)?.content === 'plain', 'history: the plain message inbox gave out, from <identity>.inbox.log');
  now += 60;
  await ca.sendAll('bob', ['kept 1', 'kept 2'], {});
  await ca.send('bob', { secret: 'a worker key' }, { label: 'sigelo-identity/0' });
  ok(await refused(() => ca.send('bob', { secret: 'device material' }, { label: 'sigelo-device/1' })) === 'body', 'the label sigelo-device/1 without the device verbs\' own token: refused (body)');
  await ca.send('bob', { secret: 'device material' }, { label: DEVICE_LABEL, internal: DEVICE_SEND });
  now += 60;
  const broken = new Carrier({ identity: () => ({ secret: bob.secret, bundle: bob.bundle }), ...pathsFor(join(dir, 'bob.local.json')), log: join(dir, 'no-such-dir', 'x.log'),
    relay: HOST, endpoints, clock: () => now, keep: true, retentionDays: 7 });
  ok(await refused(() => broken.inbox()) !== 'accepted', 'a log that cannot be written: inbox throws');
  const kb = await cb.inbox();
  ok(kb.messages.map((m) => m.content?.secret ?? m.content).join() === 'kept 1,kept 2,a worker key', `…and nothing was taken: the next inbox has them (${kb.messages.length})`);
  const dv = cb.takeDevices();
  ok(dv.length === 1 && dv[0].content.secret === 'device material' && dv[0].label === DEVICE_LABEL && cb.takeDevices().length === 0, 'the sigelo-device/1 message: never an inbox message, kept apart for takeDevices (once)');
  const hist = cb.history().messages.map((m) => m.content);
  ok(hist.includes('kept 1') && hist.includes('kept 2') && !readFileSync(bobLog, 'utf8').includes('a worker key') && !readFileSync(bobLog, 'utf8').includes('device material'),
    'logged once each; a sigelo-identity/0 message (a worker key) and a sigelo-device/1 one (device material) never');
  ok(cb.history({ since: now + 1 }).messages.length === 0 && cb.history({ since: now - 60 }).messages.length === 2, 'history since: by received');
  now += 60;
  await ca.send('bob', 'taken by take');
  await cb.sync();
  const tk = cb.take((m) => m.content === 'taken by take');
  ok(tk.length === 1 && cb.history().messages.at(-1)?.content === 'taken by take', 'take() logs what it hands out');
  writeFileSync(bobLog, Array.from({ length: LOG_MAX + 100 }, (_, i) => JSON.stringify({ content: `old ${i}`, received: 1 })).join('\n') + '\n', { mode: 0o600 });
  now += 60;
  await ca.send('bob', 'newest');
  await cb.inbox();
  const trimmed = cb.history().messages;
  ok(trimmed.length === LOG_MAX && trimmed.at(-1).content === 'newest' && trimmed[0].content === 'old 101', `the log keeps the newest ${LOG_MAX} (${trimmed.length}, first ${trimmed[0]?.content})`);
  const none = new Carrier({ identity: () => ({ secret: bob.secret, bundle: bob.bundle }), ...pathsFor(join(dir, 'bob.local.json')), log: false, relay: HOST, endpoints, clock: () => now, keep: true });
  ok(none.logPath === null && none.history().messages.length === 0, 'log: false: no log, history empty');

  // Refused before anything connects: oversize, missing, a directory, the identity's own files.
  const big = join(dir, 'big.bin');
  writeFileSync(big, Buffer.alloc(MAX_FILE + 1));
  ok(await refused(() => ca.sendFile('bob', big)) === 'file_too_large', 'sendFile of 8 MiB and a byte: file_too_large');
  ok(await refused(() => ca.sendFile('bob', join(dir, 'nope.bin'))) === 'file', 'sendFile of a missing file: file');
  ok(await refused(() => ca.sendFile('bob', dir)) === 'file', 'sendFile of a directory: file');
  for (const f of ['alice.local.json', 'bob.local.json']) writeFileSync(join(dir, f), '{}');
  for (const own of ['alice.local.json', 'alice.local.carrier.json', 'alice.local.contacts.json', 'bob.local.json', 'alice.local.inbox.log']) {
    ok(await refused(() => ca.sendFile('bob', join(dir, own))) === 'file', `sendFile of ${own}: refused (an identity's own file)`);
  }
  const bobDir = join(dir, 'alice.local.files', contactDir({ name: 'bob', did: bob.did })), got = readdirSync(bobDir)[0];
  ok(await refused(() => ca.sendFile('bob', join(bobDir, got))) === 'file', 'sendFile of a file received: refused');

  // A forged file: a manifest, then a chunk not of those bytes (still canonical base64).
  now += 60;
  const real = seeded('sigelo-file-test/0 forged', 1000), { manifest, chunks } = splitFile(real, 'forged.txt');
  const raw = Buffer.from(chunks[0].data, 'base64');
  raw[10] ^= 0xff;
  await ca.sendAll('bob', [manifest, { ...chunks[0], data: raw.toString('base64') }], { label: FILE_LABEL });
  const fb = await cb.inbox();
  ok(fb.messages.length === 0 && fb.dropped.file_hash === 1 && !readdirSync(join(dir, 'bob.local.files', contactDir({ name: 'alice', did: alice.did }))).some((n) => n.endsWith('forged.txt')), `a tampered chunk: no file, dropped file_hash (${JSON.stringify(fb.dropped)})`);
  // A chunk with no manifest, and a malformed manifest.
  now += 60;
  await ca.sendAll('bob', [splitFile(real, 'orphan.txt').chunks[0], { ...manifest, id: 'x' }], { label: FILE_LABEL });
  const ob = await cb.inbox();
  ok(ob.messages.length === 0 && ob.dropped.file_chunk === 1 && ob.dropped.file === 1, `a chunk without its manifest: file_chunk; a malformed manifest: file (${JSON.stringify(ob.dropped)})`);
  // An incomplete file: the manifest and one chunk of two, then the retention passes.
  now += 60;
  const half = splitFile(seeded('sigelo-file-test/0 half', CHUNK + 5), 'half.bin');
  await ca.sendAll('bob', [half.manifest, half.chunks[0]], { label: FILE_LABEL });
  const hb = await cb.inbox();
  const parts = join(dir, 'bob.local.files', '.partial');
  ok(hb.messages.length === 0 && readdirSync(parts).length === 1 && mode(parts) === 0o700, 'half a file: nothing in the inbox, its part kept (0700)');
  now += 7 * 86400 + 1;
  const late = await cb.inbox();
  ok(late.dropped.file_incomplete === 1 && late.events.some((e) => e.check === 'file_incomplete' && e.detail.includes('half.bin')) && readdirSync(parts).length === 0,
    `past the retention: its parts go, said once (${JSON.stringify(late.dropped)})`);
  // Queued, then the contact forgotten: the spool goes with the outbox.
  await refused(() => offline(alice).sendFile('bob', qSrc));
  const before = spooled().length;
  await ca.forget(bob.did);
  ok(before === 4 && spooled().length === 0, `queued for a contact then forgotten: the spool is removed (${before} → ${spooled().length})`);
  for (const c of [ca, cb]) await c.stop();
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
report();
console.log(`ALL PASS (${count})`);
