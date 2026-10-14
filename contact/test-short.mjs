// SPDX-License-Identifier: MIT
// Short invite codes (short.mjs, contract sigelo-park/0): fixtures/short-code-v0.json against
// short.mjs, gen-short.mjs --check, the word list's hash; then, with the relay checkout beside
// contact/ (SIGELO_RELAY_DIR, else ../relay), the whole flow on a loopback relay: invite → short
// code → accept by the short code → paired → the same four words on both sides; one use; a wrong
// code; an expired one.
//   node contact/test-short.mjs   → ALL PASS (n)
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keygen } from 'sigelo';
import { BIP39_SHA256, WORDS } from './bip39-english.mjs';
import { ALPHABET, SHORT_TTL, codeHash, fingerprint, formatShort, isShort, makeShort, normaliseShort } from './short.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const checkOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.check ?? `exception ${e.constructor.name}: ${e.message}`; } };
const report = () => {
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) { console.log(`${fails.length} FAILED, ${count - fails.length} passed`); process.exit(1); }
};

// ================================================================ the fixture
{
  const gen = spawnSync(process.execPath, [join(HERE, 'gen-short.mjs'), '--check'], { encoding: 'utf8' });
  ok(gen.status === 0, `gen-short.mjs --check: ${(gen.stderr || gen.stdout).trim()}`);
  const F = JSON.parse(readFileSync(join(HERE, 'fixtures', 'short-code-v0.json'), 'utf8'));
  ok(WORDS.length === 2048 && createHash('sha256').update(WORDS.join('\n') + '\n').digest('hex') === BIP39_SHA256 && Object.isFrozen(WORDS), 'the BIP-39 English list: 2048 words, its published SHA-256, frozen');
  ok(F.alphabet === ALPHABET && !/[ILOU]/.test(ALPHABET) && new Set(ALPHABET).size === 32, 'Crockford base32: 32 digits, no I, L, O, U');
  for (const c of F.codes) {
    const norm = makeShort(() => new Uint8Array(Buffer.from(c.rng, 'hex')));
    ok(norm === c.normalised && formatShort(norm) === c.code, `code ${c.label}: ${c.rng} → ${formatShort(norm)}, expected ${c.code}`);
    ok(codeHash(c.code) === c.code_hash && codeHash(c.normalised) === c.code_hash && codeHash(c.code.toLowerCase()) === c.code_hash, `code ${c.label}: code_hash, shown, bare and lowercase alike`);
    ok(isShort(c.code), `code ${c.label}: recognised as a short code`);
  }
  for (const n of F.normalise) {
    const got = checkOf(() => normaliseShort(n.input));
    if (n.error) ok(got === n.error && !isShort(n.input), `normalise ${n.case}: ${got}, expected ${n.error}`);
    else ok(normaliseShort(n.input) === n.normalised && isShort(n.input), `normalise ${n.case}: ${JSON.stringify(n.input)} → ${checkOf(() => normaliseShort(n.input)) === 'accepted' ? normaliseShort(n.input) : got}, expected ${n.normalised}`);
  }
  for (const f of F.fingerprints) ok(fingerprint(f.pair) === f.words, `fingerprint ${f.case}: ${fingerprint(f.pair)}, expected ${f.words}`);
  ok(checkOf(() => fingerprint('A2CF45BD3D6AEE6D6E3F14FFD2751924')) === 'pair' && checkOf(() => fingerprint('ab')) === 'pair', 'fingerprint: anything but 32 lowercase hex digits is refused (pair)');
  ok(checkOf(() => normaliseShort(undefined)) === 'short_code' && checkOf(() => normaliseShort('0'.repeat(65))) === 'short_code', 'normalise: no string, or past 64 characters, is short_code');
  ok(checkOf(() => makeShort(() => new Uint8Array(4))) === 'short_code', 'makeShort: a random source that gives fewer than 5 bytes is refused');
  // The real source: 1,000 codes, all well formed, no repeat (40 bits).
  const seen = new Set();
  for (let i = 0; i < 1000; i++) seen.add(makeShort());
  ok(seen.size === 1000 && [...seen].every((s) => /^[0-9A-HJKMNP-TV-Z]{8}$/.test(s)), 'makeShort: 1,000 codes from the CSPRNG, all 8 Crockford digits, no repeat');
  ok(SHORT_TTL === 600, 'a short code lives 10 minutes');
}

const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(HERE, '..', 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs'))) {
  report();
  console.log(`ALL PASS (${count}): the fixture part; SKIP the flow, no relay checkout beside contact/: set SIGELO_RELAY_DIR`);
  process.exit(0);
}

// ================================================================ the flow, on a loopback relay
const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
const { Carrier, pathsFor } = await import('./carrier.mjs');
setTimeout(() => { console.log(`FAIL the run did not finish in 120 s (${count} checks so far)`); process.exit(1); }, 120000).unref();

const HOST = 'relay.test', CREATED = '2026-10-01T00:00:00Z';
const dir = mkdtempSync(join(tmpdir(), 'sigelo-short-'));
let now = Date.parse('2026-10-14T12:00:00Z') / 1000;
const lines = [];
const relay = await startRelay({ host: HOST, db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, clock: () => now, diskUsed: () => 0.1,
  log: (l) => lines.push(l), policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const endpoints = { [HOST]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
const seed = (l) => new Uint8Array(createHash('sha256').update(`sigelo-short-test/0 ${l}`).digest());
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
try {
  const alice = agent('alice'), bob = agent('bob'), carol = agent('carol');
  const ca = make(alice), cb = make(bob), cc = make(carol);
  // alice: a short code by default, the long code beside it.
  const inv = await ca.invite({ name: 'bob', short: true });
  ok(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/.test(inv.short ?? '') && /^sgl1/.test(inv.code) && inv.short_exp === now + SHORT_TTL, 'invite: a short code K7F3-Q9ZP, 10 minutes, beside the long one', JSON.stringify(inv));
  ok(!lines.some((l) => l.includes(inv.short) || l.includes(normaliseShort(inv.short)) || l.includes(codeHash(inv.short)) || l.includes(inv.code)), 'the relay log holds neither the code, nor its hash, nor the long code');
  // bob types it as heard: lowercase, no dash, an O for a 0 where there is one.
  const typed = inv.short.toLowerCase().replace('-', ' ').replace(/0/g, 'o');
  await ca.start();
  const r = await cb.accept(typed, { name: 'alice', wait: 20 });
  ok(r.status === 'connected' && r.contact?.did === alice.did, `accept by the short code, typed ${JSON.stringify(typed)}: connected to alice`);
  ok(/^[a-z]+ [a-z]+ [a-z]+ [a-z]+$/.test(r.contact?.fingerprint ?? '') && r.contact.fingerprint.split(' ').every((w) => WORDS.includes(w)), 'accept returns four BIP-39 words', JSON.stringify(r));
  await ca.stop();
  const wordsOf = (c, did) => c.contacts().contacts.find((x) => x.did === did)?.fingerprint;
  ok(wordsOf(ca, bob.did) === r.contact.fingerprint && wordsOf(cb, alice.did) === r.contact.fingerprint, 'contacts: both sides show the same four words');
  const paired = events.alice.find((e) => e.type === 'paired');
  ok(paired?.fingerprint === r.contact.fingerprint, 'the inviter\'s paired event carries the same four words');
  // One use: carol tries the same code.
  ok(await refused(() => cc.accept(inv.short, { wait: 1 })) === 'park_unknown', 'the same short code a second time: park_unknown');
  // A code nobody parked.
  ok(await refused(() => cc.accept(formatShort(makeShort()), { wait: 1 })) === 'park_unknown', 'a code nobody parked: park_unknown');
  // Expiry: parked, then 10 minutes and a second pass.
  const late = await ca.invite({ name: 'carol', short: true });
  now += SHORT_TTL;
  ok(await refused(() => cc.accept(late.short, { wait: 1 })) === 'park_unknown', 'a short code after its 10 minutes: park_unknown');
  // An inviter whose clock runs a minute ahead of the relay's still parks (relay/park.mjs PARK_SKEW).
  const ahead = new Carrier({ identity: () => ({ secret: alice.secret, bundle: alice.bundle }), ...pathsFor(join(dir, 'alice.local.json')), relay: HOST, endpoints,
    clock: () => now + 60, keep: true, backoff: [100, 400], retentionDays: 7 });
  const fast = await refused(() => ahead.invite({ name: 'carol', short: true }));
  ok(fast === 'accepted', `an inviter's clock a minute ahead of the relay's: the short code parks (${fast})`);
  await ahead.stop();
  // --long: no parking at all.
  const long = await ca.invite({ name: 'carol', short: false });
  ok(long.short === undefined && /^sgl1/.test(long.code), 'invite without a short code (--long): the long code only');
  // A long code is still accepted as before.
  await ca.start();
  const rl = await cc.accept(long.code, { name: 'alice', wait: 20 });
  await ca.stop();
  ok(rl.status === 'connected' && rl.contact.fingerprint === wordsOf(ca, carol.did), 'accept by the long code: connected, the same four words on both sides');
  ok(rl.contact.fingerprint !== r.contact.fingerprint, 'another pairing, other words');
  // The database holds no short code and no long code (memory only).
  const dump = readFileSync(join(dir, 'relay.db')).toString('latin1') + (existsSync(join(dir, 'relay.db-wal')) ? readFileSync(join(dir, 'relay.db-wal')).toString('latin1') : '');
  ok(![inv.short, normaliseShort(inv.short), codeHash(inv.short), inv.code, late.code].some((s) => dump.includes(s)), 'the relay\'s database files hold no code, no hash, no parked invite');
  for (const c of [cb, cc]) await c.stop();
} finally {
  await relay.close();
  rmSync(dir, { recursive: true, force: true });
}
report();
console.log(`ALL PASS (${count})`);
