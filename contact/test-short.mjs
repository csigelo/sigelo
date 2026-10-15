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
import { makeInvite } from './invite.mjs';
import { ALPHABET, GIFT_V, SHORT_TTL, codeHash, codeKind, fingerprint, formatGift, formatShort, giftHash, isShort, makeShort, normaliseGift, normaliseShort } from './short.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let count = 0;
const fails = [];
const ok = (cond, what) => { count++; if (!cond) fails.push(what); };
const messageOf = (f) => { try { f(); return 'accepted'; } catch (e) { return e.message; } };
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

// ================================================================ refusals a person can act on
// Short or long is decided on the shape, before either parser runs; each refusal says how the code
// was read, names the character at fault, and says what to do.
{
  for (const [t, kind] of [['K7F3-Q9ZP', 'short'], ['k7f3 q9z', 'short'], ['K7F3-Q9ZP.', 'short'], ['', 'short'], ['K7F3-Q9ZP-ABC', 'short'], ['K7F3Q9ZPABCDE', 'long'], ['sgl1abc', 'long'], ['SGL1ABC', 'long'], ['x'.repeat(126), 'long']]) {
    ok(codeKind(t) === kind, `codeKind ${JSON.stringify(t)}: ${codeKind(t)}, expected ${kind}`);
  }
  const u = messageOf(() => normaliseShort('K7F3-U9ZP'));
  ok(u.startsWith('short_code: "K7F3-U9ZP" read as a short code') && u.includes('character 5 "U" is not in the alphabet; a short code uses 0-9 and A-Z without I, L, O, U'), `a U: its position named (${u})`);
  const seven = messageOf(() => normaliseShort('K7F3-Q9Z'));
  ok(seven.includes('7 characters, a short code has 8 (like K7F3-Q9ZP): 1 missing'), `7 characters: said (${seven})`);
  const nine = messageOf(() => normaliseShort('K7F3 Q9ZPX'));
  ok(nine.includes('9 characters, a short code has 8 (like K7F3-Q9ZP): 1 too many'), `9 characters: said (${nine})`);
  const dot = messageOf(() => normaliseShort('k7f3-q9zp.'));
  ok(dot.includes('character 9 "." is not in the alphabet'), `a leftover character: its position named (${dot})`);
  const { readCode } = await import('./carrier.mjs');
  const t0 = Date.parse('2026-10-14T12:00:00Z') / 1000, D = keygen({ seed: new Uint8Array(32), recovery: 'sha256:' + '0'.repeat(64) }).did;
  const long = messageOf(() => readCode('hello-world-this-is-long', t0));
  ok(long.startsWith('code_checksum: read as a long code (it starts sgl1, or has more than 12 characters') && long.includes('paste the whole code'), `a long input without sgl1: read as a long code, said (${long})`);
  const code = makeInvite({ did: D, relay: 'relay.test', now: t0, ttl: 600 }).text;
  const typo = messageOf(() => readCode(code.slice(0, 40) + (code[40] === 'A' ? 'B' : 'A') + code.slice(41), t0));
  ok(typo.startsWith('code_checksum: read as a long code') && typo.includes('checksum does not match') && typo.includes('do not retype it'), `a long code with a typo: the checksum, and what to do (${typo})`);
  const bad = messageOf(() => readCode(code.slice(0, 40) + '0' + code.slice(41), t0));
  ok(bad.includes('character 41 "0" is not in a long code'), `a long code with a 0: its position named (${bad})`);
  const late = messageOf(() => readCode(code, t0 + 3600));
  ok(late.startsWith('code_expired: it expired at 2026-10-14T12:10:00Z, 50 minutes ago by this machine\'s clock') && late.includes('date -u'), `an expired code: when, by which clock, what to do (${late})`);
  const skew = messageOf(() => readCode(makeInvite({ did: D, relay: 'relay.test', now: t0, ttl: 7 * 86400 }).text, t0 - 3 * 86400));
  ok(skew.startsWith('code_ttl:') && skew.includes('this clock is behind (date -u)'), `a code living past 7 days by this clock: clock skew said (${skew})`);
  const parked = messageOf(() => readCode('sgl1abc', t0, 'parked'));
  ok(parked.startsWith('code_length: the long code the relay holds for this short code does not parse'), `a parked code that does not parse: blamed on what the relay holds (${parked})`);
}

// ================================================================ gift codes (sigelo-gift/0)
// A short code's 8 characters, alphabet and folding, shown PRO-K7F3-Q9ZP; hashed under a label of
// its own, never the park label.
{
  ok(GIFT_V === 'sigelo-gift/0' && formatGift('K7F3Q9ZP') === 'PRO-K7F3-Q9ZP', 'a gift code is shown PRO-K7F3-Q9ZP; its label is sigelo-gift/0');
  const forms = ['PRO-K7F3-Q9ZP', 'pro-k7f3-q9zp', 'PROK7F3Q9ZP', 'pro k7f3 q9zp', 'PR0-K7F3-Q9ZP', 'K7F3-Q9ZP', 'k7f3q9zp', 'PRO\u2013K7F3\u2013Q9ZP', 'PRO-K7F3-Q9Z0'.replace('0', 'P')];
  ok(forms.every((f) => normaliseGift(f) === 'K7F3Q9ZP'), `normaliseGift: any case, with or without dashes, spaces or the PRO prefix (its O typed 0 too) → K7F3Q9ZP`);
  ok(normaliseGift('PRO-K7F3-Q9Z0') === 'K7F3Q9Z0' && normaliseGift('PRO-1L0I-OOOO') === '11010000', 'normaliseGift folds I and L to 1, O to 0, as a short code does');
  const want = createHash('sha256').update('sigelo-gift/0K7F3Q9ZP').digest('hex');
  ok(giftHash('PRO-K7F3-Q9ZP') === want && giftHash('k7f3 q9zp') === want && giftHash('PRO-K7F3-Q9ZP') !== codeHash('K7F3-Q9ZP'),
    `giftHash = hex SHA-256("sigelo-gift/0" ‖ the 8 characters) (${want.slice(0, 16)}…), never the park hash of the same characters`);
  for (const [t, why] of [['PRO-AB12-U9ZP', 'character 5 "U" is not in the alphabet'], ['PRO-AB12-CD3', '7 characters, a gift code has 8 after PRO: 1 missing'], ['PRO-AB12-CD34X', '1 too many'], ['sgl1abc', 'not a gift code'], [undefined, 'not a gift code']]) {
    const m = messageOf(() => normaliseGift(t));
    ok(checkOf(() => normaliseGift(t)) === 'gift_code' && m.includes(why) && (t === undefined || !m.includes(t)), `normaliseGift ${JSON.stringify(t)}: gift_code, ${why}, the input not quoted (${m})`);
  }
  // makeShort makes gift codes too (commercial/gift-codes.mjs): any of its codes reads back.
  const g = makeShort();
  ok(normaliseGift(formatGift(g)) === g, 'a code from makeShort, shown as a gift code, reads back');
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
const failure = async (f) => { try { await f(); return { check: 'accepted', message: 'accepted' }; } catch (e) { return e; } };
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
  const nobody = formatShort(makeShort());
  ok(await refused(() => cc.accept(nobody, { wait: 1 })) === 'park_unknown', 'a code nobody parked: park_unknown');
  const pu = await failure(() => cc.accept(nobody.toLowerCase(), { wait: 1 }));
  ok(pu.check === 'park_unknown' && pu.message.includes(`short code ${nobody}: no invite waits under it at ${HOST}`) && pu.message.includes('expired (a short code lives 10 minutes), was used already (once only), or is mistyped; ask the inviter for a new one')
    && pu.message.includes('another relay') && pu.http?.status === 404, `park_unknown: the code, the relay, the three reasons, the next step, another relay; the answer kept for SIGELO_DEBUG (${pu.message})`);
  // A mistyped short code is refused before anything connects, as a short code.
  const mt = await failure(() => cc.accept('K7F3-Q9Z', { wait: 1 }));
  ok(mt.check === 'short_code' && mt.message.includes('7 characters, a short code has 8'), `carrier.accept of 7 characters: short_code, not code_checksum (${mt.message})`);
  // Expiry: parked, then 10 minutes and a second pass.
  const late = await ca.invite({ name: 'carol', short: true });
  now += SHORT_TTL;
  ok(await refused(() => cc.accept(late.short, { wait: 1 })) === 'park_unknown', 'a short code after its 10 minutes: park_unknown');
  // An inviter whose clock runs a minute ahead of the relay's still parks (relay/park.mjs PARK_SKEW).
  const ahead = new Carrier({ identity: () => ({ secret: alice.secret, bundle: alice.bundle }), ...pathsFor(join(dir, 'alice.local.json')), relay: HOST, endpoints,
    clock: () => now + 60, keep: true, backoff: [100, 400], retentionDays: 7 });
  let fastInv = {}, fast = 'accepted';
  try { fastInv = await ahead.invite({ name: 'carol', short: true }); } catch (e) { fast = e.check ?? `exception ${e.message}`; }
  ok(fast === 'accepted', `an inviter's clock a minute ahead of the relay's: the short code parks (${fast})`);
  ok(fastInv.short_exp === now + SHORT_TTL, `short_exp is the relay's exp (${now + SHORT_TTL}), not the fast clock's (${now + 60 + SHORT_TTL}): ${fastInv.short_exp}`);
  await ahead.stop();
  // An inviter's clock an hour ahead: the relay refuses the parking, and the refusal says the clock.
  const far = new Carrier({ identity: () => ({ secret: alice.secret, bundle: alice.bundle }), ...pathsFor(join(dir, 'alice.local.json')), relay: HOST, endpoints,
    clock: () => now + 3600, keep: true, backoff: [100, 400], retentionDays: 7 });
  const fa = await failure(() => far.invite({ name: 'carol', short: true }));
  ok(fa.check === 'park' && fa.message.includes('this machine\'s clock may be off (date -u)'), `an inviter's clock an hour ahead: park refused, the clock named (${fa.message})`);
  await far.stop();
  // A short code is spent once fetched: a refusal after that carries the long code it stood for.
  // erin's clock is an hour ahead, past the long code's two minutes: code_expired after the fetch.
  const erin = agent('erin'), brief = await ca.invite({ name: 'erin', ttl: 120, short: true });
  const skewed = new Carrier({ identity: () => ({ secret: erin.secret, bundle: erin.bundle }), ...pathsFor(join(dir, 'erin.local.json')), relay: HOST, endpoints,
    clock: () => now + 3600, keep: true, backoff: [100, 400], retentionDays: 7 });
  const kept = await failure(() => skewed.accept(brief.short, { wait: 1 }));
  ok(kept.check === 'code_expired' && kept.long === brief.code && kept.message.includes(`its long code: ${brief.code} (keep this; accept it with the long code)`),
    `refused after the short code was fetched: the long code in the refusal and as .long (${kept.message})`);
  await skewed.stop();
  const ce = make(erin);
  await ca.start();
  const kr = await ce.accept(kept.long, { name: 'alice', wait: 20 });
  await ca.stop();
  ok(kr.status === 'connected', `the kept long code, accepted with a right clock: connected (${kr.status})`);
  await ce.stop();
  // --long: no parking at all.
  const long = await ca.invite({ name: 'carol', short: false });
  ok(long.short === undefined && /^sgl1/.test(long.code), 'invite without a short code (--long): the long code only');
  // A long code is still accepted as before.
  await ca.start();
  const rl = await cc.accept(long.code, { name: 'alice', wait: 20 });
  await ca.stop();
  ok(rl.status === 'connected' && rl.contact.fingerprint === wordsOf(ca, carol.did), 'accept by the long code: connected, the same four words on both sides');
  ok(rl.contact.fingerprint !== r.contact.fingerprint, 'another pairing, other words');
  // The same long code a second time, by another agent: answered already, said so.
  const dave = agent('dave'), cd = make(dave);
  const again = await failure(() => cd.accept(long.code, { name: 'alice', wait: 3 }));
  ok(again.check === 'mailbox_taken' && again.message.includes('this code was answered already, by another agent (a code works once): ask the inviter for a new one'), `a long code answered before: said so (${again.message})`);
  await cd.stop();
  // The relay's brake on lookups: rate, and when to try again.
  let rate = null;
  for (let i = 0; i < 30 && rate === null; i++) { const e = await failure(() => cd.unpark(formatShort(makeShort()))); if (e.check === 'rate') rate = e; }
  ok(rate !== null && rate.message.includes(`wait ${600 - (now % 600)} s, or ask for the long code`) && rate.http?.status === 429, `lookups past the relay's brake: rate, and the relay's Retry-After as when to try again (${rate?.message})`);
  // An answer that outlives its code, the inviter offline throughout: accept said waiting; then
  // contacts and the next inbox say the pairing failed (code_expired), once, in one line.
  const frank = agent('frank'), cf = make(frank), brief2 = await ca.invite({ name: 'frank', ttl: 120, short: false });
  const fw = await cf.accept(brief2.code, { name: 'alice', wait: 1 });
  ok(fw.status === 'waiting' && cf.contacts().answers.length === 1 && cf.contacts().failed.length === 0, `accept with the inviter offline: waiting, one answer (${fw.status})`);
  now += 121;
  const lc = cf.contacts(), lf = lc.failed[0];
  ok(lc.answers.length === 0 && lc.failed.length === 1 && lf.code === 'code_expired' && lf.name === 'alice' && lf.did === alice.did
    && lf.detail === `the code from alice expired at ${new Date(brief2.exp * 1000).toISOString().replace('.000', '')} before the inviter's agent replied: ask the inviter for a new code`,
    `contacts after the code's expiry: the answer gone, failed lists it (code_expired, the time, what to do): ${JSON.stringify(lc.failed)}`);
  ok(events.frank.filter((e) => e.type === 'pairing_failed' && e.code === 'code_expired').length === 1, 'onEvent: one pairing_failed code_expired');
  const lb = await cf.inbox({ wait: 0 });
  ok(lb.events.filter((e) => e.type === 'pairing_failed' && e.code === 'code_expired' && e.did === alice.did).length === 1, `the next inbox reports it once (${JSON.stringify(lb.events)})`);
  ok(cf.contacts().failed.length === 0 && (await cf.inbox({ wait: 0 })).events.every((e) => e.type !== 'pairing_failed'), 'and then neither contacts nor inbox again');
  await cf.stop();
  // The code expires during accept --wait: refused code_expired then, not "waiting" at the wait's end;
  // onEvent said pairing_failed once, the next inbox not again.
  const gina = agent('gina'), cg = make(gina), brief3 = await ca.invite({ name: 'gina', ttl: 120, short: false });
  const tick = setTimeout(() => { now += 121; }, 1500), t1 = Date.now();
  const gw = await failure(() => cg.accept(brief3.code, { name: 'alice', wait: 60 }));
  clearTimeout(tick);
  const gAt = new Date(brief3.exp * 1000).toISOString().replace('.000', '');
  ok(gw.check === 'code_expired' && gw.lapsed === true && gw.message === `code_expired: the code from alice expired at ${gAt} before the inviter's agent replied: ask the inviter for a new code`
    && Date.now() - t1 < 30000, `the code expired during accept --wait 60: code_expired at once, the time, what to do (${gw.message}, ${Date.now() - t1} ms)`);
  ok(events.gina.filter((e) => e.type === 'pairing_failed' && e.code === 'code_expired').length === 1 && cg.contacts().answers.length === 0 && cg.contacts().failed.length === 0
    && (await cg.inbox({ wait: 0 })).events.every((e) => e.type !== 'pairing_failed'), 'onEvent: one pairing_failed; contacts and the next inbox do not say it again');
  // inbox --wait ends on a pairing that failed, rather than at its timeout.
  const brief4 = await ca.invite({ name: 'gina', ttl: 120, short: false });
  ok((await cg.accept(brief4.code, { name: 'alice', wait: 1 })).status === 'waiting', 'accept, the inviter offline: waiting');
  const tick2 = setTimeout(() => { now += 121; }, 1500), t2 = Date.now();
  const gb = await cg.inbox({ wait: 60 });
  clearTimeout(tick2);
  ok(gb.events.filter((e) => e.type === 'pairing_failed' && e.code === 'code_expired').length === 1 && Date.now() - t2 < 30000,
    `inbox --wait 60 ends when the answer expires, and says so (${JSON.stringify(gb.events)}, ${Date.now() - t2} ms)`);
  await cg.stop();
  // A gift code (relay/gifts.mjs), redeemed by carol as the operator: the relay gets its hash only.
  const gift = makeShort(), shown = formatGift(gift);
  relay.db.raw.prepare('INSERT INTO gift_campaigns (campaign, issued) VALUES (?, 1)').run('test');
  relay.db.raw.prepare('INSERT INTO gifts (code_hash, campaign, months, expires) VALUES (?, ?, ?, ?)').run(giftHash(shown), 'test', 1, Math.floor(now / 86400) * 86400 + 30 * 86400);
  const gr = await cc.redeemGift(shown.toLowerCase());
  ok(gr.months === 1 && gr.exp > now + 27 * 86400 && gr.exp % 86400 === 0, `redeemGift: a fresh identity (proof of work in the same login) redeems 1 month, Pro to the start of a UTC day (${JSON.stringify(gr)})`);
  const g2 = await failure(() => cc.redeemGift(shown));
  ok(g2.check === 'gift' && !g2.message.includes(gift) && !g2.message.includes(giftHash(shown)), `redeemGift twice: refused "gift", the code not quoted (${g2.message})`);
  const g3 = await failure(() => cc.redeemGift('PRO-K7F3-U9ZP'));
  ok(g3.check === 'gift_code', 'redeemGift of a malformed code: gift_code, refused before any login');
  ok(!lines.some((l) => l.includes(gift) || l.includes(giftHash(shown))), 'the relay log holds neither the gift code nor its hash');
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
