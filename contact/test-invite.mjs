// SPDX-License-Identifier: MIT
// Runs fixtures/invite-v0.json against invite.mjs and store.mjs, then gen-invite.mjs --check.
//   node contact/test-invite.mjs   -> "ALL PASS (n)", or one FAIL line per failing check and exit 1
// Stores live in a fresh temporary directory, removed at the end.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@noble/hashes/utils.js';
import { canonicalize } from 'sigelo';
import { MsgError } from './kdf.mjs';
import { SKEW, TTL_MAX, answerId, buildAnswer, buildReply, checkAnswer, checkReply, hex, inviteKeys, makeInvite, parseInvite } from './invite.mjs';
import { Contacts } from './store.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const F = JSON.parse(readFileSync(join(HERE, 'fixtures', 'invite-v0.json'), 'utf8'));
let pass = 0;
const fails = [];
const ok = (cond, what) => { if (cond) pass++; else fails.push(what); };
const same = (a, b) => canonicalize(a) === canonicalize(b);
// Run f; the step either expects a value (compared as JCS) or an error by check name.
function run(label, step, f) {
  let got, err;
  try { got = f(); } catch (e) { err = e; }
  if (step.error !== undefined) ok(err?.check === step.error, `${label}: expected ${step.error}, got ${err ? `${err.check ?? 'exception'} (${err.message})` : 'success'}`);
  else if (err) fails.push(`${label}: ${err.message}`);
  else ok(step.expect === undefined || same(got, step.expect), `${label}: got ${JSON.stringify(got)}`);
  return got;
}
const project = (c) => c && { name: c.name, did: c.did, current_did: c.current_did, current_key: c.current_key, revoked: c.revoked, relay: c.relay, pair_key: c.pair_key };
const made = (c) => makeInvite({ did: c.did, relay: c.relay, now: c.now, ttl: c.ttl, secret: hexToBytes(c.secret) });

// Codes: exact bytes and text, round trip, what the secret yields.
for (const c of F.codes) {
  run(`code ${c.case}`, { expect: { bytes: c.bytes, length: c.length, text: c.text, nonce: c.nonce } }, () => {
    const m = made(c);
    return { bytes: hex(m.bytes), length: m.bytes.length, text: m.text, nonce: m.nonce };
  });
  run(`code ${c.case} keys`, { expect: { answer_topic: c.answer_topic, reply_topic: c.reply_topic, key: c.key } }, () => {
    const k = inviteKeys(hexToBytes(c.secret));
    return { answer_topic: k.answer_topic, reply_topic: k.reply_topic, key: hex(k.key) };
  });
}
for (const p of F.parse) {
  run(`parse ${p.case}`, p, () => { const r = parseInvite(p.text, p.now); return { did: r.did, secret: hex(r.secret), exp: r.exp, relay: r.relay }; });
}

const dir = mkdtempSync(join(tmpdir(), 'sigelo-invite-'));
try {
  const stores = Object.fromEntries(Object.entries(F.stores).map(([k, l]) => [k, new Contacts(join(dir, `${k}.json`), F.dids[l])]));
  const identity = (l) => ({ secret: hexToBytes(F.seeds[l]), genesis: F.geneses[l] });
  const agree = (h) => () => hexToBytes(h);
  F.steps.forEach((s, i) => {
    const store = stores[s.store], label = `step ${i} ${s.case} ${s.op}`;
    if (s.op === 'invite') {
      const c = F.codes.find((x) => x.case === s.code);
      run(label, s, () => { const m = made(c); store.addInvite(m, s.name, s.now, s.peer); return undefined; });
    } else if (s.op === 'answer') {
      run(label, s, () => {
        const code = parseInvite(s.code, s.now);
        const a = buildAnswer({ code, identity: identity(s.identity), bundle: F.bundles[s.bundle], kem_pk: s.kem_pk, prekeys: s.prekeys });
        store.addAccept(code, answerId(a), s.name, s.now, s.kem_sk);
        return { answer: a, answer_id: answerId(a) };
      });
    } else if (s.op === 'check_answer') run(label, s, () => checkAnswer(s.answer, store, s.now, agree(s.shared)));
    else if (s.op === 'reply') run(label, s, () => buildReply({ answer_id: s.answer_id, identity: identity(s.identity), bundle: F.bundles[s.bundle], kem_ct: s.kem_ct, prekeys: s.prekeys }));
    else if (s.op === 'check_reply') {
      run(label, s, () => checkReply(s.reply, store, s.now, (ct, sk) => {
        if (sk !== s.kem_sk) throw new Error(`agree() was handed ${JSON.stringify(sk)}, not the kem_sk given to addAccept`);
        return agree(s.shared)();
      }));
    }
    else if (s.op === 'lookup') run(label, s, () => project(store.lookup(s.did)));
    else if (s.op === 'revoke') run(label, s, () => project(store.revoke(s.did)));
    else fails.push(`${label}: unknown op`);
  });

  // Beyond the steps: properties of the store itself.
  const pairStep = (st) => F.steps.find((s) => s.case === 'pair' && s.op === 'lookup' && s.store === st).expect.pair_key;
  ok(pairStep('A') === pairStep('B') && /^[0-9a-f]{64}$/.test(pairStep('A')), 'both sides of one pairing hold the same K');
  ok((statSync(join(dir, 'A.json')).mode & 0o777) === 0o600, 'the store file is 0600: it holds secrets and pairing keys');
  run('a store belongs to one identity', { error: 'store' }, () => new Contacts(join(dir, 'A.json'), F.dids.B0));
  // Re-read on every operation: a second process takes an invite, the first then cannot.
  const c = F.codes.find((x) => x.case === 'pair'), x1 = new Contacts(join(dir, 'X.json'), F.dids.A0), x2 = new Contacts(join(dir, 'X.json'), F.dids.A0);
  x1.addInvite(made(c), 'bob', c.now);
  ok(x2.take('invites', c.nonce, c.now) !== null && x1.take('invites', c.nonce, c.now) === null, 'single use holds across two store objects on one file');
  x1.addInvite(made(c), 'bob', c.now);
  x2.cancelInvite(c.nonce);
  ok(x1.take('invites', c.nonce, c.now) === null, 'a cancelled invite cannot be answered');
  run('the inviter refuses a code longer than 7 days', { error: 'ttl' }, () => x1.addInvite({ ...made(c), exp: c.now + TTL_MAX + 1 }, 'bob', c.now));
  run('makeInvite refuses a relay of 64 characters', { error: 'code_relay' }, () => makeInvite({ did: c.did, relay: `${'a'.repeat(30)}.${'b'.repeat(33)}`, now: c.now }));
  run('makeInvite refuses a DID that is not did:sigelo', { error: 'did' }, () => makeInvite({ did: 'did:example:alice', relay: c.relay, now: c.now }));
  run('makeInvite refuses a ttl over 7 days', { error: 'ttl' }, () => makeInvite({ did: c.did, relay: c.relay, now: c.now, ttl: TTL_MAX + 1 }));

  // `now` is checked at every entry point: NaN, undefined or a string would make expiry checks fail open.
  const pairAnswer = F.steps.find((s) => s.case === 'pair' && s.op === 'check_answer').answer;
  const pairReply = F.steps.find((s) => s.case === 'pair' && s.op === 'check_reply').reply;
  x1.addInvite(made(c), 'bob', c.now);
  run('checkAnswer refuses now = undefined', { error: 'now' }, () => checkAnswer(pairAnswer, x1, undefined, () => new Uint8Array(32)));
  run('checkReply refuses now = "x"', { error: 'now' }, () => checkReply(pairReply, x1, 'x', () => new Uint8Array(32)));
  run('addInvite refuses now = NaN', { error: 'now' }, () => x1.addInvite(made(c), 'bob', NaN));
  run('take refuses now = NaN', { error: 'now' }, () => x1.take('invites', c.nonce, NaN));
  ok(x1.take('invites', c.nonce, c.now) !== null, 'a refused now consumes nothing');

  // A message with no canonical form: Bob is told by name, Alice refuses it as `card`, and the
  // invite stays (card runs before the lookup, as in sigelo-pair).
  const a0 = F.bundles.A0, floaty = { ...a0, attestations: [{ ...a0.attestations[0], body: { ...a0.attestations[0].body, claims: { tasks: 1.5 } } }] };
  run('buildAnswer names a bundle item without canonical form', { error: 'bundle' }, () => buildAnswer({ code: parseInvite(c.text, c.now), identity: identity('B0'), bundle: floaty, kem_pk: 'k', prekeys: {} }));
  x1.addInvite(made(c), 'bob', c.now);
  run('checkAnswer refuses an answer without canonical form as card', { error: 'card' }, () => checkAnswer({ ...pairAnswer, prekeys: { n: 1.5 } }, x1, c.now + 20, () => new Uint8Array(32)));
  ok(x1.take('invites', c.nonce, c.now) !== null, 'a card failure leaves the invite in place');

  // The owner's own chain is never a contact, even behind a throwaway genesis in front of it.
  for (const [b, who] of [['A0', 'A0'], ['A2_prefixed', 'A2']]) {
    const code = made(c);
    x1.addInvite(code, 'me', c.now);
    const mine = buildAnswer({ code, identity: identity(who), bundle: F.bundles[b], kem_pk: 'k', prekeys: {} });
    run(`checkAnswer refuses the owner's own chain (${b})`, { error: 'self' }, () => checkAnswer(mine, x1, c.now + 20, () => new Uint8Array(32)));
  }

  // Re-key codes: pinned to a known, live contact; a new contact's code names no peer.
  run('a re-key code needs the contact it is for', { error: 'not_contact' }, () => x1.addInvite(made(c), null, c.now));
  run('a new contact\'s code names no peer', { error: 'name' }, () => x1.addInvite(made(c), 'x', c.now, F.dids.B0));
  run('no re-key code for a revoked contact', { error: 'revoked' }, () => stores.A.addInvite(made(c), null, c.now, F.dids.B0));

  // Bob's side caps a code at 7 days plus SKEW (parseInvite does too, `code_ttl`), and expired
  // entries go, one-time secret and kem_sk with them, at the next add or take.
  const y = new Contacts(join(dir, 'Y.json'), F.dids.B0), code = parseInvite(c.text, c.now);
  run('addAccept refuses a code beyond 7 days and SKEW', { error: 'ttl' }, () => y.addAccept({ ...code, exp: c.now + TTL_MAX + SKEW + 1 }, 'zA', 'alice', c.now, 'kem_sk:long'));
  run('addAccept takes a code of 7 days and SKEW', {}, () => y.addAccept({ ...code, exp: c.now + TTL_MAX + SKEW }, 'zB', 'alice', c.now, 'kem_sk:edge'));
  const short = makeInvite({ did: c.did, relay: c.relay, now: c.now, ttl: 60, secret: new Uint8Array(32).fill(7) });
  y.addAccept(short, 'zC', 'alice', c.now, 'kem_sk:short');
  y.take('accepts', 'zNone', c.now + 60);
  const file = readFileSync(join(dir, 'Y.json'), 'utf8');
  ok(!file.includes('kem_sk:short') && !file.includes(hex(short.secret)) && file.includes('kem_sk:edge'), 'an expired answer, its secret and kem_sk go at the next take');

  // Two records sharing a DID (a file written by something else): lookup refuses to pick one.
  const twin = (d, chain) => ({ name: d, did: d, current_did: F.dids.B0, current_key: 'z', revoked: d === F.dids.B0, chain, rotations: [], relay: 'r', pair_key: null });
  writeFileSync(join(dir, 'T.json'), JSON.stringify({ v: 'sigelo-invite/0', self: F.dids.A0, invites: {}, accepts: {}, contacts: { [F.dids.B0]: twin(F.dids.B0, [F.dids.B0]), [F.dids.XB]: twin(F.dids.XB, [F.dids.XB, F.dids.B0]) } }));
  run('lookup refuses two records holding one DID', { error: 'original_did' }, () => new Contacts(join(dir, 'T.json'), F.dids.A0).lookup(F.dids.B0));

  // save() never writes through a planted "<path>.tmp", and leaves the file 0600 whatever its mode was.
  const sub = mkdtempSync(join(dir, 'save-')), target = join(sub, 'target');
  writeFileSync(target, 'untouched', { mode: 0o644 });
  symlinkSync(target, join(sub, 'Z.json.tmp'));
  writeFileSync(join(sub, 'Z.json'), JSON.stringify({ v: 'sigelo-invite/0', self: F.dids.A0, invites: {}, accepts: {}, contacts: {} }), { mode: 0o644 });
  run('save() with a planted .tmp symlink', {}, () => new Contacts(join(sub, 'Z.json'), F.dids.A0).addInvite(made(c), 'bob', c.now));
  ok(readFileSync(target, 'utf8') === 'untouched' && (statSync(join(sub, 'Z.json')).mode & 0o777) === 0o600, 'save() ignores a planted .tmp symlink and writes 0600');
  ok(readdirSync(sub).sort().join(' ') === 'Z.json Z.json.tmp target', 'save() leaves no temporary file behind');

  let thrown;
  try { parseInvite('sgl2', c.now); } catch (e) { thrown = e; }
  ok(thrown?.constructor === MsgError && thrown.check === 'code_version', 'invite refusals are MsgError, the one error class of contact/, with .check');
} finally {
  rmSync(dir, { recursive: true, force: true });
}

const gen = spawnSync(process.execPath, [join(HERE, 'gen-invite.mjs'), '--check'], { encoding: 'utf8' });
ok(gen.status === 0, `gen-invite.mjs --check: ${(gen.stderr || gen.stdout).trim()}`);

for (const f of fails) console.log('FAIL ' + f);
if (fails.length) { console.log(`${fails.length} FAILED, ${pass} passed`); process.exit(1); }
console.log(`ALL PASS (${pass})`);
