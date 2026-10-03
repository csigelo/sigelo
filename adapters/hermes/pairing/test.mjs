// SPDX-License-Identifier: MIT
// Runs fixtures/pairing-v0.json through the node acceptor (accept/node/sigelo-pair.mjs), re-opening
// each JSON contacts store from disk at every step, then checks the fixtures regenerate from the
// seeds and both acceptors stay under 100 code lines.
//   node adapters/hermes/pairing/test.mjs      (needs ts/dist and accept/node's npm install)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { Contacts, pair } from '../../../accept/node/sigelo-pair.mjs';
import { sign } from '../../../ts/dist/sigelo.js';

const HERE = dirname(fileURLToPath(import.meta.url)), REPO = join(HERE, '../../..');
const fx = JSON.parse(readFileSync(join(HERE, 'fixtures/pairing-v0.json'), 'utf8'));
const tmp = mkdtempSync(join(tmpdir(), 'sigelo-pairing-'));
process.on('exit', () => rmSync(tmp, { recursive: true, force: true }));
let fails = 0;
const ok = (c, m, extra = '') => { console.log(`${c ? 'ok  ' : 'FAIL'} ${m}${c ? '' : '  ' + extra}`); if (!c) fails++; };
const pick = (c) => c && { name: c.name, did: c.did, current_did: c.current_did, current_key: c.current_key, revoked: c.revoked };

ok(fx.v === 'sigelo-a2a-pairing/0', `fixture version ${fx.v}`);
for (const s of fx.steps) {
  const store = new Contacts(join(tmp, `${s.store}.json`)), what = `${s.case} [${s.store} ${s.op}]`;
  if (s.op === 'issue') ok(isDeepStrictEqual(store.issue(s.did, s.ctx, s.now, s.contact_name, s.expect.nonce), s.expect), what);
  else if (s.op === 'lookup') ok(isDeepStrictEqual(pick(store.lookup(s.did)), s.expect), what, JSON.stringify(pick(store.lookup(s.did))));
  else if (s.op === 'revoke') ok(isDeepStrictEqual(pick(store.revoke(s.did)), s.expect), what);
  else {
    let got, err;
    try { got = pair(fx.cards[s.card], s.answer, store, s.now); } catch (e) { err = e; }
    if (s.error) ok(err?.check === s.error, `${what} → rejected: ${s.error}`, err ? err.message : 'accepted');
    else ok(!err && isDeepStrictEqual(got, s.expect), `${what} → ${s.expect.current_did.slice(0, 20)}… accepted`, err ? err.message : JSON.stringify(got).slice(0, 300));
  }
}
// Beyond the fixture, found running inside Hermes: a long-lived store (one per plugin process) must see
// the owner's revoke made by another process, and expired challenges must not pile up.
{
  const A0 = fx.dids.A0, ctx = 'hermes-contacts:' + fx.dids.B0, t = fx.steps[0].now, path = join(tmp, 'two-handles.json');
  const answer = (c) => ({ body: c, sig: sign(Buffer.from(fx.seeds.A0, 'hex'), c) });  // seed(label) is the Ed25519 secret
  const gateway = new Contacts(path), owner = new Contacts(path);
  pair(fx.cards.A0, answer(gateway.issue(A0, ctx, t, 'alice')), gateway, t + 1);
  owner.revoke(A0);
  let err; try { pair(fx.cards.A0, answer(gateway.issue(A0, ctx, t + 2)), gateway, t + 3); } catch (e) { err = e; }
  ok(err?.check === 'revoked', 'revoke by another handle holds → rejected: revoked', err ? err.message : 'accepted');
  ok(new Contacts(path).lookup(A0).revoked === true, 'the revoke is still on disk after the refused pairing');
  gateway.issue(A0, ctx, t + 10_000); owner.issue(A0, ctx, t + 10_001);
  ok(Object.keys(new Contacts(path).s.pending).length === 2, 'expired challenges are dropped at issue, live ones from both handles kept');
}
try { execFileSync('node', [join(HERE, 'gen.mjs'), '--check'], { stdio: 'pipe' }); ok(true, 'gen.mjs --check: fixtures reproduce from the seeds'); }
catch (e) { ok(false, 'gen.mjs --check', String(e.stderr)); }
// The adoption argument: each acceptor under 100 code lines (non-blank, not a comment line).
for (const f of ['accept/node/sigelo-pair.mjs', 'accept/python/sigelo_pair.py']) {
  const n = readFileSync(join(REPO, f), 'utf8').split('\n').filter((l) => !/^\s*(\/\/|#|$)/.test(l)).length;
  ok(n < 100, `${f}: ${n} code lines (< 100)`);
}
console.log(fails ? `FAILURES: ${fails}` : 'ALL PASS');
process.exit(fails ? 1 : 0);
