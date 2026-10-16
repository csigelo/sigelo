// SPDX-License-Identifier: MIT
// `node test.mjs` → ALL PASS (N). Offline: present → verify round trips, refusals, rotation,
// recovery after theft, example.json, and the CLI through a stand-in sigelo-agent.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { attest, canonicalize, keygen, parse, rotate, sign } from 'sigelo';
import { OPERATOR_CTX, URI, verifyPresentation } from './verify.mjs';
import { pairwise, present } from './present.mjs';

let fails = 0, passes = 0;
const ok = (c, m) => { c ? passes++ : fails++; console.log(`${c ? 'ok  ' : 'FAIL'} ${m}`); };
const throws = (f, re, m) => { try { f(); ok(false, `${m} (accepted)`); } catch (e) { ok(re.test(e.message), `${m}: ${e.message}`); } };
const NOW = 1790900000, DAY = 86400, seed = (n) => new Uint8Array(32).fill(n), C = '2026-10-16T00:00:00Z';
const ISSUER = 'https://auth.example.com', NONCE = 'n0nce-Q7c1vK-1790900000', USER = 'usr_Q7c1vK';
const signerOf = (id) => ({ did: id.did, sign: (body) => sign(id.secret, body) });   // tests hold keys; agents use sigelo-agent

const warn = console.warn; console.warn = () => {};                                  // keygen warns on recovery: null
const rec = keygen({ recovery: null, seed: seed(9), created: C, nonce: seed(10) });   // the recovery key, kept offline
const op = keygen({ recovery: null, seed: seed(7), created: C, nonce: seed(8) });     // the operator
console.warn = warn;
const a = keygen({ recovery: rec.key, seed: seed(1), created: C, nonce: seed(2) });
const opAtt = (sub, iat = NOW - DAY, exp = NOW + 89 * DAY) => attest({ secret: op.secret, iss: op.did, sub, iat, exp, ctx: OPERATOR_CTX,
  admission: 'invite', admission_by: op.did, claims: { relay: 'relay.sigelo.ai' } });
const bundleOf = (rotations = [], atts = [opAtt(a.did)]) => ({ v: 'sigelo/0', typ: 'bundle', genesis: a.genesis, rotations, bindings: [], attestations: atts, issuers: [op.genesis] });
const at = { issuer: ISSUER, nonce: NONCE, now: NOW };
const pres = (id, bundle, issuer = ISSUER) => present({ signer: signerOf(id), bundle, issuer, nonce: NONCE, user_id: USER, client_name: 'Example Agent', now: NOW });
const edit = (p, f) => { const x = parse(p.client_assertion); f(x); return { ...p, client_assertion: canonicalize(x) }; };

// 1. round trip
const p = pres(a, bundleOf()), v = verifyPresentation(p, at);
ok(v.client_id === a.did && v.did === a.did && p.client_assertion_type === URI && p.user_id === USER, 'round trip: client_id = the DID, user_id carried');
ok(v.operators.length === 1 && v.operators[0].did === op.did, 'the operator attestation names who stands behind the agent');

// 2. tampering and wrong context
throws(() => verifyPresentation(edit(p, (x) => { x.proof.body.nonce = 'other'; }), { ...at, nonce: 'other' }), /bad proof signature/, 'a tampered proof (nonce changed after signing) refused');
throws(() => verifyPresentation(edit(p, (x) => { x.proof.sig = sign(op.secret, x.proof.body); }), at), /bad proof signature/, 'a proof signed by another key refused');
throws(() => verifyPresentation(p, { ...at, issuer: 'https://auth.other.example' }), /not this Company's auth.issuer/, 'an answer made for another Company refused');
throws(() => verifyPresentation(pres(a, bundleOf(), 'https://auth.evil.example'), at), /not this Company's auth.issuer/, 'an answer whose challenge names a wrong origin refused');
throws(() => verifyPresentation(p, { ...at, nonce: 'n0nce-later' }), /another nonce/, 'a replay against a fresh nonce refused');
throws(() => verifyPresentation(edit(p, (x) => { x.proof.body.sub = USER; }), at), /not a SPEC §5.2 challenge/, 'a proof with a sixth field refused');
throws(() => verifyPresentation({ ...p, client_id: op.did }, at), /original DID/, 'a client_id other than the bundle\'s refused');
throws(() => verifyPresentation({ ...p, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' }, at), /not the sigelo profile/, 'another client_assertion_type refused');
throws(() => verifyPresentation({ ...p, client_assertion: p.client_assertion.replace('{', '{"proof":1,') }, at), /[Dd]uplicate/, 'a duplicate key in client_assertion refused');

// 3. operator attestation: expiry, self-attestation
const pExp = pres(a, bundleOf([], [opAtt(a.did, NOW - 91 * DAY, NOW - DAY)]));
throws(() => verifyPresentation(pExp, at), /no unexpired operator/, 'an expired operator attestation: refused');
ok(verifyPresentation(pExp, { ...at, requireOperator: false }).operators.length === 0, '... and reported as no operator when the Company does not require one');
const self = attest({ secret: a.secret, iss: a.did, sub: a.did, iat: NOW - DAY, exp: NOW + DAY, ctx: OPERATOR_CTX, admission: 'invite', admission_by: a.did, claims: {} });
throws(() => verifyPresentation(pres(a, { ...bundleOf([], [self]), issuers: [a.genesis] }), at), /no unexpired operator/, 'an agent cannot be its own operator');

// 4. rotation: the client_id stays, the new key answers
const b = keygen({ recovery: rec.key, seed: seed(3), created: C, nonce: seed(4) });
const vol = rotate({ genesis: a.genesis, next_genesis: b.genesis, iat: NOW - 100, reason: 'voluntary', secret: a.secret });
const vr = verifyPresentation(pres(b, bundleOf([vol])), { ...at, known: [a.did] });
ok(vr.client_id === a.did && vr.did === b.did && vr.operators.length === 1, 'a rotated agent verifies under the same client_id, the attestation follows the chain');
throws(() => pres(a, bundleOf([vol])), /not the bundle's current DID/, 'after rotation: present refuses the old key');

// 5. theft, then recovery: the owner rotates A → R with the offline recovery key
const r = keygen({ recovery: rec.key, seed: seed(5), created: C, nonce: seed(6) });
const recv = rotate({ genesis: a.genesis, next_genesis: r.genesis, iat: NOW - 200, reason: 'recovery', secret: rec.secret });
const recovered = verifyPresentation(pres(r, bundleOf([recv])), { ...at, known: [a.did] });
ok(recovered.client_id === a.did && recovered.did === r.did, 'recovered: same client_id, the new key answers');
// what a thief sends without present()'s own check: any bundle, a proof signed with a key it holds
const forge = (id, bundle) => { const body = { v: 'sigelo/0', typ: 'challenge', did: id.did, ctx: ISSUER, nonce: NONCE };
  return { ...p, client_assertion: canonicalize({ bundle, proof: { body, sig: sign(id.secret, body) } }) }; };
throws(() => verifyPresentation(forge(a, bundleOf([recv])), at), /current DID/, 'stolen old key with the recovered bundle: refused');
throws(() => verifyPresentation(pres(a, bundleOf()), { ...at, known: recovered.chain }), /does not extend/, 'stolen old key with the old bundle, at a Company that saw the recovery: refused');
throws(() => verifyPresentation(pres(b, bundleOf([vol])), { ...at, known: recovered.chain }), /does not extend/, 'the thief\'s own rotation, at that Company: refused');
throws(() => verifyPresentation(forge(b, bundleOf([vol, recv])), at), /current DID/, 'thief\'s rotation and the recovery in one bundle: recovery wins, the thief\'s key refused');

ok(verifyPresentation(pres(a, bundleOf()), at).did === a.did, 'stolen old key, old bundle, at a Company that never saw the recovery: accepted (README, limits)');

// 6. one DID per business, from one keeper root (README)
const K = seed(11), B2 = 'https://auth.other.example';
const pw = (iss) => { const x = pairwise(K, rec.key, iss); return verifyPresentation(present({ signer: x.signer, bundle: x.bundle, issuer: iss, nonce: NONCE, user_id: USER, now: NOW }), { issuer: iss, nonce: NONCE, now: NOW, requireOperator: false }); };
const [p1, p2, p1b] = [pw(ISSUER), pw(B2), pw(ISSUER)];
ok(p1.client_id !== p2.client_id && p1.operators.length === 0, 'pairwise: two businesses get different DIDs from one seed, no operator re-links them');
ok(p1.client_id === p1b.client_id && p1.recovery === p1b.recovery, 'pairwise: the same business gets the same DID twice');

// 7. example.json (regenerate: node test.mjs --write)
if (process.argv[2] === '--write') writeFileSync(new URL('./example.json', import.meta.url), JSON.stringify({ issuer: ISSUER, nonce: NONCE, now: NOW, params: p }, null, 2) + '\n');
const ex = parse(readFileSync(new URL('./example.json', import.meta.url), 'utf8'));
const ev = verifyPresentation(ex.params, ex);
ok(ev.client_id === ex.params.client_id && ev.operators[0]?.did === op.did, `example.json verifies: ${ev.did}, operator ${ev.operators[0]?.did}`);

// 8. the CLI, with a stand-in for sigelo-agent: present.mjs reads no key file
const dir = mkdtempSync(join(tmpdir(), 'pap-')), fake = join(dir, 'sigelo-agent');
writeFileSync(join(dir, 'b.json'), JSON.stringify(bundleOf()));
writeFileSync(fake, `#!/usr/bin/env node
import { readFileSync } from 'node:fs'; import { sign } from ${JSON.stringify(new URL('./node_modules/sigelo/dist/sigelo.js', import.meta.url).href)};
const [verb, body] = process.argv.slice(2);
console.log(verb === 'bundle' ? readFileSync(${JSON.stringify(join(dir, 'b.json'))}, 'utf8') : JSON.stringify({ sig: sign(new Uint8Array(32).fill(1), JSON.parse(body)) }));
`, { mode: 0o755 });
try {
  const out = parse(execFileSync(process.execPath, [fileURLToPath(new URL('./present.mjs', import.meta.url)), ISSUER, NONCE, USER], { env: { ...process.env, SIGELO_AGENT: fake }, encoding: 'utf8' }));
  ok(verifyPresentation(out, { issuer: ISSUER, nonce: NONCE }).did === a.did, 'CLI: signs through sigelo-agent sign-challenge, verifies');
} catch (e) { ok(false, `CLI: ${e.message}`); } finally { rmSync(dir, { recursive: true }); }

console.log(fails ? `${fails} FAILED` : `ALL PASS (${passes})`);
process.exit(fails ? 1 : 0);
