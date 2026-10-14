// SPDX-License-Identifier: MIT
// `npm i && node test.mjs` → ALL PASS. Checks example-card.json and sign/verify round trips,
// including after a rotation and against tampering. Uses the published `sigelo` package.
import { readFileSync } from 'node:fs';
import { attest, keygen, parse, rotate } from 'sigelo';
import { URI, verifyCard } from './verify.mjs';
import { signCard } from './sign.mjs';

let fails = 0, passes = 0;
const ok = (c, m) => { c ? passes++ : fails++; console.log(`${c ? 'ok  ' : 'FAIL'} ${m}`); };
const throws = (f, re, m) => { try { f(); ok(false, `${m} (accepted)`); } catch (e) { ok(re.test(e.message), `${m}: ${e.message}`); } };
const NOW = 1790000000, seed = (n) => new Uint8Array(32).fill(n);

const card = { name: 'test', description: 'd', version: '1',
  supportedInterfaces: [{ url: 'https://agent.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
  capabilities: { streaming: true, extensions: [{ uri: 'urn:other', required: false }] }, defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'], skills: [] };
const a = keygen({ recovery: seed(9), seed: seed(1), created: '2026-10-14T00:00:00Z', nonce: seed(2) });
const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: a.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
const signed = signCard(card, bundle, a.secret, NOW);
ok(verifyCard(signed, NOW).did === a.did, 'sign → verify round trip');
ok(signed.capabilities.extensions.length === 2 && signed.capabilities.extensions[0].uri === 'urn:other', 'other extensions kept');
const tamper = (f) => { const c = structuredClone(signed); f(c); return c; };
throws(() => verifyCard(tamper((c) => { c.supportedInterfaces[0].url = 'https://evil.example/a2a'; }), NOW), /bad signature/, 'changed url refused');
ok(verifyCard(tamper((c) => { c.signatures = [{ protected: 'e30', signature: 'x' }]; }), NOW).did === a.did, 'an A2A JWS signatures array added later: still verifies');
throws(() => verifyCard(tamper((c) => { c.capabilities.extensions[1].params.did = 'did:sigelo:zX'; }), NOW), /current DID/, 'swapped did refused');
throws(() => verifyCard(tamper((c) => { c.capabilities.extensions.pop(); }), NOW), /exactly one/, 'missing extension refused');
throws(() => verifyCard(tamper((c) => { c.capabilities.extensions.push(c.capabilities.extensions[1]); }), NOW), /exactly one/, 'two extensions refused');
throws(() => signCard(card, bundle, seed(7), NOW), /bad signature/, 'a key that is not the bundle\'s refused');

const b = keygen({ recovery: seed(9), seed: seed(3), created: '2026-10-14T00:00:00Z', nonce: seed(4) });
const rot = rotate({ genesis: a.genesis, next_genesis: b.genesis, iat: NOW - 10, reason: 'voluntary', secret: a.secret });
const rotated = { ...bundle, rotations: [rot] };
ok(verifyCard(signCard(card, rotated, b.secret, NOW), NOW).did === b.did, 'after rotation: signed by the new key, verifies');
throws(() => signCard(card, rotated, a.secret, NOW), /bad signature/, 'after rotation: the old key refused');

// Regenerate example-card.json: node test.mjs --write
if (process.argv[2] === '--write') {
  const w = keygen({ recovery: seed(9), seed: seed(5), created: '2026-10-14T00:00:00Z', nonce: seed(6) });
  const att = attest({ secret: w.secret, iss: w.did, sub: a.did, iat: NOW - 100, exp: NOW + 86400 * 365 * 5, ctx: 'world.example',
    admission: 'open', claims: { tasks: 3 } });
  const card2 = { ...card, name: 'example agent', capabilities: { streaming: true } };
  const full = { ...bundle, attestations: [att], issuers: [w.genesis] };
  const { writeFileSync } = await import('node:fs');
  writeFileSync(new URL('./example-card.json', import.meta.url), JSON.stringify(signCard(card2, full, a.secret, NOW), null, 2) + '\n');
  console.log('wrote example-card.json');
}
const ex = parse(readFileSync(new URL('./example-card.json', import.meta.url), 'utf8'));
const r = verifyCard(ex, NOW);
ok(r.did === ex.capabilities.extensions.find((e) => e.uri === URI).params.did && Object.keys(r.attestations).length === 1,
  `example-card.json verifies: ${r.did}, 1 issuer's attestation`);

console.log(fails ? `${fails} FAILED` : `ALL PASS (${passes})`);
process.exit(fails ? 1 : 0);
