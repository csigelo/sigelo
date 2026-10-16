// SPDX-License-Identifier: MIT
// `npm i && node test.mjs` → ALL PASS. Checks example-card.json and sign/verify round trips,
// including after a rotation, against tampering, and the operator attestation. Uses the published
// `sigelo` package. Signers here are built from test seeds; real use goes through sigelo-agent-keys.ts.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { attest, keygen, parse, rotate, sign } from 'sigelo';
import { OPERATOR_CTX, URI, verifyCard } from './verify.mjs';
import { operatorFrom, signCard, signerFor } from './sign.mjs';

let fails = 0, passes = 0;
const ok = (c, m) => { c ? passes++ : fails++; console.log(`${c ? 'ok  ' : 'FAIL'} ${m}`); };
const rejects = async (f, re, m) => { try { await f(); ok(false, `${m} (accepted)`); } catch (e) { ok(re.test(e.message), `${m}: ${e.message}`); } };
const NOW = 1790000000, DAY = 86400, seed = (n) => new Uint8Array(32).fill(n);
const signerOf = (id) => ({ did: id.did, key: id.genesis.key, sign: (b) => sign(id.secret, b) });
const bundleOf = (genesis, rotations = []) => ({ v: 'sigelo/0', typ: 'bundle', genesis, rotations, bindings: [], attestations: [], issuers: [] });

const card = { name: 'test', description: 'd', version: '1',
  supportedInterfaces: [{ url: 'https://agent.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
  capabilities: { streaming: true, extensions: [{ uri: 'urn:other', required: false }] }, defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'], skills: [] };
const a = keygen({ recovery: seed(9), seed: seed(1), created: '2026-10-14T00:00:00Z', nonce: seed(2) });
const bundle = bundleOf(a.genesis);
const signed = await signCard(card, bundle, signerOf(a), NOW);
ok(verifyCard(signed, NOW).did === a.did, 'sign → verify round trip');
ok(signed.capabilities.extensions.length === 2 && signed.capabilities.extensions[0].uri === 'urn:other', 'other extensions kept');
const tamperOf = (s) => (f) => { const c = structuredClone(s); f(c); return c; }, tamper = tamperOf(signed);
await rejects(() => verifyCard(tamper((c) => { c.supportedInterfaces[0].url = 'https://evil.example/a2a'; }), NOW), /bad signature/, 'changed url refused');
ok(verifyCard(tamper((c) => { c.signatures = [{ protected: 'e30', signature: 'x' }]; }), NOW).did === a.did, 'an A2A JWS signatures array added later: still verifies');
await rejects(() => verifyCard(tamper((c) => { c.capabilities.extensions[1].params.did = 'did:sigelo:zX'; }), NOW), /current DID/, 'swapped did refused');
await rejects(() => verifyCard(tamper((c) => { c.capabilities.extensions.pop(); }), NOW), /exactly one/, 'missing extension refused');
await rejects(() => verifyCard(tamper((c) => { c.capabilities.extensions.push(c.capabilities.extensions[1]); }), NOW), /exactly one/, 'two extensions refused');
await rejects(() => signCard(card, bundle, signerOf(keygen({ recovery: seed(9), seed: seed(7) })), NOW), /bad signature/, 'a signer that is not the bundle\'s key refused');
await rejects(() => signCard(card, bundle, a.secret, NOW), /pass a signer/, 'a raw key refused: signing goes through a signer (K1)');

const b = keygen({ recovery: seed(9), seed: seed(3), created: '2026-10-14T00:00:00Z', nonce: seed(4) });
const rot = rotate({ genesis: a.genesis, next_genesis: b.genesis, iat: NOW - 10, reason: 'voluntary', secret: a.secret });
const rotated = { ...bundle, rotations: [rot] };
ok(verifyCard(await signCard(card, rotated, signerOf(b), NOW), NOW).did === b.did, 'after rotation: signed by the new key, verifies');
await rejects(() => signCard(card, rotated, signerOf(a), NOW), /bad signature/, 'after rotation: the old key refused');

// The operator (params.operator): the attestation sigelo-agent writes, and the operator's chain.
const op = keygen({ recovery: seed(19), seed: seed(11), created: '2026-10-14T00:00:00Z', nonce: seed(12) });
const opAtt = (o) => attest({ secret: op.secret, iss: op.did, sub: a.did, iat: NOW - 100, exp: NOW + 90 * DAY, ctx: OPERATOR_CTX,
  admission: 'invite', admission_by: op.did, claims: { relay: 'relay.test' }, ...o });
const att = opAtt({});
const withOp = await signCard(card, bundle, signerOf(a), NOW, { attestation: att, bundle: bundleOf(op.genesis) });
const v = verifyCard(withOp, NOW);
ok(v.did === a.did && v.operator.did === op.did && v.operator.exp === NOW + 90 * DAY, `operator round trip: ${JSON.stringify({ did: v.operator.did, exp: v.operator.exp })}`);
const idFile = { v: 'sigelo/0', genesis: a.genesis, rotations: [], attestations: [att], issuers: [op.genesis] }; // sigelo-agent's file, minus secret
ok(verifyCard(await signCard(card, bundle, signerOf(a), NOW, operatorFrom(idFile)), NOW).operator.did === op.did, 'operator from the identity file sigelo-agent writes');
const other = keygen({ recovery: seed(9), seed: seed(13) });
await rejects(() => signCard(card, bundle, signerOf(a), NOW, { attestation: opAtt({ sub: other.did }), bundle: bundleOf(op.genesis) }), /operator_subject/, 'an attestation for another agent refused');
await rejects(() => verifyCard(withOp, NOW + 90 * DAY), /operator_expired/, 'expired refused');
await rejects(() => signCard(card, bundle, signerOf(a), NOW, { attestation: opAtt({ ctx: 'world.example' }), bundle: bundleOf(op.genesis) }), /operator_ctx/, 'another ctx refused');
await rejects(() => signCard(card, bundle, signerOf(a), NOW, { attestation: att, bundle: bundleOf(other.genesis) }), /operator_issuer/, 'an issuer outside the operator\'s chain refused');
// SPEC §5: the old attestation verifies under the old DID, but the chain shows the key was rotated away
// from, so it is refused, as the keeper's licence check refuses a rotated-away vendor key (spend/licence.ts).
const op2 = keygen({ recovery: seed(19), seed: seed(14), created: '2026-10-15T00:00:00Z', nonce: seed(15) });
const opChain = bundleOf(op.genesis, [rotate({ genesis: op.genesis, next_genesis: op2.genesis, iat: NOW - 50, reason: 'voluntary', secret: op.secret })]);
await rejects(() => signCard(card, bundle, signerOf(a), NOW, { attestation: att, bundle: opChain }), /operator_rotated/, 'operator\'s rotated-away key refused (SPEC §5)');
const att2 = attest({ ...att.body, secret: op2.secret, iss: op2.did, admission_by: op2.did });
const v2 = verifyCard(await signCard(card, bundle, signerOf(a), NOW, { attestation: att2, bundle: opChain }), NOW);
ok(v2.operator.did === op2.did && v2.operator.chain[0] === op.did, 'reissued by the operator\'s new key: verifies, chain from the original DID');
const tamperOp = tamperOf(withOp);
await rejects(() => verifyCard(tamperOp((c) => { c.capabilities.extensions[1].params.operator.attestation.body.exp += DAY; }), NOW), /bad signature/, 'operator exp changed after signing refused');
await rejects(() => verifyCard(tamperOp((c) => { delete c.capabilities.extensions[1].params.operator; }), NOW), /bad signature/, 'operator removed after signing refused');
await rejects(() => verifyCard(tamperOp((c) => { c.capabilities.extensions[1].params.operator.bundle = opChain; }), NOW), /bad signature/, 'operator chain swapped after signing refused');
ok(verifyCard(signed, NOW).operator === null && !('operator' in signed.capabilities.extensions[1].params), 'no-operator card: operator null, no field added');

// K1: an identity file path goes through sigelo-agent-keys.ts's signer (needs adapters/moadim installed).
let k1 = null;
try { k1 = (await import('../../adapters/moadim/sigelo-agent-keys.ts')).signer; } catch { /* not installed */ }
if (k1) {
  const dir = mkdtempSync(join(tmpdir(), 'a2a-')), path = join(dir, 'id.json');
  writeFileSync(path, JSON.stringify({ v: 'sigelo/0', provider: 'file', secret: Buffer.from(a.secret).toString('hex'), genesis: a.genesis, rotations: [], attestations: [], issuers: [] }), { mode: 0o600 });
  try {
    ok((await signerFor(path)).did === a.did, 'signerFor: K1 signer from an identity file');
    ok(JSON.stringify(await signCard(card, bundle, path, NOW)) === JSON.stringify(signed), 'an identity file path signs through K1: same card as the signer');
  } finally { rmSync(dir, { recursive: true }); }
} else console.log('SKIP K1 path: adapters/moadim not installed (npm ci there)');

// Regenerate example-card.json: node test.mjs --write
const w = keygen({ recovery: seed(9), seed: seed(5), created: '2026-10-14T00:00:00Z', nonce: seed(6) });
const worldAtt = attest({ secret: w.secret, iss: w.did, sub: a.did, iat: NOW - 100, exp: NOW + 86400 * 365 * 5, ctx: 'world.example',
  admission: 'open', claims: { tasks: 3 } });
const card2 = { ...card, name: 'example agent', capabilities: { streaming: true } };
const full = { ...bundle, attestations: [worldAtt], issuers: [w.genesis] };
// The profile before params.operator, byte for byte: example-card.json at a7dbd16 carried this sig.
ok((await signCard(card2, full, signerOf(a), NOW)).capabilities.extensions[0].params.sig ===
  'z65Sg1yv15vw7ENKCZuDxE4tEPpha2xRGJPk8KySi5HVdhcMncqqtb5QcA58sb2Reicvvj44CChzTB1We47YuUKH9', 'no-operator card unchanged: same signature as before the field');
if (process.argv[2] === '--write') {
  const example = await signCard(card2, full, signerOf(a), NOW, { attestation: att, bundle: bundleOf(op.genesis) });
  writeFileSync(new URL('./example-card.json', import.meta.url), JSON.stringify(example, null, 2) + '\n');
  console.log('wrote example-card.json');
}
const ex = parse(readFileSync(new URL('./example-card.json', import.meta.url), 'utf8'));
const r = verifyCard(ex, NOW);
ok(r.did === ex.capabilities.extensions.find((e) => e.uri === URI).params.did && Object.keys(r.attestations).length === 1 && r.operator?.did === op.did,
  `example-card.json verifies: ${r.did}, 1 issuer's attestation, operator ${r.operator?.did}`);

console.log(fails ? `${fails} FAILED` : `ALL PASS (${passes})`);
process.exit(fails ? 1 : 0);
