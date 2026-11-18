// SPDX-License-Identifier: MIT
// Regenerates fixtures/lookup-v0.json, byte for byte, from the seeds below (Ed25519 is deterministic).
//   node apps/integrations/a2a/python/gen.mjs           write the file
//   node apps/integrations/a2a/python/gen.mjs --check   exit 1 if the committed file differs
// Needs the a2a folder's node_modules (npm ci there).
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { keygen, rotate, sign } from 'sigelo';
import { signCard } from '../sign.mjs';
import { URI, cardBody } from '../verify.mjs';

const NOW = 1790000000, CREATED = '2026-11-01T00:00:00Z', OUT = new URL('./fixtures/lookup-v0.json', import.meta.url);
// seed(label) = SHA-256("sigelo-a2a-lookup/0 " + label); genesis nonce = first 16 bytes of SHA-256(".. nonce " + label).
const sha = (s) => new Uint8Array(createHash('sha256').update('sigelo-a2a-lookup/0 ' + s).digest());
const seed = (l) => sha(l), nonce = (l) => sha('nonce ' + l).subarray(0, 16);
const ZERO = 'sha256:' + '0'.repeat(64); // placeholder commitment: only to read a recovery seed's public key
const pub = (l) => keygen({ seed: seed(l), recovery: ZERO, created: CREATED, nonce: nonce(l) }).genesis.key;
const id = (l, rec) => keygen({ seed: seed(l), recovery: pub(rec), created: CREATED, nonce: nonce(l) });
const A0 = id('A0', 'A-rec'), A1 = id('A1', 'A-rec'), T = id('T', 'A-rec'), X = id('X', 'A-rec');
const A2 = id('A2', 'A-rec-2'), A3 = id('A3', 'A-rec-2'), B0 = id('B0', 'B-rec');
const rot = (from, to, iat, reason = 'voluntary', secret = from.secret) =>
  rotate({ genesis: from.genesis, next_genesis: to.genesis, iat, reason, secret, next_secret: to.secret });
const rA1 = rot(A0, A1, NOW - 9000);                 // voluntary A0 -> A1
const rT = rot(A1, T, NOW - 5000);                   // a thief holding A1's key: A1 -> T
const rX = rot(A1, X, NOW - 4000);                   // a second voluntary rotation at A1: with rT, a fork (SPEC §7.3)
const rA2 = rot(A1, A2, NOW - 6000, 'recovery', seed('A-rec'));   // recovery at A1, earlier iat: beats rT (§7.1)
const rA3 = rot(T, A3, NOW - 3000, 'recovery', seed('A-rec'));    // recovery after the thief's rotation, at T
const bundle = (g, rotations = []) => ({ v: 'sigelo/0', typ: 'bundle', genesis: g.genesis, rotations, bindings: [], attestations: [], issuers: [] });

const bundles = {
  genesis: bundle(A0), rotated: bundle(A0, [rA1]), thief: bundle(A0, [rA1, rT]),
  recovered: bundle(A0, [rA1, rT, rA2]), recovered_at_thief: bundle(A0, [rA1, rT, rA3]),
  fork_other: bundle(A0, [rA1, rX]), duplicate: bundle(A0, [rA1, rA1]), other_genesis: bundle(B0),
};
const card = { name: 'Alice', description: 'Hermes Agent — a general-purpose agent reachable over A2A.', version: '1.0.0',
  supportedInterfaces: [{ url: 'https://alice.example/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
  capabilities: { streaming: true, extensions: [{ uri: 'urn:other', required: false }] },
  defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [] };
const signer = (x) => ({ did: x.did, key: x.genesis.key, sign: (b) => sign(x.secret, b) });
const out = {
  v: 'sigelo-a2a-lookup/0', now: NOW,
  dids: Object.fromEntries(Object.entries({ A0, A1, A2, A3, T, X, B0 }).map(([k, v]) => [k, v.did])),
  keys: Object.fromEntries(Object.entries({ A0, A1, A2, A3, T, X, B0 }).map(([k, v]) => [k, v.genesis.key])),
  bundles,
  card: await signCard(card, bundles.genesis, signer(A0), NOW),
  card_rotated: await signCard(card, bundles.rotated, signer(A1), NOW),
};
const text = JSON.stringify(out, null, 2) + '\n';
if (process.argv.includes('--check')) {
  let cur = ''; try { cur = readFileSync(OUT, 'utf8'); } catch {}
  if (cur !== text) { console.error('FAIL fixtures/lookup-v0.json differs from what the seeds generate: run gen.mjs'); process.exit(1); }
  console.log('ok fixtures/lookup-v0.json reproduces from the seeds');
} else writeFileSync(OUT, text);
