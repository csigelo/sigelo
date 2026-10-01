// SPDX-License-Identifier: MIT
// A mock world in one file: the issuer + verifier side of QUICKSTART steps 2 and 4.
// Run from the repo root after `cd ts && npm install && npx tsc`. Needs node >= 22.18.
// `node examples/world.mjs --help` prints the usage below.
//
//   node examples/world.mjs challenge <agent-genesis.json>            -> challenge body (JSON) on stdout
//   node examples/world.mjs attest    <agent-genesis.json> <sig>      -> { attestation, issuer } on stdout
//
// The world keeps its own identity in ./world.local.json (a real world keeps it in a secret
// store and, like this one, usually has no recovery key: a stable service key is rotated by
// deploying a new one, not by an offline ceremony).
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { attest, did, keygen, parse, verifySig, encodeKey, multibase } from '../ts/dist/sigelo.js';

const USAGE = `world.mjs — the mock world of QUICKSTART. Run it; do not reimplement it.
Run from the repo root (the directory holding examples/). Needs ts/dist (cd ts && npx tsc).

  node examples/world.mjs challenge <genesis.json>
      prints one line: the challenge body { v, typ, did, ctx, nonce } for that genesis's DID
  node examples/world.mjs attest <genesis.json> <sig>
      checks <sig> over the last challenge against that genesis's key, then prints one line:
      { "attestation": { body, sig }, "issuer": <this world's genesis> }

<genesis.json> is the agent's genesis as it stands now (after a rotation, the new one).
State, in the current directory: ./world.local.json (this world's identity, made on first
run) and ./challenge.local.json (the last challenge; attest answers only that one).
Nonces everywhere are z + base58btc (SPEC §2); a challenge nonce is opaque to the agent (SPEC §5.2).`;
const [cmd, genesisPath, sig] = process.argv.slice(2);
if (cmd === '--help' || cmd === '-h' || cmd === 'help') { console.log(USAGE); process.exit(0); }
if (!((cmd === 'challenge' && genesisPath) || (cmd === 'attest' && genesisPath && sig))) { console.error(USAGE); process.exit(2); }

const CTX = 'example.world';
const load = (p) => parse(readFileSync(p, 'utf8'));
const world = existsSync('world.local.json')
  ? load('world.local.json')
  : (() => { const k = keygen({ recovery: null }); const w = { genesis: k.genesis, secret: Buffer.from(k.secret).toString('hex') };
             writeFileSync('world.local.json', JSON.stringify(w), { mode: 0o600 }); return w; })();
const worldDid = did(world.genesis);
const agentGenesis = load(genesisPath);
const agentDid = did(agentGenesis);                       // recomputed from the bytes shown, never trusted as told

if (cmd === 'challenge') {
  // A real world binds the nonce to the requesting session and a short lifetime (SPEC §5.2).
  const nonce = multibase(randomBytes(16)); // z + base58btc, the same form as genesis and binding nonces
  writeFileSync('challenge.local.json', JSON.stringify({ did: agentDid, nonce }));
  console.log(JSON.stringify({ v: 'sigelo/0', typ: 'challenge', did: agentDid, ctx: CTX, nonce }));
} else if (cmd === 'attest') {
  const c = load('challenge.local.json');
  if (c.did !== agentDid) throw new Error('that challenge was issued to a different DID (compared in full)');
  const body = { v: 'sigelo/0', typ: 'challenge', did: agentDid, ctx: CTX, nonce: c.nonce };
  if (!verifySig(agentGenesis.key, body, sig)) throw new Error('signature does not verify against genesis.key');
  const iat = Math.floor(Date.now() / 1000);
  const attestation = attest({ secret: Uint8Array.from(Buffer.from(world.secret, 'hex')), iss: worldDid, sub: agentDid,
    iat, exp: iat + 30 * 86400, ctx: CTX, admission: 'open', claims: { joined: new Date().toISOString().slice(0, 10), posts: 3 } });
  console.log(JSON.stringify({ attestation, issuer: world.genesis }));
}
