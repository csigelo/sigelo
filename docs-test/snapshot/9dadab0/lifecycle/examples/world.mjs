// SPDX-License-Identifier: MIT
// A mock world in one file: the issuer + verifier side of QUICKSTART steps 2 and 4.
// Run from the repo root after `cd ts && npm ci && npx tsc`. Needs node >= 22.18.
// `node examples/world.mjs --help` prints the usage below.
//
//   node examples/world.mjs challenge <agent-genesis.json>            -> challenge body (JSON) on stdout
//   node examples/world.mjs attest    <agent-genesis.json> <sig>      -> { attestation, issuer } on stdout
//
// The world keeps its own identity in ./world.local.json (a real world keeps it in a secret
// store and, like this one, usually has no recovery key: a stable service key is rotated by
// deploying a new one, not by an offline ceremony).
import { readFileSync, writeFileSync, existsSync, openSync, closeSync, renameSync, rmSync, statSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { attest, did, keygen, parseBytes, verifySig, encodeKey, multibase } from '../ts/dist/sigelo.js';

const USAGE = `world.mjs — the mock world of QUICKSTART. Run it; do not reimplement it.
Run from the repo root (the directory holding examples/). Needs ts/dist (cd ts && npx tsc).

  node examples/world.mjs challenge <genesis.json>
      prints one line: the challenge body { v, typ, did, ctx, nonce } for that genesis's DID
  node examples/world.mjs attest <genesis.json> <sig>
      checks <sig> over the challenge outstanding for that genesis's DID against its key, then
      prints one line: { "attestation": { body, sig }, "issuer": <this world's genesis> }
      and forgets that challenge (answered once)

<genesis.json> is the agent's genesis as it stands now (after a rotation, the new one).
State, in the current directory: ./world.local.json (this world's identity, made on first
run) and ./challenge.local.json (the outstanding challenges, one per DID: a new challenge for
a DID replaces its old one, so several agents can be challenged at once and attested in any
order). Concurrent runs in one directory are serialised by ./world.lock.
Nonces everywhere are z + base58btc (SPEC §2); a challenge nonce is opaque to the agent (SPEC §5.2).`;
const [cmd, genesisPath, sig] = process.argv.slice(2);
if (cmd === '--help' || cmd === '-h' || cmd === 'help') { console.log(USAGE); process.exit(0); }
if (!((cmd === 'challenge' && genesisPath) || (cmd === 'attest' && genesisPath && sig))) { console.error(USAGE); process.exit(2); }

const CTX = 'example.world';
const load = (p) => parseBytes(readFileSync(p)); // fatal UTF-8 decode, as the Go verifier (SPEC §3)
// An orchestrator may run this for many subagents in parallel: hold a lock around the whole
// read-modify-write of the state files (a lock older than 30 s is from a killed run).
for (let t = 0; ; t++) {
  try { closeSync(openSync('world.lock', 'wx')); break; } catch (e) {
    if (e.code !== 'EEXIST') throw e;
    try { if (Date.now() - statSync('world.lock').mtimeMs > 30000) rmSync('world.lock', { force: true }); } catch {}
    if (t > 1000) throw new Error('world.lock held for too long (another world.mjs run in this directory?)');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
  }
}
process.on('exit', () => rmSync('world.lock', { force: true }));
const save = (p, v, mode) => { writeFileSync(p + '.tmp', JSON.stringify(v), { mode }); renameSync(p + '.tmp', p); };
const world = existsSync('world.local.json')
  ? load('world.local.json')
  : (() => { const k = keygen({ recovery: null }); const w = { genesis: k.genesis, secret: Buffer.from(k.secret).toString('hex') };
             save('world.local.json', w, 0o600); return w; })();
const worldDid = did(world.genesis);
const agentGenesis = load(genesisPath);
const agentDid = did(agentGenesis);                       // recomputed from the bytes shown, never trusted as told
// Outstanding challenges: DID -> challenge body. The old format (one { did, nonce }) is one entry.
const pending = (() => {
  if (!existsSync('challenge.local.json')) return {};
  const c = load('challenge.local.json');
  return typeof c.did === 'string' && typeof c.nonce === 'string'
    ? { [c.did]: { v: 'sigelo/0', typ: 'challenge', did: c.did, ctx: CTX, nonce: c.nonce } } : c;
})();

if (cmd === 'challenge') {
  // A real world binds the nonce to the requesting session and a short lifetime (SPEC §5.2).
  const nonce = multibase(randomBytes(16)); // z + base58btc, the same form as genesis and binding nonces
  pending[agentDid] = { v: 'sigelo/0', typ: 'challenge', did: agentDid, ctx: CTX, nonce };  // replaces any older one
  save('challenge.local.json', pending);
  console.log(JSON.stringify(pending[agentDid]));
} else if (cmd === 'attest') {
  const c = Object.hasOwn(pending, agentDid) ? pending[agentDid] : null;   // keyed by the DID in full
  if (!c) throw new Error('no outstanding challenge for that DID (run challenge first)');
  if (c.answered) throw new Error('that challenge was already answered (each is answered once; run challenge again)');
  const body = { v: 'sigelo/0', typ: 'challenge', did: agentDid, ctx: CTX, nonce: c.nonce };
  if (!verifySig(agentGenesis.key, body, sig)) throw new Error('signature does not verify against genesis.key');
  const iat = Math.floor(Date.now() / 1000);
  const attestation = attest({ secret: Uint8Array.from(Buffer.from(world.secret, 'hex')), iss: worldDid, sub: agentDid,
    iat, exp: iat + 30 * 86400, ctx: CTX, admission: 'open', claims: { joined: new Date().toISOString().slice(0, 10), posts: 3 } });
  pending[agentDid] = { ...c, answered: iat };   // kept, marked: a replay is refused, the record stays readable
  save('challenge.local.json', pending);
  console.log(JSON.stringify({ attestation, issuer: world.genesis }));
}
