// SPDX-License-Identifier: MIT
// accept/test.mjs — drives running accept servers with a real sigelo agent (adapters/moadim's
// sigelo-agent CLI) and, for the stolen-old-key case, the ts library. Run by test.sh.
//   node accept/test.mjs <name>=<base url> ...
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { did, keygen, rotate, sign } from '../ts/dist/sigelo.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '../adapters/moadim/dist/cli.js');
const tmp = mkdtempSync(join(tmpdir(), 'sigelo-accept-'));
process.on('exit', () => rmSync(tmp, { recursive: true, force: true }));
let fails = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'} ${m}`); if (!c) fails++; };

// Agents: A and B fresh, R rotated once (its current DID is not its first), all through the CLI.
const agent = (name) => {
  const env = { ...process.env, SIGELO_IDENTITY: join(tmp, `${name}.local.json`) };
  const run = (...a) => JSON.parse(execFileSync('node', [CLI, ...a], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
  run('init', '--no-recovery');
  return { run, get did() { return run('whoami').did; }, bundle: () => run('bundle'), genesis: () => run('whoami').genesis, sign: (c) => run('sign-challenge', JSON.stringify(c)).sig };
};
const A = agent('a'), B = agent('b'), R = agent('r');
R.run('rotate');
ok(R.did !== R.run('whoami').chain[0], 'agent R rotated: its current DID is not its first');
// S: the stolen-old-key case, built with the library because the CLI rightly refuses to sign for a DID that is not current.
const rc = 'sha256:' + '0'.repeat(64), s0 = keygen({ recovery: rc }), s1 = keygen({ recovery: rc });
const S = { old: did(s0.genesis), bundle: { v: 'sigelo/0', typ: 'bundle', genesis: s0.genesis, bindings: [], attestations: [], issuers: [],
  rotations: [rotate({ genesis: s0.genesis, next_genesis: s1.genesis, iat: Math.floor(Date.now() / 1000) - 60, reason: 'key', secret: s0.secret })] } };

const get = async (base, d) => { const r = await fetch(`${base}/sigelo/challenge?did=${encodeURIComponent(d)}`); return r.ok ? r.json() : null; };
const post = async (base, body) => { const r = await fetch(`${base}/sigelo/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch {} return { status: r.status, did: j?.did, text: t.trim() }; };
const accepted = (r, d) => r.status === 200 && r.did === d;
const why = (r) => ` (${r.status} ${r.text.slice(0, 90)})`;
const flip = (sig) => sig.slice(0, -2) + (sig.at(-2) === 'A' ? 'B' : 'A') + sig.at(-1);

for (const arg of process.argv.slice(2)) {
  const [name, base] = arg.split('=');
  for (let t = 0; t < 100 && !(await fetch(base + '/sigelo/challenge?did=x').then(() => true, () => false)); t++) await new Promise((r) => setTimeout(r, 100));
  const login = async (who, c, extra = {}) => post(base, { challenge: c, did: who.did, sig: who.sign(c), bundle: who.bundle(), ...extra });
  let c = await get(base, A.did), r;
  ok(c && Object.keys(c).sort().join() === 'ctx,did,nonce,typ,v' && c.typ === 'challenge' && c.did === A.did, `${name}: GET /sigelo/challenge is a five-field §5.2 challenge`);
  const body = { challenge: c, did: A.did, sig: A.sign(c), bundle: A.bundle() };
  ok(accepted(r = await post(base, body), A.did), `${name}: agent A's bundle + sign-challenge answer → accepted` + why(r));
  ok(!accepted(r = await post(base, body), A.did), `${name}: the same answer replayed → rejected` + why(r));
  c = await get(base, A.did);
  ok(!accepted(r = await post(base, { challenge: c, did: A.did, sig: flip(A.sign(c)), bundle: A.bundle() }), A.did), `${name}: tampered sig → rejected` + why(r));
  c = await get(base, A.did);
  ok(!accepted(r = await post(base, { challenge: c, did: A.did, sig: A.sign(c), bundle: B.bundle() }), A.did), `${name}: A's answer with B's bundle (current DID ≠ did) → rejected` + why(r));
  c = await get(base, S.old);
  ok(!accepted(r = await post(base, { challenge: c, did: S.old, sig: sign(s0.secret, c), bundle: S.bundle }), S.old), `${name}: a rotated-away DID signing with its old key → rejected` + why(r));
  ok(accepted(r = await login(R, await get(base, R.did)), R.did), `${name}: agent R after a rotation → accepted under its current key` + why(r));
  ok(accepted(r = await login(A, await get(base, A.did), { bundle: A.genesis() }), A.did), `${name}: agent A with its genesis instead of a bundle → accepted` + why(r));
  c = await get(base, A.did);
  const forged = { ...c, nonce: c.nonce.slice(0, -1) + (c.nonce.at(-1) === 'A' ? 'B' : 'A') };
  ok(!accepted(r = await post(base, { challenge: forged, did: A.did, sig: A.sign(forged), bundle: A.bundle() }), A.did), `${name}: a challenge it never issued → rejected` + why(r));
  c = await get(base, A.did);
  ok(!accepted(r = await post(base, { challenge: c, did: B.did, sig: B.sign({ ...c, did: B.did }), bundle: B.bundle() }), B.did), `${name}: B answering a challenge issued to A → rejected` + why(r));
}

// The README shows the Express and Flask examples verbatim (the Go one is linked).
const readme = readFileSync(join(HERE, 'README.md'), 'utf8');
for (const f of ['node/example.mjs', 'python/example.py'])
  ok(readme.includes(readFileSync(join(HERE, f), 'utf8').trim()), `README.md shows ${f} verbatim`);
console.log(fails ? `FAILURES: ${fails}` : 'ALL PASS');
process.exit(fails ? 1 : 0);
