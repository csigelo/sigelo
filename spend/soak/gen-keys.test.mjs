#!/usr/bin/env node
// node spend/soak/gen-keys.test.mjs — gen-keys.mjs keys a soak in a scratch directory without
// touching the repository: the tracked policy.template.json is byte-identical (sha256) after a full
// run (keys, policy, check, a second policy run), and the policy.json it writes carries keys/'
// identities and the wallet's subaddresses. The wallet-rpc is a stub on a random local port
// (SIGELO_SOAK_WALLET_RPC), so no live soak or wallet is asked. The licence step: a bare run issues
// keeper/licence.json under the soak's TEST vendor, keeps it on a rerun, check verifies it, and an
// altered or missing licence fails check. Needs ts/ and spend/ built (npx tsc in each).
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const GEN = join(HERE, 'gen-keys.mjs'), TEMPLATE = join(HERE, 'policy.template.json');
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const addr = (i) => `5stub${String(i).padStart(3, '0')}${'x'.repeat(87)}`;

const server = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const { method, params } = JSON.parse(body);
    const i = params?.address_index?.[0];
    res.end(JSON.stringify(method === 'get_address' ? { jsonrpc: '2.0', id: '0', result: { addresses: [{ address: addr(i), address_index: i }] } }
      : { jsonrpc: '2.0', id: '0', error: { code: -1, message: `stub: ${method}` } }));
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const RPC = `http://127.0.0.1:${server.address().port}/json_rpc`;

const scratch = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'gen-keys-test-'));
const env = { ...process.env, SIGELO_SOAK_DIR: scratch, SIGELO_SOAK_WALLET_RPC: RPC };
const run = (...args) => new Promise((resolve) => execFile('node', [GEN, ...args], { env }, (err, stdout, stderr) => resolve({ code: err ? err.code ?? 1 : 0, out: stdout + stderr })));

let failed = 0;
const ok = (cond, what) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${what}`); if (!cond) failed++; };

const before = sha(TEMPLATE);
try {
  const keeper = join(scratch, 'keeper');
  const r0 = await run();
  ok(r0.code === 0 && existsSync(join(scratch, 'keys', 'S.hex')), `gen-keys.mjs creates keys/ in the scratch dir (${r0.out.trim().split('\n').at(-1)})`);
  ok(sha(TEMPLATE) === before, 'template unchanged after a bare run');
  const { parseRoot } = await import(new URL('../../ts/dist/keys.js', import.meta.url).href);
  let canon = true; try { parseRoot(readFileSync(join(scratch, 'keys', 'S.hex'), 'utf-8')); } catch { canon = false; }
  ok(canon, 'keys/S.hex is a canonical root (sigelo-offline recover accepts it)');
  ok(existsSync(join(keeper, 'licence.json')) && existsSync(join(scratch, 'keys', 'vendor.hex')) && /wrote .*licence\.json: tier pro/.test(r0.out), 'a bare run creates the test vendor and issues keeper/licence.json, tier pro');
  const vendorBefore = readFileSync(join(scratch, 'keys', 'vendor.json'), 'utf-8'), licBefore = readFileSync(join(keeper, 'licence.json'), 'utf-8');
  const rl = await run('licence');
  ok(rl.code === 0 && rl.out.includes('kept') && readFileSync(join(scratch, 'keys', 'vendor.json'), 'utf-8') === vendorBefore && readFileSync(join(keeper, 'licence.json'), 'utf-8') === licBefore, 'a second licence run keeps the vendor key and the licence byte for byte');
  const empty = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'gen-keys-empty-'));
  const nk = await new Promise((resolve) => execFile('node', [GEN, 'licence'], { env: { ...env, SIGELO_SOAK_DIR: empty } }, (err, o, e) => resolve({ code: err ? err.code ?? 1 : 0, out: o + e })));
  ok(nk.code !== 0 && nk.out.includes('keeper key') && !existsSync(join(empty, 'keys')), 'licence refuses where the keeper key\'s root (keys/S.hex) is absent, creating nothing');
  rmSync(empty, { recursive: true, force: true });
  const rc = await run('check', keeper);
  ok(rc.code !== 0, 'check fails while there is no policy.json');
  const { mkdirSync } = await import('node:fs');
  mkdirSync(keeper, { recursive: true, mode: 0o700 }); // the bare run's licence step made it
  const r1 = await run('policy', keeper);
  ok(r1.code === 0, `policy writes ${keeper}/policy.json`);
  const pol = JSON.parse(readFileSync(join(keeper, 'policy.json'), 'utf-8'));
  ok(!JSON.stringify(pol).includes('"<'), 'policy.json has no placeholder left');
  ok(pol.agents['soak-root'].allow.map((e) => e.addr).join() === [addr(1), addr(2)].join(), 'allowlist = the wallet-rpc\'s subaddresses 0/1, 0/2');
  ok(pol.wallet.rpc === RPC, 'policy.json names the wallet-rpc it was filled from');
  ok(typeof pol.agents['soak-root'].genesis === 'object' && pol.agents['soak-root'].did.startsWith('did:sigelo:'), 'soak-root identity filled from keys/');
  const ck = await run('check', keeper);
  ok(ck.code === 0 && ck.out.includes('licence ok: tier pro'), 'check passes on the written policy.json and the licence (tier pro)');
  const { renameSync } = await import('node:fs');
  const lic = join(keeper, 'licence.json'), tampered = JSON.parse(licBefore);
  tampered.attestation.body.claims.seats = 99;
  writeFileSync(lic, JSON.stringify(tampered));
  ok((await run('check', keeper)).code !== 0, 'check fails on a licence altered after issue');
  ok((await run('licence')).code !== 0, 'licence refuses to keep a licence that does not verify (without --reissue)');
  writeFileSync(lic, licBefore);
  renameSync(lic, lic + '.away');
  ok((await run('check', keeper)).code !== 0, 'check fails without licence.json');
  renameSync(lic + '.away', lic);
  const r2 = await run('policy', keeper);
  ok(r2.code === 0 && r2.out.includes('kept'), 'a second policy run keeps policy.json');
  // README steps 5–6 on this soak's own root: the recovery rotation of soak-root to keeper 1's (0, 0).
  const g = join(scratch, 'soak-root.genesis.json');
  writeFileSync(g, JSON.stringify(pol.agents['soak-root']));
  const rec = await new Promise((resolve) => {
    const c = execFile('node', [join(HERE, '..', '..', 'ts', 'dist', 'offline.js'), 'recover', '--genesis', g, '-', '--agent', '0', '--keeper', '1', '--n', '0'],
      (err, stdout) => resolve({ code: err ? err.code ?? 1 : 0, out: stdout }));
    c.stdin.end(readFileSync(join(scratch, 'keys', 'S.hex')));
  });
  let rot = null; try { rot = JSON.parse(rec.out).rotation?.body; } catch { /* reported below */ }
  ok(rec.code === 0 && rot?.id === pol.agents['soak-root'].did && rot?.reason === 'recovery', 'sigelo-offline recover - < keys/S.hex signs soak-root\'s recovery rotation (README step 5)');
  // The keeper's own DID (INCIDENT.md §5): identity.json commits to the root's recovery key, the licence names
  // its DID, and sigelo-offline recover --new-keeper rotates it from keys/S.hex alone.
  const S = readFileSync(join(scratch, 'keys', 'S.hex'), 'utf-8').trim();
  const { recoveryCommitment, keeperRoot } = await import(new URL('../../ts/dist/keys.js', import.meta.url).href);
  const { did, verify } = await import(new URL('../../ts/dist/sigelo.js', import.meta.url).href);
  const unhex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
  const idj = JSON.parse(readFileSync(join(keeper, 'identity.json'), 'utf-8'));
  const RC = recoveryCommitment(unhex(S));
  ok(idj.typ === 'bundle' && idj.genesis.recovery === RC && JSON.parse(licBefore).attestation.body.sub === did(idj.genesis) && ck.out.includes('keeper identity: recoverable'),
    'policy writes identity.json: the keeper genesis commits to recoveryCommitment(S), and the licence (issued before it) names that DID');
  const kr = await new Promise((resolve) => {
    const c = execFile('node', [join(HERE, '..', '..', 'ts', 'dist', 'offline.js'), 'recover', '--genesis', join(keeper, 'identity.json'), '-', '--new-keeper', '1'],
      (err, stdout) => resolve({ code: err ? err.code ?? 1 : 0, out: stdout }));
    c.stdin.end(S);
  });
  let ko = null; try { ko = JSON.parse(kr.out); } catch { /* reported below */ }
  ok(kr.code === 0 && ko?.did === did(idj.genesis) && ko?.keeper_root_hex === Buffer.from(keeperRoot(unhex(S), 1)).toString('hex') &&
    verify(ko.bundle, Math.floor(Date.now() / 1000)).chain[0] === did(idj.genesis), 'sigelo-offline recover --new-keeper 1 - < keys/S.hex recovers the keeper DID (a chain of two)');
  // A soak keyed before identity.json: spend.key and no identity.json — kept as is, legacy DID, said so.
  const legacy = join(scratch, 'legacy-keeper');
  mkdirSync(legacy, { recursive: true, mode: 0o700 });
  writeFileSync(join(legacy, 'spend.key'), Buffer.from(keeperRoot(unhex(S), 0)).toString('hex') + '\n', { mode: 0o600 });
  const rl2 = await run('policy', legacy);
  ok(rl2.code === 0 && !existsSync(join(legacy, 'identity.json')) && rl2.out.includes('NOT recoverable'), 'policy on a pre-identity.json keeper keeps its legacy DID (writes no identity.json) and says it is not recoverable');
  ok(sha(TEMPLATE) === before, `template sha256 unchanged after keys + policy + check (${before.slice(0, 16)}…)`);
} finally {
  server.close();
  rmSync(scratch, { recursive: true, force: true });
}
console.log(failed ? `${failed} FAILED` : 'all passed');
process.exit(failed ? 1 : 0);
