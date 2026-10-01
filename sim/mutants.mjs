// SPDX-License-Identifier: MIT
// sim/mutants.mjs — does the swarm's oracle notice a broken verifier?
//
//   node sim/mutants.mjs [--agents N] [--rounds R] [--seed S]      (defaults 120 agents, 30 rounds)
//
// Copies ts/dist to sim/out/mutants/<name>/, applies ONE deliberate bug to the copy (each one
// breaks an invariant from CLAUDE.md or a SPEC §5/§7.4/§9 rule), runs sim/swarm.mjs and
// sim/worlds.mjs against it with SIM_TS_DIST, and reports whether the runs produced findings
// ("killed (swarm+worlds)") or not ("SURVIVED" — a blind spot of the simulation). The repo's own
// ts/dist is never modified.
import { cpSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { availableParallelism } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(HERE);
const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i >= 0 ? process.argv[i + 1] : d; };
const agents = arg('agents', '120'), rounds = arg('rounds', '30'), seed = arg('seed', 'sigelo-swarm-1');

const MUTANTS = [
  ['fork-resolved', 'invariant 6a: a fork picks the first rotation', 'sigelo.js', 'else if (voluntary.length === 1) {', 'else if (voluntary.length >= 1) {'],
  ['recovery-by-iat', 'invariant 4: a newer voluntary rotation beats a recovery', 'sigelo.js', 'if (recovery.length) {',
    'if (recovery.length && !voluntary.some((v) => recovery.every((x) => v.body.iat > x.body.iat))) {'],
  ['commitment-not-carried', 'invariant 5: a voluntary rotation may change the commitment', 'sigelo.js', 'r.next_genesis.recovery === commitment);', 'true);'],
  ['recovery-tie-picks', '§7.4: two recoveries at one iat pick one', 'sigelo.js', 'if (recovery.filter((r) => r.body.iat === top).length > 1)', 'if (false)'],
  ['cycle-stops', 'invariant 6c: a cycle ends the chain instead of rejecting it', 'sigelo.js', 'throw new SigeloError(`chain: cycle back to ${chosen.body.next}`);', 'return { chain, recovery: commitment };'],
  ['malformed-item-fatal', 'invariant 7: a malformed attestation sinks the bundle', 'sigelo.js', 'bad.add(i);', 'throw e;'],
  ['expiry-inclusive', '§9 step 5: an attestation is still valid at now == exp', 'sigelo.js', '!(body.iat <= now && now < body.exp) || !chain.includes(body.sub)', '!(body.iat <= now && now <= body.exp) || !chain.includes(body.sub)'],
  ['sub-not-checked', '§9 step 5: an attestation to a DID outside the chain counts', 'sigelo.js', ' || !chain.includes(body.sub)) {', ') {'],
  ['unproven-is-proven', '§6.1: a binding without sig_addr reads as proven', 'sigelo.js', "proof = 'unproven'; // a claim only", "proof = 'proven'; // a claim only"],
  ['integrated-accepted', '§6.2: an integrated address proves a binding', 'monero.js', "if (decodeAddress(address).kind === 'integrated')", 'if (false)'],
  // Aimed at worlds.mjs's dishonest issuers (the swarm's worlds are honest).
  ['future-iat-accepted', '§9 step 5: an attestation dated in the future counts', 'sigelo.js', '!(body.iat <= now && now < body.exp) || !chain.includes(body.sub)', '!(now < body.exp) || !chain.includes(body.sub)'],
  ['att-sig-unchecked', '§5: an attestation is not checked against its issuer key', 'sigelo.js', 'iss === undefined || !verifySig(iss.key, body, a.sig) ||', 'iss === undefined ||'],
  ['issuer-structure-unchecked', '§9 step 2: a malformed issuer genesis is not fatal', 'sigelo.js', "for (const g of bundle.issuers)\n        structure(g, 'genesis');", ''],
];

// Each mutant runs through swarm.mjs AND worlds.mjs (in-process, no Go): killed if either reports.
function run1(dist, script, args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [join(HERE, script), ...args, '--no-go'],
      { env: { ...process.env, SIM_TS_DIST: dist, SIM_OUT: join(dirname(dist), 'out') }, maxBuffer: 1 << 26, timeout: 900_000 },
      (err, stdout) => {
        const last = stdout.trim().split('\n').pop() ?? '';
        try { resolve({ findings: JSON.parse(last).findings }); } catch { resolve({ error: err ? String(err.message).slice(0, 200) : 'no summary' }); }
      });
  });
}
async function run(dist) {
  const [sw, wo] = [await run1(dist, 'swarm.mjs', ['--agents', agents, '--rounds', rounds, '--seed', seed]), await run1(dist, 'worlds.mjs', [])];
  if (sw.error || wo.error) return { error: sw.error ?? wo.error };
  return { findings: sw.findings + wo.findings, swarm: sw.findings, worlds: wo.findings };
}

const base = join(HERE, 'out', 'mutants');
rmSync(base, { recursive: true, force: true });
const t0 = Date.now();
const results = [];
let next = 0;
const lanes = Math.max(1, Math.floor(availableParallelism() / 3));
await Promise.all(Array.from({ length: lanes }, async () => {
  while (next < MUTANTS.length) {
    const [name, what, file, from, to] = MUTANTS[next++];
    const dir = join(base, name);
    mkdirSync(dir, { recursive: true });
    cpSync(join(ROOT, 'ts', 'dist'), join(dir, 'dist'), { recursive: true });
    symlinkSync(join(ROOT, 'ts', 'node_modules'), join(dir, 'node_modules'));
    const p = join(dir, 'dist', file);
    const src = readFileSync(p, 'utf8');
    if (!src.includes(from)) { results.push({ name, what, status: 'NOT APPLIED (pattern missing — update sim/mutants.mjs)' }); continue; }
    writeFileSync(p, src.replace(from, to));
    const r = await run(join(dir, 'dist'));
    results.push({ name, what, status: r.error ? `ERROR ${r.error}` : r.findings > 0 ? `killed (${r.swarm}+${r.worlds})` : 'SURVIVED', findings: r.findings, swarm: r.swarm, worlds: r.worlds });
  }
}));
results.sort((a, b) => MUTANTS.findIndex((m) => m[0] === a.name) - MUTANTS.findIndex((m) => m[0] === b.name));
for (const r of results) console.log(`${r.status.padEnd(24)} ${r.name.padEnd(24)} ${r.what}`);
const survived = results.filter((r) => !r.status.startsWith('killed')).length;
console.log(`\n${results.length - survived}/${results.length} mutants killed, ${Math.round((Date.now() - t0) / 1000)} s`);
writeFileSync(join(HERE, 'out', 'mutants.json'), JSON.stringify(results, null, 1));
process.exitCode = survived ? 1 : 0;
