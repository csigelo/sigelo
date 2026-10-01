#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// site/test/grade-site.mjs — grades a TASK-site.md run: 6 points, each a mechanical check.
//
//   node site/test/grade-site.mjs <run-dir> --verify <sigelo-verify binary> [--now N]
//
// <run-dir> holds the candidate's out/ files and, in <run-dir>/_world/, the world's own state
// (world.local.json from the candidate's $W), which proves issued.json came from the served
// mock world. Needs ts/dist (cd ts && npm ci && npx tsc). Running a round: site/README.md.
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const lib = path.join(repo, 'ts', 'dist', 'sigelo.js');
if (!existsSync(lib)) { console.error('grade-site.mjs: build ts first (cd ts && npm ci && npx tsc)'); process.exit(2); }
const S = await import(lib);
const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); return i < 0 ? undefined : args[i + 1]; };
const dir = args.find((a, i) => !a.startsWith('--') && !['--verify', '--now'].includes(args[i - 1]));
const bin = opt('--verify');
if (!dir || !bin) { console.error('usage: grade-site.mjs <run-dir> --verify <sigelo-verify> [--now N]'); process.exit(2); }
const now = opt('--now') !== undefined ? Number(opt('--now')) : Math.floor(Date.now() / 1000);

class Fail extends Error {}
const must = (c, why) => { if (!c) throw new Fail(why); };
const file = (f) => { const p = path.join(dir, f); must(existsSync(p), `missing ${f}`); return readFileSync(p, 'utf8'); };
const json = (f) => { try { return S.parse(file(f)); } catch (e) { if (e instanceof Fail) throw e; throw new Fail(`${f}: strict parse: ${e.message}`); } };
const eq = (a, b) => JSON.stringify(S.canonicalize(a)) === JSON.stringify(S.canonicalize(b));
const verified = () => { try { return S.verify(json('bundle.json'), now); } catch (e) { throw new Fail(`ts verify(bundle.json) rejects: ${e.message}`); } };
const world = () => { const p = path.join(dir, '_world', 'world.local.json'); must(existsSync(p), 'missing _world/world.local.json'); return JSON.parse(readFileSync(p, 'utf8')); };

const points = [
  ['recovery commitment', () => {
    const pub = file('recovery.pub').trim();
    must(/^z6Mk[1-9A-HJ-NP-Za-km-z]+$/.test(pub), 'recovery.pub is not one bare z6Mk… line');
    const g = json('genesis.json');
    S.structure(g, 'genesis');
    must(g.recovery === S.commitmentOf(pub), `genesis.recovery ${g.recovery} is not the commitment of recovery.pub`);
    must(g.key !== pub, 'the recovery key is the identity key');
  }],
  ['bundle carries this identity', () => {
    must(eq(json('bundle.json').genesis, json('genesis.json')), 'bundle.json genesis is not genesis.json');
    must(verified().chain[0] === S.did(json('genesis.json')), 'chain does not start at the DID of genesis.json');
  }],
  ['challenge answered', () => {
    const c = json('challenge.json'), a = json('challenge.signed.json'), g = json('genesis.json');
    S.structure(c, 'challenge');
    must(Object.keys(a).sort().join() === 'did,sig', 'challenge.signed.json is not exactly {did, sig}');
    must(c.did === S.did(g) && a.did === c.did, 'challenge or answer does not name the agent DID');
    must(S.verifySig(g.key, c, a.sig), 'the signature does not verify over challenge.json under the genesis key');
  }],
  ['attested by the served world', () => {
    const w = world(), wd = S.did(w.genesis), issued = json('issued.json'), r = verified();
    must(eq(issued.issuer, w.genesis), 'issued.json issuer is not the mock world the candidate ran');
    must(issued.attestation.body.sub === S.did(json('genesis.json')), 'the attestation is not to the agent DID');
    must((r.attestations[wd] ?? []).length >= 1, 'verify() accepts no attestation from the world');
    must(r.rejected.attestations === 0 && r.rejected.bindings === 0, 'verify() discarded something');
  }],
  ['sigelo-verify accepts', () => {
    const out = spawnSync(bin, [path.join(dir, 'bundle.json'), '--now', String(now)], { encoding: 'utf8' });
    must(out.status === 0, `sigelo-verify exit ${out.status}: ${out.stderr.trim()}`);
    must(eq(JSON.parse(out.stdout), verified()), 'sigelo-verify and ts verify() disagree');
    let printed; try { printed = JSON.parse(file('verify.txt')); } catch (e) { if (e instanceof Fail) throw e; throw new Fail('verify.txt is not the JSON sigelo-verify prints'); }
    must(eq(printed, JSON.parse(out.stdout)), 'verify.txt is not sigelo-verify\'s output for bundle.json');
  }],
  ['report', () => {
    const r = json('report.json');
    must(r.did === verified().did, `report.json did ${r.did} is not the current DID ${verified().did}`);
    must(/^sigelo-verify-(linux|darwin)-(amd64|arm64)$|^sigelo-verify-windows-amd64\.exe$/.test(r.verifier ?? ''), 'report.json verifier is not a release binary name');
    must(r.sha256_ok === true, 'report.json does not say the binary matched SHA256SUMS');
  }],
];
let score = 0;
for (const [i, [name, check]] of points.entries()) {
  try { check(); score++; console.log(`PASS ${i + 1} ${name}`); }
  catch (e) { console.log(`FAIL ${i + 1} ${name}: ${e instanceof Fail ? e.message : e.stack}`); }
}
console.log(`SCORE ${score}/${points.length}`);
