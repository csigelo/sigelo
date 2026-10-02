#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Mechanical grader for the docs-only lifecycle condition (docs-test/TASK-lifecycle.md).
//
//   node docs-test/grade.mjs <out-dir> [--now N] [--go PATH/TO/sigelo-verify] [--json]
//
// Reads the candidate's artifacts from <out-dir> (file names fixed by TASK-lifecycle.md; plus
// <out-dir>/_world/, the mock world's state, which docs-test/collect.sh copies there) and
// scores the ten points below with the repo's own verifiers: ts/dist (build it first:
// `cd ts && npx tsc`) and the Go reference `sigelo-verify` (--go, else $SIGELO_VERIFY, else
// built from go/ into a temp dir; needs `go` on PATH). No model grades anything. `now`
// defaults to the wall clock at grading time: grade right after the run, or pass --now.
// Prints a per-point PASS/FAIL table and SCORE n/10. Exit 0 always: it is a measurement.
//
//  1 genesis      genesis.json is a structurally valid genesis (§3.1, §4) and is the original
//                 `genesis` of each bundle that exists (a missing bundle costs points 3-9, not this)
//  2 recovery     genesis.recovery = "sha256:" + hex(SHA-256(raw recovery.pub)) (§4), and the
//                 recovery key is not the identity key
//  3 attestation  the harness world's attestation (issued.json; its issuer is _world's genesis)
//                 is to the original DID, and verify() accepts it verbatim under the world's DID
//                 in bundle.json AND bundle-recovered.json (reputation follows the chain)
//  4 binding      binding.json is method ed25519-test (§6.1a), its id is in the chain, and
//                 verify() reports it `proven` in bundle.json
//  5 rotation     rotation-voluntary.json is a voluntary rotation from the original DID, it is
//                 in bundle.json, and verify() gives chain [original, next] with the original
//                 recovery commitment still governing (§7, §7.2)
//  6 challenge    challenge-2.json is the world's outstanding five-field §5.2 challenge (nonce as in
//                 _world/challenge.local.json) naming the DID current after the rotation, and
//                 challenge-2.signed.json's sig verifies under THAT genesis's key, not the original
//  7 sigelo-verify  the Go reference verifier exits 0 on both bundles and prints the same §9.1
//                 result, by value, as ts verify()
//  8 recovery     rotation-recovery.json: reason recovery, recovery_key = recovery.pub, from the
//                 rotated DID. rotation-stolen.json: a FULLY VALID voluntary rotation from the
//                 same DID (signature by the leaked key, commitment carried) with a LATER iat.
//                 bundle-recovered.json holds all three rotations, verify() follows the recovery
//                 (chain [original, rotated, recovery.next]), and without the recovery rotation
//                 the same bundle would follow the thief's — so precedence (§7.1) decided it
//  9 invariants   every artifact parses strictly (no duplicate keys, no __proto__), carries no
//                 non-integer number, validates against schema/ for its slot (and challenge-*.signed
//                 is exactly {did, sig}); both results validate as verify-result and discarded
//                 nothing (rejected = 0/0)
// 10 report       report.json's "did" equals, in full, the current DID verify() computes for
//                 bundle-recovered.json
import { readFileSync, existsSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.join(here, '..');
const sigeloPath = path.join(repo, 'ts', 'dist', 'sigelo.js');
if (!existsSync(sigeloPath)) { console.error('grade.mjs: build ts first (cd ts && npm ci && npx tsc)'); process.exit(2); }
const S = await import(sigeloPath);

const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); return i < 0 ? undefined : args[i + 1]; };
const outDir = args.find((a, i) => !a.startsWith('--') && !['--now', '--go'].includes(args[i - 1]));
if (!outDir) { console.error('usage: grade.mjs <out-dir> [--now N] [--go PATH] [--json]'); process.exit(2); }
const now = opt('--now') !== undefined ? Number(opt('--now')) : Math.floor(Date.now() / 1000);
const asJson = args.includes('--json');

// ---- the schema validator of schema/check.mjs, reused verbatim (the section between its two
// "----" markers) so the grader cannot drift from what CI checks the vectors with
const schemaDir = path.join(repo, 'schema');
const V = (() => {
  const src = readFileSync(path.join(schemaDir, 'check.mjs'), 'utf8');
  const a = src.indexOf('// ---------------------------------------------------------------- the validator');
  const b = src.indexOf('// ---------------------------------------------------------------- the run');
  if (a < 0 || b < 0) return null;
  const readJSON = (p) => JSON.parse(readFileSync(p, 'utf8'));
  return new Function('fs', 'path', 'dir', 'readJSON', src.slice(a, b) + '\nreturn { check };')(fs, path, schemaDir, readJSON);
})();
const schema = (name, v) => (V ? V.check(name, v) : 'schema validator not found in schema/check.mjs');

// ---- artifacts
const FILES = ['recovery.pub', 'genesis.json', 'challenge-1.json', 'challenge-1.signed.json', 'issued.json', 'binding.json',
  'rotation-voluntary.json', 'challenge-2.json', 'challenge-2.signed.json', 'bundle.json', 'rotation-stolen.json',
  'rotation-recovery.json', 'bundle-recovered.json', 'report.json'];
const A = {};
for (const f of FILES) {
  const p = path.join(outDir, f);
  if (!existsSync(p)) { A[f] = { missing: true }; continue; }
  const text = readFileSync(p, 'utf8');
  if (f.endsWith('.pub')) { A[f] = { text, value: text.trim() }; continue; }
  try { A[f] = { text, value: S.parse(text) }; } catch (e) { A[f] = { text, err: `strict parse: ${e.message}` }; }
}
class Fail extends Error {}
const need = (f) => {
  const a = A[f];
  if (a.missing) throw new Fail(`missing ${f}`);
  if (a.err) throw new Fail(`${f}: ${a.err}`);
  return a.value;
};
const must = (cond, why) => { if (!cond) throw new Fail(why); };
const eq = (a, b) => {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => eq(x, b[i]));
  const ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
  return eq(ka, kb) && ka.every((k) => eq(a[k], b[k]));
};
const tsVerify = (f) => {
  const b = need(f);
  try { return S.verify(b, now); } catch (e) { throw new Fail(`ts verify(${f}) rejects: ${e.message}`); }
};
const memo = (fn) => { let done = false, v, err; return () => { if (!done) { done = true; try { v = fn(); } catch (e) { err = e; } } if (err) throw err; return v; }; };
const vB = memo(() => tsVerify('bundle.json'));
const vR = memo(() => tsVerify('bundle-recovered.json'));
const d0 = () => S.did(need('genesis.json'));
const rv = () => need('rotation-voluntary.json');
const d1 = () => rv().body.next;
// the world's own state, copied next to out/ by collect.sh: what proves issued.json and
// challenge-2.json came from examples/world.mjs and not from the candidate
const worldFile = (f) => {
  const p = path.join(outDir, '_world', f);
  if (!existsSync(p)) throw new Fail(`missing _world/${f} (collect with docs-test/collect.sh)`);
  return JSON.parse(readFileSync(p, 'utf8'));
};
const world = memo(() => worldFile('world.local.json'));
const hasRot = (bundle, r) => Array.isArray(bundle.rotations) && bundle.rotations.some((x) => eq(x, r));

// ---- the Go reference verifier
let goBin = opt('--go') ?? process.env.SIGELO_VERIFY, goNote = '', goTmp;
if (!goBin) {
  goTmp = mkdtempSync(path.join(tmpdir(), 'sigelo-grade-'));
  const exe = path.join(goTmp, process.platform === 'win32' ? 'sigelo-verify.exe' : 'sigelo-verify');
  const b = spawnSync('go', ['build', '-o', exe, './cmd/sigelo-verify'],
    { cwd: path.join(repo, 'go'), encoding: 'utf8', env: { ...process.env, CGO_ENABLED: '0' } });
  if (b.status === 0) goBin = exe;
  else goNote = `could not build go/cmd/sigelo-verify (${b.error?.code ?? b.stderr.trim().split('\n')[0]}); pass --go`;
}
const goVerify = (f) => {
  must(goBin, goNote);
  need(f);
  const p = spawnSync(goBin, [path.join(outDir, f), '--now', String(now)], { encoding: 'utf8' });
  must(p.status === 0, `sigelo-verify ${f} exit ${p.status}: ${(p.stderr || '').trim().split('\n')[0]}`);
  return JSON.parse(p.stdout);
};

// ---- the ten points
const points = [
  ['genesis', () => {
    const g = need('genesis.json');
    try { S.structure(g, 'genesis'); } catch (e) { throw new Fail(`genesis.json: ${e.message}`); }
    const present = ['bundle.json', 'bundle-recovered.json'].filter((f) => !A[f].missing);
    for (const f of present) must(eq(need(f).genesis, g), `${f} genesis ≠ genesis.json`);
    return `${d0()}${present.length < 2 ? ' (a bundle is missing: compared with ' + (present.join(', ') || 'none') + ')' : ''}`;
  }],
  ['recovery commitment', () => {
    const g = need('genesis.json'), pub = need('recovery.pub');
    let c;
    try { c = S.commitmentOf(pub); } catch (e) { throw new Fail(`recovery.pub is not a multibase Ed25519 key: ${e.message}`); }
    must(g.recovery === c, `genesis.recovery ${g.recovery} ≠ commitment of recovery.pub ${c}`);
    must(pub !== g.key, 'the recovery key IS the identity key');
    return c;
  }],
  ['attestation accepted', () => {
    const iss = need('issued.json');
    must(iss.attestation?.body && iss.issuer, 'issued.json is not the world\'s { attestation, issuer }');
    const w = S.did(iss.issuer);
    must(w === S.did(world().genesis), 'issued.json is not from the harness world (_world/world.local.json)');
    must(iss.attestation.body.sub === d0(), 'the attestation is not to the original DID');
    for (const [f, r] of [['bundle.json', vB], ['bundle-recovered.json', vR]])
      must((r().attestations[w] ?? []).some((b) => eq(b, iss.attestation.body)), `${f}: the world's attestation is not accepted (rejected: ${JSON.stringify(r().rejected)})`);
    return `iss ${w}`;
  }],
  ['binding proven', () => {
    const b = need('binding.json');
    must(b.body?.method === 'ed25519-test', `method ${JSON.stringify(b.body?.method)}, want "ed25519-test" (§6.1a)`);
    must(vB().chain.includes(b.body.id), 'binding id is not in the chain');
    const got = vB().bindings.find((x) => eq(x.body, b.body));
    must(got, `bundle.json: binding not accepted (rejected bindings ${vB().rejected.bindings})`);
    must(got.proof === 'proven', `proof "${got.proof}", want "proven"`);
    return got.proof;
  }],
  ['voluntary rotation', () => {
    const r = rv(), g = need('genesis.json');
    must(r.body?.reason === 'voluntary' && r.body.id === d0(), 'rotation-voluntary.json is not a voluntary rotation from the original DID');
    must(hasRot(need('bundle.json'), r), 'rotation-voluntary.json is not in bundle.json');
    must(eq(vB().chain, [d0(), r.body.next]), `chain ${JSON.stringify(vB().chain)}, want [original, rotation.next]`);
    must(vB().recovery === g.recovery, 'governing commitment changed');
    return `chain of ${vB().chain.length}`;
  }],
  ['challenge under the current key', () => {
    const c = need('challenge-2.json'), s = need('challenge-2.signed.json'), ng = rv().next_genesis;
    try { S.structure(c, 'challenge'); } catch (e) { throw new Fail(`challenge-2.json: ${e.message}`); }
    must(c.did === d1() && S.did(ng) === d1(), 'challenge-2.json does not name the DID current after the rotation');
    const wf = worldFile('challenge.local.json');       // DID -> body; older worlds kept one { did, nonce }
    const wc = typeof wf.did === 'string' ? wf : (Object.hasOwn(wf, c.did) ? wf[c.did] : {});   // an answered one is kept, marked { answered }
    must(wc.nonce === c.nonce && wc.did === c.did, 'challenge-2.json is not a challenge the world holds for that DID (_world/challenge.local.json)');
    must(s.did === c.did, 'challenge-2.signed.json did ≠ challenge did');
    must(S.verifySig(ng.key, c, s.sig), 'sig does not verify under the rotated key');
    must(!S.verifySig(need('genesis.json').key, c, s.sig), 'sig verifies under the ORIGINAL key');
    return 'rotated key';
  }],
  ['sigelo-verify exit 0', () => {
    for (const [f, r] of [['bundle.json', vB], ['bundle-recovered.json', vR]]) {
      const g = goVerify(f);
      must(eq(g, JSON.parse(JSON.stringify(r()))), `${f}: Go result ≠ ts result`);
    }
    return 'both bundles, Go = ts';
  }],
  ['recovery rotation + precedence', () => {
    const rr = need('rotation-recovery.json'), rs = need('rotation-stolen.json'), br = need('bundle-recovered.json');
    must(rr.body?.reason === 'recovery', 'rotation-recovery.json reason is not "recovery"');
    must(rr.body.recovery_key === need('recovery.pub'), 'recovery_key ≠ recovery.pub');
    must(rr.body.id === d1(), 'the recovery rotation is not from the rotated DID');
    must(rs.body?.reason === 'voluntary' && rs.body.id === rr.body.id, 'rotation-stolen.json is not a voluntary rotation from the same DID');
    must(rs.body.iat > rr.body.iat, `stolen iat ${rs.body.iat} is not later than recovery iat ${rr.body.iat}`);
    must(S.verifySig(rv().next_genesis.key, rs.body, rs.sig), 'stolen rotation is not signed by the leaked key');
    must(S.did(rs.next_genesis) === rs.body.next && rs.next_genesis.recovery === vB().recovery, 'stolen rotation is not fully valid (next hash or commitment)');
    for (const [n, r] of [['voluntary', rv()], ['recovery', rr], ['stolen', rs]]) must(hasRot(br, r), `bundle-recovered.json lacks the ${n} rotation`);
    must(eq(vR().chain, [d0(), d1(), rr.body.next]), `chain ${JSON.stringify(vR().chain)}, want [original, rotated, recovery.next]`);
    // the counterfactual: without the recovery rotation the thief's would be followed, so the
    // result above is precedence at work, not a stolen rotation that was invalid anyway
    let cf;
    try { cf = S.verify({ ...br, rotations: br.rotations.filter((x) => !eq(x, rr)) }, now); } catch (e) { throw new Fail(`without the recovery rotation the bundle rejects (${e.message}): the stolen rotation is not the lone valid voluntary one`); }
    must(cf.did === rs.body.next, 'without the recovery rotation the thief\'s rotation is not followed');
    return `current ${vR().did}`;
  }],
  ['invariants', () => {
    const bad = [];
    for (const f of FILES) {
      if (A[f].missing) { bad.push(`missing ${f}`); continue; }
      if (A[f].err) { bad.push(`${f}: ${A[f].err}`); continue; }
    }
    const floats = (v, at) => {
      if (typeof v === 'number' && !(Number.isSafeInteger(v))) bad.push(`${at}: non-integer or out-of-range number ${v}`);
      else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) floats(x, `${at}/${k}`);
    };
    for (const f of FILES) if (A[f].value !== undefined && f.endsWith('.json')) floats(A[f].value, f);
    const slot = [['genesis.json', 'genesis'], ['binding.json', 'binding-envelope'], ['rotation-voluntary.json', 'rotation-envelope'],
      ['rotation-stolen.json', 'rotation-envelope'], ['rotation-recovery.json', 'rotation-envelope'], ['challenge-1.json', 'challenge'],
      ['challenge-2.json', 'challenge'], ['bundle.json', 'bundle'], ['bundle-recovered.json', 'bundle']];
    for (const [f, s] of slot) if (A[f].value !== undefined) { const e = schema(s, A[f].value); if (e) bad.push(`${f} as ${s}: ${e}`); }
    const iss = A['issued.json'].value;
    if (iss) {
      for (const [v, s] of [[iss.attestation, 'attestation-envelope'], [iss.issuer, 'genesis']]) { const e = schema(s, v); if (e) bad.push(`issued.json ${s}: ${e}`); }
    }
    for (const f of ['challenge-1.signed.json', 'challenge-2.signed.json']) {
      const v = A[f].value;
      if (v && !(eq(Object.keys(v).sort(), ['did', 'sig']) && typeof v.did === 'string' && typeof v.sig === 'string')) bad.push(`${f} is not exactly { did, sig }`);
    }
    for (const [f, r] of [['bundle.json', vB], ['bundle-recovered.json', vR]]) {
      if (A[f].missing || A[f].err) continue;
      let res;
      try { res = JSON.parse(JSON.stringify(r())); } catch (e) { bad.push(e.message); continue; }
      const e = schema('verify-result', res); if (e) bad.push(`${f} result: ${e}`);
      if (!eq(res.rejected, { attestations: 0, bindings: 0 })) bad.push(`${f}: verify discarded items ${JSON.stringify(res.rejected)}`);
    }
    const rep = A['report.json'].value;
    if (rep && typeof rep.did !== 'string') bad.push('report.json has no string "did"');
    must(bad.length === 0, bad.join('; '));
    return `${FILES.length} artifacts`;
  }],
  ['reported DID', () => {
    const r = need('report.json');
    must(r.did === vR().did, `report.did ${JSON.stringify(r.did)} ≠ verified ${vR().did}`);
    return 'exact match';
  }],
];

const rows = points.map(([name, fn], i) => {
  try { return { n: i + 1, name, ok: true, detail: String(fn()) }; }
  catch (e) { return { n: i + 1, name, ok: false, detail: e instanceof Fail ? e.message : `grader exception: ${e.stack?.split('\n').slice(0, 2).join(' ')}` }; }
});
if (goTmp) rmSync(goTmp, { recursive: true, force: true });

// what to quote beside the score: the artifacts' digest, "sha256  name" lines like MANIFEST
const listing = readdirSync(outDir).sort().filter((f) => fs.statSync(path.join(outDir, f)).isFile())
  .map((f) => `${createHash('sha256').update(readFileSync(path.join(outDir, f))).digest('hex')}  ${f}\n`).join('');
const artifactDigest = createHash('sha256').update(listing).digest('hex');
const commit = spawnSync('git', ['rev-parse', '--short=7', 'HEAD'], { cwd: repo, encoding: 'utf8' }).stdout.trim();
const score = rows.filter((r) => r.ok).length;
if (asJson) console.log(JSON.stringify({ outDir: path.resolve(outDir), now, grader_commit: commit, artifact_digest: artifactDigest, score, of: 10, points: rows }, null, 1));
else {
  console.log(`out ${path.resolve(outDir)}  now ${now}  grader ${commit}  artifacts sha256 ${artifactDigest.slice(0, 16)}…`);
  for (const r of rows) console.log(`${String(r.n).padStart(2)} ${r.ok ? 'PASS' : 'FAIL'}  ${r.name.padEnd(32)} ${r.detail}`);
  console.log(`\nSCORE ${score}/10`);
}
