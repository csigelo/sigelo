#!/usr/bin/env node
// ts/ as a candidate for `sigelo-verify --conformance --impl` (and docs-test/grade-verifier.mjs):
// the TASK-verifier.md interface over ts/dist (run `npx tsc` in ts/ first).
//
//   node ts-candidate.mjs [--break] <bundle.json|-> --now <N>
//
// Accepted: the §9.1 result as JCS on stdout, exit 0. Rejected (a SigeloError or JcsError, i.e.
// §9 fatal): "REJECT: <check>" on stderr, exit 1. Anything else thrown is a crash, exit 3.
// --break is the deliberately wrong candidate the runner must catch: it reports every
// `unproven` binding as `proven` (a verifier that never looks for sig_addr).
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const dist = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'ts', 'dist');
const { verify, SigeloError } = await import(pathToFileURL(path.join(dist, 'sigelo.js')).href);
const { parseBytes, canonicalize, JcsError } = await import(pathToFileURL(path.join(dist, 'jcs.js')).href);

const args = process.argv.slice(2);
const broken = args[0] === '--break' && args.shift();
const [file, flag, now] = args;
if (!file || flag !== '--now' || !/^\d+$/.test(now ?? '')) { console.error('usage: ts-candidate.mjs [--break] <bundle.json|-> --now N'); process.exit(2); }
try {
  const r = verify(parseBytes(readFileSync(file === '-' ? 0 : file)), Number(now));
  if (broken) for (const b of r.bindings) if (b.proof === 'unproven') b.proof = 'proven';
  console.log(canonicalize(r));
} catch (e) {
  if (!(e instanceof SigeloError || e instanceof JcsError)) { console.error(e); process.exit(3); }
  console.error(`REJECT: ${e.message}`);
  process.exit(1);
}
