// SPDX-License-Identifier: MIT
// world/conformance.mjs — what POST /world/conformance needs besides the §5.2 flow, kept pure:
// how many cases `sigelo-verify --conformance --impl` (and docs-test/grade-verifier.mjs) build
// from a vectors file, and a strict reader of the summary that runner prints. See world/README.md.

// The number of bundle cases grade-verifier.mjs builds from test-vectors.json, counted the way it
// adds them (go/cmd/sigelo-verify/impl.go builds the same list). Keep in step with that file:
// world/test.mjs compares this count with a real --impl run over the same vectors.
export function countCases(T) {
  const N = T.negative;
  let n = 0;
  n += 2;   // positive: bundle, bundle_minimal == expect
  n += 3;   // positive: genesis, world_genesis, member_genesis did
  n += 2;   // positive: attestation, attestation_unicode accepted
  n += 2;   // positive: a challenge in the attestation slot, an invoice in the binding slot
  n += 5;   // positive/monero: binding, binding_unproven, binding_monero, two subaddress bindings
  n += 3;   // positive: expected_chain, the same reversed, chain_precedence_only
  n += 8;   // negative: attestations discarded
  n += 2;   // negative: duplicate_key, proto_key in bundle text
  n += 1;   // negative: genesis_tampered
  n += 2;   // negative: unknown_field_genesis, genesis_bad_key
  n += 4;   // negative: not-a-candidate rotations
  n += 3;   // negative: fork, cycle, self_rotation
  n += 1;   // negative: bundle_rotations_not_array
  for (const x of Object.values(N)) if (x && typeof x === 'object' && 'sig_id' in x) n++;   // bindings discarded
  n += Object.keys(N.parity.cases).length;                                                   // parity
  return n;
}

// The lines runImpl (go/cmd/sigelo-verify/impl.go) prints, as regular expressions over its formats:
//   "PASS "+name | "FAIL "+name+" — "+why | "%-9s %d/%d" | "not expressible …: …" | "%d passed, %d failed" | ALL PASS | FAILURES
const PASS = /^PASS \S/, FAIL = /^FAIL \S/, GROUP = /^([a-z]+) +(\d+)\/(\d+)$/, TOTAL = /^(\d+) passed, (\d+) failed$/;
const INEXPRESSIBLE = /^not expressible through the bundle interface \(not scored\): /;

// → { passed, total } for a clean run; throws a reason (a string) for anything else.
export function readSummary(text, want) {
  if (typeof text !== 'string' || !text.trim()) throw 'results: paste the summary lines `sigelo-verify --conformance --impl` printed';
  let totals = null, allPass = false, passLines = 0, gPass = 0, gTotal = 0, groups = 0;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    let m;
    if (line.trim() === '') continue;
    if (PASS.test(line)) passLines++;
    else if (FAIL.test(line)) throw `results: a case failed: ${line.slice(0, 120)}`;
    else if (INEXPRESSIBLE.test(line)) continue;
    else if ((m = GROUP.exec(line))) {
      const [p, t] = [Number(m[2]), Number(m[3])];
      if (p !== t) throw `results: group ${m[1]} passed ${p} of ${t}`;
      gPass += p; gTotal += t; groups++;
    } else if ((m = TOTAL.exec(line))) {
      if (totals) throw 'results: more than one "N passed, M failed" line';
      totals = { passed: Number(m[1]), failed: Number(m[2]) };
    } else if (line === 'ALL PASS') allPass = true;
    else if (line === 'FAILURES') throw 'results: the run ended in FAILURES';
    else throw `results: not a line sigelo-verify --impl prints: ${JSON.stringify(line.slice(0, 80))}`;
  }
  if (!totals) throw 'results: no "N passed, M failed" line';
  const total = totals.passed + totals.failed;
  if (totals.failed !== 0) throw `results: ${totals.passed}/${total}: every case must pass`;
  if (!allPass) throw 'results: no ALL PASS line';
  if (groups && (gPass !== totals.passed || gTotal !== total)) throw `results: the group lines add up to ${gPass}/${gTotal}, not ${totals.passed}/${total}`;
  if (passLines && passLines !== totals.passed) throw `results: ${passLines} PASS lines for ${totals.passed} passed`;
  if (total !== want) throw `results: ${totals.passed}/${total}, but these vectors make ${want} cases: run the runner over the vectors this world ships`;
  return { passed: totals.passed, total };
}
