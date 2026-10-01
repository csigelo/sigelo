#!/usr/bin/env node
// Mechanical grader for the spec-only verifier condition (docs-test/TASK-verifier.md).
//
//   node docs-test/grade-verifier.mjs [--vectors FILE] [--timeout MS] [--verbose] [--json] -- <cmd> [args...]
//
// Every case is a bundle FILE handed to the candidate as `<cmd> [args...] <file> --now <N>`,
// the interface of go/cmd/sigelo-verify (TASK-verifier.md). The candidate must print the SPEC
// §9.1 result as JSON on stdout and exit 0, or exit 1 to reject. Cases are built from
// test-vectors.json the way go/conformance.go builds its checks, wrapped into bundles, so the
// whole score is observable through one command:
//
//   result   exit 0, stdout parses as JSON, compared BY VALUE with the vector's `expect` on the
//            §9.1 conformance surface (the six fields; body + proof per binding; extras ignored)
//   check    exit 0, and the named fields of the result are as the vector says
//   reject   exit 1 (a crash that happens to exit 1 is indistinguishable; the positive cases are
//            what catch a verifier that rejects everything)
//
// Vectors that cannot be expressed as a bundle (invoices never enter one, §6.3) are listed as
// not expressible and are not in the denominator. Prints one PASS/FAIL line per case and
// `N/M`. Exit 0 always: this is a measurement, not a gate.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const dd = argv.indexOf('--');
if (dd < 0 || dd === argv.length - 1) {
  console.error('usage: grade-verifier.mjs [--vectors FILE] [--timeout MS] [--verbose] [--json] -- <cmd> [args...]');
  process.exit(2);
}
const opts = argv.slice(0, dd), cmd = argv.slice(dd + 1);
const opt = (k, d) => { const i = opts.indexOf(k); return i < 0 ? d : opts[i + 1]; };
const vectorsPath = opt('--vectors', path.join(here, '..', 'test-vectors.json'));
const timeout = Number(opt('--timeout', 20000));
const verbose = opts.includes('--verbose'), asJson = opts.includes('--json');

const text = readFileSync(vectorsPath, 'utf8');
// Cases are re-serialized from JSON.parse. That is only faithful if no number token changes
// on the round trip (1.0 would become 1 and a float case would silently turn valid).
{
  const lossy = [];
  for (let i = 0; i < text.length;) {
    if (text[i] === '"') { i++; while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1; i++; continue; }
    if (/[-0-9]/.test(text[i])) { let j = i; while (/[-+.eE0-9]/.test(text[j])) j++; const t = text.slice(i, j); if (String(Number(t)) !== t) lossy.push(t); i = j; continue; }
    i++;
  }
  if (lossy.length) { console.error(`grade-verifier: vectors hold number spellings JSON.parse does not preserve (${lossy.join(', ')}); extend the grader to splice raw text`); process.exit(2); }
}
const T = JSON.parse(text);
const P = T.vectors, N = T.negative, NOW = T.now;
const G0 = P.genesis.doc, W = P.world_genesis.doc;

const bundle = (o = {}) => ({ v: 'sigelo/0', typ: 'bundle', genesis: G0, rotations: [], bindings: [], attestations: [], issuers: [], ...o });
const env = (x, ks) => Object.fromEntries(ks.filter((k) => k in x).map((k) => [k, x[k]]));
const rot = (x) => env(x, ['body', 'sig', 'next_genesis']);
const bnd = (x) => env(x, ['body', 'sig_id', 'sig_addr']);
const ROT = ['rotation_voluntary', 'rotation_hostile', 'rotation_hostile_carried', 'rotation_recovery', 'rotation_recovery_second'];

const eq = (a, b) => {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => eq(x, b[i]));
  const ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
  return eq(ka, kb) && ka.every((k) => eq(a[k], b[k]));
};
// §9.1: "the fields above are the conformance surface"; implementations MAY attach per-item
// reasons alongside, and §6.2 says a verifier SHOULD report the Monero signing mode. So only the
// six fields are compared, and of a binding entry only body and proof; anything else is ignored.
const surface = (r) => (r && typeof r === 'object' ? {
  did: r.did, chain: r.chain, recovery: r.recovery, attestations: r.attestations,
  bindings: Array.isArray(r.bindings) ? r.bindings.map((b) => ({ body: b?.body, proof: b?.proof })) : r.bindings,
  rejected: r.rejected && typeof r.rejected === 'object' ? { attestations: r.rejected.attestations, bindings: r.rejected.bindings } : r.rejected,
} : r);
const nAtt = (r) => Object.values(r.attestations ?? {}).reduce((n, xs) => n + (Array.isArray(xs) ? xs.length : 0), 0);
const proofs = (r) => (r.bindings ?? []).map((b) => b.proof);
const want = (cond, why) => (cond ? null : why);

// Each case: { name, group, text | bundle, now, kind: 'result'|'check'|'reject', expect | fn }
const cases = [], inexpressible = [];
const add = (c) => cases.push({ now: NOW, ...c });

// ---- positive: the two bundles with a full §9.1 expectation
for (const n of ['bundle', 'bundle_minimal']) add({ group: 'positive', name: `${n} == expect`, bundle: P[n].bundle, now: P[n].now, kind: 'result', expect: P[n].expect });

// ---- positive: genesis → DID (§4)
for (const n of ['genesis', 'world_genesis', 'member_genesis'])
  add({ group: 'positive', name: `${n} did`, bundle: bundle({ genesis: P[n].doc }), kind: 'check',
    fn: (r) => want(r.did === P[n].expect_did && eq(r.chain, [P[n].expect_did]), `did/chain ≠ ${P[n].expect_did}`) });

// ---- positive: attestations (§5, §3 JCS via the unicode claims)
for (const n of ['attestation', 'attestation_unicode'])
  add({ group: 'positive', name: `${n} accepted`, bundle: bundle({ attestations: [env(P[n], ['body', 'sig'])], issuers: [W] }), kind: 'check',
    fn: (r) => want(eq(r.attestations, { [P[n].body.iss]: [P[n].body] }) && eq(r.rejected, { attestations: 0, bindings: 0 }), 'not accepted verbatim under its iss') });

// ---- positive: typ binding (§3). A challenge and an invoice fit no bundle slot.
add({ group: 'positive', name: 'challenge presented as an attestation is discarded', bundle: bundle({ attestations: [env(P.challenge, ['body', 'sig'])], issuers: [W] }),
  kind: 'check', fn: (r) => want(nAtt(r) === 0 && r.rejected?.attestations === 1, 'challenge accepted in the attestation slot') });
add({ group: 'positive', name: 'invoice presented as a binding is discarded', bundle: bundle({ bindings: [{ body: P.invoice.body, sig_id: P.invoice.sig }] }),
  kind: 'check', fn: (r) => want(proofs(r).length === 0 && r.rejected?.bindings === 1, 'invoice accepted in the binding slot') });

// ---- positive: bindings and their proof status (§6.1, §6.1a, §6.2)
for (const [n, p] of [['binding', 'proven'], ['binding_unproven', 'unproven'], ['binding_monero', 'proven'],
  ['binding_monero_subaddress_spend', 'proven'], ['binding_monero_subaddress_view', 'proven']])
  add({ group: n.includes('monero') ? 'monero' : 'positive', name: `${n} → ${p}`, bundle: bundle({ bindings: [bnd(P[n])] }), kind: 'check',
    fn: (r) => want(eq(r.bindings, [{ body: P[n].body, proof: p }]) && r.rejected?.bindings === 0, `bindings ${JSON.stringify(proofs(r))}, want ["${p}"]`) });

// ---- positive: chains (§7)
add({ group: 'positive', name: 'expected_chain (all five rotations)', bundle: bundle({ rotations: ROT.map((n) => rot(P[n])) }), kind: 'check',
  fn: (r) => want(eq(r.chain, P.expected_chain) && r.did === P.expected_chain.at(-1), 'chain ≠ expected_chain') });
add({ group: 'positive', name: 'expected_chain (rotations in reverse array order)', bundle: bundle({ rotations: ROT.map((n) => rot(P[n])).reverse() }), kind: 'check',
  fn: (r) => want(eq(r.chain, P.expected_chain), 'chain depends on array order') });
add({ group: 'positive', name: 'chain_precedence_only', bundle: bundle({ rotations: P.chain_precedence_only.rotations.map((n) => rot(P[n])) }), kind: 'check',
  fn: (r) => want(eq(r.chain, P.chain_precedence_only.expected_chain), 'chain ≠ expected (precedence §7.1)') });

// ---- negatives: attestations discarded individually (§9 steps 2, 5)
const A = P.attestation;
for (const n of ['tampered_claims', 'wrong_signer', 'missing_prefix', 'typ_mismatch', 'unknown_field_attestation', 'expired_attestation', 'float_in_claims', 'int_out_of_range']) {
  const x = N[n];
  // float_in_claims / int_out_of_range carry only v/typ/claims: grafted onto the positive attestation, as schema/check.mjs does
  const body = x.sig ? x.body : { ...A.body, claims: x.body.claims };
  add({ group: 'negative', name: `neg ${n} discarded`, bundle: bundle({ attestations: [{ body, sig: x.sig ?? A.sig }], issuers: [W] }), kind: 'check',
    fn: (r) => want(nAtt(r) === 0 && r.rejected?.attestations === 1, 'attestation accepted') });
}
// duplicate key / __proto__ anywhere in the bundle TEXT is fatal (§3)
for (const n of ['duplicate_key', 'proto_key']) {
  const t = JSON.stringify(bundle({ attestations: ['@@RAW@@'], issuers: [W] })).replace('"@@RAW@@"', `{"body":${N[n].raw},"sig":${JSON.stringify(A.sig)}}`);
  add({ group: 'negative', name: `neg ${n} in bundle text rejects`, text: t, kind: 'reject' });
}
add({ group: 'negative', name: 'neg genesis_tampered: result DID ≠ claimed DID', bundle: bundle({ genesis: N.genesis_tampered.doc }), kind: 'check',
  fn: (r) => want(typeof r.did === 'string' && r.did !== N.genesis_tampered.claimed_did, 'result DID equals the claimed DID') });
for (const n of ['unknown_field_genesis', 'genesis_bad_key']) add({ group: 'negative', name: `neg ${n} rejects`, bundle: bundle({ genesis: N[n].doc }), kind: 'reject' });
// "not a candidate" rotations: each states the chain that results (§7.4)
for (const n of ['recovery_key_mismatch', 'stale_recovery_key', 'voluntary_changes_recovery', 'rotation_bad_sig'])
  add({ group: 'negative', name: `neg ${n} → chain of ${N[n].expected_chain.length}`, bundle: bundle({ rotations: [...N[n].chain_with.map((m) => rot(P[m])), rot(N[n])] }),
    kind: 'check', fn: (r) => want(eq(r.chain, N[n].expected_chain), `chain ${JSON.stringify(r.chain)}`) });
for (const n of ['fork', 'cycle', 'self_rotation'])
  add({ group: 'negative', name: `neg ${n} rejects`, bundle: bundle({ rotations: [rot(P.rotation_voluntary), rot(N[n])] }), kind: 'reject' });
add({ group: 'negative', name: 'neg bundle_rotations_not_array rejects', bundle: N.bundle_rotations_not_array.bundle, kind: 'reject' });
// bindings discarded, never downgraded (§6.1, §6.2, §3.1 types)
for (const [n, x] of Object.entries(N)) {
  if (!x || typeof x !== 'object' || !('sig_id' in x)) continue;
  add({ group: n.includes('monero') ? 'monero' : 'negative', name: `neg ${n} discarded`, bundle: bundle({ bindings: [bnd(x)] }), kind: 'check',
    fn: (r) => want(proofs(r).length === 0 && r.rejected?.bindings === 1, `bindings ${JSON.stringify(proofs(r))}, rejected ${r.rejected?.bindings}`) });
}
for (const n of Object.keys(N)) if (n.startsWith('invoice_')) inexpressible.push(n);

// ---- parity: malformed bundles both reference verifiers treat identically
// A case given as an OBJECT that holds a "__proto__" key is an in-memory bundle: verify()
// discards the item carrying it. Written to a file it becomes bundle TEXT, and §3 makes that
// fatal ("a duplicate key or __proto__ anywhere in it"), so through this interface it rejects.
const hasProto = (v) => v !== null && typeof v === 'object' &&
  (Object.prototype.hasOwnProperty.call(v, '__proto__') || Object.values(v).some(hasProto));
const pc = N.parity.cases;
for (const [n, c] of Object.entries(pc)) {
  const asText = c.raw === undefined && hasProto(c.bundle);
  const base = { group: 'parity', name: `parity ${n}${asText ? ' (as text: __proto__ is fatal, §3)' : ''}`, now: N.parity.now,
    ...(c.raw !== undefined ? { text: c.raw } : { bundle: c.bundle }) };
  if (c.expect.reject !== undefined || asText) add({ ...base, kind: 'reject' });
  else add({ ...base, kind: 'check', fn: (r) => want(eq(proofs(r), c.expect.proofs) && nAtt(r) === c.expect.attestations && eq(r.rejected, c.expect.rejected),
    `got proofs ${JSON.stringify(proofs(r))} attestations ${nAtt(r)} rejected ${JSON.stringify(r.rejected)}, want ${JSON.stringify(c.expect)}`) });
}

// ---- run
const dir = mkdtempSync(path.join(tmpdir(), 'sigelo-grade-verifier-'));
const rows = [];
cases.forEach((c, i) => {
  const f = path.join(dir, `case-${String(i).padStart(3, '0')}.json`);
  writeFileSync(f, c.text ?? JSON.stringify(c.bundle));
  const p = spawnSync(cmd[0], [...cmd.slice(1), f, '--now', String(c.now)], { encoding: 'utf8', timeout, maxBuffer: 16 << 20 });
  let ok = false, why = '';
  if (p.error) why = `could not run: ${p.error.code ?? p.error.message}`;
  else if (c.kind === 'reject') { ok = p.status === 1; why = ok ? '' : `exit ${p.status ?? p.signal}, want 1 (reject)`; }
  else if (p.status !== 0) why = `exit ${p.status ?? p.signal}, want 0: ${(p.stderr || '').trim().split('\n')[0].slice(0, 120)}`;
  else {
    let r;
    try { r = surface(JSON.parse(p.stdout)); } catch { why = 'stdout is not JSON'; }
    if (r !== undefined) {
      if (c.kind === 'result') { ok = eq(r, c.expect); why = ok ? '' : `result ≠ expect: ${p.stdout.trim().slice(0, 160)}`; }
      else { const e = c.fn(r); ok = e === null; why = e ?? ''; }
    }
  }
  rows.push({ group: c.group, name: c.name, ok, why, file: f });
  if (!asJson) console.log(`${ok ? 'PASS' : 'FAIL'} ${c.name}${ok ? '' : ` — ${why}`}${verbose ? `  [${f}]` : ''}`);
});
const pass = rows.filter((r) => r.ok).length;
const byGroup = {};
for (const r of rows) { const g = (byGroup[r.group] ??= { pass: 0, total: 0 }); g.total++; if (r.ok) g.pass++; }
if (asJson) console.log(JSON.stringify({ candidate: cmd, vectors: vectorsPath, score: `${pass}/${rows.length}`, groups: byGroup, cases: rows.map(({ file, ...r }) => r), inexpressible }, null, 1));
else {
  console.log('');
  for (const [g, x] of Object.entries(byGroup)) console.log(`${g.padEnd(9)} ${x.pass}/${x.total}`);
  console.log(`not expressible through the bundle interface (not scored): ${inexpressible.join(', ')}`);
  console.log(`\nSCORE ${pass}/${rows.length}`);
}
if (!verbose) rmSync(dir, { recursive: true, force: true });
