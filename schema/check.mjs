// Checks schema/*.json against test-vectors.json. Dependency-free: a minimal JSON Schema
// 2020-12 validator for exactly the keywords these schemas use (any other keyword throws, so a
// schema edit cannot be silently ignored). Run: node schema/check.mjs  → ends ALL PASS or exits 1.
//
//   positives   every positive vector body, envelope and genesis validates; so do both
//               bundles, their §9.1 `expect`, and adapters/1f916/sample-bundle.json
//   negatives   every negative that fails on STRUCTURE fails validation; every negative that
//               fails on signature, chain, time or a method's own check still validates (the
//               schemas are not stricter than the spec); the rest are listed as not expressible
//   parity      each parity bundle fails bundle.json iff the verifiers reject it for a
//               structural reason, and the items the envelope schemas refuse are exactly the
//               ones the verifiers discard, save the listed exceptions
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(dir, '..');
const readJSON = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

// ---------------------------------------------------------------- the validator
const registry = new Map(); // $id → schema
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.json') && f !== 'package.json')) {
  const s = readJSON(path.join(dir, f));
  if (s.$schema !== 'https://json-schema.org/draft/2020-12/schema') throw new Error(`${f}: not draft 2020-12`);
  if (!s.$id?.endsWith('/' + f)) throw new Error(`${f}: $id does not end in its file name`);
  registry.set(s.$id, s);
}
const ANNOTATIONS = new Set(['$schema', '$id', '$defs', 'title', 'description', 'examples']);
const KNOWN = new Set([...ANNOTATIONS, '$ref', 'type', 'const', 'enum', 'pattern', 'minimum', 'maximum', 'minItems',
  'required', 'properties', 'additionalProperties', 'propertyNames', 'items', 'anyOf', 'allOf', 'not', 'if', 'then', 'else']);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const typeOf = (v) => v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v;
const deepEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b) && typeOf(a) === typeOf(b);
const regexes = new Map();

function resolve(ref, base) {
  const u = new URL(ref, base);
  const frag = decodeURIComponent(u.hash.slice(1));
  u.hash = '';
  let s = registry.get(u.href);
  if (!s) throw new Error(`unresolvable $ref ${ref} from ${base}`);
  for (const part of frag.split('/').slice(1)) s = s[part.replace(/~1/g, '/').replace(/~0/g, '~')];
  if (s === undefined) throw new Error(`unresolvable pointer in $ref ${ref}`);
  return { schema: s, base: u.href };
}

// Returns the first failure as a string ("/path: why"), or null when v is valid.
function validate(schema, v, base, at = '') {
  if (schema === true) return null;
  if (schema === false) return `${at || '/'}: not allowed`;
  for (const k of Object.keys(schema)) if (!KNOWN.has(k)) throw new Error(`validator does not implement keyword ${k}`);
  if (schema.$id) base = schema.$id;
  const fail = (why) => `${at || '/'}: ${why}`;
  let r;
  if (schema.$ref) {
    const t = resolve(schema.$ref, base);
    if ((r = validate(t.schema, v, t.base, at))) return r;
  }
  const t = typeOf(v);
  if (schema.type) {
    const types = [schema.type].flat();
    const okType = types.some((ty) => ty === t || (ty === 'integer' && t === 'number' && Number.isInteger(v)));
    if (!okType) return fail(`${JSON.stringify(v)?.slice(0, 40)} is not ${types.join('|')}`);
  }
  if (own(schema, 'const') && !deepEqual(v, schema.const)) return fail(`is not ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.some((e) => deepEqual(v, e))) return fail(`not one of ${JSON.stringify(schema.enum)}`);
  if (t === 'string' && schema.pattern) {
    if (!regexes.has(schema.pattern)) regexes.set(schema.pattern, new RegExp(schema.pattern, 'u'));
    if (!regexes.get(schema.pattern).test(v)) return fail(`${JSON.stringify(v).slice(0, 40)} does not match ${schema.pattern}`);
  }
  if (t === 'number') {
    if (own(schema, 'minimum') && v < schema.minimum) return fail(`${v} < ${schema.minimum}`);
    if (own(schema, 'maximum') && v > schema.maximum) return fail(`${v} > ${schema.maximum}`);
  }
  if (t === 'array') {
    if (own(schema, 'minItems') && v.length < schema.minItems) return fail(`fewer than ${schema.minItems} items`);
    if (schema.items !== undefined) for (let i = 0; i < v.length; i++) if ((r = validate(schema.items, v[i], base, `${at}/${i}`))) return r;
  }
  if (t === 'object') {
    for (const k of schema.required ?? []) if (!own(v, k)) return fail(`missing ${k}`);
    for (const k of Object.keys(v)) {
      if (schema.propertyNames !== undefined && (r = validate(schema.propertyNames, k, base, `${at}/${k} (key)`))) return r;
      const sub = schema.properties && own(schema.properties, k) ? schema.properties[k] : schema.additionalProperties;
      if (sub === false) return fail(`unknown field ${JSON.stringify(k)}`);
      if (sub !== undefined && (r = validate(sub, v[k], base, `${at}/${k}`))) return r;
    }
  }
  if (schema.allOf) for (const s of schema.allOf) if ((r = validate(s, v, base, at))) return r;
  if (schema.anyOf && !schema.anyOf.some((s) => validate(s, v, base, at) === null)) return fail('matches no anyOf branch');
  if (schema.not !== undefined && validate(schema.not, v, base, at) === null) return fail('matches `not`');
  if (schema.if !== undefined) {
    const branch = validate(schema.if, v, base, at) === null ? schema.then : schema.else;
    if (branch !== undefined && (r = validate(branch, v, base, at))) return r;
  }
  return null;
}
const ID = (name) => `https://sigelo.invalid/schema/v0/${name}.json`;
const check = (name, v) => validate(registry.get(ID(name)), v, ID(name));

// ---------------------------------------------------------------- the run
let pass = 0, fail = 0;
const out = (ok, line) => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'} ${line}`); };
const mustPass = (label, name, v) => { const e = check(name, v); out(e === null, `${label} valid as ${name}${e ? ` — ${e}` : ''}`); };
const mustFail = (label, name, v, where = '') => { const e = check(name, v); out(e !== null && e.includes(where), `${label} refused as ${name}${e ? ` (${e})` : ' — ACCEPTED'}`); };
const pick = (o, ks) => Object.fromEntries(ks.filter((k) => own(o, k)).map((k) => [k, o[k]]));
const envelopeOf = { attestation: ['body', 'sig'], binding: ['body', 'sig_id', 'sig_addr'], rotation: ['body', 'sig', 'next_genesis'] };

const T = readJSON(path.join(root, 'test-vectors.json'));
const counts = { positive: 0, structural: 0, sound: 0, inexpressible: 0, parity: 0 };

// positives
for (const [name, x] of Object.entries(T.vectors)) {
  if (Array.isArray(x)) continue; // expected_chain: DIDs only
  if (x.doc) { mustPass(name + '.doc', 'genesis', x.doc); counts.positive++; }
  if (x.body) {
    const slot = x.body.typ;
    mustPass(name + '.body', slot, x.body); counts.positive++;
    if (envelopeOf[slot]) { mustPass(name + ' envelope', slot + '-envelope', pick(x, envelopeOf[slot])); counts.positive++; }
    if (x.next_genesis) { mustPass(name + '.next_genesis', 'genesis', x.next_genesis); counts.positive++; }
  }
  if (x.bundle) {
    mustPass(name + '.bundle', 'bundle', x.bundle); mustPass(name + '.expect', 'verify-result', x.expect); counts.positive += 2;
    // its items: the ones the envelope schemas refuse must be among the ones verify discards
    const badA = x.bundle.attestations.filter((e) => check('attestation-envelope', e) !== null).length;
    const badB = x.bundle.bindings.filter((e) => check('binding-envelope', e) !== null).length;
    out(badA <= x.expect.rejected.attestations && badB <= x.expect.rejected.bindings,
      `${name} items: envelopes refuse ${badA}+${badB}, verify discards ${x.expect.rejected.attestations}+${x.expect.rejected.bindings}`);
  }
}
const sample = readJSON(path.join(root, 'adapters/1f916/sample-bundle.json'));
mustPass('adapters/1f916/sample-bundle.json', 'bundle', sample.bundle); counts.positive++;

// negatives. Structural: the object that carries the fault, in the slot it is presented in.
const N = T.negative;
// Each entry: [slot, object, where] — the refusal must name `where`, so a body refused for an
// unrelated reason (a missing field, say) does not count. The three `claims` cases carry only
// v/typ/claims in the vectors file, so their claims are grafted onto the positive attestation.
const A = T.vectors.attestation.body;
const structural = {
  float_in_claims: ['attestation', { ...A, claims: N.float_in_claims.body.claims }, '/claims'],
  int_out_of_range: ['attestation', { ...A, claims: N.int_out_of_range.body.claims }, '/claims'],
  proto_key: ['attestation', { ...A, claims: JSON.parse(N.proto_key.raw).claims }, '/claims'],
  typ_mismatch: ['attestation', N.typ_mismatch.body, '/typ'],
  unknown_field_attestation: ['attestation', N.unknown_field_attestation.body, 'unknown field "extra"'],
  unknown_field_genesis: ['genesis', N.unknown_field_genesis.doc, 'unknown field "extra"'],
  genesis_bad_key: ['genesis', N.genesis_bad_key.doc, '/key'],
  bundle_rotations_not_array: ['bundle', N.bundle_rotations_not_array.bundle, '/rotations'],
  invoice_memo_lone_surrogate: ['invoice', JSON.parse(N.invoice_memo_lone_surrogate.raw), '/memo'],
  binding_monero_integrated_addr: ['binding', N.binding_monero_integrated_addr.body, '/addr'], // §6.2 addr form: 106 characters
  binding_monero_noncanonical_varint_addr: ['binding', N.binding_monero_noncanonical_varint_addr.body, '/addr'], // prefix as a 2-byte varint: 97 characters
};
for (const n of ['invoice_amount_number', 'invoice_amount_float_string', 'invoice_amount_negative', 'invoice_amount_empty'])
  structural[n] = ['invoice', N[n].body, '/amount'];
structural.invoice_memo_not_string = ['invoice', N.invoice_memo_not_string.body, '/memo'];
for (const n of ['binding_addr_not_string', 'binding_iat_string', 'binding_iat_null', 'binding_iat_bool', 'binding_iat_negative', 'binding_exp_string', 'binding_nonce_number'])
  structural[n] = ['binding', N[n].body, '/' + n.split('_')[1]];
// Not structural: they lose on a signature, the DID hash, the chain, the clock or a method's own
// decoder. Each object must still VALIDATE, or the schemas would be stricter than the spec.
const sound = {
  tampered_claims: ['attestation', N.tampered_claims.body], wrong_signer: ['attestation', N.wrong_signer.body],
  missing_prefix: ['attestation', N.missing_prefix.body], genesis_tampered: ['genesis', N.genesis_tampered.doc],
  expired_attestation: ['attestation', N.expired_attestation.body],
};
for (const n of ['recovery_key_mismatch', 'stale_recovery_key', 'voluntary_changes_recovery', 'rotation_bad_sig', 'fork', 'cycle'])
  sound[n] = ['rotation-envelope', pick(N[n], envelopeOf.rotation)];
for (const n of ['binding_monero_subaddress_base_sig', 'binding_monero_sigv1', 'binding_monero_view_key_y_ge_p', 'binding_monero_spend_key_x0_signbit'])
  sound[n] = ['binding-envelope', pick(N[n], envelopeOf.binding)];
// Structural, but not something JSON Schema can say.
const inexpressible = {
  duplicate_key: 'a duplicate key is a parse-time rule: JSON.parse keeps the last value before any schema sees it',
  self_rotation: 'next != id compares two values of one instance; 2020-12 has no $data',
  binding_exp_not_after_iat: 'exp > iat compares two values of one instance; 2020-12 has no $data',
};
for (const [n, [slot, v, where]] of Object.entries(structural)) { mustFail('neg ' + n, slot, v, where); counts.structural++; }
for (const [n, [slot, v]] of Object.entries(sound)) { mustPass('neg ' + n + ' (fails on crypto/chain/time/method, not shape)', slot, v); counts.sound++; }
for (const [n, why] of Object.entries(inexpressible)) { console.log(`N/A  neg ${n}: ${why}`); counts.inexpressible++; }
const covered = new Set([...Object.keys(structural), ...Object.keys(sound), ...Object.keys(inexpressible), 'parity']);
for (const n of Object.keys(N)) if (!covered.has(n)) out(false, `neg ${n} is not classified in check.mjs`);

// parity: the fatal part (bundle.json) vs the per-item part (the envelopes), as SPEC §9 step 2 splits them
const itemsIn = (b, k) => (b && typeof b === 'object' && Array.isArray(b[k]) ? b[k] : []);
const parityExpressible = {
  // discarded by the verifiers for a reason the schemas cannot see
  binding_exp_equal_iat: 'exp > iat', binding_exp_before_iat: 'exp > iat',
  binding_sig_addr_null: "monero's own sig_addr check (the schemas leave sig_addr to the method)",
  raw_fatal_attestation_duplicate_key: 'duplicate key (parse-time)',
  raw_fatal_depth_513_in_claims: 'nesting deeper than 512 (parse-time, SPEC §3)',
  // parse-time, so fatal wherever it sits; common.json#/$defs/string refuses the same strings, per item
  raw_fatal_noncharacter_in_claims_value: 'a noncharacter (parse-time, SPEC §3.1)', raw_fatal_noncharacter_astral_in_claims_key: 'a noncharacter (parse-time, SPEC §3.1)',
  fatal_genesis_created_feb_29_common_year: 'a day that does not exist in that month and year (SPEC §4)',
  fatal_genesis_key_all_zero: 'a key that is no usable Ed25519 point (SPEC §2)', fatal_issuer_key_identity: 'a key that is no usable Ed25519 point (SPEC §2)',
  fatal_rotation_recovery_key_y_ge_p: 'a key that is no usable Ed25519 point (SPEC §2)',
  binding_ed25519_test_addr_all_zero_unproven: 'an ed25519-test addr that is no usable Ed25519 point (SPEC §2)',
  fatal_duplicate_rotation_is_fork: 'a fork (§7.3 chain walk over valid signatures)',
  rotation_next_genesis_not_next: 'a sub off the chain, since hash(next_genesis) != next ends it (§7.2 hash check)',
};
for (const [n, c] of Object.entries(N.parity.cases)) {
  counts.parity++;
  const b = c.raw !== undefined ? JSON.parse(c.raw) : c.bundle;
  const fatalErr = check('bundle', b); // bundle.json is exactly the fatal part
  const why = parityExpressible[n];
  if (c.expect.reject !== undefined) {
    if (why) { console.log(`N/A  parity ${n}: fatal in the verifiers on ${why}; not expressible`); continue; }
    out(fatalErr !== null, `parity ${n}: bundle refused (verifiers: ${c.expect.reject})${fatalErr ? ` (${fatalErr})` : ' — ACCEPTED'}`);
    continue;
  }
  const badA = itemsIn(b, 'attestations').filter((e) => check('attestation-envelope', e) !== null).length;
  const badB = itemsIn(b, 'bindings').filter((e) => check('binding-envelope', e) !== null).length;
  const want = c.expect.rejected;
  const exact = badA === want.attestations && badB === want.bindings;
  if (!exact && why && badA <= want.attestations && badB <= want.bindings) {
    console.log(`N/A  parity ${n}: discarded by the verifiers on ${why}; schemas refuse ${badA}+${badB}, verifiers ${want.attestations}+${want.bindings}`);
    continue;
  }
  out(fatalErr === null && exact,
    `parity ${n}: bundle valid, envelopes refuse ${badA} attestation(s) + ${badB} binding(s) = verifiers' rejected${fatalErr ? ` — bundle: ${fatalErr}` : ''}`);
}

console.log(`\npositive ${counts.positive}, structural negatives ${counts.structural}, non-structural negatives ${counts.sound}, not expressible ${counts.inexpressible}, parity cases ${counts.parity}`);
console.log(`${pass} passed, ${fail} failed`);
console.log(fail === 0 ? 'ALL PASS' : 'FAILURES');
process.exit(fail === 0 ? 0 : 1);
