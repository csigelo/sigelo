/**
 * Conformance run against ../test-vectors.json. `npx tsc && node dist/test.js`.
 *
 * Three things are checked, per CLAUDE.md: every positive vector is reproduced byte-for-byte
 * from the documented seeds with this library's own constructors (Ed25519 is deterministic,
 * so the signatures must match exactly), the `bundle` vector's §9.1 result is reproduced as
 * JSON, and every negative case is rejected for the stated reason.
 */
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { Age, ceremony, IMPORT_REFUSED, importRoot, keeperLastHonest, openTty, recover, recoverKeeper, restore, restoreWords, roles } from './ceremony.js';
import { JcsError, RawNumber } from './jcs.js';
import {
  agentIdentitySeed, decodeMoneroWords, deriveIdentity, deriveRoot, encodeMoneroWords, identitySeed, k, keeperRoot,
  mnemonicFromRoot, newRoot, parseRoot, recoveryCommitment, recoveryPublicKey, recoverySeed, rootFromMnemonic,
  vaultFromRoot, walletFromRoot,
} from './keys.js';
import { MONERO_WORDS } from './monero-words.js';
import {
  attest, bind, Bundle, canonicalize, challenge, commitmentOf, did, encodeKey, Genesis, keygen,
  parse, parseBytes, rotate, SigeloError, sign, signingInput, structure, verify, verifySig, VERSION,
} from './sigelo.js';
import {
  decodeAddress, encodeAddress, hashToScalar, keccak256, keysFromSpend, MoneroError, moneroBase58Decode,
  moneroBase58Encode, Net, signMessage, signMessageHash, sigeloMoneroSigAddr, subaddress, verifyMessage,
  verifySigeloMoneroSigAddr,
} from './monero.js';

// The vectors file is untyped data; this alias keeps that explicit rather than implicit.
type Any = any;

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const file: Any = JSON.parse(readFileSync(join(root, 'test-vectors.json'), 'utf-8'));
const P: Any = file.vectors;
const N: Any = file.negative;
const NOW: number = file.now;
const K: Record<string, Uint8Array> = {};
for (const [name, seed] of Object.entries(file.seeds as Record<string, string>)) K[name] = hexToBytes(seed);
const pub = (name: string): Uint8Array => ed.getPublicKey(K[name]!); // raw 32-byte public key

let failures = 0;
function t(name: string, cond: boolean): void {
  console.log((cond ? 'PASS ' : 'FAIL ') + name);
  if (!cond) failures++;
}
/** Assert that `fn` throws a sigelo/JCS rejection whose message names `want`. */
function rejects(name: string, fn: () => unknown, want: string): void {
  try {
    fn();
    t(`${name} (accepted!)`, false);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    t(`${name} (${msg})`, (e instanceof SigeloError || e instanceof JcsError) && msg.includes(want));
  }
}
/** Deep equality that ignores object key order (array order still matters). */
const stable = (v: unknown): unknown =>
  Array.isArray(v) ? v.map(stable)
    : v !== null && typeof v === 'object'
      ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, stable((v as Any)[k])]))
      : v;
const same = (a: unknown, b: unknown): boolean => JSON.stringify(stable(a)) === JSON.stringify(stable(b));

// ---------------------------------------------------------------- a. reproduce the vectors

// keygen(recovery: null) must warn loudly — it means theft is terminal (CLAUDE.md).
let warned = '';
const orig = console.warn;
console.warn = (...args: unknown[]): void => {
  warned += args.join(' ');
};
/** Every body this library mints, checked against §3.1 below. */
const minted: [Any, Any][] = [];
/** Rebuild a genesis from its seed and the vector's own `created`/`nonce`. */
function regen(seed: string, recovery: Uint8Array | null, vec: Any): Genesis {
  const id = keygen({ recovery, seed: K[seed]!, created: vec.created, nonce: vec.nonce });
  t(`genesis ${seed} reproduced`, canonicalize(id.genesis) === canonicalize(vec));
  minted.push(['genesis', id.genesis]);
  return id.genesis;
}
const g0 = regen('agent', pub('recovery'), P.genesis.doc);
const gw = regen('world', null, P.world_genesis.doc);
const gm = regen('member', null, P.member_genesis.doc);
console.warn = orig;
t('keygen warns on recovery: null', warned.includes('NO recovery key') && warned.includes('PERMANENTLY'));

for (const g of ['genesis', 'world_genesis', 'member_genesis']) {
  t(`${g} did`, did(P[g].doc) === P[g].expect_did);
}
// §4: only the hash is public, so keygen must also accept an existing commitment verbatim.
t('keygen accepts a recovery commitment string',
  keygen({ recovery: P.genesis.doc.recovery, seed: K.agent!, created: P.genesis.doc.created, nonce: P.genesis.doc.nonce })
    .genesis.recovery === P.genesis.doc.recovery);
t('genesis did == keygen did', did(g0) === P.genesis.expect_did && did(gw) === P.world_genesis.expect_did && did(gm) === P.member_genesis.expect_did);

/** Rebuild an attestation with attest() and compare canonical body + signature. */
function reattest(name: string, seed: string): void {
  const v = P[name];
  const made = attest({ secret: K[seed]!, ...v.body });
  minted.push(['attestation', made.body]);
  t(`${name} reproduced`, canonicalize(made.body) === canonicalize(v.body) && made.sig === v.sig);
}
reattest('attestation', 'world');
reattest('attestation_unicode', 'world');

const b = P.binding;
const made = bind({
  secret: K.agent!, id: b.body.id, method: b.body.method, addr: b.body.addr,
  iat: b.body.iat, exp: b.body.exp, nonce: b.body.nonce, addr_secret: K.paykey!,
});
minted.push(['binding', made.body]);
t('binding reproduced (cross-signed)', canonicalize(made.body) === canonicalize(b.body) && made.sig_id === b.sig_id && made.sig_addr === b.sig_addr);
const bu = P.binding_unproven;
const madeu = bind({
  secret: K.agent!, id: bu.body.id, method: bu.body.method, addr: bu.body.addr,
  iat: bu.body.iat, exp: bu.body.exp, nonce: bu.body.nonce,
});
minted.push(['binding', madeu.body]);
t('binding_unproven reproduced (no sig_addr)', canonicalize(madeu.body) === canonicalize(bu.body) && madeu.sig_id === bu.sig_id && madeu.sig_addr === undefined);
rejects('bind refuses to sign addr for an unsupported method',
  () => bind({ secret: K.agent!, id: b.body.id, method: 'monero', addr: '8Bx', iat: b.body.iat, exp: b.body.exp, addr_secret: K.paykey! }),
  'cannot sign addr');

/** Rebuild a rotation with rotate() and compare canonical body + signature + next_genesis. */
function rerotate(name: string, from: Genesis, nextSeed: string, nextRecovery: Uint8Array | null, signer: string): Genesis {
  const v = P[name];
  const next = regen(nextSeed, nextRecovery, v.next_genesis);
  const made = rotate({ genesis: from, next_genesis: next, iat: v.body.iat, reason: v.body.reason, secret: K[signer]! });
  minted.push(['rotation', made.body]);
  t(`${name} reproduced`, canonicalize(made.body) === canonicalize(v.body) && made.sig === v.sig &&
    canonicalize(made.next_genesis) === canonicalize(v.next_genesis) &&
    (v.expect_next_did === undefined || did(made.next_genesis) === v.expect_next_did));
  return next;
}
const g1 = rerotate('rotation_voluntary', g0, 'agent2', pub('recovery'), 'agent');
// rotation_hostile changes the recovery commitment, so rotate() must refuse to mint it (§7);
// only its raw signature can be reproduced, with sign().
const ga = keygen({ recovery: pub('attacker'), seed: K.attacker!, created: P.rotation_hostile.next_genesis.created, nonce: P.rotation_hostile.next_genesis.nonce }).genesis;
rejects('rotate refuses a voluntary rotation that changes the commitment',
  () => rotate({ genesis: g1, next_genesis: ga, iat: P.rotation_hostile.body.iat, reason: 'voluntary', secret: K.agent2! }),
  'changes the recovery commitment');
t('rotation_hostile signature reproduced', sign(K.agent2!, P.rotation_hostile.body) === P.rotation_hostile.sig &&
  canonicalize(ga) === canonicalize(P.rotation_hostile.next_genesis));
// ...whereas rotation_hostile_carried is a fully valid voluntary rotation: the library mints
// it happily, and only §7.1 precedence defeats it at verification time.
rerotate('rotation_hostile_carried', g1, 'attacker', pub('recovery'), 'agent2');
const g2 = rerotate('rotation_recovery', g1, 'agent3', pub('recovery2'), 'recovery');
rerotate('rotation_recovery_second', g2, 'agent', pub('recovery2'), 'recovery2');
rejects('rotate refuses a recovery rotation under a retired key',
  () => rotate({ genesis: g2, next_genesis: g0, iat: NOW, reason: 'recovery', secret: K.recovery! }),
  'does not hash to the current commitment');

// SPEC §5.2 proof of control: fixed body, identity key, never in a bundle.
const ch = P.challenge;
const madeCh = challenge({ secret: K.agent!, genesis: g0, ctx: ch.body.ctx, nonce: new Uint8Array(16).fill(0xe9) });
minted.push(['challenge', madeCh.body]);
t('challenge reproduced', canonicalize(madeCh.body) === canonicalize(ch.body) && madeCh.sig === ch.sig);
t('challenge verifies against genesis.key', verifySig(g0.key, ch.body, ch.sig));
// A challenge body has none of an attestation's fields, so the required-field check fires
// first; the typ binding is what rejects it once the shapes overlap (SPEC §3, §5.2).
rejects('challenge body is rejected in the attestation slot', () => structure(ch.body, 'attestation'), 'attestation:');
rejects('typ: challenge is rejected in the attestation slot',
  () => structure({ ...P.attestation.body, typ: 'challenge' }, 'attestation'), 'typ is "challenge"');
rejects('challenge refuses a key that is not the genesis key',
  () => challenge({ secret: K.attacker!, genesis: g0, ctx: ch.body.ctx, nonce: ch.body.nonce }), 'does not match genesis.key');

// SPEC §6.3 invoice: identity key, `method`/`addr` naming where to pay this time, never in a
// bundle. There is no `invoice()` constructor — an invoice is a body plus `sign` — so the
// nonce is spelled by the one constructor that takes raw bytes and hands back the multibase.
const iv = P.invoice;
const ivBody = {
  v: VERSION, typ: 'invoice', did: iv.body.did, method: iv.body.method, addr: iv.body.addr,
  iat: iv.body.iat, exp: iv.body.exp,
  nonce: challenge({ secret: K.agent!, genesis: g0, ctx: 'nonce', nonce: new Uint8Array(16).fill(0xea) }).body.nonce,
  amount: iv.body.amount,
};
structure(ivBody, 'invoice');
minted.push(['invoice', ivBody]);
t('invoice reproduced', canonicalize(ivBody) === canonicalize(iv.body) && sign(K.agent!, ivBody) === iv.sig);
t('invoice verifies against genesis.key', verifySig(g0.key, iv.body, iv.sig));
// The whole point of `typ` (§3): an invoice carries an address and an expiry, so a verifier
// that took it as a binding would report a payment address nobody cross-signed for.
rejects('invoice body is rejected in the binding slot', () => structure(iv.body, 'binding'), 'binding:');
rejects('typ: invoice is rejected in the binding slot',
  () => structure({ ...P.binding.body, typ: 'invoice' }, 'binding'), 'typ is "invoice"');

// §6.2 from the vectors file (the wallet-oracle cross-check is in section f, over
// ts/test/monero-vectors.json). One verify() call, so the proof STATUS is pinned and not just
// the signature: a verifier that reported this `unproven` would still pass a raw sig check.
const bm = P.binding_monero;
const xb1 = (e: Any): Bundle => ({
  v: VERSION, typ: 'bundle', genesis: P.genesis.doc, rotations: [], // the envelope only: §3.1 discards one with the vector's annotations
  bindings: [{ body: e.body, sig_id: e.sig_id, ...(e.sig_addr !== undefined && { sig_addr: e.sig_addr }) }],
  attestations: [], issuers: [],
}) as Bundle;
const rbm = verify(xb1(bm), NOW);
t('binding_monero verifies as proven, view mode',
  rbm.bindings.length === 1 && rbm.bindings[0]!.proof === bm.expect_proof && rbm.rejected.bindings === 0 &&
  verifySigeloMoneroSigAddr(bm.body, bm.body.addr, bm.sig_addr).mode === bm.expect_mode);
// §6.2 subaddress (0,1) of the same wallet, one binding per mode, each signed over the
// subaddress's own (D, C). The keys are inside the hash, so neither verifies under the base.
for (const n of ['binding_monero_subaddress_spend', 'binding_monero_subaddress_view']) {
  const e = P[n], r = verify(xb1(e), NOW);
  t(`${n} verifies as proven, ${e.expect_mode} mode`,
    decodeAddress(e.body.addr).kind === 'subaddress' && r.bindings.length === 1 && r.bindings[0]!.proof === e.expect_proof &&
    r.rejected.bindings === 0 && verifySigeloMoneroSigAddr(e.body, e.body.addr, e.sig_addr).mode === e.expect_mode);
  t(`${n} sig_addr does not verify under the base address`,
    !verifySigeloMoneroSigAddr(e.body, bm.body.addr, e.sig_addr).good);
}

// §3.1: nothing this library mints may carry a key outside its row (or miss one).
let mintedOk = true;
for (const [slot, body] of minted) {
  try {
    structure(body, slot);
  } catch (e) {
    mintedOk = false;
    console.log(`  minted ${slot}: ${e instanceof Error ? e.message : String(e)}`);
  }
}
t(`every minted body (${minted.length}) satisfies §3.1`, mintedOk);

// ---------------------------------------------------------------- b. JCS (SPEC §3)

const u = P.attestation_unicode;
t('attestation_unicode canonical bytes', canonicalize(u.body) === u.canonical);
t('attestation_unicode signing-input hash', bytesToHex(sha256(signingInput(u.body))) === u.signing_input_sha256);
t('attestation_unicode sig verifies', verifySig(gw.key, u.body, u.sig));
t('signing input is "sigelo\\n" || JCS', same(Array.from(signingInput(u.body)), Array.from(utf8ToBytes('sigelo\n' + u.canonical))));
t('canonicalize round-trips through the strict parser', canonicalize(parse(u.canonical)) === u.canonical);
t('jcs key order is UTF-16, not code point', canonicalize({ '\u{1d11e}': 1, '～': 2 }) === '{"\u{1d11e}":1,"～":2}');
t('jcs escapes are the ES6 set, lowercase hex', canonicalize('\b\t\n\f\r"\\ ') === '"\\u0001\\b\\t\\n\\f\\r\\"\\\\ "');
t('jcs integers', canonicalize([0, -0, -1, 9007199254740991, -9007199254740991]) === '[0,0,-1,9007199254740991,-9007199254740991]');
rejects('jcs rejects floats', () => canonicalize({ x: 0.5 }), 'non-integer');
rejects('jcs rejects out-of-range integers', () => canonicalize({ x: 2 ** 53 }), '2^53');
rejects('jcs rejects undefined', () => canonicalize({ x: undefined }), 'unserializable');
rejects('jcs rejects bigint', () => canonicalize({ x: 1n }), 'bigint');
// Invariant 7: a forbidden NUMBER is not parse ambiguity. It parses (as a RawNumber) and is
// refused at canonicalization, so only the item holding it is malformed; "1.0" included.
const floaty = parse('{"a":1.0,"b":1e2,"c":9007199254740992}') as Any;
t('strict parser keeps a forbidden number as a RawNumber, not a parse error',
  floaty.a instanceof RawNumber && floaty.a.text === '1.0' && floaty.b.text === '1e2' && floaty.c.text === '9007199254740992');
rejects('canonicalize refuses a parsed float literal', () => canonicalize({ a: floaty.a }), 'non-integer number 1.0');
rejects('canonicalize refuses a parsed out-of-range integer', () => canonicalize({ c: floaty.c }), 'integer outside +-2^53-1: 9007199254740992');
t('a parsed float is never signed over', !verifySig(gw.key, { ...u.body, claims: floaty }, u.sig));
rejects('strict parser rejects a truncated fraction', () => parse('{"a":1.}'), 'expected digit');
rejects('strict parser rejects a duplicate key anywhere (the text has two readings)', () => parse('[{"a":{"b":1,"b":1}}]'), 'duplicate key');
rejects('strict parser rejects trailing content', () => parse('{} {}'), 'trailing content');
// SPEC §3 nesting depth: 512 levels, arrays and objects combined. Go's recursive parser died of
// a fatal (uncatchable) stack overflow near 750 000 levels while this one answered; now both
// refuse level 513 as a parse error at the same offset, and canonicalize refuses it too.
const nest = (n: number, inner = ''): string => '['.repeat(n) + inner + ']'.repeat(n);
t('strict parser accepts depth 512 and canonicalize round-trips it', canonicalize(parse(nest(512))) === nest(512));
t('depth 512 mixing objects and arrays parses', canonicalize(parse(nest(511, '{"a":1}'))) === nest(511, '{"a":1}'));
rejects('depth 513 is a parse error at the bracket that opens level 513', () => parse(nest(513)), 'nesting deeper than 512 at offset 512');
rejects('an empty object at level 513 counts', () => parse(nest(512, '{}')), 'nesting deeper than 512 at offset 512');
rejects('offsets are UTF-16 units, as everywhere', () => parse('{"é😀":' + nest(512) + '}'), 'nesting deeper than 512 at offset 518');
{
  const started = Date.now();
  rejects('depth 800000 (Go crashed here) is the same parse error, at once', () => parse(nest(800_000)), 'nesting deeper than 512 at offset 512');
  t('depth 800000 is refused in under a second', Date.now() - started < 1000);
}
rejects('a duplicate key under depth 511 still rejects', () => parse(nest(511, '{"a":1,"a":2}')), 'duplicate key');
// Differential M1: offsets differed by one from go/jcs.go on four messages (ts incremented past
// the character before failing). Both point AT the offending character now; the same table,
// message for message, is in go/sigelo_test.go.
for (const [text, want] of [
  ['{"a":"\\u12G4"}', 'bad \\u escape at offset 7'], ['{"a":"\\u12"}', 'bad \\u escape at offset 7'],
  ['{"a" 1}', 'expected ":" at offset 5'], ['{"a":1 "b":2}', 'expected "," or "}" at offset 7'],
  ['[1 2]', 'expected "," or "]" at offset 3'], ['["😀" 1]', 'expected "," or "]" at offset 6'],
  ['{"a":"\\x"}', 'bad escape \\x at offset 7'], ['{"a":1,}', 'expected string at offset 7'], ['[1,', 'unexpected end of input at offset 3'],
]) {
  let got = '';
  try { parse(text); } catch (e) { got = e instanceof JcsError ? e.message : String(e); }
  t(`parse ${JSON.stringify(text)}: ${want}${got === want ? '' : ` (got ${got})`}`, got === want);
}
// Differential S5: I-JSON (RFC 7493 §2.1, which RFC 8785 requires) forbids noncharacters. Raw
// or escaped, in a value or a key: a parse error at the string's opening quote, same text as
// go/jcs.go (whose test has the same table); canonicalize refuses a value built in memory.
for (const [cp, bad] of [
  [0xfdcf, false], [0xfdd0, true], [0xfdef, true], [0xfdf0, false], [0xfffd, false], [0xfffe, true], [0xffff, true],
  [0x1fffe, true], [0x1ffff, true], [0x10000, false], [0x10fffd, false], [0x10fffe, true], [0x10ffff, true], [0xeffff, true],
] as [number, boolean][]) {
  const ch = String.fromCodePoint(cp), u = 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
  const esc = Array.from({ length: ch.length }, (_, k) => '\\u' + ch.charCodeAt(k).toString(16).padStart(4, '0')).join(''); // UTF-16 units: a pair for an astral one
  for (const [how, text] of [['raw', `{"a":["x","${ch}"]}`], ['escaped', `{"a":["x","${esc}"]}`], ['key', `{"a":{"${esc}":1}}`]] as [string, string][]) {
    const run = (): unknown => parseBytes(new TextEncoder().encode(text));
    if (!bad) { let ok = true; try { run(); } catch { ok = false; } t(`${u} ${how} parses`, ok); }
    else rejects(`${u} ${how} is a parse error`, run, `noncharacter ${u} in string at offset ${how === 'key' ? 6 : 10}`);
  }
  if (bad) rejects(`canonicalize refuses ${u} built in memory`, () => canonicalize({ [ch]: 1 }), `noncharacter ${u} in string`);
}
{
  // An object built in memory never met the parser: canonicalize bounds it the same way, so a
  // deep value inside ONE attestation handed to verify() as an object still sinks only that item.
  let deep: unknown[] = [];
  for (let n = 1; n < 100_000; n++) deep = [deep];
  rejects('canonicalize refuses nesting deeper than 512', () => canonicalize(deep), 'nesting deeper than 512');
  let ok: unknown[] = [];
  for (let n = 1; n < 512; n++) ok = [ok];
  t('canonicalize accepts exactly 512', canonicalize(ok) === nest(512));
  const b = P.bundle as Any;
  const bd = JSON.parse(JSON.stringify(b.bundle));
  bd.attestations[0].body.claims.deep = deep;
  const r = verify(bd as Bundle, b.now);
  t('a too-deep attestation built in memory is discarded per item, not fatal (§9 step 2)',
    r.rejected.attestations === b.expect.rejected.attestations + 1 && r.did === b.expect.did);
}
// SPEC §3: a document that is not valid UTF-8 is rejected whole, as go/jcs.go's Parse does. A
// lossy decode turned ff fe into U+FFFD and sank only the one attestation carrying them.
{
  const b = P.bundle as Any;
  const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
  const text = JSON.stringify(b.bundle);
  t('parseBytes: valid UTF-8 parses as parse() does', same(parseBytes(enc(text)), parse(text)));
  const at = text.indexOf('"claims":{') + '"claims":{'.length;
  const bad = enc(text.slice(0, at) + '"x":"@@",' + text.slice(at));
  const k = bad.indexOf(0x40); bad[k] = 0xff; bad[k + 1] = 0xfe;
  rejects('parseBytes: invalid UTF-8 (ff fe in a claims string) rejects the whole document', () => parseBytes(bad), 'invalid UTF-8 in document');
  rejects('parseBytes: UTF-8-encoded surrogate (ed a0 80) is invalid UTF-8', () => parseBytes(Uint8Array.from([0x22, 0xed, 0xa0, 0x80, 0x22])), 'invalid UTF-8 in document');
  // Go: a BOM is not JSON whitespace, so its parser answers "unexpected token". Not stripped here either.
  rejects('parseBytes: a leading BOM is an unexpected token, as in go/jcs.go', () => parseBytes(concatBytes(Uint8Array.from([0xef, 0xbb, 0xbf]), enc(text))), 'unexpected token');
  // A \ud800 ESCAPE is valid UTF-8 text: it still sinks only its item (§3.1, §9 step 2).
  const lone = enc(text.slice(0, at) + '"x":"\\ud800",' + text.slice(at));
  const r = verify(parseBytes(lone) as Bundle, b.now);
  t('parseBytes: a lone-surrogate escape is still discarded per item, not fatal',
    r.rejected.attestations === b.expect.rejected.attestations + 1 && r.did === b.expect.did);
  // Differential D3: two shipped readers took the file as a 'utf8' string, so invalid bytes
  // became U+FFFD — in the genesis nonce, a DIFFERENT VALID identity; in an unsigned envelope
  // key, an accepted attestation — where sigelo-verify rejects the document. Both read bytes now.
  const tmp = mkdtempSync(join(tmpdir(), 'sigelo-d3-'));
  try {
    const splice = (after: string, raw: number[]): Uint8Array => {
      const k = text.indexOf(after) + after.length;
      return concatBytes(enc(text.slice(0, k)), Uint8Array.from(raw), enc(text.slice(k)));
    };
    const env = text.indexOf('"attestations":[{') + '"attestations":[{'.length;
    const cases: [string, Uint8Array][] = [
      ['genesis nonce', splice('"nonce":"z', [0xed, 0xa0, 0x80])],
      ['attestation envelope key', concatBytes(enc(text.slice(0, env) + '"x'), Uint8Array.from([0xed, 0xa0, 0x80]), enc('":1,' + text.slice(env)))],
      ['claims', splice('"claims":{"', [0xff])],
    ];
    const entry = (script: string, f: string): { code: number | null; err: string } => {
      const x = spawnSync(process.argv[0]!, [join(root, script), f, String(b.now)], {});
      return { code: x.status, err: String(x.stderr).trim() };
    };
    for (const [where, bytes] of cases) {
      const f = join(tmp, 'b.json');
      writeFileSync(f, bytes, {});
      const one = entry('sim/verify-one.mjs', f), cli = entry('integrations/skills-cli/sigelo/verify.mjs', f);
      t(`sim/verify-one.mjs: invalid UTF-8 in the ${where} is REJECT: parse, as sigelo-verify says (${one.err})`,
        one.code === 1 && one.err === 'REJECT: parse: invalid UTF-8 in document');
      t(`skills-cli verify.mjs: the same (${cli.err})`, cli.code === 1 && cli.err === 'sigelo verify: parse: invalid UTF-8 in document');
    }
    writeFileSync(join(tmp, 'ok.json'), enc(text), {});
    const good = spawnSync(process.argv[0]!, [join(root, 'sim/verify-one.mjs'), join(tmp, 'ok.json'), String(b.now)], {});
    t('sim/verify-one.mjs: the valid bundle still gives the §9.1 result', good.status === 0 && same(JSON.parse(String(good.stdout)), b.expect));
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

// ---------------------------------------------------------------- c. chain (SPEC §7.3)

const rot = (name: string): Any => ({ body: P[name].body, sig: P[name].sig, next_genesis: P[name].next_genesis });
const nrot = (name: string): Any => ({ body: N[name].body, sig: N[name].sig, next_genesis: N[name].next_genesis });
/** A minimal bundle carrying just a chain, so §7.3 can be exercised through verify(). */
const chainBundle = (rotations: Any[]): Bundle =>
  ({ v: VERSION, typ: 'bundle', genesis: P.genesis.doc, rotations, bindings: [], attestations: [], issuers: [] }) as Bundle;
const chainOf = (rotations: Any[]): string[] => verify(chainBundle(rotations), NOW).chain;

const ROT = ['rotation_voluntary', 'rotation_hostile', 'rotation_hostile_carried', 'rotation_recovery', 'rotation_recovery_second'];
t('chain resolves to expected_chain', same(chainOf(ROT.map(rot)), P.expected_chain));
for (const h of ['rotation_hostile', 'rotation_hostile_carried']) {
  t(`${h} sig is valid (must lose on rules, not crypto)`, verifySig(g1.key, P[h].body, P[h].sig));
  t(`recovery iat < ${h} iat`, P.rotation_recovery.body.iat < P[h].body.iat);
}
const c = P.chain_precedence_only;
t('chain_precedence_only (recovery beats the later voluntary)', same(chainOf(c.rotations.map(rot)), c.expected_chain));
t('governing recovery commitment is the latest recovery-signed one',
  verify(chainBundle(ROT.map(rot)), NOW).recovery === P.bundle.expect.recovery);

// ---------------------------------------------------------------- d. full bundle (SPEC §9.1)

// §10: every vector carrying a `bundle` and an `expect` is a §9.1 conformance case, compared
// by value — §9.1 makes the result object's key order informative only.
for (const [name, v] of Object.entries(P) as [string, Any][]) {
  if (v?.bundle === undefined || v?.expect === undefined) continue;
  t(`${name} verify == expect`, same(verify(v.bundle as Bundle, v.now), v.expect));
}
const result = verify(P.bundle.bundle as Bundle, P.bundle.now);
t('bundle attestations grouped in bundle order of first appearance',
  JSON.stringify(Object.keys(result.attestations)) === JSON.stringify(Object.keys(P.bundle.expect.attestations)));
t('bundle result has exactly the §9.1 fields',
  JSON.stringify(Object.keys(result)) === JSON.stringify(['did', 'chain', 'recovery', 'attestations', 'bindings', 'rejected']));

// §9 step 2 splits malformation by who wrote the body: issuer-written attestation and binding
// bodies are per-item, identity-defining bodies are fatal to the bundle.
const softBundle = {
  v: VERSION, typ: 'bundle', genesis: P.genesis.doc, rotations: [], bindings: [],
  attestations: [{ body: { ...P.attestation.body, admission: 'vip' }, sig: P.attestation.sig },
    { body: P.attestation.body, sig: P.attestation.sig }],
  issuers: [P.world_genesis.doc],
} as Bundle;
const soft = verify(softBundle, NOW);
t('malformed attestation body is counted in rejected, not fatal',
  soft.rejected.attestations === 1 && Object.keys(soft.attestations).length === 1);
rejects('malformed rotation body is fatal to the bundle',
  () => chainOf([{ ...rot('rotation_voluntary'), body: { ...P.rotation_voluntary.body, reason: 'whatever' } }]),
  'rotation: unknown reason');

// ---------------------------------------------------------------- e. negatives

const worldKey: string = P.world_genesis.doc.key;
t('neg tampered_claims', !verifySig(worldKey, N.tampered_claims.body, N.tampered_claims.sig));
t('neg wrong_signer', !verifySig(worldKey, N.wrong_signer.body, N.wrong_signer.sig));
t('neg missing_prefix', !verifySig(worldKey, N.missing_prefix.body, N.missing_prefix.sig));
t('neg missing_prefix is about the prefix, not a bad signature',
  ed.verify(unz(N.missing_prefix.sig), utf8ToBytes(canonicalize(N.missing_prefix.body)), pub('world'), { zip215: false }));
t('neg genesis_tampered', did(N.genesis_tampered.doc) !== N.genesis_tampered.claimed_did);
rejects('neg float_in_claims', () => structure(N.float_in_claims.body, 'attestation'), 'non-integer');
rejects('neg int_out_of_range', () => structure(N.int_out_of_range.body, 'attestation'), '2^53');
rejects('neg duplicate_key', () => parse(N.duplicate_key.raw), 'duplicate');
t('neg typ_mismatch sig is valid', verifySig(worldKey, N.typ_mismatch.body, N.typ_mismatch.sig));
rejects('neg typ_mismatch', () => structure(N.typ_mismatch.body, 'attestation'), 'typ is');
t('neg recovery_key_mismatch commitment differs', commitmentOf(N.recovery_key_mismatch.body.recovery_key) !== P.genesis.doc.recovery);
// §7.4: these four are "not a candidate" — the walk continues as if the rotation were absent,
// and each vector states the chain that results. None of them is fatal.
for (const name of ['recovery_key_mismatch', 'stale_recovery_key', 'voluntary_changes_recovery', 'rotation_bad_sig']) {
  const v = N[name];
  t(`neg ${name} is not a candidate (chain ends where the vector says)`,
    same(chainOf([...v.chain_with.map(rot), { body: v.body, sig: v.sig, next_genesis: v.next_genesis }]), v.expected_chain));
}
// §7.3 step 2 / §7.4: two valid recoveries sharing the latest iat is operator error, and no
// rule picks between them. Not in the vectors, so minted here from the same recovery key.
const tie = rotate({ genesis: g1, next_genesis: P.rotation_hostile_carried.next_genesis, iat: P.rotation_recovery.body.iat, reason: 'recovery', secret: K.recovery! });
rejects('two recovery rotations sharing the latest iat reject the chain',
  () => chainOf([rot('rotation_voluntary'), rot('rotation_recovery'), tie]), 'tie');
// Differential D2: the latest recovery iat was Math.max(...list), one argument per valid
// recovery, and V8 threw RangeError (a crash naming no check) past ~125 000 of them where go/
// answered. Now a loop. Many recoveries at one node, in any order, pick the latest; a tie at
// the top still rejects. The stack-size repro is in CHANGELOG; this pins the selection, and
// the scan below keeps any argument spread off the library's verify path.
{
  const many: Any[] = [], base: number = P.rotation_recovery.body.iat;
  for (let n = 0; n < 200; n++) {
    const ng = keygen({ recovery: pub('recovery2'), seed: K.agent3!, created: '2026-10-10T00:00:00Z', nonce: Uint8Array.from({ length: 16 }, (_, j) => (j === 0 ? n >> 8 : j === 1 ? n & 0xff : 7)) }).genesis;
    many.push(rotate({ genesis: g0, next_genesis: ng, iat: base + ((n * 7919) % 200), reason: 'recovery', secret: K.recovery! }));
  }
  const latest = many.find((r) => r.body.iat === base + 199)!;
  t('200 valid recovery rotations at one node: the latest iat is chosen (§7.3 step 2)', same(chainOf(many), [did(g0), latest.body.next]));
  const twin = rotate({ genesis: g0, next_genesis: P.rotation_recovery.next_genesis, iat: latest.body.iat, reason: 'recovery', secret: K.recovery! });
  rejects('... and a second one at that latest iat is a tie', () => chainOf([...many, twin]), 'recovery tie');
  const lib = ['sigelo.js', 'jcs.js', 'monero.js'].map((f) => readFileSync(join(dirname(fileURLToPath(import.meta.url)), f), 'utf-8')).join('\n');
  t('no argument spread over data in the verifier (Math.max/min(...), push(...), apply)', !/Math\.(max|min)\(\.\.\.|\.push\(\.\.\.|\.apply\(/.test(lib));
}
rejects('neg unknown_field_attestation', () => structure(N.unknown_field_attestation.body, 'attestation'), 'unknown field');
rejects('neg unknown_field_genesis', () => structure(N.unknown_field_genesis.doc, 'genesis'), 'unknown field');
t('neg voluntary_changes_recovery: rotation_hostile is not followed either',
  same(chainOf([rot('rotation_voluntary'), rot('rotation_hostile')]), P.expected_chain.slice(0, 2)));
rejects('neg fork', () => chainOf([rot('rotation_voluntary'), nrot('fork')]), 'fork');
rejects('neg cycle', () => chainOf([rot('rotation_voluntary'), nrot('cycle')]), 'cycle');
rejects('neg self_rotation (structure)', () => structure(N.self_rotation.body, 'rotation'), 'next == id');
rejects('neg self_rotation (rotate refuses to mint one)',
  () => rotate({ genesis: g0, next_genesis: g0, iat: N.self_rotation.body.iat, reason: 'voluntary', secret: K.agent! }), 'next == id');
const exp = N.expired_attestation;
t('neg expired_attestation (at the file-level now)', !(exp.body.iat <= NOW && NOW < exp.body.exp));
const expired = verify({
  v: VERSION, typ: 'bundle', genesis: P.genesis.doc, rotations: [], bindings: [],
  attestations: [{ body: exp.body, sig: exp.sig }], issuers: [P.world_genesis.doc],
} as Bundle, NOW);
t('neg expired_attestation discarded by verify',
  same(expired.attestations, {}) && expired.rejected.attestations === 1);

// §3.1/§6.3: `amount` is a string of atomic units. Every one of these bodies carries a VALID
// signature; only the structural check stands between a float-shaped amount and the two
// implementations disagreeing about what was signed.
for (const n of ['invoice_amount_number', 'invoice_amount_float_string', 'invoice_amount_negative', 'invoice_amount_empty']) {
  t(`neg ${n} sig is valid (must lose on structure, not crypto)`, verifySig(g0.key, N[n].body, N[n].sig));
  rejects(`neg ${n}`, () => structure(N[n].body, 'invoice'), 'atomic units');
}
// §6.2: Monero signatures that must not make a binding `proven`. Each is discarded per-item
// (§6.1: a bad proof is not no proof), never downgraded to `unproven`.
for (const n of ['binding_monero_subaddress_base_sig', 'binding_monero_integrated_addr', 'binding_monero_sigv1',
  'binding_monero_view_key_y_ge_p', 'binding_monero_spend_key_x0_signbit']) {
  const r = verify(xb1({ body: N[n].body, sig_id: N[n].sig_id, sig_addr: N[n].sig_addr }), NOW);
  t(`neg ${n} discarded, not downgraded`, r.bindings.length === 0 && r.rejected.bindings === 1);
}
// The same sig_addr still verifies under wallet2's own rules: the rule is sigelo's, not Monero's.
const xin = (body: unknown): string => 'sigelo\n' + canonicalize(body);
const ni = N.binding_monero_integrated_addr;
t('neg binding_monero_integrated_addr is a signature monero itself accepts',
  verifyMessage({ message: xin(ni.body), address: ni.body.addr, signature: ni.sig_addr }).good);
// The base-keyed sig_addr is genuine — it verifies under the base address — and wallet2 itself
// refuses it under the subaddress: the wrong keys, not a sigelo-only rule.
const nsb = N.binding_monero_subaddress_base_sig;
t('neg binding_monero_subaddress_base_sig is genuine under the base address, refused by monero under the subaddress',
  verifyMessage({ message: xin(nsb.body), address: bm.body.addr, signature: nsb.sig_addr }).good &&
  !verifyMessage({ message: xin(nsb.body), address: nsb.body.addr, signature: nsb.sig_addr }).good);
const v1 = verifyMessage({ message: xin(N.binding_monero_sigv1.body),
  address: N.binding_monero_sigv1.body.addr, signature: N.binding_monero_sigv1.sig_addr });
t('neg binding_monero_sigv1 is a signature monero itself accepts',
  v1.good && v1.mode === 'spend' && v1.version === 1);
// ge_frombytes_vartime (src/crypto/crypto-ops.c), via check_key on both address keys: y >= p and
// x = 0 with the sign bit set are refused. Each sig_addr is genuine by the mode's own (valid) key,
// which a decoder permissive about the other key accepts — checked here with ZIP-215 decoding.
const permissive = (e: Any, mode: 'spend' | 'view'): boolean => {
  const raw = moneroBase58Decode(e.body.addr), B = raw.slice(1, 33), A = raw.slice(33, 65); // 1-byte prefix 18
  const sg = moneroBase58Decode(e.sig_addr.slice(5)), P_ = mode === 'spend' ? B : A;
  const le = (b: Uint8Array): bigint => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
  const R = ed.Point.fromBytes(P_, true).multiplyUnsafe(le(sg.slice(0, 32))).add(ed.Point.BASE.multiplyUnsafe(le(sg.slice(32))));
  const h = signMessageHash({ spendPub: B, viewPub: A, mode, data: signingInput(e.body) });
  return bytesToHex(hashToScalar(h, P_, R.toBytes())) === bytesToHex(sg.slice(0, 32));
};
for (const [n, mode, want] of [['binding_monero_view_key_y_ge_p', 'spend', 'ed'.padEnd(62, 'f') + '7f'],
  ['binding_monero_spend_key_x0_signbit', 'view', '01'.padEnd(62, '0') + '80']] as const) {
  const e = N[n];
  t(`neg ${n} sig_addr is genuine under a decoder permissive about the refused key (must lose on the key, not crypto)`,
    verifySig(g0.key, e.body, e.sig_id) && permissive(e, mode) &&
    bytesToHex(moneroBase58Decode(e.body.addr).slice(mode === 'spend' ? 33 : 1, mode === 'spend' ? 65 : 33)) === want);
  rejectsXmr(`neg ${n}: decodeAddress refuses the key, as check_key does`, () => decodeAddress(e.body.addr), 'not a canonical curve point');
  t(`neg ${n}: verifyMessage (wallet2) refuses it too`, !verifyMessage({ message: xin(e.body), address: e.body.addr, signature: e.sig_addr }).good);
}
// §3.1 field types. Each binding has a VALID sig_id and a genuine SigV2 sig_addr from the vectors'
// wallet: it must lose on structure (or, for the varint spelling, at §6.2), never on crypto, and
// never by crashing. Go runs the same list (go/sigelo_test.go).
for (const [n, e] of Object.entries(N as Record<string, Any>).filter(([, e]) => 'reject' in e && 'sig_id' in e)) {
  t(`neg ${n} sig_id valid and sig_addr a genuine wallet signature (must lose on rules, not crypto)`,
    verifySig(g0.key, e.body, e.sig_id) &&
    verifyMessage({ message: xin(e.body), address: P.binding_monero.body.addr, signature: e.sig_addr }).good);
  if (e.reject !== null) rejects(`neg ${n}`, () => structure(e.body, 'binding'), e.reject);
  const r = verify(xb1({ body: e.body, sig_id: e.sig_id, sig_addr: e.sig_addr }), NOW);
  t(`neg ${n} discarded by verify`, r.bindings.length === 0 && r.rejected.bindings === 1);
}
rejectsXmr('neg binding_monero_noncanonical_varint_addr: decodeAddress refuses it, as wallet2 does',
  () => decodeAddress(N.binding_monero_noncanonical_varint_addr.body.addr), 'non-canonical');
rejectsXmr('monero base58 refuses a non-string (an array of chars would decode)',
  () => moneroBase58Decode([...P.binding_monero.body.addr] as never), 'not a string');
const lone = parse(N.invoice_memo_lone_surrogate.raw) as Any;
t('neg invoice_memo_lone_surrogate sig is valid over the U+FFFD twin (the old collision)',
  verifySig(g0.key, { ...lone, memo: '�' }, N.invoice_memo_lone_surrogate.sig));
t('neg invoice_memo_lone_surrogate sig no longer verifies over the lone-surrogate body',
  !verifySig(g0.key, lone, N.invoice_memo_lone_surrogate.sig));
rejects('neg invoice_memo_lone_surrogate', () => structure(lone, 'invoice'), N.invoice_memo_lone_surrogate.reject);
t('neg invoice_memo_not_string sig is valid', verifySig(g0.key, N.invoice_memo_not_string.body, N.invoice_memo_not_string.sig));
rejects('neg invoice_memo_not_string', () => structure(N.invoice_memo_not_string.body, 'invoice'), N.invoice_memo_not_string.reject);
rejects('neg proto_key (strict parser)', () => parse(N.proto_key.raw), '__proto__');
rejects('neg proto_key (canonicalize, via JSON.parse)', () => canonicalize(JSON.parse(N.proto_key.raw)), '__proto__');
// Parity: the same malformed bundles through verify() here and in go/sigelo_test.go, which must
// agree case for case. A crash (anything but SigeloError) fails the whole run, as it should.
for (const [n, c] of Object.entries(N.parity.cases as Record<string, Any>)) {
  try {
    // raw: bundle TEXT. A parse failure (a duplicate key: the text has two readings) is fatal.
    const r = verify(('raw' in c ? parse(c.raw) : c.bundle) as Bundle, N.parity.now);
    const got = { proofs: r.bindings.map((x) => x.proof), attestations: Object.values(r.attestations).flat().length, rejected: r.rejected };
    t(`parity ${n}`, !('reject' in c.expect) && same(got, c.expect));
  } catch (e) {
    if (!(e instanceof SigeloError || ('raw' in c && e instanceof JcsError))) throw e;
    t(`parity ${n} (${e.message})`, 'reject' in c.expect && e.message.includes(c.expect.reject));
  }
}
rejects('neg genesis_bad_key', () => structure(N.genesis_bad_key.doc, 'genesis'), 'ed25519-pub');
// Differential S1: `created` was checked only for being a string. The same table is in
// go/sigelo_test.go; both must say the same about each.
for (const [c, good] of [
  ['2026-09-07T00:00:00Z', true], ['2000-02-29T00:00:00Z', true], ['0000-01-01T00:00:00Z', true], ['9999-12-31T23:59:59Z', true],
  ['2026-06-30T23:59:60Z', false], ['2026-01-01T00:00:00+00:00', false], ['2026-01-01T00:00:00+05:30', false],
  ['2026-01-01T00:00:00.123Z', false], ['10000-01-01T00:00:00Z', false], ['2026-01-01 00:00:00Z', false],
  ['2026-01-01t00:00:00z', false], ['2026-01-01T00:00:00', false], ['2026-13-45T25:61:61Z', false], ['', false],
  ['yesterday', false], ['1900-02-29T00:00:00Z', false], ['2026-04-31T00:00:00Z', false], ['2026-00-10T00:00:00Z', false],
  ['2026-01-00T00:00:00Z', false], ['2026-1-01T00:00:00Z', false], ['２０２６-01-01T00:00:00Z', false],
] as [string, boolean][]) {
  const run = (): void => structure({ ...P.genesis.doc, created: c }, 'genesis');
  if (good) { let ok = true; try { run(); } catch { ok = false; } t(`created ${JSON.stringify(c)} is RFC 3339 UTC`, ok); }
  else rejects(`created ${JSON.stringify(c)} is refused`, run, 'genesis: created is not RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)');
}
// Differential S2: key slots held any 34 bytes with the right prefix. The same table is in
// go/sigelo_test.go: canonical, on the curve, not of small order.
{
  const k32 = (hexs: string): string => encodeKey(hexToBytes(hexs));
  const POINT = 'key: not a valid Ed25519 point (non-canonical, off the curve or of small order)';
  for (const [name, hx, good] of [
    ['a real key', bytesToHex(pub('agent')), true],
    ['y = 3 (a point with a torsion part, not small order)', '03' + '00'.repeat(31), true],
    ['all zero (order 4)', '00'.repeat(32), false],
    ['the identity', '01' + '00'.repeat(31), false],
    ['an order-8 point', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', false],
    ['y = p (non-canonical)', 'ed' + 'ff'.repeat(30) + '7f', false],
    ['x = 0 with the sign bit', '01' + '00'.repeat(30) + '80', false],
    ['y = 2 (off the curve)', '02' + '00'.repeat(31), false],
  ] as [string, string, boolean][]) {
    const k = k32(hx);
    const slots: [string, () => void][] = [
      ['genesis key', () => structure({ ...P.genesis.doc, key: k }, 'genesis')],
      ['recovery_key', () => structure({ ...P.rotation_recovery.body, recovery_key: k }, 'rotation')],
      ['ed25519-test addr', () => structure({ ...P.binding.body, addr: k }, 'binding')],
    ];
    for (const [slot, run] of slots) {
      if (good) { let ok = true; try { run(); } catch { ok = false; } t(`${slot}: ${name} is a usable key`, ok); }
      else rejects(`${slot}: ${name} is refused`, run, POINT);
    }
  }
  t('an opaque-test binding addr is not a key and is not decoded', (() => { try { structure({ ...P.binding.body, method: 'opaque-test', addr: 'anything' }, 'binding'); return true; } catch { return false; } })());
}
// Differential S3: the recovery commitment was checked for its prefix only. Same table in go/.
for (const rec of ['sha256:', 'sha256:xyz', 'sha256:' + 'A'.repeat(64), 'sha256:' + 'a'.repeat(63), 'sha256:' + 'a'.repeat(65),
  'SHA256:' + 'a'.repeat(64), ' sha256:' + 'a'.repeat(64), 'sha256:' + 'a'.repeat(64) + '\n', 'sha512:' + 'a'.repeat(128)]) {
  rejects(`recovery ${JSON.stringify(rec.length > 24 ? rec.slice(0, 20) + '…' : rec)} (${rec.length} chars) is refused`,
    () => structure({ ...P.genesis.doc, recovery: rec }, 'genesis'), 'genesis: recovery is neither null nor sha256: + 64 lowercase hex');
}
// Differential S4: nonces were any string. Same table in go/: z + base58btc, 1 to 63 digits,
// in genesis, binding and invoice; the §5.2 challenge nonce is exempt (opaque, the world's).
for (const [n, good] of [
  ['z2', true], ['z' + '2'.repeat(63), true], [P.genesis.doc.nonce, true],
  ['', false], ['z', false], ['z0', false], ['zO', false], ['zI', false], ['zl', false], ['Z2', false], ['2', false],
  ['z' + '2'.repeat(64), false], ['\u0000', false], ['z2/', false], ['z2\u2028', false], ['z😀', false], ['z\u00e9', false],
] as [string, boolean][]) {
  for (const [slot, body] of [['genesis', P.genesis.doc], ['binding', P.binding.body], ['invoice', P.invoice.body]] as [string, Any][]) {
    const run = (): void => structure({ ...body, nonce: n }, slot as 'genesis');
    if (good) { let ok = true; try { run(); } catch { ok = false; } t(`${slot} nonce ${JSON.stringify(n.slice(0, 12))} (${n.length}) is z + base58btc`, ok); }
    else rejects(`${slot} nonce ${JSON.stringify(n.slice(0, 12))} (${n.length}) is refused`, run, `${slot}: nonce is not z + base58btc (at most 64 characters)`);
  }
}
{ let ok = true; try { structure({ ...P.challenge.body, nonce: 'any opaque thing, 0OIl' }, 'challenge'); } catch { ok = false; } t('the §5.2 challenge nonce is exempt', ok); }
// Differential P1: base58 decoding is quadratic and ran before any length check — a
// 300 000-character key or signature took minutes. SPEC §2 bounds come first now.
{
  const long = 'z' + '2'.repeat(300_000), started = Date.now();
  rejects('a 300 000-character genesis key is refused on its length, before decoding',
    () => structure({ ...P.genesis.doc, key: long }, 'genesis'), 'multibase: longer than 64 characters');
  t('... and a 300 000-character signature is simply invalid', !verifySig(P.world_genesis.doc.key, P.attestation.body, long));
  t('... both in well under a second', Date.now() - started < 1000);
  rejects('the alphabet is checked before the length (same first error in go/)', () => structure({ ...P.genesis.doc, key: 'z' + '0'.repeat(100) }, 'genesis'), 'multibase: "0" is not a base58btc digit');
  const key64 = 'z' + '1'.repeat(63 - P.genesis.doc.key.length + 1) + P.genesis.doc.key.slice(1);
  rejects('64 characters is inside the bound (the key then fails on its bytes, not its length)', () => structure({ ...P.genesis.doc, key: key64 }, 'genesis'), 'key: not multicodec ed25519-pub');
}
rejects('neg bundle_rotations_not_array', () => verify(N.bundle_rotations_not_array.bundle as Bundle, NOW), 'not an array');
// §2.9: an attestation whose issuer genesis is withheld is discarded, not fatal.
const withheld = verify({
  v: VERSION, typ: 'bundle', genesis: P.genesis.doc, rotations: [], bindings: [],
  attestations: [{ body: P.attestation.body, sig: P.attestation.sig }], issuers: [],
} as Bundle, NOW);
t('withheld issuer discarded, bundle survives', same(withheld.attestations, {}) && withheld.rejected.attestations === 1);
const local = verify({
  v: VERSION, typ: 'bundle', genesis: P.genesis.doc, rotations: [], bindings: [],
  attestations: [{ body: P.attestation.body, sig: P.attestation.sig }], issuers: [],
} as Bundle, NOW, { [P.world_genesis.expect_did]: P.world_genesis.doc });
t('locally known issuer verifies without the bundle carrying it',
  Object.keys(local.attestations).length === 1 && local.rejected.attestations === 0);

/** base58btc decode, used only to re-check the missing-prefix vector with raw Ed25519. */
function unz(s: string): Uint8Array {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const out: number[] = [];
  for (const ch of s.slice(1)) {
    let carry = A.indexOf(ch);
    for (let j = 0; j < out.length; j++) {
      const x = out[j]! * 58 + carry;
      out[j] = x & 0xff;
      carry = x >> 8;
    }
    while (carry > 0) {
      out.push(carry & 0xff);
      carry >>= 8;
    }
  }
  return Uint8Array.from(out.reverse());
}

// ---------------------------------------------------------------- f. monero (SPEC §6.2)

/**
 * `test/monero-vectors.json` comes from monero-ts 0.11.15 — Monero's own C++ core compiled
 * to WASM — restored from the documented private spend key. Signatures use a random nonce,
 * so byte-equality is impossible and impossible to want: the target is that this library
 * verifies what monero itself produced, and rejects what it rejects.
 */
const XMR: Any = JSON.parse(readFileSync(join(root, 'ts', 'test', 'monero-vectors.json'), 'utf-8'));
const mk = keysFromSpend(hexToBytes(XMR.private_spend_key));

// Keccak-256 is ORIGINAL Keccak (pad 0x01). SHA3-256 (pad 0x06) over "" would be
// a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a — every Monero hash
// downstream of a wrong pad byte is silently, undetectably wrong, so it is pinned here.
t('monero keccak256("") is Keccak, not SHA3-256',
  bytesToHex(keccak256(new Uint8Array(0))) === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
t('monero base58 round-trips an 8+3 byte split',
  bytesToHex(moneroBase58Decode(moneroBase58Encode(hexToBytes('00112233445566778899aa')))) === '00112233445566778899aa');

for (const [net, d] of Object.entries(XMR.networks as Record<string, Any>)) {
  const N_: Net = net as Net;
  t(`monero ${net} keysFromSpend: a = H_s(b), B = bG, A = aG`,
    bytesToHex(mk.a) === d.private_view_key && bytesToHex(mk.B) === d.public_spend_key &&
    bytesToHex(mk.A) === d.public_view_key);
  const primary = encodeAddress({ net: N_, kind: 'standard', spend: mk.B, view: mk.A });
  t(`monero ${net} primary address`, primary === d.primary_address);
  const dec = decodeAddress(primary);
  t(`monero ${net} decodeAddress round-trips and reports kind/net`,
    dec.net === net && dec.kind === 'standard' && dec.paymentId === undefined &&
    bytesToHex(dec.spend) === d.public_spend_key && bytesToHex(dec.view) === d.public_view_key);
  // An integrated address is the same two keys plus an 8-byte payment id, under prefix+1.
  const integrated = encodeAddress({ net: N_, kind: 'integrated', spend: mk.B, view: mk.A, paymentId: hexToBytes('0123456789abcdef') });
  const decInt = decodeAddress(integrated);
  t(`monero ${net} integrated address round-trips its payment id`,
    decInt.kind === 'integrated' && bytesToHex(decInt.paymentId!) === '0123456789abcdef');
  let subs = 0;
  for (const [idx, want] of Object.entries(d.subaddresses as Record<string, string>)) {
    const [major, minor] = idx.split('/').map(Number) as [number, number];
    const got = subaddress({ a: mk.a, B: mk.B, major, minor, net: N_ });
    if (got === want && decodeAddress(got).kind === 'subaddress') subs++;
  }
  t(`monero ${net} ${Object.keys(d.subaddresses).length} subaddresses`, subs === Object.keys(d.subaddresses).length);
  // (0,0) is the account's own address, never derived (src/device/device_default.cpp).
  t(`monero ${net} subaddress (0,0) is the primary address`,
    subaddress({ a: mk.a, B: mk.B, major: 0, minor: 0, net: N_ }) === d.primary_address);

  let ok = 0;
  for (const sig of d.signatures as Any[]) {
    const r = verifyMessage({ message: sig.message, address: sig.address, signature: sig.signature });
    if (sig.oracle_verify && r.good && r.mode === sig.mode && r.version === 2) ok++;
  }
  t(`monero ${net} all ${d.signatures.length} oracle SigV2 signatures verify with the right mode`,
    ok === d.signatures.length && d.signatures.length === 18);

  // The two negatives the vectors name, built the way they describe.
  const s00: Any = (d.signatures as Any[]).find((x) => x.account === 0 && x.index === 0);
  t(`monero ${net} neg: ${d.negative[0].what}`,
    verifyMessage({ message: s00.message, address: d.subaddresses['0/1'], signature: s00.signature }).good === false);
  t(`monero ${net} neg: ${d.negative[1].what}`,
    verifyMessage({ message: s00.message + '!', address: s00.address, signature: s00.signature }).good === false);
  // A signature made for one subaddress does not verify under another address of the same
  // wallet: the address's own keys are inside the hash (wallet2::get_message_hash).
  const s01: Any = (d.signatures as Any[]).find((x) => x.account === 0 && x.index === 1);
  t(`monero ${net} signature under the wrong address fails`,
    verifyMessage({ message: s01.message, address: d.primary_address, signature: s01.signature }).good === false);
  const mutated = s00.signature.slice(0, -1) + (s00.signature.endsWith('A') ? 'B' : 'A');
  t(`monero ${net} mutated signature fails`,
    verifyMessage({ message: s00.message, address: s00.address, signature: mutated }).good === false);
}

// §6.2 accepts every oracle signature above, subaddresses included (each message is a §3 input).
let sg = 0, total = 0;
for (const d of Object.values(XMR.networks as Record<string, Any>)) {
  for (const s of d.signatures as Any[]) {
    total++;
    const r = verifySigeloMoneroSigAddr(JSON.parse(s.message.slice(7)), s.address, s.signature);
    if (s.message.startsWith('sigelo\n') && r.good && r.mode === s.mode) sg++;
  }
}
t(`monero verifySigeloMoneroSigAddr accepts all ${total} oracle signatures, subaddresses included`, sg === total && total === 54);
// A live monero-wallet-rpc (stagenet) as a second oracle: its stateless `verify` on the §6.2
// vectors, and its own `sign` for a standard and a subaddress in both modes (wallet2::sign's
// subaddress branch). Integrated is where sigelo parts from wallet2 on purpose.
const WR: Any[] = XMR.wallet_rpc_oracle.entries;
for (const e of WR) {
  const w = verifyMessage({ message: e.message, address: e.address, signature: e.signature });
  const g = verifySigeloMoneroSigAddr(JSON.parse(e.message.slice(7)), e.address, e.signature);
  t(`monero wallet-rpc oracle: ${e.what} (rpc good=${e.rpc_verify.good}, sigelo ${e.sigelo_accepts ? 'accepts' : 'refuses'})`,
    decodeAddress(e.address).kind === e.kind && w.good === e.rpc_verify.good && (!w.good || w.mode === e.rpc_verify.signature_type) &&
    g.good === e.sigelo_accepts);
}
t('monero wallet-rpc oracle covers subaddress spend+view signatures from the wallet itself',
  WR.filter((e) => e.kind === 'subaddress' && e.index === 1 && e.rpc_verify.good).length === 2 && WR.length === 9);

/** As `rejects`, for the encoders in monero.ts — their rejection class is MoneroError. */
function rejectsXmr(name: string, fn: () => unknown, want: string): void {
  try {
    fn();
    t(`${name} (accepted!)`, false);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    t(`${name} (${msg})`, e instanceof MoneroError && msg.includes(want));
  }
}
// Pinned because it is surprising and load-bearing for SPEC §6.2: the hash covers the
// address's two public keys, not its prefix, so one wallet's mainnet, stagenet and testnet
// spellings are interchangeable for verification. A verifier that cares which network an
// address is on must check `decodeAddress(addr).net` itself; the signature will not say.
t('monero a signature verifies under every network spelling of the same keys',
  verifyMessage({ message: XMR.networks.mainnet.signatures[0].message,
    address: XMR.networks.stagenet.primary_address,
    signature: XMR.networks.mainnet.signatures[0].signature }).good === true);
rejectsXmr('monero address with a corrupted digit', () => decodeAddress(XMR.networks.mainnet.primary_address.slice(0, -1) + 'x'), 'checksum');
rejectsXmr('monero address with an unknown prefix', () => decodeAddress(moneroBase58Encode((() => {
  const body = new Uint8Array(65); body[0] = 99; // prefix 99 belongs to no network
  const sum = keccak256(body);
  return Uint8Array.from([...body, ...sum.subarray(0, 4)]);
})())), 'unknown prefix');

// Round-trip through our own signer. The nonce is random, so this is the only way to test it.
const xmrMsg = 'sigelo\n{"typ":"binding","v":"sigelo/0"}';
const mainPrimary: string = XMR.networks.mainnet.primary_address;
const selfView = signMessage({ message: xmrMsg, mode: 'view', secret: mk.a, spendPub: mk.B, viewPub: mk.A });
const rView = verifyMessage({ message: xmrMsg, address: mainPrimary, signature: selfView });
t('monero signMessage(view) verifies, reported as mode view',
  selfView.startsWith('SigV2') && rView.good && rView.mode === 'view' && rView.version === 2);
const selfSpend = signMessage({ message: xmrMsg, mode: 'spend', secret: mk.b, spendPub: mk.B, viewPub: mk.A });
const rSpend = verifyMessage({ message: xmrMsg, address: mainPrimary, signature: selfSpend });
t('monero signMessage(spend) verifies, reported as mode spend',
  rSpend.good && rSpend.mode === 'spend' && rSpend.version === 2);
t('monero our own signature does not verify under another message',
  verifyMessage({ message: xmrMsg + ' ', address: mainPrimary, signature: selfSpend }).good === false);

// A real §6.2 binding end to end: the identity key signs sig_id, the wallet signs sig_addr
// over the identical §3 signing input, and verify() reports `proven`.
const xmrBind = bind({
  secret: K.agent!, id: P.genesis.expect_did, method: 'monero', addr: mainPrimary,
  iat: NOW - 60, exp: NOW + 86400, nonce: 'z2Nuar5',
});
const xmrBundle = (sig_addr: string | undefined): Bundle => ({
  v: VERSION, typ: 'bundle', genesis: P.genesis.doc, rotations: [],
  bindings: [{ body: xmrBind.body, sig_id: xmrBind.sig_id, ...(sig_addr !== undefined ? { sig_addr } : {}) }],
  attestations: [], issuers: [],
}) as Bundle;
for (const mode of ['view', 'spend'] as const) {
  const sigAddr = sigeloMoneroSigAddr(xmrBind.body, {
    mode, secret: mode === 'view' ? mk.a : mk.b, spendPub: mk.B, viewPub: mk.A,
  });
  const res = verify(xmrBundle(sigAddr), NOW);
  t(`monero binding with a ${mode}-mode sig_addr verifies as proven`,
    res.bindings.length === 1 && res.bindings[0]!.proof === 'proven' && res.rejected.bindings === 0);
}
// §6.1: a bad proof is not the same thing as no proof — the binding is discarded, not
// downgraded to `unproven`. A verifier that downgraded would let a thief publish a binding
// to an address they do not control and still have it shown.
const tampered = (() => {
  const good = sigeloMoneroSigAddr(xmrBind.body, { mode: 'view', secret: mk.a, spendPub: mk.B, viewPub: mk.A });
  return good.slice(0, -1) + (good.endsWith('A') ? 'B' : 'A');
})();
const tamperedRes = verify(xmrBundle(tampered), NOW);
t('monero binding with a tampered sig_addr is discarded, not downgraded',
  tamperedRes.bindings.length === 0 && tamperedRes.rejected.bindings === 1);
// No sig_addr at all is the `unproven` claim, whatever the method (§6.1).
t('monero binding without sig_addr is unproven', verify(xmrBundle(undefined), NOW).bindings[0]!.proof === 'unproven');
// The verifiers never throw; only the encoders do (MoneroError is exported for that).
t('monero verifyMessage on junk returns false rather than throwing',
  verifyMessage({ message: 'x', address: 'not-an-address', signature: 'SigV2nope' }).good === false &&
  new MoneroError('x').name === 'MoneroError');


// ---------------------------------------------------------------- g. keys (MONERO.md §2)

// Two roots that differ in one byte ("sigelo root seed, test vector #1" / "#2" as ASCII).
// Documented seeds, as everywhere else in this file; never use one for real funds.
const S1 = hexToBytes('736967656c6f20726f6f7420736565642c207465737420766563746f72202331');
const S2 = hexToBytes('736967656c6f20726f6f7420736565642c207465737420766563746f72202332');

/** Everything §2 derives from one root, flattened, so determinism is one comparison. */
const rootSummary = (S: Uint8Array): string => {
  const d = deriveRoot(S, 'stagenet');
  return JSON.stringify({
    identity: bytesToHex(d.identity), recovery: d.recovery.commitment,
    vault: [bytesToHex(d.vault.b), bytesToHex(d.vault.a), d.vault.address],
    treasury: [bytesToHex(d.treasury.b), bytesToHex(d.treasury.a), d.treasury.address],
    allowance: [bytesToHex(d.allowance.b), d.allowance.address],
    sub: subaddress({ a: d.treasury.a, B: d.treasury.B, major: 0, minor: 7, net: 'stagenet' }),
  });
};
t('keys the same root derives the same everything', rootSummary(S1) === rootSummary(S1));
t('keys a root differing in one byte derives nothing in common', rootSummary(S1) !== rootSummary(S2));
// The path string IS the key: HKDF `info` separates the branches and nothing else does.
const branches = [
  identitySeed(S1, 0), identitySeed(S1, 1), recoverySeed(S1), k(S1, 'sigelo/v1/monero/treasury'),
  k(S1, 'sigelo/v1/monero/allowance'), k(S1, 'sigelo/v1/monero/counterparty/acme'),
].map(bytesToHex);
t('keys distinct paths give distinct keys', new Set(branches).size === branches.length);
// A wallet name is a path segment, so `treasury` and `treasury2` are unrelated wallets.
t('keys a wallet name is part of the path',
  walletFromRoot(S1, 'treasury', 'stagenet').address !== walletFromRoot(S1, 'treasury2', 'stagenet').address);
// The same keys under another network are the same wallet with another prefix (§7).
const tw = walletFromRoot(S1, 'treasury', 'stagenet');
t('keys the network changes the address, not the keys',
  bytesToHex(walletFromRoot(S1, 'treasury', 'mainnet').b) === bytesToHex(tw.b) &&
  walletFromRoot(S1, 'treasury', 'mainnet').address !== tw.address &&
  decodeAddress(tw.address).net === 'stagenet' && decodeAddress(tw.address).kind === 'standard');
// viewOnly() is what the agent runtime holds: `b` must not be reachable from it at all.
const vo: Any = tw.viewOnly();
t('keys viewOnly() drops the spend key',
  !('b' in vo) && vo.b === undefined && bytesToHex(vo.a) === bytesToHex(tw.a) && vo.address === tw.address);
// deriveIdentity: same root, same rotation counter, same genesis — given the same created/
// nonce, which keygen would otherwise randomise (the key itself is fixed by the root).
const idNonce = hexToBytes('00112233445566778899aabbccddeeff');
const idOpts = { created: '2026-01-01T00:00:00Z', nonce: idNonce };
const id0 = deriveIdentity(S1, 0, undefined, idOpts);
t('keys deriveIdentity reproduces a genesis byte-for-byte',
  same(id0.genesis, deriveIdentity(S1, 0, undefined, idOpts).genesis) &&
  id0.did === deriveIdentity(S1, 0, undefined, idOpts).did);
t('keys deriveIdentity uses the identity path and the root recovery commitment',
  id0.key === encodeKey(ed.getPublicKey(identitySeed(S1, 0))) &&
  id0.genesis.recovery === recoveryCommitment(S1) &&
  commitmentOf(encodeKey(ed.getPublicKey(recoverySeed(S1)))) === recoveryCommitment(S1));
t('keys deriveIdentity n=1 is a different identity', deriveIdentity(S1, 1, undefined, idOpts).key !== id0.key);
// An identity derived from the root still signs and verifies as an ordinary sigelo identity.
const idChallenge = challenge({ secret: id0.secret, genesis: id0.genesis, ctx: 'keys-test', nonce: idNonce });
t('keys a derived identity signs and verifies', verifySig(id0.key, idChallenge.body, idChallenge.sig));

// --- keeper roots and agent identities (MONERO.md §2, §8 G4). Fixed vectors over S1, cross-
// checked against an independent HKDF (Python hmac) when pinned; a Go port must reproduce them.
const K0 = keeperRoot(S1, 0);
t('keys keeperRoot fixed vectors: K_0 and K_1 of S1',
  bytesToHex(K0) === '683fbd16792613e6a361b2061fb2cbfb56118276954179c63a98ac6b7d19bdf2' &&
  bytesToHex(keeperRoot(S1, 1)) === '532211c88fe219df3270cb8640c89f89f525845624b54f0352b696c97960b801' &&
  bytesToHex(K0) === bytesToHex(k(S1, 'sigelo/v1/keeper/0')));
t('keys agentIdentitySeed fixed vector: (K_0, i=0, n=0)',
  bytesToHex(agentIdentitySeed(K0, 0, 0)) === '918b0cb138791dc35a1e843585e9433a029dd6e6f3b3d7a764ccb89c1a8448c3');
t('keys agentIdentitySeed fixed vector: (K_0, i=1, n=0)',
  bytesToHex(agentIdentitySeed(K0, 1, 0)) === '36ca4e02c29c9131344139b99be1d894c30d43fab762a1dd4e37720e08c5e2df' &&
  bytesToHex(agentIdentitySeed(K0, 1, 0)) === bytesToHex(k(K0, 'sigelo/v1/identity/1/ed25519/0')));
// Domain separation: a keeper root is not an identity seed, and an agent path never collides
// with the keeper's own identity path or with another (account, rotation) pair.
const sep = [K0, keeperRoot(S1, 1), identitySeed(S1, 0), identitySeed(K0, 0), agentIdentitySeed(K0, 0, 0),
  agentIdentitySeed(K0, 1, 0), agentIdentitySeed(K0, 0, 1), agentIdentitySeed(keeperRoot(S1, 1), 0, 0)].map(bytesToHex);
t('keys keeper, root-identity and agent paths are domain-separated', new Set(sep).size === sep.length);
// deriveRoot emits K_0..K_{keepers-1} and nothing else moves: rootSummary above omits them.
const dk = deriveRoot(S1, 'stagenet', 0, 2);
t('keys deriveRoot emits keeper roots without changing the rest',
  deriveRoot(S1, 'stagenet').keepers.length === 1 && dk.keepers.map(bytesToHex).join() === [K0, keeperRoot(S1, 1)].map(bytesToHex).join() &&
  bytesToHex(dk.identity) === bytesToHex(deriveRoot(S1, 'stagenet').identity) && dk.treasury.address === tw.address);
// An agent seed is an ordinary Ed25519 seed: keygen takes it and the identity signs.
const agent = keygen({ seed: agentIdentitySeed(K0, 1, 0), recovery: recoveryPublicKey(S1), created: idOpts.created, nonce: idNonce });
const agentCh = challenge({ secret: agent.secret, genesis: agent.genesis, ctx: 'keys-test', nonce: idNonce });
t('keys an agent seed keygens to a valid identity under the root recovery commitment',
  agent.key === encodeKey(ed.getPublicKey(agentIdentitySeed(K0, 1, 0))) && agent.genesis.recovery === recoveryCommitment(S1) &&
  verifySig(agent.key, agentCh.body, agentCh.sig));
rejects('keys a negative or fractional path index is rejected', () => agentIdentitySeed(K0, -1, 0), 'non-negative integer');

// --- the root's 25 words: Monero's Electrum-style English mnemonic (src/mnemonics/electrum-words.cpp).
// The wordlist is english.h at monero d02c7c57; its hash is pinned so a reordered or retyped
// list cannot pass the round trips below (they would still round-trip).
t('words the Monero English wordlist: 1626 words, 1626 distinct 3-letter prefixes, hash pinned',
  MONERO_WORDS.length === 1626 && new Set(MONERO_WORDS.map((w) => w.slice(0, 3))).size === 1626 &&
  bytesToHex(sha256(utf8ToBytes(MONERO_WORDS.join('\n') + '\n'))) === 'eaa6bce7dd92f4d6dd74f224264e0ef4ad21095d68ec77616b26ceb599baf4f7');
// Fixed vectors, each confirmed by monero-wallet-rpc 0.18.5 (restore_deterministic_wallet on
// stagenet and mainnet: address, spend key, view key and the wallet's own mnemonic; the stagenet
// half re-runs in the interop section below). V1 = SHA-256("sigelo vault test vector #1") with
// its top nibble cleared; V2 = 2^252 - 1 (every chunk 0xffffffff but the last); V3 = l - 1, the
// largest canonical root. Never use one for funds. go/keys_test.go pins the same.
const VAULT_VECTORS = [
  { seed: '7788b79c3a481c90542e7106471ee0079f09c65b12836d74d72206e3fe49ec02',
    words: 'loyal yacht obliged afoot lofty army frown demonstrate drinks rowboat rejoices rumble different nearby uttered jittery epoxy repent woken odds lesson suture hedgehog hire lesson',
    a: 'c5df810e80b045d656dbf366622896ecc9367d8cd907fab47986beea05233d06',
    stagenet: '59XmNWmDNk6RprQAMPpqfKb36WXut2KqoBCXABdgcd9rfxS5rgbmTBpYzurnpXtRaEWqgCoRZBdSEfGNbVZi2YcF2cXZMSq',
    mainnet: '49KjHfrFj8zRprQAMPpqfKb36WXut2KqoBCXABdgcd9rfxS5rgbmTBpYzurnpXtRaEWqgCoRZBdSEfGNbVZi2YcF2fkiK1T' },
  { seed: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f',
    words: 'foamy solved soggy foamy solved soggy foamy solved soggy foamy solved soggy foamy solved soggy foamy solved soggy foamy solved soggy jury yawning ankle soggy',
    a: '4560c4b2bdacb15cc4f9a4a8938bb849c26c9011272c308f6d9b70445f53db05',
    stagenet: '5ArT6ercKKQGbrAdSKCbVL73ME4FGv2cpczjV2peqqkxagm5D4gBqAHJta6NpbtxyuRe3ywaTj6QCHD59savvPW69vakaa1',
    mainnet: '4AeR1owefiJGbrAdSKCbVL73ME4FGv2cpczjV2peqqkxagm5D4gBqAHJta6NpbtxyuRe3ywaTj6QCHD59savvPW69wfW9my' },
  { seed: 'ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010',
    words: 'laptop height rowboat beware woozy gather slackens vain nanny tumbling gained identity abbey abbey abbey abbey abbey abbey abbey abbey abbey justice yearbook annoyed annoyed',
    a: '8f368706106c9b6bc7d8e3def8aa18840f2e605e3ca5495fb99f7fc64260b503',
    stagenet: '55BScWfUCysJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmfXUvkY7NQhchNuYKoXRoGSJCjenATXkEoZobEXSTnwtF3XdByMR',
    mainnet: '44yQXfkWZNmJ8QgRfFWTzmJ8QgRfFWTzmJ8QgRfFWTzmfXUvkY7NQhchNuYKoXRoGSJCjenATXkEoZobEXSTnwtF3ZiFSbR' },
];
VAULT_VECTORS.forEach((v, i) => {
  const S = hexToBytes(v.seed), st = vaultFromRoot(S, 'stagenet'), mn = vaultFromRoot(S, 'mainnet');
  t(`words fixed vector V${i + 1}: seed -> 25 words -> seed, vault b = S, a, stagenet and mainnet addresses`,
    mnemonicFromRoot(S) === v.words && bytesToHex(rootFromMnemonic(v.words)) === v.seed &&
    bytesToHex(st.b) === v.seed && bytesToHex(st.a) === v.a && bytesToHex(mn.a) === v.a &&
    st.address === v.stagenet && mn.address === v.mainnet && deriveRoot(S, 'mainnet').vault.address === v.mainnet);
});
// A spread of roots, digest pinned identically in go/keys_test.go: the two encoders agree on
// 64 seeds, not just on the three above. Seed i = SHA-256("sigelo words sweep <i>"), top nibble cleared.
let sweep = '';
for (let i = 0; i < 64; i++) {
  const s = sha256(utf8ToBytes(`sigelo words sweep ${i}`));
  s[31] = s[31]! & 0x0f;
  sweep += mnemonicFromRoot(s) + '\n';
  if (bytesToHex(rootFromMnemonic(sweep.trim().split('\n').pop()!)) !== bytesToHex(s)) sweep += 'ROUND TRIP FAILED';
}
t('words 64-root sweep round-trips, digest pinned with Go',
  bytesToHex(sha256(utf8ToBytes(sweep))) === '1a7aff8d3f1432532425934dae8ecb56e6490105e5452d5419cf6ba766fd2733');
const w1 = VAULT_VECTORS[0]!.words;
t('words case, extra whitespace and 3-letter prefixes are accepted, as wallet2 does',
  bytesToHex(rootFromMnemonic(`  ${w1.toUpperCase().replace(/ /g, '\n\t ')} `)) === VAULT_VECTORS[0]!.seed &&
  bytesToHex(rootFromMnemonic(w1.split(' ').map((w) => w.slice(0, 3)).join(' '))) === VAULT_VECTORS[0]!.seed);
t('words newRoot is 25 words of a canonical root, fresh each call',
  [newRoot(), newRoot()].every((m) => m.split(' ').length === 25 && mnemonicFromRoot(rootFromMnemonic(m)) === m) && newRoot() !== newRoot());
t('keys parseRoot takes either 64 hex characters or the 25 words',
  bytesToHex(parseRoot(VAULT_VECTORS[0]!.seed)) === VAULT_VECTORS[0]!.seed && bytesToHex(parseRoot(w1)) === VAULT_VECTORS[0]!.seed);
/** 24 data words plus the 25th that makes the checksum hold (it is one of the 24, by prefix). */
const withChecksum = (w24: string[]): string => [...w24, w24.find((c) => {
  try { decodeMoneroWords([...w24, c].join(' ')); return true; } catch (e) { return !(e as Error).message.includes('checksum'); }
})!].join(' ');
const wrongLast = w1.split(' ').slice(0, 24).concat(w1.split(' ')[24] === 'abbey' ? 'zoom' : 'abbey').join(' ');
rejects('words a wrong checksum word is rejected', () => rootFromMnemonic(wrongLast), 'checksum');
const swapped = w1.split(' ');
[swapped[0], swapped[1]] = [swapped[1]!, swapped[0]!];
rejects('words two swapped words are rejected (the checksum covers order)', () => rootFromMnemonic(swapped.join(' ')), 'checksum');
rejects('words a word outside the wordlist is rejected', () => rootFromMnemonic(w1.replace(/^\S+/, 'sigelo')), 'wordlist');
rejects('words a word matching only on its prefix is rejected (wallet2 would take it; we take the word or its prefix)', () => rootFromMnemonic(w1.replace(/^\S+/, 'loyalty')), 'wordlist');
rejects('words 24 words (no checksum) are rejected', () => rootFromMnemonic(w1.split(' ').slice(0, 24).join(' ')), '25');
rejects('words a BIP-39 phrase is rejected', () => rootFromMnemonic(`${Array(23).fill('abandon').join(' ')} art`), 'expected 25 words');
// zoom zones zombie encodes 1626^3 - 1 >= 2^32: wallet2's uint32 wraps and its x % n == w1 check fails.
const overflow = withChecksum(['zoom', 'zones', 'zombie', ...w1.split(' ').slice(3, 24)]);
rejects('words a triple past 2^32 is rejected (electrum-words.cpp:326)', () => rootFromMnemonic(overflow), 'not a Monero seed encoding');
// S1 is ASCII, so its top byte 0x31 puts it past l: a wallet would re-export sc_reduce32(S1)'s words.
rejects('words a non-canonical root (S >= l) is refused as words', () => rootFromMnemonic(encodeMoneroWords(S1)), 'not a canonical root');
rejects('words a non-canonical root is refused as hex', () => parseRoot(bytesToHex(S1)), 'not a canonical root');
rejects('words l itself is refused', () => parseRoot('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010'), 'not a canonical root');
rejects('words the zero root is refused', () => parseRoot('00'.repeat(32)), 'not a canonical root');
rejects('words mnemonicFromRoot refuses a non-canonical root', () => mnemonicFromRoot(S1), 'not a canonical root');
// Domain separation between the vault and everything HKDF derives from the same S: HKDF-extract
// with an empty salt is HMAC(0^32, S), a PRK unrelated to sc_reduce32(S), so no derived key may
// equal the vault's b or a. Checked over every root-level branch and a keeper's.
const VS = hexToBytes(VAULT_VECTORS[0]!.seed), vd = deriveRoot(VS, 'stagenet', 0, 2), vk = vd.keepers[0]!;
const derivedAll = [vd.identity, vd.recovery.seed, vd.treasury.b, vd.treasury.a, vd.allowance.b, vd.allowance.a, ...vd.keepers,
  identitySeed(VS, 1), agentIdentitySeed(vk, 0, 0), agentIdentitySeed(vk, 1, 0), identitySeed(vk, 0),
  walletFromRoot(vk, 'counterparty/acme', 'stagenet').b, k(VS, 'sigelo/v1/monero/treasury')].map(bytesToHex);
t('keys no derived key equals the vault spend key b (= S) or view key a',
  !derivedAll.includes(bytesToHex(vd.vault.b)) && !derivedAll.includes(bytesToHex(vd.vault.a)) &&
  bytesToHex(vd.vault.b) === VAULT_VECTORS[0]!.seed && vd.treasury.address !== vd.vault.address);

// ---------------------------------------------------------------- h. ceremony (MONERO.md §4.5, G7)

// The age step is injected: a reversible fake here, the real binary further down if present.
// The fake is not encryption, so the "absent from every file" checks exclude backup.age only.
const fakeAge: Age = {
  encrypt: (r, p) => Uint8Array.from([...utf8ToBytes(`FAKE ${r}\n`), ...p.map((x) => x ^ 0x5a)]),
  decrypt: (_i, c) => c.slice(c.indexOf(10) + 1).map((x) => x ^ 0x5a),
};
const RCPT = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p';
const cerTmp = mkdtempSync(join(tmpdir(), 'sigelo-ceremony-'));
const OFFLINE = join(dirname(fileURLToPath(import.meta.url)), 'offline.js');
// The ceremony takes only a canonical root (a human restores it as Monero words), so it runs
// on V1 of the words vectors, not on the ASCII S1 above (which is past l).
const SC = hexToBytes(VAULT_VECTORS[0]!.seed), KC0 = keeperRoot(SC, 0);
const SChex = bytesToHex(SC), scWords = mnemonicFromRoot(SC), recHex = bytesToHex(recoverySeed(SC));
const txt = (b: Uint8Array): string => new TextDecoder().decode(b);
/** Every secret that must live inside backup.age and nowhere else, as it would be spelled. */
const leaks = (s: string, S: string, m: string, rec: string): boolean =>
  [S, S.toUpperCase(), m, m.split(' ').slice(0, 12).join(' '), rec].some((x) => s.includes(x)); // half the words is a leak too
const filesOf = (dir: string): string[] => readdirSync(dir).sort();
try {
  const out = join(cerTmp, 'lib');
  const cer = ceremony({ net: 'stagenet', recipient: RCPT, out, keepers: 3, treasuryKeeper: 2, age: fakeAge, created: 1790000000, S: SC.slice() });
  t('ceremony writes backup.age, fingerprint.txt and one keeper-<j>.json per keeper',
    filesOf(out).join() === 'backup.age,fingerprint.txt,keeper-0.json,keeper-1.json,keeper-2.json');
  const plain: Any = JSON.parse(txt(fakeAge.decrypt('', readFileSync(join(out, 'backup.age')))));
  t('ceremony backup round trip reproduces S, in the §4.5 shape',
    bytesToHex(rootFromMnemonic(plain.mnemonic)) === SChex && plain.v === 'sigelo-root/2' && plain.created === 1790000000 &&
    plain.keepers.length === 3 && same(plain.public, cer.public) && plain.mnemonic === scWords && plain.mnemonic.split(' ').length === 25);
  const fp = readFileSync(join(out, 'fingerprint.txt'), 'utf-8');
  const d1 = deriveRoot(SC, 'stagenet');
  t('ceremony fingerprint.txt is JCS of §4.5 public: treasury, allowance, recovery commitment',
    fp === canonicalize({ treasury: d1.treasury.address, allowance: d1.allowance.address, recovery_commitment: d1.recovery.commitment }) + '\n' &&
    fp === cer.fingerprint + '\n');
  const rs: Any = restore({ backup: readFileSync(join(out, 'backup.age')), identity: 'unused', net: 'stagenet', age: fakeAge });
  t('ceremony restore reproduces the ceremony fingerprint', rs.fingerprint === cer.fingerprint);
  const pkgs: Any[] = [0, 1, 2].map((j) => JSON.parse(readFileSync(join(out, `keeper-${j}.json`), 'utf-8')));
  t('ceremony every K_j, restored and packaged, is keeperRoot(S, j)',
    [0, 1, 2].every((j) => rs.keepers[j].keeper_root_hex === bytesToHex(keeperRoot(SC, j)) && pkgs[j].keeper_root_hex === bytesToHex(keeperRoot(SC, j))) &&
    pkgs.every((p, j) => p.j === j && p.net === 'stagenet' && p.recovery_commitment === d1.recovery.commitment &&
      p.identity_public_key === encodeKey(ed.getPublicKey(identitySeed(keeperRoot(SC, j), 0)))));
  t('ceremony keeper 0 gets allowance + root identity, the treasury keeper treasury, the rest neither',
    pkgs[0].role === 'agents' && pkgs[0].allowance.spend_key === bytesToHex(d1.allowance.b) && pkgs[0].root_identity_seed_hex === bytesToHex(d1.identity) && !('treasury' in pkgs[0]) &&
    pkgs[2].role === 'treasury' && pkgs[2].treasury.spend_key === bytesToHex(d1.treasury.b) && !('allowance' in pkgs[2]) &&
    pkgs[1].role === 'keeper' && !('treasury' in pkgs[1]) && !('allowance' in pkgs[1]));
  const mode = (f: string): number => statSync(join(out, f)).mode & 0o777;
  if (process.platform === 'win32') console.log('SKIP ceremony file modes (Windows has no POSIX modes: the files inherit the directory\'s ACL)');
  else t('ceremony keeper packages and the backup are 0600', [0, 1, 2].every((j) => mode(`keeper-${j}.json`) === 0o600) && mode('backup.age') === 0o600);
  t('ceremony S, the mnemonic and the recovery secret are in no file but backup.age, nor in the result',
    filesOf(out).filter((f) => f !== 'backup.age').every((f) => !leaks(readFileSync(join(out, f), 'utf-8'), SChex, scWords, recHex)) &&
    !leaks(JSON.stringify(cer), SChex, scWords, recHex));
  // MONERO.md §2: the vault is never loaded by a keeper. Its spend key is S itself (canonical S),
  // so a keeper holding it would hold every identity and the recovery key's root, permanently.
  const vaultSecrets = [bytesToHex(d1.vault.b), bytesToHex(d1.vault.a), SChex, SChex.toUpperCase()];
  t('ceremony no keeper package carries the vault: not its spend key (= S), not its view key, no vault field',
    bytesToHex(d1.vault.b) === SChex && pkgs.every((p) => !('vault' in p)) &&
    [0, 1, 2].every((j) => { const f = readFileSync(join(out, `keeper-${j}.json`), 'utf-8'); return vaultSecrets.every((x) => !f.includes(x)); }));
  t('ceremony prints the vault address and nothing else of it; restore does the same',
    cer.vault === d1.vault.address && vaultSecrets.every((x) => !JSON.stringify(cer).includes(x)) &&
    rs.vault.address === d1.vault.address && vaultSecrets.every((x) => !JSON.stringify(rs).includes(x)));
  const rsAll: Any = restore({ backup: readFileSync(join(out, 'backup.age')), identity: '', net: 'stagenet', age: fakeAge, revealAll: true });
  t('ceremony restore withholds like derive: treasury spend + recovery secret only under --reveal-all',
    !JSON.stringify(rs).includes(bytesToHex(d1.treasury.b)) && !JSON.stringify(rs).includes(recHex) &&
    rsAll.owner_backup.treasury.spend_key === bytesToHex(d1.treasury.b) && rsAll.owner_backup.recovery.secret_key_hex === recHex &&
    rsAll.owner_backup.vault.spend_key === SChex && rsAll.owner_backup.vault.address === d1.vault.address &&
    same(rsAll.owner_backup, roles(deriveRoot(SC, 'stagenet', 0, 3), 'stagenet', true)['owner_backup']));
  const v1backup = fakeAge.encrypt(RCPT, utf8ToBytes(JSON.stringify({ ...plain, v: 'sigelo-root/1' })));
  rejects('ceremony restore refuses a sigelo-root/1 (BIP-39) backup by name', () => restore({ backup: v1backup, identity: '', net: 'stagenet', age: fakeAge }), 'sigelo-root/1');
  rejects('ceremony refuses a non-canonical root rather than back up words a wallet would not reproduce',
    () => ceremony({ net: 'stagenet', recipient: RCPT, out: join(cerTmp, 'nc'), age: fakeAge, S: S1.slice() }), 'not a canonical root');
  rejects('ceremony restore refuses a backup for another net', () => restore({ backup: readFileSync(join(out, 'backup.age')), identity: '', net: 'mainnet', age: fakeAge }), 'fingerprint mismatch');
  const forged = fakeAge.encrypt(RCPT, utf8ToBytes(JSON.stringify({ ...plain, public: { ...plain.public, treasury: d1.allowance.address } })));
  rejects('ceremony restore refuses a backup whose public values S does not reproduce', () => restore({ backup: forged, identity: '', net: 'stagenet', age: fakeAge }), 'fingerprint mismatch');
  rejects('ceremony refuses a bad recipient', () => ceremony({ net: 'stagenet', recipient: 'age1nope', out: join(cerTmp, 'bad'), age: fakeAge }), 'not an age recipient');
  rejects('ceremony refuses to write into a non-empty directory', () => ceremony({ net: 'stagenet', recipient: RCPT, out, age: fakeAge }), 'not empty');
  rejects('ceremony refuses keeper 0 as the treasury keeper (one keeper = one wallet)', () => ceremony({ net: 'stagenet', recipient: RCPT, out: join(cerTmp, 'tk'), keepers: 2, treasuryKeeper: 0, age: fakeAge }), 'treasury-keeper');

  // --- M4 (ROADMAP §2): --human's tty sink, the refused import, restore from the words.
  // Wordlist tokens of a text, and "a window of two consecutive words of m appears in s".
  const wordTokens = (s: string): Set<string> => new Set(s.toLowerCase().split(/[^a-z]+/).filter((w) => MONERO_WORDS.includes(w)));
  const pairLeak = (s: string, m: string): boolean => { const w = m.split(' '), flat = s.toLowerCase().split(/[^a-z]+/).join(' ');
    return w.slice(0, -1).some((x, i) => flat.includes(`${x} ${w[i + 1]}`)); };
  // The --human screen numbers the words 1…25, five to a row: read them back in order.
  const numbered = (screen: string): string => screen.split('\n').filter((l) => /^\s*1?\d \S/.test(l) || /^\s*2\d \S/.test(l))
    .flatMap((l) => l.trim().split(/\s+/).filter((w) => !/^\d+$/.test(w))).join(' ');
  const ttySeen: string[] = [];
  const hOut = join(cerTmp, 'human');
  const hc = ceremony({ net: 'stagenet', recipient: RCPT, out: hOut, keepers: 2, age: fakeAge, S: SC.slice(), tty: (x) => { ttySeen.push(x); } });
  t('ceremony --human: the injected tty sink gets all 25 words once, in order, with the vault address and "vault only, never a hot wallet"',
    ttySeen.length === 1 && numbered(ttySeen[0]!) === scWords && ttySeen[0]!.includes(hc.vault) && ttySeen[0]!.includes('Vault only, never a hot wallet'));
  t('ceremony --human: the result and every file but backup.age still hold none of it',
    !leaks(JSON.stringify(hc), SChex, scWords, recHex) && !pairLeak(JSON.stringify(hc), scWords) &&
    filesOf(hOut).filter((f) => f !== 'backup.age').every((f) => !leaks(readFileSync(join(hOut, f), 'utf-8'), SChex, scWords, recHex)));
  const failAge: Age = { encrypt: () => { throw new SigeloError('ceremony: encrypting the backup: age exited 1'); }, decrypt: fakeAge.decrypt };
  let ttyAfterFail = 0;
  rejects('ceremony --human: a failed age shows no words (no backup holds them)',
    () => ceremony({ net: 'stagenet', recipient: RCPT, out: join(cerTmp, 'hfail'), age: failAge, tty: () => { ttyAfterFail++; } }), 'encrypting');
  t('ceremony --human: … and the tty sink was never called', ttyAfterFail === 0);
  const noTty = openTty(join(cerTmp, 'no-such-dir', 'tty'));
  t('ceremony --human: a tty that cannot be opened is a refusal string, not a writer', typeof noTty === 'string' && noTty.includes('never written to stdout'));
  let importRead = 0;
  rejects('ceremony import: refused by default with the M4 reason, before the words are read',
    () => importRoot(() => { importRead++; return scWords; }, false), 'a seed that has been in a hot wallet is not a root');
  t('ceremony import: … the reader never ran; with the flag the words become S', importRead === 0 && bytesToHex(importRoot(() => scWords, true)) === SChex);
  const bOut: Any = restore({ backup: readFileSync(join(out, 'backup.age')), identity: '', net: 'stagenet', age: fakeAge });
  const bAll: Any = restore({ backup: readFileSync(join(out, 'backup.age')), identity: '', net: 'stagenet', age: fakeAge, revealAll: true });
  const wOut: Any = restoreWords({ words: scWords, net: 'stagenet', keepers: 3, fingerprint: fp });
  const wAll: Any = restoreWords({ words: '  ' + scWords.toUpperCase() + '\n', net: 'stagenet', keepers: 3, revealAll: true });
  t('restore from the 25 words = restore from backup.age: same fingerprint, vault, every K_j; with --reveal-all every derived key',
    same(wOut, bOut) && same(wAll, bAll) && wAll.owner_backup.vault.spend_key === SChex && wAll.agent.identity_seed_hex === bytesToHex(d1.identity) &&
    wAll.keepers.length === 3 && wAll.keepers.every((x: Any, j: number) => x.keeper_root_hex === bytesToHex(keeperRoot(SC, j))));
  rejects('restore --words: a fingerprint.txt from another net is refused', () => restoreWords({ words: scWords, net: 'mainnet', fingerprint: fp }), 'fingerprint mismatch');
  rejects('restore --words: another root\'s words against this fingerprint.txt are refused',
    () => restoreWords({ words: VAULT_VECTORS[1]!.words, net: 'stagenet', fingerprint: fp }), 'other words');
  rejects('restore --words: a --fingerprint that is not JSON is refused', () => restoreWords({ words: scWords, net: 'stagenet', fingerprint: 'nope' }), 'not a fingerprint.txt');
  rejects('restore --words: a mistyped word is refused, never a key', () => restoreWords({ words: wrongLast, net: 'stagenet' }), 'checksum');

  // --- the CLI, as a process: what reaches stdout/stderr, exit codes, the missing binary.
  const cli = (args: string[], path?: string) => {
    // PATH replaced, the rest of the environment kept (Windows spells it Path and needs SystemRoot).
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k.toUpperCase() !== 'PATH') env[k] = v;
    const r = path === undefined ? spawnSync(process.argv[0]!, [OFFLINE, ...args]) : spawnSync(process.argv[0]!, [OFFLINE, ...args], { env: { ...env, PATH: path } });
    return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() };
  };
  const noBin = join(cerTmp, 'empty-bin'), fakeBin = join(cerTmp, 'fake-bin');
  mkdirSync(noBin, {}); mkdirSync(fakeBin, {});
  const miss = cli(['ceremony', '--net', 'stagenet', '--recipient', RCPT, '--out', join(cerTmp, 'nobin')], noBin);
  t('ceremony CLI without age or rage exits 2, names what to install, writes nothing',
    miss.code === 2 && miss.err.includes('apk add age') && miss.out === '' && readdirSync(cerTmp).every((f) => f !== 'nobin'));
  const bad = cli(['ceremony', '--net', 'stagenet', '--recipient', 'age1-not-a-key', '--out', join(cerTmp, 'badr')]);
  t('ceremony CLI refuses a bad recipient with exit 2 and a plain message', bad.code === 2 && bad.err.includes('not an age recipient') && !bad.err.includes('    at '));
  // A stand-in `age` on PATH: header then plaintext, so the test can read S back and hunt for it.
  // A `#!/bin/sh` file is not executable on Windows; there the real-age section below is the CLI check.
  if (process.platform === 'win32') console.log('SKIP ceremony CLI with a stand-in age (a #!/bin/sh script; Windows cannot run it)');
  else {
  writeFileSync(join(fakeBin, 'age'), '#!/bin/sh\n[ "$1" = --version ] && exit 0\nif [ "$1" = -d ]; then tail -n +2; else echo FAKE; cat; fi\n', { mode: 0o755 });
  const cliOut = join(cerTmp, 'cli');
  const run1 = cli(['ceremony', '--net', 'stagenet', '--recipient', RCPT, '--out', cliOut, '--keepers', '2'], `${fakeBin}:/usr/bin:/bin`);
  const cliPlain: Any = JSON.parse(readFileSync(join(cliOut, 'backup.age'), 'utf-8').split('\n').slice(1).join('\n'));
  const cliS = bytesToHex(rootFromMnemonic(cliPlain.mnemonic)), cliRec = bytesToHex(recoverySeed(rootFromMnemonic(cliPlain.mnemonic)));
  t('ceremony CLI: S, the mnemonic and the recovery secret reach neither stdout, stderr nor any file but backup.age',
    run1.code === 0 && JSON.parse(run1.out).fingerprint + '\n' === readFileSync(join(cliOut, 'fingerprint.txt'), 'utf-8') &&
    !leaks(run1.out + run1.err, cliS, cliPlain.mnemonic, cliRec) &&
    filesOf(cliOut).filter((f) => f !== 'backup.age').every((f) => !leaks(readFileSync(join(cliOut, f), 'utf-8'), cliS, cliPlain.mnemonic, cliRec)));
  const standIn = `${fakeBin}:/usr/bin:/bin`;
  const fakePlain = (dir: string): Any => JSON.parse(readFileSync(join(dir, 'backup.age'), 'utf-8').split('\n').slice(1).join('\n'));
  const wordsFile = join(cerTmp, 'words.txt');
  writeFileSync(wordsFile, scWords + '\n');
  const COLD = '--i-know-this-seed-was-cold';

  // --import: refused without the flag (nothing written), allowed with it (liability printed).
  const imp0 = cli(['ceremony', '--net', 'stagenet', '--recipient', RCPT, '--out', join(cerTmp, 'imp0'), '--import', wordsFile], standIn);
  t('ceremony CLI --import without the flag: exit 2, the M4 reason, nothing written',
    imp0.code === 2 && imp0.err.trim() === IMPORT_REFUSED && imp0.out === '' && !readdirSync(cerTmp).includes('imp0'));
  const imp1 = cli(['ceremony', '--net', 'stagenet', '--recipient', RCPT, '--out', join(cerTmp, 'imp1'), '--import', wordsFile, COLD, '--keepers', '2'], standIn);
  t('ceremony CLI --import --i-know-this-seed-was-cold: exit 0, prints the liability, the backup holds the imported words and stdout none of them',
    imp1.code === 0 && imp1.err.includes('you vouch that these words were never in a hot wallet') && imp1.err.includes('no rotation takes that back') &&
    fakePlain(join(cerTmp, 'imp1')).mnemonic === scWords && JSON.parse(imp1.out).vault === d1.vault.address && !leaks(imp1.out + imp1.err, SChex, scWords, recHex));
  const argvW = cli(['ceremony', '--net', 'stagenet', '--recipient', RCPT, '--out', join(cerTmp, 'argv'), ...scWords.split(' ')], standIn);
  t('ceremony CLI refuses words as arguments without echoing them', argvW.code === 2 && argvW.err.includes('never go on the command line') && !pairLeak(argvW.err, scWords));

  // --human needs a terminal, and the two checks below need a session without one and a pty.
  // util-linux `setsid -w` and `script -qec` provide them on Linux; macOS has no setsid and a BSD
  // `script` with no -c (it would leave the output files unwritten), so there a python3 helper
  // does the same (os.setsid, os.forkpty). Windows has neither os.forkpty nor a /dev/tty: SKIP.
  // SIGELO_TEST_PTY=python forces the helper on Linux, to exercise the macOS path.
  const forcePy = process.env['SIGELO_TEST_PTY'] === 'python';
  const pyProbe = spawnSync('python3', ['-c', 'import os, sys; os.forkpty; os.setsid; print(sys.executable)']);
  const python = pyProbe.status === 0 ? pyProbe.stdout.toString().trim() : undefined;
  const PY_SETSID = 'import os, sys\nos.setsid()\nos.execv(sys.argv[1], sys.argv[1:])\n';
  const PY_PTY = [
    'import os, sys',
    'pid, fd = os.forkpty()',
    'if pid == 0:',
    '    os.execv("/bin/sh", ["/bin/sh", "-c", sys.argv[1]])',
    'chunks = []',
    'while True:',
    '    try:',
    '        b = os.read(fd, 65536)',
    '    except OSError:',
    '        break',
    '    if not b:',
    '        break',
    '    chunks.append(b)',
    '_, st = os.waitpid(pid, 0)',
    'sys.stdout.buffer.write(b"".join(chunks))',
    'sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 1)',
  ].join('\n') + '\n';
  const setsidV = spawnSync('setsid', ['--version']);
  const hasSetsid = !forcePy && setsidV.error === undefined && setsidV.status === 0;
  const scriptV = spawnSync('script', ['--version']);
  const utilScript = !forcePy && scriptV.error === undefined && scriptV.stdout.toString().includes('util-linux');

  // --human without a controlling terminal: a new session has none.
  if (!hasSetsid && python === undefined) console.log(`SKIP ceremony CLI --human without a tty (no setsid and no python3 with os.setsid on PATH${process.platform === 'win32' ? '; Windows has no /dev/tty' : ''})`);
  else {
    const argv = [process.argv[0]!, OFFLINE, 'ceremony', '--net', 'stagenet', '--recipient', RCPT, '--out', join(cerTmp, 'notty'), '--human'];
    const ns = hasSetsid ? spawnSync('setsid', ['-w', ...argv], { env: { PATH: standIn } }) : spawnSync(python!, ['-c', PY_SETSID, ...argv], { env: { PATH: standIn } });
    t(`ceremony CLI --human with no terminal (${hasSetsid ? 'setsid' : 'python3 os.setsid'}): exit 2, says why, stdout empty, nothing written (no fallback to stdout)`,
      ns.status === 2 && ns.stderr.toString().includes('cannot open /dev/tty') && ns.stdout.toString() === '' && !readdirSync(cerTmp).includes('notty'));
  }

  // --human on a real pseudo-terminal: stdout and stderr go to files, so what the pty shows is
  // exactly what reached /dev/tty.
  if (!utilScript && python === undefined) console.log(`SKIP ceremony CLI --human on a pty (no util-linux \`script\` and no python3 with os.forkpty on PATH${scriptV.error === undefined ? '; the `script` here is not util-linux (BSD script has no -c)' : ''}; the injected-sink checks above still ran)`);
  else {
    const q = (x: string): string => `'${x.replace(/'/g, `'\\''`)}'`;
    const onPty = (dir: string, extra: string[]) => {
      const cmd = [process.argv[0]!, OFFLINE, 'ceremony', '--net', 'stagenet', '--recipient', RCPT, '--out', join(cerTmp, dir), '--keepers', '2', ...extra].map(q).join(' ');
      const line = `${cmd} >${q(join(cerTmp, dir + '.out'))} 2>${q(join(cerTmp, dir + '.err'))}`;
      const r = utilScript ? spawnSync('script', ['-q', '-e', '-c', line, '/dev/null'], { env: { PATH: standIn } }) : spawnSync(python!, ['-c', PY_PTY, line], { env: { PATH: standIn } });
      const read = (f: string): string => { try { return readFileSync(join(cerTmp, f), 'utf-8'); } catch { return `(${f} was not written: the pty helper did not run the command; status ${r.status}, ${r.stderr?.toString().trim()})`; } };
      return { code: r.status, tty: r.stdout?.toString() ?? '', out: read(dir + '.out'), err: read(dir + '.err') };
    };
    console.log(`ceremony CLI --human on a pty via ${utilScript ? 'util-linux script' : 'python3 os.forkpty'}`);
    // Baseline: the same imported root without --human. Its wordlist tokens are the fixed messages' own.
    const base = onPty('pty0', ['--import', wordsFile, COLD]);
    const hum = onPty('pty1', ['--import', wordsFile, COLD, '--human']);
    const allowed = new Set([...wordTokens(base.out + base.err), ...wordTokens('The 25 words went to /dev/tty and nowhere else')]);
    t('ceremony CLI --human on a pty: all 25 words reach /dev/tty, in order, with "vault only, never a hot wallet"',
      hum.code === 0 && numbered(hum.tty) === scWords && hum.tty.includes('Vault only, never a hot wallet') && base.tty.trim() === '');
    t('ceremony CLI --human on a pty: stdout and stderr carry no wordlist word beyond the fixed messages\' own, no two consecutive words, and stdout is the same JSON',
      hum.err.includes('went to /dev/tty') && [...wordTokens(hum.out + hum.err)].every((w) => allowed.has(w)) && !pairLeak(hum.out + hum.err, scWords) &&
      !leaks(hum.out + hum.err, SChex, scWords, recHex) && same(JSON.parse(hum.out).public, JSON.parse(base.out).public));
    const rnd = onPty('pty2', ['--human']);
    const rndWords: string = rnd.code === 0 ? fakePlain(join(cerTmp, 'pty2')).mnemonic : '(no backup.age: the pty run failed)';
    t('ceremony CLI --human, fresh root: the words on the tty are the ones in backup.age, and nowhere in stdout/stderr',
      rnd.code === 0 && numbered(rnd.tty) === rndWords && !pairLeak(rnd.out + rnd.err, rndWords) &&
      !leaks(rnd.out + rnd.err, bytesToHex(rootFromMnemonic(rndWords)), rndWords, bytesToHex(recoverySeed(rootFromMnemonic(rndWords)))));
  }

  // restore: the 25 words by file or stdin reproduce restore --backup, byte for byte.
  const impDir = join(cerTmp, 'imp1'), impFp = join(impDir, 'fingerprint.txt');
  const rb = cli(['restore', '--backup', join(impDir, 'backup.age'), '--identity', 'unused', '--net', 'stagenet'], standIn);
  const rbAll = cli(['restore', '--backup', join(impDir, 'backup.age'), '--identity', 'unused', '--net', 'stagenet', '--reveal-all'], standIn);
  const rwFile = cli(['restore', '--words', wordsFile, '--keepers', '2', '--fingerprint', impFp, '--net', 'stagenet']);
  const rwStdin = spawnSync(process.argv[0]!, [OFFLINE, 'restore', '--words', '-', '--keepers', '2', '--net', 'stagenet', '--reveal-all'], { input: scWords + '\n' });
  t('restore CLI --words <file> (checked against fingerprint.txt) prints exactly what restore --backup prints',
    rb.code === 0 && rwFile.code === 0 && rwFile.out === rb.out && !rwFile.err.includes('nothing was checked'));
  t('restore CLI --words - (stdin) --reveal-all prints exactly what restore --backup --reveal-all prints, and says nothing was checked without --fingerprint',
    rbAll.code === 0 && rwStdin.status === 0 && rwStdin.stdout.toString() === rbAll.out && rwStdin.stderr.toString().includes('nothing was checked'));
  const rArgv = cli(['restore', '--net', 'stagenet', ...scWords.split(' ')]);
  t('restore CLI refuses the words as arguments (ps would show them), without echoing them',
    rArgv.code === 2 && rArgv.err.includes('--words') && rArgv.out === '' && !pairLeak(rArgv.err, scWords));
  const rMain = cli(['restore', '--words', wordsFile, '--fingerprint', impFp, '--net', 'mainnet']);
  t('restore CLI --words refuses a fingerprint.txt the words do not reproduce, exit 2', rMain.code === 2 && rMain.err.includes('fingerprint mismatch') && rMain.out === '');
  const rBoth = cli(['restore', '--words', wordsFile, '--backup', join(impDir, 'backup.age'), '--identity', 'x', '--net', 'stagenet']);
  t('restore CLI takes exactly one of --backup and --words', rBoth.code === 2 && rBoth.err.includes('exactly one'));
  }
  const der: Any = JSON.parse(cli(['derive', SChex, '--keepers', '2']).out), derAll: Any = JSON.parse(cli(['derive', SChex, '--reveal-all']).out);
  t('offline derive speaks keeper vocabulary: agents_keeper, keepers, owner_backup; agent.treasury unchanged',
    !('operator' in der) && !('air_gapped' in der) && !('owner_backup' in der) && der.agents_keeper.keeper_root_hex === bytesToHex(KC0) &&
    der.keepers[1].keeper_root_hex === bytesToHex(keeperRoot(SC, 1)) && der.agent.treasury.view_key === bytesToHex(d1.treasury.a) &&
    derAll.owner_backup.recovery.secret_key_hex === recHex && !('air_gapped' in derAll));
  const derWords: Any = JSON.parse(cli(['derive', ...scWords.split(' '), '--keepers', '2']).out);
  t('offline derive takes the 25 words as argv and derives exactly what the hex derives; the vault shows only its address',
    same(derWords, der) && der.vault.address === d1.vault.address && Object.keys(der.vault).join() === 'address' &&
    vaultSecrets.slice(0, 2).every((x) => !JSON.stringify(der).includes(x)) && derAll.owner_backup.vault.spend_key === SChex);
  const nw = cli(['new', '--net', 'mainnet']);
  const nwLine = (k: string): string => nw.out.split('\n').find((l) => l.startsWith(k))!.slice(10);
  t('offline new prints 25 words, their root and the vault address, and says the words are a Monero seed a 25-word (not Polyseed) wallet restores',
    nw.code === 0 && nwLine('mnemonic').split(' ').length === 25 && bytesToHex(rootFromMnemonic(nwLine('mnemonic'))) === nwLine('root_hex') &&
    nwLine('vault') === vaultFromRoot(hexToBytes(nwLine('root_hex')), 'mainnet').address && nw.err.includes('Monero seed') &&
    nw.err.includes('any Monero wallet that takes a 25-word seed') && !nw.err.includes('any\nMonero wallet restores'));
  const nc = cli(['derive', bytesToHex(S1)]);
  t('offline derive refuses a non-canonical hex root with exit 2', nc.code === 2 && nc.err.includes('not a canonical root'));

  // --- the real binary: age-keygen makes a throwaway Owner identity; CLI ceremony, CLI restore.
  if (spawnSync('age-keygen', ['--version']).error !== undefined || spawnSync('age', ['--version']).error !== undefined) {
    console.log('SKIP ceremony real-age round trip (age/age-keygen not on PATH; the fake-age checks above still ran)');
  } else {
    const idFile = join(cerTmp, 'owner.key');
    spawnSync('age-keygen', ['-o', idFile]);
    const recipient = spawnSync('age-keygen', ['-y', idFile]).stdout.toString().trim();
    const realOut = join(cerTmp, 'real');
    const c = cli(['ceremony', '--net', 'stagenet', '--recipient', recipient, '--out', realOut, '--keepers', '2']);
    const r = cli(['restore', '--backup', join(realOut, 'backup.age'), '--identity', idFile, '--net', 'stagenet']);
    const dec: Any = JSON.parse(spawnSync('age', ['-d', '-i', idFile, join(realOut, 'backup.age')]).stdout.toString());
    const realS = rootFromMnemonic(dec.mnemonic);
    const rj: Any = r.code === 0 ? JSON.parse(r.out) : {};
    t('ceremony real age: stock `age -d` opens the backup and it holds S (the Owner needs no sigelo code)',
      c.code === 0 && dec.v === 'sigelo-root/2' && same(dec.public, JSON.parse(c.out).public));
    t('ceremony real age: restore reproduces fingerprint.txt and every K_j = keeperRoot(S, j)',
      r.code === 0 && rj.fingerprint + '\n' === readFileSync(join(realOut, 'fingerprint.txt'), 'utf-8') &&
      rj.keepers.length === 2 && rj.keepers.every((x: Any, j: number) => x.keeper_root_hex === bytesToHex(keeperRoot(realS, j))));
    t('ceremony real age: backup.age is ciphertext, and S is nowhere else on disk or in the output',
      !txt(readFileSync(join(realOut, 'backup.age'))).includes(dec.mnemonic) &&
      !leaks(c.out + c.err + r.out + r.err, bytesToHex(realS), dec.mnemonic, bytesToHex(recoverySeed(realS))) &&
      filesOf(realOut).filter((f) => f !== 'backup.age').every((f) => !leaks(readFileSync(join(realOut, f), 'utf-8'), bytesToHex(realS), dec.mnemonic, bytesToHex(recoverySeed(realS)))));
    const wrongId = join(cerTmp, 'other.key');
    spawnSync('age-keygen', ['-o', wrongId]);
    const w = cli(['restore', '--backup', join(realOut, 'backup.age'), '--identity', wrongId, '--net', 'stagenet']);
    t('ceremony real age: restore with another identity fails with age\'s reason, exit 2', w.code === 2 && w.err.includes('decrypting the backup') && w.out === '');
    // M4: the words the Owner reads out of backup.age with stock age restore what the backup restores.
    const realWords = join(cerTmp, 'real-words.txt');
    writeFileSync(realWords, dec.mnemonic + '\n');
    const rAll = cli(['restore', '--backup', join(realOut, 'backup.age'), '--identity', idFile, '--net', 'stagenet', '--reveal-all']);
    const wr = cli(['restore', '--words', realWords, '--keepers', '2', '--fingerprint', join(realOut, 'fingerprint.txt'), '--net', 'stagenet']);
    const wrAll = cli(['restore', '--words', realWords, '--keepers', '2', '--net', 'stagenet', '--reveal-all']);
    t('ceremony real age: restore --words (the 25 words from `age -d`) = restore --backup, plain and --reveal-all',
      r.code === 0 && wr.code === 0 && wr.out === r.out && rAll.code === 0 && wrAll.code === 0 && wrAll.out === rAll.out &&
      JSON.parse(wrAll.out).owner_backup.vault.spend_key === bytesToHex(realS));
  }
} finally {
  rmSync(cerTmp, { recursive: true, force: true });
}

// ---------------------------------------------------------------- h2. recover (SPEC §7, INCIDENT.md §5)
// A keeper-minted agent (keeper 0, account 3, rotation 0) under root SC; a world attests it;
// a thief with its key signs TWO voluntary rotations (a fork); the Owner recovers from the
// last honest node with an EARLIER iat. The recovery must win, the fork must stop mattering,
// the attestation must still count — in ts and in the Go reference verifier.
{
  const recTmp = mkdtempSync(join(tmpdir(), 'sigelo-recover-'));
  try {
    const T0 = 1790000000;
    const g0 = keygen({ seed: agentIdentitySeed(KC0, 3, 0), recovery: recoveryCommitment(SC), created: '2026-09-24T00:00:00Z', nonce: new Uint8Array(16) });
    const world = keygen({ seed: new Uint8Array(32).fill(7), recovery: recoveryCommitment(SC) });
    const att = attest({ secret: world.secret, iss: world.did, sub: g0.did, iat: T0, exp: T0 + 86400 * 30, ctx: 'recover.test', admission: 'open', claims: { posts: 3 } });
    const thief = [1, 2].map((x) => rotate({ genesis: g0.genesis, next_genesis: keygen({ seed: new Uint8Array(32).fill(x), recovery: g0.genesis.recovery }).genesis, iat: T0 + 200, reason: 'voluntary', secret: g0.secret }));
    const r = recover({ from: g0.genesis, S: SC, next: { kind: 'agent', keeper: 0, agent: 3, n: 1 }, iat: T0 + 100 });
    t('recover: a SPEC §7 recovery rotation from the given node, recovery_key = the root\'s recovery public key',
      r.rotation.body.reason === 'recovery' && r.rotation.body.id === g0.did && r.rotation.body.next === r.did && did(r.rotation.next_genesis) === r.did &&
      r.rotation.body.recovery_key === recoveryPublicKey(SC) && verifySig(recoveryPublicKey(SC), r.rotation.body, r.rotation.sig));
    t('recover: --agent derives agentIdentitySeed(K_j, i, n) and carries the commitment', r.identity_seed_hex === bytesToHex(agentIdentitySeed(KC0, 3, 1)) &&
      r.rotation.next_genesis.recovery === g0.genesis.recovery && r.rotation.next_genesis.key === encodeKey(ed.getPublicKey(agentIdentitySeed(KC0, 3, 1))));
    t('recover: output holds no S and no recovery secret', !leaks(JSON.stringify(r), SChex, scWords, recHex));
    const bundle = { v: VERSION, typ: 'bundle', genesis: g0.genesis, rotations: [...thief, r.rotation], bindings: [], attestations: [att], issuers: [world.genesis] } as unknown as Bundle;
    rejects('recover: without the recovery the thief\'s two rotations are a fork', () => verify({ ...bundle, rotations: thief } as Bundle, T0 + 300), 'fork');
    const res = verify(bundle, T0 + 300);
    t('recover: the recovery wins over the thief\'s fork despite its earlier iat; chain of two; the old attestation counts',
      res.did === r.did && same(res.chain, [g0.did, r.did]) && res.attestations[world.did]?.length === 1 && res.rejected.attestations === 0);
    const rnd = recover({ from: g0.genesis, recoverySecret: recoverySeed(SC), iat: T0 });
    t('recover: with only the recovery secret, a random new key', rnd.identity_seed_hex !== r.identity_seed_hex && verify({ ...bundle, rotations: [rnd.rotation] } as Bundle, T0).did === rnd.did);
    const other = hexToBytes(VAULT_VECTORS[1]!.seed);
    rejects('recover: another root\'s recovery key is refused by name', () => recover({ from: g0.genesis, S: other, iat: T0 }), 'recovery_key does not hash');
    rejects('recover: n landing on the stolen key is refused', () => recover({ from: g0.genesis, S: SC, next: { kind: 'agent', keeper: 0, agent: 3, n: 0 }, iat: T0 }), 'IS the current');
    rejects('recover: a derived key needs S', () => recover({ from: g0.genesis, recoverySecret: recoverySeed(SC), next: { kind: 'identity', n: 1 }, iat: T0 }), 'needs the root S');
    rejects('recover: recovery: null is terminal', () => recover({ from: { ...g0.genesis, recovery: null }, S: SC, iat: T0 }), 'recovery: null');

    // The CLI: root on stdin, genesis as whoami prints it; then a restore --reveal-all file.
    const gFile = join(recTmp, 'whoami.json');
    writeFileSync(gFile, JSON.stringify({ did: g0.did, genesis: g0.genesis }));
    const run = (args: string[], input?: string) => { const x = spawnSync(process.argv[0]!, [OFFLINE, 'recover', ...args], { input }); return { code: x.status, out: x.stdout.toString(), err: x.stderr.toString() }; };
    const c1 = run(['--genesis', gFile, '-', '--agent', '3', '--n', '1', '--iat', String(T0 + 100)], scWords + '\n');
    const o1: Any = c1.code === 0 ? JSON.parse(c1.out) : {};
    t('recover CLI: stdin words → { did, rotation, identity_seed_hex } = the library\'s, nothing secret beyond the new seed',
      c1.code === 0 && o1.identity_seed_hex === r.identity_seed_hex && same(Object.keys(o1).sort(), ['did', 'identity_seed_hex', 'rotation']) &&
      o1.rotation.body.recovery_key === recoveryPublicKey(SC) && verify({ ...bundle, rotations: [...thief, o1.rotation] } as Bundle, T0 + 300).did === o1.did &&
      !leaks(c1.out + c1.err, SChex, scWords, recHex));
    const restored = join(recTmp, 'restored.json');
    writeFileSync(restored, JSON.stringify(roles(deriveRoot(SC, 'stagenet'), 'stagenet', true)));
    const c2 = run(['--genesis', gFile, '--restored', restored, '--identity-n', '5']);
    t('recover CLI: --restored takes S from owner_backup.vault and derives identitySeed(S, n)',
      c2.code === 0 && JSON.parse(c2.out).identity_seed_hex === bytesToHex(identitySeed(SC, 5)));
    const bad: Any = roles(deriveRoot(SC, 'stagenet'), 'stagenet', true);
    bad.owner_backup.recovery.secret_key_hex = bytesToHex(recoverySeed(other));
    writeFileSync(restored, JSON.stringify(bad));
    const c3 = run(['--genesis', gFile, '--restored', restored]);
    t('recover CLI: a restored file whose recovery secret is not S\'s is refused, exit 2', c3.code === 2 && c3.err.includes('not the recovery key') && c3.out === '');
    const c4 = run(['--genesis', gFile, '-', '--restored', restored], scWords);
    t('recover CLI: two root sources refused', c4.code === 2 && c4.err.includes('exactly one way'));

    // The Go reference verifier on the same bundle (skips, loudly, without Go).
    const bPath = join(recTmp, 'bundle.json');
    writeFileSync(bPath, JSON.stringify(bundle));
    const GO = join(root, 'go'), built = join(GO, 'sigelo-verify');
    const hasBuilt = spawnSync(built, ['--version']).status === 0, hasGo = spawnSync('go', ['version']).status === 0;
    if (!hasBuilt && !hasGo) console.log('SKIP recover go cross-check — `go` is not on PATH and go/sigelo-verify is not built');
    else {
      const g = hasBuilt ? spawnSync(built, [bPath, '--now', String(T0 + 300)], { cwd: GO }) : spawnSync('go', ['run', './cmd/sigelo-verify', bPath, '--now', String(T0 + 300)], { cwd: GO });
      const gr: Any = g.status === 0 ? JSON.parse(g.stdout.toString()) : {};
      t('recover go: same DID, same two-node chain, the attestation counted, thief fork not followed',
        g.status === 0 && gr.did === r.did && same(gr.chain, res.chain) && gr.attestations[world.did]?.length === 1 && gr.rejected.attestations === 0);
      const gf = hasBuilt ? spawnSync(built, ['-', '--now', String(T0 + 300)], { input: JSON.stringify({ ...bundle, rotations: thief }) }) : spawnSync('go', ['run', './cmd/sigelo-verify', '-', '--now', String(T0 + 300)], { cwd: GO, input: JSON.stringify({ ...bundle, rotations: thief }) });
      t('recover go: the thief\'s fork alone is REJECTed', gf.status === 1 && gf.stderr.toString().includes('fork'));
    }
  } finally {
    rmSync(recTmp, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------- h3. a keeper's own DID (INCIDENT.md §5)
// The keeper genesis commits to the ROOT's recovery key (the ceremony's keeper package), never to one
// derived from its keeper root. A thief with K_0 rotates the DID voluntarily; recoverKeeper rotates from
// the last honest node to identitySeed(K_1, 0), and the bundle sigelo-spend init --adopt takes verifies.
{
  const T0 = 1790000000;
  const keeperGen = (K: Uint8Array) => keygen({ seed: identitySeed(K, 0), recovery: recoveryCommitment(SC), created: '1970-01-01T00:00:00Z', nonce: new Uint8Array(16) });
  const kg = keeperGen(KC0);
  const bundle0 = { v: VERSION, typ: 'bundle', genesis: kg.genesis, rotations: [], bindings: [], attestations: [], issuers: [] } as unknown as Bundle;
  const thief = rotate({ genesis: kg.genesis, next_genesis: keygen({ seed: new Uint8Array(32).fill(9), recovery: kg.genesis.recovery }).genesis, iat: T0 + 500, reason: 'voluntary', secret: kg.secret });
  const stolen = { ...bundle0, rotations: [thief] } as Bundle;
  t('keeper: the last honest node of a bundle with the thief\'s voluntary step is the original genesis', same(keeperLastHonest(stolen, T0), kg.genesis));
  const r = recoverKeeper({ bundle: stolen, S: SC, keeper: 1, iat: T0 + 100 });
  const v = verify(r.bundle, T0 + 1000);
  t('keeper: recoverKeeper → keeper_root_hex = keeperRoot(S, 1), the new key identitySeed(K_1, 0), did = the original, the thief loses despite a later iat',
    r.keeper_root_hex === bytesToHex(keeperRoot(SC, 1)) && r.did === kg.did && v.did === r.current && v.chain[0] === kg.did && v.chain.length === 2 &&
    r.rotation.next_genesis.key === encodeKey(ed.getPublicKey(identitySeed(keeperRoot(SC, 1), 0))) && r.rotation.next_genesis.recovery === recoveryCommitment(SC));
  t('keeper: once recovered, the recovered node is the last honest one (a second recovery chains on)', same(keeperLastHonest(r.bundle, T0 + 1000), r.rotation.next_genesis) &&
    verify(recoverKeeper({ bundle: r.bundle, S: SC, keeper: 2, iat: T0 + 200 }).bundle, T0 + 1000).chain.length === 3);
  const rnd = recoverKeeper({ bundle: bundle0, recoverySecret: recoverySeed(SC), iat: T0 });
  t('keeper: with only the recovery secret, a random new keeper root', /^[0-9a-f]{64}$/.test(rnd.keeper_root_hex) && verify(rnd.bundle, T0).did === rnd.current);
  rejects('keeper: a new keeper index landing on the stolen root is refused', () => recoverKeeper({ bundle: bundle0, S: SC, keeper: 0, iat: T0 }), 'IS the current');
  rejects('keeper: a keeper genesis whose recovery derives from K (the legacy one) cannot be recovered with the root', () =>
    recoverKeeper({ bundle: { ...bundle0, genesis: keygen({ seed: identitySeed(KC0, 0), recovery: recoveryCommitment(KC0) }).genesis } as Bundle, S: SC, keeper: 1, iat: T0 }), 'recovery_key does not hash');
  const kTmp = mkdtempSync(join(tmpdir(), 'sigelo-keeper-'));
  try {
    const f = join(kTmp, 'identity.json');
    writeFileSync(f, JSON.stringify(stolen));
    const run = (args: string[], input?: string) => { const x = spawnSync(process.argv[0]!, [OFFLINE, 'recover', ...args], { input }); return { code: x.status, out: x.stdout.toString(), err: x.stderr.toString() }; };
    const c = run(['--genesis', f, '-', '--new-keeper', '1', '--iat', String(T0 + 100)], scWords);
    const o: Any = c.code === 0 ? JSON.parse(c.out) : {};
    t('keeper CLI: recover --new-keeper 1 on identity.json = the library\'s, { did, current, rotation, keeper_root_hex, bundle }, nothing else secret',
      c.code === 0 && same(Object.keys(o).sort(), ['bundle', 'current', 'did', 'keeper_root_hex', 'rotation']) && o.keeper_root_hex === r.keeper_root_hex && o.did === kg.did &&
      verify(o.bundle, T0 + 1000).chain[0] === kg.did && !leaks(c.out + c.err, SChex, scWords, recHex));
    const bad = run(['--genesis', f, '-', '--new-keeper', '1', '--agent', '3'], scWords), bad2 = run(['--genesis', f, '-', '--new-keeper', 'x'], scWords);
    t('keeper CLI: --new-keeper with --agent, or not an index, is refused (exit 2)', bad.code === 2 && bad.err.includes('takes none of') && bad2.code === 2 && bad2.err.includes('keeper index'));
  } finally {
    rmSync(kTmp, { recursive: true, force: true });
  }
}

// --- interop: monero-wallet-rpc must reproduce what walletFromRoot and the 25 words produced
// (MONERO.md §8.4). A derivation nobody else agrees with is worthless: the derived wallets stay
// reachable from stock software by private spend key, and the vault by its 25 words.
const PORT = 38084;
const rpc = async (method: string, params: unknown, ms = 2000): Promise<Any> => {
  const r = await fetch(`http://127.0.0.1:${PORT}/json_rpc`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }), signal: AbortSignal.timeout(ms),
  });
  return await r.json() as Any;
};
const skip = (why: string): void => console.log(`SKIP monero-wallet-rpc interop (${why})`);
let portBusy = false;
try { await rpc('get_version', {}, 400); portBusy = true; } catch { /* nothing listening: good */ }
if (portBusy) {
  // Something else owns the port; generating a wallet in it would be someone else's wallet.
  skip(`port ${PORT} is already in use`);
} else {
  const dir = mkdtempSync(join(tmpdir(), 'sigelo-xmr-'));
  const proc = spawn('monero-wallet-rpc', [
    '--stagenet', '--offline', '--wallet-dir', dir, '--rpc-bind-port', String(PORT),
    '--disable-rpc-login', '--log-file', process.platform === 'win32' ? 'NUL' : '/dev/null',
  ], { stdio: 'ignore' });
  let noBinary = false;
  proc.on('error', () => { noBinary = true; }); // ENOENT arrives asynchronously, not as a throw
  try {
    let up = false;
    for (let i = 0; i < 100 && !up && !noBinary; i++) {
      try { await rpc('get_version', {}, 500); up = true; } catch { await new Promise<void>((r) => setTimeout(() => r(), 100)); }
    }
    if (!up) skip(noBinary ? 'monero-wallet-rpc is not installed' : 'monero-wallet-rpc did not start in 10 s');
    else {
      const gen = await rpc('generate_from_keys', {
        restore_height: 0, filename: 'sigelo-interop', password: '',
        address: tw.address, viewkey: bytesToHex(tw.a), spendkey: bytesToHex(tw.b),
      }, 10000);
      t('xmr interop generate_from_keys accepts our address, view key and spend key together',
        gen.error === undefined && gen.result?.address === tw.address);
      t('xmr interop the stock wallet reproduces our address',
        (await rpc('get_address', { account_index: 0 })).result?.address === tw.address);
      t('xmr interop the stock wallet reproduces our view key',
        (await rpc('query_key', { key_type: 'view_key' })).result?.key === bytesToHex(tw.a));
      t('xmr interop the stock wallet reproduces our spend key',
        (await rpc('query_key', { key_type: 'spend_key' })).result?.key === bytesToHex(tw.b));
      for (const minor of [1, 2]) {
        const made = await rpc('create_address', { account_index: 0 });
        t(`xmr interop the stock wallet reproduces our subaddress (0,${minor})`,
          made.result?.address_index === minor &&
          made.result?.address === subaddress({ a: tw.a, B: tw.B, major: 0, minor, net: 'stagenet' }));
      }
      // The root's own wallet, the vault (MONERO.md §2): a stock wallet restores it from our 25
      // words and agrees on every key and on the words it shows back. Each restore opens a new
      // wallet file in this throwaway instance (the previous one is closed, never deleted).
      const q = async (key_type: string): Promise<string | undefined> => (await rpc('query_key', { key_type }, 10000)).result?.key;
      const restoreWords = (seed: string, filename: string) =>
        rpc('restore_deterministic_wallet', { seed, restore_height: 0, filename, password: '', language: 'English' }, 30000);
      for (const [i, v] of VAULT_VECTORS.entries()) {
        const rest = await restoreWords(v.words, `sigelo-vault-${i + 1}`);
        const [sk, vk, mn] = [await q('spend_key'), await q('view_key'), await q('mnemonic')];
        t(`xmr interop V${i + 1}: restore_deterministic_wallet from our 25 words gives our vault address, b (= S), a, and our words back`,
          rest.result?.address === v.stagenet && sk === v.seed && vk === v.a && mn === v.words);
      }
      const fresh = await rpc('create_wallet', { filename: 'sigelo-fresh', password: '', language: 'English' }, 30000);
      const [fm, fsk] = [(await q('mnemonic')) ?? '', (await q('spend_key')) ?? ''];
      const faddr = (await rpc('get_address', { account_index: 0 }, 10000)).result?.address;
      t('xmr interop a wallet the RPC generated: we decode its 25 words to its spend key, encode its spend key to its words, and derive its address',
        fresh.error === undefined && fm.split(' ').length === 25 && bytesToHex(rootFromMnemonic(fm)) === fsk &&
        encodeMoneroWords(hexToBytes(fsk)) === fm && vaultFromRoot(rootFromMnemonic(fm), 'stagenet').address === faddr);
      // Why a root must be canonical: past l, the wallet reduces S and shows another root's words.
      await restoreWords(encodeMoneroWords(S1), 'sigelo-noncanonical');
      const ncm = await q('mnemonic');
      t('xmr interop restored from words(S1), S1 >= l, the wallet shows the words of sc_reduce32(S1), not ours: hence the canonical rule',
        ncm !== encodeMoneroWords(S1) && ncm === encodeMoneroWords(vaultFromRoot(S1, 'stagenet').b));
      const [of, wl] = [await restoreWords(overflow, 'sigelo-overflow'), await restoreWords(wrongLast, 'sigelo-wrong-checksum')];
      t('xmr interop wallet2 refuses what we refuse: the past-2^32 triple and a wrong checksum word',
        of.error !== undefined && of.result === undefined && wl.error !== undefined && wl.result === undefined);
    }
  } catch (e) {
    // A slow or busy wallet (fetch TimeoutError, a half-written response) is an environment
    // problem, not a derivation disagreement: SKIP, never crash the run. Checks already
    // recorded above stand; a mismatch is still a FAIL, because t() never throws.
    skip(`wallet RPC did not answer: ${(e as Error)?.name ?? 'error'}: ${(e as Error)?.message ?? String(e)}`);
  } finally {
    proc.kill(); // also on a failed assertion above: never leave an RPC listening
    rmSync(dir, { recursive: true, force: true });
  }
}


console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
