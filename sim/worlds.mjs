// SPDX-License-Identifier: MIT
// sim/worlds.mjs — dishonest worlds, and the 1f916 adapter as a world (sim/README.md).
//
//   node sim/worlds.mjs [--seed S] [--agents N] [--cases C] [--no-go] [--plant bare-genesis]
//   env: SIM_SEED SIM_AGENTS SIM_CASES SIM_TS_DIST SIM_OUT
//
// swarm.mjs has honest issuers only. Here some worlds lie: they sign attestations dated in the
// future or backdated, ship geneses whose `created` is odd or malformed, reuse challenge
// nonces, attest to DIDs they never challenged, sign with a key they rotated away from, claim
// another world's DID as issuer, replay other worlds' attestations, and collude to fabricate a
// reputation ring. One world is adapters/1f916/sigelo.ts itself, imported as shipped
// (sim/1f916/world.mjs), whose genesis/challenge/verify/attestation answers flow into bundles as
// the BYTES its router would serve.
//
// Every bundle is checked three ways: (1) against the simulation's own model of the §9.1 result
// (never computed by calling a verifier), in-process through parseBytes + verify(), with and
// without locally known issuers; (2) each case's artefact against the outcome SPEC states for it
// (cited per case in CASES) — a check on the model itself; (3) the bundle's file through
// sim/verify-one.mjs (ts) and go/cmd/sigelo-verify, whose outputs must be identical. Any
// difference is a finding and the exit code is 1. Fully deterministic: sim clock, seeded PRNG,
// deterministic Ed25519; the summary's `digest` confirms a rerun.
//
// --plant bare-genesis serves the 1f916 genesis at the top level of the router's answer again
// (the bug commit 1dfec57 fixed). The model still expects the nested shape, so a correct oracle
// reports findings, and with --plant the run exits 0 only if it did (npm run worlds-plant).
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { load1f916, take, world1f916 } from './1f916/world.mjs';

const DIST = process.env.SIM_TS_DIST ? pathToFileURL(process.env.SIM_TS_DIST.replace(/\/?$/, '/')) : new URL('../ts/dist/', import.meta.url);
const S = await import(new URL('sigelo.js', DIST).href);
const { k: kdf, recoveryCommitment } = await import(new URL('keys.js', DIST).href);

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(HERE);
const OUT = process.env.SIM_OUT ?? join(HERE, 'out');
const WOUT = join(OUT, process.argv.includes('--plant') ? 'worlds-plant' : 'worlds');
const DAY = 86400;
const T0 = 1767225600; // 2026-01-01T00:00:00Z, sim time
const NOW = T0 + 120 * DAY + 3600; // every bundle is presented at this instant

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf('--' + n); return i >= 0 ? argv[i + 1] : undefined; };
const cfg = {
  seed: String(flag('seed') ?? process.env.SIM_SEED ?? 'sigelo-worlds-1'),
  agents: Number(flag('agents') ?? process.env.SIM_AGENTS ?? 40),
  cases: Number(flag('cases') ?? process.env.SIM_CASES ?? 9),
  go: !argv.includes('--no-go') && !process.env.SIM_TS_DIST, // a mutant dist is checked in-process only
  plant: flag('plant') ?? null,
};
if (cfg.plant !== null && cfg.plant !== 'bare-genesis') throw new Error('--plant: only bare-genesis');

// ---------------------------------------------------------------- PRNG (sfc32 from SHA-256), as swarm.mjs
function rngFor(seed, stream) {
  const h = createHash('sha256').update(`${seed}\n${stream}`).digest();
  let a = h.readUInt32LE(0), b = h.readUInt32LE(4), c = h.readUInt32LE(8), d = h.readUInt32LE(12);
  const next = () => {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    const t = (a + b | 0) + d | 0; d = d + 1 | 0; a = b ^ b >>> 9; b = c + (c << 3) | 0;
    c = c << 21 | c >>> 11; c = c + t | 0; return (t >>> 0) / 4294967296;
  };
  for (let i = 0; i < 12; i++) next();
  return { float: next, int: (n) => Math.floor(next() * n), chance: (p) => next() < p, pick: (xs) => xs[Math.floor(next() * xs.length)],
    bytes: (n) => Uint8Array.from({ length: n }, () => Math.floor(next() * 256)) };
}
const rfc3339 = (t) => new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const quiet = (f) => { const w = console.warn; console.warn = () => {}; try { return f(); } finally { console.warn = w; } };
const clone = (x) => structuredClone(x);
const didRaw = (g) => 'did:sigelo:' + S.multibase(createHash('sha256').update(S.canonicalize(g)).digest());
const safeDid = (g) => { try { return S.did(g); } catch { return null; } };
const utf8 = new TextDecoder();

// ---------------------------------------------------------------- worlds
const simRoot = kdf(createHash('sha256').update(`sigelo-worlds-root\n${cfg.seed}`).digest(), 'worlds/root');
const ident = (label, { created = rfc3339(T0 - 400 * DAY), recovery = 'rec' } = {}) => {
  const root = kdf(simRoot, label);
  return quiet(() => S.keygen({ seed: kdf(root, 'id'), recovery: recovery === null ? null : recoveryCommitment(kdf(root, recovery)), created, nonce: kdf(root, 'nonce').slice(0, 16) }));
};
/** A genesis built by hand — for the ones keygen (rightly) refuses to build. DID hashed directly. */
const handGenesis = (label, patch) => {
  const base = ident(label);
  const genesis = { ...base.genesis, ...patch };
  return { genesis, secret: base.secret, did: didRaw(genesis) };
};
const H0 = ident('world/H0'), H1 = ident('world/H1'), H2a = ident('world/H2a'), H2b = ident('world/H2b');
const H2_ROTATES = T0 + 60 * DAY; // world H2 rotates its own identity H2a -> H2b; H2a's key is "rotated out"
const honest = [
  { name: 'H0', ctx: 'h0.sim', ttl: 90 * DAY, at: () => H0 },
  { name: 'H1', ctx: 'h1.sim', ttl: 45 * DAY, at: () => H1 },
  { name: 'H2', ctx: 'h2.sim', ttl: 60 * DAY, at: (t) => (t < H2_ROTATES ? H2a : H2b) },
];
const honestDids = new Set([H0.did, H1.did, H2a.did, H2b.did]);
const D0 = ident('world/D0'); // the liar
const RING = [ident('world/D1'), ident('world/D2'), ident('world/D3')]; // the colluders
const DF = ident('world/DF', { created: '2031-06-01T00:00:00Z' }); // genesis created in the future
const DB = ident('world/DB', { created: '1970-01-01T00:00:00Z' }); // genesis created at the epoch
const DM = handGenesis('world/DM', { created: '2026-02-29T00:00:00Z' }); // not a Gregorian date
const DO = handGenesis('world/DO', { created: '2026-01-01T00:00:00+00:00' }); // an offset, not Z
// A genesis whose key is the identity point, and the (R = identity, s = 0) signature that a
// non-strict Ed25519 verifier accepts for EVERY message under it (SPEC §2 "Keys are points").
const IDENTITY_KEY = S.multibase(Uint8Array.from([0xed, 0x01, 1, ...new Array(31).fill(0)]));
const DZ = handGenesis('world/DZ', { key: IDENTITY_KEY });
const FORGE_SIG = S.multibase(Uint8Array.from([1, ...new Array(63).fill(0)]));
// D0's forgery of H0's genesis: H0's fields with D0's key. It hashes to a DID of its own.
const H0FORGED = { genesis: { ...H0.genesis, key: D0.genesis.key }, secret: D0.secret };
H0FORGED.did = S.did(H0FORGED.genesis);

// ---------------------------------------------------------------- the 1f916 world (the adapter itself)
const A = await load1f916(OUT);
const regSeed = kdf(simRoot, 'world/1f916/registry');
const regPub = createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), regSeed]), format: 'der', type: 'pkcs8' }))
  .export({ format: 'der', type: 'spki' }).subarray(-32);
const F = world1f916(A, { seed: regSeed, pub: regPub, oauthKey: createHash('sha256').update(`oauth\n${cfg.seed}`).digest('hex') });
const FG_TEXT = await F.genesis(NOW * 1000, false);
const FG = take(FG_TEXT, 'genesis'); // the six-field genesis, nested since 1dfec57
const FGBARE = take(await F.genesis(NOW * 1000, true), 'genesis'); // the eight-field document the bug served
const FDID = S.did(FG);

// The locally known issuers of a "local" verifier: the honest worlds and 1F916 (pinned copies).
const KNOWN = Object.fromEntries([H0, H1, H2a, H2b].map((w) => [w.did, w.genesis]).concat([[FDID, FG]]));

// ---------------------------------------------------------------- findings, counts
const findings = [];
const counts = {};
const count = (k, n = 1) => { counts[k] = (counts[k] ?? 0) + n; };
const finding = (kind, what, expected, observed, extra = {}) => findings.push({ kind, what, expected, observed, ...extra,
  repro: `node sim/worlds.mjs --seed ${JSON.stringify(cfg.seed)} --agents ${cfg.agents} --cases ${cfg.cases}${cfg.plant ? ' --plant ' + cfg.plant : ''}` });
const perCase = {}; // case -> { n, expect, ok_model, ok_spec }

if (didRaw(FG) !== await A.didOf(FG)) finding('1f916', 'adapter didOf() and a JCS hash disagree on the world DID', didRaw(FG), await A.didOf(FG));

// ---------------------------------------------------------------- agents
function makeAgent(i) {
  const rng = rngFor(cfg.seed, `agent/${i}`);
  const root = kdf(simRoot, `agent/${i}`);
  const rec = rng.chance(0.85) ? recoveryCommitment(kdf(root, 'rec')) : null;
  const mk = (n, t) => quiet(() => S.keygen({ seed: kdf(root, `id/${n}`), recovery: rec, created: rfc3339(t), nonce: rng.bytes(16) }));
  const g0 = mk(0, T0 - rng.int(30) * DAY);
  const nodes = [{ ...g0, from: -Infinity }];
  const rotations = [];
  const days = [...new Set(Array.from({ length: rng.int(4) }, () => 5 + rng.int(110)))].sort((a, b) => a - b);
  for (const [n, d] of days.entries()) {
    const t = T0 + d * DAY;
    const cur = nodes[nodes.length - 1];
    const nx = mk(n + 1, t);
    rotations.push({ env: S.rotate({ genesis: cur.genesis, next_genesis: nx.genesis, iat: t, reason: 'voluntary', secret: cur.secret }), iat: t });
    nodes.push({ ...nx, from: t });
  }
  const at = (t) => nodes.filter((x) => x.from <= t).pop();
  return { i, rng, rec, nodes, rotations, at, chain: nodes.map((x) => x.did), cur: nodes[nodes.length - 1], atts: [], citizen: null };
}

/** The agent's bundle as the world sees it at time t: its genesis, and the rotations up to t. */
const bundleAt = (ag, t, atts = [], issuers = []) => ({ v: S.VERSION, typ: 'bundle', genesis: clone(ag.nodes[0].genesis),
  rotations: ag.rotations.filter((r) => r.iat <= t).map((r) => clone(r.env)), bindings: [], attestations: atts, issuers });

/**
 * An honest world's admission: verify the presented bundle offline, challenge the current DID
 * with a fresh nonce (or, for a dishonest world, a reused one), check the answer, attest.
 */
function admit(world, ag, t, { nonce, issuer, ttl, admission = 'open', claims } = {}) {
  const res = S.verify(S.parseBytes(new TextEncoder().encode(JSON.stringify(bundleAt(ag, t)))), t);
  const node = ag.at(t);
  if (res.did !== node.did) finding('model', 'world admission: verify() did is not the model current DID', node.did, res.did, { agent: ag.i });
  const n = nonce ?? S.multibase(ag.rng.bytes(16));
  const ch = S.challenge({ secret: node.secret, genesis: node.genesis, ctx: world.ctx, nonce: n });
  const g = [ag.nodes[0].genesis, ...ag.rotations.filter((r) => r.iat <= t).map((r) => r.env.next_genesis)].find((x) => S.did(x) === res.did);
  const good = ch.body.did === res.did && ch.body.ctx === world.ctx && ch.body.nonce === n && S.verifySig(g.key, ch.body, ch.sig);
  count(`handshake:${good ? 'answered' : 'FAILED'}`);
  if (!good) finding('model', 'honest challenge answer did not verify', 'verifies', 'does not', { agent: ag.i });
  const iss = issuer ?? world.at(t);
  const a = S.attest({ secret: iss.secret, iss: iss.did, sub: res.did, iat: t, exp: t + (ttl ?? world.ttl), ctx: world.ctx, admission,
    claims: claims ?? { role: ag.rng.pick(['member', 'builder']), since: rfc3339(t).slice(0, 10) } });
  return { item: { env: a, iss: iss.did, sub: res.did, iat: t, exp: t + (ttl ?? world.ttl), bad: false }, genesis: iss.genesis, challenge: ch };
}

/** The adapter's four routes, driven the way INTEGRATION.md tells an agent to. */
async function admit1f916(ag, t, bare) {
  const ms = t * 1000;
  const node = ag.at(t);
  ag.citizen = { id: 1000 + ag.i, handle: `sim-${ag.i}`, model: 'sim/0', created_at: (T0 - 10 * DAY) * 1000 };
  const other = { id: 5000 + ag.i, handle: `other-${ag.i}`, model: 'sim/0', created_at: T0 * 1000 };
  const genesis = take(await F.genesis(ms, bare), 'genesis');
  const ch = JSON.parse(await F.challenge(ag.citizen, ms));
  const c = S.challenge({ secret: node.secret, genesis: node.genesis, ctx: ch.ctx, nonce: ch.nonce });
  // The adapter hands over the exact bytes to sign; the agent library's §3 signing input must be them.
  const told = ch.sign.replace('<your did:sigelo: DID>', node.did);
  if (told !== utf8.decode(S.signingInput(c.body))) finding('1f916', 'challenge `sign` bytes differ from the agent library signing input', told, utf8.decode(S.signingInput(c.body)), { agent: ag.i });
  // World-side refusals (SPEC §5.2: the nonce is bound to the session and a short lifetime).
  const refuses = async (label, f) => {
    try { await f(); count(`1f916-refusal:${label}:ACCEPTED`); finding('1f916', `adapter accepted ${label}`, 'SocietyError 400', 'accepted', { agent: ag.i }); }
    catch (e) { const ok = e?.name === 'SocietyError' && e.status === 400; count(`1f916-refusal:${label}:${ok ? 'refused' : 'other'}`); if (!ok) finding('1f916', `adapter ${label}: not a 400`, 'SocietyError 400', String(e?.message ?? e), { agent: ag.i }); }
  };
  await refuses('another-citizens-nonce', () => F.verify(other, { genesis: node.genesis, challenge: ch.nonce, sig: c.sig }, ms + 1000));
  await refuses('expired-nonce', () => F.verify(ag.citizen, { genesis: node.genesis, challenge: ch.nonce, sig: c.sig }, ms + 600_001));
  await refuses('prefix-did', () => F.verify(ag.citizen, { genesis: node.genesis, challenge: ch.nonce, sig: c.sig, did: node.did.slice(0, 30) }, ms + 1000));
  const wrong = S.challenge({ secret: kdf(simRoot, `impostor/${ag.i}`), genesis: quiet(() => S.keygen({ seed: kdf(simRoot, `impostor/${ag.i}`), recovery: null, created: rfc3339(T0), nonce: new Uint8Array(16) })).genesis, ctx: ch.ctx, nonce: ch.nonce });
  await refuses('wrong-key-sig', () => F.verify(ag.citizen, { genesis: node.genesis, challenge: ch.nonce, sig: wrong.sig }, ms + 1000));
  await refuses('genesis-with-clock', () => F.verify(ag.citizen, { genesis: { ...node.genesis, now: ms }, challenge: ch.nonce, sig: c.sig }, ms + 1000));
  const bound = JSON.parse(await F.verify(ag.citizen, { genesis: node.genesis, challenge: ch.nonce, sig: c.sig }, ms + 1000));
  if (bound.did !== node.did) finding('1f916', 'adapter bound a DID other than the one the genesis hashes to', node.did, bound.did, { agent: ag.i });
  count('1f916:bound');
  const nested = take(await F.attestation(ag.citizen, ms + 2000, false), 'attestation');
  const bareAtt = take(await F.attestation(ag.citizen, ms + 2000, true), 'attestation');
  const b = nested.body;
  if (b.iss !== FDID || b.sub !== node.did) finding('1f916', 'adapter attestation names the wrong iss/sub', `${FDID} / ${node.did}`, `${b.iss} / ${b.sub}`, { agent: ag.i });
  const item = { env: bare ? bareAtt : nested, iss: b.iss, sub: b.sub, iat: b.iat, exp: b.exp, bad: false };
  return { item, genesis, bareAtt, nested };
}

// ---------------------------------------------------------------- the model of §9.1
function expected(p, local) {
  if (p.fatal) return { reject: p.fatal };
  const issuers = new Set(p.issuers.map((g) => safeDid(g)));
  if (local) for (const d of Object.keys(KNOWN)) issuers.add(d);
  const attestations = {}; let ra = 0, rb = 0;
  for (const a of p.atts) {
    const ok = !a.bad && issuers.has(a.iss) && a.iat <= NOW && NOW < a.exp && p.chain.includes(a.sub);
    a.accepted = ok;
    if (ok) (attestations[a.iss] ??= []).push(a.env.body); else ra++;
  }
  for (const b of p.bindings) { if (b.bad) rb++; }
  return { did: p.chain[p.chain.length - 1], chain: p.chain, recovery: p.recovery, attestations, bindings: [], rejected: { attestations: ra, bindings: rb } };
}
const rejectClass = (m) => /fork/.test(m) ? 'fork' : /cycle/.test(m) ? 'cycle' : /recovery tie/.test(m) ? 'tie' : /^parse/.test(m) ? 'parse' : 'structure';
function observe(bytes, local) {
  try { return S.verify(S.parseBytes(bytes), NOW, local ? KNOWN : undefined); }
  catch (e) {
    if (!(e instanceof S.SigeloError) && e?.name !== 'JcsError') return { reject: 'crash', message: String(e?.stack ?? e) };
    return { reject: e?.name === 'JcsError' ? 'parse' : rejectClass(String(e.message)), message: String(e.message) };
  }
}
const show = (x) => (x.reject ? `REJECT(${x.reject})${x.message ? ': ' + x.message : ''}` : S.canonicalize(x));
const same = (exp, obs) => (exp.reject ? obs.reject === exp.reject : !obs.reject && S.canonicalize(obs) === S.canonicalize(exp));

// ---------------------------------------------------------------- dishonest cases
// Each: [name, SPEC section, what SPEC says happens to the artefact, builder]. `expect` is
// 'discard' (counted in rejected, bundle still verifies), 'accept' (verifies — SPEC leaves the
// weighing to the caller; noted), or 'fatal' (the bundle does not verify). A builder gets the
// agent's presentation `p` and adds to it; `art` marks the artefact items the expectation is
// about. Presenter swaps (a sybil, an attacker) replace p's identity.
const att = (w, sub, iat, exp, extra = {}) => {
  const body = { v: S.VERSION, typ: 'attestation', iss: extra.iss ?? w.did, sub, iat, exp, ctx: extra.ctx ?? 'd.sim', admission: extra.admission ?? 'open', claims: extra.claims ?? { note: 'dishonest' },
    ...(extra.admission_by && { admission_by: extra.admission_by }) };
  return { env: { body, sig: S.sign(extra.secret ?? w.secret, body) }, iss: body.iss, sub, iat, exp, bad: !!extra.bad, art: true };
};
const fresh = (label) => quiet(() => S.keygen({ seed: kdf(simRoot, label), recovery: null, created: rfc3339(T0), nonce: kdf(simRoot, label + '/n').slice(0, 16) }));
const asPresenter = (p, id) => { p.genesis = clone(id.genesis); p.rotations = []; p.atts = []; p.issuers = []; p.chain = [id.did]; p.recovery = id.genesis.recovery; };
const CASES = [
  ['future-iat', '§9 step 5 (iat ≤ now)', 'discard', (p, c) => { p.atts.push(att(D0, c.cur, NOW + 7 * DAY, NOW + 37 * DAY)); p.issuers.push(D0.genesis); }],
  ['iat-equals-now', '§9 step 5 (iat ≤ now)', 'accept', (p, c) => { p.atts.push(att(D0, c.cur, NOW, NOW + 30 * DAY)); p.issuers.push(D0.genesis); }],
  ['exp-equals-now', '§9 step 5 (now < exp)', 'discard', (p, c) => { p.atts.push(att(D0, c.cur, NOW - 10 * DAY, NOW)); p.issuers.push(D0.genesis); }],
  ['backdated-live', '§7.4 (iat is signer-asserted) + §9 step 5', 'accept', (p, c) => { p.atts.push(att(D0, c.cur, T0 - 300 * DAY, NOW + 30 * DAY)); p.issuers.push(D0.genesis); }],
  ['backdated-expired', '§9 step 5 (now < exp)', 'discard', (p, c) => { p.atts.push(att(D0, c.cur, T0 - 300 * DAY, T0 - 200 * DAY)); p.issuers.push(D0.genesis); }],
  ['genesis-created-future', '§4 (created is informational; only its form is checked)', 'accept', (p, c) => { p.atts.push(att(DF, c.cur, NOW - DAY, NOW + 30 * DAY)); p.issuers.push(DF.genesis); }],
  ['genesis-created-epoch', '§4 (created is informational)', 'accept', (p, c) => { p.atts.push(att(DB, c.cur, NOW - DAY, NOW + 30 * DAY)); p.issuers.push(DB.genesis); }],
  ['genesis-created-feb29', '§4 (created exactly; fatal wherever a genesis sits, an issuer included) + §9 step 2', 'fatal', (p, c) => { p.atts.push(att(DM, c.cur, NOW - DAY, NOW + 30 * DAY)); p.issuers.push(DM.genesis); p.fatal = 'structure'; }],
  ['genesis-created-offset', '§4 (Z only, no offset) + §9 step 2', 'fatal', (p, c) => { p.atts.push(att(DO, c.cur, NOW - DAY, NOW + 30 * DAY)); p.issuers.push(DO.genesis); p.fatal = 'structure'; }],
  ['issuer-identity-point-key', '§2 (keys are points; an issuer genesis is fatal) + §9 step 2', 'fatal', (p, c) => {
    const body = { v: S.VERSION, typ: 'attestation', iss: DZ.did, sub: c.cur, iat: NOW - DAY, exp: NOW + 30 * DAY, ctx: 'dz.sim', admission: 'human', claims: {} };
    p.atts.push({ env: { body, sig: FORGE_SIG }, iss: DZ.did, sub: c.cur, iat: body.iat, exp: body.exp, bad: true, art: true }); p.issuers.push(DZ.genesis); p.fatal = 'structure';
  }],
  ['nonce-reused-by-world', '§5.2 (the nonce is the world\'s session binding; a verifier never sees a challenge)', 'accept', (p, c) => {
    const r = admit({ ctx: 'd0.sim' }, c.ag, NOW - DAY, { nonce: 'reused-nonce-0', issuer: D0, ttl: 30 * DAY });
    const again = admit({ ctx: 'd0.sim' }, c.ag, NOW - DAY + 60, { nonce: 'reused-nonce-0', issuer: D0, ttl: 30 * DAY });
    if (again.challenge.sig !== r.challenge.sig) finding('model', 'deterministic signature: the same challenge signed twice differs', r.challenge.sig, again.challenge.sig);
    p.atts.push({ ...r.item, art: true }); p.issuers.push(D0.genesis);
  }],
  ['replayed-challenge-into-attacker-bundle', '§9 step 5 (sub ∈ chain)', 'discard', (p, c) => {
    // D0 reuses its nonce, so a captured answer replays; D0 attests the victim's DID for the attacker.
    const r = admit({ ctx: 'd0.sim' }, c.ag, NOW - DAY, { nonce: 'reused-nonce-0', issuer: D0, ttl: 30 * DAY });
    asPresenter(p, fresh(`attacker/${c.ag.i}`)); p.atts.push({ ...r.item, art: true }); p.issuers.push(D0.genesis);
  }],
  ['challenge-as-attestation', '§5.2 (no bundle slot accepts typ challenge) + §9 step 2', 'discard', (p, c) => {
    const node = c.ag.cur; const ch = S.challenge({ secret: node.secret, genesis: node.genesis, ctx: 'd0.sim', nonce: 'reused-nonce-0' });
    p.atts.push({ env: ch, iss: 'x', sub: 'x', iat: 0, exp: 0, bad: true, art: true });
  }],
  ['challenge-as-binding', '§5.2 + §9 step 2 (per item)', 'discard-binding', (p, c) => {
    const node = c.ag.cur; const ch = S.challenge({ secret: node.secret, genesis: node.genesis, ctx: 'd0.sim', nonce: 'reused-nonce-0' });
    p.bindings.push({ env: { body: ch.body, sig_id: ch.sig }, bad: true, art: true });
  }],
  ['challenge-as-rotation', '§5.2 + §7.4 (rotation body malformed: REJECT) + §9 step 2', 'fatal', (p, c) => {
    const node = c.ag.cur; const ch = S.challenge({ secret: node.secret, genesis: node.genesis, ctx: 'd0.sim', nonce: 'reused-nonce-0' });
    p.rotations.push({ body: ch.body, sig: ch.sig, next_genesis: fresh(`next/${c.ag.i}`).genesis }); p.fatal = 'structure';
  }],
  ['attests-unchallenged-stranger', '§9 step 5 (sub ∈ chain)', 'discard', (p, c) => { p.atts.push(att(D0, fresh(`stranger/${c.ag.i}`).did, NOW - DAY, NOW + 30 * DAY)); p.issuers.push(D0.genesis); }],
  ['attests-unchallenged-self', '§1.3, §5.1 (verifiers decide whom to trust; sigelo proves who said what)', 'accept', (p, c) => { p.atts.push(att(D0, c.cur, NOW - DAY, NOW + 30 * DAY, { admission: 'invite', admission_by: H0.did })); p.issuers.push(D0.genesis); }],
  ['attests-rotated-away-did', '§7.4 (SHOULD treat as suspect: advisory, the caller\'s) + §9 step 5', 'accept', (p, c) => {
    const old = c.ag.nodes.length > 1 ? c.ag.nodes[c.ag.nodes.length - 2].did : c.cur;
    p.atts.push(att(D0, old, NOW - DAY, NOW + 30 * DAY)); p.issuers.push(D0.genesis);
  }],
  ['truncated-sub', '§4 (full DIDs, never prefixes) + §9 step 5', 'discard', (p, c) => { p.atts.push(att(D0, c.cur.slice(0, 30), NOW - DAY, NOW + 30 * DAY)); p.issuers.push(D0.genesis); }],
  ['rotated-out-key-under-new-did', '§5 (signature against the key of the genesis whose DID is iss)', 'discard', (p, c) => {
    p.atts.push(att(H2b, c.cur, NOW - DAY, NOW + 30 * DAY, { secret: H2a.secret, ctx: 'h2.sim', bad: true })); p.issuers.push(H2b.genesis);
  }],
  ['rotated-out-key-under-old-did', '§5 (old attestations verify against the old genesis; issuer chains are not walked in v0.1)', 'accept', (p, c) => {
    p.atts.push(att(H2a, c.cur, NOW - 5 * DAY, NOW + 30 * DAY, { ctx: 'h2.sim' })); p.issuers.push(H2a.genesis);
  }],
  ['claims-other-world-iss', '§5 + §9 step 5 (signature fails against H0\'s key)', 'discard', (p, c) => {
    p.atts.push(att(D0, c.cur, NOW - DAY, NOW + 30 * DAY, { iss: H0.did, ctx: 'h0.sim', bad: true })); p.issuers.push(H0.genesis);
  }],
  ['claims-other-world-iss-forged-genesis', '§8 (issuers are hashed, never keyed) + §9 step 4', 'discard', (p, c) => {
    // iss H0 resolves only where H0's real genesis is known (presented for another attestation, or
    // pinned locally), and then D0's signature fails against H0's key: discarded either way.
    p.atts.push(att(D0, c.cur, NOW - DAY, NOW + 30 * DAY, { iss: H0.did, ctx: 'h0.sim', bad: true })); p.issuers.push(H0FORGED.genesis);
  }],
  ['forged-genesis-under-its-own-did', '§8 (a copy of H0\'s fields is just another world: its own DID)', 'accept', (p, c) => {
    p.atts.push(att(H0FORGED, c.cur, NOW - DAY, NOW + 30 * DAY, { ctx: 'h0.sim' })); p.issuers.push(H0FORGED.genesis);
  }],
  ['replay-other-agents-attestation', '§9 step 5 (sub ∈ chain)', 'discard', (p, c) => { const o = c.other.atts[0]; p.atts.push({ ...o, env: clone(o.env), art: true }); p.issuers.push(c.genesisOf(o.iss)); }],
  ['replay-sub-edited', '§9 step 5 (signature)', 'discard', (p, c) => {
    const o = c.other.atts[0]; const env = clone(o.env); env.body.sub = c.cur; p.atts.push({ ...o, env, sub: c.cur, bad: true, art: true }); p.issuers.push(c.genesisOf(o.iss));
  }],
  ['replay-ctx-edited', '§9 step 5 (signature)', 'discard', (p, c) => {
    const o = c.ag.atts[0]; const env = clone(o.env); env.body.ctx = 'elsewhere.sim'; p.atts.push({ ...o, env, bad: true, art: true });
  }],
  ['duplicate-attestation', '§9.1 (accepted bodies verbatim, in bundle order: no deduplication)', 'accept', (p, c) => {
    const o = p.atts.find((x) => x.iat <= NOW && NOW < x.exp) ?? p.atts[0]; p.atts.push({ ...o, env: clone(o.env), art: true });
  }],
  ['issuer-omitted', '§8 (an iss matching no presented and no known genesis is discarded)', 'discard', (p, c) => { p.atts.push(att(D0, c.cur, NOW - DAY, NOW + 30 * DAY)); }],
  ['unknown-admission', '§5.1 + §9 step 2 (per item)', 'discard', (p, c) => { p.atts.push(att(D0, c.cur, NOW - DAY, NOW + 30 * DAY, { admission: 'vip', bad: true })); p.issuers.push(D0.genesis); }],
  ['exp-before-iat', '§3.1 (exp > iat) + §9 step 2 (per item)', 'discard', (p, c) => { p.atts.push(att(D0, c.cur, NOW - DAY, NOW - DAY - 1, { bad: true })); p.issuers.push(D0.genesis); }],
  ['overstated-admission', '§5.1 (MUST NOT overstate; the remedy is that verifiers stop trusting the issuer)', 'accept', (p, c) => { p.atts.push(att(D0, c.cur, NOW - DAY, NOW + 30 * DAY, { admission: 'human' })); p.issuers.push(D0.genesis); }],
  ['collusion-ring', '§1.3, §5.1, §9.1 (grouped by iss: the ring stays the ring)', 'ring', (p, c) => {
    const sybil = fresh(`sybil/${c.ag.i}`); asPresenter(p, sybil);
    const adm = ['human', 'stake', 'invite'];
    RING.forEach((w, k) => {
      p.atts.push(att(w, sybil.did, NOW - DAY - k, NOW + 60 * DAY, { admission: adm[k], ...(adm[k] === 'invite' && { admission_by: H0.did }), claims: { vouched_by: RING.map((x) => x.did), standing: 'elder' } }));
      p.atts.push(att(w, RING[(k + 1) % 3].did, NOW - DAY, NOW + 60 * DAY, { claims: { peer: 'trusted world' } })); // world-to-world: sub ∉ chain
      p.issuers.push(w.genesis);
    });
  }],
  ['1f916-bare-genesis', '§3.1 (no other top-level keys) + §9 step 2 (issuers fatal); INTEGRATION.md, commit 1dfec57', 'fatal', (p, c) => {
    p.atts.push({ ...c.f.item, env: clone(c.f.nested), art: true }); p.issuers = p.issuers.filter((g) => safeDid(g) !== FDID); p.issuers.push(clone(FGBARE)); p.fatal = 'structure';
  }],
  ['1f916-bare-attestation', '§3.1 envelopes (exactly body and sig: the router\'s now/now_utc beside them discard the item) + §9 step 2 (per item)', 'discard', (p, c) => {
    p.atts = p.atts.filter((x) => x.iss !== FDID); p.atts.push({ ...c.f.item, env: clone(c.f.bareAtt), bad: true, art: true });
  }],
  ['1f916-replay-to-other-agent', '§9 step 5 (sub ∈ chain)', 'discard', (p, c) => { p.atts.push({ ...c.other.f.item, env: clone(c.other.f.nested), art: true }); if (!p.issuers.some((g) => safeDid(g) === FDID)) p.issuers.push(clone(FG)); }],
];

// ---------------------------------------------------------------- run
const t0 = Date.now();
rmSync(WOUT, { recursive: true, force: true });
mkdirSync(join(WOUT, 'diff'), { recursive: true });
process.stderr.write(`worlds: seed ${JSON.stringify(cfg.seed)}, ${cfg.agents} agents, ${cfg.cases} dishonest cases each, ${CASES.length} kinds${cfg.plant ? `, PLANTED ${cfg.plant}` : ''}\n`);

const agents = [];
for (let i = 0; i < cfg.agents; i++) {
  const ag = makeAgent(i);
  // Honest admissions at two or three honest worlds, each at the DID current then.
  for (let n = 0; n < 2 + ag.rng.int(2); n++) {
    const w = ag.rng.pick(honest);
    const t = T0 + (1 + ag.rng.int(117)) * DAY + ag.rng.int(3600);
    const r = admit(w, ag, t);
    ag.atts.push({ ...r.item, genesis: r.genesis });
  }
  ag.f = await admit1f916(ag, NOW - (1 + ag.rng.int(25)) * DAY, cfg.plant === 'bare-genesis');
  ag.fGenesis = ag.f.genesis;
  agents.push(ag);
}
const genesisOf = (d) => [H0, H1, H2a, H2b].find((w) => w.did === d)?.genesis ?? (d === FDID ? FG : undefined);

const presentations = []; // { name, p, bytes, now }
function basePresentation(ag) {
  const items = [...ag.atts.map((a) => ({ ...a, env: clone(a.env), art: false })), { ...ag.f.item, env: clone(ag.f.item.env), art: false }];
  const issuers = []; const seen = new Set();
  for (const a of ag.atts) { const d = safeDid(a.genesis); if (!seen.has(d)) { seen.add(d); issuers.push(clone(a.genesis)); } }
  issuers.push(clone(ag.fGenesis));
  return { genesis: clone(ag.nodes[0].genesis), rotations: ag.rotations.map((r) => clone(r.env)), atts: items, bindings: [], issuers,
    chain: [...ag.chain], recovery: ag.rec, fatal: null };
}
const bundleOf = (p) => ({ v: S.VERSION, typ: 'bundle', genesis: p.genesis, rotations: p.rotations, bindings: p.bindings.map((b) => b.env), attestations: p.atts.map((a) => a.env), issuers: p.issuers });

let seq = 0;
function present(label, caseName, p) {
  seq++;
  const bytes = new TextEncoder().encode(JSON.stringify(bundleOf(p)));
  const file = `w${String(seq).padStart(4, '0')}-${label}.json`;
  writeFileSync(join(WOUT, 'diff', file), bytes);
  const rows = [];
  for (const local of [false, true]) {
    const exp = expected(p, local);
    const obs = observe(bytes, local);
    if (obs.reject === 'crash') finding('crash', `${label}: verify threw an unnamed error`, 'a result or a named error', obs.message, { file: relative(ROOT, join(WOUT, 'diff', file)) });
    else if (!same(exp, obs)) finding('model', `${label}${local ? ' (local issuers)' : ''}: verify result differs from the model`, show(exp), show(obs), { file: relative(ROOT, join(WOUT, 'diff', file)) });
    rows.push({ local, exp, obs, arts: p.atts.filter((a) => a.art).map((a) => a.accepted) });
  }
  count(`bundles:${rows[0].exp.reject ? 'REJECT-' + rows[0].exp.reject : 'VALID'}`);
  presentations.push({ file, label, caseName, ts: rows[0].obs.reject ? { reject: rows[0].obs.reject, message: rows[0].obs.message } : S.canonicalize(rows[0].obs) });
  return rows;
}

for (const ag of agents) {
  const other = agents[(ag.i + 1) % agents.length];
  // 1. the honest bundle alone: must verify, and so must its 1f916 attestation.
  const base = basePresentation(ag);
  const [hr] = present(`a${ag.i}-honest`, null, base);
  const fOk = !hr.exp.reject && (hr.exp.attestations[FDID] ?? []).length === 1;
  count(`honest:${hr.exp.reject ? 'FATAL' : 'valid'}`);
  count(`1f916-attestation:${fOk ? 'accepted' : 'not accepted'}`);
  if (!cfg.plant && (hr.exp.reject || !fOk)) finding('model', `a${ag.i}: the honest bundle is not VALID with its 1f916 attestation`, 'VALID', show(hr.exp));
  // 2. the dishonest cases: a rotating window over CASES, so every kind is exercised.
  const picks = new Set();
  for (let k = 0; k < cfg.cases; k++) picks.add((ag.i * cfg.cases + k) % CASES.length);
  for (const ci of [...picks].sort((a, b) => a - b)) {
    const [name, spec, expect, build] = CASES[ci];
    const p = basePresentation(ag);
    build(p, { ag, cur: ag.cur.did, other, genesisOf, f: ag.f });
    const before = findings.length;
    const rows = present(`a${ag.i}-${name}`, name, p);
    const pc = perCase[name] ??= { spec, expect, presented: 0, model_ok: 0, spec_ok: 0 };
    pc.presented++;
    const r0 = rows[0];
    if (findings.length === before) pc.model_ok++;
    // The outcome SPEC states for the artefact, checked against the model (a check on the model).
    let specOk;
    if (expect === 'fatal') specOk = !!r0.exp.reject;
    else if (expect === 'discard') specOk = !r0.exp.reject && r0.arts.length > 0 && r0.arts.every((x) => x === false);
    else if (expect === 'discard-binding') specOk = !r0.exp.reject && r0.exp.rejected.bindings === 1;
    else if (expect === 'accept') specOk = !r0.exp.reject && r0.arts.length > 0 && r0.arts.every((x) => x === true);
    else if (expect === 'ring') {
      // The three attestations about the sybil verify; the three world-to-world ones do not;
      // no accepted attestation is under an honest world's DID; an honest world that admits
      // migrants only on a trusted world's attestation turns the sybil away (swarm.mjs admits()).
      const iss = Object.keys(r0.obs.attestations ?? {});
      const trusted = iss.filter((d) => honestDids.has(d) || d === FDID);
      specOk = !r0.exp.reject && r0.arts.filter((x) => x).length === 3 && r0.arts.filter((x) => !x).length === 3 && trusted.length === 0;
      count(`ring:migration-at-honest-world:${trusted.length ? 'admitted' : 'denied'}`);
    }
    if (specOk) pc.spec_ok++;
    else finding('spec', `a${ag.i} ${name}: the model's outcome for the artefact is not what ${spec} says (${expect})`, expect, show(r0.exp));
  }
}
const simMs = Date.now() - t0;

// ---------------------------------------------------------------- ts (verify-one.mjs) vs go, on the files
let diff = { skipped: cfg.go ? undefined : (process.env.SIM_TS_DIST ? 'SIM_TS_DIST set: in-process only' : '--no-go') };
if (cfg.go) {
  const bin = join(OUT, 'sigelo-verify');
  execFileSync('go', ['build', '-o', bin, './cmd/sigelo-verify'], { cwd: join(ROOT, 'go'), stdio: 'inherit' });
  const run = (cmd, args) => new Promise((resolve) => execFile(cmd, args, { maxBuffer: 1 << 26 }, (err, stdout, stderr) => {
    if (!err) resolve({ out: stdout.trim() });
    else if (err.code === 1 && /^REJECT: /.test(stderr)) resolve({ reject: stderr.trim().slice(8) });
    else resolve({ error: `${err.code}: ${String(stderr).trim() || err.message}` });
  }));
  diff = { compared: 0, identical: 0, bothRejected: 0, classDiffers: 0, mismatches: 0, tsSubprocessVsInProcess: 0 };
  let next = 0;
  await Promise.all(Array.from({ length: Math.max(2, availableParallelism()) }, async () => {
    while (next < presentations.length) {
      const d = presentations[next++];
      const f = join(WOUT, 'diff', d.file);
      const [t, g] = await Promise.all([run(process.execPath, [join(HERE, 'verify-one.mjs'), f, String(NOW)]), run(bin, [f, '--now', String(NOW)])]);
      diff.compared++;
      const rel = relative(ROOT, f);
      const repro = `(cd go && go run ./cmd/sigelo-verify ../${rel} --now ${NOW})  vs  node sim/verify-one.mjs ${rel} ${NOW}`;
      // verify-one.mjs is the harness; it must say what the in-process run said.
      const tsIn = typeof d.ts === 'string' ? d.ts : null;
      if ((tsIn !== null && t.out !== tsIn) || (tsIn === null && (t.reject === undefined || rejectClass(t.reject) !== d.ts.reject))) {
        diff.tsSubprocessVsInProcess++;
        finding('harness', `${d.label}: verify-one.mjs differs from the in-process verify()`, tsIn ?? `REJECT(${d.ts.reject}) ${d.ts.message}`, JSON.stringify(t), { file: rel });
      }
      if (t.error || g.error) { diff.mismatches++; finding('differential', `${d.label}: a verifier errored`, JSON.stringify(t), JSON.stringify(g), { file: rel, repro }); continue; }
      if (t.out !== undefined && g.out !== undefined) {
        if (t.out === g.out) diff.identical++; else { diff.mismatches++; finding('differential', `${d.label}: §9.1 result differs`, `ts ${t.out}`, `go ${g.out}`, { file: rel, repro }); }
      } else if (t.reject !== undefined && g.reject !== undefined) {
        diff.bothRejected++;
        if (rejectClass(t.reject) !== rejectClass(g.reject)) { diff.classDiffers++; finding('differential-reason', `${d.label}: both reject, for different checks`, `ts ${t.reject}`, `go ${g.reject}`, { file: rel, repro }); }
      } else { diff.mismatches++; finding('differential', `${d.label}: one accepts, one rejects`, `ts ${t.out ?? 'REJECT ' + t.reject}`, `go ${g.out ?? 'REJECT ' + g.reject}`, { file: rel, repro }); }
    }
  }));
}

const sorted = (o) => Object.fromEntries(Object.entries(o).sort());
const summary = {
  seed: cfg.seed, agents: cfg.agents, cases_per_agent: cfg.cases, case_kinds: CASES.length, plant: cfg.plant, now: NOW,
  bundles: presentations.length, verifies: presentations.length * 2, wall_ms: Date.now() - t0, sim_ms: simMs,
  differential: diff, findings: findings.length, counts: sorted(counts), cases: sorted(perCase),
};
summary.digest = createHash('sha256').update(JSON.stringify([summary.counts, summary.cases, findings.map((f) => [f.kind, f.what, f.expected, f.observed]), presentations.map((d) => [d.file, d.ts])])).digest('hex').slice(0, 16);
const stem = cfg.plant ? `worlds-plant-${cfg.plant}` : 'worlds'; // a planted run never overwrites the real one
writeFileSync(join(OUT, `${stem}-summary.json`), JSON.stringify(summary, null, 1));
writeFileSync(join(OUT, `${stem}-findings.json`), JSON.stringify(findings, null, 1));
for (const f of findings.slice(0, 30)) process.stderr.write(`FINDING ${f.kind}: ${f.what}\n  expected ${String(f.expected).slice(0, 300)}\n  observed ${String(f.observed).slice(0, 300)}\n  repro: ${f.repro}${f.file ? `  (bytes: ${f.file})` : ''}\n`);
console.log(JSON.stringify({ ...summary, counts: undefined, cases: undefined }));
if (cfg.plant) {
  // A planted bug is the check on the oracle: it must be reported, so findings are the pass.
  process.stderr.write(`worlds: PLANTED ${cfg.plant}: ${findings.length ? `caught (${findings.length} findings)` : 'NOT CAUGHT — the oracle is blind to it'}\n`);
  process.exitCode = findings.length ? 0 : 1;
} else process.exitCode = findings.length ? 1 : 0;
