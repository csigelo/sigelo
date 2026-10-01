// SPDX-License-Identifier: MIT
// sim/swarm.mjs — a seeded, deterministic swarm of agents moving between worlds (sim/README.md).
//
//   node sim/swarm.mjs [--seed S] [--agents N] [--worlds M] [--rounds R] [--workers W]
//                      [--diff P] [--only-agent i] [--no-go]
//   env: SIM_SEED SIM_AGENTS SIM_WORLDS SIM_ROUNDS SIM_WORKERS SIM_DIFF
//
// Every agent is an independent storyline driven by its own PRNG stream (seed, agent index),
// so a run is reproducible and independent of the worker count, and any one agent's storyline
// can be replayed alone with --only-agent. For every presentation the simulation builds an
// EXPECTED §9.1 result from its own event model (who rotated where, who stole what, which
// items were tampered) — never by calling the verifier — and compares it, JCS against JCS,
// with what verify() returns. Any difference is a finding. A sample of the presented bundles
// is then run through the Go reference verifier (go/cmd/sigelo-verify) and compared byte for
// byte.
import { isMainThread, Worker, parentPort, workerData } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, relative } from 'node:path';
// SIM_TS_DIST points the whole simulation at another build of ts/dist — how sim/mutants.mjs
// checks that the oracle notices a broken verifier. Default: the repo's own build.
const DIST = process.env.SIM_TS_DIST ? pathToFileURL(process.env.SIM_TS_DIST.replace(/\/?$/, '/')) : new URL('../ts/dist/', import.meta.url);
const S = await import(new URL('sigelo.js', DIST).href);
const { k: kdf, agentIdentitySeed, keeperRoot, walletFromRoot, recoverySeed, recoveryPublicKey, recoveryCommitment } = await import(new URL('keys.js', DIST).href);
const { subaddress, sigeloMoneroSigAddr, decodeAddress, encodeAddress } = await import(new URL('monero.js', DIST).href);

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(HERE);
// SIM_OUT: where bytes, findings and the summary go (sim/mutants.mjs runs several at once).
const OUT = process.env.SIM_OUT ?? join(HERE, 'out');
const DAY = 86400;
const T0 = 1767225600; // 2026-01-01T00:00:00Z — sim time; nothing here reads the wall clock for protocol time

// ---------------------------------------------------------------- config

function config(argv, env) {
  const flag = (name) => { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : undefined; };
  const num = (name, envName, dflt) => { const v = flag(name) ?? env[envName]; return v === undefined ? dflt : Number(v); };
  return {
    seed: String(flag('seed') ?? env.SIM_SEED ?? 'sigelo-swarm-1'),
    agents: num('agents', 'SIM_AGENTS', 300),
    worlds: num('worlds', 'SIM_WORLDS', 6),
    rounds: num('rounds', 'SIM_ROUNDS', 40),
    workers: num('workers', 'SIM_WORKERS', Math.max(1, Math.min(6, availableParallelism() - 1))),
    diff: num('diff', 'SIM_DIFF', 0.3),
    onlyAgent: flag('only-agent') === undefined ? undefined : Number(flag('only-agent')),
    go: !argv.includes('--no-go'),
  };
}

// ---------------------------------------------------------------- PRNG (sfc32 seeded by SHA-256)

function rngFor(seed, stream) {
  const h = createHash('sha256').update(`${seed}\n${stream}`).digest();
  let a = h.readUInt32LE(0), b = h.readUInt32LE(4), c = h.readUInt32LE(8), d = h.readUInt32LE(12);
  const next = () => {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    const t = (a + b | 0) + d | 0; d = d + 1 | 0; a = b ^ b >>> 9; b = c + (c << 3) | 0;
    c = c << 21 | c >>> 11; c = c + t | 0; return (t >>> 0) / 4294967296;
  };
  for (let i = 0; i < 12; i++) next();
  const r = {
    float: next, int: (n) => Math.floor(next() * n), chance: (p) => next() < p,
    pick: (xs) => xs[Math.floor(next() * xs.length)],
    bytes: (n) => Uint8Array.from({ length: n }, () => Math.floor(next() * 256)),
    weighted: (table) => { // [[name, weight], ...]
      const tot = table.reduce((s, [, w]) => s + w, 0); let x = next() * tot;
      for (const [n, w] of table) { if ((x -= w) < 0) return n; } return table[table.length - 1][0];
    },
  };
  return r;
}

const rfc3339 = (t) => new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const clone = (x) => structuredClone(x);
const quiet = (f) => { const w = console.warn; console.warn = () => {}; try { return f(); } finally { console.warn = w; } };

// ---------------------------------------------------------------- the world

function makeWorlds(cfg, simRoot) {
  const modes = ['open', 'invite', 'payment', 'stake', 'captcha', 'open'];
  const ttls = [3, 30, 10, 20, 5, 60];
  const worlds = [];
  for (let j = 0; j < cfg.worlds; j++) {
    const root = kdf(simRoot, `sim/world/${j}`);
    const id = S.keygen({ seed: kdf(root, 'identity'), recovery: recoveryPublicKey(kdf(root, 'recovery')),
      created: rfc3339(T0 - 400 * DAY), nonce: kdf(root, 'nonce').slice(0, 16) });
    const founder = S.keygen({ seed: kdf(root, 'founder'), recovery: recoveryPublicKey(kdf(root, 'founder-rec')),
      created: rfc3339(T0 - 400 * DAY), nonce: kdf(root, 'founder-nonce').slice(0, 16) });
    worlds.push({ j, id, did: id.did, ctx: `world-${j}.sim`, mode: modes[j % modes.length], ttl: ttls[j % ttls.length] * DAY,
      founder: founder.did, local: j % 2 === 0, trusts: new Set(), unicode: j % 3 === 1 });
  }
  for (const w of worlds) for (const d of [1, 2]) if (cfg.worlds > d) w.trusts.add(worlds[(w.j + d) % cfg.worlds].did);
  const known = Object.fromEntries(worlds.map((w) => [w.did, w.id.genesis]));
  return { worlds, known };
}

/** A world's admission rule, applied identically to the observed and the expected result. */
function admits(world, res, migrating) {
  if (res.reject) return 'reject: ' + res.reject;
  if (world.mode === 'payment' && !res.bindings.some((b) => b.proof === 'proven' && b.body.method === 'monero' && netOf(b.body.addr) === 'stagenet')) return 'no proven stagenet binding';
  if (world.mode === 'stake' && (res.recovery === null || !Object.keys(res.attestations).some((i) => i !== world.did && res.attestations[i].length))) return 'stake needs recovery + reputation';
  if (migrating && !Object.keys(res.attestations).some((i) => world.trusts.has(i) && res.attestations[i].length)) return 'no attestation from a trusted world';
  return 'ok';
}
function netOf(addr) { try { return decodeAddress(addr).net; } catch { return null; } }

// ---------------------------------------------------------------- serialization with raw holes

const HOLE = { '@@FLOAT@@': '1.5', '@@BIG@@': '9007199254740993', '@@EXP@@': '1e2' };
function serializeText(obj, textMut) {
  let t = JSON.stringify(obj);
  for (const [k, v] of Object.entries(HOLE)) t = t.split(JSON.stringify(k)).join(v);
  return textMut ? textMut(t) : t;
}
// A presentation is BYTES, and the verifier reads bytes (parseBytes, as every real entry point
// does): a JS string cannot hold invalid UTF-8, so a sim that handed verify() strings could never
// see the class where a lossy decoder and a byte-level parser disagree (differential D3).
// byteMut edits the encoded bytes; spliceBytes puts raw bytes after the first `at`.
const utf8Bytes = (t) => new TextEncoder().encode(t);
function serialize(obj, textMut, byteMut) {
  const b = utf8Bytes(serializeText(obj, textMut));
  return byteMut ? byteMut(b) : b;
}
function spliceBytes(b, at, raw) {
  const needle = utf8Bytes(at);
  const k = Buffer.from(b).indexOf(Buffer.from(needle));
  if (k < 0) return b;
  const j = k + needle.length;
  const out = new Uint8Array(b.length + raw.length);
  out.set(b.subarray(0, j)); out.set(raw, j); out.set(b.subarray(j), j + raw.length);
  return out;
}
const INVALID_UTF8 = [[0xff], [0xfe], [0x80], [0xc0, 0xaf], [0xc3, 0x28], [0xed, 0xa0, 0x80], [0xe2, 0x82], [0xf4, 0x90, 0x80, 0x80]];

// ---------------------------------------------------------------- one agent's storyline

function simulateAgent(i, cfg, env) {
  const { simRoot, K, worlds, known } = env;
  const rng = rngFor(cfg.seed, `agent/${i}`);
  const ev = { counts: {}, findings: [], diffs: [], verifies: 0, verifyMs: 0, maxChain: 0, maxRotations: 0 };
  const count = (k) => { ev.counts[k] = (ev.counts[k] ?? 0) + 1; };
  let seq = 0;

  // --- identity state (the MODEL; the verifier never feeds back into it)
  const hasRecovery = rng.chance(0.93);
  let recGen = 0;
  const recRoot = (g) => kdf(simRoot, `sim/agent/${i}/rec/${g}`);
  let ownerN = 0;
  const nodes = new Map(); // did -> { genesis, secret }
  const mkGenesis = (seed, recovery, t) => quiet(() => S.keygen({ seed, recovery, created: rfc3339(t), nonce: rng.bytes(16) }));
  const g0id = mkGenesis(agentIdentitySeed(K, i, 0), hasRecovery ? recoveryCommitment(recRoot(0)) : null, T0 - rng.int(30) * DAY);
  nodes.set(g0id.did, { genesis: g0id.genesis, secret: g0id.secret });
  const A = {
    g0: g0id.genesis, pubRotations: [], pubChain: [g0id.did], pubCommit: g0id.genesis.recovery,
    fatal: null, owner: g0id.did, thief: null, clean: true,
    atts: [], thiefAtts: [], bindings: [], worlds: new Set(), sub: 0,
  };
  const wallet = walletFromRoot(simRoot, `counterparty/${i}`, 'stagenet');
  const view = wallet.viewOnly();
  const viewPub = decodeAddress(view.address).view;
  const tail = () => A.pubChain[A.pubChain.length - 1];
  const ownerIsTail = () => A.fatal === null && A.owner === tail();

  // --- builders
  function publish(r, tag) { A.pubRotations.push(r); A.clean &&= tag === 'link'; }
  function nextOwnerGenesis(now, recovery) {
    const n = ++ownerN;
    const id = mkGenesis(agentIdentitySeed(K, i, n), recovery, now);
    nodes.set(id.did, { genesis: id.genesis, secret: id.secret });
    return id;
  }
  function bindNow(now, proven) {
    const cur = nodes.get(A.owner);
    const body = { v: S.VERSION, typ: 'binding', id: A.owner, method: 'monero', addr: view.address, iat: now, exp: now + (8 + rng.int(20)) * DAY, nonce: S.multibase(rng.bytes(16)) };
    const sig_addr = proven ? sigeloMoneroSigAddr(body, { mode: 'view', secret: view.a, spendPub: view.B, viewPub, nonce: rng.bytes(32) }) : undefined;
    const b = S.bind({ secret: cur.secret, id: body.id, method: body.method, addr: body.addr, iat: body.iat, exp: body.exp, nonce: body.nonce, ...(sig_addr && { sig_addr }) });
    if (S.canonicalize(b.body) !== S.canonicalize(body)) finding('bind', 0, 'bind() body', S.canonicalize(body), S.canonicalize(b.body));
    A.bindings.push({ env: b, id: body.id, iat: body.iat, exp: body.exp, proof: proven ? 'proven' : 'unproven' });
    // An agent keeps its two newest bindings; older ones are dropped from what it presents.
    if (A.bindings.length > 2) A.bindings.shift();
  }

  /** The bundle a presenter shows, as item records the expectation is computed from. */
  function presentation(who) {
    const atts = (who === 'thief' ? A.thiefAtts : A.atts).map((a) => ({ ...a, env: clone(a.env), bad: false }));
    const bindings = A.bindings.map((b) => ({ ...b, env: clone(b.env), bad: false }));
    const iss = [...new Set(atts.map((a) => a.iss))];
    return { genesis: clone(A.g0), rotations: A.pubRotations.map(clone), atts, bindings, issuers: iss.map((d) => clone(known[d])),
      chain: [...A.pubChain], recovery: A.pubCommit, fatal: A.fatal, textMut: undefined, bundleMut: undefined };
  }
  const bundleOf = (p) => {
    const b = { v: S.VERSION, typ: 'bundle', genesis: p.genesis, rotations: p.rotations, bindings: p.bindings.map((x) => x.env),
      attestations: p.atts.map((x) => x.env), issuers: p.issuers };
    if (p.bundleMut) p.bundleMut(b);
    return b;
  };
  function expected(p, now, local) {
    if (p.fatal) return { reject: p.fatal };
    const issuers = new Set(p.issuers.filter((g) => g && typeof g === 'object').map((g) => { try { return S.did(g); } catch { return null; } }));
    const attestations = {}; let ra = 0, rb = 0;
    for (const a of p.atts) {
      const ok = !a.bad && (issuers.has(a.iss) || (local && a.iss in known)) && a.iat <= now && now < a.exp && p.chain.includes(a.sub);
      if (ok) (attestations[a.iss] ??= []).push(a.env.body); else ra++;
    }
    const bindings = [];
    for (const b of p.bindings) {
      const ok = !b.bad && p.chain.includes(b.id) && b.iat <= now && now < b.exp && b.proof !== 'bad';
      if (ok) bindings.push({ body: b.env.body, proof: b.proof }); else rb++;
    }
    return { did: p.chain[p.chain.length - 1], chain: p.chain, recovery: p.recovery, attestations, bindings, rejected: { attestations: ra, bindings: rb } };
  }
  /** What verify() says about the bytes. Fatal outcomes are classified by the check they name. */
  function observe(bytes, now, knownIssuers) {
    const t = process.hrtime.bigint();
    ev.verifies++;
    try {
      const obj = S.parseBytes(bytes);
      return { res: S.verify(obj, now, knownIssuers), obj };
    } catch (e) {
      const m = String(e?.message ?? e);
      const cls = /fork/.test(m) ? 'fork' : /cycle/.test(m) ? 'cycle' : /recovery tie/.test(m) ? 'tie' : e?.name === 'JcsError' ? 'parse' : 'structure';
      if (!(e instanceof S.SigeloError) && e?.name !== 'JcsError') return { res: { reject: 'crash', message: m, stack: e?.stack } };
      return { res: { reject: cls, message: m } };
    } finally { ev.verifyMs += Number(process.hrtime.bigint() - t) / 1e6; }
  }
  const same = (exp, obs) => exp.reject ? obs.reject === exp.reject : !obs.reject && S.canonicalize(obs) === S.canonicalize(exp);
  const show = (x) => x.reject ? `REJECT(${x.reject})${x.message ? ': ' + x.message : ''}` : S.canonicalize(x);

  function finding(kind, r, what, exp, obs, text) {
    const f = { agent: i, round: r, seq, kind, what, expected: exp, observed: obs,
      repro: `node sim/swarm.mjs --seed ${JSON.stringify(cfg.seed)} --agents ${cfg.agents} --worlds ${cfg.worlds} --rounds ${cfg.rounds} --only-agent ${i}` };
    if (text !== undefined) { mkdirSync(join(OUT, 'findings'), { recursive: true }); f.file = relative(ROOT, join(OUT, 'findings', `a${i}-${seq}.json`)); writeFileSync(join(ROOT, f.file), text); }
    ev.findings.push(f);
  }

  /** Present p to a verifier; compare with the model; maybe queue for the Go differential. */
  function present(kind, r, now, p, world, forceDiff = false) {
    seq++;
    const local = world ? world.local : false;
    const text = serialize(bundleOf(p), p.textMut, p.byteMut);
    const exp = expected(p, now, local);
    const { res: obs, obj } = observe(text, now, local ? known : undefined);
    count(`${kind}:${exp.reject ? 'REJECT-' + exp.reject : 'accept'}`);
    if (!same(exp, obs)) finding(kind, r, 'verify result', show(exp), show(obs), text);
    if (!local && (forceDiff || rng.chance(cfg.diff))) {
      const name = `a${i}-${seq}.json`;
      writeFileSync(join(OUT, 'diff', name), text);
      ev.diffs.push({ file: name, now, kind, ts: obs.reject ? { reject: obs.reject, message: obs.message } : S.canonicalize(obs) });
    }
    if (!obs.reject) { ev.maxChain = Math.max(ev.maxChain, obs.chain.length); ev.maxRotations = Math.max(ev.maxRotations, p.rotations.length); }
    return { exp, obs, obj };
  }

  // --- world interactions: challenge -> sign -> verify bundle offline -> decide -> attest
  function admission(kind, r, now, world, who) {
    const migrating = kind === 'migrate';
    const p = presentation(who);
    const { exp, obs, obj } = present(kind, r, now, p, world);
    // The presenter answers a challenge with the key it holds for the node it believes current.
    const holds = who === 'thief' ? A.thief.tail : A.owner;
    const nonce = S.multibase(rng.bytes(16));
    const ch = S.challenge({ secret: nodes.get(holds).secret, genesis: nodes.get(holds).genesis, ctx: world.ctx, nonce });
    let obsDecision = admits(world, obs, migrating);
    if (obsDecision === 'ok') {
      const gens = [obj.genesis, ...obj.rotations.map((x) => x.next_genesis)];
      const g = gens.find((x) => S.did(x) === obs.did);
      const good = ch.body.did === obs.did && ch.body.ctx === world.ctx && ch.body.nonce === nonce && g && S.verifySig(g.key, ch.body, ch.sig);
      if (!good) obsDecision = 'challenge does not answer for the current DID';
    }
    let expDecision = admits(world, exp, migrating);
    if (expDecision === 'ok' && holds !== exp.did) expDecision = 'challenge does not answer for the current DID';
    if (expDecision !== obsDecision) finding(kind, r, 'admission decision', expDecision, obsDecision);
    count(`${kind}-decision:${obsDecision === 'ok' ? 'admitted' : 'denied'}${who === 'thief' ? '(thief)' : ''}`);
    if (obsDecision !== 'ok') return false;
    const claims = { role: rng.pick(['member', 'builder', 'moderator']), level: 1 + rng.int(9), since_round: r,
      tags: [rng.pick(['a', 'b', 'c']), world.ctx], ...(migrating && { migrated: true }),
      ...(world.unicode && { motto: rng.pick(['żółw ☃', 'ünïcödé', '𝄞 music', 'emoji 🦀', 'tab\tand "quote"']) }) };
    const a = S.attest({ secret: world.id.secret, iss: world.did, sub: obs.did, iat: now, exp: now + world.ttl, ctx: world.ctx,
      admission: world.mode, ...(world.mode === 'invite' && { admission_by: world.founder }), ...(world.mode === 'payment' && { admission_cost: `${1 + rng.int(50)}0000000000 piconero` }), claims });
    const list = who === 'thief' ? A.thiefAtts : A.atts;
    list.push({ env: a, iss: world.did, sub: obs.did, iat: now, exp: now + world.ttl });
    // An agent drops expired attestations beyond the three newest expired ones.
    const expired = list.filter((x) => x.exp <= now);
    if (expired.length > 3) list.splice(list.indexOf(expired[0]), 1);
    if (list.length > 14) list.shift();
    if (who === 'owner') A.worlds.add(world.j);
    return true;
  }

  // --- theft, fork, recovery
  function steal(r, now) {
    const X = tail();
    const { secret, genesis } = nodes.get(X);
    const tseed = kdf(simRoot, `sim/thief/${i}/${r}`);
    const style = rng.weighted([['valid', 0.75], ['swap-commitment', 0.15], ['forged-recovery', 0.1]]);
    count(`theft:${style}`);
    if (style === 'valid') {
      const nid = mkGenesis(tseed, A.pubCommit, now);
      nodes.set(nid.did, { genesis: nid.genesis, secret: nid.secret });
      publish(S.rotate({ genesis, next_genesis: nid.genesis, iat: now, reason: 'voluntary', secret }), 'thief');
      A.pubChain.push(nid.did);
      A.thief = { at: X, tail: nid.did, n: 0 };
    } else if (style === 'swap-commitment') {
      // Invariant 5: a thief installing its own recovery key. rotate() refuses to build it, so
      // it is signed by hand — and must be "not a candidate" for every verifier.
      const nid = mkGenesis(tseed, recoveryCommitment(kdf(tseed, 'rec')), now);
      nodes.set(nid.did, { genesis: nid.genesis, secret: nid.secret });
      const body = { v: S.VERSION, typ: 'rotation', id: X, next: nid.did, iat: now, reason: 'voluntary' };
      publish({ body, sig: S.sign(secret, body), next_genesis: nid.genesis }, 'thief');
      A.thief = null; // its rotation leads nowhere
    } else {
      // A recovery signed with a key that does not hash to the commitment: not a candidate.
      const rs = recoverySeed(kdf(tseed, 'rec'));
      const nid = mkGenesis(tseed, recoveryCommitment(kdf(tseed, 'rec')), now);
      nodes.set(nid.did, { genesis: nid.genesis, secret: nid.secret });
      const body = { v: S.VERSION, typ: 'rotation', id: X, next: nid.did, iat: now + 5, reason: 'recovery', recovery_key: recoveryPublicKey(kdf(tseed, 'rec')) };
      publish({ body, sig: S.sign(rs, body), next_genesis: nid.genesis }, 'thief');
      A.thief = null;
    }
    // The thief presents the stolen identity to a world straight away.
    if (A.thief) admission('thief-join', r, now, rng.pick(worlds), 'thief');
    else { const p = presentation('owner'); present('thief-failed', r, now, p, rng.pick(worlds), true); }
  }
  function ownerRotate(r, now) {
    const X = A.owner;
    const cur = nodes.get(X);
    const nid = nextOwnerGenesis(now, A.pubCommit === null ? null : nodes.get(X).genesis.recovery);
    publish(S.rotate({ genesis: cur.genesis, next_genesis: nid.genesis, iat: now, reason: 'voluntary', secret: cur.secret }), 'link');
    A.owner = nid.did;
    if (A.thief && A.thief.at === X && A.fatal === null) {
      // Two valid voluntary rotations from X: the key was stolen. Every verifier must reject.
      A.fatal = 'fork';
      A.forkAt = X;
      count('fork:created');
      const p = presentation('owner');
      for (const w of worlds) present('fork-presented', r, now, p, w, true);
      return;
    }
    if (A.fatal === null) A.pubChain.push(nid.did);
  }
  function recover(r, now) {
    const X = A.thief ? A.thief.at : A.fatal === 'fork' ? A.forkAt : tail();
    const rec = recRoot(recGen);
    const change = rng.chance(0.3);
    if (change) recGen++;
    const newCommit = recoveryCommitment(recRoot(recGen));
    const nid = nextOwnerGenesis(now, newCommit);
    // "Regardless of iat": half the time the recovery claims to be older than everything.
    const iat = rng.chance(0.5) ? T0 - (1 + rng.int(300)) * DAY : now;
    const from = nodes.get(X).genesis;
    publish(S.rotate({ genesis: from, next_genesis: nid.genesis, iat, reason: 'recovery', secret: recoverySeed(rec) }), 'recovery');
    if (rng.chance(0.15)) {
      // The operator also published an earlier recovery at X (lower iat): the latest one wins.
      const alt = mkGenesis(kdf(simRoot, `sim/agent/${i}/alt/${r}`), newCommit, now);
      publish(S.rotate({ genesis: from, next_genesis: alt.genesis, iat: iat - 1 - rng.int(1000), reason: 'recovery', secret: recoverySeed(rec) }), 'recovery');
      count('recovery:with-older-sibling');
    }
    A.pubChain = [...A.pubChain.slice(0, A.pubChain.indexOf(X) + 1), nid.did];
    A.pubCommit = newCommit;
    A.fatal = null; A.thief = null; A.owner = nid.did;
    count(`recovery:${change ? 'new-commitment' : 'same-commitment'}${iat < T0 ? ':backdated' : ''}`);
    const p = presentation('owner');
    for (const w of [rng.pick(worlds), rng.pick(worlds)]) present('recovered', r, now, p, w, true);
  }

  // --- invoices (SPEC §6.3), checked the way a payer must check them
  function invoice(r, now) {
    const variant = rng.weighted([['honest', 0.55], ['amount-tampered', 0.1], ['expired', 0.1], ['old-key', 0.1], ['float-amount', 0.05], ['mainnet-addr', 0.1]]);
    const minor = ++A.sub;
    const net = variant === 'mainnet-addr' ? 'mainnet' : 'stagenet';
    const addr = subaddress({ a: view.a, B: view.B, major: 0, minor, net });
    const signer = variant === 'old-key' && A.pubChain.indexOf(A.owner) > 0 ? A.pubChain[A.pubChain.indexOf(A.owner) - 1] : A.owner;
    const iat = variant === 'expired' ? now - 3 * DAY : now;
    const body = { v: S.VERSION, typ: 'invoice', did: A.owner, method: 'monero', addr, iat, exp: iat + DAY, nonce: S.multibase(rng.bytes(16)), amount: String(1 + rng.int(1e9)), memo: `round ${r}` };
    const sig = S.sign(nodes.get(signer).secret, body);
    if (variant === 'amount-tampered') body.amount = String(BigInt(body.amount) + 1n);
    if (variant === 'float-amount') body.amount = 0.5;
    const p = presentation('owner');
    const { exp, obs, obj } = present('invoice-bundle', r, now, p, null);
    // Expected, from the model alone.
    const provenBinding = !exp.reject && exp.bindings.some((b) => b.proof === 'proven' && netOf(b.body.addr) === 'stagenet');
    const honestSig = variant !== 'amount-tampered' && variant !== 'float-amount' && !(variant === 'old-key' && signer !== A.owner);
    const expOk = !exp.reject && ownerIsTail() && provenBinding && honestSig && variant !== 'expired' && net === 'stagenet';
    // Observed: the payer's checks, SPEC §6.3, with the library's own primitives.
    let obsOk = false, why = '';
    try {
      if (obs.reject) throw new Error('bundle: ' + obs.reject);
      S.structure(body, 'invoice');
      if (body.did !== obs.did) throw new Error('invoice did is not the current DID');
      const g = [obj.genesis, ...obj.rotations.map((x) => x.next_genesis)].find((x) => S.did(x) === obs.did);
      if (!S.verifySig(g.key, body, sig)) throw new Error('signature');
      if (!(body.iat <= now && now < body.exp)) throw new Error('not valid now');
      if (!obs.bindings.some((b) => b.proof === 'proven' && b.body.method === 'monero' && netOf(b.body.addr) === 'stagenet')) throw new Error('no proven stagenet binding');
      const d = decodeAddress(body.addr);
      if (d.kind !== 'subaddress' || d.net !== 'stagenet') throw new Error('addr is not a stagenet subaddress');
      obsOk = true;
    } catch (e) { why = String(e.message ?? e); }
    count(`invoice:${variant}:${obsOk ? 'payable' : 'refused'}`);
    if (expOk !== obsOk) finding('invoice', r, `invoice ${variant}`, expOk ? 'payable' : 'refused', obsOk ? 'payable' : `refused (${why})`);
    // The keeper's own policy library (spend/policy.js evaluate) must reach the same verdict.
    if (env.evaluate && exp.attestations && Object.keys(exp.attestations).length) {
      const issuer = Object.keys(exp.attestations)[0];
      const policy = env.policyFor(issuer);
      const d = env.evaluate({ token: 'sim-payer-token', to: { addr, did: A.owner, bundle: obj, invoice: { body, sig } }, amount: typeof body.amount === 'string' ? body.amount : '1', purpose: 'sim' }, policy, [], now);
      const kOk = d.ok === true;
      count(`invoice-keeper:${kOk ? 'payable' : 'refused'}`);
      if (kOk !== expOk) finding('invoice-keeper', r, `spend evaluate() on invoice ${variant}`, expOk ? 'payable' : 'refused', kOk ? 'payable' : `refused (${d.reason})`);
    }
  }

  // --- tampering: every variant states its expected outcome from the model
  function tamper(r, now) {
    const p = presentation(A.thief && rng.chance(0.3) ? 'thief' : 'owner');
    const world = rng.pick(worlds);
    const nA = p.atts.length, nB = p.bindings.length, nR = p.rotations.length;
    const table = [
      ['att-body-mutated', nA ? 3 : 0], ['att-wrong-typ', nA ? 2 : 0], ['att-float', nA ? 2 : 0], ['att-big-int', nA ? 1 : 0],
      ['att-exponent', nA ? 1 : 0], ['att-unknown-v', nA ? 2 : 0], ['att-lone-surrogate', nA ? 1 : 0], ['att-missing-sig', nA ? 1 : 0],
      ['att-unknown-field', nA ? 1 : 0], ['att-issuer-omitted', nA ? 2 : 0], ['challenge-as-attestation', 2], ['att-null', 1],
      ['bind-addr-swapped', nB ? 2 : 0], ['bind-unproven', nB ? 1 : 0], ['bind-garbage-proof', nB ? 1 : 0],
      ['bind-integrated', ownerIsTail() ? 1 : 0], ['bind-mainnet', ownerIsTail() ? 1 : 0], ['bind-subaddr-view-signed', ownerIsTail() ? 1 : 0],
      ['dup-key-top', 2], ['dup-key-att', nA ? 1 : 0], ['proto-key', nA ? 1 : 0], ['invalid-utf8', 1], ['genesis-wrong-typ', 1], ['genesis-float', 1],
      ['rotation-float-iat', nR ? 1 : 0], ['rotation-unknown-v', nR ? 1 : 0], ['rotation-missing-next-genesis', nR ? 1 : 0],
      ['rotation-missing-sig', nR ? 1 : 0], ['rotation-typ-attestation', nR ? 1 : 0], ['issuer-malformed', p.issuers.length ? 1 : 0],
      ['bundle-unknown-field', 1], ['bundle-unknown-v', 1], ['cycle', p.fatal || p.chain.length < 2 ? 0 : 2], ['recovery-tie', !p.fatal && A.pubCommit ? 2 : 0],
      ['recovery-low-iat', !p.fatal && A.pubCommit ? 1 : 0], ['rotation-bad-sig', p.fatal ? 0 : 2], ['rotation-next-mismatch', p.fatal ? 0 : 1],
      ['voluntary-changes-commitment', p.fatal ? 0 : 2], ['stale-recovery-key', !p.fatal && recGen > 0 ? 2 : 0],
      ['rotation-mutated', !p.fatal && A.clean && nR ? 2 : 0], ['rotations-shuffled', nR > 1 ? 1 : 0],
    ];
    const v = rng.weighted(table);
    const ai = nA ? rng.int(nA) : 0, bi = nB ? rng.int(nB) : 0, ri = nR ? rng.int(nR) : 0;
    const X = p.fatal ? null : p.chain[p.chain.length - 1];
    const tailNode = X && nodes.get(X);
    const fatal = (cls) => { p.fatal = cls; };
    const rot = (from, next, iat, reason, secret, extra = {}) => {
      const body = { v: S.VERSION, typ: 'rotation', id: S.did(from), next: S.did(next), iat, reason, ...extra };
      return { body, sig: S.sign(secret, body), next_genesis: next };
    };
    const fresh = (tag, rec) => mkGenesis(kdf(simRoot, `sim/tamper/${i}/${r}/${tag}`), rec, now);
    switch (v) {
      case 'att-body-mutated': p.atts[ai].env.body.claims.level = (p.atts[ai].env.body.claims.level ?? 0) + 1; p.atts[ai].bad = true; break;
      case 'att-wrong-typ': p.atts[ai].env.body.typ = 'binding'; p.atts[ai].bad = true; break;
      case 'att-float': p.atts[ai].env.body.claims.score = '@@FLOAT@@'; p.atts[ai].bad = true; break;
      case 'att-big-int': p.atts[ai].env.body.claims.score = '@@BIG@@'; p.atts[ai].bad = true; break;
      case 'att-exponent': p.atts[ai].env.body.claims.score = '@@EXP@@'; p.atts[ai].bad = true; break;
      case 'att-unknown-v': p.atts[ai].env.body.v = 'sigelo/1'; p.atts[ai].bad = true; break;
      case 'att-lone-surrogate': p.atts[ai].env.body.claims.note = 'x\ud800y'; p.atts[ai].bad = true; break;
      case 'att-missing-sig': delete p.atts[ai].env.sig; p.atts[ai].bad = true; break;
      case 'att-unknown-field': p.atts[ai].env.body.karma = 7; p.atts[ai].bad = true; break;
      case 'att-issuer-omitted': { const d = p.atts[ai].iss; p.issuers = p.issuers.filter((g) => S.did(g) !== d); break; } // expectation: resolvable only via a local copy
      case 'challenge-as-attestation': { // a signed challenge replayed into the attestation slot (typ is checked against the slot)
        const holds = p.fatal ? A.owner : X;
        const c = S.challenge({ secret: nodes.get(holds).secret, genesis: nodes.get(holds).genesis, ctx: world.ctx, nonce: S.multibase(rng.bytes(16)) });
        p.atts.push({ env: c, iss: 'x', sub: 'x', iat: 0, exp: 0, bad: true }); break;
      }
      case 'att-null': p.atts.push({ env: null, iss: 'x', sub: 'x', iat: 0, exp: 0, bad: true }); break;
      case 'bind-addr-swapped': p.bindings[bi].env.body.addr = walletFromRoot(simRoot, `counterparty/${(i + 1) % cfg.agents}`, 'stagenet').address; p.bindings[bi].bad = true; break;
      case 'bind-unproven': if (p.bindings[bi].proof !== 'bad') { delete p.bindings[bi].env.sig_addr; p.bindings[bi].proof = 'unproven'; } break;
      case 'bind-garbage-proof': p.bindings[bi].env.sig_addr = p.bindings[bi].env.sig_id; p.bindings[bi].proof = 'bad'; break;
      case 'bind-integrated': case 'bind-mainnet': case 'bind-subaddr-view-signed': {
        // §6.2: an integrated spelling reuses the base signature but is not accepted; a mainnet
        // spelling is PROVEN (the hash does not cover the prefix — the payer checks the net);
        // a subaddress signed with the base address's view keys is discarded.
        const addr = v === 'bind-integrated' ? encodeAddress({ net: 'stagenet', kind: 'integrated', spend: view.B, view: viewPub, paymentId: rng.bytes(8) })
          : v === 'bind-mainnet' ? encodeAddress({ net: 'mainnet', kind: 'standard', spend: view.B, view: viewPub })
            : subaddress({ a: view.a, B: view.B, major: 0, minor: 1 + rng.int(50), net: 'stagenet' });
        const body = { v: S.VERSION, typ: 'binding', id: X, method: 'monero', addr, iat: now, exp: now + DAY, nonce: S.multibase(rng.bytes(16)) };
        const sig_addr = sigeloMoneroSigAddr(body, { mode: 'view', secret: view.a, spendPub: view.B, viewPub, nonce: rng.bytes(32) });
        p.bindings.push({ env: { body, sig_id: S.sign(tailNode.secret, body), sig_addr }, id: X, iat: now, exp: now + DAY, bad: false, proof: v === 'bind-mainnet' ? 'proven' : 'bad' });
        break;
      }
      case 'dup-key-top': p.textMut = (t) => t.replace('"typ":"bundle"', '"typ":"bundle","typ":"bundle"'); fatal('parse'); break;
      case 'dup-key-att': p.textMut = (t) => t.replace(/"ctx":"world-/, '"ctx":"dup","ctx":"world-'); fatal('parse'); break;
      case 'proto-key': p.textMut = (t) => t.replace('"claims":{', '"claims":{"__proto__":{},'); fatal('parse'); break;
      // SPEC §3: invalid UTF-8 anywhere rejects the whole document. Into the genesis nonce, where a
      // lossy decode (U+FFFD) used to verify as a different, VALID identity.
      case 'invalid-utf8': { const raw = rng.pick(INVALID_UTF8); p.byteMut = (b) => spliceBytes(b, '"nonce":"z', raw); fatal('parse'); break; }
      case 'genesis-wrong-typ': p.genesis.typ = 'rotation'; fatal('structure'); break;
      case 'genesis-float': p.genesis.created = '@@FLOAT@@'; fatal('structure'); break;
      case 'rotation-float-iat': p.rotations[ri].body.iat = '@@FLOAT@@'; fatal('structure'); break;
      case 'rotation-unknown-v': p.rotations[ri].body.v = 'sigelo/9'; fatal('structure'); break;
      case 'rotation-missing-next-genesis': delete p.rotations[ri].next_genesis; fatal('structure'); break;
      case 'rotation-missing-sig': delete p.rotations[ri].sig; fatal('structure'); break;
      case 'rotation-typ-attestation': p.rotations[ri].body.typ = 'attestation'; fatal('structure'); break;
      case 'issuer-malformed': p.issuers[rng.int(p.issuers.length)].v = 'sigelo/7'; fatal('structure'); break;
      case 'bundle-unknown-field': p.bundleMut = (b) => { b.trust_score = 99; }; fatal('structure'); break;
      case 'bundle-unknown-v': p.bundleMut = (b) => { b.v = 'sigelo/1'; }; fatal('structure'); break;
      case 'cycle': {
        // The tail key holder rotates back to a genesis already in the chain. It is a candidate
        // only if that genesis carries the governing commitment; then it is a cycle (fatal).
        const target = p.chain.slice(0, -1).map((d) => nodes.get(d).genesis).filter((g) => g.recovery === p.recovery);
        const g = target.length ? rng.pick(target) : nodes.get(p.chain[0]).genesis;
        p.rotations.push(rot(tailNode.genesis, g, now, 'voluntary', tailNode.secret));
        if (target.length) fatal('cycle');
        break;
      }
      case 'recovery-tie': {
        const a = fresh('tie-a', p.recovery), b = fresh('tie-b', p.recovery);
        const rk = recoveryPublicKey(recRoot(recGen)), rs = recoverySeed(recRoot(recGen));
        p.rotations.push(rot(tailNode.genesis, a.genesis, now, 'recovery', rs, { recovery_key: rk }), rot(tailNode.genesis, b.genesis, now, 'recovery', rs, { recovery_key: rk }));
        fatal('tie'); break;
      }
      case 'recovery-low-iat': {
        const a = fresh('low', p.recovery);
        p.rotations.push(rot(tailNode.genesis, a.genesis, 1, 'recovery', recoverySeed(recRoot(recGen)), { recovery_key: recoveryPublicKey(recRoot(recGen)) }));
        p.chain = [...p.chain, a.did]; break;
      }
      case 'rotation-bad-sig': { const a = fresh('badsig', p.recovery); p.rotations.push(rot(tailNode.genesis, a.genesis, now, 'voluntary', a.secret)); break; }
      case 'rotation-next-mismatch': { const a = fresh('nm-a', p.recovery), b = fresh('nm-b', p.recovery); const x = rot(tailNode.genesis, a.genesis, now, 'voluntary', tailNode.secret); x.next_genesis = b.genesis; p.rotations.push(x); break; }
      case 'voluntary-changes-commitment': { const a = fresh('vcc', recoveryCommitment(kdf(simRoot, `sim/tamper/${i}/${r}/x`))); p.rotations.push(rot(tailNode.genesis, a.genesis, now, 'voluntary', tailNode.secret)); break; }
      case 'stale-recovery-key': { const a = fresh('stale', p.recovery); p.rotations.push(rot(tailNode.genesis, a.genesis, now, 'recovery', recoverySeed(recRoot(recGen - 1)), { recovery_key: recoveryPublicKey(recRoot(recGen - 1)) })); break; }
      case 'rotation-mutated': {
        // A clean chain has exactly one rotation per node, so breaking one signature ends the
        // chain at its `id`: later DIDs, and whatever was issued to them, fall away.
        const x = p.rotations[ri]; x.body.iat += 1;
        p.chain = p.chain.slice(0, p.chain.indexOf(x.body.id) + 1);
        p.recovery = nodes.get(p.chain[p.chain.length - 1]).genesis.recovery; break;
      }
      case 'rotations-shuffled': for (let k2 = p.rotations.length - 1; k2 > 0; k2--) { const j = rng.int(k2 + 1); [p.rotations[k2], p.rotations[j]] = [p.rotations[j], p.rotations[k2]]; } break;
    }
    count(`tamper:${v}`);
    present(`tamper:${v}`, r, now, p, world, true);
  }

  // --- fuzz: blind mutations with no model expectation. The oracle is the other
  // implementation (Go, byte for byte) and the rule that ts never throws anything but a named
  // SigeloError/JcsError — a RangeError or TypeError is a crash, not a check.
  function fuzz(r, now) {
    const p = presentation(A.thief && rng.chance(0.3) ? 'thief' : 'owner');
    const obj = JSON.parse(serializeText(bundleOf(p)));
    const paths = [];
    const walk = [[obj, []]];
    while (walk.length) {
      const [v, path] = walk.pop();
      if (path.length) paths.push(path);
      if (v && typeof v === 'object') for (const k of Object.keys(v)) walk.push([v[k], [...path, Array.isArray(v) ? Number(k) : k]]);
    }
    const ops = [];
    const n = 1 + rng.int(3);
    for (let m = 0; m < n; m++) {
      const path = rng.pick(paths);
      const parent = path.slice(0, -1).reduce((o, k) => (o == null ? o : o[k]), obj);
      if (parent == null || typeof parent !== 'object') continue;
      const key = path[path.length - 1];
      const op = rng.pick(['delete', 'null', 'zero', 'neg', 'maxint', 'empty-string', 'array', 'object', 'true', 'string', 'dup-elem', 'wrap', 'unicode', 'nul-char', 'swap', 'long']);
      ops.push(op);
      const set = (x) => { parent[key] = x; };
      switch (op) {
        case 'delete': if (Array.isArray(parent)) parent.splice(key, 1); else delete parent[key]; break;
        case 'null': set(null); break;
        case 'zero': set(0); break;
        case 'neg': set(-1 - rng.int(1000)); break;
        case 'maxint': set(9007199254740991); break;
        case 'empty-string': set(''); break;
        case 'array': set([]); break;
        case 'object': set({}); break;
        case 'true': set(true); break;
        case 'string': set('z' + S.multibase(rng.bytes(8)).slice(1)); break;
        case 'dup-elem': if (Array.isArray(parent)) parent.splice(key, 0, structuredClone(parent[key])); else set(structuredClone(parent[key])); break;
        case 'wrap': set([parent[key]]); break;
        case 'unicode': set(typeof parent[key] === 'string' ? parent[key] + '\u2028𝄞' : '\u2029'); break;
        case 'nul-char': set(typeof parent[key] === 'string' ? parent[key] + '\u0000' : '\u007f'); break;
        case 'swap': if (Array.isArray(parent) && parent.length > 1) { const j = rng.int(parent.length); [parent[key], parent[j]] = [parent[j], parent[key]]; } break;
        case 'long': set('x'.repeat(10000 + rng.int(50000))); break;
      }
    }
    let text = JSON.stringify(obj);
    const top = rng.pick(['none', 'none', 'deep', 'escaped-key', 'escaped-dup-key', 'bom', 'minus-zero', 'one-point-zero', 'whitespace', 'dot-escape', 'upper-hex', 'surrogate-escape', 'trailing-ws', 'invalid-utf8']);
    if (top !== 'none') ops.push(top);
    const d = 500 + rng.int(20000);
    switch (top) {
      case 'deep': text = text.replace(rng.chance(0.5) ? /"claims":\{(\}?)/ : /"bindings":\[(\]?)/, (m, end) => m.slice(0, m.length - end.length) + (m[m.length - 1 - end.length] === '{' ? '"deep":' : '') + '['.repeat(d) + ']'.repeat(d) + (end || ',')); break;
      case 'escaped-key': text = text.replace('"typ":', '"\\u0074yp":'); break;
      case 'escaped-dup-key': text = text.replace('"typ":"bundle"', '"typ":"bundle","\\u0074yp":"bundle"'); break;
      case 'bom': text = '\ufeff' + text; break;
      case 'minus-zero': text = text.replace(/"iat":\d+/, '"iat":-0'); break;
      case 'one-point-zero': text = text.replace(/"(iat|exp)":(\d+)/, '"$1":$2.0'); break;
      case 'whitespace': text = text.replace(/,/g, (m) => rng.chance(0.2) ? ' ,\n\t' : m); break;
      case 'dot-escape': text = text.replace(/"ctx":"world-(\d+)\.sim"/, '"ctx":"world-$1\\u002esim"'); break;
      case 'upper-hex': text = text.replace(/"ctx":"w/, '"ctx":"\\u0077'); break;
      case 'surrogate-escape': text = text.replace(/"role":"/, '"role":"\\ud834\\udd1e'); break;
      case 'trailing-ws': text += ' \n'; break;
    }
    let bytes = utf8Bytes(text);
    // Byte-level: raw invalid UTF-8 inside a string somewhere, which no JS string can carry.
    if (top === 'invalid-utf8') bytes = spliceBytes(bytes, rng.pick(['"nonce":"', '"ctx":"', '"sig":"', '"v":"']), rng.pick(INVALID_UTF8));
    text = bytes;
    seq++;
    const { res } = observe(bytes, now, undefined);
    const label = ops.join('+') || 'noop';
    count(`fuzz:${res.reject ? 'REJECT-' + res.reject : 'accept'}`);
    if (res.reject === 'crash') finding('fuzz', r, `ts verify threw an unnamed error (${label})`, 'a result or a named SigeloError/JcsError', res.message, text);
    const name = `a${i}-${seq}.json`;
    writeFileSync(join(OUT, 'diff', name), text);
    ev.diffs.push({ file: name, now, kind: `fuzz:${label}`, ts: res.reject ? { reject: res.reject, message: res.message } : S.canonicalize(res) });
  }

  // --- the rounds
  const initialBind = rng.chance(0.7);
  for (let r = 0; r < cfg.rounds; r++) {
    const now = T0 + r * DAY + 3600;
    if (r === 0 && initialBind) { bindNow(now, rng.chance(0.9)); count('bind'); }
    // The thief, while it holds a live branch, acts on its own.
    if (A.thief && A.fatal === null) {
      const t = rng.weighted([['join', 0.4], ['extend', 0.2], ['idle', 0.4]]);
      if (t === 'join') admission('thief-join', r, now, rng.pick(worlds), 'thief');
      if (t === 'extend' && A.pubChain[A.pubChain.length - 1] === A.thief.tail) {
        const cur = nodes.get(A.thief.tail);
        const nid = mkGenesis(kdf(simRoot, `sim/thief/${i}/${r}/x`), A.pubCommit, now);
        nodes.set(nid.did, { genesis: nid.genesis, secret: nid.secret });
        publish(S.rotate({ genesis: cur.genesis, next_genesis: nid.genesis, iat: now, reason: 'voluntary', secret: cur.secret }), 'thief');
        A.pubChain.push(nid.did); A.thief.tail = nid.did; count('thief:extend');
      }
    }
    let act;
    if (A.fatal === 'fork') act = A.pubCommit !== null && rng.chance(0.8) ? 'recover' : 'join';
    else if (A.thief) act = A.pubCommit !== null ? rng.weighted([['recover', 0.55], ['rotate', 0.25], ['join', 0.2]]) : rng.weighted([['rotate', 0.3], ['join', 0.3], ['idle', 0.4]]);
    else act = rng.weighted([['join', 0.2], ['migrate', 0.17], ['rotate', 0.06], ['robbed', 0.025], ['recover', 0.01], ['bind', 0.04], ['invoice', 0.06], ['tamper', 0.14], ['fuzz', 0.06], ['idle', 0.235]]);
    if (act === 'recover' && A.pubCommit === null) act = 'idle';
    count(`act:${act}`);
    switch (act) {
      case 'join': case 'migrate': {
        const pool = worlds.filter((w) => act === 'migrate' ? !A.worlds.has(w.j) && A.worlds.size > 0 : !A.worlds.has(w.j));
        if (pool.length) admission(act, r, now, rng.pick(pool), 'owner');
        break;
      }
      case 'rotate': ownerRotate(r, now); break;
      case 'robbed': steal(r, now); break;
      case 'recover': recover(r, now); break;
      case 'bind': if (ownerIsTail()) { bindNow(now, rng.chance(0.9)); count('bind'); } break;
      case 'invoice': invoice(r, now); break;
      case 'tamper': tamper(r, now); break;
      case 'fuzz': fuzz(r, now); break;
    }
  }
  return ev;
}

// ---------------------------------------------------------------- worker / main

async function envFor(cfg) {
  const simRoot = kdf(createHash('sha256').update(`sigelo-sim-root\n${cfg.seed}`).digest(), 'sim/root');
  const { worlds, known } = makeWorlds(cfg, simRoot);
  const e = { simRoot, K: keeperRoot(simRoot, 0), worlds, known };
  try {
    const P = await import('../spend/dist/policy.js');
    e.evaluate = P.evaluate;
    const cache = new Map();
    e.policyFor = (issuer) => {
      if (!cache.has(issuer)) cache.set(issuer, P.parsePolicy({ net: 'stagenet', unlock_time: 0, priority: 0, wallet: { rpc: 'http://127.0.0.1:39999/json_rpc' }, agents: {
        payer: { account: 1, per_tx_max: '1000000000000', per_period_max: '100000000000000', period_seconds: 86400, rate_per_minute: 1000000,
          token_hash: P.tokenHash('sim-payer-token'), allow: [{ issuer }] } } }));
      return cache.get(issuer);
    };
  } catch (err) { e.evaluateError = String(err); }
  return e;
}

function merge(into, ev) {
  for (const [k, v] of Object.entries(ev.counts)) into.counts[k] = (into.counts[k] ?? 0) + v;
  // Loops, not push(...list): a spread is one argument per element and overflows the stack on a large list.
  for (const f of ev.findings) into.findings.push(f);
  for (const d of ev.diffs) into.diffs.push(d);
  into.verifies += ev.verifies; into.verifyMs += ev.verifyMs;
  into.maxChain = Math.max(into.maxChain, ev.maxChain); into.maxRotations = Math.max(into.maxRotations, ev.maxRotations);
}
const empty = () => ({ counts: {}, findings: [], diffs: [], verifies: 0, verifyMs: 0, maxChain: 0, maxRotations: 0 });

async function runShard(cfg, agents) {
  const env = await envFor(cfg);
  const acc = empty();
  for (const i of agents) {
    try { merge(acc, simulateAgent(i, cfg, env)); } catch (e) {
      acc.findings.push({ agent: i, kind: 'crash', what: 'simulation threw', observed: String(e?.stack ?? e),
        repro: `node sim/swarm.mjs --seed ${JSON.stringify(cfg.seed)} --agents ${cfg.agents} --worlds ${cfg.worlds} --rounds ${cfg.rounds} --only-agent ${i}` });
    }
  }
  acc.evaluate = env.evaluate ? 'spend/dist/policy.js' : `unavailable: ${env.evaluateError}`;
  return acc;
}

function goVerify(bin, file, now) {
  return new Promise((resolve) => {
    execFile(bin, [join(OUT, 'diff', file), '--now', String(now)], { maxBuffer: 1 << 26 }, (err, stdout, stderr) => {
      if (!err) resolve({ out: stdout.trim() });
      else if (err.code === 1 && /^REJECT: /.test(stderr)) resolve({ reject: stderr.trim().slice(8) });
      else resolve({ error: `${err.code}: ${stderr.trim() || err.message}` });
    });
  });
}
const rejectClass = (m) => /fork/.test(m) ? 'fork' : /cycle/.test(m) ? 'cycle' : /recovery tie/.test(m) ? 'tie' : /^parse/.test(m) ? 'parse' : 'structure';

async function differential(cfg, diffs, findings) {
  const bin = join(OUT, process.platform === 'win32' ? 'sigelo-verify.exe' : 'sigelo-verify');
  execFileSync('go', ['build', '-o', bin, './cmd/sigelo-verify'], { cwd: join(ROOT, 'go'), stdio: 'inherit' });
  const stats = { compared: 0, identical: 0, bothRejected: 0, classDiffers: 0, mismatches: 0 };
  let next = 0;
  const lanes = Math.max(2, availableParallelism());
  await Promise.all(Array.from({ length: lanes }, async () => {
    while (next < diffs.length) {
      const d = diffs[next++];
      const g = await goVerify(bin, d.file, d.now);
      stats.compared++;
      const rel = relative(ROOT, join(OUT, 'diff', d.file));
      const repro = `(cd go && go run ./cmd/sigelo-verify ../${rel} --now ${d.now})  vs  node sim/verify-one.mjs ${rel} ${d.now}`;
      if (g.error) { stats.mismatches++; findings.push({ kind: 'differential', what: `go error on ${d.kind}`, expected: typeof d.ts === 'string' ? d.ts : d.ts.message, observed: g.error, file: rel, repro }); continue; }
      if (typeof d.ts === 'string' && g.out !== undefined) {
        if (g.out === d.ts) stats.identical++;
        else { stats.mismatches++; findings.push({ kind: 'differential', what: `${d.kind}: §9.1 result differs`, expected: `ts ${d.ts}`, observed: `go ${g.out}`, file: rel, repro }); }
      } else if (typeof d.ts !== 'string' && g.reject !== undefined) {
        stats.bothRejected++;
        const gc = rejectClass(g.reject);
        if (gc !== d.ts.reject) { stats.classDiffers++; findings.push({ kind: 'differential-reason', what: `${d.kind}: both reject, for different checks`, expected: `ts ${d.ts.reject}: ${d.ts.message}`, observed: `go ${gc}: ${g.reject}`, file: rel, repro }); }
      } else {
        stats.mismatches++;
        findings.push({ kind: 'differential', what: `${d.kind}: one accepts, one rejects`, expected: `ts ${typeof d.ts === 'string' ? d.ts : 'REJECT ' + d.ts.message}`, observed: `go ${g.out ?? 'REJECT ' + g.reject}`, file: rel, repro });
      }
    }
  }));
  return stats;
}

async function main() {
  const cfg = config(process.argv.slice(2), process.env);
  const t0 = Date.now();
  if (cfg.onlyAgent === undefined) rmSync(OUT + '/diff', { recursive: true, force: true });
  rmSync(OUT + '/findings', { recursive: true, force: true });
  mkdirSync(join(OUT, 'diff'), { recursive: true });
  const ids = cfg.onlyAgent !== undefined ? [cfg.onlyAgent] : Array.from({ length: cfg.agents }, (_, i) => i);
  const W = Math.min(cfg.workers, ids.length);
  const shards = Array.from({ length: W }, (_, w) => ids.filter((_, n) => n % W === w));
  process.stderr.write(`swarm: seed ${JSON.stringify(cfg.seed)}, ${ids.length} agents, ${cfg.worlds} worlds, ${cfg.rounds} rounds, ${W} workers\n`);
  const results = await Promise.all(shards.map((agents) => new Promise((resolve, reject) => {
    const w = new Worker(fileURLToPath(import.meta.url), { workerData: { cfg, agents } });
    w.once('message', resolve); w.once('error', reject);
  })));
  const all = empty();
  for (const r of results) merge(all, r);
  all.findings.sort((a, b) => (a.agent ?? 0) - (b.agent ?? 0) || (a.round ?? 0) - (b.round ?? 0) || (a.seq ?? 0) - (b.seq ?? 0));
  const simMs = Date.now() - t0;
  all.diffs.sort((a, b) => a.file < b.file ? -1 : 1);
  let diff = { skipped: 'go not available or --no-go' };
  if (cfg.go) {
    try { diff = await differential(cfg, all.diffs, all.findings); } catch (e) { diff = { skipped: String(e.message ?? e) }; }
  }
  const counts = Object.fromEntries(Object.entries(all.counts).sort());
  const summary = {
    config: cfg, wall_ms: Date.now() - t0, sim_ms: simMs, verifies: all.verifies, verify_ms_total: Math.round(all.verifyMs),
    max_chain: all.maxChain, max_rotations_in_bundle: all.maxRotations, keeper_library: results[0]?.evaluate,
    differential: diff, findings: all.findings.length, counts,
  };
  // A digest over everything seed-determined, so two runs with one seed can be compared.
  summary.digest = createHash('sha256').update(JSON.stringify([counts, all.findings.map((f) => [f.agent, f.round, f.kind, f.what, f.expected, f.observed]), all.diffs.map((d) => [d.file, d.ts])])).digest('hex').slice(0, 16);
  writeFileSync(join(OUT, 'swarm-summary.json'), JSON.stringify(summary, null, 1));
  writeFileSync(join(OUT, 'swarm-findings.json'), JSON.stringify(all.findings, null, 1));
  for (const f of all.findings.slice(0, 40)) process.stderr.write(`FINDING ${f.kind} a${f.agent ?? '-'} r${f.round ?? '-'}: ${f.what}\n  expected ${String(f.expected).slice(0, 400)}\n  observed ${String(f.observed).slice(0, 400)}\n  repro: ${f.repro}${f.file ? `  (bytes: ${f.file})` : ''}\n`);
  console.log(JSON.stringify({ ...summary, counts: undefined, config: undefined, seed: cfg.seed, agents: ids.length, worlds: cfg.worlds, rounds: cfg.rounds }));
  process.exitCode = all.findings.length ? 1 : 0;
}

if (isMainThread) await main();
else parentPort.postMessage(await runShard(workerData.cfg, workerData.agents));
