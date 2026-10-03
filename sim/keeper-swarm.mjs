// SPDX-License-Identifier: MIT
// sim/keeper-swarm.mjs — a swarm of agents hammering ONE spend/ keeper (MONERO.md §4) that runs
// as a real `sigelo-spend serve` child process against sim/mock-wallet.mjs, a wallet-rpc
// stand-in that keeps books. The keeper is SIGKILLed and SIGTERMed mid-run and restarted on the
// same directory. Every request records expected-vs-observed; afterwards the keeper's spend.log
// is audited against the mock wallet's ground truth. Any mismatch is a finding.
//
//   node sim/keeper-swarm.mjs [--seed S] [--agents K] [--flows F] [--concurrency C] [--port P] [--no-chaos] [--keep]
//   env: SIM_SEED, SIM_AGENTS, SIM_FLOWS, SIM_CONCURRENCY, SIM_PORT
//
// Needs ts/dist and spend/dist (`cd ts && npx tsc`, `cd spend && npx tsc`). Loopback only, ports
// ≥ 39000 (default 39100 mock, 39101 keeper), state in a fresh mkdtemp directory. It never
// touches a real monero-wallet-rpc. The keeper is licensed (pro) by a throwaway test vendor
// (sim/licence.mjs); keeper-scenarios.mjs checks the unlicensed refusals.
//
// Determinism: the seed fixes every identity, policy, amount and the whole flow plan (which
// agent does what, in what order, with which ref). Outcomes that depend on wall-clock timing —
// which of two racing approvals lands first, where a SIGKILL falls, the keeper's per-minute rate
// window — can differ between runs of one seed; the invariants must hold on every run.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { attest, bind, keygen, multibase, sign, verify, verifySig } from '../ts/dist/sigelo.js';
import { deriveIdentity, recoveryCommitment, walletFromRoot } from '../ts/dist/keys.js';
import { sigeloMoneroSigAddr, subaddress } from '../ts/dist/monero.js';
import { readLog } from '../spend/dist/service.js';
import { tokenHash } from '../spend/dist/policy.js';
import { startMockWallet } from './mock-wallet.mjs';
import { installLicence, keyKeeper, testVendor } from './licence.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const argv = process.argv.slice(2);
const opt = (name, env, dflt) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : process.env[env] ?? dflt;
};
const SEED = String(opt('seed', 'SIM_SEED', 'sigelo-sim'));
const K = Number(opt('agents', 'SIM_AGENTS', 50));
const FLOWS = Number(opt('flows', 'SIM_FLOWS', K * 16));
const CONC = Number(opt('concurrency', 'SIM_CONCURRENCY', 16));
const PORT = Number(opt('port', 'SIM_PORT', 39100));
const CHAOS = !argv.includes('--no-chaos');
const KEEP = argv.includes('--keep');
const SELFTEST = argv.includes('--selftest') || process.env.SIM_SELFTEST === '1';
if (!(PORT >= 39000)) throw new Error('--port must be ≥ 39000 (38083 and 38200 belong to the live soak)');
const NET = 'stagenet';
const FEE = 30480000n;
const T0 = Date.now();

// ---------------------------------------------------------------- seeded PRNG (sfc32 from SHA-256)
function prng(label) {
  const h = createHash('sha256').update(`${SEED}/${label}`).digest();
  let [a, b, c, d] = [h.readUInt32LE(0), h.readUInt32LE(4), h.readUInt32LE(8), h.readUInt32LE(12)];
  const next = () => {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    const t = (a + b) | 0; a = b ^ (b >>> 9); b = (c + (c << 3)) | 0; c = (c << 21) | (c >>> 11); d = (d + 1) | 0;
    const r = (t + d) | 0; c = (c + r) | 0;
    return (r >>> 0) / 4294967296;
  };
  for (let i = 0; i < 16; i++) next();
  return next;
}
const R = prng('plan');
const int = (lo, hi) => lo + Math.floor(R() * (hi - lo + 1));
const pick = (xs) => xs[Math.floor(R() * xs.length)];
const bytes = (n = 32) => Uint8Array.from({ length: n }, () => Math.floor(R() * 256));
const hex = (b) => Buffer.from(b).toString('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- the world the agents live in
const nowS = () => Math.floor(Date.now() / 1000);
const vendors = Array.from({ length: 6 }, (_, i) => walletFromRoot(bytes(), `vendor/${i}`, NET).address);
const stranger = walletFromRoot(bytes(), 'stranger', NET).address;
const mainnetAddr = walletFromRoot(bytes(), 'elsewhere', 'mainnet').address;
const world = keygen({ recovery: bytes(), seed: bytes() });
const CTX = 'sim.world';
const payees = Array.from({ length: 4 }, (_, i) => {
  const root = bytes();
  const id = deriveIdentity(root, 0);
  const w = walletFromRoot(root, 'treasury', NET);
  const t = nowS();
  const b = bind({ secret: id.secret, id: id.did, method: 'monero', addr: w.address, iat: t - 3600, exp: t + 3 * 86400, nonce: bytes(16) });
  const binding = { ...b, sig_addr: sigeloMoneroSigAddr(b.body, { mode: 'view', secret: w.a, spendPub: w.B, viewPub: w.A, nonce: bytes() }) };
  const attestation = attest({ secret: world.secret, iss: world.did, sub: id.did, iat: t - 3600, exp: t + 3 * 86400, ctx: CTX, admission: 'open', claims: { role: 'vendor', n: i } });
  const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: id.genesis, rotations: [], bindings: [binding], attestations: [attestation], issuers: [world.genesis] };
  let minor = 0;
  return { i, id, w, bundle, nextSub: () => subaddress({ a: w.a, B: w.B, major: 0, minor: ++minor, net: NET }) };
});
const approvers = [keygen({ recovery: bytes(), seed: bytes() }), keygen({ recovery: bytes(), seed: bytes() })];
const outsider = keygen({ recovery: bytes(), seed: bytes() });
const idBundle = (g) => ({ v: 'sigelo/0', typ: 'bundle', genesis: g, rotations: [], bindings: [], attestations: [], issuers: [] });
const REC = recoveryCommitment(bytes());
const MAX_TTL = 30;

const agents = [];
const balances = { 0: 0n };
for (let i = 0; i < K; i++) {
  const perTx = pick([2_000_000_000n, 5_000_000_000n, 10_000_000_000n]);
  const id = keygen({ recovery: bytes(), seed: bytes() });
  const lits = [...new Set(Array.from({ length: int(1, 3) }, () => int(0, vendors.length - 1)))];
  const allow = lits.map((v) => ({ label: `v${v}`, addr: vendors[v] }));
  const issuerRule = R() < 0.4;
  if (issuerRule) allow.push({ issuer: world.did, ctx: CTX });
  const a = {
    name: `ag${String(i).padStart(3, '0')}`, account: i + 1, token: hex(bytes()), id, lits, issuerRule,
    per_tx_max: perTx, per_period_max: perTx * BigInt(int(3, 8)), rate_per_minute: pick([4, 10, 30, 60]), period_seconds: R() < 0.25 ? 30 : 86400,
    approval_above: R() < 0.3 ? perTx / 2n : null, max_delegates: R() < 0.25 ? 2 : 0, allow,
    delegates: [], liveDelegates: 0,
  };
  balances[a.account] = R() < 0.1 ? perTx * 3n : 1_000_000_000_000_000n;
  agents.push(a);
}
const probe = { name: 'probe', account: K + 1, token: hex(bytes()), id: keygen({ recovery: bytes(), seed: bytes() }), per_tx_max: 10n ** 13n, per_period_max: 10n ** 15n, period_seconds: 86400,
  rate_per_minute: 100000, approval_above: null, max_delegates: 0, allow: [{ label: 'v0', addr: vendors[0] }], lits: [0], issuerRule: false, delegates: [] };
balances[probe.account] = 10n ** 17n;
const byName = new Map([...agents, probe].map((a) => [a.name, a]));
const byAccount = new Map([...agents, probe].map((a) => [a.account, a]));

// ---------------------------------------------------------------- the flow plan (fully seeded)
const KINDS = {
  pay_ok: 26, pay_burst: 5, pay_over_tx: 4, pay_fee_edge: 4, pay_at_cap: 3, pay_not_allowed: 3, pay_wrong_net: 2,
  pay_dup: 6, pay_conflict: 2, pay_abort: 4, pay_did: 5, pay_invoice: 4, approval: 6, approval_late: 1,
  receive: 5, balance: 4, history: 3, bind: 2, bad_token: 2, delegate: 5, half_body: 1,
};
const bag = Object.entries(KINDS).flatMap(([k, w]) => Array(w).fill(k));
const plan = Array.from({ length: FLOWS }, (_, n) => {
  const agent = pick(agents);
  return { n, kind: pick(bag), agent: agent.name, u: R(), v: R(), w: R(), x: bytes(16) };
});
const planHash = createHash('sha256').update(JSON.stringify(plan.map((f) => [f.n, f.kind, f.agent, f.u, f.v, hex(f.x)]))).digest('hex').slice(0, 16);

// ---------------------------------------------------------------- infrastructure
const dir = mkdtempSync(join(tmpdir(), 'sigelo-sim-keeper-'));
const policyPath = join(dir, 'policy.json');
const wallet = await startMockWallet({
  net: NET, root: bytes(), balances, nextAccount: K + 2, rand: prng('chaos'), port: PORT,
  chaos: CHAOS ? { latencyMs: 15, buildError: 0.01, relayError: 0.015, relayGarbage: 0.01, fee: FEE } : { fee: FEE },
});
const agentJson = (a) => ({
  account: a.account, token_hash: tokenHash(a.token), did: a.id.did, genesis: a.id.genesis,
  per_tx_max: String(a.per_tx_max), per_period_max: String(a.per_period_max), period_seconds: a.period_seconds, rate_per_minute: a.rate_per_minute,
  allow: a.allow, ...(a.approval_above !== null && { approval_above: String(a.approval_above) }), ...(a.max_delegates > 0 && { max_delegates: a.max_delegates }),
});
writeFileSync(policyPath, JSON.stringify({
  net: NET, wallet: { rpc: `http://127.0.0.1:${wallet.port}/json_rpc` }, unlock_time: 0, priority: 1, dedupe_seconds: 600,
  max_approval_ttl: MAX_TTL, approvers: approvers.map((a) => ({ did: a.did })), recovery_commitment: REC,
  agents: Object.fromEntries([...agents, probe].map((a) => [a.name, agentJson(a)])),
}, null, 2), { mode: 0o600 });
// The policy uses delegates and approvals, paid verbs a keeper without a licence refuses 403
// licence_required (spend/licence.ts): the scratch keeper is a pro customer of a throwaway TEST
// vendor (sim/licence.mjs). Its own stream, so the seeded plan above is unchanged.
const LR = prng('licence');
const lbytes = (n) => Uint8Array.from({ length: n }, () => Math.floor(LR() * 256));
const vendor = testVendor(lbytes);
const licence = { status: await installLicence({ dir, spendDist: join(ROOT, 'spend', 'dist'), vendor,
  keeper: await keyKeeper({ dir, spendDist: join(ROOT, 'spend', 'dist'), bytes: lbytes, vendor }) }) };

const events = [];
const findings = [];
const counts = {};
const finding = (what, detail) => { findings.push({ what, detail: typeof detail === 'string' ? detail : JSON.stringify(detail).slice(0, 600) }); };

// the keeper, as a real child process
const KPORT = PORT + 1;
const keeper = { proc: null, up: false, ready: null, starts: 0, stderr: '', kills: [] };
function startKeeper() {
  keeper.starts++;
  keeper.ready = new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [join(ROOT, 'spend/dist/cli.js'), 'serve', policyPath, '--port', String(KPORT)], { stdio: ['ignore', 'pipe', 'pipe'] });
    keeper.proc = p;
    let out = '';
    p.stdout.setEncoding('utf-8'); p.stderr.setEncoding('utf-8');
    p.stdout.on('data', (c) => { out += c; if (!keeper.up && out.includes('receipts signed by')) { keeper.up = true; resolve(); } });
    p.stderr.on('data', (c) => { keeper.stderr += c; });
    p.on('exit', (code, sig) => {
      keeper.up = false;
      if (!out.includes('receipts signed by')) reject(new Error(`keeper did not start (exit ${code} ${sig}): ${keeper.stderr.slice(-800)}`));
    });
  });
  return keeper.ready;
}
async function stopKeeper(signal) {
  const p = keeper.proc;
  keeper.up = false;
  let unblock;
  keeper.ready = new Promise((r) => { unblock = r; });
  keeper.ready.unblock = unblock;
  await new Promise((r) => { p.once('exit', r); p.kill(signal); });
}

/** One HTTP call. status 0 = no answer: refused (keeper down, nothing sent), reset, timeout, abort. */
async function call(path, { method = 'GET', token, body, rawBody, timeoutMs = 60_000, abortAfter } = {}) {
  const signals = [AbortSignal.timeout(timeoutMs)];
  if (abortAfter !== undefined) signals.push(AbortSignal.timeout(abortAfter));
  const t = Date.now();
  try {
    const r = await fetch(`http://127.0.0.1:${KPORT}${path}`, {
      method, signal: AbortSignal.any(signals),
      headers: { 'Content-Type': 'application/json', ...(token === undefined ? {} : { Authorization: `Bearer ${token}` }) },
      ...(body !== undefined || rawBody !== undefined ? { body: rawBody ?? JSON.stringify(body) } : {}),
    });
    const text = await r.text();
    let j; try { j = JSON.parse(text); } catch { j = { nonjson: text.slice(0, 200) }; }
    return { status: r.status, body: j, ms: Date.now() - t };
  } catch (e) {
    const code = e?.cause?.code;
    const why = code === 'ECONNREFUSED' ? 'refused' : e?.name === 'TimeoutError' || e?.name === 'AbortError'
      ? (abortAfter !== undefined && Date.now() - t < timeoutMs - 50 ? 'abort' : 'timeout') : 'reset';
    return { status: 0, why, body: {}, ms: Date.now() - t };
  }
}
/** A call that rides out keeper restarts: a refused/reset call is sent again (same body, same ref) once the keeper is back. */
let crashRetries = 0, expiredUnderLoad = 0;
async function callR(path, o = {}) {
  let crashed = false;
  for (let i = 0; i < 6; i++) {
    const r = await call(path, o);
    if (r.status !== 0 || r.why === 'abort') return { ...r, crashed };
    if (r.why === 'timeout') { finding('queue froze: a request got no answer within 60 s', { path, body: o.body }); return { ...r, crashed }; }
    crashed = crashed || r.why === 'reset';
    crashRetries++;
    await keeper.ready; await sleep(50);
  }
  return { status: 0, why: 'gave up', body: {}, crashed };
}
const key = (r) => (r.status === 0 ? `0:${r.why}` : `${r.status}:${r.body?.code ?? ''}`);

let keeperKey = null, keeperDid = null;
const receiptsSeen = [];
const halfBodyMs = [];
function record(flow, step, r, allowed, extra = {}) {
  const obs = key(r);
  const ok = allowed.includes(obs) || (r.crashed && (obs.startsWith('502:relay_failed') || obs === '403:delegate' || obs === '401:token'));
  events.push({ flow: flow.n, kind: flow.kind, step, agent: flow.agent, expected: allowed, observed: obs, ok });
  counts[`${flow.kind}/${step}`] ??= {};
  counts[`${flow.kind}/${step}`][obs] = (counts[`${flow.kind}/${step}`][obs] ?? 0) + 1;
  if (!ok) finding(`${flow.kind}/${step}: expected ${allowed.join('|')}, observed ${obs}`, { flow: flow.n, agent: flow.agent, ...extra, body: r.body });
  if (r.status === 200 && r.body?.receipt !== undefined) receiptsSeen.push({ flow: flow.n, agent: extra.as ?? flow.agent, r: r.body });
  if (r.status === 403 && r.body?.code === 'per_period_max') {
    const f = r.body.facts;
    if (!(f && BigInt(f.cost) > BigInt(f.left ?? '0'))) finding('per_period_max refusal whose facts do not show cost > left', r.body);
  }
  return obs;
}

// the allowed outcome sets
const PAID = ['200:', '403:per_period_max', '403:rate_per_minute', '502:wallet_funds', '502:wallet', '502:relay_failed', '502:wallet_locked'];
const WAITS = ['202:approval', '403:per_period_max', '403:rate_per_minute'];
const payable = (a, amount) => (a.approval_above !== null && amount > a.approval_above ? WAITS : PAID);
const vendorOf = (a, u) => vendors[a.lits[Math.floor(u * a.lits.length)]];
const okAmount = (a, u) => BigInt(Math.max(1, Math.floor(Number(a.per_tx_max - FEE) * (0.02 + 0.5 * u))));
const pay = (tok, body, o = {}) => callR('/pay', { method: 'POST', token: tok, body, ...o });

async function approveFlow(flow, a, first) {
  const q = first.body.approval_request;
  const env = (who) => ({ body: q, sig: sign(who.secret, q), bundle: idBundle(who.genesis) });
  record(flow, 'approve_outsider', await callR('/approve', { method: 'POST', body: env(outsider) }), ['403:approval']);
  const [x, y] = await Promise.all([callR('/approve', { method: 'POST', body: env(approvers[0]) }), callR('/approve', { method: 'POST', body: env(approvers[1]) })]);
  const pair = [key(x), key(y)].sort().join(',');
  // Under load the lane can hold both approvals past the request's exp: a correct refusal, not a finding.
  if (pair === '403:approval,403:approval' && [x, y].every((r) => /not valid at/.test(r.body.error ?? '')) && nowS() >= q.exp) { expiredUnderLoad++; return false; }
  record(flow, 'approve_race', { status: pair === '200:,403:approval' ? 200 : 999, body: { pair, x: x.body, y: y.body } }, ['200:'], { pair });
  return pair === '200:,403:approval';
}

// ---------------------------------------------------------------- flows
async function runFlow(f) {
  const a = byName.get(f.agent);
  const ref = `f${f.n}`;
  const purpose = `sim flow ${f.n} ${f.kind}`;
  const tok = a.token;
  switch (f.kind) {
    case 'pay_ok': case 'pay_at_cap': {
      const amount = f.kind === 'pay_at_cap' ? a.per_tx_max - FEE : okAmount(a, f.u);
      const r = await pay(tok, { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose, ref });
      record(f, 'pay', r, payable(a, amount), { amount: String(amount) });
      if (r.status === 200 && f.v < 0.3) {
        const again = await pay(tok, { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose, ref });
        record(f, 'repeat', again, ['200:']);
        if (again.body.txid !== r.body.txid || again.body.already_paid !== true) finding('a repeat of a paid ref did not answer already_paid with the same txid', { first: r.body.txid, again: again.body });
      }
      return;
    }
    case 'pay_burst': {
      // Distinct refs, concurrently, each near per_tx: together they may exceed per_period_max.
      const amount = a.per_tx_max - FEE - BigInt(int(0, 1000));
      const rs = await Promise.all(Array.from({ length: 5 }, (_, i) => pay(tok, { to: { addr: vendorOf(a, f.u) }, amount: String(amount), purpose: `${purpose} #${i}`, ref: `${ref}-${i}` })));
      rs.forEach((r) => record(f, 'burst', r, payable(a, amount)));
      return;
    }
    case 'pay_over_tx': {
      const amount = a.per_tx_max + 1n + BigInt(Math.floor(f.u * 1e9));
      record(f, 'pay', await pay(tok, { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose, ref }), ['403:per_tx_max']);
      return;
    }
    case 'pay_fee_edge': {
      // amount ≤ per_tx_max, amount + fee > per_tx_max: must never pay (README "Both caps count amount + fee").
      const amount = a.per_tx_max - FEE + 1n;
      const allowed = ['403:per_tx_max', '403:per_period_max', '403:rate_per_minute', '502:wallet_funds', '502:wallet', ...(a.approval_above !== null ? ['202:approval'] : [])];
      record(f, 'pay', await pay(tok, { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose, ref }), allowed);
      return;
    }
    case 'pay_not_allowed':
      record(f, 'pay', await pay(tok, { to: { addr: stranger }, amount: '1000', purpose, ref }), ['403:allowlist']);
      return;
    case 'pay_wrong_net':
      record(f, 'pay', await pay(tok, { to: { addr: mainnetAddr }, amount: '1000', purpose, ref }), ['403:to.addr']);
      return;
    case 'pay_dup': {
      const body = { to: { label: `v${a.lits[0]}` }, amount: String(okAmount(a, f.u)), purpose, ref };
      const rs = await Promise.all(Array.from({ length: 4 }, () => pay(tok, body)));
      const allowed = [...payable(a, BigInt(body.amount)), '202:approval'];
      rs.forEach((r) => record(f, 'dup', r, allowed));
      const txids = new Set(rs.filter((r) => r.status === 200 || r.body?.code === 'relay_failed').map((r) => r.body.txid));
      if (txids.size > 1) finding('duplicate ref: concurrent identical requests got different txids', { ref, txids: [...txids] });
      const paid = rs.filter((r) => r.status === 200 && r.body.repeat !== true).length;
      if (paid > 1) finding('duplicate ref: more than one fresh payment answered for one ref', { ref, paid });
      return;
    }
    case 'pay_conflict': {
      const amount = okAmount(a, f.u);
      const r1 = await pay(tok, { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose, ref });
      record(f, 'first', r1, payable(a, amount));
      const logged = r1.status === 200 || r1.status === 202 || r1.body?.code === 'relay_failed';
      const r2 = await pay(tok, { to: { label: `v${a.lits[0]}` }, amount: String(amount + 1n), purpose, ref });
      record(f, 'reuse_ref', r2, logged ? ['409:repeat'] : [...payable(a, amount + 1n), '409:repeat']);
      return;
    }
    case 'pay_abort': {
      const amount = okAmount(a, f.u);
      const body = { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose, ref };
      const r1 = await call('/pay', { method: 'POST', token: tok, body, abortAfter: Math.floor(f.v * 40) });
      counts['pay_abort/first'] ??= {}; counts['pay_abort/first'][key(r1)] = (counts['pay_abort/first'][key(r1)] ?? 0) + 1;
      await sleep(300 + Math.floor(f.w * 700));
      const r2 = await pay(tok, body);
      record(f, 'resend', r2, [...payable(a, amount), '202:approval']);
      return;
    }
    case 'pay_did': {
      const p = payees[Math.floor(f.u * payees.length)];
      const amount = okAmount(a, f.v);
      const r = await pay(tok, { to: { addr: p.w.address, did: p.id.did, bundle: p.bundle }, amount: String(amount), purpose, ref });
      record(f, 'pay', r, a.issuerRule ? payable(a, amount) : ['403:allowlist']);
      if (r.status === 200 && r.body.receipt?.entry?.request?.to?.did !== p.id.did) finding('a DID payment receipt does not name the DID', r.body);
      return;
    }
    case 'pay_invoice': {
      const p = payees[Math.floor(f.u * payees.length)];
      const amount = okAmount(a, f.v);
      const sub = p.nextSub(), t = nowS();
      const ib = { v: 'sigelo/0', typ: 'invoice', did: p.id.did, method: 'monero', addr: sub, iat: t - 60, exp: t + 3600, nonce: multibase(f.x), amount: String(amount) };
      const invoice = { body: ib, sig: sign(p.id.secret, ib) };
      const to = { addr: sub, did: p.id.did, bundle: p.bundle, invoice };
      const r = await pay(tok, { to, amount: String(amount), purpose, ref });
      record(f, 'pay', r, a.issuerRule ? payable(a, amount) : ['403:allowlist']);
      if (r.status === 200) {
        record(f, 'replay_invoice', await pay(tok, { to, amount: String(amount), purpose: purpose + ' again', ref: ref + '-again' }), ['403:invoice']);
        const wrong = await pay(tok, { to: { ...to, invoice: { body: { ...ib, nonce: multibase(bytes(16)) }, sig: invoice.sig } }, amount: String(amount), purpose: purpose + ' forged', ref: ref + '-forged' });
        record(f, 'forged_invoice', wrong, ['403:allowlist']);
      }
      return;
    }
    case 'approval': case 'approval_late': {
      if (a.approval_above === null) {
        // Nobody may approve for an agent without a threshold; a big pay just pays.
        const amount = okAmount(a, f.u);
        record(f, 'pay_no_threshold', await pay(tok, { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose, ref }), PAID);
        return;
      }
      const amount = a.approval_above + 1n + BigInt(Math.floor(f.u * Number(a.per_tx_max - a.approval_above - FEE - 2n)));
      const body = { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose, ref };
      const first = await pay(tok, body);
      record(f, 'ask', first, WAITS);
      if (first.status !== 202) return;
      if (f.kind === 'approval_late') {
        await sleep((MAX_TTL + 2) * 1000);
        const q = first.body.approval_request;
        record(f, 'approve_expired', await callR('/approve', { method: 'POST', body: { body: q, sig: sign(approvers[0].secret, q), bundle: idBundle(approvers[0].genesis) } }), ['403:approval']);
        const again = await pay(tok, body);
        record(f, 'ask_again', again, WAITS);
        if (again.status === 202 && again.body.approval_request?.nonce === q.nonce) finding('an expired approval request was handed out again', again.body);
        return;
      }
      const again = await pay(tok, body);
      record(f, 'ask_repeat', again, WAITS);
      if (!(await approveFlow(f, a, first))) return;
      const paid = await pay(tok, body);
      if (paid.status === 202 && nowS() >= first.body.approval_request.exp) { expiredUnderLoad++; return; } // approval expired while queued
      record(f, 'pay_approved', paid, PAID);
      if (paid.status === 200) {
        const twice = await pay(tok, body);
        record(f, 'pay_approved_again', twice, ['200:']);
        if (twice.body.already_paid !== true || twice.body.txid !== paid.body.txid) finding('an approved ref paid twice', { paid: paid.body.txid, twice: twice.body });
      }
      return;
    }
    case 'receive': {
      const r = await callR('/receive', { method: 'POST', token: tok, body: { purpose: `note ${f.n}` } });
      record(f, 'receive', r, ['200:', '403:rate_per_minute']);
      if (r.status === 200) {
        const where = wallet.own.get(r.body.address);
        if (r.body.account !== a.account || where?.major !== a.account) finding('receive handed out an address of another account', { agent: a.name, account: a.account, got: r.body, where });
      }
      return;
    }
    case 'balance': {
      const r = await callR('/balance', { token: tok });
      record(f, 'balance', r, ['200:']);
      if (r.status === 200 && r.body.account !== a.account) finding('balance answered for another account', { agent: a.name, got: r.body.account });
      return;
    }
    case 'history': {
      const r = await callR(`/history?n=${1 + Math.floor(f.u * 100)}`, { token: tok });
      record(f, 'history', r, ['200:']);
      if (r.status === 200 && (r.body.account !== a.account || r.body.agent !== a.name)) finding('history answered for another agent', { agent: a.name, got: [r.body.agent, r.body.account] });
      const lg = await callR('/log', { token: tok });
      record(f, 'log', lg, ['200:']);
      if (lg.status === 200 && lg.body.entries.some((e) => (e.entry.request.agent ?? e.entry.request.bucket) !== a.name)) finding('/log leaked another agent\'s lines', { agent: a.name });
      return;
    }
    case 'bind': {
      const t = nowS();
      const own = wallet.addrOf(a.account, 0);
      const b = bind({ secret: a.id.secret, id: a.id.did, method: 'monero', addr: own, iat: t - 60, exp: t + 86400, nonce: f.x });
      const r = await callR('/bind', { method: 'POST', token: tok, body: { body: b.body } });
      record(f, 'bind', r, ['200:']);
      if (r.status === 200) {
        const res = verify({ ...idBundle(a.id.genesis), bindings: [{ ...b, sig_addr: r.body.sig_addr }] }, nowS());
        if (res.bindings[0]?.proof !== 'proven') finding('a keeper /bind signature does not make the binding proven', { agent: a.name, res });
      }
      const other = agents[(agents.indexOf(a) + 1) % agents.length];
      const nb = bind({ secret: a.id.secret, id: other.id.did, method: 'monero', addr: own, iat: t - 60, exp: t + 86400, nonce: f.x });
      record(f, 'bind_foreign_did', await callR('/bind', { method: 'POST', token: tok, body: { body: nb.body } }), ['403:bind']);
      return;
    }
    case 'bad_token': {
      const bad = hex(f.x) + hex(f.x);
      record(f, 'pay', await pay(bad, { to: { addr: vendors[0] }, amount: '1000', purpose, ref }), ['401:token']);
      record(f, 'balance', await callR('/balance', { token: bad }), ['401:token']);
      return;
    }
    case 'delegate': {
      const name = `${a.name}-d${f.n}`;
      const fund = a.per_tx_max / 4n;
      const caps = { per_tx_max: String(a.per_tx_max / 2n), max_delegates: 0 };
      if (a.max_delegates === 0) {
        record(f, 'delegate_not_allowed', await callR('/delegate', { method: 'POST', token: tok, body: { name, fund: '0', caps } }), ['403:delegate']);
        return;
      }
      record(f, 'delegate_over_cap', await callR('/delegate', { method: 'POST', token: tok, body: { name: name + 'x', fund: '0', caps: { per_tx_max: String(a.per_tx_max * 2n) } } }), ['403:delegate']);
      const full = a.liveDelegates >= a.max_delegates;
      const r = await callR('/delegate', { method: 'POST', token: tok, body: { name, fund: String(fund), caps } });
      record(f, 'delegate', r, full ? ['403:delegate'] : ['200:', '403:rate_per_minute', '403:per_period_max']);
      if (r.status !== 200) return;
      a.liveDelegates++;
      const d = { name, token: r.body.token, account: r.body.account, parent: a.name, per_tx_max: a.per_tx_max / 2n, revoked: false };
      a.delegates.push(d);
      const fh = `${r.body.fund?.http}:${r.body.fund?.code ?? ''}`;
      const fundOk = [...payable(a, fund).map((x) => x), '403:per_tx_max'];
      if (!fundOk.includes(fh)) finding(`delegate funding: expected ${fundOk.join('|')}, observed ${fh}`, r.body.fund);
      const amount = d.per_tx_max / 3n;
      const dp = await pay(d.token, { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose: purpose + ' by delegate', ref: ref + '-d' });
      record(f, 'delegate_pays', dp, [...payable(a, amount), '502:wallet_funds'], { as: name });
      record(f, 'delegate_over_tx', await pay(d.token, { to: { label: `v${a.lits[0]}` }, amount: String(d.per_tx_max + 1n), purpose: purpose + ' too much', ref: ref + '-dx' }), ['403:per_tx_max'], { as: name });
      if (f.v < 0.6) {
        // The delegate pays WHILE its delegator revokes it: either order is fine, never both after.
        const [rv, race] = await Promise.all([callR('/revoke', { method: 'POST', token: tok, body: { name } }),
          pay(d.token, { to: { label: `v${a.lits[0]}` }, amount: String(amount), purpose: purpose + ' racing revoke', ref: ref + '-drace' })]);
        record(f, 'revoke', rv, ['200:']);
        record(f, 'pay_racing_revoke', race, [...payable(a, amount), '401:token', '502:wallet_funds'], { as: name });
        if (rv.status === 200) { d.revoked = true; a.liveDelegates--; }
        record(f, 'revoked_pays', await pay(d.token, { to: { label: `v${a.lits[0]}` }, amount: '1000', purpose: purpose + ' after revoke', ref: ref + '-dr' }), ['401:token']);
        record(f, 'revoked_balance', await callR('/balance', { token: d.token }), ['401:token']);
      }
      return;
    }
    case 'half_body': {
      // A client that sends half a body and holds the connection: the lane must not wait for it.
      const s = connect(KPORT, '127.0.0.1');
      let got = '';
      let closed = false;
      s.on('data', (x) => { got += x; }); s.on('error', () => {}); s.on('close', () => { closed = true; });
      s.write(`POST /pay HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${tok}\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{"to":`);
      const during = await pay(probe.token, { to: { label: 'v0' }, amount: '1000', purpose: purpose + ' during', ref: ref + '-probe' });
      record(f, 'pay_during_half_body', during, ['200:', '502:wallet', '502:relay_failed']);
      const t0 = Date.now();
      while (got === '' && !closed && Date.now() - t0 < 30_000) await sleep(100);
      s.destroy();
      halfBodyMs.push(Date.now() - t0 + during.ms);
      const obs = got.startsWith('HTTP/1.1 408') ? 408 : got === '' ? 0 : Number(got.slice(9, 12));
      const why = closed ? 'closed' : 'noanswer'; // closed with no answer: the keeper was restarted under it
      record(f, 'half_body_answer', { status: obs, why, body: { code: obs === 408 ? 'body' : '' } }, ['408:body', '0:closed']);
      return;
    }
  }
}

// ---------------------------------------------------------------- run
await startKeeper();
const health = await call('/health', { token: probe.token });
keeperKey = health.body?.service?.key; keeperDid = health.body?.service?.did;
if (typeof keeperKey !== 'string') throw new Error(`no keeper key from /health: ${JSON.stringify(health)}`);

// Crashes, planned by flow count so a seed fixes WHEN (in flows) they happen.
const crashes = [{ at: Math.floor(FLOWS * 0.25), sig: 'SIGKILL' }, { at: Math.floor(FLOWS * 0.5), sig: 'SIGKILL' }, { at: Math.floor(FLOWS * 0.75), sig: 'SIGTERM' }];
let started = 0;
const byAgentQueue = new Map(); // serialise each agent's flows; agents run concurrently
async function chaosMonkey() {
  for (const c of crashes) {
    while (started < c.at) await sleep(50);
    await sleep(int(0, 200));
    const t = Date.now();
    await stopKeeper(c.sig);
    const unblock = keeper.ready.unblock;
    await sleep(200 + int(0, 400));
    try { await startKeeper(); } catch (e) { finding('keeper did not restart after ' + c.sig, String(e)); unblock(); throw e; }
    unblock();
    const h = await call('/health', { token: probe.token });
    if (h.body?.service?.did !== keeperDid) finding('keeper DID changed across a restart', { before: keeperDid, after: h.body?.service?.did });
    keeper.kills.push({ sig: c.sig, atFlow: c.at, downMs: Date.now() - t });
  }
}
const monkey = chaosMonkey();
const queue = [...plan];
async function worker() {
  for (;;) {
    // next flow whose agent is not busy
    const i = queue.findIndex((f) => !byAgentQueue.get(f.agent));
    if (i < 0) { if (queue.length === 0) return; await sleep(5); continue; }
    const [f] = queue.splice(i, 1);
    byAgentQueue.set(f.agent, true);
    started++;
    try { await runFlow(f); } catch (e) { finding(`flow ${f.n} (${f.kind}) threw`, String(e?.stack ?? e)); }
    byAgentQueue.set(f.agent, false);
  }
}
await Promise.all(Array.from({ length: CONC }, worker));
await monkey;
await keeper.ready;
const runMs = Date.now() - T0;

// ---------------------------------------------------------------- audit: spend.log against the wallet
// The probe asks whether the queue still answers, not whether chaos can hit it: with chaos on, a
// 1 % simulated build failure made this line a finding by itself (seen once in a 120-flow run).
Object.assign(wallet.chaos, { buildError: 0, relayError: 0, relayGarbage: 0 });
const probeT = Date.now();
const fin = await call('/pay', { method: 'POST', token: probe.token, body: { to: { label: 'v0' }, amount: '1000', purpose: 'final probe', ref: 'final-probe' }, timeoutMs: 5000 });
if (!(fin.status === 200 || fin.body?.code === 'relay_failed')) finding('final probe: the queue did not answer a plain pay within 5 s', { status: fin.status, why: fin.why, body: fin.body });
const probeMs = Date.now() - probeT;

// --selftest: plant violations the auditor below must catch, so a clean run means something.
const planted = [];
if (SELFTEST) {
  const victim = agents[0];
  wallet.moved.push({ txid: 'f'.repeat(64), account: victim.account, dest: stranger, amount: victim.per_tx_max, fee: FEE, kind: 'transfer', at: Date.now() });
  planted.push('the wallet relayed a transaction with no intent line', 'per_tx_max exceeded', 'outside the agent\'s allowlist');
  if (receiptsSeen.length > 0) { const r = receiptsSeen[0].r; receiptsSeen[0] = { ...receiptsSeen[0], r: { ...r, receipt: { ...r.receipt, entry: { ...r.receipt.entry, amount: '1' } } } }; planted.push('a receipt does not verify'); }
}
const rawLines = readFileSync(join(dir, 'spend.log'), 'utf-8').split('\n').filter((l) => l !== '');
let log = [];
try { log = readLog(policyPath); } catch (e) { finding('spend.log does not replay', String(e)); }
const tree = [];
rawLines.forEach((l, i) => {
  const r = JSON.parse(l);
  if (!verifySig(keeperKey, r.entry, r.sig)) finding('a spend.log line does not verify under the keeper key', { line: i });
  if (r.entry.kind !== undefined) tree.push({ ...r.entry, line: i });
});
// receipts handed to clients
for (const s of receiptsSeen) {
  const rc = s.r.receipt;
  if (!verifySig(keeperKey, rc.entry, rc.sig) || rc.entry.status !== 'relayed' || rc.entry.txid !== s.r.txid) finding('a receipt does not verify against the keeper DID', { flow: s.flow, txid: s.r.txid });
  const m = wallet.moved.find((x) => x.txid === rc.entry.txid);
  if (m === undefined) finding('a receipt names a txid the wallet never relayed', { flow: s.flow, txid: rc.entry.txid });
  else if (BigInt(rc.entry.amount) !== m.amount || rc.entry.plan.account_index !== m.account) finding('a receipt disagrees with the wallet (amount or account)', { flow: s.flow, receipt: rc.entry, moved: { ...m, amount: String(m.amount), fee: String(m.fee) } });
}
// the ledger
const byTx = new Map();
for (const r of log) if (r.entry.txid !== '') { const l = byTx.get(r.entry.txid) ?? []; l.push(r.entry); byTx.set(r.entry.txid, l); }
const movedIds = new Set(wallet.moved.map((m) => m.txid));
let uncertainMoved = 0, uncertainHome = 0, intentOnly = 0;
for (const m of wallet.moved) {
  const ls = byTx.get(m.txid);
  const intent = ls?.find((e) => e.status === 'intent');
  if (intent === undefined) { finding('the wallet relayed a transaction with no intent line in spend.log', { txid: m.txid, account: m.account }); continue; }
  if (BigInt(intent.amount) !== m.amount || BigInt(intent.fee) !== m.fee || intent.plan.account_index !== m.account || intent.plan.destinations[0].address !== m.dest) {
    finding('an intent line disagrees with what the wallet relayed', { txid: m.txid, intent: { amount: intent.amount, fee: intent.fee, account: intent.plan.account_index }, moved: { amount: String(m.amount), fee: String(m.fee), account: m.account } });
  }
  if (ls.some((e) => e.status === 'relay_failed')) uncertainMoved++;
}
for (const [txid, ls] of byTx) {
  const st = ls.map((e) => e.status);
  if (st.includes('relayed') && !movedIds.has(txid)) finding('spend.log says relayed, the wallet never relayed it', { txid });
  if (st.includes('relay_failed') && !movedIds.has(txid)) uncertainHome++;
  if (st.length === 1 && st[0] === 'intent') intentOnly++;
  if (st.filter((s) => s === 'intent').length > 1) finding('two intent lines for one txid', { txid });
}
// no double pay per ref; approvals single-use
const refPaid = new Map();
for (const r of log) {
  const e = r.entry;
  if (e.status !== 'intent' || e.request.ref === undefined || !movedIds.has(e.txid)) continue;
  const k = `${e.request.agent}/${e.request.ref}`;
  refPaid.set(k, (refPaid.get(k) ?? 0) + 1);
}
for (const [k, n] of refPaid) if (n > 1) finding('double pay: one ref relayed more than once', { ref: k, n });
const nonces = new Map();
for (const r of log) if (r.entry.status === 'intent' && r.entry.request.approval !== undefined) nonces.set(r.entry.request.approval, (nonces.get(r.entry.request.approval) ?? 0) + 1);
for (const [nonce, n] of nonces) if (n > 1) finding('one approval spent by more than one payment', { nonce, n });
const approvedNonces = new Set(log.filter((r) => r.entry.status === 'approved').map((r) => r.entry.approval?.body?.nonce));

// caps, approvals and allowlists, from the WALLET's side
const delegates = new Map(tree.filter((t) => t.kind === 'delegate').map((t) => [t.name, t]));
const revokedAt = new Map(tree.filter((t) => t.kind === 'revoke').map((t) => [t.name, t.line]));
const ownerOf = (account) => byAccount.get(account) ?? [...delegates.values()].find((d) => d.account === account);
const capsOf = (who) => {
  if (who.kind !== 'delegate') return { per_tx: who.per_tx_max, per_period: who.per_period_max, rate: who.rate_per_minute, period: who.period_seconds, above: who.approval_above, root: who };
  const up = capsOf(byName.get(who.parent) ?? delegates.get(who.parent));
  const min = (x, y) => (x < y ? x : y);
  const above = who.approval_above === null ? up.above : up.above === null ? BigInt(who.approval_above) : min(BigInt(who.approval_above), up.above);
  return { per_tx: min(BigInt(who.caps.per_tx_max), up.per_tx), per_period: min(BigInt(who.caps.per_period_max), up.per_period), rate: Math.min(who.caps.rate_per_minute, up.rate), period: up.period, above, root: up.root };
};
const perAccount = new Map();
const timeline = new Map(); // account -> [{ ts of the intent line, cost }] of what the wallet moved
const intentOf = (txid) => byTx.get(txid)?.find((e) => e.status === 'intent');
for (const m of wallet.moved) {
  if (m.kind !== 'transfer') continue;
  const who = ownerOf(m.account);
  if (who === undefined) { finding('the wallet paid from an account no agent holds', { account: m.account }); continue; }
  const c = capsOf(who);
  const cost = m.amount + m.fee;
  if (cost > c.per_tx) finding('per_tx_max exceeded (wallet side, amount + fee)', { agent: who.name, txid: m.txid, cost: String(cost), cap: String(c.per_tx) });
  perAccount.set(m.account, (perAccount.get(m.account) ?? 0n) + cost);
  const intent = intentOf(m.txid);
  const tl = timeline.get(m.account) ?? []; tl.push({ ts: intent?.ts ?? 0, cost, txid: m.txid }); timeline.set(m.account, tl);
  if (c.above !== null && m.amount > c.above && !(intent?.request.approval !== undefined && approvedNonces.has(intent.request.approval))) {
    finding('a payment above approval_above went out without an approval', { agent: who.name, txid: m.txid, amount: String(m.amount), above: String(c.above) });
  }
  const dests = new Set([...c.root.lits.map((v) => vendors[v]), ...[...delegates.values()].filter((d) => d.account !== m.account).map((d) => d.address)]);
  const payeeDest = payees.some((p) => p.w.address === m.dest) || (wallet.own.get(m.dest) === undefined && intent?.request.to.invoice !== undefined);
  if (!dests.has(m.dest) && !(c.root.issuerRule && payeeDest)) finding('the wallet paid a destination outside the agent\'s allowlist', { agent: who.name, dest: m.dest });
  if (who.kind === 'delegate' && revokedAt.has(who.name)) {
    const line = rawLines.findIndex((l) => l.includes(m.txid));
    if (line > revokedAt.get(who.name) && !intent?.request.purpose.startsWith('sweep:')) finding('a revoked delegate paid after its revoke line', { agent: who.name, txid: m.txid });
  }
}
// Sliding windows, as the keeper counts them: at each spend's time t, what moved with ts in (t − P, t].
for (const [account, tl] of timeline) {
  const who = ownerOf(account), c = capsOf(who);
  for (const x of tl) {
    const inPeriod = tl.filter((y) => y.ts > x.ts - c.period && y.ts <= x.ts);
    const sum = inPeriod.reduce((t, y) => t + y.cost, 0n);
    if (sum > c.per_period) { finding('per_period_max exceeded (wallet side, amount + fee moved within one period window)', { agent: who.name, at: x.ts, period: c.period, sum: String(sum), cap: String(c.per_period) }); break; }
    const inMinute = tl.filter((y) => y.ts > x.ts - 60 && y.ts <= x.ts).length;
    if (inMinute > c.rate) { finding('rate_per_minute exceeded (wallet side, transactions moved within 60 s)', { agent: who.name, at: x.ts, n: inMinute, rate: c.rate }); break; }
  }
}
const windowsChecked = [...timeline.values()].reduce((t, l) => t + l.length, 0);
// the keeper's budget view never under-counts what the wallet moved
for (const a of [...agents, probe]) {
  const b = await call('/budget', { token: a.token });
  if (a.period_seconds !== 86400) continue;
  const moved = perAccount.get(a.account) ?? 0n;
  if (b.status !== 200) finding('/budget did not answer at the end', { agent: a.name, b: b.body });
  else if (BigInt(b.body.spent) < moved) finding('/budget spent is below what the wallet moved (under-count)', { agent: a.name, spent: b.body.spent, moved: String(moved) });
}
for (const a of agents) for (const d of a.delegates.filter((x) => x.revoked)) {
  const r = await call('/balance', { token: d.token });
  if (r.status !== 401) finding('a revoked delegate token still answers at the end', { delegate: d.name, status: r.status });
}
for (const x of wallet.anomalies) finding('mock wallet anomaly', x);
let selftest;
if (SELFTEST) {
  const caught = planted.filter((p) => findings.some((f) => f.what.includes(p)));
  selftest = { planted: planted.length, caught: caught.length, missed: planted.filter((p) => !caught.includes(p)) };
  // A self-test run audits a doctored wallet: everything it reports is the plants and their
  // consequences (e.g. /budget now below what the wallet 'moved'). Only a MISSED plant is a finding.
  selftest.triggered = findings.splice(0).map((f) => f.what);
  if (selftest.missed.length > 0) finding('auditor self-test: a planted violation was not caught', selftest.missed);
}
const sweeps = wallet.moved.filter((m) => m.kind === 'sweep').length;

// A power loss in the middle of an append leaves half a line at the tail (K1, sim/REPORT.md).
// The keeper must start anyway: the torn bytes moved to spend.log.torn-<ts> (never dropped),
// one warning naming the file, the log back to its last whole line. A torn line that is NOT the
// last one is corruption, not a crash: that start must still be refused, naming the line.
const observations = [];
{
  const natural = (keeper.stderr.match(/ended in a torn line/g) ?? []).length;
  observations.push(`chaos kills: ${keeper.kills.length}, keeper starts ${keeper.starts}, torn tails repaired at those starts: ${natural}`);
  await stopKeeper('SIGKILL');
  const logFile = join(dir, 'spend.log');
  const whole = readFileSync(logFile, 'utf-8');
  const tail = '{"entry":{"ts":' + nowS() + ',"status":"inte';
  writeFileSync(logFile, whole + tail);
  const errBefore = keeper.stderr.length;
  let refused = '';
  try { await startKeeper(); } catch (e) { refused = String(e.message); }
  const said = keeper.stderr.slice(errBefore);
  const moved = readdirSync(dir).filter((f) => f.startsWith('spend.log.torn-')).map((f) => join(dir, f));
  const exact = moved.find((f) => readFileSync(f, 'utf-8') === tail);
  if (refused !== '') finding('the keeper refused to start over a torn spend.log tail (K1: it must move it aside and start)', refused.slice(0, 300));
  else if (exact === undefined || readFileSync(logFile, 'utf-8') !== whole || !said.includes(`moved its ${Buffer.byteLength(tail)} bytes to ${exact}`)) {
    finding('torn tail: not moved aside intact with one warning naming the file', { said: said.slice(0, 300), moved, logIntact: readFileSync(logFile, 'utf-8') === whole });
  } else observations.push(`torn tail: moved ${Buffer.byteLength(tail)} bytes to ${exact.slice(dir.length + 1)}, warned, started — no operator needed`);
  const after = await call('/pay', { method: 'POST', token: probe.token, body: { to: { label: 'v0' }, amount: '1000', purpose: 'probe after torn tail', ref: 'final-probe-2' }, timeoutMs: 5000 });
  if (!(after.status === 200 || after.body?.code === 'relay_failed')) finding('after the torn tail the keeper did not pay', after.body);
  // A torn MIDDLE line: refused, naming it; nothing moved.
  await stopKeeper('SIGTERM');
  const now = readFileSync(logFile, 'utf-8'), ls = now.split('\n');
  const mid = Math.floor(ls.length / 2);
  const holed = [...ls.slice(0, mid), ls[mid].slice(0, 30), ...ls.slice(mid + 1)].join('\n');
  writeFileSync(logFile, holed);
  let midRefused = '';
  try { await startKeeper(); await stopKeeper('SIGTERM'); } catch (e) { midRefused = String(e.message); }
  if (midRefused === '' || !midRefused.includes(`spend.log: line ${mid + 1} is not JSON`) || readFileSync(logFile, 'utf-8') !== holed) finding('a torn middle line did not refuse the start (or was altered)', midRefused.slice(0, 300));
  else observations.push(`torn middle line ${mid + 1}: refused as before (${midRefused.match(/spend\.log: line \d+[^(]*/)?.[0]?.trim()}) — a hole in the ledger is corruption, not a crash`);
  writeFileSync(logFile, now);
  await startKeeper();
}

// ---------------------------------------------------------------- summary
await stopKeeper('SIGTERM');
await wallet.close();
if (!KEEP) rmSync(dir, { recursive: true, force: true });
const byKind = {};
for (const e of events) { byKind[e.kind] ??= { events: 0, mismatches: 0 }; byKind[e.kind].events++; if (!e.ok) byKind[e.kind].mismatches++; }
const summary = {
  sim: 'keeper-swarm', seed: SEED, plan_hash: planHash, agents: K, flows: FLOWS, concurrency: CONC, chaos: CHAOS,
  events: events.length, mismatches: events.filter((e) => !e.ok).length, by_kind: byKind, outcomes: counts,
  licence: { tier: licence.status.tier, seats: licence.status.seats, vendor: process.env.SIGELO_VENDOR_DID },
  keeper: { starts: keeper.starts, kills: keeper.kills, did: keeperDid, crash_retries: crashRetries, approvals_expired_under_load: expiredUnderLoad, half_body_answer_ms: halfBodyMs, stderr_tail: keeper.stderr.slice(-1500) },
  wallet: { relayed: wallet.moved.length, sweeps, injected: wallet.injected, calls: Object.fromEntries(wallet.calls) },
  log: { lines: rawLines.length, tree_lines: tree.length, uncertain_but_moved: uncertainMoved, uncertain_stayed_home: uncertainHome, intent_only: intentOnly },
  receipts_checked: receiptsSeen.length, windows_checked: windowsChecked, delegates: delegates.size, revoked: revokedAt.size,
  final_probe_ms: probeMs, run_ms: runMs, wall_ms: Date.now() - T0, dir: KEEP ? dir : undefined,
  ...(selftest !== undefined && { selftest }), observations, findings,
};
mkdirSync(join(HERE, 'out'), { recursive: true });
writeFileSync(join(HERE, 'out', 'keeper-summary.json'), JSON.stringify(summary, null, 2) + '\n');
console.error(`keeper-swarm: seed ${SEED} plan ${planHash} · ${K} agents · ${FLOWS} flows · ${events.length} events · ${wallet.moved.length} relayed · ${keeper.starts} keeper starts · ${findings.length} findings · ${Math.round((Date.now() - T0) / 1000)} s`);
for (const f of findings.slice(0, 30)) console.error(`FINDING ${f.what} ${f.detail}`);
console.log(JSON.stringify(summary));
process.exit(findings.length === 0 ? 0 : 1);
