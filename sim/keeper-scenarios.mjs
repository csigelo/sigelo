// SPDX-License-Identifier: MIT
// sim/keeper-scenarios.mjs — delegates of delegates, and policy.json edited under a running
// keeper (sim/README.md). A scripted companion to keeper-swarm.mjs: one real `sigelo-spend serve`
// against sim/mock-wallet.mjs (its own books, loopback, never the soak's wallet or ports), in a
// fresh mkdtemp directory. Every step states the answer spend/README.md or MONERO.md promises;
// any other answer is a finding and the exit code is 1.
//
//   node sim/keeper-scenarios.mjs [--seed S] [--port P] [--keep]
//   node sim/keeper-scenarios.mjs --mutants        (plants 7 bugs in copies of spend/dist; each must be caught)
//   env: SIM_SEED, SIM_PORT, SIM_SPEND_DIST (another build of spend/dist to run), SIM_OUT
//
// D — delegation chains (MONERO.md §4.3, spend/README "Delegation"): root → d1 → d2 → d3 → d4,
//     each within its delegator (depth 4); a fifth level, a delegate above its delegator's caps,
//     rate or allowlist, a count over the subtree's reservation, names reused (an ancestor's, a
//     root's, a revoked one's: the only way a cycle could be written), revokes by non-ancestors;
//     then the middle delegate revoked: its whole subtree dies at once and is swept one hop up,
//     the delegator above it keeps paying and gets its reservation back.
// P — policy.json edited while the keeper runs: caps tightened, a root removed, an approver
//     added, a root's token rotated with `sigelo-spend token new`, a root added, then a malformed
//     edit. The documented contract (spend/README "What a running keeper re-reads"; "The nesting
//     rule": "tightens a root in policy.json AND RESTARTS"; MONERO.md §6; cli.ts: SIGHUP, like
//     SIGINT/SIGTERM, exits 0 and removes spend.lock) is that a running keeper re-reads the token
//     of each root it already serves on every request, and everything else at start only.
//     So: the rotated token is refused and the new one pays at once (a malformed file changes no
//     token); nothing else changes until a restart; SIGHUP stops the keeper; a restart on a malformed
//     file is refused with the field named (no fallback to the old policy); after a good restart
//     the tightened root clamps its whole subtree, the removed root and its delegates answer 401
//     (orphaned, with a warning), the new approver's approval pays a request made before the
//     restart exactly once, and a root re-added on another account refuses the start.
//
// Where a document says something else than the keeper does, the step is recorded under
// `doc_divergences` in the summary (with the quote) and does not fail the run: those are
// findings to report, not to fix here.
import { spawn, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { keygen, sign } from '../ts/dist/sigelo.js';
import { recoveryCommitment, walletFromRoot } from '../ts/dist/keys.js';
import { startMockWallet } from './mock-wallet.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(HERE);
const OUT = process.env.SIM_OUT ?? join(HERE, 'out');
const argv = process.argv.slice(2);
const opt = (n, env, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : process.env[env] ?? d; };
const SEED = String(opt('seed', 'SIM_SEED', 'sigelo-keeper-scenarios'));
const PORT = Number(opt('port', 'SIM_PORT', 39120));
const SPEND = process.env.SIM_SPEND_DIST ?? join(ROOT, 'spend', 'dist');
if (!(PORT >= 39000)) throw new Error('--port must be ≥ 39000 (38083 and 38200 belong to the live soak)');

// ---------------------------------------------------------------- --mutants: plant bugs in copies of spend/dist
const MUTANTS = [
  ['clamp-skipped', 'a delegate is not clamped to its ancestors at spend time', 'tree.js', 'per_tx_max: min(d.caps.per_tx_max, p.per_tx_max)', 'per_tx_max: d.caps.per_tx_max'],
  ['revoke-not-cascading', "revoking a delegate leaves its subtree live", 'tree.js', 'if (c.some((n) => t.revoked.has(n)))', 'if (t.revoked.has(name))'],
  ['cap-above-delegator', 'a delegate may be created above its delegator\'s caps', 'tree.js', 'if (BigInt(v) > BigInt(p[f]))', 'if (false)'],
  ['count-per-child', 'max_delegates bounds direct children, not the subtree', 'tree.js', 'if (used + 1 + md > p.max_delegates) {', 'if (1 + md > p.max_delegates) {'],
  ['revoke-by-anyone', 'any agent may revoke any delegate', 'tree.js', '!chain(t, name).slice(1).includes(caller)', 'false'],
  ['orphans-live', 'a delegate whose root was removed stays live', 'tree.js', "return own(roots, c.at(-1)) ? 'live' : 'orphaned';", "return 'live';"],
  ['names-reused', 'a delegate may take a used name', 'tree.js', 'if (usedNames(t, roots, ctx.logged).has(ask.name))', 'if (false)'],
];
if (argv.includes('--mutants')) {
  const base = join(OUT, 'keeper-mutants');
  rmSync(base, { recursive: true, force: true });
  const t0 = Date.now();
  const results = [];
  let next = 0;
  // Two lanes on distinct ports; each run is ~1 min of mostly waiting on keeper starts.
  await Promise.all([0, 1].map(async (lane) => {
    while (next < MUTANTS.length) {
      const k = next++;
      const [name, what, file, from, to] = MUTANTS[k];
      const dir = join(base, name);
      mkdirSync(dir, { recursive: true });
      cpSync(join(ROOT, 'spend', 'dist'), join(dir, 'dist'), { recursive: true });
      symlinkSync(join(ROOT, 'spend', 'node_modules'), join(dir, 'node_modules'));
      symlinkSync(join(ROOT, 'spend', 'package.json'), join(dir, 'package.json'));
      const p = join(dir, 'dist', file);
      const src = readFileSync(p, 'utf8');
      if (!src.includes(from)) { results.push({ name, what, status: 'NOT APPLIED (pattern missing — update sim/keeper-scenarios.mjs)' }); continue; }
      writeFileSync(p, src.replace(from, to));
      const r = await new Promise((resolve) => execFile(process.execPath, [fileURLToPath(import.meta.url), '--port', String(39140 + 10 * lane)],
        { env: { ...process.env, SIM_SPEND_DIST: join(dir, 'dist'), SIM_OUT: join(dir, 'out') }, maxBuffer: 1 << 26, timeout: 600_000 },
        (err, stdout) => { try { resolve(JSON.parse(stdout.trim().split('\n').pop())); } catch { resolve({ error: String(err?.message ?? 'no summary').slice(0, 200) }); } }));
      results.push({ name, what, status: r.error ? `ERROR ${r.error}` : r.findings > 0 ? `killed (${r.findings} findings)` : 'SURVIVED', findings: r.findings });
    }
  }));
  results.sort((a, b) => MUTANTS.findIndex((m) => m[0] === a.name) - MUTANTS.findIndex((m) => m[0] === b.name));
  for (const r of results) console.log(`${r.status.padEnd(24)} ${r.name.padEnd(22)} ${r.what}`);
  const survived = results.filter((r) => !r.status.startsWith('killed')).length;
  console.log(`\n${results.length - survived}/${results.length} keeper mutants killed, ${Math.round((Date.now() - t0) / 1000)} s`);
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, 'keeper-mutants.json'), JSON.stringify(results, null, 1));
  process.exit(survived ? 1 : 0);
}

// ---------------------------------------------------------------- seeded identities
function prng(label) {
  const h = createHash('sha256').update(`${SEED}/${label}`).digest();
  let [a, b, c, d] = [h.readUInt32LE(0), h.readUInt32LE(4), h.readUInt32LE(8), h.readUInt32LE(12)];
  return () => { a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0; const t = (a + b) | 0; a = b ^ (b >>> 9); b = (c + (c << 3)) | 0; c = (c << 21) | (c >>> 11); d = (d + 1) | 0; const r = (t + d) | 0; c = (c + r) | 0; return (r >>> 0) / 4294967296; };
}
const R = prng('ids');
const bytes = (n = 32) => Uint8Array.from({ length: n }, () => Math.floor(R() * 256));
const hex = (b) => Buffer.from(b).toString('hex');
const tokenHash = (t) => 'sha256:' + createHash('sha256').update(t, 'utf8').digest('hex');
const NET = 'stagenet';
const XMR = 10n ** 12n;
const vendors = Array.from({ length: 3 }, (_, i) => walletFromRoot(bytes(), `vendor/${i}`, NET).address);
const approvers = { A1: keygen({ recovery: bytes(), seed: bytes() }), A2: keygen({ recovery: bytes(), seed: bytes() }) };
const idBundle = (g) => ({ v: 'sigelo/0', typ: 'bundle', genesis: g, rotations: [], bindings: [], attestations: [], issuers: [] });
const root = (name, account, o) => ({ name, account, token: hex(bytes()), id: keygen({ recovery: bytes(), seed: bytes() }), ...o });
const roots = {
  R1: root('R1', 1, { per_tx_max: 10n * XMR, per_period_max: 200n * XMR, max_delegates: 4, approval_above: 9n * XMR, allow: [{ label: 'v0', addr: vendors[0] }, { label: 'v1', addr: vendors[1] }] }),
  R2: root('R2', 2, { per_tx_max: 5n * XMR, per_period_max: 50n * XMR, max_delegates: 1, approval_above: null, allow: [{ label: 'v0', addr: vendors[0] }] }),
  R3: root('R3', 3, { per_tx_max: 5n * XMR, per_period_max: 50n * XMR, max_delegates: 0, approval_above: null, allow: [{ label: 'v0', addr: vendors[0] }] }),
  R5: root('R5', 5, { per_tx_max: 10n * XMR, per_period_max: 100n * XMR, max_delegates: 0, approval_above: 1n * XMR, allow: [{ label: 'v0', addr: vendors[0] }] }),
};
const R4 = root('R4', 4, { per_tx_max: 1n * XMR, per_period_max: 10n * XMR, max_delegates: 0, approval_above: null, allow: [{ label: 'v0', addr: vendors[0] }] });
const REC = recoveryCommitment(bytes());
const agentJson = (a) => ({
  account: a.account, token_hash: tokenHash(a.token), did: a.id.did, genesis: a.id.genesis,
  per_tx_max: String(a.per_tx_max), per_period_max: String(a.per_period_max), period_seconds: 86400, rate_per_minute: 1000, allow: a.allow,
  ...(a.approval_above !== null && { approval_above: String(a.approval_above) }), ...(a.max_delegates > 0 && { max_delegates: a.max_delegates }),
});

// ---------------------------------------------------------------- infrastructure
const dir = mkdtempSync(join(tmpdir(), 'sigelo-sim-kscen-'));
const policyPath = join(dir, 'policy.json');
const lockPath = join(dir, 'spend.lock');
const balances = { 0: 0n, 1: 10n ** 16n, 2: 10n ** 16n, 3: 10n ** 16n, 4: 10n ** 16n, 5: 10n ** 16n };
const wallet = await startMockWallet({ net: NET, root: bytes(), balances, nextAccount: 10, rand: prng('wallet'), port: PORT, chaos: { fee: 30480000n } });
const policyDoc = (agents, extra = {}) => ({
  net: NET, wallet: { rpc: `http://127.0.0.1:${wallet.port}/json_rpc` }, unlock_time: 0, priority: 1, dedupe_seconds: 600, max_approval_ttl: 1800,
  approvers: [{ did: approvers.A1.did }], recovery_commitment: REC, agents: Object.fromEntries(agents.map((a) => [a.name, agentJson(a)])), ...extra,
});
const writePolicy = (doc) => writeFileSync(policyPath, typeof doc === 'string' ? doc : JSON.stringify(doc, null, 2), { mode: 0o600 });
writePolicy(policyDoc(Object.values(roots)));

const KPORT = PORT + 1;
const keeper = { proc: null, stderr: '', starts: 0 };
/** Start the keeper; resolves { ok: true } once it listens, or { ok: false, code, stderr } if it exits first. */
function start() {
  keeper.starts++;
  keeper.stderr = '';
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [join(SPEND, 'cli.js'), 'serve', policyPath, '--port', String(KPORT)], { stdio: ['ignore', 'pipe', 'pipe'] });
    keeper.proc = p;
    let out = '', up = false;
    p.stdout.setEncoding('utf-8'); p.stderr.setEncoding('utf-8');
    p.stdout.on('data', (c) => { out += c; if (!up && out.includes('receipts signed by')) { up = true; resolve({ ok: true }); } });
    p.stderr.on('data', (c) => { keeper.stderr += c; });
    p.on('exit', (code, sig) => { keeper.exit = { code, sig }; if (!up) resolve({ ok: false, code, sig, stderr: keeper.stderr }); });
  });
}
/** Signal the keeper and wait for it to exit: { code, sig }. */
const stop = (signal) => new Promise((resolve) => { const p = keeper.proc; if (p.exitCode !== null || p.signalCode !== null) return resolve({ code: p.exitCode, sig: p.signalCode }); p.once('exit', (code, sig) => resolve({ code, sig })); p.kill(signal); });

async function call(path, { method = 'GET', token, body } = {}) {
  try {
    const r = await fetch(`http://127.0.0.1:${KPORT}${path}`, { method, signal: AbortSignal.timeout(30_000),
      headers: { 'Content-Type': 'application/json', ...(token === undefined ? {} : { Authorization: `Bearer ${token}` }) }, ...(body !== undefined && { body: JSON.stringify(body) }) });
    const text = await r.text(); let j; try { j = JSON.parse(text); } catch { j = { nonjson: text.slice(0, 200) }; }
    return { status: r.status, body: j };
  } catch (e) { return { status: 0, body: { error: String(e?.cause?.code ?? e?.name ?? e) } }; }
}
const key = (r) => `${r.status}:${r.body?.code ?? ''}`;
const pay = (tok, amount, ref, to = { label: 'v0' }) => call('/pay', { method: 'POST', token: tok, body: { to, amount: String(amount), purpose: `scenario ${ref}`, ref } });

// ---------------------------------------------------------------- steps
const steps = [], findings = [], divergences = [], observations = [];
let count_load = 0;
/** `why`: a refusal must also be for the reason the step is about (a count refusal is not a cap refusal). */
function step(id, what, expect, r, detail, why) {
  const obs = typeof r === 'string' ? r : key(r);
  const ok = expect.includes(obs) && (why === undefined || why.test(String(r?.body?.error ?? '')));
  steps.push({ id, what, expect, observed: obs, ok, ...(typeof r === 'object' && r?.body?.error && { error: String(r.body.error).slice(0, 200) }) });
  if (!ok) findings.push({ id, what, expected: expect.join('|'), observed: obs, detail: JSON.stringify(detail ?? r?.body ?? '').slice(0, 500) });
  return ok;
}
const check = (id, what, cond, detail) => step(id, what, ['true'], String(!!cond), detail);
function divergence(id, doc, behaviour, reproducer) { divergences.push({ id, doc, behaviour, reproducer }); }

const t0 = Date.now();
process.on('exit', () => { try { keeper.proc?.kill('SIGKILL'); } catch { /* gone */ } });
// A step that depends on an earlier one that went differently (a planted bug, a regression) may
// throw; that is a finding, never a crash of the run.
try {
const s0 = await start();
if (!s0.ok) throw new Error(`keeper did not start: ${s0.stderr}`);
const tok = Object.fromEntries([...Object.values(roots), R4].map((a) => [a.name, a.token]));
const D = {}; // delegate name -> { token, account }
async function delegate(id, by, name, caps, fund, expect, extra = {}, why) {
  const r = await call('/delegate', { method: 'POST', token: by === undefined ? undefined : (tok[by] ?? D[by]?.token), body: { name, fund: String(fund), ...(caps && { caps }), ...extra } });
  step(id, `${by} delegates ${name}`, expect, r, undefined, why);
  if (r.status === 200) {
    D[name] = { token: r.body.token, account: r.body.account, parent: by };
    if (fund > 0n) step(`${id}.fund`, `${by} funds ${name} (${fund})`, ['200:'], `${r.body.fund?.http}:${r.body.fund?.code ?? ''}`, r.body.fund);
  }
  return r;
}
const T = (n) => tok[n] ?? D[n]?.token;

// ===== D: delegates of delegates (gap 2) =====
await delegate('D1', 'R1', 'd1', { per_tx_max: String(6n * XMR), max_delegates: 3 }, 8n * XMR, ['200:']);
await delegate('D2', 'd1', 'd2', { per_tx_max: String(4n * XMR), max_delegates: 2 }, 4n * XMR, ['200:']);
// While d2 still has room (so a refusal is for the cap, not the count): above its caps, rate, allowlist.
await delegate('D9', 'd2', 'x-over-tx', { per_tx_max: String(4n * XMR + 1n) }, 0n, ['403:delegate'], {}, /per_tx_max .* exceeds yours/);
await delegate('D10', 'd2', 'x-over-rate', { rate_per_minute: 1001 }, 0n, ['403:delegate'], {}, /rate_per_minute 1001 exceeds yours/);
await delegate('D13', 'd2', 'x-allow', { max_delegates: 0 }, 0n, ['403:delegate'], { allow: [{ label: 'v2', addr: vendors[2] }] }, /not in your own allowlist/);
await delegate('D3', 'd2', 'd3', { per_tx_max: String(3n * XMR), max_delegates: 1 }, 3n * XMR, ['200:']);
await delegate('D4', 'd3', 'd4', { per_tx_max: String(2n * XMR), max_delegates: 0 }, 2n * XMR, ['200:']);
await delegate('D5', 'd4', 'd5', { max_delegates: 0 }, 0n, ['403:delegate'], {}, /max_delegates is 0/); // d4's max_delegates is 0: depth 5 refused
step('D6', 'd4 pays within its caps (depth 4)', ['200:'], await pay(T('d4'), XMR, 'd4-pay'));
step('D7', 'd3 pays above its own per_tx_max', ['403:per_tx_max'], await pay(T('d3'), 3n * XMR + 1n, 'd3-over'));
step('D8', 'd4 pays above its delegator d3\'s cap', ['403:per_tx_max'], await pay(T('d4'), 2n * XMR + 1n, 'd4-over'));
await delegate('D11', 'd1', 'x-count', { max_delegates: 0 }, 0n, ['403:delegate'], {}, /you have 0 of 3 left/); // d1: 3 of 3 reserved by d2 (1 + 2)
await delegate('D12', 'R1', 'x-count-root', { max_delegates: 0 }, 0n, ['403:delegate'], {}, /you have 0 of 4 left/); // R1: 4 of 4 reserved by d1 (1 + 3)
step('D16', 'd3 revokes its delegator d2', ['403:revoke'], await call('/revoke', { method: 'POST', token: T('d3'), body: { name: 'd2' } }), undefined, /no delegate named/);
step('D17', 'd2 revokes itself', ['403:revoke'], await call('/revoke', { method: 'POST', token: T('d2'), body: { name: 'd2' } }));
step('D18', 'R2 (another root) revokes d2', ['403:revoke'], await call('/revoke', { method: 'POST', token: T('R2'), body: { name: 'd2' } }));
step('D19', 'd1 funds d3 (not its own child)', ['403:fund'], await call('/fund', { method: 'POST', token: T('d1'), body: { name: 'd3', amount: String(XMR) } }));
// R2's own delegate and a payment on account 2: used by P (orphaning, re-adding on another account).
await delegate('D20', 'R2', 'e1', { max_delegates: 0 }, 2n * XMR, ['200:']);
step('D21', 'R2 pays', ['200:'], await pay(T('R2'), XMR, 'r2-pay'));
// The middle delegate revoked: d2 and everything below it die at once; d1 lives on.
const before = Object.fromEntries(['d2', 'd3', 'd4'].map((n) => [n, wallet.balances.get(D[n]?.account) ?? 0n]));
const rv = await call('/revoke', { method: 'POST', token: T('R1'), body: { name: 'd2' } });
step('D22', 'R1 revokes the middle delegate d2', ['200:'], rv);
check('D22.cascade', 'the revoke cascades to d2, d3, d4', JSON.stringify([...(rv.body.cascade ?? [])].sort()) === JSON.stringify(['d2', 'd3', 'd4']), rv.body);
check('D22.swept', 'each subtree account is swept one hop to R1 (empty in the wallet\'s books)', ['d2', 'd3', 'd4'].every((n) => before[n] > 0n && wallet.balances.get(D[n]?.account) === 0n), { before: Object.fromEntries(Object.entries(before).map(([k, v]) => [k, String(v)])), after: ['d2', 'd3', 'd4'].map((n) => String(wallet.balances.get(D[n]?.account))) });
for (const n of ['d2', 'd3', 'd4']) {
  step(`D23.${n}`, `revoked ${n} pays`, ['401:token'], await pay(T(n), 1000n, `${n}-after-revoke`));
  step(`D24.${n}`, `revoked ${n} asks its balance`, ['401:token'], await call('/balance', { token: T(n) }));
}
step('D25', 'd3 (revoked by the cascade) delegates', ['401:token'], await call('/delegate', { method: 'POST', token: T('d3'), body: { name: 'late', fund: '0' } }));
step('D26', 'd1, above the revoked middle, still pays', ['200:'], await pay(T('d1'), XMR, 'd1-after'));
const dl = await call('/delegates', { token: T('d1') });
check('D27', 'd1 sees d2, d3, d4 as revoked', ['d2', 'd3', 'd4'].every((n) => dl.body.delegates?.find((x) => x.name === n)?.status === 'revoked'), dl.body);
step('D28', 'd1 revokes d3 again (covered by the cascade: no new line)', ['200:'], await call('/revoke', { method: 'POST', token: T('d1'), body: { name: 'd3' } }));
await delegate('D29', 'd1', 'd2', null, 0n, ['403:delegate'], {}, /is taken/); // a revoked name is never reused
await delegate('D30', 'd1', 'd2b', { per_tx_max: String(5n * XMR), max_delegates: 1 }, XMR, ['200:']); // the reservation came back
// A name already in the tree or the policy: the only way a cycle could be written (tree.ts `chain`).
await delegate('D14', 'd2b', 'd1', null, 0n, ['403:delegate'], {}, /is taken/); // its own delegator's name
await delegate('D15', 'd2b', 'R2', null, 0n, ['403:delegate'], {}, /is taken/); // a root's name
const logText = readFileSync(join(dir, 'spend.log'), 'utf-8');
check('D31', 'exactly one revoke line for d2, none for d3/d4', (logText.match(/"kind":"revoke"/g) ?? []).length === 1, (logText.match(/"kind":"revoke"[^}]*/g) ?? []));

// ===== P: policy.json edited while the keeper runs (gap 3) =====
step('P0', 'R1 pays 5 XMR (per_tx_max 10)', ['200:'], await pay(T('R1'), 5n * XMR, 'r1-before'));
// A request that waits for approval, made before the edit (R5 approval_above 1 XMR).
const pend = await pay(T('R5'), 2n * XMR, 'r5-approve');
step('P1', 'R5 pays 2 XMR: approval needed', ['202:approval'], pend);
const q = pend.body.approval_request;
const approval = (who) => ({ body: q, sig: sign(approvers[who].secret, q), bundle: idBundle(approvers[who].genesis) });
// Traffic keeps flowing while the file is rewritten: three agents paying small amounts in a loop.
// Every answer must be a payment (the running keeper's policy does not move under it).
const load = { on: true, answers: {} };
const loadLoop = Promise.all([['R1', 'v0'], ['R5', 'v0'], ['d1', 'v1']].map(async ([who, v], k) => {
  for (let n = 0; load.on; n++) { const r = await pay(T(who), XMR / 1000n, `load-${who}-${n}`, { label: v }); load.answers[key(r)] = (load.answers[key(r)] ?? 0) + 1; }
}));
// The edit: R1 tightened to 2 XMR, R2 removed, approver A2 added, R4 added; then R3's token rotated by the real CLI.
const edited = policyDoc([{ ...roots.R1, per_tx_max: 2n * XMR, approval_above: 2n * XMR }, roots.R3, roots.R5, R4], { approvers: [{ did: approvers.A1.did }, { did: approvers.A2.did }] });
writePolicy(edited);
const tn = await new Promise((resolve) => execFile(process.execPath, [join(SPEND, 'cli.js'), 'token', 'new', policyPath, 'R3'], (err, stdout, stderr) => resolve({ err, stdout: stdout.trim(), stderr: stderr.trim() })));
check('P2', 'sigelo-spend token new R3 succeeds on the edited file', !tn.err && /^[0-9a-f]{64}$/.test(tn.stdout), tn);
const R3new = tn.stdout;
const validEdited = readFileSync(policyPath, 'utf-8');
// Before any restart: the running keeper still holds the policy it started with.
step('P3', 'R1 pays 5 XMR after tightening, before a restart (old caps)', ['200:'], await pay(T('R1'), 5n * XMR, 'r1-edited-unrestarted'));
step('P4', 'removed R2 pays before a restart', ['200:'], await pay(T('R2'), XMR, 'r2-removed-unrestarted'));
const oldR3 = await pay(T('R3'), XMR, 'r3-old-token-unrestarted');
// Root tokens are re-read on every request (spend/README "What a running keeper re-reads"): the
// rotated token is dead and the new one pays at once. Nothing else in the file is live.
step('P5', 'R3\'s OLD token after token new, before a restart', ['401:token'], oldR3);
if (oldR3.status === 200) {
  divergence('P5', `spend/cli.ts \`token new\` prints: "${tn.stderr.replace(/^.*?(agents\.)/, '… $1')}"`,
    'the old token still spends after token new under a running keeper',
    'sigelo-spend serve policy.json & ; sigelo-spend token new policy.json R3 ; SIGELO_SPEND_TOKEN=<old> sigelo-spend pay … → 200 (sim/keeper-scenarios.mjs steps P5, P6)');
}
step('P6', 'R3\'s NEW token before a restart', ['200:'], await pay(R3new, XMR, 'r3-new-token-unrestarted'));
const r4pre = await pay(T('R4'), XMR, 'r4-unrestarted');
step('P7', 'new root R4 before a restart (MONERO.md §6: add, token new, restart)', ['401:token'], r4pre);
if (r4pre.status === 401 && !/restart/.test(tn.stderr)) {
  divergence('P7', '`token new` does not say that a root added since the keeper started needs a restart',
    'a root added to policy.json under a running keeper answers 401 token until the keeper restarts',
    'add R4 to policy.json while `sigelo-spend serve` runs, `token new policy.json R4`, then pay with its token → 401 (sim/keeper-scenarios.mjs step P7; P23 after a restart: 200)');
}
step('P8', 'A2 (added, not yet loaded) approves R5\'s request', ['403:approval'], await call('/approve', { method: 'POST', body: approval('A2') }), undefined, /is not in approvers/);
// A malformed edit under the running keeper: it keeps serving; SIGHUP stops it; the restart is refused.
writePolicy(validEdited.replace('"net":', '"nett": "typo",\n  "net":'));
step('P9', 'R1 pays 1 XMR while policy.json is malformed (still running)', ['200:'], await pay(T('R1'), XMR, 'r1-during-malformed'));
load.on = false; await loadLoop;
check('P9.load', 'every payment made while policy.json was being rewritten was paid', Object.keys(load.answers).length === 1 && load.answers['200:'] > 0, load.answers);
count_load = Object.values(load.answers).reduce((a, b) => a + b, 0);
const hup = await stop('SIGHUP');
check('P10', 'SIGHUP stops the keeper with exit 0 (it is not a reload)', hup.code === 0, hup);
check('P10.lock', 'spend.lock is removed on SIGHUP', !existsSync(lockPath));
const bad = await start();
check('P11', 'a restart on the malformed policy is refused, naming the field', !bad.ok && /nett/.test(bad.stderr ?? ''), { code: bad.code, stderr: (bad.stderr ?? '').slice(-300) });
check('P11.lock', 'the refused start leaves no spend.lock', !existsSync(lockPath));
observations.push('P11: a malformed policy.json is not refused at edit time and the old policy is not kept: the running keeper carries on until its next start, which fails (fail closed). Under Restart=always any crash or SIGHUP after a bad edit is an outage until the file is fixed; nothing but `token new` validates a policy before a restart.');
writePolicy(validEdited);
const good = await start();
check('P12', 'the restart on the repaired, edited policy succeeds', good.ok, good);
check('P12.warn', 'the start warns that e1 is orphaned (its root R2 was removed)', /orphan|no longer in policy\.json/i.test(keeper.stderr) && /e1/.test(keeper.stderr), keeper.stderr.slice(-400));
step('P13', 'R1 pays 5 XMR after the restart (per_tx_max now 2)', ['403:per_tx_max'], await pay(T('R1'), 5n * XMR, 'r1-restarted'));
step('P14', 'd1 (created with per_tx_max 6) pays 3 XMR: clamped to R1\'s new 2', ['403:per_tx_max'], await pay(T('d1'), 3n * XMR, 'd1-clamped'));
step('P15', 'd2b (created with per_tx_max 5) pays 3 XMR: clamped too', ['403:per_tx_max'], await pay(T('d2b'), 3n * XMR, 'd2b-clamped'));
step('P16', 'd1 pays 1.5 XMR (under the clamp)', ['200:'], await pay(T('d1'), 3n * XMR / 2n, 'd1-under-clamp'));
step('P18', 'd1 creates a delegate with per_tx_max 3 (above its clamped 2)', ['403:delegate'], await call('/delegate', { method: 'POST', token: T('d1'), body: { name: 'x-after-clamp', fund: '0', caps: { per_tx_max: String(3n * XMR) } } }), undefined, /per_tx_max 3000000000000 exceeds yours, 2000000000000/);
step('P19', 'removed R2 pays after the restart', ['401:token'], await pay(T('R2'), XMR, 'r2-restarted'));
step('P20', 'orphaned e1 pays after the restart', ['401:token'], await pay(T('e1'), XMR, 'e1-orphaned'));
step('P21', 'R3\'s old token after the restart', ['401:token'], await pay(T('R3'), XMR, 'r3-old-restarted'));
step('P22', 'R3\'s new token after the restart', ['200:'], await pay(R3new, XMR, 'r3-new-restarted'));
step('P23', 'new root R4 after the restart', ['200:'], await pay(T('R4'), XMR / 2n, 'r4-restarted'));
step('P24', 'A2 approves R5\'s pre-restart request (the keeper DID is stable)', ['200:'], await call('/approve', { method: 'POST', body: approval('A2') }));
step('P25', 'R5 repeats the pay: paid once', ['200:'], await pay(T('R5'), 2n * XMR, 'r5-approve'));
const again = await pay(T('R5'), 2n * XMR, 'r5-approve');
step('P26', 'R5 repeats it again: already paid, no second transaction', ['200:'], again);
check('P26.once', 'the repeat answers already_paid', again.body?.already_paid === true, again.body);
// Re-adding the removed root: on another account the start is refused; on its own, e1 comes back.
await stop('SIGTERM');
const readd = JSON.parse(validEdited);
readd.agents.R2 = { ...agentJson(roots.R2), account: 7 };
writePolicy(readd);
const moved = await start();
check('P27', 'R2 re-added on another account: the start is refused (a name stays bound to its account)', !moved.ok && /R2/.test(moved.stderr ?? '') && /account/.test(moved.stderr ?? ''), { stderr: (moved.stderr ?? '').slice(-300) });
readd.agents.R2 = agentJson(roots.R2);
writePolicy(readd);
const back = await start();
check('P28', 'R2 re-added on its own account: the start succeeds', back.ok, back);
step('P29', 'R2 pays again', ['200:'], await pay(T('R2'), XMR, 'r2-readded'));
const e1back = await call('/balance', { token: T('e1') });
step('P30', 'e1, orphaned while R2 was gone, answers again once R2 is back', ['200:'], e1back);
observations.push('P30: an orphaned delegate is not dead for good — re-adding its root on the same account revives it with its old token (README: "dead, its funds left in its account until the root is restored and revokes it" implies but does not say this). Revoke it before or right after restoring the root if that is not wanted.');
await stop('SIGTERM');
} catch (e) {
  findings.push({ id: 'crash', what: 'the scenario could not continue (an earlier step went differently)', observed: String(e?.stack ?? e).slice(0, 600) });
  if (keeper.proc && keeper.proc.exitCode === null && keeper.proc.signalCode === null) await stop('SIGKILL');
}

// ---------------------------------------------------------------- summary
if (wallet.anomalies.length) for (const a of wallet.anomalies) findings.push({ id: 'wallet', what: 'the keeper made the wallet do something a correct keeper never does', observed: a });
await wallet.close();
if (!argv.includes('--keep')) rmSync(dir, { recursive: true, force: true });
const summary = {
  seed: SEED, spend_dist: SPEND, steps: steps.length, passed: steps.filter((s) => s.ok).length, keeper_starts: keeper.starts,
  wall_ms: Date.now() - t0, payments_during_edits: count_load, findings: findings.length, doc_divergences: divergences, observations,
  digest: createHash('sha256').update(JSON.stringify(steps.map((s) => [s.id, s.observed]))).digest('hex').slice(0, 16),
};
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'keeper-scenarios-summary.json'), JSON.stringify({ ...summary, steps, findings }, null, 1));
for (const f of findings) process.stderr.write(`FINDING ${f.id}: ${f.what}\n  expected ${f.expected}\n  observed ${f.observed}\n  ${f.detail ?? ''}\n`);
for (const d of divergences) process.stderr.write(`DOC DIVERGENCE ${d.id}: ${d.behaviour}\n  doc: ${d.doc}\n`);
console.log(JSON.stringify({ ...summary, doc_divergences: divergences.length, observations: observations.length }));
process.exitCode = findings.length ? 1 : 0;
