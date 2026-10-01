#!/usr/bin/env node
// One tick of the scripted soak agent (ROADMAP T6). Run by sigelo-soak-agent.timer every 30 min.
//
// Every tick, as soak-root:  balance · pay bob 0.0002 "soak <n>" · the same again (ALREADY PAID)
// Every 6 h:                 pay carol 0.00042 "rent <k>" → WAITING FOR APPROVAL → approve-request,
//                            sign as the approver, POST /approve → the same pay → PAID (or TRY LATER,
//                            then re-run on the next ticks while the approval lives)
// Once a UTC day:            delegate d<YYYYMMDD> 0.00035 → (next ticks) the delegate pays bob 0.0002
//                            → revoke, re-run every tick until every sweep line says "empty"
//
// Every command goes to soak.log (NDJSON: ts, tick, who, cmd, exit, got, expect, verdict, out);
// counters and the last mismatches to soak-stats.json. TRY LATER (locked change, rate) is expected
// behaviour and counts as "tolerated", not a mismatch. Nothing here throws out of the tick.
//
// An outage tick (soak incident #4: the host had no network for 32 h) is one where the wallet height
// did not advance since the previous tick's snapshot, or the keeper answered wallet_offline. In it, a
// TRY LATER where the script expected success is the keeper failing closed, so its verdict is
// "outage", not MISMATCH; the tick is counted in outage_ticks and gets a kind:"outage" line. Any other
// unexpected answer is still a MISMATCH. A carol rent given up after 3 h in which every pay attempt
// was an outage TRY LATER is "abandoned_offline" (tolerated), not a mismatch.
import { spawnSync } from 'node:child_process';
import { appendFileSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SPEND = join(HERE, '..'), TS = join(HERE, '..', '..', 'ts', 'dist');
const { sign, verify } = await import(pathToFileURL(join(TS, 'sigelo.js')).href);
const DATA = process.env.SIGELO_SOAK_DIR ?? join(homedir(), '.local/share/sigelo-soak');
const KEEPER = join(DATA, 'keeper'), POLICY = join(KEEPER, 'policy.json');
const URL_ = `http://127.0.0.1:${process.env.SIGELO_SOAK_PORT ?? '38200'}`;
const WALLET_RPC = process.env.SIGELO_SOAK_WALLET_RPC ?? 'http://127.0.0.1:38083/json_rpc';
const LOG = join(DATA, 'soak.log'), STATS = join(DATA, 'soak-stats.json'), STATE = join(DATA, 'state.json');
const RATE_GAP_MS = Number(process.env.SOAK_RATE_GAP_MS ?? 62_000); // rate_per_minute 2: space root spends
const CAROL_EVERY = 6 * 3600 - 600, CAROL_GIVE_UP = 3 * 3600;
const BOB = '0.0002', CAROL = '0.00042', CAROL_ATOMIC = '420000000', FUND = '0.00035';

const now = () => Math.floor(Date.now() / 1000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const readJson = (p, d) => { try { return JSON.parse(readFileSync(p, 'utf-8')); } catch { return d; } };
const writeJson = (p, v) => { writeFileSync(p + '.tmp', JSON.stringify(v, null, 2) + '\n', { mode: 0o600 }); renameSync(p + '.tmp', p); };
const why = (e) => (e instanceof Error ? e.message : String(e));
const redact = (s) => String(s).replace(/(SIGELO_WALLET_TOKEN=)\S+/g, '$1<redacted>');
const oneLine = (s) => redact(String(s).trim().split('\n').map((l) => l.trim()).filter(Boolean).join(' | ')).slice(0, 600);

const stats = readJson(STATS, {
  started: new Date().toISOString(), ticks: 0, last_tick: null, commands: 0, payments: 0, already_paid: 0,
  try_later: 0, waiting: 0, refused: 0, uncertain: 0, approvals: 0, delegates_created: 0, delegates_closed: 0,
  mismatches: 0, errors: 0, last_mismatches: [], outage_ticks: 0, abandoned_offline: 0,
});
const state = readJson(STATE, { tick: 0, last_carol: 0, carol_n: 0, carol: null, delegate: null, last_delegate_day: null, last_height: null });
/** Why this tick is an outage tick ([] while it is not): see the header. */
const outage = [];
let excused = 0;
const ROOT = readFileSync(join(DATA, 'root.token'), 'utf-8').trim();

function record(rec) {
  appendFileSync(LOG, JSON.stringify({ ts: new Date().toISOString(), tick: state.tick, ...rec }) + '\n', { mode: 0o600 });
}
/** expect = { ok: [...], tol?: [...] } over "status/code" with "*" for any code. */
const matches = (got, pats = []) => pats.some((p) => p === got || (p.endsWith('/*') && got.startsWith(p.slice(0, -1))));
function judge(cmd, who, got, exit, out, expect, ms) {
  let verdict = matches(got, expect.ok) ? 'ok' : matches(got, expect.tol) ? 'tolerated' : 'MISMATCH';
  // The keeper failing closed while the host has no network is correct behaviour, not a mismatch.
  if (verdict === 'MISMATCH' && outage.length > 0 && got.startsWith('try_later/')) { verdict = 'outage'; excused++; }
  const exp = [...expect.ok, ...(expect.tol ?? []).map((t) => `(${t})`)].join('|');
  stats.commands++;
  if (verdict === 'MISMATCH') {
    stats.mismatches++;
    stats.last_mismatches = [...stats.last_mismatches, { ts: new Date().toISOString(), tick: state.tick, who, cmd, expect: exp, got, out }].slice(-20);
  }
  record({ who, cmd, exit, got, expect: exp, verdict, ms, out });
  return verdict;
}

let lastRootSpend = 0;
async function rateGap() {
  const wait = lastRootSpend + RATE_GAP_MS - Date.now();
  if (wait > 0) await sleep(wait);
  lastRootSpend = Date.now();
}

/** sigelo-wallet as a process, --json, exactly as a harness would drive it. */
function wallet(who, token, args, expect) {
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [join(SPEND, 'dist', 'wallet.js'), '--json', ...args], {
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: homedir(), SIGELO_WALLET_URL: URL_, SIGELO_WALLET_TOKEN: token },
    encoding: 'utf-8', timeout: 330_000,
  });
  let o;
  try { o = JSON.parse(r.stdout.trim().split('\n').pop()); } catch { o = { status: 'crash', code: r.error ? String(r.error.code ?? r.error) : `noparse(${r.signal ?? r.status})`, message: `${r.stdout} ${r.stderr}` }; }
  const got = `${o.status}/${o.code}`;
  if (o.code === 'wallet_offline' && !outage.includes('wallet_offline')) outage.push('wallet_offline');
  const cmd = `sigelo-wallet ${args.map((a) => (/\s/.test(a) ? JSON.stringify(a) : a)).join(' ')}`;
  const v = judge(cmd, who, got, r.status, oneLine(o.message), expect, Date.now() - t0);
  if (o.status === 'try_later') stats.try_later++;
  if (o.status === 'waiting') stats.waiting++;
  if (o.status === 'refused') stats.refused++;
  if (o.status === 'uncertain') stats.uncertain++;
  if (o.code === 'already_paid') stats.already_paid++;
  if ((args[0] === 'pay' || args[0] === 'fund') && got === 'done/ok') stats.payments++;
  if (args[0] === 'delegate' && o.data?.fund?.http === 200) stats.payments++;
  return { ...o, got, verdict: v, exit: r.status };
}

async function walletRpc(method, params = {}) {
  const r = await fetch(WALLET_RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }), signal: AbortSignal.timeout(90_000) });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

async function keeperDid() {
  const r = await fetch(URL_ + '/health', { headers: { Authorization: `Bearer ${ROOT}` }, signal: AbortSignal.timeout(60_000) });
  return (await r.json()).service?.did;
}

/** The approver, on "its own device": fetch the body the keeper built, check it, sign, POST /approve. */
async function approve(ref) {
  const t0 = Date.now();
  const cmd = `sigelo-spend approve-request policy.json ${ref}`;
  const r = spawnSync(process.execPath, [join(SPEND, 'dist', 'cli.js'), 'approve-request', POLICY, ref], { encoding: 'utf-8', timeout: 60_000 });
  const line = (r.stdout ?? '').trim().split('\n')[0] ?? '';
  judge(cmd, 'approver', `exit${r.status}`, r.status, oneLine(line || r.stderr), { ok: ['exit0'] }, Date.now() - t0);
  if (r.status !== 0) return false;
  const body = JSON.parse(line);
  const id = JSON.parse(readFileSync(join(DATA, 'keys', 'approver.json'), 'utf-8'));
  const kd = await keeperDid();
  const sane = body.typ === 'spend-approval' && body.net === 'stagenet' && body.keeper === kd && body.amount === CAROL_ATOMIC && body.ref === ref;
  if (!sane) { judge('approver: check body', 'approver', 'insane', null, oneLine(line), { ok: ['sane'] }, 0); return false; }
  const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: id.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
  if (verify(bundle, now()).did !== id.did) throw new Error('approver bundle does not verify');
  const sig = sign(Uint8Array.from(Buffer.from(id.seed_hex, 'hex')), body);
  const t1 = Date.now();
  const res = await fetch(URL_ + '/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ body, sig, bundle }), signal: AbortSignal.timeout(60_000) });
  const j = await res.json().catch(() => ({}));
  judge(`POST /approve (ref ${ref})`, 'approver', `http${res.status}`, null, oneLine(JSON.stringify(j)), { ok: ['http200'] }, Date.now() - t1);
  if (res.status === 200) stats.approvals++;
  return res.status === 200;
}

// ---------------------------------------------------------------- steps

async function snapshot() {
  const b0 = await walletRpc('get_balance', { account_index: 0 });
  const all = await walletRpc('get_accounts');
  const h = await walletRpc('get_height');
  // ~15 stagenet blocks arrive in 30 min: a height that did not move means the wallet is not syncing.
  if (Number.isSafeInteger(state.last_height) && h.height <= state.last_height) outage.push(`height ${h.height} did not advance since the last tick`);
  state.last_height = h.height;
  record({ kind: 'wallet', height: h.height, acct0: b0.balance, acct0_unlocked: b0.unlocked_balance, total: String(all.total_balance), total_unlocked: String(all.total_unlocked_balance), accounts: all.subaddress_accounts.length });
}

async function bob() {
  wallet('soak-root', ROOT, ['balance'], { ok: ['done/ok'] });
  await rateGap();
  const p = wallet('soak-root', ROOT, ['pay', 'bob', BOB, `soak ${state.tick}`], { ok: ['done/ok'], tol: ['try_later/*'] });
  // The identical command: answered from the log, never a second transaction.
  wallet('soak-root', ROOT, ['pay', 'bob', BOB, `soak ${state.tick}`],
    p.got === 'done/ok' ? { ok: ['done/already_paid'] } : { ok: ['done/ok', 'try_later/*'] });
}

/** A carol pay that reached the wallet: `online` unless it was an outage TRY LATER (for abandoned_offline). */
function carolTried(c, r) {
  if (r.status === 'waiting') return; // an approval wait never touches the wallet
  c.tries = (c.tries ?? 0) + 1;
  if (!(r.status === 'try_later' && (r.code === 'wallet_offline' || outage.length > 0))) c.online = true;
}

async function carolPay(c, rerun) {
  await rateGap();
  const args = ['pay', 'carol', CAROL, c.purpose];
  let r = wallet('soak-root', ROOT, args, rerun ? { ok: ['done/ok', 'done/already_paid', 'waiting/approval'], tol: ['try_later/*'] } : { ok: ['waiting/approval'] });
  carolTried(c, r);
  if (r.status === 'waiting') {
    const ref = r.data?.ref ?? (/\(ref ([^)]+)\)/.exec(r.message) ?? [])[1];
    if (ref === undefined) throw new Error('WAITING FOR APPROVAL without a ref');
    c.ref = ref;
    if (!(await approve(ref))) return;
    await rateGap();
    r = wallet('soak-root', ROOT, args, { ok: ['done/ok'], tol: ['try_later/*'] });
    carolTried(c, r);
  }
  if (r.status === 'done') {
    if (r.code === 'ok') wallet('soak-root', ROOT, args, { ok: ['done/already_paid'] });
    state.carol = null;
  }
}

async function carol() {
  const c = state.carol;
  if (c) {
    if (now() - c.since > CAROL_GIVE_UP) {
      // Every attempt an outage TRY LATER: the keeper was right to refuse all of them.
      const offline = (c.tries ?? 0) > 0 && c.online !== true;
      if (offline) stats.abandoned_offline = (stats.abandoned_offline ?? 0) + 1;
      judge(`carol ${c.purpose}: give up`, 'soak', offline ? 'abandoned_offline' : 'abandoned', null,
        `not paid within ${CAROL_GIVE_UP / 3600} h (ref ${c.ref}; ${c.tries ?? 0} pay attempts${offline ? ', every one an outage TRY LATER' : ''})`, { ok: ['paid'], tol: ['abandoned_offline'] }, 0);
      state.carol = null;
      return;
    }
    return carolPay(c, true);
  }
  if (now() - state.last_carol < CAROL_EVERY) return;
  state.carol_n++;
  state.carol = { k: state.carol_n, purpose: `rent ${state.carol_n}`, since: now() };
  state.last_carol = now();
  return carolPay(state.carol, false);
}

async function delegateCycle() {
  const today = new Date().toISOString().slice(0, 10).replaceAll('-', '');
  const d = state.delegate;
  if (!d) {
    if (state.last_delegate_day === today) return;
    state.last_delegate_day = today;
    const name = `d${today}`;
    await rateGap();
    const r = wallet('soak-root', ROOT, ['delegate', name, FUND], { ok: ['done/ok'], tol: ['try_later/*'] });
    if (typeof r.data?.token === 'string') {
      state.delegate = { name, token: r.data.token, account: r.data.account, stage: r.data.fund?.http === 200 ? 'funded' : 'unfunded', created: now() };
      stats.delegates_created++;
      writeJson(STATE, state); // the token has no second showing: keep it before anything else can fail
    }
    return;
  }
  if (d.stage === 'unfunded') {
    await rateGap();
    const r = wallet('soak-root', ROOT, ['fund', d.name, FUND], { ok: ['done/ok', 'done/already_paid'], tol: ['try_later/*'] });
    if (r.status === 'done') d.stage = 'funded';
    return;
  }
  if (d.stage === 'funded') {
    // The funding output is locked ~10 blocks: the first try after creation is often TRY LATER.
    const r = wallet(d.name, d.token, ['pay', 'bob', BOB, `from ${d.name}`], { ok: ['done/ok', 'done/already_paid'], tol: ['try_later/*'] });
    if (r.status === 'done') d.stage = 'paid';
    return;
  }
  // paid / revoking: revoke, then re-run each tick until every sweep line is "empty".
  if (d.stage === 'revoking' && now() - (d.revoked ?? now()) > 86400 && !d.late) {
    d.late = true;
    judge(`revoke ${d.name}: still not empty`, 'soak', 'late', null, 'a revoked delegate still holds funds after 24 h', { ok: ['empty'] }, 0);
  }
  await rateGap();
  const r = wallet('soak-root', ROOT, ['revoke', d.name], { ok: ['done/ok'] });
  if (r.status !== 'done') return;
  if (d.stage === 'paid') {
    d.stage = 'revoking';
    d.revoked = now();
    wallet(d.name, d.token, ['balance'], { ok: ['refused/token'] }); // its token must be dead now
  }
  const sweeps = Array.isArray(r.data?.sweeps) ? r.data.sweeps : [];
  if (sweeps.length > 0 && sweeps.every((s) => s.status === 'skipped' && s.reason === 'empty')) {
    stats.delegates_closed++;
    record({ kind: 'delegate_closed', name: d.name, hours: ((now() - d.created) / 3600).toFixed(1) });
    state.delegate = null;
  }
}

async function step(name, fn) {
  try { await fn(); } catch (e) {
    stats.errors++;
    record({ kind: 'error', step: name, error: why(e) });
  }
}

state.tick++;
stats.ticks++;
stats.last_tick = new Date().toISOString();
record({ kind: 'tick', pid: process.pid });
try {
  await step('snapshot', snapshot);
  await step('bob', bob);
  await step('carol', carol);
  await step('delegate', delegateCycle);
  if (outage.length > 0) {
    stats.outage_ticks = (stats.outage_ticks ?? 0) + 1;
    record({ kind: 'outage', reasons: outage, excused });
  }
} finally {
  try { writeJson(STATE, state); } catch (e) { record({ kind: 'error', step: 'state', error: why(e) }); }
  try { writeJson(STATS, stats); } catch (e) { record({ kind: 'error', step: 'stats', error: why(e) }); }
}
process.exit(0);
