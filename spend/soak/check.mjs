#!/usr/bin/env node
// Soak summary: uptime, ticks, payments, mismatches, the keeper log verified line by line under the
// keeper key, and the wallet balance trend. Read-only. Exit 1 if anything is unhealthy.
//
// --evidence: for a directory that is no longer the live soak (the T14 rehearsal's burnt copy):
// skips everything that asks the live host — units, /health, the wallet-rpc — and the liveness
// rules (last tick, last payment, wallet height), keeping the line-by-line verification and the
// clock checks.
//
// --notify: the host noticing (incident #4: 32 h offline and nobody knew). When UNHEALTHY, append
// one line to <SIGELO_SOAK_DIR>/soak-alerts.log and send a notification with notify-send
// if it is there; when HEALTHY after an UNHEALTHY line, log and notify the recovery once. HEALTHY
// with nothing to clear writes nothing. A crash of this script counts as UNHEALTHY. Run hourly by
// sigelo-soak-check.timer.
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const TS = join(HERE, '..', '..', 'ts', 'dist');
const { keygen, verifySig } = await import(pathToFileURL(join(TS, 'sigelo.js')).href);
const { identitySeed } = await import(pathToFileURL(join(TS, 'keys.js')).href);
const DATA = process.env.SIGELO_SOAK_DIR ?? join(homedir(), '.local/share/sigelo-soak');
const KEEPER = join(DATA, 'keeper');
const URL_ = `http://127.0.0.1:${process.env.SIGELO_SOAK_PORT ?? '38200'}`;
const WALLET_RPC = process.env.SIGELO_SOAK_WALLET_RPC ?? 'http://127.0.0.1:38083/json_rpc';
const EVIDENCE = process.argv.includes('--evidence');
const SKEW = 300; // seconds a log's newest ts may be ahead of this host's clock (spend/README.md, the clock guard)
const xmr = (a) => { const n = BigInt(a), s = (n < 0n ? -n : n).toString().padStart(13, '0'); return `${n < 0n ? '-' : ''}${s.slice(0, -12)}.${s.slice(-12)}`.replace(/\.?0+$/, '') || '0'; };
const dur = (s) => `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
const readJson = (p, d) => { try { return JSON.parse(readFileSync(p, 'utf-8')); } catch { return d; } };
const nd = (p) => (existsSync(p) ? readFileSync(p, 'utf-8').split('\n').filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch { return { unparsable: l }; } }) : []);
let unhealthy = [];
const NOTIFY = process.argv.includes('--notify');
const ALERTS = join(DATA, 'soak-alerts.log');

/** --notify: one alerts line per UNHEALTHY run (and one on recovery), and notify-send if present. */
function alert(reasons) {
  let was = false;
  try { was = / UNHEALTHY: /.test(readFileSync(ALERTS, 'utf-8').trimEnd().split('\n').at(-1) ?? ''); } catch { /* no alerts yet */ }
  if (reasons.length === 0 && !was) return;
  const [title, body] = reasons.length ? ['sigelo soak UNHEALTHY', reasons.join('\n')] : ['sigelo soak healthy again', 'check.mjs: HEALTHY'];
  let sent;
  try {
    execFileSync('notify-send', ['--app-name=sigelo soak', `--urgency=${reasons.length ? 'critical' : 'normal'}`, title, body], { stdio: 'ignore', timeout: 15_000 });
    sent = 'notify-send ok';
  } catch (e) { sent = `notify-send ${e.code === 'ENOENT' ? 'not installed' : `failed (${e.status ?? e.code ?? e.message})`}`; }
  const line = `${new Date().toISOString()} ${reasons.length ? `UNHEALTHY: ${reasons.join('; ')}` : 'HEALTHY again'} (${sent})`;
  appendFileSync(ALERTS, line + '\n', { mode: 0o600 });
  console.log(`notify      ${sent}; logged to ${ALERTS}`);
}
function finish(reasons) {
  console.log(reasons.length ? `UNHEALTHY: ${reasons.join('; ')}` : 'HEALTHY');
  if (NOTIFY) alert(reasons);
  process.exit(reasons.length ? 1 : 0);
}
if (NOTIFY) process.on('uncaughtException', (e) => finish([...unhealthy, `check.mjs crashed: ${e?.message ?? e}`]));

// ---- units
if (EVIDENCE) console.log(`evidence    ${DATA}: the live host (units, /health, wallet-rpc) and the liveness rules are not checked`);
const unit = (u) => { try { return execFileSync('systemctl', ['--user', 'is-active', u], { encoding: 'utf-8' }).trim(); } catch (e) { return String(e.stdout ?? 'unknown').trim(); } };
if (!EVIDENCE) {
  const units = Object.fromEntries(['sigelo-soak-keeper.service', 'sigelo-soak-agent.timer', 'monero-wallet-rpc-stagenet.service'].map((u) => [u, unit(u)]));
  console.log('units       ' + Object.entries(units).map(([u, s]) => `${u.replace(/\.service$/, '')}=${s}`).join('  '));
  if (units['sigelo-soak-keeper.service'] !== 'active') unhealthy.push('keeper not active');
  if (units['sigelo-soak-agent.timer'] !== 'active') unhealthy.push('agent timer not active');
}

// ---- agent stats
const st = readJson(join(DATA, 'soak-stats.json'), null);
if (!st) { console.log('no soak-stats.json yet (no tick has run)'); finish(['no soak-stats.json (no tick has run)']); }
const up = (Date.now() - Date.parse(st.started)) / 1000, since = (Date.now() - Date.parse(st.last_tick)) / 1000;
console.log(`uptime      ${dur(up)} since ${st.started}; ${st.ticks} ticks, last ${dur(since)} ago`);
console.log(`commands    ${st.commands}: payments ${st.payments}, already-paid ${st.already_paid}, try-later ${st.try_later}, waiting ${st.waiting}, approvals ${st.approvals}, refused ${st.refused}, uncertain ${st.uncertain}`);
console.log(`delegates   created ${st.delegates_created}, closed ${st.delegates_closed}`);
console.log(`mismatches  ${st.mismatches}   errors ${st.errors}   outage ticks ${st.outage_ticks ?? 0}   carol abandoned offline ${st.abandoned_offline ?? 0}`);
for (const m of st.last_mismatches.slice(-5)) console.log(`  ${m.ts} tick ${m.tick} ${m.who}: ${m.cmd}\n      expected ${m.expect}, got ${m.got}: ${m.out}`);
if (since > 3600 && !EVIDENCE) unhealthy.push(`no tick for ${dur(since)}`);
// UNCERTAIN is cumulative in soak-stats.json and, by the keeper's design, only an operator can
// settle it (check the txid in the wallet). `uncertain-acked.json` {uncertain: n, note} records that
// the first n were checked; only newer ones page.
const ack = readJson(join(DATA, 'uncertain-acked.json'), { uncertain: 0 });
if (st.uncertain > (ack.uncertain ?? 0)) unhealthy.push(`${st.uncertain - (ack.uncertain ?? 0)} UNCERTAIN (${st.uncertain} total, ${ack.uncertain ?? 0} acked)`);
else if (st.uncertain > 0) console.log(`uncertain   ${st.uncertain}, all acked: ${ack.note ?? ''}`);
const log = nd(join(DATA, 'soak.log'));
const errs = log.filter((r) => r.kind === 'error');
if (errs.length) console.log(`  last error: ${errs.at(-1).ts} ${errs.at(-1).step}: ${errs.at(-1).error}`);
// Liveness (incident #4: 32 h with no network and this said HEALTHY): a payment that went through
// in the last 2 h, and a wallet height that moved between the last two snapshots.
const paidAt = log.filter((r) => /^sigelo-wallet (pay|fund) /.test(r.cmd ?? '') && r.got === 'done/ok').at(-1)?.ts;
const hs = log.filter((r) => r.kind === 'wallet' && Number.isSafeInteger(r.height)).slice(-2);
console.log(`liveness    last payment ${paidAt ? `${paidAt} (${dur((Date.now() - Date.parse(paidAt)) / 1000)} ago)` : 'never'}; wallet height ${hs.map((h) => h.height).join(' → ') || 'no snapshot'}`);
if (!EVIDENCE) {
  if (up > 7200 && (!paidAt || Date.now() - Date.parse(paidAt) > 7200e3)) unhealthy.push(`no successful payment for ${paidAt ? dur((Date.now() - Date.parse(paidAt)) / 1000) : 'the whole soak'}`);
  if (hs.length === 2 && hs[1].height <= hs[0].height) unhealthy.push(`wallet height stuck at ${hs[1].height} over the last two snapshots (no daemon? see incident #4)`);
}
/** Clock sanity for one log: its newest ts is not in the future, and not older than the line before it. */
function clockOf(name, ts) {
  if (ts.length === 0) return;
  const last = ts.at(-1), prev = ts.at(-2);
  if (last > Date.now() / 1000 + SKEW) unhealthy.push(`${name}: newest ts ${new Date(last * 1000).toISOString()} is in the future — this host's clock is behind`);
  if (prev !== undefined && last < prev) unhealthy.push(`${name}: newest ts ${new Date(last * 1000).toISOString()} is older than the line before it (${new Date(prev * 1000).toISOString()}) — a clock stepped back`);
}
clockOf('soak.log', log.map((r) => Date.parse(r.ts) / 1000).filter((t) => Number.isFinite(t)));

// ---- licence (spend/licence.ts, since 17e7787): the policy's delegates and approvals are paid verbs.
// Read, not verified (gen-keys.mjs check verifies it under the keeper and test-vendor DIDs): its exp, to
// warn 30 days ahead. A soak deployed before the gate (no app/spend/dist/licence.js) needs none.
{
  const gated = existsSync(join(DATA, 'app', 'spend', 'dist', 'licence.js'));
  const lic = readJson(join(KEEPER, 'licence.json'), null), b = lic?.attestation?.body;
  if (!lic) {
    console.log(`licence     none${gated ? '' : ' (the deployed code predates the licence gate: none needed)'}`);
    if (gated) unhealthy.push('no keeper/licence.json: delegates and approvals refuse licence_required (gen-keys.mjs licence, then restart the keeper)');
  } else if (!Number.isSafeInteger(b?.exp)) unhealthy.push('keeper/licence.json has no exp');
  else {
    const left = b.exp - Date.now() / 1000;
    console.log(`licence     tier ${b.claims?.tier}, ${b.claims?.seats} seats, until ${new Date(b.exp * 1000).toISOString()} (${left > 0 ? `${dur(left)} left` : 'EXPIRED'}); verify: gen-keys.mjs check`);
    if (left <= 0) unhealthy.push('licence expired: delegates and approvals refuse (gen-keys.mjs licence --reissue)');
    else if (left < 30 * 86400) unhealthy.push(`licence expires in ${dur(left)} (gen-keys.mjs licence --reissue)`);
  }
}

// ---- keeper log: every line must verify under the keeper key
const khex = readFileSync(join(KEEPER, 'spend.key'), 'utf-8').trim();
const derived = keygen({ seed: identitySeed(Uint8Array.from(Buffer.from(khex, 'hex')), 0), recovery: 'sha256:' + '0'.repeat(64) }).key;
let live = null;
if (!EVIDENCE) try {
  const tok = readFileSync(join(DATA, 'root.token'), 'utf-8').trim();
  live = (await (await fetch(URL_ + '/health', { headers: { Authorization: `Bearer ${tok}` }, signal: AbortSignal.timeout(30_000) })).json()).service ?? null;
} catch { /* keeper down: the derived key still checks the log */ }
if (live && live.key !== derived) unhealthy.push('keeper /health key differs from spend.key');
const kl = nd(join(KEEPER, 'spend.log'));
let bad = 0, fees = 0n;
const kinds = {};
for (const l of kl) {
  const ok = l.entry !== undefined && typeof l.sig === 'string' && verifySig(derived, l.entry, l.sig);
  if (!ok) bad++;
  const k = l.entry?.kind ?? l.entry?.status ?? '?';
  kinds[k] = (kinds[k] ?? 0) + 1;
  if (ok && (l.entry.status === 'relayed' || l.entry.status === 'relay_failed')) fees += BigInt(l.entry.fee);
}
console.log(`keeper log  ${kl.length} lines, ${kl.length - bad} verify under ${derived.slice(0, 16)}…${live ? ` (= /health ${live.did.slice(0, 22)}…)` : ' (keeper not answering; key from spend.key)'}; ${bad} do not`);
console.log(`            ${Object.entries(kinds).map(([k, n]) => `${k} ${n}`).join(', ')}; fees paid ${xmr(fees)} XMR`);
if (bad > 0) unhealthy.push(`${bad} keeper log lines do not verify`);
clockOf('spend.log', kl.map((l) => l.entry?.ts).filter((t) => Number.isSafeInteger(t)));
// A torn last line moved aside at a start (spend/README.md "Torn last line"): not unhealthy by
// itself, but each is a crash mid-write; one naming a txid is checked in the wallet.
const torn = readdirSync(KEEPER).filter((f) => f.startsWith('spend.log.torn-'));
if (torn.length) console.log(`            torn tails moved aside at start: ${torn.map((f) => `${f} (${statSync(join(KEEPER, f)).size} B)`).join(', ')}`);

// ---- wallet trend (the agent's per-tick snapshots, plus one now)
const snaps = log.filter((r) => r.kind === 'wallet');
if (!EVIDENCE) try {
  const r = await fetch(WALLET_RPC, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: '0', method: 'get_accounts' }), signal: AbortSignal.timeout(30_000) });
  const a = (await r.json()).result;
  snaps.push({ ts: new Date().toISOString(), total: String(a.total_balance), total_unlocked: String(a.total_unlocked_balance), now: true });
} catch (e) {
  // A wallet-rpc that blocks on a daemon it cannot reach is the phone being offline, not the soak
  // being sick (2026-10-04: a Wi-Fi hand-over paged the Owner twice). Count it only when the
  // phone itself is online.
  const online = await fetch('https://api.github.com/', { method: 'HEAD', signal: AbortSignal.timeout(15_000) }).then(() => true, () => false);
  if (online) unhealthy.push('wallet-rpc not answering');
  else console.log('wallet-rpc  not answering while the phone is offline (api.github.com unreachable): not counted');
}
if (snaps.length > 0) {
  const first = snaps[0], last = snaps.at(-1);
  const days = Math.max((Date.parse(last.ts) - Date.parse(first.ts)) / 86400e3, 1e-9);
  const drop = BigInt(first.total) - BigInt(last.total);
  const perDay = days > 0.02 ? BigInt(Math.round(Number(drop) / days)) : 0n;
  console.log(`wallet      ${xmr(first.total)} → ${xmr(last.total)} XMR (all accounts) over ${(days * 24).toFixed(1)} h: −${xmr(drop)}` +
    (days > 0.02 ? `, ≈ ${xmr(perDay)}/day, 14 d ≈ ${xmr(perDay * 14n)}` : '') + `; unlocked now ${xmr(last.total_unlocked)}`);
  console.log(`            drop vs fees logged: ${xmr(drop - fees)} XMR (0 when the soak started with the keeper log)`);
  const daily = new Map();
  for (const s of snaps) daily.set(s.ts.slice(0, 10), s.total);
  if (daily.size > 1) console.log('            daily close: ' + [...daily].map(([d, t]) => `${d.slice(5)} ${xmr(t)}`).join(' · '));
}
finish(unhealthy);
