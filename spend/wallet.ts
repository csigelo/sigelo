#!/usr/bin/env node
// SPDX-License-Identifier: MIT
/**
 * sigelo-wallet — the agent's side of the keeper (MONERO.md §4.2, §8 G3).
 *
 *   sigelo-wallet balance
 *   sigelo-wallet receive [note]
 *   sigelo-wallet pay <to> <amount> [purpose] [--ref R] [--atomic]
 *   sigelo-wallet history [n]
 *   (any verb) --json
 *
 * and, for an agent whose policy lets it delegate (§4.3; never in the weak-agent snippet, §9
 * decision 9):
 *
 *   sigelo-wallet delegate <name> <fund-amount> [--per-tx X] [--per-day Y] [--allow label=addr ...] [--max-delegates N]
 *   sigelo-wallet fund <name> <amount>
 *   sigelo-wallet revoke <name>
 *   sigelo-wallet delegates
 *
 * Built for weak models: one line out per verb (one per entry for `history`), a status word
 * first, an exit code per status, no keys, no JSON-RPC, no atomic units. It is a thin client
 * of the keeper's loopback HTTP (`SIGELO_WALLET_URL`, `SIGELO_WALLET_TOKEN`); every decision
 * is the keeper's. A retry is safe because the keeper derives a `ref` from (to, amount,
 * purpose) and answers a repeat with the first outcome.
 */
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseBytes } from 'sigelo';

export type Status = 'done' | 'refused' | 'try_later' | 'waiting' | 'uncertain';
export const EXIT: Record<Status, number> = { done: 0, refused: 1, try_later: 2, waiting: 3, uncertain: 4 };
/** `message` is what is printed: one line, or one line per entry for `history`. */
export interface Outcome { status: Status; code: string; message: string; data?: unknown }
type Env = Record<string, string | undefined>;
type Body = Record<string, unknown>;

// ---------------------------------------------------------------- amounts

const UNIT = 10n ** 12n;
const MAX_ATOMIC = 9007199254740991n; // epee sends JSON numbers; the keeper refuses more anyway
/**
 * XMR as the agent writes it → atomic units, by string arithmetic: never a float, which cannot
 * hold 0.1 exactly. At most 12 decimals; no sign, exponent, blank or leading zeros. Returns
 * undefined for anything else, and for zero or more than 2^53−1 atomic units.
 */
export function toAtomic(xmr: string, atomic = false): string | undefined {
  const m = (atomic ? /^([1-9][0-9]*)$/ : /^(0|[1-9][0-9]*)(?:\.([0-9]{1,12}))?$/).exec(xmr);
  if (m === null) return undefined;
  const a = atomic ? BigInt(m[1]!) : BigInt(m[1]!) * UNIT + BigInt((m[2] ?? '').padEnd(12, '0'));
  return a === 0n || a > MAX_ATOMIC ? undefined : a.toString();
}
/** Atomic units → XMR, exact, trailing zeros dropped: 500000000000 → "0.5". */
export function toXmr(atomic: string | bigint): string {
  const a = BigInt(atomic);
  const frac = (a % UNIT).toString().padStart(12, '0').replace(/0+$/, '');
  return frac === '' ? `${a / UNIT}` : `${a / UNIT}.${frac}`;
}

// ---------------------------------------------------------------- the message table (§4.2)

const CLI = 'sigelo-wallet';
/** Every line this command prints on failure. The table in README.md is this object. */
export const LINES = {
  token: 'REFUSED: this wallet is not set up for you (unknown or revoked token). Tell your operator.',
  unset: 'REFUSED: this wallet is not set up for you (SIGELO_WALLET_URL or SIGELO_WALLET_TOKEN is not set). Tell your operator.',
  allowlist: (to: string) => `REFUSED: you are not allowed to pay ${to}. Ask the payee for an invoice file, or ask your operator to add them.`,
  contact: (name: string) => `REFUSED: you have no contact named ${name}. Use an address or an invoice file, or ask your operator to add them.`,
  destination: (to: string) => `REFUSED: ${to} is not an address you can pay here (wrong network, integrated, or mistyped). Ask the payee for a subaddress.`,
  invoiceFile: (path: string) => `REFUSED: ${path} is not a readable invoice file ({invoice, bundle}). Ask the payee to send it again.`,
  invoice: 'REFUSED: that invoice is already paid (or expired). Ask the payee for a new one.',
  per_tx_max: (cost: string, limit: string, fee: boolean) => `REFUSED: ${cost} XMR${fee ? ' with fee' : ''} is over your ${limit} XMR per-payment limit. Pay less, or ask your operator.`,
  per_period_max: (left: string, until: string) => `REFUSED: you have ${left} XMR left to spend${until}. Pay less, or wait.`,
  rate: 'TRY LATER: too many payments this minute. Run the same command in a minute.',
  rateReceive: 'TRY LATER: too many new addresses this minute. Run the same command in a minute.',
  locked: (min: number) => `TRY LATER: your money is locked for about ${min} minutes after a payment or deposit.`,
  confirming: 'TRY LATER: a payment is still confirming; your money is locked for about 20 minutes.',
  funds: (held: string) => `REFUSED: you hold ${held} XMR, not enough. Use ${CLI} receive to get paid, or ask your operator.`,
  approval: (ref: string) => `WAITING FOR APPROVAL (ref ${ref}): tell your operator, then run the same command again.`,
  uncertain: (txid: string) => `UNCERTAIN: the payment may have gone out (txid ${txid}). Do not pay again; tell your operator.`,
  unreachable: 'TRY LATER: the wallet service is not answering.',
  timeout: 'UNCERTAIN: the request timed out; the payment may have gone out. Run `sigelo-wallet history` before paying again.',
  wallet: 'TRY LATER: the wallet could not do that right now; nothing was sent. Run the same command later.',
  offline: 'TRY LATER: the wallet has no connection to the Monero network; nothing was sent. Run the same command later.',
  slow: 'TRY LATER: the wallet is still working on that payment (a slow network); nothing was sent. Run the same command in a few minutes.',
  clock: 'TRY LATER: the wallet service\'s clock is not set yet; nothing was sent. Run the same command later.',
  amount: 'REFUSED: amount must look like 0.05 (XMR, at most 12 decimals).',
  amountAtomic: 'REFUSED: with --atomic, amount must be a whole number of atomic units above 0, like 50000000000.',
  purpose: 'REFUSED: purpose must be at most 200 characters.',
  ref: 'REFUSED: --ref must be 1 to 128 characters.',
  conflict: (ref: string) => `REFUSED: ref ${ref} was already used for a different payment. Use a new --ref.`,
  service: (why: string) => `REFUSED: the wallet service refused (${why}). Tell your operator.`,
  usage: `REFUSED: unknown command. Use: ${CLI} balance | ${CLI} receive [note] | ${CLI} pay <to> <amount> [purpose] | ${CLI} history [n]`,
  // Delegation (§4.3): for harnesses and agents allowed to delegate, not for the weak-agent prompt.
  usageDelegation: `REFUSED: unknown command. Use: ${CLI} delegate <name> <fund-amount> [--per-tx X] [--per-day Y] [--allow label=addr ...] | ${CLI} fund <name> <amount> | ${CLI} revoke <name> | ${CLI} delegates`,
  allowArg: 'REFUSED: --allow takes label=address, like --allow bob=5B9n…',
  shownOnce: 'Give this to the delegate, it is shown once:',
};

const out = (status: Status, code: string, message: string, data?: unknown): Outcome => ({ status, code, message, ...(data !== undefined && { data }) });
const str = (x: unknown): string => (typeof x === 'string' ? x : '');

// ---------------------------------------------------------------- text from strangers
//
// An invoice file is written by the payee, and the log and the wallet carry labels, notes and
// purposes that may have been copied from one. None of it may reach the agent as anything but
// data (THREAT-MODEL §4): a newline would print a second line — a fake `PAID …` or an
// "operator note" — and an ESC or C1 byte is a terminal escape. So nothing external is printed
// raw unless it has a shape that cannot carry either.

/** C0 (newline and ESC included), DEL, C1, and the invisible and bidi-reordering format characters. */
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/g;
const u4 = (c: string): string => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;
/** JSON string syntax, with every character in `UNSAFE` escaped (JSON.stringify leaves C1 and bidi raw). */
const quote = (x: string): string => JSON.stringify(x).replace(UNSAFE, u4);
/** The keeper's own words: printed as they are, with any character in `UNSAFE` escaped in place. */
const clean = (x: string): string => x.replace(UNSAFE, u4);
const ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{95}$|^[1-9A-HJ-NP-Za-km-z]{106}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
/** An address, or a name: printed only in one of those two shapes (95/106 base58, the label rule), JSON-quoted otherwise. */
const ext = (x: string): string => (ADDRESS.test(x) || NAME.test(x) ? x : quote(x));
/** Free text (a purpose, a note, a path): printed as it is only when it is printable ASCII, JSON-quoted otherwise. */
const prose = (x: string): string => (/^[\x20-\x7e]*$/.test(x) ? x : quote(x));
/** A unix time as the agent reads it: `HH:MM UTC` within a day, the date too beyond. */
function when(ts: number, now = Date.now() / 1000): string {
  const iso = new Date(ts * 1000).toISOString();
  return ts - now < 86400 ? `${iso.slice(11, 16)} UTC` : `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

/**
 * A refusal from the keeper, in the table's words. `code` is the §4.1 check the keeper named
 * (service.ts `codeOf`); the numbers come from its `facts` and balance fields, never from
 * parsing its prose.
 */
export function explain(status: number, b: Body, shown = '', label?: string, verb = 'pay'): Outcome {
  const code = status === 401 ? 'token' : str(b['code']) || 'service';
  const f = (typeof b['facts'] === 'object' && b['facts'] !== null ? b['facts'] : {}) as Body;
  switch (code) {
    case 'token': return out('refused', code, LINES.token, b);
    case 'allowlist': return out('refused', code, label !== undefined ? LINES.contact(ext(label)) : LINES.allowlist(shown), b);
    case 'invoice': return out('refused', code, LINES.invoice, b);
    case 'to': case 'to.addr': case 'to.did': return out('refused', code, LINES.destination(shown), b);
    case 'amount': return out('refused', code, LINES.amount, b);
    case 'purpose': return out('refused', code, LINES.purpose, b);
    case 'ref': return out('refused', code, LINES.ref, b);
    case 'per_tx_max': return out('refused', code, LINES.per_tx_max(toXmr(str(f['cost']) || '0'), toXmr(str(f['limit']) || '0'), f['fee_included'] === true), b);
    case 'per_period_max': return out('refused', code, LINES.per_period_max(toXmr(str(f['left']) || '0'), typeof f['until'] === 'number' ? ` until ${when(f['until'])}` : ''), b);
    case 'rate_per_minute': return out('try_later', code, verb === 'receive' ? LINES.rateReceive : LINES.rate, b);
    case 'wallet_locked': {
      // blocks_to_unlock 0 with nothing unlocked: the money is change of a payment still in the
      // pool, which unlocks ~10 blocks after it is mined — about 20 minutes, not "0".
      const blocks = typeof b['blocks_to_unlock'] === 'number' ? b['blocks_to_unlock'] : 0;
      return out('try_later', code, blocks > 0 ? LINES.locked(blocks * 2) : LINES.confirming, b);
    }
    case 'wallet_funds': return out('refused', code, LINES.funds(typeof b['balance'] === 'string' ? toXmr(b['balance']) : 'less than that'), b);
    case 'approval': return out('waiting', code, LINES.approval(prose(str(b['ref']))), b);
    case 'relay_failed': return out('uncertain', code, LINES.uncertain(prose(str(b['txid']))), b);
    case 'repeat': return out('refused', code, LINES.conflict(prose(str(b['ref']))), b);
    case 'wallet': return out('try_later', code, LINES.wallet, b);
    case 'wallet_offline': return out('try_later', code, LINES.offline, b);
    case 'wallet_slow': return out('try_later', code, LINES.slow, b);
    case 'clock_behind': return out('try_later', code, LINES.clock, b);
    default: return out('refused', code, LINES.service(clean(str(b['error'])) || `HTTP ${status}`), b);
  }
}

// ---------------------------------------------------------------- the keeper

/**
 * One keeper call. `spends`: the call may move money (`pay`, `fund`). A pay can take the wallet
 * a while to build, so the wait is long (300 s; `SIGELO_WALLET_TIMEOUT_MS` for harnesses and
 * tests). A spend that times out is NOT "try later": the keeper may have relayed it after we
 * stopped listening, so it is UNCERTAIN, and the agent checks `history` before paying again.
 * Anything else that fails to answer is TRY LATER.
 */
async function call(env: Env, method: 'GET' | 'POST', path: string, body?: unknown, spends = false): Promise<{ status: number; body: Body } | Outcome> {
  const [base, token] = [env['SIGELO_WALLET_URL'], env['SIGELO_WALLET_TOKEN']];
  if (!base || !token) return out('refused', 'token', LINES.unset);
  const wait = /^[1-9][0-9]{0,8}$/.test(env['SIGELO_WALLET_TIMEOUT_MS'] ?? '') ? Number(env['SIGELO_WALLET_TIMEOUT_MS']) : 300_000;
  try {
    const res = await fetch(base.replace(/\/+$/, '') + path, {
      method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      ...(body !== undefined && { body: JSON.stringify(body) }), signal: AbortSignal.timeout(wait),
    });
    const b = await res.json();
    if (typeof b !== 'object' || b === null) throw new Error('reply is not an object');
    return { status: res.status, body: b as Body };
  } catch (e) {
    if (spends && (e as { name?: unknown })?.name === 'TimeoutError') return out('uncertain', 'timeout', LINES.timeout);
    return out('try_later', 'unreachable', LINES.unreachable);
  }
}
const failed = (r: { status: number; body: Body } | Outcome): r is Outcome => 'message' in r;

/**
 * `<to>` (§4.2): a path to a file the payee sent (`{invoice, bundle}`) → a DID payment with
 * invoice; something shaped like a Monero address (95 or 106 base58 characters — longer than
 * any contact name) → `{addr}`; anything else → `{label}`, a name from the agent's allowlist.
 * Only a path with a `/` or ending `.json` is read as a file, so a file in the working
 * directory can never shadow a contact's name.
 */
function destination(to: string): { to: Body; shown: string; label?: string } | Outcome {
  if (to.includes('/') || to.endsWith('.json')) {
    let f: unknown;
    try { f = parseBytes(readFileSync(to)); } catch { return out('refused', 'to', LINES.invoiceFile(prose(to))); }
    const o = f as Body, inv = o?.['invoice'] as Body | undefined, body = inv?.['body'] as Body | undefined;
    if (typeof f !== 'object' || f === null || Object.keys(o).sort().join() !== 'bundle,invoice' || typeof body !== 'object' || body === null ||
      typeof body['addr'] !== 'string' || typeof body['did'] !== 'string') return out('refused', 'to', LINES.invoiceFile(prose(to)));
    // The payee wrote `addr`: it is shown only if it looks like an address (`ext`).
    return { to: { addr: body['addr'], did: body['did'], bundle: o['bundle'], invoice: inv }, shown: ext(body['addr']) };
  }
  if (ADDRESS.test(to)) return { to: { addr: to }, shown: to };
  return { to: { label: to }, shown: ext(to), label: to };
}

// ---------------------------------------------------------------- verbs

async function balance(env: Env): Promise<Outcome> {
  const r = await call(env, 'GET', '/balance');
  if (failed(r)) return r;
  if (r.status !== 200) return explain(r.status, r.body, '', undefined, 'balance');
  const b = r.body, held = BigInt(str(b['balance']) || '0'), free = BigInt(str(b['unlocked_balance']) || '0');
  const blocks = typeof b['blocks_to_unlock'] === 'number' && b['blocks_to_unlock'] > 0 ? b['blocks_to_unlock'] : 10;
  const locked = held > free ? `, ${toXmr(held - free)} locked for about ${blocks * 2} min` : '';
  const period = b['period_seconds'] === 86400 ? 'today' : 'this period';
  return out('done', 'ok', `BALANCE ${toXmr(held)} XMR (${toXmr(free)} spendable now${locked}; ${toXmr(str(b['remaining']) || '0')} XMR left to spend ${period}, at most ${toXmr(str(b['per_tx_max']) || '0')} per payment)`, b);
}

async function receive(env: Env, note: string): Promise<Outcome> {
  if (note.length > 200) return out('refused', 'purpose', LINES.purpose);
  const r = await call(env, 'POST', '/receive', note === '' ? {} : { purpose: note });
  if (failed(r)) return r;
  if (r.status !== 200) return explain(r.status, r.body, '', undefined, 'receive');
  return out('done', 'ok', `RECEIVE ${str(r.body['address'])}`, r.body);
}

async function pay(env: Env, args: string[], ref: string | undefined, atomic: boolean): Promise<Outcome> {
  const [to, amountIn] = args;
  if (to === undefined || amountIn === undefined) return out('refused', 'usage', LINES.usage);
  const amount = toAtomic(amountIn, atomic);
  if (amount === undefined) return out('refused', 'amount', atomic ? LINES.amountAtomic : LINES.amount);
  const purpose = args.slice(2).join(' ') || '(none)';
  if (purpose.length > 200) return out('refused', 'purpose', LINES.purpose);
  if (ref !== undefined && (ref === '' || ref.length > 128)) return out('refused', 'ref', LINES.ref);
  const d = destination(to);
  if ('message' in d) return d;
  const r = await call(env, 'POST', '/pay', { to: d.to, amount, purpose, ...(ref !== undefined && { ref }) }, true);
  if (failed(r)) return r;
  const b = r.body, fee = `(+${toXmr(str(b['fee']) || '0')} fee)`;
  if (r.status === 200 && b['dry_run'] === true) return out('done', 'dry_run', `DRY RUN: ${toXmr(amount)} XMR ${fee} to ${d.shown} would be paid; nothing was sent.`, b);
  if (r.status === 200 && b['already_paid'] === true) return out('done', 'already_paid', `ALREADY PAID ${toXmr(amount)} XMR ${fee} to ${d.shown}. txid ${str(b['txid'])}. Not paid again.`, b);
  if (r.status === 200) return out('done', 'ok', `PAID ${toXmr(amount)} XMR ${fee} to ${d.shown}. txid ${str(b['txid'])}`, b);
  if (r.status === 202) return out('waiting', 'approval', LINES.approval(prose(str(b['ref']))), b);
  return explain(r.status, b, d.shown, d.label);
}

const VERB: Record<string, string> = { relayed: 'paid', relay_failed: 'maybe paid (UNCERTAIN)', intent: 'maybe paid (UNCERTAIN)', pending: 'waiting for approval to pay', approved: 'approved, not yet paid (run the same pay again)' };
async function history(env: Env, n: string | undefined): Promise<Outcome> {
  if (n !== undefined && !/^[1-9][0-9]?$|^100$/.test(n)) return out('refused', 'usage', LINES.usage);
  const r = await call(env, 'GET', `/history${n === undefined ? '' : `?n=${n}`}`);
  if (failed(r)) return r;
  if (r.status !== 200) return explain(r.status, r.body, '', undefined, 'history');
  const entries = (Array.isArray(r.body['entries']) ? r.body['entries'] : []) as Body[];
  if (entries.length === 0) return out('done', 'ok', 'HISTORY: no payments in or out yet.', r.body);
  const lines = entries.map((e) => {
    const at = new Date(Number(e['ts']) * 1000).toISOString().slice(0, 16).replace('T', ' ');
    const xmr = `${toXmr(str(e['amount']) || '0')} XMR`;
    // Labels, notes and purposes may be a stranger's words (a receive note copied from an
    // invoice memo): addresses and labels in their own shapes, free text as printable ASCII.
    if (e['dir'] === 'out') return `${at} ${VERB[str(e['status'])] ?? 'paid'} ${xmr} to ${ext(str(e['label']) || str(e['to']))} (${prose(str(e['purpose']))})`;
    const how = e['status'] === 'pool' ? 'incoming (unconfirmed)' : e['status'] === 'locked' ? 'received (locked)' : 'received';
    return `${at} ${how} ${xmr} at ${ext(str(e['address']))}${str(e['note']) === '' ? '' : ` (${prose(str(e['note']))})`}`;
  });
  return out('done', 'ok', lines.join('\n'), r.body);
}

// ---------------------------------------------------------------- delegation (§4.3)

interface DelegateOpts { perTx?: string; perDay?: string; allow: string[]; maxDelegates?: string; atomic: boolean }
const amountOr = (x: string, atomic: boolean): string | undefined => (x === '0' ? '0' : toAtomic(x, atomic));

/**
 * `delegate <name> <fund>`: the keeper creates the delegate and answers with its token ONCE.
 * The token and URL are printed even when the funding was refused or is uncertain — there is
 * no second chance to see them — and the exit status is then the funding's.
 */
async function delegate(env: Env, args: string[], o: DelegateOpts): Promise<Outcome> {
  const [name, fundIn] = args;
  if (args.length !== 2 || name === undefined || fundIn === undefined) return out('refused', 'usage', LINES.usageDelegation);
  const fund = amountOr(fundIn, o.atomic);
  if (fund === undefined) return out('refused', 'amount', o.atomic ? LINES.amountAtomic : LINES.amount);
  const caps: Body = {};
  for (const [k, v] of [['per_tx_max', o.perTx], ['per_period_max', o.perDay]] as const) {
    if (v === undefined) continue;
    const a = toAtomic(v, o.atomic);
    if (a === undefined) return out('refused', 'amount', o.atomic ? LINES.amountAtomic : LINES.amount);
    caps[k] = a;
  }
  if (o.maxDelegates !== undefined) {
    if (!/^(0|[1-9][0-9]{0,5})$/.test(o.maxDelegates)) return out('refused', 'usage', LINES.usageDelegation);
    caps['max_delegates'] = Number(o.maxDelegates);
  }
  const allow: Body[] = [];
  for (const a of o.allow) {
    const i = a.indexOf('=');
    if (i < 1 || i === a.length - 1) return out('refused', 'usage', LINES.allowArg);
    allow.push({ label: a.slice(0, i), addr: a.slice(i + 1) });
  }
  const r = await call(env, 'POST', '/delegate', { name, fund, ...(Object.keys(caps).length > 0 && { caps }), ...(o.allow.length > 0 && { allow }) });
  if (failed(r)) return r;
  if (r.status !== 200) return explain(r.status, r.body, '', undefined, 'delegate');
  const b = r.body, f = b['fund'] as Body | null;
  let funded: Outcome = out('done', 'ok', 'not funded (fund 0)');
  if (f !== null && typeof f === 'object') {
    const fee = `(+${toXmr(str(f['fee']) || '0')} fee)`;
    funded = f['http'] === 200 ? out('done', 'ok', `funded ${toXmr(fund)} XMR ${fee}, txid ${str(f['txid'])}`)
      : (() => { const e = explain(Number(f['http']), f, name, undefined, 'fund'); return { ...e, message: `NOT FUNDED — ${e.message}` }; })();
  }
  const url = (env['SIGELO_WALLET_URL'] ?? '').replace(/\/+$/, '') || str(b['url']);
  return out(funded.status, funded.code, [
    `DELEGATE ${ext(name)} created: account ${String(b['account'])}, ${clean(str(b['did']))}; ${funded.message}`,
    LINES.shownOnce, `SIGELO_WALLET_URL=${clean(url)}`, `SIGELO_WALLET_TOKEN=${clean(str(b['token']))}`,
  ].join('\n'), b);
}

async function fund(env: Env, args: string[], atomic: boolean): Promise<Outcome> {
  const [name, amountIn] = args;
  if (args.length !== 2 || name === undefined || amountIn === undefined) return out('refused', 'usage', LINES.usageDelegation);
  const amount = toAtomic(amountIn, atomic);
  if (amount === undefined) return out('refused', 'amount', atomic ? LINES.amountAtomic : LINES.amount);
  const r = await call(env, 'POST', '/fund', { name, amount }, true);
  if (failed(r)) return r;
  const b = r.body, fee = `(+${toXmr(str(b['fee']) || '0')} fee)`;
  if (r.status === 200 && b['already_paid'] === true) return out('done', 'already_paid', `ALREADY FUNDED ${ext(name)} ${toXmr(amount)} XMR ${fee}. txid ${str(b['txid'])}. Not paid again.`, b);
  if (r.status === 200) return out('done', 'ok', `FUNDED ${ext(name)} ${toXmr(amount)} XMR ${fee}. txid ${str(b['txid'])}`, b);
  return explain(r.status, b, ext(name), undefined, 'fund');
}

/** One line per swept account, after the headline. */
function sweptLine(s: Body): string {
  const at = `${ext(str(s['name']))} (account ${String(s['account'])})`;
  if (s['status'] === 'swept') return `  ${at}: swept ${toXmr(str(s['amount']) || '0')} XMR (+${toXmr(str(s['fee']) || '0')} fee) to your account.`;
  if (s['status'] === 'uncertain') return `  ${at}: UNCERTAIN — a sweep may have gone out; tell your operator. ${clean(JSON.stringify(s['txs']))}`;
  if (s['status'] === 'skipped' && s['reason'] === 'empty') return `  ${at}: empty, nothing to sweep.`;
  const holds = typeof s['balance'] === 'string' && /^[1-9][0-9]*$/.test(s['balance']) ? ` and still holds ${toXmr(s['balance'])} XMR` : '';
  return `  ${at}: not swept (${clean(str(s['reason']) || str(s['error']))})${holds}; run revoke again later.`;
}

async function revoke(env: Env, args: string[]): Promise<Outcome> {
  if (args.length !== 1) return out('refused', 'usage', LINES.usageDelegation);
  const r = await call(env, 'POST', '/revoke', { name: args[0] });
  if (failed(r)) return r;
  if (r.status !== 200) return explain(r.status, r.body, '', undefined, 'revoke');
  const b = r.body, sweeps = (Array.isArray(b['sweeps']) ? b['sweeps'] : []) as Body[];
  const cascade = (Array.isArray(b['cascade']) ? b['cascade'] : []) as string[];
  const below = cascade.length > 1 ? ` and its delegates ${cascade.slice(1).map((n) => ext(String(n))).join(', ')}` : '';
  const head = b['already'] === true ? `ALREADY REVOKED ${ext(args[0]!)}${below}; swept again:` : `REVOKED ${ext(args[0]!)}${below}: their tokens no longer work.`;
  const unsure = sweeps.some((s) => s['status'] === 'uncertain');
  return out(unsure ? 'uncertain' : 'done', unsure ? 'relay_failed' : 'ok', [head, ...sweeps.map(sweptLine)].join('\n'), b);
}

async function listDelegates(env: Env): Promise<Outcome> {
  const r = await call(env, 'GET', '/delegates');
  if (failed(r)) return r;
  if (r.status !== 200) return explain(r.status, r.body, '', undefined, 'delegates');
  const b = r.body, list = (Array.isArray(b['delegates']) ? b['delegates'] : []) as Body[];
  const head = `DELEGATES: ${list.length}; you may create ${String(b['left'])} more (of ${String(b['max_delegates'])}).`;
  const lines = list.map((d) => {
    const c = (d['caps'] ?? {}) as Body, held = typeof d['balance'] === 'string' ? `holds ${toXmr(d['balance'])} XMR` : 'balance unknown';
    const name = ext(str(d['name']));
    if (d['status'] !== 'live') return `  ${name} (account ${String(d['account'])}) ${clean(String(d['status']).toUpperCase())}, ${held}${d['holds_funds'] === true ? ` — run ${CLI} revoke ${name} to sweep it` : ''}`;
    return `  ${name} (account ${String(d['account'])}, under ${ext(str(d['parent']))}) live, ${held}; at most ${toXmr(str(c['per_tx_max']) || '0')} per payment, ${toXmr(str(c['per_period_max']) || '0')} per period`;
  });
  return out('done', 'ok', [head, ...lines].join('\n'), b);
}

/**
 * The whole command, testable without a process: argv after the program name, and an env.
 * Whatever a verb built, no line of it carries a control or format character: the last fence
 * after the per-field rules above, since a line break inside one field is already escaped.
 */
export async function run(argv: string[], env: Env): Promise<Outcome> {
  const o = await verb(argv, env);
  return { ...o, message: o.message.split('\n').map(clean).join('\n') };
}

async function verb(argv: string[], env: Env): Promise<Outcome> {
  const pos: string[] = [];
  let ref: string | undefined, atomic = false;
  const d: DelegateOpts = { allow: [], atomic: false };
  let delegation = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--ref') { ref = argv[++i] ?? ''; continue; }
    if (a === '--atomic') { atomic = true; continue; }
    if (a === '--json') continue;
    if (a === '--per-tx') { d.perTx = argv[++i] ?? ''; delegation = true; continue; }
    if (a === '--per-day') { d.perDay = argv[++i] ?? ''; delegation = true; continue; }
    if (a === '--allow') { d.allow.push(argv[++i] ?? ''); delegation = true; continue; }
    if (a === '--max-delegates') { d.maxDelegates = argv[++i] ?? ''; delegation = true; continue; }
    if (a.startsWith('--')) return out('refused', 'usage', LINES.usage);
    pos.push(a);
  }
  const [verb, ...rest] = pos;
  if (delegation && verb !== 'delegate') return out('refused', 'usage', LINES.usage);
  if (verb === 'delegate') return delegate(env, rest, { ...d, atomic });
  if (verb === 'fund') return fund(env, rest, atomic);
  if (verb === 'revoke') return revoke(env, rest);
  if (verb === 'delegates' && rest.length === 0) return listDelegates(env);
  if (verb === 'balance' && rest.length === 0) return balance(env);
  if (verb === 'receive') return receive(env, rest.join(' '));
  if (verb === 'pay') return pay(env, rest, ref, atomic);
  if (verb === 'history' && rest.length <= 1) return history(env, rest[0]);
  return out('refused', 'usage', LINES.usage);
}

async function main(argv: string[]): Promise<void> {
  const o = await run(argv, process.env);
  // --json (§4.2) is for harnesses: {status, code, message} and the keeper's answer.
  // JSON.stringify escapes C0 but not C1 or bidi characters; those are escaped too.
  console.log(argv.includes('--json') ? JSON.stringify({ status: o.status, code: o.code, message: o.message, ...(o.data !== undefined && { data: o.data }) }).replace(UNSAFE, u4) : o.message);
  process.exitCode = EXIT[o.status];
}

const self = fileURLToPath(import.meta.url);
if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(self)) {
  main(process.argv.slice(2)).catch(() => { console.log(LINES.unreachable); process.exitCode = EXIT.try_later; });
}
