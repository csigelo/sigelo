// SPDX-License-Identifier: MIT
/**
 * The wallet-rpc canary (ROADMAP §5.5): the `monero-wallet-rpc` interface the keeper depends
 * on, pinned. Method names, the parameters the keeper sends and the result fields it reads —
 * the same fields `service.ts` parses (`asBuilt`, `held`, `receive`, `history`, `bind`,
 * `/delegate`, the revoke sweep). An upstream change of any of them (FCMP++/Carrot is the one
 * expected) must fail here before it fails a payment.
 *
 *   pure, always: the RPC version rule (`rpcVersionOk`) over the edges of its range;
 *   read-only, against the LIVE wallet on 127.0.0.1:38083 (SKIP if unreachable): get_version
 *   (RPC 1.30 to 1.33 accepted, see RPC_RANGE), get_height, get_balance, get_address, validate_address, sign in both
 *   modes, verify, get_transfers, and the JSON-RPC error shape;
 *   mutating, against the mock wallet `test.ts` runs every keeper test on: create_account,
 *   create_address, transfer (do_not_relay + get_tx_metadata), relay_tx, sweep_all
 *   (subaddr_indices_all), sign — so the mock cannot drift from the shapes pinned here.
 *
 * Run from test.ts (one line, sharing its counters and its mock), or alone as
 * `node dist/canary.js`, which runs the pure and live halves, SKIPs the mock half and prints ALL PASS.
 */
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PINNED_RPC, RPC_RANGE, rpcVersionOk } from './rpcrange.js';

type Ok = (name: string, cond: boolean, detail?: string) => void;
type Skip = (name: string, reason: string) => void;
type R = Record<string, unknown>;
interface Mock { port: number; close: () => Promise<void> }
export interface CanaryCtx {
  ok: Ok; skip: Skip;
  mockWallet?: (mode: { balances?: Record<number, { balance: number; unlocked: number }> }) => Promise<Mock>;
  live?: string;
}

/**
 * wallet-rpc's `get_version`: `version` = major << 16 | minor. PINNED_RPC is the one version
 * every check here, the whole spend/ suite and the stock-wallet oracle actually RAN against:
 * 1.30 = v0.18.5.0, on the soak host (2026-09-29). The rest of RPC_RANGE is accepted on a SOURCE
 * DIFF only, never run: 1.31 = v0.18.5.1 (2026-07-08), 1.33 = the FCMP++ stressnet beta
 * (seraphis-migration v0.19.0.0-beta.3.0, 2026-09-25); neither changes a method, parameter or
 * result field this file pins (ROADMAP M6). A version outside the range FAILS: re-run the oracle
 * and the whole spend/ suite against it, then move the ceiling (or the floor) in rpcrange.ts.
 */
// The constants live in rpcrange.ts, which the package ships (`sigelo-spend doctor` checks the
// wallet-rpc against the same range); the reasoning above stays here, with the checks.
export { PINNED_RPC, RPC_RANGE, rpcVersionOk };

const uint = (x: unknown): boolean => typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
const hex64 = (x: unknown): boolean => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
const addr = (x: unknown): boolean => typeof x === 'string' && /^[1-9A-HJ-NP-Za-km-z]{95}$/.test(x);
const str = (x: unknown): boolean => typeof x === 'string';
const plain = (x: unknown): x is R => typeof x === 'object' && x !== null && !Array.isArray(x);
const lists = (r: R, keys: string[]): boolean => {
  const n = Array.isArray(r[keys[0]!]) ? (r[keys[0]!] as unknown[]).length : -1;
  return n >= 1 && keys.every((k) => Array.isArray(r[k]) && (r[k] as unknown[]).length === n);
};

/** Each pinned result, as a predicate over the `result` object. Exported for the weekly job. */
export const SHAPES: Record<string, (r: R) => boolean> = {
  get_version: (r) => uint(r['version']) && typeof r['release'] === 'boolean',
  get_height: (r) => uint(r['height']) && (r['height'] as number) > 0,
  get_balance: (r) => uint(r['balance']) && uint(r['unlocked_balance']) && (r['blocks_to_unlock'] === undefined || uint(r['blocks_to_unlock'])),
  get_address: (r) => addr(r['address']) && Array.isArray(r['addresses']) &&
    (r['addresses'] as unknown[]).every((a) => plain(a) && uint(a['address_index']) && (a['label'] === undefined || str(a['label']))),
  validate_address: (r) => typeof r['valid'] === 'boolean' && typeof r['integrated'] === 'boolean' && typeof r['subaddress'] === 'boolean' && str(r['nettype']),
  sign: (r) => typeof r['signature'] === 'string' && r['signature'].startsWith('SigV2'),
  verify: (r) => typeof r['good'] === 'boolean' && (r['signature_type'] === undefined || str(r['signature_type'])),
  // `in` and `pool` are absent, not empty, when there is nothing to list.
  get_transfers: (r) => ['in', 'pool'].every((k) => r[k] === undefined || (Array.isArray(r[k]) && (r[k] as unknown[]).every((t) =>
    plain(t) && plain(t['subaddr_index']) && uint(t['subaddr_index']['major']) && uint(t['subaddr_index']['minor']) &&
    uint(t['amount']) && hex64(t['txid']) && addr(t['address']) && uint(t['timestamp'])))),
  create_account: (r) => uint(r['account_index']) && addr(r['address']),
  create_address: (r) => addr(r['address']) && uint(r['address_index']),
  transfer: (r) => hex64(r['tx_hash']) && uint(r['fee']) && typeof r['tx_metadata'] === 'string' && r['tx_metadata'] !== '',
  relay_tx: (r) => hex64(r['tx_hash']),
  sweep_all: (r) => lists(r, ['tx_hash_list', 'fee_list', 'amount_list', 'tx_metadata_list']) &&
    (r['tx_hash_list'] as unknown[]).every(hex64) && [...(r['fee_list'] as unknown[]), ...(r['amount_list'] as unknown[])].every(uint) &&
    (r['tx_metadata_list'] as unknown[]).every((m) => typeof m === 'string' && m !== ''),
};

async function rpc(url: string, method: string, params: unknown): Promise<{ result?: R; error?: R } | null> {
  try {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }), signal: AbortSignal.timeout(20_000) });
    return await res.json() as { result?: R; error?: R };
  } catch { return null; }
}

export async function canary({ ok, skip, mockWallet, live = 'http://127.0.0.1:38083/json_rpc' }: CanaryCtx): Promise<void> {
  const pinned = (where: string, method: string, r: { result?: R; error?: R } | null): R => {
    const res = r?.result;
    ok(`canary ${where}: ${method} result has the pinned shape`, plain(res) && SHAPES[method]!(res), JSON.stringify(r).slice(0, 400));
    return plain(res) ? res : {};
  };

  // ---------------------------------------------------------------- pure: the version rule
  const edges: [number, number, boolean][] = [[1, 29, false], [1, 30, true], [1, 31, true], [1, 33, true], [1, 34, false], [0, 30, false], [2, 30, false]];
  for (const [maj, min, want] of edges) ok(`canary: RPC ${maj}.${min} is ${want ? 'accepted' : 'refused'}`, rpcVersionOk(maj, min) === want);

  // ---------------------------------------------------------------- live, read-only
  const version = await rpc(live, 'get_version', {});
  if (version === null) {
    skip(`canary live: wallet-rpc ${live}`, 'unreachable');
  } else {
    const v = pinned('live', 'get_version', version);
    const [major, minor] = [Number(v['version']) >>> 16, Number(v['version']) & 0xffff];
    const range = `${RPC_RANGE.major}.${RPC_RANGE.minMinor}–${RPC_RANGE.major}.${RPC_RANGE.maxMinor}`;
    console.log(`canary live: wallet-rpc RPC version ${major}.${minor} (accepted ${range}; ran against ${PINNED_RPC.major}.${PINNED_RPC.minor})`);
    ok(`canary live: wallet-rpc RPC version ${major}.${minor} is within ${range}`, rpcVersionOk(major, minor),
      `got ${major}.${minor}, outside ${range} — re-run the oracle and the whole spend/ suite against it, then move the ceiling in spend/canary.ts (RPC_RANGE)`);
    pinned('live', 'get_height', await rpc(live, 'get_height', {}));
    pinned('live', 'get_balance', await rpc(live, 'get_balance', { account_index: 0 }));
    // As /bind asks: address_index [0] narrows `addresses` to (0, 0).
    const base = pinned('live', 'get_address', await rpc(live, 'get_address', { account_index: 0, address_index: [0] }));
    const a = String(base['address']);
    ok('canary live: get_address with address_index [0] lists exactly (0, 0)',
      Array.isArray(base['addresses']) && base['addresses'].length === 1 && (base['addresses'][0] as R)['address_index'] === 0, JSON.stringify(base['addresses']));
    const va = pinned('live', 'validate_address', await rpc(live, 'validate_address', { address: a }));
    ok('canary live: validate_address calls the base address a valid standard stagenet address',
      va['valid'] === true && va['integrated'] === false && va['subaddress'] === false && va['nettype'] === 'stagenet', JSON.stringify(va));
    // `sign` honours `signature_type`, and `verify` reports which mode it saw: /bind depends on both.
    for (const mode of ['view', 'spend'] as const) {
      const data = `sigelo\ncanary ${mode}`;
      const s = pinned('live', 'sign', await rpc(live, 'sign', { data, account_index: 0, address_index: 0, signature_type: mode }));
      const good = pinned('live', 'verify', await rpc(live, 'verify', { data, address: a, signature: s['signature'] }));
      ok(`canary live: verify accepts a ${mode}-mode sign and names the mode`, good['good'] === true && good['signature_type'] === mode, JSON.stringify(good));
      const bad = pinned('live', 'verify', await rpc(live, 'verify', { data: data + ' ', address: a, signature: s['signature'] }));
      ok(`canary live: verify refuses a tampered ${mode}-mode message`, bad['good'] === false, JSON.stringify(bad));
    }
    // As /history asks: account 0 only, every row carrying its subaddr_index.
    const tr = pinned('live', 'get_transfers', await rpc(live, 'get_transfers', { in: true, pool: true, account_index: 0 }));
    const rows = [...(Array.isArray(tr['in']) ? tr['in'] : []), ...(Array.isArray(tr['pool']) ? tr['pool'] : [])] as R[];
    ok('canary live: get_transfers with account_index answers for that account only', rows.every((t) => (t['subaddr_index'] as R)['major'] === 0), `${rows.length} rows`);
    const e = await rpc(live, 'no_such_method', {});
    ok('canary live: an error is {error: {code, message}} with no result', plain(e?.error) && typeof e.error['code'] === 'number' && str(e.error['message']) && e.result === undefined, JSON.stringify(e));
  }

  // ---------------------------------------------------------------- mock, mutating
  if (mockWallet === undefined) { skip('canary mock: mutating methods', 'run from test.ts (npm test), which owns the mock wallet'); return; }
  const w = await mockWallet({ balances: { 1: { balance: 3000000000, unlocked: 3000000000 } } });
  const url = `http://127.0.0.1:${w.port}/json_rpc`;
  try {
    const acct = pinned('mock', 'create_account', await rpc(url, 'create_account', { label: 'sigelo delegate canary' }));
    pinned('mock', 'create_address', await rpc(url, 'create_address', { account_index: acct['account_index'], label: 'canary' }));
    const built = pinned('mock', 'transfer', await rpc(url, 'transfer', {
      account_index: 1, destinations: [{ address: String(acct['address']), amount: 1000 }],
      unlock_time: 0, priority: 1, do_not_relay: true, get_tx_metadata: true,
    }));
    const relayed = pinned('mock', 'relay_tx', await rpc(url, 'relay_tx', { hex: built['tx_metadata'] }));
    ok('canary mock: relay_tx answers the tx_hash transfer built', relayed['tx_hash'] === built['tx_hash'], JSON.stringify([built['tx_hash'], relayed['tx_hash']]));
    const swept = pinned('mock', 'sweep_all', await rpc(url, 'sweep_all', {
      address: String(acct['address']), account_index: 1, subaddr_indices_all: true, priority: 1, unlock_time: 0, do_not_relay: true, get_tx_metadata: true,
    }));
    pinned('mock', 'relay_tx', await rpc(url, 'relay_tx', { hex: (swept['tx_metadata_list'] as string[] | undefined)?.[0] }));
    pinned('mock', 'sign', await rpc(url, 'sign', { data: 'sigelo\ncanary', account_index: 1, address_index: 0, signature_type: 'spend' }));
    for (const m of ['get_balance', 'get_address', 'get_height'] as const) pinned('mock', m, await rpc(url, m, { account_index: 1 }));
  } finally { await w.close(); }
}

// Alone: `node dist/canary.js` — its own counters, the live half only.
if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let passed = 0, failed = 0, skipped = 0;
  await canary({
    ok: (name, cond, detail = '') => { if (cond) passed++; else { failed++; console.error(`FAIL ${name}${detail === '' ? '' : ` — ${detail}`}`); } },
    skip: (name, reason) => { skipped++; console.log(`SKIP ${name} — ${reason}`); },
    ...(process.env['SIGELO_CANARY_RPC'] !== undefined && { live: process.env['SIGELO_CANARY_RPC'] }),
  });
  console.log(`${passed} passed, ${failed} failed, ${skipped} skipped`);
  if (failed > 0) process.exit(1);
  console.log('ALL PASS');
}
