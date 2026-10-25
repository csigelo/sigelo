// SPDX-License-Identifier: MIT
/**
 * The height a wallet scans from (MONERO.md §6 "Restore height").
 *
 *   sigelo-spend wallet-restore --keeper-package keeper-<j>.json --wallet-rpc URL [--wallet-rpc-login u:p]
 *                               --wallet-file NAME --password-file F [--daemon URL [--daemon-ssl-fingerprint HEX]]
 *                               [--restore-height N | --restore-date YYYY-MM-DD]
 *   sigelo-spend restore-height [--daemon URL [--daemon-ssl-fingerprint HEX]] [--restore-height N | --restore-date YYYY-MM-DD | --keeper-package F]
 *
 * A wallet restored from height 0 scans the whole chain: hours to days on a small machine. The
 * height is, in this order: `--restore-height`; else the first block of `--restore-date`'s day
 * minus one day; else the same for the `created` day the ceremony wrote into the keeper package;
 * else 0, with a loud warning. A day becomes a height only by asking a daemon (`--daemon`):
 * monero-wallet-rpc has no date lookup, so this binary-searches block timestamps over the
 * daemon's `get_info` and `get_block_header_by_height`. Nothing is cached. No daemon, or none
 * that answers: 0 and the warning, never a guess.
 *
 * `wallet-restore` makes the keeper's wallet file (the package's allowance or treasury keys) in
 * a monero-wallet-rpc started with `--wallet-dir`, by `generate_from_keys`; `init
 * --create-wallet-rpc --wallet-file` then runs over it. `restore-height` prints the height alone
 * (stdout), for a restore done by hand (`refresh {start_height}`, the vault, a runbook).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { decodeAddress } from 'sigelo/dist/monero.js';
import { flags, one } from './init.js';
import { walletRpc } from './service.js';
import { httpsPost, normalFingerprint, type TlsTrust } from './daemontls.js';
import type { Policy } from './policy.js';

const DAY_S = 86400;
/** One daemon JSON-RPC call; throws on anything but a JSON-RPC result. */
export type DaemonCall = (method: string, params: Record<string, unknown>) => Promise<Record<string, unknown>>;
export interface RestoreAsk { height?: string; date?: string; created?: string }
export interface Restore { height: number; source: 'height' | 'date' | 'created' | 'genesis'; day?: string; warning?: string }
export const GENESIS_WARNING = 'WARNING: scanning from genesis (height 0): hours to days on a small machine; pass --restore-height <n> or --restore-date YYYY-MM-DD';

/** Unix seconds → the UTC day, YYYY-MM-DD. */
export const dayOf = (t: number): string => new Date(t * 1000).toISOString().slice(0, 10);
/** YYYY-MM-DD (a real calendar day) → unix seconds at 00:00 UTC. */
export function parseDay(s: string, what: string): number {
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(s);
  const t = m === null ? NaN : Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) / 1000;
  if (!Number.isFinite(t) || dayOf(t) !== s) throw new Error(`${what} ${JSON.stringify(s)} is not a day as YYYY-MM-DD`);
  return t;
}
/** A height as typed: a whole number ≥ 0, digits only. */
export function parseHeight(s: string): number {
  const n = /^(0|[1-9][0-9]{0,15})$/.test(s) ? Number(s) : NaN;
  if (!Number.isSafeInteger(n)) throw new Error(`--restore-height ${JSON.stringify(s)} is not a block height (a whole number, 0 or more)`);
  return n;
}

/**
 * A daemon's JSON-RPC: host:port, http://… or https://…; `/json_rpc` when no path is given. An
 * https:// daemon's certificate is checked as the keeper checks it (daemontls.ts): it verifies
 * against the CA store for that hostname, or, with `pins` (`--daemon-ssl-fingerprint`), it is
 * one of them.
 */
export function daemonCall(daemon: string, timeoutMs = 20_000, trust: TlsTrust & { pins?: string[] } = {}): DaemonCall {
  let url: URL;
  try { url = new URL(/^https?:\/\//.test(daemon) ? daemon : `http://${daemon}`); } catch { throw new Error(`--daemon ${JSON.stringify(daemon)} is not host:port or a URL`); }
  if (url.pathname === '/') url.pathname = '/json_rpc';
  const tls = url.protocol === 'https:';
  if ((trust.pins ?? []).length > 0 && !tls) throw new Error(`--daemon-ssl-fingerprint pins an https:// daemon, and --daemon ${daemon} is not one`);
  return async (method, params) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: '0', method, params });
    const r = tls ? await httpsPost(url.toString(), body, { ...trust, timeoutMs })
      : await fetch(url.toString(), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, signal: AbortSignal.timeout(timeoutMs) }).then(async (x) => ({ status: x.status, text: await x.text() }));
    let j: { result?: Record<string, unknown>; error?: { message?: string } };
    try { j = JSON.parse(r.text) as typeof j; } catch { throw new Error(`${method}: the reply is not JSON (HTTP ${r.status})`); }
    if (j?.error !== undefined) throw new Error(`${method}: ${String(j.error.message)}`);
    if (typeof j?.result !== 'object' || j.result === null) throw new Error(`${method}: no result (HTTP ${r.status})`);
    return j.result;
  };
}

const int = (x: unknown, what: string): number => {
  if (typeof x !== 'number' || !Number.isSafeInteger(x) || x < 0) throw new Error(`the daemon's ${what} is not a whole number`);
  return x;
};
/**
 * The first block whose timestamp is at or after `t` (unix seconds): a binary search over
 * `get_block_header_by_height`, ~22 calls on mainnet. Block timestamps are only roughly ordered,
 * which the caller's one-day margin covers. A `t` past the tip gives the tip.
 */
export async function heightAt(call: DaemonCall, t: number): Promise<number> {
  const tip = int((await call('get_info', {}))['height'], 'height') - 1;
  if (tip < 0) throw new Error('the daemon has no blocks');
  const ts = async (h: number): Promise<number> =>
    int(((await call('get_block_header_by_height', { height: h }))['block_header'] as Record<string, unknown> | undefined)?.['timestamp'], `timestamp of block ${h}`);
  if (await ts(0) >= t) return 0;
  if (await ts(tip) < t) return tip;
  let lo = 0, hi = tip;               // ts(lo) < t <= ts(hi)
  while (hi - lo > 1) {
    const mid = lo + Math.floor((hi - lo) / 2);
    if (await ts(mid) >= t) hi = mid; else lo = mid;
  }
  return hi;
}

/** The precedence: height > date > created > 0 with the warning. `call` undefined: no daemon. */
export async function restoreHeight(ask: RestoreAsk, call: DaemonCall | undefined): Promise<Restore> {
  if (ask.height !== undefined) return { height: parseHeight(ask.height), source: 'height' };
  const source = ask.date !== undefined ? 'date' : ask.created !== undefined ? 'created' : undefined;
  if (source === undefined) return { height: 0, source: 'genesis', warning: GENESIS_WARNING };
  const day = (source === 'date' ? ask.date : ask.created)!;
  const t = parseDay(day, source === 'date' ? '--restore-date' : 'the package\'s created');
  const named = source === 'date' ? `--restore-date ${day}` : `created ${day}`;
  if (call === undefined) return { height: 0, source: 'genesis', day, warning: `${GENESIS_WARNING} (${named} needs --daemon to become a height)` };
  try {
    return { height: await heightAt(call, t - DAY_S), source, day };
  } catch (e) {
    return { height: 0, source: 'genesis', day, warning: `${GENESIS_WARNING} (the daemon did not turn ${named} into a height: ${e instanceof Error ? e.message : String(e)})` };
  }
}

const said = (r: Restore): string => r.source === 'height' ? 'from --restore-height'
  : r.source === 'genesis' ? 'from genesis' : `the first block of ${r.day} minus a day (${r.source === 'date' ? '--restore-date' : 'the package\'s created'})`;

/** A keeper package (the ceremony's keeper-<j>.json): its wallet, and its `created` day if any. */
function packageOf(file: string): { created?: string; wallet?: { spend_key: string; view_key: string; address: string }; which?: string } {
  let p: Record<string, unknown>;
  try { p = JSON.parse(readFileSync(resolve(file), 'utf-8')) as Record<string, unknown>; } catch (e) { throw new Error(`--keeper-package ${file}: not JSON (${e instanceof Error ? e.message : String(e)})`); }
  if (p['v'] !== 'sigelo-keeper/1') throw new Error(`--keeper-package ${file}: not a sigelo-keeper/1 package (the ceremony's keeper-<j>.json)`);
  const created = typeof p['created'] === 'string' ? p['created'] : undefined;
  const which = ['allowance', 'treasury'].find((k) => typeof p[k] === 'object' && p[k] !== null);
  return { ...(created !== undefined && { created }), ...(which !== undefined && { which, wallet: p[which] as never }) };
}

/** `sigelo-spend wallet-restore | restore-height` → exit code. `call` replaces the daemon (tests). */
export async function restoreCli(argv: string[], io: { out?: (s: string) => void; err?: (s: string) => void; call?: DaemonCall; ca?: string[] } = {}): Promise<number> {
  const out = io.out ?? ((s) => { console.log(s); }), err = io.err ?? ((s) => { console.error(s); });
  const [cmd, ...rest] = argv;
  const common = ['--daemon', '--daemon-ssl-fingerprint', '--restore-height', '--restore-date', '--keeper-package'];
  const f = cmd === 'wallet-restore' ? flags(rest, [...common, '--wallet-rpc', '--wallet-rpc-login', '--wallet-file', '--password-file'], []) : flags(rest, common, []);
  if (f.pos.length > 0) throw new Error(`${cmd} takes flags only, not ${JSON.stringify(f.pos[0])}`);
  const pkgFile = one(f, '--keeper-package'), daemon = one(f, '--daemon');
  const pins = (f.v.get('--daemon-ssl-fingerprint') ?? []).flatMap((x) => x.split(',')).filter((x) => x.trim() !== '').map((x) => {
    const h = normalFingerprint(x);
    if (h === undefined) throw new Error(`--daemon-ssl-fingerprint ${JSON.stringify(x)} is not a SHA-256 fingerprint (64 hex characters, colons allowed)`);
    return h;
  });
  if (pins.length > 0 && daemon === undefined) throw new Error('--daemon-ssl-fingerprint pins the --daemon, and there is none');
  const call = (): DaemonCall | undefined => io.call ?? (daemon !== undefined ? daemonCall(daemon, 20_000, { pins, ...(io.ca !== undefined && { ca: io.ca }) }) : undefined);
  const pkg = pkgFile !== undefined ? packageOf(pkgFile) : undefined;
  const ask: RestoreAsk = { ...(one(f, '--restore-height') !== undefined && { height: one(f, '--restore-height') }), ...(one(f, '--restore-date') !== undefined && { date: one(f, '--restore-date') }), ...(pkg?.created !== undefined && { created: pkg.created }) };
  if (ask.date !== undefined) parseDay(ask.date, '--restore-date');   // a typo stops here, before the daemon or the wallet
  if (ask.height !== undefined) parseHeight(ask.height);
  if (cmd === 'restore-height') {
    const r = await restoreHeight(ask, call());
    if (r.warning !== undefined) err(r.warning);
    out(String(r.height));
    return 0;
  }
  // wallet-restore: everything checked before the daemon is asked or the wallet touched.
  const rpc0 = one(f, '--wallet-rpc'), file = one(f, '--wallet-file'), pwFile = one(f, '--password-file');
  if (pkgFile === undefined || rpc0 === undefined || file === undefined || pwFile === undefined) throw new Error('wallet-restore needs --keeper-package, --wallet-rpc (a monero-wallet-rpc started with --wallet-dir), --wallet-file <name> and --password-file');
  if (pkg!.wallet === undefined) throw new Error(`--keeper-package ${pkgFile} carries no wallet (only keeper 0's allowance and the treasury keeper's treasury do)`);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(file)) throw new Error(`--wallet-file ${JSON.stringify(file)}: a file name in the wallet-rpc's --wallet-dir (letters, digits, . _ -), not a path`);
  const w = pkg!.wallet!;
  decodeAddress(w.address);
  let rpc = rpc0;
  try { if (new URL(rpc).pathname === '/') rpc = rpc.replace(/\/?$/, '/json_rpc'); } catch { throw new Error(`--wallet-rpc ${JSON.stringify(rpc0)} is not a URL`); }
  const password = readFileSync(resolve(pwFile), 'utf-8').replace(/\r?\n$/, '');
  const r = await restoreHeight(ask, call());
  if (r.warning !== undefined) err(r.warning);
  const login = one(f, '--wallet-rpc-login');
  const policy = { wallet: { rpc, ...(login !== undefined && { login }) } } as Policy;
  await walletRpc(policy, 'generate_from_keys', { filename: file, address: w.address, spendkey: w.spend_key, viewkey: w.view_key, password, restore_height: r.height }, 120_000);
  out(`wallet-restore: ${file} (${pkg!.which} ${w.address}) made in ${rpc}, restore height ${r.height}, ${said(r)}. ` +
    `The wallet-rpc scans from there; then: sigelo-spend init --create-wallet-rpc --wallet-file <its --wallet-dir>/${file} --password-file ${pwFile} --keeper-package ${pkgFile} …`);
  return 0;
}
