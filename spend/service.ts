// SPDX-License-Identifier: MIT
/**
 * sigelo-spend — the HTTP service (MONERO.md §4).
 *
 * Loopback only, one process, no framework. It owns the allowance wallet's RPC and the
 * append-only spend log; policy.ts owns every decision. The agent holds a bearer token and
 * nothing else, so the blast radius of a compromised agent is this wallet's balance.
 */
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, closeSync, existsSync, fstatSync, fsyncSync, ftruncateSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { canonicalize, decodeKey, did, keygen, sign, parse, structure, verify, verifySig, type Bundle, type Genesis } from 'sigelo';
import { agentIdentitySeed, deriveIdentity, identitySeed as identitySeedOf, recoveryCommitment } from 'sigelo/dist/keys.js';
import { decodeAddress, verifySigeloMoneroSigAddr, type Net } from 'sigelo/dist/monero.js';
import { affordable, agentOf, evaluate, invoiceKey, parseAllow, parsePolicy, plain, tokenHash, type Decision, type PayRequest, type Plan, type Policy, type Prior, type Spent, type Status } from './policy.js';
import { approvalRequest, checkApproval, type ApprovalBody, type Approved } from './approval.js';
import { describe as describeLicence, LICENCE_FILE, licenceRefusal, readLicence, type LicenceStatus } from './licence.js';
import { asTreeEntry, chain, effective, effectivePolicy, planDelegate, planRevoke, replay as replayTree, reserved, status as statusOf, usedAccounts, type DelegateAsk, type DelegateEntry, type RevokeEntry, type TreeEntry } from './tree.js';

/**
 * The two-phase spend (MONERO.md §4.1) writes up to two lines per transaction, each a signed
 * entry: `intent` before `relay_tx` is called, then `relayed` or `relay_failed`. `status` is
 * INSIDE the signature, so an intent line lifted out of `/log` cannot pass for a receipt.
 * A line with no `status` was written before two-phase relay and is read as `relayed`; one
 * with `request.bucket` instead of `request.agent` was written before per-agent entries (G1),
 * and one without `ref` before idempotency (G2) — it is debited, never replayed as an answer.
 * A `pending` line carries the `approval_request` its 202 handed out, an `approved` line the
 * spend-approval `POST /approve` accepted for it, and the intent line of the spend that uses an
 * approval names its nonce in `request.approval` — which is what makes it single-use (§8 G6).
 */
export type { Status };
export interface LogEntry {
  ts: number; status?: Status;
  request: {
    to: { addr: string; did?: string; invoice?: { did: string; nonce: string } }; amount: string; purpose: string;
    agent?: string; bucket?: string; ref?: string; fp?: string; approval?: string;
  };
  plan: Plan; txid: string; amount: string; fee: string;
  approval_request?: ApprovalBody; approval?: Approved;
}
/** `error` is outside the signature: it is what the wallet said after the entry was signed. */
export interface Receipt { entry: LogEntry; sig: string; error?: string }
/** A `delegate` or `revoke` line (MONERO.md §4.3): signed like a spend line, and never a debit. */
export interface TreeLine { entry: TreeEntry; sig: string }
export interface ServeOptions {
  policyPath: string; dryRun?: boolean; port?: number;
  /**
   * How long one wallet-rpc call may take (default `WALLET_TIMEOUT_MS`). When set, it is also the
   * build's wait unless `buildTimeoutMs` is set too — tests set one short value for both.
   */
  walletTimeoutMs?: number;
  /** How long a `do_not_relay` build (`transfer`, `sweep_all`) may take (default `BUILD_TIMEOUT_MS`). */
  buildTimeoutMs?: number;
  /** How long a request body may take to arrive, whole (default 10 000 ms): past it, 408. */
  bodyTimeoutMs?: number;
  /** The keeper's clock, unix seconds (default: the system clock). For tests: a clock set back. */
  clock?: () => number;
  /**
   * The daemon fallback list (`SIGELO_DAEMONS`, `parseDaemons`): ordered daemon addresses, the
   * first the one wallet-rpc was started on. Fewer than two: no fallback, no extra wallet call.
   */
  daemons?: string[];
  /** The fallback's clock, milliseconds (default `Date.now`). For tests. */
  daemonClock?: () => number;
}
export interface Service {
  port: number; close(): Promise<void>; policy: Policy; did: string; key: string;
  /** The keeper's identity (identity.json, or the legacy genesis): `identity.recoverable` is false for the latter. */
  identity: KeeperId;
  /** The licence as of now (licence.ts): `pro`, or `free` and why. Re-read when licence.json changes. */
  licence(): LicenceStatus;
}

/**
 * The clock guard (MONERO.md §4.1 "Clock"). Every line the keeper signs carries its `ts`, every
 * window (per-period cap, rate, `dedupe_seconds`) is `ts > now − period`, and a spend-approval's
 * `iat`/`exp` are the keeper's `now`. A clock set back — a host whose clock boots at its
 * build epoch and has no network for NTP — would sign lines with old `ts` that fall out of every
 * window once the clock is right again: spends that stop counting against the daily cap, in a
 * log that is append-only and signed, so never corrected. So the keeper signs nothing while
 * `now` is before `CLOCK_FLOOR` (a date this build cannot run before) or more than `CLOCK_SKEW`
 * behind the newest `ts` it has signed in spend.log; the request is refused `clock_behind`, a
 * TRY LATER: nothing is signed, logged or sent. 300 s absorbs an NTP step backwards and seconds
 * of drift, and is far below any window the policy counts in.
 */
export const CLOCK_FLOOR = 1790640000; // 2026-09-29T00:00:00Z, the day this guard was written
export const CLOCK_SKEW = 300;

/**
 * The keeper's waits on wallet-rpc (MONERO.md §4.1 "Timeouts"). A build — `transfer` or
 * `sweep_all` with `do_not_relay` — fetches decoys for every input from the daemon, and over a
 * slow daemon link that takes minutes (soak finding, 2026-10-01 tick 5: 152 s for one input over
 * a slow link, where 10 s is usual). A build that runs out the wait is `wallet_slow`, a TRY LATER:
 * it was asked not to relay, so whatever wallet-rpc finishes after we stopped listening is
 * discarded and can never be sent, and the same command later builds afresh. Every other call,
 * `relay_tx` included, waits `WALLET_TIMEOUT_MS`; a `relay_tx` that runs out it is UNCERTAIN
 * (`relay_failed`), never retried. Build + relay (240 s) stays under the 300 s `sigelo-wallet`
 * waits for the keeper, so a pay's answer arrives before its CLI gives up on it.
 */
export const BUILD_TIMEOUT_MS = 180_000;
export const WALLET_TIMEOUT_MS = 60_000;

/**
 * The daemon fallback (MONERO.md §4 "Daemons"). A keeper whose wallet-rpc talks to one remote
 * daemon is down whenever that node is: every pay is `wallet_offline`, a TRY LATER. With
 * `SIGELO_DAEMONS` set to two or more addresses, the keeper moves wallet-rpc to the next one
 * (`set_daemon`, `trusted: false`) when `DAEMON_FAILS` builds in a row answered "no connection
 * to daemon", or when the wallet height has not moved for `DAEMON_STALE_MS` while it is asked to
 * pay — never on one failure, and never twice within `DAEMON_SWITCH_MS`. A switch is a warning on
 * stderr, never a spend.log line: nothing is signed and no pay is answered differently; while the
 * wallet has no daemon, every pay is still `wallet_offline`.
 */
export const DAEMON_FAILS = 3;
export const DAEMON_SWITCH_MS = 60_000;
export const DAEMON_STALE_MS = 20 * 60_000; // 10 blocks' time: P(no block in 20 min) ≈ e^-10
const DAEMON = /^(?:https?:\/\/)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\]):([0-9]{1,5})$/;
/**
 * `SIGELO_DAEMONS` → the fallback list: addresses separated by commas or whitespace, each
 * `host:port`, `[ipv6]:port` or either with `http://`/`https://`, as wallet-rpc's
 * `--daemon-address` takes them. Throws on anything else and on a repeat, so a typo stops the
 * start instead of turning into a fallback that is never there.
 */
export function parseDaemons(raw: string): string[] {
  const list = raw.split(/[\s,]+/).filter((x) => x !== '');
  for (const d of list) {
    const m = DAEMON.exec(d);
    if (m === null || Number(m[1]) < 1 || Number(m[1]) > 65535) throw new Error(`SIGELO_DAEMONS: ${JSON.stringify(d)} is not host:port (or [ipv6]:port, optionally with http:// or https://)`);
  }
  if (new Set(list).size !== list.length) throw new Error('SIGELO_DAEMONS: an address is listed twice');
  return list;
}

const MODE = 0o600;
const why = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
/** Bytes → text, throwing on invalid UTF-8 instead of substituting U+FFFD (SPEC §3). */
const utf8 = (b: Uint8Array): string => STRICT_UTF8.decode(b);

// ---------------------------------------------------------------- policy file

/** Read and validate a policy (policy.ts `parsePolicy`: strict, and a buckets-style file loads as one agent). */
export function loadPolicy(path: string): Policy {
  let raw: unknown;
  try { raw = JSON.parse(utf8(readFileSync(path))); } catch (e) { throw new Error(`policy: ${path} is not UTF-8 JSON (${why(e)})`); }
  return parsePolicy(raw);
}

/** What changes when policy.json is rewritten or replaced: inode, size, mtime and ctime (ns). */
function statKey(path: string): string {
  try { const s = statSync(path, { bigint: true }); return `${s.ino}:${s.size}:${s.mtimeNs}:${s.ctimeNs}`; } catch { return 'missing'; }
}

// ---------------------------------------------------------------- state and key

const logPath = (policyPath: string): string => join(dirname(policyPath), 'spend.log');
const keyPath = (policyPath: string): string => join(dirname(policyPath), 'spend.key');
const lockPath = (policyPath: string): string => join(dirname(policyPath), 'spend.lock');

const ATOMIC = /^(0|[1-9][0-9]*)$/;
const STATUSES: (Status | undefined)[] = ['intent', 'relayed', 'relay_failed', 'pending', 'approved', undefined];
/** The agent a line debits: `agent`, or `bucket` on a line written before G1. */
const agentOfEntry = (e: LogEntry): string => (e.request.agent ?? e.request.bucket)!;

/** Every line of the log, parsed, with its 1-based line number. */
function logLines(policyPath: string): { r: unknown; at: string }[] {
  const path = logPath(policyPath);
  if (!existsSync(path)) return [];
  let text: string;
  try { text = utf8(readFileSync(path)); } catch { throw new Error('spend.log: invalid UTF-8'); }
  return text.split('\n').map((line, i) => ({ line, i })).filter(({ line }) => line.trim() !== '').map(({ line, i }) => {
    try { return { r: JSON.parse(line) as unknown, at: `spend.log: line ${i + 1}` }; } catch (e) { throw new Error(`spend.log: line ${i + 1} is not JSON (${why(e)})`); }
  });
}
/** A tree line carries `entry.kind`; a spend line never does. */
const isTreeLine = (r: unknown): boolean => plain(r) && plain(r['entry']) && Object.hasOwn(r['entry'], 'kind');

/**
 * Replay the log's spends. A line we cannot parse, or one whose debit we cannot compute, is
 * fatal: an unreadable log is an unknown budget, and an unknown budget refuses (fail closed).
 * Tree lines are skipped here and checked by `readTree`, which the service runs at start.
 */
export function readLog(policyPath: string): Receipt[] {
  return logLines(policyPath).filter(({ r }) => !isTreeLine(r)).map(({ r: raw, at }) => {
    const r = raw as Receipt;
    const e = r?.entry as LogEntry | undefined;
    if (!plain(r) || !plain(e) || !plain(e.request) || !plain(e.request.to)) throw new Error(`${at} has no entry.request.to`);
    const who = e.request.agent ?? e.request.bucket;
    if (!Number.isSafeInteger(e.ts) || typeof who !== 'string' || typeof e.txid !== 'string') throw new Error(`${at}: ts, request.agent or txid is malformed`);
    for (const f of ['ref', 'fp', 'approval'] as const) if (e.request[f] !== undefined && typeof e.request[f] !== 'string') throw new Error(`${at}: request.${f} is not a string`);
    if (!ATOMIC.test(String(e.amount)) || !ATOMIC.test(String(e.fee))) throw new Error(`${at}: amount or fee is not a decimal string of atomic units — its debit is unknown`);
    if (!STATUSES.includes(e.status)) throw new Error(`${at}: unknown status ${JSON.stringify(e.status)}`);
    const inv = e.request.to.invoice;
    if (inv !== undefined && !(plain(inv) && typeof inv.did === 'string' && typeof inv.nonce === 'string')) throw new Error(`${at}: request.to.invoice is malformed`);
    return r;
  });
}

/**
 * The log's `delegate` and `revoke` lines, in order, each checked in shape and VERIFIED under
 * the keeper's key. Unlike a spend line, a tree line grants a token, so one this keeper did
 * not sign stops the service: a line appended by anything but this keeper must not be able to
 * mint an agent.
 */
export function readTree(policyPath: string, net: Net, key: string): TreeLine[] {
  return logLines(policyPath).filter(({ r }) => isTreeLine(r)).map(({ r, at }) => {
    const l = r as TreeLine;
    const entry = asTreeEntry(l.entry, net, at)!;
    if (typeof l.sig !== 'string' || !verifySig(key, entry, l.sig)) throw new Error(`${at}: ${entry.kind} line is not signed by this keeper (spend.key) — refusing to start`);
    return { entry, sig: l.sig };
  });
}

/**
 * What the log has debited. Every line debits amount + fee, except that a `relayed` or
 * `relay_failed` line SETTLES the unsettled `intent` before it with the same txid instead of
 * debiting again. So an intent whose outcome was never written (a crash, a kill, a full disk
 * between intent and outcome) still counts, and a `relay_failed` one counts too: the wallet
 * may have broadcast it before it failed to answer. Never under-count; that is the direction
 * the allowance balance cannot correct.
 */
export function spentOf(log: Receipt[]): Spent[] {
  const open = new Map<string, number>();
  const out: Spent[] = [];
  for (const { entry: e } of log) {
    // An approval wait moved nothing and debits nothing (§4.1 step 8) — but each one is a line
    // the agent made the keeper write, so it ticks the rate like a dry run. An approval, which
    // the approver made the keeper write, does neither.
    if (e.status === 'approved') continue;
    if (e.status === 'pending') { out.push({ ts: e.ts, agent: agentOfEntry(e), amount: '0' }); continue; }
    const n = open.get(e.txid) ?? 0;
    if ((e.status === 'relayed' || e.status === 'relay_failed') && n > 0) { open.set(e.txid, n - 1); continue; }
    if (e.status === 'intent') open.set(e.txid, n + 1);
    const inv = e.request.to.invoice;
    out.push({ ts: e.ts, agent: agentOfEntry(e), amount: String(BigInt(e.amount) + BigInt(e.fee)), ...(inv !== undefined && { invoice: invoiceKey(inv.did, inv.nonce) }) });
  }
  return out;
}

/**
 * Every line that carries a `ref`, for §4.1 step 4. Replayed from the log like the budget, so
 * a repeat after a restart — or after a crash that left only the intent line — is still
 * answered from what was written, and never paid a second time.
 *
 * An `approved` line lets a payment above `approval_above` through, so, like a tree line, it
 * counts only if it verifies under the keeper's `key`; without the key, or unsigned, it is
 * left out and the ref just waits (fail closed).
 */
export function priorOf(log: Receipt[], key?: string): Prior[] {
  return log.flatMap(({ entry: e, sig }, line) => {
    if (e.request.ref === undefined) return [];
    if (e.status === 'approved' && !(key !== undefined && plain(e.approval) && plain(e.approval.body) && verifySig(key, e, sig))) return [];
    const nonce = e.status === 'pending' ? e.approval_request?.nonce : e.status === 'approved' ? e.approval!.body.nonce : e.request.approval;
    const until = e.status === 'pending' ? e.approval_request?.exp : e.status === 'approved' ? e.approval!.body.exp : undefined;
    return [{
      ts: e.ts, agent: agentOfEntry(e), ref: e.request.ref, fp: e.request.fp ?? '', status: e.status ?? 'relayed', line,
      ...(typeof nonce === 'string' && { nonce }), ...(Number.isSafeInteger(until) && { until: until as number }),
      ...(e.status === 'approved' && { approval: e.approval! }),
    }];
  });
}

/** What a `relay_failed` answer says, the first time and on every repeat. */
const uncertain = (failure: string): string =>
  `${failure} — the transaction may have been broadcast; it is logged as relay_failed and counts against the budget. Do not pay again; tell your operator.`;

/**
 * Append one line and fsync it: the intent line is the only record of money that may move.
 * Every caller acts on a line (relays, answers, grants) only after this returns, so a line cut
 * off by a crash is one nothing was done on — what `repairTail` relies on. A short write is
 * written on; a failed one is cut back to where it began, so the next line never glues onto
 * half of this one (that would be a torn line in the MIDDLE of the log: fatal at every start).
 */
function appendDurable(path: string, line: string): void {
  const fd = openSync(path, 'a', MODE);
  try {
    const buf = new TextEncoder().encode(line + '\n');
    const at = fstatSync(fd).size;
    try {
      for (let off = 0; off < buf.length;) off += writeSync(fd, buf, off, buf.length - off);
      fsyncSync(fd);
    } catch (e) {
      try { ftruncateSync(fd, at); fsyncSync(fd); } catch { /* the start-up repair gets it */ }
      throw e;
    }
  } finally { closeSync(fd); }
}

const blank = (b: number): boolean => b === 0x0a || b === 0x0d || b === 0x20 || b === 0x09;
const parses = (text: string): boolean => { try { JSON.parse(text); return true; } catch { return false; } };

/**
 * Soak finding K1 (sim/REPORT.md): a keeper killed, or a host losing power, in the middle of
 * an append leaves a torn last line, and a keeper that refused to start on it turned every power
 * cut into an outage that needed a human (the class of soak incident #1). Run at start, under
 * spend.lock, before the log is read.
 *
 * Torn = the LAST non-blank line of spend.log is not JSON (partial JSON, a cut signature, NUL
 * bytes from an unflushed block) while every earlier line is. Its bytes, and whatever blank
 * bytes follow them, are moved to `spend.log.torn-<unix s>` next to it (written and fsynced
 * BEFORE spend.log is cut, so a crash in between duplicates them, never loses them), with one
 * warning naming the file and the byte count. Nothing was acted on for such a line
 * (`appendDurable`): a torn `intent` was never relayed, so no money moved and it rightly
 * debits nothing; a torn `relayed`/`relay_failed` leaves its intent line standing, which still
 * debits and answers a repeat UNCERTAIN (`replay`), so the operator checks that txid in the
 * wallet exactly as after a crash between the two lines. A torn `pending`, `approved` or tree
 * line was never answered: the caller asks again.
 *
 * Not repaired, and so fatal as before in `logLines`: an unparseable line anywhere else (a
 * hole in the middle is corruption, not a crash), and a last line that IS JSON but is not a
 * line this keeper would write (that is not what a cut-off write looks like). A complete last
 * line that only lost its newline is kept (never under-count) and given the newline, so the
 * next append does not glue onto it.
 */
export function repairTail(policyPath: string): void {
  const path = logPath(policyPath);
  if (!existsSync(path)) return;
  const buf = readFileSync(path);
  let j = buf.length - 1;
  while (j >= 0 && blank(buf[j]!)) j--;
  if (j < 0) return;
  const start = buf.lastIndexOf(0x0a, j) + 1;
  // Fatal decode (SPEC §3): invalid UTF-8 is not a sound line. A write cut off inside a multibyte
  // character is exactly what a torn last line looks like; a lossy decode could not see it.
  const text = (b: Uint8Array): string | undefined => { try { return utf8(b); } catch { return undefined; } };
  const last = text(buf.subarray(start, j + 1));
  if (last !== undefined && parses(last)) {
    if (buf[buf.length - 1] !== 0x0a) {
      const fd = openSync(path, 'a', MODE);
      try { writeSync(fd, '\n'); fsyncSync(fd); } finally { closeSync(fd); }
      console.warn(`sigelo-spend: ${path} ended without a newline after a complete line; added it`);
    }
    return;
  }
  // Every earlier line must be sound, or this is not a crash: leave it all for logLines to refuse.
  const before = text(buf.subarray(0, start));
  if (before === undefined || !before.split('\n').every((l) => l.trim() === '' || parses(l))) return;
  const torn = buf.subarray(start);
  const ts = Math.floor(Date.now() / 1000);
  let file = `${path}.torn-${ts}`;
  for (let i = 1; existsSync(file); i++) file = `${path}.torn-${ts}-${i}`;
  const out = openSync(file, 'wx', MODE);
  try { writeSync(out, torn); fsyncSync(out); } finally { closeSync(out); }
  const fd = openSync(path, 'r+');
  try { ftruncateSync(fd, start); fsyncSync(fd); } finally { closeSync(fd); }
  try { const d = openSync(dirname(path), 'r'); try { fsyncSync(d); } finally { closeSync(d); } } catch { /* not every platform fsyncs a directory */ }
  // A hint in a warning, never parsed or acted on: a lossy decode is fine here, and needed, since the
  // torn bytes may end inside a character.
  const txid = /"txid":"([0-9a-f]{64})"/.exec(new TextDecoder().decode(torn))?.[1];
  console.warn(`sigelo-spend: ${path} ended in a torn line (a write cut off by a crash or power loss): moved its ${torn.length} bytes to ${file} and started. ` +
    'Nothing was acted on for a line cut off in its write: a torn intent was never relayed; a torn relayed/relay_failed line leaves its intent line counting, and a repeat of it answers UNCERTAIN' +
    (txid === undefined ? '.' : ` — it names txid ${txid}: check it in the wallet (get_transfer_by_txid).`));
}

/**
 * Phase (a)'s reply, checked before any of it is used. A wallet reply is the one input here
 * that the policy never saw, and a malformed one after a RELAYED transfer was a spend with no
 * log line; phase (a) is `do_not_relay`, so refusing it now moves no money.
 */
function asBuilt(r: Record<string, unknown>): { txid: string; fee: string; metadata: string } | string {
  const [txid, fee, metadata] = [r['tx_hash'], r['fee'], r['tx_metadata']];
  if (typeof txid !== 'string' || !/^[0-9a-f]{64}$/.test(txid)) return `wallet: transfer: tx_hash ${JSON.stringify(txid)} is not 64 hex characters — nothing was relayed`;
  if (typeof fee !== 'number' || !Number.isSafeInteger(fee) || fee < 0) return `wallet: transfer: fee ${JSON.stringify(fee)} is not a non-negative safe integer — nothing was relayed`;
  if (typeof metadata !== 'string' || metadata === '') return 'wallet: transfer: no tx_metadata in the reply (get_tx_metadata was asked for) — nothing was relayed';
  return { txid, fee: String(fee), metadata };
}

// ---------------------------------------------------------------- one keeper per policy directory

/**
 * `spend.lock`, next to spend.log. Two keepers on one directory each cache the delegation tree
 * at start and each serialise only their own /pay calls: a delegate revoked through one still
 * pays through the other, both can create a delegate of one name (and the log then refuses
 * every later start), and both can spend one budget. So a second start is refused while the
 * keeper named in the file is running.
 *
 * The file is two lines: the pid alone (so `kill -9 $(head -n1 spend.lock)` works), then
 * `{"pid","boot_id","start"}` — `boot_id` from /proc/sys/kernel/random/boot_id, `start` the
 * process's starttime (field 22 of /proc/<pid>/stat, clock ticks since boot, fixed for the
 * life of a pid). A pid alone cannot tell "the keeper" from "whatever got that pid after a
 * reboot or a crash" (soak incident #1: after a reboot pid 1103 was bluetoothd and the keeper
 * refused to start for 54 minutes under Restart=always). A held lock is stale, and taken over
 * with one warning naming what was stale, when its boot_id is not this boot's, or its pid is
 * dead, or its pid is alive with another starttime. Otherwise it is live and the start is
 * refused. A live pid whose starttime cannot be read (/proc hidden) counts as live.
 *
 * Without /proc (not Linux), and for a lock of one bare-pid line (written before this change;
 * read, not migrated — the next keeper to take it writes the new form), only the pid is known:
 * dead → stale, alive → refused, and a reused pid must be removed by hand — the refusal says so.
 *
 * Limit: the takeover is check-then-unlink-then-O_EXCL-create. Two keepers that find the same
 * stale lock at the same instant can both unlink and one can remove the other's fresh lock;
 * both then run. Only a stale lock opens that window, and only for simultaneous starts.
 */
const locks = new Map<string, string>(); // path → the exact text this process wrote
let exitHook = false;
function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as { code?: string }).code === 'EPERM'; }
}
/** Where /proc is. SIGELO_PROC_ROOT lets the test run the no-/proc (macOS, Windows) path on Linux. */
const procRoot = (): string => process.env['SIGELO_PROC_ROOT'] ?? '/proc';
/** This boot's id, or undefined without /proc. */
function bootId(): string | undefined {
  try { const b = readFileSync(`${procRoot()}/sys/kernel/random/boot_id`, 'utf-8').trim(); return b === '' ? undefined : b; } catch { return undefined; }
}
/** A pid's starttime (field 22 of /proc/<pid>/stat), or undefined when it cannot be read. */
export function startOf(pid: number): number | undefined {
  try {
    const stat = readFileSync(`${procRoot()}/${pid}/stat`, 'utf-8');
    // field 2 (comm) is parenthesised and may hold spaces or ')': fields 3.. follow the last ')'
    const f = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    const t = f[22 - 3];
    return t !== undefined && /^[0-9]+$/.test(t) ? Number(t) : undefined;
  } catch { return undefined; }
}
type Held = { pid: number; boot_id?: string; start?: number };
/** The lock's holder; undefined for a file that does not hold a pid (or a half-written one). */
function parseLock(text: string): Held | undefined {
  const [first = '', second, ...rest] = text.trim().split('\n');
  if (!/^[1-9][0-9]*$/.test(first.trim()) || rest.length > 0) return undefined;
  const pid = Number(first.trim());
  if (second === undefined) return { pid }; // bare pid: before boot_id/start, or no /proc
  try {
    const j = JSON.parse(second) as Record<string, unknown>;
    if (j['pid'] !== pid || typeof j['boot_id'] !== 'string' || !Number.isSafeInteger(j['start'])) return undefined;
    return { pid, boot_id: j['boot_id'], start: j['start'] as number };
  } catch { return undefined; }
}
/** Why a held lock is stale, or undefined while its keeper may still be running. */
function staleness(h: Held): string | undefined {
  const boot = bootId();
  if (h.boot_id !== undefined && boot !== undefined && h.boot_id !== boot) return `pid ${h.pid} is from an earlier boot (boot_id ${h.boot_id}, now ${boot})`;
  if (!alive(h.pid)) return `pid ${h.pid} is not running`;
  if (h.start !== undefined) {
    const now = startOf(h.pid);
    if (now !== undefined && now !== h.start) return `pid ${h.pid} is now another process (starttime ${now}, the lock's keeper had ${h.start})`;
  }
  return undefined;
}
function lockText(): string {
  const boot = bootId(), start = startOf(process.pid);
  return boot === undefined || start === undefined ? `${process.pid}\n` : `${process.pid}\n${JSON.stringify({ pid: process.pid, boot_id: boot, start })}\n`;
}
function takeLock(path: string): void {
  for (let attempt = 0; attempt < 2; attempt++) {
    let fd: number;
    try { fd = openSync(path, 'wx', MODE); } catch (e) {
      if ((e as { code?: string }).code !== 'EEXIST') throw new Error(`spend.lock: cannot create ${path} (${why(e)})`);
      let text = '';
      try { text = readFileSync(path, 'utf-8').trim(); } catch { /* removed meanwhile: try again */ }
      const held = parseLock(text);
      if (held === undefined && text !== '') throw new Error(`spend.lock: ${path} does not hold a pid — if no keeper is running on this directory, remove it by hand`);
      if (held === undefined && attempt === 0) continue; // a keeper between creating the file and writing its pid, or it just went away
      if (held !== undefined) {
        const stale = staleness(held);
        if (stale === undefined) {
          const pid = held.pid;
          throw new Error(`spend.lock: ${path} is held by pid ${pid}${pid === process.pid ? ' (this process)' : ''}: another keeper serves this policy directory — two would each spend the one budget and cache their own tree. ` +
            `Stop it first. If no keeper is running (the pid was reused after a crash), remove ${path} by hand.`);
        }
        try { unlinkSync(path); } catch { /* another start removed it first */ }
        console.warn(`sigelo-spend: took over a stale ${path}: ${stale}`);
      }
      continue;
    }
    const mine = lockText();
    try { writeSync(fd, mine); fsyncSync(fd); } finally { closeSync(fd); }
    locks.set(path, mine);
    if (!exitHook) { exitHook = true; process.once('exit', () => { for (const l of [...locks.keys()]) dropLock(l); }); }
    return;
  }
  throw new Error(`spend.lock: could not take ${path} — another keeper may be starting; try again`);
}
/** Remove the lock, but only while it is still ours. */
function dropLock(path: string): void {
  const mine = locks.get(path);
  if (mine === undefined) return;
  locks.delete(path);
  try { if (readFileSync(path, 'utf-8') === mine) unlinkSync(path); } catch { /* already gone */ }
}

/**
 * The keeper root `K` (MONERO.md §2): what the ceremony's keeper package calls
 * `keeper_root_hex`, or, on a keeper set up before the ceremony, a random root created 0600
 * on first run. Both are 32 bytes, used the same way: the keeper's own signing identity is
 * `identitySeed(K, 0)` (via `deriveIdentity`, so a receipt is checkable by anyone holding the
 * keeper's genesis), and each delegate's identity is `agentIdentitySeed(K, i, 0)` for its
 * account `i` — the keeper can re-derive any agent's seed, and nothing else can.
 */
export function loadRoot(policyPath: string): Uint8Array {
  const path = keyPath(policyPath);
  if (!existsSync(path)) {
    writeFileSync(path, randomBytes(32).toString('hex') + '\n', { mode: MODE });
    console.warn(`sigelo-spend: created ${path} (0600) — the receipt signing root. Back it up.`);
  }
  chmodSync(path, MODE);
  const hex = readFileSync(path, 'utf-8').trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`spend.key: ${path} is not 64 hex characters`);
  return Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

// ---------------------------------------------------------------- wallet RPC

const md5 = (s: string): string => createHash('md5').update(s, 'utf8').digest('hex');

/** monero-wallet-rpc's --rpc-login is HTTP digest: unauthenticated probe, then the answer. */
function digestHeader(challenge: string, login: string, uri: string): string {
  const field = (k: string): string => new RegExp(`${k}="?([^",]*)"?`).exec(challenge)?.[1] ?? '';
  const i = login.indexOf(':');
  const [user, pass] = [login.slice(0, i), login.slice(i + 1)];
  const [realm, nonce, opaque] = [field('realm'), field('nonce'), field('opaque')];
  const [nc, cnonce] = ['00000001', randomBytes(8).toString('hex')];
  const response = md5([md5(`${user}:${realm}:${pass}`), nonce, nc, cnonce, 'auth', md5(`POST:${uri}`)].join(':'));
  return `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", qop=auth, nc=${nc}, ` +
    `cnonce="${cnonce}", response="${response}", algorithm=MD5${opaque === '' ? '' : `, opaque="${opaque}"`}`;
}

/** One JSON-RPC call. A wallet-side error is thrown with the wallet's own words. */
export async function walletRpc(policy: Policy, method: string, params: unknown, timeoutMs = WALLET_TIMEOUT_MS): Promise<Record<string, unknown>> {
  const url = policy.wallet.rpc;
  const uri = new URL(url).pathname;
  const body = JSON.stringify({ jsonrpc: '2.0', id: '0', method, params });
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const send = (): Promise<Awaited<ReturnType<typeof fetch>>> =>
    fetch(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(timeoutMs) });
  // A wait that ran out is said apart from a refused connection: for a build it is `wallet_slow`.
  const lost = (e: unknown): Error => new Error((e as { name?: unknown })?.name === 'TimeoutError'
    ? `wallet: ${method}: ${url} timed out after ${timeoutMs} ms` : `wallet: ${method}: ${url} unreachable (${why(e)})`);
  let res;
  try { res = await send(); } catch (e) { throw lost(e); }
  if (res.status === 401 && policy.wallet.login !== undefined) {
    headers['Authorization'] = digestHeader(res.headers.get('www-authenticate') ?? '', policy.wallet.login, uri);
    try { res = await send(); } catch (e) { throw lost(e); }
  }
  if (res.status === 401) throw new Error('wallet: 401 — wallet.login is missing or wrong');
  let out: { result?: unknown; error?: { code: number; message: string } };
  try { out = await res.json() as typeof out; } catch (e) { throw new Error(`wallet: ${method}: reply is not JSON (HTTP ${res.status}, ${why(e)})`); }
  if (!plain(out)) throw new Error(`wallet: ${method}: reply is not a JSON-RPC object`);
  if (out.error) throw new Error(`wallet: ${method}: ${out.error.message} (code ${out.error.code})`);
  if (!plain(out.result)) throw new Error(`wallet: ${method}: no result in the reply`);
  return out.result;
}

// ---------------------------------------------------------------- HTTP

const json = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body) + '\n');
};
/**
 * A body that could not be read: `status` is the HTTP answer (408 too slow, 413 too big, 400 a
 * broken stream), or 0 when the client went away and nobody is left to answer.
 */
class BodyError extends Error { constructor(readonly status: number, message: string) { super(message); } }
const BODY_MAX = 1_000_000;
/**
 * The whole body, or a `BodyError` — and always one or the other, promptly. It settles on
 * `end`, on a stream error, on the client going away (`close`/`aborted` before `end`), past
 * `BODY_MAX` bytes, and after `timeoutMs`. A body read that never settles is a request that
 * holds whatever it was waiting in forever.
 */
const readBody = (req: IncomingMessage, timeoutMs: number): Promise<string> => new Promise((resolve, reject) => {
  const chunks: Uint8Array[] = [];
  let size = 0, done = false;
  const settle = (f: () => void): void => { if (done) return; done = true; clearTimeout(timer); f(); };
  const gone = (): void => settle(() => reject(new BodyError(0, 'body: the client went away before sending it all')));
  const timer = setTimeout(() => settle(() => reject(new BodyError(408, `body: not received in full within ${timeoutMs} ms`))), timeoutMs);
  req.on('data', (c: Uint8Array) => {
    if (done) return;
    chunks.push(c);
    size += c.length;
    if (size > BODY_MAX) settle(() => reject(new BodyError(413, 'body: over 1 MB')));
  });
  // Bytes, decoded once whole and fatally: a lossy decode (`setEncoding`) made invalid UTF-8
  // U+FFFD, where the Go verifier rejects the document outright (SPEC §3).
  req.on('end', () => settle(() => {
    const whole = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) { whole.set(c, at); at += c.length; }
    try { resolve(utf8(whole)); } catch { reject(new BodyError(400, 'body: invalid UTF-8 in document')); }
  }));
  req.on('error', (e) => settle(() => reject(new BodyError(400, `body: ${why(e)}`))));
  req.on('aborted', gone);
  req.on('close', () => { if (!req.complete) gone(); });
  if (req.destroyed) gone();
});
/**
 * The check a refusal names (§4.1), as `code`, so a client can answer in plain words (§4.2)
 * without parsing prose: the reason's prefix, split where one check has two answers — an
 * allowlist refusal that is really a spent or expired invoice, the wallet's two kinds of
 * "not enough", and a wallet with no connection to its daemon (`wallet_offline`: wallet2's
 * `no_connection_to_daemon`, which monero-wallet-rpc answers as "no connection to daemon",
 * code -38). That one is the host's network, not the wallet or the request: soak incident #4
 * was 32 h of it, and the agent was told only "the wallet could not do that". And a build that
 * ran out its wait (`wallet_slow`, `BUILD_TIMEOUT_MS`): the wallet is still working, not unable —
 * soak finding 2026-10-01 tick 5 told the agent "could not do that" about a build 92 s from done.
 */
export function codeOf(reason: string): string {
  const head = /^([a-z_.]+):/.exec(reason)?.[1] ?? 'service';
  if (head === 'allowlist' && /invoice: (already paid|not valid at)/.test(reason)) return 'invoice';
  if (head !== 'wallet') return head;
  if (/no connection to daemon/i.test(reason)) return 'wallet_offline';
  if (/^wallet: (transfer|sweep_all): \S+ timed out after [0-9]+ ms/.test(reason)) return 'wallet_slow';
  return /not enough unlocked money/i.test(reason) ? 'wallet_locked' : /not enough money/i.test(reason) ? 'wallet_funds' : 'wallet';
}
const fail = (res: ServerResponse, status: number, reason: string, extra: Record<string, unknown> = {}): void =>
  json(res, status, { error: reason, code: codeOf(reason), ...extra });
/** An answer not yet written: what `spend` returns, so /pay and /fund can share it. */
type Reply = { status: number; body: Record<string, unknown> };
const reply = (status: number, body: Record<string, unknown>): Reply => ({ status, body });
const err = (status: number, reason: string, extra: Record<string, unknown> = {}): Reply => reply(status, { error: reason, code: codeOf(reason), ...extra });
/** A wallet amount (epee sends JSON numbers) as an atomic-unit string, or undefined if it is not one. */
const atomicOf = (x: unknown): string | undefined => (typeof x === 'number' && Number.isInteger(x) && x >= 0 ? BigInt(x).toString() : undefined);
const BIND_TTL = 30 * 86400; // MONERO.md §4.3: an agent's binding runs 30 days; the harness binds again.
const bearer = (header: string | undefined): string | undefined =>
  header !== undefined && header.startsWith('Bearer ') ? header.slice(7) : undefined;

/**
 * Body shape only; policy.ts makes every decision. Named failures, no coercion, own keys only.
 * `{to, amount, purpose, ref?}` — plus `bucket?`, which today's clients send and which must
 * name the token's own agent (§4.1 step 3).
 */
function asRequest(raw: unknown, token: string | undefined): PayRequest | string {
  if (!plain(raw)) return 'request: body is not an object';
  for (const k of Object.keys(raw)) if (!['to', 'amount', 'purpose', 'ref', 'bucket'].includes(k)) return `request: unknown field ${JSON.stringify(k)}`;
  if (!Object.hasOwn(raw, 'to') || raw['to'] === null || typeof raw['to'] !== 'object') return 'request: to is missing';
  for (const f of ['amount', 'purpose', 'ref', 'bucket']) {
    const optional = f === 'ref' || f === 'bucket';
    if (optional && !Object.hasOwn(raw, f)) continue;
    if (!Object.hasOwn(raw, f) || typeof raw[f] !== 'string' || raw[f] === '') return `request: ${f} is not a non-empty string`;
  }
  return {
    to: raw['to'] as PayRequest['to'], amount: raw['amount'] as string, purpose: raw['purpose'] as string, token,
    ...(Object.hasOwn(raw, 'ref') && { ref: raw['ref'] as string }), ...(Object.hasOwn(raw, 'bucket') && { bucket: raw['bucket'] as string }),
  };
}

/**
 * The keeper's genesis from its root `K`. Its DID must survive a restart: a spend-approval
 * names it (approval.ts), one signed before a restart must still be for this keeper after it,
 * and a licence is issued to it (licence.ts). SPEC §3.1 (`nonce`): a stable key MAY derive its
 * genesis nonce from the key, with `created` pinned.
 *
 * `recovery` is the commitment of a recovery key the keeper host never holds — the Owner's root
 * recovery key (`recoveryCommitment(S)`, the ceremony's keeper package), or one the operator
 * keeps offline (`init`). Without it this is the LEGACY genesis, whose recovery key derives from
 * `K` itself (`recoveryPublicKey(K)`): whoever takes `spend.key` takes that too, so such a keeper
 * DID can only be abandoned (INCIDENT.md §5). It stays only so keepers keyed before identity.json
 * keep their DID; `keeperGenesis` refuses to build one on purpose.
 */
export function keeperIdentity(K: Uint8Array, recovery?: string): ReturnType<typeof deriveIdentity> {
  const key0 = deriveIdentity(K, 0).key;
  const nonce = createHash('sha256').update([...decodeKey(key0)].map((x) => x.toString(16).padStart(2, '0')).join(''), 'hex').digest('hex').slice(0, 32);
  return deriveIdentity(K, 0, recovery, { created: '1970-01-01T00:00:00Z', nonce: Uint8Array.from(nonce.match(/../g)!.map((h) => parseInt(h, 16))) });
}

/** Why `recovery` cannot govern a keeper whose root is `K`, or undefined: null, malformed, or derivable from `K`. */
export function badKeeperRecovery(K: Uint8Array, recovery: string | null | undefined): string | undefined {
  if (recovery === null || recovery === undefined) return 'the keeper\'s recovery is null: a stolen keeper key would be terminal';
  if (!/^sha256:[0-9a-f]{64}$/.test(recovery)) return `the recovery commitment ${JSON.stringify(recovery)} is not sha256:<64 lowercase hex>`;
  if (recovery === recoveryCommitment(K)) return 'the recovery commitment is recoveryCommitment(spend.key) — derivable from the key a thief takes with the host, so it recovers nothing';
  return undefined;
}

/** A NEW keeper's genesis: `keeperIdentity(K, recovery)`, refused where `badKeeperRecovery` says. */
export function keeperGenesis(K: Uint8Array, recovery: string): ReturnType<typeof deriveIdentity> {
  const bad = badKeeperRecovery(K, recovery);
  if (bad !== undefined) throw new Error(`keeper identity: ${bad}`);
  return keeperIdentity(K, recovery);
}

/** The keeper's published identity, next to policy.json: a SPEC §8 bundle (genesis + rotations). */
export const IDENTITY_FILE = 'identity.json';

/**
 * Who this keeper is. `did` is its ORIGINAL DID (`chain[0]`): the name receipts, spend-approvals,
 * the licence and the host registry carry, unchanged by a recovery. `key`/`secret` are its CURRENT
 * key, `identitySeed(K, 0)` of this `spend.key`. `bundle` proves the step from one to the other
 * (SPEC §7, §9: a verifier compares a claimed DID against `chain[0]`). `recoverable` is false only
 * for a legacy keeper (no identity.json), whose genesis commits to a recovery key derived from `K`.
 */
export interface KeeperId { did: string; current: string; genesis: Genesis; key: string; secret: Uint8Array; bundle: Bundle; recoverable: boolean }

const bundleOf = (genesis: Genesis, rotations: Bundle['rotations'] = []): Bundle => ({ v: 'sigelo/0', typ: 'bundle', genesis, rotations, bindings: [], attestations: [], issuers: [] });

/**
 * The keeper identity of directory `dir` under root `K`. With identity.json: the bundle must
 * verify (SPEC §9), its current key must be this `spend.key`'s, and its governing recovery must
 * pass `badKeeperRecovery` — or the keeper does not start. Without it: the legacy genesis, which
 * keeps an existing keeper's DID (and licence) and says it is not recoverable.
 */
export function loadKeeper(dir: string, K: Uint8Array, now: number = Math.floor(Date.now() / 1000)): KeeperId {
  const p = join(dir, IDENTITY_FILE);
  if (!existsSync(p)) {
    const id = keeperIdentity(K);
    return { did: id.did, current: id.did, genesis: id.genesis, key: id.key, secret: id.secret, bundle: bundleOf(id.genesis), recoverable: false };
  }
  let b: unknown;
  try { b = parse(utf8(readFileSync(p))); } catch (e) { throw new Error(`${IDENTITY_FILE}: ${p} is not strict JSON (${why(e)})`); }
  return keeperOf(b, K, now, `${IDENTITY_FILE}: `);
}

/** `loadKeeper` on a bundle in hand (identity.json, or what `init --adopt` is given). */
export function keeperOf(b: unknown, K: Uint8Array, now: number, at = ''): KeeperId {
  const key = deriveIdentity(K, 0).key;
  let r: ReturnType<typeof verify>;
  try { r = verify(b as Bundle, now); } catch (e) { throw new Error(`${at}not a keeper bundle that verifies (${why(e)})`); }
  const bundle = b as Bundle;
  const current = [bundle.genesis, ...bundle.rotations.map((x) => x.next_genesis)].find((g) => did(g) === r.did)!;
  if (current.key !== key) throw new Error(`${at}the keeper's current key (${r.did}) is ${current.key}, but spend.key signs as ${key} — not this spend.key's identity (a keeper recovered elsewhere, or the wrong key)`);
  const bad = badKeeperRecovery(K, r.recovery);
  if (bad !== undefined) throw new Error(`${at}${bad} — refusing it`);
  return { did: r.chain[0]!, current: r.did, genesis: bundle.genesis, key, secret: identitySeedOf(K, 0), bundle, recoverable: true };
}

/** A one-node keeper bundle: a new keeper's identity.json. */
export const keeperBundle = (genesis: Genesis): Bundle => bundleOf(genesis);

export async function serve(opts: ServeOptions): Promise<Service> {
  const policy = loadPolicy(opts.policyPath);
  const K = loadRoot(opts.policyPath);
  const identity = loadKeeper(dirname(opts.policyPath), K, (opts.clock ?? ((): number => Math.floor(Date.now() / 1000)))());
  const secret = identity.secret;
  // spend.lock first: the torn-tail repair below writes the log, and must never cut a line a
  // running keeper is still appending. From here on a refused start gives the lock back.
  const lock = lockPath(opts.policyPath);
  takeLock(lock);
  const owned = <T>(f: () => T): T => { try { return f(); } catch (e) { dropLock(lock); throw e; } };
  owned(() => { repairTail(opts.policyPath); });
  // The delegation tree lives in the log, never in policy.json: replayed here on top of the
  // Owner's agents (the roots), and `eff` — roots plus live delegates, clamped — is what every
  // route below checks tokens and caps against. A tree line this keeper did not sign, or one it
  // could never have written, stops the start.
  const treeLines = owned(() => readTree(opts.policyPath, policy.net, identity.key));
  let tree = owned(() => replayTree(treeLines.map((l) => l.entry), policy.agents));
  let eff = owned(() => effectivePolicy(policy, tree));
  // Root tokens are read live (spend/README "What a running keeper re-reads"): `token new` says the
  // old token stops, and after a leak it must stop now, not at the next restart. On every request
  // a changed policy.json is loaded in full and ONLY the token_hash of each root this keeper
  // already serves is taken from it; caps, accounts, allowlists, approvers and roots added or
  // removed still take effect at the next start. A file that does not load (a typo, a write in
  // progress) or that would give two roots one hash never opens the keeper: the last good tokens
  // stay, with one warning per file state.
  let tokensFrom = statKey(opts.policyPath), warnedAt = '';
  const refreshTokens = (): void => {
    const at = statKey(opts.policyPath);
    if (at === tokensFrom || at === warnedAt) return;
    const keep = (reason: string): void => { warnedAt = at; console.warn(`sigelo-spend: policy.json changed but ${reason}; the running keeper keeps the tokens it had`); };
    let next: Policy;
    try { next = loadPolicy(opts.policyPath); } catch (e) { return keep(`does not load (${why(e)})`); }
    const agents = { ...policy.agents };
    for (const [name, a] of Object.entries(agents)) {
      const n = Object.hasOwn(next.agents, name) ? next.agents[name]! : undefined;
      if (n !== undefined && n.token_hash !== a.token_hash) agents[name] = { ...a, token_hash: n.token_hash };
    }
    const hashes = Object.values(agents).map((a) => a.token_hash);
    if (new Set(hashes).size !== hashes.length) return keep('would give two running roots one token_hash (restart to load it)');
    const changed = Object.keys(agents).filter((n) => agents[n] !== policy.agents[n]);
    policy.agents = agents;
    eff = effectivePolicy(policy, tree);
    tokensFrom = at; warnedAt = '';
    licence(); // a policy reload re-reads the licence too, and says so if the tier changed
    if (changed.length > 0) console.warn(`sigelo-spend: policy.json: new token_hash for ${changed.join(', ')} — the old token(s) no longer work`);
  };
  // A name is bound to its account for as long as the log names it: every line an agent's
  // name is on counts toward that agent's /budget, /log, /history and refs. An agent in
  // policy.json (or the tree) whose name the log shows spending from ANOTHER account is a
  // different agent under a reused name — it would inherit those lines — so the start is refused.
  owned(() => { for (const r of readLog(opts.policyPath)) {
    const name = agentOfEntry(r.entry), acct: unknown = plain(r.entry.plan) ? r.entry.plan.account_index : undefined;
    const holder = Object.hasOwn(policy.agents, name) ? policy.agents[name]!.account : tree.delegates.get(name)?.account;
    if (holder !== undefined && Number.isSafeInteger(acct) && acct !== holder) {
      throw new Error(`spend.log: agent ${JSON.stringify(name)} spent from account ${String(acct)}, but ${JSON.stringify(name)} is now account ${holder} — a name stays bound to its account in the log; give the new agent a new name`);
    }
  } });
  const orphans = [...tree.delegates.keys()].filter((n) => statusOf(tree, policy.agents, n) === 'orphaned');
  if (orphans.length > 0) console.warn(`sigelo-spend: delegates whose root is no longer in policy.json are dead: ${orphans.join(', ')} (their accounts keep any funds; restore the root and revoke them to sweep)`);
  let port = 0;
  const dryRun = opts.dryRun === true;
  const timeout = opts.walletTimeoutMs ?? WALLET_TIMEOUT_MS;
  const buildTimeout = opts.buildTimeoutMs ?? opts.walletTimeoutMs ?? BUILD_TIMEOUT_MS;
  const logFile = logPath(opts.policyPath);
  const clock = opts.clock ?? ((): number => Math.floor(Date.now() / 1000));
  // The newest `ts` this keeper has signed: read once here, from the lines that verify under its
  // key (a line it did not sign must not be able to stop it), then kept by `write`. spend.lock
  // makes this process the log's only writer.
  let newest = 0;
  owned(() => { for (const { r } of logLines(opts.policyPath)) {
    const l = r as { entry?: Record<string, unknown>; sig?: unknown };
    const ts = plain(l) && plain(l.entry) ? l.entry['ts'] : undefined;
    if (Number.isSafeInteger(ts) && (ts as number) > newest && typeof l.sig === 'string' && verifySig(identity.key, l.entry, l.sig)) newest = ts as number;
  } });
  // The licence (licence.ts): read at start, on a policy reload and before every paid verb, each
  // time checked at `now` — an expired one makes the paid verbs refuse from that moment, and
  // nothing else changes. A change of tier is one warning. Never a network call.
  const keeperDir = dirname(opts.policyPath);
  let tierSaid = describeLicence(readLicence(keeperDir, identity.genesis, clock()));
  const licence = (): LicenceStatus => {
    const s = readLicence(keeperDir, identity.genesis, clock()), said = describeLicence(s);
    if (said !== tierSaid) { tierSaid = said; console.warn(`sigelo-spend: ${LICENCE_FILE}: now ${said}`); }
    return s;
  };
  /** The refusal of a paid verb while the keeper is free, or undefined while it is pro. */
  const unlicensed = (feature: string): string | undefined => { const s = licence(); return s.tier === 'pro' ? undefined : licenceRefusal(feature, s); };
  /** Append one signed line (`appendDurable`) and keep `newest`. */
  const write = (line: { entry: { ts: number }; sig: string; error?: string }): void => {
    appendDurable(logFile, JSON.stringify(line));
    if (line.entry.ts > newest) newest = line.entry.ts;
  };
  const iso = (t: number): string => new Date(t * 1000).toISOString().replace('.000Z', 'Z');
  /** Why the clock cannot be trusted to sign with (the guard above `CLOCK_FLOOR`), or undefined. */
  const clockBehind = (now: number): string | undefined => {
    const then = ' — nothing was signed, logged or sent; run the same command once the clock is set (NTP)';
    if (now < CLOCK_FLOOR) return `clock_behind: the keeper's clock reads ${iso(now)}, before ${iso(CLOCK_FLOOR)}, the earliest this build can run at${then}`;
    if (now < newest - CLOCK_SKEW) return `clock_behind: the keeper's clock reads ${iso(now)}, ${newest - now} s behind the newest line it signed in spend.log (${iso(newest)}; ${CLOCK_SKEW} s allowed)${then}`;
    return undefined;
  };
  // A dry run debits nothing, but it does make the wallet build and price a transaction, so it
  // is rate-limited like a spend: one tick of amount 0 per call, held in memory only.
  const dryTicks: Spent[] = [];
  const state = (log = readLog(opts.policyPath)): Spent[] => spentOf(log).concat(dryTicks);

  // One spend at a time. `evaluate` reads the log, and the intent line is written only after
  // the wallet has priced the transaction, so two concurrent /pay calls would otherwise see
  // the same budget and both spend it. This serialises evaluation; it does not queue refusals
  // (§4: exhaustion refuses).
  let inFlight: Promise<unknown> = Promise.resolve();
  /**
   * Set once `relay_tx` was asked (relayed or not): the wallet's memory then holds a transaction
   * its file does not. monero-wallet-rpc saves the file only on `store` or a clean exit, so a host
   * that only ever stops by crashing rescans from the last save at every start (the soak: 18 min,
   * from 12 days back) and loses what it cached since — tx keys, notes, new accounts. A failed
   * store is a warning: the payment's answer and its log lines are already final.
   */
  let unsaved = false;
  const store = async (): Promise<void> => {
    try { await walletRpc(policy, 'store', {}, timeout); } catch (e) {
      console.warn(`sigelo-spend: wallet store after a transfer failed (${why(e)}) — the transfer's answer and log lines stand; the wallet file is saved at the next store or clean exit`);
    }
  };
  // The daemon fallback (`DAEMON_FAILS` above). `misses` counts builds in a row that wallet-rpc
  // refused for want of its daemon, reset by a build that worked; `seen` is the highest wallet
  // height and when it was first seen. Both only ever act from the lane, after an answer.
  const daemons = opts.daemons ?? [], nowMs = opts.daemonClock ?? Date.now;
  let current = 0, misses = 0, switched = -Infinity, asked = -Infinity;
  let seen: { height: number; at: number } | undefined;
  const daemonSaw = (offline: boolean): void => { misses = offline ? misses + 1 : 0; };
  const daemonCheck = async (): Promise<void> => {
    if (daemons.length < 2) return;
    const t = nowMs();
    // The height at most once a minute: a lane of pays must not each wait on a slow wallet.
    if (t - asked >= DAEMON_SWITCH_MS) {
      asked = t;
      try {
        const h = (await walletRpc(policy, 'get_height', {}, 15_000))['height'];
        if (Number.isSafeInteger(h) && (seen === undefined || (h as number) > seen.height)) seen = { height: h as number, at: t };
      } catch { /* wallet-rpc itself not answering: no evidence about its daemon */ }
    }
    const stale = seen !== undefined && t - seen.at >= DAEMON_STALE_MS;
    if ((misses < DAEMON_FAILS && !stale) || t - switched < DAEMON_SWITCH_MS) return;
    const cause = misses >= DAEMON_FAILS ? `${misses} wallet builds in a row answered "no connection to daemon"`
      : `the wallet height has stayed at ${seen!.height} for ${Math.round((t - seen!.at) / 60_000)} min while asked to pay`;
    const from = daemons[current]!;
    current = (current + 1) % daemons.length;
    [switched, misses, seen] = [t, 0, undefined];
    const to = daemons[current]!, which = `${current + 1}/${daemons.length}`;
    try {
      await walletRpc(policy, 'set_daemon', { address: to, trusted: false }, 15_000);
      console.warn(`sigelo-spend: daemon fallback: ${cause}; wallet-rpc moved from ${from} to ${to} (${which}, trusted=false). Not a spend: nothing signed or logged; pays stay TRY LATER (wallet_offline) until the wallet syncs`);
    } catch (e) {
      console.warn(`sigelo-spend: daemon fallback: ${cause}; set_daemon ${to} (${which}) failed (${why(e)}) — the next address is tried in a minute at the earliest`);
    }
  };
  const oneAtATime = (fn: () => Promise<void>): Promise<void> => {
    const run = inFlight.then(fn, fn);
    inFlight = run.catch(() => undefined);
    return run;
  };

  /** The agent a read-only route answers for: the same token → agent step as /pay's. */
  const authorized = (req: IncomingMessage): string | undefined => {
    const token = bearer(req.headers['authorization']);
    return token === undefined || token === '' ? undefined : agentOf(token, eff);
  };

  /** A body, or `undefined` once the refusal is written (or the client is gone). */
  const bodyTimeout = opts.bodyTimeoutMs ?? 10_000;
  const bodyOrFail = async (req: IncomingMessage, res: ServerResponse): Promise<string | undefined> => {
    try { return await readBody(req, bodyTimeout); } catch (e) {
      const status = e instanceof BodyError ? e.status : 400;
      if (status === 0) { res.destroy(); return undefined; }
      // The rest of a body we stopped reading is never read: close the connection with the answer.
      res.setHeader('Connection', 'close');
      fail(res, status, why(e));
      return undefined;
    }
  };

  /**
   * The routes that write the log or may spend take the one-at-a-time lane: /pay; delegation
   * (§4.3), which creates accounts and funds; and /approve — the approver is not an agent and
   * holds no token: its signature, its bundle and the Owner's `approvers` are the authorisation
   * (approval.ts).
   *
   * The body is read, whole and bounded (`readBody`), BEFORE the request joins the lane, so the
   * lane only ever holds work that is ready to run: a client that sends half a body, or goes
   * away while its request waits, holds nothing. A queued request whose client has gone by the
   * time its turn comes is dropped — no wallet call, no log line; there is nobody to answer,
   * and the same command run again is answered from the log like any repeat.
   */
  const lane = new Map<string, (req: IncomingMessage, res: ServerResponse, raw: string) => Promise<void>>([
    ['POST /pay', (q, r, b) => pay(q, r, b)], ['POST /delegate', (q, r, b) => delegate(q, r, b)], ['POST /fund', (q, r, b) => fund(q, r, b)],
    ['POST /revoke', (q, r, b) => revoke(q, r, b)], ['POST /approve', (q, r, b) => approve(q, r, b)],
  ]);

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    refreshTokens(); // before any token is looked at: a rotated token is dead from this request on
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const route = `${req.method} ${url.pathname}`;
    const job = lane.get(route);
    if (job !== undefined) {
      const raw = await bodyOrFail(req, res);
      if (raw === undefined) return;
      let gone = false;
      res.on('close', () => { if (!res.writableFinished) gone = true; });
      return oneAtATime(async () => {
        if (gone || res.destroyed || req.socket.destroyed) return;
        // Every route in the lane signs a line or may spend: none of them runs on a clock set back.
        const behind = clockBehind(clock());
        if (behind !== undefined) return fail(res, 503, behind);
        await job(req, res, raw);
        // After the answer, still in the lane: a transfer is on the wallet's books only in memory
        // until wallet-rpc stores it (soak incident #4: the file was 12 days stale, every stop a crash).
        if (unsaved) { unsaved = false; await store(); }
        // Then the daemon fallback: after the answer, so a switch never delays or changes one.
        await daemonCheck();
      });
    }
    // The read-only routes are not harmless: /log is every destination, purpose and amount
    // this service ever paid, /health is the allowance balance and the wallet's height. They
    // bind to loopback, and loopback is not an authorisation boundary — every process on this
    // host reaches them, and so does any browser page whose name resolves to 127.0.0.1. Same
    // bearer token as /pay, and each answers for that token's agent ONLY: another agent's
    // payees, purposes and balance are not this agent's business. /pay's own token check stays
    // in policy.ts, where §4.1 puts it.
    // The §4.2 agent surface (G3) takes the same token and answers for the same agent only.
    if (['GET /budget', 'GET /log', 'GET /health', 'GET /balance', 'GET /history', 'POST /receive', 'POST /bind', 'GET /delegates'].includes(route)) {
      const who = authorized(req);
      if (who === undefined) return fail(res, 401, 'token: this wallet is not set up for you (unknown or revoked token). Tell your operator.');
      if (route === 'GET /budget') return budget(res, who, url.searchParams.get('agent') ?? url.searchParams.get('bucket'));
      if (route === 'GET /log') return json(res, 200, { entries: readLog(opts.policyPath).filter((r) => agentOfEntry(r.entry) === who) });
      if (route === 'GET /balance') return balance(res, who);
      if (route === 'GET /history') return history(res, who, url.searchParams.get('n'));
      if (route === 'POST /receive') return receive(req, res, who);
      if (route === 'POST /bind') return bindAddr(req, res, who);
      if (route === 'GET /delegates') return delegates(res, who);
      return health(res, who);
    }
    return fail(res, 404, `route: no handler for ${route}`);
  };

  const pay = async (req: IncomingMessage, res: ServerResponse, raw: string): Promise<void> => {
    let parsed: unknown;
    // sigelo's parser, not JSON.parse: this body carries SIGNED objects — a bundle and a §6.3
    // invoice — and a body with the same key twice has no canonical form, so one implementation
    // verifies a signature over bytes another never saw (SPEC §3, THREAT-MODEL §2.8). Reject it.
    try { parsed = parse(raw); } catch (e) { return fail(res, 400, `request: body is not strict JSON (${why(e)})`); }
    const request = asRequest(parsed, bearer(req.headers['authorization']));
    if (typeof request === 'string') return fail(res, 400, request);
    const r = await spend(request, eff);
    return json(res, r.status, r.body);
  };

  /**
   * One spend through every §4.1 check and the two-phase relay. `pol` is the effective policy
   * (roots + live delegates, clamped); for a delegator funding its delegate it is that policy
   * with the delegate's (i, 0) address added to the delegator's allowlist and nothing else
   * changed — funding is an ordinary spend of the delegator (MONERO.md §4.3).
   */
  const spend = async (request: PayRequest, pol: Policy): Promise<Reply> => {
    const now = clock();
    const log = readLog(opts.policyPath);
    const decision: Decision = evaluate(request, pol, state(log), now, { prior: priorOf(log, identity.key), keeper: identity.did });
    // A repeat is answered with the first outcome, from the log; nothing is built or paid.
    if (!decision.ok && decision.repeat !== undefined) return replay(decision.repeat, log);
    if (!decision.ok && decision.conflict === true) return err(409, decision.reason, { ref: request.ref });
    if (!decision.ok && decision.wait !== undefined) {
      // Approvals are paid: without a licence a payment that needs one is refused, never paid
      // without it (fail closed). An approval already on file pays as before.
      const no = unlicensed('approvals (a payment above approval_above)');
      if (no !== undefined) return err(403, no);
      return wait(decision.wait, request, decision.reason, now);
    }
    // A refusal is 403 with the failing check, never a queue and never a retry hint (§4.1) —
    // except the token check, which is 401 here as on every other route: no agent, not a refusal of one.
    if (!decision.ok) return err(codeOf(decision.reason) === 'token' ? 401 : 403, decision.reason, decision.facts === undefined ? {} : { facts: decision.facts });
    const { plan, agent, ref } = decision;
    if (dryRun) {
      // Only the last minute matters to the rate limit, and a tick debits nothing.
      while (dryTicks.length > 0 && dryTicks[0]!.ts <= now - 60) dryTicks.shift();
      dryTicks.push({ ts: now, agent, amount: '0' });
    }

    // (a) Build and price the transaction WITHOUT relaying it. Nothing below this line and
    // above `relay_tx` can move money, so every failure until then is a clean refusal.
    let built;
    try {
      built = asBuilt(await walletRpc(policy, 'transfer', {
        account_index: plan.account_index,
        // The amount is a string everywhere in sigelo and a uint64 only here, at the wall.
        destinations: plan.destinations.map((d) => ({ address: d.address, amount: Number(d.amount) })),
        unlock_time: plan.unlock_time, priority: plan.priority, do_not_relay: true, get_tx_metadata: true,
      }, buildTimeout));
    } catch (e) {
      // "not enough (unlocked) money" gets the account's balance beside it, so the agent can be
      // told what it holds and how long the rest is locked (§4.2) without a second call. A build
      // past its wait (`wallet_slow`) may still finish in wallet-rpc, but it was asked not to
      // relay and its metadata never reached us, so nothing can send it; no line was written, so
      // the same command later is a new build — one payment, not two.
      const slow = codeOf(why(e)) === 'wallet_slow'
        ? ' (the wallet is still building it on a slow daemon link; built with do_not_relay, so what it finishes is never sent — run the same command in a few minutes)' : '';
      const reason = `${why(e)}${slow} — nothing was relayed`;
      if (codeOf(reason) === 'wallet_offline') daemonSaw(true);
      return err(502, reason, ['wallet_locked', 'wallet_funds'].includes(codeOf(reason)) ? await held(plan.account_index) : {});
    }
    if (typeof built === 'string') return err(502, built);
    daemonSaw(false);
    const txid = built.txid;
    if (log.some((r) => r.entry.txid === txid)) return err(502, `wallet: transfer: tx_hash ${txid} is already in spend.log — nothing was relayed`);

    // (b) Both caps on what actually leaves the wallet: amount + fee (MONERO.md §4).
    const cost = BigInt(request.amount) + BigInt(built.fee);
    const fits = affordable(agent, pol.agents[agent]!, cost, 'amount + fee', state(log), now);
    if (!fits.ok) return err(403, fits.reason, { facts: fits.facts });
    // A dry run ends here: a price and a plan, and NO receipt. A signed entry for a
    // transaction nobody broadcast would read, to anyone but us, as proof of a payment.
    if (dryRun) return reply(200, { dry_run: true, amount: request.amount, fee: built.fee, cost: String(cost), plan });

    // (c) Sign every line this spend can write, BEFORE anything is relayed: once money may
    // have moved, nothing may be left that can fail except the disk.
    const base = {
      ts: now,
      // The bearer token and the bundle are stripped: one is a secret, the other is bulk.
      // `ref` and `fp` make a retry answerable from this line alone, after any restart.
      request: {
        to: { addr: plan.destinations[0]!.address, ...(decision.did !== undefined && { did: decision.did }),
          ...(decision.invoice !== undefined && { invoice: decision.invoice }) },
        amount: request.amount, agent, purpose: request.purpose, ref, fp: decision.fp,
        // The approval this spend uses, spent by this line: from here on it answers nothing.
        ...(decision.approval !== undefined && { approval: decision.approval }),
      },
      plan, txid, amount: request.amount, fee: built.fee,
    };
    const lines = {} as Record<'intent' | 'relayed' | 'relay_failed', Receipt>;
    try {
      for (const status of ['intent', 'relayed', 'relay_failed'] as const) {
        const entry: LogEntry = { ...base, status };
        lines[status] = { entry, sig: sign(secret, entry) };
      }
    } catch (e) { return err(400, `request: the spend cannot be signed (${why(e)}) — nothing was relayed`); }

    // (d) The intent line, fsynced. From here on the spend counts against the budget whatever
    // happens next; if it cannot be written, nothing is relayed.
    try { write(lines.intent); } catch (e) { return err(500, `log: intent line not written (${why(e)}) — nothing was relayed`); }

    // (e) Relay. A timeout, a non-JSON reply or a wallet error here does NOT mean the
    // transaction stayed home, so (f) records it as relay_failed and it keeps its debit.
    let failure: string | undefined;
    unsaved = true;
    try {
      const r = await walletRpc(policy, 'relay_tx', { hex: built.metadata }, timeout);
      if (r['tx_hash'] !== txid) failure = `wallet: relay_tx answered tx_hash ${JSON.stringify(r['tx_hash'])}, the built transaction is ${txid}`;
    } catch (e) { failure = why(e); }

    // (f) The outcome line. Receipts exist only for relayed spends.
    if (failure !== undefined) {
      let also = '';
      try { write({ ...lines.relay_failed, error: failure }); } catch (e) { also = ` (and the relay_failed line was not written: ${why(e)} — the intent line stands)`; }
      return reply(502, { error: uncertain(failure) + also, code: 'relay_failed', ref, txid, fee: built.fee });
    }
    const receipt = lines.relayed;
    try { write(receipt); } catch (e) {
      return reply(200, { ref, txid, fee: built.fee, receipt, warning: `log: relayed line not written (${why(e)}) — the intent line still counts this spend` });
    }
    return reply(200, { ref, txid, fee: built.fee, receipt });
  };

  /**
   * §4.2: the same command within the window gets the FIRST outcome back — the same receipt
   * for a relayed spend, the same UNCERTAIN for a relay_failed one or for an intent whose
   * outcome a crash never wrote (money may have moved: never build a second transaction),
   * the approval wait for a pending one. `repeat: true` says it is a replay.
   */
  const replay = (p: Prior, log: Receipt[]): Reply => {
    const r = log[p.line]!;
    const base = { repeat: true, ref: p.ref, txid: r.entry.txid, fee: r.entry.fee };
    if (p.status === 'relayed') return reply(200, { ...base, already_paid: true, receipt: r });
    if (p.status === 'relay_failed') return reply(502, { ...base, code: 'relay_failed', error: uncertain(r.error ?? 'relay_tx failed') });
    if (p.status === 'intent') {
      return reply(502, { ...base, code: 'relay_failed', error: `repeat: this payment was logged as about to be relayed (txid ${r.entry.txid}) and its outcome was never written — it may have been broadcast. Do not pay again; tell your operator.` });
    }
    return reply(202, { repeat: true, ref: p.ref, status: 'approval_needed', code: 'approval', pending: r,
      ...(r.entry.approval_request !== undefined && { approval_request: r.entry.approval_request }) });
  };

  /**
   * §4.1 step 8: no approval on file for a payment above `approval_above`. A signed `pending`
   * line — status inside the signature, no debit — carrying the body an approver must sign,
   * and a 202 with that body. Nothing touched the wallet. The agent asks again; until the
   * request expires the same command gets this same request back (step 4).
   */
  const wait = (w: NonNullable<Extract<Decision, { ok: false }>['wait']>, request: PayRequest, reason: string, now: number): Reply => {
    const approval_request = approvalRequest({
      keeper: identity.did, net: policy.net, agent: w.did, ref: w.ref, to: w.to.addr, amount: request.amount, purpose: request.purpose,
      nonce: randomBytes(16).toString('hex'), iat: now, ttl: policy.max_approval_ttl,
    });
    const entry: LogEntry = {
      ts: now, status: 'pending', request: { to: w.to, amount: request.amount, agent: w.agent, purpose: request.purpose, ref: w.ref, fp: w.fp },
      plan: w.plan, txid: '', amount: request.amount, fee: '0', approval_request,
    };
    try { write({ entry, sig: sign(secret, entry) }); } catch (e) { return err(500, `log: pending line not written (${why(e)}) — nothing was asked or paid`); }
    return reply(202, { status: 'approval_needed', code: 'approval', ref: w.ref, error: reason, approval_request });
  };

  /**
   * POST /approve {body, sig, bundle} (§4.1 "The spend-approval"). approval.ts decides; this
   * finds what it needs in the log — the keeper-signed pending line for the nonce, and whether
   * the nonce was already approved or spent — and writes the signed `approved` line. It pays
   * nothing: the agent's next run of the same pay does (§9 decision 10).
   */
  const approve = async (_req: IncomingMessage, res: ServerResponse, text: string): Promise<void> => {
    const no = unlicensed('approvals (POST /approve)');
    if (no !== undefined) return fail(res, 403, no);
    let raw: unknown;
    try { raw = parse(text); } catch (e) { return fail(res, 400, `request: body is not strict JSON (${why(e)})`); }
    const now = clock();
    const pendings = new Map<string, Receipt>(), used = new Map<string, 'approved' | 'spent'>();
    for (const r of readLog(opts.policyPath)) {
      const e = r.entry;
      if (e.status === 'pending' && plain(e.approval_request) && verifySig(identity.key, e, r.sig)) pendings.set(e.approval_request.nonce, r);
      // Only the keeper's own approved lines count: an appended one must not block a real approval.
      if (e.status === 'approved' && plain(e.approval) && plain(e.approval.body) && verifySig(identity.key, e, r.sig)) used.set(e.approval.body.nonce, 'approved');
      if (e.status === 'intent' && e.request.approval !== undefined) used.set(e.request.approval, 'spent');
    }
    const r = checkApproval(raw, {
      keeper: identity.did, keeperKey: identity.key, net: policy.net, now, maxTtl: policy.max_approval_ttl,
      approvers: (policy.approvers ?? []).map((a) => a.did), used: (n) => used.get(n),
      pending: (n) => {
        const line = pendings.get(n);
        // A pending line of an agent revoked (or removed) since is no request any more.
        const a = line === undefined ? undefined : eff.agents[agentOfEntry(line.entry)];
        if (line === undefined || a?.did === undefined) return undefined;
        return { request: line.entry.approval_request!, agent: { did: a.did, keys: a.genesis === undefined ? [] : [a.genesis.key] } };
      },
    });
    if (!r.ok) return fail(res, 403, r.reason);
    const body = r.approved.body, entry: LogEntry = { ...pendings.get(body.nonce)!.entry, ts: now, status: 'approved', approval: r.approved };
    try { write({ entry, sig: sign(secret, entry) }); } catch (e) { return fail(res, 500, `log: approved line not written (${why(e)}) — nothing was approved`); }
    return json(res, 200, { status: 'approved', ref: body.ref, agent: agentOfEntry(entry), approver: r.approved.approver, nonce: body.nonce, exp: body.exp,
      next: 'the agent runs the same pay again; this approval pays it once' });
  };

  /** What the caller's policy still allows: shared by /budget and /balance. */
  const usage = (who: string) => {
    const a = eff.agents[who]!;
    const now = clock();
    const mine = state().filter((s) => s.agent === who);
    const spent = mine.filter((s) => s.ts > now - a.period_seconds).reduce((t, s) => t + BigInt(s.amount), 0n);
    const cap = BigInt(a.per_period_max);
    return {
      per_tx_max: a.per_tx_max, per_period_max: a.per_period_max, period_seconds: a.period_seconds,
      window_start: now - a.period_seconds, spent: String(spent), remaining: String(spent > cap ? 0n : cap - spent),
      rate: { limit: a.rate_per_minute, used: mine.filter((s) => s.ts > now - 60).length },
    };
  };

  /** `?agent=` (or today's `?bucket=`) may only name the caller: another agent reads as unknown. */
  const budget = (res: ServerResponse, who: string, asked: string | null): void => {
    if (asked !== null && asked !== who) return fail(res, 404, `bucket: your token belongs to ${JSON.stringify(who)}, not ${JSON.stringify(asked)}`);
    return json(res, 200, { agent: who, bucket: who, account: eff.agents[who]!.account, ...usage(who) });
  };

  /** The account's balance as the wallet reports it, or nothing: used beside a wallet refusal. */
  const held = async (account: number): Promise<Record<string, unknown>> => {
    try {
      const b = await walletRpc(policy, 'get_balance', { account_index: account }, 15_000);
      const [balance, unlocked] = [atomicOf(b['balance']), atomicOf(b['unlocked_balance'])];
      if (balance === undefined || unlocked === undefined) return {};
      return { balance, unlocked_balance: unlocked, blocks_to_unlock: Number.isSafeInteger(b['blocks_to_unlock']) ? b['blocks_to_unlock'] : 0 };
    } catch { return {}; }
  };

  /** GET /balance (§4.2): the caller's ACCOUNT, never the wallet total, and what its policy still allows. */
  const balance = async (res: ServerResponse, who: string): Promise<void> => {
    const account = eff.agents[who]!.account;
    const b = await held(account);
    if (!('balance' in b)) return fail(res, 502, `wallet: get_balance for account ${account} failed or answered no balance`);
    return json(res, 200, { agent: who, account, ...b, ...usage(who) });
  };

  /**
   * POST /receive {purpose?} (§4.2): a fresh subaddress of the caller's account, labelled with
   * the purpose in the wallet. Never reused (MONERO.md §3: two payers to one subaddress can
   * link each other). Rate-limited like /pay, in memory: every call grows the wallet's
   * subaddress table, and one past the lookahead is invisible to a restored wallet.
   */
  const minted = new Map<string, number[]>();
  const receive = async (req: IncomingMessage, res: ServerResponse, who: string): Promise<void> => {
    const text = await bodyOrFail(req, res);
    if (text === undefined) return;
    let raw: unknown = {};
    if (text.trim() !== '') { try { raw = parse(text); } catch (e) { return fail(res, 400, `request: body is not strict JSON (${why(e)})`); } }
    if (!plain(raw) || Object.keys(raw).some((k) => k !== 'purpose')) return fail(res, 400, 'request: /receive takes { purpose? } and nothing else');
    const purpose = Object.hasOwn(raw, 'purpose') ? raw['purpose'] : '';
    if (typeof purpose !== 'string' || purpose.length > 200) return fail(res, 400, 'purpose: must be a string of 0..200 characters');
    // Revoked while this body was read: the token is dead now, and so is the answer.
    if (eff.agents[who] === undefined) return fail(res, 401, 'token: this wallet is not set up for you (unknown or revoked token). Tell your operator.');
    const a = eff.agents[who]!, now = clock();
    const recent = (minted.get(who) ?? []).filter((t) => t > now - 60);
    if (recent.length >= a.rate_per_minute) return fail(res, 403, `rate_per_minute: ${recent.length} new addresses for ${JSON.stringify(who)} in the last 60s, limit ${a.rate_per_minute}`);
    minted.set(who, [...recent, now]);
    let r;
    try { r = await walletRpc(policy, 'create_address', { account_index: a.account, label: purpose }, 15_000); } catch (e) { return fail(res, 502, why(e)); }
    if (typeof r['address'] !== 'string' || !Number.isSafeInteger(r['address_index'])) return fail(res, 502, 'wallet: create_address answered no address');
    return json(res, 200, { address: r['address'], account: a.account, index: r['address_index'] });
  };

  /**
   * GET /history?n= (§4.2): the caller's payments out, one per payment (its latest log line),
   * and the transfers into its account (`get_transfers` in and pool, pinned to the account),
   * newest first. `note` is the label /receive gave the subaddress.
   */
  const history = async (res: ServerResponse, who: string, nParam: string | null): Promise<void> => {
    const n = nParam === null ? 10 : Number(nParam);
    if (!Number.isSafeInteger(n) || n < 1 || n > 100) return fail(res, 400, 'request: n must be an integer 1..100');
    const a = eff.agents[who]!;
    const payments = new Map<string, LogEntry>();
    for (const { entry: e } of readLog(opts.policyPath)) {
      if (agentOfEntry(e) !== who) continue;
      // A wait (pending, approved) is one entry per ref until the payment it waited for is built.
      if (e.txid !== '' && e.request.ref !== undefined) payments.delete(`ref ${e.request.ref}`);
      payments.set(e.txid === '' ? `ref ${e.request.ref}` : e.txid, e);
    }
    const out = [...payments.values()].map((e) => {
      const label = a.allow.find((r) => r.addr === e.request.to.addr && r.label !== undefined)?.label;
      return { ts: e.ts, dir: 'out', status: e.status ?? 'relayed', amount: e.amount, fee: e.fee, to: e.request.to.addr,
        ...(label !== undefined && { label }), ...(e.request.to.did !== undefined && { did: e.request.to.did }), purpose: e.request.purpose, txid: e.txid };
    });
    let tr, addrs;
    try {
      tr = await walletRpc(policy, 'get_transfers', { in: true, pool: true, account_index: a.account }, 15_000);
      addrs = await walletRpc(policy, 'get_address', { account_index: a.account }, 15_000);
    } catch (e) { return fail(res, 502, why(e)); }
    const notes = new Map<number, string>();
    for (const x of Array.isArray(addrs['addresses']) ? addrs['addresses'] : []) if (plain(x) && typeof x['label'] === 'string') notes.set(x['address_index'] as number, x['label']);
    const incoming = (list: unknown, pool: boolean) => (Array.isArray(list) ? list : []).flatMap((t: unknown) => {
      // The wallet was asked for this account only; anything else it sends is not shown.
      if (!plain(t) || !plain(t['subaddr_index']) || t['subaddr_index']['major'] !== a.account || atomicOf(t['amount']) === undefined) return [];
      const minor = t['subaddr_index']['minor'] as number;
      const locked = t['locked'] === true || (typeof t['confirmations'] === 'number' && t['confirmations'] < 10);
      return [{ ts: Number(t['timestamp']), dir: 'in', status: pool ? 'pool' : locked ? 'locked' : 'received', amount: atomicOf(t['amount'])!,
        txid: String(t['txid']), address: String(t['address']), index: minor, note: notes.get(minor) ?? '' }];
    });
    const entries = [...out, ...incoming(tr['in'], false), ...incoming(tr['pool'], true)].sort((x, y) => y.ts - x.ts).slice(0, n);
    return json(res, 200, { agent: who, account: a.account, entries });
  };

  /**
   * POST /bind {body} (§4.2, SPEC §6.2): the keeper's `sig_addr` for the caller's OWN account
   * address, (i, 0), over a binding body the agent built and signs `sig_id` over itself.
   * Account 0 (a root agent on the wallet's base address) keeps a view-mode signature at (0,0):
   * "can see this wallet", never "can spend". Any other account is a subaddress, and SPEC §6.2
   * accepts a subaddress binding in either mode; spend mode is used because a subaddress's view
   * signature needs the spend key anyway (secret a·(b + m)), so view mode would claim less than
   * the signer holds without protecting anything. The keeper signs only its own agents'
   * bindings to their own addresses: `id` must be the DID the policy (or the delegate line)
   * gives this agent, `addr` that agent's (i, 0), the window ≤ 30 days around now. The result
   * is checked before it leaves, so a wallet that signed with another key, address or mode is
   * a 502, not a binding that proves something else.
   */
  const bindAddr = async (req: IncomingMessage, res: ServerResponse, who: string): Promise<void> => {
    const text = await bodyOrFail(req, res);
    if (text === undefined) return;
    // /bind is outside the lane but signs: its window check is against `now`, which a clock set back cannot judge.
    const behind = clockBehind(clock());
    if (behind !== undefined) return fail(res, 503, behind);
    let raw: unknown;
    try { raw = parse(text); } catch (e) { return fail(res, 400, `request: body is not strict JSON (${why(e)})`); }
    if (!plain(raw) || Object.keys(raw).join() !== 'body') return fail(res, 400, 'request: /bind takes { body } and nothing else');
    const body = raw['body'];
    try { structure(body, 'binding'); } catch (e) { return fail(res, 400, `bind: body is not a binding (${why(e)})`); }
    if (eff.agents[who] === undefined) return fail(res, 401, 'token: this wallet is not set up for you (unknown or revoked token). Tell your operator.');
    const b = body as Record<string, unknown>, mine = eff.agents[who]!.did;
    if (mine === undefined) return fail(res, 403, `bind: the policy registers no did for ${JSON.stringify(who)} — ask your operator to add it`);
    if (b['id'] !== mine) return fail(res, 403, `bind: body.id is ${JSON.stringify(b['id'])}, but ${JSON.stringify(who)} is ${mine} — the keeper binds its own agents only`);
    if (b['method'] !== 'monero') return fail(res, 403, `bind: method is ${JSON.stringify(b['method'])}, not "monero"`);
    const now = clock(), [iat, exp] = [b['iat'] as number, b['exp'] as number];
    if (!(iat <= now + 300 && now < exp && exp - iat <= BIND_TTL)) return fail(res, 403, `bind: iat ${iat}..exp ${exp} must contain now (${now}) and span at most ${BIND_TTL}s`);
    const account = eff.agents[who]!.account, mode = account === 0 ? 'view' : 'spend';
    let own: unknown, sig: unknown;
    try { own = (await walletRpc(policy, 'get_address', { account_index: account, address_index: [0] }, 15_000))['address']; } catch (e) { return fail(res, 502, why(e)); }
    if (typeof own !== 'string') return fail(res, 502, 'wallet: get_address answered no address');
    if (b['addr'] !== own) return fail(res, 403, `bind: body.addr is ${JSON.stringify(b['addr'])}, but ${JSON.stringify(who)}'s own address (${account}, 0) is ${own}`);
    try {
      sig = (await walletRpc(policy, 'sign', { data: 'sigelo\n' + canonicalize(body), account_index: account, address_index: 0, signature_type: mode }, 15_000))['signature'];
    } catch (e) { return fail(res, 502, why(e)); }
    const v = verifySigeloMoneroSigAddr(body, own, sig);
    if (!v.good || v.mode !== mode) return fail(res, 502, `wallet: sign returned a signature that is not a ${mode}-mode signature by ${own} over this body`);
    return json(res, 200, { addr: own, account, mode, sig_addr: sig });
  };

  /** The caller's own account balance, not the wallet's: the wallet total is every agent's money. */
  const health = async (res: ServerResponse, who: string): Promise<void> => {
    const service = { did: identity.did, key: identity.key };
    try {
      const h = await walletRpc(policy, 'get_height', {}, 15_000);
      const account = eff.agents[who]!.account;
      if (!Number.isSafeInteger(h['height'])) throw new Error('wallet: get_height answered no height');
      const bal = await walletRpc(policy, 'get_balance', { account_index: account }, 15_000);
      const [balance, unlocked] = [atomicOf(bal['balance']), atomicOf(bal['unlocked_balance'])];
      if (balance === undefined || unlocked === undefined) throw new Error(`wallet: get_balance for account ${account} answered no balance`);
      return json(res, 200, {
        net: policy.net, dry_run: dryRun, service, height: h['height'], agent: who, account,
        balance, unlocked_balance: unlocked,
      });
    } catch (e) { return json(res, 502, { error: why(e), code: 'wallet', net: policy.net, dry_run: dryRun, service }); }
  };

  // ---------------------------------------------------------------- delegation (MONERO.md §4.3, §8 G5)

  /** Sign a tree line, append it fsynced, and only then rebuild the tree: the log decides. */
  const writeTree = (entry: TreeEntry): void => {
    const line: TreeLine = { entry, sig: sign(secret, entry) };
    write(line);
    treeLines.push(line);
    tree = replayTree(treeLines.map((l) => l.entry), policy.agents);
    eff = effectivePolicy(policy, tree);
  };
  /** `pol` with one address added to `who`'s allowlist: how a delegator may pay its own delegate. */
  const allowing = (pol: Policy, who: string, addr: string): Policy =>
    ({ ...pol, agents: { ...pol.agents, [who]: { ...pol.agents[who]!, allow: [...pol.agents[who]!.allow, { addr }] } } });
  /** A body that must be a strict-JSON object with only `fields`; a string is the refusal. */
  const bodyOf = (text: string, fields: string[], what: string): Record<string, unknown> | string => {
    let raw: unknown;
    try { raw = parse(text); } catch (e) { return `request: body is not strict JSON (${why(e)})`; }
    if (!plain(raw)) return 'request: body is not an object';
    for (const k of Object.keys(raw)) if (!fields.includes(k)) return `request: ${what} takes { ${fields.join(', ')} } — unknown field ${JSON.stringify(k)}`;
    return raw;
  };
  const noDryRun = (res: ServerResponse): void => fail(res, 403, 'dry_run: delegation creates accounts, writes the log and moves money; a --dry-run keeper does none of that');
  const ATOMIC_FUND = /^(0|[1-9][0-9]*)$/;

  /**
   * POST /delegate {name, fund, caps?, allow?} (§4.3). In order: the nesting rule (tree.ts
   * `planDelegate`); the funding pre-checked against the caller's own caps, so a delegate is not
   * created only to have its funding refused by policy; `create_account` (an index some agent
   * ever held is skipped, never reused); the delegate's identity from `K` at its account; a
   * token, returned here once and stored only as its hash; the signed `delegate` line; then, if
   * `fund` > 0, the funding as an ordinary spend of the caller. The delegate exists from the
   * moment its line is on disk — a funding refusal after that leaves it unfunded, and says so.
   */
  const delegate = async (req: IncomingMessage, res: ServerResponse, text: string): Promise<void> => {
    const token = bearer(req.headers['authorization']);
    const who = authorized(req);
    if (who === undefined || token === undefined) return fail(res, 401, 'token: this wallet is not set up for you (unknown or revoked token). Tell your operator.');
    const no = unlicensed('delegation (POST /delegate)');
    if (no !== undefined) return fail(res, 403, no);
    if (dryRun) return noDryRun(res);
    const raw = bodyOf(text, ['name', 'fund', 'caps', 'allow'], '/delegate');
    if (typeof raw === 'string') return fail(res, 400, raw);
    const [name, fundAmt, capsRaw] = [raw['name'], raw['fund'], raw['caps'] ?? {}];
    if (typeof name !== 'string') return fail(res, 400, 'delegate: name is not a string');
    if (typeof fundAmt !== 'string' || !ATOMIC_FUND.test(fundAmt)) return fail(res, 400, 'delegate: fund is not a decimal string of atomic units ("0" for none)');
    if (!plain(capsRaw)) return fail(res, 400, 'delegate: caps is not an object');
    for (const k of Object.keys(capsRaw)) if (!['per_tx_max', 'per_period_max', 'rate_per_minute', 'max_delegates', 'approval_above'].includes(k)) return fail(res, 400, `delegate: caps: unknown field ${JSON.stringify(k)} — caps is { per_tx_max?, per_period_max?, rate_per_minute?, max_delegates?, approval_above? }`);
    const ask: DelegateAsk = { name, caps: capsRaw as DelegateAsk['caps'] };
    if (Object.hasOwn(raw, 'allow')) {
      try { ask.allow = parseAllow(raw['allow'], policy.net, 'delegate: allow'); } catch (e) { return fail(res, 400, why(e)); }
    }
    // §2 / §9 decision 2: a delegate's genesis carries the ROOT's recovery commitment. A keeper
    // without one would have to invent a recovery key it holds itself — no recovery at all.
    if (policy.recovery_commitment === undefined) return fail(res, 403, 'delegate: policy.json has no recovery_commitment — copy it from the keeper package (keeper-<j>.json) the ceremony wrote');
    // Every name spend.log has ever named is taken, not only the tree's and policy.json's: a
    // root the Owner removed still owns its lines, and a delegate given its name would read them.
    const logged = new Set(readLog(opts.policyPath).map((r) => agentOfEntry(r.entry)));
    const plan = planDelegate(tree, policy.agents, who, ask, { logged, approvers: (policy.approvers ?? []).length });
    if (!plan.ok) return fail(res, 403, plan.reason);
    const now = clock(), fundN = BigInt(fundAmt);
    if (fundN > 0n) {
      const me = eff.agents[who]!, st = state();
      const fits = affordable(who, me, fundN, 'amount', st, now);
      if (!fits.ok) return fail(res, 403, fits.reason, { facts: fits.facts });
      if (st.filter((x) => x.agent === who && x.ts > now - 60).length >= me.rate_per_minute) return fail(res, 403, `rate_per_minute: the funding would exceed ${me.rate_per_minute} spends a minute for ${JSON.stringify(who)}`);
    }

    // The next account index nobody has held. The wallet counts up and never reuses one; an
    // index the policy already names (an Owner-written agent whose account the wallet had not
    // created yet) is created, skipped, and left to that agent.
    const used = usedAccounts(tree, policy.agents);
    let account = -1, address = '';
    for (let tries = 0; tries <= used.size && account < 0; tries++) {
      let r;
      try { r = await walletRpc(policy, 'create_account', { label: `sigelo delegate ${name}` }, 15_000); } catch (e) { return fail(res, 502, why(e)); }
      if (!Number.isSafeInteger(r['account_index']) || typeof r['address'] !== 'string') return fail(res, 502, 'wallet: create_account answered no account_index or address');
      if (!used.has(r['account_index'] as number)) [account, address] = [r['account_index'] as number, r['address']];
    }
    if (account < 0) return fail(res, 502, `wallet: create_account kept answering account indices already held (${[...used].join(', ')}) — nothing was created`);
    try {
      const d = decodeAddress(address);
      if (d.net !== policy.net || d.kind !== 'subaddress') throw new Error(`a ${d.net} ${d.kind} address`);
    } catch (e) { return fail(res, 502, `wallet: create_account answered address ${address} for account ${account}, not a ${policy.net} subaddress (${why(e)})`); }

    // Its identity: `agentIdentitySeed(K, i, 0)`, the root's recovery commitment. The genesis
    // goes into the signed line, so the DID is reproducible from the log and the seed from K.
    const seed = agentIdentitySeed(K, account, 0);
    const id = keygen({ seed, recovery: policy.recovery_commitment });
    const tok = randomBytes(32).toString('hex');
    const entry: DelegateEntry = {
      kind: 'delegate', ts: now, name, parent: who, account, address, did: id.did, genesis: id.genesis,
      token_hash: tokenHash(tok), caps: plan.caps, allow: plan.allow, max_delegates: plan.max_delegates, approval_above: plan.approval_above,
    };
    try { writeTree(entry); } catch (e) { return fail(res, 500, `log: delegate line not written (${why(e)}) — no delegate was created (wallet account ${account} stays empty and unused)`); }
    const credentials = {
      name, account, address, did: id.did, genesis: id.genesis, identity_seed_hex: [...seed].map((x) => x.toString(16).padStart(2, '0')).join(''),
      url: `http://127.0.0.1:${port}`, token: tok, shown_once: 'Give the token to the delegate; it is shown once and the keeper keeps only its hash.',
    };
    if (fundN === 0n) return json(res, 200, { ...credentials, fund: null });
    const f = await spend({ token, to: { addr: address }, amount: fundAmt, purpose: `fund delegate ${name}` }, allowing(eff, who, address));
    // `http` is the funding's own HTTP status; the body's own `status` (e.g. "approval_needed") stays.
    return json(res, 200, { ...credentials, fund: { http: f.status, ...f.body } });
  };

  /** POST /fund {name, amount, ref?}: the caller pays its OWN live delegate's (i, 0), as an ordinary spend. */
  const fund = async (req: IncomingMessage, res: ServerResponse, text: string): Promise<void> => {
    const token = bearer(req.headers['authorization']);
    const who = authorized(req);
    if (who === undefined || token === undefined) return fail(res, 401, 'token: this wallet is not set up for you (unknown or revoked token). Tell your operator.');
    const no = unlicensed('funding a delegate (POST /fund)');
    if (no !== undefined) return fail(res, 403, no);
    if (dryRun) return noDryRun(res);
    const raw = bodyOf(text, ['name', 'amount', 'ref'], '/fund');
    if (typeof raw === 'string') return fail(res, 400, raw);
    const [name, amount, ref] = [raw['name'], raw['amount'], raw['ref']];
    if (typeof name !== 'string' || typeof amount !== 'string' || (ref !== undefined && typeof ref !== 'string')) return fail(res, 400, 'request: /fund takes { name, amount, ref? }, all strings');
    const d = tree.delegates.get(name);
    if (d === undefined || d.parent !== who || statusOf(tree, policy.agents, name) !== 'live') return fail(res, 403, `fund: you have no live delegate named ${JSON.stringify(name)}`);
    const f = await spend({ token, to: { addr: d.address }, amount, purpose: `fund delegate ${name}`, ...(ref !== undefined && { ref }) }, allowing(eff, who, d.address));
    return json(res, f.status, f.body);
  };

  /**
   * POST /revoke {name} (§4.3). (1) A signed `revoke` line unless one already covers it: from
   * that line on, the delegate's token and its whole subtree's match nothing. (2) A sweep of
   * every account in the subtree, each ONE hop to the revoker's (r, 0). Re-running it writes no
   * second line and sweeps whatever has unlocked or arrived since; the keeper never sweeps on
   * its own. The account indices stay retired.
   */
  const revoke = async (req: IncomingMessage, res: ServerResponse, text: string): Promise<void> => {
    const who = authorized(req);
    if (who === undefined) return fail(res, 401, 'token: this wallet is not set up for you (unknown or revoked token). Tell your operator.');
    if (dryRun) return noDryRun(res);
    const raw = bodyOf(text, ['name'], '/revoke');
    if (typeof raw === 'string') return fail(res, 400, raw);
    if (typeof raw['name'] !== 'string') return fail(res, 400, 'revoke: name is not a string');
    const name = raw['name'];
    // Revoked while this body was read (an ancestor revoked the caller): the token is dead now.
    if (eff.agents[who] === undefined) return fail(res, 401, 'token: this wallet is not set up for you (unknown or revoked token). Tell your operator.');
    const plan = planRevoke(tree, who, name);
    if (!plan.ok) return fail(res, 403, plan.reason);
    if (!plan.already) {
      const entry: RevokeEntry = { kind: 'revoke', ts: clock(), name, by: who };
      try { writeTree(entry); } catch (e) { return fail(res, 500, `log: revoke line not written (${why(e)}) — nothing was revoked`); }
    }
    const revoked = { revoked: name, already: plan.already, cascade: plan.accounts.map((a) => a.name) };
    let to: unknown;
    try { to = (await walletRpc(policy, 'get_address', { account_index: eff.agents[who]!.account, address_index: [0] }, 15_000))['address']; } catch (e) {
      return fail(res, 502, `${why(e)} — revoked, but nothing was swept; run revoke again`, revoked);
    }
    if (typeof to !== 'string') return fail(res, 502, 'wallet: get_address answered no address — revoked, but nothing was swept; run revoke again', revoked);
    const sweeps = [];
    for (const a of plan.accounts) sweeps.push(await sweep(a.name, a.account, to, who));
    return json(res, 200, { ...revoked, to, sweeps });
  };

  /**
   * One revoked account's unlocked balance to `to`, two-phase like a spend: `sweep_all` with
   * `do_not_relay` builds and prices it, a sweep that would cost at least what it moves is
   * skipped as dust (§7), and each transaction gets its intent line before `relay_tx` and its
   * outcome after. The lines name the revoked delegate as `agent` — a debit nobody can spend
   * against any more — so the log shows where its money went.
   */
  const sweep = async (name: string, account: number, to: string, by: string): Promise<Record<string, unknown>> => {
    const at = { name, account };
    const b = await held(account);
    if (!('balance' in b)) return { ...at, status: 'error', error: `wallet: get_balance for account ${account} failed — run revoke again` };
    if (b['unlocked_balance'] === '0') return { ...at, ...b, status: 'skipped', reason: b['balance'] === '0' ? 'empty' : 'locked: run revoke again once it unlocks' };
    let r;
    try {
      // wallet-rpc `sweep_all` (docs.getmonero.org/rpc-library/wallet-rpc/#sweep_all):
      // `account_index` + `subaddr_indices_all: true` takes every subaddress of the account, not
      // only those the wallet happens to pick; `unlock_time` 0 (§7); built, not relayed, with
      // the metadata `relay_tx` needs.
      r = await walletRpc(policy, 'sweep_all', {
        address: to, account_index: account, subaddr_indices_all: true, priority: policy.priority, unlock_time: 0,
        do_not_relay: true, get_tx_metadata: true,
      }, buildTimeout);
    } catch (e) {
      if (/no connection to daemon/i.test(why(e))) daemonSaw(true);
      return { ...at, ...b, status: 'skipped', reason: `${why(e)} — nothing was relayed` };
    }
    daemonSaw(false);
    const [txids, fees, amounts, metas] = [r['tx_hash_list'], r['fee_list'], r['amount_list'], r['tx_metadata_list']];
    const n = Array.isArray(txids) ? txids.length : -1;
    if (n < 1 || ![fees, amounts, metas].every((l) => Array.isArray(l) && l.length === n) ||
      !(txids as unknown[]).every((x) => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x)) ||
      ![...(fees as unknown[]), ...(amounts as unknown[])].every((x) => typeof x === 'number' && Number.isSafeInteger(x) && x >= 0) ||
      !(metas as unknown[]).every((x) => typeof x === 'string' && x !== '')) {
      return { ...at, ...b, status: 'error', error: 'wallet: sweep_all answered malformed tx lists — nothing was relayed' };
    }
    const total = (l: unknown) => (l as number[]).reduce((t, x) => t + BigInt(x), 0n);
    const [amount, fee] = [total(amounts), total(fees)];
    if (amount <= fee) return { ...at, ...b, status: 'skipped', reason: `dust: sweeping would move ${amount} for ${fee} in fees — nothing was relayed` };
    const log = readLog(opts.policyPath);
    const out: { txid: string; status: string }[] = [];
    for (let i = 0; i < n; i++) {
      const txid = (txids as string[])[i]!, amt = String((amounts as number[])[i]), f = String((fees as number[])[i]);
      if (log.some((l) => l.entry.txid === txid)) { out.push({ txid, status: 'already in spend.log — not relayed again' }); continue; }
      const base = {
        ts: clock(),
        request: { to: { addr: to }, amount: amt, agent: name, purpose: `sweep: ${name} revoked, to ${by}` },
        plan: { account_index: account, destinations: [{ address: to, amount: amt }], unlock_time: 0, priority: policy.priority, do_not_relay: false },
        txid, amount: amt, fee: f,
      };
      const sig = (status: Status) => ({ entry: { ...base, status }, sig: sign(secret, { ...base, status }) });
      const [intent, relayed, failedLine] = [sig('intent'), sig('relayed'), sig('relay_failed')];
      try { write(intent); } catch (e) { out.push({ txid, status: `not relayed: intent line not written (${why(e)})` }); continue; }
      let failure: string | undefined;
      unsaved = true;
      try {
        const rr = await walletRpc(policy, 'relay_tx', { hex: (metas as string[])[i] }, timeout);
        if (rr['tx_hash'] !== txid) failure = `wallet: relay_tx answered tx_hash ${JSON.stringify(rr['tx_hash'])}, the built transaction is ${txid}`;
      } catch (e) { failure = why(e); }
      try { write(failure === undefined ? relayed : { ...failedLine, error: failure }); } catch { /* the intent line stands */ }
      out.push({ txid, status: failure === undefined ? 'relayed' : `relay_failed: ${failure}` });
    }
    const allRelayed = out.every((o) => o.status === 'relayed');
    return { ...at, ...b, status: allRelayed ? 'swept' : 'uncertain', amount: String(amount), fee: String(fee), txs: out };
  };

  /**
   * GET /delegates: every delegate below the caller, live or not, with what it may spend now
   * (clamped) and what its account holds. A revoked one that still holds funds says so:
   * `revoke` again sweeps it (§4.3 (3)).
   */
  const delegates = async (res: ServerResponse, who: string): Promise<void> => {
    const me = eff.agents[who]!;
    const mine = [...tree.delegates.values()].filter((d) => chain(tree, d.name).slice(1).includes(who));
    const list = [];
    for (const d of mine) {
      const st = statusOf(tree, policy.agents, d.name)!, a = effective(tree, policy.agents, d.name);
      const b = await held(d.account);
      list.push({
        name: d.name, parent: d.parent, account: d.account, address: d.address, did: d.did, status: st,
        ...(a === undefined ? { caps: d.caps, allow: d.allow, max_delegates: d.max_delegates }
          : { caps: { per_tx_max: a.per_tx_max, per_period_max: a.per_period_max, period_seconds: a.period_seconds, rate_per_minute: a.rate_per_minute }, allow: a.allow, max_delegates: a.max_delegates }),
        ...b, ...(st !== 'live' && typeof b['balance'] === 'string' && b['balance'] !== '0' && { holds_funds: true }),
      });
    }
    const used = reserved(tree, policy.agents, who);
    return json(res, 200, { agent: who, max_delegates: me.max_delegates, left: Math.max(0, me.max_delegates - used), delegates: list });
  };

  const server: Server = createServer((req, res) => {
    handler(req, res).catch((e) => json(res, 500, { error: `service: ${why(e)}`, code: 'internal' }));
  });
  try {
    await new Promise<number>((resolve, reject) => {
      server.on('error', reject);
      // Loopback only. Nothing here is safe to expose and the token is a bearer secret.
      server.listen(opts.port ?? 38090, '127.0.0.1', () => {
        const a = server.address();
        port = typeof a === 'object' && a !== null ? a.port : 0;
        resolve(port);
      });
    });
  } catch (e) { dropLock(lock); throw e; }
  return { port, policy, did: identity.did, key: identity.key, identity, licence, close: async () => {
    // The lane first: a spend's store runs after its answer, and must not outlive the keeper that asked for it.
    await inFlight;
    await new Promise<void>((resolve) => server.close(() => { dropLock(lock); resolve(); }));
  } };
}
