// SPDX-License-Identifier: MIT
/**
 * Own agents from the operator's seed (apps/contact/enrol.mjs, ENROL.md, THREAT-MODEL §2.11): argv and
 * output. An enrolled agent is WORKER i: an identity derived from the operator's keeper root K
 * (keys.ts `agentIdentitySeed(K, i, n)`, genesis committing to the seed's recovery key), so the 25
 * words bring the same DID back. K lives hot beside the operator identity (`me.local.keeper.json`,
 * 0600), made once by `keeper --from-words`; the words never go to any server. The same run makes
 * the operator identity itself when absent: the ROOT identity of S (keys.ts identitySeed(S, n),
 * genesis pinned like a worker's), marked `derived: {path, n}`; `--rotate-me` derives rotation n+1.
 *
 * Remote: `enrol --name x` prints a one-time code; `init --enrol <code>` on the other machine pairs
 * like any contact (a temporary identity), then its identity is replaced with the operator's worker i,
 * sent once end to end. No four words to compare: the operator's side derives worker i's DID itself and
 * marks the worker words-checked when that DID pairs (THREAT-MODEL §2.11: what a code guesser gets);
 * `--confirm-words` asks them before the key goes. The worker files its operator as "operator", or as
 * the label `--operator-name` gave. `--here`: the worker's file goes into this machine's
 * agents' directory, for a sub-agent's SIGELO_IDENTITY. `--restore i [--rotate]`: the same again.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { did, keygen, parseBytes, VERSION } from 'sigelo';
import { keeperRoot, mnemonicFromRoot, newRootBytes, parseRoot, recoveryCommitment, vaultFromRoot } from 'sigelo/dist/keys.js';
import { bundleOf, head, identityPath, load, save, type Store } from './sigelo-agent.ts';
import { main as keysMain, signer } from './sigelo-agent-keys.ts';
import * as keychain from './sigelo-agent-keychain.ts';
import { withLock } from './sigelo-agent-monero.ts';
import { absent, agentFileFor, agentsDirFor, contactLib, debug, duration, heldPath, lifeText, holderFor, humanPath, lockHolder, MISSING, operatorFile, putBack, safeJson, safeText, trustOf, unreadable, type Batch } from './sigelo-agent-contact.ts';

export const USAGE = `Own agents, derived from your seed (ENROL.md): worker i of your keeper root, restorable from the 25 words
  keeper --from-words [--keeper <j>]       once: your identity (the root identity of the words, when absent) and
       [--replace-me] [--rotate-me]        K_j beside it (0600), the words read from the terminal or stdin (never argv);
                                           j default 1, never 0. --replace-me: an identity not from the words is set
                                           aside; --rotate-me: your identity's next key, rotation n+1 of the words
       [--keychain] [--net <n>]            --keychain: the key and K_j sealed in the OS keychain before anything is
       [--restore-height <h> | --restore-date <YYYY-MM-DD>]   written (the phone app's restore); --net mainnet|stagenet
                                           and the wallet's birth, kept in the keeper file for its wallet restore
       [--made-here]                       the words were just made by keeper --new-words (kept: Me says "Created on")
  keeper --new-words [--net <n>]           the phone app's create: 25 new words and their wallet's address as JSON on
                                           stdout, piped only (never a terminal); writes nothing
  enrol --name <n> [--index <i>]           worker i (next free): a one-time enrol code (ENROL-K7F3-Q9ZP, 10 minutes) for
       [--wait <s>] [--identity <file>]    the other machine; it joins you, then takes on worker i's identity, run by you;
                                           checked here: its DID is derived from your words (no four words to compare);
                                           --wait up to the code's life. --name: a-z 0-9 _ - and dots between
       [--ttl <s|10m|1h|24h>]              the code's life, 60 s to 24 h: a local model on a busy CPU takes long
       [--tier friend|quiet]               --tier: yours but low trust (it reads the web): its messages wait in the
                                           inbox, never pushed (default own: pushed in full)
       [--confirm-words]                   ask the four words on this terminal before its key goes (default off)
       [--operator-name <label>]           how it files you (default "operator")
  enrol --name <n> --here                  worker i into this machine's agents' directory, for a sub-agent
  enrol --restore <i> [--rotate] [--here]  place worker i again: the same DID; --rotate: its next key (rotation n+1);
                                           the tier stays unless --tier
  enrol --finish [--wait <s>]              finish what is pending here, either side (kept 24 hours)
  enrol --list | --cancel <code|name|id>   your pending enrolments; drop one (its code stops working, at the relay too)
  init --enrol <code> [--wait <s>]         on the other machine (no identity yet): join the operator, then become its
       [--service]                         worker, filing it as "operator" (or its label); --wait 0 to 300 s, default 60
                                           (under a 120 s tool cap); cut off, or a refused proof of work: the code is not
                                           spent, enrol --finish (or the same init --enrol) takes it up; --service: then
                                           sigelo-agent service install, so its owner's messages always come
Operator identity: --identity, else $SIGELO_HUMAN, else ~/.config/sigelo/me.local.json; never in the agents'
directory (SIGELO_IDENTITY's, unless it names this file, and the default's). Exit 3: still pending when the wait ended.`;

/** A pending enrolment as the operator issued it, and as the machine joins it (apps/contact/enrol.mjs "The pending file"). */
export interface Issued { done?: unknown; temp?: string; i: number; name: string | null; did: string; exp: number; relay: string; short_hash?: string; sent_at?: number; unparked?: boolean; attestation: { body: { iat: number } } }
export interface Joining { temp?: string; code_did: string; exp: number; short_hash?: string; long?: string; answered?: boolean; status?: { check: string; detail: string } }
export interface Placed { id: string; name: string; did: string; original: string; i?: number; n?: number; ours?: boolean | null; tier?: string; temp: string | null; released?: boolean; exp: number;
  worker?: number | null; operator?: string; status?: string | null; contact?: { fingerprint?: string } | null; verified?: boolean; words?: string | null }
export interface Out { delivered: { id: string; name: string; temp: string; did: string }[]; placed: Placed[]; refused: { check: string; detail: string; from?: string }[];
  sent: { did: string }[]; rest: Batch; held?: unknown[]; offline?: string; lastError?: unknown; status?: { check: string; detail: string }[] }
export interface Carrier { relay: string; stop(): Promise<void>; unpark(code: string, o?: { relay: string }): Promise<string>; inbox(o: object): Promise<Batch>;
  accept(code: string, o: object): Promise<{ status: string; contact?: { did: string; name: string; fingerprint?: string } }>;
  contacts(): { answers: unknown[]; contacts: { did: string; revoked: boolean; ours: boolean; tier: string; pair?: string | null }[] }; presetTier(did: string, tier: string): { tier: string } }
export interface Enrol {
  enrolPath(identity: string): string;
  pending<T>(file: string, now: number, fn?: (s: { issued: Record<string, Issued>; joining: Record<string, Joining> }) => T): T;
  issue(o: object): Promise<{ short: string; short_exp: number; id: string; did: string; original: string; enrol_code?: string; relay: string }>;
  accept(o: object): Promise<{ status: string; did: string; contact?: { name: string; did: string; fingerprint?: string } }>;
  resumeAnswer?(o: object): Promise<number>;
  complete(o: object): Promise<Out>;
  workerChain(K: Uint8Array, i: number, n: number, recovery: string): { original: string; did: string };
  operatorChain(S: Uint8Array, n: number): { genesis: Store['genesis']; rotations: Store['rotations']; secret: Uint8Array; original: string; did: string };
  operatorIdentity(S: Uint8Array, n: number): Store;
  IDENTITY_PATH: string;
  workerIdentity(o: object): Store;
  operatorAttestation(o: object): { body: { exp: number } };
}
export interface Libs { lib: { Carrier: new (o: object) => Carrier; pathsFor(p: string): { store: string; state: string }; optionsFromEnv(): { relay?: string }; DEFAULT_RELAY: string;
  readCode(t: string, now: number): unknown; keepLong(e: unknown, long: string): unknown }; short: { codeKind(t: string): string; codeHash(t: string): string; stripEnrol(t: string): string; isEnrolCode(t: string): boolean };
  kdf: { MsgError: new (c: string, w: string) => Error }; enrol: Enrol }

// JOIN_WAIT: init --enrol's default wait, 60 s (the agent-setup feedback, point 8: at 120 s it equalled common agent tool
// caps, and a host killed it mid-step); enrol --finish takes it up. NAME: an agent's contact name, dots allowed
// (k.bench-1); FILE_NAME: one that also names a file (--here: sigelo.<name>.local.json, the MCP profile pattern).
const WAIT_MAX = 300, JOIN_WAIT = 60, TTL_MAX = 86400, KEEPER_V = 'sigelo-keeper-hot/0', NAME = /^[a-z0-9](?:[a-z0-9_-]|\.(?=[a-z0-9_-])){0,63}$/, FILE_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const note = (s: string): void => console.error(`sigelo-agent: ${safeText(s)}`);
const out = (x: unknown): void => console.log(safeJson(JSON.stringify(x, null, 2)));
const nowS = (): number => Math.floor(Date.now() / 1000);
const until = (t: number): string => new Date(t * 1000).toISOString().replace('.000', '');
const usageError = (why: string): Error => Object.assign(new Error(why), { usage: true });
function seconds(v: string | undefined, dflt: number, max = WAIT_MAX): number {
  if (v === undefined) return dflt;
  if (!/^\d+$/.test(v) || Number(v) > max) throw usageError(`--wait: whole seconds, 0 to ${max}${max > WAIT_MAX ? ' (the code\'s --ttl)' : ''}, not ${JSON.stringify(v)}`);
  return Number(v);
}
const index = (flag: string, v: string): number => {
  if (!/^\d+$/.test(v) || !Number.isSafeInteger(Number(v))) throw usageError(`${flag}: a whole number (0, 1, 2…), not ${JSON.stringify(v)}`);
  return Number(v);
};

/** The operator's identity file: --identity, $SIGELO_HUMAN, else ~/.config/sigelo/me.local.json. */
export const operatorPath = (flag: string | undefined, env: Record<string, string | undefined> = process.env): string => (flag !== undefined ? resolve(flag) : humanPath(env));
/** The agents' directory: the pool sub-agents take their SIGELO_IDENTITY from (never the operator's own file's). */
const agentsDir = (op: string): string => agentsDirFor(op);
// The MCP server signs with any `sigelo.<name>.local.json` in the agents' directory, for any caller:
// an operator key there, or K beside it, would be every agent's (operatorFile refuses it).
export function checkOperator(path: string, mayBeAbsent = false, what = 'enrol'): void {
  operatorFile(what, path);
  if (!mayBeAbsent && !existsSync(path)) throw usageError(`${what}: no operator identity at ${path}: make it once from your 25 words: sigelo-agent keeper --from-words (read from the terminal, never the command line)`);
}

export async function libs(): Promise<Libs> {
  try { return await contactLib() as never; } catch (e) {
    const why = (e as Error).message.split('\n')[0]!;
    throw new Error(absent(e) ? `enrol ${MISSING}: ${why}` : why, { cause: e });
  }
}
export function carrierFor(lib: Libs['lib'], path: string, temp = false, enrolHash: string | null = null): Carrier {
  // temp: the throwaway pairing identity, a file key whatever holds the real one: under SIGELO_KEY_AGENT
  // it was key_agent_mismatch, and the enrolment never paired. It lives minutes and is dropped.
  // enrolHash: the enrolment code it holds (its park hash): its first login asks the base proof of work.
  const env = temp ? { ...process.env, SIGELO_KEY_AGENT: undefined } : process.env;
  return new lib.Carrier({ ...(enrolHash !== null && { enrolHash }),
    identity: () => { let s; try { s = load(path); } catch (e) { throw unreadable(path, e); } return { sign: signer(path, s, env).sign, bundle: bundleOf(s) }; },
    ...lib.pathsFor(path), ...lib.optionsFromEnv(), keep: true,
    onEvent: (e: { type?: string; ms?: number }) => {
      if (e.type === 'pow') note('proof of work for a new identity: about 30 s on a phone, minutes under load');
      else if (e.type === 'pow_done') note(`proof of work done in ${((e.ms ?? 0) / 1000).toFixed(1)} s`);
    },
  });
}

// ---------------------------------------------------------------- the keeper root, hot

/** K, its index, the seed's recovery commitment and the roster of workers: beside the operator identity. */
interface Me { n: number; did: string; original: string }
/** The operator identity file: seed-derived, marked so `rotate` refuses a random key (cli.ts). */
type MeStore = Store & { derived?: { path: string; n: number } };
// root_hex: K plain (0600); or root: K sealed in the OS keychain (a FULL device's, DEVICES.md), provider "keychain".
// created: the UTC day the file was first made (YYYY-MM-DD), kept after; not signed, read by nothing here.
export interface Keeper { v: string; keeper: number; root_hex?: string; root?: keychain.WrappedSecret; provider?: string; recovery: string; me?: Me; created?: string;
  workers: Record<string, { name: string; n: number; did: string; original: string; placed: string; at: number; rank?: string; via?: string; revoked?: number; attestation?: { body: { exp: number; iat: number }; sig: string }; until?: number }> }
export const keeperPath = (op: string): string => op.replace(/\.json$/, '') + '.keeper.json';
export function readKeeper(op: string): Keeper {
  const f = keeperPath(op);
  if (!existsSync(f)) throw usageError(`enrol: no keeper root at ${f}: make it once from your 25 words: sigelo-agent keeper --from-words (read from the terminal, never the command line)`);
  let k: Keeper;
  try { k = parseBytes(readFileSync(f)) as never; } catch (e) { throw new Error(`keeper: ${f} does not parse (${(e as Error).message}): make it again with sigelo-agent keeper --from-words`, { cause: e }); }
  const sealed = k?.root !== undefined && k.root_hex === undefined && (k.root as { provider?: unknown }).provider === 'keychain';
  if (k?.v !== KEEPER_V || !(sealed || /^[0-9a-f]{64}$/.test(k.root_hex ?? '')) || typeof k.workers !== 'object') throw new Error(`keeper: ${f} is not a ${KEEPER_V} file: make it again with sigelo-agent keeper --from-words`);
  return k;
}
export const rootOf = (k: Keeper): { K: Uint8Array; recovery: string } =>
  ({ K: k.root_hex !== undefined ? Uint8Array.from(Buffer.from(k.root_hex, 'hex')) : keychain.unwrapRoot(k.root!, k.keeper, k.recovery), recovery: k.recovery });
export const writeKeeper = (op: string, fn: (k: Keeper) => void): Keeper => withLock(keeperPath(op), () => { const k = readKeeper(op); fn(k); save(keeperPath(op), k as never); return k; });

/** The 25 words from the terminal, not echoed, or from stdin when it is not one. Never argv. */
async function readWords(): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) return readFileSync(0, 'utf8');
  process.stderr.write('sigelo-agent: type the 25 words (or 64 hex of the root), then Enter. Nothing is shown.\n> ');
  return new Promise((done) => {
    let s = '';
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    const on = (d: string): void => {
      for (const ch of d) {
        if (ch === '\u0003') { stdin.setRawMode(false); process.stderr.write('\n'); process.exit(130); }
        if (ch === '\r' || ch === '\n') { stdin.off('data', on); stdin.setRawMode(false); stdin.pause(); process.stderr.write('\n'); done(s); return; }
        s = ch === '\u007f' || ch === '\b' ? s.slice(0, -1) : s + ch;
      }
    };
    stdin.on('data', on);
  });
}

// The roster again, from what knows the workers: the operator's contacts and this machine's agents'
// directory. i = 0, 1, … until neither knows worker i's original DID.
function scan(enrol: Enrol, lib: Libs['lib'], op: string, k: Keeper): void {
  const { K, recovery } = rootOf(k), store = lib.pathsFor(op).store;
  const contacts = existsSync(store) ? Object.values((JSON.parse(readFileSync(store, 'utf8')) as { contacts: Record<string, { did: string; name: string; chain: string[]; revoked?: boolean }> }).contacts) : [];
  const pool: { file: string; s: Store }[] = [];
  try { for (const f of readdirSync(agentsDir(op))) if (/^sigelo\.[a-z0-9][a-z0-9_-]{0,63}\.local\.json$/.test(f)) { try { pool.push({ file: f, s: load(join(agentsDir(op), f)) }); } catch {} } } catch {}
  for (let i = 0; ; i++) {
    const original = enrol.workerChain(K, i, 0, recovery).original;
    const c = contacts.find((x) => x.did === original), p = pool.find((x) => did(x.s.genesis) === original);
    if (!c && !p) break;
    if (k.workers[i]) continue;
    const n = c ? c.chain.length - 1 : p!.s.rotations.length;
    k.workers[i] = { name: c?.name ?? p!.file.slice(7, -11), n, did: enrol.workerChain(K, i, n, recovery).did, original, placed: c ? 'remote' : 'here', at: nowS() };
  }
}

/** Set an identity's files aside before another takes its place: `<base>.old-<tag><suffix>`, all or none. */
export function setAside(file: string, tag: string): string[] {
  const base = file.replace(/\.json$/, ''), moves = ['.json', '.contacts.json', '.carrier.json', '.held.json', '.enrol.json', '.history.jsonl', '.ui.json', '.files']
    .filter((x) => existsSync(base + x)).map((x) => [base + x, `${base}.old-${tag}${x}`] as const);
  const taken = moves.find(([, to]) => existsSync(to));
  if (taken) throw new Error(`${taken[1]} exists: move it away first; nothing moved`);
  for (const [from, to] of moves) renameSync(from, to);
  return moves.map(([, to]) => to);
}
const tagOf = (d: string): string => d.slice(-8);
const busyOn = (f: string): void => {
  const h = lockHolder(f);
  if (h) throw Object.assign(new Error(`keeper: ${f} is open in sigelo-agent ${h.kind} (pid ${h.pid}): stop it (Ctrl-C) first; nothing changed`), { check: 'busy' });
};

/** The operator identity from S: written when absent (rotation n), kept when it is S's, rotated with --rotate-me. */
/** An identity file's key sealed in the OS keychain (sigelo-wrap/1, as `keys wrap` and a FULL device scan seal it). */
function sealedMe(id: Store): Store {
  const x = { ...id } as Store, seed = Uint8Array.from(Buffer.from(id.secret as string, 'hex'));
  try { x.secret = keychain.wrap(seed, x, keychain.systemKeychain()) as never; x.provider = 'keychain'; } finally { seed.fill(0); }
  return x;
}
function placeMe(enrol: Enrol, S: Uint8Array, op: string, known: number | undefined, replace: boolean, rotateMe: boolean, wrap = false): Me {
  const original = enrol.operatorChain(S, 0).original, mark = (n: number) => ({ path: `${enrol.IDENTITY_PATH}/${n}`, n });
  if (existsSync(op)) {
    let s: MeStore;
    try { s = load(op); } catch (e) { throw unreadable(op, e); }
    const was = did(s.genesis);
    if (was !== original) {
      if (!replace) throw Object.assign(new Error(`keeper: ${op} is ${was}, a key your words cannot restore. Replacing it loses its contacts and the attestations it issued (they name the old DID); agents made mine with it must be enrolled again. To go on: sigelo-agent keeper --from-words --replace-me (its files are kept aside, .old-${tagOf(was)})`), { check: 'keeper_me' });
      busyOn(op);
      note(`set aside ${setAside(op, tagOf(was)).join(', ')}: ${was} is no longer yours to use here`);
    } else {
      const n = s.rotations.length, c = enrol.operatorChain(S, n);
      if (did(head(s)) !== c.did) throw Object.assign(new Error(`keeper: ${op} is your root identity ${was}, but its rotation ${n} is not from your words (a random rotate, or a recovery): nothing changed`), { check: 'keeper_me' });
      if (!rotateMe) {
        if (s.derived?.n !== n) withLock(op, () => { const t: MeStore = load(op); t.derived = mark(n); save(op, t); });
        note(`your identity ${op} is the root identity of your words (${c.did}, rotation ${n}): kept`);
        return { n, did: c.did, original };
      }
      busyOn(op);
      const x = enrol.operatorChain(S, n + 1);
      withLock(op, () => { const t = load(op); Object.assign(t, { secret: Buffer.from(x.secret).toString('hex'), genesis: x.genesis, rotations: x.rotations, derived: mark(n + 1) }); save(op, t); });
      note(`your identity rotated to rotation ${n + 1} of your words (${x.did}); the previous key retires. Contacts follow at their next exchange; ask each world to reissue its attestation`);
      return { n: n + 1, did: x.did, original };
    }
  }
  const n = (known ?? 0) + (rotateMe ? 1 : 0), id = enrol.operatorIdentity(S, n), d = did(id.rotations.at(-1)?.next_genesis ?? id.genesis);
  mkdirSync(dirname(op), { recursive: true, mode: 0o700 });
  withLock(op, () => { if (existsSync(op)) throw new Error(`keeper: ${op} appeared meanwhile: run it again`); save(op, wrap ? sealedMe(id) : id); });
  note(`your identity ${op} (0600${wrap ? ', its key sealed in the OS keychain' : ''}): the root identity of your words, rotation ${n} (${d}). Lost, the words make it again: sigelo-agent keeper --from-words`);
  return { n, did: d, original };
}

/**
 * The wallet metadata a keeper file keeps for its wallet restore (design/apps-seed.md): net, and the
 * wallet's birth as restore_height or restore_date (UTC day). Field names only: sigelo-spend reads them.
 */
function walletMeta(f: Map<string, string>): { net?: string; restore_height?: number; restore_date?: string } {
  const out: { net?: string; restore_height?: number; restore_date?: string } = {}, h = f.get('--restore-height'), d = f.get('--restore-date'), n = f.get('--net');
  if (n !== undefined) { if (n !== 'mainnet' && n !== 'stagenet') throw usageError(`--net: mainnet or stagenet, not ${JSON.stringify(n)}`); out.net = n; }
  if (h !== undefined && d !== undefined) throw usageError('--restore-height or --restore-date, not both');
  if (h !== undefined) { if (!/^\d{1,10}$/.test(h) || Number(h) > 2 ** 31 - 1) throw usageError(`--restore-height: a block height, not ${JSON.stringify(h)}`); out.restore_height = Number(h); }
  if (d !== undefined) {
    const t = /^(\d{4})-(\d{2})-(\d{2})$/.exec(d) ? Date.parse(`${d}T00:00:00Z`) : NaN;
    if (!(t >= Date.UTC(2014, 3, 18)) || new Date(t).toISOString().slice(0, 10) !== d || t > Date.now()) throw usageError(`--restore-date: a day as YYYY-MM-DD, from 2014-04-18 (Monero's first block) to today, not ${JSON.stringify(d)}`);
    out.restore_date = d;
  }
  return out;
}

/**
 * keeper --new-words [--net n]: a fresh root (newRoot's draw) as its 25 words and the address of its own
 * wallet (the vault), one JSON line on stdout, for the GTK app's create (apps/gtk): it shows them once, asks
 * three back, then hands them to keeper --from-words --made-here on stdin. Writes nothing. Refused on a
 * terminal: the words would stay in its scrollback (on a computer: sigelo-offline new, offline).
 */
function newWordsMain(rest: string[]): number {
  try {
    const f = flags(rest, ['--net'], ['--new-words']), net = f.get('--net') ?? 'mainnet';
    if (net !== 'mainnet' && net !== 'stagenet') throw usageError(`--net: mainnet or stagenet, not ${JSON.stringify(net)}`);
    if (process.stdout.isTTY) throw usageError('keeper --new-words: for the phone app, its output piped; on a terminal the words would stay in its scrollback (on a computer: sigelo-offline new, offline)');
    const S = newRootBytes(), v = vaultFromRoot(S, net);
    try { process.stdout.write(`${JSON.stringify({ words: mnemonicFromRoot(S), vault: v.address, net })}\n`); } finally { S.fill(0); v.b.fill(0); v.a.fill(0); }
    return 0;
  } catch (e) { return failed(e); }
}

/** sigelo-agent keeper [--from-words [--replace-me] [--rotate-me] [--keychain] [--net n] [--restore-height h | --restore-date d]] [--keeper j] [--identity f] → exit code. */
export async function keeperMain(rest: string[]): Promise<number> {
  if (rest.includes('--new-words')) return newWordsMain(rest);
  try {
    const f = flags(rest, ['--keeper', '--identity', '--net', '--restore-height', '--restore-date'], ['--from-words', '--replace-me', '--rotate-me', '--operator', '--keychain', '--made-here']), op = operatorPath(f.get('--identity'));
    if ((f.has('--replace-me') || f.has('--rotate-me')) && !f.has('--from-words')) throw usageError('keeper: --replace-me and --rotate-me go with --from-words: they need the words');
    const meta = { ...walletMeta(f), ...(f.has('--made-here') && { made: 'here' }) }, wrap = f.has('--keychain');
    if ((wrap || Object.keys(meta).length) && !f.has('--from-words')) throw usageError('keeper: --keychain, --net, --restore-height, --restore-date and --made-here go with --from-words');
    if (wrap && !keychain.answers(keychain.systemKeychain())) throw Object.assign(new Error('keeper: keychain_unavailable: --keychain, but no OS keychain answers here (Secret Service, macOS keychain, DPAPI): nothing written'), { check: 'keychain_unavailable' });
    checkOperator(op, f.has('--from-words'), 'keeper');
    const { lib, enrol } = await libs();
    let me: Me | undefined;
    if (f.has('--from-words')) {
      const j = index('--keeper', f.get('--keeper') ?? '1');
      if (j === 0) throw usageError('keeper: not 0: K_0 is the agents\' keeper of the ceremony (sigelo-spend), and worker i under it would be its account i\'s identity. Take an index no sigelo-spend keeper of yours runs on (default 1)');
      let S: Uint8Array;
      try { S = parseRoot(await readWords()); } catch (e) { throw Object.assign(new Error(`keeper: ${(e as Error).message}`), { check: 'keeper_words' }); }
      const K = keeperRoot(S, j), recovery = recoveryCommitment(S), file = keeperPath(op), hex = Buffer.from(K).toString('hex');
      try {
        const old = existsSync(file) ? readKeeper(op) : undefined;
        if (old && Buffer.from(rootOf(old).K).toString('hex') !== hex) throw Object.assign(new Error(`keeper: ${file} holds another keeper root (K_${old.keeper} of other words, or another index): delete it first if you mean to replace it; its workers stay placed but cannot be restored from it`), { check: 'keeper_exists' });
        me = placeMe(enrol, S, op, old?.me?.n, f.has('--replace-me'), f.has('--rotate-me'), wrap);
        // --keychain: K_j sealed under the identity's keychain item before the file exists (the plain write below then finds it).
        if (wrap) withLock(file, () => { if (!existsSync(file)) save(file, { v: KEEPER_V, keeper: j, provider: 'keychain', root: keychain.wrapRoot(K, me!.original, j, recovery), recovery, created: new Date().toISOString().slice(0, 10), workers: {} } as never); });
        withLock(file, () => { if (!existsSync(file)) save(file, { v: KEEPER_V, keeper: j, root_hex: hex, recovery, created: new Date().toISOString().slice(0, 10), workers: {} } as never); });
      } finally { S.fill(0); K.fill(0); }
    }
    const k = writeKeeper(op, (x) => { scan(enrol, lib, op, x); if (me) x.me = me; Object.assign(x, meta); });
    note(`keeper root K_${k.keeper} in ${keeperPath(op)} (0600). It is not your seed: whoever reads it can derive every worker under it, `
      + 'never your vault, your other keepers or the recovery key. A worker\'s key on a server reveals that worker only. Delete the file to stop enrolling; the 25 words make it again.');
    out({ keeper: k.keeper, file: keeperPath(op), recovery: k.recovery, me: k.me ?? null, workers: Object.entries(k.workers).map(([i, w]) => ({ worker: Number(i), ...w })) });
    return 0;
  } catch (e) { return failed(e); }
}

/** The roster's workers by original DID → index, or null without a keeper file (the page's renew-or-enrol). */
export function workersOf(op: string): Map<string, number> | null {
  if (!existsSync(keeperPath(op))) return null;
  return new Map(Object.entries(readKeeper(op).workers).map(([i, w]) => [w.original, Number(i)]));
}

/** The page's Enrol: worker i (next free) into an agent's EXISTING file, its old files set aside. */
export async function enrolInto(op: string, file: string, name: string, relay: string): Promise<{ worker: number; n: number; did: string; original: string; old: string; exp: number; contacts: number }> {
  const k = readKeeper(op), { K, recovery } = rootOf(k), { lib, enrol } = await libs(), t = nowS();
  const used = Object.keys(k.workers).map(Number), i = used.length ? Math.max(...used) + 1 : 0, w = enrol.workerChain(K, i, 0, recovery);
  const me = load(op), attestation = enrol.operatorAttestation({ sign: signer(op, me).sign, iss: did(head(me)), sub: w.original, relay, now: t });
  const id = enrol.workerIdentity({ K, i, n: 0, recovery, attestation, issuer: head(me) });
  let old = '', contacts = 0;
  withLock(file, () => {
    const cur = load(file), store = lib.pathsFor(file).store;
    old = did(cur.genesis);
    try { contacts = Object.values((JSON.parse(readFileSync(store, 'utf8')) as { contacts: Record<string, { revoked?: boolean }> }).contacts).filter((c) => !c.revoked).length; } catch {}
    setAside(file, tagOf(old));
    if (cur.monero) id.monero = cur.monero;   // the treasury's view-only keys; bindings name the old DID: bind again
    save(file, id);
  });
  writeKeeper(op, (x) => { x.workers[i] = { name, n: 0, did: w.did, original: w.original, placed: 'here', at: t }; });
  return { worker: i, n: 0, did: w.did, original: w.original, old, exp: attestation.body.exp, contacts };
}

// ---------------------------------------------------------------- enrol

export function flags(rest: string[], value: string[], bare: string[]): Map<string, string> {
  const m = new Map<string, string>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (!value.includes(a) && !bare.includes(a)) throw usageError(`unexpected ${JSON.stringify(a)}${a.startsWith('--') ? '' : ' (the 25 words are read from the terminal or stdin, never the command line)'}`);
    if (m.has(a)) throw usageError(`${a} given twice`);
    const v = value.includes(a) ? rest[++i] : '';
    if (v === undefined) throw usageError(`${a} needs a value`);
    m.set(a, v);
  }
  return m;
}
function failed(e: unknown): number {
  note(e instanceof Error ? e.message : String(e));
  debug(e, { identity: identityPath() });
  // A wrong value is said in its one line; the whole help only for a command line that is not one (the agent-setup feedback, point 9).
  if ((e as { usage?: boolean }).usage) { if (!(e as { brief?: boolean }).brief && !/no (operator identity|keeper root)|^--wait|^enrol --ttl/.test((e as Error).message)) console.error(USAGE); return 2; }
  return 1;
}
/**
 * Own workers checked by derivation (Placed.verified) are words-checked on the operator's page: its data
 * file (`x.json` → `x.ui.json`, 0600, written whole) gets `checked[original] = pair`, as "They match" does.
 * Only beside no page (holderFor refused one before the run), so the page never writes it at the same time.
 */
export function markChecked(op: string, c: Carrier, placed: Placed[]): number {
  const mine = placed.filter((p) => p.verified === true && p.i !== undefined);
  if (mine.length === 0) return 0;
  const file = op.replace(/\.json$/, '') + '.ui.json', cs = c.contacts().contacts;
  let d: { checked?: Record<string, string> } = {};
  try { d = JSON.parse(readFileSync(file, 'utf8')) as typeof d; } catch {}
  d.checked ??= {};
  let n = 0;
  for (const p of mine) { const x = cs.find((y) => y.did === p.original && !y.revoked); if (x?.pair) { d.checked[x.did] = x.pair; n++; } }
  if (n === 0) return 0;
  const tmp = join(dirname(file), `.${basename(file)}.${randomBytes(8).toString('hex')}.tmp`);
  writeFileSync(tmp, JSON.stringify(d), { mode: 0o600, flag: 'wx' });
  renameSync(tmp, file);
  return n;
}
/** The optional words gate on this terminal (--confirm-words): y only when the agent's machine shows the same four. */
async function askWords(o: { name: string | null; i: number; words: string; ask?: boolean }): Promise<boolean> {
  const { ttyLine } = await import('./sigelo-agent-device.ts');
  const a = await ttyLine(`sigelo-agent: ${o.name ?? `worker ${o.i}`} answered the code. Its machine shows four words: ${o.words}\n  The same there? Its key goes only on y [y/N] `);
  return /^y(es)?$/i.test(a.trim());
}
const restored = (w: string): string => `the contacts of the lost copy are gone: it starts with you only. Any contact that invites it again, or that it re-pairs with, sees the same DID ${w}`;

// What a run did, one line each; the rest of the inbox goes back for `inbox`.
export function report(path: string, r: Out, said?: string, own = false): void {
  putBack(heldPath(path), r.rest);
  // own: an agent's enrolment, whose pairings (the temporary one, the worker's) need no four words:
  // checked by derivation. A device's (sigelo-agent-device.ts) still shows them: its words gate.
  const mine = new Set<string | undefined>([said, ...(own ? r.placed.flatMap((p) => [p.did, p.original, p.temp ?? undefined, p.operator]) : []), ...(own ? r.delivered.map((d) => d.temp) : [])]);
  for (const e of r.rest.events as { type?: string; name?: string; did?: string; fingerprint?: string | null }[]) {
    if (e.type === 'paired' && e.fingerprint && !mine.has(e.did) && !(own && / \(enrolling\)$/.test(e.name ?? ''))) note(`paired with ${e.name ?? e.did}. Check with them: ${e.fingerprint}`);
  }
  for (const d of r.delivered) note(`sent worker ${d.did}'s identity to ${d.temp}, end to end, once`);
  for (const p of r.placed) {
    if (p.i !== undefined) note(`${p.name}: enrolled, its identity replaced with yours: worker ${p.i} (${p.did}), run by you until ${until(p.exp)}. Its temporary DID ${p.temp} is forgotten. `
      + (p.verified ? `Checked: its DID is worker ${p.i} derived here from your words, so no four words to compare${p.words ? ` (if you want them: ${p.words})` : ''}. ` : '') + trustOf(p.name, p.ours, p.tier, p.i));
    else note(`enrolled: this machine's identity replaced with the operator's: worker ${p.worker ?? '?'} (${p.did}), run by ${p.operator} until ${until(p.exp)}. The temporary DID ${p.temp} is forgotten`);
  }
  for (const x of r.refused) note(`enrol: ${x.check}: ${x.detail}`);
  if (r.rest.messages.length > 0) note(`${r.rest.messages.length} other message(s) kept for sigelo-agent inbox`);
  if (r.offline !== undefined) note(`enrol: offline: ${r.offline}`);
}

/** The operator's tier for worker `original` (--tier, kept by tier_by "owner", filed when it pairs), else
 *  what its contact has, else own (detected by the attestation). → the tier. */
function tierFor(c: Carrier, original: string, tier: string | undefined): string {
  if (tier !== undefined) return c.presetTier(original, tier).tier;
  return c.contacts().contacts.find((x) => x.did === original && !x.revoked)?.tier ?? 'own';
}

// The words gate for complete(): asked only for an enrolment made with --confirm-words (ask), else yes.
const gate = async (o: { name: string | null; i: number; words: string; ask?: boolean }): Promise<boolean> => (o.ask ? askWords(o) : true);

/** The operator: worker i derived, then placed here or by a code. */
async function place(opPath: string, f: Map<string, string>): Promise<number> {
  checkOperator(opPath);
  const k = readKeeper(opPath), { K, recovery } = rootOf(k), { lib, enrol } = await libs();
  const ttl = f.has('--ttl') ? duration(f.get('--ttl')!, '--ttl') : undefined;
  if (ttl !== undefined && (f.has('--here') || ttl < 60 || ttl > TTL_MAX)) throw usageError(f.has('--here') ? 'enrol --here: no code, so no --ttl' : `enrol --ttl: the code lives 60 s to 24 h (default 10m; 1h or 24h for a slow local model), not ${lifeText(ttl)}`);
  // --wait: as long as the code lives, at most (the agent-setup feedback, point 9: it stopped at 300 s while --ttl allowed an hour).
  const restore = f.has('--restore'), here = f.has('--here'), wait = seconds(f.get('--wait'), 0, Math.max(WAIT_MAX, ttl ?? 600)), tier = f.get('--tier'), asked = f.has('--confirm-words');
  const operatorName = f.get('--operator-name');
  if (asked && !(await import('./sigelo-agent-device.ts')).hasTty()) throw usageError('enrol --confirm-words: the four words are asked on this terminal (/dev/tty), and there is none');
  // By a code, the operator identity logs in: not beside its page or watcher (the page enrols too).
  if (!here) holderFor(opPath, 'enrol');
  // A worker index is allocated at the seat only (DEVICES.md): a standby refuses seat_elsewhere.
  await (await import('./sigelo-agent-device.ts')).seatGate(opPath, 'enrol');
  let i: number, n: number, name = f.get('--name');
  if (name !== undefined && !NAME.test(name)) throw Object.assign(usageError(`--name: lowercase letters, digits, _, - and dots between them, at most 64, not ${JSON.stringify(name)}`), { brief: true });
  if (name !== undefined && here && !FILE_NAME.test(name)) throw Object.assign(usageError(`enrol --here --name: it names the file sigelo.<name>.local.json: lowercase letters, digits, _ and -, no dots, not ${JSON.stringify(name)}`), { brief: true });
  if (restore) {
    i = index('--restore', f.get('--restore')!);
    const w = k.workers[i];
    if (!w) note(`worker ${i} is not in the roster of ${keeperPath(opPath)}: placing it from K all the same (rotation 0 unless your contacts know more)`);
    name ??= w?.name;
    if (name === undefined) throw usageError(`enrol --restore ${i}: worker ${i} has no name in the roster: give one with --name`);
    n = (w?.n ?? 0) + (f.has('--rotate') ? 1 : 0);
  } else {
    if (name === undefined) throw usageError('enrol: --name <name> is required (the contact name, and the file name with --here)');
    const used = Object.keys(k.workers).map(Number);
    i = f.has('--index') ? index('--index', f.get('--index')!) : used.length ? Math.max(...used) + 1 : 0;
    if (k.workers[i]) throw Object.assign(new Error(`enrol_index: worker ${i} is enrolled already (${k.workers[i]!.name}, ${k.workers[i]!.did}): to place it again, sigelo-agent enrol --restore ${i}`), { check: 'enrol_index' });
    n = 0;
  }
  const w = enrol.workerChain(K, i, n, recovery);
  const roster = (placed: string): void => { writeKeeper(opPath, (x) => { x.workers[i] = { name: name!, n, did: w.did, original: w.original, placed, at: nowS() }; }); };
  if (restore) note(`worker ${i}: ${n > (k.workers[i]?.n ?? 0) ? `rotation ${n}, its next key (the previous one retires), ` : ''}the same DID ${w.original}; ${restored(w.original)}`);
  if (here) {
    const file = join(agentsDir(opPath), `sigelo.${name}.local.json`), s = load(opPath), relay = lib.optionsFromEnv().relay ?? lib.DEFAULT_RELAY, t = nowS();
    const attestation = enrol.operatorAttestation({ sign: signer(opPath, s).sign, iss: did(head(s)), sub: w.original, relay, now: t });
    const id = enrol.workerIdentity({ K, i, n, recovery, attestation, issuer: head(s) });
    mkdirSync(agentsDir(opPath), { recursive: true, mode: 0o700 });
    withLock(file, () => {
      if (existsSync(file)) throw Object.assign(new Error(`enrol: ${file} exists (${did(load(file).genesis)}): move it away first; nothing written`), { check: 'enrol_exists' });
      save(file, id);
    });
    roster('here');
    const oc = carrierFor(lib, opPath);
    let tierNow: string;
    try { tierNow = tierFor(oc, w.original, tier); } finally { await oc.stop(); }
    note(`worker ${i} (${w.did}) written to ${file} (0600), run by you until ${until(attestation.body.exp)}. A sub-agent uses it as SIGELO_IDENTITY=${file}. ${trustOf(name, true, tierNow, i)}`);
    out({ worker: i, n, did: w.did, original: w.original, name, file, ours: true, tier: tierNow });
    return 0;
  }
  const c = carrierFor(lib, opPath), file = enrol.enrolPath(opPath);
  try {
    const r = await enrol.issue({ carrier: c, file, i, n, name, keeper: { K, recovery }, ...(operatorName !== undefined && { operatorName }), ...(asked && { confirmWords: true }), ...(ttl !== undefined && { ttl }) });
    roster('remote');
    tierFor(c, w.original, tier);
    const shown = r.enrol_code ?? r.short;
    console.log(shown);
    note(`enrol code for worker ${i} (${name}), good for ${lifeText(ttl ?? 600)} (until ${until(r.short_exp)}), once. On the other machine: sigelo-agent init --enrol ${shown} --wait 60. `
      + `It joins you, then its identity is replaced with yours: worker ${i} (${w.did}), checked here by its DID${asked ? ' (and the four words, asked here before its key goes)' : ''}`
      + (wait > 0 ? `; waiting up to ${wait} s` : '; then here: sigelo-agent enrol --finish'));
    const res = await enrol.complete({ carrier: c, file, keeper: { K, recovery }, wait, until: (o: Out) => o.placed.some((p) => p.id === r.id), confirm: gate });
    report(opPath, res, undefined, true);
    markChecked(opPath, c, res.placed);
    if (res.offline !== undefined) { debug(res.lastError, { identity: opPath, relay: c.relay }); return 1; }
    const done = res.placed.find((p) => p.id === r.id);
    if (done) out({ worker: i, n, did: done.did, original: done.original, name, ours: done.ours, tier: done.tier });
    if (wait > 0 && !done) { note(`enrol: not done within ${wait} s; kept 24 hours: sigelo-agent enrol --finish once the other side has run`); return 3; }
    return 0;
  } finally { await c.stop(); }
}

// The machine: the temporary identity's files, all of them (identity, contacts, carrier, held, files).
export function dropTemp(temp: string): void {
  const base = basename(temp).replace(/\.json$/, '');
  for (const f of readdirSync(dirname(temp))) if (f === basename(temp) || f.startsWith(`${base}.`)) rmSync(join(dirname(temp), f), { recursive: true, force: true });
}
/**
 * Who this identity works for, from what its file and its contacts say (the agent-setup feedback, points 3 and 6):
 * worker i (its `enrolled` mark, kept at placement; null for one placed before 0.1.19), the operator's DID
 * (the operator attestation's issuer) and name, and the tier its operator's messages have here. null: no worker.
 */
export function workerOf(path: string, s: Store, storePath?: string): { worker: number | null; operator: { did: string; name: string | null; tier: string | null } } | null {
  const mark = (s as Store & { enrolled?: { worker?: number | null; operator?: string } }).enrolled;
  const att = s.attestations.find((a) => (a as { body?: { ctx?: string } }).body?.ctx === 'sigelo-relay/operator') as { body: { iss: string } } | undefined;
  const op = mark?.operator ?? att?.body.iss;
  if (op === undefined) return null;
  let name: string | null = null, tier: string | null = null;
  try {
    const cs = (JSON.parse(readFileSync(storePath ?? path.replace(/\.json$/, '') + '.contacts.json', 'utf8')) as { contacts: Record<string, { name: string; chain?: string[]; revoked?: boolean; tier?: string }> }).contacts;
    const c = Object.values(cs).find((x) => !x.revoked && (x.chain ?? []).includes(op)) ?? cs[op];
    if (c) { name = c.name; tier = c.tier ?? 'own'; }
  } catch {}
  return { worker: Number.isSafeInteger(mark?.worker) ? mark!.worker! : null, operator: { did: op, name, tier } };
}

/** Why init (plain or --enrol) refuses over an existing identity: one line, never "move it away" (models
 *  deleted enrolled worker keys on that advice, the agent-setup feedback point 3). */
export function alreadyHere(path: string): string {
  let s: Store | null = null;
  try { s = load(path); } catch {}
  const w = s ? workerOf(path, s) : null;
  const code = 'an enrol code is for a new machine; a pairing code goes to `sigelo-agent accept CODE`';
  if (w) return `this machine is already worker ${w.worker ?? '?'} of ${w.operator.name ?? 'its operator'} (${w.operator.did}): ${code}; whoami shows it`;
  return `${path} already holds this machine's identity${s ? ` (${did(head(s))})` : ''}: ${code}; another agent here takes its own file (SIGELO_IDENTITY=<new file>)`;
}

/** --force: the identity's files kept as `<file>.bak` (each of its family: .contacts.json → .contacts.json.bak…) before
 *  another takes its place; refused, nothing moved, when a .bak is there already. → the files kept. */
export function keepBak(file: string): string[] {
  const base = file.replace(/\.json$/, ''), moves = ['.json', '.contacts.json', '.carrier.json', '.held.json', '.enrol.json', '.history.jsonl', '.ui.json', '.files']
    .filter((x) => existsSync(base + x)).map((x) => [base + x, `${base + x}.bak`] as const);
  const taken = moves.find(([, to]) => existsSync(to));
  if (taken) throw Object.assign(new Error(`init --force: ${taken[1]} exists, from an earlier --force: keep it somewhere safe first; nothing moved`), { check: 'bak_exists' });
  for (const [from, to] of moves) renameSync(from, to);
  return moves.map(([, to]) => to);
}

// The machine's place(): the worker's file written under its lock, then pairing as the worker.
// The operator is filed as "operator", or as its own label when the enrolment carries one (operator_name).
const placer = (l: Libs, path: string, wait: () => number) => async (x: { identity: Store; original: string; did: string; invite: string; operator_name?: string; worker?: number | null }, ctx?: { operator?: { did: string } }) => {
  const made = withLock(path, () => {
    // enrolled: worker i of which operator (its original DID), for whoami and init's refusal; not signed, read by nothing else.
    if (!existsSync(path)) { save(path, { ...x.identity, ...(ctx?.operator && { enrolled: { worker: x.worker ?? null, operator: ctx.operator.did } }) } as Store); return true; }
    if (did(load(path).genesis) !== x.original) throw new l.kdf.MsgError('enrol_exists', `${path} holds another identity: moved it away? nothing replaced`);
    return false;
  });
  note(`identity replaced: ${path} (0600) is now ${x.did}`);
  // With a key agent the worker's key goes there, as init's does (SIGELO_KEY_PROVIDER=agent): a file key
  // beside SIGELO_KEY_AGENT could not pair as the worker (key_agent_mismatch), and every later call failed.
  if (made && (process.env['SIGELO_KEY_AGENT'] || process.env['SIGELO_KEY_PROVIDER'] === 'agent')) {
    keysMain(['to-agent'], path, load(path));
    note(`the worker's key is in the key agent; ${path} holds none`);
  }
  const wc = carrierFor(l.lib, path);
  try { return await wc.accept(x.invite, { name: x.operator_name ?? 'operator', wait: Math.min(wait(), 60) }); } finally { await wc.stop(); }
};

/** The machine, after the code: the temporary identity runs the enrolment until placed or `wait`. */
// init --enrol --service: the listener installed as a service once placed (sigelo-agent-service.ts).
let serviceAsked = false;
async function asMachine(l: Libs, path: string, temp: string, wait: number, said?: string, own = true): Promise<number> {
  const res = await runMachine(l, path, temp, wait);
  report(temp, res, said, own);
  const p = res.placed[0];
  if (p) {
    dropTemp(temp);
    out({ did: p.did, original: p.original, worker: p.worker, operator: p.operator, status: p.status });
    if (p.status !== 'connected') { note('enrol: the worker joins the operator once the operator runs sigelo-agent enrol --finish; then here: sigelo-agent enrol --finish'); return 3; }
    // Always reachable by its owner (WATCH.md "Always on"): the service, now with --service, else offered in one line.
    if (serviceAsked) return await (await import('./sigelo-agent-service.ts')).main(path, ['install']);
    note('enrol: run sigelo-agent service install to receive your owner\'s messages at all times');
    return 0;
  }
  if (res.offline !== undefined) { debug(res.lastError, { identity: temp, relay: l.lib.optionsFromEnv().relay ?? l.lib.DEFAULT_RELAY }); return 1; }
  // The operator's word on this request (enrol.mjs "The machine is told why"), one line; else the generic one.
  const said_ = res.status?.at(-1);
  note(said_ ? `enrol: not done yet: ${said_.check}: ${said_.detail}; then here: sigelo-agent enrol --finish` : 'enrol: not done yet; kept 24 hours: run sigelo-agent enrol --finish here (again later if it says pending); the code is not spent');
  return 3;
}

/** The machine's enrolment rounds as its temporary identity, until placed or `wait` s (also the page's device scan). */
export async function runMachine(l: Libs, path: string, temp: string, wait: number): Promise<Out> {
  const end = Date.now() + wait * 1000, left = (): number => Math.max(0, Math.ceil((end - Date.now()) / 1000));
  const file = l.enrol.enrolPath(path), hash = l.enrol.pending(file, nowS(), (s) => Object.values(s.joining).find((j) => j.temp === temp)?.short_hash) ?? null;
  const c = carrierFor(l.lib, temp, true, hash);
  try {
    // An answer a refused proof of work withdrew goes again from the pending entry (the agent-setup feedback, point 2).
    await l.enrol.resumeAnswer?.({ carrier: c, file, temp, wait: Math.min(left(), 30) });
    return await l.enrol.complete({ carrier: c, file: l.enrol.enrolPath(path), temp, wait: left(), until: (o: Out) => o.placed.length > 0, place: placer(l, path, left) });
  } finally { await c.stop(); }
}

/** Whatever is pending here: the operator's issued, the machine's joining, a worker's own pairing. */
async function finish(opFlag: string | undefined, wait: number): Promise<number> {
  const l = await libs(), { lib, enrol } = l, end = Date.now() + wait * 1000, left = (): number => Math.max(0, Math.ceil((end - Date.now()) / 1000));
  const opPath = operatorPath(opFlag), agentPath = agentFileFor(opPath);
  const temps = [...new Set(enrol.pending(enrol.enrolPath(agentPath), nowS(), (s) => Object.values(s.joining).map((j) => j.temp)).filter((t): t is string => typeof t === 'string' && existsSync(t)))];
  const issued = existsSync(opPath) && resolve(opPath) !== resolve(agentPath) && enrol.pending(enrol.enrolPath(opPath), nowS(), (s) => Object.values(s.issued).some((e) => !e.done));
  const answering = existsSync(agentPath) && temps.length === 0 && carrierFor(lib, agentPath).contacts().answers.length > 0;
  if (temps.length === 0 && !issued && !answering) { note('enrol: nothing pending here'); return 0; }
  if (temps.length > 0 || answering) holderFor(agentPath, 'enrol --finish');
  if (issued) holderFor(opPath, 'enrol --finish');
  if (issued) await (await import('./sigelo-agent-device.ts')).seatGate(opPath, 'enrol --finish');
  let code = 0;
  for (const t of temps) code = Math.max(code, await asMachine(l, agentPath, t, left()));
  if (answering) {
    const c = carrierFor(lib, agentPath);
    try {
      const b = await c.inbox({ wait: left(), paired: true });
      report(agentPath, { delivered: [], placed: [], refused: [], sent: [], rest: b, ...(b.offline !== undefined && { offline: b.offline }) });
      if (b.offline !== undefined) code = 1;
      else if (c.contacts().answers.length > 0) { note('enrol: the worker still waits for the operator (sigelo-agent enrol --finish there)'); code = code || 3; }
    } finally { await c.stop(); }
  }
  if (issued) {
    checkOperator(opPath);
    const keeper = rootOf(readKeeper(opPath)), c = carrierFor(lib, opPath), file = enrol.enrolPath(opPath);
    try {
      const res = await enrol.complete({ carrier: c, file, keeper, wait: left(), until: (o: Out) => o.placed.length > 0, confirm: gate });
      report(opPath, res, undefined, true);
      markChecked(opPath, c, res.placed);
      if (res.offline !== undefined) { debug(res.lastError, { identity: opPath, relay: c.relay }); code = 1; }
      const still = enrol.pending(file, nowS(), (s) => Object.values(s.issued).filter((e) => !e.done).length);
      if (still > 0 && code !== 1) { note(`enrol: ${still} enrolment(s) still pending as the operator: they finish when the other side has run too`); code = code || 3; }
    } finally { await c.stop(); }
  }
  return code;
}

/** The operator's pending enrolments (enrol --list, the agent-setup feedback point 9): one line each, and JSON. */
async function listPending(opFlag: string | undefined): Promise<number> {
  const opPath = operatorPath(opFlag);
  checkOperator(opPath);
  const { enrol } = await libs(), now = nowS();
  const rows = enrol.pending(enrol.enrolPath(opPath), now, (s) => Object.entries(s.issued).map(([id, e]) => ({ id, worker: e.i, name: e.name,
    state: e.done ? 'done' : e.sent_at !== undefined ? 'sent' : e.temp ? 'answered' : 'waiting', code_spent: e.unparked === true, until: until(e.exp) })));
  for (const r of rows) note(`${r.id.slice(0, 9)}  worker ${r.worker} (${r.name ?? '?'}): ${r.state === 'waiting' ? 'waiting for the other machine' : r.state === 'answered' ? 'its machine answered the code' : r.state === 'sent' ? 'its key went, waiting for it to pair' : 'done'}; kept until ${r.until}. Drop it: sigelo-agent enrol --cancel ${r.name ?? r.id.slice(0, 9)}`);
  if (rows.length === 0) note('enrol: nothing pending here');
  out(rows);
  return 0;
}

/** enrol --cancel <enrol code | name | id>: the code stops working here and at the relay, its temporary contact is
 *  forgotten, and the worker index goes back (revoked instead when its key went already), as the page's Cancel. */
async function cancelPending(opFlag: string | undefined, what: string): Promise<number> {
  const opPath = operatorPath(opFlag);
  checkOperator(opPath);
  const { lib, short, enrol } = await libs(), file = enrol.enrolPath(opPath), bare = short.stripEnrol(what.trim());
  const hash = short.codeKind(bare) === 'short' ? (() => { try { return short.codeHash(bare); } catch { return null; } })() : null;
  const hit = enrol.pending(file, nowS(), (s) => {
    const all = Object.entries(s.issued).filter(([, e]) => !e.done);
    return all.find(([, e]) => hash !== null && e.short_hash === hash) ?? all.find(([id]) => id === what || (what.length >= 6 && id.startsWith(what))) ?? all.filter(([, e]) => e.name === what).at(-1) ?? null;
  });
  if (!hit) throw Object.assign(usageError(`enrol --cancel: no pending enrolment here matches ${JSON.stringify(what)} (an enrol code, a name or an id from enrol --list)`), { brief: true });
  const [id, e] = hit;
  holderFor(opPath, 'enrol --cancel');
  const c = carrierFor(lib, opPath);
  try {
    if (e.short_hash) { try { await (c as unknown as { cancelInvite(h: string, o: object): Promise<unknown> }).cancelInvite(e.short_hash, { relay: e.relay }); } catch {} }
    if (e.temp) { try { await (c as unknown as { forget(d: string): Promise<unknown> }).forget(e.temp); } catch {} }
  } finally { await c.stop(); }
  enrol.pending(file, nowS(), (s) => { delete s.issued[id]; });
  let revoked = false;
  writeKeeper(opPath, (k) => {
    const w = k.workers[e.i];
    if (!w || w.placed !== 'remote' || w.revoked !== undefined) return;
    if (e.sent_at !== undefined) { w.revoked = nowS(); revoked = true; } else delete k.workers[e.i];
  });
  note(`enrol: worker ${e.i} (${e.name ?? '?'}) cancelled: its code no longer works and nothing more is sent${revoked ? '; its key went already, so it is revoked' : '; the index is free again'}`);
  out({ id, worker: e.i, cancelled: true, revoked });
  return 0;
}

/** sigelo-agent enrol …; → the exit code (0 done, 1 refused or offline, 2 usage, 3 still pending). */
export async function main(rest: string[]): Promise<number> {
  try {
    const f = flags(rest, ['--name', '--wait', '--identity', '--index', '--restore', '--tier', '--operator-name', '--ttl', '--cancel', '--enrol'], ['--finish', '--here', '--rotate', '--operator', '--confirm-words', '--list']);
    // enrol --enrol <code> (a model's guess, the agent-setup feedback point 7): the machine's verb is init --enrol.
    if (f.has('--enrol')) throw Object.assign(usageError('enrol is the operator\'s verb (it makes a code). On the machine that got the code: sigelo-agent init --enrol <code>'), { brief: true });
    const alone = (k: string): void => { if ([...f.keys()].some((x) => ![k, '--identity', '--operator'].includes(x))) throw usageError(`enrol: ${k} takes only --identity`); };
    if (f.has('--list')) { alone('--list'); return await listPending(f.get('--identity')); }
    if (f.has('--cancel')) { alone('--cancel'); return await cancelPending(f.get('--identity'), f.get('--cancel')!); }
    if (f.has('--here') && (f.has('--confirm-words') || f.has('--operator-name'))) throw usageError('enrol --here: no code: --confirm-words and --operator-name go with a code');
    if (f.has('--finish') && [...f.keys()].some((k) => !['--finish', '--wait', '--identity', '--operator'].includes(k))) throw usageError('enrol: --finish takes only --wait and --identity');
    if (f.has('--rotate') && !f.has('--restore')) throw usageError('enrol: --rotate goes with --restore <i>');
    if (f.has('--index') && f.has('--restore')) throw usageError('enrol: --index or --restore, not both');
    if (f.has('--here') && f.has('--wait')) throw usageError('enrol: --here waits for nothing (no --wait)');
    // own is the default, detected by the attestation; --tier lowers it at enrolment.
    if (f.has('--tier') && f.get('--tier') !== 'friend' && f.get('--tier') !== 'quiet') throw usageError(`enrol --tier: friend or quiet, not ${JSON.stringify(f.get('--tier'))} (own is the default)`);
    if (f.has('--finish')) return await finish(f.get('--identity'), seconds(f.get('--wait'), 0));
    return await place(operatorPath(f.get('--identity')), f);
  } catch (e) { return failed(e); }
}

/**
 * sigelo-agent init --enrol <code>: a temporary identity fetches the code, pairs, and is replaced by the worker.
 * Refused over an identity already here (alreadyHere; --force keeps it as .bak first). The code is kept pending
 * from its fetch on (apps/contact/enrol.mjs "The pending file"): the same code again, or enrol --finish, takes it
 * up, never fetching it twice or making a second temporary identity; a refused proof of work or a cut-off run
 * spends nothing. An agent's run is strict: the relay must have parked it as an enrolment code (a contact's
 * pairing code never starts one, THREAT-MODEL §2.11a); a device's scan (o.words) compares four words instead.
 */
export async function initEnrol(path: string, code: string, rest: string[], o: { words?: boolean } = {}): Promise<number> {
  // words: a device's scan (sigelo-agent-device.ts), whose giving side asks the four words: they are shown to compare.
  const flag = (n: string): string | undefined => (rest.includes(n) ? rest[rest.indexOf(n) + 1] : undefined);
  let l: Libs | undefined, temp: string | undefined, kept = false;
  try {
    const wait = seconds(flag('--wait'), JOIN_WAIT), name = flag('--name'), end = Date.now() + wait * 1000, left = (): number => Math.max(0, Math.ceil((end - Date.now()) / 1000));
    serviceAsked = rest.includes('--service') && !o.words;
    // --name named the OPERATOR here before (an agent ran `--name <its own name>` and filed its operator so).
    // The operator chooses the agent's name; this side files the operator as "operator" (or its label).
    if (name !== undefined && !o.words) note(`init --enrol: --name ${JSON.stringify(name)} is not used: your operator names this agent, and it is filed here as "operator" (or the label your operator chose)`);
    if (existsSync(path)) {
      if (!rest.includes('--force')) throw usageError(`init --enrol: ${alreadyHere(path)}`);
      busyOn(path);
      note(`init --enrol --force: the identity here kept as ${keepBak(path).join(', ')}`);
    }
    l = await libs();
    const given = l.short.stripEnrol(code.trim()), short = l.short.codeKind(given) === 'short', hash = short ? l.short.codeHash(given) : null, file = l.enrol.enrolPath(path);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    // The same code pending here: taken up again (its temporary identity, its answer), nothing fetched.
    const was = l.enrol.pending(file, nowS(), (s) => Object.values(s.joining).find((j) => typeof j.temp === 'string' && existsSync(j.temp) && (hash !== null ? j.short_hash === hash : j.long === given)));
    if (was?.temp) {
      note(`init --enrol: this code is pending here already (since ${until(was.exp - 86400)}): taken up again, nothing fetched twice. If this run is cut off: sigelo-agent enrol --finish`);
      return await asMachine(l, path, was.temp, wait, undefined, !o.words);
    }
    // Temporary: it only pairs. Its recovery commits to a random key nobody keeps; it lives minutes.
    temp = path.replace(/\.json$/, '') + `.enrol-${randomBytes(4).toString('hex')}.json`;
    const t = keygen({ recovery: 'sha256:' + randomBytes(32).toString('hex') });
    save(temp, { v: VERSION, secret: Buffer.from(t.secret).toString('hex'), genesis: t.genesis, rotations: [], attestations: [], issuers: [] });
    const relay = flag('--relay');
    const c = carrierFor(l.lib, temp, true, hash);
    let j;
    try {
      j = await l.enrol.accept({ carrier: c, file, code: given, name: 'operator', wait: Math.min(wait, 30), temp, strict: !o.words, ...(relay !== undefined && { relay }) });
    } catch (e) {
      // From the fetch on the enrolment is pending here (its entry, its temporary identity): exit 3, not lost.
      if ((e as { pending?: string }).pending !== undefined) kept = true;
      throw e;
    } finally { await c.stop(); }
    kept = true;
    note(`a temporary identity (${t.did}) reached the operator through the enrol code; then it is replaced with theirs. If this run is cut off (a tool timeout): sigelo-agent enrol --finish takes it up`);
    note(`the code names ${j.did}: your operator's DID (sigelo-agent whoami there)`);
    // Own enrolment: the operator's side checks the result by derivation; the four words are shown, not asked.
    if (j.contact && o.words) note(`paired with ${j.contact.did} as "${j.contact.name}". Check with them: ${j.contact.fingerprint}`);
    else if (j.contact) note(`joined ${j.contact.did} through the enrol code${j.contact.fingerprint ? ` (four words, only if your operator asks: ${j.contact.fingerprint})` : ''}`);
    return await asMachine(l, path, temp, left(), j.contact?.did, !o.words);
  } catch (e) {
    const k = e;
    note(k instanceof Error ? k.message : String(k));
    debug(k, { identity: path });
    // Nothing kept (a typo, a pairing code, a code run out): the temporary identity goes with it.
    if (!kept && temp !== undefined) { try { dropTemp(temp); } catch {} }
    if (kept) { note('init --enrol: kept pending here, the code not spent: sigelo-agent enrol --finish (or the same init --enrol again) takes it up'); return 3; }
    return (k as { usage?: boolean }).usage ? 2 : 1;
  }
}
