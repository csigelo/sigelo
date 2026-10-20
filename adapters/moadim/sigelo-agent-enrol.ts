// SPDX-License-Identifier: MIT
/**
 * Own agents from the operator's seed (contact/enrol.mjs, ENROL.md, THREAT-MODEL §2.11): argv and
 * output. An enrolled agent is WORKER i: an identity derived from the operator's keeper root K
 * (keys.ts `agentIdentitySeed(K, i, n)`, genesis committing to the seed's recovery key), so the 25
 * words bring the same DID back. K lives hot beside the operator identity (`me.local.keeper.json`,
 * 0600), made once by `keeper --from-words`; the words never go to any server. The same run makes
 * the operator identity itself when absent: the ROOT identity of S (keys.ts identitySeed(S, n),
 * genesis pinned like a worker's), marked `derived: {path, n}`; `--rotate-me` derives rotation n+1.
 *
 * Remote: `enrol --name x` prints a one-time code; `init --enrol <code>` on the other machine pairs
 * like any contact (a temporary identity, the four words), then its identity is replaced with the
 * operator's worker i, sent once end to end. `--here`: the worker's file goes into this machine's
 * agents' directory, for a sub-agent's SIGELO_IDENTITY. `--restore i [--rotate]`: the same again.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { did, keygen, parseBytes, VERSION } from 'sigelo';
import { keeperRoot, parseRoot, recoveryCommitment } from 'sigelo/dist/keys.js';
import { bundleOf, head, identityPath, load, save, type Store } from './sigelo-agent.ts';
import { signer } from './sigelo-agent-keys.ts';
import { withLock } from './sigelo-agent-monero.ts';
import { absent, agentFileFor, agentsDirFor, contactLib, debug, heldPath, holderFor, humanPath, lockHolder, MISSING, operatorFile, putBack, safeJson, safeText, trustOf, unreadable, type Batch } from './sigelo-agent-contact.ts';

export const USAGE = `Own agents, derived from your seed (ENROL.md): worker i of your keeper root, restorable from the 25 words
  keeper --from-words [--keeper <j>]       once: your identity (the root identity of the words, when absent) and
       [--replace-me] [--rotate-me]        K_j beside it (0600), the words read from the terminal or stdin (never argv);
                                           j default 1, never 0. --replace-me: an identity not from the words is set
                                           aside; --rotate-me: your identity's next key, rotation n+1 of the words
  enrol --name <n> [--index <i>]           worker i (next free): a one-time code (10 minutes) for the other machine;
       [--wait <s>] [--identity <file>]    it pairs like any contact, then takes on worker i's identity, run by you
       [--tier friend|quiet]               --tier: yours but low trust (it reads the web): its messages wait in the
                                           inbox, never pushed (default own: pushed in full)
  enrol --name <n> --here                  worker i into this machine's agents' directory, for a sub-agent
  enrol --restore <i> [--rotate] [--here]  place worker i again: the same DID; --rotate: its next key (rotation n+1);
                                           the tier stays unless --tier
  enrol --finish [--wait <s>]              finish what is pending here, either side (kept 24 hours)
  init --enrol <code> [--name <n>]         on the other machine: pair, then become the operator's worker
       [--wait <s>]                        (--name: the operator's contact name; --wait 0 to 300 s, default 120)
Operator identity: --identity, else $SIGELO_HUMAN, else ~/.config/sigelo/me.local.json; never in the agents'
directory (SIGELO_IDENTITY's, unless it names this file, and the default's). Exit 3: still pending when the wait ended.`;

interface Placed { id: string; name: string; did: string; original: string; i?: number; n?: number; ours?: boolean | null; tier?: string; temp: string | null; released?: boolean; exp: number;
  worker?: number | null; operator?: string; status?: string | null; contact?: { fingerprint?: string } | null }
interface Out { delivered: { id: string; name: string; temp: string; did: string }[]; placed: Placed[]; refused: { check: string; detail: string; from?: string }[];
  sent: { did: string }[]; rest: Batch; offline?: string; lastError?: unknown }
interface Carrier { relay: string; stop(): Promise<void>; unpark(code: string): Promise<string>; inbox(o: object): Promise<Batch>;
  accept(code: string, o: object): Promise<{ status: string; contact?: { did: string; name: string; fingerprint?: string } }>;
  contacts(): { answers: unknown[]; contacts: { did: string; revoked: boolean; ours: boolean; tier: string }[] }; presetTier(did: string, tier: string): { tier: string } }
interface Enrol {
  enrolPath(identity: string): string;
  pending<T>(file: string, now: number, fn?: (s: { issued: Record<string, { done?: unknown; temp?: string }>; joining: Record<string, { temp?: string }> }) => T): T;
  issue(o: object): Promise<{ short: string; short_exp: number; id: string; did: string; original: string }>;
  accept(o: object): Promise<{ status: string; did: string; contact?: { name: string; did: string; fingerprint?: string } }>;
  complete(o: object): Promise<Out>;
  workerChain(K: Uint8Array, i: number, n: number, recovery: string): { original: string; did: string };
  operatorChain(S: Uint8Array, n: number): { genesis: Store['genesis']; rotations: Store['rotations']; secret: Uint8Array; original: string; did: string };
  operatorIdentity(S: Uint8Array, n: number): Store;
  IDENTITY_PATH: string;
  workerIdentity(o: object): Store;
  operatorAttestation(o: object): { body: { exp: number } };
}
interface Libs { lib: { Carrier: new (o: object) => Carrier; pathsFor(p: string): { store: string; state: string }; optionsFromEnv(): { relay?: string }; DEFAULT_RELAY: string;
  readCode(t: string, now: number): unknown; keepLong(e: unknown, long: string): unknown }; short: { codeKind(t: string): string }; kdf: { MsgError: new (c: string, w: string) => Error }; enrol: Enrol }

const WAIT_MAX = 300, JOIN_WAIT = 120, KEEPER_V = 'sigelo-keeper-hot/0', NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const note = (s: string): void => console.error(`sigelo-agent: ${safeText(s)}`);
const out = (x: unknown): void => console.log(safeJson(JSON.stringify(x, null, 2)));
const nowS = (): number => Math.floor(Date.now() / 1000);
const until = (t: number): string => new Date(t * 1000).toISOString().replace('.000', '');
const usageError = (why: string): Error => Object.assign(new Error(why), { usage: true });
function seconds(v: string | undefined, dflt: number): number {
  if (v === undefined) return dflt;
  if (!/^\d+$/.test(v) || Number(v) > WAIT_MAX) throw usageError(`--wait: whole seconds, 0 to ${WAIT_MAX}, not ${JSON.stringify(v)}`);
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
function checkOperator(path: string, mayBeAbsent = false, what = 'enrol'): void {
  operatorFile(what, path);
  if (!mayBeAbsent && !existsSync(path)) throw usageError(`${what}: no operator identity at ${path}: make it once from your 25 words: sigelo-agent keeper --from-words (read from the terminal, never the command line)`);
}

async function libs(): Promise<Libs> {
  try { return await contactLib() as never; } catch (e) {
    const why = (e as Error).message.split('\n')[0]!;
    throw new Error(absent(e) ? `enrol ${MISSING}: ${why}` : why, { cause: e });
  }
}
function carrierFor(lib: Libs['lib'], path: string): Carrier {
  return new lib.Carrier({
    identity: () => { let s; try { s = load(path); } catch (e) { throw unreadable(path, e); } return { sign: signer(path, s).sign, bundle: bundleOf(s) }; },
    ...lib.pathsFor(path), ...lib.optionsFromEnv(), keep: true,
    onEvent: (e: { type?: string; ms?: number }) => {
      if (e.type === 'pow') note('proof of work for a new identity: 5–60 s');
      else if (e.type === 'pow_done') note(`proof of work done in ${((e.ms ?? 0) / 1000).toFixed(1)} s`);
    },
  });
}

// ---------------------------------------------------------------- the keeper root, hot

/** K, its index, the seed's recovery commitment and the roster of workers: beside the operator identity. */
interface Me { n: number; did: string; original: string }
/** The operator identity file: seed-derived, marked so `rotate` refuses a random key (cli.ts). */
type MeStore = Store & { derived?: { path: string; n: number } };
interface Keeper { v: string; keeper: number; root_hex: string; recovery: string; me?: Me; workers: Record<string, { name: string; n: number; did: string; original: string; placed: string; at: number }> }
export const keeperPath = (op: string): string => op.replace(/\.json$/, '') + '.keeper.json';
function readKeeper(op: string): Keeper {
  const f = keeperPath(op);
  if (!existsSync(f)) throw usageError(`enrol: no keeper root at ${f}: make it once from your 25 words: sigelo-agent keeper --from-words (read from the terminal, never the command line)`);
  let k: Keeper;
  try { k = parseBytes(readFileSync(f)) as never; } catch (e) { throw new Error(`keeper: ${f} does not parse (${(e as Error).message}): make it again with sigelo-agent keeper --from-words`, { cause: e }); }
  if (k?.v !== KEEPER_V || !/^[0-9a-f]{64}$/.test(k.root_hex ?? '') || typeof k.workers !== 'object') throw new Error(`keeper: ${f} is not a ${KEEPER_V} file: make it again with sigelo-agent keeper --from-words`);
  return k;
}
const rootOf = (k: Keeper): { K: Uint8Array; recovery: string } => ({ K: Uint8Array.from(Buffer.from(k.root_hex, 'hex')), recovery: k.recovery });
const writeKeeper = (op: string, fn: (k: Keeper) => void): Keeper => withLock(keeperPath(op), () => { const k = readKeeper(op); fn(k); save(keeperPath(op), k as never); return k; });

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
function placeMe(enrol: Enrol, S: Uint8Array, op: string, known: number | undefined, replace: boolean, rotateMe: boolean): Me {
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
  withLock(op, () => { if (existsSync(op)) throw new Error(`keeper: ${op} appeared meanwhile: run it again`); save(op, id); });
  note(`your identity ${op} (0600): the root identity of your words, rotation ${n} (${d}). Lost, the words make it again: sigelo-agent keeper --from-words`);
  return { n, did: d, original };
}

/** sigelo-agent keeper [--from-words [--replace-me] [--rotate-me]] [--keeper j] [--identity f] → exit code. */
export async function keeperMain(rest: string[]): Promise<number> {
  try {
    const f = flags(rest, ['--keeper', '--identity'], ['--from-words', '--replace-me', '--rotate-me', '--operator']), op = operatorPath(f.get('--identity'));
    if ((f.has('--replace-me') || f.has('--rotate-me')) && !f.has('--from-words')) throw usageError('keeper: --replace-me and --rotate-me go with --from-words: they need the words');
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
        if (old && old.root_hex !== hex) throw Object.assign(new Error(`keeper: ${file} holds another keeper root (K_${old.keeper} of other words, or another index): delete it first if you mean to replace it; its workers stay placed but cannot be restored from it`), { check: 'keeper_exists' });
        me = placeMe(enrol, S, op, old?.me?.n, f.has('--replace-me'), f.has('--rotate-me'));
        withLock(file, () => { if (!existsSync(file)) save(file, { v: KEEPER_V, keeper: j, root_hex: hex, recovery, workers: {} } as never); });
      } finally { S.fill(0); K.fill(0); }
    }
    const k = writeKeeper(op, (x) => { scan(enrol, lib, op, x); if (me) x.me = me; });
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

function flags(rest: string[], value: string[], bare: string[]): Map<string, string> {
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
  if ((e as { usage?: boolean }).usage) { if (!/no (operator identity|keeper root)/.test((e as Error).message)) console.error(USAGE); return 2; }
  return 1;
}
const restored = (w: string): string => `the contacts of the lost copy are gone: it starts with you only. Any contact that invites it again, or that it re-pairs with, sees the same DID ${w}`;

// What a run did, one line each; the rest of the inbox goes back for `inbox`.
function report(path: string, r: Out, said?: string): void {
  putBack(heldPath(path), r.rest);
  for (const e of r.rest.events as { type?: string; name?: string; did?: string; fingerprint?: string | null }[]) {
    if (e.type === 'paired' && e.fingerprint && e.did !== said) note(`paired with ${e.name ?? e.did}. Check with them: ${e.fingerprint}`);
  }
  for (const d of r.delivered) note(`sent worker ${d.did}'s identity to ${d.temp}, end to end, once`);
  for (const p of r.placed) {
    if (p.i !== undefined) note(`${p.name}: paired, then replaced its identity with yours: worker ${p.i} (${p.did}), run by you until ${until(p.exp)}. Its temporary DID ${p.temp} is forgotten. ${trustOf(p.name, p.ours, p.tier, p.i)}`);
    else note(`paired, then replaced this machine's identity with the operator's: worker ${p.worker ?? '?'} (${p.did}), run by ${p.operator} until ${until(p.exp)}. The temporary DID ${p.temp} is forgotten`);
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

/** The operator: worker i derived, then placed here or by a code. */
async function place(opPath: string, f: Map<string, string>): Promise<number> {
  checkOperator(opPath);
  const k = readKeeper(opPath), { K, recovery } = rootOf(k), { lib, enrol } = await libs();
  const restore = f.has('--restore'), here = f.has('--here'), wait = seconds(f.get('--wait'), 0), tier = f.get('--tier');
  // By a code, the operator identity logs in: not beside its page or watcher (the page enrols too).
  if (!here) holderFor(opPath, 'enrol');
  let i: number, n: number, name = f.get('--name');
  if (name !== undefined && !NAME.test(name)) throw usageError(`--name: lowercase letters, digits, _ and -, at most 64 (it names the file sigelo.<name>.local.json), not ${JSON.stringify(name)}`);
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
    const r = await enrol.issue({ carrier: c, file, i, n, name, keeper: { K, recovery } });
    roster('remote');
    tierFor(c, w.original, tier);
    console.log(r.short);
    note(`enrolment code for worker ${i} (${name}), good for 10 minutes (until ${until(r.short_exp)}), once. On the other machine: sigelo-agent init --enrol ${r.short}. `
      + `It pairs like any contact (compare the four words), then its identity is replaced with yours: worker ${i} (${w.did})`
      + (wait > 0 ? `; waiting up to ${wait} s` : '; then here: sigelo-agent enrol --finish'));
    const res = await enrol.complete({ carrier: c, file, keeper: { K, recovery }, wait, until: (o: Out) => o.placed.some((p) => p.id === r.id) });
    report(opPath, res);
    if (res.offline !== undefined) { debug(res.lastError, { identity: opPath, relay: c.relay }); return 1; }
    const done = res.placed.find((p) => p.id === r.id);
    if (done) out({ worker: i, n, did: done.did, original: done.original, name, ours: done.ours, tier: done.tier });
    if (wait > 0 && !done) { note(`enrol: not done within ${wait} s; kept 24 hours: sigelo-agent enrol --finish once the other side has run`); return 3; }
    return 0;
  } finally { await c.stop(); }
}

// The machine: the temporary identity's files, all of them (identity, contacts, carrier, held, files).
function dropTemp(temp: string): void {
  const base = basename(temp).replace(/\.json$/, '');
  for (const f of readdirSync(dirname(temp))) if (f === basename(temp) || f.startsWith(`${base}.`)) rmSync(join(dirname(temp), f), { recursive: true, force: true });
}
// The machine's place(): the worker's file written under its lock, then pairing as the worker.
const placer = (l: Libs, path: string, name: string | undefined, wait: () => number) => async (x: { identity: Store; original: string; did: string; invite: string }, o: { operator: { name: string } }) => {
  withLock(path, () => {
    if (!existsSync(path)) { save(path, x.identity); return; }
    if (did(load(path).genesis) !== x.original) throw new l.kdf.MsgError('enrol_exists', `${path} holds another identity: moved it away? nothing replaced`);
  });
  note(`identity replaced: ${path} (0600) is now ${x.did}`);
  const wc = carrierFor(l.lib, path);
  try { return await wc.accept(x.invite, { name: name ?? o.operator.name, wait: Math.min(wait(), 60) }); } finally { await wc.stop(); }
};

/** The machine, after the code: the temporary identity runs the enrolment until placed or `wait`. */
async function asMachine(l: Libs, path: string, temp: string, name: string | undefined, wait: number, said?: string): Promise<number> {
  const end = Date.now() + wait * 1000, left = (): number => Math.max(0, Math.ceil((end - Date.now()) / 1000));
  const c = carrierFor(l.lib, temp);
  let res: Out;
  try {
    res = await l.enrol.complete({ carrier: c, file: l.enrol.enrolPath(path), temp, wait: left(), until: (o: Out) => o.placed.length > 0, place: placer(l, path, name, left) });
  } finally { await c.stop(); }
  report(temp, res, said);
  const p = res.placed[0];
  if (p) {
    dropTemp(temp);
    out({ did: p.did, original: p.original, worker: p.worker, operator: p.operator, status: p.status });
    if (p.status !== 'connected') { note('enrol: the worker\'s pairing with the operator completes when the operator runs sigelo-agent enrol --finish; then here too'); return 3; }
    return 0;
  }
  if (res.offline !== undefined) { debug(res.lastError, { identity: temp, relay: c.relay }); return 1; }
  note('enrol: not done yet; kept 24 hours: once the operator has run sigelo-agent enrol --finish, run it here too');
  return 3;
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
  let code = 0;
  for (const t of temps) code = Math.max(code, await asMachine(l, agentPath, t, undefined, left()));
  if (answering) {
    const c = carrierFor(lib, agentPath);
    try {
      const b = await c.inbox({ wait: left(), paired: true });
      report(agentPath, { delivered: [], placed: [], refused: [], sent: [], rest: b, ...(b.offline !== undefined && { offline: b.offline }) });
      if (b.offline !== undefined) code = 1;
      else if (c.contacts().answers.length > 0) { note('enrol: the worker\'s pairing still waits for the operator (sigelo-agent enrol --finish there)'); code = code || 3; }
    } finally { await c.stop(); }
  }
  if (issued) {
    checkOperator(opPath);
    const keeper = rootOf(readKeeper(opPath)), c = carrierFor(lib, opPath), file = enrol.enrolPath(opPath);
    try {
      const res = await enrol.complete({ carrier: c, file, keeper, wait: left(), until: (o: Out) => o.placed.length > 0 });
      report(opPath, res);
      if (res.offline !== undefined) { debug(res.lastError, { identity: opPath, relay: c.relay }); code = 1; }
      const still = enrol.pending(file, nowS(), (s) => Object.values(s.issued).filter((e) => !e.done).length);
      if (still > 0 && code !== 1) { note(`enrol: ${still} enrolment(s) still pending as the operator: they finish when the other side has run too`); code = code || 3; }
    } finally { await c.stop(); }
  }
  return code;
}

/** sigelo-agent enrol …; → the exit code (0 done, 1 refused or offline, 2 usage, 3 still pending). */
export async function main(rest: string[]): Promise<number> {
  try {
    const f = flags(rest, ['--name', '--wait', '--identity', '--index', '--restore', '--tier'], ['--finish', '--here', '--rotate', '--operator']);
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

/** sigelo-agent init --enrol <code>: the code is read and fetched before anything is made, so a typo or
 *  a spent code leaves nothing behind; then a temporary identity pairs, and is replaced by the worker. */
export async function initEnrol(path: string, code: string, rest: string[]): Promise<number> {
  const flag = (n: string): string | undefined => (rest.includes(n) ? rest[rest.indexOf(n) + 1] : undefined);
  let long: string | undefined, l: Libs | undefined;
  try {
    const wait = seconds(flag('--wait'), JOIN_WAIT), name = flag('--name'), end = Date.now() + wait * 1000;
    if (existsSync(path)) throw usageError(`init: ${path} already holds an identity; enrolment makes the operator's worker there: use another file (SIGELO_IDENTITY) or move this one away`);
    l = await libs();
    const temp = path.replace(/\.json$/, '') + `.enrol-${randomBytes(4).toString('hex')}.json`;
    // The short code is spent here (one fetch): from now on a refusal prints the long code.
    long = l.short.codeKind(code) === 'short' ? await carrierFor(l.lib, temp).unpark(code) : code.replace(/\s+/g, '');
    l.lib.readCode(long, nowS());
    // Temporary: it only pairs. Its recovery commits to a random key nobody keeps; it lives minutes.
    const t = keygen({ recovery: 'sha256:' + randomBytes(32).toString('hex') });
    save(temp, { v: VERSION, secret: Buffer.from(t.secret).toString('hex'), genesis: t.genesis, rotations: [], attestations: [], issuers: [] });
    note(`a temporary identity (${t.did}) pairs with the operator like any contact; then it is replaced with theirs`);
    const c = carrierFor(l.lib, temp);
    let j;
    try { j = await l.enrol.accept({ carrier: c, file: l.enrol.enrolPath(path), code: long, name: name ?? 'operator', wait: Math.min(wait, 30), temp }); } finally { await c.stop(); }
    note(`the code names ${j.did}: your operator's DID (sigelo-agent whoami there)`);
    if (j.contact) note(`paired with ${j.contact.did} as "${j.contact.name}". Check with them: ${j.contact.fingerprint}`);
    return await asMachine(l, path, temp, name, Math.max(0, Math.ceil((end - Date.now()) / 1000)), j.contact?.did);
  } catch (e) {
    const k = long !== undefined && l !== undefined && long !== code ? l.lib.keepLong(e, long) : e;
    note(k instanceof Error ? k.message : String(k));
    debug(k, { identity: path });
    return (k as { usage?: boolean }).usage ? 2 : 1;
  }
}
