// SPDX-License-Identifier: MIT
/**
 * `sigelo-agent ui`: the human's side (design/human-ui-plan.md §1-§3, §5). A page on 127.0.0.1 for
 * one person's own DID: contacts in two groups (Mine: tier own; Contacts) with tags and tiers, pairing by short code
 * with the four words, conversations, and the agents on this machine enrolled (worker i of the
 * keeper root, ENROL.md) and paired.
 *
 * The human's identity is the root identity of their 25 words, made by `keeper --from-words`, at
 * $SIGELO_HUMAN or ~/.config/sigelo/me.local.json, never in the agents' directory: the MCP server
 * maps any `identity: "<name>"` to a file there, so a human file there is signable by every agent.
 * One Carrier for it stays connected in this process (CLI verbs log in per call and nobody listens
 * between clicks); what its inbox() hands over (messages, pairing events) goes to
 * `me.local.history.jsonl`, the page's own data (tags, words checked, read marks) to
 * `me.local.ui.json`, both 0600 and in plaintext until §7's keychain (K2): "clear" empties the history. A pid lock (`me.local.ui.pid`) refuses a
 * second page, and cli.ts refuses a session verb (invite, accept, send, inbox, forget) on the file:
 * either would take the relay session and the messages.
 *
 * HTTP: 127.0.0.1, a random port, a 128-bit token in the URL fragment (never logged, never in a
 * Referer), sent back as X-Sigelo-Token: a custom header forces a CORS preflight this server never
 * grants. Host is checked (DNS rebinding), Origin on writes, no cookies; CSP default-src 'self'.
 * The JSON API is UI-API.md. Key: the file key (decision 6; K1-K2 before a public release).
 * `--remote`: a second listener on the LAN, `POST /r` only, sealed per control (sigelo-agent-remote.ts),
 * into the same routes, within the control's scope; `/api/devices/*` never.
 */
import { spawn } from 'node:child_process';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { appendFileSync, chmodSync, closeSync, existsSync, openSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { isIPv4 } from 'node:net';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { did, verify, VERSION, type Attestation, type Genesis } from 'sigelo';
import * as id from './sigelo-agent.ts';
import { signer } from './sigelo-agent-keys.ts';
import { withLock } from './sigelo-agent-monero.ts';
import { enrolInto, keeperPath, workersOf } from './sigelo-agent-enrol.ts';
import { CONTROL_NAME, controlLine, defaultAddress, deviceRoute, isScope, loadAead, newControl, openRequest, R_BODY_MAX, SCOPES, sealAnswer, type Control, type Scope } from './sigelo-agent-remote.ts';
import { agentsDirFor, busyText, contactLib, humanPath, insideAgents, operatorFile, lockHolder, lockPath, safeJson, safeText, unreadable } from './sigelo-agent-contact.ts';

export const OPERATOR_CTX = 'sigelo-relay/operator';
const DAY = 86400, OPERATOR_DAYS = 90, RENEW_DAYS = 14, TAG_MAX = 20, NAME_MAX = 64, TEXT_MAX = 100_000, BODY_MAX = 256 * 1024;
const STATIC: Record<string, [string, string]> = {
  '/': ['ui.html', 'text/html'], '/ui.html': ['ui.html', 'text/html'], '/ui.js': ['ui.js', 'text/javascript'], '/ui.css': ['ui.css', 'text/css'],
  '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json'], '/sw.js': ['sw.js', 'text/javascript'], '/icon.svg': ['icon.svg', 'image/svg+xml'],
};
const HERE = dirname(fileURLToPath(import.meta.url));
const nowS = (): number => Math.floor(Date.now() / 1000);
const note = (s: string): void => console.error(`sigelo-agent: ${safeText(s)}`);

// The operator's file and the agents' directory: one rule for every verb (sigelo-agent-contact.ts).
export { humanPath, insideAgents };

// ---- the pid lock (sigelo-agent-contact.ts lockPath), shared with `watch`: one of them per file
export { lockPath };
/** The pid of a live `ui` on this identity file, or null (a watcher's lock is not a page's). */
export function uiHolder(identity: string): number | null {
  const h = lockHolder(identity);
  return h?.kind === 'ui' ? h.pid : null;
}
export const busy = (identity: string, pid: number, what: string): string => busyText(identity, { pid, kind: 'ui' }, what);
/** The lock for a page (kind ui) or a watcher; refused while either runs on the file. → its release. */
export function takeLock(identity: string, kind: 'ui' | 'watch' = 'ui'): () => void {
  const f = lockPath(identity), mine = kind === 'ui' ? String(process.pid) : `${process.pid} watch`;
  for (let i = 0; i < 3; i++) {
    try {
      const fd = openSync(f, 'wx', 0o600);
      writeSync(fd, mine); closeSync(fd);
      return () => { try { if (readFileSync(f, 'utf8').trim() === mine) rmSync(f, { force: true }); } catch {} };
    } catch (e) {
      if ((e as { code?: string }).code !== 'EEXIST') throw e;
      const h = lockHolder(identity);
      if (h !== null) {
        const what = kind === 'ui' ? (h.kind === 'ui' ? 'a second page' : 'a page') : (h.kind === 'watch' ? 'a second watcher' : 'a watcher');
        throw Object.assign(new Error(busyText(identity, h, what)), { check: 'busy' });
      }
      rmSync(f, { force: true });   // left by a process that is gone
    }
  }
  throw new Error(`cannot take ${f}`);
}

// ---- small files, 0600, written whole (temp sibling + rename)
function writePrivate(file: string, text: string): void {
  const tmp = join(dirname(file), `.${basename(file)}.${randomBytes(8).toString('hex')}.tmp`);
  writeFileSync(tmp, text, { mode: 0o600, flag: 'wx' });
  renameSync(tmp, file);
}
const readJson = <T>(file: string, empty: T): T => { try { return JSON.parse(readFileSync(file, 'utf8')) as T; } catch { return empty; } };

// ---- types of what sigelo-contact hands out (carrier.mjs header)
interface Contact {
  name: string; did: string; current_did: string; chain: string[]; revoked: boolean; relay: string; queued: number; re_pair: string | null; fingerprint: string | null;
  pair: string | null; ours: boolean; tier: string; tier_by: string | null; prekeys: boolean; waiting: string | null;
}
type Ev = Record<string, unknown> & { type?: string };
interface Car {
  relay: string; endpoints?: object; retentionDays: number;
  invite(o: { name?: string; short?: boolean }): Promise<{ code: string; did: string; relay: string; exp: number; short?: string; short_exp?: number }>;
  cancelInvite(code: string): Promise<{ cancelled: boolean; name: string }>;
  accept(code: string, o: { name?: string; wait?: number; tier?: string }): Promise<{ status: string; did?: string; detail?: string; contact?: { did: string; name: string; fingerprint?: string | null } }>;
  rename(who: string, name: string): { did: string; name: string };
  setTier(who: string, tier: string): { did: string; name: string; tier: string };
  observe(bundle: object): { did: string; tier: string } | null;
  contacts(): { contacts: Contact[]; invites: { name: string; exp: number; relay: string }[]; answers: { name: string; did: string; exp: number; relay: string }[] };
  sendAll(to: string, texts: unknown[], o: { label?: string }): Promise<{ status: string; id: string; code?: string; detail?: string }[]>;
  inbox(o: { local: boolean }): Promise<{ messages: Ev[]; events: Ev[]; dropped: Record<string, number> }>;
  clockOffset(): { offset: number; checked: number } | null;
  checkClock(): Promise<unknown>;
  forget(d: string): Promise<{ offline?: string }>;
  start(): Promise<void>; stop(): Promise<void>; sync(o?: { wait?: number }): Promise<void>;
}
interface StoreFile { contacts: Record<string, { revoked: boolean }> }
interface Rec { n: number; at: number; kind: 'in' | 'out' | 'status' | 'event'; did?: string; id?: string | null; text?: unknown; label?: string; status?: string; code?: string; detail?: string; type?: string; name?: string }
interface UiData { tags: Record<string, string[]>; checked: Record<string, string>; read: Record<string, number>; controls: Record<string, Control>; remote?: { port: number } }
interface Agent { name: string; file: string; did?: string; chain?: string[]; mine?: { exp: number; days_left: number } | null; error?: string; bundle?: object }
type Fail = Error & { check?: string; long?: string; status?: number };
const refuse = (status: number, check: string, message: string): never => { throw Object.assign(new Error(message), { check, status }); };

export interface UiOptions {
  identity: string; agents?: string; carrier?: Record<string, unknown>; port?: number;
  /** A LAN listener for remote controls: on `listen` (else the default route's address); `name` made if new, in `scope` (chat). */
  remote?: { listen?: string; name?: string; scope?: Scope };
}
export interface Ui { url: string; port: number; token: string; remote: { ip: string; port: number; name: string | null; line: string | null } | null; close(): Promise<void> }

const dataPath = (identity: string): string => `${resolve(identity).replace(/\.json$/, '')}.ui.json`;
/** `ui --controls`: name, scope, created, last used; never the key. */
export function listControls(identity: string): { name: string; scope: Scope; created: number; last_used: number | null }[] {
  const d = readJson<Partial<UiData>>(dataPath(identity), {});
  return Object.entries(d.controls ?? {}).map(([name, c]) => ({ name, scope: c.scope, created: c.created, last_used: c.last_used })).sort((a, b) => a.name.localeCompare(b.name));
}
/** `ui --revoke-control <name>`: its key forgotten. The page owns ui.json: refused while one runs on the file (stop it: its listener goes with it). */
export function revokeControl(identity: string, name: string): boolean {
  const h = uiHolder(identity);
  if (h !== null) refuse(409, 'busy', busy(identity, h, 'revoking a control here (stop the page: its remote listener stops with it, then revoke)'));
  const f = dataPath(identity), d = readJson<Partial<UiData>>(f, {});
  if (!d.controls?.[name]) return false;
  delete d.controls[name];
  writePrivate(f, JSON.stringify(d));
  return true;
}

export async function startUi(o: UiOptions): Promise<Ui> {
  const path = resolve(o.identity), agentsDir = resolve(o.agents ?? agentsDirFor(path));
  const inside = insideAgents(path, process.env, [agentsDir]);
  if (inside !== null) refuse(400, 'identity', `${path} is in the agents' directory ${inside}: any agent could sign as you there. Use $SIGELO_HUMAN outside it, or the default ~/.config/sigelo/me.local.json`);
  if (!existsSync(path)) refuse(400, 'identity', `no identity at ${path}: make it once from your 25 words: sigelo-agent keeper --from-words`);
  const loadMe = (): id.Store => { try { return id.load(path); } catch (e) { throw unreadable(path, e); } };
  loadMe();
  // --remote: checked before anything is taken.
  let remoteIp: string | null = null;
  if (o.remote) {
    const r = o.remote;
    if (r.name !== undefined && !CONTROL_NAME.test(r.name)) refuse(400, 'remote', `control name: 1 to 20 of a-z 0-9 _ -, starting with a letter or digit`);
    if (r.scope !== undefined && !isScope(r.scope)) refuse(400, 'remote', 'scope: read, chat or all');
    if (r.listen !== undefined && (!isIPv4(r.listen) || r.listen === '0.0.0.0')) refuse(400, 'remote', `--listen: one IPv4 address of this machine, not ${JSON.stringify(r.listen)}`);
    remoteIp = r.listen ?? await defaultAddress() ?? refuse(400, 'remote', 'no LAN address found: give one with --listen <ip>');
    await loadAead();
  }
  const release = takeLock(path);
  const { lib, short } = await contactLib();
  const base = path.replace(/\.json$/, ''), historyFile = `${base}.history.jsonl`, dataFile = `${base}.ui.json`;
  const paths = lib.pathsFor(path), opts = { ...lib.optionsFromEnv(), ...o.carrier } as { endpoints?: object };

  // ---- history: every message and pairing event, one JSON line each; status lines fold into their message
  const recs: Rec[] = [], outById = new Map<string, Rec>();
  let seq = 0;
  const fold = (r: Rec): void => {
    seq = Math.max(seq, r.n);
    if (r.kind !== 'status') { recs.push(r); if (r.kind === 'out' && r.id) outById.set(r.id, r); return; }
    const m = r.id ? outById.get(r.id) : undefined;
    if (m) Object.assign(m, { status: r.status, code: r.code, detail: r.detail, n: r.n });
  };
  if (existsSync(historyFile)) for (const l of readFileSync(historyFile, 'utf8').split('\n')) { try { if (l) fold(JSON.parse(l) as Rec); } catch {} }
  const record = (r: Omit<Rec, 'n' | 'at'>): Rec => {
    const full = { n: seq + 1, at: nowS(), ...r } as Rec;
    appendFileSync(historyFile, JSON.stringify(full) + '\n', { mode: 0o600 });
    fold(full);
    return full;
  };
  if (existsSync(historyFile)) chmodSync(historyFile, 0o600);
  const data = readJson<UiData>(dataFile, { tags: {}, checked: {}, read: {}, controls: {} });
  for (const k of ['tags', 'checked', 'read', 'controls'] as const) data[k] ??= {};
  delete (data as { waiting?: unknown }).waiting;   // kept by an earlier page; the carrier says it now (contacts: prekeys, waiting)
  const saveData = (): void => writePrivate(dataFile, JSON.stringify(data));
  if (o.remote) {
    // A new control by name; an existing one keeps its key and scope (revoke it to change them).
    const name = o.remote.name ?? (Object.keys(data.controls).length === 0 ? 'phone' : undefined), had = name === undefined ? undefined : data.controls[name];
    if (had && o.remote.scope !== undefined && had.scope !== o.remote.scope) { release(); refuse(409, 'remote', `control ${name} has scope ${had.scope}: revoke it (ui --revoke-control ${name}) to make it again with ${o.remote.scope}`); }
    if (name !== undefined && !had) { data.controls[name] = newControl(o.remote.scope ?? 'chat', nowS()); saveData(); }
    o = { ...o, remote: { ...o.remote, ...(name !== undefined && { name }) } };
  }

  // ---- live status, not kept
  const live = { online: new Set<string>(), pow: null as null | { bits: number; since: number }, powDone: null as number | null, error: null as string | null };
  const invites = new Map<string, { id: string; name: string; code: string; exp: number; short?: string; short_exp?: number; paired?: string }>();
  // What the carrier's inbox() hands over, as every client takes it: messages and the events it
  // keeps (pairings, failures, rotations), into the history. Taken at once after any event, and
  // every minute for what no event announced.
  let draining: Promise<void> | null = null, again = false;
  function take(b: { messages: Ev[]; events: Ev[]; dropped: Record<string, number> }): void {
    for (const m of b.messages) {
      if (m['type'] === 'file') record({ kind: 'in', did: m['from'] as string, name: m['contact'] as string, label: m['label'] as string, text: `file ${String(m['name'])} (${String(m['size'])} bytes), saved at ${String(m['path'])}` });
      else record({ kind: 'in', did: m['from'] as string, name: m['name'] as string, text: m['content'], label: m['label'] as string });
    }
    const named = new Set<string>();
    for (const e of b.events) {
      const d = (e['did'] ?? e['from'] ?? e['peer']) as string | undefined;
      switch (e.type) {
        case 'paired': {
          const inv = [...invites.values()].find((x) => x.name === e['name'] && !x.paired);
          if (inv && d) inv.paired = d;
          record({ kind: 'event', type: 'paired', did: d, name: e['name'] as string });
          break;
        }
        // A refusal of one of my messages (it has an id) is its status, from onEvent.
        case 'refused': if (e['id'] === undefined) record({ kind: 'event', type: 'refused', did: d, name: e['name'] as string, code: e['code'] as string, detail: e['detail'] as string }); break;
        case 'pairing_failed': case 're_pair': case 'rotated': case 'dropped':
          if (e.type === 'dropped') named.add(String(e['check']));
          record({ kind: 'event', type: e.type, did: d, name: e['name'] as string, code: (e['code'] ?? e['check']) as string, detail: e['detail'] as string });
          break;
      }
    }
    for (const [check, n] of Object.entries(b.dropped)) if (!named.has(check)) record({ kind: 'event', type: 'dropped', code: check, detail: `${n} dropped` });
  }
  function drain(): Promise<void> {
    if (draining) { again = true; return draining; }
    draining = (async () => {
      try { do { again = false; take(await carrier.inbox({ local: true })); } while (again); } catch (err) { live.error = `inbox: ${(err as Error).message}`; }
      finally { draining = null; }
    })();
    return draining;
  }
  // Inside the carrier's lock for some events: the inbox waits for it to be released.
  const soon = (): void => { setImmediate(() => void drain()); };
  const onEvent = (e: Ev): void => {
    try {
      const d = (e['did'] ?? e['from'] ?? e['peer']) as string | undefined;
      switch (e.type) {
        case 'sent': case 'queued': case 'refused': {
          if (e['control'] !== undefined) break;
          // Before send returns, its own result says the same: only later ones are recorded.
          const st = e.type, i = e['id'] as string | undefined;
          if (i && outById.has(i)) { record({ kind: 'status', id: i, status: st, code: e['code'] as string, detail: e['detail'] as string }); break; }
          // A message queued by a send that failed has no id here: the oldest such one to this peer.
          const orphan = recs.find((r) => r.kind === 'out' && !r.id && r.did === d && r.status === 'queued');
          if (orphan && i && st === 'sent') { orphan.id = i; outById.set(i, orphan); record({ kind: 'status', id: i, status: st }); break; }
          if (st === 'refused' && !i) soon();
          break;
        }
        case 'pow': live.pow = { bits: Number(e['bits']), since: Date.now() }; break;
        case 'pow_done': live.pow = null; live.powDone = Number(e['ms']); break;
        case 'connected': live.online.add(String(e['relay'])); live.error = null; void checkClock(); break;
        case 'disconnected': live.online.delete(String(e['relay'])); break;
        case 'error': live.error = `${e['check']}: ${e['detail']}`; break;
        case 'notice': break;
        default: soon();
      }
    } catch (err) { live.error = `history: ${(err as Error).message}`; }
  };
  const carrier = new lib.Carrier({
    identity: () => { const s = loadMe(); return { sign: signer(path, s).sign, bundle: id.bundleOf(s) }; },
    ...paths, ...opts, keep: true, onEvent,
  }) as unknown as Car;
  const me = (): { store: id.Store; did: string; original: string; chain: string[]; geneses: Record<string, Genesis> } => {
    const store = loadMe(), chain = id.chainOf(store), gs = [store.genesis, ...store.rotations.map((r) => r.next_genesis)];
    return { store, did: did(id.head(store)), original: chain[0]!, chain, geneses: Object.fromEntries(gs.map((g) => [did(g), g])) };
  };
  async function checkClock(): Promise<void> { try { await carrier.checkClock(); } catch {} }
  void checkClock();
  const clockTimer = setInterval(() => void checkClock(), 600_000); clockTimer.unref();
  const drainTimer = setInterval(() => void drain(), 60_000); drainTimer.unref();
  await carrier.start();
  await drain();

  // ---- reads
  const agentCache = new Map<string, { mtime: number; a: Agent }>();
  function agents(): Agent[] {
    let files: string[] = [];
    try { files = readdirSync(agentsDir).filter((f) => f === 'sigelo.local.json' || /^sigelo\.[a-z0-9][a-z0-9_-]{0,63}\.local\.json$/.test(f)).sort(); } catch {}
    const m = me(), t = nowS();
    return files.map((f) => {
      const file = join(agentsDir, f), name = f === 'sigelo.local.json' ? 'default' : f.slice(7, -11);
      let mtime = 0;
      try { mtime = statSync(file).mtimeMs; } catch {}
      const hit = agentCache.get(file);
      if (hit && hit.mtime === mtime && (!hit.a.mine || hit.a.mine.exp > t)) return hit.a;
      let a: Agent;
      try {
        const s = id.load(file), r = verify(id.bundleOf(s), t, m.geneses);
        // "Mine": an unexpired operator attestation from any DID of my chain (§2).
        const exp = Math.max(0, ...m.chain.flatMap((x) => (r.attestations[x] ?? []).filter((b) => b.ctx === OPERATOR_CTX).map((b) => b.exp)));
        a = { name, file, did: r.chain[0]!, chain: r.chain, mine: exp > t ? { exp, days_left: Math.floor((exp - t) / DAY) } : null, bundle: id.bundleOf(s) };
      } catch (e) { a = { name, file, error: (e as Error).message.split('\n')[0]! }; }
      agentCache.set(file, { mtime, a });
      return a;
    });
  }
  const textOf = (v: unknown): string => (typeof v === 'string' ? v : JSON.stringify(v));
  function state(since: number): unknown {
    const t = nowS(), c = carrier.contacts(), local = agents(), clock = carrier.clockOffset();
    const live_ = c.contacts.filter((x) => !x.revoked).map((x) => {
      const pair = x.pair, agent = local.find((a) => a.did !== undefined && x.chain.includes(a.did));
      const mine = agent?.mine ?? null;
      // My agent on this machine, its attestation in its file: own, unless I chose otherwise (store.mjs observe).
      let tier = x.tier;
      if (mine && agent?.bundle && tier !== 'own' && x.tier_by !== 'owner') { try { tier = carrier.observe(agent.bundle)?.tier ?? tier; } catch {} }
      // Their keys not here yet (an invitee who has not read our reply, or a bundle run out), or why messages wait.
      const waiting = x.waiting ?? (x.prekeys ? null : 'their keys have not come: their side has not read the reply yet, or has been away');
      const msgs = recs.filter((r) => (r.kind === 'in' || r.kind === 'out') && r.did === x.did);
      const last = msgs.at(-1), read = data.read[x.did] ?? 0;
      const queued = msgs.filter((r) => r.kind === 'out' && r.status === 'queued');
      return {
        did: x.did, name: x.name, current_did: x.current_did, relay: x.relay, re_pair: x.re_pair, words: x.fingerprint, pair,
        words_checked: pair !== null && data.checked[x.did] === pair, tags: data.tags[x.did] ?? [],
        local: agent?.name ?? null, mine, unread: msgs.filter((r) => r.kind === 'in' && r.n > read).length,
        last: last ? { dir: last.kind, text: textOf(last.text).slice(0, 200), at: last.at, status: last.status ?? null } : null,
        waiting, not_collected: queued.length, queued: x.queued,
        status: x.re_pair ? 'pair_again' : waiting ? 'waiting' : queued.length ? 'not_collected' : 'ok', ours: x.ours === true || mine !== null, tier,
      };
    });
    // Mine: ours by key, whatever the tier (an own agent set to friend is still mine), or tier own.
    const isMine = (x: { ours: boolean; tier: string }): boolean => x.ours || x.tier === 'own';
    const mineGroup = live_.filter(isMine), rest = live_.filter((x) => !isMine(x));
    const pendingInvites = c.invites.map((p) => {
      const ours = [...invites.values()].find((x) => x.name === p.name);
      return { name: p.name, exp: p.exp, relay: p.relay, ...(ours && { id: ours.id, short: ours.short ?? null, short_exp: ours.short_exp ?? null, code: ours.code }) };
    });
    const paired = [...invites.values()].filter((x) => x.paired).map((x) => ({ id: x.id, name: x.name, paired: x.paired }));
    const failed = recs.filter((r) => r.kind === 'event' && r.type === 'pairing_failed' && r.at > t - DAY).slice(-5).map((r) => ({ name: r.name, did: r.did, code: r.code, detail: r.detail, at: r.at }));
    const m = me();
    return {
      seq, now: t,
      me: {
        did: m.did, relay: carrier.relay, online: live.online.has(carrier.relay), clock_offset: clock?.offset ?? null, clock_checked: clock?.checked ?? null,
        retention_days: carrier.retentionDays, error: live.error, pow_done_ms: live.powDone,
        pow: live.pow && { bits: live.pow.bits, elapsed_s: Math.round((Date.now() - live.pow.since) / 1000), expected_s: Math.ceil(2 ** live.pow.bits / 180000) },
      },
      groups: { mine: mineGroup, contacts: rest },
      pending: { invites: pendingInvites, paired, answers: c.answers, failed },
      events: recs.filter((r) => r.kind === 'event' && r.n > since).slice(-50),
    };
  }

  // ---- writes
  let chain = Promise.resolve() as Promise<unknown>;
  const serial = <T>(fn: () => Promise<T>): Promise<T> => { const p = chain.then(fn, fn); chain = p.catch(() => {}); return p; };
  const contactOf = (d: unknown): Contact => {
    if (typeof d !== 'string') refuse(400, 'body', 'contact: a DID');
    return carrier.contacts().contacts.find((x) => !x.revoked && x.did === d) ?? refuse(404, 'not_contact', `${String(d)} is not a contact`);
  };
  const cleanName = (v: unknown, what: string): string => {
    if (typeof v !== 'string' || v.trim() === '' || [...v.trim()].length > NAME_MAX || /[\u0000-\u001f\u007f-\u009f]/.test(v)) refuse(400, 'body', `${what}: 1 to ${NAME_MAX} characters, no controls`);
    return (v as string).trim();
  };
  const rosterOrNull = (): Map<string, number> | null => { try { return workersOf(path); } catch (e) { return refuse(409, 'keeper', (e as Error).message); } };
  const contactsOf = (file: string): number => {
    try { return Object.values(readJson<StoreFile>(lib.pathsFor(file).store, { contacts: {} }).contacts).filter((c) => !c.revoked).length; } catch { return 0; }
  };
  const agentOf = (name: unknown): Agent => {
    const a = agents().find((x) => x.name === name) ?? refuse(404, 'agent', `no agent ${JSON.stringify(name)} in ${agentsDir}`);
    if (a.error) refuse(409, 'agent', `${a.file}: ${a.error}`);
    return a;
  };
  const routes: Record<string, (b: Record<string, unknown>, q: URLSearchParams) => unknown> = {
    'GET /api/state': async (_, q) => { if (draining) await draining; return state(Number(q.get('since') ?? 0) || 0); },
    'GET /api/me': () => {
      const m = me(), recovery = id.head(m.store).recovery;
      return { did: m.did, original: m.original, chain: m.chain, identity_file: path, recovery: recovery === null ? 'none' : 'set', key: 'file', relay: carrier.relay, retention_days: carrier.retentionDays,
        erase: `SIGELO_IDENTITY=${path} sigelo-agent erase-request --recovery-key <your recovery.key>   (on the machine holding the recovery key)` };
    },
    'POST /api/invite': (b) => serial(async () => {
      const name = b['name'] === undefined || b['name'] === '' ? `contact-${randomBytes(2).toString('hex')}` : cleanName(b['name'], 'name');
      const r = await carrier.invite({ name, short: b['long'] !== true });
      const inv = { id: randomBytes(6).toString('hex'), name, code: r.code, exp: r.exp, ...(r.short !== undefined && { short: r.short, short_exp: r.short_exp! }) };
      invites.set(inv.id, inv);
      return { ...inv, relay: r.relay };
    }),
    'POST /api/invite/cancel': (b) => serial(async () => {
      const inv = invites.get(String(b['id'])) ?? refuse(404, 'invite', 'no such invite');
      await carrier.cancelInvite(inv.code);
      invites.delete(inv.id);
      return { cancelled: true };
    }),
    'POST /api/accept': (b) => serial(async () => {
      if (typeof b['code'] !== 'string' || b['code'].trim() === '') refuse(400, 'body', 'code: the short code (K7F3-Q9ZP) or the long one (sgl1…)');
      const text = b['code'] as string, code = short.codeKind(text) === 'short' ? text : text.replace(/\s+/g, '');
      const name = b['name'] === undefined || b['name'] === '' ? undefined : cleanName(b['name'], 'name');
      // friend or quiet, the human's choice; own is detected, never asked (store.mjs tiers).
      const tier = b['tier'];
      if (tier !== undefined && tier !== 'friend' && tier !== 'quiet') refuse(400, 'body', 'tier: friend or quiet');
      const r = await carrier.accept(code, { ...(name !== undefined && { name }), wait: 10, ...(tier !== undefined && { tier: tier as string }) });
      const now = r.contact ? carrier.contacts().contacts.find((x) => x.did === r.contact!.did) : undefined;
      return r.contact ? { status: r.status, contact: { ...r.contact, pair: now?.pair ?? null, tier: now?.tier ?? null } }
        : { ...r, exp: carrier.contacts().answers.find((x) => x.did === r.did)?.exp ?? null };
    }),
    'POST /api/words': (b) => serial(async () => {
      const c = contactOf(b['contact']);
      if (b['match'] === true) { data.checked[c.did] = c.pair ?? ''; saveData(); return { checked: true }; }
      if (b['match'] !== false) refuse(400, 'body', 'match: true or false');
      return forget(c);
    }),
    'POST /api/rename': (b) => serial(async () => {
      // A name another live contact holds is refused (409 name_taken): `send <name>` would refuse both.
      return carrier.rename(contactOf(b['contact']).did, cleanName(b['name'], 'name'));
    }),
    'POST /api/tier': (b) => serial(async () => {
      const c = contactOf(b['contact']), tier = b['tier'];
      if (tier !== 'own' && tier !== 'friend' && tier !== 'quiet') refuse(400, 'body', 'tier: own, friend or quiet');
      return carrier.setTier(c.did, tier as string);
    }),
    'POST /api/tag': (b) => serial(async () => {
      const c = contactOf(b['contact']), tags = b['tags'];
      if (!Array.isArray(tags) || tags.length > 8) refuse(400, 'body', 'tags: a list of at most 8');
      const clean = [...new Set((tags as unknown[]).map((x) => cleanName(x, 'tag').replace(/^#/, '')))];
      if (clean.some((x) => [...x].length > TAG_MAX)) refuse(400, 'body', `a tag has at most ${TAG_MAX} characters`);
      data.tags[c.did] = clean; saveData();
      return { tags: clean };
    }),
    'POST /api/forget': (b) => serial(async () => forget(contactOf(b['contact']))),
    'POST /api/send': (b) => serial(async () => {
      const c = contactOf(b['to']), text = b['text'];
      if (typeof text !== 'string' || text.trim() === '' || text.length > TEXT_MAX) refuse(400, 'body', `text: 1 to ${TEXT_MAX} characters`);
      let r: Awaited<ReturnType<Car['sendAll']>>[number];
      try { [r] = (await carrier.sendAll(c.did, [text], { label: '' })) as [typeof r]; } catch (e) {
        // The session failed: the message stays queued in the carrier and goes at a later connection.
        const f = e as Fail;
        if (!/queued/.test(f.message)) throw e;
        return record({ kind: 'out', did: c.did, id: null, text, status: 'queued', code: f.check, detail: f.message });
      }
      const out = record({ kind: 'out', did: c.did, id: r.id, text, status: r.status, code: r.code, detail: r.detail });
      return out;
    }),
    'GET /api/messages': (_, q) => {
      const d = contactOf(q.get('contact')).did, since = Number(q.get('since') ?? 0) || 0;
      const msgs = recs.filter((r) => (r.kind === 'in' || r.kind === 'out') && r.did === d && r.n > since).slice(-200);
      // Read: the page has shown them.
      if ((data.read[d] ?? 0) < seq) { data.read[d] = seq; saveData(); }
      return { seq, messages: msgs.map((r) => ({ n: r.n, dir: r.kind, at: r.at, text: textOf(r.text), label: r.label ?? '', status: r.status ?? null, code: r.code ?? null, detail: r.detail ?? null })) };
    },
    'POST /api/sync': () => serial(async () => { await carrier.sync(); return { synced: true }; }),
    'POST /api/history/clear': () => serial(async () => {
      writePrivate(historyFile, ''); recs.length = 0; outById.clear(); data.read = {}; saveData();
      return { cleared: true };
    }),
    'GET /api/agents': () => {
      const cs = carrier.contacts().contacts, workers = rosterOrNull();
      return agents().map((a) => {
        const worker = a.did !== undefined ? workers?.get(a.did) ?? null : null;
        return { name: a.name, did: a.did ?? null, error: a.error ?? null, mine: a.mine ?? null, worker, renew: worker !== null && a.mine ? a.mine.days_left < RENEW_DAYS : false,
          contacts: contactsOf(a.file), contact: a.did !== undefined && cs.some((c) => !c.revoked && c.chain.includes(a.did!)) };
      });
    },
    // Enrol (ENROL.md): worker i of the keeper root into the agent's file, so the 25 words restore it;
    // a worker already only has its operator attestation renewed. Nothing here attests a random key.
    'POST /api/agents/enrol': (b) => serial(async () => {
      const a = agentOf(b['agent']), m = me(), t = nowS(), workers = rosterOrNull();
      if (workers === null) refuse(400, 'keeper', `no keeper root at ${keeperPath(path)}: run sigelo-agent keeper --from-words once (your 25 words, read from the terminal)`);
      const holder = lockHolder(a.file);
      if (holder !== null) refuse(409, 'busy', `${a.file} is open in sigelo-agent ${holder.kind} (pid ${holder.pid}): stop it first`);
      const worker = workers!.get(a.did!);
      if (worker !== undefined) {
        // The body sigelo's attest() builds, signed through the key provider (sigelo-agent-keys.ts).
        const body: Attestation['body'] = { v: VERSION, typ: 'attestation', iss: m.did, sub: a.did!, iat: t, exp: t + OPERATOR_DAYS * DAY, ctx: OPERATOR_CTX, admission: 'invite', claims: { relay: carrier.relay }, admission_by: m.did };
        const att = { body, sig: signer(path, m.store).sign(body) };
        withLock(a.file, () => { const s = id.load(a.file); id.addIssuer(s, id.head(m.store)); id.addAttestation(s, att); id.save(a.file, s); });
        agentCache.delete(a.file);
        return { agent: a.name, worker, renewed: true, did: did(id.head(id.load(a.file))), exp: att.body.exp, days_left: OPERATOR_DAYS };
      }
      const r = await enrolInto(path, a.file, a.name, carrier.relay);
      agentCache.delete(a.file);
      return { agent: a.name, worker: r.worker, renewed: false, did: r.did, old: r.old, exp: r.exp, days_left: OPERATOR_DAYS, contacts: r.contacts,
        ...(r.contacts > 0 && { warning: `${r.contacts} contact(s) of ${a.name} know its old DID ${r.old}: they must pair again` }) };
    }),
    'POST /api/agents/pair': (b) => serial(async () => {
      const a = agentOf(b['agent']);
      const holder = uiHolder(a.file);
      if (holder !== null) refuse(409, 'busy', busy(a.file, holder, 'pairing here'));
      // Both sides in this process: my code, the agent's carrier answers it, mine replies.
      const inv = await carrier.invite({ name: a.name === 'default' ? 'agent' : a.name, short: false });
      const other = new lib.Carrier({ identity: () => { const s = id.load(a.file); return { sign: signer(a.file, s).sign, bundle: id.bundleOf(s) }; }, ...lib.pathsFor(a.file), ...opts }) as unknown as Car;
      let r;
      try { r = await other.accept(inv.code, { name: 'operator', wait: 30 }); } finally { await other.stop(); }
      if (!r.contact) return { status: r.status, detail: r.detail ?? null };
      const c = carrier.contacts().contacts.find((x) => x.current_did === r.contact!.did || x.did === r.contact!.did || x.did === a.did);
      if (c) { data.checked[c.did] = c.pair ?? ''; saveData(); }
      return { status: 'connected', contact: c ? { did: c.did, name: c.name } : null };
    }),
  };
  async function forget(c: Contact): Promise<unknown> {
    const r = await carrier.forget(c.did);
    delete data.tags[c.did]; delete data.checked[c.did]; saveData();
    return { forgotten: c.did, offline: r.offline ?? null };
  }

  // ---- HTTP
  const token = randomBytes(16).toString('hex'), tokenBytes = Buffer.from(token);
  let port = 0;
  const hosts = (): Set<string> => new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const secure = (res: ServerResponse): void => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Cache-Control', 'no-store'); res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  };
  const json = (res: ServerResponse, status: number, v: unknown): void => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(safeJson(JSON.stringify(v)));
  };
  const deny = (res: ServerResponse, why: string): void => json(res, 403, { error: { check: 'forbidden', message: why } });
  const body = (req: IncomingMessage): Promise<Record<string, unknown>> => new Promise((ok, no) => {
    const parts: Buffer[] = [];
    let n = 0;
    req.on('data', (d: Buffer) => { n += d.length; if (n > BODY_MAX) { no(Object.assign(new Error('body too large'), { check: 'body', status: 413 })); req.destroy(); } else parts.push(d); });
    req.on('end', () => {
      if (n === 0) return ok({});
      try { const v = JSON.parse(Buffer.concat(parts).toString('utf8')) as unknown; if (typeof v === 'object' && v !== null && !Array.isArray(v)) ok(v as Record<string, unknown>); else no(Object.assign(new Error('a JSON object'), { check: 'body', status: 400 })); } catch { no(Object.assign(new Error('not JSON'), { check: 'body', status: 400 })); }
    });
    req.on('error', no);
  });
  // One handler for both listeners: the route's answer as [status, JSON value].
  async function dispatch(method: string, url: URL, b: Record<string, unknown>): Promise<[number, unknown]> {
    const route = routes[`${method} ${url.pathname}`];
    if (!route) return [404, { error: { check: 'route', message: `no ${method} ${url.pathname}` } }];
    try { return [200, await route(b, url.searchParams)]; } catch (e) {
      const f = e as Fail;
      return [f.status ?? (f.check ? 409 : 500), { error: { check: f.check ?? 'internal', message: f.message, ...(f.long !== undefined && { long: f.long }) } }];
    }
  }
  const server = createServer((req, res) => {
    secure(res);
    void (async () => {
      const host = req.headers.host ?? '';
      if (!hosts().has(host)) return deny(res, 'host');
      const url = new URL(req.url ?? '/', `http://${host}`);
      if (!url.pathname.startsWith('/api/')) {
        const f = STATIC[url.pathname];
        if (req.method !== 'GET' || f === undefined) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('not found'); }
        res.writeHead(200, { 'Content-Type': `${f[1]}; charset=utf-8` });
        return res.end(readFileSync(join(HERE, f[0])));
      }
      const given = Buffer.from(String(req.headers['x-sigelo-token'] ?? ''));
      if (given.length !== tokenBytes.length || !timingSafeEqual(given, tokenBytes)) return deny(res, 'token');
      if (req.method !== 'GET') {
        if (req.method !== 'POST') return deny(res, 'method');
        if (req.headers.origin === undefined || !hosts().has(req.headers.origin.replace(/^http:\/\//, '')) || !req.headers.origin.startsWith('http://')) return deny(res, 'origin');
        if (!/^application\/json\b/.test(req.headers['content-type'] ?? '')) return deny(res, 'content-type');
      }
      if (!routes[`${req.method} ${url.pathname}`]) return json(res, 404, { error: { check: 'route', message: `no ${req.method} ${url.pathname}` } });
      let b: Record<string, unknown> = {};
      try { if (req.method === 'POST') b = await body(req); } catch (e) {
        const f = e as Fail;
        return json(res, f.status ?? 400, { error: { check: f.check ?? 'body', message: f.message } });
      }
      json(res, ...(await dispatch(req.method!, url, b)));
    })().catch(() => { try { res.destroy(); } catch {} });
  });

  // ---- the LAN listener (--remote): POST /r, sealed; everything else a status and no body.
  const bare = (res: ServerResponse, status: number): void => { res.writeHead(status, { 'Content-Length': '0' }); res.end(); };
  const lan = o.remote ? createServer((req, res) => {
    // One request per connection: no idle socket outlives a page that stopped.
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Connection', 'close');
    if (req.method !== 'POST' || req.url !== '/r') { req.resume(); return bare(res, 404); }
    void (async () => {
      const parts: Buffer[] = [];
      let n = 0;
      for await (const d of req as AsyncIterable<Buffer>) { n += d.length; if (n > R_BODY_MAX) return bare(res, 413); parts.push(d); }
      let raw: unknown;
      try { raw = JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { return bare(res, 400); }
      const r = openRequest(data.controls, raw);
      if (r === null) return bare(res, 403);
      // Kept before the call runs: the same request never runs twice, even across a restart.
      r.c.ctr = r.ctr; r.c.last_used = nowS(); saveData();
      let status: number, answer: unknown;
      let url: URL | null = null;
      try { url = new URL(r.msg.path, 'http://remote'); } catch {}
      const b = r.msg.body === undefined ? {} : r.msg.body;
      if (url === null || !url.pathname.startsWith('/api/') || url.origin !== 'http://remote') [status, answer] = [404, { error: { check: 'route', message: 'not a route' } }];
      else if (deviceRoute(url.pathname)) [status, answer] = [403, { error: { check: 'remote', message: 'device routes are never remote: moving keys needs a human at the computer' } }];
      else if (!SCOPES[r.c.scope].has(`${r.msg.method} ${url.pathname}`)) {
        [status, answer] = routes[`${r.msg.method} ${url.pathname}`] ? [403, { error: { check: 'scope', message: `${r.msg.method} ${url.pathname} is outside this control's scope (${r.c.scope})` } }]
          : [404, { error: { check: 'route', message: `no ${r.msg.method} ${url.pathname}` } }];
      } else if (typeof b !== 'object' || b === null || Array.isArray(b)) [status, answer] = [400, { error: { check: 'body', message: 'a JSON object' } }];
      else [status, answer] = await dispatch(r.msg.method, url, b as Record<string, unknown>);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(sealAnswer(r.c, r.ctr, safeJson(JSON.stringify({ status, body: answer }))));
    })().catch(() => { try { res.destroy(); } catch {} });
  }) : null;

  const listen = (srv: ReturnType<typeof createServer>, p: number, ip: string): Promise<number> => new Promise((ok, no) => {
    srv.once('error', (e: Error & { code?: string }) => no(e.code === 'EADDRINUSE' ? Object.assign(new Error(`port ${p} on ${ip} is taken: another program (or another page) has it`), { check: 'port_taken', status: 409 }) : e));
    srv.listen(p, ip, () => ok((srv.address() as { port: number }).port));
  });
  const stopAll = async (): Promise<void> => {
    clearInterval(clockTimer); clearInterval(drainTimer);
    for (const srv of [server, lan]) if (srv?.listening) { srv.closeAllConnections(); await new Promise<void>((ok) => srv.close(() => ok())); }
    try { await carrier.stop(); } finally { release(); }
  };
  let remote: Ui['remote'] = null;
  try {
    port = await listen(server, o.port ?? 0, '127.0.0.1');
    if (lan && o.remote && remoteIp !== null) {
      let rp: number;
      // The port is kept, so a control's text stays valid; taken now: a new one, and the texts must be shown again.
      try { rp = await listen(lan, data.remote?.port ?? 0, remoteIp); } catch (e) {
        if ((e as Fail).check !== 'port_taken' || data.remote === undefined) throw e;
        note(`remote: port ${data.remote.port} is taken; a new one: show each control's text again (ui --remote --name <name>)`);
        rp = await listen(lan, 0, remoteIp);
      }
      if (data.remote?.port !== rp) { data.remote = { port: rp }; saveData(); }
      const name = o.remote.name ?? null, c = name === null ? null : data.controls[name]!;
      remote = { ip: remoteIp, port: rp, name, line: c ? controlLine(remoteIp, rp, c) : null };
    }
  } catch (e) { await stopAll(); throw e; }
  return {
    url: `http://127.0.0.1:${port}/#t=${token}`, port, token, remote,
    close: stopAll,
  };
}

function openBrowser(url: string): void {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['rundll32', ['url.dll,FileProtocolHandler', url]] : ['xdg-open', [url]];
  try { const c = spawn(cmd as string, args as string[], { detached: true, stdio: 'ignore' }); c.on('error', () => {}); c.unref(); } catch {}
}

const USAGE = 'ui [--no-open] [--identity <file>] [--port <p>] [--remote [--listen <ip>] [--name <control>] [--scope read|chat|all]] | ui --controls | ui --revoke-control <name>';
/** `sigelo-agent ui [--no-open] [--port <p>] [--remote …]`. Runs until SIGINT/SIGTERM. `--controls`, `--revoke-control <name>`: print, exit. */
export async function main(rest: string[]): Promise<number> {
  let noOpen = false, flag: string | undefined, port: number | undefined, remote = false, listen: string | undefined, name: string | undefined, scope: string | undefined;
  let list = false, revoke: string | undefined;
  const value = (i: number): string | undefined => (rest[i + 1] !== undefined && !rest[i + 1]!.startsWith('--') ? rest[i + 1] : undefined);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!, v = value(i);
    if (a === '--no-open') noOpen = true;
    else if (a === '--identity' && v !== undefined && flag === undefined) { flag = v; i++; }
    else if (a === '--operator') continue;
    else if (a === '--port' && v !== undefined && /^\d{1,5}$/.test(v) && Number(v) >= 1 && Number(v) <= 65535 && port === undefined) { port = Number(v); i++; }
    else if (a === '--remote') remote = true;
    else if (a === '--listen' && v !== undefined && listen === undefined) { listen = v; i++; }
    else if (a === '--name' && v !== undefined && name === undefined) { name = v; i++; }
    else if (a === '--scope' && v !== undefined && scope === undefined) { scope = v; i++; }
    else if (a === '--controls') list = true;
    else if (a === '--revoke-control' && v !== undefined && revoke === undefined) { revoke = v; i++; }
    else { note(`ui: unexpected ${JSON.stringify(a)}: ${USAGE}${a.includes('recovery') ? '. Your identity comes from your 25 words: sigelo-agent keeper --from-words' : ''}`); return 2; }
  }
  if (!remote && (listen ?? name ?? scope) !== undefined) { note(`ui: --listen, --name and --scope go with --remote: ${USAGE}`); return 2; }
  if (scope !== undefined && !isScope(scope)) { note('ui: --scope read, chat or all'); return 2; }
  if ((list || revoke !== undefined) && (remote || port !== undefined || (list && revoke !== undefined))) { note(`ui: --controls and --revoke-control stand alone: ${USAGE}`); return 2; }
  let path: string;
  try { path = operatorFile('ui', flag); } catch (e) { note((e as Error).message); return 2; }
  if (!existsSync(path)) { note(`ui: no identity at ${path}: make it once from your 25 words (it is their root identity, so they restore it): sigelo-agent keeper --from-words`); return 2; }
  if (list) { console.log(safeJson(JSON.stringify(listControls(path), null, 2))); return 0; }
  if (revoke !== undefined) {
    try { if (!revokeControl(path, revoke)) { note(`ui: no control ${JSON.stringify(revoke)} (ui --controls lists them)`); return 1; } } catch (e) { note((e as Error).message); return 1; }
    note(`control ${revoke} revoked: its key is forgotten here; a device holding it controls nothing`);
    return 0;
  }
  let ui: Ui;
  try {
    ui = await startUi({ identity: path, ...(port !== undefined && { port }), ...(remote && { remote: { ...(listen !== undefined && { listen }), ...(name !== undefined && { name }), ...(scope !== undefined && { scope: scope as Scope }) } }) });
  } catch (e) { note((e as Error).message); return (e as Fail).status === 400 ? 2 : 1; }
  console.log(ui.url);
  note(`your page (experimental): ${ui.url} (this machine only; the link is its key: do not share it). Ctrl-C stops it.`);
  if (ui.remote) {
    if (ui.remote.line !== null) console.log(ui.remote.line);
    const names = listControls(path).map((c) => `${c.name} (${c.scope})`).join(', ');
    note(`remote: ${ui.remote.ip}:${ui.remote.port}, POST /r sealed; controls: ${names || 'none'}.${ui.remote.line !== null ? ` Scan or paste the SIGELO:UI: line on the device for ${ui.remote.name}: whoever holds it controls this page within its scope until revoked (ui --revoke-control ${ui.remote.name}).` : ''}`);
  }
  if (!noOpen) openBrowser(ui.url);
  await new Promise<void>((ok) => { process.once('SIGINT', () => ok()); process.once('SIGTERM', () => ok()); });
  await ui.close();
  return 0;
}
