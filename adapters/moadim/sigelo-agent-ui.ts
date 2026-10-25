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
 * `--app`: for a shell that shows the page itself (apps/gtk): no browser opened, and the page stops when
 * stdin ends, so a shell that dies takes its page (and the file's lock) with it.
 * Links (LINKS.md, contact/link.mjs): the page owns the session, so it runs link.mjs handle() as `watch`
 * does (at each `link` or `paired` event, each minute, after each link route): the operator's links
 * complete here, introductions to this identity wait for an answer (`/api/links*`). Never in the history.
 * Devices (DEVICES.md, sigelo-agent-device.ts devicePage): `/api/devices*` over this carrier, SAFE only; the
 * enrolment messages its inbox hands over are kept apart for the device rounds (after each drain), never in
 * the history. The page reads QR codes itself: contact/qr.mjs and qr-decode.mjs are served with two shims
 * (ui.html's import map, allowed by its hash in the CSP; shim-*.mjs).
 */
import { spawn } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { appendFileSync, chmodSync, closeSync, existsSync, openSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { isIPv4 } from 'node:net';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { did, verify, VERSION, type Attestation, type Genesis } from 'sigelo';
import * as id from './sigelo-agent.ts';
import { signer } from './sigelo-agent-keys.ts';
import { withLock } from './sigelo-agent-monero.ts';
import { enrolInto, keeperPath, readKeeper, workersOf } from './sigelo-agent-enrol.ts';
import { deviceRound, hasTty, seatGate, seatInfo, terminalQr, ttyLine, ttyWrite, type DevMsg } from './sigelo-agent-device.ts';
import { CONTROL_NAME, controlLine, defaultAddress, isRelay, isScope, lanControls, loadAead, newControl, openRequest, R_BODY_MAX, remoteCall, sealAnswer, type AnyControl, type Control, type Scope } from './sigelo-agent-remote.ts';
import { relayControls, type RelayCarrier, type Relays } from './sigelo-agent-control.ts';
import { devicePage, type DevicePage } from './sigelo-agent-device.ts';
import { agentsDirFor, busyText, contactDir, contactLib, contactModule, humanPath, insideAgents, operatorFile, lockHolder, lockPath, safeJson, safeText, unreadable, type LinkLib } from './sigelo-agent-contact.ts';

export const OPERATOR_CTX = 'sigelo-relay/operator';
const DAY = 86400, OPERATOR_DAYS = 90, RENEW_DAYS = 14, BODY_MAX = 256 * 1024;
const STATIC: Record<string, [string, string]> = {
  '/': ['ui.html', 'text/html'], '/ui.html': ['ui.html', 'text/html'], '/ui.js': ['ui.js', 'text/javascript'], '/ui.css': ['ui.css', 'text/css'],
  '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json'], '/sw.js': ['sw.js', 'text/javascript'], '/icon.svg': ['icon.svg', 'image/svg+xml'],
  '/icon-maskable.svg': ['icon-maskable.svg', 'image/svg+xml'],
  '/shim-zlib.mjs': ['shim-zlib.mjs', 'text/javascript'], '/shim-kdf.mjs': ['shim-kdf.mjs', 'text/javascript'],
  // QR reading and drawing in the page (design/devices.md §6.4): sigelo-contact's own files, as they are.
  '/qr.mjs': ['contact:qr.mjs', 'text/javascript'], '/qr-decode.mjs': ['contact:qr-decode.mjs', 'text/javascript'],
};
const HERE = dirname(fileURLToPath(import.meta.url));
const staticFile = (f: string): string => (f.startsWith('contact:') ? join(contactDir(), f.slice(8)) : join(HERE, f));
// The page's one inline script, its import map (node:zlib and kdf.mjs → the shims): allowed by its hash.
const IMPORT_MAP = ((): string => {
  const m = /<script type="importmap">([\s\S]*?)<\/script>/.exec(readFileSync(join(HERE, 'ui.html'), 'utf8'));
  return m ? ` 'sha256-${createHash('sha256').update(m[1]!).digest('base64')}'` : '';
})();
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
  link?: { id: string; purpose: string; linked_by: string; expires: number | null } | null;
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
interface UiData { tags: Record<string, string[]>; checked: Record<string, string>; read: Record<string, number>; controls: Record<string, AnyControl>; remote?: { port: number } }
interface Agent { name: string; file: string; did?: string; chain?: string[]; mine?: { exp: number; days_left: number } | null; error?: string; bundle?: object }
type Fail = Error & { check?: string; long?: string; status?: number };
type Route = (b: Record<string, unknown>, q: URLSearchParams) => unknown;
/** contact/page.mjs: the routes over the carrier, shared with the self-contained app. */
interface PageLib {
  makePage(o: {
    makeCarrier: (onEvent: (e: Ev) => void, kept: { relay?: string }) => unknown; link: LinkLib; relayFixed: string | null; linksFile: string; codeKind: (t: string) => string; unlogged: RegExp;
    store: { readHistory(): string | null; append(line: string): void; clearHistory(): void; readData(): string | null; writeData(text: string): void };
    hooks: { me(): { did: string; original: string; chain: string[] }; meInfo(): { identity_file: string; recovery: string; key: string; erase: string; restored?: unknown };
      agents(): Agent[]; seat(): unknown; deviceRound(): Promise<{ gave?: string }>; defer(f: () => void): void; hidden(x: { did?: unknown; name?: unknown }): boolean };
  }): {
    carrier: unknown; routes: Record<string, Route>; dispatch(method: string, url: URL, b: Record<string, unknown>): Promise<[number, unknown]>;
    start(): Promise<void>; halt(): Promise<void>; serial<T>(f: () => Promise<T>): Promise<T>; data: unknown; saveData(): void;
    live: { online: Set<string>; seatGone: string | null }; seen(did: string): number | null; setDevices(d: DevicePage): void; onChange(f: () => void): () => void;
  };
}
const refuse = (status: number, check: string, message: string): never => { throw Object.assign(new Error(message), { check, status }); };

export interface UiOptions {
  identity: string; agents?: string; carrier?: Record<string, unknown>; port?: number;
  /** A LAN listener for remote controls: on `listen` (else the default route's address); `name` made if new, in `scope` (chat).
   *  relay: no listener; `name` is a relay control (sigelo-agent-control.ts): its SIGELO:CTL: code when it is not paired yet. */
  remote?: { listen?: string; name?: string; scope?: Scope; relay?: boolean };
}
/** The relay controls of a running page: the code made at start, pairings as they come, the words confirmed, revoke. */
export interface UiRelay {
  name: string | null; line: string | null; exp: number | null;
  /** The next pairing of a control (its name, its four words). */
  paired(): Promise<{ name: string; words: string | null }>;
  /** Another control's code (null: paired already). */
  issue(name: string, scope: Scope): Promise<{ line: string; exp: number } | null>;
  confirm(name: string, match: boolean): Promise<boolean>; revoke(name: string): Promise<boolean>;
}
export interface Ui { url: string; port: number; token: string; remote: { ip: string; port: number; name: string | null; line: string | null } | null; relay: UiRelay; close(): Promise<void> }

const dataPath = (identity: string): string => `${resolve(identity).replace(/\.json$/, '')}.ui.json`;
/** `ui --controls`: name, scope, created, last used; never the key. */
export function listControls(identity: string): { name: string; scope: Scope; created: number; last_used: number | null; relay?: { paired: boolean; confirmed: boolean } }[] {
  const d = readJson<Partial<UiData>>(dataPath(identity), {});
  return Object.entries(d.controls ?? {}).map(([name, c]) => ({ name, scope: c.scope, created: c.created, last_used: c.last_used, ...(isRelay(c) && { relay: { paired: c.did !== null, confirmed: c.confirmed } }) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
/**
 * `ui --revoke-control <name>`: a LAN control's key forgotten; a relay control's contact forgotten (its
 * identity can reach this computer no more). The page owns ui.json: refused while one runs on the file.
 */
export async function revokeControl(identity: string, name: string, carrierOptions: Record<string, unknown> = {}): Promise<boolean> {
  const h = uiHolder(identity);
  if (h !== null) refuse(409, 'busy', busy(identity, h, 'revoking a control here (stop the page: its remote listener stops with it, then revoke)'));
  const f = dataPath(identity), d = readJson<Partial<UiData>>(f, {});
  const c = d.controls?.[name];
  if (!c) return false;
  if (isRelay(c) && c.did !== null) {
    const { lib } = await contactLib(), path = resolve(identity);
    const car = new lib.Carrier({ identity: () => { const s = id.load(path); return { sign: signer(path, s).sign, bundle: id.bundleOf(s) }; }, ...lib.pathsFor(path), ...lib.optionsFromEnv(), ...carrierOptions }) as unknown as Car;
    try { await car.forget(c.did); } catch (e) { if ((e as Fail).check !== 'not_contact') throw e; } finally { await car.stop(); }
  }
  delete d.controls![name];
  writePrivate(f, JSON.stringify(d));
  return true;
}

/**
 * Me's "restored from seed" line (UI-API.md GET /api/me `restored`): an identity from the 25 words
 * (`derived`) with its keeper file and the day that file was made: { on, keeper, seat: here | elsewhere | null }.
 */
function restoredOf(path: string): { restored?: { on: string; keeper: number; seat: string | null } } {
  try {
    if (!(id.load(path) as { derived?: unknown }).derived || !existsSync(keeperPath(path))) return {};
    const k = readKeeper(path) as { keeper: number; created?: unknown }, st = seatInfo(path);
    return typeof k.created === 'string' ? { restored: { on: k.created, keeper: k.keeper, seat: st ? (st.here ? 'here' : 'elsewhere') : null } } : {};
  } catch { return {}; }
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
    if (r.relay && r.listen !== undefined) refuse(400, 'remote', '--relay: no LAN listener, so no --listen');
    if (r.listen !== undefined && (!isIPv4(r.listen) || r.listen === '0.0.0.0')) refuse(400, 'remote', `--listen: one IPv4 address of this machine, not ${JSON.stringify(r.listen)}`);
    if (!r.relay) {
      remoteIp = r.listen ?? await defaultAddress() ?? refuse(400, 'remote', 'no LAN address found: give one with --listen <ip>');
      await loadAead();
    }
  }
  // The operator's seat (DEVICES.md): this machine's device inbox first; elsewhere the page does not start.
  try { await seatGate(path, 'ui'); } catch (e) { refuse(409, (e as Fail).check ?? 'seat_elsewhere', (e as Error).message); }
  const release = takeLock(path);
  const { lib, short, link: L } = await contactLib();
  // The routes over the carrier, shared with the self-contained app (contact/page.mjs, apps/web/router.mjs).
  const P = await contactModule<PageLib>('page');
  const linksFile = L.linksPath(path);
  const UNLOGGED = (lib as unknown as { UNLOGGED: RegExp }).UNLOGGED;
  let devices: DevicePage | null = null, relay: Relays | null = null, handling = Promise.resolve();
  const base = path.replace(/\.json$/, ''), historyFile = `${base}.history.jsonl`, dataFile = `${base}.ui.json`;
  // The relay new codes name: SIGELO_RELAY (or the caller's carrier.relay) wins over the page's setting (contact/page.mjs).
  const paths = lib.pathsFor(path), opts = { ...lib.optionsFromEnv(), ...o.carrier } as { endpoints?: object; relay?: string };
  const me = (): { store: id.Store; did: string; original: string; chain: string[]; geneses: Record<string, Genesis> } => {
    const store = loadMe(), chain = id.chainOf(store), gs = [store.genesis, ...store.rotations.map((r) => r.next_genesis)];
    return { store, did: did(id.head(store)), original: chain[0]!, chain, geneses: Object.fromEntries(gs.map((g) => [did(g), g])) };
  };
  if (existsSync(historyFile)) chmodSync(historyFile, 0o600);
  // History (`.history.jsonl`, appended, 0600) and the page's data (`.ui.json`, written whole): this host's files.
  const page = P.makePage({
    makeCarrier: (onEvent, kept) => new lib.Carrier({
      identity: () => { const s = loadMe(); return { sign: signer(path, s).sign, bundle: id.bundleOf(s) }; },
      ...paths, ...kept, ...opts, keep: true, onEvent,
    }),
    relayFixed: typeof opts.relay === 'string' ? opts.relay : null,
    link: L, linksFile, codeKind: (t) => short.codeKind(t), unlogged: UNLOGGED,
    store: {
      readHistory: () => (existsSync(historyFile) ? readFileSync(historyFile, 'utf8') : null),
      append: (line) => appendFileSync(historyFile, line, { mode: 0o600 }),
      clearHistory: () => writePrivate(historyFile, ''),
      readData: () => { try { return readFileSync(dataFile, 'utf8'); } catch { return null; } },
      writeData: (text) => writePrivate(dataFile, text),
    },
    hooks: {
      me: () => me(),
      meInfo: () => ({ identity_file: path, recovery: id.head(loadMe()).recovery === null ? 'none' : 'set', key: 'file',
        erase: `SIGELO_IDENTITY=${path} sigelo-agent erase-request --recovery-key <your recovery.key>   (on the machine holding the recovery key)`,
        ...restoredOf(path) }),
      agents: () => agents(),
      // The seat (DEVICES.md); device messages after each drain: wiped answers, a standby asking for the seat.
      seat: () => seatInfo(path),
      // The relay controls' requests are split from the device messages first (sigelo-agent-control.ts).
      deviceRound: async () => {
        const msgs = (page.carrier as { takeDevices(): DevMsg[] }).takeDevices();
        const [mine, rest] = relay ? relay.split(msgs) as [DevMsg[], DevMsg[]] : [[], msgs];
        const r = await deviceRound(page.carrier, path, undefined, (l) => note(l), rest);
        if (relay) {
          for (const p of relay.look()) paired(p);
          if (r.gave !== undefined) await relay.refuseAll(mine, r.gave);
          else if (mine.length) { const rl = relay; handling = handling.then(() => rl.handle(mine)).catch((e: Error) => note(`remote: ${e.message}`)); }
          relay.changed();
        }
        return r;
      },
      defer: (f) => { setImmediate(f); },
      hidden: (x) => relay?.hidden(x) ?? false,
    },
  });
  const { routes, dispatch, serial } = page, data = page.data as UiData, saveData = page.saveData;
  const carrier = page.carrier as unknown as Car;
  // Relay controls: always answered while the page runs (a paired control is no flag of this run).
  const inviteLib = await contactModule<{ parseInvite(t: string, now: number): { nonce: string } }>('invite');
  const waiters: ((p: { name: string; words: string | null }) => void)[] = [], early: { name: string; words: string | null }[] = [];
  const paired = (p: { name: string; words: string | null }): void => { const w = waiters.shift(); if (w) w(p); else early.push(p); };
  relay = await relayControls({
    carrier: page.carrier as RelayCarrier, controls: data.controls, save: () => saveData(), routes, dispatch, serial,
    seatElsewhere: () => { if (page.live.seatGone !== null) return page.live.seatGone; const st = seatInfo(path); return st && !st.here ? st.holder : null; },
    lib: lib as unknown as { DEVICE_LABEL: string; DEVICE_SEND: symbol; DEFAULT_RELAY: string }, nonceOf: (code) => inviteLib.parseInvite(code, nowS()).nonce, note,
  });
  page.onChange(() => relay?.changed());
  if (o.remote && !o.remote.relay) {
    // A new control by name; an existing one keeps its key and scope (revoke it to change them).
    const name = o.remote.name ?? (Object.keys(data.controls).length === 0 ? 'phone' : undefined), had = name === undefined ? undefined : data.controls[name];
    if (isRelay(had)) { release(); refuse(409, 'remote', `control ${name} is a relay control: pick another --name for the LAN, or ui --remote --relay --name ${name}`); }
    if (had && o.remote.scope !== undefined && had.scope !== o.remote.scope) { release(); refuse(409, 'remote', `control ${name} has scope ${had.scope}: revoke it (ui --revoke-control ${name}) to make it again with ${o.remote.scope}`); }
    if (name !== undefined && !had) { data.controls[name] = newControl(o.remote.scope ?? 'chat', nowS()); saveData(); }
    o = { ...o, remote: { ...o.remote, ...(name !== undefined && { name }) } };
  }
  // Devices (sigelo-agent-device.ts): before the first inbox, so its enrolment messages are kept apart.
  devices = await devicePage({ op: path, agentsDir, carrier, online: () => page.live.online.has(carrier.relay), seen: page.seen });
  page.setDevices(devices);
  await page.start();
  let relayLine: { name: string; line: string | null; exp: number | null } | null = null;
  if (o.remote?.relay) {
    const name = o.remote.name ?? 'phone';
    try { const r = await relay.issue(name, o.remote.scope ?? 'chat'); relayLine = { name, line: r?.line ?? null, exp: r?.exp ?? null }; } catch (e) {
      await page.halt(); try { await carrier.stop(); } finally { release(); }
      throw e;
    }
  }

  // ---- the agents' directory: this host's own routes
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
  const rosterOrNull = (): Map<string, number> | null => { try { return workersOf(path); } catch (e) { return refuse(409, 'keeper', (e as Error).message); } };
  const contactsOf = (file: string): number => {
    try { return Object.values(readJson<StoreFile>(lib.pathsFor(file).store, { contacts: {} }).contacts).filter((c) => !c.revoked).length; } catch { return 0; }
  };
  const agentOf = (name: unknown): Agent => {
    const a = agents().find((x) => x.name === name) ?? refuse(404, 'agent', `no agent ${JSON.stringify(name)} in ${agentsDir}`);
    if (a.error) refuse(409, 'agent', `${a.file}: ${a.error}`);
    return a;
  };
  Object.assign(routes, {
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
    'POST /api/agents/enrol': (b: Record<string, unknown>) => serial(async () => {
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
    'POST /api/agents/pair': (b: Record<string, unknown>) => serial(async () => {
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
  });
  // Devices: the writes through this carrier one at a time; a scan runs its own (another identity file).
  for (const [k, f] of Object.entries(devices.routes)) routes[k] = k.startsWith('POST ') && k !== 'POST /api/devices/scan' ? (b) => serial(async () => f(b)) : (b) => f(b);

  // ---- HTTP: the page's listener (pageServer) over this page's routes
  let port = 0;
  const { server, token } = pageServer({ port: () => port, has: (k) => routes[k] !== undefined, dispatch, onPost: () => relay?.changed() });

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
      const r = openRequest(lanControls(data.controls), raw);
      if (r === null) return bare(res, 403);
      // Kept before the call runs: the same request never runs twice, even across a restart.
      r.c.ctr = r.ctr; r.c.last_used = nowS(); saveData();
      const [status, answer] = await remoteCall(r.c.scope, r.msg, routes, dispatch);
      relay?.changed();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(sealAnswer(r.c, r.ctr, safeJson(JSON.stringify({ status, body: answer }))));
    })().catch(() => { try { res.destroy(); } catch {} });
  }) : null;

  const listen = (srv: ReturnType<typeof createServer>, p: number, ip: string): Promise<number> => new Promise((ok, no) => {
    srv.once('error', (e: Error & { code?: string }) => no(e.code === 'EADDRINUSE' ? Object.assign(new Error(`port ${p} on ${ip} is taken: another program (or another page) has it`), { check: 'port_taken', status: 409 }) : e));
    srv.listen(p, ip, () => ok((srv.address() as { port: number }).port));
  });
  const stopAll = async (): Promise<void> => {
    relay?.stop();
    await page.halt();
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
      const name = o.remote.name ?? null, c = name === null ? null : data.controls[name]! as Control;
      remote = { ip: remoteIp, port: rp, name, line: c ? controlLine(remoteIp, rp, c) : null };
    }
  } catch (e) { await stopAll(); throw e; }
  const rl = relay;
  return {
    url: `http://127.0.0.1:${port}/#t=${token}`, port, token, remote,
    relay: {
      name: relayLine?.name ?? null, line: relayLine?.line ?? null, exp: relayLine?.exp ?? null,
      paired: () => (early.length ? Promise.resolve(early.shift()!) : new Promise((ok) => { waiters.push(ok); })),
      confirm: async (name, match) => { const r = await rl.confirm(name, match); rl.changed(); return r; },
      revoke: (name) => rl.revoke(name),
      issue: (name, scope) => { if (!CONTROL_NAME.test(name)) refuse(400, 'remote', 'control name: 1 to 20 of a-z 0-9 _ -'); return rl.issue(name, scope); },
    },
    close: stopAll,
  };
}

/**
 * The page's listener on 127.0.0.1 (`ui`, and `control ui` for a relay control, sigelo-agent-control.ts):
 * the static files, `/api/*` with the token in X-Sigelo-Token, Host checked, Origin and JSON on writes,
 * no cookies, the CSP. has(METHOD path): whether the route exists; dispatch: its answer.
 */
export function pageServer(o: { port(): number; has(key: string): boolean; dispatch(method: string, url: URL, b: Record<string, unknown>): Promise<[number, unknown]>; onPost?(): void }): { server: ReturnType<typeof createServer>; token: string } {
  const token = randomBytes(16).toString('hex'), tokenBytes = Buffer.from(token);
  const hosts = (): Set<string> => new Set([`127.0.0.1:${o.port()}`, `localhost:${o.port()}`]);
  const secure = (res: ServerResponse): void => {
    res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self'${IMPORT_MAP}; media-src 'self' mediastream: blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`);
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
  // One handler for both listeners (contact/page.mjs dispatch): the route's answer as [status, JSON value].
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
        return res.end(readFileSync(staticFile(f[0])));
      }
      const given = Buffer.from(String(req.headers['x-sigelo-token'] ?? ''));
      if (given.length !== tokenBytes.length || !timingSafeEqual(given, tokenBytes)) return deny(res, 'token');
      if (req.method !== 'GET') {
        if (req.method !== 'POST') return deny(res, 'method');
        if (req.headers.origin === undefined || !hosts().has(req.headers.origin.replace(/^http:\/\//, '')) || !req.headers.origin.startsWith('http://')) return deny(res, 'origin');
        if (!/^application\/json\b/.test(req.headers['content-type'] ?? '')) return deny(res, 'content-type');
      }
      if (!o.has(`${req.method} ${url.pathname}`)) return json(res, 404, { error: { check: 'route', message: `no ${req.method} ${url.pathname}` } });
      let b: Record<string, unknown> = {};
      try { if (req.method === 'POST') b = await body(req); } catch (e) {
        const f = e as Fail;
        return json(res, f.status ?? 400, { error: { check: f.check ?? 'body', message: f.message } });
      }
      json(res, ...(await o.dispatch(req.method!, url, b)));
      if (req.method === 'POST') o.onPost?.();
    })().catch(() => { try { res.destroy(); } catch {} });
  });
  return { server, token };
}

function openBrowser(url: string): void {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['rundll32', ['url.dll,FileProtocolHandler', url]] : ['xdg-open', [url]];
  try { const c = spawn(cmd as string, args as string[], { detached: true, stdio: 'ignore' }); c.on('error', () => {}); c.unref(); } catch {}
}

const USAGE = 'ui [--no-open | --app] [--identity <file>] [--port <p>] [--remote [--relay | --listen <ip>] [--name <control>] [--scope read|chat|all]] | ui --controls | ui --revoke-control <name>';
/** `sigelo-agent ui [--no-open | --app] [--port <p>] [--remote …]`. Runs until SIGINT/SIGTERM (`--app`: or stdin's end). `--controls`, `--revoke-control <name>`: print, exit. */
export async function main(rest: string[]): Promise<number> {
  let noOpen = false, app = false, flag: string | undefined, port: number | undefined, remote = false, listen: string | undefined, name: string | undefined, scope: string | undefined;
  let list = false, revoke: string | undefined, viaRelay = false;
  const value = (i: number): string | undefined => (rest[i + 1] !== undefined && !rest[i + 1]!.startsWith('--') ? rest[i + 1] : undefined);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!, v = value(i);
    if (a === '--no-open') noOpen = true;
    else if (a === '--app') app = true;
    else if (a === '--identity' && v !== undefined && flag === undefined) { flag = v; i++; }
    else if (a === '--operator') continue;
    else if (a === '--port' && v !== undefined && /^\d{1,5}$/.test(v) && Number(v) >= 1 && Number(v) <= 65535 && port === undefined) { port = Number(v); i++; }
    else if (a === '--remote') remote = true;
    else if (a === '--relay') viaRelay = true;
    else if (a === '--listen' && v !== undefined && listen === undefined) { listen = v; i++; }
    else if (a === '--name' && v !== undefined && name === undefined) { name = v; i++; }
    else if (a === '--scope' && v !== undefined && scope === undefined) { scope = v; i++; }
    else if (a === '--controls') list = true;
    else if (a === '--revoke-control' && v !== undefined && revoke === undefined) { revoke = v; i++; }
    else { note(`ui: unexpected ${JSON.stringify(a)}: ${USAGE}${a.includes('recovery') ? '. Your identity comes from your 25 words: sigelo-agent keeper --from-words' : ''}`); return 2; }
  }
  if (viaRelay && (!remote || listen !== undefined)) { note(`ui: --relay goes with --remote, without --listen: ${USAGE}`); return 2; }
  if (!remote && (listen ?? name ?? scope) !== undefined) { note(`ui: --listen, --name and --scope go with --remote: ${USAGE}`); return 2; }
  if (scope !== undefined && !isScope(scope)) { note('ui: --scope read, chat or all'); return 2; }
  if ((list || revoke !== undefined) && (app || remote || port !== undefined || (list && revoke !== undefined))) { note(`ui: --controls and --revoke-control stand alone: ${USAGE}`); return 2; }
  let path: string;
  try { path = operatorFile('ui', flag); } catch (e) { note((e as Error).message); return 2; }
  if (!existsSync(path)) { note(`ui: no identity at ${path}: make it once from your 25 words (it is their root identity, so they restore it): sigelo-agent keeper --from-words`); return 2; }
  if (list) { console.log(safeJson(JSON.stringify(listControls(path), null, 2))); return 0; }
  if (revoke !== undefined) {
    try { if (!await revokeControl(path, revoke)) { note(`ui: no control ${JSON.stringify(revoke)} (ui --controls lists them)`); return 1; } } catch (e) { note((e as Error).message); return 1; }
    note(`control ${revoke} revoked: its key (or, over the relay, its contact) is forgotten here; a device holding it controls nothing`);
    return 0;
  }
  let ui: Ui;
  try {
    ui = await startUi({ identity: path, ...(port !== undefined && { port }), ...(remote && { remote: { ...(listen !== undefined && { listen }), ...(name !== undefined && { name }), ...(scope !== undefined && { scope: scope as Scope }), ...(viaRelay && { relay: true }) } }) });
  } catch (e) { note((e as Error).message); return (e as Fail).status === 400 ? 2 : 1; }
  console.log(ui.url);
  note(`your page (experimental): ${ui.url} (this machine only; the link is its key: do not share it). Ctrl-C stops it.`);
  if (ui.remote) {
    if (ui.remote.line !== null) console.log(ui.remote.line);
    const names = listControls(path).map((c) => `${c.name} (${c.scope})`).join(', ');
    note(`remote: ${ui.remote.ip}:${ui.remote.port}, POST /r sealed; controls: ${names || 'none'}.${ui.remote.line !== null ? ` Scan or paste the SIGELO:UI: line on the device for ${ui.remote.name}: whoever holds it controls this page within its scope until revoked (ui --revoke-control ${ui.remote.name}).` : ''}`);
  }
  if (viaRelay) void relayTerminal(ui, path);
  if (!noOpen && !app) openBrowser(ui.url);
  await new Promise<void>((ok) => {
    process.once('SIGINT', () => ok()); process.once('SIGTERM', () => ok());
    if (app) { process.stdin.once('end', () => ok()).once('error', () => ok()).resume(); }
  });
  await ui.close();
  return 0;
}

/** `ui --remote --relay`: the control's code (stdout, and a QR on the terminal), then each pairing's four words, confirmed here. */
async function relayTerminal(ui: Ui, path: string): Promise<void> {
  const r = ui.relay, tty = hasTty();
  if (r.line !== null) {
    console.log(r.line);
    if (tty) { try { await ttyWrite((await terminalQr(r.line)).join('\n') + '\n'); } catch {} }
    note(`remote over the relay: scan or type the SIGELO:CTL: code in the app for ${r.name} within 10 minutes; then compare the four words here. The app holds a key of its own, no account key; ui --revoke-control ${r.name} forgets it.`);
  } else if (r.name !== null) note(`remote over the relay: ${r.name} is paired already (ui --controls); to pair another app, --name <another>`);
  // Paired before, its words never confirmed (no terminal then): asked now.
  const had = r.name === null ? undefined : readJson<Partial<UiData>>(dataPath(path), {}).controls?.[r.name];
  let first: { name: string; words: string | null } | null = r.line === null && isRelay(had) && had.did !== null && !had.confirmed ? { name: r.name!, words: had.words } : null;
  for (;;) {
    const p = first ?? await r.paired();
    first = null;
    note(`${p.name} paired over the relay; its four words: ${p.words ?? '(none)'}`);
    if (!tty) { note(`no terminal to confirm them: ${p.name} answers nothing until they are confirmed (run ui --remote --relay --name ${p.name} in a terminal)`); continue; }
    const yes = /^y(es)?$/i.test((await ttyLine(`Does the app show the same four words (${p.words})? [y/N] `)).trim());
    await r.confirm(p.name, yes);
    note(yes ? `${p.name} confirmed: it controls this page (its scope) while the page runs` : `${p.name} refused and forgotten: someone else may have used the code`);
  }
}
