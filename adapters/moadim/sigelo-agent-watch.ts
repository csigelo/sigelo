// SPDX-License-Identifier: MIT
/**
 * `sigelo-agent watch` (WATCH.md): one carrier for an identity file, started and kept connected (the
 * carrier reconnects with backoff), until SIGINT or SIGTERM. Whatever arrives is handed on by the
 * sender's tier (contact/store.mjs "Tiers"):
 *   own     → --on-message CMD, the message (as inbox gives it) as JSON on stdin; taken once CMD
 *             exits 0, else left for the next inbox
 *   friend  → --on-notice CMD, {from, name, tier, count} on stdin: no content; the message stays for
 *             the next inbox (count: how many of that contact's wait there)
 *   quiet   → nothing; it stays for the next inbox
 * and pairings (paired, here the inviter's side completing by itself; pairing_failed) → --on-pairing
 * CMD with the event as JSON. Env for each: SIGELO_TYPE, SIGELO_FROM (the contact's DID), SIGELO_NAME,
 * SIGELO_TIER, SIGELO_PATH (a file's), SIGELO_IDENTITY, and for a message SIGELO_MSG_ID (its id, also
 * `id` in the JSON: contact/carrier.mjs messageId; a group message's "<gid>.<mid>"). Commands run one at
 * a time through the shell, at most --hook-timeout seconds each (SIGELO_HOOK_TIMEOUT; default HOOK_MS;
 * 0: no limit). Without a hook, one line per event on stdout (--quiet: none).
 * The killed-hook rule: a hook that fails or is stopped leaves the message unread; it is offered again
 * at the next round (SYNC_MS) and the next start: a hook dedupes on SIGELO_MSG_ID.
 * Accept now, reply later: --spool DIR instead of --on-message writes each own message to
 * DIR/<id>.json (0600, whole or not at all) and takes it, no process run; the agent answers when it
 * is done with `sigelo-agent reply --to <id>` (sigelo-agent-contact.ts).
 *
 * The lock is `ui`'s (`<identity>.ui.pid`, "<pid> watch"): a page and a watcher never run on one file.
 * The watcher alone logs in with the identity (sigelo-agent-contact.ts lockPath): beside it the CLI
 * and MCP inbox read the state without a session (what the watcher received), send and send-file
 * queue in the state and touch `<identity>.ui.kick`, which makes it sync at once (polled every
 * KICK_MS); every other session verb refuses. Every SYNC_MS a round picks up the rest.
 * Links (LINKS.md, contact/link.mjs): link messages never reach a hook or a line; the watcher handles
 * them by code (handle) at each `link` or `paired` event, each round and each kick (links accept),
 * and says what it did. An introduction from a contact that is not quiet here → --on-notice CMD with
 * {type: "link", id, from, name, peer, peer_name, purpose, note} (purpose and note are data).
 * Groups (GROUPS.md): group messages are checked by code at start, at each `group` event and each round
 * (the creator carries copies on, rosters are filed, notices said), then handed on by the sender's tier
 * as messages are: own → --on-message (the item as inbox gives it, SIGELO_TYPE group, SIGELO_GROUP its
 * gid; taken once CMD exits 0), friend → --on-notice {type: "group", group, from, name, tier, count}.
 * Transfers (TRANSFER.md, contact/transfer-node.mjs): the watcher holds the session, so its engine makes
 * and answers the offers and moves the bytes, at each `transfer` event, each round and each kick (a CLI
 * transfer verb beside it). A file offered → a line, or --on-notice CMD with {type: "transfer", id, from,
 * name, file, size}; nothing is written before the operator's `transfer accept`.
 * Devices (DEVICES.md): device messages are handled by code at each `device` event and each round; on
 * the operator's file the watcher starts only at the seat, and stops once it gave the seat away.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, renameSync, rmSync, unwatchFile, watchFile, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as id from './sigelo-agent.ts';
import { signer } from './sigelo-agent-keys.ts';
import { actingFile, contactLib, contactModule, debug, duration, introText, kickPath, linkNotes, noIdentity, safeJson, safeText, unreadable } from './sigelo-agent-contact.ts';
import type { GroupItem, GroupLib } from './sigelo-agent-group.ts';
import { takeLock } from './sigelo-agent-ui.ts';
import { deviceRound, seatGate } from './sigelo-agent-device.ts';

export const HOOK_MS = 120_000;
const SYNC_MS = 60_000, KICK_MS = 1000, NOTICE_MS = 300, TEXT_MAX = 200;
// A lost connection (the network, a relay restart, another copy of the identity logging in elsewhere):
// back in 7.5 to 15 s.
export const WATCH_BACKOFF: [number, number] = [15_000, 120_000];
const note = (s: string): void => console.error(`sigelo-agent: ${safeText(s)}`);

type Item = { type?: string; id?: string; from: string; name?: string; contact?: string; content?: unknown; label?: string; iat?: number; received?: number; path?: string; size?: number; tier?: string };
type Ev = Record<string, unknown> & { type?: string };
interface Car {
  relay: string;
  start(): Promise<void>; stop(): Promise<void>; sync(o?: { wait?: number }): Promise<void>;
  peek(): Item[]; take(pick: (m: Item, tier: string) => boolean): Item[];
}
export interface WatchOptions {
  identity: string; onMessage?: string; onNotice?: string; onPairing?: string; quiet?: boolean;
  /** Seconds a hook may run before it is stopped (default HOOK_MS / 1000); 0: no limit. */
  hookTimeout?: number;
  /** Own messages written to this directory as <id>.json and taken, instead of --on-message. */
  spool?: string;
  /** Carrier options over the environment's (tests: relay, endpoints, backoff). */
  carrier?: Record<string, unknown>;
  /** Where lines go (stdout). */
  print?: (line: string) => void;
  syncMs?: number;
}
export interface Watch { relay: string; close(): Promise<void>; idle(): Promise<void>; /** Resolves when the watcher stopped by itself: the seat went to another device. */ ended: Promise<string> }

// The same stored message: by its id; an item kept by an earlier version has none, and its sender,
// signing time, label and content tell it apart.
const same = (a: Item, b: Item): boolean => (a.id !== undefined && b.id !== undefined ? a.id === b.id : a.from === b.from && a.iat === b.iat && a.received === b.received && a.label === b.label
  && JSON.stringify(a.content ?? null) === JSON.stringify(b.content ?? null) && a.path === b.path);
const textOf = (m: Item): string => {
  if (m.type === 'file') return `file ${m.name ?? ''} (${m.size ?? 0} bytes) → ${m.path ?? ''}`;
  const t = typeof m.content === 'string' ? m.content : JSON.stringify(m.content);
  // One line on a terminal: cut, and said so, with where the whole is (the message stays for inbox).
  return t.length > TEXT_MAX ? `${t.slice(0, TEXT_MAX)}… (${t.length - TEXT_MAX} more characters: sigelo-agent inbox)` : t;
};

/** Runs CMD through the shell with json on stdin; → true when it exits 0 within ms (0: no limit). */
function hook(cmd: string, json: unknown, env: Record<string, string>, ms: number): Promise<boolean> {
  return new Promise((done) => {
    let c;
    try { c = spawn(cmd, { shell: true, stdio: ['pipe', 'inherit', 'inherit'], env: { ...process.env, ...env } }); } catch (e) { note(`hook ${cmd}: ${(e as Error).message}`); done(false); return; }
    const unread = env['SIGELO_MSG_ID'] ? `; message ${env['SIGELO_MSG_ID']} stays unread, offered again at the next round (dedupe on SIGELO_MSG_ID)` : '';
    const timer = ms > 0 ? setTimeout(() => { note(`hook ${cmd}: no exit within ${ms / 1000} s (--hook-timeout), stopped${unread}`); c.kill('SIGTERM'); }, ms) : null;
    const clear = (): void => { if (timer) clearTimeout(timer); };
    c.on('error', (e) => { clear(); note(`hook ${cmd}: ${e.message}${unread}`); done(false); });
    c.on('close', (code, signal) => { clear(); if (code !== 0) note(`hook ${cmd}: ${code === null ? `stopped (${signal})` : `exit ${code}`}${unread}`); done(code === 0); });
    c.stdin.on('error', () => {});
    c.stdin.end(safeJson(JSON.stringify(json)) + '\n');
  });
}

export async function startWatch(o: WatchOptions): Promise<Watch> {
  const path = resolve(o.identity);
  if (!existsSync(path)) throw Object.assign(new Error(noIdentity(path)), { usage: true });
  try { id.load(path); } catch (e) { throw unreadable(path, e); }
  // The operator's seat: this machine's device inbox first; elsewhere, refused (seat_elsewhere).
  await seatGate(path, 'watch');
  if (o.spool !== undefined && o.onMessage !== undefined) throw Object.assign(new Error('watch: --spool or --on-message, not both'), { usage: true });
  const hookMs = o.hookTimeout === undefined ? HOOK_MS : o.hookTimeout * 1000;
  if (!Number.isSafeInteger(hookMs) || hookMs < 0) throw Object.assign(new Error(`watch: --hook-timeout: whole seconds, 0 for no limit, not ${JSON.stringify(o.hookTimeout)}`), { usage: true });
  const spool = o.spool === undefined ? null : resolve(o.spool);
  if (spool !== null) mkdirSync(spool, { recursive: true, mode: 0o700 });
  const release = takeLock(path, 'watch');
  try {
    const { lib, link } = await contactLib();
    const print = o.print ?? ((l: string) => { process.stdout.write(`${safeText(l)}\n`); });
    const say = (l: string): void => { if (!o.quiet) print(l); };
    const base = { SIGELO_IDENTITY: path };
    const run = (cmd: string, json: unknown, env: Record<string, string>): Promise<boolean> => hook(cmd, json, env, hookMs);
    // Accept now (--spool): the item whole in DIR/<id>.json or nothing (a name of its own, then renamed); the same id again: the same file.
    const spooled = (msgId: string, item: unknown): string | null => {
      const f = join(spool!, `${msgId}.json`), tmp = `${f}.${process.pid}.tmp`;
      try { writeFileSync(tmp, safeJson(JSON.stringify(item)) + '\n', { mode: 0o600 }); renameSync(tmp, f); return f; } catch (e) {
        rmSync(tmp, { force: true });
        note(`spool ${spool}: ${(e as Error).message}; message ${msgId} stays unread, offered again at the next round`);
        return null;
      }
    };
    const pushes = o.onMessage !== undefined || spool !== null;
    // Handled one at a time, in order of arrival.
    let queue: Promise<unknown> = Promise.resolve();
    const later = (fn: () => Promise<unknown> | unknown): void => { queue = queue.then(fn).catch((e) => note(`watch: ${(e as Error).message}`)); };

    let carrier: Car;
    const tierOf = (m: Item): Item | undefined => carrier.peek().find((x) => same(x, m));
    async function onMessage(m: Item): Promise<void> {
      const kept = tierOf(m);
      if (!kept) return;                          // taken already (an inbox beside us)
      const tier = kept.tier ?? 'friend', name = m.contact ?? m.name ?? m.from;
      if (tier === 'own') {
        const { tier: _t, ...rest } = kept;
        const msgId = lib.messageId(kept), item = { ...rest, id: msgId };
        if (!pushes) { say(`own ${name}: ${textOf(m)}`); return; }
        if (spool !== null) {
          const f = spooled(msgId, item);
          if (f === null) return;
          say(`own ${name}: ${msgId} → ${f} (answer: sigelo-agent reply --to ${msgId} <text>)`);
        } else {
          const env = { ...base, SIGELO_TYPE: m.type === 'file' ? 'file' : 'message', SIGELO_FROM: m.from, SIGELO_NAME: String(name), SIGELO_TIER: tier, SIGELO_MSG_ID: msgId, ...(m.path !== undefined && { SIGELO_PATH: m.path }) };
          if (!(await run(o.onMessage!, item, env))) return;
        }
        let one = true;                            // taken once handed on: this one message
        carrier.take((x) => { if (!one || !same(x, kept)) return false; one = false; return true; });
        return;
      }
      if (tier === 'friend') notice(m.from, String(name));
    }
    // Each message once in the queue at a time: an arrival, the start, and each round (one a hook left unread).
    const offering = new Set<string>();
    const offer = (m: Item): void => {
      const k = lib.messageId(m);
      if (offering.has(k)) return;
      offering.add(k);
      later(async () => { try { await onMessage(m); } finally { offering.delete(k); } });
    };
    // A friend's messages: one notice per contact for a burst (NOTICE_MS), with how many wait.
    const pending = new Map<string, string>();
    let noticeTimer: NodeJS.Timeout | null = null;
    function notice(from: string, name: string): void {
      pending.set(from, name);
      noticeTimer ??= setTimeout(() => {
        noticeTimer = null;
        const all = [...pending]; pending.clear();
        later(async () => {
          const box = carrier.peek();
          for (const [from, name] of all) {
            const count = box.filter((x) => x.from === from && x.tier === 'friend').length;
            if (count === 0) continue;
            const n = { from, name, tier: 'friend', count };
            if (o.onNotice === undefined) say(`friend ${name}: ${count} new message${count === 1 ? '' : 's'} (not shown: sigelo-agent inbox)`);
            else await run(o.onNotice, n, { ...base, SIGELO_TYPE: 'notice', SIGELO_FROM: from, SIGELO_NAME: name, SIGELO_TIER: 'friend' });
          }
        });
      }, NOTICE_MS);
    }
    async function onPairing(e: Ev): Promise<void> {
      const name = String(e['name'] ?? e['did'] ?? ''), did = String(e['did'] ?? '');
      if (o.onPairing !== undefined) {
        await run(o.onPairing, e, { ...base, SIGELO_TYPE: String(e.type), SIGELO_FROM: did, SIGELO_NAME: name });
        return;
      }
      if (e.type === 'paired') say(`paired ${name} (${did}): check the words with them: ${String(e['fingerprint'] ?? '')}`);
      else say(`pairing failed ${name}: ${String(e['code'] ?? '')}: ${String(e['detail'] ?? '')}`);
    }
    // Links: one round at a time, in the queue with everything else.
    const linkRound = (): void => later(async () => {
      const r = await link.handle({ carrier, file: link.linksPath(path) });
      for (const l of linkNotes(r, { received: false })) say(l);
      for (const x of r.received.filter((y) => y.notice)) {
        if (o.onNotice === undefined) { say(introText(x)); continue; }
        const n = { type: 'link', id: x.id, from: x.from, name: x.name, peer: x.peer, peer_name: x.peer_name, purpose: x.purpose, note: x.note };
        await run(o.onNotice, n, { ...base, SIGELO_TYPE: 'link', SIGELO_FROM: x.from, SIGELO_NAME: x.name });
      }
    });
    // Device messages: by code, in the queue. The seat given away: the watcher stops (it no longer logs in as you).
    let endWith: (why: string) => void = () => {};
    const ended = new Promise<string>((r) => { endWith = r; });
    const deviceTurn = (): void => later(async () => {
      const r = await deviceRound(carrier, path, undefined, say);
      if (r.gave !== undefined) { say(`the seat went to ${r.gave}: this watcher stops`); endWith(`seat: ${r.gave}`); }
      if (r.wiped) endWith('wiped');
    });
    // Groups: by code (filed, carried on, rosters taken), then pushed by the sender's tier as messages are:
    // own → --on-message with the item as inbox gives it (group, mid, name, role, tier, note "not your
    // operator"…), taken once CMD exits 0; friend → --on-notice {type: "group", group, from, name, tier,
    // count}, the messages left for inbox; quiet → nothing. Each item handed on once per run.
    const pushed = new Set<string>();
    const groupTurn = (): void => later(async () => {
      const GR = await import('./sigelo-agent-group.ts');
      await GR.groupRound(carrier, path, { messages: [], events: [], dropped: {} }, { tiers: [], said: say });
      const G = await contactModule<GroupLib>('group'), file = G.groupsPath(path);
      const fresh = G.unread({ carrier, file }).filter((i) => !pushed.has(`${i.group.gid}.${i.mid}`));
      const friends = new Map<string, { group: GroupItem['group']; from: string; name: string; count: number }>();
      for (const i of fresh) {
        const gm = `${i.group.gid}.${i.mid}`;
        pushed.add(gm);
        if (i.tier === 'own') {
          if (!pushes) { say(`own ${i.name} in ${i.group.name} (${i.role}${i.note ? `, ${i.note}` : ''}): ${textOf(i as unknown as Item)}`); continue; }
          const env = { ...base, SIGELO_TYPE: 'group', SIGELO_FROM: i.from, SIGELO_NAME: i.name, SIGELO_TIER: i.tier, SIGELO_GROUP: i.group.gid, SIGELO_MSG_ID: gm };
          // Taken once handed on; a hook that failed or was stopped: offered again next round.
          const f = spool !== null ? spooled(gm, { ...i, id: gm }) : null;
          if (spool !== null && f !== null) say(`own ${i.name} in ${i.group.name}: ${gm} → ${f} (answer in the group: sigelo-agent group send)`);
          if (spool !== null ? f !== null : await run(o.onMessage!, { ...i, id: gm }, env)) G.unread({ carrier, file, pick: (x) => x.group.gid === i.group.gid && x.mid === i.mid });
          else pushed.delete(gm);
        } else if (i.tier === 'friend') {
          const k = `${i.group.gid} ${i.from}`, f = friends.get(k);
          friends.set(k, { group: i.group, from: i.from, name: i.name, count: (f?.count ?? 0) + 1 });
        }
      }
      for (const f of friends.values()) {
        if (o.onNotice === undefined) say(`friend ${f.name} in ${f.group.name}: ${f.count} new message${f.count === 1 ? '' : 's'} (not shown: sigelo-agent inbox)`);
        else await run(o.onNotice, { type: 'group', group: f.group, from: f.from, name: f.name, tier: 'friend', count: f.count }, { ...base, SIGELO_TYPE: 'group', SIGELO_FROM: f.from, SIGELO_NAME: f.name, SIGELO_TIER: 'friend', SIGELO_GROUP: f.group.gid });
      }
    });
    // Transfers: the engine of this session (made below, once the carrier is).
    let engine: { kick(): Promise<void>; close(): Promise<void> } | null = null;
    const onTransfer = (e: Ev): void => {
      const what = String(e['what'] ?? '');
      if (what === 'asked') {
        const n = { type: 'transfer', id: e['id'], from: e['from'], name: e['contact'], file: e['name'], size: e['size'] };
        if (o.onNotice === undefined) say(`transfer ${String(e['id'])}: ${String(e['contact'])} offers ${String(e['name'])} (${(Number(e['size']) / 1e6).toFixed(1)} MB): sigelo-agent transfer accept ${String(e['id'])} | decline ${String(e['id'])}`);
        else later(() => run(o.onNotice!, n, { ...base, SIGELO_TYPE: 'transfer', SIGELO_FROM: String(e['from']), SIGELO_NAME: String(e['contact']) }));
      } else if (['done', 'failed', 'declined', 'cancelled', 'interrupted'].includes(what)) {
        say(`transfer ${String(e['id'])}: ${what}${e['reason'] ? ` (${String(e['reason'])})` : ''}${e['path'] ? ` → ${String(e['path'])}` : ''}${typeof e['rate'] === 'number' ? `, ${(e['rate'] as number).toFixed(2)} MB/s` : ''}`);
      }
    };
    const onEvent = (e: Ev): void => {
      if (e.type === 'transfer') void engine?.kick();
      if (e.type === 'group') groupTurn();
      if (e.type === 'link' || e.type === 'paired') linkRound();
      if (e.type === 'device') deviceTurn();
      switch (e.type) {
        case 'message': case 'file': offer(e as unknown as Item); break;
        case 'paired': case 'pairing_failed': later(() => onPairing(e)); break;
        case 'tier': say(`tier ${String(e['name'])}: ${String(e['tier'])}`); break;
        case 'connected': note(`watch: connected to ${String(e['relay'])}`); break;
        case 'disconnected': note(`watch: disconnected from ${String(e['relay'])}; reconnecting`); break;
        case 'error': note(`watch: ${String(e['relay'] ?? '')} ${String(e['check'])}: ${String(e['detail'])}`); break;
        case 'pow': note('watch: proof of work for a new identity: 5–60 s'); break;
      }
    };
    carrier = new lib.Carrier({
      identity: () => { let s; try { s = id.load(path); } catch (e) { throw unreadable(path, e); } return { sign: signer(path, s).sign, bundle: id.bundleOf(s) }; },
      ...lib.pathsFor(path), ...lib.optionsFromEnv(), backoff: WATCH_BACKOFF, ...o.carrier, keep: true, onEvent,
    }) as unknown as Car;
    const X = await (await import('./sigelo-agent-contact.ts')).contactModule<{ Engine: new (o: object) => { kick(): Promise<void>; close(): Promise<void> } }>('transfer-node');
    engine = new X.Engine({ carrier, identity: path, onEvent: onTransfer });
    // What waited before this start: own pushed, one notice per friend.
    for (const m of carrier.peek()) if (m.tier === 'own' || m.tier === 'friend') offer(m);
    await carrier.start();
    linkRound();
    deviceTurn();
    groupTurn();
    // Each round: an own message a hook left unread (it failed, or was stopped) is offered again.
    const again = (): void => { if (pushes) for (const m of carrier.peek()) if (m.tier === 'own') offer(m); };
    const timer = setInterval(() => { carrier.sync().then(() => { again(); linkRound(); deviceTurn(); groupTurn(); void engine?.kick(); }, () => {}); }, o.syncMs ?? SYNC_MS);
    timer.unref();
    // A CLI or MCP send beside us queued something: send it now.
    const kicks = kickPath(path), onKick = (): void => { void engine?.kick(); carrier.sync().then(linkRound, () => {}); };
    watchFile(kicks, { interval: KICK_MS, persistent: false }, onKick);
    let closed = false;
    return {
      relay: carrier.relay, ended,
      idle: async () => { await new Promise((r) => setTimeout(r, NOTICE_MS + 50)); await queue; },
      async close() {
        if (closed) return;
        closed = true;
        clearInterval(timer);
        unwatchFile(kicks, onKick);
        rmSync(kicks, { force: true });
        if (noticeTimer) clearTimeout(noticeTimer);
        try { await engine?.close(); await carrier.stop(); await queue; } finally { release(); }
      },
    };
  } catch (e) { release(); throw e; }
}

export const USAGE = `watch [--identity <file> | --operator] [--on-message <cmd> | --spool <dir>] [--on-notice <cmd>] [--on-pairing <cmd>]
      [--hook-timeout <s|10m|1h>] [--quiet]
  stays connected; own contacts' messages → --on-message (JSON on stdin, SIGELO_MSG_ID), friends' → --on-notice
  ({from, name, tier, count}), quiet → nothing; pairings → --on-pairing. No hook: a line on stdout.
  --spool: each own message to <dir>/<id>.json and taken, no hook (answer later: reply --to <id>).
  --hook-timeout: a hook is stopped after it (default 120 s, $SIGELO_HOOK_TIMEOUT; 0: no limit). A hook
  that fails or is stopped leaves the message unread: offered again at the next round; dedupe on SIGELO_MSG_ID.`;

/** `sigelo-agent watch …`: runs until SIGINT/SIGTERM → 0; 2 usage or no identity; 1 refused (busy). */
export async function main(rest: string[]): Promise<number> {
  const o: Partial<WatchOptions> = {};
  let operator = false;
  const takes: Record<string, keyof WatchOptions> = { '--identity': 'identity', '--on-message': 'onMessage', '--on-notice': 'onNotice', '--on-pairing': 'onPairing', '--spool': 'spool', '--hook-timeout': 'hookTimeout' };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!, k = takes[a];
    if (a === '--quiet') { o.quiet = true; continue; }
    if (a === '--operator') { operator = true; continue; }
    if (k === undefined || rest[i + 1] === undefined || o[k] !== undefined) { note(`watch: ${k === undefined ? `unexpected ${JSON.stringify(a)}` : o[k] !== undefined ? `${a} given twice` : `${a} needs a value`}\n${USAGE}`); return 2; }
    (o as Record<string, unknown>)[k] = rest[++i];
  }
  if (o.onMessage !== undefined && o.spool !== undefined) { note(`watch: --on-message or --spool, not both\n${USAGE}`); return 2; }
  // --hook-timeout over SIGELO_HOOK_TIMEOUT: seconds, or 10m, 1h; 0 is no limit.
  try {
    const t = (o.hookTimeout as unknown as string | undefined) ?? process.env['SIGELO_HOOK_TIMEOUT'];
    o.hookTimeout = t === undefined || t === '' ? undefined : duration(t, o.hookTimeout !== undefined ? '--hook-timeout' : 'SIGELO_HOOK_TIMEOUT');
  } catch (e) { note(`watch: ${(e as Error).message}`); return 2; }
  let path: string;
  try { path = actingFile('watch', o.identity, operator); } catch (e) { note((e as Error).message); return 2; }
  let w: Watch;
  try { w = await startWatch({ ...o, identity: path } as WatchOptions); } catch (e) {
    note((e as Error).message);
    debug(e, { identity: path });
    return (e as { usage?: boolean }).usage ? 2 : 1;
  }
  const limit = o.hookTimeout === undefined ? '' : o.hookTimeout === 0 ? '; hooks without a time limit' : `; hooks stopped after ${o.hookTimeout} s`;
  note(`watching ${resolve(path)} at ${w.relay}${o.onMessage || o.onNotice || o.onPairing ? '' : o.spool ? `: own messages to ${resolve(o.spool)}` : ': a line per event'}${limit}. Ctrl-C stops it.`);
  await Promise.race([new Promise<void>((ok) => { process.once('SIGINT', () => ok()); process.once('SIGTERM', () => ok()); }), w.ended]);
  await w.close();
  return 0;
}
