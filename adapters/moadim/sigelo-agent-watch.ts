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
 * SIGELO_TIER, SIGELO_PATH (a file's), SIGELO_IDENTITY. Commands run one at a time through the shell,
 * at most HOOK_MS each. Without a hook, one line per event on stdout (--quiet: none).
 *
 * The lock is `ui`'s (`<identity>.ui.pid`, "<pid> watch"): a page and a watcher never run on one file.
 * The watcher alone logs in with the identity (sigelo-agent-contact.ts lockPath): beside it the CLI
 * and MCP inbox read the state without a session (what the watcher received), send and send-file
 * queue in the state and touch `<identity>.ui.kick`, which makes it sync at once (polled every
 * KICK_MS); every other session verb refuses. Every SYNC_MS a round picks up the rest.
 */
import { spawn } from 'node:child_process';
import { existsSync, rmSync, unwatchFile, watchFile } from 'node:fs';
import { resolve } from 'node:path';
import * as id from './sigelo-agent.ts';
import { signer } from './sigelo-agent-keys.ts';
import { contactLib, debug, kickPath, noIdentity, safeJson, safeText, unreadable } from './sigelo-agent-contact.ts';
import { takeLock } from './sigelo-agent-ui.ts';

const HOOK_MS = 120_000, SYNC_MS = 60_000, KICK_MS = 1000, NOTICE_MS = 300, TEXT_MAX = 200;
// A lost connection (the network, a relay restart, another copy of the identity logging in elsewhere):
// back in 7.5 to 15 s.
export const WATCH_BACKOFF: [number, number] = [15_000, 120_000];
const note = (s: string): void => console.error(`sigelo-agent: ${safeText(s)}`);

type Item = { type?: string; from: string; name?: string; contact?: string; content?: unknown; label?: string; iat?: number; received?: number; path?: string; size?: number; tier?: string };
type Ev = Record<string, unknown> & { type?: string };
interface Car {
  relay: string;
  start(): Promise<void>; stop(): Promise<void>; sync(o?: { wait?: number }): Promise<void>;
  peek(): Item[]; take(pick: (m: Item, tier: string) => boolean): Item[];
}
export interface WatchOptions {
  identity: string; onMessage?: string; onNotice?: string; onPairing?: string; quiet?: boolean;
  /** Carrier options over the environment's (tests: relay, endpoints, backoff). */
  carrier?: Record<string, unknown>;
  /** Where lines go (stdout). */
  print?: (line: string) => void;
  syncMs?: number;
}
export interface Watch { relay: string; close(): Promise<void>; idle(): Promise<void> }

// The same stored message: inbox items carry no id; sender, signing time, label and content do.
const same = (a: Item, b: Item): boolean => a.from === b.from && a.iat === b.iat && a.received === b.received && a.label === b.label
  && JSON.stringify(a.content ?? null) === JSON.stringify(b.content ?? null) && a.path === b.path;
const textOf = (m: Item): string => {
  if (m.type === 'file') return `file ${m.name ?? ''} (${m.size ?? 0} bytes) → ${m.path ?? ''}`;
  const t = typeof m.content === 'string' ? m.content : JSON.stringify(m.content);
  // One line on a terminal: cut, and said so, with where the whole is (the message stays for inbox).
  return t.length > TEXT_MAX ? `${t.slice(0, TEXT_MAX)}… (${t.length - TEXT_MAX} more characters: sigelo-agent inbox)` : t;
};

/** Runs CMD through the shell with json on stdin; → true when it exits 0 within HOOK_MS. */
function hook(cmd: string, json: unknown, env: Record<string, string>): Promise<boolean> {
  return new Promise((done) => {
    let c;
    try { c = spawn(cmd, { shell: true, stdio: ['pipe', 'inherit', 'inherit'], env: { ...process.env, ...env } }); } catch (e) { note(`hook ${cmd}: ${(e as Error).message}`); done(false); return; }
    const timer = setTimeout(() => { note(`hook ${cmd}: no exit within ${HOOK_MS / 1000} s, stopped`); c.kill('SIGTERM'); }, HOOK_MS);
    c.on('error', (e) => { clearTimeout(timer); note(`hook ${cmd}: ${e.message}`); done(false); });
    c.on('close', (code) => { clearTimeout(timer); if (code !== 0) note(`hook ${cmd}: exit ${code}`); done(code === 0); });
    c.stdin.on('error', () => {});
    c.stdin.end(safeJson(JSON.stringify(json)) + '\n');
  });
}

export async function startWatch(o: WatchOptions): Promise<Watch> {
  const path = resolve(o.identity);
  if (!existsSync(path)) throw Object.assign(new Error(noIdentity(path)), { usage: true });
  try { id.load(path); } catch (e) { throw unreadable(path, e); }
  const release = takeLock(path, 'watch');
  try {
    const { lib } = await contactLib();
    const print = o.print ?? ((l: string) => { process.stdout.write(`${safeText(l)}\n`); });
    const say = (l: string): void => { if (!o.quiet) print(l); };
    const base = { SIGELO_IDENTITY: path };
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
        const { tier: _t, ...item } = kept;
        if (o.onMessage === undefined) { say(`own ${name}: ${textOf(m)}`); return; }
        const env = { ...base, SIGELO_TYPE: m.type === 'file' ? 'file' : 'message', SIGELO_FROM: m.from, SIGELO_NAME: String(name), SIGELO_TIER: tier, ...(m.path !== undefined && { SIGELO_PATH: m.path }) };
        if (!(await hook(o.onMessage, item, env))) return;
        let one = true;                            // taken once handed on: this one message
        carrier.take((x) => { if (!one || !same(x, m)) return false; one = false; return true; });
        return;
      }
      if (tier === 'friend') notice(m.from, String(name));
    }
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
            else await hook(o.onNotice, n, { ...base, SIGELO_TYPE: 'notice', SIGELO_FROM: from, SIGELO_NAME: name, SIGELO_TIER: 'friend' });
          }
        });
      }, NOTICE_MS);
    }
    async function onPairing(e: Ev): Promise<void> {
      const name = String(e['name'] ?? e['did'] ?? ''), did = String(e['did'] ?? '');
      if (o.onPairing !== undefined) {
        await hook(o.onPairing, e, { ...base, SIGELO_TYPE: String(e.type), SIGELO_FROM: did, SIGELO_NAME: name });
        return;
      }
      if (e.type === 'paired') say(`paired ${name} (${did}): check the words with them: ${String(e['fingerprint'] ?? '')}`);
      else say(`pairing failed ${name}: ${String(e['code'] ?? '')}: ${String(e['detail'] ?? '')}`);
    }
    const onEvent = (e: Ev): void => {
      switch (e.type) {
        case 'message': case 'file': { const m = e as unknown as Item; later(() => onMessage(m)); break; }
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
    // What waited before this start: own pushed, one notice per friend.
    for (const m of carrier.peek()) if (m.tier === 'own' || m.tier === 'friend') later(() => onMessage(m));
    await carrier.start();
    const timer = setInterval(() => { carrier.sync().catch(() => {}); }, o.syncMs ?? SYNC_MS);
    timer.unref();
    // A CLI or MCP send beside us queued something: send it now.
    const kicks = kickPath(path), onKick = (): void => { carrier.sync().catch(() => {}); };
    watchFile(kicks, { interval: KICK_MS, persistent: false }, onKick);
    let closed = false;
    return {
      relay: carrier.relay,
      idle: async () => { await new Promise((r) => setTimeout(r, NOTICE_MS + 50)); await queue; },
      async close() {
        if (closed) return;
        closed = true;
        clearInterval(timer);
        unwatchFile(kicks, onKick);
        rmSync(kicks, { force: true });
        if (noticeTimer) clearTimeout(noticeTimer);
        try { await carrier.stop(); await queue; } finally { release(); }
      },
    };
  } catch (e) { release(); throw e; }
}

export const USAGE = `watch [--identity <file>] [--on-message <cmd>] [--on-notice <cmd>] [--on-pairing <cmd>] [--quiet]
  stays connected; own contacts' messages → --on-message (JSON on stdin), friends' → --on-notice
  ({from, name, tier, count}), quiet → nothing; pairings → --on-pairing. No hook: a line on stdout.`;

/** `sigelo-agent watch …`: runs until SIGINT/SIGTERM → 0; 2 usage or no identity; 1 refused (busy). */
export async function main(rest: string[]): Promise<number> {
  const o: Partial<WatchOptions> = {};
  const takes: Record<string, keyof WatchOptions> = { '--identity': 'identity', '--on-message': 'onMessage', '--on-notice': 'onNotice', '--on-pairing': 'onPairing' };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!, k = takes[a];
    if (a === '--quiet') { o.quiet = true; continue; }
    if (k === undefined || rest[i + 1] === undefined || o[k] !== undefined) { note(`watch: ${k === undefined ? `unexpected ${JSON.stringify(a)}` : o[k] !== undefined ? `${a} given twice` : `${a} needs a value`}\n${USAGE}`); return 2; }
    (o as Record<string, unknown>)[k] = rest[++i];
  }
  const path = o.identity ?? id.identityPath();
  let w: Watch;
  try { w = await startWatch({ ...o, identity: path } as WatchOptions); } catch (e) {
    note((e as Error).message);
    debug(e, { identity: path });
    return (e as { usage?: boolean }).usage ? 2 : 1;
  }
  note(`watching ${resolve(path)} at ${w.relay}${o.onMessage || o.onNotice || o.onPairing ? '' : ': a line per event'}. Ctrl-C stops it.`);
  await new Promise<void>((ok) => { process.once('SIGINT', () => ok()); process.once('SIGTERM', () => ok()); });
  await w.close();
  return 0;
}
