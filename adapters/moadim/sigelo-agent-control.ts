// SPDX-License-Identifier: MIT
/**
 * Remote control over the relay, the computer's side (design/apps.md §6.3, UI-API.md "Remote"):
 * `sigelo-agent ui --remote --relay --name <n> [--scope read|chat|all]`.
 *
 * The page's operator carrier makes a short code named `control:<n>`; the computer prints
 * `SIGELO:CTL:<code>[:<HOST>]` (contact/control.mjs). An app pairs through it with its control
 * identity (a random key made there: never derived, attested, enrolled or listed as a device); the
 * computer records the control in `ui.json` `controls{<n>: {relay: true, scope, did, words, confirmed}}`
 * and shows the four words. Until the human confirms them here, every request is answered 403 words; a
 * "no" forgets the control's contact. Revoke: the same (its contact forgotten, the entry gone).
 *
 * Requests come as sigelo-device/1 `request` messages from the control's DID, kept apart by the
 * carrier (takeDevices) and split from the device messages after each drain; each runs as the LAN path
 * runs a sealed one (sigelo-agent-remote.ts remoteCall: scope, never the device routes) and is answered
 * by a `response`. A request starts a lease (contact/control.mjs LEASE): while it runs the computer
 * pushes `events` (GET /api/state?since=<last pushed seq>) when the state changed, at most one a
 * second, never asked for. A control holds a bucket of BURST requests refilled at RATE a second; one
 * over it is answered 429 rate once in ten seconds, then dropped. The seat elsewhere (DEVICES.md):
 * 409 seat_elsewhere. Every request, answer and event is a relay message: requests count in the
 * control's day and sit in the operator's queue; answers and events in the operator's day (pooled
 * if Pro) and the control's queue.
 * The control's contact is hidden from the page (state, history, contactOf): it is no one to talk to.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { contactLib, contactModule, safeJson, safeText } from './sigelo-agent-contact.ts';
import { isRelay, remoteCall, type AnyControl, type RelayControl, type Scope } from './sigelo-agent-remote.ts';

interface Ctl {
  ANSWER_MAX: number; LEASE: number; RATE: number; BURST: number;
  readControlText(t: string): { code: string; relay: string | null };
  newControlIdentity(): { secret: string; genesis: object } & Record<string, unknown>;
  makeControl(o: { operator: string; timeout?: number }): { attach(c: unknown): void; onEvent(e: unknown): void; call(m: string, p: string, b?: unknown): Promise<{ status: number; body: unknown }>; stop(): void };
  bucket(o: { now: () => number }): { take(): boolean };
  controlText(short: string, host?: string): string;
  readControl(c: unknown): Record<string, unknown>;
  responseMessage(o: { id: string; status: number; body: unknown }): object;
  eventsMessage(o: { seq: number; since: number; state: unknown }): object;
}
export interface RelayCarrier {
  relay: string;
  invite(o: { name?: string; short?: boolean }): Promise<{ code: string; short?: string; short_exp?: number; exp: number; relay: string }>;
  cancelInvite(code: string): Promise<unknown>;
  answeredBy(nonce: string): string | null;
  contacts(): { contacts: { did: string; revoked: boolean; fingerprint: string | null }[] };
  send(to: string, content: object, o: { label: string; internal: symbol }): Promise<unknown>;
  forget(did: string): Promise<unknown>;
}
export interface DevMessage { from: string; content: unknown }
export interface Relays {
  /** What the page never shows: the controls' contacts and their codes waiting. */
  hidden(x: { did?: unknown; name?: unknown }): boolean;
  /** A control's code: a new one, or null when it is paired already. Refused for a LAN control's name. */
  issue(name: string, scope: Scope): Promise<{ line: string; exp: number } | null>;
  /** Pairings done since: each control that answered its code now, with its four words. */
  look(): { name: string; words: string | null }[];
  confirm(name: string, match: boolean): Promise<boolean>;
  revoke(name: string): Promise<boolean>;
  /** The device messages split: the controls' (to handle), the rest (the device rounds'). */
  split(msgs: DevMessage[]): [DevMessage[], DevMessage[]];
  handle(msgs: DevMessage[]): Promise<void>;
  /** Every request in msgs answered 409 seat_elsewhere: the seat went, this page stops. */
  refuseAll(msgs: DevMessage[], holder: string): Promise<void>;
  /** The state may have changed: a push to each control with a lease, within a second. */
  changed(): void;
  stop(): void;
}

export async function relayControls(o: {
  carrier: RelayCarrier; controls: Record<string, AnyControl>; save(): void; routes: Record<string, unknown>;
  dispatch(method: string, url: URL, b: Record<string, unknown>): Promise<[number, unknown]>;
  serial<T>(f: () => Promise<T>): Promise<T>;
  /** The seat's holder when it is elsewhere, else null. */
  seatElsewhere(): string | null;
  lib: { DEVICE_LABEL: string; DEVICE_SEND: symbol; DEFAULT_RELAY: string }; nonceOf(code: string): string;
  note(s: string): void; now?: () => number;
}): Promise<Relays> {
  const C = await contactModule<Ctl>('control');
  const { carrier: c, controls, save, lib } = o, nowMs = o.now ?? Date.now, nowS = (): number => Math.floor(nowMs() / 1000);
  const relays = (): [string, RelayControl][] => Object.entries(controls).filter((e): e is [string, RelayControl] => isRelay(e[1]));
  const byDid = (d: string): [string, RelayControl] | undefined => relays().find(([, x]) => x.did === d);
  // In memory: the lease, what was pushed last, the bucket, when a refusal was told.
  const live = new Map<string, { lease: number; pushed: number; digest: string; bucket: { take(): boolean }; told: number }>();
  const liveOf = (d: string) => { let l = live.get(d); if (!l) { l = { lease: 0, pushed: 0, digest: '', bucket: C.bucket({ now: nowMs }), told: -Infinity }; live.set(d, l); } return l; };
  const send = (to: string, content: object): Promise<unknown> => c.send(to, content, { label: lib.DEVICE_LABEL, internal: lib.DEVICE_SEND });
  const answer = async (to: string, id: string, status: number, body: unknown): Promise<void> => {
    let b = body;
    if (JSON.stringify(b).length > C.ANSWER_MAX) [status, b] = [413, { error: { check: 'too_large', message: `the answer is longer than ${C.ANSWER_MAX} bytes, more than one relay message: ask for less (since)` } }];
    try { await send(to, C.responseMessage({ id, status, body: JSON.parse(JSON.stringify(b)) })); } catch (e) { o.note(`remote: an answer to a control not sent (${(e as Error).message})`); }
  };

  // stopped: the page closed; nothing more is sent or saved from here (ui.json may be another's by now).
  let timer: ReturnType<typeof setTimeout> | null = null, pushing = Promise.resolve(), stopped = false;
  // Volatile fields left out of the comparison: a state only "changes" when something in it did.
  const digestOf = (st: Record<string, unknown>): string => JSON.stringify({ ...st, now: 0, me: { ...(st['me'] as object), pow: (st['me'] as { pow?: unknown })?.pow ? 1 : 0 } });
  async function push(): Promise<void> {
    const t = nowS();
    for (const [, x] of relays()) {
      if (stopped) return;
      if (x.did === null || !x.confirmed) continue;
      const l = liveOf(x.did);
      if (l.lease <= t) continue;
      if (o.seatElsewhere() !== null) continue;
      const [status, st] = await o.dispatch('GET', new URL(`/api/state?since=${l.pushed}`, 'http://remote'), {});
      if (status !== 200) continue;
      const s = st as Record<string, unknown> & { seq: number }, d = digestOf(s);
      if (d === l.digest) continue;
      try { await send(x.did, C.eventsMessage({ seq: s.seq, since: l.pushed, state: JSON.parse(JSON.stringify(s)) })); l.pushed = s.seq; l.digest = d; } catch (e) { o.note(`remote: events to a control not sent (${(e as Error).message})`); }
    }
  }
  const changed = (): void => {
    if (stopped || timer !== null || !relays().some(([, x]) => x.did !== null && (live.get(x.did)?.lease ?? 0) > nowS())) return;
    timer = setTimeout(() => { timer = null; pushing = pushing.then(push).catch(() => {}); }, 1000);
  };

  async function revoke(name: string): Promise<boolean> {
    const x = controls[name];
    if (!isRelay(x)) return false;
    if (x.did !== null) {
      const d = x.did;
      await o.serial(async () => { try { await c.forget(d); } catch (e) { if ((e as { check?: string }).check !== 'not_contact') throw e; } });
      live.delete(d);
    }
    delete controls[name];
    save();
    return true;
  }
  return {
    hidden(x) {
      if (typeof x.name === 'string' && x.name.startsWith('control:')) return true;
      return typeof x.did === 'string' && byDid(x.did) !== undefined;
    },
    async issue(name, scope) {
      const had = controls[name];
      if (had && !isRelay(had)) throw Object.assign(new Error(`control ${name} is a LAN control (SIGELO:UI:): revoke it (ui --revoke-control ${name}) or pick another --name`), { check: 'remote', status: 409 });
      if (had && had.scope !== scope) throw Object.assign(new Error(`control ${name} has scope ${had.scope}: revoke it (ui --revoke-control ${name}) to make it again with ${scope}`), { check: 'remote', status: 409 });
      if (had?.did) return null;
      const r = await c.invite({ name: `control:${name}`, short: true });
      if (r.short === undefined) throw Object.assign(new Error('no short code from the relay: try again'), { check: 'remote', status: 502 });
      controls[name] = { relay: true, scope, created: had?.created ?? nowS(), last_used: null, did: null, nonce: o.nonceOf(r.code), exp: r.short_exp ?? r.exp, words: null, confirmed: false };
      save();
      return { line: C.controlText(r.short, c.relay === lib.DEFAULT_RELAY ? undefined : c.relay), exp: r.short_exp ?? r.exp };
    },
    look() {
      const done: { name: string; words: string | null }[] = [];
      for (const [name, x] of relays()) {
        if (x.did !== null || x.nonce === null) continue;
        const by = c.answeredBy(x.nonce);
        if (!by) continue;
        x.did = by; x.nonce = null;
        x.words = c.contacts().contacts.find((y) => y.did === by)?.fingerprint ?? null;
        done.push({ name, words: x.words });
      }
      if (done.length) save();
      return done;
    },
    async confirm(name, match) {
      const x = controls[name];
      if (!isRelay(x) || x.did === null) return false;
      if (match) { x.confirmed = true; save(); return true; }
      await revoke(name);
      return true;
    },
    revoke,
    // The cap counts at arrival: over it, the first is answered 429 (once in ten seconds), the rest dropped.
    split(msgs) {
      const mine: DevMessage[] = [], rest: DevMessage[] = [], t = nowMs();
      for (const m of msgs) {
        if (!byDid(m.from)) { rest.push(m); continue; }
        const l = liveOf(m.from);
        if (l.bucket.take()) mine.push(m);
        else if (t - l.told >= 10_000) { l.told = t; mine.push({ ...m, over: true } as DevMessage); }
      }
      return [mine, rest];
    },
    async handle(msgs) {
      for (const m of msgs) {
        if (stopped) return;
        const hit = byDid(m.from);
        if (!hit) continue;
        const [name, x] = hit;
        let q: { id: string; method: string; path: string; body?: Record<string, unknown> };
        try { q = C.readControl(m.content) as unknown as typeof q; } catch { continue; }
        if ((q as { typ?: string }).typ !== 'request') continue;
        const l = liveOf(m.from);
        if ((m as DevMessage & { over?: boolean }).over) { await answer(m.from, q.id, 429, { error: { check: 'rate', message: `more than ${C.BURST} requests at once, or more than ${C.RATE} a second: slow down` } }); continue; }
        if (!x.confirmed) { await answer(m.from, q.id, 403, { error: { check: 'words', message: `the four words of ${name} are not confirmed on the computer yet: compare them there` } }); continue; }
        const holder = o.seatElsewhere();
        if (holder !== null) { await answer(m.from, q.id, 409, { error: { check: 'seat_elsewhere', message: `the seat is with ${holder}: only it logs in as you; this computer answers nothing more` } }); continue; }
        x.last_used = nowS(); save();
        l.lease = nowS() + C.LEASE;
        const [status, body] = await remoteCall(x.scope, q, o.routes, o.dispatch);
        if (q.method === 'GET' && status === 200 && new URL(q.path, 'http://remote').pathname === '/api/state') {
          const s = body as Record<string, unknown> & { seq: number };
          l.pushed = s.seq; l.digest = digestOf(s);
        }
        await answer(m.from, q.id, status, body);
        if (q.method === 'POST') changed();
      }
    },
    async refuseAll(msgs, holder) {
      for (const m of msgs) {
        let q: { id: string; typ?: string };
        try { q = C.readControl(m.content) as unknown as typeof q; } catch { continue; }
        if (q.typ === 'request') await answer(m.from, q.id, 409, { error: { check: 'seat_elsewhere', message: `the seat went to ${holder}: this computer no longer logs in as you` } });
      }
    },
    changed,
    stop() { stopped = true; if (timer !== null) clearTimeout(timer); timer = null; },
  };
}

// ---------------------------------------------------------------- the app's side on a Linux phone (apps/gtk)
// `sigelo-agent control pair <SIGELO:CTL:…>`: a control identity made here (random key, never attested),
// kept in ~/.config/sigelo/control.local.json (0600, $SIGELO_CONTROL; it can do nothing but talk to that
// computer), the code accepted; prints {words, operator}: the four words to compare with the computer's.
// `sigelo-agent control ui [--app | --no-open] [--port <p>]`: the page on 127.0.0.1 (pageServer), every
// call a request to the computer over the relay, the state pushed (contact/control.mjs).
// `sigelo-agent control forget`: the control's files deleted here (revoke it on the computer too).
export const CONTROL_USAGE = 'control pair <SIGELO:CTL:…> [--force] | control ui [--app | --no-open] [--port <p>] | control forget   (--file <f>: else $SIGELO_CONTROL, else ~/.config/sigelo/control.local.json)';
const note = (s: string): void => console.error(`sigelo-agent: ${safeText(s)}`);
const controlFile = (flag: string | undefined): string => resolve(flag ?? process.env['SIGELO_CONTROL'] ?? join(homedir(), '.config', 'sigelo', 'control.local.json'));
interface ControlFile { secret: string; genesis: object; operator: string | null; relay: string | null }
async function controlCarrier(file: string, idf: ControlFile, onEvent?: (e: unknown) => void): Promise<{ accept(c: string, o: object): Promise<{ status: string; contact?: { did: string } }>; contacts(): { contacts: { did: string; fingerprint: string | null }[] }; start(): Promise<void>; stop(): Promise<void> }> {
  const { lib } = await contactLib();
  const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: idf.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
  return new lib.Carrier({ identity: () => ({ secret: Buffer.from(idf.secret, 'hex'), bundle }), ...lib.pathsFor(file), ...lib.optionsFromEnv(), ...(idf.relay && { relay: idf.relay }), ...(onEvent && { onEvent }) }) as never;
}

export async function controlMain(rest: string[]): Promise<number> {
  const sub = rest[0], args = rest.slice(1);
  let file: string | undefined, port: number | undefined, app = false, force = false, text: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!, v = args[i + 1];
    if (a === '--file' && v !== undefined && file === undefined) { file = v; i++; }
    else if (a === '--port' && v !== undefined && /^\d{1,5}$/.test(v) && port === undefined) { port = Number(v); i++; }
    else if (a === '--app') app = true;
    else if (a === '--no-open') continue;
    else if (a === '--force') force = true;
    else if (sub === 'pair' && text === undefined && !a.startsWith('--')) text = a;
    else { note(`control: unexpected ${JSON.stringify(a)}: ${CONTROL_USAGE}`); return 2; }
  }
  const f = controlFile(file), C = await contactModule<Ctl>('control');
  if (sub === 'pair') {
    if (text === undefined) { note(`control pair: the computer's SIGELO:CTL: text: ${CONTROL_USAGE}`); return 2; }
    let t: { code: string; relay: string | null };
    try { t = C.readControlText(text); } catch (e) { note(`control pair: ${(e as Error).message}`); return 2; }
    if (existsSync(f) && !force) { note(`control pair: ${f} holds a control already: control forget first (and revoke it on the computer), or --force`); return 1; }
    const idf = { ...C.newControlIdentity(), operator: null, relay: t.relay } as unknown as ControlFile;
    mkdirSync(dirname(f), { recursive: true, mode: 0o700 });
    writeFileSync(f, JSON.stringify(idf), { mode: 0o600 });
    const car = await controlCarrier(f, idf);
    try {
      const r = await car.accept(t.code, { name: 'computer', wait: 20, ...(t.relay && { relay: t.relay }) });
      if (!r.contact) { note(`control pair: the computer did not answer (${r.status}): is sigelo-agent ui --remote --relay still running, its code under 10 minutes old?`); return 1; }
      idf.operator = r.contact.did;
      writeFileSync(f, JSON.stringify(idf), { mode: 0o600 });
      const words = car.contacts().contacts.find((c) => c.did === r.contact!.did)?.fingerprint ?? null;
      console.log(safeJson(JSON.stringify({ operator: idf.operator, words })));
      note(`paired: compare the four words with the computer's (${words}); it answers once you confirm them there`);
      return 0;
    } catch (e) { note(`control pair: ${(e as Error).message}`); return 1; } finally { await car.stop(); }
  }
  if (sub === 'forget') {
    const { lib } = await contactLib(), p = lib.pathsFor(f) as { store: string; state: string; log?: string; files?: string };
    for (const x of [f, p.store, p.state, p.log, `${p.state}.lock`]) if (x) rmSync(x, { force: true });
    note(`forgotten here: ${f}. Revoke it on the computer too: sigelo-agent ui --revoke-control <name>`);
    return 0;
  }
  if (sub !== 'ui') { note(`control: ${CONTROL_USAGE}`); return 2; }
  let idf: ControlFile;
  try { idf = JSON.parse(readFileSync(f, 'utf8')) as ControlFile; } catch { note(`control ui: no control at ${f}: control pair <SIGELO:CTL:…> first`); return 2; }
  if (typeof idf.operator !== 'string') { note(`control ui: ${f} is not paired: control pair <SIGELO:CTL:…> again`); return 2; }
  const ctl = C.makeControl({ operator: idf.operator }), car = await controlCarrier(f, idf, (e) => ctl.onEvent(e));
  await car.start();
  ctl.attach(car);
  const { pageServer } = await import('./sigelo-agent-ui.ts');
  let at = 0;
  const { server, token } = pageServer({ port: () => at, has: (k) => /^(GET|POST) \/api\//.test(k),
    dispatch: async (m, url, b) => { const r = await ctl.call(m, url.pathname + url.search, m === 'POST' ? b : undefined); return [r.status, r.body]; } });
  try {
    at = await new Promise<number>((ok, no) => { server.once('error', no); server.listen(port ?? 0, '127.0.0.1', () => ok((server.address() as { port: number }).port)); });
  } catch (e) { ctl.stop(); await car.stop(); note(`control ui: ${(e as Error).message}`); return 1; }
  console.log(`http://127.0.0.1:${at}/#t=${token}`);
  note(`the computer's page over the relay (this machine only; the link is its key). ${app ? 'Stops with the app.' : 'Ctrl-C stops it.'}`);
  await new Promise<void>((ok) => {
    process.once('SIGINT', () => ok()); process.once('SIGTERM', () => ok());
    if (app) process.stdin.once('end', () => ok()).once('error', () => ok()).resume();
  });
  ctl.stop();
  server.closeAllConnections();
  await new Promise<void>((ok) => server.close(() => ok()));
  await car.stop();
  return 0;
}
