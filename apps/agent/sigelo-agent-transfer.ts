// SPDX-License-Identifier: MIT
/**
 * The transfer verbs of the sidecar (TRANSFER.md, apps/contact/transfer-node.mjs, design/transfer.md):
 * `sigelo-agent transfer send|accept|decline|cancel|resume|forget|list|direct|settings`. A file of up to
 * 16 GiB goes agent to agent, direct (sigelo-transfer) or over a one-shot Tor onion; the relay carries
 * four small signed messages. Beside a watcher on the identity, the verbs change the transfers file,
 * queue what they send and kick it (its engine moves the bytes); beside a page they refuse (busy). With
 * neither, send, accept and resume stay connected until the transfer ends or --wait seconds pass.
 */
import { existsSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { bundleOf, load } from './sigelo-agent.ts';
import { signer } from './sigelo-agent-keys.ts';
import { actingFile, contactLib, contactModule, debug, holderFor, kick, lockHolder, noIdentity, safeJson, safeText, unreadable } from './sigelo-agent-contact.ts';

const lockFree = (path: string): boolean => lockHolder(path) === null;

export interface Rec { id: string; to?: string; from?: string; contact: string; name: string; size: number; state: string; reason?: string; detail?: string; attempt?: number; got?: number; sent?: number;
  live?: string; rate?: number | null; saved?: string; path_used?: string; via?: string; exp: number }
interface Engine { kick(): Promise<void>; idle(ms?: number, busy?: () => boolean): Promise<boolean>; close(): Promise<void>; progress(id: string): { live: string; got: number; sent: number; rate: number | null } | null }
export interface TransferLib {
  send(o: object): Promise<Rec>; accept(o: object): Rec; resume(o: object): Rec; decline(o: object): Promise<Rec>; cancel(o: object): Promise<Rec>; forget(o: object): Rec;
  list(o: object): { out: Rec[]; in: Rec[]; direct: Record<string, boolean>; settings: { tor: boolean; prefer: string } };
  setDirect(o: object): { did: string; name: string; direct: boolean }; settings(o: object): { tor: boolean; prefer: string; auto_mb: number };
  setAuto(o: object): { did: string; name: string; auto_mb: number | null };
  intake(o: object): Promise<unknown[]>;
  torCaps(cfg: unknown): Promise<{ serve: boolean; connect: boolean }>; torConfig(): unknown; loadRtc(): Promise<unknown>;
  Engine: new (o: object) => Engine;
}

export const USAGE = `sigelo-agent transfer — big files agent to agent (TRANSFER.md)

  transfer send <contact> <path>           up to 16 GiB, read in place: the contact is asked first; then
       [--via tor] [--direct on|off]       direct (your addresses to them) or over Tor; --via tor: Tor only;
       [--wait <s>]                        --direct: may this contact see your address (asked once; own: on)
  transfer list                            both sides: asked, offering, active (MB, MB/s), done, failed
  transfer accept <id> [--direct on|off]   yes to a file offered to you (free disk checked); nothing is
       [--via tor] [--wait <s>]            written before it; saved as send-file saves, one inbox item
  transfer decline <id> | cancel <id>      no to an offer; stop one either side (partials go)
  transfer resume <id> [--wait <s>]        after a drop or a lapsed offer: only the chunks missing
  transfer forget <id>                     the record and its partials gone, here
  transfer direct <contact> on|off         the direct switch for that contact
  transfer auto <contact> <MB>|default     that contact's size for landing without a question (0: always ask)
  transfer settings [--tor on|off] [--prefer fast|private] [--auto <MB>]   Tor (off when no tor daemon
                                           answers); Pro's order; files from own agents and contacts (and
                                           friends whose words were compared) up to --auto MB (default 25)
                                           land unasked, larger ones ask

--wait: seconds to stay connected (default 3600; 0: return once sent). Each verb: --identity <file>, or
--operator. A watcher (sigelo-agent watch) moves the bytes for it when one runs on the identity.`;

const SUBS: Record<string, { flags: string[]; args: [number, number] }> = {
  send: { flags: ['--via', '--direct', '--wait'], args: [2, 2] }, list: { flags: [], args: [0, 0] }, accept: { flags: ['--direct', '--via', '--wait'], args: [1, 1] },
  decline: { flags: [], args: [1, 1] }, cancel: { flags: [], args: [1, 1] }, resume: { flags: ['--wait', '--direct'], args: [1, 1] }, forget: { flags: [], args: [1, 1] },
  direct: { flags: [], args: [2, 2] }, auto: { flags: [], args: [2, 2] }, settings: { flags: ['--tor', '--prefer', '--auto'], args: [0, 0] },
};
const VALUED = ['--via', '--direct', '--wait', '--tor', '--prefer', '--auto', '--identity'];
const SESSION = ['send', 'accept', 'resume', 'decline', 'cancel'];
const out = (x: unknown): void => console.log(safeJson(JSON.stringify(x, null, 2)));
const note = (s: string): void => console.error(`sigelo-agent: ${safeText(s)}`);
const mb = (n: number): string => `${(n / 1e6).toFixed(1)} MB`;
const onOff = (v: string | undefined, name: string): boolean | undefined => {
  if (v === undefined) return undefined;
  if (v !== 'on' && v !== 'off') throw Object.assign(new Error(`${name}: on or off, not ${JSON.stringify(v)}`), { usage: true });
  return v === 'on';
};
/** One line for a transfer, for people. */
export function line(r: Rec, side: 'in' | 'out'): string {
  const who = side === 'in' ? `from ${r.contact}` : `to ${r.contact}`, size = mb(r.size);
  const prog = r.live ? `, ${mb(side === 'in' ? r.got ?? 0 : r.sent ?? 0)} of ${size}${r.rate ? `, ${r.rate.toFixed(2)} MB/s` : ''} (${r.live})` : '';
  const why = r.reason ? `: ${r.reason}${r.detail ? ` (${r.detail})` : ''}` : '';
  const next = side === 'in' && r.state === 'asked' ? ` · sigelo-agent transfer accept ${r.id} | decline ${r.id}` : side === 'in' && r.state === 'interrupted' ? ` · transfer resume ${r.id}` : '';
  return `transfer ${r.id} ${who}: ${r.name}, ${size}, ${r.state}${prog}${why}${r.saved ? ` → ${r.saved}` : ''}${next}`;
}

/** `sigelo-agent transfer <sub> …` → 0 done (or queued, asked), 1 refused or failed, 2 usage or no identity. */
export async function main(rest: string[]): Promise<number> {
  const sub = rest[0] ?? '', spec = SUBS[sub];
  const usage = (why: string): number => { note(`transfer: ${why}`); console.error(USAGE); return 2; };
  if (!spec) return usage(sub ? `no verb ${JSON.stringify(sub)}` : 'which verb?');
  const flags = new Map<string, string>(), args: string[] = [];
  for (let i = 1; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === '--') { args.push(...rest.slice(i + 1)); break; }
    if (!a.startsWith('--')) { args.push(a); continue; }
    if (![...spec.flags, '--identity', '--operator'].includes(a)) return usage(`${sub}: unknown flag ${a}`);
    if (flags.has(a)) return usage(`${a} given twice`);
    const v = VALUED.includes(a) ? rest[++i] : '';
    if (v === undefined) return usage(`${a} needs a value`);
    flags.set(a, v);
  }
  if (args.length < spec.args[0] || args.length > spec.args[1]) return usage(`${sub}: ${args.length < spec.args[0] ? 'an argument is missing' : `unexpected argument ${JSON.stringify(args[spec.args[1]])}`}`);
  const via = flags.get('--via');
  if (via !== undefined && via !== 'tor') return usage('--via: tor');
  const waitS = flags.has('--wait') ? Number(flags.get('--wait')) : 3600;
  if (!Number.isSafeInteger(waitS) || waitS < 0) return usage('--wait: whole seconds');
  let direct: boolean | undefined, tor: boolean | undefined;
  try { direct = onOff(flags.get('--direct'), '--direct'); tor = onOff(flags.get('--tor'), '--tor'); } catch (e) { return usage((e as Error).message); }
  const prefer = flags.get('--prefer');
  if (prefer !== undefined && prefer !== 'fast' && prefer !== 'private') return usage('--prefer: fast or private');
  const auto = flags.has('--auto') ? Number(flags.get('--auto')) : undefined;
  if (auto !== undefined && (!Number.isFinite(auto) || auto < 0)) return usage('--auto: a size in MB, 0: always ask');
  if (sub === 'auto' && args[1] !== 'default' && !(Number.isFinite(Number(args[1])) && Number(args[1]) >= 0)) return usage('auto: a size in MB (0: always ask), or default');
  let path: string;
  try { path = actingFile('transfer', flags.get('--identity'), flags.has('--operator')); } catch (e) { note((e as Error).message); return 2; }
  if (!existsSync(path)) { note(noIdentity(path, flags.has('--operator'))); return 2; }
  let lib, X: TransferLib;
  try { ({ lib } = await contactLib()); X = await contactModule<TransferLib>('transfer-node'); } catch (e) { note((e as Error).message.split('\n')[0]!); debug(e); return 1; }
  let w: { pid: number; kind: 'ui' | 'watch' } | null = null;
  if (SESSION.includes(sub)) {
    try { w = holderFor(path, `transfer ${sub}`, true); } catch (e) { note((e as Error).message); return 1; }
    if (w === null) { try { await (await import('./sigelo-agent-device.ts')).seatGate(path, `transfer ${sub}`); } catch (e) { note((e as Error).message); debug(e, { identity: path }); return 1; } }
  }
  let engine: Engine | null = null;
  const c = new lib.Carrier({
    identity: () => { let s; try { s = load(path); } catch (e) { throw unreadable(path, e); } return { sign: signer(path, s).sign, bundle: bundleOf(s) }; },
    ...lib.pathsFor(path), ...lib.optionsFromEnv(), keep: true,
    onEvent: (e: { type?: string }) => { if (e.type === 'pow') note('proof of work for a new identity: about 30 s on a phone, minutes under load'); if (e.type === 'transfer') void engine?.kick(); },
  }) as unknown as { start(): Promise<void>; stop(): Promise<void>; sync(o?: object): Promise<void> };
  const o = { carrier: c, identity: path, local: w !== null };
  // With no holder: this process holds the session and moves the bytes until the record ends.
  const live = async (id: string, side: 'in' | 'out'): Promise<number> => {
    const rec = (): Rec | undefined => X.list({ carrier: c, identity: path })[side].find((r) => r.id === id);
    if (w || waitS === 0) out(rec());
    if (w) { kick(path); note(`transfer ${sub}: queued for sigelo-agent watch (pid ${w.pid}), which moves the bytes: transfer list shows how far`); return 0; }
    if (waitS === 0) { await c.sync(); note(`transfer ${id}: sent; a watcher or a later transfer verb carries on`); return 0; }
    engine = new X.Engine({ carrier: c, identity: path, onEvent: (e: { what?: string; id?: string; detail?: string }) => { if (e.id === id && e.what === 'no_direct') note(`transfer ${id}: no direct path (${e.detail}); trying Tor`); } });
    await c.start();
    const busy = (): boolean => { const r = rec(); return !!r && (side === 'in' ? ['accepted', 'offering', 'active'].includes(r.state) || (r.state === 'interrupted' && r.reason === 'drop') : ['offered', 'active'].includes(r.state)); };
    const tick = setInterval(() => { const r = rec(), p = engine?.progress(id); if (r && p) note(line({ ...r, ...p }, side)); }, 10_000);
    try { await engine.idle(waitS * 1000, busy); } finally { clearInterval(tick); await engine.close(); await c.stop(); }
    const r = rec();
    if (r) { out(r); note(line(r, side)); }
    if (r && busy()) note(`transfer ${id}: still ${r.state} after ${waitS} s; it goes on with sigelo-agent watch, or transfer resume`);
    return r && ['failed', 'cancelled', 'declined', 'expired'].includes(r.state) ? 1 : 0;
  };
  // The direct switch, asked once on a terminal when it is not set for that contact (design §7).
  const ask = async <T>(fn: (d: boolean | undefined) => Promise<T> | T): Promise<T> => {
    try { return await fn(direct); } catch (e) {
      if ((e as { check?: string }).check !== 'direct_ask' || !process.stdin.isTTY) {
        if ((e as { check?: string }).check === 'direct_ask') (e as Error).message += `: pass --direct on or --direct off`;
        throw e;
      }
      const rl = createInterface({ input: process.stdin, output: process.stderr });
      const a = (await rl.question(`sigelo-agent: ${(e as Error).message}. Allow direct? [y/N] `)).trim().toLowerCase();
      rl.close();
      return fn(a === 'y' || a === 'yes');
    }
  };
  try {
    switch (sub) {
      case 'list': {
        // What the carrier kept since the last session: files offered filed (with no holder; else the holder's).
        if (lockFree(path)) { await c.sync().catch((e: Error) => note(`transfer list: offline (${e.message}): what this file holds`)); await X.intake({ carrier: c, identity: path }); }
        const r = X.list({ carrier: c, identity: path });
        out(r);
        for (const x of r.in) note(line(x, 'in'));
        for (const x of r.out) note(line(x, 'out'));
        if (!r.in.length && !r.out.length) note('transfer list: none (transfer send <contact> <path>)');
        return 0;
      }
      case 'send': {
        const r = await ask((d) => X.send({ ...o, to: args[0]!, path: args[1]!, ...(via && { via }), ...(d !== undefined && { direct: d }) }));
        note(`transfer ${r.id}: ${r.name} (${mb(r.size)}) offered to ${r.contact}; it goes once their operator says yes`);
        return live(r.id, 'out');
      }
      case 'accept': case 'resume': {
        const r = await ask((d) => X.accept({ ...o, id: args[0]!, ...(via && { via }), ...(d !== undefined && { direct: d }) }));
        note(`transfer ${r.id}: ${sub === 'accept' ? 'accepted' : 'resumed'}, ${r.name} from ${r.contact}`);
        return live(r.id, 'in');
      }
      case 'decline': { const r = await X.decline({ ...o, id: args[0]! }); out(r); note(`transfer ${r.id}: declined; ${r.contact} is told`); if (w) kick(path); return 0; }
      case 'cancel': { const r = await X.cancel({ ...o, id: args[0]! }); out(r); note(`transfer ${r.id}: cancelled; ${r.contact} is told`); if (w) kick(path); return 0; }
      case 'forget': { const r = X.forget({ carrier: c, identity: path, id: args[0]! }); out(r); note(`transfer ${r.id}: forgotten here, partials gone`); return 0; }
      case 'direct': {
        const on = onOff(args[1], 'direct');
        const r = X.setDirect({ carrier: c, identity: path, contact: args[0]!, on });
        out(r); note(`transfer direct ${r.name}: ${r.direct ? 'on: it may see your public and local addresses' : 'off: Tor, else no path'}`);
        return 0;
      }
      case 'auto': {
        const r = X.setAuto({ carrier: c, identity: path, contact: args[0]!, mb: args[1] === 'default' ? null : Number(args[1]) });
        out(r); note(`transfer auto ${r.name}: ${r.auto_mb === null ? 'the default size' : r.auto_mb === 0 ? 'always asked' : `files up to ${r.auto_mb} MB land without a question`}`);
        return 0;
      }
      case 'settings': {
        const s = X.settings({ identity: path, patch: { ...(tor !== undefined && { tor }), ...(prefer && { prefer }), ...(auto !== undefined && { auto_mb: auto }) } });
        const caps = await X.torCaps(X.torConfig());
        out({ ...s, tor_daemon: caps });
        note(`transfer settings: Tor ${s.tor ? (caps.serve || caps.connect ? 'on' : 'on, but no tor daemon answers here: off') : 'off'}; Pro order ${s.prefer}; files land unasked up to ${s.auto_mb} MB from own and compared contacts; direct ${(await X.loadRtc()) ? 'available' : 'unavailable (install sigelo-transfer)'}`);
        return 0;
      }
    }
    return 2;
  } catch (e) {
    note(e instanceof Error ? e.message : String(e));
    debug(e, { identity: path });
    return (e as { usage?: boolean } | null)?.usage === true ? 2 : 1;
  }
}
