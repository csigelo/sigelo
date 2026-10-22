// SPDX-License-Identifier: MIT
/**
 * Devices (DEVICES.md, design/devices.md D1–D3): this account on a phone or a second computer, by QR.
 * SAFE: worker i of the operator's keeper root, its own DID, tier own, its operator attestation 14
 * days. FULL (--full, "type FULL"): the same, plus the operator identity and the keeper root K_j,
 * sent once end to end after the words (online) or sealed in the frames (offline); written on the
 * device keychain-sealed where a store answers. The operator keeps a signed device list
 * (<identity>.devices.json) and sends it to every device at each change; `device revoke` wipes a
 * reachable device (9.1) or, --lost, does the steps of 9.2 that need no words and prints the rest.
 * The seat (D3, devices.md §4.3): the one FULL device that logs in as the operator, named in the signed
 * list (seat: {holder, epoch, iat}). Every operator login first reads this machine's device inbox
 * (seatGate), so a newer seat record is seen; elsewhere, it refuses seat_elsewhere. `device seat give`
 * and `take` move it with a sealed snapshot of the operator's state (contact/device.mjs sealSnapshot);
 * `take --force` imports the newest snapshot held and starts every session afresh. A standby keeps
 * the operator's state only sealed (<identity>.snapshot.sgs). Device messages are handled wherever
 * the inbox is read: inbox, watch, the page, MCP (deviceRound).
 * The protocol side is contact/device.mjs (frames, the sealed container, the material, the list),
 * contact/enrol.mjs (the online flow) and contact/qr*.mjs; this file is argv, the terminal and files.
 *
 *   online   device add → enrolment's short code as a QR (SIGELO:DEV:…); device scan on the device =
 *            init --enrol; the operator's side asks the four words on /dev/tty before the key goes.
 *   offline  device add --offline → the material sealed under k words, shown as QR frames, then
 *            (after Enter) the words; device scan reads the frames (any order), asks the words on
 *            /dev/tty, rebuilds and writes the identity, and accepts the 7-day operator invite.
 * Images: zbarimg when it is on PATH (execFile, never a shell, 10 s), else PNG built in.
 */
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { open as openFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { ReadStream, WriteStream } from 'node:tty';
import { did, keygen, verifySig, VERSION, type Attestation, type Genesis } from 'sigelo';
import { addAttestation, addIssuer, identityPath, head, load, save, secretOf, type Store } from './sigelo-agent.ts';
import { signer } from './sigelo-agent-keys.ts';
import * as keychain from './sigelo-agent-keychain.ts';
import { withLock } from './sigelo-agent-monero.ts';
import { agentsDirFor, contactModule, debug, heldPath, holderFor, lockHolder, putBack, safeJson, safeText, type Batch } from './sigelo-agent-contact.ts';
import { carrierFor, checkOperator, dropTemp, flags, initEnrol, keeperPath, libs, operatorPath, readKeeper, report, rootOf, runMachine, writeKeeper, type Keeper, type Out } from './sigelo-agent-enrol.ts';

export const USAGE = `Devices (DEVICES.md): this account on a phone or a second computer, by QR (SAFE: an own agent; FULL: you)
  device add --name <n> [--full]           --full: your identity and keeper root go too (asks "type FULL"; a terminal)
       [--wait <s>]                        online: a one-time QR (10 minutes); asks the device's four words
       [--tier friend|quiet] [--days <d>]  on this terminal before its key goes (--yes-words-checked: you did)
       [--png <dir>] [--yes-words-checked] --days: its attestation, 1 to 90 (default 14)
  device add --name <n> --offline          no network: the identity sealed in QR frames, then (Enter) the
       [--words 5..8] [--png <dir>] [--paged]  six words to type on the device; never both on one screen
  device scan [<code>|--text <t|->|--image <file>…] [--name <n>] [--into <file>] [--wait <s>]
                                           on the device: a QR's text, a code, or images (any order);
                                           words read on the terminal; into sigelo.<name>.local.json
  device scan --finish [--into <file>]     the operator invite of an offline scan, once online
  device show-qr [--png <dir>]             the pending online QR again (10 minutes)
  device list [--json]                     the devices of your roster: name, rank, worker, DID, paired, revoked
  device revoke <name> [--lost] [--wait <s>]  wipe a device you hold (it deletes its keys, answers); --lost: revoke
                                           and forget it now, and print the steps that need your 25 words
  device sync [--wait <s>] [--renew]       the seat: the signed list and a snapshot to every device, renewals due
                                           (--renew: all now); their answers read
  device sync --identity <device file>     on a device: take the list, seat, snapshot, renewal or wipe that came
  device seat [status]                     who holds the seat (logs in as you), its epoch, the snapshot held here
  device seat init --name <n>              once, on the machine that logs in as you: it becomes device <n>, the seat
  device seat give <name> [--with-history] the seat: the snapshot to <name>, the seat to it; this machine stops
  device seat take [--wait <s>]            a FULL standby: ask the seat for it (it sends the snapshot)
  device seat take --force                 the seat is lost or off: the newest snapshot here, every session afresh`;

// contact/ is plain JavaScript: its modules are typed loosely here, as contactLib's are.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Mod = Record<string, any>;
type Dev = Mod;
type Qr = Mod;
type QrDecode = Mod;
interface Qrm { size: number; version: number; modules: boolean[][] }

const note = (s: string): void => console.error(`sigelo-agent: ${safeText(s)}`);
const out = (x: unknown): void => console.log(safeJson(JSON.stringify(x, null, 2)));
const nowS = (): number => Math.floor(Date.now() / 1000);
const until = (t: number): string => new Date(t * 1000).toISOString().replace('.000', '');
const usageError = (why: string): Error => Object.assign(new Error(why), { usage: true });
const refuse = (check: string, why: string): never => { throw Object.assign(new Error(`${check}: ${why}`), { check }); };
const WAIT_MAX = 900, WAIT_ADD = 600, WAIT_SCAN = 120, SCAN_MS = 10000;
const failed = (e: unknown): number => {
  note(e instanceof Error ? e.message : String(e));
  debug(e, { identity: identityPath() });
  if ((e as { usage?: boolean }).usage) { console.error(USAGE); return 2; }
  return 1;
};
function seconds(v: string | undefined, dflt: number): number {
  if (v === undefined) return dflt;
  if (!/^\d+$/.test(v) || Number(v) > WAIT_MAX) throw usageError(`--wait: whole seconds, 0 to ${WAIT_MAX}, not ${JSON.stringify(v)}`);
  return Number(v);
}
const int = (flag: string, v: string | undefined, lo: number, hi: number, dflt: number): number => {
  if (v === undefined) return dflt;
  if (!/^\d+$/.test(v) || Number(v) < lo || Number(v) > hi) throw usageError(`${flag}: ${lo} to ${hi}, not ${JSON.stringify(v)}`);
  return Number(v);
};

// ---------------------------------------------------------------- the terminal

/** Whether this process has a controlling terminal (/dev/tty opens). */
export function hasTty(): boolean { try { closeSync(openSync('/dev/tty', 'r+')); return true; } catch { return false; } }
/** Write to the terminal (not stdout, not stderr: a pipe or a log never gets it). */
export async function ttyWrite(text: string): Promise<void> { const f = await openFile('/dev/tty', 'w'); try { await f.write(text); } finally { await f.close(); } }
/** One line from /dev/tty after `prompt`; hidden: not echoed (raw mode). */
export async function ttyLine(prompt: string, hidden = false): Promise<string> {
  const fd = openSync('/dev/tty', 'r+'), rs = new ReadStream(fd), ws = new WriteStream(fd);
  ws.write(prompt);
  return new Promise((done) => {
    let s = '';
    if (hidden) rs.setRawMode(true);
    rs.setEncoding('utf8');
    const finish = (v: string): void => { rs.off('data', on); if (hidden) { rs.setRawMode(false); ws.write('\n'); } rs.pause(); rs.destroy(); done(v); };
    const on = (d: string): void => {
      for (const ch of d) {
        if (ch === '\u0003') { if (hidden) rs.setRawMode(false); ws.write('\n'); process.exit(130); }
        if (ch === '\r' || ch === '\n') { finish(s); return; }
        s = ch === '\u007f' || ch === '\b' ? s.slice(0, -1) : s + ch;
      }
    };
    rs.on('data', on);
  });
}
const CLEAR = '\x1b[2J\x1b[3J\x1b[H';

function drawQr(q: Qr, text: string, maxVersion = 40): { m: Qrm; lines: string[] } {
  const m = q.encode(text, { ecc: 'M', maxVersion }) as Qrm;
  return { m, lines: q.toTerminal(m, { quiet: 2 }) };
}
/** A text as QR lines for the terminal (contact/qr.mjs), quiet zone 2. */
export async function terminalQr(text: string): Promise<string[]> { return drawQr(await contactModule<Qr>('qr'), text).lines; }
/** The terminal's width in columns, else 80. */
const columns = (): number => process.stderr.columns || process.stdout.columns || 80;
/** The largest QR version a terminal of `cols` columns shows with a quiet zone of 2: 17 + 4v + 4 ≤ cols, at most 20. */
export const versionFor = (cols: number): number => Math.max(1, Math.min(20, Math.floor((cols - 21) / 4)));
function writePng(q: Qr, dir: string, file: string, m: Qrm): string {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const f = join(resolve(dir), file);
  writeFileSync(f, q.toPng(m, { scale: 8, quiet: 4 }), { mode: 0o600 });
  return f;
}

// ---------------------------------------------------------------- images

/** The QR texts in an image file: zbarimg when on PATH (execFile, 10 s), else PNG built in, else scan_format. */
export async function scanImage(path: string, dec: QrDecode, env: NodeJS.ProcessEnv = process.env): Promise<string[]> {
  if (!existsSync(path)) refuse('scan_format', `${path}: no such file`);
  const z = await new Promise<{ ok: boolean; text?: string; missing?: boolean }>((done) => {
    execFile('zbarimg', ['--raw', '-q', '--', path], { timeout: SCAN_MS, encoding: 'utf8', env, maxBuffer: 1 << 20 }, (e, stdout) => {
      if (e && (e as { code?: unknown }).code === 'ENOENT') done({ ok: false, missing: true });
      else if (e) done({ ok: false });
      else done({ ok: true, text: stdout });
    });
  });
  if (z.ok && z.text) return z.text.split('\n').map((l) => l.replace(/\r$/, '')).filter(Boolean);
  const bytes = readFileSync(path);
  const png = bytes.length > 8 && bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  if (!png) refuse('scan_format', `${path} is not a PNG${z.missing ? ', and zbarimg is not installed: install zbar (zbarimg) or save the image as PNG' : ' and zbarimg read no code in it'}`);
  return [dec.scanPng(new Uint8Array(bytes))];
}

// ---------------------------------------------------------------- add

const qrPath = (op: string): string => op.replace(/\.json$/, '') + '.device-qr.json';
const nextIndex = (k: Keeper): number => { const used = Object.keys(k.workers).map(Number); return used.length ? Math.max(...used) + 1 : 0; };
function checkFree(k: Keeper, name: string): void {
  const taken = Object.entries(k.workers).find(([, w]) => w.name === name);
  if (taken) refuse('device_name_taken', `${name} is worker ${taken[0]} already (${taken[1].did}): another name`);
}

/** The operator: a device online (the words gate) or offline (frames, then words). */
async function add(f: Map<string, string>): Promise<number> {
  const op = operatorPath(f.get('--identity'));
  checkOperator(op, false, 'device add');
  const dev = await contactModule<Dev>('device'), q = await contactModule<Qr>('qr');
  const name = f.get('--name');
  if (name === undefined) throw usageError('device add: --name <name> is required (lowercase letters, digits, _ and -, at most 20)');
  try { dev.checkName(name); } catch (e) { throw usageError(`device add --name: ${(e as Error).message.replace(/^device_name: /, '')}`); }
  const tier = f.get('--tier');
  if (tier !== undefined && tier !== 'friend' && tier !== 'quiet') throw usageError(`device add --tier: friend or quiet, not ${JSON.stringify(tier)} (own is the default)`);
  const days = int('--days', f.get('--days'), 1, 90, dev.DEVICE_DAYS);
  const k = readKeeper(op);
  checkFree(k, name);
  await seatGate(op, 'device add');
  const full = f.has('--full');
  if (full) {
    if (f.has('--yes-words-checked')) throw usageError('device add --full: no --yes-words-checked: the words and FULL are confirmed on this terminal');
    if (!hasTty()) refuse('device_tty', 'a FULL device is confirmed on this terminal (/dev/tty): run it in a terminal');
    if (keychainOf(load(op)) === 'agent') refuse('key_provider_agent', 'your key is in sigelo-key-agent: it cannot go to a FULL device from here');
    const a = await ttyLine(`${name} gets your identity and your keeper root: it can sign as you and derive every worker. Lost, it costs your 25 words (DEVICES.md). Type FULL to go on: `);
    if (a.trim() !== 'FULL') refuse('device_full', 'FULL was not typed: nothing done');
  }
  return f.has('--offline') ? addOffline(op, k, name, days, tier, f, dev, q, full) : addOnline(op, k, name, days, tier, f, dev, q, full);
}
const keychainOf = (s: Store): string => (typeof s.secret === 'string' ? 'file' : (s.secret as { provider?: string }).provider ?? 'file');

async function addOnline(op: string, k: Keeper, name: string, days: number, tier: string | undefined, f: Map<string, string>, dev: Dev, q: Qr, full: boolean): Promise<number> {
  const rank = full ? 'full' : 'safe';
  let confirmedAt: number | undefined;
  const checked = f.has('--yes-words-checked'), wait = seconds(f.get('--wait'), WAIT_ADD);
  if (!checked && !hasTty()) refuse('device_words', 'the device\'s four words are confirmed on this terminal before its key goes, and there is none (/dev/tty): run it in a terminal, or compare the words yourself and pass --yes-words-checked');
  holderFor(op, 'device add');
  const { lib, enrol } = await libs(), { K, recovery } = rootOf(k), i = nextIndex(k), w = enrol.workerChain(K, i, 0, recovery);
  const c = carrierFor(lib, op), file = enrol.enrolPath(op);
  try {
    const r = await enrol.issue({ carrier: c, file, i, n: 0, name, keeper: { K, recovery }, days });
    writeKeeper(op, (x) => { x.workers[i] = { name, n: 0, did: w.did, original: w.original, placed: 'device', rank, via: 'online', at: nowS() }; });
    c.presetTier(w.original, tier ?? 'own');
    const text = dev.onlineText(r.short, c.relay === lib.DEFAULT_RELAY ? undefined : c.relay);
    save(qrPath(op), { v: 'sigelo-device-qr/1', qr: text, exp: r.short_exp, name, worker: i } as never);
    console.log(text);
    show(q, text, f.get('--png'), name);
    note(`device ${name}: scan this QR on it within 10 minutes (until ${until(r.short_exp)}), once: sigelo-agent device scan, or type ${r.short}. `
      + `It becomes worker ${i} (${w.did}), yours, attested ${days} days${full ? ', FULL' : ''}. Its four words are asked here before its key goes; waiting up to ${wait} s`);
    const confirm = async (x: { words: string; temp: string }): Promise<boolean> => {
      if (checked) { note(`the device paired; its four words: ${x.words} (not asked: --yes-words-checked)`); confirmedAt = nowS(); return true; }
      const a = await ttyLine(`\nThe device paired. Do its words read: ${x.words} ? [y/N] `);
      const yes = /^y(es)?$/i.test(a.trim());
      if (yes) confirmedAt = nowS();
      return yes;
    };
    const res: Out = await enrol.complete({ carrier: c, file, keeper: { K, recovery }, wait, confirm, until: (o: Out) => o.placed.some((p) => p.id === r.id) || o.refused.some((x) => x.check === 'device_words') });
    report(op, res);
    rmSync(qrPath(op), { force: true });
    if (res.refused.some((x) => x.check === 'device_words')) {
      writeKeeper(op, (x) => { delete x.workers[i]; });
      note('device add: the words were not confirmed: nothing was sent. If they differed, someone else answered the code: make a new one');
      return 1;
    }
    if (res.offline !== undefined) { debug(res.lastError, { identity: op, relay: c.relay }); return 1; }
    const done = res.placed.find((p) => p.id === r.id);
    if (!done) {
      note(`device add: not done within ${wait} s; kept 24 hours: sigelo-agent enrol --finish once the device has run${full ? '. Your identity and keeper root did not go: they go only within 10 minutes of the words; add it again for FULL' : ''}`);
      return 3;
    }
    const list = bumpList(op, dev, (ds) => [...ds.filter((d) => d.worker !== i), entryFor(op, name, i, w.original, rank)]);
    let sent = false;
    if (full) {
      if (!dev.gateOpen(confirmedAt, nowS())) note('device add: more than 10 minutes since the words were confirmed: your identity and keeper root were not sent. The device is SAFE now: revoke it and add it again with --full');
      else {
        await sendDevice(c, w.original, dev.materialMessage({ operator: operatorPayload(op), keeper: keeperPayload(op), devices: list, now: nowS() }));
        sent = true;
        note(`sent ${name} your identity and keeper root, end to end, once`);
      }
    }
    const pushed = await pushList(c, list, op);
    out({ device: name, rank: full && !sent ? 'safe' : rank, worker: i, did: done.did, original: done.original, via: 'online', ours: done.ours, tier: done.tier, exp: done.exp, list: list.seq, synced: pushed });
    return full && !sent ? 1 : 0;
  } finally { await c.stop(); }
}

function show(q: Qr, text: string, png: string | undefined, label: string): void {
  const { m, lines } = drawQr(q, text);
  if (lines[0]!.length > columns()) note(`this terminal is ${columns()} columns, the QR ${lines[0]!.length}: widen it, or use --png <dir>`);
  console.error(lines.join('\n'));
  if (png !== undefined) note(`QR image: ${writePng(q, png, `${label}-qr.png`, m)} (0600): delete it once scanned`);
}

async function addOffline(op: string, k: Keeper, name: string, days: number, tier: string | undefined, f: Map<string, string>, dev: Dev, q: Qr, full: boolean): Promise<number> {
  const rank = full ? 'full' : 'safe';
  if (!hasTty()) refuse('device_tty', 'the words of an offline device are shown on this terminal only (/dev/tty), after its frames: run it in a terminal');
  for (const x of ['--wait', '--yes-words-checked']) if (f.has(x)) throw usageError(`device add --offline: no ${x}`);
  const words = dev.makeWords(int('--words', f.get('--words'), dev.WORDS_MIN, dev.WORDS_MAX, dev.WORDS_DEFAULT));
  const { lib, enrol } = await libs(), { K, recovery } = rootOf(k), i = nextIndex(k), w = enrol.workerChain(K, i, 0, recovery);
  const me = load(op), iss = did(head(me)), now = nowS(), c = carrierFor(lib, op);
  let frames: string[], seq = 0;
  try {
    const attestation = enrol.operatorAttestation({ sign: signer(op, me).sign, iss, sub: w.original, relay: c.relay, now, days }) as { body: { exp: number; iat: number }; sig: string };
    const identity = enrol.workerIdentity({ K, i, n: 0, recovery, attestation, issuer: head(me) });
    const invite = (await (c as unknown as { invite(o: object): Promise<{ code: string }> }).invite({ name, ttl: 7 * 86400, local: true })).code;
    c.presetTier(w.original, tier ?? 'own');
    writeKeeper(op, (x) => { x.workers[i] = { name, n: 0, did: w.did, original: w.original, placed: 'device', rank, via: 'offline', at: now, attestation }; });
    const list = bumpList(op, dev, (ds) => [...ds.filter((d) => d.worker !== i), entryFor(op, name, i, w.original, rank)]);
    seq = list.seq;
    const safe = { name, identity, i, n: 0, invite, exp: now + dev.OFFLINE_EXP };
    const material = full ? dev.compactFull({ ...safe, operator: operatorPayload(op), keeper: keeperPayload(op), devices: list }) : dev.compactSafe(safe);
    const png = f.get('--png'), maxVersion = png !== undefined ? dev.FRAME_VERSION : versionFor(columns());
    frames = dev.toFrames(dev.seal(material, words), { maxVersion });
  } finally { await c.stop(); }
  for (const t of frames) console.log(t);
  const pngDir = f.get('--png');
  if (pngDir !== undefined) for (const [n, t] of frames.entries()) note(`frame ${n + 1} of ${frames.length}: ${writePng(q, pngDir, `${name}-frame-${String(n + 1).padStart(2, '0')}.png`, drawQr(q, t).m)} (0600)`);
  note(`device ${name}: worker ${i} (${w.did}), ${frames.length} frame(s). On the device: sigelo-agent device scan (the frames in any order), then type the words shown here next`);
  await showFrames(q, frames, f.has('--paged') || pngDir !== undefined);
  await ttyWrite(CLEAR);
  await ttyLine(`The words for ${name} (type them on the device; never photograph them with the frames):\n\n    ${words}\n\nThe device shows worker ${i}, ${w.did}.\nPress Enter once typed: the screen is cleared. `);
  await ttyWrite(CLEAR);
  note(`device ${name} added offline${full ? ', FULL' : ''}. Its invite lives 7 days: run sigelo-agent inbox (or the page) once online before the device connects, so its answer is read; then sigelo-agent device sync sends the device list to every device`);
  out({ device: name, rank, worker: i, did: w.did, original: w.original, via: 'offline', frames: frames.length, exp: now + 7 * 86400, list: seq });
  return 0;
}

// The frames on the terminal: cycled every second until Enter, or one per Enter (paged, or images written).
async function showFrames(q: Qr, frames: string[], paged: boolean): Promise<void> {
  const draw = (n: number): string => `${CLEAR}${drawQr(q, frames[n]!).lines.join('\n')}\n frame ${n + 1} of ${frames.length}\n`;
  if (paged || frames.length === 1) {
    for (let n = 0; n < frames.length; n++) {
      await ttyWrite(draw(n));
      await ttyLine(n + 1 < frames.length ? 'Enter: the next frame ' : 'Scanned? Enter: the words (the frames go first) ');
    }
    return;
  }
  let n = 0, stop = false;
  const tick = async (): Promise<void> => { while (!stop) { await ttyWrite(`${draw(n)}Enter once all are scanned: the words (the frames go first)\n`); n = (n + 1) % frames.length; await new Promise((r) => setTimeout(r, 1000)); } };
  const t = tick();
  await ttyLine('');
  stop = true;
  await t;
}

// ---------------------------------------------------------------- scan

const pendingPath = (into: string): string => into.replace(/\.json$/, '') + '.device.json';
interface Pending { v: string; frames?: string[]; invite?: string; operator?: string }
const readPending = (into: string): Pending => { try { return JSON.parse(readFileSync(pendingPath(into), 'utf8')) as Pending; } catch { return { v: 'sigelo-device-pending/1' }; } };

/** The device: a QR (online or frames), words on the terminal, the identity written. */
async function scan(rest: string[]): Promise<number> {
  const texts: string[] = [], images: string[] = [];
  const opts: string[] = [];
  for (let n = 0; n < rest.length; n++) {
    const a = rest[n]!;
    if (a === '--image') { while (rest[n + 1] !== undefined && !rest[n + 1]!.startsWith('--')) images.push(rest[++n]!); if (images.length === 0) throw usageError('--image needs a file'); }
    else if (a === '--text') { const v = rest[++n]; if (v === undefined) throw usageError('--text needs the text, or - for stdin'); texts.push(...(v === '-' ? readFileSync(0, 'utf8') : v).split(/\r?\n/).map((s) => s.trim()).filter(Boolean)); }
    else if (!a.startsWith('--') && texts.length === 0 && images.length === 0 && opts.length === 0) texts.push(a);
    else opts.push(a, ...(['--name', '--into', '--wait', '--identity'].includes(a) && rest[n + 1] !== undefined ? [rest[++n]!] : []));
  }
  const f = flags(opts, ['--name', '--into', '--wait', '--identity'], ['--finish']);
  const dev = await contactModule<Dev>('device'), dec = await contactModule<QrDecode>('qr-decode');
  const name = f.get('--name') ?? 'device';
  try { dev.checkName(name); } catch (e) { throw usageError(`device scan --name: ${(e as Error).message.replace(/^device_name: /, '')}`); }
  const into = resolve(f.get('--into') ?? f.get('--identity') ?? join(dirname(identityPath()), `sigelo.${name}.local.json`));
  const wait = seconds(f.get('--wait'), WAIT_SCAN);
  if (f.has('--finish')) return finishInvite(into, wait);
  for (const img of images) texts.push(...await scanImage(img, dec));
  if (texts.length === 0) throw usageError('device scan: give the QR\'s text, a code, --text <frames|-> or --image <file>…');
  const read = texts.map((t) => dev.readScan(t));
  const online = read.find((r) => r.kind !== 'frame') as { kind: string; code: string; relay?: string | null } | undefined;
  if (online) {
    if (read.length > 1) refuse('scan_text', 'one online code at a time (an online QR is a single code, not frames)');
    if (existsSync(into)) refuse('enrol_exists', `${into} holds an identity: --into <another file>, or move it away`);
    const code = online.code.slice(0, 4) + '-' + online.code.slice(4);
    note(`online code ${code}: pairing with the operator; compare the four words with the giving screen, which asks for them`);
    const t0 = Date.now(), r = await initEnrol(into, code, ['--wait', String(wait), '--name', 'operator', ...(online.relay ? ['--relay', online.relay] : [])]);
    if (r !== 0) return r;
    note(`this device's identity: ${into} (SIGELO_IDENTITY=${into}). ${images.length ? `Delete the image now: ${images.join(', ')}` : ''}`);
    // The operator sends the device list (and, FULL, its identity and keeper root first) once the device paired.
    const h = await receive(into, Math.max(10, wait - Math.floor((Date.now() - t0) / 1000)), true);
    say(h);
    if (h.list === undefined) { note('the device list has not come yet: sigelo-agent device sync --identity ' + into + ' takes it (and, FULL, your identity) later'); return 3; }
    return h.refused.length && !h.material && h.refused.some((x) => x.startsWith('device_material') || x.startsWith('device_expired')) ? 1 : 0;
  }
  if (existsSync(into)) refuse('enrol_exists', `${into} holds an identity: --into <another file>, or move it away`);
  const pend = readPending(into), all = [...(pend.frames ?? []), ...texts];
  const j = dev.joinFrames(all);
  if (!j.done) {
    mkdirSync(dirname(into), { recursive: true, mode: 0o700 });
    save(pendingPath(into), { v: 'sigelo-device-pending/1', frames: [...new Set(all)] } as never);
    note(`${j.have} of ${j.count} frames; still missing ${j.missing.join(', ')}: scan them (device scan --image … or --text …), any order`);
    return 3;
  }
  if (!hasTty()) refuse('device_tty', 'the words are typed on this terminal (/dev/tty), never on the command line: run it in a terminal');
  let material: unknown;
  for (let t = 1; ; t++) {
    const words = await ttyLine(`All ${j.count} frame(s) read. Type the words the giving screen shows (not shown here): `, true);
    try { material = dev.open(j.container, words); break; } catch (e) {
      const ch = (e as { check?: string }).check;
      if ((ch !== 'device_words') || t === 3) throw e;
      note(`${(e as Error).message} (try ${t} of 3)`);
    }
  }
  const x = dev.rebuild(material as never, { now: nowS() }) as { identity: Store; did: string; original: string; worker: number; operator: string; invite: string; name: string; exp: number; rank: string; full?: { operator: Store; keeper: Keeper; devices: List } };
  if (x.full) {
    const op = operatorPath(undefined);
    checkOperator(op, true, 'device scan');
    if (existsSync(op) && did(load(op).genesis) !== did(x.full.operator.genesis)) refuse('device_exists', `${op} holds another identity: set it aside first; nothing written`);
  }
  const wrap = provider(), id = sealed(x.identity, wrap);
  mkdirSync(dirname(into), { recursive: true, mode: 0o700 });
  withLock(into, () => { if (existsSync(into)) refuse('enrol_exists', `${into} appeared meanwhile: nothing written`); save(into, id); });
  rmSync(pendingPath(into), { force: true });
  note(`this device is worker ${x.worker} (${x.did}) of operator ${x.operator}, written to ${into} (0600${wrap ? ', the key sealed in the OS keychain' : ''}): check the DID against the giving screen. SIGELO_IDENTITY=${into}`);
  if (x.full) say({ refused: [], material: { ...writeFull(x.full, into), operator: x.operator }, list: x.full.devices.seq });
  if (images.length) note(`delete the image(s) now: ${images.join(', ')}`);
  save(pendingPath(into), { v: 'sigelo-device-pending/1', invite: x.invite, operator: x.operator } as never);
  const code = await finishInvite(into, wait);
  out({ did: x.did, original: x.original, worker: x.worker, operator: x.operator, rank: x.rank, file: into, provider: wrap ? 'keychain' : 'file', paired: code === 0, ...(x.full && { operator_file: operatorPath(undefined) }) });
  return code;
}

/** The operator's invite of an offline device, accepted (kept for --finish while offline or waiting). */
async function finishInvite(into: string, wait: number): Promise<number> {
  const p = readPending(into);
  if (!p.invite) { note('device scan --finish: nothing pending here'); return 0; }
  holderFor(into, 'device scan');
  const { lib } = await libs(), c = carrierFor(lib, into);
  try {
    const r = await c.accept(p.invite, { name: 'operator', wait: Math.min(wait, 60) });
    if (r.status === 'connected') {
      rmSync(pendingPath(into), { force: true });
      note(`paired with the operator ${p.operator ?? ''}${r.contact?.fingerprint ? `: ${r.contact.fingerprint}` : ''}`);
      return 0;
    }
    rmSync(pendingPath(into), { force: true });
    note('the invite is answered; the pairing completes once the operator is online (its inbox or page), then at this device\'s next connection (sigelo-agent inbox)');
    return 3;
  } catch (e) {
    note(`the operator invite waits (${(e as Error).message}): when online, sigelo-agent device scan --finish --into ${into}`);
    return 3;
  } finally { await c.stop(); }
}


// ---------------------------------------------------------------- the list, the material (D2)

interface Entry { name: string; worker: number; did: string; rank: string; added: number; by: string; revoked?: number }
interface Seat { holder: string; epoch: number; iat: number }
interface List { v: string; operator: string; seq: number; iat: number; devices: Entry[]; seat?: Seat; sig: string }
export interface DevMsg { from: string; name: string; current_did: string; content: { typ: string; devices?: List; name?: string; worker?: number } & Record<string, unknown> }
// The carrier as these verbs use it beyond enrol's: device messages, sent and taken apart.
interface DevCarrier { send(to: string, content: object, o: { label: string; internal: symbol }): Promise<{ status: string }>; takeDevices(): DevMsg[];
  inbox(o: object): Promise<Batch>; forget(did: string): Promise<{ released?: boolean }>; contacts(): { contacts: { did: string; current_did: string; chain: string[]; revoked: boolean; name: string; fingerprint?: string | null }[] };
  sendFile(to: string, path: string): Promise<{ status: string }>; freshEpochs(o: { only?: string[]; retire?: boolean }): string[];
  invite(o: object): Promise<{ code: string }>; accept(code: string, o: object): Promise<{ status: string; contact?: { did: string } }>; start(): Promise<void>;
  stop(): Promise<void>; storePath: string }
const dc = (c: unknown): DevCarrier => c as DevCarrier;

/** The signed device list beside an identity file: x.json → x.devices.json (0600). */
export const listPath = (file: string): string => file.replace(/\.json$/, '') + '.devices.json';
const readList = (file: string): List | null => { try { return JSON.parse(readFileSync(listPath(file), 'utf8')) as List; } catch { return null; } };
const opDids = (op: string): { original: string; current: string; key: string } => { const s = load(op); return { original: did(s.genesis), current: did(head(s)), key: head(s).key }; };
const entryFor = (op: string, name: string, worker: number, original: string, rank: string): Entry => ({ name, worker, did: original, rank, added: nowS(), by: opDids(op).current });

/**
 * The operator's list changed by fn, signed with seq + 1 and saved, under the keeper's lock. The first
 * list is the roster's devices (those D1 placed), revoked ones marked.
 */
function bumpList(op: string, dev: Dev, fn: (ds: Entry[]) => Entry[], seatFn?: (cur: Seat | undefined) => Seat): List {
  return withLock(listPath(op), () => {
    const cur = readList(op), me = opDids(op), s = load(op);
    if (cur) dev.checkList(cur, { keys: [me.key], operator: me.original });
    const base = cur?.devices ?? Object.entries(readKeeper(op).workers).filter(([, w]) => w.placed === 'device')
      .map(([i, w]) => ({ name: w.name, worker: Number(i), did: w.original, rank: w.rank ?? 'safe', added: w.at, by: me.current, ...(w.revoked !== undefined && { revoked: w.revoked }) }));
    const next = dev.signList({ operator: me.original, seq: (cur?.seq ?? 0) + 1, iat: nowS(), devices: fn(base), ...((seatFn || cur?.seat) && { seat: seatFn ? seatFn(cur?.seat) : cur!.seat }) }, signer(op, s).sign) as List;
    save(listPath(op), next as never);
    return next;
  });
}

/** The operator identity file as a FULL device takes it: the secret as plain hex (unsealed from the keychain here). */
function operatorPayload(op: string): Store {
  const s = load(op), p = keychainOf(s);
  if (p === 'agent') refuse('key_provider_agent', 'your key is in sigelo-key-agent: it cannot go to a FULL device');
  const seed = p === 'file' ? secretOf({ ...s, provider: 'file' }) : keychain.unwrap(s);
  try {
    const { provider: _p, ...rest } = s as Store & { provider?: string };
    return { ...rest, secret: Buffer.from(seed).toString('hex') } as Store;
  } finally { seed.fill(0); }
}
/** The keeper file as a FULL device takes it: K as root_hex (unsealed here when sealed). */
function keeperPayload(op: string): Keeper {
  const k = readKeeper(op), { K } = rootOf(k);
  try {
    const { root: _r, provider: _p, ...rest } = k;
    return { ...rest, root_hex: Buffer.from(K).toString('hex') };
  } finally { K.fill(0); }
}

async function sendDevice(c: unknown, to: string, content: object): Promise<void> {
  const { lib } = await libs(), l = lib as unknown as { DEVICE_LABEL: string; DEVICE_SEND: symbol };
  await dc(c).send(to, content, { label: l.DEVICE_LABEL, internal: l.DEVICE_SEND });
}
/** The list to every live device of it; one not reachable is named (device sync sends it again). → how many it went to. */
async function pushList(c: unknown, list: List, op: string, typ = 'list', skip: string[] = []): Promise<number> {
  let n = 0;
  const paired = new Set(dc(c).contacts().contacts.filter((x) => !x.revoked).map((x) => x.did));
  for (const d of list.devices) {
    if (d.revoked !== undefined || skip.includes(d.did)) continue;
    if (!paired.has(d.did)) { note(`device list ${list.seq}: ${d.name} has not paired yet; sigelo-agent device sync sends it later`); continue; }
    try { await sendDevice(c, d.did, { v: 'sigelo-device/1', typ, devices: list }); n++; } catch (e) { note(`device list ${list.seq}: not sent to ${d.name} (${(e as Error).message}); sigelo-agent device sync sends it later`); }
  }
  void op;
  return n;
}

// ---------------------------------------------------------------- the device side of the channel

const provider = (): boolean => {
  const p = process.env['SIGELO_KEY_PROVIDER'];
  if (p !== undefined && p !== 'file' && p !== 'keychain') refuse('key_provider_unknown', `SIGELO_KEY_PROVIDER ${JSON.stringify(p)}: file or keychain here`);
  return p === 'keychain' || (p === undefined && keychain.answers(keychain.systemKeychain()));
};
/** An identity file's key sealed in the OS keychain (wrap) or left plain hex: → the file to save. */
function sealed(id: Store, wrap: boolean): Store {
  const x = { ...id } as Store;
  if (!wrap) { x.provider = 'file'; return x; }
  const seed = Uint8Array.from(Buffer.from(id.secret as string, 'hex'));
  try { x.secret = keychain.wrap(seed, x, keychain.systemKeychain()) as never; x.provider = 'keychain'; } finally { seed.fill(0); }
  return x;
}

/**
 * A FULL device: the operator identity, the keeper file and the list written beside the operator
 * path of this machine ($SIGELO_HUMAN, else ~/.config/sigelo/me.local.json), the key and K sealed in
 * the OS keychain where one answers. Refused when another operator identity is there.
 */
function writeFull(full: { operator: Store; keeper: Keeper; devices: List }, deviceFile: string): { file: string; wrapped: boolean } {
  const op = operatorPath(undefined);
  checkOperator(op, true, 'device scan');
  const original = did(full.operator.genesis);
  if (existsSync(op) && did(load(op).genesis) !== original) refuse('device_exists', `${op} holds another identity (${did(load(op).genesis)}): set it aside first; your identity and keeper root were not written`);
  const wrap = provider();
  const id = sealed(full.operator, wrap);
  let keeper: Keeper = full.keeper;
  if (wrap) {
    const K = Uint8Array.from(Buffer.from(full.keeper.root_hex!, 'hex'));
    try { const { root_hex: _h, ...rest } = full.keeper; keeper = { ...rest, provider: 'keychain', root: keychain.wrapRoot(K, original, full.keeper.keeper, full.keeper.recovery) }; } finally { K.fill(0); }
  }
  mkdirSync(dirname(op), { recursive: true, mode: 0o700 });
  withLock(op, () => save(op, id));
  withLock(keeperPath(op), () => save(keeperPath(op), keeper as never));
  save(listPath(op), full.devices as never);
  save(listPath(deviceFile), full.devices as never);
  const self = did(load(deviceFile).genesis), me = full.devices.devices.find((d) => d.did === self);
  if (me) writeSeatLocal(op, (x) => { x.here = { name: me.name, file: resolve(deviceFile), did: self }; });
  return { file: op, wrapped: wrap };
}

// The operator this device's identity was attested by: its contact record (did, current_did, current_key).
function operatorOf(c: unknown, file: string): { did: string; current_did: string; current_key: string; name: string; fingerprint?: string | null } | null {
  const iss = did(load(file).issuers?.[0] ?? {} as never);
  const ct = dc(c).contacts().contacts.find((x) => !x.revoked && x.chain.includes(iss));
  if (!ct) return null;
  const rec = (JSON.parse(readFileSync(dc(c).storePath, 'utf8')) as { contacts: Record<string, { current_key: string }> }).contacts[ct.did];
  return { did: ct.did, current_did: ct.current_did, current_key: rec!.current_key, name: ct.name, fingerprint: ct.fingerprint };
}

interface Handled { material?: { file: string; wrapped: boolean; operator: string }; list?: number; wipe?: boolean; refused: string[]; seat?: { epoch: number; holder: string; mine: boolean; imported?: number | null }; snapshot?: number; renewed?: number; used?: unknown[] }
type FileItem = { type?: string; from?: string; sha256?: string; path?: string; name?: string };
/** The device: its device messages (from its operator only): material, list, wipe, seat, snapshot, renew. A wipe answers `wiped`; the caller deletes after stopping the carrier. items: the batch's messages, where a snapshot's file is (taken: `used`). */
async function onDevice(c: unknown, file: string, dev: Dev, msgs: DevMsg[], items: unknown[] = []): Promise<Handled> {
  const out: Handled = { refused: [] }, self = did(load(file).genesis), op = operatorOf(c, file), t = nowS();
  for (const m of msgs) {
    try {
      if (!op || m.from !== op.did) refuse('device_from', `a device message from ${m.name} (${m.from}), not your operator: ignored`);
      const x = dev.readMessage(m.content) as DevMsg['content'];
      if (x.typ === 'material') {
        const opFile = operatorPath(undefined);
        if (existsSync(opFile) && existsSync(keeperPath(opFile)) && did(load(opFile).genesis) === op!.did) refuse('device_material_done', 'your identity is here already: a second material is not taken');
        const full = dev.checkMaterial(x, { from: op, self, now: t }) as { operator: Store; keeper: Keeper; devices: List };
        out.material = { ...writeFull(full, file), operator: op!.current_did };
        out.list = full.devices.seq;
      } else if (x.typ === 'snapshot') {
        const opFile = fullHere(op!.did);
        if (!opFile) refuse('device_snapshot', 'a snapshot, but your identity is not on this device (SAFE): ignored');
        let bytes: Buffer;
        if (typeof x['data'] === 'string') bytes = Buffer.from(x['data'] as string, 'base64');
        else {
          const sha = x['sha256'] as string, it = (items as FileItem[]).find((m) => m?.type === 'file' && m.sha256 === sha && m.from === op!.did);
          const path = it?.path ?? findReceived(file, sha);
          if (!path) refuse('device_snapshot', 'its file has not come (yet): device sync --identity again later');
          bytes = readFileSync(path!);
          rmSync(path!, { force: true });
          if (it) (out.used ??= []).push(it);
        }
        if (createHash('sha256').update(bytes).digest('hex') !== x['sha256']) refuse('device_snapshot', 'the snapshot does not match its sha256: not kept');
        const got = keepSnapshot(opFile!, dev, new Uint8Array(bytes));
        if (got !== null) out.snapshot = got;
      } else if (x.typ === 'renew') {
        out.renewed = renewHere(file, op!, x['attestation'] as Attestation, x['issuer'] as Genesis, t);
      } else if (x.typ === 'list' || x.typ === 'wipe' || x.typ === 'seat') {
        const cur = readList(file), next = x.devices!;
        try { dev.acceptList(cur, next, { keys: [op!.current_key] }); } catch (e) {
          if ((e as { check?: string }).check === 'device_list_stale' && cur && next.seq === cur.seq && next.sig === cur.sig && x.typ !== 'wipe') continue;
          throw e;
        }
        if (x.typ === 'wipe' && !next.devices.some((d) => d.did === self && d.revoked !== undefined)) refuse('device_wipe', 'a wipe whose list does not revoke this device: ignored');
        save(listPath(file), next as never);
        const opFile = operatorPath(undefined);
        if (existsSync(opFile) && did(load(opFile).genesis) === op!.did) save(listPath(opFile), next as never);
        out.list = next.seq;
        if (next.seat && next.seat.epoch !== cur?.seat?.epoch) {
          const mine = next.seat.holder === self, full = fullHere(op!.did);
          out.seat = { epoch: next.seat.epoch, holder: next.seat.holder, mine };
          if (full && mine) out.seat.imported = await takeUp(full, dev, next);
          else if (full) await park(full, dev, next);
        }
        if (x.typ === 'wipe') {
          const meE = next.devices.find((d) => d.did === self)!;
          await sendDevice(c, op!.did, { v: 'sigelo-device/1', typ: 'wiped', name: meE.name, worker: meE.worker });
          out.wipe = true;
          return out;
        }
      } else refuse('device_message', `${x.typ} is the operator's to read`);
    } catch (e) {
      const ch = (e as { check?: string }).check ?? 'error';
      out.refused.push(`${ch}: ${(e as Error).message.replace(new RegExp(`^${ch}: `), '')}`);
    }
  }
  return out;
}

// After a wipe: this device's identity and its files, and the operator's here when it is the wiping one.
function wipeHere(file: string, operator: string): string[] {
  const gone: string[] = [];
  const drop = (f: string): void => {
    const base = basename(f).replace(/\.json$/, '');
    if (!existsSync(dirname(f))) return;
    for (const x of readdirSync(dirname(f))) if (x === basename(f) || x.startsWith(`${base}.`)) { rmSync(join(dirname(f), x), { recursive: true, force: true }); gone.push(join(dirname(f), x)); }
  };
  const op = operatorPath(undefined);
  if (existsSync(op) && did(load(op).genesis) === operator) drop(op);
  drop(file);
  return gone;
}

/** The device: read its inbox (up to wait s, until a list or a wipe came, when untilList), act on its device messages; the rest goes back for `inbox`. */
async function receive(file: string, wait: number, untilList: boolean | ((h: Handled) => boolean)): Promise<Handled & { offline?: string }> {
  const dev = await contactModule<Dev>('device'), { lib } = await libs(), c = carrierFor(lib, file);
  const all: Handled = { refused: [] };
  let opDid = '', offline: string | undefined;
  try {
    opDid = operatorOf(c, file)?.did ?? '';
    const end = Date.now() + wait * 1000;
    for (;;) {
      const b = await dc(c).inbox({ wait: Math.max(0, Math.ceil((end - Date.now()) / 1000)) });
      if (b.offline !== undefined) { putBack(heldPath(file), { messages: b.messages, events: b.events, dropped: b.dropped }); offline = b.offline; break; }
      const h = await onDevice(c, file, dev, dc(c).takeDevices(), b.messages);
      putBack(heldPath(file), { messages: b.messages.filter((m) => !h.used?.includes(m)), events: b.events, dropped: b.dropped });
      Object.assign(all, { ...h, refused: [...all.refused, ...h.refused], material: h.material ?? all.material, list: h.list ?? all.list, seat: h.seat ?? all.seat, snapshot: h.snapshot ?? all.snapshot, renewed: h.renewed ?? all.renewed });
      if (all.wipe || !untilList || (untilList === true ? all.list !== undefined : untilList(all)) || Date.now() >= end) break;
    }
  } finally { await c.stop(); }
  if (all.wipe) for (const g of wipeHere(file, opDid)) note(`wiped ${g}`);
  return { ...all, ...(offline !== undefined && { offline }) };
}
const say = (h: Handled): void => {
  for (const r of h.refused) note(`device: ${r}`);
  if (h.material) note(`your identity is here now: ${h.material.file} (0600${h.material.wrapped ? ', the key and keeper root sealed in the OS keychain' : ''}), ${h.material.operator}. This device is FULL: it signs as you; it logs in as you once it holds the seat (sigelo-agent device seat take)`);
  if (h.list !== undefined) note(`device list ${h.list} taken`);
  if (h.snapshot !== undefined) note(`a sealed snapshot of your state (seat epoch ${h.snapshot}) is kept here`);
  if (h.renewed !== undefined) note(`this device's attestation is renewed until ${until(h.renewed)}`);
  if (h.seat) note(h.seat.mine ? `the seat is this device's now (epoch ${h.seat.epoch})${h.seat.imported ? `: your state imported (snapshot epoch ${h.seat.imported})` : h.seat.imported === null ? ': no snapshot here yet' : ''}` : `the seat moved (epoch ${h.seat.epoch}): another device logs in as you`);
  if (h.wipe) note('the operator revoked this device: its keys and files here are deleted');
};

// ---------------------------------------------------------------- the seat (D3, devices.md §4.3–§4.5)

const OPERATOR_CTX = 'sigelo-relay/operator', HOUR = 3600, RENEW_BEFORE = 7 * 86400;
/** This machine's seat notes beside the operator file (0600): its device, the snapshot held, what was sent. Never in a snapshot. */
interface SeatLocal { v: string; here?: { name: string; file: string; did: string }; imported?: number; held?: { epoch: number; seq: number; iat: number }; sent?: { sha256: string; at: number } }
const seatLocalPath = (op: string): string => op.replace(/\.json$/, '') + '.seat.json';
/** The newest sealed snapshot this machine holds (a standby's, or the last one it gave): never plaintext. */
export const snapPath = (op: string): string => op.replace(/\.json$/, '') + '.snapshot.sgs';
const readSeatLocal = (op: string): SeatLocal => { try { return JSON.parse(readFileSync(seatLocalPath(op), 'utf8')) as SeatLocal; } catch { return { v: 'sigelo-seat-local/1' }; } };
function writeSeatLocal(op: string, fn: (x: SeatLocal) => void): SeatLocal {
  return withLock(seatLocalPath(op), () => { const x = readSeatLocal(op); fn(x); save(seatLocalPath(op), x as never); return x; });
}
/** A file's text written whole, 0600 (temp sibling + rename). */
function writePrivate(file: string, text: string): void {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const tmp = join(dirname(file), `.${basename(file)}.${randomBytes(8).toString('hex')}.tmp`);
  writeFileSync(tmp, text, { mode: 0o600, flag: 'wx' });
  renameSync(tmp, file);
}
const live = (l: List): Entry[] => l.devices.filter((d) => d.revoked === undefined);
const nameOf = (l: List, d: string): string => l.devices.find((x) => x.did === d)?.name ?? d;
/** Whether `file` is the operator of the list beside it (its keeper there): the operator's role, not a device's. */
export function operatorRole(file: string): boolean {
  try { return existsSync(keeperPath(file)) && readList(file)?.operator === did(load(file).genesis); } catch { return false; }
}
/** The operator file of this machine when it is `opDid`'s, with its keeper (a FULL holder), else null. */
function fullHere(opDid: string): string | null {
  const op = operatorPath(undefined);
  try { return existsSync(op) && existsSync(keeperPath(op)) && did(load(op).genesis) === opDid ? op : null; } catch { return null; }
}
/** This machine's own device of the list (its identity file), from the seat notes, else found in the agents' directory. */
export function hereOf(op: string): { name: string; file: string; did: string } | null {
  const l = readList(op), x = readSeatLocal(op).here;
  if (x && existsSync(x.file) && l?.devices.some((d) => d.did === x.did && d.revoked === undefined)) return x;
  if (!l) return null;
  let files: string[] = [];
  try { files = readdirSync(agentsDirFor(op)).filter((f) => /^sigelo\.[a-z0-9][a-z0-9_-]{0,63}\.local\.json$/.test(f)); } catch {}
  for (const f of files) {
    const file = join(agentsDirFor(op), f);
    let o: string;
    try { o = did(load(file).genesis); } catch { continue; }
    const d = l.devices.find((y) => y.did === o && y.revoked === undefined && y.rank === 'full');
    if (d) { const h = { name: d.name, file, did: o }; writeSeatLocal(op, (s) => { s.here = h; }); return h; }
  }
  return null;
}
const seatHere = (op: string): boolean => { const l = readList(op); return !!l?.seat && hereOf(op)?.did === l.seat.holder; };
/** The seat as the page shows it (GET /api/state me.seat): null without one; here: this machine holds it. */
export function seatInfo(op: string): { holder: string; epoch: number; here: boolean } | null {
  try { const l = readList(op); return l?.seat ? { holder: nameOf(l, l.seat.holder), epoch: l.seat.epoch, here: hereOf(op)?.did === l.seat.holder } : null; } catch { return null; }
}

/** A received file of `sha` among an identity's received files (it came in an earlier batch), or undefined. */
function findReceived(file: string, sha: string): string | undefined {
  const root = file.replace(/\.json$/, '') + '.files';
  const walk = (d: string): string | undefined => {
    let es;
    try { es = readdirSync(d, { withFileTypes: true }); } catch { return undefined; }
    for (const e of es) {
      const p = join(d, e.name);
      if (e.isDirectory()) { const r = walk(p); if (r) return r; } else if (createHash('sha256').update(readFileSync(p)).digest('hex') === sha) return p;
    }
    return undefined;
  };
  return walk(root);
}

/** A sealed snapshot kept beside the operator file when K opens it, it is this operator's, and it is newer than the one held. → its epoch, or null (not newer). */
function keepSnapshot(op: string, dev: Dev, bytes: Uint8Array): number | null {
  const { K } = rootOf(readKeeper(op));
  let b: { epoch: number; seq: number; iat: number };
  try { b = dev.openSnapshot(bytes, K, { operator: did(load(op).genesis) }) as typeof b; } finally { K.fill(0); }
  const loc = readSeatLocal(op);
  if (!dev.newerSnapshot(b, existsSync(snapPath(op)) ? loc.held : undefined)) return null;
  writePrivate(snapPath(op), '');
  writeFileSync(snapPath(op), bytes, { mode: 0o600 });
  writeSeatLocal(op, (x) => { x.held = { epoch: b.epoch, seq: b.seq, iat: b.iat }; });
  return b.epoch;
}

// The operator's files a snapshot carries (devices.md §4.4), by name; history and log only with --with-history.
async function snapFiles(op: string): Promise<Record<string, string>> {
  const { lib, enrol } = await libs(), p = lib.pathsFor(op) as { store: string; state: string; log?: string }, base = op.replace(/\.json$/, '');
  return { carrier: p.state, contacts: p.store, ui: `${base}.ui.json`, enrol: enrol.enrolPath(op), held: heldPath(op), history: `${base}.history.jsonl`, log: p.log ?? `${base}.inbox.log` };
}
/** The operator's state as a snapshot for `list` (its seat epoch and seq), sealed under K_j. */
async function buildSnapshot(op: string, dev: Dev, list: List, history: boolean): Promise<{ bytes: Uint8Array; body: { epoch: number; seq: number; iat: number; files: Record<string, string> } }> {
  const where = await snapFiles(op), files: Record<string, string> = {};
  for (const [k, f] of Object.entries(where)) if (existsSync(f)) files[k] = readFileSync(f, 'utf8');
  files['carrier'] ??= '{}';
  files['contacts'] ??= '{}';
  files['devices'] = JSON.stringify(list);
  files['roster'] = JSON.stringify(readKeeper(op).workers);
  const body = dev.snapshotBody({ operator: list.operator, epoch: list.seat?.epoch ?? 1, seq: list.seq, iat: nowS(), files, history });
  const { K } = rootOf(readKeeper(op));
  try { return { bytes: dev.sealSnapshot(body, K) as Uint8Array, body }; } finally { K.fill(0); }
}
/**
 * A snapshot imported into the operator's files here: carrier state, contacts, page data, enrolments,
 * held messages (history and log when it carries them); the roster's workers merged into the keeper.
 * Then the sessions with `only` (default all) start afresh (retire: every one-time key replaced). → its epoch, the contacts restarted.
 */
async function importSnapshot(op: string, dev: Dev, bytes: Uint8Array, o: { only?: string[]; retire: boolean }): Promise<{ epoch: number; restarted: number }> {
  if (lockHolder(op) !== null) refuse('busy', `${op} is open in a page or a watcher: stop it to take the seat's state`);
  const { K } = rootOf(readKeeper(op));
  let b: { epoch: number; files: Record<string, string> };
  try { b = dev.openSnapshot(bytes, K, { operator: did(load(op).genesis) }) as typeof b; } finally { K.fill(0); }
  const where = await snapFiles(op);
  for (const [k, f] of Object.entries(where)) {
    const text = b.files[k];
    if (typeof text !== 'string') continue;
    withLock(f, () => writePrivate(f, text));
  }
  if (typeof b.files['roster'] === 'string') {
    const r = JSON.parse(b.files['roster']) as Keeper['workers'];
    writeKeeper(op, (x) => { for (const [i, w] of Object.entries(r)) x.workers[i] = { ...x.workers[i], ...w }; });
  }
  const { lib } = await libs(), c = carrierFor(lib, op);
  let restarted: string[];
  try { restarted = dc(c).freshEpochs({ ...(o.only && { only: o.only }), retire: o.retire }); } finally { await c.stop(); }
  return { epoch: b.epoch, restarted: restarted.length };
}
/** The seat came here by a give: the snapshot held imported once (it must be of this epoch). → its epoch, or null when none of this epoch is here. */
async function takeUp(op: string, dev: Dev, list: List): Promise<number | null> {
  const loc = readSeatLocal(op), e = list.seat!.epoch;
  if (loc.imported === e) return e;
  if (!existsSync(snapPath(op)) || loc.held?.epoch !== e) return null;
  const r = await importSnapshot(op, dev, new Uint8Array(readFileSync(snapPath(op))), { only: live(list).map((d) => d.did), retire: false });
  writeSeatLocal(op, (x) => { x.imported = e; });
  return r.epoch;
}
/**
 * The seat is elsewhere: the operator's plaintext state here (an earlier tenure's) sealed into the
 * snapshot held when it is newer (counted at the epoch before the current one), then deleted, so a
 * standby keeps it only sealed. Not beside a page or a watcher on the file.
 */
async function park(op: string, dev: Dev, list: List): Promise<boolean> {
  if (lockHolder(op) !== null) return false;
  const where = await snapFiles(op), plain = ['carrier', 'contacts', 'ui', 'enrol', 'held'].map((k) => where[k]!).filter((f) => existsSync(f));
  if (!existsSync(where['carrier']!)) return false;
  const was = { ...list, seq: Math.max(1, list.seq), seat: list.seat ? { ...list.seat, epoch: Math.max(1, list.seat.epoch - 1) } : undefined } as List;
  const { bytes } = await buildSnapshot(op, dev, was, false);
  keepSnapshot(op, dev, bytes);
  for (const f of plain) rmSync(f, { force: true });
  writeSeatLocal(op, (x) => { delete x.imported; });
  return true;
}

/**
 * Before any login as the operator (devices.md §4.3): with a seat in the list, this machine's device
 * identity reads its inbox first, so a newer seat record is seen; then only the holder goes on.
 * Elsewhere: seat_elsewhere (and the plaintext state here is sealed away). No seat yet: as before.
 */
export async function seatGate(op: string, what: string): Promise<void> {
  const l0 = readList(op);
  if (!l0?.seat) return;
  try { if (l0.operator !== did(load(op).genesis)) return; } catch { return; }
  const here = hereOf(op);
  if (here && lockHolder(here.file) === null) {
    const h = await receive(here.file, 0, false);
    if (h.seat || h.snapshot !== undefined || h.refused.length) say(h);
  }
  const l = readList(op)!, dev = await contactModule<Dev>('device');
  if (!here || l.seat!.holder !== here.did) {
    try { if (await park(op, dev, l)) note(`your state here is sealed away (${snapPath(op)}): the seat is elsewhere`); } catch (e) { note(`your state here stays as it is (${(e as Error).message})`); }
    refuse('seat_elsewhere', `${what}: the seat is with ${nameOf(l, l.seat!.holder)} (epoch ${l.seat!.epoch}): only it logs in as you. Here: sigelo-agent device seat take (it asks the seat), or --force if it is lost`);
  }
  const loc = readSeatLocal(op);
  if (loc.imported !== l.seat!.epoch && (await takeUp(op, dev, l)) === null) {
    refuse('seat_snapshot', `${what}: the seat is this machine's (epoch ${l.seat!.epoch}), but its snapshot has not come: sigelo-agent device sync --identity ${here!.file} again, or device seat take --force (the newest snapshot here)`);
  }
}

/** The renewal of a device's attestation, taken: from its operator, for this device, newer. → its exp. */
function renewHere(file: string, op: { current_did: string; current_key: string }, a: Attestation, issuer: Genesis, now: number): number {
  const self = did(load(file).genesis);
  if (a.body.sub !== self || a.body.iss !== op.current_did || a.body.ctx !== OPERATOR_CTX || !(a.body.exp > now)) refuse('device_renew', 'not your operator\'s attestation of this device: ignored');
  if (!verifySig(op.current_key, a.body, a.sig) || did(issuer) !== op.current_did) refuse('device_renew', 'the renewal does not verify under your operator\'s key: ignored');
  withLock(file, () => { const s = load(file); addIssuer(s, issuer); addAttestation(s, a); save(file, s); });
  return a.body.exp;
}
/** The seat: each listed device whose attestation ends within RENEW_BEFORE (all: force) gets a fresh one (14 days). → their names. */
async function renewDue(c: unknown, op: string, dev: Dev, force: boolean): Promise<string[]> {
  const l = readList(op);
  if (!l) return [];
  const { enrol } = await libs(), me = load(op), t = nowS(), k = readKeeper(op), done: string[] = [];
  const paired = new Set(dc(c).contacts().contacts.filter((x) => !x.revoked).map((x) => x.did));
  for (const d of live(l)) {
    const w = k.workers[d.worker], exp = w?.until ?? w?.attestation?.body.exp ?? d.added + dev.DEVICE_DAYS * 86400;
    if (!(force || exp - t < RENEW_BEFORE) || !paired.has(d.did)) continue;
    const attestation = enrol.operatorAttestation({ sign: signer(op, me).sign, iss: did(head(me)), sub: d.did, relay: (c as { relay: string }).relay, now: t, days: dev.DEVICE_DAYS }) as Attestation;
    try { await sendDevice(c, d.did, { v: 'sigelo-device/1', typ: 'renew', attestation, issuer: head(me) }); } catch (e) { note(`renewal of ${d.name}: not sent (${(e as Error).message})`); continue; }
    writeKeeper(op, (x) => { if (x.workers[d.worker]) x.workers[d.worker]!.until = attestation.body.exp; });
    done.push(d.name);
  }
  return done;
}

const inlineMax = (dev: Dev): number => { const v = Number(process.env['SIGELO_SNAPSHOT_INLINE_MAX']); return Number.isSafeInteger(v) && v > 0 ? v : dev.INLINE_MAX; };
/** One sealed snapshot to one device DID: inline, or as a sigelo-file/0 file first, then the message naming it. → 'inline' | 'file'. */
async function sendSnapshot(c: unknown, dev: Dev, to: string, bytes: Uint8Array, body: { epoch: number; seq: number }): Promise<string> {
  const sha256 = createHash('sha256').update(bytes).digest('hex'), meta = { v: 'sigelo-device/1', typ: 'snapshot', epoch: body.epoch, seq: body.seq, sha256, size: bytes.length };
  if (dev.snapshotRoute(bytes.length, inlineMax(dev)) === 'inline') { await sendDevice(c, to, { ...meta, data: Buffer.from(bytes).toString('base64') }); return 'inline'; }
  const dir = mkdtempSync(join(tmpdir(), 'sigelo-snap-')), f = join(dir, `sigelo-snapshot-${body.epoch}-${body.seq}.sgs`);
  try {
    writeFileSync(f, bytes, { mode: 0o600 });
    const r = await dc(c).sendFile(to, f);
    if (r.status === 'refused') refuse('device_snapshot', `the snapshot file was refused: ${JSON.stringify(r)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  await sendDevice(c, to, { ...meta, file: basename(f) });
  return 'file';
}
/** The seat: its snapshot to every FULL standby, when it changed and an hour has passed (force: now). → how many it went to. */
async function pushSnapshots(c: unknown, op: string, dev: Dev, force: boolean): Promise<number> {
  const l = readList(op), here = hereOf(op);
  if (!l?.seat || !here || l.seat.holder !== here.did) return 0;
  const loc = readSeatLocal(op), t = nowS();
  if (!force && loc.sent && t - loc.sent.at < HOUR) return 0;
  const paired = new Set(dc(c).contacts().contacts.filter((x) => !x.revoked).map((x) => x.did));
  const to = live(l).filter((d) => d.rank === 'full' && d.did !== here.did && paired.has(d.did));
  if (to.length === 0) return 0;
  const { bytes, body } = await buildSnapshot(op, dev, l, false);
  const sum = createHash('sha256').update(JSON.stringify([body.epoch, body.seq, body.files])).digest('hex');
  if (!force && loc.sent?.sha256 === sum) return 0;
  let n = 0;
  for (const d of to) { try { await sendSnapshot(c, dev, d.did, bytes, body); n++; } catch (e) { note(`snapshot to ${d.name}: not sent (${(e as Error).message})`); } }
  writeSeatLocal(op, (x) => { x.sent = { sha256: sum, at: t }; });
  return n;
}
/**
 * The seat gives itself to `to` (a live FULL device): the list signed with the next epoch naming it,
 * the snapshot (of that list) to its device DID, then the list to every device. The snapshot is kept
 * here, sealed; this machine's plaintext state is sealed away at its next operator login (seatGate).
 */
async function giveSeat(c: unknown, op: string, dev: Dev, to: Entry, history: boolean): Promise<{ epoch: number; route: string }> {
  const cur = readList(op)!, me = load(op), t = nowS();
  const next = dev.signList({ operator: cur.operator, seq: cur.seq + 1, iat: t, devices: cur.devices, seat: dev.nextSeat(cur.seat, to.did, t) }, signer(op, me).sign) as List;
  const { bytes, body } = await buildSnapshot(op, dev, next, history);
  const route = await sendSnapshot(c, dev, to.did, bytes, body);
  withLock(listPath(op), () => save(listPath(op), next as never));
  const here = hereOf(op);
  if (here) save(listPath(here.file), next as never);
  await pushList(c, next, op, 'seat');
  keepSnapshot(op, dev, bytes);
  return { epoch: next.seat!.epoch, route };
}

/**
 * Device messages wherever an inbox is read (inbox, watch, the page, MCP; devices.md §7.2): the
 * operator's (wiped, seat-ask; then, at the seat, snapshots hourly and renewals due), or a device's
 * (material, list, seat, snapshot, renew, wipe). → the batch without the snapshot files taken, to whom
 * the seat went, and what a wipe deleted. said: where notes go.
 */
// taken: the device messages already taken from the carrier (the page keeps its relay controls' apart).
export async function deviceRound(c: unknown, file: string, batch?: Batch, said: (s: string) => void = note, taken?: DevMsg[]): Promise<{ batch?: Batch; gave?: string; wiped?: string[] }> {
  const dev = await contactModule<Dev>('device');
  if (operatorRole(file)) {
    const gone = await onOperator(c, file, dev, said, taken);
    if (gone.gave === undefined && seatHere(file)) {
      const n = await pushSnapshots(c, file, dev, false), r = await renewDue(c, file, dev, false);
      if (n) said(`snapshot sent to ${n} standby device(s)`);
      if (r.length) said(`renewed: ${r.join(', ')}`);
    }
    return { ...(batch && { batch }), ...(gone.gave !== undefined && { gave: gone.gave }) };
  }
  const msgs = taken ?? dc(c).takeDevices();
  if (msgs.length === 0) return { ...(batch && { batch }) };
  const opDid = operatorOf(c, file)?.did ?? '', h = await onDevice(c, file, dev, msgs, batch?.messages ?? []);
  for (const r of h.refused) said(`device: ${r}`);
  if (h.list !== undefined) said(`device list ${h.list} taken`);
  if (h.seat) said(h.seat.mine ? `the seat is this device's now (epoch ${h.seat.epoch})` : `the seat moved (epoch ${h.seat.epoch})`);
  if (h.snapshot !== undefined) said(`a sealed snapshot (epoch ${h.snapshot}) is kept`);
  if (h.renewed !== undefined) said(`attestation renewed until ${until(h.renewed)}`);
  const rest = batch && { ...batch, messages: batch.messages.filter((m) => !h.used?.includes(m)) };
  if (!h.wipe) return { ...(rest && { batch: rest }) };
  await dc(c).stop();
  const gone = wipeHere(file, opDid);
  said('the operator revoked this device: its keys and files here are deleted');
  return { ...(rest && { batch: rest }), wiped: gone };
}

// ---------------------------------------------------------------- device seat …

async function seat(args: string[]): Promise<number> {
  const sub = args[0] === undefined || args[0].startsWith('--') ? 'status' : args[0], rest = sub === args[0] ? args.slice(1) : args;
  const dev = await contactModule<Dev>('device');
  if (sub === 'status') {
    const f = flags(rest, ['--identity'], ['--json', '--operator']), op = operatorPath(f.get('--identity'));
    checkOperator(op, false, 'device seat');
    const l = readList(op), here = hereOf(op), loc = readSeatLocal(op);
    const r = { seat: l?.seat ? { holder: nameOf(l, l.seat.holder), did: l.seat.holder, epoch: l.seat.epoch, since: l.seat.iat } : null, here: here?.name ?? null, holds: !!l?.seat && here?.did === l.seat.holder, snapshot: existsSync(snapPath(op)) ? loc.held ?? null : null };
    out(r);
    if (!r.seat) note('no seat yet: on the machine that logs in as you, sigelo-agent device seat init --name <its name>');
    else note(r.holds ? `this machine (${r.here}) holds the seat, epoch ${r.seat.epoch}` : `the seat is with ${r.seat.holder} (epoch ${r.seat.epoch}); this machine is ${r.here ?? 'no device of your list'}`);
    return 0;
  }
  if (sub === 'init') return await seatInit(flags(rest, ['--name', '--identity'], ['--operator']), dev);
  if (sub === 'give') {
    const name = rest[0] !== undefined && !rest[0].startsWith('--') ? rest[0] : undefined;
    if (name === undefined) throw usageError('device seat give <name>: which device (device list names them)');
    return await seatGive(name, flags(rest.slice(1), ['--identity'], ['--with-history', '--operator']), dev);
  }
  if (sub === 'take') return await seatTake(flags(rest, ['--identity', '--wait'], ['--force', '--operator']), dev);
  throw usageError(`device seat: ${JSON.stringify(sub)} is not a verb (status, init, give, take)`);
}

async function seatInit(f: Map<string, string>, dev: Dev): Promise<number> {
  const op = operatorPath(f.get('--identity')), name = f.get('--name');
  checkOperator(op, false, 'device seat init');
  if (name === undefined) throw usageError('device seat init --name <name>: this machine\'s name among your devices');
  try { dev.checkName(name); } catch (e) { throw usageError(`device seat init --name: ${(e as Error).message.replace(/^device_name: /, '')}`); }
  holderFor(op, 'device seat init');
  const cur = readList(op);
  if (cur?.seat) refuse('seat_exists', `the seat exists already: ${nameOf(cur, cur.seat.holder)}, epoch ${cur.seat.epoch} (device seat status)`);
  const k = readKeeper(op);
  checkFree(k, name);
  const { lib, enrol } = await libs(), { K, recovery } = rootOf(k), i = nextIndex(k), w = enrol.workerChain(K, i, 0, recovery);
  const file = join(agentsDirFor(op), `sigelo.${name}.local.json`);
  if (existsSync(file)) { K.fill(0); refuse('enrol_exists', `${file} exists: another --name, or move it away`); }
  const me = load(op), t = nowS(), c = carrierFor(lib, op);
  let paired = false;
  try {
    const attestation = enrol.operatorAttestation({ sign: signer(op, me).sign, iss: did(head(me)), sub: w.original, relay: c.relay, now: t, days: dev.DEVICE_DAYS }) as { body: { exp: number; iat: number }; sig: string };
    const id = enrol.workerIdentity({ K, i, n: 0, recovery, attestation, issuer: head(me) });
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    withLock(file, () => { if (existsSync(file)) refuse('enrol_exists', `${file} appeared meanwhile`); save(file, sealed(id, provider())); });
    writeKeeper(op, (x) => { x.workers[i] = { name, n: 0, did: w.did, original: w.original, placed: 'device', rank: 'full', via: 'here', at: t, attestation, until: attestation.body.exp }; });
    c.presetTier(w.original, 'own');
    // Both sides here: the operator's code, the device answers it, the started operator replies.
    await dc(c).start();
    const inv = await dc(c).invite({ name, short: false }), d = carrierFor(lib, file);
    try { paired = (await dc(d).accept(inv.code, { name: 'operator', wait: 30 })).status === 'connected'; } finally { await d.stop(); }
  } finally { K.fill(0); await c.stop(); }
  const list = bumpList(op, dev, (ds) => [...ds.filter((d) => d.worker !== i), entryFor(op, name, i, w.original, 'full')], (s) => dev.nextSeat(s, w.original, nowS()));
  save(listPath(file), list as never);
  writeSeatLocal(op, (x) => { x.here = { name, file, did: w.original }; x.imported = list.seat!.epoch; });
  const c2 = carrierFor(lib, op);
  let synced = 0;
  try { synced = await pushList(c2, list, op, 'seat'); } finally { await c2.stop(); }
  note(`this machine is device ${name} (worker ${i}, ${w.did}) and holds the seat (epoch ${list.seat!.epoch}): it alone logs in as you; FULL devices take it with device seat take${paired ? '' : '. Its pairing with you completes at your next inbox'}`);
  out({ device: name, worker: i, did: w.did, original: w.original, file, seat: list.seat, list: list.seq, paired, synced });
  return 0;
}

async function seatGive(name: string, f: Map<string, string>, dev: Dev): Promise<number> {
  const op = operatorPath(f.get('--identity'));
  checkOperator(op, false, 'device seat give');
  holderFor(op, 'device seat give');
  const cur0 = readList(op);
  if (!cur0?.seat) refuse('seat_none', 'no seat yet: sigelo-agent device seat init --name <this machine> first');
  await seatGate(op, 'device seat give');
  const cur = readList(op)!, d = cur.devices.find((x) => x.name === name);
  if (!d) refuse('device_unknown', `no device ${JSON.stringify(name)}: sigelo-agent device list`);
  if (d!.revoked !== undefined || d!.rank !== 'full') refuse('device_seat', `${name} is not a live FULL device: the seat goes to one only`);
  if (d!.did === cur.seat!.holder) refuse('device_seat', `${name} holds the seat already`);
  const { lib } = await libs(), c = carrierFor(lib, op);
  let r: { epoch: number; route: string };
  try {
    // Everything waiting for you is taken first, so it rides in the snapshot (held).
    const b = await dc(c).inbox({ wait: 0 });
    report(op, { delivered: [], placed: [], refused: [], sent: [], rest: { messages: b.messages, events: b.events, dropped: b.dropped } });
    if (b.offline !== undefined) refuse('offline', `${b.offline}: the seat stays here`);
    const gone = await onOperator(c, op, dev);
    if (gone.gave !== undefined) { out({ seat_to: gone.gave }); return 0; }
    r = await giveSeat(c, op, dev, d!, f.has('--with-history'));
  } finally { await c.stop(); }
  if (await park(op, dev, readList(op)!)) note(`your state here is sealed away (${snapPath(op)})`);
  note(`the seat went to ${name} (epoch ${r.epoch}; the snapshot ${r.route}, sealed): this machine no longer logs in as you. It takes your state at its next device sync or operator login`);
  out({ seat_to: name, epoch: r.epoch, snapshot: r.route, history: f.has('--with-history') });
  return 0;
}

async function seatTake(f: Map<string, string>, dev: Dev): Promise<number> {
  const op = operatorPath(f.get('--identity')), wait = seconds(f.get('--wait'), 60), force = f.has('--force');
  checkOperator(op, false, 'device seat take');
  const cur = readList(op), here = hereOf(op);
  if (!cur?.seat) refuse('seat_none', 'no seat yet: the machine that logs in as you runs device seat init --name <its name>');
  if (!here) refuse('device_seat', 'this machine holds no FULL device of your list: add it with device add --full first');
  holderFor(here!.file, 'device seat take');
  holderFor(op, 'device seat take');
  const h0 = await receive(here!.file, 0, false);
  say(h0);
  if (h0.offline !== undefined && !force) refuse('offline', `${h0.offline}: the seat is asked over the relay (lost? --force)`);
  let l = readList(op)!;
  if (l.seat!.holder === here!.did) {
    const imported = readSeatLocal(op).imported === l.seat!.epoch ? l.seat!.epoch : await takeUp(op, dev, l);
    if (imported === null) refuse('seat_snapshot', 'the seat is this device\'s, but its snapshot has not come: device sync --identity again, or --force');
    out({ seat: l.seat!.epoch, holder: here!.name, imported });
    note(`this machine (${here!.name}) holds the seat, epoch ${l.seat!.epoch}`);
    return 0;
  }
  if (force) return await forceTake(op, dev, l, here!);
  const { lib } = await libs(), c = carrierFor(lib, here!.file);
  try {
    const o = operatorOf(c, here!.file);
    if (!o) refuse('device_seat', 'this device is not paired with you: device sync --identity first');
    await sendDevice(c, o!.did, { v: 'sigelo-device/1', typ: 'seat-ask', epoch_seen: l.seat!.epoch });
  } finally { await c.stop(); }
  note(`asked ${nameOf(l, l.seat!.holder)} (the seat, epoch ${l.seat!.epoch}) for the seat; waiting up to ${wait} s. It answers at its next inbox, watch round, page or device sync`);
  const h = await receive(here!.file, wait, (x) => x.seat?.mine === true);
  say(h);
  l = readList(op)!;
  if (l.seat!.holder !== here!.did) { note(`device seat take: no answer within ${wait} s: run it again once the seat has read its inbox; lost or off for good: device seat take --force`); return 3; }
  out({ seat: l.seat!.epoch, holder: here!.name, imported: h.seat?.imported ?? null });
  return h.seat?.imported ? 0 : 1;
}

/** take --force: the newest snapshot here imported, the seat written to this device at epoch + 1, every session afresh. */
async function forceTake(op: string, dev: Dev, cur: List, here: { name: string; file: string; did: string }): Promise<number> {
  const t = nowS(), me = load(op);
  const next = dev.signList({ operator: cur.operator, seq: cur.seq + 1, iat: t, devices: cur.devices, seat: dev.nextSeat(cur.seat, here.did, t) }, signer(op, me).sign) as List;
  let imported: number | null = null, restarted = 0;
  if (existsSync(snapPath(op))) {
    const r = await importSnapshot(op, dev, new Uint8Array(readFileSync(snapPath(op))), { retire: true });
    imported = r.epoch; restarted = r.restarted;
  } else note('no snapshot here: you start with what this machine holds (none: no contacts); your contacts pair again where needed');
  withLock(listPath(op), () => save(listPath(op), next as never));
  save(listPath(here.file), next as never);
  writeSeatLocal(op, (x) => { x.imported = next.seat!.epoch; });
  const { lib } = await libs(), c = carrierFor(lib, op);
  let synced = 0;
  try {
    if (imported === null) restarted = dc(c).freshEpochs({ retire: true }).length;
    // One round as you: the fresh prekeys go to every contact; then the seat to every device.
    const b = await dc(c).inbox({ wait: 0 });
    report(op, { delivered: [], placed: [], refused: [], sent: [], rest: { messages: b.messages, events: b.events, dropped: b.dropped } });
    if (b.offline !== undefined) note(`offline (${b.offline}): the fresh keys and the seat go at your next login`);
    else synced = await pushList(c, next, op, 'seat');
  } finally { await c.stop(); }
  note(`the seat is this machine's (${here.name}, epoch ${next.seat!.epoch}), taken by force${imported !== null ? ` from the snapshot of epoch ${imported}` : ''}; every session starts afresh. Messages the old seat took after that snapshot stay there`);
  out({ seat: next.seat!.epoch, holder: here.name, forced: true, imported, restarted, synced });
  return 0;
}

// ---------------------------------------------------------------- show-qr, list

async function showQr(f: Map<string, string>): Promise<number> {
  const op = operatorPath(f.get('--identity')), q = await contactModule<Qr>('qr');
  const p = ((): { qr: string; exp: number; name: string } | null => { try { return JSON.parse(readFileSync(qrPath(op), 'utf8')) as { qr: string; exp: number; name: string }; } catch { return null; } })();
  if (!p || !(p.exp > nowS())) { rmSync(qrPath(op), { force: true }); return refuse('device_qr', 'no online device code pending (it lives 10 minutes, while device add waits): sigelo-agent device add --name <n>'); }
  console.log(p.qr);
  show(q, p.qr, f.get('--png'), p.name);
  note(`device ${p.name}: good until ${until(p.exp)}`);
  return 0;
}

interface Row { name: string; rank: string; worker: number; did: string; original: string; via: string | null; added: number; paired: boolean; ours: boolean | null; tier: string | null;
  attested_until: number | null; revoked: number | null }
/** The devices of the roster as `device list` and the page show them, through carrier c (the operator's). */
async function rowsOf(op: string, c: unknown): Promise<{ rows: Row[]; signed: List | null }> {
  const k = readKeeper(op), { enrol } = await libs(), { K, recovery } = rootOf(k);
  const devices = Object.entries(k.workers).filter(([, w]) => w.placed === 'device');
  const me = load(op), dev = await contactModule<Dev>('device');
  let signed = readList(op);
  try { if (signed) dev.checkList(signed, { keys: [head(me).key], operator: did(me.genesis) }); } catch (e) { note(`device list: ${(e as Error).message}: not used`); signed = null; }
  const rows: Row[] = [], cc = c as { contacts(): { contacts: { did: string; revoked: boolean; ours: boolean; tier: string }[] }; observe(b: object): unknown };
  try {
    const cs = cc.contacts().contacts;
    for (const [i, w] of devices) {
      let ct = cs.find((x) => x.did === w.original && !x.revoked);
      // An offline device pairs through a plain invite: its attestation, which the operator issued, is
      // filed here once it has paired (ours).
      if (ct && !ct.ours && w.attestation) {
        const id = enrol.workerIdentity({ K, i: Number(i), n: w.n, recovery, attestation: w.attestation, issuer: head(me) });
        try { cc.observe({ v: 'sigelo/0', typ: 'bundle', genesis: id.genesis, rotations: id.rotations, bindings: [], attestations: id.attestations, issuers: id.issuers }); } catch {}
        ct = cc.contacts().contacts.find((x) => x.did === w.original && !x.revoked);
      }
      const e = signed?.devices.find((x) => x.worker === Number(i));
      rows.push({ name: w.name, rank: e?.rank ?? w.rank ?? 'safe', worker: Number(i), did: w.did, original: w.original, via: w.via ?? null, added: w.at, paired: !!ct, ours: ct?.ours ?? null, tier: ct?.tier ?? null,
        attested_until: w.attestation?.body.exp ?? null, revoked: e?.revoked ?? w.revoked ?? null });
    }
  } finally { K.fill(0); }
  return { rows, signed };
}

async function list(f: Map<string, string>): Promise<number> {
  const op = operatorPath(f.get('--identity'));
  checkOperator(op, false, 'device list');
  readKeeper(op);
  const { lib } = await libs(), c = carrierFor(lib, op);
  let r: Awaited<ReturnType<typeof rowsOf>>;
  try { r = await rowsOf(op, c); } finally { await c.stop(); }
  const { rows, signed } = r;
  if (f.has('--json')) out({ devices: rows, list: signed ? { seq: signed.seq, iat: signed.iat } : null });
  else if (rows.length === 0) note('no devices yet: sigelo-agent device add --name <n>');
  else for (const r of rows) console.log(`${r.name.padEnd(20)} ${r.rank}  worker ${r.worker}  ${r.did}  ${r.revoked ? `revoked ${until(r.revoked)}` : r.paired ? `paired, ${r.tier}` : 'not paired yet'}  (${r.via}, ${until(r.added)})`);
  return 0;
}

// ---------------------------------------------------------------- revoke, sync (the operator)

/** The operator: device messages taken (wiped answers: the device is forgotten; seat-ask: the seat goes to the asker). → the names forgotten, and to whom the seat went. */
async function onOperator(c: unknown, op: string, dev: Dev, said: (s: string) => void = note, taken?: DevMsg[]): Promise<string[] & { gave?: string }> {
  const list = readList(op), gone: string[] & { gave?: string } = [];
  for (const m of taken ?? dc(c).takeDevices()) {
    const d = list?.devices.find((x) => x.did === m.from);
    try {
      const x = dev.readMessage(m.content) as DevMsg['content'];
      if (!d) refuse('device_from', `a device message from ${m.name} (${m.from}), not a device of your list: ignored`);
      if (x.typ === 'seat-ask') {
        if (gone.gave !== undefined) refuse('seat_elsewhere', `${d!.name} asks for the seat, but it went to ${gone.gave} already`);
        if (d!.revoked !== undefined || d!.rank !== 'full') refuse('device_seat', `${d!.name} asks for the seat, but it is not a live FULL device: ignored`);
        const cur = readList(op), here = hereOf(op);
        if (!cur?.seat || !here || cur.seat.holder !== here.did) refuse('seat_elsewhere', `${d!.name} asks for the seat, but this machine does not hold it`);
        const r = await giveSeat(c, op, dev, d!, false);
        gone.gave = d!.name;
        said(`the seat went to ${d!.name} (it asked; epoch ${r.epoch}, the snapshot ${r.route}): this machine no longer logs in as you`);
        continue;
      }
      if (x.typ !== 'wiped') refuse('device_message', `${x.typ} from ${d!.name}: only wiped and seat-ask go this way`);
      if (d!.revoked === undefined) refuse('device_wipe', `${d!.name} says it wiped itself, but it is not revoked: ignored`);
      await dc(c).forget(m.from);
      writeKeeper(op, (k) => { if (k.workers[d!.worker]) k.workers[d!.worker]!.revoked ??= d!.revoked; });
      gone.push(d!.name);
      said(`${d!.name} wiped its keys and is forgotten`);
    } catch (e) { said(`device: ${(e as Error).message}`); }
  }
  return gone;
}

/** The operator's revocation up to the wait: the list and roster marked; --lost: forgotten and the list
 *  pushed; else the wipe sent and the list pushed to the others. Through carrier c (the CLI's or the page's). */
async function revokeStart(op: string, c: unknown, name: string, lost: boolean, dev: Dev): Promise<{ d: Entry; list: List; k: Keeper; forgot: boolean; synced: number }> {
  const cur = readList(op) ?? bumpList(op, dev, (ds) => ds);
  const d = cur.devices.find((x) => x.name === name) ?? refuse('device_unknown', `no device ${JSON.stringify(name)}: sigelo-agent device list`);
  if (d.revoked !== undefined && !lost) refuse('device_revoked', `${name} was revoked already; lost? sigelo-agent device revoke ${name} --lost`);
  const t = nowS(), list = d.revoked !== undefined ? cur : bumpList(op, dev, (ds) => dev.revokeIn(ds, name, t) as Entry[]);
  const k = writeKeeper(op, (x) => { if (x.workers[d.worker]) x.workers[d.worker]!.revoked ??= t; });
  let forgot = false, synced: number;
  if (lost) {
    try { await dc(c).forget(d.did); forgot = true; } catch (e) { if ((e as { check?: string }).check !== 'not_contact') throw e; }
    synced = await pushList(c, list, op);
  } else {
    try { await sendDevice(c, d.did, { v: 'sigelo-device/1', typ: 'wipe', devices: list }); } catch (e) { note(`${name} is not reachable (${(e as Error).message}): doubtful? sigelo-agent device revoke ${name} --lost`); }
    synced = await pushList(c, list, op, 'list', [d.did]);
  }
  return { d, list, k, forgot, synced };
}
/** --lost: the steps of 9.2, those done and those needing the words. */
function stepsOf(op: string, dev: Dev, d: Entry, k: Keeper): { now: string[]; words: string[] } {
  const w = k.workers[d.worker];
  const until = new Date(((w?.attestation?.body.exp ?? (d.added + dev.DEVICE_DAYS * 86400))) * 1000).toISOString().slice(0, 10);
  return dev.lostSteps({ d, n: w?.n ?? 0, j: k.keeper, opN: k.me?.n ?? load(op).rotations.length, until }) as { now: string[]; words: string[] };
}

/** device revoke <name> [--lost]: 9.1 (wipe a reachable device) or 9.2's steps without words. */
async function revoke(name: string | undefined, f: Map<string, string>): Promise<number> {
  const op = operatorPath(f.get('--identity')), lost = f.has('--lost'), wait = seconds(f.get('--wait'), 30);
  checkOperator(op, false, 'device revoke');
  if (name === undefined) throw usageError('device revoke <name>: which device (device list names them)');
  const dev = await contactModule<Dev>('device');
  holderFor(op, 'device revoke');
  await seatGate(op, 'device revoke');
  const cur = readList(op) ?? bumpList(op, dev, (ds) => ds);
  if (!cur.devices.some((x) => x.name === name)) refuse('device_unknown', `no device ${JSON.stringify(name)}: sigelo-agent device list`);
  const { lib } = await libs(), c = carrierFor(lib, op);
  let wiped = false, r: Awaited<ReturnType<typeof revokeStart>>;
  try {
    r = await revokeStart(op, c, name, lost, dev);
    if (!lost) {
      const end = Date.now() + wait * 1000;
      while (!wiped && Date.now() < end) {
        const b = await dc(c).inbox({ wait: Math.max(1, Math.ceil((end - Date.now()) / 1000)) });
        report(op, { delivered: [], placed: [], refused: [], sent: [], rest: { messages: b.messages, events: b.events, dropped: b.dropped } });
        wiped = (await onOperator(c, op, dev)).includes(name);
        if (b.offline !== undefined) { note(`offline: ${b.offline}`); break; }
      }
      r.forgot = wiped;
      if (!wiped) note(`${name} has not answered within ${wait} s: it wipes itself at its next sigelo-agent device sync, and is forgotten here when it answers (device sync). Doubtful: device revoke ${name} --lost`);
    }
  } finally { await c.stop(); }
  const { d, list, k, forgot, synced } = r;
  const steps = lost ? stepsOf(op, dev, d, k) : null;
  if (steps) {
    for (const x of steps.now) note(`done: ${x}`);
    note(d.rank === 'full' ? 'with your 25 words, in this order:' : 'with your 25 words, if you want:');
    steps.words.forEach((x, n) => note(`  ${n + 1}. ${x}`));
  }
  out({ device: name, rank: d.rank, worker: d.worker, revoked: list.devices.find((x) => x.name === name)!.revoked, lost, wiped, forgot, list: list.seq, synced, ...(steps && { steps }) });
  return 0;
}

/** device sync: the operator sends its list to every live device and reads their answers; on a device (--identity), it takes what came. */
async function sync(f: Map<string, string>): Promise<number> {
  const wait = seconds(f.get('--wait'), 0), id = f.get('--identity');
  if (id !== undefined && !existsSync(keeperPath(resolve(id)))) {
    const file = resolve(id);
    if (!existsSync(file)) throw usageError(`device sync: no identity at ${file}`);
    holderFor(file, 'device sync');
    const h = await receive(file, wait, false);
    say(h);
    if (h.offline !== undefined) { note(`offline: ${h.offline}`); return 1; }
    out({ list: h.list ?? readList(file)?.seq ?? null, full: !!h.material, wiped: !!h.wipe, refused: h.refused.length });
    return h.refused.length ? 1 : 0;
  }
  const op = operatorPath(id), dev = await contactModule<Dev>('device');
  checkOperator(op, false, 'device sync');
  holderFor(op, 'device sync');
  await seatGate(op, 'device sync');
  const list = readList(op) ?? bumpList(op, dev, (ds) => ds), { lib } = await libs(), c = carrierFor(lib, op);
  let synced = 0, gone: string[] & { gave?: string } = [], snaps = 0, renewed: string[] = [];
  try {
    const b = await dc(c).inbox({ wait });
    report(op, { delivered: [], placed: [], refused: [], sent: [], rest: { messages: b.messages, events: b.events, dropped: b.dropped } });
    if (b.offline !== undefined) { note(`offline: ${b.offline}`); return 1; }
    gone = await onOperator(c, op, dev);
    if (gone.gave === undefined) {
      const now = readList(op) ?? list;
      synced = await pushList(c, now, op, now.seat ? 'seat' : 'list');
      renewed = await renewDue(c, op, dev, f.has('--renew'));
      snaps = await pushSnapshots(c, op, dev, true);
    }
  } finally { await c.stop(); }
  out({ list: (readList(op) ?? list).seq, synced, forgot: gone, ...(gone.gave !== undefined && { seat_to: gone.gave }), snapshots: snaps, renewed });
  return 0;
}

// ---------------------------------------------------------------- the page (D4, UI-API.md "Devices")
//
// The same verbs through the page's own carrier (sigelo-agent-ui.ts holds the operator's session, so the
// CLI's carriers would refuse busy). SAFE only: FULL moves the identity and keeper root after "type FULL"
// on a terminal (DEVICES.md), so it stays the CLI's. Online add: the page shows the QR; the enrolment
// request the page's inbox keeps apart (hold) waits until the human answers the four words (confirm),
// then a round (enrol.complete over the held messages) sends the worker and files it. Offline add: the
// frames, then the six words once (words), never in the same answer. Scan (this machine as the device):
// an online code runs as a background job (the giving side asks the words), offline frames are read
// here and the words come typed in the body; the identity goes to the agents' directory. Devices are
// never remote (sigelo-agent-remote.ts deviceRoute).

/** One online add, as GET /api/devices shows it (never a key). */
interface Adding { id: string; name: string; worker: number; did: string; original: string; via: 'online'; qr: string; short: string; exp: number; at: number;
  state: 'code' | 'words' | 'sending' | 'done' | 'refused' | 'expired'; temp?: string; words?: string | null; decision?: boolean; check?: string; detail?: string }
/** This machine joining as a device by an online code (scan). */
interface Joining { state: 'joining' | 'words' | 'done' | 'failed'; file: string; name: string; words: string | null; operator: string | null; did?: string; worker?: number | null; check?: string; message?: string; long?: string; list?: number | null }
export interface DevicePage {
  /** An enrolment message the page's inbox took: kept here (true), never in the history. */
  hold(m: Record<string, unknown>): boolean;
  /** Whether a round has work: an add under way, held messages, a wipe unanswered. */
  busy(): boolean;
  round(): Promise<void>;
  routes: Record<string, (b: Record<string, unknown>) => unknown>;
}
type Fail = Error & { check?: string; status?: number; usage?: boolean };
const no = (status: number, check: string, message: string): never => { throw Object.assign(new Error(message), { check, status }); };
const WORDS_TTL = 600, JOIN_WAIT = 120;

/** The device routes of the page of operator `op`, over its carrier. `seen(did)`: the last time the page heard from that DID; `online()`: its session is up. */
export async function devicePage(o: { op: string; agentsDir: string; carrier: unknown; seen: (did: string) => number | null; online: () => boolean }): Promise<DevicePage> {
  const { op, agentsDir } = o, c = o.carrier as Record<string, any>;
  const dev = await contactModule<Dev>('device'), { lib, enrol } = await libs();
  const adds = new Map<string, Adding>(), words = new Map<string, { words: string; exp: number }>(), wipes = new Set<string>();
  let held: Record<string, unknown>[] = [], joining: Joining | null = null;
  const enrolFile = enrol.enrolPath(op);
  const pub = (a: Adding): object => ({ id: a.id, name: a.name, worker: a.worker, did: a.did, via: a.via, qr: a.qr, short: a.short, exp: a.exp, state: a.state, words: a.words ?? null,
    ...(a.check !== undefined && { check: a.check, detail: a.detail ?? null }) });
  const nameOf = (v: unknown): string => {
    try { return dev.checkName(v) as string; } catch (e) { return no(400, 'body', `name: ${(e as Error).message.replace(/^device_name: /, '')}`); }
  };
  // Refusals as the page answers them: usage → 400, unknown → 404, the rest by their check → 409.
  const call = <T>(fn: () => Promise<T> | T) => async (): Promise<T> => {
    try { return await fn(); } catch (e) {
      const f = e as Fail;
      if (f.status === undefined) {
        if (f.usage) Object.assign(f, { status: 400, check: f.check ?? 'keeper' });
        else if (f.check !== undefined) f.status = ['device_unknown'].includes(f.check) ? 404 : 409;
      }
      if (f.check !== undefined && f.message.startsWith(`${f.check}: `)) f.message = f.message.slice(f.check.length + 2);
      throw f;
    }
  };

  async function list(): Promise<unknown> {
    const { rows, signed } = await rowsOf(op, c);
    look();
    const t = nowS();
    for (const [k, v] of words) if (v.exp <= t) words.delete(k);
    return { devices: rows.map((r) => ({ ...r, seen: o.seen(r.original) })), list: signed ? { seq: signed.seq, iat: signed.iat } : null,
      adding: [...adds.values()].filter((a) => a.state !== 'done' || t - a.at < 3600).map(pub), joining };
  }

  async function add(b: Record<string, unknown>): Promise<unknown> {
    const name = nameOf(b['name']);
    if (b['full'] === true || b['rank'] === 'full') no(409, 'device_full', 'FULL moves your identity and keeper root: only in a terminal, where you type FULL: sigelo-agent device add --name <n> --full');
    if (b['rank'] !== undefined && b['rank'] !== 'safe' && b['rank'] !== 'full') no(400, 'body', 'rank: safe (FULL: in a terminal)');
    const tier = b['tier'], days = b['days'] ?? dev.DEVICE_DAYS, n = b['words'] ?? dev.WORDS_DEFAULT;
    if (tier !== undefined && tier !== 'friend' && tier !== 'quiet') no(400, 'body', 'tier: friend or quiet (own is the default)');
    if (!Number.isSafeInteger(days) || (days as number) < 1 || (days as number) > 90) no(400, 'body', 'days: 1 to 90');
    if (!Number.isSafeInteger(n) || (n as number) < dev.WORDS_MIN || (n as number) > dev.WORDS_MAX) no(400, 'body', `words: ${dev.WORDS_MIN} to ${dev.WORDS_MAX}`);
    if (b['offline'] !== undefined && typeof b['offline'] !== 'boolean') no(400, 'body', 'offline: true or false');
    const k = readKeeper(op);
    checkFree(k, name);
    const { K, recovery } = rootOf(k), i = nextIndex(k), w = enrol.workerChain(K, i, 0, recovery), now = nowS();
    try {
      if (b['offline'] !== true) {
        const r = await enrol.issue({ carrier: c, file: enrolFile, i, n: 0, name, keeper: { K, recovery }, days });
        writeKeeper(op, (x) => { x.workers[i] = { name, n: 0, did: w.did, original: w.original, placed: 'device', rank: 'safe', via: 'online', at: nowS() }; });
        c['presetTier'](w.original, tier ?? 'own');
        const text = dev.onlineText(r.short, c['relay'] === lib.DEFAULT_RELAY ? undefined : c['relay']) as string;
        const a: Adding = { id: r.id, name, worker: i, did: w.did, original: w.original, via: 'online', qr: text, short: r.short, exp: r.short_exp, at: now, state: 'code' };
        adds.set(a.id, a);
        return pub(a);
      }
      // Offline: the material sealed under fresh words; the frames now, the words once by POST /api/devices/words.
      const me = load(op), iss = did(head(me)), ws = dev.makeWords(n) as string;
      const attestation = enrol.operatorAttestation({ sign: signer(op, me).sign, iss, sub: w.original, relay: c['relay'], now, days }) as { body: { exp: number; iat: number }; sig: string };
      const identity = enrol.workerIdentity({ K, i, n: 0, recovery, attestation, issuer: head(me) });
      // Online, its answer topic is claimed now; offline, at the page's next login (local).
      const invite = (await c['invite']({ name, ttl: 7 * 86400, local: !o.online() }) as { code: string }).code;
      c['presetTier'](w.original, tier ?? 'own');
      writeKeeper(op, (x) => { x.workers[i] = { name, n: 0, did: w.did, original: w.original, placed: 'device', rank: 'safe', via: 'offline', at: now, attestation }; });
      const l = bumpList(op, dev, (ds) => [...ds.filter((d) => d.worker !== i), entryFor(op, name, i, w.original, 'safe')]);
      const frames = dev.toFrames(dev.seal(dev.compactSafe({ name, identity, i, n: 0, invite, exp: now + dev.OFFLINE_EXP }), ws), { maxVersion: dev.FRAME_VERSION }) as string[];
      const id = randomBytes(6).toString('hex');
      words.set(id, { words: ws, exp: now + WORDS_TTL });
      return { id, name, worker: i, did: w.did, via: 'offline', frames, list: l.seq, exp: now + 7 * 86400, words_until: now + WORDS_TTL };
    } finally { K.fill(0); }
  }

  /** The words gate (devices.md §5.1, "page: two buttons"). Declined: the enrolment dropped, the code's pairing forgotten. */
  async function confirm(b: Record<string, unknown>): Promise<unknown> {
    if (typeof b['id'] !== 'string' || typeof b['match'] !== 'boolean') no(400, 'body', 'id: an add; match: true or false');
    const a = adds.get(b['id'] as string) ?? no(404, 'device_unknown', 'no such add pending');
    if (a.state !== 'words') no(409, 'device_state', a.state === 'code' ? 'the device has not answered the code yet: no words to compare' : `this add is ${a.state}`);
    a.decision = b['match'] as boolean;
    if (!a.decision) {
      a.state = 'refused'; a.check = 'device_words'; a.detail = 'the words were not confirmed: nothing was sent. If they differed, someone else answered the code: add it again';
      enrol.pending(enrolFile, nowS(), (s) => { delete s.issued[a.id]; });
      writeKeeper(op, (x) => { delete x.workers[a.worker]; });
      held = held.filter((m) => m['from'] !== a.temp);
      try { if (a.temp) await c['forget'](a.temp); } catch {}
    } else await round();
    return pub(a);
  }

  // Who answered each code (its words to compare), and codes dead unanswered.
  function look(): Adding[] {
    const t = nowS(), live = [...adds.values()].filter((a) => a.state === 'code' || a.state === 'words' || a.state === 'sending');
    for (const a of live) {
      if (a.state === 'code') {
        const by = c['answeredBy'](a.id) as string | null;
        if (by) {
          a.temp = by; a.state = 'words';
          a.words = (c['contacts']().contacts as { did: string; fingerprint?: string | null }[]).find((x) => x.did === by)?.fingerprint ?? null;
        } else if (t > a.exp + 30) {
          // The code is dead (10 minutes, once) and nobody answered it: the worker index is free again.
          a.state = 'expired';
          enrol.pending(enrolFile, t, (s) => { delete s.issued[a.id]; });
          writeKeeper(op, (x) => { if (x.workers[a.worker]?.name === a.name) delete x.workers[a.worker]; });
        }
      }
    }
    return live.filter((a) => a.state !== 'expired');
  }

  async function round(): Promise<void> {
    if (wipes.size) for (const n of await onOperator(c, op, dev)) wipes.delete(n);
    const live = look();
    // A request from a code's DID waits for the human's answer; any other goes to enrolment (which refuses it).
    const waiting = (m: Record<string, unknown>): boolean => live.some((a) => a.temp === m['from'] && a.decision === undefined && a.state === 'words');
    const pass = held.filter((m) => !waiting(m));
    held = held.filter(waiting);
    if (!pass.length && !live.some((a) => a.state === 'sending')) return;
    const k = readKeeper(op), { K, recovery } = rootOf(k);
    // The carrier as enrolment sees it: its inbox is what the page kept apart.
    const proxy = new Proxy(c, { get: (x, p) => (p === 'inbox' ? async () => ({ messages: pass.splice(0), events: [], dropped: {} }) : typeof x[p as string] === 'function' ? x[p as string].bind(x) : x[p as string]) });
    let res: Out;
    try {
      res = await enrol.complete({ carrier: proxy, file: enrolFile, keeper: { K, recovery }, wait: 0, confirm: async (x: { id: string }) => adds.get(x.id)?.decision === true });
    } finally { K.fill(0); }
    for (const d of res.delivered) { const a = adds.get(d.id); if (a) a.state = 'sending'; }
    for (const x of res.refused) {
      const a = [...adds.values()].find((y) => y.temp !== undefined && y.temp === x.from);
      if (a && a.state !== 'done') { a.check = x.check; a.detail = x.detail; if (x.check === 'device_words') a.state = 'refused'; }
      else note(`device: ${x.check}: ${x.detail}`);
    }
    for (const p of res.placed) {
      const a = adds.get(p.id);
      if (!a) continue;
      a.state = 'done'; a.at = nowS();
      const l = bumpList(op, dev, (ds) => [...ds.filter((d) => d.worker !== a.worker), entryFor(op, a.name, a.worker, p.original, 'safe')]);
      rmSync(qrPath(op), { force: true });
      await pushList(c, l, op);
    }
  }

  function wordsOnce(b: Record<string, unknown>): unknown {
    const w = typeof b['id'] === 'string' ? words.get(b['id']) : undefined;
    if (!w || w.exp <= nowS()) no(404, 'device_unknown', 'no words wait under this id: they are shown once, within 10 minutes of the frames');
    words.delete(b['id'] as string);
    return { words: w!.words };
  }

  // ---- this machine as the device
  async function scan(b: Record<string, unknown>): Promise<unknown> {
    const raw = b['texts'] ?? (typeof b['text'] === 'string' ? (b['text'] as string).split(/\r?\n/) : undefined);
    if (!Array.isArray(raw) || raw.length === 0 || raw.length > dev.FRAMES_MAX || raw.some((x) => typeof x !== 'string' || x.length > 4096)) no(400, 'body', 'text: the QR\'s text or a code; or texts: the frames read, in any order');
    const texts = (raw as string[]).map((x) => x.trim()).filter(Boolean);
    if (!texts.length) no(400, 'body', 'text: the QR\'s text or a code');
    const name = nameOf(b['name'] ?? 'device'), into = join(agentsDir, `sigelo.${name}.local.json`);
    let read: { kind: string; code?: string; relay?: string | null }[];
    try { read = texts.map((x) => dev.readScan(x)); } catch (e) { return no(400, (e as Fail).check ?? 'scan_text', (e as Error).message.replace(/^scan_text: /, '')); }
    if (existsSync(into)) no(409, 'enrol_exists', `${into} holds an identity: another name`);
    const online = read.find((r) => r.kind !== 'frame');
    if (online) {
      if (read.length > 1) no(400, 'scan_text', 'one online code at a time (an online QR is a single code, not frames)');
      if (joining && (joining.state === 'joining' || joining.state === 'words')) no(409, 'busy', `joining as ${joining.name} already: wait for it`);
      const code = online.code!.slice(0, 4) + '-' + online.code!.slice(4);
      const j: Joining = { state: 'joining', file: into, name, words: null, operator: null };
      joining = j;
      void join_(j, code, online.relay ?? undefined);
      return { kind: 'online', state: j.state, file: into };
    }
    const f = dev.joinFrames(texts);
    if (!f.done) return { kind: 'offline', state: 'frames', have: f.have, count: f.count, missing: f.missing };
    if (b['words'] === undefined) return { kind: 'offline', state: 'words', count: f.count };
    if (typeof b['words'] !== 'string') no(400, 'body', 'words: the words the giving screen shows');
    const material = dev.open(f.container, b['words']);
    const x = dev.rebuild(material as never, { now: nowS() }) as { identity: Store; did: string; original: string; worker: number; operator: string; invite: string; rank: string; full?: unknown };
    if (x.full) no(409, 'device_full', 'these frames hold a FULL device (the operator identity too): read them in a terminal, sigelo-agent device scan --text - (or --image)');
    const wrap = provider(), id = sealed(x.identity, wrap);
    mkdirSync(dirname(into), { recursive: true, mode: 0o700 });
    withLock(into, () => { if (existsSync(into)) refuse('enrol_exists', `${into} appeared meanwhile: nothing written`); save(into, id); });
    save(pendingPath(into), { v: 'sigelo-device-pending/1', invite: x.invite, operator: x.operator } as never);
    const paired = (await finishInvite(into, 20)) === 0;
    return { kind: 'offline', state: 'done', did: x.did, original: x.original, worker: x.worker, operator: x.operator, file: into, provider: wrap ? 'keychain' : 'file', paired };
  }
  // The device side of an online code, as init --enrol: a temporary identity pairs, the four words show
  // here (the giving side asks them), the worker arrives, then the device list.
  async function join_(j: Joining, code: string, relay: string | undefined): Promise<void> {
    const temp = j.file.replace(/\.json$/, '') + `.enrol-${randomBytes(4).toString('hex')}.json`;
    let long: string | undefined;
    try {
      mkdirSync(dirname(j.file), { recursive: true, mode: 0o700 });
      long = await carrierFor(lib, temp).unpark(code, ...(relay ? [{ relay }] : []));
      lib.readCode(long, nowS());
      const t = keygen({ recovery: 'sha256:' + randomBytes(32).toString('hex') });
      save(temp, { v: VERSION, secret: Buffer.from(t.secret).toString('hex'), genesis: t.genesis, rotations: [], attestations: [], issuers: [] } as never);
      const tc = carrierFor(lib, temp);
      let r;
      try { r = await enrol.accept({ carrier: tc, file: enrol.enrolPath(j.file), code: long, name: 'operator', wait: 30, temp }); } finally { await tc.stop(); }
      j.operator = r.did; j.words = r.contact?.fingerprint ?? null; j.state = 'words';
      const res = await runMachine(await libs(), j.file, temp, 'operator', JOIN_WAIT);
      const p = res.placed[0];
      if (!p) {
        const x = res.refused[0];
        Object.assign(j, { state: 'failed', check: x?.check ?? (res.offline !== undefined ? 'offline' : 'enrol_pending'), message: x?.detail ?? res.offline ?? 'not done within 2 minutes: the giving side has not confirmed the words; add the device again' });
        return;
      }
      dropTemp(temp);
      Object.assign(j, { did: p.did, worker: p.worker ?? null, operator: p.operator ?? j.operator });
      const h = await receive(j.file, 20, true);
      j.list = h.list ?? null;
      j.state = 'done';
    } catch (e) {
      const k = long !== undefined && long !== code ? lib.keepLong(e, long) as Fail : e as Fail;
      Object.assign(j, { state: 'failed', check: k.check ?? 'error', message: k.message, ...(long !== undefined && long !== code && { long }) });
    }
  }

  async function revokeR(b: Record<string, unknown>): Promise<unknown> {
    if (typeof b['name'] !== 'string' || (b['lost'] !== undefined && typeof b['lost'] !== 'boolean')) no(400, 'body', 'name: a device; lost: true or false');
    const lost = b['lost'] === true, name = b['name'] as string;
    const { d, list: l, k, forgot, synced } = await revokeStart(op, c, name, lost, dev);
    if (!lost) wipes.add(name);
    return { device: name, rank: d.rank, worker: d.worker, revoked: l.devices.find((x) => x.name === name)!.revoked, lost, wiped: false, forgot, list: l.seq, synced, ...(lost && { steps: stepsOf(op, dev, d, k) }) };
  }
  async function syncR(): Promise<unknown> {
    const l = readList(op) ?? bumpList(op, dev, (ds) => ds), gone = await onOperator(c, op, dev);
    for (const n of gone) wipes.delete(n);
    return { list: l.seq, synced: await pushList(c, l, op), forgot: gone };
  }

  const { LABEL_ENROL } = enrol as unknown as { LABEL_ENROL: string };
  return {
    hold: (m) => { if (m['label'] !== LABEL_ENROL) return false; held.push(m); return true; },
    busy: () => held.length > 0 || wipes.size > 0 || [...adds.values()].some((a) => a.state === 'code' || a.state === 'words' || a.state === 'sending'),
    round: call(round),
    routes: {
      'GET /api/devices': call(list),
      'POST /api/devices/add': (b) => call(() => add(b))(),
      'POST /api/devices/confirm': (b) => call(() => confirm(b))(),
      'POST /api/devices/words': (b) => call(() => wordsOnce(b))(),
      'POST /api/devices/scan': (b) => call(() => scan(b))(),
      'POST /api/devices/revoke': (b) => call(() => revokeR(b))(),
      'POST /api/devices/sync': call(syncR),
    },
  };
}

/** sigelo-agent device …; → the exit code (0 done, 1 refused, 2 usage, 3 pending). */
export async function main(rest: string[]): Promise<number> {
  const [verb, ...args] = rest;
  try {
    if (verb === 'add') return await add(flags(args, ['--name', '--wait', '--tier', '--days', '--png', '--words', '--identity'], ['--offline', '--paged', '--yes-words-checked', '--operator', '--full']));
    if (verb === 'scan') return await scan(args);
    if (verb === 'show-qr') return await showQr(flags(args, ['--png', '--identity'], ['--operator']));
    if (verb === 'list') return await list(flags(args, ['--identity'], ['--json', '--operator']));
    if (verb === 'revoke') { const named = args[0] !== undefined && !args[0].startsWith('--'); return await revoke(named ? args[0] : undefined, flags(named ? args.slice(1) : args, ['--wait', '--identity'], ['--lost', '--operator'])); }
    if (verb === 'sync') return await sync(flags(args, ['--wait', '--identity'], ['--operator', '--renew']));
    if (verb === 'seat') return await seat(args);
    throw usageError(`device: ${JSON.stringify(verb ?? '')} is not a verb (add, scan, show-qr, list, revoke, sync, seat)`);
  } catch (e) { return failed(e); }
}
