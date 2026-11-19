// SPDX-License-Identifier: MIT
/**
 * `sigelo-agent service install | status | remove` (WATCH.md "Always on"): the listener as a service of this
 * machine, so an enrolled agent always gets its owner's messages, whether or not anything else of it runs
 * (0.1.17: "An agent MUST always get the owner messages. This must be app level"). The service runs
 * `sigelo-agent watch --spool <dir> --quiet` for one identity file: it holds the relay session, every own
 * message lands in <dir>/<id>.json, and `inbox` and the MCP `sigelo_inbox` beside it take them from there
 * (sigelo-agent-contact.ts takeSpool) instead of logging in, which would evict it.
 *
 * One unit per identity (2026-11-19): its name carries TAG, 8 hex of the sha256 of the identity file's path,
 * so several identities on one machine each get their own: sigelo-watch-<tag>.service, io.sigelo.watch.<tag>,
 * task sigelo-watch-<tag>. Never two units on one identity (the second crash-loops on its lock): install and remove
 * retire an install of the fixed legacy name (sigelo-watch.service with its sigelo-watch.timer, io.sigelo.watch, task
 * sigelo-watch) when it runs this identity (legacyFor), and leave it, said, when it runs another; status lists every
 * sigelo unit here with its identity and any two that claim one.
 *
 *   Linux    a systemd user unit, ~/.config/systemd/user/sigelo-watch-<tag>.service (Restart=always, RestartSec=15,
 *            after network-online.target, WantedBy=default.target), enabled and started with
 *            `systemctl --user enable --now`; `loginctl enable-linger` keeps it running after you log out
 *   macOS    a LaunchAgent, ~/Library/LaunchAgents/io.sigelo.watch.<tag>.plist (RunAtLoad, KeepAlive), loaded
 *            with `launchctl bootstrap gui/<uid>`
 *   Windows  not automated: the schtasks command to run once (ONLOGON), printed
 *
 * `service install --host claude [--cwd DIR]`: the unit runs `sigelo-agent host claude` instead (sigelo-agent-host.ts: the
 * operator's messages go into a Claude session it holds), in DIR (default: where install ran), PATH kept so
 * the SDK finds `claude`; --dangerously-skip-permissions, --quiet-progress and --others data written into it (host claude's flags).
 *
 * SIGELO_SERVICE_DIR: where the unit or plist is written (tests); SIGELO_SERVICE_DRY=1: nothing is run
 * (no systemctl, launchctl): what would run is printed; SIGELO_SERVICE_OS: linux, darwin or win32 instead of
 * this machine's (tests). Nothing here needs root.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { lockHolder } from './sigelo-agent-contact.ts';
import { notFound, spawnArgs, which } from './sigelo-agent-exec.ts';
import { identityPath } from './sigelo-agent.ts';

/** The legacy fixed names (one identity per machine, before 2026-11-19; TIMER: an early install restarted the
 *  service with it); RESTART_S. */
export const UNIT = 'sigelo-watch.service', TIMER = 'sigelo-watch.timer', LABEL = 'io.sigelo.watch', TASK = 'sigelo-watch', RESTART_S = 15;
/** An identity's tag: 8 hex of the sha256 of its resolved path (no file needed: remove works after it is gone). */
export const tagOf = (identity: string): string => createHash('sha256').update(resolve(identity)).digest('hex').slice(0, 8);
/** An identity's own unit, LaunchAgent label and scheduled task names. */
export const namesOf = (identity: string): { unit: string; label: string; task: string } => {
  const t = tagOf(identity);
  return { unit: `sigelo-watch-${t}.service`, label: `${LABEL}.${t}`, task: `${TASK}-${t}` };
};
const note = (s: string): void => { process.stderr.write(`sigelo-agent: ${s}\n`); };
const say = (s: string): void => { process.stdout.write(`${s}\n`); };

/** What the service runs: node, this CLI, watch for `identity` spooling to `spool`; the environment it keeps. */
export interface Plan { node: string; cli: string; identity: string; spool: string; env: Record<string, string>; host?: 'claude'; cwd?: string; skipPermissions?: boolean; quietProgress?: boolean; others?: 'data' }
// The variables a watcher needs as this shell has them (the relay, the key's provider); never a secret.
const KEPT = ['SIGELO_RELAY', 'SIGELO_RELAY_ENDPOINTS', 'SIGELO_RELAY_TRANSPORT', 'SIGELO_SHORT_RELAY', 'SIGELO_KEY_PROVIDER', 'SIGELO_KEY_AGENT', 'SIGELO_NAME', 'HTTPS_PROXY', 'NO_PROXY'];
export function planFor(identity: string, spool?: string, env: NodeJS.ProcessEnv = process.env, cli = process.argv[1] ?? '', o: { host?: 'claude'; cwd?: string; skipPermissions?: boolean; quietProgress?: boolean; others?: 'data' } = {}): Plan {
  const id = resolve(identity);
  const kept = Object.fromEntries([...KEPT, ...(o.host ? ['PATH'] : [])].filter((k) => typeof env[k] === 'string' && env[k] !== '').map((k) => [k, env[k]!]));
  return { node: process.execPath, cli: resolve(cli), identity: id, spool: resolve(spool ?? `${id.replace(/\.json$/, '')}.spool`), env: { SIGELO_IDENTITY: id, ...kept },
    ...(o.host && { host: o.host, cwd: resolve(o.cwd ?? process.cwd()), ...(o.skipPermissions && { skipPermissions: true }), ...(o.quietProgress && { quietProgress: true }), ...(o.others && { others: o.others }) }) };
}
export const argsOf = (p: Plan): string[] => [p.node, p.cli, ...(p.host ? ['host', p.host] : ['watch']), '--identity', p.identity, '--spool', p.spool, ...(p.host && p.cwd ? ['--cwd', p.cwd] : []), ...(p.host && p.skipPermissions ? ['--dangerously-skip-permissions'] : []), ...(p.host && p.quietProgress ? ['--quiet-progress'] : []), ...(p.host && p.others ? ['--others', p.others] : []), '--quiet'];
const what = (p: Plan): string => (p.host ? `sigelo-agent host ${p.host}` : 'sigelo-agent watch');

// systemd: a word with a space, a quote or a backslash in double quotes, escaped; % doubled (a specifier otherwise).
const sdWord = (w: string): string => { const t = w.replace(/%/g, '%%'); return /[\s"\\]/.test(t) ? `"${t.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"` : t; };
/** The systemd user unit. */
export function unitOf(p: Plan): string {
  return ['[Unit]', `Description=sigelo: receive your owner's messages (${what(p)})`, 'Wants=network-online.target', 'After=network-online.target', '',
    '[Service]', ...Object.entries(p.env).map(([k, v]) => `Environment=${sdWord(`${k}=${v}`)}`), `ExecStart=${argsOf(p).map(sdWord).join(' ')}`,
    'Restart=always', `RestartSec=${RESTART_S}`, '', '[Install]', 'WantedBy=default.target', ''].join('\n');
}
/** A unit read back: its ExecStart words and its Environment, as systemd splits them (the subset unitOf writes). */
export function parseUnit(text: string): { exec: string[]; env: Record<string, string>; restart: string | null; wanted: string | null } {
  const words = (s: string): string[] => {
    const out: string[] = [];
    for (const m of s.matchAll(/"((?:[^"\\]|\\.)*)"|(\S+)/g)) out.push((m[1] !== undefined ? m[1].replace(/\\(.)/g, '$1') : m[2]!).replace(/%%/g, '%'));
    return out;
  };
  const env: Record<string, string> = {};
  let exec: string[] = [], restart: string | null = null, wanted: string | null = null;
  for (const l of text.split('\n')) {
    const m = /^(\w+)=(.*)$/.exec(l);
    if (!m) continue;
    if (m[1] === 'Environment') for (const w of words(m[2]!)) { const i = w.indexOf('='); if (i > 0) env[w.slice(0, i)] = w.slice(i + 1); }
    if (m[1] === 'ExecStart') exec = words(m[2]!);
    if (m[1] === 'Restart') restart = m[2]!;
    if (m[1] === 'WantedBy') wanted = m[2]!;
  }
  return { exec, env, restart, wanted };
}
const xml = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
/** The macOS LaunchAgent. */
export function plistOf(p: Plan, label = namesOf(p.identity).label): string {
  const str = (s: string): string => `<string>${xml(s)}</string>`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key>${str(label)}
  <key>ProgramArguments</key><array>${argsOf(p).map(str).join('')}</array>
  <key>EnvironmentVariables</key><dict>${Object.entries(p.env).map(([k, v]) => `<key>${xml(k)}</key>${str(v)}`).join('')}</dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>${RESTART_S}</integer>
  <key>StandardErrorPath</key>${str(`${p.spool}.log`)}
</dict></plist>
`;
}
/** Windows: the command to run once (not run here: a scheduled task's quoting and rights are the human's to check). */
export const schtasksOf = (p: Plan, task = namesOf(p.identity).task): string => `schtasks /Create /SC ONLOGON /RL LIMITED /TN ${task} /TR "${argsOf(p).map((a) => (/\s/.test(a) ? `\\"${a}\\"` : a)).join(' ')}"`;

const platformOf = (): 'linux' | 'darwin' | 'win32' | 'other' => { const p = process.env['SIGELO_SERVICE_OS'] || process.platform; return ['linux', 'darwin', 'win32'].includes(p) ? p as 'linux' | 'darwin' | 'win32' : 'other'; };
const unxml = (s: string): string => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
/** The program arguments and environment of a written unit or LaunchAgent (null: unreadable). */
function readOf(file: string): { exec: string[]; env: Record<string, string> } | null {
  let t: string;
  try { t = readFileSync(file, 'utf8'); } catch { return null; }
  if (!file.endsWith('.plist')) { const u = parseUnit(t); return { exec: u.exec, env: u.env }; }
  const a = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(t)?.[1] ?? '', e = /<key>EnvironmentVariables<\/key>\s*<dict>([\s\S]*?)<\/dict>/.exec(t)?.[1] ?? '';
  return { exec: [...a.matchAll(/<string>([\s\S]*?)<\/string>/g)].map((m) => unxml(m[1]!)),
    env: Object.fromEntries([...e.matchAll(/<key>([\s\S]*?)<\/key>\s*<string>([\s\S]*?)<\/string>/g)].map((m) => [unxml(m[1]!), unxml(m[2]!)])) };
}
/** The identity file a unit runs: its --identity, else its SIGELO_IDENTITY, else the default one (as sigelo-agent picks it
 *  for this user; an early install ran watch without --identity). null: no program arguments to read. */
export function identityOfRun(exec: string[], env: Record<string, string>): string | null {
  if (exec.length === 0) return null;
  const i = exec.indexOf('--identity');
  if (i >= 0 && exec[i + 1]) return resolve(exec[i + 1]!);
  return resolve(identityPath({ HOME: process.env['HOME'], XDG_CONFIG_HOME: process.env['XDG_CONFIG_HOME'], ...env }));
}
/** One identity file however its path is spelled (a symlink, a relative path): its real path when it exists. */
const keyOf = (p: string): string => { try { return realpathSync(p); } catch { return resolve(p); } };
const same = (a: string | null, b: string): boolean => a !== null && keyOf(a) === keyOf(b);
const runsOf = (x: string[]): string => (x[2] === 'host' ? `host ${x[3] ?? ''}`.trim() : x[2] ?? '');

export interface Unit { name: string; file: string; identity: string | null; runs: string; legacy: boolean; timer?: string }
/** Every sigelo unit (or LaunchAgent) in dir: its name, file, identity, what it runs, legacy or per identity; the legacy
 *  systemd service with its timer (sigelo-watch.timer, which an early install used to restart it) when that is there. */
export function unitsIn(dir: string, os: string): Unit[] {
  const re = os === 'darwin' ? /^io\.sigelo\.watch(\.[0-9a-f]{8})?\.plist$/ : /^sigelo-watch(-[0-9a-f]{8})?\.service$/;
  let names: string[] = [];
  try { names = readdirSync(dir).filter((f) => re.test(f)).sort(); } catch { return []; }
  return names.map((f) => {
    const r = readOf(join(dir, f)), legacy = !re.exec(f)![1];
    return { name: os === 'darwin' ? f.replace(/\.plist$/, '') : f, file: join(dir, f), identity: r ? identityOfRun(r.exec, r.env) : null, runs: runsOf(r?.exec ?? []), legacy,
      ...(legacy && os === 'linux' && existsSync(join(dir, TIMER)) && { timer: TIMER }) };
  });
}
/** This identity's own unit (always its per-identity name; a legacy install is retired, not reused). */
export function unitFor(dir: string, os: string, identity: string): { name: string; file: string } {
  const n = namesOf(identity);
  return os === 'darwin' ? { name: n.label, file: join(dir, `${n.label}.plist`) } : { name: n.unit, file: join(dir, n.unit) };
}
/** The units of `units` that claim one identity file between them (more than one: a conflict, the later ones crash-loop on its lock). */
export function conflictsOf(units: { name: string; identity: string | null }[]): { identity: string; units: string[] }[] {
  const by = new Map<string, { identity: string; units: string[] }>();
  for (const u of units) if (u.identity !== null) { const k = keyOf(u.identity), g = by.get(k) ?? { identity: u.identity, units: [] }; g.units.push(u.name); by.set(k, g); }
  return [...by.values()].filter((g) => g.units.length > 1);
}
const dirFor = (os: string): string => process.env['SIGELO_SERVICE_DIR'] || (os === 'darwin' ? join(homedir(), 'Library', 'LaunchAgents') : join(process.env['XDG_CONFIG_HOME'] || join(homedir(), '.config'), 'systemd', 'user'));
const dry = (): boolean => process.env['SIGELO_SERVICE_DRY'] === '1';
function run(cmd: string, args: string[]): { ok: boolean; out: string } {
  if (dry()) { note(`(dry run) ${[cmd, ...args].join(' ')}`); return { ok: true, out: '' }; }
  const f = which(cmd);
  if (f === null) return { ok: false, out: `${cmd} is not on this machine's PATH` };
  const a = spawnArgs(f, args), r = spawnSync(a.cmd, a.args, { encoding: 'utf8', shell: a.shell });
  if (notFound(r.status, r.error as { code?: string } | undefined)) return { ok: false, out: `${cmd} is not on this machine's PATH` };
  return { ok: r.status === 0, out: `${r.stdout ?? ''}${r.stderr ?? ''}`.trim() || (r.error?.message ?? '') };
}
/** A read-only question to systemctl, launchctl or schtasks: its output, '' when it fails or in a dry run (nothing run). */
const ask = (cmd: string, args: string[]): string => { if (dry()) return ''; const r = run(cmd, args); return r.ok ? r.out : ''; };

/** The legacy install (fixed names, before one unit per identity) and whether it runs `identity`. mine: its unit, plist or
 *  task names this identity file (by --identity, SIGELO_IDENTITY or the default path), or, its file not found, systemd
 *  says its main process is the one holding this identity's lock. null: no legacy install here. */
export interface Legacy { names: string[]; files: string[]; identity: string | null; mine: boolean }
export function legacyFor(dir: string, os: string, identity: string): Legacy | null {
  if (os === 'linux') {
    const where = (n: string): string | null => { if (existsSync(join(dir, n))) return join(dir, n); const f = ask('systemctl', ['--user', 'show', '-p', 'FragmentPath', '--value', n]).split('\n')[0]!.trim(); return f && existsSync(f) ? f : null; };
    const svc = where(UNIT), tmr = where(TIMER);
    if (svc === null && tmr === null) return null;
    const r = svc ? readOf(svc) : null, id = r ? identityOfRun(r.exec, r.env) : null;
    let mine = same(id, identity);
    if (id === null) { const h = lockHolder(identity), pid = ask('systemctl', ['--user', 'show', '-p', 'MainPID', '--value', UNIT]).trim(); mine = h !== null && pid === String(h.pid); }
    return { names: [...(tmr ? [TIMER] : []), UNIT], files: [tmr, svc].filter((f): f is string => f !== null), identity: id, mine };
  }
  if (os === 'darwin') {
    const f = join(dir, `${LABEL}.plist`);
    if (!existsSync(f)) return null;
    const r = readOf(f), id = r ? identityOfRun(r.exec, r.env) : null;
    return { names: [LABEL], files: [f], identity: id, mine: same(id, identity) };
  }
  if (os !== 'win32') return null;
  const x = ask('schtasks', ['/Query', '/TN', TASK, '/XML']);
  if (!x.includes('<Exec>')) return null;
  const words = (s: string): string[] => [...s.matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? m[2]!);
  const exec = [...words(unxml(/<Command>([\s\S]*?)<\/Command>/.exec(x)?.[1] ?? '')), ...words(unxml(/<Arguments>([\s\S]*?)<\/Arguments>/.exec(x)?.[1] ?? ''))];
  const id = identityOfRun(exec, {});
  return { names: [TASK], files: [], identity: id, mine: same(id, identity) };
}

export const USAGE = `service install [--spool <dir>] [--host claude [--cwd <dir>] [--dangerously-skip-permissions] [--quiet-progress] [--others data]] | service status | service remove
      the listener as a service of this machine, one per identity (systemd user unit sigelo-watch-<tag>; macOS LaunchAgent;
      Windows: the step printed): sigelo-agent watch --spool <dir> --quiet for this identity, restarted always; inbox and
      the MCP read its spool; --host claude: it runs host claude instead (a Claude session in <dir>, default here, fed the
      operator's messages); an earlier sigelo-watch (and its timer) running this identity is retired; status lists every
      sigelo unit here and any two that claim one identity`;

/** sigelo-agent service …; → the exit code. */
export async function main(path: string, rest: string[]): Promise<number> {
  const [sub, ...more] = rest, os = platformOf();
  const f: Record<string, string> = {};
  let skip = false, quietProgress = false;
  for (let i = 0; i < more.length; i += 2) {
    const k = more[i]!, v = more[i + 1];
    if (k === '--dangerously-skip-permissions' && sub === 'install' && !skip) { skip = true; i--; continue; }
    if (k === '--quiet-progress' && sub === 'install' && !quietProgress) { quietProgress = true; i--; continue; }
    if (!['--spool', '--host', '--cwd', '--others'].includes(k) || v === undefined || f[k] !== undefined || sub !== 'install') { note(`usage: ${USAGE}`); return 2; }
    f[k] = v;
  }
  if (!['install', 'status', 'remove'].includes(sub ?? '') || (f['--host'] !== undefined && f['--host'] !== 'claude') || (f['--others'] !== undefined && !['spool', 'data'].includes(f['--others']))
    || ((f['--cwd'] !== undefined || f['--others'] !== undefined || skip || quietProgress) && f['--host'] === undefined)) { note(`usage: ${USAGE}`); return 2; }
  const p = planFor(path, f['--spool'], process.env, process.argv[1] ?? '', f['--host'] ? { host: 'claude', cwd: f['--cwd'], skipPermissions: skip, quietProgress, ...(f['--others'] === 'data' && { others: 'data' as const }) } : {}), dir = dirFor(os);
  const u = unitFor(dir, os, p.identity), n = namesOf(p.identity), uid = process.getuid?.() ?? 0;
  const short = u.name.replace(/\.service$/, '');
  // Never two units on one identity: the legacy install when it runs this identity, and any other per-identity unit
  // naming this same file (another spelling of its path), are stopped, disabled and removed; one line says so.
  const stop = (name: string): void => { if (os === 'linux') run('systemctl', ['--user', 'disable', '--now', name]); else if (os === 'darwin') run('launchctl', ['bootout', `gui/${uid}/${name}`]); };
  const drop = (file: string): void => { try { rmSync(file, { force: true }); } catch (e) { note(`service: ${file} could not be removed (${(e as Error).message}); it is stopped and disabled`); } };
  const retireOthers = (): string[] => {
    const out: string[] = [], L = legacyFor(dir, os, p.identity);
    if (L) {
      if (L.mine) { for (const x of L.names) stop(x); for (const x of L.files) drop(x); say(`retired the earlier ${L.names.join(' and ')} (${L.identity ?? 'its main process holds this identity'}): stopped, disabled, removed`); out.push(...L.names); }
      else say(`left the earlier ${L.names.join(' and ')}: ${L.identity ? `it runs another identity (${L.identity})` : `which identity it runs is not known here; if it is this one, stop it: ${os === 'linux' ? `systemctl --user disable --now ${L.names.join(' ')}` : `launchctl bootout gui/${uid}/${LABEL}`}`}`);
    }
    if (os === 'linux' || os === 'darwin') for (const x of unitsIn(dir, os)) if (!x.legacy && x.file !== u.file && same(x.identity, p.identity)) { stop(x.name); drop(x.file); say(`retired ${x.name}: it ran this identity under another spelling of its path (${x.identity})`); out.push(x.name); }
    return out;
  };
  if (sub === 'install') {
    if (!existsSync(p.identity)) { note(`service: no identity at ${p.identity}: enrol or init first`); return 2; }
    // --host claude: without the SDK the unit still runs (host keeps the listener, the operator told why); said here.
    if (p.host) try { await (await import('./sigelo-agent-host.ts')).loadSdk(); } catch (e) { note(`service: ${(e as Error).message}; the unit runs all the same: until the SDK is there, host claude keeps the listener and tells the operator why`); }
    mkdirSync(p.spool, { recursive: true, mode: 0o700 });
    if (os === 'win32' || os === 'other') {
      const L = legacyFor(dir, os, p.identity);
      if (L?.mine) say(`First retire the earlier task ${TASK}, it runs this identity: schtasks /End /TN ${TASK}, then schtasks /Delete /TN ${TASK} /F`);
      else if (L) say(`The earlier task ${TASK} is left: ${L.identity ? `it runs another identity (${L.identity})` : 'which identity it runs is not known here'}`);
      say(`Run this once in a terminal (it starts the listener at each logon), then sign out and in:\n  ${schtasksOf(p, n.task)}`);
      say(`Set SIGELO_IDENTITY=${p.identity} for that task if your setup needs it. Check: schtasks /Query /TN ${n.task}`);
      return 0;
    }
    mkdirSync(dir, { recursive: true });
    retireOthers();
    const what_ = `${what(p)}${p.skipPermissions ? ' --dangerously-skip-permissions' : ''}${p.quietProgress ? ' --quiet-progress' : ''}${p.others ? ` --others ${p.others}` : ''}`;
    const again = existsSync(u.file);
    if (os === 'linux') {
      writeFileSync(u.file, unitOf(p), { mode: 0o644 });
      say(`wrote ${u.file}: ${what_} for ${p.identity}, own messages ${p.host ? `from the operator into the session, the others to` : 'to'} ${p.spool}`);
      const a = run('systemctl', ['--user', 'daemon-reload']), b = a.ok ? run('systemctl', ['--user', 'enable', '--now', u.name]) : a;
      if (!b.ok) { note(`service: systemctl --user did not take it (${b.out}): the unit is written; start it with systemctl --user enable --now ${u.name}`); return 1; }
      // Installed again (a running unit keeps its old ExecStart): restarted, the new one from now on.
      if (again) run('systemctl', ['--user', 'restart', u.name]);
      say(`enabled and started (systemctl --user enable --now ${u.name}).`);
      say(`Check: systemctl --user status ${short}; its log: journalctl --user -u ${short}`);
      say(`To keep it running after you log out (a server): loginctl enable-linger ${process.env['USER'] ?? '$USER'}`);
      return 0;
    }
    writeFileSync(u.file, plistOf(p, u.name), { mode: 0o644 });
    say(`wrote ${u.file}: ${what_} for ${p.identity}, own messages ${p.host ? `from the operator into the session, the others to` : 'to'} ${p.spool}`);
    if (again) run('launchctl', ['bootout', `gui/${uid}/${u.name}`]);
    const r = run('launchctl', ['bootstrap', `gui/${uid}`, u.file]);
    if (!r.ok) { note(`service: launchctl did not load it (${r.out}): load it with launchctl bootstrap gui/${uid} ${u.file}`); return 1; }
    say(`loaded (launchctl bootstrap gui/${uid}). Check: launchctl print gui/${uid}/${u.name}`);
    return 0;
  }
  if (sub === 'status') {
    const h = lockHolder(p.identity);
    const activeOf = (name: string): string | boolean => {
      const st = os === 'linux' ? run('systemctl', ['--user', 'is-active', name]) : os === 'darwin' ? run('launchctl', ['print', `gui/${uid}/${name}`]) : { ok: false, out: '' };
      return os === 'linux' ? st.out.split('\n')[0] || (st.ok ? 'active' : 'inactive') : st.ok;
    };
    let units: (Unit & { active?: string | boolean; mine: boolean })[] = [];
    if (os === 'linux' || os === 'darwin') {
      units = unitsIn(dir, os).map((x) => ({ ...x, active: activeOf(x.name), mine: same(x.identity, p.identity) }));
      // The legacy service's file elsewhere, or a timer alone: listed too (legacyFor finds them through systemd).
      const L = units.some((x) => x.legacy) ? null : legacyFor(dir, os, p.identity);
      if (L) units.push({ name: os === 'linux' ? UNIT : LABEL, file: L.files.find((x) => !x.endsWith('.timer')) ?? '', identity: L.identity, runs: '', legacy: true, ...(L.names.includes(TIMER) && { timer: TIMER }), active: activeOf(os === 'linux' ? UNIT : LABEL), mine: L.mine });
    } else for (const t of [TASK, n.task]) {
      const x = ask('schtasks', ['/Query', '/TN', t, '/XML']);
      if (!x.includes('<Exec>')) continue;
      const L = t === TASK ? legacyFor(dir, os, p.identity) : null, args = unxml(/<Arguments>([\s\S]*?)<\/Arguments>/.exec(x)?.[1] ?? '');
      const id = L ? L.identity : (/--identity\s+(?:"([^"]*)"|(\S+))/.exec(args)?.slice(1).find(Boolean) ?? null);
      units.push({ name: t, file: '', identity: id, runs: /\bhost claude\b/.test(args) ? 'host claude' : 'watch', legacy: t === TASK, mine: same(id, p.identity) });
    }
    const conflicts = conflictsOf(units);
    const listening = h?.kind === 'watch';
    const mine = units.find((x) => x.name === u.name || x.name === n.task);
    say(JSON.stringify({ installed: os === 'win32' || os === 'other' ? !!mine : existsSync(u.file), unit: os === 'win32' || os === 'other' ? n.task : u.name, file: u.file, active: mine ? mine.active ?? null : os === 'linux' || os === 'darwin' ? activeOf(u.name) : null,
      listening, pid: listening ? h.pid : null, spool: h?.spool ?? null, units, conflicts }, null, 2));
    for (const c of conflicts) note(`service: conflict: ${c.units.join(' and ')} all run ${c.identity}; one holds it, the others crash-loop on its lock. sigelo-agent service install for it keeps one (its own unit) and retires the rest`);
    if (!listening) note(`service: no watcher holds ${p.identity} now: your owner's messages wait at the relay until one runs (sigelo-agent service install)`);
    return listening ? 0 : 3;
  }
  // remove: this identity's unit, the legacy one (and its timer) when it runs this identity, any other unit naming it.
  if (os === 'linux' || os === 'darwin') {
    stop(u.name);
    const had = existsSync(u.file);
    rmSync(u.file, { force: true });
    const others = retireOthers();
    if (os === 'linux') run('systemctl', ['--user', 'daemon-reload']);
    say(had ? `removed ${u.file}; the listener stopped.` : others.length ? `no ${os === 'linux' ? 'unit' : 'LaunchAgent'} of its own name for ${p.identity} (${u.file}).` : `no ${os === 'linux' ? 'unit' : 'LaunchAgent'} for ${p.identity} here (${u.file}); nothing removed.`);
  } else {
    const L = legacyFor(dir, os, p.identity);
    say(`Run once: schtasks /Delete /TN ${n.task} /F${L?.mine ? `; the earlier task runs this identity too: schtasks /End /TN ${TASK}, then schtasks /Delete /TN ${TASK} /F` : L ? ` (the earlier task ${TASK} is left: ${L.identity ? `it runs another identity (${L.identity})` : 'which identity it runs is not known here'})` : ''}`);
  }
  return 0;
}
