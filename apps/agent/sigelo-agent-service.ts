// SPDX-License-Identifier: MIT
/**
 * `sigelo-agent service install | status | remove` (WATCH.md "Always on"): the listener as a service of this
 * machine, so an enrolled agent always gets its owner's messages, whether or not anything else of it runs
 * (0.1.17: "An agent MUST always get the owner messages. This must be app level"). The service runs
 * `sigelo-agent watch --spool <dir> --quiet` for one identity file: it holds the relay session, every own
 * message lands in <dir>/<id>.json, and `inbox` and the MCP `sigelo_inbox` beside it take them from there
 * (sigelo-agent-contact.ts takeSpool) instead of logging in, which would evict it.
 *
 *   Linux    a systemd user unit, ~/.config/systemd/user/sigelo-watch.service (Restart=always, RestartSec=15,
 *            after network-online.target, WantedBy=default.target), enabled and started with
 *            `systemctl --user enable --now`; `loginctl enable-linger` keeps it running after you log out
 *   macOS    a LaunchAgent, ~/Library/LaunchAgents/io.sigelo.watch.plist (RunAtLoad, KeepAlive), loaded
 *            with `launchctl bootstrap gui/<uid>`
 *   Windows  not automated: the schtasks command to run once (ONLOGON), printed
 *
 * `service install --host claude [--cwd DIR]`: the unit runs `sigelo-agent host claude` instead (sigelo-agent-host.ts: the
 * operator's messages go into a Claude session it holds), in DIR (default: where install ran), PATH kept so
 * the SDK finds `claude`.
 *
 * SIGELO_SERVICE_DIR: where the unit or plist is written (tests); SIGELO_SERVICE_DRY=1: nothing is run
 * (no systemctl, launchctl): what would run is printed. Nothing here needs root.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { lockHolder } from './sigelo-agent-contact.ts';

export const UNIT = 'sigelo-watch.service', LABEL = 'io.sigelo.watch', TASK = 'sigelo-watch', RESTART_S = 15;
const note = (s: string): void => { process.stderr.write(`sigelo-agent: ${s}\n`); };
const say = (s: string): void => { process.stdout.write(`${s}\n`); };

/** What the service runs: node, this CLI, watch for `identity` spooling to `spool`; the environment it keeps. */
export interface Plan { node: string; cli: string; identity: string; spool: string; env: Record<string, string>; host?: 'claude'; cwd?: string }
// The variables a watcher needs as this shell has them (the relay, the key's provider); never a secret.
const KEPT = ['SIGELO_RELAY', 'SIGELO_RELAY_ENDPOINTS', 'SIGELO_RELAY_TRANSPORT', 'SIGELO_SHORT_RELAY', 'SIGELO_KEY_PROVIDER', 'SIGELO_KEY_AGENT', 'SIGELO_NAME', 'HTTPS_PROXY', 'NO_PROXY'];
export function planFor(identity: string, spool?: string, env: NodeJS.ProcessEnv = process.env, cli = process.argv[1] ?? '', o: { host?: 'claude'; cwd?: string } = {}): Plan {
  const id = resolve(identity);
  const kept = Object.fromEntries([...KEPT, ...(o.host ? ['PATH'] : [])].filter((k) => typeof env[k] === 'string' && env[k] !== '').map((k) => [k, env[k]!]));
  return { node: process.execPath, cli: resolve(cli), identity: id, spool: resolve(spool ?? `${id.replace(/\.json$/, '')}.spool`), env: { SIGELO_IDENTITY: id, ...kept },
    ...(o.host && { host: o.host, cwd: resolve(o.cwd ?? process.cwd()) }) };
}
export const argsOf = (p: Plan): string[] => [p.node, p.cli, ...(p.host ? ['host', p.host] : ['watch']), '--identity', p.identity, '--spool', p.spool, ...(p.host && p.cwd ? ['--cwd', p.cwd] : []), '--quiet'];
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
export function plistOf(p: Plan): string {
  const str = (s: string): string => `<string>${xml(s)}</string>`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key>${str(LABEL)}
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
export const schtasksOf = (p: Plan): string => `schtasks /Create /SC ONLOGON /RL LIMITED /TN ${TASK} /TR "${argsOf(p).map((a) => (/\s/.test(a) ? `\\"${a}\\"` : a)).join(' ')}"`;

const platformOf = (): 'linux' | 'darwin' | 'win32' | 'other' => (['linux', 'darwin', 'win32'].includes(process.platform) ? process.platform as 'linux' | 'darwin' | 'win32' : 'other');
const dirFor = (os: string): string => process.env['SIGELO_SERVICE_DIR'] || (os === 'darwin' ? join(homedir(), 'Library', 'LaunchAgents') : join(process.env['XDG_CONFIG_HOME'] || join(homedir(), '.config'), 'systemd', 'user'));
const dry = (): boolean => process.env['SIGELO_SERVICE_DRY'] === '1';
function run(cmd: string, args: string[]): { ok: boolean; out: string } {
  if (dry()) { note(`(dry run) ${[cmd, ...args].join(' ')}`); return { ok: true, out: '' }; }
  const r = spawnSync(cmd, args, { encoding: 'utf8' });
  return { ok: r.status === 0, out: `${r.stdout ?? ''}${r.stderr ?? ''}`.trim() || (r.error?.message ?? '') };
}

export const USAGE = `service install [--spool <dir>] [--host claude [--cwd <dir>]] | service status | service remove
      the listener as a service of this machine (systemd user unit; macOS LaunchAgent; Windows: the step printed):
      sigelo-agent watch --spool <dir> --quiet for this identity, restarted always; inbox and the MCP read its spool;
      --host claude: it runs host claude instead (a Claude session in <dir>, default here, fed the operator's messages)`;

/** sigelo-agent service …; → the exit code. */
export async function main(path: string, rest: string[]): Promise<number> {
  const [sub, ...more] = rest, os = platformOf();
  const f: Record<string, string> = {};
  for (let i = 0; i < more.length; i += 2) {
    const k = more[i]!, v = more[i + 1];
    if (!['--spool', '--host', '--cwd'].includes(k) || v === undefined || f[k] !== undefined || sub !== 'install') { note(`usage: ${USAGE}`); return 2; }
    f[k] = v;
  }
  if (!['install', 'status', 'remove'].includes(sub ?? '') || (f['--host'] !== undefined && f['--host'] !== 'claude') || (f['--cwd'] !== undefined && f['--host'] === undefined)) { note(`usage: ${USAGE}`); return 2; }
  const p = planFor(path, f['--spool'], process.env, process.argv[1] ?? '', f['--host'] ? { host: 'claude', cwd: f['--cwd'] } : {}), dir = dirFor(os);
  if (sub === 'install') {
    if (!existsSync(p.identity)) { note(`service: no identity at ${p.identity}: enrol or init first`); return 2; }
    // --host claude: the SDK must load here, before a unit that would fail at each restart is written.
    if (p.host) try { await (await import('./sigelo-agent-host.ts')).loadSdk(); } catch (e) { note(`service: ${(e as Error).message}`); return 1; }
    mkdirSync(p.spool, { recursive: true, mode: 0o700 });
    if (os === 'win32' || os === 'other') {
      say(`Run this once in a terminal (it starts the listener at each logon), then sign out and in:\n  ${schtasksOf(p)}`);
      say(`Set SIGELO_IDENTITY=${p.identity} for that task if your setup needs it. Check: schtasks /Query /TN ${TASK}`);
      return 0;
    }
    mkdirSync(dir, { recursive: true });
    if (os === 'linux') {
      const f = join(dir, UNIT);
      writeFileSync(f, unitOf(p), { mode: 0o644 });
      say(`wrote ${f}: ${what(p)} for ${p.identity}, own messages ${p.host ? `from the operator into the session, the others to` : 'to'} ${p.spool}`);
      const a = run('systemctl', ['--user', 'daemon-reload']), b = a.ok ? run('systemctl', ['--user', 'enable', '--now', UNIT]) : a;
      if (!b.ok) { note(`service: systemctl --user did not take it (${b.out}): the unit is written; start it with systemctl --user enable --now ${UNIT}`); return 1; }
      say(`enabled and started (systemctl --user enable --now ${UNIT}).`);
      say(`Check: systemctl --user status ${UNIT.replace('.service', '')}; its log: journalctl --user -u ${UNIT.replace('.service', '')}`);
      say(`To keep it running after you log out (a server): loginctl enable-linger ${process.env['USER'] ?? '$USER'}`);
      return 0;
    }
    const f = join(dir, `${LABEL}.plist`);
    writeFileSync(f, plistOf(p), { mode: 0o644 });
    say(`wrote ${f}: ${what(p)} for ${p.identity}, own messages ${p.host ? `from the operator into the session, the others to` : 'to'} ${p.spool}`);
    const uid = process.getuid?.() ?? 0;
    const r = run('launchctl', ['bootstrap', `gui/${uid}`, f]);
    if (!r.ok) { note(`service: launchctl did not load it (${r.out}): load it with launchctl bootstrap gui/${uid} ${f}`); return 1; }
    say(`loaded (launchctl bootstrap gui/${uid}). Check: launchctl print gui/${uid}/${LABEL}`);
    return 0;
  }
  if (sub === 'status') {
    const f = join(dir, os === 'darwin' ? `${LABEL}.plist` : UNIT), h = lockHolder(p.identity);
    const st = os === 'linux' ? run('systemctl', ['--user', 'is-active', UNIT]) : os === 'darwin' ? run('launchctl', ['print', `gui/${process.getuid?.() ?? 0}/${LABEL}`]) : { ok: false, out: '' };
    const listening = h?.kind === 'watch';
    say(JSON.stringify({ installed: existsSync(f), file: f, active: os === 'linux' ? st.out.split('\n')[0] || (st.ok ? 'active' : 'inactive') : st.ok, listening, pid: listening ? h.pid : null, spool: h?.spool ?? null }, null, 2));
    if (!listening) note(`service: no watcher holds ${p.identity} now: your owner's messages wait at the relay until one runs (sigelo-agent service install)`);
    return listening ? 0 : 3;
  }
  // remove
  if (os === 'linux') {
    const f = join(dir, UNIT);
    run('systemctl', ['--user', 'disable', '--now', UNIT]);
    rmSync(f, { force: true });
    run('systemctl', ['--user', 'daemon-reload']);
    say(`removed ${f}; the listener stopped.`);
  } else if (os === 'darwin') {
    const f = join(dir, `${LABEL}.plist`);
    run('launchctl', ['bootout', `gui/${process.getuid?.() ?? 0}/${LABEL}`]);
    rmSync(f, { force: true });
    say(`removed ${f}; the listener stopped.`);
  } else say(`Run once: schtasks /Delete /TN ${TASK} /F`);
  return 0;
}
