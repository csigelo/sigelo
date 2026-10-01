#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// kit/drill/schedule.mjs — the drill cadence, offline.
//
//   sigelo-kit-drill install --dir <drills dir> [--every quarterly] [--at 09:00] [--kit kit.json]
//                            [--units-dir <dir>] [--dry-run]
//       writes sigelo-drill-reminder.timer + .service (systemd --user; default units dir
//       ~/.config/systemd/user) and <drills dir>/crontab.line, the cron alternative. It never runs
//       systemctl or crontab: it prints the one command that enables what it wrote.
//       --dry-run prints the files instead of writing them.
//   sigelo-kit-drill new --dir <drills dir> [--date YYYY-MM-DD] [--kind tabletop|stagenet|live] [--kit kit.json]
//       creates <drills dir>/<date>/TIMELINE.md from the template, the step table pre-filled.
//       Refuses to overwrite an existing timeline.
//   sigelo-kit-drill remind --dir <drills dir> [--every quarterly] [--kit kit.json]
//       what the timer runs: creates today's timeline (kind tabletop) if absent, writes
//       <drills dir>/NEXT with the following drill's date, and says so on stdout, to syslog
//       (`logger`) and as a desktop notification (`notify-send`) where those exist.
//   sigelo-kit-drill next [--every quarterly] [--from YYYY-MM-DD]
//
// --every: monthly, quarterly (default), semiannually or yearly — systemd's own calendar
// shorthands, the 1st of the period at --at local time. A yearly stagenet drill is the
// recommended minimum on top of quarterly tabletops (DRILL.md).
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SELF = fileURLToPath(import.meta.url);
const HERE = dirname(SELF);
export const CADENCE = {
  monthly: { months: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], cal: '*-*-01', cron: '*' },
  quarterly: { months: [1, 4, 7, 10], cal: '*-01,04,07,10-01', cron: '1,4,7,10' },
  semiannually: { months: [1, 7], cal: '*-01,07-01', cron: '1,7' },
  yearly: { months: [1], cal: '*-01-01', cron: '1' },
};

/** The first day of the next period strictly after `from` (YYYY-MM-DD, UTC date arithmetic). */
export function nextDrill(every, from) {
  const c = CADENCE[every];
  if (!c) throw new Error(`--every must be one of ${Object.keys(CADENCE).join(', ')}`);
  const [y, m, d] = from.split('-').map(Number);
  for (let k = 0; k < 25; k++) {
    const mm = ((m - 1 + k) % 12) + 1, yy = y + Math.floor((m - 1 + k) / 12);
    if (c.months.includes(mm) && (k > 0 || d < 1)) return `${yy}-${String(mm).padStart(2, '0')}-01`;
  }
  throw new Error('unreachable');
}

export function units({ dir, every, at, kit, node = process.execPath, script = SELF }) {
  const c = CADENCE[every];
  if (!c) throw new Error(`--every must be one of ${Object.keys(CADENCE).join(', ')}`);
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(at)) throw new Error('--at must be HH:MM');
  const dq = (s) => `"${s.replace(/(["\\])/g, '\\$1')}"`, sq = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
  const args = ['remind', '--dir', dir, '--every', every, ...(kit ? ['--kit', kit] : [])];
  const timer = `# sigelo recovery kit — drill reminder (${every}). Written by schedule.mjs install.
[Unit]
Description=sigelo recovery kit: drill reminder (${every})

[Timer]
OnCalendar=${c.cal} ${at}:00
Persistent=true

[Install]
WantedBy=timers.target
`;
  const service = `# sigelo recovery kit — creates the next drill timeline and reminds the operator. Offline; sends nothing.
[Unit]
Description=sigelo recovery kit: create the drill timeline and remind the operator

[Service]
Type=oneshot
ExecStart=${[node, script, ...args].map(dq).join(' ')}
`;
  const [hh, mi] = at.split(':').map(Number);
  const cron = `${mi} ${hh} 1 ${c.cron} * ${[node, script, ...args].map(sq).join(' ')}   # sigelo recovery kit: drill reminder (${every})\n`;
  return { timer, service, cron };
}

const kitOf = (p) => (p ? JSON.parse(readFileSync(p, 'utf8')) : {});

export function newTimeline({ dir, date, kind = 'tabletop', kit }) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('--date must be YYYY-MM-DD');
  if (!['tabletop', 'stagenet', 'live'].includes(kind)) throw new Error('--kind must be tabletop, stagenet or live');
  const f = join(dir, date, 'TIMELINE.md');
  if (existsSync(f)) return { file: f, created: false };
  const k = kitOf(kit);
  const text = readFileSync(join(HERE, 'TIMELINE.template.md'), 'utf8')
    .replaceAll('{{installation}}', k.installation ?? '<installation>').replaceAll('{{date}}', date).replaceAll('{{kind}}', kind);
  mkdirSync(dirname(f), { recursive: true, mode: 0o700 });
  writeFileSync(f, text, { flag: 'wx', mode: 0o600 });
  return { file: f, created: true };
}

const today = () => new Date().toISOString().slice(0, 10);

function main(argv) {
  const [cmd, ...a] = argv;
  const opt = (n, d) => { const i = a.indexOf(n); return i < 0 ? d : a[i + 1]; };
  const dir = opt('--dir') && resolve(opt('--dir'));
  const kit = opt('--kit') && resolve(opt('--kit'));
  const every = opt('--every', 'quarterly');
  if (cmd === 'next') { console.log(nextDrill(every, opt('--from', today()))); return 0; }
  if (!dir || !['install', 'new', 'remind'].includes(cmd)) {
    console.error('usage: sigelo-kit-drill install|new|remind --dir <drills dir> [...] | next [--every e] [--from date]  (see the header of drill/schedule.mjs)');
    return 2;
  }
  if (cmd === 'new') {
    const r = newTimeline({ dir, date: opt('--date', today()), kind: opt('--kind', 'tabletop'), kit });
    console.log(r.created ? `created ${r.file}` : `exists, left as is: ${r.file}`);
    return 0;
  }
  if (cmd === 'remind') {
    const r = newTimeline({ dir, date: today(), kind: 'tabletop', kit });
    const next = nextDrill(every, today());
    writeFileSync(join(dir, 'NEXT'), `${next}\n`);
    const msg = `sigelo recovery drill due: ${r.file} (procedure: DRILL.md). Next after this one: ${next}.`;
    console.log(msg);
    if (!process.env.SIGELO_KIT_NO_NOTIFY) { // the kit's own tests set it
      spawnSync('logger', ['-t', 'sigelo-kit', msg]);
      spawnSync('notify-send', ['-u', 'critical', 'sigelo recovery drill due', msg]);
    }
    return 0;
  }
  const u = units({ dir, every, at: opt('--at', '09:00'), kit });
  const udir = resolve(opt('--units-dir', join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'systemd', 'user')));
  if (a.includes('--dry-run')) {
    process.stdout.write(`==> ${join(udir, 'sigelo-drill-reminder.timer')}\n${u.timer}\n==> ${join(udir, 'sigelo-drill-reminder.service')}\n${u.service}\n==> ${join(dir, 'crontab.line')}\n${u.cron}`);
    return 0;
  }
  mkdirSync(udir, { recursive: true });
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(udir, 'sigelo-drill-reminder.timer'), u.timer);
  writeFileSync(join(udir, 'sigelo-drill-reminder.service'), u.service);
  writeFileSync(join(dir, 'crontab.line'), u.cron);
  writeFileSync(join(dir, 'NEXT'), `${nextDrill(every, today())}\n`);
  console.log(`wrote ${join(udir, 'sigelo-drill-reminder.timer')}, ${join(udir, 'sigelo-drill-reminder.service')}, ${join(dir, 'crontab.line')}\n` +
    `enable (systemd): systemctl --user daemon-reload && systemctl --user enable --now sigelo-drill-reminder.timer\n` +
    `or (cron): (crontab -l 2>/dev/null; cat ${join(dir, 'crontab.line')}) | crontab -\n` +
    `next drill: ${nextDrill(every, today())}`);
  return 0;
}

if (process.argv[1] && realpathSync(process.argv[1]) === SELF) {
  try { process.exit(main(process.argv.slice(2))); } catch (e) { console.error(`sigelo-kit-drill: ${e.message}`); process.exit(2); }
}
