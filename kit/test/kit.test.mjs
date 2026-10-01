#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// kit/test/kit.test.mjs — bind, print, the drill scheduler and the grader, in a scratch directory.
// Nothing is installed: units are written to a scratch --units-dir or printed with --dry-run,
// no systemctl or crontab runs, and the reminder's logger/notify-send are switched off.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const KIT = dirname(dirname(fileURLToPath(import.meta.url)));
const { GUARD, DOCS, secretProblems } = await import(join(KIT, 'bind.mjs'));
const { grade } = await import(join(KIT, 'drill', 'grade.mjs'));
const { nextDrill, units } = await import(join(KIT, 'drill', 'schedule.mjs'));
let pass = 0, fail = 0;
const t = (name, ok) => { if (ok) { pass++; console.log(`ok   ${name}`); } else { fail++; console.log(`FAIL ${name}`); } };
const tmp = mkdtempSync(join(process.env.SIGELO_KIT_TMP ?? tmpdir(), 'kit-'));
const node = (args, env = {}) => { const r = spawnSync(process.execPath, args, { env: { ...process.env, SIGELO_KIT_NO_NOTIFY: '1', ...env } }); return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() }; };
const sh = (args, env = {}) => { const r = spawnSync('sh', args, { env: { ...process.env, ...env } }); return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() }; };
const read = (p) => readFileSync(p, 'utf8');

// --- the rule is written down everywhere it must be -----------------------------------------
const boxed = (s) => s.split('\n').some((l) => l.startsWith('> ') && l.includes(GUARD));
t('the vendor rule is a boxed sentence in README, CONTACT and every procedure page',
  [join(KIT, 'README.md'), join(KIT, 'CONTACT.md'), ...DOCS.map((d) => join(KIT, 'procedure', d))].every((f) => boxed(read(f))));
t('README carries the MiCA sentence, the <price> placeholder and the vault-only line nowhere weakened',
  read(join(KIT, 'README.md')).includes('no custody, no key material') && read(join(KIT, 'README.md')).includes('MiCA') && read(join(KIT, 'README.md')).includes('`<price>`') &&
  read(join(KIT, 'procedure', 'CEREMONY.md')).includes('Vault only, never a hot wallet'));
t('CONTACT.md names contact@sigelo.io as its channel and lists what the facilitator never does', read(join(KIT, 'CONTACT.md')).includes('`contact@sigelo.io`') && read(join(KIT, 'CONTACT.md')).includes('## What the facilitator never does'));

// --- bind -----------------------------------------------------------------------------------
const kit = JSON.parse(read(join(KIT, 'kit.example.json')));
const kitPath = join(tmp, 'kit.json');
writeFileSync(kitPath, JSON.stringify({ ...kit, net: 'stagenet' }, null, 2));
const record = { v: 'sigelo-kit-ceremony/1', created: '2026-10-01T12:00:00Z', net: 'stagenet', vault_address: '5' + 'A'.repeat(94), fingerprint: '{"allowance":"5…"}' };
const recPath = join(tmp, 'ceremony-record.json');
writeFileSync(recPath, JSON.stringify(record));
const noRec = node([join(KIT, 'bind.mjs'), '--kit', kitPath, '--out', join(tmp, 'b0')]);
t('bind without a vault address anywhere: exit 2, names {{vault_address}} in DRILL.md and RUNBOOK.md, writes nothing',
  noRec.code === 2 && noRec.err.includes('DRILL.md: {{vault_address}}') && noRec.err.includes('RUNBOOK.md: {{vault_address}}') && !existsSync(join(tmp, 'b0')));
const bound = join(tmp, 'bound');
const b = node([join(KIT, 'bind.mjs'), '--kit', kitPath, '--record', recPath, '--out', bound]);
const texts = Object.fromEntries(DOCS.map((d) => [d, existsSync(join(bound, d)) ? read(join(bound, d)) : '']));
t('bind with the record: exit 0, three files, no {{placeholder}} left, the vault address and the installation filled in',
  b.code === 0 && DOCS.every((d) => texts[d] && !/\{\{[\w.]+\}\}/.test(texts[d])) && texts['RUNBOOK.md'].includes(record.vault_address) &&
  texts['CEREMONY.md'].startsWith('# Root ceremony — acme-agents-prod') && texts['RUNBOOK.md'].includes('/home/agents/.local/share/sigelo/keeper/spend.lock'));
t('bind, systemd-user: freeze is stop + disable + is-active/is-enabled checks, never mask --runtime',
  texts['RUNBOOK.md'].includes('systemctl --user stop sigelo-keeper.service && systemctl --user disable sigelo-keeper.service') &&
  texts['RUNBOOK.md'].includes('is-enabled sigelo-keeper.service') && !/^systemctl[^\n]*mask --runtime/m.test(texts['RUNBOOK.md'] + texts['DRILL.md']));
t('bound DRILL and RUNBOOK carry the T14 corrections: Restart=no before the kill, --no-initial-sync, priority step-down, transfer_split, the licence reissue, INCIDENT §5 for the keeper DID',
  ['DRILL.md', 'RUNBOOK.md'].every((d) => ['Restart=no', 'daemon-reload', 'kill -9', '--no-initial-sync', 'error -4', 'transfer_split', 'licence install', 'licence_required', 'INCIDENT.md §5', 'unmask --runtime'].every((x) => texts[d].includes(x))) &&
  texts['DRILL.md'].includes('for u in sigelo-keeper.service monero-wallet-rpc.service; do') && /^\s*- \[ \] \*\*4\.4 Licence/m.test(texts['DRILL.md']) && /^\s*- \[ \] \*\*5\.3 /m.test(texts['DRILL.md']));
writeFileSync(join(tmp, 'kit-none.json'), JSON.stringify({ ...kit, net: 'stagenet', supervisor: 'none' }));
const bn = node([join(KIT, 'bind.mjs'), '--kit', join(tmp, 'kit-none.json'), '--record', recPath, '--out', join(tmp, 'bound-none')]);
t('bind, no supervisor: freeze is kill -9 on spend.lock\'s pid (the lock stays as evidence)', bn.code === 0 && read(join(tmp, 'bound-none', 'RUNBOOK.md')).includes('kill -9 "$(head -n1 /home/agents/.local/share/sigelo/keeper/spend.lock)"'));
const bnet = node([join(KIT, 'bind.mjs'), '--kit', join(KIT, 'kit.example.json'), '--record', recPath, '--out', join(tmp, 'b1')]);
t('bind refuses a kit.json whose net disagrees with the ceremony record', bnet.code === 2 && bnet.err.includes('the ceremony record says stagenet'));
const words25 = 'abbey abducts ability ablaze abnormal abort abrasive absorb abyss academy aces aching acidic acoustic acquire across actress acumen adapt addicted adept adhesive adjust adopt adrenalin';
const bad = { ...kit, net: 'stagenet', keeper: { ...kit.keeper, spend_key: 'x' }, backup: { ...kit.backup, paper_location: words25 }, note: 'a'.repeat(0) + 'f'.repeat(64), extra: 'AGE-SECRET-KEY-1QQQ' };
writeFileSync(join(tmp, 'kit-bad.json'), JSON.stringify(bad));
const bs = node([join(KIT, 'bind.mjs'), '--kit', join(tmp, 'kit-bad.json'), '--record', recPath, '--out', join(tmp, 'b2')]);
t('bind refuses key material in kit.json: a secret-named field, seed words, 64 hex, an age identity — each named, nothing written',
  bs.code === 2 && bs.err.includes('keeper.spend_key: a field named like a secret') && bs.err.includes('backup.paper_location: holds 25 seed words') &&
  bs.err.includes('note: holds 64 hex') && bs.err.includes('extra: holds an age identity') && !existsSync(join(tmp, 'b2')) && !bs.err.includes('abducts'));
t('the example kit.json and ordinary prose pass the secret check (no false alarm on English)',
  secretProblems(kit, new Set(['the', 'and'])).length === 0 && secretProblems({ x: 'a second person who signs the record and never looks at the screen while the words are shown' }, null).length === 0);

// --- print ----------------------------------------------------------------------------------
const pr = sh([join(KIT, 'procedure', 'print.sh'), bound]);
const prMin = sh([join(KIT, 'procedure', 'print.sh'), bound, join(tmp, 'print-min')], { SIGELO_KIT_RENDERER: 'minimal' });
const inClone = existsSync(join(KIT, '..', 'site', 'build.mjs'));
const tasks = DOCS.reduce((n, d) => n + (texts[d].match(/^\s*- \[ \]/gm) ?? []).length, 0);
for (const [name, r, dir] of [['site renderer', pr, join(bound, 'print')], ['minimal renderer', prMin, join(tmp, 'print-min')]]) {
  const all = existsSync(join(dir, 'procedure.html')) ? read(join(dir, 'procedure.html')) : '';
  t(`print (${name}): four self-contained HTML files, each document on its own page, no script, nothing external`,
    r.code === 0 && ['CEREMONY.html', 'DRILL.html', 'RUNBOOK.html', 'procedure.html'].every((f) => existsSync(join(dir, f))) &&
    (all.match(/<section class="doc">/g) ?? []).length === 3 && all.includes('.doc + .doc { break-before: page; }') &&
    !/<script|<link|src=|@import|https?:\/\/[^"\s<]*\.(css|js|woff)/i.test(all));
  t(`print (${name}): every checkbox becomes a printed box (${tasks}), the vendor rule prints boxed in each document, code stays code`,
    (all.match(/class="box"/g) ?? []).length === tasks && (all.match(/<blockquote>[\s\S]*?never receives, holds, escrows or sees[\s\S]*?<\/blockquote>/g) ?? []).length >= 3 &&
    all.includes('systemctl --user stop sigelo-keeper.service &amp;&amp; systemctl --user disable') && !all.includes('[ ]'));
}
t(`print uses site/build.mjs's renderer in a clone${inClone ? '' : ' (not a clone: SKIP-equivalent)'}`, !inClone || pr.out.includes('(site/build.mjs)'));
const unb = sh([join(KIT, 'procedure', 'print.sh'), join(KIT, 'procedure'), join(tmp, 'p-unbound')]);
t('print refuses an unbound template (placeholders left) unless --unbound', unb.code === 2 && unb.err.includes('run bind.mjs first') &&
  sh([join(KIT, 'procedure', 'print.sh'), join(KIT, 'procedure'), join(tmp, 'p-unbound'), '--unbound']).code === 0);

// --- the drill scheduler --------------------------------------------------------------------
const drills = join(tmp, 'drills'), udir = join(tmp, 'units');
const dry = node([join(KIT, 'drill', 'schedule.mjs'), 'install', '--dir', drills, '--units-dir', udir, '--kit', kitPath, '--dry-run']);
t('install --dry-run prints timer, service and cron line and writes nothing',
  dry.code === 0 && dry.out.includes('OnCalendar=*-01,04,07,10-01 09:00:00') && dry.out.includes('Type=oneshot') && dry.out.includes('0 9 1 1,4,7,10 *') && !existsSync(udir) && !existsSync(drills));
const ins = node([join(KIT, 'drill', 'schedule.mjs'), 'install', '--dir', drills, '--units-dir', udir, '--every', 'yearly', '--at', '07:30', '--kit', kitPath]);
const timer = existsSync(join(udir, 'sigelo-drill-reminder.timer')) ? read(join(udir, 'sigelo-drill-reminder.timer')) : '';
const service = existsSync(join(udir, 'sigelo-drill-reminder.service')) ? read(join(udir, 'sigelo-drill-reminder.service')) : '';
t('install writes the timer + service into the given units dir and the cron line beside the drills, runs no systemctl, prints how to enable',
  ins.code === 0 && timer.includes('OnCalendar=*-01-01 07:30:00') && timer.includes('Persistent=true') && service.includes('"remind" "--dir"') &&
  read(join(drills, 'crontab.line')).startsWith('30 7 1 1 * ') && ins.out.includes('systemctl --user enable --now sigelo-drill-reminder.timer') && /^\d{4}-01-01\n$/.test(read(join(drills, 'NEXT'))));
const u = units({ dir: '/d i r', every: 'quarterly', at: '09:00', node: '/usr/bin/node', script: "/k it/s'chedule.mjs" });
t('units quote paths with spaces and quotes for systemd and for the shell', u.service.includes('ExecStart="/usr/bin/node" "/k it/s\'chedule.mjs" "remind" "--dir" "/d i r"') && u.cron.includes(`'/k it/s'\\''chedule.mjs'`));
t('next drill dates: quarterly, monthly, semiannually, yearly, across a year end',
  nextDrill('quarterly', '2026-10-01') === '2027-01-01' && nextDrill('quarterly', '2026-09-30') === '2026-10-01' && nextDrill('monthly', '2026-12-15') === '2027-01-01' &&
  nextDrill('semiannually', '2026-01-01') === '2026-07-01' && nextDrill('yearly', '2026-06-01') === '2027-01-01');
const nw = node([join(KIT, 'drill', 'schedule.mjs'), 'new', '--dir', drills, '--date', '2026-10-01', '--kind', 'stagenet', '--kit', kitPath]);
const tl = join(drills, '2026-10-01', 'TIMELINE.md');
t('new: drills/<date>/TIMELINE.md from the template, installation and kind filled, the step table pre-filled',
  nw.code === 0 && existsSync(tl) && read(tl).includes('# Drill timeline — acme-agents-prod — 2026-10-01') && read(tl).includes('| kind | stagenet |') &&
  (read(tl).match(/^\| \d\.\d \|/gm) ?? []).length === 28 && read(tl).includes('| 4.4 | licence') && read(tl).includes('| 5.3 | keeper') && !read(tl).includes('{{'));
writeFileSync(tl, read(tl) + '\n- operator note\n');
const again = node([join(KIT, 'drill', 'schedule.mjs'), 'new', '--dir', drills, '--date', '2026-10-01']);
t('new never overwrites a timeline', again.code === 0 && again.out.includes('exists, left as is') && read(tl).endsWith('- operator note\n'));
const rem = node([join(KIT, 'drill', 'schedule.mjs'), 'remind', '--dir', join(tmp, 'drills2'), '--kit', kitPath]);
const today = new Date().toISOString().slice(0, 10);
t('remind (what the timer runs): creates today\'s tabletop timeline, writes NEXT, says so', rem.code === 0 && existsSync(join(tmp, 'drills2', today, 'TIMELINE.md')) &&
  rem.out.includes('drill due') && read(join(tmp, 'drills2', 'NEXT')).trim() === nextDrill('quarterly', today));

// --- the grader -----------------------------------------------------------------------------
const fx = read(join(KIT, 'test', 'fixtures', 'completed-TIMELINE.md'));
const g = grade(fx);
t('grade: the T14-modelled completed timeline scores 100 and passes; detect → frozen 1 min 46 s, detect → last sweep 15 min 26 s',
  g.pass && g.score === 100 && g.detect_to_frozen === '1 min 46 s' && g.detect_to_last_sweep === '15 min 26 s' && g.findings === 5);
const cli = node([join(KIT, 'drill', 'grade.mjs'), join(KIT, 'test', 'fixtures', 'completed-TIMELINE.md')]);
t('grade CLI: exit 0 and a per-part table', cli.code === 0 && cli.out.includes('100/100 — PASS') && cli.out.includes('sweeps     20/20'));
const blank = node([join(KIT, 'drill', 'grade.mjs'), join(tmp, 'drills2', today, 'TIMELINE.md'), '--json']);
const bj = blank.out ? JSON.parse(blank.out) : {};
t('grade: a blank timeline fails, exit 1, every step named as untimed', blank.code === 1 && bj.score === 0 && bj.parts.steps.note.startsWith('no time: 0.1, 0.2'));
const badTx = grade(fx.replace('659d86e498447b3a06bafe9707932d59e378e492983049b20b1e6c46173079ef', '659d86e4…79ef'));
t('grade: a truncated txid costs its share of the sweep points and is named', badTx.parts.sweeps.score < 20 && badTx.parts.sweeps.note.includes('not a txid: account 0'));
const noFind = grade(fx.replace(/## Findings[\s\S]*$/, '## Findings\n\n<!-- none -->\n'));
t('grade: no findings scores 0 for findings and says why that matters', noFind.parts.findings.score === 0 && noFind.parts.findings.note.includes('zero findings is itself a finding'));
const missingStep = grade(fx.replace('| 2.3 | wallet-rpc stopped and disabled | 13:21:34 |', '| 2.3 | wallet-rpc stopped and disabled | |'));
t('grade: one step without a time fails the drill even above 80 points', !missingStep.pass && missingStep.score >= 80 && missingStep.parts.steps.note === 'no time: 2.3');
const backwards = grade(fx.replace('| 3.4 | LAST SWEEP sent | 13:35:19 |', '| 3.4 | LAST SWEEP sent | 13:10:00 |'));
t('grade: a sweep before the detect breaks the order points', backwards.parts.order.score === 0);
const table = grade(fx.replace('| kind | stagenet |', '| kind | tabletop |').replace(/## Sweeps[\s\S]*?(?=## Findings)/, '## Sweeps\n\n| account | txid | amount | fee | priority |\n|---|---|---|---|---|\n\n'));
t('grade: a tabletop drill is not graded on sweeps and can still pass', table.pass && table.parts.sweeps.of === 0 && table.score === 100);

if (!process.env.SIGELO_KIT_KEEP) rmSync(tmp, { recursive: true, force: true });
console.log(fail === 0 ? `kit: ALL PASS (${pass} checks)` : `kit: ${fail} FAILED, ${pass} passed`);
process.exit(fail === 0 ? 0 : 1);
