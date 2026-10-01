#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// kit/test/ceremony.test.mjs — kit/ceremony/run.sh, run as an operator runs it, in a scratch directory.
//
// The offline check is faked with SIGELO_KIT_NET_DIR (a stand-in /proc/net with or without a
// default route); everything else is real: the sigelo package's sigelo-offline, the real `age`
// (an identity made here with age-keygen), and a real pseudo-terminal from util-linux `script`
// with stdout and stderr redirected to files — so what `script` prints is exactly what reached
// /dev/tty, and the files are exactly what an agent or a log would have seen. The leak checks
// are ts/src/test.ts's M4 technique (wordlist tokens, consecutive-word windows), made stricter:
// every wordlist token in stdout/stderr must come from the programs' own fixed text.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const KIT = dirname(dirname(fileURLToPath(import.meta.url)));
const RUN = join(KIT, 'ceremony', 'run.sh');
let pass = 0, fail = 0, skip = 0;
const t = (name, ok) => { if (ok) { pass++; console.log(`ok   ${name}`); } else { fail++; console.log(`FAIL ${name}`); } };

// The sigelo package: installed beside the kit, or the clone's ts/dist.
let dist;
try { dist = dirname(createRequire(join(KIT, 'package.json')).resolve('sigelo/dist/offline.js')); } catch { dist = join(KIT, '..', 'ts', 'dist'); }
const OFFLINE = join(dist, 'offline.js');
const { MONERO_WORDS } = await import(pathToFileURL(join(dist, 'monero-words.js')).href);
const { rootFromMnemonic, recoverySeed } = await import(pathToFileURL(join(dist, 'keys.js')).href);
const hex = (b) => Buffer.from(b).toString('hex');
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const has = (cmd) => spawnSync(cmd, ['--version']).error === undefined;
if (!has('script') || !has('age') || !has('age-keygen')) {
  console.log('SKIP kit ceremony: needs util-linux `script`, `age` and `age-keygen` on PATH');
  process.exit(0);
}

// Wordlist tokens of a text, with base58 runs (addresses, multibase keys) and hex removed first:
// a 95-character address can contain a 3-letter word by chance, a line of the 25 words cannot.
const WORDS = new Set(MONERO_WORDS);
const tokens = (s) => new Set(s.replace(/[1-9A-HJ-NP-Za-km-z]{30,}/g, ' ').toLowerCase().split(/[^a-z]+/).filter((w) => WORDS.has(w)));
const pairLeak = (s, m) => { const w = m.split(' '), flat = s.toLowerCase().split(/[^a-z]+/).join(' ');
  return w.slice(0, -1).some((x, i) => flat.includes(`${x} ${w[i + 1]}`)); };
// ceremony --human numbers the words 1…25, five to a row (ts/src/test.ts `numbered`).
const numbered = (screen) => screen.split('\n').filter((l) => /^\s*1?\d \S/.test(l) || /^\s*2\d \S/.test(l))
  .flatMap((l) => l.trim().split(/\s+/).filter((w) => !/^\d+$/.test(w))).join(' ');

const tmp = mkdtempSync(join(process.env.SIGELO_KIT_TMP ?? tmpdir(), 'kit-ceremony-'));
const offNet = join(tmp, 'net-offline'), onNet = join(tmp, 'net-online');
mkdirSync(offNet); mkdirSync(onNet);
const HDR = 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n';
writeFileSync(join(offNet, 'route'), HDR + 'lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n');
writeFileSync(join(offNet, 'ipv6_route'), '00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n');
writeFileSync(join(onNet, 'route'), HDR + 'wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n');
writeFileSync(join(onNet, 'ipv6_route'), '');
spawnSync('age-keygen', ['-o', join(tmp, 'owner.key')]);
const RCPT = spawnSync('age-keygen', ['-y', join(tmp, 'owner.key')]).stdout.toString().trim();
const q = (x) => `'${x.replace(/'/g, `'\\''`)}'`;

/** run.sh on a pty: { code, tty, out, err }. */
function onPty(name, args, net = offNet, input) {
  const o = join(tmp, `${name}.out`), e = join(tmp, `${name}.err`);
  const cmd = `SIGELO_KIT_NET_DIR=${q(net)} sh ${[RUN, ...args].map(q).join(' ')} >${q(o)} 2>${q(e)}`;
  const r = spawnSync('script', ['-q', '-e', '-c', cmd, '/dev/null'], { input });
  return { code: r.status, tty: r.stdout.toString(), out: readFileSync(o, 'utf8'), err: readFileSync(e, 'utf8'), cmd };
}
/** run.sh with no terminal at all (pipes). */
function plain(args, env = {}, input) {
  const r = spawnSync('sh', [RUN, ...args], { env: { ...process.env, SIGELO_KIT_NET_DIR: offNet, ...env }, input });
  return { code: r.status, out: r.stdout.toString(), err: r.stderr.toString() };
}
const cer = (out, extra = []) => ['--out', out, '--recipient', RCPT, '--net', 'stagenet', '--keepers', '2', '--operator', 'kit test', ...extra];
const decrypt = (dir) => JSON.parse(spawnSync('age', ['-d', '-i', join(tmp, 'owner.key'), join(dir, 'backup.age')]).stdout.toString());
const filesUnder = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? filesUnder(join(d, e.name)) : [join(d, e.name)]);

// The fixed text the programs print, from which every wordlist token in stdout/stderr must come.
const SOURCES = [RUN, join(KIT, 'ceremony', 'record.mjs'), OFFLINE, join(dist, 'ceremony.js')].map((p) => readFileSync(p, 'utf8')).join('\n');

// --- refusals: nothing written --------------------------------------------------------------
const r1 = plain(cer(join(tmp, 'online')), { SIGELO_KIT_NET_DIR: onNet });
t('refuses on a host with a default route: exit 2, says so, writes nothing', r1.code === 2 && r1.err.includes('default route') && !existsSync(join(tmp, 'online')));
mkdirSync(offNet.replace('offline', 'v6'));
writeFileSync(join(offNet.replace('offline', 'v6'), 'route'), HDR);
writeFileSync(join(offNet.replace('offline', 'v6'), 'ipv6_route'), '00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003    wlan0\n');
const r1c = plain(cer(join(tmp, 'online6')), { SIGELO_KIT_NET_DIR: offNet.replace('offline', 'v6') });
t('refuses on an IPv6 default route too (lo\'s reject route is not one)', r1c.code === 2 && r1c.err.includes('ipv6-default') && !existsSync(join(tmp, 'online6')));
const fakeBin = join(tmp, 'bin-no-age');
mkdirSync(fakeBin);
spawnSync('ln', ['-s', process.execPath, join(fakeBin, 'node')]);
const noAgeOnSystem = ['/usr/bin', '/bin'].every((d) => !existsSync(join(d, 'age')) && !existsSync(join(d, 'rage')));
if (noAgeOnSystem) {
  const r2 = plain(cer(join(tmp, 'noage')), { PATH: `${fakeBin}:/usr/bin:/bin` });
  t('refuses without age: exit 2, names the install, writes nothing', r2.code === 2 && r2.err.includes('apk add age') && !existsSync(join(tmp, 'noage')));
} else { skip++; console.log('SKIP refusal without age (age is in /usr/bin or /bin here)'); }
const r3 = plain(['--out', join(tmp, 'argv'), 'abbey', 'abducts']);
t('refuses stray arguments (the words never go on the command line), writes nothing', r3.code === 2 && r3.err.includes('never go on the command line') && !existsSync(join(tmp, 'argv')));
const r4 = plain(['--out', join(tmp, 'norcpt'), '--net', 'stagenet']);
t('refuses without --recipient', r4.code === 2 && r4.err.includes('--recipient') && !existsSync(join(tmp, 'norcpt')));
const r5 = plain(cer(join(tmp, 'notty')));
t('without a terminal sigelo-offline --human refuses, and run.sh leaves no directory behind', r5.code === 2 && r5.err.includes('/dev/tty') && !existsSync(join(tmp, 'notty')));

// --- the ceremony on a pty ------------------------------------------------------------------
const outA = join(tmp, 'mediumA', 'root');
const a = onPty('a', cer(outA));
const wordsA = numbered(a.tty);
const plainA = decrypt(outA);
t('ceremony: exit 0; the 25 words reach the terminal, in order, and are the ones inside backup.age (real age)',
  a.code === 0 && wordsA.split(' ').length === 25 && wordsA === plainA.mnemonic && a.tty.includes('Vault only, never a hot wallet'));
const SA = hex(rootFromMnemonic(wordsA)), recA = hex(recoverySeed(rootFromMnemonic(wordsA)));
const allowed = tokens(SOURCES + a.cmd);
const leakedTokens = [...tokens(a.out + a.err)].filter((w) => !allowed.has(w));
t('ceremony: stdout and stderr carry no wordlist word that is not the programs\' fixed text, and no two consecutive words',
  leakedTokens.length === 0 && !pairLeak(a.out + a.err, wordsA));
t('ceremony: stdout and stderr hold neither S nor the recovery secret', !(a.out + a.err).includes(SA) && !(a.out + a.err).includes(recA));
const filesA = filesUnder(dirname(outA));
const leakFiles = filesA.filter((f) => !f.endsWith('backup.age')).filter((f) => { const s = readFileSync(f, 'utf8'); return s.includes(SA) || s.includes(recA) || pairLeak(s, wordsA); });
t('ceremony: no file but backup.age holds S, the recovery secret or two consecutive words (keeper packages included)', leakFiles.length === 0);
t('ceremony: <out> holds backup.age, fingerprint.txt, ceremony-public.json, ceremony-record.json and the keeper directory, nothing else',
  readdirSync(outA).sort().join(',') === 'backup.age,ceremony-public.json,ceremony-record.json,fingerprint.txt,keepers-move-then-shred' &&
  readdirSync(join(outA, 'keepers-move-then-shred')).sort().join(',') === 'keeper-0.json,keeper-1.json' &&
  (statSync(outA).mode & 0o777) === 0o700 && (statSync(join(outA, 'keepers-move-then-shred')).mode & 0o777) === 0o700);
const rec = JSON.parse(readFileSync(join(outA, 'ceremony-record.json'), 'utf8'));
t('record: what/when/host/tools, sha256 of backup.age and fingerprint.txt, the offline check, no secret',
  rec.v === 'sigelo-kit-ceremony/1' && rec.net === 'stagenet' && rec.keepers === 2 && rec.backup_sha256 === sha(join(outA, 'backup.age')) &&
  rec.fingerprint_sha256 === sha(join(outA, 'fingerprint.txt')) && /^[0-9a-f]{64}$/.test(rec.host.id_sha256) && rec.host.offline_check === 'no-default-route' &&
  rec.age_recipient === RCPT && rec.fingerprint + '\n' === readFileSync(join(outA, 'fingerprint.txt'), 'utf8') && rec.people.operator === 'kit test' &&
  !JSON.stringify(rec).includes('AGE-SECRET-KEY') && rec.vendor.includes('never receives, holds, escrows or sees'));
t('the printed checklist follows, with the vault-only line and the vendor rule', a.out.includes('[ ] Paper check now') && a.out.includes('Vault only, never a hot wallet') && a.out.includes('never receives, holds, escrows or sees'));

// A second, independent root: what reaches stdout/stderr must not depend on the root at all.
const b = onPty('b', cer(join(tmp, 'mediumB', 'root')));
const wordsB = numbered(b.tty);
const norm = (r, dir) => [...tokens((r.out + r.err).split(dir).join('<out>'))].sort().join(' ');
t('a second ceremony: a different root, and exactly the same wordlist tokens in stdout/stderr (nothing root-dependent printed)',
  b.code === 0 && wordsB !== wordsA && norm(a, 'mediumA') === norm(b, 'mediumB') && !pairLeak(b.out + b.err, wordsB));

// --- restore from the words captured off the terminal (the test's stand-in for the paper) ---
const paper = join(tmp, 'paper.txt');
writeFileSync(paper, wordsA + '\n', { mode: 0o600 });
const rw = spawnSync(process.execPath, [OFFLINE, 'restore', '--words', paper, '--keepers', '2', '--fingerprint', join(outA, 'fingerprint.txt'), '--net', 'stagenet']);
const rb = spawnSync(process.execPath, [OFFLINE, 'restore', '--backup', join(outA, 'backup.age'), '--identity', join(tmp, 'owner.key'), '--net', 'stagenet']);
t('restore --words from the terminal\'s words passes the fingerprint check and prints byte for byte what restore --backup (real age) prints',
  rw.status === 0 && rb.status === 0 && rw.stdout.toString() === rb.stdout.toString() && JSON.parse(rw.stdout.toString()).fingerprint === rec.fingerprint);
const vp = plain(['--verify-paper', '--out', outA], {}, wordsA.split(' ').slice(0, 12).join(' ') + '\n' + wordsA.split(' ').slice(12).join(' ') + '\n');
t('--verify-paper: the words typed on two lines reproduce fingerprint.txt: PAPER OK, exit 0, nothing echoed', vp.code === 0 && vp.out.includes('PAPER OK') && !pairLeak(vp.out + vp.err, wordsA));
const w = wordsA.split(' '); [w[3], w[4]] = [w[4], w[3]];
const vbad = plain(['--verify-paper', '--out', outA], {}, w.join(' ') + '\n');
t('--verify-paper: two swapped words: PAPER DOES NOT MATCH, exit 1, the words not echoed', vbad.code === 1 && vbad.err.includes('DOES NOT MATCH') && !pairLeak(vbad.out + vbad.err, wordsA));
const typo = wordsA.replace(/^\S+/, 'sigeloo');
const vtypo = plain(['--verify-paper', '--out', outA], {}, typo + '\n');
t('--verify-paper: a word not in the list is refused without echoing what was typed', vtypo.code === 1 && !vtypo.err.includes('sigeloo') && vtypo.err.includes('<a typed word>'));

// --- idempotency and refusal to overwrite ---------------------------------------------------
const before = sha(join(outA, 'backup.age'));
const again = onPty('again', cer(outA));
t('rerun on a finished ceremony: exit 0, "already done", no words on the terminal, backup.age unchanged',
  again.code === 0 && again.err.includes('already done') && numbered(again.tty) === '' && sha(join(outA, 'backup.age')) === before);
const stray = join(tmp, 'stray');
mkdirSync(stray); writeFileSync(join(stray, 'notes.txt'), 'x');
const rs = onPty('stray', cer(stray));
t('a non-empty --out is refused: exit 3, no words shown, nothing added', rs.code === 3 && numbered(rs.tty) === '' && readdirSync(stray).join() === 'notes.txt');
const orphan = join(tmp, 'orphan');
mkdirSync(orphan); writeFileSync(join(orphan, 'backup.age'), 'an earlier root');
const ro = onPty('orphan', cer(orphan));
t('a backup.age without a matching record is never overwritten: exit 3', ro.code === 3 && ro.err.includes('Refusing to overwrite') && readFileSync(join(orphan, 'backup.age'), 'utf8') === 'an earlier root');
const tam = join(tmp, 'tamper');
spawnSync('cp', ['-rp', outA, tam]);
writeFileSync(join(tam, 'backup.age'), 'replaced');
const rt = onPty('tamper', cer(tam));
t('a backup.age that is not the one its record hashes: exit 3, not "already done"', rt.code === 3 && !rt.err.includes('already done'));
const stage = join(tmp, 'interrupted');
mkdirSync(join(stage, '.stage'), { recursive: true }); writeFileSync(join(stage, '.stage', 'backup.age'), 'half');
const ri = onPty('interrupted', cer(stage));
t('an interrupted ceremony (.stage) is reported and left alone: exit 3', ri.code === 3 && ri.err.includes('interrupted') && existsSync(join(stage, '.stage', 'backup.age')));

// --- the deliberate override ----------------------------------------------------------------
const outO = join(tmp, 'override');
const ov = onPty('override', cer(outO, ['--i-am-online-on-purpose']), onNet);
const recO = existsSync(join(outO, 'ceremony-record.json')) ? JSON.parse(readFileSync(join(outO, 'ceremony-record.json'), 'utf8')) : {};
t('--i-am-online-on-purpose on an online host: runs, warns, and the record says "overridden"',
  ov.code === 0 && ov.err.includes('not provably offline') && String(recO.host?.offline_check).startsWith('overridden:ipv4-default'));
const kdir = join(tmp, 'keepers-elsewhere');
const ke = onPty('kout', cer(join(tmp, 'kout-root'), ['--keepers-out', kdir, '--treasury-keeper', '1']));
t('--keepers-out puts the keeper packages on another medium; the treasury keeper is recorded',
  ke.code === 0 && readdirSync(kdir).sort().join() === 'keeper-0.json,keeper-1.json' && !existsSync(join(tmp, 'kout-root', 'keepers-move-then-shred')) &&
  JSON.parse(readFileSync(join(tmp, 'kout-root', 'ceremony-record.json'), 'utf8')).treasury_keeper === 1 &&
  JSON.parse(readFileSync(join(kdir, 'keeper-1.json'), 'utf8')).role === 'treasury');

if (!process.env.SIGELO_KIT_KEEP) rmSync(tmp, { recursive: true, force: true });
console.log(fail === 0 ? `kit ceremony: ALL PASS (${pass} checks${skip ? `, ${skip} SKIP` : ''})` : `kit ceremony: ${fail} FAILED, ${pass} passed`);
process.exit(fail === 0 ? 0 : 1);
