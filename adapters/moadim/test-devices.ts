// SPDX-License-Identifier: MIT
// Devices end to end (DEVICES.md, contact/device.mjs): HOMEs as machines, one loopback relay in this
// process. Online: `device add` refuses without a terminal for the words, prints SIGELO:DEV:…, the
// device scans it (text, and as a PNG through show-qr) and becomes worker i, attested 14 days, own;
// a "n" at the words gate sends nothing. Offline: `device add --offline` shows frames, then the
// words; the device reads the frames in any order (some first: pending), types wrong words then
// right ones, writes the identity 0600 and pairs through the 7-day invite. `device list` shows both.
// Neither label (sigelo-identity/0, sigelo-device/1) nor a key reaches any inbox.log. The terminal
// is a pty (python3's pty module); without python3 those checks SKIP.
// FULL (D2): a second computer online ("type FULL", the words, then the operator identity and K end
// to end), another offline with an OS keychain (a fake secret-tool on its PATH: the key and K sealed);
// the signed list synced to every device; revoke: a wipe answered (a SAFE and a FULL device), --lost
// for a FULL one (the steps printed), refusals.
// The seat (D3): an operator (device main after seat init) and two FULL devices, a contact paired as
// the operator; the standby refuses seat_elsewhere (ui, invite, enrol, inbox, device add) after reading
// its device inbox, yet signs as you; snapshots sent (as a file) and kept sealed; give, take (asked,
// answered at the seat's inbox), take --force (fresh epochs: messages both ways); device identities
// keep their own sessions throughout.
//   node test-devices.ts   → ALL PASS test-devices.ts (n ok)
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalize, decodeKey, keygen, verify } from 'sigelo';
import { agentIdentitySeed, keeperRoot, newRoot, recoveryCommitment, rootFromMnemonic } from 'sigelo/dist/keys.js';
import { CLI, done, hasRelay, NO_RELAY, ok, startTestRelay } from './test-helpers.ts';

if (!hasRelay()) {
  console.log(`SKIP devices end to end: ${NO_RELAY}`);
  done(import.meta.filename);
}
const python = spawnSync('python3', ['-c', 'import pty'], { encoding: 'utf8' }).status === 0;

const words = newRoot(), S = rootFromMnemonic(words), K = keeperRoot(S, 1), RC = recoveryCommitment(S);
const derived = (i: number) => {
  const seed = agentIdentitySeed(K, i, 0), key = keygen({ seed, recovery: RC, created: '1970-01-01T00:00:00Z', nonce: new Uint8Array(16) }).key;
  return { seed, ...keygen({ seed, recovery: RC, created: '1970-01-01T00:00:00Z', nonce: new Uint8Array(createHash('sha256').update(decodeKey(key)).digest().subarray(0, 16)) }) };
};

const D = mkdtempSync(join(tmpdir(), 'sigelo-devices-'));
const relay = await startTestRelay(D);
// A home may run with more (or other) variables: the keychain one gets a fake secret-tool on its PATH.
const extra: Record<string, Record<string, string>> = {};
const env = (home: string): Record<string, string> => {
  const e: Record<string, string> = { PATH: process.env['PATH'] ?? '', SIGELO_KEY_PROVIDER: 'file', HOME: home, SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: JSON.stringify(relay.endpoints), ...extra[home] };
  for (const [k, v] of Object.entries(e)) if (v === '') delete e[k];
  return e;
};
type Run = { status: number | null; stdout: string; stderr: string };
// detached: a session of its own, so no controlling terminal (/dev/tty does not open).
const cli = (home: string, args: string[], o: { input?: string; onLine?: (l: string) => void; env?: Record<string, string> } = {}) => new Promise<Run>((resolve) => {
  const c = spawn('node', [CLI, ...args], { env: { ...env(home), ...o.env }, cwd: home, detached: true });
  let stdout = '', stderr = '', onLine = o.onLine;
  c.stdout.on('data', (d) => { stdout += d; if (onLine && stdout.includes('\n')) { onLine(stdout.split('\n')[0]!); onLine = undefined; } });
  c.stderr.on('data', (d) => { stderr += d; });
  c.on('close', (status) => resolve({ status, stdout, stderr }));
  c.stdin.end(o.input ?? '');
});
// In a pty: each [regex, reply] answers the first output matching it, in order. → all output, the exit code.
const DRIVER = join(D, 'pty-driver.py');
writeFileSync(DRIVER, `import json, os, pty, re, sys, select, time
steps = json.loads(sys.argv[1]); argv = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)
buf = b''; seen = 0; end = time.time() + 240
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try: d = os.read(fd, 65536)
        except OSError: break
        if not d: break
        buf += d
    if steps and re.search(steps[0][0].encode(), buf[seen:]):
        m = re.search(steps[0][0].encode(), buf[seen:]); seen += m.end()
        time.sleep(0.3); os.write(fd, steps[0][1].encode()); steps.pop(0)
_, st = os.waitpid(pid, 0)
sys.stdout.write(buf.decode('utf8', 'replace'))
sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 99)
`);
const inPty = (home: string, args: string[], steps: [string, string][]) => new Promise<Run>((resolve) => {
  const c = spawn('python3', ['-I', DRIVER, JSON.stringify(steps), 'node', CLI, ...args], { env: env(home), cwd: home });
  let stdout = '';
  c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stdout += d; });
  c.on('close', (status) => resolve({ status, stdout: stdout.replace(/\r/g, ''), stderr: '' }));
});
const verbose = (what: string, r: Run): void => { if (process.env['SIGELO_TEST_VERBOSE'] === '1') console.log(`  ${what} exit ${r.status}\n${r.stdout}${r.stderr}`.replace(/^/gm, '  | ')); };
const waitFor = (get: () => string) => new Promise<void>((r) => { const t = setInterval(() => { if (get()) { clearInterval(t); r(); } }, 50); });

const OP = mkdtempSync(join(tmpdir(), 'sigelo-dev-op-')), PHONE = mkdtempSync(join(tmpdir(), 'sigelo-dev-phone-')), TAB = mkdtempSync(join(tmpdir(), 'sigelo-dev-tab-')), X = mkdtempSync(join(tmpdir(), 'sigelo-dev-x-'));
const LAP = mkdtempSync(join(tmpdir(), 'sigelo-dev-lap-')), DESK = mkdtempSync(join(tmpdir(), 'sigelo-dev-desk-'));
// The seat (D3): a third operator, two FULL devices, a contact.
const OP3 = mkdtempSync(join(tmpdir(), 'sigelo-dev-op3-')), ALPHA = mkdtempSync(join(tmpdir(), 'sigelo-dev-alpha-')), BETA = mkdtempSync(join(tmpdir(), 'sigelo-dev-beta-')), CARL = mkdtempSync(join(tmpdir(), 'sigelo-dev-carl-'));
const CONTACT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'contact');
const meOf = (h: string): string => join(h, '.config', 'sigelo', 'me.local.json');
const readJ = (f: string): Record<string, unknown> => JSON.parse(readFileSync(f, 'utf8')) as Record<string, unknown>;
// secret-tool as a Secret Service answers it, items in $HOME/.fake-keyring (lookup, store, clear).
const FAKE = join(DESK, 'bin');
mkdirSync(FAKE, { recursive: true });
writeFileSync(join(FAKE, 'secret-tool'), `#!/bin/sh
d="$HOME/.fake-keyring"; mkdir -p "$d"
case "$1" in
  lookup) [ -f "$d/$5" ] && cat "$d/$5" && exit 0; exit 1;;
  store) cat > "$d/$6"; exit 0;;
  clear) rm -f "$d/$5"; exit 0;;
esac
exit 2
`, { mode: 0o755 });
extra[DESK] = { PATH: `${FAKE}:${process.env['PATH'] ?? ''}`, SIGELO_KEY_PROVIDER: '' };
const human = join(OP, '.config', 'sigelo', 'me.local.json'), kfile = human.replace(/\.json$/, '.keeper.json');
const pool = (h: string, n: string): string => join(h, '.config', 'moadim', `sigelo.${n}.local.json`);
const contactsOf = (f: string) => (JSON.parse(readFileSync(f.replace(/\.json$/, '.contacts.json'), 'utf8')) as { contacts: Record<string, { did: string; revoked: boolean; tier: string; name: string }> }).contacts;
const json = (s: string): Record<string, unknown> => { try { return JSON.parse(s.slice(s.indexOf('{'))) as Record<string, unknown>; } catch { return {}; } };
const now = (): number => Math.floor(Date.now() / 1000);

try {
  const kp = await cli(OP, ['keeper', '--from-words'], { input: words });
  ok('keeper --from-words: the operator identity and K_1', kp.status === 0 && existsSync(kfile), kp.stderr);

  // ---- online
  const noTty = await cli(OP, ['device', 'add', '--name', 'phone']);
  ok('device add without a terminal: refused device_words, exit 1, says --yes-words-checked; nothing issued', noTty.status === 1 && noTty.stderr.includes('device_words') && noTty.stderr.includes('--yes-words-checked')
    && Object.keys((JSON.parse(readFileSync(kfile, 'utf8')) as { workers: object }).workers).length === 0, noTty.stderr);
  ok('device add --name Bad!: usage, exit 2', (await cli(OP, ['device', 'add', '--name', 'Bad!'])).status === 2);
  ok('device show-qr with nothing pending: exit 1', ((r) => r.status === 1 && r.stderr.includes('device_qr'))(await cli(OP, ['device', 'show-qr'])));
  let qr = '';
  const add = cli(OP, ['device', 'add', '--name', 'phone', '--yes-words-checked', '--wait', '90'], { onLine: (l) => { qr = l.trim(); } });
  await Promise.race([waitFor(() => qr), add]);
  ok(`device add prints the online QR text first (${qr}: a relay-tagged code off the default relay), at most 60 characters`, /^SIGELO:DEV:[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}:RELAY\.TEST$/.test(qr) && qr.length <= 60, qr);
  const pngDir = join(PHONE, 'shots'), sq = await cli(OP, ['device', 'show-qr', '--png', pngDir]);
  const png = existsSync(pngDir) ? readdirSync(pngDir).map((f) => join(pngDir, f))[0] : undefined;
  ok('device show-qr: the same text, and a PNG of it (0600)', sq.status === 0 && sq.stdout.trim() === qr && png !== undefined && (statSync(png).mode & 0o777) === 0o600, sq.stderr);
  const scan = await cli(PHONE, ['device', 'scan', '--image', png!, '--name', 'phone', '--wait', '90']);
  const op1 = await add;
  verbose('device add (online)', op1); verbose('device scan (online)', scan);
  const w0 = derived(0), file0 = pool(PHONE, 'phone');
  ok('device scan --image (the PNG, read built in): exit 0, the device is worker 0, derived from the root', scan.status === 0 && json(scan.stdout)['did'] === w0.did && json(scan.stdout)['worker'] === 0, scan.stderr + scan.stdout);
  ok('device add: exit 0, rank safe, worker 0, ours, own', op1.status === 0 && op1.stdout.includes('"rank": "safe"') && json(op1.stdout.split('\n').slice(1).join('\n'))['did'] === w0.did
    && json(op1.stdout.split('\n').slice(1).join('\n'))['tier'] === 'own', op1.stdout + op1.stderr);
  ok('both sides show the same four words', ((a, b) => a !== undefined && a === b)(/its four words: (\w+ \w+ \w+ \w+)/.exec(op1.stderr)?.[1], /Check with them: (\w+ \w+ \w+ \w+)/.exec(scan.stderr)?.[1]), op1.stderr + scan.stderr);
  const st0 = JSON.parse(readFileSync(file0, 'utf8')) as { secret: string; attestations: { body: { iat: number; exp: number } }[] };
  ok('the device file: 0600, worker 0\'s key, an operator attestation of 14 days', (statSync(file0).mode & 0o777) === 0o600 && st0.secret === Buffer.from(w0.seed).toString('hex')
    && st0.attestations[0]!.body.exp - st0.attestations[0]!.body.iat === 14 * 86400);
  const bun = spawnSync('node', [CLI, 'bundle'], { env: { ...env(PHONE), SIGELO_IDENTITY: file0 }, encoding: 'utf8' });
  const v = verify(JSON.parse(bun.stdout) as never, now());
  ok('offline: the device\'s bundle verifies its attestation by the operator', v.did === w0.did && Object.values(v.attestations)[0]?.[0]?.ctx === 'sigelo-relay/operator');
  ok('the roster: worker 0 placed "device", rank safe, online', ((w) => w?.placed === 'device' && w.rank === 'safe' && w.via === 'online')((JSON.parse(readFileSync(kfile, 'utf8')) as { workers: Record<string, { placed: string; rank: string; via: string }> }).workers['0']));
  const sq2 = await cli(OP, ['device', 'show-qr']);
  ok('show-qr after the device was added: nothing pending', sq2.status === 1);
  const again = await cli(X, ['device', 'scan', qr, '--wait', '2']);
  ok('the same QR a second time: refused (park_unknown), no identity left', again.status === 1 && again.stderr.includes('park_unknown') && !existsSync(pool(X, 'device')), again.stderr);
  ok('device scan of a frame-less nonsense text: refused scan_text', ((r) => r.status === 1 && r.stderr.includes('scan_text'))(await cli(X, ['device', 'scan', 'not a code at all'])));
  ok('device scan of a JPEG without zbarimg: scan_format', await (async () => {
    const f = join(X, 'x.jpg'); writeFileSync(f, Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0, 0, 0]));
    const r = await cli(X, ['device', 'scan', '--image', f]);
    return r.status === 1 && r.stderr.includes('scan_format');
  })());

  // ---- the words gate on a terminal
  if (python) {
    let qrN = '';
    const no = inPty(OP, ['device', 'add', '--name', 'nope', '--wait', '60'], [['\\[y/N\\] ', 'n\r']]);
    // The pty's output comes at the end: read the code from the pending show-qr file instead.
    await waitFor(() => { try { qrN = (JSON.parse(readFileSync(human.replace(/\.json$/, '.device-qr.json'), 'utf8')) as { qr: string }).qr; } catch {} return qrN; });
    const sN = await cli(X, ['device', 'scan', qrN, '--name', 'nope', '--wait', '20']);
    const rN = await no;
    verbose('add (n)', rN); verbose('scan (n)', sN);
    ok('the words gate: "n" on the terminal → exit 1, nothing sent, the roster entry dropped', rN.status === 1 && rN.stdout.includes('Do its words read:') && rN.stdout.includes('nothing was sent')
      && !(JSON.parse(readFileSync(kfile, 'utf8')) as { workers: Record<string, { name: string }> }).workers['1'], rN.stdout);
    ok('…and the device got no identity (exit 3, pending)', sN.status === 3 && !existsSync(pool(X, 'nope')), sN.stderr);
    let qrY = '';
    const yes = inPty(OP, ['device', 'add', '--name', 'pad', '--wait', '60'], [['\\[y/N\\] ', 'y\r']]);
    await waitFor(() => { try { qrY = (JSON.parse(readFileSync(human.replace(/\.json$/, '.device-qr.json'), 'utf8')) as { qr: string }).qr; } catch {} return qrY !== qrN ? qrY : ''; });
    const sY = await cli(X, ['device', 'scan', qrY, '--name', 'pad', '--wait', '60']);
    const rY = await yes;
    verbose('add (y)', rY); verbose('scan (y)', sY);
    ok('the words gate: "y" on the terminal → the device is worker 1', rY.status === 0 && sY.status === 0 && json(sY.stdout)['did'] === derived(1).did && rY.stdout.includes(/Check with them: (\w+ \w+ \w+ \w+)/.exec(sY.stderr)?.[1] ?? '#'), rY.stdout + sY.stderr);
  } else console.log('  SKIP the words gate on a terminal: no python3 (pty)');

  // ---- offline
  if (python) {
    const off = await inPty(OP, ['device', 'add', '--name', 'tab', '--offline', '--paged'], [['Enter: the next frame ', '\r'], ['Enter: the words', '\r'], ['Press Enter once typed', '\r']]);
    verbose('add --offline', off);
    const frames = off.stdout.split('\n').filter((l) => /^SGD1\d{4}/.test(l));
    const sixWords = /The words for tab[^\n]*\n\n\s+([a-z]+(?: [a-z]+){5})\n/.exec(off.stdout)?.[1];
    ok(`device add --offline: exit 0, ${frames.length} frames (an 80-column terminal), then six words`, off.status === 0 && frames.length >= 2 && sixWords !== undefined && off.stdout.indexOf(sixWords) > off.stdout.lastIndexOf('frame '), off.stdout.slice(-1500));
    const w1 = derived(2), tabFile = pool(TAB, 'tab');
    ok('no frame and the words in one screen: the screen is cleared between them', /frame \d+ of \d+[\s\S]*\x1b\[2J[\s\S]*The words for tab/.test(off.stdout));
    const part = await cli(TAB, ['device', 'scan', '--text', frames.at(-1)!, '--name', 'tab']);
    ok(`one frame first: exit 3, "1 of ${frames.length}", kept`, part.status === 3 && part.stderr.includes(`1 of ${frames.length} frames`), part.stderr);
    // The operator connects once, so the invite's topic is claimed before the device answers it.
    await cli(OP, ['inbox', '--operator']);
    const rest = frames.slice(0, -1).reverse().join('\n');
    const sc = await inPty(TAB, ['device', 'scan', '--text', rest, '--name', 'tab', '--wait', '20'], [['not shown here\\): ', 'abandon ability able about above absent\r'], ['not shown here\\): ', `${sixWords?.toUpperCase()}\r`]]);
    verbose('scan --offline', sc);
    ok('the rest of the frames, reversed: wrong words refused (device_words, try 1 of 3), the right ones (upper case) open it', sc.stdout.includes('device_words') && sc.stdout.includes('try 1 of 3') && (sc.status === 0 || sc.status === 3), sc.stdout);
    ok('the words are not echoed', !sc.stdout.includes(sixWords ?? '#') && !sc.stdout.includes('abandon ability'));
    const tab = existsSync(tabFile) ? JSON.parse(readFileSync(tabFile, 'utf8')) as { secret: string; provider: string } : null;
    ok('device scan offline: worker 2, derived from the root, written 0600 (provider file here)', tab?.secret === Buffer.from(w1.seed).toString('hex') && tab.provider === 'file' && (statSync(tabFile).mode & 0o777) === 0o600
      && sc.stdout.includes(`worker 2 (${w1.did})`), sc.stdout);
    const fin = await cli(TAB, ['device', 'scan', '--finish', '--into', tabFile]);
    ok('device scan --finish with the invite answered already: nothing pending', fin.status === 0 && fin.stderr.includes('nothing pending'), fin.stderr);
    const tabEnv = { ...env(TAB), SIGELO_IDENTITY: tabFile };
    const opDid = (JSON.parse(spawnSync('node', [CLI, 'whoami', '--operator'], { env: env(OP), encoding: 'utf8' }).stdout) as { did: string }).did;
    const paired = (): boolean => existsSync(tabFile.replace(/\.json$/, '.contacts.json')) && Object.values(contactsOf(tabFile)).some((c) => c.did === opDid && !c.revoked);
    // Each side reads in turn until the pairing is complete on the device (a loaded machine takes more rounds).
    for (let k = 0; k < 8 && !paired(); k++) { await cli(OP, ['inbox', '--operator']); await cli(TAB, ['inbox', '--identity', tabFile]); }
    const tc = spawnSync('node', [CLI, 'contacts'], { env: tabEnv, encoding: 'utf8' });
    ok('the device paired with the operator through the 7-day invite', (JSON.parse(tc.stdout || '{}') as { contacts?: { did: string }[] }).contacts?.some((c) => c.did === opDid) === true, tc.stdout + tc.stderr);
    const ls = await cli(OP, ['device', 'list', '--json']);
    const devs = (json(ls.stdout)['devices'] ?? []) as { name: string; worker: number; rank: string; paired: boolean; ours: boolean; tier: string; via: string }[];
    ok('device list --json: phone, pad (online) and tab (offline), all safe, paired, ours, own', ls.status === 0 && devs.map((d) => `${d.name}:${d.worker}:${d.rank}:${d.via}:${d.paired}:${d.ours}:${d.tier}`).join() === 'phone:0:safe:online:true:true:own,pad:1:safe:online:true:true:own,tab:2:safe:offline:true:true:own', ls.stdout + ls.stderr);
    const lt = await cli(OP, ['device', 'list']);
    ok('device list: one line a device', lt.status === 0 && lt.stdout.trim().split('\n').length === 3 && lt.stdout.includes('tab') && lt.stdout.includes('paired'), lt.stdout);
    ok('device add --offline without a terminal: refused device_tty', ((r) => r.status === 1 && r.stderr.includes('device_tty'))(await cli(OP, ['device', 'add', '--name', 'z', '--offline'])));
    ok('device add --name tab again: device_name_taken', ((r) => r.status === 1 && r.stderr.includes('device_name_taken'))(await cli(OP, ['device', 'add', '--name', 'tab', '--yes-words-checked'])));
  } else console.log('  SKIP offline add and scan: no python3 (pty)');


  // ---- FULL (D2): a second computer online, another offline with a keychain; the list; revoke
  if (python) {
    const opMe = readJ(human) as { secret: string; genesis: object }, opDid = (JSON.parse(spawnSync('node', [CLI, 'whoami', '--operator'], { env: env(OP), encoding: 'utf8' }).stdout) as { did: string }).did;
    const K1 = (readJ(kfile) as { root_hex: string }).root_hex;
    ok('device add --full --yes-words-checked: usage (FULL is confirmed on the terminal), exit 2', (await cli(OP, ['device', 'add', '--name', 'lap', '--full', '--yes-words-checked'])).status === 2);
    ok('device add --full without a terminal: device_tty', ((r) => r.status === 1 && r.stderr.includes('device_tty'))(await cli(OP, ['device', 'add', '--name', 'lap', '--full'])));
    const nf = await inPty(OP, ['device', 'add', '--name', 'lap', '--full'], [['Type FULL to go on: ', 'full\r']]);
    ok('device add --full, "full" typed (not FULL): device_full, exit 1, nothing issued', nf.status === 1 && nf.stdout.includes('device_full') && !existsSync(human.replace(/\.json$/, '.device-qr.json'))
      && !Object.values((readJ(kfile) as { workers: Record<string, { name: string }> }).workers).some((w) => w.name === 'lap'), nf.stdout);

    let qrF = '';
    const addF = inPty(OP, ['device', 'add', '--name', 'lap', '--full', '--wait', '90'], [['Type FULL to go on: ', 'FULL\r'], ['\\[y/N\\] ', 'y\r']]);
    await waitFor(() => { try { qrF = (readJ(human.replace(/\.json$/, '.device-qr.json')) as { qr: string }).qr; } catch {} return qrF; });
    const scF = await cli(LAP, ['device', 'scan', qrF, '--name', 'lap', '--wait', '90']);
    const rF = await addF;
    verbose('add --full', rF); verbose('scan (full)', scF);
    const lapMe = meOf(LAP);
    ok('device add --full online: "type FULL", the words, exit 0, rank full, the list sent', rF.status === 0 && rF.stdout.includes('Type FULL') && rF.stdout.includes('Do its words read:') && /"rank": "full"/.test(rF.stdout) && rF.stdout.includes('sent lap your identity and keeper root'), rF.stdout);
    ok('device scan on the second computer: exit 0, worker 3, and your identity is there', scF.status === 0 && json(scF.stdout)['worker'] === 3 && scF.stderr.includes('your identity is here now') && existsSync(lapMe), scF.stderr + scF.stdout);
    const lm = existsSync(lapMe) ? readJ(lapMe) as { secret: string; genesis: object; provider: string } : null, lk = existsSync(lapMe.replace(/\.json$/, '.keeper.json')) ? readJ(lapMe.replace(/\.json$/, '.keeper.json')) as { root_hex: string; workers: Record<string, { name: string }> } : null;
    ok('…the operator file: the same key and genesis, 0600 (provider file here)', lm?.secret === opMe.secret && canonicalize(lm.genesis) === canonicalize(opMe.genesis) && lm.provider === 'file' && (statSync(lapMe).mode & 0o777) === 0o600);
    ok('…the keeper file: K_1, the roster with lap', lk?.root_hex === K1 && Object.values(lk.workers).some((w) => w.name === 'lap') && (statSync(lapMe.replace(/\.json$/, '.keeper.json')).mode & 0o777) === 0o600);
    const lapW = spawnSync('node', [CLI, 'whoami', '--operator'], { env: env(LAP), encoding: 'utf8' });
    ok('…and it is you there: whoami --operator on the second computer is your DID', (JSON.parse(lapW.stdout || '{}') as { did?: string }).did === opDid, lapW.stderr);
    const lapList = readJ(lapMe.replace(/\.json$/, '.devices.json')) as { seq: number; devices: { name: string; rank: string }[] };
    ok('…the signed list beside it (and beside its device file), lap rank full', lapList.devices.some((d) => d.name === 'lap' && d.rank === 'full') && existsSync(pool(LAP, 'lap').replace(/\.json$/, '.devices.json')));

    // Offline FULL into a home whose OS keychain answers (the fake secret-tool): key and K sealed.
    const steps: [string, string][] = [['Type FULL to go on: ', 'FULL\r'], ...Array.from({ length: 8 }, (): [string, string] => ['Enter: the (next frame|words)|Press Enter once typed', '\r'])];
    const offF = await inPty(OP, ['device', 'add', '--name', 'desk', '--full', '--offline', '--paged'], steps);
    verbose('add --full --offline', offF);
    const fr = offF.stdout.split('\n').filter((l) => /^SGD1\d{4}/.test(l)), w6 = /The words for desk[^\n]*\n\n\s+([a-z]+(?: [a-z]+){5})\n/.exec(offF.stdout)?.[1];
    ok(`device add --full --offline: exit 0, ${fr.length} frames, then the words`, offF.status === 0 && fr.length >= 2 && w6 !== undefined && /"rank": "full"/.test(offF.stdout), offF.stdout.slice(-1500));
    ok('…neither your key nor K_1 in the frames', !fr.join('').includes(K1.toUpperCase()) && !offF.stdout.includes(K1) && !offF.stdout.includes(opMe.secret));
    await cli(OP, ['inbox', '--operator']);
    const scD = await inPty(DESK, ['device', 'scan', '--text', fr.join('\n'), '--name', 'desk', '--wait', '20'], [['not shown here\\): ', `${w6}\r`]]);
    verbose('scan --full offline', scD);
    const deskMe = meOf(DESK), dm = existsSync(deskMe) ? readJ(deskMe) as { provider: string; secret: { provider?: string } | string } : null;
    const dk = existsSync(deskMe.replace(/\.json$/, '.keeper.json')) ? readJ(deskMe.replace(/\.json$/, '.keeper.json')) as { root_hex?: string; root?: { provider: string }; provider?: string } : null;
    ok('device scan --full offline: exit 0 or 3, the device file and your identity written', (scD.status === 0 || scD.status === 3) && existsSync(pool(DESK, 'desk')) && dm !== null && scD.stdout.includes('your identity is here now'), scD.stdout);
    ok('…a keychain answers: your key sealed (provider keychain), K sealed (root, no root_hex)', dm?.provider === 'keychain' && typeof dm.secret === 'object' && dk?.provider === 'keychain' && dk.root?.provider === 'keychain' && dk.root_hex === undefined
      && !readFileSync(deskMe.replace(/\.json$/, '.keeper.json'), 'utf8').includes(K1) && !readFileSync(deskMe, 'utf8').includes(opMe.secret));
    ok('…one keychain item for your DID, one for the device\'s', existsSync(join(DESK, '.fake-keyring', opDid)) && readdirSync(join(DESK, '.fake-keyring')).length === 2);
    const kd = spawnSync('node', [CLI, 'keeper'], { env: env(DESK), encoding: 'utf8' }), dw = spawnSync('node', [CLI, 'whoami', '--operator'], { env: env(DESK), encoding: 'utf8' });
    ok('…unsealed where used: keeper on that machine reads K_1 (its roster has desk), whoami --operator is you', kd.status === 0 && (JSON.parse(kd.stdout || '{}') as { workers?: { name: string }[] }).workers?.some((w) => w.name === 'desk') === true && (JSON.parse(dw.stdout || '{}') as { did?: string }).did === opDid, kd.stderr + dw.stderr);
    // The device pairs through its invite: each side reads until it has.
    const deskFile = pool(DESK, 'desk'), dpaired = (): boolean => existsSync(deskFile.replace(/\.json$/, '.contacts.json')) && Object.values(contactsOf(deskFile)).some((c) => c.did === opDid && !c.revoked);
    for (let k = 0; k < 8 && !dpaired(); k++) { await cli(OP, ['inbox', '--operator']); await cli(DESK, ['inbox', '--identity', deskFile]); }
    ok('…and the offline FULL device paired with you', dpaired());

    // The list: signed by you, sent to every device, taken; again: nothing new.
    const sy = await cli(OP, ['device', 'sync']);
    const opList = readJ(human.replace(/\.json$/, '.devices.json')) as { seq: number; devices: { name: string; rank: string }[]; sig: string };
    ok(`device sync: the list (seq ${opList.seq}: phone, pad, tab, lap, desk) to each paired device`, sy.status === 0 && json(sy.stdout)['synced'] === 5 && opList.devices.map((d) => `${d.name}:${d.rank}`).join() === 'phone:safe,pad:safe,tab:safe,lap:full,desk:full', sy.stdout + sy.stderr);
    const phoneFile = pool(PHONE, 'phone'), ps = await cli(PHONE, ['device', 'sync', '--identity', phoneFile, '--wait', '15']);
    ok('a SAFE device takes it: device sync --identity, the list beside its file, the same signature', ps.status === 0 && (readJ(phoneFile.replace(/\.json$/, '.devices.json')) as { sig: string }).sig === opList.sig, ps.stderr + ps.stdout);
    const ps2 = await cli(PHONE, ['device', 'sync', '--identity', phoneFile, '--wait', '0']);
    ok('…a second sync with nothing new: exit 0', ps2.status === 0, ps2.stderr);
    const ls2 = await cli(LAP, ['device', 'sync', '--identity', pool(LAP, 'lap'), '--wait', '15']);
    ok('a FULL device takes it too, and keeps it beside your identity there', ls2.status === 0 && (readJ(lapMe.replace(/\.json$/, '.devices.json')) as { sig: string }).sig === opList.sig, ls2.stderr);

    // Revoke a reachable device (9.1): wipe, wiped, forgotten.
    const padFile = pool(X, 'pad');
    const rv = cli(OP, ['device', 'revoke', 'pad', '--wait', '40']);
    await new Promise((r) => setTimeout(r, 2000));
    const ws = await cli(X, ['device', 'sync', '--identity', padFile, '--wait', '20']);
    const rvr = await rv;
    verbose('revoke pad', rvr); verbose('sync pad', ws);
    ok('device revoke pad: the device wiped itself and answered; forgotten here', rvr.status === 0 && json(rvr.stdout)['wiped'] === true && json(rvr.stdout)['forgot'] === true && ws.stderr.includes('revoked this device') && !existsSync(padFile), rvr.stdout + rvr.stderr + ws.stderr);
    ok('…its contact gone here, the list marks it revoked', !Object.values(contactsOf(human)).some((c) => c.did === derived(1).did && !c.revoked) && (readJ(human.replace(/\.json$/, '.devices.json')) as { devices: { name: string; revoked?: number }[] }).devices.find((d) => d.name === 'pad')?.revoked !== undefined);
    ok('device revoke pad again: device_revoked, exit 1', ((r) => r.status === 1 && r.stderr.includes('device_revoked'))(await cli(OP, ['device', 'revoke', 'pad'])));
    ok('device revoke nobody: device_unknown', ((r) => r.status === 1 && r.stderr.includes('device_unknown'))(await cli(OP, ['device', 'revoke', 'nobody'])));

    // A FULL device wiped: its identity, your identity and K there, all gone.
    const rd = cli(OP, ['device', 'revoke', 'desk', '--wait', '40']);
    await new Promise((r) => setTimeout(r, 2000));
    const wd = await cli(DESK, ['device', 'sync', '--identity', deskFile, '--wait', '20']);
    const rdr = await rd;
    verbose('revoke desk', rdr); verbose('sync desk', wd);
    ok('device revoke desk (FULL): wiped; your identity, keeper and list gone from it', rdr.status === 0 && json(rdr.stdout)['wiped'] === true && !existsSync(deskFile) && !existsSync(meOf(DESK)) && !existsSync(meOf(DESK).replace(/\.json$/, '.keeper.json')) && !existsSync(meOf(DESK).replace(/\.json$/, '.devices.json')), rdr.stdout + rdr.stderr + wd.stderr);

    // Lost (9.2): revoked and forgotten at once; the steps with the words printed.
    const lo = await cli(OP, ['device', 'revoke', 'lap', '--lost']);
    const lj = json(lo.stdout) as { forgot?: boolean; steps?: { now: string[]; words: string[] } };
    ok('device revoke lap --lost (FULL): exit 0, forgotten now, five steps with the words (operator recovery n+1, K_2, …)', lo.status === 0 && lj.forgot === true && lj.steps?.words.length === 5 && lo.stderr.includes('--identity-n 1') && lo.stderr.includes('--keeper 2'), lo.stdout + lo.stderr);
    ok('…not one of them run: your identity here unchanged', (readJ(human) as { secret: string }).secret === opMe.secret);
    const lt2 = await cli(OP, ['device', 'revoke', 'tab', '--lost']);
    ok('device revoke tab --lost (SAFE): one optional step (recover worker 2 at rotation 1)', lt2.status === 0 && (json(lt2.stdout) as { steps?: { words: string[] } }).steps?.words.length === 1 && lt2.stderr.includes('--agent 2 --keeper 1 --n 1'), lt2.stderr);
    const ps3 = await cli(PHONE, ['device', 'sync', '--identity', phoneFile, '--wait', '15']);
    const pl = readJ(phoneFile.replace(/\.json$/, '.devices.json')) as { seq: number; devices: { name: string; revoked?: number }[] };
    ok('the phone takes the newest list: pad, desk, lap, tab revoked; itself not', ps3.status === 0 && pl.seq === (readJ(human.replace(/\.json$/, '.devices.json')) as { seq: number }).seq
      && pl.devices.filter((d) => d.revoked !== undefined).map((d) => d.name).sort().join() === 'desk,lap,pad,tab', ps3.stderr + JSON.stringify(pl));
    const lsj = await cli(OP, ['device', 'list', '--json']);
    ok('device list --json: lap full revoked, phone live', ((d) => d.find((x) => x.name === 'lap')?.rank === 'full' && !!d.find((x) => x.name === 'lap')?.revoked && d.find((x) => x.name === 'phone')?.revoked === null)((json(lsj.stdout)['devices'] ?? []) as { name: string; rank: string; revoked: number | null }[]), lsj.stdout);
  } else console.log('  SKIP FULL, list and revoke: no python3 (pty)');

  // ---- the seat (D3): an operator and two FULL devices; give, take, take --force; standby refusals; snapshots
  if (python) {
    const words3 = newRoot(), S3 = rootFromMnemonic(words3), K3 = keeperRoot(S3, 1);
    const me3 = meOf(OP3), list3 = (h: string) => readJ(meOf(h).replace(/\.json$/, '.devices.json')) as { seq: number; seat?: { holder: string; epoch: number }; devices: { name: string; did: string }[] };
    const holder = (h: string): string | undefined => ((l) => l.devices.find((d) => d.did === l.seat?.holder)?.name)(list3(h));
    ok('seat: keeper --from-words on a third operator', (await cli(OP3, ['keeper', '--from-words'], { input: words3 })).status === 0);
    const st0 = await cli(OP3, ['device', 'seat']);
    ok('device seat status before any: no seat, exit 0', st0.status === 0 && json(st0.stdout)['seat'] === null, st0.stdout + st0.stderr);
    const init = await cli(OP3, ['device', 'seat', 'init', '--name', 'main']);
    verbose('seat init', init);
    const mainFile = pool(OP3, 'main');
    ok('device seat init --name main: this machine is device main (worker 0), FULL, paired with you, and holds the seat (epoch 1)', init.status === 0 && json(init.stdout)['paired'] === true && existsSync(mainFile)
      && holder(OP3) === 'main' && list3(OP3).seat?.epoch === 1, init.stdout + init.stderr);
    ok('device seat init again: seat_exists, exit 1', ((r) => r.status === 1 && r.stderr.includes('seat_exists'))(await cli(OP3, ['device', 'seat', 'init', '--name', 'other'])));
    // Two FULL devices online (the words gate on a terminal).
    const addFull = async (name: string, home: string): Promise<Run[]> => {
      let q = '';
      const qrFile = me3.replace(/\.json$/, '.device-qr.json');
      rmSync(qrFile, { force: true });
      const a = inPty(OP3, ['device', 'add', '--name', name, '--full', '--wait', '90'], [['Type FULL to go on: ', 'FULL\r'], ['\\[y/N\\] ', 'y\r']]);
      await waitFor(() => { try { q = (readJ(qrFile) as { qr: string }).qr; } catch {} return q; });
      const s = await cli(home, ['device', 'scan', q, '--name', name, '--wait', '90']);
      return [await a, s];
    };
    const [aa, as] = await addFull('alpha', ALPHA);
    verbose('add alpha', aa); verbose('scan alpha', as);
    const [ba, bs] = await addFull('beta', BETA);
    verbose('add beta', ba); verbose('scan beta', bs);
    const alphaFile = pool(ALPHA, 'alpha'), betaFile = pool(BETA, 'beta');
    ok('two FULL devices added at the seat (alpha, beta): your identity on each, the list naming main the seat', aa.status === 0 && as.status === 0 && ba.status === 0 && bs.status === 0
      && existsSync(meOf(ALPHA)) && existsSync(meOf(BETA)) && holder(ALPHA) === 'main' && holder(BETA) === 'main', aa.stdout + as.stderr + ba.stdout + bs.stderr);

    // A contact of yours, paired as the operator at the seat.
    ok('carl: an agent of its own', (await cli(CARL, ['init', '--no-recovery'])).status === 0);
    const inv = await cli(OP3, ['invite', '--operator', '--name', 'carl']), code = inv.stdout.trim().split('\n')[0]!;
    const acc = await cli(CARL, ['accept', code, '--name', 'op', '--wait', '5']);
    const carlDid = (JSON.parse(spawnSync('node', [CLI, 'whoami'], { env: env(CARL), encoding: 'utf8' }).stdout) as { did: string }).did;
    const opHas = (h: string): boolean => { try { return Object.values(contactsOf(meOf(h))).some((c) => c.did === carlDid && !c.revoked); } catch { return false; } };
    for (let k = 0; k < 6; k++) { await cli(OP3, ['inbox', '--operator']); await cli(CARL, ['inbox']); }
    ok('carl paired with you at the seat (invite --operator, accept)', inv.status === 0 && acc.status === 0 && opHas(OP3), inv.stderr + acc.stderr);

    // Standby: every relay verb as you refuses, after reading its device inbox; signing as you works.
    const ui = await cli(ALPHA, ['ui', '--no-open']), invA = await cli(ALPHA, ['invite', '--operator', '--name', 'x']), enA = await cli(ALPHA, ['enrol', '--name', 'x']);
    const inA = await cli(ALPHA, ['inbox', '--operator']), addA = await cli(ALPHA, ['device', 'add', '--name', 'x', '--yes-words-checked']);
    ok('the standby refuses seat_elsewhere, exit 1: ui, invite, enrol, inbox, device add', [ui, invA, enA, inA, addA].every((r) => r.status === 1 && r.stderr.includes('seat_elsewhere') && r.stderr.includes('main')),
      [ui, invA, enA, inA, addA].map((r) => `${r.status} ${r.stderr}`).join('\n'));
    ok('…and allocates no worker index there', !Object.values((readJ(meOf(ALPHA).replace(/\.json$/, '.keeper.json')) as { workers: Record<string, { name: string }> }).workers).some((w) => w.name === 'x'));
    const sigA = spawnSync('node', [CLI, 'bundle', '--operator'], { env: env(ALPHA), encoding: 'utf8' });
    const opDid3 = (JSON.parse(spawnSync('node', [CLI, 'whoami', '--operator'], { env: env(OP3), encoding: 'utf8' }).stdout) as { did: string }).did;
    ok('…but signs as you anywhere: bundle --operator on the standby verifies as your DID', sigA.status === 0 && verify(JSON.parse(sigA.stdout) as never, now()).did === opDid3, sigA.stderr);
    const dsend = await cli(ALPHA, ['send', 'operator', 'from alpha itself', '--identity', alphaFile]);
    ok('a device identity\'s own session, on the standby: it sends as itself', dsend.status === 0, dsend.stderr);

    // Snapshots: the seat sends one to each FULL standby (forced as a file here); they keep it sealed.
    await cli(CARL, ['send', 'op', 'before give']);
    const sy = await cli(OP3, ['device', 'sync'], { env: { SIGELO_SNAPSHOT_INLINE_MAX: '1000' } });
    ok('device sync at the seat: the list, and the snapshot to both standbys (as sigelo-file/0: larger than the inline limit)', sy.status === 0 && json(sy.stdout)['snapshots'] === 2, sy.stdout + sy.stderr);
    const ia = await cli(ALPHA, ['inbox', '--identity', alphaFile]);
    const snapA = meOf(ALPHA).replace(/\.json$/, '.snapshot.sgs');
    ok('inbox on the device takes it by code (never shown): the sealed snapshot kept beside your identity there', ia.status === 0 && existsSync(snapA) && !ia.stdout.includes('sigelo-snapshot'), ia.stdout + ia.stderr);
    const dv = await import(pathToFileURL(join(CONTACT, 'device.mjs')).href) as { openSnapshot(b: Uint8Array, K: Uint8Array): { epoch: number; files: Record<string, string> } };
    const opened = dv.openSnapshot(new Uint8Array(readFileSync(snapA)), K3);
    ok('…it opens under K_1 (epoch 1): your contact store in it names carl; at rest only sealed', opened.epoch === 1 && opened.files['contacts']!.includes(carlDid) && !readFileSync(snapA).includes(Buffer.from(carlDid))
      && (statSync(snapA).mode & 0o777) === 0o600);
    // Files naming carl in plaintext; the inbox log and the page history stay where they were written (§4.4: never in a snapshot without --with-history).
    const plainIn = (h: string): string[] => { const hit: string[] = []; const w = (d: string): void => { for (const f of readdirSync(d, { withFileTypes: true })) { const p = join(d, f.name); if (f.isDirectory()) w(p); else if (!/\.(inbox\.log|history\.jsonl)$/.test(f.name) && readFileSync(p).includes(Buffer.from(carlDid))) hit.push(p); } }; w(h); return hit; };
    const plainOn = (h: string): boolean => plainIn(h).length > 0;
    ok('…and no file on the standby names carl in plaintext', !plainOn(ALPHA));

    // give: the seat to alpha; the snapshot goes; main stops logging in as you.
    const gv = await cli(OP3, ['device', 'seat', 'give', 'alpha']);
    verbose('give', gv);
    ok('device seat give alpha: exit 0, epoch 2', gv.status === 0 && json(gv.stdout)['epoch'] === 2, gv.stdout + gv.stderr);
    const mainIn = await cli(OP3, ['inbox', '--operator']);
    ok('main, now a standby: inbox --operator refuses seat_elsewhere (alpha), and its state is sealed away', mainIn.status === 1 && mainIn.stderr.includes('seat_elsewhere') && mainIn.stderr.includes('alpha')
      && !existsSync(me3.replace(/\.json$/, '.carrier.json')) && !existsSync(me3.replace(/\.json$/, '.contacts.json')) && existsSync(me3.replace(/\.json$/, '.snapshot.sgs')) && !plainOn(join(OP3, '.config', 'sigelo')), mainIn.stderr + plainIn(join(OP3, '.config', 'sigelo')).join());
    const ts = await cli(ALPHA, ['device', 'sync', '--identity', alphaFile, '--wait', '10']);
    verbose('alpha takes', ts);
    ok('alpha takes the seat at its next device sync: the snapshot imported; carl (paired as you) is a contact there', ts.status === 0 && holder(ALPHA) === 'alpha' && opHas(ALPHA), ts.stderr + ts.stdout);
    const ain = await cli(ALPHA, ['inbox', '--operator']);
    ok('alpha logs in as you: what came before the give is there (held in the snapshot)', ain.status === 0 && ain.stdout.includes('before give') && ain.stdout.includes('from alpha itself'), ain.stdout + ain.stderr);
    await cli(CARL, ['send', 'op', 'after give']);
    const ain2 = await cli(ALPHA, ['inbox', '--operator', '--wait', '5']);
    ok('carl writes on: alpha reads it as you', ain2.status === 0 && ain2.stdout.includes('after give'), ain2.stdout + ain2.stderr);

    // take: beta asks; the seat (alpha) answers at its next inbox.
    const tk = cli(BETA, ['device', 'seat', 'take', '--wait', '60']);
    await new Promise((r) => setTimeout(r, 4000));
    let alphaGave: Run | undefined;
    for (let k = 0; k < 6; k++) { alphaGave = await cli(ALPHA, ['inbox', '--operator', '--wait', '3']); if (alphaGave.stderr.includes('the seat went to beta') || alphaGave.status === 1) break; }
    const tkr = await tk;
    verbose('beta take', tkr); verbose('alpha gives', alphaGave!);
    ok('device seat take on beta: alpha answered at its inbox (the seat went to beta), beta holds it (epoch 3), its state imported', tkr.status === 0 && json(tkr.stdout)['seat'] === 3 && alphaGave!.stderr.includes('the seat went to beta') && holder(BETA) === 'beta' && opHas(BETA),
      tkr.stdout + tkr.stderr + alphaGave!.stderr);
    ok('alpha now refuses (seat_elsewhere, beta)', ((r) => r.status === 1 && r.stderr.includes('seat_elsewhere') && r.stderr.includes('beta'))(await cli(ALPHA, ['invite', '--operator', '--name', 'y'])));
    await cli(CARL, ['send', 'op', 'to beta']);
    ok('beta reads carl as you', ((r) => r.status === 0 && r.stdout.includes('to beta'))(await cli(BETA, ['inbox', '--operator', '--wait', '5'])));

    // take --force: beta is "lost"; alpha imports the newest snapshot it holds, every session afresh.
    const tf = now(), fc = await cli(ALPHA, ['device', 'seat', 'take', '--force']);
    verbose('force', fc);
    ok('device seat take --force on alpha: epoch 4, its newest snapshot imported, every session restarted (carl among them)', fc.status === 0 && json(fc.stdout)['seat'] === 4 && json(fc.stdout)['imported'] === 3 && (json(fc.stdout)['restarted'] as number) >= 1 && holder(ALPHA) === 'alpha', fc.stdout + fc.stderr);
    const cs = readJ(meOf(ALPHA).replace(/\.json$/, '.carrier.json')) as { peers: Record<string, { session: { out: { epoch: unknown } } | null; renew?: boolean; prekeys_iat?: number }> };
    ok('…fresh epochs: no outgoing epoch toward carl, a fresh bundle of ours (every one-time key replaced) sent at the take', cs.peers[carlDid]?.session?.out.epoch === null && (cs.peers[carlDid]?.prekeys_iat ?? 0) >= tf && cs.peers[carlDid]?.renew !== true, JSON.stringify(cs.peers[carlDid]?.session?.out.epoch ?? null));
    for (let k = 0; k < 3; k++) { await cli(CARL, ['inbox']); await cli(ALPHA, ['inbox', '--operator']); }
    const sendC = await cli(CARL, ['send', 'op', 'after force']);
    const af = await cli(ALPHA, ['inbox', '--operator', '--wait', '5']);
    ok('after the force: carl\'s messages reach alpha', sendC.status === 0 && af.stdout.includes('after force'), sendC.stderr + af.stdout + af.stderr);
    const back = await cli(ALPHA, ['send', 'carl', 'from the new seat', '--operator']);
    const cb = await cli(CARL, ['inbox', '--wait', '5']);
    ok('…and alpha\'s reach carl', back.status === 0 && cb.stdout.includes('from the new seat'), back.stderr + cb.stdout + cb.stderr);
    const bIn = await cli(BETA, ['inbox', '--operator']), bUi = await cli(BETA, ['ui', '--no-open']);
    ok('beta, back: it reads its device inbox first, sees epoch 4 and refuses (inbox, ui): seat_elsewhere; its state sealed away', bIn.status === 1 && bIn.stderr.includes('seat_elsewhere') && bUi.status === 1 && bUi.stderr.includes('seat_elsewhere')
      && !existsSync(meOf(BETA).replace(/\.json$/, '.contacts.json')) && !plainOn(BETA), bIn.stderr + bUi.stderr + plainIn(BETA).join());
    const sb = await cli(BETA, ['device', 'seat']);
    ok('device seat on beta: alpha holds it, epoch 4; a snapshot held here', sb.status === 0 && (json(sb.stdout)['seat'] as { holder: string; epoch: number }).holder === 'alpha' && (json(sb.stdout)['seat'] as { epoch: number }).epoch === 4 && json(sb.stdout)['snapshot'] !== null, sb.stdout);
    const bsend = await cli(BETA, ['send', 'operator', 'beta as itself', '--identity', betaFile]);
    ok('beta\'s device identity is its own, standby or not: it sends', bsend.status === 0, bsend.stderr);
  } else console.log('  SKIP the seat: no python3 (pty)');


  // ---- a FULL device restored from seed in an app (apps/web/seed.mjs, sigelo-contact/restore.mjs; design/apps-seed.md)
  {
    const CDIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'contact');
    const RS = await import(pathToFileURL(join(CDIR, 'restore.mjs')).href) as { restoreFromWords(w: string, o: object): { identity: { secret: string; genesis: { key: string } }; keeper: Record<string, unknown>; device: object; notes: object; list: { seat: { holder: string; epoch: number }; devices: { name: string; worker: number; did: string; rank: string; added: number; by: string }[] }; did: string; worker: string } };
    const DV = await import(pathToFileURL(join(CDIR, 'device.mjs')).href) as { signList(l: object, sign: (b: object) => string): object; nextSeat(c: unknown, h: string, t: number): object };
    const { sign: signWith } = await import('sigelo');
    const W2 = newRoot(), t0 = now(), REST = mkdtempSync(join(tmpdir(), 'sigelo-dev-rest-')), REF = mkdtempSync(join(tmpdir(), 'sigelo-dev-ref-'));
    try {
      const r = RS.restoreFromWords(W2, { name: 'rphone', relay: 'relay.test', net: 'stagenet', restore: { restore_height: 3100000 }, seat: 'here', now: t0 });
      // The app's files, placed where sigelo-agent keeps them (the device's own file in the agents' directory).
      const me = meOf(REST), dev = pool(REST, 'rphone'), put = (f: string, o: unknown): void => { mkdirSync(dirname(f), { recursive: true, mode: 0o700 }); writeFileSync(f, JSON.stringify(o, null, 2), { mode: 0o600 }); };
      put(me, r.identity); put(me.replace(/\.json$/, '.keeper.json'), r.keeper); put(me.replace(/\.json$/, '.seat.json'), r.notes); put(me.replace(/\.json$/, '.devices.json'), r.list); put(dev, r.device); put(dev.replace(/\.json$/, '.devices.json'), r.list);
      const ref = await cli(REF, ['keeper', '--from-words'], { input: W2 });
      ok('seed-restored: the app\'s operator file and K_1 are what keeper --from-words writes for the same words', ref.status === 0 && JSON.stringify(readJ(meOf(REF))) === JSON.stringify(r.identity)
        && (readJ(meOf(REF).replace(/\.json$/, '.keeper.json')) as { root_hex: string }).root_hex === r.keeper['root_hex'], ref.stderr);
      const st = await cli(REST, ['device', 'seat']);
      ok('seed-restored FULL device: device seat says it holds the seat, epoch 1 (seat init semantics)', st.status === 0 && json(st.stdout)['holds'] === true && (json(st.stdout)['seat'] as { holder: string; epoch: number }).holder === 'rphone'
        && (json(st.stdout)['seat'] as { epoch: number }).epoch === 1 && json(st.stdout)['here'] === 'rphone', st.stdout + st.stderr);
      const ls = await cli(REST, ['device', 'list', '--json']);
      ok('seed-restored: device list shows it, FULL, worker 0', ls.status === 0 && /"rphone"/.test(ls.stdout) && /"full"/.test(ls.stdout), ls.stdout + ls.stderr);
      const kp = await cli(REST, ['keeper']);
      ok('seed-restored: the keeper file reads as the CLI\'s (keeper 1; net and restore_height kept)', kp.status === 0 && json(kp.stdout)['keeper'] === 1 && (readJ(me.replace(/\.json$/, '.keeper.json')) as { net?: string; restore_height?: number }).restore_height === 3100000, kp.stdout + kp.stderr);
      const in1 = await cli(REST, ['inbox', '--operator']);
      ok('seed-restored: the seat is here, so it logs in as you (inbox --operator, exit 0)', in1.status === 0, in1.stderr);
      // The seat moved away (a newer list, signed by you, naming another FULL device): the restored device refuses.
      const secret = Uint8Array.from(Buffer.from(r.identity.secret, 'hex')), tab = { name: 'rtab', worker: 1, did: 'did:sigelo:zTabTabTabTabTabTabTabTabTabTabTabTab', rank: 'full', added: t0, by: r.did };
      const moved = DV.signList({ operator: r.did, seq: 2, iat: t0 + 1, devices: [...r.list.devices, tab], seat: DV.nextSeat(r.list.seat, tab.did, t0 + 1) }, (b) => signWith(secret, b));
      put(me.replace(/\.json$/, '.devices.json'), moved); put(dev.replace(/\.json$/, '.devices.json'), moved);
      const in2 = await cli(REST, ['inbox', '--operator']), ui2 = await cli(REST, ['ui', '--no-open']);
      ok('seed-restored, the seat elsewhere: inbox --operator and ui refuse seat_elsewhere (rtab), exit 1', in2.status === 1 && in2.stderr.includes('seat_elsewhere') && in2.stderr.includes('rtab') && ui2.status === 1 && ui2.stderr.includes('seat_elsewhere'), in2.stderr + ui2.stderr);
      const tk = await cli(REST, ['device', 'seat', 'take', '--force']);
      const in3 = await cli(REST, ['inbox', '--operator']);
      ok('seed-restored: device seat take --force takes it back (epoch 3), then it logs in as you again', tk.status === 0 && json(tk.stdout)['seat'] === 3 && json(tk.stdout)['holder'] === 'rphone' && in3.status === 0, tk.stdout + tk.stderr + in3.stderr);
      secret.fill(0);
      // The GTK app restores, then takes the seat with seat init: offline first (stopped before the list), then again online.
      const off = await cli(REF, ['device', 'seat', 'init', '--name', 'gphone'], { env: { SIGELO_RELAY_ENDPOINTS: JSON.stringify({ 'relay.test': { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:1' } }) } });
      const on = await cli(REF, ['device', 'seat', 'init', '--name', 'gphone']), sr = await cli(REF, ['device', 'seat']);
      ok('device seat init offline stops (exit 1); run again online it goes on with the same device (not device_name_taken) and holds the seat', off.status === 1 && on.status === 0 && json(on.stdout)['worker'] === 0 && json(sr.stdout)['holds'] === true, off.stderr + on.stderr + on.stdout);
      // The GTK app's restore: keeper --from-words --keychain (a Secret Service: the fake secret-tool), the wallet's birth and net kept.
      const KC = mkdtempSync(join(tmpdir(), 'sigelo-dev-kc-')), NOKC = mkdtempSync(join(tmpdir(), 'sigelo-dev-nokc-'));
      extra[KC] = { PATH: `${FAKE}:${process.env['PATH'] ?? ''}`, SIGELO_KEY_PROVIDER: '' };
      try {
        const kc = await cli(KC, ['keeper', '--from-words', '--keychain', '--net', 'stagenet', '--restore-date', '2024-02-29'], { input: W2 });
        const kme = readJ(meOf(KC)) as { provider?: string; secret: unknown }, kk = readJ(meOf(KC).replace(/\.json$/, '.keeper.json')) as Record<string, unknown>;
        ok('keeper --from-words --keychain: the key and K_1 sealed in the keychain (no hex on disk), net and restore_date kept, the same DID', kc.status === 0 && kme.provider === 'keychain' && typeof kme.secret === 'object'
          && kk['root_hex'] === undefined && (kk['root'] as { provider?: string })?.provider === 'keychain' && kk['net'] === 'stagenet' && kk['restore_date'] === '2024-02-29' && typeof kk['created'] === 'string'
          && (json(kc.stdout)['me'] as { did?: string })?.did === r.did && !readFileSync(meOf(KC), 'utf8').includes(r.identity.secret), kc.stderr);
        const ks = await cli(KC, ['keys', 'status', '--operator']);
        ok('…and the sealed key signs for you (keys status)', ks.status === 0 && json(ks.stdout)['signs'] === true, ks.stdout + ks.stderr);
        // A Secret Service that does not answer (secret-tool says why, as without a D-Bus session).
        const NOBIN = join(NOKC, 'bin'); mkdirSync(NOBIN);
        writeFileSync(join(NOBIN, 'secret-tool'), '#!/bin/sh\necho "Cannot autolaunch D-Bus without X11 $DISPLAY" >&2\nexit 1\n', { mode: 0o755 });
        const nk = await cli(NOKC, ['keeper', '--from-words', '--keychain'], { input: W2, env: { PATH: `${NOBIN}:${process.env['PATH'] ?? ''}` } });
        ok('keeper --from-words --keychain without a keychain: keychain_unavailable, nothing written', nk.status === 1 && nk.stderr.includes('keychain_unavailable') && !existsSync(meOf(NOKC)), nk.stderr);
        const both = await cli(NOKC, ['keeper', '--from-words', '--restore-height', '1', '--restore-date', '2024-02-29'], { input: W2 }), net = await cli(NOKC, ['keeper', '--from-words', '--net', 'testnet'], { input: W2 });
        ok('keeper: --restore-height with --restore-date, or --net testnet: usage, exit 2, nothing written', both.status === 2 && net.status === 2 && !existsSync(meOf(NOKC)), both.stderr + net.stderr);
      } finally { for (const d of [KC, NOKC]) rmSync(d, { recursive: true, force: true }); }
    } finally { for (const d of [REST, REF]) rmSync(d, { recursive: true, force: true }); }
  }

  // A plain message from the phone: the operator's inbox log has it, and nothing key-carrying.
  const sent = await cli(PHONE, ['send', 'operator', 'hello from the phone', '--identity', pool(PHONE, 'phone')]);
  const got = await cli(OP, ['inbox', '--operator']);
  ok('a message from the device reaches the operator (own: pushed in full)', sent.status === 0 && got.stdout.includes('hello from the phone'), sent.stderr + got.stdout + got.stderr);

  // ---- nothing key-carrying in any inbox.log
  const logs: string[] = [];
  const walk = (d: string): void => { for (const f of readdirSync(d, { withFileTypes: true })) { const p = join(d, f.name); if (f.isDirectory()) walk(p); else if (f.name.endsWith('.inbox.log')) logs.push(readFileSync(p, 'utf8')); } };
  for (const h of [OP, PHONE, TAB, X, LAP, DESK, OP3, ALPHA, BETA, CARL]) walk(h);
  const all = logs.join('\n'), seeds = [derived(0).seed, derived(1).seed, derived(2).seed, derived(3).seed].map((s) => Buffer.from(s).toString('hex'));
  seeds.push((readJ(human) as { secret: string }).secret, (readJ(kfile) as { root_hex: string }).root_hex);
  ok(`UNLOGGED: ${logs.length} inbox log(s) (the message in one), none with sigelo-identity/0, sigelo-enrol/1 or sigelo-device/1, nor a device key, your key or K`, logs.length > 0 && all.includes('hello from the phone') && !/sigelo-(identity|enrol|device)\//.test(all) && seeds.every((s) => !all.includes(s)));
} finally {
  await relay.close?.();
  for (const d of [D, OP, PHONE, TAB, X, LAP, DESK, OP3, ALPHA, BETA, CARL]) rmSync(d, { recursive: true, force: true });
}
done(import.meta.filename);
