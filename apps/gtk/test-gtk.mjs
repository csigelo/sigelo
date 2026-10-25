// SPDX-License-Identifier: MIT
// The GTK phone app without a window: install.sh (dry run, then into a temporary prefix), the
// start page's scripts, and the installed sigelo-app.js under gjs (SIGELO_APP_TEST): sealed calls to
// a real `ui --remote` (scope, a revoked text), this phone's page through `ui --app`, and a computer's
// page over the relay (SIGELO:CTL:, control pair, control ui --app; SKIP without the relay checkout).
//   node apps/gtk/test-gtk.mjs     (needs gjs; a checkout with ts/dist, contact/ and adapters/moadim/ node_modules)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { newRoot } from '../../ts/dist/keys.js';

const HERE = import.meta.dirname, ROOT = join(HERE, '..', '..'), CLI = join(ROOT, 'adapters', 'moadim', 'cli.ts');
let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => { if (cond) { passed++; console.log(`ok   ${name}`); } else { failed++; console.log(`FAIL ${name}${detail ? `\n     ${detail}` : ''}`); } };
const T = mkdtempSync(join(tmpdir(), 'sigelo-gtk-')), P = join(T, 'prefix'), H = join(T, 'home');
mkdirSync(H, { recursive: true, mode: 0o700 });

// ── scripts parse; install.sh dry run writes nothing; then a real install into the prefix
ok('install.sh: sh -n', spawnSync('sh', ['-n', join(HERE, 'install.sh')]).status === 0);
for (const f of ['web/start.js', 'web/seed-check.mjs', '../../adapters/moadim/shim-zlib.mjs', '../../adapters/moadim/shim-kdf.mjs']) ok(`${f}: node --check`, spawnSync(process.execPath, ['--check', join(HERE, f)]).status === 0);
const dry = spawnSync('sh', [join(HERE, 'install.sh'), '--dry-run', '--prefix', P], { encoding: 'utf8' });
ok('install.sh --dry-run: exit 0, every target under the prefix, nothing written', dry.status === 0 && !existsSync(P)
  && dry.stdout.split('\n').filter((l) => /^(cp|write) /.test(l)).every((l) => l.includes(` ${P}/`)), dry.stdout + dry.stderr);
const ins = spawnSync('sh', [join(HERE, 'install.sh'), '--prefix', P], { encoding: 'utf8' });
const S = join(P, 'share', 'sigelo-app');
const want = ['bin/sigelo-app', 'share/applications/io.sigelo.App.desktop', 'share/icons/hicolor/scalable/apps/io.sigelo.App.svg', 'share/sigelo-app/sigelo-app.js',
  'share/sigelo-app/lib/remote-client.mjs', 'share/sigelo-app/lib/jcs.js', 'share/sigelo-app/lib/noble-ciphers/chacha.js', 'share/sigelo-app/web/start.html', 'share/sigelo-app/web/ui.js',
  'share/sigelo-app/web/shim-zlib.mjs', 'share/sigelo-app/web/shim-kdf.mjs', 'share/sigelo-app/web/seed-check.mjs', 'share/sigelo-app/web/monero-words.js'];
ok('install.sh --prefix: the launcher, desktop file, icon, app and page files', ins.status === 0 && want.every((f) => existsSync(join(P, f))), ins.stderr + want.filter((f) => !existsSync(join(P, f))).join(' '));
ok('install.sh: QR reading installed beside the page (contact/qr-decode.mjs, qr.mjs), no "scanning off" warning', ['qr-decode.mjs', 'qr.mjs'].every((f) => existsSync(join(S, 'web', f))) && !/scanning off/.test(ins.stderr), ins.stderr);
const desk = readFileSync(join(P, 'share/applications/io.sigelo.App.desktop'), 'utf8');
ok('desktop file: Exec the installed launcher, icon io.sigelo.App, mobile form factor', desk.includes(`Exec=${P}/bin/sigelo-app\n`) && desk.includes('Icon=io.sigelo.App') && desk.includes('X-Purism-FormFactor=Workstation;Mobile;'));
const v = spawnSync('desktop-file-validate', [join(HERE, 'io.sigelo.App.desktop')], { encoding: 'utf8' });
if (v.error) console.log('SKIP desktop-file-validate: not installed'); else ok('desktop-file-validate', v.status === 0 && v.stdout.trim() === '', v.stdout);
const svg = readFileSync(join(ROOT, 'assets', 'brand', 'app-icon.svg'), 'utf8');
ok('icon: assets/brand/app-icon.svg (the seal), SVG, no text, no external reference; installed as io.sigelo.App.svg byte for byte', svg.startsWith('<svg') && !/<text|href=|url\(/.test(svg)
  && readFileSync(join(P, 'share/icons/hicolor/scalable/apps/io.sigelo.App.svg'), 'utf8') === svg);
const unin = spawnSync('sh', [join(HERE, 'install.sh'), '--uninstall', '--dry-run', '--prefix', P], { encoding: 'utf8' });
ok('install.sh --uninstall --dry-run: removes only the app\'s paths', unin.status === 0 && unin.stdout.includes(`rm -rf ${S}`) && !/rm -rf \S+\/(bin|share)\n/.test(unin.stdout));

// ── a computer: `ui --remote` on 127.0.0.1, no relay reachable
const human = join(H, 'me.local.json');
const ends = JSON.stringify({ 'relay.test': { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:1' } });
const env = { PATH: process.env.PATH, HOME: H, SIGELO_KEY_PROVIDER: 'file', SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: ends };
spawnSync(process.execPath, [CLI, 'keeper', '--from-words', '--identity', human], { env, input: newRoot(), encoding: 'utf8' });
const page = async (...a) => {
  const c = spawn(process.execPath, [CLI, 'ui', '--identity', human, '--no-open', '--remote', '--listen', '127.0.0.1', ...a], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let so = ''; c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', () => {});
  const end = Date.now() + 20000;
  while (!/SIGELO:UI:[^\n]+\n/.test(so) && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
  return { line: /SIGELO:UI:[^\n]+/.exec(so)?.[0] ?? '', stop: () => new Promise((r) => { c.on('close', r); c.kill('SIGTERM'); }) };
};
const gjs = (vars) => new Promise((resolve) => { vars = { SIGELO_APP_DEBUG: '1', ...vars };
  const c = spawn('gjs', ['-m', join(S, 'sigelo-app.js')], { env: { ...env, ...vars }, stdio: ['ignore', 'pipe', 'pipe'] });
  let so = '', se = ''; c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', (d) => { se += d; });
  const t = setTimeout(() => c.kill('SIGKILL'), 60000);
  c.on('close', () => { clearTimeout(t); try { resolve({ ...JSON.parse(so.trim().split("\n").at(-1)), ...(se && { stderr: se }) }); } catch { resolve({ raw: so + se }); } });
});
{
  const a = await page('--name', 'phone', '--scope', 'read');
  const r = await gjs({ SIGELO_APP_TEST: 'remote', SIGELO_APP_CONTROL: `  ${a.line}\r\n` });
  ok('gjs, remote (text pasted with blanks around it): sealed GET /api/me, /api/state and /api/links → 200 through Soup; forget outside scope read → 403; /api/devices never remote → 403', r.ok === true && r.did?.startsWith('did:sigelo:') && r.state === 200 && r.links === 200 && r.scope === 403 && r.devices === 403, JSON.stringify(r).slice(0, 400));
  const bad = await gjs({ SIGELO_APP_TEST: 'remote', SIGELO_APP_CONTROL: 'SIGELO:UI:127.0.0.1:1:AB' });
  ok('gjs, remote: a malformed text refused before any call', bad.ok === false && /Not a computer's text/.test(bad.message ?? ''), JSON.stringify(bad));
  await a.stop();
  spawnSync(process.execPath, [CLI, 'ui', '--identity', human, '--revoke-control', 'phone'], { env });
  const b = await page('--name', 'other');
  const rev = await gjs({ SIGELO_APP_TEST: 'remote', SIGELO_APP_CONTROL: a.line });
  ok('gjs, remote: a revoked text → refused, nothing opened', rev.ok === false && /refused this phone's text/.test(rev.message ?? ''), JSON.stringify(rev));
  await b.stop();
  const gone = await gjs({ SIGELO_APP_TEST: 'remote', SIGELO_APP_CONTROL: b.line });
  ok('gjs, remote: the computer\'s page stopped → "No answer"', gone.ok === false && /No answer from 127\.0\.0\.1/.test(gone.message ?? ''), JSON.stringify(gone));
}

// ── this phone: `ui --app` spawned by the app, the page answers, the child ends with the app
{
  const start = readFileSync(join(S, 'web', 'start.html'), 'utf8');
  ok('start page: this phone\'s form shows the relay field, relay.sigelo.ai pre-filled, and that a 12-character code names its own relay',
    /<input id="relay" value="relay\.sigelo\.ai"/.test(start) && start.includes('12-character code always names its own relay') && readFileSync(join(S, 'web', 'start.js'), 'utf8').includes("ask('self', relayEdited"));
  const r = await gjs({ SIGELO_APP_TEST: 'self', SIGELO_APP_IDENTITY: human, SIGELO_AGENT: JSON.stringify([process.execPath, CLI]), SIGELO_APP_RELAY: 'corp.example.com' });
  ok('gjs, this phone: the relay set through the page (POST /api/settings) → 200, kept as corp.example.com', r.relay === 200 && r.setting === 'corp.example.com', JSON.stringify(r).slice(0, 400));
  ok('gjs, this phone: ui --app spawned, GET /api/me with its token → 200; stopped → exit 0', r.ok === true && r.me === 200 && r.exited === true && r.code === 0, JSON.stringify(r).slice(0, 400));
  ok('gjs, this phone: the page serves the device routes (GET /api/devices → 200, no devices yet) and the QR decoder', r.devices === 200 && r.devices_list === 0 && r.decoder === 200, JSON.stringify(r).slice(0, 400));
  const n = await gjs({ SIGELO_APP_TEST: 'self', SIGELO_APP_IDENTITY: join(H, 'none.local.json'), SIGELO_AGENT: JSON.stringify([process.execPath, CLI]) });
  ok('gjs, this phone: no identity → ui\'s own message (keeper --from-words)', n.ok === false && /keeper --from-words/.test(n.message ?? ''), JSON.stringify(n).slice(0, 400));
}


// ── restore from seed (design/apps-seed.md): the start page's form, its word check, and the app's restore:
// keeper --from-words --keychain on stdin (a Secret Service: a fake secret-tool keeping items under $HOME), then the seat
{
  const start = readFileSync(join(S, 'web', 'start.html'), 'utf8'), js = readFileSync(join(S, 'web', 'start.js'), 'utf8');
  const box = /<textarea id="seed-words"[^>]*>/.exec(start)?.[0] ?? '';
  ok('start page: Restore from seed beside this phone and a computer: "I have my 25 words on paper" first, one box without autocomplete, autocorrect, capitals or spellcheck, height or date, network, the seat elsewhere',
    start.includes('<h2>Restore from seed</h2>') && start.includes('I have my 25 words on paper') && ['autocomplete="off"', 'autocorrect="off"', 'autocapitalize="none"', 'spellcheck="false"'].every((a) => box.includes(a))
    && start.includes('id="seed-height"') && start.includes('value="stagenet"') && start.includes('id="seed-elsewhere"') && start.includes('Take the seat here'), box);
  ok('start.js: the words go to the app once (restore), the clipboard emptied after a paste (clipclear), no word ever shown back or logged',
    js.includes("ask('restore', { words: $('seed-words').value") && js.includes("ask('clipclear')") && !/console\.|show (the |your )?(seed|25 words)/i.test(js));
  const { checkWords: gtkCheck } = await import(pathToFileURL(join(S, 'web', 'seed-check.mjs')).href);
  const { checkWords: libCheck } = await import(pathToFileURL(join(ROOT, 'contact', 'restore.mjs')).href);
  const w = newRoot(), l = w.split(' '), cases = [w, l.slice(0, 7).join(' '), [l[1], l[0], ...l.slice(2)].join(' '), [...l.slice(0, 3), 'zzzq', ...l.slice(4)].join(' '), `${w} ${l[0]}`, l.map((x) => x.slice(0, 3)).join('\n'), w.toUpperCase()];
  ok('seed-check.mjs (the page\'s live check) agrees with contact/restore.mjs on 25 words, partial, swapped, a bad word, 26, prefixes, capitals',
    cases.every((c) => { const a = gtkCheck(c), b = libCheck(c); return a.ok === b.ok && a.count === b.count && (a.error === null) === (b.error === null); }) && gtkCheck(w).ok === true && gtkCheck(cases[2]).ok === false);
  const KB = join(T, 'kbin'); mkdirSync(KB, { recursive: true });
  writeFileSync(join(KB, 'secret-tool'), '#!/bin/sh\nd="$HOME/.fake-keyring"; mkdir -p "$d"\ncase "$1" in\n  lookup) [ -f "$d/$5" ] && cat "$d/$5" && exit 0; exit 1;;\n  store) cat > "$d/$6"; exit 0;;\n  clear) rm -f "$d/$5"; exit 0;;\nesac\nexit 2\n', { mode: 0o755 });
  const restoreIn = async (home, vars) => { mkdirSync(home, { recursive: true, mode: 0o700 }); return gjs({ HOME: home, PATH: `${KB}:${process.env.PATH}`, SIGELO_KEY_PROVIDER: '', SIGELO_AGENT: JSON.stringify([process.execPath, CLI]), SIGELO_APP_TEST: 'restore', SIGELO_APP_WORDS: w, ...vars }); };
  const H1 = join(T, 'home-seed'), r1 = await restoreIn(H1, { SIGELO_APP_HEIGHT: '3100000' });
  const me1 = join(H1, '.config', 'sigelo', 'me.local.json'), k1 = me1.replace(/\.json$/, '.keeper.json');
  const id1 = existsSync(me1) ? JSON.parse(readFileSync(me1, 'utf8')) : {}, kp1 = existsSync(k1) ? JSON.parse(readFileSync(k1, 'utf8')) : {};
  const REF = join(T, 'home-ref'); mkdirSync(REF, { recursive: true });
  spawnSync(process.execPath, [CLI, 'keeper', '--from-words', '--identity', join(REF, 'me.local.json')], { env: { PATH: process.env.PATH, HOME: REF, SIGELO_KEY_PROVIDER: 'file' }, input: w, encoding: 'utf8' });
  const ref = JSON.parse(readFileSync(join(REF, 'me.local.json'), 'utf8'));
  ok('gjs, restore: keeper --from-words --keychain: your key and K_1 sealed in the keyring (no hex on disk), stagenet and restore_height kept, the same identity as keeper --from-words',
    r1.ok === true && id1.provider === 'keychain' && typeof id1.secret === 'object' && JSON.stringify(id1.genesis) === JSON.stringify(ref.genesis) && !readFileSync(me1, 'utf8').includes(ref.secret)
    && kp1.root_hex === undefined && kp1.root?.provider === 'keychain' && kp1.net === 'stagenet' && kp1.restore_height === 3100000 && readdirSync(join(H1, '.fake-keyring')).length >= 1, JSON.stringify(r1).slice(0, 400));
  ok('gjs, restore: no relay here: the seat not taken yet, said how (device seat init when online); not a standby', r1.seat === 'pending' && /device seat init --name gphone/.test(r1.message ?? '') && r1.standby === null && r1.refused === false, JSON.stringify(r1).slice(0, 400));
  const H2 = join(T, 'home-standby'), r2 = await restoreIn(H2, { SIGELO_APP_ELSEWHERE: '1', SIGELO_APP_TAKE: '1' });
  ok('gjs, restore with the seat on another device: a standby (this phone\'s page refused); Take the seat here runs seat init, refused offline, still a standby',
    r2.ok === true && r2.seat === 'elsewhere' && r2.standby === 'gphone' && r2.refused === true && r2.take?.ok === false && existsSync(join(H2, '.config', 'sigelo-app', 'standby')), JSON.stringify(r2).slice(0, 400));
  const bad = await restoreIn(join(T, 'home-bad'), { SIGELO_APP_WORDS: l.slice(0, 24).join(' ') });
  ok('gjs, restore: 24 words refused by keeper (no word echoed), nothing written', bad.ok === false && !l.some((x) => (bad.message ?? '').split(/\W+/).includes(x) && x.length > 3) && !existsSync(join(T, 'home-bad', '.config', 'sigelo', 'me.local.json')), JSON.stringify(bad).slice(0, 300));
}

// ── over the relay: a computer's `ui --remote --relay` (in this process), the app pairs by SIGELO:CTL:
// through `sigelo-agent control pair`, the words confirmed on the computer, then `control ui --app`
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(ROOT, 'relay');
if (!existsSync(join(RELAY_DIR, 'server.mjs')) || !existsSync(join(RELAY_DIR, 'node_modules'))) console.log('SKIP gtk over the relay: no relay checkout with its node_modules');
else {
  const { startRelay } = await import(join(RELAY_DIR, 'server.mjs'));
  const { TIERS, relayPolicy } = await import(join(RELAY_DIR, 'allowance.mjs'));
  const R = join(T, 'relay'); mkdirSync(R, { recursive: true });
  const relay = await startRelay({ host: 'relay.test', db: join(R, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1, log: () => {},
    policy: (c) => relayPolicy(c, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 }, freeQueue: 64 * 1024 * 1024, tiers: TIERS }) });
  const endpoints = { 'relay.test': { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } };
  const U = await import(join(ROOT, 'adapters', 'moadim', 'sigelo-agent-ui.ts'));
  const op = join(H, 'op.local.json');
  mkdirSync(join(H, 'op-agents'), { recursive: true });
  spawnSync(process.execPath, [CLI, 'keeper', '--from-words', '--identity', op], { env, input: newRoot(), encoding: 'utf8' });
  const pg = await U.startUi({ identity: op, agents: join(H, 'op-agents'), carrier: { relay: 'relay.test', endpoints }, remote: { relay: true, name: 'phone', scope: 'read' } });
  const go = join(T, 'confirmed');
  try {
    const renv = { ...env, SIGELO_RELAY_ENDPOINTS: JSON.stringify(endpoints), SIGELO_RELAY_REGISTRY: 'off', SIGELO_CONTROL: join(H, 'control.local.json'), SIGELO_AGENT: JSON.stringify([process.execPath, CLI]) };
    const c = spawn('gjs', ['-m', join(S, 'sigelo-app.js')], { env: { ...renv, SIGELO_APP_TEST: 'relay', SIGELO_APP_CONTROL: ` ${pg.relay.line}\n`, SIGELO_APP_WAIT: go }, stdio: ['ignore', 'pipe', 'pipe'] });
    let so = '', se = ''; c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', (d) => { se += d; });
    const closed = new Promise((r) => c.on('close', r)), killer = setTimeout(() => c.kill('SIGKILL'), 120000);
    const seen = await pg.relay.paired();
    const end = Date.now() + 30000;
    while (!/"paired"/.test(so) && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
    const appWords = (() => { try { return JSON.parse(/\{"paired"[^\n]*\}/.exec(so)[0]).paired; } catch { return null; } })();
    ok('gjs, over the relay: SIGELO:CTL: pasted (blanks around it) → control pair; the computer sees the same four words', seen.name === 'phone' && typeof appWords === 'string' && appWords === seen.words, `${JSON.stringify(seen)} ${so} ${se.slice(-500)}`);
    await pg.relay.confirm('phone', true);
    writeFileSync(go, '');
    await closed; clearTimeout(killer);
    let r = {};
    try { r = JSON.parse(so.trim().split('\n').at(-1)); } catch {}
    const did = JSON.parse(readFileSync(op, 'utf8')).genesis ? (await import(join(ROOT, 'ts', 'dist', 'sigelo.js'))).did(JSON.parse(readFileSync(op, 'utf8')).genesis) : '';
    ok('gjs, over the relay: control ui --app serves the computer\'s page here: GET /api/me, /api/state → 200 (the operator\'s DID); the control kept; stopped with the app', r.ok === true && r.me === 200 && r.did === did && r.state === 200 && r.again === 200 && r.kept === true && r.exited === true,
      JSON.stringify(r).slice(0, 400) + se.slice(-400));
    const st = (await import('node:fs')).statSync(join(H, 'control.local.json'));
    const cf = JSON.parse(readFileSync(join(H, 'control.local.json'), 'utf8'));
    ok('control.local.json: 0600, a random key, recovery null, the operator\'s DID; not an attested identity', (st.mode & 0o777) === 0o600 && cf.genesis.recovery === null && cf.operator === r.did && cf.attestations.length === 0);
  } finally {
    await pg.close(); await relay.close?.();
  }
}

rmSync(T, { recursive: true, force: true });
console.log(failed === 0 ? `\nALL PASS test-gtk.mjs (${passed} ok)` : `\nFAIL test-gtk.mjs (${failed} of ${passed + failed} failed)`);
process.exit(failed === 0 ? 0 : 1);
