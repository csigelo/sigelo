// SPDX-License-Identifier: MIT
// The GTK phone app without a window: install.sh (dry run, then into a temporary prefix), the
// start page's scripts, and the installed sigelo-app.js under gjs (SIGELO_APP_TEST): sealed calls to
// a real `ui --remote` (scope, a revoked text), this phone's page through `ui --app`, and a computer's
// page over the relay (SIGELO:CTL:, control pair, control ui --app; SKIP without the relay checkout).
//   node apps/gtk/test-gtk.mjs     (needs gjs; a checkout with ts/dist, contact/ and adapters/moadim/ node_modules)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { newRoot } from '../../ts/dist/keys.js';

const HERE = import.meta.dirname, ROOT = join(HERE, '..', '..'), CLI = join(ROOT, 'adapters', 'moadim', 'cli.ts');
let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => { if (cond) { passed++; console.log(`ok   ${name}`); } else { failed++; console.log(`FAIL ${name}${detail ? `\n     ${detail}` : ''}`); } };
const T = mkdtempSync(join(tmpdir(), 'sigelo-gtk-')), P = join(T, 'prefix'), H = join(T, 'home');
mkdirSync(H, { recursive: true, mode: 0o700 });

// ── scripts parse; install.sh dry run writes nothing; then a real install into the prefix
ok('install.sh: sh -n', spawnSync('sh', ['-n', join(HERE, 'install.sh')]).status === 0);
for (const f of ['web/start.js', '../../adapters/moadim/shim-zlib.mjs', '../../adapters/moadim/shim-kdf.mjs']) ok(`${f}: node --check`, spawnSync(process.execPath, ['--check', join(HERE, f)]).status === 0);
const dry = spawnSync('sh', [join(HERE, 'install.sh'), '--dry-run', '--prefix', P], { encoding: 'utf8' });
ok('install.sh --dry-run: exit 0, every target under the prefix, nothing written', dry.status === 0 && !existsSync(P)
  && dry.stdout.split('\n').filter((l) => /^(cp|write) /.test(l)).every((l) => l.includes(` ${P}/`)), dry.stdout + dry.stderr);
const ins = spawnSync('sh', [join(HERE, 'install.sh'), '--prefix', P], { encoding: 'utf8' });
const S = join(P, 'share', 'sigelo-app');
const want = ['bin/sigelo-app', 'share/applications/io.sigelo.App.desktop', 'share/icons/hicolor/scalable/apps/io.sigelo.App.svg', 'share/sigelo-app/sigelo-app.js',
  'share/sigelo-app/lib/remote-client.mjs', 'share/sigelo-app/lib/jcs.js', 'share/sigelo-app/lib/noble-ciphers/chacha.js', 'share/sigelo-app/web/start.html', 'share/sigelo-app/web/ui.js',
  'share/sigelo-app/web/shim-zlib.mjs', 'share/sigelo-app/web/shim-kdf.mjs'];
ok('install.sh --prefix: the launcher, desktop file, icon, app and page files', ins.status === 0 && want.every((f) => existsSync(join(P, f))), ins.stderr + want.filter((f) => !existsSync(join(P, f))).join(' '));
ok('install.sh: QR reading installed beside the page (contact/qr-decode.mjs, qr.mjs), no "scanning off" warning', ['qr-decode.mjs', 'qr.mjs'].every((f) => existsSync(join(S, 'web', f))) && !/scanning off/.test(ins.stderr), ins.stderr);
const desk = readFileSync(join(P, 'share/applications/io.sigelo.App.desktop'), 'utf8');
ok('desktop file: Exec the installed launcher, icon io.sigelo.App, mobile form factor', desk.includes(`Exec=${P}/bin/sigelo-app\n`) && desk.includes('Icon=io.sigelo.App') && desk.includes('X-Purism-FormFactor=Workstation;Mobile;'));
const v = spawnSync('desktop-file-validate', [join(HERE, 'io.sigelo.App.desktop')], { encoding: 'utf8' });
if (v.error) console.log('SKIP desktop-file-validate: not installed'); else ok('desktop-file-validate', v.status === 0 && v.stdout.trim() === '', v.stdout);
const svg = readFileSync(join(HERE, 'io.sigelo.App.svg'), 'utf8');
ok('icon: SVG, no text, no external reference', svg.startsWith('<svg') && !/<text|href=|url\(/.test(svg));
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
  const r = await gjs({ SIGELO_APP_TEST: 'self', SIGELO_APP_IDENTITY: human, SIGELO_AGENT: JSON.stringify([process.execPath, CLI]) });
  ok('gjs, this phone: ui --app spawned, GET /api/me with its token → 200; stopped → exit 0', r.ok === true && r.me === 200 && r.exited === true && r.code === 0, JSON.stringify(r).slice(0, 400));
  ok('gjs, this phone: the page serves the device routes (GET /api/devices → 200, no devices yet) and the QR decoder', r.devices === 200 && r.devices_list === 0 && r.decoder === 200, JSON.stringify(r).slice(0, 400));
  const n = await gjs({ SIGELO_APP_TEST: 'self', SIGELO_APP_IDENTITY: join(H, 'none.local.json'), SIGELO_AGENT: JSON.stringify([process.execPath, CLI]) });
  ok('gjs, this phone: no identity → ui\'s own message (keeper --from-words)', n.ok === false && /keeper --from-words/.test(n.message ?? ''), JSON.stringify(n).slice(0, 400));
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
