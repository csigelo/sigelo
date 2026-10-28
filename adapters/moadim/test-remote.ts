// SPDX-License-Identifier: MIT
// sigelo-agent ui --remote (sigelo-agent-remote.ts, remote-client.mjs, UI-API.md "Remote"), --port, --app,
// the installable page.   node test-remote.ts   (the end-to-end part SKIPs without relay/ and its node_modules)
import { spawnSync } from 'node:child_process';
import { readFileSync, rmSync, statSync, mkdirSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { join } from 'node:path';
import { newRoot } from 'sigelo/dist/keys.js';
import { CLI, done, hasRelay, NO_RELAY, ok, posixModes, startTestRelay, tmpHome } from './test-helpers.ts';

const ui = await import('./sigelo-agent-ui.ts');
const rm = await import('./sigelo-agent-remote.ts');
const spec = './remote-client.mjs';
const rc = await import(spec) as {
  remoteClient(text: string, o?: object): Promise<{ call(m: string, p: string, b?: unknown): Promise<{ status: number; body: any }>; deps: any; id: Uint8Array; key: Uint8Array; host: string; port: number; ctr: number }>;
  parseControl(t: string): { host: string; port: number; id: Uint8Array; key: Uint8Array };
  base45Decode(s: string): Uint8Array; sealRequest(d: unknown, c: unknown, ctr: number, msg: unknown): string;
};
const H = tmpHome('remote');
const env = { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H };
const fromWords = (file: string) => spawnSync('node', [CLI, 'keeper', '--from-words', '--identity', file], { env, input: newRoot(), encoding: 'utf8' });
const unreachable = { relay: 'relay.test', endpoints: { 'relay.test': { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:1' } } };
type Res = { status: number; headers: Record<string, string | string[] | undefined>; body: string };
const http = (port: number, method: string, path: string, headers: Record<string, string> = {}, body?: string | Buffer): Promise<Res> => new Promise((resolve, reject) => {
  const r = request({ host: '127.0.0.1', port, method, path, agent: false, headers: { Host: `127.0.0.1:${port}`, ...headers } }, (res) => {
    let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: b }));
  });
  r.on('error', (e) => ((e as { code?: string }).code === 'ECONNRESET' || (e as { code?: string }).code === 'EPIPE' ? resolve({ status: -1, headers: {}, body: '' }) : reject(e)));
  r.end(body);
});
const uiJson2 = (d: string): { controls: Record<string, any> } => JSON.parse(readFileSync(join(d, 'me.local.ui.json'), 'utf8'));
const dir = (n: string): string => { const d = join(H, n); mkdirSync(join(d, 'agents'), { recursive: true, mode: 0o700 }); fromWords(join(d, 'me.local.json')); return d; };

// ── base45 (RFC 9285 §4.2 examples) and the control's text
{
  const enc = (s: string) => rm.base45(Buffer.from(s));
  ok('remote: base45 as RFC 9285 (AB, Hello!!, base-45), and back', enc('AB') === 'BB8' && enc('Hello!!') === '%69 VD92EX0' && enc('base-45') === 'UJCLQE7W581'
    && Buffer.from(rc.base45Decode('%69 VD92EX0')).toString() === 'Hello!!');
  let bad = '';
  try { rc.base45Decode('GGW'); } catch (e) { bad = (e as Error).message; }
  ok('remote: base45 over 65535 refused (GGW)', bad === 'not base45');
}

// ── offline: the LAN listener on 127.0.0.1, no relay reachable
const A = dir('alice'), human = join(A, 'me.local.json');
let page = await ui.startUi({ identity: human, agents: join(A, 'agents'), carrier: unreachable, remote: { listen: '127.0.0.1', name: 'tab', scope: 'read' } });
const line = page.remote?.line ?? '';
ok('remote: SIGELO:UI:<ip>:<port>:<base45 of id ‖ key>, about 90 characters', /^SIGELO:UI:127\.0\.0\.1:\d+:[0-9A-Z $%*+\-./:]{60}$/.test(line) && line.length <= 90 && page.remote?.port !== page.port, line);
const uiJson = (): { controls: Record<string, { id: string; key: string; scope: string; ctr: number; last_used: number | null }>; remote: { port: number } } => JSON.parse(readFileSync(join(A, 'me.local.ui.json'), 'utf8'));
const ctl = rc.parseControl(line);
ok('remote: the control kept in ui.json controls{}: the same id and key, scope read, ctr 0', uiJson().controls['tab']?.key === Buffer.from(ctl.key).toString('hex')
  && uiJson().controls['tab']?.id === Buffer.from(ctl.id).toString('hex') && uiJson().controls['tab']?.scope === 'read' && uiJson().controls['tab']?.ctr === 0);
if (posixModes) ok('remote: ui.json 0600', (statSync(join(A, 'me.local.ui.json')).mode & 0o777) === 0o600);
const T = { 'X-Sigelo-Token': page.token };
const local = async (path: string) => JSON.parse((await http(page.port, 'GET', path, T)).body);
let tab = await rc.remoteClient(line);
const st = await tab.call('GET', '/api/state');
ok('remote: GET /api/state sealed → 200, the same state as the local listener', st.status === 200 && st.body.me.did === (await local('/api/state')).me.did && st.body.me.relay === 'relay.test', JSON.stringify(st).slice(0, 200));
const me = await tab.call('GET', '/api/me');
ok('remote: GET /api/me sealed → the local answer, byte for byte', me.status === 200 && JSON.stringify(me.body) === JSON.stringify(await local('/api/me')));
const msgs = await tab.call('GET', '/api/messages?contact=did:sigelo:zNope');
ok('remote: GET /api/messages sealed, query kept → 404 not_contact, as locally', msgs.status === 404 && msgs.body.error.check === 'not_contact');
const out = await tab.call('POST', '/api/send', { to: 'did:sigelo:zNope', text: 'x' });
ok('remote: scope read: POST /api/send → sealed 403 scope', out.status === 403 && out.body.error.check === 'scope', JSON.stringify(out));
ok('remote: scope read: clear, forget, agents → 403 scope', (await Promise.all([['POST', '/api/history/clear'], ['POST', '/api/forget'], ['GET', '/api/agents']].map(([m, p]) => tab.call(m!, p!)))).every((r) => r.status === 403 && r.body.error.check === 'scope'));
const lks = await tab.call('GET', '/api/links'), lka = await tab.call('POST', '/api/links/answer', { id: 'K7F3Q9ZP', accept: true }), lkl = await tab.call('POST', '/api/link', { a: 'x', b: 'y', purpose: 'p' });
ok('remote: scope read: GET /api/links → the local answer; links/answer and link → 403 scope', lks.status === 200 && JSON.stringify(lks.body) === JSON.stringify(await local('/api/links'))
  && lka.status === 403 && lka.body.error.check === 'scope' && lkl.status === 403 && lkl.body.error.check === 'scope', JSON.stringify([lks, lka, lkl]));
{
  // Agents (the app's main list): the list is read; enrolling, revoking, renaming a worker and the relay Test are all.
  const wk = await tab.call('GET', '/api/agents/workers'), outs = await Promise.all([['POST', '/api/agents/enrol-code', { name: 'vps' }], ['POST', '/api/agents/revoke', { worker: 0 }],
    ['POST', '/api/agents/rename', { worker: 0, name: 'x' }], ['POST', '/api/relays/test', { relay: 'relay.test' }]].map(([m, p, b]) => tab.call(m as string, p as string, b as object)));
  ok('remote: scope read: GET /api/agents/workers → the local answer; enrol-code, revoke, rename, relays/test → 403 scope', wk.status === 200 && JSON.stringify(wk.body) === JSON.stringify(await local('/api/agents/workers'))
    && outs.every((r) => r.status === 403 && r.body.error.check === 'scope'), JSON.stringify([wk, outs]));
}
const dev = await tab.call('GET', '/api/devices/list'), dev2 = await tab.call('POST', '/api/../api/devices/add', {});
ok('remote: /api/devices/* → sealed 403 remote, also through ..', dev.status === 403 && dev.body.error.check === 'remote' && dev2.status === 403 && dev2.body.error.check === 'remote', JSON.stringify([dev, dev2]));
const nope = await tab.call('GET', '/api/nothing'), stat = await tab.call('GET', '/ui.js');
ok('remote: an unknown route → sealed 404; a static file is not remote (404)', nope.status === 404 && nope.body.error.check === 'route' && stat.status === 404);
const R = page.remote!.port, post = (b: string | Buffer) => http(R, 'POST', '/r', { 'Content-Type': 'application/json' }, b);
// Wrong key, replay, tampering: a status and no body.
const wrong = { ...ctl, key: new Uint8Array(32).fill(7) };
const w = await post(rc.sealRequest(tab.deps, wrong, Date.now() * 1000 + 5e6, { method: 'GET', path: '/api/state' }));
ok('remote: a wrong key → 403, no body', w.status === 403 && w.body === '', `${w.status} ${w.body}`);
const next = Date.now() * 1000 + 1e7, once = rc.sealRequest(tab.deps, ctl, next, { method: 'GET', path: '/api/me' });
const first = await post(once), again = await post(once);
ok('remote: the same request twice: once 200, then 403 no body (replayed ctr)', first.status === 200 && again.status === 403 && again.body === '');
const older = await post(rc.sealRequest(tab.deps, ctl, next - 1, { method: 'GET', path: '/api/me' }));
ok('remote: a lower ctr (reordered) → 403', older.status === 403 && older.body === '');
const tampered = JSON.parse(rc.sealRequest(tab.deps, ctl, next + 1, { method: 'GET', path: '/api/me' }));
tampered.ctr = next + 2;
ok('remote: ctr changed in transit (it is in the aad) → 403', (await post(JSON.stringify(tampered))).status === 403);
const unknownId = JSON.parse(rc.sealRequest(tab.deps, ctl, next + 3, { method: 'GET', path: '/api/me' }));
unknownId.id = '00'.repeat(8);
ok('remote: an unknown id → 403', (await post(JSON.stringify(unknownId))).status === 403);
ok('remote: ctr kept in ui.json, last_used set', uiJson().controls['tab']!.ctr === next && (uiJson().controls['tab']!.last_used ?? 0) > 0);
// The LAN listener answers nothing but POST /r.
const others = await Promise.all([http(R, 'GET', '/r'), http(R, 'GET', '/'), http(R, 'GET', '/ui.js'), http(R, 'GET', '/api/state', T), http(R, 'POST', '/api/sync', T, '{}'), http(R, 'POST', '/r/', {}, '{}'), http(R, 'OPTIONS', '/r'), http(R, 'POST', '/r?x=1', {}, '{}')]);
ok('remote: the LAN listener: GET /r, /, /ui.js, /api/* with the token, /r/, OPTIONS → 404, no body', others.every((x) => x.status === 404 && x.body === ''), JSON.stringify(others.map((x) => [x.status, x.body])));
ok('remote: not JSON or not a request → 400 / 403, no body', (await post('nope')).status === 400 && (await post('{}')).status === 403 && (await post('[1]')).body === '');
const big = await post(Buffer.alloc(1024 * 1024 + 10, 0x20));
ok('remote: a body over 1 MiB → 413 (or the connection cut), never 200', big.status === 413 || big.status === -1, String(big.status));
// The local listener's rules, unchanged beside it.
ok('remote: the local listener still checks Host, token and Origin', (await http(page.port, 'GET', '/api/state', { ...T, Host: `127.0.0.1:${R}` })).status === 403
  && (await http(page.port, 'GET', '/api/state', {})).status === 403
  && (await http(page.port, 'POST', '/api/sync', { ...T, 'Content-Type': 'application/json', Origin: `http://127.0.0.1:${R}` }, '{}')).status === 403
  && (await http(page.port, 'POST', '/api/history/clear', { ...T, 'Content-Type': 'application/json', Origin: `http://127.0.0.1:${page.port}` }, '{}')).status === 200);
// The installable page.
const man = await http(page.port, 'GET', '/manifest.webmanifest'), sw = await http(page.port, 'GET', '/sw.js'), icon = await http(page.port, 'GET', '/icon.svg'), mask = await http(page.port, 'GET', '/icon-maskable.svg'), html = await http(page.port, 'GET', '/');
const kept = /KEPT = (\[[^\]]*\])/.exec(sw.body)?.[1] ?? '';
ok('install: manifest (start_url /, an SVG icon and a maskable one, both served), sw.js keeping ui.html, ui.js, ui.css only, the icon; ui.html links the manifest',
  man.status === 200 && String(man.headers['content-type']).startsWith('application/manifest+json') && JSON.parse(man.body).start_url === '/' && JSON.parse(man.body).icons[0].src === '/icon.svg'
    && JSON.parse(man.body).icons[1]?.src === '/icon-maskable.svg' && JSON.parse(man.body).icons[1]?.purpose === 'maskable' && mask.status === 200 && String(mask.headers['content-type']).startsWith('image/svg+xml')
    && sw.status === 200 && String(sw.headers['content-type']).startsWith('text/javascript') && kept === "['/ui.html', '/ui.js', '/ui.css']" && !/caches?\.[a-z]+\([^)]*api/.test(sw.body)
    && icon.status === 200 && String(icon.headers['content-type']).startsWith('image/svg+xml') && html.body.includes('rel="manifest" href="/manifest.webmanifest"'), kept);
// CLI beside the page: --controls lists, never the key; --revoke-control refused while it runs.
const cli = (...a: string[]) => spawnSync('node', [CLI, 'ui', '--identity', human, ...a], { env, encoding: 'utf8' });
const listed = cli('--controls');
ok('ui --controls: name, scope, created, last used; never the key', listed.status === 0 && JSON.parse(listed.stdout)[0].name === 'tab' && JSON.parse(listed.stdout)[0].scope === 'read'
  && JSON.parse(listed.stdout)[0].last_used > 0 && !listed.stdout.includes(uiJson().controls['tab']!.key) && !listed.stdout.includes('"key"'), listed.stdout + listed.stderr);
const busyRevoke = cli('--revoke-control', 'tab');
ok('ui --revoke-control while the page runs: exit 1, busy, stop it first', busyRevoke.status === 1 && busyRevoke.stderr.includes('stop the page'), busyRevoke.stderr);
const remotePort = page.remote!.port;
await page.close();
// Restarted: the port kept (the control's text stays valid), the ctr kept (no replay across a restart).
page = await ui.startUi({ identity: human, agents: join(A, 'agents'), carrier: unreachable, remote: { listen: '127.0.0.1', name: 'full', scope: 'all' } });
ok('remote: restarted, the LAN port kept; the old request still refused', page.remote?.port === remotePort && (await post(once)).status === 403);
tab = await rc.remoteClient(line, { ctr: next + 10 });
ok('remote: the first control still answers after a restart', (await tab.call('GET', '/api/state')).status === 200);
const full = await rc.remoteClient(page.remote!.line!);
ok('remote: scope all: forget, tier, agents, link, links/allow in scope (404 not_contact / 200), devices still refused', (await full.call('POST', '/api/forget', { contact: 'did:sigelo:zNope' })).body.error.check === 'not_contact'
  && (await full.call('POST', '/api/link', { a: 'did:sigelo:zNope', b: 'did:sigelo:zNope2', purpose: 'p' })).body.error.check === 'not_contact'
  && (await full.call('POST', '/api/links/allow', { contact: 'did:sigelo:zNope', allow: true })).body.error.check === 'not_contact'
  && (await full.call('GET', '/api/agents')).status === 200 && (await full.call('GET', '/api/devices')).body.error.check === 'remote');
{
  const [ec, rv, rt] = [await full.call('POST', '/api/agents/enrol-code', { name: 'vps' }), await full.call('POST', '/api/agents/revoke', { worker: 7 }), await full.call('POST', '/api/relays/test', { relay: 'relay.test' })];
  ok('remote: scope all: enrol-code reaches the route (no relay here: 409 connect), revoke an unknown worker 404, relays/test answers (the relay unreachable: ok false)',
    ec.status === 409 && ec.body.error.check === 'connect' && rv.status === 404 && rv.body.error.check === 'worker' && rt.status === 200 && rt.body.ok === false, JSON.stringify([ec, rv, rt]));
}
{
  const [rs, rp, fs, fp] = [await tab.call('GET', '/api/settings'), await tab.call('POST', '/api/settings', { relay: 'corp.example.com' }), await full.call('GET', '/api/settings'), await full.call('POST', '/api/settings', { relay: '' })];
  ok('remote: the relay setting is scope all: read → 403 scope (GET and POST); all → 200, the local answer', rs.status === 403 && rs.body.error.check === 'scope' && rp.status === 403 && rp.body.error.check === 'scope'
    && fs.status === 200 && fs.body.relay === 'relay.sigelo.ai' && fs.body.fixed === 'relay.test' && fp.status === 200 && fp.body.relay === 'relay.sigelo.ai', JSON.stringify([rs, rp, fs, fp]));
}
// D4: the device routes are real here (the page's Devices view), and still never remote, at any scope (apps.md §6.2).
const DEV: [string, string, object?][] = [['GET', '/api/devices'], ['POST', '/api/devices/add', { name: 'phone' }], ['POST', '/api/devices/confirm', { id: 'x', match: true }], ['POST', '/api/devices/words', { id: 'x' }],
  ['POST', '/api/devices/scan', { text: 'K7F3-Q9ZP' }], ['POST', '/api/devices/revoke', { name: 'phone', lost: true }], ['POST', '/api/devices/sync']];
const devLocal = await http(page.port, 'GET', '/api/devices', { 'X-Sigelo-Token': page.token }), devRemote = await Promise.all(DEV.map(([m, p, b]) => full.call(m, p, b)));
ok('remote: every device route (list, add, confirm, words, scan, revoke, sync) → sealed 403 remote at scope all, while the local page answers GET /api/devices 200; nothing added',
  devLocal.status === 200 && devRemote.every((r) => r.status === 403 && r.body.error.check === 'remote') && (JSON.parse((await http(page.port, 'GET', '/api/devices', { 'X-Sigelo-Token': page.token })).body) as { adding: unknown[] }).adding.length === 0,
  JSON.stringify(devRemote.map((r) => r.status)));
await page.close();
let changed = '';
try { await ui.startUi({ identity: human, agents: join(A, 'agents'), carrier: unreachable, remote: { listen: '127.0.0.1', name: 'tab', scope: 'all' } }); } catch (e) { changed = (e as Error).message; }
ok('remote: an existing control with another --scope → refused, revoke it first; the lock released', changed.includes('revoke it') && ui.uiHolder(human) === null, changed);
const revoked = cli('--revoke-control', 'tab'), none = cli('--revoke-control', 'tab');
ok('ui --revoke-control tab: exit 0; again: exit 1, no such control', revoked.status === 0 && none.status === 1 && !JSON.stringify(uiJson().controls).includes('"tab"'), revoked.stderr + none.stderr);
page = await ui.startUi({ identity: human, agents: join(A, 'agents'), carrier: unreachable, remote: { listen: '127.0.0.1' } });
let refusedStatus = 0;
try { await tab.call('GET', '/api/state'); } catch (e) { refusedStatus = (e as { status: number }).status; }
ok('remote: a revoked control → 403; the other one still answers; no --name prints no text', refusedStatus === 403 && (await full.call('GET', '/api/me')).status === 200 && page.remote?.line === null);
await page.close();

// ── the scope table covers every route of UI-API.md; read ⊂ chat ⊂ all
{
  const all = [...readFileSync(join(import.meta.dirname, 'UI-API.md'), 'utf8').matchAll(/^\| `((?:GET|POST) \/api\/[a-z/-]+)`/gm)].map((m) => m[1]!);
  // The device routes (D4) are documented too, and in no scope: deviceRoute refuses them before any scope.
  const devices = all.filter((x) => rm.deviceRoute(x.split(' ')[1]!)), routes = all.filter((x) => !devices.includes(x));
  const [r, c, a] = [rm.SCOPES.read, rm.SCOPES.chat, rm.SCOPES.all];
  ok('remote: every UI-API.md route but the device ones is in scope all; read ⊂ chat ⊂ all', routes.length >= 17 && routes.every((x) => a.has(x)) && a.size === routes.length
    && [...r].every((x) => c.has(x)) && [...c].every((x) => a.has(x)), JSON.stringify(routes.filter((x) => !a.has(x))));
  ok('remote: the device routes of UI-API.md (list, add, confirm, words, scan, revoke, sync) are in no scope', devices.length === 7 && !devices.some((x) => a.has(x) || c.has(x) || r.has(x)), JSON.stringify(devices));
}

// ── review 2026-10-28: a code that pairs is read only by the scope that may pair (MEDIUM 8); the LAN
// listener never takes a public address by itself (LOW)
{
  const state = { seq: 1, pending: { invites: [{ name: 'carol', exp: 1, relay: 'relay.test', id: 'i1', short: 'K7F3-Q9ZP', short_exp: 1, code: 'sgl1Long' }] } };
  const workers = { keeper: true, workers: [{ worker: 0, name: 'vps', enrolling: { id: 'e1', state: 'code', code: 'K7F3-Q9ZP', command: 'sigelo-agent init --enrol K7F3-Q9ZP', exp: 1 } }] };
  const routes = { 'GET /api/state': 1, 'GET /api/agents/workers': 1 };
  const call = async (scope: 'read' | 'chat' | 'all', path: string, body: unknown) => (await rm.remoteCall(scope, { method: 'GET', path }, routes, async () => [200, body]))[1] as any;
  const [rs, cs, as] = [await call('read', '/api/state', state), await call('chat', '/api/state', state), await call('all', '/api/state', state)];
  ok('remote: scope read: GET /api/state carries a waiting invite without its codes (short, code); chat and all get them; the page\'s own answer is untouched',
    rs.pending.invites[0].name === 'carol' && rs.pending.invites[0].code === undefined && rs.pending.invites[0].short === undefined && cs.pending.invites[0].code === 'sgl1Long' && as.pending.invites[0].short === 'K7F3-Q9ZP'
      && state.pending.invites[0]!.code === 'sgl1Long', JSON.stringify(rs));
  const [rw, cw, aw] = [await call('read', '/api/agents/workers', workers), await call('chat', '/api/agents/workers', workers), await call('all', '/api/agents/workers', workers)];
  ok('remote: GET /api/agents/workers: an enrolment\'s code and command only to scope all (read and chat see its state)', rw.workers[0].enrolling.state === 'code' && rw.workers[0].enrolling.code === undefined && rw.workers[0].enrolling.command === undefined
    && cw.workers[0].enrolling.code === undefined && aw.workers[0].enrolling.code === 'K7F3-Q9ZP', JSON.stringify([rw, cw]));
  const ifs = (a: string, internal = false) => ({ eth0: [{ address: a, family: 'IPv4', internal, netmask: '255.255.255.0', mac: '00:00:00:00:00:00', cidr: null }] }) as never;
  ok('remote: the LAN address: the default route\'s when private; a public one is passed over for a private interface, else none (--listen)',
    rm.lanAddress('192.168.1.5', ifs('10.0.0.2')) === '192.168.1.5' && rm.lanAddress('203.0.113.7', ifs('10.0.0.2')) === '10.0.0.2' && rm.lanAddress('203.0.113.7', ifs('198.51.100.9')) === null
      && rm.lanAddress(null, ifs('172.20.1.1')) === '172.20.1.1' && rm.lanAddress(null, ifs('127.0.0.1', true)) === null);
  ok('remote: private ranges: 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16; not 172.32, 100.128, 8.8.8.8',
    ['10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.0.1', '100.64.0.1', '169.254.1.1'].every(rm.privateV4) && !['172.32.0.1', '100.128.0.1', '8.8.8.8', '192.169.0.1', '::1'].some(rm.privateV4));
}

// ── --port: kept, and a taken one fails port_taken (the lock released)
{
  const blocker = createServer();
  await new Promise<void>((r) => blocker.listen(0, '127.0.0.1', () => r()));
  const taken = (blocker.address() as { port: number }).port;
  let why = '';
  try { await ui.startUi({ identity: human, agents: join(A, 'agents'), carrier: unreachable, port: taken }); } catch (e) { why = (e as { check?: string }).check ?? ''; }
  ok('ui --port taken → port_taken, the lock released', why === 'port_taken' && ui.uiHolder(human) === null, why);
  await new Promise<void>((r) => blocker.close(() => r()));
  const p2 = await ui.startUi({ identity: human, agents: join(A, 'agents'), carrier: unreachable, port: taken });
  ok('ui --port <p>: the page on that port', p2.port === taken && p2.url.startsWith(`http://127.0.0.1:${taken}/`) && p2.remote === null);
  await p2.close();
  const bad = [cli('--port', '70000'), cli('--name', 'x'), cli('--remote', '--scope', 'root'), cli('--remote', '--name', 'Bad Name', '--no-open'), cli('--controls', '--remote')];
  ok('ui (CLI): --port 70000, --name without --remote, a bad scope, a bad name, --controls with --remote → exit 2', bad.every((x) => x.status === 2), bad.map((x) => `${x.status} ${x.stderr}`).join('\n'));
  const rel = [cli('--relay'), cli('--remote', '--relay', '--listen', '127.0.0.1')];
  const ctlCli = (...a: string[]) => spawnSync('node', [CLI, 'control', ...a], { env: { ...env, SIGELO_CONTROL: join(H, 'none.control.json') }, encoding: 'utf8' });
  const cbad = [ctlCli('pair', 'SIGELO:UI:1.2.3.4:5:AB'), ctlCli('pair'), ctlCli('ui', '--app'), ctlCli('nope')];
  ok('ui --relay without --remote, or with --listen; control pair of a text not SIGELO:CTL:, without one; control ui unpaired; an unknown verb → exit 2', [...rel, ...cbad].every((x) => x.status === 2)
    && cbad[2]!.stderr.includes('control pair'), [...rel, ...cbad].map((x) => `${x.status} ${x.stderr}`).join('\n'));
}

// ── the CLI: `ui --remote` prints the page's URL, then the control's text
{
  const { spawn } = await import('node:child_process');
  const c = spawn('node', [CLI, 'ui', '--identity', human, '--remote', '--listen', '127.0.0.1', '--name', 'cli', '--scope', 'chat', '--no-open'],
    { env: { ...env, SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: JSON.stringify(unreachable.endpoints) } });
  let so = '', se = '';
  c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', (d) => { se += d; });
  const end = Date.now() + 20000;
  while (!/SIGELO:UI:/.test(so) && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
  const [u, t] = so.split('\n');
  let answer = 0, links: unknown[] = [];
  try {
    const cc = await rc.remoteClient(t!);
    answer = (await cc.call('POST', '/api/send', { to: 'did:sigelo:zNope', text: 'x' })).status;
    links = await Promise.all([cc.call('POST', '/api/links/answer', { id: 'K7F3Q9ZP', accept: false }), cc.call('POST', '/api/unlink', { id: 'K7F3Q9ZP' })]).then((x) => x.map((y) => [y.status, y.body.error?.check]));
  } catch {}
  const closed = new Promise((r) => c.on('close', r));
  c.kill('SIGTERM'); await closed;
  ok('ui --remote (CLI): stdout the URL, then SIGELO:UI:; stderr names the controls; scope chat sends (404 not_contact)', /^http:\/\/127\.0\.0\.1:\d+\/#t=/.test(u ?? '') && /^SIGELO:UI:127\.0\.0\.1:/.test(t ?? '')
    && se.includes('cli (chat)') && answer === 404, `${so}\n${se}`);
  ok('ui --remote, scope chat: links/answer in scope (404 link_unknown), unlink outside it (403 scope)', JSON.stringify(links) === JSON.stringify([[404, 'link_unknown'], [403, 'scope']]), JSON.stringify(links));
}

// ── `ui --app` (a shell shows the page): stdout the URL, no browser; stdin's end stops it and frees the file
{
  const { spawn } = await import('node:child_process');
  const c = spawn('node', [CLI, 'ui', '--identity', human, '--app'], { env: { ...env, SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: JSON.stringify(unreachable.endpoints) }, stdio: ['pipe', 'pipe', 'pipe'] });
  let so = '';
  c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', () => {});
  const end = Date.now() + 20000;
  while (!so.includes('\n') && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
  const m = /^http:\/\/127\.0\.0\.1:(\d+)\/#t=([0-9a-f]{32})\n/.exec(so);
  const me = m ? await http(Number(m[1]), 'GET', '/api/me', { 'X-Sigelo-Token': m[2]! }) : null;
  const lock = human.replace(/\.json$/, '.ui.pid'), held = (() => { try { statSync(lock); return true; } catch { return false; } })();
  const closed = new Promise<number | null>((r) => c.on('close', r)), t0 = Date.now();
  c.stdin.end();
  const code = await Promise.race([closed, new Promise<string>((r) => setTimeout(() => r('timeout'), 10000))]);
  if (code === 'timeout') c.kill('SIGKILL');
  let pid = true;
  try { statSync(lock); } catch { pid = false; }
  ok('ui --app: stdout the URL with its token, the page answers; stdin closed → exit 0, lock file gone', me?.status === 200 && held && code === 0 && !pid, `${so} ${me?.status} ${code} ${Date.now() - t0}ms`);
  const r = spawnSync('node', [CLI, 'ui', '--identity', human, '--app', '--controls'], { env, encoding: 'utf8' });
  ok('ui --app --controls refused (exit 2)', r.status === 2);
}

// ── end to end: every route in scope, sealed, against the relay the contact tests use
if (!hasRelay()) console.log(`SKIP remote end to end: ${NO_RELAY}`);
else {
  const relay = await startTestRelay(H), carrier = { relay: 'relay.test', endpoints: relay.endpoints, registry: false };
  const Ad = dir('a2'), Bd = dir('b2');
  const pa = await ui.startUi({ identity: join(Ad, 'me.local.json'), agents: join(Ad, 'agents'), carrier, remote: { listen: '127.0.0.1', name: 'phone', scope: 'all' } });
  const pb = await ui.startUi({ identity: join(Bd, 'me.local.json'), agents: join(Bd, 'agents'), carrier });
  const done_ = new Map<string, number>();
  const r = await rc.remoteClient(pa.remote!.line!);
  const call = async (m: string, p: string, b?: unknown) => { const x = await r.call(m, p, b); done_.set(`${m} ${p.split('?')[0]}`, x.status); return x; };
  const bcall = async (m: string, p: string, b?: unknown) => JSON.parse((await http(pb.port, m, p, m === 'POST' ? { 'X-Sigelo-Token': pb.token, Origin: `http://127.0.0.1:${pb.port}`, 'Content-Type': 'application/json' } : { 'X-Sigelo-Token': pb.token }, b === undefined ? (m === 'POST' ? '{}' : undefined) : JSON.stringify(b))).body);
  const until = async <V>(f: () => Promise<V | undefined>, ms = 15000): Promise<V | undefined> => { const e = Date.now() + ms; for (;;) { const v = await f(); if (v || Date.now() > e) return v; await new Promise((s) => setTimeout(s, 200)); } };
  try {
    const inv = await call('POST', '/api/invite', { name: 'bob' });
    const acc = await bcall('POST', '/api/accept', { code: inv.body.short, name: 'alice' });
    const bob = await until(async () => ((await call('GET', '/api/state')).body.groups.contacts as { name: string; did: string }[]).find((c) => c.name === 'bob'));
    ok('remote e2e: invite (sealed), accepted at the other page, the contact in the sealed state', inv.status === 200 && acc.status === 'connected' && bob !== undefined, JSON.stringify([inv, acc]).slice(0, 300));
    await bcall('POST', '/api/words', { contact: acc.contact.did, match: true });
    const steps = [
      await call('POST', '/api/words', { contact: bob!.did, match: true }), await call('POST', '/api/rename', { contact: bob!.did, name: 'Bob' }),
      await call('POST', '/api/tag', { contact: bob!.did, tags: ['work'] }), await call('POST', '/api/tier', { contact: bob!.did, tier: 'quiet' }),
      await call('POST', '/api/send', { to: bob!.did, text: 'from the phone' }), await call('POST', '/api/sync'),
    ];
    ok('remote e2e: words, rename, tag, tier, send, sync → 200; the send sent', steps.every((x) => x.status === 200) && steps[4]!.body.status === 'sent', JSON.stringify(steps.map((x) => x.status)));
    const got = await until(async () => ((await bcall('GET', `/api/messages?contact=${encodeURIComponent(acc.contact.did)}`)).messages as { text: string }[]).find((m) => m.text === 'from the phone'));
    await bcall('POST', '/api/send', { to: acc.contact.did, text: 'to the phone' });
    const back = await until(async () => ((await call('GET', `/api/messages?contact=${encodeURIComponent(bob!.did)}`)).body.messages as { text: string }[]).find((m) => m.text === 'to the phone'));
    ok('remote e2e: the other page gets it; its answer read through GET /api/messages, sealed', got !== undefined && back !== undefined);
    const inv2 = await bcall('POST', '/api/invite', { name: 'alice2' });
    const acc2 = await call('POST', '/api/accept', { code: inv2.short });
    const inv3 = await call('POST', '/api/invite', { name: 'later', long: true }), cancel = await call('POST', '/api/invite/cancel', { id: inv3.body.id });
    ok('remote e2e: accept (sealed) a code of the other page; invite and cancel', acc2.status === 200 && acc2.body.status === 'connected' && cancel.body.cancelled === true, JSON.stringify(acc2).slice(0, 300));
    spawnSync('node', [CLI, 'init', '--no-recovery'], { env: { ...env, SIGELO_IDENTITY: join(Ad, 'agents', 'sigelo.bot.local.json') } });
    const ag = await call('GET', '/api/agents'), en = await call('POST', '/api/agents/enrol', { agent: 'bot' }), pr = await call('POST', '/api/agents/pair', { agent: 'bot' });
    ok('remote e2e: agents, enrol, pair (scope all) → 200', ag.status === 200 && en.status === 200 && en.body.worker === 0 && pr.status === 200 && pr.body.status === 'connected', JSON.stringify([en, pr]).slice(0, 300));
    // Links, sealed: B links its agent helper to A (external for B: A is not B's); A answers from the phone.
    const relayEnv = { ...env, SIGELO_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: JSON.stringify(relay.endpoints) } as Record<string, string>;
    const helper = join(Bd, 'agents', 'sigelo.helper.local.json');
    spawnSync('node', [CLI, 'init', '--no-recovery'], { env: { ...env, SIGELO_IDENTITY: helper } });
    const hen = await bcall('POST', '/api/agents/enrol', { agent: 'helper' }), hpr = await bcall('POST', '/api/agents/pair', { agent: 'helper' });
    const { spawn } = await import('node:child_process');
    const hw = spawn('node', [CLI, 'watch', '--identity', helper], { env: relayEnv });
    let hwOut = '';
    hw.stdout.on('data', (d) => { hwOut += d; }); hw.stderr.on('data', (d) => { hwOut += d; });
    try {
      await until(async () => (hwOut.includes('watching ') ? true : undefined));
      const aOrig = (await call('GET', '/api/me')).body.original as string;
      await call('POST', '/api/tier', { contact: bob!.did, tier: 'friend' });
      const bl = await bcall('POST', '/api/link', { a: hpr.contact.did, b: aOrig, purpose: 'compare notes' });
      const ban = await until(async () => ((await call('GET', '/api/state')).body.introductions as { id: string; purpose: string }[]).find((x) => x.id === bl.id), 30000);
      const rec = (await call('GET', '/api/links')).body.received as { id: string; peer: string; purpose: string }[];
      ok('remote e2e links: the other page links its agent to me; the sealed state carries the introduction (banner); GET /api/links lists it', hen.worker === 0 && bl.status === 'pending'
        && ban?.purpose === 'compare notes' && rec.some((x) => x.id === bl.id && x.peer === hpr.contact.did), JSON.stringify([bl, ban]) + hwOut);
      const yes = await call('POST', '/api/links/answer', { id: bl.id, accept: true });
      const filed = await until(async () => ((await call('GET', '/api/state')).body.groups.contacts as { did: string; tier: string; link: { id: string } | null }[]).find((c) => c.link?.id === bl.id), 30000);
      const linked = await until(async () => ((await bcall('GET', '/api/links')).made as { id: string; status: string }[]).find((x) => x.id === bl.id && x.status === 'linked'), 30000);
      ok('remote e2e links: accepted from the phone → the helper filed at quiet (the default) with the link; the other page: linked', yes.status === 200 && filed?.tier === 'quiet' && filed.did === hpr.contact.did
        && linked !== undefined, JSON.stringify([yes, filed]));
      const al = await call('POST', '/api/link', { a: pr.body.contact.did, b: bob!.did, purpose: 'share the calendar' });
      const un = await call('POST', '/api/unlink', { id: al.body.id });
      const ok1 = await call('POST', '/api/links/allow', { contact: bob!.did, allow: true }), ok2 = await call('POST', '/api/links/allow', { contact: bob!.did, allow: false });
      ok('remote e2e links: link, unlink, allow, deny sealed (scope all)', al.status === 200 && al.body.kind === 'external' && un.body.status === 'ended' && ok1.body.tier === 'quiet' && ok2.body.had === true, JSON.stringify([al, un, ok1, ok2]));
    } finally {
      const closed = new Promise((x) => hw.on('close', x));
      hw.kill('SIGTERM'); await closed;
    }
    const me2 = await call('GET', '/api/me'), fg = await call('POST', '/api/forget', { contact: bob!.did }), cl = await call('POST', '/api/history/clear');
    ok('remote e2e: me, forget, history/clear → 200', me2.status === 200 && fg.body.forgotten === bob!.did && cl.body.cleared === true);
    const se = await call('GET', '/api/settings'), sp = await call('POST', '/api/settings', { relay: 'corp.example.com' }), rl = await call('GET', '/api/relays');
    ok('remote e2e: settings and relays sealed (scope all): the setting kept, SIGELO_RELAY-like caller relay still fixed; no registry → []', se.status === 200 && sp.body.relay === 'corp.example.com' && sp.body.fixed === 'relay.test'
      && rl.status === 200 && rl.body.relays.length === 0, JSON.stringify([se, sp, rl]));
    const wk = await call('GET', '/api/agents/workers'), ec = await call('POST', '/api/agents/enrol-code', { name: 'vps' });
    const rn = await call('POST', '/api/agents/rename', { worker: ec.body.worker, name: 'vps2' }), rv = await call('POST', '/api/agents/revoke', { worker: ec.body.worker }), rt = await call('POST', '/api/relays/test', { relay: 'relay.test' });
    ok('remote e2e agents: the list, a code (12 characters: relay.test names its tag), rename, revoke (the unused code cancelled), the relay Test, sealed (scope all) → 200', wk.status === 200 && wk.body.keeper === true && ec.status === 200
      && /^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(ec.body.code) && rn.body.name === 'vps2' && rv.body.cancelled === true && rt.body.ok === true, JSON.stringify([ec, rn, rv, rt]).slice(0, 900));
    const all = [...rm.SCOPES.all], missed = all.filter((x) => done_.get(x) !== 200);
    ok(`remote e2e: every route in scope all answered 200 sealed (${all.length})`, missed.length === 0, JSON.stringify(missed));
  } finally {
    await pa.close(); await pb.close(); await relay.close?.();
  }
}
// ── the pushed state's cap (contact/control.mjs capState, PUSH_MAX 64 KiB): a summary past it, and the
// app pulls the whole on demand (GET /api/state?full=1 is a request, never the pushed summary)
{
  const C = await import('sigelo-contact/control.mjs' as string) as any;
  const row = (i: number) => ({ did: `did:sigelo:z${i}`, name: `c${i}`, last: { dir: 'in', text: 'x'.repeat(190), at: 1000 + i } });
  const small = { seq: 3, me: { did: 'd' }, groups: { mine: [row(1)], contacts: [row(2)] }, events: [{ n: 1 }] };
  const big = { seq: 9, me: { did: 'd' }, groups: { mine: Array.from({ length: 30 }, (_, i) => row(i)), contacts: Array.from({ length: 400 }, (_, i) => row(100 + i)) }, events: Array.from({ length: 50 }, (_, i) => ({ n: i, detail: 'y'.repeat(100) })) };
  const cut = C.capState(big);
  ok('capState: a state within 64 KiB goes as it is; past it a summary within 64 KiB: the newest 20 of each group and events, the counts, truncated',
    C.PUSH_MAX === 64 * 1024 && C.capState(small) === small && JSON.stringify(big).length > C.PUSH_MAX && JSON.stringify(cut).length <= C.PUSH_MAX && cut.truncated.kept === 20
    && cut.truncated.contacts.mine === 30 && cut.truncated.contacts.contacts === 400 && cut.truncated.events === 50 && cut.groups.contacts.length === 20 && cut.groups.contacts[0].name === 'c499'
    && cut.events.length === 20 && cut.events.at(-1).n === 49 && cut.seq === 9 && cut.me.did === 'd', JSON.stringify(cut.truncated));
  const huge = { ...big, groups: { mine: [], contacts: Array.from({ length: 50 }, (_, i) => ({ ...row(i), last: { ...row(i).last, text: 'z'.repeat(4000) } })) } };
  ok('capState: fewer kept until it fits (each contact 4 KiB: under 16 of them)', JSON.stringify(C.capState(huge)).length <= C.PUSH_MAX && C.capState(huge).truncated.kept < 16, JSON.stringify(C.capState(huge).truncated));
  // The app: the pushed summary answers GET /api/state (no request); full=1 asks the computer, whose whole answer then stands.
  const op = 'did:sigelo:zOperator', inbox: { from: string; content: unknown }[] = [], sent: any[] = [];
  const fake = { takeDevices: () => inbox.splice(0), send: async (_to: string, c: any) => { sent.push(c); inbox.push({ from: op, content: C.responseMessage({ id: c.id, status: 200, body: { ...big, seq: 10 } }) }); setTimeout(() => ctl.onEvent({ type: 'device' }), 0); } };
  const ctl = C.makeControl({ operator: op, timeout: 2000 });
  ctl.attach(fake);
  await ctl.call('GET', '/api/state');   // the lease starts with a request
  inbox.push({ from: op, content: C.eventsMessage({ seq: 11, since: 10, state: cut }) }); ctl.onEvent({ type: 'device' });
  await new Promise((r) => setTimeout(r, 20));
  const n0 = sent.length, pushed = await ctl.call('GET', '/api/state?since=10'), full = await ctl.call('GET', '/api/state?since=0&full=1'), after = await ctl.call('GET', '/api/state');
  ok('control: the pushed summary answers GET /api/state, truncated (no request); full=1 is a request; its whole answer stands until the next push',
    pushed.status === 200 && pushed.body.truncated?.kept === 20 && sent.length === n0 + 1 && full.status === 200 && full.body.truncated === undefined && full.body.groups.contacts.length === 400
    && after.body.truncated === undefined && sent.length === n0 + 1, JSON.stringify([n0, sent.length, pushed.body.truncated, full.status]));
  ctl.stop();
}

// ── over the relay (design/apps.md §6.3): a control identity, SIGELO:CTL:, request/response/events
if (!hasRelay()) console.log(`SKIP remote over the relay: ${NO_RELAY}`);
else {
  const { writeFileSync, unlinkSync } = await import('node:fs');
  const hexToBytes = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'));
  const C = await import('sigelo-contact/control.mjs' as string) as any, L = await import('sigelo-contact/carrier.mjs' as string) as any;
  const { did: didOf, canonicalize } = await import('sigelo');
  mkdirSync(join(H, 'r3'), { recursive: true });
  const relay = await startTestRelay(join(H, 'r3')), carrier = { relay: 'relay.test', endpoints: relay.endpoints };
  const Pd = dir('p3'), op = join(Pd, 'me.local.json');
  const T3 = (pg: { token: string }) => ({ 'X-Sigelo-Token': pg.token });
  const until = async <V>(f: () => Promise<V | undefined> | V | undefined, ms = 15000): Promise<V | undefined> => { const e = Date.now() + ms; for (;;) { const v = await f(); if (v || Date.now() > e) return v; await new Promise((s) => setTimeout(s, 100)); } };
  const apps: { car: any; ctl: any }[] = [];
  // The app's side, as apps/web/shell.mjs does it: a new control identity, the code accepted, the client.
  const app = async (line: string, tag: string, timeout = 15000) => {
    const t = C.readControlText(line), idf = C.newControlIdentity(), file = join(Pd, `control-${tag}.local.json`);
    writeFileSync(file, JSON.stringify(idf), { mode: 0o600 });
    const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: idf.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
    let ctl: any = null;
    const car = new L.Carrier({ identity: () => ({ secret: hexToBytes(idf.secret), bundle }), ...L.pathsFor(file), ...carrier, onEvent: (e: { type: string }) => ctl?.onEvent(e) });
    const r = await car.accept(t.code, { relay: t.relay ?? undefined, name: 'computer', wait: 15 });
    const opDid = r.contact?.did as string;
    ctl = C.makeControl({ operator: opDid, timeout });
    await car.start(); ctl.attach(car);
    let sent = 0;
    const send = car.send.bind(car);
    car.send = (...a: unknown[]) => { sent++; return send(...a); };
    const x = { car, ctl, did: didOf(idf.genesis), words: car.contacts().contacts.find((c: { did: string }) => c.did === opDid)?.fingerprint as string, status: r.status, get sent() { return sent; } };
    apps.push(x);
    return x;
  };
  let pr = await ui.startUi({ identity: op, agents: join(Pd, 'agents'), carrier, remote: { relay: true, name: 'phone', scope: 'read' } });
  try {
    const line = pr.relay.line ?? '';
    ok('relay: ui --remote --relay prints SIGELO:CTL:<short code>:<HOST> (8 characters, 12 with a relay tag; ≤ 60 characters), no LAN listener', /^SIGELO:CTL:[0-9A-Z]{4}-[0-9A-Z]{4}(-[0-9A-Z]{4})?:RELAY\.TEST$/.test(line) && line.length <= 60 && pr.remote === null, line);
    const pend = JSON.parse((await http(pr.port, 'GET', '/api/state', T3(pr))).body);
    ok('relay: the control\'s code waiting is not among the page\'s invites', !JSON.stringify(pend.pending.invites).includes('control:'));
    const a = await app(line, 'phone');
    const p = await until(() => Promise.race([pr.relay.paired(), new Promise<undefined>((r) => setTimeout(() => r(undefined), 15000))]));
    ok('relay: the app pairs by the code; the computer sees the same four words', a.status === 'connected' && p?.name === 'phone' && typeof p.words === 'string' && p.words.split(' ').length === 4 && p.words === a.words, JSON.stringify([p, a.words]));
    const kept = uiJson2(Pd).controls['phone'];
    ok('relay: ui.json controls{phone}: relay, scope read, the control DID, no key, not confirmed', kept?.relay === true && kept.scope === 'read' && kept.did === a.did && kept.key === undefined && kept.confirmed === false, JSON.stringify(kept));
    const early = await a.ctl.call('GET', '/api/me');
    ok('relay: before the words are confirmed on the computer → 403 words', early.status === 403 && early.body.error.check === 'words', JSON.stringify(early));
    // The computer's page: the Controls card lists it with its four words; Confirm there = the terminal's y.
    const W3 = { ...T3(pr), Origin: `http://127.0.0.1:${pr.port}`, 'Content-Type': 'application/json' };
    const pc = JSON.parse((await http(pr.port, 'GET', '/api/controls', T3(pr))).body), sentC = a.sent, overRelay = await a.ctl.call('GET', '/api/controls');
    ok('relay: the computer\'s page lists the control waiting for its words (GET /api/controls: name, scope, the four words); over the relay that route is refused at once (403, no relay message)',
      JSON.stringify(pc.pending) === JSON.stringify([{ name: 'phone', scope: 'read', words: p?.words }]) && overRelay.status === 403 && a.sent === sentC, JSON.stringify([pc, overRelay]));
    const cf = await http(pr.port, 'POST', '/api/controls/confirm', W3, JSON.stringify({ name: 'phone', match: true }));
    const cf2 = await http(pr.port, 'POST', '/api/controls/confirm', W3, JSON.stringify({ name: 'phone', match: false }));
    ok('relay: Confirm on the page → confirmed (ui.json), nothing pending; a second answer → 404 control_unknown (the first stands)', cf.status === 200 && JSON.parse(cf.body).confirmed === true
      && uiJson2(Pd).controls['phone']?.confirmed === true && JSON.parse((await http(pr.port, 'GET', '/api/controls', T3(pr))).body).pending.length === 0 && cf2.status === 404, cf.body + cf2.body);
    ok('relay: /api/controls* in no remote scope (never answered over the LAN or the relay)', ![...rm.SCOPES.all].some((x) => x.includes('/api/controls')));
    const me = await a.ctl.call('GET', '/api/me'), localMe = JSON.parse((await http(pr.port, 'GET', '/api/me', T3(pr))).body);
    ok('relay: confirmed: GET /api/me over the relay → the local answer (JCS: the same value)', me.status === 200 && canonicalize(me.body) === canonicalize(localMe), JSON.stringify(me).slice(0, 200));
    const st = await a.ctl.call('GET', '/api/state');
    ok('relay: GET /api/state → 200; the control\'s own contact is not in the page (groups, contactOf)', st.status === 200 && !JSON.stringify(st.body.groups).includes(a.did)
      && JSON.parse((await http(pr.port, 'GET', `/api/messages?contact=${encodeURIComponent(a.did)}`, T3(pr))).body).error?.check === 'not_contact', JSON.stringify(st.body.groups));
    const sc = await a.ctl.call('POST', '/api/send', { to: 'did:sigelo:zNope', text: 'x' }), dv = await a.ctl.call('GET', '/api/devices');
    ok('relay: scope read: POST /api/send → 403 scope; GET /api/devices → 403 remote (never remote)', sc.status === 403 && sc.body.error.check === 'scope' && dv.status === 403 && dv.body.error.check === 'remote', JSON.stringify([sc, dv]));
    // Events: pushed on change, read without a relay message, the same since.
    const seq0 = st.body.seq as number;
    let pushed = 0;
    a.ctl.onChange(() => { pushed++; });
    const sent0 = a.sent;
    const inv = JSON.parse((await http(pr.port, 'POST', '/api/invite', { ...T3(pr), Origin: `http://127.0.0.1:${pr.port}`, 'Content-Type': 'application/json' }, JSON.stringify({ name: 'carol' }))).body);
    await until(() => (pushed > 0 ? true : undefined), 10000);
    const st2 = await a.ctl.call('GET', `/api/state?since=${seq0}`);
    ok('relay: a change on the computer (an invite made there) → events pushed; GET /api/state answered from them, no relay message', pushed > 0 && st2.status === 200
      && st2.body.pending.invites.some((x: { name: string }) => x.name === 'carol') && a.sent === sent0, JSON.stringify([pushed, a.sent, sent0, inv.name]));
    const carolR = st2.body.pending.invites.find((x: { name: string }) => x.name === 'carol'), carolL = JSON.parse((await http(pr.port, 'GET', '/api/state', T3(pr))).body).pending.invites.find((x: { name: string }) => x.name === 'carol');
    ok('relay: scope read: the pushed state names the invite but not its codes (no short, no long code); the page itself has both (review 2026-10-28, MEDIUM 8)', carolR !== undefined && carolR.code === undefined && carolR.short === undefined
      && typeof carolL?.code === 'string' && typeof carolL?.short === 'string', JSON.stringify([carolR, carolL]));
    await new Promise((r) => setTimeout(r, 2500));
    ok('relay: nothing changed → nothing pushed (no polling either way)', pushed === 1 && a.sent === sent0, String(pushed));
    // chat and all, each its own control
    const issue = async (name: string, scope: 'chat' | 'all') => {
      const r = await pr.relay.issue(name, scope), x = await app(r!.line, name);
      const q = await Promise.race([pr.relay.paired(), new Promise<undefined>((s) => setTimeout(() => s(undefined), 15000))]);
      await pr.relay.confirm(name, q?.words === x.words);
      return x;
    };
    const chat = await issue('tab', 'chat'), all = await issue('desk', 'all');
    const c1 = await chat.ctl.call('POST', '/api/send', { to: 'did:sigelo:zNope', text: 'x' }), c2 = await chat.ctl.call('POST', '/api/forget', { contact: 'did:sigelo:zNope' });
    const a1 = await all.ctl.call('POST', '/api/forget', { contact: 'did:sigelo:zNope' }), a2 = await all.ctl.call('GET', '/api/agents'), a3 = await all.ctl.call('POST', '/api/devices/add', { name: 'x' });
    ok('relay: scope chat: send in scope (404 not_contact), forget outside (403 scope)', c1.status === 404 && c1.body.error.check === 'not_contact' && c2.status === 403 && c2.body.error.check === 'scope', JSON.stringify([c1, c2]));
    ok('relay: scope all: forget in scope (404 not_contact), agents 200; devices/add still 403 remote', a1.status === 404 && a2.status === 200 && a3.status === 403 && a3.body.error.check === 'remote', JSON.stringify([a1.status, a2.status, a3]));
    const cinv = await chat.ctl.call('POST', '/api/invite', { name: 'dave' });
    ok('relay: scope chat: POST /api/invite over the relay → 200, a short code', cinv.status === 200 && typeof cinv.body.short === 'string', JSON.stringify(cinv).slice(0, 200));
    // Wrong words: the computer says no → the control is forgotten, its requests unanswered.
    const bad = await (async () => {
      const r = await pr.relay.issue('bad', 'all'), x = await app(r!.line, 'bad'); await pr.relay.paired();
      await http(pr.port, 'POST', '/api/controls/confirm', W3, JSON.stringify({ name: 'bad', match: false })); return x;
    })();
    const bq = await bad.ctl.call('GET', '/api/me');
    ok('relay: words refused on the computer\'s page (Refuse) → the control forgotten (not in ui.json), its request never answered 200', bq.status !== 200 && uiJson2(Pd).controls['bad'] === undefined, JSON.stringify(bq));
    // Review 2026-10-28 (LOW): a code made again withdraws the one before; answering the old one pairs nothing.
    const old = await pr.relay.issue('re', 'chat'), fresh = await pr.relay.issue('re', 'chat');
    const late = await app(old!.line, 're-old', 4000);
    const held = (): string => { try { return readFileSync(op.replace(/\.json$/, '.contacts.json'), 'utf8'); } catch { return ''; } };
    await new Promise((r) => setTimeout(r, 3000));
    ok('relay: a control\'s code made again: the first code pairs nobody on the computer (no hidden, unconfirmed contact); the new one stands', fresh !== null && fresh.line !== old!.line && late.status !== 'connected'
      && !held().includes(late.did) && uiJson2(Pd).controls['re']?.did === null, JSON.stringify([late.status, uiJson2(Pd).controls['re']]));
    // Seat elsewhere: the list names another device the seat.
    const lp = op.replace(/\.json$/, '.devices.json'), t0 = Math.floor(Date.now() / 1000);
    writeFileSync(lp, JSON.stringify({ v: 'sigelo-devices/1', operator: 'did:sigelo:zOp', seq: 1, iat: t0, devices: [{ name: 'other', worker: 0, did: 'did:sigelo:zOther', rank: 'full', added: t0, by: 'did:sigelo:zOp' }], seat: { holder: 'did:sigelo:zOther', epoch: 1, iat: t0 }, sig: 'x' }), { mode: 0o600 });
    const se = await all.ctl.call('GET', '/api/me'), se2 = await chat.ctl.call('POST', '/api/send', { to: 'did:sigelo:zNope', text: 'x' });
    unlinkSync(lp);
    ok('relay: the seat elsewhere → 409 seat_elsewhere naming the holder (the app shows the banner)', se.status === 409 && se.body.error.check === 'seat_elsewhere' && se.body.error.message.includes('other') && se2.status === 409, JSON.stringify([se, se2]));
    // The rate cap: a burst of 10, then one 429 told, the rest dropped.
    const many = await Promise.all(Array.from({ length: 14 }, () => all.ctl.call('GET', '/api/me')));
    const n200 = many.filter((r) => r.status === 200).length, n429 = many.filter((r) => r.status === 429).length;
    ok('relay: rate cap: of 14 at once, about 10 answered, one 429 rate, the rest dropped (no answer)', n200 >= 9 && n200 <= 12 && n429 === 1 && many.find((r) => r.status === 429)?.body.error.check === 'rate', JSON.stringify(many.map((r) => r.status)));
    // Revoke: the contact forgotten; the app's requests go unanswered.
    const rv = await pr.relay.revoke('phone');
    const after = await a.ctl.call('POST', '/api/sync');  // 15 s: nobody answers
    ok('relay: revoke → forgotten here (ui.json, the contact), further requests never answered 200', rv && uiJson2(Pd).controls['phone'] === undefined && after.status !== 200, JSON.stringify(after));
    const lc = ui.listControls(op);
    ok('ui --controls: relay controls marked (paired, confirmed), never a key', lc.some((x) => x.name === 'tab' && x.relay?.paired === true && x.relay.confirmed === true) && !JSON.stringify(lc).includes('"key"'), JSON.stringify(lc));
    // Restarted: a paired control still answers (no flag needed), the CLI revokes it while the page is down.
    await pr.close();
    pr = await ui.startUi({ identity: op, agents: join(Pd, 'agents'), carrier });
    const again = await chat.ctl.call('GET', '/api/me');
    ok('relay: the page restarted without --relay: a paired control still answers', again.status === 200, JSON.stringify(again));
    await pr.close();
    const gone = await ui.revokeControl(op, 'tab', carrier);
    pr = await ui.startUi({ identity: op, agents: join(Pd, 'agents'), carrier });
    const revoked = await chat.ctl.call('GET', '/api/me');
    ok('relay: ui --revoke-control tab (page stopped): forgotten; restarted, its requests unanswered', gone && revoked.status !== 200 && uiJson2(Pd).controls['tab'] === undefined, JSON.stringify(revoked));
  } finally {
    for (const x of apps) { x.ctl.stop(); await x.car.stop(); }
    await pr.close(); await relay.close?.();
  }
}
rmSync(H, { recursive: true, force: true });
done(import.meta.filename);
