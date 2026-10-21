// SPDX-License-Identifier: MIT
// sigelo-agent ui --remote (sigelo-agent-remote.ts, remote-client.mjs, UI-API.md "Remote"), --port, the
// installable page.   node test-remote.ts   (the end-to-end part SKIPs without relay/ and its node_modules)
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
const man = await http(page.port, 'GET', '/manifest.webmanifest'), sw = await http(page.port, 'GET', '/sw.js'), icon = await http(page.port, 'GET', '/icon.svg'), html = await http(page.port, 'GET', '/');
const kept = /KEPT = (\[[^\]]*\])/.exec(sw.body)?.[1] ?? '';
ok('install: manifest (start_url /, an SVG icon), sw.js keeping ui.html, ui.js, ui.css only, the icon; ui.html links the manifest',
  man.status === 200 && String(man.headers['content-type']).startsWith('application/manifest+json') && JSON.parse(man.body).start_url === '/' && JSON.parse(man.body).icons[0].src === '/icon.svg'
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
ok('remote: scope all: forget, tier, agents in scope (404 not_contact / 200), devices still refused', (await full.call('POST', '/api/forget', { contact: 'did:sigelo:zNope' })).body.error.check === 'not_contact'
  && (await full.call('GET', '/api/agents')).status === 200 && (await full.call('GET', '/api/devices')).body.error.check === 'remote');
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
  const routes = [...readFileSync(join(import.meta.dirname, 'UI-API.md'), 'utf8').matchAll(/^\| `((?:GET|POST) \/api\/[a-z/]+)`/gm)].map((m) => m[1]!);
  const [r, c, a] = [rm.SCOPES.read, rm.SCOPES.chat, rm.SCOPES.all];
  ok('remote: every UI-API.md route is in scope all, none is a device route; read ⊂ chat ⊂ all', routes.length >= 17 && routes.every((x) => a.has(x)) && a.size === routes.length
    && [...r].every((x) => c.has(x)) && [...c].every((x) => a.has(x)) && !routes.some((x) => rm.deviceRoute(x.split(' ')[1]!)), JSON.stringify(routes.filter((x) => !a.has(x))));
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
  let answer = 0;
  try { answer = (await (await rc.remoteClient(t!)).call('POST', '/api/send', { to: 'did:sigelo:zNope', text: 'x' })).status; } catch {}
  const closed = new Promise((r) => c.on('close', r));
  c.kill('SIGTERM'); await closed;
  ok('ui --remote (CLI): stdout the URL, then SIGELO:UI:; stderr names the controls; scope chat sends (404 not_contact)', /^http:\/\/127\.0\.0\.1:\d+\/#t=/.test(u ?? '') && /^SIGELO:UI:127\.0\.0\.1:/.test(t ?? '')
    && se.includes('cli (chat)') && answer === 404, `${so}\n${se}`);
}

// ── end to end: every route in scope, sealed, against the relay the contact tests use
if (!hasRelay()) console.log(`SKIP remote end to end: ${NO_RELAY}`);
else {
  const relay = await startTestRelay(H), carrier = { relay: 'relay.test', endpoints: relay.endpoints };
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
    const me2 = await call('GET', '/api/me'), fg = await call('POST', '/api/forget', { contact: bob!.did }), cl = await call('POST', '/api/history/clear');
    ok('remote e2e: me, forget, history/clear → 200', me2.status === 200 && fg.body.forgotten === bob!.did && cl.body.cleared === true);
    const all = [...rm.SCOPES.all], missed = all.filter((x) => done_.get(x) !== 200);
    ok(`remote e2e: every route in scope all answered 200 sealed (${all.length})`, missed.length === 0, JSON.stringify(missed));
  } finally {
    await pa.close(); await pb.close(); await relay.close?.();
  }
}
rmSync(H, { recursive: true, force: true });
done(import.meta.filename);
