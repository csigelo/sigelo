// SPDX-License-Identifier: MIT
// sigelo-agent ui (sigelo-agent-ui.ts, UI-API.md).
//   node test-ui.ts   (the end-to-end part SKIPs without relay/ and its node_modules)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { did } from 'sigelo';
import { agentIdentitySeed, keeperRoot, newRoot, rootFromMnemonic } from 'sigelo/dist/keys.js';
import { load } from './sigelo-agent.ts';
import { CLI, done, hasRelay, NO_RELAY, ok, posixModes, startTestRelay, tmpHome } from './test-helpers.ts';

// ── ui: the human's page (sigelo-agent-ui.ts, UI-API.md) ───────────────────────────────────
// The HTTP layer first, with no relay reachable: token, Host, Origin, CSP, no cookie, the pid lock,
// a path in the agents' directory refused, the files 0600. Then the CLI's first run (no identity: it
// points to keeper --from-words, which makes it from the words) and a refusal of a session verb while
// the page holds the file. Then, against the in-process relay the contact tests use (SKIP without
// relay/), two pages pair by short code, check the words and talk both ways, and one enrols a local
// agent (worker 0 of its keeper root, its old contacts warned of) and pairs with it.
{
  const ui = await import('./sigelo-agent-ui.ts');
  const { request } = await import('node:http');
  const H = tmpHome('ui');
  const agentsDir = join(H, 'agents'), humanDir = join(H, 'human');
  mkdirSync(agentsDir, { mode: 0o700 }); mkdirSync(humanDir, { mode: 0o700 });
  const human = join(humanDir, 'me.local.json');
  const unreachable = { relay: 'relay.test', endpoints: { 'relay.test': { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:1' } } };
  // The human's identity: the root identity of their words (keeper --from-words, sigelo-agent-enrol.ts).
  const fromWords = (file: string, words = newRoot()) => spawnSync('node', [CLI, 'keeper', '--from-words', '--identity', file], { env: { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H }, input: words, encoding: 'utf8' });
  fromWords(human);
  type Res = { status: number; headers: Record<string, string | string[] | undefined>; body: string };
  const http = (port: number, method: string, path: string, headers: Record<string, string>, body?: unknown): Promise<Res> => new Promise((resolve, reject) => {
    const r = request({ host: '127.0.0.1', port, method, path, headers: { Host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: b }));
    });
    r.on('error', reject);
    r.end(body === undefined ? undefined : JSON.stringify(body));
  });
  const page = await ui.startUi({ identity: human, agents: agentsDir, carrier: unreachable });
  const P = page.port, T = { 'X-Sigelo-Token': page.token }, W = { ...T, Origin: `http://127.0.0.1:${P}`, 'Content-Type': 'application/json' };
  ok('ui: binds 127.0.0.1, a random port, a 128-bit token in the fragment', page.url === `http://127.0.0.1:${P}/#t=${page.token}` && /^[0-9a-f]{32}$/.test(page.token));
  const root = await http(P, 'GET', '/', {});
  ok('ui: the page itself needs no token; CSP default-src \'self\', nosniff, no-referrer, no cookie',
    root.status === 200 && String(root.headers['content-security-policy']).startsWith("default-src 'self'") && root.headers['x-content-type-options'] === 'nosniff'
      && root.headers['referrer-policy'] === 'no-referrer' && root.headers['set-cookie'] === undefined && root.body.includes('/ui.js'), JSON.stringify(root.headers));
  const js = await http(P, 'GET', '/ui.js', {});
  ok('ui: ui.js served, with the token read from the fragment and sent as X-Sigelo-Token, text by textContent only',
    js.status === 200 && js.body.includes('X-Sigelo-Token') && !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(js.body));
  ok('ui: no token → 403', (await http(P, 'GET', '/api/state', {})).status === 403);
  ok('ui: a wrong token → 403', (await http(P, 'GET', '/api/state', { 'X-Sigelo-Token': '0'.repeat(32) })).status === 403);
  const st = await http(P, 'GET', '/api/state', T);
  ok('ui: the token → 200, the state as JSON, no cookie', st.status === 200 && (JSON.parse(st.body) as { me: { relay: string } }).me.relay === 'relay.test' && st.headers['set-cookie'] === undefined, st.body.slice(0, 200));
  ok('ui: another Host (DNS rebinding) → 403, even with the token and for the page', (await http(P, 'GET', '/api/state', { ...T, Host: `evil.example:${P}` })).status === 403
    && (await http(P, 'GET', '/', { Host: `evil.example:${P}` })).status === 403);
  ok('ui: a write without Origin → 403', (await http(P, 'POST', '/api/sync', { ...T, 'Content-Type': 'application/json' }, {})).status === 403);
  ok('ui: a write from another Origin → 403', (await http(P, 'POST', '/api/sync', { ...W, Origin: 'http://evil.example' }, {})).status === 403);
  const pre = await http(P, 'OPTIONS', '/api/sync', { Origin: 'http://evil.example', 'Access-Control-Request-Headers': 'x-sigelo-token' });
  ok('ui: a CORS preflight is never granted', pre.status === 403 && pre.headers['access-control-allow-origin'] === undefined);
  const cleared = await http(P, 'POST', '/api/history/clear', W, {});
  ok('ui: a write with the token, its Origin and JSON → 200', cleared.status === 200, cleared.body);
  ok('ui: an unknown contact → 404 not_contact', (await http(P, 'POST', '/api/send', W, { to: 'did:sigelo:zNope', text: 'x' })).body.includes('not_contact'));
  // The Controls card (relay controls' four words, confirmed here as in the terminal): none pending here.
  const ctl0 = await http(P, 'GET', '/api/controls', T), ctlNo = await http(P, 'POST', '/api/controls/confirm', W, { name: 'phone', match: true });
  const ctlBad = await http(P, 'POST', '/api/controls/confirm', W, { name: 'phone', match: 'yes' }), ctlTok = await http(P, 'GET', '/api/controls', {});
  ok('ui controls: GET /api/controls → {pending: []}; confirm of no pending control → 404 control_unknown; match not a boolean → 400; no token → 403',
    ctl0.status === 200 && JSON.parse(ctl0.body).pending.length === 0 && ctlNo.status === 404 && JSON.parse(ctlNo.body).error.check === 'control_unknown' && ctlBad.status === 400 && ctlTok.status === 403, ctl0.body + ctlNo.body);
  ok('ui.js: the Controls card (the four words, Confirm / Refuse → POST /api/controls/confirm), a pushed state cut short ("State truncated", "Pull the rest" → full=1), a linked contact\'s message badge',
    js.body.includes("h('h2', null, 'Controls')") && js.body.includes('/api/controls/confirm') && js.body.includes("'Confirm'") && js.body.includes("'Refuse'")
    && js.body.includes('State truncated') && js.body.includes('Pull the rest') && js.body.includes('full=1') && js.body.includes('m.link ? badge(`link ${m.link.id}: ${m.link.purpose}`'));
  // Links (LINKS.md): the same token and Origin rules; nothing yet; refusals by check.
  const lsNo = await http(P, 'GET', '/api/links', {}), ls0 = await http(P, 'GET', '/api/links', T);
  const l0 = JSON.parse(ls0.body) as Record<string, unknown[]>;
  ok('ui links: GET /api/links without the token → 403; with it → {links, made, received, allow}, all empty', lsNo.status === 403 && ls0.status === 200
    && ['links', 'made', 'received', 'allow'].every((k) => Array.isArray(l0[k]) && l0[k]!.length === 0), ls0.body);
  const lk = (body: unknown, path = '/api/link', h: Record<string, string> = W) => http(P, 'POST', path, h, body).then((r) => ({ status: r.status, check: (JSON.parse(r.body) as { error?: { check: string } }).error?.check }));
  const noOrigin = await lk({ a: 'x', b: 'y', purpose: 'p' }, '/api/link', { ...T, 'Content-Type': 'application/json' }), noTok = await lk({ id: 'X' }, '/api/unlink', { ...W, 'X-Sigelo-Token': '' });
  ok('ui links: POST /api/link without Origin, /api/unlink without the token → 403', noOrigin.status === 403 && noTok.status === 403);
  const refusals = [await lk({ a: 'did:sigelo:zNope', b: 'did:sigelo:zNope2', purpose: 'x' }), await lk({ a: 'did:sigelo:zNope', b: 'did:sigelo:zNope2' }), await lk({ a: 'a', b: 'b', purpose: 'x', tier_a: 'own' }),
    await lk({ a: 'a', b: 'b', purpose: 'x', days: 'many' }), await lk({ id: 'K7F3Q9ZP' }, '/api/unlink'), await lk({ id: 'K7F3Q9ZP', accept: true }, '/api/links/answer'),
    await lk({ id: 'K7F3Q9ZP', accept: true, tier: 'own' }, '/api/links/answer'), await lk({ contact: 'did:sigelo:zNope', allow: true }, '/api/links/allow'), await lk({ contact: 'did:sigelo:zNope' }, '/api/links/allow')];
  ok('ui links: unknown contacts 404 not_contact; no purpose 400; tier own 409 link_tier; bad days 400; unknown link or introduction 404 link_unknown; answer at own 400; allow unknown 404, without allow 400',
    JSON.stringify(refusals.map((r) => [r.status, r.check])) === JSON.stringify([[404, 'not_contact'], [400, 'body'], [409, 'link_tier'], [400, 'body'], [404, 'link_unknown'], [404, 'link_unknown'], [400, 'body'], [404, 'not_contact'], [400, 'body']]), JSON.stringify(refusals));
  ok('ui links: the state carries introductions (none yet)', Array.isArray((JSON.parse((await http(P, 'GET', '/api/state', T)).body) as { introductions: unknown[] }).introductions));
  // The relay setting (UI-API.md Settings): the same token and Origin rules; the caller's relay wins (fixed).
  type RelaySet = { relay: string; default: string; fixed: string | null; in_use: string; error?: { check: string } };
  const sj = async (method: string, body?: unknown, h: Record<string, string> = method === 'POST' ? W : T): Promise<{ status: number } & RelaySet> => { const r = await http(P, method, '/api/settings', h, body); return { status: r.status, ...(JSON.parse(r.body) as RelaySet) }; };
  const s0 = await sj('GET');
  ok('ui settings: GET /api/settings without the token → 403; with it → relay.sigelo.ai, fixed by the caller\'s relay.test, in use',
    (await http(P, 'GET', '/api/settings', {})).status === 403 && s0.status === 200 && s0.relay === 'relay.sigelo.ai' && s0.default === 'relay.sigelo.ai' && s0.fixed === 'relay.test' && s0.in_use === 'relay.test', JSON.stringify(s0));
  const sNo = [await sj('POST', { relay: 'corp.example.com' }, { ...T, 'Content-Type': 'application/json' }), await sj('POST', { relay: 'corp.example.com' }, { ...W, 'X-Sigelo-Token': '' })];
  const sBad = [await sj('POST', { relay: 'not a host' }), await sj('POST', {}), await sj('POST', { relay: 7 })];
  ok('ui settings: POST without Origin or token → 403; not a host, none, a number → 400 body', sNo.every((r) => r.status === 403) && sBad.every((r) => r.status === 400 && r.error?.check === 'body'), JSON.stringify([sNo, sBad]));
  const s1 = await sj('POST', { relay: ' Corp.Example.com ' });
  ok('ui settings: POST {relay} → kept lower case in .ui.json settings; fixed still wins', s1.status === 200 && s1.relay === 'corp.example.com' && s1.fixed === 'relay.test'
    && (JSON.parse(readFileSync(join(humanDir, 'me.local.ui.json'), 'utf8')) as { settings: { relay: string } }).settings.relay === 'corp.example.com', JSON.stringify(s1));
  // Devices (DEVICES.md, sigelo-agent-device.ts devicePage): the same token and Origin rules; SAFE only.
  const mod = (f: string): Promise<Record<string, any>> => import(pathToFileURL(join(import.meta.dirname, '..', '..', 'contact', f)).href);
  const dv = await mod('device.mjs'), qr = await mod('qr.mjs'), qd = await mod('qr-decode.mjs');
  const dj = async (method: string, path: string, body?: unknown, h: Record<string, string> = method === 'POST' ? W : T): Promise<Record<string, any>> => { const r = await http(P, method, path, h, body); return { status: r.status, ...(JSON.parse(r.body) as Record<string, any>) }; };
  const d0 = await dj('GET', '/api/devices');
  ok('ui devices: GET /api/devices without the token → 403; with it → no devices, nothing adding, no list yet', (await http(P, 'GET', '/api/devices', {})).status === 403 && d0.status === 200
    && d0['devices'].length === 0 && d0['adding'].length === 0 && d0['list'] === null && d0['joining'] === null, JSON.stringify(d0));
  const dNo = [await dj('POST', '/api/devices/add', { name: 'tab', offline: true }, { ...T, 'Content-Type': 'application/json' }), await dj('POST', '/api/devices/revoke', { name: 'tab' }, { ...W, 'X-Sigelo-Token': '' }),
    await dj('POST', '/api/devices/scan', { text: 'K7F3-Q9ZP' }, { ...W, Origin: 'http://evil.example' })];
  ok('ui devices: add without Origin, revoke without the token, scan from another Origin → 403', dNo.every((r) => r.status === 403), JSON.stringify(dNo));
  const dBad = [await dj('POST', '/api/devices/add', { name: 'Bad!' }), await dj('POST', '/api/devices/add', { name: 'big', full: true }), await dj('POST', '/api/devices/add', { name: 'big', rank: 'full' }),
    await dj('POST', '/api/devices/add', { name: 'x', days: 91 }), await dj('POST', '/api/devices/add', { name: 'x', tier: 'own' }), await dj('POST', '/api/devices/revoke', { name: 'nope' }),
    await dj('POST', '/api/devices/confirm', { id: 'nope', match: true }), await dj('POST', '/api/devices/words', { id: 'nope' }), await dj('POST', '/api/devices/scan', { text: 'hello there, not a code at all' }), await dj('POST', '/api/devices/scan', {})];
  ok('ui devices: a bad name 400; FULL 409 device_full (a terminal); days 91, tier own 400; unknown device, add, words 404; a text that is no code 400 scan_text; no text 400',
    JSON.stringify(dBad.map((r) => [r.status, r['error']?.check])) === JSON.stringify([[400, 'body'], [409, 'device_full'], [409, 'device_full'], [400, 'body'], [400, 'body'], [404, 'device_unknown'], [404, 'device_unknown'], [404, 'device_unknown'], [400, 'scan_text'], [400, 'body']])
      && String(dBad[1]!['error']?.message).includes('device add --name <n> --full'), JSON.stringify(dBad));
  const seq0 = (await dj('GET', '/api/devices'))['list']?.seq ?? 0;
  const off = await dj('POST', '/api/devices/add', { name: 'tab', offline: true });
  ok('ui devices: add offline → worker 0, frames (SGD1…), an id for the words, never the words', off.status === 200 && off['worker'] === 0 && off['via'] === 'offline' && Array.isArray(off['frames']) && off['frames'].every((f: string) => f.startsWith('SGD1'))
    && typeof off['id'] === 'string' && !('words' in off), JSON.stringify(off).slice(0, 300));
  const sameName = await dj('POST', '/api/devices/add', { name: 'tab', offline: true });
  ok('ui devices: the same name again → 409 device_name_taken', sameName.status === 409 && sameName['error']?.check === 'device_name_taken', JSON.stringify(sameName));
  const w1 = await dj('POST', '/api/devices/words', { id: off['id'] }), w2 = await dj('POST', '/api/devices/words', { id: off['id'] });
  const joined = dv.joinFrames(off['frames']), opened = joined.done ? dv.open(joined.container, w1['words']) : null;
  ok('ui devices: the words once (six), then 404; the frames open under them: SAFE material for worker 0 with a 7-day invite', /^\w+( \w+){5}$/.test(w1['words']) && w2.status === 404
    && opened?.rank === 'safe' && opened.worker.i === 0 && opened.name === 'tab' && String(opened.invite).startsWith('sgl1'), JSON.stringify([w1.status, w2]));
  const frameQr = qd.scanPng(qr.toPng(qr.encode(off['frames'][0], { ecc: 'M', maxVersion: 20 })));
  ok('ui devices: a frame as the page draws it (qr.mjs, level M, ≤ v20) reads back through qr-decode.mjs', frameQr === off['frames'][0]);
  const d1 = await dj('GET', '/api/devices');
  ok('ui devices: listed: tab, SAFE, worker 0, added now, not paired, not seen, not revoked; the signed list one further', d1['devices'].length === 1 && d1['devices'][0].name === 'tab' && d1['devices'][0].rank === 'safe'
    && d1['devices'][0].worker === 0 && Math.abs(d1['devices'][0].added - Date.now() / 1000) < 60 && d1['devices'][0].paired === false && d1['devices'][0].seen === null && d1['devices'][0].revoked === null && d1['list']?.seq === seq0 + 1, JSON.stringify(d1));
  const lost = await dj('POST', '/api/devices/revoke', { name: 'tab', lost: true });
  const d2 = await dj('GET', '/api/devices');
  ok('ui devices: revoke tab --lost → revoked now, the steps (now, with the words), the list one further; listed revoked', lost.status === 200 && lost['lost'] === true && typeof lost['revoked'] === 'number' && lost['list'] === seq0 + 2
    && lost['steps']?.now.length >= 1 && lost['steps'].words.length >= 1 && d2['devices'][0].revoked === lost['revoked'], JSON.stringify(lost));
  const again = await dj('POST', '/api/devices/revoke', { name: 'tab' }), sync = await dj('POST', '/api/devices/sync');
  ok('ui devices: revoke it again (not lost) → 409 device_revoked; sync → the list, sent to nobody', again.status === 409 && again['error']?.check === 'device_revoked' && sync.status === 200 && sync['list'] === seq0 + 2 && sync['synced'] === 0, JSON.stringify([again, sync]));
  const page0 = await http(P, 'GET', '/', {}), map = /<script type="importmap">([\s\S]*?)<\/script>/.exec(page0.body)?.[1] ?? '';
  const hash = (await import('node:crypto')).createHash('sha256').update(map).digest('base64');
  const served = await Promise.all(['/qr.mjs', '/qr-decode.mjs', '/shim-zlib.mjs', '/shim-kdf.mjs'].map((f) => http(P, 'GET', f, {})));
  ok('ui devices: the page\'s one inline script is its import map (node:zlib, kdf.mjs → the shims), allowed by its hash; default-src \'self\' kept', map.includes('/shim-zlib.mjs') && map.includes('/shim-kdf.mjs')
    && String(page0.headers['content-security-policy']).startsWith(`default-src 'self'; script-src 'self' 'sha256-${hash}'`) && !/<script>(?!<)/.test(page0.body), String(page0.headers['content-security-policy']));
  ok('ui devices: qr.mjs and qr-decode.mjs (sigelo-contact\'s, byte for byte) and the shims served as JavaScript', served.every((r) => r.status === 200 && String(r.headers['content-type']).startsWith('text/javascript'))
    && served[1]!.body === readFileSync(join(import.meta.dirname, '..', '..', 'contact', 'qr-decode.mjs'), 'utf8'));
  ok('ui devices: the page has a Devices view: camera by getUserMedia (feature-detected), an image file, paste; BarcodeDetector first, jsQR after', /getUserMedia/.test(js.body) && /enumerateDevices/.test(js.body)
    && /createImageBitmap/.test(js.body) && /BarcodeDetector/.test(js.body) && /\/qr-decode\.mjs/.test(js.body) && /\/api\/devices\/scan/.test(js.body));
  if (posixModes) {
    ok('ui: me.local.history.jsonl and me.local.ui.json are 0600', ['history.jsonl', 'ui.json'].every((x) => (statSync(join(humanDir, `me.local.${x}`)).mode & 0o777) === 0o600));
  }
  let second = '';
  try { await ui.startUi({ identity: human, agents: agentsDir, carrier: unreachable }); } catch (e) { second = (e as Error).message; }
  ok('ui: a second page on the same file is refused (pid lock)', second.includes(`is open in sigelo-agent ui (pid ${process.pid})`), second);
  const inbox = spawnSync('node', [CLI, 'inbox'], { env: { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: human }, encoding: 'utf8' });
  ok('ui: a CLI inbox on the page\'s file is refused, exit 1, saying why', inbox.status === 1 && inbox.stderr.includes('a CLI inbox would take its relay session and its messages'), inbox.stderr);
  const pageEnv = { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: human };
  const sendBusy = spawnSync('node', [CLI, 'send', 'bob', 'hi'], { env: pageEnv, encoding: 'utf8' });
  ok('ui: a CLI send on the page\'s file is refused too (no queue beside a page), exit 1', sendBusy.status === 1 && sendBusy.stderr.includes('a CLI send would take its relay session'), sendBusy.stderr);
  const enrolBusy = spawnSync('node', [CLI, 'enrol', '--name', 'w', '--identity', human], { env: { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H }, encoding: 'utf8' });
  ok('ui: a CLI enrol by code as the page\'s identity is refused, exit 1, use the page; no worker in the roster',
    enrolBusy.status === 1 && enrolBusy.stderr.includes('enrol would take its relay session') && enrolBusy.stderr.includes('Use the page')
      && !readFileSync(human.replace(/\.json$/, '.keeper.json'), 'utf8').includes('"w"'), enrolBusy.stderr);
  let inside = '';
  try { await ui.startUi({ identity: join(agentsDir, 'me.local.json'), agents: agentsDir }); } catch (e) { inside = (e as Error).message; }
  ok('ui: a human file in the agents\' directory is refused', inside.includes('agents\' directory'), inside);
  await page.close();
  ok('ui: closing removes the pid lock', !existsSync(ui.lockPath(human)));
  // No relay from the caller or SIGELO_RELAY: the setting kept above is the carrier's own relay at the next start.
  {
    const noEnv = process.env['SIGELO_RELAY'];
    delete process.env['SIGELO_RELAY'];
    const ends = { 'relay.sigelo.ai': unreachable.endpoints['relay.test'], 'corp.example.com': unreachable.endpoints['relay.test'] };
    const again = await ui.startUi({ identity: human, agents: agentsDir, carrier: { endpoints: ends, registry: false } });
    try {
      const g = async (path: string, method = 'GET', body?: unknown) => JSON.parse((await http(again.port, method, path, method === 'POST' ? { 'X-Sigelo-Token': again.token, Origin: `http://127.0.0.1:${again.port}`, 'Content-Type': 'application/json' } : { 'X-Sigelo-Token': again.token }, body)).body);
      const st2 = await g('/api/settings'), me2 = await g('/api/me');
      ok('ui settings: nothing fixed → the setting is the relay in use at the next start (me.relay corp.example.com)', st2.fixed === null && st2.in_use === 'corp.example.com' && me2.relay === 'corp.example.com', JSON.stringify([st2, me2.relay]));
      const back = await g('/api/settings', 'POST', { relay: '' }), rel = await g('/api/relays');
      ok('ui settings: "" → back to relay.sigelo.ai (in use until the next start: corp.example.com); GET /api/relays with no registry → []', back.relay === 'relay.sigelo.ai' && back.in_use === 'corp.example.com'
        && Array.isArray(rel.relays) && rel.relays.length === 0, JSON.stringify([back, rel]));
    } finally { await again.close(); if (noEnv !== undefined) process.env['SIGELO_RELAY'] = noEnv; }
  }

  // The CLI: no identity → keeper --from-words, once; then the page, for the DID of the words.
  const env = { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: JSON.stringify(unreachable.endpoints) };
  const bare = spawnSync('node', [CLI, 'ui', '--no-open'], { env, encoding: 'utf8' });
  ok('ui (CLI), first run with no identity: exit 2, points to keeper --from-words', bare.status === 2 && bare.stderr.includes('sigelo-agent keeper --from-words'), bare.stderr);
  const oldFlag = spawnSync('node', [CLI, 'ui', '--no-recovery', '--no-open'], { env, encoding: 'utf8' });
  ok('ui (CLI) --no-recovery: gone, exit 2, the words instead', oldFlag.status === 2 && oldFlag.stderr.includes('keeper --from-words'), oldFlag.stderr);
  const inAgents = spawnSync('node', [CLI, 'ui', '--no-open'], { env: { ...env, SIGELO_HUMAN: join(H, '.config', 'moadim', 'me.local.json') }, encoding: 'utf8' });
  ok('ui (CLI): SIGELO_HUMAN in the agents\' directory → exit 2', inAgents.status === 2 && inAgents.stderr.includes('agents\' directory'), inAgents.stderr);
  const made = join(H, '.config', 'sigelo', 'me.local.json'), mw = newRoot();
  const kp = spawnSync('node', [CLI, 'keeper', '--from-words'], { env, input: mw, encoding: 'utf8' });
  const first = (JSON.parse(kp.stdout || '{}') as { me?: { did: string } }).me;
  const cli = spawn('node', [CLI, 'ui', '--no-open'], { env });
  let out = '', err = '';
  cli.stdout.on('data', (d) => { out += d; }); cli.stderr.on('data', (d) => { err += d; });
  const end = Date.now() + 20000;
  while (!/http:\/\/127\.0\.0\.1:\d+\/#t=[0-9a-f]{32}/.test(out) && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
  const url = /http:\/\/127\.0\.0\.1:(\d+)\/#t=([0-9a-f]{32})/.exec(out);
  const meRes = url ? await http(Number(url[1]), 'GET', '/api/me', { 'X-Sigelo-Token': url[2]! }) : null;
  ok('ui (CLI) after keeper --from-words: the page answers for the root identity of the words',
    kp.status === 0 && existsSync(made) && first?.did !== undefined && meRes?.status === 200 && (JSON.parse(meRes.body) as { did: string }).did === first.did, `${kp.stderr}\n${out}\n${err}`);
  const exited = new Promise<number | null>((r) => cli.on('close', r));
  cli.kill('SIGTERM');
  const code = await exited;
  // Windows has no SIGTERM: kill() ends the process at once, no handler runs and the lock file
  // stays; a dead pid in it holds nothing (lockHolder checks the pid), so the next ui starts.
  ok('ui (CLI): SIGTERM stops it, exit 0, lock gone (Windows: ended at once, the stale lock holds nothing)',
    posixModes ? code === 0 && !existsSync(ui.lockPath(made)) : code !== 0 && ui.uiHolder(made) === null);

  // End to end against the relay the contact tests use, in this process.
  if (!hasRelay()) console.log(`SKIP ui end to end: ${NO_RELAY}`);
  else {
    const relay = await startTestRelay(H), endpoints = relay.endpoints;
    const open = async (n: string) => {
      const d = join(H, n);
      mkdirSync(join(d, 'agents'), { recursive: true, mode: 0o700 });
      const words = newRoot();
      fromWords(join(d, 'me.local.json'), words);
      const u = await ui.startUi({ identity: join(d, 'me.local.json'), agents: join(d, 'agents'), carrier: { relay: 'relay.test', shortRelay: 'relay.test', registry: false, endpoints } });
      const call = async (method: string, path: string, body?: unknown): Promise<Record<string, any>> => {
        const r = await http(u.port, method, path, method === 'POST' ? { 'X-Sigelo-Token': u.token, Origin: `http://127.0.0.1:${u.port}`, 'Content-Type': 'application/json' } : { 'X-Sigelo-Token': u.token }, body ?? (method === 'POST' ? {} : undefined));
        return { ...(JSON.parse(r.body) as object), http: r.status };
      };
      return { u, call, dir: d, words };
    };
    const until = async <T>(f: () => Promise<T | undefined>, ms = 15000): Promise<T | undefined> => { const e = Date.now() + ms; for (;;) { const v = await f(); if (v || Date.now() > e) return v; await new Promise((r) => setTimeout(r, 200)); } };
    const A = await open('alice'), B = await open('bob');
    try {
      const inv = await A.call('POST', '/api/invite', { name: 'bob' });
      ok('ui e2e: invite → an 8-character code and the relay\'s expiry, about 10 minutes', /^[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(String(inv['short'])) && Math.abs(inv['short_exp'] - Date.now() / 1000 - 600) < 30 && inv['code']?.startsWith('sgl1'), JSON.stringify(inv));
      const pend = await A.call('GET', '/api/state');
      ok('ui e2e: the state lists it pending, with the short code and its expiry', pend['pending'].invites.some((x: { id: string; short: string }) => x.id === inv['id'] && x.short === inv['short']));
      ok('ui e2e: accept with tier own → 400 (own is detected, never asked)', (await B.call('POST', '/api/accept', { code: 'K7F3-Q9ZP', tier: 'own' }))['http'] === 400);
      const acc = await B.call('POST', '/api/accept', { code: String(inv['short']).toLowerCase().replace('-', ' '), name: 'alice', tier: 'quiet' });
      ok('ui e2e: accept, the short code as typed (lower case, a space), tier quiet → connected, with the four words, filed quiet', acc['status'] === 'connected' && /^\w+ \w+ \w+ \w+$/.test(acc['contact']?.fingerprint)
        && acc['contact']?.tier === 'quiet', JSON.stringify(acc));
      const bob = await until(async () => ((await A.call('GET', '/api/state'))['groups'].contacts as { name: string; did: string; words: string; words_checked: boolean }[]).find((c) => c.name === 'bob'));
      ok('ui e2e: the inviter\'s page files the contact, the same four words, not yet checked, tier friend (the default), under Contacts', bob?.words === acc['contact']?.fingerprint && bob?.words_checked === false
        && (bob as unknown as { tier: string }).tier === 'friend', JSON.stringify(bob));
      const tq = await A.call('POST', '/api/tier', { contact: bob!.did, tier: 'own' });
      const inMine = ((await A.call('GET', '/api/state'))['groups'].mine as { did: string; tier: string }[]).find((c) => c.did === bob!.did);
      ok('ui e2e: /api/tier own → {did, name, tier}; the contact moves to Mine', tq['http'] === 200 && tq['tier'] === 'own' && tq['name'] === 'bob' && inMine?.tier === 'own', JSON.stringify(tq));
      const tf = await A.call('POST', '/api/tier', { contact: bob!.did, tier: 'friend' });
      ok('ui e2e: /api/tier back to friend; a bad tier → 400; no contact → 404', tf['tier'] === 'friend' && (await A.call('POST', '/api/tier', { contact: bob!.did, tier: 'vip' }))['http'] === 400
        && (await A.call('POST', '/api/tier', { contact: 'did:sigelo:zNope', tier: 'quiet' }))['http'] === 404);
      const paired = (await A.call('GET', '/api/state'))['pending'].paired as { id: string; paired: string }[];
      ok('ui e2e: the pairing view finds its code paired', paired.some((x) => x.id === inv['id'] && x.paired === bob?.did));
      await A.call('POST', '/api/words', { contact: bob!.did, match: true });
      await B.call('POST', '/api/words', { contact: acc['contact'].did, match: true });
      const checked = ((await A.call('GET', '/api/state'))['groups'].contacts as { did: string; words_checked: boolean }[]).find((c) => c.did === bob!.did);
      ok('ui e2e: "They match" is kept', checked?.words_checked === true);
      const sent = await A.call('POST', '/api/send', { to: bob!.did, text: 'hello bob' });
      ok('ui e2e: send → sent', sent['http'] === 200 && sent['status'] === 'sent' && sent['kind'] === 'out', JSON.stringify(sent));
      const got = await until(async () => ((await B.call('GET', '/api/state'))['groups'].contacts as { did: string; unread: number; last: { text: string } }[]).find((c) => c.unread > 0));
      ok('ui e2e: the other page receives it: unread 1, last message', got?.unread === 1 && got.last.text === 'hello bob', JSON.stringify(got));
      const msgs = await B.call('GET', `/api/messages?contact=${encodeURIComponent(acc['contact'].did)}`);
      ok('ui e2e: messages → the text, from them; read once shown', msgs['messages']?.[0]?.text === 'hello bob' && msgs['messages'][0].dir === 'in'
        && ((await B.call('GET', '/api/state'))['groups'].contacts as { unread: number }[])[0]?.unread === 0);
      await B.call('POST', '/api/send', { to: acc['contact'].did, text: 'hi alice ‮evil' });
      const back = await until(async () => ((await A.call('GET', `/api/messages?contact=${encodeURIComponent(bob!.did)}`))['messages'] as { dir: string; text: string }[]).find((m) => m.dir === 'in'));
      ok('ui e2e: and back; history keeps both, a bidi override as \\u escape in the JSON', back?.text === 'hi alice ‮evil'
        && readFileSync(join(A.dir, 'me.local.history.jsonl'), 'utf8').split('\n').filter(Boolean).length >= 3);
      const renamed = await A.call('POST', '/api/rename', { contact: bob!.did, name: 'Bob B' });
      const tagged = await A.call('POST', '/api/tag', { contact: bob!.did, tags: ['#work', 'family'] });
      const after = ((await A.call('GET', '/api/state'))['groups'].contacts as { did: string; name: string; tags: string[] }[]).find((c) => c.did === bob!.did);
      ok('ui e2e: rename and tag', renamed['http'] === 200 && tagged['http'] === 200 && after?.name === 'Bob B' && after.tags.join() === 'work,family', JSON.stringify(after));
      const carrierState = JSON.parse(readFileSync(join(A.dir, 'me.local.carrier.json'), 'utf8')) as { events: unknown[]; inbox: unknown[] };
      ok('ui e2e: the page takes what the carrier keeps through inbox(): no events, no messages left in its state', carrierState.events.length === 0 && carrierState.inbox.length === 0, JSON.stringify(carrierState.events).slice(0, 300));
      const inv2 = await A.call('POST', '/api/invite', { name: 'later', long: true });
      const cancelled = await A.call('POST', '/api/invite/cancel', { id: inv2['id'] });
      const pend2 = (await A.call('GET', '/api/state'))['pending'].invites as { name: string }[];
      ok('ui e2e: cancel an invite → {cancelled: true}; no longer pending; again → 404', cancelled['cancelled'] === true && !pend2.some((x) => x.name === 'later')
        && (await A.call('POST', '/api/invite/cancel', { id: inv2['id'] }))['http'] === 404, JSON.stringify(cancelled));
      const meState = (await A.call('GET', '/api/state'))['me'] as { clock_offset: number | null; clock_checked: number | null };
      ok('ui e2e: me.clock_offset from the carrier: about 0 against a relay on this machine', meState.clock_offset !== null && Math.abs(meState.clock_offset) <= 2 && meState.clock_checked !== null, JSON.stringify(meState));
      // An agent on A's machine with a random key and one contact: Enrol makes it worker 0 of A's
      // keeper root (its old files set aside, the contact warned of), then it is paired in-process.
      const bot = join(A.dir, 'agents', 'sigelo.bot.local.json');
      spawnSync('node', [CLI, 'init', '--no-recovery'], { env: { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: bot } });
      const botOld = did(load(bot).genesis);
      writeFileSync(join(A.dir, 'agents', 'sigelo.bot.local.contacts.json'), JSON.stringify({ contacts: { 'did:sigelo:zSomeone': { did: 'did:sigelo:zSomeone', revoked: false } } }));
      const listed = ((await A.call('GET', '/api/agents')) as unknown as { 0: { name: string; worker: number | null; mine: unknown; contacts: number } })[0];
      ok('ui e2e: GET /api/agents: a random-key agent is no worker, not mine, its contacts counted', listed.name === 'bot' && listed.worker === null && listed.mine === null && listed.contacts === 1, JSON.stringify(listed));
      ok('ui e2e: the random-key attest route is gone (POST /api/agents/mine → 404)', (await A.call('POST', '/api/agents/mine', { agent: 'bot' }))['http'] === 404);
      const KA = keeperRoot(rootFromMnemonic(A.words), 1), en = await A.call('POST', '/api/agents/enrol', { agent: 'bot' });
      const att = load(bot).attestations[0]?.body;
      ok('ui e2e: Enrol → worker 0 of my keeper root in the agent\'s file, an operator attestation from my DID, 90 days, invite, claims {relay}', en['http'] === 200 && en['worker'] === 0 && en['renewed'] === false
        && load(bot).secret === Buffer.from(agentIdentitySeed(KA, 0, 0)).toString('hex') && att?.ctx === 'sigelo-relay/operator' && att.sub === en['did']
        && att.admission === 'invite' && att.exp - att.iat === 90 * 86400 && JSON.stringify(att.claims) === '{"relay":"relay.test"}' && att.iss === (await A.call('GET', '/api/me'))['did'], JSON.stringify(en));
      ok('ui e2e: Enrol warns that its 1 contact knows the old DID; the old files are set aside', en['contacts'] === 1 && String(en['warning']).includes(`know its old DID ${botOld}`)
        && existsSync(join(A.dir, 'agents', `sigelo.bot.local.old-${botOld.slice(-8)}.json`)) && existsSync(join(A.dir, 'agents', `sigelo.bot.local.old-${botOld.slice(-8)}.contacts.json`))
        && !existsSync(join(A.dir, 'agents', 'sigelo.bot.local.contacts.json')), JSON.stringify(en));
      const roster = JSON.parse(readFileSync(join(A.dir, 'me.local.keeper.json'), 'utf8')) as { workers: Record<string, { name: string; did: string; placed: string }> };
      ok('ui e2e: the roster has it: worker 0, bot, here', roster.workers['0']?.name === 'bot' && roster.workers['0'].did === en['did'] && roster.workers['0'].placed === 'here');
      const renew = await A.call('POST', '/api/agents/enrol', { agent: 'bot' });
      const listed2 = ((await A.call('GET', '/api/agents')) as unknown as { 0: { worker: number; mine: { days_left: number }; renew: boolean } })[0];
      ok('ui e2e: Enrol on a worker only renews: the same DID, renewed; listed worker 0, mine, no renew due', renew['renewed'] === true && renew['did'] === en['did'] && renew['worker'] === 0
        && listed2.worker === 0 && listed2.mine?.days_left >= 89 && listed2.renew === false, JSON.stringify(renew));
      spawnSync('node', [CLI, 'init', '--no-recovery'], { env: { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: join(B.dir, 'agents', 'sigelo.x.local.json') } });
      const bk = join(B.dir, 'me.local.keeper.json');
      renameSync(bk, `${bk}.away`);
      const noK = await B.call('POST', '/api/agents/enrol', { agent: 'x' });
      renameSync(`${bk}.away`, bk);
      ok('ui e2e: Enrol without a keeper root → 400, run sigelo-agent keeper --from-words once', noK['http'] === 400 && noK['error']?.check === 'keeper' && String(noK['error']?.message).includes('sigelo-agent keeper --from-words'), JSON.stringify(noK));
      const pairBot = await A.call('POST', '/api/agents/pair', { agent: 'bot' });
      const group = (await A.call('GET', '/api/state'))['groups'] as { mine: { name: string; local: string; words_checked: boolean; mine: { days_left: number } }[] };
      ok('ui e2e: pair with my agent in-process → connected; it sits in Mine (tier own, detected), on this machine, words checked', pairBot['status'] === 'connected' && group.mine[0]?.local === 'bot'
        && group.mine[0].words_checked && group.mine[0].mine.days_left >= 89 && (group.mine[0] as unknown as { tier: string }).tier === 'own', JSON.stringify(group.mine));
      const botStore = JSON.parse(readFileSync(join(A.dir, 'me.local.contacts.json'), 'utf8')) as { contacts: Record<string, { name: string; tier: string; tier_by: string }> };
      ok('ui e2e: written to the store: own, auto', Object.values(botStore.contacts).some((c) => c.name === 'bot' && c.tier === 'own' && c.tier_by === 'auto'));
      const taken = await A.call('POST', '/api/rename', { contact: group.mine[0] && (group.mine[0] as unknown as { did: string }).did, name: 'Bob B' });
      ok('ui e2e: rename to another contact\'s name → 409 name_taken', taken['http'] === 409 && taken['error']?.check === 'name_taken', JSON.stringify(taken));
      // ---- links through the page: A links its agent bot to Bob (not A's: external); Bob's page answers.
      // bot pairs with Bob first (the link attaches the purpose to that pairing), then runs `watch`.
      const relayEnv = { PATH: process.env['PATH'] ?? '', SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: JSON.stringify(endpoints) };
      const aliceAtB = acc['contact'].did as string, botDid = (group.mine[0] as unknown as { did: string }).did;
      await B.call('POST', '/api/tier', { contact: aliceAtB, tier: 'friend' });
      const binv = await B.call('POST', '/api/invite', { name: 'bot', long: true });
      // Not spawnSync: the relay and both pages run in this process.
      const bacc = await new Promise<{ status: number | null; stderr: string }>((r) => {
        const c = spawn('node', [CLI, 'accept', binv['code'], '--name', 'bob', '--wait', '30', '--identity', bot], { env: relayEnv });
        let stderr = '';
        c.stderr.on('data', (d) => { stderr += d; }); c.stdout.resume();
        c.on('close', (status) => r({ status, stderr }));
      });
      const botAtB = await until(async () => ((await B.call('GET', '/api/state'))['groups'].contacts as { did: string; name: string }[]).find((c) => c.name === 'bot'));
      ok('ui links: bot (A\'s agent) and Bob paired first', bacc.status === 0 && botAtB !== undefined, bacc.stderr);
      const botWatch = spawn('node', [CLI, 'watch', '--identity', bot], { env: relayEnv });
      let botOut = '';
      botWatch.stdout.on('data', (d) => { botOut += d; }); botWatch.stderr.on('data', (d) => { botOut += d; });
      await until(async () => (botOut.includes('watching ') ? true : undefined));
      const made = async (id: string) => ((await A.call('GET', '/api/links'))['made'] as { id: string; status: string; check: string | null }[]).find((x) => x.id === id);
      const intro = (id: string) => until(async () => ((await B.call('GET', '/api/state'))['introductions'] as { id: string; name: string; purpose: string }[]).find((x) => x.id === id), 30000);
      // bot's record of Bob: paired before, so a link attaches to it at the ask (and leaves it at the end).
      const botBob = () => Object.values((JSON.parse(readFileSync(bot.replace(/\.json$/, '.contacts.json'), 'utf8')) as { contacts: Record<string, { name: string; revoked: boolean; link?: { id: string } }> }).contacts).find((c) => c.name === 'bob' && !c.revoked);
      const botFree = () => until(async () => (botBob() && !botBob()!.link ? true : undefined), 30000);
      const link = (purpose: string, extra = {}) => A.call('POST', '/api/link', { a: bob!.did, b: botDid, purpose, ...extra });
      try {
        const l1 = await link('book rooms for the offsite', { note: 'Ask for the group rate.' });
        ok('ui links: POST /api/link (Bob, bot) → pending, external, bot is A (yours), 30 days by default', l1['http'] === 200 && l1['status'] === 'pending' && l1['kind'] === 'external' && l1['a'] === botDid
          && l1['b'] === bob!.did && l1['expires'] - Date.now() / 1000 > 29 * 86400 && !JSON.stringify(l1).includes('sgl1'), JSON.stringify(l1));
        const i1 = await intro(l1['id']);
        ok('ui links: Bob\'s state carries the introduction for the banner {id, from, name, purpose}', i1?.name === 'alice' && i1.purpose === 'book rooms for the offsite', JSON.stringify(i1) + botOut);
        const r1 = (await B.call('GET', '/api/links'))['received'] as { id: string; from: string; peer: string; peer_name: string; purpose: string; note: string; quiet: boolean; exp: number }[];
        ok('ui links: GET /api/links at Bob: received {id, from, peer, purpose, note, exp}, no code', r1[0]?.id === l1['id'] && r1[0].from === aliceAtB && r1[0].note === 'Ask for the group rate.' && r1[0].quiet === false
          && r1[0].exp > Date.now() / 1000 && !JSON.stringify(r1).includes('sgl1'), JSON.stringify(r1));
        const quietly = await B.call('POST', '/api/links/answer', { id: l1['id'], accept: false });
        ok('ui links: refuse → refused, nothing told; gone from the list; A\'s link still pending', quietly['status'] === 'refused' && quietly['told'] === false
          && ((await B.call('GET', '/api/links'))['received'] as unknown[]).length === 0 && (await made(l1['id']))?.status === 'pending', JSON.stringify(quietly));
        const u1 = await A.call('POST', '/api/unlink', { id: l1['id'] });
        ok('ui links: unlink the pending link → ended; bot drops the purpose it attached', u1['status'] === 'ended' && u1['role'] === 'operator' && (await botFree()) === true && (await made(l1['id']))?.status === 'ended', JSON.stringify(u1));
        const l2 = await link('book rooms');
        await intro(l2['id']);
        const told = await B.call('POST', '/api/links/answer', { id: l2['id'], accept: false, tell: true });
        const m2 = await until(async () => { const m = await made(l2['id']); return m?.status === 'refused' ? m : undefined; });
        ok('ui links: refuse and tell → A\'s link refused, link_refused; bot told to drop it', told['http'] === 200 && told['status'] === 'refused' && m2?.check === 'link_refused' && (await botFree()) === true, JSON.stringify([told, m2]));
        const l3 = await link('book rooms, third try');
        await intro(l3['id']);
        const yes = await B.call('POST', '/api/links/answer', { id: l3['id'], accept: true, tier: 'friend' });
        const filed = await until(async () => ((await B.call('GET', '/api/state'))['groups'].contacts as { did: string; tier: string; link: { id: string; purpose: string } | null }[]).find((c) => c.link?.id === l3['id']));
        const m3 = await until(async () => { const m = await made(l3['id']); return m?.status === 'linked' ? m : undefined; });
        ok('ui links: accept at friend → Bob files bot at friend with the purpose; A\'s link linked; bot files Bob with it', yes['http'] === 200 && ['linked', 'accepting'].includes(yes['status'])
          && filed?.tier === 'friend' && filed.link?.purpose === 'book rooms, third try' && m3 !== undefined
          && botBob()?.link?.id === l3['id'], JSON.stringify([yes, filed, m3]));
        const own = await B.call('POST', '/api/tier', { contact: filed!.did, tier: 'own' });
        ok('ui links: /api/tier own on the linked agent → 409 link_tier', own['http'] === 409 && own['error']?.check === 'link_tier', JSON.stringify(own));
        // The page's messages: a linked contact's carry the link {id, purpose} (data, shown as a badge).
        await new Promise<void>((r) => { const c = spawn('node', [CLI, 'send', 'bob', 'about the rooms', '--identity', bot], { env: relayEnv }); c.stdout.resume(); c.stderr.resume(); c.on('close', () => r()); });
        const lmsg = await until(async () => ((await B.call('GET', `/api/messages?contact=${encodeURIComponent(filed!.did)}`))['messages'] as { text: string; dir: string; link: { id: string; purpose: string } | null }[]).find((m) => m.text === 'about the rooms'), 30000);
        ok('ui links: GET /api/messages: the linked agent\'s message carries link {id, purpose}', lmsg?.dir === 'in' && lmsg.link?.id === l3['id'] && lmsg.link?.purpose === 'book rooms, third try', JSON.stringify(lmsg) + botOut.slice(-300));
        const un = await A.call('POST', '/api/unlink', { id: l3['id'] });
        const dropped = await until(async () => ((await B.call('GET', '/api/state'))['groups'].contacts as { did: string; link: unknown }[]).find((c) => c.did === filed!.did && c.link === null));
        ok('ui links: unlink → ended; paired before, so Bob keeps bot, the purpose dropped', un['status'] === 'ended' && dropped !== undefined && (await made(l3['id']))?.status === 'ended' && (await botFree()) === true, JSON.stringify(un));
        const al = await B.call('POST', '/api/links/allow', { contact: aliceAtB, allow: true, tier: 'quiet', days: 5 });
        ok('ui links: allow alice at quiet for 5 days → in the list', al['http'] === 200 && al['tier'] === 'quiet' && ((await B.call('GET', '/api/links'))['allow'] as { contact: string; tier: string }[]).some((x) => x.contact === aliceAtB && x.tier === 'quiet'), JSON.stringify(al));
        const l4 = await link('pay the deposit');
        const byRule = await until(async () => ((await B.call('GET', '/api/state'))['groups'].contacts as { did: string; tier: string; link: { id: string } | null }[]).find((c) => c.link?.id === l4['id']), 30000);
        ok('ui links: the allow rule accepts by itself, at quiet; no banner for it', byRule?.tier === 'quiet' && !((await B.call('GET', '/api/state'))['introductions'] as { id: string }[]).some((x) => x.id === l4['id'])
          && (await until(async () => { const m = await made(l4['id']); return m?.status === 'linked' ? m : undefined; })) !== undefined, JSON.stringify(byRule) + botOut);
        const dn = await B.call('POST', '/api/links/allow', { contact: aliceAtB, allow: false });
        ok('ui links: deny → the rule gone', dn['http'] === 200 && dn['had'] === true && ((await B.call('GET', '/api/links'))['allow'] as unknown[]).length === 0, JSON.stringify(dn));
        const hist = readFileSync(join(B.dir, 'me.local.history.jsonl'), 'utf8') + readFileSync(join(A.dir, 'me.local.history.jsonl'), 'utf8');
        ok('ui links: no link message nor code in either page\'s history', !hist.includes('sigelo-link/') && !/sgl1[1-9A-HJ-NP-Za-km-z]{16}/.test(hist));
      } finally {
        const closed = new Promise((r) => botWatch.on('close', r));
        botWatch.kill('SIGTERM'); await closed;
      }
      // ---- devices through the pages: A adds a device online; B's page scans its QR as the new device.
      // The device side runs carriers of its own files, configured as the CLI's are (the environment).
      const envWas = { ...process.env };
      Object.assign(process.env, { SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: JSON.stringify(endpoints) });
      try {
        const dvA = (await A.call('GET', '/api/devices')) as Record<string, any>;
        const add = await A.call('POST', '/api/devices/add', { name: 'phone' });
        const qrText = qd.scanPng(qr.toPng(qr.encode(String(add['qr']), { ecc: 'M' })));
        ok('ui devices e2e: add online → SIGELO:DEV:<short code> (the test relay named), worker after the roster\'s, state code; its QR reads back', add['http'] === 200 && String(add['qr']).startsWith(`SIGELO:DEV:${add['short']}`)
          && add['state'] === 'code' && add['worker'] === 1 && qrText === add['qr'] && dvA['devices'].length === 0, JSON.stringify(add));
        const early = await A.call('POST', '/api/devices/confirm', { id: add['id'], match: true });
        ok('ui devices e2e: confirm before the device answered → 409 device_state', early['http'] === 409 && early['error']?.check === 'device_state', JSON.stringify(early));
        const sc = await B.call('POST', '/api/devices/scan', { text: qrText, name: 'phone' });
        ok('ui devices e2e: B scans it (the QR\'s text) → joining, into its agents\' directory', sc['http'] === 200 && sc['kind'] === 'online' && sc['file'] === join(B.dir, 'agents', 'sigelo.phone.local.json'), JSON.stringify(sc));
        const words = await until(async () => ((await A.call('GET', '/api/devices'))['adding'] as { id: string; state: string; words: string }[]).find((x) => x.id === add['id'] && x.state === 'words' && x.words), 30000);
        const bWords = await until(async () => { const j = (await B.call('GET', '/api/devices'))['joining'] as { words: string | null } | null; return j?.words ?? undefined; }, 30000);
        ok('ui devices e2e: both pages show the same four words; A\'s waits for the human, nothing sent yet', words !== undefined && words.words === bWords && /^\w+ \w+ \w+ \w+$/.test(words.words)
          && !existsSync(join(B.dir, 'agents', 'sigelo.phone.local.json')), JSON.stringify([words, bWords]));
        const yes = await A.call('POST', '/api/devices/confirm', { id: add['id'], match: true });
        const doneA = await until(async () => ((await A.call('GET', '/api/devices'))['adding'] as { id: string; state: string }[]).find((x) => x.id === add['id'] && x.state === 'done'), 60000);
        const doneB = await until(async () => { const j = (await B.call('GET', '/api/devices'))['joining'] as { state: string; worker: number; did: string } | null; return j?.state === 'done' || j?.state === 'failed' ? j : undefined; }, 60000);
        const listed = ((await A.call('GET', '/api/devices'))['devices'] as { name: string; worker: number; paired: boolean; tier: string; did: string; seen: number | null }[]).find((x) => x.name === 'phone');
        ok('ui devices e2e: "They match" → the worker sent; A files it (paired, own); B\'s page has worker 1 in sigelo.phone.local.json, the device list taken', yes['http'] === 200 && doneA !== undefined
          && doneB?.state === 'done' && doneB.worker === 1 && doneB.did === listed?.did && (doneB as unknown as { list: number }).list >= 1 && listed?.paired === true && listed.tier === 'own'
          && load(join(B.dir, 'agents', 'sigelo.phone.local.json')).secret === Buffer.from(agentIdentitySeed(keeperRoot(rootFromMnemonic(A.words), 1), 1, 0)).toString('hex'), JSON.stringify([yes, doneA, doneB, listed]));
        // Offline: A's frames and words; B's page reads the frames (one, then all), wrong words, then the right ones.
        const off2 = await A.call('POST', '/api/devices/add', { name: 'tab', offline: true }), wd = await A.call('POST', '/api/devices/words', { id: off2['id'] });
        const frames = off2['frames'] as string[];
        const f1 = await B.call('POST', '/api/devices/scan', { texts: frames.slice(-1), name: 'tab' });
        const f2 = await B.call('POST', '/api/devices/scan', { texts: frames, name: 'tab' });
        const bad = await B.call('POST', '/api/devices/scan', { texts: frames, name: 'tab', words: 'abandon ability able about above absent' });
        const got = await B.call('POST', '/api/devices/scan', { texts: [...frames].reverse(), name: 'tab', words: String(wd['words']).toUpperCase() });
        ok('ui devices e2e: offline frames in any order: some → frames (have, count, missing), all → words; wrong words 409 device_words; right → worker 2 written, paired through the 7-day invite',
          (frames.length === 1 ? f1['state'] === 'words' : f1['state'] === 'frames' && f1['have'] === 1 && f1['count'] === frames.length) && f2['state'] === 'words' && bad['http'] === 409 && bad['error']?.check === 'device_words'
          && got['state'] === 'done' && got['worker'] === 2 && got['file'] === join(B.dir, 'agents', 'sigelo.tab.local.json') && existsSync(got['file']) && got['paired'] === true, JSON.stringify([f1, f2, bad, got]).slice(0, 600));
        // Revoke the online one: a wipe; the device takes it (device sync on its file), deletes its keys and answers; A forgets it.
        const rv = await A.call('POST', '/api/devices/revoke', { name: 'phone' });
        const phoneFile = join(B.dir, 'agents', 'sigelo.phone.local.json');
        const wiped = await new Promise<{ status: number | null; out: string }>((r) => {
          const c = spawn('node', [CLI, 'device', 'sync', '--identity', phoneFile, '--wait', '20'], { env: relayEnv });
          let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; });
          c.on('close', (status) => r({ status, out }));
        });
        const forgotten = await until(async () => (((await A.call('GET', '/api/state'))['groups'].mine as { did: string }[]).some((c) => c.did === listed?.did) ? undefined : true), 30000);
        const after = ((await A.call('GET', '/api/devices'))['devices'] as { name: string; revoked: number | null; paired: boolean }[]).find((x) => x.name === 'phone');
        ok('ui devices e2e: revoke phone → wipe sent (not lost); the device wipes itself and answers; A forgets it, listed revoked', rv['http'] === 200 && rv['lost'] === false && typeof rv['revoked'] === 'number'
          && !existsSync(phoneFile) && forgotten === true && after?.revoked === rv['revoked'] && after.paired === false, JSON.stringify([rv, after]) + wiped.out.slice(-400));
        const sy = await A.call('POST', '/api/devices/sync');
        ok('ui devices e2e: sync → the list to the one live device (tab)', sy['http'] === 200 && sy['synced'] === 1, JSON.stringify(sy));
        const histA = readFileSync(join(A.dir, 'me.local.history.jsonl'), 'utf8'), histB = readFileSync(join(B.dir, 'me.local.history.jsonl'), 'utf8');
        ok('ui devices e2e: no enrolment, identity or device message, no key and no code in either page\'s history', !/sigelo-(enrol|identity|device)\//.test(histA + histB) && !/"secret"|sgl1[1-9A-HJ-NP-Za-km-z]{16}/.test(histA + histB));
      } finally { for (const k of ['SIGELO_RELAY', 'SIGELO_SHORT_RELAY', 'SIGELO_RELAY_REGISTRY', 'SIGELO_RELAY_ENDPOINTS']) { if (envWas[k] === undefined) delete process.env[k]; else process.env[k] = envWas[k]; } }
      // ---- agents through the page (UI-API.md /api/agents/*): the keeper's workers; a one-time code issued on the
      // page's own session (the CLI's enrol refuses busy beside it); a Node agent runs init --enrol with it.
      {
        const noTok = await http(A.u.port, 'GET', '/api/agents/workers', {}), noOrig = await http(A.u.port, 'POST', '/api/agents/enrol-code', { 'X-Sigelo-Token': A.u.token, 'Content-Type': 'application/json' }, { name: 'x' });
        ok('ui agents: GET /api/agents/workers without the token, POST /api/agents/enrol-code without Origin → 403', noTok.status === 403 && noOrig.status === 403);
        type Wk = { worker: number; name: string; did: string; original: string; placed: string; status: string; tier: string | null; contact: string | null; local: string | null; revoked: number | null; attested_until: number | null;
          enrolling: { id: string; state: string; code: string | null; words: string | null; command: string | null } | null };
        const wl = async () => (await A.call('GET', '/api/agents/workers')) as { http: number; keeper: boolean; seat: string | null; workers: Wk[] };
        const w0 = await wl();
        ok('ui agents: the list from the keeper: bot worker 0 on this machine, enrolled; phone revoked; tab a device', w0.http === 200 && w0.keeper === true
          && w0.workers.find((w) => w.worker === 0)?.status === 'enrolled' && w0.workers[0]?.local === 'bot' && w0.workers.find((w) => w.name === 'phone')?.status === 'revoked'
          && w0.workers.find((w) => w.name === 'tab')?.placed === 'device', JSON.stringify(w0).slice(0, 600));
        const bad = await A.call('POST', '/api/agents/enrol-code', { name: 'Not OK' }), taken = await A.call('POST', '/api/agents/enrol-code', { name: 'bot' }), noB = await B.call('POST', '/api/agents/rename', { worker: 0, name: 'x' });
        ok('ui agents: a bad name → 400; a name a worker has → 409 name_taken; B (keeper of its own, no worker 0) → 404 worker', bad['http'] === 400 && taken['http'] === 409 && taken['error']?.check === 'name_taken'
          && noB['http'] === 404 && noB['error']?.check === 'worker', JSON.stringify([bad, taken, noB]));
        const cli = (args: string[], env: Record<string, string>) => new Promise<{ status: number | null; out: string }>((r) => {
          const c = spawn('node', [CLI, ...args], { env });
          let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; });
          c.on('close', (status) => r({ status, out }));
        });
        const busyCli = await cli(['enrol', '--name', 'cli', '--identity', join(A.dir, 'me.local.json')], relayEnv);
        ok('ui agents: the CLI\'s enrol beside the page → busy (the page enrols)', busyCli.status === 1 && /busy|open in sigelo-agent ui/.test(busyCli.out), busyCli.out.slice(-300));
        const ec = await A.call('POST', '/api/agents/enrol-code', { name: 'vps', tier: 'friend' });
        const KA = keeperRoot(rootFromMnemonic(A.words), 1);
        ok('ui agents: enrol-code → worker 3 (after the roster\'s), an 8-character code for 10 minutes, the command for the agent\'s machine, tier friend', ec['http'] === 200 && ec['worker'] === 3
          && /^[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(String(ec['code'])) && ec['state'] === 'code' && Math.abs(ec['exp'] - Date.now() / 1000 - 600) < 30
          && ec['command'] === `SIGELO_RELAY=relay.test sigelo-agent init --enrol ${ec['code']}` && ec['tier'] === 'friend' && typeof ec['did'] === 'string', JSON.stringify(ec));
        const st0 = await A.call('GET', '/api/state');
        ok('ui agents: the code\'s own invite is not among the page\'s pending invites (it shows in Agents)', !(st0['pending'].invites as { name: string }[]).some((x) => x.name.includes('(enrolling)')), JSON.stringify(st0['pending']));
        const vpsFile = join(H, 'vps', 'sigelo.local.json');
        mkdirSync(join(H, 'vps'), { recursive: true, mode: 0o700 });
        const joined = await cli(['init', '--enrol', String(ec['code']), '--wait', '90'], { ...relayEnv, SIGELO_IDENTITY: vpsFile });
        const done_ = async () => { const w = (await wl()).workers.find((x) => x.worker === 3); return w?.status === 'enrolled' && w.contact ? w : undefined; };
        const vps = await until(done_, 30000);
        ok('ui agents: a Node agent runs init --enrol CODE → worker 3 on its machine (its key from my keeper root), paired with me', joined.status === 0 && existsSync(vpsFile)
          && load(vpsFile).secret === Buffer.from(agentIdentitySeed(KA, 3, 0)).toString('hex'), joined.out.slice(-600));
        ok('ui agents: the list shows it enrolled: on another machine, tier friend (my choice), its contact; the four words kept', vps !== undefined && vps.placed === 'remote' && vps.tier === 'friend'
          && vps.did === ec['did'] && /^\w+ \w+ \w+ \w+$/.test(vps.enrolling?.words ?? '') && joined.out.includes(vps.enrolling!.words!) && (vps.attested_until ?? 0) > Date.now() / 1000 + 80 * 86400, JSON.stringify(vps) + joined.out.slice(-300));
        const st1 = await A.call('GET', '/api/state'), inMine = (st1['groups'].mine as { did: string; ours: boolean; name: string }[]).find((c) => c.did === vps?.contact);
        ok('ui agents: it sits in Mine (ours by the attestation), named vps; the temporary DID forgotten', inMine?.ours === true && inMine.name === 'vps'
          && !([...st1['groups'].mine, ...st1['groups'].contacts] as { name: string }[]).some((c) => c.name.includes('(enrolling)')), JSON.stringify(st1['groups']).slice(0, 500));
        const rn = await A.call('POST', '/api/agents/rename', { worker: 3, name: 'vps2' });
        ok('ui agents: rename → the roster and its contact', rn['http'] === 200 && (await wl()).workers.find((x) => x.worker === 3)?.name === 'vps2'
          && ((await A.call('GET', '/api/state'))['groups'].mine as { did: string; name: string }[]).find((c) => c.did === vps?.contact)?.name === 'vps2', JSON.stringify(rn));
        // A standby: the seat on another device (the list naming another holder): agents are enrolled at the seat only.
        const lp = join(A.dir, 'me.local.devices.json'), keepList = readFileSync(lp, 'utf8'), l = JSON.parse(keepList);
        writeFileSync(lp, JSON.stringify({ ...l, seat: { holder: 'did:sigelo:zElsewhere', epoch: 9 } }));
        const se = await A.call('POST', '/api/agents/enrol-code', { name: 'other' }), sr = await A.call('POST', '/api/agents/revoke', { worker: 3 }), sw = await wl();
        writeFileSync(lp, keepList);
        ok('ui agents: the seat elsewhere → enrol-code and revoke 409 seat_elsewhere; the list still reads (seat elsewhere)', se['http'] === 409 && se['error']?.check === 'seat_elsewhere'
          && sr['http'] === 409 && sr['error']?.check === 'seat_elsewhere' && sw.http === 200 && sw.seat === 'elsewhere', JSON.stringify([se, sr, sw.seat]));
        const rv = await A.call('POST', '/api/agents/revoke', { worker: 3 }), after = (await wl()).workers.find((x) => x.worker === 3);
        const gone = !([...(await A.call('GET', '/api/state'))['groups'].mine] as { did: string }[]).some((c) => c.did === vps?.contact);
        ok('ui agents: revoke → revoked, its contact forgotten, the attestation\'s end said; again → 409 revoked', rv['http'] === 200 && typeof rv['revoked'] === 'number' && rv['forgot'] === vps?.contact
          && rv['attested_until'] === vps?.attested_until && after?.status === 'revoked' && gone && (await A.call('POST', '/api/agents/revoke', { worker: 3 }))['error']?.check === 'revoked', JSON.stringify([rv, after]));
        const ec2 = await A.call('POST', '/api/agents/enrol-code', { name: 'later' }), cn = await A.call('POST', '/api/agents/revoke', { worker: ec2['worker'] });
        ok('ui agents: a code nobody used, revoked → cancelled, the index free again', ec2['worker'] === 4 && cn['cancelled'] === true && !(await wl()).workers.some((x) => x.worker === 4), JSON.stringify([ec2, cn]));
        const rt = await A.call('POST', '/api/relays/test', { relay: 'relay.test' }), rb = await A.call('POST', '/api/relays/test', { relay: 'not a host' }), rn2 = await A.call('POST', '/api/relays/test', { relay: 'nowhere.invalid' });
        ok('ui relay picker: Test → the test relay answers (ms); a bad host 400; a host that does not answer → ok false, why', rt['http'] === 200 && rt['ok'] === true && typeof rt['ms'] === 'number'
          && rb['http'] === 400 && rn2['http'] === 200 && rn2['ok'] === false && typeof rn2['detail'] === 'string', JSON.stringify([rt, rb, rn2]));
        const hist = readFileSync(join(A.dir, 'me.local.history.jsonl'), 'utf8');
        ok('ui agents: no enrolment or identity message, no key in the page\'s history', !/sigelo-(enrol|identity)\//.test(hist) && !/"secret"/.test(hist));
      }
      const forgot = await A.call('POST', '/api/words', { contact: bob!.did, match: false });
      ok('ui e2e: "They don\'t" forgets and blocks', forgot['http'] === 200 && !((await A.call('GET', '/api/state'))['groups'].contacts as { did: string }[]).some((c) => c.did === bob!.did));
    } finally {
      await A.u.close(); await B.u.close();
      await relay.close?.();
    }
  }
  rmSync(H, { recursive: true, force: true });
}

done(import.meta.filename);
