// SPDX-License-Identifier: MIT
// sigelo-agent ui (sigelo-agent-ui.ts, UI-API.md).
//   node test-ui.ts   (the end-to-end part SKIPs without relay/ and its node_modules)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
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

  // The CLI: no identity → keeper --from-words, once; then the page, for the DID of the words.
  const env = { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: JSON.stringify(unreachable.endpoints) };
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
      const u = await ui.startUi({ identity: join(d, 'me.local.json'), agents: join(d, 'agents'), carrier: { relay: 'relay.test', endpoints } });
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
