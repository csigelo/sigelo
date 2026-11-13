// SPDX-License-Identifier: MIT
// sigelo-agent ui (sigelo-agent-ui.ts, UI-API.md).
//   node test-ui.ts   (the end-to-end part SKIPs without relay/ and its node_modules)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
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
  ok('ui.js: a control to confirm under Requests (the four words, Confirm / Refuse → POST /api/controls/confirm), a pushed state cut short ("The newest … are shown", "Show all" → full=1), a linked contact\'s message marked',
    js.body.includes('wants to control this computer') && js.body.includes('/api/controls/confirm') && js.body.includes("btn('Confirm'") && js.body.includes("btn('Refuse'")
    && js.body.includes('The newest ${cut.kept}') && js.body.includes("btn('Show all'") && js.body.includes('full=1') && js.body.includes('m.link ? h(\'span\', { class: \'help\' }, `Introduced: ${m.link.purpose}`)'));
  // The keeper of this computer (UI-API.md "Keeper", sigelo-agent-spend.ts): a sigelo-spend directory registered on this host,
  // its policy read and written field by field, a pending request (signed by the keeper) approved with the human's key at the
  // keeper's own /approve (a stand-in that checks the signature as the keeper does), refused here, restart refused without systemd.
  {
    const { keygen, sign: sg, verifySig: vs, verify: vf, decodeKey } = await import('sigelo');
    const { encodeAddress } = await import('sigelo/dist/monero.js');
    const KD = join(H, 'keeper-dir'), REG = join(H, 'keepers.json');
    mkdirSync(KD, { mode: 0o700 });
    const kid = keygen({ recovery: 'sha256:' + '1'.repeat(64) }), agentId = keygen({ recovery: 'sha256:' + '2'.repeat(64) });
    const pt = (): Uint8Array => decodeKey(keygen({ recovery: 'sha256:' + '3'.repeat(64) }).key);
    const ADDR = encodeAddress({ net: 'stagenet', kind: 'standard', spend: pt(), view: pt() }), MAIN = encodeAddress({ net: 'mainnet', kind: 'standard', spend: pt(), view: pt() });
    const meDid = (JSON.parse((await http(P, 'GET', '/api/me', T)).body) as { did: string }).did;
    const policy = { net: 'stagenet', wallet: { rpc: 'http://127.0.0.1:38083/json_rpc', login: 'u:p' }, unlock_time: 0, priority: 1, approvers: [{ did: meDid }],
      agents: { scout: { account: 1, token_hash: 'sha256:' + 'a'.repeat(64), did: agentId.did, genesis: agentId.genesis, per_tx_max: '100000000000', per_period_max: '500000000000', period_seconds: 2592000,
        rate_per_minute: 3, approval_above: '20000000000', allow: [{ addr: ADDR, label: 'seat-hold' }] } } };
    writeFileSync(join(KD, 'policy.json'), JSON.stringify(policy), { mode: 0o600 });
    writeFileSync(join(KD, 'identity.json'), JSON.stringify({ v: 'sigelo/0', typ: 'bundle', genesis: kid.genesis, rotations: [], bindings: [], attestations: [], issuers: [] }));
    const t0 = Math.floor(Date.now() / 1000), NONCE = 'ab'.repeat(16);
    const body = { v: 'sigelo/0', typ: 'spend-approval', keeper: kid.did, net: 'stagenet', agent: agentId.did, ref: 'r1', to: ADDR, amount: '30000000000', purpose: 'seat-hold service', nonce: NONCE, iat: t0 - 60, exp: t0 + 3540 };
    const line = (entry: object, secret = kid.secret) => JSON.stringify({ entry, sig: sg(secret, entry) }) + '\n';
    const intent = { ts: t0 - 100, status: 'intent', request: { to: { addr: ADDR }, amount: '100000000000', agent: 'scout', purpose: 'x', ref: 'r0', fp: 'f' }, plan: {}, txid: 'aa', amount: '100000000000', fee: '20000000000' };
    const pending = { ts: t0 - 60, status: 'pending', request: { to: { addr: ADDR }, amount: '30000000000', agent: 'scout', purpose: 'seat-hold service', ref: 'r1', fp: 'f' }, plan: {}, txid: '', amount: '30000000000', fee: '0', approval_request: body };
    const forged = { ...pending, approval_request: { ...body, nonce: 'cd'.repeat(16) } };
    // A second request, refused at the keeper through the page (pass 4).
    const REFQ = { ...body, nonce: 'ef'.repeat(16), ref: 'r2', amount: '40000000000', purpose: 'a table' };
    const pending2 = { ...pending, ts: t0 - 30, request: { ...pending.request, ref: 'r2', amount: '40000000000', purpose: 'a table' }, amount: '40000000000', approval_request: REFQ };
    writeFileSync(join(KD, 'spend.log'), line(intent) + line({ ...intent, status: 'relayed' }) + line(pending) + line(forged, agentId.secret) + line(pending2), { mode: 0o600 });
    // The keeper's /approve, as service.ts checks it: the body is the pending one, the bundle verifies, the sig is its head key's.
    const got: { body?: Record<string, unknown>; ok?: boolean; url?: string; reason?: string }[] = [];
    const { createServer } = await import('node:http');
    const fake = createServer((req, res) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => {
      const x = JSON.parse(b) as { body: Record<string, unknown>; sig: string; bundle: { genesis: { key: string } } };
      let good = false;
      // /refuse (0.1.15): the same body with typ spend-refusal, signed the same way, and the reason beside it.
      const want = req.url === '/refuse' ? { ...REFQ, typ: 'spend-refusal' } : body;
      try { good = (req.url === '/approve' || req.url === '/refuse') && req.headers.origin === undefined && JSON.stringify(x.body) === JSON.stringify(want) && vf(x.bundle as never, t0).did === meDid && vs(x.bundle.genesis.key, x.body, x.sig); } catch {}
      got.push({ body: x.body, ok: good, url: req.url, reason: (x as { reason?: string }).reason });
      res.writeHead(good ? 200 : 403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(good ? { status: 'approved' } : { error: 'approval: no', code: 'approval' }));
    }); });
    await new Promise<void>((r) => fake.listen(0, '127.0.0.1', () => r()));
    const kport = (fake.address() as { port: number }).port;
    writeFileSync(join(KD, 'install.json'), JSON.stringify({ v: 1, net: 'stagenet', port: kport, systemd: false, units: [] }));
    const kj = async () => JSON.parse((await http(P, 'GET', '/api/keeper', T)).body) as Record<string, any>;
    const post = async (route: string, b: unknown) => { const r = await http(P, 'POST', `/api/keeper/${route}`, W, b); return { status: r.status, body: JSON.parse(r.body) as Record<string, any> }; };
    process.env['SIGELO_SPEND_REGISTRY'] = join(H, 'none.json');
    ok('ui keeper: no keeper registered on this computer → {state: "none"}', (await kj()).state === 'none');
    writeFileSync(REG, JSON.stringify({ keepers: [{ dir: KD, did: kid.did, genesis: kid.genesis }] }));
    process.env['SIGELO_SPEND_REGISTRY'] = REG;
    const k1 = await kj(), a1 = k1.agents?.[0], r1 = k1.requests ?? [];
    ok('ui keeper: GET /api/keeper → here: the keeper (its DID, me an approver, restart by hand), scout\'s caps and allowlist, 0.12 spent (amount + fee, once per tx), one request (the forged one left out)',
      k1.state === 'here' && k1.keepers[0].id === 'keeper-dir' && k1.keepers[0].did === kid.did && k1.keepers[0].me_approver === true && k1.keepers[0].restart.can === false
      && a1.name === 'scout' && a1.worker === null && a1.per_tx_max === '100000000000' && a1.approval_above === '20000000000' && a1.allow[0].kind === 'addr' && a1.allow[0].label === 'seat-hold'
      && a1.spent === '120000000000' && a1.remaining === '380000000000' && r1.length === 2 && r1.some((x: { nonce: string; amount: string; purpose: string }) => x.nonce === NONCE && x.amount === '30000000000' && x.purpose === 'seat-hold service'), JSON.stringify(k1).slice(0, 600));
    ok('ui keeper: GET /api/keeper → seen: the addresses spend.log names (paid by scout), for Who it may pay; live/refuse not known without its frozen copy',
      k1.keepers[0].seen?.[0]?.addr === ADDR && k1.keepers[0].seen[0].agent === 'scout' && k1.keepers[0].seen[0].paid === true && k1.keepers[0].live === null && k1.keepers[0].refuse === null, JSON.stringify(k1.keepers[0]).slice(0, 400));
    const bad = [await post('agent', { keeper: 'keeper-dir', agent: 'scout', per_tx_max: '0.5' }), await post('agent', { keeper: 'keeper-dir', agent: 'nobody', per_tx_max: '1' }),
      await post('agent', { keeper: 'keeper-dir', agent: 'scout', per_tx_max: '900000000000' }), await post('agent', { keeper: 'keeper-dir', agent: 'scout', allow: [{ addr: MAIN }] }),
      await post('agent', { keeper: 'keeper-dir', agent: 'scout', period_seconds: 12345 }), await post('agent', { keeper: 'nope', agent: 'scout', per_tx_max: '1' })];
    ok('ui keeper: writes checked as the keeper checks: not atomic → 400, unknown agent 404, per payment above the period 400 keeper_caps, a mainnet address 400 allow_addr, an odd period 400, unknown keeper 404; nothing written',
      bad.map((x) => `${x.status}${x.body.error.check === 'body' ? '' : ' ' + x.body.error.check}`).join() === '400,404 keeper_agent,400 keeper_caps,400 allow_addr,400,404 keeper_unknown'
      && readFileSync(join(KD, 'policy.json'), 'utf8') === JSON.stringify(policy), bad.map((x) => JSON.stringify(x.body)).join(' '));
    const sv = await post('agent', { keeper: 'keeper-dir', agent: 'scout', per_tx_max: '50000000000', per_period_max: '600000000000', period_seconds: 604800, rate_per_minute: 5, max_delegates: 1, approval_above: null, allow: [{ addr: ADDR, label: 'seat-hold' }, { issuer: meDid, ctx: 'sigelo-relay/operator' }] });
    const pol = JSON.parse(readFileSync(join(KD, 'policy.json'), 'utf8')) as typeof policy & { agents: { scout: Record<string, unknown> } };
    ok('ui keeper: POST /api/keeper/agent → the fields written, every other kept (token_hash, account, the wallet login), 0600; the answer says how to restart it',
      sv.status === 200 && sv.body.saved === true && /sigelo-spend serve .*policy\.json --port \d+/.test(sv.body.restart.command) && pol.agents.scout['per_tx_max'] === '50000000000' && pol.agents.scout['period_seconds'] === 604800
      && pol.agents.scout['rate_per_minute'] === 5 && pol.agents.scout['max_delegates'] === 1 && !('approval_above' in pol.agents.scout) && pol.agents.scout['token_hash'] === 'sha256:' + 'a'.repeat(64)
      && pol.wallet.login === 'u:p' && (pol.agents.scout['allow'] as unknown[]).length === 2 && (posixModes ? (statSync(join(KD, 'policy.json')).mode & 0o777) === 0o600 : true), JSON.stringify(sv.body));
    await post('agent', { keeper: 'keeper-dir', agent: 'scout', approval_above: '20000000000' });
    const noAppr = await post('approvers', { keeper: 'keeper-dir', me: false });
    ok('ui keeper: approvers emptied while scout asks above a limit → 409 keeper_approvers', noAppr.status === 409 && noAppr.body.error.check === 'keeper_approvers', JSON.stringify(noAppr.body));
    const ap = await post('approve', { keeper: 'keeper-dir', nonce: NONCE });
    ok('ui keeper: Approve → the pending body, signed by this identity\'s key with its bundle, posted to the keeper\'s /approve (no Origin) → {approved}',
      ap.status === 200 && ap.body.approved === true && got.length === 1 && got[0]!.ok === true, JSON.stringify(ap.body) + JSON.stringify(got));
    const forgedAp = await post('approve', { keeper: 'keeper-dir', nonce: 'cd'.repeat(16) });
    ok('ui keeper: a pending line the keeper did not sign is no request: 404 keeper_request, nothing signed', forgedAp.status === 404 && forgedAp.body.error.check === 'keeper_request' && got.length === 1);
    const rf = await post('refuse', { keeper: 'keeper-dir', nonce: 'ef'.repeat(16), reason: 'not this month' }), k2 = await kj();
    const sent = got.at(-1)!;
    ok('ui keeper: Refuse → the spend-refusal (typ spend-refusal, signed with this identity\'s key, the reason) posted to the keeper\'s /refuse → logged; kept here too: the request leaves the list; no contact to tell',
      rf.status === 200 && rf.body.refused === true && rf.body.logged === true && sent.url === '/refuse' && sent.ok === true && sent.reason === 'not this month' && rf.body.told === false
      && (k2.requests as { nonce: string }[]).every((x) => x.nonce !== 'ef'.repeat(16)), JSON.stringify([rf.body, sent]));
    const rs = await post('restart', { keeper: 'keeper-dir' });
    ok('ui keeper: Restart without a systemd user unit → 409 keeper_restart naming the command', rs.status === 409 && rs.body.error.check === 'keeper_restart' && rs.body.error.message.includes('sigelo-spend serve'));
    const kind = await http(P, 'POST', '/api/kind', W, { contact: 'did:sigelo:zNope', kind: 'agent' }), kindBad = await http(P, 'POST', '/api/kind', W, { contact: 'did:sigelo:zNope', kind: 'robot' });
    ok('ui kind: POST /api/kind of no contact → 404 not_contact (the contact is checked first, any kind)', kind.status === 404 && JSON.parse(kind.body).error.check === 'not_contact' && kindBad.status === 404, kind.body + kindBad.body);
    // ---- the Wallet (UI-API.md "Wallet", sigelo-agent-wallet.ts) over a fake monero-wallet-rpc (digest login, as the keeper's),
    // a fake node and a fake price source: off asks nothing; the keeper's wallet, your account (never an agent's); every sync state;
    // review, send; receive; history; the service and the node; the price, through this server, kept 10 minutes; the live keeper.
    {
      const { createHash: ch } = await import('node:crypto');
      const md5 = (x: string) => ch('md5').update(x).digest('hex');
      const RPC: { calls: { method: string; params: Record<string, unknown> }[]; height: number; down: boolean; accounts: number } = { calls: [], height: 3512160, down: false, accounts: 3 };
      const MAINT = encodeAddress({ net: 'stagenet', kind: 'standard', spend: pt(), view: pt() }), SUB = encodeAddress({ net: 'stagenet', kind: 'subaddress', spend: pt(), view: pt() });
      const TXA = 'a1'.repeat(32), TXB = 'b2'.repeat(32);
      const answer = (method: string, q: Record<string, unknown>): unknown => {
        switch (method) {
          case 'get_height': return { height: RPC.height };
          case 'get_balance': return { balance: '912000000000', unlocked_balance: '812000000000', blocks_to_unlock: 6 };
          case 'get_address': return { address: q['account_index'] === 1 ? SUB : MAINT, addresses: [{ address: SUB, address_index: 7, label: 'Concert tickets', used: true }] };
          case 'get_accounts': return { subaddress_accounts: [0, 1, 2].slice(0, RPC.accounts).map((i) => ({ account_index: i, base_address: MAINT, balance: String(i * 1e9), label: i === 1 ? 'scout' : '' })) };
          case 'create_account': RPC.accounts++; return { account_index: RPC.accounts - 1, address: SUB };
          case 'create_address': return { address: SUB, address_index: 8 };
          case 'transfer': return { amount: (q['destinations'] as { amount: number }[])[0]!.amount, fee: 30000000, tx_hash: TXB, tx_metadata: 'cafe' };
          case 'relay_tx': return { tx_hash: TXB };
          case 'get_transfers': return { in: [{ txid: TXA, type: 'in', amount: 250000000000, fee: 0, timestamp: t0 - 3600, height: 3512100, confirmations: 60, locked: false, address: SUB, subaddr_index: { major: 0, minor: 7 }, note: '' }],
            out: [{ txid: TXB, type: 'out', amount: 1000, fee: 30000000, timestamp: t0 - 60, height: 3512150, confirmations: 3, locked: false, destinations: [{ address: ADDR, amount: 1000 }], note: 'rent' }], pool: [] };
          case 'get_transfer_by_txid': return { transfer: { txid: q['txid'], type: 'in', amount: 250000000000, fee: 0, timestamp: t0 - 3600, height: 3512100, confirmations: 60, address: SUB, subaddr_index: { major: 0, minor: 7 }, suggested_confirmations_threshold: 10 } };
          default: return {};
        }
      };
      const wsrv = createServer((req, res) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => {
        if (RPC.down) { res.destroy(); return; }
        const auth = String(req.headers['authorization'] ?? ''), f = (k: string) => new RegExp(`${k}="?([^",]*)"?`).exec(auth)?.[1] ?? '';
        const good = auth.startsWith('Digest ') && f('response') === md5([md5(`u:rpc:p`), 'n0nce', f('nc'), f('cnonce'), 'auth', md5(`POST:${f('uri')}`)].join(':'));
        if (!good) { res.writeHead(401, { 'WWW-Authenticate': 'Digest qop="auth",algorithm=MD5,realm="rpc",nonce="n0nce",stale=false' }); res.end(); return; }
        const x = JSON.parse(b) as { method: string; params: Record<string, unknown> };
        RPC.calls.push({ method: x.method, params: x.params });
        res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: '0', result: answer(x.method, x.params ?? {}) }));
      }); });
      const NODE = { height: 3512160, down: false }, PRICE: { hits: string[] } = { hits: [] };
      const nsrv = createServer((req, res) => { req.resume(); if (NODE.down) { res.writeHead(500); res.end(); return; } res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ height: NODE.height, status: 'OK' })); });
      const psrv = createServer((req, res) => { PRICE.hits.push(req.url ?? ''); res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ monero: { eur: 150.5, usd: 162.1, chf: 141.2, jpy: 24500 } })); });
      const port = async (sv: ReturnType<typeof createServer>) => { await new Promise<void>((r) => sv.listen(0, '127.0.0.1', () => r())); return (sv.address() as { port: number }).port; };
      const [wp, np, pp] = [await port(wsrv), await port(nsrv), await port(psrv)];
      const pol2 = JSON.parse(readFileSync(join(KD, 'policy.json'), 'utf8')) as Record<string, any>;
      pol2.wallet = { rpc: `http://127.0.0.1:${wp}/json_rpc`, login: 'u:p' };
      writeFileSync(join(KD, 'policy.json'), JSON.stringify(pol2), { mode: 0o600 });
      // The keeper's frozen copy (init.ts copies the package to <dir>/app): this one re-reads its policy and takes /refuse.
      mkdirSync(join(KD, 'app', 'dist'), { recursive: true });
      writeFileSync(join(KD, 'app', 'dist', 'service.js'), "// sigelo-spend: policy.json: now in use for\nconst lane = [['POST /refuse', 1]];\n");
      writeFileSync(join(KD, 'install.json'), JSON.stringify({ v: 1, net: 'stagenet', port: kport, systemd: false, units: [], app: join(KD, 'app', 'dist', 'cli.js'), daemons: [`127.0.0.1:${np}`] }));
      process.env['SIGELO_PRICE_URL'] = `http://127.0.0.1:${pp}/simple/price`;
      const g = async (path: string) => { const r = await http(P, 'GET', path, T); return { status: r.status, body: JSON.parse(r.body) as Record<string, any> }; };
      const w = async (path: string, b: unknown = {}) => { const r = await http(P, 'POST', path, W, b); return { status: r.status, body: JSON.parse(r.body) as Record<string, any> }; };
      const off = await g('/api/wallet'), offPrice = await g('/api/price'), offRecv = await w('/api/wallet/receive');
      ok('ui wallet: off (the default) → {on: false}; no price; Receive 409 wallet_off; nothing asked of the wallet, the node or the price source',
        off.body.on === false && Object.keys(off.body).length === 1 && offPrice.body.on === false && offRecv.status === 409 && offRecv.body.error.check === 'wallet_off' && RPC.calls.length === 0 && PRICE.hits.length === 0, JSON.stringify([off.body, offPrice.body]));
      await w('/api/settings', { wallet: true });
      const on = await g('/api/wallet');
      ok('ui wallet: on → the keeper\'s wallet-rpc (digest login), your account 0 (scout holds 1), synced with the keeper\'s node: the balance current',
        on.body.ready === true && on.body.service.kind === 'keeper' && on.body.service.account === 0 && on.body.net === 'stagenet' && on.body.sync.state === 'synced' && on.body.balance.total === '912000000000'
        && on.body.balance.current === true && on.body.node === `127.0.0.1:${np}` && RPC.calls.some((c) => c.method === 'get_balance' && c.params['account_index'] === 0), JSON.stringify(on.body));
      RPC.height = 3510000;
      const syn = await w('/api/wallet/sync');
      ok('ui wallet: behind the node → syncing, 2160 blocks, 3 days, the balance not current (as of its last sync); a keeper\'s wallet is not asked to refresh',
        syn.body.sync.state === 'syncing' && syn.body.sync.behind === 2160 && syn.body.sync.behind_s === 259200 && syn.body.balance.current === false && syn.body.balance.at === on.body.sync.synced_at
        && !RPC.calls.some((c) => c.method === 'refresh'), JSON.stringify(syn.body.sync));
      const unsynced = await w('/api/wallet/review', { to: { addr: ADDR }, amount: '1000' });
      ok('ui wallet: Send while syncing → 409 wallet_unsynced, nothing built', unsynced.status === 409 && unsynced.body.error.check === 'wallet_unsynced' && !RPC.calls.some((c) => c.method === 'transfer'));
      NODE.down = true;
      const nd = await w('/api/wallet/sync');
      RPC.down = true;
      const wd = await w('/api/wallet/sync');
      ok('ui wallet: the node down → state node; the wallet program down → state wallet, the last balance kept, not current',
        nd.body.sync.state === 'node' && wd.body.sync.state === 'wallet' && wd.body.balance?.total === '912000000000' && wd.body.balance.current === false, JSON.stringify([nd.body.sync, wd.body]));
      NODE.down = false; RPC.down = false; RPC.height = 3512160;
      await w('/api/wallet/sync');
      const bad = await w('/api/wallet/review', { to: { addr: MAIN }, amount: '1000' }), rv = await w('/api/wallet/review', { to: { addr: ADDR }, amount: '1000', note: 'rent' });
      const tr = RPC.calls.find((c) => c.method === 'transfer');
      ok('ui wallet: review → built with do_not_relay and its metadata, priced (fee), from your account; a mainnet address 400 address',
        bad.status === 400 && bad.body.error.check === 'address' && rv.status === 200 && rv.body.fee === '30000000' && rv.body.amount === '1000' && tr?.params['do_not_relay'] === true && tr.params['get_tx_metadata'] === true
        && tr.params['account_index'] === 0 && !RPC.calls.some((c) => c.method === 'relay_tx'), JSON.stringify([bad.body, rv.body]));
      const gone = await w('/api/wallet/send', { id: 'nope' }), sent = await w('/api/wallet/send', { id: rv.body.id }), again = await w('/api/wallet/send', { id: rv.body.id });
      ok('ui wallet: send {id} → relay_tx of that build, the note kept (set_tx_notes), stored; an unknown or used id 409 review_gone',
        gone.status === 409 && gone.body.error.check === 'review_gone' && sent.status === 200 && sent.body.txids[0] === TXB && RPC.calls.some((c) => c.method === 'relay_tx' && c.params['hex'] === 'cafe')
        && RPC.calls.some((c) => c.method === 'set_tx_notes' && (c.params['notes'] as string[])[0] === 'rent') && RPC.calls.some((c) => c.method === 'store') && again.status === 409, JSON.stringify(sent.body));
      const topup = await w('/api/wallet/review', { to: { agent: 'scout', keeper: 'keeper-dir' }, amount: '5000' });
      ok('ui wallet: Top up scout → its allowance account\'s address (1, 0) in the keeper\'s wallet', topup.status === 200 && topup.body.to === SUB && topup.body.agent === 'scout', JSON.stringify(topup.body));
      const rc = await w('/api/wallet/receive', { note: 'Concert tickets' }), lb = await w('/api/wallet/label', { index: 8, note: 'tickets' });
      ok('ui wallet: Receive → a new subaddress of your account, labelled with the note; label it again', rc.status === 200 && rc.body.address === SUB && rc.body.index === 8
        && RPC.calls.some((c) => c.method === 'create_address' && c.params['account_index'] === 0 && c.params['label'] === 'Concert tickets') && lb.status === 200 && RPC.calls.some((c) => c.method === 'label_address'));
      const hs = await g('/api/wallet/history'), one = await g(`/api/wallet/tx?txid=${TXA}`);
      ok('ui wallet: History → in (confirmed, its address\'s label as the note) and out (confirming · 3, the note), newest first; a payment by txid',
        hs.body.entries.length === 2 && hs.body.entries[0].txid === TXB && hs.body.entries[0].status === 'confirming' && hs.body.entries[0].note === 'rent' && hs.body.entries[1].status === 'confirmed'
        && hs.body.entries[1].note === 'Concert tickets' && one.body.txid === TXA && one.body.suggested === 10, JSON.stringify(hs.body));
      const sv0 = await g('/api/wallet/services'), held = await w('/api/wallet/service', { keeper: 'keeper-dir', account: 1 }), far = await w('/api/wallet/service', { url: 'http://wallet.example:18083/json_rpc' });
      const mk = await w('/api/wallet/service', { keeper: 'keeper-dir', new_account: true }), now2 = await g('/api/wallet');
      ok('ui wallet: services → the keeper\'s accounts (1 held by scout); scout\'s account refused 409 account_held; a wallet-rpc off this computer 400; Make an account → create_account, your account now',
        sv0.body.keepers[0].accounts.find((a: { index: number }) => a.index === 1)?.held === 'scout' && held.status === 409 && held.body.error.check === 'account_held' && far.status === 400 && far.body.error.check === 'wallet_url'
        && mk.status === 200 && RPC.calls.some((c) => c.method === 'create_account') && now2.body.service.account === 3, JSON.stringify([sv0.body.keepers, now2.body.service]));
      const ns = await g('/api/wallet/nodes'), use = await w('/api/wallet/node', { use: `127.0.0.1:${np}` }), dead = await w('/api/wallet/node', { add: '127.0.0.1:1' });
      ok('ui wallet: nodes → the keeper\'s daemon, its height, in use; use it → set_daemon (untrusted); a node that doesn\'t answer 409 node_down',
        ns.body.nodes[0]?.url === `127.0.0.1:${np}` && ns.body.nodes[0].height === 3512160 && ns.body.nodes[0].in_use === true && use.status === 200
        && RPC.calls.some((c) => c.method === 'set_daemon' && c.params['trusted'] === false) && dead.status === 409 && dead.body.error.check === 'node_down', JSON.stringify([ns.body, dead.body]));
      const pOff = await g('/api/price');
      await w('/api/settings', { prices: true, currency: 'CHF' });
      const p1 = await g('/api/price'), p2 = await g('/api/price');
      await w('/api/settings', { currency: 'JPY' });
      const p3 = await g('/api/price');
      ok('ui wallet: price off until asked; on → through this server from the source (CoinGecko\'s simple price, every currency at once), CHF 141.2; kept 10 minutes (one fetch for three answers, another currency included)',
        pOff.body.on === false && p1.body.on === true && p1.body.rate === 141.2 && p1.body.source === 'CoinGecko' && p2.body.rate === 141.2 && p3.body.rate === 24500 && PRICE.hits.length === 1
        && /ids=monero&vs_currencies=eur,usd,gbp,chf/.test(PRICE.hits[0]!), JSON.stringify([p1.body, PRICE.hits]));
      // The keeper's frozen copy re-reads its policy: Save says so, and the keeper carries live and refuse.
      const sv2 = await post('agent', { keeper: 'keeper-dir', agent: 'scout', rate_per_minute: 4 }), kk = await kj();
      ok('ui keeper: a keeper that re-reads its policy (its frozen copy) → Save answers live: true; the keeper carries live and refuse', sv2.body.live === true && kk.keepers[0].live === true && kk.keepers[0].refuse === true, JSON.stringify([sv2.body, kk.keepers[0]]));
      await w('/api/settings', { wallet: false, prices: false });
      delete process.env['SIGELO_PRICE_URL'];
      for (const x of [wsrv, nsrv, psrv]) x.close();
    }
    delete process.env['SIGELO_SPEND_REGISTRY'];
    fake.close();
  }
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
  // Transfers (TRANSFER.md): the routes of the page's engine; nothing yet; refusals by check; the view in ui.js.
  const tr = async (method: string, path: string, body?: unknown, h: Record<string, string> = method === 'POST' ? W : T) => { const r = await http(P, method, path, h, body); return { status: r.status, j: JSON.parse(r.body) as Record<string, any> }; };
  const t0 = await tr('GET', '/api/transfers'), tNo = await tr('GET', '/api/transfers', undefined, {}), tSt = JSON.parse((await http(P, 'GET', '/api/state', T)).body) as { transfers: { asked: number; active: number } | null };
  ok('ui transfers: GET /api/transfers without the token → 403; with it → {out, in} empty, settings Tor on; the state counts {asked: 0, active: 0}', tNo.status === 403 && t0.status === 200
    && t0.j['out'].length === 0 && t0.j['in'].length === 0 && t0.j['settings'].tor === true && tSt.transfers?.asked === 0 && tSt.transfers.active === 0, JSON.stringify(t0.j));
  const tRef = [await tr('POST', '/api/transfers/accept', { id: 'ab'.repeat(16) }), await tr('POST', '/api/transfers/accept', { id: 'nope' }), await tr('POST', '/api/transfers/send', { to: 'did:sigelo:zNope', path: '/etc/hostname' }),
    await tr('POST', '/api/transfers/send', { to: 'did:sigelo:zNope' }), await tr('POST', '/api/transfers/settings', { prefer: 'cheap' }), await tr('POST', '/api/transfers/direct', { contact: 'did:sigelo:zNope', on: 'yes' })];
  ok('ui transfers: unknown id 404 transfer_unknown; a bad id, no path, a bad prefer, on not a boolean 400; unknown contact 404 not_contact',
    JSON.stringify(tRef.map((r) => [r.status, r.j['error']?.check])) === JSON.stringify([[404, 'transfer_unknown'], [400, 'body'], [404, 'not_contact'], [400, 'body'], [400, 'body'], [400, 'body']]), JSON.stringify(tRef.map((r) => r.j)));
  const tSet = await tr('POST', '/api/transfers/settings', { tor: false, prefer: 'private' });
  ok('ui transfers: settings kept (tor off, prefer private), the tor daemon probed', tSet.status === 200 && tSet.j['tor'] === false && tSet.j['prefer'] === 'private' && typeof tSet.j['tor_daemon']?.serve === 'boolean', JSON.stringify(tSet.j));
  ok('ui.js: the Files view (Accept / Decline → /api/transfers/accept, decline; the direct question; progress; Tor checkbox off without a daemon)',
    js.body.includes('function viewTransfers(') && js.body.includes('/api/transfers/accept') && js.body.includes('/api/transfers/decline') && js.body.includes("e?.check !== 'direct_ask'") && js.body.includes('No tor daemon found'));
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
  const mod = (f: string): Promise<Record<string, any>> => import(pathToFileURL(join(import.meta.dirname, '..', 'contact', f)).href);
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
    && served[1]!.body === readFileSync(join(import.meta.dirname, '..', 'contact', 'qr-decode.mjs'), 'utf8'));
  const pj = await http(P, 'GET', '/package.json', {});
  ok('ui about: /package.json served as JSON with the package\'s own version', pj.status === 200 && String(pj.headers['content-type']).startsWith('application/json')
    && JSON.parse(pj.body).version === JSON.parse(readFileSync(join(import.meta.dirname, 'package.json'), 'utf8')).version);
  const wl = await http(P, 'GET', '/words-lock.mjs', {});
  ok('ui security: words-lock.mjs (sigelo-contact\'s, byte for byte) served as JavaScript, for Me → Security in the GTK phone app (design/apps-seed.md §8)', wl.status === 200 && String(wl.headers['content-type']).startsWith('text/javascript')
    && wl.body === readFileSync(join(import.meta.dirname, '..', 'contact', 'words-lock.mjs'), 'utf8'));
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
      // Presence: bob's page lets alice see when bob is online; alice's state shows it, then nothing once denied.
      const bobAt = async () => ((await A.call('GET', '/api/state'))['groups'].contacts as { did: string; online: boolean | null; last_seen: number | null; presence: string }[]).find((c) => c.did === bob!.did);
      const p0 = await bobAt();
      ok('ui presence: by default alice reads nothing of bob (online null), and bob sees nothing of her (presence deny)', p0?.online === null && p0?.last_seen === null && p0?.presence === 'deny', JSON.stringify(p0));
      const pa = await B.call('POST', '/api/presence', { contact: acc['contact'].did, allow: true });
      const on = await until(async () => ((await bobAt())?.online === true ? true : undefined));
      ok('ui presence: /api/presence {allow: true} on bob\'s page → {presence: allow}; alice\'s page shows bob online', pa['http'] === 200 && pa['presence'] === 'allow' && on === true, JSON.stringify(pa));
      const bad = await B.call('POST', '/api/presence', { contact: acc['contact'].did, allow: 'yes' });
      const pd = await B.call('POST', '/api/presence', { contact: acc['contact'].did, allow: false });
      const gone = await until(async () => ((await bobAt())?.online === null ? true : undefined));
      ok('ui presence: allow not a boolean → 400; {allow: false} → deny, and alice\'s page knows nothing again (null, not offline)', bad['http'] === 400 && pd['presence'] === 'deny' && gone === true, JSON.stringify([bad, pd]));
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
      // Seen receipts (UI-API.md): bob's page showed it, so a receipt went inside the envelope; alice's message turns seen.
      type Msg = { dir: string; text: string; status: string };
      const msgsOf = async (P: typeof A, d: string): Promise<Msg[]> => ((await P.call('GET', `/api/messages?contact=${encodeURIComponent(d)}`))['messages'] ?? []) as Msg[];
      const seenA = await until(async () => (await msgsOf(A, bob!.did)).find((m) => m.text === 'hello bob' && m.status === 'seen'));
      ok('ui seen receipts: once bob\'s page shows it, alice\'s message is seen (✓✓); the receipt is no message on either side', seenA !== undefined
        && !(await msgsOf(A, bob!.did)).some((m) => m.dir === 'in') && (await msgsOf(B, acc['contact'].did)).length === 1);
      await B.call('POST', '/api/send', { to: acc['contact'].did, text: 'hi alice ‮evil' });
      const back = await until(async () => ((await A.call('GET', `/api/messages?contact=${encodeURIComponent(bob!.did)}`))['messages'] as { dir: string; text: string }[]).find((m) => m.dir === 'in'));
      ok('ui e2e: and back; history keeps both, a bidi override as \\u escape in the JSON', back?.text === 'hi alice ‮evil'
        && readFileSync(join(A.dir, 'me.local.history.jsonl'), 'utf8').split('\n').filter(Boolean).length >= 3);
      const seenB = await until(async () => (await msgsOf(B, acc['contact'].did)).find((m) => m.dir === 'out' && m.status === 'seen'));
      ok('ui seen receipts: and back: bob\'s message seen once alice\'s page showed it', seenB !== undefined);
      const s0 = await B.call('GET', '/api/settings'), off = await B.call('POST', '/api/settings', { seen_receipts: false }), badSet = await B.call('POST', '/api/settings', { seen_receipts: 'no' });
      ok('ui settings: GET /api/settings has the chat defaults (seen_receipts on, notify on, new_tier friend, new_presence off); seen_receipts false kept; not a boolean → 400',
        s0['seen_receipts'] === true && s0['notify'] === true && s0['new_tier'] === 'friend' && s0['new_presence'] === false && off['seen_receipts'] === false && badSet['http'] === 400, JSON.stringify([s0, off]));
      await A.call('POST', '/api/send', { to: bob!.did, text: 'unseen' });
      const got3 = await until(async () => (await msgsOf(B, acc['contact'].did)).find((m) => m.text === 'unseen'));
      await new Promise((r) => setTimeout(r, 2500));
      ok('ui seen receipts: off on bob\'s page: he reads it, alice keeps one tick (sent)', got3 !== undefined && (await msgsOf(A, bob!.did)).find((m) => m.text === 'unseen')?.status === 'sent');
      await B.call('POST', '/api/settings', { seen_receipts: true });
      // Pictures (UI-API.md "Pictures"): mine end to end to a contact that reads them (bob: his receipts came), a cap of 64 KiB,
      // JPEG or WebP by their bytes; his own, a local one over it, removed; never in the history.
      const aliceAtB0 = acc['contact'].did as string, b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
      const jpeg = (n: number) => { const b = new Uint8Array(n); b.set([0xff, 0xd8, 0xff, 0xe0]); for (let i = 4; i < n; i++) b[i] = (i * 7) & 255; return b; };
      const webp = (n: number) => { const b = new Uint8Array(n); b.set([...Buffer.from('RIFF'), 0, 0, 0, 0, ...Buffer.from('WEBP')]); return b; };
      const big = await A.call('POST', '/api/picture', { of: 'me', type: 'image/jpeg', data: b64(jpeg(64 * 1024 + 1)) });
      const png = await A.call('POST', '/api/picture', { of: 'me', type: 'image/png', data: b64(jpeg(100)) });
      const liar = await A.call('POST', '/api/picture', { of: 'me', type: 'image/jpeg', data: b64(webp(100)) });
      const nobody = await A.call('POST', '/api/picture', { of: 'did:sigelo:zNope', type: 'image/jpeg', data: b64(jpeg(100)) });
      ok('ui pictures: over 64 KiB, not JPEG or WebP, bytes that are not what the type says → 400 picture; no such contact → 404', big['http'] === 400 && big['error']?.check === 'picture'
        && png['http'] === 400 && liar['http'] === 400 && nobody['http'] === 404, JSON.stringify([big['error'], png['error'], liar['error'], nobody['error']]));
      const mine = await A.call('POST', '/api/picture', { of: 'me', type: 'image/jpeg', data: b64(jpeg(64 * 1024)) });
      const meRev = (await A.call('GET', '/api/state'))['me'].picture;
      ok('ui pictures: mine set (64 KiB exactly) → its rev in the state (me.picture)', mine['http'] === 200 && mine['of'] === 'me' && typeof meRev === 'string' && meRev === mine['picture'], JSON.stringify(mine));
      const aliceAt = async () => ((await B.call('GET', '/api/state'))['groups'].contacts as { did: string; picture: string | null; picture_local: boolean }[]).find((c) => c.did === aliceAtB0);
      const came = await until(async () => { const c = await aliceAt(); return c?.picture ? c : undefined; });
      const gotPic = await B.call('GET', `/api/picture?of=${encodeURIComponent(aliceAtB0)}`);
      const picDir = join(B.dir, 'me.local.pictures'), picFiles = existsSync(picDir) ? readdirSync(picDir) : [];
      ok('ui pictures: it reaches bob end to end: alice\'s row has a picture, GET /api/picture the same bytes, kept in .pictures/ (0600), no message in the history',
        came !== undefined && gotPic['data'] === b64(jpeg(64 * 1024)) && gotPic['type'] === 'image/jpeg' && gotPic['local'] === false && picFiles.length === 1
        && (!posixModes || (statSync(join(picDir, picFiles[0]!)).mode & 0o777) === 0o600) && !(await msgsOf(B, aliceAtB0)).some((m) => (m as unknown as { label: string }).label === 'sigelo-picture/0')
        && !readFileSync(join(B.dir, 'me.local.history.jsonl'), 'utf8').includes('sigelo-picture'), JSON.stringify([came, picFiles]));
      const ov = await B.call('POST', '/api/picture', { of: aliceAtB0, type: 'image/webp', data: b64(webp(300)) });
      const ovPic = await B.call('GET', `/api/picture?of=${encodeURIComponent(aliceAtB0)}`), ovRow = await aliceAt();
      const unov = await B.call('POST', '/api/picture', { of: aliceAtB0, remove: true }), backPic = await B.call('GET', `/api/picture?of=${encodeURIComponent(aliceAtB0)}`);
      ok('ui pictures: a local one for alice wins (local, WebP); removed, hers shows again', ov['local'] === true && ovPic['type'] === 'image/webp' && ovPic['local'] === true && ovRow?.picture_local === true
        && unov['local'] === false && backPic['type'] === 'image/jpeg' && backPic['local'] === false && (await aliceAt())?.picture_local === false, JSON.stringify([ov, unov]));
      await A.call('POST', '/api/picture', { of: 'me', remove: true });
      const picGone = await until(async () => { const c = await aliceAt(); return c && c.picture === null ? c : undefined; });
      ok('ui pictures: alice removes hers → gone at bob\'s too (the initial shows); GET /api/picture of hers → 404 picture_none', picGone !== undefined
        && (await B.call('GET', `/api/picture?of=${encodeURIComponent(aliceAtB0)}`))['error']?.check === 'picture_none' && (await A.call('GET', '/api/state'))['me'].picture === null);
      // Signed statements (UI-API.md "Signed statements"): sign, check offline, tamper refused; in a chat with "Signed by".
      const sg = await A.call('POST', '/api/statement/sign', { text: 'I agree to share the flat costs, 4 ways.' });
      const meA = await A.call('GET', '/api/me');
      ok('ui statements: sign → the portable text (the text, the four words, the signature line), valid, by me', sg['http'] === 200 && sg['valid'] === true && sg['by']?.kind === 'me'
        && String(sg['statement']).startsWith('I agree to share the flat costs, 4 ways.\n-- Signed with sigelo by ' + meA['words'] + '.') && /\nsigelo-statement\/0 [A-Za-z0-9_-]+$/.test(sg['statement'])
        && sg['original'] === meA['original'] && sg['current'] === true, JSON.stringify(sg).slice(0, 400));
      const ck = await B.call('POST', '/api/statement/check', { statement: sg['statement'] });
      ok('ui statements: bob checks it: valid, by his contact alice (words not compared yet), the text, its time, her identity\'s date', ck['valid'] === true && ck['by']?.kind === 'contact' && ck['by'].did === aliceAtB0
        && ck['text'] === 'I agree to share the flat costs, 4 ways.' && Math.abs(ck['iat'] - Date.now() / 1000) < 60 && typeof ck['created'] === 'string' && ck['edited'] === false, JSON.stringify(ck).slice(0, 400));
      const stx = String(sg['statement']), line = stx.slice(stx.lastIndexOf('\n') + 1), blob = JSON.parse(Buffer.from(line.split(' ')[1]!, 'base64url').toString('utf8'));
      const forged = `${stx.split('\n')[0]}\n${stx.split('\n')[1]}\nsigelo-statement/0 ${Buffer.from(JSON.stringify({ ...blob, body: { ...blob.body, text: 'I agree to pay it all.' } })).toString('base64url')}`;
      const tampered = await B.call('POST', '/api/statement/check', { statement: forged });
      const edited = await B.call('POST', '/api/statement/check', { statement: stx.replace('4 ways', '1 way') });
      const cut = await B.call('POST', '/api/statement/check', { statement: stx.slice(0, -10) }), plain = await B.call('POST', '/api/statement/check', { statement: 'just text' });
      ok('ui statements: the signed text changed → refused statement_sig; the shown text changed → valid, edited (the signed one shown); cut or none → statement_format', tampered['valid'] === false && tampered['check'] === 'statement_sig'
        && edited['valid'] === true && edited['edited'] === true && edited['text'].includes('4 ways') && cut['valid'] === false && cut['check'] === 'statement_format' && plain['check'] === 'statement_format', JSON.stringify([tampered, edited['edited'], cut]));
      const other = await B.call('POST', '/api/statement/sign', { text: 'bob says' }), notMine = await A.call('POST', '/api/statement/check', { statement: other['statement'] });
      ok('ui statements: empty → 400; one by a contact checked at the other page: by that contact', (await A.call('POST', '/api/statement/sign', { text: '  ' }))['http'] === 400 && notMine['by']?.kind === 'contact' && notMine['by'].did === bob!.did && notMine['by'].name === 'bob', JSON.stringify(notMine['by']));
      const sendSt = await A.call('POST', '/api/send', { to: bob!.did, statement: sg['statement'] }), badSt = await A.call('POST', '/api/send', { to: bob!.did, statement: forged });
      const stMsg = await until(async () => ((await B.call('GET', `/api/messages?contact=${encodeURIComponent(aliceAtB0)}`))['messages'] as { label: string; statement?: { valid: boolean; by: { kind: string; name: string }; text: string } }[]).find((m) => m.label === 'sigelo-statement/0'));
      ok('ui statements: sent in a chat (labelled sigelo-statement/0); a forged one refused 400 statement; bob\'s message carries statement {valid, by alice, the text}', sendSt['http'] === 200 && sendSt['label'] === 'sigelo-statement/0'
        && badSt['http'] === 400 && badSt['error']?.check === 'statement' && stMsg?.statement?.valid === true && stMsg.statement.by.kind === 'contact' && stMsg.statement.text === 'I agree to share the flat costs, 4 ways.', JSON.stringify(stMsg).slice(0, 300));
      // Proof of age: what the bundle shows (its genesis date; no attestation on a human root).
      const age = await A.call('GET', '/api/attestations');
      ok('ui proof of age: GET /api/attestations → the genesis date, the attestations verified (none here)', age['http'] === 200 && typeof age['created'] === 'string' && Array.isArray(age['attestations']) && age['rejected'] === 0, JSON.stringify(age));
      // The public invite: a long code, 7 days, kept across restarts in .ui.json; Stop for good.
      const pub = await A.call('POST', '/api/invite', { long: true, public: true, ttl: 7 * 86400 }), pubSt = (await A.call('GET', '/api/state'))['pending'].public;
      const badTtl = await A.call('POST', '/api/invite', { ttl: 600 }), badPub = await A.call('POST', '/api/invite', { public: true });
      ok('ui public invite: a long code for 7 days; the state\'s pending.public (waiting); ttl without long, or too short, and public without long → 400', pub['http'] === 200 && pub['public'] === true && String(pub['code']).startsWith('sgl1')
        && Math.abs(pub['exp'] - Date.now() / 1000 - 7 * 86400) < 60 && pubSt?.id === pub['id'] && pubSt.waiting === true && pubSt.paired === null && badTtl['http'] === 400 && badPub['http'] === 400
        && JSON.parse(readFileSync(join(A.dir, 'me.local.ui.json'), 'utf8')).public?.code === pub['code'], JSON.stringify([pub, pubSt]).slice(0, 400));
      const stop = await A.call('POST', '/api/invite/cancel', { id: pub['id'] });
      ok('ui public invite: Stop for good → cancelled; gone from the state and .ui.json', stop['cancelled'] === true && (await A.call('GET', '/api/state'))['pending'].public === null
        && JSON.parse(readFileSync(join(A.dir, 'me.local.ui.json'), 'utf8')).public === undefined);
      const nf = await A.call('POST', '/api/notify', { chat: bob!.did, on: false }), nfRow = ((await A.call('GET', '/api/state'))['groups'].contacts as { did: string; notify: boolean }[]).find((c) => c.did === bob!.did);
      ok('ui notify: POST /api/notify {chat, on: false} → the contact\'s notify false; no such chat → 404', nf['notify'] === false && nfRow?.notify === false
        && (await A.call('POST', '/api/notify', { chat: 'did:sigelo:zNope', on: false }))['http'] === 404, JSON.stringify(nf));
      await A.call('POST', '/api/notify', { chat: bob!.did, on: true });
      const cl = await B.call('POST', '/api/history/clear', { contact: acc['contact'].did });
      ok('ui history: clear one chat ({contact}) → its messages gone, here and in the file', cl['cleared'] === true && (await msgsOf(B, acc['contact'].did)).length === 0
        && !readFileSync(join(B.dir, 'me.local.history.jsonl'), 'utf8').includes('hello bob'), JSON.stringify(cl));
      const renamed = await A.call('POST', '/api/rename', { contact: bob!.did, name: 'Bob B' });
      const tagged = await A.call('POST', '/api/tag', { contact: bob!.did, tags: ['#work', 'family'] });
      const after = ((await A.call('GET', '/api/state'))['groups'].contacts as { did: string; name: string; tags: string[] }[]).find((c) => c.did === bob!.did);
      ok('ui e2e: rename and tag', renamed['http'] === 200 && tagged['http'] === 200 && after?.name === 'Bob B' && after.tags.join() === 'work,family', JSON.stringify(after));
      // Groups (GROUPS.md): the pages handle them at each drain; a friend's group waits for its operator; labels.
      // alice is quiet at bob's page (accepted so): a quiet creator's roster is ignored outright.
      const quietMk = await A.call('POST', '/api/groups/create', { name: 'hush', members: [bob!.did] });
      await new Promise((r) => setTimeout(r, 1500));
      ok('ui groups: a group from a creator quiet here: ignored, nothing filed', quietMk['http'] === 200 && ((await B.call('GET', '/api/groups'))['groups'] as unknown[]).length === 0);
      await A.call('POST', '/api/groups/leave', { group: (quietMk['group'] as { gid: string }).gid });
      await B.call('POST', '/api/tier', { contact: acc['contact'].did, tier: 'friend' });
      const mk = await A.call('POST', '/api/groups/create', { name: 'crew', members: [bob!.did], humans: [bob!.did] });
      const gid = (mk['group'] as { gid: string } | undefined)?.gid ?? '';
      const invited = await until(async () => ((await B.call('GET', '/api/groups'))['groups'] as { gid: string; status: string; creator_name: string }[] | undefined)?.find((g) => g.gid === gid && g.status === 'pending'));
      const st = await B.call('GET', '/api/state');
      ok('ui groups: create on one page; the other page takes the roster at its drain: an invitation (alice is a friend there), counted in chats', mk['http'] === 200 && invited?.creator_name === 'alice' && st['chats'].invited === 1, JSON.stringify([mk['copies'], invited, st['chats']]).slice(0, 600));
      const early = await B.call('POST', '/api/groups/send', { group: gid, text: 'too early' });
      const jn = await B.call('POST', '/api/groups/join', { group: gid });
      ok('ui groups: send before joining → 409 group_pending; join → member', early['http'] === 409 && early['error']?.check === 'group_pending' && jn['http'] === 200 && (jn['group'] as { status: string }).status === 'member', JSON.stringify([early, jn]));
      await A.call('POST', '/api/groups/send', { group: gid, text: 'hello crew @Bob B' });
      const seen = await until(async () => (((await B.call('GET', `/api/groups/history?group=${gid}`))['messages'] ?? []) as { text: string; name: string; role: string; note: string | null; mentioned: boolean }[]).find((m) => m.text.startsWith('hello crew')));
      ok('ui groups: the message on the other page, labelled: name, role, "not your operator"', seen?.name === 'alice' && seen.role === 'human' && seen.note === 'not your operator', JSON.stringify(seen));
      const busyCli = spawnSync('node', [CLI, 'group', 'send', 'crew', 'beside the page'], { env: { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: join(A.dir, 'me.local.json') }, encoding: 'utf8' });
      ok('ui groups: the CLI\'s group send beside the page refuses (exit 1, busy): the page owns the session', busyCli.status === 1 && /busy|page/.test(busyCli.stderr), busyCli.stderr);
      const carrierState = JSON.parse(readFileSync(join(A.dir, 'me.local.carrier.json'), 'utf8')) as { events: unknown[]; inbox: unknown[] };
      ok('ui e2e: the page takes what the carrier keeps through inbox(): no events, no messages left in its state', carrierState.events.length === 0 && carrierState.inbox.length === 0, JSON.stringify(carrierState.events).slice(0, 300));
      const inv2 = await A.call('POST', '/api/invite', { name: 'later', long: true });
      const cancelled = await A.call('POST', '/api/invite/cancel', { id: inv2['id'] });
      const pend2 = (await A.call('GET', '/api/state'))['pending'].invites as { name: string }[];
      ok('ui e2e: cancel an invite → {cancelled: true}; no longer pending; again → 404', cancelled['cancelled'] === true && !pend2.some((x) => x.name === 'later')
        && (await A.call('POST', '/api/invite/cancel', { id: inv2['id'] }))['http'] === 404, JSON.stringify(cancelled));
      // "Cancel this code": a short code cancelled from the page is gone at the relay too; by id or by the code.
      const inv3 = await A.call('POST', '/api/invite', { name: 'gone' }), c3 = await A.call('POST', '/api/invite/cancel', { id: inv3['id'] });
      const tried = await B.call('POST', '/api/accept', { code: inv3['short'], name: 'x' });
      ok('ui e2e: cancel a short code → {cancelled, unparked: true}; accepting it now → park_unknown', c3['cancelled'] === true && c3['unparked'] === true && tried['error']?.check === 'park_unknown', JSON.stringify([c3, tried['error']]));
      const inv4 = await A.call('POST', '/api/invite', { name: 'bycode' }), c4 = await A.call('POST', '/api/invite/cancel', { code: inv4['short'] });
      ok('ui e2e: cancel by {code: <short>} → cancelled (again: still cancelled, the relay\'s tombstone); a code nobody made → 404', c4['cancelled'] === true && !((await A.call('GET', '/api/state'))['pending'].invites as { name: string }[]).some((x) => x.name === 'bycode')
        && (await A.call('POST', '/api/invite/cancel', { code: inv4['short'] }))['cancelled'] === true && (await A.call('POST', '/api/invite/cancel', { code: 'K7F3-Q9ZP' }))['http'] === 404, JSON.stringify(c4));
      const badRenew = await A.call('POST', '/api/invite', { long: true, renew: true });
      ok('ui e2e: renew with a long code → 400', badRenew['http'] === 400, JSON.stringify(badRenew));
      // A code that renews itself: carol uses it, the next one is in its place, under the same id; cancel ends it.
      {
        const C = await open('carol');
        try {
          const rn = await A.call('POST', '/api/invite', { name: 'friend', renew: true });
          type Inv = { id: string; short: string | null; renew?: boolean; used?: { name: string; did: string }[] };
          const cur = async () => ((await A.call('GET', '/api/state'))['pending'].invites as Inv[]).find((x) => x.id === rn['id']);
          ok('ui renew: POST /api/invite {renew: true} → renew: true, an id "r…"; the state lists it with renew: true, nothing used', rn['renew'] === true && /^r[0-9a-f]{16}$/.test(String(rn['id'])) && (await cur())?.renew === true && (await cur())?.used?.length === 0, JSON.stringify(rn));
          const ca = await C.call('POST', '/api/accept', { code: rn['short'], name: 'alice' });
          const next = await until(async () => { const x = await cur(); return x?.short && x.short !== rn['short'] ? x : undefined; });
          const carolDid = (await C.call('GET', '/api/state'))['me'].did;
          ok('ui renew: once carol uses it, the next code is in its place (same id), the one used listed with carol', ca['status'] === 'connected' && next !== undefined && next.used?.length === 1 && next.used[0]!.did === carolDid
            && !((await A.call('GET', '/api/state'))['pending'].paired as { id: string }[]).some((x) => x.id === rn['id']), JSON.stringify([ca['status'], next]));
          const rr = await A.call('POST', '/api/invite/cancel', { id: rn['id'] });
          ok('ui renew: cancel by its id → cancelled at the relay; no renewing code left', rr['cancelled'] === true && rr['unparked'] === true && (await cur()) === undefined
            && (await C.call('POST', '/api/accept', { code: next!.short, name: 'x' }))['error']?.check === 'park_unknown', JSON.stringify(rr));
        } finally { await C.u.close(); }
      }
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
      // Pictures and an earlier version (or an agent): sent only to a contact known to read them; bot sent no receipt, so none goes to it.
      await A.call('POST', '/api/picture', { of: 'me', type: 'image/jpeg', data: Buffer.from([0xff, 0xd8, 0xff, 0xdb, 1, 2, 3]).toString('base64') });
      await until(async () => (JSON.parse(readFileSync(join(A.dir, 'me.local.ui.json'), 'utf8')).pic_sent?.[bob!.did] ? true : undefined));
      const sentTo = JSON.parse(readFileSync(join(A.dir, 'me.local.ui.json'), 'utf8')).pic_sent as Record<string, string>;
      ok('ui pictures: a contact not known to read pictures (my agent bot: no receipt from it) gets none; bob does', Boolean(sentTo[bob!.did]) && sentTo[(group.mine[0] as unknown as { did: string }).did] === undefined, JSON.stringify(sentTo));
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
          enrolling: { id: string; state: string; code: string | null; words: string | null; command: string | null; verified?: boolean; confirm_words?: boolean; words_ok?: boolean | null } | null };
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
        const vc = (st1['groups'].mine as { did: string; words_checked: boolean }[]).find((c) => c.did === vps?.contact);
        ok('ui agents: own enrolment, no tap: the worker is words-checked (its DID is the one derived here), the row says verified', vc?.words_checked === true && vps?.enrolling?.verified === true
          && vps.enrolling.confirm_words === false, JSON.stringify([vc, vps?.enrolling]));
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
        // The optional switch: confirm_words holds the key until "They match" (enrol-words).
        const ec3 = await A.call('POST', '/api/agents/enrol-code', { name: 'asked', confirm_words: true, operator_name: 'boss' });
        const askedFile = join(H, 'asked', 'sigelo.local.json');
        mkdirSync(join(H, 'asked'), { recursive: true, mode: 0o700 });
        const joining = cli(['init', '--enrol', String(ec3['code']), '--wait', '90'], { ...relayEnv, SIGELO_IDENTITY: askedFile });
        const waits = await until(async () => { const w = (await wl()).workers.find((x) => x.worker === 4); return w?.enrolling?.state === 'words' && w.enrolling.words ? w : undefined; }, 30000);
        await new Promise((r) => setTimeout(r, 3000));
        const still = (await wl()).workers.find((x) => x.worker === 4);
        ok('ui agents: confirm_words → the agent answered, its words shown, its key held (not enrolled) until the human says', ec3['confirm_words'] === true && waits !== undefined
          && still?.status === 'pending' && still.enrolling?.words_ok === null && !existsSync(askedFile), JSON.stringify(still));
        const yes = await A.call('POST', '/api/agents/enrol-words', { id: ec3['id'], match: true }), joined3 = await joining;
        const asked = await until(async () => { const w = (await wl()).workers.find((x) => x.worker === 4); return w?.status === 'enrolled' ? w : undefined; }, 30000);
        const askedOp = (JSON.parse(readFileSync(askedFile.replace(/\.json$/, '.contacts.json'), 'utf8')) as { contacts: Record<string, { name: string }> }).contacts;
        ok('ui agents: "They match" → its key goes, enrolled; the agent files me as the label I gave (operator_name)', yes['http'] === 200 && joined3.status === 0 && asked !== undefined
          && Object.values(askedOp).map((c) => c.name).join() === 'boss', JSON.stringify([yes, asked, askedOp]) + joined3.out.slice(-300));
        const nw = await A.call('POST', '/api/agents/enrol-words', { id: 'nope', match: true }), pt = await A.call('POST', '/api/pow/try', {});
        ok('ui agents: enrol-words for no such enrolment 404; pow/try with every relay connected → tried none', nw['http'] === 404 && pt['http'] === 200 && Array.isArray(pt['tried']), JSON.stringify([nw, pt]));
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
