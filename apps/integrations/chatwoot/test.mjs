// SPDX-License-Identifier: MIT
// `node test.mjs` → ALL PASS (N). Offline: a fake Chatwoot on loopback, a stand-in sigelo-agent.
// Both directions, retry, idempotency, allowlist refusal, webhook signature refusal, the config checks.
import { createHmac } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKOFF, Bridge, cliSend, kindOf, mapPathOf } from './bridge.mjs';
import { load } from './cli.mjs';

let fails = 0, passes = 0;
const ok = (c, m) => { c ? passes++ : fails++; console.log(`${c ? 'ok  ' : 'FAIL'} ${m}`); };
const dir = mkdtempSync(join(tmpdir(), 'sigelo-chatwoot-'));
const ALICE = 'did:sigelo:z6MkAlice', BOB = 'did:sigelo:z6MkBob', TOKEN = 'tok-123', SECRET = 'whsec-456';
const id = (n) => n.toString(16).padStart(32, '0');

// ---- the fake Chatwoot: the Application API paths bridge.mjs calls, every request recorded ----
const cw = { reqs: [], down: 0, contacts: [], convs: {}, msgs: {}, n: 100, gone: new Set() };
const fake = createServer((req, res) => {
  const parts = [];
  req.on('data', (d) => parts.push(d)).on('end', () => {
    const raw = Buffer.concat(parts), ct = req.headers['content-type'] ?? '';
    const body = ct.startsWith('application/json') ? JSON.parse(raw) : raw.toString('latin1');
    const r = { method: req.method, url: req.url, auth: req.headers.api_access_token, bearer: req.headers.authorization, ct, body };
    cw.reqs.push(r);
    const send = (code, o) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (cw.down > 0) { cw.down--; return send(503, { error: 'down' }); }
    if (r.auth !== TOKEN || r.bearer !== `Bearer ${TOKEN}`) return send(401, { error: 'token' });
    const p = req.url.replace(/^\/api\/v1\/accounts\/7/, '');
    let m;
    if (req.method === 'POST' && p === '/contacts') {
      if (cw.contacts.some((c) => c.identifier === body.identifier)) return send(422, { message: 'Identifier has already been taken' });
      const c = { id: ++cw.n, name: body.name, identifier: body.identifier, contact_inboxes: [{ source_id: `src-${cw.n}`, inbox: { id: body.inbox_id } }] };
      cw.contacts.push(c);
      return send(200, { payload: { contact: c, contact_inbox: c.contact_inboxes[0] } });
    }
    if (req.method === 'GET' && (m = p.match(/^\/contacts\/search\?q=(.*)$/))) return send(200, { payload: cw.contacts.filter((c) => c.identifier === decodeURIComponent(m[1])), meta: {} });
    if (req.method === 'POST' && p === '/conversations') { const i = ++cw.n; cw.convs[i] = body; cw.msgs[i] = []; return send(200, { id: i, account_id: 7, inbox_id: body.inbox_id }); }
    if ((m = p.match(/^\/conversations\/(\d+)\/messages$/))) {
      if (cw.gone.has(m[1]) || !cw.msgs[m[1]]) return send(404, { error: 'not found' });
      if (req.method === 'GET') return send(200, { payload: cw.msgs[m[1]].map((x) => ({ ...x, message_type: ['incoming', 'outgoing'].indexOf(x.message_type) })) });  // REST: a number, as Chatwoot 4.20.1
      let msg;
      if (ct.startsWith('multipart/form-data')) {
        const f = (k) => body.match(new RegExp(`name="${k.replace(/[[\]]/g, '\\$&')}"[^\\r]*\\r\\n\\r\\n([^\\r]*)`))?.[1];
        msg = { content: f('content'), message_type: f('message_type'), source_id: f('source_id'), multipart: true, file: /name="attachments\[\]"; filename="([^"]+)"/.exec(body)?.[1], data: f('attachments[]') };
      } else msg = { ...body };
      msg.id = ++cw.n;
      cw.msgs[m[1]].push(msg);
      return send(200, msg);
    }
    send(404, { error: `no route ${req.method} ${p}` });
  });
});
await new Promise((r) => fake.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${fake.address().port}`;
const posts = () => cw.reqs.filter((r) => r.method === 'POST' && r.url.endsWith('/messages'));

// ---- a bridge over a temp spool; send recorded ----
const spool = join(dir, 'me.spool'), identity = join(dir, 'me.json');
mkdirSync(spool, { mode: 0o700 });
const sent = [];
let sendOk = (did, text, re) => true;
const logs = [];
let T = 1790900000000;
const make = (o = {}) => new Bridge({ base: BASE, account: 7, inbox: 3, token: TOKEN, secret: SECRET, allow: ['alice'], identity, spool,
  send: async (did, text, re) => { sent.push({ did, text, re }); return sendOk(did, text, re) ? { ok: true } : { ok: false, detail: 'refused (msg_unknown)' }; },
  now: () => T, log: (l) => logs.push(l), ...o });
const spoolMsg = (n, from, name, extra = {}) => writeFileSync(join(spool, `${id(n)}.json`), JSON.stringify({ id: id(n), from, name, label: '', content: `hello ${n}`, iat: 1, received: 1, ...extra }));
let b = make();

// 1. in: an allowlisted message → contact, conversation, incoming message; the file taken
spoolMsg(1, ALICE, 'alice');
let r = await b.pollOnce();
const ct = cw.reqs.find((x) => x.url.endsWith('/contacts'));
ok(r.posted === 1 && !existsSync(join(spool, `${id(1)}.json`)), 'in: posted, the spool file taken');
ok(ct?.body.identifier === ALICE && ct.body.inbox_id === 3 && ct.body.name === 'alice', 'in: contact made with identifier = the DID, in the inbox');
const conv = cw.reqs.find((x) => x.url.endsWith('/conversations'));
ok(conv?.body.source_id?.startsWith('src-') && conv.body.inbox_id === 3 && conv.body.status === 'open', 'in: conversation made with the contact inbox source_id');
const p1 = posts()[0];
ok(p1?.body.message_type === 'incoming' && p1.body.private === false && p1.body.source_id === `sigelo:${id(1)}` && p1.body.content === 'hello 1', 'in: an incoming message, source_id sigelo:<msg id>');
ok((statSync(mapPathOf(identity)).mode & 0o777) === 0o600 && mapPathOf(identity).endsWith('me.chatwoot.json'), 'state: <identity>.chatwoot.json, 0600');
ok(!readFileSync(mapPathOf(identity), 'utf8').includes(TOKEN) && !readFileSync(mapPathOf(identity), 'utf8').includes(SECRET), 'state: no token or secret in the map');

// 2. a second message: the same contact and conversation
spoolMsg(2, ALICE, 'alice');
const nContacts = cw.reqs.filter((x) => x.url.endsWith('/contacts')).length;
await b.pollOnce();
ok(cw.reqs.filter((x) => x.url.endsWith('/contacts')).length === nContacts && cw.reqs.filter((x) => x.url.endsWith('/conversations')).length === 1 && posts().length === 2, 'in: a second message reuses contact and conversation');

// 3. allowlist refusal, group messages, nothing allowed by default
const before = cw.reqs.length;
spoolMsg(3, BOB, 'bob');
writeFileSync(join(spool, `${id(9)}.${id(4)}.json`), JSON.stringify({ id: `${id(9)}.${id(4)}`, from: ALICE, name: 'alice', group: { gid: id(9) }, content: 'group' }));
r = await b.pollOnce();
ok(r.left === 2 && r.posted === 0 && cw.reqs.length === before, 'allowlist: bob and a group message left, no Chatwoot call');
ok(existsSync(join(spool, `${id(3)}.json`)) && existsSync(join(spool, `${id(9)}.${id(4)}.json`)), 'allowlist: their files stay for the operator');
ok(logs.filter((l) => l.includes('not on the allowlist')).length === 1 && (await b.pollOnce(), logs.filter((l) => l.includes('not on the allowlist')).length === 1), 'allowlist: said once, not every poll');
const none = make({ allow: [], map: join(dir, 'none.json') });
ok((await none.pollOnce()).posted === 0, 'allowlist: empty by default bridges nothing');
rmSync(join(spool, `${id(3)}.json`)); rmSync(join(spool, `${id(9)}.${id(4)}.json`));

// 4. retry: Chatwoot down → the file stays; up → posted once
cw.down = 1; spoolMsg(5, ALICE, 'alice');
r = await b.pollOnce();
ok(r.failed?.status === 503 && existsSync(join(spool, `${id(5)}.json`)), 'retry: Chatwoot 503, the file stays');
r = await b.pollOnce();
ok(r.posted === 1 && posts().filter((x) => x.body.source_id === `sigelo:${id(5)}`).length === 2, 'retry: posted at the next round (the 503 one never landed)');
ok(cw.msgs[conv && Object.keys(cw.msgs)[0]].filter((m) => m.source_id === `sigelo:${id(5)}`).length === 1, 'retry: one message in Chatwoot');

// 5. backoff: run() waits 2 s doubling on failure (scaled down here), resets on success
BACKOFF.first = 20; BACKOFF.max = 80;
cw.down = 3; spoolMsg(6, ALICE, 'alice');
const stop = b.run(10);
await new Promise((res) => setTimeout(res, 400));
stop();
const waits = logs.filter((l) => / again in /.test(l)).slice(-3).map((l) => Number(l.match(/again in ([\d.]+) s/)[1]) * 1000);
ok(waits.join() === '20,40,80' && !existsSync(join(spool, `${id(6)}.json`)), `backoff: ${waits.join(', ')} ms, then posted`);

// 6. idempotency in: a post that landed before a crash (pending) is found, not posted again; a done id re-spooled is dropped
const convId = b.state.contacts[ALICE].conversation;
cw.msgs[convId].push({ id: 998, content: 'not it', message_type: 'outgoing', source_id: `sigelo:${id(7)}` }, { id: 999, content: 'hello 7', message_type: 'incoming', source_id: `sigelo:${id(7)}` });
b.state.in[id(7)] = { state: 'pending', at: T / 1000 }; b.save();
spoolMsg(7, ALICE, 'alice');
let n0 = posts().length;
await b.pollOnce();
ok(posts().length === n0 && b.state.in[id(7)].state === 'done' && b.state.in[id(7)].cw === 999 && !existsSync(join(spool, `${id(7)}.json`)), 'idempotency: a pending post found by source_id (REST message_type 0), not posted twice');
ok(kindOf(0) === 'incoming' && kindOf('1') === 'outgoing' && kindOf(1) === 'outgoing' && kindOf('outgoing') === 'outgoing' && kindOf(2) === 'activity', 'message_type: number (REST) and string (webhook) read alike');
spoolMsg(1, ALICE, 'alice');
await b.pollOnce();
ok(posts().length === n0 && !existsSync(join(spool, `${id(1)}.json`)), 'idempotency: a message posted before, spooled again, is dropped');

// 7. a conversation deleted in Chatwoot (404): a new one at the next round
cw.gone.add(String(convId)); spoolMsg(8, ALICE, 'alice');
r = await b.pollOnce();
ok(r.failed?.status === 404 && b.state.contacts[ALICE].conversation === undefined, '404: the conversation forgotten');
r = await b.pollOnce();
ok(r.posted === 1 && b.state.contacts[ALICE].conversation !== convId && b.state.convs[String(b.state.contacts[ALICE].conversation)] === ALICE, '404: a new conversation, the message in it');

// 8. a lost map: the contact exists (422) → found by identifier
const fresh = make({ map: join(dir, 'lost.json') });
spoolMsg(10, ALICE, 'alice');
r = await fresh.pollOnce();
ok(r.posted === 1 && fresh.state.contacts[ALICE].contact === cw.contacts[0].id && cw.contacts.length === 1, '422: the existing contact found by search, not made twice');

// 9. a file: uploaded as attachments[]
const fpath = join(dir, 'report.txt'); writeFileSync(fpath, 'FILE-BYTES');
writeFileSync(join(spool, `${id(11)}.json`), JSON.stringify({ type: 'file', id: id(11), from: ALICE, contact: 'alice', name: 'report.txt', size: 10, path: fpath }));
await b.pollOnce();
const fm = posts().at(-1);
ok(fm.ct.startsWith('multipart/form-data') && /filename="report.txt"/.test(fm.body) && fm.body.includes('FILE-BYTES') && /name="source_id"\r\n\r\nsigelo:0+b/.test(fm.body), 'file: multipart attachments[], source_id kept');
ok(b.state.contacts[ALICE].last_in === id(8) && b.state.contacts[ALICE].name === 'alice', 'file: not what a reply quotes; the contact keeps its name, not the file\'s');
writeFileSync(join(spool, `${id(12)}.json`), JSON.stringify({ type: 'file', id: id(12), from: BOB, contact: 'bob', name: 'alice', size: 1, path: fpath }));
ok((await b.pollOnce()).left === 1, 'allowlist: a file named like an allowed contact is not let in');
rmSync(join(spool, `${id(12)}.json`));

// ---- out: the webhook ----
const srv = createServer(b.handler('/chatwoot'));
await new Promise((res) => srv.listen(0, '127.0.0.1', res));
const hook = (ev, { ts = String(Math.floor(T / 1000)), sig, path = '/chatwoot', secret = SECRET } = {}) => new Promise((done) => {
  const raw = JSON.stringify(ev);
  const s = sig ?? 'sha256=' + createHmac('sha256', secret).update(`${ts}.${raw}`).digest('hex');
  const q = request({ host: '127.0.0.1', port: srv.address().port, path, method: 'POST', headers: { 'content-type': 'application/json', 'x-chatwoot-timestamp': ts, 'x-chatwoot-signature': s } }, (res) => {
    let t = ''; res.on('data', (d) => { t += d; }).on('end', () => done({ code: res.statusCode, text: t.trim() }));
  });
  q.on('error', (e) => done({ code: e.code }));
  q.end(raw);
});
const conv2 = b.state.contacts[ALICE].conversation;
const reply = (mid, extra = {}) => ({ event: 'message_created', id: mid, content: `answer ${mid}`, message_type: 'outgoing', private: false, conversation: { display_id: conv2 }, inbox: { id: 3 }, sender: { type: 'user' }, ...extra });

// 10. a support reply → sigelo-agent send <did> --re <last text>
let h = await hook(reply(5001));
ok(h.code === 200 && h.text === 'sent' && sent.at(-1)?.did === ALICE && sent.at(-1).text === 'answer 5001' && sent.at(-1).re === id(8), 'out: a reply sent to the DID, quoting the last message');
// 11. delivered again: nothing sent twice
const ns = sent.length;
h = await hook(reply(5001));
ok(h.code === 200 && h.text === 'duplicate' && sent.length === ns, 'out: a webhook delivered again sends nothing');
// 12. signature refusals
ok((await hook(reply(5002), { secret: 'wrong' })).code === 401, 'auth: a wrong secret → 401');
ok((await hook(reply(5002), { sig: '' })).code === 401, 'auth: no signature → 401');
ok((await hook(reply(5002), { ts: String(Math.floor(T / 1000) - 301) })).code === 401, 'auth: signed more than 5 minutes ago → 401');
ok((await hook(reply(5002), { ts: 'x' })).code === 401, 'auth: a bad timestamp → 401');
ok((await hook(reply(5002), { path: '/other' })).code === 404, 'auth: another path → 404');
ok(sent.length === ns && !b.state.out['5002'], 'auth: refused ones send and mark nothing');
// 13. ignored: incoming, private notes, our own, other inboxes, unknown conversations, other events
const ign = [[{ message_type: 'incoming' }, 'not outgoing'], [{ message_type: 0 }, 'not outgoing'], [{ private: true }, 'private note'], [{ source_id: 'sigelo:abc' }, 'ours'],
  [{ inbox: { id: 4 } }, 'another inbox'], [{ conversation: { display_id: 424242 } }, 'not a bridged conversation'], [{ event: 'conversation_status_changed' }, 'event']];
for (const [i, [x, why]] of ign.entries()) { h = await hook(reply(5100 + i, x)); ok(h.code === 200 && h.text === `ignored: ${why}`, `out: ignored: ${why}`); }
h = await hook(reply(5199, { conversation: { display_id: '__proto__' } }));
ok(h.text === 'ignored: not a bridged conversation', 'out: a conversation id like __proto__ is not one of ours');
ok(sent.length === ns, 'out: none of them sent');
h = await hook(reply(5200, { message_type: 1, conversation: { id: conv2 } }));
ok(h.text === 'sent', 'out: message_type 1 and conversation.id understood as well');
// 14. send refused → unquoted once, then a private note
sendOk = (did, text, re) => re === undefined;
h = await hook(reply(5300));
ok(h.text === 'sent' && sent.at(-2).re === id(8) && sent.at(-1).re === undefined, 'out: the quote refused, sent unquoted');
sendOk = () => false;
h = await hook(reply(5301));
const note = posts().at(-1);
ok(h.text === 'refused: send' && note.body.private === true && note.body.message_type === 'outgoing' && /not sent/.test(note.body.content) && b.state.out['5301'].state === 'refused', 'out: refused → a private note, marked');
sendOk = () => true;
// 15. attachments not sent, the text is
h = await hook(reply(5400, { attachments: [{ data_url: 'https://x/y.png' }] }));
ok(h.text === 'sent' && /attachments are not sent/.test(posts().at(-1).body.content) && !JSON.stringify(sent.at(-1)).includes('y.png'), 'out: attachment not sent, a note says so; the text goes');
// 16. off the allowlist since: refused
b.allow = new Set();
const ns2 = sent.length;
h = await hook(reply(5500));
ok(h.text === 'refused: not allowed' && sent.length === ns2 && /no longer bridged/.test(posts().at(-1).body.content), 'out: a contact taken off the allowlist gets nothing');
b.allow = new Set(['alice']);
// 17. restart: the map read back, replies still routed, duplicates still known
const b2 = make();
ok((await b2.outbound(reply(5001))) === 'duplicate' && (await b2.outbound(reply(5600))) === 'sent', 'restart: the map read back (duplicates known, replies routed)');
// 17a. a crash between the mark and send: at the next start a private note, never sent again
b2.state.out['5700'] = { state: 'sending', at: T / 1000, conv: conv2 }; b2.save();
const b3 = make(), ns3 = sent.length;
await b3.unsure();
ok(b3.state.out['5700'].state === 'unknown' && /may not have gone/.test(posts().at(-1).body.content) && posts().at(-1).body.private === true && sent.length === ns3, 'crash: an unsure reply noted privately, not sent again');
ok((await b3.outbound(reply(5700))) === 'duplicate', 'crash: the same webhook again is still a duplicate');
// 18. a body over 1 MiB → 413
const big = await hook({ event: 'message_created', pad: 'x'.repeat(1 << 20) });
ok(big.code === 413 || big.code === 'ECONNRESET' || big.code === 'EPIPE', `out: a body over 1 MiB refused unread (${big.code})`);
srv.close();

// ---- the stand-in sigelo-agent ----
const fakeCli = join(dir, 'sigelo-agent');
writeFileSync(fakeCli, `#!/bin/sh\nprintf '%s\\n' "$@" > "${dir}/args"\ncat > "${dir}/stdin"\n[ "$3" = - ] || exit 2\n[ "$2" = refuse ] && { echo 'send: refused (contact_revoked)' >&2; exit 1; }\nexit 0\n`);
chmodSync(fakeCli, 0o755);
r = await cliSend(fakeCli, identity, ALICE, 'multi\nline "text" $HOME', id(8));
ok(r.ok && readFileSync(join(dir, 'args'), 'utf8') === `send\n${ALICE}\n-\n--re\n${id(8)}\n--identity\n${identity}\n` && readFileSync(join(dir, 'stdin'), 'utf8') === 'multi\nline "text" $HOME', 'cli: send <did> - --re <id> --identity, the text on stdin untouched');
r = await cliSend(fakeCli, identity, 'refuse', 'x');
ok(!r.ok && r.detail === 'send: refused (contact_revoked)', 'cli: a refusal returns its reason');

// ---- config ----
const tok = join(dir, 'token'), sec = join(dir, 'secret'), cfgf = join(dir, 'c.json');
writeFileSync(tok, `${TOKEN}\n`, { mode: 0o600 }); writeFileSync(sec, SECRET, { mode: 0o600 });
const cfg = (o) => { writeFileSync(cfgf, JSON.stringify({ chatwoot: 'https://chat.example.com', account_id: 7, inbox_id: 3, token_file: tok, webhook_secret_file: sec, identity, allow: ['alice'], ...o })); return () => load(cfgf); };
const L = cfg({})();
ok(L.opts.token === TOKEN && L.opts.secret === SECRET && L.opts.spool === join(dir, 'me.spool') && L.host === '127.0.0.1' && L.port === 7330 && L.path === '/chatwoot', 'config: defaults (spool beside the identity, loopback 7330, /chatwoot)');
const bad = (o, re, m) => { try { cfg(o)(); ok(false, `${m} (accepted)`); } catch (e) { ok(re.test(e.message), `${m}: ${e.message}`); } };
bad({ chatwoot: 'http://chat.example.com' }, /https only/, 'config: http to a remote host refused');
bad({ account_id: '7' }, /account_id/, 'config: account_id must be a number');
bad({ allow: 'alice' }, /allow/, 'config: allow must be a list');
chmodSync(tok, 0o644);
bad({}, /readable by others/, 'config: a token file others can read refused');
chmodSync(tok, 0o600);
bad({ webhook_secret_file: undefined }, /webhook_secret_file: missing/, 'config: no webhook secret, no start');
let threw = null; try { new Bridge({ ...L.opts, secret: '' }); } catch (e) { threw = e.message; }
ok(/secret is missing/.test(threw ?? ''), 'bridge: refuses to run without the webhook secret');

// ---- the CLI process: starts, serves, stops on SIGTERM; a bad config exits 2 ----
{
  const { spawn } = await import('node:child_process');
  writeFileSync(cfgf, JSON.stringify({ chatwoot: BASE, account_id: 7, inbox_id: 3, token_file: tok, webhook_secret_file: sec, identity, allow: [], listen: '127.0.0.1:0' }));
  const p = spawn(process.execPath, [fileURLToPath(new URL('./cli.mjs', import.meta.url)), cfgf], { stdio: ['ignore', 'ignore', 'pipe'] });
  let err = '';
  const up = await new Promise((res) => { p.stderr.on('data', (d) => { err += d; if (/webhook http:/.test(err)) res(true); }); setTimeout(() => res(false), 5000); });
  p.kill('SIGTERM');
  const code = await new Promise((res) => p.on('close', res));
  ok(up && /allow is empty/.test(err) && code === 0, 'cli: starts (an empty allowlist said), SIGTERM → exit 0');
  writeFileSync(cfgf, '{}');
  const q = spawn(process.execPath, [fileURLToPath(new URL('./cli.mjs', import.meta.url)), cfgf], { stdio: 'ignore' });
  ok(await new Promise((res) => q.on('close', res)) === 2, 'cli: a bad config → exit 2');
}

fake.close();
rmSync(dir, { recursive: true, force: true });
console.log(fails ? `${fails} FAILED` : `ALL PASS (${passes})`);
process.exit(fails ? 1 : 0);
