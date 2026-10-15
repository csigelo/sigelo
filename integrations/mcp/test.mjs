// SPDX-License-Identifier: MIT
// Scripted stdio client: spawns server.mjs, speaks MCP line-delimited JSON-RPC, exercises every
// tool. A mock world is built from the library; a mock keeper is a loopback HTTP server on an
// ephemeral port (never the soak's 38083/38200). The contact tools: listed when sigelo-contact
// resolves as sigelo-agent loads it (here: npm ci in adapters/moadim and contact/); a package that
// only takes its name's place, or one above sigelo-agent's tree, never runs. Against a loopback
// relay (relay/ here, else SIGELO_RELAY_DIR; SKIP without one): pairing, parallel calls, an inbox
// past one result (held across a restart), a nested message, wait bounds, a recovery after which
// each side lists the other re_pair. `npm test` → ALL PASS or exit 1.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { attest, did, keygen, verifySig } from '../../ts/dist/sigelo.js';

const here = dirname(fileURLToPath(import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'sigelo-mcp-'));
let fails = 0, passes = 0;
const ok = (c, name, extra = '') => { if (c) passes++; else { fails++; console.error(`FAIL ${name} ${extra}`); } };

function client(env, server = join(here, 'server.mjs')) {
  const p = spawn(process.execPath, [server], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  let buf = '', next = 1; const waiting = new Map(); let stderr = '';
  p.stderr.on('data', (d) => { stderr += d; });
  p.stdout.on('data', (d) => {
    buf += d; let i;
    while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); waiting.get(m.id)?.(m); waiting.delete(m.id); }
  });
  const rpc = (method, params) => new Promise((res) => { const id = next++; waiting.set(id, res); p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, ...(params && { params }) }) + '\n'); });
  const raw = (line, id) => new Promise((res) => { waiting.set(id, res); p.stdin.write(line + '\n'); });
  const call = async (name, args = {}) => {
    const m = await rpc('tools/call', { name, arguments: args });
    if (m.error) return { error: m.error };
    const text = m.result.content[0].text;
    let data; try { data = JSON.parse(text); } catch { data = undefined; }
    return { isError: m.result.isError, text, data, structured: m.result.structuredContent };
  };
  const exited = new Promise((res) => p.on('exit', (code) => res(code)));
  return { p, rpc, raw, call, exited, notify: (method) => p.stdin.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n'), stderr: () => stderr, close: () => p.stdin.end() };
}

// ---- mock keeper
const TOKEN = 'test-token';
const keeper = createServer((req, res) => {
  let body = ''; req.on('data', (d) => { body += d; }).on('end', () => {
    const send = (s, o) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { error: 'token' , code: 'token' });
    if (req.url === '/balance') return send(200, { balance: '1500000000000', unlocked_balance: '1500000000000', remaining: '1000000000000', per_tx_max: '500000000000', period_seconds: 86400 });
    if (req.url === '/receive') return send(200, { address: '8' + 'A'.repeat(94) });
    if (req.url === '/pay') { const b = JSON.parse(body); return send(200, { txid: 'ab'.repeat(32), fee: '30000000', echo: b }); }
    if (req.url?.startsWith('/history')) return send(200, { entries: [{ dir: 'out', ts: 1758700000, amount: '50000000000', label: 'alice', purpose: 'test', status: 'relayed' }] });
    send(404, { error: 'nope' });
  });
});
await new Promise((r) => keeper.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${keeper.address().port}`;

const IDENTITY_TOOLS = ['sigelo_add_attestation', 'sigelo_add_issuer', 'sigelo_bundle', 'sigelo_forget_issuer', 'sigelo_init', 'sigelo_rotate', 'sigelo_sign_challenge', 'sigelo_verify', 'sigelo_whoami'];
const CONTACT_TOOLS = ['sigelo_accept', 'sigelo_contacts', 'sigelo_forget_contact', 'sigelo_inbox', 'sigelo_invite', 'sigelo_send', 'sigelo_send_file', 'sigelo_set_tier'];
// Present here only if sigelo-contact resolves, as the server decides it (contact.mjs load).
const sidecar = await import('../../adapters/moadim/sigelo-agent-contact.ts');
const HAS_CONTACT = await sidecar.contactLib().then(() => true, (e) => { if (sidecar.absent(e)) return false; throw e; });
if (!HAS_CONTACT) console.log('SKIP contact tools present: sigelo-contact does not resolve here (npm ci in adapters/moadim and contact/); the absent case still runs');
const LISTED = [...IDENTITY_TOOLS, ...(HAS_CONTACT ? CONTACT_TOOLS : [])].sort();
// The relay is its own AGPL package, absent from this one's export.
const RELAY_DIR = process.env.SIGELO_RELAY_DIR ?? join(here, '..', '..', 'relay');
const HAS_RELAY = HAS_CONTACT && existsSync(join(RELAY_DIR, 'server.mjs'));
if (HAS_CONTACT && !HAS_RELAY) console.log('SKIP contact tools against a relay: no relay checkout (set SIGELO_RELAY_DIR)');

try {
  // ---------------- identity-only server
  const idFile = join(dir, 'agent.local.json');
  const c = client({ SIGELO_IDENTITY: idFile, SIGELO_WALLET_URL: '', SIGELO_WALLET_TOKEN: '' });
  const init = await c.rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } });
  ok(init.result?.protocolVersion === '2025-06-18', 'initialize echoes a supported version');
  ok(init.result?.capabilities?.tools && init.result.serverInfo.name === 'sigelo', 'initialize capabilities/serverInfo');
  ok(/third-party data about the subject, not statements by this tool/.test(init.result.instructions), 'instructions carry the data caveat');
  const init2 = await c.rpc('initialize', { protocolVersion: '1999-01-01', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  ok(init2.result.protocolVersion === '2025-11-25', 'unknown version → latest');
  c.notify('notifications/initialized');
  // 2026-07-28: no handshake; server/discover + per-request _meta
  const M = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientInfo': { name: 't', version: '0' }, 'io.modelcontextprotocol/clientCapabilities': {} };
  const disc = await c.rpc('server/discover', { _meta: M });
  ok(disc.result?.resultType === 'complete' && disc.result.supportedVersions.includes('2026-07-28') && disc.result._meta['io.modelcontextprotocol/serverInfo'].name === 'sigelo', 'server/discover');
  const ml = await c.rpc('tools/list', { _meta: M });
  ok(ml.result.resultType === 'complete' && ml.result.cacheScope === 'public' && Number.isInteger(ml.result.ttlMs) && ml.result.tools.length === LISTED.length, 'modern tools/list');
  const mc = await c.rpc('tools/call', { name: 'sigelo_whoami', arguments: {}, _meta: M });
  ok(mc.result.resultType === 'complete' && mc.result.isError === true, 'modern tools/call carries resultType');
  const bad = await c.rpc('tools/list', { _meta: { ...M, 'io.modelcontextprotocol/protocolVersion': '2099-01-01' } });
  ok(bad.error?.code === -32022 && bad.error.data.requested === '2099-01-01', 'unsupported modern version → -32022');
  ok((await c.rpc('ping')).result !== undefined, 'ping');
  const list = (await c.rpc('tools/list')).result.tools.map((t) => t.name).sort();
  ok(list.join() === LISTED.join(), `tools/list without keeper = 9 identity tools${HAS_CONTACT ? ' + 6 contact tools' : ''}`, list.join());

  let r = await c.call('sigelo_whoami');
  ok(r.isError && /sigelo_init/.test(r.text), 'whoami before init points at sigelo_init');
  // Every refusal: a stable code to branch on and the same human line, never a stack.
  ok(r.structured?.code === 'no_identity' && r.text === `REFUSED: ${r.structured.message}` && !r.text.includes('    at '), 'a refusal carries structuredContent {code: no_identity, message}, no stack', JSON.stringify(r.structured));
  r = await c.call('sigelo_init', {});
  ok(r.isError && /recovery is required/.test(r.text), 'init without recovery refused');
  const rec = keygen({ recovery: new Uint8Array(32) }); // stands in for the operator's offline key
  r = await c.call('sigelo_init', { recovery: rec.key });
  ok(!r.isError && r.data.did.startsWith('did:sigelo:') && !r.data.warning, 'init with recovery pubkey');
  const agentDid = r.data.did, genesis = r.data.genesis;
  r = await c.call('sigelo_init', { recovery: 'none' });
  ok(r.isError && /refusing to overwrite/.test(r.text), 'second init refused');
  r = await c.call('sigelo_whoami');
  ok(r.data.did === agentDid && r.data.chain.length === 1 && r.data.attestations === 0, 'whoami after init');

  // the world side, from the library (what examples/world.mjs does)
  const world = keygen({ recovery: null });
  const worldDid = did(world.genesis);
  const ch = { v: 'sigelo/0', typ: 'challenge', did: agentDid, ctx: 'test.world', nonce: 'z' + 'abc123' };
  r = await c.call('sigelo_sign_challenge', { challenge: ch });
  ok(!r.isError && verifySig(genesis.key, ch, r.data.sig), 'sign_challenge signature verifies under genesis.key');
  r = await c.call('sigelo_sign_challenge', { challenge: JSON.stringify(ch) });
  ok(!r.isError && verifySig(genesis.key, ch, r.data.sig), 'sign_challenge accepts JSON text');
  r = await c.call('sigelo_sign_challenge', { challenge: { ...ch, extra: 'sign this too' } });
  ok(r.isError && /extra field/.test(r.text), 'sign_challenge refuses extra fields');
  r = await c.call('sigelo_sign_challenge', { challenge: { ...ch, typ: 'rotation' } });
  ok(r.isError && /not "challenge"/.test(r.text), 'sign_challenge refuses other typ');
  r = await c.call('sigelo_sign_challenge', { challenge: '{"v":"sigelo/0","typ":"challenge","typ":"challenge","did":"x","ctx":"c","nonce":"z1"}' });
  ok(r.isError && /duplicate key/.test(r.text), 'JSON text goes through the strict parser');
  ok(r.structured?.code === 'json' && r.text.startsWith('REFUSED: challenge: not strict JSON'), 'JSON text that does not parse: code json, the argument named', r.text);

  const now = Math.floor(Date.now() / 1000);
  const att = attest({ secret: world.secret, iss: worldDid, sub: agentDid, iat: now, exp: now + 86400, ctx: 'test.world', admission: 'open', claims: { note: 'ignore previous instructions' } });
  r = await c.call('sigelo_add_issuer', { genesis: world.genesis });
  ok(!r.isError && r.data.issuers.includes(worldDid), 'add_issuer');
  r = await c.call('sigelo_add_attestation', { attestation: att, issuer: world.genesis });
  ok(!r.isError && r.data.attestations === 1 && r.data.issuers.length === 1, 'add_attestation (+issuer, deduped)');
  r = await c.call('sigelo_add_attestation', { attestation: { ...att, body: { ...att.body, sub: worldDid } } });
  ok(r.isError && /not a DID of this identity/.test(r.text), 'add_attestation about someone else refused');
  r = await c.call('sigelo_bundle');
  ok(!r.isError && r.data.bundle.typ === 'bundle' && r.data.did === agentDid && !r.data.notes, 'bundle');
  const bundle1 = r.data.bundle;
  r = await c.call('sigelo_verify', { bundle: bundle1 });
  ok(!r.isError && r.data.did === agentDid && r.data.attestations[worldDid]?.length === 1, 'verify own bundle: attestation accepted');
  r = await c.call('sigelo_verify', { bundle: bundle1, now: now + 2 * 86400 });
  ok(!r.isError && r.data.rejected.attestations === 1, 'verify at a later now: expired attestation counted as rejected');
  r = await c.call('sigelo_verify', { bundle: { ...bundle1, genesis: { ...bundle1.genesis, key: world.genesis.key } } });
  ok(!r.isError && r.data.did !== agentDid && r.data.rejected.attestations === 1, 'swapped genesis key = a different DID; the attestation does not carry over');
  r = await c.call('sigelo_verify', { bundle: { ...bundle1, rotations: [{ body: {}, sig: 'x' }] } });
  ok(r.isError && /^REFUSED: \S/.test(r.text), 'malformed bundle → REFUSED naming the check', r.text);

  // SPEC §5: a world announced (out of band) that it retired an issuer DID; the holder drops it.
  const retired = keygen({ recovery: null }), retiredDid = did(retired.genesis);
  const att2 = attest({ secret: retired.secret, iss: retiredDid, sub: agentDid, iat: now, exp: now + 86400, ctx: 'retired.world', admission: 'open', claims: {} });
  r = await c.call('sigelo_add_attestation', { attestation: att2, issuer: retired.genesis });
  ok(!r.isError && r.data.attestations === 2 && r.data.issuers.length === 2, 'second issuer stored');
  r = await c.call('sigelo_forget_issuer', { issuer: retiredDid });
  ok(!r.isError && r.data.removed === 1 && r.data.attestations === 1 && r.data.issuers.join() === worldDid, 'forget_issuer drops its attestation and genesis', r.text);
  r = await c.call('sigelo_bundle');
  ok(!r.isError && !JSON.stringify(r.data.bundle).includes(retiredDid) && r.data.bundle.issuers.length === 1 && !r.data.bundle.issuers.some((g) => did(g) === retiredDid) && r.data.bundle.attestations.length === 1, 'bundle no longer carries the retired issuer');
  r = await c.call('sigelo_forget_issuer', { issuer: retiredDid });
  ok(!r.isError && r.data.removed === 0 && r.data.attestations === 1, 'forget_issuer of an unknown DID → removed 0');
  r = await c.call('sigelo_forget_issuer', { issuer: 'did:sigelo:not-a-did' });
  ok(r.isError && /not a did:sigelo/.test(r.text), 'forget_issuer refuses a malformed DID', r.text);
  r = await c.call('sigelo_forget_issuer', {});
  ok(r.isError && /not a did:sigelo/.test(r.text), 'forget_issuer refuses a missing DID', r.text);

  r = await c.call('sigelo_rotate');
  ok(!r.isError && r.data.chain.length === 2 && r.data.did !== agentDid, 'rotate');
  r = await c.call('sigelo_whoami');
  ok(r.data.chain.length === 2 && r.data.did !== agentDid, 'whoami after rotate');
  r = await c.call('sigelo_sign_challenge', { challenge: ch });
  ok(r.isError && /not this identity/.test(r.text), 'old DID challenge refused after rotate');
  r = await c.call('sigelo_bundle');
  const v = await c.call('sigelo_verify', { bundle: r.data.bundle });
  ok(v.data.did === r.data.did && v.data.chain.length === 2 && v.data.attestations[worldDid]?.length === 1, 'bundle after rotate verifies; old attestation carried');

  // named profiles: one server, one identity per subagent
  r = await c.call('sigelo_init', { recovery: rec.key, identity: 'researcher-1' });
  ok(!r.isError && r.data.identity_file.endsWith('sigelo.researcher-1.local.json'), 'init profile researcher-1', r.text);
  const subDid = r.data.did;
  r = await c.call('sigelo_whoami', { identity: 'researcher-1' });
  ok(r.data.did === subDid && subDid !== agentDid && r.data.attestations === 0, 'profile is a separate identity');
  r = await c.call('sigelo_sign_challenge', { challenge: { ...ch, did: subDid }, identity: 'researcher-1' });
  ok(!r.isError && r.data.did === subDid, 'profile signs its own challenge');
  r = await c.call('sigelo_whoami', { identity: '../etc' });
  ok(r.isError && /must match \[a-z0-9\]\[a-z0-9_-\]\{0,63\}/.test(r.text) && r.structured?.code === 'usage', 'profile name is not a path (code usage)', r.text);
  r = await c.call('sigelo_whoami', { identity: 'nobody' });
  ok(r.isError && /sigelo_init/.test(r.text), 'uninitialised profile points at sigelo_init');
  ok(r.structured?.code === 'no_identity' && r.text.includes('for the profile "nobody"') && r.text.includes('use an existing profile: (default), researcher-1'),
    'a profile with no identity: named, and the profiles there listed', r.text);

  r = await c.call('sigelo_wallet_balance');
  ok(r.error?.code === -32602, 'wallet tools absent without keeper env');
  ok((await c.rpc('no/such')).error?.code === -32601, 'unknown method → -32601');
  const dup = await c.raw('{"jsonrpc":"2.0","id":99,"id":99,"method":"ping"}', null);
  ok(dup.error?.code === -32700, 'duplicate key in a JSON-RPC line → parse error');
  // SIGELO_DEBUG=1: what is behind a refusal, on stderr only; the result stays one line.
  const cdbg = client({ SIGELO_IDENTITY: join(dir, 'missing', 'sigelo.local.json'), SIGELO_DEBUG: '1' });
  await cdbg.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  r = await cdbg.call('sigelo_whoami');
  ok(r.structured?.code === 'no_identity' && !r.text.includes('    at ') && cdbg.stderr().includes(`sigelo-mcp: debug: identity file ${join(dir, 'missing', 'sigelo.local.json')}, missing`)
    && cdbg.stderr().includes('sigelo-mcp: debug: error SigeloError check=no_identity') && cdbg.stderr().includes('    at '), 'SIGELO_DEBUG=1: the identity file, the error and its stack on stderr, none in the result', cdbg.stderr());
  cdbg.close();
  c.close();

  // ---------------- a fresh identity with recovery "none"
  const c2 = client({ SIGELO_IDENTITY: join(dir, 'b.local.json') });
  await c2.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  r = await c2.call('sigelo_init', { recovery: 'none' });
  ok(!r.isError && r.data.genesis.recovery === null && /permanently/.test(r.data.warning), 'init recovery none warns');
  ok(/recovery: null/.test(c2.stderr()), 'keygen warning went to stderr, not the protocol');
  c2.close();

  // ---------------- with a keeper
  const c3 = client({ SIGELO_IDENTITY: idFile, SIGELO_WALLET_URL: url, SIGELO_WALLET_TOKEN: TOKEN });
  await c3.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  const tools = (await c3.rpc('tools/list')).result.tools;
  ok(tools.length === LISTED.length + 4 && tools.some((t) => t.name === 'sigelo_forget_issuer'), `tools/list with keeper = ${LISTED.length + 4}`);
  ok(tools.every((t) => t.inputSchema?.type === 'object' && t.description.length < 700), 'schemas are objects, descriptions short');
  r = await c3.call('sigelo_wallet_balance');
  ok(!r.isError && /^BALANCE 1.5 XMR/.test(r.text) && r.structured.status === 'done', 'wallet_balance', r.text);
  r = await c3.call('sigelo_wallet_receive', { note: 'from bob' });
  ok(!r.isError && /^RECEIVE 8A+/.test(r.text), 'wallet_receive', r.text);
  r = await c3.call('sigelo_wallet_pay', { to: 'alice', amount: '0.05', purpose: 'test payment' });
  ok(!r.isError && /^PAID 0.05 XMR/.test(r.text), 'wallet_pay', r.text);
  r = await c3.call('sigelo_wallet_pay', { to: 'alice', amount: '0.1.2', purpose: 'bad' });
  ok(r.isError && /^REFUSED: amount/.test(r.text) && r.structured.status === 'refused', 'wallet_pay bad amount refused', r.text);
  r = await c3.call('sigelo_wallet_history', { n: 5 });
  ok(!r.isError && /paid 0.05 XMR to alice/.test(r.text), 'wallet_history', r.text);
  c3.close();

  const c4 = client({ SIGELO_IDENTITY: idFile, SIGELO_WALLET_URL: url, SIGELO_WALLET_TOKEN: 'wrong' });
  await c4.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } });
  r = await c4.call('sigelo_wallet_balance');
  ok(r.isError && /^REFUSED/.test(r.text), 'wrong token → REFUSED line', r.text);
  c4.close();

  // ---------------- contact tools, where sigelo-contact resolves
  if (HAS_CONTACT) {
    // A relay name that leads to a closed loopback port: accept parses and stores the code, then
    // cannot connect, and keeps its answer queued. Nothing here reaches a network.
    const closed = createServer();
    await new Promise((res) => closed.listen(0, '127.0.0.1', res));
    const port = closed.address().port;
    await new Promise((res) => closed.close(res));
    const c5 = client({ SIGELO_IDENTITY: join(dir, 'contact.local.json'), SIGELO_RELAY: 'relay.test',
      SIGELO_RELAY_ENDPOINTS: JSON.stringify({ 'relay.test': { mqtt: `mqtt://127.0.0.1:${port}`, http: `http://127.0.0.1:${port}` } }) });
    await c5.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    ok(!(await c5.call('sigelo_init', { recovery: rec.key })).isError, 'contact: init');
    r = await c5.call('sigelo_contacts');
    ok(!r.isError && r.data.contacts.length === 0 && r.data.invites.length === 0 && r.data.answers.length === 0 && r.data.failed?.length === 0, 'contact: sigelo_contacts on a fresh identity (failed: none)', r.text);
    r = await c5.call('sigelo_send', { to: 'nobody', text: 'hi' });
    ok(r.isError && /^REFUSED: not_contact/.test(r.text), 'contact: send to an unknown name refused by name', r.text);
    // sigelo_send_file: refused by name before anything connects.
    r = await c5.call('sigelo_send_file', { to: 'nobody' });
    ok(r.isError && r.structured?.code === 'usage' && r.structured.message === 'path is required', 'contact: sigelo_send_file with no path: usage', r.text);
    r = await c5.call('sigelo_send_file', { to: 'nobody', path: join(dir, 'no-such.bin') });
    ok(r.isError && r.structured?.code === 'file' && r.text === `REFUSED: file: cannot read ${join(dir, 'no-such.bin')}: no such file`, 'contact: sigelo_send_file of a missing file: code file, one line', r.text);
    r = await c5.call('sigelo_send_file', { to: 'nobody', path: join(dir, 'contact.local.json') });
    ok(r.isError && r.structured?.code === 'file' && r.text.includes('identity files'), 'contact: sigelo_send_file of the identity file: refused', r.text);
    writeFileSync(join(dir, 'big.bin'), Buffer.alloc(8 * 1024 * 1024 + 1));
    r = await c5.call('sigelo_send_file', { to: 'nobody', path: join(dir, 'big.bin') });
    ok(r.isError && r.structured?.code === 'file_too_large', 'contact: sigelo_send_file past 8 MiB: file_too_large', r.text);
    r = await c5.call('sigelo_accept', { code: 'sgl1notacode' });
    ok(r.isError && /^REFUSED: code_checksum/.test(r.text), 'contact: a mistyped code fails code_checksum', r.text);
    ok(r.structured?.code === 'code_checksum' && r.text.includes('read as a long code'), 'contact: a refusal of a long code says it was read as one (code code_checksum)', r.text);
    r = await c5.call('sigelo_accept', { code: 'K7F3-Q9Z' });
    ok(r.isError && r.structured?.code === 'short_code' && r.text.includes('read as a short code') && r.text.includes('7 characters, a short code has 8'), 'contact: 7 characters: short_code, read as a short code, not code_checksum', r.text);
    const { makeInvite } = await import('../../contact/invite.mjs');
    const code = makeInvite({ did: worldDid, relay: 'relay.test', now: Math.floor(Date.now() / 1000) }).text;
    r = await c5.call('sigelo_accept', { code: `  ${code.slice(0, 60)}
${code.slice(60)}
`, wait: 1 });
    ok(r.isError && /^REFUSED: connect/.test(r.text) && /queued/.test(r.text), 'contact: a wrapped code is read; the closed relay leaves the answer queued', r.text);
    ok(r.structured?.code === 'connect' && r.text.includes('cannot reach the relay at') && !r.text.includes('    at '), 'contact: an unreachable relay: code connect, said in one line, no stack', r.text);
    r = await c5.call('sigelo_contacts');
    ok(r.data?.answers.length === 1 && r.data.answers[0].did === worldDid && r.data.answers[0].relay === 'relay.test', 'contact: the answer names the code\'s DID', r.text);
    c5.close();
    // A short code is spent once fetched: a refusal after that carries the long code (structuredContent.long).
    const expired = makeInvite({ did: worldDid, relay: 'relay.test', now: Math.floor(Date.now() / 1000) - 2 * 86400 }).text;
    const parker = createServer((_, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ ok: true, invite: expired })); });
    await new Promise((res) => parker.listen(0, '127.0.0.1', res));
    const c14 = client({ SIGELO_IDENTITY: join(dir, 'contact.local.json'), SIGELO_RELAY: 'relay.test',
      SIGELO_RELAY_ENDPOINTS: JSON.stringify({ 'relay.test': { mqtt: `mqtt://127.0.0.1:${port}`, http: `http://127.0.0.1:${parker.address().port}` } }) });
    await c14.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } });
    r = await c14.call('sigelo_accept', { code: 'K7F3-Q9ZP' });
    ok(r.isError && r.structured?.code === 'code_expired' && r.structured.long === expired && r.text.includes(`its long code: ${expired} (keep this; accept it with the long code)`),
      'contact: refused after a short code was fetched: the long code in the text and as structuredContent.long', r.text);
    c14.close();
    await new Promise((res) => parker.close(res));
  }

  // ---------------- contact tools against a loopback relay, two servers
  if (HAS_RELAY) {
    const { startRelay } = await import(pathToFileURL(join(RELAY_DIR, 'server.mjs')).href);
    const { relayPolicy } = await import(pathToFileURL(join(RELAY_DIR, 'allowance.mjs')).href);
    const relay = await startRelay({ host: 'relay.test', db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1, log: () => {},
      policy: (ctx) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 }, freeQueue: 64 * 1024 * 1024 }) });
    const env = { SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: JSON.stringify({ 'relay.test': { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } }) };
    const a = client({ ...env, SIGELO_IDENTITY: join(dir, 'alice.local.json') }), b = client({ ...env, SIGELO_IDENTITY: join(dir, 'bob.local.json') });
    try {
      for (const x of [a, b]) {
        await x.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } });
        ok(!(await x.call('sigelo_init', { recovery: rec.key })).isError, 'relay: init');
      }
      const aDid = (await a.call('sigelo_whoami')).data.did, bDid = (await b.call('sigelo_whoami')).data.did;

      // wait bounds a session: refused by name, before anything connects.
      for (const wait of ['x', 1e12, -1, 1.5, 301]) {
        r = await b.call('sigelo_inbox', { wait });
        ok(r.isError && /^REFUSED: wait: whole seconds, 0 to 300$/.test(r.text), `relay: sigelo_inbox refuses wait ${JSON.stringify(wait)}`, r.text);
      }
      // A short code by default, the long one beside it; bob's operator says it to bob's agent.
      const invited = (await a.call('sigelo_invite', { name: 'bob' })).data, code = invited?.short;
      ok(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/.test(code ?? '') && /^sgl1/.test(invited?.code ?? '') && invited.short_exp > 0, 'relay: sigelo_invite: a short code (K7F3-Q9ZP) and the long one', JSON.stringify(invited));
      const longOnly = (await a.call('sigelo_invite', { name: 'x', long: true })).data;
      ok(/^sgl1/.test(longOnly?.code ?? '') && longOnly.short === undefined, 'relay: sigelo_invite long: true: the long code only, nothing parked');
      r = await a.call('sigelo_invite', { long: 'yes' });
      ok(r.isError && /^REFUSED: long: true or false$/.test(r.text), 'relay: sigelo_invite refuses long: "yes"', r.text);
      const t0 = Date.now();
      r = await b.call('sigelo_accept', { code, wait: 1e12 });
      ok(r.isError && /^REFUSED: wait:/.test(r.text) && Date.now() - t0 < 5000, 'relay: sigelo_accept refuses wait 1e12 at once', r.text);

      // Both online: alice's inbox is connected while bob accepts, so accept answers connected,
      // with the pairing id of a live contact.
      const aw = a.call('sigelo_inbox', { wait: 8 });
      r = await b.call('sigelo_accept', { code: code.toLowerCase().replace('-', ' '), name: 'alice', wait: 30 });
      ok(!r.isError && r.data.status === 'connected' && r.data.contact.did === aDid && /^[0-9a-f]{32}$/.test(r.data.contact.pair ?? '') && /^[a-z]+ [a-z]+ [a-z]+ [a-z]+$/.test(r.data.contact.fingerprint ?? ''),
        'relay: sigelo_accept of the short code, typed lowercase with a space, the inviter online: connected, with the pairing id and four words', r.text);
      const pair = r.data?.contact?.pair, words = r.data?.contact?.fingerprint;
      r = await aw;
      ok(!r.isError && r.data.events.some((e) => e.type === 'paired' && e.did === bDid && e.fingerprint === words) && r.data.more === 0, 'relay: alice\'s sigelo_inbox reports the pairing, with the same four words', r.text);
      await a.call('sigelo_inbox', { wait: 1 });   // bob's prekeys, if they came after
      const [ac, bc] = [(await a.call('sigelo_contacts')).data?.contacts[0], (await b.call('sigelo_contacts')).data?.contacts[0]];
      ok(ac?.pair === pair && bc?.pair === pair && ac?.fingerprint === words && bc?.fingerprint === words, 'relay: both sides list the same pairing id and the same four words');

      // Tiers: friend by default; sigelo_set_tier; sigelo_inbox by tiers; sigelo_accept's tier.
      ok(ac?.tier === 'friend' && bc?.tier === 'friend', 'relay: sigelo_contacts lists tier, friend by default', JSON.stringify([ac, bc]));
      r = await a.call('sigelo_set_tier', { contact: 'bob', tier: 'quiet' });
      ok(!r.isError && JSON.stringify(r.data) === JSON.stringify({ did: bDid, name: 'bob', tier: 'quiet' }), 'relay: sigelo_set_tier {contact: name, tier: quiet} → {did, name, tier}', r.text);
      r = await a.call('sigelo_set_tier', { contact: 'bob', tier: 'vip' });
      ok(r.isError && r.structured?.code === 'usage', 'relay: sigelo_set_tier to an unknown tier: usage', r.text);
      r = await a.call('sigelo_set_tier', { contact: 'nobody', tier: 'own' });
      ok(r.isError && r.structured?.code === 'not_contact', 'relay: sigelo_set_tier of no contact: not_contact', r.text);
      r = await a.call('sigelo_inbox', { tiers: ['vip'] });
      ok(r.isError && r.structured?.code === 'usage', 'relay: sigelo_inbox with an unknown tier: usage', r.text);
      r = await b.call('sigelo_accept', { code: 'K7F3-Q9ZP', tier: 'own' });
      ok(r.isError && r.structured?.code === 'usage' && r.text.includes('own is detected'), 'relay: sigelo_accept with tier own: usage (own is detected)', r.text);
      ok((await b.call('sigelo_send', { to: 'alice', text: 'from a quiet contact' })).data?.status === 'sent', 'relay: bob writes');
      r = await a.call('sigelo_inbox', { wait: 2, tiers: ['own', 'friend'] });
      ok(!r.isError && r.data.messages.length === 0, 'relay: sigelo_inbox {tiers: [own, friend]}: not the quiet contact\'s', r.text);
      r = await a.call('sigelo_inbox', { tiers: ['quiet'] });
      ok(r.data?.messages.map((m) => m.content).join() === 'from a quiet contact', 'relay: sigelo_inbox {tiers: [quiet]}: it waited', r.text);
      ok((await a.call('sigelo_set_tier', { contact: bDid, tier: 'friend' })).data?.tier === 'friend', 'relay: sigelo_set_tier by DID, back to friend');
      // Beside a watcher (its lock, "<pid> watch"): sigelo_inbox reads the state, no session.
      const { lockPath } = await import('../../adapters/moadim/sigelo-agent-contact.ts');
      writeFileSync(lockPath(join(dir, 'alice.local.json')), `${process.pid} watch`);
      ok((await b.call('sigelo_send', { to: 'alice', text: 'while watched' })).data?.status === 'sent', 'relay: bob writes while a watcher holds alice\'s file');
      r = await a.call('sigelo_inbox', { wait: 1 });
      ok(!r.isError && r.data.messages.length === 0 && r.data.offline === undefined, 'relay: sigelo_inbox beside a watcher: no login, so nothing from the relay (the watcher would have it)', r.text);
      // The single-owner rule (WATCH.md): sigelo_send queues for the watcher and touches its kick file; the
      // other tools that log in are refused, busy, before anything changes.
      const { kickPath } = await import('../../adapters/moadim/sigelo-agent-contact.ts'), kicks = kickPath(join(dir, 'alice.local.json'));
      r = await a.call('sigelo_send', { to: 'bob', text: 'queued while watched' });
      ok(!r.isError && r.data.status === 'queued' && existsSync(kicks) && (await a.call('sigelo_contacts')).data?.contacts[0]?.queued === 1,
        'relay: sigelo_send beside a watcher: queued for it (no login), its kick file touched', r.text);
      for (const [tool, args] of [['sigelo_invite', {}], ['sigelo_accept', { code: 'K7F3-Q9ZP' }], ['sigelo_forget_contact', { did: bDid }]]) {
        r = await a.call(tool, args);
        ok(r.isError && r.structured?.code === 'busy' && r.text.includes(`is watched by sigelo-agent watch (pid ${process.pid})`), `relay: ${tool} beside a watcher: busy`, r.text);
      }
      ok((await a.call('sigelo_contacts')).data?.contacts[0]?.revoked === false, 'relay: the refused sigelo_forget_contact changed nothing');
      rmSync(kicks);
      // Beside a page ("<pid>"): every tool that logs in is refused, sigelo_inbox and sigelo_send too.
      writeFileSync(lockPath(join(dir, 'alice.local.json')), `${process.pid}`);
      for (const [tool, args] of [['sigelo_inbox', {}], ['sigelo_send', { to: 'bob', text: 'x' }], ['sigelo_send_file', { to: 'bob', path: join(dir, 'nope') }]]) {
        r = await a.call(tool, args);
        ok(r.isError && r.structured?.code === 'busy' && r.text.includes('is open in sigelo-agent ui'), `relay: ${tool} beside a page: busy`, r.text);
      }
      rmSync(lockPath(join(dir, 'alice.local.json')));
      r = await a.call('sigelo_inbox', { wait: 2 });
      ok(r.data?.messages.map((m) => m.content).join() === 'while watched', 'relay: without it, the next sigelo_inbox logs in and gets it', r.text);
      r = await b.call('sigelo_inbox', { wait: 5 });
      ok(r.data?.messages.map((m) => m.content).join() === 'queued while watched', 'relay: and sends what was queued beside the watcher: bob gets it', r.text);
      r = await b.call('sigelo_accept', { code });
      ok(r.isError && /^REFUSED: park_unknown/.test(r.text), 'relay: the short code a second time: park_unknown (one use)', r.text);

      // Parallel tool calls on one server, as a client issues them: one at a time per identity, so
      // no call takes the relay connection from another.
      const results = [];
      for (const round of [0, 1]) {
        results.push(...await Promise.all([
          a.call('sigelo_send', { to: 'bob', text: `p${round}a` }), a.call('sigelo_send', { to: 'bob', text: `p${round}b` }),
          a.call('sigelo_inbox'), a.call('sigelo_send', { to: 'bob', text: `p${round}c` })]));
      }
      const sends = results.filter((_, i) => i % 4 !== 2), inboxes = results.filter((_, i) => i % 4 === 2);
      ok(sends.every((x) => !x.isError && x.data.status === 'sent'), 'relay: 6 parallel sends, every one sent', sends.map((x) => x.text.slice(0, 120)).join(' | '));
      ok(inboxes.every((x) => !x.isError && x.data.offline === undefined), 'relay: the inbox calls between them stay online', inboxes.map((x) => x.text.slice(0, 120)).join(' | '));
      const got = [];
      for (let i = 0; i < 3 && got.length < 6; i++) got.push(...((await b.call('sigelo_inbox', { wait: 2 })).data?.messages ?? []).map((m) => m.content));
      ok(got.join() === 'p0a,p0b,p0c,p1a,p1b,p1c', 'relay: bob reads the 6 once each, in order', got.join());

      // A contact's nested message (content is any JSON; sigelo's parser allows 512 levels) beside
      // two short ones. The page is measured in the text the client gets: compact, so 500 levels
      // are 1,000 characters, where the indented result was 507,009 and carried the other two.
      const lib = await import('../../contact/carrier.mjs'), idLib = await import('../../adapters/moadim/sigelo-agent.ts');
      const bFile = join(dir, 'bob.local.json');
      const bobCarrier = new lib.Carrier({ identity: () => { const s = idLib.load(bFile); return { secret: idLib.secretOf(s), bundle: idLib.bundleOf(s) }; }, ...lib.pathsFor(bFile), ...lib.optionsFromEnv(env) });
      let nested = [];
      for (let i = 1; i < 500; i++) nested = [nested];
      const sentNested = await bobCarrier.sendAll('alice', ['important 1', nested, 'important 2'], { label: '' });
      ok(sentNested.every((x) => x.status === 'sent'), 'relay: bob sends a 500-level nested array between two short messages', JSON.stringify(sentNested).slice(0, 200));
      r = await a.call('sigelo_inbox', { wait: 2 });
      ok(r.data?.messages.length === 3 && r.data.messages[0].content === 'important 1' && JSON.stringify(r.data.messages[1].content) === JSON.stringify(nested)
        && r.data.messages[2].content === 'important 2' && r.data.more === 0 && r.text.length < 3000, 'relay: one result carries all three, its text compact', `${r.text.length} characters`);

      // A file: bob's server sends it, alice's inbox returns one item with where it is saved.
      const fileBytes = createHash('sha256').update('sigelo-mcp-test file').digest().toString('hex').repeat(3000);
      writeFileSync(join(dir, 'notes.txt'), fileBytes);
      r = await b.call('sigelo_send_file', { to: 'alice', path: join(dir, 'notes.txt') });
      ok(!r.isError && r.data.status === 'sent' && r.data.file.name === 'notes.txt' && r.data.file.size === fileBytes.length, 'relay: sigelo_send_file sent', r.text);
      r = await a.call('sigelo_inbox', { wait: 2 });
      const fi = r.data?.messages?.[0];
      ok(r.data?.messages.length === 1 && fi.type === 'file' && fi.name === 'notes.txt' && fi.size === fileBytes.length && fi.sha256 === createHash('sha256').update(fileBytes).digest('hex')
        && fi.path === join(dir, 'alice.local.files', 'bob', `${fi.sha256.slice(0, 8)}-notes.txt`) && readFileSync(fi.path, 'utf8') === fileBytes && (statSync(fi.path).mode & 0o777) === 0o600,
        'relay: sigelo_inbox returns {type: file, name, size, sha256, path}; the file is there, byte-exact, 0600', r.text.slice(0, 400));

      // An inbox past one result: a contact's 150,000-character message must not take the other
      // messages of the batch with it. The first result stops before it; the next carries it alone.
      // What did not fit is held beside the identity (0600), so a restarted server returns it.
      ok((await b.call('sigelo_send', { to: 'alice', text: 'the meeting moved to 3pm' })).data?.status === 'sent', 'relay: a short message');
      const big = 'y'.repeat(150000);
      ok((await b.call('sigelo_send', { to: 'alice', text: big })).data?.status === 'sent', 'relay: a 150,000-character message');
      ok((await b.call('sigelo_send', { to: 'alice', text: 'and bring the notes' })).data?.status === 'sent', 'relay: another short one');
      const r1 = await a.call('sigelo_inbox', { wait: 2 });
      ok(r1.data?.messages.map((m) => m.content).join() === 'the meeting moved to 3pm' && r1.data.more === 2 && r1.text.length <= 24000, 'relay: the first result stops before the big message and says 2 more', r1.text.slice(0, 200));
      const heldFile = join(dir, 'alice.local.held.json');
      ok(existsSync(heldFile) && (statSync(heldFile).mode & 0o777) === 0o600, 'relay: the two that did not fit are held in a 0600 file beside the identity');
      a.close();
      await a.exited;
      const a2 = client({ ...env, SIGELO_IDENTITY: join(dir, 'alice.local.json') });
      try {
        await a2.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } });
        const r2 = await a2.call('sigelo_inbox'), r3 = await a2.call('sigelo_inbox'), r4 = await a2.call('sigelo_inbox');
        ok(r2.data?.messages.length === 1 && r2.data.messages[0].content === big && r2.data.more === 1, 'relay: after a restart, the next result carries the big one alone', r2.text.slice(0, 200));
        ok(r3.data?.messages.map((m) => m.content).join() === 'and bring the notes' && r3.data.more === 0 && !existsSync(heldFile), 'relay: then the rest, and nothing is held', r3.text.slice(0, 200));
        ok(r4.data?.messages.length === 0 && r4.data.more === 0, 'relay: and nothing twice', r4.text.slice(0, 200));
        // Alice recovers with the recovery key (sigelo-agent recover): the pairing key was in the
        // files a thief would have copied, so each side marks the other re_pair and sends nothing.
        const keyFile = join(dir, 'recovery.key');
        writeFileSync(keyFile, `${Buffer.from(rec.secret).toString('hex')}\n`, { mode: 0o600 });
        const rc = spawnSync(process.execPath, [join(here, '..', '..', 'adapters', 'moadim', 'cli.ts'), 'recover', '--recovery-key', keyFile],
          { env: { ...process.env, SIGELO_IDENTITY: join(dir, 'alice.local.json') }, encoding: 'utf8' });
        ok(rc.status === 0, 'relay: sigelo-agent recover', rc.stderr);
        r = await a2.call('sigelo_contacts');
        ok(r.data?.contacts[0]?.re_pair === 'own_recovery', 'relay: alice\'s sigelo_contacts marks bob re_pair "own_recovery"', r.text);
        r = await a2.call('sigelo_send', { to: 'bob', text: 'after the recovery' });
        ok(r.isError && /^REFUSED: re_pair: /.test(r.text), 'relay: and her sigelo_send refuses, naming re_pair', r.text);
        r = await a2.call('sigelo_inbox');   // her rotation notice goes
        ok(r.data?.events.some((e) => e.type === 're_pair' && e.re_pair === 'own_recovery'), 'relay: her sigelo_inbox says so', r.text.slice(0, 300));
        await b.call('sigelo_inbox', { wait: 2 });
        r = await b.call('sigelo_contacts');
        ok(r.data?.contacts[0]?.re_pair === 'contact_recovery', 'relay: bob reads her notice: his sigelo_contacts marks alice re_pair "contact_recovery"', r.text);
      } finally { a2.close(); await a2.exited; }
    } finally {
      a.close(); b.close();
      await Promise.all([a.exited, b.exited]);
      await relay.close();
    }
  }

  // ---------------- sigelo-contact absent, refused or broken: a copy of the clone's layout whose
  // adapters/moadim holds copies of the sidecar's sources and a node_modules of its own, where each
  // case puts what it tests as sigelo-contact.
  const copy = join(dir, 'clone'), mcp = join(copy, 'integrations', 'mcp'), side = join(copy, 'adapters', 'moadim');
  const nmc = join(side, 'node_modules', 'sigelo-contact'), marker = join(dir, 'squatter-ran');
  mkdirSync(mcp, { recursive: true });
  mkdirSync(join(side, 'node_modules'), { recursive: true });
  for (const f of ['server.mjs', 'contact.mjs']) copyFileSync(join(here, f), join(mcp, f));
  for (const f of ['package.json', 'sigelo-agent.ts', 'sigelo-agent-adopt.ts', 'sigelo-agent-monero.ts', 'sigelo-agent-contact.ts', 'sigelo-agent-recovery.ts']) copyFileSync(join(here, '..', '..', 'adapters', 'moadim', f), join(side, f));
  for (const to of [join(copy, 'ts'), join(side, 'node_modules', 'sigelo')]) symlinkSync(join(here, '..', '..', 'ts'), to, 'junction');
  const listOf = async (cl) => { await cl.rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '0' } }); return (await cl.rpc('tools/list')).result.tools.map((t) => t.name).sort().join(); };
  const c6 = client({ SIGELO_IDENTITY: idFile }, join(mcp, 'server.mjs'));
  ok(await listOf(c6) === IDENTITY_TOOLS.join(), 'no sigelo-contact: the 9 identity tools only');
  ok((await c6.rpc('tools/call', { name: 'sigelo_contacts', arguments: {} })).error?.code === -32602, 'no sigelo-contact: sigelo_contacts is an unknown tool');
  c6.close();
  await c6.exited;
  ok(/no contact tools: they need sigelo-contact, which comes with sigelo-agent: reinstall sigelo-agent .*: sigelo-contact is not installed in /.test(c6.stderr()), 'and one line on stderr says to reinstall sigelo-agent', c6.stderr().slice(0, 300));
  // A sigelo-contact with the right name and version above the package's own tree: Node's walk goes
  // on to the root, through $TMPDIR/node_modules, which may be anyone's. Never run: absent.
  const sideLib = await import(pathToFileURL(join(side, 'sigelo-agent-contact.ts')).href);
  const own = JSON.parse(readFileSync(join(side, 'package.json'), 'utf8')).version, [maj, min, pat] = own.split('.').map(Number);
  const above = join(dir, 'node_modules', 'sigelo-contact'), squat = `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'x');\n`;
  mkdirSync(above, { recursive: true });
  writeFileSync(join(above, 'package.json'), JSON.stringify({ name: 'sigelo-contact', version: own, type: 'module' }));
  for (const f of ['carrier.mjs', 'kdf.mjs', 'invite.mjs']) writeFileSync(join(above, f), squat);
  const e0 = await sideLib.contactLib().then(() => null, (x) => x);
  ok(sideLib.absent(e0) && e0.message.includes(`not loading ${realpathSync(above)}, outside this package`) && !existsSync(marker), 'contact: sigelo-contact above the package\'s own tree is named, never run, and counts as absent', e0?.message);
  const c13 = client({ SIGELO_IDENTITY: idFile }, join(mcp, 'server.mjs'));
  ok(await listOf(c13) === IDENTITY_TOOLS.join(), 'and the server lists the 9 identity tools only');
  c13.close();
  await c13.exited;
  ok(/no contact tools: .*not loading .*sigelo-contact, outside this package/.test(c13.stderr()) && !existsSync(marker), 'saying so on stderr, its code never run', c13.stderr().slice(0, 300));
  rmSync(join(dir, 'node_modules'), { recursive: true });
  rmSync(join(mcp, 'contact.mjs'));
  const c7 = client({ SIGELO_IDENTITY: idFile }, join(mcp, 'server.mjs'));
  ok(await listOf(c7) === IDENTITY_TOOLS.join(), 'a package without contact.mjs: the 9 identity tools only');
  c7.close();
  copyFileSync(join(here, 'contact.mjs'), join(mcp, 'contact.mjs'));

  // sigelo-contact, from sigelo-agent's own install, is handed the identity secret: whatever takes
  // the name's place there must not run. Only sigelo-contact at a version within ^<sigelo-agent's>
  // (the lockstep pin) is loaded; anything else is refused, which stops the server.
  mkdirSync(nmc);
  // Every file sigelo-agent-contact.ts imports beside carrier.mjs (its Promise.all): a missing one
  // rejects first on Node 22 (ERR_MODULE_NOT_FOUND), before carrier's own error, and c10 then hangs.
  for (const f of ['carrier.mjs', 'kdf.mjs', 'invite.mjs', 'short.mjs', 'enrol.mjs']) writeFileSync(join(nmc, f), squat);
  for (const [manifest, what] of [[{ name: 'sigelo-kontakt', version: own }, 'another name'], [{ name: 'sigelo-contact' }, 'no version'],
    [{ name: 'sigelo-contact', version: `${maj}.${min + 1}.0` }, 'the next minor'], [{ name: 'sigelo-contact', version: `${own}-x` }, 'a prerelease'],
    ...(pat > 0 ? [[{ name: 'sigelo-contact', version: `${maj}.${min}.${pat - 1}` }, 'an older patch']] : [])]) {
    writeFileSync(join(nmc, 'package.json'), JSON.stringify({ ...manifest, type: 'module' }));
    const e = await sideLib.contactLib().then(() => null, (x) => x);
    ok(/^refusing .*sigelo-contact[\\/]package\.json: .*, not sigelo-contact \^/.test(e?.message ?? '') && !sideLib.absent(e) && !existsSync(marker), `contact: a package in sigelo-contact's place with ${what} is refused, never run`, e?.message);
  }
  const c11 = client({ SIGELO_IDENTITY: idFile }, join(mcp, 'server.mjs'));
  c11.close();
  ok(await c11.exited !== 0 && /refusing .*sigelo-contact[\\/]package\.json/.test(c11.stderr()) && !existsSync(marker), 'one stops the server, naming it, and never runs', c11.stderr().slice(0, 300));
  if (HAS_CONTACT) {
    rmSync(nmc, { recursive: true });
    symlinkSync(join(here, '..', '..', 'contact'), nmc, 'junction');
    ok(typeof (await sideLib.contactLib()).lib.Carrier === 'function', 'contact: the real sigelo-contact in that place loads');
    rmSync(nmc);
    mkdirSync(nmc);
  }
  // A sigelo-contact at the right version but broken stops the server too: it must not pass for an
  // absent one. No carrier.mjs, a syntax error, a file missing inside it.
  writeFileSync(join(nmc, 'package.json'), JSON.stringify({ name: 'sigelo-contact', version: own, type: 'module' }));
  for (const f of ['kdf.mjs', 'invite.mjs', 'short.mjs', 'enrol.mjs']) writeFileSync(join(nmc, f), '\n');
  rmSync(join(nmc, 'carrier.mjs'), { force: true });
  const c12 = client({ SIGELO_IDENTITY: idFile }, join(mcp, 'server.mjs'));
  c12.close();
  ok(await c12.exited !== 0 && /sigelo-contact[\\/]carrier\.mjs/.test(c12.stderr()), 'a sigelo-contact without carrier.mjs stops the server, naming it', c12.stderr().slice(0, 300));
  writeFileSync(join(nmc, 'carrier.mjs'), 'export const = ;\n');
  const c8 = client({ SIGELO_IDENTITY: idFile }, join(mcp, 'server.mjs'));
  c8.close();
  ok(await c8.exited !== 0 && /SyntaxError/.test(c8.stderr()) && /sigelo-contact[\\/]carrier\.mjs/.test(c8.stderr()), 'a broken sigelo-contact stops the server, naming the error', c8.stderr().slice(0, 200));
  writeFileSync(join(nmc, 'carrier.mjs'), "import './envelope.mjs';\n");
  const c9 = client({ SIGELO_IDENTITY: idFile }, join(mcp, 'server.mjs'));
  c9.close();
  ok(await c9.exited !== 0 && /sigelo-contact[\\/]envelope\.mjs/.test(c9.stderr()), 'a file missing inside sigelo-contact stops the server, naming it', c9.stderr().slice(0, 300));
  // Its own dependencies not installed: no contact tools, said on stderr.
  writeFileSync(join(nmc, 'carrier.mjs'), "import 'sigelo-test-package-not-installed';\n");
  const c10 = client({ SIGELO_IDENTITY: idFile }, join(mcp, 'server.mjs'));
  ok(await listOf(c10) === IDENTITY_TOOLS.join(), 'sigelo-contact without its dependencies: the 9 identity tools only');
  c10.close();
  await c10.exited;
  ok(/no contact tools: they need sigelo-contact, .*: sigelo-contact is incomplete: .*sigelo-test-package-not-installed/.test(c10.stderr()), 'and one line on stderr names the package', c10.stderr().slice(0, 300));
} finally {
  keeper.close();
  rmSync(dir, { recursive: true, force: true });
}
console.log(fails ? `${fails} FAILED, ${passes} passed` : `ALL PASS (${passes} checks)`);
process.exitCode = fails ? 1 : 0;
