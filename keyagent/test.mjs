// SPDX-License-Identifier: MIT
// sigelo-key-agent, milestone K3 (KEYS.md). `node test.mjs` → ALL PASS or exit 1.
//   1. fixtures/protocol-v0.json: every request and refusal of §4.2–4.3 as byte-exact request/reply
//      lines, replayed through the agent in-process (fixed randomness and clock); signatures equal
//      test-vectors.json where a vector exists. `node test.mjs --write` regenerates it.
//   2. The agent as a process on a temp socket: an unsafe socket directory refused, a second agent
//      refused, no agent → key_agent_unavailable within 2 s, a line over 2 MiB refused, the log
//      holds no body and no key; the default keychain store wraps (an in-memory store), and with no
//      OS keychain and no --store-plain the agent does not start.
//   3. The sidecar through it (SIGELO_KEY_AGENT): init, sign-challenge, keys status, keys to-agent
//      (the file then holds no key), key_agent_mismatch, rotate; a torn rotation (the caller killed
//      between rotate and its write) converges; a stale copy cannot fork the identity.
//   4. install-unit for systemd and launchd.
//   5. The contact and MCP suites with the key in an agent (SIGELO_TEST_KEY_AGENT=1): each spawns its
//      own agent on a temp socket and passes with every identity file saying {"provider":"agent"}.
// Windows: the named pipe runs here as a socket would; its ACL is checked by hand (README.md).
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAgent, unit } from './agent.mjs';
import { encode, keychain, keyclient, MAX_LINE, PROTOCOL, S } from './protocol.mjs';

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '..');
const AGENT = join(HERE, 'agent.mjs'), CLI = join(ROOT, 'adapters', 'moadim', 'cli.ts'), FIXTURE = join(HERE, 'fixtures', 'protocol-v0.json');
const WIN = process.platform === 'win32';
const V = JSON.parse(readFileSync(join(ROOT, 'test-vectors.json'), 'utf8'));
const TMP = mkdtempSync(join(tmpdir(), 'sigelo-keyagent-'));
let passes = 0, fails = 0;
const ok = (c, name, extra = '') => { if (c) { passes++; console.log(`ok   ${name}`); } else { fails++; console.log(`FAIL ${name}${extra ? ` — ${String(extra).slice(0, 600)}` : ''}`); } };
const code = (fn) => { try { fn(); return null; } catch (e) { return e.check ?? e.message; } };
const hex = (b) => Buffer.from(b).toString('hex');

// ── 1. the fixture ──────────────────────────────────────────────────────────────────────────
const NOW = 1790000000000;
/** The fixture's randomness: SHA-256("sigelo-key-agent-fixture/0 " ‖ n), n = 0, 1, … across the file. */
const fixtureRand = () => { let n = 0; return (len) => createHash('sha256').update(`sigelo-key-agent-fixture/0 ${n++}`).digest().subarray(0, len); };
const G = V.vectors.genesis.doc, D = S.did(G), W = V.vectors.world_genesis.doc, WD = S.did(W);
const OTHER = 'did:sigelo:z8hhrKBPMQH3A9Ph8CX7jxRvfppT5nWQYtMmugXjCQoKq';  // rotation_voluntary's next: not held here
const PAIR = '0'.repeat(64);
const line = (o) => JSON.stringify(o);
const sign = (body, did = D) => line({ op: 'sign', did, body });
const bodies = (d) => ({
  challenge: { ...V.vectors.challenge.body, did: d },
  'relay-login': { v: 'sigelo-relay/0', typ: 'relay-login', did: d, relay: 'relay.test', nonce: 'zRe1ayNonce' },
  'invite-answer': { v: 'sigelo-invite/0', typ: 'invite-answer', did: d, nonce: 'zInv1teNonce', transcript: 'z' + 'A'.repeat(43) },
  'invite-reply': { v: 'sigelo-invite/0', typ: 'invite-reply', did: d, nonce: 'zInv1teNonce', transcript: 'z' + 'B'.repeat(43) },
  message: { v: 'sigelo-msg/0', typ: 'message', from: d, to: OTHER, pair: PAIR, epoch: '11'.repeat(16), n: 0, iat: 1790000000, label: 'x', content: { text: 'hello' } },
  prekeys: { v: 'sigelo-msg/0', typ: 'prekeys', did: d, pair: PAIR, iat: 1790000000, exp: 1792678400, keys: [], last_resort: null },
  'contact-notice': { v: 'sigelo-carrier/0', typ: 'contact-notice', did: d, pair: PAIR },
});
const SESSIONS = [
  { name: 'the default agent: no payments, no attestations', flags: {}, requests: () => {
    const b = bodies(D);
    return [
      ['list, empty', line({ op: 'list' })],
      ['import the vector identity (test-vectors seed "agent")', line({ op: 'import', genesis: G, seed: V.seeds.agent })],
      ['import it again: key_held', line({ op: 'import', genesis: G, seed: V.seeds.agent })],
      ['import a seed that is not the genesis key: key_mismatch', line({ op: 'import', genesis: W, seed: V.seeds.agent })],
      ['import a genesis that is not one: request_invalid', line({ op: 'import', genesis: { ...G, typ: 'rotation' }, seed: V.seeds.agent })],
      ['list, one key', line({ op: 'list' })],
      ['pubkey', line({ op: 'pubkey', did: D })],
      ['pubkey of a DID not held: key_unknown', line({ op: 'pubkey', did: OTHER })],
      ...Object.entries(b).map(([typ, body]) => [`sign ${typ}${typ === 'challenge' ? ' (the challenge vector\'s sig)' : ''}`, sign(body)]),
      ['sign a binding without --allow-payments: policy_typ', sign(V.vectors.binding.body)],
      ['sign an invoice without --allow-payments: policy_typ', sign(V.vectors.invoice.body)],
      ['sign an attestation without --allow-attest: policy_typ', sign({ ...V.vectors.attestation.body, iss: D })],
      ['sign a rotation: policy_rotation', sign(V.vectors.rotation_voluntary.body)],
      ['sign a rotation under another v: policy_rotation', sign({ ...V.vectors.rotation_voluntary.body, v: 'sigelo-msg/0' })],
      ['sign a genesis: policy_typ', sign(G)],
      ['sign a bundle: policy_typ', sign({ v: 'sigelo/0', typ: 'bundle', genesis: G, rotations: [], bindings: [], attestations: [], issuers: [] })],
      ['sign a probe body: policy_typ', sign({ v: 'sigelo-keys/0', typ: 'probe', did: D })],
      ['sign an enrol request: policy_typ', sign({ v: 'sigelo-enrol/1', typ: 'enrol-request', proof: {} })],
      ['sign a challenge under v sigelo/1: policy_typ', sign({ ...b.challenge, v: 'sigelo/1' })],
      ['sign a challenge with an extra field: policy_typ', sign({ ...b.challenge, extra: 1 })],
      ['sign a body that is not an object: policy_typ', sign('sigelo')],
      ...['challenge', 'relay-login', 'invite-answer', 'contact-notice', 'prekeys'].map((typ) => [`sign a${/^[aeiou]/.test(typ) ? 'n' : ''} ${typ} naming a foreign DID: policy_did`, sign(bodies(OTHER)[typ])]),
      ['sign a message from a foreign DID: policy_did', sign({ ...b.message, from: OTHER })],
      ['sign a message naming this DID as to, not from: policy_did', sign({ ...b.message, from: OTHER, to: D })],
      ['sign for a DID not held: key_unknown', sign(bodies(OTHER).challenge, OTHER)],
      ['create, recovery a commitment', line({ op: 'create', recovery: G.recovery })],
      ['create, recovery a key', line({ op: 'create', recovery: 'z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG' })],
      ['create, recovery null', line({ op: 'create', recovery: null })],
      ['create, recovery not a key: request_invalid', line({ op: 'create', recovery: 'sha256:00' })],
      ['rotate to fido2: key_provider_unbuilt (K4)', line({ op: 'rotate', did: D, to: 'fido2' })],
      ['rotate to card: key_provider_unbuilt (K5)', line({ op: 'rotate', did: D, to: 'card' })],
      ['rotate a DID not held: key_unknown', line({ op: 'rotate', did: OTHER, to: 'software' })],
      ['rotate: the rotation, kept pending', line({ op: 'rotate', did: D, to: 'software' })],
      ['rotate again before the write: the same rotation (a torn rotation converges)', line({ op: 'rotate', did: D, to: 'software' })],
      ['sign with the old key while the rotation is pending', sign(b['relay-login'])],
      ['commit naming the old DID: policy_did', line({ op: 'commit', did: D })],
      ['commit a DID not held: key_unknown', line({ op: 'commit', did: OTHER })],
    ];
  } },
  { name: 'after the rotation: the new DID', flags: {}, after: 'the default agent: no payments, no attestations', requests: (prev) => {
    const R = prev.rotation, N = S.did(R.next_genesis), b = bodies(N);
    return [
      ['commit naming the new DID', line({ op: 'commit', did: N })],
      ['commit again: nothing pending, already current', line({ op: 'commit', did: N })],
      ['sign with the old DID now: policy_did (the file is behind)', sign(bodies(D).challenge)],
      ['rotate from the old DID: policy_did (no fork from a stale copy)', line({ op: 'rotate', did: D, to: 'software' })],
      ['sign a challenge for the new DID', sign({ ...b.challenge, did: N }, N)],
      ['a challenge for the new DID sent as the old one: policy_did', sign({ ...b.challenge, did: N })],
      ['rotate the new DID', line({ op: 'rotate', did: N, to: 'software' })],
      ['pubkey naming the pending DID commits it', line({ op: 'pubkey', did: '@PENDING' })],
      ['list', line({ op: 'list' })],
      ['lock', line({ op: 'lock' })],
    ];
  } },
  { name: 'started with --allow-payments --allow-attest 1f916.ai', flags: { allowPayments: true, allowAttest: ['1f916.ai'] }, requests: () => [
    ['import the vector identity', line({ op: 'import', genesis: G, seed: V.seeds.agent })],
    ['import the vector world', line({ op: 'import', genesis: W, seed: V.seeds.world })],
    ['sign the binding vector (its sig_id)', sign(V.vectors.binding.body)],
    ['sign the invoice vector (its sig)', sign(V.vectors.invoice.body)],
    ['sign a binding for a foreign DID: policy_did', sign({ ...V.vectors.binding.body, id: OTHER })],
    ['the world signs the attestation vector, ctx 1f916.ai (its sig)', sign(V.vectors.attestation.body, WD)],
    ['an attestation under another ctx: policy_typ', sign({ ...V.vectors.attestation.body, ctx: 'other.example' }, WD)],
    ['an attestation issued by another DID: policy_did', sign(V.vectors.attestation.body)],
    ['a rotation, even so: policy_rotation', sign(V.vectors.rotation_voluntary.body)],
  ] },
  { name: 'malformed requests', flags: {}, requests: () => [
    ['not JSON: request_invalid', '{"op":"list"'],
    ['a duplicate key: request_invalid', '{"op":"list","op":"lock"}'],
    ['not UTF-8: request_invalid', '{"op":"\xff"}', 'latin1'],
    ['an array: request_invalid', '[]'],
    ['an unknown op: request_invalid', line({ op: 'export', did: D })],
    ['an op inherited from Object: request_invalid', line({ op: 'toString' })],
    ['an extra field: request_invalid', line({ op: 'list', did: D })],
    ['a missing field: request_invalid', line({ op: 'sign', did: D })],
    ['did not a string: request_invalid', line({ op: 'pubkey', did: 7 })],
    ['seed not 64 hex: request_invalid', line({ op: 'import', genesis: G, seed: `${V.seeds.agent.slice(0, 62)}0g` })],
    ['to unknown: request_invalid', line({ op: 'rotate', did: D, to: 'hsm' })],
    ['recovery a number: request_invalid', line({ op: 'create', recovery: 1 })],
  ] },
];

/** Replay the request lines through an agent on `dir`; `@PENDING` stands for the pending rotation's DID. */
function replay(session, requests, dir, rand) {
  const agent = createAgent({ store: dir, plain: true, ...session.flags, rand, now: () => NOW, log: () => {} });
  return requests.map(([name, request, encoding]) => {
    const e = agent.store.entries.find((x) => x.pending);
    const req = request.replace('@PENDING', e ? S.did(e.pending.rotation.next_genesis) : '@PENDING');
    return { name, request: req, ...(encoding && { encoding }), reply: encode(agent.handle(Buffer.from(req, encoding ?? 'utf8'))).trimEnd() };
  });
}
function build() {
  const out = [], kept = {}, rand = fixtureRand();
  for (const s of SESSIONS) {
    const dir = s.after ? kept[s.after].dir : mkdtempSync(join(TMP, 'fx-'));
    const pairs = replay(s, s.requests(kept[s.after]?.state), dir, rand);
    const rot = pairs.find((p) => p.name.startsWith('rotate: the rotation'));
    kept[s.name] = { dir, state: rot && { rotation: JSON.parse(rot.reply).rotation } };
    out.push({ name: s.name, flags: s.flags, ...(s.after && { continues: s.after }), pairs });
  }
  return { v: PROTOCOL, about: 'sigelo-key-agent/0 request and reply lines (KEYS.md), replayed in order per session through one agent with a plain store. A session with "continues" runs on the store the named session left. Randomness: draw n (from 0, counted across the file) is the first bytes of SHA-256("sigelo-key-agent-fixture/0 " + n), 32 for a seed then 16 for a genesis nonce; clock: now (ms). A request is sent as UTF-8 bytes, or in its \"encoding\" (latin1: to carry a byte that is not UTF-8).', now: NOW, sessions: out };
}
{
  const warn = console.warn;
  console.warn = () => {};   // keygen's recovery: null warning (the agent prints it on its stderr)
  const built = build();
  console.warn = warn;
  if (process.argv.includes('--write')) { writeFileSync(FIXTURE, `${JSON.stringify(built, null, 2)}\n`); console.log(`wrote ${FIXTURE}`); }
  const want = existsSync(FIXTURE) ? JSON.parse(readFileSync(FIXTURE, 'utf8')) : { sessions: [] };
  const all = built.sessions.flatMap((s) => s.pairs), fixed = want.sessions.flatMap((s) => s.pairs);
  ok(all.length === fixed.length && fixed.length > 70, `fixture: ${fixed.length} request/reply pairs`, `${all.length} built`);
  for (const [i, p] of all.entries()) ok(fixed[i]?.request === p.request && fixed[i]?.reply === p.reply, `fixture: ${p.name}`, `\n  want ${fixed[i]?.reply}\n  got  ${p.reply}`);
  const reply = (name) => JSON.parse(fixed.find((p) => p.name.startsWith(name))?.reply ?? '{}');
  ok(reply('sign challenge').sig === V.vectors.challenge.sig, 'the challenge signs as its vector, byte for byte');
  ok(reply('sign the binding vector').sig === V.vectors.binding.sig_id && reply('sign the invoice vector').sig === V.vectors.invoice.sig && reply('the world signs the attestation').sig === V.vectors.attestation.sig, 'binding, invoice and attestation sign as their vectors');
  const sigs = fixed.filter((p) => /"sig"/.test(p.reply)).map((p) => [JSON.parse(p.request), JSON.parse(p.reply).sig]);
  ok(sigs.length >= 12 && sigs.every(([q, sig]) => { const key = q.did === WD ? W.key : null; return key ? S.verifySig(key, q.body, sig) : true; }), 'every signature present verifies where its key is known');
  const codes = new Set(fixed.map((p) => JSON.parse(p.reply).code).filter(Boolean));
  for (const c of ['policy_typ', 'policy_did', 'policy_rotation', 'key_unknown', 'key_held', 'key_mismatch', 'key_provider_unbuilt', 'request_invalid']) ok(codes.has(c), `the fixture holds a ${c} refusal`);
  const r1 = reply('rotate: the rotation'), r2 = reply('rotate again before');
  ok(JSON.stringify(r1) === JSON.stringify(r2) && S.verifySig(G.key, r1.rotation.body, r1.rotation.sig) && r1.rotation.next_genesis.recovery === G.recovery, 'a repeated rotate returns the same rotation, signed by the old key, the commitment carried');
  ok(fixed.every((p) => !p.reply.includes(V.seeds.agent) && !p.reply.includes(V.seeds.world)), 'no reply holds a seed');
}

// ── 2. the agent as a process ───────────────────────────────────────────────────────────────
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
let pipes = 0;
/** sigelo-key-agent start on a fresh socket under `dir`, its log in dir/agent.log; ready when it answers. */
function startAgent(dir, extra = []) {
  mkdirSync(dir, { recursive: true });
  const run = join(dir, 'run');
  if (!WIN) mkdirSync(run, { mode: 0o700, recursive: true });
  const sock = WIN ? `\\\\.\\pipe\\sigelo-keyagent-test-${process.pid}-${pipes++}` : join(run, 'agent.sock'), log = join(dir, 'agent.log');
  const proc = spawn(process.execPath, [AGENT, 'start', '--socket', sock, '--store', join(dir, 'store'), '--store-plain', ...extra], { stdio: ['ignore', 'ignore', openSync(log, 'a')] });
  const env = { SIGELO_KEY_AGENT: sock };
  for (let i = 0; i < 200; i++) { try { keyclient.request({ op: 'list' }, env); break; } catch { sleep(50); } }
  return { sock, env, proc, log, stop: () => new Promise((res) => { proc.once('exit', res); proc.kill(); }) };
}
const agentRun = (args, env = {}) => spawnSync(process.execPath, [AGENT, ...args], { env: { ...process.env, ...env }, encoding: 'utf8' });
/** Raw bytes to the socket; resolves with what came back once `lines` replies arrived or it closed. */
const raw = (sock, data, lines = 1) => new Promise((res) => {
  let got = '';
  const s = connect(sock, () => s.write(data)), end = () => { s.destroy(); res(got); };
  s.on('data', (d) => { got += d; if (got.split('\n').length > lines) end(); }); s.on('close', end); s.on('error', end);
});

const A = startAgent(join(TMP, 'a'));
process.on('exit', () => A.proc.kill());
{
  ok(keyclient.request({ op: 'list' }, A.env).keys.length === 0, 'the agent answers on its socket: list');
  const t0 = Date.now();
  ok(code(() => keyclient.request({ op: 'list' }, { SIGELO_KEY_AGENT: join(TMP, 'none', 'agent.sock') })) === 'key_agent_unavailable' && Date.now() - t0 <= 2000, 'no agent at the path: key_agent_unavailable within 2 s', Date.now() - t0);
  if (!WIN) {
    mkdirSync(join(TMP, 'stale'), { mode: 0o700 });
    writeFileSync(join(TMP, 'stale', 'agent.sock'), '');
    const t1 = Date.now();
    ok(code(() => keyclient.request({ op: 'list' }, { SIGELO_KEY_AGENT: join(TMP, 'stale', 'agent.sock') })) === 'key_agent_unavailable' && Date.now() - t1 <= 2000, 'a dead socket file: key_agent_unavailable within 2 s');
    for (const [name, mode] of [['0755', 0o755], ['0770', 0o770], ['0701', 0o701]]) {
      const d = join(TMP, `unsafe-${name}`);
      mkdirSync(d); chmodSync(d, mode);
      const r = agentRun(['start', '--socket', join(d, 'agent.sock'), '--store', join(TMP, `st-${name}`), '--store-plain']);
      ok(r.status === 1 && r.stderr.includes('socket_dir_unsafe') && !existsSync(join(d, 'agent.sock')), `a socket directory of mode ${name}: socket_dir_unsafe, nothing listens`, r.stderr);
    }
    mkdirSync(join(TMP, 'real'), { mode: 0o700 }); symlinkSync(join(TMP, 'real'), join(TMP, 'link'));
    const l = agentRun(['start', '--socket', join(TMP, 'link', 'agent.sock'), '--store', join(TMP, 'st-link'), '--store-plain']);
    ok(l.status === 1 && l.stderr.includes('socket_dir_unsafe'), 'a socket directory that is a symlink: socket_dir_unsafe', l.stderr);
    const st = join(TMP, 'open-store'); mkdirSync(st); chmodSync(st, 0o755);
    const o = agentRun(['start', '--socket', join(TMP, 'real', 'x.sock'), '--store', st, '--store-plain']);
    ok(o.status === 1 && o.stderr.includes('store_dir_unsafe'), 'a store directory open to others: store_dir_unsafe', o.stderr);
    const B = startAgent(join(TMP, 'fresh-agent'), []); await B.stop();
    ok(!existsSync(B.sock), 'a stopped agent removes its socket');
  }
  const twice = agentRun(['start', '--socket', A.sock, '--store', join(TMP, 'a', 'store'), '--store-plain']);
  ok(twice.status === 1 && twice.stderr.includes('key_agent_running'), 'a second agent on a live socket: key_agent_running, the first keeps it', twice.stderr);
  ok(keyclient.request({ op: 'list' }, A.env).ok, 'the first agent still answers');
  const big = await raw(A.sock, `{"op":"list","x":"${'a'.repeat(MAX_LINE)}"}\n{"op":"list"}\n`, 2);
  ok(JSON.parse(big.split('\n')[0] || '{}').code === 'request_too_large' && big.split('\n').filter(Boolean).length === 1, 'a line over 2 MiB: request_too_large, nothing after it answered (the connection ends)', big.slice(0, 200));
  const mib = { v: 'sigelo-msg/0', typ: 'message', from: OTHER, to: D, pair: PAIR, epoch: '11'.repeat(16), n: 0, iat: 1, label: 'x', content: { text: 'm'.repeat(1 << 20) } };
  ok(code(() => keyclient.request({ op: 'sign', did: OTHER, body: mib }, A.env)) === 'key_unknown', 'a 1 MiB message body fits a request (refused here only for its DID)');
  const two = await raw(A.sock, '{"op":"list"}\n{"op":"lock"}\n', 2);
  ok(two.split('\n').filter(Boolean).length === 2, 'two requests on one connection: two replies');
  ok(code(() => keyclient.request({ op: 'list', x: 1 }, A.env)) === 'request_invalid', 'a refusal reaches the client by its code');
  // The default store is keychain-wrapped (§4.4), here through an in-memory store (the host's real one is never written).
  const items = new Map(), missing = () => { throw Object.assign(new Error('keychain_missing: none'), { check: 'keychain_missing' }); };
  keychain.inject({ store: 'secret-service', read: (a) => Uint8Array.from(items.get(a) ?? missing()), write: (a, k) => { items.set(a, Buffer.from(k)); }, remove: (a) => { items.delete(a); } });
  const kdir = join(TMP, 'kc-store'), kc = createAgent({ store: kdir, log: () => {} });
  const made = JSON.parse(encode(kc.handle(Buffer.from(line({ op: 'create', recovery: G.recovery })))));
  const imp = JSON.parse(encode(kc.handle(Buffer.from(line({ op: 'import', genesis: G, seed: V.seeds.agent })))));
  const signed = JSON.parse(encode(kc.handle(Buffer.from(line({ op: 'sign', did: D, body: { v: 'sigelo/0', typ: 'challenge', did: D, ctx: 'k3.test', nonce: 'zK3aCTZHfuBYaDyoFv5VS' } })))));
  const files = readdirSync(kdir).map((f) => readFileSync(join(kdir, f), 'utf8'));
  ok(made.ok && imp.ok && signed.ok && files.length === 2 && items.size === 2 && files.every((f) => !f.includes(V.seeds.agent) && JSON.parse(f).secret.provider === 'keychain'),
    'the default (keychain) store: create and import wrapped, the imported key signs, never a plain seed on disk', `${made.code} ${imp.code} ${signed.code}`);
  keychain.inject();
  if (!WIN) {
    mkdirSync(join(TMP, 'nokc'), { mode: 0o700 });
    const n = agentRun(['start', '--socket', join(TMP, 'nokc', 'agent.sock'), '--store', join(TMP, 'st-nokc')], { PATH: join(TMP, 'no-such-bin') });
    ok(n.status === 1 && n.stderr.includes('keychain_unavailable') && n.stderr.includes('--store-plain') && !existsSync(join(TMP, 'nokc', 'agent.sock')), 'no OS keychain answers and no --store-plain: keychain_unavailable, nothing listens', n.stderr);
  }
}

// ── 3. the sidecar through the agent ────────────────────────────────────────────────────────
const HOME = join(TMP, 'home');
mkdirSync(HOME, { recursive: true });
const cli = (file, env, ...args) => spawnSync(process.execPath, [CLI, ...args], { env: { PATH: process.env.PATH, HOME, SIGELO_IDENTITY: file, ...env }, encoding: 'utf8' });
const json = (r) => { try { return JSON.parse(r.stdout); } catch { return {}; } };
const load = (f) => JSON.parse(readFileSync(f, 'utf8'));
const challengeFor = (d, nonce = 'zK3aCTZHfuBYaDyoFv5VS') => JSON.stringify({ v: 'sigelo/0', typ: 'challenge', did: d, ctx: 'k3.test', nonce });
{
  const f = join(HOME, 'made.json');
  const r = cli(f, { ...A.env, SIGELO_KEY_PROVIDER: 'agent' }, 'init', '--recovery', 'z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG');
  const s = existsSync(f) ? load(f) : {}, d = s.genesis ? S.did(s.genesis) : '';
  ok(r.status === 0 && s.provider === 'agent' && JSON.stringify(s.secret) === '{"provider":"agent"}', 'init with SIGELO_KEY_PROVIDER=agent: the file says {"provider":"agent"} and holds no key', r.stderr);
  const sc = cli(f, A.env, 'sign-challenge', challengeFor(d));
  ok(sc.status === 0 && S.verifySig(s.genesis.key, JSON.parse(challengeFor(d)), json(sc).sig), 'sign-challenge through the agent: a signature by the genesis key', sc.stderr);
  const st = cli(f, A.env, 'keys', 'status');
  ok(st.status === 0 && json(st).signs === true && json(st).provider === 'agent' && json(st).key_agent === A.sock, 'keys status: agent, signs', st.stdout + st.stderr);
  const other = cli(f, A.env, 'sign-challenge', challengeFor('did:sigelo:zF5FYbH5zNLX5pfd7DZUjPirXeAFzLVxrdFyCrnexdpBG'));
  ok(other.status === 1 && other.stderr.includes('not this identity'), 'a challenge for another DID: refused before the agent is asked', other.stderr);

  // keys to-agent: the vector identity's plain file; afterwards it signs the vector byte for byte.
  const p = join(HOME, 'plain.json');
  writeFileSync(p, `${JSON.stringify({ v: 'sigelo/0', secret: V.seeds.agent, genesis: G, rotations: [], attestations: [], issuers: [] }, null, 2)}\n`, { mode: 0o600 });
  const mm = cli(p, A.env, 'sign-challenge', JSON.stringify(V.vectors.challenge.body));
  ok(mm.status === 1 && mm.stderr.includes('key_agent_mismatch'), 'SIGELO_KEY_AGENT with the key still in the file: key_agent_mismatch', mm.stderr);
  const ta = cli(p, A.env, 'keys', 'to-agent');
  const after = readFileSync(p, 'utf8');
  ok(ta.status === 0 && json(ta).did === D && !after.includes(V.seeds.agent) && load(p).provider === 'agent' && JSON.stringify(load(p).secret) === '{"provider":"agent"}', 'keys to-agent: the key moves, the file holds {"provider":"agent"} and no hex', ta.stderr);
  const vs = cli(p, A.env, 'sign-challenge', JSON.stringify(V.vectors.challenge.body));
  ok(vs.status === 0 && json(vs).sig === V.vectors.challenge.sig, 'then sign-challenge through the agent: the vector, byte for byte', vs.stderr);
  const again = cli(p, A.env, 'keys', 'to-agent');
  ok(again.status === 1 && again.stderr.includes('key_provider_required') && readFileSync(p, 'utf8') === after, 'keys to-agent again: refused, the file unchanged', again.stderr);
  writeFileSync(join(HOME, 'retry.json'), `${JSON.stringify({ v: 'sigelo/0', secret: V.seeds.agent, genesis: G, rotations: [], attestations: [], issuers: [] }, null, 2)}\n`, { mode: 0o600 });
  const retry = cli(join(HOME, 'retry.json'), A.env, 'keys', 'to-agent');
  ok(retry.status === 0 && !readFileSync(join(HOME, 'retry.json'), 'utf8').includes(V.seeds.agent), 'keys to-agent of a key the agent holds already (a retry): the file still moves', retry.stderr);
  const none = cli(p, { SIGELO_KEY_AGENT: join(TMP, 'none', 'agent.sock') }, 'sign-challenge', JSON.stringify(V.vectors.challenge.body));
  ok(none.status === 1 && none.stderr.includes('key_agent_unavailable'), 'the agent absent: sign-challenge exits 1, key_agent_unavailable', none.stderr);

  // rotate through the agent, then a torn rotation and a stale copy.
  const rot = cli(f, A.env, 'rotate'), s1 = load(f), d1 = S.did(s1.rotations.at(-1)?.next_genesis ?? s1.genesis);
  ok(rot.status === 0 && s1.rotations.length === 1 && JSON.stringify(s1.secret) === '{"provider":"agent"}' && S.verify({ v: 'sigelo/0', typ: 'bundle', genesis: s1.genesis, rotations: s1.rotations, bindings: [], attestations: [], issuers: [] }, Math.floor(Date.now() / 1000) + 5).did === d1, 'rotate through the agent: one rotation, the chain verifies, the file still holds no key', rot.stderr);
  ok(cli(f, A.env, 'sign-challenge', challengeFor(d1)).status === 0 && cli(f, A.env, 'keys', 'status').stdout.includes('"signs": true'), 'the new DID signs');
  const listed = keyclient.request({ op: 'list' }, A.env).keys;
  ok(listed.some((k) => k.did === d1) && !listed.some((k) => k.did === d) && listed.every((k) => k.form === 'plain' && !('seed' in k)), 'list: the new DID, the old one gone, no key material');

  const copy = join(HOME, 'copy.json');
  writeFileSync(copy, readFileSync(f));
  const killer = join(TMP, 'killed-caller.mjs');
  writeFileSync(killer, `const { request } = await import(${JSON.stringify(new URL('../adapters/moadim/sigelo-agent-keyclient.ts', import.meta.url).href)});
const r = request({ op: 'rotate', did: process.argv[2], to: 'software' });
process.stdout.write(JSON.stringify(r.rotation));
process.kill(process.pid, 'SIGKILL');   // between rotate and its write
`);
  const k = spawnSync(process.execPath, [killer, d1], { env: { ...process.env, ...A.env }, encoding: 'utf8' });
  const torn = (() => { try { return JSON.parse(k.stdout); } catch { return null; } })();
  ok((k.signal === 'SIGKILL' || (WIN && k.status !== 0)) && torn?.body?.id === d1 && load(f).rotations.length === 1, 'a caller killed between rotate and its write: the file unchanged', k.stderr);
  ok(cli(f, A.env, 'sign-challenge', challengeFor(d1)).status === 0, 'the torn rotation leaves the old key working');
  const rr = cli(f, A.env, 'rotate'), s2 = load(f), d2 = S.did(s2.rotations.at(-1).next_genesis);
  ok(rr.status === 0 && s2.rotations.length === 2 && JSON.stringify(s2.rotations[1]) === JSON.stringify(torn), 'the next rotate converges: it writes the rotation the killed caller got', rr.stderr);
  ok(cli(f, A.env, 'sign-challenge', challengeFor(d2)).status === 0, 'and the new key signs');
  const stale = cli(copy, A.env, 'rotate');
  ok(stale.status === 1 && stale.stderr.includes('policy_did') && load(copy).rotations.length === 1, 'a stale copy rotating the old DID: policy_did, no fork through the agent', stale.stderr);
  const st2 = cli(copy, A.env, 'sign-challenge', challengeFor(d1));
  ok(st2.status === 1 && st2.stderr.includes('policy_did'), 'nor does the stale copy sign under the old DID', st2.stderr);

  const ls = agentRun(['list'], A.env), lk = agentRun(['lock'], A.env);
  ok(ls.status === 0 && JSON.parse(ls.stdout).keys.length >= 2 && lk.status === 0 && JSON.parse(lk.stdout).ok === true, 'sigelo-key-agent list and lock ask the running agent', ls.stderr + lk.stderr);
  ok(cli(f, A.env, 'sign-challenge', challengeFor(d2)).status === 0, 'a plain store signs again after lock');
  const log = readFileSync(A.log, 'utf8');
  ok(/^sigelo-key-agent: sign did:sigelo:z\S+ challenge ok$/m.test(log) && /^sigelo-key-agent: rotate did:sigelo:z\S+ - ok$/m.test(log), 'the log: one line per request, op, DID, typ, outcome');
  ok(![V.seeds.agent, 'zK3aCTZHfuBYaDyoFv5VS', 'k3.test', V.vectors.challenge.body.nonce].some((x) => log.includes(x)), 'the log holds no key and no body');
}

// ── 4. install-unit ─────────────────────────────────────────────────────────────────────────
{
  const f = { rest: ['--allow-payments', '--idle', '600'] };
  const lu = unit('linux', f, { XDG_RUNTIME_DIR: '/run/user/1000', XDG_CONFIG_HOME: '/cfg' }), mu = unit('darwin', f, { TMPDIR: '/var/folders/x/T/' });
  ok(lu.path === '/cfg/systemd/user/sigelo-key-agent.service' && lu.text.includes(`ExecStart="${process.execPath.replace(/\\/g, '\\\\')}" "${AGENT.replace(/\\/g, '\\\\')}" "start" "--socket" "/run/user/1000/sigelo/agent.sock" "--allow-payments" "--idle" "600"`) && /UMask=0077/.test(lu.text) && !lu.text.includes('@ARGS@'), 'install-unit, Linux: a user unit starting the agent on the default socket', lu.text);
  ok(mu.path.endsWith('Library/LaunchAgents/io.sigelo.key-agent.plist') && mu.text.includes('<string>/var/folders/x/T/sigelo/agent.sock</string>') && mu.text.includes('<string>--allow-payments</string>') && !mu.text.includes('@ARGS@'), 'install-unit, macOS: a LaunchAgent with the same arguments', mu.text);
  ok(/on Windows start the agent by hand/.test(code(() => unit('win32', f)) ?? ''), 'install-unit on Windows: refused, by hand');
  if (process.platform === 'linux') {
    const cfg = join(TMP, 'cfg'), env = { XDG_CONFIG_HOME: cfg, XDG_RUNTIME_DIR: join(TMP, 'rt') };
    const w = agentRun(['install-unit'], env), again = agentRun(['install-unit'], env);
    ok(w.status === 0 && existsSync(join(cfg, 'systemd', 'user', 'sigelo-key-agent.service')) && again.status === 1 && again.stderr.includes('exists'), 'install-unit writes the unit once, never over one', w.stderr + again.stderr);
  }
}
await A.stop();

// ── 5. the contact and MCP suites with the key in the agent ──────────────────────────────────
const suite = (name, args, cwd, pass) => new Promise((res) => {
  const c = spawn(process.execPath, args, { cwd, env: { ...process.env, SIGELO_TEST_KEY_AGENT: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; });
  c.on('close', (status) => { const last = out.trim().split('\n').filter((l) => pass.test(l)).at(-1); ok(status === 0 && Boolean(last), `${name} with SIGELO_TEST_KEY_AGENT=1: ${last ?? 'FAILED'}`, out.split('\n').filter((l) => /FAIL|Error/.test(l)).slice(0, 8).join('\n')); res(); });
});
if (process.argv.includes('--quick')) console.log('SKIP the contact and MCP suites in agent mode (--quick)');
else {
  await suite('adapters/moadim test-contact.ts', ['test-contact.ts'], join(ROOT, 'adapters', 'moadim'), /^ALL PASS test-contact\.ts \(\d+ ok\)$/);
  await suite('integrations/mcp test.mjs', ['test.mjs'], join(ROOT, 'integrations', 'mcp'), /^ALL PASS/);
}

rmSync(TMP, { recursive: true, force: true });
console.log(fails ? `\nFAIL keyagent: ${fails} of ${passes + fails} failed` : `\nALL PASS keyagent (${passes} ok)`);
process.exit(fails ? 1 : 0);
