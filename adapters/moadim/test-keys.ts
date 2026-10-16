// SPDX-License-Identifier: MIT
// Key providers, milestone K1 (design/key-providers.md §2, §7): the provider interface over the
// plain file. A file from the test seeds signs byte for byte as before; "provider": "file" and no
// provider both work; an unknown provider, provider keychain with no store answering, provider
// agent with no agent answering and the core's plain-key path refuse by name and write nothing; a
// derived identity still refuses `rotate`. Then the pre-K1 CLI (0.1.7, from git; SKIP without the
// commit) reads files the new code writes. K2: test-keychain.ts; the key agent itself (K3):
// keyagent/test.mjs. Nothing here touches this machine's real keychain.
//   node test-keys.ts
import { execFileSync, spawnSync } from 'node:child_process';
import { createPublicKey, verify as edVerify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeKey, did, sign, verifySig, VERSION, type Genesis } from 'sigelo';
import * as keys from './sigelo-agent-keys.ts';
import * as keychain from './sigelo-agent-keychain.ts';
import { request } from './sigelo-agent-keyclient.ts';
import { challengeDid, load, save, secretOf, signChallenge, type Store } from './sigelo-agent.ts';
import { CLI, ROOT, done, ok, tmpHome } from './test-helpers.ts';

const HOME = tmpHome('keys');
const V = JSON.parse(readFileSync(join(ROOT, 'test-vectors.json'), 'utf8')) as {
  seeds: Record<string, string>; vectors: { genesis: { doc: Genesis }; challenge: { body: Record<string, unknown>; sig: string } };
};
const vec = V.vectors.challenge;
const COMMIT = V.vectors.genesis.doc.recovery!; // a recovery commitment: no keygen warning
const plain = (extra: object = {}): Store => ({ v: VERSION, ...extra, secret: V.seeds['agent']!, genesis: V.vectors.genesis.doc, rotations: [], attestations: [], issuers: [] } as Store);
/** The refusal's code (`.check`), or null when nothing was thrown. */
const code = (fn: () => unknown): string | null => { try { fn(); return null; } catch (e) { return (e as { check?: string }).check ?? (e as Error).message; } };
const cli = (file: string, env: Record<string, string> = {}, ...args: string[]) =>
  spawnSync('node', [CLI, ...args], { env: { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME, SIGELO_IDENTITY: file, ...env }, encoding: 'utf8' });
const file = (name: string, s: object): string => { const p = join(HOME, name); writeFileSync(p, JSON.stringify(s, null, 2) + '\n', { mode: 0o600 }); return p; };

// ── the plain file: byte for byte ─────────────────────────────────────────────────────────
{
  const p = file('plain.json', plain());
  ok('the vector challenge names the seed identity', challengeDid(plain(), vec.body) === did(V.vectors.genesis.doc));
  ok('signer: the challenge vector, byte for byte', keys.signer(p, plain()).sign(vec.body) === vec.sig);
  ok('core signChallenge (plain path) unchanged', signChallenge(plain(), vec.body).sig === vec.sig);
  ok('keys.signChallenge equals sign(seed, body)', keys.signChallenge(p, plain(), vec.body).sig === sign(secretOf(plain()), vec.body));
  const r = cli(p, {}, 'sign-challenge', JSON.stringify(vec.body));
  ok('CLI sign-challenge on a file without provider: the vector', r.status === 0 && (JSON.parse(r.stdout) as { sig: string }).sig === vec.sig, r.stderr);
  const q = file('provider-file.json', plain({ provider: 'file' }));
  const r2 = cli(q, {}, 'sign-challenge', JSON.stringify(vec.body));
  ok('CLI sign-challenge with "provider": "file": the vector', r2.status === 0 && (JSON.parse(r2.stdout) as { sig: string }).sig === vec.sig, r2.stderr);
  const st = cli(q, {}, 'keys', 'status');
  ok('keys status: file, signs, no key material', st.status === 0 && /"provider": "file"/.test(st.stdout) && /"signs": true/.test(st.stdout) && !st.stdout.includes(V.seeds['agent']!), st.stdout + st.stderr);
  ok('keys <unknown verb> is usage (exit 2)', cli(q, {}, 'keys', 'frob').status === 2);
  const s = keys.signer(q, plain({ provider: 'file' }));
  ok('Signer carries the head DID and key', s.did === did(V.vectors.genesis.doc) && s.key === V.vectors.genesis.doc.key);
}

// ── signHttp: RFC 9421 bases for Web Bot Auth only (integrations/web-bot-auth) ────────────
{
  const p = file('http.json', plain()), s = keys.signer(p, plain());
  const base = '"@authority": example.com\n"signature-agent": "https://agent.example"\n"@signature-params": ("@authority" "signature-agent");created=1;keyid="k";alg="ed25519";expires=2;tag="web-bot-auth"';
  const pub = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), decodeKey(V.vectors.genesis.doc.key)]), format: 'der', type: 'spki' });
  const sig = s.signHttp(base);
  ok('signHttp: Ed25519 over the base bytes, under the head key', edVerify(null, Buffer.from(base), pub, Buffer.from(sig, 'base64')));
  const r = cli(p, {}, 'sign-http', base);
  ok('CLI sign-http: the same signature, did and key', r.status === 0 && (JSON.parse(r.stdout) as { sig: string }).sig === sig, r.stderr);
  ok('signHttp refuses a sigelo signing input', code(() => s.signHttp(`sigelo\n${JSON.stringify(vec.body)}`)) === 'http_base');
  ok('signHttp refuses a base not tagged web-bot-auth', code(() => s.signHttp(base.replace('web-bot-auth', 'other'))) === 'http_base');
  ok('signHttp refuses non-ASCII and CR', code(() => s.signHttp(base.replace('example.com', 'exämple.com'))) === 'http_base' && code(() => s.signHttp(base.replace('\n', '\r\n'))) === 'http_base');
  const other = plain(); other.secret = V.seeds['world']!;
  ok('signHttp with a seed that is not the head key: key_mismatch', code(() => keys.signer('x', other).signHttp(base)) === 'key_mismatch');
  const agent = plain(); agent.secret = { provider: 'agent' };
  ok('signHttp on an agent key: key_provider_unbuilt, before any request', code(() => keys.signer('x', agent, { SIGELO_KEY_AGENT: '/nonexistent/a.sock' }).signHttp(base)) === 'key_provider_unbuilt');
}

// ── refusals by name, nothing written ─────────────────────────────────────────────────────
{
  const unknown = plain(); unknown.secret = { provider: 'hsm' };
  const p = file('unknown.json', unknown), before = readFileSync(p);
  ok('unknown provider in secret: key_provider_unknown', code(() => keys.signer(p, unknown)) === 'key_provider_unknown');
  ok('unknown top-level provider: key_provider_unknown', code(() => keys.signer(p, plain({ provider: 'hsm' }))) === 'key_provider_unknown');
  ok('a top-level provider disagreeing with the secret: key_provider_unknown', code(() => keys.providerOf(plain({ provider: 'agent' }))) === 'key_provider_unknown');
  for (const verb of [['sign-challenge', JSON.stringify(vec.body)], ['rotate'], ['keys', 'status']]) {
    const r = cli(p, {}, ...verb);
    ok(`CLI ${verb[0]} on an unknown provider: exit 1, by name, file unchanged`, r.status === 1 && r.stderr.includes('key_provider_unknown') && readFileSync(p).equals(before), r.stderr);
  }
  const fresh = join(HOME, 'never.json');
  ok('init with SIGELO_KEY_PROVIDER=hsm: refused, nothing written', code(() => keys.init(fresh, COMMIT, 'hsm')) === 'key_provider_unknown' && !existsSync(fresh));
  const r = cli(fresh, { SIGELO_KEY_PROVIDER: 'hsm' }, 'init', '--no-recovery');
  ok('CLI init with SIGELO_KEY_PROVIDER=hsm: exit 1, nothing written', r.status === 1 && r.stderr.includes('key_provider_unknown') && !existsSync(fresh), r.stderr);
  const other = plain(); other.secret = V.seeds['world']!;
  ok('a seed that is not the head key: key_mismatch', code(() => keys.signer('x', other).sign(vec.body)) === 'key_mismatch');
  ok('SIGELO_KEY_AGENT with a key in the file: key_agent_mismatch', code(() => keys.signer('x', plain(), { SIGELO_KEY_AGENT: '/run/x.sock' })) === 'key_agent_mismatch');
}

// ── no store answering (K2), no agent answering (K3: keyagent/test.mjs runs one) ─────────
{
  const agent = plain(); agent.secret = { provider: 'agent' };
  const NONE = { SIGELO_KEY_AGENT: join(HOME, 'no-agent', 'agent.sock') };
  // An in-memory store to wrap with, then one that does not answer: the real keychain module, never the host's store.
  const items = new Map<string, Buffer>();
  const mem: keychain.Keychain = { store: 'secret-service', read: (a) => Uint8Array.from(items.get(a) ?? keys.fail('keychain_missing', a)), write: (a, k) => { items.set(a, Buffer.from(k)); return undefined; }, remove: (a) => { items.delete(a); } };
  const down: keychain.Keychain = { store: 'secret-service', read: () => keys.fail('keychain_unavailable', 'test: no store'), write: () => keys.fail('keychain_unavailable', 'test: no store'), remove: () => keys.fail('keychain_unavailable', 'test: no store') };
  const wrapped = plain(); wrapped.secret = keychain.wrap(Buffer.from(V.seeds['agent']!, 'hex'), plain(), mem);
  ok('keychain.wrap through a store: sigelo-wrap/1, signs the vector', (wrapped.secret as keychain.WrappedSecret).v === 'sigelo-wrap/1' && (keychain.inject(mem), keys.signer('x', wrapped).sign(vec.body)) === vec.sig);
  keychain.inject(down);
  ok('keychain.answers: false when the store does not answer', keychain.answers(down) === false);
  ok('keychain.wrap, no store: keychain_unavailable', code(() => keychain.wrap(new Uint8Array(32), plain())) === 'keychain_unavailable');
  ok('a keychain file, no store: signs nothing, keychain_unavailable', code(() => keys.signer('x', wrapped).sign(vec.body)) === 'keychain_unavailable');
  ok('a keychain file, no store: does not rotate', code(() => keys.rotate('x', wrapped, 1)) === 'keychain_unavailable' && wrapped.rotations.length === 0);
  const t0 = Date.now();
  ok('keyclient.request, no agent: key_agent_unavailable within 2 s', code(() => request({ op: 'list' }, NONE)) === 'key_agent_unavailable' && Date.now() - t0 <= 2000);
  ok('an agent file, no agent: signs nothing, key_agent_unavailable', code(() => keys.signer('x', agent, NONE).sign(vec.body)) === 'key_agent_unavailable');
  ok('an agent file, no agent: does not rotate', code(() => keys.rotate('x', agent, 1, NONE)) === 'key_agent_unavailable' && agent.rotations.length === 0);
  for (const [prov, want, env] of [['keychain', 'keychain_unavailable', {}], ['agent', 'key_agent_unavailable', NONE]] as const) {
    const f = join(HOME, `init-${prov}.json`);
    ok(`init as ${prov}: ${want}, nothing written`, code(() => keys.init(f, COMMIT, prov, env)) === want && !existsSync(f));
  }
  keychain.inject();
  // The CLI with no store tool on PATH and no session bus: the host's keychain is out of reach.
  const p = file('wrap.json', plain()), before = readFileSync(p), BIN = join(HOME, 'no-bin');
  mkdirSync(BIN, { recursive: true });
  const nokc = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { env: { PATH: BIN, HOME, SIGELO_IDENTITY: p, DBUS_SESSION_BUS_ADDRESS: 'unix:path=/nonexistent', ...NONE }, encoding: 'utf8' });
  for (const [args, want] of [[['wrap'], 'keychain_unavailable'], [['unwrap'], 'usage'], [['unwrap', '--plain'], 'key_provider_required'], [['to-agent'], 'key_agent_unavailable']] as const) {
    const r = nokc('keys', ...args);
    ok(`keys ${args.join(' ')}: refused (${want}), file unchanged`, r.status === 1 && r.stderr.includes(want) && readFileSync(p).equals(before), r.stderr);
  }
  const st = cli(file('agent.json', agent), NONE, 'keys', 'status');
  ok('keys status on an agent file, no agent: provider agent, does not sign, by name', st.status === 0 && /"provider": "agent"/.test(st.stdout) && /"code": "key_agent_unavailable"/.test(st.stdout), st.stdout + st.stderr);
}

// ── the core refuses a key that is not a plain file ───────────────────────────────────────
{
  const wrapped = plain(); wrapped.secret = { provider: 'keychain' };
  ok('secretOf refuses a wrapped secret: key_provider_required', code(() => secretOf(wrapped)) === 'key_provider_required');
  ok('secretOf refuses a hex secret under another provider', code(() => secretOf(plain({ provider: 'keychain' }))) === 'key_provider_required');
  ok('core signChallenge refuses it too', code(() => signChallenge(wrapped, vec.body)) === 'key_provider_required');
}

// ── init and rotate through the provider ──────────────────────────────────────────────────
{
  const p = join(HOME, 'new', 'file.json');
  const r = cli(p, { SIGELO_KEY_PROVIDER: 'file' }, 'init', '--no-recovery');
  const s = r.status === 0 ? load(p) : plain();
  ok('init with SIGELO_KEY_PROVIDER=file: "provider": "file", secret a 64-hex string', r.status === 0 && s.provider === 'file' && /^[0-9a-f]{64}$/.test(s.secret as string), r.stderr);
  const d0 = did(s.genesis), rot = cli(p, {}, 'rotate');
  const after = load(p);
  ok('rotate a "provider": "file" identity: one rotation, still file, new key signs', rot.status === 0 && after.rotations.length === 1 && after.provider === 'file'
    && keys.providerOf(after) === 'file' && after.rotations[0]!.body.id === d0 && verifySig(after.rotations[0]!.next_genesis.key, vec.body, keys.signer(p, after).sign(vec.body)), rot.stderr);
  const derived = Object.assign(plain(), { derived: { path: 'sigelo/v1/identity/ed25519/0', n: 0 } });
  ok('a derived identity refuses keys.rotate', code(() => keys.rotate('x', derived, 1))?.includes('comes from your 25 words') === true && derived.rotations.length === 0);
  const dp = file('derived.json', derived), before = readFileSync(dp), rd = cli(dp, {}, 'rotate');
  ok('CLI rotate on a derived identity: refused, file unchanged', rd.status === 1 && rd.stderr.includes('--rotate-me') && readFileSync(dp).equals(before), rd.stderr);
}

// ── the pre-K1 CLI (sigelo-agent 0.1.7) on files the new code writes ──────────────────────
const PRE_K1 = 'b5d7d9a';
const git = (...a: string[]) => spawnSync('git', ['-C', ROOT, ...a], { encoding: 'utf8' });
if (git('cat-file', '-e', `${PRE_K1}^{commit}`).status !== 0) console.log(`SKIP pre-K1 CLI: commit ${PRE_K1} is not in this checkout`);
else {
  const old = join(HOME, 'old');
  mkdirSync(old);
  for (const f of git('ls-tree', '--name-only', PRE_K1, 'adapters/moadim/').stdout.trim().split('\n').filter((x) => /\.(ts|html|js|css|json)$/.test(x))) {
    writeFileSync(join(old, f.split('/').at(-1)!), execFileSync('git', ['-C', ROOT, 'show', `${PRE_K1}:${f}`]));
  }
  symlinkSync(join(import.meta.dirname, 'node_modules'), join(old, 'node_modules'));
  const oldCli = (p: string, ...args: string[]) => spawnSync('node', [join(old, 'cli.ts'), ...args], { env: { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME, SIGELO_IDENTITY: p }, encoding: 'utf8' });
  const p = join(HOME, 'k1-file.json');
  keys.init(p, COMMIT, 'file');
  const s = load(p), body = { v: 'sigelo/0', typ: 'challenge', did: did(s.genesis), ctx: 'k1.test', nonce: 'zVtK1aCTZHfuBYaDyoFv5VS' };
  const r = oldCli(p, 'sign-challenge', JSON.stringify(body));
  ok('0.1.7 signs with a "provider": "file" file the new code wrote, same signature', r.status === 0 && (JSON.parse(r.stdout) as { sig: string }).sig === keys.signer(p, s).sign(body), r.stderr);
  const a = plain(); a.secret = { provider: 'agent' };
  const ap = file('old-agent.json', a);
  const w = oldCli(ap, 'whoami'), c = oldCli(ap, 'sign-challenge', JSON.stringify(vec.body));
  ok('0.1.7 on {"provider":"agent"}: whoami works', w.status === 0 && (JSON.parse(w.stdout) as { did: string }).did === did(V.vectors.genesis.doc), w.stderr);
  ok('0.1.7 on {"provider":"agent"}: sign-challenge exits non-zero', c.status !== 0 && c.stdout === '', c.stdout);
  save(p, s); // the new code's save keeps the field where 0.1.7 reads it
  ok('the secret stays a top-level 64-hex string', /^[0-9a-f]{64}$/.test((JSON.parse(readFileSync(p, 'utf8')) as { secret: string }).secret));
}

rmSync(HOME, { recursive: true, force: true });
done(import.meta.filename);
