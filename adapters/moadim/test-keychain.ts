// SPDX-License-Identifier: MIT
// Key providers, milestone K2 (design/key-providers.md §3, §7): the keychain-wrapped identity file.
// The wrap vector (fixtures/wrap-v1.json) and RFC 8439's own AEAD vector; a round trip, refusals
// by name, a rotation and `keys wrap`/`unwrap --plain` through a store emulated behind the real
// macOS, Secret Service and DPAPI adapters (a spawn spy that also proves no secret reaches an
// argv or an environment); no store: no plain write; the default form of a new identity; the
// pre-K1 CLI (0.1.7) on a wrapped file. SIGELO_KEYCHAIN_LIVE=1 adds this machine's real store
// (KEYCHAIN.md); without it nothing here touches one.
//   node test-keychain.ts
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { did, verifySig, VERSION, type Genesis } from 'sigelo';
import * as keys from './sigelo-agent-keys.ts';
import { answers, inject, seal, systemKeychain, unwrap, wrap, type Keychain, type Run, type WrappedSecret } from './sigelo-agent-keychain.ts';
import { load, save, type Store } from './sigelo-agent.ts';
import { CLI, ROOT, done, ok, tmpHome } from './test-helpers.ts';

const HOME = tmpHome('keychain');
const V = JSON.parse(readFileSync(join(ROOT, 'test-vectors.json'), 'utf8')) as {
  seeds: Record<string, string>; vectors: { genesis: { doc: Genesis }; challenge: { body: Record<string, unknown>; sig: string } };
};
const F = JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', 'wrap-v1.json'), 'utf8')) as { file_key: string; nonce: string; seed: string; head_key: string; aad: string; ct: string; secret: WrappedSecret };
const vec = V.vectors.challenge, SEED = V.seeds['agent']!, COMMIT = V.vectors.genesis.doc.recovery!;
const plain = (): Store => ({ v: VERSION, secret: SEED, genesis: V.vectors.genesis.doc, rotations: [], attestations: [], issuers: [] });
const code = (fn: () => unknown): string | null => { try { fn(); return null; } catch (e) { return (e as { check?: string }).check ?? (e as Error).message; } };
const file = (name: string, s: object): string => { const p = join(HOME, name); writeFileSync(p, JSON.stringify(s, null, 2) + '\n', { mode: 0o600 }); return p; };
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const challenge = (s: Store) => ({ v: 'sigelo/0', typ: 'challenge', did: did(s.rotations.at(-1)?.next_genesis ?? s.genesis), ctx: 'k2.test', nonce: 'zVtK2aCTZHfuBYaDyoFv5VS' });

/** secret-tool, security and powershell as a store would answer them; every call recorded. */
function emulator() {
  const items = new Map<string, string>(), calls: { cmd: string; args: string[]; env: Record<string, string | undefined>; input: string; stdout: string }[] = [];
  const st = { items, calls, down: false, writes: 0, run: null as unknown as Run };
  const r = (status: number | null, stdout = '', stderr = '') => ({ status, stdout, stderr });
  const answer: Run = (cmd, args, input) => {
    if (st.down) return { ...r(null), error: Object.assign(new Error(`spawnSync ${cmd} ENOENT`), { code: 'ENOENT' }) };
    const val = (k: string) => args[args.indexOf(k) + 1]!;
    if (cmd === 'secret-tool') {
      const a = val('account');
      if (args[0] === 'store') { st.writes++; items.set(a, input); return r(0); }
      if (args[0] === 'lookup') return items.has(a) ? r(0, items.get(a)) : r(1);
      if (args[0] === 'clear') return r(items.delete(a) ? 0 : 1);
    }
    if (cmd === 'security') {
      const m = /^add-generic-password -U -s sigelo -a (\S+) -T "" -w (\S+)\n$/.exec(input);
      if (args[0] === '-i') { if (!m) return r(1, '', 'security: parse error'); st.writes++; items.set(m[1]!, m[2]!); return r(0, 'security> '); }
      const nf = r(44, '', 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.');
      if (args[0] === 'find-generic-password') return items.has(val('-a')) ? r(0, `${items.get(val('-a'))}\n`) : nf;
      if (args[0] === 'delete-generic-password') return items.delete(val('-a')) ? r(0) : nf;
    }
    if (cmd === 'powershell') {
      const script = Buffer.from(val('-EncodedCommand'), 'base64').toString('utf16le');
      if (script.includes('-AsPlainText')) { st.writes++; return r(0, Buffer.from(`dpapi:${input}`).toString('hex')); }
      if (!input) return r(3);
      const t = Buffer.from(input, 'hex').toString();
      return t.startsWith('dpapi:') ? r(0, t.slice(6)) : r(4, '', 'Key not valid for use in specified state.');
    }
    return r(127, '', `${cmd}: not emulated`);
  };
  st.run = (cmd, args, input, env) => { const out = answer(cmd, args, input, env); calls.push({ cmd, args: [...args], env: { ...env }, input, stdout: out.stdout }); return out; };
  return st;
}
const ENV = { PATH: '/usr/bin', HOME: '/var/empty' };

// ── the vectors ───────────────────────────────────────────────────────────────────────────
{
  const g = V.vectors.genesis.doc;
  ok('wrap-v1: seed, head key and account are the test vectors\'', F.seed === SEED && F.head_key === g.key && F.secret.account === did(g) && F.aad === `sigelo-wrap/1\n${g.key}`);
  ok('wrap-v1: seal(file_key, nonce, seed, aad) gives ct exactly', seal(Buffer.from(F.file_key, 'hex'), Buffer.from(F.nonce, 'hex'), Buffer.from(F.seed, 'hex'), Buffer.from(F.aad)).toString('base64url') === F.ct && F.secret.ct === F.ct);
  // RFC 8439 §2.8.2: the same function is the standard AEAD, so any implementation reproduces ct.
  const rfc = seal(Buffer.from(F.file_key, 'hex'), Buffer.from('070000004041424344454647', 'hex'),
    Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.'), Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex'));
  ok('seal is RFC 8439 §2.8.2: ciphertext and tag', rfc.subarray(0, 8).toString('hex') === 'd31a8d34648e60db' && rfc.subarray(-16).toString('hex') === '1ae10b594f09e26a7e902ecbd0600691');
  const kc: Keychain = { store: 'secret-service', read: () => Buffer.from(F.file_key, 'hex'), write: () => undefined, remove: () => {} };
  const s = plain(); s.secret = F.secret;
  ok('wrap-v1: unwrap gives the seed back', hex(unwrap(s, kc)) === SEED);
}

// ── round trip through an emulated Secret Service ─────────────────────────────────────────
const emu = emulator();
inject(systemKeychain(ENV, emu.run, 'linux'));
{
  const p = join(HOME, 'kc.json'), s = keys.init(p, COMMIT, 'keychain'), w = load(p).secret as WrappedSecret;
  ok('init keychain: secret is sigelo-wrap/1, store secret-service, account = DID', load(p).provider === 'keychain' && w.provider === 'keychain' && w.v === 'sigelo-wrap/1' && w.store === 'secret-service' && w.account === did(s.genesis));
  ok('init keychain: one store write; the file key is in the store, not the file', emu.writes === 1 && emu.items.has(did(s.genesis)) && !readFileSync(p, 'utf8').includes(emu.items.get(did(s.genesis))!));
  const body = challenge(s), sig = keys.signer(p, load(p)).sign(body);
  ok('a keychain identity signs; the signature verifies under its genesis key', verifySig(s.genesis.key, body, sig));
  const st = keys.main(['status'], p, load(p)) as { provider: string; signs: boolean };
  ok('keys status: keychain, signs', st.provider === 'keychain' && st.signs === true);

  const tamper = (f: (w: WrappedSecret) => void): Store => { const t = load(p); f(t.secret as WrappedSecret); return t; };
  ok('tampered ct: wrap_auth', code(() => keys.signer(p, tamper((w) => { w.ct = (w.ct[0] === 'A' ? 'B' : 'A') + w.ct.slice(1); })).sign(body)) === 'wrap_auth');
  ok('tampered nonce: wrap_auth', code(() => unwrap(tamper((w) => { w.nonce = (w.nonce[0] === 'A' ? 'B' : 'A') + w.nonce.slice(1); }))) === 'wrap_auth');
  const q = join(HOME, 'kc2.json'), other = keys.init(q, COMMIT, 'keychain');
  ok('another account\'s item: wrap_auth', code(() => unwrap(tamper((w) => { w.account = did(other.genesis); }))) === 'wrap_auth');
  ok('another identity\'s ct (another head key): wrap_auth', code(() => unwrap(tamper((w) => { w.ct = (load(q).secret as WrappedSecret).ct; }))) === 'wrap_auth');
  ok('a file wrapped by the macOS store, read here: keychain_missing', code(() => unwrap(tamper((w) => { w.store = 'macos'; }))) === 'keychain_missing');
  ok('an unknown wrap version: key_provider_unknown', code(() => unwrap(tamper((w) => { (w as { v: string }).v = 'sigelo-wrap/2'; }))) === 'key_provider_unknown');
  const item = emu.items.get(did(other.genesis))!;
  emu.items.delete(did(other.genesis));
  ok('no item for the account: keychain_missing', code(() => keys.signer(q, load(q)).sign(challenge(other))) === 'keychain_missing');
  emu.items.set(did(other.genesis), item);
  emu.down = true;
  ok('the store does not answer: keychain_unavailable', code(() => keys.signer(q, load(q)).sign(challenge(other))) === 'keychain_unavailable');
  emu.down = false;

  // ── a rotation re-seals in the one write that appends it ──
  const before = load(p).secret as WrappedSecret, writes = emu.writes, r = keys.rotate(p, load(p), 1790000000);
  save(p, r);
  const after = load(p), aw = after.secret as WrappedSecret, nb = challenge(after);
  ok('rotate: the rotation and the re-sealed seed in one save', after.rotations.length === 1 && aw.ct !== before.ct && aw.nonce !== before.nonce && aw.account === before.account && after.provider === 'keychain');
  ok('rotate: the same file key, no store write', emu.writes === writes);
  ok('rotate: the new key signs for the new DID', verifySig(after.rotations[0]!.next_genesis.key, nb, keys.signer(p, after).sign(nb)) && nb.did !== did(after.genesis));
}

// ── keys wrap, keys unwrap --plain ────────────────────────────────────────────────────────
{
  const p = file('plain.json', plain()), seed = Buffer.from(SEED, 'hex');
  const out = keys.main(['wrap'], p, load(p)) as { provider: string; store: string }, text = readFileSync(p, 'utf8');
  ok('keys wrap: provider keychain, store named', out.provider === 'keychain' && out.store === 'secret-service' && load(p).provider === 'keychain');
  ok('keys wrap: the old hex is nowhere in the file (nor its base64)', ![SEED, SEED.toUpperCase(), seed.toString('base64'), seed.toString('base64url')].some((x) => text.includes(x)));
  ok('keys wrap: the challenge vector, byte for byte', keys.signer(p, load(p)).sign(vec.body) === vec.sig);
  const wrapped = readFileSync(p);
  ok('keys wrap on a wrapped file: key_provider_required, unchanged', code(() => keys.main(['wrap'], p, load(p))) === 'key_provider_required' && readFileSync(p).equals(wrapped));
  ok('keys unwrap without --plain: refused, unchanged', code(() => keys.main(['unwrap'], p, load(p))) === 'usage' && readFileSync(p).equals(wrapped));
  const back = keys.main(['unwrap', '--plain'], p, load(p)) as { provider: string; item_left?: string };
  ok('keys unwrap --plain: the seed back as hex, provider file, the item removed', load(p).secret === SEED && back.provider === 'file' && !back.item_left && !emu.items.has(did(plain().genesis)));
  ok('keys unwrap --plain on a plain file: key_provider_required', code(() => keys.main(['unwrap', '--plain'], p, load(p))) === 'key_provider_required');
  // Two copies of one identity (or an item unwrap could not remove): wrap reuses the item, never overwrites it.
  const twinA = file('twin-a.json', plain()), twinB = file('twin-b.json', plain()), acc = did(plain().genesis);
  keys.main(['wrap'], twinA, load(twinA));
  const item = emu.items.get(acc), w0 = emu.writes;
  keys.main(['wrap'], twinB, load(twinB));
  ok('keys wrap where the store holds the account already: the item reused, not overwritten; both copies sign', emu.writes === w0 && emu.items.get(acc) === item
    && keys.signer(twinA, load(twinA)).sign(vec.body) === vec.sig && keys.signer(twinB, load(twinB)).sign(vec.body) === vec.sig);
  emu.items.delete(acc);
  emu.down = true;
  const before = readFileSync(p);
  ok('keys wrap with no store: keychain_unavailable, file unchanged', code(() => keys.main(['wrap'], p, load(p))) === 'keychain_unavailable' && readFileSync(p).equals(before));
  const f = join(HOME, 'never.json');
  ok('init keychain with no store: keychain_unavailable, nothing written', code(() => keys.init(f, COMMIT, 'keychain')) === 'keychain_unavailable' && !existsSync(f));
  // init's default (plan §8.3): keychain where a store answers, else a plain file and one warning line.
  const said: string[] = [], err = console.error;
  console.error = (m: string) => { said.push(String(m)); };
  const d = join(HOME, 'default-file.json'), ds = keys.init(d, COMMIT);
  console.error = err;
  ok('default init, no store: "provider": "file", hex, one warning', ds.provider === 'file' && /^[0-9a-f]{64}$/.test(load(d).secret as string) && said.length === 1 && said[0]!.includes('no OS keychain answers'), said.join('|'));
  emu.down = false;
  const k = join(HOME, 'default-kc.json');
  ok('default init, a store answers: keychain', keys.init(k, COMMIT).provider === 'keychain' && (load(k).secret as WrappedSecret).v === 'sigelo-wrap/1');
}
inject();

// ── the three adapters behind the spawn spy ───────────────────────────────────────────────
for (const [platform, store, tool] of [['darwin', 'macos', 'security'], ['linux', 'secret-service', 'secret-tool'], ['win32', 'dpapi', 'powershell']] as const) {
  const e = emulator(), kc = systemKeychain(ENV, e.run, platform), s = plain();
  const w = wrap(Buffer.from(SEED, 'hex'), s, kc);
  s.secret = w;
  ok(`${store}: wrap and unwrap through ${tool}`, kc.store === store && w.store === store && hex(unwrap(s, kc)) === SEED && e.calls.every((c) => c.cmd === tool) && (store === 'dpapi') === (w.dpapi !== undefined));
  kc.remove(w.account);
  ok(`${store}: removed, the item is missing`, code(() => unwrap(s, kc)) === (store === 'dpapi' ? null : 'keychain_missing'));
  if (store === 'dpapi') { delete w.dpapi; ok('dpapi: no blob, keychain_missing', code(() => unwrap(s, kc)) === 'keychain_missing'); }
  const secrets = [SEED, Buffer.from(SEED, 'hex').toString('base64url'), ...e.calls.flatMap((c) => [c.input, c.stdout].map((x) => x.trim()).filter((x) => x.length >= 32 && !x.startsWith('security'))), w.dpapi ?? ''].filter(Boolean);
  ok(`${store}: no secret in any argv or environment (${e.calls.length} calls)`, secrets.length > 1 && e.calls.every((c) => !secrets.some((x) => c.args.some((a) => a.includes(x)) || Object.values(c.env).some((v) => v?.includes(x)))));
  ok(`${store}: the environment passed is the caller's`, e.calls.every((c) => JSON.stringify(c.env) === JSON.stringify(ENV)));
  e.down = true;
  ok(`${store}: the tool absent: keychain_unavailable; answers() false`, code(() => unwrap(s, kc)) === 'keychain_unavailable' && !answers(kc));
  e.down = false;
  ok(`${store}: a store with no item answers`, answers(kc));
}
{
  const kc = systemKeychain(ENV, () => ({ status: 1, stdout: '', stderr: 'Cannot autolaunch D-Bus without X11 $DISPLAY' }), 'linux');
  ok('secret-tool with no D-Bus session: keychain_unavailable, its reason named', code(() => kc.read('did:x')) === 'keychain_unavailable' && !answers(kc) && (() => { try { kc.read('did:x'); } catch (e) { return (e as Error).message.includes('D-Bus'); } return false; })());
  ok('an account that is not a DID never reaches argv', code(() => systemKeychain(ENV, () => { throw new Error('spawned'); }, 'darwin').read('x; rm -rf /')) === 'wrap_auth');
}

// ── this machine with no store: the CLI (Linux; a D-Bus-less environment) ─────────────────
if (process.platform !== 'linux') console.log(`SKIP no-store CLI checks: Linux only (here ${process.platform})`);
else {
  const cli = (p: string, env: Record<string, string>, ...args: string[]) => spawnSync('node', [CLI, ...args], { env: { PATH: process.env['PATH'] ?? '', HOME, SIGELO_IDENTITY: p, DBUS_SESSION_BUS_ADDRESS: 'unix:path=/nonexistent', ...env }, encoding: 'utf8' });
  const p = join(HOME, 'cli-kc.json'), r = cli(p, { SIGELO_KEY_PROVIDER: 'keychain' }, 'init', '--no-recovery');
  ok('CLI init SIGELO_KEY_PROVIDER=keychain, no store: exit 1, keychain_unavailable, nothing written', r.status === 1 && r.stderr.includes('keychain_unavailable') && !existsSync(p), r.stderr);
  const q = join(HOME, 'cli-default.json'), r2 = cli(q, {}, 'init', '--no-recovery');
  ok('CLI init by default, no store: "provider": "file", a warning on stderr', r2.status === 0 && load(q).provider === 'file' && r2.stderr.includes('no OS keychain answers'), r2.stderr);
  const before = readFileSync(q), w = cli(q, {}, 'keys', 'wrap');
  ok('CLI keys wrap, no store: exit 1, keychain_unavailable, file unchanged', w.status === 1 && w.stderr.includes('keychain_unavailable') && readFileSync(q).equals(before), w.stderr);
}

// ── the pre-K1 CLI (sigelo-agent 0.1.7) on a wrapped file: fails closed ───────────────────
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
  const oldCli = (p: string, ...args: string[]) => spawnSync('node', [join(old, 'cli.ts'), ...args], { env: { PATH: process.env['PATH'], HOME, SIGELO_IDENTITY: p }, encoding: 'utf8' });
  const s = plain(); s.provider = 'keychain'; s.secret = F.secret;
  const p = file('old-wrapped.json', s), before = readFileSync(p);
  const w = oldCli(p, 'whoami'), c = oldCli(p, 'sign-challenge', JSON.stringify(vec.body)), r = oldCli(p, 'rotate');
  ok('0.1.7 on a wrapped file: whoami works', w.status === 0 && (JSON.parse(w.stdout) as { did: string }).did === did(V.vectors.genesis.doc), w.stderr);
  ok('0.1.7 on a wrapped file: sign-challenge exits non-zero, signs nothing', c.status !== 0 && c.stdout === '', c.stdout);
  ok('0.1.7 on a wrapped file: rotate exits non-zero, file unchanged', r.status !== 0 && readFileSync(p).equals(before), r.stdout);
}

// ── this machine's real store (opt-in: SIGELO_KEYCHAIN_LIVE=1, KEYCHAIN.md) ──────────────
if (process.env['SIGELO_KEYCHAIN_LIVE'] !== '1') console.log('SKIP live store: SIGELO_KEYCHAIN_LIVE=1 runs wrap, sign and delete against this machine\'s real store (KEYCHAIN.md)');
else {
  const kc = systemKeychain();
  if (!answers(kc)) console.log(`LIVE ${kc.store}: keychain_unavailable (no store answers here)`);
  else {
    inject(kc);
    const p = join(HOME, 'live.json'), s = keys.init(p, COMMIT, 'keychain'), body = challenge(s), sg = keys.signer(p, load(p));
    const t0 = performance.now(), N = 10;
    for (let i = 0; i < N; i++) sg.sign(body);
    const ms = (performance.now() - t0) / N;
    ok(`LIVE ${kc.store}: wrap, sign (${ms.toFixed(0)} ms per signature)`, verifySig(s.genesis.key, body, sg.sign(body)));
    kc.remove(did(s.genesis));
    ok(`LIVE ${kc.store}: item deleted: keychain_missing`, code(() => sg.sign(body)) === 'keychain_missing');
    inject();
  }
}

rmSync(HOME, { recursive: true, force: true });
done(import.meta.filename);
