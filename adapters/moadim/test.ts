// SPDX-License-Identifier: MIT
// The full agent-side flow, end to end, in a throwaway HOME: init, whoami, challenge accepted
// and refused, issuer + attestation, bundle, rotate, bundle again — then the emitted bundle is
// re-verified by sigelo's Go reference verifier (go/cmd/sigelo-verify) so the two
// implementations must agree.
//
//   npm test                     (the Go cross-check SKIPs, loudly, when `go` is not on PATH)
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { attest, did, keygen, rotate, sign, verify, verifySig, type Binding, type Genesis, type Rotation } from 'sigelo';
import { agentIdentitySeed, deriveRoot, keeperRoot, newRoot, recoveryCommitment, rootFromMnemonic } from 'sigelo/dist/keys.js';
import { decodeAddress, subaddress } from 'sigelo/dist/monero.js';
import { receive, verifyInvoice } from './sigelo-agent-monero.ts';
import { load, save } from './sigelo-agent.ts';

const HOME = mkdtempSync(join(tmpdir(), 'sigelo-moadim-'));
const CLI = join(import.meta.dirname, 'cli.ts');
const ROOT = join(import.meta.dirname, '..', '..');
const CTX = 'moadim.test';
const now = Math.floor(Date.now() / 1000);
let failures = 0;

const ok = (name: string, cond: boolean, detail = ''): void => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}${cond || !detail ? '' : ` — ${detail}`}`);
  if (!cond) failures++;
};
const run = (...args: string[]): string =>
  execFileSync('node', [CLI, ...args], { env: { PATH: process.env['PATH'], HOME }, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
const fails = (...args: string[]): string => {
  try {
    run(...args);
    return '';
  } catch (e) {
    return String((e as { stderr?: string }).stderr ?? '');
  }
};

// A recovery keypair, generated the way the CLI's own instructions say to generate it: offline,
// and only `key` (the public half) ever crosses to the agent.
const recovery = keygen({ recovery: new Uint8Array(32) });
// A world. It attests about us; its genesis is what makes that checkable by a stranger (§8).
const world = keygen({ recovery: new Uint8Array(32) });

// ── init ──────────────────────────────────────────────────────────────────────────────────
ok('init refuses a silently-null recovery', fails('init').includes('--no-recovery'));
const created = JSON.parse(run('init', '--recovery', recovery.key)) as { did: string; genesis: Genesis };
const path = join(HOME, '.config', 'moadim', 'sigelo.local.json');
ok('identity lands beside machine.local.toml', statSync(path).isFile());
// Windows has no POSIX modes (a file inherits its directory's ACL): these checks run on the others.
const posixModes = process.platform !== 'win32';
if (!posixModes) console.log('SKIP file-mode checks (Windows has no POSIX modes)');
else {
  ok('identity file is 0600', (statSync(path).mode & 0o777) === 0o600, (statSync(path).mode & 0o777).toString(8));
  ok('identity dir is 0700', (statSync(join(HOME, '.config', 'moadim')).mode & 0o777) === 0o700);
}
ok('genesis carries the recovery commitment', created.genesis.recovery?.startsWith('sha256:') === true);
ok('init refuses to overwrite an identity', fails('init', '--no-recovery').includes('refusing to overwrite'));

// ── whoami ────────────────────────────────────────────────────────────────────────────────
const me = JSON.parse(run('whoami')) as { did: string; genesis: Genesis; chain: string[] };
ok('whoami prints the DID of the genesis it prints', me.did === did(me.genesis) && me.did === created.did);

// ── sign-challenge ────────────────────────────────────────────────────────────────────────
const challenge = { v: 'sigelo/0', typ: 'challenge', did: me.did, ctx: CTX, nonce: 'z3vQB7B6MrGQZaxCuFg4oh' };
const signed = JSON.parse(run('sign-challenge', JSON.stringify(challenge))) as { did: string; sig: string };
ok('challenge signature verifies under the genesis key', verifySig(me.genesis.key, challenge, signed.sig));
ok('refuses a challenge naming another DID',
  fails('sign-challenge', JSON.stringify({ ...challenge, did: did(world.genesis) })).includes('not this identity'));
ok('refuses a non-challenge body (a rotation)',
  fails('sign-challenge', JSON.stringify({ v: 'sigelo/0', typ: 'rotation', id: me.did, next: did(world.genesis), iat: now, reason: 'voluntary' }))
    .includes('not "challenge"'));
ok('refuses an attestation body', fails('sign-challenge', JSON.stringify({ typ: 'attestation', did: me.did })).includes('not "challenge"'));

// ── issuer + attestation ──────────────────────────────────────────────────────────────────
const attestation = attest({
  secret: world.secret, iss: world.did, sub: me.did, iat: now - 60, exp: now + 30 * 86400,
  ctx: CTX, admission: 'invite', admission_by: world.did, claims: { runs: 412, standing: 'operator' },
});
ok('add-attestation refuses a malformed body',
  fails('add-attestation', JSON.stringify({ body: { ...attestation.body, admission: 'vibes' }, sig: attestation.sig })).includes('admission'));
ok('add-attestation refuses one about someone else',
  fails('add-attestation', JSON.stringify({ body: { ...attestation.body, sub: world.did }, sig: attestation.sig })).includes('not a DID of this identity'));
run('add-issuer', JSON.stringify(world.genesis));
run('add-attestation', JSON.stringify({ ...attestation, now: now * 1000, now_utc: 'stray' })); // a router's clock beside it: not stored (SPEC §3.1)
// SPEC §3: a file that is not valid UTF-8 is refused whole (fatal decode), as the Go verifier
// refuses it, instead of becoming U+FFFD and failing only one signature later.
{
  const bad = join(HOME, 'bad-utf8.json');
  const bytes = Buffer.from(JSON.stringify(attestation).replace('"operator"', '"@@"'));
  bytes[bytes.indexOf(0x40)] = 0xff; bytes[bytes.indexOf(0x40)] = 0xfe;
  writeFileSync(bad, bytes);
  ok('add-attestation refuses a file with invalid UTF-8, naming it', fails('add-attestation', bad).includes('invalid UTF-8 in document'));
}
// ── forget-issuer: the holder drops a retired issuer (SPEC §5, out-of-band notice) ─────────
{
  const old = keygen({ recovery: new Uint8Array(32) });
  run('add-issuer', JSON.stringify(old.genesis));
  run('add-attestation', JSON.stringify(attest({ secret: old.secret, iss: old.did, sub: me.did, iat: now - 60, exp: now + 86400, ctx: 'retired.test', admission: 'open', claims: {} })));
  const f = JSON.parse(run('forget-issuer', old.did)) as { removed: number; attestations: number; issuers: string[] };
  ok('forget-issuer drops that issuer\'s attestation and genesis, keeps the other', f.removed === 1 && f.attestations === 1 && f.issuers.join() === world.did);
  ok('forget-issuer of an unknown DID removes nothing', (JSON.parse(run('forget-issuer', old.did)) as { removed: number }).removed === 0);
  ok('forget-issuer refuses a malformed DID', fails('forget-issuer', 'did:sigelo:nope').includes('not a did:sigelo'));
}

// ── bundle ────────────────────────────────────────────────────────────────────────────────
type Bundle = { genesis: Genesis; rotations: unknown[]; bindings: Binding[]; attestations: { body: { sub: string } }[]; issuers: Genesis[] };
const first = JSON.parse(run('bundle')) as Bundle;
ok('bundle carries the issuer genesis', first.issuers.length === 1 && did(first.issuers[0]!) === world.did);
ok('bundle carries the attestation, body and sig only', first.attestations.length === 1 && Object.keys(first.attestations[0]!).join() === 'body,sig');

// ── monero: the treasury is VIEW-ONLY here ───────────────────────────────────────────────
// A root derived in-test, exactly as the air-gapped box would (MONERO.md §2); only the
// `agent.treasury` projection of it — view key, public spend key, address — crosses over.
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const S = new Uint8Array(32).fill(0x11);
const d = deriveRoot(S, 'stagenet');
const view = { net: 'stagenet', view_key: hex(d.treasury.a), public_spend_key: hex(d.treasury.B), address: d.treasury.address };

ok('wallet-set refuses a blob carrying a spend key',
  fails('wallet-set', JSON.stringify({ ...view, spend_key: hex(d.treasury.b) })).includes('SPEND key'));
ok('wallet-set refuses the operator/air-gapped spelling too',
  fails('wallet-set', JSON.stringify({ ...view, b: hex(d.treasury.b) })).includes('SPEND key'));
ok('wallet-set refuses an unknown field', fails('wallet-set', JSON.stringify({ ...view, restore_height: '1' })).includes('unknown field'));
ok('wallet-set refuses an address the keys do not produce',
  fails('wallet-set', JSON.stringify({ ...view, address: d.allowance.address })).includes('does not match the keys'));
ok('wallet-set refuses a net the address contradicts',
  fails('wallet-set', JSON.stringify({ ...view, net: 'mainnet' })).includes('net says mainnet'));
const installed = JSON.parse(run('wallet-set', JSON.stringify(view))) as { net: string; address: string };
ok('wallet-set installs the view-only treasury', installed.address === d.treasury.address && installed.net === 'stagenet');
// The whole point of the refusals above: this string must not exist anywhere in the file.
ok('the identity file holds no spend key', !readFileSync(path, 'utf8').includes(hex(d.treasury.b)));

// ── bind (SPEC §6) ────────────────────────────────────────────────────────────────────────
const binding = JSON.parse(run('bind')) as Binding;
ok('binding names this DID, method monero and the BASE address',
  binding.body.id === me.did && binding.body.method === 'monero' && binding.body.addr === d.treasury.address);
ok('binding carries a view-mode SigV2 sig_addr', binding.sig_addr?.startsWith('SigV2') === true);
ok('binding sig_id verifies under the genesis key', verifySig(me.genesis.key, binding.body, binding.sig_id));
// Each CLI call reads its own clock, so a freshly minted `iat` can be a second past the `now`
// this test captured at startup — and `iat <= now` would then be false. Verify at the later of
// the two; `now` is a parameter precisely so this is a choice and not a race (CLAUDE.md).
const at = (...iats: number[]): number => Math.max(now, ...iats);
const bound = JSON.parse(run('bundle')) as Bundle;
const boundResult = verify(bound as never, at(binding.body.iat));
ok('bundle now carries the binding and it is PROVEN (§6.1)',
  boundResult.bindings.length === 1 && boundResult.bindings[0]!.proof === 'proven' && boundResult.rejected.bindings === 0);

// ── receive (MONERO.md §3) ────────────────────────────────────────────────────────────────
const got = [1, 2, 3].map(() => JSON.parse(run('receive')) as { account: number; index: number; address: string });
ok('receive hands out three distinct subaddresses', new Set(got.map((g) => g.address)).size === 3);
ok('receive reproduces subaddress(a, B, 0, 1..3), starting at 1 because (0,0) is the base address',
  got.every((g, i) => g.account === 0 && g.index === i + 1 &&
    g.address === subaddress({ a: d.treasury.a, B: d.treasury.B, major: 0, minor: i + 1, net: 'stagenet' })));
ok('a receive address is a stagenet SUBaddress', decodeAddress(got[0]!.address).kind === 'subaddress' && decodeAddress(got[0]!.address).net === 'stagenet');
ok('receive on another account starts at 0', (JSON.parse(run('receive', '--account', '1')) as { account: number; index: number }).index === 0);
// Past the default lookahead a RESTORED wallet does not scan the index, so money sent there
// is invisible until that is fixed by hand (wallet2.cpp:131). Warn, on stderr, do not refuse.
const bumped = JSON.parse(readFileSync(path, 'utf8')) as { monero: { next_minor: Record<string, number> } };
bumped.monero.next_minor['0'] = 201;
writeFileSync(path, JSON.stringify(bumped));
const past = spawnSync('node', [CLI, 'receive'], { env: { PATH: process.env['PATH'], HOME }, encoding: 'utf8' });
ok('receive warns past the 200 lookahead but still hands out the address',
  past.status === 0 && past.stderr.includes('lookahead') && (JSON.parse(past.stdout) as { index: number }).index === 201);
// `load -> receive -> save` is a read-modify-write of one counter, and moadim runs its sidecar
// as a CLI it may invoke more than once at a time. Two payers handed ONE subaddress can link
// each other (MONERO.md §3), so the four racing runs below must get four different indices.
const racing = await Promise.all([0, 1, 2, 3].map(() => new Promise<string>((resolve) => {
  const child = spawn('node', [CLI, 'receive', '--account', '2'], { env: { PATH: process.env['PATH'], HOME } });
  let stdout = '';
  child.stdout.on('data', (c: Buffer) => { stdout += String(c); });
  child.on('close', () => { resolve(stdout); });
})));
const raced = racing.map((o) => (JSON.parse(o) as { index: number; address: string }));
ok('four concurrent receives hand out four distinct subaddresses',
  new Set(raced.map((r) => r.index)).size === 4 && new Set(raced.map((r) => r.address)).size === 4,
  JSON.stringify(raced.map((r) => r.index)));

// Review finding 7 (2026-09-23): only `receive` took the lock. A `bind` that loaded before a
// `receive` saved wrote the old counter back, and the next `receive` handed the same
// subaddress out again. Hold the lock exactly as a racing `receive` holds it, start `bind`
// and `wallet-set`, bump the counter while they are (or are not) waiting, then release.
{
  const lock = `${path}.lock`;
  writeFileSync(lock, '', { flag: 'wx' });
  const start = (...args: string[]): { exited: () => boolean; done: Promise<number | null> } => {
    const c = spawn('node', [CLI, ...args], { env: { PATH: process.env['PATH'], HOME }, stdio: 'ignore' });
    return { exited: () => c.exitCode !== null, done: new Promise((r) => { c.on('close', r); }) };
  };
  const racers = [start('bind'), start('wallet-set', JSON.stringify(view)), start('add-issuer', JSON.stringify(world.genesis))];
  await new Promise((r) => { setTimeout(r, 1200); }); // CLI start-up is ~0.3 s; the lock waits 2.5 s
  const waiting = racers.every((r) => !r.exited());
  const store = load(path);
  const won = receive(store, 2); // the `receive` that holds the lock
  save(path, store);
  rmSync(lock);
  const codes = await Promise.all(racers.map((r) => r.done));
  const next = JSON.parse(run('receive', '--account', '2')) as { index: number };
  ok('bind, wallet-set and add-issuer wait for the lock', waiting && codes.every((c) => c === 0), `waiting ${waiting}, exit codes ${codes}`);
  ok('so a counter bumped under the lock survives them: no subaddress handed out twice', next.index === won.index + 1, `held ${won.index}, next ${next.index}`);
}

// ── invoice / verify-invoice (SPEC §6.3) ──────────────────────────────────────────────────
const bundleFile = join(HOME, 'bound.json');
writeFileSync(bundleFile, JSON.stringify(bound));
const inv = JSON.parse(run('invoice', '--addr', got[0]!.address, '--amount', '150000000000', '--memo', 'one run')) as
  { body: { v: string; typ: string; did: string; method: string; addr: string; iat: number; exp: number; nonce: string; amount?: string; memo?: string }; sig: string };
ok('invoice is signed by the identity key', verifySig(me.genesis.key, inv.body, inv.sig));
ok('invoice names this DID, the subaddress, and amount as a STRING (no floats, SPEC §3)',
  inv.body.did === me.did && inv.body.addr === got[0]!.address && inv.body.amount === '150000000000' && inv.body.memo === 'one run');
ok('invoice ttl defaults to 24h', inv.body.exp - inv.body.iat === 86400);
const verdict = JSON.parse(run('verify-invoice', JSON.stringify(inv), '--bundle', bundleFile)) as
  { did: string; current: boolean; binding: { addr: string; proof: string }; net: string; amount: string | null };
ok('verify-invoice accepts it against the bundle whose binding anchors it',
  verdict.did === me.did && verdict.current && verdict.binding.proof === 'proven' &&
  verdict.binding.addr === d.treasury.address && verdict.net === 'stagenet' && verdict.amount === '150000000000');

ok('invoice refuses the base address', fails('invoice', '--addr', d.treasury.address).includes('standard address'));
ok('invoice refuses a subaddress of another network',
  fails('invoice', '--addr', subaddress({ a: d.treasury.a, B: d.treasury.B, major: 0, minor: 1, net: 'mainnet' })).includes('mainnet address'));
ok('invoice refuses a non-integer amount', fails('invoice', '--addr', got[1]!.address, '--amount', '0.15').includes('atomic units'));
// THREAT-MODEL §4: `--addr` is a string this process was handed, and a payer pays what the
// invoice names. A well-formed stagenet subaddress of SOMEONE ELSE'S wallet must not get the
// identity key's signature — that would hand them the money, and a coin does not rotate back.
const theirs = deriveRoot(new Uint8Array(32).fill(0xAA), 'stagenet');
const foreignSub = subaddress({ a: theirs.treasury.a, B: theirs.treasury.B, major: 0, minor: 1, net: 'stagenet' });
ok('invoice refuses a subaddress this wallet never handed out',
  fails('invoice', '--addr', foreignSub).includes('not a subaddress this wallet has handed out'));
ok('verify-invoice refuses without a bundle', fails('verify-invoice', JSON.stringify(inv)).includes('--bundle'));

// `now` is a parameter, never a clock read (CLAUDE.md), so expiry is testable without waiting.
const refused = (i: unknown, t: number): string => {
  try {
    verifyInvoice(i, bound as never, t);
    return '';
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
};
ok('an expired invoice is refused', refused(inv, inv.body.exp).includes('expired or not yet valid'));
ok('a tampered invoice is refused', refused({ body: { ...inv.body, amount: '1' }, sig: inv.sig }, at(inv.body.iat)).includes('signature does not verify'));
ok('an invoice naming a DID the bundle does not describe is refused',
  refused({ body: { ...inv.body, did: world.did }, sig: inv.sig }, at(inv.body.iat)).includes('not a node of the bundle'));
// A well-signed invoice for the right wallet on the WRONG network: §6.2 warns that the
// signature hash does not cover the network prefix, so only this check catches it.
const secret = Uint8Array.from(Buffer.from((JSON.parse(readFileSync(path, 'utf8')) as { secret: string }).secret, 'hex'));
const foreign = { ...inv.body, addr: subaddress({ a: d.treasury.a, B: d.treasury.B, major: 0, minor: 1, net: 'mainnet' }) };
ok('verify-invoice refuses an addr on another network', refused({ body: foreign, sig: sign(secret, foreign) }, at(inv.body.iat)).includes('the bound wallet is stagenet'));
// MONERO.md §4: an invoice names a SUBaddress. A well-signed one naming a standard address —
// here the bound base address itself — is refused, as sigelo-spend refuses it.
const standard = { ...inv.body, addr: d.treasury.address };
ok('verify-invoice refuses an invoice naming a standard address', refused({ body: standard, sig: sign(secret, standard) }, at(inv.body.iat)).includes('an invoice names a subaddress'));

// ── rotate ────────────────────────────────────────────────────────────────────────────────
ok('rotate refuses a recovery rotation in the agent runtime', fails('rotate', '--recovery').includes('voluntary rotations only'));
const rotated = JSON.parse(run('rotate')) as { did: string; chain: string[] };
ok('rotation produces a 2-node chain', rotated.chain.length === 2 && rotated.chain[0] === me.did && rotated.did !== me.did);
// Bind again under the new key. The CLI keeps one binding per method — a stale one names an
// address nobody watches — so the old one is put back by hand here to check the protocol
// rule: a binding whose `id` is a RETIRED DID is still accepted while that DID is in the chain.
const binding2 = JSON.parse(run('bind')) as Binding;
ok('bind after rotation names the new DID', binding2.body.id === rotated.did && binding2.body.addr === d.treasury.address);
const store = JSON.parse(readFileSync(path, 'utf8')) as { bindings: Binding[] };
ok('bind replaced the binding for its method rather than appending', store.bindings.length === 1);
store.bindings = [binding, binding2];
writeFileSync(path, JSON.stringify(store));
const second = JSON.parse(run('bundle')) as Bundle;
ok('bundle root is still the ORIGINAL genesis', did(second.genesis) === me.did);
ok('the attestation still names the old DID', second.attestations[0]!.body.sub === me.did);

// ── the library's own verifier ────────────────────────────────────────────────────────────
const T = at(binding.body.iat, binding2.body.iat); // the whole bundle, at a clock no earlier than its newest iat
const result = verify(second as never, T);
ok('verify: current DID is the rotated one', result.did === rotated.did);
ok('verify: chain is 2 nodes', result.chain.length === 2);
ok('verify: recovery commitment carried forward', result.recovery === created.genesis.recovery);
ok('verify: attestation grouped under the world DID', result.attestations[world.did]?.length === 1);
ok('verify: nothing rejected', result.rejected.attestations === 0 && result.rejected.bindings === 0);
ok('verify: both bindings proven, the old one under the retired DID',
  result.bindings.length === 2 && result.bindings.every((b) => b.proof === 'proven') &&
  result.bindings[0]!.body.id === me.did && result.bindings[1]!.body.id === rotated.did);

// ── a RETIRED key must not name a payment address (THREAT-MODEL §2.4, §3.6) ───────────────
// `secret` above is the pre-rotation key. An attacker holding it signs a structurally perfect
// invoice for a wallet of their own; every other check passes — the DID is in the chain, the
// bundle has a proven binding, the networks agree — so only the current-DID check refuses it.
const stale = { ...inv.body, did: me.did, addr: foreignSub, iat: T - 60, exp: T + 3600 };
const staleVerdict = ((): string => {
  try {
    verifyInvoice({ body: stale, sig: sign(secret, stale) }, second as never, T);
    return '';
  } catch (e) { return e instanceof Error ? e.message : String(e); }
})();
ok('verify-invoice refuses an invoice signed by the ROTATED-AWAY key', staleVerdict.includes('ROTATED AWAY'), staleVerdict || 'ACCEPTED IT');

// ── cross-check with the Go reference ─────────────────────────────────────────────────────
// Same bytes, a second implementation: if these disagree, one of them is wrong (SPEC §10).
// `go run ./cmd/sigelo-verify` from go/ is the verifier exactly as a user runs it; a prebuilt
// go/sigelo-verify is used instead when present (CI builds it statically first).
const bundlePath = join(HOME, 'bundle.json');
writeFileSync(bundlePath, JSON.stringify(second));
const GO = join(ROOT, 'go');
const built = join(GO, 'sigelo-verify');
const hasGo = spawnSync('go', ['version'], { encoding: 'utf8' }).status === 0;
const [cmd, args] = existsSync(built)
  ? [built, [bundlePath, '--now', String(T)]]
  : ['go', ['run', './cmd/sigelo-verify', bundlePath, '--now', String(T)]];
if (!existsSync(built) && !hasGo) {
  console.log('SKIP go cross-check — `go` is not on PATH and go/sigelo-verify is not built; install Go to run it');
} else {
  const run = spawnSync(cmd, args, { cwd: GO, encoding: 'utf8' });
  if (run.status !== 0) ok('go cross-check ran and accepted the bundle', false, `${run.error ?? ''}${run.stderr}`.trim().split('\n').slice(-2).join(' '));
  else {
    const ref = JSON.parse(run.stdout) as { did: string; chain: string[]; recovery: string;
      attestations: Record<string, unknown[]>; rejected: Record<string, number>;
      bindings: { body: { id: string; method: string; addr: string }; proof: string }[] };
    console.log(`go: ${run.stdout.trim().slice(0, 200)}…`);
    ok('go: same current DID', ref.did === result.did);
    ok('go: same chain', JSON.stringify(ref.chain) === JSON.stringify(result.chain));
    ok('go: same recovery commitment', ref.recovery === result.recovery);
    ok('go: same issuer accepted', Object.keys(ref.attestations).length === 1 && Object.keys(ref.attestations)[0] === world.did);
    ok('go: nothing rejected', ref.rejected['attestations'] === 0 && ref.rejected['bindings'] === 0);
    // The Monero SigV2 signature made here with the view key, checked by a second implementation.
    ok('go: both monero bindings proven, same addr',
      ref.bindings.length === 2 && ref.bindings.every((b) => b.proof === 'proven' && b.body.method === 'monero' && b.body.addr === d.treasury.address) &&
      JSON.stringify(ref.bindings.map((b) => b.body.id)) === JSON.stringify(result.bindings.map((b) => b.body.id)));
  }
}

// ── adopt: a key this process did not make (a keeper's POST /delegate, then a recovery) ────
// The keeper mints agent 3's identity from K_0 of a throwaway root; the subagent adopts the
// /delegate answer; a world attests it; a thief with the key forks it twice; the Owner runs
// `sigelo-offline recover` from the last honest node; the subagent adopts the rotation.
{
  const idFile = join(HOME, 'delegate.local.json');
  const at2 = (...args: string[]): string => execFileSync('node', [CLI, ...args],
    { env: { PATH: process.env['PATH'], HOME, SIGELO_IDENTITY: idFile }, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  const at2In = (input: string, ...args: string[]): string => execFileSync('node', [CLI, ...args],
    { env: { PATH: process.env['PATH'], HOME, SIGELO_IDENTITY: idFile }, encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'] });
  const at2Fails = (input: string, ...args: string[]): string => { try { at2In(input, ...args); return ''; } catch (e) { return String((e as { stderr?: string }).stderr ?? ''); } };
  const words = newRoot(), S = rootFromMnemonic(words), K0 = keeperRoot(S, 0);
  const seed = agentIdentitySeed(K0, 3, 0), hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
  const minted = keygen({ seed, recovery: recoveryCommitment(S) });
  const answer = { name: 'sub', account: 3, address: '5…', did: minted.did, genesis: minted.genesis, identity_seed_hex: hex(seed),
    url: 'http://127.0.0.1:1', token: 'tok-secret-shown-once', shown_once: '…', fund: null };
  ok('adopt refuses a seed that is not the genesis key',
    at2Fails(JSON.stringify({ ...answer, identity_seed_hex: hex(agentIdentitySeed(K0, 4, 0)) }), 'adopt', '-').includes('does not produce'));
  ok('adopt refuses a did that is not the genesis DID', at2Fails(JSON.stringify({ ...answer, did: me.did }), 'adopt', '-').includes('is not the DID'));
  ok('adopt wrote nothing on refusal', !existsSync(idFile));
  const adopted = JSON.parse(at2In(JSON.stringify(answer), 'adopt', '-')) as { did: string };
  const f = JSON.parse(readFileSync(idFile, 'utf8')) as Record<string, unknown>;
  ok('adopt takes the whole /delegate answer: same DID, init\'s file format, 0600, no token',
    adopted.did === minted.did && JSON.stringify(Object.keys(f)) === JSON.stringify(['v', 'secret', 'genesis', 'rotations', 'attestations', 'issuers']) &&
    f['secret'] === hex(seed) && (!posixModes || (statSync(idFile).mode & 0o777) === 0o600) && !readFileSync(idFile, 'utf8').includes('tok-secret'));
  ok('adopt refuses to overwrite without --force', at2Fails(JSON.stringify(answer), 'adopt', '-').includes('refusing to overwrite'));
  at2In(JSON.stringify(answer), 'adopt', '-', '--force');
  ok('adopt --force replaces it', JSON.parse(at2('whoami')).did === minted.did);
  const att = attest({ secret: world.secret, iss: world.did, sub: minted.did, iat: now - 60, exp: now + 86400, ctx: CTX, admission: 'open', claims: { n: 1 } });
  at2In(JSON.stringify(world.genesis), 'add-issuer', '-');
  at2In(JSON.stringify(att), 'add-attestation', '-');
  // The adopted identity signs challenges like an init'ed one.
  const ch = { v: 'sigelo/0', typ: 'challenge', did: minted.did, ctx: CTX, nonce: 'zAdopt' };
  ok('adopted identity signs a challenge under the minted key', verifySig(minted.genesis.key, ch, (JSON.parse(at2(`sign-challenge`, JSON.stringify(ch))) as { sig: string }).sig));
  // The compromised agent rotates voluntarily (its file now has a 2-node chain the thief shares),
  // and the thief forks from the genesis too. The Owner recovers from the genesis.
  at2('rotate');
  const thief: Rotation[] = [1, 2].map((x) => rotate({ genesis: minted.genesis, next_genesis: keygen({ seed: new Uint8Array(32).fill(x), recovery: minted.genesis.recovery }).genesis, iat: now + 5, reason: 'voluntary', secret: seed }));
  const gFile = join(HOME, 'honest-genesis.json'), recFile = join(HOME, 'recovery.local.json');
  writeFileSync(gFile, JSON.stringify(minted.genesis));
  const rec = spawnSync('node', [join(ROOT, 'ts', 'dist', 'offline.js'), 'recover', '--genesis', gFile, '-', '--agent', '3', '--n', '1', '--iat', String(now)], { input: words, encoding: 'utf8' });
  ok('sigelo-offline recover signs from the honest genesis', rec.status === 0, rec.stderr);
  writeFileSync(recFile, rec.stdout);
  const r = JSON.parse(rec.stdout) as { did: string; rotation: Rotation; identity_seed_hex: string };
  const foreign = keygen({ seed: new Uint8Array(32).fill(9), recovery: minted.genesis.recovery });
  ok('adopt --rotation refuses a rotation that is not from this chain',
    at2Fails('', 'adopt', '--rotation', JSON.stringify({ ...r, rotation: rotate({ genesis: foreign.genesis, next_genesis: r.rotation.next_genesis, iat: now, reason: 'voluntary', secret: foreign.secret }) })).includes('not a DID of this identity'));
  ok('adopt --rotation refuses a seed that is not the new key',
    at2Fails('', 'adopt', '--rotation', JSON.stringify({ ...r, identity_seed_hex: hex(seed) })).includes('does not produce'));
  ok('adopt --rotation refuses a voluntary rotation from a retired node (a fork)',
    at2Fails('', 'adopt', '--rotation', JSON.stringify({ rotation: thief[0], identity_seed_hex: hex(new Uint8Array(32).fill(1)) })).includes('is a fork'));
  const after = JSON.parse(at2('adopt', '--rotation', recFile)) as { did: string; chain: string[] };
  ok('adopt --rotation (a file): the head is the recovered DID, the compromised rotation dropped, chain of two',
    after.did === r.did && JSON.stringify(after.chain) === JSON.stringify([minted.did, r.did]));
  ok('adopt --rotation refuses the same rotation twice', at2Fails('', 'adopt', '--rotation', recFile).includes('already in this chain'));
  const rb = JSON.parse(at2('bundle')) as Bundle;
  const withThief = { ...rb, rotations: [...thief, ...rb.rotations] };
  const rv = verify(withThief as never, now + 10);
  ok('recovered bundle + thief\'s fork: recovery wins, chain of two, the old attestation still counts',
    rv.did === r.did && rv.chain.length === 2 && rv.attestations[world.did]?.length === 1 && rv.rejected.attestations === 0);
  const recovered = JSON.parse(readFileSync(idFile, 'utf8')) as { secret: string };
  ok('the identity file now holds the recovered secret', recovered.secret === r.identity_seed_hex);
  const p2 = join(HOME, 'recovered-bundle.json');
  writeFileSync(p2, JSON.stringify(withThief));
  if (!existsSync(built) && !hasGo) console.log('SKIP go cross-check of the recovered bundle');
  else {
    const g = spawnSync(existsSync(built) ? built : 'go', existsSync(built) ? [p2, '--now', String(now + 10)] : ['run', './cmd/sigelo-verify', p2, '--now', String(now + 10)], { cwd: GO, encoding: 'utf8' });
    const gr = g.status === 0 ? JSON.parse(g.stdout) as { did: string; chain: string[]; attestations: Record<string, unknown[]> } : null;
    ok('go: recovered bundle, same DID and chain, thief fork not followed, attestation counted',
      gr !== null && gr.did === rv.did && JSON.stringify(gr.chain) === JSON.stringify(rv.chain) && gr.attestations[world.did]?.length === 1, g.stderr);
  }
}

console.log(failures === 0 ? `\nALL PASS (HOME was ${HOME})` : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
