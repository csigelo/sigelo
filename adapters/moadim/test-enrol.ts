// SPDX-License-Identifier: MIT
// Enrolment end to end (ENROL.md, contact/enrol.mjs): worker i derived from the operator's seed.
// HOMEs as machines, one loopback relay in this process behind a recording proxy, so every byte a
// client sends the relay is kept: the operator makes its keeper root from 25 words on stdin, enrols
// worker 0 on a server (`enrol --wait` / `init --enrol`), the server ends up as the DID derived
// directly from the same root, the temporary DID is gone on both sides, the code works once; worker
// 1 goes `--here` into the agents' directory and a sub-agent runs a verb on it; `--restore 0` onto a
// third machine gives the same DID; `--restore 0 --rotate` gives rotation 1 and the operator's
// contact follows. No worker key, and not K, ever reaches the relay in clear. The operator identity
// itself is the root identity of the words: `keeper --from-words` writes it (a random one in its way
// is refused, then set aside with --replace-me), gives the same DID again after a loss, refuses a
// random `rotate`, and `--rotate-me` derives rotation 1.
//   node test-enrol.ts   → ALL PASS test-enrol.ts (n ok)
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer, connect, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { decodeKey, did, keygen, verify } from 'sigelo';
import { agentIdentitySeed, identitySeed, keeperRoot, newRoot, recoveryCommitment, rootFromMnemonic } from 'sigelo/dist/keys.js';
import { CLI, done, hasRelay, NO_RELAY, ok, RELAY } from './test-helpers.ts';

if (!hasRelay()) {
  console.log(`SKIP enrol end to end: ${NO_RELAY}`);
  done(import.meta.filename);
}

// The direct derivation the server's DID must equal: keys.ts agentIdentitySeed(K_1, i, n), the
// genesis pinned as SPEC §4 allows (created fixed, nonce = SHA-256 of the raw key, 16 bytes).
const words = newRoot(), S = rootFromMnemonic(words), K = keeperRoot(S, 1), RC = recoveryCommitment(S);
const pinned = (seed: Uint8Array) => {
  const key = keygen({ seed, recovery: RC, created: '1970-01-01T00:00:00Z', nonce: new Uint8Array(16) }).key;
  return { seed, ...keygen({ seed, recovery: RC, created: '1970-01-01T00:00:00Z', nonce: new Uint8Array(createHash('sha256').update(decodeKey(key)).digest().subarray(0, 16)) }) };
};
const derived = (i: number, n: number) => pinned(agentIdentitySeed(K, i, n));
// The operator: the root identity of S, keys.ts identitySeed(S, n), pinned the same way.
const rootId = (n: number) => pinned(identitySeed(S, n));

// The relay, and a proxy in front of each of its ports that keeps every byte clients send.
const { startRelay } = await import(pathToFileURL(join(RELAY, 'server.mjs')).href) as { startRelay(o: object): Promise<{ ports: { tcp: number; http: number }; close(): Promise<void> }> };
const { relayPolicy } = await import(pathToFileURL(join(RELAY, 'allowance.mjs')).href) as { relayPolicy(ctx: unknown, o: object): unknown };
const D = mkdtempSync(join(tmpdir(), 'sigelo-moadim-enrol-'));
const relay = await startRelay({ host: 'relay.test', db: join(D, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1, log: () => {},
  policy: (ctx: unknown) => relayPolicy(ctx, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 } }) });
const seen: Buffer[] = [];
const proxy = (port: number): Promise<{ s: Server; port: number }> => new Promise((done) => {
  const s = createServer((c) => {
    const up = connect(port, '127.0.0.1');
    c.on('data', (d: Buffer) => { seen.push(Buffer.from(d)); up.write(d); });
    up.on('data', (d: Buffer) => c.write(d));
    c.on('error', () => up.destroy()); up.on('error', () => c.destroy());
    c.on('close', () => up.end()); up.on('close', () => c.end());
  });
  s.listen(0, '127.0.0.1', () => done({ s, port: (s.address() as { port: number }).port }));
});
const [pm, ph] = [await proxy(relay.ports.tcp), await proxy(relay.ports.http)];
const endpoints = JSON.stringify({ 'relay.test': { mqtt: `mqtt://127.0.0.1:${pm.port}`, http: `http://127.0.0.1:${ph.port}` } });
const env = (home: string, extra: Record<string, string> = {}): Record<string, string> => ({ PATH: process.env['PATH'] ?? '', HOME: home, SIGELO_RELAY: 'relay.test', SIGELO_RELAY_ENDPOINTS: endpoints, ...extra });
type Run = { status: number | null; stdout: string; stderr: string };
const cli = (home: string, args: string[], o: { onLine?: (l: string) => void; input?: string; extra?: Record<string, string> } = {}) => new Promise<Run>((resolve) => {
  const c = spawn('node', [CLI, ...args], { env: env(home, o.extra), cwd: home });
  let stdout = '', stderr = '', onLine = o.onLine;
  c.stdout.on('data', (d) => { stdout += d; if (onLine && stdout.includes('\n')) { onLine(stdout.split('\n')[0]!); onLine = undefined; } });
  c.stderr.on('data', (d) => { stderr += d; });
  c.on('close', (status) => resolve({ status, stdout, stderr }));
  c.stdin.end(o.input ?? '');
});
const verbose = (what: string, r: Run): void => { if (process.env['SIGELO_TEST_VERBOSE'] === '1') console.log(`  ${what} exit ${r.status}\n${r.stdout}${r.stderr}`.replace(/^/gm, '  | ')); };
const words4 = (s: string): string | undefined => /Check with them: (\w+ \w+ \w+ \w+)/.exec(s)?.[1];
// The operator's `enrol …` (it prints the code first) beside the machine's `init --enrol <code>`.
async function enrolOn(home: string, args: string[], machineArgs: string[] = []): Promise<{ op: Run; m: Run; code: string }> {
  let code = '';
  const got = new Promise<void>((r) => { const t = setInterval(() => { if (code) { clearInterval(t); r(); } }, 50); });
  const op = cli(OP, ['enrol', ...args, '--wait', '90'], { onLine: (l) => { code = l.trim(); } });
  await Promise.race([got, op]);
  const m = await cli(home, ['init', '--enrol', code, '--wait', '90', ...machineArgs]);
  const r = { op: await op, m, code };
  verbose(`enrol ${args.join(' ')}`, r.op); verbose(`init --enrol (${home})`, r.m);
  return r;
}

const OP = mkdtempSync(join(tmpdir(), 'sigelo-enrol-op-')), SRV = mkdtempSync(join(tmpdir(), 'sigelo-enrol-srv-')), THIRD = mkdtempSync(join(tmpdir(), 'sigelo-enrol-3-'));
const FOURTH = mkdtempSync(join(tmpdir(), 'sigelo-enrol-4-')), FIFTH = mkdtempSync(join(tmpdir(), 'sigelo-enrol-5-')), OTHER = mkdtempSync(join(tmpdir(), 'sigelo-enrol-x-'));
const human = join(OP, '.config', 'sigelo', 'me.local.json'), agentFile = (h: string): string => join(h, '.config', 'moadim', 'sigelo.local.json');
const contactsOf = (f: string) => (JSON.parse(readFileSync(f.replace(/\.json$/, '.contacts.json'), 'utf8')) as { contacts: Record<string, { did: string; current_did: string; revoked: boolean; tier: string; name: string; enrolled?: unknown }> }).contacts;
try {
  const none = await cli(OP, ['enrol', '--name', 'vps']);
  ok('enrol without an operator identity: exit 2, says keeper --from-words makes it', none.status === 2 && none.stderr.includes(`no operator identity at ${human}`) && none.stderr.includes('sigelo-agent keeper --from-words'), none.stderr);
  const inAgents = await cli(OP, ['enrol', '--name', 'vps', '--identity', join(OP, '.config', 'moadim', 'sigelo.me.local.json')]);
  ok('enrol with an operator identity in the agents\' directory: refused, exit 2', inAgents.status === 2 && inAgents.stderr.includes('in the agents\' directory'), inAgents.stderr);
  // An operator identity of the old kind (a random key, `ui --recovery`) is in the way.
  const mk = spawnSync('node', [CLI, 'init', '--no-recovery'], { env: { ...env(OP), SIGELO_IDENTITY: human }, encoding: 'utf8' });
  const randomDid = (JSON.parse(mk.stdout) as { did: string }).did, opDid = rootId(0).did;
  const noKeeper = await cli(OP, ['enrol', '--name', 'vps']);
  ok('enrol without a keeper root: exit 2, says keeper --from-words', noKeeper.status === 2 && noKeeper.stderr.includes('sigelo-agent keeper --from-words'), noKeeper.stderr);

  // The keeper root, once, from the 25 words on stdin: never argv, never index 0.
  ok('keeper: words on the command line are refused, exit 2', (await cli(OP, ['keeper', '--from-words', ...words.split(' ').slice(0, 3)])).status === 2);
  ok('keeper --keeper 0: refused (the ceremony\'s agents\' keeper), exit 2', (await cli(OP, ['keeper', '--from-words', '--keeper', '0'], { input: words })).status === 2);
  const typo = await cli(OP, ['keeper', '--from-words'], { input: words.split(' ').reverse().join(' ') });
  ok('keeper: a wrong word order: refused by the checksum, exit 1, nothing written', typo.status === 1 && /checksum|mnemonic/.test(typo.stderr) && !existsSync(human.replace(/\.json$/, '.keeper.json')), typo.stderr);
  const kfile0 = human.replace(/\.json$/, '.keeper.json'), meDid = (): string => { const x = JSON.parse(readFileSync(human, 'utf8')) as { genesis: object; rotations: { next_genesis: object }[] }; return did((x.rotations.at(-1)?.next_genesis ?? x.genesis) as never); };
  const inWay = await cli(OP, ['keeper', '--from-words'], { input: words });
  ok('keeper --from-words over a random operator identity: exit 1, says what is lost and --replace-me, nothing written', inWay.status === 1 && inWay.stderr.includes('--replace-me')
    && inWay.stderr.includes('loses its contacts and the attestations it issued') && inWay.stderr.includes('enrolled again') && !existsSync(kfile0) && meDid() === randomDid, inWay.stderr);
  ok('keeper --replace-me without --from-words: exit 2', (await cli(OP, ['keeper', '--replace-me'])).status === 2);
  const kp = await cli(OP, ['keeper', '--from-words', '--replace-me'], { input: `${words}\n` });
  const aside = human.replace(/\.json$/, `.old-${randomDid.slice(-8)}.json`);
  ok('keeper --from-words --replace-me: the operator identity is the root identity of the words (identitySeed(S, 0), pinned), 0600; the random one set aside',
    kp.status === 0 && meDid() === opDid && (statSync(human).mode & 0o777) === 0o600 && existsSync(aside) && JSON.parse(kp.stdout).me?.did === opDid
    && (JSON.parse(readFileSync(human, 'utf8')) as { secret: string; derived: { n: number; path: string } }).secret === Buffer.from(rootId(0).seed).toString('hex')
    && JSON.parse(readFileSync(human, 'utf8')).derived.path === 'sigelo/v1/identity/ed25519/0', kp.stdout + kp.stderr);
  const kfile = human.replace(/\.json$/, '.keeper.json'), kjson = existsSync(kfile) ? readFileSync(kfile, 'utf8') : '';
  ok('keeper --from-words: K_1 beside the operator identity, 0600, the trust said', kp.status === 0 && (statSync(kfile).mode & 0o777) === 0o600 && kjson.includes(Buffer.from(K).toString('hex'))
    && JSON.parse(kp.stdout).keeper === 1 && kp.stderr.includes('whoever reads it can derive every worker under it'), kp.stderr);
  ok('the keeper file holds K, not the seed', !kjson.includes(Buffer.from(S).toString('hex')) && !kjson.includes(words.split(' ')[0]!) && JSON.parse(kjson).recovery === RC);
  const twice = await cli(OP, ['keeper', '--from-words'], { input: words });
  ok('keeper --from-words again: the same DID, kept, said', twice.status === 0 && meDid() === opDid && twice.stderr.includes('is the root identity of your words') && twice.stderr.includes(': kept'), twice.stderr);
  rmSync(human);
  const back = await cli(OP, ['keeper', '--from-words'], { input: words });
  ok('the operator identity lost: keeper --from-words gives the same DID back', back.status === 0 && meDid() === opDid, back.stderr);

  // Remote: worker 0 on the server.
  const w0 = derived(0, 0);
  const e1 = await enrolOn(SRV, ['--name', 'vps'], ['--name', 'owner']);
  ok(`enrol prints a short code on stdout (${e1.code})`, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/.test(e1.code));
  const res = JSON.parse(e1.m.stdout || '{}') as { did: string; operator: string; worker: number };
  ok('init --enrol: exit 0; the server is worker 0, the DID derived directly from the same root', e1.m.status === 0 && res.did === w0.did && res.worker === 0 && res.operator === opDid, e1.m.stderr);
  ok('the server says it: paired, then replaced its identity with the operator\'s', e1.m.stderr.includes(`replaced this machine's identity with the operator's: worker 0 (${w0.did}), run by ${opDid}`), e1.m.stderr);
  ok('enrol --wait: exit 0, "paired, then replaced its identity with yours: worker 0", the same four words on both sides', e1.op.status === 0
    && e1.op.stderr.includes(`paired, then replaced its identity with yours: worker 0 (${w0.did}), run by you`) && words4(e1.op.stderr) !== undefined && words4(e1.op.stderr) === words4(e1.m.stderr), e1.op.stderr);
  const sfile = agentFile(SRV), stored = JSON.parse(readFileSync(sfile, 'utf8')) as { secret: string; genesis: { recovery: string } };
  ok('the server\'s identity file: worker 0\'s derived key, 0600, committing to the seed\'s recovery key', stored.secret === Buffer.from(w0.seed).toString('hex') && (statSync(sfile).mode & 0o777) === 0o600 && stored.genesis.recovery === RC);
  const b = await cli(SRV, ['bundle']);
  const v = verify(JSON.parse(b.stdout) as never, Math.floor(Date.now() / 1000));
  ok('offline: the server\'s bundle verifies an operator attestation by the operator, ≤ 90 days', v.did === w0.did && v.attestations[opDid]?.[0]?.ctx === 'sigelo-relay/operator'
    && v.attestations[opDid]![0]!.exp - v.attestations[opDid]![0]!.iat <= 90 * 86400 && v.rejected.attestations === 0);
  const oc = contactsOf(human), temps = Object.values(oc).filter((c) => c.did !== w0.did);
  ok('the operator\'s contact: the worker\'s derived DID, tier own, no enrolled flag', oc[w0.did]?.tier === 'own' && oc[w0.did]!.name === 'vps' && !oc[w0.did]!.revoked && oc[w0.did]!.enrolled === undefined, JSON.stringify(oc));
  ok('the temporary DID is forgotten at the operator', temps.length === 1 && temps[0]!.revoked === true);
  const sc = contactsOf(sfile);
  ok('the server\'s contacts start with the operator (own); no temporary file is left', Object.keys(sc).join() === opDid && sc[opDid]!.tier === 'own'
    && !readdirSync(join(SRV, '.config', 'moadim')).some((f) => f.includes('.enrol-')), readdirSync(join(SRV, '.config', 'moadim')).join());
  const again = await cli(OTHER, ['init', '--enrol', e1.code, '--wait', '2']);
  ok('the same code a second time: exit 1, park_unknown, no identity left behind', again.status === 1 && again.stderr.includes('park_unknown') && !existsSync(agentFile(OTHER))
    && (!existsSync(join(OTHER, '.config', 'moadim')) || !readdirSync(join(OTHER, '.config', 'moadim')).some((f) => f.includes('sigelo.local'))), again.stderr);
  ok('init --enrol with --recovery: refused, exit 2', (await cli(OTHER, ['init', '--enrol', 'K7F3-Q9ZP', '--no-recovery'])).status === 2);
  ok('enrol --finish on the server, nothing pending: exit 0, says so', ((r) => r.status === 0 && r.stderr.includes('nothing pending'))(await cli(SRV, ['enrol', '--finish'])));
  ok('enrol --index 0 again: refused (enrol_index), points to --restore', ((r) => r.status === 1 && r.stderr.includes('enrol --restore 0'))(await cli(OP, ['enrol', '--name', 'x', '--index', '0'])));

  // --here: worker 1 into the agents' directory; a sub-agent runs a verb on it.
  const w1 = derived(1, 0), here = await cli(OP, ['enrol', '--name', 'helper', '--here']);
  const pool = join(OP, '.config', 'moadim', 'sigelo.helper.local.json');
  ok('enrol --here: worker 1 in the agents\' directory, 0600, nothing sent', here.status === 0 && (JSON.parse(here.stdout) as { did: string }).did === w1.did && (statSync(pool).mode & 0o777) === 0o600
    && here.stderr.includes(`SIGELO_IDENTITY=${pool}`), here.stderr);
  const sub = await cli(OP, ['bundle'], { extra: { SIGELO_IDENTITY: pool } });
  const sv = ((): { did?: string; attestations: Record<string, { ctx: string }[]> } => { try { return verify(JSON.parse(sub.stdout) as never, Math.floor(Date.now() / 1000)); } catch { return { attestations: {} }; } })();
  ok('a sub-agent with SIGELO_IDENTITY = the pooled file: bundle → worker 1, run by the operator', sub.status === 0 && sv.did === w1.did && sv.attestations[opDid]?.[0]?.ctx === 'sigelo-relay/operator', sub.stderr);
  ok('enrol --here onto a name in use: refused, nothing overwritten', (await cli(OP, ['enrol', '--name', 'helper', '--here'])).status === 1);

  // Restore worker 0 on a third machine: the same DID.
  const e3 = await enrolOn(THIRD, ['--restore', '0']);
  ok('enrol --restore 0 onto a third machine: the same DID', e3.m.status === 0 && e3.op.status === 0 && (JSON.parse(e3.m.stdout || '{}') as { did: string }).did === w0.did, e3.m.stderr + e3.op.stderr);
  ok('restore says the lost copy\'s contacts are gone, the DID stays', e3.op.stderr.includes('the contacts of the lost copy are gone') && e3.op.stderr.includes(`sees the same DID ${w0.did}`), e3.op.stderr);
  // --rotate: rotation 1, placed on a fourth machine; the operator's contact follows.
  const w01 = derived(0, 1), e4 = await enrolOn(FOURTH, ['--restore', '0', '--rotate']);
  const r4 = JSON.parse(e4.m.stdout || '{}') as { did: string; original: string };
  ok('enrol --restore 0 --rotate: rotation 1, the same original DID', e4.m.status === 0 && e4.op.status === 0 && r4.did === w01.did && r4.original === w0.did, e4.m.stderr + e4.op.stderr);
  const oc2 = contactsOf(human);
  ok('the operator\'s contact follows: current DID = rotation 1, still own', oc2[w0.did]?.current_did === w01.did && oc2[w0.did]!.tier === 'own', JSON.stringify(oc2[w0.did]));
  const roster = JSON.parse(readFileSync(kfile, 'utf8')) as { workers: Record<string, { n: number; did: string }> };
  ok('the roster: worker 0 at rotation 1, worker 1 here', roster.workers['0']?.n === 1 && roster.workers['0'].did === w01.did && roster.workers['1']?.did === w1.did);
  const rk = await cli(OP, ['keeper']);
  ok('keeper (no words): the roster again, no secret printed', rk.status === 0 && !rk.stdout.includes(Buffer.from(K).toString('hex')) && (JSON.parse(rk.stdout) as { workers: unknown[] }).workers.length === 2);

  // Lazily, nobody waiting: `enrol` prints the code and exits; `init --enrol` exits 3 (pending); then
  // `enrol --finish` on each side in turn, each run doing its part, until both are done.
  const w2 = derived(2, 0);
  let lazyCode = '';
  const lop = await cli(OP, ['enrol', '--name', 'lazy'], { onLine: (l) => { lazyCode = l.trim(); } });
  const lm = await cli(FIFTH, ['init', '--enrol', lazyCode, '--wait', '2']);
  ok('lazy: enrol exits 0 with the code; init --enrol exits 3, pending', lop.status === 0 && lm.status === 3 && lm.stderr.includes('enrol --finish'), lm.stderr);
  const runs: number[][] = [];
  for (let k = 0; k < 6; k++) {
    const a = await cli(OP, ['enrol', '--finish', '--wait', '4']), m = await cli(FIFTH, ['enrol', '--finish', '--wait', '4']);
    verbose(`finish op ${k}`, a); verbose(`finish machine ${k}`, m);
    runs.push([a.status ?? -1, m.status ?? -1]);
    if (a.status === 0 && m.status === 0) break;
  }
  const lc = existsSync(agentFile(FIFTH)) ? contactsOf(agentFile(FIFTH)) : {};
  ok(`lazy: enrol --finish on each side in turn ends both at exit 0 (${JSON.stringify(runs)}); the machine is worker 2, paired with the operator`,
    runs.at(-1)!.join() === '0,0' && (JSON.parse(readFileSync(agentFile(FIFTH), 'utf8')) as { secret: string }).secret === Buffer.from(w2.seed).toString('hex')
    && lc[opDid]?.tier === 'own' && contactsOf(human)[w2.did]?.tier === 'own' && !readdirSync(join(FIFTH, '.config', 'moadim')).some((f) => f.includes('.enrol-')));

  // The roster is recoverable: the keeper file lost, the words make it again and the scan finds
  // workers 0 (a contact, at rotation 1), 1 (the agents' directory) and 2, and stops at 3.
  rmSync(kfile);
  const rb = await cli(OP, ['keeper', '--from-words'], { input: words });
  const ws = (JSON.parse(rb.stdout || '{}') as { workers?: { worker: number; n: number; did: string; placed: string }[] }).workers ?? [];
  ok('keeper --from-words after the file was lost: the roster rebuilt from contacts and the agents\' directory', rb.status === 0 && ws.map((w) => w.worker).join() === '0,1,2'
    && ws[0]!.n === 1 && ws[0]!.did === w01.did && ws[1]!.placed === 'here' && ws[2]!.did === w2.did, rb.stdout + rb.stderr);
  ok('and the next new worker is 3', ((r) => r.status === 0 && (JSON.parse(r.stdout) as { worker: number; did: string }).did === derived(3, 0).did)(await cli(OP, ['enrol', '--name', 'four', '--here'])));

  // The operator identity rotates from the words, never randomly; a loss restores the rotation.
  const rr = await cli(OP, ['rotate'], { extra: { SIGELO_IDENTITY: human } });
  ok('rotate on the seed-derived operator identity: refused, exit 1, points to keeper --from-words --rotate-me', rr.status === 1 && rr.stderr.includes('keeper --from-words --rotate-me') && meDid() === opDid, rr.stderr);
  const rm1 = await cli(OP, ['keeper', '--from-words', '--rotate-me'], { input: words });
  const h1 = JSON.parse(readFileSync(human, 'utf8')) as { genesis: object; rotations: { body: { iat: number } }[]; derived: { n: number } };
  ok('keeper --from-words --rotate-me: rotation 1 of the words (identitySeed(S, 1)), the same original DID, marker n 1', rm1.status === 0 && meDid() === rootId(1).did
    && did(h1.genesis as never) === opDid && h1.rotations.length === 1 && h1.rotations[0]!.body.iat === 0 && h1.derived.n === 1 && JSON.parse(readFileSync(kfile, 'utf8')).me.n === 1, rm1.stderr);
  rmSync(human);
  const back1 = await cli(OP, ['keeper', '--from-words'], { input: words });
  ok('lost again: keeper --from-words restores rotation 1 (n from the keeper file)', back1.status === 0 && meDid() === rootId(1).did, back1.stderr);

  // The relay saw no key in clear: not the workers' seeds, not K (hex, base64, base64url, raw).
  const all = Buffer.concat(seen), forms = (b: Uint8Array): Buffer[] => [Buffer.from(Buffer.from(b).toString('hex')), Buffer.from(Buffer.from(b).toString('base64')), Buffer.from(Buffer.from(b).toString('base64url')), Buffer.from(b)];
  const leaked = [w0.seed, w01.seed, w2.seed, rootId(0).seed, rootId(1).seed, K, S].flatMap(forms).filter((f) => all.includes(f));
  ok(`the relay received ${all.length} bytes from clients, none of them a worker key, the operator key, K or S in clear`, all.length > 10000 && leaked.length === 0);
} finally {
  await relay.close();
  pm.s.close(); ph.s.close();
  for (const d of [D, OP, SRV, THIRD, FOURTH, FIFTH, OTHER]) rmSync(d, { recursive: true, force: true });
}
done(import.meta.filename);
