// SPDX-License-Identifier: MIT
// The contact verbs and the recovery key without a relay: recovery-key, init --recovery, erase-request,
// recover and the re_pair it leaves, accept's code parsing, send and send-file refused before anything
// connects, inbox and forget offline, held messages and files, exit codes; a short code fetched then
// refused (the long code printed); a recovery after a fork a relay saw first; on a loopback relay,
// `send <name> -` byte for byte and the inbox log read again by `history`.
//   node test-contact.ts
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { commitmentOf, keygen, verify, verifySig, type Genesis, type Rotation } from 'sigelo';
import { load } from './sigelo-agent.ts';
import { CLI, ROOT, NO_RELAY, cliIn, done, hasRelay, now, ok, posixModes, startTestRelay, tmpHome, type Bundle } from './test-helpers.ts';

// SIGELO_TEST_KEY_AGENT=1 (keyagent/test.mjs runs it so): the same checks with every key in a
// sigelo-key-agent on a temp socket; init writes {"provider":"agent"}, a recovered key is moved
// back into the agent (keys to-agent), and the stolen copy below cannot fork through it.
const KA: Record<string, string> = {};
let keyAgent: import('node:child_process').ChildProcess | undefined, agentHome = '';
if (process.env['SIGELO_TEST_KEY_AGENT'] === '1') {
  const { request } = await import('./sigelo-agent-keyclient.ts');
  agentHome = tmpHome('agent');
  const run = join(agentHome, 'run');
  mkdirSync(run, { mode: 0o700 });
  const sock = process.platform === 'win32' ? `\\\\.\\pipe\\sigelo-contact-test-${process.pid}` : join(run, 'agent.sock');
  keyAgent = spawn(process.execPath, [join(ROOT, 'keyagent', 'agent.mjs'), 'start', '--socket', sock, '--store', join(run, 'store'), '--store-plain'], { stdio: 'ignore' });
  for (let i = 0; i < 200; i++) { try { request({ op: 'list' }, { SIGELO_KEY_AGENT: sock }); break; } catch { await new Promise((r) => setTimeout(r, 50)); } }
  Object.assign(KA, { SIGELO_KEY_AGENT: sock, SIGELO_KEY_PROVIDER: 'agent' });
  console.log(`key agent mode: every key in sigelo-key-agent at ${sock}`);
}

// ── the recovery key from the CLI alone; re_pair; exit codes ───────────────────────────────
// recovery-key prints the public key alone and writes the secret 0600, never over a file, so
// `init --recovery "$(sigelo-agent recovery-key --out f)"` needs nothing else installed; recover signs
// the recovery rotation with it. A contact paired before the recovery is marked re_pair: nothing is
// sent to it. A contact verb with no identity exits 2; one that cannot reach the relay exits 1,
// naming the check on stderr, with its JSON on stdout.
{
  const H = tmpHome('rk');
  const env = { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: JSON.stringify({ 'relay.test': { mqtt: 'mqtt://127.0.0.1:1', http: 'http://127.0.0.1:1' } }), ...KA };
  const cli = (...args: string[]) => spawnSync('node', [CLI, ...args], { env, cwd: H, encoding: 'utf8' });
  const inv = cli('invite', '--name', 'x');
  ok('invite with no identity: exit 2, "no identity: run sigelo-agent init", no raw ENOENT', inv.status === 2 && inv.stderr.includes('no identity: run sigelo-agent init') && !inv.stderr.includes('ENOENT'), inv.stderr);
  const who = cli('whoami');
  ok('whoami with no identity: exit 2 and "run sigelo-agent init", as the contact verbs', who.status === 2 && who.stderr.includes('no identity: run sigelo-agent init') && who.stdout === '', who.stderr);
  const ad = cli('adopt', '--rotation', '{}');
  ok('adopt --rotation with no identity: exit 2, "no identity", not "does not load"', ad.status === 2 && ad.stderr.includes('no identity: run sigelo-agent init') && !ad.stderr.includes('does not load'), ad.stderr);
  const ver = cli('--version'), pkgVersion = (JSON.parse(readFileSync(join(import.meta.dirname, 'package.json'), 'utf8')) as { version: string }).version;
  ok('--version: the package version, exit 0', ver.status === 0 && ver.stdout === `${pkgVersion}\n`, `${ver.status} ${ver.stdout}${ver.stderr}`);
  const { tooOld } = await import('./node-check.ts');
  ok('node-check: 22.18 and newer pass, older refused', !tooOld('22.18.0') && !tooOld('24.18.1') && !tooOld('23.0.0') && tooOld('22.17.9') && tooOld('20.19.2') && tooOld('18.0.0'));
  const rk = cli('recovery-key', '--out', 'recovery.key'), keyFile = join(H, 'recovery.key'), key = rk.stdout.trim();
  const secret = existsSync(keyFile) ? readFileSync(keyFile, 'utf8') : '';
  ok('recovery-key: stdout is the public key alone; the secret, 64 hex, in a 0600 file, the public key in recovery.pub; the operator told to move both offline',
    rk.status === 0 && /^z[1-9A-HJ-NP-Za-km-z]+\n$/.test(rk.stdout) && /^[0-9a-f]{64}\n$/.test(secret) && (!posixModes || (statSync(keyFile).mode & 0o777) === 0o600) && rk.stderr.includes('offline')
      && readFileSync(join(H, 'recovery.pub'), 'utf8') === rk.stdout && rk.stderr.includes('recovery.pub'), rk.stderr);
  const again = cli('recovery-key', '--out', 'recovery.key');
  ok('recovery-key never overwrites a key file, and says init --recovery "$(…)" around it gets no key',
    again.status === 1 && again.stderr.includes('refusing to overwrite') && again.stderr.includes('No key printed') && readFileSync(keyFile, 'utf8') === secret, again.stderr);
  const nodir = cli('recovery-key', '--out', join('no-such-dir', 'recovery.key'));
  ok('recovery-key into a missing directory: exit 1, the verb and the file named, no bare ENOENT, nothing on stdout',
    nodir.status === 1 && nodir.stdout === '' && nodir.stderr.includes(`recovery-key: cannot write ${join('no-such-dir', 'recovery.key')} (its directory does not exist)`) && !nodir.stderr.includes('ENOENT'), nodir.stderr);
  const made = cli('init', '--recovery', key), g = JSON.parse(made.stdout || '{}') as { did: string; genesis: Genesis; recovery_key?: string };
  ok('init --recovery takes its output: the genesis commits to that key, and init prints the key', made.status === 0 && g.genesis.recovery === commitmentOf(key) && g.recovery_key === key, made.stderr);
  // A data request for sigelo.ai (relay/site/agents.md "Erasure"), signed by the recovery key.
  const er = cli('erase-request', '--recovery-key', 'recovery.key'), req = JSON.parse(er.stdout || '{}') as { body: Record<string, string>; recovery_key: string; sig: string; bundle: Bundle };
  ok('erase-request: a challenge for the original DID, ctx sigelo.ai/erase, nonce today\'s UTC date, signed by the recovery key, with the key and the chain',
    er.status === 0 && req.body?.typ === 'challenge' && req.body.did === g.did && req.body.ctx === 'sigelo.ai/erase' && req.body.nonce === new Date().toISOString().slice(0, 10)
      && req.recovery_key === key && verifySig(key, req.body, req.sig) && verify(req.bundle as never, now + 5).did === g.did && er.stderr.includes('SimpleX'), er.stderr);
  const ea = cli('erase-request', '--recovery-key', 'recovery.key', '--access');
  ok('erase-request --access: ctx sigelo.ai/access', ea.status === 0 && (JSON.parse(ea.stdout) as { body: { ctx: string } }).body.ctx === 'sigelo.ai/access', ea.stderr);
  cli('recovery-key', '--out', 'stranger.key');
  const es = cli('erase-request', '--recovery-key', 'stranger.key');
  ok('erase-request with another key: exit 1, "not this identity\'s recovery key", nothing on stdout', es.status === 1 && es.stdout === '' && es.stderr.includes('not this identity\'s recovery key'), es.stderr);
  // A contact paired before the recovery, as the carrier stores one (contact/store.mjs).
  const peer = keygen({ recovery: 'sha256:' + '1'.repeat(64) });
  writeFileSync(join(H, '.config', 'moadim', 'sigelo.local.contacts.json'), JSON.stringify({ v: 'sigelo-invite/0', self: g.did, invites: {}, accepts: {}, contacts: { [peer.did]: {
    name: 'peer', did: peer.did, current_did: peer.did, current_key: peer.key, revoked: false, chain: [peer.did], rotations: [], relay: 'relay.test', pair_key: '11'.repeat(32) } } }), { mode: 0o600 });
  ok('contacts before the recovery: no re_pair', (JSON.parse(cli('contacts').stdout) as { contacts: { re_pair: unknown }[] }).contacts[0]?.re_pair === null);
  // The four words of a pairing (contact/short.mjs), on stderr beside each live contact and in the JSON.
  const cl = cli('contacts'), words = (JSON.parse(cl.stdout) as { contacts: { fingerprint?: string }[] }).contacts[0]?.fingerprint ?? '';
  ok('contacts: "Check with them:" and four words per live contact, the same words in the JSON (fingerprint)',
    /^[a-z]+ [a-z]+ [a-z]+ [a-z]+$/.test(words) && cl.stderr.includes(`sigelo-agent: peer: Check with them: ${words}\n`), cl.stderr);
  // A short code is recognised by its shape, typed in two pieces, and fetched first: the relay is unreachable here.
  const sa = cli('accept', 'k7f3', 'q9zp');
  ok('accept K7F3-Q9ZP typed as "k7f3 q9zp", relay unreachable: exit 1 naming connect, no code_checksum, no answer stored',
    sa.status === 1 && /^sigelo-agent: connect: /m.test(sa.stderr) && !sa.stderr.includes('code_checksum') && (JSON.parse(cli('contacts').stdout) as { answers: unknown[] }).answers.length === 0, sa.stderr);
  ok('accept short, relay unreachable: says it cannot reach the relay, names the place, what to check, no raw "fetch failed"',
    sa.stderr.includes('cannot reach the relay at http://127.0.0.1:1/park/<code hash>') && sa.stderr.includes('SIGELO_RELAY') && !sa.stderr.includes('fetch failed'), sa.stderr);
  // Short or long by the input's shape (12 characters or fewer, no sgl1: short), before any parser:
  // a mistyped short code is never refused as "does not start with sgl1".
  const nu = cli('accept', 'K7F3-Q9ZU');
  ok('accept with a U: read as a short code, character 8 "U" named, the alphabet said, exit 1, no code_checksum',
    nu.status === 1 && nu.stderr.includes('short_code: "K7F3-Q9ZU" read as a short code') && nu.stderr.includes('character 8 "U" is not in the alphabet; a short code uses 0-9 and A-Z without I, L, O, U')
      && !nu.stderr.includes('code_checksum') && !nu.stderr.includes('sgl1:'), nu.stderr);
  const seven = cli('accept', 'K7F3-Q9Z');
  ok('accept with 7 characters: "7 characters, a short code has 8", exit 1', seven.status === 1 && seven.stderr.includes('7 characters, a short code has 8') && !seven.stderr.includes('code_checksum'), seven.stderr);
  const dot = cli('accept', 'K7F3-Q9ZP.');
  ok('accept with a leftover character: character 9 "." named, exit 1', dot.status === 1 && dot.stderr.includes('character 9 "." is not in the alphabet'), dot.stderr);
  const lg = cli('accept', 'hello-world-this-is-long');
  ok('accept of something long without sgl1: read as a long code, says so and how to paste it, exit 1',
    lg.status === 1 && lg.stderr.includes('code_checksum: read as a long code (it starts sgl1, or has more than 12 characters') && lg.stderr.includes('paste the whole code'), lg.stderr);
  const wt = cli('inbox', '--wait', '999');
  ok('inbox --wait 999: exit 2, the bound and the value said', wt.status === 2 && wt.stderr.includes('--wait: whole seconds, 0 to 300, not "999"'), wt.stderr);
  const noArg = cli('accept');
  ok('accept with no code: exit 2, the missing argument named', noArg.status === 2 && noArg.stderr.includes('an argument is missing: accept <code>'), noArg.stderr);
  // Exit 2 for a command line missing what it needs, as for an unknown flag.
  ok('invoice without --addr: exit 2', cli('invoice').status === 2);
  ok('verify-invoice without --bundle: exit 2', cli('verify-invoice', '{}').status === 2);
  ok('init with neither --recovery nor --no-recovery: exit 2', cli('init').status === 2);
  const badJson = cli('sign-challenge', '{"typ":"x"');
  ok('sign-challenge with broken JSON: exit 1, says the argument is not strict JSON', badJson.status === 1 && badJson.stderr.includes('sign-challenge: the argument is not strict JSON'), badJson.stderr);
  const notFile = cli('add-issuer', 'genesis.json');
  ok('add-issuer naming no file: "neither a file nor JSON", exit 1', notFile.status === 1 && notFile.stderr.includes('"genesis.json" is neither a file nor JSON'), notFile.stderr);
  // The profile: SIGELO_IDENTITY naming no file is said, so a mistyped profile is not taken for a lost identity.
  const prof = spawnSync('node', [CLI, 'whoami'], { env: { ...env, SIGELO_IDENTITY: join(H, 'sigelo.typo.local.json') }, cwd: H, encoding: 'utf8' });
  ok('whoami with SIGELO_IDENTITY naming no file: exit 2, the path and SIGELO_IDENTITY named', prof.status === 2 && prof.stderr.includes('sigelo.typo.local.json') && prof.stderr.includes('from SIGELO_IDENTITY'), prof.stderr);
  const missing = cli('recover', '--recovery-key', 'nope.key');
  ok('recover with a missing key file: exit 1, "recover: nope.key not found", no bare ENOENT',
    missing.status === 1 && missing.stderr.includes('recover: nope.key not found') && !missing.stderr.includes('ENOENT'), missing.stderr);
  cli('recovery-key', '--out', 'other.key');
  const wrong = cli('recover', '--recovery-key', 'other.key');
  ok('recover refuses a key that is not this identity\'s, and writes nothing',
    wrong.status === 1 && wrong.stderr.includes('not this identity\'s recovery key') && (JSON.parse(cli('whoami').stdout) as { chain: string[] }).chain.length === 1, wrong.stderr);
  const rec = cli('recover', '--recovery-key', 'recovery.key'), after = JSON.parse(rec.stdout || '{}') as { did: string; chain: string[] };
  if (keyAgent) ok('key agent mode: the recovered key moves to the agent', cli('keys', 'to-agent').status === 0);
  const rb = JSON.parse(cli('bundle').stdout) as Bundle & { rotations: Rotation[] };
  ok('recover: a recovery rotation from the last honest node (the genesis here), signed by that key; the bundle verifies to the new DID; told to pair again',
    rec.status === 0 && JSON.stringify(after.chain) === JSON.stringify([g.did, after.did]) && rb.rotations[0]?.body.reason === 'recovery'
      && verify(rb as never, now + 5).did === after.did && rec.stderr.includes('pair again') && rec.stderr.includes('clean machine') && !rec.stderr.includes('dropped'), rec.stderr);
  const listed = cli('contacts');
  ok('contacts after it: the peer is marked re_pair "own_recovery", and stderr says re-pair needed',
    (JSON.parse(listed.stdout) as { contacts: { re_pair: unknown }[] }).contacts[0]?.re_pair === 'own_recovery' && listed.stderr.includes('re-pair needed'), listed.stderr);
  const sent = cli('send', 'peer', 'hello');
  ok('send to it: exit 1, re_pair named, nothing queued', sent.status === 1 && /re_pair: this agent recovered its identity/.test(sent.stderr)
    && (JSON.parse(cli('contacts').stdout) as { contacts: { queued: number }[] }).contacts[0]?.queued === 0, sent.stderr);
  // send-file (contact/file.mjs): refused before anything connects when the file is missing, too
  // big or one of the identity's own; a file to a re_pair contact is refused as a message is.
  const sfArg = cli('send-file', 'peer');
  ok('send-file with no path: exit 2, the missing argument named', sfArg.status === 2 && sfArg.stderr.includes('an argument is missing: send-file <did|name> <path>'), sfArg.stderr);
  const sfMissing = cli('send-file', 'peer', 'nope.bin');
  ok('send-file of a missing file: exit 1, one line "file: cannot read nope.bin: no such file", no stack',
    sfMissing.status === 1 && sfMissing.stderr.trim() === 'sigelo-agent: file: cannot read nope.bin: no such file' && sfMissing.stdout === '', sfMissing.stderr);
  const sfDebug = spawnSync('node', [CLI, 'send-file', 'peer', 'nope.bin'], { env: { ...env, SIGELO_DEBUG: '1' }, cwd: H, encoding: 'utf8' });
  ok('send-file of a missing file, SIGELO_DEBUG=1: the cause (ENOENT) and the stack', sfDebug.status === 1 && sfDebug.stderr.includes('debug: caused by Error code=ENOENT') && sfDebug.stderr.includes('    at '), sfDebug.stderr);
  writeFileSync(join(H, 'big.bin'), Buffer.alloc(8 * 1024 * 1024 + 1));
  const sfBig = cli('send-file', 'peer', 'big.bin');
  ok('send-file of 8 MiB and a byte: exit 1, file_too_large', sfBig.status === 1 && sfBig.stderr.includes('file_too_large: big.bin is 8388609 bytes, at most 8388608 (8 MiB) a file'), sfBig.stderr);
  const sfOwn = cli('send-file', 'peer', join(H, '.config', 'moadim', 'sigelo.local.json'));
  ok('send-file of the identity file: exit 1, refused as one of its own files', sfOwn.status === 1 && sfOwn.stderr.includes('one of this agent\'s identity files'), sfOwn.stderr);
  writeFileSync(join(H, 'note.txt'), 'hello file\n');
  const sfRe = cli('send-file', 'peer', 'note.txt');
  ok('send-file to a re_pair contact: exit 1, re_pair named, nothing queued', sfRe.status === 1 && /re_pair: this agent recovered its identity/.test(sfRe.stderr)
    && (JSON.parse(cli('contacts').stdout) as { contacts: { queued: number }[] }).contacts[0]?.queued === 0, sfRe.stderr);
  const ib = cli('inbox', '--wait', '1');
  ok('inbox with the relay unreachable: exit 1, "offline" and the check on stderr, the JSON on stdout',
    ib.status === 1 && /^sigelo-agent: inbox: offline: connect: /m.test(ib.stderr) && typeof (JSON.parse(ib.stdout) as { offline?: string }).offline === 'string', ib.stderr);
  ok('inbox --expect, unreachable: exit 1, offline comes first', cli('inbox', '--expect').status === 1);
  ok('inbox, unreachable: one line, no stack, without SIGELO_DEBUG', !ib.stderr.includes('    at ') && !ib.stderr.includes('debug:'), ib.stderr);
  const dbg = spawnSync('node', [CLI, 'inbox'], { env: { ...env, SIGELO_DEBUG: '1' }, cwd: H, encoding: 'utf8' });
  ok('inbox, unreachable, SIGELO_DEBUG=1: the identity file, the relay and its endpoints, the cause chain and the stack on stderr',
    dbg.status === 1 && dbg.stderr.includes(`debug: identity file ${join(H, '.config', 'moadim', 'sigelo.local.json')}`) && dbg.stderr.includes('debug: relay relay.test at {"mqtt":"mqtt://127.0.0.1:1"')
      && dbg.stderr.includes('debug: error Error check=connect') && dbg.stderr.includes('debug: caused by TypeError') && dbg.stderr.includes('    at '), dbg.stderr);
  // A message held from a reader that went away, then the relay unreachable: printed and taken, so
  // exit 0 (a script that drops stdout on exit 1 would lose it), the offline still on stderr.
  const heldFile = join(H, '.config', 'moadim', 'sigelo.local.held.json');
  writeFileSync(heldFile, JSON.stringify({ messages: [{ from: peer.did, content: 'held one' }], events: [], dropped: {} }), { mode: 0o600 });
  const hb = cli('inbox'), hj = JSON.parse(hb.stdout || '{}') as { messages?: { content: string }[]; offline?: string };
  ok('inbox, unreachable, printing a held message: exit 0, the message on stdout and taken, the offline on stderr',
    hb.status === 0 && hj.messages?.[0]?.content === 'held one' && typeof hj.offline === 'string' && !existsSync(heldFile)
      && /^sigelo-agent: inbox: offline: connect: .*exit 0: the 1 message\(s\) on stdout are taken/m.test(hb.stderr), hb.stderr);
  // A file received (carrier.mjs #onFile), held: inbox prints the item and says where it is.
  const fileItem = { type: 'file', from: peer.did, contact: 'peer', name: 'report.pdf', size: 1536, sha256: 'ab'.repeat(32), path: '/x/sigelo.local.files/peer/abababab-report.pdf' };
  writeFileSync(heldFile, JSON.stringify({ messages: [fileItem], events: [], dropped: {} }), { mode: 0o600 });
  const fb = cli('inbox'), fj = JSON.parse(fb.stdout || '{}') as { messages?: { type?: string; path?: string }[] };
  ok('inbox with a file: the item on stdout, "📎 name size → path" on stderr', fb.status === 0 && fj.messages?.[0]?.type === 'file' && fj.messages[0].path === fileItem.path
    && fb.stderr.includes(`sigelo-agent: 📎 report.pdf 1.5 KiB → ${fileItem.path} (from peer)`), fb.stderr);
  const fg = cli('forget', peer.did), fr = JSON.parse(fg.stdout || '{}') as { revoked?: boolean; released?: boolean };
  ok('forget, unreachable: revoked here (JSON on stdout), exit 1 saying the mailboxes go later', fg.status === 1 && fr.revoked === true && fg.stderr.includes('offline'), fg.stderr);
  // An identity file that does not parse: named, and never "run init" (that makes another identity).
  writeFileSync(join(H, '.config', 'moadim', 'sigelo.local.json'), 'garbage\n', { mode: 0o600 });
  for (const verb of ['whoami', 'contacts']) {
    const bad = cli(verb);
    ok(`${verb} with an identity file that does not parse: exit 1, the file named, "do not run init"`,
      bad.status === 1 && bad.stderr.includes(`identity file ${join(H, '.config', 'moadim', 'sigelo.local.json')} does not load`) && bad.stderr.includes('do not run init'), bad.stderr);
  }
  rmSync(H, { recursive: true, force: true });
}

// ── a short code fetched, then refused: the long code it stood for is printed ───────────────
// GET /park answers once (the short code is spent); the long code it gives here has expired, so the
// accept fails after the fetch. The refusal names the long code, to keep and accept instead.
{
  const H = tmpHome('keep');
  const { createServer } = await import('node:http');
  const { pathToFileURL } = await import('node:url');
  const { makeInvite } = await import(pathToFileURL(join(ROOT, 'contact', 'invite.mjs')).href) as { makeInvite(o: object): { text: string } };
  const long = makeInvite({ did: keygen({ recovery: 'sha256:' + '2'.repeat(64) }).did, relay: 'relay.test', now: Math.floor(Date.now() / 1000) - 2 * 86400 }).text;
  const srv = createServer((_, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ ok: true, invite: long })); });
  await new Promise<void>((r) => { srv.listen(0, '127.0.0.1', () => r()); });
  const port = (srv.address() as { port: number }).port;
  const env = { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: JSON.stringify({ 'relay.test': { mqtt: 'mqtt://127.0.0.1:1', http: `http://127.0.0.1:${port}` } }), ...KA };
  const cli = (...args: string[]) => new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
    const c = spawn('node', [CLI, ...args], { env, cwd: H });
    let stdout = '', stderr = '';
    c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
    c.on('close', (status) => resolve({ status, stdout, stderr }));
  });
  await cli('init', '--no-recovery');
  const k = await cli('accept', 'K7F3-Q9ZP');
  ok('accept of a short code whose long code then fails: exit 1, the check, and the long code to keep and accept instead',
    k.status === 1 && k.stderr.includes('code_expired') && k.stderr.includes(`its long code: ${long} (keep this; accept it with the long code)`), k.stderr);
  // An answer that outlived its code (as the carrier stores one, contact/store.mjs): contacts says the pairing failed, in one line.
  const me = (JSON.parse((await cli('whoami')).stdout) as { did: string }).did, peer = keygen({ recovery: 'sha256:' + '3'.repeat(64) }).did, exp = Math.floor(Date.now() / 1000) - 60;
  writeFileSync(join(H, '.config', 'moadim', 'sigelo.local.contacts.json'), JSON.stringify({ v: 'sigelo-invite/0', self: me, invites: {}, contacts: {},
    accepts: { ['a'.repeat(64)]: { secret: '00'.repeat(32), code_did: peer, exp, name: 'alice', relay: 'relay.test', kem_sk: null, as: me } } }), { mode: 0o600 });
  const lc = await cli('contacts'), lj = JSON.parse(lc.stdout || '{}') as { answers?: unknown[]; failed?: { code: string; did: string }[] };
  ok('contacts after an answer outlived its code: failed lists it (code_expired), and one stderr line says the pairing failed and what to do',
    lc.status === 0 && lj.answers?.length === 0 && lj.failed?.[0]?.code === 'code_expired' && lj.failed[0].did === peer
      && lc.stderr.includes(`pairing with alice failed: code_expired: the code from alice expired at ${new Date(exp * 1000).toISOString().replace('.000', '')} before the inviter's agent replied: ask the inviter for a new code`), lc.stderr);
  srv.close();
  rmSync(H, { recursive: true, force: true });
}

// ── recover after a fork a relay saw first ─────────────────────────────────────────────────
// A thief copies the identity file. The owner rotates (on a schedule; no relay sees it yet), and
// the thief rotates from the same node and reaches the relay first: the relay now holds a fork at
// that node and refuses the owner. A recovery from the owner's head leaves that fork (SPEC §7.3);
// one from the last honest node (the genesis here) supersedes both voluntary rotations (§7.1), so
// a relay or contact holding the thief's rotation follows the recovery.
{
  const H = tmpHome('fork');
  const env = { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, ...KA };
  const cli = (...args: string[]) => spawnSync('node', [CLI, ...args], { env, cwd: H, encoding: 'utf8' });
  const g = JSON.parse(cli('init', '--recovery', cli('recovery-key').stdout.trim()).stdout || '{}') as { did: string };
  const idFile = join(H, '.config', 'moadim', 'sigelo.local.json'), stolen = join(H, 'stolen', 'sigelo.local.json');
  mkdirSync(join(H, 'stolen'), { mode: 0o700 });
  copyFileSync(idFile, stolen);
  cli('rotate');
  const thief = spawnSync('node', [CLI, 'rotate'], { env: { ...env, SIGELO_IDENTITY: stolen }, encoding: 'utf8' });
  if (keyAgent) {
    // The copy holds no key, and the agent rotates only from the current DID: no fork to recover from.
    ok('key agent mode: the stolen copy\'s rotate is refused (policy_did), nothing written', thief.status === 1 && thief.stderr.includes('policy_did') && load(stolen).rotations.length === 0, thief.stderr);
    const rec = cli('recover', '--recovery-key', 'recovery.key'), after = JSON.parse(rec.stdout || '{}') as { did: string; chain: string[] };
    ok('key agent mode: recover from the genesis still works, then the key moves to the agent', rec.status === 0 && after.chain?.[0] === g.did && cli('keys', 'to-agent').status === 0
      && cli('sign-challenge', JSON.stringify({ v: 'sigelo/0', typ: 'challenge', did: after.did, ctx: 'k3.test', nonce: 'zVtK1aCTZHfuBYaDyoFv5VS' })).status === 0, rec.stderr);
    rmSync(H, { recursive: true, force: true });
  } else {
    const thiefRotation = load(stolen).rotations[0]!;
    // What the relay verifies: the rotations it keeps (the thief's) merged into the bundle sent.
    const atRelay = (b: Bundle): string => { try { return verify({ ...b, rotations: [thiefRotation, ...b.rotations] } as never, now + 5).did; } catch (e) { return (e as Error).message; } };
    const forked = atRelay(JSON.parse(cli('bundle').stdout || '{}') as Bundle);
    ok('the owner\'s unseen rotation and the thief\'s from the same node: a fork wherever the thief\'s is held', /fork/.test(forked), forked);
    const rec = cli('recover', '--recovery-key', 'recovery.key'), after = JSON.parse(rec.stdout || '{}') as { did: string; chain: string[] };
    const rb = JSON.parse(cli('bundle').stdout || '{}') as Bundle & { rotations: Rotation[] };
    const merged = atRelay(rb);
    ok('recover after it: from the genesis, the owner\'s rotation dropped and said so; with the thief\'s merged in, the chain follows the recovery',
      rec.status === 0 && JSON.stringify(after.chain) === JSON.stringify([g.did, after.did]) && rb.rotations.length === 1 && rb.rotations[0]?.body.id === g.did
        && merged === after.did && rec.stderr.includes('The 1 rotation(s) after'), `${merged}; ${rec.stderr}`);
    rmSync(H, { recursive: true, force: true });
  }
}

// ── stdin, byte for byte; the inbox log (history) ──────────────────────────────────────────
// A reviewer's first message, ~1.9 KB and many lines through `send operator -`, was reported cut
// "after the first lines". Each body here goes through stdin, a loopback relay and `inbox`, and must
// come back exactly: blank lines, CRLF, no final newline, 1.9 KB. One final line end (LF or CRLF) is
// what echo and heredocs add: dropped, nothing else. Then inbox's output is lost (a reader that
// filtered it): `history` prints the same messages again from <identity>.inbox.log (0600), no relay.
{
  if (!hasRelay()) console.log(`SKIP stdin round trip: ${NO_RELAY}`);
  else {
    const H = tmpHome('stdin'), relay = await startTestRelay(H), endpoints = JSON.stringify(relay.endpoints);
    const envOf = (n: string): Record<string, string | undefined> => ({ PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: join(H, `${n}.local.json`), SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: endpoints, ...KA });
    const cli = (n: string, ...args: string[]) => cliIn(envOf(n), H)(...args);
    const piped = (n: string, input: string, ...args: string[]) => new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
      const c = spawn('node', [CLI, ...args], { env: envOf(n), cwd: H });
      let stdout = '', stderr = '';
      c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
      c.on('close', (status) => resolve({ status, stdout, stderr }));
      c.stdin.end(Buffer.from(input, 'utf8'));
    });
    try {
      for (const n of ['rev', 'op']) await cli(n, 'init', '--no-recovery');
      const code = (await cli('op', 'invite', '--long', '--name', 'rev')).stdout.trim();
      const acc = await cli('rev', 'accept', code, '--name', 'operator', '--wait', '0');
      await cli('op', 'inbox'); await cli('rev', 'inbox');
      ok('stdin: rev and op paired over the loopback relay', acc.status === 0 && (JSON.parse((await cli('op', 'contacts')).stdout) as { contacts: unknown[] }).contacts.length === 1, acc.stderr);
      const line = (i: number): string => `line ${String(i).padStart(2, '0')}: the quick brown fox jumps over the lazy dog, again and again.`;
      const long = Array.from({ length: 27 }, (_, i) => line(i)).join('\n');
      const bodies: [string, string, string][] = [
        ['blank lines', 'first\n\nthird\n\n\nsixth\n \n\tlast', 'first\n\nthird\n\n\nsixth\n \n\tlast'],
        ['CRLF, no final newline', 'one\r\ntwo\r\n\r\nfour', 'one\r\ntwo\r\n\r\nfour'],
        ['CRLF with a final CRLF', 'one\r\ntwo\r\n', 'one\r\ntwo'],
        ['no final newline', 'no newline at the end', 'no newline at the end'],
        ['a final LF, and blank lines before it', 'a\n\n\nb\n\n\n', 'a\n\n\nb\n\n'],
        [`${long.length} bytes, 27 lines`, `${long}\n`, long],
        ['unicode and a lone CR', 'naïve 🦀\rafter CR\n— end', 'naïve 🦀\rafter CR\n— end'],
      ];
      ok('stdin: the long body is about 1.9 KB', long.length > 1850 && long.length < 2000, String(long.length));
      for (const [, input] of bodies) {
        const r = await piped('rev', input, 'send', 'operator', '-');
        if (r.status !== 0) ok(`send - (${JSON.stringify(input.slice(0, 20))}): exit 0`, false, r.stderr);
      }
      const ib = await cli('op', 'inbox', '--wait', '10'), got = (JSON.parse(ib.stdout || '{}') as { messages?: { content: unknown; received: number }[] }).messages ?? [];
      ok(`stdin: ${bodies.length} messages arrive, in order`, ib.status === 0 && got.length === bodies.length, `${got.length}: ${ib.stderr}`);
      bodies.forEach(([what, , want], i) => ok(`send - round trip, byte for byte: ${what}`, got[i]?.content === want, JSON.stringify(got[i]?.content)));
      // The inbox log: written before the output, the same items, 0600; history prints them again.
      const logFile = join(H, 'op.local.inbox.log');
      ok('inbox log: <identity>.inbox.log beside the identity, 0600, one line per message', existsSync(logFile) && (!posixModes || (statSync(logFile).mode & 0o777) === 0o600)
        && readFileSync(logFile, 'utf8').trim().split('\n').length === bodies.length);
      const again = await cli('op', 'inbox');
      ok('inbox again: nothing (each message shown once)', ((JSON.parse(again.stdout) as { messages: unknown[] }).messages).length === 0);
      const h = await cli('op', 'history'), hm = (JSON.parse(h.stdout || '{}') as { messages?: { content: unknown }[] }).messages ?? [];
      ok('history: the same messages again, byte for byte, no relay needed', h.status === 0 && hm.length === bodies.length && hm.every((m, i) => m.content === bodies[i]![2]), h.stderr);
      const hs = await cli('op', 'history', '--since', '3600'), hf = await cli('op', 'history', '--since', '2099-01-01T00:00:00Z');
      ok('history --since 3600 (seconds ago): all; --since a future ISO time: none, said on stderr',
        (JSON.parse(hs.stdout) as { messages: unknown[] }).messages.length === bodies.length && (JSON.parse(hf.stdout) as { messages: unknown[] }).messages.length === 0 && hf.stderr.includes('history: nothing'), hf.stderr);
      const hb = await cli('op', 'history', '--since', 'yesterday');
      ok('history --since yesterday: exit 2, the forms named', hb.status === 2 && hb.stderr.includes('an ISO time'), hb.stderr);
      const sf = await cli('op', 'send-file', 'rev', logFile);
      ok('send-file of the inbox log: refused (one of the identity\'s own files)', sf.status === 1 && sf.stderr.includes('inbox log'), sf.stderr);
    } finally {
      await relay.close?.();
      rmSync(H, { recursive: true, force: true });
    }
  }
}

// ── invite --relay, accept --relay: a pairing on a relay other than SIGELO_RELAY ───────────
// Both agents' SIGELO_RELAY is relay.test; op invites on corp.test. The short code is parked there
// and carries its relay tag; rev knows no relay with that tag, so an accept without --relay is asked
// to name it (relay_tag); with --relay
// corp.test it pairs, contacts shows corp.test, and a message goes over it.
{
  if (!hasRelay()) console.log(`SKIP invite --relay: ${NO_RELAY}`);
  else {
    const H = tmpHome('corp'), home = await startTestRelay(H), corp = await startTestRelay(H, 'corp.test');
    const endpoints = JSON.stringify({ ...home.endpoints, ...corp.endpoints });
    const envOf = (n: string): Record<string, string | undefined> => ({ PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_IDENTITY: join(H, `${n}.local.json`), SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: endpoints, ...KA });
    const cli = (n: string, ...args: string[]) => cliIn(envOf(n), H)(...args);
    try {
      for (const n of ['rev', 'op']) await cli(n, 'init', '--no-recovery');
      const bad = await cli('op', 'invite', '--relay', 'Corp Test');
      ok('invite --relay with no host: exit 1, the relay check, before anything connects', bad.status === 1 && bad.stderr.includes('--relay "Corp Test": want a lowercase host[:port]'), bad.stderr);
      const inv = await cli('op', 'invite', '--relay', 'corp.test', '--json', '--name', 'rev'), j = JSON.parse(inv.stdout || '{}') as { short?: string; relay?: string };
      ok('invite --relay corp.test: a 12-character short code ending in corp.test\'s relay tag, the code names corp.test, the accept line says --relay corp.test if asked',
        inv.status === 0 && /^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(j.short ?? '') && j.relay === 'corp.test' && inv.stderr.includes(`accept ${j.short} --name <your name> (made on corp.test: if it asks which relay, --relay corp.test)`), inv.stderr);
      const miss = await cli('rev', 'accept', j.short!, '--wait', '0');
      ok('accept of it without --relay, no relay known with its tag (registry off): relay_tag, asked for --relay', miss.status === 1 && miss.stderr.includes('relay_tag')
        && miss.stderr.includes('was made on a relay this agent does not know') && miss.stderr.includes('accept it with --relay <host>'), miss.stderr);
      const acc = await cli('rev', 'accept', j.short!, '--relay', 'corp.test', '--name', 'operator', '--wait', '0');
      await cli('op', 'inbox'); await cli('rev', 'inbox');
      const listed = (JSON.parse((await cli('op', 'contacts')).stdout || '{}') as { contacts?: { relay?: string }[] }).contacts ?? [];
      const theirs = (JSON.parse((await cli('rev', 'contacts')).stdout || '{}') as { contacts?: { relay?: string }[] }).contacts ?? [];
      ok('accept --relay corp.test: paired, and contacts shows corp.test on both sides', acc.status === 0 && listed.length === 1 && listed[0]?.relay === 'corp.test' && theirs[0]?.relay === 'corp.test', acc.stderr);
      const sent = await cli('rev', 'send', 'operator', 'over corp');
      const got = JSON.parse((await cli('op', 'inbox', '--wait', '10')).stdout || '{}') as { messages?: { content: unknown }[] };
      ok('a message goes over corp.test', sent.status === 0 && got.messages?.[0]?.content === 'over corp', sent.stderr);
    } finally {
      await home.close?.(); await corp.close?.();
      rmSync(H, { recursive: true, force: true });
    }
  }
}

// ── one rule for which identity (ENROL.md "Which identity") ───────────────────────────────
// The operator runs contact verbs on their own file while the shell names an agent (SIGELO_IDENTITY):
// --identity <file>, or --operator ($SIGELO_HUMAN, else ~/.config/sigelo/me.local.json). Beside a
// watch on that file, however it was named, send queues for it and inbox reads what it got. The
// operator role still refuses a file in an agents' directory.
{
  if (!hasRelay()) console.log(`SKIP which identity: ${NO_RELAY}`);
  else {
    const H = tmpHome('which'), relay = await startTestRelay(H), endpoints = JSON.stringify(relay.endpoints);
    const me = join(H, '.config', 'sigelo', 'me.local.json'), rev = join(H, 'agents', 'rev.local.json');
    const base = { PATH: process.env['PATH'], SIGELO_KEY_PROVIDER: 'file', HOME: H, SIGELO_RELAY: 'relay.test', SIGELO_SHORT_RELAY: 'relay.test', SIGELO_RELAY_REGISTRY: 'off', SIGELO_RELAY_ENDPOINTS: endpoints, ...KA };
    // The shell names the agent; SIGELO_HUMAN names the operator.
    const env = { ...base, SIGELO_IDENTITY: rev, SIGELO_HUMAN: me };
    const cli = (...args: string[]) => cliIn(env, H)(...args), plain = (...args: string[]) => cliIn({ ...base, SIGELO_IDENTITY: rev }, H)(...args);
    const json = (r: { stdout: string }): Record<string, unknown> => { try { return JSON.parse(r.stdout) as Record<string, unknown>; } catch { return {}; } };
    let w: import('node:child_process').ChildProcess | undefined;
    try {
      const mk = await plain('init', '--no-recovery', '--identity', me), mkr = await plain('init', '--no-recovery');
      const opDid = (json(mk) as { did?: string }).did, revDid = (json(mkr) as { did?: string }).did;
      const who = await plain('whoami', '--operator'), whoF = await plain('whoami', '--identity', me);
      ok('init/whoami --identity <file> and whoami --operator (default ~/.config/sigelo/me.local.json): the operator file, not SIGELO_IDENTITY',
        mk.status === 0 && existsSync(me) && json(who)['did'] === opDid && json(whoF)['did'] === opDid && opDid !== revDid, who.stderr + whoF.stderr);
      ok('init --operator: refused (the operator identity comes from the words), exit 2', ((r) => r.status === 2 && r.stderr.includes('keeper --from-words'))(await plain('init', '--operator', '--no-recovery')));
      const code = (await cli('invite', '--long', '--name', 'rev', '--operator')).stdout.trim();
      const acc = await cli('accept', code, '--name', 'operator', '--wait', '0');
      await cli('inbox', '--operator'); await cli('inbox');
      const listed = (r: { stdout: string }): string[] => ((json(r)['contacts'] ?? []) as { did: string }[]).map((c) => c.did);
      const cF = await plain('contacts', '--identity', me), cH = await cli('contacts', '--operator');
      ok('contacts --identity <operator file> and SIGELO_HUMAN + --operator: the operator\'s contact (rev), not the agent\'s', acc.status === 0
        && listed(cF).join() === revDid && listed(cH).join() === revDid && listed(await cli('contacts')).join() === opDid, cF.stderr + cH.stderr + acc.stderr);
      const tierOf = (f: string): string | undefined => (Object.values((JSON.parse(readFileSync(f.replace(/\.json$/, '.contacts.json'), 'utf8')) as { contacts: Record<string, { tier: string }> }).contacts)[0])?.tier;
      const t1 = await cli('tier', 'rev', 'quiet', '--operator'), q = tierOf(me), t2 = await plain('tier', 'rev', 'friend', '--identity', me);
      ok('tier on the operator file: via SIGELO_HUMAN + --operator (quiet), via --identity (friend); the agent\'s contacts untouched',
        t1.status === 0 && q === 'quiet' && t2.status === 0 && tierOf(me) === 'friend' && tierOf(rev) !== 'quiet', t1.stderr + t2.stderr);
      const s1 = await plain('send', 'rev', 'by --identity', '--identity', me), s2 = await cli('send', 'rev', 'by SIGELO_HUMAN', '--operator');
      const got = ((json(await cli('inbox', '--wait', '10')).messages ?? []) as { content: unknown; from: string }[]);
      ok('send on the operator file via --identity and via SIGELO_HUMAN + --operator: both arrive from the operator\'s DID', s1.status === 0 && s2.status === 0
        && got.length === 2 && got.every((m) => m.from === opDid), JSON.stringify(got) + s1.stderr + s2.stderr);
      const back = await cli('send', 'operator', 'to you'), ib = await cli('inbox', '--wait', '10', '--operator', '--quiet-too');
      const hF = await plain('history', '--identity', me), hH = await cli('history', '--operator');
      const contents = (r: { stdout: string }): unknown[] => ((json(r)['messages'] ?? []) as { content: unknown }[]).map((m) => m.content);
      ok('history on the operator file via --identity and via SIGELO_HUMAN + --operator: what its inbox gave out', back.status === 0 && contents(ib).join() === 'to you'
        && contents(hF).join() === 'to you' && contents(hH).join() === 'to you', ib.stderr + hF.stderr);
      const sameEnv = await cliIn({ ...base, SIGELO_IDENTITY: me }, H)('contacts', '--operator');
      ok('SIGELO_IDENTITY = the operator file, with --operator: taken as the operator\'s (one line), not refused', sameEnv.status === 0 && listed(sameEnv).join() === revDid
        && sameEnv.stderr.includes('SIGELO_IDENTITY names your operator identity'), sameEnv.stderr);
      // The one-owner rule, the file named three ways: a watcher by --operator; send by --identity
      // queues for it; inbox by SIGELO_HUMAN reads through it; invite refuses (busy).
      w = spawn('node', [CLI, 'watch', '--operator', '--quiet'], { env, cwd: H });
      let werr = '';
      w.stderr!.on('data', (d) => { werr += d; });
      for (let i = 0; i < 150 && !werr.includes('connected to relay.test'); i++) await new Promise((r) => setTimeout(r, 200));
      const sq = await plain('send', 'rev', 'queued', '--identity', me), iq = await cli('inbox', '--operator'), bz = await plain('invite', '--identity', me);
      ok('watch --operator owns the session: send --identity queues for it, inbox --operator reads through it, invite --identity refuses busy',
        werr.includes('connected to relay.test') && sq.status === 0 && sq.stderr.includes('queued for sigelo-agent watch') && iq.status === 0
        && iq.stderr.includes('holds the relay session') && bz.status === 1 && bz.stderr.includes('is watched by sigelo-agent watch'), werr + sq.stderr + iq.stderr + bz.stderr);
      w.kill('SIGTERM'); await new Promise((r) => w!.once('close', r)); w = undefined;
      const inA = await cliIn({ ...base, SIGELO_IDENTITY: rev, SIGELO_HUMAN: join(H, 'agents', 'me.local.json') }, H)('contacts', '--operator');
      const inD = await cliIn({ ...base, SIGELO_IDENTITY: rev }, H)('tier', 'rev', 'own', '--operator', '--identity', join(H, '.config', 'moadim', 'me.local.json'));
      ok('--operator on a file in an agents\' directory (SIGELO_IDENTITY\'s, or the default\'s): refused, exit 2', inA.status === 2 && inA.stderr.includes('in the agents\' directory')
        && inD.status === 2 && inD.stderr.includes('in the agents\' directory'), inA.stderr + inD.stderr);
    } finally {
      if (w) { w.kill('SIGTERM'); await new Promise((r) => w!.once('close', r)); }
      await relay.close?.();
      rmSync(H, { recursive: true, force: true });
    }
  }
}

if (keyAgent) { keyAgent.kill(); await new Promise((r) => keyAgent!.once('exit', r)); rmSync(agentHome, { recursive: true, force: true }); }
done(import.meta.filename);
