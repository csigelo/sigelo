#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// sigelo-key-agent (KEYS.md): holds identity keys and signs known sigelo bodies
// over a local socket, as ssh-agent does, so the model and the MCP server hold a socket path and an
// identity file saying {"provider":"agent"}, never the key. No network listener, no request that
// returns a key, no dependency beyond sigelo, sigelo-agent and node: modules.
//   sigelo-key-agent start [--socket <path>] [--store <dir>] [--store-plain] [--allow-payments]
//                          [--allow-attest <ctx>]… [--idle <seconds>]
//   sigelo-key-agent install-unit [--print] [start flags]   systemd user unit or LaunchAgent
//   sigelo-key-agent list | lock                            ask the running agent
// The socket: SIGELO_KEY_AGENT, else $XDG_RUNTIME_DIR/sigelo/agent.sock (Linux), $TMPDIR/sigelo/
// agent.sock (macOS), \\.\pipe\sigelo-agent-<user> (Windows), in a 0700 directory of this uid
// (else socket_dir_unsafe), created under umask 077. One log line per request on stderr: op, DID,
// typ, outcome; never a body or a key.
import { randomBytes } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { homedir } from 'node:os';
import { dirname, join, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { check } from './policy.mjs';
import { encode, keychain, keyclient, MAX_LINE, parseRequest, refuse, refusalOf, ROTATE_TO, S } from './protocol.mjs';
import { current, dataDir, head, openStore, pendingDid, privateDir } from './store.mjs';

const rfc3339 = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

/**
 * The agent without its socket: `handle(bytes)` answers one request line. `rand` and `now` are
 * injectable so the fixture's replies are byte-exact (keyagent/fixtures/protocol-v0.json).
 */
export function createAgent({ store: dir, plain = false, allowPayments = false, allowAttest = [], rand = randomBytes, now = Date.now, log = (l) => process.stderr.write(`sigelo-key-agent: ${l}\n`) }) {
  const store = openStore(dir, { plain }), opts = { allowPayments, allowAttest };
  const fresh = (recovery) => S.keygen({ recovery, seed: new Uint8Array(rand(32)), created: rfc3339(now()), nonce: new Uint8Array(rand(16)) });
  /** The entry of `did`, which must be its current DID; naming its pending rotation's DID commits it. */
  const held = (did) => {
    const e = store.find(did) ?? refuse('key_unknown', `this agent holds no key for ${did}`);
    if (pendingDid(e) === did) store.commit(e);
    if (current(e) !== did) refuse('policy_did', `${did} is not the current DID of this identity (${current(e)}): the identity file is behind`);
    return e;
  };
  const OPS = {
    list: () => ({ ok: true, keys: store.entries.map((e) => ({ did: current(e), key: head(e).key, form: store.formOf(e) })) }),
    create: ({ recovery }) => {
      let id;
      try { id = fresh(recovery); } catch (e) { refuse('request_invalid', e.message); }
      try { return { ok: true, genesis: store.add(id.genesis, id.secret).chain.genesis }; } finally { id.secret.fill(0); }
    },
    import: ({ genesis, seed }) => {
      try { S.structure(genesis, 'genesis'); } catch (e) { refuse('request_invalid', e.message); }
      const d = S.did(genesis), bytes = Uint8Array.from(Buffer.from(seed, 'hex')), probe = { v: 'sigelo-key-agent/0', typ: 'import', did: d };
      try {
        if (!S.verifySig(genesis.key, probe, S.sign(bytes, probe))) refuse('key_mismatch', `the seed is not the key of ${d}`);
        if (store.find(d)) refuse('key_held', `this agent holds ${d} already`);
        store.add(genesis, bytes);
      } finally { bytes.fill(0); }
      return { ok: true, did: d };
    },
    pubkey: ({ did }) => ({ ok: true, key: head(held(did)).key }),
    sign: ({ did, body }) => {
      const e = held(did);
      check(body, did, store.asStore(e), opts);
      return { ok: true, sig: store.withSeed(e, (seed) => S.sign(seed, body)) };
    },
    rotate: ({ did, to }) => {
      if (ROTATE_TO[to]) refuse('key_provider_unbuilt', `rotate to ${to}: hardware keys arrive with milestone ${ROTATE_TO[to]}`);
      const e = held(did);
      if (e.pending) return { ok: true, rotation: e.pending.rotation };   // a caller that died before writing it gets the same one
      const cur = head(e), next = fresh(cur.recovery);
      try {
        const rotation = store.withSeed(e, (secret) => S.rotate({ genesis: cur, next_genesis: next.genesis, iat: Math.floor(now() / 1000), reason: 'voluntary', secret, next_secret: next.secret }));
        store.pend(e, rotation, next.secret);
        return { ok: true, rotation };
      } finally { next.secret.fill(0); }
    },
    commit: ({ did }) => {
      const e = store.find(did) ?? refuse('key_unknown', `this agent holds no key for ${did}`);
      if (pendingDid(e) === did) store.commit(e);
      else if (current(e) !== did || e.pending) refuse('policy_did', `${did} is not the pending rotation's DID ${pendingDid(e) ?? '(none pending)'} nor the current one without a rotation pending`);
      return { ok: true };
    },
    lock: () => { store.lock(); return { ok: true }; },
  };
  return {
    store,
    handle(bytes) {
      let req, reply;
      try { req = parseRequest(bytes); reply = OPS[req.op](req); } catch (e) { reply = refusalOf(e); }
      const typ = req?.op === 'sign' && typeof req.body?.typ === 'string' ? req.body.typ : '-';
      log(`${req?.op ?? '?'} ${typeof req?.did === 'string' ? req.did : '-'} ${typ} ${reply.ok ? 'ok' : reply.code}`);
      return reply;
    },
  };
}

/** Is something listening at `path`? (A stale socket file from a killed agent is not.) */
const answers = (path) => new Promise((res) => {
  const s = connect(path, () => { s.destroy(); res(true); });
  s.on('error', () => res(false));
});

/** Listen on `socket`: the directory checked first, a live agent never replaced, umask 077. */
export async function startAgent({ socket, idle = 0, ...opts }) {
  // The store is keychain-wrapped where an OS store answers (§4.4); else the operator says --store-plain, never we.
  if (!opts.plain && !keychain.answers(keychain.systemKeychain())) refuse('keychain_unavailable', 'no OS keychain answers here for the key store: start with --store-plain (an agent running as its own user, key providers §4.6)');
  if (process.platform !== 'win32') privateDir(dirname(socket), 'socket_dir_unsafe');
  if (await answers(socket)) refuse('key_agent_running', `an agent already answers at ${socket}`);
  if (process.platform !== 'win32' && existsSync(socket) && lstatSync(socket).isSocket()) unlinkSync(socket);
  const agent = createAgent(opts);
  let timer;
  const touch = () => { if (!idle) return; clearTimeout(timer); timer = setTimeout(() => agent.store.lock(), idle * 1000); timer.unref(); };
  const server = createServer((c) => {
    let buf = Buffer.alloc(0), over = false;
    c.on('error', () => {});
    c.on('data', (d) => {   // one reply per line, in order; a line over MAX_LINE is refused and the connection ends
      if (over) return;
      buf = Buffer.concat([buf, d]);
      for (let i = buf.indexOf(10); i >= 0 || buf.length > MAX_LINE; i = buf.indexOf(10)) {
        const line = i < 0 ? buf : buf.subarray(0, i);
        buf = i < 0 ? Buffer.alloc(0) : buf.subarray(i + 1);
        touch();
        const reply = encode(agent.handle(line));
        if (line.length > MAX_LINE) { over = true; c.end(reply); return; }
        c.write(reply);
      }
    });
  });
  const mask = process.umask(0o077);
  try { await new Promise((res, rej) => { server.once('error', rej); server.listen(socket, res); }); } finally { process.umask(mask); }
  return { agent, server, close: () => new Promise((res) => { clearTimeout(timer); agent.store.lock(); server.close(() => res()); }) };
}

// ── the command line ──────────────────────────────────────────────────────────────────────
const HERE = dirname(fileURLToPath(import.meta.url));
const USAGE = `usage: sigelo-key-agent start [--socket <path>] [--store <dir>] [--store-plain] [--allow-payments] [--allow-attest <ctx>]… [--idle <seconds>]
       sigelo-key-agent install-unit [--print] [start flags]
       sigelo-key-agent list | lock`;
function flags(args) {
  const o = { allowAttest: [], rest: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i], val = () => args[++i] ?? refuse('usage', `${a} needs a value\n${USAGE}`);
    if (a === '--socket') o.socket = val();
    else if (a === '--store') o.store = val();
    else if (a === '--store-plain') o.plain = true;
    else if (a === '--allow-payments') o.allowPayments = true;
    else if (a === '--allow-attest') o.allowAttest.push(val());
    else if (a === '--idle') { o.idle = Number(val()); if (!Number.isSafeInteger(o.idle) || o.idle < 0) refuse('usage', '--idle: whole seconds'); }
    else if (a === '--print') o.print = true;
    else refuse('usage', `${JSON.stringify(a)} is not a flag here\n${USAGE}`);
    if (a !== '--print') o.rest.push(a, ...(['--store-plain', '--allow-payments'].includes(a) ? [] : [args[i]]));
  }
  return o;
}

/** The systemd user unit or LaunchAgent for these start flags, the socket fixed to where the clients look. */
export function unit(platform, f, env = process.env) {
  if (platform !== 'linux' && platform !== 'darwin') refuse('usage', 'install-unit writes a systemd user unit (Linux) or a LaunchAgent (macOS); on Windows start the agent by hand');
  const argv = [process.execPath, join(HERE, 'agent.mjs'), 'start', ...(f.socket ? [] : ['--socket', keyclient.socketPath(env, platform)]), ...f.rest];
  const tpl = readFileSync(join(HERE, 'units', platform === 'linux' ? 'sigelo-key-agent.service' : 'io.sigelo.key-agent.plist'), 'utf8');
  const xml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const args = platform === 'linux' ? argv.map((a) => `"${a.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%')}"`).join(' ') : argv.map((a) => `\t\t<string>${xml(a)}</string>`).join('\n');
  // The unit is for a POSIX host, so its path is joined the POSIX way even when generated elsewhere.
  return { path: platform === 'linux' ? posix.join(env.XDG_CONFIG_HOME || posix.join(homedir(), '.config'), 'systemd', 'user', 'sigelo-key-agent.service') : posix.join(homedir(), 'Library', 'LaunchAgents', 'io.sigelo.key-agent.plist'), text: tpl.replace('@ARGS@', args) };
}

async function main(argv) {
  const [cmd, ...args] = argv;
  if (cmd === 'start') {
    const f = flags(args);
    const socket = f.socket ?? keyclient.socketPath(process.env), store = f.store ?? dataDir();
    const a = await startAgent({ socket, store, plain: f.plain, allowPayments: f.allowPayments, allowAttest: f.allowAttest, idle: f.idle });
    for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { a.close().then(() => process.exit(0)); });
    process.stderr.write(`sigelo-key-agent: listening at ${socket}, store ${store} (${f.plain ? 'plain' : 'keychain'})\nSIGELO_KEY_AGENT=${socket}\n`);
    return;
  }
  if (cmd === 'install-unit') {
    const f = flags(args), u = unit(process.platform, f);
    if (f.print) { process.stdout.write(u.text); return; }
    if (existsSync(u.path)) refuse('unit_exists', `${u.path} exists: remove it first, or --print to see the new one`);
    mkdirSync(dirname(u.path), { recursive: true });
    writeFileSync(u.path, u.text, { mode: 0o644 });
    process.stdout.write(`${u.path}\n`);
    process.stderr.write(process.platform === 'linux' ? 'sigelo-key-agent: now systemctl --user enable --now sigelo-key-agent\n' : `sigelo-key-agent: now launchctl bootstrap gui/$(id -u) ${u.path}\n`);
    return;
  }
  if (cmd === 'list' || cmd === 'lock') { process.stdout.write(`${JSON.stringify(keyclient.request({ op: cmd }), null, 2)}\n`); return; }
  refuse('usage', USAGE);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === (await import('node:fs')).realpathSync(process.argv[1])) {
  main(process.argv.slice(2)).catch((e) => {
    const r = refusalOf(e);
    process.stderr.write(`sigelo-key-agent: ${r.code === 'usage' ? '' : `${r.code}: `}${r.detail}\n`);
    process.exit(r.code === 'usage' ? 2 : 1);
  });
}
