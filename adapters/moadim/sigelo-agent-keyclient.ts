// SPDX-License-Identifier: MIT
/**
 * Provider `agent` (design/key-providers.md §4): this process never holds the key and asks
 * `sigelo-key-agent` (keyagent/) over its socket. Synchronous, as every signing call site is: one
 * worker thread, started on first use and unref'd, talks to the socket; the caller blocks on
 * `Atomics.wait` and takes the reply with `receiveMessageOnPort`. The worker is an inline string,
 * so a bundle (plugins/build.mjs) stays one file. Fails closed by name, never falls back to a key:
 *   key_agent_unavailable  nothing answers at the socket within 2 s
 *   key_agent_timeout      no reply within 60 s (a touch not given)
 *   <the agent's code>     a refusal (policy_typ, policy_did, policy_rotation, key_unknown, …)
 */
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { MessageChannel, type MessagePort, receiveMessageOnPort, Worker } from 'node:worker_threads';
import { parseBytes, SigeloError } from 'sigelo';

export type Env = Record<string, string | undefined>;
export const CONNECT_MS = 2000, REPLY_MS = 60000;
const fail = (code: string, detail: string): never => { throw Object.assign(new SigeloError(`${code}: ${detail}`), { check: code }); };

/** §4.1: SIGELO_KEY_AGENT, else the platform's default; the agent listens where the client looks. */
export function socketPath(env: Env = process.env, platform: string = process.platform): string {
  if (env['SIGELO_KEY_AGENT']) return env['SIGELO_KEY_AGENT'];
  if (platform === 'win32') return `\\\\.\\pipe\\sigelo-agent-${userInfo().username}`;
  if (platform === 'darwin') return join(env['TMPDIR'] || tmpdir(), 'sigelo', 'agent.sock');
  return env['XDG_RUNTIME_DIR'] ? join(env['XDG_RUNTIME_DIR'], 'sigelo', 'agent.sock') : join(tmpdir(), `sigelo-${userInfo().uid}`, 'agent.sock');
}

// One request per message: connect (2 s), write the line, read to the first newline (60 s). The
// reply goes back as bytes, for sigelo's strict parser; the flag wakes the blocked caller.
const WORKER = `const net = require('node:net'), { workerData: { port, flag } } = require('node:worker_threads');
port.on('message', ({ id, path, line }) => {
  let got = Buffer.alloc(0), done = false, timer;
  const end = (m) => { if (done) return; done = true; clearTimeout(timer); s.destroy(); port.postMessage({ id, ...m }); Atomics.store(flag, 0, 1); Atomics.notify(flag, 0); };
  const s = net.connect(path, () => { clearTimeout(timer); timer = setTimeout(() => end({ code: 'key_agent_timeout', detail: 'no reply within ${REPLY_MS / 1000} s' }), ${REPLY_MS}); s.write(line); });
  timer = setTimeout(() => end({ code: 'key_agent_unavailable', detail: 'nothing answers within ${CONNECT_MS / 1000} s' }), ${CONNECT_MS});
  s.on('data', (d) => { got = Buffer.concat([got, d]); const i = got.indexOf(10); if (i >= 0) end({ bytes: got.subarray(0, i) }); });
  s.on('error', (e) => end({ code: 'key_agent_unavailable', detail: e.code || e.message }));
  s.on('close', () => end({ code: 'key_agent_unavailable', detail: 'the agent closed the connection without a reply' }));
});`;
let chan: { port: MessagePort; flag: Int32Array } | undefined, seq = 0;
function channel(): { port: MessagePort; flag: Int32Array } {
  if (chan) return chan;
  const flag = new Int32Array(new SharedArrayBuffer(4)), { port1, port2 } = new MessageChannel();
  new Worker(WORKER, { eval: true, workerData: { port: port2, flag }, transferList: [port2] }).unref();
  port1.unref();
  return (chan = { port: port1, flag });
}

/** One request of §4.2 (`{ op: "sign", did, body }`, …) and its reply; a refusal throws by its code. */
export function request(req: Record<string, unknown>, env: Env = process.env): Record<string, unknown> {
  const path = socketPath(env), c = channel(), id = ++seq, until = Date.now() + REPLY_MS + CONNECT_MS + 1000;
  type Msg = { id: number; code?: string; detail?: string; bytes?: Uint8Array };
  let m: Msg | undefined;
  Atomics.store(c.flag, 0, 0);
  c.port.postMessage({ id, path, line: JSON.stringify(req) + '\n' });
  while (!m && Date.now() < until) {   // a late reply to an earlier, abandoned request is dropped
    Atomics.wait(c.flag, 0, 0, until - Date.now());
    Atomics.store(c.flag, 0, 0);
    for (let x; (x = receiveMessageOnPort(c.port)?.message as Msg | undefined);) if (x.id === id) m = x;
  }
  if (!m) return fail('key_agent_timeout', `the key agent at ${path} did not answer`);
  if (m.code) return fail(m.code, `the key agent at ${path} (SIGELO_KEY_AGENT): ${m.detail}; start it with sigelo-key-agent start`);
  let r: Record<string, unknown> | undefined;
  try { r = parseBytes(m.bytes!) as Record<string, unknown>; } catch { /* below */ }
  if (r?.['ok'] === true) return r;
  return fail(typeof r?.['code'] === 'string' ? r['code'] : 'key_agent_reply', `${typeof r?.['detail'] === 'string' ? r['detail'] : 'not a reply of protocol sigelo-key-agent/0'} (key agent at ${path})`);
}
