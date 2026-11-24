#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// A FAKE Agent Client Protocol agent for test-acp.ts: JSON-RPC 2.0 on stdio, one message a line, never a model.
// Its replies are scripted by the prompt's last text block: hello, run ls (a permission request), work (tool
// calls), fail (a JSON-RPC error), refuse (a refusal, no text), crash (exits 3), fs (asks the client for a file),
// slow (answers after 1 s), anything else echoed with the number of prompt blocks.
// Env: FAKE_ACP_LOG a file each received message is appended to; FAKE_ACP_AUTH=1 session/new needs a login;
// FAKE_ACP_VERSION the protocol version it answers; FAKE_ACP_DIE_MS exits that long after session/new.
import { appendFileSync } from 'node:fs';
const env = process.env, out = (m) => process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', ...m })}\n`);
let n = 1000, sid = 'sess-1', cancelled = false;
const waiting = new Map();
const ask = (method, params) => new Promise((ok) => { const id = ++n; waiting.set(id, ok); out({ id, method, params }); });
const update = (u) => out({ method: 'session/update', params: { sessionId: sid, update: u } });
const say = (t) => update({ sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: t } });
const tool = (id, title, kind, rawInput) => update({ sessionUpdate: 'tool_call', toolCallId: id, title, kind, status: 'pending', rawInput });
process.stdout.write('fake-acp: a log line on stdout, not JSON\n');
async function prompt(id, p) {
  const blocks = p.prompt ?? [], text = blocks.at(-1)?.text ?? '';
  cancelled = false;
  const end = (stopReason) => out({ id, result: { stopReason } });
  if (text === 'hello') { say('hi '); say('operator'); return end('end_turn'); }
  if (text === 'run ls') {
    tool('c1', 'Run ls -la /tmp', 'execute', { command: 'ls -la /tmp' });
    const r = await ask('session/request_permission', { sessionId: sid, toolCall: { toolCallId: 'c1' }, options: [
      { optionId: 'yes1', name: 'Allow', kind: 'allow_once' }, { optionId: 'yes!', name: 'Always', kind: 'allow_always' },
      { optionId: 'no1', name: 'Reject', kind: 'reject_once' }, { optionId: 'no!', name: 'Never', kind: 'reject_always' }] });
    const o = r.result?.outcome;
    say(`ran: ${o?.outcome === 'selected' ? o.optionId : o?.outcome}`);
    return end(cancelled ? 'cancelled' : 'end_turn');
  }
  if (text === 'work') {
    tool('w1', 'Run npm test', 'execute', { command: 'npm test' });
    update({ sessionUpdate: 'tool_call_update', toolCallId: 'w1', status: 'completed' });
    tool('w2', 'Read src/app.ts', 'read', { path: '/x/src/app.ts' });
    tool('w2', 'Read src/app.ts', 'read', { path: '/x/src/app.ts' });
    update({ sessionUpdate: 'tool_call_update', toolCallId: 'w3', title: 'Search for x', kind: 'search', status: 'in_progress' });
    tool('w4', 'Preparing file…', 'edit', {});
    update({ sessionUpdate: 'tool_call_update', toolCallId: 'w4', title: 'Write a.txt', rawInput: { path: 'a.txt' } });
    update({ sessionUpdate: 'plan', entries: [] });
    update({ sessionUpdate: 'agent_thought_chunk', content: { type: 'text', text: 'hmm' } });
    say('worked');
    return end('end_turn');
  }
  if (text === 'fail') { say('half an answer'); return out({ id, error: { code: -32603, message: 'model overloaded' } }); }
  if (text === 'refuse') return end('refusal');
  if (text === 'crash') { process.stderr.write('fake-acp: boom\n'); process.exit(3); }
  if (text === 'fs') { const r = await ask('fs/read_text_file', { sessionId: sid, path: '/etc/passwd' }); say(`fs: ${r.error?.code}`); return end('end_turn'); }
  if (text === 'slow') { await new Promise((r) => setTimeout(r, 1000)); say(cancelled ? 'slow cancelled' : 'slow done'); return end(cancelled ? 'cancelled' : 'end_turn'); }
  say(`echo: ${text} (${blocks.length} blocks)`);
  return end('end_turn');
}
let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => {
  buf += d;
  for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (env.FAKE_ACP_LOG) appendFileSync(env.FAKE_ACP_LOG, `${line}\n`);
    const m = JSON.parse(line);
    if (m.method === undefined) { waiting.get(m.id)?.(m); waiting.delete(m.id); continue; }
    if (m.method === 'initialize') out({ id: m.id, result: { protocolVersion: Number(env.FAKE_ACP_VERSION ?? 1), agentCapabilities: {}, authMethods: [{ id: 'fake-login', name: 'fake login' }] } });
    else if (m.method === 'session/new') {
      if (env.FAKE_ACP_AUTH === '1') out({ id: m.id, error: { code: -32000, message: 'Authentication required' } });
      else { out({ id: m.id, result: { sessionId: sid } }); if (env.FAKE_ACP_DIE_MS) setTimeout(() => process.exit(4), Number(env.FAKE_ACP_DIE_MS)); }
    } else if (m.method === 'session/prompt') void prompt(m.id, m.params);
    else if (m.method === 'session/cancel') cancelled = true;
    else if (m.id !== undefined) out({ id: m.id, error: { code: -32601, message: `no ${m.method}` } });
  }
});
process.stdin.on('end', () => process.exit(0));
