// SPDX-License-Identifier: MIT
// sigelo-agent host acp (sigelo-agent-acp.ts): the ACP plug under hostCore, against a FAKE ACP agent
// (fixtures/fake-acp-agent.mjs, a child on stdio, never a model): turns, progress lines, permission requests
// as approvals, errors, the agent's exit, close; then the CLI's argument checks.
//   node test-acp.ts   → ALL PASS test-acp.ts (n ok)
import { spawnSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { done, ok, tmpHome } from './test-helpers.ts';
import * as A from './sigelo-agent-acp.ts';
import * as H from './sigelo-agent-host.ts';

const FAKE = join(import.meta.dirname, 'fixtures', 'fake-acp-agent.mjs'), CMD = [process.execPath, FAKE];
const until = async (f: () => boolean, ms = 5000): Promise<boolean> => { const e = Date.now() + ms; while (!f() && Date.now() < e) await new Promise((r) => setTimeout(r, 20)); return f(); };
const home = tmpHome('acp'), LOG = join(home, 'acp.log');
const logged = (): { method?: string; params?: Record<string, unknown>; result?: Record<string, unknown> }[] => { try { return readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } };
const fakes = (): number => (process.platform === 'win32' ? 0 : spawnSync('pgrep', ['-fx', CMD.join(' ')], { encoding: 'utf8' }).stdout.trim().split('\n').filter(Boolean).length);
const core = (o: Partial<H.CoreOptions> & { env?: NodeJS.ProcessEnv } = {}): { c: H.Core; sent: { t: string; label?: string }[]; has(f: (t: string) => boolean): Promise<boolean> } => {
  const sent: { t: string; label?: string }[] = [];
  const c = H.hostCore({ sdk: A.acpSdk(CMD, { ...process.env, ...o.env }), name: 'fake', tell: async (t, label) => { sent.push({ t, label }); }, approveMs: 5000, backoff: [30, 60], progress: false, log: () => {}, ...o });
  return { c, sent, has: (f) => until(() => sent.some((x) => f(x.t))) };
};

// ── the helpers ───────────────────────────────────────────────────────────────────────────────────
ok('agentName: the command\'s base name, past a runner and a package scope',
  A.agentName(['npx', '@zed-industries/claude-code-acp']) === 'claude-code-acp' && A.agentName(['gemini', '--experimental-acp']) === 'gemini' && A.agentName(CMD) === 'fake-acp-agent' && A.agentName(['C:\\bin\\opencode.cmd', 'acp']) === 'opencode'
  && A.agentName(['node', '/n/node_modules/@agentclientprotocol/claude-agent-acp/dist/index.js']) === 'claude-agent-acp');
ok('toolOf: the title (one line, ≤ 80), the raw input; none: the kind as a description',
  JSON.stringify(A.toolOf({ title: 'Run\n ls', kind: 'execute', rawInput: { command: 'ls' } })) === '{"tool":"Run ls","input":{"command":"ls"}}' && JSON.stringify(A.toolOf({ kind: 'edit' })) === '{"tool":"edit","input":{"description":"edit"}}' && A.toolOf({ title: 'x'.repeat(200) }).tool.length === 80);
const opts = [{ optionId: 'a!', kind: 'allow_always' }, { optionId: 'a1', kind: 'allow_once' }, { optionId: 'r!', kind: 'reject_always' }];
ok('pick: allow → allow_once, else allow_always; deny → reject_once, else reject_always; none → null (cancelled)',
  A.pick(opts, true) === 'a1' && A.pick(opts.slice(0, 1), true) === 'a!' && A.pick(opts, false) === 'r!' && A.pick(opts.slice(0, 2), false) === null && A.pick('x', true) === null);

// ── the session (hostCore over the ACP plug) ──────────────────────────────────────────────────────
{
  const { c, sent, has } = core({ env: { FAKE_ACP_LOG: LOG } });
  ok('host acp: the mode line names the agent', await has((t) => t === 'fake session started: tools ask you first (approve CODE?)'), JSON.stringify(sent));
  ok('an operator message → session/prompt; the streamed text goes back as the answer', c.input('hello') === 'turn' && await has((t) => t === 'hi operator'), JSON.stringify(sent));
  ok('…the agent: one child process', fakes() === (process.platform === 'win32' ? 0 : 1), String(fakes()));
  const init = logged().find((m) => m.method === 'initialize'), nw = logged().find((m) => m.method === 'session/new'), pr = logged().filter((m) => m.method === 'session/prompt');
  ok('…initialize: protocol version 1, no fs or terminal offered; session/new: an absolute cwd, no MCP servers',
    init?.params?.['protocolVersion'] === 1 && JSON.stringify(init.params['clientCapabilities']) === '{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false}' && typeof nw?.params?.['cwd'] === 'string' && isAbsolute(nw.params['cwd'] as string) && JSON.stringify(nw.params['mcpServers']) === '[]', JSON.stringify(logged().slice(0, 2)));
  const first = (pr[0]?.params?.['prompt'] ?? []) as { text: string }[];
  ok('…the first turn of a session carries the hosting note first (ACP has no system prompt to count on)', first.length === 2 && first[0]!.text.startsWith('You are hosted by sigelo-agent') && first[1]!.text === 'hello', JSON.stringify(first));
  ok('…later turns: the message alone', c.input('what') === 'turn' && await has((t) => t === 'echo: what (1 blocks)'), JSON.stringify(sent));
  c.input('run ls');
  ok('session/request_permission → the host\'s approval: approve CODE? <title>: <command>', await has((t) => /^approve [A-Z2-9]{4}\? Run ls -la \/tmp: ls -la \/tmp\nanswer: yes [A-Z2-9]{4} or no [A-Z2-9]{4}$/.test(t)), JSON.stringify(sent));
  let code = /^approve (\w{4})/.exec(sent.find((x) => x.t.startsWith('approve'))!.t)![1]!;
  ok('…"yes CODE" → the allow_once option selected', c.input(`yes ${code}`) === 'approval' && await has((t) => t === 'ran: yes1'), JSON.stringify(sent));
  sent.length = 0;
  c.input('run ls');
  await has((t) => t.startsWith('approve'));
  code = /^approve (\w{4})/.exec(sent.find((x) => x.t.startsWith('approve'))!.t)![1]!;
  ok('…"no CODE" → reject_once', c.input(`no ${code}`) === 'approval' && await has((t) => t === 'ran: no1'), JSON.stringify(sent));
  c.input('fs');
  ok('a request the client did not offer (fs/read_text_file) → -32601, never served', await has((t) => t === 'fs: -32601'), JSON.stringify(sent));
  c.input('fail');
  ok('a JSON-RPC error to session/prompt → the turn ended without an answer, the error named', await has((t) => t === 'the turn ended without an answer (error_during_execution: model overloaded (-32603))'), JSON.stringify(sent));
  c.input('refuse');
  ok('a stop without text (refusal) → the same, the stop reason named', await has((t) => t === 'the turn ended without an answer (error_during_execution: stop reason refusal)'), JSON.stringify(sent));
  sent.length = 0;
  c.input('crash');
  ok('the agent exits mid-turn → "session restarted", the message said lost; a new child', await has((t) => t === 'session restarted: your last message was not answered, send it again') && c.sessions() === 2, JSON.stringify(sent));
  ok('…and the new session takes the next message (the hosting note again)', c.input('hey') === 'turn' && await has((t) => t === 'echo: hey (2 blocks)'), JSON.stringify(sent));
  c.input('slow');
  await until(() => logged().some((m) => m.method === 'session/prompt' && JSON.stringify(m.params).includes('"slow"')));
  await c.close();
  // The fake logs what it reads: wait for the line (a slow runner), then for the child's end.
  const cancelled = await until(() => logged().some((m) => m.method === 'session/cancel' && m.params?.['sessionId'] === 'sess-1'), 2000);
  ok('close mid-turn: session/cancel sent (read by the agent before it stops), the child stopped', cancelled && await until(() => fakes() === 0), `${cancelled} ${fakes()}`);
}
{
  const { c, sent, has } = core({ progress: [0, 8, 60_000] });
  c.input('work');
  await has((t) => t === 'worked');
  const pr = sent.filter((x) => x.label === 'progress').map((x) => x.t);
  ok('host acp progress: each tool call once, when its input is known or it runs (a placeholder title and no input: not yet) → "working: <title>", before the reply',
    pr.join('|') === 'working: Run npm test|working: Read src/app.ts|working: Search for x|working: Write a.txt' && sent.at(-1)?.t === 'worked', JSON.stringify(sent));
  await c.close();
}
{
  const { c, sent, has } = core({ approveMs: 300 });
  c.input('run ls');
  ok('no answer within the approve timeout → reject_once', await has((t) => t === 'ran: no1'), JSON.stringify(sent));
  await c.close();
}
{
  const { c, sent, has } = core({ skipPermissions: true });
  c.input('run ls');
  ok('--dangerously-skip-permissions: said at the start, the permission allowed without asking', await has((t) => t === 'ran: yes1') && sent[0]?.t.startsWith('fake session started: permissions skipped') === true && !sent.some((x) => x.t.startsWith('approve')), JSON.stringify(sent));
  await c.close();
}
{
  const { c, sent, has } = core({ env: { FAKE_ACP_DIE_MS: '200' }, failN: 2 });
  ok('the agent exits between turns → the session ends at once: restarted, then unavailable after FAIL_N, the exit named',
    await has((t) => t === 'session restarted') && await has((t) => t.startsWith('fake is unavailable here: the session failed: the ACP agent exited (code 4) 2 times in a row')), JSON.stringify(sent));
  ok('…the operator\'s message is held while it is', c.input('later') === 'held');
  await c.close();
}
{
  const { c, sent, has } = core({ env: { FAKE_ACP_AUTH: '1' }, failN: 1 });
  ok('session/new needs a login (-32000) → unavailable, sign it in on this machine, the agent\'s methods named (never the login flow of the phone)',
    await has((t) => t.startsWith('fake is unavailable here: the session failed: the ACP agent needs signing in on this machine first (fake login)')), JSON.stringify(sent));
  await c.close();
}
{
  const { c, sent, has } = core({ env: { FAKE_ACP_VERSION: '2' }, failN: 1 });
  ok('another protocol version → unavailable, both versions named', await has((t) => t.includes('the ACP agent speaks protocol version 2, this client 1')), JSON.stringify(sent));
  await c.close();
}
{
  const { c, sent, has } = core({ sdk: A.acpSdk(['no-such-acp-agent-here']), failN: 1 });
  ok('a command not on PATH → unavailable, said', await has((t) => t.includes('no no-such-acp-agent-here command on this machine\'s PATH')), JSON.stringify(sent));
  await c.close();
}
ok('every fake agent stopped', await until(() => fakes() === 0), String(fakes()));

// ── the CLI's arguments ───────────────────────────────────────────────────────────────────────────
{
  const err = console.error; const lines: string[] = []; console.error = (s: string) => { lines.push(String(s)); };
  const codes = [await H.main(['acp']), await H.main(['acp', '--quiet']), await H.main(['acp', '--model', 'x', '--identity', join(home, 'none.json'), '--', 'gemini']), await H.main(['codex'])];
  console.error = err;
  ok('host acp: no command after -- → 2; a host claude flag → 2; an unknown host → 2, naming both', codes.join() === '2,2,2,2' && lines.some((l) => l.includes('--permission-mode, --model and --install-sdk are host claude\'s')) && lines.some((l) => l.includes('host claude or host acp')), JSON.stringify(lines.map((l) => l.split('\n')[0])));
}
rmSync(home, { recursive: true, force: true });
done(import.meta.filename);
