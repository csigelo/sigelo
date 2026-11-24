// SPDX-License-Identifier: MIT
/**
 * `sigelo-agent host acp -- <agent command…>` (README "Hosted mode"): the second host plug. The host's SDK
 * seam (sigelo-agent-host.ts Sdk: query({prompt, options}) → messages) played over the Agent Client Protocol
 * (agentclientprotocol.com, protocol version 1): this process is the CLIENT, the agent a child speaking
 * JSON-RPC 2.0 on its stdio, one message a line. hostCore is the same for both plugs; only this mapping is new:
 *   a session        → the child started, initialize, session/new (cwd; no MCP servers, no fs or terminal offered)
 *   a user turn      → session/prompt, a text block (the first of a session preceded by the host's hosting note,
 *                      options.systemPrompt.append: ACP has no system prompt a client can count on)
 *   session/update   → tool_call (or a tool_call_update first naming one): an assistant tool_use block, so the
 *                      host's progress lines; agent_message_chunk text: the turn's answer; the rest ignored
 *   the prompt's end → a result: success with the text (end_turn, or any stop with text), else an error result
 *                      named by the stop reason or the JSON-RPC error
 *   session/request_permission → options.canUseTool (the host's approval: card, CODE fallback, timeout):
 *                      allowed → the allow_once option (else allow_always), denied → reject_once (else
 *                      reject_always, else cancelled); the turn ended or the session closed → cancelled
 *   any other request from the agent (fs/*, terminal/*) → -32601, never served (not offered at initialize)
 *   the child exits, or a start step fails or times out → the query throws: the host's "session restarted",
 *                      then unavailable after FAIL_N, exactly as for the SDK
 *   close()          → session/cancel when a turn runs, stdin ended, the child stopped: SIGTERM after a grace
 *                      (CLOSE_GRACE_MS, its exit ends it early), SIGKILL CLOSE_KILL_MS later; the query awaits the exit
 * No cancel on a new operator message: the SDK plug queues it as the next turn, and so does this one.
 */
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import type { CanUse, Sdk, SdkMsg, SdkUser } from './sigelo-agent-host.ts';
import { version } from './sigelo-agent-contact.ts';
import { spawnArgs, stop, which } from './sigelo-agent-exec.ts';

const agentVersion = (): string => { try { return version(); } catch { return '0'; } };
export const ACP_VERSION = 1, ACP_START_MS = 120_000, TITLE_MAX = 80, CLOSE_GRACE_MS = 500, CLOSE_KILL_MS = 3000;
type Rpc = { jsonrpc?: string; id?: number | string | null; method?: string; params?: Record<string, unknown>; result?: Record<string, unknown>; error?: { code?: number; message?: string } };
type Tool = { title?: string; kind?: string; rawInput?: unknown; status?: string; shown?: boolean };
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const oneLine = (s: string): string => { const t = s.replace(/\s+/g, ' ').trim(); return t.length > TITLE_MAX ? `${t.slice(0, TITLE_MAX - 1)}…` : t; };
/** The agent's name in the host's lines: the command's base name, past a runner (npx, node, uvx…) to what it runs. */
export function agentName(cmd: string[]): string {
  // A script's generic name (…/claude-agent-acp/dist/index.js): its package directory's instead.
  const base = (s: string): string => {
    const p = s.split(/[\\/]/).filter(Boolean), f = p.at(-1)!.replace(/\.(cmd|exe|bat|[cm]?js|ts)$/i, '');
    if (!/^(index|main|cli)$/i.test(f)) return f;
    return p.slice(0, -1).reverse().find((d) => !/^(dist|bin|lib|build|src|out)$/i.test(d)) ?? f;
  };
  const runners = new Set(['npx', 'node', 'bunx', 'bun', 'pnpm', 'pnpx', 'yarn', 'uvx', 'deno', 'dlx', 'exec', 'run']);
  const words = cmd.filter((a) => !a.startsWith('-')).map(base);
  return words.find((w) => !runners.has(w))?.replace(/^@[^/]+\//, '') ?? words[0] ?? 'agent';
}
/** What an approval names: the tool call's title (else its kind), its raw input (else its kind as a description). */
export function toolOf(t: Tool): { tool: string; input: Record<string, unknown> } {
  const tool = oneLine(String(t.title || t.kind || 'tool'));
  return { tool, input: isObj(t.rawInput) && Object.keys(t.rawInput).length > 0 ? t.rawInput : { description: String(t.kind ?? '') } };
}
/** The option answering a decision: allow → allow_once, else allow_always; deny → reject_once, else reject_always; none → null (cancelled). */
export function pick(options: unknown, allow: boolean): string | null {
  const l = Array.isArray(options) ? options.filter(isObj) : [];
  const want = allow ? ['allow_once', 'allow_always'] : ['reject_once', 'reject_always'];
  for (const k of want) { const o = l.find((x) => x['kind'] === k && typeof x['optionId'] === 'string'); if (o) return o['optionId'] as string; }
  return null;
}

/** The ACP plug as the host's Sdk: one child per query (session), started from cmd in options.cwd. */
export function acpSdk(cmd: string[], env: NodeJS.ProcessEnv = process.env): Sdk {
  return { query: ({ prompt, options }) => acpQuery(cmd, env, prompt, options) };
}

function acpQuery(cmd: string[], env: NodeJS.ProcessEnv, prompt: AsyncIterable<SdkUser>, options: Record<string, unknown> & { canUseTool: CanUse }): AsyncIterable<SdkMsg> & { close(): void } {
  const cwd = resolve(typeof options['cwd'] === 'string' ? options['cwd'] : process.cwd());
  const sp = options['systemPrompt'], note = isObj(sp) && typeof sp['append'] === 'string' ? sp['append'] : '';
  const f = which(cmd[0]!, env);
  const queue: (SdkMsg | Error)[] = [];
  let wake: (() => void) | null = null, closed = false, gone: Error | null = null, n = 0, err = '';
  const push = (m: SdkMsg | Error): void => { queue.push(m); wake?.(); };
  const pending = new Map<number, { ok(r: Record<string, unknown>): void; no(e: Error): void }>();
  // dead: rejects when the child is gone, so an exit between two turns ends the session at once, as the SDK's does.
  let died: (e: Error) => void = () => {};
  const dead = new Promise<never>((_, no) => { died = no; });
  dead.catch(() => {});
  const fail = (e: Error): void => { if (gone !== null) return; gone = e; for (const p of pending.values()) p.no(e); pending.clear(); push(e); died(e); };
  if (f === null) { fail(new Error(`the ACP agent: no ${cmd[0]} command on this machine's PATH`)); }
  const a = f === null ? null : spawnArgs(f, cmd.slice(1));
  const child = a === null ? null : spawn(a.cmd, a.args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'], shell: a.shell });
  // exited: the child's end (or it never started), what close() waits for.
  const exited = child === null ? Promise.resolve() : new Promise<void>((r) => { child.on('exit', () => r()); child.on('error', () => { if (child.pid === undefined) r(); }); });
  const send = (m: Rpc): void => { if (child !== null && gone === null && child.stdin.writable) child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...m })}\n`); };
  const request = (method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> => new Promise((ok, no) => {
    if (gone !== null) { no(gone); return; }
    const id = ++n;
    pending.set(id, { ok, no });
    send({ id, method, params });
  });
  // The turn's state: its text, the tool calls seen (by id), its abort (a permission waiting is answered cancelled).
  let said: string[] = [], tools = new Map<string, Tool>(), turn: AbortController | null = null, sid = '';
  const onUpdate = (u: Record<string, unknown>): void => {
    const kind = u['sessionUpdate'];
    if (kind === 'agent_message_chunk' && isObj(u['content']) && u['content']['type'] === 'text' && typeof u['content']['text'] === 'string') { said.push(u['content']['text']); return; }
    if ((kind !== 'tool_call' && kind !== 'tool_call_update') || typeof u['toolCallId'] !== 'string') return;
    const id = u['toolCallId'], had = tools.get(id), t: Tool = { ...had };
    for (const k of ['title', 'kind', 'rawInput', 'status'] as const) if (u[k] !== undefined && u[k] !== null) (t as Record<string, unknown>)[k] = u[k];
    tools.set(id, t);
    // One tool_use a tool call (the host counts each id once), once it is known: its input there, or it runs. An agent
    // that streams the call first names it by a placeholder ("Terminal", "Preparing file…") and an empty input.
    const known = isObj(t.rawInput) && Object.keys(t.rawInput).length > 0, runs = t.status !== undefined && t.status !== 'pending';
    if (!t.shown && t.title !== undefined && (known || runs)) { t.shown = true; const x = toolOf(t); push({ type: 'assistant', parent_tool_use_id: null, message: { content: [{ type: 'tool_use', id, name: x.tool, input: x.input }] } }); }
  };
  const onPermission = async (id: Rpc['id'], p: Record<string, unknown>): Promise<void> => {
    const tc = isObj(p['toolCall']) ? p['toolCall'] : {}, known = typeof tc['toolCallId'] === 'string' ? tools.get(tc['toolCallId']) : undefined;
    const t: Tool = { ...known };
    for (const k of ['title', 'kind', 'rawInput'] as const) if (tc[k] !== undefined && tc[k] !== null) (t as Record<string, unknown>)[k] = tc[k];
    const x = toolOf(t), ac = turn ?? new AbortController();
    if (closed || turn === null) ac.abort();
    let optionId: string | null = null;
    if (!ac.signal.aborted) {
      const d = await options.canUseTool(x.tool, x.input, { signal: ac.signal }).catch(() => ({ behavior: 'deny' as const, message: '' }));
      if (!ac.signal.aborted) optionId = pick(p['options'], d.behavior === 'allow');
    }
    send({ id, result: { outcome: optionId === null ? { outcome: 'cancelled' } : { outcome: 'selected', optionId } } });
  };
  if (child !== null) {
    let buf = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (d: string) => {
      buf += d;
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        let m: Rpc;
        try { m = JSON.parse(line) as Rpc; } catch { continue; }      // a log line on stdout: not ours
        if (!isObj(m)) continue;
        if (typeof m.method === 'string' && m.id !== undefined && m.id !== null) {
          if (m.method === 'session/request_permission') void onPermission(m.id, isObj(m.params) ? m.params : {});
          else send({ id: m.id, error: { code: -32601, message: `${m.method}: not offered by this client` } });
        } else if (m.method === 'session/update' && isObj(m.params) && isObj(m.params['update'])) onUpdate(m.params['update']);
        else if (typeof m.id === 'number' && pending.has(m.id)) {
          const p = pending.get(m.id)!; pending.delete(m.id);
          if (m.error !== undefined) p.no(Object.assign(new Error(`${m.error.message ?? 'error'} (${m.error.code ?? '?'})`), { code: m.error.code })); else p.ok(isObj(m.result) ? m.result : {});
        }
      }
      if (buf.length > 16 << 20) { fail(new Error('the ACP agent sent a line over 16 MiB')); stop(child.pid, () => child.kill('SIGTERM')); }
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (d: string) => { err = (err + d).slice(-4000); });
    child.stdin.on('error', () => {});
    child.on('error', (e) => fail(new Error(`the ACP agent did not start: ${e.message}`)));
    child.on('close', (code, sig) => {
      const last = err.split('\n').map((l) => l.trim()).filter(Boolean).at(-1);
      fail(new Error(`the ACP agent ${closed ? 'was stopped' : `exited (${sig ?? `code ${code}`})`}${last ? `: ${last}` : ''}`));
    });
  }
  const timed = <T>(p: Promise<T>, what: string): Promise<T> => new Promise((ok, no) => {
    const t = setTimeout(() => no(new Error(`the ACP agent did not answer ${what} within ${ACP_START_MS / 1000} s`)), ACP_START_MS);
    p.then((v) => { clearTimeout(t); ok(v); }, (e: unknown) => { clearTimeout(t); no(e); });
  });
  const next = async (): Promise<SdkMsg> => {
    for (;;) {
      const m = queue.shift();
      if (m instanceof Error) throw m;
      if (m !== undefined) return m;
      await new Promise<void>((r) => { wake = r; });
      wake = null;
    }
  };
  const close = (): void => {
    if (closed) return;
    closed = true;
    if (turn !== null) { send({ method: 'session/cancel', params: { sessionId: sid } }); turn.abort(); }
    if (child === null) { fail(new Error('the ACP agent was stopped')); return; }
    child.stdin.end();
    // A grace for the cancel (and stdin's end) to be read, the exit ending it early; then SIGTERM, then SIGKILL.
    if (child.exitCode !== null || child.signalCode !== null) return;
    let t2: NodeJS.Timeout | undefined;
    const t = setTimeout(() => { stop(child.pid, () => child.kill('SIGTERM')); t2 = setTimeout(() => child.kill('SIGKILL'), CLOSE_KILL_MS); }, CLOSE_GRACE_MS);
    void exited.then(() => { clearTimeout(t); clearTimeout(t2); });
  };
  async function* run(): AsyncGenerator<SdkMsg> {
    try {
      if (gone !== null) throw gone;
      const init = await timed(request('initialize', { protocolVersion: ACP_VERSION, clientCapabilities: { fs: { readTextFile: false, writeTextFile: false }, terminal: false }, clientInfo: { name: 'sigelo-agent', version: agentVersion() } }), 'initialize');
      if (init['protocolVersion'] !== ACP_VERSION) throw new Error(`the ACP agent speaks protocol version ${JSON.stringify(init['protocolVersion'])}, this client ${ACP_VERSION}`);
      let s: Record<string, unknown>;
      try { s = await timed(request('session/new', { cwd, mcpServers: [] }), 'session/new'); } catch (e) {
        if ((e as { code?: number }).code !== -32000) throw e;
        const ms = Array.isArray(init['authMethods']) ? init['authMethods'].filter(isObj).map((x) => String(x['name'] ?? x['id'] ?? '')).filter(Boolean) : [];
        throw new Error(`the ACP agent needs signing in on this machine first${ms.length ? ` (${ms.join(', ')})` : ''}: sign it in there, it is tried again`);
      }
      if (typeof s['sessionId'] !== 'string') throw new Error('the ACP agent\'s session/new gave no sessionId');
      sid = s['sessionId'];
      let first = true;
      const it = prompt[Symbol.asyncIterator]();
      for (;;) {
        const r = await Promise.race([it.next(), dead]);
        if (r.done) break;
        const u = r.value;
        said = []; tools = new Map(); turn = new AbortController();
        const blocks = [...(first && note !== '' ? [{ type: 'text', text: note }] : []), { type: 'text', text: u.message.content }];
        first = false;
        const me = turn;
        request('session/prompt', { sessionId: sid, prompt: blocks }).then((r) => {
          const stop = String(r['stopReason'] ?? ''), text = said.join('');
          push(stop === 'end_turn' || (text.trim() !== '' && stop !== 'cancelled') ? { type: 'result', subtype: 'success', is_error: false, result: text }
            : { type: 'result', subtype: 'error_during_execution', is_error: true, result: text, errors: [`stop reason ${stop || 'none'}`] });
        }, (e: Error) => { if (gone === null) push({ type: 'result', subtype: 'error_during_execution', is_error: true, result: said.join(''), errors: [e.message] }); });
        for (;;) {
          const m = await next();
          yield m;
          if (m.type === 'result') break;
        }
        me.abort();
        if (turn === me) turn = null;
      }
    } finally { close(); await exited; }
  }
  return Object.assign(run(), { close });
}
