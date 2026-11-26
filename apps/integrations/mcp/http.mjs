// SPDX-License-Identifier: MIT
// sigelo-mcp --http: the server's answer() behind MCP Streamable HTTP, for clients that speak
// only HTTP (Open WebUI's native MCP, and others). Transport only: the tools, their identity
// files and their locking are server.mjs's and the libraries', exactly as on stdio.
//   POST   /mcp  one JSON-RPC message (or a 2025-03-26 batch) → its answer as application/json
//                 (only notifications: 202); an initialize answer carries an Mcp-Session-Id
//   DELETE /mcp  ends that session; GET /mcp → 405 (the spec's optional SSE stream is not offered)
//   GET    /     a text page: what this is and how to add it (no token on it)
// Both eras (modelcontextprotocol.io/specification/2025-11-25/basic/transports and
// /2026-07-28/basic/transports/streamable-http): a request is 2026-07-28 when its
// MCP-Protocol-Version header or its _meta says so; then MCP-Protocol-Version, Mcp-Method and
// (tools/call) Mcp-Name must be there and match the body (else 400, -32020), an unknown method is
// 404 with -32601, and Mcp-Session-Id is ignored (that revision has no sessions).
// Guarded three ways: it listens on loopback unless --insecure-listen; every /mcp request needs a
// bearer token (--token or SIGELO_MCP_TOKEN, else the one in --token-file or made per install);
// a browser Origin other than loopback (or the listen address) is refused with 403, so a web page
// cannot drive it (DNS rebinding included). No CORS headers are ever sent.
// Legacy sessions are optional: a request without the header stands alone; an unknown or ended one → 404.
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';

const DEFAULT_PORT = 7310;
const MAX_SESSIONS = 1024;
const MAX_BODY = 4 * 1024 * 1024;  // a bundle or a message is kilobytes; files go by path
const HEADER_MISMATCH = -32020;    // MCP 2026-07-28: a routing header is missing or disagrees with the body
const UNSUPPORTED = -32022;        // MCP 2026-07-28: UnsupportedProtocolVersionError, as server.mjs
const say = (s) => process.stderr.write(`sigelo-mcp: ${s}\n`);
const loopback = (h) => h === 'localhost' || h === '::1' || (isIP(h) === 4 && h.startsWith('127.'));

// --http [HOST:PORT] | --http [PORT], or --listen HOST[:PORT] / --port PORT; --token T | --token-file F;
// --insecure-listen to bind off loopback.
const HOSTPORT = /^(?:(?:\[([0-9A-Fa-f:.]+)\]|([^:[\]]+)):)?(\d{1,5})$/;
function options(argv, env) {
  const value = (flag) => {
    const i = argv.findIndex((a) => a === flag || a.startsWith(`${flag}=`));
    if (i === -1) return undefined;
    const v = argv[i].includes('=') ? argv[i].slice(flag.length + 1) : argv[i + 1];
    if (v === undefined || v.startsWith('--')) throw new Error(`${flag} needs a value`);
    return v;
  };
  let host = value('--listen'), p = value('--port');
  // --listen 127.0.0.1:7310 or [::1]:7310; a bare address (::1 included) is the host alone.
  const lm = host !== undefined && !isIP(host.replace(/^\[|\]$/g, '')) ? HOSTPORT.exec(host) : null;
  if (lm && (lm[1] ?? lm[2]) !== undefined) {
    if (p !== undefined) throw new Error(`--listen ${host}: a port here and in --port`);
    host = lm[1] ?? lm[2]; p = lm[3];
  } else if (host !== undefined) host = host.replace(/^\[|\]$/g, '');
  const at = argv[argv.indexOf('--http') + 1];
  if (at !== undefined && !at.startsWith('--')) {
    const m = HOSTPORT.exec(at);
    if (!m || (host ?? p) !== undefined) throw new Error(`--http ${at}: give HOST:PORT (e.g. 127.0.0.1:7310, [::1]:7310) or a PORT, not with --listen/--port`);
    host = m[1] ?? m[2]; p = m[3];
  }
  host ??= '127.0.0.1'; p ??= String(DEFAULT_PORT);
  const given = value('--token') ?? (env.SIGELO_MCP_TOKEN || undefined);
  if (given !== undefined && !/^[\x21-\x7e]{32,}$/.test(given)) throw new Error('--token / SIGELO_MCP_TOKEN: 32 or more printable characters, no spaces');
  if (!/^\d{1,5}$/.test(p) || Number(p) > 65535) throw new Error(`--port ${p}: not a port number`);
  if (host !== 'localhost' && !isIP(host)) throw new Error(`--listen ${host}: give an IP address this machine has on your network`);
  if (!loopback(host) && !argv.includes('--insecure-listen')) throw new Error(`${host} is not loopback: refused without --insecure-listen`);
  return { port: Number(p), host, given, file: value('--token-file') };
}

// One token per install, beside the identity file (or at --token-file): made once (0600), read on
// every later start. Delete the file and restart for a new one.
function token(base, given) {
  const file = given ?? join(dirname(base), 'sigelo-mcp-http.token');
  try {
    const t = readFileSync(file, 'utf8').trim();
    if (!/^[A-Za-z0-9_-]{32,}$/.test(t)) throw Object.assign(new Error(`${file} is not a token; delete it and start again for a new one`), { fatal: true });
    return { file, token: t };
  } catch (e) {
    if (e.fatal || e.code !== 'ENOENT') throw e;
  }
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const t = randomBytes(32).toString('base64url');
  writeFileSync(file, t + '\n', { mode: 0o600, flag: 'wx' });
  return { file, token: t, made: true };
}

export async function serveHttp({ argv, answer, parseBytes, base, versions, modern = [], info, env = process.env }) {
  let opt, tok;
  try { opt = options(argv, env); tok = opt.given !== undefined ? { token: opt.given, given: true } : token(base, opt.file); } catch (e) { say(e.message); process.exit(2); }
  const want = createHash('sha256').update(`Bearer ${tok.token}`).digest();
  const authorised = (h) => typeof h === 'string' && timingSafeEqual(createHash('sha256').update(h).digest(), want);
  const shown = isIP(opt.host) === 6 ? `[${opt.host}]` : opt.host;
  const url = (port) => `http://${opt.host === '0.0.0.0' || opt.host === '::' ? '<this machine\'s address>' : shown}:${port}/mcp`;
  // A browser always sends Origin; server-side clients (Open WebUI's backend) send none.
  const originOk = (o) => {
    if (o === undefined) return true;
    try { const h = new URL(o).hostname.replace(/^\[|\]$/g, ''); return loopback(h) || h === opt.host; } catch { return false; }
  };
  const page = (port) => `${info.name}-mcp ${info.version}: MCP over Streamable HTTP for one sigelo identity.

Endpoint: POST ${url(port)}
Header:   Authorization: Bearer <token>
The token is the one given (SIGELO_MCP_TOKEN or --token), else the one printed at start and
kept in sigelo-mcp-http.token beside the identity file. It is never shown on this page.

Open WebUI (0.6.31 or later), as an admin:
  Settings > Integrations > External Tool Servers > + Add Connection
  Type: MCP (Streamable HTTP)
  URL: ${url(port)}
  Auth: Bearer, the token in Key
  Access Control: whoever you let use it acts as this one identity.
  Save. In a chat: + > Tools, switch sigelo on (a model with tool calling).

Other HTTP MCP clients: transport "streamable-http", the URL and header above.
Docs: https://github.com/csigelo/sigelo/blob/main/apps/integrations/mcp/README.md
`;
  const sessions = new Set();  // ids only: a session holds no state, the tools read the files
  const server = createServer((req, res) => {
    const out = (status, body, type = 'text/plain; charset=utf-8', extra = {}) => {
      res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra });
      res.end(body);
    };
    const rpcError = (status, code, message, id = null) => out(status, JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }), 'application/json');
    if (!originOk(req.headers.origin)) return out(403, 'refused: this server answers no web page (Origin is not loopback)\n');
    const path = req.url.split('?')[0];
    if (path === '/' && (req.method === 'GET' || req.method === 'HEAD')) return out(200, req.method === 'HEAD' ? '' : page(server.address().port));
    if (path !== '/mcp') return out(404, 'not found: the MCP endpoint is /mcp\n');
    if (req.method !== 'POST' && req.method !== 'DELETE') return out(405, 'POST (and DELETE to end a session) only: no SSE stream\n', undefined, { Allow: 'POST, DELETE' });
    if (!authorised(req.headers.authorization)) return out(401, 'refused: wrong or missing bearer token\n', undefined, { 'WWW-Authenticate': 'Bearer realm="sigelo-mcp"' });
    const v = req.headers['mcp-protocol-version'];
    const vModern = v !== undefined && modern.includes(v);
    // 2026-07-28 has no sessions: its requests carry no session to check (the header is ignored).
    const sid = vModern ? undefined : req.headers['mcp-session-id'];
    if (sid !== undefined && !sessions.has(sid)) return out(404, 'unknown or ended session: initialize again\n');
    if (req.method === 'DELETE') { if (sid === undefined) return out(400, 'DELETE needs Mcp-Session-Id\n'); sessions.delete(sid); return out(204, ''); }
    if (!/^application\/json\s*(;|$)/i.test(req.headers['content-type'] ?? '')) return out(415, 'Content-Type must be application/json\n');
    if (v !== undefined && !versions.includes(v)) {
      const j = { jsonrpc: '2.0', id: null, error: { code: UNSUPPORTED, message: `unsupported MCP-Protocol-Version ${v}; supported: ${versions.join(', ')}`, data: { supported: versions, requested: v } } };
      return out(400, JSON.stringify(j), 'application/json');
    }
    const chunks = []; let size = 0;
    req.on('data', (c) => { size += c.length; if (size <= MAX_BODY) chunks.push(c); });
    req.on('end', async () => {
      if (size > MAX_BODY) return out(413, `body over ${MAX_BODY} bytes\n`);
      let msg;
      // Strict, as on stdio: fatal UTF-8 and duplicate keys rejected (SPEC §3).
      try { msg = parseBytes(Buffer.concat(chunks)); } catch (e) { return rpcError(400, -32700, `parse error: ${e.message}`); }
      // 2025-03-26 lets a POST carry a batch (later revisions do not); each element is answered alone.
      if (Array.isArray(msg)) {
        if (v !== undefined && v !== '2025-03-26') return rpcError(400, -32600, `invalid request: no batches in MCP ${v}`);
        if (msg.length === 0) return rpcError(400, -32600, 'invalid request: empty batch');
        const rs = (await Promise.all(msg.map(answer))).filter((r) => r !== null);
        if (rs.length === 0) { res.writeHead(202); return res.end(); }
        return out(200, JSON.stringify(rs), 'application/json');
      }
      let isModern = false;
      if (msg && typeof msg === 'object' && typeof msg.method === 'string') {
        const id = msg.id ?? null, meta = msg.params?._meta?.['io.modelcontextprotocol/protocolVersion'];
        const m = req.headers['mcp-method'], request = msg.id !== undefined;
        isModern = vModern || (meta !== undefined && modern.includes(meta));
        const bad = (what) => rpcError(400, HEADER_MISMATCH, `header mismatch: ${what}`, id);
        if (meta !== undefined && v !== undefined && v !== meta) return bad('MCP-Protocol-Version differs from the body\'s _meta protocol version');
        if (m !== undefined && m !== msg.method) return bad('Mcp-Method differs from the body\'s method');
        // 2026-07-28 requests: the standard headers are required and the version is in _meta too.
        if (isModern && request) {
          if (v === undefined) return bad('MCP-Protocol-Version is missing');
          if (meta === undefined) return bad('the body has no _meta protocol version');
          if (m === undefined) return bad('Mcp-Method is missing');
          const named = { 'tools/call': 'name', 'resources/read': 'uri', 'prompts/get': 'name' }[msg.method];
          if (named) {
            let n = req.headers['mcp-name'];
            const b = typeof n === 'string' && /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(n);
            if (b) n = Buffer.from(b[1], 'base64').toString('utf8');
            if (n === undefined) return bad('Mcp-Name is missing');
            if (n !== msg.params?.[named]) return bad(`Mcp-Name differs from the body's params.${named}`);
          }
        }
      }
      const r = await answer(msg);
      if (r === null) { res.writeHead(202); return res.end(); }
      // 2026-07-28: a method the server does not implement is 404 with -32601.
      if (isModern && r.error?.code === -32601) return out(404, JSON.stringify(r), 'application/json');
      const extra = {};
      if (msg?.method === 'initialize' && r.result) {
        extra['Mcp-Session-Id'] = randomBytes(24).toString('base64url');
        sessions.add(extra['Mcp-Session-Id']);
        if (sessions.size > MAX_SESSIONS) sessions.delete(sessions.values().next().value);  // the oldest
      }
      out(200, JSON.stringify(r), 'application/json', extra);
    });
  });
  server.on('error', (e) => { say(`cannot listen on ${opt.host}:${opt.port}: ${e.message}`); process.exit(1); });
  await new Promise((r) => server.listen(opt.port, opt.host, r));
  const port = server.address().port;
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { server.close(); process.exit(0); });
  // The first line is the one to parse; the rest is for the human starting it.
  say(`listening on ${url(port)}`);
  if (!loopback(opt.host)) say(`WARNING: ${opt.host} is not loopback: anyone who reaches it with the token acts as this identity, and plain HTTP carries the token in clear`);
  say(`identity ${base}; one process serves one identity (SIGELO_IDENTITY picks the file)`);
  // The token is printed once, when made; later starts name the file.
  say(tok.given ? 'bearer token given (SIGELO_MCP_TOKEN or --token), not printed' : tok.made ? `new token, kept in ${tok.file}; paste into your client: ${url(port)}  Authorization: Bearer ${tok.token}` : `bearer token in ${tok.file}`);
  say(`Open WebUI: Settings > Integrations > External Tool Servers > + : Type MCP (Streamable HTTP), URL ${url(port)}, Auth Bearer, the token in Key`);
  return server;
}
