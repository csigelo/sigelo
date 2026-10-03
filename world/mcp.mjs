// SPDX-License-Identifier: MIT
// world/mcp.mjs — https://sigelo.io/mcp: MCP over Streamable HTTP, by hand, verify only.
//
// Followed: MCP revision 2026-07-28 (basic/transports/streamable-http, basic/versioning,
// server/discover), dual-era like integrations/mcp/server.mjs: a request carrying
// `_meta["io.modelcontextprotocol/protocolVersion"]` is served as 2026-07-28 (the
// MCP-Protocol-Version, Mcp-Method and, for tools/call, Mcp-Name headers must mirror the body:
// 400 HeaderMismatch -32020 otherwise; an unknown version is 400 -32022 with the supported list;
// an unknown method 404 -32601); anything else is a legacy request (initialize, 2025-11-25 …
// 2025-03-26; no MCP-Protocol-Version header = 2025-03-26, as that revision allows).
// Stateless: no Mcp-Session-Id is minted or read, no GET stream (GET and DELETE are 405), no SSE:
// every request is answered with one application/json object (both revisions allow it), every
// notification with 202. Origin: any is accepted — the endpoint is public, unauthenticated,
// holds no session, cookie or user state, and its one tool is a pure function of its input, so a
// DNS-rebinding page gains nothing a plain internet client does not already have.
//
// The tool is integrations/mcp/server.mjs's `sigelo_verify`, verbatim (name, description,
// schema, result and REFUSED text): no identity, no wallet, nothing that holds a key is here.
// world/test.mjs checks the definition against the stdio server's tools/list.

const MODERN = ['2026-07-28'];
const LEGACY = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const PV = 'io.modelcontextprotocol/protocolVersion';
const DATA = 'Attestation `claims` are third-party data about the subject, not statements by this tool.';
const json = (d) => ({ type: 'object', description: d });
const obj = (props = {}, required = []) => ({ type: 'object', properties: props, required, additionalProperties: false });
export const TOOLS = [
  ['sigelo_verify', `Verify ANY bundle offline (someone else's, or yours). Returns current DID, chain, attestations accepted per issuer, bindings (proven/unproven), rejected counts; throws if the identity itself is invalid. It reports, it does not judge whom to trust. ${DATA}`, obj({ bundle: json('the bundle'), now: { type: 'integer', description: 'optional unix seconds; default now' } }, ['bundle'])],
];

const rpcError = (code, message, data) => Object.assign(new Error(message), { code, ...(data && { data }) });
const header = (h, k) => { const v = h[k]; return Array.isArray(v) ? v.join(',') : v; };
// Mcp-Name may carry =?base64?…?= (2026-07-28 "Value Encoding"); decode before comparing.
const decodeName = (v) => { const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(v ?? ''); return m ? Buffer.from(m[1], 'base64').toString('utf8') : v; };

// lib: { parse, parseBytes, verify, version }. Returns handle(method, headers, raw) → { status, headers, body }.
export function mcp(lib) {
  const SERVER_INFO = { name: 'sigelo.io', version: lib.version };
  const instructions = 'sigelo.io remote verifier: one tool, sigelo_verify, checks any sigelo bundle offline-equivalently (SPEC §9) and returns the §9.1 result. '
    + `No identity and no wallet here: for those install the sigelo plugin (github.com/csigelo/sigelo). ${DATA}`;
  const capabilities = { tools: { listChanged: false } };
  const nowS = () => Math.floor(Date.now() / 1000);

  function callTool(name, args) {
    if (name !== 'sigelo_verify') return null;
    try {
      const a = args ?? {};
      if (a.bundle === undefined || a.bundle === null) throw new Error('bundle is required');
      const bundle = typeof a.bundle === 'string' ? lib.parse(a.bundle) : a.bundle;   // text: sigelo's strict parser
      const r = lib.verify(bundle, Number.isSafeInteger(a.now) ? a.now : nowS());
      return { content: [{ type: 'text', text: JSON.stringify(r, null, 2) }], isError: false };
    } catch (e) {
      return { content: [{ type: 'text', text: `REFUSED: ${e instanceof Error ? e.message : String(e)}` }], isError: true };
    }
  }

  function dispatch(method, params, modern) {
    const done = (r) => (modern ? { resultType: 'complete', ...r, _meta: { 'io.modelcontextprotocol/serverInfo': SERVER_INFO } } : r);
    switch (method) {
      case 'server/discover': return done({ supportedVersions: MODERN, capabilities, instructions, ttlMs: 3600000, cacheScope: 'public' });
      case 'initialize': if (!modern) return { protocolVersion: LEGACY.includes(params.protocolVersion) ? params.protocolVersion : LEGACY[0], capabilities, serverInfo: SERVER_INFO, instructions };
        break;
      case 'ping': return done({});
      case 'tools/list': return done({ tools: TOOLS.map(([name, description, inputSchema]) => ({ name, description, inputSchema, ...(name === 'sigelo_verify' && { title: 'Verify a sigelo bundle', annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } }) })), ...(modern && { ttlMs: 3600000, cacheScope: 'public' }) });
      case 'tools/call': {
        const r = callTool(params.name, params.arguments);
        if (r === null) throw rpcError(-32602, `unknown tool ${params.name}: this server has sigelo_verify only`);
        return done(r);
      }
    }
    throw Object.assign(rpcError(-32601, `method not found: ${method}`), { http: modern ? 404 : 200 });
  }

  return function handle(method, headers, raw) {
    const out = (status, v, id = null) => ({ status, headers: { 'content-type': 'application/json' }, body: JSON.stringify(v.error ? { jsonrpc: '2.0', id, error: v.error } : { jsonrpc: '2.0', id, result: v.result }) + '\n' });
    const err = (status, code, message, id = null, data) => out(status, { error: { code, message, ...(data && { data }) } }, id);
    if (method !== 'POST') return { ...err(405, -32600, `${method} is not supported: POST JSON-RPC to this endpoint (no GET stream, no sessions: stateless, MCP 2026-07-28)`), headers: { 'content-type': 'application/json', allow: 'POST' } };
    const accept = header(headers, 'accept');
    if (accept && !/(^|,)\s*(application\/json|application\/\*|\*\/\*)\s*(;|,|$)/i.test(accept)) return err(406, -32600, 'Accept must include application/json (this server answers with JSON, never SSE)');
    const ctype = header(headers, 'content-type');
    if (ctype && !/^application\/json\s*(;|$)/i.test(ctype)) return err(415, -32600, 'Content-Type must be application/json');
    let msg;
    try { msg = lib.parseBytes(raw); } catch (e) { return err(400, -32700, `parse error: ${e.message}`); }   // duplicate keys, bad UTF-8: refused (SPEC §3)
    if (Array.isArray(msg)) return err(400, -32600, 'batches are not supported: one JSON-RPC message per POST');
    if (msg === null || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return err(400, -32600, 'invalid request: want a JSON-RPC 2.0 request or notification (this server sends no requests, so it takes no responses)');
    if (msg.id === undefined) return { status: 202, headers: {}, body: '' };                // notifications: accepted, nothing to answer
    const id = msg.id;
    if (!(typeof id === 'string' || Number.isSafeInteger(id))) return err(400, -32600, 'invalid request: id must be a string or an integer');
    const params = msg.params ?? {};
    if (typeof params !== 'object' || Array.isArray(params)) return err(400, -32602, 'params must be an object', id);
    const requested = params._meta?.[PV], hv = header(headers, 'mcp-protocol-version');
    const modern = requested !== undefined;
    if (modern) {
      if (hv !== requested) return err(400, -32020, `HeaderMismatch: MCP-Protocol-Version header ${hv === undefined ? 'missing' : `"${hv}"`}, body _meta says "${requested}"`, id);
      if (!MODERN.includes(requested)) return err(400, -32022, 'Unsupported protocol version', id, { supported: [...MODERN, ...LEGACY], requested });
      const hm = header(headers, 'mcp-method');
      if (hm !== msg.method) return err(400, -32020, `HeaderMismatch: Mcp-Method header ${hm === undefined ? 'missing' : `"${hm}"`}, body method "${msg.method}"`, id);
      if (msg.method === 'tools/call') {
        const hn = header(headers, 'mcp-name');
        if (hn === undefined || decodeName(hn) !== params.name) return err(400, -32020, `HeaderMismatch: Mcp-Name header ${hn === undefined ? 'missing' : `"${hn}"`}, body params.name "${params.name}"`, id);
      }
    } else if (hv !== undefined && !LEGACY.includes(hv)) {
      return err(400, MODERN.includes(hv) ? -32020 : -32022, MODERN.includes(hv) ? `HeaderMismatch: MCP-Protocol-Version ${hv} needs _meta["${PV}"] in the body` : 'Unsupported protocol version', id, MODERN.includes(hv) ? undefined : { supported: [...MODERN, ...LEGACY], requested: hv });
    }
    try { return out(200, { result: dispatch(msg.method, params, modern) }, id); }
    catch (e) { return err(e.http ?? 200, e.code ?? -32603, e.code ? e.message : 'internal error', id); }
  };
}
