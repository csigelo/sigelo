#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// sigelo-pass/0 verifier for nginx auth_request and Caddy forward_auth (accept/pass/README.md):
// one process on loopback that serves the hint file, the challenge and accept routes, and answers
// the subrequest GET /sigelo-pass/check: 204 + Sigelo-Pass-DID for a valid cookie, else 403 with
// the wall (Sigelo-Pass header, Link, the HTML page), which Caddy passes on and nginx maps to
// /sigelo-pass/wall through error_page. No framework.
// Env: SIGELO_PASS_ORIGIN (https://example.com, required), SIGELO_PASS_SECRET_FILE (≥ 32 bytes,
// required; or SIGELO_PASS_SECRET), SIGELO_PASS_PORT (8791; 0 = any), SIGELO_PASS_TTL (3600),
// SIGELO_PASS_ADDR_HEADER (the proxy's client-address header, e.g. x-real-ip; unset = the socket),
// SIGELO_PASS_OPERATOR=1, SIGELO_PASS_MIN_AGE (s) + SIGELO_PASS_AGE_BY (issuer DIDs, comma-separated).
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { sigeloPass } from './sigelo-pass.mjs';
import { wall } from './clearance.mjs';

const env = process.env;
if (!env.SIGELO_PASS_ORIGIN || !(env.SIGELO_PASS_SECRET_FILE || env.SIGELO_PASS_SECRET)) {
  console.error('verifier: set SIGELO_PASS_ORIGIN and SIGELO_PASS_SECRET_FILE (see the header of accept/pass/verifier.mjs)');
  process.exit(2);
}
const header = env.SIGELO_PASS_ADDR_HEADER?.toLowerCase();
const door = sigeloPass({
  origin: env.SIGELO_PASS_ORIGIN,
  secret: env.SIGELO_PASS_SECRET_FILE ? readFileSync(env.SIGELO_PASS_SECRET_FILE, 'utf8').trim() : env.SIGELO_PASS_SECRET,
  ttl: Number(env.SIGELO_PASS_TTL ?? 3600),
  wants: { operator: env.SIGELO_PASS_OPERATOR === '1', min_age: Number(env.SIGELO_PASS_MIN_AGE ?? 0), age_by: (env.SIGELO_PASS_AGE_BY ?? '').split(',').filter(Boolean) },
  addr: (req) => (header ? String(req.headers[header] ?? '').split(',')[0].trim() : req.socket.remoteAddress),
});

const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://verifier').pathname;
  try {
    if (path === '/sigelo-pass/check' || path === '/sigelo-pass/wall') {
      const p = path === '/sigelo-pass/check' && door.check(req);
      if (p) { res.writeHead(204, { 'sigelo-pass-did': p.did, 'cache-control': 'no-store' }); return res.end(); }
      const w = wall(door.hintUrl);
      res.writeHead(403, w.headers); return res.end(w.body);
    }
    await door.routes(req, res);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) { res.writeHead(500, { 'content-type': 'application/json' }); res.end('{"error":"internal error"}\n'); }
  }
});
server.requestTimeout = 20000; server.headersTimeout = 10000;
server.listen(Number(env.SIGELO_PASS_PORT ?? 8791), '127.0.0.1', () => console.log(`sigelo-pass verifier for ${door.ctx} on 127.0.0.1:${server.address().port}`));
for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => server.close(() => process.exit(0)));
