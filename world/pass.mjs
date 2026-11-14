// SPDX-License-Identifier: MIT
// world/pass.mjs — the agent pass demo lane at https://sigelo.io/world/pass/ (accept/pass/README.md):
// a page behind a sigelo-pass/0 door. A browser gets the 403 with the hint; `sigelo-agent pass
// https://sigelo.io/world/pass/` gets through. The handshake is the world's own §5.2 check
// (GET /world/challenge, proveControl in server.mjs), the clearance accept/pass/clearance.mjs's
// cookie, signed with pass.key in the world's state directory (made at first start, 0600).
// The cookie is set only for an agent that asked for it and lives one hour.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { V, check, hint, limiter, mint, readCookie, setCookie, wall } from '../accept/pass/clearance.mjs';

const TTL = 3600, PAGE = '/world/pass/', HINT = '/world/pass/hint', COOKIE = 'sigelo_pass';

export function passLane({ state, ctx, proveControl }) {
  const file = join(state, 'pass.key');
  if (!existsSync(file)) writeFileSync(file, randomBytes(32).toString('hex') + '\n', { mode: 0o600, flag: 'wx' });
  const secret = Buffer.from(readFileSync(file, 'utf8').trim(), 'utf8'), hit = limiter(3600);
  const hintUrl = `https://${ctx}${HINT}`;
  // per_addr: nginx's 60 a minute per /24 or /48 (the service sees no address); per_did: here.
  const doc = hint({ ctx, challenge: '/world/challenge', accept: '/world/pass/accept', cookie: COOKIE, ttl: TTL, limits: { per_did: 20, per_addr: 60, window: 3600 } });
  const json = (status, v, headers = {}) => ({ status, headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(v) + '\n' });
  const page = (did) => `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>Through the agent pass</title></head>\n<body><h1>Through</h1>`
    + `<p>You are <code>${did}</code>. This page let you in because you proved that DID, not because you solved anything. Your cookie lasts an hour.</p>`
    + '<p><a href="https://sigelo.io/accept.html">Install the door on your site</a></p></body></html>\n';

  /** method, path, the Cookie header, the parsed POST body → { status, headers, body }; null when the path is not ours. */
  return (method, path, cookie, body) => {
    try {
      if (path === HINT && method === 'GET') return json(200, doc);
      if (path === PAGE && method === 'GET') {
        const p = check(secret, ctx, readCookie(cookie, COOKIE), Math.floor(Date.now() / 1000), TTL);
        if (p) return { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }, body: page(p.did) };
        const w = wall(hintUrl);
        return { status: 403, headers: w.headers, body: w.body };
      }
      if (path === '/world/pass/accept' && method === 'POST') {
        const wait = typeof body.did === 'string' ? hit(`did ${body.did}`, doc.limits.per_did) : 0;
        if (wait) return json(429, { error: `too many passes for this DID: try again in ${wait} s`, check: 'rate_limited' }, { 'retry-after': String(wait) });
        const { now } = proveControl(body), exp = now + TTL, value = mint(secret, ctx, body.did, exp);
        return json(200, { v: V, did: body.did, cookie: { name: COOKIE, value, exp, path: PAGE } }, { 'set-cookie': setCookie(COOKIE, value, { ttl: TTL, path: PAGE, secure: true }) });
      }
      if ([PAGE, HINT, '/world/pass/accept'].includes(path)) return json(405, { error: `no ${method} ${path}` });
      return null;
    } catch (e) {
      if (!e.status) throw e;
      return json(e.status, { error: e.message, check: 'refused' });
    }
  };
}
