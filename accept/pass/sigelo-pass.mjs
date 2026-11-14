// SPDX-License-Identifier: MIT
// sigelo-pass/0, the site side (accept/pass/README.md): a door for AI agents beside your captcha,
// built on accept/node/sigelo-accept.mjs. Node http or Express (req, res, next):
//   const door = sigeloPass({ origin: 'https://example.com', secret: process.env.SIGELO_PASS_SECRET });
//   app.use(door.routes);                 // hint file, challenge, accept
//   app.use('/members', door.gate);       // no valid cookie → 403 with the Sigelo-Pass hint
// door.check(req) → { did, exp } or null, for your own gates; req.sigeloPass after door.gate.
import { parseBytes } from 'sigelo';
import { accept, challenge } from '../node/sigelo-accept.mjs';
import { COOKIE, HINT_PATH, V, addrKey, check, hint, isDid, limiter, mint, readCookie, secretOf, setCookie, wall, wanting } from './clearance.mjs';

const MAX_BODY = 256 * 1024, MAX_ITEMS = 64;
const fail = (status, check, error, extra) => Object.assign(new Error(error), { status, check, extra });

/**
 * origin: the site as the agent reaches it ('https://example.com'); ctx is its host.
 * secret: ≥ 32 bytes, signs the cookie. ttl: cookie life in s (3600). wants: { min_age, age_by, operator }.
 * limits: { per_did, per_addr, window } challenges per window (20, 60, 3600). addr(req): the client
 * address (behind a proxy, from your trusted header). onAccept(result, req): your own policy over the
 * §9.1 result; throw to refuse. paths: { hint, challenge, accept }.
 */
export function sigeloPass(o) {
  const origin = new URL(o.origin), ctx = origin.host, secret = secretOf(o.secret);
  const ttl = o.ttl ?? 3600, cookie = o.cookie ?? COOKIE, wants = o.wants ?? {};
  if ((wants.min_age ?? 0) > 0 && !(wants.age_by?.length)) throw new Error('wants.min_age needs wants.age_by: the issuers whose attestations date an identity');
  const limits = { per_did: 20, per_addr: 60, window: 3600, ...o.limits };
  const paths = { hint: HINT_PATH, challenge: '/sigelo-pass/challenge', accept: '/sigelo-pass/accept', ...o.paths };
  const hintUrl = new URL(paths.hint, origin).href, hit = limiter(limits.window);
  const addr = o.addr ?? ((req) => req.socket?.remoteAddress);
  const doc = hint({ ctx, challenge: paths.challenge, accept: paths.accept, cookie, ttl, wants, limits });
  const send = (res, status, body, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }); res.end(JSON.stringify(body) + '\n'); };

  const limit = (key, max) => { const wait = hit(key, max); if (wait) throw fail(429, 'rate_limited', `too many passes from this ${key.startsWith('did ') ? 'DID' : 'address'}: try again in ${wait} s`, { 'retry-after': String(wait) }); };

  async function body(req) {
    if (req.body !== undefined && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;   // a parser ran first
    const parts = []; let n = 0;
    for await (const c of req) { n += c.length; if (n > MAX_BODY) throw fail(413, 'request', `body over ${MAX_BODY} bytes`); parts.push(c); }
    try { return parseBytes(Buffer.concat(parts)); } catch (e) { throw fail(400, 'request', `body is not strict JSON: ${e.message}`); }
  }

  function issue(req, url) {
    const d = url.searchParams.get('did');
    if (!isDid(d)) throw fail(400, 'request', 'did: want ?did=did:sigelo:z… (your current DID, in full)');
    limit(`addr ${addrKey(addr(req))}`, limits.per_addr);
    limit(`did ${d}`, limits.per_did);
    return challenge(d, ctx);
  }

  async function enter(req) {
    const b = await body(req);
    if (b === null || typeof b !== 'object' || typeof b.challenge !== 'object' || b.challenge === null || typeof b.did !== 'string' || typeof b.sig !== 'string')
      throw fail(400, 'request', 'want { challenge, did, sig, bundle }: the challenge object as received');
    // A challenge another site (another door in this process) issued is refused before it is spent.
    if (b.challenge.ctx !== ctx) throw fail(401, 'ctx', `challenge ctx is ${JSON.stringify(b.challenge.ctx)}, not this site's ${ctx}`);
    const items = ['rotations', 'attestations', 'bindings'].reduce((n, k) => n + (Array.isArray(b.bundle?.[k]) ? b.bundle[k].length : 0), 0);
    if (items > MAX_ITEMS) throw fail(413, 'request', `bundle has more than ${MAX_ITEMS} rotations+attestations+bindings`);
    let result;
    try { result = accept(b.challenge, b, b.bundle); } catch (e) { throw fail(401, 'refused', e.message); }
    const now = Math.floor(Date.now() / 1000), w = wanting(result, wants, now);
    if (w) throw fail(403, w.check, w.error);
    if (o.onAccept) { try { await o.onAccept(result, req); } catch (e) { throw fail(403, 'policy', e.message); } }
    const exp = now + ttl, value = mint(secret, ctx, result.did, exp);
    return { did: result.did, exp, value };
  }

  async function routes(req, res, next) {
    const url = new URL(req.originalUrl ?? req.url, origin);
    try {
      if (req.method === 'GET' && url.pathname === paths.hint) return send(res, 200, doc);
      if (req.method === 'GET' && url.pathname === paths.challenge) return send(res, 200, issue(req, url));
      if (req.method === 'POST' && url.pathname === paths.accept) {
        const { did, exp, value } = await enter(req);
        return send(res, 200, { v: V, did, cookie: { name: cookie, value, exp, path: '/' } }, { 'set-cookie': setCookie(cookie, value, { ttl, secure: origin.protocol === 'https:' }) });
      }
    } catch (e) {
      if (!e.status) throw e;
      return send(res, e.status, { error: e.message, check: e.check }, e.extra);
    }
    return next ? next() : send(res, 404, { error: 'not found' });
  }

  const passOf = (req) => check(secret, ctx, readCookie(req.headers.cookie, cookie), Math.floor(Date.now() / 1000), ttl);
  function gate(req, res, next) {
    const p = passOf(req);
    if (p) { req.sigeloPass = p; return next(); }
    const w = wall(hintUrl);
    res.writeHead(403, w.headers); res.end(w.body);
  }
  return { routes, gate, check: passOf, hint: doc, hintUrl, ctx };
}
