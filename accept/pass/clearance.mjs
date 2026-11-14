// SPDX-License-Identifier: MIT
// sigelo-pass/0 without the handshake (accept/pass/README.md): the clearance cookie, the hint file,
// what the site wants, the rate limits and the 403 page. No dependencies, node:crypto only, so a
// site with its own §5.2 check (world/server.mjs) uses it as is. sigelo-pass.mjs adds the handshake.
import { createHmac, timingSafeEqual } from 'node:crypto';

export const V = 'sigelo-pass/0', COOKIE = 'sigelo_pass', OPERATOR_CTX = 'sigelo-relay/operator';
export const HINT_PATH = '/.well-known/sigelo-pass';
const DID_RE = /^did:sigelo:z[1-9A-HJ-NP-Za-km-z]{40,50}$/;

/** The site's secret, at least 32 bytes: a string (its UTF-8 bytes) or a Buffer. */
export function secretOf(s) {
  const b = typeof s === 'string' ? Buffer.from(s, 'utf8') : Buffer.isBuffer(s) ? s : null;
  if (!b || b.length < 32) throw new Error('secret: want at least 32 bytes (openssl rand -hex 32)');
  return b;
}
const mac = (secret, ctx, did, exp) => createHmac('sha256', secret).update(`${V}\n${ctx}\n${did}\n${exp}`).digest('base64url');

/** The cookie value: sp0.<did>.<exp>.<HMAC-SHA256(secret, "sigelo-pass/0\n" ctx "\n" did "\n" exp), base64url>. */
export const mint = (secret, ctx, did, exp) => `sp0.${did}.${exp}.${mac(secret, ctx, did, exp)}`;

/** { did, exp } for a value this site minted for ctx and not yet expired; else null. ttl bounds exp from above. */
export function check(secret, ctx, value, now = Math.floor(Date.now() / 1000), ttl = 86400) {
  const m = typeof value === 'string' && /^sp0\.(did:sigelo:z[1-9A-HJ-NP-Za-km-z]{40,50})\.(\d{1,12})\.([\w-]{43})$/.exec(value);
  if (!m) return null;
  const [, did, e, sig] = m, exp = Number(e), want = Buffer.from(mac(secret, ctx, did, exp));
  if (!timingSafeEqual(Buffer.from(sig), want)) return null;
  return exp > now && exp <= now + ttl ? { did, exp } : null;
}

/** One cookie's value from a Cookie header, or undefined. */
export function readCookie(header, name = COOKIE) {
  for (const part of String(header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

export function setCookie(name, value, { ttl, path = '/', secure }) {
  return `${name}=${value}; Path=${path}; Max-Age=${ttl}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
}

/** The hint file (README "Hint file"). URLs may be relative to the hint's own URL. */
export function hint({ ctx, challenge, accept, cookie = COOKIE, ttl, wants = {}, limits }) {
  return { v: V, ctx, challenge, accept, cookie, ttl,
    wants: { min_age: wants.min_age ?? 0, age_by: wants.age_by ?? [], operator: Boolean(wants.operator) },
    limits: { per_did: limits.per_did, per_addr: limits.per_addr, window: limits.window } };
}

/** The age the site can count: now − the earliest iat of an accepted attestation from an age_by issuer
 *  (genesis `created` is self-asserted, SPEC §4, and never counts). 0 when there is none. */
export function ageOf(result, ageBy, now) {
  let first = Infinity;
  for (const iss of ageBy ?? []) for (const a of result?.attestations?.[iss] ?? []) if (Number.isSafeInteger(a.iat)) first = Math.min(first, a.iat);
  return first === Infinity ? 0 : Math.max(0, now - first);
}
export const hasOperator = (result) => Object.values(result?.attestations ?? {}).some((list) => list.some((a) => a.ctx === OPERATOR_CTX));

/** null when the §9.1 result has what the site wants; else { check, error }. Agent and site run the same test. */
export function wanting(result, wants = {}, now = Math.floor(Date.now() / 1000)) {
  if ((wants.min_age ?? 0) > 0 && ageOf(result, wants.age_by, now) < wants.min_age)
    return { check: 'wants_age', error: `this site wants an identity at least ${wants.min_age} s old, counted from an attestation by ${(wants.age_by ?? []).join(' or ') || 'nobody (age_by is empty)'}` };
  if (wants.operator && !hasOperator(result))
    return { check: 'wants_operator', error: `this site wants an operator statement: an unexpired ${OPERATOR_CTX} attestation in the bundle` };
  return null;
}

/** Fixed windows: hit(key, max) → 0 when under max, else the seconds until the window resets. */
export function limiter(window = 3600, cap = 100000) {
  const seen = new Map();
  return (key, max, now = Math.floor(Date.now() / 1000)) => {
    let w = seen.get(key);
    if (!w || w.reset <= now) {
      if (seen.size >= cap) for (const [k, v] of seen) if (v.reset <= now || seen.size >= cap) seen.delete(k); else break;
      w = { n: 0, reset: now + window }; seen.set(key, w);
    }
    return ++w.n > max ? w.reset - now : 0;
  };
}
/** The address a limit counts: IPv4 as is, IPv6 by its /64. */
export function addrKey(a) {
  const s = String(a ?? '').replace(/^::ffff:(?=\d+\.)/, '');
  if (!s.includes(':')) return s;
  const [head, tail = ''] = s.split('::'), h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const full = s.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  return full.slice(0, 4).map((x) => x.toLowerCase().replace(/^0+(?=.)/, '')).join(':') + '::/64';
}

export const isDid = (d) => typeof d === 'string' && DID_RE.test(d);

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
/** The headers and HTML of the wall: the hint as Sigelo-Pass and Link, and <link rel="sigelo-pass"> in the page. */
export function wall(hintUrl, title = 'Agents: show your sigelo pass') {
  return {
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'sigelo-pass': hintUrl, link: `<${hintUrl}>; rel="sigelo-pass"` },
    body: `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title>\n<link rel="sigelo-pass" href="${esc(hintUrl)}"></head>\n`
      + `<body><h1>${esc(title)}</h1><p>This page admits AI agents that prove a sigelo identity. An agent runs <code>sigelo-agent pass &lt;this URL&gt;</code>, then loads the page with the cookie it gets. The site installed this door; nothing here is a captcha to solve.</p></body></html>\n`,
  };
}
