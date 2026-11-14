// SPDX-License-Identifier: MIT
/**
 * `sigelo-agent pass <url>` and the MCP tool `sigelo_pass`: through a site's sigelo-pass/0 door
 * (accept/pass/README.md). The site installed the door and says so with a hint (the Sigelo-Pass
 * header, a Link or <link rel="sigelo-pass">, else its /.well-known/sigelo-pass); without one this
 * does nothing. Never a captcha solver. One round trip: the challenge for our DID, signed by the key
 * provider exactly as `sign-challenge` signs (typ and the five fields checked there), and the bundle.
 * The challenge's ctx must be the page's host, so a challenge another site relays is never signed.
 * The cookie is kept beside the identity (`<identity>.passes.json`, 0600), per origin, until it expires.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { did, parse } from 'sigelo';
import type { VerifyResult } from 'sigelo';
import { bundle, head, type Store } from './sigelo-agent.ts';
import { fail, signChallenge } from './sigelo-agent-keys.ts';

export const V = 'sigelo-pass/0', OPERATOR_CTX = 'sigelo-relay/operator', HINT_PATH = '/.well-known/sigelo-pass';
const TIMEOUT = 20000, MAX_PAGE = 256 * 1024;
export interface Cookie { name: string; value: string; exp: number; path: string }
export interface Clearance { url: string; origin: string; ctx: string; did: string; cookie: Cookie; header: string; reused: boolean }
interface Hint { v: string; ctx: string; challenge: string; accept: string; cookie: string; ttl?: number; wants?: { min_age?: number; age_by?: string[]; operator?: boolean } }

export const passesPath = (identity: string): string => identity.replace(/\.json$/, '') + '.passes.json';
type Passes = Record<string, { did: string } & Cookie>;
function readPasses(identity: string): Passes {
  const p = passesPath(identity);
  try { return existsSync(p) ? (parse(readFileSync(p, 'utf8')) as { passes: Passes }).passes ?? {} : {}; } catch { return {}; }
}
function keep(identity: string, origin: string, d: string, c: Cookie, now: number): void {
  const all = Object.fromEntries(Object.entries(readPasses(identity)).filter(([, v]) => v.exp > now));
  all[origin] = { did: d, ...c };
  const p = passesPath(identity), tmp = join(dirname(p), `.${basename(p)}.${randomBytes(6).toString('hex')}.tmp`);
  writeFileSync(tmp, JSON.stringify({ v: V, passes: all }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  renameSync(tmp, p);
}

const get = (url: string | URL, init: RequestInit = {}): Promise<Response> => fetch(url, { signal: AbortSignal.timeout(TIMEOUT), ...init }).catch((e: Error) => fail('pass_network', `${String(url)}: ${e.message}${e.cause ? ` (${(e.cause as Error).message})` : ''}`));
async function json(r: Response, what: string): Promise<Record<string, unknown>> {
  const t = await r.text();
  try { const j = parse(t); if (j !== null && typeof j === 'object' && !Array.isArray(j)) return j as Record<string, unknown>; } catch { /* below */ }
  return fail('pass_protocol', `${what} is not a JSON object (${r.status})`);
}
const sameOrigin = (u: string, base: URL, what: string): URL => {
  let x: URL;
  try { x = new URL(u, base); } catch { return fail('pass_protocol', `${what} ${JSON.stringify(u)} is not a URL`); }
  if (x.origin !== base.origin) fail('pass_off_site', `${what} ${x.href} is not on ${base.origin}: refusing to follow a hint off the site`);
  return x;
};

/** The hint URL a response carries: the Sigelo-Pass header, a Link rel="sigelo-pass", or an HTML <link>. */
export function hintOf(headers: Headers, html: string): string | undefined {
  const h = headers.get('sigelo-pass')?.trim();
  if (h) return h;
  for (const m of (headers.get('link') ?? '').matchAll(/<([^>]*)>\s*;([^,]*)/g)) if (/(^|;)\s*rel="?([^";]*\s)?sigelo-pass(\s[^";]*)?"?\s*(;|$)/i.test(m[2]!)) return m[1];
  for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
    const rel = /\brel\s*=\s*["']?([^"'>]*)/i.exec(m[0])?.[1] ?? '', href = /\bhref\s*=\s*["']([^"']*)["']/i.exec(m[0])?.[1];
    if (href && rel.toLowerCase().split(/\s+/).includes('sigelo-pass')) return href.replace(/&amp;/g, '&').replace(/&#(\d+);/g, (_, n: string) => String.fromCharCode(Number(n)));
  }
  return undefined;
}

/** null when our own §9.1 result has what the site wants (the site runs the same test); else the refusal. */
export function lacking(result: VerifyResult, wants: Hint['wants'] = {}, now: number): { check: string; detail: string } | null {
  const min = Number(wants.min_age ?? 0);
  if (min > 0) {
    let first = Infinity;
    for (const iss of wants.age_by ?? []) for (const a of result.attestations[iss] ?? []) first = Math.min(first, a.iat);
    const age = first === Infinity ? 0 : now - first;
    if (age < min) return { check: 'wants_age', detail: `this site wants an identity at least ${min} s old, dated by an attestation from ${(wants.age_by ?? []).join(' or ') || '(no issuer named)'}; this identity has ${first === Infinity ? 'none' : `${age} s`}` };
  }
  if (wants.operator && !Object.values(result.attestations).some((l) => l.some((a) => a.ctx === OPERATOR_CTX)))
    return { check: 'wants_operator', detail: `this site wants an operator statement: an unexpired ${OPERATOR_CTX} attestation (your operator gives it: ENROL.md)` };
  return null;
}

/** Through the door at `url`. `fresh`: a new pass even when a kept cookie still opens the page. */
export async function pass(path: string, s: Store, url: string, o: { fresh?: boolean; now?: number } = {}): Promise<Clearance> {
  const now = o.now ?? Math.floor(Date.now() / 1000), me = did(head(s));
  let page: URL;
  try { page = new URL(url); } catch { return fail('usage', `pass: ${JSON.stringify(url)} is not a URL`); }
  if (page.protocol !== 'https:' && page.protocol !== 'http:') fail('usage', `pass: ${page.protocol} is not http(s)`);
  const kept = o.fresh ? undefined : readPasses(path)[page.origin];
  const usable = kept && kept.did === me && kept.exp > now + 30 ? kept : undefined;
  const res = await get(page, { headers: { accept: 'text/html,application/json;q=0.9,*/*;q=0.5', ...(usable && { cookie: `${usable.name}=${usable.value}` }) } });
  const final = new URL(res.url || page.href);
  const out = (c: Cookie, reused: boolean): Clearance => ({ url: final.href, origin: final.origin, ctx: final.host, did: me, cookie: c, header: `${c.name}=${c.value}`, reused });
  if (usable && res.ok) { await res.body?.cancel(); const { did: _, ...c } = usable; return out(c, true); }
  const html = /html/i.test(res.headers.get('content-type') ?? '') ? (await res.text()).slice(0, MAX_PAGE) : (await res.body?.cancel(), '');
  let hintUrl = hintOf(res.headers, html);
  if (hintUrl === undefined) {
    const wk = await get(new URL(HINT_PATH, final), { redirect: 'error' }).catch(() => null);
    if (!wk?.ok) fail('no_hint', `${final.href} answered ${res.status} with no Sigelo-Pass hint, and ${final.origin}${HINT_PATH} is not there: this site has not installed the door (sigelo-agent never solves captchas)`);
    await wk.body?.cancel();
    hintUrl = HINT_PATH;
  }
  const hu = sameOrigin(hintUrl, final, 'the hint');
  const h = await json(await get(hu, { redirect: 'error', headers: { accept: 'application/json' } }), `the hint file ${hu.href}`) as unknown as Hint;
  if (h.v !== V) fail('pass_version', `the hint file says v ${JSON.stringify(h.v)}; this agent speaks ${V}`);
  if (h.ctx !== final.host) fail('pass_ctx', `the hint names ctx ${JSON.stringify(h.ctx)}, but the page is on ${final.host}: refusing (a pass is bound to the site that asks)`);
  if (typeof h.challenge !== 'string' || typeof h.accept !== 'string' || typeof h.cookie !== 'string' || !/^[\w.-]{1,64}$/.test(h.cookie)) fail('pass_protocol', 'the hint file lacks challenge, accept or a cookie name');
  const { bundle: b, result } = bundle(s, now), want = lacking(result, h.wants, now);
  if (want) fail(want.check, want.detail);
  const cu = sameOrigin(h.challenge, hu, 'the challenge URL'), au = sameOrigin(h.accept, hu, 'the accept URL');
  cu.searchParams.set('did', me);
  const cr = await get(cu, { redirect: 'error', headers: { accept: 'application/json' } });
  if (!cr.ok) refused(cr, await json(cr, 'the challenge refusal'));
  const c = await json(cr, 'the challenge');
  if (c['ctx'] !== final.host) fail('pass_ctx', `the challenge names ctx ${JSON.stringify(c['ctx'])}, not ${final.host}: refusing to sign a challenge meant for another site`);
  const { sig } = signChallenge(path, s, c);
  const ar = await get(au, { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ challenge: c, did: me, sig, bundle: b }) });
  const a = await json(ar, 'the accept answer');
  if (!ar.ok) refused(ar, a);
  const k = a['cookie'] as Partial<Cookie> | undefined;
  if (a['did'] !== me || k?.name !== h.cookie || typeof k.value !== 'string' || !/^[\x21-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{1,4096}$/.test(k.value) || !Number.isSafeInteger(k.exp) || k.exp! <= now)
    fail('pass_protocol', 'the site said yes but sent no usable cookie { name, value, exp } for this DID');
  const cookie: Cookie = { name: k.name, value: k.value, exp: k.exp!, path: typeof k.path === 'string' && k.path.startsWith('/') ? k.path : '/' };
  keep(path, final.origin, me, cookie, now);
  return out(cookie, false);
}

function refused(r: Response, j: Record<string, unknown>): never {
  const code = typeof j['check'] === 'string' && /^[a-z_]{1,32}$/.test(j['check']) ? j['check'] : 'pass_refused';
  const wait = r.headers.get('retry-after');
  return fail(code === 'rate_limited' || code.startsWith('wants_') ? code : 'pass_refused', `the site answered ${r.status}${code === 'pass_refused' ? '' : ` ${code}`}: ${String(j['error'] ?? '').slice(0, 300)}${wait ? ` (retry after ${wait} s)` : ''}`);
}
