// SPDX-License-Identifier: MIT
// `sigelo-agent pass <url>` against accept/pass's drop-in in this process, on loopback: the hint
// (header, Link-free HTML <link>, /.well-known), the handshake, the kept cookie, --fresh, --json;
// refusals before anything is signed (wants, a hint or challenge for another ctx, a hint off the
// site, no hint at all) and the site's own (policy, rate limit). SKIPs without accept/pass's and
// accept/node's node_modules (npm install in each).
//   node test-pass.ts   → ALL PASS test-pass.ts (n ok)
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { attest, keygen } from 'sigelo';
import { cliIn, done, now, ok, posixModes, ROOT, tmpHome } from './test-helpers.ts';
import { passesPath } from './sigelo-agent-pass.ts';

const PASS = join(ROOT, 'accept', 'pass');
if (!['pass', 'node'].every((d) => existsSync(join(ROOT, 'accept', d, 'node_modules', 'sigelo')))) {
  console.log('SKIP sigelo-agent pass: accept/pass and accept/node have no node_modules (npm install in each)');
  done(import.meta.filename);
}
type Handler = (req: IncomingMessage, res: ServerResponse, next?: () => void) => void | Promise<void>;
type Door = { routes: Handler; gate: Handler; hintUrl: string };
const { sigeloPass } = await import(pathToFileURL(join(PASS, 'sigelo-pass.mjs')).href) as { sigeloPass(o: object): Door };
const SECRET = 's'.repeat(40);
const HOME = tmpHome('pass'), ID = join(HOME, 'agent.local.json');
const cli = cliIn({ PATH: process.env['PATH'], HOME, SIGELO_KEY_PROVIDER: 'file', SIGELO_IDENTITY: ID }, HOME);
console.warn = () => {};

const servers: { close(): void }[] = [];
/** A loopback site; `make(origin)` returns its handler. */
async function site(make: (origin: string) => Handler): Promise<string> {
  const srv = createServer();
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const origin = `http://127.0.0.1:${(srv.address() as { port: number }).port}`, h = make(origin);
  srv.on('request', (req, res) => { void h(req, res); });
  servers.push(srv);
  return origin;
}
let accepts = 0;
const doorSite = (opts: object = {}) => site((origin) => {
  const d = sigeloPass({ origin, secret: SECRET, ...opts });
  return (req, res) => {
    if (req.url === '/sigelo-pass/accept') accepts++;
    void d.routes(req, res, () => {
      if (req.url!.startsWith('/members')) return void d.gate(req, res, () => { res.writeHead(200); res.end(`hello ${(req as { sigeloPass?: { did: string } }).sigeloPass!.did}\n`); });
      if (req.url === '/plain') { res.writeHead(403, { 'content-type': 'text/html' }); res.end('<h1>no bots</h1>'); return; }
      res.writeHead(404); res.end();
    });
  };
});
const html = (status: number, body: string, headers: Record<string, string> = {}) => (_: IncomingMessage, res: ServerResponse) => { res.writeHead(status, { 'content-type': 'text/html', ...headers }); res.end(body); };
const get = async (url: string, cookie?: string) => { const r = await fetch(url, { headers: cookie ? { cookie } : {} }); return { status: r.status, text: await r.text() }; };

const me = JSON.parse((await cli('init', '--no-recovery')).stdout) as { did: string };
const S = await doorSite();

// ── through the door ─────────────────────────────────────────────────────────
let r = await cli('pass', `${S}/members/`);
const header = /^cookie {3}(sigelo_pass=\S+)$/m.exec(r.stdout)?.[1];
ok('pass: exit 0, prints "cookie name=value", the expiry and the DID', r.status === 0 && header !== undefined && /^expires {2}\d{4}-\d\d-\d\dT/m.test(r.stdout) && r.stdout.includes(`did      ${me.did}`), r.stderr + r.stdout);
ok('the printed cookie opens the gated page', (await get(`${S}/members/`, header)).text === `hello ${me.did}\n`);
ok('the cookie is kept beside the identity, per origin', JSON.parse(readFileSync(passesPath(ID), 'utf8')).passes[S]?.value === header?.slice('sigelo_pass='.length));
if (posixModes) ok('the passes file is 0600', (statSync(passesPath(ID)).mode & 0o777) === 0o600);
const before = accepts;
r = await cli('pass', `${S}/members/`, '--json');
let j = JSON.parse(r.stdout) as { did: string; ctx: string; header: string; reused: boolean; cookie: { name: string; value: string; exp: number; path: string } };
ok('--json: { did, ctx, cookie { name, value, exp, path }, header, reused }; a kept cookie that still opens the page is reused', r.status === 0 && j.reused && j.header === header && j.ctx === new URL(S).host && j.cookie.path === '/' && j.cookie.exp > now && accepts === before, r.stderr);
r = await cli('pass', `${S}/members/`, '--json', '--fresh');
j = JSON.parse(r.stdout);
ok('--fresh: a new handshake', r.status === 0 && !j.reused && accepts === before + 1);
r = await cli('pass', `${S}/plain`, '--json');
ok('no hint on the page: /.well-known/sigelo-pass of the origin is the door', r.status === 0 && !JSON.parse(r.stdout).reused, r.stderr);
const L = await site((origin) => { const d = sigeloPass({ origin, secret: SECRET }); return (req, res) => void d.routes(req, res, () => html(403, `<html><head><link href="${d.hintUrl}" rel="preload sigelo-pass"></head></html>`)(req, res)); });
r = await cli('pass', `${L}/x`, '--json');
ok('only an HTML <link rel="… sigelo-pass"> → through', r.status === 0, r.stderr);

// ── refused before anything is signed ───────────────────────────────────────
const W = keygen({ recovery: null });
const O = await doorSite({ wants: { operator: true } });
let n = accepts;
r = await cli('pass', `${O}/members/`);
ok('wants an operator statement this identity lacks → exit 1 wants_operator, nothing posted', r.status === 1 && r.stderr.includes('wants_operator') && accepts === n, r.stderr);
const A = await doorSite({ wants: { min_age: 86400, age_by: ['did:sigelo:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'] } });
r = await cli('pass', `${A}/members/`);
ok('wants an identity age this identity lacks → exit 1 wants_age, nothing posted', r.status === 1 && r.stderr.includes('wants_age') && accepts === n, r.stderr);
const C = await site((origin) => (req, res) => req.url === '/hint'
  ? void (res.writeHead(200, { 'content-type': 'application/json' }), res.end(JSON.stringify({ v: 'sigelo-pass/0', ctx: 'other.example', challenge: '/c', accept: '/a', cookie: 'sigelo_pass' })))
  : html(403, 'no', { 'sigelo-pass': `${origin}/hint` })(req, res));
r = await cli('pass', `${C}/`);
ok('a hint naming another ctx → exit 1 pass_ctx', r.status === 1 && r.stderr.includes('pass_ctx'), r.stderr);
// A relay: its own hint, but the challenge comes from S. The agent must not sign S's challenge for it.
const R = await site((origin) => async (req, res) => {
  if (req.url === '/hint') { res.writeHead(200); res.end(JSON.stringify({ v: 'sigelo-pass/0', ctx: new URL(origin).host, challenge: '/c', accept: '/a', cookie: 'sigelo_pass' })); return; }
  if (req.url!.startsWith('/c')) { const c = await fetch(`${S}/sigelo-pass/challenge${req.url!.slice(2)}`); res.writeHead(c.status); res.end(await c.text()); return; }
  if (req.url === '/a') { accepts += 1000; res.writeHead(500); res.end(); return; }
  html(403, 'no', { 'sigelo-pass': '/hint' })(req, res);
});
n = accepts;
r = await cli('pass', `${R}/`);
ok("a site relaying another site's challenge → exit 1 pass_ctx, nothing signed or posted", r.status === 1 && r.stderr.includes('pass_ctx') && accepts === n, r.stderr);
const F = await site(() => html(403, 'no', { 'sigelo-pass': `${S}/.well-known/sigelo-pass` }));
r = await cli('pass', `${F}/`);
ok('a hint on another origin → exit 1 pass_off_site', r.status === 1 && r.stderr.includes('pass_off_site'), r.stderr);
const N = await site(() => html(403, '<h1>captcha</h1>'));
r = await cli('pass', `${N}/`);
ok('no hint and no /.well-known/sigelo-pass → exit 1 no_hint: never a captcha', r.status === 1 && r.stderr.includes('no_hint') && r.stderr.includes('never solves captchas'), r.stderr);

// ── the site refuses ─────────────────────────────────────────────────────────
const P = await doorSite({ onAccept: () => { throw new Error('closed today'); } });
r = await cli('pass', `${P}/members/`);
ok("the site's own policy → exit 1 with its reason", r.status === 1 && r.stderr.includes('pass_refused') && r.stderr.includes('closed today'), r.stderr);
const Q = await doorSite({ limits: { per_did: 1 } });
await cli('pass', `${Q}/members/`);
r = await cli('pass', `${Q}/members/`, '--fresh');
ok('over the per-DID limit → exit 1 rate_limited, with the wait', r.status === 1 && r.stderr.includes('rate_limited') && /retry after \d+ s/.test(r.stderr), r.stderr);

// ── an operator attestation and a rotated key ───────────────────────────────
const wDid = (await import('sigelo')).did(W.genesis);
const a = attest({ secret: W.secret, iss: wDid, sub: me.did, iat: now - 10, exp: now + 86400, ctx: 'sigelo-relay/operator', admission: 'invite', admission_by: wDid, claims: {} });
await cli('add-issuer', JSON.stringify(W.genesis));
await cli('add-attestation', JSON.stringify(a));
r = await cli('pass', `${O}/members/`, '--json');
ok('with an operator attestation the same door lets it through', r.status === 0, r.stderr);
const rot = JSON.parse((await cli('rotate')).stdout) as { did: string };
r = await cli('pass', `${S}/members/`, '--json');
j = JSON.parse(r.stdout);
ok('after a rotation: a new pass for the new DID (the kept one names the old DID)', r.status === 0 && !j.reused && j.did === rot.did && (await get(`${S}/members/`, j.header)).text === `hello ${rot.did}\n`, r.stderr);
writeFileSync(passesPath(ID), JSON.stringify({ v: 'sigelo-pass/0', passes: { [S]: { ...j.cookie, did: rot.did, exp: now - 1 } } }));
r = await cli('pass', `${S}/members/`, '--json');
ok('an expired kept cookie is not reused', r.status === 0 && !JSON.parse(r.stdout).reused);
ok('pass without a URL → usage, exit 2', (await cli('pass')).status === 2);

for (const s of servers) s.close();
done(import.meta.filename);
