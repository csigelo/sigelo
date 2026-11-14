// SPDX-License-Identifier: MIT
// accept/pass/test.mjs — sigelo-pass/0, the site side, on loopback only: the middleware in this
// process, verifier.mjs and the Express example as children. Agents are made with the ts library.
//   cd accept/pass && npm install && node test.mjs        → ALL PASS (n ok)
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { attest, did, keygen, sign } from 'sigelo';
import { sigeloPass } from './sigelo-pass.mjs';
import { addrKey, check, mint, OPERATOR_CTX } from './clearance.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), 'sigelo-pass-'));
const kids = [];
process.on('exit', () => { for (const k of kids) k.kill(); rmSync(tmp, { recursive: true, force: true }); });
let passed = 0, fails = 0;
const ok = (c, m, extra = '') => { console.log(`${c ? 'ok  ' : 'FAIL'} ${m}${c ? '' : ' ' + extra}`); if (c) passed++; else fails++; };
console.warn = () => {};   // keygen's recovery: null warning
const SECRET = 'x'.repeat(40), now = () => Math.floor(Date.now() / 1000);

// ---- agents (library) ----
const agent = () => { const k = keygen({ recovery: null }); return { k, did: did(k.genesis), attestations: [], issuers: [],
  bundle() { return { v: 'sigelo/0', typ: 'bundle', genesis: k.genesis, rotations: [], bindings: [], attestations: this.attestations, issuers: this.issuers }; } }; };
const A = agent(), B = agent(), W = agent();   // W: a world that attests
const from = (iss, sub, ctx, iat) => attest({ secret: iss.k.secret, iss: iss.did, sub: sub.did, iat, exp: now() + 86400, ctx, admission: 'open', claims: {} });

// ---- doors in this process: A at site a, B at site b (two origins, one pending map) ----
const freePort = () => new Promise((r) => { const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
async function site(opts = {}) {
  const port = await freePort(), origin = `http://127.0.0.1:${port}`;
  const door = sigeloPass({ origin, secret: SECRET, ...opts });
  const srv = createServer((req, res) => door.routes(req, res, () => (req.url.startsWith('/members')
    ? door.gate(req, res, () => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(`hello ${req.sigeloPass.did}\n`); })
    : (res.writeHead(200), res.end('open\n')))));
  await new Promise((r) => srv.listen(port, '127.0.0.1', r));
  return { origin, door, close: () => srv.close() };
}
const challengeOf = async (base, d, path = '/sigelo-pass/challenge') => { const r = await fetch(`${base}${path}?did=${encodeURIComponent(d)}`); return { status: r.status, headers: r.headers, json: await r.json() }; };
const post = async (base, body, path = '/sigelo-pass/accept') => { const r = await fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  return { status: r.status, cookie: r.headers.get('set-cookie'), json: await r.json().catch(() => null) }; };
const answer = (who, c, extra = {}) => ({ challenge: c, did: who.did, sig: sign(who.k.secret, c), bundle: who.bundle(), ...extra });
const page = async (base, cookie, path = '/members/') => { const r = await fetch(base + path, { headers: cookie ? { cookie } : {} }); return { status: r.status, headers: r.headers, text: await r.text() }; };
const flip = (s, i) => s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
const pass = async (base, who) => { const c = (await challengeOf(base, who.did)).json; return post(base, answer(who, c)); };

const S = await site(), T = await site();
let r = await page(S.origin);
ok(r.status === 403 && r.headers.get('sigelo-pass') === `${S.origin}/.well-known/sigelo-pass`, 'no cookie → 403 with the Sigelo-Pass header');
ok(r.headers.get('link') === `<${S.origin}/.well-known/sigelo-pass>; rel="sigelo-pass"` && r.text.includes(`<link rel="sigelo-pass" href="${S.origin}/.well-known/sigelo-pass">`), 'the 403 carries the hint as Link and as <link rel="sigelo-pass">');
ok((await page(S.origin, undefined, '/open')).status === 200, 'routes outside the gate pass through');
const hint = await (await fetch(`${S.origin}/.well-known/sigelo-pass`)).json();
ok(hint.v === 'sigelo-pass/0' && hint.ctx === new URL(S.origin).host && hint.challenge === '/sigelo-pass/challenge' && hint.accept === '/sigelo-pass/accept' && hint.cookie === 'sigelo_pass' && hint.ttl === 3600
  && hint.wants.operator === false && hint.wants.min_age === 0 && hint.limits.per_did === 20, 'hint file: v, ctx = the host, challenge, accept, cookie, ttl, wants, limits');
let c = (await challengeOf(S.origin, A.did)).json;
ok(c.v === 'sigelo/0' && c.typ === 'challenge' && c.did === A.did && c.ctx === hint.ctx && Object.keys(c).length === 5, 'challenge: the §5.2 five fields, ctx = the site');
const body = answer(A, c);
r = await post(S.origin, body);
ok(r.status === 200 && r.json.did === A.did && r.json.v === 'sigelo-pass/0' && r.json.cookie.name === 'sigelo_pass' && r.json.cookie.exp > now() && r.json.cookie.exp <= now() + 3600, 'accept → 200 { v, did, cookie: { name, value, exp, path } }', JSON.stringify(r.json));
ok(/^sigelo_pass=sp0\.did:sigelo:z\w+\.\d+\.[\w-]{43}; Path=\/; Max-Age=3600; HttpOnly; SameSite=Lax$/.test(r.cookie ?? ''), 'Set-Cookie: HttpOnly, SameSite=Lax, Max-Age = ttl (no Secure on http)', r.cookie);
const cookie = `sigelo_pass=${r.json.cookie.value}`;
r = await page(S.origin, `theme=dark; ${cookie}`);
ok(r.status === 200 && r.text === `hello ${A.did}\n`, 'the cookie opens the gate; req.sigeloPass.did is the DID');
ok((await post(S.origin, body)).status === 401, 'the same answer replayed → 401');
c = (await challengeOf(S.origin, A.did)).json;
r = await post(S.origin, { ...answer(A, c), sig: flip(sign(A.k.secret, c), 10) });
ok(r.status === 401 && r.json.check === 'refused', 'a bad signature → 401 refused', JSON.stringify(r.json));
c = (await challengeOf(S.origin, A.did)).json;
r = await post(S.origin, answer(A, c, { bundle: B.bundle() }));
ok(r.status === 401, "A's answer with B's bundle → 401");
c = (await challengeOf(T.origin, A.did)).json;
r = await post(S.origin, answer(A, c));
ok(r.status === 401 && r.json.check === 'ctx', "a challenge site T issued, posted to site S (same process) → 401 ctx", JSON.stringify(r.json));
ok((await post(T.origin, answer(A, c))).status === 200, '… and it was not spent: T still takes it');
c = (await challengeOf(S.origin, A.did)).json;
r = await post(S.origin, answer(A, { ...c, ctx: 'evil.example' }));
ok(r.status === 401 && r.json.check === 'ctx', 'a challenge with its ctx changed → 401 ctx');
r = await post(S.origin, answer(B, { ...c, did: B.did }));
ok(r.status === 401, "B answering a challenge issued to A → 401");
ok((await post(S.origin, '{"challenge":{},"challenge":{}}')).status === 400, 'duplicate keys in the body → 400');
ok((await challengeOf(S.origin, 'did:sigelo:short')).status === 400, 'a malformed DID → 400');

// ---- the cookie ----
const ctx = new URL(S.origin).host, tamper = (v) => page(S.origin, `sigelo_pass=${v}`);
const good = mint(SECRET, ctx, A.did, now() + 600);
ok((await tamper(good)).status === 200, 'a cookie minted with the site secret opens the gate');
ok((await tamper(mint(SECRET, ctx, A.did, now() - 1))).status === 403, 'an expired cookie → 403');
ok((await tamper(mint(SECRET, ctx, A.did, now() + 7200))).status === 403, 'a cookie past now + ttl → 403');
ok((await tamper(good.replace(A.did, B.did))).status === 403, 'another DID in the cookie → 403');
ok((await tamper(good.replace(/\.(\d+)\./, (_, e) => `.${Number(e) + 1}.`))).status === 403, 'a changed expiry → 403');
ok((await tamper(flip(good, good.length - 5))).status === 403, 'a changed MAC → 403');
ok((await tamper(mint('y'.repeat(40), ctx, A.did, now() + 600))).status === 403, "another site's secret → 403");
ok((await tamper(mint(SECRET, 'other.example', A.did, now() + 600))).status === 403, 'minted for another ctx → 403');
ok(check(SECRET, ctx, good)?.did === A.did && check(SECRET, ctx, 'sp0.x.1.y') === null, 'clearance.check: { did, exp } or null');

// ---- what the site wants ----
const O = await site({ wants: { operator: true } });
r = await pass(O.origin, A);
ok(r.status === 403 && r.json.check === 'wants_operator', 'wants.operator: no operator attestation → 403 wants_operator', JSON.stringify(r.json));
const Aop = agent(); Aop.attestations.push(from(W, Aop, OPERATOR_CTX, now() - 10)); Aop.issuers.push(W.k.genesis);
ok((await pass(O.origin, Aop)).status === 200, 'wants.operator: an unexpired sigelo-relay/operator attestation → 200');
const G = await site({ wants: { min_age: 86400, age_by: [W.did] } });
const young = agent(); young.attestations.push(from(W, young, 'w.example', now() - 60)); young.issuers.push(W.k.genesis);
const old = agent(); old.attestations.push(from(W, old, 'w.example', now() - 2 * 86400)); old.issuers.push(W.k.genesis);
const self = agent(); self.attestations.push(from(self, self, 'self', now() - 9 * 86400)); self.issuers.push(self.k.genesis);
ok((await pass(G.origin, young)).json?.check === 'wants_age', 'wants.min_age: dated a minute ago by an age_by issuer → 403 wants_age');
ok((await pass(G.origin, old)).status === 200, 'wants.min_age: dated two days ago by an age_by issuer → 200');
ok((await pass(G.origin, self)).json?.check === 'wants_age', 'wants.min_age: a backdated attestation by an issuer not in age_by counts for nothing');
let threw = false; try { sigeloPass({ origin: 'https://x.example', secret: SECRET, wants: { min_age: 1 } }); } catch { threw = true; }
ok(threw, 'min_age without age_by is refused at setup');
threw = false; try { sigeloPass({ origin: 'https://x.example', secret: 'short' }); } catch { threw = true; }
ok(threw, 'a secret under 32 bytes is refused at setup');
const P = await site({ onAccept: (res) => { if (res.did === B.did) throw new Error('not B'); } });
ok((await pass(P.origin, B)).json?.check === 'policy' && (await pass(P.origin, A)).status === 200, 'onAccept(result): the site\'s own policy refuses with 403 policy');

// ---- rate limits ----
const L = await site({ limits: { per_did: 2, per_addr: 3 } });
const codes = [];
for (let i = 0; i < 3; i++) codes.push((await challengeOf(L.origin, A.did)).status);
const last = await challengeOf(L.origin, B.did);
ok(codes.join() === '200,200,429' && last.status === 429 && Number(last.headers.get('retry-after')) > 0, `per DID 2, per address 3: A A A(429) B(429, address) with Retry-After (${codes.join()},${last.status})`);
ok(addrKey('2001:db8:1:2:3:4:5:6') === addrKey('2001:db8:1:2::9') && addrKey('::ffff:10.0.0.1') === '10.0.0.1', 'addresses: IPv6 counted per /64, IPv4-mapped as IPv4');
for (const s of [S, T, O, G, P, L]) s.close();

// ---- verifier.mjs (nginx auth_request, Caddy forward_auth) ----
const start = (file, env) => new Promise((resolve, reject) => {
  const k = spawn(process.execPath, [join(HERE, file)], { cwd: HERE, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] }); kids.push(k);
  let err = ''; k.stderr.on('data', (d) => { err += d; });
  k.stdout.on('data', (d) => { const m = String(d).match(/127\.0\.0\.1:(\d+)/); if (m) resolve(`http://127.0.0.1:${m[1]}`); });
  k.on('exit', (code) => reject(new Error(`${file} exited ${code}: ${err}`)));
});
writeFileSync(join(tmp, 'secret'), SECRET + '\n', { mode: 0o600 });
const vport = await freePort(), V0 = `http://127.0.0.1:${vport}`;
const vbase = await start('verifier.mjs', { SIGELO_PASS_ORIGIN: V0, SIGELO_PASS_SECRET_FILE: join(tmp, 'secret'), SIGELO_PASS_PORT: String(vport), SIGELO_PASS_ADDR_HEADER: 'x-real-ip' });
r = await page(vbase, undefined, '/sigelo-pass/check');
ok(r.status === 403 && r.headers.get('sigelo-pass') === `${V0}/.well-known/sigelo-pass` && r.text.includes('rel="sigelo-pass"'), 'verifier: /sigelo-pass/check without a cookie → 403 with the wall');
r = await pass(vbase, A);
ok(r.status === 200, 'verifier: hint → challenge → accept');
r = await page(vbase, `sigelo_pass=${r.json.cookie.value}`, '/sigelo-pass/check');
ok(r.status === 204 && r.headers.get('sigelo-pass-did') === A.did, 'verifier: /sigelo-pass/check with the cookie → 204, Sigelo-Pass-DID');
r = await page(vbase, `sigelo_pass=${good}`, '/sigelo-pass/wall');
ok(r.status === 403 && r.headers.get('link')?.includes('rel="sigelo-pass"'), 'verifier: /sigelo-pass/wall is always the 403 (nginx error_page)');
const byAddr = async (ip) => (await fetch(`${vbase}/sigelo-pass/challenge?did=${encodeURIComponent(agent().did)}`, { headers: { 'x-real-ip': ip } })).status;
const statuses = []; for (let i = 0; i < 61; i++) statuses.push(await byAddr('192.0.2.7'));
ok(statuses.slice(0, 60).every((s) => s === 200) && statuses[60] === 429 && (await byAddr('192.0.2.8')) === 200, 'verifier: 60 challenges an hour per address, read from SIGELO_PASS_ADDR_HEADER');

// ---- the Express example, verbatim in README.md (express is a devDependency: CI installs without it) ----
if (!existsSync(join(HERE, 'node_modules', 'express'))) console.log('SKIP the Express example: no express (npm install here, with dev dependencies)');
else {
const eport = await freePort(), E0 = `http://127.0.0.1:${eport}`;
const ex = start('example.mjs', { PORT: String(eport), ORIGIN: E0, SIGELO_PASS_SECRET: SECRET });
await Promise.race([ex.catch(() => {}), new Promise((res) => setTimeout(res, 300))]);
for (let t = 0; t < 100 && !(await fetch(E0 + '/.well-known/sigelo-pass').then(() => true, () => false)); t++) await new Promise((res) => setTimeout(res, 100));
ok((await page(E0)).status === 403, 'Express example: /members/ → 403 with the hint');
r = await pass(E0, A);
ok(r.status === 200 && (await page(E0, `sigelo_pass=${r.json.cookie.value}`)).text === `hello ${A.did}\n`, 'Express example: pass → the cookie opens /members/');
}
ok(readFileSync(join(HERE, 'README.md'), 'utf8').includes(readFileSync(join(HERE, 'example.mjs'), 'utf8').trim()), 'README.md shows example.mjs verbatim');

console.log(fails ? `\nFAIL accept/pass (${fails} of ${passed + fails} failed)` : `\nALL PASS accept/pass (${passed} ok)`);
process.exit(fails ? 1 : 0);
