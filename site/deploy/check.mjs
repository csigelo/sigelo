#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// site/deploy/check.mjs — verifies a deployed sigelo.io from the outside, the way an agent meets it.
//
//   node site/deploy/check.mjs                                   https://sigelo.io, every check
//   node site/deploy/check.mjs --origin https://staging.example --no-www
//   node site/deploy/check.mjs --origin http://127.0.0.1:8080 --no-tls --node-server
//   node site/deploy/check.mjs --preflight                       the local build's off-origin targets only
//
// Checks: status 200 and the exact content type site/test/run.mjs serves for /, /llms.txt,
// /adopt.md, /index.json, /.well-known/security.txt, /sitemap.xml, /robots.txt, /spec.md,
// /examples/world.mjs, /icon-512.png and a /sha256/<hex>/ file (whose hash is recomputed); Accept:
// text/markdown on /, /spec.html and /spec serves the Markdown twin; index.json's sha256s match the
// files served; its built_from.commit is the local HEAD and not dirty; security.txt has not expired;
// the security, cache and Link headers of site/deploy/nginx.conf; an unknown path is a 404 cached a
// minute that still names /llms.txt (Link rel=describedby); /_stats/ answers 401 (basic auth,
// noindex, no-store; also as /%5Fstats/ and //_stats/) and is not in the sitemap; the not-found
// page is noindex (also as /%34%30%34.md); HSTS of a year; http:// → https:// and www → apex
// 301s; the held domains' 301s (below); every place index.json sends people or agents off this
// origin answers 200 itself (no redirect) with the content type of what it is: each redirect
// target's /robots.txt (an unreachable robots.txt reads as "disallow all"), its relay URLs (the
// relay's index.json naming the relay), the official repositories and payment places; when index.json
// has a `world` block, the world (world/README.md): a §5.2 challenge, the whole attest flow with a
// fixed-seed check agent (the ts library from ts/dist; one subject, idempotent for 24 h),
// /world/stats with counts only, /world/conformance refusing an empty body and /mcp answering
// initialize; the release mirror /releases/<tag>/ (SHA256SUMS, one binary
// downloaded and hashed, every file's content type, /releases/index.json, latest); /security.md's
// "Official channels" and index.json official.issuer_did. Prints ok/FAIL/skip/note lines, then ALL PASS and exit 0, or exit 1.
//
// Flags:
//   --origin URL       what to check (default https://sigelo.io); index.json's URLs are mapped onto it
//   --no-tls           plain-HTTP origin: skip HSTS and the redirect checks
//   --no-www           skip www.<host> (a staging origin has none), and the held domains
//   --no-alt           skip the held domains. Their table is the deployed index.json's `official`,
//                      which must equal site/src/official.mjs OFFICIAL when the deployed build is the
//                      local HEAD: each of `redirects` (apex and www) must 301 to its target with the
//                      path kept, or the check FAILs, because SECURITY.md and /contact say it
//                      redirects. Each of `redirects_pending_dns` is checked the same way once its A
//                      records point where the origin's do (then: mark it live in official.mjs), and
//                      is a `skip` until then.
//   --node-server      the origin is `node site/test/run.mjs --serve`, which implements the content
//                      types and negotiation but sends no security or cache headers and does not map
//                      /spec to /spec.html: skip those checks (they are nginx's job)
//   --commit SHA       expected build commit (default: git rev-parse HEAD of this repository)
//   --any-commit       do not compare the build commit (after a rollback)
//   --quiet            print only the FAIL lines and the summary
//   --preflight        before an upload: read the local site/dist/index.json (node site/build.mjs first)
//                      and check only its off-origin targets, so a build that redirects or links to a
//                      sigelo.ai that does not answer yet is refused before it is served. deploy.sh
//                      does not run it yet (it runs the full check after the upload): run it by hand
//                      before a deploy that changes where sigelo.io sends people (RELAY_LIVE is true
//                      since the launch commit: sigelo.net and sigelo.online to sigelo.ai)
//   --index FILE       with --preflight: read FILE instead (site/test/run.mjs points it at its own server)
// Every request sends User-Agent UA (below): nginx.conf logs it to access-self.log, not access.log,
// so the project's own checks stay out of the visit statistics.
// Uses node's fetch, no dependencies, node >= 22.
import { createHash } from 'node:crypto';
import { promises as dns } from 'node:dns';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { OFFICIAL } from '../src/official.mjs';

const CANON = 'https://sigelo.io';
const UA = 'sigelo-selfcheck/1 (+https://sigelo.io/privacy)';
const argv = process.argv.slice(2);
const flag = (f) => argv.includes(f);
const opt = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const known = new Set(['--origin', '--no-tls', '--no-www', '--node-server', '--commit', '--any-commit', '--no-alt', '--quiet', '--preflight', '--index']);
const NO_ALT = flag('--no-alt'), PREFLIGHT = flag('--preflight');
for (let i = 0; i < argv.length; i++) {
  if (!known.has(argv[i])) { console.error(`check.mjs: unknown argument ${argv[i]}`); process.exit(2); }
  if (argv[i] === '--origin' || argv[i] === '--commit' || argv[i] === '--index') i++;
}
const ORIGIN = (opt('--origin', CANON) ?? '').replace(/\/+$/, '');
const NO_TLS = flag('--no-tls'), NO_WWW = flag('--no-www') || NO_TLS, NODE = flag('--node-server');
let o; try { o = new URL(ORIGIN); } catch { console.error(`check.mjs: --origin is not a URL: ${ORIGIN}`); process.exit(2); }
if (!NO_TLS && o.protocol !== 'https:') { console.error('check.mjs: an http:// origin needs --no-tls'); process.exit(2); }

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
let head = null;
try { head = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* below */ }
let want = opt('--commit');
if (!want && !flag('--any-commit') && !PREFLIGHT) {
  if (!head) { console.error('check.mjs: cannot read the local HEAD (git); pass --commit SHA or --any-commit'); process.exit(2); }
  want = head;
}

// The test server's types (site/test/run.mjs TYPES), byte for byte.
const T = { html: 'text/html; charset=utf-8', md: 'text/markdown; charset=utf-8', txt: 'text/plain; charset=utf-8',
  json: 'application/json', xml: 'application/xml', mjs: 'text/javascript; charset=utf-8', yaml: 'application/yaml', css: 'text/css; charset=utf-8', png: 'image/png' };
const typeOf = (path) => T[(path.match(/\.([a-z]+)$/) ?? [])[1]] ?? (path.endsWith('/') ? T.html : null);
// site/deploy/nginx.conf's headers, verbatim.
const H = {
  'content-security-policy': "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'permissions-policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=(), browsing-topics=()',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
};
const HOUR = 'public, max-age=3600', YEAR = 'public, max-age=31536000, immutable', MISS = 'public, max-age=60';
const HSTS_AGE = 31536000;

const QUIET = flag('--quiet'), say = QUIET ? () => {} : console.log;
let n = 0, skipped = 0; const fails = [];
const ok = (cond, what) => { n++; if (cond) say(`ok ${what}`); else { fails.push(what); console.log(`FAIL ${what}`); } return cond; };
const skip = (what, why) => { skipped++; say(`skip ${what} (${why})`); };
const note = (what) => say(`note ${what}`);
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const get = async (url, headers = {}, redirect = 'follow') => {
  try {
    const r = await fetch(url, { headers: { 'user-agent': UA, ...headers }, redirect, signal: AbortSignal.timeout(20000) });
    return { status: r.status, h: r.headers, type: r.headers.get('content-type') ?? '', body: Buffer.from(await r.arrayBuffer()), url: r.url };
  } catch (e) { return { status: 0, h: new Headers(), type: '', body: Buffer.alloc(0), error: e.cause?.code ?? e.message }; }
};
const at = (path) => ORIGIN + path;
const local = (u) => (u.startsWith(CANON) ? u.slice(CANON.length) || '/' : u);
const show = (r) => (r.status ? `${r.status}, ${r.type || 'no content-type'}` : `no response: ${r.error}`);
const summary = () => {
  if (fails.length) { console.log(`FAILURES (${fails.length} of ${n} checks${skipped ? `, ${skipped} skipped` : ''})`); process.exit(1); }
  console.log(`ALL PASS (${n} checks${skipped ? `, ${skipped} skipped` : ''})`);
  process.exit(0);
};

// Every place a build sends people or agents off this origin must answer 200 itself, with the
// content type of what it is: each redirect's target, live or pending (its /robots.txt, text/plain:
// an unreachable robots.txt reads as "disallow all"; sigelo.io's own is checked as the origin's),
// the relay's home page (text/html), llms.txt (text/plain) and index.json (application/json, naming
// the relay as sigelo.io's index.json does), the official repositories and the payment places
// (text/html). Not followed: a redirect is a FAIL, because a parked or expired domain answers 200
// for every path after one, and then a payment place would be someone else's page. Since the
// relay launch (RELAY_LIVE) that includes sigelo.ai: a sigelo.io that redirects or links to a
// sigelo.ai (or names a relay repository or pay page) that does not answer as ours FAILs.
const mediaType = (r) => r.type.split(';')[0].trim().toLowerCase();
async function offOrigin(ix) {
  const of = ix?.official ?? {};
  const targets = [...new Set([...Object.values(of.redirects ?? {}), ...Object.values(of.redirects_pending_dns ?? {})])]
    .filter((t) => t.replace(/\/$/, '') !== CANON).map((t) => [`${t.replace(/\/$/, '')}/robots.txt`, 'text/plain']);
  const relayKeys = ['homepage', 'llms_txt', 'index'];
  const relayType = { homepage: 'text/html', llms_txt: 'text/plain', index: 'application/json' };
  if (ix?.relay) ok(typeof ix.relay.name === 'string' && relayKeys.every((k) => typeof ix.relay[k] === 'string'), `index.json relay: name, ${relayKeys.join(', ')}`);
  const urls = [...targets, ...(ix?.relay ? relayKeys.filter((k) => typeof ix.relay[k] === 'string').map((k) => [ix.relay[k], relayType[k]]) : []),
    ...(of.repositories ?? []).map((u) => [u, 'text/html']), ...(of.payment_details_only_on ?? []).map((u) => [u, 'text/html'])];
  ok(urls.length > 0 && Array.isArray(of.repositories) && of.repositories.length > 0, `index.json official names its repositories (${urls.length} off-origin URLs to check)`);
  for (const [u, type] of urls) {
    const r = await get(u, {}, 'manual');
    const moved = r.status >= 300 && r.status < 400 ? ` to ${r.h.get('location') ?? 'nowhere'}` : '';
    ok(r.status === 200 && mediaType(r) === type, `off-origin target serves: ${u} answers 200 ${type} itself, no redirect (got ${show(r)}${moved})`);
    if (ix?.relay && u === ix.relay.index && r.status === 200) {
      let rj = null; try { rj = JSON.parse(r.body); } catch { /* reported below */ }
      ok(rj?.name === ix.relay.name && rj?.homepage === ix.relay.homepage,
        `off-origin target serves: ${u} names the relay (name ${JSON.stringify(ix.relay.name)}, homepage ${ix.relay.homepage}; got ${rj ? `${JSON.stringify(rj.name)}, ${rj.homepage}` : 'no JSON'})`);
    }
  }
}

if (opt('--index') && !PREFLIGHT) { console.error('check.mjs: --index goes with --preflight'); process.exit(2); }
if (PREFLIGHT) {
  const file = opt('--index') ?? join(ROOT, 'site', 'dist', 'index.json');
  let ix = null;
  try { ix = JSON.parse(readFileSync(file, 'utf8')); }
  catch (e) { console.error(`check.mjs --preflight: cannot read ${file} (node site/build.mjs first): ${e.message}`); process.exit(2); }
  say(`preflight: the off-origin targets of ${file} (built from ${String(ix?.built_from?.commit).slice(0, 12)})`);
  await offOrigin(ix);
  summary();
}

say(`checking ${ORIGIN}${NO_TLS ? ' (--no-tls)' : ''}${NODE ? ' (--node-server)' : ''}`);

// ---- the files: 200 and the exact content type ------------------------------------------------
const got = {};
for (const p of ['/', '/llms.txt', '/adopt.md', '/index.json', '/.well-known/security.txt', '/sitemap.xml', '/robots.txt', '/spec.md', '/examples/world.mjs', '/style.css', '/icon-512.png']) {
  const r = got[p] = await get(at(p));
  ok(r.status === 200 && r.type === typeOf(p), `${p}: 200, ${typeOf(p)} (got ${show(r)})`);
}
ok(got['/'].body.toString().includes('<h1') && got['/'].body.toString().includes('rel="alternate" type="text/markdown"'), '/: the HTML index with its Markdown alternate');
ok(/^# \S/.test(got['/llms.txt'].body.toString()), '/llms.txt: starts with an H1');
ok(got['/examples/world.mjs'].body.toString().includes("from 'sigelo'"), "/examples/world.mjs: imports the npm package 'sigelo'");
ok(got['/robots.txt'].body.toString().includes(`Sitemap: ${CANON}/sitemap.xml`), '/robots.txt: names the sitemap');
ok(got['/sitemap.xml'].body.toString().startsWith('<?xml') && got['/sitemap.xml'].body.toString().includes(`<loc>${CANON}/</loc>`), '/sitemap.xml: XML with the site\'s URLs');

// ---- Markdown negotiation ---------------------------------------------------------------------
{
  const md = { accept: 'text/markdown' };
  const spec = got['/spec.md'].body;
  const a = await get(at('/spec.html'), md);
  ok(a.status === 200 && a.type === T.md && a.body.equals(spec), `Accept: text/markdown on /spec.html serves /spec.md (got ${show(a)})`);
  const i = await get(at('/'), md); const im = await get(at('/index.md'));
  ok(i.status === 200 && i.type === T.md && im.status === 200 && i.body.equals(im.body), `Accept: text/markdown on / serves /index.md (got ${show(i)})`);
  if (NODE) skip('Accept: text/markdown on /spec serves /spec.md; /spec serves /spec.html', 'the node test server does not map extensionless paths');
  else {
    const e = await get(at('/spec'), md);
    ok(e.status === 200 && e.type === T.md && e.body.equals(spec), `Accept: text/markdown on /spec serves /spec.md (got ${show(e)})`);
    const h = await get(at('/spec'));
    ok(h.status === 200 && h.type === T.html && h.body.toString().includes('<h1'), `/spec without Accept serves the HTML page (got ${show(h)})`);
  }
  const plain = await get(at('/spec.html'));
  ok(plain.status === 200 && plain.type === T.html, `/spec.html without Accept is HTML (got ${show(plain)})`);
}

// ---- index.json: commit, sha256s, the immutable copies ----------------------------------------
let ix = null;
try { ix = JSON.parse(got['/index.json'].body); } catch { /* reported */ }
if (ok(ix && ix.name === 'sigelo' && ix.built_from?.commit, 'index.json parses and names its build commit')) {
  if (want) ok(ix.built_from.commit === want, `index.json built_from.commit = local HEAD ${want.slice(0, 12)} (deployed: ${String(ix.built_from.commit).slice(0, 12)})`);
  else skip('index.json built_from.commit = local HEAD', '--any-commit');
  ok(ix.built_from.dirty === false, `index.json: built from a clean tree (dirty: ${ix.built_from.dirty})`);
  const entries = [['spec', ix.spec], ['vectors', ix.vectors], ['openapi', ix.openapi], ...(ix.schemas ?? []).map((s) => [local(s.url), s])];
  const bad = [];
  for (const [name, e] of entries) {
    const r = await get(at(local(e.url)));
    if (r.status !== 200 || sha256(r.body) !== e.sha256 || r.body.length !== e.bytes) bad.push(`${name} (${show(r)})`);
    else if (r.type !== typeOf(local(e.url))) bad.push(`${name} content type ${r.type}`);
  }
  ok(bad.length === 0, `index.json: ${entries.length} files served with the listed sha256 and size${bad.length ? ` (bad: ${bad.join(', ')})` : ''}`);
  const imm = [ix.spec.immutable, ix.vectors.immutable].filter(Boolean);
  for (const u of imm) {
    const p = local(u); const hex = p.match(/^\/sha256\/([0-9a-f]{64})\//)?.[1];
    const r = await get(at(p));
    ok(hex && r.status === 200 && sha256(r.body) === hex && r.type === typeOf(p), `${p.slice(0, 22)}…${p.slice(-20)}: sha256 of the body = the hex in its path, ${typeOf(p)} (got ${show(r)})`);
    if (NODE) skip(`${p.slice(0, 22)}…: Cache-Control immutable`, 'node test server sends no cache headers');
    else ok(r.h.get('cache-control') === YEAR, `${p.slice(0, 22)}…: Cache-Control "${YEAR}" (got "${r.h.get('cache-control')}")`);
  }
  ok(imm.length === 2, 'index.json lists the two immutable copies (SPEC.md, test-vectors.json)');
}

// ---- the release mirror (site/deploy/mirror-release.sh) and the official names ----------------
if (ix?.release?.tag && NODE) skip('/releases/: the mirror', 'it lives on the server, outside dist/; the node test server does not have it');
else if (ix?.release?.tag) {
  const rel = ix.release, base = `/releases/${rel.tag}/`;
  const sr = await get(at(`${base}SHA256SUMS`));
  const sums = new Map(sr.body.toString().trim().split('\n').map((l) => l.match(/^([0-9a-f]{64}) [ *](.+)$/)?.slice(1).reverse() ?? ['?', '?']));
  ok(sr.status === 200 && sr.type === T.txt && sums.size === rel.files.length && rel.files.every((f) => sums.get(f.name) === f.sha256),
    `${base}SHA256SUMS: 200, ${T.txt}, the ${rel.files.length} sha256s index.json lists (got ${show(sr)}, ${sums.size} lines)`);
  ok(sr.h.get('cache-control') === YEAR, `${base}SHA256SUMS: Cache-Control "${YEAR}" (got "${sr.h.get('cache-control')}")`);
  const bin = rel.files.find((f) => f.name === 'sigelo-verify-linux-arm64') ?? rel.files.find((f) => f.name.startsWith('sigelo-verify-'));
  if (bin) {
    const br = await get(at(base + bin.name));
    ok(br.status === 200 && sha256(br.body) === sums.get(bin.name) && br.type === 'application/octet-stream',
      `${base}${bin.name}: 200, application/octet-stream, sha256 = SHA256SUMS (got ${show(br)}, ${br.body.length} bytes)`);
  }
  // every file: present with the right type (HEAD only; mirror-release.sh downloads them all)
  const TYPE = (n) => (/\.(tgz|tar\.gz)$/.test(n) ? 'application/gzip' : n.endsWith('.json') ? 'application/json' : 'application/octet-stream');
  const wrong = [];
  for (const f of rel.files) {
    let r; try { r = await fetch(at(base + f.name), { method: 'HEAD', headers: { 'user-agent': UA }, signal: AbortSignal.timeout(20000) }); } catch (e) { wrong.push(`${f.name} (${e.message})`); continue; }
    if (r.status !== 200 || r.headers.get('content-type') !== TYPE(f.name)) wrong.push(`${f.name} (${r.status}, ${r.headers.get('content-type')})`);
  }
  ok(wrong.length === 0, `${base}: all ${rel.files.length} files 200 with their content type (tgz/tar.gz application/gzip, binaries and .exe octet-stream)${wrong.length ? ` (wrong: ${wrong.join(', ')})` : ''}`);
  const mi = await get(at('/releases/index.json'));
  let mj = null; try { mj = JSON.parse(mi.body); } catch { /* reported */ }
  const mrel = mj?.releases?.find((r) => r.tag === rel.tag);
  ok(mi.status === 200 && mi.type === T.json && mrel && mrel.files.every((f) => sums.get(f.name) === f.sha256 && Number.isInteger(f.bytes)) && mi.h.get('cache-control') === 'public, max-age=300',
    `/releases/index.json: 200, lists ${rel.tag} with sizes and the same sha256s, Cache-Control 5 min (got ${show(mi)}, "${mi.h.get('cache-control')}")`);
  const lt = await get(at(`/releases/${mj?.latest ?? 'latest'}/SHA256SUMS`)); const ll = await get(at('/releases/latest/SHA256SUMS'));
  ok(ll.status === 200 && ll.body.equals(lt.body) && ll.h.get('cache-control') === 'public, max-age=300', `/releases/latest/ = ${mj?.latest} (short cache; got ${show(ll)}, "${ll.h.get('cache-control')}")`);
  const ls = await get(at('/releases/'));
  ok(ls.status === 200 && ls.type === T.md && ls.body.toString().includes(rel.tag), `/releases/: the Markdown listing names ${rel.tag} (got ${show(ls)})`);
}
{
  const sm = await get(at('/security.md'));
  ok(sm.status === 200 && sm.body.toString().includes('## Official channels'), `/security.md: has "Official channels" (got ${show(sm)})`);
  ok(ix?.official?.issuer_did && (!ix.world || ix.official.issuer_did === ix.world.issuer) && sm.body.toString().includes(ix.official.issuer_did),
    `index.json official.issuer_did = world.issuer = the DID /security.md names (${ix?.official?.issuer_did})`);
}

// ---- off this origin: redirect targets, the relay, repositories, payment places ---------------
await offOrigin(ix);

// ---- the world: challenge, attest, stats ------------------------------------------------------
if (!ix?.world) note('index.json has no world block: the world checks are skipped');
else {
  const w = ix.world, wurl = (u) => at(local(u));
  let lib = null;
  try { lib = await import(new URL('../../ts/dist/sigelo.js', import.meta.url)); } catch (e) { note(`no ts/dist (cd ts && npx tsc): ${e.message}`); }
  const g = await get(wurl(w.genesis));
  let genesis = null; try { genesis = JSON.parse(g.body); } catch { /* reported */ }
  ok(g.status === 200 && genesis && lib && lib.did(genesis) === w.issuer, `/world/genesis.json: 200, hashes to index.json's world.issuer ${w.issuer}`);
  // A fixed seed: the same check agent every run, so the world counts one subject, not one per deploy.
  const agent = lib && lib.keygen({ seed: createHash('sha256').update('sigelo.io check.mjs agent').digest(), recovery: 'sha256:' + '0'.repeat(64), created: '2026-10-02T00:00:00Z', nonce: new Uint8Array(16) });
  const cr = agent ? await get(wurl(w.challenge.replace('{did}', encodeURIComponent(agent.did)))) : { status: 0 };
  let ch = null; try { ch = JSON.parse(cr.body); } catch { /* reported */ }
  ok(cr.status === 200 && ch && Object.keys(ch).join() === 'v,typ,did,ctx,nonce' && ch.ctx === w.ctx && ch.did === agent.did, `/world/challenge: 200, the five §5.2 fields, ctx ${w.ctx} (got ${show(cr)})`);
  let issued = null;
  if (ch?.nonce) {
    const signed = lib.challenge({ secret: agent.secret, genesis: agent.genesis, ctx: ch.ctx, nonce: ch.nonce });
    const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: agent.genesis, rotations: [], bindings: [], attestations: [], issuers: [] };
    try {
      const r = await fetch(wurl(w.attest), { method: 'POST', headers: { 'user-agent': UA }, body: JSON.stringify({ challenge: ch, did: agent.did, sig: signed.sig, bundle }), signal: AbortSignal.timeout(20000) });
      issued = r.status === 200 ? await r.json() : { status: r.status, error: (await r.json().catch(() => ({}))).error };
    } catch (e) { issued = { error: e.message }; }
  }
  const res = issued?.attestation && lib.verify({ v: 'sigelo/0', typ: 'bundle', genesis: agent.genesis, rotations: [], bindings: [], attestations: [issued.attestation], issuers: [issued.issuer] }, Math.floor(Date.now() / 1000));
  ok(res && res.attestations[w.issuer]?.length === 1 && Object.keys(issued.attestation).join() === 'body,sig' && issued.attestation.body.admission === 'open',
    `/world/attest: an attestation from ${w.issuer.slice(0, 24)}… that verifies offline in a bundle (got ${issued?.attestation ? JSON.stringify(issued.attestation.body.claims) : JSON.stringify(issued)})`);
  const st = await get(wurl(w.stats));
  let sj = null; try { sj = JSON.parse(st.body); } catch { /* reported */ }
  ok(st.status === 200 && sj && Number.isInteger(sj.attestations) && Object.keys(sj).join() === 'issuer,ctx,attestations,subjects' && (NODE || st.h.get('cache-control') === 'no-store'),
    `/world/stats: 200, counts only, not cached (got ${show(st)} ${st.body.toString().trim().slice(0, 160)})`);
  // POST /world/conformance and the remote MCP endpoint (world/mcp.mjs): reachable, refusing and answering as built
  const postTo = async (url, body, headers = {}) => {
    try { const r = await fetch(url, { method: 'POST', headers: { 'user-agent': UA, ...headers }, body, signal: AbortSignal.timeout(20000) }); return { status: r.status, h: r.headers, text: await r.text() }; }
    catch (e) { return { status: 0, h: new Headers(), text: '', error: e.cause?.code ?? e.message }; }
  };
  const cf = await postTo(wurl(w.conformance ?? `${CANON}/world/conformance`), '');
  ok(cf.status === 400 && /JSON/.test(cf.text), `/world/conformance: an empty body is 400 (got ${cf.status || cf.error} ${cf.text.trim().slice(0, 100)})`);
  const mi = await postTo(wurl(w.mcp ?? `${CANON}/mcp`), JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'check.mjs', version: '0' } } }),
    { accept: 'application/json, text/event-stream', 'content-type': 'application/json' });
  let mj = null; try { mj = JSON.parse(mi.text); } catch { /* reported */ }
  ok(mi.status === 200 && mj?.result?.protocolVersion === '2025-11-25' && mj.result.capabilities?.tools && !mi.h.get('mcp-session-id') && (NODE || mi.h.get('cache-control') === 'no-store'),
    `/mcp initialize: 200, protocolVersion, capabilities.tools, no session, not cached (got ${mi.status || mi.error} ${mi.text.trim().slice(0, 120)})`);
}

// ---- security.txt -----------------------------------------------------------------------------
{
  const t = got['/.well-known/security.txt'].body.toString();
  const exp = Date.parse((t.match(/^Expires:\s*(\S+)/m) ?? [])[1] ?? '');
  const days = Math.floor((exp - Date.now()) / 86400e3);
  ok(days > 0, `security.txt: Expires in the future (${Number.isFinite(days) ? `${days} days left` : 'missing'})`);
  if (days > 0 && days < 60) note(`security.txt expires in ${days} days: rebuild and redeploy (the build sets commit date + 1 year)`);
  ok(/^Contact: (mailto:|https:)/m.test(t) && t.includes(`Canonical: ${CANON}/.well-known/security.txt`), 'security.txt: Contact and Canonical');
}

// ---- headers ----------------------------------------------------------------------------------
if (NODE) skip('security headers, Cache-Control, Server', 'the node test server sends none; nginx.conf does');
else {
  for (const p of ['/', '/spec.md', '/index.json', '/.well-known/security.txt']) {
    const r = got[p];
    const wrong = Object.entries(H).filter(([k, v]) => r.h.get(k) !== v).map(([k]) => `${k}: ${r.h.get(k) ?? 'missing'}`);
    ok(wrong.length === 0, `${p}: CSP, Permissions-Policy, nosniff, no-referrer${wrong.length ? ` (wrong: ${wrong.join('; ')})` : ''}`);
    ok((r.h.get('vary') ?? '').split(',').map((s) => s.trim().toLowerCase()).includes('accept'), `${p}: Vary includes Accept (got "${r.h.get('vary')}")`);
    ok(r.h.get('cache-control') === HOUR, `${p}: Cache-Control "${HOUR}" (got "${r.h.get('cache-control')}")`);
  }
  const srv = got['/'].h.get('server');
  ok(!srv || !/\d/.test(srv), `Server header carries no version (server_tokens off; got "${srv ?? 'none'}")`);
  ok(!got['/'].h.get('set-cookie'), '/: sets no cookie');
  const link = got['/'].h.get('link') ?? '';
  ok(link.includes('</index.md>; rel="alternate"; type="text/markdown"') && link.includes('</llms.txt>; rel="describedby"; type="text/plain"'),
    `/: Link names the Markdown twin and /llms.txt (got "${link}")`);
  const miss = await get(at(`/no-such-page-${Date.now()}`), {}, 'manual');
  ok(miss.status === 404 && miss.h.get('cache-control') === MISS, `an unknown path: 404, Cache-Control "${MISS}" (got ${miss.status || miss.error}, "${miss.h.get('cache-control')}")`);
  ok((miss.h.get('link') ?? '').includes('</llms.txt>; rel="describedby"; type="text/plain"'), `an unknown path: Link names /llms.txt (rel=describedby) on the 404 too (got "${miss.h.get('link') ?? 'none'}")`);
}

// ---- /_stats/: the visit statistics are private --------------------------------------------
ok(!got['/sitemap.xml'].body.toString().includes('/_stats'), '/sitemap.xml: does not list /_stats/');
if (NODE) skip('/_stats/: 401 without credentials, noindex, no-store', 'nginx serves /_stats/, the node test server does not');
else {
  // Percent-encoded and doubled-slash forms reach the same location: nginx.conf keys its header
  // maps on the normalised $uri, so they must carry the same headers.
  for (const p of ['/_stats/', '/%5Fstats/', '//_stats/']) {
    const r = await get(at(p), {}, 'manual');
    ok(r.status === 401 && /^Basic /i.test(r.h.get('www-authenticate') ?? '') && /noindex/.test(r.h.get('x-robots-tag') ?? '') && r.h.get('cache-control') === 'no-store',
      `${p}: 401 Basic without credentials, X-Robots-Tag noindex, Cache-Control no-store (got ${r.status || r.error}, "${r.h.get('www-authenticate') ?? ''}", "${r.h.get('x-robots-tag') ?? ''}", "${r.h.get('cache-control') ?? ''}")`);
  }
}
// The not-found page itself is noindex, whichever way its path is written.
if (NODE) skip('/404.html and /404.md: X-Robots-Tag noindex', 'nginx sends it, the node test server does not');
else {
  for (const p of ['/404.html', '/404.md', '/%34%30%34.md']) {
    const r = await get(at(p), {}, 'manual');
    ok(r.status === 200 && /\bnoindex\b/.test(r.h.get('x-robots-tag') ?? ''), `${p}: 200, X-Robots-Tag noindex (got ${r.status || r.error}, "${r.h.get('x-robots-tag') ?? ''}")`);
  }
}

// ---- TLS: HSTS and the redirects --------------------------------------------------------------
if (NO_TLS) skip('HSTS, http:// → https://, www → apex', '--no-tls');
else {
  const hsts = got['/'].h.get('strict-transport-security') ?? '';
  ok(hsts === `max-age=${HSTS_AGE}`, `HSTS on /: max-age=${HSTS_AGE}, as nginx.conf sets it (got "${hsts || 'missing'}")`);
  const host = o.host;
  const redir = async (from, to) => {
    const r = await get(from, {}, 'manual');
    ok(r.status === 301 && r.h.get('location') === to, `${from} → 301 ${to} (got ${r.status || r.error} ${r.h.get('location') ?? ''})`);
  };
  await redir(`http://${host}/`, `https://${host}/`);
  await redir(`http://${host}/spec.md?x=1`, `https://${host}/spec.md?x=1`);
  if (NO_WWW) skip('www → apex', '--no-www');
  else {
    await redir(`https://www.${host}/spec.md`, `https://${host}/spec.md`);
    await redir(`http://www.${host}/`, `https://${host}/`);
    const w = await get(`https://www.${host}/`, {}, 'manual');
    ok(w.h.get('strict-transport-security') === `max-age=${HSTS_AGE}`, `https://www.${host}/: HSTS on the redirect too (got "${w.h.get('strict-transport-security') ?? 'missing'}")`);
    // The held domains, from the deployed index.json (site/src/official.mjs OFFICIAL). A live
    // redirect is what SECURITY.md and /contact promise, so a missing 301 FAILs; a pending one is
    // checked once its DNS reaches the origin's server, which serves its 301 already. Built from
    // the local HEAD, the table must be the local one: an empty or edited `redirects` is not a pass.
    const of = ix?.official ?? {};
    const table = (live) => Object.fromEntries(OFFICIAL.domains.filter((d) => d.role === 'redirect' && !!d.live === live).map((d) => [d.name, `https://${d.to}/`]));
    if (NO_ALT) skip('the held domains\' 301s', '--no-alt');
    else if (ok(of.redirects && of.redirects_pending_dns, 'index.json official: redirects and redirects_pending_dns')) {
      if (head && ix.built_from?.commit === head)
        ok(JSON.stringify(of.redirects) === JSON.stringify(table(true)) && JSON.stringify(of.redirects_pending_dns) === JSON.stringify(table(false)),
          `index.json official.redirects and redirects_pending_dns = site/src/official.mjs OFFICIAL (deployed ${JSON.stringify(of.redirects)}, local ${JSON.stringify(table(true))})`);
      else skip('index.json official redirects = site/src/official.mjs', `the deployed build ${String(ix?.built_from?.commit).slice(0, 12)} is not the local HEAD`);
      const a4 = (name) => dns.resolve4(name).catch(() => []);
      const ours = await a4(o.hostname);
      const held = async (d, to) => {
        const base = to.replace(/\/$/, '');
        await redir(`http://${d}/`, `${base}/`);
        await redir(`https://${d}/spec.md?x=1`, `${base}/spec.md?x=1`);
        await redir(`https://www.${d}/`, `${base}/`);
      };
      for (const [d, to] of Object.entries(of.redirects)) await held(d, to);
      for (const [d, to] of Object.entries(of.redirects_pending_dns)) {
        const r = await a4(d);
        if (ours.length && r.length && r.every((a) => ours.includes(a))) { note(`${d} now resolves to this server: once its 301s pass, mark it live in site/src/official.mjs`); await held(d, to); }
        else skip(`${d} → 301 ${to}`, `DNS not pointed yet: ${d} resolves to ${r.join(' ') || 'nothing'}, ${o.hostname} to ${ours.join(' ') || 'nothing'}`);
      }
    }
  }
}

summary();
