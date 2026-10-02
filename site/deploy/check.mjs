#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// site/deploy/check.mjs — verifies a deployed sigelo.io from the outside, the way an agent meets it.
//
//   node site/deploy/check.mjs                                   https://sigelo.io, every check
//   node site/deploy/check.mjs --origin https://staging.example --no-www
//   node site/deploy/check.mjs --origin http://127.0.0.1:8080 --no-tls --node-server
//
// Checks: status 200 and the exact content type site/test/run.mjs serves for /, /llms.txt,
// /adopt.md, /index.json, /.well-known/security.txt, /sitemap.xml, /robots.txt, /spec.md,
// /examples/world.mjs and a /sha256/<hex>/ file (whose hash is recomputed); Accept: text/markdown
// on /, /spec.html and /spec serves the Markdown twin; index.json's sha256s match the files
// served; its built_from.commit is the local HEAD and not dirty; security.txt has not expired;
// the security and cache headers of site/deploy/nginx.conf; /_stats/ answers 401 (basic auth,
// noindex, no-store) and is not in the sitemap; HSTS; http:// → https:// and
// www → apex 301s; when index.json has a `world` block, the world (world/README.md): a §5.2
// challenge, the whole attest flow with a fixed-seed check agent (the ts library from ts/dist; one
// subject, idempotent for 24 h), /world/stats with counts only, /world/conformance refusing an empty
// body and /mcp answering initialize. Prints ok/FAIL/skip/note lines, then ALL PASS and exit 0, or exit 1.
//
// Flags:
//   --origin URL       what to check (default https://sigelo.io); index.json's URLs are mapped onto it
//   --no-tls           plain-HTTP origin: skip HSTS and the redirect checks
//   --no-www           skip www.<host> (a staging origin has none)
//   --alt DOMAIN       the second domain that 301s to the apex (default sigelo.net); --no-alt skips it
//   --node-server      the origin is `node site/test/run.mjs --serve`, which implements the content
//                      types and negotiation but sends no security or cache headers and does not map
//                      /spec to /spec.html: skip those checks (they are nginx's job)
//   --commit SHA       expected build commit (default: git rev-parse HEAD of this repository)
//   --any-commit       do not compare the build commit (after a rollback)
// Uses node's fetch, no dependencies, node >= 22.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const CANON = 'https://sigelo.io';
const argv = process.argv.slice(2);
const flag = (f) => argv.includes(f);
const opt = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const known = new Set(['--origin', '--no-tls', '--no-www', '--node-server', '--commit', '--any-commit', '--alt', '--no-alt']);
const ALT = flag('--no-alt') ? [] : [opt('--alt', 'sigelo.net')].filter((x) => x && !x.startsWith('--'));
for (let i = 0; i < argv.length; i++) {
  if (!known.has(argv[i])) { console.error(`check.mjs: unknown argument ${argv[i]}`); process.exit(2); }
  if (argv[i] === '--origin' || argv[i] === '--commit' || argv[i] === '--alt') i++;
}
const ORIGIN = (opt('--origin', CANON) ?? '').replace(/\/+$/, '');
const NO_TLS = flag('--no-tls'), NO_WWW = flag('--no-www') || NO_TLS, NODE = flag('--node-server');
let o; try { o = new URL(ORIGIN); } catch { console.error(`check.mjs: --origin is not a URL: ${ORIGIN}`); process.exit(2); }
if (!NO_TLS && o.protocol !== 'https:') { console.error('check.mjs: an http:// origin needs --no-tls'); process.exit(2); }

let want = opt('--commit');
if (!want && !flag('--any-commit')) {
  const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
  try { want = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(); }
  catch { console.error('check.mjs: cannot read the local HEAD (git); pass --commit SHA or --any-commit'); process.exit(2); }
}

// The test server's types (site/test/run.mjs TYPES), byte for byte.
const T = { html: 'text/html; charset=utf-8', md: 'text/markdown; charset=utf-8', txt: 'text/plain; charset=utf-8',
  json: 'application/json', xml: 'application/xml', mjs: 'text/javascript; charset=utf-8', yaml: 'application/yaml', css: 'text/css; charset=utf-8' };
const typeOf = (path) => T[(path.match(/\.([a-z]+)$/) ?? [])[1]] ?? (path.endsWith('/') ? T.html : null);
// site/deploy/nginx.conf's headers, verbatim.
const H = {
  'content-security-policy': "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'permissions-policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=(), browsing-topics=()',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
};
const HOUR = 'public, max-age=3600', YEAR = 'public, max-age=31536000, immutable';

let n = 0, skipped = 0; const fails = [];
const ok = (cond, what) => { n++; if (cond) console.log(`ok ${what}`); else { fails.push(what); console.log(`FAIL ${what}`); } return cond; };
const skip = (what, why) => { skipped++; console.log(`skip ${what} (${why})`); };
const note = (what) => console.log(`note ${what}`);
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const get = async (url, headers = {}, redirect = 'follow') => {
  try {
    const r = await fetch(url, { headers, redirect, signal: AbortSignal.timeout(20000) });
    return { status: r.status, h: r.headers, type: r.headers.get('content-type') ?? '', body: Buffer.from(await r.arrayBuffer()), url: r.url };
  } catch (e) { return { status: 0, h: new Headers(), type: '', body: Buffer.alloc(0), error: e.cause?.code ?? e.message }; }
};
const at = (path) => ORIGIN + path;
const local = (u) => (u.startsWith(CANON) ? u.slice(CANON.length) || '/' : u);
const show = (r) => (r.status ? `${r.status}, ${r.type || 'no content-type'}` : `no response: ${r.error}`);

console.log(`checking ${ORIGIN}${NO_TLS ? ' (--no-tls)' : ''}${NODE ? ' (--node-server)' : ''}`);

// ---- the files: 200 and the exact content type ------------------------------------------------
const got = {};
for (const p of ['/', '/llms.txt', '/adopt.md', '/index.json', '/.well-known/security.txt', '/sitemap.xml', '/robots.txt', '/spec.md', '/examples/world.mjs', '/style.css']) {
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
      const r = await fetch(wurl(w.attest), { method: 'POST', body: JSON.stringify({ challenge: ch, did: agent.did, sig: signed.sig, bundle }), signal: AbortSignal.timeout(20000) });
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
    try { const r = await fetch(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(20000) }); return { status: r.status, h: r.headers, text: await r.text() }; }
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
}

// ---- /_stats/: the visit statistics are private --------------------------------------------
ok(!got['/sitemap.xml'].body.toString().includes('/_stats'), '/sitemap.xml: does not list /_stats/');
if (NODE) skip('/_stats/: 401 without credentials, noindex, no-store', 'nginx serves /_stats/, the node test server does not');
else {
  const r = await get(at('/_stats/'), {}, 'manual');
  ok(r.status === 401 && /^Basic /i.test(r.h.get('www-authenticate') ?? '') && /noindex/.test(r.h.get('x-robots-tag') ?? '') && r.h.get('cache-control') === 'no-store',
    `/_stats/: 401 Basic without credentials, X-Robots-Tag noindex, Cache-Control no-store (got ${r.status || r.error}, "${r.h.get('www-authenticate') ?? ''}", "${r.h.get('x-robots-tag') ?? ''}", "${r.h.get('cache-control') ?? ''}")`);
}

// ---- TLS: HSTS and the redirects --------------------------------------------------------------
if (NO_TLS) skip('HSTS, http:// → https://, www → apex', '--no-tls');
else {
  const hsts = got['/'].h.get('strict-transport-security') ?? '';
  const age = Number((hsts.match(/max-age=(\d+)/) ?? [])[1] ?? -1);
  ok(age >= 300, `HSTS on / (got "${hsts || 'missing'}")`);
  if (age >= 300 && age < 31536000) note(`HSTS max-age=${age}: once this check passes on the live site, set max-age=31536000 in both lines of site/deploy/nginx.conf and redeploy`);
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
    // the second domain the project holds: every name 301s to the apex of the first
    for (const alt of ALT) {
      await redir(`http://${alt}/`, `https://${host}/`);
      await redir(`https://${alt}/spec.md`, `https://${host}/spec.md`);
      await redir(`https://www.${alt}/`, `https://${host}/`);
    }
    const w = await get(`https://www.${host}/`, {}, 'manual');
    ok(/max-age=\d+/.test(w.h.get('strict-transport-security') ?? ''), `https://www.${host}/: HSTS on the redirect too`);
  }
}

if (fails.length) { console.log(`FAILURES (${fails.length} of ${n} checks${skipped ? `, ${skipped} skipped` : ''})`); process.exit(1); }
console.log(`ALL PASS (${n} checks${skipped ? `, ${skipped} skipped` : ''})`);
