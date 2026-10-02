#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// site/test/run.mjs — checks site/dist/ the way an agent would meet it, over HTTP on localhost.
//
//   node site/build.mjs && node site/test/run.mjs
//   node site/test/run.mjs --serve [port]      serve dist on 127.0.0.1 and keep running (no checks)
//
// Serves dist on 127.0.0.1 (random port, node:http, no dependencies) with the content types and
// the Accept: text/markdown negotiation site/README.md asks of the deployer, then checks: every
// internal link (and #fragment) resolves; every page has its .md twin, a parsing JSON-LD block
// with the project's SoftwareSourceCode, a description and a canonical URL; tags balance; nothing
// loads from another origin; llms.txt, robots.txt, sitemap.xml, security.txt parse and their links
// resolve; index.json's sha256s match the files served and the repository's own files;
// integrations/mcp/server.json agrees with its package.json. Prints `ok …` lines, then
// `ALL PASS (<n> checks)` and exits 0, or `FAIL …` lines and exits 1.
import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, extname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE = dirname(dirname(fileURLToPath(import.meta.url)));
const ROOT = dirname(SITE);
const DIST = join(SITE, 'dist');
const ORIGIN = 'https://sigelo.io';
if (!existsSync(join(DIST, 'index.html'))) { console.error('FAIL no site/dist/index.html: run node site/build.mjs first'); process.exit(1); }

let n = 0; const fails = [];
const ok = (cond, what) => { n++; if (cond) console.log(`ok ${what}`); else { fails.push(what); console.log(`FAIL ${what}`); } };
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

// The content types below are the contract; site/deploy/nginx.conf (and apache.conf) must send the same.
const TYPES = { '.html': 'text/html; charset=utf-8', '.md': 'text/markdown; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
  '.json': 'application/json', '.xml': 'application/xml', '.css': 'text/css; charset=utf-8', '.yaml': 'application/yaml',
  '.mjs': 'text/javascript; charset=utf-8' };
const handler = (req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p.includes('..')) { res.writeHead(400).end(); return; }
  if (p.endsWith('/')) p += 'index.html';
  if (/\btext\/markdown\b/.test(req.headers.accept ?? '') && p.endsWith('.html')) p = p.replace(/\.html$/, '.md');
  const f = join(DIST, p);
  if (!existsSync(f) || !statSync(f).isFile()) { res.writeHead(404, { 'content-type': 'text/plain' }).end('not found'); return; }
  res.writeHead(200, { 'content-type': TYPES[extname(f)] ?? 'application/octet-stream', vary: 'Accept' });
  res.end(readFileSync(f));
};
const server = createServer(handler);
// `--serve [port]`: serve dist and keep running (what TASK-site.md's runner does); no checks.
const serveAt = process.argv.indexOf('--serve');
if (serveAt >= 0) {
  const port = Number(process.argv[serveAt + 1] ?? 0) || 0;
  server.listen(port, '127.0.0.1', () => {
    const p = server.address().port;
    // localhost may resolve to ::1 first: answer there too when the host has IPv6 loopback
    createServer(handler).on('error', () => {}).listen(p, '::1');
    console.log(`serving site/dist at http://localhost:${p}/ (127.0.0.1 and ::1; Ctrl-C stops)`);
  });
  await new Promise(() => {});
}
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
const get = async (path, headers = {}) => { const r = await fetch(BASE + path, { headers }); return { status: r.status, type: r.headers.get('content-type') ?? '', body: Buffer.from(await r.arrayBuffer()) }; };
const local = (url) => (url.startsWith(ORIGIN) ? url.slice(ORIGIN.length) || '/' : url);
// /releases/ is the release mirror, a directory on the server outside dist/ (site/deploy/mirror-release.sh):
// it cannot resolve here, so links into it are skipped and site/deploy/check.mjs checks them live.
const MIRRORED = (path) => path.startsWith('/releases/');

// ---- a small HTML reader: tags balance, attributes, ids, scripts ------------------------------
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
function readHtml(html) {
  const stack = []; const errors = []; const tags = [];
  const re = /<!--[\s\S]*?-->|<!doctype[^>]*>|<script\b[^>]*>[\s\S]*?<\/script>|<(\/?)([a-zA-Z][\w-]*)((?:\s+[\w:-]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>/gi;
  let m; let last = 0;
  const scripts = [];
  while ((m = re.exec(html))) {
    const between = html.slice(last, m.index);
    if (/[<>]/.test(between.replace(/&lt;|&gt;/g, ''))) errors.push(`stray < or > near: ${between.slice(0, 60)}`);
    last = re.lastIndex;
    const t = m[0];
    if (t.startsWith('<!')) continue;
    if (/^<script\b/i.test(t)) {
      const open = t.match(/^<script\b([^>]*)>/i)[1];
      scripts.push({ attrs: open, body: t.replace(/^<script\b[^>]*>/i, '').replace(/<\/script>$/i, '') });
      continue;
    }
    const [, close, name, attrStr, self] = m; const tag = name.toLowerCase();
    const attrs = {};
    for (const a of attrStr.matchAll(/([\w:-]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) attrs[a[1].toLowerCase()] = a[3] ?? a[4] ?? a[5] ?? '';
    if (close) {
      const top = stack.pop();
      if (top !== tag) errors.push(`</${tag}> closes <${top ?? 'nothing'}>`);
    } else {
      tags.push({ tag, attrs });
      if (!VOID.has(tag) && !self) stack.push(tag);
    }
  }
  if (stack.length) errors.push(`unclosed: ${stack.join(', ')}`);
  return { errors, tags, scripts };
}
const unesc = (s) => s.replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

// ---- walk dist --------------------------------------------------------------------------------
const files = [];
(function walk(d) { for (const e of readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(join(d, e.name)) : files.push('/' + relative(DIST, join(d, e.name)).split('\\').join('/')); })(DIST);
const htmlFiles = files.filter((f) => f.endsWith('.html'));
const idsOf = new Map(); const linksOf = new Map();
for (const f of htmlFiles) {
  const html = readFileSync(join(DIST, f), 'utf8');
  const { errors, tags, scripts } = readHtml(html);
  ok(errors.length === 0, `${f}: tags balance${errors.length ? ` (${errors.slice(0, 3).join('; ')})` : ''}`);
  idsOf.set(f, new Set(tags.filter((t) => t.attrs.id).map((t) => t.attrs.id)));
  linksOf.set(f, tags.filter((t) => t.tag === 'a' && t.attrs.href).map((t) => unesc(t.attrs.href)));
  const twin = f.replace(/\.html$/, '.md');
  ok(files.includes(twin), `${f}: Markdown twin ${twin} exists`);
  ok(tags.some((t) => t.tag === 'link' && t.attrs.rel === 'alternate' && t.attrs.type === 'text/markdown' && t.attrs.href === twin), `${f}: <link rel=alternate type=text/markdown href=${twin}>`);
  const desc = tags.find((t) => t.tag === 'meta' && t.attrs.name === 'description');
  ok(desc && desc.attrs.content.length >= 50 && desc.attrs.content.length <= 320, `${f}: meta description (${desc?.attrs.content.length ?? 0} chars)`);
  const canon = tags.find((t) => t.tag === 'link' && t.attrs.rel === 'canonical');
  ok(canon && canon.attrs.href === (f === '/index.html' ? `${ORIGIN}/` : `${ORIGIN}${f}`), `${f}: canonical ${canon?.attrs.href}`);
  ok(tags.filter((t) => t.tag === 'h1').length === 1, `${f}: exactly one <h1>`);
  const ld = scripts.filter((s) => /type="application\/ld\+json"/.test(s.attrs));
  ok(scripts.length === ld.length, `${f}: no executable <script> (only JSON-LD)`);
  let graph = null; try { graph = JSON.parse(ld[0]?.body ?? ''); } catch { /* reported below */ }
  const types = (graph?.['@graph'] ?? []).map((g) => g['@type']);
  ok(graph?.['@context'] === 'https://schema.org' && types.includes('SoftwareSourceCode'), `${f}: JSON-LD parses, schema.org, SoftwareSourceCode present (${types.join(', ')})`);
  const sw = graph?.['@graph']?.find((g) => g['@type'] === 'SoftwareSourceCode');
  ok(sw && sw.codeRepository && sw.programmingLanguage?.length && sw.license, `${f}: SoftwareSourceCode has codeRepository, programmingLanguage, license`);
  ok(sw?.sameAs === sw?.codeRepository, `${f}: SoftwareSourceCode sameAs = codeRepository`);
  if (/^\/(spec|threat-model)\.html$/.test(f)) {
    const art = graph?.['@graph']?.find((g) => g['@type'] === 'TechArticle');
    ok(art && art.headline && art.headline.length <= 110 && !Number.isNaN(Date.parse(art.dateModified)), `${f}: TechArticle with headline (≤ 110 chars) and dateModified`);
  }
  const external = tags.filter((t) => (t.tag === 'link' && t.attrs.rel !== 'canonical' && /^https?:/.test(t.attrs.href)) || (/^(img|script|iframe|source|video|audio)$/.test(t.tag) && t.attrs.src));
  ok(external.length === 0, `${f}: loads nothing from another origin or by src=`);
  ok(!/\sstyle=|<style\b|\son[a-z]+=/i.test(html), `${f}: no inline style or event handler (CSP default-src 'self')`);
}

// ---- links: every internal href (and #fragment) resolves over HTTP ----------------------------
const seen = new Map();
const status = async (path) => { if (!seen.has(path)) seen.set(path, (await get(path)).status); return seen.get(path); };
for (const [f, links] of linksOf) {
  const bad = [];
  for (const href of links) {
    if (/^(https?:|mailto:|simplex:)/.test(href) && !href.startsWith(ORIGIN)) continue;
    const u = new URL(local(href), BASE + f);
    if (MIRRORED(u.pathname)) continue;
    if (await status(u.pathname) !== 200) { bad.push(href); continue; }
    if (u.hash) {
      const target = u.pathname.endsWith('/') ? `${u.pathname}index.html` : u.pathname;
      const ids = idsOf.get(target);
      if (ids && !ids.has(decodeURIComponent(u.hash.slice(1)))) bad.push(href);
    }
  }
  ok(bad.length === 0, `${f}: ${links.length} links, every internal one resolves${bad.length ? ` (broken: ${bad.slice(0, 5).join(' ')})` : ''}`);
}
// The .md twins: their internal links resolve too.
for (const f of files.filter((x) => x.endsWith('.md') && !x.startsWith('/raw/') && !x.startsWith('/sha256/'))) {
  const md = readFileSync(join(DIST, f), 'utf8').replace(/```[\s\S]*?```/g, '').replace(/`[^`\n]*`/g, '');
  const bad = [];
  for (const [, u] of md.matchAll(/\]\((\/[^)\s]*)\)/g)) { const p = new URL(u, BASE).pathname; if (!MIRRORED(p) && await status(p) !== 200) bad.push(u); }
  ok(bad.length === 0, `${f}: internal links resolve${bad.length ? ` (broken: ${bad.slice(0, 5).join(' ')})` : ''}`);
}

// ---- negotiation and content types ------------------------------------------------------------
{
  const r = await get('/spec.html', { accept: 'text/markdown' });
  ok(r.status === 200 && r.type.startsWith('text/markdown') && r.body.toString().startsWith('# '), 'Accept: text/markdown on /spec.html serves the Markdown twin');
  const t = await get('/spec.md');
  ok(t.type === 'text/markdown; charset=utf-8', '/spec.md is text/markdown; charset=utf-8');
  ok(t.body.equals(readFileSync(join(ROOT, 'SPEC.md'))) || t.body.toString().includes('## 9. Verification algorithm'), '/spec.md carries SPEC.md');
  ok((await get('/raw/SPEC.md')).body.equals(readFileSync(join(ROOT, 'SPEC.md'))), '/raw/SPEC.md is SPEC.md byte for byte');
}

// ---- llms.txt ---------------------------------------------------------------------------------
{
  const t = (await get('/llms.txt')).body.toString();
  const lines = t.split('\n');
  ok(/^# \S/.test(lines[0]), 'llms.txt: starts with an H1');
  ok(lines.slice(1).find((l) => l.trim())?.startsWith('> '), 'llms.txt: the H1 is followed by a blockquote summary');
  const sections = lines.filter((l) => l.startsWith('## ')).map((l) => l.slice(3));
  ok(sections.length >= 3 && sections[sections.length - 1] === 'Optional', `llms.txt: H2 sections, "Optional" last (${sections.join(' | ')})`);
  const items = lines.filter((l) => l.startsWith('- '));
  ok(items.every((l) => /^- \[[^\]]+\]\([^)]+\)(: .+)?$/.test(l)), `llms.txt: every list item is "- [name](url): description" (${items.length})`);
  const bad = [];
  for (const l of items) { const u = l.match(/\]\(([^)]+)\)/)[1]; if (!u.startsWith(ORIGIN) || (!MIRRORED(local(u)) && await status(local(u)) !== 200)) bad.push(u); }
  ok(bad.length === 0, `llms.txt: all ${items.length} links are on ${ORIGIN} and resolve${bad.length ? ` (${bad.join(' ')})` : ''}`);
  const full = (await get('/llms-full.txt')).body.toString();
  const parts = [...full.matchAll(/^==> https:\/\/sigelo\.io\/([\w-]+)\.md <==$/gm)].map((m) => m[1]);
  ok(parts.join() === 'spec,adopt,verify,keeper,security', `llms-full.txt: carries spec, adopt, verify, keeper, security only (${parts.join(', ')})`);
  const sz = Buffer.byteLength(full); const kb = `${Math.max(1, Math.round(sz / 1024))} KB`;
  ok(t.includes(`(${ORIGIN}/llms-full.txt): ${kb}`), `llms.txt: states llms-full.txt's size (${kb})`);
  ok(items.filter((l) => lines.indexOf(l) < lines.indexOf('## Optional')).length <= 10, 'llms.txt: at most 10 links before Optional');
  ok(t.includes(`- [Releases](${ORIGIN}/releases/): binaries, tarballs, SHA256SUMS`), 'llms.txt: names the release mirror /releases/');
  ok((await get('/adopt.md')).body.toString().split('\n').length <= 90, 'adopt.md: short enough to follow (≤ 90 lines)');
}

// ---- /changelog: terse, impersonal --------------------------------------------------------------
// The reader pays per token: every bullet in the file (continuation lines joined) is ≤ 220
// characters, and nowhere a story, a feedback quote or a first person. The why lives
// in the internal JOURNAL.md.
{
  const cl = readFileSync(join(DIST, 'changelog.md'), 'utf8');
  const bullets = cl.split(/\n(?=- |\S)/).filter((b) => b.startsWith('- ')).map((b) => b.replace(/\s*\n\s*/g, ' ').trim());
  const long = bullets.filter((b) => [...b].length > 220);
  ok(bullets.length > 0 && long.length === 0, `changelog: all ${bullets.length} bullets ≤ 220 characters${long.length ? ` (over: ${long.map((b) => b.slice(0, 40)).join(' | ')})` : ''}`);
  const BANNED = [/\bOwner\b/, /\b[Ff]eedback\b/, /\bthe same day\b/i, /(?:^|[\s("])[Ww]e /m, /(?:^|[\s("])I (?=[a-z])/m,
    /\b(?:an?|each|its own|one|the|Haiku|Sonnet|Opus|sub)\s*agents? (?:ran|found|wrote|fixed|reviewed|built|did|made|checked|closed|proved)\b/i, /\bby (?:an?|each|its own|one) agent\b/i];
  const hits = BANNED.filter((re) => re.test(cl));
  ok(hits.length === 0, `changelog: no narration (Owner, agent as actor, feedback, "the same day", first person)${hits.length ? ` — hit ${hits.join(' ')}` : ''}`);
}

// ---- the page list and the word budgets ---------------------------------------------------------
// The reader pays per token. Words = whitespace-separated tokens holding a letter or digit;
// inside fenced code and on link-list lines they count half. llms.txt counts every word in full.
{
  const PAGES = ['accept', 'adopt', 'changelog', 'contact', 'index', 'keeper', 'privacy', 'security', 'spec', 'verify'];
  const got = htmlFiles.filter((f) => /^\/[\w-]+\.html$/.test(f)).map((f) => f.slice(1, -5)).sort();
  ok(got.join() === PAGES.join(), `pages: exactly ${PAGES.join(', ')} (${got.join(', ')})`);
  const words = (md, half = true) => {
    let w = 0; let fence = false;
    for (const line of md.split('\n')) {
      if (/^\s*(```|~~~)/.test(line)) { fence = !fence; continue; }
      const k = !half ? 1 : fence || /^\s*[-*] .*\]\(/.test(line) ? 0.5 : 1;
      w += k * line.split(/\s+/).filter((x) => /[\p{L}\p{N}]/u.test(x)).length;
    }
    return w;
  };
  const BUDGET = { '/index.md': 120, '/adopt.md': 250, '/accept.md': 200, '/verify.md': 150, '/keeper.md': 200, '/contact.md': 80, '/privacy.md': 150 };
  for (const [f, max] of Object.entries(BUDGET)) {
    const w = words(readFileSync(join(DIST, f), 'utf8'));
    ok(w <= max, `budget: ${f} ${w} words ≤ ${max}`);
  }
  const lw = words(readFileSync(join(DIST, 'llms.txt'), 'utf8'), false);
  ok(lw <= 150, `budget: /llms.txt ${lw} words ≤ 150 (all counted in full)`);
  // /privacy: its two halves have their own caps (privacy 90, terms 60 words).
  const [pv, tm] = readFileSync(join(DIST, 'privacy.md'), 'utf8').split(/^## Terms$/m);
  ok(tm !== undefined && words(pv.replace(/^# .*$/m, '')) <= 90 && words(tm) <= 60, `budget: /privacy.md privacy ${words(pv.replace(/^# .*$/m, ''))} ≤ 90, terms ${words(tm ?? '')} ≤ 60`);
}

// ---- privacy, terms, release signing -------------------------------------------------------------
{
  const ix = JSON.parse(readFileSync(join(DIST, 'index.json'), 'utf8'));
  const html = readFileSync(join(DIST, 'privacy.html'), 'utf8');
  ok(ix.privacy === `${ORIGIN}/privacy.html` && ix.terms === `${ORIGIN}/privacy.html#terms` && html.includes('id="terms"'), 'index.json: privacy and terms (/privacy.html#terms) resolve');
  ok(['index.md', 'contact.md'].every((p) => readFileSync(join(DIST, p), 'utf8').includes('(/privacy.md)')), '/ and /contact link /privacy.html');
  const same = (w, r) => readFileSync(join(DIST, w)).equals(readFileSync(join(ROOT, r)));
  ok(same('.well-known/sigelo-release-signers', 'release/allowed_signers') && same('.well-known/sigelo-release-identity.json', 'release/release-identity.json')
    && /^\S+ namespaces="git" ssh-ed25519 \S+$/m.test(readFileSync(join(ROOT, 'release/allowed_signers'), 'utf8')) && /^did:sigelo:z\w+$/.test(ix.release_signing?.identity ?? ''),
    `release signing: /.well-known/sigelo-release-signers and -identity.json = release/, index.json release_signing.identity ${ix.release_signing?.identity}`);
}

// ---- robots.txt and sitemap.xml ---------------------------------------------------------------
{
  const t = (await get('/robots.txt')).body.toString();
  const FIELDS = new Set(['user-agent', 'allow', 'disallow', 'sitemap', 'crawl-delay']);
  const bad = t.split('\n').filter((l) => l.trim() && !l.startsWith('#') && !(l.includes(':') && FIELDS.has(l.slice(0, l.indexOf(':')).trim().toLowerCase())));
  ok(bad.length === 0, `robots.txt: every line is a comment or a known field${bad.length ? ` (${bad[0]})` : ''}`);
  ok(!/^disallow:\s*\S/im.test(t), 'robots.txt: disallows nothing');
  const uas = [...t.matchAll(/^User-agent:\s*(\S+)/gim)].map((m) => m[1]);
  const want = ['GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-SearchBot', 'Claude-User', 'PerplexityBot', 'Perplexity-User', 'Google-Extended', 'Applebot', 'Applebot-Extended', 'CCBot', 'Amazonbot', 'Amzn-SearchBot', 'Meta-ExternalAgent', 'Meta-WebIndexer', 'MistralAI-User', 'MistralAI-Index', 'DuckAssistBot', '*'];
  ok(want.every((w) => uas.includes(w)), `robots.txt: names the crawlers of ROADMAP §3 (${uas.length} user-agents)`);
  const sm = t.match(/^Sitemap:\s*(\S+)/im)?.[1];
  ok(sm === `${ORIGIN}/sitemap.xml` && await status(local(sm)) === 200, 'robots.txt: Sitemap line resolves');
  const x = (await get('/sitemap.xml')).body.toString();
  const { errors } = readHtml(x.replace(/^<\?xml[^>]*\?>/, ''));
  ok(x.startsWith('<?xml') && x.includes('xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"') && errors.length === 0, 'sitemap.xml: XML declaration, sitemap namespace, tags balance');
  const locs = [...x.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  const badLocs = []; for (const l of locs) if (!l.startsWith(ORIGIN) || await status(local(l)) !== 200) badLocs.push(l);
  ok(locs.length >= htmlFiles.length && badLocs.length === 0, `sitemap.xml: ${locs.length} URLs, all on ${ORIGIN}, all resolve`);
}

// ---- IndexNow: /<key>.txt holds site/deploy/indexnow-key.txt's key --------------------------
{
  const key = readFileSync(join(SITE, 'deploy', 'indexnow-key.txt'), 'utf8').trim();
  const r = await get(`/${key}.txt`);
  ok(/^[a-zA-Z0-9-]{8,128}$/.test(key) && r.status === 200 && r.type.startsWith('text/plain') && r.body.toString().trim() === key, 'IndexNow: /<key>.txt serves the key as text/plain');
}

// ---- index.json -------------------------------------------------------------------------------
{
  const ix = JSON.parse((await get('/index.json')).body);
  ok(ix.wire === 'sigelo/0' && ix.name === 'sigelo' && ix.license === 'MIT', 'index.json: name, wire sigelo/0, MIT');
  const entries = [['spec', ix.spec], ['vectors', ix.vectors], ['openapi', ix.openapi], ...ix.schemas.map((s) => [s.url, s])];
  const bad = [];
  for (const [name, e] of entries) {
    const r = await get(local(e.url));
    if (r.status !== 200 || sha256(r.body) !== e.sha256 || r.body.length !== e.bytes) bad.push(name);
    if (e.immutable) { const im = await get(local(e.immutable)); if (sha256(im.body) !== e.sha256 || !e.immutable.includes(e.sha256)) bad.push(`${name} immutable`); }
  }
  ok(bad.length === 0, `index.json: ${entries.length} sha256s match the files served${bad.length ? ` (${bad.join(', ')})` : ''}`);
  ok(ix.spec.sha256 === sha256(readFileSync(join(ROOT, 'SPEC.md'))) && ix.vectors.sha256 === sha256(readFileSync(join(ROOT, 'test-vectors.json'))), 'index.json: spec and vectors sha256 = the repository\'s SPEC.md and test-vectors.json');
  const v = JSON.parse(readFileSync(join(ROOT, 'test-vectors.json')));
  ok(ix.vectors.counts.positive === Object.keys(v.vectors).length && ix.vectors.counts.parity === Object.keys(v.negative.parity.cases).length, 'index.json: vector counts match the file');
  const vers = ix.implementations.filter((i) => i.path !== 'go/').every((i) => JSON.parse(readFileSync(join(ROOT, i.path, 'package.json'))).version === i.version);
  ok(vers, 'index.json: implementation versions = their package.json');
  ok(ix.pages.every((p) => !p.source || p.source_sha256 === sha256(readFileSync(join(ROOT, p.source)))), 'index.json: page sources hash to the tree\'s files');
  ok(ix.release.artefacts.includes('SHA256SUMS') && ix.release.artefacts.filter((a) => a.startsWith('sigelo-verify-')).length === 6, 'index.json: release artefacts named (5 binaries + source archive, SHA256SUMS)');
  // The mirror: release.files is the committed SHA256SUMS of the latest mirrored tag, line for line.
  const rel = ix.release;
  const sumsFile = join(SITE, 'src', 'releases', `${rel.tag}.SHA256SUMS`);
  const sums = existsSync(sumsFile) ? readFileSync(sumsFile, 'utf8').trim().split('\n').map((l) => l.split(/ [ *]/)) : [];
  ok(rel.mirror === `${ORIGIN}/releases/` && rel.sha256sums === `${ORIGIN}/releases/${rel.tag}/SHA256SUMS` && sums.length > 0
    && rel.files.length === sums.length && rel.files.every((f, i) => f.sha256 === sums[i][0] && f.name === sums[i][1] && f.url === `${ORIGIN}/releases/${rel.tag}/${f.name}`),
    `index.json: release.mirror, and release.files = site/src/releases/${rel.tag}.SHA256SUMS (${rel.files?.length} files)`);
  if (rel.tag === `v${rel.version}`) ok([...rel.files.map((f) => f.name), 'SHA256SUMS'].sort().join() === [...rel.artefacts].sort().join(), `index.json: release.files of ${rel.tag} = release.artefacts (+ SHA256SUMS)`);
  ok(!files.some((f) => f.startsWith('/releases/')), 'dist has no /releases/ (the mirror lives on the server, outside dist/)');
  // The official names: index.json `official`, SECURITY.md "Official channels", one line on / and /contact.
  const of = ix.official ?? {};
  const sec = readFileSync(join(ROOT, 'SECURITY.md'), 'utf8');
  const section = sec.match(/^## Official channels\n([\s\S]*?)(?=\n## )/m)?.[1] ?? '';
  ok(of.issuer_did && of.issuer_did === ix.world?.issuer && of.domains?.join() === 'sigelo.io,sigelo.net' && of.repository === 'https://github.com/csigelo/sigelo'
    && of.npm_user === 'csigelo' && of.maintainer === 'csigelo' && of.packages?.length === 5 && of.releases?.includes(`${ORIGIN}/releases/`),
    `index.json: official (domains, repository, releases, issuer_did = world.issuer, npm_user, ${of.packages?.length} packages, maintainer)`);
  ok(section && section.trim().split('\n').length <= 11 && [of.issuer_did, of.repository, `${ORIGIN}/releases/`, 'sigelo.net', 'security@sigelo.io', ...(of.packages ?? [])].every((s) => s && section.includes(s)),
    `SECURITY.md: "## Official channels" (${section.trim().split('\n').length + 1} lines ≤ 12) names the issuer DID, repository, mirror, domains, packages, security@`);
  ok(idsOf.get('/security.html')?.has('official-channels'), '/security.html: #official-channels anchor');
  for (const p of ['/index.md', '/contact.md']) {
    const t = readFileSync(join(DIST, p), 'utf8');
    ok(t.includes('anything else is not us') && t.includes(of.issuer_did?.slice(0, 17)) && t.includes('github.com/csigelo/sigelo'), `${p}: the one "Official: … anything else is not us" line`);
  }
}

// ---- security.txt (RFC 9116) ------------------------------------------------------------------
{
  const r = await get('/.well-known/security.txt');
  const t = r.body.toString();
  const field = (k) => [...t.matchAll(new RegExp(`^${k}:\\s*(.+)$`, 'gim'))].map((m) => m[1].trim());
  ok(r.status === 200 && r.type.startsWith('text/plain'), '/.well-known/security.txt is served as text/plain');
  ok(field('Contact').length >= 1 && field('Contact').every((c) => /^(mailto:|https:|simplex:)/.test(c)) && field('Contact')[0] === 'mailto:security@sigelo.io', `security.txt: Contact (${field('Contact').join(', ')})`);
  const exp = field('Expires');
  const ms = Date.parse(exp[0]);
  ok(exp.length === 1 && /Z$/.test(exp[0]) && ms > Date.now() && ms - Date.now() <= 366 * 86400e3 + 86400e3 * 30, `security.txt: one Expires, in the future, about a year out (${exp[0]})`);
  ok(field('Canonical')[0] === `${ORIGIN}/.well-known/security.txt`, 'security.txt: Canonical');
  ok(field('Policy')[0] === `${ORIGIN}/security.html` && await status('/security.html') === 200, 'security.txt: Policy resolves');
  ok(field('Policy')[1] === `${ORIGIN}/security.html#official-channels` && idsOf.get('/security.html')?.has('official-channels'), 'security.txt: second Policy, /security.html#official-channels, resolves to its anchor');
  ok(t.split('\n').every((l) => !l.trim() || l.startsWith('#') || /^[A-Za-z-]+: \S/.test(l)), 'security.txt: every line is a comment or a field');
}

// ---- the contact surface: the SimpleX placeholder never ships ---------------------------------
{
  // site/build.mjs SIMPLEX is the one source of the address. While it is an <angle-bracket>
  // placeholder, no generated file may carry it; only SECURITY.md's own copies (verbatim, rendered,
  // in llms-full.txt) may, because that document keeps the placeholder as its channel 3.
  const PH = '<simplex-contact-address>';
  const CARRIERS = new Set(['/raw/SECURITY.md', '/security.md', '/security.html', '/llms-full.txt']);
  const leaks = files.filter((f) => !CARRIERS.has(f) && /<simplex-[\w-]*>|&lt;simplex-[\w-]*&gt;/.test(readFileSync(join(DIST, f), 'utf8')));
  ok(leaks.length === 0, `no generated file carries a SimpleX placeholder (${PH}), only SECURITY.md's copies${leaks.length ? ` (leaks: ${leaks.join(' ')})` : ''}`);
  const ix = JSON.parse(readFileSync(join(DIST, 'index.json'), 'utf8'));
  const sx = readFileSync(join(DIST, '.well-known/security.txt'), 'utf8').match(/^Contact: (?!mailto:)(.+)$/m)?.[1] ?? null;
  const md = readFileSync(join(DIST, 'contact.md'), 'utf8');
  ok(ix.contact?.email === 'contact@sigelo.io' && ix.contact.security === 'security@sigelo.io' && ix.contact.simplex === sx
    && (sx ? md.includes(sx) : /\*\*SimpleX:\*\* \*\*coming\*\*/.test(md)),
    `contact: index.json, security.txt and /contact agree on the SimpleX address (${sx ?? 'unset: omitted, page says coming'})`);
  const ld = JSON.parse(readFileSync(join(DIST, 'contact.html'), 'utf8').match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)[1]);
  const cps = ld['@graph'].find((g) => g['@type'] === 'ContactPage')?.mainEntity?.contactPoint ?? [];
  ok(cps.some((c) => c.email === 'contact@sigelo.io') && cps.some((c) => c.email === 'security@sigelo.io') && cps.filter((c) => c.url && c.url === sx).length === (sx ? 1 : 0),
    `/contact.html: JSON-LD ContactPage with ${cps.length} ContactPoints (SimpleX only when set)`);
}

// ---- integrations/mcp/server.json -------------------------------------------------------------
{
  const sj = JSON.parse(readFileSync(join(ROOT, 'integrations/mcp/server.json'), 'utf8'));
  const pj = JSON.parse(readFileSync(join(ROOT, 'integrations/mcp/package.json'), 'utf8'));
  const p = sj.packages?.[0];
  ok(/^[a-z0-9.-]+\/[a-z0-9._-]+$/i.test(sj.name) && sj.version === pj.version && sj.description.length <= 100, `server.json: name ${sj.name}, version = package.json (${pj.version}), description ≤ 100 chars`);
  ok(pj.mcpName === sj.name && sj.name.startsWith('io.github.') && sj.repository?.url === `https://github.com/${sj.name.split('/')[0].slice('io.github.'.length)}/sigelo`, `server.json: package.json mcpName = ${sj.name} (the registry's package-ownership check), its GitHub namespace = repository.url's account`);
  ok(p?.registryType === 'npm' && p.identifier === pj.name && p.version === pj.version && p.transport?.type === 'stdio', 'server.json: one npm package, sigelo-mcp, stdio');
}

server.close();
if (fails.length) { console.log(`FAILURES (${fails.length} of ${n} checks)`); process.exit(1); }
console.log(`ALL PASS (${n} checks)`);
