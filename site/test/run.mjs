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
// titles ≤ 60 characters and descriptions ≤ 155; the official names agree everywhere with
// site/src/official.mjs OFFICIAL (index.json, SECURITY.md, / and /contact, site/deploy/nginx.conf,
// each server block on its own); the links to the relay only from its launch (RELAY_LIVE); the
// sitemap's lastmod; site/deploy/check.mjs --preflight refuses an off-origin target that does not
// answer (against this server); site/deploy/indexnow.sh sends changed URLs only;
// site/deploy/stats-agents.sh classifies a fixture log; integrations/mcp/server.json agrees with
// its package.json. Prints `ok …` lines, then `ALL PASS (<n> checks)` and exits 0, or `FAIL …`
// lines and exits 1.
import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync, readdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync, spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname, extname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE = dirname(dirname(fileURLToPath(import.meta.url)));
const ROOT = dirname(SITE);
const DIST = join(SITE, 'dist');
const ORIGIN = 'https://sigelo.io';
if (!existsSync(join(DIST, 'index.html'))) { console.error('FAIL no site/dist/index.html: run node site/build.mjs first'); process.exit(1); }
// The tables the build renders from (importing it builds nothing): the official names and the page list.
const { DOMAINS, HOSTS, CONTENT_HOSTS, REPOSITORIES, PAGES: PAGE_LIST, REPO, RELAY_LIVE, OFFICIAL, BEFORE_LAUNCH, PAYMENT_PLACES, VALUE_SOURCES, securityDomainsLine, packagesAt, RELEASED } = await import('../build.mjs');
const git = (...a) => execFileSync('git', ['-C', ROOT, ...a], { encoding: 'utf8' }).trim();

let n = 0; const fails = [];
const ok = (cond, what) => { n++; if (cond) console.log(`ok ${what}`); else { fails.push(what); console.log(`FAIL ${what}`); } };
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

// The content types below are the contract; site/deploy/nginx.conf (and apache.conf) must send the same.
const TYPES = { '.html': 'text/html; charset=utf-8', '.md': 'text/markdown; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
  '.json': 'application/json', '.xml': 'application/xml', '.css': 'text/css; charset=utf-8', '.yaml': 'application/yaml',
  '.mjs': 'text/javascript; charset=utf-8', '.png': 'image/png' };
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
const idsOf = new Map(); const linksOf = new Map(); const titles = []; const descs = [];
const graphOf = new Map();
for (const f of htmlFiles) {
  const html = readFileSync(join(DIST, f), 'utf8');
  const { errors, tags, scripts } = readHtml(html);
  // The not-found page: no canonical, no JSON-LD, no Open Graph, noindex.
  const notFound = f === '/404.html';
  ok(errors.length === 0, `${f}: tags balance${errors.length ? ` (${errors.slice(0, 3).join('; ')})` : ''}`);
  idsOf.set(f, new Set(tags.filter((t) => t.attrs.id).map((t) => t.attrs.id)));
  linksOf.set(f, tags.filter((t) => t.tag === 'a' && t.attrs.href).map((t) => unesc(t.attrs.href)));
  const twin = f.replace(/\.html$/, '.md');
  ok(files.includes(twin), `${f}: Markdown twin ${twin} exists`);
  ok(tags.some((t) => t.tag === 'link' && t.attrs.rel === 'alternate' && t.attrs.type === 'text/markdown' && t.attrs.href === twin), `${f}: <link rel=alternate type=text/markdown href=${twin}>`);
  // Search engines cut titles near 60 characters and descriptions near 155.
  const title = unesc(html.match(/<title>([^<]*)<\/title>/)?.[1] ?? '');
  ok(title && [...title].length <= 60 && title.split(' — ').length <= 2, `${f}: title ≤ 60 characters, at most one " — " (${[...title].length}: ${title})`);
  const desc = tags.find((t) => t.tag === 'meta' && t.attrs.name === 'description');
  const d = unesc(desc?.attrs.content ?? '');
  ok(d.length >= 50 && d.length <= 155, `${f}: meta description 50 to 155 characters (${d.length})`);
  titles.push(title); descs.push(d);
  const canon = tags.find((t) => t.tag === 'link' && t.attrs.rel === 'canonical');
  const robots = tags.find((t) => t.tag === 'meta' && t.attrs.name === 'robots');
  if (notFound) ok(!canon && robots?.attrs.content === 'noindex', `${f}: noindex and no canonical`);
  else ok(canon && canon.attrs.href === (f === '/index.html' ? `${ORIGIN}/` : `${ORIGIN}${f}`) && !robots, `${f}: canonical ${canon?.attrs.href}, no robots meta`);
  ok(tags.some((t) => t.tag === 'link' && t.attrs.rel === 'icon' && t.attrs.href === '/icon-512.png'), `${f}: <link rel=icon href=/icon-512.png>`);
  const og = Object.fromEntries(tags.filter((t) => t.tag === 'meta' && t.attrs.property?.startsWith('og:')).map((t) => [t.attrs.property, unesc(t.attrs.content)]));
  const card = tags.find((t) => t.tag === 'meta' && t.attrs.name === 'twitter:card')?.attrs.content;
  if (notFound) ok(Object.keys(og).length === 0 && !card, `${f}: no Open Graph or Twitter tags`);
  else ok(og['og:url'] === canon?.attrs.href && og['og:title'] && title.startsWith(og['og:title']) && og['og:description'] === d && og['og:type'] === 'website' && og['og:site_name'] === 'sigelo' && card === 'summary',
    `${f}: Open Graph (title, description, url = canonical, type, site_name) and twitter:card summary`);
  ok(tags.filter((t) => t.tag === 'h1').length === 1, `${f}: exactly one <h1>`);
  const ld = scripts.filter((s) => /type="application\/ld\+json"/.test(s.attrs));
  ok(scripts.length === ld.length, `${f}: no executable <script> (only JSON-LD)`);
  if (notFound) ok(ld.length === 0, `${f}: no JSON-LD`);
  else {
    let graph = null; try { graph = JSON.parse(ld[0]?.body ?? ''); } catch { /* reported below */ }
    graphOf.set(f, graph);
    const types = (graph?.['@graph'] ?? []).map((g) => g['@type']);
    ok(graph?.['@context'] === 'https://schema.org' && types.includes('SoftwareSourceCode'), `${f}: JSON-LD parses, schema.org, SoftwareSourceCode present (${types.join(', ')})`);
    const sw = graph?.['@graph']?.find((g) => g['@type'] === 'SoftwareSourceCode');
    ok(sw && sw.codeRepository && sw.programmingLanguage?.length && sw.license, `${f}: SoftwareSourceCode has codeRepository, programmingLanguage, license`);
    ok(sw?.sameAs === sw?.codeRepository, `${f}: SoftwareSourceCode sameAs = codeRepository`);
    // The headline is the page's title as written (no lowercasing, no prefix).
    const art = graph?.['@graph']?.find((g) => g['@type'] === 'TechArticle');
    if (art) ok(art.headline === title.replace(/ — sigelo$/, '') && !Number.isNaN(Date.parse(art.dateModified)), `${f}: TechArticle headline = the title as written (${art.headline}), dateModified`);
  }
  const external = tags.filter((t) => (t.tag === 'link' && t.attrs.rel !== 'canonical' && /^https?:/.test(t.attrs.href)) || (/^(img|script|iframe|source|video|audio)$/.test(t.tag) && t.attrs.src));
  ok(external.length === 0, `${f}: loads nothing from another origin or by src=`);
  ok(!/\sstyle=|<style\b|\son[a-z]+=/i.test(html), `${f}: no inline style or event handler (CSP default-src 'self')`);
}
ok(new Set(titles).size === titles.length && new Set(descs).size === descs.length, `every page has its own title and description (${titles.length} pages)`);
{
  const r = await get('/icon-512.png');
  ok(r.status === 200 && r.type === 'image/png' && r.body.subarray(1, 4).toString() === 'PNG', '/icon-512.png: 200, image/png, a PNG');
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
  // From the relay launch (RELAY_LIVE) one link leaves the site: the relay's own llms.txt, not fetched here.
  const urls = items.map((l) => l.match(/\]\(([^)]+)\)/)[1]);
  const off = urls.filter((u) => !u.startsWith(ORIGIN));
  ok(off.join() === (RELAY_LIVE ? 'https://sigelo.ai/llms.txt' : ''), `llms.txt: ${RELAY_LIVE ? 'exactly one link' : 'no link'} off ${ORIGIN}${RELAY_LIVE ? ', the relay\'s llms.txt' : ' before the relay launch'} (${off.join(' ') || 'none'})`);
  const bad = [];
  for (const u of urls) if (u.startsWith(ORIGIN) && !MIRRORED(local(u)) && await status(local(u)) !== 200) bad.push(u);
  ok(bad.length === 0, `llms.txt: all ${urls.length - off.length} links on ${ORIGIN} resolve${bad.length ? ` (${bad.join(' ')})` : ''}`);
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
// characters, and nowhere a story, a feedback quote or a first person.
//
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
  const PAGES = ['404', 'accept', 'adopt', 'changelog', 'contact', 'frameworks', 'index', 'keeper', 'privacy', 'security', 'spec', 'verify'];
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
  const BUDGET = { '/index.md': 120, '/adopt.md': 250, '/accept.md': 200, '/verify.md': 150, '/keeper.md': 200, '/contact.md': 80, '/privacy.md': 150, '/404.md': 40 };
  for (const [f, max] of Object.entries(BUDGET)) {
    const w = words(readFileSync(join(DIST, f), 'utf8'));
    ok(w <= max, `budget: ${f} ${w} words ≤ ${max}`);
  }
  // /frameworks: 450 words of prose plus its one table (one row a framework, at most 40 rows).
  const fw = readFileSync(join(DIST, 'frameworks.md'), 'utf8').split('\n'), rowsOf = fw.filter((l) => /^\|/.test(l)).length - 2;
  const fwWords = words(fw.filter((l) => !/^\|/.test(l)).join('\n'));
  ok(fwWords <= 450 && rowsOf > 0 && rowsOf <= 40, `budget: /frameworks.md ${fwWords} words ≤ 450 outside its table, ${rowsOf} rows ≤ 40`);
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
  const indexable = PAGE_LIST.filter((p) => !p.noindex);
  const pageLoc = (p) => (p.slug === 'index' ? `${ORIGIN}/` : `${ORIGIN}/${p.slug}.html`);
  ok(indexable.every((p) => locs.includes(pageLoc(p))) && badLocs.length === 0, `sitemap.xml: ${locs.length} URLs, every indexable page, all on ${ORIGIN}, all resolve`);
  // No twin (each names its HTML page as canonical) and no not-found page in the sitemap.
  ok(!locs.some((l) => l.endsWith('.md') || /\/404(\.html)?$/.test(l)), 'sitemap.xml: no .md twin, no not-found page');
  // lastmod: a page's is the last commit of what it is rendered from, never the build date (Google
  // uses it only when accurate): its source plus the inputs of each template value it uses
  // (site/build.mjs VALUE_SOURCES). / and /contact render the official names, so a change to
  // site/src/official.mjs moves theirs. The generated files' are a date no later than the build commit.
  const lastmod = Object.fromEntries([...x.matchAll(/<url><loc>([^<]+)<\/loc>(?:<lastmod>([^<]+)<\/lastmod>)?<\/url>/g)].map((m) => [m[1], m[2]]));
  const head = git('log', '-1', '--format=%cI', 'HEAD').slice(0, 10);
  const keysIn = (src) => [...new Set([...readFileSync(join(ROOT, src), 'utf8').matchAll(/\{\{([\w.:/-]+)\}\}/g)].map((m) => m[1]))];
  const unmapped = PAGE_LIST.filter((p) => p.src).flatMap((p) => keysIn(p.src).filter((k) => !VALUE_SOURCES[k]).map((k) => `${p.slug} {{${k}}}`));
  const inputs = (p) => (p.repo ? [p.repo] : [p.src, ...new Set(keysIn(p.src).flatMap((k) => VALUE_SOURCES[k] ?? []))]);
  ok(unmapped.length === 0 && ['index', 'contact'].every((s) => inputs(PAGE_LIST.find((p) => p.slug === s)).includes('site/src/official.mjs')),
    `sitemap.xml: every template value a page uses has its inputs (VALUE_SOURCES); / and /contact count site/src/official.mjs${unmapped.length ? ` (unmapped: ${unmapped.join(', ')})` : ''}`);
  const wrong = indexable.filter((p) => lastmod[pageLoc(p)] !== (git('log', '-1', '--format=%cI', '--', ...inputs(p)).slice(0, 10) || undefined)).map((p) => p.slug);
  ok(wrong.length === 0, `sitemap.xml: each page's lastmod = the last commit of its source and its values' inputs${wrong.length ? ` (wrong: ${wrong.join(', ')})` : ''}`);
  const gen = locs.filter((l) => !indexable.some((p) => pageLoc(p) === l));
  ok(gen.every((l) => /^\d{4}-\d\d-\d\d$/.test(lastmod[l] ?? '') && lastmod[l] <= head), `sitemap.xml: ${gen.length} generated files with a lastmod no later than the build commit (${head})`);
  // A generated file is no older than what it is made of: llms-full.txt than each of its parts'
  // pages (their lastmods checked against git above), llms.txt than llms-full.txt (it states its
  // size) and than site/src/official.mjs (the relay line from the launch).
  const PARTS = ['spec', 'adopt', 'verify', 'keeper', 'security'];
  const notOlder = (lm) => {
    const bad = PARTS.filter((s) => !(lm[`${ORIGIN}/llms-full.txt`] >= lm[pageLoc(PAGE_LIST.find((p) => p.slug === s))])).map((s) => `llms-full.txt < ${s}`);
    if (!(lm[`${ORIGIN}/llms.txt`] >= lm[`${ORIGIN}/llms-full.txt`])) bad.push('llms.txt < llms-full.txt');
    if (!(lm[`${ORIGIN}/llms.txt`] >= git('log', '-1', '--format=%cI', '--', 'site/src/official.mjs').slice(0, 10))) bad.push('llms.txt < site/src/official.mjs');
    return bad;
  };
  const stale = { ...lastmod, [`${ORIGIN}/llms-full.txt`]: '2000-01-01' };
  ok(notOlder(lastmod).length === 0 && notOlder(stale).includes('llms-full.txt < adopt') && notOlder(stale).length > 1 && notOlder({ ...lastmod, [`${ORIGIN}/llms.txt`]: '2000-01-01' }).includes('llms.txt < site/src/official.mjs'),
    `sitemap.xml: llms-full.txt's lastmod is no older than its parts' pages, llms.txt's than llms-full.txt and site/src/official.mjs (a stale copy is refused)${notOlder(lastmod).length ? ` (${notOlder(lastmod).join(', ')})` : ''}`);
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
  // The official names: index.json `official`, SECURITY.md "Official channels", one line on / and
  // /contact, all following site/src/official.mjs OFFICIAL: DOMAINS from the relay launch
  // (RELAY_LIVE), BEFORE_LAUNCH until then. Both tables are pinned here to the decided roles
  // (site/src/official.mjs):
  // changing a role is a decision, not a refactor.
  const role = (d) => (d.role === 'redirect' ? `redirect ${d.to}${d.live ? '' : ' (DNS pending)'}` : d.role === 'content' ? `content: ${d.what}` : d.role);
  const tableOf = (domains) => domains.map((d) => `${d.name} ${role(d)}`).join('; ');
  ok(tableOf(DOMAINS) === 'sigelo.io content: protocol; sigelo.ai content: relay and front page; sigelo.net redirect sigelo.ai; sigelo.online redirect sigelo.ai (DNS pending); sigelo.dev redirect sigelo.io (DNS pending); sigelo.org parked'
    && HOSTS.map((h) => h.name).join() === 'relay.sigelo.ai' && REPOSITORIES.join() === 'https://github.com/csigelo/sigelo,https://github.com/csigelo/sigelo-relay',
    `site/src/official.mjs DOMAINS is the decided table, stated from the relay launch (${tableOf(DOMAINS)})`);
  ok(tableOf(BEFORE_LAUNCH.domains) === 'sigelo.io content: protocol; sigelo.ai parked; sigelo.net redirect sigelo.io; sigelo.online redirect sigelo.io (DNS pending); sigelo.dev redirect sigelo.io (DNS pending); sigelo.org parked'
    && BEFORE_LAUNCH.domains.map((d) => d.name).join() === DOMAINS.map((d) => d.name).join()
    && BEFORE_LAUNCH.hosts.length === 0 && BEFORE_LAUNCH.repositories.join() === REPO && BEFORE_LAUNCH.payment_places.length === 0,
    `site/src/official.mjs BEFORE_LAUNCH: the same domains, sigelo.ai parked, every redirect to sigelo.io, one repository, no payment place (${tableOf(BEFORE_LAUNCH.domains)})`);
  ok(typeof RELAY_LIVE === 'boolean' && OFFICIAL.domains === (RELAY_LIVE ? DOMAINS : BEFORE_LAUNCH.domains) && OFFICIAL.hosts === (RELAY_LIVE ? HOSTS : BEFORE_LAUNCH.hosts)
    && OFFICIAL.repositories === (RELAY_LIVE ? REPOSITORIES : BEFORE_LAUNCH.repositories) && OFFICIAL.payment_places === (RELAY_LIVE ? PAYMENT_PLACES : BEFORE_LAUNCH.payment_places),
    `site/src/official.mjs OFFICIAL is ${RELAY_LIVE ? 'DOMAINS (RELAY_LIVE)' : 'BEFORE_LAUNCH (RELAY_LIVE false)'}`);
  // Payment details: the exact file, never the relay repository as a whole (anyone can put text
  // under its URL: an issue, a pull request, a fork's commit viewed through it).
  ok(PAYMENT_PLACES.join() === 'https://sigelo.ai/contact.html,https://github.com/csigelo/sigelo-relay/blob/main/site/contact.md',
    'site/src/official.mjs PAYMENT_PLACES: sigelo.ai\'s contact page (by invoice) and its file on the relay repository\'s default branch, not the repository');
  const domains = OFFICIAL.domains;
  const redirects = (live) => Object.fromEntries(domains.filter((d) => d.role === 'redirect' && !!d.live === live).map((d) => [d.name, `https://${d.to}/`]));
  const of = ix.official ?? {};
  ok(of.issuer_did && of.issuer_did === ix.world?.issuer && of.domains?.join() === domains.map((d) => d.name).join() && of.content?.join() === CONTENT_HOSTS.join()
    && JSON.stringify(of.redirects) === JSON.stringify(redirects(true)) && JSON.stringify(of.redirects_pending_dns) === JSON.stringify(redirects(false))
    && of.parked?.join() === domains.filter((d) => d.role === 'parked').map((d) => d.name).join()
    && of.repositories?.join() === OFFICIAL.repositories.join() && of.repository === REPO && JSON.stringify(of.payment_details_only_on) === JSON.stringify(OFFICIAL.payment_places)
    && of.npm_user === 'csigelo' && of.maintainer === 'csigelo' && of.packages?.join() === packagesAt(RELEASED).join() && of.releases?.includes(`${ORIGIN}/releases/`),
    `index.json: official follows OFFICIAL (domains, content, redirects, pending, parked, repositories, payment places), issuer_did = world.issuer, npm_user, the ${of.packages?.length} packages of v${RELEASED} (sigelo-contact from 0.1.2, which SECURITY.md must then name: below), maintainer`);
  // SECURITY.md's "Nobody from the project…" line, as data: a payment address comes only with an
  // invoice the buyer asked for, over the SimpleX address on /contact (sigelo.ai's index.json has the
  // same two fields; relay/site/build.mjs --launch refuses the older ones).
  const secText = readFileSync(join(ROOT, 'SECURITY.md'), 'utf8');
  ok(of.payment_address_only_with === 'an invoice the buyer asked for' && of.invoice_only_via === `${ORIGIN}/contact.html`
    && !('never_sends_by_email_or_chat' in of) && !('payment_proof_only_via' in of) && !('payment_address_or_link_only_with' in of)
    && secText.includes(`- Nobody from the project will ever ask for a seed, an identity or wallet private key, or a token. A payment address comes only with an invoice you asked for, in the SimpleX conversation you opened with the address on \`${ORIGIN}/contact.html\`.`),
    'index.json: official.payment_address_only_with and invoice_only_via say what SECURITY.md\'s "Nobody…" line says, no older field');
  // redirect_only keeps its first meaning for the readers that take content = domains minus
  // redirect_only: every held domain that serves nothing of its own, parked ones included.
  const contentDomains = domains.filter((d) => d.role === 'content').map((d) => d.name);
  ok(of.redirect_only?.join() === domains.filter((d) => d.role !== 'content').map((d) => d.name).join()
    && of.domains?.filter((d) => !of.redirect_only.includes(d)).join() === contentDomains.join(),
    `index.json: official.redirect_only is every domain but the content ones, so domains minus redirect_only = ${contentDomains.join(', ')} (got ${of.redirect_only?.join(', ')})`);
  if (RELAY_LIVE) ok(ix.relay?.homepage === 'https://sigelo.ai/' && ix.relay.llms_txt === 'https://sigelo.ai/llms.txt' && ix.relay.index === 'https://sigelo.ai/index.json' && ix.relay.host === 'relay.sigelo.ai',
    'index.json: relay (homepage https://sigelo.ai/, its llms.txt and index.json, host relay.sigelo.ai)');
  else ok(!('relay' in ix) && !JSON.stringify(ix).includes('https://sigelo.ai'), 'index.json: no relay block and no https://sigelo.ai URL before the relay launch');
  // What every text that states a domain's role must say, word for word (backticks aside). The
  // parked domains may share one clause ("a and b are ours and parked").
  // `missing` and `pendingSaid` take the table as an argument: the launch table is checked too.
  const rolesOf = (off) => [...off.domains.filter((d) => d.role === 'content').map((d) => `${d.name} (${d.what}`), ...off.hosts.map((h) => h.name),
    ...off.domains.filter((d) => d.role === 'redirect' && d.live).map((d) => `${d.name} redirects to ${d.to}`),
    ...off.domains.filter((d) => d.role === 'redirect' && !d.live).map((d) => `${d.name} (to ${d.to})`)];
  const pendingSaid = (t, off = OFFICIAL) => off.domains.every((d) => d.role !== 'redirect' || d.live) || /redirects? once (its|their) DNS points to us/.test(t);
  const missing = (t, off = OFFICIAL) => [...rolesOf(off).filter((r) => !t.includes(r)),
    ...off.domains.filter((d) => d.role === 'parked').map((d) => d.name)
      .filter((x) => !t.split(/; |\. /).some((c) => c.includes(x) && /\bours and parked\b/.test(c))).map((x) => `${x} … ours and parked`)];
  // Wrong once the relay site exists: sigelo.ai serves, and two repositories are ours.
  const STALE = /only redirect|serves? nothing|the only one/;
  const sec = readFileSync(join(ROOT, 'SECURITY.md'), 'utf8');
  const part = (h) => sec.split(/^## /m).find((x) => x.startsWith(`${h}\n`)) ?? '';
  const section = part('Official channels').replace(/^Official channels\n/, '');
  const domainsLine = section.split('\n').find((l) => l.startsWith('- Domains:'))?.replace(/`/g, '') ?? '';
  ok(section && section.trim().split('\n').length <= 11 && [of.issuer_did, ...OFFICIAL.repositories, `${ORIGIN}/releases/`, ...domains.map((d) => `\`${d.name}\``), ...OFFICIAL.hosts.map((h) => `\`${h.name}\``), 'security@sigelo.io', ...(of.packages ?? [])].every((x) => x && section.includes(x)),
    `SECURITY.md: "## Official channels" (${section.trim().split('\n').length + 1} lines ≤ 12) names the issuer DID, the repositories, mirror, every domain and host, packages, security@`);
  ok(missing(domainsLine).length === 0 && pendingSaid(domainsLine) && !STALE.test(section), `SECURITY.md: the Domains line gives every domain its OFFICIAL role${missing(domainsLine).length ? ` (missing: ${missing(domainsLine).join(' | ')})` : ''}`);
  // The line is written by hand (the launch flip too), so it must be exactly the generated one:
  // containing every right role is not enough, a second, contradicting role must fail as well.
  const wantLine = securityDomainsLine(OFFICIAL);
  ok(domainsLine === wantLine, `SECURITY.md: the Domains line is exactly site/build.mjs securityDomainsLine(OFFICIAL), backticks aside${domainsLine === wantLine ? '' : ` (want: ${wantLine})`}`);
  const launch = { domains: DOMAINS, hosts: HOSTS, repositories: REPOSITORIES };
  const launchLine = securityDomainsLine(launch);
  const extra = [wantLine.replace('; ', '; sigelo.org redirects to sigelo.io; '), wantLine.replace('; ', '; sigelo.dev redirects to sigelo.io now; '),
    wantLine.replace(' (protocol)', ' (protocol), sigelo.ai (relay)'), wantLine.replace(/\. Repositor/, '; sigelo.net redirects to sigelo.ai. Repositor')];
  ok(missing(launchLine, launch).length === 0 && pendingSaid(launchLine, launch) && !STALE.test(launchLine) && OFFICIAL.repositories.every((r) => wantLine.includes(r))
    && launch.repositories.every((r) => launchLine.includes(r)) && extra.every((x) => x !== wantLine && missing(x).length === 0),
    `SECURITY.md Domains line generator: the launch line gives every DOMAINS role and both repositories; a line with a second role added (${extra.length} cases, each passing the role check) is refused`);
  // Which repository's Releases page: named, not "that repository's" (there may be two). And what
  // anyone can write under a repository's URL is not ours.
  ok(section.includes(`- Releases: only \`${REPO}/releases\` and \`${ORIGIN}/releases/\``) && domainsLine.includes('issues, pull requests, comments or forks is not official'),
    `SECURITY.md: Releases names ${REPO}/releases and ${ORIGIN}/releases/; issues, pull requests, comments and forks are not official`);
  // The relay's own lines go in with the launch: its repository's reporting channel, the relay in
  // Scope, relay.sigelo.ai in Safe harbour. Before it SECURITY.md names neither (a 404 channel, a
  // host that refuses connections).
  if (RELAY_LIVE) ok(part('Reporting').includes('csigelo/sigelo-relay') && /\bthe relay\b/.test(part('Scope')) && part('Safe harbour').includes('relay.sigelo.ai'),
    'SECURITY.md: the relay repository\'s reporting channel, the relay in Scope, relay.sigelo.ai in Safe harbour');
  else ok(!/sigelo-relay|relay\.sigelo\.ai/.test(sec), 'SECURITY.md: names neither csigelo/sigelo-relay nor relay.sigelo.ai before the relay launch');
  ok(idsOf.get('/security.html')?.has('official-channels'), '/security.html: #official-channels anchor');
  const bare = (u) => u.replace(/^https:\/\//, '');
  const lineOf = (p) => readFileSync(join(DIST, p), 'utf8').split('\n').find((l) => l.includes('anything else is not us')) ?? '';
  for (const p of ['/index.md', '/contact.md']) {
    const t = lineOf(p);
    ok(t.includes(of.issuer_did?.slice(0, 17)) && [...CONTENT_HOSTS, ...OFFICIAL.repositories.map(bare)].every((x) => t.includes(x)) && !STALE.test(t),
      `${p}: the one "Official: … anything else is not us" line names every content host, the repositories and the issuer`);
  }
  const cl = lineOf('/contact.md');
  ok(domains.every((d) => cl.includes(d.name)) && missing(cl).length === 0 && pendingSaid(cl) && cl.split(/[.!?] /).length === 1,
    `/contact.md: the "Official" line gives all ${domains.length} domains their roles, one sentence${missing(cl).length ? ` (missing: ${missing(cl).join(' | ')})` : ''}`);
}

// ---- the links to the relay, the motto, words never written -------------------------------------
{
  const md = (p) => readFileSync(join(DIST, p), 'utf8');
  const home = graphOf.get('/index.html')?.['@graph']?.find((g) => g['@type'] === 'WebPage');
  const texts = files.filter((f) => /\.(html|md|txt|json)$/.test(f) && !f.startsWith('/raw/') && !f.startsWith('/sha256/'));
  if (RELAY_LIVE) {
    ok(md('/index.md').includes('[Relay: encrypted messages between AI agents](https://sigelo.ai/)') && md('/adopt.md').includes('[Message other agents: sigelo relay](https://sigelo.ai/)')
      && md('/contact.md').includes('[sigelo.ai](https://sigelo.ai/)'), '/, /adopt and /contact link https://sigelo.ai/ with their anchors');
    ok(home?.relatedLink?.includes('https://sigelo.ai/'), '/: JSON-LD WebPage relatedLink https://sigelo.ai/');
  } else {
    // Before the relay launch nothing links to sigelo.ai: it refuses connections, and an unreachable
    // robots.txt reads as "disallow all", so no link goes there before its robots.txt answers 200.
    const linking = texts.filter((f) => /https:\/\/(www\.|relay\.)?sigelo\.ai\b/.test(md(f)));
    ok(linking.length === 0 && !home?.relatedLink && !/\{\{relay_/.test(md('/index.md') + md('/adopt.md') + md('/contact.md')),
      `no file links or names a URL on sigelo.ai before the relay launch, no JSON-LD relatedLink${linking.length ? ` (in: ${linking.join(' ')})` : ''}`);
  }
  // The motto belongs to sigelo.ai; sigelo.io keeps only the disclosure line.
  const motto = texts.filter((f) => /By AI, for AI/i.test(readFileSync(join(DIST, f), 'utf8')));
  ok(motto.length === 0 && /^Built and operated by an AI agent .* under a human owner, `csigelo`\./m.test(md('/index.md')),
    `no sigelo.io file carries the motto; / keeps the disclosure line${motto.length ? ` (motto in: ${motto.join(' ')})` : ''}`);
  // Words never written: untrue of sigelo, or someone else's product. Over every page as HTML
  // (title, meta description, Open Graph, JSON-LD: what search snippets show) and as Markdown, the
  // repository documents (/spec, /security, /changelog) included, llms.txt, llms-full.txt and the
  // whole of index.json. One exception, by its exact text: CHANGELOG.md's record of the Hermes
  // adapter's upstream A2A hook proposal (history about another project's protocol, not a claim
  // about sigelo), in /changelog.md and /changelog.html. It must still be there in both, so a
  // stale exception is noticed.
  const NEVER = /\bA2A\b|MQTT 5|quantum-(safe|proof|resistant)|forward secrecy|Signal-grade|agent (inbox|mailbox|passport)|verifiable credentials|\bweb3\b|blockchain|trustless|decentralized messaging|free forever|unlimited|real-time/i;
  const EXCEPT = 'upstream A2A authenticator hook proposal drafted';
  const EXCEPT_IN = ['/changelog.md', '/changelog.html'];
  const scanned = [...PAGE_LIST.flatMap((p) => [`/${p.slug}.html`, `/${p.slug}.md`]), '/llms.txt', '/llms-full.txt', '/index.json'];
  const neverHits = (read) => scanned.filter((f) => {
    const t = f.endsWith('.html') ? unesc(read(f)) : read(f);
    return NEVER.test(EXCEPT_IN.includes(f) ? t.split(EXCEPT).join('') : t);
  });
  const hits = neverHits(md);
  ok(['/spec.html', '/security.md', '/changelog.html'].every((f) => scanned.includes(f)) && EXCEPT_IN.every((f) => md(f).includes(EXCEPT)) && hits.length === 0,
    `every page as HTML and Markdown (${PAGE_LIST.length} pages, repository documents included), llms.txt, llms-full.txt and all of index.json write none of the never-write terms${hits.length ? ` (in: ${hits.join(' ')})` : ''}`);
  // The checker against the copies that passed before: a term in a front-matter description or
  // title (only the HTML carries them), in a repository page's PAGES title, in index.json outside
  // its description.
  const edited = (file, edit) => (f) => (f === file ? edit(md(f)) : md(f));
  const planted = [
    ['/keeper.html', edited('/keeper.html', (t) => t.replace('<meta name="description" content="', '<meta name="description" content="A2A '))],
    ['/verify.html', edited('/verify.html', (t) => t.replace('<title>', '<title>A2A '))],
    ['/spec.html', edited('/spec.html', (t) => t.replace('<title>Specification', '<title>Blockchain specification'))],
    ['/index.json', edited('/index.json', (t) => t.replace('"official": {', '"official": {"x": "unlimited real-time",'))],
  ];
  ok(planted.every(([f, read]) => read(f) !== md(f) && neverHits(read).join() === f),
    `never-write checker: refuses a term planted in a meta description, a page title, a repository page's title, index.json's official block (${planted.map(([f]) => f).join(' ')})`);
}

// ---- site/deploy/nginx.conf follows OFFICIAL and the content types above --------------------------
{
  // → [why …], each server block on its own: a count over the whole file let one block's HSTS stand
  // in for another's, and a "contains the right return" test passed a block whose first return
  // (the one nginx runs) went elsewhere.
  const HSTS = 'add_header Strict-Transport-Security "max-age=31536000" always;';
  const LINK = `add_header Link '</llms.txt>; rel="describedby"; type="text/plain"' always;`;
  const nginxRefusals = (conf) => {
    const bad = [];
    // Top-level server blocks: "server {" and "}" at column 0 (the helper's house style).
    const servers = conf.split(/^server \{$/m).slice(1).map((b) => b.slice(0, b.search(/^\}$/m)));
    // Every server_name line of a block: nginx adds them all up.
    const names = (b) => [...b.matchAll(/^\s*server_name ([^;]+);/gm)].flatMap((m) => m[1].trim().split(/\s+/));
    const returns = (b) => (b.match(/^\s*return [^;]*;/gm) ?? []).map((l) => l.trim());
    const tls = (b) => /^\s*listen 443 ssl/m.test(b) && !/ssl_reject_handshake on;/.test(b);
    // Plain names only: a regex (~…) or wildcard (*) server_name would let one block answer for a
    // name the exact comparisons below never see.
    servers.forEach((b, i) => {
      const odd = names(b).filter((x) => !/^([a-z0-9-]+\.)+[a-z]+$/.test(x) && x !== '_');
      if (odd.length) bad.push(`server ${i + 1}: server_name ${odd.join(' ')} is not a plain host name`);
    });
    // A redirect block holds these lines and nothing else: a rewrite, an if, a try_files or another
    // location would run before (or instead of) its one return, on every path or on some.
    const REDIRECT_LINES = [/^listen (80|\[::\]:80|443 ssl http2|\[::\]:443 ssl http2);$/, /^server_name [^;]+;$/, /^server_tokens off;$/,
      /^access_log [^;]+;$/, /^error_log [^;]+;$/, /^ssl_[a-z_]+ [^;]+;$/, /^add_header Strict-Transport-Security [^;]+;$/, /^return [^;]+;$/,
      /^location \^~ \/\.well-known\/acme-challenge\/ \{$/, /^root \/var\/www\/acme;$/, /^default_type text\/plain;$/, /^location \/ \{$/, /^\}$/];
    for (const d of OFFICIAL.domains.filter((x) => x.role === 'redirect')) {
      const blocks = servers.filter((b) => names(b).includes(d.name) || names(b).includes(`www.${d.name}`));
      const want = `return 301 https://${d.to}$request_uri;`;
      if (blocks.length !== 2 || blocks.filter(tls).length !== 1 || !blocks.some((b) => /^\s*listen 80;$/m.test(b))) bad.push(`${d.name}: not one port-80 and one TLS server block (${blocks.length} blocks)`);
      for (const b of blocks) {
        if (names(b).join(' ') !== `${d.name} www.${d.name}`) bad.push(`${d.name}: server_name ${names(b).join(' ')}`);
        if (returns(b).join(' | ') !== want) bad.push(`${d.name}: returns "${returns(b).join(' | ') || 'nothing'}", not exactly one "${want}"`);
        const other = b.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#') && !REDIRECT_LINES.some((re) => re.test(l)));
        if (other.length) bad.push(`${d.name}: a redirect block holds "${other.join(' | ')}"`);
        // Port 80 returns from `location /` (the ACME location answers the challenge); TLS at server level.
        const placed = tls(b) ? /^ {4}return /m.test(b) && !/^\s*location /m.test(b) : b.includes(`\n    location / {\n        ${want}\n    }\n`);
        if (!placed) bad.push(`${d.name}: the ${tls(b) ? 'TLS' : 'port-80'} block's return is not where it must be (${tls(b) ? 'server level, no location' : 'alone in location /'})`);
      }
    }
    for (const x of OFFICIAL.domains.filter((y) => y.role === 'parked' || (y.role === 'content' && y.name !== 'sigelo.io')).map((y) => y.name)) {
      if (servers.some((b) => names(b).includes(x) || names(b).includes(`www.${x}`))) bad.push(`${x} has a server block`);
    }
    servers.forEach((b, i) => {
      const sts = b.split('\n').filter((l) => /Strict-Transport-Security/i.test(l)).map((l) => l.trim());
      if (tls(b) ? sts.join(' | ') !== HSTS : sts.length) bad.push(`server ${i + 1} (${names(b).join(' ')}): HSTS "${sts.join(' | ') || 'missing'}"${tls(b) ? `, not exactly one "${HSTS}"` : ' on a server without TLS'}`);
    });
    const typesBlock = conf.match(/^ {4}types \{\n([\s\S]*?)^ {4}\}/m)?.[1] ?? '';
    const missingTypes = Object.entries(TYPES).filter(([ext, t]) => !typesBlock.includes(`${t.split(';')[0]} ${ext.slice(1)};`));
    if (missingTypes.length) bad.push(`types block lacks ${missingTypes.map(([e]) => e).join(' ')}`);
    // The describedby Link goes on every response, a 404 too: `always`.
    if (!conf.includes(LINK)) bad.push(`no "${LINK}"`);
    // The header maps key on $uri, the decoded, normalised path the locations matched: keyed on the
    // raw $request_uri, /%34%30%34.md or //_stats/ reach the same file without its headers.
    // $sigelo_stats tells the stats report's root apart, whose rewrite makes $uri /index.html.
    const map = (v) => conf.match(new RegExp(`^map ("[^"]*"|\\S+) \\$${v} \\{\\n([\\s\\S]*?)^\\}$`, 'm'));
    for (const [v, needs] of [['sigelo_cache', ['$uri', '$sigelo_stats']], ['sigelo_robots', ['$uri', '$sigelo_stats']], ['sigelo_link', ['$uri', '$sigelo_stats']], ['sigelo_csp', ['$sigelo_stats']]]) {
      const src = map(v)?.[1] ?? '';
      if (src.includes('$request_uri') || !needs.every((x) => src.includes(x))) bad.push(`map $${v} keyed on ${src || 'nothing'}, not ${needs.join(' and ')}`);
    }
    if (map('sigelo_stats')?.[1] !== '$document_root' || !map('sigelo_stats')[2].includes('    "/var/www/sigelo.io/stats" "stats:";\n')
      || !/^ {4}location \^~ \/_stats\/ \{\n(?: {8}.*\n)*? {8}root \/var\/www\/sigelo\.io\/stats;$/m.test(conf)) bad.push('$sigelo_stats does not name the root of location ^~ /_stats/');
    if (!(map('sigelo_cache')?.[2] ?? '').includes('    "~^404 " "public, max-age=60";\n')) bad.push('404s not cached a minute');
    if (!(map('sigelo_robots')?.[2] ?? '').includes('    "~^/404(\\.html|\\.md)?$" "noindex";\n')) bad.push('the not-found page not noindex');
    return bad;
  };
  const conf = readFileSync(join(SITE, 'deploy', 'nginx.conf'), 'utf8');
  const bad = nginxRefusals(conf);
  ok(bad.length === 0, `nginx.conf: plain server names; each redirect domain has one port-80 and one TLS block, each with exactly one return, to its OFFICIAL target, and nothing else that could run first; no block for sigelo.ai or a parked domain; exactly one HSTS line of a year in every TLS block, none elsewhere; every content type; Link rel=describedby always; header maps keyed on $uri; 404s cached a minute; the not-found page noindex${bad.length ? ` (${bad.join('; ')})` : ''}`);
  // The checker against broken copies (each must be refused, by name).
  const parts = conf.split(/^(?=server \{$)/m);
  const block = (name, isTls) => parts.findIndex((x) => x.startsWith('server {') && x.includes(`server_name ${name}`) && /listen 443 ssl/.test(x) === isTls);
  const mutate = (edits) => { const c = [...parts]; for (const [i, f] of edits) c[i] = f(c[i]); return c.join(''); };
  const dev = block('sigelo.dev', true), io = block('sigelo.io;', true), net = block('sigelo.net', true);
  const shifted = mutate([[dev, (x) => x.replace(`    ${HSTS}\n`, '')], [io, (x) => x.replace(HSTS, `${HSTS}\n    ${HSTS}`)]]);
  const firstReturn = mutate([[net, (x) => x.replace(/(server_name [^\n]*\n)/, '$1    return 301 https://other.example$request_uri;\n')]]);
  const rewrite = mutate([[net, (x) => x.replace(/(server_name [^\n]*\n)/, '$1    rewrite ^ https://evil.example/ permanent;\n')]]);
  const regexName = mutate([[io, (x) => x.replace('server_name sigelo.io;', 'server_name sigelo.io ~^(www\\.)?sigelo\\.ai$;')]]);
  const rawKey = conf.replace('map "$sigelo_stats$uri" $sigelo_robots {', 'map $request_uri $sigelo_robots {');
  ok(dev > 0 && io > 0 && net > 0 && nginxRefusals(shifted).some((w) => /server_name|sigelo\.dev/.test(w) && /HSTS "missing"/.test(w)) && nginxRefusals(shifted).some((w) => /\(sigelo\.io\): HSTS ".* \| /.test(w))
    && nginxRefusals(firstReturn).some((w) => w.startsWith('sigelo.net: returns "return 301 https://other.example$request_uri; | '))
    && nginxRefusals(conf.replace(LINK, LINK.replace(' always;', ';'))).some((w) => w.includes('describedby'))
    && rewrite !== conf && nginxRefusals(rewrite).some((w) => w.startsWith('sigelo.net: a redirect block holds "rewrite ^ https://evil.example/ permanent;"'))
    && regexName !== conf && nginxRefusals(regexName).some((w) => /server_name ~\^\(www.*is not a plain host name/.test(w))
    && rawKey !== conf && nginxRefusals(rawKey).some((w) => w.startsWith('map $sigelo_robots keyed on $request_uri')),
    'nginx.conf checker: refuses one block\'s HSTS moved to another, a wrong return before the right one, a describedby Link without always, a rewrite in a redirect block, a regex server_name, a header map keyed on $request_uri');
}

// ---- site/deploy/check.mjs --preflight: what a build sends people to off its origin must answer ------
// Against servers in this process: a stand-in relay (its own origin), one that 302s every path to
// it (another origin) and a parked domain's lander (200 text/html for every path). A target that
// answers itself with its content type passes; one that does not answer, redirects, answers with
// another type, or a relay index.json that does not name the relay FAILs by name, and so does a
// relay block without its URLs. (Async: this process serves the requests check.mjs makes.)
{
  const tmp = mkdtempSync(join(tmpdir(), 'sigelo-preflight-'));
  const listen = async (h) => { const srv = createServer(h); await new Promise((r) => srv.listen(0, '127.0.0.1', r)); return [srv, `http://127.0.0.1:${srv.address().port}`]; };
  let RELAY = '';
  const RELAY_FILES = { '/': ['text/html; charset=utf-8', '<!doctype html><h1>relay</h1>'], '/robots.txt': ['text/plain; charset=utf-8', 'User-agent: *\nAllow: /\n'],
    '/llms.txt': ['text/plain; charset=utf-8', '# relay\n'], '/pay.html': ['text/html; charset=utf-8', '<!doctype html><h1>pay</h1>'] };
  const [relaySrv, R] = await listen((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    if (p === '/index.json') { res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ name: 'sigelo relay', homepage: `${RELAY}/` })); return; }
    const f = RELAY_FILES[p];
    if (f) res.writeHead(200, { 'content-type': f[0] }).end(f[1]); else res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
  });
  RELAY = R;
  const [fwdSrv, FWD] = await listen((req, res) => res.writeHead(302, { location: `${R}${req.url}` }).end());
  const [parkedSrv, PARKED] = await listen((req, res) => res.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html>This domain is parked'));
  let k = 0;
  const preflight = (ix) => new Promise((resolve) => {
    const f = join(tmp, `index-${++k}.json`); writeFileSync(f, JSON.stringify(ix));
    const c = spawn(process.execPath, [join(SITE, 'deploy', 'check.mjs'), '--preflight', '--index', f]);
    let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; });
    c.on('close', (code) => resolve({ code, out }));
  });
  const on = (o) => ({ built_from: { commit: 'test' },
    official: { redirects: { 'sigelo.net': `${o}/` }, redirects_pending_dns: { 'sigelo.online': `${o}/` }, repositories: [`${BASE}/`], payment_details_only_on: [`${o}/pay.html`] },
    relay: { name: 'sigelo relay', homepage: `${o}/`, llms_txt: `${o}/llms.txt`, index: `${o}/index.json` } });
  const good = on(R);
  const a = await preflight(good);
  ok(a.code === 0 && /ALL PASS/.test(a.out) && a.out.includes(`ok off-origin target serves: ${R}/robots.txt answers 200 text/plain itself`) && a.out.includes(`ok off-origin target serves: ${R}/index.json names the relay`),
    `check.mjs --preflight: every off-origin target answers itself with its type: ALL PASS (${a.out.trim().split('\n').pop()})`);
  const fail = (url) => `FAIL off-origin target serves: ${url} answers 200 `;
  const cases = [
    ['a live redirect target that does not answer', { ...good, official: { ...good.official, redirects: { 'sigelo.net': `${R}/gone/` } } }, `${R}/gone/robots.txt`, '(got 404'],
    ['a pending redirect target that does not answer', { ...good, official: { ...good.official, redirects_pending_dns: { 'sigelo.online': `${R}/gone/` } } }, `${R}/gone/robots.txt`, '(got 404'],
    ['a relay URL that does not answer', { ...good, relay: { ...good.relay, llms_txt: `${R}/gone.txt` } }, `${R}/gone.txt`, '(got 404'],
    ['a repository that does not answer', { ...good, official: { ...good.official, repositories: [`${BASE}/gone`] } }, `${BASE}/gone`, '(got 404'],
    ['a payment place that does not answer', { ...good, official: { ...good.official, payment_details_only_on: [`${R}/gone.md`] } }, `${R}/gone.md`, '(got 404'],
    ['a redirect target that 302s to another host', { ...good, official: { ...good.official, redirects: { 'sigelo.net': `${FWD}/` } } }, `${FWD}/robots.txt`, `(got 302, no content-type to ${R}/robots.txt)`],
    ['a payment place that 302s to another host', { ...good, official: { ...good.official, payment_details_only_on: [`${FWD}/pay.html`] } }, `${FWD}/pay.html`, '(got 302'],
    ['a robots.txt served as text/html', { ...good, official: { ...good.official, redirects: { 'sigelo.net': `${PARKED}/` } } }, `${PARKED}/robots.txt`, '(got 200, text/html)'],
    ['a relay index.json served as text/html', { ...good, relay: { ...good.relay, index: `${PARKED}/index.json` } }, `${PARKED}/index.json`, '(got 200, text/html)'],
  ];
  for (const [what, ix, url, got] of cases) {
    const r = await preflight(ix);
    const line = r.out.split('\n').find((l) => l.startsWith(fail(url))) ?? '';
    ok(r.code === 1 && line.includes(got), `check.mjs --preflight: ${what} FAILs (${url} ${got}…)`);
  }
  // The reviewer's case: every off-origin URL on a host that 302s to a parked lander, and on the lander itself.
  const parked = await preflight(on(FWD)); const lander = await preflight(on(PARKED));
  ok(parked.code === 1 && !parked.out.split('\n').some((l) => l.startsWith(`ok off-origin target serves: ${FWD}`)) && lander.code === 1
    && lander.out.includes(`FAIL off-origin target serves: ${PARKED}/robots.txt answers 200 text/plain itself`),
    'check.mjs --preflight: a build whose relay, redirect targets and payment places sit on a redirecting host or a parked lander FAILs');
  const wrongRelay = await preflight({ ...good, relay: { ...good.relay, index: `${BASE}/index.json` } });
  ok(wrongRelay.code === 1 && wrongRelay.out.includes(`FAIL off-origin target serves: ${BASE}/index.json names the relay`), 'check.mjs --preflight: a relay index.json that names another site FAILs');
  const partial = await preflight({ ...good, relay: { homepage: `${R}/` } });
  ok(partial.code === 1 && partial.out.includes('FAIL index.json relay: name, homepage, llms_txt, index'), 'check.mjs --preflight: a relay block without its name and three URLs FAILs');
  for (const srv of [relaySrv, fwdSrv, parkedSrv]) srv.close();
  rmSync(tmp, { recursive: true, force: true });
}

// ---- site/deploy/indexnow.sh: only changed or vanished URLs (dry run, no network) -----------------
{
  const tmp = mkdtempSync(join(tmpdir(), 'sigelo-indexnow-'));
  const state = join(tmp, 'state.json');
  const run = () => { const r = spawnSync('sh', [join(SITE, 'deploy', 'indexnow.sh'), '--dry-run', '--state', state], { encoding: 'utf8' });
    return { code: r.status, urls: r.stdout.split('\n').filter((l) => l.startsWith('https://')), out: r.stdout + r.stderr }; };
  const sm = readFileSync(join(DIST, 'sitemap.xml'), 'utf8');
  const all = [...sm.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  const first = run();
  ok(first.code === 0 && first.urls.join() === all.join(), `indexnow.sh --dry-run, no state: all ${all.length} sitemap URLs (got ${first.urls.length}; ${first.out.trim().split('\n')[0]})`);
  const hashOf = (u) => { const p = new URL(u).pathname; return sha256(readFileSync(join(DIST, p.endsWith('/') ? `${p}index.html` : p))); };
  const urls = Object.fromEntries(all.map((u) => [u, hashOf(u)]));
  urls[`${ORIGIN}/spec.html`] = '0'.repeat(64); urls[`${ORIGIN}/gone.html`] = '1'.repeat(64);
  writeFileSync(state, JSON.stringify({ urls }));
  const second = run();
  ok(second.code === 0 && second.urls.join() === `${ORIGIN}/spec.html,${ORIGIN}/gone.html`, `indexnow.sh --dry-run: only the changed and the vanished URL (${second.urls.join(' ')})`);
  delete urls[`${ORIGIN}/gone.html`]; urls[`${ORIGIN}/spec.html`] = hashOf(`${ORIGIN}/spec.html`);
  writeFileSync(state, JSON.stringify({ urls }));
  const third = run();
  ok(third.code === 0 && third.urls.length === 0 && /nothing sent/.test(third.out), `indexnow.sh --dry-run: nothing changed, nothing sent (${third.out.trim()})`);
  // Another site's URLs in the same state file are not this site's vanished ones (IndexNow refuses
  // a URL off the host with 422, and the state is kept after a refusal, so every run would fail).
  writeFileSync(state, JSON.stringify({ urls: { ...urls, 'https://other.example/x': '1'.repeat(64), [`${ORIGIN}.evil.example/y`]: '2'.repeat(64) } }));
  const other = run();
  ok(other.code === 0 && other.urls.length === 0 && /nothing sent/.test(other.out), `indexnow.sh --dry-run: another origin's URLs in the state are not sent (${other.urls.join(' ') || other.out.trim()})`);
  // `urls` that is not an object is unreadable: every URL counts as changed, no junk key is sent.
  writeFileSync(state, JSON.stringify({ urls: 'abc' }));
  const junk = run();
  ok(junk.code === 0 && junk.urls.join() === all.join() && /unreadable/.test(junk.out), `indexnow.sh --dry-run: a state whose urls is not an object counts as unreadable, all ${all.length} sitemap URLs and nothing else (${junk.urls.length})`);
  rmSync(tmp, { recursive: true, force: true });
}

// ---- site/deploy/stats-agents.sh: the classifier over a fixture log -----------------------------
{
  const tmp = mkdtempSync(join(tmpdir(), 'sigelo-stats-'));
  const line = (path, ua) => `0.0.0.0 - - [07/Oct/2026:10:00:00 +0000] "GET ${path} HTTP/2.0" 200 100 "-" "${ua}" "*/*" 0.001`;
  writeFileSync(join(tmp, 'access.log'), [
    line('/llms.txt', 'Claude-User (claude-code/2.0.14; +https://support.anthropic.com/)'),
    line('/spec.md', 'Mozilla/5.0 (compatible; Google-Extended)'),
    line('/index.json', 'meta-externalfetcher/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)'),
  ].join('\n') + '\n');
  const r = spawnSync('sh', [join(SITE, 'deploy', 'stats-agents.sh'), tmp, join(tmp, 'agents.txt')], { encoding: 'utf8' });
  const out = existsSync(join(tmp, 'agents.txt')) ? readFileSync(join(tmp, 'agents.txt'), 'utf8') : r.stderr;
  const byName = out.split('AI agents by name\n')[1]?.split(/\n(?! )/)[0] ?? '';
  ok(r.status === 0 && /^ +1 Claude Code$/m.test(byName) && /^ +1 Meta-ExternalFetcher$/m.test(byName) && !/Google-Extended|Claude-User/.test(byName) && /^browsers +1 +1$/m.test(out),
    `stats-agents.sh: claude-code/ counts as Claude Code, Meta-ExternalFetcher as an AI agent, Google-Extended (a robots token) not (${byName.trim().replace(/\s+/g, ' ')})`);
  rmSync(tmp, { recursive: true, force: true });
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
