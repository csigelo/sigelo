// SPDX-License-Identifier: MIT
// The self-contained app's vendored files (design/apps.md §3): no bundler, no transform. Walks the
// static import graph of the page (index.html's import map, the app's own modules, the QR codec ui.js
// loads), and copies every file it reaches from where the repository has it into apps/web/vendor/,
// byte for byte: sigelo-contact's modules, sigelo's dist (ts/: `npx tsc` first), @noble's, MQTT.js's
// browser build (mqtt.esm.js), the page's shim for node:zlib, ui.js, ui.css and the icon. What ships
// is what the tests ran.
//
//   node apps/web/copy.mjs           copy; write vendor.json (each file, its source, its SHA-256)
//   node apps/web/copy.mjs --check   copy nothing: every file reached is in vendor/ as its source is,
//                                    vendor.json lists exactly them, and the CSP admits the import map
//
// vendor/ is not committed (.gitignore); vendor.json is, so a change in what ships shows in review.
// Also a module: importMap(html), resolve(spec, parent, map), walk(map) for the tests (test-web.mjs).
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');
/** The page's own URL space: index.html is PAGE + 'index.html'. */
export const PAGE = 'https://app.invalid/';
// Where each vendored path comes from in the repository.
const SOURCES = [
  ['vendor/contact/', 'contact/'],
  ['vendor/sigelo/', 'ts/dist/'],
  ['vendor/@noble/', 'contact/node_modules/@noble/'],
  ['vendor/mqtt.esm.js', 'contact/node_modules/mqtt/dist/mqtt.esm.js'],
  ['vendor/shim-zlib.mjs', 'adapters/moadim/shim-zlib.mjs'],
  ['vendor/ui.js', 'adapters/moadim/ui.js'],
  ['vendor/ui.css', 'adapters/moadim/ui.css'],
  ['vendor/icon.svg', 'adapters/moadim/icon.svg'],
  ['vendor/remote-client.mjs', 'adapters/moadim/remote-client.mjs'],
];
// Imports a module makes only when run in Node, never in the page: remote-client.mjs finds its own
// dependencies in Node (nodeDeps) and is given them in the page (shell.mjs). Not followed.
export const NODE_ONLY = { 'vendor/remote-client.mjs': ['node:module', 'node:url'] };
// The page's modules (not copied: they are the app), and the QR codec ui.js imports by name.
const ENTRIES = ['./app.mjs', './router.mjs', './platform-web.mjs', './platform-stub.mjs', './pow-worker.mjs', './platform-android.mjs', './ws-over-stream.mjs', './shell.mjs', '/qr.mjs', '/qr-decode.mjs'];
const ASSETS = ['vendor/ui.js', 'vendor/ui.css', 'vendor/icon.svg'];

export const sourceOf = (rel) => {
  for (const [to, from] of SOURCES) if (to.endsWith('/') ? rel.startsWith(to) : rel === to) return join(REPO, from + rel.slice(to.length));
  return null;
};
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

/** The import map of index.html (its one inline script) → { text, imports: [[key URL or bare, target URL]] }. */
export function importMap(html = readFileSync(join(HERE, 'index.html'), 'utf8')) {
  const m = /<script type="importmap">([\s\S]*?)<\/script>/.exec(html);
  if (!m) throw new Error('index.html: no import map');
  const map = JSON.parse(m[1]), imports = [];
  for (const [k, v] of Object.entries(map.imports ?? {})) {
    const key = /^(\/|\.\/|\.\.\/)/.test(k) ? new URL(k, PAGE + 'index.html').href : k;
    imports.push([key, new URL(v, PAGE + 'index.html').href]);
  }
  // Longest key first, as the import map algorithm matches.
  imports.sort((a, b) => b[0].length - a[0].length);
  return { text: m[1], imports };
}

/** A specifier imported from parent (a page URL), resolved as the page does: → a page URL. */
export function resolve(spec, parent, map) {
  const asUrl = /^(\/|\.\/|\.\.\/)/.test(spec) ? new URL(spec, parent).href : /^[a-z][a-z0-9+.-]*:/i.test(spec) ? spec : null;
  const key = asUrl ?? spec;
  for (const [k, v] of map.imports) {
    if (k === key) return v;
    if (k.endsWith('/') && key.startsWith(k)) return new URL(key.slice(k.length), v).href;
  }
  if (asUrl === null || !asUrl.startsWith(PAGE)) throw new Error(`${spec} (from ${parent}) does not resolve in the page`);
  return asUrl;
}

/** The specifiers a module imports statically (and by a literal import()), from its text. */
export function importsOf(text) {
  const out = new Set();
  for (const re of [/^\s*(?:import|export)\b[^;'"`]*?\bfrom\s*['"]([^'"\n]+)['"]/gm, /^\s*import\s*['"]([^'"\n]+)['"]/gm, /\bimport\(\s*['"]([^'"\n]+)['"]\s*\)/g]) {
    for (const m of text.matchAll(re)) out.add(m[1]);
  }
  return [...out];
}

/**
 * The page's import graph from its entries: → { files: Map(path under apps/web → its source file,
 * or null for the app's own), missing: [what resolved to no file] }.
 */
export function walk(map = importMap()) {
  const files = new Map(), missing = [], todo = ENTRIES.map((e) => [resolve(e, PAGE + 'index.html', map), 'index.html']);
  for (const a of ASSETS) files.set(a, sourceOf(a));
  while (todo.length) {
    const [url, from] = todo.pop();
    const rel = url.slice(PAGE.length);
    if (files.has(rel)) continue;
    const own = !rel.startsWith('vendor/'), src = own ? join(HERE, ...rel.split('/')) : sourceOf(rel);
    if (src === null || !existsSync(src)) { missing.push(`${rel} (from ${from})`); files.set(rel, null); continue; }
    files.set(rel, own ? null : src);
    if (!/\.m?js$/.test(rel)) continue;
    for (const s of importsOf(readFileSync(src, 'utf8')).filter((x) => !NODE_ONLY[rel]?.includes(x))) {
      try { todo.push([resolve(s, url, map), rel]); } catch (e) { missing.push(e.message); }
    }
  }
  return { files, missing };
}

/** The CSP of index.html (its meta), and the hash its script-src must hold for the import map. */
export function csp(html = readFileSync(join(HERE, 'index.html'), 'utf8')) {
  const m = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html);
  return { policy: m?.[1] ?? null, want: `'sha256-${createHash('sha256').update(importMap(html).text).digest('base64')}'` };
}

function main(check) {
  const map = importMap(), { files, missing } = walk(map), problems = [...missing.map((x) => `unresolved: ${x}`)];
  const { policy, want } = csp();
  if (!policy || !policy.includes(`script-src 'self' ${want}`)) problems.push(`index.html's CSP must say script-src 'self' ${want} (the import map's hash)`);
  const manifest = {};
  for (const [rel, src] of [...files].sort(([a], [b]) => a.localeCompare(b))) {
    if (src === null || !rel.startsWith('vendor/')) continue;
    const bytes = readFileSync(src), to = join(HERE, ...rel.split('/'));
    manifest[rel] = { from: relative(REPO, src).split(sep).join('/'), sha256: sha256(bytes) };
    if (check) { if (!existsSync(to) || sha256(readFileSync(to)) !== manifest[rel].sha256) problems.push(`${rel}: not as ${manifest[rel].from} (run node apps/web/copy.mjs)`); }
    else { mkdirSync(dirname(to), { recursive: true }); copyFileSync(src, to); }
  }
  const text = JSON.stringify({ v: 'sigelo-app-vendor/0', files: manifest }, null, 1) + '\n', mf = join(HERE, 'vendor.json');
  if (check) { if (!existsSync(mf) || readFileSync(mf, 'utf8') !== text) problems.push('vendor.json is not what copy.mjs writes now (run node apps/web/copy.mjs, commit vendor.json)'); }
  else writeFileSync(mf, text);
  const n = Object.keys(manifest).length, bytes = Object.values(manifest).reduce((s, f) => s + readFileSync(join(REPO, f.from)).length, 0);
  for (const p of problems) console.log(`FAIL ${p}`);
  if (problems.length) process.exit(1);
  console.log(`ok ${n} files, ${(bytes / 1024).toFixed(0)} KiB${check ? ', as their sources' : ' copied into apps/web/vendor/'}`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const check = process.argv.includes('--check');
  if (!check && process.argv.includes('--clean')) rmSync(join(HERE, 'vendor'), { recursive: true, force: true });
  main(check);
}
