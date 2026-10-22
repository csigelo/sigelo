// SPDX-License-Identifier: MIT
// The page in the APK (design/apps.md §8): apps/web/copy.mjs vendors what the page imports, then
// every file the page reaches (its import graph, as copy.mjs walks it, and index.html) is copied as
// it is into app/src/main/assets/web/, which is emptied first: what ships is what test-web.mjs and
// test-shell.mjs ran, and nothing else (no test, no copy.mjs, no README).
//
//   node apps/android/assets.mjs           vendor, then copy (run before ./gradlew; CI does)
//   node apps/android/assets.mjs --check   copy nothing: assets/web/ holds exactly those files, byte for byte
//
// Also a module: files() → [[path under assets/web, source file]] for check.mjs.
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const WEB = join(HERE, '..', 'web');
export const OUT = join(HERE, 'app', 'src', 'main', 'assets', 'web');

/** The page's files: index.html and everything its import graph reaches, as [published path, source]. */
export async function files() {
  const C = await import(pathToFileURL(join(WEB, 'copy.mjs')).href);
  const { files: graph, missing } = C.walk(C.importMap());
  if (missing.length) throw new Error(`the page's import graph does not resolve: ${missing.join('; ')}`);
  const out = [['index.html', join(WEB, 'index.html')]];
  for (const rel of [...graph.keys()].sort()) out.push([rel, join(WEB, ...rel.split('/'))]);
  return out;
}

const walkDir = (d, base = d) => (existsSync(d) ? readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walkDir(p, base) : [relative(base, p).split(sep).join('/')]; }) : []);

async function main(check) {
  if (!check) execFileSync(process.execPath, [join(WEB, 'copy.mjs')], { stdio: 'inherit' });
  const list = await files(), problems = [];
  if (check) {
    const want = new Set(list.map(([p]) => p));
    for (const [p, src] of list) {
      const to = join(OUT, ...p.split('/'));
      if (!existsSync(src)) problems.push(`${p}: its source is missing (node apps/web/copy.mjs)`);
      else if (!existsSync(to) || !readFileSync(to).equals(readFileSync(src))) problems.push(`${p}: not as its source`);
    }
    for (const p of walkDir(OUT)) if (!want.has(p)) problems.push(`${p}: in assets/web/ but not in the page`);
  } else {
    rmSync(OUT, { recursive: true, force: true });
    for (const [p, src] of list) {
      const to = join(OUT, ...p.split('/'));
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(src, to);
    }
  }
  for (const p of problems) console.log(`FAIL ${p}`);
  if (problems.length) process.exit(1);
  const bytes = list.reduce((n, [, src]) => n + statSync(src).size, 0);
  console.log(`ok ${list.length} files, ${(bytes / 1024).toFixed(0)} KiB ${check ? 'in' : 'copied into'} ${relative(join(HERE, '..', '..'), OUT).split(sep).join('/')}/`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) await main(process.argv.includes('--check'));
