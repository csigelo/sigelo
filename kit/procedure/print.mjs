#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// kit/procedure/print.mjs <bound dir> [<out dir>] [--unbound] — called by print.sh.
//
// Renders CEREMONY.md, DRILL.md and RUNBOOK.md from <bound dir> (bind.mjs's output) to
// self-contained HTML for the printer: one file each plus procedure.html with all three, each
// starting on a new page. No script, no external resource, no font to fetch: open it in any
// browser offline and print. Checkboxes print as empty boxes to tick in pen; the vendor rule
// prints boxed. A file still holding a {{placeholder}} is refused unless --unbound (a blank
// copy to read before binding).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const DOCS = ['CEREMONY.md', 'DRILL.md', 'RUNBOOK.md'];

/** site/build.mjs's renderer in a clone (one Markdown dialect for the site and the paper), else md.mjs. */
export async function renderer() {
  const site = join(HERE, '..', '..', 'site', 'build.mjs');
  if (process.env.SIGELO_KIT_RENDERER !== 'minimal' && existsSync(site)) {
    try { const m = await import(pathToFileURL(site).href); if (typeof m.render === 'function') return { name: 'site/build.mjs', render: (md) => m.render(md, (u) => u) }; } catch { /* not a clone */ }
  }
  const m = await import(pathToFileURL(join(HERE, 'md.mjs')).href);
  return { name: 'kit/procedure/md.mjs', render: m.render };
}

const CSS = `
@page { size: A4; margin: 16mm 14mm; }
:root { color-scheme: light; }
body { font: 11pt/1.45 Georgia, "Times New Roman", serif; color: #000; background: #fff; max-width: 48em; margin: 1em auto; padding: 0 1em; }
h1 { font-size: 18pt; border-bottom: 2px solid #000; padding-bottom: .2em; }
h2 { font-size: 13.5pt; margin-top: 1.4em; break-after: avoid; }
code, pre { font: 9.5pt/1.35 "DejaVu Sans Mono", Menlo, Consolas, monospace; }
pre { white-space: pre-wrap; word-break: break-all; border: 1px solid #999; padding: .5em .7em; break-inside: avoid; }
blockquote { border: 2.5px solid #000; margin: 1em 0; padding: .4em 1em; break-inside: avoid; }
table { border-collapse: collapse; width: 100%; break-inside: avoid; }
th, td { border: 1px solid #666; padding: .25em .45em; vertical-align: top; text-align: left; }
td:empty::after { content: "\\00a0"; }
li { margin: .2em 0; }
li.task { list-style: none; margin-left: -1.3em; }
.box { display: inline-block; width: .9em; height: .9em; border: 1.5px solid #000; margin-right: .45em; vertical-align: -.1em; }
.doc + .doc { break-before: page; }
.meta { font-size: 9pt; color: #333; border-top: 1px solid #999; margin-top: 2em; padding-top: .4em; }
@media screen { body { background: #fff; } }
`;

export async function print(dir, outDir, { unbound = false } = {}) {
  const r = await renderer();
  const docs = DOCS.map((d) => {
    const md = readFileSync(join(dir, d), 'utf8');
    const left = md.match(/\{\{[\w.]+\}\}/g);
    if (left && !unbound) throw new Error(`print: ${d} still has ${left.length} placeholder(s) (${[...new Set(left)].slice(0, 3).join(', ')}…) — run bind.mjs first, or pass --unbound for a blank copy`);
    // Task-list items become a printed box; the site renderer leaves "[ ]" as text.
    const html = r.render(md).replace(/<li>(<p>)?\[ \] /g, (_, p) => `<li class="task">${p ?? ''}<span class="box"></span>`);
    const title = (md.match(/^# (.*)$/m) ?? [, d])[1];
    return { d, title, html };
  });
  mkdirSync(outDir, { recursive: true });
  const page = (title, body) => `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>${title.replace(/</g, '&lt;')}</title>\n<style>${CSS}</style>\n</head>\n<body>\n${body}\n` +
    `<p class="meta">Printed procedure of the sigelo recovery kit, rendered by ${r.name}. Software and facilitation only: no custody, no key material.</p>\n</body>\n</html>\n`;
  const files = [];
  for (const x of docs) { const f = join(outDir, x.d.replace(/\.md$/, '.html')); writeFileSync(f, page(x.title, `<section class="doc">\n${x.html}\n</section>`)); files.push(f); }
  const all = join(outDir, 'procedure.html');
  writeFileSync(all, page('sigelo recovery kit — printed procedure', docs.map((x) => `<section class="doc">\n${x.html}\n</section>`).join('\n')));
  files.push(all);
  return { files, renderer: r.name };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const a = process.argv.slice(2).filter((x) => x !== '--unbound');
  if (!a[0]) { console.error('usage: print.sh <bound dir> [<out dir>] [--unbound]'); process.exit(2); }
  try {
    const { files, renderer: name } = await print(a[0], a[1] ?? join(a[0], 'print'), { unbound: process.argv.includes('--unbound') });
    console.log(`printed (${name}): ${files.join(', ')}\nOpen procedure.html in a browser and print it; each document starts on a new page.`);
  } catch (e) { console.error(e.message); process.exit(2); }
}
