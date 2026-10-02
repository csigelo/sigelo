#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Word budgets for the public docs (docs-test/budgets.json: { "<repo path>": maxWords }).
// Words are counted as GNU `wc -w` counts them: runs of non-whitespace. Exit 1 on any overrun or
// missing file. Run from anywhere: `node docs-test/check-budgets.mjs`.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const budgets = JSON.parse(readFileSync(join(root, 'docs-test', 'budgets.json'), 'utf8'));
let bad = 0;
for (const [path, max] of Object.entries(budgets)) {
  let words;
  try { words = readFileSync(join(root, path), 'utf8').split(/[ \t\n\r\f\v]+/).filter(Boolean).length; }
  catch { console.log(`FAIL ${path}: missing`); bad++; continue; }
  const ok = words <= max;
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${path}: ${words} words (budget ${max})`);
}
console.log(bad ? `${bad} over budget` : 'ALL PASS');
process.exit(bad ? 1 : 0);
