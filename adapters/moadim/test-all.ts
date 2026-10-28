// SPDX-License-Identifier: MIT
// `npm test`: every test file in turn, its output as it comes, then one line per file (its own last
// line, `ALL PASS <file> (<n> ok)`, or why it failed) and a last line: `ALL PASS sigelo-agent: …`, or
// `FAIL sigelo-agent: …` with exit 1. One file failing does not stop the others.
import { spawn } from 'node:child_process';
import { join } from 'node:path';

const FILES = ['test-identity.ts', 'test-operator.ts', 'test-keys.ts', 'test-keychain.ts', 'test-contact.ts', 'test-ui.ts', 'test-remote.ts', 'test-watch.ts', 'test-enrol.ts', 'test-links.ts', 'test-devices.ts'];
const lines: string[] = [];
let total = 0, failed = 0;
for (const f of FILES) {
  console.log(`\n── ${f}`);
  const { code, last } = await new Promise<{ code: number | null; last: string }>((resolve) => {
    const c = spawn(process.execPath, [join(import.meta.dirname, f)], { stdio: ['ignore', 'pipe', 'inherit'] });
    let tail = '';
    c.stdout.on('data', (d: Buffer) => { process.stdout.write(d); tail = (tail + d.toString()).slice(-2000); });
    c.on('close', (code) => resolve({ code, last: tail.trim().split('\n').at(-1) ?? '' }));
  });
  const n = /^ALL PASS \S+ \((\d+) ok\)$/.exec(last);
  if (code === 0 && n) { total += Number(n[1]); lines.push(last); } else { failed++; lines.push(/^FAIL /.test(last) ? last : `FAIL ${f} (exit ${code}, no summary line)`); }
}
console.log(`\n── summary\n${lines.join('\n')}`);
console.log(failed === 0 ? `ALL PASS sigelo-agent: ${FILES.length} files, ${total} ok` : `FAIL sigelo-agent: ${failed} of ${FILES.length} files failed`);
process.exit(failed === 0 ? 0 : 1);
