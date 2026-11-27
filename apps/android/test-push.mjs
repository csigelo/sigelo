// SPDX-License-Identifier: MIT
// WebPush.java (the RFC 8291 side of the push connector) and Ntfy.java (the built-in client's topic,
// endpoint, stream parser and backoff, §6) on a desktop JVM: compiles them with test/WebPushTest.java and test/NtfyTest.java
// and runs both (RFC 8291 Appendix A; the sigelo wake of relay/test/push.mjs, also as ntfy carries it).
//   node apps/android/test-push.mjs     → ALL PASS (n), the sum of both, or SKIP without a JDK
// The JDK: $SIGELO_JDK/bin, else $JAVA_HOME/bin, else javac on the PATH.
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const bins = [process.env.SIGELO_JDK, process.env.JAVA_HOME].filter(Boolean).map((d) => join(d, 'bin'));
const pick = (tool) => bins.map((d) => join(d, tool)).find(existsSync) ?? (spawnSync(tool, ['-version']).status === 0 ? tool : null);
const javac = pick('javac'), java = javac && (javac === 'javac' ? 'java' : join(dirname(javac), 'java'));
if (!javac) { console.log('ALL PASS (0): SKIP, no javac (set SIGELO_JDK or JAVA_HOME)'); process.exit(0); }
const out = mkdtempSync(join(tmpdir(), 'sigelo-webpush-'));
try {
  const src = (f) => join(HERE, 'app/src/main/java/io/sigelo/app', f);
  execFileSync(javac, ['-Xlint:all', '-Werror', '-d', out, src('WebPush.java'), src('Ntfy.java'), join(HERE, 'test/WebPushTest.java'), join(HERE, 'test/NtfyTest.java')], { stdio: 'inherit' });
  let total = 0, status = 0;
  for (const t of ['WebPushTest', 'NtfyTest']) {
    const r = spawnSync(java, ['-cp', out, `io.sigelo.app.${t}`], { encoding: 'utf8' });
    const m = /^ALL PASS \((\d+)\)$/m.exec(r.stdout);
    if (r.status !== 0 || !m) { process.stdout.write(`${t}: ${r.stdout}${r.stderr}`); status = 1; } else total += Number(m[1]);
  }
  if (status === 0) console.log(`ALL PASS (${total})`);
  process.exit(status);
} finally { rmSync(out, { recursive: true, force: true }); }
