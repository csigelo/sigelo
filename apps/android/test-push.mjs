// SPDX-License-Identifier: MIT
// WebPush.java (the RFC 8291 side of the push connector, design/push.md) on a desktop JVM: compiles it with
// test/WebPushTest.java and runs the vectors (RFC 8291 Appendix A; the sigelo wake of relay/test/push.mjs).
//   node apps/android/test-push.mjs     → ALL PASS (n), or SKIP without a JDK
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
  execFileSync(javac, ['-Xlint:all', '-Werror', '-d', out, join(HERE, 'app/src/main/java/io/sigelo/app/WebPush.java'), join(HERE, 'test/WebPushTest.java')], { stdio: 'inherit' });
  const r = spawnSync(java, ['-cp', out, 'io.sigelo.app.WebPushTest'], { encoding: 'utf8' });
  process.stdout.write(r.stdout + r.stderr);
  process.exit(r.status ?? 1);
} finally { rmSync(out, { recursive: true, force: true }); }
