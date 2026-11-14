// SPDX-License-Identifier: MIT
// What every test-*.ts file shares: the CLI's path, `ok`, the summary line, a temp HOME, a CLI run
// in a child, and the in-process relay (relay/server.mjs, SKIP without a checkout and its
// node_modules). Each file ends with one line: `ALL PASS <file> (<n> ok)` or `FAIL <file> (…)`.
// `npm test` runs them all (test-all.ts). Every CLI child gets SIGELO_KEY_PROVIDER=file: `init`'s default
// is the OS keychain where one answers (a desktop session, Windows), and test identities stay files.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Genesis } from 'sigelo';

export const CLI = join(import.meta.dirname, 'cli.ts');
export const ROOT = join(import.meta.dirname, '..', '..');
export const RELAY = process.env['SIGELO_RELAY_DIR'] ?? join(ROOT, 'relay');
export const now = Math.floor(Date.now() / 1000);
// Windows has no POSIX modes (a file inherits its directory's ACL): those checks run on the others.
export const posixModes = process.platform !== 'win32';
export type Bundle = { genesis: Genesis; rotations: unknown[]; bindings: import('sigelo').Binding[]; attestations: { body: { sub: string } }[]; issuers: Genesis[] };

let passed = 0, failures = 0;
export const ok = (name: string, cond: boolean, detail = ''): void => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}${cond || !detail ? '' : ` — ${detail}`}`);
  if (cond) passed++; else failures++;
};
/** The file's last line, then its exit: 0 when every check passed. */
export function done(file: string): never {
  const name = basename(file);
  console.log(failures === 0 ? `\nALL PASS ${name} (${passed} ok)` : `\nFAIL ${name} (${failures} of ${passed + failures} failed)`);
  process.exit(failures === 0 ? 0 : 1);
}

export const tmpHome = (tag: string): string => mkdtempSync(join(tmpdir(), `sigelo-moadim-${tag}-`));
export interface Ran { status: number | null; stdout: string; stderr: string }
/** sigelo-agent in a child, with this env, without blocking this process (an in-process relay answers it). */
export const cliIn = (env: Record<string, string | undefined>, cwd: string) => (...args: string[]): Promise<Ran> => new Promise((resolve) => {
  const c = spawn('node', [CLI, ...args], { env, cwd });
  let stdout = '', stderr = '';
  c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
  c.on('close', (status) => resolve({ status, stdout, stderr }));
});

export const hasRelay = (): boolean => existsSync(join(RELAY, 'server.mjs')) && existsSync(join(RELAY, 'node_modules'));
export const NO_RELAY = 'no relay checkout with its node_modules (SIGELO_RELAY_DIR, else ../../relay)';
export interface TestRelay { ports: { tcp: number; http: number }; close?: () => Promise<void>; endpoints: Record<string, { mqtt: string; http: string }> }
/** The relay the contact tests use, in this process, its database in dir: host relay.test, light proof of work. */
// host: the relay's name (a second relay beside relay.test: invite --relay).
export async function startTestRelay(dir: string, host = 'relay.test'): Promise<TestRelay> {
  type Relay = { ports: { tcp: number; http: number }; close?: () => Promise<void> };
  const { startRelay } = await import(pathToFileURL(join(RELAY, 'server.mjs')).href) as { startRelay(c: object): Promise<Relay> };
  const { TIERS, relayPolicy } = await import(pathToFileURL(join(RELAY, 'allowance.mjs')).href) as { TIERS: object; relayPolicy(c: unknown, o: object): unknown };
  const relay = await startRelay({ host, db: join(dir, host === 'relay.test' ? 'relay.db' : `${host}.db`), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1, log: () => {},
    // Every test is one network (loopback): the short-code brakes are relay/test/run.mjs's, not these
    // (a cancel and a park each count as a lookup, and the tests' codes ran past 20 in 10 minutes).
    // Public codes are Pro's (relay/park.mjs): every test identity is, here.
    park: { lookups: { n: 1000, window: 600 }, parks: { n: 1000, window: 3600 }, lookupsAll: { n: 8000, window: 600 }, publicFetches: { n: 1000, window: 600 }, pro: () => true },
    policy: (c: unknown) => relayPolicy(c, { pow: { bits: 4, loadBits: 8, loadPerHour: 1000, cost: { m: 8, t: 1, p: 1 } }, freeQueue: 64 * 1024 * 1024, tiers: TIERS }) });
  return Object.assign(relay, { endpoints: { [host]: { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } } });
}
