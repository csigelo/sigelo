// SPDX-License-Identifier: MIT
// What every test-*.ts file shares: the CLI's path, `ok`, the summary line, a temp HOME, a CLI run
// in a child, and the in-process relay (relay/server.mjs, SKIP without a checkout and its
// node_modules). Each file ends with one line: `ALL PASS <file> (<n> ok)` or `FAIL <file> (…)`.
// `npm test` runs them all (test-all.ts).
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
export async function startTestRelay(dir: string): Promise<TestRelay> {
  type Relay = { ports: { tcp: number; http: number }; close?: () => Promise<void> };
  const { startRelay } = await import(pathToFileURL(join(RELAY, 'server.mjs')).href) as { startRelay(c: object): Promise<Relay> };
  const { TIERS, relayPolicy } = await import(pathToFileURL(join(RELAY, 'allowance.mjs')).href) as { TIERS: object; relayPolicy(c: unknown, o: object): unknown };
  const relay = await startRelay({ host: 'relay.test', db: join(dir, 'relay.db'), tcpPort: 0, httpPort: 0, loginRate: 100000, verifyBudget: 1e9, diskUsed: () => 0.1, log: () => {},
    policy: (c: unknown) => relayPolicy(c, { pow: { bits: 8, loadBits: 12, loadPerHour: 1000 }, freeQueue: 64 * 1024 * 1024, tiers: TIERS }) });
  return Object.assign(relay, { endpoints: { 'relay.test': { mqtt: `mqtt://127.0.0.1:${relay.ports.tcp}`, http: `http://127.0.0.1:${relay.ports.http}` } } });
}
