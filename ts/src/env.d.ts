// SPDX-License-Identifier: MIT
/**
 * The entire host surface this package uses. Declared here rather than depending on
 * @types/node: CLAUDE.md caps the dependency list, and the runtime needs are this small.
 */
declare const console: {
  log(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
};
declare const process: {
  exit(code?: number): never; argv: string[];
  stdout: { write(s: string): boolean }; stderr: { write(s: string): boolean };
  /** For test.ts: `win32` has no POSIX file modes, no /usr/bin/env and runs no `#!/bin/sh` stand-in. */
  platform: string; env: Record<string, string | undefined>;
};
declare function setTimeout(fn: () => void, ms: number): unknown;

/** Enough of fetch/AbortSignal for the wallet-RPC interop check in test.ts. */
declare const AbortSignal: { timeout(ms: number): unknown };
declare function fetch(url: string, init: {
  method: string; headers: Record<string, string>; body: string; signal?: unknown;
}): Promise<{ json(): Promise<unknown> }>;

declare module 'node:fs' {
  export function readFileSync(path: string | number, encoding: 'utf-8'): string;
  export function writeFileSync(path: string, data: string): void;
  export function mkdtempSync(prefix: string): string;
  export function rmSync(path: string, opts: { recursive: boolean; force: boolean }): void;
}
declare module 'node:os' {
  export function tmpdir(): string;
}
declare module 'node:child_process' {
  export function spawn(cmd: string, args: string[], opts: { stdio: 'ignore' }): {
    kill(): boolean;
    on(event: 'error', cb: (err: Error) => void): void;
  };
}
declare module 'node:url' {
  export function fileURLToPath(url: string): string;
}
declare module 'node:path' {
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
}

/** `import.meta.url` under module: NodeNext; normally supplied by @types/node. */
interface ImportMeta {
  readonly url: string;
}
