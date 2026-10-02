// SPDX-License-Identifier: MIT
/**
 * The host surface src/ceremony.ts, src/offline.ts and their tests add to src/env.d.ts's:
 * files with modes, synchronous child processes for `age`, UTF-8 text. Same reason as
 * env.d.ts — no @types/node (CLAUDE.md caps the dependencies). Ambient modules merge.
 */
declare class TextEncoder { encode(s: string): Uint8Array }
declare class TextDecoder {
  constructor(label?: string, opts?: { fatal?: boolean; ignoreBOM?: boolean });
  decode(b: Uint8Array): string;
}

declare module 'node:fs' {
  export function readFileSync(path: string): Uint8Array;
  export function writeFileSync(path: string, data: string | Uint8Array, opts: { mode?: number; flag?: string }): void;
  export function mkdirSync(path: string, opts: { recursive?: boolean; mode?: number }): void;
  export function readdirSync(path: string): string[];
  export function statSync(path: string): { mode: number };
  export function chmodSync(path: string, mode: number): void;
  export function openSync(path: string, flags: string): number;
  export function writeSync(fd: number, data: string): number;
}
declare module 'node:child_process' {
  export function spawnSync(cmd: string, args: string[], opts?: {
    input?: Uint8Array | string; maxBuffer?: number; env?: Record<string, string>; cwd?: string;
  }): { status: number | null; stdout: Uint8Array & { toString(): string }; stderr: Uint8Array & { toString(): string }; error?: Error };
}
