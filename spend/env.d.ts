/**
 * The entire host surface this package uses, declared rather than depended on — the same
 * choice ts/src/env.d.ts makes, for the same reason: CLAUDE.md caps the dependency list and
 * sigelo-spend's one dependency is the sigelo library itself.
 */
declare const console: {
  log(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
};
declare const process: {
  exit(code?: number): never; argv: string[]; exitCode: number;
  env: Record<string, string | undefined>;
  /** For test.ts: `win32` has no POSIX file modes. */
  platform: string;
  /** The spend.lock (service.ts): this process's pid, and `kill(pid, 0)` to ask whether one is alive. */
  pid: number; kill(pid: number, signal?: number | string): boolean;
  once(event: 'exit', cb: () => void): void;
  on(event: 'SIGINT' | 'SIGTERM' | 'SIGHUP', cb: () => void): void;
  /** init.ts: the node binary the systemd units run. */
  execPath: string;
};
declare function setTimeout(fn: () => void, ms: number): { unref(): unknown };
declare function clearTimeout(t: unknown): void;
declare class URL {
  constructor(input: string, base?: string);
  pathname: string;
  hostname: string;
  port: string;
  protocol: string;
  searchParams: { get(key: string): string | null };
}
/** The torn-tail repair (service.ts `repairTail`) handles spend.log as bytes, not text. */
declare class TextEncoder { encode(s: string): Uint8Array }
/** `fatal: true` (service.ts `utf8`): invalid UTF-8 throws instead of becoming U+FFFD (SPEC §3). */
declare class TextDecoder {
  constructor(label?: string, opts?: { fatal?: boolean; ignoreBOM?: boolean });
  decode(b: Uint8Array): string;
}
declare const AbortSignal: { timeout(ms: number): unknown };
declare function fetch(url: string, init?: {
  method?: string; headers?: Record<string, string>; body?: string | Uint8Array; signal?: unknown;
}): Promise<{
  status: number; ok: boolean;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

declare module 'node:crypto' {
  export function createHash(algorithm: string): {
    update(data: string, encoding?: string): { digest(encoding: 'hex'): string };
    digest(encoding: 'hex'): string;
  };
  /** A Buffer, which is a Uint8Array; `toString('hex')` is the only extra used here. */
  export function randomBytes(n: number): Uint8Array & { toString(encoding: 'hex' | 'base64url'): string };
}
declare module 'node:fs' {
  export function readFileSync(path: string, encoding: 'utf-8'): string;
  export function readFileSync(path: string): Uint8Array;
  export function writeFileSync(path: string, data: string, opts: { mode: number }): void;
  export function appendFileSync(path: string, data: string, opts: { mode: number }): void;
  export function openSync(path: string, flags: string, mode?: number): number;
  export function writeSync(fd: number, data: string): number;
  export function writeSync(fd: number, data: Uint8Array, offset?: number, length?: number): number;
  export function fstatSync(fd: number): { size: number };
  export function ftruncateSync(fd: number, len: number): void;
  export function fsyncSync(fd: number): void;
  export function closeSync(fd: number): void;
  export function existsSync(path: string): boolean;
  export function realpathSync(path: string): string;
  export function chmodSync(path: string, mode: number): void;
  export function mkdtempSync(prefix: string): string;
  export function rmSync(path: string, opts: { recursive: boolean; force: boolean }): void;
  export function statSync(path: string): { mode: number; isDirectory(): boolean };
  export function statSync(path: string, opts: { bigint: true }): { ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint };
  export function unlinkSync(path: string): void;
  export function readdirSync(path: string): string[];
  /** init.ts: the keeper directory, its frozen copy of this package, and atomic replaces. */
  export function mkdirSync(path: string, opts?: { recursive?: boolean; mode?: number }): void;
  export function renameSync(from: string, to: string): void;
  export function cpSync(from: string, to: string, opts?: { recursive?: boolean; dereference?: boolean; filter?: (src: string) => boolean }): void;
}
declare module 'node:path' {
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
  export function resolve(...paths: string[]): string;
  export function basename(path: string): string;
}
declare module 'node:os' {
  export function tmpdir(): string;
  export function homedir(): string;
}
declare module 'node:http' {
  export interface IncomingMessage {
    method?: string; url?: string; headers: Record<string, string | undefined>;
    /** The whole body arrived; `destroyed` the stream is gone; `socket` the connection. */
    complete: boolean; destroyed: boolean; socket: { destroyed: boolean };
    setEncoding(encoding: string): void;
    /** No `setEncoding`: chunks arrive as bytes (a Buffer), decoded fatally once whole (service.ts `readBody`). */
    on(event: 'data', cb: (chunk: Uint8Array) => void): void;
    on(event: 'end' | 'aborted' | 'close', cb: () => void): void;
    on(event: 'error', cb: (err: Error) => void): void;
  }
  export interface ServerResponse {
    writeHead(status: number, headers?: Record<string, string>): void;
    setHeader(name: string, value: string): void;
    end(body?: string): void;
    destroy(): void;
    /** `close` fires when the response is done or the connection went first (then `writableFinished` is false). */
    on(event: 'close', cb: () => void): void;
    destroyed: boolean; writableFinished: boolean;
  }
  export interface Server {
    listen(port: number, host: string, cb?: () => void): Server;
    close(cb?: (err?: Error) => void): void;
    address(): { port: number; address: string } | string | null;
    on(event: 'error', cb: (err: Error) => void): void;
    unref(): Server;
    closeAllConnections(): void;
  }
  export function createServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Server;
}
declare module 'node:child_process' {
  /** init.ts: systemctl --user and notify-send; test.ts: the CLI verbs. */
  export function spawnSync(cmd: string, args: string[], opts?: { encoding?: 'utf-8'; stdio?: 'ignore' | 'pipe'; timeout?: number; env?: Record<string, string | undefined>; input?: string }): {
    status: number | null; stdout: string; stderr: string; error?: Error;
  };
  /** With `stdio: 'pipe'` (the G3 CLI tests), stdout is read as text. */
  export function spawn(cmd: string, args: string[], opts: { stdio: 'pipe'; env: Record<string, string | undefined> }): {
    stdout: { setEncoding(encoding: string): void; on(event: 'data', cb: (chunk: string) => void): void };
    stderr: { setEncoding(encoding: string): void; on(event: 'data', cb: (chunk: string) => void): void };
    on(event: 'close', cb: (code: number | null) => void): void;
  };
  export function spawn(cmd: string, args: string[], opts: { stdio: 'ignore' | 'inherit' }): {
    pid?: number; kill(signal?: string): boolean;
    on(event: 'error', cb: (err: Error) => void): void;
    on(event: 'exit', cb: (code: number | null) => void): void;
  };
}
declare module 'node:net' {
  /** Raw sockets, for the tests that send half a request or walk away from one. */
  export function connect(port: number, host: string, cb?: () => void): {
    write(data: string): boolean; destroy(): void; end(): void;
    on(event: 'data', cb: (chunk: { toString(): string }) => void): void;
    on(event: 'error', cb: (err: Error) => void): void;
    on(event: 'close', cb: () => void): void;
  };
}
declare module 'node:url' {
  export function fileURLToPath(url: string): string;
}
interface ImportMeta { readonly url: string }
