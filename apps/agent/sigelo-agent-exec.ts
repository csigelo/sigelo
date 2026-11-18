// SPDX-License-Identifier: MIT
/**
 * A command found and run the same way on POSIX and Windows (host claude's login, sdk install's npm,
 * service's systemctl/launchctl): PATH split by the platform's delimiter, PATHEXT tried on Windows, a
 * .cmd/.bat (npm.cmd, a global CLI's shim) run through the shell, quoted (Node refuses to spawn one
 * without it); "not found" from ENOENT or the shell's 127 (sh) / 9009 (cmd.exe), never the shell's own
 * text. Every function takes the platform, so the Windows branches are tested on any machine.
 */
import { spawnSync } from 'node:child_process';
import { accessSync, constants, realpathSync, statSync } from 'node:fs';
import { posix, win32 } from 'node:path';

export const pathFor = (platform: NodeJS.Platform = process.platform): typeof posix => (platform === 'win32' ? win32 : posix);
const envKey = (env: NodeJS.ProcessEnv, k: string, platform: NodeJS.Platform): string | undefined =>
  platform === 'win32' ? Object.entries(env).find(([n]) => n.toUpperCase() === k)?.[1] : env[k];
function runnable(f: string, platform: NodeJS.Platform): boolean {
  try { if (!statSync(f).isFile()) return false; if (platform !== 'win32') accessSync(f, constants.X_OK); return true; } catch { return false; }
}
/** The file a command name runs: on PATH (and PATHEXT on Windows), or the path itself; null: none. */
export function which(cmd: string, env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform, exists: (f: string) => boolean = (f) => runnable(f, platform)): string | null {
  const P = pathFor(platform);
  const exts = platform === 'win32' ? (envKey(env, 'PATHEXT', platform) || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean) : [''];
  const tries = platform === 'win32' && exts.some((e) => cmd.toLowerCase().endsWith(e.toLowerCase())) ? ['', ...exts] : exts;
  const direct = P.isAbsolute(cmd) || cmd.includes('/') || (platform === 'win32' && cmd.includes('\\'));
  const dirs = direct ? [''] : (envKey(env, 'PATH', platform) ?? '').split(P.delimiter).map((d) => d.replace(/^"(.*)"$/, '$1')).filter(Boolean);
  for (const d of dirs) for (const e of tries) { const f = d === '' ? cmd + e : P.join(d, cmd + e); if (exists(f)) return f; }
  return null;
}
const winArg = (a: string): string => (/^[\w@.\/:=+,-]+$/.test(a) ? a : `"${a.replace(/"/g, '""')}"`);
/** How to spawn a found file: a .cmd/.bat on Windows through the shell, the file and arguments quoted. */
export function spawnArgs(file: string, args: string[], platform: NodeJS.Platform = process.platform): { cmd: string; args: string[]; shell: boolean } {
  return platform === 'win32' && /\.(cmd|bat)$/i.test(file) ? { cmd: `"${file}"`, args: args.map(winArg), shell: true } : { cmd: file, args, shell: false };
}
/** A command that is not there: ENOENT, or the shell's exit 127 (sh) or 9009 (cmd.exe). */
export const notFound = (code: number | null | undefined, err?: { code?: string } | null): boolean => err?.code === 'ENOENT' || code === 127 || code === 9009;
/** Stops a child and what it started (Windows: a .cmd's node under cmd.exe holds the pipes: taskkill /T). */
export function stop(pid: number | undefined, kill: () => void, platform: NodeJS.Platform = process.platform): void {
  if (platform === 'win32' && pid !== undefined) { const r = spawnSync('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' }); if (r.status === 0) return; }
  kill();
}
/** One directory? Through realpath where it exists (Windows 8.3 short names, macOS /private), then resolved; win32: any case. */
export function samePath(a: string, b: string, platform: NodeJS.Platform = process.platform): boolean {
  const P = pathFor(platform);
  const n = (x: string): string => {
    let r = x;
    if (platform === process.platform) try { r = realpathSync.native(x); } catch {}
    r = P.resolve(r);
    return platform === 'win32' ? r.toLowerCase() : r;
  };
  return n(a) === n(b);
}
