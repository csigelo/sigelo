// SPDX-License-Identifier: MIT
/**
 * `sigelo-agent ui --remote`: page control from another device on the LAN, sealed (UI-API.md "Remote").
 * A control is a name, an 8-byte id, a 32-byte key and a scope, kept in `<identity>.ui.json`
 * `controls{}` (0600) by the page, the file's one owner; it travels once, as the text
 * `SIGELO:UI:<ip>:<port>:<base45 of id ‖ key>`.
 *
 * sigelo-remote/0. Request `POST /r` `{id: hex, ctr, nonce: b64url(24), box: b64url}`:
 * box = XChaCha20-Poly1305(key, nonce, aad = "sigelo-remote/0 req" ‖ id ‖ u64be(ctr),
 * JCS({method, path, body?})). `ctr` strictly increasing per control, kept here before the call runs:
 * a replayed or reordered request is refused. Answer `{nonce, box}` under aad "sigelo-remote/0 res" ‖
 * id ‖ u64be(ctr), the JSON `{status, body}` the local listener would have answered. Anything that is not
 * an opened request (other paths, bad shape, unknown id, old ctr, wrong key) gets a status and no body.
 */
import { randomBytes } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { isIPv4 } from 'node:net';
import { networkInterfaces } from 'node:os';
import { contactModule } from './sigelo-agent-contact.ts';

export const REMOTE = 'sigelo-remote/0', R_BODY_MAX = 1024 * 1024, CONTROL_NAME = /^[a-z0-9][a-z0-9_-]{0,19}$/;
export type Scope = 'read' | 'chat' | 'all';
export interface Control { id: string; key: string; scope: Scope; ctr: number; created: number; last_used: number | null }

// The scope table (design: read ⊂ chat ⊂ all). A route in none of them is never remote.
const READ = ['GET /api/state', 'GET /api/me', 'GET /api/messages'];
const CHAT = [...READ, 'POST /api/send', 'POST /api/accept', 'POST /api/invite', 'POST /api/invite/cancel', 'POST /api/words', 'POST /api/rename', 'POST /api/tag', 'POST /api/sync'];
const ALL = [...CHAT, 'POST /api/forget', 'POST /api/tier', 'POST /api/history/clear', 'GET /api/agents', 'POST /api/agents/enrol', 'POST /api/agents/pair'];
export const SCOPES: Record<Scope, ReadonlySet<string>> = { read: new Set(READ), chat: new Set(CHAT), all: new Set(ALL) };
export const isScope = (s: unknown): s is Scope => s === 'read' || s === 'chat' || s === 'all';
/** Moving keys needs a human at the computer: never remote, whatever the scope. */
export const deviceRoute = (pathname: string): boolean => pathname === '/api/devices' || pathname.startsWith('/api/devices/');

// ---- base45 (RFC 9285)
const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
export function base45(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 2) {
    let n = i + 1 < b.length ? b[i]! * 256 + b[i + 1]! : b[i]!;
    const k = i + 1 < b.length ? 3 : 2;
    for (let j = 0; j < k; j++) { s += B45[n % 45]; n = Math.floor(n / 45); }
  }
  return s;
}

/** The text a control travels as (a QR later). */
export const controlLine = (ip: string, port: number, c: Control): string =>
  `SIGELO:UI:${ip}:${port}:${base45(Buffer.concat([Buffer.from(c.id, 'hex'), Buffer.from(c.key, 'hex')]))}`;
export const newControl = (scope: Scope, now: number): Control => ({ id: randomBytes(8).toString('hex'), key: randomBytes(32).toString('hex'), scope, ctr: 0, created: now, last_used: null });

const aad = (dir: 'req' | 'res', id: Buffer, ctr: number): Uint8Array => {
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(ctr));
  return Buffer.concat([Buffer.from(`${REMOTE} ${dir}`), id, c]);
};
type Aead = (key: Uint8Array, nonce: Uint8Array, aad: Uint8Array) => { encrypt(p: Uint8Array): Uint8Array; decrypt(c: Uint8Array): Uint8Array };
let aead: Aead | undefined;
/** XChaCha20-Poly1305 from @noble/ciphers, sigelo-contact's own dependency. */
export async function loadAead(): Promise<void> { aead ??= ((await contactModule('@noble/ciphers/chacha.js')) as { xchacha20poly1305: Aead }).xchacha20poly1305; }

const B64 = /^[A-Za-z0-9_-]+$/;
/** A request opened: its control's name, ctr and message; or null (the caller answers with no body). */
export function openRequest(controls: Record<string, Control>, raw: unknown): { name: string; c: Control; ctr: number; msg: { method: string; path: string; body?: unknown } } | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const { id, ctr, nonce, box } = raw as Record<string, unknown>;
  if (typeof id !== 'string' || !/^[0-9a-f]{16}$/.test(id) || !Number.isSafeInteger(ctr) || (ctr as number) < 1) return null;
  if (typeof nonce !== 'string' || !B64.test(nonce) || typeof box !== 'string' || !B64.test(box)) return null;
  const hit = Object.entries(controls).find(([, c]) => c.id === id);
  if (!hit || (ctr as number) <= hit[1].ctr) return null;
  const n = Buffer.from(nonce, 'base64url'), b = Buffer.from(box, 'base64url');
  if (n.length !== 24 || b.length < 16) return null;
  let plain: Uint8Array;
  try { plain = aead!(Buffer.from(hit[1].key, 'hex'), n, aad('req', Buffer.from(id, 'hex'), ctr as number)).decrypt(b); } catch { return null; }
  let msg: unknown;
  try { msg = JSON.parse(Buffer.from(plain).toString('utf8')); } catch { return null; }
  const m = msg as { method?: unknown; path?: unknown };
  if (typeof msg !== 'object' || msg === null || (m.method !== 'GET' && m.method !== 'POST') || typeof m.path !== 'string') return null;
  return { name: hit[0], c: hit[1], ctr: ctr as number, msg: msg as { method: string; path: string; body?: unknown } };
}
/** The answer to an opened request, sealed under its control's key and ctr. */
export function sealAnswer(c: Control, ctr: number, json: string): string {
  const nonce = randomBytes(24), box = aead!(Buffer.from(c.key, 'hex'), nonce, aad('res', Buffer.from(c.id, 'hex'), ctr)).encrypt(Buffer.from(json));
  return JSON.stringify({ nonce: nonce.toString('base64url'), box: Buffer.from(box).toString('base64url') });
}

/** The address of the interface the default route leaves by (no packet is sent), else the first non-internal IPv4. */
export async function defaultAddress(): Promise<string | null> {
  const viaRoute = await new Promise<string | null>((ok) => {
    const s = createSocket('udp4');
    s.on('error', () => { s.close(); ok(null); });
    s.connect(9, '192.0.2.1', () => { let a: string | null = null; try { a = s.address().address; } catch {} s.close(); ok(a); });
  });
  if (viaRoute && isIPv4(viaRoute) && viaRoute !== '0.0.0.0') return viaRoute;
  for (const list of Object.values(networkInterfaces())) for (const i of list ?? []) if (i.family === 'IPv4' && !i.internal) return i.address;
  return null;
}
