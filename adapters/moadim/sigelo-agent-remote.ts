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
import { contactDependency } from './sigelo-agent-contact.ts';

export const REMOTE = 'sigelo-remote/0', R_BODY_MAX = 1024 * 1024, CONTROL_NAME = /^[a-z0-9][a-z0-9_-]{0,19}$/;
export type Scope = 'read' | 'chat' | 'all';
export interface Control { id: string; key: string; scope: Scope; ctr: number; created: number; last_used: number | null }

// The scope table (design: read ⊂ chat ⊂ all). A route in none of them is never remote. Links: the list
// is read; answering an introduction pairs as accept does (chat); making or ending a link and an allow
// rule set who the agents talk to and at what trust, as tier and forget do (all). The relay setting
// and the registry's list: all (where new codes point is the operator's choice). The agents list (the
// keeper's workers) is read; enrolling, revoking or renaming a worker is all.
const READ = ['GET /api/state', 'GET /api/me', 'GET /api/messages', 'GET /api/links', 'GET /api/agents/workers'];
const CHAT = [...READ, 'POST /api/send', 'POST /api/accept', 'POST /api/invite', 'POST /api/invite/cancel', 'POST /api/words', 'POST /api/rename', 'POST /api/tag', 'POST /api/sync',
  'POST /api/links/answer'];
const ALL = [...CHAT, 'POST /api/forget', 'POST /api/tier', 'POST /api/history/clear', 'GET /api/agents', 'POST /api/agents/enrol', 'POST /api/agents/pair',
  'POST /api/link', 'POST /api/unlink', 'POST /api/links/allow', 'GET /api/settings', 'POST /api/settings', 'GET /api/relays', 'POST /api/relays/test',
  'POST /api/agents/enrol-code', 'POST /api/agents/revoke', 'POST /api/agents/rename'];
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

/** A relay control (design/apps.md §6.3, sigelo-agent-control.ts): no key here, a paired control identity. */
// code: the long code while nobody answered it (withdrawn when the code is made again), never shown.
export interface RelayControl { relay: true; scope: Scope; created: number; last_used: number | null; did: string | null; nonce: string | null; code?: string; exp: number | null; words: string | null; confirmed: boolean }
export type AnyControl = Control | RelayControl;
export const isRelay = (c: AnyControl | undefined): c is RelayControl => (c as RelayControl | undefined)?.relay === true;
/** The LAN controls among them (the same objects: openRequest's ctr goes into ui.json). */
export const lanControls = (all: Record<string, AnyControl>): Record<string, Control> => Object.fromEntries(Object.entries(all).filter(([, c]) => !isRelay(c))) as Record<string, Control>;

type Dispatch = (method: string, url: URL, b: Record<string, unknown>) => Promise<[number, unknown]>;
/**
 * One opened call within a scope, as the local listener answers it: [status, JSON]. The LAN path
 * (sealed) and the relay path (sigelo-device/1 request) both come here: not a route, a device route
 * (never remote), outside the scope, a body that is not an object, else the route itself.
 */
export async function remoteCall(scope: Scope, msg: { method: string; path: string; body?: unknown }, routes: Record<string, unknown>, dispatch: Dispatch): Promise<[number, unknown]> {
  let url: URL | null = null;
  try { url = new URL(msg.path, 'http://remote'); } catch {}
  const b = msg.body === undefined ? {} : msg.body;
  if (url === null || !url.pathname.startsWith('/api/') || url.origin !== 'http://remote') return [404, { error: { check: 'route', message: 'not a route' } }];
  if (deviceRoute(url.pathname)) return [403, { error: { check: 'remote', message: 'device routes are never remote: moving keys needs a human at the computer' } }];
  if (!SCOPES[scope].has(`${msg.method} ${url.pathname}`)) {
    return routes[`${msg.method} ${url.pathname}`] ? [403, { error: { check: 'scope', message: `${msg.method} ${url.pathname} is outside this control's scope (${scope})` } }]
      : [404, { error: { check: 'route', message: `no ${msg.method} ${url.pathname}` } }];
  }
  if (typeof b !== 'object' || b === null || Array.isArray(b)) return [400, { error: { check: 'body', message: 'a JSON object' } }];
  const [status, body] = await dispatch(msg.method, url, b as Record<string, unknown>);
  return [status, scrub(scope, msg.method, url.pathname, body)];
}

/**
 * An answer as a scope may read it (review 2026-10-28, MEDIUM 8): a code that pairs is the act it
 * enables, so a waiting invite's codes (`pending.invites[].code`, `short`) go only to chat and all,
 * an enrolment's (`workers[].enrolling.code`, `command`) only to all. A copy; the page's own is untouched.
 */
export function scrub(scope: Scope, method: string, pathname: string, body: unknown): unknown {
  if (method !== 'GET' || typeof body !== 'object' || body === null) return body;
  const invites = pathname === '/api/state' && scope === 'read', enrol = (pathname === '/api/agents/workers' || pathname === '/api/agents') && scope !== 'all';
  if (!invites && !enrol) return body;
  const x = JSON.parse(JSON.stringify(body)) as { pending?: { invites?: Record<string, unknown>[] }; workers?: { enrolling?: Record<string, unknown> | null }[] };
  if (invites) for (const i of x.pending?.invites ?? []) { delete i['code']; delete i['short']; }
  if (enrol && Array.isArray(x.workers)) for (const w of x.workers) if (w.enrolling) { delete w.enrolling['code']; delete w.enrolling['command']; }
  return x;
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
export async function loadAead(): Promise<void> { aead ??= ((await contactDependency('@noble/ciphers/chacha.js')) as { xchacha20poly1305: Aead }).xchacha20poly1305; }

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

/** An RFC 1918 address, or 100.64/10 (shared, CGNAT and tailnets) or 169.254/16 (link-local): never routed on the internet. */
export function privateV4(ip: string): boolean {
  if (!isIPv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number) as [number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254);
}
/**
 * The LAN address to listen on: the default route's when it is private, else the first private
 * non-internal IPv4, else null (the caller asks for --listen). A host whose default route leaves by
 * a public address (a server) never opens the listener to the internet by default (review 2026-10-28).
 */
export function lanAddress(viaRoute: string | null, ifaces: ReturnType<typeof networkInterfaces>): string | null {
  if (viaRoute && privateV4(viaRoute)) return viaRoute;
  for (const list of Object.values(ifaces)) for (const i of list ?? []) if (i.family === 'IPv4' && !i.internal && privateV4(i.address)) return i.address;
  return null;
}
/** The address of the interface the default route leaves by (no packet is sent), when private; see lanAddress. */
export async function defaultAddress(): Promise<string | null> {
  const viaRoute = await new Promise<string | null>((ok) => {
    const s = createSocket('udp4');
    s.on('error', () => { s.close(); ok(null); });
    s.connect(9, '192.0.2.1', () => { let a: string | null = null; try { a = s.address().address; } catch {} s.close(); ok(a); });
  });
  return lanAddress(viaRoute, networkInterfaces());
}
