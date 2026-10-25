// SPDX-License-Identifier: MIT
/**
 * An https:// daemon's certificate: verify, then pin (spend/README.md "Choosing a daemon").
 *
 * monero-wallet-rpc 0.18 checks no CA for its daemon: with `--daemon-ssl enabled` it refuses to
 * start without a pin (`--daemon-ssl-allowed-fingerprints`, the certificate's SHA-256), and its
 * `--daemon-ssl-ca-certificates` takes trust anchors without any hostname check. So sigelo-spend
 * verifies first, with Node's TLS: the chain against Node's CA store (Mozilla's roots, plus
 * NODE_EXTRA_CA_CERTS) and the hostname; then it hands wallet-rpc that certificate's fingerprint.
 *
 * Two modes, for all https:// daemons of a keeper:
 * - auto (no `--daemon-ssl-fingerprint`): the pin is whatever certificate verified last. When the
 *   node renews its certificate the wallet loses its daemon; the keeper reads the new certificate,
 *   verifies it the same way, and re-pins (`set_daemon`, `daemon-pins.json`, and the wallet-rpc's
 *   own `--config-file`, so a restart keeps it). A certificate that does not verify is refused.
 * - hard (`--daemon-ssl-fingerprint`, the operator's list): never re-pinned; a node presenting
 *   another certificate is an error naming both. A self-signed node certificate needs this mode.
 * `.onion` daemons are reached through Tor and need no pin (wallet-rpc accepts them as they are).
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { checkServerIdentity, connect, rootCertificates, type PeerCertificate, type TLSSocket } from 'node:tls';
import { fileURLToPath } from 'node:url';

export const PINS_FILE = 'daemon-pins.json';
export const PROBE_TIMEOUT_MS = 15_000;
/** An error's words; a connect to a name with two addresses fails as an AggregateError with none. */
const why = (e: unknown): string => {
  if (!(e instanceof Error)) return String(e);
  const x = e as Error & { code?: unknown; errors?: unknown[] };
  if (x.message !== '') return x.message;
  const inner = Array.isArray(x.errors) ? x.errors.map((y) => why(y)).filter((y) => y !== '') : [];
  return inner.length > 0 ? [...new Set(inner)].join('; ') : typeof x.code === 'string' ? x.code : 'failed';
};

/** What a daemon's TLS presented: its leaf certificate, and whether it verifies for that host. */
export interface TlsProbe {
  daemon: string; host: string;
  /** SHA-256 of the leaf certificate (DER), lowercase hex without colons: wallet-rpc's pin. */
  fingerprint: string;
  notBefore: string; notAfter: string; subject: string; issuer: string;
  /** The chain verifies against the CA store AND the certificate names the host. */
  valid: boolean;
  /** Why not, when `valid` is false. */
  why?: string;
}
/** Extra trust anchors (PEM), added to Node's CA store: tests, or a private CA by choice. */
export interface TlsTrust { ca?: string[]; timeoutMs?: number }

/** An https:// daemon whose certificate sigelo-spend verifies and pins: not a .onion (Tor). */
export const pinnable = (d: string): boolean => d.startsWith('https://') && !/\.onion(?::[0-9]+)?$/i.test(d);
/** 64 hex, colons allowed, any case → wallet-rpc's form; undefined when it is not one. */
export const normalFingerprint = (x: string): string | undefined => {
  const h = x.trim().replace(/:/g, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(h) ? h : undefined;
};
const iso = (d: string): string => { const t = Date.parse(d); return Number.isNaN(t) ? d : new Date(t).toISOString().replace('.000Z', 'Z'); };
const nameOf = (x: unknown): string => {
  if (typeof x !== 'object' || x === null) return '';
  const o = x as Record<string, unknown>;
  return [o['CN'], o['O']].filter((v) => v !== undefined).map((v) => (Array.isArray(v) ? v.join('+') : String(v))).join(', ');
};

function hostPort(daemon: string): { host: string; port: number } {
  const m = /^(?:https:\/\/)?(\[[0-9A-Fa-f:.]+\]|[^:/]+):([0-9]{1,5})\/?$/.exec(daemon);
  if (m === null) throw new Error(`${JSON.stringify(daemon)} is not https://host:port`);
  return { host: m[1]!.replace(/^\[(.*)\]$/, '$1'), port: Number(m[2]) };
}

/** Why a certificate does not verify for `host`, or undefined when it does: chain, then name. */
function verdict(s: TLSSocket, host: string, c: PeerCertificate): string | undefined {
  // Node checks the name itself when it sent one (SNI) and says so as ERR_TLS_CERT_ALTNAME_INVALID.
  if (!s.authorized && s.authorizationError === 'ERR_TLS_CERT_ALTNAME_INVALID') return `not issued to ${host}: it names ${nameOf((c as { subject?: unknown }).subject) || 'another host'}`;
  if (!s.authorized) return `not verified by the CA store: ${String(s.authorizationError)}`;
  const named = checkServerIdentity(host, c);
  return named !== undefined ? `not issued to ${host}: ${named.message}` : undefined;
}
const fpOf = (c: PeerCertificate): string => String(c.fingerprint256).replace(/:/g, '').toLowerCase();

/** Connect, read the certificate, close. Throws when nothing answers TLS there. */
export function probeTls(daemon: string, trust: TlsTrust = {}): Promise<TlsProbe> {
  const { host, port } = hostPort(daemon), timeoutMs = trust.timeoutMs ?? PROBE_TIMEOUT_MS;
  const ip = /^[0-9.]+$/.test(host) || host.includes(':');
  return new Promise((done, fail) => {
    const s = connect({
      host, port, ...(!ip && { servername: host }), rejectUnauthorized: false,
      ...(trust.ca !== undefined && trust.ca.length > 0 && { ca: [...rootCertificates, ...trust.ca] }),
    });
    const timer = setTimeout(() => { s.destroy(); fail(new Error(`${host}:${port}: no TLS answer in ${timeoutMs} ms`)); }, timeoutMs);
    s.once('error', (e: Error) => { clearTimeout(timer); fail(new Error(`${host}:${port}: ${why(e)}`)); });
    s.once('secureConnect', () => {
      clearTimeout(timer);
      const c = s.getPeerCertificate();
      s.destroy();
      if (c === null || typeof c !== 'object' || !(c.raw instanceof Uint8Array)) { fail(new Error(`${host}:${port}: presented no certificate`)); return; }
      const bad = verdict(s, host, c);
      done({
        daemon, host, fingerprint: fpOf(c),
        notBefore: iso(c.valid_from), notAfter: iso(c.valid_to), subject: nameOf(c.subject), issuer: nameOf(c.issuer),
        valid: bad === undefined, ...(bad !== undefined && { why: bad }),
      });
    });
  });
}

/**
 * `probeTls` for synchronous callers (init): in a child node, which reads NODE_EXTRA_CA_CERTS
 * from the environment like any node. Throws as `probeTls` does.
 */
export function probeTlsSync(daemon: string, timeoutMs = PROBE_TIMEOUT_MS): TlsProbe {
  const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), 'probe', daemon, String(timeoutMs)], { encoding: 'utf-8', timeout: timeoutMs + 10_000 });
  let out: { probe?: TlsProbe; error?: string };
  try { out = JSON.parse(r.stdout) as typeof out; } catch { throw new Error(`${daemon}: the TLS probe did not finish (${(r.stderr ?? '').trim() || r.error?.message || `exit ${String(r.status)}`})`); }
  if (out.probe === undefined) throw new Error(out.error ?? `${daemon}: the TLS probe said nothing`);
  return out.probe;
}

/**
 * One POST over TLS to a daemon (restore.ts `--daemon`), its certificate checked before the
 * answer is read: with `pins` (the operator's `--daemon-ssl-fingerprint`, a hard pin) it must be
 * one of them, CA or not; without, it must verify as `probeTls` says (chain and hostname).
 */
export function httpsPost(url: string, body: string, trust: TlsTrust & { pins?: string[] } = {}): Promise<{ status: number; text: string }> {
  const u = new URL(url), host = u.hostname.replace(/^\[(.*)\]$/, '$1'), timeoutMs = trust.timeoutMs ?? 20_000;
  const ip = /^[0-9.]+$/.test(host) || host.includes(':');
  const pins = trust.pins ?? [];
  return new Promise((done, fail) => {
    let refused: string | undefined, checked = false;
    const check = (s: TLSSocket): void => {
      const c = s.getPeerCertificate();
      if (c === null || !(c.raw instanceof Uint8Array)) refused = `${host}: presented no certificate`;
      else if (pins.length > 0) refused = pins.includes(fpOf(c)) ? undefined : `${host} presents certificate sha256 ${fpOf(c)}, not the pinned ${pins.join(', ')} (--daemon-ssl-fingerprint): refused`;
      else { const bad = verdict(s, host, c); refused = bad === undefined ? undefined : `${host}: certificate sha256 ${fpOf(c)} refused, ${bad} (a node with its own certificate: pin it with --daemon-ssl-fingerprint)`; }
      checked = true;
      if (refused !== undefined) s.destroy(new Error(refused));
    };
    const req = httpsRequest(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, rejectUnauthorized: false, agent: false,
      ...(!ip && { servername: host }), ...(trust.ca !== undefined && trust.ca.length > 0 && { ca: [...rootCertificates, ...trust.ca] }),
    }, (res) => {
      if (!checked) check(res.socket);
      if (refused !== undefined) { clearTimeout(timer); fail(new Error(refused)); return; }
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { text += String(c); });
      res.on('end', () => { clearTimeout(timer); done({ status: res.statusCode ?? 0, text }); });
      res.on('error', (e: Error) => { clearTimeout(timer); fail(e); });
    });
    req.on('socket', (s) => { s.once('secureConnect', () => { check(s); }); });
    const timer = setTimeout(() => { req.destroy(new Error(`${host}: no answer in ${timeoutMs} ms`)); }, timeoutMs);
    req.on('error', (e: Error) => { clearTimeout(timer); fail(new Error(refused ?? `${host}: ${why(e)}`)); });
    req.end(body);
  });
}

// ---------------------------------------------------------------- the keeper's pins

export interface Pin { fingerprint: string; not_after: string; pinned_at: string }
export interface Pins { v: 1; mode: 'auto' | 'hard'; hard: string[]; daemons: Record<string, Pin> }

/**
 * `<keeper dir>/daemon-pins.json`, which init writes and the keeper rewrites on a re-pin. Missing
 * (a keeper from before it, or one set up by hand): hard when install.json lists
 * `daemon_ssl_fingerprints`, else auto with nothing pinned yet.
 */
export function readPins(dir: string): Pins {
  const f = join(dir, PINS_FILE);
  if (existsSync(f)) {
    const p = JSON.parse(readFileSync(f, 'utf-8')) as Partial<Pins>;
    if (p.v !== 1 || (p.mode !== 'auto' && p.mode !== 'hard') || !Array.isArray(p.hard) || typeof p.daemons !== 'object' || p.daemons === null) throw new Error(`${f}: not a sigelo-spend daemon-pins file`);
    return p as Pins;
  }
  let hard: string[] = [];
  try {
    const i = JSON.parse(readFileSync(join(dir, 'install.json'), 'utf-8')) as Record<string, unknown>;
    if (Array.isArray(i['daemon_ssl_fingerprints'])) hard = i['daemon_ssl_fingerprints'].map(String);
  } catch { /* no install.json: auto */ }
  return { v: 1, mode: hard.length > 0 ? 'hard' : 'auto', hard, daemons: {} };
}
export function writePins(dir: string, p: Pins): void {
  const f = join(dir, PINS_FILE);
  writeFileSync(`${f}.new`, JSON.stringify(p, null, 2) + '\n', { mode: 0o600 });
  chmodSync(`${f}.new`, 0o600);
  renameSync(`${f}.new`, f);
}
export const pinOf = (p: TlsProbe, at: Date = new Date()): Pin => ({ fingerprint: p.fingerprint, not_after: p.notAfter, pinned_at: at.toISOString().replace(/\.\d+Z$/, 'Z') });

/** The `daemon-ssl-allowed-fingerprints=` lines of a wallet-rpc --config-file. */
export const confPins = (text: string): string[] => [...text.matchAll(/^daemon-ssl-allowed-fingerprints=(\S+)$/gm)].map((m) => m[1]!);
/** That config file with its pin lines replaced by `fps` (every other line kept), atomically, 0600. */
export function writeConfPins(conf: string, fps: string[]): void {
  const kept = readFileSync(conf, 'utf-8').split('\n').filter((l) => !l.startsWith('daemon-ssl-allowed-fingerprints=') && l !== '');
  writeFileSync(`${conf}.new`, [...kept, ...fps.map((x) => `daemon-ssl-allowed-fingerprints=${x}`)].join('\n') + '\n', { mode: 0o600 });
  chmodSync(`${conf}.new`, 0o600);
  renameSync(`${conf}.new`, conf);
}

// `node daemontls.js probe <daemon> <timeoutMs>`: probeTlsSync's child. One JSON line.
if (process.argv[2] === 'probe' && process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  probeTls(process.argv[3] ?? '', { timeoutMs: Number(process.argv[4]) || PROBE_TIMEOUT_MS })
    .then((probe) => { process.stdout.write(JSON.stringify({ probe }) + '\n'); }, (e: unknown) => { process.stdout.write(JSON.stringify({ error: why(e) }) + '\n'); });
}
