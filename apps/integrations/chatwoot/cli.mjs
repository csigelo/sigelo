#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// sigelo-chatwoot <config.json>: the bridge of bridge.mjs, polling the spool and serving the webhook.
// Exit 2: bad config (the check is named on stderr). SIGINT or SIGTERM: exit 0.
import { realpathSync, statSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { Bridge } from './bridge.mjs';

const USAGE = 'usage: sigelo-chatwoot <config.json>   (README.md: chatwoot, account_id, inbox_id, token_file, webhook_secret_file, identity, allow)';
const home = (p) => (typeof p === 'string' && p.startsWith('~/') ? homedir() + p.slice(1) : p);

/** A secret from a file only the owner can read (as ssh does); trimmed. */
export function secretFile(path, what) {
  if (typeof path !== 'string') throw new Error(`${what}: missing`);
  const st = statSync(path);
  if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) throw new Error(`${what}: ${path} is readable by others (chmod 600)`);
  const s = readFileSync(path, 'utf8').trim();
  if (s === '') throw new Error(`${what}: ${path} is empty`);
  return s;
}

/** config.json → Bridge options and where to listen. Throws naming the field. */
export function load(file) {
  const c = JSON.parse(readFileSync(file, 'utf8'));
  let u;
  try { u = new URL(c.chatwoot); } catch { throw new Error('chatwoot: the Chatwoot base URL, https://…'); }
  const loop = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loop)) throw new Error('chatwoot: https only (the token would cross in the clear), http only on loopback');
  for (const k of ['account_id', 'inbox_id']) if (!Number.isSafeInteger(c[k]) || c[k] < 1) throw new Error(`${k}: a whole number (the numeric id from the Chatwoot URL)`);
  if (!Array.isArray(c.allow) || !c.allow.every((x) => typeof x === 'string')) throw new Error('allow: a list of contact names or DIDs (empty: nothing bridged)');
  const identity = home(c.identity ?? process.env.SIGELO_IDENTITY ?? '~/.config/moadim/sigelo.local.json');
  const [host, port] = String(c.listen ?? '127.0.0.1:7330').split(/:(?=\d+$)/);
  return {
    opts: {
      base: u.href, account: c.account_id, inbox: c.inbox_id, allow: c.allow, identity,
      token: secretFile(home(c.token_file), 'token_file'), secret: secretFile(home(c.webhook_secret_file), 'webhook_secret_file'),
      spool: home(c.spool ?? `${identity.replace(/\.json$/, '')}.spool`), cli: c.sigelo_agent ?? 'sigelo-agent',
    },
    host, port: Number(port), path: c.path ?? '/chatwoot',
  };
}

const main = (() => { try { return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })();
if (main) {
  const file = process.argv[2];
  if (file === undefined || file.startsWith('-')) { console.error(USAGE); process.exit(2); }
  let cfg, b;
  try { cfg = load(file); b = new Bridge(cfg.opts); } catch (e) { console.error(`sigelo-chatwoot: ${e.message}`); process.exit(2); }
  if (cfg.opts.allow.length === 0) b.log('allow is empty: nothing is bridged');
  const stop = b.run();
  const srv = createServer(b.handler(cfg.path)).listen(cfg.port, cfg.host, () => b.log(`spool ${cfg.opts.spool} → ${cfg.opts.base}; webhook http://${cfg.host}:${cfg.port}${cfg.path}`));
  const bye = () => { stop(); srv.close(); process.exit(0); };
  process.on('SIGINT', bye).on('SIGTERM', bye);
}
