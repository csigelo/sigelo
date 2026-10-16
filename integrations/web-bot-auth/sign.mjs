// SPDX-License-Identifier: MIT
// The agent side: sign one HTTP request for Web Bot Auth with the sigelo identity key, through
// the signer (`sigelo-agent sign-http`); this file never reads the key.
//   node sign.mjs GET https://origin.example/path https://agent.example > request.json
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { TAG, jwk, sfDict, sigParams, signatureBase, thumbprint } from './verify.mjs';

/**
 * A signer is { key, signHttp(base) → base64 }: `key` the identity's current multibase key,
 * `signHttp` Ed25519 over an RFC 9421 base. This one asks the sigelo-agent CLI (key providers
 * file and keychain; the key agent signs sigelo bodies only).
 */
export function cliSigner(bin = process.env.SIGELO_AGENT ?? 'sigelo-agent') {
  const run = (args, input) => {
    const r = spawnSync(bin, args, { input, encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`web-bot-auth: ${bin} ${args[0]}: ${r.stderr || r.error?.message}`);
    return JSON.parse(r.stdout);
  };
  return { key: run(['whoami']).genesis.key, signHttp: (base) => run(['sign-http', '-'], base).sig };
}

/** Low level: sign `components` over `msg` (and `req` for ;req) under `label`; returns the two header values. */
export function signFields(signer, msg, { label, components, params, req }) {
  const p = sigParams(components, params), items = sfDict(`x=${p}`).get('x').v;
  const base = signatureBase(msg, req, items, p);
  return { 'signature-input': `${label}=${p}`, signature: `${label}=:${signer.signHttp(base)}:` };
}

/**
 * Sign `req` = { method, url, headers } as `agent` (the https origin serving the directory).
 * `form`: "string" sends `Signature-Agent: "https://…"`, what Cloudflare verifies today (its docs,
 * 2026-10-08); "dictionary" sends `sig1="https://…"`, what the IETF draft says signers MUST send.
 * Returns the request with Signature-Agent, Signature-Input and Signature added.
 */
export function signRequest(signer, req, { agent, now = Math.floor(Date.now() / 1000), ttl = 60, label = 'sig1', form = 'string',
  nonce = randomBytes(64).toString('base64'), cover = [] } = {}) {
  if (typeof agent !== 'string' || new URL(agent).protocol !== 'https:' || new URL(agent).origin !== agent.replace(/\/$/, '')) throw new Error('web-bot-auth: agent must be an https origin');
  const sa = form === 'dictionary' ? `${label}="${agent}"` : `"${agent}"`;
  const headers = { ...req.headers, 'signature-agent': sa };
  const components = [['@authority'], ...cover.map((c) => [c]), form === 'dictionary' ? ['signature-agent', [['key', label]]] : ['signature-agent']];
  const params = { created: now, keyid: thumbprint(jwk(signer.key)), alg: 'ed25519', expires: now + ttl, nonce: nonce ?? undefined, tag: TAG };
  return { ...req, headers: { ...headers, ...signFields(signer, { ...req, headers }, { label, components, params }) } };
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) {
  const [method, url, agent] = process.argv.slice(2);
  if (!agent) { console.error('usage: node sign.mjs <METHOD> <url> <https://agent-origin>'); process.exit(2); }
  console.log(JSON.stringify(signRequest(cliSigner(), { method, url, headers: {} }, { agent }), null, 2));
}
