// SPDX-License-Identifier: MIT
// The key agent's wire protocol, sigelo-key-agent/0 (design/key-providers.md §4.2): one JSON object
// per line, UTF-8, read with sigelo's strict parser (duplicate keys refused), one reply per request.
// At most 2 MiB a line, not the plan's 64 KB: a message body the agent signs is up to 1 MiB padded
// (contact/envelope.mjs MAX_PADDED), and 64 KB refused every file chunk and long message. Each op has exactly its fields; anything else is `request_invalid`. No request
// returns a key or deletes one. Also the libraries this package runs on: from a clone, the sibling
// directories (ts/dist, adapters/moadim's .ts sources); installed, the packages sigelo and
// sigelo-agent, decided by where this file is, as integrations/mcp/server.mjs decides it.
import { sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const INSTALLED = fileURLToPath(import.meta.url).split(sep).includes('node_modules');
const lib = (pkg, repo) => import(INSTALLED ? pkg : new URL(repo, import.meta.url).href);
/** sigelo: parseBytes, keygen, rotate, sign, verifySig, did, structure. */
export const S = await lib('sigelo', '../ts/dist/sigelo.js');
/** sigelo-agent: challengeDid and head (the core), wrap and unwrap (keychain), socketPath (keyclient). */
export const core = await lib('sigelo-agent/dist/sigelo-agent.js', '../adapters/moadim/sigelo-agent.ts');
export const keychain = await lib('sigelo-agent/dist/sigelo-agent-keychain.js', '../adapters/moadim/sigelo-agent-keychain.ts');
export const keyclient = await lib('sigelo-agent/dist/sigelo-agent-keyclient.js', '../adapters/moadim/sigelo-agent-keyclient.ts');

export const PROTOCOL = 'sigelo-key-agent/0';
export const MAX_LINE = 2 * 1024 * 1024;
/** Each op and its fields, all required. */
export const OPS = {
  list: [], create: ['recovery'], import: ['genesis', 'seed'], pubkey: ['did'],
  sign: ['did', 'body'], rotate: ['did', 'to'], commit: ['did'], lock: [],
};
/** Where `rotate` may go: a software key here; hardware arrives with K4 (fido2) and K5 (card). */
export const ROTATE_TO = { software: null, fido2: 'K4', card: 'K5' };

/** A refusal: the reply `{ ok: false, code, detail }`. */
export class Refusal extends Error {
  constructor(code, detail) { super(`${code}: ${detail}`); this.code = code; this.detail = detail; }
}
export const refuse = (code, detail) => { throw new Refusal(code, detail); };

/** One request line (bytes, the newline excluded): the request, or a `request_invalid` refusal. */
export function parseRequest(bytes) {
  if (bytes.length > MAX_LINE) refuse('request_too_large', `a request is at most ${MAX_LINE} bytes`);
  let req;
  try { req = S.parseBytes(bytes); } catch (e) { refuse('request_invalid', `not strict JSON (${e.message})`); }
  if (req === null || typeof req !== 'object' || Array.isArray(req)) refuse('request_invalid', 'a request is a JSON object');
  const fields = OPS[typeof req.op === 'string' && Object.hasOwn(OPS, req.op) ? req.op : ''];
  if (!fields) refuse('request_invalid', `op ${JSON.stringify(req.op)} is not one of ${Object.keys(OPS).join(', ')}`);
  const extra = Object.keys(req).filter((k) => k !== 'op' && !fields.includes(k)), missing = fields.filter((k) => !(k in req));
  if (extra.length || missing.length) refuse('request_invalid', `${req.op} takes exactly ${fields.join(', ') || 'no field'}${extra.length ? `; extra: ${extra.join(', ')}` : ''}${missing.length ? `; missing: ${missing.join(', ')}` : ''}`);
  for (const k of ['did', 'seed', 'to']) if (k in req && typeof req[k] !== 'string') refuse('request_invalid', `${k} is a string`);
  if ('recovery' in req && req.recovery !== null && typeof req.recovery !== 'string') refuse('request_invalid', 'recovery is "sha256:…", "z6Mk…" or null');
  if ('seed' in req && !/^[0-9a-f]{64}$/.test(req.seed)) refuse('request_invalid', 'seed is 64 lowercase hex');
  if ('to' in req && !Object.hasOwn(ROTATE_TO, req.to)) refuse('request_invalid', `to is one of ${Object.keys(ROTATE_TO).join(', ')}`);
  return req;
}

/** The reply line: compact JSON and a newline; the refusal for any error (`agent_error` for a bug). */
export const encode = (reply) => `${JSON.stringify(reply)}\n`;
export const refusalOf = (e) => {
  const code = e instanceof Refusal ? e.code : typeof e?.check === 'string' ? e.check : 'agent_error';
  const msg = e instanceof Refusal ? e.detail : String(e?.message ?? e);
  return { ok: false, code, detail: msg.startsWith(`${code}: `) ? msg.slice(code.length + 2) : msg };
};
