// SPDX-License-Identifier: MIT
// The origin side of Web Bot Auth for a sigelo agent (README.md). No network: the caller hands
// in the directory it resolved. `verify` is plain Web Bot Auth (RFC 9421, Ed25519, tag
// "web-bot-auth"); `verifyDeep` also checks the sigelo bundle the directory carries (SPEC §9).
//   node verify.mjs request.json directory.json https://agent.example [now]
import { readFileSync, realpathSync } from 'node:fs';
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { decodeKey, did, verify as verifyBundle } from 'sigelo';

export const TAG = 'web-bot-auth', DIR_TAG = 'http-message-signatures-directory';
export const WELL_KNOWN = '/.well-known/http-message-signatures-directory';
export const MEDIA = 'application/http-message-signatures-directory+json';
export const GRACE = 7 * 86400;
const fail = (m) => { throw new Error(`web-bot-auth: ${m}`); };
const b64u = (b) => Buffer.from(b).toString('base64url');

/** A sigelo multibase key as an Ed25519 JWK (RFC 8037), and its RFC 7638 thumbprint: the keyid. */
export const jwk = (key) => ({ kty: 'OKP', crv: 'Ed25519', x: b64u(decodeKey(key)) });
export const thumbprint = (k) => b64u(createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${k.x}"}`).digest());
export const digest = (body) => `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;

// ── RFC 8941 structured fields: just what Signature, Signature-Input and Signature-Agent use ──
export function sfDict(s) {
  let i = 0; const out = new Map(), ws = () => { while (s[i] === ' ' || s[i] === '\t') i++; };
  const key = () => { const m = /^[a-z*][a-z0-9_\-.*]*/.exec(s.slice(i)) ?? fail(`bad structured field at ${i}: ${s}`); i += m[0].length; return m[0]; };
  const bare = () => {
    if (s[i] === '"') { let v = ''; for (i++; s[i] !== '"'; i++) { if (i >= s.length) fail('unterminated string'); if (s[i] === '\\') i++; v += s[i]; } i++; return { t: 's', v }; }
    if (s[i] === ':') { const j = s.indexOf(':', i + 1); if (j < 0) fail('unterminated byte sequence'); const v = s.slice(i + 1, j); i = j + 1; return { t: 'b', v }; }
    if (s[i] === '?') { const v = s[i + 1] === '1'; i += 2; return { t: '?', v }; }
    let m = /^-?\d{1,15}/.exec(s.slice(i)); if (m) { i += m[0].length; return { t: 'i', v: Number(m[0]) }; }
    m = /^[A-Za-z*][!#$%&'*+\-.^_`|~:/\w]*/.exec(s.slice(i)) ?? fail(`bad item at ${i}: ${s}`); i += m[0].length; return { t: 'k', v: m[0] };
  };
  const params = () => { const p = []; while (s[i] === ';') { i++; ws(); const k = key(); p.push([k, s[i] === '=' ? (i++, bare()) : { t: '?', v: true }]); } return p; };
  const item = () => {
    if (s[i] !== '(') return { ...bare(), p: params() };
    const list = []; i++;
    for (;;) { ws(); if (s[i] === ')') { i++; break; } if (i >= s.length) fail('unterminated inner list'); list.push({ ...bare(), p: params() }); if (s[i] !== ' ' && s[i] !== ')') fail('bad inner list'); }
    return { t: 'l', v: list, p: params() };
  };
  ws();
  while (i < s.length) {
    const k = key(); out.set(k, s[i] === '=' ? (i++, item()) : { t: '?', v: true, p: params() }); ws();
    if (i >= s.length) break; if (s[i++] !== ',') fail(`bad dictionary: ${s}`); ws();
  }
  return out;
}
const ser = (x) => x.t === 's' ? `"${x.v.replace(/[\\"]/g, '\\$&')}"` : x.t === 'b' ? `:${x.v}:` : x.t === '?' ? `?${x.v ? 1 : 0}` : String(x.v);
const serP = (p) => p.map(([k, v]) => (v.t === '?' && v.v === true ? `;${k}` : `;${k}=${ser(v)}`)).join('');
export const serItem = (x) => (x.t === 'l' ? `(${x.v.map((c) => ser(c) + serP(c.p)).join(' ')})` : ser(x)) + serP(x.p);
/** Inner list + parameters from plain values, in the order given (Cloudflare's: created, keyid, alg, expires, nonce, tag). */
export const sigParams = (components, params) => serItem({ t: 'l', v: components.map(([name, p = []]) => ({ t: 's', v: name, p: p.map(([k, v]) => [k, v === true ? { t: '?', v } : { t: 's', v }]) })),
  p: Object.entries(params).filter(([, v]) => v !== undefined).map(([k, v]) => [k, { t: typeof v === 'number' ? 'i' : 's', v }]) });

// ── RFC 9421 §2: component values and the signature base ─────────────────────────────────────
const lower = (h) => Object.fromEntries(Object.entries(h ?? {}).map(([k, v]) => [k.toLowerCase(), String(v).trim()]));
function value(msg, name, p) {
  const u = () => new URL(msg.url), h = lower(msg.headers), keyp = p.find(([k]) => k === 'key');
  if (name === '@authority') return u().host;                // lowercased, default port dropped (§2.2.3)
  if (name === '@method') return msg.method.toUpperCase();
  if (name === '@path') return u().pathname;
  if (name === '@target-uri') return u().href;
  if (name.startsWith('@')) fail(`component ${name} is not supported here`);
  const v = h[name] ?? fail(`covered header ${name} is missing`);
  if (!keyp) return v;
  const m = sfDict(v).get(keyp[1].v) ?? fail(`${name} has no member ${keyp[1].v}`);
  return serItem(m);
}
/** `components` as parsed items ({ v: name, p: params }); `params` the serialized "@signature-params" value. */
export function signatureBase(msg, req, components, params) {
  const lines = components.map((c) => {
    if (c.p.some(([k]) => !['key', 'req'].includes(k))) fail(`component parameter on ${c.v} is not supported`);
    const from = c.p.some(([k]) => k === 'req') ? req : msg;
    return `${serItem({ ...c, p: c.p })}: ${value(from ?? fail('a ;req component needs the request'), c.v, c.p.filter(([k]) => k !== 'req'))}`;
  });
  const base = [...lines, `"@signature-params": ${params}`].join('\n');
  if (!/^"[\x20-\x7e\n]*$/.test(base)) fail('signature base is not printable ASCII');
  return base;
}

const spki = (x) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(x, 'base64url')]), format: 'der', type: 'spki' });
const usable = (k, now) => k?.kty === 'OKP' && k.crv === 'Ed25519' && typeof k.x === 'string' && Buffer.from(k.x, 'base64url').length === 32
  && (k.kid === undefined || k.kid === thumbprint(k)) && !(Number.isInteger(k.exp) && now >= k.exp) && !(Number.isInteger(k.nbf) && now < k.nbf);

/** One labelled signature over `msg` (request, or response with `req`), checked with a key of `keys` (JWKs). */
export function checkSignature(msg, req, keys, { tag, now, label, skew = 60 }) {
  const h = lower(msg.headers), inputs = sfDict(h['signature-input'] ?? fail('no Signature-Input')), sigs = sfDict(h['signature'] ?? fail('no Signature'));
  const labels = [...inputs].filter(([l, x]) => (label === undefined || l === label) && x.t === 'l' && x.p.some(([k, v]) => k === 'tag' && v.v === tag));
  if (labels.length !== 1) fail(`expected one signature tagged ${tag}, found ${labels.length}`);
  const [lab, input] = labels[0], P = Object.fromEntries(input.p.map(([k, v]) => [k, v.v]));
  if (P.alg !== undefined && P.alg !== 'ed25519') fail(`alg ${P.alg} is not ed25519`);
  if (!Number.isInteger(P.created) || !Number.isInteger(P.expires) || P.created > P.expires) fail('created and expires must be integers, created ≤ expires');
  if (now >= P.expires) fail(`signature expired at ${P.expires} (now ${now})`);
  if (P.created > now + skew) fail(`signature created in the future (${P.created})`);
  if (typeof P.keyid !== 'string') fail('no keyid');
  const key = keys.find((k) => usable(k, now) && thumbprint(k) === P.keyid) ?? fail(`keyid ${P.keyid} names no usable key in the directory`);
  const sig = sigs.get(lab); if (sig?.t !== 'b') fail(`no Signature for ${lab}`);
  const base = signatureBase(msg, req, input.v, serItem({ t: 'l', v: input.v, p: input.p }));
  if (!edVerify(null, Buffer.from(base, 'ascii'), spki(key.x), Buffer.from(sig.v, 'base64'))) fail('bad signature');
  return { label: lab, keyid: P.keyid, created: P.created, expires: P.expires, nonce: P.nonce, components: input.v.map((c) => serItem(c)), base };
}

/**
 * Plain Web Bot Auth: `req` = { method, url, headers }, `directory` = the JWKS the caller resolved
 * from `origin` (the Signature-Agent URL; lookup is keyed on that pair, protocol draft §5.4).
 * Throws with the failing check; returns what verified. Legacy sf-string and dictionary forms both.
 */
export function verify(req, directory, { origin, now = Math.floor(Date.now() / 1000), label } = {}) {
  const r = checkSignature(req, undefined, directory?.keys ?? fail('directory has no keys'), { tag: TAG, now, label });
  if (!r.components.includes('"@authority"') && !r.components.includes('"@target-uri"')) fail('signature covers neither @authority nor @target-uri');
  const agents = r.components.filter((c) => c.startsWith('"signature-agent"'));
  if (agents.length !== 1) fail('signature must cover exactly one signature-agent');
  const sa = lower(req.headers)['signature-agent'], m = /;key="([^"]*)"$/.exec(agents[0]);
  const url = m ? sfDict(sa).get(m[1])?.v : sa.startsWith('"') ? JSON.parse(sa) : fail('Signature-Agent is neither a string nor covered by key');
  if (typeof url !== 'string' || !url.startsWith('https://')) fail('Signature-Agent is not an https URL');
  if (origin === undefined || new URL(url).origin !== new URL(origin).origin) fail(`Signature-Agent ${url} is not the origin this directory came from (${origin})`);
  return { ...r, agent: new URL(url).origin };
}

/** The directory response's possession proofs (protocol draft App. B): which keyids signed this body for `authority`. */
export function verifyDirectory(res, { authority, now }) {
  const h = lower(res.headers);
  if (h['content-digest'] !== digest(res.body)) fail('Content-Digest does not match the body');
  const keys = JSON.parse(res.body).keys, req = { method: 'GET', url: `https://${authority}${WELL_KNOWN}`, headers: {} }, proven = [];
  for (const [label, x] of sfDict(h['signature-input'] ?? '')) if (x.p.some(([k, v]) => k === 'tag' && v.v === DIR_TAG)) proven.push(checkSignature(res, req, keys, { tag: DIR_TAG, now, label }).keyid);
  return proven;
}

/**
 * Plain `verify`, then the sigelo side with no network: the bundle the directory carries verifies
 * (SPEC §9), names the directory's DID, and the request's key is that DID's current key, or the
 * previous one for `grace` seconds after the rotation. Returns the §9.1 result too, and the
 * attestations from `operator` (a DID) if given. It reports; whom to trust is the caller's call.
 */
export function verifyDeep(req, directory, { origin, now = Math.floor(Date.now() / 1000), label, grace = GRACE, operator } = {}) {
  const plain = verify(req, directory, { origin, now, label });
  const s = directory.sigelo ?? fail('directory carries no sigelo member');
  const r = verifyBundle(s.bundle, now);
  if (r.did !== s.did) fail("sigelo.did is not the bundle's current DID");
  const gens = [s.bundle.genesis, ...s.bundle.rotations.map((x) => x.next_genesis)], gen = (d) => gens.find((g) => did(g) === d);
  const cur = gen(r.did), prev = r.chain.length > 1 ? gen(r.chain.at(-2)) : undefined;
  let key;
  if (plain.keyid === thumbprint(jwk(cur.key))) key = 'current';
  else if (prev && plain.keyid === thumbprint(jwk(prev.key))) {
    const rot = s.bundle.rotations.find((x) => x.body.id === r.chain.at(-2) && x.body.next === r.did);
    if (!(now < rot.body.iat + grace)) fail(`keyid is ${r.chain.at(-2)}'s key, rotated away at ${rot.body.iat}: grace of ${grace}s is over`);
    key = 'previous';
  } else fail(`keyid ${plain.keyid} is not a key of ${r.did}`);
  return { ...plain, did: r.did, key, sigelo: r, operator: operator ? r.attestations[operator] ?? [] : undefined };
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) {
  const [reqF, dirF, origin, now] = process.argv.slice(2), read = (f) => JSON.parse(readFileSync(f, 'utf8'));
  const dir = read(dirF), d = typeof dir.body === 'string' ? JSON.parse(dir.body) : dir, opts = { origin, now: now ? Number(now) : undefined };
  console.log(JSON.stringify(d.sigelo ? verifyDeep(read(reqF), d, opts) : verify(read(reqF), d, opts), null, 2));
}
