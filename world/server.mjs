#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// world/server.mjs — sigelo.io's own world: proves control of a DID (SPEC §5.2), issues one
// `admission: "open"` attestation (§5), a self-reported conformance attestation, verifies bundles
// (§9) and serves the verifier as remote MCP at /mcp (world/mcp.mjs), over loopback HTTP behind nginx.
// No crypto here: every check is the `sigelo` library (ts/). See world/README.md.
//
//   node world/server.mjs                                    serve (env below)
//   node world/server.mjs keygen <sha256:commitment> <out>   issuer identity → <out> (0600), genesis on stdout
//   node world/server.mjs recovery-key <out>                 an off-site recovery key → <out> (0600), commitment on stdout
//   node world/server.mjs rotate <rotations.json|-> <current-genesis> <next-genesis> <recovery-key>
//                                                            recovery-rotate the issuer: the new rotations.json on stdout
//
// Env: SIGELO_WORLD_KEY (issuer file, default /var/lib/sigelo-world/issuer.json), SIGELO_WORLD_STATE
// (default: the key's directory), SIGELO_WORLD_PORT (default 8790; 0 = any), SIGELO_WORLD_VECTORS
// (default ../test-vectors.json beside world/: deploy.sh ships the site's copy). Binds 127.0.0.1 only.
// State: nonces.json (the outstanding challenges, a ring of RING) and attestations.jsonl (what was
// issued, append-only, never served). No client address ever reaches this process (nginx sends none).
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, appendFileSync, renameSync, existsSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { attest, canonicalize, commitmentOf, did, keygen, multibase, parse, parseBytes, rotate, structure, verify, verifySig } from '../ts/dist/sigelo.js';
import { countCases, readSummary } from './conformance.mjs';
import { mcp } from './mcp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(join(HERE, '../ts/package.json'), 'utf8')).version;
const VERIFIER = `sigelo ${VERSION}`, RUNNER = `sigelo-verify ${VERSION}`;
const CTX = 'sigelo.io', CONF_CTX = 'sigelo.io/conformance', V = 'sigelo/0';
const TTL = 300, DAY = 86400, LIFETIME = 90 * DAY, MAX_BODY = 256 * 1024, RING = 2048;
const DID_RE = /^did:sigelo:z[1-9A-HJ-NP-Za-km-z]{40,50}$/;
const nowS = () => Math.floor(Date.now() / 1000);
const load = (p) => parseBytes(readFileSync(p));
const save = (p, v, mode = 0o644) => { writeFileSync(p + '.tmp', typeof v === 'string' ? v : JSON.stringify(v), { mode }); renameSync(p + '.tmp', p); };
const fail = (status, error) => Object.assign(new Error(error), { status });

const [cmd, ...args] = process.argv.slice(2);
if (cmd === 'keygen' || cmd === 'recovery-key') {
  const out = args[cmd === 'keygen' ? 1 : 0];
  if (!out || (cmd === 'keygen' && !/^sha256:[0-9a-f]{64}$/.test(args[0] ?? ''))) { console.error('usage: see the header of world/server.mjs'); process.exit(2); }
  if (existsSync(out)) { console.error(`${out} exists: refusing to overwrite a key`); process.exit(1); }
  // A recovery key is an Ed25519 key pair; keygen makes one (its genesis is thrown away).
  const k = keygen({ recovery: cmd === 'keygen' ? args[0] : new Uint8Array(32) });
  const secret = Buffer.from(k.secret).toString('hex');
  writeFileSync(out, JSON.stringify(cmd === 'keygen' ? { genesis: k.genesis, secret } : { key: k.key, commitment: commitmentOf(k.key), secret }) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(cmd === 'keygen' ? JSON.stringify(k.genesis) : commitmentOf(k.key));
  process.exit(0);
}
if (cmd === 'rotate') {
  const [rotPath, curPath, nextPath, recPath] = args;
  if (!recPath) { console.error('usage: see the header of world/server.mjs'); process.exit(2); }
  const cur = load(curPath), next = load(nextPath);
  const chain = rotPath === '-' ? { genesis: cur, rotations: [] } : load(rotPath);
  const r = rotate({ genesis: cur, next_genesis: next, iat: nowS(), reason: 'recovery', secret: Uint8Array.from(Buffer.from(load(recPath).secret, 'hex')) });
  chain.rotations.push(r);
  // The published chain must resolve to the new issuer, exactly as a verifier walks it.
  const res = verify({ v: V, typ: 'bundle', genesis: chain.genesis, rotations: chain.rotations, bindings: [], attestations: [], issuers: [] }, nowS());
  if (res.did !== did(next)) throw new Error(`the chain resolves to ${res.did}, not ${did(next)}`);
  console.log(JSON.stringify(chain, null, 2));
  process.exit(0);
}
if (cmd !== undefined) { console.error('usage: see the header of world/server.mjs'); process.exit(2); }

const KEY = process.env.SIGELO_WORLD_KEY || '/var/lib/sigelo-world/issuer.json';
const STATE = process.env.SIGELO_WORLD_STATE || dirname(KEY);
const PORT = Number(process.env.SIGELO_WORLD_PORT ?? 8790);
const world = load(KEY);
structure(world.genesis, 'genesis');
const ISS = did(world.genesis), SECRET = Uint8Array.from(Buffer.from(world.secret, 'hex'));
const NONCES = join(STATE, 'nonces.json'), ISSUED = join(STATE, 'attestations.jsonl');
// The vectors the site serves (/test-vectors.json, /raw/test-vectors.json): a conformance claim
// names their sha256 and must have run exactly as many cases as they make.
const VECTORS = process.env.SIGELO_WORLD_VECTORS || join(HERE, '../test-vectors.json');
const vectors = existsSync(VECTORS) ? (() => { const b = readFileSync(VECTORS); return { sha256: createHash('sha256').update(b).digest('hex'), cases: countCases(JSON.parse(b)) }; })() : null;   // JSON.parse, as grade-verifier.mjs: the vectors hold __proto__ cases on purpose

// Outstanding challenges: nonce -> { did, exp }. Insertion-ordered, so the oldest is evicted first.
const pending = new Map(existsSync(NONCES) ? load(NONCES).filter(([, , exp]) => exp > nowS()).map(([n, d, exp]) => [n, { did: d, exp }]) : []);
const persist = () => save(NONCES, [...pending].map(([n, p]) => [n, p.did, p.exp]), 0o600);
// Idempotence and counts, rebuilt from the append-only log.
const last = new Map(), lastConf = new Map(); let issued = 0;
const confKey = (sub, c) => `${sub}\n${c.implementation}\n${c.vectors}`;
const remember = (a) => { const c = a.body.claims.conformance; if (c) lastConf.set(confKey(a.body.sub, c), a); else last.set(a.body.sub, a); };
if (existsSync(ISSUED)) for (const line of readFileSync(ISSUED, 'utf8').split('\n')) if (line) { remember(JSON.parse(line)); issued++; }

const challengeBody = (d, nonce) => ({ v: V, typ: 'challenge', did: d, ctx: CTX, nonce });

function challenge(url) {
  const d = url.searchParams.get('did') ?? '';
  if (!DID_RE.test(d)) throw fail(400, 'did: want ?did=did:sigelo:z… (your current DID, in full)');
  const nonce = multibase(randomBytes(16)), now = nowS();
  for (const [n, p] of pending) if (p.exp <= now || pending.size >= RING) pending.delete(n); else break;
  pending.set(nonce, { did: d, exp: now + TTL });
  persist();
  return challengeBody(d, nonce);
}

// The current key of the DID that answers: from a verified bundle (its chain's head), or from
// the genesis itself. Either way the DID is recomputed from bytes, never taken as told (§4).
function currentKey(req) {
  if (req.bundle !== undefined) {
    let r;
    try { r = verify(req.bundle, nowS()); } catch (e) { throw fail(422, `bundle: REJECT: ${e.message}`); }
    if (r.did !== req.did) throw fail(400, `did is not the bundle's current DID (${r.did})`);
    return { key: [req.bundle.genesis, ...req.bundle.rotations.map((x) => x.next_genesis)].find((g) => did(g) === r.did).key, bundle_valid: true };
  }
  if (req.genesis === undefined) throw fail(400, 'send your bundle (preferred) or your current genesis with the signature');
  try { structure(req.genesis, 'genesis'); } catch (e) { throw fail(400, `genesis: ${e.message}`); }
  if (did(req.genesis) !== req.did) throw fail(400, `did does not match the genesis sent (it hashes to ${did(req.genesis)})`);
  return { key: req.genesis.key, bundle_valid: false };
}

// The §5.2 answer: the challenge back (single use), the DID, a signature under its current key.
// → bundle_valid. Shared by /world/attest and /world/conformance.
function proveControl(req) {
  if (typeof req.did !== 'string' || typeof req.sig !== 'string') throw fail(400, 'want { challenge, did, sig, bundle | genesis }');
  const ch = req.challenge, nonce = typeof ch === 'string' ? ch : ch?.nonce;
  const p = typeof nonce === 'string' && pending.get(nonce);
  if (!p) throw fail(409, 'challenge unknown, expired or already answered: GET /world/challenge again');
  pending.delete(nonce); persist();                       // single use, whatever happens next
  const now = nowS(), body = challengeBody(p.did, nonce);
  if (p.exp <= now) throw fail(409, 'challenge expired (5 minutes): GET /world/challenge again');
  if (p.did !== req.did) throw fail(400, 'did is not the DID this challenge was issued to');
  if (typeof ch === 'object' && canonicalize(ch) !== canonicalize(body)) throw fail(400, 'challenge differs from the one issued: send it back unmodified');
  const { key, bundle_valid } = currentKey(req);
  if (!verifySig(key, body, req.sig)) throw fail(400, 'sig does not verify against the current key over the challenge (SPEC §3 signing input)');
  return { now, bundle_valid };
}

function issue(a) { appendFileSync(ISSUED, JSON.stringify(a) + '\n', { mode: 0o600 }); remember(a); issued++; return { attestation: a, issuer: world.genesis }; }

function attestation(req) {
  const { now, bundle_valid } = proveControl(req);
  const prev = last.get(req.did);
  if (prev && now - prev.body.iat < DAY) return { attestation: prev, issuer: world.genesis };   // idempotent for 24 h
  const a = attest({ secret: SECRET, iss: ISS, sub: req.did, iat: now, exp: now + LIFETIME, ctx: CTX, admission: 'open',
    claims: { seen: new Date(now * 1000).toISOString().slice(0, 10), bundle_valid, verifier: VERIFIER } });
  return issue(a);
}

// Self-reported conformance (world/README.md): the world cannot run the candidate, so it checks
// what it can — the vectors are the ones it ships, the pasted summary is a clean run of all of
// them — before the §5.2 answer, so a fixable payload does not use up the challenge.
const TEXT = (v, max) => typeof v === 'string' && v.length >= 1 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
function conformance(req) {
  if (!vectors) throw fail(503, 'this world has no vectors file installed');
  const im = req.implementation;
  if (im === null || typeof im !== 'object' || Array.isArray(im) || !TEXT(im.name, 64) || !/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$/.test(im.version ?? '')
    || !TEXT(im.language, 32) || (im.url !== undefined && !(TEXT(im.url, 200) && /^https:\/\/[^\s]+$/.test(im.url))) || Object.keys(im).some((k) => !['name', 'version', 'language', 'url'].includes(k)))
    throw fail(400, 'implementation: want { name (≤ 64), version ([0-9A-Za-z.+_-], ≤ 32), language (≤ 32), url? (https://…) }');
  if (typeof req.vectors_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(req.vectors_sha256)) throw fail(400, 'vectors_sha256: the lowercase hex sha256 of the test-vectors.json your runner used');
  if (req.vectors_sha256 !== vectors.sha256) throw Object.assign(fail(409, `vectors_sha256 is not the vectors this world ships: fetch https://sigelo.io/test-vectors.json (sha256 ${vectors.sha256}) and run again`), { extra: { vectors_sha256: vectors.sha256 } });
  let score;
  try { score = readSummary(req.results, vectors.cases); } catch (why) { if (typeof why !== 'string') throw why; throw fail(422, why); }
  const { now } = proveControl(req);
  const claim = { implementation: `${im.name} ${im.version}`, vectors: vectors.sha256, passed: score.passed, total: score.total, self_reported: true, runner: RUNNER };
  const prev = lastConf.get(confKey(req.did, claim));
  if (prev && now - prev.body.iat < DAY) return { attestation: prev, issuer: world.genesis };   // idempotent for 24 h
  return issue(attest({ secret: SECRET, iss: ISS, sub: req.did, iat: now, exp: now + LIFETIME, ctx: CONF_CTX, admission: 'open', claims: { conformance: claim } }));
}

function verifyBundle(req) {
  const bundle = req?.typ === 'bundle' ? req : req?.bundle;
  try { return verify(bundle, Number.isSafeInteger(req?.now) ? req.now : nowS()); }
  catch (e) { throw fail(422, `REJECT: ${e.message}`); }
}

const ROUTES = {
  'GET /world/': () => ({ issuer: ISS, ctx: CTX, genesis: world.genesis, endpoints: { challenge: 'GET /world/challenge?did=…', attest: 'POST /world/attest',
    conformance: 'POST /world/conformance', verify: 'POST /world/verify', mcp: 'POST /mcp', stats: 'GET /world/stats', genesis: 'GET /world/genesis.json',
    rotations: 'GET /world/rotations.json' }, ...(vectors && { vectors_sha256: vectors.sha256, conformance_cases: vectors.cases }) }),
  'GET /world/challenge': (_, url) => challenge(url),
  'GET /world/genesis.json': () => world.genesis,          // nginx serves the published copy; this is the fallback
  'GET /world/stats': () => ({ issuer: ISS, ctx: CTX, attestations: issued, subjects: last.size }),
  'POST /world/attest': attestation,
  'POST /world/conformance': conformance,
  'POST /world/verify': verifyBundle,
};

const readBody = (req) => new Promise((resolve, reject) => {
  if (Number(req.headers['content-length'] ?? 0) > MAX_BODY) return reject(fail(413, `body over ${MAX_BODY} bytes`));
  const parts = []; let n = 0;
  req.on('data', (c) => { n += c.length; if (n > MAX_BODY) { reject(fail(413, `body over ${MAX_BODY} bytes`)); req.destroy(); } else parts.push(c); });
  req.on('end', () => resolve(Buffer.concat(parts)));
  req.on('error', reject);
});

const mcpHandle = mcp({ parse, parseBytes, verify, version: VERSION });

const server = createServer(async (req, res) => {
  const send = (status, v) => { if (res.headersSent) return; res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(v) + '\n'); };
  try {
    const url = new URL(req.url, 'http://world');
    if (url.pathname === '/mcp') {
      let raw = Buffer.alloc(0);
      if (req.method === 'POST') {
        try { raw = await readBody(req); } catch (e) { if (e.status !== 413) throw e; return send(413, { jsonrpc: '2.0', id: null, error: { code: -32600, message: e.message } }); }
      }
      const r = mcpHandle(req.method, req.headers, raw);
      res.writeHead(r.status, r.headers); return res.end(r.body);
    }
    const route = ROUTES[`${req.method} ${url.pathname}`];
    if (!route) throw fail(Object.keys(ROUTES).some((k) => k.endsWith(' ' + url.pathname)) ? 405 : 404, `no ${req.method} ${url.pathname}; see GET /world/`);
    let body;
    if (req.method === 'POST') {
      const raw = await readBody(req);
      try { body = parseBytes(raw); } catch (e) { throw fail(400, `body is not strict JSON: ${e.message}`); }   // duplicate keys, bad UTF-8: refused (§3)
      if (body === null || typeof body !== 'object' || Array.isArray(body)) throw fail(400, 'body is not a JSON object');
    }
    send(200, route(body, url));
  } catch (e) {
    if (!e.status) console.error(e);
    send(e.status ?? 500, { error: e.status ? e.message : 'internal error', ...e.extra });
  }
});
server.listen(PORT, '127.0.0.1', () => console.log(`sigelo world ${ISS} (ctx ${CTX}) on 127.0.0.1:${server.address().port}`));
for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => server.close(() => process.exit(0)));
