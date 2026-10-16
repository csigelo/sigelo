// SPDX-License-Identifier: MIT
// `node test.mjs` → ALL PASS (N). No network. Cloudflare's Ed25519 vectors and the IETF draft's
// signed directory response reproduced byte for byte; then a sigelo identity end to end.
// `node test.mjs --write` regenerates example/.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, sign as edSign } from 'node:crypto';
import { attest, encodeKey, keygen, multibase, rotate, sign, signingInput, verifySig } from 'sigelo';
import { verify, verifyDeep, verifyDirectory, thumbprint, jwk, digest, WELL_KNOWN } from './verify.mjs';
import { signFields, signRequest } from './sign.mjs';
import { directory, response } from './directory.mjs';

let fails = 0, passes = 0;
const ok = (c, m) => { c ? passes++ : fails++; console.log(`${c ? 'ok  ' : 'FAIL'} ${m}`); };
const throws = (f, re, m) => { try { f(); ok(false, `${m} (accepted)`); } catch (e) { ok(re.test(e.message), `${m}: ${e.message}`); } };
const seed = (n) => new Uint8Array(32).fill(n);
/** Test-only stand-in for sigelo-agent's signer (adapters/moadim/sigelo-agent-keys.ts signHttp): seed in, base64 out. */
const seedSigner = (s, key) => ({ key, signHttp: (base) => {
  if (!base.startsWith('"')) throw new Error('not an RFC 9421 base');
  return edSign(null, Buffer.from(base, 'ascii'), createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(s)]), format: 'der', type: 'pkcs8' })).toString('base64');
} });

// ── Cloudflare's vectors (cloudflare-vectors.json), byte for byte ──────────────────────────────
const V = JSON.parse(readFileSync(new URL('./cloudflare-vectors.json', import.meta.url), 'utf8'));
const tk = seedSigner(Buffer.from(V.key.d, 'base64url'), encodeKey(Buffer.from(V.key.x, 'base64url')));
ok(thumbprint(jwk(tk.key)) === 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U', 'RFC 9421 B.1.4 test key: thumbprint poqk…r0U');
for (const t of V.thumbprint) ok(thumbprint(JSON.parse(t.jwk)) === t.thumbprint, `jsonwebkey-thumbprint vector ${t.name}: ${t.thumbprint}`);
const testDir = { keys: [{ kty: 'OKP', crv: 'Ed25519', x: V.key.x }] }, AGENT = 'https://signature-agent.test';
for (const [set, vs] of [['architecture_v1', V.architecture_v1], ['architecture_v2', V.architecture_v2]]) for (const v of vs) {
  const created = v.created_ms / 1000, expires = v.expires_ms / 1000, headers = v.signature_agent ? { 'signature-agent': v.signature_agent } : {};
  const components = [['@authority'], ...(v.signature_agent ? [v.signature_agent_key ? ['signature-agent', [['key', v.signature_agent_key]]] : ['signature-agent']] : [])];
  const params = { created, keyid: thumbprint(jwk(tk.key)), alg: 'ed25519', expires, nonce: v.nonce, tag: 'web-bot-auth' };
  const f = signFields(tk, { method: 'GET', url: v.target_url, headers }, { label: v.label, components, params });
  ok(f['signature-input'] === v.signature_input && f.signature === v.signature, `${set} ${v.label}${v.signature_agent_key ? ' (dictionary)' : v.signature_agent ? ' (sf-string)' : ''}: Signature-Input and Signature identical`);
  const req = { method: 'GET', url: v.target_url, headers: { ...headers, 'signature-input': v.signature_input, signature: v.signature } };
  if (v.signature_agent) ok(verify(req, testDir, { origin: AGENT, now: created + 100 }).keyid === params.keyid, `${set} ${v.label}: verify accepts it`);
  else throws(() => verify(req, testDir, { origin: AGENT, now: created + 100 }), /signature-agent/, `${set} ${v.label}: no Signature-Agent, refused (protocol draft -02 requires it)`);
  if (v.signature_agent && !v.signature_agent_key) {
    const r = signRequest(tk, { method: 'GET', url: v.target_url, headers: {} }, { agent: AGENT, now: created, ttl: expires - created, label: v.label, nonce: v.nonce });
    ok(r.headers.signature === v.signature && r.headers['signature-agent'] === v.signature_agent, `${set} ${v.label}: signRequest (Cloudflare's string form) reproduces it`);
  }
}
const dv = V.directory_response_v1[0], dres = dv.response;
const df = signFields(tk, { headers: dres.headers }, { label: 'binding0', req: { url: dv.request.target_url }, components: [['@authority', [['req', true]]], ['content-digest']],
  params: { created: 1735689600, keyid: dv.public_key.kid, alg: 'ed25519', expires: 4889289600, tag: 'http-message-signatures-directory' } });
ok(df['signature-input'] === dres.headers['Signature-Input'] && df.signature === dres.headers.Signature, 'directory_response_v1: Signature-Input and Signature identical');
ok(digest(dres.body) === dres.headers['content-digest'], 'directory_response_v1: Content-Digest identical');
ok(verifyDirectory(dres, { authority: 'signature-agent.test', now: 1735689700 })[0] === dv.public_key.kid, 'directory_response_v1: verifyDirectory proves the key');
const E = V.draft_e23, ef = signFields(tk, { headers: { 'content-digest': digest(E.body) } }, { label: 'binding', req: { url: `https://${E.authority}${WELL_KNOWN}` },
  components: [['@authority', [['req', true]]], ['content-digest']], params: { created: 1735689600, expires: 4889289600, keyid: thumbprint(jwk(tk.key)), tag: 'http-message-signatures-directory' } });
ok(digest(E.body) === E['content-digest'] && ef['signature-input'] === E['signature-input'] && ef.signature === E.signature, 'draft-ietf-webbotauth-httpsig-protocol-00 E.2.3 signed directory: identical');
throws(() => verifyDirectory({ ...dres, body: dres.body.replace('"sig"', '"enc"') }, { authority: 'signature-agent.test', now: 1735689700 }), /Content-Digest/, 'directory body altered: Content-Digest refuses');
throws(() => verifyDirectory(dres, { authority: 'evil.test', now: 1735689700 }), /bad signature/, 'directory re-served under another authority: refused');

// ── a sigelo identity ───────────────────────────────────────────────────────────────────────
const NOW = 1790000000, ORIGIN = 'https://agent.example', URL1 = 'https://shop.example/catalog?page=2';
const a = keygen({ recovery: seed(9), seed: seed(1), created: '2026-10-16T00:00:00Z', nonce: seed(2) });
const op = keygen({ recovery: seed(9), seed: seed(5), created: '2026-10-16T00:00:00Z', nonce: seed(6) });
const opAtt = attest({ secret: op.secret, iss: op.did, sub: a.did, iat: NOW - 100, exp: NOW + 86400 * 90, ctx: 'sigelo-relay/operator', admission: 'invite', admission_by: op.did, claims: { role: 'crawler' } });
const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: a.genesis, rotations: [], bindings: [], attestations: [opAtt], issuers: [op.genesis] };
const A = seedSigner(a.secret, a.key), get = { method: 'GET', url: URL1, headers: { accept: 'text/html' } };
const dir = directory(bundle, { now: NOW }), signed = signRequest(A, get, { agent: ORIGIN, now: NOW, nonce: 'n'.repeat(86) + '==' });
const o = { origin: ORIGIN, now: NOW + 5 };
ok(dir.keys.length === 1 && dir.keys[0].kid === thumbprint(jwk(a.key)) && dir.sigelo.did === a.did, 'directory: the current key, kid = thumbprint, the DID alongside');
ok(verify(signed, dir, o).keyid === thumbprint(jwk(a.key)), 'round trip: plain verify');
const deep = verifyDeep(signed, dir, { ...o, operator: op.did });
ok(deep.did === a.did && deep.key === 'current' && deep.operator.length === 1 && deep.operator[0].ctx === 'sigelo-relay/operator', 'round trip: verifyDeep, current key, the operator attestation reported');
const { sigelo: _, ...plainDir } = dir;
ok(verify(signed, JSON.parse(JSON.stringify(plainDir)), o).agent === ORIGIN, 'a verifier that ignores the sigelo member still verifies (RFC 7517 §5)');
throws(() => verifyDeep(signed, plainDir, o), /no sigelo member/, 'verifyDeep without the sigelo member: refused');
const dict = signRequest(A, get, { agent: ORIGIN, now: NOW, form: 'dictionary', cover: ['@method', '@path'] });
ok(dict.headers['signature-agent'] === 'sig1="https://agent.example"' && verifyDeep(dict, dir, o).components.includes('"signature-agent";key="sig1"'), 'dictionary form (IETF draft) with @method and @path: verifies');
const alter = (r, f) => { const c = structuredClone(r); f(c); return c; };
throws(() => verify(alter(signed, (c) => { c.url = 'https://evil.example/catalog?page=2'; }), dir, o), /bad signature/, 'altered @authority: bad signature');
throws(() => verify(alter(dict, (c) => { c.method = 'POST'; }), dir, o), /bad signature/, 'altered @method (covered): bad signature');
throws(() => verify(signed, dir, { ...o, now: NOW + 60 }), /expired/, 'expired (60 s default lifetime): refused');
throws(() => verify(signed, dir, { ...o, now: NOW - 3600 }), /future/, 'created in the future: refused');
throws(() => verify(alter(signed, (c) => { c.headers['signature-input'] = c.headers['signature-input'].replace(/keyid="[^"]*"/, `keyid="${thumbprint(jwk(op.key))}"`); }), dir, o), /names no usable key/, 'wrong keyid: refused');
throws(() => verify(signed, dir, { ...o, origin: 'https://other.example' }), /not the origin/, 'directory from another origin than Signature-Agent: refused');
throws(() => verify(alter(signed, (c) => { c.headers['signature-agent'] = '"https://other.example"'; }), dir, { ...o, origin: 'https://other.example' }), /bad signature/, 'Signature-Agent swapped: bad signature');
throws(() => verifyDeep(signed, { ...dir, sigelo: { ...dir.sigelo, did: op.did } }, o), /current DID/, 'sigelo.did not the bundle\'s: refused');
const B = seedSigner(op.secret, op.key), foreign = { ...dir, keys: [...dir.keys, { kty: 'OKP', crv: 'Ed25519', x: jwk(op.key).x }] };
throws(() => verifyDeep(signRequest(B, get, { agent: ORIGIN, now: NOW }), foreign, o), /not a key of/, 'a directory key outside the sigelo chain: plain verifies, verifyDeep refuses');

// ── rotation: the previous key for 7 days, then refused ─────────────────────────────────────
const b = keygen({ recovery: seed(9), seed: seed(3), created: '2026-10-16T00:00:00Z', nonce: seed(4) });
const RIAT = NOW + 1000, rot = rotate({ genesis: a.genesis, next_genesis: b.genesis, iat: RIAT, reason: 'voluntary', secret: a.secret });
const rb = { ...bundle, rotations: [rot] }, inGrace = RIAT + 6 * 86400, after = RIAT + 7 * 86400;
const rdir = directory(rb, { now: inGrace }), old = signRequest(A, get, { agent: ORIGIN, now: inGrace });
ok(rdir.keys.length === 2 && rdir.keys[1].exp === after && rdir.sigelo.did === b.did, 'after a rotation: current + previous key, previous with exp = rotation + 7 days');
ok(verify(old, rdir, { origin: ORIGIN, now: inGrace }).keyid === thumbprint(jwk(a.key)), 'rotated key during grace: plain verify accepts');
ok(verifyDeep(old, rdir, { origin: ORIGIN, now: inGrace }).key === 'previous', 'rotated key during grace: verifyDeep says previous');
ok(verifyDeep(signRequest(seedSigner(b.secret, b.key), get, { agent: ORIGIN, now: inGrace }), rdir, { origin: ORIGIN, now: inGrace }).key === 'current', 'the new key: current');
const late = signRequest(A, get, { agent: ORIGIN, now: after });
throws(() => verify(late, rdir, { origin: ORIGIN, now: after }), /names no usable key/, 'after grace, cached directory: the JWK exp refuses it');
ok(directory(rb, { now: after }).keys.length === 1, 'after grace: the directory lists only the current key');
throws(() => verifyDeep(late, { ...rdir, keys: rdir.keys.map(({ exp, ...k }) => k) }, { origin: ORIGIN, now: after }), /grace .* is over/, 'after grace, exp stripped: verifyDeep refuses from the bundle alone');

// ── domain separation: the same key, two disjoint message spaces ───────────────────────────
const body = { v: 'sigelo/0', typ: 'challenge', did: a.did, ctx: 'shop.example', nonce: 'z11111111111111111111111' };
ok(signingInput(body)[0] === 0x73 && signed.headers['signature-input'] && verify(signed, dir, o).base.charCodeAt(0) === 0x22, 'a sigelo input starts with "s" (0x73), every RFC 9421 base with \'"\' (0x22): no byte string is both');
const sigeloRaw = edSign(null, Buffer.from(signingInput(body)), createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(a.secret)]), format: 'der', type: 'pkcs8' }));
ok(multibase(sigeloRaw) === sign(a.secret, body), 'the sigelo signature of a body is plain Ed25519 over "sigelo\\n" || JCS(body)');
throws(() => verify(alter(signed, (c) => { c.headers.signature = `sig1=:${sigeloRaw.toString('base64')}:`; }), dir, o), /bad signature/, 'a sigelo body signed by the key does not verify as a request');
const reqSig = Buffer.from(/:(.*):/.exec(signed.headers.signature)[1], 'base64');
ok(!verifySig(a.key, body, multibase(reqSig)) && !verifySig(a.key, JSON.parse(JSON.stringify(verify(signed, dir, o).base)), multibase(reqSig)), 'a request signature does not verify as a sigelo signature (over a body, or over the base as a body)');
throws(() => seedSigner(a.secret, a.key).signHttp(new TextDecoder().decode(signingInput(body))), /not an RFC 9421 base/, 'the signer refuses a sigelo signing input as a base');

// ── the directory response, signed by the current key ───────────────────────────────────────
const res = response(rb, [seedSigner(b.secret, b.key)], { authority: 'agent.example', now: inGrace });
ok(res.headers['content-type'] === 'application/http-message-signatures-directory+json' && verifyDirectory(res, { authority: 'agent.example', now: inGrace }).join() === thumbprint(jwk(b.key)), 'directory response: media type, Content-Digest, the current key proves possession');
ok(JSON.parse(res.body).keys.length === 2, 'directory response: the previous key listed, unproven (its key is gone after rotation)');

// ── example/ ─────────────────────────────────────────────────────────────────────────────────
const EX = { now: NOW, origin: ORIGIN };
if (process.argv[2] === '--write') {
  const w = (f, x) => writeFileSync(new URL(`./example/${f}`, import.meta.url), JSON.stringify(x, null, 2) + '\n');
  w('request.json', signRequest(A, { method: 'GET', url: 'https://shop.example/catalog', headers: { 'user-agent': 'example-agent/1.0' } }, { agent: ORIGIN, now: NOW, ttl: 86400 * 365 * 5, nonce: Buffer.alloc(64, 7).toString('base64') }));
  w('directory-response.json', response(bundle, [A], { authority: 'agent.example', now: NOW, ttl: 86400 * 365 * 5 }));
  console.log('wrote example/');
}
const exReq = JSON.parse(readFileSync(new URL('./example/request.json', import.meta.url), 'utf8'));
const exRes = JSON.parse(readFileSync(new URL('./example/directory-response.json', import.meta.url), 'utf8'));
ok(verifyDirectory(exRes, { authority: 'agent.example', now: EX.now })[0] === thumbprint(jwk(a.key)) && verifyDeep(exReq, JSON.parse(exRes.body), { ...EX, operator: op.did }).operator.length === 1,
  `example/ verifies: ${a.did}, operator attestation from ${op.did.slice(0, 20)}…`);

console.log(fails ? `${fails} FAILED` : `ALL PASS (${passes})`);
process.exit(fails ? 1 : 0);
