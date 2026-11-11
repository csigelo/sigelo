// SPDX-License-Identifier: MIT
// The key directory at /.well-known/http-message-signatures-directory for a sigelo identity: a
// JWKS (RFC 7517 §5) with the current key and, for GRACE after a rotation, the previous one; the
// DID and bundle ride in a top-level "sigelo" member, which RFC 7517 §5 says a reader that does
// not understand it MUST ignore. Signed per the protocol draft, Appendix B.
//   sigelo-agent bundle > bundle.json
//   node directory.mjs agent.example bundle.json > response.json     # { status, headers, body }
import { readFileSync, realpathSync } from 'node:fs';
import { did, parse, verify } from 'sigelo';
import { DIR_TAG, GRACE, MEDIA, WELL_KNOWN, digest, jwk, thumbprint } from './verify.mjs';
import { cliSigner, signFields } from './sign.mjs';

const entry = (key, extra) => { const k = jwk(key); return { ...k, kid: thumbprint(k), use: 'sig', ...extra }; };

/** The directory body as an object: keys first, then { did, bundle }. Refuses a bundle that does not verify. */
export function directory(bundle, { now, grace = GRACE }) {
  const r = verify(bundle, now), gens = [bundle.genesis, ...bundle.rotations.map((x) => x.next_genesis)], gen = (d) => gens.find((g) => did(g) === d);
  const keys = [entry(gen(r.did).key)];
  if (r.chain.length > 1) {
    const rot = bundle.rotations.find((x) => x.body.id === r.chain.at(-2) && x.body.next === r.did);
    if (now < rot.body.iat + grace) keys.push(entry(gen(r.chain.at(-2)).key, { exp: rot.body.iat + grace }));
  }
  return { keys, sigelo: { did: r.did, bundle } };
}

/**
 * The full response for a GET from `authority`: one possession proof per key the caller can sign
 * with (`signers`; after a rotation sigelo-agent holds only the new key, so the previous key is
 * listed without a proof: verifiers that use only proven keys, Cloudflare's among them, drop it).
 */
export function response(bundle, signers, { authority, now, ttl = 86400, grace = GRACE }) {
  const body = JSON.stringify(directory(bundle, { now, grace })), headers = { 'content-type': MEDIA, 'cache-control': 'max-age=3600', 'content-digest': digest(body) };
  const req = { method: 'GET', url: `https://${authority}${WELL_KNOWN}`, headers: {} }, inputs = [], sigs = [];
  signers.forEach((s, i) => {
    const params = { created: now, keyid: thumbprint(jwk(s.key)), alg: 'ed25519', expires: now + ttl, tag: DIR_TAG };
    const f = signFields(s, { headers }, { label: `binding${i}`, components: [['@authority', [['req', true]]], ['content-digest']], params, req });
    inputs.push(f['signature-input']); sigs.push(f.signature);
  });
  return { status: 200, headers: { ...headers, 'signature-input': inputs.join(', '), signature: sigs.join(', ') }, body };
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) {
  const [authority, bundleF] = process.argv.slice(2);
  if (!bundleF) { console.error('usage: node directory.mjs <authority> <bundle.json>'); process.exit(2); }
  console.log(JSON.stringify(response(parse(readFileSync(bundleF, 'utf8')), [cliSigner()], { authority, now: Math.floor(Date.now() / 1000) }), null, 2));
}
