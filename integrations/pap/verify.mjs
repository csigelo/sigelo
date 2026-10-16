// SPDX-License-Identifier: MIT
// Company side of the PAP profile draft (README.md): check a Personal Agent's sigelo identification
// offline. `node verify.mjs params.json <auth.issuer> <nonce> [now]` → the result, or throws.
import { readFileSync, realpathSync } from 'node:fs';
import { did, parse, verify, verifySig } from 'sigelo';

export const URI = 'https://github.com/csigelo/sigelo/tree/main/integrations/pap';
// The operator attestation contact/ and the relay already use (relay/operator.mjs): the operator
// signs `sub` = the agent, admission "invite" by itself. Its claims are the operator's business.
export const OPERATOR_CTX = 'sigelo-relay/operator';
const fail = (m) => { throw new Error(`pap: ${m}`); };

/**
 * `params`: the token request's form fields, as the Company parsed them. `issuer`: the Company's
 * own auth.issuer. `nonce`: the one it issued for this request and still holds live. `known`: the
 * chain it stored for this client_id last time, if any. Returns what it should record.
 */
export function verifyPresentation(params, { issuer, nonce, now = Math.floor(Date.now() / 1000), known = [], requireOperator = true }) {
  if (params?.client_assertion_type !== URI) fail('client_assertion_type is not the sigelo profile');
  const { bundle, proof, ...extra } = parse(String(params.client_assertion));      // duplicate keys rejected
  if (Object.keys(extra).length) fail(`client_assertion has unknown field(s) ${Object.keys(extra).join(', ')}`);
  const r = verify(bundle, now);                                                     // SPEC §9, offline
  if (params.client_id !== r.chain[0]) fail("client_id is not the bundle's original DID");
  if (known.some((d, i) => r.chain[i] !== d)) fail('the chain does not extend the one held for this client_id (a rotation or recovery seen before is missing)');
  const b = proof?.body ?? {}, keys = Object.keys(b).sort().join();
  if (keys !== 'ctx,did,nonce,typ,v' || b.v !== 'sigelo/0' || b.typ !== 'challenge') fail('proof is not a SPEC §5.2 challenge');
  if (b.ctx !== issuer) fail(`proof names ${JSON.stringify(b.ctx)}, not this Company's auth.issuer`);
  if (b.nonce !== nonce) fail('proof answers another nonce');
  if (b.did !== r.did) fail("proof is not from the bundle's current DID");
  const g = [bundle.genesis, ...bundle.rotations.map((x) => x.next_genesis)].find((x) => did(x) === r.did);
  if (!verifySig(g.key, b, proof.sig)) fail('bad proof signature');
  const operators = Object.entries(r.attestations).filter(([iss]) => !r.chain.includes(iss))
    .flatMap(([iss, bodies]) => bodies.filter((x) => x.ctx === OPERATOR_CTX && x.admission === 'invite' && x.admission_by === iss)
      .map((x) => ({ did: iss, exp: x.exp })));
  if (requireOperator && !operators.length) fail('no unexpired operator attestation');
  return { client_id: r.chain[0], did: r.did, chain: r.chain, recovery: r.recovery, operators, result: r };
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) {
  const [file, issuer, nonce, now] = process.argv.slice(2);
  const out = verifyPresentation(parse(readFileSync(file, 'utf8')), { issuer, nonce, ...(now && { now: Number(now) }) });
  console.log(JSON.stringify(out, null, 2));
}
