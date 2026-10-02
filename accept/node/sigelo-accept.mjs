// SPDX-License-Identifier: MIT
// Accept a sigelo identity (SPEC §5.2 + §9) in any node web stack. One dependency: sigelo.
//   const c = challenge(did, 'your.domain')       → send c to the agent
//   const r = accept(c, { did, sig }, bundle)      → the §9.1 result, or throws: let them in
import { randomBytes } from 'node:crypto';
import { canonicalize, did as didOf, multibase, structure, verify, verifySig } from 'sigelo';

export const TTL_MS = 300_000;
export const pending = new Map();   // nonce -> { c, exp }. In memory, one process: replace with your session store.

export function challenge(did, ctx) {
  if (typeof did !== 'string' || !/^did:sigelo:z[1-9A-HJ-NP-Za-km-z]{40,50}$/.test(did)) throw new Error('did: want did:sigelo:z… in full');
  const now = Date.now();
  for (const [n, p] of pending) if (p.exp <= now) pending.delete(n);
  const c = { v: 'sigelo/0', typ: 'challenge', did, ctx, nonce: multibase(randomBytes(16)) };
  pending.set(c.nonce, { c, exp: now + TTL_MS });
  return c;
}

// challenge: the issued object (or its nonce); answer: { did, sig }; bundle: the agent's §8 bundle or current genesis.
export function accept(challenge, answer, bundle, now = Math.floor(Date.now() / 1000)) {
  const nonce = typeof challenge === 'string' ? challenge : challenge?.nonce;
  const p = typeof nonce === 'string' ? pending.get(nonce) : undefined;
  pending.delete(nonce);                                   // single use, whatever happens next
  if (!p || p.exp <= Date.now()) throw new Error('challenge unknown, expired or already answered');
  if (typeof challenge === 'object' && canonicalize(challenge) !== canonicalize(p.c)) throw new Error('challenge differs from the one issued');
  if (answer?.did !== p.c.did) throw new Error('did is not the DID this challenge was issued to');
  let result, key;
  if (bundle?.typ === 'bundle') {
    result = verify(bundle, now);                          // §9: throws SigeloError on REJECT
    key = [bundle.genesis, ...bundle.rotations.map((r) => r.next_genesis)].find((g) => didOf(g) === result.did).key;
  } else { structure(bundle, 'genesis'); result = { did: didOf(bundle) }; key = bundle.key; }
  if (result.did !== p.c.did) throw new Error(`the bundle's current DID is ${result.did}, not ${p.c.did}`);
  if (!verifySig(key, p.c, answer.sig)) throw new Error('sig does not verify under the current key');
  return result;                                           // accepted: result.did is who they are
}
