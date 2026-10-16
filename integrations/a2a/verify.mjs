// SPDX-License-Identifier: MIT
// Verify a sigelo-signed A2A AgentCard (profile draft, README.md). Offline: `node verify.mjs card.json`.
import { readFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { parse, canonicalize, structure, verify, verifySig, did } from 'sigelo';

export const URI = 'https://github.com/csigelo/sigelo/tree/main/integrations/a2a';
// The operator attestation sigelo-agent writes (contact/enrol.mjs operatorAttestation, relay/operator.mjs).
export const OPERATOR_CTX = 'sigelo-relay/operator';
const exts = (card) => (card?.capabilities?.extensions ?? []).filter((e) => e?.uri === URI);
const nodes = (b) => [b.genesis, ...b.rotations.map((x) => x.next_genesis)];
const refuse = (check, m) => { throw Object.assign(new Error(`a2a-card: ${check}: ${m}`), { check }); };
const plain = (x, keys) => typeof x === 'object' && x !== null && !Array.isArray(x) && Object.keys(x).sort().join() === keys;

/** What the identity key signs: the card minus A2A `signatures` and this `params.sig`, hashed (JCS). */
export function cardBody(card) {
  const [ext] = exts(card), { sig, ...params } = ext.params;
  const { signatures, ...rest } = card, unsigned = { ...rest, capabilities: { ...card.capabilities,
    extensions: card.capabilities.extensions.map((e) => (e === ext ? { ...e, params } : e)) } };
  const h = createHash('sha256').update(canonicalize(unsigned)).digest('hex');
  return { v: 'sigelo/0', typ: 'a2a-card', did: params.did, card: `sha256:${h}` };
}

/**
 * `params.operator` = {attestation, bundle}: the operator's attestation and the operator's own bundle
 * (its chain). Checks by name; `chain` is the card's (SPEC §9.1). → {did, chain, exp} of the operator.
 */
export function checkOperator(op, chain, now) {
  if (!plain(op, 'attestation,bundle') || !plain(op.attestation, 'body,sig')) refuse('operator_shape', 'operator is not {attestation: {body, sig}, bundle}');
  try { structure(op.attestation.body, 'attestation'); } catch (e) { refuse('operator_shape', e.message); }
  const b = op.attestation.body;
  let r;
  try { r = verify(op.bundle, now); } catch (e) { refuse('operator_chain', `the operator's bundle does not verify (${e.message})`); }
  const g = nodes(op.bundle).find((x) => did(x) === b.iss);
  if (!r.chain.includes(b.iss) || !g) refuse('operator_issuer', `${b.iss} is not in the operator's chain`);
  if (!verifySig(g.key, b, op.attestation.sig)) refuse('operator_sig', 'the attestation does not verify under its issuer key');
  // SPEC §5: a verifier that knows a DID was rotated away from stops trusting it; the chain says so (as spend/licence.ts).
  if (b.iss !== r.did) refuse('operator_rotated', `signed by ${b.iss}, which the operator rotated away from (its chain ends at ${r.did}): the operator reissues`);
  if (b.ctx !== OPERATOR_CTX) refuse('operator_ctx', `ctx ${JSON.stringify(b.ctx)}, not ${OPERATOR_CTX}`);
  if (!chain.includes(b.sub)) refuse('operator_subject', `it is for ${b.sub}, not this card's identity`);
  if (b.iat > now) refuse('operator_time', 'its iat is in the future');
  if (now >= b.exp) refuse('operator_expired', `it expired at ${new Date(b.exp * 1000).toISOString()}`);
  return { did: r.did, chain: r.chain, exp: b.exp };
}

/** Throws on any failure (`.check` names it); returns the SPEC §9.1 result plus `operator` ({did, chain, exp} or null). */
export function verifyCard(card, now = Math.floor(Date.now() / 1000)) {
  if (exts(card).length !== 1) throw new Error('a2a-card: not exactly one sigelo extension');
  const { did: claimed, bundle, sig, operator } = exts(card)[0].params ?? {};
  const r = verify(bundle, now);                                     // SPEC §9, offline
  if (r.did !== claimed) throw new Error("a2a-card: did is not the bundle's current DID");
  const g = nodes(bundle).find((x) => did(x) === r.did);
  if (!verifySig(g.key, cardBody(card), sig)) throw new Error('a2a-card: bad signature');
  return { ...r, operator: operator === undefined ? null : checkOperator(operator, r.chain, now) };
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) console.log(JSON.stringify(verifyCard(parse(readFileSync(process.argv[2], 'utf8'))), null, 2));
