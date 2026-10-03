// SPDX-License-Identifier: MIT
// Pair two agents by sigelo DID, not by Agent Card name or bearer token (SPEC §5.2, §7, §9).
// The card carries {did, bundle} in an A2A extension; everything is verified offline.
//   const store = new Contacts('contacts.json')
//   const c = store.issue(did, ctx, now, 'alice')   → send c; a null name refreshes a known contact
//   pair(card, { body, sig }, store, now)            → { did, current_did, current_key, attestations, rejected }, or throws
// Contract and fixtures: adapters/hermes/pairing/. One dependency: sigelo.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { canonicalize, did as didOf, multibase, verify, verifySig } from 'sigelo';

export const V = 'sigelo-a2a-pairing/0', EXT = 'urn:sigelo:a2a-pairing:0', TTL = 300;
export class PairingError extends Error { constructor(check, why) { super(`${check}: ${why}`); this.check = check; } }
const fail = (check, why) => { throw new PairingError(check, why); };
const attempt = (check, f) => { try { return f(); } catch (e) { return fail(check, e.message); } };

// The JSON-file store: { v, pending: { nonce: { challenge, exp, name } }, contacts: { original DID: contact } }.
export class Contacts {
  constructor(path) { this.path = path; this.load(); }
  // Every operation re-reads the file: another process (the owner's revoke) may have written it.
  load() { this.s = existsSync(this.path) ? JSON.parse(readFileSync(this.path, 'utf8')) : { v: V, pending: {}, contacts: {} }; return this; }
  save() { writeFileSync(this.path + '.tmp', JSON.stringify(this.s, null, 2)); renameSync(this.path + '.tmp', this.path); }
  // name: the owner pairs a new contact under that name; null: only a known contact may answer.
  issue(did, ctx, now, name = null, nonce = multibase(randomBytes(16))) {
    const challenge = { v: 'sigelo/0', typ: 'challenge', did, ctx, nonce };
    for (const [n, p] of Object.entries(this.load().s.pending)) if (p.exp <= now) delete this.s.pending[n];  // expired ones go
    this.s.pending[nonce] = { challenge, exp: now + TTL, name }; this.save(); return challenge;
  }
  lookup(did) { return Object.values(this.load().s.contacts).find((c) => c.chain.includes(did)) ?? null; }
  revoke(did) {  // local and final for this store; pending challenges to the contact die with it
    const c = this.lookup(did) ?? fail('not_contact', `${did} is not a contact`);
    c.revoked = true;
    for (const [n, p] of Object.entries(this.s.pending)) if (c.chain.includes(p.challenge.did)) delete this.s.pending[n];
    this.save(); return c;
  }
}

export function pair(card, answer, store, now) {
  const ext = Array.isArray(card?.capabilities?.extensions) ? card.capabilities.extensions.find((x) => x?.uri === EXT) : undefined;
  const claimed = ext?.params?.did, bundle = ext?.params?.bundle;
  if (typeof claimed !== 'string' || bundle?.typ !== 'bundle') fail('card', `no ${EXT} extension with params { did, bundle }`);
  const nonce = answer?.body?.nonce;
  const p = typeof nonce === 'string' && Object.hasOwn(store.load().s.pending, nonce) ? store.s.pending[nonce] : fail('challenge_unknown', 'not issued here, or already answered');
  delete store.s.pending[nonce]; store.save();                  // single use, whatever happens next
  if (now >= p.exp) fail('challenge_expired', `expired at ${p.exp}`);
  let r = attempt('bundle', () => verify(bundle, now));          // §9, offline; a fork or bad chain throws
  if (r.did !== claimed) fail('card_did', `the bundle resolves to ${r.did}, the card claims ${claimed}`);
  if (p.challenge.did !== r.did) fail('challenge_did', `issued to ${p.challenge.did}, answered by ${r.did}: a card name is not an identity`);
  if (canonicalize(answer.body) !== canonicalize(p.challenge)) fail('challenge_body', 'differs from the challenge issued');
  const keyOf = (rots, d) => [bundle.genesis, ...rots.map((x) => x.next_genesis)].find((g) => didOf(g) === d).key;
  if (!verifySig(keyOf(bundle.rotations, r.did), p.challenge, answer.sig)) fail('sig', 'does not verify under the current key');
  const old = store.s.contacts[r.chain[0]];                     // keyed by the ORIGINAL DID: rotation keeps the pairing
  if (old?.revoked) fail('revoked', `${r.chain[0]} was revoked by this owner`);
  if (!old && p.name === null) fail('not_contact', `${r.chain[0]} is not a contact; pairing needs the owner`);
  let rotations = bundle.rotations;
  if (old) {  // a peer cannot hide a rotation this store has seen: merge, and §7.3 decides (recovery beats voluntary)
    const seen = new Set(rotations.map(canonicalize));
    rotations = [...rotations, ...old.rotations.filter((x) => !seen.has(canonicalize(x)))];
    r = attempt('bundle', () => verify({ ...bundle, rotations }, now));
    if (r.did !== claimed) fail('stale_chain', `the rotations already seen resolve to ${r.did}, not ${claimed}`);
  }
  if (store.load().s.contacts[r.chain[0]]?.revoked) fail('revoked', `${r.chain[0]} was revoked during this pairing`);
  const c = { name: old?.name ?? p.name, did: r.chain[0], current_did: r.did, current_key: keyOf(rotations, r.did), revoked: false, chain: r.chain, rotations };
  store.s.contacts[c.did] = c; store.save();
  return { did: c.did, current_did: c.current_did, current_key: c.current_key, attestations: r.attestations, rejected: r.rejected };
}
