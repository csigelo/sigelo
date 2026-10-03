// SPDX-License-Identifier: MIT
// Regenerates fixtures/pairing-v0.json, byte for byte, from the documented seeds below.
//   node adapters/hermes/pairing/gen.mjs           write the file
//   node adapters/hermes/pairing/gen.mjs --check   exit 1 if the committed file differs
// Needs ts/dist (cd ts && npm ci && npx tsc). Ed25519 is deterministic, so fixed seeds, fixed
// genesis nonces, fixed `created` and fixed times fix every byte. Output: JSON.stringify(out,
// null, 2) + "\n", keys in insertion order. The contract is in README.md.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { attest, challenge, keygen, rotate } from '../../../ts/dist/sigelo.js';

const V = 'sigelo-a2a-pairing/0', EXT = 'urn:sigelo:a2a-pairing:0', TTL = 300;
const T0 = 1791000000, CREATED = '2026-10-01T00:00:00Z'; // T0 = 2026-10-03T00:40:00Z
const OUT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'pairing-v0.json');
// Every secret is seed(label) = SHA-256(UTF-8 "sigelo-a2a-pairing/0 " + label); every genesis nonce
// is the first 16 bytes of SHA-256("sigelo-a2a-pairing/0 nonce " + label); every challenge nonce
// the first 16 bytes of SHA-256("sigelo-a2a-pairing/0 challenge " + case).
const sha = (s) => createHash('sha256').update(V + ' ' + s).digest();
const seed = (l) => new Uint8Array(sha(l)), nonce = (l) => new Uint8Array(sha('nonce ' + l).subarray(0, 16));
const LABELS = ['A0', 'A1', 'A2', 'A-recovery', 'A-recovery-2', 'B0', 'B-recovery', 'M0', 'M-recovery', 'T', 'X', 'W', 'W-recovery'];
const ZERO = 'sha256:' + '0'.repeat(64); // placeholder commitment: only to read a recovery seed's public key
const id = (l, recovery) => keygen({ seed: seed(l), recovery, created: CREATED, nonce: nonce(l) });
const pub = (l) => id(l, ZERO).key;
const [aRec, aRec2, bRec, mRec, wRec] = ['A-recovery', 'A-recovery-2', 'B-recovery', 'M-recovery', 'W-recovery'].map(pub);
const A0 = id('A0', aRec), A1 = id('A1', aRec), X = id('X', aRec), T = id('T', aRec), A2 = id('A2', aRec2);
const B0 = id('B0', bRec), M0 = id('M0', mRec), W = id('W', wRec);

// Rotations (SPEC §7). The recovery A1 -> A2 carries an EARLIER iat than the thief's A1 -> T:
// precedence never reads timestamps (§7.1).
const rot = (from, to, iat, reason, secret) => rotate({ genesis: from.genesis, next_genesis: to.genesis, iat, reason, secret });
const rA1 = rot(A0, A1, T0 + 1000, 'voluntary', A0.secret), rX = rot(A0, X, T0 + 1001, 'voluntary', A0.secret);
const rT = rot(A1, T, T0 + 2000, 'voluntary', A1.secret), rA2 = rot(A1, A2, T0 + 1500, 'recovery', seed('A-recovery'));
// One world W attests A0, so `attestations` is not empty (SPEC §5).
const att = attest({ secret: W.secret, iss: W.did, sub: A0.did, iat: T0 - 86400, exp: T0 + 30 * 86400, ctx: 'example.world',
  admission: 'invite', admission_by: B0.did, claims: { joined: '2026-09-01', tasks: 12 } });
const tampered = { ...att, body: { ...att.body, claims: { ...att.body.claims, tasks: 1200 } } };
const bundle = (g, rotations = [], attestations = [], issuers = []) => ({ v: 'sigelo/0', typ: 'bundle', genesis: g.genesis, rotations, bindings: [], attestations, issuers });

// An Agent Card exactly as Hermes' protocol.build_agent_card builds it (auth_required, one
// JSONRPC interface, the default skill), plus one A2A AgentExtension carrying {did, bundle}.
const card = (name, host, did, b) => {
  const url = `https://${host}/a2a`;
  return { name, description: 'Hermes Agent — a general-purpose agent reachable over A2A.', url, version: '1.0.0',
    provider: { organization: 'Hermes Agent', url }, supportedInterfaces: [{ url, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    capabilities: { streaming: true, pushNotifications: true, stateTransitionHistory: false, extendedAgentCard: false,
      extensions: [{ uri: EXT, description: 'sigelo identity: the pairing binds to params.did, verified offline from params.bundle', required: false, params: { did, bundle: b } }] },
    defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
    skills: [{ id: 'general', name: 'general', description: 'General-purpose conversational agent', tags: ['general'] }],
    securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } }, security: [{ bearer: [] }] };
};
const wa = [att], wi = [W.genesis];
const cards = {
  A0: card('Alice', 'alice.example', A0.did, bundle(A0, [], wa, wi)),
  B0: card('Bob', 'bob.example', B0.did, bundle(B0)),
  M0_named_alice: card('Alice', 'alice.example', M0.did, bundle(M0)),
  A0_claims_with_M0_bundle: card('Alice', 'alice.example', A0.did, bundle(M0)),
  M0: card('Mallory', 'mallory.example', M0.did, bundle(M0)),
  A0_tampered_attestation: card('Alice', 'alice.example', A0.did, bundle(A0, [], [tampered], wi)),
  A1_fork: card('Alice', 'alice.example', A1.did, bundle(A0, [rA1, rX], wa, wi)),
  A1: card('Alice', 'alice.example', A1.did, bundle(A0, [rA1], wa, wi)),
  T_thief: card('Alice', 'alice.example', T.did, bundle(A0, [rA1, rT], wa, wi)),
  A2_recovered: card('Alice', 'alice.example', A2.did, bundle(A0, [rA1, rA2], wa, wi)),
};

const ctx = { A: 'hermes-contacts:' + A0.did, B: 'hermes-contacts:' + B0.did }; // whose store issues: the receiver
const steps = [];
const keys = { A0, A1, A2, B0, M0, T, X };
const contact = (name, original, cur, revoked = false) => ({ name, did: original.did, current_did: cur.did, current_key: cur.key, revoked });
const accepted = (original, cur, attestations, rejected = 0) => ({ did: original.did, current_did: cur.did, current_key: cur.key,
  attestations: attestations ? { [W.did]: [att.body] } : {}, rejected: { attestations: rejected, bindings: 0 } });
let t = T0;
// issue + pair as one case. `to`: the DID the challenge is issued to; `signer`: who answers (it
// signs a body naming its own DID, as an agent library must, SPEC §5.2); `late`: answered after TTL.
function exchange(c, store, to, contactName, cardName, signer, result, { late = false, now } = {}) {
  t = now ?? t + 10;
  const n = new Uint8Array(sha('challenge ' + c).subarray(0, 16));
  const answer = challenge({ secret: signer.secret, genesis: signer.genesis, ctx: ctx[store], nonce: n });
  steps.push({ case: c, store, op: 'issue', now: t, did: to.did, ctx: ctx[store], contact_name: contactName, expect: { v: 'sigelo/0', typ: 'challenge', did: to.did, ctx: ctx[store], nonce: answer.body.nonce } });
  steps.push({ case: c, store, op: 'pair', now: late ? t + TTL : t + 1, card: cardName, answer, ...result });
  return answer;
}
const first = exchange('pair_b_learns_a', 'B', A0, 'alice', 'A0', A0, { expect: accepted(A0, A0, true) });
exchange('pair_a_learns_b', 'A', B0, 'bob', 'B0', B0, { expect: accepted(B0, B0, false) });
steps.push({ case: 'lookup_both_directions', store: 'A', op: 'lookup', now: (t += 10), did: B0.did, expect: contact('bob', B0, B0) });
steps.push({ case: 'lookup_both_directions', store: 'B', op: 'lookup', now: t, did: A0.did, expect: contact('alice', A0, A0) });
steps.push({ case: 'replayed_challenge', store: 'B', op: 'pair', now: (t += 10), card: 'A0', answer: first, error: 'challenge_unknown' });
exchange('expired_challenge', 'B', A0, null, 'A0', A0, { error: 'challenge_expired' }, { late: true });
exchange('card_name_is_not_identity', 'B', A0, null, 'M0_named_alice', M0, { error: 'challenge_did' }, { now: t + TTL + 10 });
exchange('bundle_from_another_did', 'B', A0, null, 'A0_claims_with_M0_bundle', A0, { error: 'card_did' });
exchange('unknown_peer', 'B', M0, null, 'M0', M0, { error: 'not_contact' });
exchange('tampered_attestation_discarded', 'B', A0, null, 'A0_tampered_attestation', A0, { expect: accepted(A0, A0, false, 1) });
exchange('chain_fork', 'B', A1, null, 'A1_fork', A1, { error: 'bundle' }, { now: T0 + 1100 });
exchange('voluntary_rotation', 'B', A1, null, 'A1', A1, { expect: accepted(A0, A1, true) });
steps.push({ case: 'voluntary_rotation', store: 'B', op: 'lookup', now: (t += 10), did: A0.did, expect: contact('alice', A0, A1) });
exchange('thief_before_recovery_undetectable', 'B', T, null, 'T_thief', T, { expect: accepted(A0, T, true) }, { now: T0 + 2100 });
exchange('recovery_beats_voluntary', 'B', A2, null, 'A2_recovered', A2, { expect: accepted(A0, A2, true) });
steps.push({ case: 'recovery_beats_voluntary', store: 'B', op: 'lookup', now: (t += 10), did: A2.did, expect: contact('alice', A0, A2) });
steps.push({ case: 'recovery_beats_voluntary', store: 'B', op: 'lookup', now: t, did: T.did, expect: null }); // the thief's DID left the chain
exchange('thief_after_recovery', 'B', T, null, 'T_thief', T, { error: 'stale_chain' });
steps.push({ case: 'revoke', store: 'B', op: 'revoke', now: (t += 10), did: A0.did, expect: contact('alice', A0, A2, true) });
exchange('revoked_pairing', 'B', A2, null, 'A2_recovered', A2, { error: 'revoked' });
steps.push({ case: 'revoke_is_local', store: 'A', op: 'lookup', now: (t += 10), did: B0.did, expect: contact('bob', B0, B0) });
for (const s of steps) if (s.op === 'pair' && !s.expect && !s.error) throw new Error('step without outcome');

const out = {
  v: V,
  note: 'A2A pairing by sigelo DID. Run steps in order against two empty contact stores A and B; each pair step names its card in `cards` and either `expect`s the result or fails with `error`, the first failing check. See README.md.',
  extension: EXT, ttl: TTL, created: CREATED,
  seeds: Object.fromEntries(LABELS.map((l) => [l, Buffer.from(seed(l)).toString('hex')])),
  dids: Object.fromEntries(Object.entries({ ...keys, W }).map(([k, v]) => [k, v.did])),
  cards, steps,
};
const text = JSON.stringify(out, null, 2) + '\n';
if (process.argv.includes('--check')) {
  let cur = ''; try { cur = readFileSync(OUT, 'utf8'); } catch {}
  if (cur !== text) { console.error(`FAIL ${OUT} differs from what the seeds generate: run node adapters/hermes/pairing/gen.mjs`); process.exit(1); }
  console.log(`ok fixtures/pairing-v0.json reproduces from the seeds (${steps.length} steps)`);
} else writeFileSync(OUT, text);
