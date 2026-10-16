// SPDX-License-Identifier: MIT
// What the key agent signs (design/key-providers.md §4.3). It receives BODIES and builds the
// signing input itself ("sigelo\n" ‖ JCS(body), SPEC §3); raw bytes have no request. Each allowed
// body must name this key's current DID in its signer field, so no caller has it sign for another
// identity, or for this one under an old DID. A rotation is never signed here: only `rotate` makes
// one, to a key the agent made itself, so an injected model gets signatures, never a voluntary
// rotation to a key it chose (THREAT-MODEL §2.4). Anything not listed is `policy_typ`.
import { core, refuse } from './protocol.mjs';

/** [v, typ, the field naming the signer, the start flag it needs (or null)]. */
export const RULES = [
  ['sigelo/0', 'challenge', 'did', null],             // and the sidecar's own challengeDid checks
  ['sigelo-relay/0', 'relay-login', 'did', null],
  ['sigelo-invite/0', 'invite-answer', 'did', null],
  ['sigelo-invite/0', 'invite-reply', 'did', null],
  ['sigelo-msg/0', 'message', 'from', null],
  ['sigelo-msg/0', 'prekeys', 'did', null],
  ['sigelo-carrier/0', 'contact-notice', 'did', null],
  ['sigelo/0', 'binding', 'id', '--allow-payments'],   // the agent cannot see which subaddresses the wallet issued
  ['sigelo/0', 'invoice', 'did', '--allow-payments'],
  ['sigelo/0', 'attestation', 'iss', '--allow-attest'], // only for a ctx given with --allow-attest <ctx>
];

/**
 * Refuse `body` unless this agent signs it for `cur`, the key's current DID. `id` is the chain as
 * the core reads a store ({ genesis, rotations }); `opts` the start flags.
 */
export function check(body, cur, id, opts) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) refuse('policy_typ', 'the body is not a JSON object');
  const { v, typ } = body;
  if (typ === 'rotation') refuse('policy_rotation', 'a rotation is never signed through sign; rotate makes one, to a key this agent made itself');
  const rule = RULES.find(([rv, rt]) => rv === v && rt === typ);
  if (!rule) refuse('policy_typ', `${JSON.stringify(v)} ${JSON.stringify(typ)} is not a body this agent signs (design/key-providers.md §4.3)`);
  const [, , field, flag] = rule;
  if (flag === '--allow-payments' && !opts.allowPayments) refuse('policy_typ', `${typ}: this agent was started without --allow-payments`);
  if (flag === '--allow-attest' && !opts.allowAttest.includes(body.ctx)) refuse('policy_typ', `attestation: ctx ${JSON.stringify(body.ctx)} was not given with --allow-attest`);
  if (body[field] !== cur) refuse('policy_did', `${typ}: ${field} is ${JSON.stringify(body[field])}, not this key's current DID ${cur}`);
  if (typ === 'challenge') {
    try { core.challengeDid(id, body); } catch (e) { refuse('policy_typ', e.message); }
  }
}
