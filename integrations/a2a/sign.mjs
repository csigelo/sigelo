// SPDX-License-Identifier: MIT
// Add the sigelo extension to an A2A AgentCard and sign it through the identity's signer (profile draft).
//   sigelo-agent bundle > bundle.json
//   node sign.mjs card.json bundle.json [--operator <file>] [--operator-chain <file>] > signed-card.json
// The key: $SIGELO_IDENTITY (else ~/.config/moadim/sigelo.local.json), used only through sigelo-agent's
// signer (adapters/moadim/sigelo-agent-keys.ts): file, keychain or key agent; nothing here reads `secret`.
// --operator: the agent's identity file as `sigelo-agent` enrol writes it (its "sigelo-relay/operator"
// attestation, the operator's genesis in `issuers`), or {attestation, bundle}. --operator-chain: the
// operator's bundle or identity file, so the card carries the operator's rotations (genesis, rotations only).
import { readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { did, parse, verify } from 'sigelo';
import { OPERATOR_CTX, URI, cardBody, verifyCard } from './verify.mjs';

/** K1's signer for the identity file at `path`: the checkout's sigelo-agent-keys.ts, else an installed sigelo-agent. */
export async function signerFor(path) {
  let keys;
  try { keys = await import('../../adapters/moadim/sigelo-agent-keys.ts'); } catch {
    try { keys = await import('sigelo-agent/dist/sigelo-agent-keys.js'); } catch {
      throw new Error("a2a-card: signing needs sigelo-agent's key providers (sigelo-agent-keys): run from the sigelo checkout with adapters/moadim installed, or where sigelo-agent is installed");
    }
  }
  return keys.signer(path, parse(readFileSync(path, 'utf8')));
}

/** `params.operator` from what sigelo-agent writes; `chain` (optional) gives the operator's rotations. */
export function operatorFrom(file, chain) {
  if (file?.attestation && file?.bundle) return { attestation: file.attestation, bundle: file.bundle };
  const atts = (file?.attestations ?? []).filter((a) => a?.body?.ctx === OPERATOR_CTX).sort((a, b) => b.body.exp - a.body.exp);
  const att = atts.find((a) => (file.issuers ?? []).some((g) => did(g) === a.body.iss));
  if (!att) throw new Error(`a2a-card: operator_shape: no ${OPERATOR_CTX} attestation with its issuer's genesis in the file`);
  const genesis = chain?.genesis ?? file.issuers.find((g) => did(g) === att.body.iss);
  return { attestation: att, bundle: { v: 'sigelo/0', typ: 'bundle', genesis, rotations: chain?.rotations ?? [], bindings: [], attestations: [], issuers: [] } };
}

/** `signer`: K1's {did, key, sign(body)}, or an identity file path. `operator`: {attestation, bundle} or undefined. */
export async function signCard(card, bundle, signer, now, operator) {
  if (typeof signer === 'string') signer = await signerFor(signer);
  if (typeof signer?.sign !== 'function') throw new Error('a2a-card: pass a signer (sigelo-agent-keys.ts) or an identity file path, not a key');
  const params = { did: verify(bundle, now ?? Math.floor(Date.now() / 1000)).did, bundle, ...(operator && { operator }) };
  const ext = { uri: URI, description: 'sigelo identity: DID, bundle, card signature (profile draft)', required: false, params };
  const others = (card.capabilities?.extensions ?? []).filter((e) => e?.uri !== URI);
  const out = { ...card, capabilities: { ...card.capabilities, extensions: [...others, ext] } };
  params.sig = signer.sign(cardBody(out));
  verifyCard(out, now);                     // refuses a key that is not the bundle's current one, and a bad operator
  return out;
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) {
  const read = (p) => parse(readFileSync(p, 'utf8')), arg = (k) => { const i = process.argv.indexOf(k); return i < 0 ? undefined : process.argv[i + 1]; };
  const op = arg('--operator'), chain = arg('--operator-chain');
  const operator = op ? operatorFrom(read(op), chain ? read(chain) : undefined) : undefined;
  const path = process.env.SIGELO_IDENTITY ?? `${homedir()}/.config/moadim/sigelo.local.json`;
  console.log(JSON.stringify(await signCard(read(process.argv[2]), read(process.argv[3]), path, undefined, operator), null, 2));
}
