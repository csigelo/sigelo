// SPDX-License-Identifier: MIT
// Add the sigelo extension to an A2A AgentCard and sign it with the identity key (profile draft).
//   sigelo-agent bundle > bundle.json
//   node sign.mjs card.json bundle.json > signed-card.json      # key: $SIGELO_IDENTITY
// `sigelo-agent sign-challenge` signs challenges only, so this reads the identity file itself.
import { readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { parse, sign, verify } from 'sigelo';
import { URI, cardBody, verifyCard } from './verify.mjs';

export function signCard(card, bundle, secret, now) {
  const params = { did: verify(bundle, now ?? Math.floor(Date.now() / 1000)).did, bundle };
  const ext = { uri: URI, description: 'sigelo identity: DID, bundle, card signature (profile draft)', required: false, params };
  const others = (card.capabilities?.extensions ?? []).filter((e) => e?.uri !== URI);
  const out = { ...card, capabilities: { ...card.capabilities, extensions: [...others, ext] } };
  params.sig = sign(secret, cardBody(out));
  verifyCard(out, now);                     // refuses a key that is not the bundle's current one
  return out;
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) {
  const id = JSON.parse(readFileSync(process.env.SIGELO_IDENTITY ?? `${homedir()}/.config/moadim/sigelo.local.json`, 'utf8'));
  const read = (p) => parse(readFileSync(p, 'utf8'));
  console.log(JSON.stringify(signCard(read(process.argv[2]), read(process.argv[3]), Buffer.from(id.secret, 'hex')), null, 2));
}
