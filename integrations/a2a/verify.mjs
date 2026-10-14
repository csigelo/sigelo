// SPDX-License-Identifier: MIT
// Verify a sigelo-signed A2A AgentCard (profile draft, README.md). Offline: `node verify.mjs card.json`.
import { readFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { parse, canonicalize, verify, verifySig, did } from 'sigelo';

export const URI = 'https://github.com/csigelo/sigelo/tree/main/integrations/a2a';
const exts = (card) => (card?.capabilities?.extensions ?? []).filter((e) => e?.uri === URI);

/** What the identity key signs: the card minus A2A `signatures` and this `params.sig`, hashed (JCS). */
export function cardBody(card) {
  const [ext] = exts(card), { sig, ...params } = ext.params;
  const { signatures, ...rest } = card, unsigned = { ...rest, capabilities: { ...card.capabilities,
    extensions: card.capabilities.extensions.map((e) => (e === ext ? { ...e, params } : e)) } };
  const h = createHash('sha256').update(canonicalize(unsigned)).digest('hex');
  return { v: 'sigelo/0', typ: 'a2a-card', did: params.did, card: `sha256:${h}` };
}

/** Throws on any failure; returns the SPEC §9.1 result for the carried bundle. */
export function verifyCard(card, now = Math.floor(Date.now() / 1000)) {
  if (exts(card).length !== 1) throw new Error('a2a-card: not exactly one sigelo extension');
  const { did: claimed, bundle, sig } = exts(card)[0].params ?? {};
  const r = verify(bundle, now);                                     // SPEC §9, offline
  if (r.did !== claimed) throw new Error("a2a-card: did is not the bundle's current DID");
  const g = [bundle.genesis, ...bundle.rotations.map((x) => x.next_genesis)].find((x) => did(x) === r.did);
  if (!verifySig(g.key, cardBody(card), sig)) throw new Error('a2a-card: bad signature');
  return r;
}

if (process.argv[1] && realpathSync(process.argv[1]) === import.meta.filename) console.log(JSON.stringify(verifyCard(parse(readFileSync(process.argv[2], 'utf8'))), null, 2));
