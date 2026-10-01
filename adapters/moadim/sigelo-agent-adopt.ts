// SPDX-License-Identifier: MIT
/**
 * Keys this process did not generate. `init` makes a key here; these two take one made
 * elsewhere and make it the identity file:
 *
 *   adopt          a keeper-minted identity — `POST /delegate`'s `{identity_seed_hex, genesis}`
 *                  (spend/README.md), or any `{identity_seed_hex, genesis}` — as a fresh file.
 *   applyRotation  a rotation signed elsewhere plus its new secret — `sigelo-offline recover`'s
 *                  `{did, rotation, identity_seed_hex}` — appended to the existing file, so a
 *                  recovered identity keeps its genesis, its chain and its attestations.
 *
 * Kept out of sigelo-agent.ts so the identity core an integrator reads stays at its line count.
 * Both refuse anything that does not check: a seed that is not the genesis key, a rotation
 * whose chain does not end at the new key under the §9 verifier.
 */
import { existsSync } from 'node:fs';
import type { Genesis, Rotation } from 'sigelo';
import { did, sign, SigeloError, structure, verify, verifySig, VERSION } from 'sigelo';
import { bundleOf, chainOf, save, type Store } from './sigelo-agent.ts';

const HEX32 = /^[0-9a-f]{64}$/;

/** The seed, checked against the key it must produce: a signature under it verifies under `key`. */
function seedFor(what: string, hex: unknown, key: string): string {
  if (typeof hex !== 'string' || !HEX32.test(hex)) throw new SigeloError(`${what}: identity_seed_hex is not 64 lowercase hex characters`);
  const probe = { typ: 'sigelo-agent-adopt-probe', key };
  if (!verifySig(key, probe, sign(Uint8Array.from(Buffer.from(hex, 'hex')), probe))) {
    throw new SigeloError(`${what}: identity_seed_hex does not produce ${key} — this is not that identity's key`);
  }
  return hex;
}

const obj = (what: string, x: unknown): Record<string, unknown> => {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) throw new SigeloError(`${what}: input is not a JSON object`);
  return x as Record<string, unknown>;
};

/** A fresh identity file from `{identity_seed_hex, genesis, did?}`; other fields (a /delegate
 *  answer's token, url, …) are ignored and never written. `init`'s format exactly. */
export function adopt(path: string, input: unknown, force: boolean): Store {
  const i = obj('adopt', input);
  structure(i['genesis'], 'genesis');
  const genesis = i['genesis'] as Genesis;
  if (i['did'] !== undefined && i['did'] !== did(genesis)) throw new SigeloError(`adopt: did ${JSON.stringify(i['did'])} is not the DID of the genesis given (${did(genesis)})`);
  const secret = seedFor('adopt', i['identity_seed_hex'], genesis.key);
  if (existsSync(path) && !force) throw new SigeloError(`adopt: ${path} already holds an identity — refusing to overwrite it (--force replaces it, and loses its attestations)`);
  const store: Store = { v: VERSION, secret, genesis, rotations: [], attestations: [], issuers: [] };
  save(path, store);
  return store;
}

/**
 * Append `{rotation, identity_seed_hex}`. `rotation.id` must be a DID of this chain: the head,
 * or — recovery only — an earlier node, the last honest one (SPEC §7.1); the rotations after
 * it are then dropped from the file (a thief's or a compromised run's), as are attestations
 * and bindings naming the dropped DIDs. The result must verify with the new DID at the head,
 * else nothing is written.
 */
export function applyRotation(s: Store, input: unknown, now: number): { store: Store; dropped: number } {
  const i = obj('adopt --rotation', input);
  const r = obj('adopt --rotation: rotation', i['rotation']) as unknown as Rotation;
  structure(r.body, 'rotation');
  structure(r.next_genesis, 'genesis');
  const secret = seedFor('adopt --rotation', i['identity_seed_hex'], r.next_genesis.key);
  const chain = chainOf(s), at = chain.indexOf(r.body.id);
  if (chain.includes(r.body.next)) throw new SigeloError(`adopt --rotation: ${r.body.next} is already in this chain — applied before?`);
  if (at < 0) throw new SigeloError(`adopt --rotation: rotation.id ${r.body.id} is not a DID of this identity (chain: ${chain.join(', ')})`);
  if (at < chain.length - 1 && r.body.reason !== 'recovery') throw new SigeloError(`adopt --rotation: a voluntary rotation from ${r.body.id}, which is not the head, is a fork (SPEC §7.3) — only a recovery rotation may start from an earlier node`);
  const dropped = s.rotations.length - at;
  const kept = new Set(chain.slice(0, at + 1).concat(r.body.next));
  const next: Store = {
    ...s, secret, rotations: s.rotations.slice(0, at).concat(r),
    attestations: s.attestations.filter((a) => kept.has(a.body.sub)),
    ...(s.bindings ? { bindings: s.bindings.filter((b) => kept.has(b.body.id)) } : {}),
  };
  const got = verify(bundleOf(next), now).did; // throws the §9 reason if the chain is rejected
  if (got !== r.body.next) throw new SigeloError(`adopt --rotation: the chain does not follow this rotation (head is ${got}) — a recovery key that is not this identity's, or a voluntary rotation that changes the recovery commitment (SPEC §7.4)`);
  return { store: next, dropped };
}
