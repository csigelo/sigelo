// SPDX-License-Identifier: MIT
// sim/licence.mjs — a scratch keeper's licence (spend/licence.ts), so the sims run the paid verbs
// (/delegate, /fund, /approve, pays above approval_above) as a pro customer would.
//
// The way spend/soak/gen-keys.mjs `licence` and commercial/issue-licence.mjs do it, offline: a
// throwaway TEST VENDOR identity is minted from the caller's seeded bytes, and sigelo's own
// `attest` issues {tier: "pro", seats} to the keeper's DID in the chain-carrying format
// {attestation, issuer, rotations}. The keeper accepts it only because SIGELO_VENDOR_DID names the
// test vendor (set here in process.env, so the keeper child inherits it); SIGELO_SPEND_REGISTRY
// points at a file in the scratch directory, so the host's real keeper registry is never read or
// written and the seat count is this keeper alone. The licence is checked with the keeper's own
// checkLicence before it is used: a sim that thinks it is pro and is not would report the wrong bugs.
import { renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { attest, keygen } from '../ts/dist/sigelo.js';

/** A throwaway vendor identity ({did, genesis, secret}); `bytes(n)` is the caller's seeded stream. */
export const testVendor = (bytes) => keygen({ recovery: bytes(32), seed: bytes(32) });

/**
 * Key the scratch keeper in `dir`: spend.key from `bytes`, so its DID is known before it starts.
 * Sets SIGELO_VENDOR_DID and SIGELO_SPEND_REGISTRY for this process and the keeper children it
 * spawns. Returns {did, genesis}: no identity.json, so the keeper's DID is the legacy genesis of
 * spend.key (service.ts loadKeeper).
 */
export async function keyKeeper({ dir, spendDist, bytes, vendor }) {
  const { keeperIdentity } = await import(pathToFileURL(join(spendDist, 'service.js')).href);
  process.env.SIGELO_VENDOR_DID = vendor.did;
  process.env.SIGELO_SPEND_REGISTRY = join(dir, 'keepers-registry.json');
  const K = bytes(32);
  writeFileSync(join(dir, 'spend.key'), Buffer.from(K).toString('hex') + '\n', { mode: 0o600 });
  const id = keeperIdentity(K);
  return { did: id.did, genesis: id.genesis };
}

/**
 * Issue `keeper` a pro licence from `vendor` and write it to `dir`/licence.json (a running keeper
 * reads it before its next paid verb). Returns checkLicence's status; throws if it is not pro.
 */
export async function installLicence({ dir, spendDist, vendor, keeper, seats = 1, days = 30 }) {
  const lic = await import(pathToFileURL(join(spendDist, 'licence.js')).href);
  const iat = Math.floor(Date.now() / 1000) - 60;
  const file = { attestation: attest({ secret: vendor.secret, iss: vendor.did, sub: keeper.did, iat, exp: iat + days * 86400,
    ctx: lic.LICENCE_CTX, admission: 'payment', claims: { tier: 'pro', seats } }), issuer: vendor.genesis, rotations: [] };
  const status = lic.checkLicence(file, keeper.genesis, dir, Math.floor(Date.now() / 1000), []);
  if (status.tier !== 'pro' || status.legacy) throw new Error(`sim/licence.mjs: the test licence does not make the keeper pro: ${lic.describe(status)}`);
  writeFileSync(join(dir, `${lic.LICENCE_FILE}.new`), JSON.stringify(file, null, 2) + '\n', { mode: 0o600 });
  renameSync(join(dir, `${lic.LICENCE_FILE}.new`), join(dir, lic.LICENCE_FILE));
  return status;
}
