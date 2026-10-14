// SPDX-License-Identifier: MIT
/**
 * The recovery key from the installed CLI alone: `sigelo-agent recovery-key` and `recover`. Counted
 * apart from the 77-line identity core, as the Monero, adopt and contact halves are (INTEGRATION.md).
 *
 *   recoveryKey(out)            a fresh Ed25519 keypair: the secret, hex, to `out` (0600, never over
 *                               an existing file); → the public z… key for `init --recovery`. Only its
 *                               hash reaches the identity (SPEC §4).
 *   recoverWith(path, file, t)  SPEC §7's recovery rotation from the last honest node to a fresh key,
 *                               signed by the secret in `file`, applied as `adopt --rotation` applies one.
 *
 * Made here, the key has passed through this machine: the file goes offline at once (THREAT-MODEL §5:
 * a recovery key beside the identity key protects nothing), and comes back only for `recover`, which
 * keeps nothing of it. No crypto here: keygen, the signer behind `sigelo-offline recover`
 * (ceremony.ts recover) and adopt's applyRotation do the work.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import type { Genesis } from 'sigelo';
import { did, keygen, SigeloError } from 'sigelo';
import { recover } from 'sigelo/dist/ceremony.js';
import { applyRotation } from './sigelo-agent-adopt.ts';
import { withLock } from './sigelo-agent-monero.ts';
import { chainOf, head, load, save, type Store } from './sigelo-agent.ts';

// keygen makes the keypair. The commitment it is handed lands in a genesis nobody keeps: only
// `secret` (the recovery key) and `key` (its public half) are used.
const UNUSED = 'sha256:' + '0'.repeat(64);

export function recoveryKey(out: string): string {
  const k = keygen({ recovery: UNUSED });
  try {
    // 'wx': an identity may already commit to the key in an existing file, its only copy.
    writeFileSync(out, Buffer.from(k.secret).toString('hex') + '\n', { mode: 0o600, flag: 'wx' });
  } catch (e) {
    if ((e as { code?: string }).code === 'EEXIST') throw new SigeloError(`recovery-key: ${out} exists: refusing to overwrite what may be an identity's recovery key; pass another --out`);
    throw e;
  } finally { k.secret.fill(0); }
  return k.key;
}

/** The secret in `file`: 64 hex characters, as recoveryKey writes it. */
function secretIn(file: string): Uint8Array {
  const text = readFileSync(file, 'utf8').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new SigeloError(`recover: ${file} does not hold a recovery key (64 hex characters, as recovery-key writes it)`);
  return Uint8Array.from(Buffer.from(text, 'hex'));
}

/** The node a recovery starts from: the last one a recovery rotation led to, else the genesis
 *  (ceremony.ts keeperLastHonest walks a keeper's chain the same way). A stolen copy rotates from
 *  the head it had, and the owner may have rotated from that node too, unseen by a relay that now
 *  holds the thief's: from the owner's head the recovery leaves that fork (SPEC §7.3); from here it
 *  supersedes every voluntary rotation after it (§7.1). applyRotation drops them, with the
 *  attestations and bindings naming their DIDs. */
const lastHonest = (s: Store): Genesis => s.rotations.findLast((r) => r.body.reason === 'recovery')?.next_genesis ?? s.genesis;

/** → the node recovered from, the new DID and the chain. Nothing is written unless the result verifies. */
export function recoverWith(path: string, file: string, now: number): { from: string; did: string; chain: string[] } {
  const secret = secretIn(file);
  try {
    return withLock(path, () => {
      const s = load(path), from = lastHonest(s);
      let r: ReturnType<typeof recover>;
      try { r = recover({ from, recoverySecret: secret, iat: now }); } catch (e) {
        // rotate() refuses a key whose public half does not hash to the commitment: say which file.
        if (e instanceof SigeloError && /does not hash to the current commitment/.test(e.message)) {
          throw new SigeloError(`recover: the key in ${file} is not this identity's recovery key (its public half does not hash to the commitment of ${did(from)})`);
        }
        throw e;
      }
      const { store } = applyRotation(s, { rotation: r.rotation, identity_seed_hex: r.identity_seed_hex }, now);
      save(path, store);
      return { from: did(from), did: did(head(store)), chain: chainOf(store) };
    });
  } finally { secret.fill(0); }
}
