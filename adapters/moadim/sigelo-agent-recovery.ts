// SPDX-License-Identifier: MIT
/**
 * The recovery key from the installed CLI alone: `sigelo-agent recovery-key`, `recover` and
 * `erase-request`. Counted apart from the 77-line identity core, as the Monero, adopt and contact
 * halves are (INTEGRATION.md).
 *
 *   recoveryKey(out)            a fresh Ed25519 keypair: the secret, hex, to `out` (0600, never over
 *                               an existing file), the public z… key to pubPath(out); → that key for
 *                               `init --recovery`. Only its hash reaches the identity (SPEC §4).
 *   recoverWith(path, file, t)  SPEC §7's recovery rotation from the last honest node to a fresh key,
 *                               signed by the secret in `file`, applied as `adopt --rotation` applies one.
 *   eraseRequest(path, file, access, t)
 *                               a data request to sigelo.ai (relay/site/agents.md "Erasure"): a §5.2
 *                               challenge for the original DID, ctx sigelo.ai/erase or sigelo.ai/access,
 *                               nonce the UTC date, signed by the recovery key; with that key and the
 *                               chain, whose genesis or recovery commits to it.
 *
 * Made here, the key has passed through this machine: the files go offline at once (THREAT-MODEL §5:
 * a recovery key beside the identity key protects nothing), and come back only for `recover` or
 * `erase-request`, which keep nothing of it. The public half goes with them: the identity file
 * holds only its hash (SPEC §4), and the operator needs the key itself to check a request. No
 * crypto here: keygen, sign, the signer behind `sigelo-offline recover` (ceremony.ts recover) and
 * adopt's applyRotation do the work.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import type { Genesis } from 'sigelo';
import { commitmentOf, did, keygen, sign, SigeloError, VERSION } from 'sigelo';
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
  // Beside it, over any older one: it names the key in `out`, which is new.
  writeFileSync(pubPath(out), k.key + '\n', { mode: 0o600 });
  return k.key;
}

/** Where recoveryKey puts the public key: recovery.key → recovery.pub, anything else → <file>.pub. */
export const pubPath = (file: string): string => (file.endsWith('.key') ? file.slice(0, -4) : file) + '.pub';

/** → { body, recovery_key, sig, bundle }: the request agents.md asks for, in one file. bundle: the
 *  chain only (genesis and rotations), so the operator checks the key against the chain offline. */
export function eraseRequest(path: string, file: string, access: boolean, now: number): object {
  const s = load(path), secret = secretIn(file, 'erase-request');
  try {
    const key = keygen({ recovery: UNUSED, seed: secret }).key, commits = head(s).recovery;
    // Voluntary rotations carry the commitment forward and a recovery may replace it: the head's
    // is the one in force (SPEC §4, §7).
    if (commitmentOf(key) !== commits) throw new SigeloError(`erase-request: the key in ${file} is not this identity's recovery key (its public half does not hash to ${commits ?? 'null: this identity has no recovery key'})`);
    const body = { v: VERSION, typ: 'challenge', did: did(s.genesis), ctx: access ? 'sigelo.ai/access' : 'sigelo.ai/erase', nonce: new Date(now * 1000).toISOString().slice(0, 10) };
    return { body, recovery_key: key, sig: sign(secret, body),
      bundle: { v: VERSION, typ: 'bundle', genesis: s.genesis, rotations: s.rotations, bindings: [], attestations: [], issuers: [] } };
  } finally { secret.fill(0); }
}

/** The secret in `file`: 64 hex characters, as recoveryKey writes it. */
function secretIn(file: string, verb = 'recover'): Uint8Array {
  const text = readFileSync(file, 'utf8').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new SigeloError(`${verb}: ${file} does not hold a recovery key (64 hex characters, as recovery-key writes it)`);
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
