// SPDX-License-Identifier: MIT
/**
 * sigelo v0.1 adapter — the AGENT side, for moadim (github.com/moadim-io/daemon).
 *
 * A moadim routine runs its agent in a throwaway workbench under `~/.moadim/workbenches/`,
 * reaped on a 5-minute sweep, so nothing the agent holds survives the run. This file is the
 * one thing that does: an identity in `~/.config/moadim/sigelo.local.json`, beside
 * `machine.local.toml`, created once and carried across every later session — the same
 * identity-on-first-run precedent as `src/machine/mod.rs::resolve()`, with a keypair instead
 * of `machine-{8hex}`.
 *
 * SIDECAR: zero Rust changes. moadim reaches it through `routine.local.toml`'s `[env]`
 * table (see INTEGRATION.md); the agent invokes it as a CLI.
 *
 * The identity key is HOT (THREAT-MODEL §1): it lives one pipe away from a process that
 * reads untrusted text all day. So this file signs exactly one thing on request — a world's
 * challenge, `typ` checked (SPEC §3) — and the recovery key is never here, not even its
 * public half. Recovery rotation is an offline procedure; `cli.ts` prints the recipe.
 *
 * The payment side lives next door in `sigelo-agent-monero.ts` — same store, same hot-key
 * discipline, separate file so this core stays inside the 100-line adoption budget. Nothing
 * here knows what a wallet is; it only carries the `bindings` that file mints (SPEC §6).
 */
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join } from 'node:path';
import type { Attestation, Binding, Bundle, Genesis, Rotation, VerifyResult } from 'sigelo';
import type { MoneroWallet } from './sigelo-agent-monero.ts';
import { did, keygen, parseBytes, rotate, sign, SigeloError, structure, verify, VERSION } from 'sigelo';

/** The whole persistent identity. One file, 0600, written atomically. */
export interface Store {
  v: string; secret: string; genesis: Genesis;
  rotations: Rotation[]; attestations: Attestation[]; issuers: Genesis[];
  /** Written only by sigelo-agent-monero.ts; absent in an identity-only install. */
  bindings?: Binding[]; monero?: MoneroWallet;
}

/**
 * Where the identity lives. `SIGELO_IDENTITY` (set by the routine's `[env]`) wins; otherwise
 * moadim's own config root, resolved the way `src/paths/mod.rs::config_root_from()` resolves
 * it — `$XDG_CONFIG_HOME` when absolute, else `$HOME/.config` — so both agree after a
 * relocated config tree. `.local.` keeps it inside the `*.local.*` pattern that
 * `src/cli/ensure_config_gitignore.rs` seeds, so a shared config repo never carries a key.
 */
export function identityPath(env: Record<string, string | undefined> = process.env): string {
  if (env['SIGELO_IDENTITY']) return env['SIGELO_IDENTITY'];
  const xdg = env['XDG_CONFIG_HOME'];
  const root = xdg && isAbsolute(xdg) ? xdg : join(env['HOME'] ?? homedir(), '.config');
  return join(root, 'moadim', 'sigelo.local.json');
}

export const secretOf = (s: Store): Uint8Array => Uint8Array.from(Buffer.from(s.secret, 'hex'));
/** Every DID this identity has had, oldest first — what attestations may name as `sub` (§7.3). */
export const chainOf = (s: Store): string[] => [did(s.genesis), ...s.rotations.map((r) => did(r.next_genesis))];
/** The genesis the CURRENT secret belongs to: the last rotation's, else the original. */
export const head = (s: Store): Genesis => s.rotations.at(-1)?.next_genesis ?? s.genesis;

/** Read the store. sigelo's duplicate-key-rejecting parser, not `JSON.parse`, over fatally decoded bytes (§3). */
export function load(path: string): Store {
  if (!existsSync(path)) throw new SigeloError(`load: no identity at ${path} — run \`sigelo-agent init\` first`);
  return parseBytes(readFileSync(path)) as Store;
}

/**
 * Temp sibling + rename, 0600 in a 0700 directory — moadim's own contract for files holding
 * secrets (`src/utils/atomic.rs::create_private`, `src/utils/fs_perms.rs`). A torn write here
 * would lose the only copy of the key, and a rotation swaps the secret and appends the
 * rotation in this one write, so the two can never disagree.
 */
export function save(path: string, store: Store): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(8).toString('hex')}.tmp`);
  writeFileSync(tmp, JSON.stringify(store, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  renameSync(tmp, path);
}

/** First run. `recovery` is the recovery PUBLIC key (multibase); `keygen` warns when it is null. */
export function init(path: string, recovery: string | null): Store {
  if (existsSync(path)) throw new SigeloError(`init: ${path} already holds an identity — refusing to overwrite it`);
  const id = keygen({ recovery });
  const store: Store = { v: VERSION, secret: Buffer.from(id.secret).toString('hex'), genesis: id.genesis, rotations: [], attestations: [], issuers: [] };
  save(path, store);
  return store;
}

/**
 * Sign a world's challenge — `{ v, typ: "challenge", did, ctx, nonce }`, SPEC §5.2. `typ` is inside the signed bytes (SPEC §3), so these two checks are
 * what keep the hot key from ever signing a rotation, binding or attestation by accident: a
 * caller who can choose the body could otherwise have it sign away the identity.
 */
export function signChallenge(s: Store, body: Record<string, unknown>): { did: string; sig: string } {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new SigeloError('sign-challenge: body is not a JSON object');
  if (body['typ'] !== 'challenge') throw new SigeloError(`sign-challenge: typ is ${JSON.stringify(body['typ'])}, not "challenge" — this key signs challenges and nothing else`);
  // §5.2: five fields and no others. `typ` already keeps the signature out of every bundle
  // slot; this keeps a world from riding extra content into the signed bytes anyway.
  const extra = Object.keys(body).filter((k) => !['v', 'typ', 'did', 'ctx', 'nonce'].includes(k));
  if (extra.length) throw new SigeloError(`sign-challenge: a challenge has exactly v, typ, did, ctx, nonce — refusing extra field(s) ${extra.join(', ')}`);
  structure(body, 'challenge');
  const d = did(head(s));
  if (body['did'] !== d) throw new SigeloError(`sign-challenge: body.did is ${JSON.stringify(body['did'])}, not this identity's ${d} (DIDs compare in full, SPEC §9 step 1)`);
  return { did: d, sig: sign(secretOf(s), body) };
}

/** Store a world's attestation. Opaque here — structure only, no judgement (SPEC §9.8). */
export function addAttestation(s: Store, a: Attestation): Store {
  structure(a?.body, 'attestation');
  if (typeof a.sig !== 'string') throw new SigeloError('add-attestation: missing sig');
  if (!chainOf(s).includes(a.body.sub)) throw new SigeloError(`add-attestation: sub ${a.body.sub} is not a DID of this identity`);
  // SPEC §5: there is no revocation list, freshness comes from reissuance — so a fresh
  // attestation from the same issuer for the same `ctx` replaces the one it supersedes.
  s.attestations = s.attestations.filter((x) => x.body.iss !== a.body.iss || x.body.ctx !== a.body.ctx).concat({ body: a.body, sig: a.sig }); // §3.1: nothing unsigned rides along
  return s;
}

/** Store an issuer's genesis. Without it that world's attestations count for nothing (§8). */
export function addIssuer(s: Store, g: Genesis): Store {
  structure(g, 'genesis');
  if (!s.issuers.some((x) => did(x) === did(g))) s.issuers.push(g);
  return s;
}

/** SPEC §8. `bindings` is whatever `bind` has stored — empty until a wallet is bound. */
export const bundleOf = (s: Store): Bundle => ({
  v: VERSION, typ: 'bundle', genesis: s.genesis, rotations: s.rotations,
  bindings: s.bindings ?? [], attestations: s.attestations, issuers: s.issuers,
});

/** Verified before it is ever printed: a bundle that does not verify is a bug here. */
export function bundle(s: Store, now: number): { bundle: Bundle; result: VerifyResult } {
  const b = bundleOf(s);
  return { bundle: b, result: verify(b, now) };
}

/** Voluntary rotation (SPEC §7). Recovery rotation is NOT here — it needs the offline key.
 *  Never append the same rotation twice: two byte-identical entries are two candidates, a fork
 *  (SPEC §7.4). Each call rotates from the head, and `adopt --rotation` refuses a known `next`. */
export function rotateKey(s: Store, now: number): Store {
  const cur = head(s);
  // This process holds only the commitment: the recovery key's public half is deliberately
  // absent from the agent's file (SPEC §4 — an attacker with full agent compromise should
  // learn a hash). `keygen` accepts the commitment verbatim, so the new genesis carries it
  // forward unchanged, which is what §7 demands and what `rotate()` re-checks before signing.
  const fresh = keygen({ recovery: cur.recovery });
  s.rotations.push(rotate({ genesis: cur, next_genesis: fresh.genesis, iat: now, reason: 'voluntary', secret: secretOf(s) }));
  s.secret = Buffer.from(fresh.secret).toString('hex');
  return s;
}
