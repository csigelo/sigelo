/**
 * The root ceremony and its restore (MONERO.md §4.5, §8 G7), as a library so the one step that
 * touches the outside world — age encryption — is a small injectable `Age`. src/offline.ts is
 * the CLI over it; src/test.ts drives it with a fake `Age` where the binary is absent.
 *
 * `S` goes from the RNG to `deriveRoot` and into age's stdin as the §4.5 backup JSON, and
 * nowhere else: no file but `backup.age`, no return value, no stdout. Neither is the recovery
 * secret written anywhere but inside the backup. Files written to `out` (created 0700, must
 * be empty or absent):
 *
 *   backup.age        age -r <Owner> over { v, mnemonic, created, keepers, public }   0600
 *                     (v "sigelo-root/2": `mnemonic` is S as Monero's 25 words)
 *   fingerprint.txt   JCS(public) + "\n" — §4.5's "plaintext copy of public"          0644
 *   keeper-<j>.json   one per keeper: K_j and what that keeper needs to start          0600
 *
 * The one other exit for the 25 words is `tty` (`ceremony --human`, ROADMAP §2 M4): the human
 * running the ceremony sees them on /dev/tty, which the CLI opens itself (`openTty`) so they
 * never pass through stdout, stderr or a pipe an agent reads. `importRoot` is the refusal to
 * make a root of words that already existed.
 *
 * Keeper 0 is the agents' keeper (the `allowance` wallet; account 0 is the root identity's,
 * so it also carries the root identity seed to hand over, §2). A keeper named by
 * `treasuryKeeper` (index ≥ 1: one keeper = one wallet, §2) gets the `treasury` keys, which
 * §4.5 has the ceremony run beside; without it the treasury spend key is in the backup only.
 * The vault (the wallet the 25 words restore, spend key = S) goes to no keeper, ever: its
 * keys are S, and S is every identity (MONERO.md §2).
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, openSync, readdirSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { canonicalize } from './jcs.js';
import { agentIdentitySeed, deriveRoot, identitySeed, keeperRoot, mnemonicFromRoot, newRoot, recoverySeed, rootFromMnemonic } from './keys.js';
import { decodeAddress, Net } from './monero.js';
import { Bundle, did, encodeKey, Genesis, keygen, rotate, Rotation, SigeloError, structure, verify } from './sigelo.js';

/** The age step. `encrypt` takes the recipient, `decrypt` a path to an identity file. */
export interface Age { encrypt(recipient: string, plaintext: Uint8Array): Uint8Array; decrypt(identity: string, ciphertext: Uint8Array): Uint8Array }

/**
 * `age` or `rage` from PATH, recipient on the command line and plaintext on stdin (no npm
 * dependency, and the Owner restores with the stock binary). A string is the refusal to print.
 */
export function ageBinary(): Age | string {
  const bin = ['age', 'rage'].find((b) => spawnSync(b, ['--version']).error === undefined);
  if (bin === undefined) return 'ceremony: neither `age` nor `rage` is on PATH — install one (Alpine: apk add age; Debian/Ubuntu: apt install age; macOS: brew install age; Windows: winget install FiloSottile.age) and run again. Nothing was written.';
  const run = (args: string[], input: Uint8Array, what: string): Uint8Array => {
    const r = spawnSync(bin, args, { input, maxBuffer: 1 << 24 });
    // age's stderr names the problem (bad recipient, wrong identity); it never echoes stdin.
    if (r.status !== 0) throw new SigeloError(`${what}: ${bin} exited ${r.status}: ${r.stderr.toString().trim()}`);
    return new Uint8Array(r.stdout);
  };
  return {
    encrypt: (recipient, p) => run(['-r', recipient], p, 'ceremony: encrypting the backup'),
    decrypt: (identity, c) => run(['-d', '-i', identity], c, 'restore: decrypting the backup'),
  };
}

/** An age X25519 or plugin recipient (bech32 `age1…`), or an SSH public key age accepts. */
export function checkRecipient(r: string): void {
  if (/^age1[02-9ac-hj-np-z]{58,}$/.test(r) || /^ssh-(ed25519|rsa) [A-Za-z0-9+/=]+( \S*)?$/.test(r)) return;
  throw new SigeloError(`ceremony: --recipient ${JSON.stringify(r)} is not an age recipient (age1… from age-keygen -y, or an ssh-ed25519 key)`);
}

type Derived = ReturnType<typeof deriveRoot>;
const hex = bytesToHex;
const wallet = (w: Derived['treasury']) => ({ spend_key: hex(w.b), view_key: hex(w.a), address: w.address });
const pubkey = (seed: Uint8Array): string => encodeKey(ed.getPublicKey(seed));
/** §4.5's `public`: the backup's fingerprint. JCS so the Owner can compare it byte for byte. */
const publicOf = (d: Derived) => ({ treasury: d.treasury.address, allowance: d.allowance.address, recovery_commitment: d.recovery.commitment });
const role = (j: number, t?: number): string => (j === 0 ? 'agents' : j === t ? 'treasury' : 'keeper');

/** Where `--human` shows the 25 words: the CLI's is `openTty()`; a test injects its own. */
export type Tty = (text: string) => void;

/**
 * /dev/tty for writing, opened explicitly: the controlling terminal of whoever runs the
 * command, whatever stdout and stderr are redirected to. No terminal (a service, a pipe from
 * an agent's tool call, `setsid`) is a refusal string, never a fallback to stdout.
 */
export function openTty(path = '/dev/tty'): Tty | string {
  let fd: number;
  try { fd = openSync(path, 'w'); } catch (e) {
    return `ceremony --human: cannot open ${path} (${(e as { code?: string }).code ?? String(e)}) — --human is for a person at a terminal, and the words are never written to stdout or stderr instead. Nothing was written.`;
  }
  return (text) => { writeSync(fd, text); };
}

/** The --human screen. "Vault only, never a hot wallet" is ROADMAP §2's one line. */
function humanScreen(words: string, vault: string): string {
  const w = words.split(' ');
  const rows = [0, 5, 10, 15, 20].map((i) => w.slice(i, i + 5).map((x, k) => `${String(i + k + 1).padStart(2)} ${x.padEnd(12)}`).join('').trimEnd());
  return ['', '*** sigelo root: the 25 words, shown once, on this terminal only ***',
    'Write them on paper now. They are the vault\'s Monero seed and the root of every identity,',
    'keeper and wallet below it; backup.age holds the same words for the Owner\'s age key.',
    'Vault only, never a hot wallet: never type them into a mobile or desktop wallet or any networked device.',
    '', ...rows, '', `vault address  ${vault}`,
    'Then clear this terminal\'s scrollback (and stop any recording of it).', '', ''].join('\n');
}

/** The M4 sentence: why `ceremony --import` refuses without `--i-know-this-seed-was-cold`. */
export const IMPORT_REFUSED = 'ceremony: importing an existing seed is refused by default — a seed that has been in a hot wallet is not a root (ROADMAP §2 M4). ' +
  'Run the ceremony without --import to generate one. Only if these words have existed solely on paper or an air-gapped box, never in a wallet on a networked device, pass --i-know-this-seed-was-cold.';
/** What `--i-know-this-seed-was-cold` makes the operator accept, printed on every such run. */
export const IMPORT_LIABILITY = 'ceremony: --i-know-this-seed-was-cold: you vouch that these words were never in a hot wallet. If they were, whoever copied them ' +
  'from that device holds the vault, the treasury, the allowance, every keeper root, every identity and the recovery key, and no rotation takes that back — ' +
  'only moving every coin to a new root does (MONERO.md §4.6).';

/** An existing root for the ceremony, refused unless `cold`. `read` runs only once allowed, so a refused import never reads the words. */
export function importRoot(read: () => string, cold: boolean): Uint8Array {
  if (!cold) throw new SigeloError(IMPORT_REFUSED);
  return rootFromMnemonic(read());
}

export interface CeremonyOpts { net: Net; recipient: string; out: string; keepers?: number; treasuryKeeper?: number; age: Age; created?: number; S?: Uint8Array; tty?: Tty }

/** Run §4.5 steps 2–6. Returns only public values, which is all the CLI prints. */
export function ceremony(o: CeremonyOpts) {
  const n = o.keepers ?? 1;
  checkRecipient(o.recipient);
  if (!Number.isSafeInteger(n) || n < 1) throw new SigeloError(`ceremony: --keepers must be a positive integer, got ${n}`);
  const t = o.treasuryKeeper;
  if (t !== undefined && !(Number.isSafeInteger(t) && t >= 1 && t < n)) throw new SigeloError(`ceremony: --treasury-keeper must be 1…${n - 1} (keeper 0 serves allowance; one keeper = one wallet), got ${t}`);
  mkdirSync(o.out, { recursive: true, mode: 0o700 });
  if (readdirSync(o.out).length > 0) throw new SigeloError(`ceremony: ${o.out} is not empty — refusing to overwrite an earlier ceremony's backup`);

  const mnemonic = o.S === undefined ? newRoot() : mnemonicFromRoot(o.S); // refuses a non-canonical S
  const S = rootFromMnemonic(mnemonic);
  const d = deriveRoot(S, o.net, 0, n);
  const keepers = d.keepers.map((K, j) => ({ j, role: role(j, t), identity: pubkey(identitySeed(K, 0)) }));
  const pub = publicOf(d);
  const backup = { v: 'sigelo-root/2', mnemonic, created: o.created ?? Math.floor(Date.now() / 1000), keepers, public: pub };
  // Encrypt before writing anything: a failed age leaves the directory empty.
  const sealed = o.age.encrypt(o.recipient, new TextEncoder().encode(JSON.stringify(backup)));
  S.fill(0);
  const write = (name: string, body: string | Uint8Array, mode: number): string => (writeFileSync(join(o.out, name), body, { mode, flag: 'wx' }), name);
  const files = [write('backup.age', sealed, 0o600), write('fingerprint.txt', canonicalize(pub) + '\n', 0o644)];
  d.keepers.forEach((K, j) => {
    const pkg = {
      v: 'sigelo-keeper/1', j, role: role(j, t), net: o.net,
      keeper_root_hex: hex(K), identity_public_key: keepers[j]!.identity, recovery_commitment: d.recovery.commitment,
      ...(j === 0 ? { allowance: wallet(d.allowance), root_identity_seed_hex: hex(d.identity) } : {}),
      ...(j === t ? { treasury: wallet(d.treasury) } : {}),
    };
    files.push(write(`keeper-${j}.json`, JSON.stringify(pkg, null, 2) + '\n', 0o600));
  });
  // Only once backup.age exists: a human never copies words that no backup holds.
  o.tty?.(humanScreen(mnemonic, d.vault.address));
  return { net: o.net, public: pub, fingerprint: canonicalize(pub), vault: d.vault.address, keepers, files };
}

/**
 * What `derive` and `restore` print from a root. Without `revealAll`: the agent's seed and
 * treasury view (`agent`, the shape `sigelo-agent wallet-set` takes), each keeper's `K_j`
 * and the allowance wallet (`agents_keeper`), the recovery public half, the vault's address.
 * The treasury spend key, the vault's keys and the recovery secret appear only under
 * `revealAll`, as `owner_backup`.
 */
export function roles(d: Derived, net: Net, revealAll: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {
    net,
    agent: { identity_seed_hex: hex(d.identity), treasury: { view_key: hex(d.treasury.a), public_spend_key: hex(d.treasury.B), address: d.treasury.address } },
    agents_keeper: { allowance: wallet(d.allowance), keeper_root_hex: hex(d.keepers[0]!) },
    keepers: d.keepers.map((K, j) => ({ j, keeper_root_hex: hex(K) })),
    recovery: { public_key_multibase: d.recovery.key, commitment: d.recovery.commitment },
    vault: { address: d.vault.address },
  };
  if (revealAll) out['owner_backup'] = { vault: wallet(d.vault), treasury: wallet(d.treasury), recovery: { secret_key_hex: hex(d.recovery.seed) } };
  return out;
}

/** Re-derive from `S` and, given the expected `public`, refuse unless the result reproduces it. */
function fromRoot(S: Uint8Array, net: Net, keepers: number, expected: { treasury?: unknown } | undefined, revealAll: boolean) {
  const d = deriveRoot(S, net, 0, keepers);
  S.fill(0);
  const fingerprint = canonicalize(publicOf(d));
  if (expected !== undefined && fingerprint !== canonicalize(expected)) {
    const was = typeof expected.treasury === 'string' ? (() => { try { return decodeAddress(expected.treasury as string).net; } catch { return '?'; } })() : '?';
    throw new SigeloError(`restore: fingerprint mismatch — the backup's public values are for ${was}, re-derived for ${net}${was === net ? ' (the backup is corrupt, or these are other words)' : ''}`);
  }
  const all = roles(d, net, revealAll);
  return revealAll ? { fingerprint, ...all } : { fingerprint, net, vault: all['vault'], keepers: all['keepers'] };
}

/**
 * The Owner's restore: decrypt, re-derive, and refuse unless the result reproduces the
 * backup's own `public` — §4.5's "compare against the fingerprint", done by the program.
 */
export function restore(o: { backup: Uint8Array; identity: string; net: Net; age: Age; revealAll?: boolean }) {
  let b: { v?: unknown; mnemonic?: unknown; keepers?: unknown; public?: { treasury?: unknown } };
  // Fatal decode: a backup whose plaintext is not UTF-8 is damaged, and U+FFFD would hide that.
  try { b = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(o.age.decrypt(o.identity, o.backup))); } catch (e) {
    if (e instanceof SigeloError) throw e;
    throw new SigeloError('restore: the decrypted backup is not UTF-8 JSON');
  }
  // v1 carried S as BIP-39 words (same derivations), which this version no longer decodes.
  if (b.v === 'sigelo-root/1') throw new SigeloError('restore: a sigelo-root/1 backup (BIP-39 words) — this version reads sigelo-root/2 (Monero 25 words) only');
  if (b.v !== 'sigelo-root/2' || typeof b.mnemonic !== 'string' || !Array.isArray(b.keepers)) throw new SigeloError('restore: not a sigelo-root/2 backup');
  return fromRoot(rootFromMnemonic(b.mnemonic), o.net, b.keepers.length, b.public ?? {}, o.revealAll === true);
}

/**
 * The same restore from the 25 words themselves (the human's copy, no age identity): the
 * output `restore` gives for the backup holding them. The words carry no keeper count and no
 * `public`, so `keepers` defaults to 1 and `fingerprint` — fingerprint.txt's contents — is
 * checked when given.
 */
export function restoreWords(o: { words: string; net: Net; keepers?: number; fingerprint?: string; revealAll?: boolean }) {
  let expected: { treasury?: unknown } | undefined;
  if (o.fingerprint !== undefined) {
    try { expected = JSON.parse(o.fingerprint); } catch { throw new SigeloError('restore: --fingerprint is not a fingerprint.txt (JCS of public)'); }
    if (typeof expected !== 'object' || expected === null) throw new SigeloError('restore: --fingerprint is not a fingerprint.txt (JCS of public)');
  }
  return fromRoot(rootFromMnemonic(o.words), o.net, o.keepers ?? 1, expected, o.revealAll === true);
}

/**
 * Where the recovered identity's new key comes from. `agent`: `agentIdentitySeed(K_j, i, n)`,
 * a keeper-minted agent or delegate (INCIDENT.md §5: the same keeper's next `n`, or `K_{j+1}`
 * when the keeper itself burnt). `identity`: the root identity's `identitySeed(S, n)`.
 * `random`: a fresh key nobody can re-derive — the default, and the only choice without `S`.
 */
export type NextKey = { kind: 'agent'; keeper: number; agent: number; n: number } | { kind: 'identity'; n: number } | { kind: 'random' }
  /**
   * A KEEPER's own identity (INCIDENT.md §5): a new keeper root `K'` — `keeperRoot(S, keeper)`, or
   * random without `keeper` — whose `identitySeed(K', 0)` is the new key, as `sigelo-spend` signs
   * with. The output carries `keeper_root_hex` (the new host's `spend.key`) instead of a seed.
   */
  | { kind: 'keeper'; keeper?: number };

/**
 * SPEC §7 recovery rotation from `from`, the LAST HONEST node (§7.1: it beats any voluntary
 * rotation a thief signed there, whatever the `iat`), signed with the recovery secret. Either
 * `S` (the recovery secret is `recoverySeed(S)`, and the derived `NextKey`s become possible)
 * or the bare `recoverySecret`. `nextRecovery` defaults to `from.recovery` (§7: a recovery MAY
 * change it; `null` retires recovery for good). Returns what the agent needs and nothing
 * else: the rotation envelope `rotate()` made, and the NEW identity's seed. Never the
 * recovery secret, never `S`.
 */
export function recover(o: {
  from: Genesis; S?: Uint8Array; recoverySecret?: Uint8Array; next?: NextKey; nextRecovery?: string | null;
  iat: number; created?: string; nonce?: Uint8Array | string;
}): { did: string; rotation: Rotation; identity_seed_hex?: string; keeper_root_hex?: string } {
  structure(o.from, 'genesis');
  if ((o.S === undefined) === (o.recoverySecret === undefined)) throw new SigeloError('recover: pass exactly one of the root S or the recovery secret');
  if (o.from.recovery === null) throw new SigeloError(`recover: ${did(o.from)} has recovery: null — theft of it is terminal and no recovery rotation can exist (SPEC §4)`);
  const secret = o.recoverySecret ?? recoverySeed(o.S!);
  const next = o.next ?? { kind: 'random' };
  const derived = next.kind === 'agent' || next.kind === 'identity' || (next.kind === 'keeper' && next.keeper !== undefined);
  if (derived && o.S === undefined) throw new SigeloError(`recover: a derived new key (${next.kind}) needs the root S, not only the recovery secret`);
  const K = next.kind !== 'keeper' ? undefined : next.keeper === undefined ? randomBytes(32) : keeperRoot(o.S!, next.keeper);
  const seed = next.kind === 'agent' ? agentIdentitySeed(keeperRoot(o.S!, next.keeper), next.agent, next.n)
    : next.kind === 'identity' ? identitySeed(o.S!, next.n) : K !== undefined ? identitySeed(K, 0) : undefined;
  const id = keygen({ recovery: o.nextRecovery === undefined ? o.from.recovery : o.nextRecovery, seed, created: o.created, nonce: o.nonce });
  // A derived index that lands on the stolen key would "recover" into the thief's hands.
  if (id.key === o.from.key) throw new SigeloError('recover: the new key IS the current (stolen) key — pick the next rotation index (--n)');
  // rotate() checks SHA-256(recovery_key) against from.recovery: a wrong root fails here, named.
  const rotation = rotate({ genesis: o.from, next_genesis: id.genesis, iat: o.iat, reason: 'recovery', secret });
  return K !== undefined ? { did: id.did, rotation, keeper_root_hex: bytesToHex(K) } : { did: id.did, rotation, identity_seed_hex: bytesToHex(id.secret) };
}

/**
 * The last honest node of a KEEPER's bundle (its `identity.json`, SPEC §8): the original genesis,
 * or the last node a recovery rotation led to. A keeper never rotates voluntarily (sigelo-spend has
 * no verb for it), so a voluntary step in its chain is the thief's and the walk stops before it.
 */
export function keeperLastHonest(bundle: Bundle, now: number): Genesis {
  const { chain } = verify(bundle, now);
  const genesisOf = new Map<string, Genesis>([[did(bundle.genesis), bundle.genesis]]);
  for (const r of bundle.rotations) genesisOf.set(did(r.next_genesis), r.next_genesis);
  let i = 0;
  while (i + 1 < chain.length && bundle.rotations.some((r) => r.body.id === chain[i] && r.body.next === chain[i + 1] && r.body.reason === 'recovery')) i++;
  return genesisOf.get(chain[i]!)!;
}

/**
 * Recover a keeper's own identity (INCIDENT.md §5): `recover` from `keeperLastHonest`, with a
 * keeper `NextKey`, plus the keeper's bundle with the new rotation appended — what
 * `sigelo-spend init --adopt` takes. The bundle is verified here: its current DID must be the new
 * one, and its original DID (`chain[0]`, the name receipts, approvals and the licence carry) the old.
 */
export function recoverKeeper(o: { bundle: Bundle; S?: Uint8Array; recoverySecret?: Uint8Array; keeper?: number; iat: number }) {
  const from = keeperLastHonest(o.bundle, o.iat);
  const r = recover({ from, S: o.S, recoverySecret: o.recoverySecret, next: { kind: 'keeper', keeper: o.keeper }, iat: o.iat });
  const bundle: Bundle = { ...o.bundle, rotations: [...o.bundle.rotations, r.rotation] };
  const v = verify(bundle, o.iat);
  if (v.did !== r.did) throw new SigeloError(`recover: the keeper bundle with the recovery appended resolves to ${v.did}, not ${r.did}`);
  return { did: v.chain[0]!, current: r.did, rotation: r.rotation, keeper_root_hex: r.keeper_root_hex!, bundle };
}
