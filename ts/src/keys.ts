// SPDX-License-Identifier: MIT
/**
 * Root-seed derivation (MONERO.md §2). One 32-byte root `S`, generated offline, is the only
 * backup; everything else is a pure function of it.
 *
 * ```
 * vault    = the Monero wallet whose 25-word seed is S: b = sc_reduce32(S), a = H_s(b)
 * k(path)  = HKDF-SHA256(ikm = S, salt = "", info = path)          -> 32 bytes
 * identity = Ed25519 seed  k("sigelo/v1/identity/ed25519/<n>")     n = rotation counter
 * recovery = Ed25519 seed  k("sigelo/v1/recovery/ed25519")
 * wallet   = b = sc_reduce32(k("sigelo/v1/monero/<w>"))            a = H_s(b), B = bG, A = aG
 * keeper   = K_j = k("sigelo/v1/keeper/<j>")                        j = keeper index
 * agent    = Ed25519 seed  k(K, "sigelo/v1/identity/<i>/ed25519/<n>")  i = account, on K not S
 * ```
 *
 * Ed25519 takes its seed raw; only the Monero branch reduces mod l. The path string is the
 * HKDF `info` verbatim — change one byte of it and every key below it changes, so the paths
 * are literals here and must never be "tidied".
 *
 * The human carries `S` as a **Monero 25-word seed** (Electrum-style, English): any stock
 * Monero wallet restores the vault from it, and sigelo re-derives everything else from the
 * same words. The vault is the Owner's cold wallet and is never loaded by a keeper; the
 * `treasury` a keeper spends is the derived wallet above (MONERO.md §2). `S` must be a
 * canonical nonzero scalar (0 < S < l): only then is the vault's spend key `S` itself, so the words a wallet
 * shows back are the words sigelo was given.
 */
import * as ed from '@noble/ed25519';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { encodeAddress, keysFromSpend, Net, scReduce32 } from './monero.js';
import { MONERO_WORDS } from './monero-words.js';
import { commitmentOf, encodeKey, Identity, keygen, SigeloError } from './sigelo.js';

/**
 * A fresh root, as its 25 words. Generate it on the air-gapped box and nowhere else (MONERO.md
 * §2). Uniform over [1, l), as Monero's own random32_unbiased (src/crypto/crypto.cpp:168-182):
 * 253 random bits, redrawn while >= l or zero (about half the draws), so the vault's spend key
 * is S itself.
 */
export function newRoot(): string {
  for (;;) {
    const r = randomBytes(32);
    r[31] = r[31]! & 0x1f;
    if (canonical(r)) return encodeMoneroWords(r);
  }
}

/** `k(path) = HKDF-SHA256(ikm = S, salt = "", info = path)`, 32 bytes. */
export function k(S: Uint8Array, path: string): Uint8Array {
  if (S.length !== 32) throw new SigeloError(`root: seed must be 32 bytes, got ${S.length}`);
  return hkdf(sha256, S, new Uint8Array(0), utf8ToBytes(path), 32);
}

/** Ed25519 seed for identity rotation `n`. Raw seed: the Ed25519 branch never reduces. */
export function identitySeed(S: Uint8Array, n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new SigeloError(`identity: rotation counter must be a non-negative integer, got ${n}`);
  return k(S, `sigelo/v1/identity/ed25519/${n}`);
}

/**
 * Keeper root `K_j`: the subtree of `S` one keeper holds so it can mint agent identities
 * after the ceremony has forgotten `S` (MONERO.md §2). A root in its own right: `identitySeed`,
 * `walletFromRoot` and `agentIdentitySeed` all take it where they take `S`.
 */
export const keeperRoot = (S: Uint8Array, j: number): Uint8Array => k(S, `sigelo/v1/keeper/${index('keeper', j)}`);

/**
 * Ed25519 seed for agent `i` (its account index), rotation `n`, under keeper root `K`. The
 * account segment sits before `ed25519`, so no agent path equals a keeper's own
 * `identity/ed25519/<n>`; decimal without leading zeros keeps every path a distinct string.
 */
export const agentIdentitySeed = (K: Uint8Array, i: number, n: number): Uint8Array =>
  k(K, `sigelo/v1/identity/${index('agent', i)}/ed25519/${index('agent rotation', n)}`);

/** A path index: a safe non-negative integer, so `${v}` is plain decimal with no exponent. */
function index(what: string, v: number): number {
  if (!Number.isSafeInteger(v) || v < 0) throw new SigeloError(`${what}: index must be a non-negative integer, got ${v}`);
  return v;
}

/** Ed25519 seed for the recovery key. One per root: recovery outlives every rotation. */
export const recoverySeed = (S: Uint8Array): Uint8Array => k(S, 'sigelo/v1/recovery/ed25519');

/** The recovery **public** key, multibase. The only half that ever leaves the offline box. */
export const recoveryPublicKey = (S: Uint8Array): string => encodeKey(ed.getPublicKey(recoverySeed(S)));

/** `sha256:<hex>` of the recovery public key — what a genesis actually carries (SPEC §4). */
export const recoveryCommitment = (S: Uint8Array): string => commitmentOf(recoveryPublicKey(S));

/** What the agent and the operator may hold: sees every receipt, can spend nothing. */
export interface ViewOnlyWallet { a: Uint8Array; B: Uint8Array; address: string }
export interface Wallet extends ViewOnlyWallet {
  b: Uint8Array; A: Uint8Array;
  /** Drop the spend key. The result is what MONERO.md §2's table hands to a runtime. */
  viewOnly(): ViewOnlyWallet;
}

/**
 * One Monero wallet from the root. `name` is the §2 wallet name — `treasury`, `allowance`,
 * `counterparty/<id>` — and goes into the path verbatim, so it is part of the backup.
 * `net` is explicit on purpose: an address is the one field a human will copy wrong.
 */
export function walletFromRoot(S: Uint8Array, name: string, net: Net): Wallet {
  if (name === '') throw new SigeloError('wallet: name must not be empty');
  return walletOf(k(S, `sigelo/v1/monero/${name}`), net);
}

/**
 * The vault: the wallet a stock Monero wallet restores from `S`'s 25 words (`b = sc_reduce32(S)`,
 * `a = sc_reduce32(Keccak(b))`: account_base::generate, src/cryptonote_basic/account.cpp:179-187,
 * and generate_keys, src/crypto/crypto.cpp:198-212). The Owner's, cold:
 * no keeper ever loads it, because its spend key is `S` and `S` is every identity (MONERO.md §2).
 * HKDF-extract over `S` yields a PRK unrelated to `sc_reduce32(S)`, so no derived key is `b` or `a`.
 */
export const vaultFromRoot = (S: Uint8Array, net: Net): Wallet => walletOf(S, net);

function walletOf(seed: Uint8Array, net: Net): Wallet {
  const { b, a, B, A } = keysFromSpend(seed); // keysFromSpend reduces: b = sc_reduce32(seed)
  const address = encodeAddress({ net, kind: 'standard', spend: B, view: A });
  return { b, a, B, A, address, viewOnly: () => ({ a, B, address }) };
}

/**
 * A full sigelo identity for rotation `n`, its recovery commitment taken from the same root
 * unless a foreign `recoveryPub` is passed. `created`/`nonce` exist so the offline box can
 * reproduce a genesis byte-for-byte; without them keygen randomises the nonce, so the DID of
 * two calls differs even though the key does not.
 */
export function deriveIdentity(
  S: Uint8Array, n: number, recoveryPub?: Uint8Array | string | null,
  opts: { created?: string; nonce?: Uint8Array | string } = {},
): Identity {
  return keygen({ seed: identitySeed(S, n), recovery: recoveryPub === undefined ? recoveryPublicKey(S) : recoveryPub, ...opts });
}

// ---------------------------------------------------------------- Monero 25 words for S

/*
 * Monero's Electrum-style mnemonic, English only, per src/mnemonics/electrum-words.cpp (monero
 * d02c7c57). Each 4-byte little-endian chunk x becomes three indices into the 1626-word list
 * (bytes_to_words, :471-473):  w1 = x % n,  w2 = (x/n + w1) % n,  w3 = (x/n/n + w2) % n.
 * The 25th word repeats word crc32(first 3 letters of each of the 24, concatenated) % 24
 * (create_checksum_index, :192-209, appended at :488; boost::crc_32_type is the IEEE CRC-32). Decoding inverts it
 * (words_to_bytes, :323-324): x = w1 + n((n - w1 + w2) % n) + n²((n - w2 + w3) % n), which
 * Monero computes in uint32 and then refuses unless x % n == w1 (:326). For x < 2^32 that always
 * holds; past 2^32 it never does (2^32 % 1626 = 490), so the check is exactly "x < 2^32" and
 * that is how it is written here. Words match on their first 3 letters, case-insensitively
 * (language_base.h trimmed_word_map): we accept the full word or exactly its 3-letter prefix.
 */
const N = MONERO_WORDS.length, PREFIX = 3;
const BY_PREFIX = new Map(MONERO_WORDS.map((w, i) => [w.slice(0, PREFIX), i]));

/** IEEE CRC-32 (reflected, poly 0xEDB88320, init and xorout 0xFFFFFFFF), as boost::crc_32_type. */
function crc32(s: string): number {
  let c = 0xffffffff;
  for (let i = 0; i < s.length; i++) {
    c ^= s.charCodeAt(i); // the prefixes are ASCII: one byte per char
    for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return (c ^ 0xffffffff) >>> 0;
}
const checksumIndex = (idx: number[]): number => crc32(idx.map((i) => MONERO_WORDS[i]!.slice(0, PREFIX)).join('')) % idx.length;

/** 32 bytes -> Monero's 25 words, exactly as bytes_to_words. No canonicality check: see `mnemonicFromRoot`. */
export function encodeMoneroWords(b: Uint8Array): string {
  if (b.length !== 32) throw new SigeloError(`mnemonic: seed must be 32 bytes, got ${b.length}`);
  const idx: number[] = [];
  for (let i = 0; i < 32; i += 4) {
    const x = (b[i]! | (b[i + 1]! << 8) | (b[i + 2]! << 16) | (b[i + 3]! << 24)) >>> 0, q = Math.floor(x / N);
    const w1 = x % N, w2 = (q + w1) % N;
    idx.push(w1, w2, (Math.floor(q / N) + w2) % N);
  }
  return [...idx, idx[checksumIndex(idx)]!].map((i) => MONERO_WORDS[i]!).join(' ');
}

/** Monero's 25 words -> 32 bytes, checksum enforced: a mistyped or reordered word is a rejection, never a key. */
export function decodeMoneroWords(text: string): Uint8Array {
  const words = text.toLowerCase().trim().split(/\s+/);
  if (words.length !== 25) throw new SigeloError(`mnemonic: expected 25 words, got ${words.length}`);
  const idx = words.map((w) => {
    const i = BY_PREFIX.get(w.slice(0, PREFIX));
    if (i === undefined || (w !== MONERO_WORDS[i] && w !== MONERO_WORDS[i]!.slice(0, PREFIX))) {
      throw new SigeloError(`mnemonic: ${JSON.stringify(w)} is not in the Monero English wordlist`);
    }
    return i;
  });
  const last = idx.pop()!;
  if (idx[checksumIndex(idx)] !== last) throw new SigeloError('mnemonic: checksum mismatch (the 25th word)');
  const out = new Uint8Array(32);
  for (let t = 0; t < 8; t++) {
    const [w1, w2, w3] = [idx[3 * t]!, idx[3 * t + 1]!, idx[3 * t + 2]!];
    const x = w1 + N * ((N - w1 + w2) % N) + N * N * ((N - w2 + w3) % N);
    if (x >= 2 ** 32) throw new SigeloError(`mnemonic: words ${3 * t + 1}-${3 * t + 3} are not a Monero seed encoding (electrum-words.cpp:326)`);
    for (let j = 0; j < 4; j++) out[4 * t + j] = (x >>> (8 * j)) & 0xff;
  }
  return out;
}

/**
 * 0 < S < l. At or past l, a wallet restored from the words re-exports the words of
 * sc_reduce32(S) — which sigelo reads as another root; zero is a spend key Monero never makes.
 */
const canonical = (S: Uint8Array): boolean => bytesToHex(scReduce32(S)) === bytesToHex(S) && S.some((x) => x !== 0);
function checkCanonical(S: Uint8Array, what: string): Uint8Array {
  if (!canonical(S)) {
    throw new SigeloError(`${what}: not a canonical root (need 0 < S < l) — a Monero wallet restored from it would show different words, and sigelo would derive a different root from those`);
  }
  return S;
}

/** The 25 words of a root. Refuses a non-canonical `S` (see `checkCanonical`). */
export const mnemonicFromRoot = (S: Uint8Array): string => encodeMoneroWords(checkCanonical(S, 'mnemonic'));

/** The root `S` from its 25 words: checksum enforced, canonical scalar required. */
export const rootFromMnemonic = (words: string): Uint8Array => checkCanonical(decodeMoneroWords(words), 'mnemonic');

/** Accept a root as its 25 words or as 64 hex characters. Anything else is a rejection. */
export function parseRoot(text: string): Uint8Array {
  const s = text.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return checkCanonical(Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16))), 'root');
  return rootFromMnemonic(s);
}

/**
 * Everything §2 derives on `S`, in one call: what src/offline.ts splits between the holders.
 * `keepers` is how many keeper roots to emit, `K_0 … K_{keepers-1}`; the other fields do not
 * depend on it. Any 32 bytes are accepted here (the vault is then `sc_reduce32(S)`'s wallet);
 * canonicality is enforced where a human's root comes in: `newRoot`, `parseRoot`, the ceremony.
 */
export function deriveRoot(S: Uint8Array, net: Net, n = 0, keepers = 1): {
  identity: Uint8Array; recovery: { seed: Uint8Array; key: string; commitment: string };
  vault: Wallet; treasury: Wallet; allowance: Wallet; keepers: Uint8Array[];
} {
  const seed = recoverySeed(S);
  return {
    identity: identitySeed(S, n),
    recovery: { seed, key: encodeKey(ed.getPublicKey(seed)), commitment: commitmentOf(encodeKey(ed.getPublicKey(seed))) },
    vault: vaultFromRoot(S, net),
    treasury: walletFromRoot(S, 'treasury', net),
    allowance: walletFromRoot(S, 'allowance', net),
    keepers: Array.from({ length: index('keepers', keepers) }, (_, j) => keeperRoot(S, j)),
  };
}
