/**
 * Monero primitives for `method: "monero"` bindings (SPEC §6.2).
 *
 * Checked line by line against monero master 9e3a3103; every routine names the file it
 * mirrors. Monero signs on edwards25519 — the same curve as Ed25519 — with a different
 * construction (a Schnorr signature over Keccak-256 instead of RFC 8032), so
 * `@noble/ed25519`'s `Point` supplies all the arithmetic and no third dependency is needed.
 *
 * Two things here are easy to get wrong and silently produce garbage:
 *  - Keccak-256 is the ORIGINAL Keccak (pad 0x01), not SHA3-256 (pad 0x06). `keccak_256`,
 *    never `sha3_256`.
 *  - The domain strings are hashed WITH their trailing NUL (`sizeof` on a C literal, not
 *    `strlen`): "SubAddr\0" is 8 bytes, "MoneroMessageSignature\0" is 23.
 */
import { Point } from '@noble/ed25519';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize } from './jcs.js';

/** Thrown by the encoders. The verifiers never throw: malformed input is a `false`. */
export class MoneroError extends Error {
  override readonly name = 'MoneroError';
}

export type Net = 'mainnet' | 'stagenet' | 'testnet';
export type AddrKind = 'standard' | 'integrated' | 'subaddress';
export type Mode = 'spend' | 'view';
export interface Address { net: Net; kind: AddrKind; spend: Uint8Array; view: Uint8Array; paymentId?: Uint8Array }
export interface MsgResult { good: boolean; mode?: Mode; version: 1 | 2 }

/** l = 2^252 + 27742317777372353535851937790883648493 (src/crypto/crypto-ops.c sc_reduce32). */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const G = Point.BASE;

// ---------------------------------------------------------------- little-endian scalars

const leNum = (b: Uint8Array): bigint => {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
};
const leBytes = (n: bigint, len = 32): Uint8Array => {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
};
const le32 = (n: number): Uint8Array => leBytes(BigInt(n >>> 0), 4);
/** Monero/LEB128 unsigned varint (src/common/varint.h write_varint). */
const varint = (n: number): Uint8Array => {
  const out: number[] = [];
  for (let v = n; ; v = Math.floor(v / 128)) { out.push(v < 128 ? v : (v % 128) + 128); if (v < 128) break; }
  return Uint8Array.from(out);
};
const readVarint = (b: Uint8Array, at: number): [number, number] => {
  let n = 0, shift = 0, i = at;
  for (;;) {
    const byte = b[i++];
    if (byte === undefined || shift > 28) throw new MoneroError('varint: truncated or too long');
    // read_varint's EVARINT_REPRESENT (src/common/varint.h): a zero byte after the first is a
    // non-minimal encoding. `98 00` spells 24 in two bytes; wallet2's decode_addr refuses it,
    // so we must too, or one wallet has two spellings and only one of them is Monero's.
    if (byte === 0 && shift !== 0) throw new MoneroError('varint: non-canonical (zero continuation byte)');
    n += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return [n, i];
    shift += 7;
  }
};

/** Keccak-256, original padding (src/crypto/keccak.c). Concatenates its arguments first. */
export const keccak256 = (...parts: Uint8Array[]): Uint8Array => keccak_256(concatBytes(...parts));
/** 32 bytes little-endian, reduced mod l (src/crypto/crypto-ops.c sc_reduce32). */
export function scReduce32(b: Uint8Array): Uint8Array {
  if (b.length !== 32) throw new MoneroError(`sc_reduce32: expected 32 bytes, got ${b.length}`);
  return leBytes(leNum(b) % L);
}
/** `H_s(x) = sc_reduce32(Keccak256(x))` (src/crypto/crypto.cpp hash_to_scalar). */
export const hashToScalar = (...parts: Uint8Array[]): Uint8Array => scReduce32(keccak256(...parts));
/**
 * ge_frombytes_vartime (src/crypto/crypto-ops.c): fe_frombytes_vartime refuses y >= p, and
 * "If x = 0, the sign must be positive". That is RFC 8032 strict decoding, noble's zip215:false.
 * ZIP-215 (true) would accept both, and so read addresses and signatures Monero refuses.
 */
function pt(b: Uint8Array): Point {
  try { return Point.fromBytes(b, false); } catch { throw new MoneroError('point: not a canonical curve point (ge_frombytes_vartime)'); }
}

// ---------------------------------------------------------------- base58 (src/common/base58.cpp)

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; // Bitcoin's
/** encoded_block_sizes[n]: chars produced by an n-byte block. 8 bytes -> 11 chars. */
const ENC_SIZE = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/** Monero base58: independent 8-byte blocks, big-endian within a block. No checksum here. */
export function moneroBase58Encode(data: Uint8Array): string {
  let out = '';
  for (let i = 0; i < data.length; i += 8) {
    const block = data.subarray(i, Math.min(i + 8, data.length));
    let n = 0n;
    for (const b of block) n = (n << 8n) | BigInt(b);
    let s = '';
    while (n > 0n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n; }
    out += s.padStart(ENC_SIZE[block.length]!, '1'); // leading zero bytes are '1's
  }
  return out;
}

export function moneroBase58Decode(s: string): Uint8Array {
  if (typeof s !== 'string') throw new MoneroError('base58: not a string'); // an array of chars would decode too
  const out: number[] = [];
  for (let i = 0; i < s.length; i += 11) {
    const chunk = s.slice(i, i + 11);
    const size = ENC_SIZE.indexOf(chunk.length); // a length not in the table cannot occur
    if (size < 1) throw new MoneroError(`base58: ${chunk.length} is not a valid block length`);
    let n = 0n;
    for (const ch of chunk) {
      const d = ALPHABET.indexOf(ch);
      if (d < 0) throw new MoneroError(`base58: ${JSON.stringify(ch)} is not a base58 digit`);
      n = n * 58n + BigInt(d);
    }
    if (n >= 1n << BigInt(8 * size)) throw new MoneroError('base58: block overflows its byte length');
    for (let j = size - 1; j >= 0; j--) out.push(Number((n >> BigInt(8 * j)) & 0xffn));
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------- addresses

/** Network prefixes (src/cryptonote_config.h). */
const PREFIXES: Record<Net, Record<AddrKind, number>> = {
  mainnet: { standard: 18, integrated: 19, subaddress: 42 },
  testnet: { standard: 53, integrated: 54, subaddress: 63 },
  stagenet: { standard: 24, integrated: 25, subaddress: 36 },
};

/** `base58(varint(prefix) || spend || view || [payment_id] || Keccak256(that)[0..4])`. */
export function encodeAddress(o: { net: Net; kind: AddrKind; spend: Uint8Array; view: Uint8Array; paymentId?: Uint8Array }): string {
  if (o.spend.length !== 32 || o.view.length !== 32) throw new MoneroError('address: keys must be 32 bytes');
  if ((o.kind === 'integrated') !== (o.paymentId !== undefined)) throw new MoneroError('address: payment_id present iff kind is integrated');
  if (o.paymentId !== undefined && o.paymentId.length !== 8) throw new MoneroError('address: payment_id must be 8 bytes');
  const prefix = PREFIXES[o.net]?.[o.kind];
  if (prefix === undefined) throw new MoneroError(`address: no prefix for ${o.net} ${o.kind}`);
  const body = concatBytes(varint(prefix), o.spend, o.view, o.paymentId ?? new Uint8Array(0));
  return moneroBase58Encode(concatBytes(body, keccak256(body).subarray(0, 4)));
}

/** Inverse of encodeAddress. Throws on a bad digit, a bad checksum or an unknown prefix. */
export function decodeAddress(s: string): Address {
  const raw = moneroBase58Decode(s);
  if (raw.length < 69) throw new MoneroError(`address: ${raw.length} bytes is too short`);
  const body = raw.subarray(0, raw.length - 4);
  const want = keccak256(body).subarray(0, 4);
  for (let i = 0; i < 4; i++) if (want[i] !== raw[raw.length - 4 + i]) throw new MoneroError('address: checksum mismatch');
  const [prefix, off] = readVarint(body, 0);
  for (const net of Object.keys(PREFIXES) as Net[]) {
    for (const kind of Object.keys(PREFIXES[net]) as AddrKind[]) {
      if (PREFIXES[net][kind] !== prefix) continue;
      const len = off + 64 + (kind === 'integrated' ? 8 : 0);
      if (body.length !== len) throw new MoneroError(`address: ${kind} body is ${body.length} bytes, expected ${len}`);
      // get_account_address_from_str (src/cryptonote_basic/cryptonote_basic_impl.cpp) runs
      // check_key on both keys. In spend mode the view key is only hashed, never decoded, so
      // without this an address with a key Monero refuses could still carry a proven binding.
      pt(body.subarray(off, off + 32));
      pt(body.subarray(off + 32, off + 64));
      return { net, kind, spend: body.slice(off, off + 32), view: body.slice(off + 32, off + 64),
        ...(kind === 'integrated' ? { paymentId: body.slice(off + 64, off + 72) } : {}) };
    }
  }
  throw new MoneroError(`address: unknown prefix ${prefix}`);
}

// ---------------------------------------------------------------- keys

/** `b = sc_reduce32(seed)`, `a = H_s(b)`, `B = bG`, `A = aG` (src/crypto/crypto.cpp). */
export function keysFromSpend(seed: Uint8Array): { b: Uint8Array; a: Uint8Array; B: Uint8Array; A: Uint8Array } {
  const b = scReduce32(seed);
  const a = hashToScalar(b);
  return { b, a, B: G.multiply(leNum(b)).toBytes(), A: G.multiply(leNum(a)).toBytes() };
}

/**
 * `m = H_s("SubAddr\0" || a || le32(major) || le32(minor))`, `D = B + mG`, `C = aD`
 * (src/device/device_default.cpp:211 get_subaddress_secret_key).
 *
 * Index (0,0) is the account's own address, never derived — deriving it would produce a
 * different, unfunded address that no wallet watches.
 */
export function subaddressKeys(o: { a: Uint8Array; B: Uint8Array; major: number; minor: number }): { C: Uint8Array; D: Uint8Array } {
  const a = leNum(o.a);
  if (o.major === 0 && o.minor === 0) return { C: G.multiply(a).toBytes(), D: Uint8Array.from(o.B) };
  const m = hashToScalar(utf8ToBytes('SubAddr\0'), o.a, le32(o.major), le32(o.minor));
  const D = pt(o.B).add(G.multiply(leNum(m)));
  return { C: D.multiply(a).toBytes(), D: D.toBytes() };
}

/** The address string for one subaddress index. (0,0) is the standard primary address. */
export function subaddress(o: { a: Uint8Array; B: Uint8Array; major: number; minor: number; net: Net }): string {
  const { C, D } = subaddressKeys(o);
  const kind: AddrKind = o.major === 0 && o.minor === 0 ? 'standard' : 'subaddress';
  return encodeAddress({ net: o.net, kind, spend: D, view: C });
}

// ---------------------------------------------------------------- message signatures

/** config::HASH_KEY_MESSAGE_SIGNING, 23 bytes: `sizeof` keeps the NUL. */
const MSG_DOMAIN = utf8ToBytes('MoneroMessageSignature\0');

/** wallet2::get_message_hash (src/wallet/wallet2.cpp ~13037). Mode byte: 0 spend, 1 view. */
export function signMessageHash(o: { spendPub: Uint8Array; viewPub: Uint8Array; mode: Mode; data: Uint8Array }): Uint8Array {
  return keccak256(MSG_DOMAIN, o.spendPub, o.viewPub, Uint8Array.of(o.mode === 'spend' ? 0 : 1), varint(o.data.length), o.data);
}

/** crypto::check_signature (src/crypto/crypto.cpp ~364). Never throws. */
function checkSignature(h: Uint8Array, P: Uint8Array, sig: Uint8Array): boolean {
  try {
    const c = leNum(sig.subarray(0, 32));
    const r = leNum(sig.subarray(32, 64));
    if (c >= L || r >= L || c === 0n) return false; // sc_check on both, sc_isnonzero on c
    const R = pt(P).multiplyUnsafe(c).add(G.multiplyUnsafe(r)); // ge_double_scalarmult_base
    if (R.is0()) return false; // the identity encodes to a fixed string Monero rejects
    return leNum(hashToScalar(h, P, R.toBytes())) === c;
  } catch {
    return false;
  }
}

const bytes = (m: Uint8Array | string): Uint8Array => (typeof m === 'string' ? utf8ToBytes(m) : m);

/**
 * `"SigV2" + base58(c || r)` (wallet2::sign ~13057, crypto::generate_signature ~335).
 * `secret` is the scalar matching the pubkey the mode selects: spend mode signs with `b`
 * (or `b + m` for a subaddress), view mode with `a` (or `a(b + m)`).
 * `nonce` exists so tests can be deterministic; production leaves it undefined.
 */
export function signMessage(o: { message: Uint8Array | string; mode: Mode; secret: Uint8Array; spendPub: Uint8Array; viewPub: Uint8Array; nonce?: Uint8Array }): string {
  const data = bytes(o.message);
  const P = o.mode === 'spend' ? o.spendPub : o.viewPub;
  const h = signMessageHash({ spendPub: o.spendPub, viewPub: o.viewPub, mode: o.mode, data });
  let k = leNum(scReduce32(o.nonce ?? randomBytes(32)));
  while (k === 0n) k = leNum(scReduce32(randomBytes(32)));
  const c = leNum(hashToScalar(h, P, G.multiply(k).toBytes()));
  const r = (((k - c * leNum(o.secret)) % L) + L) % L; // sc_mulsub: r = k - c*sec
  return 'SigV2' + moneroBase58Encode(concatBytes(leBytes(c), leBytes(r)));
}

/**
 * wallet2::verify: try mode 0 against the address's spend key, then mode 1 against its view
 * key, and report which matched. SigV1 is the legacy form whose hash is just Keccak256(data);
 * sigelo never emits it, but old wallets did, so it is accepted on the verify side.
 */
export function verifyMessage(o: { message: Uint8Array | string; address: string; signature: string }): MsgResult {
  const version: 1 | 2 = o.signature.startsWith('SigV2') ? 2 : 1;
  try {
    if (!o.signature.startsWith('SigV1') && !o.signature.startsWith('SigV2')) throw new MoneroError('signature: not SigV1 or SigV2');
    const sig = moneroBase58Decode(o.signature.slice(5));
    if (sig.length !== 64) throw new MoneroError(`signature: ${sig.length} bytes, expected 64`);
    const data = bytes(o.message);
    const { spend, view } = decodeAddress(o.address);
    for (const mode of ['spend', 'view'] as const) {
      const h = version === 2 ? signMessageHash({ spendPub: spend, viewPub: view, mode, data }) : keccak256(data);
      if (checkSignature(h, mode === 'spend' ? spend : view, sig)) return { good: true, mode, version };
    }
  } catch { /* a malformed address or signature is a failed verification, not an exception */ }
  return { good: false, version };
}

// ---------------------------------------------------------------- sigelo glue (SPEC §6.2)

/** The §3 signing input, the bytes a `method: "monero"` sig_addr covers. */
const sigeloInput = (body: unknown): Uint8Array => utf8ToBytes('sigelo\n' + canonicalize(body));

/** Produce `sig_addr` for a binding body with a Monero wallet key (SPEC §6.2). */
export function sigeloMoneroSigAddr(body: unknown, o: { mode: Mode; secret: Uint8Array; spendPub: Uint8Array; viewPub: Uint8Array; nonce?: Uint8Array }): string {
  return signMessage({ ...o, message: sigeloInput(body) });
}

/**
 * Verify one against the binding's own `addr`. Used by sigelo.verify (§6.1, §6.2).
 *
 * Two §6.2 rules live here rather than in verifyMessage, which stays a faithful wallet2:
 * a binding's `addr` must be a STANDARD or SUBADDRESS address (never integrated), and SigV1
 * is not accepted. A subaddress is checked against its own (D, C) — the keys the address
 * spells, which is what wallet2::verify hashes and what wallet2::sign's subaddress branch
 * signs with (`b + m` spend, `a(b + m)` view), so either mode needs the spend key there.
 */
export function verifySigeloMoneroSigAddr(body: unknown, address: string, sigAddr: unknown): MsgResult {
  const version: 1 | 2 = typeof sigAddr === 'string' && sigAddr.startsWith('SigV2') ? 2 : 1;
  try {
    if (typeof sigAddr !== 'string' || typeof address !== 'string') throw new MoneroError('sig_addr: not a string');
    // §6.2: "Integrated forms are not accepted as `addr`." The message hash covers (B, A) and
    // not the prefix, so the integrated spelling of a wallet reuses the base address's
    // signature verbatim — accepting it would let a payment id nobody signed for ride along on
    // a proven binding. A subaddress carries its own keys, so its signature is its own.
    if (decodeAddress(address).kind === 'integrated') return { good: false, version };
    // §6.2: "Legacy `SigV1` is not accepted." Its hash is Keccak256(data) alone — neither the
    // mode byte nor the address's keys are inside it, so it cannot tell view from spend.
    if (version !== 2) return { good: false, version };
    return verifyMessage({ message: sigeloInput(body), address, signature: sigAddr });
  } catch {
    return { good: false, version };
  }
}
