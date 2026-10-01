// SPDX-License-Identifier: MIT
/**
 * The Monero half of the sidecar (MONERO.md §2–§3, SPEC §6 and §6.3). Its own file so the
 * identity-only core stays inside the 100-line adoption budget — see INTEGRATION.md, which
 * counts the two separately.
 *
 * What this process holds, and nothing else Monero-related: the treasury's VIEW-ONLY keys
 * `{ a, B, address, net }`. `wallet-set` refuses any blob carrying a spend key, because a
 * spend key one pipe away from an LLM is the treasury (MONERO.md §2's table). So:
 *
 *  - the identity key signs four things — challenge, binding `sig_id`, rotation, invoice;
 *  - the view key signs exactly one — a binding's `sig_addr`, view mode, at index (0,0);
 *  - nothing here can move a coin.
 *
 * The `sig_addr` is produced LOCALLY, with no wallet and no daemon: it is byte-for-byte what
 * `monero-wallet-rpc` `sign { signature_type: "view", account_index: 0, address_index: 0 }`
 * returns for the same message (SPEC §6.2; `monero-wallet-cli` refuses on a watch-only
 * wallet, the RPC does not). It proves "I can SEE this wallet", which is exactly what a payer
 * needs of a receiver — not "I can spend it", which would need `b`.
 */
import { randomBytes } from 'node:crypto';
import { closeSync, openSync, rmSync } from 'node:fs';
import type { Binding, Bundle, Genesis, Proof } from 'sigelo';
import { bind, did, sign, SigeloError, structure, verify, verifySig, VERSION } from 'sigelo';
import type { Net } from 'sigelo/dist/monero.js';
import { decodeAddress, sigeloMoneroSigAddr, subaddress, verifySigeloMoneroSigAddr } from 'sigelo/dist/monero.js';
import { head, secretOf, type Store } from './sigelo-agent.ts';

/** The view-only treasury, as it sits in the identity file. `next_minor` is per account. */
export interface MoneroWallet { net: Net; a: string; B: string; address: string; next_minor: Record<string, number> }
/** SPEC §6.3. `amount` is a STRING of atomic units: a float in a signed object is forbidden. */
export interface InvoiceBody {
  v: string; typ: 'invoice'; did: string; method: string; addr: string;
  iat: number; exp: number; nonce: string; amount?: string; memo?: string;
}
export interface Invoice { body: InvoiceBody; sig: string }

const NETS: Net[] = ['mainnet', 'stagenet', 'testnet'];
const BINDING_TTL = 30 * 86400; // §6.1: keep bindings short-lived; `bind` again to extend.
const LOOKAHEAD = 200;          // wallet2.cpp:131 — past this a restored wallet is blind.
const [LOCK_TRIES, LOCK_MS] = [100, 25]; // 2.5s: long enough for a sidecar run, short enough to notice
/** Every spelling of a spend key that `sigelo-offline` or a wallet dump could carry. */
const SPEND_KEYS = ['b', 'spend_key', 'private_spend_key', 'secret_spend_key', 'spendKey'];
const FIELDS = ['net', 'view_key', 'public_spend_key', 'address'];

const hex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));
/** Multibase base58btc (SPEC §2): the library's encoder is internal to it, and a nonce only
 *  ever needs to be minted, never read back. Leading zero bytes keep their `1`, as in §2. */
function nonce16(): string {
  const b = randomBytes(16);
  let n = BigInt('0x' + b.toString('hex')), s = '';
  for (; n > 0n; n /= 58n) s = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[Number(n % 58n)]! + s;
  for (const byte of b) { if (byte !== 0) break; s = '1' + s; }
  return 'z' + s;
}
/** The configured treasury, or the reason there isn't one. */
export function wallet(s: Store): MoneroWallet {
  if (!s.monero) throw new SigeloError('monero: no wallet configured — run `sigelo-agent wallet-set` with the `agent.treasury` object from `sigelo-offline derive`');
  return s.monero;
}

/**
 * Install the view-only treasury. Input is exactly `sigelo-offline derive`'s
 * `agent.treasury` — `{ view_key, public_spend_key, address }` — plus its `net`.
 *
 * The last check is the load-bearing one: `subaddress(a, B, 0, 0)` IS the standard address
 * `varint(prefix) ‖ B ‖ aG ‖ checksum`, so one string comparison proves the network, the
 * kind, that the spend key is `B` and that the view key really is the secret behind `A`.
 * Without it a typo installs a wallet the agent can neither see nor prove.
 */
export function walletSet(s: Store, input: unknown): Store {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new SigeloError('wallet-set: input is not a JSON object');
  const o = input as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (SPEND_KEYS.includes(k)) throw new SigeloError(`wallet-set: refusing input carrying ${JSON.stringify(k)} — that is a SPEND key. This process reads untrusted text all day; MONERO.md §2 gives it the treasury's VIEW only. Pass the \`agent.treasury\` object from \`sigelo-offline derive\`, never \`operator\` or \`air_gapped\`.`);
    if (!FIELDS.includes(k)) throw new SigeloError(`wallet-set: unknown field ${JSON.stringify(k)} — expected exactly { ${FIELDS.join(', ')} }`);
  }
  for (const f of FIELDS) if (typeof o[f] !== 'string') throw new SigeloError(`wallet-set: missing or non-string ${f}`);
  const net = o['net'] as Net;
  if (!NETS.includes(net)) throw new SigeloError(`wallet-set: net is ${JSON.stringify(net)}, not one of ${NETS.join(', ')}`);
  const [a, B, address] = [o['view_key'] as string, o['public_spend_key'] as string, o['address'] as string];
  for (const [n, v] of [['view_key', a], ['public_spend_key', B]]) if (!/^[0-9a-fA-F]{64}$/.test(v!)) throw new SigeloError(`wallet-set: ${n} is not 32 bytes of hex`);
  const d = decodeAddress(address); // throws MoneroError on a bad checksum or prefix
  if (d.net !== net) throw new SigeloError(`wallet-set: address is a ${d.net} address but net says ${net}`);
  if (d.kind !== 'standard') throw new SigeloError(`wallet-set: address is ${d.kind} — this view-only agent binds the BASE address only: SPEC §6.2 accepts a subaddress too, but signing for one needs the spend key, in either mode, and this process never holds it`);
  if (subaddress({ a: hex(a), B: hex(B), major: 0, minor: 0, net }) !== address) throw new SigeloError('wallet-set: address does not match the keys — its spend key is not public_spend_key, or its view key is not view_key·G');
  // A new wallet retires any binding naming the old one: that address is no longer watched.
  s.bindings = (s.bindings ?? []).filter((x) => x.body.method !== 'monero' || x.body.addr === address);
  s.monero = { net, a: a.toLowerCase(), B: B.toLowerCase(), address, next_minor: s.monero?.address === address ? s.monero.next_minor : {} };
  return s;
}

/**
 * SPEC §6 binding for the CURRENT DID, cross-signed: `sig_id` by the identity key, `sig_addr`
 * by the view key over the identical §3 signing input. `bind()` mints the body (nonce and
 * `sig_id`); the wallet signature goes over that same body, which is why the nonce is passed
 * in rather than letting a second call randomise it.
 */
export function bindMonero(s: Store, now: number): Binding {
  const w = wallet(s);
  const b = bind({ secret: secretOf(s), id: did(head(s)), method: 'monero', addr: w.address, iat: now, exp: now + BINDING_TTL, nonce: randomBytes(16) });
  const sig_addr = sigeloMoneroSigAddr(b.body, { mode: 'view', secret: hex(w.a), spendPub: hex(w.B), viewPub: decodeAddress(w.address).view });
  if (!verifySigeloMoneroSigAddr(b.body, w.address, sig_addr).good) throw new SigeloError('bind: the sig_addr we just made does not verify against addr — the stored view key does not belong to this address');
  const binding: Binding = { ...b, sig_addr };
  // One binding per method: a stale one for a retired address is a payment address nobody watches.
  s.bindings = (s.bindings ?? []).filter((x) => x.body.method !== 'monero').concat(binding);
  return binding;
}

/**
 * The next unused receive subaddress of `account` (MONERO.md §3). Never reused across
 * counterparties: two payers to one subaddress can link each other. Account 0 starts at minor
 * 1 because (0, 0) is the base address itself; every other account starts at 0.
 */
export function receive(s: Store, major: number): { account: number; index: number; address: string } {
  const w = wallet(s);
  if (!Number.isSafeInteger(major) || major < 0) throw new SigeloError(`receive: --account must be a non-negative integer, got ${JSON.stringify(major)}`);
  const minor = w.next_minor[String(major)] ?? (major === 0 ? 1 : 0);
  w.next_minor[String(major)] = minor + 1;
  // Past the wallet's lookahead a RESTORED wallet does not scan for this index, so money sent
  // here would be invisible until the gap is closed by hand. Warn; do not silently refuse.
  if (minor > LOOKAHEAD) console.error(`sigelo-agent: minor index ${minor} is past the default wallet lookahead of ${LOOKAHEAD} (wallet2.cpp:131) — a restored treasury will not see payments to it until its lookahead is raised`);
  return { account: major, index: minor, address: subaddress({ a: hex(w.a), B: hex(w.B), major, minor, net: w.net }) };
}

/**
 * `load -> receive -> save` is a read-modify-write of one counter. Two sidecar invocations
 * racing through it hand the SAME subaddress to two counterparties, and two payers to one
 * subaddress can link each other (MONERO.md §3) — the one thing `receive` exists to prevent.
 * EVERY load→save command takes it (cli.ts `update`): a `bind` that loaded before a `receive`
 * saved would write the old counter back just as surely as a second `receive` would.
 * `wx` is an atomic create, so exactly one process holds the lock at a time; `Atomics.wait` is
 * the only sleep available on a synchronous path. A lock nobody released is named, never
 * silently broken: breaking it is what would reissue an index.
 */
export function withLock<T>(path: string, fn: () => T): T {
  const lock = `${path}.lock`;
  const idle = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; ; i++) {
    try { closeSync(openSync(lock, 'wx', 0o600)); break; } catch (e) {
      if ((e as { code?: string }).code !== 'EEXIST') throw e;
      if (i === LOCK_TRIES) throw new SigeloError(`lock: ${lock} is still held after ${(LOCK_TRIES * LOCK_MS) / 1000}s — another sigelo-agent holds it, or one was killed holding it; delete the file to continue`);
      Atomics.wait(idle, 0, 0, LOCK_MS);
    }
  }
  try { return fn(); } finally { rmSync(lock, { force: true }); }
}

/**
 * Is `addr` a subaddress THIS wallet handed out? We hold `(a, B)`, so every index `receive`
 * has issued can be re-derived and compared — the same one-string-comparison proof
 * `wallet-set` uses on the base address. A subaddress cannot be tested against a wallet any
 * other way: `D = B + H_s("SubAddr\0" ‖ a ‖ major ‖ minor)·G` has no inverse, so this walks
 * the issued range and stops at the hit.
 */
function issued(w: MoneroWallet, addr: string): boolean {
  for (const [major, next] of Object.entries(w.next_minor)) {
    for (let minor = major === '0' ? 1 : 0; minor < next; minor++) {
      if (subaddress({ a: hex(w.a), B: hex(w.B), major: Number(major), minor, net: w.net }) === addr) return true;
    }
  }
  return false;
}

/**
 * SPEC §6.3. Names where to pay THIS time; signed by the identity key, exchanged bilaterally,
 * never in a bundle (`typ` keeps it out of every bundle slot). sigelo cannot prove the
 * subaddress belongs to the bound wallet — that would need the view key — so the signature is
 * the claim and the binding is its anchor.
 */
export function invoice(s: Store, o: { addr: string; amount?: string; memo?: string; ttl: number }, now: number): Invoice {
  const w = wallet(s);
  const d = decodeAddress(o.addr);
  if (d.kind !== 'subaddress') throw new SigeloError(`invoice: addr is a ${d.kind} address — invoice a fresh subaddress from \`receive\`, never the base address (MONERO.md §3)`);
  if (d.net !== w.net) throw new SigeloError(`invoice: addr is a ${d.net} address, this wallet is ${w.net}`);
  if (o.amount !== undefined && !/^(0|[1-9][0-9]*)$/.test(o.amount)) throw new SigeloError(`invoice: amount must be a decimal string of atomic units (SPEC §3 forbids floats in signed objects), got ${JSON.stringify(o.amount)}`);
  if (!Number.isSafeInteger(o.ttl) || o.ttl <= 0) throw new SigeloError(`invoice: --ttl must be a positive integer number of seconds, got ${JSON.stringify(o.ttl)}`);
  // THREAT-MODEL §4: `addr` is a string this process was handed, and this process reads
  // attacker-controlled text all day. An invoice is what a payer pays, so signing someone
  // else's subaddress with the identity key hands them the money — and unlike a stolen
  // identity key, a spent coin is not recoverable. Only an address `receive` minted counts.
  if (!issued(w, o.addr)) throw new SigeloError(`invoice: ${o.addr} is not a subaddress this wallet has handed out — invoice one from \`receive\`, because a payer pays what this signature names`);
  const body: InvoiceBody = {
    v: VERSION, typ: 'invoice', did: did(head(s)), method: 'monero', addr: o.addr,
    iat: now, exp: now + o.ttl, nonce: nonce16(),
    ...(o.amount !== undefined && { amount: o.amount }), ...(o.memo !== undefined && { memo: o.memo }),
  };
  structure(body, 'invoice'); // §3.1, and the canonicalizer's float check with it
  return { body, sig: sign(secretOf(s), body) }; // the hot key's fourth and last job
}

/**
 * The payer's side (SPEC §6.3, §9.1-style verdict). Refusals name the failing check. Order:
 * structure, the bundle, the invoice's DID inside that bundle's chain, the signature, the
 * clock, a `proven` binding for the same method, and the two addresses agreeing on network.
 */
export function verifyInvoice(inv: unknown, bundle: Bundle, now: number): {
  did: string; current: boolean; method: string; addr: string; amount: string | null; memo: string | null;
  expires_in: number; binding: { addr: string; proof: Proof }; net: Net; attested_by: string[];
} {
  const env = inv as { body?: InvoiceBody; sig?: unknown };
  structure(env?.body, 'invoice');
  const body = env.body!;
  if (typeof env.sig !== 'string') throw new SigeloError('verify-invoice: envelope has no sig');
  if (body.method !== 'monero') throw new SigeloError(`verify-invoice: method ${JSON.stringify(body.method)} — this helper checks Monero invoices`);
  const result = verify(bundle, now); // structural failure, fork or cycle throws here
  const genesis = [bundle.genesis, ...bundle.rotations.map((r) => r.next_genesis)].find((g: Genesis) => did(g) === body.did);
  if (!genesis || !result.chain.includes(body.did)) throw new SigeloError(`verify-invoice: ${body.did} is not a node of the bundle's chain — the invoice names an identity this bundle does not describe`);
  // The CURRENT key and no other. A rotation retires the key before it (SPEC §7), and the
  // reason to rotate is that the old one may be in someone else's hands (THREAT-MODEL §2.4,
  // §3.6) — so "a retired key names where to pay" is precisely the case this must refuse, not
  // report. sigelo-spend applies the same rule to the invoices it honours (MONERO.md §4).
  if (body.did !== result.did) throw new SigeloError(`verify-invoice: the invoice is signed for ${body.did}, which this chain has ROTATED AWAY from — the current DID is ${result.did}. A retired key must not name a payment address; ask for a fresh invoice.`);
  if (!verifySig(genesis.key, body, env.sig)) throw new SigeloError('verify-invoice: signature does not verify under the current identity key of did');
  if (!(body.iat <= now && now < body.exp)) throw new SigeloError(`verify-invoice: expired or not yet valid — iat ${body.iat} <= ${now} < exp ${body.exp} is false`);
  const binding = result.bindings.find((b) => b.body.method === body.method && b.proof === 'proven');
  if (!binding) throw new SigeloError(`verify-invoice: the bundle has no PROVEN ${body.method} binding — §6.1 forbids sending funds to an address whose proof is not \`proven\``);
  const [to, bound] = [decodeAddress(body.addr), decodeAddress(binding.body.addr)];
  if (to.net !== bound.net) throw new SigeloError(`verify-invoice: invoice addr is ${to.net}, the bound wallet is ${bound.net} (§6.2: the signature hash does not cover the network prefix, so this must be checked here)`);
  // MONERO.md §3/§4: an invoice names a fresh SUBaddress. Any other kind is not one `receive`
  // minted — a standard address could be any wallet at all. sigelo-spend refuses the same.
  if (to.kind !== 'subaddress') throw new SigeloError(`verify-invoice: invoice addr is a ${to.kind} address — an invoice names a subaddress (MONERO.md §3, §4)`);
  return {
    did: body.did, current: body.did === result.did, method: body.method, addr: body.addr,
    amount: body.amount ?? null, memo: body.memo ?? null, expires_in: body.exp - now,
    binding: { addr: binding.body.addr, proof: binding.proof }, net: to.net,
    attested_by: Object.keys(result.attestations),
  };
}
