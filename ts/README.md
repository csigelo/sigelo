# sigelo (TypeScript)

TypeScript implementation of the [sigelo](../SPEC.md) protocol, wire version `sigelo/0`: the
five constructors, the verifier and the vector generator. The reference verifier is
[`../go`](../go/README.md); the two agree on every vector.
Offline verification, Ed25519 + SHA-256 + JCS, two dependencies (`@noble/ed25519`,
`@noble/hashes`), no build step beyond `tsc`.

```sh
npm ci          # the committed lockfile, exactly
npx tsc         # -> dist/
```

## API

```ts
keygen(opts: { recovery: key bytes | multibase key | 'sha256:<hex>' | null, seed?, created?, nonce? }): Identity
attest(opts: { secret, iss, sub, iat, exp, ctx, admission, admission_by?, claims }): Attestation
bind(opts: { secret, id, method, addr, iat, exp, nonce?, addr_secret?, sig_addr? }): Binding
rotate(opts: { genesis, next_genesis, iat, reason: 'voluntary' | 'recovery', secret }): Rotation
verify(bundle: Bundle, now: number, knownIssuers?: Record<string, Genesis>): VerifyResult
```

`bind` has two proven forms and one unproven. For `method: "ed25519-test"` (SPEC §6.1a, the
test method: `addr` is a multibase Ed25519 public key) pass `addr_secret`, that key's 32-byte
secret, and `bind` makes `sig_addr` itself → `proven`. For a real wallet pass the wallet's
signature as `sig_addr` (Monero: `sigeloMoneroSigAddr` from `sigelo/dist/monero.js`) →
`proven` if it verifies, discarded if it does not. Pass neither and the binding has only
`sig_id` → `unproven`: the identity claims the address, and nobody may pay it. Every `iat` is
the current Unix time when you sign: `verify` discards an attestation or binding whose `iat`
is later than its `now` (SPEC §9 steps 5–6), whatever its signatures.

`rotate` precedence (SPEC §7.1): at any node a valid recovery rotation supersedes any
voluntary one, **regardless of `iat`**: a thief's voluntary rotation at T+3600 loses to the
operator's recovery rotation at T. The chain's order comes from `id` → `next`, never from
timestamps.

`recovery` is the recovery **public** key (or an existing `sha256:` commitment, used as
is); generate the key offline, keep it out of the agent runtime. `keygen({ recovery: null })` warns — theft is then terminal. Recovery is
`rotate({ reason: 'recovery' })` signed with the recovery key, not a sixth function.
Nonces (`keygen`, `bind`): omit `nonce` and 16 random bytes are drawn and written `z` +
base58btc (SPEC §2). To choose one, pass raw bytes,
`nonce: crypto.getRandomValues(new Uint8Array(16))`; a string is used as is, so never pass
`"z"` + hex. There is no nonce helper; `encodeKey` takes 32-byte keys only.
`verify` takes `now` as a parameter, never reads a clock or the network, and returns the
SPEC §9.1 result: current DID, chain, governing recovery commitment, accepted attestations
grouped by issuer, bindings tagged `proven`/`unproven`/`unsupported`, rejected counts. Never
send funds to a binding whose `proof` is not `proven`. Structural failures, forks and cycles
throw `SigeloError` naming the failed check. Also exported: `challenge` (a thin SPEC §5.2
helper over `sign`, not a sixth constructor), `did`, `sign`, `verifySig`, `signingInput`,
`canonicalize`, `parse`, `encodeKey`, `decodeKey`, `commitmentOf`, `structure`, `VERSION`.
Monero and root-seed material are separate modules — `sigelo/dist/monero.js` and
`sigelo/dist/keys.js` — so a world that only verifies bundles never imports them.

## Conformance

`npx tsc && node dist/test.js` must end with `ALL PASS`. It runs `../test-vectors.json`:
every positive vector reproduced byte-for-byte from the documented seeds, the `bundle`
vector's §9.1 result reproduced as JSON, every negative case rejected for its stated reason.
620 `PASS` lines with `monero-wallet-rpc` on `PATH` (608 and one `SKIP` line without it; 87 of them the `parity` group, which
`go/sigelo_test.go` runs identically), including the Monero vectors, the stock-wallet interop below and
the root ceremony. The interop checks SKIP rather than fail where `monero-wallet-rpc` is not
installed, and the five real-`age` ceremony checks SKIP where `age`/`age-keygen` are not (a fake
`age` covers the rest), as do the `--human` pty and no-tty checks without util-linux `script`
and `setsid` (an injected tty sink covers the library).

`src/gen_vectors.ts` regenerates `../test-vectors.json` from the documented seeds:
`npm run gen` writes it in place, `node dist/gen_vectors.js` prints it to stdout. Its output is
byte-identical to the committed file (CI diffs it; it is the only generator), and it is
meant to be read: each vector is built there the way a conforming implementation would build
it. The header comment lists what a port to another language must reproduce to match.

## Monero bindings (SPEC §6.2)

`src/monero.ts` implements Monero's own primitives so a `method: "monero"` binding can reach
`proof: "proven"`: Keccak-256 (`keccak256`, the original padding — *not* SHA3-256, which is
the one mistake here that produces plausible-looking garbage), `scReduce32`/`hashToScalar`,
Monero base58 (`moneroBase58Encode`/`Decode`), `encodeAddress`/`decodeAddress` for standard,
integrated and subaddress forms on mainnet, stagenet and testnet, `keysFromSpend`,
`subaddressKeys`/`subaddress`, and the `SigV2` message signature scheme
(`signMessageHash`, `signMessage`, `verifyMessage`, which also accepts legacy `SigV1`).
`sigeloMoneroSigAddr(body, …)` and `verifySigeloMoneroSigAddr(body, addr, sig_addr)` are the
glue: the signed message is the ordinary §3 signing input `"sigelo\n" + JCS(body)`, and
`verify()` dispatches `method: "monero"` to the latter against the binding's own `addr`, so a
valid signature yields `proven` and an invalid one discards the binding (§6.1) rather than
downgrading it. `addr` may be a standard address or a subaddress (checked against its own
`(D, C)`), never integrated, and SigV1 is refused there. Both the spend key and a view key can
sign, and `verifyMessage` reports which matched — a view-mode signature proves a *standard*
address without touching the spend key; for a subaddress both modes need it. Curve
arithmetic reuses `@noble/ed25519`'s `Point`; **no third dependency was needed**.
`test/monero-vectors.json` holds the conformance data: addresses, subaddresses and 54 `SigV2`
signatures produced by monero-ts 0.11.15 (Monero's C++ core in WASM) from a documented spend
key, plus `wallet_rpc_oracle`: a live stagenet `monero-wallet-rpc`'s `verify` verdicts on the
§6.2 subaddress/integrated vectors and its own `sign` at (0,0) and (0,1) in both modes, by a wallet restored from the same documented key. Monero nonces are random, so the tests verify what monero produced rather than
reproducing it byte-for-byte. Note that a Monero address's network/kind prefix is *not*
covered by the signature hash — only its two public keys are — so the same signature verifies
under the mainnet, stagenet and testnet spellings of one wallet. Never automate view-key
disclosure: it is irrevocable (SPEC §6.2).

**Invoices (§6.3)** are a slot of `structure()`, not a sixth constructor: an invoice is a
body — `{ v, typ: "invoice", did, method, addr, iat, exp, nonce }`, optionally `amount` (a
**string** of atomic units; §3 forbids floats in signed objects) and `memo` — plus an
ordinary §3 `sign()` by the identity key. `typ` keeps it out of every bundle slot, which is
the point: an invoice names where to pay *this time*, a binding names the wallet, and only
the binding is cross-signed. `adapters/moadim` mints and checks them end to end.

## Root seed (MONERO.md §2)

`src/keys.ts` derives everything from one 32-byte root `S` generated offline —
`k(path) = HKDF-SHA256(ikm = S, salt = "", info = path)`, then `identitySeed(S, n)`,
`recoverySeed(S)` and `walletFromRoot(S, name, net)` (`b = sc_reduce32(k)`, then Monero's
own `a = H_s(b)`). `keeperRoot(S, j)` is keeper `j`'s subtree `k(S, "sigelo/v1/keeper/<j>")`
and `agentIdentitySeed(K, i, n)` the Ed25519 seed `k(K, "sigelo/v1/identity/<i>/ed25519/<n>")`
of agent account `i` under it, so a keeper mints agent identities without `S`; `deriveRoot(S,
net, n, keepers = 1)` returns `K_0 … K_{keepers-1}` beside everything else. `deriveIdentity(S, n, recoveryPub?)` returns a full sigelo `Identity`
whose recovery commitment comes from the same root; `wallet.viewOnly()` is the `{ a, B,
address }` projection MONERO.md §2's table hands to the agent runtime, with the spend key
absent rather than merely unused. **`S` is a Monero 25-word seed**: `mnemonicFromRoot` /
`rootFromMnemonic` are Monero's Electrum-style English encoding (checksum word enforced,
wordlist in `src/monero-words.ts`), `newRoot()` returns the 25 words of a fresh canonical
root (`0 < S < l`, refused otherwise everywhere a human's root comes in), and
`vaultFromRoot(S, net)` is the wallet any Monero wallet that restores a 25-word (legacy) seed makes from those words
(`b = sc_reduce32(S) = S`, `deriveRoot`'s `vault`). The vault is the Owner's and is never
loaded by a keeper (MONERO.md §2); the derived wallets are imported into stock software by
**private spend key**. `node dist/test.js` proves both against a real `monero-wallet-rpc`
it starts itself (`--offline`, port 38084): `generate_from_keys` + `get_address`,
`query_key` and two `create_address` calls for a derived wallet, and
`restore_deterministic_wallet` from our words + `query_key` (spend key, view key, mnemonic)
for three fixed vectors and `create_wallet`'s own words round-tripped through ours; it prints
a `SKIP` line if the binary is missing.

`sigelo-offline` (`src/offline.ts`, the CLI; `src/ceremony.ts`, the library) runs on a
machine with no network. `<net>` is `mainnet`, `stagenet` or `testnet`.

```sh
sigelo-offline ceremony --net <net> --recipient <age1…> --out <dir> [--keepers N] [--treasury-keeper j]
                        [--human] [--import <file|-> --i-know-this-seed-was-cold]
sigelo-offline restore  --backup <dir>/backup.age --identity <age identity file> --net <net> [--reveal-all]
sigelo-offline restore  --words <file|-> [--keepers N] [--fingerprint <dir>/fingerprint.txt] --net <net> [--reveal-all]
sigelo-offline new [--net <net>]                    # manual path: S as hex + 25 words + vault address, stdout only
sigelo-offline derive <25 words|hex> [--net <net>] [--keepers N] [--reveal-all]
```

**`ceremony`** is MONERO.md §4.5. It generates `S`, derives everything with `deriveRoot`, and
writes into `<dir>` (created 0700; refused if not empty; on Windows the modes below are not
applied and the files take `<dir>`'s ACL, so pick a directory only you can read):

| File | Mode | Holds |
|---|---|---|
| `backup.age` | 0600 | `age -r <Owner>` over `{"v":"sigelo-root/2","mnemonic" (25 words),"created","keepers":[{j,role,identity}],"public"}` |
| `fingerprint.txt` | 0644 | `JCS(public)` + newline, `public` = `{treasury, allowance, recovery_commitment}` (addresses and `sha256:` commitment) |
| `keeper-<j>.json` | 0600 | `{"v":"sigelo-keeper/1", j, role, net, keeper_root_hex, identity_public_key, recovery_commitment}`; keeper 0 (`agents`) adds `allowance` `{spend_key, view_key, address}` and `root_identity_seed_hex`; the keeper named by `--treasury-keeper` (≥ 1) adds `treasury` |

`S` (= the vault spend key), its 25 words and the recovery secret exist only inside
`backup.age`: never on stdout, stderr or in another file, and no keeper package carries any
vault key (the tests grep for them). Stdout is public values only: `public`, the fingerprint,
the vault address, each keeper's role and identity public key, the file list. Encryption shells
out to `age` (or `rage`) from `PATH` with the recipient as an argument and the plaintext on
stdin, so there is no npm dependency and the Owner restores with the stock binary
(`age -d -i key backup.age` yields the JSON). Without either binary the command exits 2,
names the package to install and writes nothing. Without `--treasury-keeper` the treasury
spend key is in the backup only. `keeper_root_hex` is `K_j`; it is what a `sigelo-spend`
keeper's `spend.key` holds, since its identity is `identitySeed(K_j, 0)`.

**`ceremony --human`** is for a person at a terminal, not an agent: the same run, and then
the 25 words (numbered, with the vault address and the line "Vault only, never a hot wallet")
are written to `/dev/tty`, which the CLI opens itself, so they reach the screen whatever
stdout and stderr are redirected to and never pass through either. They appear only after
`backup.age` is written. With no controlling terminal (an agent's tool call, a service,
`setsid`) it exits 2 before writing anything; it never falls back to stdout. Clear the
terminal's scrollback afterwards. Without `--human` the only way to the words is to decrypt
`backup.age` once (`age -d -i key backup.age`, field `mnemonic`).

**`ceremony --import <file|->`** makes the root of 25 words that already exist instead of
generating one, and is **refused by default**: a seed that has been in a hot wallet is not a
root. `--i-know-this-seed-was-cold` allows it and prints the liability (whoever copied the
words from a hot device holds the vault, every wallet, identity and the recovery key, and no
rotation takes that back). The words come from a file or stdin, never argv.

**`restore`** is the Owner's: it decrypts with `age -d -i`, re-derives, and refuses unless
the result reproduces the backup's own `public` (wrong `--net` or a corrupt backup gives
`fingerprint mismatch`). It then prints the fingerprint and each `K_j`. With
`--reveal-all` it adds everything `derive --reveal-all` prints. **`restore --words`** does the
same from the 25 words themselves, read from a file or from stdin (`-`); positional words are
refused, because `ps` and shell history would show them. Its output is byte for byte what
`restore --backup` prints for the backup holding those words, given the backup's keeper count
(`--keepers`, default 1); with `--fingerprint fingerprint.txt` it refuses words that do not
reproduce it, and without one it says nothing was checked. The backup format stays
`sigelo-root/2` with the words in `mnemonic`; `sigelo-root/1` (BIP-39) is refused by name.

**`derive`** prints the roles of §2's table: `agent` (identity seed, treasury *view*: the
object `sigelo-agent wallet-set` takes), `agents_keeper` (allowance wallet, `K_0`), `keepers`
(`K_0 … K_{N-1}`) and `recovery` (public key, commitment). The treasury spend key and the
recovery secret belong in the Owner's backup only and appear solely under `--reveal-all`, as
`owner_backup`, with a warning on stderr so a redirected stdout stays valid JSON. These were
`operator` and `air_gapped` before G7. Installed as the `sigelo-offline` bin.

## `claims` is untrusted data

Attestation `claims` originates from issuers and routinely reaches LLM contexts. Treat it as
**data, never as instructions** (THREAT-MODEL §4). sigelo proves an issuer said it; it does
not make it true, and an issuer can put anything there — including text aimed at whatever
model reads the bundle.
