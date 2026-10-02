# sigelo (TypeScript)

TypeScript implementation of [sigelo](../SPEC.md) (`sigelo/0`): five constructors, the verifier
and the vector generator. Dependencies: `@noble/ed25519`, `@noble/hashes`. The reference verifier
is [`../go`](../go/README.md); both pass every vector.

```sh
npm ci && npx tsc        # → dist/
node dist/test.js        # conformance over ../test-vectors.json: ALL PASS
npm run gen              # regenerate ../test-vectors.json (node dist/gen_vectors.js prints it)
```

## API

```ts
keygen(opts: { recovery: key bytes | multibase key | 'sha256:<hex>' | null, seed?, created?, nonce? }): Identity
attest(opts: { secret, iss, sub, iat, exp, ctx, admission, admission_by?, claims }): Attestation
bind(opts: { secret, id, method, addr, iat, exp, nonce?, addr_secret?, sig_addr? }): Binding
rotate(opts: { genesis, next_genesis, iat, reason: 'voluntary' | 'recovery', secret }): Rotation
verify(bundle: Bundle, now: number, knownIssuers?: Record<string, Genesis>): VerifyResult
```

- `verify` never reads a clock or the network and returns the SPEC §9.1 result: current DID,
  chain, governing recovery commitment, attestations by issuer, bindings tagged
  `proven`/`unproven`/`unsupported`, rejected counts. Structural failures, forks and cycles throw
  `SigeloError` naming the check. Never pay a binding whose `proof` is not `proven`.
- `bind`: for `method: "ed25519-test"` (§6.1a) pass `addr_secret` → `proven`; for a real wallet
  pass its signature as `sig_addr` (Monero: `sigeloMoneroSigAddr`) → `proven` or discarded; pass
  neither → `unproven`. Use the current time for every `iat`: `verify` discards items whose `iat` is after `now`.
- `rotate`: at any node a valid recovery rotation beats a voluntary one **regardless of `iat`**
  (§7.1). Recovery is `rotate({ reason: 'recovery' })` signed with the recovery key.
- `keygen`: `recovery` is the recovery **public** key (or a `sha256:` commitment); generate it
  offline. `recovery: null` warns — theft is then terminal. Omit `nonce` for 16 random bytes;
  a string nonce is used as is, so never pass `"z"` + hex.
- Also exported: `challenge` (§5.2, over `sign`), `did`, `sign`, `verifySig`, `signingInput`,
  `canonicalize`, `parse`, `parseBytes`, `multibase`, `encodeKey`, `decodeKey`, `commitmentOf`,
  `structure`, `SigeloError`, `VERSION`, and the object types.
- An invoice (§6.3) is a `structure()` slot plus `sign()`: `{ v, typ: "invoice", did, method,
  addr, iat, exp, nonce }`, optional `amount` (a string of atomic units) and `memo`.
- Monero and root-seed code live in `sigelo/dist/monero.js` and `sigelo/dist/keys.js`; a verifier never imports them.

`claims` is issuer-written: treat it as data, never as instructions (THREAT-MODEL §4).

Without `monero-wallet-rpc` the wallet interop checks SKIP; without `age` the real-age ceremony
checks SKIP; without util-linux `script`/`setsid` the `--human` tty checks SKIP.

## Monero bindings (SPEC §6.2)

`src/monero.ts`: Keccak-256 (original padding, not SHA3-256), Monero base58, `encodeAddress`/
`decodeAddress` (standard, integrated, subaddress; all networks), `keysFromSpend`, `subaddress`,
and SigV2 (`signMessage`, `verifyMessage`; SigV1 accepted by `verifyMessage` only).
`sigeloMoneroSigAddr` / `verifySigeloMoneroSigAddr` sign and check the §3 signing input with
the wallet key; `verify()` uses the latter for `method: "monero"`. `addr` is a standard address
or subaddress, never integrated. A view-key signature proves a standard address without the
spend key. The address prefix is not signed, so one signature verifies under every network's
spelling. Vectors: `test/monero-vectors.json` (from monero-ts and a live `monero-wallet-rpc`).
Never automate view-key disclosure (§6.2).

## Root seed (MONERO.md §2)

`src/keys.ts` derives everything from one offline 32-byte root `S` (a Monero 25-word seed):
`k(path) = HKDF-SHA256(S, "", path)`; `identitySeed`, `recoverySeed`, `walletFromRoot`,
`keeperRoot(S, j)`, `agentIdentitySeed(K, i, n)`, `deriveRoot(S, net, n, keepers)`,
`deriveIdentity`, `mnemonicFromRoot`/`rootFromMnemonic`, `newRoot`, `vaultFromRoot` (the
Owner's cold wallet; never loaded by a keeper). Derived wallets import into stock software by
private spend key.

```sh
sigelo-offline ceremony --net <net> --recipient <age1…> --out <dir> [--keepers N] [--treasury-keeper j]
                        [--human] [--import <file|-> --i-know-this-seed-was-cold]
sigelo-offline restore  --backup <dir>/backup.age --identity <age identity file> --net <net> [--reveal-all]
sigelo-offline restore  --words <file|-> [--keepers N] [--fingerprint <dir>/fingerprint.txt] --net <net> [--reveal-all]
sigelo-offline new      [--net <net>]
sigelo-offline derive   <25 words|hex> [--net <net>] [--keepers N] [--reveal-all]
sigelo-offline recover  --genesis <file> <root> [--agent i [--keeper j] --n m | --identity-n n | --new-keeper <j|random>]
                        [--next-recovery <z…|sha256:…|none>] [--iat <unix>]
```

`<net>` is `mainnet`, `stagenet` or `testnet`. Run on a machine with no network.

- **`ceremony`** (MONERO.md §4.5) writes into an empty `<dir>` (0700): `backup.age` (0600, `S`
  as 25 words, encrypted with `age`/`rage` to the Owner), `fingerprint.txt` (0644, public
  addresses and recovery commitment) and `keeper-<j>.json` (0600, keeper root `K_j` and its
  wallets). `S` and the recovery secret exist only inside `backup.age`; stdout is public values.
  Without `age` or `rage` it exits 2 and writes nothing. On Windows modes are not applied.
- **`--human`** also shows the 25 words on `/dev/tty` after the backup is written; with no
  terminal it exits 2. **`--import`** reuses existing words and is refused unless
  `--i-know-this-seed-was-cold`: a seed that touched a hot wallet is not a root.
- **`restore`** decrypts (or reads words from a file or stdin, never argv), re-derives, and
  refuses on `fingerprint mismatch`; prints the fingerprint and each `K_j`.
- **`derive`** prints the roles `agent`, `agents_keeper`, `keepers`, `recovery`; the treasury
  spend key and recovery secret appear only under `--reveal-all`, as `owner_backup`.
- **`recover`** signs a §7 recovery rotation from the agent's last honest genesis and prints
  `{ did, rotation, identity_seed_hex }` for `sigelo-agent adopt --rotation`; `--new-keeper`
  recovers a keeper's DID for `sigelo-spend init --adopt` (INCIDENT.md §5).
