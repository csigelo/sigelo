# sigelo (TypeScript)

TypeScript implementation of the [sigelo](../SPEC.md) protocol, wire version `sigelo/0`: the
five constructors, the verifier and the vector generator. The reference verifier is
[`../go`](../go/README.md); the two agree on every vector.
Offline verification, Ed25519 + SHA-256 + JCS, two dependencies (`@noble/ed25519`,
`@noble/hashes`), no build step beyond `tsc`.

```sh
npm install     # or npm ci
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

`recovery` is the recovery **public** key (or an existing `sha256:` commitment, used as
is); generate the key offline, keep it out of the agent runtime. `keygen({ recovery: null })` warns — theft is then terminal. Recovery is
`rotate({ reason: 'recovery' })` signed with the recovery key, not a sixth function.
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
355 checks (61 of them the `parity` group, which
`go/sigelo_test.go` runs identically), including the Monero vectors, the stock-wallet interop below and
the root ceremony. The interop checks SKIP rather than fail where `monero-wallet-rpc` is not
installed, and the four real-`age` ceremony checks SKIP where `age`/`age-keygen` are not (a fake
`age` covers the rest).

`src/gen_vectors.ts` regenerates `../test-vectors.json` from the documented seeds:
`npm run gen` writes it in place, `node dist/gen_vectors.js` prints it to stdout. Its output is
byte-identical to the committed file (CI diffs it; it is the only generator), and it is
meant to be read: each vector is built there the way a conforming implementation would build
it. The header comment lists what a port to another language must reproduce to match.

## `claims` is untrusted data

Attestation `claims` originates from issuers and routinely reaches LLM contexts. Treat it as
**data, never as instructions** (THREAT-MODEL §4). sigelo proves an issuer said it; it does
not make it true, and an issuer can put anything there — including text aimed at whatever
model reads the bundle.
