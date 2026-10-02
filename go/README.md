# sigelo — Go reference verifier

SPEC §9 in Go: what a second implementation checks itself against. It verifies; the only
constructive code is `keys.go` (MONERO.md §2 derivation, identical to `ts/src/keys.ts`).
One dependency: `filippo.io/edwards25519`.

```sh
go test ./... -v                                   # every vector: ALL PASS
CGO_ENABLED=0 go build ./cmd/sigelo-verify         # static binary
./sigelo-verify bundle.json --now 1757289600       # or - for stdin
./sigelo-verify --conformance ../test-vectors.json [--monero ../ts/test/monero-vectors.json]
./sigelo-verify --conformance ../test-vectors.json --impl '<your verifier command>' [--impl-stdin] [--impl-timeout S]
./sigelo-verify --version
```

Verify: exit 0 and the §9.1 result as JCS JSON on stdout; exit 1 and `REJECT: <check>` on
stderr; exit 2 on usage errors. Without `--now` the CLI reads the clock; the library never does.

`--conformance` checks the vectors against this verifier, one `PASS`/`FAIL` line per check, exit
1 on any `FAIL`. The §6.2 Monero section uses `monero-vectors.json` next to the vectors file or
`--monero`, and SKIPs if absent.

## Checking your implementation: `--impl`

`--impl '<command>'` scores a candidate verifier on every bundle case, identically to
`docs-test/grade-verifier.mjs`:

- The candidate runs as `<command> <case.json> --now <N>` (`--impl-stdin`: `-` and the bytes on stdin).
- **Exit 0** + the §9.1 result as one JSON value on stdout = accept, compared by value on the six
  §9.1 fields (bindings on `body` and `proof`). An absent field is not `null`.
- **Exit 1** = reject. Any other exit, a signal or a timeout (default 10 s) is a failure.
- Discarded attestations and bindings must be absent and counted in `rejected`.
- Case bytes are the vectors file's bytes, never re-serialized, so hostile-JSON cases arrive intact.
- Invoices are not scored (they never enter a bundle); `--monero` is refused in this mode.

Example: `--impl 'node cmd/sigelo-verify/testdata/ts-candidate.mjs'` scores `ts/` (after `npx tsc` there).

## Files

| File | What |
|---|---|
| `sigelo.go` | `Verify(bundle, now, knownIssuers)` → §9.1 `Result`; `Structure` (§3.1); `DID`, `VerifySig`, `SigningInput` for world-side checks. Error strings equal ts's. |
| `jcs.go` | RFC 8785 for integers: UTF-16 key order, ES6 escapes; strict `Parse` (duplicate keys, `__proto__`, invalid UTF-8 fatal); floats and lone surrogates fail only the item that carries them |
| `primitives.go` | base58btc, Ed25519 verify as strict as `@noble/ed25519` `zip215: false` (`crypto/ed25519` is looser) |
| `monero.go` | §6.2: Keccak-256, Monero base58, addresses, subaddresses, SigV2, `sig_addr` glue |
| `keys.go`, `monero_words.go` | root-seed derivation and 25-word encoding, byte-identical to ts |
| `conformance.go` | `Conformance(w, vectors, moneroVectors)`: the vector run used by `TestVectors` and `--conformance` |
| `cmd/sigelo-verify` | the CLI; `impl.go` is the `--impl` runner |

Reproducible binaries for five targets: `../release/build.sh` (see `release/RELEASE.md`).
