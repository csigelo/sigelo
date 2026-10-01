# sigelo — Go verifier

The reference verifier: SPEC §9 in Go. It is what a second implementation checks itself
against, next to `ts/`, and the two agree on every vector. It verifies; it does not
construct identities — `ts/` does that, and `ts/src/gen_vectors.ts` generates the vectors.
One dependency: `filippo.io/edwards25519`, for the Ed25519 and Monero group operations.
Keccak-256 and both base58 codecs are written out here.

## Build and run

```sh
go test ./... -v                      # every vector; prints ALL PASS
CGO_ENABLED=0 go build ./cmd/sigelo-verify   # static binary, no libc
# the test vectors' `bundle`, on stdin (-): prints its §9.1 result, exit 0
node -e 'process.stdout.write(JSON.stringify(require("../test-vectors.json").vectors.bundle.bundle))' | ./sigelo-verify - --now 1757289600
./sigelo-verify ../bundle.json               # a file: the one QUICKSTART step 6 writes at the repo root
```

`sigelo-verify` parses the bundle strictly. On success it prints the §9.1 result as JCS JSON
and exits 0. On rejection it prints `REJECT: <failing check>` on stderr and exits 1. Usage
errors exit 2. `--now` is Unix seconds. Without it the command reads the wall clock. The
verifier itself never does.

## What it checks

- `jcs.go`: RFC 8785 for the integer-only subset. Keys sort by UTF-16 code unit, strings use
  the ES6 escape set. The parser rejects duplicate keys, `"__proto__"` and invalid UTF-8 for the
  whole document; a non-integer or out-of-range number literal is kept as a marker and
  `Canonicalize` rejects it, so it discards only the attestation or binding that carries it. A `\ud800` escape is kept, and
  `Canonicalize` rejects it, so it discards only the attestation or binding that carries it.
  `encoding/json/v2` is not used: it fails the whole document on a lone surrogate, or maps it
  to U+FFFD (see `TestJSONv2`).
- `sigelo.go`: `Verify(bundle, now, knownIssuers)` runs §9 steps 1–7 and returns the §9.1
  `Result`. `Structure(body, slot)` holds the §3.1 rules. `VerifySig`, `DID` and
  `SigningInput` are for world-side checks such as a §5.2 challenge. Error strings copy
  `ts/src/sigelo.ts` word for word.
- `primitives.go`: base58btc multibase and Ed25519 verification. Verification is exactly as
  strict as ts/'s `@noble/ed25519` with `zip215: false`: canonical A and R, no small-order A,
  cofactored equation. `crypto/ed25519` is looser.
- `monero.go`: §6.2. It covers Keccak-256 (original padding), Monero base58, addresses
  (standard, integrated and subaddress, with non-minimal varints rejected), subaddress
  derivation, SigV2 sign and verify in both modes, and the sigelo glue. That glue accepts
  a standard or subaddress `addr` (a subaddress against its own keys) and refuses an
  integrated one and SigV1.

`go test ./... -v` prints 498 `PASS` lines and ends `ALL PASS`: `TestVectors` 242 (the
conformance run, the same lines as `--conformance` below), `TestJCS` 199, `TestJSONv2` 4,
`TestEd25519Strict` 3, `Test1f916` 7, `TestKeys` 26 and `TestMoneroWords` 17. It covers every
vector in `../test-vectors.json` and `../ts/test/monero-vectors.json`, the `parity` group
`ts/` runs identically, the JCS known answers, the json/v2 findings and the Ed25519 edge
cases. `Test1f916` is the cross-implementation check on the 1f916 adapter: the bundle that
adapter's own test emitted (`adapters/1f916/sample-bundle.json`) is accepted byte for byte,
and rejected when one signature character is flipped.

`keys.go` is the one constructive part: MONERO.md §2's root-seed derivation, the same
functions as `ts/src/keys.ts` (`K` = HKDF-SHA256 with empty salt and the path as `info`,
`IdentitySeed`, `RecoverySeed`, `KeeperRoot`, `AgentIdentitySeed`, `WalletFromRoot`,
`DeriveIdentity`), so a Go keeper derives from `S` or a keeper root `K_j` exactly the keys the
ts offline box does. Indices are `uint64` capped at 2^53−1, the JS safe-integer range, with
ts's error strings. `S` is a Monero 25-word seed: `RootFromMnemonic`, `MnemonicFromRoot`,
`EncodeMoneroWords`/`DecodeMoneroWords` (wordlist in `monero_words.go`) and `VaultFromRoot`
(`b = sc_reduce32(S)`, the wallet a stock wallet restores from the words) match ts word for word;
`TestMoneroWords` pins the same three vectors and a 64-root sweep digest as ts. `keys_test.go` pins ts's fixed
vectors and the key, DID, recovery commitment and wallet addresses ts derives from the test
root (`TestKeys`); the 25-word root is `TestMoneroWords`. The §6.2 subaddress bindings and the
live wallet-rpc oracle entries in `../ts/test/monero-vectors.json` run inside `TestVectors`.

## Conformance from the binary, and reproducible builds

`conformance.go` is the vector run itself: `Conformance(w, vectors, moneroVectors)` checks
every vector in `test-vectors.json` the way this verifier checks it and writes one `PASS`/`FAIL`
line per check. `TestVectors` calls it, and so does the binary, so the lines are the same:

```sh
sigelo-verify --conformance ../test-vectors.json   # … 242 passed, 0 failed / ALL PASS, exit 0
sigelo-verify --version                             # wire sigelo/0, Go version, commit, deps
```

`--conformance` defaults to `./test-vectors.json` and exits 1 on any `FAIL`. The §6.2 Monero
section needs `ts/test/monero-vectors.json`: `--monero <file>` names it; otherwise it is looked
for next to the vectors file, and the section is skipped with a `SKIP` line if absent (188
checks instead of 242). It checks the vectors file against this verifier: an implementer can
confirm a copy of the vectors is intact and this verifier agrees with it, then diff their own
implementation's output against these lines.

### Checking another implementation: `--impl`

`--conformance --impl '<command>'` runs the vectors against a **candidate** verifier instead of
this one (ROADMAP T7), so the check an agent runs on its own port is one released binary:

```sh
sigelo-verify --conformance ../test-vectors.json --impl 'python3 -m myverifier'
# PASS bundle == expect … FAIL neg fork rejects — exit 0, want 1 (reject) …
# positive 14/14, monero 9/9, negative 29/29, parity 87/87
# 139 passed, 0 failed / ALL PASS, exit 0 (1 on any FAIL, 2 if the vectors file is unusable)
```

The protocol is `docs-test/grade-verifier.mjs`'s, adopted verbatim — the interface of
`sigelo-verify` itself and of `docs-test/TASK-verifier.md` — so the binary and the node grader
score a candidate identically (same case names, same order, same verdicts; checked by diffing
both over the same candidate):

- Each case is a **bundle file**. The candidate is run once per case as
  `<command> <case.json> --now <N>`, with `N` the vectors file's `now` (or the vector's own).
  `--impl-stdin` passes `-` instead of a path and the case bytes on stdin.
- **Exit 0** with the §9.1 result as one JSON value on stdout is an **accept**. It is compared by
  value (key order, whitespace and number spelling free) on the six §9.1 fields, and of each
  binding entry on `body` and `proof`; anything else the candidate prints alongside is ignored.
  An absent field is not `null`.
- **Exit 1** is a **reject** (§9 fatal; `REJECT: <check>` on stderr by convention, not compared).
  Every other exit code, a signal or a timeout (`--impl-timeout` seconds per case, default 10)
  is a failure of the candidate, never a rejection.
- Per-item discards are observed through the result: a discarded attestation or binding must be
  absent and counted in `rejected`, and a binding keeps the exact `proof` the vector pins
  (`proven`, `unproven`, `unsupported`). The `parity` cases pin `proofs`, the accepted
  attestation count and `rejected`; a `reject` expectation means exit 1.
- Case bytes: every sub-document is spliced in as the bytes the vectors file holds, never
  re-serialized, so hostile-JSON cases (`raw`, duplicate keys, `__proto__`, floats, escapes)
  reach the candidate unchanged. A parity `bundle` holding a `"__proto__"` key becomes bundle
  TEXT, which §3 makes fatal, so it is scored as a reject.
- Invoice vectors never enter a bundle (§6.3): listed as not expressible, not scored. The
  §6.2 section of `ts/test/monero-vectors.json` is not in this mode (`--monero` is refused);
  the Monero bindings of `test-vectors.json` are, as the `monero` group.

Proofs, re-run at cad0357 (139 bundle cases): this binary as its own candidate
(`--impl ./sigelo-verify`) 139/139, with `--impl-stdin` 139/139; `ts/` as a candidate through
`cmd/sigelo-verify/testdata/ts-candidate.mjs` (`--impl 'node …/ts-candidate.mjs'`, after
`npx tsc` in `ts/`) 139/139; the same wrapper with `--break` (every `unproven` reported
`proven`) 136/139, FAIL `bundle == expect`, `binding_unproven → unproven` and `parity
binding_envelope_sig_id_only_unproven`, exit 1.
`impl_test.go` runs the runner over the test binary as a fake candidate — correct, flipped,
never-rejecting, crashing and hanging — and pins the comparison rules. CI runs the first three.

`../release/build.sh [outdir]` builds `sigelo-verify` for linux/{amd64,arm64},
darwin/{amd64,arm64} and windows/amd64 with `CGO_ENABLED=0 -trimpath -ldflags='-s -w
-buildid='`, `GOENV=off`, `-mod=readonly`, `SOURCE_DATE_EPOCH` from the commit, and writes
`SHA256SUMS` (`sha256sum -c` format). It refuses a dirty tree unless `SIGELO_ALLOW_DIRTY=1`,
because the embedded VCS stamp (`--version`) records it. Same commit and same Go version give
the same hashes; CI builds twice, the second time with an empty build cache, diffs the sums and
uploads `SHA256SUMS` as an artifact. Nothing is published.
