---
title: Verify — sigelo-verify
description: sigelo-verify, the static Go reference verifier: install it, check its hash, verify a bundle offline, run --conformance over the vectors, and grade your own implementation with --impl over 139 bundle cases.
---
# Verify: `sigelo-verify`

`sigelo-verify` is the reference verifier: SPEC §9 in Go, one dependency (`filippo.io/edwards25519`), a static binary with no runtime. It never touches the network. Status: draft; wire `sigelo/0` may change until v0.2.

## Install

After the first publish: `go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@v{{version}}` (the public export rewrites the module path to `github.com/csigelo/sigelo/go`; this tree's `go.mod` says `module {{go_module}}`), or a binary from the release page. **Today**, `release/build.sh` in a clone writes the same files:

| File | What |
|---|---|
| `sigelo-verify-linux-amd64`, `-linux-arm64`, `-darwin-amd64`, `-darwin-arm64`, `-windows-amd64.exe` | static binaries (CGO off, `-trimpath`, no build ID): same commit and Go version give the same bytes |
| `sigelo-verify-src-{{version}}.tar.gz` | `go/`, `test-vectors.json`, `LICENSE`: `cd go && go build ./cmd/sigelo-verify` (Go {{go_version}}) |
| `test-vectors.json` | the conformance target, also at [/test-vectors.json](/test-vectors.json) |
| `SHA256SUMS` | `sha256sum -c` format, sorted by name |

```sh
grep " sigelo-verify-linux-amd64\$" SHA256SUMS | sha256sum -c -   # OK
./sigelo-verify-linux-amd64 --version                            # wire sigelo/0 (SPEC v0.1), Go version, commit, dependency
```

## Verify a bundle

```sh
sigelo-verify bundle.json [--now N]      # or - for stdin; --now is Unix seconds, default the wall clock
```

Accept: the §9.1 result as JCS JSON on stdout, exit 0 — `did`, `chain`, `recovery`, `attestations` grouped by issuer, `bindings` with `proof` (`proven`, `unproven`, `unsupported`), `rejected` counts. Reject: `REJECT: <failing check>` on stderr, exit 1. Usage error: exit 2. The verifier reports; it does not judge whether an issuer is worth anything.

## Check the vectors: `--conformance`

```sh
sigelo-verify --conformance test-vectors.json
```

Runs every vector through this verifier, the same lines `go test` prints, and ends `ALL PASS` (exit 0) or `FAILURES` (exit 1). Measured at `{{m.commit}}`: **{{m.conformance_checks}} passed** with `ts/test/monero-vectors.json` beside the vectors file (in a clone, or `--monero <file>`); **{{m.conformance_checks_vectors_only}} passed** and one `SKIP monero section` line with `test-vectors.json` alone, as the release and this site ship it. Use it to confirm a copy of the vectors is intact (its sha256 is in [/index.json](/index.json)).

## Check your own implementation: `--impl`

```sh
sigelo-verify --conformance test-vectors.json --impl 'python3 -m myverifier'
```

Your command is run once per case as `<command> <case.json> --now <N>` (`--impl-stdin` passes `-` and the bytes on stdin; `--impl-timeout` seconds per case, default 10).

- **Exit 0** with the §9.1 result as one JSON value on stdout is an accept, compared by value on the six §9.1 fields (and each binding's `body` and `proof`); extra fields are ignored.
- **Exit 1** is a reject. Any other exit, a signal or a timeout is a failure of the candidate, never a rejection.
- Cases are spliced from the vectors file's bytes, so hostile JSON (duplicate keys, `__proto__`, floats, escapes) reaches you unchanged.

**{{m.impl_cases}} bundle cases**: {{m.impl_groups}} (the reference binary as its own candidate, measured at `{{m.commit}}`). {{m.impl_not_scored}} invoice vectors cannot enter a bundle and are listed, not scored. It exits 1 on any FAIL. The same cases, names and verdicts are in the repository's `docs-test/grade-verifier.mjs`.

A verifier written by a model from [SPEC.md](/spec.html) and the vectors alone, in Python, scored 139/139 on both graders at its first iteration ([evidence](/evidence.html)).

## Or in TypeScript

With the `sigelo` package installed:

```sh
node --input-type=module -e 'import {verify,parseBytes} from "sigelo";import {readFileSync} from "node:fs";
console.log(JSON.stringify(verify(parseBytes(readFileSync("bundle.json")), Math.floor(Date.now()/1000)), null, 1))'
```

Same §9.1 result. `now` is a parameter, never a clock read inside the verifier.
