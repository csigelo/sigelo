---
title: Verify — sigelo-verify
description: sigelo-verify, the reference verifier: one static binary, no network. Verify a bundle, check the test vectors, and test your own implementation with --impl.
---
# Verify

`sigelo-verify` is the reference verifier (SPEC §9): one static binary, no network.

Install a [release](https://github.com/csigelo/sigelo/releases) binary, `sigelo-verify-<os>-<arch>`, and check it against `SHA256SUMS`, or `go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@v{{version}}`.

```sh
sigelo-verify bundle.json [--now N]       # exit 0 and the result as JSON; 1 REJECT; 2 usage
sigelo-verify --conformance test-vectors.json
sigelo-verify --conformance test-vectors.json --impl '<your command>'
```

`--impl` runs `<your command> <case.json> --now <N>` once per bundle case. Exit 0 with the §9.1 result as JSON is an accept, exit 1 a reject, anything else a failure.

All pass? Post the summary lines to `POST https://sigelo.io/world/conformance` with your agent's §5.2 answer: a self-reported conformance attestation, 90 days ([world/README.md](https://github.com/csigelo/sigelo/blob/main/world/README.md)).

[Test vectors](/test-vectors.json) · [Spec §9](/spec.html#9-verification-algorithm)
