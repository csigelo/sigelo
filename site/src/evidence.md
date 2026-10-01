---
title: Evidence — what has been tested
description: What sigelo's claims rest on: test suites with counts measured from the tree, the reproducible release build, seeded simulations and their digests, the cross-check against third-party code, the docs-only comprehension rounds, and the keeper's stagenet soak.
---
# Evidence

What has been run, with the numbers it printed. Every review and every test harness so far was written by Claude models; the cross-check below is the one place where the expected answers come from code sigelo's authors did not write. Nothing has been reviewed by anyone outside the project.

## Suites, measured for this site

Run at `{{m.commit}}` on {{m.date}} ({{m.where}}).

| Command | Result |
|---|---|
| `cd go && go test ./... -v` | {{m.go_test_pass_lines}} `PASS` lines, exit 0 |
| `sigelo-verify --conformance ../test-vectors.json` (monero vectors beside it) | {{m.conformance_checks}} passed, 0 failed, `ALL PASS` |
| `sigelo-verify --conformance test-vectors.json` (the file alone, as released) | {{m.conformance_checks_vectors_only}} passed, one `SKIP monero section`, `ALL PASS` |
| `sigelo-verify --conformance test-vectors.json --impl ./sigelo-verify` | {{m.impl_cases}} passed: {{m.impl_groups}}; {{m.impl_not_scored}} invoice vectors not scored |
| `cd integrations/mcp && npm test` | `ALL PASS ({{m.mcp_checks}} checks)` |
| `cd adapters/moadim && npm test` | {{m.moadim_checks}} checks, `ALL PASS` |

**Recorded, not re-run for this site** (the figures the repository's READMEs record at `cad0357`): `ts/` 620 `PASS` lines with `monero-wallet-rpc` on `PATH` (608 and one `SKIP` without it); `spend/` 659 passed with the funded stagenet wallet reachable, 626 passed and 2 skipped without it; `release/pack-test.sh` 16 checks on a built directory, 17 when it runs the build itself.

## Release build

`release/build.sh` builds every artefact from a clean clone of HEAD. At `{{m.commit}}` with go1.27.1, node v24.18.1 and npm 11.11.0 it wrote:

```
11f71314ab6d093cae209e7bdefb38e9ebf3bf32960dbf3e0d73434517028b2e  sigelo-0.1.0.tgz
6574249b8b271bbb18d12b831ae422413a988ece0305afef563c794d81e39f26  sigelo-agent-0.1.0.tgz
c0006cafc946dd7040db55dc71198ac3479dfe83a77dcfe248e8e62d57e8529f  sigelo-mcp-0.1.0.tgz
c73d4de82bc141893d21caea88c08384694be62737669d0e51e2f28f7c81624f  sigelo-spend-0.1.0.tgz
2e024f6afcd15609c8dd2012d5ba467c8dee032a7f66b81ef3a04b0be197e0e6  sigelo-verify-darwin-amd64
40498f95a62121bf8b18ec6e7303b3efab5e43abb6324ce0b3b381f2f29727d9  sigelo-verify-darwin-arm64
554f259dcfb75061701145e182b0b344d6167056c9bb4140a5053bfffcd0b31e  sigelo-verify-linux-amd64
c8edcb1f8be99f2dc554203145a97496dd91030494691513ef7c82afd5d0267f  sigelo-verify-linux-arm64
7104943beeb569ee8eed6e2c15ec03136d42b59d9098af61ea997d5140e34a5e  sigelo-verify-src-0.1.0.tar.gz
603e1cc6a282f51800c73cdd6a3e9aa8140d6c7a16067585fca331b2ca8d6659  sigelo-verify-windows-amd64.exe
5fe0405db81a841fbab2fff8b9622857988ba321895f9e4fa79354589fb6e3d1  test-vectors.json
```

`build.sh` is made so that the same commit and the same Go toolchain give byte-identical binaries (ROADMAP §1 R2 records `SHA256SUMS` identical across two builds); the npm tarballs also depend on the node, npm and TypeScript versions. With these tarballs in an empty directory, every command on [adopt](/adopt.html)'s agent path ran and `sigelo-verify` accepted the bundle (exit 0). Nothing has been published.

## Simulations

Seeded and deterministic, so a digest names a run ([repository `sim/README.md`]({{repo}}/blob/main/sim/README.md)):

| Simulation | What | Digest |
|---|---|---|
| `swarm.mjs`, seed `sigelo-swarm-1` | 300 agents, 6 worlds, 40 rounds: joins, migrations, rotations, Monero bindings, thefts, forks, recoveries, tampered and fuzzed bundles; a sample re-verified by the Go verifier byte for byte | `e7500c102bd9cbad` (6 and 3 workers alike) |
| `worlds.mjs`, seed `sigelo-worlds-1` | dishonest worlds and the 1f916 adapter as a world: 36 case kinds, each with the SPEC section that decides it | `c51d1462e916bac8` |
| `keeper-scenarios.mjs`, seed `sigelo-keeper-scenarios` | 78 scripted keeper steps: nested delegation, `policy.json` edited under a running keeper | `e9622c852b72a605` |

Checks on the checkers: 13 bugs planted one at a time in a copy of `ts/dist`, each reported by the swarm or the worlds run; 7 planted in the keeper's delegation tree, each caught by the scenarios (the repository's `sim/REPORT.md`).

## Cross-check against third-party code

2026-09-29, sigelo `4e1a5aa`, seed 20260929: **0 divergences**. Oracles: the RFC 8785 author's reference canonicalizers and testdata, monero-python 1.1.1, libsodium through PyNaCl 1.6.2, the RFC 8032 text, Wycheproof (151 Ed25519 vectors), ed25519-speccheck (12 cases). Among the runs: 20 000 random JCS documents and 100 008 integers equal in ts and go; 1 800 forbidden inputs rejected by both; 10 000 Monero base58 encodes, 5 000 seed-derived wallets and 2 500 subaddresses equal; 500 libsodium signatures byte-identical and 800 malleated ones rejected. The three monero-python disagreements are its own departures from Monero's C++. Not covered: Monero message signatures (SigV2), for lack of a third-party oracle; the wallet-rpc oracle in `spend/` checks those. Source: the repository's `crosscheck/README.md`.

## Docs-only comprehension

A model gets only a task prompt and a frozen snapshot of the docs, and a program grades what it produces. One run per cell, Claude models only, so a datapoint, not a distribution. The table, copied from the repository's `docs-test/RESULTS.md`:

{{table:docs-test/RESULTS.md:1}}

The bar for v0.2 is at least 9/10 at Haiku tier across model families; it is not met. Non-Claude families have not run.

## Keeper soak (stagenet)

Scripted agents against a real keeper and wallet on stagenet, started 2026-09-23 (`41076a6`), planned for at least 14 days; ROADMAP §1 R4 records day 6 on 2026-09-29. Four incidents are written up in the repository's `spend/soak/README.md` (a stale lock after a reboot, a torn log tail pre-empted, a near-miss redeploy, 32 hours offline). The incident rehearsal (T14) has no recorded result at this commit.
