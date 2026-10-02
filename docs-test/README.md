# docs-test: the comprehension harness

Measures whether a model can use sigelo from its documents alone: it gets **only** a task prompt
and a frozen docs snapshot, and a program grades what it produces.

| File | What |
|---|---|
| `snapshot.sh` | freezes the docs a candidate may read, from git at a revision, with SHA-256s |
| `TASK-lifecycle.md` | prompt, condition **lifecycle** (docs only, ts library available) |
| `TASK-verifier.md` | prompt, condition **verifier** (SPEC + vectors only, write a verifier) |
| `collect.sh` | copies a lifecycle workspace's `out/` and the mock world's state for grading |
| `grade.mjs` | grades a lifecycle run: 10 points |
| `grade-verifier.mjs` | grades a verifier: N/M bundle cases built from `test-vectors.json` |
| `RESULTS.md` | every measurement so far, and the reporting format |
| `check-budgets.mjs`, `budgets.json` | word budgets for the public docs (CI, ts job): `node docs-test/check-budgets.mjs` |

## Conditions

**lifecycle** (docs-only). The candidate reads `SPEC.md`, `QUICKSTART.md`,
`examples/world.mjs`, `ts/README.md` (identity part only: its Monero and root-seed sections
are cut), `test-vectors.json` and `schema/`, and may run `node`, the built library
(`import('sigelo')`) and the mock world. It must not read `ts/src`, `go/`, `adapters/`,
`spend/`, or the compiled `ts/dist` and `node_modules` that sit in its workspace so they can
run. QUICKSTART's `sigelo-agent` CLI is deliberately absent: the candidate does its steps with
the library.

**verifier** (spec-only implementer). The candidate reads `SPEC.md` and `test-vectors.json`
and nothing else, and writes a bundle verifier in a language the repo does not ship (not
TypeScript/JavaScript, not Go), with the CLI of `sigelo-verify`:
`<cmd> <bundle.json> --now N` → §9.1 JSON on stdout and exit 0, or exit 1 to reject.

## Running a round

Needs node ≥ 22.18, `ts/` installed and built (`cd ts && npm ci && npx tsc`), and Go on
`PATH` for the reference verifier (or pass `--go` a built `sigelo-verify`).

Give `snapshot.sh` `HEAD` or a tag.

```sh
# 1. freeze the docs at the tag the round measures; quote MANIFEST.json's digests beside scores
docs-test/snapshot.sh v0.x --sandbox /tmp/run-A            # lifecycle workspace in /tmp/run-A
#    → docs-test/snapshot/<hash>/{lifecycle,verifier}/ + MANIFEST.json

# 2a. lifecycle: give the model TASK-lifecycle.md verbatim as its prompt, /tmp/run-A as its
#     working directory, a shell with node, and nothing else (no network, no repo). Start a clock.
#     When it says it is done:
docs-test/collect.sh /tmp/run-A runs/<id>                  # out/ + _world/ (the world's own state)
node docs-test/grade.mjs runs/<id>                         # grade at once: `now` is the wall clock

# 2b. verifier: give the model TASK-verifier.md and a directory holding only
#     docs-test/snapshot/<hash>/verifier/{SPEC.md,test-vectors.json}, a shell and its language's
#     toolchain. When it is done, build its program and grade it against the SAME vectors file:
node docs-test/grade-verifier.mjs --vectors docs-test/snapshot/<hash>/verifier/test-vectors.json -- <its command>
```

Keep every run's full transcript and its SHA-256: a lifecycle run that reads `ts/dist/*.js`, or a
verifier run that reads anything but its two files, is **void**. The harness cannot enforce this
(compiled JS and the world's state files sit in the workspace): run each candidate in a container
or VM with no network and only its workspace mounted.

## The lifecycle rubric (grade.mjs)

One point each. Artifact names are fixed by TASK-lifecycle.md; `_world/` comes from
`collect.sh`. Checks run the repo's ts `verify()` and the Go `sigelo-verify` at `now`.

| # | Point | PASS when |
|---|---|---|
| 1 | genesis | `genesis.json` passes the §3.1 genesis check and is the `genesis` of each bundle present |
| 2 | recovery commitment | `genesis.recovery` = `sha256:` + hex SHA-256 of the raw `recovery.pub` key, and that key is not the identity key |
| 3 | attestation accepted | `issued.json`'s issuer is the harness world (`_world/world.local.json`), the attestation is to the original DID, and `verify()` accepts it verbatim in `bundle.json` and `bundle-recovered.json` |
| 4 | binding proven | `binding.json` is `ed25519-test` (§6.1a), its `id` is in the chain, `verify()` reports it `proven` |
| 5 | voluntary rotation | `rotation-voluntary.json` is voluntary from the original DID and in `bundle.json`; chain = [original, next]; the original commitment still governs |
| 6 | challenge under the current key | `challenge-2.json` is the challenge the world holds for the post-rotation DID (nonce in `_world/challenge.local.json`), five fields, naming the post-rotation DID; its `sig` verifies under the rotated key and not the original |
| 7 | sigelo-verify exit 0 | the Go reference verifier exits 0 on both bundles and its §9.1 result equals ts `verify()`'s by value |
| 8 | recovery + precedence | recovery rotation from the rotated DID, `recovery_key` = `recovery.pub`; the thief's rotation from the same DID is fully valid (leaked-key signature, commitment carried, `next` hash right) with a **later** `iat`; `bundle-recovered.json` holds all three rotations; chain = [original, rotated, recovery.next]; and with the recovery rotation removed the same bundle follows the thief (so precedence decided it) |
| 9 | invariants | every artifact parses strictly (no duplicate keys, no `__proto__`), holds no non-integer number, validates against `schema/` for its slot (validator taken verbatim from `schema/check.mjs`); `challenge-*.signed.json` is exactly `{did, sig}`; both results validate as `verify-result` and discarded nothing |
| 10 | reported DID | `report.json` `did` equals, in full, the current DID `verify()` computes for `bundle-recovered.json` |

Without a verifying `bundle.json`, points 3, 4, 5, 7, 8 and 9 cannot pass.

## The verifier score (grade-verifier.mjs)

Every case is a bundle file built from `test-vectors.json` (groups `positive`, `monero`,
`negative`, `parity`); invoices cannot enter a bundle and are not scored. The protocol and case
list equal `sigelo-verify --conformance --impl` (go/README.md), which differs only by exiting 1 on
any FAIL (this script always exits 0). A case added here goes into `go/cmd/sigelo-verify/impl.go`
in the same change; CI diffs their lines.

## Reporting

One row per run in RESULTS.md:

| Date | Round | Condition | Model | Family | Snapshot | Score | Time | Transcript | Failing points |
|---|---|---|---|---|---|---|---|---|---|
| YYYY-MM-DD | 3 | lifecycle \| verifier (language) | exact model id | Claude \| GPT \| Gemini \| open-weights | `<short hash>` + condition digest (first 16 hex) | `n/10` or `N/M` (+ per-group) | wall clock, prompt to "done" | SHA-256 of the transcript | point numbers and grader lines |

Report each run, not an average; list void runs as void with the reason.
