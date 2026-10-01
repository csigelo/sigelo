# docs-test: the comprehension harness

Measures whether a model can use sigelo from its documents alone (ROADMAP R3, T5, T11). A
model gets **only** a task prompt and a frozen docs snapshot; what it produces is graded by a
program. No model grades anything, and a score is what the grader prints.

| File | What |
|---|---|
| `snapshot.sh` | freezes the docs a candidate may read, from git at a revision, with SHA-256s |
| `TASK-lifecycle.md` | prompt, condition **lifecycle** (docs only, ts library available) |
| `TASK-verifier.md` | prompt, condition **verifier** (SPEC + vectors only, write a verifier) |
| `collect.sh` | copies a lifecycle workspace's `out/` and the mock world's state for grading |
| `grade.mjs` | grades a lifecycle run: 10 points |
| `grade-verifier.mjs` | grades a verifier: N/M bundle cases built from `test-vectors.json` |
| `RESULTS.md` | every measurement so far, and the reporting format |

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

In the public repository only `HEAD` and the public tags exist as revisions: the short hashes these
pages cite (`c261ee8`, `a64d9c1`, …) are private history, so give `snapshot.sh` `HEAD` or a tag.

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

Keep the full transcript of every run (every tool call and its output). It is how the
docs-only rule is audited: a lifecycle transcript that reads `ts/dist/*.js`, or a verifier
transcript that reaches anything but the two files, is **void**, not low-scoring. Record its
SHA-256.

Sandboxing is the runner's job, and the harness cannot enforce it: the workspace holds
compiled JS a model could read, the mock world's state files (`world.local.json`,
`challenge.local.json`) sit where a model could edit them, and nothing here blocks the network.
Run each candidate in a container or VM with no network and only its workspace mounted.

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

Points depend on each other where the protocol does: without a verifying `bundle.json`,
points 3, 4, 5, 7, 8 and 9 cannot pass; a genesis that does not parse sinks most of them. The table names the first failing check for each point.

## The verifier score (grade-verifier.mjs)

Every case is a bundle file, built from `test-vectors.json` the way `go/conformance.go`
builds its checks: the two bundles with a full §9.1 `expect` (compared by value on the six
§9.1 fields; extra per-item fields ignored), each genesis's DID, each attestation and binding
wrapped in a bundle (proof status pinned), the rotation chains, every negative that a bundle
can carry (discarded item, resulting chain, or exit 1), and all `parity` cases. Invoice
vectors cannot enter a bundle and are listed, not scored. Groups: `positive`, `monero`
(§6.2), `negative`, `parity`. At `c261ee8` that is 113 cases; `sigelo-verify` scores 113/113.

The same cases, with the same names and verdicts, are built into the Go binary:
`sigelo-verify --conformance test-vectors.json --impl '<its command>'` (go/README.md,
"Checking another implementation"). It adopts this grader's protocol verbatim and differs
only in being a gate: it exits 1 on any FAIL, where this script always exits 0, and it splices
each case from the vectors file's bytes instead of re-serializing. Keep the two in step: a case
added here goes into `go/cmd/sigelo-verify/impl.go` in the same change (CI diffs their lines).
At cad0357 both count 139 cases (`SCORE 139/139` for the Go binary).

## Reporting

One row per run in RESULTS.md:

| Date | Round | Condition | Model | Family | Snapshot | Score | Time | Transcript | Failing points |
|---|---|---|---|---|---|---|---|---|---|
| YYYY-MM-DD | 3 | lifecycle \| verifier (language) | exact model id | Claude \| GPT \| Gemini \| open-weights | `<short hash>` + condition digest (first 16 hex) | `n/10` or `N/M` (+ per-group) | wall clock, prompt to "done" | SHA-256 of the transcript | point numbers and grader lines |

Several runs per cell; report each, not an average. A CHANGELOG line per round names the
failing steps. A void run (docs-only rule broken) is listed as void with the reason.
