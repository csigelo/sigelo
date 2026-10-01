# Comprehension measurements

What fresh agents did with the docs alone, as far as it was measured. Rounds 1–2 were run by
the maintainer's harness outside the repo and recorded only in commit messages and ROADMAP
R3; this file is their first record in the tree. **Every run so far used Claude models.**

| Date | Round | Task | Model | Result | Docs at | Led to |
|---|---|---|---|---|---|---|
| 2026-09-17 | 1 | lifecycle from docs only | Sonnet | **8/10** | before `38e9c76` | `38e9c76` |
| 2026-09-17 | 1 | lifecycle from docs only | Haiku | **6.5/10** | before `38e9c76` | `38e9c76` |
| 2026-09-17 | 1b | the same, after QUICKSTART fixes and `examples/world.mjs` | Haiku | **7/10** | `38e9c76` | its two remaining asks folded into QUICKSTART in `f1aba94` |
| 2026-09-17 | 2 | a verifier from SPEC alone | Opus | **34/34** vectors, first iteration; **12 spec findings** | before `f1aba94` | spec round 2, `f1aba94` |
| 2026-09-23 | keeper | the MONERO.md §4.2 snippet only, `sigelo-wallet` on stagenet | Haiku | accepted (below) | `fdaba3f`..`393b7b4` | recorded in MONERO.md §8 |
| 2026-09-29 | 3 | lifecycle from docs only | Sonnet | **10/10** (artifacts `b9278416cb18388d…`, transcript `9c8c12e479fb9952…`, no forbidden reads) | `9dadab0` (snapshot `ff3639074728bd09…`) | — |
| 2026-09-29 | 3 | lifecycle from docs only | Haiku | **7/10** (artifacts `e27afc796896aebd…`, transcript `01ec4245607ad494…`; FAIL binding discarded — cross-signed correctly but dated `now + 3600`, so §9 step 6 drops it; FAIL stolen `iat` earlier than recovery — it spaced every `iat` like a story and wrote "recovery must be AFTER the stolen one"; FAIL invariants: that binding discarded in both bundles) | `9dadab0` | R3 bar (≥ 9/10 Haiku) not met. Root cause for both: the docs stated "iat is the signing time" and "recovery beats iat" only as permissions in SPEC, with no `bind()` line and no worked case in QUICKSTART → `a795275` (QUICKSTART: the exact `ed25519-test` `bind({… addr_secret, iat: now})`, a Timestamps paragraph, recovery-beats-iat worked at T and T+3600; ts/README API notes). Re-measure at the next round |
| 2026-09-29 | 3 | a verifier from SPEC + vectors alone, **Python** (1 033 lines; PyNaCl, pycryptodome, Edwards arithmetic by hand) | Opus | **139/139** on `grade-verifier.mjs` and **139/139** on `sigelo-verify --conformance --impl`, first iteration; 0 spec findings (it asked whether an object-form parity case with `__proto__` grades as a reject — it does, by the grader's text interface, `grade-verifier.mjs:152`) | `9dadab0` (verifier snapshot `469da8a3c59fe898…`) | Perl (the second foreign language on the host) impossible: no Ed25519 library, no compiler. Non-Claude models: still no API keys |
| 2026-10-01 | site | adopt sigelo from the website alone (`site/test/TASK-site.md`: the served site + the release files, nothing else) | Haiku | **6/6** in 97 s (install from tarballs, SHA256SUMS checked, tier-2 recovery key, attested by the served mock world, bundle accepted by the release `sigelo-verify-linux-arm64`; transcript `48392b8c8c560116…`, no forbidden reads; pages read: `/`, `/adopt`, `/quickstart`, `/spec`, `/examples/world.mjs`) | site at `4bf622b` (tree c2c9cdc release) | the candidate ran the world from a subdirectory, so `site/test/collect.sh` now finds the world state anywhere under the workspace |
| 2026-10-01 | 3b | lifecycle from docs only, after `a795275` (QUICKSTART: the exact `ed25519-test` `bind()` call, a Timestamps paragraph, recovery-beats-`iat` worked) | Haiku | **10/10** (artifacts `b2d1dff2922602fb…`, transcript `ccd508f60726b629…`, no forbidden reads; 24 min) | `9516622` (snapshot `docs-test/snapshot/9516622`) | **R3 bar met at Haiku tier** (≥ 9/10) with Claude models; non-Claude families still unmeasured (API keys) |

**Round 1 findings** (`38e9c76`): `sign-challenge` accepted extra fields (now refused; SPEC
§5.2 says five fields and no others); there was no runnable world side (`examples/world.mjs`
added); four ambiguous QUICKSTART sentences became literal commands.

**Round 2 findings** (`f1aba94`, 12 in all): "REJECT" meant two things (now SPEC §7.4's two
outcomes); required fields were not tabulated (now §3.1, with no unknown keys); signature and
DID encodings were only inferable from examples (now §2); two recoveries tied on `iat` were
unspecified (now REJECT, §7.3); the signing prefix was not given as bytes; §9.1 key order
looked normative; the "not a candidate" negatives lacked complete envelopes and their
resulting chain. The rest were not itemised. Vectors went to 16 positive groups, 18 negatives.

**Keeper acceptance** (MONERO.md §8, 2026-09-23, the G3 "done when"): a Haiku agent given
only the §4.2 snippet, `sigelo-wallet` against a keeper on stagenet. A real `pay` of 0.001 XMR
to contact `bob` → `PAID`, txid
`4289634253c2a94c93a72c8dcda4ddabf44303a9e66ed1bcbb928c2772e8c49c`; the same command again →
`ALREADY PAID`, no second transaction; 0.01 XMR, over its per-payment cap → `REFUSED`;
`receive` → an address; `history` correct; and its own summary of the rules correct.

## What these numbers do not say

- **They are stale.** Rounds 1–2 predate all four wire changes of 2026-09-23: `e658348`
  (§3.1 field types), `ceab548` (per-item forgiveness), `fcb8c54` (point decoding) and
  `c4821e9` (subaddress bindings). The vectors now hold 21 positive entries and 42 negatives;
  34/34 was against far fewer. The keeper run measured the agent surface, not the wire, and
  predates review #2 (`57b57a4`).
- **They are not reproducible.** The prompts, the task scripts, the scoring rubric behind
  "x/10", and the exact docs each agent saw were not kept. The scores cannot be re-derived.
- **One model family.** Claude only, one run per cell. No variance, no other vendor.

## Round 3 needs (ROADMAP R3, T5)

1. A **docs snapshot** frozen at a tag, with the SHA-256 of every file the agent may read
   recorded here beside each result.
2. The **harness checked in** under `docs-test/`: the prompts verbatim, the task script, and a
   scorer that runs the produced code over `test-vectors.json` and names the failing step.
   A score is what the scorer prints, not a judgement.
3. **Three non-Claude families** at the same tiers: one GPT-class, one Gemini-class, one
   open-weights (Qwen or Llama), alongside Claude, several runs per cell.
4. Bar for v0.2: at least 9/10 on the lifecycle at Haiku tier across families, and a
   from-spec verifier passing every vector in two languages the repo does not ship.
5. Results here and a CHANGELOG line per round, failing step named.

## Round 3 harness

Checked in under `docs-test/` (2026-09-23, over `c261ee8`); how to run a round and the exact
rubric are in [`README.md`](README.md). It closes items 1–2 above; items 3–5 need a run.

- **Snapshot:** `snapshot.sh [REV]` copies the allowed files from git at REV into
  `snapshot/<hash>/{lifecycle,verifier}/` with a `MANIFEST.json` of SHA-256s and one digest
  per condition. `--sandbox DIR` adds a runnable lifecycle workspace (the library built from
  REV's `ts/src`, `import('sigelo')` resolving).
- **Prompts:** `TASK-lifecycle.md` (docs-only lifecycle, ten artifacts to named files) and
  `TASK-verifier.md` (a verifier from SPEC + vectors, in a language the repo does not ship,
  with `sigelo-verify`'s CLI).
- **Scorers:** `grade.mjs` (the lifecycle's 10 points, each a mechanical check with the ts
  verifier, the Go reference binary and `schema/`) and `grade-verifier.mjs` (113 bundle cases
  from `test-vectors.json`; 6 invoice vectors are not expressible as bundles and not scored).
  What "x/10" meant in rounds 1–2 was not kept, so round 3's 10 points are a new definition, and
  its scores do not compare with the older ones.

**Harness checks, not datapoints.** An Opus dry run of `TASK-lifecycle.md` (snapshot
`c261ee8`, lifecycle digest `ef9b1c2e16d0a578…`) scored **10/10** in about 20 s of tool time. It
is **not a round-3 result**: the candidate was the harness author and had read `ts/src` and
`go/` before starting. `grade-verifier.mjs` gives `go/cmd/sigelo-verify` **113/113**, the same
binary with §9.1-permitted extra fields 113/113, a stub that accepts everything 1/113, and the
real binary with rejections turned into acceptances 89/113. Thirteen mutated copies of the
dry-run artifacts each lost exactly the points their fault touches (wrong recovery key → 2, 8;
unproven binding → 4; challenge signed with the old key → 6; thief's `iat` earlier → 8; thief
changes the commitment → 8; attestation from a self-made world → 3; wrong reported DID → 10;
extra key in a signed answer → 9; float in a binding envelope → 4, 9; and so on).

## Round 3 — first datapoints (2026-09-23, Claude family only)

Condition: docs-only lifecycle. Snapshot `a64d9c1` (lifecycle digest ef9b1c2e16d0a578…),
grader `a64d9c1`, one run per model, driven by the Claude Code Agent tool with Bash+Read
only and the TASK-lifecycle.md prompt verbatim; no network; transcripts held by the harness
operator (not committed).

| Model | Score | Time | Misses |
|---|---|---|---|
| Claude Sonnet (claude-sonnet-5) | **10/10** | ~3.7 min | none; ran the mock world from `$W` |
| Claude Haiku (claude-haiku-4-5) | **5/10** | ~2.3 min | never ran `examples/world.mjs` (built its own issuer with the library → points 3, 6); wrote `recovery.pub` as a JSON string, not a bare line (→ 2, and 8 by dependency); nonces as `"z"` + hex instead of multibase base58btc (→ 9) |

What Haiku's misses say about the docs, not about Haiku: QUICKSTART must state that the
world is a program to run (`node examples/world.mjs …` from the workspace root) and where it
keeps its state; SPEC §3.1's nonce row ("multibase of raw bytes") needs one line showing how
to make one with the library (`encodeKey`-style multibase, not a hex string after `z`);
"bare string on one line" formats need an example. These fixes land after this round and
the next Haiku run must be scored against a NEW snapshot.

Not comparable with rounds 1–2 (different rubric and task). Non-Claude families: pending
API keys.

## Round 3 — Haiku rerun after the doc fixes (2026-09-24)

Same condition and driver as above. Snapshot `8e971d0` (lifecycle digest 5d555e3db77d9d6b…),
grader `a5cd9f0` (unchanged since `a64d9c1`). The docs changed between the two Haiku runs
(commit `8e971d0`: QUICKSTART says the world is a program to run and where its state lives;
a nonce one-liner; bare-line key example; `world.mjs`'s own nonces made multibase base58btc).
Nothing else changed. The transcript was audited by grep over its tool inputs: Read calls
touched only `SPEC.md`, `QUICKSTART.md`, `examples/world.mjs`, `ts/README.md` and the
candidate's own `lifecycle.mjs`; shell reads only `schema/genesis.json` and `out/`; no
network. Transcript SHA-256 `167e967bcfb2800809610308bb11e3efb3dc892b160e71f811b4b0c5c64827db`
(held by the harness operator).

| Model | Snapshot | Score | Time | Misses |
|---|---|---|---|---|
| Claude Haiku (claude-haiku-4-5) | `8e971d0` | **10/10** | ~2.8 min | none; ran the mock world from `$W`, nonces multibase, `recovery.pub` a bare line |

Read: the 5/10 on `a64d9c1` was a docs failure, not a model floor. One run per cell is a
datapoint, not a distribution; a second Haiku run on `8e971d0` would say whether 10/10 holds.
