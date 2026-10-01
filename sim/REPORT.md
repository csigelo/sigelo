# Swarm simulation: report

Run on 2026-09-24 on the test host (8 ARM cores; node 24, go 1.27). Other agents were
committing in parallel, so the machine was under load. The runs used ts at `0860009`, plus
spend and go at HEAD. The dishonest worlds, the 1f916 adapter, delegates of delegates and
policy edits were added on 2026-09-29 (ts, go and spend at `d265b77`); their sections say so.

## What was simulated

### Identity swarm (`node sim/swarm.mjs`, seed `sigelo-swarm-1`, defaults)

| | |
|---|---|
| agents × worlds × rounds | 300 × 6 × 40 (12,000 agent-rounds) |
| offline `verify()` calls, each checked against the model's expected §9.1 result | 7,280 |
| joins / migrations / rotations / binds / invoices | 2,695 / 1,848 / 782 / 718 / 657 |
| admissions granted / denied (owners) | 1,209 + 434 / 759 + 503 (join + migrate) |
| thefts: valid / commitment-swap attempt / forged recovery | 210 / 50 / 30 |
| thief presentations admitted / denied | 270 / 64 (admitting is correct: the verifier cannot tell before a recovery) |
| forks created → presentations rejected as fork | 73 → 438 at the six worlds, plus 350 later joins |
| recoveries (backdated iat / new commitment / with an older sibling) | 316 (168 / 88 / 41) |
| tampered presentations, 40 variants (SPEC §7.4 not-a-candidate vs REJECT, §9 step 2 per-item vs fatal, §6.2 integrated, mainnet and subaddress proofs) | 1,574 |
| blind fuzz presentations (structural plus text-level) | 660 |
| invoices checked per §6.3, and again through `spend/policy.js evaluate()` | 657 (535 via evaluate) |
| bundles sent to the Go verifier (`go/cmd/sigelo-verify`) | 2,713: 1,745 byte-identical results, 968 rejected by both for the same check, **0 differences** |
| longest chain / most rotations in one bundle | 10 / 14 |
| wall-clock (simulation / total including Go) | 127 s / 145 s on 6 workers; 9.5 min of CPU |

### Dishonest worlds and the 1f916 adapter (`node sim/worlds.mjs`, seed `sigelo-worlds-1`, 2026-09-29)

| | |
|---|---|
| agents × bundles | 40 × (1 honest + 9 dishonest) = 400 bundles, all at one instant (day 120) |
| case kinds (each presented 10 times, its SPEC section cited in the source) | 36: 5 fatal, 19 discarded (one a binding), 11 accepted, 1 ring (18 and 12 before W1's fix moved the bare 1f916 attestation to discarded; digest `bec82986f6a36138` then, `c51d1462e916bac8` now) |
| in-process `verify()` calls against the model (no pinned issuers / pinned honest + 1F916) | 800, 0 differences |
| artefact outcome vs the outcome SPEC states for it | 360/360 |
| honest bundles VALID with their 1f916 attestation accepted | 40/40 |
| §5.2 handshakes at honest and dishonest worlds | 134 answered |
| 1F916 adapter: bound / refused another citizen's nonce, an expired nonce, a prefix DID, a wrong-key signature, a genesis carrying the clock | 40 / 40 each; its `sign` string equalled the agent library's §3 signing input 40/40 |
| bundles through `sim/verify-one.mjs` (bytes) and `go/cmd/sigelo-verify` | 400: 350 byte-identical results, 50 rejected by both for the same check (`structure`), **0 differences**; verify-one = in-process 400/400 |
| collusion ring at an honest world that admits migrants on a trusted world's attestation | 10/10 denied |
| wall-clock | 52 s (21 s simulation, the rest spawning the two verifiers 400 times each) |
| `--plant bare-genesis` (the router serving the genesis bare, the bug `1dfec57` fixed) | caught: 671 findings (every bundle carrying the eight-field issuer is fatal in both verifiers where the model expects VALID) |

The adapter runs as shipped: `sim/1f916/world.mjs` copies `adapters/1f916/sigelo.ts` beside four
stand-ins for the 1F916 modules it imports and loads it with node's type stripping. The
stand-in JCS is written from RFC 8785, not taken from `ts/`; with the adapter test's registry
seed the stand-ins reproduce its pinned world DID `did:sigelo:z3BvQcy2…sWGpX`, so the stand-ins
are faithful where the adapter's bytes depend on them.

### Keeper scenarios (`node sim/keeper-scenarios.mjs`, 2026-09-29)

78 scripted steps against one real keeper and the mock wallet, 5 keeper starts, 5 s, 0 findings,
digest `5343dd51be5bedde` on every run; `e9622c852b72a605` since K2's fix (P5 and P6 changed
answers, 0 doc divergences).

- **Delegates of delegates (spend allows them: MONERO.md §4.3).** R1 → d1 → d2 → d3 → d4, each
  funded by its delegator through `/pay`; d4 pays at depth 4, and a fifth level is refused
  (`max_delegates` 0). Refused, each for its own reason (the step checks the error text, so a
  count refusal cannot pass for a cap refusal): a delegate above its delegator's `per_tx_max`,
  above every ancestor's rate, with an address outside the allowlist; a seventh account under a
  root whose subtree reservation is spent (`0 of 3 left`, `0 of 4 left`); an ancestor's, a
  root's and a revoked delegate's name (the only way a cycle could be written: tree lines name
  a parent that already exists, so the tree cannot hold one); revokes by a child of its parent,
  by itself and by another root; `/fund` of a grandchild. Revoking the **middle** delegate d2
  writes one revoke line, kills d2, d3 and d4 at once (401 on `/pay`, `/balance`, `/delegate`),
  sweeps their three accounts one hop to R1 (0 in the wallet's books), leaves d1 paying, frees
  d1's reservation for a new delegate, and a second revoke of d3 by d1 writes no line.
- **Policy edits under a running keeper.** While three agents pay in a loop (33 payments, all
  paid), policy.json is rewritten: R1 tightened from 10 to 2 XMR, R2 removed, approver A2
  added, R4 added, R3's token rotated with the real `sigelo-spend token new`. The documented
  contract — the policy is read at start ("tightens a root in policy.json and restarts"),
  except the tokens of roots already served (since K2's fix), SIGHUP stops the keeper like
  SIGINT/SIGTERM — holds: before a restart R1 still pays 5 XMR, the removed R2 still pays, R3's
  old token is 401 and its new one pays (before the fix: the reverse), R4 is 401, A2's approval
  is `not in approvers`; a malformed edit leaves the running keeper paying; SIGHUP exits 0 and
  removes `spend.lock`; the restart on the malformed file is refused naming the field and leaves
  no lock; after the repaired restart R1 is refused 5 XMR, d1 (created at 6) and d2b (at 5) are
  clamped to 2 at spend and at creation, R2 and its delegate e1 are 401 with the orphan warning,
  R3's new token and R4 pay, A2 approves a request made **before** the restart (the keeper DID
  is stable) and it pays exactly once; R2 re-added on another account refuses the start, on its
  own account it starts.
- **Planted bugs (`--mutants`)**: 7 bugs in copies of `spend/dist/tree.js`, all caught (2 to 40
  findings each, 19 s): no clamp at spend time, a revoke that does not cascade, a delegate
  allowed above its delegator's caps, `max_delegates` per child instead of per subtree, revoke
  by anyone, orphans left live, names reused.

### Checking the checker (`node sim/mutants.mjs`)

This plants one bug at a time in a copy of `ts/dist`. On 2026-09-24 all ten were caught by the
swarm, each producing 12 to 335 findings:

- a fork resolves instead of rejecting
- recovery is ordered by iat
- the commitment is not carried forward
- a recovery tie picks one rotation
- a cycle stops the chain instead of rejecting it
- a malformed item is fatal to the bundle
- expiry is inclusive
- `sub` is not checked
- unproven counts as proven
- an integrated address is accepted

The run took 415 s. On 2026-09-29 three mutants aimed at dishonest issuers were added, and
each mutant now also runs `worlds.mjs`. All 13 were caught (465 s); findings as swarm + worlds:

| mutant | swarm | worlds |
|---|---|---|
| fork-resolved, recovery-by-iat, commitment-not-carried, recovery-tie-picks, cycle-stops, unproven-is-proven, integrated-accepted | 330, 364, 215, 18, 10, 162, 8 | 0 (worlds has no forks, recoveries or bindings) |
| malformed-item-fatal, expiry-inclusive, sub-not-checked | 127, 141, 8 | 80, 20, 106 |
| **future-iat-accepted** (new) | **0** — the swarm's honest worlds never date an attestation ahead | 20 |
| att-sig-unchecked (new) | 15 | 83 |
| issuer-structure-unchecked (new) | 7 | 80 |

`future-iat-accepted` is the blind spot the dishonest worlds close: only `worlds.mjs` kills it.

### Keeper swarm (`node sim/keeper-swarm.mjs`, 50 agents, 800 flows, concurrency 16)

| seed | events | receipts verified | keeper starts | crash retries | findings | wall-clock |
|---|---|---|---|---|---|---|
| `sigelo-sim` | 1,419 | 500 | 6, with 3 mid-run kills (2 SIGKILL, 1 SIGTERM) | 53 | 0 | 116 s |
| `2` | 1,435 | 584 | 6 | 75 | 0 | 175 s |

The run checks every payment against the mock wallet's books:

- per_tx, per_period and rate caps at every instant
- no ref paid twice and no approval used twice
- every receipt verifies against the keeper's DID
- the ledger matches the wallet
- no stuck queue: every request answered within 60 s, and a final probe answered within 5 s

`--selftest` plants four violations, and all four were caught.

## Findings

**S1: fixed in `0860009`.** Deep JSON nesting crashed the ts verifier.

- **What broke:** `ts/src/jcs.ts` `parse` and `canonicalize` were recursive. At about depth
  5,000 they threw `RangeError: Maximum call stack size exceeded`.
- **Impact:**
  - One attestation with deeply nested `claims`, or one bundled binding shaped as a deep
    array, sank the whole bundle in ts with an error that named no check. That breaks
    invariant 7 and the "errors name the failing check" rule.
  - `go/cmd/sigelo-verify` parsed the same bytes and discarded that item per item, so the
    two implementations disagreed.
- **Fix:** both walks now use explicit stacks. Output bytes, error messages and offsets are
  unchanged, and `test-vectors.json` still regenerates byte-identically.
- **Wire format:** no change. ts now accepts exactly what Go already accepted.
- **Regression tests** in `ts/src/test.ts`:
  - a depth-200,000 round-trip
  - a duplicate key under that depth
  - the `bundle` vector with a deep attestation: `rejected.attestations + 1`, same DID
- **Repro on the old code:**
  `SIM_TS_DIST=<copy of ts/dist with the pre-fix jcs.js> node sim/swarm.mjs --agents 120 --rounds 30 --only-agent 57`.
  This gives a `fuzz` finding (`string+deep`) and one Go comparison that differs.
- **Found by:** manual probing of sampled bundles. The fuzz event added afterwards also finds
  it without help.

**K1: FIXED 2026-09-24 (was: observation, left as designed).** A keeper killed in the middle
of a write leaves a half-written last line in `spend.log`. The keeper refused to start and named
the line (`spend.log: line N is not JSON`) until an operator removed it, so every power cut on
the test host was an outage that needed a human, defeating `Restart=always` (the class of soak
incident #1). *Now*: at start, under `spend.lock` and before the log is read, a torn LAST line
(not JSON, while every earlier line is) is moved byte for byte to `spend.log.torn-<unix s>`
beside the log, with one warning naming the file and the byte count, and the keeper starts. A
torn line anywhere else, or a last line that is JSON but not a keeper line, is still refused.
A torn `pay` line cannot have moved money unseen: each line is acted on only after its fsynced
append returns, so a torn `intent` was never relayed, and a torn `relayed`/`relay_failed`
leaves its intent line standing, which still debits and answers a repeat UNCERTAIN (the warning
names the txid to check in the wallet). spend/README.md, "Torn last line". *Checked by*
`spend/test.ts` (K1 cases) and `node sim/keeper-swarm.mjs`: the planted torn tail is moved and
the keeper starts with 0 findings; a planted torn middle line is still refused.

**K2: FIXED 2026-09-29 (was: docs vs behaviour).** *Now*: a running keeper re-reads, on every
request, the `token_hash` of each root it already serves (a changed policy.json is loaded in
full and validated; a file that does not load, or would give two roots one hash, changes no
token and logs one warning); everything else still takes a restart. `token new` says so, and
MONERO.md §6 has the restart for a new root. spend/README "What a running keeper re-reads";
`spend/test.ts` ("tokens live") and keeper-scenarios P5–P7 check it. *Was*: a running keeper
never re-read `policy.json`, which is what the README's nesting rule and INCIDENT.md (a) said
("… and restart the keeper"). Two other places said otherwise:

- `sigelo-spend token new` prints `… token_hash is now sha256:…. The old token no longer
  works.` (spend/cli.ts), and spend/README "Threat notes" says `token new` "rotates a root
  agent's". Under a running keeper the old token keeps spending (200) and the new one is
  refused (401) until the restart — after a leak, the leaked token keeps working for as long as
  the operator believes the message. Reproducer: `node sim/keeper-scenarios.mjs`, steps P5–P6
  and P21–P22 (`doc_divergences` in `sim/out/keeper-scenarios-summary.json`).
- MONERO.md §6 "Procedures", *New root agent*: "the Owner adds an entry to `policy.json` and
  runs `sigelo-spend token new`", no restart; the new root is 401 until one. Steps P7 and P23.

**W1: FIXED 2026-09-29 (was: SPEC ambiguity, reported).** *Now*: SPEC §3.1 says an envelope is
exactly its defined members; any other key discards an attestation or binding (per item) and is
fatal in a rotation envelope, as an unknown body field is (vectors
`attestation_envelope_extra_key_int`, `attestation_good_and_envelope_extra_keys`,
`binding_envelope_extra_key`, `fatal_rotation_envelope_extra_key`); ts and go implement it
identically, and case `1f916-bare-attestation` now expects the bare attestation discarded, by that
rule (its signature still verifies). The moadim sidecar stores only `body` and `sig`. *Was*: SPEC
§3.1 said "Envelopes are part of the same rule" and then named only the members an envelope MUST
carry. Both verifiers accepted an attestation envelope
with extra members (`{body, sig, now, now_utc}`, what 1F916's router would serve bare), so the
1f916 attestation served bare verified in both, identically — no divergence, but the
sentence read as if "no other top-level keys" applied to envelopes too, and a third
implementation could read it that way and reject. INTEGRATION.md calls those members "stray".
Case `1f916-bare-attestation` pinned that behaviour.

**Observations (by design, but worth a line in the docs):**

- *A rotated-out world key keeps minting.* An attestation under a world's **old** DID, signed
  with the key it rotated away from and dated after the rotation, verifies (§5: issuer chains
  are not walked in v0.1). Whoever steals a retired world key can issue until `exp`; only
  verifiers dropping the old DID stop it (case `rotated-out-key-under-old-did`). Now said in
  SPEC §5 and THREAT-MODEL §3.2.
- *Duplicates count twice.* The same attestation twice in one bundle appears twice in the §9.1
  result (no deduplication, §9.1). A caller counting attestations must deduplicate. Now said
  in SPEC §9.1 (kept: deduplicating would be the verifier judging what the presenter sent).
- *A malformed policy edit is not caught until the next start*, which then fails closed: under
  `Restart=always` any crash or SIGHUP after a bad edit is an outage until the file is fixed,
  and nothing but `token new` validates a policy before a restart (step P11).
- *An orphan comes back.* A delegate orphaned by removing its root is revived, with its old
  token, when the root is re-added on the same account (step P30). The README's "until the root
  is restored and revokes it" implies it without saying it.
- *SIGHUP is a stop, not a reload.* Under `Restart=always` that is a restart; under
  `Restart=on-failure` (exit 0) the keeper stays down.

No other differences from the model, from Go, or in the keeper's invariants.

## What this did NOT cover

- **The model mirrors the spec's semantics.** A bug shared by the SPEC reading, `ts` and `go`
  would not show. The mutants show the oracle is sensitive to these ten bug classes, not to
  every possible one.
- **Differential scope:**
  - Go has no `knownIssuers`, so bundles verified at "local" worlds were not compared.
  - Rejections are compared by class (fork, cycle, tie, parse, structure), not by message.
- **Monero:** there was no real wallet or chain. Bindings are view-mode at the base address
  only. There are no spend-mode subaddress bindings from a keeper, and no tx or reserve proofs.
- **Dishonest worlds (since 2026-09-29) are one-shot.** Each dishonest artefact is presented at
  one instant against a verifier with no memory; nothing models a world's lies across time, a
  verifier that stops trusting an issuer, or discounting near a compromise window (§7.4 SHOULD,
  the caller's). Go is compared without pinned issuers only (its CLI has none); the pinned case
  is checked in-process against the model.
- **Keeper gaps:**
  - `/fund` only as a delegator funding its own delegate (and one refusal)
  - no approvers who rotate their key
  - no two keepers sharing one directory
  - no full disk
  - budget windows rolling over mid-run are covered only for the 30-second agents
  - policy edits are scripted, not random, and never land mid-request (the keeper re-reads
    root tokens between requests; a torn file is covered by `spend/test.ts`, not here)
- **Adapters:** the 1f916 adapter runs against stand-ins for its four 1F916 imports, not
  upstream's (unavailable: the repository went private); its SQL runs on an in-memory stand-in,
  not D1. MCP and `integrations/` were not exercised.
- **Real chain:** stagenet is the soak's job (`spend/soak/`), not the simulation's.
- **Scale:** about 300 agents × 40 rounds is modest. There was no memory, time or size
  pressure on the verifier: bundles held at most 14 rotations and 14 attestations.
