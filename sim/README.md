# sim/ — swarms of agents in a simulated world

Seeded simulations, scripted scenarios, and checks on the checkers. Nothing here is protocol
code. It tests `ts/`, `go/`, `spend/` and `adapters/1f916/` by running them the way many agents
and worlds would, some of them dishonest.

| file | what it does |
|---|---|
| `swarm.mjs` | N agents, M worlds, R rounds. Agents join worlds, migrate, rotate keys, bind Monero wallets, issue invoices, get robbed, fork, recover, and present tampered or fuzzed bundles. Each presentation's expected §9.1 result comes from the simulation's own event model and is compared (as JCS) with what `verify()` returns. A sample of bundles is also run through the Go verifier and compared byte for byte. Every presentation is BYTES read through `parseBytes`, as every real entry point reads them, so raw invalid UTF-8 (tamper and fuzz kind `invalid-utf8`) is exercised; a sim that handed `verify()` JS strings could not hold such a document at all. |
| `worlds.mjs` | Dishonest worlds, and the 1f916 adapter as a world. Worlds sign attestations dated in the future or backdated, ship geneses with an odd or malformed `created` or a small-order key, reuse challenge nonces, attest DIDs they never challenged, sign with a key they rotated away from, claim another world's DID, replay other worlds' attestations and collude in a reputation ring: 36 case kinds, each with the SPEC section that decides it. `adapters/1f916/sigelo.ts` is imported as shipped (`1f916/`) and its four routes' answers, as the router's bytes, go into every agent's bundle. Each bundle is checked against the model (in-process, with and without pinned issuers), each artefact against its SPEC outcome, and each file through `verify-one.mjs` and the Go verifier, which must print the same. |
| `keeper-swarm.mjs` | K agents hammer one real `sigelo-spend serve` against `mock-wallet.mjs`. The keeper is killed and restarted during the run, and its log is checked against the wallet's books. |
| `licence.mjs` | Keys each scratch keeper and makes it a pro customer of a throwaway TEST vendor, offline and the way `spend/soak/gen-keys.mjs licence` and `commercial/issue-licence.mjs` do (sigelo's `attest`, the `{attestation, issuer, rotations}` file, checked with the keeper's own `checkLicence`). It sets `SIGELO_VENDOR_DID` to that vendor and `SIGELO_SPEND_REGISTRY` to a scratch file, so the host's keeper registry is never touched. |
| `keeper-scenarios.mjs` | Scripted, against its own keeper and mock wallet: first with no licence (`/delegate`, `/fund`, `/approve` and a pay above `approval_above` refuse 403 `licence_required`, a pay under the caps is paid), then with one installed under the running keeper; delegates of delegates (depth 4, a revoked middle delegate, caps/rate/allowlist/count/name/revoker refusals) and `policy.json` edited under a running keeper (caps tightened, a root removed and re-added, an approver added, a token rotated with `token new`, a root added, a malformed edit, SIGHUP). 84 steps, each the answer spend/README.md or MONERO.md promises. Where a document says otherwise the step is listed under `doc_divergences` without failing. `--mutants` plants 7 tree bugs in copies of `spend/dist`. |
| `mutants.mjs` | Plants 13 known bugs, one at a time, in a copy of `ts/dist` and checks that `swarm.mjs` or `worlds.mjs` reports each one. A bug that goes unreported marks a blind spot. |
| `1f916/` | `world.mjs` loads the adapter beside four stand-ins for the 1F916 modules it imports (`society`, `keys`, `checkpoint`, `attestations` — its JCS written from RFC 8785, not taken from `ts/`) and serves its routes nested, as since `1dfec57`, or bare (`--plant bare-genesis`). The stand-ins reproduce the adapter test's pinned world DID. |
| `verify-one.mjs` | The ts side of one Go comparison: `node sim/verify-one.mjs <bundle.json> <now>`. Reads the file's bytes (`parseBytes`, fatal UTF-8) and prints what `sigelo-verify` prints, `REJECT: parse: …` included. |

## Run

Build first: `(cd ts && npm ci --ignore-scripts && npx tsc) && (cd spend && npm ci --ignore-scripts && npx tsc)`.
Go must be on the PATH for the Go comparison. Without Go, pass `--no-go`.

```sh
cd sim && npm run sim          # swarm, worlds, keeper-swarm, keeper-scenarios at defaults (about 5 min on the test host: 130 s + 52 s + 118 s + 5 s)
node sim/swarm.mjs             # 300 agents, 6 worlds, 40 rounds (about 2.5 min)
node sim/worlds.mjs            # 40 agents × (1 honest + 9 dishonest) bundles, 36 case kinds (about 1 min)
node sim/keeper-swarm.mjs      # 50 agents, 800 flows, 3 keeper kills (about 2–4 min)
node sim/keeper-scenarios.mjs  # 84 scripted steps, 5 keeper starts (under 10 s)
cd sim && npm run plants       # every planted-bug check below, in a row (about 10 min)
```

The planted-bug checks are separate scripts because they rerun the simulations many times. Each
exits 0 only if every plant was reported:

| script | plants | runs |
|---|---|---|
| `npm run mutants` | 13 bugs in a copy of `ts/dist` (10 for the swarm, 3 aimed at dishonest issuers) | swarm.mjs (120 × 30, no Go) and worlds.mjs (no Go) per bug |
| `npm run worlds-plant` | the 1f916 router serving the genesis bare again (the bug `1dfec57` fixed) | worlds.mjs |
| `npm run keeper-mutants` | 7 bugs in a copy of `spend/dist/tree.js` (clamp, cascade, caps at creation, count, revoker, orphans, names) | keeper-scenarios.mjs per bug |
| `node keeper-swarm.mjs --selftest` | 4 violations planted into the audited log | keeper-swarm.mjs |

`swarm.mjs` settings, as a flag or an env var:

| flag | env | default |
|---|---|---|
| `--seed` | `SIM_SEED` | `sigelo-swarm-1` |
| `--agents` | `SIM_AGENTS` | 300 |
| `--worlds` | `SIM_WORLDS` | 6 |
| `--rounds` | `SIM_ROUNDS` | 40 |
| `--workers` | `SIM_WORKERS` | CPUs − 1, at most 6 |
| `--diff` | `SIM_DIFF` | 0.3, the share of ordinary presentations sent to Go (every tampered, fuzzed, fork and recovery case is always sent) |

Other flags: `--only-agent i` replays one agent's storyline, and `--no-go` skips the Go
comparison. `SIM_TS_DIST` runs against another build of `ts/dist`, and `SIM_OUT` sets the
output directory. `worlds.mjs` takes `--seed` (default `sigelo-worlds-1`), `--agents` (40),
`--cases` (9 per agent, a window rotating over the 36 kinds so each is presented equally
often), `--no-go` and `SIM_TS_DIST` (in-process only). For `keeper-swarm.mjs` and
`keeper-scenarios.mjs` settings, see the headers of those files (`SIM_SPEND_DIST` runs the
scenarios against another build of `spend/dist`; ports ≥ 39000, never the soak's).

**Reproducibility.** Each agent has its own random stream, seeded from (seed, agent index).
Worlds are derived from the seed. The clock is simulated: round r is
`2026-01-01T01:00Z + r days`. A fixed seed therefore gives the same run, whatever the worker
count. The summary's `digest` confirms this: seed `sigelo-swarm-1` gives `e7500c102bd9cbad`
with both 6 and 3 workers. `worlds.mjs` is deterministic too (sim clock, seeded streams,
deterministic Ed25519 and HMAC in the adapter): seed `sigelo-worlds-1` gives `c51d1462e916bac8`.
`keeper-scenarios.mjs` runs its steps one at a time with no chaos, so its outcomes are fixed:
seed `sigelo-keeper-scenarios` gives `7eb54656f87d0085` (the count of payments made during the
policy edits varies with speed and is not in the digest). `keeper-swarm.mjs` fixes its whole
plan from the seed, but race winners and where a kill lands depend on timing (see its header).

**Output** goes to `sim/out/`, which git ignores:

- `swarm-summary.json`: counts per event kind, timings, the Go comparison stats and `digest`
- `swarm-findings.json`: one entry per finding
- `findings/`: the exact bytes behind each finding
- `diff/`: every bundle sent to Go
- `keeper-summary.json`
- `worlds-summary.json` (per case kind: SPEC section, expected outcome, presented, agreeing),
  `worlds-findings.json`, `worlds/diff/` (every bundle, all sent to both verifiers)
- `keeper-scenarios-summary.json` (every step with its expected and observed answer, the
  `doc_divergences` and `observations`), `keeper-mutants.json`, `mutants.json`

Every finding carries a repro command. Both simulations exit with code 1 if they report any
finding.

## What a world does in `swarm.mjs`

Each world has an admission mode (`open`, `invite`, `payment`, `stake`, `captcha`), an
attestation lifetime of 3–60 days, and two trusted peer worlds. Half the worlds know the
other worlds' geneses locally (`knownIssuers`); the other half rely only on `bundle.issuers`.
Admission works like this:

1. The world verifies the presented bundle offline.
2. It applies its rule: `payment` needs a proven stagenet binding; `stake` needs a recovery
   commitment and an attestation from another world; migrating needs an attestation from a
   trusted world.
3. The presenter signs a challenge, which must answer for the current DID.

Thieves act on their own: they present the stolen identity, extend its chain, and sometimes
try to swap the recovery commitment or forge a recovery. Every presentation carries the
public rotations for that identity, the thieves' included, because worlds pass along what they
have seen.

## What a dishonest world does in `worlds.mjs`

Three honest worlds (one of them rotates its own identity on day 60), 1F916 through the adapter,
and worlds that lie. Each agent (0–3 rotations) is admitted at two or three honest worlds by
the §5.2 handshake and at 1F916 through its four routes (whose refusals of another citizen's
nonce, an expired nonce, a prefix DID, a wrong key and a genesis carrying the clock are checked
too), then presents its honest bundle, which must verify with every live attestation, and nine
bundles each carrying one dishonest artefact:

| outcome SPEC gives the artefact | cases |
|---|---|
| **fatal** to the bundle | issuer genesis `created` not a real date or not `Z` (§4), issuer key the identity point with the (R = identity, s = 0) forgery (§2), a challenge in the rotation slot (§5.2, §7.4), the 1f916 genesis served bare (§3.1, §9 step 2) |
| **discarded**, counted in `rejected` | `iat` in the future, `exp` = now, expired backdated (§9 step 5); attested DID never challenged and not in the chain, a truncated DID (§4, §9 step 5); a key rotated out signing under the world's new DID (§5); another world's DID as `iss`, with its real or a forged genesis (§5, §8); replays to another agent, with `sub` or `ctx` edited, or of 1F916's attestation (§9 step 5); issuer genesis omitted (§8); unknown `admission`, `exp` ≤ `iat` (§5.1, §3.1); a challenge in the attestation or binding slot (§5.2); the 1f916 attestation served bare, `now`/`now_utc` beside `body` and `sig` (§3.1: an envelope is exactly its members) |
| **accepted** — SPEC leaves the weighing to the caller | backdated `iat` still live (§7.4: signer-asserted), `iat` = now, a future or epoch `created` (§4: informational), a reused world nonce (§5.2: the world's duty; a verifier never sees a challenge), a DID attested without a challenge, or after it was rotated away from (§1.3, §7.4 SHOULD), an old DID's key still signing under the old DID (§5: issuer chains are not walked), a forged copy of a world's genesis under its own DID (§8), an overstated `admission` (§5.1), the same attestation twice (§9.1: no deduplication) |
| **the ring stays the ring** | three colluding worlds attest a sybil and each other: the three about the sybil verify, the three world-to-world ones do not, nothing is filed under an honest DID, and an honest world admitting migrants only on a trusted world's attestation turns the sybil away |
