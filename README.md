# sigelo

**Portable identity for AI agents.** An agent builds reputation in one world and carries a
provable identity into the next — with no shared infrastructure between them.

Esperanto *sigelo*: a seal. A seal binds an identity to a document and lets anyone verify it
was not tampered with. That is the whole protocol.

Status: **draft v0.1**, wire format `sigelo/0`. Nothing is stable until v1.0.

**Why an agent would use this:** [`WHY.md`](WHY.md). What you get on day one with no
counterparties, what it gives an agent moving between worlds, an orchestrator running
subagents, a world admitting agents and an operator funding them, how it compares with doing
nothing, a platform API key and ERC-8004 + x402, and what it deliberately does not do. Ends
in a capability card you can paste into your notes.

**Use it from your agent:** [integrations/](integrations/README.md) — MCP server, Claude Code skill/plugin, configs for Codex, OpenCode, Agent Zero, pi, Cursor, Gemini and more.

**Requirements:** Node ≥ 22.18 (22 LTS, 24 or current) and Go ≥ 1.27; optional: `age` (or
`rage`) for the root ceremony, `monero-wallet-rpc` for a keeper. Targets Linux (glibc, musl),
macOS and Windows on x86_64 and arm64. On Windows, file modes such as 0600 are ignored: keep
secret files under your own profile. What is proven on which system:
[`docs-test/PORTABILITY.md`](docs-test/PORTABILITY.md).

---

## Build and test

From a clean clone, in the order CI runs them ([`.github/workflows/conformance.yml`](.github/workflows/conformance.yml)).
`npm ci` installs exactly the committed lockfiles (CI adds `--ignore-scripts`). Each line ends in
`ALL PASS` or the summary shown, and none leaves a tracked or untracked change behind.

```sh
(cd ts && npm ci && npx tsc)                                   # the TypeScript library, built to ts/dist
(cd ts && node dist/gen_vectors.js | diff -u ../test-vectors.json -)   # vectors reproduce byte for byte: diff prints nothing
(cd ts && node dist/test.js)                                   # ts conformance: ALL PASS
(cd adapters/moadim && npm ci && npm test)                     # moadim sidecar, re-verified by go/: ALL PASS
(cd spend && npm ci && npm test)                               # the keeper (needs ts/dist): ALL PASS
(cd integrations/mcp && npm test)                              # MCP server, no dependencies: ALL PASS
(cd go && gofmt -l . && go vet ./... && go test ./... -v)      # reference verifier (gofmt lists nothing): ALL PASS
(cd go && CGO_ENABLED=0 go build ./cmd/sigelo-verify && ./sigelo-verify --conformance ../test-vectors.json)   # the static binary: ALL PASS
node schema/check.mjs                                          # JSON Schemas against the vectors: ALL PASS
release/build.sh /tmp/rel                                      # every artifact from a clean clone of HEAD: 4 npm tarballs, static sigelo-verify (5 targets), SHA256SUMS
release/pack-test.sh /tmp/rel                                  # installs the tarballs where no clone is and runs the T4 acceptance commands: 16 checks (17 without the argument, when it runs build.sh itself)
```

Without `age` on `PATH` the ceremony's real-age check in ts/ SKIPs; without a `monero-wallet-rpc`
on 127.0.0.1:38083 the live-wallet sections of ts/ and spend/ SKIP. Not in CI, and slow: the
seeded swarm simulation, `(cd spend && npm ci && npx tsc) && (cd sim && npm run sim)` after
ts/ is built, about 5–10 min on a small host ([`sim/README.md`](sim/README.md)).

## The problem

Agents are accumulating history in places that did not exist a year ago — forums, loop
runners, agent worlds. That history is trapped where it was made. Move an agent and it
starts from zero, indistinguishable from something spawned five seconds ago for the price of
an API key.

The missing piece is not storage. It is a way for world B to verify that this agent is the
one that built standing in world A, without B trusting A's servers, calling A's API, or A
still existing.

## The approach

Three objects, all signed, all verifiable offline.

**Identity** is a genesis document — a public key plus a commitment to an offline recovery
key. The DID is that document's hash, so nothing in it can be revised after the fact. No
registry, no chain, no resolution step.

**Attestations** are signed statements by a world about an agent. Their content is
world-defined and opaque to sigelo. What is *not* opaque is `admission`: what it cost the
agent to get in — open signup, invite, payment, stake. That is what lets a verifier read "2,000 citizens"
as, say, 1,800 open signups and 200 invite-chained members — a number that means something.

**Bindings** cross-sign an identity against a payment address. Both keys sign identical
bytes, so neither an address claim nor an identity claim stands alone. Identity keys and
spending keys stay separate — an agent that reads untrusted text all day should be able to
prove who it is without being able to move money.

## Why identity and payment are bound, not fused

Money moved is a costly signal that post counts are not. But proving payment history usually
means exposing your position on a transparent chain, permanently and to everybody.

Because the payment address is a *separate object* joined by a proof, an agent can bind a
Monero wallet it can only *see*, not spend: the binding is a view-mode wallet signature,
produced by a view-only wallet. It then hands each counterparty a fresh subaddress, proves
individual payments with Monero's tx and reserve proofs, and, where a relationship warrants
a full view of its history, uses a dedicated wallet derived from the same root seed whose
view key can be shared on its own. The identity stays stable across worlds; the money stays
where the spend key is. Details in [`MONERO.md`](MONERO.md).

Selectively disclosed, unforgeable reputation. Only reachable because the two are bound
rather than fused.

## Recovery

The agent's key is hot by construction; assume it will be stolen. So the genesis commits to
the hash of an offline recovery key at creation.

**A valid recovery rotation supersedes any voluntary rotation, regardless of timestamp.** An
attacker with the stolen key can produce a valid rotation to a key they control. The
operator with the offline recovery key overrides it — even if the attacker rotated first.

This field cannot be retrofitted: a recovery commitment only means anything if it predates
the compromise. Which is why it is in v0.1 rather than v0.2.

## Non-goals

No trust scores. No revocation lists. No discovery. No hosted service. sigelo reports who
signed what and when; weighting is the verifier's job. If every sigelo service vanished,
existing bundles would still verify.

## Status and integration

- [`QUICKSTART.md`](QUICKSTART.md) — the whole lifecycle in seven steps, start here
- [`site/`](site/README.md) — the website for https://sigelo.io, generated from these documents (`node site/build.mjs`, checked by `node site/test/run.mjs`); not deployed yet
- [`SPEC.md`](SPEC.md) — the protocol
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — including what this does *not* defend against
- [`MONERO.md`](MONERO.md) — the payment side: key model, keepers, bounded spending, the root
  ceremony, and §8, which says what is built and how far it has been exercised
- [`test-vectors.json`](test-vectors.json) — real signatures from documented seeds, a full
  bundle with its expected verification result, and negative cases. Conformance target for
  any implementation.

A bundle is self-contained: it carries the genesis of every world that attested, so a
verifier with no prior knowledge of anyone gets the same result as one with all of it.

**For integrators:** `claims` is issuer-written text that will end up in an LLM context.
Treat it as untrusted data, never as instructions.

Implementations and adapters:

- [`ts/`](ts/README.md) — TypeScript, `@noble/ed25519` + `@noble/hashes`, five functions,
  conformance test over the vectors. Also Monero's own primitives for `method: "monero"`
  bindings (`src/monero.ts`), root-seed derivation from one offline 32-byte seed
  carried as a Monero 25-word seed that also restores the Owner's vault wallet (`src/keys.ts`), and the `sigelo-offline` CLI that generates and derives it and runs the
  root ceremony and restore (`src/offline.ts`, `src/ceremony.ts`)
- [`go/`](go/README.md) — the reference verifier: SPEC §9 and the Monero binding check in Go,
  one dependency (`filippo.io/edwards25519`), a static `sigelo-verify` binary. It verifies;
  its one constructive part is `keys.go`, the root-seed derivation, byte-identical to ts/, so
  a Go keeper derives the same keys. The vector generator is `ts/src/gen_vectors.ts`
- [`spend/`](spend/README.md) — the **keeper**: no agent holds a Monero key. `sigelo-spend`
  runs it over one `monero-wallet-rpc`; each agent is an account with its own token, caps,
  allowlist and identity, and asks with `sigelo-wallet` — `balance`, `receive`, `pay`,
  `history`, one plain line each, a retry never pays twice — so weak models can use it.
  Delegation with nested budgets, and approval above an optional threshold. Optional, and
  never on the verify path
- [`adapters/1f916/`](adapters/1f916/INTEGRATION.md) — world side for 1f916.ai: issue
  attestations and verify DID control, 99 lines (plus a 6-line `src/connect.ts` entry that
  upstream's own guard tests require, listed separately), zero new dependencies
- [`adapters/moadim/`](adapters/moadim/INTEGRATION.md) — agent side for moadim: a persistent
  identity for a looped agent, 77 lines, one dependency, no Rust changes. Its Monero half —
  bind a wallet, hand out receive addresses, sign and check invoices — is a further 131 lines
  in a separate file, so an identity-only install still reads 77

Target integration cost for a world is under 100 lines and one dependency. If it is more
than that, file an issue — that is a bug in the design, not in your integration.

MIT.
