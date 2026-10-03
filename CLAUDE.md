# sigelo — working context

## What this is

A protocol for portable AI-agent identity. Agents accumulate reputation inside individual
worlds; sigelo lets them carry a provable identity between worlds that share no
infrastructure.

**We are building a protocol, not a platform.** Success is other people's software
implementing the spec. Anything that makes sigelo a service that must be running for the
protocol to work is a design failure.

Read `SPEC.md` before writing code. Read `THREAT-MODEL.md` before changing anything
security-relevant.

## Invariants — do not change without an explicit decision

1. **Offline verification.** No network call is ever required to verify a bundle. If you
   find yourself adding a fetch to the verify path, stop.
2. **Ed25519 + SHA-256 + JCS. One suite.** No algorithm negotiation in v0.1. Agility is a
   downgrade attack surface and we do not need it yet.
3. **No floats in signed objects.** Ever. This is load-bearing for cross-language interop.
4. **Recovery beats key, always.** At any chain node a valid recovery rotation supersedes a
   voluntary one regardless of timestamp. Never reorder by `iat`.
5. **Recovery authority lives in the most recent recovery-signed genesis.** Voluntary
   rotations MUST carry the commitment forward unchanged and are rejected if they don't.
   Only a recovery rotation may change it.
6. **Detached signatures, domain-prefixed.** Signing input is `"sigelo\n" || JCS(body)`.
   The signature is never inside the object it signs. `typ` is always checked against the
   slot the object was presented in.
6a. **Forks are rejected, not resolved.** Two valid voluntary rotations from one node means
   the key was stolen. The verifier does not pick one.
6b. **Two words for two outcomes.** A failing rotation is either "not a candidate" (ignored
   at its node) or it "REJECTs the chain" (fatal); SPEC §7.4 says which. Never a third thing.
6c. **Chains terminate.** A rotation whose `next` is already in the chain is a cycle and
   rejects the chain. Never follow it, never loop.
7. **Fail closed, per item.** Any parse ambiguity (duplicate keys included), unknown version, or
   malformed field is a rejection, not a warning. Malformation in what defines the identity
   (bundle shape, genesis, rotations, issuers) is fatal to the bundle; anything wrong with an
   individual attestation or binding, structural or not, discards that item and counts it.
8. **The verifier reports, it does not judge.** No trust scores, no rankings, no
   "is this issuer good" logic in the core library.

## Explicitly out of scope

Do not add, even if it seems obviously useful: trust scoring, reputation aggregation,
revocation lists, a discovery mechanism, bundle encryption, a hosted resolver as a
dependency, algorithm negotiation, or a plugin system.

Each of these has been considered and deferred. If one seems necessary, that is a
conversation, not a commit.

## Repository layout

```
SPEC.md                     the protocol. Source of truth.
THREAT-MODEL.md             what we defend against and what we do not.
MONERO.md                   payment side: key model, keepers (agents = accounts, delegation,
                            approvals), root ceremony; §8 = what is built and verified.
QUICKSTART.md               the lifecycle in seven steps, against examples/world.mjs
CHANGELOG.md                what changed and why.
test-vectors.json           real signatures from documented seeds. Conformance target.
examples/world.mjs          a mock world in one file: the issuer + verifier side of QUICKSTART
integrations/               harness wrappers: mcp/ (stdio MCP server, zero deps), claude-code/ skill+plugin, per-harness configs
WHY.md                      selling points for an agent reader (roles, scenarios, capability card)
.github/workflows/          CI: vectors must regenerate byte-identically and all must pass
go/                         THE reference verifier; `go test ./... -v` → ALL PASS, static
                            `cmd/sigelo-verify`. Verifies; the only constructive part is keys.go (§2 derivation), so a Go keeper can derive what ts derives.
                            One dep: filippo.io/edwards25519
go/sigelo.go                §9 Verify (→ §9.1 Result), Structure (§3.1 slots), DID, VerifySig
go/jcs.go                   RFC 8785 canonicalizer (UTF-16 key order, ES6 escapes) + strict parser
go/monero.go                §6.2 Monero: Keccak-256, base58, addresses, subaddresses, SigV2, `sig_addr` glue
go/keys.go                  MONERO.md §2 derivation (K, keeper roots, agent identities, wallets, 25 words, vault), = ts byte for byte
go/monero_words.go          the same Monero English wordlist, data only
go/primitives.go            base58btc multibase, Ed25519 verify at @noble zip215:false strictness
go/sigelo_test.go           conformance run over every vector + the 1f916 fixture (Test1f916)
ts/                         TypeScript implementation; `npx tsc && node dist/test.js` → ALL PASS
ts/src/sigelo.ts            the five functions, `structure()` slots and §9 verify
ts/src/jcs.ts               JCS canonicalizer and strict parser; `parseBytes` = fatal UTF-8 decode + `parse`,
                            the entry point for every signed document read as bytes (SPEC §3)
ts/src/gen_vectors.ts       THE vector generator: regenerates test-vectors.json from the seeds
                            (`npm run gen`); the header lists what a port must reproduce
ts/src/monero.ts            Keccak, Monero base58, addresses, subaddresses, SigV2; vectors in ts/test/
ts/src/keys.ts              root-seed derivation (MONERO.md §2 HKDF paths), S as Monero's 25 words, the vault
ts/src/monero-words.ts      the Monero English mnemonic wordlist (1626 words), data only
ts/src/offline.ts           `sigelo-offline new|derive|ceremony|restore` — the root ceremony and restore (CLI)
ts/src/ceremony.ts          the ceremony/restore library: age backup, keeper packages, fingerprint
spend/                      the keeper, MONERO.md §4. See spend/README.md. Bins: `sigelo-spend` (serve,
                            token, approve-request), `sigelo-wallet` (the agent CLI)
spend/policy.ts             policy loader + per-agent checks (pure)
spend/service.ts            loopback HTTP: /pay two-phase relay, agent surface, delegation, /approve
spend/tree.ts               the delegation tree replayed from signed log lines (pure)
spend/approval.ts           the spend-approval object and its checks (pure)
spend/wallet.ts             `sigelo-wallet`: four verbs for weak agents, + delegation verbs
spend/cli.ts                `sigelo-spend`
adapters/1f916/             world side: drop-in src/sigelo.ts + patch for 1f916, docket proposal
adapters/moadim/            agent side: sigelo-agent sidecar CLI for moadim-run agents
adapters/moadim/sigelo-agent-monero.ts   the Monero half, kept out of the identity core
```

CI enforces conformance three ways: `ts/src/gen_vectors.ts` must reproduce `test-vectors.json`
byte-for-byte from the seeds, `ts/` must build and print `ALL PASS` over the vectors, and the
Go reference verifier (`go/`) must pass gofmt and vet, print `ALL PASS` over the same vectors
and `keys.go`'s derivation vectors (including the 1f916 adapter's emitted `sample-bundle.json`, which must be ACCEPTED), build
statically, and reproduce the `bundle` vector's §9.1 result from the binary. It also runs the
moadim adapter's `npm test`, whose Go cross-check must run (Go is installed in that job), and
`spend/`'s `npm test`, whose live-wallet section SKIPs without a `monero-wallet-rpc` on
127.0.0.1:38083 (so does the ceremony's real-`age` section of `ts/` without `age`). The only Python in CI is the thin accept/pairing drop-ins (they shell out to the Go verifier); there is no Python implementation of the protocol.
Do not weaken any check to make a change land. Adding a vector means updating both
implementations' tests in the same change.

## Implementation rules

- **Test vectors are the specification in executable form.** Both implementations must
  reproduce every positive vector byte-for-byte, reproduce the `bundle` vector's §9.1 result as
  JSON, and reject every negative case for the stated reason. The two implementations are
  `ts/` and `go/`. `go/` is the reference verifier: a minimal verifier that passes them; use it
  (or `sigelo-verify`) to sanity-check yours, do not copy it as the implementation.
  Wire this into CI before writing features.
- **Dependencies:** TS gets `@noble/ed25519` and `@noble/hashes` and nothing else. Go gets
  one, `filippo.io/edwards25519`. Adding another dependency to either needs justification.
  No framework, no build step beyond `tsc`.
- **Target ~300 lines per implementation.** If it is growing past that, something out of
  scope has crept in. The rule is about the *core verifier*, and it is under strain:
  `ts/src/sigelo.ts` is 364 code lines and `go/sigelo.go` is 383 (JCS: `ts/src/jcs.ts` 194,
  `go/jcs.go` 423). Method: non-blank lines that are not `//` comments or inside `/* */`
  blocks, measured 2026-09-29 at 5cde1ac. The last step up (358→364, 368→383) is the §3.1
  envelope rule of bcee912 (an envelope has exactly its defined keys); the one before
  (337→358, 355→368) the hostile-JSON differential's S1–S5 field checks (`created`, curve
  points, commitment, nonce format) and the base58 length bound; the JCS growth is the depth
  limit and noncharacter rule. The growth past the target is the §3.1
  field-type enforcement and junk-envelope handling that keep the two verifiers in agreement —
  spec-mandated, not scope creep — but nothing else may land in these two files. Everything
  Monero added lives outside those two files — `ts/src/monero.ts` 190, `ts/src/keys.ts` 123,
  `ts/src/offline.ts` 167, `ts/src/ceremony.ts` 169 (M4: `--human`, `--words`, the import refusal,
  278e87c; keeper recovery, 164b8c4), `go/monero.go` 341, `go/keys.go` 215 (the
  25-word encoding and the vault, measured on the working tree over 57b57a4; the wordlists
  `ts/src/monero-words.ts` and `go/monero_words.go` are data, 128 and 130) — and
  `spend/` is a separate package of 2 711 (`policy.ts` 400, `service.ts` 1 037, `tree.ts` 172,
  `approval.ts` 85, `wallet.ts` 309, `cli.ts` 126, `init.ts` 494, `licence.ts` 84,
  `rpcrange.ts` 4; tests excluded; measured 2026-10-01 at cc0a83c — the step 755→1 037 in
  `service.ts` is incident #4's clock guard, `wallet_offline` and post-relay `store`, the
  `SIGELO_DAEMONS` fallback, the per-request token re-read, the licence gate and the recoverable
  keeper identity (`identity.json`, 164b8c4); `init.ts` is the installer and `licence.ts` the
  offline licence check of 17e7787, both outside the request path). Keep it that way: a world
  that only verifies bundles should never have to read a line of Monero.
- **Public API is five functions:** `keygen`, `attest`, `bind`, `rotate`, `verify`.
  Recovery is `rotate` with `reason: "recovery"` and a recovery key, not a sixth function.
  Two additions are deliberately *not* constructors: `challenge()` is a thin §5.2 helper over
  `sign()`, and a §6.3 `invoice` is a `structure()` slot plus an ordinary `sign()` — adding a
  sixth object did not add a sixth function.
- **Return rich results, not booleans.** `verify(bundle, now)` returns the §9.1 result: current
  DID, chain, governing recovery commitment, accepted attestations grouped by issuer, bindings
  tagged `proven`/`unproven`/`unsupported`, and rejected counts. A caller must not be able to
  ignore that a binding was unproven. `now` is a parameter, never a clock read.
- **Canonicalize properly.** A sorted `JSON.stringify` is not JCS. Key order is by UTF-16 code
  unit; escapes are the ES6 set with lowercase hex. Vector `attestation_unicode` carries the
  exact canonical string to diff against. Parse signed bodies with duplicate-key rejection.
- **Warn on `recovery: null` at keygen.** Loudly. It means theft is terminal.
- **Never automate Monero view-key disclosure.** It is irrevocable and wallet-wide (there is
  no per-subaddress view key). Provide the primitive, make the caller invoke it deliberately.
  Bindings, invoices and proofs are what get automated. MONERO.md is the design.
- **No agent holds a Monero key.** Every wallet sits behind a *keeper* (`spend/`): a
  non-LLM service over one loopback `monero-wallet-rpc`, where each agent is one **account**
  with its own bearer token, caps, allowlist and derived identity (`agentIdentitySeed(K, i, 0)`
  from the keeper root `K` in `spend.key`). Agents ask with four `sigelo-wallet` verbs
  (balance, receive, pay, history); a repeated pay never pays twice (`ref`); delegates nest
  under their delegator and can never exceed it; a second approval is needed only above an
  optional `approval_above`; `POST /bind` signs each agent's own `(i, 0)` in spend mode
  (account 0: view mode at the base address). The request never names an account — keep it
  that way; between agents of one keeper, account pinning is the only boundary. The keeper
  roots, wallets and the root identity come from one `S` via `sigelo-offline ceremony`, which
  leaves `S` only inside an age backup to the Owner. `S` is a Monero 25-word seed; its own
  wallet, the **vault**, is the Owner's cold wallet and is never loaded by a keeper (its spend
  key is `S`). The older `sigelo-agent` Monero half
  (view-only wallet, local view-mode `bind`) remains for the root identity or a relationship
  wallet.

## Style

- No cleverness in the verification path. It should read like the numbered steps in SPEC.md
  §9, in the same order, with the same names.
- Errors name the failing check, not "invalid input".
- Comments explain *why*, especially for the precedence rule, which looks wrong until you
  know what it defends against.
- Commit messages reference the spec section they implement.

## Adoption targets

Two, both open source and both reachable:

- **1f916.ai** — `github.com/1f916-ai/1f916`. Forum for AI agents (~2,500 citizens, 730 with
  bound Ed25519 keys as of 2026-09-17), TypeScript on Cloudflare Workers, AGPL-3.0, maintained
  by an agent that reviews proposals in public. It already has Ed25519, JCS and a signed
  offline dossier (`/api/record/:handle`); it is the **world side** (issuer + verifier).
  Registration is open, so `admission: "open"` is the only honest value; karma is excluded
  from its own attestations by governance and must not leak through ours. Propose on the
  docket first, in the register its SECURITY.md asks for: cite HEAD, say what you ran, name
  files and lines, state what you did not verify. `adapters/1f916/PROPOSAL.md` is the draft.
- **moadim.io** — `github.com/moadim-io/daemon`. Rust loop engine, MIT, single-operator local
  daemon with no member concept and no signing anywhere. Its contribution gates (100 % line
  coverage, 200-line file cap, 83 deny lints) make an upstream Rust PR far over 100 lines,
  so it is the **agent side**: a sidecar CLI giving a moadim-run agent a persistent sigelo
  identity, zero Rust changes. Precedent for identity-on-first-run is `machine::resolve()`.

The adapter for each must be under 100 lines to integrate. That number is the adoption
argument — protect it. It holds today: 1f916 is 99 code lines across its files
(`adapters/1f916/INTEGRATION.md`; since the rebase onto upstream 1eedadd a 6-line
`AGENTIC_ACCESS` entry in `src/connect.ts` is required by upstream's own guard tests and is
listed there separately — decide whether it counts; upstream's GitHub repository went private
in late 2026-09, the patch is verified against public forks), moadim's identity core is 77 — 75 in `sigelo-agent.ts`
plus the 2-line `[env]` hookup (`adapters/moadim/INTEGRATION.md`). The moadim Monero half is
a further 131 lines and is counted separately, in its own file, precisely so an
identity-only install still reads 77.
