# Audit — 2026-09-24, before the first public export

A code audit of the whole repository at the pre-export head, done by the model that
orchestrated most of its construction (Claude Fable 5.1) after the pieces had been written
by other model tiers. It is a self-audit and says so: it stands in for nothing in
ROADMAP §5.4 (external review), and it is published so a reader can see what was checked
and how, not as a certificate.

## Scope and method

Read in full, line by line, against SPEC.md, THREAT-MODEL.md, MONERO.md and CLAUDE.md's
invariants: `ts/src/sigelo.ts`, `ts/src/jcs.ts`, `ts/src/keys.ts`, `ts/src/monero.ts`,
`ts/src/ceremony.ts`, `ts/src/offline.ts`; `go/sigelo.go`, `go/jcs.go`, `go/primitives.go`,
`go/monero.go`, `go/keys.go`; `spend/service.ts`, `spend/policy.ts`, `spend/tree.ts`,
`spend/approval.ts`, `spend/wallet.ts`, `spend/cli.ts`, `spend/canary.ts`;
`adapters/moadim/*.ts`, `adapters/1f916/sigelo.ts`, `examples/world.mjs`,
`integrations/mcp/server.mjs`, `schema/check.mjs`, `release/build.sh`,
`.github/workflows/conformance.yml`. Skimmed: the test suites, `ts/src/gen_vectors.ts`,
`go/conformance.go`, `sim/`. Each property below was checked by reading, and where marked
(exp) by an experiment run against both verifiers on the same bytes.

## Properties checked and held

- **One suite, strict signatures** (SPEC §2, §3). Both verifiers refuse a non-canonical `S`
  (`S + l`), a tweaked `R`, a non-canonical key encoding and a small-order key (exp; the
  Go verifier's own `ed25519Strict` exists because `crypto/ed25519` accepts the first and
  last). Signing input is `"sigelo\n" ‖ JCS(body)` everywhere; `typ` is inside the signed
  bytes and every slot checks it, so no signature moves between slots.
- **Canonicalisation** (SPEC §3). UTF-16 key order, ES6 escape set, integers only, no
  `__proto__`, no duplicate keys, lone surrogates per item. Nesting depth is bounded at 512
  in both parsers and canonicalizers (SPEC §3). This line used to say the parsers were
  iterative and depth could not crash a verifier: true of ts after sim finding S1, not of
  Go, whose recursive parser died of an uncatchable stack overflow near 750 000 levels
  (hostile-JSON differential D1, CHANGELOG).
- **Chain rules** (SPEC §7). Recovery beats voluntary regardless of `iat`; a voluntary
  rotation that changes the commitment is not a candidate; a fork under one key, a cycle
  and a recovery tie REJECT the chain; only a recovery may change the commitment; the thief
  cannot install a recovery key (its hash never matches). Identical in ts and go.
- **Per-item versus fatal** (SPEC §9 step 2, invariant 7). Malformation in what defines
  the identity is fatal; a bad attestation or binding is discarded and counted.
- **Bindings** (SPEC §6). `unproven` without `sig_addr`; `unsupported` for an unknown
  method; a bad proof is a rejection, not a downgrade; integrated addresses and SigV1 are
  refused; a subaddress is checked against its own keys; the network prefix is checked by
  the keeper because the Monero message hash does not cover it.
- **Key derivation** (MONERO.md §2). Paths are literals, identical in ts and go; the root
  must be a canonical scalar so the vault's spend key is the root itself; the 25-word
  codec matches Monero's, checksum enforced; the ceremony writes the root nowhere but the
  age backup; `restore` refuses a fingerprint mismatch; `recover` never prints the recovery
  secret and refuses a derived key equal to the stolen one.
- **The keeper** (MONERO.md §4). Every decision is in a pure function; the token is compared
  by hash in constant time; the account comes from the policy, never the request; amounts
  are BigInt strings and become a number only at the wallet call, bounded to 2^53−1; both
  caps count amount plus fee and are checked again after the wallet has priced the
  transaction; two-phase relay with the intent line fsynced before `relay_tx`; a relay
  failure keeps its debit and answers UNCERTAIN forever; refs are per agent and a repeat
  never builds a second transaction; an approval is one nonce, spent by the intent line
  that uses it, and an approver cannot be the agent, any DID of its chain, any key of its
  chain, or the keeper; tree lines are verified under the keeper key at start; a delegate
  never exceeds its delegator and the count rule bounds whole subtrees; names and account
  indices are never reused; the wallet RPC must be loopback and the service binds loopback;
  no secret (token, seed, spend key) is ever written to the log or a reply except the
  one-time delegate credentials; the lock survives reboots and pid reuse; a torn last log
  line is moved aside and a torn middle line is fatal.
- **The agent side.** The hot key signs a challenge only if `typ` is `challenge`, the field
  set is exact and the DID is its own; it never holds a spend key (`wallet-set` refuses
  every spelling of one); an invoice names only a subaddress this wallet minted; every
  load→save is under one lock; `adopt` refuses a seed that does not produce the genesis key
  and a rotation whose chain does not verify with the new DID at the head.
- **Worlds.** The mock world recomputes the DID from the bytes shown, answers each
  challenge once and never trusts a DID as told. The 1f916 adapter seals its challenge to
  the citizen and verifies over the exact signing input.

## Findings

| ID | Severity | Where | What | Status |
|---|---|---|---|---|
| A1 | low | ts+go verifiers, SPEC §7 | Two byte-identical copies of one voluntary rotation are two candidates: the chain REJECTs as a fork. Consistent in both implementations, but the spec did not say it. No attacker gain (one who can insert a duplicate can insert anything), no CLI produces one. | SPEC sentence added: a bundle MUST NOT carry a rotation twice; verifiers do not deduplicate |
| A2 | low–medium | every ts byte edge | A document containing invalid UTF-8 was rejected whole by Go (RFC 8259 §8.1) but read lossily by ts callers (`readFileSync(…, 'utf8')`, `setEncoding`), which turned the bytes into U+FFFD and discarded only the item whose signature then failed. Same bytes, different verdicts (exp). | `parseBytes()` decodes fatally; used at every file, body and stdin edge; tests in ts, moadim, spend; SPEC §3 states the rule |
| A3 | low | adapters/1f916/sigelo.ts | The world bound a DID after checking only `v`, `typ` and `key` of the genesis; a genesis with an extra field or a malformed `recovery`/`created`/`nonce` was bound though no verifier would ever accept a bundle built on it. | Full §3.1 genesis shape check before binding |
| A4 | medium (process) | release/publish.sh | The export's identity-string gate used `grep -r --binary-files=without-match --exclude…`; on a busybox host (this one) grep rejects those flags and exits 2, and `2>/dev/null` plus `hits=$(…) && [ -n "$hits" ]` read that error as "no hits". The gate never ran: the first export (fd6bf70) shipped with two generic-pattern hits in ROADMAP §5.1 (the literal time-zone offset and home path, in prose about the gate itself) — no private device string, but exactly what CI would have failed on at the first push. Found after the export by running the gate by hand. | Gate is now `git grep` over HEAD (runs the same on GNU, busybox, macOS, Git Bash), exit 0/1/other handled explicitly — any grep failure aborts the export; ROADMAP wording fixed; CI excludes `release/publish.sh` like it excludes its own file; export re-run and the CI check run by hand inside it |
| A5 | low (process) | `.github/workflows/conformance.yml`, `release/publish.sh`, ROADMAP §5.1 | The identity gate kept three "generic" patterns inline in the two tracked files it excluded from its own search — so the first export published exactly the strings it was guarding. ROADMAP §5.1 also described the maintainer's existing infrastructure in words. Found by an independent sweep of the first export that built its own pattern list instead of trusting the gate. | No tracked file holds a pattern: all come from the `DEVICE_STRINGS` secret / private file, the gate refuses an empty list, nothing is excluded; ROADMAP §5.1 reworded; host-specific wording → "the test host" in docs |

## Accepted limits (unchanged, documented where they live)

- Loopback is not an authorisation boundary; `/approve` takes no token and reads the whole
  log per call, so any local process can make the keeper work (spend/README.md).
- An agent that rotates to a fresh key and gets that DID listed in `approvers` is not
  caught by the self-approval check; the Owner's `approvers` list is the boundary
  (approval.ts).
- Two keepers finding one stale lock at the same instant can both start (service.ts).
- `localhost` is accepted as the wallet host and could resolve elsewhere via the hosts file.
- The spend log's spend lines are trusted as written (0600, the keeper's own); only tree
  and approved lines are verified under the keeper key.
- `approval_above` compares the amount without the fee (MONERO.md §4.1).

## Not covered

Everything ROADMAP §1 R8 and §5.4 name: no review by anyone but Claude; no cross-check of
SigV2, base58 or JCS against third-party code; dishonest worlds, delegates of delegates,
live policy edits and the 1f916 adapter were not simulated (sim/REPORT.md). Portability
across operating systems is in PORTABILITY.md.

## T12 third-party cross-check (2026-09-29, at 4e1a5aa)

`crosscheck/run.sh` (README there): sigelo ts and go against code and vectors Claude did not
write — the RFC 8785 author's reference canonicalizers (Python, Go, Node) and testdata,
monero-python 1.1.1, libsodium (PyNaCl), RFC 8032 §7.1 and §6, Wycheproof, ed25519-speccheck.
Counts: JCS 8 testdata cases (6 byte-equal, 2 refused for floats by SPEC §3), 20 000 random
documents, 100 008 integers and 100 000 doubles against ES6 formatting, 1 800 restricted
inputs; Monero base58 10 000 encodes and 20 000 decodes, 5 000 wallets, 2 500 subaddresses,
10 000 valid and 10 000 adversarial addresses, 4 004 + 8 004 25-word seed cases; Ed25519 5 RFC
+ 151 Wycheproof + 12 speccheck vectors, 500 libsodium-signed bodies end to end plus 800
malleations; 12 000 base58btc multibase cases. **0 divergences.** Disagreements with
monero-python were all its own departures from Monero's C++ (a base58 block of exactly 2^64,
a word triple ≥ 2^32 silently truncated, address keys never decoded). Still self-built: the
harness, and the choice of what to compare. SigV2 is not covered (monero-python has none).
