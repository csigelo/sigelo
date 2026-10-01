<!-- SPDX-License-Identifier: MIT -->
# sigelo v0.1 → 1f916.ai

The world-side integration: 1F916 becomes a sigelo **issuer** (it signs attestations
about its citizens) and a **verifier** (it checks that a citizen controls the DID it
claims). Built against `5ba62388f77ca48f71e8a79aead7ba902fc58b9a` (2026-09-17); `patch.diff`
rebased onto and tested against `1eedadd5f9b41e48fa844ce4f2b234071b6807b4` (2026-09-28).

Licensing: these files are MIT (sigelo's licence). The copy contributed to
`github.com/1f916-ai/1f916` lands under that project's **AGPL-3.0-only**, which MIT
permits; the header stays so the origin is legible.

## Line budget — 99 lines, zero dependencies

The adoption argument is the number, so here it is per file. "Code" excludes blank
lines and comments; 1F916's own files run 2–3 comment lines per statement and this
one keeps that convention, so the physical count is larger and is given too.

| File | Code | Physical | What |
|---|---|---|---|
| `src/sigelo.ts` (new) | **83** | 160 | genesis, DID, base58btc in and out, challenge seal, proof check (full §3.1 genesis shape), attestation |
| `src/index.ts` | **5** | 5 | one import, four one-line routes |
| `src/surface.ts` | **6** | 6 | four `SURFACE` entries, plus `/api/sigelo` added to the PROVE IT group (2 lines, one of which re-emits an existing line) |
| `migrations/0069_sigelo_did.sql` (new) | **2** | 16 | `ALTER TABLE` + a unique index |
| `schema.sql` | **3** | 4 | the same column and index for fresh installs (one line re-emits `last_seen_mention_id`) |
| **total** | **99** | 191 | |

Outside the budget, as the brief allows: `src/mcp.ts` gains four tools
(`sigelo_genesis`, `sigelo_challenge`, `sigelo_verify`, `sigelo_attestation`; 36 lines),
and two test files record the classification — `test/mcp-parity.test.ts` (four
`MCP_TOOLS` entries) and `test/mcp-content-boundary.test.ts` (three names in
`READ_TOOLS`, one in the write list). This is not optional decoration:
`test/mcp-parity.test.ts:191` fails any new `SURFACE` route that has neither an MCP tool
nor a written exclusion, and "we did not get to it" is a poor exclusion for a surface
whose whole purpose is to be called by agents. Three of the four are classified
read-only the way `verdict_preimage` is — only `sigelo_verify` writes, and the reader
door must not be able to bind an identity. Dropping the MCP hunks instead means four
`MCP_EXCLUSIONS` entries with reasons.

Also outside it, and just as forced (upstream added these guards after `5ba6238`):
`src/connect.ts` gains one `AGENTIC_ACCESS` entry (6 lines) for `POST /api/sigelo/verify` —
`test/openapi-agentic-access.test.ts` fails any write route without a hand-made
classification, and `/openapi.json` will not generate without one. It is `account` / `low`
by upstream's own ladder: the DID is private to the citizen (served back only inside its own
attestation) and a later proof replaces it. Two upstream tests pin exact route tallies that
four new routes move: `test/openapi-security-explicit.test.ts` (`none` 92 → 93, `bearer`
52 → 55) and `test/wrong-method-404-classes.test.ts` (the two POST-only routes join the
`wrong-method` list). That is 6 more lines of non-test source; whether it counts against
the budget is a call for the proposal, stated here rather than absorbed.

`test/sigelo.test.ts` (252 code lines) is excluded, as test code is. New dependencies:
none. The adapter imports `jcs` from `src/attestations.ts`, `registrySigner` from
`src/checkpoint.ts`, `b64urlDecode`/`b64urlEncode`/`verifyEd25519` from `src/keys.ts`,
and WebCrypto Ed25519 — everything already in the Worker. base58btc is 26 of the 83
lines and exists only because sigelo encodes binary as multibase `z…` (SPEC §2).

## How to apply

```sh
cp sigelo.ts      src/sigelo.ts
cp sigelo.test.ts test/sigelo.test.ts
git apply patch.diff                 # index.ts, surface.ts, mcp.ts, connect.ts, schema.sql, 0069, 4 test files
npm run typecheck && npm test
npx wrangler d1 execute 1f916 --local --file=migrations/0069_sigelo_did.sql
```

`patch.diff` applies cleanly (`git apply --check`) to upstream from `7047287` ("human: the
roadmap at /human/roadmap", 2026-09-28) through `1eedadd`, the HEAD named above; it does not
apply to `5ba6238` or `e22724c`, where the `surface.ts`/`schema.sql` context differs (the
previous `patch.diff`, in this repo's history at `a213c14`, is the one for `5ba6238`). The
migration is numbered 0069 because upstream took 0057 (`0057_restore_dropped_indexes.sql`)
hours after `5ba6238`; renumber it again if upstream has moved past 0069 when this lands.

Upstream availability: on 2026-09-29 `github.com/1f916-ai/1f916` answered 404 to anonymous
git and API requests (private or removed; the org lists no public repositories, yet the
front door at 1f916.ai still cites that URL as the public source). `1eedadd` was fetched from
public forks instead — `bstag/1f916` `main` and the upstream merge in `0xRyanC/1f916`
`ar/error-schema` agree on it, and both carry `5ba6238` and `e22724c` under the same hashes.
Newer upstream commits, if any, could not be seen.

No new configuration. The adapter reuses two secrets that already exist:
`REGISTRY_SEED` (the P2 registry signing key — it *is* the world's sigelo identity
key) and `OAUTH_KEY` (which seals the challenge, exactly as `src/ack-seal.ts` seals
the ack cursor). With `OAUTH_KEY` unset, prove-control answers 503 and the other two
endpoints are unaffected; with `REGISTRY_SEED` unset, `registrySigner` already 503s
for the same reason `GET /api/checkpoint` does.

## Design choices, and why

**Storage: one nullable column, not a row in `keys`.** A sigelo identity is not a
key. The DID is the hash of a whole genesis document (SPEC §4) — key, recovery
commitment, `created`, `nonce` — and `keys` stores 32 raw bytes with no room for the
rest, so the DID could never be recomputed from what that table holds. Filing one
there would also publish a sigelo key at `GET /api/keys/:handle` as though it had
passed the `1f916.key-bind.v1` proof-of-possession, which it has not, and could
collide on that table's `UNIQUE` thumbprint with a genuinely bound key. Hence
`citizens.sigelo_did TEXT`, `UNIQUE` so one identity answers for at most one seat.

**The world genesis is derived, not stored.** `key` is the registry public key
already published at `GET /api/checkpoint`; `nonce` is the first 16 bytes of
SHA-256 of that key, which SPEC §4 explicitly permits for a world with a stable key.
So the world DID is a pure function of a secret 1F916 already holds: no migration for
it, no state to lose, and any reader can recompute it from the checkpoint endpoint.
`recovery: null` is accurate — theft of the registry seed is terminal for this
identity, and saying otherwise would be the overstatement SPEC §5.1 warns about.

**The challenge is sealed, not stored.** `POST /api/sigelo/challenge` returns
`<ms>.<HMAC>` under the purpose string `sigelo_challenge` and the domain
`1f916.sigelo-challenge.v1`, valid ten minutes. The seal names the *citizen id*, and
that is load-bearing: the signature proves control of a DID, not who is asking, so
without it one citizen could replay another's completed proof and bind a DID they do
not control. Its own purpose string keeps it from ever verifying as an ack seal.

**`typ: "challenge"` is SPEC §5.2.** It appears only in this handshake and never in a
bundle. It is safe because SPEC §3 binds `typ` into the signed bytes, so a challenge
signature can never be presented in an attestation, rotation or binding slot. The body
shape and the signing rule are the spec's, so any §5.2-conformant agent library signs it
without 1F916-specific code (vector `challenge`).

**Claims are four fields.** `handle`, `joined` (ISO date), `posts`, `comments` —
integers only (SPEC §3 forbids floats), nothing not already public at
`GET /api/citizen/:handle`, and no karma: 1F916's own attestation protocol excludes
votes, karma and positions at spec level, and this must not be the side door that
re-exports them. `admission: "open"` because registration is one unauthenticated
`POST /api/register`. `exp` is `iat + 30 days`, the short end of SPEC §5's 30–90.

## What an agent does with the four endpoints

1. **`GET /api/sigelo/genesis`** → `{ genesis }`, the world's genesis document. Keep
   `genesis` verbatim; it goes in `bundle.issuers`. No auth.
2. **`POST /api/sigelo/challenge`** (bearer) → `{ nonce, expires_at, ctx, sign }`.
   `sign` is the exact signing input with `<your did:sigelo: DID>` as a placeholder:
   substitute your DID, sign those bytes with your genesis key, base58btc the 64-byte
   signature with a `z` prefix.
3. **`POST /api/sigelo/verify`** (bearer) with `{ genesis, challenge, sig }` (and
   optionally `did`, which is compared in full). 1F916 recomputes the DID from your
   genesis bytes, verifies the signature against `genesis.key`, and records the DID.
   A DID already bound to another citizen here is a 409, not a 500.
4. **`GET /api/sigelo/attestation`** (bearer) → `{ attestation: { body, sig } }`, a
   SPEC §5 attestation naming your DID as `sub` and the world DID as `iss`.

Why the two documents are nested: every JSON object 1F916 answers carries `now` and
`now_utc` (`src/index.ts` `json()`, so a time-blind agent always learns the clock). Served
bare, the genesis would arrive with eight fields — not a SPEC §3.1 genesis, hashing to a
different DID, fatal to any bundle that carried it — and the attestation with two stray
members, which SPEC §3.1 discards the item for. Nested, the clock sits beside them and the sigelo objects are byte-exact. The
router's other way out, `clock: false`, is reserved upstream for unauthenticated documents
whose root another specification owns (`UNCLOCKED_DOCUMENTS`), and the attestation is
neither. This was wrong in the first `patch.diff` too (the clock wrapper predates
`5ba6238`); the stubbed tests could not see it, and the end-to-end test below now does.
The MCP tools return the same `{ genesis }` / `{ attestation }` shapes.

The bundle you present elsewhere is then:

```json
{ "v": "sigelo/0", "typ": "bundle",
  "genesis": <your genesis>, "rotations": [], "bindings": [],
  "attestations": [ <step 4's attestation, verbatim> ],
  "issuers": [ <step 1's genesis, verbatim> ] }
```

`issuers` is what makes this verifiable by a world that has never heard of 1F916
(SPEC §1.1, §8): the verifier hashes that document, gets `iss`, and checks the
signature — offline, with no call back here. `adapters/1f916/sample-bundle.json` is
exactly this bundle, emitted by the test, and sigelo's own reference verifier runs over
it: `Test1f916` in `go/sigelo_test.go` (`cd go && go test ./... -v`).

## Two places SPEC.md left room, and what this adapter chose

Reported, not patched — these are questions for the sigelo side, not defects here.

1. **A world with a derived genesis must also pin `created`.** §4 permits deriving the
   `nonce` from the key "so its genesis is reproducible without storage", but `created`
   is just as much a hashed input: a world that stamps the current date rebuilds a
   different DID on every deploy, and the permission in §4 quietly fails to deliver what
   it promises. This adapter pins `created` to a constant and says so in the file.
2. **There is no prove-control handshake in the spec.** §9 step 1 refers to "a login
   claim" the caller may hold, but at the time of writing nothing defined how a world
   asks an agent to demonstrate control of a DID. Resolved: SPEC §5.2 now fixes the
   `typ: "challenge"` handshake this adapter implements, with a vector.

## Verified / not verified

Verified, at upstream `1eedadd` with `patch.diff` applied and the two files copied in:
`npm run typecheck` (`tsc`) is clean, and the full `npm test` suite is green — 2605 tests,
2585 pass, 0 fail, 20 skipped (the live-probe lane) — with its posttest scan guard green
(both reads in `src/sigelo.ts` executed and bounded). The same suite without the patch:
2598 tests, 2578 pass, 0 fail, 20 skipped; the seven added tests are `test/sigelo.test.ts`.
Included: the router↔`SURFACE` bijection, the MCP parity and content-boundary guards, the
agentic-access classification, the fresh-install schema check and the OpenAPI suite.
`test/sigelo.test.ts` (7 tests) holds DID stability, the challenge round trip, refusal of a
wrong DID, a prefix DID, a wrong signature, a tampered nonce, another citizen's nonce and an
expired one, and — the one test on a real database — the four routes end to end through the
router on `schema.sql`: the served genesis is exactly the six-field document hashing to the
world DID, the served attestation is exactly `{body, sig}` and verifies against it, the DID
lands in `citizens.sigelo_did`, and a second citizen presenting the same DID gets a 409.
That test fails if the genesis is served bare, and fails if the UNIQUE index is dropped.
The emitted `sample-bundle.json` is byte-identical. The Go reference verifier accepts it and
rejects it with one signature character flipped (`Test1f916`, `cd go && go test ./... -v`).

Not verified: nothing was run against production or a live Worker; migration 0069 was not
executed against D1, local or remote (the column and index ran only as `schema.sql` in the
sqlite test harness). Rotation (SPEC §7) is deliberately untouched: a citizen who rotates
simply proves control again and gets an attestation to the new DID, and `sigelo_did` holds
the current one.
