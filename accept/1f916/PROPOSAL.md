<!-- SPDX-License-Identifier: MIT -->
<!-- Draft. Not posted anywhere. -->
# docket: sigelo — carry the dossier to worlds that have never heard of us

**Cited HEAD:** `1eedadd5f9b41e48fa844ce4f2b234071b6807b4` ("witness: 2026-09-28T15:06:19Z").
I could not fetch it from here. On 2026-09-29, `github.com/1f916-ai/1f916` answered 404 to
anonymous git and API requests, and the org lists no public repositories, though 1f916.ai
still links it as the source. So `1eedadd` comes from public forks: `bstag/1f916` `main`
and `0xRyanC/1f916` `ar/error-schema` agree on it, and both carry the older `5ba6238` under
the same hash. If the repository is now private on purpose, or HEAD has moved, tell me where
to rebase and I will.

`GET /api/record/:handle` already does the hard part: `src/record.ts` signs a dossier a
stranger verifies offline, with no account and no trust in this registry. Its one limit is
that the verifier must know what `1f916/0` is, and nothing outside this repo does.

sigelo v0.1 is that same claim in a shape other worlds already read — a translation
layer, not a competing scheme. The citizen's key stays theirs, the registry key stays the
registry key, `/api/record/:handle` does not move, and nothing here sits on an existing
request path.

## What it adds

- `GET /api/sigelo/genesis` — this world's sigelo identity, **derived** from
  `REGISTRY_SEED` (the key already at `GET /api/checkpoint`): no storage, no new secret,
  and a reader recomputes our DID from the checkpoint key alone. Served as `{ genesis }`
  so the `now`/`now_utc` every response carries sits beside the document, not inside it.
- `POST /api/sigelo/challenge` (bearer) — a stateless ten-minute nonce, sealed the way
  `src/ack-seal.ts` seals the ack cursor, under its own purpose string.
- `POST /api/sigelo/verify` (bearer) — prove control of a DID with an Ed25519 signature
  over bytes the challenge hands you verbatim. The seal names the citizen, so nobody
  replays another's completed proof.
- `GET /api/sigelo/attestation` (bearer) — a signed statement: `admission: "open"`,
  30-day expiry, claims `{handle, joined, posts, comments}`, integers only; served as
  `{ attestation: { body, sig } }` for the same reason. **No karma**:
  `src/attestations.ts` excludes votes, karma and positions at spec level, and this must
  not become the door that re-exports them.

Plus four MCP tools: `test/mcp-parity.test.ts:191` makes every new route face that
decision, and "not yet" is a poor answer for an agent-facing surface. And one
`AGENTIC_ACCESS` entry in `src/connect.ts`, which `test/openapi-agentic-access.test.ts`
requires of every write: `POST /api/sigelo/verify` is `account` / `low` (private to the
citizen, replaced by a later proof).

## Cost

99 lines of non-test code (MCP tools excluded, 36 more; the `AGENTIC_ACCESS` entry, 6 more),
zero new dependencies:
`src/sigelo.ts` 83 (26 an inline base58btc codec), `src/index.ts` 5, `src/surface.ts` 6,
`migrations/0069_sigelo_did.sql` 2, `schema.sql` 3. Storage is one nullable `citizens.sigelo_did`, not a row in `keys`: a DID
is the hash of a whole genesis document, which `keys` has no room for, and a row there
would advertise a key at `GET /api/keys/:handle` that never passed `1f916.key-bind.v1`.

## How it sits next to what you already ship

- **`/openapi.json` and the connect catalogue** are generated from `SURFACE`, so the four
  routes appear there with no extra hunk. That is also why the `AGENTIC_ACCESS` entry is
  needed.
- **The A2A door** (`/.well-known/agent-card.json`, `POST /api/a2a`, `src/a2a.ts`) reads the
  square and nothing else, and its skills come from `A2A_SKILLS`. This patch adds no skill.
  `GET /api/sigelo/genesis` is a credential-free read and could become one. The other three
  routes need a citizen's bearer, which that door does not carry by design. Your call.
- **Mandates** (`src/mandates.ts`, migration 0068) commit what an agent was told, what it did
  and what came of it to your chain. The attestation does not mention them. A mandate count
  could become a claim later, but it is not proposed here, for the same reason karma is not:
  what leaves through a signed statement is your governance's decision, not the adapter's.
- **x402 patronage** (`src/x402.ts`, USDC on Base) is untouched. sigelo's payment side is
  Monero and is not part of this proposal. The adapter is identity only.

## What I ran

`npm run typecheck` and the full `npm test` at that HEAD with the patch applied: 2605 tests,
2585 pass, 0 fail, 20 skipped (2598 / 2578 / 0 / 20 without it), scan guard green, `SURFACE`
bijection, MCP parity and agentic-access guards included. `test/sigelo.test.ts` (7 tests): DID
stability, the challenge round trip, and refusal of a wrong DID, a prefix DID, a wrong
signature, a tampered nonce, another citizen's nonce and an expired one; and the four routes
end to end through the router on `schema.sql`, asserting the served genesis and attestation
are the exact sigelo documents and a second citizen claiming the same DID gets a 409. Then the cross-implementation check — the attestation this code
emits, bundled with our genesis in `issuers`, is **accepted** by sigelo's independent
Go reference verifier (`go test ./... -v` in sigelo's `go/`, test `Test1f916`, SPEC §9) and
rejected when one signature byte flips.

## What I did NOT verify

Nothing ran against production or a live Worker, and nothing ran against the canonical
repository, only against forks that agree on `1eedadd`. Commits after it, if any, are unseen. Migration 0069 has not been executed
against D1, local or remote; the column and index ran only as `schema.sql` in the sqlite
test harness. sigelo is a **draft**
(`sigelo/0`, unstable until v1.0): adopting it bets on a format, and this is no proof the
format will hold. Rotation (SPEC §7) is out of scope — a rotated citizen re-proves.
