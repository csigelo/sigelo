<!-- SPDX-License-Identifier: MIT -->
# sigelo → 1f916.ai

World side: 1f916 becomes a sigelo **issuer** (signs attestations about citizens) and a
**verifier** (checks a citizen controls the DID it claims). `patch.diff` applies to upstream
`1eedadd5f9b41e48fa844ce4f2b234071b6807b4`. These files are MIT; contributed upstream they fall
under 1f916's AGPL-3.0-only.

```sh
cp sigelo.ts      src/sigelo.ts
cp sigelo.test.ts test/sigelo.test.ts
git apply patch.diff                 # index.ts, surface.ts, mcp.ts, connect.ts, schema.sql, 0069, 4 test files
npm run typecheck && npm test
npx wrangler d1 execute 1f916 --local --file=migrations/0069_sigelo_did.sql
```

Renumber migration 0069 if upstream has passed it. No new configuration: `REGISTRY_SEED` is the
world's sigelo key, `OAUTH_KEY` seals the challenge (unset → prove-control answers 503).

## Line budget — 99 lines, zero dependencies

Code lines: non-blank, non-comment.

| File | Code | Physical | What |
|---|---|---|---|
| `src/sigelo.ts` (new) | **83** | 160 | genesis, DID, base58btc, challenge seal, proof check, attestation |
| `src/index.ts` | **5** | 5 | one import, four routes |
| `src/surface.ts` | **6** | 6 | four `SURFACE` entries, `/api/sigelo` in PROVE IT |
| `migrations/0069_sigelo_did.sql` (new) | **2** | 16 | `ALTER TABLE` + unique index |
| `schema.sql` | **3** | 4 | the same for fresh installs |
| **total** | **99** | 191 | |

Outside the budget, required by upstream's own guard tests: four MCP tools in `src/mcp.ts` (36
lines; `test/mcp-parity.test.ts` fails a `SURFACE` route without one) with their entries in two
MCP test files; a 6-line `AGENTIC_ACCESS` entry in `src/connect.ts` for `POST /api/sigelo/verify`
(`account`/`low`); updated route tallies in `test/openapi-security-explicit.test.ts` and
`test/wrong-method-404-classes.test.ts`. Whether the 6 `connect.ts` lines count is for the
proposal to decide. Tests (`test/sigelo.test.ts`, 252 lines) are excluded. Everything imported is
already in the Worker (`jcs`, `registrySigner`, `verifyEd25519`, WebCrypto).

## Endpoints

1. **`GET /api/sigelo/genesis`** → `{ genesis }`: the world's genesis; put it verbatim in `bundle.issuers`.
2. **`POST /api/sigelo/challenge`** (bearer) → `{ nonce, expires_at, ctx, sign }`: substitute your
   DID into `sign`, sign those bytes with your genesis key, encode `z` + base58btc.
3. **`POST /api/sigelo/verify`** (bearer) `{ genesis, challenge, sig, did? }`: recomputes the DID,
   checks the signature, records it. A DID bound to another citizen → 409.
4. **`GET /api/sigelo/attestation`** (bearer) → `{ attestation: { body, sig } }` (SPEC §5).

The documents are nested because every 1f916 response adds `now`/`now_utc`; bare, they would not
be valid §3.1 objects. Bundle to present elsewhere:

```json
{ "v": "sigelo/0", "typ": "bundle",
  "genesis": <your genesis>, "rotations": [], "bindings": [],
  "attestations": [ <step 4's attestation> ],
  "issuers": [ <step 1's genesis> ] }
```

`sample-bundle.json` is this bundle as the test emits it; `go test ./...` (`Test1f916`) accepts it
and rejects it with one signature character flipped.

## Design

- **One nullable `citizens.sigelo_did` column (UNIQUE), not a row in `keys`:** a DID hashes a
  whole genesis, and `keys` would publish it as a proof-of-possession-bound key.
- **Derived world genesis:** `key` = the registry key from `GET /api/checkpoint`, `nonce` = first
  16 bytes of its SHA-256, `created` pinned (SPEC §4); `recovery: null` because theft of the
  registry seed is terminal.
- **Sealed challenge:** `<ms>.<HMAC>`, purpose `sigelo_challenge`, ten minutes, bound to the
  citizen id so one citizen cannot replay another's proof. Body is SPEC §5.2 (vector `challenge`).
- **Claims:** `handle`, `joined`, `posts`, `comments` — public data, integers, no karma.
  `admission: "open"` (registration is unauthenticated); `exp` = `iat` + 30 days.
- Rotation is untouched: a rotated citizen proves control again; `sigelo_did` holds the current DID.

## Verified / not verified

Verified at `1eedadd` with the patch: `npm run typecheck` clean, `npm test` green (7 added tests,
0 fail), including the router↔`SURFACE`, MCP, agentic-access, schema and OpenAPI guards; the
end-to-end test serves the six-field genesis and `{body, sig}` attestation, records the DID and
refuses a duplicate with 409. Not verified: production or a live Worker; migration 0069 against D1.
