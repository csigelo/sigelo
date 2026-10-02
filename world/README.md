# world/ — sigelo.io's own world

The first world that accepts sigelo identities. It proves control of a DID (SPEC §5.2), issues one
`admission: "open"` attestation (§5), attests self-reported conformance and verifies bundles (§9),
also as remote MCP. Not a dependency: if it goes down,
nothing breaks — attestations it issued verify offline against its genesis, which every holder's
bundle already carries (ROADMAP R10). Node ≥ 20, the `sigelo` library in `ts/`, nothing else.

| Endpoint (https://sigelo.io) | |
|---|---|
| `GET /world/challenge?did=…` | a §5.2 challenge `{v, typ, did, ctx: "sigelo.io", nonce}`; single use, 5 minutes |
| `POST /world/attest` | `{challenge, did, sig, bundle}` (or `genesis` instead of `bundle`) → `{attestation, issuer}` |
| `POST /world/conformance` | `{challenge, did, sig, bundle \| genesis, implementation, vectors_sha256, results}` → `{attestation, issuer}` (below) |
| `POST /world/verify` | a bundle (or `{bundle, now}`) → the §9.1 result; `422 {error: "REJECT: …"}` |
| `POST /mcp` | MCP over Streamable HTTP, one tool `sigelo_verify` (below) |
| `GET /world/stats` | counts only: attestations issued, distinct subjects |
| `GET /world/genesis.json`, `/world/rotations.json` | the issuer genesis and its rotation chain (static) |

The attestation: `claims: {seen: "<date>", bundle_valid, verifier: "sigelo <version>"}`, 90 days (SPEC §5 recommends 30–90; an agent re-attests whenever it likes).
`bundle_valid` is true when the answer came with a bundle that verified (its chain's current key
signed); false when only a genesis came. The same DID within 24 h gets the same attestation back.
A failed answer uses up its nonce. Errors are JSON `{error}`: 400 bad input, 409 nonce unknown,
expired or used, 413 body over 256 KB, 422 bundle rejected.

Kept: the outstanding nonces (`nonces.json`, a ring of 2048) and what was issued (`attestations.jsonl`,
append-only, never served). nginx passes no client address to the service; its log is the site's
anonymised one (`/24`, `/48`). Rate limit: 60 requests a minute per truncated address (nginx
`limit_req`, burst 20). No accounts, no cookies.

Run and test: `node world/test.mjs` (the whole flow, the Go verifier as judge, the nginx allowlist).
Install: `server-setup.sh --world sha256:<recovery commitment>` after one `deploy.sh`; then commit the
genesis it prints as `world/genesis.json` (and `rotations.json` = `{"genesis": …, "rotations": []}`)
and deploy again. `deploy.sh` ships `world/` with the site and restarts the unit through
`/usr/local/sbin/sigelo-world-apply`, the deploy user's second sudo rule (copy the code, restart, nothing else).

## Key safety

The issuer key is on the VPS, hot by necessity: `/var/lib/sigelo-world/issuer.json`, owned by the
system user `sigelo-world` (no shell, no ssh, locked password; directory 0700, files 0600), which
is the only user the service runs as. The deploy user `sigelo` cannot read it, nor the nonces or
the issued log. Code: `deploy.sh` ships it to `/var/www/sigelo.io/world-app` (deploy-owned);
`sigelo-world-apply`, the deploy user's one world sudo rule, copies it root-owned to
`/opt/sigelo-world/app`, logs its sha256 to the journal and restarts the unit — nothing else.

Blast radius of a stolen deploy key: it can restart the world and replace its code, and code it
ships runs as `sigelo-world` and can read the key. That is a code-injection path to the key, and it
remains. Mitigation: deploy only from the public export (what runs is public, reviewable code); the
helper logs the installed code's sha256 to a journal the deploy user cannot write, and `deploy.sh`
stops if it differs from what it staged, so a foreign deploy shows up as a hash no public build
produces. Checking that hash against the public commit on the server, before the restart, is not
done (the server would need the commit's build): accepted. A key thief, by either path, can mint
false "seen" attestations under this DID until rotation. It cannot touch anyone's identity, keys or
bundles, and `admission: "open"` claims nothing a thief could inflate. The recovery key never comes
here: it stays offline with the Owner (and in the Owner's encrypted backup), and only its
commitment is in the genesis.

Rotation (theft, or routine), from the repository root:
1. Owner's machine: `node world/server.mjs recovery-key new-recovery.key` → prints the new commitment.
2. VPS (root): stop the unit, move `issuer.json` aside, `server-setup.sh --world <new commitment>`.
3. Owner's machine: `node world/server.mjs rotate world/rotations.json world/genesis.json new-genesis.json world-recovery.key > r.json`, signed with the OLD recovery key.
4. `mv r.json world/rotations.json`, the new genesis → `world/genesis.json`, new-recovery.key → `world-recovery.key`; commit, deploy.
5. Verifiers do not walk issuer chains (SPEC §5): tell them to stop trusting the old DID; holders re-attest.

## Conformance (self-reported)

Run `sigelo-verify --conformance test-vectors.json --impl '<your verifier>'` over the vectors this
site serves, then post what it printed with your agent's §5.2 answer (the same challenge as
`/attest`): `implementation: {name, version, language, url?}`, `vectors_sha256` (lowercase hex of the
`test-vectors.json` you ran) and `results` (the summary lines, or the whole output). The attestation,
ctx `sigelo.io/conformance`, admission `open`, 90 days:

```json
"claims": { "conformance": { "implementation": "<name> <version>", "vectors": "<sha256>",
  "passed": 139, "total": 139, "self_reported": true, "runner": "sigelo-verify 0.1.0" } }
```

**Self-reported** means the world ran nothing: it cannot execute your code. It checks that the
vectors are the ones it ships (else `409` with `vectors_sha256` = the current one), that `results`
parses as a clean run (the runner's own line formats; every group n/n, `N passed, 0 failed`,
`ALL PASS`) and that N is the number of bundle cases those vectors make, counted as
docs-test/grade-verifier.mjs counts them (else `422` with the reason) — and only then takes the
challenge, so a fixable payload does not use it up. It attests that this DID claimed that result,
nothing more; a paste can be fabricated. `runner` names the runner format of the release the world
ships. The same (DID, implementation, vectors) within 24 h gets the same attestation back. One per
DID sits in a holder's store (same issuer + ctx replaces). A paid attestation from a run done by us
is the later product.

## Remote MCP

`https://sigelo.io/mcp` (world/mcp.mjs), hand-written, no SDK: MCP revision 2026-07-28 Streamable
HTTP, dual-era. A request with `_meta["io.modelcontextprotocol/protocolVersion"]` is served as
2026-07-28 (`server/discover`, `tools/list`, `tools/call`, `ping`; the MCP-Protocol-Version,
Mcp-Method and Mcp-Name headers must mirror the body, else `400` HeaderMismatch `-32020`; unknown
version `400 -32022`; unknown method `404 -32601`); one without is legacy (`initialize`
2025-11-25 … 2024-11-05). Stateless: no session ids, no GET stream (GET/DELETE `405`), no SSE —
each request gets one `application/json` response, each notification `202`. One JSON-RPC message per
POST (batches `400`), strict JSON (duplicate keys `-32700`), 256 KB (`413`), the `/world/` rate limit.
Any `Origin` is accepted: public, unauthenticated, no session or user state, one pure tool — DNS
rebinding gains nothing a plain client lacks. The tool is the stdio server's `sigelo_verify`
verbatim (world/test.mjs compares the definitions); no identity, wallet or key is here.
