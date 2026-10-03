# world/ — sigelo.io's own world

A world that proves control of a DID (SPEC §5.2), issues one `admission: "open"` attestation (§5),
attests self-reported conformance and verifies bundles (§9), also as remote MCP. Not a dependency:
its attestations verify offline against its genesis. Node ≥ 20 and `ts/`.

```sh
node world/test.mjs        # whole flow on loopback, judged by the Go verifier; nginx allowlist: ALL PASS
```

| Endpoint (https://sigelo.io) | |
|---|---|
| `GET /world/challenge?did=…` | §5.2 challenge `{v, typ, did, ctx: "sigelo.io", nonce}`; single use, 5 minutes |
| `POST /world/attest` | `{challenge, did, sig, bundle}` (or `genesis` instead of `bundle`) → `{attestation, issuer}` |
| `POST /world/conformance` | `{challenge, did, sig, bundle \| genesis, implementation, vectors_sha256, results}` → `{attestation, issuer}` |
| `POST /world/verify` | a bundle or `{bundle, now}` → the §9.1 result, or `422 {error: "REJECT: …"}` |
| `POST /mcp` | MCP over Streamable HTTP, one tool `sigelo_verify` |
| `GET /world/stats` | counts: attestations issued, distinct subjects |
| `GET /world/genesis.json`, `/world/rotations.json` | issuer genesis and rotation chain |

Attestation: `claims: {seen: "<date>", bundle_valid, verifier: "sigelo <version>"}`, 90 days.
`bundle_valid` is false when only a genesis came. Same DID within 24 h → same attestation. A
failed answer uses up its nonce. Errors `{error}`: 400 bad input, 409 nonce unknown/expired/used,
413 body over 256 KB, 422 bundle rejected.

Stored: outstanding nonces (`nonces.json`, ring of 2048) and issued attestations
(`attestations.jsonl`, never served). No client addresses reach the service; nginx rate-limits 60
requests a minute (burst 20) per truncated address. No accounts, no cookies. Terms:
https://sigelo.io/privacy.html#terms.

## Deploy

`server-setup.sh --world sha256:<recovery commitment>` after one `deploy.sh`; commit the printed
genesis as `world/genesis.json` (and `rotations.json` = `{"genesis": …, "rotations": []}`), deploy
again. `deploy.sh` ships the code; `/usr/local/sbin/sigelo-world-apply` (the deploy user's one world
sudo rule) copies it root-owned to `/opt/sigelo-world/app`, logs its sha256 and restarts the unit.

## Key safety

The issuer key is hot: `/var/lib/sigelo-world/issuer.json`, 0600, owned by the no-login system user
`sigelo-world` the service runs as; the deploy user cannot read it. Residual risk: a stolen deploy
key can ship code that reads it. Mitigations: deploy only the public export, and `deploy.sh` stops if
the logged sha256 differs from what it staged. A key thief can mint false "seen" attestations under
this DID until rotation, nothing more. The recovery key stays offline with the Owner.

Rotation, from the repository root:

1. Owner: `node world/server.mjs recovery-key new-recovery.key` → prints the new commitment.
2. VPS (root): stop the unit, move `issuer.json` aside, `server-setup.sh --world <new commitment>`.
3. Owner: `node world/server.mjs rotate world/rotations.json world/genesis.json new-genesis.json world-recovery.key > r.json` (OLD recovery key).
4. `mv r.json world/rotations.json`, new genesis → `world/genesis.json`, `new-recovery.key` → `world-recovery.key`; commit, deploy.
5. Verifiers do not walk issuer chains (SPEC §5): announce the new DID; holders re-attest.

## Conformance (self-reported)

Run `sigelo-verify --conformance test-vectors.json --impl '<your verifier>'` over the vectors this
site serves, then post the output with a §5.2 answer: `implementation: {name, version, language,
url?}`, `vectors_sha256` (hex of the file you ran) and `results`. You get ctx
`sigelo.io/conformance`, 90 days:

```json
"claims": { "conformance": { "implementation": "<name> <version>", "vectors": "<sha256>",
  "passed": <N>, "total": <N>, "self_reported": true, "runner": "sigelo-verify 0.1.0" } }
```

The world runs nothing: it checks the vectors hash (else `409` with the current one), that
`results` is a clean run with N equal to the bundle-case count (else `422`), and only then consumes
the challenge. It attests that this DID claimed the result. Same (DID, implementation, vectors)
within 24 h → same attestation.

## Remote MCP

`https://sigelo.io/mcp` (`world/mcp.mjs`, no SDK): Streamable HTTP, revision 2026-07-28 (requests
carrying `_meta["io.modelcontextprotocol/protocolVersion"]`; `server/discover`, `tools/list`,
`tools/call`, `ping`; MCP-Protocol-Version, Mcp-Method and Mcp-Name headers must match the body,
else `400 -32020`) and legacy `initialize` (2025-11-25 … 2024-11-05). Stateless: one
`application/json` response per POST, `202` per notification, no sessions, no SSE, GET/DELETE `405`,
batches `400`, duplicate keys `-32700`, 256 KB limit. Any `Origin`: one pure public tool, so DNS
rebinding gains nothing. The tool is the stdio server's `sigelo_verify` verbatim (plus the item cap
below — the stdio server runs on local, trusted input and has none).

## Abuse

Verification is synchronous Ed25519 (~6 ms per rotation/attestation/binding) on one thread, so a
bundle is capped at **64** items total (over that → refused on `/world/verify`, `/attest`,
`/conformance`, `/mcp`; verify larger ones offline, where there is no cap) and 256 KB: one request
blocks the loop ~0.4 s at most, under the self-check's 10 s timeout even at nginx's `burst=20`.
Accepted residuals: the nginx limit (60 r/m, burst 20) is keyed on the /24 or /48, so an IPv6 /48
buys a fresh bucket (inherent to accountless IP limiting); `attestations.jsonl` is append-only and
`nonces.json` a ring of 2048, so sustained (rate-limited) attestation of fresh DIDs grows disk slowly
and the idempotency map toward `MemoryMax=256M` — the operator rotates the log and watches disk. The
service binds loopback behind nginx (no client address reaches it), 20 s request / 10 s header timeouts.
