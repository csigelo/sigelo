# world/ — sigelo.io's own world

The first world that accepts sigelo identities. It proves control of a DID (SPEC §5.2), issues one
`admission: "open"` attestation (§5) and verifies bundles (§9). Not a dependency: if it goes down,
nothing breaks — attestations it issued verify offline against its genesis, which every holder's
bundle already carries (ROADMAP R10). Node ≥ 20, the `sigelo` library in `ts/`, nothing else.

| Endpoint (https://sigelo.io) | |
|---|---|
| `GET /world/challenge?did=…` | a §5.2 challenge `{v, typ, did, ctx: "sigelo.io", nonce}`; single use, 5 minutes |
| `POST /world/attest` | `{challenge, did, sig, bundle}` (or `genesis` instead of `bundle`) → `{attestation, issuer}` |
| `POST /world/verify` | a bundle (or `{bundle, now}`) → the §9.1 result; `422 {error: "REJECT: …"}` |
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

## Next

`POST /world/conformance` (T3 seed): `{implementation, did, sig_over_report, report}` where `report`
is the hash of a `sigelo-verify --impl` summary line, attested as a signed claim. Not built yet.
Remote MCP: see integrations/mcp/README.md.
