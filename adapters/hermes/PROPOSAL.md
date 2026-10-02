<!-- SPDX-License-Identifier: MIT -->
<!-- Draft. Not posted anywhere. -->
<!-- HOW TO POST (Owner):
1. Venue: a Feature Request issue, https://github.com/NousResearch/hermes-agent/issues/new?template=feature_request.yml — Discussions are disabled on the repo (CONTRIBUTING's "GitHub Discussions" line is stale) and there is no RFC directory; a sigelo directory under plugins/ would be closed (CONTRIBUTING: third-party integrations ship as standalone plugins), and the core hook is exactly the "feature request to widen the generic plugin surface" CONTRIBUTING asks for.
2. Title: "[Feature]: pluggable A2A peer authenticator, so a peer can prove a key-based identity instead of holding a bearer token"
3. Labels: the template adds `enhancement`; outsiders cannot set others. Triage will likely add type/feature, comp/plugins, area/auth (what #56434, #80534 and #86061 carry).
4. Template fields: Problem → "Problem or Use Case"; Proposal, What it is not, Smallest step, Open question → "Proposed Solution"; Alternatives: "per-peer tokens (today), asserted headers (#101731)"; Scope: small; tick "I'd like to implement this myself".
5. Attach nothing: link config.yaml and test.py from the public export instead (replace the two https://github.com/csigelo/sigelo links below), and post only from the Owner's account. -->

## Problem

`plugins/platforms/a2a/DESIGN.md` (unchanged since 81c7e5d, 2026-08-02; read at e9d7a18, 2026-10-01) defines a peer as whoever holds a token: "the matched name is the authenticated identity used for rate limiting, the trust gate, message framing, and audit." It defers the alternative: "**DID / Ed25519 identity, OAuth2 scopes, x402 micropayments** (#14559 bindu) — heavy, niche; revisit if there's real demand."

The demand shows up as workarounds. #80534: a shared token "collapses every peer to one identity behind a reverse proxy". #101731 has the sender assert `X-A2A-Identity`, which the receiver cannot check. #56434, #86061 and #125818 build trust tiers on top of names that are only token labels, and #98958 asks for an agent identity layer. A token is a secret shared by two instances; it tells a third nothing about the peer.

## Proposal

The peer proves a key-based DID in one extra round trip. Hermes issues a challenge `{v, typ, did, ctx, nonce}` (sigelo SPEC §5.2: single use, five minutes). The peer replies with `{did, sig}` and its bundle. Hermes verifies offline and mints a short-lived token named after the DID. The existing path then runs unchanged: `a2a.trusted_peers` can list DIDs, and rate limiting, framing and audit key on the DID. The bundle carries attestations signed by services the peer has worked with, so an operator's policy can say "accept peers attested by X" with no registry and no service run by Nous.

```python
# standalone plugin, not core. Both calls exist today: accept/python/sigelo_accept.py
from sigelo_accept import challenge, accept

class SigeloPeers:
    name = "sigelo"
    def challenge(self, did):               # GET  <a2a>/peer-auth/challenge?did=
        return challenge(did, "hermes.example")
    def authenticate(self, body):           # POST <a2a>/peer-auth {challenge, did, sig, bundle}
        r = accept(body["challenge"], body, body["bundle"])  # offline; raises on any failure
        return r["did"] if not REQUIRED or REQUIRED & set(r["attestations"]) else None

def register(ctx):
    ctx.register_a2a_peer_authenticator(SigeloPeers())   # the one new core surface
```

## What it is not

There is no custody, no token or coin, and no network call during verification. If sigelo.io disappears, nothing breaks. The world at sigelo.io/world/ is only a convenience. The code is MIT. The plugin needs `cryptography`, which Hermes already pins, plus one static verifier binary. The agent side runs today as 9 lines of `config.yaml` (MCP server plus `skills.external_dirs`). Unmodified `hermes -z` runs init, a challenge, an attestation and a bundle the Go verifier accepts (12 checks, `main` at e9d7a18, scripted model): [config](https://github.com/csigelo/sigelo/adapters/hermes/config.yaml), [test](https://github.com/csigelo/sigelo/adapters/hermes/test.py).

## Smallest step

Add `ctx.register_a2a_peer_authenticator(provider)`, modelled on `register_dashboard_auth_provider`. When a provider is registered, the adapter serves the two `peer-auth` routes and mints the token. A provider counts as a credential for bind safety, so a remote bind still needs `A2A_HOST`. That is roughly 60 lines in `security.py`, `adapter.py` and `hermes_cli/plugins.py`, plus tests. Without a provider nothing changes. sigelo then ships as its own repo with a catalog entry. I'll write the PR if the hook shape is acceptable.

## Open question

The peer's DID can be taken back with a recovery key that the agent never holds. In your deployment model, who would hold it for a Hermes instance: the operator's machine, the profile, or nobody (`recovery none`, so a lost key means a new DID)?
