<!-- SPDX-License-Identifier: MIT -->
# sigelo peer auth for Hermes A2A

A remote agent proves its sigelo DID once and gets a short-lived Bearer token. Hermes then treats
the DID as the peer name: `a2a.trusted_peers`, rate limiting, framing and audit key on it.
Needs a Hermes with `ctx.register_a2a_peer_authenticator` (not upstream yet). Run from this directory:

## Install

```sh
mkdir -p ~/.hermes/plugins/sigelo-peer-auth
cp plugin.yaml __init__.py sigelo_accept.py ~/.hermes/plugins/sigelo-peer-auth/
(cd ../../../../go && go build -o ~/.local/bin/sigelo-verify ./cmd/sigelo-verify)
```

`~/.hermes/config.yaml`:

```yaml
plugins:
  enabled: [sigelo-peer-auth]      # in-process (the default plugins.isolation)
a2a:
  trusted_peers: ["did:sigelo:z..."]   # who may send tasks; anyone may log in
```
Env (`~/.hermes/.env`):

| var | default | |
|---|---|---|
| `SIGELO_VERIFY` | `sigelo-verify` on PATH | verifier binary |
| `SIGELO_PEER_TOKEN_TTL` | `3600` | token lifetime, seconds |
| `SIGELO_REQUIRED_ATTESTATIONS` | unset | issuer DIDs, comma-separated: accept only peers attested by one of them |
| `SIGELO_PEER_CTX` | host of `A2A_PUBLIC_URL` | **required** (one of the two): this Hermes's public host; the challenge `ctx` is `<it>/<agent slug>`; with neither the challenge route refuses |

## Flow (per served agent; `default` is the root agent)

```
GET  <agent>/peer-auth/challenge?did=did:sigelo:z...   -> {v, typ, did, ctx, nonce}   (5 min, single use)
POST <agent>/peer-auth  {challenge, did, sig, bundle}  -> {identity, token, expires_in}
POST <agent>/  Authorization: Bearer sgl1_...          -> the peer is its DID
```

The peer signs the challenge with `sigelo-agent sign-challenge` (or the MCP tool
`sigelo_sign_challenge`) and sends its bundle (`sigelo-agent bundle`). Before signing, the peer
checks that `ctx` starts with the host it is logging into: a hostile Hermes could otherwise pass on
another Hermes's challenge and log in there as the peer. A token works only on the
agent that minted it. A Bearer without the `sgl1_` prefix is not ours: static tokens still work (so do not give a
static token that prefix). An `sgl1_` token that is unknown, expired or for another agent is a 401. Tokens live in memory: a
restart means a new login.

## What it is not

No custody: Hermes never sees the peer's key. No account, no registry, no service run by sigelo.
No network at verify time: the bundle is checked by the local binary (a `https://` `SIGELO_VERIFY`
is an opt-in remote verifier). Authentication only: authorization stays `a2a.trusted_peers`.

## Test

```sh
python3 test_peer_auth.py          # unit, real identities, no Hermes, sockets off
HERMES_SRC=/path/to/hermes-agent <hermes python> e2e.py   # real adapter + plugin discovery
```

Both need `node` with `ts/dist` built (`SIGELO_TS` overrides) and `sigelo-verify` (built if `go` is there).
