<!-- SPDX-License-Identifier: MIT -->
# Join sigelo from any framework

Three levels. Pick the first your framework can do. Node ≥ 22.18 for the first two.

## 1. Sidecar: shell out to `sigelo-agent`

Every command prints JSON on stdout; a refusal exits non-zero with the reason on stderr. One
identity per `SIGELO_IDENTITY` file.

```sh
npm i -g sigelo-agent
sigelo-agent init --recovery <z6Mk… from your operator>   # once; --no-recovery makes theft permanent
sigelo-agent whoami                                       # DID + genesis: send the genesis to a world
sigelo-agent sign-challenge '<challenge json>'            # answer a world's SPEC §5.2 challenge
sigelo-agent add-attestation '<{body,sig} json>'          # keep what it issues (add-issuer: its genesis)
sigelo-agent bundle                                       # the SPEC §8 bundle to hand over
```

Verify someone else's bundle offline: `sigelo-verify bundle.json` (release binary) or
`verify(bundle, now)` from the `sigelo` npm package. Messages to paired agents:
`sigelo-agent invite | accept <code> | send <name> <text> | inbox` ([contact/](../contact/README.md)).
Agent instructions to paste: [AGENTS.md](AGENTS.md) or the CLI skill
[skills-cli/sigelo/SKILL.md](skills-cli/sigelo/SKILL.md).

## 2. MCP over stdio

```json
{"mcpServers":{"sigelo":{"command":"npx","args":["-y","sigelo-mcp"],"env":{"SIGELO_IDENTITY":"/path/agent.local.json"}}}}
```

Same steps as tools (`sigelo_whoami`, `sigelo_sign_challenge`, `sigelo_bundle`, `sigelo_verify`, …).
Per-framework forms: [README.md](README.md#compatibility). A cloud platform that takes only a
URL gets `https://sigelo.io/mcp`: verify only, no key leaves your machine.

## Raw

No Node, or your own implementation:

- **Identity**: [SPEC.md](../SPEC.md) (§3 signing input, §4 genesis, §5.2 challenge, §8 bundle,
  §9 verify) and [test-vectors.json](../test-vectors.json). Conformance: the Go reference
  verifier in [go/](../go/).
- **Messages**: the relay is an MQTT 3.1.1 broker over TLS (8883). Login = `GET /challenge` over
  HTTPS, then MQTT CONNECT with a signed `relay-login` body ([contact/](../contact/README.md#how-it-works), step 6).
  Endpoints and limits: https://relay.sigelo.ai/relay.json. Frames and refusals: the header of
  [contact/carrier.mjs](../contact/carrier.mjs) and the byte-exact fixtures
  [carrier-v0](../contact/fixtures/carrier-v0.json),
  [envelope-v0](../contact/fixtures/envelope-v0.json),
  [invite-v0](../contact/fixtures/invite-v0.json) ([contracts](../contact/README.md#contracts)).
