<!-- SPDX-License-Identifier: MIT -->
# sigelo in Hermes Agent: 9 lines of config, zero code

[Hermes Agent](https://github.com/NousResearch/hermes-agent) (Nous Research's agent runtime) is an
MCP client and reads SKILL.md, so sigelo's MCP server and skill plug in unchanged: identity plus
the keeper's four wallet verbs, with no key in the agent.

## Install

1. Build sigelo once (`integrations/README.md`, "Build once"); node ≥ 22.18 on the Hermes host.
2. Add `SIGELO_HOME=/path/to/sigelo` to `~/.hermes/.env`.
3. Merge [`config.yaml`](config.yaml) into `~/.hermes/config.yaml` (or a profile's
   `~/.hermes/profiles/<name>/config.yaml`, with its own identity path). For the wallet,
   uncomment the two `SIGELO_WALLET_*` lines; Hermes passes stdio servers only the env in `env:`.
4. `hermes mcp test sigelo` lists 8 tools (12 with the keeper). Then ask the agent to create its
   sigelo identity (QUICKSTART step 0). Hermes fences every MCP result as
   `<untrusted_tool_result>`, which is how `claims` should reach a model.

## Test

```sh
HERMES=hermes python3 adapters/hermes/test.py     # stdlib only; HERMES_TEST_HOME reuses a Hermes home
```

Runs the unmodified `hermes -z` four times (the identity must persist): init, the
`examples/world.mjs` challenge → attestation → bundle (re-verified by `go/cmd/sigelo-verify`),
then balance/receive/pay/history against a mock keeper; checks all 12 tools are offered, the skill
is listed and results are fenced. The LLM is a scripted OpenAI-compatible endpoint inside the
test; everything else is Hermes' code. Not verified: a real model choosing the tools unprompted,
the Docker image, gateway modes, Windows.

## World side

Not built: gating Hermes' A2A inbound peers on a §5.2 challenge plus a verified bundle is a
change to Hermes, drafted in [`PROPOSAL.md`](PROPOSAL.md).
Pairing two agents by DID through the Agent Card, as a fixture contract:
[`pairing/`](pairing/README.md).
