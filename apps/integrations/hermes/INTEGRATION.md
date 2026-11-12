<!-- SPDX-License-Identifier: MIT -->
# sigelo in Hermes Agent: 9 lines of config, zero code

[Hermes Agent](https://github.com/NousResearch/hermes-agent) (Nous Research's agent runtime) is an
MCP client and reads SKILL.md, so sigelo's MCP server and skill plug in unchanged: identity plus
the keeper's four wallet verbs, with no key in the agent.

## Install

1. Build sigelo once (`apps/integrations/README.md`, "Build once"); node ≥ 22.18 on the Hermes host.
2. Add `SIGELO_HOME=/path/to/sigelo` to `~/.hermes/.env`.
3. Merge [`config.yaml`](config.yaml) into `~/.hermes/config.yaml` (or a profile's
   `~/.hermes/profiles/<name>/config.yaml`, with its own identity path). For the wallet,
   uncomment the two `SIGELO_WALLET_*` lines; Hermes passes stdio servers only the env in `env:`.
   Or by script (npm, no checkout):
   ```sh
   printf 'y\n' | hermes mcp add sigelo --command npx \
     --env SIGELO_IDENTITY="$HOME/.hermes/sigelo.local.json" SIGELO_WALLET_URL=… SIGELO_WALLET_TOKEN=… \
     --args -y sigelo-mcp@0.1.15
   ```
   One `--env` takes all pairs (a second replaces the first); `--args` last takes the rest. The
   `y` enables all tools; without it: `Cancelled.`, nothing saved, exit 0.
4. `hermes mcp test sigelo` lists 8 tools (12 with the keeper). Then ask the agent to create its
   sigelo identity (QUICKSTART step 0). Hermes fences every MCP result as
   `<untrusted_tool_result>`: how `claims` should reach a model.

## Slow agents

A CPU-only Hermes may take hours per task: `sigelo_wait_for_message` (10 minutes a call), then
`sigelo_reply` by message id (delivery status). CLI: [WATCH.md](../../agent/WATCH.md#slow-agents).
Codes: `invite --ttl 1h`.

## Test

```sh
HERMES=hermes python3 apps/integrations/hermes/test.py     # stdlib only; HERMES_TEST_HOME reuses a Hermes home
```

Runs unmodified `hermes -z` four times (identity persists): init, the
`accept/examples/world.mjs` challenge → attestation → bundle (re-verified by `go/cmd/sigelo-verify`),
then the wallet verbs on a mock keeper; checks the 12 tools, skill and fencing. The
LLM is a scripted endpoint in the test; the rest is Hermes' code. Not verified: a real model
choosing tools unprompted, Docker, gateway modes, Windows.

## World side

Not built: gating Hermes' A2A inbound peers on a §5.2 challenge plus a verified bundle (a change
to Hermes): [`PROPOSAL.md`](PROPOSAL.md).
Pairing two agents by DID through the Agent Card, as a fixture contract:
[`pairing/`](pairing/README.md).
