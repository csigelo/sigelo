<!-- SPDX-License-Identifier: MIT -->
# sigelo in Hermes Agent: one command, zero code

[Hermes Agent](https://github.com/NousResearch/hermes-agent) is an
MCP client and reads SKILL.md, so sigelo's MCP server and skill plug in unchanged: identity plus
the keeper's four wallet verbs, no key in the agent.

## Install

CLI: npm `sigelo-agent`; MCP server: `sigelo-mcp`. Node ≥ 22.18 on the
Hermes host. The operator runs:

```sh
printf 'y\n' | hermes mcp add sigelo --command npx \
  --env SIGELO_IDENTITY="$HOME/.hermes/sigelo.local.json" HOME="$HOME" PATH="$PATH" \
  --args sigelo-mcp@0.1.20
```

Hermes passes the server only `--env`: `HOME` and `PATH` let `npx` run. Wallet: add
`SIGELO_WALLET_URL=… SIGELO_WALLET_TOKEN=…` to the same `--env`. Hermes refuses direct `config.yaml`
edits; [`config.yaml`](config.yaml) is the checkout variant.

Hermes bugs, worked around:
- No TTY: "Enable all … tools? [Y/n/select]" prints `Cancelled.`, saves nothing, exits 0: pipe the `y`.
- A second `--env` replaces the first: one `--env A=1 B=2`; `--args` last, it takes the rest.

Then ask the agent to create its identity (QUICKSTART step 0). Hermes fences every MCP result as
`<untrusted_tool_result>`.

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
LLM is a scripted endpoint; the rest is Hermes' code. Not verified: a real model
choosing tools unprompted, Docker, gateway modes, Windows.

## World side

Gating inbound A2A peers on a §5.2 challenge plus a verified bundle: the plugin
[`peer-auth/`](peer-auth/README.md) (the DID becomes the peer name for `a2a.trusted_peers`). It
needs the core hook proposed in [`PROPOSAL.md`](PROPOSAL.md), not in Hermes yet.
Pairing two agents by DID through the Agent Card (a fixture contract):
[`pairing/`](pairing/README.md).

Check: `hermes mcp test sigelo` lists 28 tools (32 with the keeper); `hermes mcp list` shows `sigelo`.
