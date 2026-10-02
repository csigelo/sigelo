<!-- SPDX-License-Identifier: MIT -->
# sigelo in Hermes Agent: agent side, 9 lines of config, zero code

**Hermes Agent** (`github.com/NousResearch/hermes-agent`, MIT, Python ≥ 3.11) is Nous Research's
self-improving agent runtime: CLI/TUI, a messaging gateway (Telegram, Discord, Slack, …), cron,
subagents, profiles, skills and memory. Launched 2026-02-25; latest release **v0.21.5
(v2026.9.24)**, 2026-09-24; ~250k stars and ~54k forks on 2026-10-02 (github.com, fetched that
day). Not to be confused with Nous's *Hermes* models (function-calling LLMs, not a runtime).

## Why an adapter, and why this small

- **It is an MCP client.** `mcp_servers:` in `~/.hermes/config.yaml` spawns stdio servers and
  registers their tools as `mcp__<server>__<tool>` (`tools/mcp_tool*.py`). Our existing server
  covers identity and the keeper's four wallet verbs, so the adapter is configuration only.
- **It reads SKILL.md.** `skills.external_dirs` loads `integrations/claude-code/skills/sigelo`
  unchanged (agentskills.io format).
- **It has no agent identity.** Its A2A plugin authenticates peers by bearer token and lists
  "DID / Ed25519 identity, OAuth2 scopes, x402 micropayments (#14559)" under *deliberately out of
  scope* (`plugins/platforms/a2a/DESIGN.md`, commit `e9d7a18`, 2026-10-01). Memory and Honcho
  user models persist the *user*, not a provable identity of the agent. Payments exist only as
  third-party plugins/skills that hold or reach a key (MetaMask, Tempo MPP, Stripe Link, EVM,
  Solana); sigelo's keeper gives the agent four verbs and no key.

## Install (agent operator)

1. Build sigelo once (`integrations/README.md`, "Build once"); node ≥ 22.18 on the Hermes host.
2. Add `SIGELO_HOME=/path/to/sigelo` to `~/.hermes/.env`.
3. Merge [`config.yaml`](config.yaml) into `~/.hermes/config.yaml`. Identity lives at
   `~/.hermes/sigelo.local.json`; for one identity per Hermes profile, put the block in
   `~/.hermes/profiles/<name>/config.yaml` with that profile's path. For the wallet, uncomment
   the two `SIGELO_WALLET_*` lines (Hermes passes stdio servers a filtered env, so they must be
   in `env:`).
4. `hermes mcp test sigelo` lists 8 tools (12 with the keeper). Then ask the agent to "create
   your sigelo identity with recovery none" (or the operator's `z6Mk…` / `sha256:` key;
   QUICKSTART step 0), and from then on to answer challenges, store attestations and hand out
   its bundle. Hermes wraps every MCP result in `<untrusted_tool_result>`, which is how
   attestation `claims` should reach a model.

## Test

`HERMES=hermes python3 adapters/hermes/test.py` (stdlib only; `HERMES_TEST_HOME` reuses a Hermes
home to skip first-run setup). It runs the **unmodified `hermes -z`** four times — four
processes, so the identity must persist — with this `config.yaml`: init, then the
`examples/world.mjs` challenge → `sign_challenge` → `attest` → `add_attestation` → `bundle`,
the bundle re-verified by `go/cmd/sigelo-verify`, then balance/receive/pay/history against a
mock keeper; plus: all 12 tools offered to the model, the skill listed by Hermes'
`skills_list`, every result fenced as untrusted. 12 checks.

**What is real and what is not.** No model key exists on the test host, so the LLM is a
scripted OpenAI-compatible endpoint inside the test that emits the tool calls the prompt spells
out. Everything else is Hermes' own code: config load and `${VAR}` interpolation, the MCP
client, tool registry, agent loop, result fencing. Not verified: that a given real model
chooses these tools unprompted (the skill's job), the Docker image and gateway modes, Windows.
Run here 2026-10-02 against commit `e9d7a18` (Python 3.12 venv, Linux aarch64 musl): ALL PASS.

## World side: not built

Hermes does not host worlds that admit agents. The nearest thing is the A2A inbound adapter's
trust gate (`A2A_TRUSTED_PEERS`); gating it on a §5.2 challenge plus a verified bundle is the
1f916 pattern and would close its #14559 item, but it is a change to Hermes, so it is a
proposal for upstream, not part of this adapter.
