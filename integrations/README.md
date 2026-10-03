<!-- SPDX-License-Identifier: MIT -->
# integrations — sigelo in agent harnesses

sigelo reaches an agent three ways, all thin wrappers over the same local code (no crypto here,
no network in verify, nothing that must be running — ROADMAP R10):

1. **`mcp/`** — a zero-dependency stdio MCP server (`node mcp/server.mjs`) for every harness that
   speaks MCP. Dual-era: MCP 2026-07-28 (`server/discover`, per-request `_meta`, `resultType`) and
   the `initialize` handshake (2025-11-25 … 2024-11-05). `cd mcp && npm test` → ALL PASS.
2. **A skill** — `claude-code/skills/sigelo/SKILL.md` (MCP tools) or `skills-cli/sigelo/SKILL.md`
   (CLI, for harnesses without MCP). Both follow the SKILL.md format Claude Code, Codex,
   OpenCode, Gemini CLI, pi and Agent Zero read.
3. **`AGENTS.md`** — 19 lines to paste into AGENTS.md / CLAUDE.md / GEMINI.md / .cursorrules.

Build once: `(cd ts && npm ci && npx tsc) && (cd adapters/moadim && npm ci)`;
for the wallet verbs also `(cd spend && npm ci && npx tsc)`. Node ≥ 22.18. (POSIX shell;
in PowerShell run the same commands with `cd` and `;`, as in [QUICKSTART](../QUICKSTART.md).)

## Harnesses

| Harness | Mechanism | File | Status |
|---|---|---|---|
| any MCP client | stdio MCP server | [mcp/server.mjs](mcp/server.mjs) | **tested here** — scripted client, 50 checks, every tool, both protocol eras |
| Claude Code | skills-dir plugin = skill + MCP server; subagents inherit it | [claude-code/](claude-code/README.md) | **tested here** — 2.1.281: plugin loaded, MCP connected via symlink, Haiku session + a subagent ran init→challenge→attest→bundle→verify |
| shell-only agents | CLI skill + `sigelo-agent`/`sigelo-wallet` | [skills-cli/sigelo/](skills-cli/sigelo/SKILL.md) | **tested here** — commands smoke-tested against `examples/world.mjs`; not run inside a harness |
| Hermes Agent (`NousResearch/hermes-agent`) | `mcp_servers:` + `skills.external_dirs` in `~/.hermes/config.yaml` | [../adapters/hermes/](../adapters/hermes/INTEGRATION.md) | **tested here** — v0.21.5+ (`e9d7a18`): unmodified `hermes -z`, scripted model, 12 checks incl. wallet verbs and go/ re-verify |
| OpenAI Codex CLI | `[mcp_servers.sigelo]` in `~/.codex/config.toml`; skill in `~/.agents/skills`; AGENTS.md | [codex.md](codex.md) | doc-verified |
| OpenCode | `mcp` block (`type: local`, command array) in `opencode.json`; skill; AGENTS.md | [opencode.md](opencode.md) | doc-verified; per-agent MCP filtering UNVERIFIED |
| Agent Zero (`agent0ai/agent-zero`) | MCP via Settings → MCP/A2A; `usr/skills/`; optional native Python tool | [agent-zero.md](agent-zero.md) | doc-verified; node in the image, settings file, native tool UNVERIFIED |
| pi (pi.dev, "agent pi") | CLI skill (pi has no MCP by design); optional TS extension | [agent-pi.md](agent-pi.md) | doc-verified; extension UNVERIFIED |
| Cursor | `.cursor/mcp.json`; rules / AGENTS.md | [others.md](others.md#cursor--cursormcpjson-project-or-cursormcpjson-global) | doc-verified |
| Cline | `cline_mcp_settings.json` / `~/.cline/mcp.json` | [others.md](others.md) | doc-verified; Linux path UNVERIFIED |
| Goose | `extensions:` in `~/.config/goose/config.yaml` | [others.md](others.md) | doc-verified |
| Gemini CLI | `mcpServers` in `~/.gemini/settings.json`; skills; GEMINI.md | [others.md](others.md) | doc-verified |
| LangGraph / CrewAI / Vercel AI SDK | their MCP stdio clients | [others.md](others.md) | doc-verified |

"doc-verified" = the config was checked against the harness's own documentation (URL in each
file, fetched 2026-09-24) but the harness was not run here.

## Tools

| Tool | Does |
|---|---|
| `sigelo_whoami` | current DID, genesis, chain, attestation count |
| `sigelo_init` | create the identity once; `recovery`: `"z6Mk…"` or `"none"` |
| `sigelo_sign_challenge` | sign a SPEC §5.2 challenge naming this DID; nothing else |
| `sigelo_add_issuer` / `sigelo_add_attestation` | store a world's genesis / attestation (optionally with its `issuer`) |
| `sigelo_forget_issuer` | drop a retired issuer's attestations and genesis (SPEC §5; after an out-of-band notice) |
| `sigelo_bundle` | the verified SPEC §8 bundle |
| `sigelo_verify` | SPEC §9 verify of any bundle, offline; reports, does not judge |
| `sigelo_rotate` | voluntary rotation (recovery rotation stays offline) |
| `sigelo_wallet_balance` / `_receive` / `_pay` / `_history` | the keeper's four verbs (MONERO.md §4.2); only listed when the wallet env is set |

Every identity tool takes an optional `identity` profile name (`[a-z0-9][a-z0-9_-]{0,63}` →
`sigelo.<name>.local.json` beside the default file): one identity per subagent on a shared
server. A convenience, not a boundary; separate processes with separate `SIGELO_IDENTITY` are.
JSON arguments may also be passed as text, which goes through sigelo's duplicate-key-rejecting
parser, as does every incoming JSON-RPC line.

## Environment

| Variable | |
|---|---|
| `SIGELO_IDENTITY` | identity file; default `~/.config/moadim/sigelo.local.json` (as `sigelo-agent`) |
| `SIGELO_WALLET_URL`, `SIGELO_WALLET_TOKEN` | keeper URL and this agent's token (spend/README.md); both set → wallet tools appear |
| `SIGELO_WALLET_TIMEOUT_MS` | optional, as for `sigelo-wallet` |
| `SIGELO_HOME` | the checkout, for the CLI skill |
