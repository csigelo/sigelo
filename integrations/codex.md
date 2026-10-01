<!-- SPDX-License-Identifier: MIT -->
# sigelo in OpenAI Codex CLI

Status: **doc-verified** against the pages below (fetched 2026-09-24; developers.openai.com now
308-redirects to learn.chatgpt.com). Codex is not installed on this machine; nothing here was run
in Codex. The server itself is tested (`integrations/mcp`, `npm test`).

`SIGELO_HOME` = your sigelo checkout, built (`ts` + `adapters/moadim`, see README.md). Absolute
paths only.

## 1. MCP server — `~/.codex/config.toml` (or `.codex/config.toml` in a trusted project)

Source: https://learn.chatgpt.com/docs/extend/mcp?surface=cli

```toml
[mcp_servers.sigelo]
command = "node"
args = ["/abs/path/to/sigelo/integrations/mcp/server.mjs"]
env_vars = ["SIGELO_WALLET_URL", "SIGELO_WALLET_TOKEN"]   # forwarded from Codex's env, if set

[mcp_servers.sigelo.env]
SIGELO_IDENTITY = "/home/you/.config/sigelo/codex.local.json"
```

or the CLI form from the same page:

```sh
codex mcp add sigelo --env SIGELO_IDENTITY=/home/you/.config/sigelo/codex.local.json -- node /abs/path/to/sigelo/integrations/mcp/server.mjs
```

Optional keys documented there: `cwd`, `startup_timeout_sec` (default 10), `tool_timeout_sec`
(default 60 — a keeper `pay` may wait longer on approval; raise it if you use the wallet),
`enabled`, `enabled_tools`, `disabled_tools`.

## 2. Skill — `~/.agents/skills/sigelo/` (or `.agents/skills/sigelo/` in the repo)

Source: https://learn.chatgpt.com/docs/build-skills (Codex scans `$CWD/.agents/skills`, parents,
`$REPO_ROOT/.agents/skills`, `$HOME/.agents/skills`, `/etc/codex/skills`; `SKILL.md` needs
`name` + `description`; invoke explicitly with `$sigelo`).

```sh
mkdir -p ~/.agents/skills && ln -sfn "$SIGELO_HOME/integrations/claude-code/skills/sigelo" ~/.agents/skills/sigelo
```

The Claude Code plugin files beside `SKILL.md` (`.claude-plugin/`, `.mcp.json`, `mcp.mjs`) are
ignored by Codex as far as the docs say (UNVERIFIED: not run). Without the MCP server, link
`integrations/skills-cli/sigelo` instead: the same workflow through the `sigelo-agent` CLI.

## 3. AGENTS.md

Source: https://learn.chatgpt.com/docs/agent-configuration/agents-md — global
`~/.codex/AGENTS.md` (or `AGENTS.override.md`), then every `AGENTS.md` from the git root down to
the working directory, concatenated; 32 KiB total by default. Paste `integrations/AGENTS.md`.

## Subagents / several agents

One `[mcp_servers.<name>]` entry per identity, each with its own `SIGELO_IDENTITY`, or the
optional `identity: "<name>"` argument every identity tool takes (one server, separate files; a
convenience, not isolation).
