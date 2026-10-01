<!-- SPDX-License-Identifier: MIT -->
# sigelo in OpenCode

Status: **doc-verified** against https://opencode.ai/docs/mcp-servers/,
https://opencode.ai/docs/rules/, https://opencode.ai/docs/skills/ and
https://opencode.ai/docs/agents/ (fetched 2026-09-24). OpenCode is not installed here; not run.

## 1. MCP server — `opencode.json` (project root) or `~/.config/opencode/opencode.json`

`command` is ONE array (program + args); env goes in `environment`, not `env`; `{env:VAR}` reads
OpenCode's own environment.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "sigelo": {
      "type": "local",
      "command": ["node", "/abs/path/to/sigelo/integrations/mcp/server.mjs"],
      "enabled": true,
      "environment": {
        "SIGELO_IDENTITY": "/home/you/.config/sigelo/opencode.local.json",
        "SIGELO_WALLET_URL": "{env:SIGELO_WALLET_URL}",
        "SIGELO_WALLET_TOKEN": "{env:SIGELO_WALLET_TOKEN}"
      }
    }
  }
}
```

The wallet tools appear only when both wallet variables are non-empty; drop those two lines for
an identity-only agent. `timeout` (ms, default 5000) is for fetching the tool list only.

## 2. Skill

OpenCode reads `.opencode/skills/<name>/SKILL.md`, `~/.config/opencode/skills/`, and also
`.claude/skills/` and `.agents/skills/`. A Claude Code install (`~/.claude/skills/sigelo`
symlink) is therefore picked up if OpenCode scans the user-level `~/.claude/skills` too
(UNVERIFIED: the page lists `.claude/skills/`; the global path was not confirmed). Explicitly:

```sh
mkdir -p ~/.config/opencode/skills && ln -sfn "$SIGELO_HOME/integrations/claude-code/skills/sigelo" ~/.config/opencode/skills/sigelo
```

`name: sigelo` matches OpenCode's `^[a-z0-9]+(-[a-z0-9]+)*$` rule. Access is governed by
`permission.skill`.

## 3. AGENTS.md

`AGENTS.md` at the project root and `~/.config/opencode/AGENTS.md` (falls back to `CLAUDE.md`
unless `OPENCODE_DISABLE_CLAUDE_CODE=1`). Paste `integrations/AGENTS.md`.

## Subagents with their own identity

OpenCode subagents are `"agent": { "<name>": { "mode": "subagent", … } }` or
`.opencode/agents/<name>.md`. MCP servers are global to the session, so give each subagent a
profile name in its prompt: *"pass `identity: "reviewer"` to every sigelo tool"*. For separate
processes, declare a second `mcp` entry (`"sigelo-reviewer"`, its own `SIGELO_IDENTITY`) and
restrict tools per agent with its `permission`/tools settings (UNVERIFIED: per-agent MCP tool
filtering syntax not checked).
