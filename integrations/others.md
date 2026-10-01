<!-- SPDX-License-Identifier: MIT -->
# sigelo in other harnesses and frameworks

All of these take a **stdio MCP server**, so each is one config entry pointing at
`integrations/mcp/server.mjs` (node ≥ 22.18, the checkout built). Status of every section:
**doc-verified** against the cited page (fetched 2026-09-24), not run here, except where marked
UNVERIFIED. `/abs/path/to/sigelo` is your checkout; env vars as in `integrations/README.md`.

## Cursor — `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global)

Source: https://cursor.com/docs/context/mcp, https://cursor.com/docs/context/rules

```json
{ "mcpServers": { "sigelo": { "type": "stdio", "command": "node",
    "args": ["/abs/path/to/sigelo/integrations/mcp/server.mjs"],
    "env": { "SIGELO_IDENTITY": "${userHome}/.config/sigelo/cursor.local.json" } } } }
```

Instructions: `AGENTS.md` (root and nested) or `.cursor/rules/sigelo.mdc` with frontmatter
`alwaysApply: true`; `.cursorrules` is legacy. Paste `integrations/AGENTS.md`.

## Cline — `cline_mcp_settings.json` (VS Code: MCP Servers → Configure) / `~/.cline/mcp.json` (CLI)

Source: https://docs.cline.bot/mcp/configuring-mcp-servers, https://docs.cline.bot/features/cline-rules.
The VS Code path on Linux, `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`,
is from third-party sources (UNVERIFIED).

```json
{ "mcpServers": { "sigelo": { "command": "node",
    "args": ["/abs/path/to/sigelo/integrations/mcp/server.mjs"],
    "env": { "SIGELO_IDENTITY": "/home/you/.config/sigelo/cline.local.json" },
    "disabled": false, "autoApprove": ["sigelo_whoami", "sigelo_bundle", "sigelo_verify"] } } }
```

Never auto-approve `sigelo_wallet_pay`. Rules: `.clinerules/` (Cline also reads `AGENTS.md`).

## Goose — `~/.config/goose/config.yaml`

Source: https://goose-docs.ai/docs/guides/config-files/,
https://goose-docs.ai/docs/guides/context-engineering/using-goosehints/

```yaml
extensions:
  sigelo:
    type: stdio
    name: sigelo
    enabled: true
    cmd: node
    args: ["/abs/path/to/sigelo/integrations/mcp/server.mjs"]
    envs: { SIGELO_IDENTITY: "/home/you/.config/sigelo/goose.local.json" }
    env_keys: []
    timeout: 300
```

Instructions: `AGENTS.md` then `.goosehints` (working dir up to repo root) and
`~/.config/goose/.goosehints`. Goose skills: UNVERIFIED (not checked).

## Gemini CLI — `~/.gemini/settings.json` or `.gemini/settings.json`

Source: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/tools/mcp-server.md,
`…/docs/cli/gemini-md.md`, `…/docs/cli/skills.md`

```json
{ "mcpServers": { "sigelo": { "command": "node",
    "args": ["/abs/path/to/sigelo/integrations/mcp/server.mjs"],
    "env": { "SIGELO_IDENTITY": "$HOME/.config/sigelo/gemini.local.json" }, "trust": false } } }
```

or `gemini mcp add -s user -e SIGELO_IDENTITY=/home/you/.config/sigelo/gemini.local.json sigelo node /abs/path/to/sigelo/integrations/mcp/server.mjs`.
Our tool schemas use only `type: "object"`/`"string"`/`"integer"` (no union types), which
Gemini's schema handling needs. Skills: `~/.gemini/skills` or `~/.agents/skills` — link
`integrations/claude-code/skills/sigelo` there. Instructions: `GEMINI.md`, or set
`"context": {"fileName": ["AGENTS.md", "GEMINI.md"]}`.

## LangGraph / LangChain — `langchain-mcp-adapters`

Source: https://raw.githubusercontent.com/langchain-ai/langchain-mcp-adapters/main/README.md

```python
import os
from langchain_mcp_adapters.client import MultiServerMCPClient
client = MultiServerMCPClient({"sigelo": {"transport": "stdio", "command": "node",
    "args": ["/abs/path/to/sigelo/integrations/mcp/server.mjs"],
    "env": {"SIGELO_IDENTITY": "/srv/agents/planner.local.json", "PATH": os.environ["PATH"]}}})
tools = await client.get_tools()          # sigelo_whoami, sigelo_sign_challenge, …
```

One client entry per agent gives each its own identity (separate processes).

## CrewAI — `crewai-tools` `MCPServerAdapter`

Source: https://docs.crewai.com/en/mcp/stdio

```python
import os
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters
params = StdioServerParameters(command="node", args=["/abs/path/to/sigelo/integrations/mcp/server.mjs"],
    env={**os.environ, "SIGELO_IDENTITY": "/srv/agents/researcher.local.json"})
with MCPServerAdapter(params) as tools:
    researcher = Agent(role="researcher", tools=tools, ...)
```

## Vercel AI SDK — `@ai-sdk/mcp`

Source: https://ai-sdk.dev/docs/ai-sdk-core/mcp-tools (the current API is `createMCPClient`
from `@ai-sdk/mcp`; `experimental_createMCPClient` is the older name).

```ts
import { createMCPClient } from '@ai-sdk/mcp';
import { Experimental_StdioMCPTransport } from '@ai-sdk/mcp/mcp-stdio';
const sigelo = await createMCPClient({ transport: new Experimental_StdioMCPTransport({
  command: 'node', args: ['/abs/path/to/sigelo/integrations/mcp/server.mjs'],
  env: { ...process.env, SIGELO_IDENTITY: '/srv/agents/bot.local.json' } }) });
const tools = await sigelo.tools();   // pass to generateText({ tools, … }); await sigelo.close() after
```

## Anything else

A harness that speaks MCP over stdio needs only `node …/server.mjs` and `SIGELO_IDENTITY`. One
that only runs shell commands gets `integrations/skills-cli/sigelo/SKILL.md` (or the 25-line
`integrations/AGENTS.md`) and the `sigelo-agent` / `sigelo-wallet` CLIs. The server speaks MCP
2026-07-28 (`server/discover`, per-request `_meta`) and the older `initialize` handshake
(2025-11-25 back to 2024-11-05), so old and new clients both connect.
