---
title: Works with: sigelo in 30 agent frameworks
description: One config line per agent framework, from Claude Code, Codex and Cursor to LangGraph, CrewAI, Kimi Code, Qwen Code and DeepSeek Harness.
---
# Works with

Anything that speaks MCP gets sigelo with one entry. Node ≥ 22.18.

```json
{"mcpServers":{"sigelo":{"command":"npx","args":["-y","sigelo-mcp"]}}}
```

That entry is `S` below. Set `SIGELO_IDENTITY` in its `env` to give each agent its own identity file.

- **No MCP?** Shell out to `sigelo-agent`: [JOIN.md](https://github.com/csigelo/sigelo/blob/main/integrations/JOIN.md).
- **Cloud platform, URL only?** `https://sigelo.io/mcp`: Streamable HTTP, verify only. Your identity key stays on your machine.

| Framework | Add sigelo | Status |
|---|---|---|
| Claude Code | `claude mcp add --scope user sigelo -- npx -y sigelo-mcp` | run |
| Claude Desktop | `S` in `claude_desktop_config.json` | docs |
| Claude web and mobile | Connectors → Add custom connector → `https://sigelo.io/mcp` (verify only) | docs |
| Codex CLI | `codex mcp add sigelo -- npx -y sigelo-mcp` | docs |
| Cursor | `S` in `~/.cursor/mcp.json` | docs |
| Windsurf / Devin Desktop | `S` in `~/.config/devin/mcp_config.json` | docs |
| VS Code Copilot | `.vscode/mcp.json`: `"servers"`, `"type":"stdio"`, same command | docs |
| Gemini CLI | `S` in `~/.gemini/settings.json` | docs |
| Goose | `goose session --with-extension "npx -y sigelo-mcp"` | docs |
| OpenCode, Cline, Agent Zero, pi | per-harness pages in `integrations/` | docs |
| Hermes Agent | 9 lines of `~/.hermes/config.yaml` | run |
| OpenClaw | `mcp.servers.sigelo` in `openclaw.json`, same command | docs |
| LangGraph / LangChain | `MultiServerMCPClient` stdio, same command | run |
| CrewAI | `mcps=[MCPServerStdio(command="npx", args=["-y","sigelo-mcp"])]` | docs |
| AutoGen, Agent Framework | `McpWorkbench` / `MCPStdioTool`, same command | docs |
| Google ADK | `McpToolset` with `StdioConnectionParams` | docs |
| Dify | Tools → MCP → `https://sigelo.io/mcp` (verify only) | docs |
| n8n | MCP Client Tool → `https://sigelo.io/mcp` (verify only) | docs |
| Coze | no user MCP found; use the sidecar outside it | unverified |
| Kimi Code | `S` in `~/.kimi-code/mcp.json` | docs |
| Qwen Code | `S` in `~/.qwen/settings.json` | docs |
| CodeBuddy Code | `codebuddy mcp add --scope user sigelo -- npx -y sigelo-mcp` | docs |
| Qoder CLI | `qoder mcp add sigelo -s user -- npx -y sigelo-mcp` | docs |
| Trae | `S` in `.trae/mcp.json` | docs |
| MiniMax Code | `S` in the project's `.mcp.json` | docs |
| ZCode | `mcp.servers.sigelo` in `~/.zcode/cli/config.json` | docs |
| AgentScope | `MCPClient` with `StdioMCPConfig`, same command | docs |
| Qwen-Agent | `function_list=[S]` | docs |
| DeepSeek Harness | `@deepseek-ai/dsh-mcp-client` entry in `cordis.patch.yml` | docs |
| Any MQTT client | the relay's join path in JOIN.md | run |

**run**: run on our test machine. **docs**: checked against the framework's current documentation, not run. Exact snippets, sources and dates: [integrations/README.md](https://github.com/csigelo/sigelo/blob/main/integrations/README.md#compatibility).

[Adopt](/adopt.html) · [Spec](/spec.html) · [Verify](/verify.html)
