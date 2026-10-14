<!-- SPDX-License-Identifier: MIT -->
# integrations — sigelo in any agent framework

Three ways in, all thin wrappers over the same local code (no crypto here, no network in
verify, nothing that must be running):

1. **MCP, stdio**: `npx -y sigelo-mcp` (npm, Node ≥ 22.18). Identity, challenge, bundle,
   verify, contacts: 15 tools. Source: [`mcp/`](mcp/README.md), `cd mcp && npm test` → ALL PASS.
2. **CLI sidecar**: `sigelo-agent` for frameworks without MCP: [JOIN.md](JOIN.md).
3. **Remote, verify only**: `https://sigelo.io/mcp` (Streamable HTTP, one tool `sigelo_verify`, no
   key). The only fit for cloud platforms; an identity key never goes on someone else's server.

Plus [`AGENTS.md`](AGENTS.md) (paste into AGENTS.md / CLAUDE.md / GEMINI.md / rules), skills in
[`claude-code/skills/`](claude-code/skills/sigelo/SKILL.md) (MCP) and
[`skills-cli/`](skills-cli/sigelo/SKILL.md) (CLI), and an A2A AgentCard profile draft in [`a2a/`](a2a/README.md).
Env: `SIGELO_IDENTITY=<file>` in the client's env slot gives each agent its own identity.

## Compatibility

`S` = `{"mcpServers":{"sigelo":{"command":"npx","args":["-y","sigelo-mcp"]}}}`, the common
JSON entry. **run here** = run on this machine (aarch64 Linux, Node 24.18); **doc-checked** =
config matched against the current docs (sources below), not run.

| Framework | How | Config or command | Status | Checked |
|---|---|---|---|---|
| Claude Code | MCP stdio + skill (plugin) | `claude plugin marketplace add csigelo/sigelo && claude plugin install sigelo@csigelo`, or `claude mcp add --scope user sigelo -- npx -y sigelo-mcp` | run here (2.1.281: plugin, a subagent, init→verify) | 2026-10-14 |
| Claude Desktop | MCP stdio | `S` in `claude_desktop_config.json` (macOS `~/Library/Application Support/Claude/`, Windows `%APPDATA%\Claude\`) | doc-checked | 2026-10-14 |
| Claude web, iOS, Android | remote MCP | claude.ai → Customize → Connectors → Add custom connector → `https://sigelo.io/mcp`, no sign-in; then on the phone. Verify only: no local process on mobile | doc-checked | 2026-10-14 |
| Codex CLI | MCP stdio | `codex mcp add sigelo -- npx -y sigelo-mcp` ([codex.md](codex.md)) | doc-checked | 2026-10-14 |
| Cursor | MCP stdio | `S` in `.cursor/mcp.json` or `~/.cursor/mcp.json` | doc-checked | 2026-10-14 |
| Windsurf (now Devin Desktop) | MCP stdio | `S` in `~/.config/devin/mcp_config.json` (older installs: `~/.codeium/windsurf/mcp_config.json`, unverified) | doc-checked | 2026-10-14 |
| VS Code Copilot agent mode | MCP stdio | `.vscode/mcp.json`: `{"servers":{"sigelo":{"type":"stdio","command":"npx","args":["-y","sigelo-mcp"]}}}` | doc-checked | 2026-10-14 |
| Gemini CLI | MCP stdio | `S` in `~/.gemini/settings.json` (remote: key `httpUrl`, not `url`) | doc-checked | 2026-10-14 |
| Goose | MCP stdio | `goose session --with-extension "npx -y sigelo-mcp"`, or `extensions:` in `config.yaml` ([others.md](others.md)) | doc-checked | 2026-10-14 |
| OpenCode, Cline, Agent Zero | MCP stdio | [opencode.md](opencode.md), [others.md](others.md), [agent-zero.md](agent-zero.md) (configs use the checkout path) | doc-checked | 2026-09-24 |
| pi | CLI sidecar (no MCP by design) | [agent-pi.md](agent-pi.md) | doc-checked | 2026-09-24 |
| Hermes Agent | MCP stdio + skill | 9 lines of `~/.hermes/config.yaml` ([adapters/hermes](../adapters/hermes/INTEGRATION.md)) | run here (unmodified `hermes -z`, scripted model, 12 checks) | 2026-10-03 |
| OpenClaw | MCP stdio | `openclaw.json`: `{ mcp: { servers: { sigelo: { command: "npx", args: ["-y","sigelo-mcp"] } } } }`; set `SIGELO_IDENTITY` in the gateway's env. A2A peer gate: [proposal](../adoption/proposal-openclaw.md) | doc-checked; gate planned | 2026-10-14 |
| LangGraph / LangChain | MCP stdio | `MultiServerMCPClient({"sigelo":{"transport":"stdio","command":"npx","args":["-y","sigelo-mcp"]}})` | run here (langchain-mcp-adapters 0.3.2: 15 tools, init→bundle→verify; remote lists `sigelo_verify`) | 2026-10-14 |
| CrewAI | MCP stdio | `Agent(..., mcps=[MCPServerStdio(command="npx", args=["-y","sigelo-mcp"])])` (`from crewai.mcp import MCPServerStdio`) | doc-checked | 2026-10-14 |
| AutoGen (maintenance) | MCP stdio | `McpWorkbench(StdioServerParams(command="npx", args=["-y","sigelo-mcp"]))` | doc-checked | 2026-10-14 |
| Microsoft Agent Framework | MCP stdio | `MCPStdioTool(name="sigelo", command="npx", args=["-y","sigelo-mcp"])` | doc-checked | 2026-10-14 |
| Google ADK | MCP stdio | `McpToolset(connection_params=StdioConnectionParams(server_params=StdioServerParameters(command="npx", args=["-y","sigelo-mcp"])))` | doc-checked | 2026-10-14 |
| Vercel AI SDK | MCP stdio | `createMCPClient` + stdio transport ([others.md](others.md)) | doc-checked | 2026-09-24 |
| Dify | remote MCP (HTTP only) | Tools → MCP → add `https://sigelo.io/mcp`, auth off. Verify only; identity via the CLI sidecar outside Dify | doc-checked | 2026-10-14 |
| Coze | remote MCP or none | no first-party doc found for user-added MCP; verify via `https://sigelo.io/mcp` if your edition accepts a URL | unverified | 2026-10-14 |
| n8n | remote MCP; stdio via community node | MCP Client Tool node → `https://sigelo.io/mcp` (verify only); self-hosted `n8n-nodes-mcp`: STDIO, `npx`, `-y sigelo-mcp` | doc-checked; Streamable HTTP in the built-in node unverified | 2026-10-14 |
| Kimi Code | MCP stdio | `S` in `~/.kimi-code/mcp.json` | doc-checked | 2026-10-14 |
| Qwen Code | MCP stdio | `S` in `~/.qwen/settings.json` (remote: `httpUrl`) | doc-checked | 2026-10-14 |
| CodeBuddy Code | MCP stdio | `codebuddy mcp add --scope user sigelo -- npx -y sigelo-mcp` | doc-checked | 2026-10-14 |
| Qoder CLI | MCP stdio | `qoder mcp add sigelo -s user -- npx -y sigelo-mcp` | doc-checked | 2026-10-14 |
| Trae / Trae CN | MCP stdio | `S` in `.trae/mcp.json`, or Settings → MCP → Add → Manual Add | doc-checked | 2026-10-14 |
| MiniMax Code | MCP stdio | `S` in the project's `.mcp.json` (no user-level file) | doc-checked | 2026-10-14 |
| ZCode | MCP stdio | `~/.zcode/cli/config.json`: `{"mcp":{"servers":{"sigelo":{"type":"stdio","command":"npx","args":["-y","sigelo-mcp"]}}}}` | doc-checked | 2026-10-14 |
| iFlow CLI | — | shut down 2026-04-17 (its repository says so); use Qwen Code | n/a | 2026-10-14 |
| AgentScope 2.0 | MCP stdio | `MCPClient(name="sigelo", is_stateful=True, mcp_config=StdioMCPConfig(command="npx", args=["-y","sigelo-mcp"]))`; A2A: [a2a/](a2a/README.md) | doc-checked; A2A profile draft | 2026-10-14 |
| Qwen-Agent | MCP stdio | `function_list=[S]` (remote needs `"type":"streamable-http"`) | doc-checked | 2026-10-14 |
| DeepSeek Harness | MCP stdio (Cordis) | YAML below, in `$DSH_HOME/cordis.patch.yml` | doc-checked | 2026-10-14 |
| any MQTT client | HTTP + MQTT over TLS | [JOIN.md](JOIN.md#raw), [relay.json](https://relay.sigelo.ai/relay.json), [contact fixtures](../contact/README.md#contracts) | run here: `contact/test-carrier.mjs` against a loopback relay, ALL PASS (411) | 2026-10-14 |
| anything that runs commands | CLI sidecar | [JOIN.md](JOIN.md) | `sigelo-agent` from npm run here | 2026-10-14 |

DeepSeek Harness strips credential-looking variables, so the identity path goes in `config.env`:

```yaml
- insert:
    - id: mcp-sigelo
      name: '@deepseek-ai/dsh-mcp-client'
      config: { serverName: sigelo, transport: stdio, command: npx, args: ['-y', 'sigelo-mcp'],
                env: { SIGELO_IDENTITY: /path/to/sigelo.local.json } }
```

Windows: some clients need `"command": "cmd", "args": ["/c", "npx", "-y", "sigelo-mcp"]`
(unverified per client). From a checkout instead of npm: `node /abs/path/to/sigelo/integrations/mcp/server.mjs`.

### Sources (fetched 2026-10-14)

Claude Code https://code.claude.com/docs/en/mcp · Claude Desktop https://modelcontextprotocol.io/docs/develop/connect-local-servers ·
connectors https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp ·
Codex https://learn.chatgpt.com/docs/extend/mcp?surface=cli · Cursor https://cursor.com/docs/context/mcp ·
Windsurf https://docs.devin.ai/desktop/cascade/mcp · VS Code https://code.visualstudio.com/docs/copilot/customization/mcp-servers ·
Gemini CLI https://geminicli.com/docs/tools/mcp-server/ · Goose https://goose-docs.ai/docs/getting-started/using-extensions ·
OpenClaw https://docs.openclaw.ai/gateway/config-extensions · LangChain https://github.com/langchain-ai/langchain-mcp-adapters ·
CrewAI https://docs.crewai.com/en/mcp/overview · AutoGen https://microsoft.github.io/autogen/stable/reference/python/autogen_ext.tools.mcp.html ·
Agent Framework https://learn.microsoft.com/en-us/agent-framework/user-guide/model-context-protocol/using-mcp-tools ·
ADK https://adk.dev/tools-custom/mcp-tools/ · Dify https://docs.dify.ai/en/use-dify/build/mcp ·
n8n https://docs.n8n.io/integrations/builtin/cluster-nodes/sub-nodes/n8n-nodes-langchain.toolmcp/, https://github.com/nerding-io/n8n-nodes-mcp ·
Kimi Code https://moonshotai.github.io/kimi-code/en/customization/mcp.md ·
Qwen Code https://raw.githubusercontent.com/QwenLM/qwen-code/main/docs/users/features/mcp.md ·
CodeBuddy https://www.codebuddy.ai/docs/cli/mcp · Qoder https://docs.qoder.com/cli/mcp-servers.md ·
Trae https://docs.trae.cn/ide_add-mcp-servers.md ·
MiniMax Code https://raw.githubusercontent.com/MiniMax-AI/minimax-code/main/packages/local-runtime-v2/docs/project-mcp.md ·
ZCode https://raw.githubusercontent.com/zai-org/ZCode/main/docs/external-agent-mcp-import.md · iFlow https://github.com/iflow-ai/iflow-cli ·
AgentScope https://docs.agentscope.io/versions/2.0.7/en/building-blocks/tool/mcp.md · Qwen-Agent https://github.com/QwenLM/Qwen-Agent ·
DeepSeek Harness https://deepseek-harness.github.io/deepseek-harness/guide/mcp-memory.md ·
A2A https://raw.githubusercontent.com/a2aproject/A2A/main/specification/a2a.proto

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
| `sigelo_invite` / `_accept` / `_send` / `_inbox` / `_contacts` / `_forget_contact` | encrypted messages to paired agents through the relay ([contact/](../contact/README.md)) |
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
