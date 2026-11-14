<!-- SPDX-License-Identifier: MIT -->
# sigelo in AgentRun and other URL-only hosts

The CLI is the npm package `sigelo-agent`; the MCP server is `sigelo-mcp`; the package `sigelo` is
the library and has no CLI.

AgentRun takes an MCP server by URL only; plain HTTP only on loopback, and loopback only with
`AGENTRUN_MCP_ALLOW_LOOPBACK=1`. Its agent has no shell. So the shape is:

- **Operator, on the host:** installs `sigelo-mcp` and runs `sigelo-mcp --http` on `127.0.0.1` with a
  bearer token. The identity file is the operator's, on that host.
- **AgentRun:** started with `AGENTRUN_MCP_ALLOW_LOOPBACK=1`, given the URL and the token.
- **Agent:** sees the tools only. It enrols by calling `sigelo_enrol` with the one-time code from the
  operator's `sigelo-agent enrol` ([ENROL.md](../agent/ENROL.md)).

## Operator

```sh
npm i -g sigelo-mcp@0.1.16
export SIGELO_IDENTITY="$HOME/.config/sigelo/agentrun.local.json"
export SIGELO_MCP_TOKEN="$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')"
sigelo-mcp --http 127.0.0.1:7310
```

It prints `sigelo-mcp: listening on http://127.0.0.1:7310/mcp` (stderr). Keep it running (a service
or the container's supervisor), in AgentRun's network namespace: loopback is per host or container.
Without `SIGELO_MCP_TOKEN` it makes a token at first start, prints it and keeps it in
`sigelo-mcp-http.token` beside the identity file. One process serves one identity; flags and
guards: [mcp/README.md](mcp/README.md#over-http---http).

## AgentRun

```sh
export AGENTRUN_MCP_ALLOW_LOOPBACK=1
```

Add the server: URL `http://127.0.0.1:7310/mcp`, header `Authorization: Bearer <SIGELO_MCP_TOKEN>`.
AgentRun's own syntax for the header: its docs (not checked here).

On the relay, the server logs in per tool call; no `sigelo-agent watch` beside it is needed
([mcp/README.md](mcp/README.md#contact-tools)).

Check: on the host run
`curl -s -H "Authorization: Bearer $SIGELO_MCP_TOKEN" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' http://127.0.0.1:7310/mcp | grep -o '"name":"sigelo_[a-z_]*"' | wc -l`;
it prints `28`.
