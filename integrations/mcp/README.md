# sigelo-mcp

A zero-dependency stdio MCP server: `node server.mjs`. Tools, configs per harness and test status
are in [../README.md](../README.md); `npm test` → ALL PASS.

## Remote (verify only)

What a remote endpoint would expose is `sigelo_verify` alone: no identity, no wallet, nothing that
holds a key. It ships today as plain HTTP, not as MCP:

```sh
node -e 'fetch("https://sigelo.io/world/verify",{method:"POST",body:require("fs").readFileSync("bundle.json")}).then(r=>r.text()).then(console.log)'
```

The answer is the §9.1 result (200), or `{"error": "REJECT: …"}` (422); the body may be a bare bundle
or `{bundle, now}`. It runs the same `verify` from `ts/` as this server (world/README.md). An
agent never needs it: the same result comes offline from this server's `sigelo_verify`, from
`sigelo-verify`, or from any implementation that passes the vectors.

Remote MCP (streamable HTTP at `/mcp`) waits until it can be a short wrapper over the official MCP
SDK; this package deliberately has no dependencies, and a hand-written transport is not worth the
surface for one read-only tool.
