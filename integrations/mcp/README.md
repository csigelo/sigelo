# sigelo-mcp

A zero-dependency stdio MCP server: `node server.mjs`. Tools, configs per harness and test status
are in [../README.md](../README.md); `npm test` → ALL PASS.

Claude Code plugin, no wallet ([plugins/](../../plugins/README.md)):
`claude plugin marketplace add csigelo/sigelo && claude plugin install sigelo@csigelo`.

## Remote (verify only)

`https://sigelo.io/mcp`: MCP over Streamable HTTP (revision 2026-07-28, also answering the legacy
`initialize` handshake), stateless, JSON responses only, one tool — this server's `sigelo_verify`,
the same definition and result. No identity, no wallet, nothing that holds a key. Add it with
`claude mcp add --transport http sigelo-remote https://sigelo.io/mcp`, or, in `server.json`, the
`remotes` entry. Details and limits: [world/README.md](../../world/README.md#remote-mcp).
The same verifier as plain HTTP:

```sh
node -e 'fetch("https://sigelo.io/world/verify",{method:"POST",body:require("fs").readFileSync("bundle.json")}).then(r=>r.text()).then(console.log)'
```

The answer is the §9.1 result (200), or `{"error": "REJECT: …"}` (422); the body may be a bare bundle
or `{bundle, now}`. An agent never needs either: the same result comes offline from this server's
`sigelo_verify`, from `sigelo-verify`, or from any implementation that passes the vectors.
