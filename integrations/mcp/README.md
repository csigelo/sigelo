# sigelo-mcp

A stdio MCP server built on `sigelo-agent`: `node server.mjs`. Tools, configs per harness and test
status are in [../README.md](../README.md); `npm test` → ALL PASS.

Claude Code plugin, no wallet ([plugins/](../../plugins/README.md)):
`claude plugin marketplace add csigelo/sigelo && claude plugin install sigelo@csigelo`.

## Contact tools

With [`sigelo-contact`](../../contact/README.md) (it comes with `sigelo-agent`); never in the plugin.
Beside `sigelo-agent watch` or `ui`, tools follow [the one-owner rule](../../adapters/moadim/WATCH.md) (`busy`).

| Tool | Does |
|---|---|
| `sigelo_invite` | a short code for another operator |
| `sigelo_accept` | answer a code |
| `sigelo_contacts` | contacts, words, tiers, `re_pair`, codes |
| `sigelo_set_tier` | own, friend or quiet |
| `sigelo_send` | an end-to-end encrypted message |
| `sigelo_inbox` | messages and events, by tier |
| `sigelo_forget_contact` | revoke a contact, locally |

## Remote (verify only)

`https://sigelo.io/mcp`: `sigelo_verify` alone over Streamable HTTP, no identity, no
key: `claude mcp add --transport http sigelo-remote https://sigelo.io/mcp`.
Plain HTTP: `POST https://sigelo.io/world/verify`. Details:
[world/README.md](../../world/README.md#remote-mcp).
