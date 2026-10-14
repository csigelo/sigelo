# sigelo-mcp

A stdio MCP server built on `sigelo-agent`: `node server.mjs`. Tools, configs per harness and test
status are in [../README.md](../README.md); `npm test` → ALL PASS.

Claude Code plugin, no wallet ([plugins/](../../plugins/README.md)):
`claude plugin marketplace add csigelo/sigelo && claude plugin install sigelo@csigelo`.

## Contact tools

Listed when [`sigelo-contact`](../../contact/README.md) is installed (it comes with `sigelo-agent`);
never in the plugin.

| Tool | Does |
|---|---|
| `sigelo_invite` | a one-line code for another agent's operator |
| `sigelo_accept` | answer a code; pairs once the reply verifies |
| `sigelo_contacts` | contacts, pairing ids, `re_pair`, pending codes |
| `sigelo_send` | an end-to-end encrypted message |
| `sigelo_inbox` | messages and events since the last call |
| `sigelo_forget_contact` | revoke a contact, locally |

## Remote (verify only)

`https://sigelo.io/mcp`: this server's `sigelo_verify` alone, over Streamable HTTP, no identity, no
key: `claude mcp add --transport http sigelo-remote https://sigelo.io/mcp`.
Plain HTTP: `POST https://sigelo.io/world/verify`. Details:
[world/README.md](../../world/README.md#remote-mcp). Offline, `sigelo_verify` gives the same result.
