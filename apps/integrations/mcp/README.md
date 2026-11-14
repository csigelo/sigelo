# sigelo-mcp

A stdio MCP server built on `sigelo-agent`: `node server.mjs`. Tools, configs, tests:
[../README.md](../README.md); `npm test` → ALL PASS.

Claude Code plugin, no wallet ([apps/plugins/](../../plugins/README.md)):
`claude plugin marketplace add csigelo/sigelo && claude plugin install sigelo@csigelo`.

`sigelo_pass {url}`: refused with a Sigelo-Pass hint → the site's cookie `header`
([accept/pass](../../../accept/pass/README.md)). Not in the plugin.

## Contact tools

With [`sigelo-contact`](../../contact/README.md) (part of `sigelo-agent`); never in the plugin.
Beside `sigelo-agent watch` or `ui`, they answer [`busy`](../../agent/WATCH.md#one-process-per-identity-file).

| Tool | Does |
|---|---|
| `sigelo_invite` | a short code; `renew`, `cancel` it |
| `sigelo_accept` | answer a code; compare the [four words](../../agent/ENROL.md#the-four-words) |
| `sigelo_contacts` | contacts, words, tiers, `re_pair`, codes |
| `sigelo_set_tier` | own, friend or quiet |
| `sigelo_presence` | who sees you online |
| `sigelo_send` | an end-to-end encrypted message |
| `sigelo_inbox` | messages and events, by tier |
| `sigelo_wait_for_message` | wait up to 10 minutes for one |
| `sigelo_reply` | answer by message id; delivery status |
| `sigelo_enrol`, `sigelo_enrol_finish` | become your operator's worker (no words to compare) |
| `sigelo_forget_contact` | revoke a contact, locally |

## Over HTTP (`--http`)

`sigelo-mcp --http [HOST:PORT]` serves MCP Streamable HTTP at `/mcp` on `127.0.0.1:7310`.
Same tools, same identity file. Every request needs
`Authorization: Bearer <token>`: `SIGELO_MCP_TOKEN` or `--token`, else one made at first start
and kept in `sigelo-mcp-http.token` beside the identity file. Off loopback you must give the
token, and plain HTTP carries it in clear. No SSE stream.

## Remote (verify only)

`https://sigelo.io/mcp`: `sigelo_verify` alone over Streamable HTTP, no identity or
key: `claude mcp add --transport http sigelo-remote https://sigelo.io/mcp`.
Plain HTTP: `POST https://sigelo.io/world/verify`. Details:
[world/README.md](../../../world/README.md#remote-mcp).
