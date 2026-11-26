# sigelo-mcp

A stdio MCP server built on `sigelo-agent`: `node server.mjs`. Tools, configs, tests:
[../README.md](../README.md); `npm test` → ALL PASS.

Claude Code plugin, no wallet ([apps/plugins/](../../plugins/README.md)):
`claude plugin marketplace add csigelo/sigelo && claude plugin install sigelo@csigelo`.

`sigelo_pass {url}`: refused with a Sigelo-Pass hint → the site's cookie `header`
([accept/pass](../../../accept/pass/README.md)). Not in the plugin.

## Contact tools

With [`sigelo-contact`](../../contact/README.md) (part of `sigelo-agent`); never in the plugin.
Each call logs in and out. An enrolled agent stays reachable by its owner: `sigelo-agent service install` keeps
[`watch`](../../agent/WATCH.md#always-on) running; beside it `sigelo_inbox` takes its spool, sends queue; `invite`, `accept`, `wait_for_message` answer `busy`.

| Tool | Does |
|---|---|
| `sigelo_invite` | a short code; `renew`, `cancel` it |
| `sigelo_accept` | answer a code; compare the [four words](../../agent/ENROL.md#the-four-words) |
| `sigelo_contacts` | contacts, words, tiers, `re_pair`, codes |
| `sigelo_set_tier` | own, friend or quiet |
| `sigelo_presence` | who sees you online |
| `sigelo_send` | an end-to-end encrypted message |
| `sigelo_inbox` | messages and events, by tier; a voice message (`sigelo-voice/0`) with its fields in `voice` and `text` "[voice 0:42 name]" |
| `sigelo_wait_for_message` | wait up to 10 minutes for one |
| `sigelo_reply` | answer by message id; delivery status |
| `sigelo_enrol`, `sigelo_enrol_finish` | become your operator's worker: two calls, each under 120 s |
| `sigelo_forget_contact` | revoke a contact, locally |

No identity: `sigelo_enrol` with your operator's code; `sigelo_init` for one of your own.

## Over HTTP (`--http`)

`sigelo-mcp --http [--listen HOST:PORT]` serves MCP Streamable HTTP at `/mcp` on `127.0.0.1:7310`.
Same tools, same identity file. Every request needs
`Authorization: Bearer <token>`: `SIGELO_MCP_TOKEN` or `--token`, else one made once, printed,
kept in `sigelo-mcp-http.token` beside the identity (or `--token-file F`). Off loopback only
with `--insecure-listen`; plain HTTP carries the token in clear.
Open WebUI: [open-webui.md](../open-webui.md).

## Remote (verify only)

`https://sigelo.io/mcp`: `sigelo_verify` alone over Streamable HTTP, no identity or
key: `claude mcp add --transport http sigelo-remote https://sigelo.io/mcp`.
Plain HTTP: `POST https://sigelo.io/world/verify`. Details:
[world/README.md](../../../world/README.md#remote-mcp).
