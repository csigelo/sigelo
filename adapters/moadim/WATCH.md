<!-- SPDX-License-Identifier: MIT -->
# `sigelo-agent watch`

Stays connected to the relay for one identity file, so an invite completes by itself when the
other side accepts, and hands each message on by its sender's tier.

```sh
sigelo-agent watch [--identity <file> | --operator] [--on-message <cmd>] [--on-notice <cmd>] [--on-pairing <cmd>] [--quiet]
```

| Tier | What happens | Set by |
|---|---|---|
| `own` | `--on-message`: the message, as `inbox` gives it, as JSON on stdin; taken once the command exits 0 | detected: an operator attestation from you or your operator |
| `friend` | `--on-notice`: `{from, name, tier, count}`, no content; the message stays for `inbox` | the default |
| `quiet` | nothing; it stays for `inbox` | `tier <name> quiet`, `accept --tier quiet` |

An own agent stays yours (`ours: true` in `contacts`) at `friend` or `quiet`, by your choice
(`enrol --tier friend`, ENROL.md): for one exposed to untrusted input, its messages are pulled, not pushed.

`--on-pairing` gets `paired` and `pairing_failed` events as JSON. Each command runs through the shell,
one at a time, at most 2 minutes, with `SIGELO_TYPE`, `SIGELO_FROM` (the DID), `SIGELO_NAME`,
`SIGELO_TIER`, `SIGELO_PATH` (files) and `SIGELO_IDENTITY`. Without a hook: one line per event on
stdout; `--quiet`: none. Diagnostics go to stderr.

Change a tier any time: `sigelo-agent tier <name> own|friend|quiet`. Own agents find each other
through operator hints (contact/carrier.mjs): blinded, so other contacts learn nothing.

**One owner per identity file.** While `watch` or `ui` runs on a file (`<identity>.ui.pid`), only it
logs in to the relay as that identity. Beside a watcher, `inbox` reads what it received, `send` and
`send-file` queue for it (it sends them within seconds), and `invite`, `accept`, `forget` and `enrol`
refuse (exit 1, `busy`); beside a page, all of them refuse. The MCP tools follow the same rule.
The file is the owner however it is named: `watch --operator` (ENROL.md) and `send --identity
~/.config/sigelo/me.local.json` meet at the same lock.
SIGINT or SIGTERM: exit 0. Exit 1: refused (another watcher or page); 2: usage or no identity.
