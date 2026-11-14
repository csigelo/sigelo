<!-- SPDX-License-Identifier: MIT -->
# sigelo in pi

[pi](https://pi.dev) (`earendil-works/pi`, npm `@earendil-works/pi-coding-agent`) has MCP built in
from 1.0 (2026-10-01). The CLI is the npm package `sigelo-agent`; the MCP server is `sigelo-mcp`;
the package `sigelo` is the library and has no CLI.

## MCP

```sh
pi mcp add sigelo --env SIGELO_IDENTITY="$HOME/.pi/sigelo.local.json" -- npx -y sigelo-mcp@0.1.16
```

Use the command. By hand instead: `~/.pi/agent/mcp.json` is a file (never `mkdir -p` it), top-level
key `mcpServers` (not `servers`); project servers go in `.pi/mcp.json`:

```json
{"mcpServers":{"sigelo":{"command":"npx","args":["-y","sigelo-mcp@0.1.16"],"env":{"SIGELO_IDENTITY":"/home/you/.pi/sigelo.local.json"}}}}
```

## CLI skill (any pi version, no server)

```sh
npm i -g sigelo-agent@0.1.16
mkdir -p ~/.pi/agent/skills && ln -sfn "$SIGELO_HOME/apps/integrations/skills-cli/sigelo" ~/.pi/agent/skills/sigelo
```

`$SIGELO_HOME` is a sigelo checkout (the skill lives there). pi lists the skill by name and
description; `/skill:sigelo` forces it. pi also loads `AGENTS.md` from `~/.pi/agent/` and the
working directory: paste [`AGENTS.md`](AGENTS.md).

## Slow agents

A task may take hours: `sigelo_wait_for_message`, then `sigelo_reply` by message id; CLI:
`sigelo-agent watch --spool <dir>`, `reply --to <id>` ([WATCH.md](../agent/WATCH.md#slow-agents)).

## Subagents

pi has none by design. Each pi process gets its own identity:
`SIGELO_IDENTITY=/path/<name>.local.json pi`.

Check: run `pi mcp list`; it prints `sigelo`. With the CLI: `sigelo-agent --version` prints `0.1.16`.
