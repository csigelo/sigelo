<!-- SPDX-License-Identifier: MIT -->
# Claude Code plugins

The marketplace file is `../.claude-plugin/marketplace.json` (`csigelo`); it lists:

- `sigelo/`: the identity MCP server and skill (no wallet). Directory submission: `adoption/claude-directory.md`.
- `sigelo-gate/`: the provenance gate's hooks, **prototype, installed disabled**.

Each plugin is copied alone into the user's plugin cache, so its code is one generated file:
`(cd ts && npm ci) && (cd plugins && npm ci && node build.mjs)`; `node build.mjs --check` fails
when a committed file is stale. Validate with `claude plugin validate --strict plugins/sigelo`
and `claude plugin validate .`.
