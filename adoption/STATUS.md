<!-- SPDX-License-Identifier: MIT -->
# Listings and proposals: status

One row per place sigelo is listed or proposed. States: **filed** (submitted, waiting on the
other side), **prepared** (branch or text ready, not submitted), **blocked** (needs something
first), **live**. Dates are UTC.

| What | Where | URL | Date | State |
|---|---|---|---|---|
| Hermes A2A peer-auth hook | NousResearch/hermes-agent issue | https://github.com/NousResearch/hermes-agent/issues/131484 | 2026-10-02 | filed |
| Hermes contacts RFC: pairing fixture | NousResearch/hermes-agent#132248 (kvnloo) | https://github.com/NousResearch/hermes-agent/issues/132248#issuecomment-5971957901 | 2026-10-03 | posted: opener + fixture link (adapters/hermes/pairing) |
| OpenClaw A2A peer resolver hook | openclaw/openclaw#164508 | https://github.com/openclaw/openclaw/issues/164508 | 2026-10-03 | filed (PR offered) |
| Directory entry (stdio + remote) | mcpservers.org free form | submission #9488, contact@sigelo.io | 2026-10-03 | filed (free review, up to 2 weeks) |
| Directory entry (stdio + remote) | mcp.so, issue route | https://github.com/chatmcp/mcpso/issues/4636 | 2026-10-03 | filed |
| `🪪 Identity` entry | punkpeye/awesome-mcp-servers | branch https://github.com/csigelo/awesome-mcp-servers/tree/add-sigelo | 2026-10-03 | prepared; blocked on Glama |
| `🔒 Security` remote entry | punkpeye/awesome-remote-mcp-servers | text below | 2026-10-03 | prepared; blocked on a Glama connector |
| `did:sigelo` registration | w3c/did-extensions | OPENED 2026-10-03: https://github.com/w3c/did-extensions/pull/764 — automated checklist: all MUST/SHOULD pass (2026-10-03); editor review pending
| Official MCP Registry | registry.modelcontextprotocol.io | `io.github.csigelo/sigelo` | — | blocked: npm, or a remote-only version (below) |
| Claude Code marketplace `csigelo` (`sigelo`, `sigelo-gate` prototype) | own marketplace, `.claude-plugin/marketplace.json` | `claude plugin marketplace add csigelo/sigelo` | 2026-10-03 | prepared; installs tested from a local copy; live after `release/publish.sh` + push |
| Plugin bundle `sigelo` (no wallet) | Anthropic directory, claude.ai/directory/manage | [claude-directory.md](claude-directory.md) §B | 2026-10-03 | prepared; blocked on Owner: submitting account, GitHub link, icon; mirror push |
| MCP connector `https://sigelo.io/mcp` | Anthropic directory, claude.ai/directory/manage | [claude-directory.md](claude-directory.md) §A | 2026-10-03 | prepared; blocked on tool `title`/`readOnlyHint` in world/mcp.mjs, then Owner |
| Glama server + connector | glama.ai | glama.ai/mcp/servers, glama.ai/mcp/connectors | — | needs a Glama sign-in |
| Smithery | smithery.ai | smithery.ai/new | — | needs a Smithery sign-in |
| PulseMCP | pulsemcp.com | — | — | none: ingests the official registry (submissions paused, 2026-09-03) |
| Proposals: MPP, x402, LangGraph | — | `proposal-*.md` here | 2026-10-03 | prepared, not posted |

## Why the awesome lists wait

Both lists require a Glama score badge, and their CI labels a PR without one `missing-glama`.
Of the last 200 closed PRs on awesome-mcp-servers (read 2026-10-03), every merged one carried
`has-glama`, and 53 `missing-glama` PRs were closed without merging. awesome-remote-mcp-servers
also requires that the opening account has starred the repository. Order: Glama lists the
server, then the badge resolves, then the PR opens:

```sh
gh pr create -R punkpeye/awesome-mcp-servers --head csigelo:add-sigelo --title "Add csigelo/sigelo (Identity)" \
  --body "Agent identity: DID, challenges, attestations, offline bundle verification. MIT, zero dependencies."
```

Remote entry, once the connector exists (Security, alphabetical before Semgrep):

```markdown
- [sigelo](https://sigelo.io) `https://sigelo.io/mcp`
  [![sigelo MCP connector](https://glama.ai/mcp/connectors/NAMESPACE/NAME/badges/score.svg)](https://glama.ai/mcp/connectors/NAMESPACE/NAME)
  🔓 - Verify an AI agent's identity bundle (DID, rotations, attestations) offline; holds no keys.
```

## Official MCP Registry

The `packages` entry in `integrations/mcp/server.json` points at npm `sigelo-mcp`, which is not
published, and the registry checks it. Publishing needs only the csigelo GitHub login
(`mcp-publisher login github`). Two ways:

1. After npm: `mcp-publisher publish` in `integrations/mcp/` as it is.
2. Now: publish a copy without `packages` (remote only). Versions are immutable, so the npm
   release would then need the next version number. Glama imports connectors from the registry,
   which would unblock both awesome lists.

## DID registry

The PR needs: the JSON entry (done), the PR template's checklist, and a specification URL the AI
reviewer can fetch with syntax, CRUD, Security and Privacy sections (SPEC §12.1–§12.7). Then
two editor reviews and 7–30 days. Command, once `https://sigelo.io/spec.html#12-did-method-didsigelo`
serves §12:

```sh
gh pr create -R w3c/did-extensions --head csigelo:add-did-sigelo --title "Register did:sigelo" --body-file adoption/did-pr-body.md
```
