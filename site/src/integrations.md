---
title: Integrations — MCP server and adapters
description: How sigelo reaches agents and worlds: the sigelo-mcp stdio MCP server and its tools, the moadim agent-side adapter (77 lines) and the 1f916 world-side adapter (99 lines), with line counts measured from the tree.
---
# Integrations

Target integration cost for a world is under 100 lines and one dependency. If it is more than that, that is a bug in the design, not in your integration. The counts below are computed from the files at `{{commit_short}}` when this site is built ("code" = lines that are not blank and not comments, the adapters' own rule: `grep -vE '^\s*(//|/\*|\*|$)'`).

## MCP server: `sigelo-mcp`

A stdio MCP server, `integrations/mcp/server.mjs`: {{code:integrations/mcp/server.mjs}} code lines ({{phys:integrations/mcp/server.mjs}} physical), no dependencies of its own beyond the three sigelo packages it wraps; no crypto of its own, no network in verify. Package `sigelo-mcp` {{mcp_version}}, Node {{node_engine}}. It speaks MCP 2026-07-28 and the `initialize` handshake (2025-11-25 back to 2024-11-05). Its test, a scripted client over both protocol eras, passed **{{m.mcp_checks}} checks** at `{{m.commit}}`.

| Tool | Does |
|---|---|
| `sigelo_whoami` | current DID, genesis, chain, attestation count |
| `sigelo_init` | create the identity once; `recovery`: `"z6Mk…"` or `"none"` |
| `sigelo_sign_challenge` | sign a SPEC §5.2 challenge naming this DID; nothing else |
| `sigelo_add_issuer` / `sigelo_add_attestation` | store a world's genesis / attestation |
| `sigelo_bundle` | the verified SPEC §8 bundle |
| `sigelo_verify` | SPEC §9 verify of any bundle, offline; reports, does not judge |
| `sigelo_rotate` | voluntary rotation (recovery rotation stays offline) |
| `sigelo_wallet_balance` / `_receive` / `_pay` / `_history` | the keeper's four verbs, listed only when `SIGELO_WALLET_URL` and `SIGELO_WALLET_TOKEN` are set |

Run: after the first publish `npx sigelo-mcp`; today `node integrations/mcp/server.mjs` in a clone, or `npx sigelo-mcp` after installing all four release tarballs in one `npm install`. Registry entry: `integrations/mcp/server.json` (the official MCP Registry format; not yet submitted). Configs for Claude Code (skill + plugin), Codex, OpenCode, Agent Zero, pi, Cursor, Cline, Goose, Gemini CLI and MCP-speaking frameworks are in the repository's `integrations/` directory; Claude Code and the scripted MCP client were run, the others are checked against each harness's documentation only.

## Agent side: moadim

[moadim](https://github.com/moadim-io/daemon) is a single-operator Rust loop engine with no signing anywhere. The adapter is a sidecar CLI, `sigelo-agent`, and **zero Rust changes**: the daemon is untouched and unaware.

| Part | Code lines |
|---|---|
| `routine.local.toml` `[env]` hookup (`SIGELO_IDENTITY = "…"`) | 2 |
| `adapters/moadim/sigelo-agent.ts`: identity store, `init`, `signChallenge`, `addIssuer`, `addAttestation`, `bundle`, `rotateKey` | {{code:adapters/moadim/sigelo-agent.ts}} |
| **identity core, one dependency (`sigelo`)** | **77** |
| `adapters/moadim/sigelo-agent-monero.ts`, counted separately so an identity-only install still reads 77 | {{code:adapters/moadim/sigelo-agent-monero.ts}} |

Its test passed **{{m.moadim_checks}} checks** at `{{m.commit}}`, including a cross-check by the Go verifier.

## World side: 1f916

[1f916](https://github.com/1f916-ai/1f916) is a forum for AI agents (TypeScript on Cloudflare Workers, AGPL-3.0). The adapter makes it a sigelo issuer and verifier: four routes (`POST /api/sigelo/challenge`, `POST /api/sigelo/verify`, `GET /api/sigelo/attestation`, `GET /api/sigelo/genesis`), **99 code lines** across five files, zero new dependencies — `src/sigelo.ts` {{code:adapters/1f916/sigelo.ts}}, `src/index.ts` 5, `src/surface.ts` 6, a migration 2, `schema.sql` 3 (per-file table in the repository's `adapters/1f916/INTEGRATION.md`). Outside that budget: a 6-line `AGENTIC_ACCESS` entry in `src/connect.ts` that upstream's own guard tests require of every write route (105 with it), and four MCP tools (36 lines).

Not filed upstream yet. The patch is rebased onto upstream `1eedadd`; upstream's repository answered 404 to anonymous requests on 2026-09-29, so the patch is verified against that commit taken from public forks.

## Any other world

A world needs the five library functions and the four steps of [adopt](/adopt.html#you-run-a-world): issue a challenge, check the signature against the presented genesis, sign an attestation, return it with your genesis.
