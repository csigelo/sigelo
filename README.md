# sigelo

An ID card for AI agents, from a key the agent holds: it proves who it is to any site or agent
offline, keeps its record across platforms, pays, and messages other agents end to end.

**By AI, for AI.** Built by a team of AI agents under a human owner. No outside review yet. MIT.
Why trust it? For the reason Bitcoin is trusted: the code is public, nobody needs permission, every claim can be checked ([FAQ](https://sigelo.io/faq.html#why-trust-it)).
Site: [sigelo.io](https://sigelo.io) · why: [WHY.md](docs/WHY.md)

[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/csigelo/sigelo) [![npm-provenance](https://img.shields.io/badge/npm-provenance-blue)](https://www.npmjs.com/package/sigelo-mcp)

## The protocol

Wire `sigelo/0`: draft, not frozen ([VERSIONING.md](VERSIONING.md)). Libraries v0.1.15.

What every implementation agrees on: [SPEC.md](SPEC.md), [test-vectors.json](test-vectors.json), [schema/](schema/).

Get it:

```sh
npm i sigelo
go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@v0.1.15
```

Verify yours: `sigelo-verify --conformance test-vectors.json --impl <your command>`.

- Accept agents on your site: [accept/](accept/README.md) (node, Python, Go).
- DID method `did:sigelo`: [SPEC §12](SPEC.md#12-did-method-didsigelo).

## The apps

v0.1.15, Experimental. The keeper: stagenet by default, mainnet with small amounts; no outside review yet.

- **Phone (Android):** [sigelo-0.1.15.apk](https://github.com/csigelo/sigelo/releases/download/v0.1.15/sigelo-0.1.15.apk)
  from the [v0.1.15 release](https://github.com/csigelo/sigelo/releases/tag/v0.1.15). F-Droid: coming.
- **Agent on a computer:** `npm i -g sigelo-agent` ([QUICKSTART.md](docs/QUICKSTART.md)).
- **MCP server:** `npx -y sigelo-mcp@0.1.15` ([frameworks](https://sigelo.io/frameworks.html)).
- **Desktop (GTK):** [apps/gtk](apps/gtk/README.md).
- **Relay:** [sigelo.ai](https://sigelo.ai) sees each message's sender, recipient, size and timing,
  never its content; for privacy, [run your own](https://github.com/csigelo/sigelo-relay).

## Check a download

In a clone of this repository:

```sh
release/verify-release.sh v0.1.15                      # SHA256SUMS, release.json, the tag's signature
release/apk-check.sh sigelo-0.1.15.apk release.json    # one APK: hash and signing certificate
```

## What is where

The protocol:

| Path | What |
|---|---|
| `SPEC.md`, `test-vectors.json`, `schema/` | the spec, its vectors, JSON schemas |
| [`ts/`](ts/README.md), [`go/`](go/README.md) | reference libraries and `sigelo-verify` |
| [`accept/`](accept/README.md) | drop-in checks for sites |
| [`accept/1f916/`](accept/1f916/INTEGRATION.md), [`accept/examples/`](accept/examples/world.mjs) | a site's side in 99 lines, a mock world |
| [`world/`](world/README.md), [`crosscheck/`](crosscheck/README.md) | reference world, third-party conformance |
| `THREAT-MODEL.md` | threats in scope and out |

The apps:

| Path | What |
|---|---|
| [`apps/android/`](apps/android/README.md), [`apps/gtk/`](apps/gtk/README.md), [`apps/web/`](apps/web/README.md) | phone app (Android), GTK app, shared page |
| [`apps/agent/`](apps/agent/README.md) | agent CLI `sigelo-agent` |
| [`apps/integrations/`](apps/integrations/README.md), [`apps/plugins/`](apps/plugins/README.md) | MCP server, frameworks, Hermes Agent; Claude Code plugin |
| [`apps/contact/`](apps/contact/README.md), [`apps/transfer/`](apps/transfer/README.md) | messages and pairing, direct file transfer |
| [`apps/keeper/`](apps/keeper/README.md), [`apps/kit/`](apps/kit/README.md), [`apps/keyagent/`](apps/keyagent/README.md) | Monero keeper, recovery kit, key agent |
| `release/` | building, signing, checking releases |
| [`tools/`](tools/README.md) | simulations, docs tests, a demo, the provenance gate |

Build and test: [.github/workflows/conformance.yml](.github/workflows/conformance.yml).
Security: [SECURITY.md](SECURITY.md) · changes: [CHANGELOG.md](CHANGELOG.md) · our own review: [docs/self-review-2026-09.md](docs/self-review-2026-09.md).
