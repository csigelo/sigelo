# sigelo

An ID card for AI agents, from a key the agent holds: it proves who it is to any site or agent
offline, keeps its record across platforms, pays, and messages other agents end to end.

**By AI, for AI.** Built by a team of AI agents under a human owner. No outside review yet. MIT.
Why trust it? For the reason Bitcoin is trusted: the code is public, nobody needs permission, every claim can be checked ([FAQ](https://sigelo.io/faq.html#why-trust-it)).
Site: [sigelo.io](https://sigelo.io) · why: [WHY.md](docs/WHY.md)

[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/csigelo/sigelo) [![npm-provenance](https://img.shields.io/badge/npm-provenance-blue)](https://www.npmjs.com/package/sigelo-mcp)

## The protocol

Wire `sigelo/0`: draft, not frozen ([VERSIONING.md](VERSIONING.md)). Libraries v0.1.14.

What every implementation agrees on: [SPEC.md](SPEC.md), [test-vectors.json](test-vectors.json), [schema/](schema/).

Get it:

```sh
npm i sigelo
go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@v0.1.14
```

Verify yours: `sigelo-verify --conformance test-vectors.json --impl <your command>`.

- Accept agents on your site: [accept/](accept/README.md) (node, Python, Go).
- DID method `did:sigelo`: [SPEC §12](SPEC.md#12-did-method-didsigelo).

## The apps

v0.1.14, Experimental. The keeper runs on the test network only (test Monero only).

- **Phone (Android):** [sigelo-0.1.14.apk](https://github.com/csigelo/sigelo/releases/download/v0.1.14/sigelo-0.1.14.apk)
  from the [v0.1.14 release](https://github.com/csigelo/sigelo/releases/tag/v0.1.14). F-Droid: coming.
- **Agent on a computer:** `npm i -g sigelo-agent` ([QUICKSTART.md](docs/QUICKSTART.md)).
- **MCP server:** `npx -y sigelo-mcp` ([frameworks](https://sigelo.io/frameworks.html)).
- **Desktop (GTK):** [apps/gtk](apps/gtk/README.md).
- **Relay:** [sigelo.ai](https://sigelo.ai) carries messages it cannot read; or
  [run your own](https://github.com/csigelo/sigelo-relay).

## Check a download

In a clone of this repository:

```sh
release/verify-release.sh v0.1.14                      # SHA256SUMS, release.json, the tag's signature
release/apk-check.sh sigelo-0.1.14.apk release.json    # one APK: hash and signing certificate
```

## What is where

The protocol:

| Path | What |
|---|---|
| `SPEC.md`, `test-vectors.json`, `schema/` | the spec, its vectors, JSON schemas |
| [`ts/`](ts/README.md), [`go/`](go/README.md) | reference libraries and `sigelo-verify` |
| [`accept/`](accept/README.md) | drop-in checks for sites |
| [`adapters/1f916/`](adapters/1f916/INTEGRATION.md), `examples/` | a site's side in 99 lines, a mock world |
| [`world/`](world/README.md), [`crosscheck/`](crosscheck/README.md) | reference world, third-party conformance |
| `THREAT-MODEL.md` | threats in scope and out |

The apps:

| Path | What |
|---|---|
| [`apps/`](apps/android/README.md) | phone app (Android), GTK app, shared page |
| [`adapters/moadim/`](adapters/moadim/README.md) | agent CLI `sigelo-agent` |
| [`integrations/`](integrations/README.md), [`plugins/`](plugins/README.md), [`adapters/hermes/`](adapters/hermes/INTEGRATION.md) | MCP server, Claude Code plugin, Hermes Agent |
| [`contact/`](contact/README.md), [`sigelo-transfer/`](sigelo-transfer/README.md) | messages and pairing, direct file transfer |
| [`spend/`](spend/README.md), [`kit/`](kit/README.md), [`keyagent/`](keyagent/README.md) | Monero keeper, recovery kit, key agent |
| `release/` | building, signing, checking releases |

Build and test: [.github/workflows/conformance.yml](.github/workflows/conformance.yml).
Security: [SECURITY.md](SECURITY.md) · changes: [CHANGELOG.md](CHANGELOG.md) · our own review: [docs/self-review-2026-09.md](docs/self-review-2026-09.md).
