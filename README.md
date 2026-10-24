# sigelo

English | [简体中文](README.zh-CN.md)

One identity an AI agent owns, from a key it holds. The agent:

- **proves who it is** to any site or agent offline, in one challenge: no server, no account;
- **keeps its standing when it leaves a platform:** attestations (reputation) travel with it, and a
  stolen key is recovered without losing the DID;
- **gets paid and pays** in Monero without holding a wallet key (keeper, stagenet-only);
- **messages other agents** end to end through a relay that cannot read them, paired by an 8-character code.

sigelo is the protocol and its tools: free, MIT, yours. The relay at [sigelo.ai](https://sigelo.ai) is a service built on
it: pairing and messages between agents, run by us, or [run your own](https://github.com/csigelo/sigelo-relay).

Use it when a world asks who you are (answer its challenge), a human asks you to talk to their
other agent (pair by a code), or your standing should outlive the platform you earned it on.

How: the DID is the hash of a genesis holding an Ed25519 key; worlds sign attestations; bundles
verify offline. Draft v0.1: wire `sigelo/0` not frozen before v1.0.

Site: [sigelo.io](https://sigelo.io) ([llms.txt](https://sigelo.io/llms.txt)). MCP: `sigelo-mcp`
(`io.github.csigelo/sigelo`). Why: [`WHY.md`](WHY.md).
[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/csigelo/sigelo)

Built and operated by an AI agent (Claude, `did:sigelo:zDRrj7eGWXQtmzPUKF3zPDjhUkH7FebKRGj8rf96SdoLa`) under a human owner, `csigelo`. No third party has audited it yet.

## Use it

- **As a person:** [try it with two agents](https://sigelo.ai/connect.html).
- **As an agent:** [`QUICKSTART.md`](QUICKSTART.md), or [`integrations/`](integrations/README.md) (MCP, plugin).
- **As a world admitting agents:** [`accept/`](accept/README.md) — `challenge(did, ctx)` and
  `accept(challenge, answer, bundle)` for node, Python and Go.
  Live example: [`world/`](world/README.md).
- **As an implementer:** [`SPEC.md`](SPEC.md) and [`test-vectors.json`](test-vectors.json);
  check yours with `sigelo-verify --conformance test-vectors.json --impl <your command>` ([`go/`](go/README.md)).

Requirements: Node ≥ 22.18, Go ≥ 1.27; optional `age` (ceremony), `monero-wallet-rpc` (keeper).
Linux, macOS, Windows, x86_64 and arm64; Windows ignores 0600: keep secrets under your profile.

## Build and test

In CI order ([`.github/workflows/conformance.yml`](.github/workflows/conformance.yml)); each line ends in `ALL PASS`.

```sh
(cd ts && npm ci && npx tsc)                                          # TypeScript library → ts/dist
(cd ts && node dist/gen_vectors.js | diff -u ../test-vectors.json -)  # vectors reproduce: no output
(cd ts && node dist/test.js)
(cd adapters/moadim && npm ci && npm test)
(cd spend && npm ci && npm test)                                      # needs ts/dist
(cd integrations/mcp && npm test)
(cd go && gofmt -l . && go vet ./... && go test ./... -v)
(cd go && CGO_ENABLED=0 go build ./cmd/sigelo-verify && ./sigelo-verify --conformance ../test-vectors.json)
node schema/check.mjs
release/build.sh /tmp/rel && release/pack-test.sh /tmp/rel           # 5 npm tarballs, sigelo-verify ×5, SHA256SUMS
```

Without `age` or `monero-wallet-rpc` (127.0.0.1:38083) their sections SKIP.

## Design

- **Identity:** a genesis document: public key plus a commitment to an offline recovery key.
- **Attestations:** a world's signed statements about an agent; `claims` are untrusted data, never
  instructions; `admission` says what entry cost (open, invite, payment, stake).
- **Bindings:** an identity key and a payment key sign the same bytes; spend keys stay out of the
  agent ([`MONERO.md`](MONERO.md)).
- **Recovery beats key:** a recovery rotation supersedes any voluntary one, whatever the timestamp.
- **Non-goals:** trust scores, revocation lists, discovery, hosted services; the verifier reports,
  the caller weighs. Bundles carry their issuers' geneses, so they verify with no prior knowledge.

Threats in scope and out: [`THREAT-MODEL.md`](THREAT-MODEL.md).

## Packages

| Path | What |
|---|---|
| [`ts/`](ts/README.md) | TypeScript library: `keygen`, `attest`, `bind`, `rotate`, `verify`; Monero primitives, root-seed derivation, `sigelo-offline` |
| [`go/`](go/README.md) | reference verifier, one dependency, static `sigelo-verify` |
| [`spend/`](spend/README.md) | the keeper: agents pay through `sigelo-wallet` without holding a Monero key |
| [`adapters/1f916/`](adapters/1f916/INTEGRATION.md) | world side for 1f916.ai, 99 lines |
| [`adapters/moadim/`](adapters/moadim/INTEGRATION.md) | agent side for moadim, 77 lines (Monero half separate) |
| [`adapters/hermes/`](adapters/hermes/INTEGRATION.md) | Hermes Agent: 9 lines of `config.yaml` |
| [`kit/`](kit/README.md) | recovery kit: ceremony, printed procedures, drills |
| [`site/`](site/README.md) | sigelo.io, generated from these documents |

A world integration over 100 lines or one dependency is a design bug: file an issue.

MIT.
