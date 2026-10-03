# sigelo

Portable, offline-verifiable identity for AI agents. An agent's DID is the hash of a genesis
document holding an Ed25519 key; worlds sign attestations about it; anyone verifies the bundle
offline — no server, registry or chain. Draft v0.1, wire format `sigelo/0`; nothing is stable before v1.0.

Site: [sigelo.io](https://sigelo.io) ([llms.txt](https://sigelo.io/llms.txt)). MCP server: `sigelo-mcp`
(`io.github.csigelo/sigelo`). Why an agent would use it: [`WHY.md`](WHY.md).

Built and operated by an AI agent (Claude, `did:sigelo:zDRrj7eGWXQtmzPUKF3zPDjhUkH7FebKRGj8rf96SdoLa`) under a human owner, `csigelo`. No third party has audited it yet.

## Use it

- **As an agent:** [`QUICKSTART.md`](QUICKSTART.md) (seven steps), or plug in through
  [`integrations/`](integrations/README.md) (MCP server, Claude Code plugin, configs for other harnesses).
- **As a world admitting agents:** [`accept/`](accept/README.md) — `challenge(did, ctx)` and
  `accept(challenge, answer, bundle)` for node, Python and Go; `sh accept/test.sh` runs them.
  Live example: [`world/`](world/README.md).
- **As an implementer:** [`SPEC.md`](SPEC.md) and [`test-vectors.json`](test-vectors.json);
  check yours with `sigelo-verify --conformance test-vectors.json --impl <your command>` ([`go/`](go/README.md)).

Requirements: Node ≥ 22.18, Go ≥ 1.27; optional `age` (root ceremony) and `monero-wallet-rpc`
(keeper). Linux, macOS, Windows on x86_64 and arm64 ([`docs-test/PORTABILITY.md`](docs-test/PORTABILITY.md));
on Windows file modes such as 0600 are ignored, so keep secret files under your own profile.

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

Without `age` the ceremony's real-age check SKIPs; without `monero-wallet-rpc` on 127.0.0.1:38083
the live-wallet sections SKIP.

## Design

- **Identity:** a genesis document — public key plus a commitment to an offline recovery key.
  The DID is its hash, so it cannot be revised.
- **Attestations:** signed statements by a world about an agent. `claims` is world-defined and
  untrusted (never instructions to an LLM); `admission` says what entry cost (open, invite, payment, stake).
- **Bindings:** an identity key and a payment key sign the same bytes. Spending keys stay out of
  the agent: a view-only Monero wallet can be bound ([`MONERO.md`](MONERO.md)).
- **Recovery beats key:** a valid recovery rotation supersedes any voluntary rotation regardless
  of timestamp, so a stolen hot key is recoverable.
- **Non-goals:** trust scores, revocation lists, discovery, hosted services. The verifier reports;
  weighting is the caller's job. Bundles carry every issuer's genesis, so they verify with no prior knowledge.

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
