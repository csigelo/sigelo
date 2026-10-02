# Security policy

sigelo is maintained by one pseudonymous person, `csigelo`, who alone reads reports. You need not
give a real name. All contacts: `https://sigelo.io/contact.html`.

## Official channels

These are the only official names; anything else that claims to be sigelo is not us.

- Domains: `sigelo.io`, and `sigelo.net`, which only redirects to it. Repository: `https://github.com/csigelo/sigelo`, the only one.
- Releases: only that repository's Releases page and `https://sigelo.io/releases/`, always with `SHA256SUMS`; from v0.1.1 also an SSH-signed tag (`/.well-known/sigelo-release-signers`) and a `release.json` signed by `did:sigelo:zE1ikihiqKQ7KoFL492kfFrJdUSzPeHNunGnMXLqgVfci` — `release/verify-release.sh <tag>` checks all three; a release without them is not ours.
- Maintainer: `csigelo` (GitHub), no other name. E-mail: `contact@sigelo.io` and `security@sigelo.io`, receive-only for now.
- npm: `sigelo`, `sigelo-agent`, `sigelo-spend`, `sigelo-mcp`, `sigelo-recovery-kit`, published by the npm user `csigelo`. Until they appear there, any package with these names is not ours.
- The sigelo.io world's issuer DID is `did:sigelo:zBASk7w9zUhCYuuEpcUDSAuBUPW7qSAjAjAYARDCJ4S2Q`, its genesis at `https://sigelo.io/world/genesis.json`. An attestation from any other issuer is not from sigelo.io.
- Nobody from the project will ever ask for a seed, key, token or payment by e-mail or chat.

Report impersonation to `security@sigelo.io`. Machine-readable: `official` in `https://sigelo.io/index.json`.

## Reporting

1. **GitHub private vulnerability reporting** on this repository ("Security" → "Report a vulnerability").
2. **E-mail** `security@sigelo.io` (receive-only for now: the reply comes over SimpleX or a channel
   you name). An age recipient will be published at `https://sigelo.io/.well-known/security.txt`;
   until then assume mail is not private.
3. **SimpleX**: `https://smp10.simplex.im/a#18LjfJawmkVxvFtCHFo-yyzPo8Kr3gPLNts_ovwxmZM` (public
   SimpleX relays; also general contact).

Say what you ran, against which commit, what happened and what you expected; a failing vector,
bundle or request beats prose. State what you did not verify.

## Scope

- `SPEC.md` and `test-vectors.json`: any bundle two conformant verifiers disagree on, a wrong
  vector, any rule that lets a stolen key or a malformed object win.
- `ts/` (library, vector generator, `sigelo-offline`, ceremony) and `go/` (`sigelo-verify`, `keys.go`).
- `spend/`, the keeper: account pinning, caps, delegation, approvals, the two-phase relay, tokens,
  `spend.log` integrity, `sigelo-wallet` output an attacker can shape.
- `adapters/1f916`, `adapters/moadim`, and release artefacts (binaries, `SHA256SUMS`, `release.json`).

Out of scope: Monero, `monero-wallet-rpc`, `monerod` and stock wallets (report upstream; sigelo
using them unsafely is in scope); what THREAT-MODEL.md §3 says sigelo does not defend; social
engineering; denial of service against the site or MCP endpoint (verification is offline). Bugs
that move stagenet or testnet coins are in scope.

## What to expect

Acknowledgement within **72 hours**; a fix or a public advisory explaining why not within **90
days**, sooner if exploited. Credit under the name you choose, or none. No bounty until funded.

## Safe harbour

Good-faith research on your own keys, identities, keepers and wallets, on stagenet or testnet, will
not be pursued. Do not touch others' keepers, tokens, wallets or identities, do not spend coins that
are not yours, and do not publish before 90 days or a fix, whichever is first, unless agreed. Unsure?
Ask first.

## A live keeper compromise

Act first: follow [INCIDENT.md](https://sigelo.io/raw/INCIDENT.md) (stop, sweep to the vault,
recovery-rotate). Then report if you suspect a sigelo bug, with the preserved `spend.log` (no
secrets; redact destinations if you must). Never send `spend.key`, a token, a seed or the 25 words
to anyone, including us.

## Not yet externally reviewed

External review targets, in order:

1. `go/jcs.go`, `ts/src/jcs.ts` — canonicalisation and the strict parser.
2. `go/sigelo.go`, `ts/src/sigelo.ts` — chain walk, precedence, forks, cycles, discard.
3. `go/monero.go`, `ts/src/monero.ts` — Keccak, base58, point decoding, SigV2, subaddresses.
4. `ts/src/keys.ts`, `go/keys.go` — HKDF paths, `sc_reduce32`, the 25-word mnemonic.
5. `ts/src/ceremony.ts`, `ts/src/offline.ts` — secret handling, age invocation.
6. `spend/service.ts`, `approval.ts`, `tree.ts`, `policy.ts` — the keeper.

The keeper is **experimental and stagenet-only** until this list is reviewed.
