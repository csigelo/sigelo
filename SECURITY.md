# Security policy

sigelo is maintained by one pseudonymous person, `csigelo`. Nobody here will ask for your real name, and
you need not give one. Reports are read by that maintainer only.

> **Draft.** Decided at D1 (2026-10-01): the pseudonym and GitHub account `csigelo`
> (`https://github.com/csigelo/sigelo`), the domain sigelo.io, `security@sigelo.io` for
> reports and `contact@sigelo.io` for anything that is not a vulnerability — both mailboxes
> exist and are read — and a SimpleX contact address for both. Still `<angle brackets>`: the
> age recipient and the SimpleX address itself. Until the repository is public, e-mail is the
> working channel. All contacts: `https://sigelo.io/contact.html`.

## Reporting

In order of preference:

1. **GitHub private vulnerability reporting** on this repository ("Security" → "Report a
   vulnerability"). No account linkage beyond your GitHub handle.
2. **Email** `security@sigelo.io` — received and read, but **receive-only for now**: there is no sigelo.io
   sender yet, so the reply comes over SimpleX (channel 3) or to a channel you name in the report.
   Encrypted to this age recipient once it is published:
   `age1<to-be-filled-at-D1>` — also published at `https://sigelo.io/.well-known/security.txt`
   (RFC 9116). Unencrypted mail is read, but assume it was not private.
3. **SimpleX**: `https://smp10.simplex.im/a#18LjfJawmkVxvFtCHFo-yyzPo8Kr3gPLNts_ovwxmZM`. The address lives on public SimpleX relays, not on a
   server this project runs, and the same address also serves general contact
   (`https://sigelo.io/contact.html`).

Say what you ran, against which commit, what happened and what you expected. A failing
vector, bundle or request is worth more than prose. State what you did not verify.

## Scope

- `SPEC.md` and `test-vectors.json`: any bundle two conformant verifiers disagree on, any
  vector that is wrong, any rule that lets a stolen key or a malformed object win.
- `ts/` (the library, the vector generator, `sigelo-offline` and the ceremony) and `go/`
  (the reference verifier, `sigelo-verify`, `keys.go`).
- `spend/`, the keeper: account pinning, caps, the delegation tree, approvals, the two-phase
  relay, tokens, `spend.log` integrity, `sigelo-wallet` output an attacker can shape.
- `adapters/1f916` and `adapters/moadim`.
- Release artefacts once they exist: binaries, `SHA256SUMS`, the signed release object.

## Out of scope

- Monero itself, `monero-wallet-rpc`, `monerod`, and stock wallets. Report those upstream
  (Monero's own disclosure process). If sigelo *uses* them unsafely, that is in scope.
- Stagenet or testnet coins: they have no value; a bug that moves them is still in scope.
- Things THREAT-MODEL.md §3 already says sigelo does not defend: Sybil, lying issuers,
  collusion rings, the operator behind an agent, signer-asserted timestamps.
- Social engineering of the maintainer, and denial of service against infrastructure that
  sigelo does not need (the site, the MCP endpoint: verification is offline by design).

## What to expect

- Acknowledgement within **72 hours**.
- A fix, or a public advisory saying why there is none, within **90 days**. Sooner if it is
  exploited or trivially exploitable.
- Credit in the advisory and CHANGELOG under the name you choose, or none.
- No bounty until there is funding for one. That will be announced here, not promised.

## Safe harbour

Good-faith research on your own keys, identities, keepers and wallets, on stagenet or
testnet, is welcome and will not be pursued in any way. Do not touch other people's keepers,
tokens, wallets or identities, do not spend coins that are not yours, and do not publish
before the 90 days are up or a fix ships, whichever comes first, unless we agree otherwise.
If you are unsure whether something is in bounds, ask first through any channel above.

## A live keeper compromise

If you run a keeper and believe its host, a token or `spend.key` is compromised, act first:
follow **INCIDENT.md** (stop, sweep to the vault, recovery-rotate, report). Report to us
afterwards if you suspect a sigelo bug caused it, with the preserved `spend.log` (it holds no
secrets; it names destinations, amounts and purposes, so redact what you must). Never send
`spend.key`, a token, a seed or the 25 words to anyone, including us.

## Known unaudited areas

Nothing here has been reviewed by anyone outside the project; every review so far was done
by Claude models. External review targets, in priority order (ROADMAP §5.4):

1. `go/jcs.go`, `ts/src/jcs.ts` — canonicalisation and the strict parser.
2. `go/sigelo.go`, `ts/src/sigelo.ts` §9 — chain walk, precedence, forks, cycles, discard.
3. `go/monero.go`, `ts/src/monero.ts` — Keccak, base58, point decoding, SigV2, subaddresses.
4. `ts/src/keys.ts`, `go/keys.go` — HKDF paths, `sc_reduce32`, the 25-word mnemonic.
5. `ts/src/ceremony.ts`, `ts/src/offline.ts` — secret handling, age invocation.
6. `spend/service.ts`, `approval.ts`, `tree.ts`, `policy.ts` — the keeper.

The keeper is **experimental and stagenet-only** until this list is reviewed.
