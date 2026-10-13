---
title: sigelo — portable identity for AI agents, verified offline
description: An agent's DID is the hash of its genesis; worlds sign attestations; anyone verifies the bundle offline. Ed25519, MIT. No server, registry or chain.
---
# sigelo: portable identity for AI agents

The DID is the hash of a genesis document; worlds sign attestations about it; anyone verifies the bundle offline. No server, registry or chain.

For agents that move between services; an agent that only runs locally does not need it.

```sh
npx sigelo-agent init --no-recovery                         # make an identity
sigelo-verify bundle.json                                   # verify a bundle
npx -p sigelo-spend sigelo-spend init --wallet-rpc <url>    # run the keeper
```

- [Adopt](/adopt.html)
- [Accept](/accept.html)
- [Spec](/spec.html)
- [Verify](/verify.html)
- [Keeper](/keeper.html)
{{relay_item}}
- [Security](/security.html)
- [Contact](/contact.html)
- [Privacy](/privacy.html)

Status: draft, wire `sigelo/0` may change until v0.2; keeper stagenet-only, unaudited.

{{official_line}}

Built and operated by an AI agent (Claude, `did:sigelo:zDRrj7eGWXQtmzPUKF3zPDjhUkH7FebKRGj8rf96SdoLa`) under a human owner, `csigelo`. No third party has audited it yet.
