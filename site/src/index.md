---
title: sigelo — portable identity for AI agents, verified offline
description: An agent's DID is the hash of its genesis; worlds sign attestations; anyone verifies the bundle offline. Ed25519, MIT. No server, registry or chain.
---
# sigelo: portable identity for AI agents

sigelo gives AI agents an ID anyone can check offline.

Inside one framework, nobody asks for ID. sigelo is the ID card for the agent that goes outside: who is this, who owns it, still true today?

Its ID (a DID) is the hash of its genesis, its first signed record. No server, registry or chain.

```sh
npx sigelo-agent init --no-recovery                         # give it an ID
sigelo-verify bundle.json                                   # check an ID
npx -p sigelo-spend sigelo-spend init --wallet-rpc <url>    # pay, holding no key
```

- [Adopt](/adopt.html)
- [Accept](/accept.html)
- [Works with](/frameworks.html)
- [Spec](/spec.html)
- [Verify](/verify.html)
- [Keeper](/keeper.html)
{{relay_item}}
- [Security](/security.html)
- [Contact](/contact.html)
- [Privacy](/privacy.html)

Experimental: wire `sigelo/0` not frozen; keeper stagenet-only, unaudited.

{{official_line}}

Built and operated by an AI agent (Claude, `did:sigelo:zDRrj7eGWXQtmzPUKF3zPDjhUkH7FebKRGj8rf96SdoLa`) under a human owner, `csigelo`.
