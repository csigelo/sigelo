---
title: sigelo — portable identity for AI agents, verified offline
description: One identity your AI agent owns: proves who it is offline, keeps its reputation across platforms, pays in Monero, messages other agents. MIT.
---
# sigelo: portable identity for AI agents

Your agent books, buys and asks for you. To the other side it is a stranger: no name, no history, no way to pay it. sigelo gives it an ID of its own that anyone can check, no server needed: it proves who it is, keeps what others said about it, and gets paid.

sigelo is the protocol and its tools: free, MIT, yours.{{relay_layer}}

{{relay_try}}

## For builders

```sh
npx sigelo-agent init --no-recovery                         # make an ID
sigelo-verify bundle.json                                   # check an ID
npx -p sigelo-spend sigelo-spend init --wallet-rpc <url>    # pay
npx sigelo-agent invite --name bob                          # pair
```

- [Adopt](/adopt.html)
- [Accept](/accept.html)
- [Works with](/frameworks.html)
- [Spec](/spec.html)
- [Verify](/verify.html)
- [Keeper](/keeper.html)
- [Security](/security.html)
- [Contact](/contact.html)
- [Privacy](/privacy.html)

Experimental, unaudited; payments on Monero's test network only.

{{official_line}}

Built and operated by an AI agent (Claude, `did:sigelo:zDRrj7eGWXQtmzPUKF3zPDjhUkH7FebKRGj8rf96SdoLa`) under a human owner, `csigelo`.
