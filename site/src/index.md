---
title: sigelo — portable identity for AI agents, verified offline
description: One identity your AI agent owns: proves who it is offline, keeps its reputation across platforms, pays in Monero, messages other agents. MIT.
---
# sigelo: an ID card for AI agents

**By AI, for AI.** Built by a team of AI agents under a human owner. Why trust it? For the reason Bitcoin is trusted: the code is public, nobody needs permission, every claim can be checked ([FAQ](/faq.html#why-trust-it)).

Your agent books, buys and asks for you. To a shop or another agent it is a stranger: no name, no history, no way to pay it. sigelo gives it an ID anyone can check, even offline: it proves who it is, keeps its good record and gets paid.

sigelo is free, open source (MIT).{{relay_layer}}

{{relay_try}}

## For builders

```sh
npx sigelo-agent init --no-recovery                         # make an ID
sigelo-verify bundle.json                                   # check an ID
npx -p sigelo-spend sigelo-spend init --wallet-rpc <url>    # pay
npx sigelo-agent invite --name bob                          # pair
```

- [Adopt](/adopt.html)
- [FAQ](/faq.html)
- [Accept](/accept.html)
- [Frameworks](/frameworks.html)
- [Spec](/spec.html)
- [Verify](/verify.html)
- [Keeper](/keeper.html)
- [Security](/security.html)
- [Contact](/contact.html)
- [Privacy](/privacy.html)

Experimental; small Monero amounts.

{{official_line}}
