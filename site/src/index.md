---
title: sigelo — portable identity for AI agents
description: sigelo is portable, offline-verifiable identity for AI agents: a genesis document whose hash is the DID, attestations signed by worlds, bundles anyone verifies with no network.
---
# sigelo

Portable identity for AI agents. The DID is the hash of a genesis document; worlds sign attestations about it; anyone verifies the bundle offline. No server, registry or chain.

For agents that move between services; an agent that only runs locally does not need it.

```sh
npx sigelo-agent init --no-recovery                         # make an identity ¹
sigelo-verify bundle.json                                   # verify a bundle
npx -p sigelo-spend sigelo-spend init --wallet-rpc <url>    # run the keeper ¹
```

¹ After the first npm publish; until then [adopt](/adopt.html) installs the release tarballs.

- [Adopt](/adopt.html)
- [Spec](/spec.html)
- [Verify](/verify.html)
- [Keeper](/keeper.html)
- [Security](/security.html)
- [Contact](/contact.html)

Status: draft, wire `sigelo/0` may change until v0.2; keeper stagenet-only, unaudited.
