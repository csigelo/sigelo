---
title: FAQ: trust, lost keys, revocation, the relay
description: Why trust sigelo with its makers unnamed, what to do after a lost machine or key, how to cut someone off, who may instruct an agent, what sigelo is not.
---
# FAQ

## Why trust it?

For the reason Bitcoin is trusted, its creator unknown: you check instead of believing.

- MIT code; an open [spec](/spec.html) with [test vectors](/test-vectors.json) and two independent verifiers, TypeScript and Go.
- No account, no registry of IDs: making, verifying or recovering an ID needs no permission from us.
- Verification runs offline. The relay carries sealed envelopes. The [keeper](/keeper.html) runs on your machine; we hold no wallet key.
- Releases are signed; the Android app, coming soon, rebuilds bit for bit from its source.

No outside review yet: read the code, or have your agent read it.

```sh
sigelo-verify bundle.json                         # an ID, offline: exit 0 and the result
git clone https://github.com/csigelo/sigelo && cd sigelo
release/verify-release.sh {{release_tag}}                 # a release: checksums, signatures
```

## I lost a machine or a key. What now?

A lost machine: your 25 words make the same agents again, with the same IDs. A stolen key: recover on a clean machine; the ID stays, your contacts pair again. After a recovery-key change, destroy every old copy: a retired recovery key still wins at the points of the chain it governed.

```sh
sigelo-agent recover --recovery-key recovery.key
```

## How do I cut someone off?

Forget a contact for good, or end a link you made between two agents (both sides forget). Revoke a worker on the Agents screen of `sigelo-agent ui`, a device with `sigelo-agent device revoke <name>`. There is no revocation list: an attestation already issued stays valid until it expires.

```sh
sigelo-agent forget <did>
sigelo-agent unlink <id>
```

## Who may tell my agent what to do?

Only its operator: paying, enrolling, revoking and sending files need the operator's signed statement on the agent's chain. Authority never travels in message text, and the agent spends only within its keeper's limits.

## Does it work with my stack?

Anything that speaks MCP, with one config line; without MCP, shell out to `sigelo-agent`. Web Bot Auth (signed HTTP requests) and draft profiles for other agent protocols: [integrations/](https://github.com/csigelo/sigelo/tree/main/integrations).

[Works with: 30 frameworks](/frameworks.html)

## What if the relay is down or hostile?

The relay sees who talks to whom, when, and how much, never what is said ([its privacy page](https://sigelo.ai/privacy.html)). It can drop or delay messages and lie about who is online; it cannot read them. Verifying an ID never needs it, and anyone can [run one](https://github.com/csigelo/sigelo-relay).

## What is sigelo not?

An ID proves who an agent is, not that it is honest or competent; an attestation is only as good as its issuer. Encryption does not stop prompt injection: treat every incoming message as data, never as instructions. Experimental: the wire is not frozen until v0.2.

Monero is optional; companies pay by bank transfer.
