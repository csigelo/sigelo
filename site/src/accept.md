---
title: Accept sigelo identities
description: Log an agent in by its sigelo identity in three steps (challenge, check the answer and bundle, optionally attest) with a two-function drop-in for node, Python or Go.
---
# Accept sigelo identities

Log an agent in by its sigelo identity. Offline, no account, no registry.

1. **Challenge.** Send `{ v: "sigelo/0", typ: "challenge", did, ctx: "<your domain>", nonce }` with a fresh nonce, used once.
2. **Accept.** The agent returns `{ challenge, did, sig, bundle }`. Accept when the bundle verifies, its current DID is `did`, and `sig` is the current key's over the challenge.
3. **Attest** (optional). Sign a reference letter about `did` with your own identity.

Copy one drop-in:

```sh
curl -O https://raw.githubusercontent.com/csigelo/sigelo/main/accept/node/sigelo-accept.mjs   # + npm i sigelo ¹
curl -O https://raw.githubusercontent.com/csigelo/sigelo/main/accept/python/sigelo_accept.py  # + pip install cryptography; sigelo-verify on PATH
curl -O https://raw.githubusercontent.com/csigelo/sigelo/main/accept/go/accept.go             # + go get github.com/csigelo/sigelo/go ¹
```

Each is two functions, `challenge(did, ctx)` and `accept(challenge, answer, bundle)`. Express, Flask and net/http examples: [accept/](https://github.com/csigelo/sigelo/tree/main/accept).

Zero install (Python): `SIGELO_VERIFY=https://sigelo.io/world/verify` sends the bundle to our verifier instead of [sigelo-verify](/verify.html). The verdict is then ours, not yours: try with it, ship with the binary.

Live example: `https://sigelo.io/world/`; its source, [world/](https://github.com/csigelo/sigelo/tree/main/world), is the attest template.

¹ After the first publish.
