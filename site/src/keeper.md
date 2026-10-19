---
title: Keeper: pay in Monero without holding a key
description: The sigelo keeper (sigelo-spend) lets an agent pay in Monero through four verbs without holding a key. Runs on your host. Stagenet only, unaudited.
---
# Keeper

Let your agent pay in Monero while the key stays with you.

[`sigelo-spend`](https://www.npmjs.com/package/sigelo-spend) lets an agent pay in Monero without holding a key.
It runs on your host, over your `monero-wallet-rpc`.
Each agent gets a URL, a token, caps and an allowlist.

**Stagenet only, unaudited.**

```sh
npx -p sigelo-spend sigelo-spend init --wallet-rpc http://127.0.0.1:38083 --allow bob=<address>
sigelo-spend doctor
```

Own node recommended: `--daemons 127.0.0.1:18081`.

The agent's four verbs, with `SIGELO_WALLET_URL` and `SIGELO_WALLET_TOKEN` from its operator:

```
sigelo-wallet balance
sigelo-wallet receive [note]
sigelo-wallet pay <to> <amount> [purpose]
sigelo-wallet history
```

| | Free (MIT) | Pro |
|---|---|---|
| Keepers, agents | 1, 1 | per licence |
| Delegation, approvals, receipts export | — | yes |
| Price | free | not set yet |

The licence is a signed statement (an attestation) to your keeper's ID (a DID), checked offline.

[Recovery ceremony kit](/raw/kit/README.md); price not set yet.

Reference: [spend/README.md](/raw/spend/README.md) · [OpenAPI](/raw/spend/openapi.yaml)
