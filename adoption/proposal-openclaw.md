<!-- SPDX-License-Identifier: MIT -->
<!-- POSTED 2026-10-03 as https://github.com/openclaw/openclaw/issues/164508. Venue: https://github.com/openclaw/openclaw/issues/new?template=feature_request.yml
Title: "[Feature]: a resolver hook for A2A peers, so a plugin can admit a peer by a key it proves" -->

## Problem

`extensions/a2a/src/http.ts` (read at c52a2778, 2026-10-03) knows a peer in one way: `resolvePeerName`
hashes the Bearer token and compares it with each `channels.a2a.peers.<name>.token`. No match is a 401
before any plugin hook runs. So a peer is whoever holds a secret shared by two gateways, and a third
gateway learns nothing from it.

#49971 asked for identity in core and was closed (2026-04-25): "the plugin layer is the right home".
Agreed. But no plugin can reach this 401, so the plugin layer cannot do it today.

## Smallest step

When the configured tokens do not match, `resolvePeerName` asks resolvers registered through the
channel runtime; the first non-empty name wins. With no resolver registered, nothing changes.

```ts
registerA2aPeerResolver((token: string): string | undefined => myTokens.get(token));
```

About 30 lines in `http.ts` and `runtime.ts`, plus tests in `http.test.ts`. I'll write the PR if
this shape is acceptable.

## What a plugin does with it

Admit a peer by a key it proves: challenge, signed answer, offline check, then mint a short-lived
token named after the peer's DID and register it. Logs, rate limits and routing then key on the
DID instead of a shared secret. One working example, 50 lines over the existing route API, is in
`accept/node` at github.com/csigelo/sigelo; any other key scheme fits the same hook.

Not in scope: custody, tokens or coins, any network call during verification, any new service.

Prepared with AI assistance.
