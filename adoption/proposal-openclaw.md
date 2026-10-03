<!-- SPDX-License-Identifier: MIT -->
<!-- Draft, not posted. Venue: https://github.com/openclaw/openclaw/issues/new?template=feature_request.yml
Title: "[Feature]: let a plugin resolve A2A peers, so a peer can prove a key-based identity instead of holding a shared token" -->

## Problem

`extensions/a2a/src/http.ts` (read at c52a2778, 2026-10-03) authenticates an A2A peer in one
way. `resolvePeerName` hashes the Bearer token and compares it with each `channels.a2a.peers.<name>.token`.
When none matches, the request gets a 401 before any plugin hook runs. A peer is therefore whoever
holds a secret shared by two gateways, and that secret tells a third gateway nothing.

#49971 asked for identity in core. It was closed on 2026-04-25 with "the plugin layer is the
right home". That works for tools and installs. It does not work here, because no plugin can
reach the A2A 401.

## Proposal

Add one resolver hook to the A2A channel. A plugin can then admit a peer by a key-based DID in
one extra round trip. The plugin serves `GET /a2a/peer-auth/challenge?did=` and returns
`{v, typ, did, ctx, nonce}` (single use, five minutes). The peer posts `{challenge, did, sig, bundle}`.
The plugin verifies it offline and mints a short-lived token named after the DID. After that the
existing path runs unchanged, and logs, rate limits and routing key on the DID.

```ts
// plugin side, not core: the two calls exist today (accept/node/sigelo-accept.mjs)
import { challenge, accept } from "./sigelo-accept.mjs";
const tokens = new Map<string, { did: string; exp: number }>();

api.registerHttpRoute({ path: "/a2a/peer-auth", auth: "plugin", handler: async (req, res) => {
  if (req.method === "GET") return json(res, challenge(query(req).did, "gateway.example"));
  const b = await body(req);
  const { did } = accept(b.challenge, b, b.bundle);        // offline; throws on any failure
  const t = randomToken(); tokens.set(t, { did, exp: Date.now() + 3600e3 });
  json(res, { token: t });
}});
registerA2aPeerResolver((token) => {                       // the one new core surface
  const e = tokens.get(token); return e && e.exp > Date.now() ? e.did : undefined;
});
```

## What it is not

It holds no custody and uses no token or coin. Verification makes no network call. No service is
needed, so nothing breaks if sigelo.io goes away. The code is MIT with no dependency beyond node,
and it would ship as a ClawHub plugin. OpenClaw is already an MCP client, so the agent side is
config only.

## Smallest step

`resolvePeerName` consults resolvers registered through the channel runtime after the configured
tokens fail. With no resolver registered, nothing changes. That is about 30 lines in `http.ts` and
`runtime.ts`, plus tests in `http.test.ts`. I'll write the PR if this shape is acceptable.
