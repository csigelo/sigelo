<!-- SPDX-License-Identifier: MIT -->
# Web Bot Auth: a sigelo agent signs its HTTP requests

[Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) is
Cloudflare's scheme for agents that sign HTTP requests: RFC 9421 signatures with Ed25519, tag
`web-bot-auth`, `keyid` = the RFC 7638 JWK thumbprint, and a `Signature-Agent` header naming the
origin that serves `/.well-known/http-message-signatures-directory`. Here the key is the sigelo
identity key. Read on 2026-10-16: draft-ietf-webbotauth-httpsig-protocol-00 (2026-09-01; it absorbs
the directory draft), Cloudflare's Web Bot Auth docs (updated 2026-10-08), cloudflare/web-bot-auth
at 2e52f5d.

```sh
node sign.mjs GET https://shop.example/ https://agent.example   # through sigelo-agent sign-http
sigelo-agent bundle > bundle.json
node directory.mjs agent.example bundle.json   # { status, headers, body }: serve it at the well-known path
node verify.mjs request.json directory.json https://agent.example
npm test                                       # ALL PASS
```

- **sign.mjs** covers `@authority` and `signature-agent`; `expires` is 60 s on. It sends
  `Signature-Agent: "https://…"`, the form Cloudflare accepts. The draft's `sig1="https://…"` is
  `form: "dictionary"`.
- **directory.mjs** is a JWKS with the current key. After a rotation it also lists the previous
  key for 7 days, with `exp`. The DID and SPEC §8 bundle sit in a top-level `"sigelo"` member.
  RFC 7517 §5 says readers MUST ignore members they do not understand. The directory signature
  covers it.
- **verify.mjs** has two checks. `verify` is plain Web Bot Auth against the directory you
  resolved. `verifyDeep` also verifies the bundle offline: chain, rotation grace from the
  rotation's `iat`, and attestations from an `operator` DID you name.

[`cloudflare-vectors.json`](cloudflare-vectors.json) holds Cloudflare's Ed25519 vectors and the
draft's signed directory (E.2.3). `test.mjs` reproduces them byte for byte. `example/` holds a
signed request and its directory.

## Behind Cloudflare, today

Cloudflare passes `Signature`, `Signature-Input` and `Signature-Agent` to the origin. Your origin,
or a Worker in front of it, fetches the agent's directory once, caches it, and runs `verifyDeep`.
Cloudflare plays no part in this.

Cloudflare's own check needs its registry. Its Verified Bots form (Request Signature) takes the
directory URL; only then does `cf.bot_management.verified_bot` reflect the signature. Nothing
here is registered, verified or listed by Cloudflare.

## Domain separation

A sigelo signing input starts with `sigelo\n` (byte `0x73`, SPEC §3). In an RFC 9421 signature
base every line starts with a quoted component name, so the first byte is always `"` (`0x22`). No
byte string is both, so a signature over one never verifies as the other. The signer enforces
it: `signHttp` (`adapters/moadim/sigelo-agent-keys.ts`) signs only printable ASCII that starts with `"` and ends in `"@signature-params"`, tagged `web-bot-auth` or
`http-message-signatures-directory`. The tests check both directions.

## Limits

- The draft says "SHOULD NOT reuse a signing key for different purposes" (§6.5). The separation
  above is why reusing the key is safe here. It is still a choice against that SHOULD.
- The key agent (K3) signs sigelo bodies only, so `sign-http` needs a `file` or `keychain` key.
- The previous key cannot sign the directory after rotation, because sigelo-agent drops it. It
  is listed without a possession proof. Cloudflare uses only keys that have one.
- `verify.mjs` neither fetches nor tracks nonces.
