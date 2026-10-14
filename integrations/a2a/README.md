<!-- SPDX-License-Identifier: MIT -->
# A2A AgentCard: a sigelo profile (draft)

**Profile draft, not an A2A standard.** How an [A2A](https://a2a-protocol.org/latest/specification/)
1.0 AgentCard carries a sigelo DID and bundle, signed by the identity key. Checked against
`specification/a2a.proto` on 2026-10-14 (`AgentCapabilities.extensions`, `AgentExtension
{uri, description, required, params}`).

## Shape

One entry in `capabilities.extensions` ([example-card.json](example-card.json)):

```json
{ "uri": "https://github.com/csigelo/sigelo/tree/main/integrations/a2a",
  "description": "sigelo identity: DID, bundle, card signature (profile draft)",
  "required": false,
  "params": { "did": "<current DID>", "bundle": { <SPEC §8 bundle> }, "sig": "z…" } }
```

`sig` is `sign(identity key, body)` (SPEC §3: `"sigelo\n" || JCS(body)`) over

```json
{ "v": "sigelo/0", "typ": "a2a-card", "did": "<current DID>", "card": "sha256:<hex>" }
```

where `<hex>` = SHA-256 of JCS(the card without its top-level `signatures` and without this
`params.sig`). So A2A's own JWS `signatures` can be added after, and every other card field is covered.

## Use

```sh
npm i
sigelo-agent bundle > bundle.json
node sign.mjs card.json bundle.json > signed-card.json   # key from $SIGELO_IDENTITY
node verify.mjs signed-card.json                          # SPEC §9.1 result, or throws
npm test                                                  # ALL PASS
```

`verify.mjs` (30 lines, published `sigelo` package): one sigelo extension, `verify(bundle)`
offline, `did` = the bundle's current DID, `sig` checked with that DID's key. It reports; whom
to trust is the caller's call.

## Limits

- `typ: "a2a-card"` is not in SPEC §3.1: no sigelo verifier accepts this signature in any other
  slot, and `sigelo-agent sign-challenge` will not produce it (`sign.mjs` reads the key file).
- A card signature proves the key holder published this card, not that the endpoint is theirs.
  For a live caller, run a §5.2 challenge ([accept/](../../accept/README.md)).
- After a rotation, re-sign the card. A float anywhere in the card makes it unsignable (SPEC §3).
