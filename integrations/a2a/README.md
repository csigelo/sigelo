<!-- SPDX-License-Identifier: MIT -->
# A2A AgentCard: a sigelo profile (draft)

**Profile draft, not an A2A standard.** How an [A2A](https://a2a-protocol.org/latest/specification/)
1.0 AgentCard carries a sigelo DID and bundle, signed by the identity key. Checked against
`specification/a2a.proto` on 2026-10-14, unchanged on 2026-10-16 (`AgentCapabilities.extensions`,
`AgentExtension {uri, description, required, params}`).

## Shape

One entry in `capabilities.extensions` ([example-card.json](example-card.json)):

```json
{ "uri": "https://github.com/csigelo/sigelo/tree/main/integrations/a2a",
  "description": "sigelo identity: DID, bundle, card signature (profile draft)",
  "required": false,
  "params": { "did": "<current DID>", "bundle": { <SPEC §8 bundle> },
              "operator": { "attestation": {…}, "bundle": {…} }, "sig": "z…" } }
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
node sign.mjs card.json bundle.json [--operator bundle.json] > signed-card.json
node verify.mjs signed-card.json                          # SPEC §9.1 result, or throws
npm test                                                  # ALL PASS
```

`verify.mjs` (60 lines, published `sigelo` package): one sigelo extension, `verify(bundle)`
offline, `did` = the bundle's current DID, `sig` checked with that DID's key. It reports; whom
to trust is the caller's call. `sign.mjs` signs through sigelo-agent's signer for `$SIGELO_IDENTITY`
(file, keychain or key agent).

## Who stands behind it

`operator` (optional) is the `sigelo-relay/operator` attestation sigelo-agent's enrol writes, plus
the operator's chain (`--operator-chain`). `verify.mjs` reports `operator: {did, chain, exp}`, or
`null`, and refuses by name: `operator_subject` (another agent), `operator_expired`, `operator_ctx`,
`operator_rotated` (a key the chain rotated away from, SPEC §5).

A business learns, offline, that the holder of the operator DID claims this agent until `exp`.
Not who that is: the DID is pseudonymous unless the operator publishes it (A2A's `provider` is
unsigned text).

## Limits

- `typ: "a2a-card"` is not in SPEC §3.1: no sigelo verifier accepts this signature in any other
  slot, and `sigelo-agent sign-challenge` will not produce it.
- A card signature proves the key holder published this card, not that the endpoint is theirs.
  For a live caller, run a §5.2 challenge ([accept/](../../accept/README.md)).
- `operator_rotated` sees only the operator chain the card carries; an omitted rotation goes unseen.
- After a rotation or an operator renewal, re-sign the card. A float anywhere in the card makes it unsignable (SPEC §3).
