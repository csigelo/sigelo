<!-- SPDX-License-Identifier: MIT -->
<!-- Draft, not posted. Venue: https://github.com/x402-foundation/wg-identity/issues/new
Title: "Solution - Portable agent identity: offline-verifiable DID, and receipts the buyer keeps".
Link #8, #11, #18 and #32 in the body; do not comment on each. -->

## Problem

The issues here name the gap. #8 asks for a post-settlement accountability record, #11 for a
returning customer, #18 for a portable verified attribute schema, and #32 for what key rotation
does to existing mandates. In x402 today, identity is a wallet address (SIWX), and
offer-and-receipt receipts are signed by the seller and held by the seller. A buyer agent cannot
carry evidence of good conduct from one resource server to the next, and a rotated wallet starts
from zero.

## Proposal

Add a resource-server extension, `sigelo`, built on hooks that already exist in
`@x402/core`.

- The agent sends its DID. The 402 then carries a challenge `{v, typ, did, ctx, nonce}`
  (single use, five minutes), the same shape as the SIWX parameters.
- The retry carries `{did, sig, bundle}`. The server verifies the bundle offline: the hash chain
  from the genesis, the rotations, and the attestations from other servers.
- After settlement, the server signs an attestation about the DID ("paid for X at T"). The buyer
  keeps it in its bundle, and any later server can verify it with no call back.

A DID survives key rotation: a recovery key held offline overrides a thief's rotation. Payment
addresses are bound to the DID by both keys signing the same bytes.

```ts
// ResourceServerExtension, key "sigelo"; challenge/accept are accept/node/sigelo-accept.mjs
const sigeloExt = {
  key: "sigelo",
  enrichPaymentRequiredResponse: (decl, ctx) => ({ ...decl, challenge: challenge(didOf(ctx), ORIGIN) }),
  onBeforeVerify: async (decl, ctx) => {
    try { ctx.sigelo = accept(...answerOf(ctx)); }          // offline; throws on any failure
    catch (e) { return { abort: true, reason: "sigelo_identity", message: e.message }; }
  },
  onAfterSettle: async (decl, ctx) => { ctx.receipt = attest(ctx.sigelo.did, { paid: ctx.result }); },
};
```

## What it is not

It holds no custody, uses no token, and needs no chain or registry. The facilitator is not
involved. The code is MIT, with reference verifiers in TypeScript and Go and shared test vectors.
It does not score trust: the verifier reports what each issuer signed, and the server decides.

## Ask

Does this belong as a third-party extension under `specs/extensions`? If so, I'll write the spec
text and a TypeScript package.
