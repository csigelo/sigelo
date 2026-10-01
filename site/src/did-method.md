---
title: did:sigelo — the DID method
description: did:sigelo is the DID method of sigelo: the identifier is the multibase SHA-256 of a JCS-canonical genesis document, and resolution is offline, from a bundle, with no registry. Not yet registered with the W3C.
---
# `did:sigelo`

Method name: **`sigelo`**. A DID looks like `did:sigelo:zyDSS47dPz1g7rHaQSZ77MtAAPECp9NHNEj1DooQxAhv`.

```
DID = "did:sigelo:" + multibase_z( SHA-256( JCS(genesis) ) )
```

`multibase_z` is `z` + base58btc of the raw 32-byte digest, no multicodec prefix ([SPEC §2](/spec.html#2-primitives), [§4](/spec.html#4-genesis-and-identity)). The genesis holds the identity key, the recovery commitment, `created` and a nonce; since the DID is its hash, nothing in it can be revised afterwards, the recovery commitment included.

## Resolution is offline

There is no registry, no chain and no resolver to call. The genesis document — and so the key — travels with the identity, in a bundle ([SPEC §8](/spec.html#8-bundles)). To "resolve" a DID, a verifier:

1. recomputes the DID from the presented genesis and rejects on mismatch, comparing full DIDs, never prefixes;
2. walks the rotations from that genesis, where a valid recovery rotation beats any voluntary one at the same node, whatever the timestamps ([SPEC §7](/spec.html#7-rotation-and-recovery));
3. returns the current DID and key as part of the §9.1 result ([SPEC §9](/spec.html#9-verification-algorithm)).

Attestations to an earlier DID in the chain still count. A world's DID is resolved the same way, from the issuer geneses the bundle carries. A hosted resolver may exist as a convenience; nothing may depend on it.

## Status

Not registered in the W3C DID methods registry yet (ROADMAP T3, not started). Wire `sigelo/0` is a draft until the freeze at tag v0.2 ([versioning](/versioning.html)). There is no `/.well-known/did-configuration.json` here: that file links a domain to DIDs through Verifiable Credentials, which sigelo does not use.
