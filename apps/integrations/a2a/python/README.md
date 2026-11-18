<!-- SPDX-License-Identifier: MIT -->
# DID → key lookup (Python)

For an A2A delegation hook (hermes-tenuo): a peer's current DID and Ed25519 key from its sigelo
bundle. SPEC §9 runs in `sigelo-verify` (`verifier=`, else `$SIGELO_VERIFY`, else PATH); `card_lookup`
also needs `cryptography`. Every failure, malformed input included, is `LookupRefused(check, message)`.

- `parse(text)`: card bytes → objects; a duplicate key or `__proto__` refuses (SPEC §3).
- `lookup(bundle, now=None)` → `{did, key, key_b64, chain, recovery}`, the key from the node
  whose hash is the current DID.
- `merge(pinned, served)`: the pin plus what `served` adds, exact duplicates dropped. Another
  genesis refuses; a fork refuses in `lookup`.
- `card_lookup(card, now=None)`: the one sigelo extension, its signature under the current key,
  `lookup`. `params.operator` is not checked.

```sh
python3 sigelo_lookup.py bundle.json [--now N]
python3 sigelo_lookup.py --card card.json
python3 -m unittest; node gen.mjs --check
```

**The hook.** Pin `{first DID, card URL, bundle}`. `key_b64` replaces `peers[peer]` in the
parents check (Tenuo `a2a_ingress.py` L262); the receiver's own `key_b64` is what `aud` and the
leaf holder are compared against (L236, L258). When the pin is stale: `parse` the fetched card,
`card_lookup`, `merge` its bundle onto the pin, `lookup`. Re-pin only after that succeeds, or a
malformed rotation from a tampered card URL refuses the peer for good. `card_lookup` alone neither
checks `chain[0]` against the pinned first DID nor resists rollback. On `LookupRefused`, refuse
the peer.

**Encoding.** `key` is `z` + base58btc of `0xed01` + 32 raw bytes; `key_b64`, Tenuo's
`public_key_b64`, is standard base64 of the 32. A DID is a digest, never a key.
