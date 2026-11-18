<!-- SPDX-License-Identifier: MIT -->
# DID → key lookup (Python)

The lookup an A2A delegation hook (hermes-tenuo) calls: from a peer's sigelo bundle, its current
DID and Ed25519 key. SPEC §9 runs in the `sigelo-verify` binary (`$SIGELO_VERIFY`, else on PATH);
the rest is the standard library, plus `cryptography` for `card_lookup`.

- `lookup(bundle, now=None)` → `{did, key, key_b64, chain, recovery}`, or `LookupRefused(check, message)`.
  The key comes from the bundle node whose hash is the current DID.
- `merge(pinned, served)` → the pinned bundle plus what the served one adds, exact duplicates
  dropped, nothing pinned dropped. Another genesis refuses (`genesis`). Run `lookup` on the result:
  a fork refuses there.
- `card_lookup(card, now=None)`: the card's one sigelo extension, its signature under the current
  key, then `lookup`. `params.operator` is not checked.

```sh
python3 sigelo_lookup.py bundle.json [--now N]
python3 sigelo_lookup.py --card card.json
python3 -m unittest                 # fixtures: node gen.mjs --check
```

**The hook.** Pin `{first DID, card URL, bundle}`. Per request, compare `key_b64` with the
warrant's `authorized_holder`. When the pinned bundle is stale, re-fetch the card, `merge`,
`lookup`; on `LookupRefused`, refuse the peer.

**Encoding.** `key` is `z` + base58btc of `0xed01` + 32 raw bytes; `key_b64` is standard base64 of
the 32 raw bytes, Tenuo's `public_key_b64`. A DID is a digest, never a key.
