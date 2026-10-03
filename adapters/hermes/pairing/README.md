<!-- SPDX-License-Identifier: MIT -->
# A2A pairing by DID

```sh
node adapters/hermes/pairing/test.mjs        # node acceptor over the fixtures, gen --check, line counts
python3 adapters/hermes/pairing/test.py      # python acceptor over the same fixtures (cryptography, go or sigelo-verify)
node adapters/hermes/pairing/gen.mjs --check # fixtures reproduce byte for byte from the seeds
```

A fixture contract, `sigelo-a2a-pairing/0`, for the pairing step of a Hermes contacts plugin
(hermes-agent #132248). An Agent Card's name is a label anyone can type. Here the card carries a
sigelo bundle, the receiver verifies it offline and checks a challenge answer, and the pairing
is stored under the peer's original DID. A rotation keeps the pairing. A recovery beats a thief's
rotation. No model runs before these checks.

Reference acceptors, one function and a JSON-file store each:
[`accept/node/sigelo-pair.mjs`](../../../accept/node/sigelo-pair.mjs) **53** code lines,
[`accept/python/sigelo_pair.py`](../../../accept/python/sigelo_pair.py) **67** (`test.mjs` fails at 100).

## Where the bundle rides

One entry in `capabilities.extensions` (A2A v1.0 `AgentExtension`: `uri`, `description`,
`required`, `params`), `uri: "urn:sigelo:a2a-pairing:0"`, `required: false`, `params: { did, bundle }`.
Not `securitySchemes`: its five types are fixed and none fits a challenge-response. Not the card's
JWS `signatures`: signing JWS input with the identity key would break sigelo's domain separation
(SPEC §3). A peer that ignores the extension still talks over bearer tokens.
The rest of the card is what Hermes' `build_agent_card` emits (hermes-agent b71ba34).

## In a contacts plugin

```python
from sigelo_pair import Contacts, pair                  # accept/python
store = Contacts(hermes_home + '/contacts.json')
c = store.issue(did, ctx, now, 'alice')                 # pair: the owner confirmed did (the peer's CURRENT DID) out of band; None = known contacts only
contact = pair(card, {'body': c, 'sig': sig}, store, now)   # raises PairingError(.check) before any model runs
```

| kvnloo's step | identity |
|---|---|
| 1 pair | `issue(did, ctx, now, name)` + `pair(...)`: the stored contact is keyed by the original DID |
| 2 preview | none |
| 3 receive | `issue(card_did, ctx, now)` + `pair(...)`, or a token minted from it (#131484): unknown or revoked → refused |
| 4 clarify, 5 return | none |
| 6 revoke | `store.revoke(did)`: local, final for this store, pending challenges die |

## The contract

`fixtures/pairing-v0.json`: `v`, `extension`, `ttl` (300 s), `created`, `seeds` (label → hex;
secret = SHA-256(`"sigelo-a2a-pairing/0 " + label`), genesis nonce and challenge nonce derived
the same way, see `gen.mjs`), `dids`, `cards` (name → Agent Card) and `steps`, run in order
against two empty stores `A` and `B`:

- `issue` `{did, ctx, now, contact_name}` → exactly `expect` (pass `expect.nonce` in)
- `pair` `{card, answer: {body, sig}, now}` → `expect` `{did, current_did, current_key, attestations, rejected}` (§9.1 values), or `error`, the first failing check
- `lookup`, `revoke` `{did}` → `expect` `{name, did, current_did, current_key, revoked}` or `null`

The store re-reads its file at every operation, so one long-lived `Contacts` in the plugin sees a revoke the
owner made from another process, and `issue` drops expired challenges. Two simultaneous writers still need the integrator's lock.

Checks, in order: `card`, `challenge_unknown` (single use), `challenge_expired`
(`now ≥ issued + ttl`), `bundle` (§9 rejects: fork, structure), `card_did`, `challenge_did`,
`challenge_body`, `sig`, `revoked`, `not_contact`, `stale_chain` (the store merges every rotation
it has seen, §7.3 picks again). Conformant: every `expect` by value, every `error` by check name; messages are free text. Adding a step keeps `v`; changing a step or a check is a new `v`.

Cases: both directions, replay, expiry, card name, foreign bundle, unknown peer, tampered
attestation (discarded and counted, not fatal: SPEC §9 step 5), fork, voluntary rotation,
thief before recovery (accepted: nothing offline can tell), recovery beats voluntary (§7.1),
thief after recovery, revocation.

## What this does not do

- Say who the human is. A DID is a key, not a person. The owners confirm it out of band.
- Reachability, relays, discovery: the URL is configured by hand.
- Payments, trust scores, judgement of an issuer's attestations.
- Erase what was already delivered when a contact is revoked.
