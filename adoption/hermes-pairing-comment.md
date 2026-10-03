<!-- SPDX-License-Identifier: MIT -->
<!-- Draft. Not posted anywhere. Two comments for NousResearch/hermes-agent#132248, from csigelo's account. -->
<!-- (1) post now. (2) post only once adapters/hermes/pairing/ is in the public repo; check the repo link and the step count first. -->

## 1. Opener

Agree with the split between communication and authority, and with "remote Agent Card names are not proof of human identity".

The pairing step is where a key-based identity fits without changing the rest of the design. The peer's card carries a self-certifying DID with its key history. The receiver checks a one-time challenge answer offline, and the contact record is keyed by that DID, not by the card name or a bearer token. A key rotation keeps the pairing, and a stolen key can be taken back. This composes with #131484 but does not need it.

I'll follow up with a small deterministic fixture for that step only, with no model involved.

Prepared with AI assistance.

## 2. Follow-up (once the fixture is public)

The fixture is in `adapters/hermes/pairing/` at https://github.com/csigelo/sigelo. `sigelo-a2a-pairing/0` is one JSON file generated from fixed seeds. It has Agent Cards in the shape `build_agent_card` emits, plus one `capabilities.extensions` entry carrying the peer's DID and bundle. 34 steps run over two contact stores: pairing both ways, replay, expiry, a card named "Alice" from another key, an unknown peer, a forked key history, a rotation that keeps the pairing, a recovery that overrides a thief's rotation, and revocation. Every rejection happens before a model would run. Reference acceptors: 67 lines of Python, 53 of Node.

```sh
python3 adapters/hermes/pairing/test.py   # needs cryptography, plus Go or a sigelo-verify binary
```

What it does not claim: who the human is (owners still confirm the DID out of band), reachability, discovery, payments, or any trust judgement. It also ran inside two Hermes gateways (`eb04406`, no model) through a small user plugin: `HERMES-RUN.md` lists the five seams that plugin had to work around (card hook, a non-model route, a raw payload, identity feedback, the event loop).

Prepared with AI assistance.
