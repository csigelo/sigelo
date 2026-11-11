<!-- SPDX-License-Identifier: MIT -->
# `sigelo-a2a-pairing/0` inside two real Hermes gateways

Run 2026-10-03, hermes-agent `eb044063235fbf7a4e68dd2970ade05dbe637ff3`, Debian 13 arm64, no Docker. Installed with the repo's own `setup-hermes.sh --runtime-only` (pinned uv 0.12.3,
CPython 3.14.7; optional `cua-driver` fails headless, harmless). No model,
no API key: `hermes gateway run` starts and serves A2A with only warnings.

Two instances: separate `HERMES_HOME`, A2A on loopback only, per-peer tokens, own `sigelo-agent init` identity. The local plugin [`hermes-lab/sigelo-pair`](hermes-lab/sigelo-pair/__init__.py)
(user plugin, no core edit) puts `{did, bundle}` on the card and answers pairing messages in
`pre_gateway_dispatch`, before auth and before any model. [`hermes-lab/drive.py`](hermes-lab/drive.py)
is the initiator, sending through Hermes' own `a2a_call`.

## What worked

- Card served by Hermes with `capabilities.extensions[urn:sigelo:a2a-pairing:0]`, re-read after a rotation.
- Pairing both ways over A2A `SendMessage`: the receiver issues, the initiator checks `ctx` and signs, the receiver fetches the peer's card from the peer's configured `a2a_agents` URL, verifies it offline (`sigelo-verify`) and stores the contact.
- Replay → `challenge_unknown`. `sigelo-agent rotate` on A, then re-pairing: same contact, new `current_did`.
- Revocation on B → A refused with `revoked`; A's own contact for B is untouched.
- Baseline `test.py` there: ALL PASS.

## What did not, and was fixed here

- A long-lived `Contacts` (the README's plugin pattern) undid a revoke made by the owner from
  another process; the revoked peer paired again. Fixed in both acceptors (re-read per operation,
  re-check before writing), with tests. Expired challenges were never dropped; fixed too.
- An owner-confirmed DID must be the peer's current DID: confirming the original DID of an already
  rotated peer gives `not_contact`. Now in the README.

## Not run

Recovery and fork (fixture only), a remote bind, a model choosing the tools.

## Seams a standalone plugin would need from Hermes

1. A card hook: `build_agent_card` takes no `extensions`. The plugin scans `sys.modules` for `*.protocol` and wraps it, retrying because of load order.
2. A non-model route: there is no plugin route. Pairing rides `SendMessage`, uses the private `gateway._intake_adapter_for`, and replies with `adapter.send(..., metadata={"notify": True})`.
3. A raw payload: data Parts become text, with the privacy prefix, the injection filter and `redact_outbound` on both legs. An e-mail-shaped `ctx` would break `challenge_body`/`sig`.
4. Identity feedback: the trust gate, rate limiter and audit still key on the token label. A pairing cannot name the peer by DID (#131484's authenticator hook).
5. The hook runs on the event loop, so a slow verifier stalls the gateway.

```sh
git clone https://github.com/NousResearch/hermes-agent && cd hermes-agent && git checkout eb044063
HOME=$LAB/home bash setup-hermes.sh --runtime-only           # venv under $LAB/home/.hermes/installs
cp -r hermes-lab/sigelo-pair $HERMES_HOME/plugins/           # config.yaml: plugins.enabled [sigelo-pair],
                                                             # gateway.platforms.a2a {enabled, extra.port}, a2a_agents
SIGELO_IDENTITY=$HERMES_HOME/sigelo.local.json sigelo-agent init --recovery <z…>
A2A_PORT=19901 A2A_PEER_TOKENS=bob:<tok> hermes gateway run  # and B on 19902
python drive.py pair bob ; python drive.py revoke <did> ; python drive.py lookup <did>
```
