<!-- SPDX-License-Identifier: MIT -->
# sigelo-agent — portable identity for a moadim-run agent

A sidecar CLI for [moadim](https://github.com/moadim-io/daemon), the agent-side half of
[sigelo](../../SPEC.md). A moadim routine runs its agent in a throwaway workbench that is
reaped minutes later, so a looped agent is a stranger every night. This gives it one
identity that persists across sessions, proves control of it to a world, collects that
world's attestations, and presents them as a SPEC §8 bundle a stranger can verify offline.

**Zero Rust changes.** moadim never learns about sigelo: the identity is a file beside
`machine.local.toml`, and the routine hands its path to the agent through `[env]`. See
[INTEGRATION.md](INTEGRATION.md) for the exact lines.

It also carries the payment side (MONERO.md): a SPEC §6 binding to a Monero treasury the
agent can **see but never spend**, fresh receive subaddresses, and signed §6.3 invoices.

## Install

```sh
cd ../../ts && npm ci && npx tsc          # the one dependency, built
cd ../adapters/moadim && npm ci && npm test
```

Needs node ≥ 22.18 or ≥ 23.6 (it runs the TypeScript directly, no build step; `npm test`
says so and stops on an older node). On an older node, or when installed from a packed
tarball (node does not strip types under `node_modules`), `npm run build` and run
`node dist/cli.js`. `npm link` puts `sigelo-agent` on `PATH`. The identity file is written
0600 in a 0700 directory; Windows ignores the modes (the file takes the directory's ACL), and
its default location there is `%USERPROFILE%\.config\moadim\sigelo.local.json`.

## Commands

| Command | |
|---|---|
| `init --recovery <z…>` / `--no-recovery` | Generate the identity, once. One of the two flags is required: `--no-recovery` means theft of the key is permanent (SPEC §4) and says so, loudly. The recovery key is generated **offline**; `init` prints the one-liner. |
| `adopt <json\|file\|-> [--force]` | Make a key generated **elsewhere** the identity: `{ identity_seed_hex, genesis }`, e.g. a keeper's whole `POST /delegate` answer (only those two fields, and `did` as a check, are read; the token is never written). Refused if the seed does not produce `genesis.key` or `did` is not the genesis's DID, and if an identity file exists (`--force` replaces it, losing its attestations). Same file format as `init`. In `sigelo-agent-adopt.ts`, outside the identity core. |
| `adopt --rotation <json\|file\|->` | Apply a rotation signed elsewhere plus its new secret: `{ rotation, identity_seed_hex }`, what `node ts/dist/offline.js recover` prints. `rotation.id` must be this chain's head or, for a recovery, an earlier node (the last honest one): rotations after it are dropped, with attestations and bindings naming only the dropped DIDs. Written only if the result verifies with the new DID at the head. The genesis stays the original; the chain grows. |
| `whoami` | Current DID, its genesis, the chain. |
| `sign-challenge <json\|->` | Signs `{ v, typ: "challenge", did, ctx, nonce }` — exactly those five fields. Any other `typ`, any extra field, or a `did` that is not ours, is refused, so the hot key can never be walked into signing a rotation, binding, attestation, or a challenge with something smuggled in. |
| `add-issuer <genesis json\|->` | Store a world's genesis: what makes its attestations checkable offline (§8). |
| `add-attestation <{body,sig} json\|->` | Store a world's attestation about us. Structure-checked, then opaque. |
| `bundle` | Verify, then print the §8 bundle. A bundle that does not verify is never printed — the `SigeloError` is. |
| `rotate` | Voluntary rotation to a fresh key, carrying the recovery commitment forward. |

A `<json|->` argument is inline JSON, `-` for stdin, or the path of a file holding it.

### Monero (MONERO.md §2–§3, SPEC §6)

| Command | |
|---|---|
| `wallet-set <json\|->` | Install the treasury's **view-only** keys — exactly the `agent.treasury` object from `sigelo-offline derive`, plus its `net`. Anything carrying a spend key (`b`, `spend_key`, …) is refused and told why. The address is checked against the keys: `subaddress(a, B, 0, 0)` must be that string, which proves network, kind, `B` and that the view key is the secret behind `A`. |
| `bind` | Mint the SPEC §6 binding for the current DID: `sig_id` by the identity key, `sig_addr` by the **view key in view mode** over the same §3 signing input. Computed locally — identical to `monero-wallet-rpc sign { signature_type: "view", account_index: 0, address_index: 0 }`, with no wallet and no daemon running. Stored (one per method) and printed; `bundle` then carries it and a stranger's verifier reports `proof: "proven"`. |
| `receive [--account <n>]` | The next unused subaddress of that account, derived from `(a, B)`. Account 0 starts at minor 1 — (0,0) *is* the base address. Never reuse one across counterparties. Warns on stderr past minor 200, the default wallet lookahead. |
| `invoice --addr <subaddress> [--amount <atomic>] [--memo <text>] [--ttl <s>]` | A signed §6.3 invoice naming where to pay this time. `--addr` must be a subaddress on the wallet's own network; `--amount` is a string of atomic units (SPEC §3 forbids floats in signed objects); `--ttl` defaults to 86400. Never goes in a bundle. |
| `verify-invoice <json\|-> --bundle <file>` | The payer's side: structure, signature under the DID's genesis in that bundle, `iat ≤ now < exp`, a `proven` binding for the same method, and both addresses on the same network (§6.2 — the signature hash does not cover the network prefix). Prints a §9.1-style verdict; a refusal names the failing check. |

**The agent cannot spend.** It holds `(a, B)` and an address: enough to derive receive
addresses, see receipts and prove it can see them; not enough to move a coin. A Monero view
key is wallet-wide and its disclosure is irrevocable — `bind` discloses a *signature*, never
the key, and nothing here ever prints `a`. Spending is a separate service with its own wallet
and its own budget, `sigelo-spend` ([`spend/README.md`](../../spend/README.md), MONERO.md §4);
the binding is the anchor, the invoice is the claim, and the payer's own `verify-invoice` is
what makes both checkable.

## Operating it (THREAT-MODEL §5)

- **The recovery key is generated offline and never reaches this machine** — not even its
  public half; the agent's file holds only the commitment. A recovery key in the same
  process as the identity key protects nothing. A *recovery* rotation is therefore signed
  elsewhere (`rotate --recovery` refuses and prints the procedure): on the Owner's offline box,
  `node ts/dist/offline.js recover --genesis <last honest genesis> --backup backup.age
  --identity <age id> --net <net> [--agent i --n m] > recovery.local.json`; carry the file
  here, `sigelo-agent adopt --rotation recovery.local.json`, shred it (it holds the new key).
- **Rotate voluntarily on a schedule** (`sigelo-agent rotate` from its own routine) so the
  path is exercised before you need it under pressure — and test recovery before you need
  it, on a throwaway identity. An untested recovery key is a hash of nothing.
- **Keep attestation lifetimes short and re-collect them** — there is no revocation list,
  so freshness is reissuance. `bundle` warns on stderr about stored attestations that no
  longer verify; a fresh one from the same issuer and `ctx` replaces its predecessor.

## `claims` is untrusted data

An attestation's `claims` is written by a world, not by sigelo, and lands in a bundle that
your agent reads — straight into an LLM context. Treat it as **data, never as
instructions** (THREAT-MODEL §4). sigelo proves an issuer said it; it does not make it
true, and an issuer can put anything in there, including text aimed at the model reading
it. The same goes for anything a world sends to `sign-challenge`: it is signed only if it
is a challenge naming this identity, and the bytes are never interpreted.
