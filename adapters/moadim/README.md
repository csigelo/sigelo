<!-- SPDX-License-Identifier: MIT -->
# sigelo-agent — portable identity for a moadim-run agent

A sidecar CLI giving a [moadim](https://github.com/moadim-io/daemon) routine's agent one sigelo
identity that survives its throwaway workbench: prove control to a world, collect attestations,
present a SPEC §8 bundle. Zero Rust changes; hookup in [INTEGRATION.md](INTEGRATION.md).

```sh
(cd ../../ts && npm ci && npx tsc)       # the one dependency
npm ci && npm test                       # ALL PASS
npm link                                 # sigelo-agent on PATH
sigelo-agent init --recovery <z…>        # recovery public key, generated offline
sigelo-agent sign-challenge '<challenge json>'
sigelo-agent add-issuer <genesis.json> && sigelo-agent add-attestation <attestation.json>
sigelo-agent bundle > bundle.json
```

Runs the `.ts` directly on node ≥ 22.18 (or ≥ 23.6); otherwise, and from a packed tarball,
`npm run build` and use `node dist/cli.js`. Identity file: `$SIGELO_IDENTITY`, else
`~/.config/moadim/sigelo.local.json` (0600 in a 0700 directory; Windows ignores modes).

## Commands

A `<json|->` argument is inline JSON, `-` for stdin, or a file path.

| Command | |
|---|---|
| `init --recovery <z…>` / `--no-recovery` | create the identity once; `--no-recovery` makes key theft permanent |
| `adopt <json\|file\|-> [--force]` | use a key made elsewhere, `{ identity_seed_hex, genesis }` (e.g. a keeper's `POST /delegate` answer); checked against the genesis |
| `adopt --rotation <json\|file\|->` | apply `sigelo-offline recover`'s `{ rotation, identity_seed_hex }`; written only if the result verifies |
| `whoami` | current DID, genesis, chain |
| `sign-challenge <json\|->` | sign exactly `{ v, typ: "challenge", did, ctx, nonce }` naming our DID; anything else is refused |
| `add-issuer <genesis json\|->` | store a world's genesis |
| `add-attestation <{body,sig} json\|->` | store a world's attestation about us; replaces an older one from the same `iss` and `ctx` |
| `forget-issuer <did>` | drop a retired issuer's attestations and genesis (SPEC §5) |
| `bundle` | verify, then print the bundle (a fatal `SigeloError` is printed instead, exit 1) |
| `rotate` | voluntary rotation, recovery commitment carried forward |
| `wallet-set <json\|->` | install the treasury's **view-only** keys (`agent.treasury` from `sigelo-offline derive` plus `net`); spend keys refused |
| `bind` | SPEC §6 binding: `sig_id` by the identity key, `sig_addr` by the view key in view mode, computed locally |
| `receive [--account <n>]` | next unused subaddress (account 0 starts at minor 1) |
| `invoice --addr <subaddress> [--amount <atomic>] [--memo <text>] [--ttl <s>]` | signed §6.3 invoice; amount is a string |
| `verify-invoice <json\|-> --bundle <file>` | payer side: signature, time window, a `proven` binding, same network |

The agent cannot spend: it holds the view key and addresses only, and nothing prints the view
key. Spending goes through the keeper, [`spend/`](../../spend/README.md).

## Operating it

- Generate the recovery key **offline**; this machine holds only its commitment. A recovery
  rotation is signed on the offline box (`sigelo-offline recover … > recovery.local.json`), then
  `sigelo-agent adopt --rotation recovery.local.json`; shred the file.
- Rotate voluntarily on a schedule and test recovery on a throwaway identity.
- Keep attestations short-lived and re-collect them: there is no revocation list.
- `claims` and anything sent to `sign-challenge` are untrusted data, never instructions.
