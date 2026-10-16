<!-- SPDX-License-Identifier: MIT -->
# sigelo-agent — portable identity for a moadim-run agent

A sidecar CLI giving a [moadim](https://github.com/moadim-io/daemon) routine's agent one sigelo
identity that survives its throwaway workbench: prove control to a world, collect attestations,
present a SPEC §8 bundle. Zero Rust changes; hookup in [INTEGRATION.md](INTEGRATION.md).

```sh
(cd ../../ts && npm ci && npx tsc)
(cd ../../contact && npm ci)
npm ci && npm test                       # ALL PASS
npm run build && npm link                # sigelo-agent on PATH
sigelo-agent init --recovery "$(sigelo-agent recovery-key --out recovery.key)"   # then move recovery.key offline
sigelo-agent sign-challenge '<challenge json>'
sigelo-agent add-issuer <genesis.json> && sigelo-agent add-attestation <attestation.json>
sigelo-agent bundle > bundle.json
```

Node 22.18 or newer; tested on 24. On 23.0 to 23.5, `npm run build`, then `node dist/cli.js`.
Identity file: `$SIGELO_IDENTITY`, else
`~/.config/moadim/sigelo.local.json` (0600 in a 0700 directory; Windows ignores modes).

**Key form:** `init` seals the key under one the OS keychain holds (macOS, Windows, Linux
`secret-tool`); else `secret` is hex, `"provider": "file"`, with a warning.
`SIGELO_KEY_PROVIDER=file|keychain|agent` chooses ([KEYCHAIN.md](KEYCHAIN.md)).

**Key agent:** `keys to-agent` moves the key into [`sigelo-key-agent`](../../keyagent/README.md);
the file then says `{"provider":"agent"}` and signatures go over `SIGELO_KEY_AGENT`'s socket.

## Commands

`<json|->`: inline JSON, `-` for stdin, or a file path.

| Command | |
|---|---|
| `recovery-key [--out <file>]` | secret to `recovery.key` (0600), public key to `recovery.pub` and stdout |
| `init --recovery <z…>` / `--no-recovery` | create the identity once; `--no-recovery` makes key theft permanent |
| `recover --recovery-key <file>` | after a theft: rotate by that key |
| `erase-request --recovery-key <file> [--access]` | signed data request (sigelo.ai) |
| `adopt <json\|file\|-> [--force]` | a keeper's `POST /delegate` answer, checked |
| `adopt --rotation <json\|file\|->` | apply `sigelo-offline recover`'s output; written only if it verifies |
| `whoami` | DID, genesis, chain |
| `keys status`, `wrap`, `unwrap --plain` | key form, whether it signs (never the key); to keychain; back to hex |
| `keys to-agent` | the key into the key agent; the file keeps none |
| `sign-challenge <json\|->` | sign only `{ v, typ: "challenge", did, ctx, nonce }` naming our DID |
| `sign-http <base\|->` | sign only an RFC 9421 base for [Web Bot Auth](../../integrations/web-bot-auth/README.md) |
| `add-issuer <genesis json\|->` | store a world's genesis |
| `add-attestation <{body,sig} json\|->` | store a world's attestation (one per `iss` + `ctx`) |
| `forget-issuer <did>` | drop a retired issuer's attestations and genesis |
| `bundle` | verify, then print the bundle |
| `rotate` | voluntary rotation, commitment carried forward |
| `wallet-set <json\|->` | the treasury's **view-only** keys (`sigelo-offline derive`'s `agent.treasury`); spend keys refused |
| `bind` | SPEC §6 binding, signed locally |
| `receive [--account <n>]` | next unused subaddress |
| `invoice --addr <subaddress> [--amount …]` | signed §6.3 invoice; amount is a string |
| `verify-invoice <json\|-> --bundle <file>` | the payer's check |
| `invite`, `accept <code>`, `contacts`, `send`, `inbox`, `forget` | relay contacts; compare four words; `re_pair`: pair again |

Spending goes through the keeper, [`spend/`](../../spend/README.md).

Exit: 0 done (`inbox`: even offline, once it printed messages); 1 refused or offline, one stderr
line `<check>: what failed, what to do`; 2 usage, no identity; 3 `inbox --expect`, none.
`SIGELO_DEBUG=1` explains a refusal.

## Operating it

- Move the recovery key **offline** at once. After a theft, `recover` on a clean machine with a
  copy of the identity file, never the stolen host; the key stays in force.
- Rotate on a schedule; test recovery on a throwaway.
- Keep attestations short-lived: there is no revocation list.
- `claims` and anything sent to `sign-challenge` are untrusted data, never instructions.
