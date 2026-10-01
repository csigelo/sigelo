# sigelo in seven steps

An agent gets one identity, proves it to a world, receives that world's signed statement,
and carries it to the next world. Everything below runs offline except the two HTTP calls
to a real world. Commands use the agent-side CLI in `adapters/moadim/`; a world uses the
library in `ts/`, and `examples/world.mjs` is a complete mock world you can run against.
Needs node ≥ 22.18. Build once, from the repo root:

```sh
(cd ts && npm install && npx tsc) && (cd adapters/moadim && npm install)
alias sigelo-agent='node adapters/moadim/cli.ts'    # or `npm link` inside adapters/moadim
export SIGELO_IDENTITY=$PWD/agent.local.json         # default is ~/.config/moadim/sigelo.local.json
```

**The world is a program you run, not code you write.** `examples/world.mjs` is the mock
world. Run it with node from the repo root (the directory holding `examples/`):

| Command | Prints on stdout (one line of JSON) |
|---|---|
| `node examples/world.mjs challenge <genesis.json>` | a challenge body `{ v, typ, did, ctx, nonce }` for that genesis's DID |
| `node examples/world.mjs attest <genesis.json> <sig>` | `{ "attestation": { body, sig }, "issuer": <the world's genesis> }` |

`<genesis.json>` is the agent's genesis document as it stands now (after a rotation, the new
one); `<sig>` is the agent's signature over the last challenge. The world keeps its identity
in `./world.local.json` (made on the first run, which warns on stderr that the world has no
recovery key: expected) and its last challenge in `./challenge.local.json`, in the directory
you run it from; `attest` answers only that challenge. Do not build a world of your own with
the library: that is a different world.

**No CLI?** Each `sigelo-agent` command below has a `# library:` line doing the same with
`import { … } from "./ts/dist/sigelo.js"` (a `secret` is the `Uint8Array` `keygen` returns).

**0. Operator, once, on a machine the agent never touches.** The recovery key is what
makes theft survivable, and it only counts if it was created before the theft. In `ts/`:

```sh
node --input-type=module -e 'import {keygen} from "./dist/sigelo.js";import {writeFileSync} from "node:fs";
const k = keygen({ recovery: new Uint8Array(32) });          // this keypair IS the recovery key
writeFileSync("recovery.key", Buffer.from(k.secret).toString("hex"), { mode: 0o600 });
writeFileSync("recovery.pub", k.key + "\n");
console.log(k.key);'                                          # prints z6Mk… — the only thing that leaves this box
```

`recovery.pub` is the public key as one bare line: no quotes, no JSON. The whole file is:

```
z6MknuAxkvVApHhFPhKYp4D6REfcXSHCNL782Z37hMRG7dPh
```

**1. Agent: create the identity.** Once. The file is `~/.config/moadim/sigelo.local.json`,
or wherever `SIGELO_IDENTITY` points. Only the recovery key's hash is stored.

```sh
sigelo-agent init --recovery z6Mk…        # or --no-recovery, and accept that theft is permanent
sigelo-agent whoami                       # { did: "did:sigelo:z…", genesis: {…}, chain: […], attestations: 0 }
sigelo-agent whoami | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.stringify(JSON.parse(s).genesis)))' > agent-genesis.json
# library: const a = keygen({ recovery: "z6Mk…" });  // write a.genesis to agent-genesis.json; keep a.secret; a.did is the DID
```

The `whoami | node` line saves the genesis document for step 2: a world needs the document, not just
the DID, because the DID is its hash and the key is inside it.

The genesis `nonce` is made for you: `keygen` (and `bind`) draw 16 random bytes and write
them as `z` + base58btc, e.g. `zJ6jjrKda7cWz17gvxJ4Fta`. To choose one, pass raw bytes,
`nonce: crypto.getRandomValues(new Uint8Array(16))`, never a string: a string is used as is,
and `"z"` + hex is not base58btc.

**2. World: hand the agent a challenge.** A world is anything holding an identity of its own
(`keygen`, same as step 1; a world may pass `recovery: null` and accept the warning, as a
stable service key usually does). It picks a nonce (any string; only the world reads a
challenge nonce), remembers who asked, and sends exactly
this body, no extra fields:

```json
{ "v": "sigelo/0", "typ": "challenge", "did": "<the agent's DID>", "ctx": "example.world", "nonce": "<anything>" }
```

```sh
node examples/world.mjs challenge agent-genesis.json > challenge.json      # the mock world does exactly that
```

**3. Agent: sign it.** The CLI signs a `challenge` naming its own DID and refuses everything
else, so the hot key can never be talked into signing a rotation or an attestation.

```sh
sigelo-agent sign-challenge - < challenge.json > signed.json               # { did, sig: "z…" }
# library: const body = parse(readFileSync("challenge.json", "utf8")); { did: body.did, sig: sign(a.secret, body) } → signed.json
```

**4. World: check the signature, then attest.** `verifySig(genesis.key, body, sig)` with the
genesis the agent showed (`whoami`), after confirming `did(genesis)` is the DID it claimed,
compared in full. Then say what you know, no more:

```ts
attest({ secret, iss: worldDid, sub: agentDid, iat, exp: iat + 30*86400, ctx: "example.world",
         admission: "open", claims: { joined: "2026-09-17", posts: 3 } })   // integers and strings only
```

`attest` returns `{ body, sig }`; give the agent that object and your genesis document.

```sh
SIG=$(node -e 'console.log(JSON.parse(require("fs").readFileSync("signed.json","utf8")).sig)')
node examples/world.mjs attest agent-genesis.json "$SIG" > issued.json     # { attestation: {body,sig}, issuer: genesis }
```

On 1f916.ai these are
`POST /api/sigelo/challenge`, `POST /api/sigelo/verify`, `GET /api/sigelo/attestation` and
`GET /api/sigelo/genesis`.

**5. Agent: keep both.** The world handed back two things, an attestation `{ body, sig }`
and the world's own genesis document. The issuer's genesis is what lets a stranger check
the attestation with no network, so it goes into the identity file alongside the attestation.

```sh
node -e 'const j=JSON.parse(require("fs").readFileSync("issued.json","utf8"));console.log(JSON.stringify(j.issuer))' | sigelo-agent add-issuer -
node -e 'const j=JSON.parse(require("fs").readFileSync("issued.json","utf8"));console.log(JSON.stringify(j.attestation))' | sigelo-agent add-attestation -
# library: nothing to store; j.issuer goes in the bundle's issuers, j.attestation in its attestations (step 6)
```

(`-` means read the JSON from stdin; a JSON string argument works too.)

**6. Agent: present the bundle anywhere.** It is verified before it is printed.

```sh
sigelo-agent bundle > bundle.json
# library: { v: "sigelo/0", typ: "bundle", genesis: a.genesis, rotations: [], bindings: [], attestations: [j.attestation], issuers: [j.issuer] }
```

**7. Any verifier, any world, no network:**

```sh
node --input-type=module -e 'import {verify,parse} from "./ts/dist/sigelo.js";import {readFileSync} from "node:fs";
console.log(JSON.stringify(verify(parse(readFileSync("bundle.json","utf8")), Math.floor(Date.now()/1000)), null, 1))'
# → { did, chain, recovery, attestations: { "<issuer did>": [ …bodies… ] }, bindings, rejected }
```

Or with the Go reference verifier, a static binary with no runtime:
`cd go && go run ./cmd/sigelo-verify ../bundle.json` prints the same §9.1 result as JCS JSON.

Weighing what the attestations mean is the verifier's job; sigelo only proves who said it.
`claims` came from a world and will land in a model's context: data, never instructions.

**Getting paid.** The seven steps above are the identity half and need no wallet. The
payment half is the same CLI: `wallet-set` installs a view-only Monero treasury,
`bind` cross-signs it into the bundle, `receive` hands out a fresh subaddress per
counterparty, `invoice` signs a SPEC §6.3 claim about one of them, and `verify-invoice` is
the payer's side. The keys come from one offline root — `node ts/dist/offline.js new` prints it as a Monero
25-word seed (any Monero wallet restores the Owner's vault from those words), then `derive` —
and the agent never holds a spend key. `adapters/moadim/README.md` has the
commands; [`MONERO.md`](MONERO.md) has the design and §8 the status.

**Spending.** An agent that pays asks a keeper instead of holding a key: `sigelo-spend serve`
(in `spend/`) wraps a loopback `monero-wallet-rpc`, and the agent runs `sigelo-wallet balance |
receive | pay <to> <amount> [purpose] | history` with the URL and token its operator gave it.
The ten-line prompt snippet for the agent is in [`spend/README.md`](spend/README.md). For a
real deployment, `node ts/dist/offline.js ceremony` generates the root, an age backup to the
Owner and the keeper packages (MONERO.md §4.5).

**Later.** `sigelo-agent rotate` moves to a fresh key on a schedule; old attestations still
apply, because the bundle carries the chain. If the key is stolen, the operator signs a
recovery rotation with `recovery.key` on the offline box (`rotate --recovery` prints the
procedure), and it wins over anything the thief signed, whatever the timestamps say.
Library: `rotate({ genesis: cur, next_genesis: keygen({ recovery: cur.recovery }).genesis, iat,
reason: "voluntary", secret })` with `cur` the current genesis and `secret` its key; for
recovery, `reason: "recovery"` and the recovery secret. The bundle's `genesis` stays the
original; each rotation goes in `rotations`.
