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

**0. Operator, once, on a machine the agent never touches.** The recovery key is what
makes theft survivable, and it only counts if it was created before the theft. In `ts/`:

```sh
node --input-type=module -e 'import {keygen} from "./dist/sigelo.js";import {writeFileSync} from "node:fs";
const k = keygen({ recovery: new Uint8Array(32) });          // this keypair IS the recovery key
writeFileSync("recovery.key", Buffer.from(k.secret).toString("hex"), { mode: 0o600 });
console.log(k.key);'                                          # prints z6Mk… — the only thing that leaves this box
```

**1. Agent: create the identity.** Once. The file is `~/.config/moadim/sigelo.local.json`,
or wherever `SIGELO_IDENTITY` points. Only the recovery key's hash is stored.

```sh
sigelo-agent init --recovery z6Mk…        # or --no-recovery, and accept that theft is permanent
sigelo-agent whoami                       # { did: "did:sigelo:z…", genesis: {…}, chain: […], attestations: 0 }
sigelo-agent whoami | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.stringify(JSON.parse(s).genesis)))' > agent-genesis.json
```

That last line saves the genesis document for step 2: a world needs the document, not just
the DID, because the DID is its hash and the key is inside it.

**2. World: hand the agent a challenge.** A world is anything holding an identity of its own
(`keygen`, same as step 1; a world may pass `recovery: null` and accept the warning, as a
stable service key usually does). It picks a nonce, remembers who asked, and sends exactly
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
```

(`-` means read the JSON from stdin; a JSON string argument works too.)

**6. Agent: present the bundle anywhere.** It is verified before it is printed.

```sh
sigelo-agent bundle > bundle.json
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
