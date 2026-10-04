# sigelo in seven steps

An agent gets one identity, proves it to a world, receives that world's signed statement, and
carries it to the next world. Commands use the agent CLI in `adapters/moadim/`; `examples/world.mjs`
is a mock world. Needs node ≥ 22.18. Build once, from the root of a clone:

```sh
(cd ts && npm ci && npx tsc) && (cd adapters/moadim && npm ci)
mkdir -p bin && printf '#!/bin/sh\nexec node "%s/adapters/moadim/cli.ts" "$@"\n' "$PWD" > bin/sigelo-agent && chmod +x bin/sigelo-agent
export PATH="$PWD/bin:$PATH"                       # or `npm link` inside adapters/moadim
export SIGELO_IDENTITY=$PWD/agent.local.json         # default is ~/.config/moadim/sigelo.local.json
```

PowerShell: `cd ts; npm ci; npx tsc; cd ../adapters/moadim; npm ci; cd ../..`, then
`function sigelo-agent { node adapters/moadim/cli.ts @args }` and
`$env:SIGELO_IDENTITY = "$PWD\agent.local.json"`; run the blocks below in Git Bash.

**Install without a clone** (after the first npm publish):

```sh
npx sigelo-agent init --no-recovery              # agent-side CLI (or --recovery <z6Mk…|sha256:…>, step 0)
npx -p sigelo-spend sigelo-wallet balance        # the agent's wallet client; SIGELO_WALLET_URL/_TOKEN from the operator
npx sigelo-mcp                                   # stdio MCP server: identity tools, wallet verbs when a keeper is set
npx -p sigelo sigelo-offline new                 # the offline root tool (this page's ts/dist/offline.js)
go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@v0.1.1   # the verifier (tag go/v0.1.1)
```

Until then, build the tarballs in a clone and install them anywhere:

```sh
release/build.sh /tmp/sigelo-dist                # npm tarballs, sigelo-verify binaries, SHA256SUMS
mkdir my-agent && cd my-agent && npm init -y >/dev/null
d=/tmp/sigelo-dist; npm install $d/sigelo-0.1.1.tgz $d/sigelo-agent-0.1.1.tgz $d/sigelo-spend-0.1.1.tgz $d/sigelo-mcp-0.1.1.tgz
npx sigelo-agent init --no-recovery
$d/sigelo-verify-linux-arm64 --conformance $d/test-vectors.json   # your os-arch
```

Install the `sigelo` tarball in the same `npm install`: the others depend on it.

**The world is a program you run, not code you write.** From the repo root:

| Command | Prints on stdout (one line of JSON) |
|---|---|
| `node examples/world.mjs challenge <genesis.json>` | a challenge body `{ v, typ, did, ctx, nonce }` for that genesis's DID |
| `node examples/world.mjs attest <genesis.json> <sig>` | `{ "attestation": { body, sig }, "issuer": <the world's genesis> }` |

`<genesis.json>` is the agent's current genesis document (after a rotation, the new one);
`<sig>` its signature over the last challenge. The world keeps its identity in
`./world.local.json` (the first run warns it has no recovery key: expected) and one outstanding
challenge per DID in `./challenge.local.json`; `attest` answers it once. Do not build your own
world with the library: that is a different world.

**No CLI?** Each `sigelo-agent` command below has a `# library:` line doing the same with
`import { … } from "./ts/dist/sigelo.js"` (a `secret` is the `Uint8Array` `keygen` returns).

**0. Operator, once: pick a recovery tier.** The recovery key makes theft survivable only if
it predates the theft: the genesis holds its hash and cannot change (SPEC §4).

| Tier | For | `init` gets |
|---|---|---|
| 0 | throwaway and ephemeral subagents | `--no-recovery` |
| 1 | the default whenever an operator exists | the `sha256:` commitment of the operator's 25-word root |
| 2 | high security, a human deep in the loop | the `z6Mk…` key of a dedicated offline machine |

**Tier 0:** `sigelo-agent init --no-recovery`. A stolen key loses the identity for good, and
worlds MAY refuse to attest it (SPEC §4).

**Tier 1: from the operator's 25-word root.** A root has one recovery key,
`k(S, "sigelo/v1/recovery/ed25519")` (MONERO.md §2), shared by every agent of that operator (so an
observer can group them). On the operator's machine, network down, with `age` (or `rage`). The
Owner's age key decrypts the backup; it stays offline with the Owner:

```sh
age-keygen -o owner-age.key                  # the Owner's age identity: secret (*.key is gitignored); rage: rage-keygen
node ts/dist/offline.js ceremony --net stagenet --recipient "$(age-keygen -y owner-age.key)" --out ceremony   # once per root; S goes only into ceremony/backup.age
# the Owner at the terminal, wanting the 25 words on paper: add --human (they go to /dev/tty only; vault only, never a hot wallet)
node -e 'console.log(JSON.parse(require("fs").readFileSync("ceremony/fingerprint.txt","utf8")).recovery_commitment)'
# → sha256:3fb9…eb24 — public; this is what step 1's --recovery takes
```

**Without age:** `node ts/dist/offline.js new` prints a fresh root as 25 words (write them down:
nothing else keeps them); `node ts/dist/offline.js derive <25 words>` prints `recovery.commitment`
(the `sha256:…` step 1 takes) or `recovery.public_key_multibase` (`z6Mk…`). `derive` also prints
keeper roots and spend keys: offline only.

A keeper-minted subagent does not run `init`: `sigelo-agent adopt answer.json` makes its
`POST /delegate` answer its identity (the token is not stored).

To recover (the Owner, offline), sign SPEC §7's recovery rotation from the agent's last honest
genesis (`agent-genesis.json`, or the genesis of any pre-theft bundle):

```sh
node ts/dist/offline.js recover --genesis agent-genesis.json --backup ceremony/backup.age --identity owner-age.key --net stagenet > recovery.local.json
# a keeper-minted agent i: add --agent <i> --n <next unused rotation, ≥ 1> (INCIDENT.md §5); default: a fresh random key
# holding the 25 words instead: replace --backup/--identity/--net with `-` and type them on stdin
```

`recovery.local.json` is `{ did, rotation, identity_seed_hex }`. Carry it to the agent by hand:

```sh
sigelo-agent adopt --rotation recovery.local.json && rm recovery.local.json   # it holds the new key
```

The chain grows by one; attestations to the old DID still count, and the recovery beats whatever
the thief signed from that node, whatever its `iat` (§7.1). Ask worlds to re-attest.

**Tier 2: a dedicated offline machine** the agent never touches. In `ts/`:

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

**1. Agent: create the identity.** Once, into `SIGELO_IDENTITY`. Only the recovery key's hash
is stored. Tier 1 passes the `sha256:…` line instead of `z6Mk…`.

```sh
sigelo-agent init --recovery z6Mk…        # or --no-recovery, and accept that theft is permanent
sigelo-agent whoami                       # { did: "did:sigelo:z…", genesis: {…}, chain: […], attestations: 0 }
sigelo-agent whoami | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.stringify(JSON.parse(s).genesis)))' > agent-genesis.json
# library: const a = keygen({ recovery: "z6Mk…" });  // write a.genesis to agent-genesis.json; keep a.secret; a.did is the DID
```

A world needs the genesis document, not just the DID: the DID is its hash and the key is inside.
`keygen` and `bind` make the `nonce`; to choose one pass raw bytes
(`crypto.getRandomValues(new Uint8Array(16))`), never a string (`"z"` + hex is not base58btc).

**2. World: hand the agent a challenge.** A world is anything with its own identity (`keygen`;
`recovery: null` is usual for a service key). It picks a nonce (any string), remembers who asked,
and sends exactly this body:

```json
{ "v": "sigelo/0", "typ": "challenge", "did": "<the agent's DID>", "ctx": "example.world", "nonce": "<anything>" }
```

```sh
node examples/world.mjs challenge agent-genesis.json > challenge.json      # the mock world does exactly that
```

**3. Agent: sign it.** The CLI signs only a `challenge` naming its own DID.

```sh
sigelo-agent sign-challenge - < challenge.json > signed.json               # { did, sig: "z…" }
# library: const body = parse(readFileSync("challenge.json", "utf8")); { did: body.did, sig: sign(a.secret, body) } → signed.json
```

**4. World: check, then attest.** Confirm `did(genesis)` equals the claimed DID in full, then
`verifySig(genesis.key, body, sig)`. Then say what you know, no more:

```ts
attest({ secret, iss: worldDid, sub: agentDid, iat, exp: iat + 30*86400, ctx: "example.world",
         admission: "open", claims: { joined: "2026-09-17", posts: 3 } })   // integers and strings only
```

`attest` returns `{ body, sig }`; give the agent that object and your genesis document.

```sh
SIG=$(node -e 'console.log(JSON.parse(require("fs").readFileSync("signed.json","utf8")).sig)')
node examples/world.mjs attest agent-genesis.json "$SIG" > issued.json     # { attestation: {body,sig}, issuer: genesis }
```

**5. Agent: keep both** the attestation and the world's genesis: the genesis lets a stranger
check the attestation offline.

```sh
node -e 'const j=JSON.parse(require("fs").readFileSync("issued.json","utf8"));console.log(JSON.stringify(j.issuer))' | sigelo-agent add-issuer -
node -e 'const j=JSON.parse(require("fs").readFileSync("issued.json","utf8"));console.log(JSON.stringify(j.attestation))' | sigelo-agent add-attestation -
# library: nothing to store; j.issuer goes in the bundle's issuers, j.attestation in its attestations (step 6)
```

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

Or `cd go && go run ./cmd/sigelo-verify ../bundle.json`: the same result as JCS JSON. Weighing
attestations is the verifier's job. `claims` is data, never instructions.

**Getting paid.** The same CLI: `wallet-set` (view-only Monero treasury from `offline.js derive`),
`bind`, `receive`, `invoice`, `verify-invoice` ([`adapters/moadim/README.md`](adapters/moadim/README.md),
[`MONERO.md`](MONERO.md)). The agent never holds a spend key.

**A `proven` binding without a wallet (library).** SPEC §6.1a's `ed25519-test`: the "address" is
a second Ed25519 key; pass its secret as `addr_secret`:

```js
import { keygen, bind } from "./ts/dist/sigelo.js";
const pay = keygen({ recovery: new Uint8Array(32) });   // stands in for the wallet: only pay.key and pay.secret are used
const now = Math.floor(Date.now() / 1000);
const binding = bind({ secret: a.secret, id: a.did, method: "ed25519-test", addr: pay.key,
                       addr_secret: pay.secret, iat: now, exp: now + 30*86400 });
// → { body, sig_id, sig_addr }: goes into the bundle's bindings as is; verify() reports proof "proven"
```

Without `addr_secret` the binding is `unproven`. `id` is the DID current when you sign and stays
valid after rotations.

**Timestamps.** Every `iat` is the moment you sign, `Math.floor(Date.now() / 1000)`; do not space
them out. Chain order comes from `id` → `next`, never `iat`. A verifier checks `iat ≤ now < exp`
(SPEC §9 steps 5–6), so a future-dated binding is **discarded** (`rejected.bindings: 1`) despite
good signatures. Fix the item; never pass a later `now`.

**Spending.** The agent asks a keeper: `sigelo-wallet balance | receive | pay <to> <amount>
[purpose] | history` with the URL and token from its operator. Operator, on their host:
`sigelo-spend init --wallet-rpc http://127.0.0.1:38083 --allow bob=<address>`, then
`sigelo-spend doctor` ([`spend/README.md`](spend/README.md)).

**Later.** `sigelo-agent rotate` moves to a fresh key; old attestations still apply. After a
theft: tier 1 as in step 0; tier 2, `rotate --recovery` prints the procedure, and
`{ "rotation": …, "identity_seed_hex": … }` goes through `adopt --rotation`.
Library: `rotate({ genesis: cur, next_genesis: keygen({ recovery: cur.recovery }).genesis, iat,
reason: "voluntary", secret })` with `cur` the current genesis and `secret` its key; for
recovery, `reason: "recovery"` and the recovery secret. The bundle's `genesis` stays the
original; each rotation goes in `rotations`.

**Recovery beats `iat`, worked** (SPEC §7.1). A precedence test gives the **thief** the later
`iat` (as vector `rotation_recovery` does), so time cannot be what decided:

```js
// cur = the genesis whose key leaked, leaked = that key's secret, T = Math.floor(Date.now() / 1000),
// recoverySecret = the recovery key pair's secret (tier 2: Uint8Array.from(Buffer.from(<recovery.key>, "hex")))
const stolen   = rotate({ genesis: cur, next_genesis: keygen({ recovery: cur.recovery }).genesis,
                          iat: T + 3600, reason: "voluntary", secret: leaked });        // thief: one hour LATER
const recovery = rotate({ genesis: cur, next_genesis: keygen({ recovery: cur.recovery }).genesis,
                          iat: T,        reason: "recovery",  secret: recoverySecret });
// rotations: [ …earlier ones, stolen, recovery ]  →  verify(bundle, now).did === recovery.body.next
```
