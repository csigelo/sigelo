# sigelo in seven steps

An agent gets one identity, proves it to a world, receives that world's signed statement,
and carries it to the next world. Everything below runs offline except the two HTTP calls
to a real world. Commands use the agent-side CLI in `adapters/moadim/`; a world uses the
library in `ts/`, and `examples/world.mjs` is a complete mock world you can run against.
Needs node ≥ 22.18. The walkthrough runs in a clone (it uses `examples/world.mjs`); build once, from the repo root:

```sh
(cd ts && npm ci && npx tsc) && (cd adapters/moadim && npm ci)
mkdir -p bin && printf '#!/bin/sh\nexec node "%s/adapters/moadim/cli.ts" "$@"\n' "$PWD" > bin/sigelo-agent && chmod +x bin/sigelo-agent
export PATH="$PWD/bin:$PATH"                       # or `npm link` inside adapters/moadim
export SIGELO_IDENTITY=$PWD/agent.local.json         # default is ~/.config/moadim/sigelo.local.json
```

PowerShell: `cd ts; npm ci; npx tsc; cd ../adapters/moadim; npm ci; cd ../..`, then
`function sigelo-agent { node adapters/moadim/cli.ts @args }` and
`$env:SIGELO_IDENTITY = "$PWD\agent.local.json"`. The blocks below are POSIX shell: on Windows, run them in Git Bash.
`bin/sigelo-agent` is a two-line wrapper (gitignored) rather than an alias, because a script
ignores aliases: with `bin/` on `PATH`, the commands below work typed, pasted into a script,
after a `cd`, and from any program that runs `sigelo-agent`.

**Install without a clone.** After the first publish — not yet: the npm account and the Go
module path are an Owner decision (ROADMAP D1) — each implementation is one command:

```sh
npx sigelo-agent init --no-recovery              # agent-side CLI (or --recovery <z6Mk…|sha256:…>, step 0)
npx -p sigelo-spend sigelo-wallet balance        # the agent's wallet client; SIGELO_WALLET_URL/_TOKEN from the operator
npx sigelo-mcp                                   # stdio MCP server: identity tools, wallet verbs when a keeper is set
npx -p sigelo sigelo-offline new                 # the offline root tool (this page's ts/dist/offline.js)
go install <module>/cmd/sigelo-verify@v0.1.0     # the verifier; <module> is fixed at publication
```

plus static `sigelo-verify` binaries (linux/darwin × amd64/arm64, windows/amd64) and
`SHA256SUMS` on the release page. **Today**, the same packages come as tarballs from
`release/build.sh` (in a clone; it packs the committed tree), installed anywhere:

```sh
release/build.sh /tmp/sigelo-dist                # 4 npm tarballs, sigelo-verify binaries + source archive, SHA256SUMS
mkdir my-agent && cd my-agent && npm init -y >/dev/null
d=/tmp/sigelo-dist; npm install $d/sigelo-0.1.0.tgz $d/sigelo-agent-0.1.0.tgz $d/sigelo-spend-0.1.0.tgz $d/sigelo-mcp-0.1.0.tgz
npx sigelo-agent init --no-recovery
$d/sigelo-verify-linux-arm64 --conformance $d/test-vectors.json   # your os-arch
```

Install the `sigelo` tarball in the same `npm install` as the others: they depend on
`sigelo@^0.1.0`, which nothing but that tarball satisfies until it is on npm (`sigelo-mcp`
needs all four). `release/pack-test.sh` runs exactly this, and the MCP server and a Go build
from the source archive, in an empty directory. With `node_modules/.bin` on `PATH`, the
`sigelo-agent` commands below work as written.

**The world is a program you run, not code you write.** `examples/world.mjs` is the mock
world. Run it with node from the repo root (the directory holding `examples/`):

| Command | Prints on stdout (one line of JSON) |
|---|---|
| `node examples/world.mjs challenge <genesis.json>` | a challenge body `{ v, typ, did, ctx, nonce }` for that genesis's DID |
| `node examples/world.mjs attest <genesis.json> <sig>` | `{ "attestation": { body, sig }, "issuer": <the world's genesis> }` |

`<genesis.json>` is the agent's genesis document as it stands now (after a rotation, the new
one); `<sig>` is the agent's signature over the last challenge. The world keeps its identity
in `./world.local.json` (made on the first run, which warns on stderr that the world has no
recovery key: expected) and its outstanding challenges in `./challenge.local.json`, one per
DID, in the directory you run it from; `attest` answers the latest challenge for that DID,
once. Do not build a world of your own with the library: that is a different world.

**No CLI?** Each `sigelo-agent` command below has a `# library:` line doing the same with
`import { … } from "./ts/dist/sigelo.js"` (a `secret` is the `Uint8Array` `keygen` returns).

**0. Operator, once: pick a recovery tier.** The recovery key is what makes theft
survivable, and it only counts if it was created before the theft: the genesis holds its
hash, and nothing in a genesis can change later (SPEC §4). So the tier is chosen before
step 1. Why the agent would want one at all: [`WHY.md`](WHY.md).

| Tier | For | `init` gets |
|---|---|---|
| 0 | throwaway and ephemeral subagents | `--no-recovery` |
| 1 | the default whenever an operator exists | the `sha256:` commitment of the operator's 25-word root |
| 2 | high security, a human deep in the loop | the `z6Mk…` key of a dedicated offline machine |

**Tier 0: no recovery.** `sigelo-agent init --no-recovery`. If the key is stolen the identity
is lost for good: no rotation can take it back, and worlds MAY refuse to attest it (SPEC §4).
Fine for a subagent whose identity ends with its task.

**Tier 1: from the operator's 25-word root.** A root has **one** recovery key,
`k(S, "sigelo/v1/recovery/ed25519")` (MONERO.md §2), and every agent of that operator carries
its commitment; keeper-minted delegates get it automatically (MONERO.md §4.3). There is no
per-agent recovery key: one key recovers them all (MONERO.md §9 decision 2), and an observer
can group them by it (§4.6). On the operator's machine, networking down, with `age` (or `rage`)
installed (MONERO.md §4.5). The ceremony encrypts `S` to the Owner's age key; if the Owner has none
yet, make one first. Its file is the only thing that can ever decrypt the backup, so it stays
offline, with the Owner:

```sh
age-keygen -o owner-age.key                  # the Owner's age identity: secret (*.key is gitignored); rage: rage-keygen
node ts/dist/offline.js ceremony --net stagenet --recipient "$(age-keygen -y owner-age.key)" --out ceremony   # once per root; S goes only into ceremony/backup.age
node -e 'console.log(JSON.parse(require("fs").readFileSync("ceremony/fingerprint.txt","utf8")).recovery_commitment)'
# → sha256:3fb9…eb24 — public; this is what step 1's --recovery takes
```

**Without age**, or for an operator who already holds the 25 words: `node ts/dist/offline.js new`
prints a fresh root as 25 words (write them down: they are `S`, and nothing else keeps them),
and `node ts/dist/offline.js derive <25 words>` prints field `recovery.commitment`, the same
`sha256:…` line step 1 takes (or `recovery.public_key_multibase`, the `z6Mk…` key). No backup
file or keeper packages are made; to recover, type the words on stdin (below). `derive` also
prints keeper roots and the allowance spend key: offline only, never on an agent host.

A keeper-minted subagent does not run `init`: it makes its `POST /delegate` answer its
identity with `sigelo-agent adopt answer.json` (or `- <` it; only `identity_seed_hex` and
`genesis` are read, the token is not stored), and carries the commitment from then on.

To recover (the Owner, offline): `recover` decrypts the backup in memory and signs SPEC §7's
recovery rotation from the agent's last honest genesis (step 1's `agent-genesis.json`, or
the genesis of any bundle from before the theft):

```sh
node ts/dist/offline.js recover --genesis agent-genesis.json --backup ceremony/backup.age --identity owner-age.key --net stagenet > recovery.local.json
# a keeper-minted agent i: add --agent <i> --n <next unused rotation, ≥ 1> (INCIDENT.md §5); default: a fresh random key
# holding the 25 words instead: replace --backup/--identity/--net with `-` and type them on stdin
```

`recovery.local.json` is `{ did, rotation, identity_seed_hex }`: the rotation and the new
key, nothing else (the recovery secret and the root are printed nowhere). Carry it to the
agent by hand:

```sh
sigelo-agent adopt --rotation recovery.local.json && rm recovery.local.json   # it holds the new key
```

The genesis stays the original and the chain grows by one; attestations to the old DID still
count (SPEC §9 step 5), and the recovery beats whatever the thief signed from that node,
whatever its `iat` (§7.1). Worlds should be shown the new bundle and asked to re-attest.

**Tier 2: a dedicated offline machine.** For high security, where a human is deep in the
loop: a machine the agent never touches. In `ts/`:

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
or wherever `SIGELO_IDENTITY` points. Only the recovery key's hash is stored. The example
uses tier 2's `z6Mk…`; under tier 1 pass the `sha256:…` line instead (`init` takes either),
under tier 0 `--no-recovery`.

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
recovery rotation on the offline box, and it wins over anything the thief signed, whatever
the timestamps say. Tier 1: `node ts/dist/offline.js recover --genesis <last honest genesis>
--backup … > recovery.local.json` there, `sigelo-agent adopt --rotation recovery.local.json`
here (step 0). Tier 2: `rotate --recovery` prints the procedure with `recovery.key`; the
rotation and the new key's hex, as `{ "rotation": …, "identity_seed_hex": … }`, go through
the same `adopt --rotation`.
Library: `rotate({ genesis: cur, next_genesis: keygen({ recovery: cur.recovery }).genesis, iat,
reason: "voluntary", secret })` with `cur` the current genesis and `secret` its key; for
recovery, `reason: "recovery"` and the recovery secret. The bundle's `genesis` stays the
original; each rotation goes in `rotations`.
