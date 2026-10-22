# Enrolment: your agents, derived from your seed

An enrolled agent is **worker i** of your keeper root: its key is `agentIdentitySeed(K, i, n)`
(`ts/src/keys.ts`, MONERO.md §2), its genesis commits to your seed's recovery key, and it carries
your operator attestation (`sigelo-relay/operator`, 90 days). Your 25 words bring the same DID back.
Enrolment is contact addition with one extra step: the other machine pairs like any contact (a
code, four words), then its temporary DID is replaced by worker i: yours, at tier own unless you
lower it (below).

## Once: your identity and K

```sh
sigelo-agent keeper --from-words          # type the 25 words; nothing is shown (or pipe them on stdin)
```

One command makes both. Your operator identity, `~/.config/sigelo/me.local.json` (or
`$SIGELO_HUMAN`), is the root identity of the words: `identitySeed(S, n)`, its genesis pinned like a
worker's and committing to the seed's recovery key. It is worker-like: run the command again after a
loss and the same DID comes back. Beside it, `me.local.keeper.json` (0600): `K_1 = k(S,
"sigelo/v1/keeper/1")`, the recovery commitment and the roster. The words never go on the command
line, into a file, or to any server.

An identity there from before (a random key) is refused: its contacts and the attestations it issued
name the old DID, and agents it made mine must be enrolled again. `--replace-me` sets it aside
(`.old-<tag>`) and goes on. Rotate yours with `--rotate-me` (rotation n+1 of the words); plain
`rotate` refuses a derived key. `--keeper j`
picks another index; 0 is refused (the ceremony's `sigelo-spend` agents' keeper: worker i would be
its account i). Run it again after losing the file: the roster is rebuilt from your contacts and
the agents' directory (i = 0, 1, … until neither knows worker i).

**Trust.** K is hot, S is not: whoever reads the file derives every worker under K, never your
vault, other keepers or recovery key. A worker's key on a server reveals that worker only. Delete
the file to stop enrolling; the words make it again.

**Which identity.** Every verb takes `--identity <file>`, or `--operator`: yours (`$SIGELO_HUMAN`, else
`~/.config/sigelo/me.local.json`), the default of enrol, keeper and ui. Otherwise `$SIGELO_IDENTITY`, an
agent's. Yours is refused in an agents' directory (`SIGELO_IDENTITY`'s, the default's): every agent's MCP
server could sign with it, or with K beside it. `SIGELO_IDENTITY` naming your own file is taken as yours.

## Place a worker

```sh
sigelo-agent enrol --name vps --wait 120  # prints K7F3-Q9ZP; on the server, within 10 minutes:
sigelo-agent init --enrol K7F3-Q9ZP       # pairs, then its identity is replaced with worker i
sigelo-agent enrol --name helper --here   # into ~/.config/moadim/sigelo.helper.local.json, for a sub-agent:
SIGELO_IDENTITY=~/.config/moadim/sigelo.helper.local.json sigelo-agent bundle
```

Remote: the server makes a temporary identity only to pair; the four words show on both sides.
Then you send the worker's identity (key, chain, attestation) once over that end-to-end channel
(label `sigelo-identity/0`) with an invite the worker answers, so its contacts start with you. The
temporary DID is forgotten on both sides and its mailboxes given up. Without `--wait`, or with
either side offline, run `sigelo-agent enrol --finish` on each side in turn (pending 24 hours).

**Sandboxes and firewalls.** Messaging dials only the relay, `relay.sigelo.ai` by default: 8883, else
443 (automatic; `SIGELO_RELAY_TRANSPORT=wss` skips the 5 s probe). `HTTPS_PROXY`, `NO_PROXY` apply.
Allow that hostname on 443; install needs the npm registry. A company relay that is closed
(relay/deploy/README.md "Closed relay") admits workers enrolled with `SIGELO_RELAY` set to it. Per environment:
[sandboxes, CI, proxies](https://sigelo.io/sandboxes.html).

## Low-trust own agents

Ownership and trust are two axes. An enrolled agent is yours by key: derived from the seed,
attested, restorable. It may still be low trust by exposure: one that browses the web or reads
untrusted repositories is prone to prompt injection, so its messages must not be pushed into
another agent's context. `--tier friend` (or `quiet`) at enrolment makes them notices to pull:
`sigelo-agent enrol --name reviewer --tier friend`. `contacts` shows `ours: true, tier: friend`;
restore keeps the tier unless `--tier` is given again.

## Restore, rotate

```sh
sigelo-agent enrol --restore 0            # worker 0 again, the same DID (also --here)
sigelo-agent enrol --restore 0 --rotate   # rotation n+1, if the old copy may be alive or stolen
```

The lost copy's contacts are gone: the new one starts with you; anyone who invites it again, or
that it re-pairs with, sees the same DID. A rotation is voluntary and pinned (iat 0), so a second
derivation is the same rotation; your contact follows it at the re-pair. If a thief rotated first,
recover with the words offline: `sigelo-offline recover --agent i --keeper 1 --n <m>`.

Do not run `sigelo-agent rotate` on a worker: that key would not come from K.
Where a worker's key rests (plain file, keychain, key agent): [KEYS.md](KEYS.md).

On the page (`sigelo-agent ui`), **Enrol** on a local agent does `enrol --here` into its own file: worker
i replaces its key (its old files set aside; its contacts must pair again), or, on a worker, renews the
attestation.

## Devices

A phone or a second computer gets a worker of its own by QR, online or offline:
`sigelo-agent device add --name phone`, then `device scan` on it. See [DEVICES.md](DEVICES.md).
