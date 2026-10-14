<!-- SPDX-License-Identifier: MIT -->
# Two agents on two machines

Two agents pair by code, exchange 100 messages, one goes offline for a day, then rotates its
key. Nothing is lost, and the relay can read nothing. Then a thief copies the other's files: she
recovers with her recovery key, and the two pair again. The whole run on one machine, with an
injected clock and a relay on loopback at its default login rate, with a 12-bit proof of work:

```sh
sh demo/two-machines.sh        # DEMO PASS; the relay is relay/ here, else SIGELO_RELAY_DIR
```

By hand on two machines, A (alice) and B (bob):

## 1. Install, on both

Node 22.18 or newer (tested on 24), a clone of [csigelo/sigelo](https://github.com/csigelo/sigelo), then:

```sh
(cd ts && npm ci && npx tsc) && (cd contact && npm ci) && (cd adapters/moadim && npm ci && npm run build && npm link)
export SIGELO_RELAY=relay.sigelo.ai      # or your own: relay/README.md; both must use the code's relay
sigelo-agent init --recovery "$(sigelo-agent recovery-key --out recovery.key)"
sigelo-agent whoami                      # your DID
```

`recovery-key` writes the recovery key's secret to `recovery.key` (0600) and its public half to
`recovery.pub`, and prints that half, which `init` commits to. Move both off the machine now: it is the only way back after a
theft, and whoever holds it can take the identity.

Exit codes, for scripts: 0 done; 1 refused or offline, the reason on stderr and any JSON on
stdout (`inbox` offline exits 0 once it printed messages: they are taken); 2 usage, or no identity
yet; 3 `inbox --expect` when no message came.

## 2. Pair by code

A:

```sh
sigelo-agent invite --name bob           # K7F3-Q9ZP: say it to B's operator (--long: sgl1…; --json: both)
```

The first login of an identity proves work, 5 to 60 s on a phone: a line on stderr says so before,
and another when it is done.

The short code works once and for 10 minutes: say it, text it, write it down. Case, dashes and I/L/O
for 1/1/0 do not matter. `--long` prints the one-line code instead (24 hours; for agent channels).
Whoever holds either can answer it, so treat it like a one-time password.

B:

```sh
sigelo-agent accept K7F3-Q9ZP --name alice   # "waiting": the answer is at the relay
```

`accept` prints the DID the code names, for B's operator to check with A's. So far B's agent has
checked only the code's checksum. The next time A's agent connects it checks B's bundle offline and
replies; the next time B's connects it checks A's reply against the code's DID:

```sh
sigelo-agent inbox                       # A: replies
sigelo-agent inbox                       # B: paired; sends his prekeys
sigelo-agent inbox                       # A: has B's prekeys
sigelo-agent contacts                    # each: the other's DID, name, relay, "Check with them: …"
```

The operators say the four words to each other. They come from the pairing key, which binds both
DIDs: the same words on both sides mean A paired with B, not with another code holder, the relay
included. 44 bits: for all 128, compare the pairing id (`pair`, 32 digits).

If both are online at once, `accept --wait 30` on B and `inbox --wait 30` on A finish it in one go.

A may `send` right after its first `inbox`: the message stays `queued` with A until B's agent has
connected, and goes at A's next `inbox`. B's first `send` reads A's reply first, then goes at once.

## 3. A hundred messages

```sh
seq 50 | sed 's/^/alice to bob /' | sigelo-agent send bob - --lines      # A
sigelo-agent inbox                                                       # B: 50, in order
seq 50 | sed 's/^/bob to alice /' | sigelo-agent send alice - --lines    # B
sigelo-agent inbox                                                       # A
```

`--lines` sends each line as a message over one login: a relay allows 30 logins a minute per
network, so a loop of 50 `send` meets `rate` at about 30. `"status": "sent"`: the relay accepted it
for the contact. Each message carries `from` (the sender's original DID) and `current_did` (the key
that signed it). If `inbox`'s reader goes away, the batch waits in `sigelo.local.held.json` for the
next call.

## 4. A day offline, then a rotation

B's agent stops. A sends ten more; they wait at the relay (14 days on the free tier). Each agent
holds its mailbox topics from a week back to a week ahead, so what is written after a week boundary
while B is away is held too. A day later, B rotates before reading them:

```sh
sigelo-agent rotate                      # B: new key, new current DID, same original DID
sigelo-agent inbox                       # B: the ten, in order, read under the new key
sigelo-agent send alice "after the rotation"
sigelo-agent inbox                       # A: from B's original DID, current_did = the new one
sigelo-agent contacts                    # A: current_did followed the rotation
sigelo-agent send bob "got it"           # A; B reads it at his next inbox
```

B's agent sends A its chain before anything signed by the new key. A merges it as pairing does: a
recovery rotation beats a thief's (SPEC §7.1).

## 5. A theft, a recovery, a new pairing

A thief copies A's files and rotates the key. The relay now follows the thief's chain, and A's
agent is locked out: `inbox` exits 1, and stderr names the refusal (`bundle`) and says to recover.
A brings `recovery.key` back for one command (on a real theft, on a clean machine with a copy of
the identity file, never the host it was stolen from: the same recovery key stays in force):

```sh
sigelo-agent recover --recovery-key recovery.key   # A: a recovery rotation; the stolen key is retired
sigelo-agent contacts                    # A: bob is "re_pair": "own_recovery"
sigelo-agent inbox                       # A: tells B of the recovery; the relay follows it too
sigelo-agent contacts                    # B, after his inbox: alice is "re_pair": "contact_recovery"
```

The thief's copy held the pairing key `K` as well, and with it every later mailbox of the pair. So
after a recovery neither side sends on `K` (a `send` exits 1, `re_pair`) or claims a new mailbox
under it, until a new code replaces it: A runs `invite --name bob`, B `accept`, then `inbox` on
each side as in step 2. Both show new words, and messages flow again under A's recovered key.
A message queued for B before the recovery is refused, and A's `inbox` reports it (`refused`,
`re_pair`). A contact still on sigelo-agent 0.1.2 follows the recovery but marks nothing: pair with it at once.

## 6. Check that the relay is blind

With your own relay:

```sh
node --input-type=module -e '
  import { DatabaseSync } from "node:sqlite";
  const db = new DatabaseSync("/var/lib/sigelo-relay/relay.db", { readOnly: true });
  console.log(db.prepare("SELECT topic, length(payload) AS bytes FROM messages").all());
  console.log(db.prepare("SELECT topic FROM claims").all());'
grep -c 'did:sigelo' /var/lib/sigelo-relay/relay.db*     # 0: no DID in the file or its WAL
grep -c 'after the rotation' /var/lib/sigelo-relay/relay.db*   # 0: no text
journalctl --namespace=sigelo-relay | grep -cE 'did:sigelo|[mi]/[0-9a-f]{32}'   # 0
```

Expect topics `m/` or `i/` and 32 random hex digits, payloads in multiples of 256 bytes plus a
header, accounts as hashes. The script checks this while B is offline (ten envelopes queued) and at
the end, against the DIDs, the code, the pairing id and every message.

What the relay does learn: which identity reads and writes which topic, when, and how much.

## How the script fakes a day

Every node process it starts (relay and agents) runs with `--import 'data:text/javascript,…'`,
which adds the seconds in one file to `Date.now()`. Writing 86400 there is the day offline:
retention, expiry and ISO weeks move as they would.
