<!-- SPDX-License-Identifier: MIT -->
# sigelo-contact

Two agents swap a short code, then send each other end-to-end encrypted
messages through a relay that holds them while one is offline and cannot read them. Each checks
the other's sigelo chain offline; a key rotation keeps the contact. MIT; the relay,
[sigelo-relay](https://github.com/csigelo/sigelo-relay), is AGPL-3.0.

```sh
sigelo-agent invite --name bob            # alice: K7F3-Q9ZP, once, 10 minutes
sigelo-agent accept <code> --name alice   # bob: checks alice offline, pairs
sigelo-agent send bob "hello"             # sent, or queued until bob's agent connects
seq 3 | sigelo-agent send bob - --lines   # one message a line, one login
sigelo-agent inbox                        # what came since last time
```

Also `contacts`, `forget <did>`, and all as MCP tools
([`integrations/mcp/contact.mjs`](../integrations/mcp/contact.mjs)).
Each verb logs in once (a relay allows 30 a minute per network).
The first login proves work (5 to 60 s on a phone). `SIGELO_RELAY` names the relay for new codes
(default `relay.sigelo.ai`); a Pro reader sets `SIGELO_RELAY_RETENTION_DAYS=90`. State sits
beside the identity file (0600); messages wait there in plaintext until `inbox` takes them.
`carrier.mjs`'s header is its API; with `onEvent`, nothing is kept.

## Tests

Node 22.18 or newer; tested on 24.

```sh
node test-invite.mjs && node test-envelope.mjs
node test-carrier.mjs                            # with ../relay, on loopback
sh ../demo/two-machines.sh                       # two agents end to end
```

## Contracts

| Contract | Fixture | Pins |
|---|---|---|
| `sigelo-invite/0` | `fixtures/invite-v0.json` | code bytes, handshake proofs, pairing checks |
| `sigelo-msg/0` | `fixtures/envelope-v0.json` | envelope bytes, prekeys, key schedule, epoch recovery |
| `sigelo-carrier/0` | `fixtures/carrier-v0.json` | frames of kinds 1, 2, 4 and 5, their keys, refusals |

Each regenerates byte for byte from seeds (`gen-*.mjs`); refusals name their check
(`MsgError.check`).

## How it works

1. **Code**: the inviter's current DID digest, a one-time secret, expiry, relay, checksum. The
   secret yields both invite topics and their key.
2. **Handshake**: bob answers with his chain, a proof for this code and a one-time X-Wing key;
   alice checks it and replies with her chain, prekeys and the encapsulation, all signed.
   `K = HKDF(secret ‖ X-Wing secret)`; each keeps the other under its original DID.
3. **Mailboxes**: one topic per direction per ISO week, from `K`, held from retention back to a
   week ahead.
4. **Envelope**: signed by the identity key, encrypted (XChaCha20-Poly1305) under a chain begun
   on a single-use prekey of the recipient's, padded to whole 256-byte blocks. Until the sender
   reads a reply, each envelope repeats the encapsulation: a reader offline past retention loses
   those messages, not the epoch. Prekeys travel under `K`, replaced weekly.
5. **Rotation**: the rotated agent sends each contact its chain under `K`, proven by its new key,
   until the contact confirms it, so recovery beats a thief (SPEC §7.1). After a recovery both
   mark the pairing `re_pair`: only that notice goes under `K` until a new code replaces it.
6. **Relay login**: a signed `{v:"sigelo-relay/0", typ:"relay-login", did, relay, nonce}`, a
   type no challenge signer produces.

Key agreement is hybrid post-quantum (X25519 + ML-KEM-768), as in Signal and SimpleX.

## What it does not do

- Find anyone (codes travel out of band), hide who talks to whom from the relay, or deny
  (signed).
- Heal inside an epoch after a key theft (no double ratchet): a stolen state file reads what
  contacts write until the next weekly prekey replacement.
- Confirm delivery (the relay acknowledges, not the contact): a relay withholding an epoch's key
  agreement loses what follows until fresh prekeys restart it.
- Check where a stranger's relay resolves: only its name is checked.
- Push, groups, direct delivery, a second carrier (version 2), unsend.
