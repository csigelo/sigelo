<!-- SPDX-License-Identifier: MIT -->
# Contacts: connecting two agents with one code

## 1. The goal

The Owner: "make it extremely simple for operators to exchange agent contacts: my agent
generates a code, I give it to another operator, they put it in their agent, and the agents are
connected; then they communicate without further interaction with any server of ours."

An **operator** runs an agent. A **DID** (decentralised identifier) is the agent's sigelo name:
a hash of its first identity document, the **genesis** (SPEC §4).

## 2. The invite code

```
Alice:  sigelo invite          ->  sgl1...  (one line, ~130 characters)
          | sent by chat, mail, QR code
Bob:    sigelo accept sgl1...  ->  "connected to did:sigelo:z..., name it alice?"
```

| Inside | Bytes | Why |
|---|---|---|
| Alice's current DID | 32 | Bob checks Alice against it |
| one-time secret | 32 | proves Bob holds the code; works once |
| expiry | 4 | default 24 hours (proposal) |
| where to meet | ~20 | the relay's address |
| version, checksum | 5 | catches typos |

~93 bytes: ~130 characters in base58 (letters and digits minus look-alikes).

1. Alice's agent keeps the secret and opens a **mailbox** named by a hash of it on the **relay**,
   a server that holds messages (section 6).
2. Bob's agent posts its **bundle** (the self-contained proof of its identity, SPEC §8) and a
   signed answer, encrypted with a key made from the secret.
3. Alice's agent verifies the bundle offline, checks the answer, deletes the secret and replies
   with its own bundle. Bob's agent checks it against the code.
4. Both run the key agreement of section 3 and move to private mailboxes (section 4).

This is our tested pairing contract (`adapters/hermes/pairing/`) with a code instead of a
hand-typed address: a reused code fails `challenge_unknown`, an old one `challenge_expired`. Its
challenge lives 300 seconds, too short for humans, so the invite needs its own expiry.

**Key rotation** gives an agent a new key and current DID (SPEC §7). Each side stores the
contact under the peer's **original** DID with every rotation seen, as
`accept/node/sigelo-pair.mjs` does: a rotation keeps the contact, and a recovery (the operator's
offline key overriding a thief) still wins.

## 3. The message envelope

An **envelope** is one message in transit.

```
[ message + topic label ]      signed by the sender's identity key
[ all of the above ]           encrypted for the one recipient
[ mailbox name | ciphertext ]  <- all the relay sees
```

Signing inside hides the signer from the relay. The signature needs its own prefix (e.g.
`sigelo-msg/0`) so it can never pass as a sigelo document (THREAT-MODEL §2.5c).
Undecided: signing every message lets a recipient prove what you said; Signal avoids that. We
could sign only the setup.

**Key agreement**: two agents agree a secret key over an open line. We use two at once,
"hybrid": **X25519** (classic elliptic-curve exchange) plus **ML-KEM-768** (post-quantum,
a 2024 US standard). Why: an eavesdropper can record traffic today and decrypt it when
a quantum computer exists ("record now, decrypt later"). ML-KEM resists that; X25519 is long
tested; the key holds while either does. Signal and HTTPS already do this.

**Prekeys** give **forward secrecy**: keys stolen today must not open yesterday's messages. Each
agent hands its contacts single-use public keys in advance; a sender uses one while the
recipient is offline, who deletes it after use. Keys keep changing (a "ratchet").

**Outside the core.** The core stays one suite: Ed25519, SHA-256, JCS (canonical JSON); SPEC §11
excludes encryption. The envelope is a separate MIT package using the core only to verify
identities.

## 4. Addressing

```
shared secret --hash("A->B", week)--> name 7f3a...   Alice writes, Bob reads
              --hash("B->A", week)--> name c91e...   Bob writes, Alice reads
```

Mailbox names come from the secret only the two agents share and change weekly (proposal).
Nobody else can compute, find or link them. This is not discovery (out of scope): nobody can be
looked up.

One connection, many topics: an agent keeps one relay connection and listens on two names per
contact. Conversation topics ("billing", "tests") are labels inside the encryption.

Limit: the relay sees which names one connection uses, and from which internet address, so it
can group them. Mitigation: one connection per contact, or Tor (an anonymising network).

## 5. Carriers

A **carrier** moves envelopes; any will do. **MQTT first** (Message Queuing Telemetry Transport, the smart-home sensor protocol): tiny
clients in every language; the agent dials out, so it works behind home routers; a **persistent
session** makes the broker hold messages while the agent is offline (store-and-forward). Caveat:
a broker queues only for a mailbox someone listened on before, hence step 1.

**Later:** DeltaChat (chat over e-mail), SimpleX (relay queues, no user IDs).

**Direct** (peer-to-peer) when both are reachable (same network, public address): free. Alone
it fails: both must be online at once, and most home and mobile connections refuse incoming
calls. Something always-on must hold messages.

| System | What | Verdict |
|---|---|---|
| Tox | peer-to-peer messenger | no offline delivery; no |
| Briar | Tor, Bluetooth, Wi-Fi, optional mailbox | Android-centred; borrow ideas |
| Bitchat | Bluetooth mesh | local radio; no |
| Yggdrasil | encrypted mesh network | reachability for direct, not storage; later |
| Nostr | signed events on public relays | other key type; possible carrier later |
| libp2p | full peer-to-peer stack | too heavy for a 100-line integration |
| Reticulum | mesh over radio and anything | off-grid niche; watch |
| IPFS | content-addressed storage | not messaging; no |

## 6. The relay

Dumb on purpose: it holds encrypted envelopes on random names while an agent is offline, then
deletes them. It is named in the invite and movable: an agent sends its contacts a signed "I now
listen at relay X" and listens on both for a while. Anyone can run one; we run the default.

**Resources** (estimates, not measured): Mosquitto (a standard MQTT broker) on one small virtual
server, 2 processors, 4 GB memory. An idle connection costs kilobytes: 10,000 agents ≈ 200 MB.
A million 4 KB messages a day ≈ 250 GB traffic a month, well inside the usual 20 TB. A few euros
a month. Queues capped (e.g. 7 days, 1,000 messages).

**Responsibilities:**

- Uptime: a watch; a backup relay named in invites.
- Abuse: rate and size limits; unreadable content cannot be filtered.
- Metadata: connection logs kept hours, nothing else.
- Law (lawyer to confirm): in the EU a public relay may be an "interpersonal communications
  service" (European Electronic Communications Code), with confidentiality duties. The EU
  child-abuse proposal ("chat control") may add scanning duties; status unchecked.
- Data protection (GDPR): no accounts, but internet addresses are personal data (EU Court of
  Justice, Breyer, 2016): privacy statement, short retention.

**Money.** The Owner's trade-off: pure peer-to-peer maximises independence and minimises what
can be sold; the relay is the convenience people pay for. So direct delivery and self-hosted
relays stay free: nobody is captive.

| Option | Sold | Compromise |
|---|---|---|
| Free | self-hosted relay, direct delivery | none: the exit |
| Hosted relay | longer retention, bigger messages, uptime guarantee, many agents per operator | billing brings accounts back, for payers only |
| Per-DID licence | pro relay features, checked offline like `spend/`'s licence | licence checks in open code invite forks |

Never: route payments, or hold anyone's identity keys.

## 7. Licensing

The relay service code (quotas, expiry, paid gate; Mosquitto keeps its own licence) is
**AGPL-3.0**: whoever offers a modified relay as a service must publish the changes, so a cloud
provider cannot take improvements private. Standard for servers; 1f916 uses it.

The protocol, envelope format, client libraries and invite code stay **MIT**, so any framework
embeds them freely. AGPL on the server never touches clients: talking to an AGPL server does not
put the client under AGPL.

## 8. Demo: Claude phone app to a laptop agent

The Claude phone app only uses remote **MCP connectors** (Model Context Protocol tools on a
server), no files, so it cannot hold an identity.

```
phone --MCP--> connector (sigelo.io) --MQTT--> relay --MQTT--> laptop agent
               per-pairing secret                              identity key
```

The connector acts for the human with a **per-pairing secret** minted by the laptop agent's
invite. Not an identity key: we never hold those. Consequences:

- The laptop agent sees a contact marked "human via hosted connector", not a DID, and should
  allow it less (no payments).
- End to end becomes end to connector: the connector decrypts this pairing, so its operator
  could read it. Other contacts are unaffected.
- No push: replies appear when Claude calls `inbox`.

1. Laptop: `sigelo invite --connector` prints a connector address carrying the secret.
2. Add it as a custom connector in Claude settings (unverified: whether the phone can add it or
   only use one added on the web).
3. Phone: "tell my laptop agent to run the tests".
4. Claude calls `send`; the connector encrypts and posts to the pairing's mailbox.
5. The laptop agent receives it, runs the tests, replies through the relay.
6. Phone: "any reply?"; Claude calls `inbox`.
7. `sigelo revoke` on the laptop kills the secret.

## 9. Identity root and backup

**Identity from a Monero 25-word seed?** Yes. MONERO.md §2 derives every identity and its
recovery key from one seed backed up as those words; built and tested in `ts/` and `go/`. Use a
dedicated seed, not the everyday wallet, so one leak cannot cost both money and identity.

**Move an existing random identity under a seed later?** Yes: one voluntary rotation to a
seed-derived key. Contacts keep it (original DID); the current DID changes. Correction: a
voluntary rotation must keep the old recovery commitment (SPEC §7), so to put recovery under the
seed as well, the old recovery key signs one recovery rotation.

## 10. Quantum resistance

Signatures: when post-quantum standards settle, agents rotate to a post-quantum key and contacts
keep them by original DID, though the core needs a new wire version for that key (the suite is
replaced, never negotiated). Encryption: hybrid from day one. Recovery: the genesis holds only a
hash of the recovery key, which a quantum computer cannot reverse, so recovery beats a quantum
thief until the key is first used.

## 11. Open decisions for the Owner

- Dedicated seed (recommended) or the existing wallet seed as identity root.
- Will the company operate relays (default, paid tier) or only publish the software?
- Default relay domain: suggest `relay.sigelo.dev`. A separate domain keeps abuse reports and
  blocklists off sigelo.io's site and mail. `.dev` forces HTTPS; `.online` is often blocklisted
  wholesale; `.org` suits the spec; `.ai` costs most.
- Confirm AGPL-3.0 for the relay, MIT for everything else.

## 12. Build order

Each step ships a fixture (fixed seeds, expected bytes) checked on every commit.

1. **Invite**: codes from seeds, round trip, typo caught, expiry, single use, rotated inviter.
2. **Envelope**: byte-exact; tampering, replay, wrong recipient, reused prekey refused; rotated
   sender accepted.
3. **MQTT carrier**: local Mosquitto, offline delivery, broker sees only random names.
4. **Direct**: same envelopes, relay fallback, no duplicates.
5. **Paid relay**: quotas, retention, offline licence check, signed relay move.
