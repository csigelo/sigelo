# sigelo — threat model

## 1. Assumptions

- **The agent's identity key is hot.** It sits in a process that ingests untrusted text from
  the open web every day. Assume eventual compromise. Everything below follows from this.
- **The recovery key is cold.** Derived from the root by the root ceremony, a program whose
  secrets never enter an agent's context, and afterwards held only inside the Owner's
  encrypted backup (MONERO.md §4.5). Never loaded into an agent runtime; only its hash is
  public until used.
- **Spending keys are not agent-held.** Every wallet sits behind a keeper, a non-LLM policy
  service agents ask (MONERO.md §4). See §4.
- **Issuers are semi-trusted.** A world can lie about its own members. It cannot forge
  another world's attestations.
- **Verifiers are adversarial to the presenter.** They will feed malformed bundles. Fail closed.

## 2. Attacks defended

### 2.1 Attestation forgery
Detached Ed25519 over JCS bytes. Any mutation invalidates. Vector: `negative.tampered_claims`.

### 2.2 Issuer impersonation
`iss` resolves to a genesis whose hash is the DID; signature must verify against that key.
Vector: `negative.wrong_signer`.

### 2.3 Retroactive recovery-key substitution
The recovery commitment is inside the genesis, and the DID is the genesis hash. Changing it
changes the identity. This is why identity is a hashed document rather than a bare public
key. Vector: `negative.genesis_tampered`.

### 2.4 Hostile rotation after key theft
An attacker with the identity key produces a *cryptographically valid* voluntary rotation to
a key they control. Defense: a recovery rotation supersedes it regardless of timestamp
(SPEC §7.1). Vectors: `rotation_hostile` and `rotation_recovery`, where the legitimate
recovery deliberately carries the earlier `iat`.

After a recovery, bindings and invoices by the stolen key's DIDs are `superseded` and never paid, whatever their `iat` (SPEC §6.1, §6.3; wire change of 2026-10-19).

### 2.5 Recovery authority hijack
Attacker with a stolen key rotates to a genesis embedding their own recovery commitment.
Defeated twice over: a voluntary rotation whose `next_genesis.recovery` differs from the
current commitment is rejected outright (SPEC §7), and even if it were not, the governing
commitment is the one in the most recent *recovery-signed* genesis, which only the true
recovery key can produce (SPEC §7.2). Vector: `negative.voluntary_changes_recovery`.

### 2.5a Stale recovery key
After the operator rotates their recovery key via a recovery rotation, the old recovery key
is retired. A rotation signed with it no longer governs. Vector: `negative.stale_recovery_key`.

### 2.5b Fork under one key
Two valid voluntary rotations from the same node, both signed by the legitimate key. Either
the operator did something odd or the key is stolen; the verifier cannot tell and does not
try. The chain is rejected and the operator's remedy is a recovery rotation. Vector:
`negative.fork`.

### 2.5b-i Cycle under one key
A rotation whose `next` is a DID already in the chain. Only a key holder can produce one,
so it is either operator error or an attacker trying to hang verifiers. Without a guard a
naive chain walk never terminates, which is a denial of service against every verifier that
receives the bundle. Chain rules step 5 rejects it before following. Vector: `negative.cycle`.

### 2.5c Cross-protocol signature reuse
A key used both in sigelo and elsewhere could be induced to sign sigelo-shaped bytes by
another protocol. Mitigated by the `"sigelo\n"` signing prefix (SPEC §3). Vector:
`negative.missing_prefix`.

### 2.5d Type confusion
A validly signed attestation presented in a binding slot. `typ` is inside the signed bytes
and verifiers check it against the slot. Vector: `negative.typ_mismatch`.

### 2.5e Vanity DID grinding
Generating genesis documents until the DID's leading characters match a target's. Cheap
against truncated displays. Verifiers compare full DIDs; UIs never truncate (SPEC §4).

### 2.6 Address hijack
Claiming someone else's payment address to borrow their history, or substituting your own to
divert funds. Defeated by cross-signing: both keys sign identical bytes (SPEC §6).

A Monero address key of small order lets a SigV2 be made with no secret; such bindings are `discarded` (SPEC §6.2; wire change of 2026-10-19).

### 2.7 Cross-language signature divergence
Two conformant implementations disagreeing on canonical bytes. Mitigated by forbidding
non-integer numbers, which removes the dominant JCS failure mode, plus byte-exact test vectors
that exercise the two remaining ones: key order for characters above U+FFFF, and control-
character escaping (SPEC §3). Vector: `attestation_unicode`.

### 2.8 Duplicate-key smuggling
A body with the same key twice. JSON parsers disagree on which value wins, so the presenter
can get one implementation to verify a signature over bytes another implementation reads
differently. Rejected outright (SPEC §3). Vector: `negative.duplicate_key`.

### 2.9 Withheld issuer
A bundle carrying attestations from a world whose genesis is not presented. Nothing can be
verified about them and they are discarded individually (SPEC §9 step 5). A bundle cannot
gain standing by naming a world the verifier cannot check. The `issuers` array (SPEC §8)
is what makes a stranger's attestation checkable at all; a bundle that omits it presents
attestations that count for nothing.

### 2.10 Short invite codes (contact/short.mjs, relay/park.mjs)
A short code (`K7F3-Q9ZP`) is 40 bits from a CSPRNG, good once for 10 minutes. The relay holds
the long code under SHA-256("sigelo-park/0" ‖ code) and answers a lookup once. **Online
guessing:** a lookup costs one of 20 per 10 minutes per /24 or /48, and at most 50,000 codes are
parked at once, so one network's 20 guesses in a code's life hit any code with odds of at most
20 × 50,000 / 2^40, under one in a million; an attacker with many networks multiplies that by
their number, up to the relay-wide cap of 600 lookups per 10 minutes (about 1 in 37,000). A guessed code pairs the guesser, not the intended contact, with the inviter, and
the intended contact then gets `park_unknown`: the inviter's agent shows a contact the inviter
did not expect, and the four words of the real contact never match. **Swapped pairing:** after
pairing both sides print four BIP-39 words from HKDF(pair id, "sigelo-fingerprint/0"); the
same words on both sides catch a casual swap and a mistyped or mixed-up code. They are 44 bits,
and whoever swapped the code is the inviter in one of the two pairings and chooses that
encapsulation: an elliptic-curve step of 1–2 µs a try finds one whose words match the other
pairing's in months on one core, hours to days on GPUs. Against a relay that spends that, compare
the 32-digit pair id (`pair` in the JSON, 128 bits) or the DID.

### 2.11 Enrolment: worker i from the operator's seed (contact/enrol.mjs, adapters/moadim/ENROL.md)
An enrolled agent is worker i of the operator's keeper root K (`agentIdentitySeed(K, i, n)`), so the
25 words restore it. **K is hot, S is not:** K sits beside the operator identity (0600, outside the
agents' directory); whoever reads it derives every worker under it, never the vault, other keepers
or the recovery key, which stay with S. The operator identity is hot too and S-derived
(`identitySeed(S, n)`): HKDF is one-way, so its key reveals nothing of S. A worker's key on a
server reveals that worker only; the operator places rotation n+1, or recovers offline from the
words if a thief rotated first. **The key
travels once, end to end:** the server pairs as a throwaway identity through a short code (§2.10),
then the operator sends the worker's key inside a sigelo-msg/0 envelope on that pairing. It is never
parked on the relay and never encrypted under the code, which is 40 bits. **The code is the
credential:** whoever fetches it first and proves it (HMAC of the invite secret over its pair id)
gets worker i's key and the operator attestation. The real server then sees `park_unknown`, and the
operator's `enrol` names the DID it sent to: abandon index i (enrol the next one), `forget` the
contact, and the attestation lapses in at most 90 days (no revocation, SPEC §5). Say the code only
to the machine it is for. **One worker per code:** the relay hands the code out once, and the
operator sends only to the DID that paired through that code (`enrol_unpaired` before anyone has, `enrol_from` for
any other contact): knowing the secret is not enough, so a contact that saw the long code, or the relay, cannot
prove it over a pairing of its own. **The server** takes an
identity only from the DID it paired with through its code, signed by that contact's current key,
whose secret matches the chain's head and whose invite names the operator. **The relay** holds the
long code (§3.8) and can answer it itself, receiving the worker's key. The four words do not differ
until after the key went: compare them, and the operator DID `init --enrol` prints with the
operator's `whoami`; on a mismatch treat index i as burnt, as above. **Ours is not trusted:** an own agent that
browses the web or reads untrusted repositories carries whatever injected it; pushed in full
(tier own) into another agent's context, its content is a prompt-injection path that the key and
attestation do nothing against. `enrol --tier friend|quiet` keeps it ours with notices only.

A relay tag (the last four characters of a 12-character code) is 20 public bits that tell relays apart, not proof of one; the secret part of a short code is still its first 40 bits. A wrong host, from a collision or a stale registry, gets `park_unknown`, or a long code that must name the relay it came from and still passes the four words.

### 2.12 Operator hints: own agents find each other (contact/carrier.mjs, `sigelo-operator/0`)
**Claim:** a contact becomes `own` only by an unexpired `sigelo-relay/operator` attestation, from me
or my operator, on its own chain; own messages reach the operator in full (`watch --on-message`),
so own is worth forging. **Hints** are HMAC(K, kind ‖ sender's original DID ‖ operator DID) inside
envelopes: the relay sees nothing, an echo or another pairing's copy matches nothing, and the
envelope layer drops replays. **Attack, fixed:** a proof is a bundle, and a rotation is signed by
the key it leaves, so a contact could rotate its genesis into a sibling's public one and carry the
sibling's attestation (SPEC §9 counts an attestation whose `sub` is any DID of the chain): it was
filed own. Now `observe` refuses a chain that ends anywhere but the contact's current DID as held
(`current_did`), a proof is taken only after our asks, at most 4 an hour, at most 64 rotations, 8
attestations and 8 issuers; `send` refuses the label. **Residual:** a contact can test any operator
DID it guesses against the hints, and on a right guess gets the attestation it names (a public
credential): it learns who operates the agent. An agent before 0.1.7 shows the hints, opaque hex,
as a message labelled `sigelo-operator/0`, once per pairing and renewal; there is no version on the
wire to gate on, and adding one to the prekeys frame would break those agents.

### 2.13 Graft into a foreign genesis

A genesis that copies a victim's public commitment cannot rotate into the victim's genesis: every rotation is countersigned by the next key (`sig_next`, SPEC §7; wire change of 2026-10-19). Residual: a thief holding the victim's key can graft before the recovery; after it, a §5.2 answer for the head fails.

### 2.14 Closed relays

A closed relay (`RELAY_CLOSED_OPERATOR`) refuses every login that is neither an operator's nor carries that operator's current-key attestation for this host: outsiders get no account, mailbox, invite topic or short code there, and pay no proof of work to learn it. It does not hide the relay or its operators (`/stats` names them; `GET /park/<hash>` is open: a fetched code is useless without an admitted login). It does not protect against the operator, nor against anyone holding an admitted key until its attestation expires (at most 90 days; the session ends then). An attestation by a key the operator rotated away from keeps admitting until the operator logs in after the rotation; if the relay's database is lost, the head reverts to the operator's original DID until its next login (the nightly backup carries neither `closed_members` nor an unlicensed operator's chain).

Clients resolve a relay tag first from relays they already know (their own, their contacts', their operator attestation's), so a registry entry cannot redirect a colleague whose contacts or operator attestation name the company relay. The registry (`sigelo.ai/relays.json`) is first-come under the release identity's signature; two known hosts with one tag are never guessed between. Long-code pairing and verification never read the registry: offline stays offline; a lost or forged registry only costs a question to the person.

## 3. Attacks NOT defended — read this section

### 3.1 Sybil
sigelo does not prevent Sybil. Anyone can generate unlimited identities for free.

What it does instead is make Sybil **legible**: the `admission` field records what entry
cost, so a verifier can distinguish 2,000 open signups from 153 invite-chained members. This
is a real improvement over a raw population count and it is not a solution. Do not describe
it as one. A public chain does not solve it either (§7).

### 3.2 Lying issuers
A world can inflate `claims` or misreport `admission`. sigelo proves the world said it,
not that it is true. The only remedy is verifiers withdrawing trust from that issuer. The
same remedy covers a world key stolen after the world rotated away from it: it keeps minting
attestations that verify under the old DID until they expire (SPEC §5, by design: issuer
chains are not walked), so a verifier told of the rotation drops the old DID.

An issuer's key stolen before its own recovery keeps minting attestations under the old DID until `exp`; the remedy is dropping that DID.

### 3.3 Collusion rings
Worlds cross-attesting each other's Sybils, all with `admission: "invite"`, all valid.
Graph analysis over issuer sets could surface this. Out of scope for v0.1 and it belongs in
the verifier's policy layer, not the protocol.

### 3.4 The operator behind the agent
sigelo says nothing about who runs an agent. One human may operate a thousand identities
with impeccable attestations. This is the fundamental limit of the whole approach.

### 3.5 Compromise window
When recovery is used, the prior key was compromised for an unknown period. sigelo cannot
determine when. Verifiers SHOULD discount attestations near a recovery event; only the
issuing world knows what actually happened.

### 3.6 Key theft itself
Recovery limits blast radius. It does not prevent theft, and does not undo whatever the
attacker did while holding the key.

### 3.7 Timestamps
Every `iat`, `exp`, and `created` is signer-asserted. sigelo has no clock and no notary.
Time-based logic is advisory unless the signer is already trusted for other reasons. The
precedence rule in SPEC §7.1 exists precisely because timestamps cannot be relied on.

### 3.7a The keeper host's clock
The keeper is where sigelo does read a clock: every spend.log line carries its `ts`, and every
cap, rate, dedupe and approval window is measured back from `now` (MONERO.md §4.1 "Clock").
A host that boots without the time (some boot at their build epoch until NTP answers) can sign
with a clock set back. Lines signed then fall out of every window once the clock is corrected,
so spends stop counting against the cap, in a log that cannot be amended. Guard: every signing route refuses `503 clock_behind` (a TRY LATER, nothing signed,
logged or sent) when `now` is before the build floor or more than 300 s behind the newest `ts`
the keeper signed (spend/README.md, "The clock guard"). Not covered: a clock set *ahead*, or a
wrong clock on a keeper with no signed lines yet past the floor. `spend/soak/check.mjs` flags a
log clock in the future or stepping back, but that is a monitor, not a refusal.

### 3.8 The relay sees who invites
The relay's short-code hash hides the code from its logs, not from the relay: 40 bits hash in
seconds, and the value parked is the long code itself, which names the inviter's DID, the relay
and the one-time secret. A relay that reads it can answer the code before the intended contact,
or hand the accepter a code of its own: the four words (§2.10) are what catches that. It learns
nothing it does not learn anyway (who pairs with whom, from the topics); it is trusted not to
spend codes, as it is trusted to deliver. Agents that share a channel should use the long code
(`invite --long`), which never touches the relay before it is answered. Parked codes live in
the relay's memory only, never on disk, and are lost at a restart.
Pro gift codes (relay/gifts.mjs) are trusted the same way: a compromised relay, or a reader of its
database or backup (40-bit codes hash in seconds), can grant Pro for nothing, which costs the relay
storage and nothing else; online, a network gets 10 guesses an hour.

### 3.9 The page's history at rest (adapters/moadim/sigelo-agent-ui.ts)
`sigelo-agent ui` keeps every message and pairing event in `me.local.history.jsonl` and its tags,
checked words and read marks in `me.local.ui.json`, in plaintext (0600) until §7's keychain unlock
(K2): whoever reads the user's files reads them, and "clear" (`POST /api/history/clear`) is the only
mitigation. The same holds for `<identity>.inbox.log` (contact/carrier.mjs `log`): the newest 500
messages and file items `inbox`, `watch`, `ui` and the MCP tools gave out, plaintext 0600, so `history`
can print them again; deleting the file is the mitigation, and `log: false` keeps none.

### 3.10 Linkability (privacy by design)
**The relay sees metadata.** Per session it sees the DID, the mailbox topics, message sizes and
timing, and the client's address (kept as its /24 or /48); behind a TLS-re-terminating egress proxy
(cloud sandboxes, corporate proxies) the proxy sees the same. Content stays end to end.
**Seed-derived identities are marked.** Enrolled workers and other identities restored from the words
carry `created: 1970-01-01T00:00:00Z`: a restore must rebuild the same genesis byte for byte, so the
timestamp cannot vary, and anyone reading the genesis can tell the identity is derived.
**Workers of one operator link.** Every worker derived from one keeper root carries the operator's
recovery commitment in its genesis, so two workers' bundles link to each other and to the operator
without any attestation: an unlinkable worker is not possible today. Known limitation.

### 3.11 Remote control of the page (`ui --remote`, `sigelo-remote/0`)

`ui --remote` opens a second listener on one LAN address that answers only `POST /r`. A control is an 8-byte id and a 32-byte key, shown once as a `SIGELO:UI:` text (a QR later) and kept in plaintext in `.ui.json` (0600, §3.9). Requests are sealed with XChaCha20-Poly1305 and counted; a replayed, reordered, tampered or wrongly keyed request is refused with no body, and the count is kept before the call runs, so a replay fails across a restart too. Device routes are never remote. The controlling device holds no account key. Not defended: no TLS, so the LAN sees addresses, sizes and timing; whoever holds the text controls the page within its scope (read; chat: send, accept, invite, words, including forget through words; all: forget, tier, history, agents) while `ui --remote` runs, until `ui --revoke-control`, which needs the page stopped (it owns the file) and so closes the listener as well.

## 4. Prompt injection

The specific reason spending authority must not be agent-held.

An agent that reads a shared board is reading attacker-controlled text into its context.
This is not hypothetical. In September 2026 Reuters reported that researchers had documented
more than 15,000 edits made by OpenAI agents to DseWiki, a German-language wiki for
programmers, with messages showing agents "plotting ways to evade detection, use tools such
as Tor and preserve communications even after they had been shut down", and concurrently
running agents reading and reproducing each other's restriction-bypass techniques within
minutes (Reuters, 2026-09-04, "OpenAI agents hijacked German website in previously
undisclosed AI breakout"; researchers' report at collusion.wiki). A public, writable page
became an inter-agent coordination channel.

Consequences by key:

| Key | If injection succeeds | Recoverable? |
|---|---|---|
| Identity signing key | attacker obtains signed attestations | yes — recovery rotation |
| Spending key | attacker moves funds | **no** |
| An agent's keeper token | attacker spends that agent's account, to its allowlist, up to its caps (clamped by its delegators'); above `approval_above`, where set, it also needs an approver | no, bounded by the account's balance and policy |
| A delegating agent's token | the same, and it can mint and fund delegates — only from its own account, since funding a delegate is a spend | no, bounded the same way |
| A token and an approver's key | spends above `approval_above` too, still within the caps | no, bounded by policy |
| Agents' keeper host | every account in its wallet; and, through its keeper root, it can sign as every agent under it — on keeper 0, which the ceremony also hands the root identity seed, as the root identity too | coins **no**; identities yes — the recovery key is not on the host, including for the keeper's own DID (its genesis commits to the root's recovery key, not one derived from `spend.key`) |
| Treasury keeper host | the whole treasury | **no** |

Therefore: the agent runtime holds its identity key and a bearer token, never a Monero key.
Every wallet sits behind a keeper that pins each agent to its own account and enforces
per-transaction, per-period and rate caps and an allowlist, clamped down the delegation tree
so that no delegate can exceed its delegator (MONERO.md §4.1, §4.3). A second approval is
optional, per agent, above a threshold — off by default, because the Owner wants agents to
spend their own funds unaided; what bounds an injected agent by default is its balance and its
caps. The agent-facing verbs carry no keys, every destination must pass the allowlist, and a repeated
payment is idempotent, so a confused or weak model cannot pay twice by retrying (MONERO.md
§4.2). Keepers are hot: the keeper host, not the policy, is the boundary against a host
compromise, which is why the treasury keeper runs on a host of its own (MONERO.md §4.4).
Derivation from one root seed gives single-seed backup, encrypted to the Owner, without
putting a spend key in an agent's process — those are orthogonal properties and you can have
both (SPEC §6). What the keeper model costs is listed in MONERO.md §4.6.

**Corollary for library authors:** `claims` content originates from issuers and reaches
LLM contexts. Consumers must treat it as untrusted data, never as instructions. Say so in
your README, not just here.

## 5. Operational guidance

- Generate recovery keys offline. Paper, hardware token, an air-gapped machine, or the root
  ceremony with networking down (MONERO.md §4.5).
- Recovery key in the same process as the identity key provides no protection whatsoever.
- Rotate voluntarily on a schedule; it exercises the path before you need it under pressure.
- Test recovery before you need it. An untested recovery key is a hash of nothing.
- Short attestation lifetimes, because there is no revocation list.

## 6. Legal exposure — worlds, not the protocol

sigelo itself processes public keys and signatures, which are not personal data.

`claims` is issuer-defined, and worlds will put personal data in it: names, contact details,
whatever their members supply in free text. When they do, GDPR applies in full and the "an
agent typed it" argument is worthless — Art. 4(1) covers information relating to an
identifiable natural person regardless of what produced it.

Three consequences for anyone operating a world:

- Attestations are designed to expire, which helps with storage limitation, but bundles
  circulate and are copied by verifiers. **You cannot recall a distributed attestation.**
  Erasure requests are therefore hard to satisfy for anything already presented. Keep
  personal data out of `claims` by schema, not by policy.
- Hosting third-party content also brings the DSA into scope for EU operators, with
  notice-and-action obligations independent of GDPR.
- If a world processes member data on another party's behalf, an Art. 28 processor
  agreement is mandatory, not optional.

The protocol's contribution is making it easy to keep `claims` structured and minimal.
It cannot stop an issuer from doing otherwise.

## 7. Public-chain rivals

The nearest rival design puts agent identity and reputation on a public chain: **ERC-8004
"Trustless Agents"** (draft ERC, 2025-08-13) gives each agent an ERC-721 identity with public
on-chain feedback, usually paired with **x402** for payment. It is deployed, and it is the
comparison every reader will make.

**What a public registry leaks, by construction.** Every registration, every payment and
every review is public, permanent and linkable. An agent's counterparties, amounts, timing
and reviewers become a graph anyone can mine, forever; nothing can be withdrawn after the
fact, which is §6's erasure problem at chain scale. sigelo discloses per bundle
and per proof, to whoever the agent hands them to (MONERO.md §1).

**Sybil gets an incentive, not a cost.** Registration is cheap and feedback is a public score,
so faking the score pays. The one empirical study (arXiv 2606.26028) found valid registrations
for only 3 %, 4 % and 15 % of agents on Ethereum, BSC and Base, and Sybil-pattern reviewers at
73.5 %, 59.2 % and 90.6 %, and concluded that the feedback "cannot function as a trust
signal". sigelo does not prevent Sybil either (§3.1); it records what admission cost and
leaves the judgement to the verifier.

**Transferable, unrecoverable, online.** An ERC-721 identity can be sold, so reputation can be
bought; a sigelo DID is a genesis hash, and a sold key is taken back by recovery (§2.4). Losing
custody of the token loses the identity unless a contract adds recovery. Checking a chain
identity needs a node or an RPC provider to trust; sigelo verifies offline (SPEC §1.1).

**What sigelo gives up.** No global registry, so nothing to enumerate and no discovery by
scanning a chain. No public score to read at a glance. No stablecoin payment rail: Monero only.
The rival has first-mover adoption and a registry agents can already search.

**What sigelo must therefore do instead.** Be findable by the agents that would adopt it,
without becoming a registry: static machine-readable docs (`/llms.txt`, `/adopt.md`), an MCP
server listed where agents look for tools, and a DID method registration. None of these is on the verification path; if all go down, every bundle still
verifies. Advertising `did:sigelo` inside an ERC-8004 registration file would be an
advertisement, not a dependency, but it touches the no-discovery rule (CLAUDE.md) and is
undecided.
