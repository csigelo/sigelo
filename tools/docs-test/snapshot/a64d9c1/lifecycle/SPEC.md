# sigelo v0.1 — portable agent identity

**Status:** draft. Wire format `sigelo/0`. Nothing is stable until v1.0, which will ship `sigelo/1`.
**Scope:** how an AI agent proves it is the same agent across worlds that share no infrastructure.

sigelo is a data format and a verification algorithm. There is no server, no registry, and
no chain. Two parties who have never communicated can verify a sigelo bundle offline.

---

## 1. Design constraints

1. **No central authority.** Any resolver or directory is convenience only. If every
   sigelo service disappeared, existing bundles must still verify.
2. **The agent's key is hot.** It lives in a process that reads untrusted text all day.
   Assume it will be stolen. Design for recovery, not prevention.
3. **Verifiers decide.** sigelo never adjudicates whether a claim is *true* or an issuer
   *trustworthy*. It proves who said what, and when.
4. **Adoption cost is the product.** Integrating must take under ~100 lines and one
   dependency. Every feature is weighed against that.
5. **Payment is bound, never fused.** Identity keys and spending keys are separate objects
   joined by a proof (§6).

### 1.1 Offline means self-contained

Everything a verifier needs is in the bundle: the subject's genesis, every rotation with
its next genesis, and the genesis of every issuer (§8). A verifier with no prior knowledge
of any party and no network verifies the same bundle to the same result as one with both.

---

## 2. Primitives

| Purpose | Algorithm |
|---|---|
| Signatures | Ed25519 (RFC 8032), pure, no prehash |
| Hashing | SHA-256 |
| Canonicalization | JCS (RFC 8785), restricted per §3 |
| Binary encoding | multibase `z` (base58btc) |
| Public keys | multicodec `0xed01` + 32 raw bytes, then multibase |
| Signatures on the wire | the 64 raw Ed25519 bytes, multibase. No multicodec prefix |
| DIDs | `did:sigelo:` + multibase of the raw 32-byte SHA-256 digest. No multicodec prefix |
| Nonces | multibase of raw bytes; 16 for a genesis. Verifiers do not check the length |

One suite. No negotiation, no agility, no downgrade surface.

---

## 3. Signing input and canonical form

```
signing_input = "sigelo\n" || JCS(body)
```

The prefix is exactly seven bytes, `73 69 67 65 6c 6f 0a` (`sigelo` then LF), followed by
the JCS serialization of the body, UTF-8, no trailing newline. The prefix separates sigelo signatures from any other
protocol that signs raw JSON with the same key. Signatures are always **detached** — never
inside the object they sign.

**Type binding.** Every signed body carries `typ`. Verifiers MUST check that `typ` matches the
slot the object is presented in (an attestation presented as a binding is rejected even with a
valid signature). `typ` inside the signed bytes is what prevents cross-type confusion.

**No non-integer numbers.** Signed objects MUST NOT contain floats, exponents, or integers
outside ±2^53−1. Implementations MUST reject any number whose value is not an integer in
that range. JCS number canonicalization is the largest source of cross-language interop
failure; forbidding floats removes the class. Use strings (`"0.15"`) or scaled integers.
Integers are serialized as plain decimal digits with no fraction, exponent, or leading
zeros; `-0` is `0`. Implementations that see the raw text MAY additionally reject
non-canonical integer spellings such as `1.0` or `1e2`; implementations working from parsed
values cannot, and are not required to.

**JCS, exactly.** Three points of RFC 8785 that a sorted `JSON.stringify` or
`json.dumps(sort_keys=True)` does *not* give you, and that the vectors exercise:

- Object keys are sorted by their **UTF-16 code units**, not by Unicode code point and not
  by UTF-8 bytes. The orders differ once a key contains a character above U+FFFF: `"𝄞"`
  (U+1D11E, encoded as the surrogates D834 DD1E) sorts *before* `"～"` (U+FF5E) in JCS and
  *after* it by code point. `claims` is world-defined, so non-ASCII keys will occur.
- String escaping is the ES6 `JSON.stringify` set and nothing more: `"` → `\"`, `\` → `\\`,
  U+0008/0009/000A/000C/000D → `\b \t \n \f \r`, other control characters below U+0020 →
  `\u00xx` with **lowercase** hex. Everything else, including U+007F, U+2028, U+2029 and all
  non-ASCII, is emitted as raw UTF-8. No `\/`, no `\u` for non-ASCII.
- No whitespace anywhere.

**Duplicate keys.** A signed object with the same key twice at any level has no canonical
form. Parsers that keep the last value would silently sign different bytes than parsers
that keep the first. Implementations MUST reject it. This means parsing with a
duplicate-detecting hook, not the language default. A verifier reading bundle text treats a
duplicate key or `__proto__` (§3.1) anywhere in it as fatal, since the text has no single reading, but
parses a forbidden number and leaves it to §9 step 2, so it sinks only the item that carries it.

**Envelopes.** Signed objects travel as:

```json
{ "body": { … }, "sig": "z…" }
```

Bindings carry `sig_id` and optionally `sig_addr` instead of `sig`. Rotations additionally
carry `next_genesis`. Nothing in the envelope outside `body` is signed, but the rules above
apply to the whole envelope, extra keys included: a float anywhere in it makes the item malformed (§9 step 2).

### 3.1 Fields, normatively

| `typ` | required | optional |
|---|---|---|
| `genesis` | `v` `typ` `key` `recovery` `created` `nonce` | — |
| `attestation` | `v` `typ` `iss` `sub` `iat` `exp` `ctx` `admission` `claims` | `admission_by` `admission_cost` |
| `binding` | `v` `typ` `id` `method` `addr` `iat` `exp` `nonce` | — |
| `rotation` | `v` `typ` `id` `next` `iat` `reason` | `recovery_key` (required iff `reason` is `recovery`, forbidden otherwise) |
| `challenge` | `v` `typ` `did` `ctx` `nonce` | — |
| `invoice` | `v` `typ` `did` `method` `addr` `iat` `exp` `nonce` | `amount` (string, atomic units) `memo` |
| `bundle` | `v` `typ` `genesis` `rotations` `bindings` `attestations` `issuers` | — |

**No other top-level keys.** A body carrying a key not in its row is malformed. `claims` is
the one free-form value and may hold anything JCS can serialize. Envelopes are part of the
same rule: a rotation envelope MUST carry `sig` and `next_genesis`, a binding `sig_id`, an
attestation `sig`, each a string; an envelope missing one is malformed in the same class as its body
(§9 step 2). `v` is `"sigelo/0"`; `iat`, `exp` are Unix seconds; `created` is RFC 3339.

**Field types.** `iat` and `exp` are JSON integers in [0, 2^53−1], and `exp` > `iat` wherever
both appear. Every other field in the table is a string, except `recovery` (string or `null`,
§4), `claims` (free-form) and the bundle's own `genesis` and four arrays. A string anywhere in
a signed object MUST be a sequence of Unicode scalar values: a lone surrogate (legal as a JSON
`\u` escape) is malformed, since RFC 8785 requires I-JSON and an encoder that replaced it with
U+FFFD would give two bodies one signing input. The object key `__proto__` is malformed at any
depth: a JavaScript parser that assigns it replaces the object's prototype instead of adding a key.
A type failure is malformation like any other (§9 step 2), never an implementation error.

---

## 4. Genesis and identity

An identity **is** its genesis document. The DID is a hash of it, so nothing inside can be
revised afterwards — including the recovery commitment.

```json
{
  "v": "sigelo/0",
  "typ": "genesis",
  "key": "z6Mk…",
  "recovery": "sha256:2c5a92ed…",
  "created": "2026-09-07T00:00:00Z",
  "nonce": "z…"
}
```

| Field | Meaning |
|---|---|
| `key` | multibase Ed25519 public key — the identity signing key |
| `recovery` | `sha256:` + hex SHA-256 of the **raw 32-byte** recovery public key, or `null` |
| `created` | RFC 3339 UTC, `Z`, second precision. Self-asserted and unverifiable; informational only |
| `nonce` | 16 bytes, multibase. Distinguishes genesis documents that share a key. Random by default; a world with a stable key MAY derive it from the key (e.g. the first 16 bytes of SHA-256 of the raw public key) so its genesis is reproducible without storage; then `created` MUST be pinned too, since every field is hashed. Uniqueness is what matters, not unpredictability: nothing secret is derived from it |

```
DID = "did:sigelo:" + multibase_z( SHA-256( JCS(genesis) ) )
```

Verifiers MUST recompute the DID from the presented genesis and reject on mismatch. First
step, every time, not optional. Verifiers MUST compare full DIDs — never prefixes — and UIs
MUST NOT truncate them; base58 vanity grinding against a truncated display is cheap.

`recovery: null` is legal and means **theft of the identity key is terminal**. Libraries
MUST warn at generation. Worlds MAY refuse attestations to such identities.

**Recovery key handling.** Generated offline, never loaded into an agent runtime. Only its
hash is public until it is used (§7). An attacker with full agent compromise learns a hash.

---

## 5. Attestations

One world's signed statement about one identity.

```json
{
  "v": "sigelo/0",
  "typ": "attestation",
  "iss": "did:sigelo:z…",
  "sub": "did:sigelo:z…",
  "iat": 1757203200,
  "exp": 1764979200,
  "ctx": "1f916.ai",
  "admission": "invite",
  "admission_by": "did:sigelo:z…",
  "claims": { "joined": "2026-04-02", "posts": 412, "standing": "citizen" }
}
```

`claims` is world-defined and **opaque to sigelo**. Verifiers interpret it according to how
much they trust `iss`. `admission_by` is informational; verifiers are not required to resolve it.
`admission_by` and `admission_cost` (§5.1) are optional; every other field shown is required.

The signature is verified against the `key` in the genesis whose DID is `iss`. A world that
has itself rotated issues new attestations under its new DID; old attestations still verify
against the old genesis. Verifiers do not walk issuer chains in v0.1.

`exp` is mandatory. There is no revocation list — freshness comes from reissuance.
Recommended lifetime 30–90 days. To signal lost standing, reissue with `claims` changed.

### 5.1 Admission taxonomy

`admission` records **what it cost the subject to enter**. It is what makes a population
count carry information.

| Value | Meaning |
|---|---|
| `open` | no barrier |
| `captcha` | automated challenge only |
| `invite` | vouched by an existing member; `admission_by` names them |
| `payment` | money was paid; `admission_cost` MAY carry a string amount |
| `human` | a human identity was verified by the issuer |
| `stake` | a slashable bond is held |

`admission` MUST be one of these six values; a verifier discards an attestation carrying any
other as malformed (§9 step 2). New values arrive with a new wire version, not silently.

Issuers MUST NOT overstate. The only remedy for a lying issuer is that verifiers stop
trusting it, which is the correct remedy. A verifier can then read a population of 2,000 as,
say, 1,847 `open` and 153 `invite` — a signal, where a raw count was not.

### 5.2 Proof of control

Before a world attests to a DID it needs the agent to demonstrate it holds the key. Every
world would otherwise invent its own handshake, so this one is fixed:

```json
{ "v": "sigelo/0", "typ": "challenge", "did": "did:sigelo:z…", "ctx": "1f916.ai", "nonce": "…" }
```

These five fields and no others: an agent library MUST refuse a challenge carrying any
additional key, so nothing can be smuggled into the signed bytes. The world chooses `nonce`
(opaque to the agent, bound by the world to the requesting session and to a short lifetime)
and `ctx`; the agent fills `did` with its current DID and
signs the §3 signing input with the identity key; the world recomputes the DID from the
presented genesis, compares full strings, and verifies the signature against `genesis.key`.
A challenge never appears in a bundle and no bundle slot accepts `typ: "challenge"`, so a
challenge signature cannot be replayed into any other slot. Agent libraries SHOULD refuse to
sign a challenge whose `did` is not their own. Vector `challenge`.

---

## 6. Payment bindings

Proves that an identity and a payment address share an operator. **Cross-signed**: both keys
sign the identical signing input.

```json
{
  "v": "sigelo/0",
  "typ": "binding",
  "id": "did:sigelo:z…",
  "method": "monero",
  "addr": "8Bx…",
  "iat": 1757203200,
  "exp": 1764979200,
  "nonce": "z…"
}
```

Envelope carries `sig_id` (identity key) and `sig_addr` (payment key, per-method format).

One-sided signatures are insufficient:
- identity-only proves the identity *claims* the address — anyone can claim anyone's
- address-only proves wallet control, not that the identity endorsed it

### 6.1 Proof status

Every binding the verifier returns carries exactly one of three statuses:

| `proof` | Meaning |
|---|---|
| `proven` | `sig_id` valid and `sig_addr` present and valid for `method` |
| `unproven` | `sig_id` valid, `sig_addr` absent — the identity *claims* the address |
| `unsupported` | `sig_id` valid, `sig_addr` present, verifier has no routine for `method` |

Where a payment method has no practical message-signing path, `sig_addr` MAY be omitted.
The binding is then an **unproven claim**, whatever the method; `unsupported` applies only
when a `sig_addr` is present. Verifiers MUST report the status in the return
type, not as a boolean, and MUST NOT send funds to any address whose status is not `proven`.
Keep `exp` short on unproven bindings.

A binding whose `sig_id` fails, or whose `sig_addr` is present but *invalid* for a method
the verifier does support, is discarded, not downgraded. A bad proof is not the same thing
as no proof.

### 6.1a Method `ed25519-test`

`addr` is a multibase Ed25519 public key (§2 encoding) and `sig_addr` is an ordinary §3
signature by that key. The method exists so the cross-signing rule can be exercised in the
vectors without a wallet. Conformant implementations MUST support it. It carries no payment
semantics and worlds SHOULD NOT accept it as a real binding. Its counterpart `opaque-test`
is a method no implementation supports; it exists to exercise the `unsupported` status.

### 6.2 Monero

`method: "monero"`. `addr` is a **standard (base) address** `varint(prefix) ‖ B ‖ A ‖
checksum` (prefix 18 mainnet, 24 stagenet, 53 testnet) or a **subaddress** `varint(prefix) ‖
D ‖ C ‖ checksum` (prefix 42 mainnet, 36 stagenet, 63 testnet), in Monero base58. Integrated
addresses are not accepted as `addr`: the hash below does not cover the prefix or the payment
id, so the base address's signature verifies for every integrated spelling of it and a payment
id nobody signed for would ride along. `sig_addr` is a Monero message signature over the
address's own two keys — `(B, A)` for a standard address, `(D, C)` for a subaddress:

```
h    = Keccak-256("MoneroMessageSignature\0" ‖ S ‖ V ‖ mode ‖ varint(len) ‖ signing_input)
sig  = c ‖ r,   c = H_s(h ‖ P ‖ kG),  r = k − c·x        (P, x) = (S, s) spend mode 0, (V, v) view mode 1
wire = "SigV2" ‖ monero_base58(sig)

standard:   (S, s) = (B, b)                  (V, v) = (A, a)
subaddress: (S, s) = (D, b + m)              (V, v) = (C, a·(b + m))
            m = H_s("SubAddr\0" ‖ a ‖ le32(major) ‖ le32(minor)),  D = B + mG,  C = a·D
```

where `signing_input` is §3's bytes, `H_s(x) = sc_reduce32(Keccak-256(x))` with original
Keccak padding, and verification recomputes `R' = c·P + r·G` and checks
`H_s(h ‖ P ‖ R') = c` (monero `src/wallet/wallet2.cpp` `get_message_hash`, `sign`;
`src/crypto/crypto.cpp` `check_signature`). Verifiers MUST accept either mode and SHOULD
report which one. Legacy `SigV1` is not accepted. Both keys in `addr` MUST decode as Monero's
`check_key` decodes them (`ge_frombytes_vartime`: y < p, and not x = 0 with the sign bit set), or
the binding is not proven, whichever mode signed.

(The subaddress row is `wallet2::sign` for a non-zero index.) A binding whose SigV2 verifies
against its `addr`'s own keys, in either mode, is `proven`; one whose signature was made with
another address's keys — a subaddress signed with the base `(B, A)`, say — is discarded.

**View mode is the intended mode for a standard address.** A view-only wallet holding
`(a, B)` produces it (through `monero-wallet-rpc` `sign` with `signature_type: "view"` at
index (0,0)), so an agent binds its wallet without ever holding a spend key. The signature
proves "I can see this wallet", which is exactly what a payer needs the receiver to be able to
do. **For a subaddress, view mode does not imply a view-only signer:** both of its secrets
are derived from `b`, so a view-only wallet cannot produce either mode, and a subaddress
binding is made by whoever holds the spend key (a keeper, MONERO.md §3).

**The hash does not cover the network prefix.** One key pair's mainnet, stagenet and testnet
addresses verify the same signature. A verifier MUST check that `addr` decodes to the
network it expects before treating the binding as `proven`.

### 6.3 Invoices

A binding names a wallet; an invoice names where to pay *this time*. Signed by the identity
key, exchanged bilaterally, never in a bundle:

```json
{ "v": "sigelo/0", "typ": "invoice", "did": "did:sigelo:z…", "method": "monero",
  "addr": "7…", "iat": 1757203200, "exp": 1757289600, "nonce": "z…", "amount": "150000000000" }
```

`addr` is a receive address of the bound wallet, for Monero a fresh subaddress per
counterparty per invoice. The payer checks: the signature against the identity key of `did`,
`iat ≤ now < exp`, and that `did` has a `proven` binding for the same `method` in a bundle
it has verified. sigelo cannot prove a subaddress belongs to the bound wallet (that needs the
view key); the identity's signature is the claim, the binding is its anchor, and a payment
to an address the identity did not sign for is the payer's own mistake. `amount` is a string
of atomic units or absent; `memo` is free text and, like `claims`, untrusted data.

**Selective disclosure.** Monero has **no per-subaddress view key**: one private view key
covers every subaddress of a wallet, and disclosing it is retroactive and irrevocable. The
primitives are per-payment proofs (`get_tx_proof`, `get_reserve_proof`) and one wallet per
relationship whose view key is meant to be shared, all derived from one root seed. See
MONERO.md. Libraries MUST NOT automate view-key disclosure; provide the primitive, make the
caller invoke it deliberately. Bindings, invoices and proofs are what get automated.

---

## 7. Rotation and recovery

```json
{
  "v": "sigelo/0",
  "typ": "rotation",
  "id":   "did:sigelo:<current>",
  "next": "did:sigelo:<new>",
  "iat": 1760227200,
  "reason": "voluntary",
  "recovery_key": "z6Mk…"
}
```

Envelope carries `next_genesis`; verifiers MUST check `hash(next_genesis) == next`.
`next` MUST differ from `id`; a self-rotation is structurally invalid.

**voluntary** — signed by the current identity key. `recovery_key` absent.
**Constraint:** `next_genesis.recovery` MUST equal the current recovery commitment. A
voluntary rotation that changes the commitment is **not a candidate** (§7.4): it is never
followed, and its presence does not by itself reject the chain. This is what stops an
attacker with a stolen key from installing their own recovery key.

**recovery** — signed by the recovery key. `recovery_key` present; `SHA-256(raw key)` MUST
equal the **current** recovery commitment (§7.2). `next_genesis` MAY carry a new commitment,
or `null`, which retires recovery permanently: no later recovery rotation can validate.

### 7.1 Precedence

> **At any node, a valid recovery rotation supersedes any voluntary rotation, regardless of `iat`.**

An attacker with a stolen key produces a perfectly valid voluntary rotation. The operator
with the offline recovery key overrides it — even if the attacker's rotation is newer, even
if it happened months earlier. Never reorder by timestamp. Vector `rotation_recovery`
deliberately carries an **earlier** `iat` than both hostile rotations.

Two hostile vectors exist because two rules defend this node. `rotation_hostile` also
changes the recovery commitment and is rejected by §7 before precedence is ever consulted.
`rotation_hostile_carried` carries the commitment forward and is a *fully valid* voluntary
rotation; only this rule defeats it. An implementation that skips precedence passes the
first and fails the second (vector `chain_precedence_only`).

### 7.2 Where recovery authority lives

The governing commitment is the one in the **most recent recovery-signed genesis** in the
chain, or the original genesis if there has been no recovery. Voluntary rotations carry it
forward unchanged (enforced above). Only a recovery rotation can change it — so the
operator can retire a recovery key, and an attacker never can.

### 7.3 Chain rules

Each DID in the chain is rotated from at most once. At a node:
1. Collect rotations whose `id` is this node.
2. Among them, the **valid** recovery rotations (signature, commitment, `next` hash all
   check; §7.4 lists what disqualifies one): if any, take the one with the latest `iat` —
   the operator controls all of them. If two share that latest `iat` → **REJECT the
   chain**; that is operator error and the fix is to reissue.
3. Otherwise, the **valid** voluntary rotations (signature, `next` hash, commitment
   unchanged); invalid ones are not counted: exactly one → follow it. **More than one →
   REJECT the chain.** A fork under a single key is a compromise signal; the remedy is a
   recovery rotation, not verifier guesswork.
4. None → chain ends here.
5. Before following the chosen rotation: if `next` is already in the chain → **REJECT the
   chain.** A rotation back to an earlier DID is a cycle. Only a key holder can produce
   one, it has no legitimate meaning, and a verifier that follows it never terminates.
   Fail closed rather than loop (vector `negative.cycle`).

The chain is walked from the original genesis until step 4 ends it. Because every step
consumes one rotation whose `id` is the current node and every `next` is new, the walk
terminates in at most `len(rotations)` steps. Rotations that were valid but not chosen
(a voluntary rotation superseded by a recovery) are simply not followed; the advice below on
discounting attestations near a recovery is how a verifier accounts for them.

### 7.4 Two outcomes, two words

A rotation that fails a check is either **not a candidate** (ignored at its node; the walk
continues as if it were absent) or it **REJECTs the chain** (fatal; the bundle does not
verify). Nothing in between.

| Failure | Outcome |
|---|---|
| signature does not verify | not a candidate |
| `hash(next_genesis) ≠ next` | not a candidate |
| voluntary, `next_genesis.recovery` ≠ current commitment | not a candidate |
| recovery, `SHA-256(recovery_key)` ≠ current commitment (wrong or stale key) | not a candidate |
| recovery while the current commitment is `null` | not a candidate |
| body or `next_genesis` malformed, `sig` or `next_genesis` missing (§3.1) | REJECT (structure, §9 step 2) |
| two valid voluntary rotations at one node | REJECT (fork) |
| two valid recovery rotations sharing the latest `iat` | REJECT (tie) |
| chosen `next` already in the chain | REJECT (cycle) |

A "not a candidate" rotation may still be a thief's artifact; that is what the advice on
discounting is for. Vectors: `negative.rotation_bad_sig`, `negative.recovery_key_mismatch`,
`negative.stale_recovery_key` and `negative.voluntary_changes_recovery` are all "not a
candidate" cases and each states the chain that results.

Reputation follows the chain: attestations to any prior DID apply to the current one. After
a recovery, the prior key was compromised for an unknown window. Verifiers SHOULD discount
attestations to the compromised DID with `iat` near the recovery, and SHOULD treat an
attestation issued to a DID *after* it was rotated away from as suspect. sigelo cannot
determine when compromise began; only the issuing world can.

`iat` everywhere is signer-asserted. Time-based logic is advisory unless the signer is trusted.

---

## 8. Bundles

```json
{
  "v": "sigelo/0",
  "typ": "bundle",
  "genesis": { … },
  "rotations": [ { "body": …, "sig": …, "next_genesis": … } ],
  "bindings":  [ { "body": …, "sig_id": …, "sig_addr": … } ],
  "attestations": [ { "body": …, "sig": … } ],
  "issuers": [ { …genesis… }, … ]
}
```

`genesis` is the **original**. Bundles are unsigned; every element carries its own signature.
All four arrays are required and MAY be empty.

`issuers` carries the genesis documents of the worlds whose attestations appear in the
bundle. It is what makes an attestation from a world the verifier has never heard of
verifiable offline (§1.1). The array holds bare genesis documents, not a DID-keyed map:
the verifier derives each DID by hashing, so there is no key/value pair that could
disagree. A verifier MAY also know issuer genesis documents from elsewhere (its own, or a
locally pinned set); the bundle's copies never override those. An attestation whose `iss`
matches no presented and no known genesis is discarded in §9 step 4, not fatal to the bundle.

---

## 9. Verification algorithm

In this order. Fail closed.

Input: a bundle and `now` (Unix seconds). The verifier takes `now` as a parameter rather
than reading a clock, so results are reproducible and testable.

1. **Genesis.** Check `bundle.genesis` structurally and compute its DID. This is the root of
   the chain; nothing else in the bundle may name the identity except by this hash. The
   algorithm takes no expected DID: a caller that has one (a login claim) compares it, in
   full, against `chain[0]` or `did` of the result, and treats a mismatch as a failed
   claim. Vector `negative.genesis_tampered` is that comparison.
2. **Structure.** A body is malformed if it has a non-integer number, a duplicate key, an
   unknown `v`, a missing required field, a top-level key outside its §3.1 row, a `typ` not
   matching its slot, or a field value outside its definition (an `admission` not in §5.1, a rotation whose `next` equals its
   `id`). Malformation in anything that defines the *identity* is fatal to the bundle: the
   bundle's own shape, `genesis`, every rotation body and `next_genesis`, every entry in
   `issuers`. Malformation anywhere in an individual attestation or binding (body or
   envelope, a non-integer number or lone surrogate included) discards that item and counts
   it in `rejected`, exactly as a bad signature would; the other items still verify. The presenter chose to
   include it, but an issuer wrote it; one world's bug must not sink its members' bundles.
3. **Chain.** Apply §7.3 from the original genesis. Output: current DID, ordered chain of
   DIDs, governing recovery commitment. Reject on fork, on cycle, or any structural failure.
4. **Issuers.** Hash each document in `bundle.issuers` to its DID. Add to the set of known
   issuer genesis documents; a locally known genesis for the same DID is kept in
   preference to the presented one (they are identical if both are honest).
5. **Attestations.** Each: resolve `iss` to a known genesis (step 4), verify signature
   against its `key`, check `iat ≤ now < exp`, check `sub` ∈ chain. Discard failures
   individually — one bad attestation does not sink a bundle.
6. **Bindings.** Verify `sig_id` against the identity key of the DID in `id` (must be ∈
   chain). Check `iat ≤ now < exp`. Verify `sig_addr` if present, per method. Tag proof
   status per §6.1. Discard failures individually.
7. **Return** the result below. No scores. No ranking. Weighting is the caller's job.

### 9.1 Result

```json
{
  "did": "did:sigelo:<current>",
  "chain": [ "did:sigelo:<original>", …, "did:sigelo:<current>" ],
  "recovery": "sha256:…",
  "attestations": { "did:sigelo:<iss>": [ { …attestation body… }, … ] },
  "bindings": [ { "body": { …binding body… }, "proof": "proven" } ],
  "rejected": { "attestations": 2, "bindings": 0 }
}
```

`attestations` holds accepted attestation bodies verbatim, grouped by `iss`, in bundle
order within each issuer. Key order of that object is informative only; conformance is
compared by value, and an implementation whose objects are unordered is conformant. `bindings` holds accepted bodies with their proof status, in bundle order.
`recovery` is the governing commitment, `null` if the identity has none. `rejected` counts
what steps 2, 5 and 6 discarded. Implementations MAY attach per-item reasons alongside;
the fields above are the conformance surface (vector `bundle`, compared as JSON).

---

## 10. Test vectors

`test-vectors.json`: real Ed25519 signatures from documented seeds. Positive groups
include a four-node chain with two hostile rotations defeated by an earlier recovery, a
recovery that changes the commitment followed by a second recovery under the new key, an
attestation whose `claims` exercise the JCS rules of §3, and a full bundle with its
expected §9.1 result at a fixed `now`. Negative cases include missing domain prefix, `typ`
mismatch, stale recovery key, voluntary rotation changing the commitment, a fork, a cycle,
a duplicate key, an integer outside ±2^53−1, an unknown top-level field, and a rotation with a
bad signature. `invoice` and `challenge` are the two signed objects that never enter a bundle. A second bundle, `bundle_minimal`, is the smallest thing that verifies: one
genesis with `recovery: null`, four empty arrays.

Conformant = every positive vector reproduced byte-for-byte, every vector carrying a `bundle`
and `expect` reproduced as a §9.1 result compared by value, every negative rejected for the stated reason. The `rotation_recovery`
versus `rotation_hostile_carried` pair is the one that matters.

---

## 11. Non-goals for v0.1

Trust scoring · revocation lists · encryption · discovery · personal-data handling in
`claims` (see THREAT-MODEL §6) · algorithm agility · plugin systems.
