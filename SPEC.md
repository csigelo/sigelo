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
| Nonces | multibase of raw bytes: `z` + base58btc, like keys (`zJ6jjrKda7cWz17gvxJ4Fta`), never `z` + hex; 16 random bytes for a genesis. A verifier MUST reject a genesis, binding or invoice `nonce` that is not `z` followed by 1 to 63 base58btc digits (at most 64 characters): `<slot>: nonce is not z + base58btc (at most 64 characters)`, fatal in a genesis, per item in a binding (vectors `fatal_genesis_nonce_z_hex`, `binding_nonce_not_multibase`, `binding_nonce_65_characters`, `binding_nonce_64_characters`). The byte length is not checked. The §5.2 challenge nonce is exempt: opaque, the world's choice |

**Keys are points** (`fatal_genesis_key_all_zero`, `fatal_issuer_key_identity`,
`fatal_rotation_recovery_key_y_ge_p`, `binding_ed25519_test_addr_all_zero_unproven`). Every
slot that holds a public key — a genesis `key` (the bundle's, a `next_genesis`'s, an
issuer's), a rotation's `recovery_key`, an `ed25519-test` binding's `addr` — MUST hold the
canonical encoding (y < p; not x = 0 with the sign bit set) of a curve point that is not of
small order: exactly the keys the §2 verification rule could ever accept a signature under.
All-zero, the identity and the other small-order points, non-canonical spellings and non-points
are malformed, `key: not a valid Ed25519 point (non-canonical, off the curve or of small order)`,
at the slot's severity: fatal for a genesis or rotation, per item for a binding.
A point with a torsion component but not of small order is a valid key, as it is to the
signature check.

**Length before decoding** (`fatal_genesis_key_too_long`, `attestation_sig_too_long`). Base58
decoding is quadratic in the length, so a verifier MUST bound a multibase value before
decoding it: a public key (`key`, `recovery_key`, an `ed25519-test` `addr`) is at most **64**
characters and a signature at most **100**, `z` included (34 bytes spell at most 47 base58
digits, 64 bytes at most 88; the rest is margin). The alphabet is checked first (a linear scan,
so the count is of ASCII characters): a non-digit is reported as such, then a value over its
bound is rejected, `multibase: longer than 64 characters`, at the severity of the slot it sits
in — fatal in a genesis or rotation, per item in an attestation or binding.

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

**Invalid UTF-8** (`raw_invalid_utf8`). JSON text is UTF-8 (RFC 8259 §8.1). A document that
is not valid UTF-8 is rejected whole; an implementation MUST decode fatally. A lossy decode
turns the bad bytes into U+FFFD and sinks only the item whose signature then fails, while a
byte-level parser rejects the document: two verifiers, two answers. A leading byte-order mark
is not JSON whitespace and is rejected the same way. This is not a vector, because
`test-vectors.json` is itself UTF-8 text; a `\ud800` *escape* is valid UTF-8 and stays per item (§3.1).

**Nesting depth** (`raw_fatal_depth_513_in_claims`, `raw_depth_512_in_claims`). A parser MUST
reject a document whose arrays and objects, combined, nest deeper than **512** levels (the
outermost container is level 1), as a parse error: the whole document is rejected, wherever
the deep value sits — in `claims` too, where a malformed *value* would sink only its item —
because the limit is on the text, like a duplicate key. The error is reported at the bracket
that opens level 513, an empty container included. A canonicalizer MUST refuse a value nested
deeper than 512 (no conforming parser returns one; an object built in memory can be one, and
then it is malformed like a float, per item where it sits). Rationale: a recursive parser has
a finite stack, and in Go exhausting it is a fatal runtime error that `recover()` cannot catch —
a 1.6 MB document killed every process embedding the reference verifier, while an iterative
parser answered. A bounded verifier must bound depth, and two verifiers that bound it at
different places give two answers for the same bytes. 512 leaves a bundle's `claims` 507 levels.

**Envelopes.** Signed objects travel as:

```json
{ "body": { … }, "sig": "z…" }
```

Bindings carry `sig_id` and optionally `sig_addr` instead of `sig`. Rotations additionally
carry `next_genesis`. Nothing in the envelope outside `body` is signed, but the rules above
apply to the whole envelope: a float anywhere in it makes the item malformed (§9 step 2), and
so does a key outside its members (§3.1).

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
the one free-form value and may hold anything JCS can serialize. **Envelopes** are part of the
same rule, both ways: an envelope is exactly its defined members — a rotation envelope `body`,
`sig` and `next_genesis`; a binding envelope `body`, `sig_id` and optionally `sig_addr`; an
attestation envelope `body` and `sig` — with `sig` and `sig_id` strings. An envelope missing
one, or carrying any other key, is malformed in the same class as its body (§9 step 2): fatal
for a rotation (`rotation: unknown envelope field "…"`), the item discarded and counted for an
attestation or binding (vectors `attestation_envelope_extra_key_int`,
`attestation_good_and_envelope_extra_keys`, `binding_envelope_extra_key`,
`fatal_rotation_envelope_extra_key`; `binding_envelope_sig_id_only_unproven` is the optional
member absent). Nothing outside `body` is signed, so an extra member is data no signature
authenticates, exactly like an unknown body field, and a verifier that ignored it would accept
what a stricter one discards. A holder that receives an item with extra members (a world whose
router adds a clock, say) keeps only the defined ones before bundling it; the signature does
not cover the rest, so dropping them changes nothing that verifies. The bundle itself is the
`bundle` row above; a §5.2 challenge answer or §6.3 invoice exchanged as `{body, sig}` follows
the same rule. `v` is `"sigelo/0"`; `iat`, `exp` are Unix seconds; `created` is RFC 3339 UTC in exactly the form §4 fixes.

**Field types.** `iat` and `exp` are JSON integers in [0, 2^53−1], and `exp` > `iat` wherever
both appear. Every other field in the table is a string, except `recovery` (string or `null`,
§4), `claims` (free-form) and the bundle's own `genesis` and four arrays. A string anywhere in
a signed object MUST be a sequence of Unicode scalar values: a lone surrogate (legal as a JSON
`\u` escape) is malformed, since RFC 8785 requires I-JSON and an encoder that replaced it with
U+FFFD would give two bodies one signing input. **Noncharacters** (`raw_fatal_noncharacter_in_claims_value`,
`raw_fatal_noncharacter_astral_in_claims_key`): RFC 7493 §2.1, which RFC 8785 cites, also
forbids them, so a parser MUST reject a string or key holding U+FDD0–U+FDEF or U+xFFFE /
U+xFFFF in any plane, raw or escaped (an escaped surrogate pair counts as the character it
spells), as a parse error — fatal to the document, reported at the string's opening quote:
`noncharacter U+FFFF in string at offset N`. A canonicalizer MUST refuse one in a value built
in memory (`noncharacter U+FFFF in string`), so a conforming library never signs a body no
conforming parser will read. The object key `__proto__` is malformed at any
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
| `recovery` | `sha256:` + hex SHA-256 of the **raw 32-byte** recovery public key, or `null`. Exactly `sha256:` and 64 **lowercase** hex digits: a verifier MUST reject anything else (`genesis: recovery is neither null nor sha256: + 64 lowercase hex`), fatally, as in every genesis slot (vectors `fatal_genesis_recovery_uppercase_hex`, `fatal_genesis_recovery_prefix_only`). Uppercase hex is the same digest spelled so that no recovery key ever matches it: recovery silently off |
| `created` | RFC 3339 UTC, `Z`, second precision. Self-asserted and unverifiable; informational only. Its *form* is checked: see below |
| `nonce` | 16 bytes, multibase. Distinguishes genesis documents that share a key. Random by default; a world with a stable key MAY derive it from the key (e.g. the first 16 bytes of SHA-256 of the raw public key) so its genesis is reproducible without storage; then `created` MUST be pinned too, since every field is hashed. Uniqueness is what matters, not unpredictability: nothing secret is derived from it |

```
DID = "did:sigelo:" + multibase_z( SHA-256( JCS(genesis) ) )
```

**`created`, exactly** (`fatal_genesis_created_leap_second` and its neighbours). A verifier
MUST reject a genesis whose `created` is not exactly `YYYY-MM-DDTHH:MM:SSZ`: four-digit year,
a real Gregorian date (30 April, 29 February only in a leap year), hours 00–23, minutes and
seconds 00–59 (no leap second: nothing offline can check one), no fraction, no offset,
uppercase `T` and `Z`. The reason is `genesis: created is not RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)`.
Every genesis slot defines an identity (§9 step 2), so this is fatal wherever a genesis sits:
the bundle's own, a `next_genesis`, an issuer. The value is hashed into the DID and read by
nobody, but a field no one checks is a field two implementations parse differently the day
one of them starts to read it.

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
against the old genesis. Verifiers do not walk issuer chains in v0.1. So, by design, a key a
world rotated away from still makes attestations that verify under the **old** DID, whatever
their `iat`, until each one's `exp`: nothing in a bundle says the old DID was retired, and a
verifier that knows it was (from the world, out of band) stops trusting that DID itself (THREAT-MODEL
§3.2).

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
   recovery rotation, not verifier guesswork. Two entries are two candidates even when
   byte-identical: a bundle MUST NOT carry the same rotation twice, and a verifier does not
   deduplicate (vector `negative.parity.fatal_duplicate_rotation_is_fork`).
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

In this order. Fail closed. Every input ends in a result or in a rejection that names its
check; running out of stack or arguments on a large but legal bundle is neither, and a
verifier MUST NOT let one decide the outcome (§3 bounds nesting for the same reason).

Input: a bundle and `now` (Unix seconds). The verifier takes `now` as a parameter rather
than reading a clock, so results are reproducible and testable.

1. **Genesis.** Check `bundle.genesis` structurally and compute its DID. This is the root of
   the chain; nothing else in the bundle may name the identity except by this hash. The
   algorithm takes no expected DID: a caller that has one (a login claim) compares it, in
   full, against `chain[0]` or `did` of the result, and treats a mismatch as a failed
   claim. Vector `negative.genesis_tampered` is that comparison.
2. **Structure.** A body is malformed if it has a non-integer number, a duplicate key, an
   unknown `v`, a missing required field, a top-level key outside its §3.1 row (or an envelope
   key outside its members, §3.1), a `typ` not
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
order within each issuer. The same attestation presented twice is accepted twice and listed
twice: a verifier does not deduplicate here any more than it does rotations (§7.3) — every
copy verifies, and it reports what was presented — so a caller that counts attestations counts
distinct ones. Key order of that object is informative only; conformance is
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

---

## 12. DID method `did:sigelo`

Non-normative: §2–§9 in the shape of a DID method specification (W3C DID Core v1.0 §8,
Recommendation of 19 July 2022; the `w3c/did-extensions` registry and its review checklist,
read 3 October 2026). It adds no rule and changes no verdict; where it seems to disagree with
§2–§9, they govern. **Method name:** `sigelo`, wire `sigelo/0` (VERSIONING.md).

### 12.1 Syntax

```abnf
sigelo-did  = "did:sigelo:" sigelo-id
sigelo-id   = "z" 32*44base58-char   ; base58btc of the 32-byte SHA-256 of JCS(genesis)
base58-char = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A
```

The id is **case-sensitive**, has no `:` and needs no percent-encoding. A DID URL uses only a
fragment, naming a verification method (§12.3). DIDs are equal only as full strings (§4).

### 12.2 Create

Generate an Ed25519 identity key and, offline, a recovery key; write the §4 genesis with the
recovery commitment (or `null`); the DID is `did:sigelo:` + multibase SHA-256 of its JCS form.
Nothing is published or registered: anyone holding the genesis recomputes the DID.

### 12.3 Read (resolve)

There is no resolver service, by design (§1). Resolving is verifying, offline, a §8 bundle the
subject presents (typically beside a §5.2 challenge answer): run §9 at `now`; the DID resolves
if it is in the result's `chain`, to the `key` of the genesis of the current DID (§7.3):

```json
{ "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
  "id": "<did>",
  "verificationMethod": [{ "id": "<did>#<key>", "type": "Multikey",
                           "controller": "<did>", "publicKeyMultibase": "<key>" }],
  "authentication": ["<did>#<key>"] }
```

`<key>` is that genesis `key` verbatim (`z6Mk…`: multicodec `0xed01` + 32 bytes, §2, the
encoding `Multikey` and `Ed25519VerificationKey2020` share). Metadata: `canonicalId` =
`chain[0]`, `equivalentId` = the rest of `chain`. `authentication` is §5.2 proof of control.
Not applicable: `controller` (self), `alsoKnownAs`, `assertionMethod` (attestations carry
their own signatures, §5), `keyAgreement` (no encryption, §11), `capabilityInvocation`,
`capabilityDelegation`, `service` (no discovery, §11). The recovery key is never a
verification method; until used it is a hash (§4). A bundle that does not verify, or whose
`chain` lacks `<did>`, gives `notFound`; a string outside §12.1 gives `invalidDid`.

### 12.4 Update

Update is rotation (§7), and it changes the DID: the chain moves to `next`, and every earlier
DID of the chain resolves to the new key. **Voluntary:** signed by the current key, commitment
carried forward. **Recovery:** signed by the recovery key, which must hash to the governing
commitment (§7.2); it may install a new commitment or `null`. **Precedence** (§7.1): at any
node a valid recovery rotation supersedes any voluntary one, regardless of `iat`; two valid
voluntary rotations at one node reject the chain (§7.3).

### 12.5 Deactivate

`sigelo/0` has none; resolution never reports `deactivated`. Substitutes: attestations and
bindings expire (`exp` is mandatory, §5, §6) and stop verifying unless reissued; the holder
can rotate to a key whose secret is then destroyed, so nothing new verifies under the chain
(for good once a recovery rotation has set `recovery: null`); worlds stop attesting. A signed
deactivation is a question for v0.2.

### 12.6 Security considerations

THREAT-MODEL.md is the analysis. **Man in the middle:** a bundle is self-certifying — the DID
hashes the genesis and every element is signed (§3) — so an intermediary can drop items, not
alter them; §5.2 binds proof of control to a world-chosen nonce and session. **Key compromise
and recovery:** the identity key is assumed hot and eventually stolen; the cold recovery key
is committed in the genesis and beats any rotation a thief makes (§7.1, THREAT-MODEL
§2.4–§2.5b). **Stale presentation:** a bundle shows the chain as far as its presenter chose,
and a thief can withhold a later recovery; a verifier that has seen a longer chain for the
same `chain[0]` keeps it, and discounts attestations near a recovery (THREAT-MODEL §3.5).
**Not defended:** Sybil, lying issuers, the operator behind the agent (THREAT-MODEL §3).

### 12.7 Privacy considerations

No registry, no ledger, no resolver: creating, rotating and resolving contact no one, so no
party learns who resolves whom, or when (no phone-home). A DID is correlatable by design — it
carries reputation between worlds — and so is a shared `recovery` commitment: unlinkable
presences need separate identities with separate recovery keys (MONERO.md §2 links one Owner's
agents this way on purpose). Keys and signatures are not personal data; `claims` may be, and
that is the issuer's charge (THREAT-MODEL §6). Bindings travel only in bundles the subject
presents, and the view key is never disclosed automatically (§6.3).

### 12.8 Conformance

A `did:sigelo` resolver is a §9 verifier: `sigelo-verify --conformance` checks the reference
against `test-vectors.json` (§10), and `--conformance --impl '<command>'` checks a candidate.
