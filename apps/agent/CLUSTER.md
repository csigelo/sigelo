<!-- SPDX-License-Identifier: MIT -->
# One identity on several machines

sigelo/0 puts no one key on several machines. What works: a **service** of several
members, each its own identity (worker i of your keeper root, ENROL.md), named together by an
attestation from you, the operator.

```sh
sigelo-agent enrol --name billing-a                     # your machine: an ENROL-… code, once per member
sigelo-agent init --enrol ENROL-K7F3-Q9ZP --service     # the member's machine
sigelo-agent whoami                                     # each member: its DID

sigelo-agent attest --operator --subject did:sigelo:zA… --ctx sigelo-service/0 \
  --claims '{"service":"billing","members":["did:sigelo:zA…","did:sigelo:zB…"]}' > claim-A.json   # your machine
sigelo-agent add-attestation - < claim-A.json           # member A; likewise B with its own claim

sigelo-agent link billing-a carol --purpose "billing" --operator   # carol pairs with a member
sigelo-agent invite                                     # or: a member gives its own code
```

## The service claim

`attest` signs one SPEC §5 attestation by your current DID about `--subject`, one per member:
`ctx` and `claims` as given, `exp` in `--days` (14; at most 365), admission `invite`
by you. It signs with whatever holds your key (file, keychain; a key agent only for a ctx given
with `--allow-attest`), signs nothing else, and refuses the contexts sigelo acts on itself
(`sigelo-relay/*`, `sigelo-spend`, `sigelo.ai/*`). A worker enrolled by you already holds your
genesis; any other member needs `sigelo-agent add-issuer '<genesis>'`, the `genesis` object of
`whoami --operator`. Run it again before `exp`: `add-attestation` replaces the earlier claim of
the same issuer and `ctx`.

**Who says what:** you, the operator, attest that these DIDs are your service. A verifier
(`sigelo-verify`, the MCP `sigelo_verify`) checks your signature and reports the claim as data
about the member; it does not judge it. The relying party decides whether your word is enough.

## How it works

- **Each member is a full identity:** its own DID, ratchets, prekeys and relay session (the relay
  keeps one per identity), so members never contend.
- **Sending to the service:** to any live member, or to every member with an id of your own in the
  content to drop duplicates (the carrier's message id differs per member).
- **A relying party** verifies a member's bundle (SPEC §9) and reads the
  attestations by your DID with `ctx` `sigelo-service/0`: `claims.service`, and a DID of the
  member's verified chain in `claims.members`.
- **A lost member** drops out when the last claim naming it expires: reissue every member's claim
  without it (the others' `claims.members` list it until their `exp`).
- **A stolen member:** `sigelo-agent enrol --restore <i> --rotate` places it at rotation n+1; if a
  thief rotated first, `sigelo-offline recover --genesis <its whoami.json> - --agent <i> --keeper 1
  --n <m>` (your words on stdin), then `sigelo-agent adopt --rotation <file>` on the member
  (ENROL.md). The recovery supersedes the thief's rotation (SPEC §7.1) in any bundle that carries
  it; one shown only the thief's bundle still sees a member until `exp`. Reissue the claims with
  the member's new DID.

## The costs

- **One pairing per member:** a contact pairs, and compares four words, once per member.
- **No shared conversation memory:** a member sees only what was sent to it; any sharing is yours.
- **Membership cannot be withdrawn before `exp`:** there is no revocation list (SPEC §5). A lost
  member's last claim lists it until it expires: keep `exp` short.
- **Relying parties must read the claim:** sigelo does not interpret `claims`.
- **No member signs as the service:** there is no service DID. A copy of one key on several
  machines is a FULL device (DEVICES.md), and whoever takes one machine takes the identity; the
  seat lets one machine at a time log in as you, with no automatic failover.
