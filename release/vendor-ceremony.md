# The vendor identity

The DID that signs `sigelo-spend` licences (spend/README.md, "The licence is a sigelo attestation").
It signs licences and nothing else: no release, no world attestation, no payment. Not yet minted:
until then `spend/licence.ts` pins a placeholder DID whose key was discarded, so no licence verifies.

## What it can and cannot do

1. It can make a keeper `pro`: delegation, approvals, receipts export, more keepers per host.
2. It cannot touch anyone's keys or money. A licence is a public attestation to a keeper DID; the
   free tier never depends on it and no payment passes through the vendor.
3. A stolen vendor key therefore mints licences, nothing more. That is the whole blast radius.

## How it is made

1. Offline, on the Owner's offline device; never on a server, a VPS or a host an agent runs on.
2. The intended form is derived from the Owner's root (MONERO.md §4.5) as
   `k(S, "sigelo/v1/vendor/ed25519/<n>")`, beside the release key's
   `sigelo/v1/release/ed25519/<n>`. Until the ceremony derives it, the vendor is made like the
   release identity (release/RELEASE.md, "Signing"): a fresh Ed25519 key, plus a separate
   recovery key generated offline whose hash is the genesis's `recovery` commitment.
3. The recovery key is kept offline, on other media than the identity key.
4. The genesis is published; the secrets are not, anywhere.

## How licences are issued

1. The buyer sends their keeper DID (`sigelo-spend licence show`). Nothing else identifies them.
2. On the offline device the vendor signs `attest({iss: <vendor DID>, sub: <keeper DID>, ctx:
   "sigelo-spend", admission: "payment", claims: {tier: "pro", seats: N}, iat, exp})`.
3. The buyer gets `{attestation, issuer}` and runs `sigelo-spend licence install <file>`. It is
   checked offline; there is no activation server and no revocation list: a licence ends at `exp`.

## Where to check it

Once minted, the vendor DID and its genesis are listed in SECURITY.md, "Official channels", and served at
`https://sigelo.io/.well-known/sigelo-vendor-identity.json`. Any other issuer is not the vendor.

## Rotation and compromise

1. On theft or suspicion, the Owner signs a recovery rotation (SPEC §7) with the offline recovery
   key and publishes it there and in the release notes.
2. Today a keeper accepts one vendor DID, fixed in its release: after a rotation, keepers need a
   `sigelo-spend` release naming the new DID, and live licences are reissued free. Until they
   upgrade, licences from the old key still verify on old keepers (SPEC §5: no revocation).
3. Planned: keepers follow the vendor's rotation chain from its published genesis, so a rotation
   needs no release, and refuse licences longer than the longest term sold.
