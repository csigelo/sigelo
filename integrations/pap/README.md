<!-- SPDX-License-Identifier: MIT -->
# PAP: a sigelo identity method (profile draft)

**Profile draft, not part of PAP, not endorsed by its authors.** A sigelo agent identifying
itself under the [Personal Agent Protocol](https://github.com/personal-agent-protocol/personal-agent-protocol)
draft 0.1, read at commit `869ce57` (`content/spec.mdx`, 2026-10-15).

PAP 0.1 (4.1): "A Personal Agent's `client_id` MUST be an HTTPS URL that returns its metadata
document." The Company fetches it and its `jwks_uri`, then checks JWTs signed with those keys
(4.1, 4.2): a domain plus a key file, fetched online.

## Shape

Token request fields ([example.json](example.json)):

| PAP 0.1 | this profile |
|---|---|
| `client_id` (HTTPS URL) | the original DID, `chain[0]`: survives rotation and recovery |
| metadata document, `jwks_uri` | `bundle` (SPEC §8) inside `client_assertion` |
| `client_assertion_type` | `https://github.com/csigelo/sigelo/tree/main/integrations/pap` |
| `client_assertion` (JWT) | JCS of `{bundle, proof}`; `proof` = a SPEC §5.2 answer, `ctx` = the Company's `auth.issuer`, `nonce` its nonce |
| Session assertion `sub` | `user_id`, bound to the nonce |
| `client_name` | `client_name`, unsigned |

DPoP, Sessions, scopes and tokens stay PAP's. The nonce comes as DPoP nonces do (4.3), bound to
`client_id`, `user_id` and a short lifetime.

## What the Company checks, offline

`verify.mjs`: the bundle (SPEC §9); `client_id` = `chain[0]`; the chain extends the stored one;
the proof is a five-field challenge naming its own `auth.issuer` and nonce, signed by the current
DID; and an unexpired operator attestation (`ctx: "sigelo-relay/operator"`, `admission_by` =
`iss`, not the agent) naming who stands behind it. No fetch.

```sh
node present.mjs <auth.issuer> <nonce> <user_id> > params.json
node verify.mjs params.json <auth.issuer> <nonce>
node test.mjs                                                    # ALL PASS
```

`sigelo-agent sign-challenge` signs; only `--pairwise` reads a key (K).

## One DID per business

A person's own agent can use one DID per business, all recoverable from the 25 words.
`present.mjs --pairwise <auth.issuer>` derives its seed as keys.ts `k(K, "sigelo/v1/pap/ed25519/<n>/<issuer>")`,
the HKDF behind `agentIdentitySeed`, on the keeper root K of `keeper --from-words`: the issuer is the
index, no table, so a business always sees the same `client_id`. An operator attestation would
re-link the DIDs: present none, or one from a per-business operator sub-identity (`--operator <file>`).
For a company's agents, linkability is the point: keep it.

## What PAP gets

- No domain: an agent on a phone can be a `client_id`.
- Verified offline: nothing to fetch.
- Rotation keeps the `client_id`; after theft, the offline recovery key takes it back, and a
  Company that stored the chain refuses the thief's key.
- Operator proof: allowlists can name operators, not only clients.

## What it does not solve

- PAP 0.1 requires an HTTPS `client_id`: Companies must opt in.
- One DID at every Company lets Companies match the person, which User IDs (4.2) prevent.
  Per-business DIDs (above) avoid it, but then reputation stays with each Company.
- No domain, no `redirect_uris`: Device and Mediated Sign-In only, not Direct.
- A recovery reaches only Companies that have seen the new chain.
- The operator attestation says which key vouches, not who holds it.
