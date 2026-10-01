---
title: Test vectors
description: test-vectors.json, the conformance target of sigelo wire sigelo/0: real Ed25519 signatures from documented seeds, positive groups, negative cases and parity cases, with their sha256 and how to run them.
---
# Test vectors

[/test-vectors.json](/test-vectors.json) — the specification in executable form. Raw JSON, the file as it is in the repository at `{{commit_short}}` (also at `/sha256/{{vectors_sha256}}/test-vectors.json`, which never changes).

| | |
|---|---|
| `spec` field | `{{vectors_spec}}` |
| sha256 | `{{vectors_sha256}}` |
| fixed `now` | `{{vectors_now}}` |
| documented seeds | {{n_seeds}} (32 bytes, all zero except the last) |
| positive entries (`vectors`) | {{n_positive}} |
| negative cases (`negative`, besides `parity`) | {{n_negative}} |
| parity cases (`negative.parity.cases`) | {{n_parity}} |

Status: draft. The vectors are versioned with the wire, not the packages; after the freeze at tag v0.2 the file only grows ([versioning §3](/versioning.html#3-test-vectors)).

## What conformant means

From [SPEC §10](/spec.html#10-test-vectors): every positive vector reproduced byte for byte, every vector carrying a `bundle` and `expect` reproduced as a §9.1 result compared by value, every negative rejected for the stated reason. The `rotation_recovery` versus `rotation_hostile_carried` pair is the one that matters: the recovery wins although the thief's rotation is newer.

- **Positive groups** include a four-node chain with two hostile rotations defeated by an earlier recovery, a recovery that changes the commitment followed by a second recovery under the new key, an attestation whose `claims` exercise the JCS rules, Monero bindings (base address and subaddresses), and two bundles with their expected §9.1 result (`bundle`, `bundle_minimal`).
- **Negatives** include a missing domain prefix, `typ` mismatch, a stale recovery key, a voluntary rotation changing the commitment, a fork, a cycle, a duplicate key, an integer outside ±2^53−1, unknown fields, and malformed Monero addresses and signatures.
- **Parity cases** are malformed objects both implementations must treat identically: raise with the stated reason, or return the stated proofs and counts.
- The signing input is `"sigelo\n" || JCS(body)`; the vectors carry canonical strings to diff against (`attestation_unicode`).

## Run them

```sh
sigelo-verify --conformance test-vectors.json                    # the reference verifier over every vector
sigelo-verify --conformance test-vectors.json --impl '<your cmd>'   # your verifier over {{m.impl_cases}} bundle cases
```

Details on [verify](/verify.html). The vectors are regenerated from the seeds by the repository's `ts/src/gen_vectors.ts`, and CI diffs the result against the committed file byte for byte.

## Schemas

JSON Schema 2020-12 for every signed object, checked in CI against every vector ({{n_schemas}} files): {{schema_list}}. They are hand-written from SPEC §3.1, not generated; one parity vector cannot be expressed in them.
