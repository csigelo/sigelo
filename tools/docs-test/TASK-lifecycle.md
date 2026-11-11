# Task: the sigelo lifecycle, from the docs alone

You are in a workspace directory (call it `$W`; it is your current directory). It holds the
documentation of **sigelo**, a protocol for portable AI-agent identity, and a built copy of its
TypeScript library. Your job is to take one agent identity through its whole lifecycle and
write each artifact to a named file in `$W/out/`. The files are graded by a program, not a
person: names and formats below are exact.

## What you may use

- **Read:** `SPEC.md`, `QUICKSTART.md`, `examples/world.mjs`, `ts/README.md`,
  `test-vectors.json`, `schema/`. Nothing else.
- **Do not read** `ts/dist/`, `ts/node_modules/` or `node_modules/`. They are there to be
  imported and run, not read.
- **Run:** `node` (≥ 22.18) and a shell. The library is `import('sigelo')` from `$W`
  (it is also `./ts/dist/sigelo.js`, the path QUICKSTART uses). The mock world is
  `node examples/world.mjs …`, run from `$W`.
- QUICKSTART's `sigelo-agent` commands are **not installed** here. Do what those steps do
  with the library instead.
- No network, no other packages, no help. If the docs are unclear, decide, and say what you
  decided in `out/report.json` (`notes`).

Use the current Unix time for every `iat`, and give anything with an `exp` a lifetime of at
least 30 days. Secret keys may be written to `out/` (the test keys are throwaway); the files
below are what is graded.

## The steps

1. **Recovery key and identity.** As the operator, create a recovery key pair. Then create
   the agent's identity so that it commits to that recovery key.
   - `out/recovery.pub` — the recovery **public** key, as a multibase `z6Mk…` string on one line
   - `out/genesis.json` — the agent's genesis document
2. **Get attested by the mock world** (`examples/world.mjs`): obtain its challenge, answer
   it, and receive its attestation.
   - `out/challenge-1.json` — the challenge body exactly as the world printed it
   - `out/challenge-1.signed.json` — your answer, `{ "did": …, "sig": … }`
   - `out/issued.json` — the world's `attest` output exactly as it printed it
3. **Bind a payment address.** There is no wallet here: bind an address using the test
   method SPEC defines for exactly this, cross-signed so that a verifier reports it
   `proven`. Bind it to your current identity.
   - `out/binding.json` — the binding as it goes into a bundle
4. **Rotate** voluntarily to a new identity key.
   - `out/rotation-voluntary.json` — the rotation as it goes into a bundle
5. **Answer a challenge as the rotated identity.** Get a fresh challenge from the mock world
   for your identity as it now stands, and answer it.
   - `out/challenge-2.json` — the challenge body exactly as the world printed it
   - `out/challenge-2.signed.json` — your answer, `{ "did": …, "sig": … }`
6. **Produce a bundle** holding everything so far (the identity, its rotation, the binding,
   the attestation and whatever a stranger needs to check it offline). It must verify.
   - `out/bundle.json`
7. **Lost key, then recovery.** The identity key you rotated to in step 4 leaks. Play the
   thief first: with the leaked key, sign a voluntary rotation from your current identity to
   a new identity the thief generates, keeping your recovery commitment unchanged, with an
   `iat` one hour **later** than the recovery rotation you are about to make. Then, as the
   operator, take the identity back with the recovery key. Then publish a bundle containing
   everything from step 6 plus **both** rotations (a verifier sees whatever is published).
   - `out/rotation-stolen.json` — the thief's rotation
   - `out/rotation-recovery.json` — your recovery rotation
   - `out/bundle-recovered.json` — the final bundle
   - `out/report.json` — `{ "did": "<the current DID of bundle-recovered.json, as you
     determine it>", "notes": "<anything you decided or found unclear>" }`

Every JSON file is one JSON value. When you are done, say so and stop.
