# Task: adopt sigelo from its website alone

You are an AI agent in a workspace directory (call it `$W`; it is your current directory). A
website about **sigelo**, a protocol for portable AI-agent identity, is served at
`http://localhost:<PORT>/`. Your job is to give yourself a sigelo identity, get it attested by
a world, and produce a bundle that verifies — using only what the website tells you. Write each
artifact to a named file in `$W/out/`. A program grades the files, not a person: names and
formats below are exact.

## What you may use

- **The website**, over HTTP, with whatever client the shell has (`node -e 'fetch(…)'`, `wget`,
  `curl`). Start at `http://localhost:<PORT>/`. Its pages call the site `https://sigelo.io`:
  that is this server; replace the origin with `http://localhost:<PORT>` (nothing else is
  reachable).
- **`$W/rel/`**: the release files the website talks about (npm tarballs, `sigelo-verify`
  binaries, `SHA256SUMS`, `test-vectors.json`). Install from them; do not read inside the
  tarballs or `node_modules/` — they are there to be installed and run, not read.
- `node` (≥ 22.18), `npm` (it may reach the npm registry, for the packages' own dependencies
  only) and a POSIX shell. No other documentation, no repository, no help. If the website is
  unclear, decide, and say what you decided in `out/report.json` (`notes`).

Use the current Unix time for every timestamp. Secret keys may be written to `out/` (the
keys are throwaway); the files below are what is graded.

## The steps

1. **Install** the agent-side tools from `$W/rel/` as the website says, and check the
   `sigelo-verify` binary for your platform against `SHA256SUMS` before you use it.
2. **Recovery key and identity.** As the operator, create a recovery key pair on its own
   (the website describes recovery tiers; use the one with a dedicated recovery key pair).
   Then create the agent's identity so that it commits to that recovery key.
   - `out/recovery.pub` — the recovery **public** key, as a multibase `z6Mk…` string on one line
   - `out/genesis.json` — the agent's genesis document
3. **Get attested by the mock world** the website serves: obtain its challenge, answer it,
   and receive its attestation. Run the world from `$W` (it keeps its state in the directory
   it runs from).
   - `out/challenge.json` — the challenge body exactly as the world printed it
   - `out/challenge.signed.json` — your answer, `{ "did": …, "sig": … }`
   - `out/issued.json` — the world's `attest` output exactly as it printed it
4. **Produce a bundle** holding the identity and the attestation, with whatever a stranger
   needs to check it offline, and verify it with the `sigelo-verify` binary from `$W/rel/`.
   - `out/bundle.json`
   - `out/verify.txt` — exactly what `sigelo-verify` printed on stdout for `out/bundle.json`
5. **Report.**
   - `out/report.json` — `{ "did": "<your current DID, in full>", "verifier": "<the file name of the sigelo-verify binary you used>", "sha256_ok": true|false, "notes": "<anything you decided>" }`

When you are done, say so and stop.
