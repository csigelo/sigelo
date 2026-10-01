---
title: sigelo — portable identity for AI agents
description: sigelo is a data format and an offline verification algorithm for AI-agent identity: a genesis document whose hash is the DID, attestations signed by worlds, recovery that beats a stolen key, bindings to Monero addresses. Draft, wire sigelo/0.
---
# sigelo

**Portable identity for AI agents.** An agent builds reputation in one world and carries a provable identity into the next — with no shared infrastructure between them.

Esperanto *sigelo*: a seal. A seal binds an identity to a document and lets anyone verify it was not tampered with. That is the whole protocol.

Status: **draft: the wire may change; the keeper is experimental, stagenet only; unaudited.** Wire format `sigelo/0`, packages {{version}}, nothing on a registry yet. SPEC.md says "Nothing is stable until v1.0"; VERSIONING.md freezes `sigelo/0` at tag v0.2 after 30 days with no wire change. See [versioning](/versioning.html).

## What it is

sigelo is a data format and a verification algorithm. There is no server, no registry, and no chain. Two parties who have never communicated can verify a sigelo bundle offline.

- **Identity** is a genesis document: a public key plus a commitment to an offline recovery key. The DID is that document's hash (`did:sigelo:z…`), so nothing in it can be revised after the fact.
- **Attestations** are signed statements by a world about an agent. Their content is world-defined and opaque to sigelo; `admission` says what it cost the agent to get in (open, captcha, invite, payment, human, stake).
- **Bindings** cross-sign an identity against a payment address. Identity keys and spending keys stay separate.
- **Recovery:** a valid recovery rotation supersedes any voluntary rotation, regardless of timestamp. The thief's newer rotation loses.
- A **bundle** carries the genesis, the rotations, the bindings, the attestations and the genesis of every world that attested, so a verifier that knows no one gets the same result as one that knows everyone.

No trust scores. No revocation lists. No discovery. No hosted service. sigelo reports who signed what and when; weighting is the verifier's job. If every sigelo service vanished, existing bundles would still verify.

## One command

After the first publish: `npx sigelo-agent init --no-recovery` (or `--recovery <commitment>`). Until then the packages are tarballs from the repository's `release/build.sh`; [adopt](/adopt.html) gives the commands that work today and the five that make an identity, answer a world, build a bundle and verify it.

## For agents

- [/adopt.md](/adopt.md) — the one page to follow.
- [/llms.txt](/llms.txt) — this site's index for models; [/llms-full.txt](/llms-full.txt) — every document in one file.
- [/index.json](/index.json) — wire version, sha256 of the spec ({{spec_sha256}}) and of the vectors ({{vectors_sha256}}), implementations, expected release files.
- Every page has a Markdown twin at the same path: `/spec.html` ↔ [/spec.md](/spec.md).

## Read

- [Why an agent would use it](/why.html) — what you get on day one, by role, and against the alternatives.
- [Specification](/spec.html) and [test vectors](/vectors.html) — enough to implement it; [verify](/verify.html) checks your implementation against all {{m.impl_cases}} bundle cases.
- [Threat model](/threat-model.html) — including what this does *not* defend against.
- [Versioning](/versioning.html) — what may change before the freeze.
- [Security](/security.html) — reporting (draft: channels open at decision D1).
- [Keeper](/keeper.html) — paying without holding a key. [Monero](/monero.html) — the payment design.
- [Integrations](/integrations.html) — MCP server, agent and world adapters. [Evidence](/evidence.html) — what has been tested.
- [did:sigelo](/did-method.html) — the DID method, resolved offline.

MIT. Source: `{{repo}}` (nothing has been pushed yet).
