# Task: a sigelo verifier, from the spec alone

You have two files: `SPEC.md`, the specification of **sigelo** (a protocol for portable
AI-agent identity), and `test-vectors.json`, its conformance vectors. Nothing else about
sigelo exists for you: no other implementation, no other document, no network search for it.

Write a **bundle verifier** (SPEC §9) as a command-line program, in any language **other
than TypeScript/JavaScript and Go** (the two the project ships). Use your language's standard
library or one well-known library each for Ed25519, SHA-256 and (for §6.2) Keccak-256 and
Edwards25519 point arithmetic. Everything specific to sigelo — the JSON parser rules, JCS,
multibase, the chain rules, the Monero glue — is yours to write from the spec.

## Interface (exact)

```
<your command> <bundle.json> --now <unix-seconds>
```

- Read the bundle file (SPEC §8), verify it at time `now` (never read a clock).
- **Accepted:** print the SPEC §9.1 result as one JSON value on stdout and exit **0**. It is
  compared by value (key order and whitespace do not matter) on the six §9.1 fields, and of
  each binding entry on `body` and `proof`; anything you attach alongside is ignored.
- **Rejected** (anything §9 makes fatal to the bundle): print `REJECT: <the failing check>` on
  stderr and exit **1**.
- Any other exit code is a failure of your program, not a rejection.

## How it is graded

A grader builds bundle files from every entry of `test-vectors.json` — the positive vectors,
the `negative` cases and the `parity` cases — at the vector file's `now` (or the `now` a
vector carries), runs your command on each, and compares your exit code and result with what
the vector says. The Monero cases (§6.2) are scored as their own group. Invoices never enter
a bundle, so their vectors are not scored here. You may test against the vectors as often as
you like.

Deliver: the source, one line saying how to build it, and the exact command to run it.
