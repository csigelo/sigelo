# sigelo — versioning

Two things carry version numbers and they move independently: the **wire** (`v` inside every
signed object, SPEC §3.1) and the **packages** (npm, the Go module). An agent that adopts a
format that then changes under it does not come back, so the wire moves rarely and loudly.

**Status:** v0.1.0 is tagged (`v0.1.0` and `go/v0.1.0`, 2026-10-02) as a GitHub pre-release, a draft: wire
`sigelo/0` may change until v0.2; the keeper is stagenet-only and unaudited; nothing is on npm yet.

## 1. The wire: `sigelo/0`

`v` is `"sigelo/0"`. Verifiers reject any other value (invariant 7; SPEC §9 step 2). There is
no minor version and no negotiation: a bundle is `sigelo/0` or it is not sigelo.

**Before the freeze** (today): the wire may change. Every change gets a CHANGELOG line
starting `wire:`, the commit hash, and at least one vector that fails on the old behaviour.

**Frozen at tag `v0.2`.** From then on, `sigelo/0` means exactly SPEC.md and
`test-vectors.json` as they stand at that tag. The freeze needs **30 consecutive days with no
wire change** first (ROADMAP R6); any wire change restarts the count. After it, a wire change
is `sigelo/1` or it does not happen.

**A breaking change is any of:**
- a vector's expected output changes: a canonical string, a DID, a signature, a §9.1 result,
  or a negative's stated reason or outcome;
- a new mandatory field, or a field removed, retyped or made optional (SPEC §3.1 table);
- any change to what is rejected, or to which outcome a failure gets (SPEC §7.4: "not a
  candidate" versus REJECT; §9: fatal versus per-item discard);
- the signing input, the suite (invariant 2), an encoding (SPEC §2), or the precedence rule.

**Not breaking, allowed after the freeze:** spec prose that changes no outcome; a new vector
for a rule the spec already states, provided both shipped implementations pass it unchanged
(if one fails, the rule was ambiguous and fixing it is breaking); anything below the wire
(keys, ceremony, keeper, adapters, MONERO.md) — those follow package semver.

## 2. Introducing `sigelo/1`

- A verifier accepts a **set** of wire versions and each bundle carries **one**. A bundle
  that mixes versions across its objects is malformed. No object carries a list.
- `sigelo/1` gets its own SPEC and its own vector file; `sigelo/0` keeps its frozen ones.
- A `sigelo/1` verifier SHOULD also accept `sigelo/0` for at least 12 months after `sigelo/1`
  ships, and MUST report which version it verified (a §9.1 field in `sigelo/1`).
- Identities carry over by rotation: a `sigelo/0` chain rotates into a `sigelo/1` genesis.
  How, and whether a `sigelo/0` recovery commitment governs it, is part of the `sigelo/1`
  spec and must be decided before anything else in it.

## 3. Test vectors

`test-vectors.json` is versioned with the wire, not the packages. Its `spec` field names the
wire (`"sigelo v0.1 (wire sigelo/0)"`). Every release records its SHA-256 in `SHA256SUMS`
(ROADMAP §5.5). After the freeze the file only grows, under §1's rule; nothing in it is edited.
It is regenerated from documented seeds by `ts/src/gen_vectors.ts`, and CI diffs the result.

## 4. Packages

Semver, per package: `sigelo` (ts), `sigelo-spend`, `sigelo-agent`, the Go module. Each
package states the wire versions it speaks. Until `1.0.0`, a minor bump may break the package
API; it may never change the wire. A package that starts speaking `sigelo/1` gets a new major.
The Go module's path is `github.com/csigelo/sigelo/go` in the public repository
(release/publish.sh rewrites the private tree's bare `sigelo` at export, T4). The module sits in
the repository's `go/` directory, so Go resolves `go install
github.com/csigelo/sigelo/go/cmd/sigelo-verify@v0.1.0` through the tag `go/v0.1.0`, not
`v0.1.0`: every release pushes both tags on the same commit. `sigelo-verify` releases carry
static binaries and a signed release object (ROADMAP §5.5).

## 5. Deprecation

A wire version is deprecated by a CHANGELOG entry and a date, never by code alone. Minimum
12 months from deprecation to removal from the reference verifier. The keeper's HTTP surface
and the `sigelo-wallet` lines (spend/README.md) are package API: a removed route, verb or
exit code is a major bump with one minor release of overlap that warns.

## 6. Dependency pinning

- **Exact versions** in every `package.json` (no `^`, no `~`) and in `go.mod`; `go.sum`
  committed; Go builds with `GOFLAGS=-mod=readonly` and a `toolchain` line.
- **Lockfiles committed**; CI installs with `npm ci --ignore-scripts`, never `npm install`.
- **GitHub Actions pinned by commit SHA**, with the tag in a comment.
- **Renovate and Dependabot are off.** Updates are manual: one dependency per commit, its
  changelog read, the full vector run in both implementations before and after. Security
  advisories are read by hand (GitHub advisory feed, `npm audit`, `govulncheck`).
- Runtime dependencies stay as CLAUDE.md lists them: `@noble/ed25519` and `@noble/hashes` for
  ts, `filippo.io/edwards25519` for Go. `monero-wallet-rpc` is pinned too (0.18.5.0, RPC
  1.30) by the canary in `spend/canary.ts`.
