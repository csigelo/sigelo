# Cutting a release

Artefacts are built from the PUBLIC tree (Go module path rewritten), never from the private one.
`<v>` is the package version, the same in every package.json; `$S` a scratch directory.

1. Private repo: CHANGELOG.md gets `## v<v> — <date>` over the entries it releases; VERSIONING.md
   status line; ROADMAP §6 step 8; site footnotes. `node site/build.mjs && node site/test/run.mjs`
   passes. Commit.
2. Sync and push (the commands under "Sync command").
3. In ../sigelo-public at that commit: `sh release/build.sh $S/a`, `sh release/build.sh $S/b`;
   `cmp $S/a/SHA256SUMS $S/b/SHA256SUMS` must be silent. `sh release/pack-test.sh $S/a` must end
   `ALL PASS (<n> checks)`. Go binaries and the npm tarballs (gzip rewritten by
   `release/normalize-tgz.mjs`) hash the same across hosts and node/npm versions (same Go version).
4. Tag that commit twice, `v<v>` and `go/v<v>` (the Go module lives in go/, VERSIONING §4):
   `TZ=UTC GIT_COMMITTER_DATE="$(date -u +%s) +0000" git -c user.name=csigelo -c
   user.email=contact@sigelo.io -c gpg.format=ssh -c user.signingkey=~/.ssh/sigelo_release_signing tag -s v<v> -m '…'`.
   `git cat-file -p v<v>` must show `+0000`. `git push origin v<v> go/v<v>`.
   Then `sh release/sign-release.sh v<v> $S/a` writes `$S/a/release.json`.
5. `gh release create v<v> --repo csigelo/sigelo --prerelease --title 'sigelo v<v> (draft)'
   --notes-file $S/notes.md $S/a/*` — every file build.sh wrote. Notes (≤ 40 lines): status,
   install lines, SHA256SUMS, link to the CHANGELOG heading. Drop `--prerelease` once not a draft.
6. Prove it from nothing: in a scratch GOPATH/GOMODCACHE,
   `GOFLAGS=-mod=mod go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@v<v>`
   (`GOPROXY=direct` if the proxy lags), then `sigelo-verify --conformance test-vectors.json` on the
   released file; `gh release download` one binary and check it against SHA256SUMS.
7. Read the tag's conformance.yml run
   (`api.github.com/repos/csigelo/sigelo/actions/runs?event=push&branch=v<v>`) and record it in
   docs-test/PORTABILITY.md.

8. npm, from the same tarballs: `npm publish $S/a/<pkg>-<v>.tgz` for `sigelo` first, then
   sigelo-agent, sigelo-spend, sigelo-mcp, sigelo-recovery-kit (token in a temporary userconfig, never
   on a command line). New names show a `0.0.0-stage` placeholder for a minute or two. Check each
   with `npm view <pkg>@<v> dist.integrity` against the tarball's sha512.
9. Bump `integrations/mcp/server.json` to `<v>`, sync, push, `gh workflow run mcp-registry.yml -R
   csigelo/sigelo`; `site/deploy/mirror-release.sh v<v> sigelo-vps`, commit its SHA256SUMS, deploy.

## Nightly on the maintainer's host

At 02:30 a user timer runs `sigelo-nightly` (outside this repository) on a clean clone of the
private HEAD, offline: the ts, Go (with `--conformance` and `--impl` on the ts candidate), moadim,
spend (`SIGELO_TEST_NO_LIVE=1`), mcp, world, accept and kit suites, the schema, doc budget and
site checks, and `npm run sim`; crosscheck (no offline mode) is run by hand. About 9 minutes
(8m04s and 8m39s on its first two runs). Each run leaves a log and a one-line summary; a failure
leaves `FAILED` and at most one critical desktop notification a day, success none.

## Signing (from v0.1.1; v0.1.0 is unsigned)

- **Tag**: SSH signature by `~/.ssh/sigelo_release_signing`; public half `release/allowed_signers`
  (principal `csigelo@users.noreply.github.com`) = https://sigelo.io/.well-known/sigelo-release-signers.
- **Artefacts**: `release/sign-release.sh <tag> <dir>` refuses an unsigned tag and writes
  `release.json`: a bundle of the release identity
  did:sigelo:zE1ikihiqKQ7KoFL492kfFrJdUSzPeHNunGnMXLqgVfci (genesis `release/release-identity.json`
  = /.well-known/sigelo-release-identity.json; key `~/.config/sigelo/release.local.json` or
  `SIGELO_RELEASE_IDENTITY`) with one self-issued attestation, ctx `sigelo.io/release`, claims
  `{tag, commit, sha256sums_sha256, files}`. An attestation, not a new `typ`, so shipped verifiers
  check it with no wire change.
- **Check**: `release/verify-release.sh <tag> [dir | url]`: SHA256SUMS, release.json at its `iat`,
  the tag against allowed_signers.
- The long-term release key is to be derived as `k(S, "sigelo/v1/release/ed25519/<n>")` and enter
  as a voluntary rotation, so the pinned genesis holds. Its recovery key
  (`~/.config/sigelo/release-recovery.key`) is kept offline.

## Sync command

From the private repository:

```sh
SIGELO_AUTHOR='csigelo <csigelo@users.noreply.github.com>' SIGELO_GO_MODULE=github.com/csigelo/sigelo/go SIGELO_EXCLUDE='RISKS.md JOURNAL.md commercial' sh release/publish.sh
GIT_SSH_COMMAND='ssh -i ~/.ssh/sigelo_ed25519 -o IdentitiesOnly=yes' git -C ../sigelo-public push
```

`RISKS.md`, `JOURNAL.md` and `commercial/` are internal and never exported.
