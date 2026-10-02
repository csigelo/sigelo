# Cutting a release (as v0.1.0 was cut, 2026-10-02)

Artefacts are built from the PUBLIC tree (Go module path rewritten), never from this one.
`<v>` is the package version, the same in every package.json; `$S` a scratch directory.

1. Here (private): CHANGELOG.md gets `## v<v> — <date>` over the entries it releases (the
   release notes link to it); VERSIONING.md status line; ROADMAP §6 step 8; site footnotes.
   `node site/build.mjs && node site/test/run.mjs` passes. Commit.
2. Sync and push:
   `SIGELO_AUTHOR='csigelo <contact@sigelo.io>' SIGELO_GO_MODULE=github.com/csigelo/sigelo/go sh release/publish.sh`
   `GIT_SSH_COMMAND='ssh -i ~/.ssh/sigelo_ed25519 -o IdentitiesOnly=yes' git -C ../sigelo-public push`
3. In ../sigelo-public at that commit: `sh release/build.sh $S/a`, `sh release/build.sh $S/b`;
   `cmp $S/a/SHA256SUMS $S/b/SHA256SUMS` must be silent. `sh release/pack-test.sh $S/a`
   must end `ALL PASS (20 checks)`. The npm tarballs' bytes depend on the npm version (CI's
   Node 22 / npm 10 differ from Node 24 / npm 11); the Go binaries match across hosts.
4. Tag that commit, both tags (the Go module lives in go/, VERSIONING §4):
   `TZ=UTC GIT_COMMITTER_DATE="$(date -u +%s) +0000" git -c user.name=csigelo -c
   user.email=contact@sigelo.io -c gpg.format=ssh -c user.signingkey=~/.ssh/sigelo_release_signing tag -s v<v> -m '…'`
   (v0.1.0 was `tag -a`, unsigned; "Signing" below) (and go/v<v>; message: draft / wire / keeper
   status). A plain `git tag -a` writes the local UTC offset into the tagger line (§5.1): check
   `git cat-file -p v<v>` says `+0000`. Push both: `git push origin v<v> go/v<v>`.
   Then `sh release/sign-release.sh v<v> $S/a` writes `$S/a/release.json` ("Signing").
5. `gh release create v<v> --repo csigelo/sigelo --prerelease --title 'sigelo v<v> (draft)'
   --notes-file $S/notes.md $S/a/*` — every file build.sh wrote, SHA256SUMS included. Notes
   (≤ 40 lines): status, install lines that work now, SHA256SUMS, link to CHANGELOG.md's heading.
   Drop `--prerelease` from the first release that is not a draft.
6. Prove it from nothing: a scratch GOPATH/GOMODCACHE,
   `GOFLAGS=-mod=mod go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@v<v>`
   (proxy.golang.org may lag the tag by minutes; `GOPROXY=direct` otherwise), then
   `sigelo-verify --conformance test-vectors.json` on the released file; `gh release download`
   one binary and check it against SHA256SUMS.
7. conformance.yml runs on the tag push (`on: push`): read its jobs through
   `api.github.com/repos/csigelo/sigelo/actions/runs?event=push&branch=v<v>`. Record the result
   in docs-test/PORTABILITY.md.

Not yet part of a release: npm publish (`npm publish $S/a/<pkg>-<v>.tgz`, `sigelo` first;
then flip the site's "after the first npm publish" footnote and index.json `published`).

## Signing (from v0.1.1; v0.1.0 stays unsigned)

Two signatures over the tagged commit; neither key is the deploy key or the maintainer's identity.
- **Tag**: SSH signature by `~/.ssh/sigelo_release_signing`; its public half is `release/allowed_signers`
  (principal `contact@sigelo.io`) = https://sigelo.io/.well-known/sigelo-release-signers.
- **Artefacts**: `release/sign-release.sh <tag> <dir>` refuses an unsigned tag and writes `release.json`, uploaded with the rest:
  a bundle of the release identity did:sigelo:zE1ikihiqKQ7KoFL492kfFrJdUSzPeHNunGnMXLqgVfci (genesis `release/release-identity.json`
  = /.well-known/sigelo-release-identity.json; key file `~/.config/sigelo/release.local.json`, or `SIGELO_RELEASE_IDENTITY`) holding one
  self-issued attestation, ctx `sigelo.io/release`, claims `{tag, commit, sha256sums_sha256, files}`. Not ROADMAP §5.5's `typ: "release"`:
  SPEC §3.1's typ table is closed and §9 step 2 rejects any other typ, so only an attestation verifies in shipped verifiers with no wire change.
- **Check**: `release/verify-release.sh <tag> [dir | url]`: SHA256SUMS, release.json at now = its `iat`, the tag against allowed_signers.
- The ceremony is to derive the long-term release key as `k(S, "sigelo/v1/release/ed25519/<n>")` (ts/src/keys.ts scheme, below the wire);
  it enters as a voluntary rotation of this identity, so the pin (chain[0]) holds. Its recovery key, `~/.config/sigelo/release-recovery.key`, goes off the phone.

## Sync command

From the private repository, every time:

```sh
SIGELO_AUTHOR='csigelo <contact@sigelo.io>' SIGELO_GO_MODULE=github.com/csigelo/sigelo/go SIGELO_EXCLUDE='RISKS.md' sh release/publish.sh
GIT_SSH_COMMAND='ssh -i ~/.ssh/sigelo_ed25519 -o IdentitiesOnly=yes' git -C ../sigelo-public push
```

`RISKS.md` is the internal risk register and decisions log: it names providers and Owner-only items and is never exported.
