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
   user.email=contact@sigelo.io tag -a v<v> -m '…'` (and go/v<v>; message: draft / wire / keeper
   status). A plain `git tag -a` writes the local UTC offset into the tagger line (§5.1): check
   `git cat-file -p v<v>` says `+0000`. Push both: `git push origin v<v> go/v<v>`.
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
then flip the site's "after the first npm publish" footnote and index.json `published`), and
the §5.5 signed `release` object plus SSH-signed tags from the project identity.
