#!/bin/sh
# SPDX-License-Identifier: MIT
# release/publish.sh — the PUBLIC export of this repository (ROADMAP §5.1).
#
#   SIGELO_AUTHOR='csigelo <csigelo@users.noreply.github.com>' SIGELO_GO_MODULE=github.com/csigelo/sigelo/go \
#     release/publish.sh [--fresh [--i-know-this-rewrites-history]] [outdir]
#                                                                  default outdir: ../sigelo-public
#
# The private history carries the maintainer's name, e-mail, time zone and device in old
# commits, so the public repository is not a rewrite of it. Its history is its own, and it is
# never rewritten once pushed (anyone may have cloned it). Two modes:
#
#   update  outdir is a public clone (a .git with a remote `origin` and at least one commit;
#           since the first push on 2026-10-01, ../sigelo-public): the export tree is built in
#           a temporary directory, gated and tested there, then synced over the clone's working
#           tree (rsync --delete, or remove-every-tracked-file + tar copy; .git is never
#           touched), and if anything changed ONE commit is added on top of `main`: authored by
#           SIGELO_AUTHOR, dated UTC, subject `sync: <the private CHANGELOG's topmost
#           "## unreleased — …" heading>`, body `private tree <HEAD short sha>`. Nothing is
#           pushed; the push command is printed. No change: says so and exits 0.
#   fresh   outdir is empty or does not exist (or --fresh): a NEW git repository with ONE root
#           commit holding the export tree — how bca5b16 was made. Re-running replaces outdir.
#           Against an outdir with a remote, --fresh refuses unless also given
#           --i-know-this-rewrites-history (pushing it would need a force push).
#
# The export tree is the same in both modes: the tracked tree of HEAD, the optional Go module
# rewrite, the CHANGELOG preface. Before anything is written to outdir, that FINAL tree is
# grepped for identity strings: the private list in SIGELO_DEVICE_STRINGS (default
# ~/.config/sigelo/device-strings, one extended regex per line, kept OUTSIDE the repository —
# the same list belongs in the GitHub secret DEVICE_STRINGS that
# .github/workflows/conformance.yml reads on every push). One hit and nothing is written. In
# update mode the staged clone is grepped again after the sync (`git grep --cached`) and its
# tree must equal the gated one; any failure after the sync restores the clone's index and
# working tree (reset, checkout, clean -fd) before exiting.
#
# Environment:
#   SIGELO_AUTHOR          required: the project pseudonym, `Name <email>` (never the real one);
#                          decided at D1: `csigelo <csigelo@users.noreply.github.com>`
#   SIGELO_DEVICE_STRINGS  the private pattern file (see above)
#   SIGELO_GO_MODULE       optional: rewrite the Go module path (bare `sigelo` today) to e.g.
#                          github.com/csigelo/sigelo/go, in go.mod and the one import of it
#   SIGELO_EXCLUDE         optional: extra paths to leave out, space-separated (default: none)
#   SIGELO_SKIP_TESTS=1    skip running every suite on the export tree (they are the proof; ~10 min)
#   SIGELO_TEST_FAIL_AFTER_SYNC=1   test hook: fail after an update-mode sync, before the
#                          commit, to prove the clone is restored
#
# Commit hashes cited in the docs refer to the private history; the export says so in
# CHANGELOG.md.
set -eu

die() {
  echo "publish.sh: $*" >&2
  if [ "${synced:-0}" = 1 ]; then
    git -C "$out" reset -q && git -C "$out" checkout -q -- . && git -C "$out" clean -qfd \
      && echo "publish.sh: $out restored to $(git -C "$out" rev-parse --short HEAD), nothing committed" >&2 \
      || echo "publish.sh: RESTORE OF $out FAILED — inspect it before anything else" >&2
  fi
  exit 1
}
fresh=0 rewrite_ok=0
while [ $# -gt 0 ]; do
  case $1 in
    --fresh) fresh=1 ;;
    --i-know-this-rewrites-history) rewrite_ok=1 ;;
    -*) die "unknown option $1" ;;
    *) break ;;
  esac
  shift
done
[ $# -le 1 ] || die "usage: publish.sh [--fresh [--i-know-this-rewrites-history]] [outdir]"
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/../sigelo-public}
case $out in /*) ;; *) out=$(pwd)/$out ;; esac
patterns=${SIGELO_DEVICE_STRINGS:-$HOME/.config/sigelo/device-strings}

[ -n "${SIGELO_AUTHOR:-}" ] || die "SIGELO_AUTHOR='Name <email>' is required (the project pseudonym)"
case $SIGELO_AUTHOR in *"<"*"@"*">"*) ;; *) die "SIGELO_AUTHOR must look like 'Name <email>'" ;; esac
[ -f "$patterns" ] || die "no private pattern file at $patterns (SIGELO_DEVICE_STRINGS): one extended regex per line; refusing to export unchecked"
[ -z "$(git -C "$root" status --porcelain)" ] || die "the working tree has uncommitted changes; export from a commit"
command -v node >/dev/null || die "node is required"
command -v go >/dev/null || die "go is required"
[ "$(git -C "$root" rev-parse --show-toplevel)" != "$(cd "$out" 2>/dev/null && git rev-parse --show-toplevel 2>/dev/null || echo none)" ] || die "outdir is inside this repository"

# The mode. A remote means a published repository: only update mode may touch it, unless the
# maintainer explicitly asks for a history rewrite.
has_remote=0 has_commit=0
if [ -d "$out/.git" ]; then
  git -C "$out" remote get-url origin >/dev/null 2>&1 && has_remote=1
  git -C "$out" rev-parse -q --verify HEAD >/dev/null 2>&1 && has_commit=1
fi
if [ $fresh = 1 ]; then
  [ $has_remote = 0 ] || [ $rewrite_ok = 1 ] || die "--fresh refused: $out has a remote origin ($(git -C "$out" remote get-url origin)); a fresh root commit pushed there rewrites public history. Run without --fresh to update, or add --i-know-this-rewrites-history"
  mode=fresh
elif [ $has_remote = 1 ] && [ $has_commit = 1 ]; then
  mode=update
elif [ $has_remote = 1 ]; then
  die "$out has a remote origin but no commit; refusing to guess (--fresh --i-know-this-rewrites-history replaces it)"
else
  mode=fresh
fi
if [ $mode = update ]; then
  [ "$(git -C "$out" symbolic-ref -q --short HEAD || true)" = main ] || die "update mode: $out is not on branch main"
  [ -z "$(git -C "$out" status --porcelain)" ] || die "update mode: $out has uncommitted changes: $(git -C "$out" status --porcelain | head -5)"
fi
echo "publish.sh: $mode mode -> $out"

src=$(git -C "$root" rev-parse --short HEAD)
work=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-publish.XXXXXX")
trap 'rm -rf "$work"' EXIT
stage=$work/tree
mkdir "$stage"

# 1. The tracked tree of HEAD, and nothing else (no node_modules, dist, *.local.json, .git).
git -C "$root" archive --format=tar HEAD | tar -x -C "$stage"
for p in ${SIGELO_EXCLUDE:-}; do rm -rf "$stage/$p"; done
# 2. Optional Go module path. The module lives in go/, a subdirectory, so the path must end in
#    /go, and `go install <path>/cmd/sigelo-verify@v<v>` then resolves the tag go/v<v>, not v<v>
#    (Go's rule for a module below the repository root); the Next list names both tags. Every Go
#    file importing the bare path, and any other go.mod requiring or replacing it, is rewritten;
#    one bare import left refuses the export (the build would fail on it, but only in step 6).
if [ -n "${SIGELO_GO_MODULE:-}" ]; then
  case $SIGELO_GO_MODULE in
    */go) ;;
    *) die "SIGELO_GO_MODULE must end in /go (the module is the repository's go/ directory), e.g. github.com/csigelo/sigelo/go" ;;
  esac
  printf '%s' "$SIGELO_GO_MODULE" | grep -Eq '^[a-z0-9.-]+\.[a-z]+(/[A-Za-z0-9._-]+)+$' || die "SIGELO_GO_MODULE does not look like a module path: $SIGELO_GO_MODULE"
  sed -i.bak "s#^module sigelo\$#module $SIGELO_GO_MODULE#" "$stage/go/go.mod" && rm -f "$stage/go/go.mod.bak"
  grep -q "^module $SIGELO_GO_MODULE\$" "$stage/go/go.mod" || die "go.mod rewrite failed"
  bare='^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_]*[[:space:]]+)?"sigelo(/[^"]*)?"[[:space:]]*$'
  find "$stage" -name '*.go' -type f | while IFS= read -r f; do
    grep -Eq "$bare" "$f" || continue
    sed -i.bak -E "s#^([[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_]*[[:space:]]+)?)\"sigelo(/[^\"]*)?\"#\\1\"$SIGELO_GO_MODULE\\4\"#" "$f" && rm -f "$f.bak"
  done
  find "$stage" -name go.mod -type f ! -path "$stage/go/go.mod" | while IFS= read -r f; do
    sed -i.bak -E "s#^((require|replace)[[:space:]]+|[[:space:]]+)sigelo([[:space:]])#\\1$SIGELO_GO_MODULE\\3#" "$f" && rm -f "$f.bak"
  done
  left=$(find "$stage" -name '*.go' -type f -exec grep -HnE "$bare" {} + || true)
  [ -z "$left" ] || die "bare Go imports of sigelo left after the module rewrite: $left"
fi

# 3. The one line the export adds — once: run against an export (whose CHANGELOG already
#    carries it), the preface must not be added a second time. The import date is the public
#    root commit's in update mode (bca5b16: 2026-10-01), so a later sync does not change it.
if [ $mode = update ]; then
  first=$(git -C "$out" rev-list --max-parents=0 HEAD | tail -n 1)
  imported=$(TZ=UTC git -C "$out" log -1 --format=%cd --date=format-local:%Y-%m-%d "$first")
else
  imported=$(date -u +%Y-%m-%d)
fi
if ! head -n 5 "$stage/CHANGELOG.md" | grep -q '^Short commit hashes cited in this repository'; then
  {
    printf '%s\n\n' '# Changelog'
    printf '%s\n%s\n\n' 'Short commit hashes cited in this repository refer to the pre-publication development' \
      "history, which is not public. This public history starts at the import of $imported."
    sed '1{/^# Changelog$/d;}' "$stage/CHANGELOG.md" | sed '1{/^$/d;}'
  } > "$stage/CHANGELOG.md.new" && mv "$stage/CHANGELOG.md.new" "$stage/CHANGELOG.md"
fi

# 4. Identity strings, grepped over the FINAL tree (after steps 2 and 3) with `git grep` on a
#    throwaway index of it, so the check runs the same on GNU, busybox, macOS and Git Bash — a
#    plain `grep -r` with GNU-only flags fails on busybox, and a swallowed error would look like
#    a clean pass. `add -f`: a tracked file the .gitignore matches is still exported, so it is
#    still grepped. Exit 0 = hits, 1 = clean, anything else = the grep itself failed; only 1
#    exports. No tracked file holds a pattern — not even a "generic" one (AUDIT A5) — so
#    nothing is excluded, and an empty list refuses to export rather than passing vacuously.
pat=$work/patterns
grep -v '^[[:space:]]*$' "$patterns" > "$pat" || true
[ -s "$pat" ] || die "the pattern file $patterns is empty; refusing to export unchecked"
gate() {  # gate <label> <git command whose index holds the tree>
  label=$1; shift
  set +e
  hits=$("$@" grep -nIiE -f "$pat" --cached 2>&1)
  rc=$?
  set -e
  case $rc in
    0) printf '%s\n' "$hits" | head -40 >&2
       die "identity or device strings in the $label (above): reword them in the private repository, then re-run" ;;
    1) ;;
    *) printf '%s\n' "$hits" >&2
       die "the identity-string grep over the $label itself failed (exit $rc); refusing to export unchecked" ;;
  esac
}
gi() { git --git-dir="$work/gate.git" --work-tree="$stage" "$@"; }
git init -q --bare "$work/gate.git"
gi add -A -f .
gate "export tree" gi
tree=$(gi write-tree)

# 5. The proof: a clean install and every suite, on a copy of the export tree (node_modules
#    and dist stay out of what is committed), before anything is written to outdir.
if [ "${SIGELO_SKIP_TESTS:-}" = 1 ]; then
  echo "publish.sh: tests skipped (SIGELO_SKIP_TESTS=1)"
else
  t=$work/test
  cp -R "$stage" "$t"
  run() { echo "publish.sh: $1"; shift; ( "$@" ) || die "failed: $*"; }
  run "ts: install + build + vectors + tests" sh -c "cd '$t/ts' && npm ci --ignore-scripts --silent && npx tsc && node dist/gen_vectors.js > '$work/vectors.json' && diff -q ../test-vectors.json '$work/vectors.json' && node dist/test.js | tail -1 | grep -q '^ALL PASS'"
  run "go: vet + tests + static build" sh -c "cd '$t/go' && go vet ./... && go test ./... 2>&1 | tail -2 | grep -q '^ok' && CGO_ENABLED=0 go build ./cmd/sigelo-verify && rm -f sigelo-verify"
  run "moadim adapter" sh -c "cd '$t/adapters/moadim' && npm ci --ignore-scripts --silent && npm test 2>&1 | grep -q '^ALL PASS'"
  run "spend keeper" sh -c "cd '$t/spend' && npm ci --ignore-scripts --silent && npm test 2>&1 | grep -q '^ALL PASS'"
  run "mcp server" sh -c "cd '$t/integrations/mcp' && npm test 2>&1 | grep -q 'ALL PASS'"
  run "schemas" sh -c "cd '$t' && node schema/check.mjs | grep -q '^ALL PASS'"
  git --git-dir="$work/gate.git" --work-tree="$t" diff --quiet || die "the test run changed exported files: $(git --git-dir="$work/gate.git" --work-tree="$t" diff --stat | tail -5)"
  echo "publish.sh: ALL PASS on the export tree ($tree)"
fi

name=${SIGELO_AUTHOR%%<*}; name=$(printf '%s' "$name" | sed 's/[[:space:]]*$//')
email=${SIGELO_AUTHOR#*<}; email=${email%>*}
epoch=$(date -u +%s)
export GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email"
export GIT_AUTHOR_DATE="@$epoch +0000" GIT_COMMITTER_DATE="@$epoch +0000" TZ=UTC

if [ $mode = update ]; then
  # 6u. Sync the gated tree over the clone's working tree; .git is never touched. From here on
  #     any failure restores the clone (die). Ignored files (node_modules, dist) survive the
  #     tar path and are deleted by rsync --delete; neither is ever committed.
  before=$(git -C "$out" rev-parse HEAD)
  synced=1
  if command -v rsync >/dev/null; then
    rsync -a --delete --exclude /.git "$stage/" "$out/" || die "rsync into $out failed"
  else
    ( cd "$out" && git ls-files -z | xargs -0 rm -f -- ) || die "removing the tracked files of $out failed"
    ( cd "$out" && find . -mindepth 1 -type d -empty ! -path ./.git ! -path "./.git/*" -delete ) || die "pruning empty directories in $out failed"
    ( cd "$stage" && tar -cf - . ) | ( cd "$out" && tar -xf - ) || die "copying the export tree into $out failed"
  fi
  git -C "$out" add -A
  git --git-dir="$work/gate.git" ls-files -z | git -C "$out" add -f --pathspec-from-file=- --pathspec-file-nul
  gate "staged public clone" git -C "$out"
  [ "$(git -C "$out" write-tree)" = "$tree" ] || die "the staged clone's tree is not the gated export tree ($tree): $(git -C "$out" diff --cached --stat | tail -3)"
  [ "${SIGELO_TEST_FAIL_AFTER_SYNC:-}" != 1 ] || die "SIGELO_TEST_FAIL_AFTER_SYNC=1: failing after the sync, before the commit"
  if git -C "$out" diff --cached --quiet; then
    synced=0
    echo "publish.sh: no changes — $out already holds the export of private $src ($(git -C "$out" log -1 --format='%h %s'))"
    exit 0
  fi
  heading=$(grep -m 1 '^## unreleased' "$root/CHANGELOG.md" || grep -m 1 '^## ' "$root/CHANGELOG.md" || echo '## export')
  git -C "$out" commit -q -F - <<MSG || die "the commit failed"
sync: ${heading#\#\# }

private tree $src
MSG
  synced=0
  [ "$(git -C "$out" rev-parse HEAD^)" = "$before" ] || die "the new commit is not on top of $before"
  echo "publish.sh: $out — one commit on main:"
  git -C "$out" log --oneline -3
  git -C "$out" show --stat --format='%h %an <%ae> %ad' --date=iso-strict HEAD
  cat <<NEXT
Not pushed. Review, then:
  git -C "$out" push origin main
CI on the push greps the tree with the DEVICE_STRINGS repository secret (keep it equal to $patterns).
NEXT
  exit 0
fi

# 6f. A fresh repository, one commit, UTC, the pseudonym.
rm -rf "$out"; mkdir -p "$out"
cp -R "$stage/." "$out/"
git -C "$out" init -q -b main
git -C "$out" config user.name "$name"
git -C "$out" config user.email "$email"
git -C "$out" config commit.gpgsign false
git -C "$out" add -A -f .
[ "$(git -C "$out" write-tree)" = "$tree" ] || die "the fresh repository's tree is not the gated export tree ($tree)"
git -C "$out" commit -q -F - <<MSG
sigelo v0.1 draft (wire sigelo/0): public import

Protocol for portable AI-agent identity (Ed25519 + SHA-256 + JCS, offline verification,
recovery-beats-key) with a Monero payment pillar. SPEC.md is the source of truth;
test-vectors.json the conformance target; go/ the reference verifier; ts/ the TypeScript
implementation; spend/ the keeper; adapters/ and integrations/ the world, agent and harness
sides. Imported from a private development history (source $src).

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
MSG
echo "publish.sh: $out — $(git -C "$out" log --format='%h %an <%ae> %ad' --date=iso-strict)"
cat <<NEXT
Next, by the maintainer (ROADMAP §5.1). The public repository already exists
(github.com/csigelo/sigelo, first push 2026-10-01): a fresh export is for a scratch check or a
deliberate history rewrite only; every sync of the published repository is update mode
(run without --fresh against its clone). For a new repository:
  1. push with the project account's own SSH key (csigelo, contact@sigelo.io), never the personal one
  2. cd "$out" && git remote add origin git@github.com:csigelo/sigelo.git && git push -u origin main
  3. repository secret DEVICE_STRINGS = the contents of $patterns (CI greps every push)
  4. release, ROADMAP T4 (the commands are in release/build.sh's header), in the clone:
       release/build.sh && release/pack-test.sh release/dist        # tarballs, binaries, ALL PASS
       git tag v<version> && git tag go/v<version> && git push origin v<version> go/v<version>
       npm publish release/dist/<pkg>-<version>.tgz                 # sigelo first, then spend, agent, mcp
       gh release create v<version> release/dist/sigelo-verify-* release/dist/test-vectors.json release/dist/SHA256SUMS
NEXT
