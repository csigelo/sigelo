#!/bin/sh
# release/publish.sh — the PUBLIC export of this repository (ROADMAP §5.1).
#
#   SIGELO_AUTHOR='csigelo <contact@sigelo.io>' SIGELO_GO_MODULE=github.com/csigelo/sigelo/go \
#     release/publish.sh [outdir]                                  default outdir: ../sigelo-public
#
# The private history carries the maintainer's name, e-mail, time zone and device in old
# commits, so the public repository is not a rewrite of it: it is a FRESH git repository with
# ONE commit holding the tracked tree of HEAD, authored by SIGELO_AUTHOR, dated in UTC. Before
# the commit, every file is grepped for identity strings: the generic patterns below plus the
# private list in SIGELO_DEVICE_STRINGS (default ~/.config/sigelo/device-strings, one extended
# regex per line, kept OUTSIDE the repository — the same list belongs in the GitHub secret
# DEVICE_STRINGS that .github/workflows/conformance.yml reads). One hit and nothing is written.
#
# Environment:
#   SIGELO_AUTHOR          required: the project pseudonym, `Name <email>` (never the real one);
#                          decided at D1: `csigelo <contact@sigelo.io>`
#   SIGELO_DEVICE_STRINGS  the private pattern file (see above)
#   SIGELO_GO_MODULE       optional: rewrite the Go module path (bare `sigelo` today) to e.g.
#                          github.com/csigelo/sigelo/go, in go.mod and the one import of it
#   SIGELO_EXCLUDE         optional: extra paths to leave out, space-separated (default: none)
#   SIGELO_SKIP_TESTS=1    skip running every suite inside the export (they are the proof; ~10 min)
#
# Re-running replaces outdir. Commit hashes cited in the docs refer to the private history;
# the export says so in CHANGELOG.md.
set -eu

die() { echo "publish.sh: $*" >&2; exit 1; }
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

src=$(git -C "$root" rev-parse --short HEAD)
stage=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-publish.XXXXXX")
trap 'rm -rf "$stage"' EXIT

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
#    carries it), the preface must not be added a second time.
if ! head -n 5 "$stage/CHANGELOG.md" | grep -q '^Short commit hashes cited in this repository'; then
  {
    printf '%s\n\n' '# Changelog'
    printf '%s\n%s\n\n' 'Short commit hashes cited in this repository refer to the pre-publication development' \
      "history, which is not public. This public history starts at the import of $(date -u +%Y-%m-%d)."
    sed '1{/^# Changelog$/d;}' "$stage/CHANGELOG.md" | sed '1{/^$/d;}'
  } > "$stage/CHANGELOG.md.new" && mv "$stage/CHANGELOG.md.new" "$stage/CHANGELOG.md"
fi

# 4. Identity strings: generic patterns plus the private file, grepped with `git grep` over the
#    tracked tree of HEAD (what step 1 archived) so the check runs the same on GNU, busybox, macOS
#    and Git Bash — a plain `grep -r` with GNU-only flags fails on busybox, and a swallowed error
#    would look like a clean pass. Exit 0 = hits, 1 = clean, anything else = the grep itself
#    failed; only 1 exports. No tracked file holds a pattern — not even a "generic" one (AUDIT
#    A5) — so nothing is excluded but the SIGELO_EXCLUDE paths, and an empty list refuses to
#    export rather than passing vacuously.
pat=$stage/.publish-patterns
grep -v '^[[:space:]]*$' "$patterns" > "$pat" || true
[ -s "$pat" ] || die "the pattern file $patterns is empty; refusing to export unchecked"
set -- .
for p in ${SIGELO_EXCLUDE:-}; do set -- "$@" ":!$p"; done
set +e
hits=$(git -C "$root" grep -nIiE -f "$pat" HEAD -- "$@" 2>&1)
rc=$?
set -e
case $rc in
  0) printf '%s\n' "$hits" | head -40 >&2
     die "identity or device strings in the export (above): reword them in the private repository, then re-run" ;;
  1) ;;
  *) printf '%s\n' "$hits" >&2
     die "the identity-string grep itself failed (exit $rc); refusing to export unchecked" ;;
esac
rm -f "$pat"

# 5. A fresh repository, one commit, UTC, the pseudonym.
rm -rf "$out"; mkdir -p "$out"
cp -R "$stage/." "$out/"
name=${SIGELO_AUTHOR%%<*}; name=$(printf '%s' "$name" | sed 's/[[:space:]]*$//')
email=${SIGELO_AUTHOR#*<}; email=${email%>*}
epoch=$(date -u +%s)
export GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email"
export GIT_AUTHOR_DATE="@$epoch +0000" GIT_COMMITTER_DATE="@$epoch +0000" TZ=UTC
git -C "$out" init -q -b main
git -C "$out" config user.name "$name"
git -C "$out" config user.email "$email"
git -C "$out" config commit.gpgsign false
git -C "$out" add -A
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

# 6. The proof: a clean install and every suite, inside the export.
[ "${SIGELO_SKIP_TESTS:-}" = 1 ] && { echo "publish.sh: tests skipped (SIGELO_SKIP_TESTS=1)"; exit 0; }
run() { echo "publish.sh: $1"; shift; ( "$@" ) || die "failed: $*"; }
run "ts: install + build + vectors + tests" sh -c "cd '$out/ts' && npm ci --ignore-scripts --silent && npx tsc && node dist/gen_vectors.js > '$stage/vectors.json' && diff -q ../test-vectors.json '$stage/vectors.json' && node dist/test.js | tail -1 | grep -q '^ALL PASS'"
run "go: vet + tests + static build" sh -c "cd '$out/go' && go vet ./... && go test ./... 2>&1 | tail -2 | grep -q '^ok' && CGO_ENABLED=0 go build ./cmd/sigelo-verify && rm -f sigelo-verify"
run "moadim adapter" sh -c "cd '$out/adapters/moadim' && npm ci --ignore-scripts --silent && npm test 2>&1 | grep -q '^ALL PASS'"
run "spend keeper" sh -c "cd '$out/spend' && npm ci --ignore-scripts --silent && npm test 2>&1 | grep -q '^ALL PASS'"
run "mcp server" sh -c "cd '$out/integrations/mcp' && npm test 2>&1 | grep -q 'ALL PASS'"
run "schemas" sh -c "cd '$out' && node schema/check.mjs | grep -q '^ALL PASS'"
# node_modules and dist are untracked (.gitignore); the export commit is untouched by the run.
[ -z "$(git -C "$out" status --porcelain)" ] || die "the test run left tracked changes in the export: $(git -C "$out" status --porcelain | head -5)"
cat <<NEXT
publish.sh: ALL PASS inside the export.
Next, by the maintainer (ROADMAP §5.1):
  1. the project account is github.com/csigelo (contact@sigelo.io, D1): push with its own SSH
     key, never the personal one
  2. cd "$out" && git remote add origin git@github.com:csigelo/sigelo.git && git push -u origin main
  3. repository secret DEVICE_STRINGS = the contents of $patterns (CI greps every push)
  4. SECURITY.md: fill the age recipient and SimpleX placeholders; create security@sigelo.io
  5. release, ROADMAP T4 (the commands are in release/build.sh's header): if this run lacked it,
     re-run with SIGELO_GO_MODULE=github.com/csigelo/sigelo/go, then in "$out":
       release/build.sh && release/pack-test.sh release/dist        # tarballs, binaries, ALL PASS
       git tag v<version> && git tag go/v<version> && git push origin v<version> go/v<version>
       npm publish release/dist/<pkg>-<version>.tgz                 # sigelo first, then spend, agent, mcp
       gh release create v<version> release/dist/sigelo-verify-* release/dist/test-vectors.json release/dist/SHA256SUMS
NEXT
