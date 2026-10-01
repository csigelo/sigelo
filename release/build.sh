#!/bin/sh
# The release artifacts (ROADMAP T4, §5.5) and their SHA256SUMS:
#
#   release/build.sh [outdir]          default outdir: release/dist
#
#   sigelo-<v>.tgz sigelo-spend-<v>.tgz sigelo-agent-<v>.tgz sigelo-mcp-<v>.tgz sigelo-recovery-kit-<v>.tgz
#                                      the five npm packages, as `npm publish` would upload them
#                                      (sigelo-spend carries the keeper installer, `sigelo-spend init`)
#   sigelo-verify-<os>-<arch>[.exe]    static verifier binaries: linux/darwin × amd64/arm64, windows/amd64
#   sigelo-verify-src-<v>.tar.gz       go/ + test-vectors.json + LICENSE: `go build ./cmd/sigelo-verify`
#   test-vectors.json                  the conformance target (`sigelo-verify --conformance`)
#
# release/pack-test.sh installs all of it in an empty directory and runs it. At D1 (ROADMAP §7),
# once the npm account and the repository exist, the maintainer publishes exactly these files:
#
#   for t in sigelo sigelo-spend sigelo-agent sigelo-mcp sigelo-recovery-kit; do npm publish "$out/$t-<v>.tgz"; done
#   gh release create v<v> "$out"/sigelo-verify-* "$out"/test-vectors.json "$out"/SHA256SUMS
#
# `sigelo` first: the other three depend on it (^<v>). Publishing a tarball runs no scripts, so
# the prepublishOnly guard in each package.json (which refuses a publish from a directory
# without SIGELO_PUBLISH=1) does not apply to it. `go install
# github.com/csigelo/sigelo/go/cmd/sigelo-verify@v<v>` works once the export carries that module path
# (release/publish.sh, SIGELO_GO_MODULE=github.com/csigelo/sigelo/go) and the tag go/v<v> is pushed.
#
# Everything is built from a fresh clone of HEAD, never from the working tree: uncommitted
# changes (yours, or another tool's) cannot reach an artifact, and the script says when there
# are any. The npm tarballs are packed there with the lockfiles (`npm ci --ignore-scripts`, then `npm pack`, whose prepack builds dist/ and whose
# release/prepack.mjs pins the `file:` sibling dependencies to ^<v>). npm writes fixed mtimes
# into a tarball, so the same commit and the same node/npm/typescript give the same bytes.
# All five packages carry one version; the build refuses otherwise.
#
# Same commit + same Go toolchain ⇒ byte-identical binaries on any host: CGO off (no libc, no
# host C toolchain), -trimpath (no build paths), -buildid= and -s -w (no build ID, no symbol or
# DWARF tables), and GOFLAGS=-mod=readonly so go.sum is what is built. The VCS stamp the Go
# toolchain embeds (commit, commit time, and whether the tree was modified) is kept on
# purpose — `sigelo-verify --version` prints it — and is a function of the commit alone, since
# the clone it is built in is clean. SOURCE_DATE_EPOCH is
# the commit time; Go embeds no timestamps of its own, so it is used only to pin the output
# files' mtimes (an archive of them is then reproducible too).
#
# The Go version is part of the input: a second builder must use the one printed here (a
# `toolchain` line in go.mod would pin it; see ROADMAP §5.5).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/release/dist}
case $out in /*) ;; *) out=$(pwd)/$out ;; esac

if [ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]; then
	echo "build.sh: the working tree has uncommitted changes; they are NOT in this build, which is HEAD." >&2
fi

commit=$(git -C "$root" rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct HEAD)
# The same instant as `touch -t` wants it, in UTC. `touch -d @N` is GNU/busybox only (macOS
# touch has no -d @); `touch -t` is POSIX, and git formats the commit time for it.
stamp=$(TZ=UTC0 git -C "$root" log -1 --format=%cd --date=format-local:%Y%m%d%H%M.%S HEAD)
export SOURCE_DATE_EPOCH CGO_ENABLED=0 GOFLAGS=-mod=readonly
# Nothing from the builder's own environment may reach the build.
# GOENV=off: a `go env -w` setting on this host (GOFLAGS, GOAMD64, …) must not change the output.
export GOENV=off GOAMD64=v1 GOARM64=v8.0 GOEXPERIMENT=

stage=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-build.XXXXXX")
trap 'rm -rf "$stage"' EXIT
src=$stage/src
# --shared: the clone borrows the object store (nothing copied, nothing written to this repo).
git clone -q --shared --no-checkout "$root" "$src"
git -C "$src" -c advice.detachedHead=false checkout -q --detach "$commit"

# The five packages share one version (VERSIONING.md: packages use semver, in lockstep in 0.x).
v=$(node -p 'require(process.argv[1]).version' "$src/ts/package.json")
for p in spend adapters/moadim integrations/mcp kit; do
	pv=$(node -p 'require(process.argv[1]).version' "$src/$p/package.json")
	[ "$pv" = "$v" ] || { echo "build.sh: $p/package.json is $pv, ts/package.json is $v; the packages move together" >&2; exit 1; }
done

rm -rf "$out"
mkdir -p "$out"

# Go first, while the clone is exactly the commit (the VCS stamp records "modified" otherwise;
# node_modules/ and dist/ are gitignored, but nothing is left to chance).
cd "$src/go"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
	os=${target%/*} arch=${target#*/}
	ext=; [ "$os" = windows ] && ext=.exe
	bin=sigelo-verify-$os-$arch$ext
	GOOS=$os GOARCH=$arch go build -trimpath -ldflags='-s -w -buildid=' -o "$out/$bin" ./cmd/sigelo-verify
done
git -C "$src" archive --format=tar.gz --prefix="sigelo-verify-src-$v/" -o "$out/sigelo-verify-src-$v.tar.gz" HEAD go test-vectors.json LICENSE
cp "$src/test-vectors.json" "$out/test-vectors.json"

# npm: flaky networks are the norm on some builders; npm ci is retried, never skipped.
retry() { n=1; until "$@"; do [ $n -ge 3 ] && return 1; n=$((n + 1)); echo "build.sh: retry $n: $*" >&2; sleep 5; done; }
for p in ts spend adapters/moadim integrations/mcp kit; do
	# mcp and kit have no build step: their pack only reads their siblings' package.json, so no install.
	[ "$p" = integrations/mcp ] || [ "$p" = kit ] || (cd "$src/$p" && retry npm ci --ignore-scripts --no-audit --no-fund --silent)
	(cd "$src/$p" && npm pack --silent --pack-destination "$out" >/dev/null)
done
for t in sigelo sigelo-spend sigelo-agent sigelo-mcp sigelo-recovery-kit; do
	[ -f "$out/$t-$v.tgz" ] || { echo "build.sh: npm pack made no $t-$v.tgz" >&2; exit 1; }
	# the published manifest must name no sibling directory
	if tar -xzOf "$out/$t-$v.tgz" package/package.json | grep -q '"file:'; then
		echo "build.sh: $t-$v.tgz still has a file: dependency" >&2; exit 1
	fi
done
# The installer ships inside sigelo-spend (it is the same package: `sigelo-spend init`), the tests do not.
listing=$(tar -tzf "$out/sigelo-spend-$v.tgz")
for f in cli init licence rpcrange service; do
	printf '%s\n' "$listing" | grep -qx "package/dist/$f.js" || { echo "build.sh: sigelo-spend-$v.tgz has no dist/$f.js" >&2; exit 1; }
done
if printf '%s\n' "$listing" | grep -q 'package/dist/test\.'; then echo "build.sh: sigelo-spend-$v.tgz carries the tests (and the test vendor key)" >&2; exit 1; fi
cd "$out"
TZ=UTC0 touch -t "$stamp" sigelo-* test-vectors.json
# sha256sum's own format, sorted by name: `sha256sum -c SHA256SUMS` checks it.
if command -v sha256sum >/dev/null 2>&1; then sum='sha256sum'; else sum='shasum -a 256'; fi
$sum sigelo-* test-vectors.json | LC_ALL=C sort -k2 > SHA256SUMS
TZ=UTC0 touch -t "$stamp" SHA256SUMS

echo "commit $commit (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
echo "$(go version); node $(node --version); npm $(npm --version)"
cat SHA256SUMS
