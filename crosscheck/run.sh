#!/bin/sh
# ROADMAP T12: cross-check sigelo's primitives against third-party code and vectors.
#
#   crosscheck/run.sh              full run (~10 min on the test host), writes results/latest/
#   crosscheck/run.sh --quick      10 % of the random cases
#   crosscheck/run.sh --self-test  damages sigelo's answers on purpose; passes only if every
#                                  section reports divergences (the comparisons can fail)
#
# Idempotent. Everything fetched or built lives in crosscheck/.work/ (git-ignored) and is
# reused on the next run. NETWORK is needed only for what is missing from .work/:
#   - three git repositories, each pinned to a commit (below)
#   - PyPI: monero, PyNaCl, base58 and their dependencies, pinned, into a venv
#   - rfc8032.txt from rfc-editor.org, checked against a SHA-256
# plus, if absent, ts/node_modules (`cd ts && npm ci`) and the Go module cache entry for
# filippo.io/edwards25519 — both are sigelo's own dependencies, not oracles. Offline with a
# populated .work/ it runs without network. Needs: git, python3 (venv), node >= 22, go.
# Nothing outside crosscheck/.work and crosscheck/results/latest (both git-ignored) is written; ts/ and go/ are only read
# (ts is compiled into .work/ts-dist; the Go driver adds its three exports by -overlay).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
W="$HERE/.work"
mkdir -p "$W" "$HERE/results/latest"

JCS_REPO=https://github.com/cyberphone/json-canonicalization
JCS_SHA=19d51d7fe467d4706a3ff08adf8a748f29fc21e0
WYCHE_REPO=https://github.com/C2SP/wycheproof
WYCHE_SHA=3fa63dd0344abb611f1fb1d77e119938603ea230
SPEC_REPO=https://github.com/novifinancial/ed25519-speccheck
SPEC_SHA=65519336fda78a3d016e947df6d82848aca0c9da
RFC_URL=https://www.rfc-editor.org/rfc/rfc8032.txt
RFC_SHA256=ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3
PIP_PKGS="monero==1.1.1 PyNaCl==1.6.2 base58==2.1.1 pycryptodomex==3.23.0 varint==1.0.2 requests==2.34.2"

retry() { # the test host's network is flaky
  for i in 1 2 3 4; do "$@" && return 0; echo "  retry $i: $*" >&2; sleep $((i * 5)); done
  return 1
}

# fetch <dir> <repo> <sha> [sparse path]: a pinned shallow checkout; reused when at <sha>
fetch() {
  d="$W/$1"
  if [ -d "$d/.git" ] && [ "$(git -C "$d" rev-parse HEAD 2>/dev/null)" = "$3" ]; then return 0; fi
  echo "network: $2 @ $3"
  rm -rf "$d" && git init -q "$d" && git -C "$d" remote add origin "$2"
  if [ -n "${4:-}" ]; then git -C "$d" sparse-checkout set "$4"; fi
  retry git -C "$d" fetch -q --depth 1 --filter=blob:none origin "$3"
  retry git -C "$d" checkout -q FETCH_HEAD
}

fetch jcs-ref "$JCS_REPO" "$JCS_SHA"
fetch wycheproof "$WYCHE_REPO" "$WYCHE_SHA" testvectors_v1
fetch speccheck "$SPEC_REPO" "$SPEC_SHA"

if [ ! -f "$W/rfc8032.txt" ] || [ "$(sha256sum "$W/rfc8032.txt" | cut -d' ' -f1)" != "$RFC_SHA256" ]; then
  echo "network: $RFC_URL"
  retry python3 -c "import urllib.request,sys; open(sys.argv[2],'wb').write(urllib.request.urlopen(sys.argv[1],timeout=60).read())" "$RFC_URL" "$W/rfc8032.txt"
  [ "$(sha256sum "$W/rfc8032.txt" | cut -d' ' -f1)" = "$RFC_SHA256" ] || { echo "rfc8032.txt: SHA-256 mismatch" >&2; exit 1; }
fi

if ! "$W/venv/bin/python" -c "import monero, nacl, base58" 2>/dev/null; then
  echo "network: PyPI $PIP_PKGS"
  rm -rf "$W/venv" && python3 -m venv "$W/venv"
  retry "$W/venv/bin/pip" install -q --disable-pip-version-check $PIP_PKGS
fi

# ---- build the drivers (offline)
[ -d "$ROOT/ts/node_modules/@noble/ed25519" ] || { echo "ts/node_modules missing: run (cd ts && npm ci) first (network)" >&2; exit 1; }
ln -sfn ../../ts/node_modules "$W/node_modules"
rm -rf "$W/ts-dist"
node "$ROOT/ts/node_modules/typescript/bin/tsc" -p "$ROOT/ts/tsconfig.json" --outDir "$W/ts-dist"

printf '{"Replace":{"%s/go/zz_crosscheck_export.go":"%s/go-driver/export.go.txt"}}\n' "$ROOT" "$HERE" > "$W/overlay.json"
(cd "$HERE/go-driver" && go build -overlay "$W/overlay.json" -o "$W/sigelo-go-driver" .)
printf 'module webpki.org/jsoncanonicalizer\n\ngo 1.13\n' > "$W/jcs-ref/go/src/webpki.org/jsoncanonicalizer/go.mod"
(cd "$HERE/ref-go" && go build -o "$W/ref-go-driver" .)

case "${1:-}" in
  --quick) export CROSSCHECK_SCALE=0.1 ;;
  --self-test) export CROSSCHECK_SELF_TEST=1 CROSSCHECK_SCALE=0.05 ;;
  "") ;;
  *) echo "usage: $0 [--quick|--self-test]" >&2; exit 2 ;;
esac
echo "sigelo HEAD $(git -C "$ROOT" rev-parse --short HEAD); running crosscheck.py"
status=0
"$W/venv/bin/python" "$HERE/crosscheck.py" || status=$?
# json.dump ends a file without a newline, so an empty list was `[]` with no line ending at all,
# and once copied into results/ git saw it as `i/none` (CI's checkout check failed on every
# runner, 2026-10-01). Every results file ends with one LF.
for f in "$HERE"/results/latest/*.json; do
  if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then printf '\n' >> "$f"; fi
done
exit "$status"
