#!/bin/sh
# release/pack-test.sh — the release artifacts, installed and run where no clone is (ROADMAP T4).
#
#   release/pack-test.sh [dist]      dist: a release/build.sh output; default: build one now
#                                    (from HEAD) into a temporary directory
#
# In an empty temporary directory, outside the repository, with HOME pointed there too:
#   1. `npm install` the five tarballs together. The pinned `sigelo@^<v>` that sigelo-spend,
#      sigelo-agent, sigelo-mcp and sigelo-recovery-kit ask for is met by the sigelo tarball installed beside them,
#      so nothing comes from the registry but the third-party dependencies (@noble/*).
#   2. The acceptance commands of T4, as a user types them: `npx sigelo-agent init`,
#      `npx -p sigelo-spend sigelo-wallet balance`, the keeper installer (`sigelo-spend init`
#      --no-systemd, then `doctor` and `licence show`), the MCP server over stdio,
#      `sigelo-offline`, and `import … from 'sigelo'`.
#   3. Go: `go build ./cmd/sigelo-verify` from the source archive, `--conformance` with it and
#      with the prebuilt binary for this host, and `sha256sum -c SHA256SUMS`.
# Every check prints `ok …`; the first failure prints `FAIL …` and exits 1. The last line is
# `ALL PASS (<n> checks)`. Needs node ≥ 22.18, npm, go, and the registry for @noble/* (retried).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-pack-test.XXXXXX")
# the Go module cache under the temporary HOME is read-only by design
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
n=0
ok() { n=$((n + 1)); echo "ok   $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }
retry() { i=1; until "$@"; do [ $i -ge 3 ] && return 1; i=$((i + 1)); echo "pack-test: retry $i: $*" >&2; sleep 5; done; }

if [ $# -ge 1 ]; then
	dist=$(cd "$1" && pwd)
else
	dist=$work/dist
	"$root/release/build.sh" "$dist" > "$work/build.log" 2>&1 || { cat "$work/build.log" >&2; fail "release/build.sh"; }
	ok "release/build.sh → $(ls "$dist" | wc -l | tr -d ' ') files"
fi
v=$(node -p 'require(process.argv[1]).version' "$root/ts/package.json")
case $(uname -s) in Linux) os=linux ;; Darwin) os=darwin ;; *) os=windows ;; esac
case $(uname -m) in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) arch=$(uname -m) ;; esac

# 0. The artifacts are the ones SHA256SUMS names.
(cd "$dist" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi) > "$work/sums.log" 2>&1 \
	|| { cat "$work/sums.log" >&2; fail "sha256sum -c SHA256SUMS"; }
ok "SHA256SUMS: $(wc -l < "$dist/SHA256SUMS" | tr -d ' ') files verified"
for t in sigelo sigelo-spend sigelo-agent sigelo-mcp sigelo-recovery-kit; do
	m=$(tar -xzOf "$dist/$t-$v.tgz" package/package.json)
	printf '%s' "$m" | grep -q '"file:' && fail "$t-$v.tgz: file: dependency in the packed manifest"
	printf '%s' "$m" | grep -q '"private": *true' && fail "$t-$v.tgz: private"
	tar -tzf "$dist/$t-$v.tgz" | grep -qx 'package/LICENSE' || fail "$t-$v.tgz: no LICENSE"
done
ok "packed manifests: no file: dependency, none private, LICENSE in each"

# 1. A consumer with nothing but the tarballs.
c=$work/consumer
case $c in "$root"/*) fail "the consumer directory $c is inside the repository" ;; esac
mkdir -p "$c" "$work/home"
export HOME=$work/home npm_config_cache=$work/npm-cache npm_config_update_notifier=false
unset SIGELO_IDENTITY SIGELO_WALLET_URL SIGELO_WALLET_TOKEN SIGELO_WALLET_CONFIG 2>/dev/null || true
cd "$c"
printf '{ "name": "consumer", "private": true, "type": "module" }\n' > package.json
retry npm install --no-audit --no-fund --silent \
	"$dist/sigelo-$v.tgz" "$dist/sigelo-spend-$v.tgz" "$dist/sigelo-agent-$v.tgz" "$dist/sigelo-mcp-$v.tgz" "$dist/sigelo-recovery-kit-$v.tgz" \
	> "$work/install.log" 2>&1 || { cat "$work/install.log" >&2; fail "npm install of the five tarballs"; }
for p in sigelo sigelo-spend sigelo-agent sigelo-mcp sigelo-recovery-kit; do
	[ -L "node_modules/$p" ] && fail "node_modules/$p is a link, not an install"
	[ -f "node_modules/$p/package.json" ] || fail "node_modules/$p missing"
done
# one sigelo, the tarball's, shared by all three dependents (no nested copy from a registry)
[ -z "$(find node_modules -mindepth 3 -path '*/node_modules/sigelo/package.json')" ] || fail "a nested second copy of sigelo"
ok "npm install of the five tarballs in $c (one shared sigelo $v)"

# 2a. sigelo-agent
out=$(npx sigelo-agent init 2>&1) && fail "init without a recovery choice succeeded"
printf '%s' "$out" | grep -q -- '--no-recovery' || fail "npx sigelo-agent init: unclear refusal: $out"
ok "npx sigelo-agent init: refuses without a recovery choice, names --no-recovery"
out=$(npx sigelo-agent init --no-recovery 2>/dev/null) || fail "npx sigelo-agent init --no-recovery"
d=$(printf '%s' "$out" | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>console.log(JSON.parse(s).did))')
case $d in did:sigelo:*) ;; *) fail "init printed no did: $out" ;; esac
[ -f "$HOME/.config/moadim/sigelo.local.json" ] || fail "no identity at \$HOME/.config/moadim/sigelo.local.json"
npx sigelo-agent whoami 2>/dev/null | grep -q "$d" || fail "npx sigelo-agent whoami"
ok "npx sigelo-agent init --no-recovery → $d; whoami agrees"
npx sigelo-agent bundle > "$work/bundle.json" 2>/dev/null || fail "npx sigelo-agent bundle"
ok "npx sigelo-agent bundle"

# 2b. sigelo-wallet: no keeper configured is a plain refusal, not a stack trace
set +e; out=$(npx -p sigelo-spend sigelo-wallet balance 2>&1); rc=$?; set -e
[ $rc -ne 0 ] || fail "sigelo-wallet balance without a keeper exited 0: $out"
printf '%s' "$out" | grep -q 'at .*\.js:[0-9]' && fail "sigelo-wallet balance: stack trace: $out"
ok "npx -p sigelo-spend sigelo-wallet balance (no keeper) → exit $rc: $(printf '%s' "$out" | head -1 | cut -c1-90)"
set +e; out=$(npx -p sigelo-spend sigelo-wallet --help 2>&1); set -e
printf '%s' "$out" | grep -q 'balance' || fail "sigelo-wallet --help does not name the verbs: $out"
ok "npx -p sigelo-spend sigelo-wallet --help names the verbs"
set +e; out=$(npx -p sigelo-spend sigelo-spend 2>&1); set -e
printf '%s' "$out" | grep -qi 'usage\|serve\|policy' || fail "sigelo-spend: $out"
ok "npx -p sigelo-spend sigelo-spend starts (prints its usage)"

# 2b'. the installer, from the same package: init a keeper over a wallet-rpc that is not there
#      (--no-systemd: unit files only), doctor says the install is valid and the wallet
#      unreachable (exit 2), licence show says free, and the frozen copy init made runs alone.
kd=$work/keeper
out=$(npx -p sigelo-spend sigelo-spend init --dir "$kd" --no-systemd --wallet-rpc http://127.0.0.1:1 2>&1) || fail "sigelo-spend init: $out"
printf '%s' "$out" | grep -q '^  keeper DID    did:sigelo:' || fail "sigelo-spend init printed no keeper DID: $out"
printf '%s' "$out" | grep -qx 'You have a Monero wallet. Use only the `sigelo-wallet` command. You never see or need keys.' || fail "sigelo-spend init printed no agent snippet: $out"
for f in policy.json spend.key agent.token install.json systemd/sigelo-keeper-keeper.service app/node_modules/sigelo-spend/dist/cli.js app/node_modules/sigelo/dist/sigelo.js; do
	[ -f "$kd/$f" ] || fail "sigelo-spend init wrote no $f"
done
[ -e "$HOME/.config/systemd" ] && fail "sigelo-spend init --no-systemd wrote under \$HOME/.config/systemd"
ok "npx -p sigelo-spend sigelo-spend init --dir … --no-systemd --wallet-rpc http://127.0.0.1:1 (policy, key, token, unit, frozen copy)"
set +e; out=$(npx -p sigelo-spend sigelo-spend doctor --dir "$kd" 2>&1); rc=$?; set -e
[ $rc -eq 2 ] || fail "sigelo-spend doctor exited $rc, not 2 (valid, with warnings): $out"
printf '%s' "$out" | grep -q '^WARN wallet-rpc unreachable' || fail "sigelo-spend doctor did not report the wallet-rpc unreachable: $out"
printf '%s' "$out" | grep -q '^FAIL' && fail "sigelo-spend doctor found the install invalid: $out"
printf '%s' "$out" | tail -1 | grep -q '^INSTALL VALID' || fail "sigelo-spend doctor: $out"
ok "sigelo-spend doctor: the install is valid, the wallet-rpc unreachable (exit 2)"
out=$(npx -p sigelo-spend sigelo-spend licence show --dir "$kd" 2>&1) || fail "sigelo-spend licence show: $out"
printf '%s' "$out" | grep -q '^tier free (no licence.json)' || fail "sigelo-spend licence show does not say free: $out"
out=$(cd / && node "$kd/app/node_modules/sigelo-spend/dist/cli.js" licence show --dir "$kd" 2>&1) || fail "the frozen copy does not run: $out"
printf '%s' "$out" | grep -q '^tier free' || fail "the frozen copy: $out"
ok "sigelo-spend licence show: tier free; the frozen copy the unit runs answers the same from /"

# 2c. sigelo-mcp over stdio: the handshake, the tool list, the identity from 2a, and a wallet verb
#     that must reach the installed sigelo-spend, whose client answers TRY LATER "unreachable" for
#     the dead keeper URL (an import failure would be an error, not that code).
req='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"pack-test","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sigelo_whoami","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sigelo_wallet_balance","arguments":{}}}'
out=$(printf '%s\n' "$req" | SIGELO_WALLET_URL=http://127.0.0.1:9 SIGELO_WALLET_TOKEN=x npx sigelo-mcp 2>"$work/mcp.err") || { cat "$work/mcp.err" >&2; fail "npx sigelo-mcp"; }
printf '%s' "$out" | node -e '
let s = ""; process.stdin.on("data", c => s += c).on("end", () => {
  const r = Object.fromEntries(s.trim().split("\n").map(l => JSON.parse(l)).map(m => [m.id, m]));
  const need = (c, m) => { if (!c) { console.error(m); process.exit(1); } };
  need(r[1]?.result?.serverInfo?.name === "sigelo", "initialize: " + JSON.stringify(r[1]));
  const names = (r[2]?.result?.tools ?? []).map(t => t.name);
  need(names.includes("sigelo_whoami") && names.includes("sigelo_wallet_balance"), "tools/list: " + names);
  need(JSON.stringify(r[3]?.result ?? {}).includes(process.argv[1]), "whoami: " + JSON.stringify(r[3]));
  const w = JSON.stringify(r[4] ?? {});
  need(r[4]?.result?.structuredContent?.code === "unreachable", "wallet_balance: " + w);   // sigelo-spend ran
  console.log(names.length);
});' "$d" > "$work/mcp.n" || { cat "$work/mcp.err" >&2; fail "sigelo-mcp stdio smoke (above)"; }
ok "npx sigelo-mcp (stdio): initialize, $(cat "$work/mcp.n") tools, whoami = $d, wallet verb → TRY LATER unreachable (dead keeper)"

# 2d. sigelo (the library and sigelo-offline)
npx sigelo-offline new 2>/dev/null | grep -qE "^mnemonic +([a-z]+ ){24}[a-z]+\$" || fail "npx sigelo-offline new: no 25 words"
ok "npx sigelo-offline new prints a 25-word root"
node --input-type=module -e '
import { keygen, did, verify } from "sigelo";
import { readFileSync } from "node:fs";
const r = verify(JSON.parse(readFileSync(process.argv[1], "utf8")), Math.floor(Date.now() / 1000));
if (r.did !== process.argv[2]) { console.error(JSON.stringify(r)); process.exit(1); }
const g = keygen({ recovery: "sha256:" + "0".repeat(64) });
if (did(g.genesis) !== g.did || !g.did.startsWith("did:sigelo:")) process.exit(1);' "$work/bundle.json" "$d" 2>"$work/lib.err" \
	|| { cat "$work/lib.err" >&2; fail "import from 'sigelo': verify the agent's bundle"; }
ok "import { verify } from 'sigelo': the agent's bundle verifies to $d"

# 2e. sigelo-recovery-kit: its own checks, run from the installed copy (scratch directories only;
#     the real-age ceremony part SKIPs where age, age-keygen or util-linux script are missing)
(cd "$c" && sh node_modules/sigelo-recovery-kit/test/run.sh) > "$work/kit.log" 2>&1 || { cat "$work/kit.log" >&2; fail "sigelo-recovery-kit test/run.sh from the installed copy"; }
tail -1 "$work/kit.log" | grep -q 'ALL PASS' || { cat "$work/kit.log" >&2; fail "sigelo-recovery-kit test/run.sh: no ALL PASS"; }
ok "sigelo-recovery-kit: test/run.sh from the installed copy → $(grep -c '^ok' "$work/kit.log") ok, $(grep -c '^SKIP' "$work/kit.log") skipped"

# 3. Go
mkdir -p "$work/go"
tar -xzf "$dist/sigelo-verify-src-$v.tar.gz" -C "$work/go"
src=$work/go/sigelo-verify-src-$v
(cd "$src/go" && CGO_ENABLED=0 GOFLAGS=-mod=readonly retry go build -o "$work/sigelo-verify" ./cmd/sigelo-verify) > "$work/go.log" 2>&1 \
	|| { cat "$work/go.log" >&2; fail "go build ./cmd/sigelo-verify from sigelo-verify-src-$v.tar.gz"; }
ok "go build ./cmd/sigelo-verify from sigelo-verify-src-$v.tar.gz"
"$work/sigelo-verify" --conformance "$src/test-vectors.json" > "$work/conf.log" 2>&1 || { tail -20 "$work/conf.log" >&2; fail "built sigelo-verify --conformance"; }
ok "built sigelo-verify --conformance: $(tail -1 "$work/conf.log")"
bin=$dist/sigelo-verify-$os-$arch; [ "$os" = windows ] && bin=$bin.exe
if [ -f "$bin" ]; then
	"$bin" --conformance "$dist/test-vectors.json" > "$work/conf2.log" 2>&1 || { tail -20 "$work/conf2.log" >&2; fail "$(basename "$bin") --conformance"; }
	ok "prebuilt $(basename "$bin") --conformance: $(tail -1 "$work/conf2.log")"
	"$bin" "$work/bundle.json" > "$work/verify.log" 2>&1 || { cat "$work/verify.log" >&2; fail "$(basename "$bin") on the agent's bundle"; }
	grep -q "$d" "$work/verify.log" || fail "$(basename "$bin"): bundle verified to another DID: $(cat "$work/verify.log")"
	ok "prebuilt $(basename "$bin") verifies the npm-installed agent's bundle → $d"
else
	echo "skip no prebuilt binary for $os/$arch"
fi

echo "ALL PASS ($n checks)"
