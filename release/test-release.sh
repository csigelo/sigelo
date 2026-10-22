#!/bin/sh
# SPDX-License-Identifier: MIT
# Tests the release signing scripts with test keys, offline: sign-release.sh (with and without
# --apk), verify-release.sh (a directory and a URL), apk-check.sh, and site/deploy/mirror-release.sh
# --dry-run (a fake gh). A scratch repository holds copies of the scripts, ts/ linked in; a test SSH
# key signs its tag, a test identity is the release identity, a fake apksigner prints a certificate.
#
#   sh release/test-release.sh        → ALL PASS (n checks)
#
# Needs git, ssh-keygen, node, tar, sha256sum and a built ts/ (cd ts && npm ci && npx tsc).
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$src/ts/dist/sigelo.js" ] || { echo "build the library first: (cd ts && npm ci && npx tsc)" >&2; exit 1; }
T=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-release-test.XXXXXX")
srv=
trap 'rm -rf "$T"; [ -z "$srv" ] || kill "$srv" 2>/dev/null || true' EXIT INT TERM
n=0 bad=0
ok() { n=$((n + 1)); echo "ok   $1"; }
no() { n=$((n + 1)); bad=$((bad + 1)); echo "FAIL $1"; [ ! -s "$T/out" ] || sed 's/^/     /' "$T/out" | head -5; }
pass() { d=$1; shift; if "$@" >"$T/out" 2>&1; then ok "$d"; else no "$d"; fi; }
refuse() { d=$1; pat=$2; shift 2; if "$@" >"$T/out" 2>&1; then no "$d (accepted)"; elif grep -q -- "$pat" "$T/out"; then ok "$d"; else no "$d (not: $pat)"; fi; }

R=$T/repo
mkdir -p "$R/release" "$R/site/deploy" "$T/bin"
cp "$src/release/sign-release.sh" "$src/release/verify-release.sh" "$src/release/apk-check.sh" "$R/release/"
cp "$src/site/deploy/mirror-release.sh" "$R/site/deploy/"
ln -s "$src/ts" "$R/ts"
ssh-keygen -q -t ed25519 -N '' -C test -f "$T/tagkey"
echo "test@example.invalid namespaces=\"git\" $(cat "$T/tagkey.pub")" >"$T/allowed_signers"
G="git -C $R -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false -c gpg.format=ssh -c user.signingkey=$T/tagkey"
$G init -q
echo x >"$R/README"
$G add README && $G commit -q -m test
$G tag -s v9.9.9 -m v9.9.9
$G tag -s v9.9.8 -m v9.9.8

# The release identity and a stranger, both test keys.
node --input-type=module - "$src" "$T" <<'EOF'
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const [src, T] = process.argv.slice(2);
const { keygen } = await import(pathToFileURL(`${src}/ts/dist/sigelo.js`).href);
for (const name of ['rel', 'other']) {
  const rec = keygen({ recovery: new Uint8Array(32).fill(7) });
  const id = keygen({ recovery: rec.genesis.key });
  writeFileSync(`${T}/${name}.json`, JSON.stringify({ genesis: id.genesis, rotations: [], secret: Buffer.from(id.secret).toString('hex') }));
  writeFileSync(`${T}/${name}-genesis.json`, JSON.stringify(id.genesis));
}
// "Any zip": an empty one.
writeFileSync(`${T}/app.apk`, Buffer.from([0x50, 0x4b, 5, 6, ...new Array(18).fill(0)]));
EOF
export SIGELO_RELEASE_IDENTITY=$T/rel.json SIGELO_RELEASE_GENESIS=$T/rel-genesis.json SIGELO_ALLOWED_SIGNERS=$T/allowed_signers
export SIGELO_VERIFY= SIGELO_APKSIGNER=$T/bin/apksigner
CERT=$(printf 'cert' | sha256sum | cut -d' ' -f1)
OTHER=$(printf 'other' | sha256sum | cut -d' ' -f1)
# apksigner verify --print-certs <apk>: FAKE_CERT's digest(s); FAKE_UNSIGNED=1 fails as on an unsigned APK.
cat >"$T/bin/apksigner" <<'EOF'
#!/bin/sh
[ "$1 $2" = "verify --print-certs" ] && [ -f "$3" ] || { echo "fake apksigner: usage" >&2; exit 2; }
[ "${FAKE_UNSIGNED:-}" != 1 ] || { echo "DOES NOT VERIFY" >&2; exit 1; }
i=0; for c in $FAKE_CERT; do i=$((i + 1)); echo "Signer #$i certificate DN: CN=test"; echo "Signer #$i certificate SHA-256 digest: $c"; done
EOF
chmod +x "$T/bin/apksigner"
export FAKE_CERT=$CERT

mkdir "$T/a" "$T/b"
for d in a b; do
  echo one >"$T/$d/one.tgz"; echo two >"$T/$d/two.txt"
  (cd "$T/$d" && sha256sum one.tgz two.txt >SHA256SUMS)
done
cp "$T/app.apk" "$T/a/sigelo-9.9.9.apk"

# sign-release.sh
refuse 'sign: --apk outside the artefact dir' 'copy the signed APK' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" --apk "$T/app.apk" "$CERT"
refuse 'sign: --apk cert not 64 hex' '64 hex' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" --apk "$T/a/sigelo-9.9.9.apk" abc
refuse 'sign: another certificate' 'not '"$OTHER" sh "$R/release/sign-release.sh" v9.9.9 "$T/a" --apk "$T/a/sigelo-9.9.9.apk" "$OTHER"
refuse 'sign: two signers' 'signed by certificate' env FAKE_CERT="$CERT $OTHER" sh "$R/release/sign-release.sh" v9.9.9 "$T/a" --apk "$T/a/sigelo-9.9.9.apk" "$CERT"
refuse 'sign: an unsigned APK' 'apksigner verify refuses' env FAKE_UNSIGNED=1 sh "$R/release/sign-release.sh" v9.9.9 "$T/a" --apk "$T/a/sigelo-9.9.9.apk" "$CERT"
refuse 'sign: an APK not named in --apk' 'not in SHA256SUMS: sigelo-9.9.9.apk' sh "$R/release/sign-release.sh" v9.9.9 "$T/a"
COLONS=$(echo "$CERT" | tr a-f A-F | sed 's/../&:/g; s/:$//')
pass 'sign: --apk, the certificate as keytool prints it' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" --apk "$T/a/sigelo-9.9.9.apk" "$COLONS"
pass 'sign: release.json holds apk {file, sha256, cert_sha256, version}' node -e '
  const [f, cert, sha] = process.argv.slice(1); const c = JSON.parse(require("fs").readFileSync(f, "utf8")).attestations[0].body.claims;
  const a = c.apk; if (!(a.file === "sigelo-9.9.9.apk" && a.cert_sha256 === cert && a.sha256 === sha && a.version === "9.9.9" && !("sigelo-9.9.9.apk" in c.files))) process.exit(1)' \
  "$T/a/release.json" "$CERT" "$(sha256sum "$T/app.apk" | cut -d' ' -f1)"
pass 'sign: without --apk (as before)' sh "$R/release/sign-release.sh" v9.9.8 "$T/b"

# verify-release.sh
pass 'verify: the release with its APK' sh "$R/release/verify-release.sh" v9.9.9 "$T/a"
grep -q 'sigelo-9.9.9.apk 9.9.9 matches, certificate matches' "$T/out" && ok 'verify: says the APK and certificate match' || no 'verify: says the APK and certificate match'
pass 'verify: a release without an APK' sh "$R/release/verify-release.sh" v9.9.8 "$T/b"
refuse 'verify: the APK signed by another certificate' 'not the release' env FAKE_CERT="$OTHER" sh "$R/release/verify-release.sh" v9.9.9 "$T/a"
cp -r "$T/a" "$T/a2"; printf 'x' >>"$T/a2/sigelo-9.9.9.apk"
refuse 'verify: a changed APK' 'is not the signed' sh "$R/release/verify-release.sh" v9.9.9 "$T/a2"
rm "$T/a2/sigelo-9.9.9.apk"
refuse 'verify: the APK missing' 'sigelo-9.9.9.apk: missing' sh "$R/release/verify-release.sh" v9.9.9 "$T/a2"
refuse 'verify: release.json for another tag' 'signs tag v9.9.9' sh "$R/release/verify-release.sh" v9.9.8 "$T/a"

# verify-release.sh from a URL: the APK is downloaded as release.json names it.
port=$(node -e 's=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')
node -e 'const [d, p] = process.argv.slice(1), fs = require("fs");
  require("http").createServer((q, r) => { const f = d + "/" + decodeURIComponent(q.url.split("/").pop());
    if (fs.existsSync(f)) { r.end(fs.readFileSync(f)); } else { r.statusCode = 404; r.end(); } }).listen(+p, "127.0.0.1")' "$T/a" "$port" &
srv=$!
i=0; until node -e 'fetch(process.argv[1]).then((r)=>process.exit(r.ok?0:1),()=>process.exit(1))' "http://127.0.0.1:$port/SHA256SUMS" 2>/dev/null; do i=$((i + 1)); [ $i -lt 50 ] || break; node -e 'setTimeout(()=>{},100)'; done
pass 'verify: from a URL, the APK fetched' sh "$R/release/verify-release.sh" v9.9.9 "http://127.0.0.1:$port"
grep -q 'sigelo-9.9.9.apk 9.9.9 matches, certificate matches' "$T/out" && ok 'verify: from a URL, the APK checked' || no 'verify: from a URL, the APK checked'
kill "$srv" 2>/dev/null || true; srv=

# apk-check.sh
pass 'apk-check: the released APK' sh "$R/release/apk-check.sh" "$T/app.apk" "$T/a/release.json"
refuse 'apk-check: another certificate' 'not the release' env FAKE_CERT="$OTHER" sh "$R/release/apk-check.sh" "$T/app.apk" "$T/a/release.json"
refuse 'apk-check: no signature' 'apksigner verify refuses' env FAKE_UNSIGNED=1 sh "$R/release/apk-check.sh" "$T/app.apk" "$T/a/release.json"
printf 'y' >"$T/evil.apk"
refuse 'apk-check: another file' 'is not v9.9.9' sh "$R/release/apk-check.sh" "$T/evil.apk" "$T/a/release.json"
refuse 'apk-check: a release without an APK' 'names no APK' sh "$R/release/apk-check.sh" "$T/app.apk" "$T/b/release.json"
node -e 'const fs=require("fs"),[f,o,s]=process.argv.slice(1),b=JSON.parse(fs.readFileSync(f,"utf8"));b.attestations[0].body.claims.apk.sha256=s;fs.writeFileSync(o,JSON.stringify(b))' "$T/a/release.json" "$T/forged.json" "$(sha256sum "$T/evil.apk" | cut -d' ' -f1)"
refuse 'apk-check: a claim changed after signing' 'release.json: a rejected' sh "$R/release/apk-check.sh" "$T/evil.apk" "$T/forged.json"
refuse 'apk-check: signed by another identity' 'not the pinned release identity' env SIGELO_RELEASE_IDENTITY="$T/other.json" SIGELO_RELEASE_GENESIS="$T/other-genesis.json" sh -c '
  mkdir "$1/c" && cp "$1/a/one.tgz" "$1/a/two.txt" "$1/a/SHA256SUMS" "$1/a/sigelo-9.9.9.apk" "$1/c/" &&
  sh "$2/release/sign-release.sh" v9.9.9 "$1/c" --apk "$1/c/sigelo-9.9.9.apk" "$3" >/dev/null &&
  SIGELO_RELEASE_GENESIS="$1/rel-genesis.json" sh "$2/release/apk-check.sh" "$1/app.apk" "$1/c/release.json"' - "$T" "$R" "$CERT"
refuse 'apk-check: no apksigner' 'apksigner not found' env SIGELO_APKSIGNER= PATH=/nonexistent:/usr/bin:/bin sh -c 'command -v apksigner >/dev/null && echo "apksigner not found (skipped: one is installed)" >&2 && exit 1; sh "$1" "$2" "$3"' - "$R/release/apk-check.sh" "$T/app.apk" "$T/a/release.json"

# mirror-release.sh --dry-run over a fake gh: the APK release.json names is accepted, others not.
cat >"$T/bin/gh" <<'EOF'
#!/bin/sh
# gh release download <tag> --repo <r> -D <dir>: copies $FAKE_RELEASE.
[ "$1 $2" = "release download" ] || exit 2
cp "$FAKE_RELEASE"/* "$7/"
EOF
chmod +x "$T/bin/gh"
for c in ssh tar sha256sum node; do command -v $c >/dev/null || { echo "missing $c" >&2; exit 1; }; done
pass 'mirror: a release with its APK (dry run)' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/a" sh "$R/site/deploy/mirror-release.sh" v9.9.9 --dry-run
grep -q 'sigelo-9.9.9.apk: sha256 as release.json signs it' "$T/out" && ok 'mirror: names the APK' || no 'mirror: names the APK'
cp -r "$T/a" "$T/a3"; printf 'x' >>"$T/a3/sigelo-9.9.9.apk"
refuse 'mirror: a changed APK' 'does not match' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/a3" sh "$R/site/deploy/mirror-release.sh" v9.9.9 --dry-run
cp "$T/a/sigelo-9.9.9.apk" "$T/a3/sigelo-9.9.9.apk"; cp "$T/app.apk" "$T/a3/stray.apk"
refuse 'mirror: an APK release.json does not name' 'differ' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/a3" sh "$R/site/deploy/mirror-release.sh" v9.9.9 --dry-run
pass 'mirror: a release without an APK (dry run)' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/b" sh "$R/site/deploy/mirror-release.sh" v9.9.8 --dry-run

[ "$bad" = 0 ] && echo "ALL PASS ($n checks)" || { echo "$bad FAILED ($n checks)"; exit 1; }
