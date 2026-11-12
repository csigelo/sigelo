#!/bin/sh
# SPDX-License-Identifier: MIT
# Tests the release signing scripts with test keys, offline: sign-release.sh (with and without
# --apk), verify-release.sh (a directory and a URL; checks 1-8, --strict, --offline, --pre,
# --dry-run), apk-check.sh, and site/deploy/mirror-release.sh --dry-run. A scratch repository holds
# copies of the scripts, ts/ linked in; a test SSH key signs its tags, a test identity is the
# release identity. Fakes on PATH: apksigner prints a certificate; gh downloads a "draft" from a
# directory and checks `attestation verify` against a fake provenance bundle (the file's sha256
# among its subjects, the source ref and workflow as asked); cosign checks `verify-blob` likewise.
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
// An unsigned "APK": entries, a central directory at 16, its end record; app.apk is it signed:
// the same first 16 bytes, a signing block, the directory moved behind it. unsigned2.apk: the
// same entries, another directory (another build, same prefix).
const eocd = (cd) => { const b = Buffer.alloc(22); b.writeUInt32LE(0x06054b50, 0); b.writeUInt32LE(cd, 16); return b; };
const entries = Buffer.from('PK\x03\x04entries-here'), dirent = Buffer.from('PK\x01\x02dir');
writeFileSync(`${T}/unsigned.apk`, Buffer.concat([entries, dirent, eocd(16)]));
writeFileSync(`${T}/unsigned2.apk`, Buffer.concat([entries, Buffer.from('PK\x01\x02other'), eocd(16)]));
writeFileSync(`${T}/app.apk`, Buffer.concat([entries, Buffer.from('APK Sig Block 42'), dirent, eocd(32)]));
writeFileSync(`${T}/evil-unsigned.apk`, Buffer.concat([Buffer.from('PK\x03\x04entries-HERE'), dirent, eocd(16)]));
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

# gh: `release download <tag> (--repo|-R) <r> [-p <name>] -D <dir>` copies $FAKE_RELEASE (all, or
# <name>); `attestation verify <file> ... --bundle <b>` passes when sha256(<file>) is a subject of
# a line of <b> made for that --source-ref, and -R, --signer-workflow are the release's.
# cosign: `verify-blob <file> --bundle <b> --certificate-identity <i> --certificate-oidc-issuer <o>`
# passes when <b> names sha256(<file>) and <i>. Both log their arguments to $FAKE_LOG.
cat >"$T/bin/gh" <<'EOF'
#!/usr/bin/env node
const fs = require('fs'), sha = (f) => require('crypto').createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const a = process.argv.slice(2), opt = (k) => { const i = a.indexOf(k); return i < 0 ? undefined : a[i + 1]; };
if (process.env.FAKE_LOG) fs.appendFileSync(process.env.FAKE_LOG, `gh ${a.join(' ')}\n`);
const die = (m) => { console.error(m); process.exit(1); };
if (a[0] === 'release' && a[1] === 'download') {
  const src = process.env.FAKE_RELEASE, d = opt('-D'), p = opt('-p');
  for (const f of p ? [p] : fs.readdirSync(src)) { if (!fs.existsSync(`${src}/${f}`)) die(`no asset ${f}`); fs.copyFileSync(`${src}/${f}`, `${d}/${f}`); }
} else if (a[0] === 'attestation' && a[1] === 'verify') {
  const f = a[2], b = opt('--bundle'), root = opt('--custom-trusted-root');
  if (opt('-R') !== 'csigelo/sigelo' || opt('--signer-workflow') !== 'csigelo/sigelo/.github/workflows/release.yml' || !a.includes('--deny-self-hosted-runners')) die('fake gh: wrong repository or workflow');
  if (root !== undefined && !fs.existsSync(root)) die('fake gh: no trusted root');
  const h = sha(f), ok = fs.readFileSync(b, 'utf8').split('\n').filter(Boolean).some((l) => { const j = JSON.parse(l);
    const st = JSON.parse(Buffer.from(j.dsseEnvelope.payload, 'base64').toString());
    return j.fake_ref === opt('--source-ref') && st.subject.some((s) => s.digest.sha256 === h); });
  if (!ok) die(`Error: verifying with issuer "sigstore.dev": no attestation matches ${f}`);
  console.log(`Loaded 1 attestation from ${b}`);
} else die(`fake gh: ${a.join(' ')}`);
EOF
cat >"$T/bin/cosign" <<'EOF'
#!/usr/bin/env node
const fs = require('fs'), a = process.argv.slice(2), opt = (k) => { const i = a.indexOf(k); return i < 0 ? undefined : a[i + 1]; };
if (process.env.FAKE_LOG) fs.appendFileSync(process.env.FAKE_LOG, `cosign ${a.join(' ')}\n`);
const b = JSON.parse(fs.readFileSync(opt('--bundle'), 'utf8')), h = require('crypto').createHash('sha256').update(fs.readFileSync(a[1])).digest('hex');
if (a[0] !== 'verify-blob' || opt('--certificate-oidc-issuer') !== 'https://token.actions.githubusercontent.com') { console.error('fake cosign: usage'); process.exit(2); }
if (b.sha256 !== h || b.identity !== opt('--certificate-identity')) { console.error('Error: none of the expected identities matched'); process.exit(1); }
console.log('Verified OK');
EOF
chmod +x "$T/bin/gh" "$T/bin/cosign"
export SIGELO_GH=$T/bin/gh SIGELO_COSIGN=$T/bin/cosign FAKE_LOG=$T/log
# proofs <dir> <tag> [<omit>]: CI's two proof files for <dir>'s SHA256SUMS, its files and the
# unsigned APK; <omit> left out of the provenance.
proofs() {
  node -e 'const fs = require("fs"), c = require("crypto"), [d, tag, apk, omit] = process.argv.slice(1);
    const sha = (f) => c.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
    const names = fs.readFileSync(`${d}/SHA256SUMS`, "utf8").trim().split("\n").map((l) => l.slice(66));
    const subject = [...names.map((n) => [n, `${d}/${n}`]), ["SHA256SUMS", `${d}/SHA256SUMS`], ["unsigned.apk", apk]]
      .filter(([n]) => n !== omit).map(([name, f]) => ({ name, digest: { sha256: sha(f) } }));
    const payload = Buffer.from(JSON.stringify({ _type: "https://in-toto.io/Statement/v1", subject })).toString("base64");
    fs.writeFileSync(`${d}/sigelo-${tag.slice(1)}.intoto.jsonl`, JSON.stringify({ dsseEnvelope: { payload }, fake_ref: `refs/tags/${tag}` }) + "\n");
    fs.writeFileSync(`${d}/SHA256SUMS.sigstore.json`, JSON.stringify({ sha256: sha(`${d}/SHA256SUMS`),
      identity: `https://github.com/csigelo/sigelo/.github/workflows/release.yml@refs/tags/${tag}` }));' "$1" "$2" "$T/unsigned.apk" "${3:-}"
}

mkdir "$T/a" "$T/b"
echo '{"bomFormat":"CycloneDX"}' >"$T/a/sigelo-9.9.9.cdx.json"
echo one >"$T/a/one.tgz"; echo two >"$T/a/two.txt"
(cd "$T/a" && sha256sum one.tgz sigelo-9.9.9.cdx.json two.txt >SHA256SUMS)
cp "$T/a/one.tgz" "$T/a/two.txt" "$T/b/"
(cd "$T/b" && sha256sum one.tgz two.txt >SHA256SUMS)
cp "$T/app.apk" "$T/a/sigelo-9.9.9.apk"
# v9.9.9 is a v2 tag (its last line the digest of SHA256SUMS), v9.9.8 an older one.
$G tag -s v9.9.9 -m "v9.9.9

sha256sums: $(sha256sum "$T/a/SHA256SUMS" | cut -d' ' -f1)"
$G tag -s v9.9.8 -m v9.9.8
proofs "$T/a" v9.9.9
mkdir "$T/draft" "$T/draft2"; cp "$T/a/SHA256SUMS" "$T/draft/"
sed '1s/  / */' "$T/a/SHA256SUMS" >"$T/draft2/SHA256SUMS"
export FAKE_RELEASE=$T/draft
SA="--apk $T/a/sigelo-9.9.9.apk"

# sign-release.sh
U="--unsigned $T/unsigned.apk"
refuse 'sign: --apk outside the artefact dir' 'copy the signed APK' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" --apk "$T/app.apk" "$CERT" $U
refuse 'sign: --apk cert not 64 hex' '64 hex' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA abc $U
refuse 'sign: --apk without --unsigned' 'usage' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$CERT"
refuse 'sign: another certificate' 'not '"$OTHER" sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$OTHER" $U
refuse 'sign: two signers' 'signed by certificate' env FAKE_CERT="$CERT $OTHER" sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$CERT" $U
refuse 'sign: an unsigned APK' 'apksigner verify refuses' env FAKE_UNSIGNED=1 sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$CERT" $U
refuse 'sign: an APK not named in --apk' 'not in SHA256SUMS: sigelo-9.9.9.apk' sh "$R/release/sign-release.sh" v9.9.9 "$T/a"
refuse 'sign: the signed APK is not that unsigned build' 'does not begin with' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$CERT" --unsigned "$T/evil-unsigned.apk"
refuse 'sign: SHA256SUMS differs from the draft' 'differs from the draft' env FAKE_RELEASE="$T/draft2" sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$CERT" $U
refuse 'sign: no draft release' 'no SHA256SUMS on the draft' env FAKE_RELEASE="$T/b/none" sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$CERT" $U
refuse 'sign: no gh' 'gh not found' env SIGELO_GH= sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$CERT" $U
printf 'x' >"$T/a/stray.txt"
refuse 'sign: a stray file beside the proofs' 'not in SHA256SUMS: stray.txt' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$CERT" $U
rm "$T/a/stray.txt"
COLONS=$(echo "$CERT" | tr a-f A-F | sed 's/../&:/g; s/:$//')
pass 'sign: --apk, the proofs beside it, the certificate as keytool prints it' sh "$R/release/sign-release.sh" v9.9.9 "$T/a" $SA "$COLONS" $U
pass 'sign: release.json holds apk {file, sha256, cert_sha256, version, unsigned_sha256}' node -e '
  const [f, cert, sha, u] = process.argv.slice(1); const c = JSON.parse(require("fs").readFileSync(f, "utf8")).attestations[0].body.claims;
  const a = c.apk; if (!(a.file === "sigelo-9.9.9.apk" && a.cert_sha256 === cert && a.sha256 === sha && a.version === "9.9.9" && a.unsigned_sha256 === u && !("sigelo-9.9.9.apk" in c.files))) process.exit(1)' \
  "$T/a/release.json" "$CERT" "$(sha256sum "$T/app.apk" | cut -d' ' -f1)" "$(sha256sum "$T/unsigned.apk" | cut -d' ' -f1)"
pass 'sign: without --apk (as before)' env FAKE_RELEASE="$T/b" sh "$R/release/sign-release.sh" v9.9.8 "$T/b"

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

# verify-release.sh checks 5-8.
has() { d=$1; shift; if grep -q -- "$1" "$T/out" && { [ $# -lt 2 ] || grep -q -- "$2" "$T/out"; }; then ok "$d"; else no "$d"; fi; }
pass 'verify: 1-8 all pass' sh "$R/release/verify-release.sh" v9.9.9 "$T/a"
has 'verify: says 5 and 6 OK' 'ok   5 the tag names this SHA256SUMS' 'ok   6 provenance: 4 files'
has 'verify: says 7 and 8 OK' 'ok   7 cosign' 'ok   8 the unsigned APK'
pass 'verify --strict: nothing left unchecked' sh "$R/release/verify-release.sh" --strict v9.9.9 "$T/a"
printf '%s\n' '{"tlogs":[{"baseUrl":"https://rekor.sigstore.dev"}]}' '{"tlogs":[]}' >"$T/trusted-root.jsonl"
: >"$T/log"
pass 'verify --offline: with the saved trusted root' env SIGELO_TRUSTED_ROOT="$T/trusted-root.jsonl" sh "$R/release/verify-release.sh" --offline --strict v9.9.9 "$T/a"
grep -q -- "--custom-trusted-root $T/trusted-root.jsonl" "$T/log" && grep -q -- '--trusted-root .*public-good.json --offline' "$T/log" &&
  ok 'verify --offline: gh and cosign get the saved roots' || no 'verify --offline: gh and cosign get the saved roots'
refuse 'verify --offline: no trusted root' 'no /nonexistent' env SIGELO_TRUSTED_ROOT=/nonexistent sh "$R/release/verify-release.sh" --offline v9.9.9 "$T/a"
mkdir "$T/t1"; cp "$T/a/one.tgz" "$T/a/two.txt" "$T/a/sigelo-9.9.9.cdx.json" "$T/a/sigelo-9.9.9.intoto.jsonl" "$T/a/SHA256SUMS.sigstore.json" "$T/t1/"
sed '1s/  / */' "$T/a/SHA256SUMS" >"$T/t1/SHA256SUMS"
refuse 'verify: a changed byte in SHA256SUMS' 'checks 5, 6, 7 failed' sh "$R/release/verify-release.sh" --pre v9.9.9 "$T/t1"
has 'verify: ... fails the tag digest and cosign' 'FAIL 5 the tag names SHA256SUMS' 'FAIL 7 cosign refuses'
cp -r "$T/a" "$T/t2"; proofs "$T/t2" v9.9.9 two.txt
refuse 'verify: a file the provenance does not name' 'FAIL 6 no provenance from release.yml at v9.9.9: two.txt' sh "$R/release/verify-release.sh" v9.9.9 "$T/t2"
cp -r "$T/a" "$T/t3"; proofs "$T/t3" v9.9.8; mv "$T/t3/sigelo-9.9.8.intoto.jsonl" "$T/t3/sigelo-9.9.9.intoto.jsonl"
refuse 'verify: provenance made for another tag' 'checks 6, 7, 8 failed' sh "$R/release/verify-release.sh" v9.9.9 "$T/t3"
mkdir "$T/t4"; cp "$T/a/one.tgz" "$T/a/two.txt" "$T/a/sigelo-9.9.9.cdx.json" "$T/a/SHA256SUMS" "$T/a/sigelo-9.9.9.intoto.jsonl" "$T/a/SHA256SUMS.sigstore.json" "$T/t4/"
cp "$T/app.apk" "$T/t4/sigelo-9.9.9.apk"
pass 'sign: another unsigned build with the same prefix (sign checks the prefix only)' sh "$R/release/sign-release.sh" v9.9.9 "$T/t4" --apk "$T/t4/sigelo-9.9.9.apk" "$CERT" --unsigned "$T/unsigned2.apk"
refuse 'verify: an unsigned APK CI did not build' 'FAIL 8 sigelo-9.9.9.intoto.jsonl names no unsigned APK' sh "$R/release/verify-release.sh" v9.9.9 "$T/t4"
# A release.json from before v2: apk without unsigned_sha256 (made as sign-release.sh did).
cp -r "$T/a" "$T/t5"
node --input-type=module - "$src" "$T/rel.json" "$T/t5/release.json" <<'EOF'
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const [src, id, out] = process.argv.slice(2);
const { attest, did, parse } = await import(pathToFileURL(`${src}/ts/dist/sigelo.js`).href);
const store = parse(readFileSync(id, 'utf8')), old = JSON.parse(readFileSync(out, 'utf8'));
const claims = old.attestations[0].body.claims; delete claims.apk.unsigned_sha256;
const iss = did(store.genesis), iat = Math.floor(Date.now() / 1000);
const att = attest({ secret: Uint8Array.from(Buffer.from(store.secret, 'hex')), iss, sub: iss, iat, exp: iat + 86400, ctx: 'sigelo.io/release', admission: 'open', claims });
writeFileSync(out, JSON.stringify({ ...old, attestations: [att] }, null, 2) + '\n');
EOF
pass 'verify: release.json without unsigned_sha256 (older)' sh "$R/release/verify-release.sh" v9.9.9 "$T/t5"
has 'verify: ... says 8 not checked' '--   8 not checked: release.json has no apk.unsigned_sha256'
refuse 'verify --strict: release.json without unsigned_sha256' 'check 8 not checked' sh "$R/release/verify-release.sh" --strict v9.9.9 "$T/t5"
pass 'verify: no gh, no cosign' env SIGELO_GH= SIGELO_COSIGN= sh "$R/release/verify-release.sh" v9.9.9 "$T/a"
has 'verify: ... says 6, 7, 8 not checked' '--   6 not checked: no gh' 'not checked: 6, 7, 8'
refuse 'verify --strict: no gh, no cosign' 'checks 6, 7, 8 not checked' env SIGELO_GH= SIGELO_COSIGN= sh "$R/release/verify-release.sh" --strict v9.9.9 "$T/a"
refuse 'verify --strict: no apksigner' 'check 4 not checked' env SIGELO_APKSIGNER=/nonexistent/apksigner PATH=/nonexistent:/usr/bin:/bin sh -c 'command -v apksigner >/dev/null && echo "check 4 not checked (skipped: an apksigner is installed)" >&2 && exit 1; SIGELO_APKSIGNER= sh "$@"' - "$R/release/verify-release.sh" --strict v9.9.9 "$T/a"
pass 'verify: a release before v2 (no digest line, no proofs)' sh "$R/release/verify-release.sh" v9.9.8 "$T/b"
has 'verify: ... says 1, 5, 6, 7 not checked' 'not checked: 1, 5, 6, 7'
refuse 'verify --strict: a release before v2' 'not checked' sh "$R/release/verify-release.sh" --strict v9.9.8 "$T/b"
mkdir "$T/pre"; cp "$T/a/one.tgz" "$T/a/two.txt" "$T/a/sigelo-9.9.9.cdx.json" "$T/a/SHA256SUMS" "$T/a/sigelo-9.9.9.intoto.jsonl" "$T/a/SHA256SUMS.sigstore.json" "$T/pre/"
refuse 'verify: a pre-release without --pre' 'a pre-release: --pre' sh "$R/release/verify-release.sh" v9.9.9 "$T/pre"
pass 'verify --pre: tag, digest, provenance, cosign' sh "$R/release/verify-release.sh" --pre v9.9.9 "$T/pre"
has 'verify --pre: ... 5, 6, 7 OK; 2, 8 not checked' 'ok   7 cosign' 'not checked: 2, 8'
pass 'verify --dry-run: no tag, no release.json' sh "$R/release/verify-release.sh" --dry-run v9.9.5 "$T/pre"
has 'verify --dry-run: ... says so' 'OK v9.9.5 (dry run): 3 files match SHA256SUMS' 'not checked: 1, 2, 3'

# verify-release.sh from a URL: the APK is downloaded as release.json names it.
port=$(node -e 's=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')
node -e 'const [d, p] = process.argv.slice(1), fs = require("fs");
  require("http").createServer((q, r) => { const [, sub, name] = decodeURIComponent(q.url).split("/"), f = `${d}/${sub}/${name}`;
    if (fs.existsSync(f)) { r.end(fs.readFileSync(f)); } else { r.statusCode = 404; r.end(); } }).listen(+p, "127.0.0.1")' "$T" "$port" &
srv=$!
i=0; until node -e 'fetch(process.argv[1]).then((r)=>process.exit(r.ok?0:1),()=>process.exit(1))' "http://127.0.0.1:$port/a/SHA256SUMS" 2>/dev/null; do i=$((i + 1)); [ $i -lt 50 ] || break; node -e 'setTimeout(()=>{},100)'; done
pass 'verify: from a URL, the APK fetched' sh "$R/release/verify-release.sh" v9.9.9 "http://127.0.0.1:$port/a"
grep -q 'sigelo-9.9.9.apk 9.9.9 matches, certificate matches' "$T/out" && ok 'verify: from a URL, the APK checked' || no 'verify: from a URL, the APK checked'
has 'verify: from a URL, the proofs fetched' 'ok   6 provenance' 'ok   7 cosign'
refuse 'verify: a pre-release from a URL, without --pre' 'no SHA256SUMS and release.json' sh "$R/release/verify-release.sh" v9.9.9 "http://127.0.0.1:$port/pre"
pass 'verify --pre: a pre-release from a URL' sh "$R/release/verify-release.sh" --pre v9.9.9 "http://127.0.0.1:$port/pre"
has 'verify --pre: ... its proofs checked' 'ok   6 provenance' '(pre-release)'
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
  mkdir "$1/c" && cp "$1/a/one.tgz" "$1/a/two.txt" "$1/a/sigelo-9.9.9.cdx.json" "$1/a/SHA256SUMS" "$1/a/sigelo-9.9.9.apk" "$1/c/" &&
  sh "$2/release/sign-release.sh" v9.9.9 "$1/c" --apk "$1/c/sigelo-9.9.9.apk" "$3" --unsigned "$1/unsigned.apk" >/dev/null &&
  SIGELO_RELEASE_GENESIS="$1/rel-genesis.json" sh "$2/release/apk-check.sh" "$1/app.apk" "$1/c/release.json"' - "$T" "$R" "$CERT"
refuse 'apk-check: no apksigner' 'apksigner not found' env SIGELO_APKSIGNER= PATH=/nonexistent:/usr/bin:/bin sh -c 'command -v apksigner >/dev/null && echo "apksigner not found (skipped: one is installed)" >&2 && exit 1; sh "$1" "$2" "$3"' - "$R/release/apk-check.sh" "$T/app.apk" "$T/a/release.json"

# mirror-release.sh --dry-run over the fake gh: the APK release.json names and CI's proofs are
# accepted, others not; verify-release.sh must pass on the download.
for c in ssh tar sha256sum node; do command -v $c >/dev/null || { echo "missing $c" >&2; exit 1; }; done
pass 'mirror: a release with its APK and proofs (dry run)' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/a" sh "$R/site/deploy/mirror-release.sh" v9.9.9 --dry-run
grep -q 'sigelo-9.9.9.apk: sha256 as release.json signs it' "$T/out" && ok 'mirror: names the APK' || no 'mirror: names the APK'
has 'mirror: runs verify-release.sh (8 OK)' 'ok   8 the unsigned APK' 'OK v9.9.9'
pass 'mirror: a pre-release (no release.json, no APK)' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/pre" sh "$R/site/deploy/mirror-release.sh" v9.9.9 --dry-run
has 'mirror: ... verified with --pre' 'OK v9.9.9 (.*) (pre-release)'
refuse 'mirror: provenance that does not cover a file' 'verify-release.sh v9.9.9 refuses' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/t2" sh "$R/site/deploy/mirror-release.sh" v9.9.9 --dry-run
cp -r "$T/a" "$T/a3"; printf 'x' >>"$T/a3/sigelo-9.9.9.apk"
refuse 'mirror: a changed APK' 'does not match' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/a3" sh "$R/site/deploy/mirror-release.sh" v9.9.9 --dry-run
cp "$T/a/sigelo-9.9.9.apk" "$T/a3/sigelo-9.9.9.apk"; cp "$T/app.apk" "$T/a3/stray.apk"
refuse 'mirror: an APK release.json does not name' 'differ' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/a3" sh "$R/site/deploy/mirror-release.sh" v9.9.9 --dry-run
pass 'mirror: a release without an APK (dry run)' env PATH="$T/bin:$PATH" FAKE_RELEASE="$T/b" sh "$R/site/deploy/mirror-release.sh" v9.9.8 --dry-run

[ "$bad" = 0 ] && echo "ALL PASS ($n checks)" || { echo "$bad FAILED ($n checks)"; exit 1; }
