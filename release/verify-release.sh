#!/bin/sh
# SPDX-License-Identifier: MIT
# Verifies a signed release (v0.1.1 on; v0.1.0 is unsigned). Run inside a clone of the repository.
#
#   release/verify-release.sh <tag> [<artefact-dir> | <base-url>]
#
# Default source: https://sigelo.io/releases/<tag>/, else
# https://github.com/csigelo/sigelo/releases/download/<tag>/. Checks, and prints OK or FAIL:
#   1. every file SHA256SUMS lists, against SHA256SUMS;
#   2. release.json as a sigelo bundle (SPEC §9) at now = the attestation's iat — with
#      sigelo-verify if it is on PATH ($SIGELO_VERIFY overrides), else the ts library — whose
#      chain starts at the pinned release identity (release/release-identity.json), holding one
#      ctx "sigelo.io/release" attestation from its current DID about itself whose claims name
#      this tag, the tag's commit, sha256(SHA256SUMS) and exactly SHA256SUMS's files;
#   3. the tag's SSH signature against release/allowed_signers (fetched from origin if absent).
# The pins are read from THIS checkout, not from the release: compare them once with
# https://sigelo.io/.well-known/sigelo-release-signers and /.well-known/sigelo-release-identity.json.
# SIGELO_RELEASE_GENESIS and SIGELO_ALLOWED_SIGNERS override the two pins.
set -eu

[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: release/verify-release.sh <tag> [<artefact-dir> | <base-url>]" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
tag=$1
src=${2:-}
pin=${SIGELO_RELEASE_GENESIS:-$root/release/release-identity.json}
signers=${SIGELO_ALLOWED_SIGNERS:-$root/release/allowed_signers}
fail() { echo "FAIL: $*" >&2; exit 1; }

fetch() { # url file
	if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}
case $src in
'' | http://* | https://*)
	dir=$(mktemp -d)
	trap 'rm -rf "$dir"' EXIT
	got=
	for base in ${src:-https://sigelo.io/releases/$tag https://github.com/csigelo/sigelo/releases/download/$tag}; do
		base=${base%/}
		if fetch "$base/SHA256SUMS" "$dir/SHA256SUMS" 2>/dev/null && fetch "$base/release.json" "$dir/release.json" 2>/dev/null; then got=$base; break; fi
	done
	[ -n "$got" ] || fail "no SHA256SUMS and release.json for $tag at ${src:-sigelo.io or GitHub}"
	for f in $(awk '{ sub(/^\*/, "", $2); print $2 }' "$dir/SHA256SUMS"); do
		case $f in */* | .*) fail "SHA256SUMS: bad name $f" ;; esac
		fetch "$got/$f" "$dir/$f" || fail "download $got/$f"
	done ;;
*) dir=$(cd "$src" && pwd) ;;
esac

git -C "$root" rev-parse --verify --quiet "refs/tags/$tag" >/dev/null ||
	git -C "$root" fetch --quiet --no-tags origin "refs/tags/$tag:refs/tags/$tag" || fail "tag $tag: not here and not on origin"
commit=$(git -C "$root" rev-parse --verify "refs/tags/$tag^{commit}")
if ! out=$(git -C "$root" -c gpg.ssh.allowedSignersFile="$signers" verify-tag "$tag" 2>&1); then
	fail "tag $tag: no SSH signature accepted by $signers"
fi
signer=$(printf '%s\n' "$out" | sed -n 's/^Good "git" signature for \(.*\)$/\1/p' | head -1)

verifier=${SIGELO_VERIFY:-$(command -v sigelo-verify || true)}
node --input-type=module - "$root" "$tag" "$commit" "$dir" "$pin" "$verifier" "$signer" <<'EOF'
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [root, tag, commit, dir, pinPath, verifier, signer] = process.argv.slice(2);
const fail = (m) => { console.error(`FAIL: ${m}`); process.exit(1); };
const sha = (b) => createHash('sha256').update(b).digest('hex');
const lib = join(root, 'ts/dist/sigelo.js');
const { did, parse, verify } = await import(pathToFileURL(lib).href).catch((e) => fail(`${lib}: ${e.message.split("\n")[0]} (cd ts && npm ci && npx tsc)`));

// 1. SHA256SUMS
const sums = readFileSync(join(dir, 'SHA256SUMS'));
const files = {};
for (const line of sums.toString('utf8').split('\n').filter(Boolean)) {
  const m = line.match(/^([0-9a-f]{64}) [ *]([^/\\]+)$/) ?? fail(`SHA256SUMS: bad line: ${line}`);
  let got; try { got = sha(readFileSync(join(dir, m[2]))); } catch { fail(`${m[2]}: missing`); }
  if (got !== m[1]) fail(`${m[2]}: sha256 ${got} is not SHA256SUMS's ${m[1]}`);
  files[m[2]] = m[1];
}

// 2. release.json: a bundle, verified as any bundle, then read as a release.
const text = readFileSync(join(dir, 'release.json'));
let bundle; try { bundle = parse(text.toString('utf8')); } catch (e) { fail(`release.json: ${e.message}`); }
const iat = bundle?.attestations?.[0]?.body?.iat;
if (!Number.isSafeInteger(iat)) fail('release.json: no attestation');
let r;
if (verifier) {
  try { r = JSON.parse(execFileSync(verifier, [join(dir, 'release.json'), '--now', String(iat)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })); }
  catch (e) { fail(`release.json: ${verifier}: ${(e.stderr || e.message).trim()}`); }
} else {
  try { r = verify(bundle, iat); } catch (e) { fail(`release.json: ${e.message}`); }
}
const pinned = did(parse(readFileSync(pinPath, 'utf8')));
if (r.chain[0] !== pinned) fail(`release.json: identity ${r.chain[0]} is not the pinned release identity ${pinned}`);
if (r.rejected.attestations || r.rejected.bindings || bundle.attestations.length !== 1) fail('release.json: a rejected or extra item');
const att = r.attestations[r.did] ?? fail(`release.json: no attestation from the current DID ${r.did}`);
const [a] = att;
if (att.length !== 1 || a.sub !== r.did || a.ctx !== 'sigelo.io/release') fail('release.json: not a sigelo.io/release attestation of the identity about itself');
const c = a.claims ?? {};
if (c.tag !== tag) fail(`release.json: signs tag ${c.tag}, not ${tag}`);
if (c.commit !== commit) fail(`release.json: signs commit ${c.commit}, the tag points at ${commit}`);
if (c.sha256sums_sha256 !== sha(sums)) fail('release.json: signs another SHA256SUMS');
const want = Object.keys(files).sort(), have = Object.keys(c.files ?? {}).sort();
if (want.join('\n') !== have.join('\n') || want.some((f) => c.files[f] !== files[f])) fail('release.json: its file list differs from SHA256SUMS');
console.log(`OK ${tag} (${commit.slice(0, 12)}): ${want.length} files match SHA256SUMS; release.json signed ${new Date(iat * 1000).toISOString().slice(0, 10)} by ${r.did}${
  r.chain.length > 1 ? ` (rotated from ${pinned})` : ''} [${verifier ? 'sigelo-verify' : 'ts library'}]; tag signed by ${signer || 'an allowed signer'}`);
EOF
