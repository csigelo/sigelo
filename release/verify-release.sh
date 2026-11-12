#!/bin/sh
# SPDX-License-Identifier: MIT
# Verifies a signed release (v0.1.1 on; v0.1.0 is unsigned). Run inside a clone of the repository.
#
#   release/verify-release.sh [--strict] [--offline] [--pre | --dry-run] <tag> [<artefact-dir> | <base-url>]
#
# Default source: https://sigelo.io/releases/<tag>/, else
# https://github.com/csigelo/sigelo/releases/download/<tag>/. Checks, and prints OK or FAIL:
#   1. every file SHA256SUMS lists, against SHA256SUMS (and the SBOM sigelo-<v>.cdx.json among them);
#   2. release.json as a sigelo bundle (SPEC §9) at now = the attestation's iat — with
#      sigelo-verify if it is on PATH ($SIGELO_VERIFY overrides), else the ts library — whose
#      chain starts at the pinned release identity (release/release-identity.json), holding one
#      ctx "sigelo.io/release" attestation from its current DID about itself whose claims name
#      this tag, the tag's commit, sha256(SHA256SUMS) and exactly SHA256SUMS's files;
#   3. the tag's SSH signature against release/allowed_signers (fetched from origin if absent);
#   4. if the claims name an Android APK (release/apk-ceremony.md): the file's SHA-256 and version
#      as signed, and its signing certificate's SHA-256 with apksigner when there is one
#      ($SIGELO_APKSIGNER overrides; without it, said so: release/apk-check.sh does it on its own);
#   5. the tag message's last line `sha256sums: <x>`: x = sha256(SHA256SUMS);
#   6. build provenance of each file and of SHA256SUMS: `gh attestation verify` against the
#      release's sigelo-<v>.intoto.jsonl, signed by release.yml at refs/tags/<tag> on a
#      GitHub-hosted runner ($SIGELO_GH overrides gh);
#   7. `cosign verify-blob` of SHA256SUMS with SHA256SUMS.sigstore.json, identity release.yml at
#      the tag ($SIGELO_COSIGN overrides cosign);
#   8. the APK's apk.unsigned_sha256 claim is a subject of the same provenance as SHA256SUMS.
# A check that cannot run (no gh, cosign or apksigner, no proof file, a release from before
# v2) prints "not checked"; --strict makes that a FAIL. --offline: gh and cosign check against
# the saved Sigstore roots, release/trusted-root.jsonl ($SIGELO_TRUSTED_ROOT overrides;
# refreshed each release: gh attestation trusted-root > release/trusted-root.jsonl), no network.
# --pre: a pre-release, release.json not made yet (2, 4 and 8 not checked). --dry-run: a dry
# run's artefacts, no tag either (only 1). The two proof files are not in SHA256SUMS: they are
# made after it. Set SIGELO_GH or SIGELO_COSIGN to an empty value to run without that tool.
# The pins are read from THIS checkout, not from the release: compare them once with
# https://sigelo.io/.well-known/sigelo-release-signers and /.well-known/sigelo-release-identity.json.
# SIGELO_RELEASE_GENESIS and SIGELO_ALLOWED_SIGNERS override the two pins.
set -eu

usage() { echo "usage: release/verify-release.sh [--strict] [--offline] [--pre | --dry-run] <tag> [<artefact-dir> | <base-url>]" >&2; exit 2; }
strict=0 offline=0 mode=final
while [ $# -gt 0 ]; do
	case $1 in
	--strict) strict=1 ;;
	--offline) offline=1 ;;
	--pre) mode=pre ;;
	--dry-run) mode=dry ;;
	-*) usage ;;
	*) break ;;
	esac
	shift
done
[ $# -ge 1 ] && [ $# -le 2 ] || usage
root=$(cd "$(dirname "$0")/.." && pwd)
tag=$1
src=${2:-}
got=
pin=${SIGELO_RELEASE_GENESIS:-$root/release/release-identity.json}
signers=${SIGELO_ALLOWED_SIGNERS:-$root/release/allowed_signers}
trusted=${SIGELO_TRUSTED_ROOT:-$root/release/trusted-root.jsonl}
fail() { echo "FAIL: $*" >&2; exit 1; }
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || fail "tag must look like v1.2.3: $tag"
[ "$offline" = 0 ] || [ -f "$trusted" ] || fail "--offline: no $trusted (gh attestation trusted-root > release/trusted-root.jsonl)"
proofs="sigelo-${tag#v}.intoto.jsonl SHA256SUMS.sigstore.json"

fetch() { # url file
	if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}
case $src in
'' | http://* | https://*)
	dir=$(mktemp -d)
	trap 'rm -rf "$dir"' EXIT
	for base in ${src:-https://sigelo.io/releases/$tag https://github.com/csigelo/sigelo/releases/download/$tag}; do
		base=${base%/}
		fetch "$base/SHA256SUMS" "$dir/SHA256SUMS" 2>/dev/null || continue
		if fetch "$base/release.json" "$dir/release.json" 2>/dev/null; then got=$base; break; fi
		rm -f "$dir/release.json"
		[ "$mode" = final ] || { got=$base; break; }
	done
	[ -n "$got" ] || fail "no SHA256SUMS and release.json for $tag at ${src:-sigelo.io or GitHub}"
	for f in $(awk '{ sub(/^\*/, "", $2); print $2 }' "$dir/SHA256SUMS"); do
		case $f in */* | .*) fail "SHA256SUMS: bad name $f" ;; esac
		fetch "$got/$f" "$dir/$f" || fail "download $got/$f"
	done
	for f in $proofs; do fetch "$got/$f" "$dir/$f" 2>/dev/null || rm -f "$dir/$f"; done ;;
*) dir=$(cd "$src" && pwd) ;;
esac
[ "$mode" != final ] || [ -f "$dir/release.json" ] || fail "no release.json in $dir (a pre-release: --pre)"

commit= signer= tagline=
if [ "$mode" != dry ]; then
	git -C "$root" rev-parse --verify --quiet "refs/tags/$tag" >/dev/null ||
		git -C "$root" fetch --quiet --no-tags origin "refs/tags/$tag:refs/tags/$tag" || fail "tag $tag: not here and not on origin"
	commit=$(git -C "$root" rev-parse --verify "refs/tags/$tag^{commit}")
	if ! out=$(git -C "$root" -c gpg.ssh.allowedSignersFile="$signers" verify-tag "$tag" 2>&1); then
		fail "tag $tag: no SSH signature accepted by $signers"
	fi
	signer=$(printf '%s\n' "$out" | sed -n 's/^Good "git" signature for \(.*\)$/\1/p' | head -1)
	tagline=$(git -C "$root" cat-file tag "$tag" | sed '/^-----BEGIN SSH SIGNATURE-----$/,$d' | grep . | tail -n 1)
fi

verifier=${SIGELO_VERIFY:-$(command -v sigelo-verify || true)}
apksigner=${SIGELO_APKSIGNER:-$(command -v apksigner || true)}
gh=${SIGELO_GH-$(command -v gh || true)}
cosign=${SIGELO_COSIGN-$(command -v cosign || true)}
node --input-type=module - "$root" "$tag" "$commit" "$dir" "$pin" "$verifier" "$signer" "$got" "$apksigner" \
	"$mode" "$strict" "$offline" "$tagline" "$gh" "$cosign" "$trusted" <<'EOF'
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [root, tag, commit, dir, pinPath, verifier, signer, base, apksigner, mode, strict, offline, tagline, gh, cosign, trusted] = process.argv.slice(2);
const fail = (m) => { console.error(`FAIL: ${m}`); process.exit(1); };
const sha = (b) => createHash('sha256').update(b).digest('hex');
const lib = join(root, 'ts/dist/sigelo.js');
const { did, parse, verify } = await import(pathToFileURL(lib).href).catch((e) => fail(`${lib}: ${e.message.split("\n")[0]} (cd ts && npm ci && npx tsc)`));
const REPO = 'csigelo/sigelo', WORKFLOW = `${REPO}/.github/workflows/release.yml`, ver = tag.replace(/^v/, '');
const INTOTO = `sigelo-${ver}.intoto.jsonl`, SIGSTORE = 'SHA256SUMS.sigstore.json';
// Checks 5-8 report each line and run to the end; 1-4 stop at the first FAIL, as before.
const report = [], nots = [], bad = [];
const ok = (n, m) => report.push(`ok   ${n} ${m}`);
const not = (n, m) => { report.push(`--   ${n} not checked: ${m}`); nots.push(n); };
const no = (n, m) => { report.push(`FAIL ${n} ${m}`); bad.push(n); };
const errText = (e) => String(e.stderr || e.message).trim().split('\n').filter(Boolean).slice(-1)[0] ?? 'failed';
const run = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

// 1. SHA256SUMS
const sums = readFileSync(join(dir, 'SHA256SUMS'));
const files = {};
for (const line of sums.toString('utf8').split('\n').filter(Boolean)) {
  const m = line.match(/^([0-9a-f]{64}) [ *]([^/\\]+)$/) ?? fail(`SHA256SUMS: bad line: ${line}`);
  let got; try { got = sha(readFileSync(join(dir, m[2]))); } catch { fail(`${m[2]}: missing`); }
  if (got !== m[1]) fail(`${m[2]}: sha256 ${got} is not SHA256SUMS's ${m[1]}`);
  files[m[2]] = m[1];
}
for (const f of [INTOTO, SIGSTORE, 'release.json']) if (f in files) fail(`SHA256SUMS lists ${f}, which is made after it`);
const sbom = `sigelo-${ver}.cdx.json`;
if (sbom in files) ok(1, `SBOM ${sbom} in SHA256SUMS`); else not(1, `SHA256SUMS lists no ${sbom} (a release before v2)`);

// 2. release.json: a bundle, verified as any bundle, then read as a release.
let c = null, iat, r, pinned;
if (mode !== 'dry' && existsSync(join(dir, 'release.json'))) {
  const text = readFileSync(join(dir, 'release.json'));
  let bundle; try { bundle = parse(text.toString('utf8')); } catch (e) { fail(`release.json: ${e.message}`); }
  iat = bundle?.attestations?.[0]?.body?.iat;
  if (!Number.isSafeInteger(iat)) fail('release.json: no attestation');
  if (verifier) {
    try { r = JSON.parse(execFileSync(verifier, [join(dir, 'release.json'), '--now', String(iat)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })); }
    catch (e) { fail(`release.json: ${verifier}: ${(e.stderr || e.message).trim()}`); }
  } else {
    try { r = verify(bundle, iat); } catch (e) { fail(`release.json: ${e.message}`); }
  }
  pinned = did(parse(readFileSync(pinPath, 'utf8')));
  if (r.chain[0] !== pinned) fail(`release.json: identity ${r.chain[0]} is not the pinned release identity ${pinned}`);
  if (r.rejected.attestations || r.rejected.bindings || bundle.attestations.length !== 1) fail('release.json: a rejected or extra item');
  const att = r.attestations[r.did] ?? fail(`release.json: no attestation from the current DID ${r.did}`);
  const [a] = att;
  if (att.length !== 1 || a.sub !== r.did || a.ctx !== 'sigelo.io/release') fail('release.json: not a sigelo.io/release attestation of the identity about itself');
  c = a.claims ?? {};
  if (c.tag !== tag) fail(`release.json: signs tag ${c.tag}, not ${tag}`);
  if (c.commit !== commit) fail(`release.json: signs commit ${c.commit}, the tag points at ${commit}`);
  if (c.sha256sums_sha256 !== sha(sums)) fail('release.json: signs another SHA256SUMS');
  const want = Object.keys(files).sort(), have = Object.keys(c.files ?? {}).sort();
  if (want.join('\n') !== have.join('\n') || want.some((f) => c.files[f] !== files[f])) fail('release.json: its file list differs from SHA256SUMS');
} else {
  not(2, mode === 'dry' ? 'a dry run, no release.json' : 'a pre-release, no release.json yet');
}
if (mode === 'dry') for (const n of [3, 5, 6, 7, 8]) not(n, n === 3 ? 'a dry run, no tag' : 'a dry run, no tag or proofs');

// 4. The Android APK, when the release names one: signed outside SHA256SUMS, so checked here.
let apkLine = '';
if (c?.apk !== undefined) {
  const p = c.apk ?? {};
  if (typeof p.file !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*\.apk$/.test(p.file) || !/^[0-9a-f]{64}$/.test(p.sha256 ?? '') ||
    !/^[0-9a-f]{64}$/.test(p.cert_sha256 ?? '') || p.version !== ver ||
    (p.unsigned_sha256 !== undefined && !/^[0-9a-f]{64}$/.test(p.unsigned_sha256))) fail('release.json: a malformed apk entry');
  if (p.file in files) fail(`release.json: ${p.file} is in SHA256SUMS too`);
  const at = join(dir, p.file);
  if (!existsSync(at) && base) {
    const res = await fetch(`${base}/${p.file}`).catch((e) => fail(`download ${base}/${p.file}: ${e.message}`));
    if (!res.ok) fail(`download ${base}/${p.file}: ${res.status}`);
    writeFileSync(at, Buffer.from(await res.arrayBuffer()));
  }
  let got; try { got = sha(readFileSync(at)); } catch { fail(`${p.file}: missing`); }
  if (got !== p.sha256) fail(`${p.file}: sha256 ${got} is not the signed ${p.sha256}`);
  let certs = 'certificate not checked (no apksigner: run release/apk-check.sh)';
  if (apksigner) {
    let out; try { out = execFileSync(apksigner, ['verify', '--print-certs', at], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (e) { fail(`${p.file}: apksigner verify refuses it: ${(e.stderr || e.message).trim()}`); }
    const seen = [...out.matchAll(/^Signer #\d+ certificate SHA-256 digest: *([0-9a-fA-F:]+)\s*$/gm)].map((m) => m[1].replace(/:/g, '').toLowerCase());
    if (seen.length !== 1 || seen[0] !== p.cert_sha256) fail(`${p.file}: signed by certificate(s) ${seen.join(' ') || 'none'}, not the release's ${p.cert_sha256}`);
    certs = 'certificate matches';
  } else not(4, `${p.file}: no apksigner for its certificate (release/apk-check.sh)`);
  apkLine = `; ${p.file} ${p.version} matches, ${certs}`;
}

// 5. The tag's digest of SHA256SUMS: the maintainer's own build (RELEASE-v2.md §2 step 1).
if (mode !== 'dry') {
  const m = /^sha256sums: ([0-9a-f]{64})$/.exec(tagline);
  if (!m) not(5, `the tag's last line is not "sha256sums: <sha256>" (a release before v2)`);
  else if (m[1] !== sha(sums)) no(5, `the tag names SHA256SUMS ${m[1]}, this one is ${sha(sums)}`);
  else ok(5, 'the tag names this SHA256SUMS');
}

// 6. Build provenance: one attestation over SHA256SUMS, its files and the unsigned APK.
const tmp = mkdtempSync(join(tmpdir(), 'sigelo-verify-'));
process.on('exit', () => rmSync(tmp, { recursive: true, force: true }));
const intoto = join(dir, INTOTO);
const attest = (file, bundle) => run(gh, ['attestation', 'verify', file, '-R', REPO, '--signer-workflow', WORKFLOW,
  '--source-ref', `refs/tags/${tag}`, '--deny-self-hosted-runners', '--bundle', bundle, ...(offline === '1' ? ['--custom-trusted-root', trusted] : [])]);
if (mode !== 'dry') {
  if (!gh) not(6, 'no gh');
  else if (!existsSync(intoto)) not(6, `no ${INTOTO}`);
  else {
    const failed = [];
    for (const f of [...Object.keys(files), 'SHA256SUMS']) {
      try { attest(join(dir, f), intoto); } catch (e) { failed.push(`${f} (${errText(e)})`); }
    }
    if (failed.length) no(6, `no provenance from release.yml at ${tag}: ${failed.join(', ')}`);
    else ok(6, `provenance: ${Object.keys(files).length + 1} files, built by release.yml at ${tag}`);
  }
}

// 7. Sigstore: what outside tools check.
const sigstore = join(dir, SIGSTORE);
if (mode !== 'dry') {
  if (!cosign) not(7, 'no cosign');
  else if (!existsSync(sigstore)) not(7, `no ${SIGSTORE}`);
  else {
    const args = ['verify-blob', join(dir, 'SHA256SUMS'), '--bundle', sigstore,
      '--certificate-identity', `https://github.com/${WORKFLOW}@refs/tags/${tag}`,
      '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'];
    if (offline === '1') {
      // cosign takes one trusted root: the public-good instance's (the one with a Rekor log).
      const line = readFileSync(trusted, 'utf8').split('\n').filter(Boolean)
        .find((l) => { try { return (JSON.parse(l).tlogs ?? []).some((t) => /rekor\.sigstore\.dev/.test(t.baseUrl ?? '')); } catch { return false; } });
      if (line) { writeFileSync(join(tmp, 'public-good.json'), line); args.push('--trusted-root', join(tmp, 'public-good.json'), '--offline'); }
    }
    try { run(cosign, args); ok(7, `cosign: SHA256SUMS signed by release.yml at ${tag}`); }
    catch (e) { no(7, `cosign refuses SHA256SUMS: ${errText(e)}`); }
  }
}

// 8. The signed APK's unsigned build: a subject of the same provenance as SHA256SUMS.
if (mode !== 'dry') {
  const u = c?.apk?.unsigned_sha256;
  if (!c) not(8, 'no release.json yet');
  else if (c.apk === undefined) ok(8, 'no APK in this release');
  else if (!u) not(8, 'release.json has no apk.unsigned_sha256 (signed before v2)');
  else if (!gh) not(8, 'no gh');
  else if (!existsSync(intoto)) not(8, `no ${INTOTO}`);
  else {
    const subjects = (l) => { try {
      const s = JSON.parse(Buffer.from(JSON.parse(l).dsseEnvelope.payload, 'base64').toString('utf8'));
      return (s.subject ?? []).map((x) => x?.digest?.sha256);
    } catch { return []; } };
    const line = readFileSync(intoto, 'utf8').split('\n').filter(Boolean).find((l) => subjects(l).includes(u));
    if (!line) no(8, `${INTOTO} names no unsigned APK ${u}`);
    else if (!subjects(line).includes(sha(sums))) no(8, `the unsigned APK's attestation does not cover SHA256SUMS`);
    else {
      writeFileSync(join(tmp, 'apk.jsonl'), line + '\n');
      try { attest(join(dir, 'SHA256SUMS'), join(tmp, 'apk.jsonl')); ok(8, `the unsigned APK ${u.slice(0, 12)}… was built by release.yml at ${tag}`); }
      catch (e) { no(8, `the attestation naming the unsigned APK does not verify: ${errText(e)}`); }
    }
  }
}

for (const l of report) console.log(l);
if (bad.length) fail(`${tag}: check${bad.length > 1 ? 's' : ''} ${[...new Set(bad)].join(', ')} failed (above)`);
if (strict === '1' && nots.length) fail(`${tag}: --strict, and check${nots.length > 1 ? 's' : ''} ${[...new Set(nots)].join(', ')} not checked (above)`);
const parts = [`${Object.keys(files).length} files match SHA256SUMS`];
if (c) parts.push(`release.json signed ${new Date(iat * 1000).toISOString().slice(0, 10)} by ${r.did}${
  r.chain.length > 1 ? ` (rotated from ${pinned})` : ''} [${verifier ? 'sigelo-verify' : 'ts library'}]`);
if (mode !== 'dry') parts.push(`tag signed by ${signer || 'an allowed signer'}`);
console.log(`OK ${tag}${commit ? ` (${commit.slice(0, 12)})` : ' (dry run)'}${mode === 'pre' && !c ? ' (pre-release)' : ''}: ${parts.join('; ')}${apkLine}${
  nots.length ? `; not checked: ${[...new Set(nots)].join(', ')}` : ''}`);
EOF
