#!/bin/sh
# SPDX-License-Identifier: MIT
# Checks an Android APK against a signed release before you install it (APPS.md, apk-ceremony.md).
# Run inside a clone of the repository (the pins are read from it).
#
#   release/apk-check.sh <app.apk> <release.json>
#
# release.json is the release's (https://sigelo.io/releases/<tag>/release.json, or the GitHub
# release's). Checks, and prints OK or FAIL:
#   1. release.json as a sigelo bundle (SPEC §9) at now = its attestation's iat, with sigelo-verify
#      if it is on PATH ($SIGELO_VERIFY overrides), else the ts library; its chain starts at the
#      pinned release identity (release/release-identity.json; SIGELO_RELEASE_GENESIS overrides),
#      one ctx "sigelo.io/release" attestation from its current DID about itself, naming an apk;
#   2. sha256(<app.apk>) is the signed sha256;
#   3. apksigner (Android SDK build-tools; $SIGELO_APKSIGNER overrides) verifies the APK and
#      reports exactly one signing certificate, whose SHA-256 is the signed cert_sha256.
# release/verify-release.sh checks the whole release, tag included; this checks one APK.
set -eu

[ $# -eq 2 ] || { echo "usage: release/apk-check.sh <app.apk> <release.json>" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
pin=${SIGELO_RELEASE_GENESIS:-$root/release/release-identity.json}
verifier=${SIGELO_VERIFY:-$(command -v sigelo-verify || true)}
apksigner=${SIGELO_APKSIGNER:-$(command -v apksigner || true)}
[ -n "$apksigner" ] || { echo "FAIL: apksigner not found: install the Android SDK build-tools (or your distribution's apksigner), or set SIGELO_APKSIGNER" >&2; exit 1; }

node --input-type=module - "$root" "$1" "$2" "$pin" "$verifier" "$apksigner" <<'EOF'
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { basename, join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [root, apkPath, relPath, pinPath, verifier, apksigner] = process.argv.slice(2);
const fail = (m) => { console.error(`FAIL: ${m}`); process.exit(1); };
const sha = (b) => createHash('sha256').update(b).digest('hex');
const lib = join(root, 'ts/dist/sigelo.js');
const { did, parse, verify } = await import(pathToFileURL(lib).href).catch((e) => fail(`${lib}: ${e.message.split('\n')[0]} (cd ts && npm ci && npx tsc)`));

// 1. release.json
let text; try { text = readFileSync(relPath, 'utf8'); } catch { fail(`${relPath}: missing`); }
let bundle; try { bundle = parse(text); } catch (e) { fail(`release.json: ${e.message}`); }
const iat = bundle?.attestations?.[0]?.body?.iat;
if (!Number.isSafeInteger(iat)) fail('release.json: no attestation');
let r;
if (verifier) {
  try { r = JSON.parse(execFileSync(verifier, [relPath, '--now', String(iat)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })); }
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
const p = a.claims?.apk ?? fail(`release.json: release ${a.claims?.tag} names no APK`);
if (!/^[0-9a-f]{64}$/.test(p.sha256 ?? '') || !/^[0-9a-f]{64}$/.test(p.cert_sha256 ?? '') || typeof p.version !== 'string') fail('release.json: a malformed apk entry');

// 2. the file
let bytes; try { bytes = readFileSync(apkPath); } catch { fail(`${apkPath}: missing`); }
const got = sha(bytes);
if (got !== p.sha256) fail(`${basename(apkPath)}: sha256 ${got} is not ${a.claims.tag}'s ${p.sha256} (${p.file})`);

// 3. its signing certificate
let out; try { out = execFileSync(apksigner, ['verify', '--print-certs', apkPath], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
catch (e) { fail(`${basename(apkPath)}: apksigner verify refuses it: ${(e.stderr || e.message).trim()}`); }
const seen = [...out.matchAll(/^Signer #\d+ certificate SHA-256 digest: *([0-9a-fA-F:]+)\s*$/gm)].map((m) => m[1].replace(/:/g, '').toLowerCase());
if (seen.length !== 1 || seen[0] !== p.cert_sha256) fail(`${basename(apkPath)}: signed by certificate(s) ${seen.join(' ') || 'none'}, not the release's ${p.cert_sha256}`);
console.log(`OK ${basename(apkPath)}: ${a.claims.tag} (version ${p.version}), sha256 ${p.sha256}; certificate ${p.cert_sha256}; release.json signed ${new Date(iat * 1000).toISOString().slice(0, 10)} by ${r.did}`);
EOF
