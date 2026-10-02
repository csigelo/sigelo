#!/bin/sh
# SPDX-License-Identifier: MIT
# Signs a release (ROADMAP §5.5): writes <artefact-dir>/release.json.
#
#   release/sign-release.sh <tag> <artefact-dir>
#
# <artefact-dir> is what release/build.sh wrote, SHA256SUMS included; <tag> must already exist in
# this repository and carry an SSH signature that release/allowed_signers accepts (RELEASE.md
# "Signing"), so the two signatures are made over the same commit.
#
# release.json is a sigelo bundle (SPEC §8) of the RELEASE identity: its genesis and rotations, no
# bindings, and one self-issued attestation (SPEC §5; iss = sub = the identity's current DID,
# admission "open") with ctx "sigelo.io/release" and
#   claims: { tag, commit, sha256sums_sha256, files: { <name>: <sha256> } }
# Any sigelo verifier checks it unchanged (`sigelo-verify release.json --now <iat>`); the release
# meaning of the claims is checked by release/verify-release.sh. Not a new `typ`: SPEC §3.1's
# table is closed and §9 step 2 rejects a `typ` outside its slot, so a "release" object would be
# a wire change no shipped verifier reads.
#
# SIGELO_RELEASE_IDENTITY  the release identity file (sigelo-agent's format), default
#                          ~/.config/sigelo/release.local.json. Never the maintainer's own identity.
# SIGELO_RELEASE_GENESIS   the pinned original genesis, default release/release-identity.json;
#                          the identity file must be that identity (or a rotation of it).
# SIGELO_ALLOWED_SIGNERS   default release/allowed_signers.
set -eu

[ $# -eq 2 ] || { echo "usage: release/sign-release.sh <tag> <artefact-dir>" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
tag=$1
dir=$(cd "$2" && pwd)
id=${SIGELO_RELEASE_IDENTITY:-$HOME/.config/sigelo/release.local.json}
pin=${SIGELO_RELEASE_GENESIS:-$root/release/release-identity.json}
signers=${SIGELO_ALLOWED_SIGNERS:-$root/release/allowed_signers}

[ -f "$dir/SHA256SUMS" ] || { echo "sign-release.sh: no SHA256SUMS in $dir" >&2; exit 1; }
[ -f "$root/ts/dist/sigelo.js" ] || { echo "sign-release.sh: build the library first: (cd ts && npm ci && npx tsc)" >&2; exit 1; }
commit=$(git -C "$root" rev-parse --verify --quiet "refs/tags/$tag^{commit}") || { echo "sign-release.sh: no tag $tag" >&2; exit 1; }
git -C "$root" -c gpg.ssh.allowedSignersFile="$signers" verify-tag "$tag" 2>/dev/null ||
	{ echo "sign-release.sh: tag $tag has no SSH signature accepted by $signers" >&2; exit 1; }

node --input-type=module - "$root" "$tag" "$commit" "$dir" "$id" "$pin" <<'EOF'
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [root, tag, commit, dir, idPath, pinPath] = process.argv.slice(2);
const { attest, did, verify, parse } = await import(pathToFileURL(join(root, 'ts/dist/sigelo.js')).href);
const die = (m) => { console.error(`sign-release.sh: ${m}`); process.exit(1); };
const sha = (b) => createHash('sha256').update(b).digest('hex');

const sums = readFileSync(join(dir, 'SHA256SUMS'));
const files = {};
for (const line of sums.toString('utf8').split('\n').filter(Boolean)) {
  const m = line.match(/^([0-9a-f]{64}) [ *]([^/\\]+)$/) ?? die(`SHA256SUMS: bad line: ${line}`);
  if (sha(readFileSync(join(dir, m[2]))) !== m[1]) die(`${m[2]}: sha256 differs from SHA256SUMS`);
  files[m[2]] = m[1];
}
const extra = readdirSync(dir).filter((f) => !(f in files) && f !== 'SHA256SUMS' && f !== 'release.json');
if (extra.length) die(`not in SHA256SUMS: ${extra.join(' ')}`);

const store = parse(readFileSync(idPath, 'utf8'));
const pinned = did(parse(readFileSync(pinPath, 'utf8')));
if (did(store.genesis) !== pinned) die(`${idPath} is ${did(store.genesis)}, not the pinned release identity ${pinned}`);
const current = store.rotations.length ? store.rotations.at(-1).next_genesis : store.genesis;
const iss = did(current);
const iat = Math.floor(Date.now() / 1000);
const att = attest({ secret: Uint8Array.from(Buffer.from(store.secret, 'hex')), iss, sub: iss, iat, exp: iat + 90 * 86400,
  ctx: 'sigelo.io/release', admission: 'open', claims: { tag, commit, sha256sums_sha256: sha(sums), files } });
const bundle = { v: 'sigelo/0', typ: 'bundle', genesis: store.genesis, rotations: store.rotations, bindings: [], attestations: [att], issuers: [current] };
const r = verify(bundle, iat);
if (r.attestations[iss]?.length !== 1 || r.rejected.attestations) die('self-check: the release attestation did not verify');
writeFileSync(join(dir, 'release.json'), JSON.stringify(bundle, null, 2) + '\n');
console.log(`release.json: ${tag} (${commit.slice(0, 12)}), ${Object.keys(files).length} files, signed by ${iss}`);
EOF
