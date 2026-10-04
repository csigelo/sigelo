#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/mirror-release.sh — mirrors a GitHub release of csigelo/sigelo to https://sigelo.io/releases/<tag>/.
#
#   site/deploy/mirror-release.sh <tag> [user@host] [--origin URL] [--no-verify] [--dry-run]
#
#   1. `gh release download <tag>` into a scratch directory; every file must be named in the
#      release's SHA256SUMS and every name there must have been downloaded, and `sha256sum -c`
#      must pass: anything else and nothing is uploaded;
#   2. writes site/src/releases/<tag>.SHA256SUMS in this tree (or checks it is the same): the
#      site build reads the mirrored release from it (index.json release.files, /verify);
#   3. uploads the files with a generated index.md listing to <webroot>/releases.incoming/<tag> on
#      the server (default host sigelo@sigelo.io), checks them there again with sha256sum -c and
#      moves them to <webroot>/releases/<tag>/ (dirs 0755, files 0644, owned by the deploy user).
#      A tag already mirrored is never changed: identical files are "unchanged", different ones
#      are refused (nginx serves /releases/v*/ files as immutable for a year);
#   4. merges the tag into <webroot>/releases/index.json (tags, files, sizes, sha256s; no
#      timestamps, so a re-run writes the same bytes) and the /releases/ index.md, points
#      <webroot>/releases/latest at the highest vX.Y.Z, and links dist/releases -> ../releases
#      if a deploy has not done so yet (deploy.sh does it on every upload);
#   5. unless --no-verify, downloads every file from <origin>/releases/<tag>/ (default
#      https://sigelo.io) and compares it with SHA256SUMS.
#
# The mirror lives on the server only: 24 MB of binaries per release do not belong in git or in
# site/dist. The directory is created on the first run. Needs gh (logged in), node >= 22, ssh,
# tar and sha256sum here; sh, tar, sha256sum on the server. Commit site/src/releases/<tag>.SHA256SUMS
# and redeploy so the site names the release.
set -eu

WEBROOT=${SIGELO_WEBROOT:-/var/www/sigelo.io}
REPO=${SIGELO_REPO:-csigelo/sigelo}
SSH=${SIGELO_SSH:-ssh}
die() { printf 'mirror-release.sh: %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
usage() { sed -n '5p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

tag=""; target=""; origin=https://sigelo.io; verify=1; dry=0
while [ $# -gt 0 ]; do
  case $1 in
    --origin) [ $# -ge 2 ] || usage; origin=${2%/}; shift 2 ;;
    --no-verify) verify=0; shift ;;
    --dry-run) dry=1; shift ;;
    -h|--help) usage ;;
    -*) die "unknown option: $1" ;;
    *) if [ -z "$tag" ]; then tag=$1; elif [ -z "$target" ]; then target=$1; else die "too many arguments: $1"; fi; shift ;;
  esac
done
[ -n "$tag" ] || usage
target=${target:-sigelo@sigelo.io}
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "tag must look like v1.2.3: $tag"
printf '%s' "$target" | grep -Eq '^([A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.:-]*$' || die "target must look like user@host: $target"
case $origin in https://*|http://*) ;; *) die "--origin must be an http(s) URL" ;; esac
printf '%s' "$WEBROOT" | grep -Eq '^/[A-Za-z0-9/._-]+$' || die "SIGELO_WEBROOT: an absolute path of letters, digits, / . _ - only"
for c in gh node tar sha256sum "${SSH%% *}"; do command -v "$c" >/dev/null 2>&1 || die "$c is required"; done

root=$(cd "$(dirname "$0")/../.." && pwd)
R=$WEBROOT/releases
tmp=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-mirror.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

step "1/5 download $REPO $tag and check it against its SHA256SUMS"
mkdir "$tmp/$tag"
gh release download "$tag" --repo "$REPO" -D "$tmp/$tag"
cd "$tmp/$tag"
[ -f SHA256SUMS ] || die "the release has no SHA256SUMS: refusing to mirror it"
for f in * .[!.]*; do
  [ -e "$f" ] || continue
  printf '%s' "$f" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' || die "file name not allowed: $f"
  [ -f "$f" ] || die "not a regular file: $f"
done
listed=$(sed -E 's/^[0-9a-f]{64} [ *]//' SHA256SUMS | LC_ALL=C sort)
present=$(ls | grep -vx -e SHA256SUMS -e release.json | LC_ALL=C sort)
grep -Evq '^[0-9a-f]{64} [ *][A-Za-z0-9][A-Za-z0-9._-]*$' SHA256SUMS && die "SHA256SUMS has a line that is not <sha256>  <file>"
[ "$listed" = "$present" ] || die "SHA256SUMS and the downloaded files differ:
listed:  $(echo $listed)
present: $(echo $present)"
sha256sum -c SHA256SUMS
# release.json (signed releases, v0.1.1 on) is the one file SHA256SUMS cannot list: it attests
# sha256(SHA256SUMS). Here only that it names this tag and these sums; release/verify-release.sh
# checks its signature, and fetches it from the mirror by default, so it is mirrored with the rest.
if [ -f release.json ]; then
  node -e 'const fs=require("fs"),[t]=process.argv.slice(1),h=require("crypto").createHash("sha256").update(fs.readFileSync("SHA256SUMS")).digest("hex");
    const c=(JSON.parse(fs.readFileSync("release.json","utf8")).attestations||[]).map((a)=>a.body&&a.body.claims).find((c)=>c&&c.tag===t);
    if(!c||c.sha256sums_sha256!==h){console.error("release.json does not attest "+t+" with sha256(SHA256SUMS) "+h);process.exit(1)}' "$tag" \
    || die "release.json does not match this release"
  echo "release.json names $tag and sha256(SHA256SUMS)"
fi
echo "$(echo "$present" | wc -l) files + SHA256SUMS: all OK"

step "2/5 site/src/releases/$tag.SHA256SUMS (the site build's copy)"
local_sums=$root/site/src/releases/$tag.SHA256SUMS
if [ -f "$local_sums" ]; then cmp -s "$local_sums" SHA256SUMS || die "$local_sums differs from the release's SHA256SUMS"; echo "present, identical"
elif [ "$dry" = 1 ]; then echo "(dry run) would write $local_sums"
else mkdir -p "$(dirname "$local_sums")"; cp SHA256SUMS "$local_sums"; echo "wrote $local_sums: commit it and redeploy"; fi

step "3/5 index.md for $tag; merge $target:$R/index.json"
old=$tmp/old-index.json
if [ "$dry" = 1 ]; then echo '{}' >"$old"; else $SSH "$target" "cat $R/index.json 2>/dev/null || true" >"$old"; fi
mkdir "$tmp/top"
latest=$(node - "$tmp" "$tag" "$REPO" "$origin" <<'EOF'
const { readFileSync, writeFileSync, statSync, existsSync } = require('node:fs');
const [tmp, tag, repo] = process.argv.slice(2);
const MIRROR = 'https://sigelo.io/releases/', GH = `https://github.com/${repo}`;
const dir = `${tmp}/${tag}`;
const files = readFileSync(`${dir}/SHA256SUMS`, 'utf8').trim().split('\n').map((l) => {
  const [, sha256, name] = l.match(/^([0-9a-f]{64}) [ *](.+)$/);
  return { name, bytes: statSync(`${dir}/${name}`).size, sha256, url: `${MIRROR}${tag}/${name}` };
});
const sums = { name: 'SHA256SUMS', bytes: statSync(`${dir}/SHA256SUMS`).size, url: `${MIRROR}${tag}/SHA256SUMS` };
const signed = existsSync(`${dir}/release.json`) ? [{ name: 'release.json', bytes: statSync(`${dir}/release.json`).size, url: `${MIRROR}${tag}/release.json` }] : [];
const entry = { tag, url: `${MIRROR}${tag}/`, github: `${GH}/releases/tag/${tag}`, sha256sums: sums.url, ...(signed.length && { release_json: signed[0].url }), files };
// The tag's listing: deterministic (no dates), so a re-run produces the same bytes.
writeFileSync(`${dir}/index.md`, `# sigelo ${tag}

The files of ${GH}/releases/tag/${tag}, verified against its SHA256SUMS before upload. Check them again:
\`sha256sum -c SHA256SUMS\` in a directory holding them, or \`grep ' <file>$' SHA256SUMS | sha256sum -c -\` for one.
All releases: [/releases/](/releases/) and [/releases/index.json](/releases/index.json).

| File | Bytes | SHA-256 |
|---|---:|---|
${[...files, sums, ...signed].map((f) => `| [${f.name}](${f.name}) | ${f.bytes} | ${f.sha256 ? `\`${f.sha256}\`` : ''} |`).join('\n')}
`);
let old = {}; try { old = JSON.parse(readFileSync(`${tmp}/old-index.json`, 'utf8') || '{}'); } catch { old = {}; }
const v = (t) => t.slice(1).split(/[.-]/).slice(0, 3).map(Number);
const cmp = (a, b) => { const x = v(a.tag), y = v(b.tag); return y[0] - x[0] || y[1] - x[1] || y[2] - x[2] || (a.tag < b.tag ? 1 : -1); };
const releases = [...(old.releases ?? []).filter((r) => r.tag !== tag), entry].sort(cmp);
const stable = releases.find((r) => !r.tag.includes('-')) ?? releases[0];
const index = { mirror: MIRROR, source: `${GH}/releases`, latest: stable.tag, latest_url: `${MIRROR}latest/`,
  verify: 'Check every file against its release\'s SHA256SUMS (sha256sum -c SHA256SUMS).', releases };
writeFileSync(`${tmp}/top/index.json`, JSON.stringify(index, null, 2) + '\n');
writeFileSync(`${tmp}/top/index.md`, `# sigelo releases

Mirror of ${GH}/releases: the same files, each release with its SHA256SUMS. Check every file against it.
Machine index: [index.json](index.json). Latest: [latest/](latest/) = ${stable.tag}.

${releases.map((r) => `- [${r.tag}](${r.tag}/): ${r.files.length} files + SHA256SUMS · ${r.github}`).join('\n')}
`);
console.log(stable.tag);
EOF
)
echo "latest: $latest"

step "4/5 upload to $target:$R/$tag (immutable once there), index.json, latest -> $latest"
remote="set -e; umask 022; R=$R; I=$WEBROOT/releases.incoming; mkdir -p \$R \$I; chmod 755 \$R
cd \$I; rm -rf $tag; tar -xf -; cd $tag; sha256sum -c SHA256SUMS >/dev/null; chmod 755 .; chmod 644 *
if [ -d \$R/$tag ]; then
  if [ \"\$(ls | LC_ALL=C sort)\" = \"\$(ls \$R/$tag | LC_ALL=C sort)\" ] && ( for f in *; do cmp -s \"\$f\" \"\$R/$tag/\$f\" || exit 1; done ); then echo \"$tag already mirrored, identical: unchanged\"
  else echo \"$tag is already mirrored with different files: a mirrored tag never changes\" >&2; cd \$I; rm -rf $tag; exit 1; fi
  cd \$I; rm -rf $tag
else
  cd \$I; mv $tag \$R/$tag; echo \"mirrored \$R/$tag\"
fi
rmdir \$I 2>/dev/null || true"
if [ "$dry" = 1 ]; then printf '+ tar -C %s -cf - %s | %s %s <remote script>\n' "$tmp" "$tag" "$SSH" "$target"
else tar -C "$tmp" -cf - "$tag" | $SSH "$target" "$remote"; fi
remote2="set -e; umask 022; cd $R; rm -rf .new; mkdir .new; tar -xf - -C .new; chmod 644 .new/index.json .new/index.md; mv .new/index.json index.json; mv .new/index.md index.md; rmdir .new
ln -sfn $latest latest
if [ -d $WEBROOT/dist ] && [ ! -e $WEBROOT/dist/releases ]; then ln -s ../releases $WEBROOT/dist/releases; echo \"linked dist/releases -> ../releases\"; fi
echo \"index.json: \$(grep -c '\"tag\"' index.json) release(s); latest -> \$(readlink latest)\""
if [ "$dry" = 1 ]; then printf '+ tar -C %s -cf - index.json index.md | %s %s <remote script>\n' "$tmp/top" "$SSH" "$target"
else tar -C "$tmp/top" -cf - index.json index.md | $SSH "$target" "$remote2"; fi

step "5/5 every file from $origin/releases/$tag/ against SHA256SUMS"
if [ "$verify" = 0 ] || [ "$dry" = 1 ]; then echo "skipped"; exit 0; fi
node - "$tmp/$tag" "$origin/releases/$tag/" <<'EOF'
const { readFileSync, existsSync } = require('node:fs');
const { createHash } = require('node:crypto');
const [dir, base] = process.argv.slice(2);
const UA = 'sigelo-selfcheck/1 (+https://sigelo.io/privacy)';  // nginx.conf: logged to access-self.log
const lines = readFileSync(`${dir}/SHA256SUMS`, 'utf8').trim().split('\n').map((l) => l.match(/^([0-9a-f]{64}) [ *](.+)$/).slice(1));
(async () => {
  let bad = 0;
  const h = (f) => createHash('sha256').update(readFileSync(`${dir}/${f}`)).digest('hex');
  const all = [...lines, [h('SHA256SUMS'), 'SHA256SUMS'], ...(existsSync(`${dir}/release.json`) ? [[h('release.json'), 'release.json']] : [])];
  for (const [sha, name] of all) {
    const r = await fetch(base + name, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(120000) });
    const b = Buffer.from(await r.arrayBuffer());
    const got = createHash('sha256').update(b).digest('hex');
    const ok = r.status === 200 && got === sha;
    if (!ok) bad++;
    console.log(`${ok ? 'ok' : 'FAIL'} ${base}${name}: ${r.status}, ${r.headers.get('content-type')}, ${b.length} bytes${ok ? '' : `, sha256 ${got}`}`);
  }
  console.log(bad ? `FAILURES (${bad})` : `ALL PASS (${all.length} files)`);
  process.exit(bad ? 1 : 0);
})();
EOF
