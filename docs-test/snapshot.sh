#!/bin/sh
# SPDX-License-Identifier: MIT
# Freeze what a round-3 candidate may read (docs-test/README.md).
#
#   docs-test/snapshot.sh [REV]                  docs-test/snapshot/<short-hash>/{lifecycle,verifier}/ + MANIFEST.json
#   docs-test/snapshot.sh [REV] --sandbox DIR    the same, plus a runnable lifecycle workspace in DIR
#
# Files come from the git object store at REV (default HEAD), never the working tree, so the
# hash in the directory name is the whole truth about what the candidate saw.
#
#   lifecycle  (docs-only lifecycle, TASK-lifecycle.md): SPEC.md, QUICKSTART.md,
#              examples/world.mjs, ts/README.md (identity part: the Monero and root-seed
#              sections are cut), test-vectors.json, schema/
#   verifier   (spec-only implementer, TASK-verifier.md): SPEC.md, test-vectors.json
#
# Never ts/src, go/, adapters/ or spend/. The sandbox adds what the lifecycle task needs to
# RUN: ts/dist (sigelo.js, jcs.js, monero.js only: no .d.ts, no maps, no tests, no generator),
# built from REV's ts/src in a temp dir, its two @noble dependencies, and node_modules/sigelo
# pointing at it, so `import('sigelo')` resolves from DIR. Compiled JS is readable; TASK
# forbids reading it and the transcript audit (README) is what enforces that.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
rev=HEAD
sandbox=
while [ $# -gt 0 ]; do
  case $1 in
    --sandbox) [ $# -ge 2 ] || { echo "--sandbox needs a directory" >&2; exit 2; }; sandbox=$2; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) rev=$1; shift ;;
  esac
done
cd "$repo"
full=$(git rev-parse --verify "$rev^{commit}")
short=$(git rev-parse --short=7 "$full")
out="$here/snapshot/$short"

LIFECYCLE="SPEC.md QUICKSTART.md examples/world.mjs ts/README.md test-vectors.json"
for f in $(git ls-tree --name-only "$full" schema/); do LIFECYCLE="$LIFECYCLE $f"; done
VERIFIER="SPEC.md test-vectors.json"

put() { # put <condition-dir> <path>
  mkdir -p "$(dirname "$1/$2")"
  if [ "$2" = ts/README.md ]; then
    # identity part: drop "## Monero bindings" and "## Root seed", keep everything else
    git show "$full:$2" | awk '/^## /{skip = ($0 ~ /^## Monero bindings/ || $0 ~ /^## Root seed/)} !skip' > "$1/$2"
  else
    git show "$full:$2" > "$1/$2"
  fi
}
rm -rf "$out"
for f in $LIFECYCLE; do put "$out/lifecycle" "$f"; done
for f in $VERIFIER; do put "$out/verifier" "$f"; done

node - "$out" "$full" "$short" <<'EOF'
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [out, commit, short] = process.argv.slice(2);
const walk = (d, pre = '') => fs.readdirSync(path.join(d, pre)).sort().flatMap((n) => {
  const p = path.join(pre, n);
  return fs.statSync(path.join(d, p)).isDirectory() ? walk(d, p) : [p];
});
const files = (cond) => walk(path.join(out, cond)).map((p) => {
  const b = fs.readFileSync(path.join(out, cond, p));
  return { path: p, bytes: b.length, sha256: crypto.createHash('sha256').update(b).digest('hex') };
});
const m = {
  commit, short, created: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  note: 'Files are exactly git show <commit>:<path>, except ts/README.md, cut to its identity part (sections "Monero bindings" and "Root seed" removed).',
  conditions: { lifecycle: files('lifecycle'), verifier: files('verifier') },
};
// one digest per condition, over "sha256  path\n" lines: the number to quote beside a score
for (const c of Object.keys(m.conditions)) {
  const lines = m.conditions[c].map((f) => `${f.sha256}  ${f.path}\n`).join('');
  m.conditions[c] = { digest: crypto.createHash('sha256').update(lines).digest('hex'), files: m.conditions[c] };
}
fs.writeFileSync(path.join(out, 'MANIFEST.json'), JSON.stringify(m, null, 1) + '\n');
console.log(`snapshot ${short}: lifecycle ${m.conditions.lifecycle.files.length} files (digest ${m.conditions.lifecycle.digest.slice(0, 16)}…), verifier ${m.conditions.verifier.files.length} files (digest ${m.conditions.verifier.digest.slice(0, 16)}…)`);
console.log(out);
EOF

[ -n "$sandbox" ] || exit 0

# ---- the lifecycle workspace
mkdir -p "$sandbox"
sandbox=$(cd "$sandbox" && pwd)
if [ -n "$(ls -A "$sandbox")" ]; then echo "sandbox $sandbox is not empty" >&2; exit 2; fi
[ -d "$repo/ts/node_modules/@noble/ed25519" ] && [ -d "$repo/ts/node_modules/typescript" ] ||
  { echo "needs ts/node_modules (cd ts && npm ci) to build REV's ts/src" >&2; exit 2; }
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
git archive "$full" ts | tar -x -C "$build"
ln -s "$repo/ts/node_modules" "$build/ts/node_modules"
(cd "$build/ts" && node node_modules/typescript/bin/tsc)
cp -R "$out/lifecycle/." "$sandbox/"
mkdir -p "$sandbox/ts/dist" "$sandbox/ts/node_modules/@noble" "$sandbox/node_modules" "$sandbox/out"
for f in sigelo.js jcs.js monero.js; do cp "$build/ts/dist/$f" "$sandbox/ts/dist/"; done
cp -R "$repo/ts/node_modules/@noble/ed25519" "$repo/ts/node_modules/@noble/hashes" "$sandbox/ts/node_modules/@noble/"
cat > "$sandbox/ts/package.json" <<EOF
{ "name": "sigelo", "version": "0.1.0", "private": true, "type": "module", "main": "dist/sigelo.js",
  "exports": { ".": "./dist/sigelo.js" }, "description": "built from $full" }
EOF
ln -s ../ts "$sandbox/node_modules/sigelo"
(cd "$sandbox" && node --input-type=module -e "const s = await import('sigelo'); if (typeof s.verify !== 'function') process.exit(1)") ||
  { echo "sandbox: import('sigelo') failed" >&2; exit 1; }
echo "sandbox $sandbox: docs of $short + ts runtime; import('sigelo') ok; candidate writes to $sandbox/out"
