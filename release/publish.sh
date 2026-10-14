#!/bin/sh
# SPDX-License-Identifier: MIT
# release/publish.sh — the PUBLIC exports of this repository (ROADMAP §5.1).
#
#   SIGELO_AUTHOR='csigelo <csigelo@users.noreply.github.com>' SIGELO_GO_MODULE=github.com/csigelo/sigelo/go \
#     release/publish.sh [--fresh [--i-know-this-rewrites-history]] [outdir]
#                                                                  default outdir: ../sigelo-public
#   SIGELO_AUTHOR=… release/publish.sh --relay [--fresh [--i-know-this-rewrites-history]] <outdir>
#                                                                  relay/ alone, for csigelo/sigelo-relay
#
# The private history carries the maintainer's name, e-mail, time zone and device in old
# commits, so the public repository is not a rewrite of it. Its history is its own, and it is
# never rewritten once pushed (anyone may have cloned it). Two modes:
#
#   update  outdir is a public clone (a .git with a remote `origin` and at least one commit;
#           since the first push on 2026-10-01, ../sigelo-public): the export tree is built in
#           a temporary directory, gated and tested there, then synced over the clone's working
#           tree (rsync --delete, or remove-every-tracked-file + tar copy; .git is never
#           touched), and if anything changed ONE commit is added on top of `main`: authored by
#           SIGELO_AUTHOR, unsigned whatever the git config says, dated UTC, subject `sync: <the private CHANGELOG's topmost
#           "## unreleased — …" heading>`, body `private tree <HEAD short sha>`. Nothing is
#           pushed; the push command is printed. No change: says so and exits 0.
#   fresh   outdir is empty or does not exist (or --fresh): a NEW git repository with ONE root
#           commit holding the export tree — how bca5b16 was made. Fresh mode deletes outdir and
#           makes it anew, so it refuses (check fresh_outdir) anything but a missing or empty
#           directory or a repository an earlier run made for the same export: its one root
#           commit authored by SIGELO_AUTHOR with subject `sigelo v0.1 draft…` (main) or
#           `sync: sigelo-relay …` (--relay), and no other commit unless --fresh is given. A
#           mistyped outdir (`..`, a home directory) is refused, --fresh or not. Against an outdir
#           with a remote, --fresh refuses unless also given --i-know-this-rewrites-history
#           (pushing it would need a force push).
#
# The main export tree is the same in both modes: the tracked tree of HEAD minus the internal paths
# (DEFAULT_EXCLUDE below: RISKS.md, JOURNAL.md, commercial/, relay/, design/relay-plan.md) and
# SIGELO_EXCLUDE, and those paths' word budgets; the optional Go module rewrite; the CHANGELOG
# preface. A Markdown link into a path left out refuses the export (md_links). relay/ is AGPL and has its own public repository, so it never goes out with the MIT one.
#
# --relay exports relay/ alone (AGPL, its own LICENSE): the tracked files under relay/ at the root
# of outdir (LICENSE, README.md, package files, deploy/, site/, test/, the code; never node_modules
# or site/dist), plus a .gitignore for those two when relay/ has none. Before anything is written,
# every relative import must resolve inside the export and every package import must be declared
# in its package.json (the export has to run on its own), relay/licence.ts must be spend/licence.ts
# at HEAD byte for byte (the keeper's licence rules, copied), every package in package-lock.json
# must be pinned by its registry URL and sha512 integrity (lockfile_pinned; the main export checks
# each of its lockfiles alike), no Markdown file may link outside the export (md_links; the main
# export refuses links into the paths it leaves out alike), and the word budgets docs-test/budgets.json
# sets for relay/ paths apply to the exported files. Same modes, same author rules, same identity
# gate; one commit, subject `sync: sigelo-relay <package version>`. Its tests: npm ci, npm test and
# node test/allowance.mjs, the nginx allowlist of deploy/sigelo-relay-apply (--self-test, --check
# deploy/nginx.conf), deploy/test-deploy.sh, deploy/backup.sh --self-test, then node site/build.mjs
# and node site/test.mjs. outdir is required; an
# outdir whose origin is not a sigelo-relay repository is refused (and the main export refuses one
# that is): a sync replaces every tracked file of outdir. Before
# anything is written to outdir, that FINAL tree is grepped for identity strings: the private
# list in SIGELO_DEVICE_STRINGS (default ~/.config/sigelo/device-strings, one extended regex
# per line, kept OUTSIDE the repository —
# the same list belongs in the GitHub secret DEVICE_STRINGS that
# .github/workflows/conformance.yml reads on every push). One hit and nothing is written. In
# update mode the staged clone is grepped again after the sync (`git grep --cached`) and its
# tree must equal the gated one; any failure after the sync restores the clone's index and
# working tree (reset, checkout, clean -fd) before exiting.
#
# Environment:
#   SIGELO_AUTHOR          required: the project pseudonym, `Name <email>` (never the real one);
#                          decided at D1: `csigelo <csigelo@users.noreply.github.com>`
#   SIGELO_DEVICE_STRINGS  the private pattern file (see above)
#   SIGELO_GO_MODULE       optional: rewrite the Go module path (bare `sigelo` today) to e.g.
#                          github.com/csigelo/sigelo/go, in go.mod and the one import of it
#   SIGELO_EXCLUDE         optional: paths to leave out of the main export besides DEFAULT_EXCLUDE,
#                          space-separated; their entries in docs-test/budgets.json are dropped with them
#   SIGELO_SKIP_TESTS=1    skip running every suite on the export tree (they are the proof; ~10 min)
#   SIGELO_TEST_FAIL_AFTER_SYNC=1   test hook: fail after an update-mode sync, before the
#                          commit, to prove the clone is restored
#
# Commit hashes cited in the docs refer to the private history; the export says so in
# CHANGELOG.md.
set -eu

die() {
  echo "publish.sh: $*" >&2
  if [ "${synced:-0}" = 1 ]; then
    git -C "$out" reset -q && git -C "$out" checkout -q -- . && git -C "$out" clean -qfd \
      && echo "publish.sh: $out restored to $(git -C "$out" rev-parse --short HEAD), nothing committed" >&2 \
      || echo "publish.sh: RESTORE OF $out FAILED — inspect it before anything else" >&2
  fi
  exit 1
}
# lockfile_pinned FILE: every package npm ci fetches for FILE is pinned by its hash. npm checks a
# tarball only against its lockfile entry's integrity: an entry without one installs whatever the
# registry of the installing user's npm config serves (deploy.sh installs the relay's so, and root
# on the host runs them). So each entry under node_modules that is not a link to a local directory
# must carry resolved https://registry.npmjs.org/… and a sha512 integrity; the first that does not
# is named. Local directories (an entry outside node_modules) are part of the export itself.
lockfile_pinned() {
  node -e '
    const f = process.argv[1], l = JSON.parse(require("node:fs").readFileSync(f, "utf8"));
    if (!(l.lockfileVersion >= 2) || typeof l.packages !== "object" || l.packages === null) { console.error(`${f}: no "packages" (lockfileVersion 2 or 3)`); process.exit(1); }
    for (const [p, e] of Object.entries(l.packages)) {
      if (!/(^|\/)node_modules\//.test(p) || e.link === true) continue;
      if (!/^https:\/\/registry\.npmjs\.org\//.test(e.resolved ?? "") || !/^sha512-[A-Za-z0-9+\/]{86}==$/.test(e.integrity ?? "")) {
        console.error(`${f}: ${p} has no resolved https://registry.npmjs.org/… with a sha512 integrity`);
        process.exit(1);
      }
    }' "$1"
}
# md_links ROOT [PATH...]: no Markdown file under ROOT links (inline `](…)` or a reference
# definition) to a relative target outside ROOT or under one of the PATHs, which the export leaves
# out: in the public repository such a link is dead (contact/README.md linked ../relay/README.md,
# relay/ being exported alone). URLs, fragments and root-relative links (site pages) are not
# checked; a path cited in prose or code is not a link and is left to review.
md_links() {
  node -e '
    const fs = require("node:fs"), path = require("node:path");
    const [root, ...paths] = process.argv.slice(1);
    const out = paths.map((p) => path.join(root, p.replace(/\/+$/, "")));
    const RE = /\]\(\s*<?([^)\s>]+)|^\s{0,3}\[[^\]]+\]:\s*<?([^\s>]+)/g;
    const bad = [];
    const check = (file) => fs.readFileSync(file, "utf8").split("\n").forEach((line, i) => {
      for (const m of line.matchAll(RE)) {
        const link = m[1] ?? m[2], t = link.split("#")[0];
        if (t === "" || t.startsWith("/") || /^[a-z][a-z0-9+.-]*:/i.test(t)) continue;
        const target = path.resolve(path.dirname(file), t);
        if (!target.startsWith(root + path.sep) || out.some((p) => target === p || target.startsWith(p + path.sep)))
          bad.push(`${path.relative(root, file)}:${i + 1} links ${link}, which is not in the export`);
      }
    });
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p); else if (e.name.endsWith(".md")) check(p);
      }
    };
    walk(root);
    if (bad.length) { console.error(bad.join("\n")); process.exit(1); }
  ' "$@"
}
# Internal or separately published: never in the main export, whatever SIGELO_EXCLUDE says.
DEFAULT_EXCLUDE="RISKS.md JOURNAL.md commercial relay design/relay-plan.md"
fresh=0 rewrite_ok=0 relay=0
while [ $# -gt 0 ]; do
  case $1 in
    --fresh) fresh=1 ;;
    --i-know-this-rewrites-history) rewrite_ok=1 ;;
    --relay) relay=1 ;;
    -*) die "unknown option $1" ;;
    *) break ;;
  esac
  shift
done
[ $# -le 1 ] || die "usage: publish.sh [--relay] [--fresh [--i-know-this-rewrites-history]] [outdir]"
[ $relay = 0 ] || [ $# = 1 ] || die "--relay needs its outdir (a clone of the sigelo-relay repository, or a new directory)"
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/../sigelo-public}
case $out in /*) ;; *) out=$(pwd)/$out ;; esac
patterns=${SIGELO_DEVICE_STRINGS:-$HOME/.config/sigelo/device-strings}

[ -n "${SIGELO_AUTHOR:-}" ] || die "SIGELO_AUTHOR='Name <email>' is required (the project pseudonym)"
case $SIGELO_AUTHOR in *"<"*"@"*">"*) ;; *) die "SIGELO_AUTHOR must look like 'Name <email>'" ;; esac
name=${SIGELO_AUTHOR%%<*}; name=$(printf '%s' "$name" | sed 's/[[:space:]]*$//')
email=${SIGELO_AUTHOR#*<}; email=${email%>*}
[ -f "$patterns" ] || die "no private pattern file at $patterns (SIGELO_DEVICE_STRINGS): one extended regex per line; refusing to export unchecked"
[ -z "$(git -C "$root" status --porcelain)" ] || die "the working tree has uncommitted changes; export from a commit"
command -v node >/dev/null || die "node is required"
[ $relay = 1 ] || command -v go >/dev/null || die "go is required"
[ "$(git -C "$root" rev-parse --show-toplevel)" != "$(cd "$out" 2>/dev/null && git rev-parse --show-toplevel 2>/dev/null || echo none)" ] || die "outdir is inside this repository"

# The mode. A remote means a published repository: only update mode may touch it, unless the
# maintainer explicitly asks for a history rewrite.
has_remote=0 has_commit=0
if [ -d "$out/.git" ]; then
  git -C "$out" remote get-url origin >/dev/null 2>&1 && has_remote=1
  git -C "$out" rev-parse -q --verify HEAD >/dev/null 2>&1 && has_commit=1
fi
# The two public repositories must never be synced over each other: a sync deletes what it does
# not export.
if [ $has_remote = 1 ]; then
  url=$(git -C "$out" remote get-url origin)
  case $url in
    *sigelo-relay*) [ $relay = 1 ] || die "$out's origin is $url, the relay's repository: the main export goes elsewhere (--relay for this one)" ;;
    *) [ $relay = 0 ] || die "--relay: $out's origin is $url, not a sigelo-relay repository" ;;
  esac
fi
# Fresh mode ends in `rm -rf "$out"`. It may only replace what nothing but this script made: a
# missing or empty directory, or the repository of an earlier fresh export of the same kind. A
# typo in outdir must never delete a directory (`..` from the repository is its parent folder).
if [ $relay = 1 ]; then root_subject='sync: sigelo-relay '; else root_subject='sigelo v0.1 draft'; fi
fresh_outdir() {  # fails, with $why, unless fresh mode may delete $out
  why=""
  [ -e "$out" ] || [ -L "$out" ] || return 0
  if [ -L "$out" ] || [ ! -d "$out" ]; then why="$out is not a directory"; return 1; fi
  [ -n "$(ls -A "$out")" ] || return 0
  if [ ! -d "$out/.git" ] || [ "$(git -C "$out" rev-parse --show-toplevel 2>/dev/null)" != "$(cd "$out" && pwd -P)" ]; then
    why="$out is not empty and not a git repository"; return 1
  fi
  roots=$(git -C "$out" rev-list --max-parents=0 HEAD 2>/dev/null || true)
  [ -n "$roots" ] && [ "$(printf '%s\n' "$roots" | wc -l)" -eq 1 ] || { why="$out has no commit, or more than one root commit"; return 1; }
  [ "$(git -C "$out" log -1 --format='%an <%ae>' "$roots")" = "$name <$email>" ] || { why="$out's root commit is not authored by $name <$email>"; return 1; }
  case $(git -C "$out" log -1 --format=%s "$roots") in "$root_subject"*) ;; *) why="$out's root commit subject does not start with '$root_subject'"; return 1 ;; esac
  n=$(git -C "$out" rev-list --count HEAD)
  [ "$n" -eq 1 ] || [ $fresh = 1 ] || { why="$out holds $n commits, not only publish.sh's root commit (--fresh replaces it)"; return 1; }
}
if [ $fresh = 1 ]; then
  [ $has_remote = 0 ] || [ $rewrite_ok = 1 ] || die "--fresh refused: $out has a remote origin ($(git -C "$out" remote get-url origin)); a fresh root commit pushed there rewrites public history. Run without --fresh to update, or add --i-know-this-rewrites-history"
  mode=fresh
elif [ $has_remote = 1 ] && [ $has_commit = 1 ]; then
  mode=update
elif [ $has_remote = 1 ]; then
  die "$out has a remote origin but no commit; refusing to guess (--fresh --i-know-this-rewrites-history replaces it)"
else
  mode=fresh
fi
if [ $mode = fresh ]; then
  fresh_outdir || die "fresh mode deletes outdir and makes it anew; refused (check fresh_outdir): $why. Name a new or empty directory, or an earlier fresh export of this kind"
fi
if [ $mode = update ]; then
  [ "$(git -C "$out" symbolic-ref -q --short HEAD || true)" = main ] || die "update mode: $out is not on branch main"
  [ -z "$(git -C "$out" status --porcelain)" ] || die "update mode: $out has uncommitted changes: $(git -C "$out" status --porcelain | head -5)"
fi
if [ $relay = 1 ]; then echo "publish.sh: relay export, $mode mode -> $out"; else echo "publish.sh: $mode mode -> $out"; fi

src=$(git -C "$root" rev-parse --short HEAD)
work=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-publish.XXXXXX")
trap 'rm -rf "$work"' EXIT
stage=$work/tree

if [ $relay = 1 ]; then
  # R1. relay/ alone, at the root of the export: the tracked files under it at HEAD (no
  #     node_modules, no site/dist), and the files a repository of its own needs.
  git -C "$root" archive --format=tar HEAD relay | tar -x -C "$work" || die "git archive of relay/ at HEAD failed"
  mv "$work/relay" "$stage"
  for f in LICENSE README.md package.json package-lock.json; do
    [ -f "$stage/$f" ] || die "relay/$f missing: the relay export must carry it"
  done
  # A clone used for a deploy runs npm ci and builds site/dist: neither may show as a change.
  [ -f "$stage/.gitignore" ] || printf 'node_modules/\ndist/\n' > "$stage/.gitignore"
  # R1b. licence.ts is the keeper's spend/licence.ts, copied so that relay/ runs alone; a copy that
  #      differs would check licences by rules the keeper no longer has (relay/site/test.mjs checks
  #      the working tree, this the commit being exported).
  git -C "$root" show HEAD:spend/licence.ts > "$work/keeper-licence.ts" || die "no spend/licence.ts at HEAD"
  cmp -s "$work/keeper-licence.ts" "$stage/licence.ts" || die "relay/licence.ts is not spend/licence.ts at HEAD byte for byte (check licence_copy): cp spend/licence.ts relay/licence.ts, commit, re-run"
  # R2. The export runs on its own: every relative import resolves to a file inside it, every
  #     package import is declared in its package.json. Static imports at the start of a line and
  #     import('…') calls; a hit inside a comment or string refuses too (reword it).
  node -e '
    const fs = require("node:fs"), path = require("node:path"), { builtinModules } = require("node:module");
    const root = process.argv[1];
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const declared = new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})]);
    const RE = /^\s*(?:import|export)\b[^;"\x27]*?\bfrom\s*(["\x27])([^"\x27\s]+)\1|^\s*import\s*(["\x27])([^"\x27\s]+)\3|\bimport\(\s*(["\x27])([^"\x27\s]+)\5\s*\)/gm;
    const bad = [];
    const check = (file) => {
      for (const m of fs.readFileSync(file, "utf8").matchAll(RE)) {
        const spec = m[2] ?? m[4] ?? m[6], where = `${path.relative(root, file)} imports ${spec}`;
        if (spec.startsWith(".")) {
          const target = path.resolve(path.dirname(file), spec);
          if (!target.startsWith(root + path.sep) || !fs.existsSync(target)) bad.push(`${where}: not a file inside the export`);
        } else if (!spec.startsWith("node:") && !builtinModules.includes(spec)) {
          const name = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
          if (!declared.has(name)) bad.push(`${where}: ${name} is not in its package.json`);
        }
      }
    };
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p); else if (/\.(mjs|cjs|js|ts)$/.test(e.name)) check(p);
      }
    };
    walk(root);
    if (bad.length) { console.error(bad.join("\n")); process.exit(1); }
  ' "$stage" || die "the relay export would not run on its own (above): fix relay/ in the private tree"
  # R2b. Every package the export installs is pinned by hash (lockfile_pinned).
  lockfile_pinned "$stage/package-lock.json" || die "relay/package-lock.json pins a package without its hash (above): regenerate it from the registry (no node_modules, no local link), commit, re-run"
  # R2c. No Markdown link out of relay/: the export holds nothing beside it.
  md_links "$stage" || die "relay/ links outside itself (above), dead in csigelo/sigelo-relay: link the public repository's URL instead"
  # R3. The word budgets docs-test/budgets.json (at HEAD) sets for relay/ paths, applied to the
  #     exported files and counted as docs-test/check-budgets.mjs counts (runs of non-whitespace).
  git -C "$root" show HEAD:docs-test/budgets.json > "$work/budgets.json" || die "no docs-test/budgets.json at HEAD"
  node -e '
    const fs = require("node:fs"), path = require("node:path");
    const [file, root] = process.argv.slice(1);
    const bad = [];
    for (const [p, max] of Object.entries(JSON.parse(fs.readFileSync(file, "utf8")))) {
      if (!p.startsWith("relay/")) continue;
      let words;
      try { words = fs.readFileSync(path.join(root, p.slice("relay/".length)), "utf8").split(/[ \t\n\r\f\v]+/).filter(Boolean).length; }
      catch { bad.push(`${p}: missing from the export`); continue; }
      if (words > max) bad.push(`${p}: ${words} words (budget ${max})`);
    }
    if (bad.length) { console.error(bad.join("\n")); process.exit(1); }
  ' "$work/budgets.json" "$stage" || die "word budgets of the relay export (above)"
else
  mkdir "$stage"
  # 1. The tracked tree of HEAD, and nothing else (no node_modules, dist, *.local.json, .git), less
  #    DEFAULT_EXCLUDE and SIGELO_EXCLUDE.
  git -C "$root" archive --format=tar HEAD | tar -x -C "$stage"
  for p in $DEFAULT_EXCLUDE ${SIGELO_EXCLUDE:-}; do rm -rf "$stage/$p"; done
  # 1b. The word budgets of excluded paths go with them: check-budgets fails on a missing file (it
  #     must, in the private tree), and the public budgets.json must not name internal documents.
  #     The file is rewritten only when an entry is dropped, so it otherwise keeps the private bytes.
  budgets=$stage/docs-test/budgets.json
  if [ -f "$budgets" ]; then
    # Unquoted on purpose: one argument per excluded path, split as the rm loop above splits it.
    # shellcheck disable=SC2086
    node -e '
      const fs = require("node:fs");
      const [file, ...args] = process.argv.slice(1);
      const excluded = args.map((p) => p.replace(/\/+$/, ""));
      const budgets = JSON.parse(fs.readFileSync(file, "utf8"));
      const kept = Object.fromEntries(Object.entries(budgets)
        .filter(([path]) => !excluded.some((p) => path === p || path.startsWith(p + "/"))));
      if (Object.keys(kept).length !== Object.keys(budgets).length)
        fs.writeFileSync(file, JSON.stringify(kept, null, 2) + "\n");
    ' "$budgets" $DEFAULT_EXCLUDE ${SIGELO_EXCLUDE:-} || die "dropping the word budgets of excluded paths from docs-test/budgets.json failed"
  fi
  # 1c. Every package an install from the export fetches is pinned by hash (lockfile_pinned).
  for f in $(cd "$stage" && find . -name package-lock.json -not -path '*/node_modules/*' | LC_ALL=C sort); do
    lockfile_pinned "$stage/$f" || die "${f#./} pins a package without its hash (above): regenerate it from the registry (no node_modules, no local link), commit, re-run"
  done
  # 1d. No Markdown link into what step 1 left out (md_links).
  # shellcheck disable=SC2086
  md_links "$stage" $DEFAULT_EXCLUDE ${SIGELO_EXCLUDE:-} || die "links into paths the main export leaves out (above), dead in csigelo/sigelo: link csigelo/sigelo-relay's URL for relay/, or drop the link"
  # 2. Optional Go module path. The module lives in go/, a subdirectory, so the path must end in
  #    /go, and `go install <path>/cmd/sigelo-verify@v<v>` then resolves the tag go/v<v>, not v<v>
  #    (Go's rule for a module below the repository root); the Next list names both tags. Every Go
  #    file importing the bare path, and any other go.mod requiring or replacing it, is rewritten;
  #    one bare import left refuses the export (the build would fail on it, but only in step 6).
  if [ -n "${SIGELO_GO_MODULE:-}" ]; then
    case $SIGELO_GO_MODULE in
      */go) ;;
      *) die "SIGELO_GO_MODULE must end in /go (the module is the repository's go/ directory), e.g. github.com/csigelo/sigelo/go" ;;
    esac
    printf '%s' "$SIGELO_GO_MODULE" | grep -Eq '^[a-z0-9.-]+\.[a-z]+(/[A-Za-z0-9._-]+)+$' || die "SIGELO_GO_MODULE does not look like a module path: $SIGELO_GO_MODULE"
    sed -i.bak "s#^module sigelo\$#module $SIGELO_GO_MODULE#" "$stage/go/go.mod" && rm -f "$stage/go/go.mod.bak"
    grep -q "^module $SIGELO_GO_MODULE\$" "$stage/go/go.mod" || die "go.mod rewrite failed"
    bare='^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_]*[[:space:]]+)?"sigelo(/[^"]*)?"[[:space:]]*$'
    find "$stage" -name '*.go' -type f | while IFS= read -r f; do
      grep -Eq "$bare" "$f" || continue
      sed -i.bak -E "s#^([[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_]*[[:space:]]+)?)\"sigelo(/[^\"]*)?\"#\\1\"$SIGELO_GO_MODULE\\4\"#" "$f" && rm -f "$f.bak"
    done
    find "$stage" -name go.mod -type f ! -path "$stage/go/go.mod" | while IFS= read -r f; do
      sed -i.bak -E "s#^((require|replace)[[:space:]]+|[[:space:]]+)sigelo([[:space:]])#\\1$SIGELO_GO_MODULE\\3#" "$f" && rm -f "$f.bak"
    done
    left=$(find "$stage" -name '*.go' -type f -exec grep -HnE "$bare" {} + || true)
    [ -z "$left" ] || die "bare Go imports of sigelo left after the module rewrite: $left"
  fi

  # 3. The one line the export adds — once: run against an export (whose CHANGELOG already
  #    carries it), the preface must not be added a second time. The import date is the public
  #    root commit's in update mode (bca5b16: 2026-10-01), so a later sync does not change it.
  if [ $mode = update ]; then
    first=$(git -C "$out" rev-list --max-parents=0 HEAD | tail -n 1)
    imported=$(TZ=UTC git -C "$out" log -1 --format=%cd --date=format-local:%Y-%m-%d "$first")
  else
    imported=$(date -u +%Y-%m-%d)
  fi
  if ! head -n 5 "$stage/CHANGELOG.md" | grep -q '^Short commit hashes cited in this repository'; then
    {
      printf '%s\n\n' '# Changelog'
      printf '%s\n%s\n\n' 'Short commit hashes cited in this repository refer to the pre-publication development' \
        "history, which is not public. This public history starts at the import of $imported."
      sed '1{/^# Changelog$/d;}' "$stage/CHANGELOG.md" | sed '1{/^$/d;}'
    } > "$stage/CHANGELOG.md.new" && mv "$stage/CHANGELOG.md.new" "$stage/CHANGELOG.md"
  fi
fi

# 4. Identity strings, grepped over the FINAL tree (after steps 2 and 3) with `git grep` on a
#    throwaway index of it, so the check runs the same on GNU, busybox, macOS and Git Bash — a
#    plain `grep -r` with GNU-only flags fails on busybox, and a swallowed error would look like
#    a clean pass. `add -f`: a tracked file the .gitignore matches is still exported, so it is
#    still grepped. Exit 0 = hits, 1 = clean, anything else = the grep itself failed; only 1
#    exports. No tracked file holds a pattern — not even a "generic" one (AUDIT A5) — so
#    nothing is excluded, and an empty list refuses to export rather than passing vacuously.
pat=$work/patterns
grep -v '^[[:space:]]*$' "$patterns" > "$pat" || true
[ -s "$pat" ] || die "the pattern file $patterns is empty; refusing to export unchecked"
gate() {  # gate <label> <git command whose index holds the tree>
  label=$1; shift
  set +e
  hits=$("$@" grep -nIiE -f "$pat" --cached 2>&1)
  rc=$?
  set -e
  case $rc in
    0) printf '%s\n' "$hits" | head -40 >&2
       die "identity or device strings in the $label (above): reword them in the private repository, then re-run" ;;
    1) ;;
    *) printf '%s\n' "$hits" >&2
       die "the identity-string grep over the $label itself failed (exit $rc); refusing to export unchecked" ;;
  esac
}
gi() { git --git-dir="$work/gate.git" --work-tree="$stage" "$@"; }
git init -q --bare "$work/gate.git"
gi add -A -f .
gate "export tree" gi
tree=$(gi write-tree)

# 5. The proof: a clean install and every suite, on a copy of the export tree (node_modules
#    and dist stay out of what is committed), before anything is written to outdir.
if [ "${SIGELO_SKIP_TESTS:-}" = 1 ]; then
  echo "publish.sh: tests skipped (SIGELO_SKIP_TESTS=1)"
else
  t=$work/test
  cp -R "$stage" "$t"
  run() { echo "publish.sh: $1"; shift; ( "$@" ) || die "failed: $*"; }
  if [ $relay = 1 ]; then
    run "relay: install + tests" sh -c "cd '$t' && npm ci --ignore-scripts --silent && npm test 2>&1 | tail -1 | grep -q '^ALL PASS'"
    run "relay: allowances, proof of work, operators, licences" sh -c "cd '$t' && node test/allowance.mjs 2>&1 | tail -1 | grep -q '^ALL PASS'"
    run "relay: nginx allowlist (self-test, deploy/nginx.conf)" sh -c "cd '$t' && sh deploy/sigelo-relay-apply --self-test >/dev/null && sh deploy/sigelo-relay-apply --check deploy/nginx.conf >/dev/null"
    run "relay: deploy.sh against a stubbed host (lockfile pins, rollback on a code sha256 mismatch)" sh -c "cd '$t' && sh deploy/test-deploy.sh 2>&1 | tail -1 | grep -q '^ALL PASS'"
    run "relay: the backup's extract holds no mailbox (deploy/backup.sh --self-test)" sh -c "cd '$t' && sh deploy/backup.sh --self-test >/dev/null"
    run "relay: front page build + tests" sh -c "cd '$t' && node site/build.mjs >/dev/null && node site/test.mjs 2>&1 | tail -1 | grep -q '^ALL PASS'"
  else
    run "ts: install + build + vectors + tests" sh -c "cd '$t/ts' && npm ci --ignore-scripts --silent && npx tsc && node dist/gen_vectors.js > '$work/vectors.json' && diff -q ../test-vectors.json '$work/vectors.json' && node dist/test.js | tail -1 | grep -q '^ALL PASS'"
    run "go: vet + tests + static build" sh -c "cd '$t/go' && go vet ./... && go test ./... 2>&1 | tail -2 | grep -q '^ok' && CGO_ENABLED=0 go build ./cmd/sigelo-verify && rm -f sigelo-verify"
    # test-carrier.mjs runs its fixture part only: the export carries no relay/ (it SKIPs the rest); before moadim, whose contact verbs load it by package name
    run "contact: install + tests + fixtures" sh -c "cd '$t/contact' && npm ci --ignore-scripts --silent && node test-invite.mjs | tail -1 | grep -q '^ALL PASS' && node test-envelope.mjs | tail -1 | grep -q '^ALL PASS' && node test-carrier.mjs | tail -1 | grep -q '^ALL PASS' && node gen-invite.mjs --check >/dev/null && node gen-envelope.mjs --check >/dev/null && node gen-carrier.mjs --check >/dev/null"
    run "moadim adapter" sh -c "cd '$t/adapters/moadim' && npm ci --ignore-scripts --silent && npm test 2>&1 | grep -q '^ALL PASS'"
    run "spend keeper" sh -c "cd '$t/spend' && npm ci --ignore-scripts --silent && npm test 2>&1 | grep -q '^ALL PASS'"
    run "mcp server" sh -c "cd '$t/integrations/mcp' && npm test 2>&1 | grep -q 'ALL PASS'"
    run "schemas" sh -c "cd '$t' && node schema/check.mjs | grep -q '^ALL PASS'"
    run "word budgets" sh -c "cd '$t' && node docs-test/check-budgets.mjs | grep -q '^ALL PASS'"
    run "pairing fixtures" sh -c "cd '$t' && node adapters/hermes/pairing/gen.mjs --check >/dev/null"
    run "site deploy: sudo rules (server-setup.sh --self-test)" sh -c "cd '$t' && sh site/deploy/server-setup.sh --self-test >/dev/null"
    run "site deploy: the watchdog's paging rules (watch.sh --self-test)" sh -c "cd '$t' && sh site/deploy/watch.sh --self-test | tail -1 | grep -q '^ALL PASS'"
  fi
  git --git-dir="$work/gate.git" --work-tree="$t" diff --quiet || die "the test run changed exported files: $(git --git-dir="$work/gate.git" --work-tree="$t" diff --stat | tail -5)"
  echo "publish.sh: ALL PASS on the export tree ($tree)"
fi

epoch=$(date -u +%s)
export GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email"
export GIT_AUTHOR_DATE="@$epoch +0000" GIT_COMMITTER_DATE="@$epoch +0000" TZ=UTC
if [ $relay = 1 ]; then
  version=$(node -p 'JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).version' "$stage/package.json") || die "no version in relay/package.json"
  subject="sync: sigelo-relay $version"
else
  heading=$(grep -m 1 '^## unreleased' "$root/CHANGELOG.md" || grep -m 1 '^## ' "$root/CHANGELOG.md" || echo '## export')
  subject="sync: ${heading#\#\# }"
fi

if [ $mode = update ]; then
  # 6u. Sync the gated tree over the clone's working tree; .git is never touched. From here on
  #     any failure restores the clone (die). Ignored files (node_modules, dist) survive the
  #     tar path and are deleted by rsync --delete; neither is ever committed.
  before=$(git -C "$out" rev-parse HEAD)
  synced=1
  if command -v rsync >/dev/null; then
    rsync -a --delete --exclude /.git "$stage/" "$out/" || die "rsync into $out failed"
  else
    ( cd "$out" && git ls-files -z | xargs -0 rm -f -- ) || die "removing the tracked files of $out failed"
    ( cd "$out" && find . -mindepth 1 -type d -empty ! -path ./.git ! -path "./.git/*" -delete ) || die "pruning empty directories in $out failed"
    ( cd "$stage" && tar -cf - . ) | ( cd "$out" && tar -xf - ) || die "copying the export tree into $out failed"
  fi
  git -C "$out" add -A
  git --git-dir="$work/gate.git" ls-files -z | git -C "$out" add -f --pathspec-from-file=- --pathspec-file-nul
  gate "staged public clone" git -C "$out"
  [ "$(git -C "$out" write-tree)" = "$tree" ] || die "the staged clone's tree is not the gated export tree ($tree): $(git -C "$out" diff --cached --stat | tail -3)"
  [ "${SIGELO_TEST_FAIL_AFTER_SYNC:-}" != 1 ] || die "SIGELO_TEST_FAIL_AFTER_SYNC=1: failing after the sync, before the commit"
  if git -C "$out" diff --cached --quiet; then
    synced=0
    echo "publish.sh: no changes — $out already holds the export of private $src ($(git -C "$out" log -1 --format='%h %s'))"
    exit 0
  fi
  # Unsigned, as fresh mode's: a clone's own or the global git config may sign commits with the
  # maintainer's personal key, whose signer would then show on GitHub (the identity gate greps the
  # tree, never the commit object).
  git -C "$out" -c commit.gpgsign=false commit -q -F - <<MSG || die "the commit failed"
$subject

private tree $src
MSG
  synced=0
  [ "$(git -C "$out" rev-parse HEAD^)" = "$before" ] || die "the new commit is not on top of $before"
  echo "publish.sh: $out — one commit on main:"
  git -C "$out" log --oneline -3
  git -C "$out" show --stat --format='%h %an <%ae> %ad' --date=iso-strict HEAD
  printf 'Not pushed. Review, then:\n  git -C "%s" push origin main\n' "$out"
  [ $relay = 1 ] || echo "CI on the push runs the generic leak check (home paths, private addresses outside tests and docs); the private pattern gate already ran here."
  exit 0
fi

# 6f. A fresh repository, one commit, UTC, the pseudonym. outdir checked again: the tests took
#     minutes, and what it holds now is what is deleted.
fresh_outdir || die "fresh mode: refused (check fresh_outdir), outdir changed during the run: $why"
rm -rf "$out"; mkdir -p "$out"
cp -R "$stage/." "$out/"
git -C "$out" init -q -b main
git -C "$out" config user.name "$name"
git -C "$out" config user.email "$email"
git -C "$out" config commit.gpgsign false
git -C "$out" add -A -f .
[ "$(git -C "$out" write-tree)" = "$tree" ] || die "the fresh repository's tree is not the gated export tree ($tree)"
if [ $relay = 1 ]; then
  git -C "$out" commit -q -F - <<MSG
$subject

private tree $src
MSG
  echo "publish.sh: $out — $(git -C "$out" log --format='%h %an <%ae> %ad %s' --date=iso-strict)"
  cat <<NEXT
Next, by the maintainer: review, then push with the project account's own SSH key, e.g.
  cd "$out" && git remote add origin git@github.com:csigelo/sigelo-relay.git && git push -u origin main
Later syncs: release/publish.sh --relay <its clone> (update mode, one commit on top).
NEXT
  exit 0
fi
git -C "$out" commit -q -F - <<MSG
sigelo v0.1 draft (wire sigelo/0): public import

Protocol for portable AI-agent identity (Ed25519 + SHA-256 + JCS, offline verification,
recovery-beats-key) with a Monero payment pillar. SPEC.md is the source of truth;
test-vectors.json the conformance target; go/ the reference verifier; ts/ the TypeScript
implementation; spend/ the keeper; adapters/ and integrations/ the world, agent and harness
sides. Imported from a private development history (source $src).

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
MSG
echo "publish.sh: $out — $(git -C "$out" log --format='%h %an <%ae> %ad' --date=iso-strict)"
cat <<NEXT
Next, by the maintainer (ROADMAP §5.1). The public repository already exists
(github.com/csigelo/sigelo, first push 2026-10-01): a fresh export is for a scratch check or a
deliberate history rewrite only; every sync of the published repository is update mode
(run without --fresh against its clone). For a new repository:
  1. push with the project account's own SSH key (csigelo, contact@sigelo.io), never the personal one
  2. cd "$out" && git remote add origin git@github.com:csigelo/sigelo.git && git push -u origin main
  3. repository secret DEVICE_STRINGS = the contents of $patterns (CI greps every push)
  4. release, ROADMAP T4 (the commands are in release/build.sh's header), in the clone:
       release/build.sh && release/pack-test.sh release/dist        # tarballs, binaries, ALL PASS
       git tag v<version> && git tag go/v<version> && git push origin v<version> go/v<version>
       npm publish release/dist/<pkg>-<version>.tgz                 # in this order: sigelo sigelo-contact sigelo-spend sigelo-agent sigelo-mcp sigelo-recovery-kit
       gh release create v<version> release/dist/sigelo-verify-* release/dist/test-vectors.json release/dist/SHA256SUMS
NEXT
