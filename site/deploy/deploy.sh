#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/deploy.sh — build, test, upload and verify https://sigelo.io in one command.
#
#   site/deploy/deploy.sh <user@host> [--os debian|alpine] [--dry-run] [--no-config]
#                         [--origin URL] [--allow-dirty]
#   site/deploy/deploy.sh <user@host> --rollback [--dry-run] [--origin URL]
#
#   1. refuses a dirty working tree (the deployed index.json names the commit; check.mjs
#      compares it with HEAD), then `node site/build.mjs` and `node site/test/run.mjs`: any
#      FAIL and nothing is uploaded;
#   2. uploads site/dist/ into <webroot>/dist.new on the server — rsync --delete when both sides
#      have rsync, otherwise `tar | ssh` — then swaps it in: dist → dist.prev, dist.new → dist
#      (an identical upload is discarded, so re-running keeps the real previous version);
#   2b. links dist/releases -> ../releases in every upload: the release mirror
#      (site/deploy/mirror-release.sh) lives in <webroot>/releases, outside dist, so a deploy
#      never deletes it, and nginx reaches it through dist (its one site root);
#   3. uploads site/deploy/nginx.conf to <webroot>/deploy/ and runs, through sudo, the one root
#      command the deploy user may run: /usr/local/sbin/sigelo-nginx-apply (allowlist, install,
#      nginx -t, reload; restores the old file if the test fails). --no-config skips it;
#   3b. ships the world service (world/server.mjs, mcp.mjs and conformance.mjs, test-vectors.json
#      — the bytes the site serves, so the world names the same sha256 — + the built ts/ library and its @noble
#      dependencies) into <webroot>/world-app (previous kept as world-app.prev) and, once
#      server-setup.sh --world installed it, restarts it through the deploy user's second and last
#      sudo command, /usr/local/sbin/sigelo-world-apply (after the nginx step below);
#   4. node site/deploy/check.mjs --origin <origin>: exit status is the check's (set -e stops
#      here on a failure); then, for https://sigelo.io only, site/deploy/indexnow.sh submits the
#      sitemap's URLs to IndexNow (it never fails the deploy).
#
# --rollback swaps dist and dist.prev on the server (no build, no sudo), then checks with
# --any-commit. Run it again to roll forward.
#
# The server is prepared ONCE by site/deploy/server-setup.sh (as root, by hand; see
# site/deploy/README.md). The SSH user is the unprivileged `sigelo`, owner of the web root.
# SSH options (key, port) go in ~/.ssh/config or SIGELO_SSH, e.g.
#   SIGELO_SSH='ssh -i ~/.ssh/sigelo_deploy -p 22' site/deploy/deploy.sh sigelo@sigelo.io
# Every step is printed (`+ command`) before it runs; --dry-run prints them and runs nothing
# (not even the build). Idempotent: re-running a deploy of the same commit changes nothing.
set -eu

# SIGELO_WEBROOT exists for the local end-to-end test (a fake ssh into a scratch directory);
# on a real server the web root is fixed by server-setup.sh and sigelo-nginx-apply.
WEBROOT=${SIGELO_WEBROOT:-/var/www/sigelo.io}
case $WEBROOT in /*) ;; *) echo "deploy.sh: SIGELO_WEBROOT must be absolute" >&2; exit 1 ;; esac
printf '%s' "$WEBROOT" | grep -Eq '^[A-Za-z0-9/._-]+$' || { echo "deploy.sh: SIGELO_WEBROOT: letters, digits, / . _ - only" >&2; exit 1; }
APPLY=/usr/local/sbin/sigelo-nginx-apply
WORLD_APPLY=/usr/local/sbin/sigelo-world-apply

die() { printf 'deploy.sh: %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
usage() { sed -n '5,7p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

codehash=""; target=""; os=""; dry=0; noconfig=0; rollback=0; origin=https://sigelo.io; dirty_ok=0
while [ $# -gt 0 ]; do
  case $1 in
    --os) [ $# -ge 2 ] || usage; os=$2; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --no-config) noconfig=1; shift ;;
    --rollback) rollback=1; shift ;;
    --origin) [ $# -ge 2 ] || usage; origin=$2; shift 2 ;;
    --allow-dirty) dirty_ok=1; shift ;;
    -h|--help) usage ;;
    -*) die "unknown option: $1" ;;
    *) [ -z "$target" ] || die "one target only (got '$target' and '$1')"; target=$1; shift ;;
  esac
done
[ -n "$target" ] || usage
# user@host or an ~/.ssh/config alias; nothing a remote shell could read as an option or command
printf '%s' "$target" | grep -Eq '^([A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.:-]*$' || die "target must look like user@host: $target"
case $os in ""|debian|alpine) ;; *) die "--os must be debian or alpine" ;; esac
case $origin in https://*|http://*) ;; *) die "--origin must be an http(s) URL" ;; esac

SSH=${SIGELO_SSH:-ssh}
root=$(cd "$(dirname "$0")/../.." && pwd)
dist=$root/site/dist

# run: print, then run unless --dry-run. rsh: the same for a command run on the server.
run() { printf '+ %s\n' "$*"; [ "$dry" = 1 ] || "$@"; }
rsh() { printf '+ %s %s %s\n' "$SSH" "$target" "'$1'"; [ "$dry" = 1 ] || $SSH "$target" "$1"; }

checkflags=""
case $origin in http://*) checkflags="--no-tls" ;; esac
[ "$origin" = https://sigelo.io ] || checkflags="$checkflags --no-www"

[ "$dry" = 0 ] || echo "deploy.sh: DRY RUN — printing the plan, running nothing"
echo "deploy.sh: target $target, web root $WEBROOT, origin $origin"
command -v node >/dev/null || die "node is required"
command -v "${SSH%% *}" >/dev/null || die "${SSH%% *} not found"

if [ "$rollback" = 1 ]; then
  step "rollback: swap dist and dist.prev on the server"
  rsh "set -e; cd $WEBROOT; test -d dist.prev || { echo \"no dist.prev to roll back to\" >&2; exit 1; }; rm -rf dist.swap; mv dist dist.swap; mv dist.prev dist; mv dist.swap dist.prev; test -e dist/releases || ln -s ../releases dist/releases; echo \"now serving the previous upload\""
  step "post-deploy check (any commit: a rollback serves an older build)"
  run node "$root/site/deploy/check.mjs" --origin "$origin" --any-commit $checkflags
  exit 0
fi

step "1/4 preflight"
if [ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]; then
  if [ "$dirty_ok" = 1 ] || [ "$dry" = 1 ]; then echo "warning: uncommitted changes; the build says dirty and check.mjs will fail its commit check"
  else die "uncommitted changes: commit first (index.json names the commit), or --allow-dirty for a staging push"; fi
fi
head=$(git -C "$root" rev-parse HEAD)
echo "HEAD $head"

step "2/4 build and test (nothing is uploaded unless every check passes)"
run node "$root/site/build.mjs"
log=${TMPDIR:-/tmp}/sigelo-site-test.$$.log
printf '+ node %s > %s\n' "$root/site/test/run.mjs" "$log"
if [ "$dry" = 0 ]; then
  if ! node "$root/site/test/run.mjs" >"$log" 2>&1; then grep -E '^FAIL' "$log" >&2 || tail -20 "$log" >&2; die "site/test/run.mjs failed (full log: $log); nothing deployed"; fi
  tail -1 "$log"; rm -f "$log"
  [ -f "$dist/index.html" ] || die "no $dist/index.html after the build"
fi

step "3/4 upload site/dist → $target:$WEBROOT/dist (previous kept as dist.prev)"
mode=tar
if command -v rsync >/dev/null 2>&1; then
  if [ "$dry" = 1 ]; then mode=rsync; echo "(rsync here; the server's rsync is checked at run time, tar | ssh if it has none)"
  elif $SSH "$target" 'command -v rsync >/dev/null 2>&1'; then mode=rsync
  else echo "no rsync on the server: tar | ssh"; fi
else
  echo "no rsync on this host: tar | ssh"
fi
rsh "set -e; test -d $WEBROOT -a -w $WEBROOT || { echo \"$WEBROOT missing or not writable: run server-setup.sh first\" >&2; exit 1; }; rm -rf $WEBROOT/dist.new; mkdir -p $WEBROOT/deploy"
if [ "$mode" = rsync ]; then
  # seed dist.new with the live tree so rsync sends only what changed (rsync replaces files by
  # rename, never in place, so the copy cannot alter dist)
  rsh "set -e; cd $WEBROOT; if [ -d dist ]; then cp -a dist dist.new; else mkdir dist.new; fi"
  run rsync -rlt --delete --chmod=D755,F644 -e "$SSH" "$dist/" "$target:$WEBROOT/dist.new/"
else
  printf '+ tar -C %s -cf - . | %s %s %s\n' "$dist" "$SSH" "$target" "'set -e; mkdir $WEBROOT/dist.new; tar -xf - -C $WEBROOT/dist.new'"
  [ "$dry" = 1 ] || tar -C "$dist" -cf - . | $SSH "$target" "set -e; mkdir $WEBROOT/dist.new; tar -xf - -C $WEBROOT/dist.new"
fi
rsh "set -e; cd $WEBROOT; mkdir -p releases; rm -f dist.new/releases; ln -s ../releases dist.new/releases; find dist.new -type d -exec chmod 755 {} +; find dist.new -type f -exec chmod 644 {} +; test -f dist.new/index.html; if [ -d dist ] && diff -r dist dist.new >/dev/null 2>&1; then rm -rf dist.new; echo \"unchanged: same files already live, dist.prev kept\"; else if [ -d dist ]; then rm -rf dist.prev; mv dist dist.prev; fi; mv dist.new dist; echo \"swapped: dist.prev = the previous upload\"; fi"

step "3b/4 the world service → $target:$WEBROOT/world-app (previous kept as world-app.prev)"
run sh -c "cd '$root/ts' && npx tsc"
stage=${TMPDIR:-/tmp}/sigelo-world-app.$$
printf '+ stage world/{server,mcp,conformance}.mjs, test-vectors.json, ts/package.json, ts/dist/*.js (no tests), ts/node_modules/@noble in %s\n' "$stage"
if [ "$dry" = 0 ]; then
  rm -rf "$stage"; mkdir -p "$stage/world" "$stage/ts/dist" "$stage/ts/node_modules"
  cp "$root/world/server.mjs" "$root/world/mcp.mjs" "$root/world/conformance.mjs" "$stage/world/"; cp "$root/test-vectors.json" "$stage/"; cp "$root/ts/package.json" "$stage/ts/"
  for f in "$root"/ts/dist/*.js; do case ${f##*/} in test.js|gen_vectors.js) ;; *) cp "$f" "$stage/ts/dist/" ;; esac; done
  cp -R "$root/ts/node_modules/@noble" "$stage/ts/node_modules/"
  # the same hash sigelo-world-apply logs for the code it installs: the two must match
  if command -v sha256sum >/dev/null 2>&1; then sum="sha256sum"; else sum="shasum -a 256"; fi
  codehash=$(cd "$stage" && find . -type f | LC_ALL=C sort | while IFS= read -r f; do $sum "$f"; done | $sum | cut -d' ' -f1)
  echo "+ world code sha256 $codehash"
fi
printf '+ tar -C %s -cf - . | %s %s %s\n' "$stage" "$SSH" "$target" "'… world-app.new, swap'"
[ "$dry" = 1 ] || tar -C "$stage" -cf - . | $SSH "$target" "set -e; cd $WEBROOT; rm -rf world-app.new; mkdir world-app.new; tar -xf - -C world-app.new; chmod -R go-w,a+rX world-app.new; if [ -d world-app ]; then rm -rf world-app.prev; mv world-app world-app.prev; fi; mv world-app.new world-app"
[ "$dry" = 1 ] || rm -rf "$stage"

step "4/4 web server config (nginx), the world restart, then the post-deploy check"
if [ "$noconfig" = 1 ]; then
  echo "--no-config: the installed nginx config is left as it is"
else
  printf '+ %s %s %s < %s\n' "$SSH" "$target" "'cat > $WEBROOT/deploy/nginx.conf'" "$root/site/deploy/nginx.conf"
  [ "$dry" = 1 ] || $SSH "$target" "cat > $WEBROOT/deploy/nginx.conf" <"$root/site/deploy/nginx.conf"
  rsh "sudo -n $APPLY${os:+ --os $os}"
fi
wout=$(rsh "if [ -x $WORLD_APPLY ]; then sudo -n $WORLD_APPLY; else echo \"world not installed yet (server-setup.sh --world): code shipped, nothing restarted\"; fi") || { printf '%s\n' "$wout"; die "sigelo-world-apply failed"; }
printf '%s\n' "$wout"
# the helper logs the sha256 of the code it installed (journal tag sigelo-world-apply): it must be what was staged here
case $wout in *"code sha256 "*) case $wout in *"code sha256 $codehash"*) ;; *) die "the server installed world code other than what was staged here (sha256 $codehash)" ;; esac ;; esac
run node "$root/site/deploy/check.mjs" --origin "$origin" --commit "$head" $checkflags
# IndexNow: only for the real site (the key file is published at https://sigelo.io/<key>.txt)
if [ "$origin" = https://sigelo.io ] && [ -x "$root/site/deploy/indexnow.sh" ]; then
  if [ "$dry" = 1 ]; then "$root/site/deploy/indexnow.sh" --dry-run; else "$root/site/deploy/indexnow.sh"; fi
fi
[ "$dry" = 1 ] && echo "deploy.sh: dry run complete; nothing was run" || echo "deploy.sh: deployed $head to $origin"
