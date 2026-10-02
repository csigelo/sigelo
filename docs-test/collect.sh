#!/bin/sh
# SPDX-License-Identifier: MIT
# Collect a lifecycle run for grading:  docs-test/collect.sh <workspace> <dest>
# Copies <workspace>/out/ to <dest>/ and the mock world's state (world.local.json, the world's
# identity; challenge.local.json, its outstanding challenges) to <dest>/_world/, which grade.mjs uses
# to check that issued.json and challenge-2.json came from examples/world.mjs. Refuses to
# overwrite. The transcript is collected separately (README.md).
set -eu
[ $# -eq 2 ] || { echo "usage: collect.sh <workspace> <dest>" >&2; exit 2; }
ws=$1 dest=$2
[ -d "$ws/out" ] || { echo "no $ws/out" >&2; exit 2; }
[ ! -e "$dest" ] || { echo "$dest exists" >&2; exit 2; }
mkdir -p "$dest/_world"
cp -R "$ws/out/." "$dest/"
for f in world.local.json challenge.local.json; do
  if [ -f "$ws/$f" ]; then cp "$ws/$f" "$dest/_world/"; else echo "warning: no $ws/$f (the candidate did not run the world from the workspace root)" >&2; fi
done
echo "$dest"
