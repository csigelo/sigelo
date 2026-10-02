#!/bin/sh
# SPDX-License-Identifier: MIT
# site/test/collect.sh <workspace> <run-dir> — gather a TASK-site.md candidate's out/ files and the
# mock world's own state into the layout grade-site.mjs reads. The task says "run the world from $W",
# but a candidate may run it from a subdirectory (the 2026-10-01 Haiku run used $W/agent/), so the
# world state is searched for anywhere under the workspace except node_modules.
set -eu
W=${1:?workspace}; R=${2:?run-dir}
mkdir -p "$R/_world"
cp "$W"/out/* "$R"/
for f in world.local.json challenge.local.json; do
  p=$(find "$W" -name "$f" -not -path '*/node_modules/*' 2>/dev/null | head -n1)
  [ -n "$p" ] && cp "$p" "$R/_world/"
done
echo "$R"
