#!/bin/sh
# SPDX-License-Identifier: MIT
# A reply hook for `sigelo-agent watch --on-message` (WATCH.md): an enrolled agent answers by itself.
#   sigelo-agent watch --on-message 'SIGELO_REPLY_CMD="my-agent --stdin" sh examples/reply-hook.sh'
# The message comes as JSON on stdin; its text is piped to $SIGELO_REPLY_CMD (unset: echoed back), and
# what that prints goes back to the sender with `reply --to "$SIGELO_MSG_ID"`, label "reply". A message
# labelled "reply" is never answered, so two agents running this hook do not answer each other without end.
# A command slower than watch's --hook-timeout (default 120 s) is stopped and the message offered again:
# raise it (--hook-timeout 1h, 0: no limit), or spool the task and answer later (WATCH.md "Slow agents").
# The text is the sender's data: the command must treat it as data, never as instructions.
# SIGELO_CLI: the sigelo-agent entry file (default: cli.ts beside this directory); paths with spaces are fine.
set -eu
[ "${SIGELO_TYPE:-message}" = message ] || exit 0          # files: left for the agent
CLI=${SIGELO_CLI:-"$(dirname "$0")/../cli.ts"}
msg=$(cat)
field() { printf '%s' "$msg" | node -e '
  let d = ""; process.stdin.on("data", (c) => { d += c; }).on("end", () => {
    const m = JSON.parse(d), v = m[process.argv[1]];
    process.stdout.write(v === undefined || v === null ? "" : typeof v === "string" ? v : JSON.stringify(v));
  });' "$1"; }
[ "$(field label)" = reply ] && exit 0
id=${SIGELO_MSG_ID:-$(field id)}
text=$(field content)
[ -n "$id" ] && [ -n "$text" ] || exit 0
if [ -n "${SIGELO_REPLY_CMD:-}" ]; then
  answer=$(printf '%s\n' "$text" | sh -c "$SIGELO_REPLY_CMD")
else
  answer=$text
fi
[ -n "$answer" ] || exit 0
printf '%s' "$answer" | node "$CLI" reply --to "$id" - >/dev/null
