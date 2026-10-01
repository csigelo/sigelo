#!/bin/sh
# SPDX-License-Identifier: MIT
# Render the bound procedures for the printer.
#
#   print.sh <bound dir> [<out dir>] [--unbound]
#
# <bound dir> is what `sigelo-kit-bind --out <dir>` wrote. Output (default <bound dir>/print):
# CEREMONY.html, DRILL.html, RUNBOOK.html and procedure.html (all three, each on a new page),
# self-contained: no script, nothing fetched. Open in a browser offline, print, tick in pen.
set -eu
self=$0
while [ -h "$self" ]; do
	l=$(readlink "$self")
	case $l in /*) self=$l ;; *) self=$(dirname "$self")/$l ;; esac
done
exec node "$(cd "$(dirname "$self")" && pwd)/print.mjs" "$@"
