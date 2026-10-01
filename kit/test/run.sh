#!/bin/sh
# SPDX-License-Identifier: MIT
# The recovery kit's own checks, in scratch directories; installs nothing, sends nothing.
#
#   sh kit/test/run.sh          (from anywhere; node >= 22; the ceremony part needs age, age-keygen
#                                and util-linux `script`, and SKIPs without them)
#
#   1. ceremony.test.mjs  run.sh on a real pty with a faked offline check: refusals, no word on
#                         stdout/stderr, restore --words from the terminal's words = restore --backup,
#                         --verify-paper, idempotency, refusal to overwrite a root
#   2. kit.test.mjs       bind (and its refusals), print (both renderers), the drill scheduler
#                         (--dry-run and a scratch --units-dir; no systemctl), the grader
#   3. the package        npm pack --dry-run: every bin and every file the kit needs is in it
set -eu
here=$(cd "$(dirname "$0")" && pwd)
kit=$(dirname "$here")
export SIGELO_KIT_TMP="${SIGELO_KIT_TMP:-${TMPDIR:-/tmp}}"
rc=0
node "$here/ceremony.test.mjs" || rc=1
node "$here/kit.test.mjs" || rc=1
if command -v npm >/dev/null 2>&1; then
	list=$(cd "$kit" && npm pack --dry-run --json --ignore-scripts 2>/dev/null) || list=
	if [ -z "$list" ]; then
		echo "FAIL package: npm pack --dry-run failed"; rc=1
	else
		printf '%s' "$list" | node -e '
			const files = new Set(JSON.parse(require("fs").readFileSync(0, "utf8"))[0].files.map((f) => f.path));
			const pkg = require(process.argv[1] + "/package.json");
			const need = [...pkg.files, ...Object.values(pkg.bin), "package.json"];
			const miss = need.filter((f) => !files.has(f));
			const extra = [...files].filter((f) => !need.includes(f) && f !== "LICENSE");
			if (miss.length || extra.length) { console.log(`FAIL package: missing ${miss.join(", ") || "-"}; unexpected ${extra.join(", ") || "-"}`); process.exit(1); }
			console.log(`ok   package: npm pack holds the ${files.size} files of package.json "files" and every bin`);
		' "$kit" || rc=1
	fi
else
	echo "SKIP package: no npm"
fi
[ $rc = 0 ] && echo "kit/test/run.sh: ALL PASS" || echo "kit/test/run.sh: FAILED"
exit $rc
