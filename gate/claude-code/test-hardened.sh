#!/bin/sh
# SPDX-License-Identifier: MIT
# The hardened layout, tested for real: run as root (doas/sudo) with the agent's user name.
#   doas sh gate/claude-code/test-hardened.sh USER
# Installs the gate under a scratch prefix in /tmp (root-owned, so the agent's user cannot write it) with a
# temporary gate user and a temporary privilege rule, runs the agent-side checks as USER (test.mjs
# --hardened), removes the helper and checks the gate fails closed, then uninstalls everything.
# It never writes /etc/claude-code: managed settings would apply to every Claude Code session on the host.
set -eu
AGENT=${1:?usage: test-hardened.sh AGENT_USER}
[ "$(id -u)" = 0 ] || { echo 'run as root' >&2; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
GU=sigelo-gate-t
P=$(mktemp -d /tmp/sigelo-gate-hard.XXXXXX); chmod 755 "$P"
PREP=$P/prep RULEDIR=/etc/doas.d
sudo -V 2>/dev/null | grep -q '^Sudo version' && RULEDIR=/etc/sudoers.d
RULE=$RULEDIR/zz-sigelo-gate-test$( [ "$RULEDIR" = /etc/doas.d ] && echo .conf )
as_agent() { su -s /bin/sh "$AGENT" -c "$*"; }
cleanup() { sh "$HERE/install-root.sh" --uninstall --agent-user "$AGENT" --gate-user "$GU" --prefix "$P/root" --rule "$RULE" >/dev/null 2>&1 || true; rm -rf "$P"; }
trap cleanup EXIT INT TERM

mkdir -p "$PREP"; chown "$AGENT" "$PREP"
as_agent "env -u CLAUDECODE node '$HERE/test.mjs' --prep '$PREP'"
sh "$HERE/install-root.sh" --agent-user "$AGENT" --config "$PREP/gate.json" --gate-user "$GU" --prefix "$P/root" --rule "$RULE" --no-managed --i-accept-user-writable-claude
CONF=$P/root/etc/sigelo-gate/gate.json
A=0; as_agent "env -u CLAUDECODE node '$HERE/test.mjs' --hardened '$CONF' '$PREP'" || A=1
mv "$P/root/usr/local/lib/sigelo-gate/gate-state" "$P/gate-state.away"
B=0; as_agent "env -u CLAUDECODE node '$HERE/test.mjs' --hardened '$CONF' '$PREP' --no-helper" || B=1
[ "${KEEP:-}" = 1 ] && { mv "$P/gate-state.away" "$P/root/usr/local/lib/sigelo-gate/gate-state"; trap - EXIT; echo "kept: $P (KEEP=1; uninstall by hand)"; }
exit $((A + B))
