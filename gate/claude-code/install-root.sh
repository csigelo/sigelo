#!/bin/sh
# SPDX-License-Identifier: MIT
# Hardened install of the sigelo provenance gate for Claude Code (gate/DESIGN.md §7). Run as root,
# from a sigelo checkout with ts/ built (cd ts && npm ci && npx tsc).
#
#   install-root.sh --agent-user USER --config gate.json [--gate-user sigelo-gate] [--prefix DIR]
#                   [--rule FILE] [--no-managed]
#   install-root.sh --uninstall --agent-user USER [--gate-user sigelo-gate] [--prefix DIR] [--rule FILE]
#
# Result (paths under --prefix, default /):
#   /usr/local/lib/sigelo-gate/       gate code, ts/dist and @noble, the gate-state wrapper   root:root, read-only
#   /etc/sigelo-gate/gate.json        config, with "state" and "state_writer" set              root:root 0644
#   /var/lib/sigelo-gate/             state: grants, taints, consumed nonces          GATE_USER:agent group 2750
#   /etc/doas.d/sigelo-gate.conf      (doas) or /etc/sudoers.d/sigelo-gate (sudo): USER may run the wrapper,
#                                     with no arguments, as GATE_USER, and nothing else
#   /etc/claude-code/managed-settings.json   the hooks, merged into any existing file           root:root 0644
# Managed settings rank above every user, project, local and --settings file and their hooks cannot be
# switched off from below (disableAllHooks there does not reach managed hooks). --prefix writes the
# managed file under DIR too, which Claude Code does not read: that is for tests.
set -eu
die() { echo "install-root: $*" >&2; exit 1; }
SRC=$(cd "$(dirname "$0")/../.." && pwd)
AGENT='' CONFIG='' GU=sigelo-gate P='' RULE='' MANAGED=1 UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --agent-user) AGENT=$2; shift ;;
    --config) CONFIG=$2; shift ;;
    --gate-user) GU=$2; shift ;;
    --prefix) P=$2; shift ;;
    --rule) RULE=$2; shift ;;
    --no-managed) MANAGED=0 ;;
    --uninstall) UNINSTALL=1 ;;
    *) die "unknown argument $1" ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || die 'run as root'
[ -n "$AGENT" ] && id "$AGENT" >/dev/null 2>&1 || die '--agent-user must name an existing user'
[ "$AGENT" != root ] || die 'the agent must not run as root'
case "$GU" in *[!a-z0-9_-]*|'') die '--gate-user: lower-case letters, digits, _ and - only' ;; esac
NODE=$(command -v node) || die 'node not found'
[ "$(stat -c %u "$NODE")" = 0 ] || die "$NODE is not root-owned: the hook would run code the agent can replace"

LIB=$P/usr/local/lib/sigelo-gate ETC=$P/etc/sigelo-gate STATE=$P/var/lib/sigelo-gate
WRAP=$LIB/gate-state CONF=$ETC/gate.json GATE=$LIB/gate/claude-code/gate.mjs
MSET=$P/etc/claude-code/managed-settings.json
# The helper runs through doas where sudo is the doas shim (Alpine-family systems), else through sudo.
if sudo -V 2>/dev/null | grep -q '^Sudo version'; then
  RUNNER=$(command -v sudo); KIND=sudo; [ -n "$RULE" ] || RULE=/etc/sudoers.d/$GU
else
  RUNNER=$(command -v doas) || die 'neither sudo nor doas found'; KIND=doas; [ -n "$RULE" ] || RULE=/etc/doas.d/$GU.conf
fi

# Hook command: absolute paths, an empty environment (no NODE_OPTIONS, no PATH games), and any failure
# to run (node or gate.mjs missing, a crash) becomes exit 2, which blocks: Claude Code treats exit 1 as
# a non-blocking error and would let the call through.
HOOKCMD="/usr/bin/env -i $NODE $GATE --config $CONF || exit 2"
merge() { # $1 = add | remove; edits $MSET, keeping everything that is not ours
  "$NODE" -e '
    const fs = require("fs"), [f, mode, cmd, ours] = process.argv.slice(1);
    const s = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : {};
    s.hooks ??= {};
    for (const ev of ["UserPromptSubmit", "UserPromptExpansion", "PreToolUse", "PostToolUse", "PostToolUseFailure"]) {
      const kept = (s.hooks[ev] ?? []).filter((m) => !(m.hooks ?? []).some((h) => String(h.command).includes(ours)));
      s.hooks[ev] = mode === "add" ? [...kept, { hooks: [{ type: "command", command: cmd, timeout: 10 }] }] : kept;
      if (!s.hooks[ev].length) delete s.hooks[ev];
    }
    if (!Object.keys(s.hooks).length) delete s.hooks;
    fs.writeFileSync(f + ".tmp", JSON.stringify(s, null, 2) + "\n", { mode: 0o644 }); fs.renameSync(f + ".tmp", f);
  ' "$MSET" "$1" "$HOOKCMD" "$GATE"
}

if [ "$UNINSTALL" = 1 ]; then
  [ -f "$MSET" ] && merge remove
  rm -rf "$LIB" "$ETC" "$STATE" "$RULE"
  if id "$GU" >/dev/null 2>&1; then deluser "$GU" 2>/dev/null || userdel "$GU"; fi
  echo "install-root: removed the gate ($LIB, $ETC, $STATE, $RULE, user $GU)"; exit 0
fi

[ -f "$CONFIG" ] || die '--config must name the gate.json to install (agent, operators)'
[ -f "$SRC/ts/dist/sigelo.js" ] && [ -d "$SRC/ts/node_modules/@noble" ] || die "build ts first: cd $SRC/ts && npm ci && npx tsc"

# 1. the gate's own user: no login, no home, owns only the state
if ! id "$GU" >/dev/null 2>&1; then
  adduser -S -D -H -h /nonexistent -s /sbin/nologin "$GU" 2>/dev/null || useradd -r -M -d /nonexistent -s /usr/sbin/nologin "$GU"
fi
# 2. code: root-owned, read-only to everyone else
umask 022
rm -rf "$LIB"; mkdir -p "$LIB/gate/claude-code" "$LIB/ts/node_modules" "$ETC" "$STATE" "$(dirname "$MSET")"
cp "$SRC/gate/claude-code/gate.mjs" "$LIB/gate/claude-code/"
cp "$SRC/ts/package.json" "$LIB/ts/"; cp -R "$SRC/ts/dist" "$LIB/ts/"; cp -R "$SRC/ts/node_modules/@noble" "$LIB/ts/node_modules/"
printf '#!/bin/sh\n# sigelo gate state writer: fixed command, fixed config; arguments are refused by the %s rule.\nexec /usr/bin/env -i %s %s --state-writer --config %s\n' "$KIND" "$NODE" "$GATE" "$CONF" > "$WRAP"
chown -R root:root "$LIB"; chmod -R u=rwX,go=rX "$LIB"; chmod 755 "$WRAP"
# 3. config: the source config plus the hardened fields
"$NODE" -e '
  const fs = require("fs"), [src, dst, state, ...w] = process.argv.slice(1);
  const c = JSON.parse(fs.readFileSync(src, "utf8"));
  Object.assign(c, { state, state_writer: w, layout_check: true });
  fs.writeFileSync(dst, JSON.stringify(c, null, 2) + "\n", { mode: 0o644 });
' "$CONFIG" "$CONF" "$STATE" "$RUNNER" -n -u "$GU" "$WRAP"
chown root:root "$ETC" "$CONF"; chmod 755 "$ETC"; chmod 644 "$CONF"
# 4. state: only the gate user writes it; the agent's group reads it (it holds the signed prompts' text)
chown "$GU:$(id -gn "$AGENT")" "$STATE"; chmod 2750 "$STATE"
# 5. the one privilege rule, checked before it is installed
TMP=$(mktemp)
if [ "$KIND" = doas ]; then
  printf 'permit nopass %s as %s cmd %s args\n' "$AGENT" "$GU" "$WRAP" > "$TMP"
  doas -C "$TMP" >/dev/null 2>&1 || { doas -C "$TMP"; rm -f "$TMP"; die "doas rejected the rule"; }
else
  printf '%s ALL=(%s) NOPASSWD: %s ""\n' "$AGENT" "$GU" "$WRAP" > "$TMP"
  visudo -cf "$TMP" >/dev/null || { rm -f "$TMP"; die "visudo rejected the rule"; }
fi
mkdir -p "$(dirname "$RULE")"; chown root:root "$TMP"; chmod 440 "$TMP"; mv "$TMP" "$RULE"
# 6. the hooks, where no user-writable settings file can remove them
if [ "$MANAGED" = 1 ]; then merge add; chown root:root "$MSET"; chmod 644 "$MSET"; fi

echo "install-root: installed ($KIND rule $RULE, state writer user $GU, agent user $AGENT)"
[ "$MANAGED" = 1 ] && echo "install-root: hooks in $MSET — restart Claude Code; /status names the managed source"
CL=$(su -s /bin/sh "$AGENT" -c 'command -v claude' 2>/dev/null || true)
if [ -n "$CL" ] && su -s /bin/sh "$AGENT" -c "test -w \"\$(readlink -f '$CL')\"" 2>/dev/null; then
  echo "install-root: WARNING: $CL is writable by $AGENT (a self-updating user install). A granted shell can" >&2
  echo "  replace it with a build that skips hooks. Install Claude Code root-owned and disable the auto-updater." >&2
fi
