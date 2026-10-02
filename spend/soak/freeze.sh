#!/bin/sh
# Freeze a compromised soak keeper (INCIDENT.md §2, README "Incident rehearsal" step 2), verifiably.
#
#   sh freeze.sh          print what it would do (units, directory, the pid in spend.lock, every
#                         process it would kill); changes nothing
#   sh freeze.sh --now    do it
#   sh freeze.sh --no-systemd [--now]   TEST MODE ONLY: no unit is touched (no drop-in, no disable,
#                         no unit checks, the wallet-rpc is left alone); steps 1, 3, 3b and the
#                         process/port/lock half of 4 run as usual. For scratch keepers started by
#                         hand; never the way to freeze a real keeper under systemd.
#
# Order: (1) evidence copy + sha256 while the keeper still runs (a clean stop deletes spend.lock);
# (2) a drop-in `Restart=no` for the keeper and the wallet-rpc units, both `disable`d, daemon-reload,
# and a check that systemd now reports Restart=no; (3) `kill -9` the pid in spend.lock, so the lock
# stays as evidence; (4) assert within 5 s: keeper inactive/failed, not auto-restarting, spend.lock
# still there; (5) `systemctl --user stop` the wallet-rpc (a clean stop saves the wallet file) and
# assert it is down. Every step prints its UTC time. The agent timer is left running on purpose.
#
# Step 3b (R13, drill 2): the spend.lock pid is not the only process that accepts the tokens. Drill 2
# found a `cli.js serve --dry-run` left by an earlier test that kept taking the root token after the
# freeze. So after the lock's pid, freeze.sh kill -9s every process whose argv is `serve <P>` with P
# resolving (against that process's cwd, symlinks followed) to the realpath of keeper/policy.json,
# and every process holding a listening socket on the keeper port (/proc/net/tcp{,6} inode →
# /proc/*/fd), logging pid, uid, ppid, parent and cgroup for each; step 4 then asserts the port is
# closed and nothing serves that policy. `serve` processes on OTHER policies are listed as a
# WARNING and left alone (they may hold copied tokens: `identical content` flags a byte-identical copy).
# Port: SIGELO_FREEZE_PORT, else `--port` in the lock pid's argv, else SIGELO_WALLET_URL in
# $DATA/env.sh, else 38090 (the cli default).
#
# Why not `systemctl --user mask --runtime` (what the runbook said until the T14 rehearsal): setup.sh
# installs the units in ~/.config/systemd/user, which the user manager ranks ABOVE the runtime
# directory /run/user/<uid>/systemd/user where a runtime mask is written, so the mask is shadowed and
# Restart=always brings the keeper back 10 s after the kill. A persistent `mask` cannot be used
# either: it would have to replace the unit file in ~/.config with a /dev/null link, and systemctl
# refuses because the file exists. A drop-in in ~/.config/systemd/user/<unit>.d/ applies whatever
# directory the unit file is in. unfreeze.sh undoes this.
#
# Env: SIGELO_SOAK_DIR (default ~/.local/share/sigelo-soak), SIGELO_FREEZE_EVIDENCE (default
# ~/sigelo-evidence-<UTC stamp>; must not exist), SIGELO_FREEZE_KEEPER_UNIT / _WALLET_UNIT (default
# the soak's units; the test points them at scratch units), SIGELO_FREEZE_PORT.
set -eu
NOW=0; NOSYS=0
for a in "$@"; do
  case "$a" in --now) NOW=1 ;; --no-systemd) NOSYS=1 ;; *) echo "freeze.sh: unknown argument $a" >&2; exit 2 ;; esac
done
umask 077
DATA=${SIGELO_SOAK_DIR:-$HOME/.local/share/sigelo-soak}
KEEPER_DIR=$DATA/keeper
KU=${SIGELO_FREEZE_KEEPER_UNIT:-sigelo-soak-keeper.service}
WU=${SIGELO_FREEZE_WALLET_UNIT:-monero-wallet-rpc-stagenet.service}
UNITDIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID=${SIGELO_FREEZE_EVIDENCE:-$HOME/sigelo-evidence-$STAMP}

say() { echo "$(date -u +%H:%M:%SZ) freeze: $*"; }
die() { echo "$(date -u +%H:%M:%SZ) freeze: FAILED: $*" >&2; exit 1; }
prop() { systemctl --user show -p "$2" --value "$1" 2>/dev/null || echo unknown; }
LOCK=$KEEPER_DIR/spend.lock
PID=$( [ -f "$LOCK" ] && head -n1 "$LOCK" | tr -cd 0-9 || true )
POL=$(readlink -f "$KEEPER_DIR/policy.json" 2>/dev/null || echo "$KEEPER_DIR/policy.json")

# ---- process discovery (R13): /proc, not a pgrep -f substring
argv() { { tr '\0' '\n' < "/proc/$1/cmdline"; } 2>/dev/null || true; }
cmdl() { { tr '\0\n\t' '   ' < "/proc/$1/cmdline"; } 2>/dev/null | cut -c1-200 || true; }
# The realpath of the policy a `serve <policy>` process uses (relative to its cwd), else nothing.
served() {
  a=$(argv "$1" | awk 'f { print; exit } $0 == "serve" { f = 1 }')
  [ -n "$a" ] || return 0
  case "$a" in /*) ;; *) a="$(readlink "/proc/$1/cwd" 2>/dev/null)/$a" ;; esac
  readlink -f "$a" 2>/dev/null || echo "$a"
}
who() {
  pp=$(awk '/^PPid:/ { print $2 }' "/proc/$1/status" 2>/dev/null)
  echo "uid $(awk '/^Uid:/ { print $2 }' "/proc/$1/status" 2>/dev/null) ppid ${pp:-?} ($(cmdl "${pp:-0}" | cut -c1-60)) cgroup $(tail -n1 "/proc/$1/cgroup" 2>/dev/null | sed 's/^0:://')"
}
port_pids() {
  hex=$(printf '%04X' "$1")
  inos=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v h=":$hex" '$4 == "0A" && substr($2, length($2) - 4) == h { print $10 }' | paste -sd'|' -)
  [ -n "$inos" ] || return 0
  for d in /proc/[0-9]*; do
    ls -l "$d/fd" 2>/dev/null | grep -Eq "socket:\[($inos)\]" && echo "${d#/proc/}"
  done
  return 0
}
port_open() { cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v h=":$(printf '%04X' "$1")" '$4 == "0A" && substr($2, length($2) - 4) == h { f = 1 } END { exit !f }'; }
# SAME: pids serving this policy or holding the port; OTHER: `serve` processes on other policies.
scan() {
  SAME=; OTHER=
  for d in /proc/[0-9]*; do
    p=${d#/proc/}; [ "$p" = "$" ] && continue
    s=$(served "$p"); [ -n "$s" ] || continue
    if [ "$s" = "$POL" ]; then SAME="$SAME $p"; else OTHER="$OTHER $p"; fi
  done
  for p in $(port_pids "$PORT"); do case " $SAME " in *" $p "*) ;; *) SAME="$SAME $p" ;; esac; done
  return 0
}
warn_others() {
  for p in $OTHER; do
    s=$(served "$p"); same=
    cmp -s "$s" "$KEEPER_DIR/policy.json" 2>/dev/null && same=", IDENTICAL CONTENT: it accepts these tokens, kill it by hand"
    say "WARNING: another keeper, not killed: pid $p serves $s$same; $(who "$p"); cmd: $(cmdl "$p")"
  done
}
PORT=${SIGELO_FREEZE_PORT:-}
[ -n "$PORT" ] || { [ -n "$PID" ] && PORT=$(argv "$PID" | awk 'f { print; exit } $0 == "--port" { f = 1 }' | tr -cd 0-9); }
[ -n "$PORT" ] || PORT=$(sed -n 's/.*SIGELO_WALLET_URL=[^ ]*:\([0-9][0-9]*\).*/\1/p' "$DATA/env.sh" 2>/dev/null | head -n1)
PORT=${PORT:-38090}
scan

if [ "$NOW" != 1 ]; then
  echo "freeze.sh (dry run; nothing changed)$( [ "$NOSYS" = 1 ] && echo ' [TEST MODE --no-systemd: no unit touched]'). With --now it would:"
  echo "  1. copy $KEEPER_DIR/{spend.log,spend.lock,policy.json} to $EVID + SHA256SUMS"
  if [ "$NOSYS" = 1 ]; then echo "  2. (skipped: --no-systemd)"; else
  echo "  2. drop-in Restart=no for $KU and $WU in $UNITDIR/<unit>.d/freeze.conf, disable both, daemon-reload"; fi
  if [ "$NOSYS" = 1 ]; then echo "  3. kill -9 ${PID:-<no spend.lock: nothing>} (spend.lock pid)"; else
  echo "  3. kill -9 ${PID:-<no spend.lock: would use systemctl kill>} (spend.lock pid; unit MainPID $(prop "$KU" MainPID), Restart now $(prop "$KU" Restart))"; fi
  echo "  3b. kill -9 every other process serving $POL or listening on :$PORT, as of now:"
  n=0; for p in $SAME; do [ "$p" = "$PID" ] && continue; n=1; echo "      pid $p; $(who "$p"); cmd: $(cmdl "$p")"; done
  [ "$n" = 1 ] || echo "      (none besides the spend.lock pid)"
  if [ "$NOSYS" = 1 ]; then echo "  4. assert port :$PORT closed, nothing serves the policy, spend.lock kept (unit checks and step 5 skipped)"; else
  echo "  4. assert $KU dead, not restarting, port :$PORT closed, nothing serves the policy, spend.lock kept; 5. systemctl --user stop $WU and assert it is down"; fi
  for p in $OTHER; do echo "  WARNING (not killed): pid $p serves $(served "$p"); cmd: $(cmdl "$p")"; done
  exit 0
fi

say "start: dir $DATA, policy $POL, port $PORT, keeper unit $KU, wallet unit $WU"
[ "$NOSYS" = 1 ] && say "TEST MODE --no-systemd: steps 2, 5 and the unit checks are skipped"

# 1. evidence, keeper still running
[ -e "$EVID" ] && die "$EVID exists; set SIGELO_FREEZE_EVIDENCE to a new directory"
mkdir -p "$EVID"; chmod 700 "$EVID"
for f in spend.log spend.lock policy.json; do
  if [ -f "$KEEPER_DIR/$f" ]; then cp -p "$KEEPER_DIR/$f" "$EVID/$f"; else say "WARNING: no $KEEPER_DIR/$f to copy"; fi
done
( cd "$EVID" && sha256sum spend.log spend.lock policy.json 2>/dev/null > SHA256SUMS || true )
chmod 600 "$EVID"/* 2>/dev/null || true
say "1 evidence in $EVID:"; sed 's/^/    /' "$EVID/SHA256SUMS"
POLSUM=$(sha256sum "$KEEPER_DIR/policy.json" 2>/dev/null | cut -d' ' -f1 || echo none)

# 2. no restart, no start at boot, for both units, before anything is killed
if [ "$NOSYS" != 1 ]; then
for u in "$KU" "$WU"; do
  mkdir -p "$UNITDIR/$u.d"
  printf '# written by spend/soak/freeze.sh at %s; removed by unfreeze.sh\n# policy.json sha256 %s (unfreeze.sh refuses while %s/policy.json still has it)\n# evidence %s\n[Service]\nRestart=no\n' \
    "$STAMP" "$POLSUM" "$KEEPER_DIR" "$EVID" > "$UNITDIR/$u.d/freeze.conf"
  systemctl --user disable "$u" 2>/dev/null || true
done
systemctl --user daemon-reload
for u in "$KU" "$WU"; do
  r=$(prop "$u" Restart)
  [ "$r" = no ] || die "$u still reports Restart=$r after the drop-in; fall back to: systemctl --user stop $KU $WU (deletes spend.lock; the evidence copy has it)"
  say "2 $u: Restart=$r, $(systemctl --user is-enabled "$u" 2>/dev/null || true), drop-in $(prop "$u" DropInPaths)"
done
fi

# 3. kill -9 the keeper by the pid its lock names: the lock stays behind as evidence
MAIN=$(prop "$KU" MainPID)
if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
  [ "$NOSYS" = 1 ] || [ "$PID" = "$MAIN" ] || say "WARNING: spend.lock pid $PID is not $KU's MainPID $MAIN; killing the lock's pid, then the unit"
  say "3 kill -9 $PID (spend.lock); $(who "$PID"); cmd: $(cmdl "$PID")"; kill -9 "$PID"
else
  say "3 spend.lock names no live pid (${PID:-none})$( [ "$NOSYS" = 1 ] || echo "; systemctl --user kill -s KILL $KU")"
fi
[ "$NOSYS" = 1 ] || { [ "$(prop "$KU" ActiveState)" = active ] && systemctl --user kill -s KILL "$KU" 2>/dev/null; } || true

# 3b. every other keeper on this policy, and whatever holds the port (R13: test keepers count)
scan; n=0
for p in $SAME; do
  [ "$p" = "$PID" ] && continue
  why="holds :$PORT"; [ "$(served "$p")" = "$POL" ] && why="serves the policy"
  say "3b kill -9 $p ($why); $(who "$p"); cmd: $(cmdl "$p")"
  kill -9 "$p" 2>/dev/null || say "3b WARNING: kill -9 $p failed (not ours? gone?)"; n=$((n + 1))
done
say "3b $n other process(es) on $POL or :$PORT killed"

# 4. assert: nothing serves the policy, the port is closed (both, whatever started them), then the unit
i=0
while :; do
  scan; port_open "$PORT" || [ -n "$SAME" ] || break
  [ $i -ge 10 ] && die "5 s after the kills: port :$PORT $(port_open "$PORT" && echo open || echo closed), still serving/holding:$SAME. Kill them by hand"
  sleep 0.5; i=$((i + 1))
done
say "4 port :$PORT closed; no process serves $POL"
if [ "$NOSYS" = 1 ]; then
  [ -f "$LOCK" ] || say "WARNING: $LOCK is gone (the evidence copy has it)"
  say "4 spend.lock $( [ -f "$LOCK" ] && echo kept || echo MISSING) (TEST MODE: unit checks and step 5 skipped)"
  warn_others
  say "FROZEN (test mode, no units). Evidence in $EVID."
  exit 0
fi
i=0; st=; sub=
while [ $i -lt 10 ]; do
  st=$(prop "$KU" ActiveState); sub=$(prop "$KU" SubState)
  case "$st" in inactive|failed) break ;; esac
  sleep 0.5; i=$((i + 1))
done
case "$st" in inactive|failed) ;; *) die "$KU is $st/$sub 5 s after the kill (a restart is pending if auto-restart): systemctl --user stop $KU now" ;; esac
[ "$sub" = auto-restart ] && die "$KU is scheduled to restart"
[ -n "$(systemctl --user list-jobs --no-legend 2>/dev/null | grep -F " $KU " || true)" ] && die "$KU has a queued job"
[ -f "$LOCK" ] || say "WARNING: $LOCK is gone (the evidence copy has it)"
say "4 $KU $st/$sub, NRestarts $(prop "$KU" NRestarts), spend.lock $( [ -f "$LOCK" ] && echo kept || echo MISSING)"

# 5. the wallet-rpc: a clean stop (it saves the wallet file), never a kill
if [ "$(prop "$WU" ActiveState)" != inactive ]; then systemctl --user stop "$WU"; fi
st=$(prop "$WU" ActiveState)
case "$st" in inactive|failed) ;; *) die "$WU is $st after stop" ;; esac
say "5 $WU $st/$(prop "$WU" SubState)"

warn_others
say "FROZEN. Tokens are dead with the keeper. Copy $EVID off-host. Never start $KU on $DATA again;"
say "the agent timer is still running (its next tick must log TRY LATER). Undo only after a new soak dir: sh unfreeze.sh"
