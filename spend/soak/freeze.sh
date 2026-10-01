#!/bin/sh
# Freeze a compromised soak keeper (INCIDENT.md §2, README "Incident rehearsal" step 2), verifiably.
#
#   sh freeze.sh          print what it would do (units, directory, the pid in spend.lock); changes nothing
#   sh freeze.sh --now    do it
#
# Order: (1) evidence copy + sha256 while the keeper still runs (a clean stop deletes spend.lock);
# (2) a drop-in `Restart=no` for the keeper and the wallet-rpc units, both `disable`d, daemon-reload,
# and a check that systemd now reports Restart=no; (3) `kill -9` the pid in spend.lock, so the lock
# stays as evidence; (4) assert within 5 s: keeper inactive/failed, not auto-restarting, spend.lock
# still there; (5) `systemctl --user stop` the wallet-rpc (a clean stop saves the wallet file) and
# assert it is down. Every step prints its UTC time. The agent timer is left running on purpose.
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
# the soak's units; the test points them at scratch units).
set -eu
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

if [ "${1:-}" != "--now" ]; then
  echo "freeze.sh (dry run; nothing changed). With --now it would:"
  echo "  1. copy $KEEPER_DIR/{spend.log,spend.lock,policy.json} to $EVID + SHA256SUMS"
  echo "  2. drop-in Restart=no for $KU and $WU in $UNITDIR/<unit>.d/freeze.conf, disable both, daemon-reload"
  echo "  3. kill -9 ${PID:-<no spend.lock: would use systemctl kill>} (spend.lock pid; unit MainPID $(prop "$KU" MainPID), Restart now $(prop "$KU" Restart))"
  echo "  4. assert $KU dead, not restarting, spend.lock kept; 5. systemctl --user stop $WU and assert it is down"
  exit 0
fi

say "start: dir $DATA, keeper unit $KU, wallet unit $WU"

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

# 3. kill -9 the keeper by the pid its lock names: the lock stays behind as evidence
MAIN=$(prop "$KU" MainPID)
if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
  [ "$PID" = "$MAIN" ] || say "WARNING: spend.lock pid $PID is not $KU's MainPID $MAIN; killing the lock's pid, then the unit"
  kill -9 "$PID"; say "3 kill -9 $PID (spend.lock)"
else
  say "3 spend.lock names no live pid (${PID:-none}); systemctl --user kill -s KILL $KU"
fi
[ "$(prop "$KU" ActiveState)" = active ] && systemctl --user kill -s KILL "$KU" 2>/dev/null || true

# 4. assert: dead, not restarting, lock kept
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

say "FROZEN. Tokens are dead with the keeper. Copy $EVID off-host. Never start $KU on $DATA again;"
say "the agent timer is still running (its next tick must log TRY LATER). Undo only after a new soak dir: sh unfreeze.sh"
