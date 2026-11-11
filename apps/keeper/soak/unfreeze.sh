#!/bin/sh
# Undo freeze.sh once the keeper has a NEW soak directory (README "Incident rehearsal" step 4):
# removes the Restart=no drop-ins, daemon-reload, `enable`s both units again. Starts nothing.
# Refuses while $SIGELO_SOAK_DIR/keeper/policy.json is still the policy freeze.sh froze (the
# sha256 recorded in the drop-in): re-enabling there would start a keeper on the burnt directory
# at the next boot. Same env as freeze.sh.
set -eu
DATA=${SIGELO_SOAK_DIR:-$HOME/.local/share/sigelo-soak}
KU=${SIGELO_FREEZE_KEEPER_UNIT:-sigelo-soak-keeper.service}
WU=${SIGELO_FREEZE_WALLET_UNIT:-monero-wallet-rpc-stagenet.service}
UNITDIR=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
say() { echo "$(date -u +%H:%M:%SZ) unfreeze: $*"; }

CONF=$UNITDIR/$KU.d/freeze.conf
if [ -f "$CONF" ]; then
  frozen=$(sed -n 's/^# policy.json sha256 \([0-9a-f]*\).*/\1/p' "$CONF")
  now=$(sha256sum "$DATA/keeper/policy.json" 2>/dev/null | cut -d' ' -f1 || true)
  if [ -n "$frozen" ] && [ "$frozen" = "$now" ]; then
    echo "unfreeze: $DATA/keeper/policy.json is the policy freeze.sh froze ($frozen): move the burnt directory away and set up a new one first" >&2
    exit 1
  fi
fi
for u in "$KU" "$WU"; do
  rm -f "$UNITDIR/$u.d/freeze.conf"
  rmdir "$UNITDIR/$u.d" 2>/dev/null || true
done
systemctl --user daemon-reload
for u in "$KU" "$WU"; do
  systemctl --user enable "$u" 2>/dev/null || say "WARNING: enable $u failed"
  say "$u: Restart=$(systemctl --user show -p Restart --value "$u"), $(systemctl --user is-enabled "$u" 2>/dev/null || true), $(systemctl --user is-active "$u" 2>/dev/null || true)"
done
say "done; start with: systemctl --user start $WU, then (after setup.sh) systemctl --user start $KU"
