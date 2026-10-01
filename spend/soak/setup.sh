#!/bin/sh
# Install (or refresh) the stagenet keeper soak under ~/.local/share/sigelo-soak.
# Idempotent: code is re-copied every run; keys (the test vendor's too), policy.json, spend.key,
# licence.json, spend.log, the root token and the agent's state are created once and never overwritten.
# Needs: ts/ and spend/ built (npx tsc in each), monero-wallet-rpc on 127.0.0.1:38083.
set -eu
umask 077
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
DATA=${SIGELO_SOAK_DIR:-$HOME/.local/share/sigelo-soak}
PORT=38200
APP=$DATA/app KEEPER=$DATA/keeper

for f in "$REPO/ts/dist/sigelo.js" "$REPO/spend/dist/cli.js" "$REPO/spend/dist/wallet.js"; do
  [ -f "$f" ] || { echo "setup: $f missing — run npx tsc in ts/ and spend/ first" >&2; exit 1; }
done

mkdir -p "$DATA" "$APP/ts/node_modules" "$APP/spend/node_modules" "$APP/spend/soak" "$KEEPER" "$DATA/bin"
chmod 700 "$DATA" "$KEEPER"

# A newer verifier may reject identities an older one issued (the SPEC §2 nonce form, for one):
# refuse to redeploy over a live soak this code would not accept — before any file is touched.
if [ -f "$KEEPER/policy.json" ]; then
  SIGELO_SOAK_DIR=$DATA node "$HERE/gen-keys.mjs" compat "$KEEPER"
fi

# Code: a frozen copy, so editing or rebuilding the repo never changes a running soak.
# Same shape as the repo: spend/node_modules/sigelo -> ../../ts.
rm -rf "$APP/ts/dist" "$APP/spend/dist" "$APP/ts/node_modules/@noble"
cp -R "$REPO/ts/dist" "$REPO/ts/package.json" "$APP/ts/"
cp -R "$REPO/ts/node_modules/@noble" "$APP/ts/node_modules/"
cp -R "$REPO/spend/dist" "$REPO/spend/package.json" "$APP/spend/"
ln -sfn ../../ts "$APP/spend/node_modules/sigelo"
cp "$HERE/agent.mjs" "$HERE/check.mjs" "$HERE/gen-keys.mjs" "$HERE/policy.template.json" "$HERE/freeze.sh" "$HERE/unfreeze.sh" "$APP/spend/soak/"
chmod -R go-w "$APP"
( cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo unknown ) > "$APP/REVISION"

# Keys (created once by gen-keys.mjs), then policy.json + spend.key from the template (read only: the
# identities and addresses are filled into $KEEPER/policy.json, never into the repository).
[ -f "$DATA/keys/S.hex" ] || { echo "setup: no $DATA/keys — run: node $HERE/gen-keys.mjs" >&2; exit 1; }
SIGELO_SOAK_DIR=$DATA node "$APP/spend/soak/gen-keys.mjs" policy "$KEEPER"

# The licence: the policy uses delegates and approvals, paid verbs a keeper without a valid licence
# refuses 403 licence_required (spend/licence.ts, since 17e7787). The soak is a pro customer of its
# own keeper under a soak-local TEST vendor (keys/vendor.*): kept if present and valid, issued if
# missing, and the keeper unit gets the vendor's DID as SIGELO_VENDOR_DID (drop-in below).
SIGELO_SOAK_DIR=$DATA node "$APP/spend/soak/gen-keys.mjs" licence "$KEEPER"
VENDOR=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).did' "$DATA/keys/vendor.json")
case $VENDOR in did:sigelo:*) ;; *) echo "setup: $DATA/keys/vendor.json names no DID" >&2; exit 1 ;; esac

# The root agent's token: once. `token new` rotates it, so never re-run it on a live soak
# without also restarting the keeper and rewriting root.token.
if [ ! -s "$DATA/root.token" ]; then
  node "$APP/spend/dist/cli.js" token new "$KEEPER/policy.json" soak-root > "$DATA/root.token.new"
  mv "$DATA/root.token.new" "$DATA/root.token"
fi
chmod 600 "$DATA/root.token" "$KEEPER/policy.json" "$KEEPER/spend.key" "$KEEPER/licence.json"

cat > "$DATA/bin/sigelo-wallet" <<W
#!/bin/sh
exec node "$APP/spend/dist/wallet.js" "\$@"
W
cat > "$DATA/bin/sigelo-spend" <<W
#!/bin/sh
exec node "$APP/spend/dist/cli.js" "\$@"
W
chmod 700 "$DATA/bin/sigelo-wallet" "$DATA/bin/sigelo-spend"

cat > "$DATA/env.sh" <<E
# . $DATA/env.sh — act as soak-root by hand (same token the agent uses)
export SIGELO_SOAK_DIR=$DATA
export SIGELO_WALLET_URL=http://127.0.0.1:$PORT
export SIGELO_WALLET_TOKEN=\$(cat $DATA/root.token)
export SIGELO_VENDOR_DID=$VENDOR   # the soak's test vendor: sigelo-spend licence show --dir $KEEPER
export PATH=$DATA/bin:\$PATH
E
chmod 600 "$DATA/env.sh"

mkdir -p "$HOME/.config/systemd/user"
cp "$HERE/systemd/"*.service "$HERE/systemd/"*.timer "$HOME/.config/systemd/user/"
# A drop-in, beside the unit's own SIGELO_DAEMONS (kept: Environment= lines add up); freeze.sh's
# freeze.conf lives in the same directory and unfreeze.sh removes only its own file.
mkdir -p "$HOME/.config/systemd/user/sigelo-soak-keeper.service.d"
printf '%s\n' '[Service]' "# setup.sh: this soak's TEST vendor (keys/vendor.json), the only issuer whose licence this keeper accepts" \
  "Environment=SIGELO_VENDOR_DID=$VENDOR" > "$HOME/.config/systemd/user/sigelo-soak-keeper.service.d/licence.conf"
systemctl --user daemon-reload

echo "setup: $DATA ready (code $(cat "$APP/REVISION"))."
echo "  start:  systemctl --user enable --now sigelo-soak-keeper.service sigelo-soak-agent.timer"
echo "  boot:   systemctl --user enable monero-wallet-rpc-stagenet.service   (enable only; see README)"
echo "  check:  node $APP/spend/soak/check.mjs"
echo "  alerts: systemctl --user enable --now sigelo-soak-check.timer   (hourly check.mjs --notify; see README)"
echo "  freeze: sh $APP/spend/soak/freeze.sh --now   (incident: evidence, Restart=no drop-ins, kill -9; dry run without --now)"
