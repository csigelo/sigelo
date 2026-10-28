#!/bin/sh
# Install (or refresh) the stagenet keeper soak under ~/.local/share/sigelo-soak.
# Idempotent: code is re-copied every run; keys (the test vendor's too), policy.json, spend.key,
# licence.json, spend.log, the root token and the agent's state are created once and never overwritten
# (except policy.json's wallet.login, set from keeper/wallet-rpc.conf when it differs).
# Needs: ts/ and spend/ built (npx tsc in each), monero-wallet-rpc on 127.0.0.1:38083.
#
# SIGELO_SOAK_NAME=<n> (a-z, 0-9): a SIDE-BY-SIDE soak in the 0.1.9 layout (README "A second soak"),
# beside the default one and touching none of its files or units:
#   dir      SIGELO_SOAK_DIR, default ~/.local/share/sigelo-soak-<n>
#   ports    keeper SIGELO_SOAK_PORT (38210), wallet-rpc SIGELO_SOAK_WALLET_PORT (38093)
#   wallet   a NEW stagenet wallet <dir>/wallet/allowance-<n>, created offline on the first run, its
#            password in <dir>/wallet/password (0600, --password-file); RPC login ON, in the 0600
#            <dir>/keeper/wallet-rpc.conf (--config-file) and policy.json's wallet.login, never argv
#   token    <dir>/root.token, outside the keeper directory (install.json agent_token_file)
#   daemons  SIGELO_SOAK_DAEMONS, default the default soak's four public stagenet nodes
#   units    sigelo-wallet-rpc-soak-<n>, sigelo-keeper-soak-<n> (the names sigelo-spend doctor vets),
#            sigelo-soak-agent-<n>.{service,timer} (:10, :40), sigelo-soak-check-<n>.{service,timer} (:45),
#            generated into <dir>/keeper/systemd/ with an install.json, so `sigelo-spend doctor --dir
#            <dir>/keeper` checks the layout; installed into ~/.config/systemd/user unless --no-systemd.
#   It needs no running wallet-rpc: while policy.json is missing it runs a temporary --offline one on
#   the wallet port (refused if something answers there that is not this soak's).
#   --mainnet (named soak only; --stagenet is the default): REAL coins. monero-wallet-rpc without
#            --stagenet, policy.json and install.json net "mainnet", SIGELO_SOAK_DAEMONS default = public
#            mainnet nodes over TLS (https:// -> --daemon-ssl enabled; the certificate verified and pinned
#            automatically by pin.mjs, or SIGELO_SOAK_DAEMON_PINS = hard pins), and the new wallet scans from
#            today, not genesis: restore height = `sigelo-spend restore-height --restore-date <today UTC>`
#            over the first daemon (spend/restore.ts), or SIGELO_SOAK_RESTORE_HEIGHT; never 0.
# setup.sh enables and starts nothing, in either mode.
set -eu
umask 077
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
die() { echo "setup: $*" >&2; exit 1; }
NOSYS=0 NET=stagenet
for a in "$@"; do case $a in --no-systemd) NOSYS=1 ;; --mainnet) NET=mainnet ;; --stagenet) NET=stagenet ;; *) die "usage: [SIGELO_SOAK_NAME=<n>] sh setup.sh [--no-systemd] [--stagenet | --mainnet]" ;; esac; done
NETFLAG=; [ "$NET" = mainnet ] || NETFLAG=--stagenet
NAME=${SIGELO_SOAK_NAME:-}
DEFAULT_DIR=$HOME/.local/share/sigelo-soak
if [ -z "$NAME" ]; then
  DATA=${SIGELO_SOAK_DIR:-$DEFAULT_DIR}
  # The default units (systemd/*) name ~/.local/share/sigelo-soak and the copy below replaces them and
  # their licence drop-in: from another directory that would repoint the live soak's keeper at a new
  # test vendor. A second directory is a named soak.
  [ "$DATA" = "$DEFAULT_DIR" ] || die "SIGELO_SOAK_DIR=$DATA without SIGELO_SOAK_NAME: the default units serve $DEFAULT_DIR only; for a soak beside it set SIGELO_SOAK_NAME (README \"A second soak\")"
  [ "$NOSYS" = 0 ] || die "--no-systemd is for a named soak (SIGELO_SOAK_NAME)"
  [ "$NET" = stagenet ] || die "--mainnet is for a named soak (SIGELO_SOAK_NAME)"
  PORT=38200
else
  case $NAME in *[!a-z0-9]*) die "SIGELO_SOAK_NAME=$NAME: use a-z and 0-9 only" ;; esac
  DATA=${SIGELO_SOAK_DIR:-$DEFAULT_DIR-$NAME}
  [ "$DATA" != "$DEFAULT_DIR" ] || die "a named soak needs its own directory, not $DEFAULT_DIR"
  PORT=${SIGELO_SOAK_PORT:-38210} WPORT=${SIGELO_SOAK_WALLET_PORT:-38093}
  [ "$PORT" != 38200 ] && [ "$WPORT" != 38083 ] || die "ports $PORT/$WPORT: 38200 and 38083 are the default soak's"
  if [ "$NET" = mainnet ]; then
    DAEMONS=${SIGELO_SOAK_DAEMONS:-https://node.monerodevs.org:18089 https://node2.monerodevs.org:18089 https://xmr-node.cakewallet.com:18081 https://node.sethforprivacy.com:443}
  else
    DAEMONS=${SIGELO_SOAK_DAEMONS:-node.monerodevs.org:38089 node2.monerodevs.org:38089 xmr-lux.boldsuck.org:38081 stagenet.xmr-tw.org:38081}
  fi
  FIRST=${DAEMONS%% *}
  # https:// = TLS required (wallet-rpc's autodetect falls back to plaintext), as sigelo-spend init does,
  # and PINNED: wallet-rpc 0.18 checks no CA and refuses --daemon-ssl enabled without a pin. By default
  # the pin is automatic, as init's (pin.mjs, below): the certificate verified by Node's CA store and
  # hostname, its SHA-256 in wallet-rpc.conf and keeper/daemon-pins.json, re-pinned by the keeper when
  # the node renews it. SIGELO_SOAK_DAEMON_PINS (hex, comma-separated) = hard pins on argv instead, never
  # re-pinned: a node with its own (self-signed) certificate.
  PINS=${SIGELO_SOAK_DAEMON_PINS:-}
  DSSL=; case $FIRST in https://*)
    DSSL="--daemon-ssl enabled"; for f in $(echo "$PINS" | tr ',' ' '); do DSSL="$DSSL --daemon-ssl-allowed-fingerprints $f"; done ;; esac
  WDIR=$DATA/wallet WNAME=allowance-$NAME
  RPC=http://127.0.0.1:$WPORT/json_rpc
  UW=sigelo-wallet-rpc-soak-$NAME.service UK=sigelo-keeper-soak-$NAME.service
  UA=sigelo-soak-agent-$NAME UC=sigelo-soak-check-$NAME
fi
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
cp "$HERE/agent.mjs" "$HERE/check.mjs" "$HERE/gen-keys.mjs" "$HERE/wallet-rpc.mjs" "$HERE/pin.mjs" "$HERE/policy.template.json" "$HERE/freeze.sh" "$HERE/unfreeze.sh" "$APP/spend/soak/"
chmod -R go-w "$APP"
( cd "$REPO" && git rev-parse --short HEAD 2>/dev/null || echo unknown ) > "$APP/REVISION"

# Keys (created once by gen-keys.mjs), then policy.json + spend.key from the template (read only: the
# identities and addresses are filled into $KEEPER/policy.json, never into the repository).
[ -f "$DATA/keys/S.hex" ] || { echo "setup: no $DATA/keys — run: node $HERE/gen-keys.mjs" >&2; exit 1; }
if [ -z "$NAME" ]; then
  # The default soak's wallet-rpc (systemd/monero-wallet-rpc-stagenet.service) reads its RPC login and
  # its password file's path from a 0600 config file, never argv: /proc/<pid>/cmdline is readable by
  # every local uid. Both files once; the password is the stagenet wallet's own, made before this.
  CONF=$KEEPER/wallet-rpc.conf PW=$KEEPER/wallet.password
  [ -s "$PW" ] || printf '%s' stagenet > "$PW"
  if [ ! -s "$CONF" ]; then
    printf '%s\n' "# monero-wallet-rpc --config-file for the default sigelo soak (setup.sh): off the command line" \
      "rpc-login=sigelo:$(node -e 'process.stdout.write(require("crypto").randomBytes(18).toString("base64url"))')" "password-file=$PW" > "$CONF"
  fi
  chmod 600 "$CONF" "$PW"
  SIGELO_SOAK_DIR=$DATA node "$APP/spend/soak/gen-keys.mjs" policy "$KEEPER"
  # A policy.json from before the login gets it; the keeper sends it only when wallet-rpc asks for one,
  # and reads it at start: restart the wallet-rpc unit, then the keeper (README "The wallet-rpc").
  node -e 'const fs=require("fs"),[p,c]=process.argv.slice(1),j=JSON.parse(fs.readFileSync(p,"utf8")),l=/^rpc-login=(\S+)$/m.exec(fs.readFileSync(c,"utf8"))?.[1];
    if (!l) { console.error(`setup: ${c} has no rpc-login`); process.exit(1); }
    if (j.wallet.login !== l) { j.wallet.login = l; fs.writeFileSync(p + ".new", JSON.stringify(j, null, 2) + "\n", { mode: 0o600 }); fs.renameSync(p + ".new", p); console.log(`setup: ${p}: wallet.login from ${c}`); }' "$KEEPER/policy.json" "$CONF"
else
  # The named soak's wallet: its own file, a password file, an RPC login in a 0600 config file, all once.
  mkdir -p "$WDIR"; chmod 700 "$WDIR"
  CONF=$KEEPER/wallet-rpc.conf PW=$WDIR/password
  RPCJ() { node "$APP/spend/soak/wallet-rpc.mjs" "$@"; }
  if [ ! -s "$CONF" ]; then
    printf '%s\n' "# monero-wallet-rpc --config-file for the sigelo soak '$NAME' (setup.sh): the login, off the command line" \
      "rpc-login=sigelo:$(node -e 'process.stdout.write(require("crypto").randomBytes(18).toString("base64url"))')" > "$CONF"
  fi
  [ -s "$PW" ] || node -e 'process.stdout.write(require("crypto").randomBytes(24).toString("base64url"))' > "$PW"
  chmod 600 "$CONF" "$PW"
  # The daemon pin, on every run (a re-run re-verifies): auto in $CONF, or the hard pins recorded.
  case $FIRST in https://*) node "$APP/spend/soak/pin.mjs" "$KEEPER" "$CONF" "$FIRST" "$PINS" || die "$FIRST: no pin (above)" ;; esac
  if [ ! -f "$WDIR/$WNAME.keys" ] || [ ! -f "$KEEPER/policy.json" ]; then
    # A temporary --offline wallet-rpc on the wallet port: create the wallet (and bob = 0/1, carol = 0/2,
    # the template's allowlist), then let gen-keys.mjs read their addresses. Never two on the port.
    if RPCJ "$RPC" "$CONF" get_version >/dev/null 2>&1; then
      die "something with this soak's login already answers on $RPC (its wallet-rpc unit?): stop it, then re-run setup.sh"
    fi
    /usr/bin/monero-wallet-rpc $NETFLAG --offline --wallet-dir "$WDIR" --rpc-bind-ip 127.0.0.1 --rpc-bind-port "$WPORT" \
      --config-file "$CONF" --non-interactive --log-file "$WDIR/setup-rpc.log" >/dev/null 2>&1 &
    TMP_RPC=$!
    trap 'kill "$TMP_RPC" 2>/dev/null; wait "$TMP_RPC" 2>/dev/null || true' EXIT
    i=0; until RPCJ "$RPC" "$CONF" get_version >/dev/null 2>&1; do
      i=$((i + 1)); [ $i -lt 60 ] || die "the temporary wallet-rpc on $RPC did not answer in 60 s ($WDIR/setup-rpc.log)"
      kill -0 "$TMP_RPC" 2>/dev/null || die "the temporary wallet-rpc exited (port $WPORT taken? $WDIR/setup-rpc.log)"
      sleep 1
    done
    if [ ! -f "$WDIR/$WNAME.keys" ]; then
      if [ "$NET" = mainnet ]; then
        # Mainnet: never a scan from genesis. A fresh wallet under a temporary name, then the same keys
        # as $WNAME by generate_from_keys with the restore height (keys pass RPC to RPC, never argv).
        RH=${SIGELO_SOAK_RESTORE_HEIGHT:-$(node "$APP/spend/dist/cli.js" restore-height --daemon "$FIRST" ${PINS:+--daemon-ssl-fingerprint "$PINS"} --restore-date "$(date -u +%Y-%m-%d)")}
        case $RH in ''|0|*[!0-9]*) die "mainnet restore height '$RH': the daemon $FIRST gave none (set SIGELO_SOAK_RESTORE_HEIGHT)" ;; esac
        RPCJ --password-file "$PW" "$RPC" "$CONF" create_wallet "{\"filename\":\"$WNAME.tmp\",\"language\":\"English\"}" >/dev/null
        node --input-type=module -e 'const [svc, rpc, conf, pwf, name, h] = process.argv.slice(1); const fs = await import("node:fs");
          const { walletRpc } = await import(svc); const login = /^rpc-login=(\S+)$/m.exec(fs.readFileSync(conf, "utf8"))[1]; const p = { wallet: { rpc, login } };
          const k = async (t) => (await walletRpc(p, "query_key", { key_type: t }, 60000)).key; const spendkey = await k("spend_key"), viewkey = await k("view_key");
          const { address } = await walletRpc(p, "get_address", { account_index: 0 }, 60000); await walletRpc(p, "close_wallet", {}, 60000);
          await walletRpc(p, "generate_from_keys", { filename: name, address, spendkey, viewkey, password: fs.readFileSync(pwf, "utf8"), restore_height: Number(h) }, 120000);' \
          "file://$APP/spend/dist/service.js" "$RPC" "$CONF" "$PW" "$WNAME" "$RH"
        rm -f "$WDIR/$WNAME.tmp" "$WDIR/$WNAME.tmp.keys"
        echo "$RH" > "$WDIR/restore-height"
        echo "setup: mainnet wallet restore height $RH (the first block of yesterday UTC, restore.ts; from $FIRST)"
      else
        RPCJ --password-file "$PW" "$RPC" "$CONF" create_wallet "{\"filename\":\"$WNAME\",\"language\":\"English\"}" >/dev/null
      fi
      RPCJ "$RPC" "$CONF" create_address '{"account_index":0,"label":"bob"}' >/dev/null
      RPCJ "$RPC" "$CONF" create_address '{"account_index":0,"label":"carol"}' >/dev/null
      echo "setup: created a NEW $NET wallet $WDIR/$WNAME (empty; fund it: README \"A second soak\")"
    else
      RPCJ --password-file "$PW" "$RPC" "$CONF" open_wallet "{\"filename\":\"$WNAME\"}" >/dev/null
    fi
    SIGELO_SOAK_DIR=$DATA SIGELO_SOAK_NET=$NET SIGELO_SOAK_WALLET_RPC=$RPC node "$APP/spend/soak/gen-keys.mjs" policy "$KEEPER"
    RPCJ "$RPC" "$CONF" close_wallet >/dev/null || true
    kill "$TMP_RPC"; wait "$TMP_RPC" 2>/dev/null || true; trap - EXIT
  else
    SIGELO_SOAK_DIR=$DATA node "$APP/spend/soak/gen-keys.mjs" policy "$KEEPER"
  fi
  node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); if (p.wallet.rpc!==process.argv[2]||!p.wallet.login||p.net!==process.argv[3]) { console.error(`setup: ${process.argv[1]}: ${JSON.stringify({net:p.net,rpc:p.wallet.rpc,login:!!p.wallet.login})}, want net ${process.argv[3]}, ${process.argv[2]} with a login`); process.exit(1); }' "$KEEPER/policy.json" "$RPC" "$NET"
fi

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

if [ -n "$NAME" ]; then
  # The named soak's units, generated (the files in systemd/ are the default soak's): into
  # $KEEPER/systemd, with an install.json in sigelo-spend init's shape, so doctor vets them.
  NODE=$(command -v node)
  SD=$KEEPER/systemd UD=$HOME/.config/systemd/user
  mkdir -p "$SD"; chmod 700 "$SD"
  cat > "$SD/$UW" <<U
[Unit]
Description=monero-wallet-rpc for the sigelo soak '$NAME' ($NET, 127.0.0.1:$WPORT)

[Service]
Type=simple
# Loopback, RPC login ON (in the 0600 --config-file and the keeper's policy.json, never argv), the
# wallet password from --password-file, an untrusted daemon: the first of SIGELO_SOAK_DAEMONS, the
# test host's PUBLIC $NET nodes (no own node on this host; spend/README.md "Choosing a daemon").
ExecStart=/usr/bin/monero-wallet-rpc $NETFLAG --wallet-file $WDIR/$WNAME --password-file $PW --daemon-address ${FIRST#https://} $DSSL --untrusted-daemon --rpc-bind-ip 127.0.0.1 --rpc-bind-port $WPORT --config-file $CONF --non-interactive --log-file $WDIR/wallet-rpc.log
Restart=on-failure
RestartSec=30
# wallet-rpc saves the wallet on SIGTERM; give it time. To keep it down: freeze.sh with SIGELO_FREEZE_*_UNIT.
TimeoutStopSec=60
UMask=0077

[Install]
WantedBy=default.target
U
  cat > "$SD/$UK" <<U
[Unit]
Description=sigelo-spend keeper for the $NET soak '$NAME' (127.0.0.1:$PORT)
After=$UW

[Service]
Type=simple
WorkingDirectory=$KEEPER
# The daemon fallback: the wallet-rpc's own --daemon-address first; the test host's public $NET nodes.
Environment="SIGELO_DAEMONS=$DAEMONS"
# This soak's TEST vendor (keys/vendor.json), the only issuer whose licence this keeper accepts.
Environment=SIGELO_VENDOR_DID=$VENDOR
ExecStart=$NODE $APP/spend/dist/cli.js serve $KEEPER/policy.json --port $PORT
Restart=always
RestartSec=10
UMask=0077

[Install]
WantedBy=default.target
U
  for kind in agent check; do
    if [ $kind = agent ]; then u=$UA; d="scripted agent, one tick"; at="*-*-* *:10,40:00"; x="$APP/spend/soak/agent.mjs"; t=25min
    else u=$UC; d="health check, --notify"; at="*-*-* *:45:00"; x="$APP/spend/soak/check.mjs --notify"; t=5min; fi
    cat > "$SD/$u.service" <<U
[Unit]
Description=sigelo soak '$NAME' $d
After=$UK

[Service]
Type=oneshot
$( [ $kind = agent ] && echo 'ExecCondition=/usr/bin/timeout 10 /usr/lib/systemd/systemd-time-wait-sync' )
Environment=SIGELO_SOAK_NAME=$NAME SIGELO_SOAK_DIR=$DATA SIGELO_SOAK_PORT=$PORT SIGELO_SOAK_WALLET_RPC=$RPC
ExecStart=$NODE $x
TimeoutStartSec=$t
UMask=0077
U
    cat > "$SD/$u.timer" <<U
[Unit]
Description=sigelo soak '$NAME' $kind ($at; the default soak's run at :00/:30 and :15)

[Timer]
OnCalendar=$at
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
U
  done
  UNITS="$UW $UK $UA.service $UA.timer $UC.service $UC.timer"
  SYS=true; [ "$NOSYS" = 0 ] || SYS=false
  KDID=$(node --input-type=module -e "const m = await import(process.argv[1]); const fs = await import('node:fs'); const k = fs.readFileSync(process.argv[2] + '/spend.key', 'utf8').trim(); console.log(m.loadKeeper(process.argv[2], Uint8Array.from(Buffer.from(k, 'hex'))).did)" "file://$APP/spend/dist/service.js" "$KEEPER")
  NET=$NET PINS=$( case $FIRST in https://*) echo "$PINS" ;; esac ) node -e 'const [f, ...a] = process.argv.slice(1); const [port, rpc, daemons, sys, ud, units, did, app, node, tok, name] = a;
    require("fs").writeFileSync(f, JSON.stringify({ v: 1, note: `written by spend/soak/setup.sh for the soak ${name}, in sigelo-spend init'"'"'s shape (doctor reads it); not an init install`,
      net: process.env.NET, port: Number(port), agent: "soak-root", account: 0, wallet_rpc: rpc, created_wallet_rpc: true, daemons: daemons.split(" "),
      daemon_proxy: null, daemon_ssl_fingerprints: (process.env.PINS ?? "").split(",").filter((x) => x !== ""), daemon_login_file: null,
      daemon_ssl_pin: daemons.split(" ")[0].startsWith("https://") ? ((process.env.PINS ?? "") !== "" ? "hard" : "auto") : null, systemd: sys === "true", unit_dir: sys === "true" ? ud : null,
      units: units.split(" "), keeper_did: did, app, node, created: new Date().toISOString().replace(/\.\d+Z$/, "Z"), agent_token_file: tok, layout: "single-user" }, null, 2) + "\n", { mode: 0o600 });' \
    "$KEEPER/install.json" "$PORT" "$RPC" "$DAEMONS" "$SYS" "$UD" "$UNITS" "$KDID" "$APP/spend/dist/cli.js" "$NODE" "$DATA/root.token" "$NAME"
  chmod 600 "$KEEPER/install.json" "$SD"/*
  if [ "$NOSYS" = 0 ]; then
    mkdir -p "$UD"
    for u in $UNITS; do cp "$SD/$u" "$UD/$u"; done
    systemctl --user daemon-reload
  fi
  echo "setup: $DATA ready (code $(cat "$APP/REVISION")), soak '$NAME': keeper 127.0.0.1:$PORT, wallet-rpc $RPC (login in $CONF)."
  echo "  units:  $SD/ $( [ "$NOSYS" = 0 ] && echo "installed in $UD" || echo "(--no-systemd: not installed)")"
  echo "  doctor: . $DATA/env.sh && sigelo-spend doctor --dir $KEEPER"
  echo "  start:  systemctl --user enable --now $UW; then $UK; then $UA.timer $UC.timer  (README \"A second soak\")"
  exit 0
fi

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
