#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/server-setup.sh — ONE-TIME preparation of a fresh Debian/Ubuntu or Alpine server for
# sigelo.io, or (--relay) of a Debian server for the relay on sigelo.ai. Run as root ON THE SERVER,
# by hand; deploy.sh never runs it. site/deploy/README.md describes every step.
#
#   # from the repository, on your machine (nginx.conf and the helper must sit beside the script):
#   scp site/deploy/server-setup.sh site/deploy/nginx.conf site/deploy/sigelo-nginx-apply root@HOST:/root/sigelo-setup/
#   ssh root@HOST 'sh /root/sigelo-setup/server-setup.sh --key "ssh-ed25519 AAAA... deploy"'
#
# Options:
#   --os debian|alpine   default: detected from /etc/os-release
#   --key 'ssh-ed25519 …'  the deploy public key for the `sigelo` user (or --key-file FILE)
#   --email ADDR          give Let's Encrypt an address (default: none — registered without one,
#                         so the ACME account is not tied to a person; LE no longer sends expiry mail)
#   --test-cert           use Let's Encrypt's staging CA (untrusted cert, no rate limits) for a dry run
#   --skip-cert           do not run certbot (a certificate is already at /etc/letsencrypt/live/sigelo.io)
#   --certs               ONLY the certificate step (6), on a server this script prepared and deploy.sh
#                         has installed nginx.conf on (nothing beside it needed; node for the DNS
#                         test): adds each of sigelo.online, .dev (apex, www) whose DNS points here to the
#                         sigelo.io lineage, prints the names skipped. Idempotent: rerun it after DNS
#                         changes; it re-issues only when a pointed name is missing from the certificate
#   --stats               ONLY the visit-statistics step, on a server this script already prepared
#                         (needs sigelo-nginx-apply and stats-agents.sh beside it): goaccess, the
#                         /_stats/ password file, the 15-minute sigelo-stats timer, the helper
#                         refreshed (its allowlist knows auth_basic), log rotation at 30 days. A
#                         fresh server runs the script once without it, then once with it.
#   --world SHA256      ONLY the world step (world/README.md), on a server this script prepared and
#                         deploy.sh has shipped world-app/ to (needs sigelo-world.service and
#                         sigelo-world-apply beside it; Debian/systemd): nodejs, the system user
#                         sigelo-world (sole owner of /var/lib/sigelo-world; migrates a world that
#                         ran as sigelo), the unit, the second sudo rule, and — first time only —
#                         the issuer key, made here with the recovery COMMITMENT given
#                         (sha256:<64 hex>; the recovery key itself never comes here). Prints
#                         the issuer genesis: commit it as world/genesis.json.
#   --guard             ONLY the self-healing step, on a server this script prepared (Debian/systemd;
#                         nothing beside it needed): nginx.service gets Restart=on-failure (a
#                         drop-in; Debian ships Restart=no), sigelo-world.service is checked for
#                         its Restart=always, and /usr/local/sbin/sigelo-selfcheck runs hourly
#                         (sigelo-selfcheck.timer, root): it fetches / and /world/stats through
#                         nginx on 127.0.0.1 and /world/stats from the world on 127.0.0.1:8790,
#                         restarts whichever unit fails, and logs to the journal
#   --backup AGE-RECIPIENT  ONLY the state-backup step (Debian/systemd): age, the recipient
#                         (age1…, the PUBLIC half; the identity stays on the Owner's phone) in
#                         /etc/sigelo-backup.recipient, /usr/local/sbin/sigelo-vps-backup and
#                         sigelo-vps-backup.timer (daily 03:30 Europe/Berlin): the world state, the
#                         nginx config and stats password file, /etc/letsencrypt, the sigelo units,
#                         helpers and sudo rule, the release mirror and stats if present, as
#                         <admin home>/backup/vps-state-<stamp>.tgz.age (admin user, 0600, 7 kept);
#                         runs it once. Restore: site/deploy/README.md, "Rebuilding the server"
#   --stats-htpasswd FILE with --stats: install FILE (one line, owner:<crypt hash>, e.g. from
#                         `openssl passwd -6 -stdin`) as /etc/nginx/sigelo-stats.htpasswd; without
#                         it an existing file is kept, and a missing one gets a random password,
#                         printed once
#   --relay               the RELAY host instead (Debian/systemd; none of the sigelo.io steps), with
#                         sigelo-relay-apply and sigelo-relay.service beside this script (deploy/ of
#                         the relay's own repository, csigelo/sigelo-relay; backup.sh too with
#                         --backup). Idempotent; each step says what it
#                         kept or changed: packages; UTC and NTP; journald capped, the relay's
#                         namespace 7 days (files rotated daily); users csigelo (admin, sudo with
#                         its password: set it with passwd), sigelo (deploy, key only: its keys in
#                         /etc/ssh/authorized_keys/sigelo, root's, which --key replaces whole; no
#                         cron or at),
#                         sigelo-relay (runs the relay); Node.js 24 from NodeSource (the keyring
#                         must hold the one pinned key; Debian's nodejs has
#                         no node:sqlite); /var/lib/sigelo-relay (0700), /opt/sigelo-relay, the
#                         site link /var/www/sigelo.ai/dist; the unit, /etc/sigelo-relay.env
#                         (kept once written), the helper and its sudo rule; nginx (errors at crit,
#                         its logs 7 days); the certificates (webroot): lineage sigelo.ai for each
#                         of sigelo.ai, www.sigelo.ai, relay.sigelo.ai whose DNS points here
#                         (nginx), lineage relay.sigelo.ai for that name alone (the broker's: a key
#                         taken from it is valid for no other name), rerun after DNS changes, a
#                         --test-cert one replaced by a run without it; the broker's lineage, and
#                         no other, copied for it by a deploy hook, and by this script whenever
#                         the copy is missing or stale (after a restore); fail2ban;
#                         unattended upgrades rebooting at 04:30 UTC when
#                         needed; nftables (22, 80, 443, 8883; armed with a 3-minute rollback the
#                         first time, confirmed by hand from a new ssh session); sshd key only,
#                         root off, AllowUsers csigelo sigelo — only once csigelo has a password,
#                         is in group sudo and both users have a key; nginx Restart=on-failure and
#                         the hourly sigelo-relay-selfcheck.timer (restarts the relay or nginx).
#                         Exits 1 while something is left to do, and says what.
#     --admin-key 'ssh-ed25519 …'  with --relay: csigelo's public key (or --admin-key-file FILE)
#     --backup AGE-RECIPIENT       with --relay: backup.sh as /usr/local/sbin/sigelo-relay-backup
#                         and sigelo-relay-backup.timer (daily 03:30 Europe/Berlin): licences,
#                         operator chains, config; never a mailbox (relay/deploy/backup.sh)
#     --key, --email, --test-cert, --skip-cert   as for sigelo.io (--key: the deploy user's key)
#   --self-test           no root, changes nothing: checks the sudo rules this script writes (each
#                         helper with only the argument lists its deploy.sh sends)
#
# Requires: DNS A (and AAAA, if the server has IPv6) for sigelo.io, www.sigelo.io, sigelo.net and
# www.sigelo.net already pointing here, and ports 80/443 open — certbot proves control over HTTP-01
# on port 80. sigelo.online and .dev join the certificate once their DNS points here (step 6).
# sigelo.ai is the relay's (--relay), on its own host; sigelo.org is parked.
# Idempotent: re-running skips what is already in place.
set -eu

DOMAIN=sigelo.io
ALT=sigelo.net          # also owned; redirect-only (nginx.conf), on the one certificate lineage
# Also owned, redirect-only like $ALT (nginx.conf: one server group each); apex and www of each join
# the same lineage as soon as their DNS points at this host.
EXTRA="sigelo.online sigelo.dev"
WEBROOT=/var/www/sigelo.io
ACME=/var/www/acme
HERE=$(cd "$(dirname "$0")" && pwd)

say() { printf '\n==> %s\n' "$*"; }
run() { printf '+ %s\n' "$*"; "$@"; }
die() { printf 'server-setup.sh: %s\n' "$*" >&2; exit 1; }

# The deploy user's sudo rules: each root helper with only the argument lists its deploy.sh sends
# ("" = none). A bare path lets sudo pass any arguments, and `--check FILE` run as root prints the
# lines of any file: the deploy key could read what only root may.
NGINX_APPLY=/usr/local/sbin/sigelo-nginx-apply WORLD_APPLY=/usr/local/sbin/sigelo-world-apply RELAY_APPLY=/usr/local/sbin/sigelo-relay-apply
site_rules() {  # $1 = 1 once --world installed its helper
  printf 'sigelo ALL=(root) NOPASSWD: %s "", %s --os debian, %s --os alpine\n' $NGINX_APPLY $NGINX_APPLY $NGINX_APPLY
  [ "$1" = 0 ] || printf 'sigelo ALL=(root) NOPASSWD: %s ""\n' $WORLD_APPLY
}
relay_rules() { printf 'sigelo ALL=(root) NOPASSWD: %s "", %s --rollback\n' $RELAY_APPLY $RELAY_APPLY; }
# The relay host's certbot deploy hook (--relay, R9): the broker gets a copy of its own lineage,
# relay.sigelo.ai, and of no other.
relay_hook() {
  cat <<'HOOK'
#!/bin/sh
# written by site/deploy/server-setup.sh --relay; certbot runs it after each renewal of any lineage
# (and server-setup.sh whenever the broker's copy is missing or stale). nginx serves sigelo.ai, www
# and relay.sigelo.ai from /etc/letsencrypt/live/sigelo.ai, and reloads after either lineage. The
# broker terminates TLS itself and runs as sigelo-relay, which cannot read /etc/letsencrypt: it
# gets a copy of /etc/letsencrypt/live/relay.sigelo.ai, a lineage for relay.sigelo.ai alone, and of
# no other, so a key taken from the broker is valid for no other name (sigelo.ai's pay pages). It
# re-reads the copy on SIGHUP (connections stay).
set -eu
L=${RENEWED_LINEAGE:-}
case $L in
  */live/relay.sigelo.ai)
    install -d -m 0755 -o root -g root /etc/sigelo-relay
    install -d -m 0700 -o sigelo-relay -g sigelo-relay /etc/sigelo-relay/tls
    install -m 0600 -o sigelo-relay -g sigelo-relay "$L/fullchain.pem" "$L/privkey.pem" /etc/sigelo-relay/tls/
    systemctl try-reload-or-restart sigelo-relay.service ;;
esac
systemctl try-reload-or-restart nginx.service
HOOK
}
# sudo_may CMD [ARG...]: whether the installed policy lets sigelo run exactly that command line as
# root (sudo -l with a command answers for that command line; root is never asked a password).
sudo_may() { sudo -n -l -U sigelo "$@" >/dev/null 2>&1; }
# --self-test (no root; release/publish.sh runs it): every command in the rules above names a helper
# and a plain argument list. No list, or a wildcard in it, and sudo passes arguments of the caller's.
self_test() {
  { site_rules 1; relay_rules; } | awk '
    function bad(m) { print "server-setup.sh --self-test: " m; err = 1 }
    !sub(/^sigelo ALL=\(root\) NOPASSWD: /, "") { bad("not a sigelo NOPASSWD rule: " $0); next }
    { n = split($0, c, /, /)
      for (i = 1; i <= n; i++) if (c[i] !~ /^\/usr\/local\/sbin\/sigelo-[a-z-]+ (""|-[-a-z0-9 ]*[a-z0-9])$/) bad("not a helper with a plain argument list (sudo would pass any): " c[i]) }
    END { exit err }' || die "self-test FAILED (above)"
  echo "server-setup.sh --self-test: every sudo rule names its helper's argument lists"
  # The deploy hook, run with install and systemctl stubbed: a renewal of sigelo.ai's lineage
  # copies nothing for the broker (that key is valid for the pay pages), one of relay.sigelo.ai's
  # copies that lineage.
  t=$(mktemp -d)
  mkdir "$t/bin"
  for c in install systemctl; do printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\n' "$c" "$t" > "$t/bin/$c"; chmod 0755 "$t/bin/$c"; done
  relay_hook > "$t/hook"
  : > "$t/calls"; PATH="$t/bin:$PATH" RENEWED_LINEAGE=/etc/letsencrypt/live/sigelo.ai sh "$t/hook"
  a=$(grep -c '^install' "$t/calls" || true)
  : > "$t/calls"; PATH="$t/bin:$PATH" RENEWED_LINEAGE=/etc/letsencrypt/live/relay.sigelo.ai sh "$t/hook"
  b=$(grep -c '^install .* /etc/letsencrypt/live/relay.sigelo.ai/fullchain.pem /etc/letsencrypt/live/relay.sigelo.ai/privkey.pem /etc/sigelo-relay/tls/$' "$t/calls" || true)
  rm -rf "$t"
  [ "$a" = 0 ] || die "self-test FAILED: the deploy hook copies files for the broker on a renewal of sigelo.ai's lineage"
  [ "$b" = 1 ] || die "self-test FAILED: the deploy hook does not copy relay.sigelo.ai's lineage for the broker"
  echo "server-setup.sh --self-test: the deploy hook copies relay.sigelo.ai's lineage for the broker, and not sigelo.ai's"
}

os=""; key=""; email=""; testcert=""; skipcert=0; certs=0; stats=0; htfile=""; world=""; guard=0; backup=""; relay=0; adminkey=""; selftest=0
while [ $# -gt 0 ]; do
  case $1 in
    --os) os=$2; shift 2 ;;
    --key) key=$2; shift 2 ;;
    --key-file) key=$(cat "$2"); shift 2 ;;
    --email) email=$2; shift 2 ;;
    --test-cert) testcert=--test-cert; shift ;;
    --skip-cert) skipcert=1; shift ;;
    --certs) certs=1; shift ;;
    --stats) stats=1; shift ;;
    --stats-htpasswd) htfile=$2; shift 2 ;;
    --world) world=$2; shift 2 ;;
    --guard) guard=1; shift ;;
    --backup) backup=$2; shift 2 ;;
    --relay) relay=1; shift ;;
    --admin-key) adminkey=$2; shift 2 ;;
    --admin-key-file) adminkey=$(cat "$2"); shift 2 ;;
    --self-test) selftest=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [ "$selftest" = 1 ]; then self_test; exit 0; fi
[ "$(id -u)" = 0 ] || die "run as root"
if [ "$relay" = 1 ]; then
  [ "$stats$guard$certs" = 000 ] && [ -z "$world$htfile" ] || die "--relay goes alone (with --key, --admin-key, --backup, --email, --test-cert, --skip-cert)"
  need="sigelo-relay-apply sigelo-relay.service"; [ -z "$backup" ] || need="$need backup.sh"
elif [ -n "$adminkey" ]; then die "--admin-key goes with --relay"
elif [ "$stats" = 1 ]; then need="sigelo-nginx-apply stats-agents.sh"
elif [ -n "$world" ]; then need="sigelo-nginx-apply sigelo-world-apply sigelo-world.service"
elif [ "$guard" = 1 ] || [ -n "$backup" ] || [ "$certs" = 1 ]; then need=""
else need="nginx.conf sigelo-nginx-apply"; fi
for f in $need; do [ -f "$HERE/$f" ] || die "$HERE/$f missing: copy it next to this script"; done
[ -z "$htfile" ] || [ "$stats" = 1 ] || die "--stats-htpasswd goes with --stats"
if [ -z "$os" ]; then
  . /etc/os-release
  case "$ID ${ID_LIKE:-}" in *alpine*) os=alpine ;; *debian*|*ubuntu*) os=debian ;; *) die "unsupported OS '$ID': pass --os debian|alpine" ;; esac
fi
case $os in
  debian) CONF=/etc/nginx/conf.d/$DOMAIN.conf ;;
  alpine) CONF=/etc/nginx/http.d/$DOMAIN.conf ;;
  *) die "--os must be debian or alpine" ;;
esac
KEY_RE='^(ssh-ed25519|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh.com|ssh-rsa) [A-Za-z0-9+/=]+( .*)?$'
if [ -n "$key" ]; then printf '%s' "$key" | grep -Eq "$KEY_RE" || die "--key does not look like one OpenSSH public key line"; fi
if [ -n "$adminkey" ]; then printf '%s' "$adminkey" | grep -Eq "$KEY_RE" || die "--admin-key does not look like one OpenSSH public key line"; fi
if [ "$relay" = 1 ]; then echo "server-setup.sh: the relay host ($os)"; else echo "server-setup.sh: $os, config $CONF, web root $WEBROOT"; fi

install_helper() {
  run install -m 0755 -o root -g root "$HERE/sigelo-nginx-apply" $NGINX_APPLY
  # the world's rule exists once --world installed its helper (re-running --stats keeps it)
  if [ -x $WORLD_APPLY ]; then w=1; else w=0; fi
  printf '+ write /etc/sudoers.d/sigelo-deploy\n'
  site_rules $w > /etc/sudoers.d/sigelo-deploy.tmp
  chmod 0440 /etc/sudoers.d/sigelo-deploy.tmp
  run visudo -cf /etc/sudoers.d/sigelo-deploy.tmp
  run mv /etc/sudoers.d/sigelo-deploy.tmp /etc/sudoers.d/sigelo-deploy
  # The installed policy, as sudo answers it (rules in /etc/sudoers count too). What deploy.sh runs
  # is asked first, so a sudo that refuses every query cannot pass the refusals after it.
  sudo_may $NGINX_APPLY && sudo_may $NGINX_APPLY --os debian && sudo_may $NGINX_APPLY --os alpine \
    || die "sudo -l: sigelo may not run $NGINX_APPLY with no argument or --os debian|alpine, as deploy.sh does"
  [ $w = 0 ] || sudo_may $WORLD_APPLY || die "sudo -l: sigelo may not run $WORLD_APPLY with no argument, as deploy.sh does"
  if sudo_may $NGINX_APPLY --check /etc/shadow || { [ $w = 1 ] && sudo_may $WORLD_APPLY --any-argument; }; then
    rm -f /etc/sudoers.d/sigelo-deploy
    die "sudo -l: sigelo may run a helper with other arguments ($NGINX_APPLY --check FILE prints any file as root); a rule in /etc/sudoers or /etc/sudoers.d allows it: /etc/sudoers.d/sigelo-deploy removed"
  fi
  if [ $w = 1 ]; then echo "sudo: sigelo may run $NGINX_APPLY with no argument or --os debian|alpine, $WORLD_APPLY with no argument; nothing else"
  else echo "sudo: sigelo may run $NGINX_APPLY with no argument or --os debian|alpine; nothing else"; fi
}

# 30 days: the window the statistics cover. The log holds no raw address (nginx.conf, Privacy).
# access-self.log (the project's own requests, nginx.conf $sigelo_self): 7 days, for debugging.
write_logrotate() {
  printf '+ write /etc/logrotate.d/sigelo\n'
  cat > /etc/logrotate.d/sigelo <<'ROT'
/var/log/nginx/sigelo/access.log /var/log/nginx/sigelo/error.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        nginx -s reopen 2>/dev/null || true
    endscript
}
/var/log/nginx/sigelo/access-self.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        nginx -s reopen 2>/dev/null || true
    endscript
}
ROT
}

if [ "$guard" = 1 ]; then
  [ "$os" = debian ] && [ -d /run/systemd/system ] || die "--guard needs Debian/Ubuntu with systemd"
  command -v curl >/dev/null 2>&1 || run env DEBIAN_FRONTEND=noninteractive apt-get install -y curl

  say "G1. nginx restarts on failure (drop-in; the Debian unit has Restart=no)"
  run install -d -m 0755 /etc/systemd/system/nginx.service.d
  printf '+ write /etc/systemd/system/nginx.service.d/sigelo-restart.conf\n'
  cat > /etc/systemd/system/nginx.service.d/sigelo-restart.conf <<'UNIT'
# written by site/deploy/server-setup.sh --guard
[Unit]
StartLimitIntervalSec=10min
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=5s
UNIT
  run systemctl daemon-reload

  say "G2. sigelo-world.service restarts itself (Restart=always in the unit file)"
  if [ "$(systemctl show -p Restart --value sigelo-world.service)" = always ]; then echo "sigelo-world.service: Restart=always"
  else echo "sigelo-world.service: Restart is not 'always': run --world again to reinstall the unit"; fi
  echo "nginx.service: Restart=$(systemctl show -p Restart --value nginx.service)"

  say "G3. /usr/local/sbin/sigelo-selfcheck and sigelo-selfcheck.timer (hourly)"
  printf '+ write /usr/local/sbin/sigelo-selfcheck\n'
  cat > /usr/local/sbin/sigelo-selfcheck.tmp <<'RUN'
#!/bin/sh
# sigelo-selfcheck — written by site/deploy/server-setup.sh --guard; run hourly by
# sigelo-selfcheck.timer as root. Fetches / and /world/stats through nginx on 127.0.0.1 (TLS,
# server name sigelo.io) and /world/stats from the world itself on 127.0.0.1:8790; restarts the
# unit that fails (nginx only after nginx -t passes), checks again, logs every step to the journal
# (journalctl -u sigelo-selfcheck). Exit 1 when something is still down after its restart.
# User-Agent UA: nginx logs it to access-self.log, out of the visit statistics.
set -u
UA='sigelo-selfcheck/1 (+https://sigelo.io/privacy)'
site() { curl -fsS -o /dev/null --max-time 15 -A "$UA" --resolve sigelo.io:443:127.0.0.1 "https://sigelo.io$1"; }
world() { curl -fsS -o /dev/null --max-time 10 -A "$UA" http://127.0.0.1:8790/world/stats; }
rc=0
if ! world; then
  echo "sigelo-selfcheck: the world on 127.0.0.1:8790 does not answer /world/stats: restarting sigelo-world.service"
  systemctl restart sigelo-world.service; sleep 5
  if world; then echo "sigelo-selfcheck: sigelo-world back after restart"; else echo "sigelo-selfcheck: sigelo-world STILL DOWN"; rc=1; fi
fi
if ! site / || ! site /world/stats; then
  echo "sigelo-selfcheck: nginx does not serve / or /world/stats on 127.0.0.1: restarting nginx"
  if nginx -t 2>&1; then systemctl restart nginx.service; sleep 3
  else echo "sigelo-selfcheck: nginx -t fails: not restarting"; fi
  if site / && site /world/stats; then echo "sigelo-selfcheck: nginx back after restart"; else echo "sigelo-selfcheck: / or /world/stats STILL DOWN"; rc=1; fi
fi
[ $rc = 0 ] && echo "sigelo-selfcheck: ok (/, /world/stats via nginx; world on :8790)"
exit $rc
RUN
  chmod 0755 /usr/local/sbin/sigelo-selfcheck.tmp
  mv /usr/local/sbin/sigelo-selfcheck.tmp /usr/local/sbin/sigelo-selfcheck
  printf '+ write /etc/systemd/system/sigelo-selfcheck.service and .timer\n'
  cat > /etc/systemd/system/sigelo-selfcheck.service <<'UNIT'
[Unit]
Description=sigelo.io self-check: /, /world/stats on localhost; restart nginx or the world on failure
After=nginx.service sigelo-world.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sigelo-selfcheck
TimeoutStartSec=3min
UNIT
  cat > /etc/systemd/system/sigelo-selfcheck.timer <<'UNIT'
[Unit]
Description=sigelo.io self-check, hourly

[Timer]
OnBootSec=10min
OnCalendar=hourly
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
UNIT
  run systemctl daemon-reload
  run systemctl enable --now sigelo-selfcheck.timer
  run systemctl start sigelo-selfcheck.service
  journalctl -u sigelo-selfcheck.service -n 3 --no-pager -o cat || true
  say "done"
  exit 0
fi

if [ -n "$backup" ] && [ "$relay" = 0 ]; then
  [ "$os" = debian ] && [ -d /run/systemd/system ] || die "--backup needs Debian/Ubuntu with systemd"
  printf '%s' "$backup" | grep -Eq '^age1[02-9ac-hj-np-z]{58}$' || die "--backup wants an age recipient (age1…, the public key; never the identity)"
  id csigelo >/dev/null 2>&1 || die "no user csigelo: the archives are written to its ~/backup"

  say "B1. age"
  command -v age >/dev/null 2>&1 || run env DEBIAN_FRONTEND=noninteractive apt-get install -y age

  say "B2. the recipient (public key only) in /etc/sigelo-backup.recipient"
  printf '%s\n' "$backup" > /etc/sigelo-backup.recipient
  chmod 0644 /etc/sigelo-backup.recipient

  say "B3. /usr/local/sbin/sigelo-vps-backup"
  cat > /usr/local/sbin/sigelo-vps-backup.tmp <<'RUN'
#!/bin/sh
# sigelo-vps-backup — written by site/deploy/server-setup.sh --backup; run daily by
# sigelo-vps-backup.timer as root. Tars the server's state, encrypts it with age to the recipient in
# /etc/sigelo-backup.recipient (its identity is on the Owner's phone only: this server cannot read
# its own backups) and writes <admin home>/backup/vps-state-<stamp>.tgz.age, admin user 0600, 7 kept.
# The phone's nightly sigelo-backup fetches the newest one. Restore: site/deploy/README.md.
set -eu
OUT="$(getent passwd csigelo | cut -d: -f6)/backup"
R=$(cat /etc/sigelo-backup.recipient)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
umask 077
list=""
for p in /var/lib/sigelo-world /etc/sigelo-world.env /etc/nginx/conf.d/sigelo* /etc/nginx/sigelo-stats.htpasswd \
         /etc/letsencrypt /etc/systemd/system/sigelo-* /etc/systemd/system/nginx.service.d \
         /usr/local/sbin/sigelo-* /usr/local/bin/sigelo-* /etc/sudoers.d/sigelo-deploy /etc/logrotate.d/sigelo \
         /etc/sigelo-backup.recipient /var/backups/sigelo-nginx /var/www/sigelo.io/releases /var/www/sigelo.io/stats; do
  if [ -e "$p" ]; then list="$list ${p#/}"; fi
done
install -d -m 0700 -o csigelo -g csigelo "$OUT"
tmp=$OUT/.vps-state-$STAMP.tmp
# shellcheck disable=SC2086
tar -C / -czf - $list | age -r "$R" -o "$tmp"
chown csigelo:csigelo "$tmp"; chmod 0600 "$tmp"
mv "$tmp" "$OUT/vps-state-$STAMP.tgz.age"
( cd "$OUT" && ls -t vps-state-*.tgz.age | tail -n +8 | xargs -r rm -f )
echo "sigelo-vps-backup: $OUT/vps-state-$STAMP.tgz.age, $(wc -c < "$OUT/vps-state-$STAMP.tgz.age") bytes:$list"
RUN
  chmod 0755 /usr/local/sbin/sigelo-vps-backup.tmp
  mv /usr/local/sbin/sigelo-vps-backup.tmp /usr/local/sbin/sigelo-vps-backup

  say "B4. sigelo-vps-backup.service and .timer (daily 03:30 Europe/Berlin, before the phone's 04:00 pull)"
  BKDIR="$(getent passwd csigelo | cut -d: -f6)/backup"
  cat > /etc/systemd/system/sigelo-vps-backup.service <<'UNIT'
[Unit]
Description=sigelo.io state backup, age-encrypted to the Owner's phone key

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sigelo-vps-backup
Nice=10
IOSchedulingClass=idle
ProtectSystem=strict
ReadWritePaths=__BKDIR__
PrivateTmp=yes
PrivateNetwork=yes
PrivateDevices=yes
NoNewPrivileges=yes
UNIT
  sed -i "s|__BKDIR__|$BKDIR|" /etc/systemd/system/sigelo-vps-backup.service
  cat > /etc/systemd/system/sigelo-vps-backup.timer <<'UNIT'
[Unit]
Description=sigelo.io state backup, daily

[Timer]
OnCalendar=*-*-* 03:30:00 Europe/Berlin
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  run systemctl daemon-reload
  run systemctl enable --now sigelo-vps-backup.timer
  run systemctl start sigelo-vps-backup.service
  journalctl -u sigelo-vps-backup.service -n 1 --no-pager -o cat || true
  say "done"
  exit 0
fi

if [ -n "$world" ]; then
  APP=$WEBROOT/world-app
  STATE=/var/lib/sigelo-world
  [ "$os" = debian ] && [ -d /run/systemd/system ] || die "--world needs Debian/Ubuntu with systemd"
  [ -f "$APP/world/server.mjs" ] || die "$APP/world/server.mjs missing: run deploy.sh once first (it ships world-app/)"

  say "W1. nodejs"
  command -v node >/dev/null 2>&1 || run env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
  node -e 'process.exit(+process.versions.node.split(".")[0] >= 20 ? 0 : 1)' || die "node >= 20 needed, have $(node -v)"

  say "W2. the restart helper, the second sudo rule (and the nginx helper, whose allowlist knows /world/)"
  run install -m 0755 -o root -g root "$HERE/sigelo-world-apply" /usr/local/sbin/sigelo-world-apply
  install_helper

  say "W3. the system user sigelo-world (no shell, no ssh), sole owner of the issuer key in $STATE"
  # The deploy user (sigelo) must not read the key: before this step the world ran as sigelo and
  # owned $STATE. Idempotent migration: stop the unit, hand $STATE to sigelo-world, then restart
  # under the new unit (W4). The path is unchanged, so /etc/sigelo-world.env and the DID are too.
  if ! id sigelo-world >/dev/null 2>&1; then
    run useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sigelo-world
  fi
  run passwd -l sigelo-world >/dev/null
  if systemctl is-active --quiet sigelo-world.service && [ "$(systemctl show -p User --value sigelo-world.service)" != sigelo-world ]; then
    run systemctl stop sigelo-world.service
  fi
  run install -d -m 0700 -o sigelo-world -g sigelo-world "$STATE"
  run chown -R sigelo-world:sigelo-world "$STATE"
  run find "$STATE" -type f -exec chmod 0600 {} +
  if [ -f "$STATE/issuer.json" ]; then echo "$STATE/issuer.json exists: kept"
  else
    printf '%s' "$world" | grep -Eq '^sha256:[0-9a-f]{64}$' || die "--world wants the recovery commitment, sha256:<64 lowercase hex>"
    run su -s /bin/sh sigelo-world -c "umask 077; node $APP/world/server.mjs keygen $world $STATE/issuer.json >/dev/null"
  fi
  # the point of this step, checked: the deploy user cannot read the key
  if su -s /bin/sh sigelo -c "test -r $STATE/issuer.json" 2>/dev/null; then die "the deploy user can still read $STATE/issuer.json"; fi
  printf '+ write /etc/sigelo-world.env\n'
  printf 'SIGELO_WORLD_KEY=%s/issuer.json\nSIGELO_WORLD_PORT=8790\n' "$STATE" > /etc/sigelo-world.env
  chmod 0644 /etc/sigelo-world.env

  say "W4. sigelo-world.service (as sigelo-world; code copied root-owned to /opt/sigelo-world/app by the helper)"
  run install -m 0644 -o root -g root "$HERE/sigelo-world.service" /etc/systemd/system/sigelo-world.service
  run systemctl daemon-reload
  run systemctl enable sigelo-world.service
  run /usr/local/sbin/sigelo-world-apply

  say "done: the issuer genesis (commit it as world/genesis.json, then deploy):"
  su -s /bin/sh sigelo-world -c "node -e 'const g=JSON.parse(require(\"fs\").readFileSync(process.argv[1],\"utf8\")).genesis;console.log(JSON.stringify(g))' $STATE/issuer.json"
  exit 0
fi

if [ "$stats" = 1 ]; then
  HT=/etc/nginx/sigelo-stats.htpasswd
  if [ "$os" = debian ]; then WEBGRP=www-data; else WEBGRP=nginx; fi

  say "S1. packages: goaccess, openssl"
  if [ "$os" = debian ]; then run env DEBIAN_FRONTEND=noninteractive apt-get install -y goaccess openssl
  else run apk add --no-cache goaccess openssl; fi

  say "S2. the config helper (its allowlist knows auth_basic, the stats root, log_format sigelo_anon)"
  install_helper

  say "S3. the /_stats/ password file $HT (user owner)"
  if [ -n "$htfile" ]; then
    [ "$(wc -l < "$htfile")" -le 1 ] && grep -Eq '^owner:\$(6|5|apr1)\$[^:[:space:]]+$' "$htfile" || die "$htfile: want one line owner:<\$6\$, \$5\$ or \$apr1\$ hash>"
    run install -m 0640 -o root -g "$WEBGRP" "$htfile" "$HT"
  elif [ -f "$HT" ]; then echo "$HT exists: kept"
  else
    pw=$(openssl rand -base64 18 | tr -d '/+=\n')
    printf 'owner:%s\n' "$(printf '%s' "$pw" | openssl passwd -6 -stdin)" > "$HT.tmp"
    chown root:"$WEBGRP" "$HT.tmp"; chmod 0640 "$HT.tmp"; mv "$HT.tmp" "$HT"
    printf 'stats login: owner / %s   (shown once; only its hash is kept on the server)\n' "$pw"
  fi

  say "S4. $WEBROOT/stats, /usr/local/sbin/sigelo-stats-agents, /usr/local/sbin/sigelo-stats"
  run install -d -m 0755 -o root -g root "$WEBROOT/stats"
  run install -m 0755 -o root -g root "$HERE/stats-agents.sh" /usr/local/sbin/sigelo-stats-agents
  printf '+ write /usr/local/sbin/sigelo-stats\n'
  cat > /usr/local/sbin/sigelo-stats.tmp <<'RUN'
#!/bin/sh
# sigelo-stats — written by site/deploy/server-setup.sh --stats; run every 15 minutes. Rebuilds
# /var/www/sigelo.io/stats/{agents.txt,index.html} (served at https://sigelo.io/_stats/) from
# every access log logrotate keeps (30 days). Lines of the old address-less format (first
# field "-") are not GoAccess-parsable and are left out of its report; agents.txt counts them.
# access.log* only: the project's own requests are in access-self.log (nginx.conf), not here.
set -eu
LOGS=/var/log/nginx/sigelo
OUT=/var/www/sigelo.io/stats
umask 022
ls "$LOGS"/access.log* >/dev/null 2>&1 || { echo "sigelo-stats: no logs yet"; exit 0; }
/usr/local/sbin/sigelo-stats-agents "$LOGS" "$OUT/agents.txt"
for f in "$LOGS"/access.log*; do case $f in *.gz) gzip -dc "$f" ;; *) cat "$f" ;; esac; done \
  | grep -v '^- ' \
  | goaccess - --no-global-config \
      --log-format='%h %^ %^ [%d:%t %^] "%m %U %H" %s %b "%R" "%u" "%^" %T' \
      --date-format='%d/%b/%Y' --time-format='%H:%M:%S' \
      --anonymize-ip --ignore-panel=HOSTS --ignore-panel=REMOTE_USER --ignore-panel=GEO_LOCATION \
      --no-query-string --num-tests=0 --html-report-title='sigelo.io, last 30 days' \
      -o "$OUT/.index.new.html"
chmod 0644 "$OUT/.index.new.html"
mv -f "$OUT/.index.new.html" "$OUT/index.html"
RUN
  chmod 0755 /usr/local/sbin/sigelo-stats.tmp
  mv /usr/local/sbin/sigelo-stats.tmp /usr/local/sbin/sigelo-stats

  say "S5. every 15 minutes"
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    printf '+ write /etc/systemd/system/sigelo-stats.service and .timer\n'
    cat > /etc/systemd/system/sigelo-stats.service <<'UNIT'
[Unit]
Description=sigelo.io visit statistics (GoAccess report and agents.txt)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sigelo-stats
Nice=10
IOSchedulingClass=idle
ProtectSystem=strict
ReadWritePaths=/var/www/sigelo.io/stats
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
PrivateDevices=yes
NoNewPrivileges=yes
UNIT
    cat > /etc/systemd/system/sigelo-stats.timer <<'UNIT'
[Unit]
Description=sigelo.io visit statistics every 15 minutes

[Timer]
OnBootSec=2min
OnCalendar=*:0/15
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
    run systemctl daemon-reload
    run systemctl enable --now sigelo-stats.timer
    run systemctl start sigelo-stats.service
  else
    printf '+ write /etc/periodic/15min/sigelo-stats\n'
    printf '#!/bin/sh\nexec /usr/local/sbin/sigelo-stats\n' > /etc/periodic/15min/sigelo-stats
    run chmod 0755 /etc/periodic/15min/sigelo-stats
    run /usr/local/sbin/sigelo-stats
  fi

  say "S6. log rotation: daily, 30 kept (access-self.log 7)"
  write_logrotate

  say "done: https://$DOMAIN/_stats/ (user owner) once nginx.conf with the /_stats/ location is deployed"
  exit 0
fi

# dns_points_here CANON NAME… prints "here NAME" or "skip NAME (why)" for every NAME: "here" when
# it has A/AAAA records and every one of them is an address of this host. The host's addresses are
# read at runtime from its interfaces (none is written anywhere); on a NAT host where CANON matches
# none of them, CANON's own addresses stand in. dns.resolve* asks the DNS servers, not /etc/hosts.
dns_points_here() {
  node -e '
    const dns = require("node:dns").promises, os = require("node:os");
    const ips = async (n) => [...await dns.resolve4(n).catch(() => []), ...await dns.resolve6(n).catch(() => [])].map((a) => a.toLowerCase());
    (async () => {
      const [canon, ...names] = process.argv.slice(1);
      let mine = new Set(Object.values(os.networkInterfaces()).flat().filter((a) => !a.internal).map((a) => a.address.toLowerCase()));
      const c = await ips(canon);
      if (!c.some((a) => mine.has(a))) { console.error(`note: ${canon} resolves to no interface address of this host (NAT?): comparing with the addresses of ${canon}`); mine = new Set(c); }
      for (const n of names) {
        const r = await ips(n);
        if (r.length && r.every((a) => mine.has(a))) console.log(`here ${n}`);
        else console.log(`skip ${n} (${r.length ? `resolves to ${r.join(" ")}, not this host` : "no A/AAAA record"})`);
      }
    })();
  ' "$@"
}

# Step 6, idempotent: the base names always; each EXTRA name only when its DNS points here. Issues
# (or expands) the one lineage only if a wanted name is missing from it.
cert_step() {
  names="$DOMAIN www.$DOMAIN $ALT www.$ALT"; skipped=""
  extra=""; for d in $EXTRA; do extra="$extra $d www.$d"; done
  if command -v node >/dev/null 2>&1; then
    res=$(dns_points_here "$DOMAIN" $extra) || die "the DNS test (node) failed"
    for n in $(printf '%s\n' "$res" | sed -n 's/^here //p'); do names="$names $n"; done
    skipped=$(printf '%s\n' "$res" | sed -n 's/^skip //p')
  else
    skipped=$(for n in $extra; do echo "$n (no node on this host for the DNS test)"; done)
  fi
  if [ -n "$skipped" ]; then
    echo "skipped, DNS not pointed here yet (rerun --certs once it is):"
    printf '%s\n' "$skipped" | sed 's/^/    /'
  fi
  have=""; staging=0
  if [ -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]; then
    info=$(certbot certificates --cert-name "$DOMAIN" 2>/dev/null || true)
    have=$(printf '%s\n' "$info" | sed -n 's/^ *Domains: //p')
    if printf '%s' "$info" | grep -q TEST_CERT; then staging=1; fi
  fi
  missing=""; for n in $names; do case " $have " in *" $n "*) ;; *) missing="$missing $n" ;; esac; done
  if [ -n "$have" ] && [ -z "$missing" ] && { [ -n "$testcert" ] || [ "$staging" = 0 ]; }; then
    echo "certificate /etc/letsencrypt/live/$DOMAIN already covers: $names"
    return 0
  fi
  if [ -z "$testcert" ] && [ "$staging" = 1 ]; then
    echo "the certificate present is a --test-cert (staging) one: replacing it"
    run certbot delete --cert-name "$DOMAIN" --non-interactive
  elif [ -n "$have" ]; then
    echo "adding to the certificate:$missing"
  fi
  if [ ! -f "$CONF" ] || ! grep -q 'listen 443' "$CONF"; then
    # port 80 only, so nginx starts without a certificate; certonly --nginx adds its challenge here
    printf '+ write the bootstrap HTTP-only config %s\n' "$CONF"
    cat > "$CONF" <<BOOT
server {
    listen 80;
    listen [::]:80;
    server_name $names;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {
        root $ACME;
    }
    location / {
        return 404;
    }
}
BOOT
    run nginx -t
    if [ "$os" = debian ]; then run systemctl enable nginx; run systemctl restart nginx; else run rc-service nginx restart; fi
  fi
  # `certonly`: certbot proves control through nginx but never edits the config, which deploy.sh
  # owns and reinstalls from nginx.conf on every deploy (edits by `certbot --nginx` would be lost).
  # --cert-name keeps one lineage, /etc/letsencrypt/live/$DOMAIN, the only path the helper allows.
  if [ -n "$email" ]; then acct="-m $email --no-eff-email"; else acct=--register-unsafely-without-email; fi
  dargs=""; for n in $names; do dargs="$dargs -d $n"; done
  # shellcheck disable=SC2086
  run certbot certonly --nginx $testcert --non-interactive --agree-tos $acct \
      --cert-name "$DOMAIN" $dargs --deploy-hook 'nginx -s reload'
}

if [ "$certs" = 1 ]; then
  say "6. certificate (--certs only)"
  cert_step
  say "done: run node site/deploy/check.mjs from the repository"
  exit 0
fi

# --relay: the relay host, Debian with systemd. Each step writes its files whole (put: replaced only
# when the content differs) and says what it kept. What cannot be finished here (a password to set,
# the firewall to confirm, DNS not pointed yet) is collected in $todo; the script then exits 1.
if [ "$relay" = 1 ]; then
  [ "$os" = debian ] && [ -d /run/systemd/system ] || die "--relay needs Debian with systemd"
  ADMIN=csigelo
  RHOST=relay.sigelo.ai
  RNAMES="sigelo.ai www.sigelo.ai relay.sigelo.ai"
  LINEAGE=sigelo.ai
  RCONF=/etc/nginx/conf.d/sigelo-relay.conf
  DKEYS=/etc/ssh/authorized_keys/sigelo
  NODESOURCE_FPR=6F71F525282841EEDAF851B42F59B5F99B1BE0B4
  todo=""
  later() { todo="$todo
  - $*"; }
  # put FILE MODE < content: writes FILE only when the content differs; changed=1 when it did.
  put() {
    cat > "$1.new"; chmod "$2" "$1.new"
    if [ -f "$1" ] && cmp -s "$1" "$1.new"; then rm -f "$1.new"; changed=0; echo "$1: unchanged"
    else mv "$1.new" "$1"; changed=1; echo "+ wrote $1"; fi
  }
  # authorize USER HOME KEY: append KEY to HOME/.ssh/authorized_keys unless it is there (the admin's;
  # the deploy user's keys are in DKEYS, R4)
  authorize() {
    run install -d -m 0700 -o "$1" -g "$1" "$2/.ssh"
    touch "$2/.ssh/authorized_keys"
    if grep -qxF "$3" "$2/.ssh/authorized_keys"; then echo "$1: key already authorized"
    else printf '+ append a key to %s/.ssh/authorized_keys\n' "$2"; printf '%s\n' "$3" >> "$2/.ssh/authorized_keys"; fi
    chown "$1:$1" "$2/.ssh/authorized_keys"; chmod 0600 "$2/.ssh/authorized_keys"
  }

  say "R1. packages"
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot python3-certbot-nginx sudo logrotate fail2ban \
      python3-systemd unattended-upgrades nftables systemd-timesyncd ca-certificates curl gnupg rsync age

  say "R2. time: UTC, NTP through systemd-timesyncd"
  run timedatectl set-timezone Etc/UTC
  run timedatectl set-ntp true

  say "R3. journald: persistent and capped; the relay's own namespace keeps 7 days"
  run install -d -m 0755 /etc/systemd/journald.conf.d
  put /etc/systemd/journald.conf.d/00-sigelo.conf 0644 <<'CONF'
# written by site/deploy/server-setup.sh --relay
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemKeepFree=2G
MaxFileSec=1month
CONF
  j=$changed
  # MaxRetentionSec deletes archived files only, and the active file rotates after MaxFileSec
  # (default a month). journald checks MaxFileSec when it writes a line: with daily files no line
  # outlives the 7 days by more than a day, as long as the relay writes at least daily; a relay
  # silent for longer keeps its last lines until its next one.
  put /etc/systemd/journald@sigelo-relay.conf 0644 <<'CONF'
# written by site/deploy/server-setup.sh --relay: the relay logs addresses cut to /24 or /48, 7 days
[Journal]
MaxRetentionSec=7day
MaxFileSec=1day
CONF
  [ "$j" = 0 ] || run systemctl restart systemd-journald
  # the relay's namespace has its own journald instance, started with the relay
  [ "$changed" = 0 ] || run systemctl try-restart systemd-journald@sigelo-relay.service

  say "R4. users: $ADMIN (admin, sudo with its password), sigelo (deploy, key only), sigelo-relay (runs the relay)"
  if id "$ADMIN" >/dev/null 2>&1; then echo "user $ADMIN exists"
  else run useradd --create-home --shell /bin/bash --groups sudo,users "$ADMIN"; fi
  ahome=$(getent passwd "$ADMIN" | cut -d: -f6)
  if [ -n "$adminkey" ]; then authorize "$ADMIN" "$ahome" "$adminkey"; fi
  if id sigelo >/dev/null 2>&1; then echo "user sigelo exists"
  else run useradd --system --create-home --home-dir /var/lib/sigelo --shell /bin/sh sigelo; fi
  # '*' (no password, not "locked"): a '!' account is refused key logins by OpenSSH without PAM
  run sed -i 's/^sigelo:[^:]*:/sigelo:*:/' /etc/shadow
  # The deploy user's keys, in a file only root writes, which sshd reads for that user alone (a
  # Match in an included file ends with the file). In its own home the deploy user could add keys
  # of its own, and a stolen deploy key outlived its revocation. --key writes the file whole: a
  # rerun with the new key alone revokes every other. Nothing is read from or written to the
  # deploy user's home as root: it may hold links to root's files.
  run install -d -m 0755 -o root -g root /etc/ssh/authorized_keys
  if [ -n "$key" ]; then printf '%s\n' "$key" | put "$DKEYS" 0644; fi
  if [ -s "$DKEYS" ]; then
    run install -d -m 0755 /etc/ssh/sshd_config.d
    put /etc/ssh/sshd_config.d/01-sigelo-deploy.conf 0644 <<SSHD
# written by site/deploy/server-setup.sh --relay: the deploy user's keys, in a file only root writes
Match User sigelo
    AuthorizedKeysFile $DKEYS
SSHD
    run sshd -t
    [ "$changed" = 0 ] || run systemctl reload ssh
    sshd -T -C user=sigelo,host=localhost,addr=127.0.0.1 2>/dev/null | grep -qx "authorizedkeysfile $DKEYS" \
      || die "sshd does not read sigelo's keys from $DKEYS (no Include line for /etc/ssh/sshd_config.d in /etc/ssh/sshd_config?)"
    echo "sigelo's keys: $DKEYS only ($(grep -c . "$DKEYS") key(s))"
  else later "sigelo has no key in $DKEYS: rerun with --key (an earlier version kept it in /var/lib/sigelo/.ssh, which sshd reads until then)"; fi
  # No cron or at jobs for the deploy user: one set up with a stolen key would outlive its
  # revocation. A crontab it already has is removed.
  for f in /etc/cron.deny /etc/at.deny; do grep -qx sigelo "$f" 2>/dev/null || { printf '+ add sigelo to %s\n' "$f"; printf 'sigelo\n' >> "$f"; }; done
  if grep -qx sigelo /etc/cron.allow /etc/at.allow 2>/dev/null; then die "/etc/cron.allow or /etc/at.allow lists sigelo: remove it there"; fi
  if command -v crontab >/dev/null 2>&1 && crontab -l -u sigelo >/dev/null 2>&1; then run crontab -r -u sigelo; fi
  if ! id sigelo-relay >/dev/null 2>&1; then
    run useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sigelo-relay
  fi
  run passwd -l sigelo-relay >/dev/null

  say "R5. directories: /var/lib/sigelo-relay (sigelo-relay 0700), /opt/sigelo-relay (root), the site link"
  run install -d -m 0700 -o sigelo-relay -g sigelo-relay /var/lib/sigelo-relay
  run install -d -m 0755 -o root -g root /opt/sigelo-relay /var/www /var/www/sigelo.ai "$ACME"
  run install -d -m 0750 /var/log/nginx/sigelo
  # nginx serves the site (relay/deploy/nginx.conf: root /var/www/sigelo.ai/dist) from the code the
  # helper installed, so the two swap together
  if [ -d /var/www/sigelo.ai/dist ] && [ ! -L /var/www/sigelo.ai/dist ]; then die "/var/www/sigelo.ai/dist is a directory: move it away (the site is a link to /opt/sigelo-relay/app/site/dist)"; fi
  run ln -sfn /opt/sigelo-relay/app/site/dist /var/www/sigelo.ai/dist

  say "R6. Node.js 24 from NodeSource (Debian's nodejs has no node:sqlite)"
  arch=$(dpkg --print-architecture)
  gh=$(mktemp -d); k=$gh/nodesource.asc
  run curl -fsSL -o "$k" https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key
  GNUPGHOME=$gh gpg --batch --dearmor < "$k" > "$gh/nodesource.gpg"
  [ -s "$gh/nodesource.gpg" ] || { rm -rf "$gh"; die "gpg --dearmor of the NodeSource key wrote nothing"; }
  # Checked on the keyring that is installed, whole: apt trusts every key in it for NodeSource's
  # packages, so a second key beside the pinned one is refused, not only a wrong first one.
  keys=$(GNUPGHOME=$gh gpg --batch --show-keys --with-colons "$gh/nodesource.gpg" 2>/dev/null | awk -F: '$1 == "pub" { n++; want = 1; next } $1 == "fpr" && want { fpr = $10; want = 0 } END { print n + 0, fpr }')
  [ "$keys" = "1 $NODESOURCE_FPR" ] || { rm -rf "$gh"; die "the NodeSource keyring holds '$keys' (primary keys, last fingerprint), not exactly the one key $NODESOURCE_FPR: refusing it"; }
  put /usr/share/keyrings/nodesource.gpg 0644 < "$gh/nodesource.gpg"
  rm -rf "$gh"
  put /etc/apt/sources.list.d/nodesource.sources 0644 <<SRC
Types: deb
URIs: https://deb.nodesource.com/node_24.x
Suites: nodistro
Components: main
Architectures: $arch
Signed-By: /usr/share/keyrings/nodesource.gpg
SRC
  put /etc/apt/preferences.d/nodejs 0644 <<'PIN'
Package: nodejs
Pin: origin deb.nodesource.com
Pin-Priority: 600
PIN
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
  node -e 'require("node:sqlite"); process.exit(+process.versions.node.split(".")[0] >= 24 ? 0 : 1)' || die "node 24 with node:sqlite needed, have $(node -v)"
  echo "node $(node -v), node:sqlite present"

  say "R7. the relay's unit, config, helper and sudo rule"
  run install -m 0644 -o root -g root "$HERE/sigelo-relay.service" /etc/systemd/system/sigelo-relay.service
  run systemctl daemon-reload
  run systemctl enable sigelo-relay.service     # started by the first deploy (sigelo-relay-apply)
  if [ -f /etc/sigelo-relay.env ]; then echo "/etc/sigelo-relay.env exists: kept"
  else
    printf '+ write /etc/sigelo-relay.env\n'
    printf 'RELAY_HOST=%s\nRELAY_TLS_CERT=/etc/sigelo-relay/tls/fullchain.pem\nRELAY_TLS_KEY=/etc/sigelo-relay/tls/privkey.pem\n' "$RHOST" > /etc/sigelo-relay.env
    chmod 0644 /etc/sigelo-relay.env
  fi
  run install -m 0755 -o root -g root "$HERE/sigelo-relay-apply" $RELAY_APPLY
  printf '+ write /etc/sudoers.d/sigelo-relay\n'
  relay_rules > /etc/sudoers.d/sigelo-relay.tmp
  chmod 0440 /etc/sudoers.d/sigelo-relay.tmp
  run visudo -cf /etc/sudoers.d/sigelo-relay.tmp
  run mv /etc/sudoers.d/sigelo-relay.tmp /etc/sudoers.d/sigelo-relay
  # the installed policy, asked as for sigelo.io (install_helper)
  sudo_may $RELAY_APPLY && sudo_may $RELAY_APPLY --rollback || die "sudo -l: sigelo may not run $RELAY_APPLY with no argument or --rollback, as deploy/deploy.sh does"
  if sudo_may $RELAY_APPLY --check /etc/shadow; then
    rm -f /etc/sudoers.d/sigelo-relay
    die "sudo -l: sigelo may run '$RELAY_APPLY --check FILE' (prints any file as root); a rule in /etc/sudoers or /etc/sudoers.d allows it: /etc/sudoers.d/sigelo-relay removed"
  fi
  echo "sudo: sigelo may run $RELAY_APPLY with no argument or --rollback; nothing else"

  say "R8. nginx: the default site removed (it logs client addresses), errors at crit, logs 7 days"
  if [ -e /etc/nginx/sites-enabled/default ]; then run rm -f /etc/nginx/sites-enabled/default; fi
  # nginx writes the client's full address into every error-level line (the relay site's privacy.md).
  # Its own error log goes beside the sites' one, which is kept 7 days (Debian keeps
  # /var/log/nginx/*.log 14).
  run sed -i 's|^error_log .*|error_log /var/log/nginx/sigelo/error.log crit;|' /etc/nginx/nginx.conf
  put /etc/logrotate.d/sigelo-ai 0644 <<'ROT'
/var/log/nginx/sigelo/*.log {
    daily
    rotate 7
    missingok
    notifempty
    sharedscripts
    postrotate
        nginx -s reopen 2>/dev/null || true
    endscript
}
ROT
  run systemctl enable nginx

  say "R9. certificates: $LINEAGE for each of $RNAMES whose DNS points here (nginx), $RHOST for $RHOST alone (the broker's copy)"
  run install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  relay_hook | put /etc/letsencrypt/renewal-hooks/deploy/sigelo-relay 0755
  # lineage exact|cover NAME DOMAIN...: the certificate /etc/letsencrypt/live/NAME for DOMAIN...,
  # issued when it is missing, a --test-cert one is in place on a run without the flag, or (cover)
  # a DOMAIN is missing from it or (exact) it names anything but the DOMAINs. --webroot: the
  # bootstrap config and relay/deploy/nginx.conf both serve /.well-known/acme-challenge/ from
  # $ACME on port 80, so issuance and every renewal work with nginx up, before and after the first
  # deploy, and certbot never edits a config.
  lineage() {
    mode=$1 ln=$2; shift 2
    have=""; staging=0
    if [ -f /etc/letsencrypt/live/$ln/fullchain.pem ]; then
      info=$(certbot certificates --cert-name "$ln" 2>/dev/null || true)
      have=$(printf '%s\n' "$info" | sed -n 's/^ *Domains: //p')
      if printf '%s' "$info" | grep -q TEST_CERT; then staging=1; fi
    fi
    missing=""; for n in "$@"; do case " $have " in *" $n "*) ;; *) missing="$missing $n" ;; esac; done
    extra=""; if [ "$mode" = exact ]; then for n in $have; do case " $* " in *" $n "*) ;; *) extra="$extra $n" ;; esac; done; fi
    if [ -n "$have" ] && [ -z "$missing$extra" ] && { [ -n "$testcert" ] || [ "$staging" = 0 ]; }; then echo "certificate $ln already covers: $have"; return 0; fi
    if [ -z "$testcert" ] && [ "$staging" = 1 ]; then
      echo "the certificate $ln is a --test-cert (staging) one: replacing it"
      run certbot delete --cert-name "$ln" --non-interactive
    elif [ -n "$extra" ]; then echo "the certificate $ln also names$extra: issued again for $* alone"
    fi
    if [ -n "$email" ]; then acct="-m $email --no-eff-email"; else acct=--register-unsafely-without-email; fi
    dargs=""; for n in "$@"; do dargs="$dargs -d $n"; done
    # shellcheck disable=SC2086
    run certbot certonly --webroot -w "$ACME" $testcert --non-interactive --agree-tos $acct --cert-name "$ln" $dargs
  }
  if [ "$skipcert" = 1 ]; then echo "--skip-cert"
  else
    res=$(dns_points_here "$RHOST" $RNAMES) || die "the DNS test (node) failed"
    names=$(printf '%s\n' "$res" | sed -n 's/^here //p' | tr '\n' ' ')
    printf '%s\n' "$res" | sed -n 's/^skip /skipped, DNS not pointed here yet: /p'
    if [ -z "$names" ]; then later "certificate: no name of $RNAMES points here yet; rerun --relay once DNS does"
    else
      if [ ! -f "$RCONF" ] || ! grep -q 'listen 443' "$RCONF"; then
        # port 80 only, so nginx starts without a certificate; the first deploy installs the real config
        put "$RCONF" 0644 <<BOOT
# written by site/deploy/server-setup.sh --relay; replaced by the first deploy (deploy/nginx.conf)
server {
    listen 80;
    listen [::]:80;
    server_name $RNAMES;
    access_log off;
    error_log /var/log/nginx/sigelo/error.log crit;
    location ^~ /.well-known/acme-challenge/ {
        root $ACME;
    }
    location / {
        return 404;
    }
}
BOOT
        run nginx -t
        run systemctl restart nginx
      fi
      # shellcheck disable=SC2086
      lineage cover "$LINEAGE" $names
      case " $names " in
        *" $RHOST "*) lineage exact "$RHOST" "$RHOST" ;;
        *) later "certificate: $RHOST does not point here yet: the broker has no certificate, the first deploy cannot start it" ;;
      esac
    fi
  fi
  # The broker's copy, of the broker's own lineage only, whenever it is missing or differs: after an
  # issuance, after a restore that untarred /etc/letsencrypt (certbot runs deploy hooks on renewals
  # only), with --skip-cert too, and on a host whose copy is still sigelo.ai's key (an earlier
  # version of this script copied that lineage).
  L=/etc/letsencrypt/live/$RHOST
  if [ -f "$L/fullchain.pem" ]; then
    if cmp -s "$L/fullchain.pem" /etc/sigelo-relay/tls/fullchain.pem && cmp -s "$L/privkey.pem" /etc/sigelo-relay/tls/privkey.pem; then
      echo "the broker's copy in /etc/sigelo-relay/tls matches $L"
    else run env RENEWED_LINEAGE="$L" /etc/letsencrypt/renewal-hooks/deploy/sigelo-relay; fi
  elif [ -f /etc/sigelo-relay/tls/privkey.pem ]; then
    later "the broker's copy in /etc/sigelo-relay/tls is not of $L, which does not exist: issue it (rerun --relay without --skip-cert once $RHOST points here); a copy of $LINEAGE's key would be valid for sigelo.ai too"
  fi
  run systemctl enable --now certbot.timer
  if [ -f /etc/letsencrypt/live/$LINEAGE/fullchain.pem ] || [ -f "$L/fullchain.pem" ]; then run certbot renew --dry-run; fi

  say "R10. fail2ban: the sshd jail"
  run install -d -m 0755 /etc/fail2ban/jail.d
  put /etc/fail2ban/jail.d/sshd.local 0644 <<'JAIL'
# written by site/deploy/server-setup.sh --relay
[sshd]
enabled = true
backend = systemd
maxretry = 4
findtime = 10m
bantime = 1h
JAIL
  f=$changed
  put /etc/fail2ban/jail.d/nginx-limit-req.local 0644 <<'JAIL'
# written by site/deploy/server-setup.sh --relay. Off on purpose: the relay's nginx logs errors at
# crit only (the relay site's privacy.md), so this jail would see nothing; turning it on means
# logging full client addresses with the DIDs they ask challenges for.
[nginx-limit-req]
enabled = false
JAIL
  run systemctl enable fail2ban
  if [ "$f$changed" != 00 ] || ! systemctl is-active --quiet fail2ban; then run systemctl restart fail2ban; fi

  say "R11. unattended upgrades: daily, NodeSource included, a reboot at 04:30 UTC when one is needed"
  put /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT
  put /etc/apt/apt.conf.d/52sigelo-relay 0644 <<'APT'
// written by site/deploy/server-setup.sh --relay. NodeSource's Release file says Origin and Label
// ". nodistro", Codename "nodistro". The reboot comes even with someone logged in: a security
// update that waits for nobody to be logged in may never come.
Unattended-Upgrade::Origins-Pattern {
        "origin=. nodistro,codename=nodistro";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
APT

  say "R12. nftables: inbound 22, 80, 443 and 8883 only"
  put /etc/nftables.conf 0755 <<'NFT'
#!/usr/sbin/nft -f
# written by site/deploy/server-setup.sh --relay. Replaces table inet filter only, never the whole
# ruleset: fail2ban keeps its bans in a table of its own (inet f2b-table), which a reload must keep.
table inet filter
delete table inet filter
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iif lo accept
        meta l4proto icmp accept
        meta l4proto ipv6-icmp accept
        udp sport 67 udp dport 68 accept          # DHCPv4 replies
        udp sport 547 udp dport 546 accept        # DHCPv6 replies
        tcp dport { 22, 80, 443, 8883 } accept    # ssh, ACME, nginx, the broker
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
NFT
  run nft -c -f /etc/nftables.conf
  if systemctl is-enabled --quiet nftables 2>/dev/null; then
    run nft -f /etc/nftables.conf
  elif systemctl is-active --quiet sigelo-nft-rollback.timer 2>/dev/null; then
    later "nftables: applied, rollback still armed: from a NEW ssh session run   systemctl stop sigelo-nft-rollback.timer && systemctl enable nftables"
  else
    # First time: a rule set that cut ssh would lock everyone out, so it undoes itself in 3 minutes
    # unless someone who could open a new session since says it works.
    systemctl reset-failed sigelo-nft-rollback.service 2>/dev/null || true
    run systemd-run --unit=sigelo-nft-rollback --on-active=180 /usr/sbin/nft delete table inet filter
    run nft -f /etc/nftables.conf
    later "nftables: applied with a 3-minute rollback: from a NEW ssh session run   systemctl stop sigelo-nft-rollback.timer && systemctl enable nftables"
  fi

  say "R13. sshd: key only, root off, AllowUsers $ADMIN sigelo"
  pw=$(getent shadow "$ADMIN" | cut -d: -f2)
  why=""
  case $pw in ""|"*"|"!"*) why="$ADMIN has no password: set one (passwd $ADMIN), or sudo cannot be reached once root is off" ;; esac
  id -nG "$ADMIN" | tr ' ' '\n' | grep -qx sudo || why="${why:+$why; }$ADMIN is not in group sudo (usermod -aG sudo $ADMIN): root would be out of reach once root login is off"
  [ -s "$ahome/.ssh/authorized_keys" ] || why="${why:+$why; }$ADMIN has no ssh key (--admin-key)"
  [ -s "$DKEYS" ] || why="${why:+$why; }sigelo has no ssh key in $DKEYS (--key)"
  if [ -n "$why" ]; then later "sshd NOT locked down: $why; then rerun --relay"
  else
    run install -d -m 0755 /etc/ssh/sshd_config.d
    put /etc/ssh/sshd_config.d/00-sigelo.conf 0644 <<SSHD
# written by site/deploy/server-setup.sh --relay. 00-: sshd takes the first value it reads.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers $ADMIN sigelo
X11Forwarding no
MaxAuthTries 3
SSHD
    run sshd -t
    [ "$changed" = 0 ] || run systemctl reload ssh
    sshd -T 2>/dev/null | grep -qx 'permitrootlogin no' || die "sshd does not apply /etc/ssh/sshd_config.d/00-sigelo.conf (no Include line in /etc/ssh/sshd_config?)"
    echo "sshd: root refused, passwords off, AllowUsers $ADMIN sigelo (root's own authorized_keys are now inert; empty them once you have checked)"
  fi

  if [ -n "$backup" ]; then
    say "R14. backup: /usr/local/sbin/sigelo-relay-backup, daily 03:30 Europe/Berlin"
    printf '%s' "$backup" | grep -Eq '^age1[02-9ac-hj-np-z]{58}$' || die "--backup wants an age recipient (age1…, the public key; never the identity)"
    printf '%s\n' "$backup" | put /etc/sigelo-relay-backup.recipient 0644
    run install -m 0755 -o root -g root "$HERE/backup.sh" /usr/local/sbin/sigelo-relay-backup
    put /etc/systemd/system/sigelo-relay-backup.service 0644 <<UNIT
[Unit]
Description=sigelo relay backup: licences, operator chains, config; age-encrypted, never a mailbox

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sigelo-relay-backup
Nice=10
IOSchedulingClass=idle
ProtectSystem=strict
ReadWritePaths=$ahome/backup /var/lib/sigelo-relay
PrivateTmp=yes
PrivateNetwork=yes
PrivateDevices=yes
NoNewPrivileges=yes
UNIT
    put /etc/systemd/system/sigelo-relay-backup.timer 0644 <<'UNIT'
[Unit]
Description=sigelo relay backup, daily

[Timer]
OnCalendar=*-*-* 03:30:00 Europe/Berlin
Persistent=true

[Install]
WantedBy=timers.target
UNIT
    run install -d -m 0700 -o "$ADMIN" -g "$ADMIN" "$ahome/backup"
    run systemctl daemon-reload
    run systemctl enable --now sigelo-relay-backup.timer
    if [ -f /var/lib/sigelo-relay/relay.db ]; then run systemctl start sigelo-relay-backup.service
    else echo "no relay database yet: the first backup runs after the first deploy"; fi
  fi

  say "R15. self-healing: nginx restarts on failure; sigelo-relay-selfcheck hourly"
  run install -d -m 0755 /etc/systemd/system/nginx.service.d
  put /etc/systemd/system/nginx.service.d/sigelo-restart.conf 0644 <<'UNIT'
# written by site/deploy/server-setup.sh --relay (Debian ships nginx with Restart=no)
[Unit]
StartLimitIntervalSec=10min
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=5s
UNIT
  put /usr/local/sbin/sigelo-relay-selfcheck 0755 <<'RUN'
#!/bin/sh
# sigelo-relay-selfcheck — written by site/deploy/server-setup.sh --relay; run hourly by
# sigelo-relay-selfcheck.timer as root (design/relay-plan.md §6 "Monitoring"). Checks the relay
# itself (GET /challenge on 127.0.0.1:8791, a TLS handshake on 127.0.0.1:8883), then nginx (GET
# /challenge through https://relay.sigelo.ai and / through https://sigelo.ai, both on 127.0.0.1);
# restarts the unit that fails (nginx only after nginx -t), checks again, logs to the journal
# (journalctl -u sigelo-relay-selfcheck). Exit 1 when something is still down. A unit stopped by
# hand (inactive) is left alone: a restore stops the relay on purpose. Nothing to check before the
# first deploy. Certificate expiry is the phone watchdog's to report, not this check's.
set -u
UA='sigelo-selfcheck/1 (+https://sigelo.ai/privacy)'
DID=did:sigelo:zF5FYbH5zNLX5pfd7DZUjPirXeAFzLVxrdFyCrnexdpBG   # test-vectors.json's first: public, nothing kept for it
[ -d /opt/sigelo-relay/app ] || { echo "sigelo-relay-selfcheck: no release installed yet: nothing to check"; exit 0; }
relay() {
  curl -fsS -o /dev/null --max-time 10 -A "$UA" "http://127.0.0.1:8791/challenge?did=$DID" &&
    node -e 'const s = require("node:tls").connect({ host: "127.0.0.1", port: 8883, servername: "relay.sigelo.ai", rejectUnauthorized: false, timeout: 10000 }, () => { s.end(); process.exit(0); }); s.on("error", () => process.exit(1)); s.on("timeout", () => process.exit(1));'
}
web() {
  curl -fsS -o /dev/null --max-time 15 -A "$UA" --resolve relay.sigelo.ai:443:127.0.0.1 "https://relay.sigelo.ai/challenge?did=$DID" &&
    curl -fsS -o /dev/null --max-time 15 -A "$UA" --resolve sigelo.ai:443:127.0.0.1 https://sigelo.ai/
}
rc=0
if [ "$(systemctl is-active sigelo-relay.service)" = inactive ]; then
  echo "sigelo-relay-selfcheck: sigelo-relay is stopped (by hand): not checked, not started"
elif ! relay; then
  echo "sigelo-relay-selfcheck: the relay does not answer on 127.0.0.1:8791 and :8883: restarting sigelo-relay.service"
  systemctl restart sigelo-relay.service; sleep 10
  if relay; then echo "sigelo-relay-selfcheck: sigelo-relay back after restart"; else echo "sigelo-relay-selfcheck: sigelo-relay STILL DOWN"; rc=1; fi
fi
if [ "$(systemctl is-active nginx.service)" = inactive ]; then
  echo "sigelo-relay-selfcheck: nginx is stopped (by hand): not checked, not started"
elif [ $rc = 0 ] && ! web; then
  echo "sigelo-relay-selfcheck: nginx does not serve /challenge or / on 127.0.0.1: restarting nginx"
  if nginx -t 2>&1; then systemctl restart nginx.service; sleep 3
  else echo "sigelo-relay-selfcheck: nginx -t fails: not restarting"; fi
  if web; then echo "sigelo-relay-selfcheck: nginx back after restart"; else echo "sigelo-relay-selfcheck: nginx STILL DOWN"; rc=1; fi
fi
[ $rc = 0 ] && echo "sigelo-relay-selfcheck: ok"
exit $rc
RUN
  put /etc/systemd/system/sigelo-relay-selfcheck.service 0644 <<'UNIT'
[Unit]
Description=sigelo relay self-check: the relay on 127.0.0.1:8791 and :8883, nginx; restart on failure
After=nginx.service sigelo-relay.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sigelo-relay-selfcheck
TimeoutStartSec=3min
UNIT
  put /etc/systemd/system/sigelo-relay-selfcheck.timer 0644 <<'UNIT'
[Unit]
Description=sigelo relay self-check, hourly

[Timer]
OnBootSec=10min
OnCalendar=hourly
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
UNIT
  run systemctl daemon-reload
  run systemctl enable --now sigelo-relay-selfcheck.timer
  echo "nginx.service: Restart=$(systemctl show -p Restart --value nginx.service)"

  if [ -n "$todo" ]; then
    say "not done yet:$todo"
    exit 1
  fi
  say "done"
  cat <<NEXT
From a clone of the relay's own repository (release/publish.sh --relay), with the ssh alias
sigelo-relay-deploy for sigelo@<this host>:
    npm ci && deploy/deploy.sh
NEXT
  exit 0
fi


say "1. packages: nginx, certbot (+ nginx plugin), sudo, logrotate"
if [ "$os" = debian ]; then
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot python3-certbot-nginx sudo logrotate
else
  run apk add --no-cache nginx certbot certbot-nginx sudo logrotate
  run rc-update add nginx default
fi

say "2. the deploy user 'sigelo' (unprivileged; owns $WEBROOT; key login only)"
if id sigelo >/dev/null 2>&1; then echo "user sigelo exists"
elif [ "$os" = debian ]; then run useradd --system --create-home --home-dir /var/lib/sigelo --shell /bin/sh sigelo
else run addgroup -S sigelo; run adduser -S -D -h /var/lib/sigelo -s /bin/sh -G sigelo sigelo
fi
# '*' (no password, not "locked"): OpenSSH without PAM (Alpine) refuses key logins to a '!' account
run sed -i 's/^sigelo:[^:]*:/sigelo:*:/' /etc/shadow
run install -d -m 0700 -o sigelo -g sigelo /var/lib/sigelo/.ssh
if [ -n "$key" ]; then
  touch /var/lib/sigelo/.ssh/authorized_keys
  if grep -qxF "$key" /var/lib/sigelo/.ssh/authorized_keys; then echo "key already authorized"
  else printf '+ append the deploy key to /var/lib/sigelo/.ssh/authorized_keys\n'; printf '%s\n' "$key" >> /var/lib/sigelo/.ssh/authorized_keys; fi
  run chown sigelo:sigelo /var/lib/sigelo/.ssh/authorized_keys
  run chmod 0600 /var/lib/sigelo/.ssh/authorized_keys
else
  echo "no --key: add the deploy public key to /var/lib/sigelo/.ssh/authorized_keys yourself"
fi

say "3. directories"
run install -d -m 0755 -o sigelo -g sigelo "$WEBROOT" "$WEBROOT/deploy"
if [ ! -d "$WEBROOT/dist" ]; then
  run install -d -m 0755 -o sigelo -g sigelo "$WEBROOT/dist"
  printf '+ write a placeholder %s/dist/index.html\n' "$WEBROOT"
  printf '<!doctype html><title>sigelo.io</title><p>Deploying.</p>\n' > "$WEBROOT/dist/index.html"
  chown sigelo:sigelo "$WEBROOT/dist/index.html"
fi
run install -d -m 0755 "$ACME"
run install -d -m 0750 /var/log/nginx/sigelo
run install -d -m 0700 /var/backups/sigelo-nginx

say "4. remove the distribution's default site (it logs client addresses and claims default_server)"
for f in /etc/nginx/sites-enabled/default /etc/nginx/http.d/default.conf; do
  if [ -e "$f" ]; then run rm -f "$f"; fi
done

say "5. the config helper and the one sudo rule"
install_helper

say "6. certificate: $DOMAIN, www.$DOMAIN, $ALT, www.$ALT, and each of $EXTRA (apex, www) whose DNS points here"
if [ "$skipcert" = 1 ]; then echo "--skip-cert"; else cert_step; fi

say "7. automatic renewal"
if [ "$os" = debian ]; then
  if systemctl list-unit-files certbot.timer >/dev/null 2>&1; then run systemctl enable --now certbot.timer
  else echo "no certbot.timer: the package's /etc/cron.d/certbot renews twice a day"; fi
else
  printf '+ write /etc/periodic/daily/certbot-renew\n'
  printf '#!/bin/sh\n# sigelo.io: renew certificates; the deploy hook stored at issuance reloads nginx\nexec certbot renew -q\n' > /etc/periodic/daily/certbot-renew
  run chmod 0755 /etc/periodic/daily/certbot-renew
  run rc-update add crond default
  rc-service crond status >/dev/null 2>&1 || run rc-service crond start
fi
run certbot renew --dry-run

say "8. log rotation: /var/log/nginx/sigelo/*.log daily, 30 kept (no raw client addresses)"
write_logrotate

say "9. the site config (what every deploy reinstalls), through the same helper deploy.sh uses"
if [ ! -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]; then
  echo "no certificate at /etc/letsencrypt/live/$DOMAIN: leaving the bootstrap config; the first deploy installs nginx.conf"
else
  run install -m 0644 -o sigelo -g sigelo "$HERE/nginx.conf" "$WEBROOT/deploy/nginx.conf"
  run /usr/local/sbin/sigelo-nginx-apply --os "$os"
fi

say "10. firewall (not changed by this script)"
cat <<'FW'
Allow only 22 (ssh), 80 (ACME + redirect) and 443 inbound. With ufw (Debian/Ubuntu):
    ufw default deny incoming && ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw enable
With nftables (any): an inet filter input chain, policy drop, accepting established/related, lo,
icmp/icmpv6, and tcp dport { 22, 80, 443 }. Also check the hosting provider's own firewall.
Consider `PermitRootLogin no` and `PasswordAuthentication no` in /etc/ssh/sshd_config once the
sigelo key and an admin login work.
FW

say "done"
cat <<NEXT
From the machine holding the repository and the deploy key:
    site/deploy/deploy.sh sigelo@$DOMAIN --os $os
Then the visit statistics, here, as root (stats-agents.sh beside this script):
    sh $0 --stats
NEXT
