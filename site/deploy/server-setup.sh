#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/server-setup.sh — ONE-TIME preparation of a fresh Debian/Ubuntu or Alpine server for
# sigelo.io. Run as root ON THE SERVER, by hand; deploy.sh never runs it. Every step it takes is
# also written out as copy-paste commands in site/deploy/README.md.
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
#   --stats               ONLY the visit-statistics step, on a server this script already prepared
#                         (needs sigelo-nginx-apply and stats-agents.sh beside it): goaccess, the
#                         /_stats/ password file, the 15-minute sigelo-stats timer, the helper
#                         refreshed (its allowlist knows auth_basic), log rotation at 30 days. A
#                         fresh server runs the script once without it, then once with it.
#   --stats-htpasswd FILE with --stats: install FILE (one line, owner:<crypt hash>, e.g. from
#                         `openssl passwd -6 -stdin`) as /etc/nginx/sigelo-stats.htpasswd; without
#                         it an existing file is kept, and a missing one gets a random password,
#                         printed once
#
# Requires: DNS A (and AAAA, if the server has IPv6) for sigelo.io AND www.sigelo.io already pointing
# here, and ports 80/443 open — certbot proves control over HTTP-01 on port 80.
# Idempotent: re-running skips what is already in place.
set -eu

DOMAIN=sigelo.io
ALT=sigelo.net          # also owned; every name 301s to https://$DOMAIN, one certificate lineage
WEBROOT=/var/www/sigelo.io
ACME=/var/www/acme
HERE=$(cd "$(dirname "$0")" && pwd)

say() { printf '\n==> %s\n' "$*"; }
run() { printf '+ %s\n' "$*"; "$@"; }
die() { printf 'server-setup.sh: %s\n' "$*" >&2; exit 1; }

os=""; key=""; email=""; testcert=""; skipcert=0; stats=0; htfile=""
while [ $# -gt 0 ]; do
  case $1 in
    --os) os=$2; shift 2 ;;
    --key) key=$2; shift 2 ;;
    --key-file) key=$(cat "$2"); shift 2 ;;
    --email) email=$2; shift 2 ;;
    --test-cert) testcert=--test-cert; shift ;;
    --skip-cert) skipcert=1; shift ;;
    --stats) stats=1; shift ;;
    --stats-htpasswd) htfile=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root"
if [ "$stats" = 1 ]; then need="sigelo-nginx-apply stats-agents.sh"; else need="nginx.conf sigelo-nginx-apply"; fi
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
if [ -n "$key" ]; then printf '%s' "$key" | grep -Eq '^(ssh-ed25519|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh.com|ssh-rsa) [A-Za-z0-9+/=]+( .*)?$' || die "--key does not look like one OpenSSH public key line"; fi
echo "server-setup.sh: $os, config $CONF, web root $WEBROOT"

install_helper() {
  run install -m 0755 -o root -g root "$HERE/sigelo-nginx-apply" /usr/local/sbin/sigelo-nginx-apply
  printf '+ write /etc/sudoers.d/sigelo-deploy\n'
  printf 'sigelo ALL=(root) NOPASSWD: /usr/local/sbin/sigelo-nginx-apply\n' > /etc/sudoers.d/sigelo-deploy.tmp
  chmod 0440 /etc/sudoers.d/sigelo-deploy.tmp
  run visudo -cf /etc/sudoers.d/sigelo-deploy.tmp
  run mv /etc/sudoers.d/sigelo-deploy.tmp /etc/sudoers.d/sigelo-deploy
}

# 30 days: the window the statistics cover. The log holds no raw address (nginx.conf, Privacy).
write_logrotate() {
  printf '+ write /etc/logrotate.d/sigelo\n'
  cat > /etc/logrotate.d/sigelo <<'ROT'
/var/log/nginx/sigelo/*.log {
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
ROT
}

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

  say "S6. log rotation: daily, 30 kept"
  write_logrotate

  say "done: https://$DOMAIN/_stats/ (user owner) once nginx.conf with the /_stats/ location is deployed"
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

say "6. certificate for $DOMAIN, www.$DOMAIN, $ALT and www.$ALT (certbot certonly --nginx, HTTP-01)"
if [ "$skipcert" = 1 ]; then echo "--skip-cert"
elif [ -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ] && [ -z "$testcert" ] && ! certbot certificates --cert-name "$DOMAIN" 2>/dev/null | grep -q TEST_CERT; then
  echo "certificate already present: /etc/letsencrypt/live/$DOMAIN"
else
  if [ -z "$testcert" ] && certbot certificates --cert-name "$DOMAIN" 2>/dev/null | grep -q TEST_CERT; then
    echo "the certificate present is a --test-cert (staging) one: replacing it"
    run certbot delete --cert-name "$DOMAIN" --non-interactive
  fi
  if [ ! -f "$CONF" ] || ! grep -q 'listen 443' "$CONF"; then
    # port 80 only, so nginx starts without a certificate; certonly --nginx adds its challenge here
    printf '+ write the bootstrap HTTP-only config %s\n' "$CONF"
    cat > "$CONF" <<BOOT
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN $ALT www.$ALT;
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
  if [ -n "$email" ]; then acct="-m $email --no-eff-email"; else acct=--register-unsafely-without-email; fi
  run certbot certonly --nginx $testcert --non-interactive --agree-tos $acct \
      -d "$DOMAIN" -d "www.$DOMAIN" -d "$ALT" -d "www.$ALT" --deploy-hook 'nginx -s reload'
fi

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
