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

os=""; key=""; email=""; testcert=""; skipcert=0
while [ $# -gt 0 ]; do
  case $1 in
    --os) os=$2; shift 2 ;;
    --key) key=$2; shift 2 ;;
    --key-file) key=$(cat "$2"); shift 2 ;;
    --email) email=$2; shift 2 ;;
    --test-cert) testcert=--test-cert; shift ;;
    --skip-cert) skipcert=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root"
for f in nginx.conf sigelo-nginx-apply; do [ -f "$HERE/$f" ] || die "$HERE/$f missing: copy it next to this script"; done
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
run install -m 0755 -o root -g root "$HERE/sigelo-nginx-apply" /usr/local/sbin/sigelo-nginx-apply
printf '+ write /etc/sudoers.d/sigelo-deploy\n'
printf 'sigelo ALL=(root) NOPASSWD: /usr/local/sbin/sigelo-nginx-apply\n' > /etc/sudoers.d/sigelo-deploy.tmp
chmod 0440 /etc/sudoers.d/sigelo-deploy.tmp
run visudo -cf /etc/sudoers.d/sigelo-deploy.tmp
run mv /etc/sudoers.d/sigelo-deploy.tmp /etc/sudoers.d/sigelo-deploy

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

say "8. log rotation: /var/log/nginx/sigelo/*.log daily, 7 kept (the log has no client addresses)"
printf '+ write /etc/logrotate.d/sigelo\n'
cat > /etc/logrotate.d/sigelo <<'ROT'
/var/log/nginx/sigelo/*.log {
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
NEXT
