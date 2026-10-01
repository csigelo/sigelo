# site/deploy/ — putting site/dist on https://sigelo.io

One command per deploy, from the machine that holds the repository and the deploy key:

```sh
site/deploy/deploy.sh sigelo@sigelo.io             # build, test, upload, nginx config, check
site/deploy/deploy.sh sigelo@sigelo.io --dry-run   # print every command, run none
node site/deploy/check.mjs                         # the post-deploy check alone, any time
site/deploy/deploy.sh sigelo@sigelo.io --rollback  # serve the previous upload again (run again to undo)
```

| File | What | Runs where |
|---|---|---|
| `deploy.sh` | build → `site/test/run.mjs` (any FAIL stops it) → upload to `dist.new` (rsync, or `tar \| ssh` when either side lacks rsync) → swap (`dist` → `dist.prev`) → nginx config through the helper → `check.mjs` | your machine (POSIX sh, busybox is enough) |
| `check.mjs` | fetches the live site and checks types, negotiation, sha256s, the build commit = local HEAD, headers, HSTS, redirects | your machine (node ≥ 22, no deps) |
| `nginx.conf` | the server config; deploy.sh reinstalls it on every deploy | server: `/etc/nginx/conf.d/sigelo.io.conf` (Alpine: `http.d/`) |
| `sigelo-nginx-apply` | root helper: allowlist check, install, `nginx -t` (restores the old file on failure), reload | server: `/usr/local/sbin/`, via one sudo rule |
| `server-setup.sh` | ONE-TIME server preparation, as root, by hand | server |
| `apache.conf` | the same behaviour for Apache 2.4; install by hand, deploy with `--no-config` | server |

Flags of `deploy.sh`: `--os debian|alpine` (default: the helper detects it), `--dry-run`,
`--no-config` (files only), `--origin URL` (check a staging origin instead of https://sigelo.io),
`--allow-dirty` (staging only: the check's commit test then fails), `--rollback`. SSH options go in
`~/.ssh/config` or `SIGELO_SSH='ssh -i ~/.ssh/sigelo_deploy -p 22'`.

## Server layout

```
/var/www/sigelo.io/            sigelo:sigelo 0755
  dist/                        what nginx serves (root)
  dist.prev/                   the previous upload: --rollback swaps it with dist
  deploy/nginx.conf            the uploaded config; only the helper reads it, after copying it
/var/www/acme/                 ACME HTTP-01 webroot (port 80)
/var/log/nginx/sigelo/         access.log (no client addresses), error.log (crit); 7 days
/usr/local/sbin/sigelo-nginx-apply, /etc/sudoers.d/sigelo-deploy
```

The deploy user `sigelo` is unprivileged: it owns the web root and may run exactly one command as
root, the helper. The helper exists because nginx parses its config as root, so a raw "install
this file" right would make the deploy key a root key (`error_log /etc/cron.d/…`, `include`,
`load_module`). It copies the uploaded file to a root-owned temp file, tokenizes it the way nginx
does, and rejects any directive outside an allowlist and any root, log or certificate path but the
fixed ones. A stolen deploy key can still rewrite the site, its headers and its redirects — that is
the intended scope; the filter is reviewed, not audited. Test it anywhere:
`sh site/deploy/sigelo-nginx-apply --check site/deploy/nginx.conf`.

An identical upload is detected (`diff -r`) and discarded, so re-running a deploy of the same
commit leaves `dist.prev` pointing at the real previous version.

## DNS (before the server setup)

| Name | Type | Value |
|---|---|---|
| `sigelo.io` | A | the server's IPv4 |
| `sigelo.io` | AAAA | the server's IPv6 (omit if it has none — nginx.conf listens on `[::]`; drop those lines if the kernel has IPv6 disabled) |
| `www.sigelo.io` | A, AAAA | the same addresses (or a CNAME to `sigelo.io`) |
| `sigelo.net`, `www.sigelo.net` | A, AAAA | the same addresses; both names 301 to `https://sigelo.io` and sit on the same certificate (the Owner holds `.net` too) |
| `sigelo.io` | CAA (optional) | `0 issue "letsencrypt.org"` — only Let's Encrypt may issue for the domain |

Mail records for `contact@` / `security@sigelo.io` (MX, SPF, DKIM, DMARC) depend on the mail host
and are not covered here; security.txt names `security@sigelo.io`, so it must exist before launch.

## One-time server setup

Needs a fresh Debian 12+/Ubuntu 22.04+ or Alpine 3.18+ server, DNS above already resolving, ports
80 and 443 reachable, and a deploy key pair made on your machine
(`ssh-keygen -t ed25519 -f ~/.ssh/sigelo_deploy -C sigelo-deploy`). Either run the script:

```sh
ssh root@HOST 'mkdir -p /root/sigelo-setup'
scp site/deploy/server-setup.sh site/deploy/nginx.conf site/deploy/sigelo-nginx-apply root@HOST:/root/sigelo-setup/
ssh root@HOST "sh /root/sigelo-setup/server-setup.sh --key '$(cat ~/.ssh/sigelo_deploy.pub)'"
#   --test-cert first if you want a rehearsal against Let's Encrypt staging (a later run without it
#   replaces the staging certificate); --email ADDR to give Let's Encrypt an address (default none)
```

(no root SSH: copy as your admin user and run with `sudo sh …`), or do the same by hand, as root:

```sh
# 1. packages
apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot python3-certbot-nginx sudo logrotate   # Debian/Ubuntu
apk add --no-cache nginx certbot certbot-nginx sudo logrotate && rc-update add nginx default                           # Alpine

# 2. the deploy user (key login only; '*' rather than '!' because OpenSSH without PAM refuses '!' accounts)
useradd --system --create-home --home-dir /var/lib/sigelo --shell /bin/sh sigelo                          # Debian/Ubuntu
addgroup -S sigelo && adduser -S -D -h /var/lib/sigelo -s /bin/sh -G sigelo sigelo                        # Alpine
sed -i 's/^sigelo:[^:]*:/sigelo:*:/' /etc/shadow
install -d -m 0700 -o sigelo -g sigelo /var/lib/sigelo/.ssh
echo 'ssh-ed25519 AAAA… sigelo-deploy' >> /var/lib/sigelo/.ssh/authorized_keys
chown sigelo:sigelo /var/lib/sigelo/.ssh/authorized_keys && chmod 0600 /var/lib/sigelo/.ssh/authorized_keys

# 3. directories
install -d -m 0755 -o sigelo -g sigelo /var/www/sigelo.io /var/www/sigelo.io/deploy /var/www/sigelo.io/dist
install -d -m 0755 /var/www/acme
install -d -m 0750 /var/log/nginx/sigelo
install -d -m 0700 /var/backups/sigelo-nginx

# 4. the distribution's default site (logs client addresses, claims default_server)
rm -f /etc/nginx/sites-enabled/default /etc/nginx/http.d/default.conf

# 5. the helper and its sudo rule
install -m 0755 -o root -g root sigelo-nginx-apply /usr/local/sbin/sigelo-nginx-apply
echo 'sigelo ALL=(root) NOPASSWD: /usr/local/sbin/sigelo-nginx-apply' > /etc/sudoers.d/sigelo-deploy.tmp
chmod 0440 /etc/sudoers.d/sigelo-deploy.tmp && visudo -cf /etc/sudoers.d/sigelo-deploy.tmp && mv /etc/sudoers.d/sigelo-deploy.tmp /etc/sudoers.d/sigelo-deploy

# 6. certificate: a port-80-only bootstrap config (CONF = /etc/nginx/conf.d/sigelo.io.conf, Alpine /etc/nginx/http.d/sigelo.io.conf)
cat > "$CONF" <<'BOOT'
server {
    listen 80;
    listen [::]:80;
    server_name sigelo.io www.sigelo.io;
    access_log off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
    }
    location / {
        return 404;
    }
}
BOOT
nginx -t && (systemctl enable nginx && systemctl restart nginx || rc-service nginx restart)
certbot certonly --nginx --non-interactive --agree-tos --register-unsafely-without-email \
    -d sigelo.io -d www.sigelo.io --deploy-hook 'nginx -s reload'

# 7. renewal
systemctl enable --now certbot.timer                                                        # Debian/Ubuntu
printf '#!/bin/sh\nexec certbot renew -q\n' > /etc/periodic/daily/certbot-renew && chmod 0755 /etc/periodic/daily/certbot-renew \
    && rc-update add crond default && rc-service crond start                                # Alpine
certbot renew --dry-run

# 8. log rotation
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

# 9. the full config, through the helper (the first deploy would do the same)
install -m 0644 -o sigelo -g sigelo nginx.conf /var/www/sigelo.io/deploy/nginx.conf
/usr/local/sbin/sigelo-nginx-apply

# 10. firewall: inbound 22, 80, 443 only
ufw default deny incoming && ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw enable    # ufw
# nftables: an inet filter input chain, policy drop; accept established/related, lo, icmp/icmpv6, tcp dport { 22, 80, 443 }
# plus the hosting provider's firewall; then PermitRootLogin no / PasswordAuthentication no in sshd_config
```

Why `certbot certonly --nginx` and not `certbot --nginx`: the nginx authenticator proves control
on port 80 without the installer editing the config. deploy.sh reinstalls `nginx.conf` on every
deploy, so installer edits would be overwritten; the certificate paths are written in `nginx.conf`
instead. Renewal uses the same authenticator against the port-80 server block; if it ever fails,
`certbot renew --webroot -w /var/www/acme` works with the same config.

## The first deploy, then HSTS

```sh
site/deploy/deploy.sh sigelo@sigelo.io --os debian    # or alpine
```

nginx.conf ships `Strict-Transport-Security: max-age=300`, so a TLS mistake on day one cannot
lock visitors out for a year. When `check.mjs` passes against the live site (it prints a `note`
while max-age is below a year), change both HSTS lines in `nginx.conf` to `max-age=31536000`,
commit, deploy. No `includeSubDomains` or `preload`: both bind every future subdomain, the Owner's
call.

## The check

`node site/deploy/check.mjs [--origin URL] [--no-tls] [--no-www] [--node-server] [--commit SHA | --any-commit]`

From the phone, against https://sigelo.io by default: `/`, `/llms.txt`, `/adopt.md`,
`/index.json`, `/.well-known/security.txt`, `/sitemap.xml`, `/robots.txt`, `/spec.md`,
`/examples/world.mjs`, `/style.css` return 200 with exactly the content types of
`site/test/run.mjs`; `Accept: text/markdown` on `/`, `/spec.html` and `/spec` returns the Markdown
twin; every file in `index.json` hashes to its listed sha256 and size; both `/sha256/<hex>/…`
copies hash to the hex in their path and are cached a year, immutable; `index.json`'s
`built_from.commit` is the local HEAD and `dirty` is false; security.txt has not expired (a note
under 60 days); CSP, Permissions-Policy, nosniff, no-referrer, `Vary: Accept`, Cache-Control, no
version in `Server`, no cookie; HSTS; `http://` → `https://` and `www` → apex 301s (path and query
kept). Exit 1 on any FAIL.

Tested here against `node site/test/run.mjs --serve <port>` with `--no-tls --node-server` (that
server has the types and negotiation but no headers and no `/spec` mapping, so those are skipped),
and against a node emulation of nginx.conf's headers with `--no-tls` (all header checks run; a
broken variant — no CSP, a charset on JSON — fails as it should). The TLS, HSTS and redirect checks
have not run against a real server yet.

## Rollback

`site/deploy/deploy.sh sigelo@sigelo.io --rollback` swaps `dist` and `dist.prev` on the server
(no build, no sudo) and runs the check with `--any-commit`; run it again to roll forward. By hand:
`ssh sigelo@sigelo.io 'cd /var/www/sigelo.io && mv dist dist.swap && mv dist.prev dist && mv dist.swap dist.prev'`.
A broken nginx config never needs a rollback: the helper keeps the old file when `nginx -t`
fails, and the last ten installed configs are in `/var/backups/sigelo-nginx/`.

## Privacy

- **No client addresses are kept.** The access log's address field is a literal `-`, the referrer
  is not logged, the error log is at `crit` (nginx writes the client address into every
  `error`-level line), requests for other hostnames are dropped unlogged, and the files rotate
  daily with 7 kept. What remains — time, request, status, size, user agent — tells which agents
  and crawlers read the site, the one figure worth having, without knowing who they are.
  Chosen over `access_log off` because a week of anonymous logs is enough to see abuse or a broken
  link and is no record of anyone.
- **The site sets no cookies, runs no scripts and loads nothing from another origin**
  (`site/test/run.mjs` checks); `Referrer-Policy: no-referrer` keeps it from leaking where readers
  go next.
- **Let's Encrypt** is registered without an e-mail address by default; issued certificates are
  public in Certificate Transparency logs (that reveals the names, not the holder).
- **The hosting account and the domain registration link sigelo.io to whoever pays for them**,
  whatever the logs say: the provider's billing records, the registrar's WHOIS data (use its
  privacy service), and the server's IP addresses. Which account, provider and jurisdiction —
  and whether GitHub Pages (no server, no IP linkage, but no headers or negotiation;
  site/README.md) is the primary instead — is the Owner's decision.
- **The build commit is public.** `index.json`, the page footers and `llms-full.txt` name the
  commit the site was built from; deployed from the private tree, that is a private-history hash
  that resolves nowhere public. Deploy from the public export to publish a hash readers can find.
