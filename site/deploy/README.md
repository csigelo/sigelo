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
| `stats-agents.sh` | the agent/human split of the visits as `agents.txt` (≤ 40 lines, phone-sized); `server-setup.sh --stats` installs it with the 15-minute timer | server: `/usr/local/sbin/sigelo-stats-agents` |
| `watch.sh` | the watchdog: reachability probes (site, TLS, `/world/stats`, `/mcp`), notify when down, throttled | the Owner's phone: `~/.local/bin/sigelo-watch` + `sigelo-watch.timer` (user) |
| `apache.conf` | the same behaviour for Apache 2.4; install by hand, deploy with `--no-config` | server |
| `mirror-release.sh` | `<tag> [user@host]`: `gh release download` → every file against SHA256SUMS → upload to `releases/<tag>/` (never changed once there) → `releases/index.json`, `latest` → re-download over HTTPS and compare | your machine (gh, node, ssh) |

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
  stats/                       root 0755: index.html (GoAccess) and agents.txt, at /_stats/
  releases/                    the release mirror, at /releases/ (mirror-release.sh): <tag>/ files 0644,
                               index.json, index.md, latest -> <tag>; dist/releases -> ../releases
                               is a symlink deploy.sh puts in every upload, so no deploy deletes it
/var/www/acme/                 ACME HTTP-01 webroot (port 80)
/var/log/nginx/sigelo/         access.log (address cut to /24 or /48), error.log (crit); 30 days
                               access-self.log: the project's own requests, same format; 7 days
/usr/local/sbin/sigelo-nginx-apply, /etc/sudoers.d/sigelo-deploy
/usr/local/sbin/sigelo-stats{,-agents}, sigelo-stats.{service,timer}, /etc/nginx/sigelo-stats.htpasswd
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

## Visit statistics (`/_stats/`)

Server-side only: no script, cookie or third party on the site. `server-setup.sh --stats` (as
root, once, on a prepared server) installs GoAccess, the password file, and `sigelo-stats.timer`,
which every 15 minutes rebuilds `/var/www/sigelo.io/stats/index.html` (GoAccess over every log
kept, `--anonymize-ip` as a second cut, the hosts panel off) and `agents.txt` (`stats-agents.sh`:
AI agents by name, programmatic clients, crawlers, browsers, `Accept: text/markdown`, the agent
funnel `/llms.txt` → `/adopt.md` → `/index.json` → `/examples/world.mjs`, top paths for agents and
for humans). Both are served at `https://sigelo.io/_stats/` behind basic auth (user `owner`; the
password lives only on the Owner's phone, the server keeps its SHA-512 crypt hash), `noindex`,
`no-store`, not in the sitemap; `check.mjs` checks the 401 and the sitemap.

**Own traffic is excluded.** Every request the project makes to its own site — `check.mjs`
(also deploy.sh's post-deploy check), `watch.sh`, `indexnow.sh`'s fetch of the key file,
`mirror-release.sh`'s verification, the server's `sigelo-selfcheck` — sends
`User-Agent: sigelo-selfcheck/1 (+https://sigelo.io/privacy)`. nginx.conf maps that user agent
(`$sigelo_self` / `$sigelo_outside`) and logs those requests to `access-self.log` (same format,
7 days kept) instead of `access.log`, with `access_log … if=`. GoAccess and `agents.txt` read
`access.log*` only, so the programmatic/`node` counts are outsiders; `agents.txt` prints the
excluded count as `own traffic (excluded) N, 7 days`. `site/test` and `world/test.mjs` run
against local servers and never reach the site. Before this change the checks sent node's default
`node` user agent: those lines stay in the 30-day window until they rotate out.

## The world (`/world/`)

`world/server.mjs` runs as `sigelo-world.service` (user `sigelo-world`, loopback 8790) behind the `/world/`
location; world/README.md is the whole story. Once, after a first deploy has shipped `world-app/`:
`sh server-setup.sh --world sha256:<recovery commitment>` (with `sigelo-world.service` and
`sigelo-world-apply` beside it) installs nodejs, the unit, the issuer key and the second sudo rule
(`sigelo-world-apply`: restart the unit, nothing else). Commit the printed genesis as `world/genesis.json`.

## Releases (`/releases/`)

`site/deploy/mirror-release.sh v0.1.0 sigelo-vps` copies a GitHub release to
`/var/www/sigelo.io/releases/v0.1.0/` after checking every file against the release's
`SHA256SUMS`, writes `releases/index.json` (tags, files, sizes, sha256s) and the Markdown
listings nginx serves at `/releases/` and `/releases/<tag>/`, points `latest` at the highest tag,
and downloads every file back over HTTPS. A mirrored tag never changes (the script refuses
different files), so nginx serves `/releases/v*/` files immutable for a year and `index.json`,
the listings and `latest/` for five minutes. The binaries are never in git or `dist/`; the site
learns a release from `site/src/releases/<tag>.SHA256SUMS`, which the script writes: commit it
and redeploy. The installed helper allows no root but `dist/`, so nginx reaches the mirror
through the `dist/releases` symlink rather than a second `root`.

## Watchdog, self-check, state backup

**Phone** — `site/deploy/watch.sh`, installed as `~/.local/bin/sigelo-watch` with
`~/.config/systemd/user/sigelo-watch.{service,timer}` (every 15 minutes). It asks only whether the
site is reachable and working — `/`, `/llms.txt`, `/index.json`, `/spec.md`, the `http://` → `https://`
301, a certificate valid 7 more days, `/world/stats`, `/mcp` initialize — never content or release
state (that is `check.mjs --quiet` at deploy time). A failure is retried after 20 s, and does not
count when the phone itself is offline. One `notify-send -u critical` when an incident starts, then
at most one an hour (a global `last-notify` cap, whatever the state); recovery is a log line;
success is silent. Log: `~/.local/share/sigelo-watch/alerts.log`. Tests use `--no-notify`;
`--origin URL` implies it and a scratch state, so a test never changes what the timer watches.

**Server, self-healing** — `server-setup.sh --guard`: `nginx.service` gets `Restart=on-failure`
(a drop-in; Debian ships `Restart=no`), `sigelo-world.service` already has `Restart=always`, and
root's `sigelo-selfcheck.timer` runs `/usr/local/sbin/sigelo-selfcheck` hourly: `/` and
`/world/stats` through nginx on 127.0.0.1, `/world/stats` from the world on :8790; it restarts the
failing unit (nginx only after `nginx -t`) and logs to `journalctl -u sigelo-selfcheck`.

**Server, state backup** — `server-setup.sh --backup age1…`: root's `sigelo-vps-backup.timer`
(daily 03:30 Europe/Berlin) tars `/var/lib/sigelo-world` (issuer key, attestations, nonces),
`/etc/sigelo-world.env`, the nginx config and stats password file, `/etc/letsencrypt`, the sigelo
units, helpers, sudo rule and logrotate file, `/var/backups/sigelo-nginx`, the release mirror and
the stats, encrypted with age to a recipient whose identity is only on the Owner's phone
(`~/.config/sigelo/vps-backup.key`): `/home/csigelo/backup/vps-state-<stamp>.tgz.age`, csigelo
0600, 7 kept. The server cannot read its own backups. The phone's nightly `sigelo-backup` (04:00)
pulls the newest into `~/.local/share/sigelo-vps-state/`, which its own passphrase-encrypted
archive then carries back to the VPS: each side holds the other's secrets, encrypted to a key the
holder lacks.

## Rebuilding the server

From a fresh Debian 13 host with DNS pointed at it, in this order (the phone's
`~/.config/sigelo/RESTORE.md` has the same steps with paths): decrypt the newest
`vps-state-*.tgz.age` on the phone (`age -d -i ~/.config/sigelo/vps-backup.key`); as root on the
server, `tar -C / -xzf vps.tgz etc/letsencrypt` and then `server-setup.sh --key …` (the certificate
is found and kept: no re-issue); `deploy.sh` from the phone; `tar … var/lib/sigelo-world
etc/sigelo-world.env` and `server-setup.sh --world keep` (the old issuer key is kept and re-owned:
same DID, no new genesis); `tar … etc/nginx/sigelo-stats.htpasswd var/www/sigelo.io/stats` and
`--stats`; `tar … var/www/sigelo.io/releases`; `--guard`; `--backup <age-keygen -y vps-backup.key>`;
then `check.mjs` must say ALL PASS.

## Rollback

`site/deploy/deploy.sh sigelo@sigelo.io --rollback` swaps `dist` and `dist.prev` on the server
(no build, no sudo) and runs the check with `--any-commit`; run it again to roll forward. By hand:
`ssh sigelo@sigelo.io 'cd /var/www/sigelo.io && mv dist dist.swap && mv dist.prev dist && mv dist.swap dist.prev'`.
A broken nginx config never needs a rollback: the helper keeps the old file when `nginx -t`
fails, and the last ten installed configs are in `/var/backups/sigelo-nginx/`.

## Privacy

- **No raw client addresses are kept.** The access log's first field is the address cut to its
  network (IPv4 /24 → `a.b.c.0`, IPv6 /48 → `a:b:c::`): a pseudonym shared by everyone on that
  network, coarse enough to name no one, fine enough for GoAccess to estimate unique visitors
  (with the user agent and the day). Chosen over a salted hash, which nginx cannot compute without
  a scripting module the allowlist would have to admit, and over no address at all, which makes
  every visitor with the same browser one visitor. The referrer is cut to scheme and host, the
  path loses its query string; time, method, status, size, user agent, `Accept` and request time
  are kept, because agents never run scripts and these lines are the only place they show up.
  The error log is at `crit` (nginx writes the full address into every `error`-level line),
  requests for other hostnames and for `/_stats/` are not logged, and the files rotate daily with
  30 kept: 30 days of truncated-address logs and the reports built from them, nothing else. The
  project's own requests (user agent `sigelo-selfcheck/1`) go to `access-self.log`, 7 kept.

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
