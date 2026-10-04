#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/watch.sh — the phone's watchdog for https://sigelo.io: is the site reachable and
# working? Installed as ~/.local/bin/sigelo-watch, run by sigelo-watch.timer (systemd --user).
#
#   sigelo-watch                  probe https://sigelo.io; notify when down (throttled, below)
#   sigelo-watch --no-notify      probe and log, never notify (every test, every manual run)
#   sigelo-watch --origin URL     probe another origin; implies --no-notify and a scratch state
#                                 directory unless --state is given: a test can never leave the
#                                 timer's state or its target changed (the timer passes no flags)
#   sigelo-watch --state DIR      state + alerts.log (default ~/.local/share/sigelo-watch)
#
# What counts as down — reachability and function only, never content or release state (that is
# check.mjs's job at deploy time): GET / (200, HTML), /llms.txt, /index.json (200, parses),
# /spec.md; http:// → https:// 301; the TLS certificate valid for 7 more days; GET /world/stats
# (200, counts); POST /mcp initialize (200, tools) — no challenge, which would spend a nonce slot
# of the world's ring on every run. A failed
# run is retried once after 20 s; when api.github.com is unreachable too, the phone is offline:
# logged, not counted.
#
# Notifications (notify-send -u critical), hard throttle: ONE when an incident starts, then at
# most one an hour while it lasts — and never two within an hour, whatever the state says
# (last-notify in the default state dir is shared by every run, any --state). Recovery is one log
# line, no notification. Success is silent. Every failed run appends one line to alerts.log.
# Exit 1 while down. Every probe of the site sends User-Agent sigelo-selfcheck/1 (nginx.conf logs
# it to access-self.log, out of the visit statistics); the api.github.com probe does not.
set -u
DEFAULT_STATE="$HOME/.local/share/sigelo-watch"
ORIGIN=https://sigelo.io; STATE=""; NOTIFY=1; REPEAT=3600; FORCE=0
while [ $# -gt 0 ]; do
  case $1 in
    --origin) ORIGIN=${2%/}; NOTIFY=0; shift 2 ;;
    --state) STATE=$2; shift 2 ;;
    --no-notify) NOTIFY=0; shift ;;
    --test-notify) FORCE=1; shift ;;   # tests of the throttle only, with a stub notify-send on PATH
    *) echo "sigelo-watch: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ "$FORCE" = 0 ] || NOTIFY=1
umask 077
if [ -z "$STATE" ]; then
  if [ "$ORIGIN" = https://sigelo.io ]; then STATE=$DEFAULT_STATE; else STATE=$(mktemp -d); echo "sigelo-watch: test origin, scratch state $STATE"; fi
fi
mkdir -p "$STATE" "$DEFAULT_STATE"
LOG=$STATE/alerts.log; ST=$STATE/state; LAST_NOTIFY=$DEFAULT_STATE/last-notify
now=$(date +%s); stamp=$(date -u +%FT%TZ)

probe() {
  NODE_NO_WARNINGS=1 node --input-type=module - "$ORIGIN" <<'JS'
import tls from 'node:tls';
import { isIP } from 'node:net';
const o = process.argv[2], u = new URL(o), bad = [];
const t = () => AbortSignal.timeout(20000);
const UA = 'sigelo-selfcheck/1 (+https://sigelo.io/privacy)';
const req = async (path, init = {}) => {
  try { const r = await fetch(o + path, { signal: t(), redirect: 'manual', ...init, headers: { 'user-agent': UA, ...init.headers } }); return { r, body: await r.text() }; }
  catch (e) { return { err: e.cause?.code ?? e.message }; }
};
const want = async (name, path, test, init) => {
  const { r, body, err } = await req(path, init);
  if (err) return bad.push(`${name}: ${err}`);
  let ok = false; try { ok = r.status === 200 && test(r, body); } catch { /* bad body */ }
  if (!ok) bad.push(`${name}: ${r.status}`);
};
await want('/', '/', (r, b) => r.headers.get('content-type')?.startsWith('text/html') && b.includes('<h1'));
await want('/llms.txt', '/llms.txt', (r, b) => b.startsWith('# '));
await want('/index.json', '/index.json', (r, b) => JSON.parse(b).name === 'sigelo');
await want('/spec.md', '/spec.md', (r, b) => b.length > 1000);
await want('/world/stats', '/world/stats', (r, b) => Number.isInteger(JSON.parse(b).attestations));
await want('/mcp initialize', '/mcp', (r, b) => !!JSON.parse(b).result?.capabilities?.tools, {
  method: 'POST', headers: { accept: 'application/json, text/event-stream', 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'sigelo-watch', version: '0' } } }) });
if (u.protocol === 'https:') {
  try {
    const r = await fetch(`http://${u.host}/`, { redirect: 'manual', headers: { 'user-agent': UA }, signal: t() });
    if (r.status !== 301 || r.headers.get('location') !== `https://${u.host}/`) bad.push(`http:// redirect: ${r.status}`);
  } catch (e) { bad.push(`http:// redirect: ${e.cause?.code ?? e.message}`); }
  const days = await new Promise((res) => {
    const s = tls.connect({ host: u.hostname, port: Number(u.port || 443), ...(isIP(u.hostname) ? {} : { servername: u.hostname }), timeout: 20000 }, () => {
      const c = s.getPeerCertificate(); s.end(); res((Date.parse(c.valid_to) - Date.now()) / 86400e3);
    });
    s.on('error', (e) => res(`TLS ${e.code ?? e.message}`)); s.on('timeout', () => { s.destroy(); res('TLS timeout'); });
  });
  if (typeof days === 'string') bad.push(days); else if (days < 7) bad.push(`TLS certificate expires in ${days.toFixed(1)} days`);
}
if (bad.length) { console.log(bad.join('; ')); process.exit(1); }
JS
}
online() {
  node -e 'fetch("https://api.github.com/",{method:"HEAD",signal:AbortSignal.timeout(15000)}).then(()=>process.exit(0),()=>process.exit(1))'
}
notify() {  # notify TITLE BODY — hard throttle: never two within REPEAT seconds, whatever the state
  lastn=0; [ -f "$LAST_NOTIFY" ] && read -r lastn < "$LAST_NOTIFY"
  if [ "$NOTIFY" != 1 ]; then echo "$stamp (--no-notify) would notify: $1" >> "$LOG"; return; fi
  if [ $((now - ${lastn:-0})) -lt "$REPEAT" ]; then echo "$stamp throttled (last notification $(( (now - lastn) / 60 )) min ago): $1" >> "$LOG"; return; fi
  echo "$now" > "$LAST_NOTIFY"
  if notify-send -a sigelo-watch -u critical "$1" "$2" 2>/dev/null; then echo "$stamp notified: $1" >> "$LOG"
  else echo "$stamp notify-send failed (no session bus?): $1" >> "$LOG"; fi
}

prev=up; since=$now; last=0
[ -f "$ST" ] && read -r prev since last < "$ST"

if out=$(probe 2>&1) || { sleep 20; out=$(probe 2>&1); }; then
  [ "$prev" = down ] && echo "$stamp ok again: $ORIGIN after $(( (now - since) / 60 )) min down" >> "$LOG"
  echo "up $now 0" > "$ST"
  exit 0
fi
if ! online; then
  echo "$stamp skip: the phone is offline ($ORIGIN and api.github.com unreachable); not counted" >> "$LOG"
  exit 0
fi
out=$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)
# One failing tick is not an outage: a phone on a half-working network reaches api.github.com and
# times out on the origin (2026-10-04, a false "DOWN" during a Wi-Fi hand-over). Notify from the
# second consecutive failing tick on, i.e. after the timer interval has passed with the origin down.
if [ "$prev" != down ]; then
  echo "$stamp DOWN $ORIGIN (first tick, confirming next run): $out" >> "$LOG"
  echo "down $now 0" > "$ST"
  exit 1
fi
echo "$stamp DOWN $ORIGIN: $out" >> "$LOG"
if [ $((now - last)) -ge "$REPEAT" ]; then
  notify "sigelo.io DOWN" "$ORIGIN, down $(( (now - since) / 60 )) min: $out (log: $LOG)"
  last=$now
fi
echo "down $since $last" > "$ST"
exit 1
