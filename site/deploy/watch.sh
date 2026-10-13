#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/watch.sh — the phone's watchdog for https://sigelo.io and the relay on https://sigelo.ai:
# is each reachable and working? Installed as ~/.local/bin/sigelo-watch, run by sigelo-watch.timer
# (systemd --user).
#
#   sigelo-watch                  probe both; notify when one is down (throttled, below)
#   sigelo-watch --no-notify      probe and log, never notify (every test, every manual run)
#   sigelo-watch --origin URL     probe URL with the sigelo.io probes only
#   sigelo-watch --relay-origin URL [--relay-host HOST[:PORT]]
#                                 probe URL with the sigelo.ai probes only; HOST (default relay.<URL
#                                 host>) answers /challenge on 443 and MQTT on PORT (default 8883)
#   sigelo-watch --state DIR      state + alerts.log (default ~/.local/share/sigelo-watch)
#   sigelo-watch --self-test      the paging rules below against stubs: no probe, no notification
# --origin, --relay-origin and --relay-host imply --no-notify and a scratch state directory unless
# --state is given: a test can never leave the timer's state or its targets changed (the timer
# passes no flags). The scratch directory goes on exit; its alerts.log is printed first.
#
# What counts as down — reachability and function only, never content or release state (that is
# check.mjs's job at deploy time).
#   sigelo.io: GET / (200, HTML), /llms.txt, /index.json (200, parses), /spec.md; http:// →
#   https:// 301; the TLS certificate valid for 7 more days; GET /world/stats (200, counts); POST
#   /mcp initialize (200, tools) — no challenge, which would spend a nonce slot of the world's ring.
#   sigelo.ai: GET / (200, HTML); GET https://relay.sigelo.ai/challenge?did=… (200, a relay-login
#   body; the relay keeps nothing for it); MQTT over TLS on relay.sigelo.ai:8883 answers a CONNECT
#   with a CONNACK (a refused login is the answer expected: the probe has no identity; a timeout,
#   a closed socket, or CONNACK 0 — a login without credentials accepted — is down); both
#   certificates valid for 7 more days.
# A failed run is retried once after 20 s; when api.github.com is unreachable too, the phone is
# offline: logged, not counted.
#
# Each target has its own state and incidents. One failing tick is not an outage: a target is down
# from its second failing tick in a row. Notifications (notify-send -u critical): ONE when an
# incident is confirmed, then at most one every 6 hours while it lasts — and never two within an
# hour across both targets, whatever the state says
# (last-notify in the default state dir is shared by every run, any --state); a page the hour cap
# holds back is sent on a later tick. Recovery is one log line, no notification. Success is silent.
# Every failed run appends one line to alerts.log. Exit 1 while a target is down. Every probe of a
# site sends User-Agent sigelo-selfcheck/1 (sigelo.io's nginx.conf logs it to access-self.log, out of
# the visit statistics); the api.github.com probe does not.
set -u

# --self-test: this script run against stubs, with HOME, TMPDIR and the state in a scratch
# directory and PATH led by stub programs: node (a probe fails unless $T/up exists; the
# api.github.com question succeeds unless $T/offline exists), sleep (returns at once) and
# notify-send (appends to $T/pages, the pages counted). Time is moved by rewriting the state files.
self_test() {
  T=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-watch-test.XXXXXX") || exit 1
  trap 'rm -rf "$T"' EXIT
  mkdir "$T/bin" "$T/tmp"
  cat > "$T/bin/node" <<STUB
#!/bin/sh
if [ "\$1" = -e ]; then [ ! -f "$T/offline" ]; exit; fi
cat > /dev/null
[ -f "$T/up" ] && exit 0
echo "stub probe: down"; exit 1
STUB
  printf '#!/bin/sh\n' > "$T/bin/sleep"
  printf '#!/bin/sh\necho "$*" >> "%s/pages"\n' "$T" > "$T/bin/notify-send"
  chmod 0755 "$T/bin/node" "$T/bin/sleep" "$T/bin/notify-send"
  # The real notify-send must never run here: the stub has to be the one PATH finds.
  [ "$(PATH="$T/bin:$PATH" command -v notify-send)" = "$T/bin/notify-send" ] || { echo "sigelo-watch --self-test: the stub notify-send is not first on PATH" >&2; exit 1; }
  n=0; failed=0
  ok() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok $2"; else failed=$((failed + 1)); echo "FAIL $2"; fi; }
  # w HOME ARG... → the run's exit status in $wrc
  w() { h=$1; shift; mkdir -p "$h"; wrc=0; HOME=$h TMPDIR=$T/tmp PATH="$T/bin:$PATH" sh "$0" "$@" > "$T/out" 2>&1 || wrc=$?; }
  pages() { if [ -f "$T/pages" ]; then grep -c . "$T/pages"; else echo 0; fi; }
  st() { cat "$T/s/state"; }
  H=$T/home; S="--state $T/s --origin https://watch.invalid --test-notify"
  ln=$H/.local/share/sigelo-watch/last-notify
  # shellcheck disable=SC2086
  {
  w "$H" $S; [ "$wrc" = 1 ] && [ "$(pages)" = 0 ] && grep -q 'first tick' "$T/s/alerts.log"; ok $? "first failing tick: down, no page"
  w "$H" $S; [ "$wrc" = 1 ] && [ "$(pages)" = 1 ]; ok $? "second failing tick in a row: one page"
  now=$(date +%s); echo $((now - 3601)) > "$ln"   # the hour cap out of the way: the 6 h rule alone
  w "$H" $S; [ "$(pages)" = 1 ]; ok $? "a third tick within 6 h: no second page for the incident"
  read -r _ since _ < "$T/s/state"
  echo "down $since $((now - 21601))" > "$T/s/state"; echo $((now - 1800)) > "$ln"
  w "$H" $S; [ "$(pages)" = 1 ] && grep -q '^.* throttled' "$T/s/alerts.log" && [ "$(st)" = "down $since $((now - 21601))" ]; ok $? "6 h later but a page 30 min ago: held back, still owed"
  echo $((now - 3601)) > "$ln"
  w "$H" $S; [ "$(pages)" = 2 ]; ok $? "the held page goes out on a later tick, an hour after the last"
  touch "$T/up"
  w "$H" $S; [ "$wrc" = 0 ] && [ "$(pages)" = 2 ] && grep -q 'ok again' "$T/s/alerts.log" && case $(st) in up*) true ;; *) false ;; esac; ok $? "recovery: a log line, no page"
  rm -f "$T/up"; touch "$T/offline"
  w "$H" $S; w "$H" $S; [ "$wrc" = 0 ] && [ "$(pages)" = 2 ] && grep -q 'phone is offline' "$T/s/alerts.log" && case $(st) in up*) true ;; *) false ;; esac; ok $? "the phone offline: logged, not counted"
  rm -f "$T/offline"
  # both targets down at once, a fresh home: one page, the other held by the hour cap
  w "$T/home2" --state "$T/s2" --origin https://watch.invalid --relay-origin https://watch.invalid --test-notify
  w "$T/home2" --state "$T/s2" --origin https://watch.invalid --relay-origin https://watch.invalid --test-notify
  [ "$(pages)" = 3 ] && grep -q 'throttled' "$T/s2/alerts.log"; ok $? "two targets confirmed down in one run: one page, never two within an hour"
  # --no-notify (and a test target without --test-notify): never a page
  w "$T/home3" --state "$T/s3" --origin https://watch.invalid; w "$T/home3" --state "$T/s3" --origin https://watch.invalid --no-notify
  [ "$wrc" = 1 ] && [ "$(pages)" = 3 ] && grep -q 'would notify' "$T/s3/alerts.log"; ok $? "a test target, --no-notify: logged as 'would notify', no page"
  # without --state a test target's scratch state goes on exit, its log printed
  w "$T/home4" --origin https://watch.invalid
  [ -z "$(ls -A "$T/tmp")" ] && grep -q 'first tick' "$T/out"; ok $? "a test target's scratch state is removed on exit, its alerts.log printed"
  }
  if [ "$failed" = 0 ]; then echo "ALL PASS ($n)"; exit 0; fi
  echo "$failed FAILED of $n"; exit 1
}
[ "${1:-}" != --self-test ] || self_test

DEFAULT_STATE="$HOME/.local/share/sigelo-watch"
ORIGIN=https://sigelo.io; RELAY_ORIGIN=https://sigelo.ai; RELAY_HOST=""
STATE=""; NOTIFY=1; REPEAT=21600; GAP=3600; FORCE=0; targets=""; custom=0
while [ $# -gt 0 ]; do
  case $1 in
    --origin) ORIGIN=${2%/}; targets="$targets io"; custom=1; shift 2 ;;
    --relay-origin) RELAY_ORIGIN=${2%/}; targets="$targets ai"; custom=1; shift 2 ;;
    --relay-host) RELAY_HOST=$2; custom=1; shift 2 ;;
    --state) STATE=$2; shift 2 ;;
    --no-notify) NOTIFY=0; shift ;;
    --test-notify) FORCE=1; shift ;;   # tests of the throttle only, with a stub notify-send on PATH
    *) echo "sigelo-watch: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$targets" ] || targets="io ai"
[ -n "$RELAY_HOST" ] || RELAY_HOST=relay.$(printf '%s' "$RELAY_ORIGIN" | sed -E 's#^[a-z]+://##; s#[:/].*$##')
[ "$custom" = 0 ] || NOTIFY=0
[ "$FORCE" = 0 ] || NOTIFY=1
umask 077
if [ -z "$STATE" ]; then
  if [ "$custom" = 0 ]; then STATE=$DEFAULT_STATE
  else
    # A test run's own state, gone on exit: repeated tests would otherwise pile up in TMPDIR.
    STATE=$(mktemp -d "${TMPDIR:-/tmp}/sigelo-watch.XXXXXX") || exit 2
    trap '[ ! -s "$STATE/alerts.log" ] || cat "$STATE/alerts.log" >&2; rm -rf "$STATE"' EXIT
    trap 'exit 2' HUP INT TERM
    echo "sigelo-watch: test target, scratch state (removed on exit, its alerts.log printed)"
  fi
fi
mkdir -p "$STATE" "$DEFAULT_STATE"
LOG=$STATE/alerts.log; LAST_NOTIFY=$DEFAULT_STATE/last-notify
now=$(date +%s); stamp=$(date -u +%FT%TZ)

probe_io() {
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

probe_ai() {
  NODE_NO_WARNINGS=1 node --input-type=module - "$RELAY_ORIGIN" "$RELAY_HOST" <<'JS'
import tls from 'node:tls';
const [o, relay] = process.argv.slice(2), u = new URL(o), bad = [];
const UA = 'sigelo-selfcheck/1 (+https://sigelo.ai/privacy)';
// test-vectors.json's first DID: well-formed and public; a challenge for it leaves nothing on the relay
const DID = 'did:sigelo:zF5FYbH5zNLX5pfd7DZUjPirXeAFzLVxrdFyCrnexdpBG';
const want = async (name, url, test) => {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(20000), redirect: 'manual', headers: { 'user-agent': UA } });
    const b = await r.text();
    let ok = false; try { ok = r.status === 200 && test(r, b); } catch { /* bad body */ }
    if (!ok) bad.push(`${name}: ${r.status}`);
  } catch (e) { bad.push(`${name}: ${e.cause?.code ?? e.message}`); }
};
const [host, port] = relay.includes(':') ? relay.split(':') : [relay, '8883'];
await want('/', `${o}/`, (r) => r.headers.get('content-type')?.startsWith('text/html'));
await want('/challenge', `https://${host}/challenge?did=${DID}`, (r, b) => JSON.parse(b).challenge?.typ === 'relay-login');
// An MQTT 3.1.1 CONNECT with no username: client id "sigelo-watch", clean session, keepalive 60 s.
// Any CONNACK but 0 is up (the relay answers 4, check `password`; 3 is its login rate, a brake, not
// an outage); 0 means login no longer holds. Also reads the broker's certificate.
const CONNECT = Buffer.from([0x10, 24, 0, 4, 0x4d, 0x51, 0x54, 0x54, 4, 0x02, 0, 60, 0, 12, ...Buffer.from('sigelo-watch')]);
const tlsProbe = (host, port, mqtt) => new Promise((res) => {
  let got = Buffer.alloc(0), days;
  const done = (err) => { s.destroy(); res({ days, err }); };
  const s = tls.connect({ host, port, servername: host, timeout: 20000 }, () => {
    days = (Date.parse(s.getPeerCertificate().valid_to) - Date.now()) / 86400e3;
    if (mqtt) s.write(CONNECT); else done('');
  });
  s.on('data', (d) => {
    got = Buffer.concat([got, d]);
    if (got.length >= 4) done(got[0] !== 0x20 || got[1] !== 2 ? 'not a CONNACK' : got[3] === 0 ? 'CONNACK 0: a login without credentials accepted' : '');
  });
  s.on('timeout', () => done('timeout'));
  s.on('error', (e) => done(e.code ?? e.message));
  s.on('close', () => done('closed before a CONNACK'));
});
const m = await tlsProbe(host, Number(port), true), w = await tlsProbe(u.hostname, Number(u.port || 443), false);
if (m.err) bad.push(`MQTT ${host}:${port}: ${m.err}`);
for (const [name, p] of [[`TLS ${u.hostname}`, w], [`TLS ${host}:${port}`, m]]) {
  if (p.days === undefined) { if (p === w) bad.push(`${name}: ${p.err}`); }   // the broker's error is already named above
  else if (p.days < 7) bad.push(`${name}: certificate expires in ${p.days.toFixed(1)} days`);
}
if (bad.length) { console.log(bad.join('; ')); process.exit(1); }
JS
}

online=""
is_online() {  # asked once per run, and only when a probe failed
  if [ -z "$online" ]; then
    if node -e 'fetch("https://api.github.com/",{method:"HEAD",signal:AbortSignal.timeout(15000)}).then(()=>process.exit(0),()=>process.exit(1))'; then online=1; else online=0; fi
  fi
  [ "$online" = 1 ]
}
notify() {  # notify TITLE BODY — hard throttle: never two within GAP seconds, whatever the state
  lastn=0; [ -f "$LAST_NOTIFY" ] && read -r lastn < "$LAST_NOTIFY"
  if [ "$NOTIFY" != 1 ]; then echo "$stamp (--no-notify) would notify: $1" >> "$LOG"; return 0; fi
  if [ $((now - ${lastn:-0})) -lt "$GAP" ]; then echo "$stamp throttled (last notification $(( (now - lastn) / 60 )) min ago): $1" >> "$LOG"; return 1; fi
  echo "$now" > "$LAST_NOTIFY"
  if notify-send -a sigelo-watch -u critical "$1" "$2" 2>/dev/null; then echo "$stamp notified: $1" >> "$LOG"; return 0; fi
  echo "$stamp notify-send failed (no session bus?): $1" >> "$LOG"; return 1
}

# tick NAME TARGET STATEFILE PROBE: one target's run. The state file holds "up|down SINCE LASTPAGE".
rc=0
tick() {
  name=$1; target=$2; st=$3; probe=$4
  prev=up; since=$now; last=0
  [ -f "$st" ] && read -r prev since last < "$st"
  if out=$($probe 2>&1) || { sleep 20; out=$($probe 2>&1); }; then
    [ "$prev" = down ] && echo "$stamp ok again: $target after $(( (now - since) / 60 )) min down" >> "$LOG"
    echo "up $now 0" > "$st"
    return 0
  fi
  if ! is_online; then
    echo "$stamp skip: the phone is offline ($target and api.github.com unreachable); not counted" >> "$LOG"
    return 0
  fi
  rc=1
  out=$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)
  # One failing tick is not an outage: a phone on a half-working network reaches api.github.com and
  # times out on the target (2026-10-04, a false "DOWN" during a Wi-Fi hand-over). Notify from the
  # second consecutive failing tick on, i.e. after the timer interval has passed with it down.
  if [ "$prev" != down ]; then
    echo "$stamp DOWN $target (first tick, confirming next run): $out" >> "$LOG"
    echo "down $now 0" > "$st"
    return 0
  fi
  echo "$stamp DOWN $target: $out" >> "$LOG"
  if [ $((now - last)) -ge "$REPEAT" ] && notify "$name DOWN" "$target, down $(( (now - since) / 60 )) min: $out (log: $LOG)"; then last=$now; fi
  echo "down $since $last" > "$st"
}

for t in $targets; do
  case $t in
    io) tick sigelo.io "$ORIGIN" "$STATE/state" probe_io ;;
    ai) tick sigelo.ai "$RELAY_ORIGIN (relay $RELAY_HOST)" "$STATE/state-ai" probe_ai ;;
  esac
done
exit $rc
