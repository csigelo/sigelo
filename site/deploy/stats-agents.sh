#!/bin/sh
# SPDX-License-Identifier: MIT
# site/deploy/stats-agents.sh — the agent/human split of sigelo.io's visits, as plain text for a
# phone (at most 40 lines, under 40 columns). Installed by server-setup.sh --stats as
# /usr/local/sbin/sigelo-stats-agents and run by sigelo-stats.timer every 15 minutes, after
# GoAccess, over the same window: every access log logrotate keeps (30 days).
#
#   sigelo-stats-agents [LOGDIR [OUTFILE]]   default /var/log/nginx/sigelo, /var/www/sigelo.io/stats/agents.txt
#
# Reads nginx.conf's log format sigelo_anon (fields split on the double quotes):
#   net - - [time] "METHOD PATH PROTO" status bytes "referrer host" "user agent" "accept" rtime
# Lines of the older sigelo_noip format (no network, no Accept) are counted too.
# Classes, by user agent, first match wins:
#   AI agent      ClaudeBot, Claude-User, Claude-SearchBot, anthropic-ai, GPTBot, OAI-SearchBot,
#                 ChatGPT-User, PerplexityBot, Perplexity-User, CCBot, Google-Extended, Amazonbot,
#                 Applebot-Extended, Bytespider
#   programmatic  node, undici, curl, wget, python-requests, Go-http-client (and a few kin)
#   crawler       any other bot|crawl|spider|slurp
#   browser       anything else starting Mozilla/
#   other         the rest (an empty user agent included)
# "agents" = AI agents + programmatic clients; "humans" = browsers. 301s (http->https, www and
# .net -> apex) are redirect hops, not visits: left out everywhere. Top paths count 200/304 only,
# so scanners' 404s do not crowd them. ~vis = distinct (network, user agent, day): an estimate.
# The project's own requests (user agent sigelo-selfcheck/, nginx.conf) are not visits: nginx logs
# them to access-self.log (7 days kept), read here only to print their count as "own traffic
# (excluded)"; one that still reaches access.log is counted there and left out the same way.
set -eu
LOGDIR=${1:-/var/log/nginx/sigelo}
OUT=${2:-/var/www/sigelo.io/stats/agents.txt}
tmp=$OUT.new
ls "$LOGDIR"/access.log* >/dev/null 2>&1 || { echo "sigelo-stats-agents: no logs in $LOGDIR" >&2; exit 0; }

for f in "$LOGDIR"/access.log* "$LOGDIR"/access-self.log*; do [ -f "$f" ] || continue; case $f in *.gz) gzip -dc "$f" ;; *) cat "$f" ;; esac; done | awk -F'"' -v now="$(date -u '+%Y-%m-%d %H:%M UTC')" '
function cls(ua,    u, i) {
  u = tolower(ua); name = ""
  for (i = 1; i <= nai; i++) if (index(u, tolower(ai[i]))) { name = ai[i]; return "ai" }
  if (match(u, /^(node|undici|curl|wget|python-requests|go-http-client|python-urllib|python-httpx|aiohttp|axios|node-fetch|deno|bun)([\/ ]|$)/)) {
    name = substr(ua, 1, RLENGTH); sub(/[\/ ]$/, "", name); return "prog"
  }
  if (u ~ /bot|crawl|spider|slurp/) return "crawl"
  if (u ~ /^mozilla\//) return "browser"
  return "other"
}
function top(arr, n, label,    k, best, bk, i, line) {
  print label
  for (i = 1; i <= n; i++) {
    best = 0; bk = ""
    for (k in arr) if (arr[k] > best) { best = arr[k]; bk = k }
    if (bk == "") { if (i == 1) print "  (none)"; break }
    printf "  %6d %s\n", best, substr(bk, 1, 30); delete arr[bk]
  }
}
BEGIN {
  nai = split("ClaudeBot Claude-User Claude-SearchBot anthropic-ai GPTBot OAI-SearchBot ChatGPT-User PerplexityBot Perplexity-User CCBot Google-Extended Amazonbot Applebot-Extended Bytespider", ai, " ")
  nf = split("/llms.txt /adopt.md /index.json /examples/world.mjs", fun, " ")
  for (i = 1; i <= nf; i++) isfun[fun[i]] = 1
  split("ai prog crawl browser other", order, " ")
  split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
  for (i = 1; i <= 12; i++) mon[m[i]] = sprintf("%02d", i)
  lab["ai"] = "AI agents"; lab["prog"] = "programmatic"; lab["crawl"] = "other crawlers"; lab["browser"] = "browsers"; lab["other"] = "other"
}
NF >= 7 {
  nh = split($1, h, " "); net = h[1]; day = ""
  for (i = 2; i <= nh; i++) if (substr(h[i], 1, 1) == "[") { day = substr(h[i], 9, 4) "-" mon[substr(h[i], 5, 3)] "-" substr(h[i], 2, 2); break }
  self = ($6 ~ /^sigelo-selfcheck\//)
  if (!self && (first == "" || day < first)) first = day
  split($2, r, " "); path = r[2]
  split($3, s, " "); st = s[1]
  if (st == "301") next
  if (self) { own++; next }
  ua = $6; acc = $8
  c = cls(ua)
  req[c]++; total++
  if (!((net SUBSEP ua SUBSEP day) in seen)) { seen[net, ua, day] = 1; vis[c]++; tvis++ }
  ag = (c == "ai" || c == "prog")
  if (c == "ai") byai[name]++
  if (c == "prog") byprog[name]++
  if (acc ~ /text\/markdown/) { md++; if (ag) mdag++ }
  if (path in isfun) { fall[path]++; if (ag) fag[path]++; else if (c == "browser") fhum[path]++ }
  if (st == "200" || st == "304") { if (ag) pag[path]++; else if (c == "browser") phum[path]++ }
}
END {
  printf "sigelo.io visits, %s\n", now
  printf "window: since %s (30 days kept)\n", (first == "" ? "-" : first)
  printf "%-15s %7s %6s\n", "", "req", "~vis"
  for (i = 1; i <= 5; i++) printf "%-15s %7d %6d\n", lab[order[i]], req[order[i]], vis[order[i]]
  printf "%-15s %7d %6d\n", "total", total, tvis
  printf "own traffic (excluded) %d, 7 days\n", own
  printf "Accept: text/markdown %d (agents %d)\n", md, mdag
  top(byai, 6, "AI agents by name")
  top(byprog, 4, "programmatic by client")
  printf "agent funnel   agents humans    all\n"
  for (i = 1; i <= nf; i++) printf "%-19s %4d %6d %6d\n", fun[i], fag[fun[i]], fhum[fun[i]], fall[fun[i]]
  top(pag, 5, "top paths, agents")
  top(phum, 5, "top paths, humans")
}' | head -n 40 > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$OUT"
