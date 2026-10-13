#!/bin/sh
# SPDX-License-Identifier: MIT
# demo/two-machines.sh: demo/two-machines.md on one machine. Two agents, each with its own HOME and
# identity file, and a relay on loopback at its default login rate; every node process reads one
# injected clock. alice runs sigelo-agent from its source (adapters/moadim/cli.ts), bob as step 1 of
# demo/two-machines.md installs it (npm run build: dist/cli.js); a copy installed from npm refuses
# the contact verbs. They pair by code (both show the same pairing id), exchange 115 messages, one
# of 150,000 characters and one a 500-level nested array, read through a pipe after a reader that
# went away; one is offline for a day, then rotates its key and reads its backlog: nothing lost,
# nothing readable on the relay. Prints DEMO PASS, or FAIL and exits 1 at the first failure.
#   sh demo/two-machines.sh        (needs ts/ built and npm ci in contact/, relay/, adapters/moadim/)
# The relay: SIGELO_RELAY_DIR, else relay/ here (it is its own AGPL repository once exported).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RELAY_DIR=${SIGELO_RELAY_DIR:-$ROOT/relay}
[ -f "$RELAY_DIR/server.mjs" ] || { echo "FAIL no relay at $RELAY_DIR: clone the relay and set SIGELO_RELAY_DIR" >&2; exit 1; }
W=$(mktemp -d)
RELAY_PID=
cleanup() { if [ -n "$RELAY_PID" ]; then kill "$RELAY_PID" 2>/dev/null || true; fi; rm -rf "$W"; }
trap cleanup EXIT INT TERM

# The clock: real time plus the seconds written in $W/offset, for every node process below, the
# relay included. Writing 86400 there is "a day later".
echo 0 > "$W/offset"
export DEMO_OFFSET="$W/offset"
CLOCK='data:text/javascript,import{readFileSync}from"node:fs";const n=Date.now;Date.now=()=>n()+1000*Number(readFileSync(process.env.DEMO_OFFSET,"utf8"))'
js() { node --import "$CLOCK" "$@"; }
die() { echo "FAIL $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
# get <path>: one field of the JSON on stdin (a.b.0.c), strings bare.
get() { node -e 'let s="";process.stdin.on("data",(d)=>{s+=d}).on("end",()=>{let v=JSON.parse(s);for(const k of process.argv[1].split("."))v=v?.[k];process.stdout.write(typeof v==="string"?v:JSON.stringify(v)??"")})' "$1"; }

step "a relay on loopback (relay/server.mjs, its own environment variables)"
# It takes no new identity once the disk holding $W is 70 % full (relay_full). Its login rate is
# the default, 30 a minute per network: each verb below logs in once, both agents share 127.0.0.1,
# so the 50-message batches go as one `send --lines` each (about 16 logins in the whole run).
RELAY_HOST=relay.demo RELAY_DB="$W/relay.db" RELAY_TCP_PORT=0 RELAY_HTTP_PORT=0 \
  RELAY_POW_BITS=12 RELAY_FREE_QUEUE_MB=64 js "$RELAY_DIR/server.mjs" > "$W/relay.log" 2>&1 &
RELAY_PID=$!
i=0
until grep -q '^sigelo relay:' "$W/relay.log" 2>/dev/null; do
  i=$((i + 1)); [ $i -le 100 ] || { cat "$W/relay.log" >&2; die "the relay did not start"; }; sleep 0.1
done
head -1 "$W/relay.log"
MQTT=$(sed -n 's/.*tcp 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$W/relay.log")
HTTP=$(sed -n 's/.*http 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$W/relay.log")
# What a real agent needs is SIGELO_RELAY alone (MQTT over TLS on 8883, HTTPS on 443); a relay on
# loopback without TLS is named by its two addresses.
export SIGELO_RELAY=relay.demo
export SIGELO_RELAY_ENDPOINTS="{\"relay.demo\":{\"mqtt\":\"mqtt://127.0.0.1:$MQTT\",\"http\":\"http://127.0.0.1:$HTTP\"}}"

# on <who> <command>: one machine, a HOME and an identity file of its own.
on() { who=$1; shift; HOME="$W/$who" SIGELO_IDENTITY="$W/$who/.config/moadim/sigelo.local.json" "$@"; }

step "the install: sigelo-agent built as demo/two-machines.md step 1 builds it"
# npm run build (tsc -p tsconfig.build.json) into a copy of the clone's layout, so the tree here is
# untouched: dist/ beside the package's node_modules, contact/ two levels up.
CLONE="$W/clone"
mkdir -p "$CLONE/adapters/moadim"
cp "$ROOT/adapters/moadim/package.json" "$CLONE/adapters/moadim/"
ln -s "$ROOT/adapters/moadim/node_modules" "$CLONE/adapters/moadim/node_modules"
ln -s "$ROOT/contact" "$CLONE/contact"
"$ROOT/adapters/moadim/node_modules/.bin/tsc" -p "$ROOT/adapters/moadim/tsconfig.build.json" --outDir "$CLONE/adapters/moadim/dist" || die "npm run build"
[ -f "$CLONE/adapters/moadim/dist/sigelo-agent-contact.js" ] || die "the build left out the contact verbs"
echo "built: dist/cli.js and dist/sigelo-agent-contact.js"
# The same build installed from npm (node_modules/sigelo-agent) refuses the contact verbs and never
# loads a package named sigelo-contact: that name is not published, and whoever registered it would
# be handed the identity secret. Here a squatter is installed beside it, and must not run.
NM="$W/npm/node_modules"
mkdir -p "$NM/sigelo-agent" "$NM/sigelo-contact"
cp -R "$CLONE/adapters/moadim/dist" "$CLONE/adapters/moadim/package.json" "$NM/sigelo-agent/"
ln -s "$ROOT/ts" "$NM/sigelo"
echo '{"name":"sigelo-contact","type":"module"}' > "$NM/sigelo-contact/package.json"
for f in carrier kdf; do echo "import{writeFileSync}from'node:fs';writeFileSync('$W/squatter-ran','x');" > "$NM/sigelo-contact/$f.mjs"; done
rc=0; on npm node "$NM/sigelo-agent/dist/cli.js" contacts > /dev/null 2> "$W/npm.err" || rc=$?
[ $rc = 1 ] && grep -q 'not in the npm release' "$W/npm.err" && [ ! -e "$W/squatter-ran" ] || die "the npm copy (exit $rc): $(cat "$W/npm.err")"
cat "$W/npm.err"
# Nor does a copy of the build outside adapters/moadim of a clone: an npm tarball unpacked with tar
# at <shared>/x/package would load <shared>/contact, which whoever can write <shared> plants.
mkdir -p "$W/shared/x/package" "$W/shared/contact"
cp -R "$CLONE/adapters/moadim/dist" "$CLONE/adapters/moadim/package.json" "$W/shared/x/package/"
ln -s "$ROOT/adapters/moadim/node_modules" "$W/shared/x/package/node_modules"
echo '{"name":"sigelo-contact","type":"module"}' > "$W/shared/contact/package.json"
for f in carrier kdf invite; do echo "import{writeFileSync}from'node:fs';writeFileSync('$W/plant-ran','x');" > "$W/shared/contact/$f.mjs"; done
rc=0; on npm node "$W/shared/x/package/dist/cli.js" contacts > /dev/null 2> "$W/plant.err" || rc=$?
[ $rc = 1 ] && grep -q 'run from adapters/moadim of a clone' "$W/plant.err" && [ ! -e "$W/plant-ran" ] || die "a copy outside adapters/moadim (exit $rc): $(cat "$W/plant.err")"
# A clone without contact/ says what is missing, and exits 1.
mkdir -p "$W/bare/adapters/moadim"
cp -R "$CLONE/adapters/moadim/dist" "$CLONE/adapters/moadim/package.json" "$W/bare/adapters/moadim/"
ln -s "$ROOT/adapters/moadim/node_modules" "$W/bare/adapters/moadim/node_modules"
rc=0; on bare node "$W/bare/adapters/moadim/dist/cli.js" contacts > /dev/null 2> "$W/bare.err" || rc=$?
[ $rc = 1 ] && grep -q 'need contact/ of this clone' "$W/bare.err" || die "a clone without contact/ (exit $rc): $(cat "$W/bare.err")"

# Two machines. agent = sigelo-agent, the contact verbs included: alice's from its source, bob's the
# build above.
agent() {
  who=$1; shift
  if [ "$who" = bob ]; then on bob js "$CLONE/adapters/moadim/dist/cli.js" "$@"; else on "$who" js "$ROOT/adapters/moadim/cli.ts" "$@"; fi
}
recovery() { node --input-type=module -e "import { keygen } from '$ROOT/ts/dist/sigelo.js'; console.log(keygen({ recovery: new Uint8Array(32) }).key)"; }
# lines <prefix> <n>: "<prefix> 1" … "<prefix> n", one a line.
lines() { n=1; while [ $n -le "$2" ]; do echo "$1 $n"; n=$((n + 1)); done; }
# sent <file> <n>: send --lines printed n results, every one "sent".
sent() { [ "$(grep -c '"status": "sent"' "$1")" = "$2" ] && [ "$(grep -c '"status"' "$1")" = "$2" ]; }
# messages <file> <prefix> <n>: the inbox in <file> holds exactly <prefix> 1 … <prefix> n, in order.
messages() {
  node -e 'const [f, p, n] = process.argv.slice(1), m = JSON.parse(require("fs").readFileSync(f, "utf8")).messages.map((x) => x.content);
    const want = Array.from({ length: Number(n) }, (_, i) => `${p} ${i + 1}`);
    if (m.join("\n") !== want.join("\n")) { console.error(`got ${m.length}: ${m.slice(0, 3).join(" | ")} …`); process.exit(1); }' "$@"
}

step "two agents, one identity each (recovery keys made offline, here thrown away)"
agent alice init --recovery "$(recovery)" > /dev/null 2>&1
agent bob init --recovery "$(recovery)" > /dev/null 2>&1
A0=$(agent alice whoami | get did)
B=$(agent bob whoami | get did)
echo "alice $A0"
echo "bob   $B"
# --wait bounds a session, refused by name before anything connects.
rc=0; agent bob inbox --wait 301 > /dev/null 2> "$W/wait.err" || rc=$?
[ $rc = 1 ] && grep -q -- '--wait: whole seconds, 0 to 300' "$W/wait.err" || die "inbox --wait 301 (exit $rc): $(cat "$W/wait.err")"
# So is a flag the verb does not take (usage, exit 2): a mistyped --wiat must not run inbox at once.
rc=0; agent bob inbox --wiat 30 > /dev/null 2> "$W/flag.err" || rc=$?
[ $rc = 2 ] && grep -q -- 'inbox: unknown flag --wiat' "$W/flag.err" || die "inbox --wiat 30 (exit $rc): $(cat "$W/flag.err")"

step "alice makes a code; bob accepts it while alice's agent is offline"
CODE=$(agent alice invite --name bob | get code)
echo "code: $CODE"
# accept names the code's DID before it connects. carol's relay cannot be reached: her answer stays
# queued (she never connects again) and accept fails, having said whom the code names. node, not
# agent: an assignment before a shell function may outlive the call.
agent carol init --recovery "$(recovery)" > /dev/null 2>&1
rc=0; HOME="$W/carol" SIGELO_IDENTITY="$W/carol/.config/moadim/sigelo.local.json" SIGELO_RELAY_ENDPOINTS='{"relay.demo":{"mqtt":"mqtt://127.0.0.1:1","http":"http://127.0.0.1:1"}}' \
  node --import "$CLOCK" "$ROOT/adapters/moadim/cli.ts" accept "$CODE" --wait 1 > /dev/null 2> "$W/carol.err" || rc=$?
[ $rc = 1 ] && grep -qF "the code names $A0" "$W/carol.err" || die "accept with the relay unreachable (exit $rc): $(cat "$W/carol.err")"
# Pasted as a mail client wraps it: accept drops the whitespace, which no code contains.
WRAPPED=$(printf '%s\n  %s' "$(echo "$CODE" | cut -c1-64)" "$(echo "$CODE" | cut -c65-)")
agent bob accept "$WRAPPED" --name alice --wait 1 > "$W/accept.json" 2> "$W/accept.err" || die "accept: $(cat "$W/accept.err")"
[ "$(get status < "$W/accept.json")" = waiting ] || die "accept: not waiting"
# What bob's operator checks with alice's: the DID the code names.
grep -qF "the code names $A0" "$W/accept.err" || die "accept does not show the code's DID: $(cat "$W/accept.err")"
cat "$W/accept.err"
echo "bob: answer delivered, waiting for alice"

step "each side's next connection completes the pairing"
agent alice inbox > /dev/null   # alice: checks bob's answer offline, replies
agent bob inbox > /dev/null     # bob: checks alice's reply, sends his prekeys
agent alice inbox > /dev/null   # alice: bob's prekeys
[ "$(agent alice contacts | get contacts.0.did)" = "$B" ] || die "alice's contact is not bob"
[ "$(agent bob contacts | get contacts.0.did)" = "$A0" ] || die "bob's contact is not alice"
echo "alice knows bob as $(agent alice contacts | get contacts.0.name), bob knows alice as $(agent bob contacts | get contacts.0.name)"
# What the two operators read to each other: one id, from the pairing key both hold.
PAIR=$(agent alice contacts | get contacts.0.pair)
echo "$PAIR" | grep -qE '^[0-9a-f]{32}$' && [ "$(agent bob contacts | get contacts.0.pair)" = "$PAIR" ] || die "the pairing ids differ"
echo "both show pairing id $PAIR"

step "50 messages from alice to bob, 50 back"
lines "alice to bob" 50 | agent alice send bob - --lines > "$W/sent.json"; sent "$W/sent.json" 50 || die "alice's 50 sends"
agent bob inbox > "$W/inbox.json"; messages "$W/inbox.json" "alice to bob" 50 || die "bob's inbox"
lines "bob to alice" 50 | agent bob send alice - --lines > "$W/sent.json"; sent "$W/sent.json" 50 || die "bob's 50 sends"
agent alice inbox > "$W/inbox.json"; messages "$W/inbox.json" "bob to alice" 50 || die "alice's inbox"
echo "100 delivered, in order"

step "three more: terminal controls, 150,000 characters, a nested array; bob reads them through a pipe"
# As an agent harness reads it: past 64 KiB, an exit before stdout drained cut the inbox, whose
# messages were already taken from the state file. And what a contact writes must not reach the
# operator's terminal as C1 or bidi controls: escaped, the JSON keeps its value.
node -e 'process.stdout.write("hi \u009b2J\u009d0;all clear\u009c \u202eevil\n" + "x".repeat(150000) + "\n")' | agent alice send bob - --lines > "$W/sent.json"; sent "$W/sent.json" 2 || die "alice's two"
# A message's content is any JSON. Indented, 500 levels printed as half a megabyte; a few such
# messages passed V8's string limit, and the inbox, already taken, was lost.
on alice js --input-type=module -e "
  import { Carrier, pathsFor, optionsFromEnv } from '$ROOT/contact/carrier.mjs';
  import { load, secretOf, bundleOf } from '$ROOT/adapters/moadim/sigelo-agent.ts';
  const f = process.env.SIGELO_IDENTITY; let a = []; for (let i = 1; i < 500; i++) a = [a];
  const c = new Carrier({ identity: () => { const s = load(f); return { secret: secretOf(s), bundle: bundleOf(s) }; }, ...pathsFor(f), ...optionsFromEnv() });
  const [r] = await c.sendAll('bob', [a], { label: '' }); if (r.status !== 'sent') { console.error(JSON.stringify(r)); process.exit(1); }" || die "alice's nested message"
# A reader that goes away (head): the inbox did not arrive, so it is kept beside bob's identity
# (0600) for his next inbox.
{ rc=0; agent bob inbox 2> "$W/epipe.err" || rc=$?; echo $rc > "$W/epipe.rc"; } | head -c 100 > /dev/null
[ "$(cat "$W/epipe.rc")" = 1 ] && grep -q 'kept for the next inbox' "$W/epipe.err" || die "an inbox whose reader went away (exit $(cat "$W/epipe.rc")): $(cat "$W/epipe.err")"
HELD="$W/bob/.config/moadim/sigelo.local.held.json"
node -e 'process.exit((require("fs").statSync(process.argv[1]).mode & 0o777) === 0o600 ? 0 : 1)' "$HELD" || die "the held inbox is not 0600"
cat "$W/epipe.err"
agent bob inbox | node -e 'let s="";process.stdin.setEncoding("utf8").on("data",(d)=>{s+=d}).on("end",()=>{
  const m = JSON.parse(s).messages.map((x) => x.content);
  let a = []; for (let i = 1; i < 500; i++) a = [a];
  if (/[\u0080-\u009f\u202a-\u202e]/.test(s)) { console.error("raw C1 or bidi controls on stdout"); process.exit(1); }
  if (s.length > 160000) { console.error(`${s.length} characters on stdout`); process.exit(1); }
  if (m.length !== 3 || m[0] !== "hi \u009b2J\u009d0;all clear\u009c \u202eevil" || m[1] !== "x".repeat(150000) || JSON.stringify(m[2]) !== JSON.stringify(a)) { console.error(`got ${m.length} messages`); process.exit(1); } })' || die "bob's inbox through a pipe"
[ ! -e "$HELD" ] || die "the held inbox is still there"
echo "all three arrived whole, compact, the controls escaped"

step "bob's agent is offline for a day; alice writes ten"
echo 86400 > "$W/offset"
lines "while you were away" 10 | agent alice send bob - --lines > "$W/sent.json"; sent "$W/sent.json" 10 || die "the sends while bob is away"

step "the relay holds ten envelopes for bob and can read none"
# Its database, WAL and log, as bytes: no DID, no text, no invite code, no pairing id; only random topics.
blind() {
  node --input-type=module -e '
    import { readFileSync, existsSync } from "node:fs";
    import { DatabaseSync } from "node:sqlite";
    const [dir, queued, ...secrets] = process.argv.slice(1);
    const files = ["relay.db", "relay.db-wal", "relay.log"].map((f) => `${dir}/${f}`).filter(existsSync);
    const raw = Buffer.concat(files.map((f) => readFileSync(f)));
    const found = secrets.filter((s) => raw.includes(Buffer.from(s)));
    const db = new DatabaseSync(`${dir}/relay.db`, { readOnly: true });
    const topics = db.prepare("SELECT topic FROM claims").all().map((r) => r.topic);
    const n = db.prepare("SELECT count(*) AS n FROM messages").get().n;
    console.log(`files: ${files.length}, topics held: ${topics.length}, envelopes queued: ${n}, secrets found: ${found.length}`);
    if (found.length || !topics.every((t) => /^[mi]\/[0-9a-f]{32}$/.test(t)) || (queued !== "any" && n !== Number(queued))) process.exit(1);' "$@"
}
blind "$W" 10 "$A0" "$B" "$CODE" "$PAIR" "alice to bob" "bob to alice" "while you were away" || die "the relay is not blind"

step "bob, still offline, rotates his key; then he is back and reads the ten"
agent bob rotate > /dev/null 2>&1
B1=$(agent bob whoami | get did)
[ "$B1" != "$B" ] || die "no rotation"
echo "bob is now $B1"
agent bob inbox > "$W/inbox.json"; messages "$W/inbox.json" "while you were away" 10 || die "bob's inbox after a day and a rotation"
echo "all ten delivered, in order, to his new key"

step "bob writes under his new key; alice follows the rotation"
agent bob send alice "after the rotation 1" | grep -q '"status": "sent"' || die "send after the rotation"
agent alice inbox > "$W/inbox.json"; messages "$W/inbox.json" "after the rotation" 1 || die "alice's inbox after the rotation"
[ "$(get messages.0.from < "$W/inbox.json")" = "$B" ] && [ "$(get messages.0.current_did < "$W/inbox.json")" = "$B1" ] || die "the message is not from bob's new key"
[ "$(agent alice contacts | get contacts.0.current_did)" = "$B1" ] || die "alice's contact did not follow the rotation"
echo "alice: from $B, now signed by $B1"
agent alice send bob "got it 1" | grep -q '"status": "sent"' || die "alice's answer"
agent bob inbox > "$W/inbox.json"; messages "$W/inbox.json" "got it" 1 || die "bob's inbox after the rotation"
echo "and alice's answer reaches his new key"

step "what the relay saw, over the whole run"
blind "$W" any "$A0" "$B" "$B1" "$CODE" "$PAIR" "alice to bob" "bob to alice" "while you were away" "after the rotation" "got it" || die "the relay is not blind"
grep -qE 'did:sigelo|[mi]/[0-9a-f]{32}' "$W/relay.log" && die "the relay's log names a DID or a topic"
echo "its log: $(grep -c '^login' "$W/relay.log") logins, addresses cut to /24, no DID, no topic"

printf '\nDEMO PASS\n'
