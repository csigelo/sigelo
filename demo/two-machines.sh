#!/bin/sh
# SPDX-License-Identifier: MIT
# demo/two-machines.sh: demo/two-machines.md on one machine. Two agents, each with its own HOME and
# identity file, and a relay on loopback at its default login rate; every node process reads one
# injected clock. alice runs sigelo-agent from its source (adapters/moadim/cli.ts), bob as step 1 of
# demo/two-machines.md installs it (npm run build: dist/cli.js); a copy laid out as npm installs it
# loads sigelo-contact beside it, and refuses a package that only takes that name's place. They
# make their recovery keys with sigelo-agent recovery-key, pair by the long code (both show the same
# pairing id and the same four words), exchange 115 messages, one of 150,000 characters and one a 500-level nested array, read
# through a pipe after a reader that went away; one is offline for a day, then rotates its key and
# reads its backlog: nothing lost, nothing readable on the relay. Then a thief copies alice's files
# and rotates: alice is locked out (exit 1, named), recovers with her recovery key, both mark the
# pairing re_pair and send nothing on it, and a short code (K7F3-Q9ZP), typed as heard, pairs them
# again: the same four words on both sides, the code good once. Exit codes: 2 with no
# identity, 3 for inbox --expect with no message. In connect.html's order: the inviter's first send
# stays queued until the invitee's agent connects, the invitee's goes at once; the thief's message
# that reaches bob with the recovery is refused (re_pair). Prints DEMO PASS, or FAIL and exits 1 at the
# first failure.
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
# later <seconds>: the clock moves on, for the relay too (its login brake counts a minute).
later() { echo $(( $(cat "$W/offset") + $1 )) > "$W/offset"; }
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
# npm run build (tsc -p tsconfig.build.json) into a copy of the package, so the tree here is
# untouched: dist/ beside the package's node_modules, where npm ci linked sigelo-contact to contact/.
CLONE="$W/clone"
mkdir -p "$CLONE/adapters/moadim"
cp "$ROOT/adapters/moadim/package.json" "$CLONE/adapters/moadim/"
ln -s "$ROOT/adapters/moadim/node_modules" "$CLONE/adapters/moadim/node_modules"
"$ROOT/adapters/moadim/node_modules/.bin/tsc" -p "$ROOT/adapters/moadim/tsconfig.build.json" --outDir "$CLONE/adapters/moadim/dist" || die "npm run build"
[ -f "$CLONE/adapters/moadim/dist/sigelo-agent-contact.js" ] || die "the build left out the contact verbs"
echo "built: dist/cli.js and dist/sigelo-agent-contact.js"
# The same build as npm installs it (node_modules/sigelo-agent) loads sigelo-contact, its dependency,
# from its own install and hands it the identity secret: only sigelo-contact at a version within
# ^<sigelo-agent's> loads. A package that only takes the name's place (here one with no version) is
# refused and must not run; with none there, the verbs say to reinstall sigelo-agent, and one at the
# right version above the install ($W/node_modules: Node's walk would reach it) is named, never run.
NM="$W/npm/node_modules"
mkdir -p "$NM/sigelo-agent" "$NM/sigelo-contact"
cp -R "$CLONE/adapters/moadim/dist" "$CLONE/adapters/moadim/package.json" "$NM/sigelo-agent/"
ln -s "$ROOT/ts" "$NM/sigelo"
echo '{"name":"sigelo-contact","type":"module"}' > "$NM/sigelo-contact/package.json"
for f in carrier kdf invite short; do echo "import{writeFileSync}from'node:fs';writeFileSync('$W/squatter-ran','x');" > "$NM/sigelo-contact/$f.mjs"; done
rc=0; on npm node "$NM/sigelo-agent/dist/cli.js" contacts > /dev/null 2> "$W/npm.err" || rc=$?
[ $rc = 1 ] && grep -q 'refusing .*sigelo-contact/package.json: "sigelo-contact" no version, not sigelo-contact ^' "$W/npm.err" && [ ! -e "$W/squatter-ran" ] || die "a package in sigelo-contact's place (exit $rc): $(cat "$W/npm.err")"
cat "$W/npm.err"
mkdir "$W/node_modules" && mv "$NM/sigelo-contact" "$W/node_modules/"
node -e 'console.log(JSON.stringify({ name: "sigelo-contact", version: require(process.argv[1]).version, type: "module" }))' \
  "$ROOT/adapters/moadim/package.json" > "$W/node_modules/sigelo-contact/package.json"
rc=0; on npm node "$NM/sigelo-agent/dist/cli.js" contacts > /dev/null 2> "$W/npm.err" || rc=$?
[ $rc = 1 ] && grep -q 'reinstall sigelo-agent' "$W/npm.err" && grep -q 'not loading .*/node_modules/sigelo-contact, outside this package' "$W/npm.err" && [ ! -e "$W/squatter-ran" ] \
  || die "no sigelo-contact, one above the install (exit $rc): $(cat "$W/npm.err")"
cat "$W/npm.err"
rm -r "$W/node_modules"
ln -s "$ROOT/contact" "$NM/sigelo-contact"
# The recovery key from the install alone, as the quick start makes it.
on npm node "$NM/sigelo-agent/dist/cli.js" init --recovery "$(on npm node "$NM/sigelo-agent/dist/cli.js" recovery-key --out "$W/npm.recovery.key" 2> /dev/null)" > /dev/null 2> "$W/npm.err" \
  || die "the npm copy: init --recovery \"\$(sigelo-agent recovery-key)\": $(cat "$W/npm.err")"
echo "the npm copy: init --recovery \"\$(sigelo-agent recovery-key --out <file>)\" works from the install alone"
rc=0; on npm node "$NM/sigelo-agent/dist/cli.js" accept sgl1x > /dev/null 2> "$W/npm.err" || rc=$?
[ $rc = 1 ] && grep -q 'code_length' "$W/npm.err" || die "the npm copy with sigelo-contact (exit $rc): $(cat "$W/npm.err")"
echo "the npm copy, sigelo-contact beside it: accept reads the code ($(cat "$W/npm.err"))"

# Two machines. agent = sigelo-agent, the contact verbs included: alice's from its source, bob's the
# build above.
agent() {
  who=$1; shift
  if [ "$who" = bob ]; then on bob js "$CLONE/adapters/moadim/dist/cli.js" "$@"; else on "$who" js "$ROOT/adapters/moadim/cli.ts" "$@"; fi
}
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

step "two agents, one identity each, each recovery key made by sigelo-agent recovery-key"
# No identity yet: a contact verb says so and exits 2.
rc=0; agent alice invite --name bob > /dev/null 2> "$W/none.err" || rc=$?
[ $rc = 2 ] && grep -q 'no identity: run sigelo-agent init' "$W/none.err" || die "invite with no identity (exit $rc): $(cat "$W/none.err")"
# The secret goes to a 0600 file (offline, on a real machine); stdout is the public key alone.
agent alice init --recovery "$(agent alice recovery-key --out "$W/alice.recovery.key" 2> /dev/null)" > /dev/null 2>&1 || die "alice's init with recovery-key"
agent bob init --recovery "$(agent bob recovery-key --out "$W/bob.recovery.key" 2> /dev/null)" > /dev/null 2>&1 || die "bob's init with recovery-key"
grep -qE '^[0-9a-f]{64}$' "$W/alice.recovery.key" && node -e 'process.exit((require("fs").statSync(process.argv[1]).mode & 0o777) === 0o600 ? 0 : 1)' "$W/alice.recovery.key" \
  || die "the recovery key file is not 64 hex digits, 0600"
agent alice whoami | get genesis.recovery | grep -qE '^sha256:[0-9a-f]{64}$' || die "alice's genesis carries no recovery commitment"
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

step "alice makes a long code; bob accepts it while alice's agent is offline"
# Her first login proves work: one line says so before, one after. stdout: the code alone (--long:
# the one-line code for agent channels; --json: both codes, its DID, relay and expiry).
CODE=$(agent alice invite --long --name bob 2> "$W/invite.err")
grep -q 'proof of work for a new identity: 5–60 s' "$W/invite.err" && grep -q 'proof of work done in' "$W/invite.err" || die "the first invite's progress lines: $(cat "$W/invite.err")"
echo "$CODE" | grep -qE '^sgl1[1-9A-HJ-NP-Za-km-z]+$' && grep -q 'one-time code, good until' "$W/invite.err" || die "invite does not print the bare code: $CODE"
cat "$W/invite.err"
echo "code: $CODE"
agent alice invite --name nobody --ttl 60 --json > "$W/invite.json" 2> /dev/null || die "invite --json"
[ "$(get did < "$W/invite.json")" = "$A0" ] && get short < "$W/invite.json" | grep -qE '^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$' && get code < "$W/invite.json" | grep -q '^sgl1' \
  || die "invite --json: $(cat "$W/invite.json")"
# accept names the code's DID before it connects. carol's relay cannot be reached: her answer stays
# queued (she never connects again) and accept fails, having said whom the code names. node, not
# agent: an assignment before a shell function may outlive the call.
agent carol init --recovery "$(agent carol recovery-key --out "$W/carol.recovery.key" 2> /dev/null)" > /dev/null 2>&1
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

step "connect.html's order: alice's inbox pairs; her first send waits for bob's agent, his goes at once"
agent alice inbox > /dev/null   # alice: checks bob's answer offline, replies
# Bob's mailbox for the pairing needs the key her reply carries: until his agent reads it, nobody
# holds it (no_reader). Her message stays queued with her (exit 0), and goes at her next inbox.
agent alice send bob "hello 1" > "$W/first.json" 2> "$W/first.err" || die "alice's first send: $(cat "$W/first.err")"
[ "$(get status < "$W/first.json")" = queued ] && grep -q "send: queued, not yet at the relay: bob's agent does not hold its mailbox" "$W/first.err" || die "alice's first send: $(cat "$W/first.err")"
cat "$W/first.err"
# His first send reads her reply first (paired), then goes.
agent bob send alice "hi 1" | grep -q '"status": "sent"' || die "bob's first send after accept"
agent alice inbox > "$W/inbox.json"; messages "$W/inbox.json" "hi" 1 || die "alice's inbox: bob's first"
agent bob inbox > "$W/inbox.json"; messages "$W/inbox.json" "hello" 1 || die "bob's inbox: alice's first, kept and sent"
echo "bob's arrived at once; alice's went at her next inbox"
[ "$(agent alice contacts | get contacts.0.did)" = "$B" ] || die "alice's contact is not bob"
[ "$(agent bob contacts | get contacts.0.did)" = "$A0" ] || die "bob's contact is not alice"
echo "alice knows bob as $(agent alice contacts | get contacts.0.name), bob knows alice as $(agent bob contacts | get contacts.0.name)"
# What the two operators read to each other: one id, from the pairing key both hold.
PAIR=$(agent alice contacts | get contacts.0.pair)
echo "$PAIR" | grep -qE '^[0-9a-f]{32}$' && [ "$(agent bob contacts | get contacts.0.pair)" = "$PAIR" ] || die "the pairing ids differ"
echo "both show pairing id $PAIR"
WORDS=$(agent alice contacts 2> /dev/null | get contacts.0.fingerprint)
echo "$WORDS" | grep -qE '^[a-z]+ [a-z]+ [a-z]+ [a-z]+$' && [ "$(agent bob contacts 2> /dev/null | get contacts.0.fingerprint)" = "$WORDS" ] || die "the four words differ"
agent bob contacts 2>&1 > /dev/null | grep -qF "alice: Check with them: $WORDS" || die "contacts does not say the four words"
echo "both say: Check with them: $WORDS"

step "50 messages from alice to bob, 50 back"
lines "alice to bob" 50 | agent alice send bob - --lines > "$W/sent.json"; sent "$W/sent.json" 50 || die "alice's 50 sends"
agent bob inbox > "$W/inbox.json"; messages "$W/inbox.json" "alice to bob" 50 || die "bob's inbox"
lines "bob to alice" 50 | agent bob send alice - --lines > "$W/sent.json"; sent "$W/sent.json" 50 || die "bob's 50 sends"
agent alice inbox > "$W/inbox.json"; messages "$W/inbox.json" "bob to alice" 50 || die "alice's inbox"
echo "100 delivered, in order"
# --expect: with nothing new, inbox exits 3; without it, 0.
rc=0; agent alice inbox --expect > /dev/null 2> "$W/expect.err" || rc=$?
[ $rc = 3 ] && grep -q 'no message came (--expect)' "$W/expect.err" || die "inbox --expect with nothing new (exit $rc): $(cat "$W/expect.err")"
echo "inbox --expect with nothing new: exit 3"

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

step "a thief copies alice's files and rotates: alice is locked out"
later 120
cp -R "$W/alice" "$W/thief"
agent thief rotate > /dev/null 2>&1
agent thief send bob "from the thief" | grep -q '"status": "sent"' || die "the thief's send"
rc=0; agent alice inbox --wait 1 > "$W/locked.json" 2> "$W/locked.err" || rc=$?
[ $rc = 1 ] && grep -q '^sigelo-agent: inbox: offline: bundle: ' "$W/locked.err" && grep -q 'Locked out' "$W/locked.err" && [ -n "$(get offline < "$W/locked.json")" ] \
  || die "alice locked out (exit $rc): $(cat "$W/locked.err")"
cat "$W/locked.err"

step "alice recovers with her recovery key; both sides stop using the stolen pairing key"
agent alice recover --recovery-key "$W/alice.recovery.key" > "$W/recover.json" 2> "$W/recover.err" || die "recover: $(cat "$W/recover.err")"
A1=$(get did < "$W/recover.json")
[ "$A1" != "$A0" ] && [ "$(agent alice whoami | get did)" = "$A1" ] || die "no recovery rotation"
echo "alice is now $A1"
[ "$(agent alice contacts 2> /dev/null | get contacts.0.re_pair)" = own_recovery ] || die "alice's contact is not marked re_pair"
rc=0; agent alice send bob "under the stolen key" > /dev/null 2> "$W/repair.err" || rc=$?
[ $rc = 1 ] && grep -q 're_pair: ' "$W/repair.err" || die "a send under the burned key (exit $rc): $(cat "$W/repair.err")"
agent alice inbox > /dev/null || die "alice's inbox after the recovery"   # her notice: the relay and bob follow the recovery
rc=0; agent thief send bob "thief again" > /dev/null 2> "$W/thief.err" || rc=$?
[ $rc = 1 ] && grep -q 'Locked out' "$W/thief.err" || die "the thief after the recovery (exit $rc): $(cat "$W/thief.err")"
echo "the thief is locked out now"
# The thief's message, written before alice recovered, reaches bob in the same inbox as her
# recovery: signed by a key the recovery overruled, it is refused, not delivered as hers.
agent bob inbox > "$W/inbox.json" 2> "$W/bob.err" || die "bob's inbox after the recovery: $(cat "$W/bob.err")"
! grep -q 'from the thief' "$W/inbox.json" && grep -q '"code": "re_pair"\|"code":"re_pair"' "$W/inbox.json" && grep -q 'message(s) from alice refused (re_pair)' "$W/bob.err" \
  || die "the thief's message after the recovery: $(cat "$W/inbox.json" "$W/bob.err")"
[ "$(agent bob contacts 2> /dev/null | get contacts.0.current_did)" = "$A1" ] && [ "$(agent bob contacts 2> /dev/null | get contacts.0.re_pair)" = contact_recovery ] \
  || die "bob did not follow the recovery, or does not mark alice re_pair"
echo "bob follows the recovery, refuses the thief's message (re_pair) and marks alice re_pair; neither sends on the old pairing key"

step "a short code, said on the phone, pairs them again"
later 120
# The default: a short code, 10 minutes, once. Bob's operator types it as heard: lowercase, a space
# for the dash, O for zero.
SHORT=$(agent alice invite --name bob 2> "$W/invite.err")
echo "$SHORT" | grep -qE '^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$' && grep -q "say it, text it or write it down: good for 10 minutes" "$W/invite.err" || die "invite does not print a short code: $SHORT $(cat "$W/invite.err")"
cat "$W/invite.err"
HEARD=$(echo "$SHORT" | tr 'A-Z0-' 'a-zo ')
agent bob accept $HEARD --name alice --wait 1 > /dev/null 2> "$W/accept.err" || die "bob's accept of the short code \"$HEARD\": $(cat "$W/accept.err")"
grep -qF "the code names $A1" "$W/accept.err" || die "accept of the short code does not show alice's DID: $(cat "$W/accept.err")"
echo "bob typed \"$HEARD\": $(head -1 "$W/accept.err")"
rc=0; agent carol accept "$SHORT" --wait 1 > /dev/null 2> "$W/carol.err" || rc=$?
[ $rc = 1 ] && grep -q 'park_unknown' "$W/carol.err" || die "the short code a second time (exit $rc): $(cat "$W/carol.err")"
echo "the same code again: $(cat "$W/carol.err")"
agent alice inbox > /dev/null 2> "$W/alice.err"; agent bob inbox > /dev/null; agent alice inbox > /dev/null
WORDS2=$(agent bob contacts 2> /dev/null | get contacts.0.fingerprint)
grep -qF "paired with bob. Check with them: $WORDS2" "$W/alice.err" && [ "$(agent alice contacts 2> /dev/null | get contacts.0.fingerprint)" = "$WORDS2" ] && [ "$WORDS2" != "$WORDS" ] \
  || die "the four words after the short code: $WORDS2; $(cat "$W/alice.err")"
echo "alice's inbox: $(cat "$W/alice.err")"
CODE2=$(echo "$SHORT" | tr -d -)
[ "$(agent alice contacts 2> /dev/null | get contacts.0.re_pair)" = null ] && [ "$(agent bob contacts 2> /dev/null | get contacts.0.re_pair)" = null ] || die "still re_pair after pairing again"
PAIR2=$(agent alice contacts | get contacts.0.pair)
[ "$PAIR2" != "$PAIR" ] && [ "$(agent bob contacts | get contacts.0.pair)" = "$PAIR2" ] || die "the new pairing ids"
agent alice send bob "after the recovery 1" | grep -q '"status": "sent"' || die "send after pairing again"
agent bob inbox --wait 5 --expect > "$W/inbox.json" || die "bob's inbox --expect after pairing again"
messages "$W/inbox.json" "after the recovery" 1 && [ "$(get messages.0.current_did < "$W/inbox.json")" = "$A1" ] || die "bob's inbox after pairing again"
echo "both show the new pairing id $PAIR2 and the same four words; alice's message reaches bob, signed by her recovered key"

step "what the relay saw, over the whole run"
blind "$W" any "$A0" "$A1" "$B" "$B1" "$CODE" "$SHORT" "$CODE2" "$PAIR" "$PAIR2" "alice to bob" "bob to alice" "while you were away" "after the rotation" "got it" "from the thief" "after the recovery" || die "the relay is not blind"
grep -qE 'did:sigelo|[mi]/[0-9a-f]{32}' "$W/relay.log" && die "the relay's log names a DID or a topic"
echo "its log: $(grep -c '^login' "$W/relay.log") logins, addresses cut to /24, no DID, no topic"

printf '\nDEMO PASS\n'
