#!/bin/sh
# SPDX-License-Identifier: MIT
# The sigelo recovery kit's air-gapped root ceremony: one script, POSIX sh (busybox ash, dash, bash).
#
#   run.sh --out <dir on removable media> --recipient <age1…> --net <mainnet|stagenet|testnet>
#          [--keepers N] [--treasury-keeper j] [--keepers-out <dir>] [--operator <name>] [--witness <name>]…
#          [--i-am-online-on-purpose]
#   run.sh --verify-paper --out <dir>      type the 25 words from the paper; checks them against fingerprint.txt
#
# What it does, in order, and refuses at the first failure with nothing written:
#   1. checks this host is offline: no IPv4 or IPv6 default route (refused otherwise, unless
#      --i-am-online-on-purpose, which the record then says);
#   2. checks node >= 22, `age` (or `rage`) and the sigelo package's `sigelo-offline`;
#   3. refuses to touch an existing root: <out> must be empty or absent. A finished ceremony
#      there (ceremony-record.json matching backup.age) is reported and nothing is generated —
#      a rerun never makes a second root;
#   4. runs `sigelo-offline ceremony --human`: the 25 words go to this terminal (/dev/tty) only,
#      never to stdout, stderr or a file; backup.age is encrypted to the Owner's age recipient;
#   5. moves backup.age + fingerprint.txt + the public output into <out>, the keeper packages
#      (plaintext keeper keys) into <keepers-out> (default <out>/keepers-move-then-shred);
#   6. writes <out>/ceremony-record.json — what, when, which host (a hash), which tools — and no
#      secret; then prints the printed procedure's checklist (procedure/CEREMONY.md).
#
# The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of
# yours — not even "for recovery". This script talks to no network and sends nothing anywhere.
set -eu

die() { code=$1; shift; printf 'kit ceremony: %s\n' "$*" >&2; exit "$code"; }
usage() { sed -n '5,8p' "$self" | sed 's/^# \{0,1\}//'; }

# This script's own directory, through npm's bin symlink if that is how it was called.
self=$0
while [ -h "$self" ]; do
	l=$(readlink "$self")
	case $l in /*) self=$l ;; *) self=$(dirname "$self")/$l ;; esac
done
here=$(cd "$(dirname "$self")" && pwd)
kit=$(dirname "$here")

out= rcpt= net= keepers=1 tk= kout= operator= witness= online_ok=0 verify=0
while [ $# -gt 0 ]; do
	case $1 in
	--out) out=${2:?--out needs a value}; shift 2 ;;
	--recipient) rcpt=${2:?--recipient needs a value}; shift 2 ;;
	--net) net=${2:?--net needs a value}; shift 2 ;;
	--keepers) keepers=${2:?--keepers needs a value}; shift 2 ;;
	--treasury-keeper) tk=${2:?--treasury-keeper needs a value}; shift 2 ;;
	--keepers-out) kout=${2:?--keepers-out needs a value}; shift 2 ;;
	--operator) operator=${2:?--operator needs a value}; shift 2 ;;
	--witness) witness="${witness:+$witness; }${2:?--witness needs a value}"; shift 2 ;;
	--i-am-online-on-purpose) online_ok=1; shift ;;
	--verify-paper) verify=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) die 2 "unknown argument $1 (the 25 words never go on the command line) — see --help" ;;
	esac
done
[ -n "$out" ] || die 2 "--out <dir> is required — see --help"
case $out in /*) ;; *) out=$(pwd)/$out ;; esac

# --- tools ------------------------------------------------------------------------------------
command -v node >/dev/null 2>&1 || die 2 "node is not on PATH (node >= 22 is required). Nothing was written."
nmajor=$(node -p 'process.versions.node.split(".")[0]')
[ "$nmajor" -ge 22 ] || die 2 "node $(node --version) is too old; node >= 22 is required. Nothing was written."
if [ -n "${SIGELO_OFFLINE:-}" ]; then
	off=$SIGELO_OFFLINE
elif off=$(node -e 'try { console.log(require.resolve("sigelo/dist/offline.js", { paths: [process.argv[1]] })) } catch { process.exit(1) }' "$kit" 2>/dev/null); then
	:
elif [ -f "$kit/../ts/dist/offline.js" ]; then
	off=$(cd "$kit/../ts/dist" && pwd)/offline.js
else
	die 2 "cannot find the sigelo package's dist/offline.js (npm install the sigelo and sigelo-recovery-kit tarballs side by side, or set SIGELO_OFFLINE). Nothing was written."
fi
[ -f "$off" ] || die 2 "$off does not exist (in a clone: npm run build in ts/). Nothing was written."
if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$1" | cut -d' ' -f1; }; else sum() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi
field() { node -e 'const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); const v = r[process.argv[2]]; console.log(v === undefined || v === null ? "" : v)' "$1" "$2"; }

# --- --verify-paper: the words on the paper reproduce fingerprint.txt -------------------------
if [ $verify = 1 ]; then
	[ -f "$out/fingerprint.txt" ] && [ -f "$out/ceremony-record.json" ] || die 2 "$out has no fingerprint.txt and ceremony-record.json — point --out at the ceremony's directory"
	vnet=$(field "$out/ceremony-record.json" net)
	vk=$(field "$out/ceremony-record.json" keepers)
	words=
	if [ -t 0 ]; then
		printf 'Type the 25 words from the paper (they are not shown), Enter after each line; Ctrl-D when done.\n' >&2
		stty -echo 2>/dev/null || true
		trap 'stty echo 2>/dev/null || true' EXIT INT TERM
	fi
	while IFS= read -r line || [ -n "$line" ]; do
		words="$words $line"
		set -f; set -- $words; set +f
		[ $# -ge 25 ] && break
	done
	[ -t 0 ] && { stty echo 2>/dev/null || true; printf '\n' >&2; }
	# printf is a shell builtin: the words travel through a pipe, never through argv (ps shows argv).
	# restore's stdout (keeper roots) is discarded; its stderr never names a typed word.
	if err=$(printf '%s\n' "$words" | node "$off" restore --words - --keepers "$vk" --fingerprint "$out/fingerprint.txt" --net "$vnet" 2>&1 >/dev/null); then
		words=
		echo "PAPER OK: the 25 words reproduce fingerprint.txt ($vnet, $vk keeper(s)). Put the paper in the vault."
		exit 0
	fi
	words=
	printf 'PAPER DOES NOT MATCH: %s\n' "$(printf '%s' "$err" | sed 's/"[^"]*"/<a typed word>/g')" >&2
	echo "Check each word against the screen copy you wrote from; a mismatch now is cheap, one found at a restore is not." >&2
	exit 1
fi

[ -n "$rcpt" ] || die 2 "--recipient <age1…> is required (the Owner's age public key: age-keygen -y <identity file>, on the Owner's own device)"
case $net in mainnet | stagenet | testnet) ;; *) die 2 "--net must be mainnet, stagenet or testnet" ;; esac
command -v age >/dev/null 2>&1 || command -v rage >/dev/null 2>&1 || die 2 "neither age nor rage is on PATH (Alpine: apk add age; Debian/Ubuntu: apt install age; macOS: brew install age). Nothing was written."

# --- offline check ----------------------------------------------------------------------------
# A default route is how a host reaches anything beyond its own links. SIGELO_KIT_NET_DIR stands
# in for /proc/net in the kit's own tests; an operator never sets it.
netdir=${SIGELO_KIT_NET_DIR:-/proc/net}
route=unknown
if [ -r "$netdir/route" ]; then
	route=none
	awk 'NR > 1 && $2 == "00000000" && $8 == "00000000" { f = 1 } END { exit !f }' "$netdir/route" && route=ipv4-default
	if [ -r "$netdir/ipv6_route" ] && awk '$1 == "00000000000000000000000000000000" && $2 == "00" && $10 != "lo" { f = 1 } END { exit !f }' "$netdir/ipv6_route"; then
		route="${route#none}"; route="${route:+$route+}ipv6-default"
	fi
elif command -v netstat >/dev/null 2>&1; then
	route=none
	netstat -rn 2>/dev/null | awk '$1 == "default" || $1 == "0.0.0.0" || $1 == "::/0" { f = 1 } END { exit !f }' && route=default
fi
offline_check=$route
case $route in
none) offline_check=no-default-route ;;
*)
	if [ $online_ok = 1 ]; then
		echo "kit ceremony: WARNING: this host is not provably offline ($route); --i-am-online-on-purpose: the record will say so." >&2
		offline_check="overridden:$route"
	elif [ "$route" = unknown ]; then
		die 2 "cannot tell whether this host is offline (no $netdir/route, no netstat). Take the network down and check by hand, then pass --i-am-online-on-purpose. Nothing was written."
	else
		die 2 "this host has a default route ($route): it is online. Take every interface down (airplane mode, unplug, ip link set <if> down) and run again. Nothing was written."
	fi
	;;
esac
swap=$(awk 'NR > 1 { printf "%s%s", (n++ ? "," : ""), ($1 ~ /zram/ ? "zram" : $2) }' /proc/swaps 2>/dev/null || true)
case ,$swap, in *,partition,* | *,file,*) echo "kit ceremony: WARNING: disk swap is on ($swap). MONERO.md §4.5: swap off or encrypted. Continue only if it is encrypted." >&2 ;; esac

# --- refuse to touch an existing root; a finished one is reported, never redone ---------------
if [ -e "$out/ceremony-record.json" ] || [ -e "$out/backup.age" ]; then
	if [ -f "$out/ceremony-record.json" ] && [ -f "$out/backup.age" ] && [ "$(field "$out/ceremony-record.json" backup_sha256)" = "$(sum "$out/backup.age")" ]; then
		echo "kit ceremony: the ceremony in $out is already done ($(field "$out/ceremony-record.json" created), fingerprint below). Nothing was generated: a second run never makes a second root." >&2
		echo "fingerprint $(cat "$out/fingerprint.txt")"
		exit 0
	fi
	die 3 "$out holds a root (backup.age or ceremony-record.json) that its record does not match. Refusing to overwrite it. If it is a failed attempt, the Owner decides what to destroy; this script never deletes a root."
fi
if [ -d "$out" ] && [ -n "$(ls -A "$out")" ]; then
	[ -e "$out/.stage" ] && die 3 "$out/.stage is an interrupted ceremony (it may hold a backup.age). Nothing was changed. The Owner inspects it and destroys it before a new ceremony; this script never deletes a root."
	die 3 "$out is not empty. Point --out at an empty or new directory on the removable medium. Nothing was written."
fi
kout=${kout:-$out/keepers-move-then-shred}
case $kout in /*) ;; *) kout=$(pwd)/$kout ;; esac
if [ -d "$kout" ] && [ -n "$(ls -A "$kout")" ]; then die 3 "$kout is not empty — refusing to mix keeper packages of two ceremonies. Nothing was written."; fi

# --- the ceremony -----------------------------------------------------------------------------
mkdir -p "$out"; chmod 700 "$out"
stage=$out/.stage
set -- ceremony --net "$net" --recipient "$rcpt" --out "$stage" --keepers "$keepers" --human
[ -n "$tk" ] && set -- "$@" --treasury-keeper "$tk"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
rc=0
node "$off" "$@" >"$out/.ceremony-public.json" || rc=$?
if [ $rc -ne 0 ]; then
	rm -f "$out/.ceremony-public.json"
	# sigelo-offline encrypts before it writes: on failure the stage is empty or absent.
	if [ -d "$stage" ] && [ -z "$(ls -A "$stage")" ]; then rmdir "$stage"; fi
	[ -e "$stage" ] || rmdir "$out" 2>/dev/null || true
	die "$rc" "sigelo-offline ceremony failed (above). ${stage}: $( [ -e "$stage" ] && echo 'left for the Owner to inspect' || echo 'nothing written')."
fi
mv "$stage/backup.age" "$stage/fingerprint.txt" "$out/"
mkdir -p "$kout"; chmod 700 "$kout"
mv "$stage"/keeper-*.json "$kout/"
rmdir "$stage"
mv "$out/.ceremony-public.json" "$out/ceremony-public.json"

# --- the record: no secret, only what, when, where, with what -----------------------------------
kitv=$(node -p 'require(process.argv[1]).version' "$kit/package.json" 2>/dev/null || echo unknown)
agev=$( (age --version 2>/dev/null || rage --version 2>/dev/null) | head -n1)
hostid=$( { cat /etc/machine-id 2>/dev/null || hostname 2>/dev/null || true; uname -srm; } | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(require("crypto").createHash("sha256").update(s).digest("hex")))')
SK_STARTED=$started SK_OFFLINE=$offline_check SK_SWAP=$swap SK_KIT=$kitv SK_AGE=$agev SK_HOST=$hostid \
SK_UNAME=$(uname -srm) SK_OFFJS=$off SK_OFFSHA=$(sum "$off") SK_BACKUP=$(sum "$out/backup.age") SK_FP=$(sum "$out/fingerprint.txt") \
SK_RCPT=$rcpt SK_KOUT=$kout SK_OPERATOR=$operator SK_WITNESS=$witness SK_TK=$tk \
	node "$here/record.mjs" "$out/ceremony-public.json" "$out/ceremony-record.json"

cat <<EOF

kit ceremony: done. In $out: backup.age, fingerprint.txt, ceremony-public.json, ceremony-record.json.
Keeper packages (PLAINTEXT keeper keys): $kout

Printed procedure, CEREMONY.md section 4 — tick each box on the paper copy:
  [ ] The 25 words are on paper, numbered 1-25, in pen, read back once. No photo, no copy typed anywhere.
  [ ] This terminal's scrollback is cleared and any recording of it stopped; the terminal is closed.
  [ ] Paper check now: sh '$self' --verify-paper --out '$out'  -> PAPER OK
  [ ] Each keeper-<j>.json moved to its keeper host by hand, then shredded here (and the directory removed).
  [ ] backup.age and fingerprint.txt copied to the second medium; the two media go to two places.
  [ ] The Owner test-decrypts backup.age later, on the Owner's own device, with the age identity:
      sigelo-offline restore --backup backup.age --identity <file> --net $net  (it checks the fingerprint).
  [ ] ceremony-record.json kept with the printed procedure. It holds no secret.
  [ ] Vault only, never a hot wallet: the 25 words never go into a mobile or desktop wallet or any networked device.
  [ ] The paper goes to the vault location today, not tomorrow.
The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours.
EOF
