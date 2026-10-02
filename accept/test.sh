#!/bin/sh
# SPDX-License-Identifier: MIT
# accept/test.sh — starts the three drop-ins' example servers (Express, Flask, net/http) on random
# loopback ports and drives each with a real sigelo agent: accept, replay, tampered sig, wrong bundle,
# rotated-away key, rotation, bare genesis, forged nonce, wrong DID. `--remote` adds the Python drop-in
# against the remote verifier https://sigelo.io/world/verify (network). Needs node, go, python3.
set -eu
here=$(cd "$(dirname "$0")" && pwd); root=$(dirname "$here")
tmp=$(mktemp -d); pids=""
trap 'for p in $pids; do kill "$p" 2>/dev/null || true; done; rm -rf "$tmp"' EXIT INT TERM
[ -f "$root/ts/dist/sigelo.js" ] || (cd "$root/ts" && npm ci --silent && npx tsc)
[ -f "$root/adapters/moadim/dist/cli.js" ] || (cd "$root/adapters/moadim" && npm ci --silent && npm run build --silent)
(cd "$here/node" && npm install --no-audit --no-fund --silent)
(cd "$root/go" && go build -o "$tmp/sigelo-verify" ./cmd/sigelo-verify)
(cd "$here/go" && go vet ./... && go build -o "$tmp/accept-example" ./example)
py=python3
if ! python3 -c 'import flask, cryptography' 2>/dev/null; then   # the one dependency (+ flask for the example), in a venv
  py="$here/.venv/bin/python"; [ -x "$py" ] || python3 -m venv "$here/.venv"
  "$py" -c 'import flask, cryptography' 2>/dev/null || PIP_DISABLE_PIP_VERSION_CHECK=1 "$py" -m pip install -q flask cryptography
fi
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
pn=$(port); (cd "$here/node" && PORT=$pn exec node example.mjs) >"$tmp/node.log" 2>&1 & pids="$pids $!"
pp=$(port); (cd "$here/python" && PORT=$pp SIGELO_VERIFY="$tmp/sigelo-verify" exec "$py" example.py) >"$tmp/py.log" 2>&1 & pids="$pids $!"
pg=$(port); PORT=$pg "$tmp/accept-example" >"$tmp/go.log" 2>&1 & pids="$pids $!"
set -- node=http://127.0.0.1:$pn python=http://127.0.0.1:$pp go=http://127.0.0.1:$pg ${1:+"$1"}
if [ "${4:-}" = --remote ]; then
  pr=$(port); (cd "$here/python" && PORT=$pr SIGELO_VERIFY=https://sigelo.io/world/verify exec "$py" example.py) >"$tmp/pyr.log" 2>&1 & pids="$pids $!"
  set -- "$1" "$2" "$3" python-remote=http://127.0.0.1:$pr
fi
node "$here/test.mjs" "$@" || { tail -n 20 "$tmp"/*.log; exit 1; }
