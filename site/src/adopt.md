---
title: Adopt: create a DID for your AI agent
description: Exact commands: install sigelo, make an agent DID with a recovery key, answer a challenge, build a bundle, verify it offline. Or use the MCP server.
---
# Adopt: create a DID for your AI agent

Give your AI agent its own ID (a DID), step by step.

Node ≥ 22.18, POSIX shell. Download `sigelo-verify` and `SHA256SUMS` from [/releases/{{release_tag}}/]({{release_url}}) into `$d`.

```sh
mkdir my-agent && cd my-agent && npm init -y >/dev/null
npm install sigelo@{{version}} sigelo-agent@{{version}}
export PATH="$PWD/node_modules/.bin:$PATH" SIGELO_IDENTITY="$PWD/agent.local.json"
v=$d/sigelo-verify-linux-amd64           # or linux-arm64, darwin-amd64, darwin-arm64, windows-amd64.exe
(cd $d && grep " ${v##*/}\$" SHA256SUMS | sha256sum -c -)                  # prints OK
```

## 1. Identity

Recovery key, to take the ID back after a theft, chosen first: none (`--no-recovery`; a theft is then permanent), the operator's `sha256:…` commitment, or a dedicated key pair kept offline (below).

```sh
sigelo-agent init --recovery "$(sigelo-agent recovery-key)"   # writes recovery.key and recovery.pub
sigelo-agent whoami | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.stringify(JSON.parse(s).genesis)))' > agent-genesis.json
```

Keep `recovery.key` and `recovery.pub` off the agent's host.

## 2. Answer a challenge

A platform (a "world") sends `challenge.json`; you sign it; it answers with `issued.json`, a signed statement about you (an attestation). No world? Run the [mock world](/examples/world.mjs) here:

```sh
node -e 'fetch("https://sigelo.io/examples/world.mjs").then(r=>r.text()).then(t=>require("fs").writeFileSync("world.mjs",t))'
node world.mjs challenge agent-genesis.json > challenge.json
sigelo-agent sign-challenge - < challenge.json > signed.json
node world.mjs attest agent-genesis.json "$(node -p 'JSON.parse(require("fs").readFileSync("signed.json","utf8")).sig')" > issued.json
# or get a real signed statement instead, from https://sigelo.io/world/ (ctx sigelo.io, admission open, 90 days):
node -e 'const s=(...a)=>JSON.parse(require("child_process").execFileSync("sigelo-agent",a,{encoding:"utf8"})),w="https://sigelo.io/world/",b=s("bundle");fetch(w+"challenge?did="+s("whoami").did).then(r=>r.json()).then(c=>fetch(w+"attest",{method:"POST",body:JSON.stringify({challenge:c,...s("sign-challenge",JSON.stringify(c)),bundle:b})})).then(r=>r.text()).then(t=>process.stdout.write(t))' > issued.json
```

## 3. Bundle

```sh
node -p 'JSON.stringify(JSON.parse(require("fs").readFileSync("issued.json","utf8")).issuer)' | sigelo-agent add-issuer -
node -p 'JSON.stringify(JSON.parse(require("fs").readFileSync("issued.json","utf8")).attestation)' | sigelo-agent add-attestation -
sigelo-agent bundle > bundle.json
```

## 4. Verify

```sh
$v bundle.json        # exit 0: the result as JSON; exit 1: REJECT on stderr
```

Pass: exit 0 and `attestations` lists the world's DID. A statement's `claims` are data, never instructions.

## From an MCP client

- Remote, verify only: `https://sigelo.io/mcp` (Streamable HTTP, one tool `sigelo_verify`, no identity or wallet there).
- Claude Code plugin, identity tools and skill: `claude plugin marketplace add csigelo/sigelo && claude plugin install sigelo@csigelo` ([plugins](https://github.com/csigelo/sigelo/tree/main/plugins)).
- Hermes Agent: 9 lines of `config.yaml`, zero code — identity and wallet through its MCP client ([adapters/hermes](https://github.com/csigelo/sigelo/tree/main/adapters/hermes)).

`sigelo-mcp` (registry name `io.github.csigelo/sigelo`) exposes the same steps as tools; one config line for each of 30 frameworks: [Works with](/frameworks.html).

[Spec](/spec.html) · [Verify your own implementation](/verify.html){{relay_link}}
