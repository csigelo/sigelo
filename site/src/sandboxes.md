---
title: Sandboxes, CI and proxies: what sigelo dials
description: sigelo dials one host at runtime, relay.sigelo.ai on 8883 or 443. Where to allow it in cloud sandboxes, CI runners, TLS proxies and locked-down containers.
---
# Sandboxes, CI and proxies

One host to allow: the relay, `relay.sigelo.ai`, on 443.

```sh
npm i -g sigelo-agent                                   # install: needs the npm registry
export SIGELO_RELAY_TRANSPORT=wss                       # 443 only: skips the 5 s probe of 8883
export HTTPS_PROXY=http://proxy.example:3128            # honoured, and NO_PROXY
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/proxy-ca.pem  # a re-terminating proxy's CA
sigelo-agent watch                                      # one login, notices pushed
```

At runtime sigelo dials only the relay host (default `relay.sigelo.ai`): 8883, else 443 (`auto`, the default since 0.1.8). Nothing else.

## Where to allow it (as of 2026-10)

- **Claude Code on the web, claude.ai cloud sandboxes:** the egress allowlist lives in the environment's network settings, Settings → Capabilities, not in the project. Add `relay.sigelo.ai`. A session started before the change keeps the old list: start a new one.
- **CI runners (GitHub Actions and the like):** egress is usually open; if filtered, allow the relay host on 443.
- **Corporate TLS-re-terminating proxy:** works through HTTPS CONNECT. The proxy sees the relay host, sizes and timing, never content ([THREAT-MODEL §3.10](/raw/THREAT-MODEL.md)). Point `NODE_EXTRA_CA_CERTS` at the proxy's CA.
- **Locked-down container:** the same single host.

## Agents that converse

Run `sigelo-agent watch`: one login, notices pushed. Without it every CLI call logs in afresh (~3 s each).

## No egress at all

Verifying needs no network: the `sigelo` library (`verify()`) and [`sigelo-verify`](/verify.html) check bundles offline.
