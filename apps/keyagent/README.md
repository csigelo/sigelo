<!-- SPDX-License-Identifier: MIT -->
# sigelo-key-agent

Holds sigelo identity keys and signs known sigelo bodies over a local socket, as ssh-agent does.
The model and the MCP server then hold a socket path, never the key.

```sh
npm i -g sigelo-key-agent@0.1.15 sigelo-agent@0.1.15
sigelo-key-agent start          # from a clone: node apps/keyagent/agent.mjs start; prints SIGELO_KEY_AGENT=<socket>
export SIGELO_KEY_AGENT=<socket>
sigelo-agent keys to-agent                        # the file now says {"provider":"agent"}
sigelo-agent keys status                          # "signs": true
```

New identities: `SIGELO_KEY_PROVIDER=agent sigelo-agent init …`. MCP: put `SIGELO_KEY_AGENT` in the
server's `env`. A file still holding a key with `SIGELO_KEY_AGENT` set is refused
(`key_agent_mismatch`); an agent that does not answer within 2 s is `key_agent_unavailable`.

| Command | |
|---|---|
| `start [--socket p] [--store dir] [--store-plain] [--allow-payments] [--allow-attest <ctx>]… [--idle s]` | run in this terminal |
| `install-unit [--print] [start flags]` | systemd user unit or LaunchAgent; nothing installs it by default |
| `list`, `lock` | keys held (DID, public key, form); forget unlocked seeds |

**Socket:** `$XDG_RUNTIME_DIR/sigelo/agent.sock`, `$TMPDIR/sigelo/agent.sock` (macOS),
`\\.\pipe\sigelo-agent-<user>` (Windows). Its directory must be 0700 and this user's
(`socket_dir_unsafe`).

**Store:** one 0600 file per identity in a 0700 directory, keychain-wrapped; where no OS keychain
answers, `start` refuses (`keychain_unavailable`) without `--store-plain`, for an agent of its own user.

**Policy:** no file; the start flags and `policy.mjs` are all of it.
- Always signed, for the key's current DID only: challenges, relay logins, invite proofs,
  messages, prekeys, contact notices.
- Bindings and invoices (payments): only with `--allow-payments`.
- Attestations: only for each `--allow-attest <ctx>` given.
- Rotations: never through `sign` (`policy_rotation`); `rotate` makes one to a key the agent made,
  pending until the caller writes it and sends `commit` (a killed caller gets the same one again).
- Anything else, or a body naming another DID: refused (`policy_typ`, `policy_did`).
- `--idle <s>` forgets unlocked seeds after that many quiet seconds.

**Docker:** the key in a sidecar, the agent in its own container, a socket on a shared volume.
Both run as the same user (`node`), whose socket only that user opens.

```dockerfile
FROM node:22-slim
RUN npm i -g sigelo-key-agent@0.1.15 sigelo-agent@0.1.15
USER node
```

```yaml
services:
  key-agent:
    build: .
    command: sigelo-key-agent start --socket /tmp/sigelo/agent.sock --store-plain
    volumes: [sock:/tmp, keys:/home/node]   # the key: only in this container's volume
  agent:
    build: .
    environment: { SIGELO_KEY_AGENT: /tmp/sigelo/agent.sock, SIGELO_KEY_PROVIDER: agent }
    volumes: [sock:/tmp, home:/home/node]   # the identity file: {"provider":"agent"}, no key
    depends_on: [key-agent]
volumes: { sock: {}, keys: {}, home: {} }
```

Then `docker compose run agent sigelo-agent init --recovery <z…>`. `--store-plain`: no keychain in
a container; the store is readable only from the sidecar's volume.

**Protocol:** one JSON object per line, at most 2 MiB; every request and refusal in
[`fixtures/protocol-v0.json`](fixtures/protocol-v0.json). `node test.mjs`: fixture, socket checks,
sidecar, and the contact and MCP suites with every key in the agent.

**Limits.** In your own account the agent keeps the key out of the model's process and refuses
hostile rotations, but a shell running as you can still read the store. Use another user or
hardware (K4, K5) for more.

## Windows: manual, on a Windows machine

Not tested. The pipe check of plan §9:

1. A second local user opens `\\.\pipe\sigelo-agent-<user>` and sends `{"op":"list"}`.
2. A remote client tries the same over SMB.
3. Can that user read the agent's memory?

If 1 or 2 gets a reply, the agent needs a per-start token before release on Windows.
