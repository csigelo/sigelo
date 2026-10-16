<!-- SPDX-License-Identifier: MIT -->
# sigelo-key-agent

Holds sigelo identity keys and signs known sigelo bodies over a local socket, as ssh-agent does.
The model and the MCP server then hold a socket path, never the key.


```sh
node keyagent/agent.mjs start                     # prints SIGELO_KEY_AGENT=<socket>
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

**Signs** challenges, relay logins, invite proofs, messages, prekeys and contact notices naming the
key's current DID; bindings and invoices only with `--allow-payments`; attestations only for a
`--allow-attest` context. Never a rotation through `sign` (`policy_rotation`): `rotate` makes one to
a key the agent made, kept pending until the caller writes it and sends `commit`. A caller killed in
between gets the same rotation on retry. Everything else: `policy_typ`, `policy_did`.

**Store:** one 0600 file per identity in a 0700 directory, keychain-wrapped; where no OS keychain
answers, `start` refuses (`keychain_unavailable`) without `--store-plain`, for an agent of its own user.

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
