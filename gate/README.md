<!-- SPDX-License-Identifier: MIT -->
# sigelo provenance gate (prototype)

Status: **prototype, not released, not externally reviewed.** Checked live against Claude Code
2.1.284 in `-p` mode, with the hardened hook line and state writer (REVIEW.md). Hermes: unit tests only.

The gate **denies** privileged tools (shell, file writes, subagents, MCP tools that write) unless the
current prompt carries an instruction signed by an operator DID you pinned, and, by default, only
until the turn reads anything. Text arriving any other way (tool results, files, web pages, MCP
output, A2A messages) cannot unlock them. It does **not** stop prompt injection in general: read
"Limits" below and [DESIGN.md](DESIGN.md) §1 before relying on it.

```sh
node gate/claude-code/test.mjs                          # 54 checks, no root
python3 gate/hermes/test.py                             # 28 checks, no Hermes needed (needs `cryptography`)
doas sh gate/claude-code/test-hardened.sh "$USER"       # 13 checks of the root-owned layout, as your user
```

## Keys (in a terminal outside any agent session; better on another user or device)

```sh
export SIGELO_HOME=$PWD
(cd ts && npm ci && npx tsc) && (cd adapters/moadim && npm ci)
OP=~/operator.local.json           # the operator key: never readable by the agent's user
SIGELO_IDENTITY=$OP node adapters/moadim/cli.ts init --no-recovery && chmod 600 $OP
G=$(SIGELO_OPERATOR_IDENTITY=$OP node gate/claude-code/sign.mjs --genesis)
A=$(node adapters/moadim/cli.ts whoami | node -pe 'JSON.parse(require("fs").readFileSync(0)).did')  # the agent
echo "{\"agent\":\"$A\",\"operators\":[$G]}" > gate.json
```

## Install, hardened (the deployment; DESIGN §7)

```sh
doas sh gate/claude-code/install-root.sh --agent-user AGENT --config gate.json   # or sudo
```

Code, config and hook definition become root-owned, the hooks go into
`/etc/claude-code/managed-settings.json` (above every user, project and `--settings` file, and not
removable from them), and state lives in `/var/lib/sigelo-gate`, written only by a `sigelo-gate`
helper the agent may run through one doas/sudo rule. Restart Claude Code; `/status` names the managed
source. Install `claude` itself root-owned with the auto-updater off: the script warns when the
agent's user can write it. `--uninstall` removes everything.

## Install, user-level (trying it out only)

Copy `gate.json` to `~/.config/sigelo-gate/`, merge [claude-code/settings.json](claude-code/settings.json)
into `~/.claude/settings.json`, keep `SIGELO_HOME` in Claude Code's environment, restart.
**Warning:** everything (code, config, settings, state) is then writable by the agent's own user, so a
granted shell, or an MCP tool that writes files, can switch the gate off. Use it to see the gate work,
not to rely on it.

**Hermes:** `ln -s "$SIGELO_HOME/gate/hermes" ~/.hermes/plugins/sigelo-gate`, add `sigelo-gate` to
`plugins.enabled` in `~/.hermes/config.yaml`, set `SIGELO_GATE_CONFIG` if gate.json lives elsewhere,
and keep the operator key off the machine: under Hermes a readable key is a full bypass.

## Signing

Sign each privileged request, then paste the whole output as the prompt:
`SIGELO_OPERATOR_IDENTITY=$OP node gate/claude-code/sign.mjs --to $A [--tools Bash] [--allow-after-read[=Edit]] < prompt.txt`

Without `--allow-after-read` a signed turn is one action: the first file, search, web, MCP or
command output it reads ends the grant. Sign "read X and then fix it" with `--allow-after-read`, and
you vouch for what X says.

## Limits

- Persuasion and exfiltration through unprivileged tools (`WebFetch`, `Read`, MCP) are not stopped.
- With `--allow-after-read`, an injected file can steer the granted tools for that turn. Taint is per
  turn unless `taint_scope` is `session`: text read in earlier turns is still in the context.
- MCP writers are found by tool name (DESIGN §4), a heuristic; list or allowlist the rest.
- A granted shell runs as the agent's user: what it starts or edits outlives the grant.
- Hermes keeps state in memory, one process.
