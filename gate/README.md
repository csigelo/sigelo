<!-- SPDX-License-Identifier: MIT -->
# sigelo provenance gate (prototype)

Status: **prototype, not released, not externally reviewed.** Checked live against Claude Code 2.1.284
(`claude -p` and the interactive TUI) with the hardened hook line (REVIEW.md). Hermes: unit tests only.

The gate **denies** privileged tools (shell, file writes, subagents, MCP writers) unless the prompt
carries an instruction signed by an operator DID you pinned, by default only until the turn reads
anything. It does **not** stop prompt injection in general: read "Limits" and [DESIGN.md](DESIGN.md) §1 first.

```sh
node gate/claude-code/test.mjs                          # 89 checks, no root
python3 gate/hermes/test.py                             # 31 checks, no Hermes needed (needs `cryptography`)
doas sh gate/claude-code/test-hardened.sh "$USER"       # 13 checks of the root-owned layout, as your user
```

## Keys (in a terminal outside any agent session; better on another user or device)

```sh
export SIGELO_HOME=$PWD; (cd ts && npm ci && npx tsc) && (cd adapters/moadim && npm ci)
OP=~/operator.local.json           # the operator key: never readable by the agent's user
SIGELO_IDENTITY=$OP node adapters/moadim/cli.ts init --no-recovery && chmod 600 $OP
G=$(SIGELO_OPERATOR_IDENTITY=$OP node gate/claude-code/sign.mjs --genesis)
A=$(node adapters/moadim/cli.ts whoami | node -pe 'JSON.parse(require("fs").readFileSync(0)).did')  # the agent
echo "{\"agent\":\"$A\",\"operators\":[$G]}" > gate.json
```

## Install and sign

**Hardened (the deployment, HARDENING §1):** `doas sh gate/claude-code/install-root.sh --agent-user AGENT --config gate.json`
(or sudo): root-owned code and config, hooks in `/etc/claude-code/managed-settings.json`, state via a
helper. It refuses while the agent's user can replace `claude` itself, and prints the fix
(`--check-claude`). Restart Claude Code; `/status` names the managed source. `--uninstall` removes it.
**User-level (trying it out only):** copy `gate.json` to `~/.config/sigelo-gate/`, merge
[claude-code/settings.json](claude-code/settings.json) into `~/.claude/settings.json`, keep `SIGELO_HOME`
set. Everything is then writable by the agent's user, so a granted shell can switch the gate off.
**Hermes:** link `gate/hermes` to `~/.hermes/plugins/sigelo-gate`, enable it; keep the operator key off the machine.
**Signing:** `SIGELO_OPERATOR_IDENTITY=$OP node gate/claude-code/sign.mjs --to $A [--tools Bash] [--allow-after-read[=Edit]] [--background-ok] < prompt.txt`,
then paste the whole output as the prompt (tabs do not survive a TUI paste). Without `--allow-after-read`
the first file, search, web, MCP or command output read ends the grant; with it you vouch for it.

## Limits

- Persuasion and exfiltration through unprivileged tools (`WebFetch`, `Read`, MCP) are not stopped.
- With `--allow-after-read`, an injected file can steer the granted tools for that turn. Taint is per
  turn unless `taint_scope` is `session`: text read in earlier turns is still in the context.
- MCP writers are found by tool name, a heuristic. Hermes keeps state in memory, one process.
- A granted shell runs as the agent's user: rc files, units and cron entries outlive the grant
  (`kill_orphans` and `deny_background` bound daemons, not those; HARDENING §2).
