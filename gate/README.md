<!-- SPDX-License-Identifier: MIT -->
# sigelo provenance gate (prototype)

Status: **prototype, not released, not externally reviewed.** Checked live once against Claude Code
2.1.284 in `-p` mode (REVIEW.md). Hermes: unit tests only.

The gate **denies** privileged tools (shell, file writes) unless the current prompt carries an
instruction signed by an operator DID you pinned. Text arriving any other way (tool results, web
pages, MCP output, A2A messages) cannot unlock them. It does **not** stop prompt injection in
general: read "Limits" below and [DESIGN.md](DESIGN.md) §1 before relying on it.

```sh
node gate/claude-code/test.mjs     # 20 checks
python3 gate/hermes/test.py        # 13 checks, no Hermes needed (needs `cryptography`)
```

## Setup (from a sigelo checkout, in a terminal outside any agent session)

```sh
export SIGELO_HOME=$PWD            # also in the environment Claude Code starts from
(cd ts && npm ci && npx tsc) && (cd adapters/moadim && npm ci)
OP=~/operator.local.json           # the operator key: better on another user or machine
SIGELO_IDENTITY=$OP node adapters/moadim/cli.ts init --no-recovery && chmod 600 $OP
G=$(SIGELO_OPERATOR_IDENTITY=$OP node gate/claude-code/sign.mjs --genesis)
A=$(node adapters/moadim/cli.ts whoami | node -pe 'JSON.parse(require("fs").readFileSync(0)).did')  # the agent
mkdir -p ~/.config/sigelo-gate && echo "{\"agent\":\"$A\",\"operators\":[$G]}" > ~/.config/sigelo-gate/gate.json
```

Sign each privileged request, then paste the whole output as the prompt:
`SIGELO_OPERATOR_IDENTITY=$OP node gate/claude-code/sign.mjs --to $A [--tools Bash] < prompt.txt`

**Claude Code:** merge [claude-code/settings.json](claude-code/settings.json) into
`~/.claude/settings.json` (better: `/etc/claude-code/managed-settings.json`, root-owned), restart.
No matchers: the gate reads `privileged` and `taint` from gate.json.

**Hermes:** `ln -s "$SIGELO_HOME/gate/hermes" ~/.hermes/plugins/sigelo-gate`, add `sigelo-gate` to
`plugins.enabled` in `~/.hermes/config.yaml`, and set `SIGELO_GATE_CONFIG` if gate.json lives elsewhere.

## Limits

- Persuasion and exfiltration through unprivileged tools (`WebFetch`, `Read`, MCP) are not stopped.
- A grant covers the whole signed turn until a web or MCP tool runs, including files read with `Read`.
- Out of the box everything (gate code, gate.json, settings, state, often the key) is writable by the
  agent's own user: a granted shell, or an MCP tool that writes files, can switch the gate off.
  Hardening: DESIGN.md §7. Hermes keeps state in memory, one process, with no taint step.
