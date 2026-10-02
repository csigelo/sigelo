<!-- SPDX-License-Identifier: MIT -->
# Provenance gate: hardening (normative for deployment)

Companion to [DESIGN.md](DESIGN.md): the deployment the guarantees depend on, the limits that are
bounded rather than closed, and how far each bound reaches.

## 1. Deployment: the hardened layout

The hook runs **as the agent's user**, the user a granted shell or file-writing tool acts as, so the
hardened layout is the deployment; the user-level install is for trying it out.
`claude-code/install-root.sh` builds it (`test-hardened.sh` checks it as the agent's user):

| What | Where | Owner, mode | Why |
|---|---|---|---|
| hook definition | `/etc/claude-code/managed-settings.json` | root, 0644 | managed settings (below) |
| gate code, `ts/dist`, `@noble` | `/usr/local/lib/sigelo-gate/` | root, read-only | the agent cannot change what runs |
| config | `/etc/sigelo-gate/gate.json` | root, 0644 | nor what it trusts |
| state writer | `/usr/local/lib/sigelo-gate/gate-state` | root, 0755 | fixed command, fixed config |
| state | `/var/lib/sigelo-gate/` | `sigelo-gate`:agent group, 2750; files 0640 | only the writer writes |
| privilege rule | `/etc/doas.d/sigelo-gate.conf` or `/etc/sudoers.d/sigelo-gate` | root, 0440 | the writer, no arguments, as `sigelo-gate` |
| node, `claude` | system paths | root | a user-writable binary replaces the gate wholesale |

**Managed settings.** Claude Code ranks `/etc/claude-code/managed-settings.json` (and
`managed-settings.d/`) above `--settings`, project-local, project and user files. Hook lists
**merge** across sources, so lower files can add hooks but not remove the managed ones, and their
`disableAllHooks` does not reach managed hooks. The hook line is
`/usr/bin/env -i CLAUDE_PID="$CLAUDE_PID" CLAUDE_CODE_SESSION_ID="$CLAUDE_CODE_SESSION_ID" /usr/bin/node …/gate.mjs --config /etc/sigelo-gate/gate.json || exit 2`:
absolute paths, no inherited environment but those two (no `NODE_OPTIONS`), and a missing file
blocks. Not live-tested here (it would gate every session on this host); live checks used the same
line through `--settings`.

**The `claude` binary.** A per-user, self-updating install (`~/.local/bin/claude` →
`~/.local/share/claude/versions/…`, `~/.claude/local`, a user npm prefix) lets a granted shell swap
in a build that skips hooks. `install-root.sh` refuses while the agent's user owns or can write any
of those paths or a directory above the binary (`--check-claude` lists them without root;
`--i-accept-user-writable-claude` overrides), prints the remedy (copy the binary root-owned to
`/usr/local/bin`, remove the per-user copies, put `/usr/local/bin` first in PATH), and writes
`env.DISABLE_AUTOUPDATER=1` and `DISABLE_UPDATES=1` into managed settings so Claude Code neither
self-updates nor runs `claude update`. Residual: a granted shell can still prepend a PATH entry in
an rc file, which takes effect the next time the user starts `claude` from that shell.

**State: a helper, not a daemon.** The writer is `gate.mjs --state-writer` behind one doas/sudo rule
that allows no arguments. Smaller than a socket daemon (nothing to supervise, no protocol, nothing
running between turns); cost one doas+node start per state change (0.3 s). The agent's user can call
it directly, so it trusts nothing it is told: it opens a grant only after verifying signature, hash
and a fresh nonce itself (it owns the nonce list); close and taint only remove privilege; `start`
marks only a brand-new session id. Missing, refused or slow → a prompt is blocked and a read in a
granted turn is denied.

**Self-check.** With `state_writer` set the hook refuses to decide unless gate.json, its code,
`ts/dist`, `@noble`, node and the state directory, with every ancestor, are neither owned nor
writable by its user (a sticky `/tmp` ancestor is accepted). A tripwire, not a proof.

**Still in reach of the agent's user:** `~/.claude*` and project `.claude/` (permissions, extra hooks,
MCP servers: none can lift the gate's denial, but a new MCP server is gated only by the name
heuristic), its own files, rc files, and anything a granted shell starts (§2).

## 2. Processes outliving a grant

A granted `Bash` can start something that acts after the grant closes. Two opt-in bounds:

- **`kill_orphans: true`.** At turn end (`Stop`) and at the next prompt or slash command, the hook
  kills every process of its user that carries this session's `CLAUDE_CODE_SESSION_ID` and whose
  parent chain no longer reaches Claude Code (`CLAUDE_PID`, checked to be the hook's ancestor):
  `nohup`, `setsid`, `(cmd &)`, double forks. Processes still attached (`run_in_background` tasks,
  running hooks) are left alone. Linux `/proc` only; if Claude Code's pid cannot be found, a prompt
  is blocked and `Stop` only logs. **Misses** a process that clears its environment (`env -i`,
  `exec -c`) and anything another service starts for it (`systemd-run --user`, `crontab`, `at`).
- **`deny_background: true`.** In a signed turn without `background_ok`, `Bash`/`PowerShell`
  commands matching `background_pattern` (`nohup`, `setsid`, `disown`, `systemd-run`, `crontab`,
  `start-stop-daemon`, `at`/`batch`/`screen`/`tmux` in command position, a lone `&`), `Monitor`, and
  `run_in_background: true` are denied (`sign.mjs --background-ok`). A regex over command text:
  it **over-matches** (`&` in a URL, `at` after `;`) and **misses** anything indirect (a script that
  daemonises, `eval`, base64, an interpreter's `fork`). Together the two catch the plain cases;
  a determined shell with a grant still persists through rc files, units or cron entries.

## 3. Taint details

- **Same batch.** `PreToolUse` sees one call, never the batch. Taint is recorded at a reader's
  `PreToolUse`, so `Read` then `Bash` in one message is denied (test 53; live: Claude Code ran
  `Read` fully before `Bash`'s hook). A privileged call emitted *before* the read in the same
  message passes (live): it was written before any result existed, so this turn's reads cannot
  have steered it. What can is text the model already had: earlier turns (session scope, below)
  or earlier untainted results of this turn, which the operator's signed prompt authorised.
- **`taint_scope: "session"`.** Taint persists across turns and slash commands for the session; a
  signed prompt then grants only with `taint_ok`. Only a session whose `SessionStart` was seen as
  `startup` or `clear` on a new id begins clean; `resume`, `fork`, `compact`, or a start never seen
  (a failed hook) begin tainted (live: a resumed and a forked session after a `Read` both denied a
  signed `Bash`). A `/clear` that keeps its id stays tainted. Default `"turn"`.
- **Subagents** (`Task`, `Agent`, `RemoteTrigger`) are privileged; a local subagent shares the turn's
  grant and taint, its reads taint the turn, its report taints like any result.
- **Hermes** runs `pre_tool_call` per call as well; the same reasoning applies.

## 4. MCP writers, a heuristic

An MCP tool is privileged when the tool part of its name (`mcp__<server>__<tool>`, Hermes
`mcp_<server>_<tool>`) matches `mcp_write_pattern` anywhere, case-insensitive, unless listed in
`mcp_allow`. Names are chosen by the server's author: a `query` that runs `DELETE` passes, and
`get_settings` over-matches. List writers of servers you do not control in `privileged`, or restrict
the servers (`managed-mcp.json`). Every MCP result taints regardless.
