<!-- SPDX-License-Identifier: MIT -->
# Provenance gate: design (prototype, 2026-10-02; hardened layout and taint step the same day)

A signature cannot stop persuasion, but it settles who said something, so the harness can
enforce the one rule the model cannot: **only an identity allowed to instruct can unlock
privileged tools; everything else is data, however it is phrased.**

## 1. What it blocks, what it does not

Blocks: injected instructions in tool results, web pages, MCP output and inbound A2A messages
**unlocking a privileged tool** (shell, file writes, code execution, delegation, the keeper's
`pay` if listed) in a turn the operator did not sign, and, inside a signed turn, anything read
during it reaching a privileged tool unless the operator signed `taint_ok` (§5). It is a deny-only layer, not a guarantee:
it holds only within the limits below and the deployment in §7.

Does **not** stop:
- **Persuasion.** The model can still believe or act on injected text with unprivileged tools.
- **Exfiltration through allowed tools**, e.g. a secret read and sent out in a `WebFetch` URL.
  Make such tools privileged, or add egress control.
- **What a granted shell leaves behind.** A shell runs as the agent's user: a background process,
  a cron or systemd user unit, a PATH shim or an edited rc file outlives the grant, and the gate
  cannot revoke it. The taint step (§5) makes it harder to steer that shell, not impossible.
- **Text from earlier turns.** Taint is per turn by default; what the model read before the signed
  prompt is still in its context (`taint_scope: "session"` closes this, at a cost: §5).
- **A compromised operator key, or the operator signing something they did not read.**
- **Tampering by the agent's own user** in the user-level install. The hardened layout (§7) takes
  the code, the config, the hook definition and the state out of that user's reach.

## 2. Envelope: an attestation, no wire change

SPEC §3.1's table is closed, so there is no new `typ`. An instruction is an ordinary §5 attestation:

```json
{ "v": "sigelo/0", "typ": "attestation", "iss": "<operator DID>", "sub": "<agent DID>",
  "iat": 1790000000, "exp": 1790000600, "ctx": "sigelo/instruction", "admission": "open",
  "claims": { "text_sha256": "<hex SHA-256 of the UTF-8 text>", "nonce": "<16–64 chars>",
              "tools": ["Bash"], "taint_ok": true } }
```

`tools` (optional) narrows the grant; `taint_ok` (optional: `true` or a list of tools) lets it
survive reads in the turn (§5). `admission` is required by §3.1 and means nothing here,
so it is fixed at `open`. The envelope `{body, sig}`, as JSON in base64url, is the message's
**last line**: `sigelo-instruction: <base64url>`. The signed text is everything before it,
exactly as passed minus trailing spaces, tabs, CR and LF (no Unicode normalisation). Every
sigelo verifier reads it unchanged. It never goes into a bundle: a one-time command, not reputation.

## 3. Verification (offline, fail closed)

In order, each failure named:
1. Strict parse (no duplicate keys or floats); envelope exactly `{body, sig}`; body fits §3.1.
2. `ctx` is `sigelo/instruction`, `iss` is a pinned operator DID, and `sub` is this agent's DID.
3. `iat ≤ now + 60`, `exp > now`, `exp − iat ≤ max_ttl` (600 s by default).
4. Ed25519 over `"sigelo\n" ‖ JCS(body)` under the pinned genesis `key`.
5. `text_sha256` matches the text. The nonce has not been used before, and is then kept until `exp`.

Anything unverifiable, malformed or erroring is **data**; a gate error **denies** the privileged
call. No network, no resolver, no clock but the local one.

## 4. Allowlist and configuration

One `gate.json` for both harnesses (hook `--config`, else `$SIGELO_GATE_CONFIG`, else
`~/.config/sigelo-gate/gate.json`; hardened: `/etc/sigelo-gate/gate.json`, fixed in the hook line):

```json
{ "agent": "did:sigelo:z…", "operators": [ { "v": "sigelo/0", "typ": "genesis", … } ],
  "max_ttl": 600,
  "privileged": ["Bash", "Monitor", "PowerShell", "Write", "Edit", "MultiEdit", "NotebookEdit", "Task", "Agent"],
  "mcp_write_pattern": "write|edit|create|delete|remove|update|insert|set|execute|exec|run|send|post|put|push|commit|merge|move|rename|upload|deploy|install|kill|pay|transfer",
  "mcp_allow": [], "taint": ["*"], "taint_exempt": ["Write", "Edit", "MultiEdit", "NotebookEdit", "TodoWrite"],
  "taint_scope": "turn", "label": ["WebFetch", "WebSearch", "mcp__*"],
  "state": "/var/lib/sigelo-gate", "state_writer": ["/usr/bin/doas", "-n", "-u", "sigelo-gate", "/usr/local/lib/sigelo-gate/gate-state"],
  "hermes_privileged": ["terminal", "write_file", "patch", "execute_code", "delegate_task"],
  "hermes_taint_exempt": ["write_file", "patch", "todo"], "hermes_mcp_allow": [],
  "hermes_platforms": ["a2a"], "hermes_data_tools": ["a2a_call", "a2a_orchestrate", "a2a_history"] }
```

Who may instruct: the pinned operator **genesis** documents (local, not a lookup); after a
rotation, pin the new one. Privileged by default: the built-in tools that run commands, write
files or start a subagent (`Monitor` runs a shell command; `Task`/`Agent`: §5).

**MCP writers, a heuristic.** An MCP tool is privileged when the tool part of its name
(`mcp__<server>__<tool>`, Hermes `mcp_<server>_<tool>`) matches `mcp_write_pattern`, case-insensitive,
anywhere (`createIssue`, `run_query`, `put_object`), unless it is listed in `mcp_allow`. Names are
chosen by whoever wrote the server: a tool called `query` that runs SQL `DELETE`, or `get` with side
effects, passes. It over-matches too (`set` in `get_settings`, `put` in `output`): allowlist those.
For servers you do not control, list their writers in `privileged` by hand, or restrict the servers
(Claude Code's `managed-mcp.json`). Every MCP result taints regardless.

## 5. Claude Code (gate/claude-code)

Hook facts (hooks reference, checked against 2.1.284 live where marked) that decide the design:
- `UserPromptSubmit` gets the raw `prompt` and fires for **user** prompts only, so the hook can
  tell the operator's turn from tool output (live). It can add `additionalContext`.
- `PreToolUse` gets `tool_name`, `tool_input`, `tool_use_id`. `permissionDecision: "deny"` blocks
  the call; a parallel hook answering `"allow"` does not override it (live). The gate never returns
  `"allow"`, which would skip the permission prompts: a granted call still meets the normal rules.
- **Exit codes.** 2 blocks (tool call, prompt, slash command) whatever stdout says; any other
  non-zero exit, a crash or a timeout is a non-blocking error and **lets the call through**. So the
  hook line ends in `|| exit 2` (node or gate.mjs missing → blocked; test 51), every internal error
  exits 2, a watchdog answers with exit 2 after 1.8 s (a stalled input: test 44), the state writer
  gets 1.2 s, and the settings give each hook `"timeout": 10` (defaults: 600 s, 30 s for
  `UserPromptSubmit`), so Claude Code's own timeout should never be the one that fires.
- `PostToolUse` / `PostToolUseFailure` cannot block; they add context.
- Subagent tool calls fire the same hooks with the same `session_id` (plus `agent_id`). Slash
  commands fire `UserPromptExpansion` instead of `UserPromptSubmit`, so that event closes the grant.

`UserPromptSubmit` closes the previous grant and opens one until `exp` if the prompt verifies.
`PreToolUse` denies a privileged tool unless an untainted grant covers it, and re-verifies the
stored signature.

**Taint.** Every tool result can carry text someone else wrote, so every tool taints except
`taint_exempt` (tools whose result is the harness's own confirmation: `Write`, `Edit`, …). That
includes `Read`, `Grep`, `Glob`, `WebFetch`, `WebSearch`, every `mcp__*` tool, a subagent's report
and the output of a granted `Bash`. The taint is recorded in `PreToolUse`, **before** the result
exists (if it cannot be recorded, that tool is denied), and again in `PostToolUse(Failure)`. After
it, privileged tools are denied for the rest of the turn unless the signed claims carry
`taint_ok: true` (every granted tool) or `taint_ok: ["Edit", …]` (those only):
`sign.mjs --allow-after-read[=Edit,…]`.

The rule is: **a privileged call the model makes after reading anything needs the operator to
have said so when signing.** Default, a signed turn is "do this one thing": `run npm test` gets one
`Bash`, and a second `Bash` (after the first one's output) is denied. A read-then-act turn ("read
the failing test and fix it") must be signed with `--allow-after-read`; the operator then vouches
for whatever the files say, which is exactly the trust the taint step otherwise withholds. The
trade-off is plain: without the flag, most coding turns lose their grant at the first `Read`; with
it, an injected file can steer the granted tools for that one turn, as before this step.
Details:
- A privileged call issued in the **same batch** as a read (the model emits `Read` and `Bash`
  together) can pass: it was written before the result existed, so the result cannot have
  steered it (seen live). Whether it passes depends on hook order; it is never steered.
- `taint_scope: "session"` keeps the taint across turns, so a signed prompt in a session that ever
  read anything grants only with `taint_ok`: the honest setting when earlier turns read untrusted
  text, since it is still in the context. Default `"turn"`.
- **Subagents** (`Task`, `Agent`) are privileged: starting one needs a signed turn, it inherits
  that turn's grant and taint (same `session_id`), its reads taint the turn, and its report
  taints like any tool result. A subagent still running after the turn finds its grant closed
  by the next prompt.

## 6. Hermes (gate/hermes)

A standalone plugin (`register(ctx)`, opt-in via `plugins.enabled`) on three existing hooks:
- `pre_gateway_dispatch` can `rewrite` an inbound message. On gated platforms (A2A), a verified
  instruction is labelled and opens a grant for that chat. Anything else is fenced as
  `<sigelo_data …>`, which keeps Hermes' own "untrusted" frame inside it, and closes the grant.
- `pre_tool_call` can `block` a privileged tool (including MCP writers by the §4 heuristic) in a
  gated chat with no untainted grant. Any other tool except `hermes_taint_exempt` taints the
  grant before it runs; `taint_ok` works as in §5. Hermes runs this hook **fail-closed** (a
  timeout or exception blocks). Sessions without a gateway origin (CLI, cron) are left to Hermes'
  approvals.
- `transform_tool_result` (args: `tool_name`, `args`, `result`, `session_id`, …) fences A2A client
  results and records the taint again. Hermes runs it **fail-open**, so it is a backstop:
  `pre_tool_call` is where the taint is decided. A tool result never grants.

Limits: in-memory state, one process. A2A filter edits break the hash: closed.

**Deployment rule: the operator key never sits where the agent can read it.** Under Hermes the
gated channel is the inbound A2A message, so anyone holding the key can sign one: a key readable
by the agent's user (or by any process a prompt can drive) is a full bypass. Keep it on another
device (the phone that signs) or another user account with `chmod 600`; `sign.mjs` refuses a
group/world-readable key and refuses to run inside Claude Code, as hygiene only. In Claude Code a
stolen key alone grants nothing: only the user submits prompts.

## 7. Deployment (normative), composition and privacy

The hook runs **as the agent's user**, and that user is what a granted shell or a file-writing tool
acts as. So the hardened layout is the deployment; the user-level install is for trying it out.
`claude-code/install-root.sh` builds it (`test-hardened.sh` checks it as the agent's user):

| What | Where | Owner, mode | Why |
|---|---|---|---|
| hook definition | `/etc/claude-code/managed-settings.json` | root, 0644 | managed settings (below) |
| gate code, `ts/dist`, `@noble` | `/usr/local/lib/sigelo-gate/` | root, read-only | the agent cannot change what runs |
| config | `/etc/sigelo-gate/gate.json` | root, 0644 | nor what it trusts |
| state writer | `/usr/local/lib/sigelo-gate/gate-state` | root, 0755 | fixed command, fixed config |
| state | `/var/lib/sigelo-gate/` | `sigelo-gate`:agent group, 2750; files 0640 | only the writer writes; the hook reads |
| privilege rule | `/etc/doas.d/sigelo-gate.conf` or `/etc/sudoers.d/sigelo-gate` | root, 0440 | the agent may run the writer, no arguments, as `sigelo-gate` |
| node, `claude` | system paths | root | a user-writable binary replaces the gate wholesale |

**Hook definition: managed settings.** Claude Code ranks managed settings (on Linux
`/etc/claude-code/managed-settings.json` and `managed-settings.d/`; the 2.1.284 binary reads that
directory) above the command line (`--settings`), project-local, project and user files: no lower
file overrides a managed key. Hooks are a list, and lists **merge** across sources, so a lower
file can add hooks but cannot remove the managed ones; `disableAllHooks` below the managed level
does not disable managed hooks. `allowManagedHooksOnly: true` would also drop every user and
project hook; the gate does not need it (its deny already wins over another hook's allow). The
hook line is `/usr/bin/env -i /usr/bin/node …/gate.mjs --config /etc/sigelo-gate/gate.json || exit 2`:
absolute paths, an empty environment (no `NODE_OPTIONS`), and a missing file blocks instead of
passing. Not live-tested here: installing a managed file on this host would gate every Claude Code
session on it; the live check used the same hook line through `--settings`.

**State: a helper, not a daemon.** The writer is `gate.mjs --state-writer` run through one doas or
sudo rule (`permit nopass AGENT as sigelo-gate cmd …/gate-state args`; sudoers `… NOPASSWD: …/gate-state ""`,
both allow no arguments). Chosen over a unix-socket daemon running as `sigelo-gate` because it is
smaller: no service to supervise, no socket protocol, no peer-credential checks, nothing running
between turns; the cost is one doas+node start per state change (0.3 s measured, only on a prompt
and on the first read of a granted turn). setuid is out (node, interpreters). The agent's user can
call the writer directly, so the writer trusts nothing it is told: it opens a grant only after
verifying the signature, the hash and a fresh nonce itself (it holds the nonce list, which the
agent can no longer clear), and its other two operations, close and taint, only remove privilege.
If the writer is missing, refused or slow, a prompt is blocked and a read in a granted turn is
denied (fail closed: tests 47, 48, H12, H13).

**Self-check.** With `state_writer` set the hook refuses to decide (exit 2) unless gate.json, its
own code, `ts/dist`, `@noble`, node and the state directory, with every ancestor, are neither owned
nor writable by the user it runs as (a sticky `/tmp` ancestor is accepted). A tripwire for a broken
install, not a proof.

**What stays in reach of the agent's user**, and so of a granted shell: `~/.claude*` and project
`.claude/` (permissions, extra hooks, MCP servers: none can lift the gate's denial, but a newly added
MCP server is gated only by the §4 heuristic), the agent's own files, and anything a granted shell
starts (§1). The user-level install (`settings.json` in `~/.claude`, code and state in the home
directory) has **none** of the guarantees above: a granted shell, or an MCP tool that writes files,
can switch the gate off.

The gate only adds denials; Claude Code permissions, Hermes approvals and the keeper's caps
still apply (for money the keeper stays the boundary). Nothing leaves the machine.

## 8. Open decisions

- **Defaults:** `taint_scope` turn or session; whether `WebFetch` (an egress path) becomes privileged.
- **Signing UX:** today pipe through `sign.mjs` and paste; options are an alias, a key on the
  phone, a hardware key, an editor that signs on send. **TTL:** one turn, ≤ 10 minutes, or longer?
- **Pinning** a genesis or a rotating bundle. **Shipping** as a sigelo package, a Hermes plugin, both.
