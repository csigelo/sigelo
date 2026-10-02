<!-- SPDX-License-Identifier: MIT -->
# Provenance gate: design (prototype, 2026-10-02)

A signature cannot stop persuasion, but it settles who said something, so the harness can enforce
the one rule the model cannot: **only an identity allowed to instruct can unlock privileged tools;
everything else is data.** Deployment, taint details and bounded limits: [HARDENING.md](HARDENING.md).

## 1. What it blocks, what it does not

Blocks: injected instructions in tool results, web pages, MCP output and inbound A2A messages
**unlocking a privileged tool** (shell, file writes, code execution, delegation, the keeper's `pay`
if listed) in a turn the operator did not sign, and, inside a signed turn, anything read during it
reaching a privileged tool unless the operator signed `taint_ok` (§5). A deny-only layer within the
limits below and the hardened deployment (HARDENING §1); Claude Code permissions, Hermes approvals
and the keeper's caps still apply. Nothing leaves the machine.

Does **not** stop:
- **Persuasion**, and **exfiltration through allowed tools** (a secret in a `WebFetch` URL): make
  such tools privileged, or add egress control.
- **What a granted shell leaves behind** as the agent's user: rc files, PATH shims, user units,
  cron. `kill_orphans` and `deny_background` bound daemons (HARDENING §2); the rest stays.
- **Text from earlier turns**, unless `taint_scope` is `"session"` (HARDENING §3).
- **A compromised operator key, or the operator signing something they did not read.**
- **Tampering by the agent's own user** in the user-level install (not in the hardened layout).

## 2. Envelope: an attestation, no wire change

SPEC §3.1's table is closed, so there is no new `typ`. An instruction is an ordinary §5 attestation:

```json
{ "v": "sigelo/0", "typ": "attestation", "iss": "<operator DID>", "sub": "<agent DID>",
  "iat": 1790000000, "exp": 1790000600, "ctx": "sigelo/instruction", "admission": "open",
  "claims": { "text_sha256": "<hex SHA-256 of the UTF-8 text>", "nonce": "<16–64 chars>",
              "tools": ["Bash"], "taint_ok": true, "background_ok": true } }
```

Optional: `tools` narrows the grant, `taint_ok` (`true` or tools) survives reads (§5), `background_ok`
allows lasting processes (HARDENING §2). `admission` is required by §3.1, fixed at `open`. The
envelope `{body, sig}`, JSON in base64url, is the **last line**: `sigelo-instruction: <base64url>`;
the signed text is everything before it minus trailing spaces, tabs, CR and LF (no Unicode
normalisation). Every sigelo verifier reads it unchanged; it never goes into a bundle.

## 3. Verification (offline, fail closed)

In order, each failure named:
1. Strict parse (no duplicate keys or floats); envelope exactly `{body, sig}`; body fits §3.1.
2. `ctx` is `sigelo/instruction`, `iss` is a pinned operator DID, and `sub` is this agent's DID.
3. `iat ≤ now + 60`, `exp > now`, `exp − iat ≤ max_ttl` (600 s by default).
4. Ed25519 over `"sigelo\n" ‖ JCS(body)` under the pinned genesis `key`.
5. `text_sha256` matches the text; optional claims are well-formed. The nonce is new, then kept until `exp`.
Anything unverifiable, malformed or erroring is **data**; a gate error **denies** the privileged call.

## 4. Configuration

One `gate.json` for both harnesses (hook `--config`, else `$SIGELO_GATE_CONFIG`, else
`~/.config/sigelo-gate/gate.json`; hardened: `/etc/sigelo-gate/gate.json`, fixed in the hook line).
Required: `agent` (this agent's DID), `operators` (pinned operator **genesis** documents; after a
rotation, pin the new one). Optional:

| Key | Default | Meaning |
|---|---|---|
| `privileged` | Bash, Monitor, PowerShell, Write, Edit, MultiEdit, NotebookEdit, Task, Agent, RemoteTrigger | denied without a grant |
| `mcp_write_pattern`, `mcp_allow` | write\|edit\|create\|delete\|run\|send\|… , `[]` | MCP writers, by name: HARDENING §4 |
| `taint`, `taint_exempt` | `["*"]`; Write, Edit, MultiEdit, NotebookEdit, TodoWrite | what ends a grant (§5) |
| `taint_scope` | `"turn"` | `"session"`: HARDENING §3 |
| `kill_orphans`, `deny_background` | `false`, `false` | HARDENING §2 |
| `max_ttl`, `label` | 600; WebFetch, WebSearch, mcp__* | lifetime cap; results labelled DATA |
| `state`, `state_writer`, `layout_check`; `hermes_*` | home dir; none; on with a writer; §6 | HARDENING §1; Hermes |

## 5. Claude Code (gate/claude-code; hook facts checked live on 2.1.284 where marked)

- `UserPromptSubmit` gets the raw `prompt`, for **user** prompts only (live). The interactive TUI
  wraps a paste in one `<pasted_content id=…>` block and turns tabs into spaces (live): the gate
  unwraps exactly one whole-prompt block; tabs then break the hash (`sign.mjs` warns).
- `PreToolUse` gets `tool_name`, `tool_input`, `tool_use_id`, never the rest of the batch.
  `permissionDecision: "deny"` blocks; a parallel `"allow"` hook does not override it (live). The
  gate never says `"allow"`, so a granted call still meets the normal permission rules.
- **Exit codes.** 2 blocks; any other failure or timeout lets the call through. So the hook line
  ends in `|| exit 2`, errors exit 2, a watchdog answers within 1.8 s (writer: 1.2 s), each hook has
  `"timeout": 10`. `Stop` and `SessionStart` cannot block: their errors exit 0.
- Subagents fire the same hooks, same `session_id`. Slash commands fire `UserPromptExpansion`
  (closes the grant). Tool and hook processes carry `CLAUDE_CODE_SESSION_ID`, `CLAUDE_PID` (live).

`UserPromptSubmit` closes the previous grant and opens one until `exp` if the prompt verifies;
`PreToolUse` denies a privileged tool unless an untainted grant covers it (re-verified).

**Taint.** Any tool result can carry someone else's text, so every tool taints except `taint_exempt`
(the harness's own confirmations): `Read`, `Grep`, `WebFetch`, `mcp__*`, a subagent's report, a
granted `Bash`'s output. The taint is
recorded in `PreToolUse`, **before** the result exists (unrecordable → that tool is denied), and
again in `PostToolUse(Failure)`. After it, privileged tools are denied for the rest of the turn
unless the claims carry `taint_ok` (`sign.mjs --allow-after-read[=Edit,…]`).

So **a privileged call made after reading anything needs the operator's say-so at signing.** A
signed turn is one action by default: `run npm test` gets one `Bash`, a second is denied. "Read the
failing test and fix it" needs `--allow-after-read`, vouching for what the files say. Same batch,
session scope, subagents: HARDENING §3.

## 6. Hermes (gate/hermes)

A standalone plugin (`register(ctx)`, opt-in via `plugins.enabled`) on three hooks:
- `pre_gateway_dispatch` on gated platforms (A2A): a verified instruction is labelled and opens a
  grant for that chat; anything else is fenced as `<sigelo_data …>` and closes it.
- `pre_tool_call` blocks a privileged tool (`hermes_privileged`: terminal, process_manage,
  execute_code, write_file, patch, delegate_task, cronjob_manage, browser_exec, browser_cdp,
  computer_use, skill_manage, memory, browser_vault_*; MCP writers by §4) in a gated chat with no
  untainted grant. Every other tool except `hermes_taint_exempt` (write_file, patch, todo_list)
  taints the grant before it runs (read_file, search_files, web_*, browser_*, vision_analyze, …).
  The plugin catches its own errors and blocks. CLI and cron sessions are left to Hermes' approvals.
- `transform_tool_result` fences A2A client results and records the taint again, as a backstop.

Limits: in-memory, one process; never run inside Hermes. **The operator key never sits where the
agent can read it**: under Hermes that is a full bypass (it signs A2A messages); in Claude Code a
stolen key alone grants nothing.

## 7. Open decisions

- **Defaults:** `taint_scope`, `kill_orphans`, `deny_background`; is `WebFetch` privileged? **TTL**?
- **Signing UX:** `sign.mjs` and paste today; an alias, a key on the phone, a hardware key.
- **Pinning** a genesis or a rotating bundle. **Shipping** as a sigelo package, a Hermes plugin, both.
