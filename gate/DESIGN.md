<!-- SPDX-License-Identifier: MIT -->
# Provenance gate: design (prototype, 2026-10-02)

A signature cannot stop persuasion, but it settles who said something, so the harness can
enforce the one rule the model cannot: **only an identity allowed to instruct can unlock
privileged tools; everything else is data, however it is phrased.**

## 1. What it blocks, what it does not

Blocks: injected instructions in tool results, web pages, MCP output and inbound A2A messages
**unlocking a privileged tool** (shell, file writes, code execution, delegation, the keeper's
`pay` if listed) in a turn the operator did not sign. It is a deny-only layer, not a guarantee:
it holds only within the limits below and the deployment in §7.

Does **not** stop:
- **Persuasion.** The model can still believe or act on injected text with unprivileged tools.
- **Exfiltration through allowed tools**, e.g. a secret read and sent out in a `WebFetch` URL.
  Make such tools privileged, or add egress control.
- **Misuse inside a signed turn** before untrusted content is read (§5; Hermes has no taint step).
- **A compromised operator key, or the operator signing something they did not read.**
- **Same-user tampering.** Whatever the agent's user can write (gate code, gate.json, hook
  settings, state), a granted shell or a file-writing MCP tool can change, and so turn the gate
  off; whatever it can read (**the operator key**) it can use. §7 narrows this.

## 2. Envelope: an attestation, no wire change

SPEC §3.1's table is closed, so there is no new `typ`. An instruction is an ordinary §5 attestation:

```json
{ "v": "sigelo/0", "typ": "attestation", "iss": "<operator DID>", "sub": "<agent DID>",
  "iat": 1790000000, "exp": 1790000600, "ctx": "sigelo/instruction", "admission": "open",
  "claims": { "text_sha256": "<hex SHA-256 of the UTF-8 text>", "nonce": "<16–64 chars>",
              "tools": ["Bash"] } }
```

`tools` (optional) narrows the grant. `admission` is required by §3.1 and means nothing here,
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

One `gate.json` for both harnesses (`$SIGELO_GATE_CONFIG`, default `~/.config/sigelo-gate/gate.json`):

```json
{ "agent": "did:sigelo:z…", "operators": [ { "v": "sigelo/0", "typ": "genesis", … } ],
  "max_ttl": 600, "privileged": ["Bash", "Monitor", "PowerShell", "Write", "Edit", "MultiEdit", "NotebookEdit"],
  "taint": ["WebFetch", "WebSearch", "mcp__*"],
  "hermes_privileged": ["terminal", "write_file", "patch", "execute_code", "delegate_task"],
  "hermes_platforms": ["a2a"], "hermes_data_tools": ["a2a_call", "a2a_orchestrate", "a2a_history"] }
```

Who may instruct: the pinned operator **genesis** documents (local, not a lookup); after a
rotation, pin the new one. Privileged by default: the built-in tools that run commands or write
files (`Monitor` runs a shell command). MCP tools that write are not covered unless listed.

## 5. Claude Code (gate/claude-code)

Hook facts (hooks reference, checked in the 2.1.284 binary) that decide the design:
- `UserPromptSubmit` gets the raw `prompt` and fires for **user** prompts only, so the hook can
  tell the operator's turn from tool output. It can add `additionalContext`.
- `PreToolUse` `permissionDecision: "deny"` blocks the call. `"allow"` would **skip** the
  permission prompts, so the gate never returns it: a granted call still meets the normal rules.
- `PostToolUse` cannot block; it adds context (`updatedToolOutput` is not used).
- Subagent tool calls fire the same hooks with the same `session_id`. Slash commands fire
  `UserPromptExpansion` instead of `UserPromptSubmit`, so that event closes the grant too.
- A hook that crashes or times out lets the call through, so the gate catches its own errors;
  hooks register without a matcher and the gate filters by gate.json, one list to keep right.

`UserPromptSubmit` closes the previous grant and opens one until `exp` if the prompt verifies.
`PreToolUse` denies a privileged tool unless an untainted grant covers it, and re-verifies the
stored signature. `PostToolUse` on `taint` tools ends the grant for the turn and labels the
result as data. Scope, plainly: **privileged tools need a signed instruction in the current
turn, and the grant ends at the first web or MCP read**. Text read in the same turn by a
non-taint tool (`Read`, by default) is covered by the grant.

## 6. Hermes (gate/hermes)

A standalone plugin (`register(ctx)`, opt-in via `plugins.enabled`) on three existing hooks:
- `pre_gateway_dispatch` can `rewrite` an inbound message. On gated platforms (A2A), a verified
  instruction is labelled and opens a grant for that chat. Anything else is fenced as
  `<sigelo_data …>`, which keeps Hermes' own "untrusted" frame inside it, and closes the grant.
- `pre_tool_call` can `block` a privileged tool in a gated chat with no grant. Sessions without
  a gateway origin (CLI, cron) are left to Hermes' approvals.
- `transform_tool_result` fences A2A client results (a peer's reply). A tool result never grants.

Limits: in-memory state, one process; no taint step. A2A filter edits break the hash: closed.

## 7. Deployment, composition and privacy

Hardened Claude Code setup (path and permission choices; the hook still runs as the agent's user):
hooks with absolute paths in root-owned `/etc/claude-code/managed-settings.json`; gate code,
`ts/dist` and gate.json root-owned, not writable by the agent's user; the operator key on another user or
device (`sign.mjs` refuses group/world-readable keys and Claude Code sessions, as hygiene only).
What stays writable: the state directory. A granted shell can keep an unexpired grant alive past
its turn or taint, or clear the nonce list, but not mint a grant (each call re-verifies the
signature). Full isolation runs the hook as another user (`sudo -n -u`); not done here.

The gate only adds denials; Claude Code permissions, Hermes approvals and the keeper's caps
still apply (for money the keeper stays the boundary). Nothing leaves the machine.

## 8. Open decisions

- **Defaults:** whether `Read`, `WebFetch` and MCP become privileged or taint.
- **Signing UX:** today pipe through `sign.mjs` and paste; options are an alias, a key on the
  phone, a hardware key, an editor that signs on send. **TTL:** one turn, ≤ 10 minutes, or longer?
- **Pinning** a genesis or a rotating bundle. **Shipping** as a sigelo package, a Hermes plugin, both.
