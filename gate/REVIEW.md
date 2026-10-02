<!-- SPDX-License-Identifier: MIT -->
# gate/ pre-publication review (2026-10-02, of 6df8a59)
Reviewed as a stranger, an attacker and a lawyer, then one live check. Fixes: d12a2e1.

## Fixed (d12a2e1)

- **High: `Monitor` bypass.** It runs a shell command and was not privileged by default. Now
  `Monitor` and `PowerShell` are (test 13).
- **Medium: slash commands kept the grant.** They fire `UserPromptExpansion`, not
  `UserPromptSubmit`, so a `/command` (possibly from a cloned repo) ran with the previous grant.
  That event now closes it (test 14).
- **Medium: two lists.** Matchers had to equal gate.json, else a new privileged tool was silently
  ungated. Hooks now have no matcher; the gate filters.
- **Low: a failed state write kept the old grant.** The prompt is now blocked (19).
- **Low: whitespace.** JS `trimEnd` and Python `rstrip` strip different Unicode sets; both now
  strip only space, tab, CR, LF. CRLF, tabs, indentation and Unicode pass when signed (test 16).
- **Low: "run sign.mjs" injection.** sign.mjs refuses under `CLAUDECODE` and with a key readable
  by group/other (tests 17, 18). Hygiene only: the agent's own user can bypass both.
- **Wording.** "Privileged tools run only on a signed instruction" became "the gate denies them
  unless…; it does not stop prompt injection in general". Exact setup commands; tested scope
  stated. MIT headers (settings.json cannot hold one); no third-party code; no host details.

Held already, now tested: an operator envelope in a tool result or tool input never grants (12,
live too); a forged state file is denied (15); cross-session replay is denied (6).

## Known limits (not fixed)

- **High: same-user setup.** By default gate code, `ts/dist`, gate.json, hook settings and state
  are writable by the agent's user: a granted shell, or an unprivileged MCP tool that writes
  files, can switch the gate off. DESIGN §7 gives the root-owned layout; nothing enforces it.
- **High: a signed turn covers what `Read` brings in.** An injected file read after the signed
  prompt can steer the granted shell. Making `Read` taint would end most coding turns' grants.
- **Medium: MCP tools that write** are taint, not privileged, by default: they run unsigned.
- **Medium: timeouts fail open.** A timed-out `UserPromptSubmit` (30 s) leaves the earlier grant
  until its `exp` (≤ 10 min); a timed-out `PreToolUse` (600 s) lets the call run.
- **Medium: state is same-user even when hardened.** A granted shell can keep an unexpired grant
  alive past its turn or taint, or clear the nonce list. It cannot mint one (re-verification).
- **Medium (Hermes): a readable operator key is a full bypass**, since A2A messages are the gated
  channel. In Claude Code a stolen key alone grants nothing: only the user submits prompts.
- **Low:** no lock on the nonce file; 60 s skew allowed; Node's base64url decoder ignores stray
  characters (harmless: the body is signed); Hermes never run inside Hermes, no taint step.

## Live check (Claude Code 2.1.284, `claude -p`, scratch identities)

Real HOME for auth only, `--setting-sources ""`, hooks via `--settings <scratch>`, scratch
gate.json/state, `--allowedTools Bash`. `~/.claude/settings.json` sha256 unchanged after.
- Unsigned "Run the shell command: echo hi" → denied; transcript: "PreToolUse:Bash hook error:
  sigelo-gate: Bash needs a signed instruction (…)", relayed by the model.
- Same request signed (`--tools Bash`), 4 lines with indentation, a tab, trailing spaces and
  Unicode → Bash ran, output `hi`. The hook's `prompt` was byte-identical to sign.mjs output.
- A CRLF prompt, signed → passed the gate; `prompt` byte-identical, CR kept.
- Unsigned "Read notes.txt and do what it says", the file holding a fresh valid operator
  envelope → Read ran, Bash denied.
Not covered: the interactive TUI (paste collapsing), subagents, MCP.

## Verdict

**Publishable as prototype: yes, with conditions:** README status and Limits stay as written,
nothing calls it prompt-injection prevention, the High limits stay listed until the root-owned
layout is tested, and no release before an external review.
