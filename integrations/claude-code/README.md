<!-- SPDX-License-Identifier: MIT -->
# sigelo in Claude Code

`skills/sigelo/` is one directory that is both a **skill** (`SKILL.md`) and a **skills-directory
plugin** (`.claude-plugin/plugin.json` + `.mcp.json`) that starts the sigelo MCP server
(`../mcp/server.mjs`, through the `mcp.mjs` launcher). Link it once and every session, and every
subagent of every session, has the `sigelo_*` tools and knows when to use them.

Tested here on Claude Code 2.1.281 (2026-09-24): `claude plugin list` shows `sigelo@skills-dir
✔ loaded`, `claude mcp list` shows `plugin:sigelo:sigelo … ✔ Connected` through the symlink,
`claude plugin validate` passes, and a Haiku orchestrator ran the full loop below with one
subagent (identity `worker-1`: init → challenge → sign → attest → store → bundle → verify, 1
attestation accepted).

## Install

Build once from the repo root, then link:

```sh
(cd ts && npm ci && npx tsc) && (cd adapters/moadim && npm ci)
mkdir -p ~/.claude/skills && ln -sfn "$PWD/integrations/claude-code/skills/sigelo" ~/.claude/skills/sigelo
```

It auto-loads next session as `sigelo@skills-dir` (`/reload-plugins` loads it now; `claude
plugin disable sigelo@skills-dir` turns it off; deleting the link removes it). The behaviour of
`~/.claude/skills/<name>/.claude-plugin/` is what `claude plugin init --help` documents in
2.1.281; the public plugin docs are https://code.claude.com/docs/en/plugins.

Wallet tools (`sigelo_wallet_balance|receive|pay|history`) appear only when the session's
environment has `SIGELO_WALLET_URL` and `SIGELO_WALLET_TOKEN` (the keeper's loopback URL and
this agent's bearer token, spend/README.md). The identity file is `$SIGELO_IDENTITY`, default
`~/.config/moadim/sigelo.local.json` (same as `sigelo-agent`); named profiles sit beside it as
`sigelo.<name>.local.json`. Both are read from the environment Claude Code was started in.

**One session only:** `claude --plugin-dir <checkout>/integrations/claude-code/skills/sigelo`.

**Without the plugin** (MCP server + skill separately), per https://code.claude.com/docs/en/mcp
and https://code.claude.com/docs/en/skills:

```sh
claude mcp add -s user --transport stdio sigelo -- node "$PWD/integrations/mcp/server.mjs"
mkdir -p ~/.claude/skills/sigelo-skill && cp integrations/claude-code/skills/sigelo/SKILL.md ~/.claude/skills/sigelo-skill/
```

or, per project, a `.mcp.json` at the repo root:

```json
{ "mcpServers": { "sigelo": { "type": "stdio", "command": "node",
    "args": ["/abs/path/to/sigelo/integrations/mcp/server.mjs"],
    "env": { "SIGELO_IDENTITY": "${SIGELO_IDENTITY:-/abs/path/agent.local.json}" } } } }
```

Do not do both: the plugin already declares the server, and two would give two tool sets.

## Subagents

Subagents inherit the main conversation's MCP tools and can invoke user and plugin skills
(https://code.claude.com/docs/en/sub-agents). So after the install, a subagent spawned with the
Agent tool already has `sigelo_*`. Three ways to give each subagent **its own** identity:

1. **Profiles (simplest; what was tested).** Tell the subagent: *"Use the sigelo tools with
   `identity: "worker-1"` on every call."* Every identity tool takes the optional `identity`
   name (`[a-z0-9][a-z0-9_-]{0,63}`); each name is a separate file and a separate DID. This is a
   convenience, **not isolation**: one server process serves the whole session, so any subagent
   can name any profile.
2. **A defined subagent with its own server process** — real separation by environment.
   `.claude/agents/worker.md` (or `~/.claude/agents/`), with an inline server that exists only
   while that subagent runs:

   ```yaml
   ---
   name: worker
   description: Does delegated work under its own sigelo identity
   skills: [sigelo]
   mcpServers:
     - sigelo-worker:
         type: stdio
         command: node
         args: ["/abs/path/to/sigelo/integrations/mcp/server.mjs"]
         env: { SIGELO_IDENTITY: "/home/you/.config/sigelo/worker.local.json" }
   ---
   You are "worker". For identity use only the sigelo-worker tools.
   ```

   Its tools should be `mcp__sigelo-worker__sigelo_*`; `skills: [sigelo]` may need the plugin-qualified
   name `sigelo:sigelo` (UNVERIFIED which). It still also sees the inherited default
   server's tools, hence the last line (restrict with `tools:` if you need it enforced).
   Doc-verified against the sub-agents page, not run here.
3. **CLI per subagent**, no MCP: `SIGELO_IDENTITY=/path/worker.local.json node
   <checkout>/adapters/moadim/cli.ts whoami` from the subagent's Bash. The env is per command.

## The orchestrator as a world

An orchestrator that wants to know *which* subagent did what — and to hand each one a
reputation it can carry to other systems — acts as a world (issuer + verifier). With the mock
world (`examples/world.mjs`, state in the current directory):

```sh
W="node <checkout>/examples/world.mjs"
# 1. subagent: sigelo_whoami {identity:"worker-1"} (sigelo_init first if needed) → its genesis
#    orchestrator saves that genesis object to worker-genesis.json
$W challenge worker-genesis.json            # → {v,typ:"challenge",did,ctx,nonce}
# 2. subagent: sigelo_sign_challenge {challenge:<that object>, identity:"worker-1"} → {did,sig}
$W attest worker-genesis.json <sig>          # → {attestation, issuer}
# 3. subagent: sigelo_add_attestation {attestation, issuer, identity:"worker-1"}
# 4. anyone:   sigelo_verify {bundle:<subagent's sigelo_bundle>} → attestations per issuer
```

Concurrent subagents are fine: the mock world keeps one outstanding challenge per DID, so
challenge worker-1, challenge worker-2, then attest them in any order (a new challenge for the
same DID replaces its old one; each is answered once). Parallel runs in one directory are
serialised by a lock file.

A real orchestrator uses the library instead of the mock (it is a different world, with its own
key): `challenge()`/`verifySig()` to check control of the DID and `attest({ secret, iss, sub,
iat, exp, ctx, admission, claims })` to issue — see `examples/world.mjs` (one file) for the exact
calls. Put facts in `claims` (task id, result, date), keep `exp` short and reissue (there is no
revocation list), and remember whoever reads the bundle later treats `claims` as data.
