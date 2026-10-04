<!-- SPDX-License-Identifier: MIT -->
<!-- DRAFT, NOT OPENED. Branch: https://github.com/csigelo/openclaw/tree/a2a-peer-resolver (commit 1a0937b0). Base: openclaw/openclaw main @ 120b4363 (newer than c52a2778).
Real diff: code 98+/5- (http.ts 54/3, runtime.ts 32/0, api.ts 6/1, runtime-api.ts 6/1); tests 86+/0 (http.test.ts).
The issue said "about 30 lines plus tests"; that was low. Timeout, fail-closed and the global registry account for most of it.
Upstream AGENTS.md says "no agent-attribution trailers": drop the Co-Authored-By/Claude-Session lines
(git commit --amend) before opening, or keep them knowingly. -->

# Title

feat(a2a): let plugins authenticate configured peers via a resolver hook

# Body

Refs #164508.

**What:** `registerA2aPeerResolver(resolver)` (exported from `@openclaw/a2a` `api`/`runtime-api`) returns an unregister function. When no configured token matches, `/a2a/v1` asks registered resolvers in order. A resolver may only name a peer already in `channels.a2a.peers`; any other name is ignored.

**Why:** the review on #164508 separates proving an identity from authorizing it. This hook covers authentication only. The operator allowlist still decides who may call, so routing, rate limits, task access and ingress keep using configured names. A plugin can accept a key-based proof instead of a shared secret.

**Fails closed:** a resolver that throws, rejects, returns nothing or takes longer than 5 s gets the same 401, never a 500. Configured tokens are checked first, and that constant-time comparison is unchanged. The registry is cleared when the plugin registry reloads.

**Compatibility:** with no resolver registered, behaviour is the same.

**Question:** `peers.<name>.token` is still required. Should it be optional for resolver-only peers? I left the validation as it is.

**Tested:** `pnpm test:extension a2a` (100 passed, 8 new), oxfmt, oxlint, tsgo.

Prepared with AI assistance.

# Command (do not run until approved)

```sh
gh pr create -R openclaw/openclaw --head csigelo:a2a-peer-resolver --base main \
  --title "feat(a2a): let plugins authenticate configured peers via a resolver hook" \
  --body-file <(sed -n '/^# Body$/,/^# Command/p' adoption/openclaw-pr-draft.md | sed '1d;$d')
```
