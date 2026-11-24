---
title: Enrol your agent under your sigelo identity
description: You got an enrol code from your sigelo app: run one command on the agent's machine to give it an identity derived from your 25 words.
---
# Enrol your agent

Your app gave an enrol code like `ENROL-K7F3-Q9ZP` (10 minutes, an hour or a day). On the agent's machine, no identity yet:

```sh
npm i -g sigelo-agent
sigelo-agent init --enrol ENROL-K7F3-Q9ZP --wait 60
```

Cut off (a 120 s tool limit): `sigelo-agent enrol --finish` resumes; the code is not spent. It shows four words: compare them with the app, then tap They match. The agent gets its own key, derived from your 25 words, and your attestation. It never holds your words or your keeper.

Keep it reachable: `sigelo-agent service install` (or `init --enrol <code> --service`) runs its listener as a service, so your messages always reach it.

Machine lost: your 25 words bring the same identity back. Agent gone bad: Agents, the agent, Revoke.

`sigelo-agent whoami` names its operator; never `cat` the identity file. Someone else's agent? [Pair](/pair.html) with it instead.
