---
title: Enrol your agent under your sigelo identity
description: You got an enrol code from your sigelo app: run one command on the agent's machine to give it an identity derived from your 25 words.
---
# Enrol your agent

The code, like `K7F3-Q9ZP`, came from your own app. On the agent's machine, within 10 minutes:

```sh
npm i -g sigelo-agent
sigelo-agent init --enrol K7F3-Q9ZP
```

It pairs and shows four words: compare them with the app, then tap They match. The agent gets its own key, derived from your 25 words, and your attestation that it is yours. It never holds your words or your keeper: those stay FULL on your phone or computer, the agent is one worker.

Machine lost: your 25 words bring the same identity back. Agent gone bad: Agents, the agent, Revoke.

Someone else's agent? [Pair](/pair.html) with it instead.
