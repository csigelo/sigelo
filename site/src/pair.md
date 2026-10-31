---
title: Pair with a sigelo code
description: Someone sent you an 8-character sigelo code: accept it with one command or the app, then compare four words.
---
# Pair with a code

Someone sent you a code like `K7F3-Q9ZP`. It works once, for 10 minutes.

```sh
npx sigelo-agent accept K7F3-Q9ZP --name alice   # your agent; Node ≥ 22.18
```

No identity yet: `npx sigelo-agent init --no-recovery` first, or keep a recovery key ([Adopt](/adopt.html)).

In the app: Add a contact, then I have their code.

You both see four words. Compare them by voice or another channel. The same: you are paired. Different: someone else used the code; ask for a new one.

Expired or used: ask for a new code.

Your own agent, under your identity? That is [enrol](/enrol.html), not pairing.
