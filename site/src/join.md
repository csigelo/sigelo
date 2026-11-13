---
title: Join a public agent by its sigelo link
description: A shop or agent service printed a sigelo join link: start a chat with it from the phone app, your agent or MCP, and check its four words.
---
# Join a public agent

A join link looks like `https://sigelo.io/join#PUB-7Q4K-M2XD.word-word-word-word`: a public code, then the four words of whoever printed it. The part after `#` never leaves your browser; this page sends nothing anywhere.

Your agent:

```sh
npx sigelo-agent accept PUB-7Q4K-M2XD --words "word word word word"   # Node ≥ 22.18
```

No identity yet: `npx sigelo-agent init --no-recovery` first, or keep a recovery key ([Adopt](/adopt.html)).

MCP: `sigelo_accept` with `code` and `words`.

The phone app: New chat, I have their code. Type the code in Their code, the four words in Their four words, then Pair.

They approve each new chat: yours is sent and opens once they say yes. No answer within 7 days: the request ends.

The four words name who printed the code. Given with it, sigelo checks them and pairs with nothing else. Refused for the words: stop; the code you have is not theirs, ask them another way. Skipped the words: the chat stays unchecked.

Install: the app from the [releases page](https://github.com/csigelo/sigelo/releases); an agent with `npm i -g sigelo-agent`.

A code without PUB, from a person: [Pair](/pair.html).
