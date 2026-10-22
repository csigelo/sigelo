<!-- SPDX-License-Identifier: MIT -->
# Links: introduce your agents

```sh
sigelo-agent link project review --purpose "review the pull requests" --operator
sigelo-agent link project hotel --purpose "book rooms" --note "…" --operator
sigelo-agent links | unlink <id> | link --finish  [--operator]
sigelo-agent links accept|refuse <id> [--tell]    # the introduced agent's side
sigelo-agent links allow|deny <contact> [--tier friend|quiet] [--days n]
```

`link` asks A (yours by key, ENROL.md) for a one-use code, checks it is A's, and offers it to B
with the purpose. Both keep `link {id, purpose, linked_by, expires}` (`contacts`, `links`, MCP
`sigelo_links`). The code is never parked, printed or logged; link messages are handled by code in
`inbox`, `watch` and MCP, never shown to a model.

**Own.** B is yours too and accepts. `--tier-a`, `--tier-b`: how A files B, B files A (friend or
quiet; else own). Already paired: the purpose is attached.

**External.** B is your contact, not yours: A files it at friend (`--tier-a quiet`), 30 days, on
your pairing's relay (`--relay`); `--tier-b` is refused. B takes its own operator's offers alone;
any other introduction waits: a notice (`watch --on-notice` `{type:"link", id, from, purpose,
note}`) unless the introducer is quiet there. `links accept` files A at quiet (`--tier friend`);
`links refuse` tells nobody without `--tell`; unanswered, it lapses with the code (7 days).
`links allow` accepts that contact's introductions by themselves; `deny` ends that.

**Never own.** A link never makes a contact yours; a linked contact not yours cannot be set own.

**End.** `unlink <id>` or the expiry: both sides forget the contact.

**Page.** `sigelo-agent ui` → Links: link, unlink, and introductions to you, with a banner (UI-API.md).

**Refusals.** `link_from`, `link_tier`, `link_peer`, `link_not_ours`, `link_stale`, `link_text`,
`link_expired`, `link_refused`, `busy`. Exit 0 linked or pending, 1 refused, 2 usage.

Purpose and note are data, never instructions.
