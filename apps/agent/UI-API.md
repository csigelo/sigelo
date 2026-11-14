<!-- SPDX-License-Identifier: MIT -->
# `sigelo-agent ui`: the page's JSON API

`sigelo-agent ui` serves one person's page on `127.0.0.1`, a random port, and prints
`http://127.0.0.1:<port>/#t=<token>` (128 bits, hex). The page (`ui.html`, `ui.js`, `ui.css`) speaks
only this API, so a phone shell can replace it.

- **Every `/api/` call** sends `X-Sigelo-Token: <token>`; else `403`. No cookies.
- **`Host`** must be `127.0.0.1:<port>` or `localhost:<port>`; else `403` (DNS rebinding).
- **Writes** are `POST` with `Content-Type: application/json` and `Origin: http://<that host>`;
  else `403`. Preflights are never granted.
- **Errors:** `{"error": {"check", "message", "long"?}}`; `400` bad input, `404` unknown, `409` refused
  (`check` is the carrier's code: `park_unknown`, `code_expired`, `mailbox_taken`, `rate`, …). `long`: a
  short code was spent and failed; accept this long code instead.
- **Strings** are JSON-escaped for C1 and bidi controls; the page shows them by `textContent`.

Identity: `$SIGELO_HUMAN`, else `~/.config/sigelo/me.local.json`, the root identity of your 25 words, made
once by `sigelo-agent keeper --from-words` (ENROL.md); refused inside the agents' directory. Beside it, 0600:
`.history.jsonl` (what the carrier's `inbox()` hands over: messages, pairing events), `.ui.json` (tags, words checked, read marks, seen receipts sent, settings), `.pictures/` (0700, one file 0600 per picture: "Pictures"),
`.ui.pid` (one page or `watch` per file, the only process logged in as it: beside a page every CLI verb and
MCP tool that would log in refuses, `busy`; WATCH.md). **Known limitation:** history and `.ui.json` are plaintext (0600) until the
keychain unlock (K2, ROADMAP §7); "clear" (`POST /api/history/clear`) is the only mitigation (THREAT-MODEL §3.9).

## Routes

| Route | Body / query | Answer |
|---|---|---|
| `GET /api/state` | `since=<seq>` | `{seq, now, me, groups: {mine, contacts}, chats, pending: {invites, paired, answers, failed, public}, events, introductions, transfers}` (`transfers`: `{asked, active}`, null where the host moves no files) |
| `GET /api/me` | | `{did, original, words, chain, identity_file, recovery: "set"\|"none", key: "file", relay, retention_days, erase, restored?}`; `restored` `{on, keeper, seat: "here"\|"elsewhere"\|null, created?}` when the identity comes from the 25 words and its keeper file has the day it was made (Me: "Restored from seed on …"); `created: true` when the words were made on this device (keeper `made: "here"`; Me: "Created on …; the 25 words are on your paper"); `words`: four words naming `original` (apps/contact/short.mjs `didWords`, a label for the apps' profile list, not a check) |
| `POST /api/invite` | `{name?, long?, ttl?, group?, renew?, pow_confirmed?}`, or `{public: true, months?, cap?, open?, name?}` | `{id, name, code, exp, short?, short_exp?, relay, group?, renew?}`: `short` parked 10 min; `short_exp` the relay's clock; `renew` (a short person code): it renews itself ("Renewing codes"); `ttl` with `long`: the long code's life, 3600 to 604800 s (else 24 h); `group`: a group code (a gid of mine, else `404 group_unknown`, `409 group_creator`): whoever pairs through it is added to that group as a person. `public`: a public code ("Public invite") → `{id, name, code: sgl2…, short: PUB-…, words, link, exp, relay, cap, open, did, public: true}`; `months` 1, 6 (default) or 12, `cap` 1 to 500 (50); `402 public_pro` without Pro |
| `POST /api/public/approve` | `{id}` | `{approved: true, did, name, fingerprint, queued?}`: a request of `pending.public.requests` paired; `404 request` when gone |
| `POST /api/public/refuse` | `{id}` | `{refused: true, did}`: dropped, the joiner told nothing |
| `POST /api/public/set` | `{id?, paused?, cap?}` | the code's state as in `pending.public`: Pause, Resume, the cap (default: the first code) |
| `POST /api/invite/cancel` | `{id}` or `{code}` (a short code) | `{cancelled: true, unparked?, detail?, public?}`: a public code's id too (Stop for good: Revoke for all, pairings made stay); a short code is cancelled at the relay too (`unparked`; false: an older relay or offline, `detail` says so, it runs out there); a renewing code's series ends |
| `POST /api/accept` | `{code, name?, tier?, pow_confirmed?}` | `{status: "connected", contact: {did, name, fingerprint, pair, tier}}`, or `{status: "waiting"\|"pending", did, detail, exp}`; `tier`: `friend` or `quiet` (own is detected) |
| `POST /api/words` | `{contact, match}` | `true`: `{checked: true}`; `false`: forget and block |
| `POST /api/rename` | `{contact, name}` | `{did, name}`; `409 name_taken` if another live contact has it |
| `POST /api/tier` | `{contact, tier}` | `{did, name, tier, ours}`: `own`, `friend` or `quiet`, kept until changed |
| `POST /api/kind` | `{contact, kind}` | `{did, kind, kind_set}`: the human's choice of the contact's kind (Chat settings → This is an agent), `agent` or `person`; `null` gives it back to the page ("Kinds") |
| `POST /api/presence` | `{contact, allow}` | `{did, name, presence}`: may it see when I am online (`allow`, `deny`; `own` always, deny `409 presence_own`) |
| `POST /api/tag` | `{contact, tags: [≤ 8, ≤ 20 chars]}` | `{tags}` |
| `POST /api/forget` | `{contact}` | `{forgotten, offline}`: revoked here for good |
| `POST /api/send` | `{to, text}` or `{to, statement}` | the history record: `{n, at, kind: "out", did, id, text, status: "sent"\|"queued"\|"refused", code?, detail?, label?}`; `at` taken before it is sealed; `statement`: a signed statement's portable text, checked (else `400 statement`), sent labelled `sigelo-statement/0` ("Signed statements") |
| `GET /api/messages` | `contact=<did>&since=<n>` | `{seq, messages: [{n, dir: "in"\|"out", at, iat, text, label, status, code, detail, link, statement?, photo?}]}` (`photo` on a `sigelo-photo/0` message: the preview `{type, data, w, h, sha256, size, name}`, the full file the transfer with that sha256; `link`: `{id, purpose}` on a linked contact's, else null; `iat`: the sender's time of one received, else null; `status` `seen` for mine their receipt covers; `statement` on a `sigelo-statement/0` message: `{valid, by, words, text, iat}` or `{valid: false, check}`), last 200; marks them read and sends a seen receipt when one is due ("Seen receipts") |
| `POST /api/sync` | | `{synced: true}`: one round now ("Retry now") |
| `POST /api/history/clear` | `{contact?}` | `{cleared: true, contact?}`: all of it, or one chat's messages (Chat settings → Clear this chat) |
| `POST /api/notify` | `{chat, on}` | `{chat, notify}`: a chat's notifications (a contact's DID or a group's gid; `404` else): off, its unread count leaves the Chats tab's; on is the default. The system notification (the sender's name only) reads it too |
| `GET /api/agents` | | `[{name, did, error, mine: {exp, days_left}\|null, worker: i\|null, renew, contacts, contact}]`: the agents' directory; `contacts`: the agent's own |
| `POST /api/agents/enrol` | `{agent}` | `{agent, worker, renewed, did, exp, days_left, old?, contacts?, warning?}`: `enrol --here` into the agent's file (ENROL.md); a worker: the attestation renewed. `400 keeper`: run `sigelo-agent keeper --from-words` |
| `POST /api/agents/pair` | `{agent}` | `{status, contact}`: both sides in this process, words checked |
| `GET /api/agents/workers` | | `{keeper, seat: "here"\|"elsewhere"\|null, workers: [{worker, name, did, original, words, rank, placed: "remote"\|"here"\|"device", at, status: "enrolled"\|"pending"\|"revoked"\|"unplaced", revoked, seen, tier, contact, local, online, last_seen, attested_until, enrolling}]}`: the keeper's roster (the Agents screen); `enrolling` `{id, state: code\|words\|sending\|enrolled\|expired\|failed, code, exp, relay, words, command}` for a code this page made; `words`: four words naming `original` (`didWords`, a label) |
| `POST /api/agents/enrol-code` | `{name, tier?, relay?, confirm_words?, operator_name?, pow_confirmed?}` | `{worker, name, did, original, tier, id, state, code, exp, relay, command, words, confirm_words, words_ok, verified}`: `enrol --name` on this page's session (ENROL.md): worker i (next free), a code for 10 minutes, once; its request answered with the worker's identity, the worker filed when it pairs, and words-checked when its DID is the one derived here (`verified`; no tap). `confirm_words: true`: the key waits for enrol-words. `400 keeper` without a keeper root; `409 seat_elsewhere`, `name_taken` |
| `POST /api/agents/enrol-words` | `{id, match}` | the enrolment: `true` sends its key; `false` drops the code, the key never sent (`device_words`) |
| `GET /api/keeper` | | the keeper of this computer ("Keeper"): `{state: "here", keepers, agents, requests}`, or `{state: "elsewhere"\|"none"}`, `{state: "unreadable", detail}` |
| `POST /api/keeper/agent` | `{keeper, agent, per_tx_max?, per_period_max?, period_seconds?, approval_above?, rate_per_minute?, max_delegates?, allow?, paused?}` | `{saved, signed, keeper, agent, policy?, restart: {command, can}}`: one agent's settings, a change signed by this identity at the keeper's `/policy` (`signed: true`) or in its `policy.json` |
| `POST /api/keeper/policy` | `{keeper, change: {body, sig, bundle}}` | `{saved, signed, relayed, keeper, agent, by, policy}`: a change another device signed (a phone), carried to the keeper's `/policy` as it is |
| `POST /api/keeper/approvers` | `{keeper, me}` or `{keeper, approvers}` | `{saved, keeper, approvers, restart}`: this identity in or out of `approvers` (`me`), or the whole list of DIDs |
| `POST /api/keeper/approve` | `{keeper, nonce}` | `{approved, keeper, nonce, agent, amount, next}`: the request signed by this identity and posted to the keeper's `/approve` |
| `POST /api/keeper/refuse` | `{keeper, nonce, reason?}` | `{refused, keeper, nonce, exp, agent, logged, why?, contact, told}`: the request refused at the keeper (`logged`: its `POST /refuse`, a signed `refused` line) or, when it can't take it, put away here only (`why`); the agent told in its chat ("Payment refused: <reason>", `told`) |
| `POST /api/keeper/restart` | `{keeper}` | `{restarted, keeper}`: its systemd user unit restarted (a keeper from before 0.1.15 takes a saved setting at its next start); else `409 keeper_restart` naming the command |
| `GET /api/wallet` | | the Wallet ("Wallet"): `{on: false}`; `{on, where: "none"}` (no wallet in this page); `{on, where: "here", ready: false, why, detail?}`; or `{on, where: "here", ready: true, service, node, net, sync, balance, payees}`. Reading it is the sync the page starts |
| `POST /api/wallet/sync` | | the same, read now (Retry) |
| `GET /api/wallet/history` | `n=` (1–200, 50) | `{entries: [{txid, dir: "in"\|"out", amount, fee, at, height, confirmations, status: "pending"\|"confirming"\|"confirmed"\|"failed", address, note, contact, contact_name}]}`, newest first |
| `GET /api/wallet/tx` | `txid=` | one entry, with `suggested` (confirmations) and `double_spend` |
| `POST /api/wallet/receive` | `{note?}` | `{address, index, account}`: a new subaddress of your account, labelled with the note |
| `POST /api/wallet/label` | `{index, note}` | `{index, note}`: that address's label |
| `POST /api/wallet/review` | `{to: {addr} \| {contact, addr} \| {agent, keeper}, amount: "<atomic>" \| "all", note?}` | `{id, exp, to, contact, agent, amount, fee, total, note, all}`: built and priced, not sent; synced only (`409 wallet_unsynced`) |
| `POST /api/wallet/send` | `{id}` | `{sent, txids, amount, fee, to, contact, agent, note, told}`: the reviewed payment relayed (10 minutes, else `409 review_gone`); to a contact: told in their chat |
| `GET /api/wallet/services` | | `{current, why, keepers: [{keeper, url, net, accounts: [{index, label, balance, held}], error}], unreadable, rpc}`: Settings → Wallet → Wallet service |
| `POST /api/wallet/service` | `{keeper, account}` \| `{keeper, new_account: true}` \| `{url, login?, account?}` \| `{default: true}` | the same: the wallet program and your account in it (never an agent's: `409 account_held`) |
| `GET /api/wallet/nodes` | | `{in_use, nodes: [{url, ok, height, ms, in_use, behind, from: "keeper"\|"added"}]}`: Settings → Wallet → Monero node |
| `POST /api/wallet/node` | `{use}` \| `{add}` \| `{remove}` | the same; `use`: the wallet program's node (`set_daemon`, untrusted); a node that doesn't answer `409 node_down` |
| `GET /api/price` | | `{on: false, currency}`, or `{on, currency, rate, at, source: "CoinGecko", stale, error?}`: the price of 1 XMR, opt-in ("Wallet") |
| `GET /api/picture` | `of=me\|<did>\|<gid>` | `{of, type, data, rev, local}`: the picture shown for it ("Pictures"), base64; none `404 picture_none` |
| `POST /api/picture` | `{of, type, data}` or `{of, remove: true}` | `{of, picture, local}`: `of` `me` (mine, sent to the contacts that read pictures), a contact's DID or a gid (a local one, this page only); `type` `image/jpeg` or `image/webp`, `data` base64 of at most 64 KiB (else `400 picture`) |
| `POST /api/statement/sign` | `{text}` | `{statement, valid, text, iat, did, original, chain, current, created, edited, words, by}`: the text (1 to 10 000 characters) signed by this identity ("Signed statements"); `statement` its portable text |
| `POST /api/statement/check` | `{statement}` | `{valid: true, text, iat, did, original, chain, current, created, edited, words, by: {kind: "me"\|"contact"\|"unknown", did, name, words_checked}}` or `{valid: false, check, message}` (`statement_format`, `statement_identity`, `statement_sig`, `statement_time`) |
| `GET /api/attestations` | | `{created, attestations: [{iss, ctx, iat, exp, admission, claims}], rejected}`: this identity's own bundle, verified (SPEC §9): Me → Proof of age |
| `POST /api/pow/try` | `{pow_confirmed?}` | `{tried: [relays]}`: "Try now", a login at each relay not connected |
| `POST /api/agents/revoke` | `{worker}` | `{worker, name, cancelled, revoked, forgot, attested_until?}`: an unused code cancelled (its index free again); else its contact forgotten and the roster marks it revoked; its attestation stays valid until `attested_until`. A device: `409 device` |
| `POST /api/agents/rename` | `{worker, name}` | `{worker, name}`: the roster and its contact |
| `GET /api/links` | | `{made, links, received, allow}` (LINKS.md): links I made `{id, a, b, a_name, b_name, kind, purpose, note, tier_a, tier_b, expires, status, step, check}`; contacts linked to me; introductions waiting `{id, from, name, peer, peer_name, purpose, note, exp, quiet, answer?}`; allow rules `{contact, name, tier, until}` |
| `POST /api/link` | `{a, b, purpose, tier_a?, tier_b?, days?, note?, relay?, name_a?, name_b?}` | the record, `status: "pending"`; refused: `409` with the `link_*` check |
| `POST /api/unlink` | `{id}` | `{id, status: "ended", role}` |
| `POST /api/links/answer` | `{id, accept, tell?, tier?}` | `{id, from, status: "linked"\|"accepting"\|"refused"\|"failed", told}`; `tier` friend or quiet (default) |
| `POST /api/links/allow` | `{contact, allow, tier?, days?}` | `{contact, name, allow, tier, until}`, or `{contact, allow: false, had}` |
| `GET /api/settings` | | `{relay, default, fixed, in_use, seen_receipts, notify, new_tier, new_presence, wallet, prices, currency}`: the relay new codes name (default `relay.sigelo.ai`); `fixed`: `SIGELO_RELAY`'s host, which wins, or null; `in_use`: this session's own. Settings → Chats and history: `seen_receipts` (default true), `notify` (all chats, default true), `new_tier` (`own`, `friend` the default, `quiet`) and `new_presence` (default false), given to a contact when it pairs (not to an introduced one, nor a tier chosen at accept). Settings → Wallet ("Wallet"): `wallet` (this profile's switch, default false), `prices` (default false), `currency` (one of 16, or null) |
| `POST /api/settings` | any of `{relay, seen_receipts, notify, new_tier, new_presence, wallet, prices, currency}` | the same; `relay` a host[:port], `""` or null for the default; each checked (`400`) before any is kept, in `.ui.json` `settings` |
| `GET /api/relays` | | `{relays: [{tag, host, did?, tier?, note?}]}`: the signed `sigelo.ai/relays.json`, verified, fetched at most once a day |
| `POST /api/relays/test` | `{relay}` | `{relay, ok, ms, retention_days, detail?}`: the picker's Test: GET `/relay.json` at that host, else `/challenge` |
| `GET /api/groups` | | `{tier: {tier, groups, members, told}, groups: [{gid, name, status, ver, brake, creator, creator_name, mine, foreign, run, members: [{did, name, role, me, contact}], unread, quiet, notify, last, picture}], notices}` (GROUPS.md): `tier` the relay's answer at login (`told`), else the guess; `quiet`: the brake reached, agents wait for a human; `last` `{name, text, at, mine}`; `picture` a local picture's rev or null ("Pictures") |
| `GET /api/groups/history` | `group=<gid>` | `{group, messages: [{mid, re, from, name, role, tier, mine, operator, note, text, mentions, mentioned, via, photo, at}]}`, last 200 (`photo`: a preview or null, as in messages); marks them read. `note`: `"not your operator"` |
| `POST /api/groups/create` | `{name, members, humans?, brake?}` | `{group, copies}`: `members` contact DIDs, `humans` those that are people (role `human`, else `agent`); `409 group_limit` past the tier |
| `POST /api/groups/add` | `{group, members, humans?}` | `{group, copies}`: the creator's; the roster to each |
| `POST /api/groups/remove` | `{group, members}` | `{group, copies}`: the creator's; the removed told |
| `POST /api/groups/rename` | `{group, name}` | `{group, copies}`: the creator's |
| `POST /api/groups/brake` | `{group, brake: "off"\|n}` | `{group, copies}`: the creator's loop brake (default 20) |
| `POST /api/groups/role` | `{group, member, role}` | `{group, copies}`: the creator's; `human` or `agent` (the brake counts agents) |
| `POST /api/groups/share` | `{group, member}` | `{group, copies}`: the creator's roster again to one member (a new device, a lost copy) |
| `POST /api/groups/send` | `{group, text, re?, mentions?}` | `{gid, mid, copies, via_creator, unreached}`; `@name` in the text mentions too; `409 group_quiet` for an agent past the brake |
| `POST /api/groups/join` | `{group}` | `{group, copies}`: an invitation (a friend's group) joined |
| `POST /api/groups/leave` | `{group}` | `{group, copies, told}`: out of a group |
| `POST /api/groups/dismiss` | `{id}` (or `"all"`) | `{dismissed}`: a notice put away |
| `GET /api/devices` | | `{devices, list, adding, joining}` (DEVICES.md): `devices` `[{name, rank, worker, did, original, via, added, seen, paired, ours, tier, attested_until, revoked}]`; `list` `{seq, iat}` or null; `adding` (online adds) `[{id, name, worker, did, qr, short, exp, state, words}]`, `state` `code`, `words`, `sending`, `done`, `refused`, `expired`; `joining`: this machine's scan of an online code `{state, file, words, …}` or null |
| `POST /api/devices/add` | `{name, offline?, tier?, days?, words?}` | online: an `adding` entry (`qr` `SIGELO:DEV:…`, 10 min); offline: `{id, name, worker, did, frames, list, exp}`. SAFE only: `full` → `409 device_full` (a terminal) |
| `POST /api/devices/confirm` | `{id, match}` | the words gate: `true` sends its key; `false` drops it (`refused`); before the device answered `409 device_state` |
| `POST /api/devices/words` | `{id}` | `{words}` of an offline add, once, within 10 minutes; then `404` |
| `POST /api/devices/scan` | `{text \| texts, name?, words?}` | this machine as the device, into `sigelo.<name>.local.json` (agents' directory): an online code → `{kind: "online", state, file}` (then `joining`); frames → `{state: "frames", have, count, missing}`, `{state: "words"}`, with `words` `{state: "done", did, worker, operator, file, paired}`; wrong words `409 device_words` |
| `POST /api/devices/revoke` | `{name, lost?}` | `{device, rank, worker, revoked, lost, wiped: false, forgot, list, synced, steps?}`: the wipe answered later; `lost` forgets now, `steps` the rest |
| `POST /api/devices/sync` | | `{list, synced, forgot}`: the signed list to every device; wiped answers read |
| `GET /api/transfers` | | `{out, in, direct, auto, settings}` (TRANSFER.md): each `{id, contact, name, size, sha256, state, attempt, via, reason?, detail?, got\|sent, live?, rate?, saved?, path_used?, by?, group?}`; `state` `asked`, `offered`, `accepted`, `offering`, `active`, `interrupted`, `done`, `declined`, `cancelled`, `failed`, `expired`; `by: "rule"`: accepted by the accept rule; `group`: a group's fan-out; `live` `waiting`: an offer held for a free slot; reason `land`: came whole, not saved (`detail` says why; resume saves again); `direct` `{did: true\|false}`; `auto` `{did: MB}` (0: always ask); `settings` `{tor, prefer, auto_mb, keep_location}` |
| `POST /api/transfers/send` | `{to \| group, path \| doc, via?, direct?, photo?}` | the record, `offered`: a file of this computer read in place (`path`, ≤ 16 GiB; never remote), or on the phone a `doc` from pick or photo; `photo` `{type, data, w, h}`: its preview (photo.mjs), sent beside the manifest as `sigelo-photo/0` and into the chat (`400 photo`); `group`: one transfer per member paired with → `{group, mid, sha256, name, size, sent: [{did, name, id}], unpaired, failed}`, the preview (or "File: name") as one group message |
| `POST /api/transfers/auto` | `{contact, mb}` | `{did, name, auto_mb}`: that contact's size for the accept rule (0: always ask; `null`: the default) |
| `POST /api/transfers/pick`, `/photo` | | the phone only: `{doc, name, size, mtime, url}` from the system's picker or camera (`url`: the page reads it, e.g. the preview), or `{cancelled: true}`; photo removes location tags unless `keep_location` |
| `POST /api/transfers/open` | `{id}` | the phone only: a file that landed, opened by the system (`409 transfer_state` before) |
| `POST /api/transfers/accept` | `{id, direct?, via?}` | the record, `accepted`: free disk checked; the page's engine offers. `409 direct_ask`: ask once, send again with `direct` |
| `POST /api/transfers/resume` | `{id, direct?}` | as accept, for `interrupted` or a failed `no_path`: only the missing chunks |
| `POST /api/transfers/decline` | `{id}` | the record, `declined`: the contact is told |
| `POST /api/transfers/cancel` | `{id}` | the record, `cancelled`: the contact is told; the partials go |
| `POST /api/transfers/forget` | `{id}` | the record, gone here with its partials |
| `POST /api/transfers/direct` | `{contact, on}` | `{did, name, direct}`: may this contact see my addresses |
| `GET /api/transfers/settings` | | `{tor, prefer, auto_mb, keep_location, tor_daemon: {serve, connect}, direct_available, pick, camera, open}`: the Tor checkbox (off when no daemon answers); Pro's order `fast`\|`private`; the accept rule's size (default 25 MB); the phone's own routes |
| `POST /api/transfers/settings` | `{tor?, prefer?, auto_mb?, keep_location?}` | the same, kept |

`contact` is the contact's original DID. A contact in `groups`: `{did, name, current_did, relay, re_pair,
words, pair, words_checked, tags, local, mine, unread, last, waiting, not_collected, queued, status,
ours, tier, link, online, online_since, last_seen, presence, notify, seen_upto, kind, kind_set, picture, picture_local, via}`; `via`: a public code it came by ("Public invite"), or null; `picture`: the rev of the picture shown (a local one, else theirs) or null; `picture_local`: a local one is set ("Pictures"). `kind` ("Kinds"): `agent` or `person`; `kind_set`: the human chose it. `last`: `{dir, text, at, status}`, `status`
as in `GET /api/messages`; `notify`: `POST /api/notify`; `seen_upto`: the contact's newest seen receipt (their time), or null. `online`: `true`, `false` (then `last_seen`, the relay's time) or `null` (not known: not allowed, or this page offline); `presence`: what they see of mine. `link`: `{id, purpose, linked_by, expires}` or null. `status`: `ok`, `waiting` (their keys have not come, or the carrier says why messages wait:
`waiting`), `not_collected` (a message queued, no reader yet), `pair_again` (`re_pair` after a recovery). `tier` (apps/contact/store.mjs): `own` (my agents:
an unexpired `sigelo-relay/operator` attestation from my DID, seen in a local agent's file or proved
by the agent), `friend` (the default; the page shows "new message" and a count), `quiet` (nothing
until opened); the human's choice (`/api/tier`) wins. `ours`: that attestation marks it, whatever the tier (an
own agent may be `friend` by choice). **Mine** = `ours` or tier `own`; `mine` = the attestation's
expiry for a local agent; `local` = the agent's name on this machine.

Only in the self-contained app (apps/web, not `ui`): `POST /api/seat/take` `{confirm: true}` for a standby
restored from seed: the list signed naming this device, then the page logs in as you (`seat take --force`
semantics: the other device must be stopped or lost) → `{seat: "here", holder, epoch}`; `400` without
`confirm`, `409 seat_here`. With the words kept behind the words password (design/apps-seed.md §8) it needs
`password` too: `403 words_password_needed` without, `403 words_password` ("Wrong password.", after the delay) when wrong.

`me` in `state`: `{did, relay, online, clock_offset (s, relay minus local, the carrier's `clockOffset`), clock_checked,
retention_days, error, pow: {bits, elapsed_s, expected_s}|null, pow_done_ms, pow_capped: {relay, next}|null, pow_confirm: {relay, detail}|null,
seat: {holder, epoch, here}|null, wallet: {on, prices, currency}, picture}` (`wallet`: Settings → Wallet, for every scope; `picture`: the rev of mine, or null). Proof of work (design/profiles.md §6): a call the human starts (invite, accept, enrol-code,
pow/try, the page's start) past 3 searches a day at a relay answers `409 pow_confirm` (its message the question), and goes with
`pow_confirmed: true`; the automatic retries stop instead (`pow_capped.next`: the next automatic try)
(`here` false: another device holds the seat; the page shows a banner and its writes refuse `seat_elsewhere`). A pending invite:
`{name, exp, relay, id?, short?, short_exp?, code?, renew?, used?, renew_error?}`; `paired`: `{id, name, paired: <did>}` for the
pairing view. `answers`: codes this side answered, waiting for the inviter until `exp`. `failed`:
`pairing_failed` of the last day (`code_expired`: expired before they replied). `public`: the public invite or null ("Public invite"). `introductions`: `[{id, from, name, purpose, peer_name}]`,
introductions to this identity waiting for an answer, introducer not quiet: the page's banner. The page runs the link handler
(link.mjs) as `watch` does; link messages and codes never reach the history.

**Agents:** the page's own session enrols them (the CLI's `enrol` refuses `busy` beside it); worker indices are given at the seat only.
The keeper's `workers` are the list; a code's temporary pairing never shows in the contacts or the history.

**Devices:** the page's own session runs them (the CLI's `device` verbs refuse `busy` beside it). Enrolment and device
messages never reach the history. QR codes are drawn and read in the page with `qr.mjs` and `qr-decode.mjs` (served
beside it, with `shim-*.mjs`; the import map is its one inline script, allowed by hash in the CSP): camera where
`getUserMedia` finds one, else an image file or paste. The six offline words come only from `/words`, after the frames.

**Groups:** the page's own session handles them at each drain (apps/contact/group.mjs `handle`: rosters taken,
copies carried on, messages filed; the CLI's `group` verbs refuse `busy` beside it). `chats` in `state`: `{unread, invited,
notices, rev}`, the Groups tab's count; `rev` changes with any group's roster, status or newest message. Notices
(`{id, why: stranger|creator_left|refused, …}`) are kept in `.ui.json` until dismissed; an invitation is a group `pending`.

**Kinds** (the marks: an agent square, a person round): a contact is an `agent` when the page knows it is one: my agent (`ours`, an
agent of this machine, or a worker of my keeper root, its original DID in the chain), or a member some group's roster names an agent
(GROUPS.md roles); else a `person`. The human's choice (`POST /api/kind`, kept in `.ui.json` `kind`) wins until given back with `null`.
A bundle carries no "I am an agent" of its own (SPEC); a stranger's agent is a person here until marked.

**Keeper** (apps/keeper, `sigelo-spend`; apps/agent/sigelo-agent-spend.ts): the allowance wallet's policy service, where it runs.
`ui` reads the keepers this host registered (`SIGELO_SPEND_REGISTRY`, else `$XDG_CONFIG_HOME/sigelo-spend/keepers.json`): `none`
when there is none, `unreadable` (`detail`) when this user cannot read one (the two-user layout: set it there with `sigelo-spend`);
the self-contained app answers `elsewhere` (`via: null`), its writes `409 keeper_elsewhere` ("Set this on the computer that runs the keeper");
with a computer of this operator paired to its profile (apps/contact/page.mjs `hooks.computer`) it answers that computer's, `via:
{computer}`, and a limit is a `policy-change` it signs itself, sent as `POST /api/keeper/policy` (the computer cannot alter it).
`here`: `keepers` `[{id, did, net, port, approvers, me_approver, me_owner, restart: {command, can}}]` (`id` its directory's name; `approvers`
the policy's DIDs, `me_approver` this identity's current DID among them, `me_owner` one of its DIDs in `owners`); `agents` `[{keeper, name, worker, did, account, per_tx_max,
per_period_max, period_seconds, rate_per_minute, approval_above, max_delegates, allow: [{kind: "addr", addr, label} | {kind: "did"|"issuer",
did, issuer, ctx}], spent, remaining, window_start, paused, address, incoming, balance?, unlocked_balance?}]`, every policy entry; with the Wallet on,
`address` (`(i, 0)`, its own), `balance` and `incoming` `[{ts, amount, txid, status}]` from the keeper's `POST /agents` signed by this
identity when it is an owner, else `address` from the keeper's wallet-rpc (`null` when neither answers); `worker` the roster's index when its `did` is a worker's
(original or current), or, for an entry with no `did`, its name a live worker's, else null; `spent`: what spend.log debits it since
`window_start` (amount + fee of each transaction, as the keeper counts); amounts are atomic units as decimal strings; `requests`
`[{keeper, nonce, agent, worker, amount, to, purpose, ref, iat, exp}]`, newest first: `pending` lines the keeper signed (its
`identity.json` key), not approved, not spent, not expired, not refused here. Writes check what apps/keeper/policy.ts checks
(`400`; an address decoded on the keeper's `net`, `allow_addr`; labels once, `allow_label`; `per_tx_max` within `per_period_max`,
`keeper_caps`; `period_seconds` an hour, a day, a week or 30 days), keep every other field, and write `policy.json` whole, 0600.
`approval_above` set needs `approvers` (`409 keeper_approvers`) and the agent's `did` and `genesis` in its entry: written from the
agent's file when it is on this machine, else `409 keeper_did`. **Signed** (apps/keeper/README.md "The Owner"): a keeper that takes `/policy`
with this identity in `owners` gets the fields given as a `policy-change` signed here (`signed: true`, its `policy` back, in use at once,
logged there); its refusal `409 keeper_<code>`. Else the file: a keeper not running (`why: "offline"`), from before, or a change that
writes the agent's `did` and `genesis`; the first such save on a keeper that takes `/policy` adds this identity's original DID to `owners`.
`paused` (Pause/Resume) needs a keeper that knows it (`409 keeper_old`). Every write answers `restart`, `can` for a systemd user unit
(`POST /api/keeper/restart`), for a keeper from before 0.1.15. **Approve:** the
pending request's body, as the keeper signed it, signed by this identity (`"sigelo\n" + JCS(body)`, its current key) with its
bundle, posted to `127.0.0.1:<install.json port>/approve`; the keeper checks it all again (an approver, the request, the licence:
its refusal `409 keeper_<code>`, e.g. `keeper_licence_required`); not an approver `409 keeper_not_approver`; not answering
`409 keeper_offline`; gone `404 keeper_request`. The agent's next run of the same pay pays it, once. **Refuse:** the same body with
`typ: "spend-refusal"`, signed the same way, with the `reason` (≤ 200), posted to the keeper's `/refuse` (apps/keeper/README.md
"Approvals"): a keeper-signed `refused` line, and the agent's same pay is REFUSED with the reason until `exp` (`logged: true`). Not an
approver (`why: "not_approver"`), no port, a keeper from before 0.1.15 (`old_keeper`), not running (`offline`) or a refusal of it (its
code): `logged: false`. Either way the request is put away in `.ui.json` `refused` until its `exp`, and the agent's contact (the worker's)
gets "Payment refused: <reason>" ("Payment refused." without one) through `POST /api/send` (`told`).
**A running keeper re-reads its policy** on its next request (0.1.15, apps/keeper/README.md "What a running keeper re-reads"): every write
answers `live` (true: from its next payment; false: a keeper from before, after a restart; null: not known, a keeper run by hand), read
from the frozen copy it runs (`install.json` `app`); keepers carry `live`, `refuse` (it takes `/refuse`) and `policy` (`/policy`) the same way. **Seen:** each
keeper's `seen` `[{addr, agent, purpose, did, invoice, paid, last}]`, the addresses spend.log names (paid, asked, invoiced), newest first,
32 at most: "Who it may pay" offers them beside the contacts.
Unknown keeper `404 keeper_unknown`, agent `404 keeper_agent`; no keeper here `409 keeper_none`, `keeper_unreadable`.

**Wallet** (design/ux1/notes.md "Decided"; sigelo-agent-wallet.ts): per profile, off by default (`settings.wallet`); off, no wallet,
node or price source is asked. *Which wallet:* `ui` uses a `monero-wallet-rpc` on this computer, the wallet service: a keeper's
(policy.json `wallet`, loopback, its digest login) or one given by hand (127.0.0.1 only), and one account of it, never one a keeper agent
or delegate is pinned to (`account_held`). Not chosen: the first keeper's, account 0 if no agent holds it, else `why: "no_account"`
(Make an account: `create_account`). The vault is never loaded. The self-contained app has none: `where: "none"`, its other wallet routes
`409 wallet_none` ("This phone has no wallet yet: use the computer's page"); a phone connected to a computer gets the computer's.
`why`: `no_service` (no keeper, none given), `no_account`, `account_held`, `keeper_gone`, `unreadable`. *Sync:* `sync` `{state, height,
chain, behind, behind_s, progress, synced_at, checked_at, detail?}`; `state` `synced` (the wallet's height within a block of the node's:
the node in use, Settings → Monero node, else the keeper's first daemon), `syncing` (`behind` blocks, `behind_s` at 2 minutes each,
`progress` since this sync began), `node` (the node doesn't answer, none is set, or the wallet hasn't moved for 3 minutes while behind),
`wallet` (the wallet program doesn't answer). A wallet not of a keeper is asked to `refresh` while behind (once a minute at most); a
keeper's refreshes itself (a page-made rescan would hold its payments). Read at most every 4 s. *Balance:* `{total, unlocked,
blocks_to_unlock, at, current}`, the account's own; `current` false and `at` its last sync when not synced (the page greys it, "as of");
the last one kept when the wallet doesn't answer. *Send:* built `do_not_relay` (the fee priced), reviewed, relayed by `id` within 10
minutes; the note kept (`set_tx_notes`); integrated addresses and another network refused (`400 address`); to a contact: told in their
chat ("Paid you 0.05 XMR: Dinner. Transaction 9c1e…04ab."), the address kept for the next Pay (`payees`), and that message carries
`pay: {txid, amount, note}` in `GET /api/messages` (shown as the payment). `{agent, keeper}`: that agent's allowance account, `(i, 0)` of
the keeper's wallet (Top up). Kept in `.ui.json` `wallet` (service, node, nodes, synced_at, last, payments, payees). *Price* (opt-in,
`settings.prices`): CoinGecko's `simple/price` (no key; `SIGELO_PRICE_URL` replaces its address, for tests), every currency at once,
asked by this server, never the page, kept 10 minutes; it learns that this computer asked (its address on the internet), never a wallet
address or an amount. `stale`: the last price, the source not answering since. Errors: `409 wallet_off`, `wallet_setup`,
`wallet_unreachable`, `wallet_login`, `wallet` (the wallet's own words), `wallet_unsynced`, `wallet_funds`, `review_gone`, `node_down`,
`account_held`; `404 tx_unknown`.

**Seen receipts** (the ticks, Telegram's: ✓ the relay took it, ✓✓ they have seen it; apps/contact/carrier.mjs "Seen receipts"):
a receipt is one more end-to-end message, body `{label: "sigelo-seen/0", content: {seen: <iat>}}` inside the same sigelo-msg/0
envelope (no new frame, nothing the relay can tell apart): every message of mine sealed at or before that time was shown. A
contact's messages shown (`GET /api/messages`) send one, the newest `iat` shown, when it moved and `seen_receipts` is on: to a
contact whose receipt came (`seen_peer`), or once to one not known to read them (never to my own agents, `ours`, before theirs). The first receipt from a contact is answered once
(`seen: 0` when off). A contact on an earlier version takes that first one as a message labelled `sigelo-seen/0`, once, and never
sends one: mine stay at one tick. Off (`seen_receipts: false`) sends none; theirs still show. A message of mine is `seen` when its
`at` (taken before the send) is at or before the contact's `seen_upto`. Kept in `.ui.json` `seen` (`{sent, told}` per contact).

**Pictures** (design/ux1/notes.md "Decided"): mine per profile (`of: "me"`), a local one for any contact or group. Mine travels to each paired
contact known to read pictures (its seen receipt came, or its own picture did) as one more end-to-end message, body `{label: "sigelo-picture/0",
content: {type, data}}` (or `{remove: true}`) inside the same sigelo-msg/0 envelope: the relay sees one more envelope, never a picture; an
earlier version is never sent one. One received is checked (JPEG or WebP by its first bytes, at most 64 KiB), kept as theirs, never in the
history; a local one wins over it. The page sends 256 × 256 or less (ui.js). Kept in `.pictures/` (the computer) or the profile's storage (the
phone); `.ui.json` `pics` (each one's type and rev), `pic_sent`, `pic_peer`. A forgotten contact's go with it. Groups and agents show their
marks until a local one is set.

**Signed statements** (Me → Sign or check a message; a chat's "Signed by … · check"): the text, a line `-- Signed with sigelo by <four
words>. Check it in the sigelo app.`, and `sigelo-statement/0 <base64url of JCS {body, sig, bundle}>`. `body` `{v: "sigelo-statement/0",
typ: "statement", did, iat, text}`, `did` the signing key's (the current one), `sig` over `"sigelo\n" ‖ JCS(body)` (SPEC §3), `bundle` the
signer's chain only (genesis and rotations; no attestation, binding or issuer). Check, offline: the bundle verifies (SPEC §9), `did` is in
its chain, the signature is by that DID's key; `edited` when the text above the signature line is not the one signed. `by` names who it is
here: me, a contact whose chain holds `did` (`words_checked` as compared), or unknown (its four words to ask). A chat-layer body, no
protocol object: in a chat it is a message labelled `sigelo-statement/0` whose text is the portable form (an earlier version shows it as
text). The key agent (KEYS.md) signs none.

**Public invite** (Me → Public invite; design/public-invite.md, Pro only): a public code, `sigelo-public/0`: `PUB-XXXX-XXXX` with the
inviter's four words (`words`, didWords of the original DID) and `link` (`https://sigelo.io/join#PUB-….w-w-w-w`), for 1, 6 or 12 months, kept in
the contact store. State's `pending.public` (the first) and `pending.publics`: `{id, name, short, words, link, exp, relay, cap, open, paused,
today, chats, requests: [{id, did, current_did, words, received, exp}]}`. Each use is a request (event `public_request`) until approved or
refused (7 days at most); `open` pairs at once. A contact that came by one carries `via`: `{public: id}` (mine: not compared) or
`{public: true, words: "checked" | null}` (theirs: checked against the page's words). `POST /api/accept {code, words?}` takes a PUB code or
its link; `status: "waiting_approval"` until the inviter approves.

**Renewing codes** (My code, New chat): `renew: true` makes a one-person short code that is replaced as soon as it is used:
the agent parks a fresh one, same name (numbered: `-2`, `-3`), ttl and relay, kept in the contact store. Its pending invite keeps the
id `r<series>` across codes and restarts: `short` the current code (`code` only for the first), `renew: true`, `used` `[{short, name,
did, at}]` the codes used (the latest 10; compare the four words with each), `renew_error` why the last renewal failed (retried a
minute later) or null; it never shows in `paired`. Cancel ends it; a code that runs out unused ends it too.

**Relay setting:** new codes name `SIGELO_RELAY` if set, else the setting, else `relay.sigelo.ai`; a change applies to the
next invite and to this page's own connection at its next start. Codes accepted never read it: 8 characters are `relay.sigelo.ai`'s,
12 name their relay by its tag (local table, then the registry).

**Files:** one received is an `in` message, `file <name> (<size> bytes), saved at <path>`. Sending one: not yet (the disabled 📎).

**Transfers:** where the host moves files (`ui`; `transfers` in `state` is `{asked, active}`, else null and no
`/api/transfers*`), the page's session runs the transfer engine as `watch` does; a file offered is an event `transfer`
in the history and the Files view's card. Refusals: unknown `404 transfer_unknown`; `409 direct_ask`, `disk_full`, `transfer_state`.

## Remote

`ui --remote [--listen <ip>] [--name <control>] [--scope read|chat|all]` adds a listener on a LAN address
(default: the default route's when private, else the first private IPv4: never a public one) that answers only `POST /r`; anything else is `404` with no body. It prints
`SIGELO:UI:<ip>:<port>:<base45 of id (8 bytes) ‖ key (32)>` for the named control (new: scope `chat`), kept in `.ui.json` `controls{}`.
A request `{id, ctr, nonce, box}` (≤ 1 MiB; `id` hex; `nonce`, `box` base64url): `box` = XChaCha20-Poly1305(key, nonce,
aad `"sigelo-remote/0 req"` ‖ id ‖ u64be(ctr), JCS `{method, path, body?}`). The answer `{nonce, box}` under aad `"… res"` ‖ id ‖ ctr
holds `{status, body}`, what this listener would answer. `ctr` must exceed the last one kept (one call at a time):
a replay, a wrong key or an unknown id get `403` and no body. **Scopes:** `read`: state, me, messages, links, agents/workers, transfers, wallet (its state, history, a payment), price, picture, attestations, statement/check; `chat`: + picture (set), send,
accept, invite, invite/cancel, words, rename, tag, sync, links/answer (pairs as accept does), pow/try, wallet/sync, wallet/receive, wallet/label; `all`: + statement/sign, forget, tier, kind, notify, history/clear, keeper (its settings, a relayed signed change, approvers, approve, refuse, restart), the wallet's review, send, service and node, agents
(enrol-code, enrol-words, revoke, rename too), link, unlink, links/allow (who the agents talk to, as tier), settings, relays, relays/test, transfers/accept, decline, cancel, resume, forget, direct, settings. Outside it: `403 scope`;
`/api/devices*` and `/api/transfers/send` (a file of the computer, by path) never (`403 remote`). `ui --controls` lists them (never a key); `ui --revoke-control <name>` forgets one
(stop the page first: it owns the file). No TLS: the LAN sees sizes and timing; the text is page control until revoked.
Client: `remote-client.mjs`. **Over the relay** (`ui --remote --relay [--name] [--scope]`, no listener): it prints
`SIGELO:CTL:<short code>[:<HOST>]`; the app pairs a control identity of its own (a random key, never attested; apps/contact/control.mjs) and the
four words are confirmed at the computer (before: `403 words`): its terminal (y/N), or the page's Controls card, `GET /api/controls` → `{pending: [{name, scope, words}]}` and `POST /api/controls/confirm` `{name, match}` → `{name, confirmed}` (refused: forgotten; none waiting: `404 control_unknown`; never remote, the app refuses it unsent: `403 remote`). Calls are `sigelo-device/1` `request` {id, method, path, body?}
→ `response` {id, status, body}, the same scopes; a request opens a 10-minute lease of `events` {seq, since, state} (GET /api/state, pushed
on change; past 64 KiB a summary, the newest 20 contacts of each group and events, `truncated: {contacts, events, kept}`, and the app's "Pull the rest" asks `GET /api/state?full=1`, a request), so the app's poll reads it locally: one request per 5 minutes while open. Cap: 10 at once, then 1/s (`429 rate`).
Seat elsewhere: `409 seat_elsewhere`. Each message counts in the relay allowance: requests the control's day, answers and events
yours. The control is marked `relay` in `controls{}`; revoking forgets its contact. Phone side without a WebView carrier:
`sigelo-agent control pair <text> | ui --app | forget` (apps/gtk); the control key sealed in the OS keyring (as `--keychain`), plain 0600 with a warning when none answers. **`local`:** the self-contained app (apps/web) answers these routes in the page, over its own carrier, with the same JSON (apps/contact/page.mjs). The Android app (apps/android) shows that page, or a computer's through `/r`, sealed in the page, carried by the app's HTTP. **`ui --app`:** for a shell that shows the page (apps/gtk): no browser, and the page stops when stdin ends. **Install:** `ui --port <p>` keeps the origin (taken: `port_taken`); `manifest.webmanifest`
and `sw.js` keep `ui.html`, `ui.js`, `ui.css` only, never `/api/`.

## Profiles (the apps)

Not routes: the phone apps' own, beside these (design/profiles.md P1). The Profiles sheet (the profile chip) and Settings → Profiles (`ui.js`) call the shell's
`profiles`: in the WebView app `sigeloLocal.profiles` (apps/web/boot.mjs), in the GTK phone app the bridge's ops
`profiles`, `profile-use`, `profile-rename`, `profile-add` (`{path?}`), `profile-remove` (answered to the start page, `ui.html` and this
phone's own page; never another page). `list()` → `{active, limit: 8, profiles: [{id, name, kind: "words"|"remote"|null,
did, words, created}]}`; `use(id)` switches (the lock once, then the page of that profile); `rename(id, name)` (1 to 24
characters, else `profile_name`); `add(path?)` (past 8: `profile_limit`) opens the new one's first run, at `path`'s step when given (the Add
sheet: `create`, `join` (an invite code first; the new page opens Enter their code with it: `sigeloLocal.joinCode()`, once), `restore`,
`backup` (WebView app: a backup file, below), `computer`); `remove(id, {name, words})`:
a `words` profile needs `words: true` (`profile_words`) and its name typed (`profile_name`), a `remote` one its name, one
not set up nothing. A computer's own page has none: no Profiles in Me. A `words` profile whose words are kept needs its
words password too: WebView `{password}`, GTK `{proof}` (below); else `words_password_needed`, `words_password`.

The words password (design/apps-seed.md §8), Settings → Backup and recovery (`ui.js`), where this phone holds its own identity from the
25 words. WebView app: `sigeloLocal.words` (apps/web/words.mjs): `status(id?)` → `{here, kept, iterations}` (with an id:
that profile's `kept`); `reveal(password)` → `{words: [25]}` after the screen lock; `change(old, next, repeat)`; `set(words, next, repeat)` (none kept: the 25 words
typed again, refused `words_other` when they make another identity, `words_check` when they are not words; then kept);
`remove(password)` (the kept words deleted); `auth(id, password)` → what a guarded call carries. `sigeloLocal.secure(on)`:
`FLAG_SECURE` while the words are up. Refusals: `words_none`, `words_password`, `words_password_needed`,
`words_password_rule` (at least 8 characters, the repeat the same). GTK phone app, bridge ops beside the profile ones:
`words-status {id?}` → `{here, kept, keyring}`; `words-get {id?}` → `{blob}` (base64 of words-lock.mjs's blob; never the
check); `words-keep {blob, check, proof?}` (proof needed over kept words); `words-drop {proof}`; `take {proof?}` on the
start page. The page does the crypto with `/words-lock.mjs`, which `ui` serves (apps/contact/words-lock.mjs, as it is).

## Backup file (the apps)

Not routes (apps/web/backup.mjs, `sigelo-backup/0`): Settings → Backup and recovery → Back up this profile, in the WebView
app and a tab. `sigeloLocal.backup.status()` → `{kind, can, kept}`; `make({password, repeat?})`: the lock, then the words
password through the page's gate (none kept: a password for the file, given twice), then the file → `{name, where:
"Downloads"|"download", size}` (Android: the shell's `big-write` and `big-land`). Refusals: `backup_remote` (a computer's
page: the computer holds it), `backup_none`, `words_password`, `words_password_rule`. Restore: the first run's "Restore
from a backup" and the Add sheet's `backup` path; `backup_exists` (the identity is a profile here already),
`backup_version`, `backup_file`, `words_password`. The GTK phone app and the computer's page: not in this pass.

## Computers (the apps)

Not routes either (design/profiles.md P2): a remote profile's computers, each paired once. Me → Devices and computers
(`ui.js`) calls `sigeloLocal.computers` (WebView app) or the GTK bridge's `computers`, `computer-use`, `computer-add`,
`computer-forget`. `list()` → `{active, limit: 8, computers: [{id: "c1"…, name, via: "lan"|"relay", did, words, where,
paired, last_used}], profile: {id, name, did, words}}`; a profile holding an identity: `not_remote` (no Connect in Me).
`use(id)` opens that computer's page (the lock once); `add()` opens the pairing screens (code or scan; Cancel back);
`forget(id)` drops its control key on this phone and answers `{revoke}`: `sigelo-agent ui --revoke-control <name>` on
the computer, which keeps the control until then. Pairing a computer whose page (`GET /api/me` `original`) is another
identity than the profile's operator is refused `other_operator`; nothing of it is kept.

