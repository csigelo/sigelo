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
`.history.jsonl` (what the carrier's `inbox()` hands over: messages, pairing events), `.ui.json` (tags, words checked, read marks),
`.ui.pid` (one page or `watch` per file, the only process logged in as it: beside a page every CLI verb and
MCP tool that would log in refuses, `busy`; WATCH.md). **Known limitation:** history and `.ui.json` are plaintext (0600) until the
keychain unlock (K2, ROADMAP §7); "clear" (`POST /api/history/clear`) is the only mitigation (THREAT-MODEL §3.9).

## Routes

| Route | Body / query | Answer |
|---|---|---|
| `GET /api/state` | `since=<seq>` | `{seq, now, me, groups: {mine, contacts}, chats, pending: {invites, paired, answers, failed}, events, introductions, transfers}` (`transfers`: `{asked, active}`, null where the host moves no files) |
| `GET /api/me` | | `{did, original, words, chain, identity_file, recovery: "set"\|"none", key: "file", relay, retention_days, erase, restored?}`; `restored` `{on, keeper, seat: "here"\|"elsewhere"\|null, created?}` when the identity comes from the 25 words and its keeper file has the day it was made (Me: "Restored from seed on …"); `created: true` when the words were made on this device (keeper `made: "here"`; Me: "Created on …; the 25 words are on your paper"); `words`: four words naming `original` (contact/short.mjs `didWords`, a label for the apps' profile list, not a check) |
| `POST /api/invite` | `{name?, long?, pow_confirmed?}` | `{id, name, code, exp, short?, short_exp?, relay}`: `short` parked 10 min; `short_exp` the relay's clock |
| `POST /api/invite/cancel` | `{id}` | `{cancelled: true}` |
| `POST /api/accept` | `{code, name?, tier?, pow_confirmed?}` | `{status: "connected", contact: {did, name, fingerprint, pair, tier}}`, or `{status: "waiting"\|"pending", did, detail, exp}`; `tier`: `friend` or `quiet` (own is detected) |
| `POST /api/words` | `{contact, match}` | `true`: `{checked: true}`; `false`: forget and block |
| `POST /api/rename` | `{contact, name}` | `{did, name}`; `409 name_taken` if another live contact has it |
| `POST /api/tier` | `{contact, tier}` | `{did, name, tier, ours}`: `own`, `friend` or `quiet`, kept until changed |
| `POST /api/presence` | `{contact, allow}` | `{did, name, presence}`: may it see when I am online (`allow`, `deny`; `own` always, deny `409 presence_own`) |
| `POST /api/tag` | `{contact, tags: [≤ 8, ≤ 20 chars]}` | `{tags}` |
| `POST /api/forget` | `{contact}` | `{forgotten, offline}`: revoked here for good |
| `POST /api/send` | `{to, text}` | the history record: `{n, at, kind: "out", did, id, text, status: "sent"\|"queued"\|"refused", code?, detail?}` |
| `GET /api/messages` | `contact=<did>&since=<n>` | `{seq, messages: [{n, dir: "in"\|"out", at, text, label, status, code, detail, link}]}` (`link`: `{id, purpose}` on a linked contact's, else null), last 200; marks them read |
| `POST /api/sync` | | `{synced: true}`: one round now ("Retry now") |
| `POST /api/history/clear` | | `{cleared: true}` |
| `GET /api/agents` | | `[{name, did, error, mine: {exp, days_left}\|null, worker: i\|null, renew, contacts, contact}]`: the agents' directory; `contacts`: the agent's own |
| `POST /api/agents/enrol` | `{agent}` | `{agent, worker, renewed, did, exp, days_left, old?, contacts?, warning?}`: `enrol --here` into the agent's file (ENROL.md); a worker: the attestation renewed. `400 keeper`: run `sigelo-agent keeper --from-words` |
| `POST /api/agents/pair` | `{agent}` | `{status, contact}`: both sides in this process, words checked |
| `GET /api/agents/workers` | | `{keeper, seat: "here"\|"elsewhere"\|null, workers: [{worker, name, did, original, rank, placed: "remote"\|"here"\|"device", at, status: "enrolled"\|"pending"\|"revoked"\|"unplaced", revoked, seen, tier, contact, local, online, last_seen, attested_until, enrolling}]}`: the keeper's roster (the Agents screen); `enrolling` `{id, state: code\|words\|sending\|enrolled\|expired\|failed, code, exp, relay, words, command}` for a code this page made |
| `POST /api/agents/enrol-code` | `{name, tier?, relay?, confirm_words?, operator_name?, pow_confirmed?}` | `{worker, name, did, original, tier, id, state, code, exp, relay, command, words, confirm_words, words_ok, verified}`: `enrol --name` on this page's session (ENROL.md): worker i (next free), a code for 10 minutes, once; its request answered with the worker's identity, the worker filed when it pairs, and words-checked when its DID is the one derived here (`verified`; no tap). `confirm_words: true`: the key waits for enrol-words. `400 keeper` without a keeper root; `409 seat_elsewhere`, `name_taken` |
| `POST /api/agents/enrol-words` | `{id, match}` | the enrolment: `true` sends its key; `false` drops the code, the key never sent (`device_words`) |
| `POST /api/pow/try` | `{pow_confirmed?}` | `{tried: [relays]}`: "Try now", a login at each relay not connected |
| `POST /api/agents/revoke` | `{worker}` | `{worker, name, cancelled, revoked, forgot, attested_until?}`: an unused code cancelled (its index free again); else its contact forgotten and the roster marks it revoked; its attestation stays valid until `attested_until`. A device: `409 device` |
| `POST /api/agents/rename` | `{worker, name}` | `{worker, name}`: the roster and its contact |
| `GET /api/links` | | `{made, links, received, allow}` (LINKS.md): links I made `{id, a, b, a_name, b_name, kind, purpose, note, tier_a, tier_b, expires, status, step, check}`; contacts linked to me; introductions waiting `{id, from, name, peer, peer_name, purpose, note, exp, quiet, answer?}`; allow rules `{contact, name, tier, until}` |
| `POST /api/link` | `{a, b, purpose, tier_a?, tier_b?, days?, note?, relay?, name_a?, name_b?}` | the record, `status: "pending"`; refused: `409` with the `link_*` check |
| `POST /api/unlink` | `{id}` | `{id, status: "ended", role}` |
| `POST /api/links/answer` | `{id, accept, tell?, tier?}` | `{id, from, status: "linked"\|"accepting"\|"refused"\|"failed", told}`; `tier` friend or quiet (default) |
| `POST /api/links/allow` | `{contact, allow, tier?, days?}` | `{contact, name, allow, tier, until}`, or `{contact, allow: false, had}` |
| `GET /api/settings` | | `{relay, default, fixed, in_use}`: the relay new codes name (default `relay.sigelo.ai`); `fixed`: `SIGELO_RELAY`'s host, which wins, or null; `in_use`: this session's own |
| `POST /api/settings` | `{relay}` | the same; `relay` a host[:port], `""` or null for the default; kept in `.ui.json` `settings` |
| `GET /api/relays` | | `{relays: [{tag, host, did?, tier?, note?}]}`: the signed `sigelo.ai/relays.json`, verified, fetched at most once a day |
| `POST /api/relays/test` | `{relay}` | `{relay, ok, ms, retention_days, detail?}`: the picker's Test: GET `/relay.json` at that host, else `/challenge` |
| `GET /api/groups` | | `{tier: {tier, groups, members, told}, groups: [{gid, name, status, ver, brake, creator, creator_name, mine, foreign, run, members: [{did, name, role, me, contact}], unread, quiet, last}], notices}` (GROUPS.md): `tier` the relay's answer at login (`told`), else the guess; `quiet`: the brake reached, agents wait for a human; `last` `{name, text, at, mine}` |
| `GET /api/groups/history` | `group=<gid>` | `{group, messages: [{mid, re, from, name, role, tier, mine, operator, note, text, mentions, mentioned, via, at}]}`, last 200; marks them read. `note`: `"not your operator"` |
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
| `GET /api/transfers` | | `{out, in, direct, settings}` (TRANSFER.md): each `{id, contact, name, size, state, attempt, via, reason?, detail?, got\|sent, live?, rate?, saved?, path_used?}`; `state` `asked`, `offered`, `accepted`, `offering`, `active`, `interrupted`, `done`, `declined`, `cancelled`, `failed`, `expired`; `direct` `{did: true\|false}`; `settings` `{tor, prefer}` |
| `POST /api/transfers/send` | `{to, path, via?, direct?}` | the record, `offered`: a file of this computer, read in place (≤ 16 GiB); never remote |
| `POST /api/transfers/accept` | `{id, direct?, via?}` | the record, `accepted`: free disk checked; the page's engine offers. `409 direct_ask`: ask once, send again with `direct` |
| `POST /api/transfers/resume` | `{id, direct?}` | as accept, for `interrupted` or a failed `no_path`: only the missing chunks |
| `POST /api/transfers/decline` | `{id}` | the record, `declined`: the contact is told |
| `POST /api/transfers/cancel` | `{id}` | the record, `cancelled`: the contact is told; the partials go |
| `POST /api/transfers/forget` | `{id}` | the record, gone here with its partials |
| `POST /api/transfers/direct` | `{contact, on}` | `{did, name, direct}`: may this contact see my addresses |
| `GET /api/transfers/settings` | | `{tor, prefer, tor_daemon: {serve, connect}, direct_available}`: the Tor checkbox (off when no daemon answers); Pro's order `fast`\|`private` |
| `POST /api/transfers/settings` | `{tor?, prefer?}` | the same, kept |

`contact` is the contact's original DID. A contact in `groups`: `{did, name, current_did, relay, re_pair,
words, pair, words_checked, tags, local, mine, unread, last, waiting, not_collected, queued, status,
ours, tier, link, online, online_since, last_seen, presence}`. `online`: `true`, `false` (then `last_seen`, the relay's time) or `null` (not known: not allowed, or this page offline); `presence`: what they see of mine. `link`: `{id, purpose, linked_by, expires}` or null. `status`: `ok`, `waiting` (their keys have not come, or the carrier says why messages wait:
`waiting`), `not_collected` (a message queued, no reader yet), `pair_again` (`re_pair` after a recovery). `tier` (contact/store.mjs): `own` (my agents:
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
seat: {holder, epoch, here}|null}`. Proof of work (design/profiles.md §6): a call the human starts (invite, accept, enrol-code,
pow/try, the page's start) past 3 searches a day at a relay answers `409 pow_confirm` (its message the question), and goes with
`pow_confirmed: true`; the automatic retries stop instead (`pow_capped.next`: the next automatic try)
(`here` false: another device holds the seat; the page shows a banner and its writes refuse `seat_elsewhere`). A pending invite:
`{name, exp, relay, id?, short?, short_exp?, code?}`; `paired`: `{id, name, paired: <did>}` for the
pairing view. `answers`: codes this side answered, waiting for the inviter until `exp`. `failed`:
`pairing_failed` of the last day (`code_expired`: expired before they replied). `introductions`: `[{id, from, name, purpose}]`,
introductions to this identity waiting for an answer, introducer not quiet: the page's banner. The page runs the link handler
(link.mjs) as `watch` does; link messages and codes never reach the history.

**Agents:** the page's own session enrols them (the CLI's `enrol` refuses `busy` beside it); worker indices are given at the seat only.
The keeper's `workers` are the list; a code's temporary pairing never shows in the contacts or the history.

**Devices:** the page's own session runs them (the CLI's `device` verbs refuse `busy` beside it). Enrolment and device
messages never reach the history. QR codes are drawn and read in the page with `qr.mjs` and `qr-decode.mjs` (served
beside it, with `shim-*.mjs`; the import map is its one inline script, allowed by hash in the CSP): camera where
`getUserMedia` finds one, else an image file or paste. The six offline words come only from `/words`, after the frames.

**Groups:** the page's own session handles them at each drain (contact/group.mjs `handle`: rosters taken,
copies carried on, messages filed; the CLI's `group` verbs refuse `busy` beside it). `chats` in `state`: `{unread, invited,
notices, rev}`, the Groups tab's count; `rev` changes with any group's roster, status or newest message. Notices
(`{id, why: stranger|creator_left|refused, …}`) are kept in `.ui.json` until dismissed; an invitation is a group `pending`.

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
a replay, a wrong key or an unknown id get `403` and no body. **Scopes:** `read`: state, me, messages, links, agents/workers, transfers; `chat`: + send,
accept, invite, invite/cancel, words, rename, tag, sync, links/answer (pairs as accept does), pow/try; `all`: + forget, tier, history/clear, agents
(enrol-code, enrol-words, revoke, rename too), link, unlink, links/allow (who the agents talk to, as tier), settings, relays, relays/test, transfers/accept, decline, cancel, resume, forget, direct, settings. Outside it: `403 scope`;
`/api/devices*` and `/api/transfers/send` (a file of the computer, by path) never (`403 remote`). `ui --controls` lists them (never a key); `ui --revoke-control <name>` forgets one
(stop the page first: it owns the file). No TLS: the LAN sees sizes and timing; the text is page control until revoked.
Client: `remote-client.mjs`. **Over the relay** (`ui --remote --relay [--name] [--scope]`, no listener): it prints
`SIGELO:CTL:<short code>[:<HOST>]`; the app pairs a control identity of its own (a random key, never attested; contact/control.mjs) and the
four words are confirmed at the computer (before: `403 words`): its terminal (y/N), or the page's Controls card, `GET /api/controls` → `{pending: [{name, scope, words}]}` and `POST /api/controls/confirm` `{name, match}` → `{name, confirmed}` (refused: forgotten; none waiting: `404 control_unknown`; never remote, the app refuses it unsent: `403 remote`). Calls are `sigelo-device/1` `request` {id, method, path, body?}
→ `response` {id, status, body}, the same scopes; a request opens a 10-minute lease of `events` {seq, since, state} (GET /api/state, pushed
on change; past 64 KiB a summary, the newest 20 contacts of each group and events, `truncated: {contacts, events, kept}`, and the app's "Pull the rest" asks `GET /api/state?full=1`, a request), so the app's poll reads it locally: one request per 5 minutes while open. Cap: 10 at once, then 1/s (`429 rate`).
Seat elsewhere: `409 seat_elsewhere`. Each message counts in the relay allowance: requests the control's day, answers and events
yours. The control is marked `relay` in `controls{}`; revoking forgets its contact. Phone side without a WebView carrier:
`sigelo-agent control pair <text> | ui --app | forget` (apps/gtk); the control key sealed in the OS keyring (as `--keychain`), plain 0600 with a warning when none answers. **`local`:** the self-contained app (apps/web) answers these routes in the page, over its own carrier, with the same JSON (contact/page.mjs). The Android app (apps/android) shows that page, or a computer's through `/r`, sealed in the page, carried by the app's HTTP. **`ui --app`:** for a shell that shows the page (apps/gtk): no browser, and the page stops when stdin ends. **Install:** `ui --port <p>` keeps the origin (taken: `port_taken`); `manifest.webmanifest`
and `sw.js` keep `ui.html`, `ui.js`, `ui.css` only, never `/api/`.

## Profiles (the apps)

Not routes: the phone apps' own, beside these (design/profiles.md P1). Me → Profiles (`ui.js`) calls the shell's
`profiles`: in the WebView app `sigeloLocal.profiles` (apps/web/boot.mjs), in the GTK phone app the bridge's ops
`profiles`, `profile-use`, `profile-rename`, `profile-add`, `profile-remove` (answered to the start page, `ui.html` and this
phone's own page; never another page). `list()` → `{active, limit: 8, profiles: [{id, name, kind: "words"|"remote"|null,
did, words, created}]}`; `use(id)` switches (the lock once, then the page of that profile); `rename(id, name)` (1 to 24
characters, else `profile_name`); `add()` (past 8: `profile_limit`) opens the new one's first run; `remove(id, {name, words})`:
a `words` profile needs `words: true` (`profile_words`) and its name typed (`profile_name`), a `remote` one its name, one
not set up nothing. A computer's own page has none: no Profiles in Me. A `words` profile whose words are kept needs its
words password too: WebView `{password}`, GTK `{proof}` (below); else `words_password_needed`, `words_password`.

The words password (design/apps-seed.md §8), Me → Security (`ui.js`), where this phone holds its own identity from the
25 words. WebView app: `sigeloLocal.words` (apps/web/words.mjs): `status(id?)` → `{here, kept, iterations}` (with an id:
that profile's `kept`); `reveal(password)` → `{words: [25]}` after the screen lock; `change(old, next, repeat)`;
`remove(password)` (the kept words deleted); `auth(id, password)` → what a guarded call carries. `sigeloLocal.secure(on)`:
`FLAG_SECURE` while the words are up. Refusals: `words_none`, `words_password`, `words_password_needed`,
`words_password_rule` (at least 8 characters, the repeat the same). GTK phone app, bridge ops beside the profile ones:
`words-status {id?}` → `{here, kept, keyring}`; `words-get {id?}` → `{blob}` (base64 of words-lock.mjs's blob; never the
check); `words-keep {blob, check, proof?}` (proof needed over kept words); `words-drop {proof}`; `take {proof?}` on the
start page. The page does the crypto with `/words-lock.mjs`, which `ui` serves (contact/words-lock.mjs, as it is).

## Computers (the apps)

Not routes either (design/profiles.md P2): a remote profile's computers, each paired once. Me → Connect → Computers
(`ui.js`) calls `sigeloLocal.computers` (WebView app) or the GTK bridge's `computers`, `computer-use`, `computer-add`,
`computer-forget`. `list()` → `{active, limit: 8, computers: [{id: "c1"…, name, via: "lan"|"relay", did, words, where,
paired, last_used}], profile: {id, name, did, words}}`; a profile holding an identity: `not_remote` (no Connect in Me).
`use(id)` opens that computer's page (the lock once); `add()` opens the pairing screens (code or scan; Cancel back);
`forget(id)` drops its control key on this phone and answers `{revoke}`: `sigelo-agent ui --revoke-control <name>` on
the computer, which keeps the control until then. Pairing a computer whose page (`GET /api/me` `original`) is another
identity than the profile's operator is refused `other_operator`; nothing of it is kept.

