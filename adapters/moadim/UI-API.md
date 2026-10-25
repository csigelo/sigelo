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
| `GET /api/state` | `since=<seq>` | `{seq, now, me, groups: {mine, contacts}, pending: {invites, paired, answers, failed}, events, introductions}` |
| `GET /api/me` | | `{did, original, chain, identity_file, recovery: "set"\|"none", key: "file", relay, retention_days, erase, restored?}`; `restored` `{on, keeper, seat: "here"\|"elsewhere"\|null}` when the identity comes from the 25 words and its keeper file has the day it was made (Me: "Restored from seed on …") |
| `POST /api/invite` | `{name?, long?}` | `{id, name, code, exp, short?, short_exp?, relay}`: `short` parked 10 min; `short_exp` the relay's clock |
| `POST /api/invite/cancel` | `{id}` | `{cancelled: true}` |
| `POST /api/accept` | `{code, name?, tier?}` | `{status: "connected", contact: {did, name, fingerprint, pair, tier}}`, or `{status: "waiting"\|"pending", did, detail, exp}`; `tier`: `friend` or `quiet` (own is detected) |
| `POST /api/words` | `{contact, match}` | `true`: `{checked: true}`; `false`: forget and block |
| `POST /api/rename` | `{contact, name}` | `{did, name}`; `409 name_taken` if another live contact has it |
| `POST /api/tier` | `{contact, tier}` | `{did, name, tier, ours}`: `own`, `friend` or `quiet`, kept until changed |
| `POST /api/tag` | `{contact, tags: [≤ 8, ≤ 20 chars]}` | `{tags}` |
| `POST /api/forget` | `{contact}` | `{forgotten, offline}`: revoked here for good |
| `POST /api/send` | `{to, text}` | the history record: `{n, at, kind: "out", did, id, text, status: "sent"\|"queued"\|"refused", code?, detail?}` |
| `GET /api/messages` | `contact=<did>&since=<n>` | `{seq, messages: [{n, dir: "in"\|"out", at, text, label, status, code, detail}]}`, last 200; marks them read |
| `POST /api/sync` | | `{synced: true}`: one round now ("Retry now") |
| `POST /api/history/clear` | | `{cleared: true}` |
| `GET /api/agents` | | `[{name, did, error, mine: {exp, days_left}\|null, worker: i\|null, renew, contacts, contact}]`: the agents' directory; `contacts`: the agent's own |
| `POST /api/agents/enrol` | `{agent}` | `{agent, worker, renewed, did, exp, days_left, old?, contacts?, warning?}`: `enrol --here` into the agent's file (ENROL.md); a worker: the attestation renewed. `400 keeper`: run `sigelo-agent keeper --from-words` |
| `POST /api/agents/pair` | `{agent}` | `{status, contact}`: both sides in this process, words checked |
| `GET /api/links` | | `{made, links, received, allow}` (LINKS.md): links I made `{id, a, b, a_name, b_name, kind, purpose, note, tier_a, tier_b, expires, status, step, check}`; contacts linked to me; introductions waiting `{id, from, name, peer, peer_name, purpose, note, exp, quiet, answer?}`; allow rules `{contact, name, tier, until}` |
| `POST /api/link` | `{a, b, purpose, tier_a?, tier_b?, days?, note?, relay?}` | the record, `status: "pending"`; refused: `409` with the `link_*` check |
| `POST /api/unlink` | `{id}` | `{id, status: "ended", role}` |
| `POST /api/links/answer` | `{id, accept, tell?, tier?}` | `{id, from, status: "linked"\|"accepting"\|"refused"\|"failed", told}`; `tier` friend or quiet (default) |
| `POST /api/links/allow` | `{contact, allow, tier?, days?}` | `{contact, name, allow, tier, until}`, or `{contact, allow: false, had}` |
| `GET /api/settings` | | `{relay, default, fixed, in_use}`: the relay new codes name (default `relay.sigelo.ai`); `fixed`: `SIGELO_RELAY`'s host, which wins, or null; `in_use`: this session's own |
| `POST /api/settings` | `{relay}` | the same; `relay` a host[:port], `""` or null for the default; kept in `.ui.json` `settings` |
| `GET /api/relays` | | `{relays: [{tag, host, did?, tier?, note?}]}`: the signed `sigelo.ai/relays.json`, verified, fetched at most once a day |
| `GET /api/devices` | | `{devices, list, adding, joining}` (DEVICES.md): `devices` `[{name, rank, worker, did, original, via, added, seen, paired, ours, tier, attested_until, revoked}]`; `list` `{seq, iat}` or null; `adding` (online adds) `[{id, name, worker, did, qr, short, exp, state, words}]`, `state` `code`, `words`, `sending`, `done`, `refused`, `expired`; `joining`: this machine's scan of an online code `{state, file, words, …}` or null |
| `POST /api/devices/add` | `{name, offline?, tier?, days?, words?}` | online: an `adding` entry (`qr` `SIGELO:DEV:…`, 10 min); offline: `{id, name, worker, did, frames, list, exp}`. SAFE only: `full` → `409 device_full` (a terminal) |
| `POST /api/devices/confirm` | `{id, match}` | the words gate: `true` sends its key; `false` drops it (`refused`); before the device answered `409 device_state` |
| `POST /api/devices/words` | `{id}` | `{words}` of an offline add, once, within 10 minutes; then `404` |
| `POST /api/devices/scan` | `{text \| texts, name?, words?}` | this machine as the device, into `sigelo.<name>.local.json` (agents' directory): an online code → `{kind: "online", state, file}` (then `joining`); frames → `{state: "frames", have, count, missing}`, `{state: "words"}`, with `words` `{state: "done", did, worker, operator, file, paired}`; wrong words `409 device_words` |
| `POST /api/devices/revoke` | `{name, lost?}` | `{device, rank, worker, revoked, lost, wiped: false, forgot, list, synced, steps?}`: the wipe answered later; `lost` forgets now, `steps` the rest |
| `POST /api/devices/sync` | | `{list, synced, forgot}`: the signed list to every device; wiped answers read |

`contact` is the contact's original DID. A contact in `groups`: `{did, name, current_did, relay, re_pair,
words, pair, words_checked, tags, local, mine, unread, last, waiting, not_collected, queued, status,
ours, tier, link}`. `link`: `{id, purpose, linked_by, expires}` or null. `status`: `ok`, `waiting` (their keys have not come, or the carrier says why messages wait:
`waiting`), `not_collected` (a message queued, no reader yet), `pair_again` (`re_pair` after a recovery). `tier` (contact/store.mjs): `own` (my agents:
an unexpired `sigelo-relay/operator` attestation from my DID, seen in a local agent's file or proved
by the agent), `friend` (the default; the page shows "new message" and a count), `quiet` (nothing
until opened); the human's choice (`/api/tier`) wins. `ours`: that attestation marks it, whatever the tier (an
own agent may be `friend` by choice). **Mine** = `ours` or tier `own`; `mine` = the attestation's
expiry for a local agent; `local` = the agent's name on this machine.

Only in the self-contained app (apps/web, not `ui`): `POST /api/seat/take` `{confirm: true}` for a standby
restored from seed: the list signed naming this device, then the page logs in as you (`seat take --force`
semantics: the other device must be stopped or lost) → `{seat: "here", holder, epoch}`; `400` without
`confirm`, `409 seat_here`.

`me` in `state`: `{did, relay, online, clock_offset (s, relay minus local, the carrier's `clockOffset`), clock_checked,
retention_days, error, pow: {bits, elapsed_s, expected_s}|null, pow_done_ms, seat: {holder, epoch, here}|null}`
(`here` false: another device holds the seat; the page shows a banner and its writes refuse `seat_elsewhere`). A pending invite:
`{name, exp, relay, id?, short?, short_exp?, code?}`; `paired`: `{id, name, paired: <did>}` for the
pairing view. `answers`: codes this side answered, waiting for the inviter until `exp`. `failed`:
`pairing_failed` of the last day (`code_expired`: expired before they replied). `introductions`: `[{id, from, name, purpose}]`,
introductions to this identity waiting for an answer, introducer not quiet: the page's banner. The page runs the link handler
(link.mjs) as `watch` does; link messages and codes never reach the history.

**Devices:** the page's own session runs them (the CLI's `device` verbs refuse `busy` beside it). Enrolment and device
messages never reach the history. QR codes are drawn and read in the page with `qr.mjs` and `qr-decode.mjs` (served
beside it, with `shim-*.mjs`; the import map is its one inline script, allowed by hash in the CSP): camera where
`getUserMedia` finds one, else an image file or paste. The six offline words come only from `/words`, after the frames.

**Relay setting:** new codes name `SIGELO_RELAY` if set, else the setting, else `relay.sigelo.ai`; a change applies to the
next invite and to this page's own connection at its next start. Codes accepted never read it: 8 characters are `relay.sigelo.ai`'s,
12 name their relay by its tag (local table, then the registry).

**Files:** one received is an `in` message, `file <name> (<size> bytes), saved at <path>`. Sending one: not yet (the disabled 📎).

## Remote

`ui --remote [--listen <ip>] [--name <control>] [--scope read|chat|all]` adds a listener on a LAN address
(default: the default route's) that answers only `POST /r`; anything else is `404` with no body. It prints
`SIGELO:UI:<ip>:<port>:<base45 of id (8 bytes) ‖ key (32)>` for the named control (new: scope `chat`), kept in `.ui.json` `controls{}`.
A request `{id, ctr, nonce, box}` (≤ 1 MiB; `id` hex; `nonce`, `box` base64url): `box` = XChaCha20-Poly1305(key, nonce,
aad `"sigelo-remote/0 req"` ‖ id ‖ u64be(ctr), JCS `{method, path, body?}`). The answer `{nonce, box}` under aad `"… res"` ‖ id ‖ ctr
holds `{status, body}`, what this listener would answer. `ctr` must exceed the last one kept (one call at a time):
a replay, a wrong key or an unknown id get `403` and no body. **Scopes:** `read`: state, me, messages, links; `chat`: + send,
accept, invite, invite/cancel, words, rename, tag, sync, links/answer (pairs as accept does); `all`: + forget, tier, history/clear, agents,
link, unlink, links/allow (who the agents talk to, as tier), settings, relays. Outside it: `403 scope`;
`/api/devices*` never (`403 remote`). `ui --controls` lists them (never a key); `ui --revoke-control <name>` forgets one
(stop the page first: it owns the file). No TLS: the LAN sees sizes and timing; the text is page control until revoked.
Client: `remote-client.mjs`. **Over the relay** (`ui --remote --relay [--name] [--scope]`, no listener): it prints
`SIGELO:CTL:<short code>[:<HOST>]`; the app pairs a control identity of its own (a random key, never attested; contact/control.mjs) and the
four words are confirmed at the computer's terminal (before: `403 words`). Calls are `sigelo-device/1` `request` {id, method, path, body?}
→ `response` {id, status, body}, the same scopes; a request opens a 10-minute lease of `events` {seq, since, state} (GET /api/state, pushed
on change), so the app's poll reads it locally: one request per 5 minutes while open. Cap: 10 at once, then 1/s (`429 rate`).
Seat elsewhere: `409 seat_elsewhere`. Each message counts in the relay allowance: requests the control's day, answers and events
yours. The control is marked `relay` in `controls{}`; revoking forgets its contact. Phone side without a WebView carrier:
`sigelo-agent control pair <text> | ui --app | forget` (apps/gtk). **`local`:** the self-contained app (apps/web) answers these routes in the page, over its own carrier, with the same JSON (contact/page.mjs). The Android app (apps/android) shows that page, or a computer's through `/r`, sealed in the page, carried by the app's HTTP. **`ui --app`:** for a shell that shows the page (apps/gtk): no browser, and the page stops when stdin ends. **Install:** `ui --port <p>` keeps the origin (taken: `port_taken`); `manifest.webmanifest`
and `sw.js` keep `ui.html`, `ui.js`, `ui.css` only, never `/api/`.
