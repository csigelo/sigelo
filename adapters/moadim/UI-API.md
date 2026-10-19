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
| `GET /api/state` | `since=<seq>` | `{seq, now, me, groups: {mine, contacts}, pending: {invites, paired, answers, failed}, events}` |
| `GET /api/me` | | `{did, original, chain, identity_file, recovery: "set"\|"none", key: "file", relay, retention_days, erase}` |
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

`contact` is the contact's original DID. A contact in `groups`: `{did, name, current_did, relay, re_pair,
words, pair, words_checked, tags, local, mine, unread, last, waiting, not_collected, queued, status,
ours, tier}`. `status`: `ok`, `waiting` (their keys have not come, or the carrier says why messages wait:
`waiting`), `not_collected` (a message queued, no reader yet), `pair_again` (`re_pair` after a recovery). `tier` (contact/store.mjs): `own` (my agents:
an unexpired `sigelo-relay/operator` attestation from my DID, seen in a local agent's file or proved
by the agent), `friend` (the default; the page shows "new message" and a count), `quiet` (nothing
until opened); the human's choice (`/api/tier`) wins. `ours`: that attestation marks it, whatever the tier (an
own agent may be `friend` by choice). **Mine** = `ours` or tier `own`; `mine` = the attestation's
expiry for a local agent; `local` = the agent's name on this machine.

`me` in `state`: `{did, relay, online, clock_offset (s, relay minus local, the carrier's `clockOffset`), clock_checked,
retention_days, error, pow: {bits, elapsed_s, expected_s}|null, pow_done_ms}`. A pending invite:
`{name, exp, relay, id?, short?, short_exp?, code?}`; `paired`: `{id, name, paired: <did>}` for the
pairing view. `answers`: codes this side answered, waiting for the inviter until `exp`. `failed`:
`pairing_failed` of the last day (`code_expired`: expired before they replied).

**Files:** one received is an `in` message, `file <name> (<size> bytes), saved at <path>`. Sending one: not yet (the disabled 📎).
