<!-- SPDX-License-Identifier: MIT -->
# Transfer: big files agent to agent

Up to 16 GiB from one contact to another. The relay carries four small signed messages; the bytes go
direct between the two computers, or over a one-shot Tor onion service. Up to 8 MiB, `send-file` still
works with one side offline.

```sh
sigelo-agent transfer send bob ~/film.mkv        # bob's operator is asked first
sigelo-agent transfer list                       # bob: "alice offers film.mkv (1.2 GB)"
sigelo-agent transfer accept <id>                # bob: yes; both move it, then exit
sigelo-agent transfer decline <id>               # or no
```

Both sides need a live session while the bytes move: `send`, `accept` and `resume` stay connected
until the transfer ends (`--wait <s>`, default 3600; `0` returns at once), or a running
`sigelo-agent watch`, `ui` or MCP server on that identity does it (an MCP server moving a file holds
the identity's lock as a page does). Beside a watcher the verbs queue
for it; beside a page they refuse (`busy`): use its Files view.

## Verbs

| Verb | |
|---|---|
| `send <contact> <path> [--via tor] [--direct on\|off]` | hashes the file in place, sends its manifest |
| `list` | both sides: state, MB, MB/s, path (direct or Tor), reason |
| `accept <id> [--direct on\|off] [--via tor]` | free disk checked; nothing is written before it |
| `decline <id>`, `cancel <id>`, `forget <id>` | no; stop either side; drop the record and partials here |
| `resume <id>` | after a drop or a lapsed offer: only the missing chunks |
| `direct <contact> on\|off` | may this contact see your addresses |
| `settings [--tor on\|off] [--prefer fast\|private]` | the Tor checkbox; Pro's order |

Exit 0 done or queued, 1 refused or failed (the check on stderr), 2 usage. MCP: `sigelo_transfer`,
`action` `send`, `accept`, `decline`, `resume`, `cancel`, `status`; a file offered reaches `sigelo_inbox`
as an event `{type: "transfer", what: "asked", id, file, size}`. Page: the Files view and
`/api/transfers*` (UI-API.md). `send` is never remote.

## Consent and the direct switch

- **A manifest is a question.** Name, size, SHA-256 and the chunk list's hash, under 1 KiB. Only the
  receiver's operator (CLI, page) or its agent (MCP, told by the operator) says yes. At most 8 wait
  per contact, 64 in all; more are answered `busy`. A manifest lives 7 days.
- **Direct shows the contact your public and LAN addresses.** On for your own agents; asked once for
  every other contact (`direct_ask` until you say on or off; a terminal asks y/N). Off: Tor, else no
  path.
- **Tor is a checkbox** (`settings --tor`), on by default, used only when a tor daemon answers:
  `SIGELO_TOR="<control host:port>[,<socks host:port>]"` (default `127.0.0.1:9051,127.0.0.1:9050`;
  `off`), `SIGELO_TOR_PASSWORD` for a hashed control password; a readable cookie or no auth works
  without it. Nothing is ever installed for it.

## Paths

Free: direct, then Tor, else refused: "No direct path to bob from these two networks, and no Tor.
Up to 8 MiB: send-file. Tor on both sides, or Pro, carries larger files." `--via tor`: Tor only. Pro:
`prefer fast` (direct, then relayed TURN, then Tor) or `private` (Tor first); TURN is not built yet,
so `fast` goes direct, then Tor.

**Direct:** WebRTC data channel (ICE, DTLS, SCTP) on werift in the separate package
`sigelo-transfer` (pure TypeScript, no native code). Candidates are gathered for 3 s and sent whole
inside the signed offer and answer, so the relay never sees them and the identities authenticate the
DTLS fingerprints. STUN: port 3478 of your relay host and the contact's (`SIGELO_STUN`, `host:port`
list; empty: local candidates only). An offer waits 10 minutes for its answer; ICE gets 30 s.

**Tor:** the side that serves (the sender if it can) adds an ephemeral v3 onion with its key discarded
and client authorization for a fresh x25519 key, and sends address, port, key and a 32-byte token
signed through the relay; the other connects over SOCKS and sends the token first. Any other stream
is closed. `DEL_ONION` when done. Publishing takes 10 to 60 s; expect 0.5 to 3 MB/s.

## On the wire and on disk

Pull by index: the receiver asks for chunks of 1 MiB, at most 8 not yet written, and asks again only
after writing (the back-pressure); each comes in frames of at most 64 KiB. The list of chunk hashes
comes first, checked against the manifest; each chunk is checked by SHA-256 (a bad one is asked once
more, then `chunk_hash`); at the end the whole file is read back and checked.

Partials: `<identity>.files/.transfer/<id>.part` (0600, written at offsets), `.have` (a bit per chunk,
set once checked and flushed), `.list`. Done: placed as `send-file` places one,
`<identity>.files/<contact>-<hex>/<sha256[0..8]>-<name>`, never opened, and one inbox item
`{type: "file", …, transfer: <id>}`. A drop resumes by itself (3 tries), with a new offer for the same
manifest. The sender reads the file in place and ends `file_changed` if its size or time moved.
Partials go 7 days after the last byte, or at `forget`. State: `<identity>.transfers.json` (0600).

## What each party learns

| | Direct | Tor |
|---|---|---|
| The contact | your public and LAN addresses | nothing of your address |
| The relay | four messages and their timing | the same |
| The relay host's STUN port | both public addresses, seconds before | nothing |
| Size, duration | nobody but the two | nobody but the two |

THREAT-MODEL §2.18, §3.14–§3.16. Measured on a phone-class computer, both ends on it over loopback:
2.6 MB/s direct; across real networks, not yet.
