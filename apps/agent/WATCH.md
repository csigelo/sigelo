<!-- SPDX-License-Identifier: MIT -->
# `sigelo-agent watch`

Stays connected to the relay for one identity file, so an invite completes by itself when the
other side accepts, and hands each message on by its sender's tier.

```sh
sigelo-agent watch [--identity <file> | --operator] [--on-message <cmd> | --spool <dir>] [--on-notice <cmd>] [--on-pairing <cmd>]
                   [--hook-timeout <s|10m|1h>] [--quiet]
```

| Tier | What happens | Set by |
|---|---|---|
| `own` | `--on-message`: the message, as `inbox` gives it, as JSON on stdin; taken once the command exits 0 | detected: an operator attestation from you or your operator |
| `friend` | `--on-notice`: `{from, name, tier, count}`, no content; the message stays for `inbox` | the default |
| `quiet` | nothing; it stays for `inbox` | `tier <name> quiet`, `accept --tier quiet` |

An own agent stays yours (`ours: true` in `contacts`) at `friend` or `quiet`, by your choice
(`enrol --tier friend`, ENROL.md): for one exposed to untrusted input, its messages are pulled, not pushed.

`--on-pairing` gets `paired` and `pairing_failed` events as JSON. Each command runs through the shell,
one at a time, at most `--hook-timeout` (default 2 minutes), with `SIGELO_TYPE`, `SIGELO_FROM` (the DID),
`SIGELO_NAME`, `SIGELO_TIER`, `SIGELO_PATH` (files), `SIGELO_IDENTITY` and, for a message, `SIGELO_MSG_ID`.
Without a hook: one line per event on stdout; `--quiet`: none. Diagnostics go to stderr.
A ready `--on-message` hook ships in the npm package: [`examples/reply-hook.sh`](examples/reply-hook.sh)
(pipes the text to `$SIGELO_REPLY_CMD`, sends back what it prints; README "Answering by itself"). Installed
with `npm i -g`: `sh "$(npm root -g)/sigelo-agent/examples/reply-hook.sh"`.

## Slow agents

An agent on a slow machine may take minutes or hours over one message.

- **A hook that fails or is stopped leaves the message unread; it is offered again on the next sync
  (each minute, and at the next start); dedupe on `SIGELO_MSG_ID`.** Nothing is dropped.
- `--hook-timeout <s|10m|1h>` (or `SIGELO_HOOK_TIMEOUT`): how long a hook may run before it is
  stopped; `0`: no limit. Hooks run one at a time, so a long one holds the next message back.
- **Accept now, reply later.** A hook that exits 0 takes the message: it can write the task down and
  exit at once. `--spool <dir>` does that without a hook: each own message goes to `<dir>/<id>.json`
  (0600, whole or not at all) and is taken. When the work is done:

```sh
sigelo-agent reply --to <id> "the answer"      # or - for stdin, or --file <path>; label "reply"
sigelo-agent reply --to <id> --status          # queued, published or refused
```

  `reply` goes to the message's sender, through the watcher if one runs. It is known for 30 days.
  Its delivery: queued (here, not yet at the relay), published (the relay holds it in the contact's
  mailbox) or refused. "Fetched" is never known: the relay does not tell the sender. A seen receipt
  (below) says what the contact's app showed, when it sends them (`contacts`: `seen_upto`).
- **Read marks** (0.1.19): an own message taken by a hook, or by `inbox`, the MCP or `host claude`
  from the spool, sends its sender one seen receipt, by code, once: the operator's app shows ✓✓.
- **The message id** is the carrier's, the same at every offer and in `inbox`, `history` and the
  MCP tools: 32 hex digits from SHA-256 of the sender's DID and the envelope's epoch and number (a
  file: its file id; a group message: `<gid>.<mid>`, answered in the group). Nothing of it is sent.
- **Codes for a slow agent:** `invite --ttl 1h` and `enrol --ttl 1h` keep a short code up to an hour
  (60 s to 1 h; default 10 minutes). A code taken by someone else still pairs wrong: the four words
  differ, so compare them.
- **MCP:** `sigelo_wait_for_message` waits for one (up to 10 minutes), `sigelo_reply` answers by id.
  Beside a watcher it refuses: use the hook.

Change a tier any time: `sigelo-agent tier <name> own|friend|quiet`. Own agents find each other
through operator hints (apps/contact/carrier.mjs): blinded, so other contacts learn nothing.

## Re-verifying a spooled message

```sh
sigelo-verify sender.bundle.json    # SPEC §9 on the sender's bundle (their `sigelo-agent bundle`): did, chain
```

```js
import { did, verify, verifySig } from 'sigelo';
const r = verify(bundle, now), s = item.signed;
const g = [bundle.genesis, ...bundle.rotations.map((x) => x.next_genesis)].find((x) => did(x) === s.body.from);
const ok = g !== undefined && r.chain.includes(s.body.from) && verifySig(g.key, s.body, s.sig);
```

Each message item (a spool file, `--on-message`'s stdin, `inbox`, `history`) carries,
beside its unchanged plaintext fields, `signed: {body, sig, epoch, n, key}` and `verified: true`.
`body` is the envelope's signed body as opened: `v` `sigelo-msg/0`, `typ`, `from` (the sender's
current DID), `to` (your original DID), `pair`, `epoch`, `n`, `iat`, `label`, `content`; `sig` is
detached over `"sigelo\n"` and its JCS (SPEC §3); `key` is the key it verified under. No CLI checks
a detached signature alone: the library's `verifySig` does. `body.from` is normally the bundle's
current DID (`r.did`); an older DID in the chain means the sender rotated since, and after a
recovery an old key may be a thief's (SPEC §7.1).

`verified: true` says only what the carrier checked before the item existed: the signature under
the sender's current key as held here, `from` that key's DID, `to` you, `pair` this pairing,
`epoch` and `n` the header's. In a file (spool, `history`) it is only what was written there: for
proof, re-verify. Files and group messages carry no `signed`; the MCP tools leave it out.

One caveat: a spooled signed body is proof, to anyone it is forwarded to, that the sender signed
that content for you.

## Always on

An enrolled agent must always get its owner's messages: `sigelo-agent service install` runs
`watch --spool <identity>.spool --quiet` as a service of the machine (Linux: a systemd user unit,
`Restart=always`; `loginctl enable-linger` keeps it after logout; macOS: a LaunchAgent; Windows: the
`schtasks` step is printed), one per identity (`sigelo-watch-<tag>`, the tag from the file's path). An
earlier fixed-name `sigelo-watch` (and its `sigelo-watch.timer`) running the same identity is stopped, disabled
and removed first, one running another identity left and said: never two units on one identity file.
`service status` says whether a watcher holds the file, lists every sigelo unit here with its identity and
any two that claim one (a conflict); `service remove` undoes it, the earlier unit of that identity too. Beside it, `inbox` and the MCP `sigelo_inbox` take what it spooled (the files deleted) instead
of logging in. `init --enrol <code> --service` installs it once placed.

## One process per identity file

While `watch` or `ui` (the page) runs on a file (`<identity>.ui.pid`), it is the only process logged
in to the relay as that identity. Beside a watcher, `inbox` reads what it received, `send`,
`send-file` and `reply` queue for it (it sends them within seconds), `accept` and `invite` are asked of
it (`<identity>.ui.ask/`: it runs them on its session and answers; never kill it to run them), `group join`
kicks it, and `forget` and `enrol` refuse (exit 1, `busy`); beside a page, all of them refuse. The MCP tools follow the same rule.
The file is the owner however it is named: `watch --operator` (ENROL.md) and `send --identity
~/.config/sigelo/me.local.json` meet at the same lock. On `busy`: stop the watcher or page, or let it
do the work (its hooks, `send`, `reply`); a second process that must log in itself needs its own
identity, a named profile (`--identity ~/.config/moadim/sigelo.<name>.local.json`, MCP `identity`).
A watcher runs for days: keep its key in the keychain or the key agent ([KEYS.md](KEYS.md)).
It stays connected to every relay a contact was paired on (`invite --relay`, `accept --relay`), not only `SIGELO_RELAY`.
It handles links by code (LINKS.md): the operator's introductions complete while it runs; no hook sees them.
Anyone else's introduction (unless that contact is quiet here) → `--on-notice` with `{type: "link", id, from,
name, peer, peer_name, purpose, note}`; `links accept <id>` beside it is carried out by the watcher.
SIGINT or SIGTERM: exit 0. Exit 1: refused (another watcher or page); 2: usage or no identity.
