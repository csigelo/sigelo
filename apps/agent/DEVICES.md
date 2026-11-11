# Devices: your account on a phone or a second computer

```sh
# Online, both connected:
sigelo-agent device add --name phone [--full] [--days 1..90]  # a QR, 10 min
sigelo-agent device scan 'SIGELO:DEV:K7F3-Q9ZP' --name phone  # on the device; or --image shot.png
sigelo-agent device show-qr [--png <dir>]                     # the pending QR

# Offline:
sigelo-agent device add --name tab --offline [--full] [--words 5..8] [--paged] [--png <dir>]
sigelo-agent device scan --text - < frames.txt   # or --image …; any order, then the words
sigelo-agent device scan --finish                # once online

sigelo-agent device list [--json]
sigelo-agent device sync [--renew] [--identity <device file>]
sigelo-agent device revoke <name> [--lost]
sigelo-agent device seat [status | init --name <n> | give <name> | take [--force]]
```

**SAFE** (default): worker i of your keeper root (ENROL.md), its own DID, tier own, attested 14
days, renewed by the seat in the last week. It cannot sign as you; lost, it drops out at expiry.

**FULL** (`--full`, type `FULL`, terminal only): your identity and keeper root too. Lost, it
costs your words. Computers with disk encryption only.

**Online.** Both screens show four words; nothing goes before your `y` here. FULL material
follows end to end, once.

**Offline.** Material and a 7-day invite sealed under six words (argon2id), shown after the
frames; three tries. Never photograph both. Run `inbox --operator` before the device connects.

**Where it lands.** `sigelo.<name>.local.json` in the agents' directory; FULL also
`~/.config/sigelo/me.local.json` and its keeper. 0600, keys in the OS keychain if any. Without
`zbarimg`, PNG only; delete images after.

**The seat.** One device logs in as you: `seat init --name main` makes this machine it. Each
login as you (`ui`, `send`, MCP) first reads this machine's device inbox; elsewhere it
refuses `seat_elsewhere`. Any FULL device signs as you. `seat give`, `seat take` move it with a
snapshot of your state; `take --force` (seat lost): the newest snapshot here, every session
restarted. Standbys keep it sealed. The seat sends snapshots and renewals as it reads its inbox.

**The list.** `me.local.devices.json`, signed by you; only a newer one replaces it.

**The page** (`ui`): Devices view: SAFE add, scan (camera, image, paste), revoke, sync. FULL
and the seat: terminal. Remote control (`ui --remote`) never reaches devices.

**Revoke.** The device deletes its keys, answers, is forgotten. `--lost`: forgotten now; the
steps needing your words are printed.

Exit codes: 0 done, 1 refused (`seat_elsewhere`, `device_words`, `scan_format`, `busy`, `enrol_*`),
2 usage, 3 pending.
