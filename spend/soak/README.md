# Keeper soak (stagenet)

ROADMAP §6 step 10, items T6 (two or more weeks of scripted agents against a real keeper and
wallet: restarts, lock waits, approval races) and T14 (incident rehearsal). Stagenet only. The
coins are worthless, but everything else is real: the keeper, the wallet, the two-phase relay,
approvals, delegation and sweeps.

## What runs

| unit (systemd `--user`) | does |
|---|---|
| `monero-wallet-rpc-stagenet.service` | the allowance wallet on `127.0.0.1:38083` (`~/.local/monero/wallets`), `Restart=on-failure`: see "The wallet-rpc" below |
| `sigelo-soak-keeper.service` | `sigelo-spend serve policy.json --port 38200`, `Restart=always`; `SIGELO_DAEMONS` = the four stagenet nodes below, the wallet-rpc's own first (daemon fallback, spend/README.md) |
| `sigelo-soak-agent.timer` → `.service` | one agent tick at :00 and :30 (`Persistent=true`: a missed tick runs once at boot), skipped while the host clock is not NTP-synced (below) |
| `keeper/licence.json` (a file, not a unit) | the soak's "pro" licence: a sigelo attestation issued by a soak-local **test vendor** (`keys/vendor.*`, from `gen-keys.mjs licence`) to the keeper's DID, `{tier: "pro", seats: 4}`, 400 days; `setup.sh` puts the test vendor's DID in the keeper unit as `SIGELO_VENDOR_DID` (drop-in `sigelo-soak-keeper.service.d/licence.conf`, beside `SIGELO_DAEMONS`). Without it a keeper from 17e7787 on refuses the policy's delegates and approvals 403 `licence_required` |
| `sigelo-soak-check.timer` → `.service` | `check.mjs --notify` every hour at :15: UNHEALTHY → a line in `soak-alerts.log` and a `notify-send` notification (see "Healthy"). Not enabled by `setup.sh` |

**The paid tier, end to end.** The soak's policy delegates (`max_delegates: 2`) and approves
(`approval_above`), both paid verbs since 17e7787 (spend/README.md "Free and paid"). So the soak is
a pro customer of its own keeper, offline: `gen-keys.mjs` (bare, or `gen-keys.mjs licence`) mints a
TEST VENDOR identity in `keys/vendor.hex` / `vendor.json` (0600, never in the repo, named as a test
vendor in the file) and issues `keeper/licence.json` with it; the keeper trusts that vendor only
because the unit's `SIGELO_VENDOR_DID` says so. Every delegate and approval tick is then the paid
tier proved under a real keeper and wallet: licence load, verification and the gated verbs. A real
deployment never sets `SIGELO_VENDOR_DID`: it gets its licence from the vendor, whose DID ships in
`spend/licence.ts` at D1 (`sigelo-spend licence install`). Idempotent: an existing vendor key and
licence are kept (a licence that no longer verifies is refused, not overwritten); `--reissue` signs
a fresh licence under the same vendor (renewal, no unit change), `--rekey-vendor` replaces the
vendor too (then `sh setup.sh` and a keeper restart). It refuses without `keys/S.hex`, the root of
the keeper key the licence names. The soak on c2c9cdc predates the gate and needs none; the next
redeploy from HEAD gets one from `setup.sh`.

**The keeper's own DID** (INCIDENT.md §5). `gen-keys.mjs policy` writes, beside `spend.key`
(`keeperRoot(S, 0)`), `keeper/identity.json`: the keeper genesis, committing to the soak root's
recovery key `recoveryCommitment(S)` — the same one soak-root and the delegates carry — and never
to one derived from `spend.key`. So a soak keyed from `164b8c4` on can recover its keeper DID from
`keys/S.hex` alone: `sigelo-offline recover --genesis keeper/identity.json - --new-keeper 1 <
keys/S.hex > keeper.recovered.json`, then `sigelo-spend init --adopt keeper.recovered.json` on the
new keeper directory (`gen-keys.test.mjs` runs the recover line). The licence `gen-keys.mjs`
issues names that DID. The live soak is one of them since drill 2 (incident #6, 2026-10-02),
which ran the recover line on it offline and verified the result. A soak keyed before `164b8c4`
(a `spend.key`, no `identity.json`; the two burnt directories) keeps its legacy DID, whose recovery
derives from `spend.key` — abandoned, not recovered, after a compromise; `gen-keys.mjs policy`
and `check` say so, and never add an `identity.json` to it (that would change the DID its licence
names).

**Daemons.** The wallet-rpc unit starts on `node.monerodevs.org:38089`; the keeper's
`SIGELO_DAEMONS` lists it first, then `node2.monerodevs.org:38089`, `xmr-lux.boldsuck.org:38081`
(native IPv6) and `stagenet.xmr-tw.org:38081` (IPv4 only), all four
answering and in sync on 2026-09-29. After 3 "no connection to daemon" builds in a row, or 20 min
of a stuck wallet height while asked to pay, the keeper moves the wallet-rpc to the next one
(`set_daemon`, `trusted: false`) and says so in its journal (`daemon fallback: …`), at most once a
minute. It covers a node that is down; it cannot cover a host with no network (incident #4), where
every node fails alike and the keeper just keeps failing closed. A wallet-rpc restart goes back to
the unit's `--daemon-address`.

**Clock at boot.** The soak units are `--user` units, and the user manager has no
`time-sync.target` (`systemctl --user list-units --all '*time*'` shows none; the system manager's
is real: `systemd-timesyncd` + `systemd-time-wait-sync`, both enabled here). So
`After=time-sync.target` in these files would order nothing, and `user@.service` is not ordered
after it either: on 2026-09-26 the keeper started at "2026-01-11 11:33" (clock still at the
build epoch) and timesyncd synced at 14:58. What the units do instead:

- the agent `.service` has `ExecCondition=/usr/bin/timeout 10 /usr/lib/systemd/systemd-time-wait-sync`:
  it passes at once when timesyncd has synced this boot (`/run/systemd/timesync/synchronized`,
  tmpfs, so per boot) or the kernel says NTP-synced (chronyd); otherwise it is killed after 10 s
  and the tick is **skipped** (`condition failed`, not a failed unit). No tick runs on a January
  clock. The timer fires once NTP steps the clock (its January next-elapse is then in the past —
  the behaviour seen at every crash-boot), so the first tick after sync runs at once, on the right
  time. `Persistent=true` stays: a tick missed while the host was *off* still runs once.
- the keeper does not wait: its read-only routes and TRY LATER answers are useful at once, and
  on a clock set back it signs nothing (`clock_behind`, spend/README.md "The clock guard"; not in
  the live 6df3b67 `app/`).
- the check timer does not wait either: a clock set back is something it reports (a log `ts` in
  the future, no tick for an hour).

What this does not guarantee: a boot with no network never syncs, so no tick runs until the
network is back — the soak stops, visibly (the check goes UNHEALTHY "no tick for …" after an
hour and notifies), instead of ticking on a wrong clock. A host whose NTP server itself lies is
out of scope.

One tick of `agent.mjs`, as the root agent `soak-root` (account 0):

- every tick: `balance`; `pay bob 0.0002 "soak <n>"`; the identical command again → `ALREADY PAID`
- every 6 h: `pay carol 0.00042 "rent <k>"` → `WAITING FOR APPROVAL` → `approve-request`, sign
  with the approver key, `POST /approve` → the same pay → `PAID` (or `TRY LATER`: re-run on the
  next ticks while the approval lives, 2 h; given up and counted after 3 h)
- once a UTC day: `delegate d<YYYYMMDD> 0.00035`; on later ticks the delegate pays bob 0.0002
  (TRY LATER until its funding unlocks); then `revoke`, whose first run also checks the
  delegate's token is dead, re-run every tick until every sweep line says `empty`

Root spends are spaced 62 s apart (rate 2/min). Every command lands in `soak.log` as one NDJSON
line: `ts, tick, who, cmd, exit, got` (`status/code` from `--json`), `expect`, `verdict`
(`ok`, `tolerated` = a TRY LATER, `outage`, `MISMATCH`), `ms`, `out` (the printed line, tokens
redacted). Per tick also a `wallet` line (height, account 0 and all-account balances; the
snapshot waits 90 s per wallet-rpc call, since wallet-rpc blocks its RPC for its 30 s
refresh-retry while it has no daemon). Counters and the last 20 mismatches: `soak-stats.json`.
An exception is an `error` line; the tick goes on.

**Outage ticks** (incident #4). A tick is an outage tick when the wallet height did not advance
since the previous tick's snapshot (~15 stagenet blocks arrive in 30 min) or the keeper answered
`wallet_offline`. In it, a TRY LATER where the script expected success (`balance`, carol's first
ask) is the keeper failing closed and gets verdict `outage`, not `MISMATCH`; the tick gets a
`{kind: "outage", reasons, excused}` line and counts in `outage_ticks`. Anything else unexpected
is still a MISMATCH. A carol rent given up after 3 h in which every pay attempt was an outage
TRY LATER is `abandoned_offline` (tolerated, counted in `abandoned_offline`), not a mismatch;
one with any other attempt stays `abandoned`, a MISMATCH.

**Policy** (`policy.template.json`, read, never written, by `gen-keys.mjs policy`): `per_tx_max` 0.0005,
`per_period_max` **0.02**/day, rate 2/min, `approval_above` 0.0004, one approver,
`max_delegates` 2, `max_approval_ttl` 7200, allow `bob` = wallet (0,1), `carol` = (0,2). The
template names those two, the approver, soak-root's DID and genesis and the recovery commitment
only as placeholders: `gen-keys.mjs policy` (run by `setup.sh`) fills the identities from `keys/`,
asks the wallet-rpc for the addresses, and writes the result into the soak directory's
`policy.json`, never into the repository (`node spend/soak/gen-keys.test.mjs` checks the
template's sha256 is unchanged after a full keying in a scratch directory).
Two numbers differ from the brief, on purpose:

- `per_period_max` 0.02, not 0.005: 48 × (0.0002 + 0.000044 fee) is 0.0117 a day before carol,
  so at 0.005 more than half the ticks would be refused by the cap, and carol (0.00049 with
  fee) would almost never get past the cap to ask for approval. 0.02 leaves ~30 % headroom.
- the delegate is funded **0.00035**, not 0.001: funding is a spend of the root, and 0.001 is
  over its `per_tx_max` (refused) and its `approval_above`.

**Margin to watch:** carol costs 0.00042 + fee against `per_tx_max` 0.0005 and must stay
above `approval_above` 0.0004. It was 0.00045 until 2026-09-24: a 2-input transaction cost
0.0000439, leaving 0.000006, and once the wallet held only small change every carol spend
needed more inputs (fee 0.0000574, measured) and was `REFUSED … per-payment limit` on 8
ticks straight, so rent 2 was abandoned. 0.00042 leaves 0.000022: a fee up to ~0.00008
(4–5 inputs) still passes. A refusal here is the cap doing its job on the real outflow
(amount + fee), not a keeper defect; the soak just has to ask for less.

## Files

`~/.local/share/sigelo-soak/` (0700; `SIGELO_SOAK_DIR` overrides it everywhere; `SIGELO_SOAK_PORT`
the keeper port, 38200, and `SIGELO_SOAK_WALLET_RPC` the wallet-rpc URL,
`http://127.0.0.1:38083/json_rpc`, for `agent.mjs` and `check.mjs`):

```
app/            frozen copy of ts/dist, spend/dist, these scripts (REVISION = the commit)
keeper/         policy.json, spend.key (= keeperRoot(S, 0)), spend.log, spend.lock
keeper/         licence.json (the test vendor's pro licence to the keeper DID)
keys/           S.hex (throwaway root), approver.hex, approver.json, vendor.hex, vendor.json (the soak's
                TEST vendor) — never in the repo
root.token      soak-root's bearer token
env.sh          `. env.sh` → sigelo-wallet / sigelo-spend on PATH, acting as soak-root
state.json      the agent's state, including the live delegate's token
soak.log  soak-stats.json
soak-alerts.log check.mjs --notify: one line per UNHEALTHY run, one on recovery
```

## Start, stop, inspect

```sh
cd spend/soak
systemctl --user enable --now monero-wallet-rpc-stagenet.service  # first: setup.sh asks it
node gen-keys.mjs            # once: keys/ in the soak dir (the repo is not touched)
sh setup.sh                  # copy code, policy.json (+ the wallet's subaddresses), spend.key, token, units; idempotent
systemctl --user enable --now sigelo-soak-keeper.service sigelo-soak-agent.timer
systemctl --user enable --now sigelo-soak-check.timer           # optional: hourly check --notify

node ~/.local/share/sigelo-soak/app/spend/soak/check.mjs        # summary; exit 1 if unhealthy
systemctl --user start sigelo-soak-agent.service                # one tick now (blocks ~1-4 min)
tail -f ~/.local/share/sigelo-soak/soak.log
journalctl --user -u sigelo-soak-keeper -u sigelo-soak-agent -f
systemctl --user list-timers sigelo-soak-agent.timer

systemctl --user stop sigelo-soak-agent.timer                   # pause the agents
systemctl --user stop sigelo-soak-keeper.service                # clean stop: removes spend.lock
```

Updating the code under a running soak: rebuild, `sh setup.sh` (keeps keys, policy, log,
token), `systemctl --user restart sigelo-soak-keeper`. A restart mid-soak is part of the test.
Never re-run `token new` by hand without rewriting `root.token`: the agent would be locked out.

A newer verifier can reject identities an older one issued — the SPEC §2 nonce form, enforced
since the hostile-JSON differential, rejects the genesis of any soak keyed before it (`gen-keys.mjs`
passed hex strings as nonces, and the library stored them verbatim). `setup.sh` therefore runs
`gen-keys.mjs compat` first and refuses to redeploy over a live soak this code would not accept:
a keeper restarted on such code would refuse its own policy. The way out is a **new** soak
directory (`SIGELO_SOAK_DIR=<new> node gen-keys.mjs && sh setup.sh`) with its own keys, DIDs and
day-0, or keeping the deployed revision (`app/REVISION`) until the rehearsal is done. `gen-keys.mjs`
also refuses to overwrite a `keys/approver.json` whose DID it would not derive now.

## Healthy

**Day 0** is `started` in `soak-stats.json`, written by the agent's first tick in that soak
directory; `check.mjs` prints it as `uptime … since <started>`, and the "once the soak is 2 h old"
rule below counts from it. The soak keyed 2026-09-23 (day 0 19:48:36Z) ended in the T14
rehearsal (incident #5) and is evidence now; so is its successor (c2c9cdc/9516622, day 0
2026-10-01 14:00:16Z), ended by drill 2 (incident #6). The current soak is a new directory on
REVISION 7ba0c4e (code = c929667), keeper live 2026-10-02 18:46:08Z, `started` at its first tick
(`soak-stats.json`); the 14 days of T6 count from there.

`check.mjs` prints `HEALTHY` when the keeper and the timer are active, a tick ran in the last
hour, no command was UNCERTAIN, every `spend.log` line verifies under the keeper key (derived
from `spend.key`, cross-checked against `/health`), the wallet-rpc answers, and (since incident
#4, where it said HEALTHY through 32 h with no network):

- a `pay` or `fund` went through (`done/ok`) in the last 2 h (once the soak is 2 h old);
- the wallet height moved between the last two `wallet` snapshots;
- the licence (keeper/licence.json, read for its `exp`, not verified) has more than 30 days left;
  none is needed when the deployed code predates the gate (no `app/spend/dist/licence.js`), and
  `node app/spend/soak/gen-keys.mjs check` verifies it under the keeper and test-vendor DIDs and
  prints the tier (by hand: `. env.sh && sigelo-spend licence show --dir keeper`);
- the clock is sane in both logs: the newest `soak.log` and `spend.log` `ts` is not more than
  300 s in the future of this host's clock, and not older than the line before it.

Otherwise it prints `UNHEALTHY: <reason>; …` and exits 1. `--evidence` checks a directory that
is no longer the live soak (the rehearsal's burnt copy): it skips the units, `/health`, the
wallet-rpc and the three liveness rules (last tick, last payment, height), and keeps the
line-by-line verification and the clock checks.

**`--notify`** (and `sigelo-soak-check.timer`, hourly at :15): the host noticing, which in
incident #4 nobody did for 32 h. On UNHEALTHY it appends `<ts> UNHEALTHY: <reasons> (notify-send
ok|not installed|failed (…))` to `soak-alerts.log` and runs `notify-send --urgency=critical
"sigelo soak UNHEALTHY" "<reasons>"` when `notify-send` is on PATH (it is here; a user unit reaches
the session bus through the user manager's imported `DBUS_SESSION_BUS_ADDRESS`, and a
critical notification stays until dismissed). Each UNHEALTHY run alerts again — hourly while it
lasts. The first HEALTHY run after an UNHEALTHY line logs `HEALTHY again` and sends one normal
notification; HEALTHY with nothing to clear writes nothing, so the check stays read-only on a
healthy soak. A crash of `check.mjs` itself (a missing `spend.key`, say) is reported as UNHEALTHY
`check.mjs crashed: …`. The unit also exits 1 while UNHEALTHY (`systemctl --user --failed`).
`setup.sh` copies the units but, as with the others, enables nothing; the live `app/` (6df3b67)
predates `--notify`, so the timer is worth enabling only after a redeploy. Tested 2026-09-29 on a
copy of the soak cut at 10:31Z (inside the incident): UNHEALTHY (no tick for 1 h 57 m, no payment
for 1 d 10 h, height stuck at 2217326), notify-send exit 0, one alerts line; the live soak the same
minute: HEALTHY, nothing written.

Beyond that:

- **mismatches ~0.** Each one is a finding: read it (`last_mismatches`), explain it, and either
  fix the code or the expectation. Tolerated TRY LATERs are normal: locked change after a
  spend, a delegate's funding still unlocking, a sweep skipped as `locked`.
- **TRY LATERs from a host outage are an outage, not mismatches.** No network means the wallet
  cannot build (`wallet_offline`, or a height that stops moving) and the keeper fails closed:
  nothing is sent, and that is correct. The agent logs those as `outage` / `abandoned_offline`;
  what makes it UNHEALTHY is the liveness rules above (no payment in 2 h, stuck height), which
  point at the host, not the keeper. Incident #4.
- **ticks ≈ 48/day**, **payments ≈ 48 bob + 4 carol + 2 delegate (fund, pay)** a day,
  `already_paid` ≈ payments, approvals 4/day, one delegate created and closed per day.
- **the wallet only loses fees.** bob and carol are the wallet's own subaddresses, delegates are
  its own accounts and are swept back, so the all-account total falls by the fees alone
  (`check.mjs`: "drop vs fees logged" stays 0).

**Expected fee cost.** ~55 transactions a day (48 bob, 4 carol, 1 funding, 1 delegate pay,
1 sweep) at 0.00003042 (1 input) to 0.00004394 XMR (2 inputs; 2 outputs, priority 1, both
measured 2026-09-23) ≈ **0.0017–0.0024 XMR/day, ≈ 0.023–0.034 XMR over 14 days**, out of 0.0998
in the wallet. The account count grows by
one a day (delegates' accounts are never reused), well under the wallet's 50-account restore
lookahead for a 14-day run.

## The wallet-rpc

The wallet-rpc runs under `monero-wallet-rpc-stagenet.service` (`Restart=on-failure`; the
hand-started `nohup` process of the first days is gone since the first reboot). The keeper orders
`After=` it but does not pull it in. Stop it only through systemd — `systemctl --user stop` for a
moment, `freeze.sh` to keep it down (an incident or the rehearsal: `stop` plus a drop-in
`Restart=no`, `disable`) — never with `pkill`, which leaves the unit to decide what happens next.
Not `mask`: `setup.sh` installs the unit files in `~/.config/systemd/user`, which the user manager
ranks above `/run/user/<uid>/systemd/user`, so `mask --runtime` (a `/dev/null` link there) is
shadowed and changes nothing (`is-enabled` stays `enabled`); and a persistent `mask` would have to
put that link where the unit file already is, which systemctl refuses (`Failed to mask unit: File
… already exists`). A drop-in in `~/.config/systemd/user/<unit>.d/` applies wherever the unit file
lives. Both measured on a scratch unit, incident #5. A clean stop
saves the wallet file; a crash does not, and the keeper now calls `store` after every transfer
(spend/README.md, "Two phases"), because before that the file was 12 days stale (incident #4).

## Host reboot

User units start at boot only with lingering on (`loginctl show-user user -p Linger` → `yes`;
already on here, otherwise `doas loginctl enable-linger user`). After a reboot: wallet-rpc and
keeper start by themselves. The keeper may start before the wallet has synced; it answers TRY
LATER until then. A `kill -9`/power loss/reboot leaves `spend.lock` behind; the next start takes
it over (dead pid, reused pid or earlier boot — see Incidents #1). A write cut off by the
power loss leaves a torn last line in `spend.log`; the keeper moves it to
`keeper/spend.log.torn-<ts>` with one warning and starts (spend/README.md, "Torn last line";
sim/REPORT.md K1) — `check.mjs` lists any such file. The timer runs the missed tick once (`Persistent=true`), as
soon as the clock is NTP-synced ("Clock at boot" above). Then run `check.mjs`:
a crash between `intent` and `relayed` shows as UNCERTAIN and is a finding for the soak.

## Incidents

**#1 — 2026-09-24: keeper locked out after a reboot (54 min down).** *Symptom*: the test host
rebooted at 04:10 UTC; the wallet-rpc unit came up, `sigelo-soak-keeper.service`
(`Restart=always`) failed in a loop for 54 minutes with `spend.lock: …/keeper/spend.lock is held
by pid 1103: another keeper serves this policy directory …`; `check.mjs` reported UNHEALTHY.
*Cause*: `spend.lock` held only the pid (1103) of the keeper from before the reboot, and after
the reboot pid 1103 was `/usr/lib/bluetooth/bluetoothd`. The lock treated any live pid as a live
keeper, so any reboot or crash followed by pid reuse left the keeper down until a human removed
the lock — on a crash-prone host this defeats `Restart=always`. *Fix*: by hand at 05:05 UTC
(`rm` the lock, restart the unit). *Prevention*: `spend.lock` now also records the boot_id and
the process starttime, and a lock from an earlier boot, with a dead pid or with a pid whose
starttime differs is taken over with one warning (`sigelo-spend: took over a stale <path>:
<why>`); two live keepers are still refused (spend/README.md, "One keeper per policy
directory"). The live soak runs the frozen copy in `app/`: it has this fix only after a
redeploy of `app/` from the commit that carries it — done 2026-09-24 05:12 UTC (`app/REVISION`
44c614e; the keeper's lock is the two-line form since). A reboot now needs no hand at all.
*Verified*: the test host rebooted again 2026-09-24 06:19 UTC (unattended). The keeper started
at 06:19:06 with `took over a stale …/spend.lock: pid 16057 is from an earlier boot`, 0 restarts,
no hand. wallet-rpc needed 18 min to rescan before it answered (the keeper reported TRY LATER
until 06:37); `check.mjs` HEALTHY after that. Fees over the first 10.8 h: 0.00086568 XMR, drop
vs fees logged 0.

**#3 (near miss) — 2026-09-24: a redeploy that would have locked the keeper out.** `sh setup.sh`
from the commit with the nonce-form rule overwrote `app/` (the keeper kept running the old code from
memory) and then crashed in `gen-keys.mjs`, because this soak's identities carry hex-string nonces.
Had the host rebooted then — it did three times that day — the keeper would have started on code
that rejects its own policy. `app/` was rolled back to the running revision within minutes
(`check.mjs` HEALTHY, REVISION 6df3b67); the compat guard above now aborts before any file is copied.
The live soak keeps 6df3b67 until the day-7 rehearsal; the next soak is keyed by the fixed generator.

**#4 — 2026-09-28 02:54Z → 09-29 11:03Z: host offline 32 h 09 min; the keeper failed closed,
the tooling did not notice.** *Symptom*: from tick 154 every pay and fund was TRY LATER, the
wallet height froze at 2217326, 0 successful payments on 09-29 before 11:30Z; `check.mjs` said
HEALTHY throughout. *Cause*: the host, not sigelo. At 02:54:43Z the test host lost its network for 32 h because
its network manager stopped auto-connecting after a failed handshake and nothing could
re-authorise it unattended: 0 connection attempts for 32 h. The Owner re-authorised it at
11:03:14Z, it connected in 4 s, and wallet-rpc resynced on its own (2217326 → 2218206 by
11:08Z); tick 219 at 11:30Z paid and funded. *What held*: nothing was sent while offline (spend.log
has no intent for the stuck ticks), 379/379 lines verify, intent = relayed, 0 UNCERTAIN, drop vs
fees 0; no restart was needed or done. *What did not*: `check.mjs` HEALTHY for 32 h (no payment or
height rule); the agent counted the keeper's correct TRY LATERs as 6 mismatches (`balance` at
tick 153, carol rents 15–19 given up after 3 h each) and 17 snapshot timeouts (its 30 s fetch vs
wallet-rpc's 30 s refresh-retry window); the agent could not tell "no network" from a wallet fault
(`try_later/wallet`, 110 on 09-28 and 82 on 09-29); and the wallet file had not been stored since
09-17 (every stop a crash, so an 18-min rescan at each boot). *Prevention* (repo, not the live
`app/`, which stays at 6df3b67): the keeper answers `wallet_offline` for "no connection to daemon"
and stores the wallet after every transfer; `agent.mjs` waits 90 s for a snapshot and logs outage
ticks as `outage`/`abandoned_offline`; `check.mjs` goes UNHEALTHY without a payment in 2 h, on a
stuck height or on a log clock in the future or stepping back. The host fix — a network connection that re-establishes itself
unattended — is the Owner's call. Rent 13–14 and 20 refused `per_tx_max` are the carol margin problem above
(the live `app/` still pays 0.00045), not this outage. *Closed by* (repo, 2026-09-29): the host now
notices — `check.mjs --notify` under `sigelo-soak-check.timer` logs to `soak-alerts.log` and raises
a critical `notify-send` notification within the hour of UNHEALTHY (with the rules above, by the 04:15Z 09-28 run
here, instead of 32 h later by chance); the keeper no longer depends on one node (`SIGELO_DAEMONS`
fallback — would not have helped this outage, which had no network at all, but closes the "their
node is down" case); and no tick runs on an unsynced clock (the agent unit's `ExecCondition`).
Still open, the Owner's: the host's network itself, and redeploying `app/` so the live soak runs any of it.

**Wrong-clock risk (found in #4, not triggered).** At every crash-boot the host's clock reads the
system's build epoch (2026-01-10/11) for 20–45 s until NTP; no tick ran in that window (the
timer suppresses catch-up while the clock is in the past, and fires once NTP steps it). A boot
*without* network would keep January for hours, and every January :00/:30 would run a tick: the
keeper would sign lines, approvals and a delegate `d20260111` with January timestamps that fall
out of the daily-cap window once the clock is corrected, and leave `spend.log` non-monotonic for
good. *Guard* (repo): the keeper refuses `clock_behind` (TRY LATER, nothing signed or sent) when
its clock is before its build floor or more than 300 s behind the newest line it signed
(spend/README.md, "The clock guard"); `check.mjs` flags a log clock that steps back. The live
6df3b67 keeper has neither: until the redeploy, a boot without network is a reason to stop the
agent timer by hand. The agent unit in the repo now also skips every tick until the clock is
NTP-synced ("Clock at boot"), so on a redeployed soak a January tick cannot run at all — the
keeper's guard covers anything else that asks it to sign.

**#2 (pre-empted) — torn last `spend.log` line after a kill** (sim K1, fixed 6df3b67: moved to
`spend.log.torn-<ts>`, one warning, keeper starts). `app/` redeployed at 6df3b67 2026-09-24 08:07
UTC (keeper restart, HEALTHY). `check.mjs` lists any `.torn-*` files.

**#5 — 2026-10-01: the T14 incident rehearsal (a drill of INCIDENT.md case (b)).** Steps 1–7
below, walked at repo c2c9cdc on day 8 of the 09-23 soak (live `app/` 6df3b67). *Durations*
(UTC): detect 13:19:53 → keeper really dead 13:20:44 (51 s, 23 s of them a keeper systemd
restarted, F1) → freeze complete 13:21:34 → **last sweep 13:35:19 (detect → last sweep
15 min 26 s)** → vault spendable 13:54:45 (10 confirmations) → new keeper live 13:56:27 (36 min
34 s) → first payment on it 14:30:32 (1 h 10 min 39 s). *Funds*: the burnt wallet's 0.09190088
went to the vault in 3 sweeps (0.07612634; fees 0.01573816; 0.00003638 dust left behind) and
back to the allowance address in 1 (0.07606886, fee 0.00005748). *What held*: the old
`spend.log` verifies 592/592 under the old keeper key (`check.mjs --evidence`), intent = relayed
236, 0 UNCERTAIN; the evidence hashes check; the restarted keeper served no request (`spend.log`
byte-identical to the evidence copy); the agent tick on the frozen keeper logged TRY LATER
`unreachable` and did not crash. *Findings*, each with what closed it:

| | finding | closed by |
|---|---|---|
| F1 | **The freeze failed.** `mask --runtime` writes to `/run/user/<uid>/systemd/user`, which ranks below `~/.config/systemd/user` where `setup.sh` installs the units: shadowed, `is-enabled` stayed `enabled`. `kill -9` → `Restart=always` revived the keeper on the burnt directory at +10 s; it took over and rewrote `spend.lock`, and the clean stop that ended it deleted the lock (the original survives only in the evidence copy). | `freeze.sh` (step 2): drop-ins `Restart=no`, `disable`, daemon-reload, checked before the kill; asserts dead, not restarting, lock kept. Scratch `Restart=always` unit: old way restarted at +10 s (lock rewritten); `freeze.sh` → `failed` for 15 s, lock unchanged; persistent `mask` refused. INCIDENT §2 rewritten. |
| F2 | The vault's wallet-rpc scans from its offline-estimated height (~20 000 blocks, ~30 min here) **before** it binds its RPC port, so `refresh {start_height}` could not be sent. | Steps 0 and 4.1: start it with `--no-initial-sync`, then `refresh {start_height}` (1 798 blocks in 4 min 11 s). |
| F3 | A plain `unmask` leaves a `--runtime` mask (`unmask --runtime` needed). | Moot: `freeze.sh` uses no mask. One-line note in step 4.2. |
| F4 | A bare `gen-keys.mjs` rewrote the tracked `policy.template.json` with the new soak's DIDs and recovery commitment (the addresses were placeholders since 5e96d29): dirty tree, and an export would name the live soak's identities. | The template holds placeholders for every identity field and is never written; `policy` fills `<dir>/policy.json`. `gen-keys.test.mjs`: template sha256 unchanged after a full keying in a scratch dir. |
| F5 | No live delegate token at freeze time: the agent revokes each day's delegate ~1 h after creating it (~00:02Z). | Step 2.5: revoke-all is tested with the root token, and with a delegate's only if one is live; "none live" is a valid outcome. |
| F6 | Steps 5–6 said "No CLI does it yet": stale, `sigelo-offline recover` does an agent's recovery rotation. But the soak's `keys/S.hex` was 32 random bytes, not a canonical root, and `recover` refuses it. | Steps 5–6 rewritten as the command per identity; `gen-keys.mjs` now keys canonical roots (the test runs `recover` on one). **Open:** the keeper's own DID has no rotation at all: its genesis's recovery key is `recoveryPublicKey(K)`, derived from `spend.key`, so the thief holds it too. It can only be abandoned and the new one announced, and no SPEC object or command does that (step 5–6, INCIDENT §5). Open too: the current soak's root (keyed before the fix) is still not canonical. |
| F7 | **The sweep's cost.** `sweep_all` at priority 4 took one tx and left 182 small outputs; priority 4 and 3 then failed with error -4 `No unlocked balance` (wallet2 skips an output worth less than its own fee at that priority); priority 2 took them in 2 txs; 0.00003638 dust could not be swept at all. Fees: 0.0158 XMR = **17 %** of the wallet. The sweep-back then lands as **one** output, so every payment on the new keeper locks the whole balance ~20 min: carol rent 1 and the delegate funding keep getting `wallet_locked` behind bob, and rent 1 may be `abandoned`, a MISMATCH that is the drill's doing. | Documented in steps 3.3 and 4.1 and INCIDENT §3: step the priority down on error -4, stop at dust, and either consolidate before a drill or accept the fees. Suggested for step 4.1 (not tried): split the sweep-back with `transfer_split` to several destinations, all the allowance address. |

Smaller ones: wallet-rpc answers nothing while `refresh` runs, so its progress cannot be polled
(the call returns when synced); `check.mjs --evidence` prints a non-zero "drop vs fees" because
the last snapshot came before the last relay's fee; busybox `timeout` in the agent's
`ExecCondition` leaves a helper in the cgroup for a moment (systemd logs it and ignores it);
the old step 4.4 forgot the wallet-rpc unit and the check timer. And the drill did not do the
real §4: `gen-keys.mjs` made a new random S, not `K_1` of the old one, so the new soak-root is
not what a recovery rotation of the old one would point at. *After it*: the new soak (day 0
14:00:16Z, "Healthy") kept running through a host network outage later that afternoon. The
keeper (pid since 13:56:27Z) did not restart and logged no daemon fallback; tick 3 at 15:00Z
paid bob; `check.mjs` HEALTHY at 15:09Z.

**Finding (not an incident) — 2026-10-01 tick 5: timeout race on a slow build.** Keeper pid
2181361 (`app/` 9516622); times UTC from `soak.log`, `rpc.log` and `spend.log` (the keeper's
journal has no line in the tick):

- 16:01:20.0 carol's `rent 1` build refused `not_enough_unlocked_money` (bob's spend, F7).
- 16:01:20.1 delegate d20261001 runs `pay bob 0.0002 "from d20261001"`; 16:01:20.33 wallet-rpc
  logs `Requested ring size 1 too low, using 16`: the `transfer` build (`do_not_relay: true`,
  account 10's single 0.00035 output) has started.
- 16:02:20.5 the keeper's wallet wait runs out — then 60 s for every call (`walletRpc` default,
  `serve` passed no `walletTimeoutMs`) — and it answers `502 wallet`; the agent prints `TRY
  LATER: the wallet could not do that right now` (ms 60 383).
- 16:03:52.2–.4 wallet-rpc finishes the decoy selection for that output (152 s build; bob's at
  16:00 took 11 s, the same delegate's at 16:32 took 9 s) and answers a closed socket.
- Nothing was relayed: no `intent` line, no `relay_tx` (the keeper never had the metadata), no
  `Spent money` for that output until 16:33:04 — tick 6's 47c5b366, whose build picked **the
  same real output and ring indexes**, so the late build had left nothing pending. Tick 6 paid
  once (intent + relayed).

Fail closed held: phase (a) is `do_not_relay`, an abandoned build is discarded by wallet-rpc,
and the intent line is written before `relay_tx`, so no timeout can make a relay with no line or
two relays of one payment (MONERO.md §4.1 "Timeouts"). The cost was a wasted tick and a wrong
word. *Fix* (spend/, takes effect at the next redeploy of `app/`): builds wait 180 s
(`BUILD_TIMEOUT_MS`; other calls keep 60 s), and a build past its wait is `wallet_slow`, `TRY
LATER: the wallet is still working on that payment (a slow network); nothing was sent. Run the
same command in a few minutes.` The agent's `try_later/*` tolerance covers it unchanged.

**#6 — 2026-10-02: drill 2, a keeper rekey with `freeze.sh` (its first real use).** Soak 9516622
(day 0 10-01 14:00:16Z, 57 ticks), repo c929667; the wallet-rpc was kept up and reused (step 2.4).
*Durations* (UTC): detect 18:22:04 → **frozen 18:22:10 (6 s**; drill 1: 1 min 41 s) → last sweep
18:24:04 (2 min 00 s; no clean-host refresh here) → vault spendable 18:43:54 → new keeper live
18:46:08 (24 min 04 s) → first payment 19:31:36 (tick 2, 1 h 09 min 32 s). *freeze.sh*: every
assertion held: keeper failed, NRestarts 0, `spend.lock` kept and byte-identical, nothing restarted
by tick 58 (18:30Z, TRY LATER `unreachable`, no crash, `balance` still counted a MISMATCH).
*Funds*: 0.0736367 → vault in one priority-2 sweep (0.07195224, fee 0.00163608 = 2.2 %, 0.00004838
dust left) → back in one `transfer_split` to 8 outputs (0.07182776, fee 0.00011316); tick 2 paid
bob, carol rent 1 and the delegate funding in the same tick (drill 1: one output, rent 1 abandoned).
*Recovery*: the new keeper (keyed at HEAD, `identity.json`, pro) recovered offline from `keys/S.hex`
with `recover --new-keeper 1`; the Go verifier accepted the bundle, the stolen `spend.key` is refused.
*Findings*: a leftover `serve --dry-run` from an earlier test, on a copy of the policy, still took the
root token after the freeze (killed; step 2.5 now checks); `freeze.sh` cannot spare the wallet-rpc.

## Incident rehearsal (T14) — ran 2026-10-01; next drill: quarterly

Walks INCIDENT.md (repo root) case (b) end to end on this soak. It ends this keeper directory for good.
Write down the wall-clock time at every step; the timeline is the product. The first run and what
it found: incident #5. The steps below carry its fixes.
The rehearsal generalised to any installation, with this run's findings folded in, is the recovery
kit's drill (`kit/procedure/DRILL.md`, timeline template and grader in `kit/drill/`).

**0. Before (the day before).** Stand in for the Owner's backup: from the wallet-rpc, record
`query_key {key_type: "view_key"}`, `query_key {key_type: "spend_key"}`, `get_address
{account_index: 0}` and a restore height (the lowest `height` in `get_transfers {in: true,
all_accounts: true}`, minus 100) into `~/drill/allowance-keys.json` (0600). Create the **vault**:
a fresh stagenet wallet in `~/drill/vault/` (0700) that no keeper ever loads, offline and
non-interactive (10 s):

```sh
monero-wallet-cli --stagenet --offline --generate-new-wallet ~/drill/vault/vault \
  --password-file ~/drill/vault/.pw --mnemonic-language English --command address \
  > ~/drill/vault/seed-and-create-output.txt   # 0600: the SEED and view key print to stdout
```

The 25-word seed goes to the terminal unless redirected, so redirect it into a 0600 file. Record
the vault address and the tip height now. Its refresh height is estimated offline, ~20 000 blocks
below the tip (2198252 against a tip of 2218207 in incident #5). A wallet-rpc opened on it scans
all of that **before it binds its RPC port** (~30 min here), so in step 4.1 it is started with
`--no-initial-sync` and then told `refresh {start_height: <tip at step 0>}`. Write that command into
the vault's README. Optional, to save the fees of step 3.3: consolidate the allowance wallet's
small outputs a few days ahead (`sweep_all` to its own address at priority 1).
Run `check.mjs` and keep the output.

**1. Detect.** Drill trigger, no real signal. Note the time.

**2. Freeze** (minutes count; time it). `sh ~/.local/share/sigelo-soak/app/spend/soak/freeze.sh`
alone is a dry run: it prints the units, the pid in `spend.lock` and what it will do. Then
`SIGELO_FREEZE_EVIDENCE=~/drill/evidence sh …/freeze.sh --now` (from the repo if `app/` predates
it). Paste its output into the timeline: every step prints its UTC time.

1. Evidence first, keeper still running: `spend.log`, `spend.lock`, `policy.json` copied to the
   evidence directory with `SHA256SUMS`. A clean stop would delete `spend.lock`.
2. **Stop systemd from undoing the kill.** For the keeper and the wallet-rpc units, a drop-in
   `~/.config/systemd/user/<unit>.d/freeze.conf` with `[Service]` `Restart=no`, `disable` (a
   reboot mid-drill must not start either on the burnt directory), `daemon-reload`, and a check
   that systemd now reports `Restart=no`, all before anything is killed. Not `mask`: why it cannot
   work here is in "The wallet-rpc". Leave the agent timer running: watching the agents fail is
   the better test.
3. `kill -9` the pid in `spend.lock`; asserted within 5 s: the unit `inactive`/`failed`, not
   `auto-restart`, no queued job, `spend.lock` still there. If an assertion fails, `freeze.sh`
   stops and names the fallback (`systemctl --user stop`, which deletes the lock; the evidence
   copy has it).
4. The wallet-rpc: `systemctl --user stop` (a clean stop saves the wallet file), asserted down.
   A drill that reuses the wallet and sweeps from it in place keeps it up. `freeze.sh` has no
   switch for that; drill 2 set `SIGELO_FREEZE_WALLET_UNIT` to a unit that does not exist
   (`show` says `Restart=no`, `inactive`, so the checks pass and the stop is skipped).
5. **Revoke-all by killing:** `. env.sh; sigelo-wallet balance` → `TRY LATER: the wallet service
   is not answering.` Then the live delegate's token from `state.json` `delegate`, **if one is
   live**: the agent creates the day's delegate at ~00:02Z and revokes it about an hour later, so
   outside that hour there is none. Record "none live": that is a valid outcome, and the root
   proof shows the same thing (no process accepts any token). The next agent tick must log TRY
   LATERs, not crash; it still counts the unreachable `balance` as a MISMATCH (6df3b67 and 9516622
   alike: an unreachable keeper with a moving height is not an outage tick). Nothing else should
   accept the tokens: check it, `pgrep -af 'cli.js serve'` must show nothing. Drill 2 found a
   leftover `serve --dry-run` on a copy of the policy that took the root token; `freeze.sh` kills
   only the pid in `spend.lock`. That is the whole of revoke-all today (INCIDENT §2).

**3. Sweep to the vault** (the "clean host": a separate wallet dir on tmpfs, another port):

1. `mkdir -m 700 /tmp/drill-clean` (tmpfs); `monero-wallet-rpc --stagenet --wallet-dir
   /tmp/drill-clean --daemon-address node.monerodevs.org:38089 --rpc-bind-ip 127.0.0.1
   --rpc-bind-port 38084 --disable-rpc-login --log-file /tmp/drill-clean/rpc.log` (without
   `--log-file` the log lands in the cwd).
2. `generate_from_keys {filename: "burnt", address, spendkey, viewkey, restore_height}` from
   `allowance-keys.json`; `refresh`. It is one blocking call (~7 min for 4 927 blocks), and the
   wallet-rpc answers nothing else until it returns, so do not poll. The soak used < 50 accounts,
   inside the default lookahead; check `get_accounts` shows every account index in `spend.log`'s
   `delegate` lines.
3. For every account with `unlocked_balance` > 0: `sweep_all {address: <vault>, account_index: i,
   subaddr_indices_all: true, priority: 4, unlock_time: 0}`. On error -4 `No unlocked balance`
   while `get_balance` still shows unlocked funds, the rest are outputs worth less than their fee
   at that priority: repeat at 3, then 2, then 1. Stop when only dust is left (refused at 1) and
   record it. Locked outputs: repeat every block until every account is empty. Record every txid.
   On a wallet of many small outputs this is expensive: 17 % of the wallet in incident #5
   (0.0158 of 0.0919 XMR). Consolidate before a drill (step 0) or accept it; in a real
   compromise, accept it, since speed is what wins the race.
4. Close that wallet-rpc and `rm -rf /tmp/drill-clean`.

**4. New keeper identity.** Keep the old directory as evidence: `systemctl --user stop
sigelo-soak-agent.timer; mv ~/.local/share/sigelo-soak ~/drill/sigelo-soak.burnt`. INCIDENT §4:
a real replacement needs a new wallet, which no CLI offers (the gap is the finding). For the
drill, reuse the stagenet wallet, in this order:

1. Sweep the vault back to the **allowance wallet's address** (`address` in
   `~/drill/allowance-keys.json`, not the vault's own) once the step-3 sweeps into the vault have
   10 confirmations (~20 min; before that they are locked). Open the vault in a wallet-rpc on a
   spare port, without the initial scan (`monero-wallet-rpc --stagenet --wallet-file
   ~/drill/vault/vault --password-file ~/drill/vault/.pw --daemon-address node.monerodevs.org:38089
   --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38086 --disable-rpc-login --no-initial-sync --log-file
   ~/drill/vault/rpc.log`; not 38085, which the spend suite's interop test binds), then `refresh
   {start_height: <tip at step 0>}`, `sweep_all {address: <allowance address>}`, record the txid,
   stop it. A `sweep_all` lands as **one** output: until change multiplies, each payment on the new
   keeper then locks the whole balance for 10 blocks (~20 min), bob goes first every tick, and
   carol's first rent may be `abandoned` (a MISMATCH that is the drill's doing). Instead (drill 2):
   `transfer_split` with 8 destinations that are all the allowance address, each (balance − fee −
   headroom) / 8, the fee from a first `do_not_relay: true` build: one tx, 8 outputs, fee
   0.00011316; the headroom stays in the vault as change.
2. `sh spend/soak/unfreeze.sh` (removes the drop-ins, enables both units; it refuses while the
   frozen `policy.json` is still at `$SIGELO_SOAK_DIR`), then `systemctl --user start
   monero-wallet-rpc-stagenet`: `setup.sh` (`gen-keys.mjs policy`) asks the wallet-rpc, so it must
   be up first. (A drill that used `mask --runtime` undoes it with `unmask --runtime`; a plain
   `unmask` leaves the runtime link.)
3. `node gen-keys.mjs` (fresh S and approver in the new directory; the repo is not touched), then
   `sh setup.sh`.
4. `systemctl --user enable --now sigelo-soak-keeper.service sigelo-soak-agent.timer
   sigelo-soak-check.timer` (the wallet-rpc is already enabled by `unfreeze.sh`). The new soak's
   day 0 is its first tick ("Healthy").

**5–6. Recovery-rotate, re-bind.** List every identity under the old keeper and, for the agents,
sign the rotations; in the soak they stay on paper past that (no world holds these DIDs). On the
offline box, networking down; the drill's stand-in is a 0700 scratch directory, shredded after.

- **Genesis files.** soak-root: `node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));require("fs").writeFileSync("soak-root.genesis.json",JSON.stringify(p.agents["soak-root"]))' <burnt>/keeper/policy.json`.
  Each delegate, from its signed `delegate` line: `node -e 'for (const l of require("fs").readFileSync(process.argv[1],"utf8").split("\n")) { if (!l) continue; const e = JSON.parse(l).entry; if (e?.kind === "delegate") require("fs").writeFileSync(e.name + ".genesis.json", JSON.stringify(e)) }' <burnt>/keeper/spend.log`
  (the file's `account` is the delegate's `i`).
- **Each agent identity** (soak-root is account 0, every delegate its own account), to keeper
  `j+1`'s `(i, 0)`:
  `sigelo-offline recover --genesis <name>.genesis.json - --agent <i> --keeper 1 --n 0 < <burnt>/keys/S.hex > <name>.recovery.local.json`
  (a real installation passes `--backup backup.age --identity <age identity> --net <net>` instead
  of `- < S.hex`). The output holds the new identity's secret; the agent applies it with
  `sigelo-agent adopt --rotation <file>`, then every copy is shredded. A soak keyed before
  incident #5 has a non-canonical `S.hex`, which `recover` refuses ("not a canonical root"); the
  current soak (c2c9cdc) is one of them. `gen-keys.test.mjs` runs the soak-root line on a soak
  keyed by today's `gen-keys.mjs`.
- **The keeper's own DID** (`/health`, `receipts signed by …`): since `164b8c4` a keeper set up with
  `sigelo-spend init` (`--keeper-package` or `--recovery-commitment`) commits to the Owner's root
  recovery key, so `sigelo-offline recover --genesis identity.json <root> --new-keeper …` followed by
  `sigelo-spend init --adopt recovered.json` on the new host serves the same `chain[0]` DID
  (INCIDENT §5). Keepers keyed before that — this soak's current keeper (c2c9cdc, no
  `identity.json`) — stay unrecoverable and are retired as before; the next rekey gets a
  recoverable one.
- **Re-bind** (§6): `POST /bind` on the new keeper for each agent's new `(i, 0)`, a new bundle
  (with the recovery rotation) to every world.

**7. Post-mortem** (INCIDENT §8): the timeline from detect to last sweep; every txid;
`sha256sum` of the evidence; `check.mjs` against the burnt directory verifying the old
`spend.log` line by line:

```sh
SIGELO_SOAK_DIR=~/drill/sigelo-soak.burnt SIGELO_SOAK_PORT=38299 node …/check.mjs --evidence
```

`--evidence` skips the live units, `/health` and the wallet-rpc and the liveness rules (all of
them would describe the NEW keeper and the swept wallet, not the burnt directory); only the
"keeper log" verification and the clock checks count. `SIGELO_SOAK_PORT` (read by `check.mjs`
for `/health`, default 38200) is set to an unused port as a belt: run without `--evidence`, it
would otherwise ask the new keeper's `/health` on 38200 with the old token. In evidence mode,
"drop vs fees" can be off by the last relay's fee (the last snapshot came before it). And every
place INCIDENT.md or these steps did not work as written goes into the incidents above.
