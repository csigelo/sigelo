# Drill timeline — soak-stagenet — 2026-10-01

| field | value |
|---|---|
| kind | stagenet |
| installation | soak-stagenet |
| date (UTC) | 2026-10-01 |
| operator | rehearsal agent |
| witness | — |
| facilitator | none |
| version running | keeper 6df3b67, repo c2c9cdc |

Test fixture for kit/drill/grade.mjs, modelled on the T14 stagenet rehearsal of 2026-10-01: its step times, its three sweep txids (public stagenet transactions) and its findings. The evidence sha256s are stand-ins (sha256 of "fixture:<name>"), not the rehearsal's files.

## Steps

| # | step | UTC | evidence | result |
|---|---|---|---|---|
| 0.1 | timeline created; kind, people and version filled | 13:18:00 | | ok |
| 0.2 | restore keys ready in a 0600 file, read by script (never on a command line) | 13:18:10 | allowance-keys.json | ok (made 09-29) |
| 0.3 | vault address for this drill recorded | 13:18:20 | vault/README | ok |
| 0.4 | paper check (yearly): PAPER OK | 13:18:30 | | N/A — soak root is a raw S.hex, no paper |
| 0.5 | test-decrypt (yearly): fingerprint matches | 13:18:40 | | N/A — no backup.age in the soak |
| 0.6 | health check before, output saved | 13:19:59 | check-detect.txt | HEALTHY, 592/592 lines verify |
| 1.1 | DETECT — the clock starts | 13:19:53 | | drill trigger |
| 2.1 | evidence copied off-host, SHA256SUMS written (keeper still running) | 13:20:07 | evidence/SHA256SUMS | ok |
| 2.2 | keeper stopped and disabled | 13:20:10 | | mask --runtime + kill -9 as written |
| 2.2a | deviation: systemd restarted the keeper; stopped it | 13:20:44 | spend.lock.restarted | runtime mask shadowed by ~/.config unit |
| 2.3 | wallet-rpc stopped and disabled | 13:21:34 | | stop saved the wallet |
| 2.4 | verified inactive and disabled, again after 15 s — FROZEN | 13:21:39 | | disabled both |
| 2.5 | revoke-all proven: root token answers TRY LATER | 13:21:42 | | TRY LATER unreachable |
| 2.6 | delegate token answers TRY LATER (or N/A: none live) | 13:21:43 | | N/A — no live delegate at drill time |
| 3.1 | clean wallet-rpc on tmpfs up (log on tmpfs) | 13:22:09 | | port 38084 |
| 3.2 | wallet generated from keys; refresh returned | 13:29:41 | | 4927 blocks in ~7 min |
| 3.3 | every account swept: priority 4, then 3, 2, 1 | 13:31:22 | | p4 one tx, p2 two tx, dust left |
| 3.4 | LAST SWEEP sent | 13:35:19 | | 0.07612634 swept, fees 0.01573816 |
| 3.5 | clean wallet-rpc stopped; tmpfs removed | 13:35:50 | | ok |
| 4.1 | burnt directory moved to evidence | 13:35:59 | | ok |
| 4.2 | new keeper root and spend.key | 13:55:58 | | new random S (not K_1): finding |
| 4.3 | new keeper up on the new directory only | 13:56:27 | | ok |
| 4.4 | licence reissued to the new keeper DID and installed (or N/A: free tier) | 13:56:30 | | N/A — the soak keeper (6df3b67) predates the licence gate |
| 5.1 | identities under the burnt keeper listed with their last honest DID | 13:54:00 | | 10 identities on paper |
| 5.2 | recovery rotations signed and adopted (or written on paper) | 13:54:30 | | on paper |
| 5.3 | keeper's own DID retired and announced out of band (INCIDENT §5) | 13:54:35 | | on paper: no command, no world holds the DID |
| 6.1 | re-bind done and worlds told (or written on paper) | 13:54:40 | | on paper |
| 7.1 | `sha256sum -c` of the evidence OK; old spend.log verified line by line | 13:57:07 | check-evidence.txt | 592/592 verify |
| 7.2 | post-mortem written; findings below | 14:20:00 | | ok |

## Evidence

| file | sha256 |
|---|---|
| spend.log | d3ce220687ff26ffa4cf1f9d33775e96e409688e24f107432fdc275e8561e33a |
| spend.lock | 8dce2e3ea0a4f78a99e02b66709fd4c31ca9d5e534d22fbd069be381acbee490 |
| policy.json | 064e85262ec6e543bfca087ed70e7cfd3e2674862695b4c48f03913c6bfeb2c5 |
| spend.lock.restarted | 344b91dd4c6e349b64644eea6cded997cdbcc74c42d2f4f90e96ca081a3fbe3e |

## Sweeps

| account | txid | amount | fee | priority |
|---|---|---|---|---|
| 0 | 659d86e498447b3a06bafe9707932d59e378e492983049b20b1e6c46173079ef | 0.0505765 | 0.006088 | 4 |
| 0 | 285f569d58b4b957b820d51be005dfc2e1b339e0c1739de4bea129bf35f2d094 | 0.0212384 | 0.0079616 | 2 |
| 0 | 08cb934ffd65ce95d492da1a658f6f41c552f6fd1a6a90e34739afc33a27ec6a | 0.00431144 | 0.00168856 | 2 |

## Findings

- `mask --runtime` is shadowed by a unit file in ~/.config/systemd/user; the keeper restarted on the burnt directory 10 s after kill -9. Fix: stop + disable, verify is-active/is-enabled.
- sweep_all at priority 4 leaves outputs worth less than their fee; repeat at 3, 2, 1. Dust stays.
- The vault wallet-rpc syncs before binding its port; --no-initial-sync, then refresh {start_height}.
- `unmask` does not remove a runtime mask; `unmask --runtime` does.
- The replacement keeper used a new random root, not K_1: the identities are not the recovery targets of the old ones.
