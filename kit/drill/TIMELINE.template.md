# Drill timeline — {{installation}} — {{date}}

| field | value |
|---|---|
| kind | {{kind}} |
| installation | {{installation}} |
| date (UTC) | {{date}} |
| operator | |
| witness | |
| facilitator | |
| version running | |

All times UTC, `HH:MM:SS`, written when the step happens, not afterwards. One row per step; add a row for every deviation (number it like `2.2a`) and say in *result* what you did instead. A step that cannot apply gets `N/A — <why>` in *result* and still a time. Procedure: DRILL.md. Grade afterwards: `sigelo-kit-grade TIMELINE.md`.

> The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery". Never write a key, a seed word or a token into this file.

## Steps

| # | step | UTC | evidence | result |
|---|---|---|---|---|
| 0.1 | timeline created; kind, people and version filled | | | |
| 0.2 | restore keys ready in a 0600 file, read by script (never on a command line) | | | |
| 0.3 | vault address for this drill recorded | | | |
| 0.4 | paper check (yearly): PAPER OK | | | |
| 0.5 | test-decrypt (yearly): fingerprint matches | | | |
| 0.6 | health check before, output saved | | | |
| 1.1 | DETECT — the clock starts | | | |
| 2.1 | evidence copied off-host, SHA256SUMS written (keeper still running) | | | |
| 2.2 | keeper: restart taken away and disabled (stop, or Restart=no drop-in + daemon-reload), then killed; not auto-restarting | | | |
| 2.3 | wallet-rpc disabled and stopped cleanly (never killed) | | | |
| 2.4 | verified inactive and disabled, again after 15 s — FROZEN | | | |
| 2.5 | revoke-all proven: root token answers TRY LATER | | | |
| 2.6 | delegate token answers TRY LATER (or N/A: none live) | | | |
| 3.1 | clean wallet-rpc on tmpfs up (log on tmpfs) | | | |
| 3.2 | wallet generated from keys; refresh returned | | | |
| 3.3 | every account swept: priority 4, stepping down to 3, 2, 1 on error -4; dust recorded | | | |
| 3.4 | LAST SWEEP sent | | | |
| 3.5 | clean wallet-rpc stopped; tmpfs removed | | | |
| 4.1 | burnt directory moved to evidence | | | |
| 4.2 | new keeper root and spend.key | | | |
| 4.3 | new keeper up on the new directory only | | | |
| 4.4 | licence reissued to the new keeper DID and installed: `licence show` says tier pro (or N/A: free tier) | | | |
| 5.1 | identities under the burnt keeper listed with their last honest DID | | | |
| 5.2 | recovery rotations signed and adopted (or written on paper) | | | |
| 5.3 | keeper's own DID retired and announced out of band (INCIDENT §5) | | | |
| 6.1 | re-bind done and worlds told (or written on paper) | | | |
| 7.1 | `sha256sum -c` of the evidence OK; old spend.log verified line by line | | | |
| 7.2 | post-mortem written; findings below | | | |

## Evidence

| file | sha256 |
|---|---|

## Sweeps

| account | txid | amount | fee | priority |
|---|---|---|---|---|

## Findings

<!-- One bullet per place DRILL.md or RUNBOOK.md did not work as written, with the fix. Zero findings is itself a finding: say why. -->
