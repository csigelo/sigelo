# sigelo recovery kit

sigelo's offline, high-security tier as a kit you run yourself: an air-gapped root ceremony in one
script, printed procedures, a drill scheduler with a self-graded timeline, and the incident runbook
bound to your installation. For operators whose agents pay through a sigelo keeper.

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".** You run every command; nothing is hosted or sent anywhere. Lose the 25 words and the backup and nobody can help — which is also why nobody can be compelled to help someone else take them. Software and facilitation only: no custody, no key material, so no crypto-asset service under MiCA (Regulation (EU) 2023/1114).

## Use

```sh
npm install ./sigelo-<v>.tgz ./sigelo-recovery-kit-<v>.tgz        # while online; verify SHA256SUMS first
cp node_modules/sigelo-recovery-kit/kit.example.json kit.json      # fill in your hosts, paths, units, people
npx sigelo-kit-bind --kit kit.json --out procedure                 # after the ceremony: add --record <out>/ceremony-record.json
npx sigelo-kit-print procedure                                     # → procedure/print/procedure.html; print it
# the day of the ceremony, offline, at a real terminal (CEREMONY.md):
npx sigelo-kit-ceremony --out /media/A/sigelo-root --recipient age1… --net mainnet --keepers 2
npx sigelo-kit-ceremony --verify-paper --out /media/A/sigelo-root
npx sigelo-kit-drill install --dir ~/sigelo-drills --kit kit.json  # writes the timer + cron line; prints how to enable
npx sigelo-kit-grade ~/sigelo-drills/<date>/TIMELINE.md            # after each drill
```

From a clone, the same scripts run in place (`sh kit/ceremony/run.sh …`, `node kit/bind.mjs …`); they find `ts/dist/offline.js`. `kit/test/run.sh` runs the kit's own checks (it needs `age`, `age-keygen` and util-linux `script` for the ceremony part, and SKIPs that part without them).

Requirements: node ≥ 22, `age` (or `rage`), a POSIX `sh` (busybox works), systemd or cron for the reminder. Linux is the tested platform; the ceremony's offline check reads `/proc/net/route` and falls back to `netstat -rn` elsewhere.

## Parts

The protocol tools (`sigelo-offline ceremony --human`, `restore --words`, `recover`, the keeper,
`INCIDENT.md`) are free in the repository. The kit adds:

| Part | Where | What |
|---|---|---|
| Scripted ceremony | `ceremony/run.sh` (`sigelo-kit-ceremony`) | refuses to run online; runs `ceremony --human`; writes `backup.age` and public outputs to removable media, keeper packages apart; never overwrites or makes a second root; writes a secret-free `ceremony-record.json`; `--verify-paper` checks the paper copy |
| Printed procedure | `procedure/CEREMONY.md`, `DRILL.md`, `RUNBOOK.md`; `procedure/print.sh` | the ceremony, the drill (detect, freeze, sweep, new identity and licence, recovery-rotate, re-bind, post-mortem) and the runbook, as printable HTML |
| Bound runbook | `bind.mjs` (`sigelo-kit-bind`) + `kit.json` | fills your hosts, paths, units, ports, people and vault address in; refuses anything that looks like key material |
| Drill scheduler | `drill/schedule.mjs` (`sigelo-kit-drill`) | quarterly systemd `--user` timer or cron line; creates `drills/<date>/TIMELINE.md` |
| Self-assessment | `drill/grade.mjs` (`sigelo-kit-grade`) | scores a timeline offline: timings, evidence hashes, sweep txids, findings |

Cadence: quarterly tabletop drills; yearly stagenet rehearsal with the paper check and a test-decrypt of `backup.age`.

## Price

`<price>` one-time for the kit (updates within 0.x, runbook binding), optional yearly drill
facilitation at `<price>` per drill (CONTACT.md). The software stays MIT.

## What the kit does not do

- It does not make a burnt keeper's coins come back; it makes the sweep faster and the identities recoverable.
- It does not close sigelo's own open gaps, it names them where you meet them: no CLI for a replacement wallet name, the keeper's own identity (INCIDENT.md §5 has its current state), no command for the `did` fields in `policy.json`, one `recover` invocation per identity (RUNBOOK.md §4–§5).
- It does not move a licence: a `sigelo-spend` licence names one keeper DID, so a replacement keeper needs a reissue from the vendor, who receives that public DID and nothing else (DRILL.md 4.4, RUNBOOK.md §4).
- It does not verify that your "offline" host has no radio you forgot; it checks for a default route and records what it found.
