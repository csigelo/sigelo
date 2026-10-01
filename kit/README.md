# sigelo recovery kit

The offline, high-security tier of sigelo as a product you run yourself: an air-gapped root ceremony in one script, the procedure printed on paper, a drill scheduler with a timeline you fill and grade, and the incident runbook bound to your own installation, rehearsed every year.

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".** The kit is software, procedure and, if you buy it, facilitation. You run every command. Nothing is hosted, nothing phones home, nothing is sent anywhere.

## Who it is for

An operator who runs agents that pay through a sigelo keeper (`sigelo-spend`) and who must:

- **never lose the root.** The 25 words are the vault, the treasury, every keeper root, every agent identity and the recovery key at once (MONERO.md §2). Lose them and the backup together and nothing is recoverable; leak them and nothing is rotatable.
- **survive a burnt keeper.** Keepers are hot (MONERO.md §4.6). When one is compromised, coins that left do not come back, but identities do — if you can freeze, sweep, re-key and recovery-rotate under pressure, from a runbook that matches your hosts and has been run before.

## What is free, and what the kit adds

Everything sigelo does is already in the repository, MIT-licensed: `sigelo-offline ceremony --human`, `restore --words`, `recover`, the keeper, `INCIDENT.md`, the stagenet rehearsal notes. The kit adds the parts that turn those into a procedure a person can follow on a bad day:

| Part | Where | What it is |
|---|---|---|
| The scripted ceremony | `ceremony/run.sh` (`sigelo-kit-ceremony`) | refuses to run online; checks node and `age`; runs `ceremony --human` so the 25 words reach your terminal only; writes `backup.age` and the public outputs to your removable medium and the keeper packages apart; never overwrites a root and never makes a second one; writes `ceremony-record.json` (what, when, which host, which tools — no secret); `--verify-paper` checks the paper copy against the fingerprint |
| The printed procedure | `procedure/CEREMONY.md`, `DRILL.md`, `RUNBOOK.md`; `procedure/print.sh` | who is in the room, what is on paper, where each item goes, the vault-only rule; the drill (detect, freeze, sweep, new identity and licence, recovery-rotate, re-bind, post-mortem) with every step that did not work as written in the 2026-10-01 rehearsal (F1–F7) corrected in place; the runbook — rendered to self-contained HTML with page breaks, to print and tick in pen |
| The runbook bound to your installation | `bind.mjs` (`sigelo-kit-bind`) + your `kit.json` | fills your hosts, paths, units, ports, people and vault address into the three documents; refuses anything in `kit.json` that looks like key material |
| The drill scheduler and timeline | `drill/schedule.mjs` (`sigelo-kit-drill`) | a systemd `--user` timer (or a cron line) that reminds you each quarter and creates `drills/<date>/TIMELINE.md` with the step table pre-filled |
| The self-assessment | `drill/grade.mjs` (`sigelo-kit-grade`) | scores a finished timeline offline: every step timed, evidence sha256s, sweep txids, post-mortem findings; prints detect → frozen and detect → last sweep |
| A yearly cadence | DRILL.md | quarterly tabletop drills, a yearly stagenet rehearsal with the paper check and a test-decrypt of `backup.age` |

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

## Price

`<price>` one-time for the kit (this directory, its updates within the 0.x line, and the binding of your runbook), plus optional yearly drill facilitation at `<price>` per drill (CONTACT.md). The software itself stays MIT: the price is for the productised procedure and the facilitation, not for access to the code.

## The rule, and why

**The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of a customer — not even "for recovery".** It is software and facilitation: no custody, no key material, so no crypto-asset service under MiCA (Regulation (EU) 2023/1114). There is no "we keep a copy for you", no key-share escrow, no hosted backup and no recovery service that needs anything of yours. If you lose the 25 words and the backup, the vendor cannot help you, by design — which is also why nobody can be compelled or compromised into helping someone else take them.

## What the kit does not do

- No custody, no escrow, no hosted backup, no remote access to your hosts — ever.
- It does not make a burnt keeper's coins come back; it makes the sweep faster and the identities recoverable.
- It does not close sigelo's own open gaps, it names them where you meet them: no CLI for a replacement wallet name, the keeper's own identity (INCIDENT.md §5 has its current state), no command for the `did` fields in `policy.json`, one `recover` invocation per identity (RUNBOOK.md §4–§5).
- It does not move a licence: a `sigelo-spend` licence names one keeper DID, so a replacement keeper needs a reissue from the vendor, who receives that public DID and nothing else (DRILL.md 4.4, RUNBOOK.md §4).
- It does not verify that your "offline" host has no radio you forgot; it checks for a default route and records what it found.
