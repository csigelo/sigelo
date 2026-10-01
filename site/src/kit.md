---
title: Recovery kit — the offline tier, run by you
description: The sigelo recovery kit: an air-gapped root ceremony in one script, the procedure printed on paper, a drill scheduler with a self-graded timeline, and the incident runbook bound to your installation. Software and facilitation only — the vendor never holds a seed, key, backup or token.
---
# Recovery kit

For an operator whose agents pay through a sigelo [keeper](/keeper.html) and who must never lose the root and must survive a burnt keeper. The kit is the offline, high-security tier of sigelo made into a procedure a person can follow on a bad day: a scripted air-gapped ceremony, printed pages to tick in pen, a quarterly drill with a timeline you fill and grade, and the incident runbook bound to your own hosts, units and paths.

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".** The kit is software you run and paper you keep; facilitation is a person who reads, times and witnesses. No custody, no key material, nothing hosted.

## Why it exists

One 25-word root carries the vault, the treasury, every keeper root, every agent identity and the recovery key ([MONERO.md §2](/monero.html#2-key-model)). Lose the words and the backup together and nothing comes back; leak them and nothing can be rotated, only abandoned. Keepers are hot ([MONERO.md §4.6](/monero.html#46-liabilities)): when one is burnt, coins that left are gone, but identities return through recovery rotations — if you can freeze, sweep, re-key and rotate under pressure.

The first full rehearsal of that, on the stagenet soak, took 15 min 26 s from detect to the last sweep and found places where the written runbook did not work, among them: a `kill -9` that systemd undid within ten seconds, a runtime mask that a user unit file silently overrode, a `sweep_all` that left more than a third of the wallet behind at the highest priority, a vault wallet that would have scanned for about half an hour before accepting the command meant to skip the scan, and an `unmask` that did not undo the mask. The kit's printed drill carries each of them, with what works instead.

## What you get

| Part | What it does |
|---|---|
| `sigelo-kit-ceremony` | One POSIX `sh` script. Refuses to run while the host has a default route; checks node and `age`; runs `sigelo-offline ceremony --human` so the 25 words reach your terminal and nothing else; puts `backup.age` and the public outputs on your removable medium and the keeper packages apart; never overwrites a root, never makes a second one; writes `ceremony-record.json` (what, when, which host, which tools — no secret). `--verify-paper` checks the paper against the fingerprint without showing what you type. |
| Printed procedure | `CEREMONY.md` (who is in the room, what is on paper, where each item goes, the vault-only rule), `DRILL.md` (detect, freeze, sweep, new identity, recovery-rotate, re-bind, post-mortem), `RUNBOOK.md` (the incident runbook) — rendered to self-contained HTML with page breaks, to print. |
| `sigelo-kit-bind` | Fills your hosts, paths, units, ports, people and vault address from a small `kit.json` into the three documents. Refuses anything in `kit.json` that looks like key material. |
| `sigelo-kit-drill` | A systemd `--user` timer, or a cron line, that reminds you each quarter and creates the drill's `TIMELINE.md` with the step table already filled in. |
| `sigelo-kit-grade` | Scores a finished timeline offline: every step timed, evidence sha256s, sweep txids, post-mortem findings; prints your detect → frozen and detect → last sweep to beat next time. |
| Cadence | Quarterly tabletop drills; a yearly stagenet rehearsal with the paper check and a test-decrypt of `backup.age`. |

Everything the kit runs is already free in the repository (MIT): the ceremony, `restore --words`, `recover`, the keeper, the runbook. The kit adds the procedure around them, bound to your installation and rehearsed.

## The guardrail

The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of a customer, not even "for recovery". There is no hosted backup, no key-share escrow, no remote access to your hosts, no recovery service. This is software and facilitation — no custody, no key material — so not a crypto-asset service under MiCA. If you lose the 25 words and the backup, nobody can help you, by design; for the same reason nobody can be compelled or compromised into helping someone else.

## Price and contact

- The kit: `<price>`, one time.
- Drill facilitation (optional): `<price>` per drill. The facilitator runs the clock, reads the runbook aloud, witnesses, and writes the post-mortem with you. The facilitator never touches a key, a host or a medium.
- Contact: `contact@sigelo.io` or SimpleX (see [contact](/contact.html)); vulnerabilities go to [security](/security.html).

**Status:** 0.1.0, built on sigelo {{version}}; the ceremony is tested end to end on a real pseudo-terminal with the real `age`; the drill procedure is generalised from one stagenet rehearsal. Like everything here: draft, stagenet only for the keeper, unaudited.
