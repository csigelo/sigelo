# Drill facilitation

The kit runs without anyone from the vendor. If you want a second pair of eyes and a clock, you can book facilitation for the ceremony or for a drill.

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".** Facilitation is a person who reads, times, witnesses and writes. It is not custody, not key management and not a recovery service.

## What the facilitator does

- **Before:** binds your runbook with you from your `kit.json` (paths, units, hosts — never keys), checks the printed procedure matches your installation, agrees the drill kind (tabletop, stagenet) and the date.
- **During:** runs the clock; reads each step of DRILL.md (or CEREMONY.md) aloud; writes the wall-clock time and what happened into your `TIMELINE.md` as you go; calls out a step that is being skipped or done out of order; witnesses.
- **After:** writes the post-mortem with you — timeline, detect → frozen, detect → last sweep, every place the procedure did not work as written, with the fix — runs `sigelo-kit-grade` with you, and updates your bound runbook from the findings.
- **Attends by voice or video pointed at the operator, never at a screen** that shows key material. During the ceremony the facilitator is never in line of sight of the words.

## What the facilitator never does

- Never touches, receives, sees, stores, escrows or transmits a seed word, `S`, a keeper root, a wallet key, `backup.age`, an age identity, a share of any of them, or a bearer token.
- Never logs into your hosts, never asks for remote access, never runs a command on your behalf. You type every command.
- Never keeps a copy of anything "for recovery". If you lose the words and the backup, the facilitator cannot help — by design.
- Never sweeps, signs or moves funds.

If anyone claiming to be the facilitator asks for any of the above, it is not the facilitator: stop and treat it as an incident.

## Contact

- Channel: `contact@sigelo.io` or SimpleX (see `https://sigelo.io/contact.html`); security reports go to `security@sigelo.io` (SECURITY.md)
- Identity to check the channel against: `<facilitator DID or key>` (a sigelo bundle the facilitator presents; verify it offline)
- Price: `<price>` per facilitated drill; the ceremony `<price>`.
- Response during an incident (case (b), live): `<hours>`, best effort. The runbook works without it.

The pseudonym (`csigelo`) and the channel were decided at ROADMAP D1 (2026-10-01). The remaining placeholders are filled when the facilitator's identity is minted and the prices and hours are set.
