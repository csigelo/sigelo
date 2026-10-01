# Root ceremony — {{installation}}

Printed procedure of the sigelo recovery kit. Print it (`procedure/print.sh`), take it into the room, tick each box in pen, sign the last page, keep it with `ceremony-record.json`. Network: **{{net}}**.

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".** This ceremony is software you run and paper you keep. Nobody outside the room gets anything.

The ceremony makes the one root `S` of your installation: 25 words (a Monero 25-word seed) from which every keeper root, wallet, agent identity and the recovery key derive (MONERO.md §2, §4.5). Whoever reads the 25 words owns the vault, the treasury and every identity, permanently: `S` cannot be rotated, only abandoned. The ceremony exists so the words reach exactly one human, once, on paper, and an encrypted copy reaches the Owner's age key, and nothing else ever holds them.

## 1. Before the day (one week ahead)

- [ ] **The Owner's age identity.** On the Owner's own device: `age-keygen -o owner.key`. The public half (`age-keygen -y owner.key`, starts `age1…`) is the recipient you bring to the ceremony. The identity file goes to {{backup.age_identity_location}}. How the Owner protects it (paper, passphrase-wrapped, hardware plugin) is the Owner's choice; nobody else ever holds it.
- [ ] **The software, verified while still online.** Download the release tarballs and `SHA256SUMS`; `sha256sum -c SHA256SUMS` must say OK for `sigelo-<v>.tgz` and `sigelo-recovery-kit-<v>.tgz`. Copy them to the ceremony host.
- [ ] **The ceremony host.** Either (A) the host of the keeper that will hold the most, so its keys never cross a wire (MONERO.md §4.5), or (B) a laptop booted from a fresh live image that will be wiped afterwards. Install node ≥ 22, `age`, then `npm install ./sigelo-<v>.tgz ./sigelo-recovery-kit-<v>.tgz` — while online. Swap off or encrypted.
- [ ] **Media.** Two removable media, labelled A and B. A holds the ceremony's output; B gets a copy. If the ceremony host is not the keeper host, a third medium labelled K for the keeper packages.
- [ ] **Paper.** One card for the 25 words, a pen (not a pencil), a tamper-evident envelope. Nothing that photographs: phones, smart watches and laptops not used for the ceremony stay outside the room.
- [ ] **The record** of who is in the room (section 2) agreed.

## 2. Who is in the room

| Role | Who | Sees the screen while the words are shown | Touches paper or media |
|---|---|---|---|
| Owner | {{people.owner}} | **yes — the only one** | yes |
| Witness | {{people.witness}} | no: faces away until the Owner says "clear" | signs the record only |
| Facilitator (optional, contracted) | {{people.facilitator}} | **never** — may attend by voice only | **never** |

The facilitator reads this procedure aloud, keeps the time and writes the record. The facilitator never sees the screen, the paper or a medium, and never receives a file. No camera, no screen sharing, no remote session on the ceremony host: `--human` keeps the words out of stdout and any agent's pipe, not out of a screen recorder or a terminal that logs (MONERO.md §4.6).

## 3. The run

- [ ] Time started: `__:__` UTC. Present: ____________________
- [ ] **Network down.** Airplane mode, cable out, `ip link set <if> down` for every interface. The script checks for a default route and refuses while there is one.
- [ ] Medium A inserted and mounted. `--out` is an empty or new directory on it: `{{ceremony_out}}`.
- [ ] The Owner runs, at a real terminal (not through an agent, not over SSH):

```sh
sigelo-kit-ceremony --out {{ceremony_out}} --recipient <age1… of the Owner> --net {{net}} \
  --keepers <N> [--treasury-keeper <j>] [--keepers-out <medium K>/keepers] \
  --operator "<Owner>" --witness "<Witness>"
```

- [ ] The witness and the facilitator look away. The 25 words appear once, numbered, on the Owner's terminal only.
- [ ] The Owner writes the 25 words on the card, numbered 1–25, in pen, and reads the card back against the screen once, silently.
- [ ] The Owner clears the scrollback (`clear && printf '\033[3J'`, or close the terminal window) and says "clear". The others turn back.
- [ ] Time the words were shown and cleared: `__:__` to `__:__` UTC.

If anything fails, the script names it and writes nothing (or leaves `.stage` for the Owner to inspect). It never deletes a root and never makes a second one in the same directory.

## 4. After the run (same sitting)

- [ ] **Paper check:** `sigelo-kit-ceremony --verify-paper --out {{ceremony_out}}` — the Owner types the 25 words from the card (not shown). It must print `PAPER OK`. A mismatch now is cheap; one found at a restore is not.
- [ ] **Keeper packages.** Each `keeper-<j>.json` is plaintext keeper keys. Carry each to its keeper host by hand (medium K), install it as that keeper's `spend.key` material, then shred every copy on the ceremony host and on K.
- [ ] **Medium B.** Copy `backup.age`, `fingerprint.txt`, `ceremony-public.json` and `ceremony-record.json` from A to B; `sha256sum` both copies of `backup.age`; they match the record's `backup_sha256`.
- [ ] **Ceremony host.** (B) wipe the live image. (A) the keeper host keeps only its own keeper package.
- [ ] **Test-decrypt, before anything is funded.** Later, on the Owner's own device: `sigelo-offline restore --backup backup.age --identity owner.key --net {{net}}`. It decrypts, re-derives and refuses unless the result reproduces `fingerprint.txt`. An untested backup is a hash of nothing (MONERO.md §4.6).

## 5. Where everything goes

| Item | Goes to | Never together with |
|---|---|---|
| The card with the 25 words | {{backup.paper_location}} (the vault) | anything else; no photo, no copy typed anywhere |
| Medium A: backup.age, fingerprint.txt, record | {{backup.medium_a_location}} | the age identity |
| Medium B: the same | {{backup.medium_b_location}} | the age identity; medium A |
| The Owner's age identity | {{backup.age_identity_location}} | either medium |
| Keeper packages | their keeper hosts, then shredded | — |
| This printed procedure, signed, and `ceremony-record.json` | the operator's records | — (they hold no secret) |

The words alone restore everything; backup.age plus the age identity restore everything. Keep each of those two paths in one place, and the two paths apart.

> **Vault only, never a hot wallet.** The 25 words are the vault's Monero seed. They never go into a mobile or desktop wallet, a password manager that syncs, a keeper host, an agent, or any networked device. A hot device that held them holds `S`, and no rotation takes that back — only moving every coin to a new root does (MONERO.md §4.6).

## 6. Sign-off

| | |
|---|---|
| Date (UTC) | |
| Started / finished | |
| `backup_sha256` from ceremony-record.json (first and last 8 hex) | |
| Paper check | PAPER OK / ______ |
| Owner | |
| Witness | |
| Facilitator (if any) | |

Next: the yearly drill re-runs the paper check and the test-decrypt (DRILL.md, step 0).

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".**
