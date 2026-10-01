# Incident runbook — {{installation}}

INCIDENT.md (sigelo repository root) bound to this installation by `kit/bind.mjs` from `kit.json`, with the corrections the stagenet rehearsal T14 found. Keepers are hot (MONERO.md §4.6): coins that leave do not come back; identities do, because the recovery key is on no keeper. Network: **{{net}}**. Keeper {{keeper.index}} on **{{keeper.host}}**, policy directory `{{keeper.policy_dir}}`, unit `{{keeper.unit}}` ({{supervisor}}).

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".** If you have a facilitation contract, call {{people.facilitator}}: they read this with you and keep the clock. They never take a key, a file or a host.

**Which case?**

- **(a) one token leaked, host clean.** A root agent's token: `sigelo-spend token new {{keeper.policy_dir}}/policy.json <agent>` (the running keeper refuses the old token from its next request). A delegate's: `sigelo-wallet revoke <name>` from any ancestor (it also sweeps the delegate one hop up). Stop there.
- **(b) the keeper host, `spend.key` or its wallet files.** Everything below.
- **(c) anything that held the 25 words, `S`, `backup.age` with its age identity, or the recovery secret.** §7, total loss.

## 1. Detect

- An outgoing transfer the log does not explain: `get_transfers {out: true, pending: true, pool: true, all_accounts: true}` on port {{keeper.wallet_rpc_port}} with txids that are not `relayed`/`relay_failed` lines in `{{keeper.policy_dir}}/spend.log`. Someone spent with the wallet keys, not through the keeper. Strongest signal.
- `spend.log` lines you cannot account for, or lines that fail to verify under the keeper DID.
- `spend.key`, `policy.json` or the wallet files changed; a `spend.lock` naming a pid you did not start; agents answered `REFUSED: … unknown or revoked token` they did not cause.

**Not a compromise: the host is offline.** Every pay answering TRY LATER with the wallet height frozen — `502 wallet_offline`, "the wallet has no connection to the Monero network; nothing was sent" — is a host without a network. Check the network and the wallet height before freezing. A host that booted without the time also answers `clock_behind`.

Write the time now. Start the timeline: `sigelo-kit-drill new --dir {{drills_dir}} --kind live`.

## 2. Freeze ({{keeper.host}}, minutes count)

The order sigelo's reference freeze (`spend/soak/freeze.sh`) runs and asserts, as corrected by T14: **evidence → no restart and no boot start → kill → assert dead → wallet-rpc stopped cleanly.**

1. **Evidence first, keeper still running** (a clean stop deletes `spend.lock`), to off-host media:

```sh
mkdir -m 700 {{evidence_dir}}/<date> && cp -p {{keeper.policy_dir}}/spend.log {{keeper.policy_dir}}/spend.lock \
  {{keeper.policy_dir}}/policy.json {{evidence_dir}}/<date>/ && (cd {{evidence_dir}}/<date> && sha256sum * > SHA256SUMS)
```

2. **Stop the keeper so nothing restarts it.** Every bearer token dies with the process.

```sh
{{freeze_keeper}}
```

   Under systemd a stopped unit is never restarted; the stop deletes `spend.lock`, which step 1 kept. To keep the lock in place as well, take the restart away **before** the kill, as `freeze.sh` does (user units shown; system units: `/etc/systemd/system` and `sudo systemctl` without `--user`):

```sh
D=~/.config/systemd/user
for u in {{keeper.unit}} {{keeper.wallet_rpc_unit}}; do
  mkdir -p "$D/$u.d" && printf '[Service]\nRestart=no\n' > "$D/$u.d/freeze.conf"; systemctl --user disable "$u"
done
systemctl --user daemon-reload
systemctl --user show -p Restart {{keeper.unit}} {{keeper.wallet_rpc_unit}}   # Restart=no, both; only then:
kill -9 "$(head -n1 {{keeper.policy_dir}}/spend.lock)"
systemctl --user show -p ActiveState,SubState {{keeper.unit}}        # inactive|failed, never auto-restart
```

3. **Stop the wallet-rpc**: a clean stop (it saves the wallet file), never a kill:

```sh
{{freeze_wallet}}
```

4. **Verify, now and 15 s later:**

```sh
{{freeze_verify}}
```

5. Never restart a keeper on this host or this policy directory. Disconnect the host; image it if you can. Treat `spend.key` and every wallet file on it as the attacker's.

*Corrected by T14 (F1):* a bare `kill -9` on a `Restart=always` unit brings the keeper back on the burnt directory (T14: after 10 s; it took over the lock and served for 23 s). `mask --runtime` is written to the runtime directory, which a unit file in `~/.config/systemd/user` or `/etc/systemd/system` outranks: silently shadowed, `is-enabled` stays `enabled`. A persistent `mask` is refused while the unit file sits where its link would go; a drop-in applies wherever the unit file lives. Units installed `WantedBy=default.target` must be disabled or the next boot starts them. Check with `show -p Restart`, `is-active` and `is-enabled`, never by a command's exit code.

**Revoke-all.** No command exists. With the keeper stopped, every token is already dead: for case (b) stopping *is* revoke-all. Check: `. {{keeper.env_file}}; sigelo-wallet balance` → `TRY LATER: the wallet service is not answering.` A live delegate's token the same way if one is live; "none live" is a valid outcome (F5).

## 3. Sweep to the vault (the clean host: {{clean_host.name}})

The vault is the wallet the 25 words restore: cold, never loaded by a keeper. Vault address: `{{vault_address}}`. The attacker holds the same keys: whichever sweep confirms first wins.

1. Keys: `sigelo-offline restore --backup backup.age --identity <file> --net {{net}}` prints keeper {{keeper.index}}'s `agents_keeper.allowance` (the treasury's spend key needs `--reveal-all`, `owner_backup.treasury`). Pass them to the wallet-rpc from a file inside a script, never on a command line.
2. Clean wallet-rpc, wallet dir and log on tmpfs:

```sh
mkdir -m 700 {{clean_host.tmpfs}}
monero-wallet-rpc --{{net}} --wallet-dir {{clean_host.tmpfs}} --daemon-address {{clean_host.daemon}} \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port {{clean_host.rpc_port}} --disable-rpc-login --log-file {{clean_host.tmpfs}}/rpc.log
```

   `generate_from_keys {filename, address, spendkey, viewkey, restore_height}`; raise the account lookahead to the highest account index in `spend.log` (MONERO.md §7); `refresh {start_height}`: one blocking call (minutes), nothing else answers meanwhile, so do not poll.
3. For every account in `get_accounts` with `unlocked_balance` > 0: `sweep_all {address: "{{vault_address}}", account_index: i, subaddr_indices_all: true, priority: 4, unlock_time: 0}`. **On error -4 `No unlocked balance` while `get_balance` still shows unlocked funds, step down to priority 3, then 2, then 1** (F7): wallet2 skips outputs worth less than their own fee at the chosen priority. Stop when only dust is left (refused at 1) and record it. Locked outputs: repeat every block until empty. Record every txid, amount and fee. Many small outputs cost: T14 paid 17 % of the wallet in fees (priority 4 left 182 outputs that only priority 2 took). Accept it: speed wins the race.
4. SIGTERM the wallet-rpc; `rm -rf {{clean_host.tmpfs}}`.

When you later open the vault itself (spent only by a human), start its wallet-rpc with `--no-initial-sync`, then `refresh {start_height: <height before the first sweep>}`: without the flag a wallet made offline scans from its estimated birth height before it binds the RPC port (F2; T14: ~30 min). The sweeps land as few outputs, so spending them back as one locks the whole balance for 10 blocks per payment until change multiplies; `transfer_split` to several destinations at the same address (e.g. 8 parts) instead of one `sweep_all` avoids that (not yet rehearsed).

## 4. New keeper identity

The burnt `K_{{keeper.index}}` signs as the keeper and derives every agent under it: abandon it. On the offline box, `sigelo-offline derive` with the 25 words and `--keepers <j+2>` prints `K_{j+1}`; the new host's `spend.key` holds it (64 hex). New `policy.json`, new tokens (`sigelo-spend token new`), empty `spend.log`, all written into the new directory, never into tracked configuration (F4); the old directory is moved to evidence, `licence.json` included. **Gap:** the burnt wallet is gone for good and wallet names are fixed per root: a replacement needs a new wallet name, which no CLI offers today, or a new root (§7).

Bring units back only on the new directory, the wallet-rpc first: `{{restore_units}}`. If step 2 used drop-ins, first remove both `<unit>.d/freeze.conf` and `daemon-reload`, and only once the `policy.json` there is not the frozen one (its sha256 differs from the evidence copy): enabling on the burnt directory starts a keeper there at the next boot. A runtime mask, if anyone made one, needs `unmask --runtime` (F3).

**Licence (paid tier).** A licence names one keeper DID (`sub`), so the burnt keeper's `licence.json` does not cover the new keeper and `sigelo-spend licence install` refuses it there. `sigelo-spend licence show --dir <new policy dir>` prints the new keeper DID: send the vendor that public DID, nothing else, for a reissue; `sigelo-spend licence install <file> --dir <new policy dir>`; `licence show` must say `tier pro`. Until then the new keeper is the free tier: delegation, funding, approvals and receipts export answer 403 `licence_required`, and a payment that needs an approval is refused, never paid.

## 5. Recovery-rotate every identity under that keeper

Every agent (`agentIdentitySeed(K_j, i, n)`, any `n`), the keeper's own identity, and, on keeper 0, the root identity. Genesis files: a root agent's from `policy.json` `agents.<name>`, a delegate's from its signed `delegate` line in the burnt `spend.log` (its `account` is the delegate's `i`; DRILL.md step 5.1 has the two one-liners that cut them out). For each agent, on the offline box, one line:

```sh
sigelo-offline recover --genesis <name>.genesis.json --backup backup.age --identity <file> --net {{net}} \
  --agent <i> --keeper <j+1> --n 0 > <name>.recovery.local.json
```

(root identity: `--identity-n <n+1>`; same keeper: `--keeper j --n <n+1>`.) The agent applies it with `sigelo-agent adopt --rotation <file>`; shred every copy. The recovery rotation beats any voluntary rotation the attacker made at that node, whatever its `iat` (SPEC §7.1). The `did`/`genesis` fields of the new `policy.json`: by hand. **The keeper's own identity:** see INCIDENT.md §5 for its current state. As of T14 it could not be recovery-rotated (its recovery key derived from `spend.key`, which the thief holds): only abandoned, the new keeper DID announced out of band, signed by the root identity, the old one retired from the start of the compromise window.

## 6. Re-attest and re-bind

New `POST /bind` for each agent's new `(i, 0)` at {{keeper.url}} (the new keeper). Hand every world — {{worlds}} — the new bundle (recovery rotation included; an attacker presents bundles without it), the compromise window, and a request to re-attest. Tell counterparties that old bindings, invoices and addresses pay the attacker.

## 7. Total loss (case c)

`S` cannot be rotated, only abandoned. New ceremony on a clean offline box (CEREMONY.md); sweep the vault, treasury and allowance to the new vault first. Recovery-rotate every identity to the new root with the old recovery key, setting the new root's commitment. If the recovery secret itself leaked, the attacker can issue a later-`iat` recovery and win (SPEC §7.3): announce the loss out of band and start new identities.

## 8. Post-mortem

- [ ] Timeline: first bad signal, freeze, every sweep txid, every rotation. Losses per account.
- [ ] Root cause: host, token, `spend.key`, wallet-rpc, or a sigelo bug (then SECURITY.md).
- [ ] Evidence hashes kept; the old `spend.log` verified line by line under the old DID.
- [ ] Every retired token, `K_j`, wallet and DID listed with its replacement; worlds told.
- [ ] This runbook corrected wherever it did not work as written; `sigelo-kit-grade` on the timeline.

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".**
