# Incident runbook: keeper compromise

For the Owner. Keepers are hot (MONERO.md §4.6). Coins that leave do not come back; identities
do, as the recovery key is on no keeper. **Rehearsed once** on the stagenet soak, 2026-10-01
(ROADMAP T14; spend/soak/README.md incident #5): detect → last sweep 15 min 26 s, after the freeze
as written here failed. §2, §3 and §5 below carry that run's corrections. Next drill: quarterly.

To run this on a schedule against your own installation: `kit/` (the recovery kit) binds it to your
hosts, units and paths (`kit/procedure/RUNBOOK.md`, with T14's corrections to §2 and §3), prints it,
and times and grades each drill (`kit/procedure/DRILL.md`).

**Which case?** (a) *one token leaked, host clean*: a root's token → `sigelo-spend token new
policy.json <agent>` (the running keeper refuses the old token from its next request; no restart
needed); a delegate's → `sigelo-wallet revoke <name>` from
any ancestor (it also sweeps the delegate one hop up). Stop there. (b) *keeper host, `spend.key`
or its wallet files*: everything below. (c) *anything that held the 25 words, `S`,
`backup.age` with its age identity, or the recovery secret*: §7, total loss.

## 1. Detect

- An outgoing transfer the log does not explain: `get_transfers {out: true, pending: true,
  pool: true, all_accounts: true}` txids that are not `relayed`/`relay_failed` lines in
  `spend.log`. Someone spent with the wallet keys, not through the keeper. Strongest signal.
- `spend.log` lines you cannot account for, or lines that fail to verify under the keeper DID.
- `spend.key`, `policy.json` or the wallet files changed; a `spend.lock` naming a pid you did
  not start; agents answered `REFUSED: … unknown or revoked token` they did not cause.

**Not a compromise: the host is offline.** Every pay, fund and delegate answering TRY LATER,
with the wallet height frozen, is what a host without a network looks like. In soak incident #4
the test host lost its network for 32 h because its network manager stopped auto-connecting
after a failed handshake and nothing could re-authorise it unattended (spend/soak/README.md). The keeper failed closed: no `intent`
line, nothing sent, every line verifies. Since `0fc50f5` the keeper names the cause:
wallet-rpc's "no connection to daemon" is `502 wallet_offline`, and `sigelo-wallet` prints
"the wallet has no connection to the Monero network; nothing was sent". Before that it was the
generic `wallet`, which looks like a wallet fault. Check the host's network and the wallet
height before freezing anything. `spend/soak/check.mjs` now goes UNHEALTHY without a payment
in 2 h or on a stuck height (`90de821`). If the host also booted without the time, expect
`clock_behind` too (THREAT-MODEL §3.7a).

## 2. Freeze (on the compromised host, minutes count)

In this order. On the soak, `spend/soak/freeze.sh --now` does steps 1–2 and checks them.

1. **Copy first.** `spend.log`, `spend.lock`, `policy.json` to off-host media, and record the
   `sha256sum` of each, while the keeper still runs: any clean stop deletes `spend.lock`.
2. **If the keeper runs under systemd with `Restart=` set** (the soak's keeper is `Restart=always`),
   take the restart away before killing, or systemd brings the keeper straight back on the same
   directory: a drop-in `<unit>.d/freeze.conf` with `[Service]` `Restart=no` in the user unit
   directory (`~/.config/systemd/user`), `systemctl --user disable <unit>`, `systemctl --user
   daemon-reload`, then check `systemctl --user show -p Restart <unit>` says `no`. **Not `mask
   --runtime`**: a unit file in `~/.config/systemd/user` outranks the runtime directory the mask
   is written to, so the mask is silently shadowed. In the rehearsal the keeper came back 10 s
   after the kill and served for 23 s. A persistent `mask` is refused while the unit file sits
   where the mask link would go.
   Then `kill -9 $(head -n1 spend.lock)` (keeps `spend.lock` as evidence) and confirm within
   seconds that the unit is `inactive`/`failed` and not `auto-restart`, and that the lock is
   still there. Then stop `monero-wallet-rpc` the same way (drop-in, `disable`, then
   `systemctl --user stop`: a clean stop saves the wallet file).
   Every bearer token dies with the process: nothing else accepts them.
3. Never restart a keeper on this host or this policy directory. Disconnect the host; image
   it if you can. Treat `spend.key` and every wallet file on it as the attacker's.

**Revoke-all.** No command exists. With the keeper stopped, every token is already dead, so
for case (b) stopping *is* revoke-all. If a keeper must keep running on that directory (case (a)
at scale): `token new` for every root in `policy.json`, discarding the printed tokens (the running
keeper refuses the old ones from its next request), then `sigelo-wallet revoke <name>` from each root for each delegate. A
`sigelo-spend revoke-all <policy.json>` would need: to take `spend.lock` itself and run with
the keeper stopped; a signed tree line that revokes every live delegate by the Owner (today
`tree.ts` accepts a `revoke` only `by` a strict ancestor, so this is a new `by` value or line
kind that replay must accept); a fresh random `token_hash` for every root, tokens discarded; an
optional `frozen` line that makes `serve` refuse to start until the Owner deletes it. It must
not sweep: sweeping from a compromised host proves nothing.

## 3. Sweep to the vault (clean host, not the compromised one)

The **vault** is the wallet the 25 words restore: cold, never loaded by a keeper, spent only
by the human. Sweeping into it needs only its address (`vault.address` in what `sigelo-offline
restore`/`derive` print). The attacker holds the same keys: whichever sweep confirms first wins.

1. Get the burnt wallet's keys on the clean host: `sigelo-offline restore --backup backup.age
   --identity <file> --net <net>` prints keeper 0's `agents_keeper.allowance`; the treasury's
   spend key needs `--reveal-all` (`owner_backup.treasury`).
2. `monero-wallet-rpc` against a trusted daemon, wallet dir on tmpfs →
   `generate_from_keys {filename, address, spendkey, viewkey, restore_height}`; raise the
   account lookahead to the highest account index in `spend.log` (MONERO.md §7); `refresh`.
3. For every account in `get_accounts` with `unlocked_balance` > 0: `sweep_all {address:
   <vault>, account_index: i, subaddr_indices_all: true, priority: 4, unlock_time: 0}`.
   Priority 4 is the highest fee tier. wallet2 skips outputs worth less than their own fee at
   the chosen priority, so a wallet of small change answers error -4 `No unlocked balance` with
   funds still unlocked. Then step down to 3, 2, 1, and stop when only dust is left (refused at
   1); record it. In the rehearsal priority 4 left 182 outputs that only priority 2 took, and the
   fees came to 17 % of the wallet. Locked outputs: repeat every block until empty. Record every
   txid with the evidence; wipe the tmpfs. The swept funds land in the vault as few outputs, and
   whatever later spends them locks the whole balance for 10 blocks per payment.

## 4. New keeper identity

The burnt `K_j` signs as the keeper and derives every agent under it: abandon it. On the
offline box, `sigelo-offline derive <25 words> --keepers <j+2>` prints `K_{j+1}` (`restore`
only the ceremony's); the new host's `spend.key` holds it (64 hex). New `policy.json`, new
tokens (`token new`), empty `spend.log`; the old log stays evidence. **Gap:** the burnt wallet
is gone for good and wallet names are fixed per root (`walletFromRoot(S, "allowance")`): a
replacement needs a new wallet name, which no CLI offers today, or a new root (§7).

## 5. Recovery-rotate every identity under that keeper

Every agent (`agentIdentitySeed(K_j, i, n)`, any `n`), the keeper's own identity, and, on
keeper 0, the root identity. For each: current genesis from `policy.json` (`genesis`), the
`delegate` line in `spend.log`, or the agent's file. New genesis: `agentIdentitySeed(K_{j+1}, i,
0)` (root: `identitySeed(S, n+1)`), same recovery commitment. Sign SPEC §7's recovery rotation
`{v: "sigelo/0", typ: "rotation", id: <last DID you know is yours>, next: <new DID>, iat,
reason: "recovery", recovery_key: <recovery public key>}` with the recovery secret, envelope
carrying `next_genesis` (ts: `rotate({genesis, next_genesis, iat, reason: "recovery", secret:
recoverySeed(S)})`). Rotate from the last honest node: the recovery beats any voluntary
rotation the attacker made there, whatever its `iat` (SPEC §7.1). CLI, on the offline box (the
recovery secret never touches a keeper): `sigelo-offline recover --genesis <current genesis>
--backup backup.age --identity <file> --net <net> --agent i --keeper <j+1> --n 0 >
recovery.local.json` (root identity: `--identity-n <n+1>` instead of `--agent/--keeper/--n`;
same keeper: `--keeper j --n <n+1>`); the agent applies it with `sigelo-agent adopt --rotation
recovery.local.json` (spend/soak/README.md steps 5–6 has the per-identity lines; the root must be
a canonical scalar, which the ceremony's always is). `policy.json` `did` fields: by hand.

**The keeper's own identity** (the DID that signs receipts, approvals and `spend.log`; `/health`
`service.did`) is recovered the same way, if it has an `identity.json` (keepers keyed by
`sigelo-spend init` or `gen-keys.mjs` from `164b8c4` on). Its genesis commits to a recovery key the
keeper host never held: the root's (`recoveryCommitment(S)`, from `init --keeper-package
keeper-<j>.json`) or the operator's offline one (`init --recovery-commitment`, or the key plain
`init` printed once). Who holds what: the thief has `spend.key` (`K_j`) and `identity.json`; the
Owner has the root (25 words or `backup.age`) or that offline key; `identity.json` is public.

1. Offline box, networking down: `sigelo-offline recover --genesis identity.json --backup
   backup.age --identity <age identity> --net <net> --new-keeper <j+1> > keeper.recovered.json`
   (`- < words` or `--restored <file>` as above; for the key plain `init` printed, `--restored
   restored.json --new-keeper random`). `--genesis` is the burnt keeper's `identity.json`, or any
   copy of its genesis: a voluntary rotation the thief appended is skipped (a keeper never rotates
   voluntarily), so the rotation is from the last honest node and wins whatever its `iat` (SPEC
   §7.1). The output is `{did, current, rotation, keeper_root_hex, bundle}`: `keeper_root_hex` is
   `K_{j+1}` (§4), the new keeper's only secret; nothing else secret is in it.
2. New host: `sigelo-spend init --dir <new> --adopt keeper.recovered.json --wallet-rpc … [the
   usual flags]` (`--key <file>` instead, when the new root came another way). It writes
   `spend.key` = `K_{j+1}` and `identity.json` = genesis + rotation, and refuses a key that is not
   the bundle's current one (the stolen `K_j` included). Copy `licence.json` from the old keeper:
   it names the same DID. Shred `keeper.recovered.json`.
3. The keeper DID is unchanged: receipts, approvals and the licence name `chain[0]`, and the new
   receipts verify under the current key of `identity.json`'s chain (SPEC §7, §9; `receipts
   export` carries the bundle). Publish the new `identity.json` wherever the old genesis was known.

A keeper keyed before `164b8c4` (no `identity.json`; `serve` and `doctor` say so) commits to
`recoveryPublicKey(K_j)`, derived from `spend.key`: the thief holds that recovery secret too and can
win any recovery race with a later `iat` (SPEC §7.3). Abandon it: announce the new keeper DID out of
band, signed by the root identity, with the old one retired from the start of the compromise window,
and key the replacement with `init` so this never repeats. The agents' tokens are policy, not
identity: new ones on the new keeper (§4).

## 6. Re-attest and re-bind

New `POST /bind` for each agent's new `(i, 0)`. Hand every world the new bundle (recovery
rotation included; an attacker presents bundles without it), the compromise window, and a
request to re-attest. Tell counterparties old bindings, invoices and addresses pay the attacker.

## 7. Total loss (case c)

`S` cannot be rotated, only abandoned. New ceremony on a clean offline box; sweep the vault,
treasury and allowance to the new vault first. Recovery-rotate every identity to the new root
with the old recovery key, setting the new root's commitment. If the recovery secret itself
leaked, the attacker can issue a later-`iat` recovery and win (SPEC §7.3): announce the loss
out of band and start new identities.

## 8. Post-mortem

- [ ] Timeline: first bad signal, freeze, every sweep txid, every rotation. Losses per account.
- [ ] Root cause: host, token, `spend.key`, wallet-rpc, or a sigelo bug (then SECURITY.md).
- [ ] Evidence hashes kept; the old `spend.log` verified line by line under the old DID.
- [ ] Every retired token, `K_j`, wallet and DID listed with its replacement; worlds told.
- [ ] This runbook corrected wherever it did not work as written.
