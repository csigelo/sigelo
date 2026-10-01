# Incident drill — {{installation}}

Printed procedure of the sigelo recovery kit: the rehearsal of a burnt keeper (INCIDENT.md case (b)), generalised from the stagenet rehearsal T14 of 2026-10-01 (spend/soak/README.md, incident #5) to any installation, with every place that rehearsal found the written procedure wrong (F1–F7 below) folded in. Print it, run it with the clock, write the wall-clock time at every step into the drill's `TIMELINE.md` (`sigelo-kit-drill new`), grade it afterwards (`sigelo-kit-grade`). **The timeline is the product**: it is what tells you, before a real incident, how long your freeze and sweep take and which line of the runbook is wrong.

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".** A facilitator runs the clock, reads this page aloud, witnesses and writes the post-mortem. Every key, command and coin movement is yours.

## Kinds of drill and cadence

| Kind | What moves | When |
|---|---|---|
| **tabletop** | nothing: every step is read, the commands are shown, the times are estimates | quarterly, the default reminder |
| **stagenet** | a stagenet replica of {{installation}}: a real keeper is frozen, really swept, really replaced | yearly, and after any change to keepers, hosts or units |
| **live** | production — this is the real incident | when INCIDENT.md case (b) happens; use RUNBOOK.md |

Every yearly drill also re-runs the **paper check** and the **test-decrypt** (step 0).

## Roles

| Role | Who | Does |
|---|---|---|
| Operator | {{people.owner}} | every command, every key, every medium |
| Witness | {{people.witness}} | confirms each step happened; signs the timeline |
| Facilitator (optional) | {{people.facilitator}} | runs the clock, reads each step aloud, writes the timeline and the post-mortem; never touches a key, a host or a medium |

## 0. Before (the day before)

- [ ] `sigelo-kit-drill new --dir {{drills_dir}}` → `{{drills_dir}}/<date>/TIMELINE.md`. Fill in kind, people, the commit/version running.
- [ ] Stand-in for the backup (stagenet): the replica keeper's wallet keys, read from its wallet-rpc (`query_key view_key`, `query_key spend_key`, `get_address {account_index: 0}`, a restore height = the lowest incoming `height` − 100) into a 0600 file **read by your script, never pasted on a command line**. (Live: these come from `sigelo-offline restore --backup` on the clean host.)
- [ ] The vault address for this drill: the real one ({{vault_address}}) for live, a fresh stagenet wallet for stagenet (`monero-wallet-cli --offline --generate-new-wallet … --command address > seed-and-create-output.txt` — the seed prints to stdout, so redirect it into a 0600 file). **Record the chain tip height now**: a wallet made offline gets a refresh height estimated ~20 000 blocks below the tip, and step 4 needs the real one.
- [ ] Optional, stagenet: consolidate the replica wallet's small outputs a few days ahead (`sweep_all` to its own address at priority 1), or accept step 3's fees (F7).
- [ ] If the replica keeper has a licence (`sigelo-spend licence show --dir {{keeper.policy_dir}}` says `tier pro`): note its `sub` (the keeper DID) and expiry. Step 4.4 needs a licence for the new keeper's DID, and only the vendor can issue one.
- [ ] Yearly: **paper check** (`sigelo-kit-ceremony --verify-paper --out <medium A>`: PAPER OK) and **test-decrypt** (`sigelo-offline restore --backup backup.age --identity <file> --net {{net}}`: the fingerprint matches). Record both results, never the words.
- [ ] Health before: your keeper's health check output saved, sha256 recorded.

## 1. Detect

- [ ] Note the time: **the clock starts**. In a drill the trigger is the facilitator's word.
- [ ] Real signals, for reference: an outgoing transfer `spend.log` does not explain (`get_transfers {out, pending, pool, all_accounts}` txids with no `relayed`/`relay_failed` line) — strongest; log lines that do not verify under the keeper DID; `spend.key`, `policy.json` or wallet files changed; a `spend.lock` naming a pid you did not start.
- [ ] **Not a compromise: the host is offline.** Every pay answering TRY LATER with the wallet height frozen (`wallet_offline`, "the wallet has no connection to the Monero network") is what a host without a network looks like (soak incident #4: 32 h offline, nothing sent, every line verified). Check the network and the wallet height before freezing. A host that booted without the time answers `clock_behind`.

## 2. Freeze (minutes count; on {{keeper.host}})

The order is the one sigelo's reference freeze (`spend/soak/freeze.sh`) runs and asserts: **evidence → take away every restart → kill → assert dead → stop the wallet-rpc cleanly.** Each step prints or gets its UTC time.

- [ ] **2.1 Evidence first, keeper still running** — a clean stop deletes `spend.lock`:

```sh
mkdir -m 700 {{evidence_dir}}/<date> && cp -p {{keeper.policy_dir}}/spend.log {{keeper.policy_dir}}/spend.lock \
  {{keeper.policy_dir}}/policy.json {{evidence_dir}}/<date>/ && (cd {{evidence_dir}}/<date> && sha256sum * > SHA256SUMS)
```

- [ ] **2.2 Stop the keeper so the supervisor cannot bring it back.** Bound for {{supervisor}}:

```sh
{{freeze_keeper}}
```

  Under systemd a *stopped* unit is never restarted, so stop + disable freezes it; the stop deletes `spend.lock`, which 2.1 kept. To keep the lock in place as well (what `freeze.sh` does), take the restart away first, then kill — **never a bare `kill -9` on a unit with `Restart=`** (F1: T14's keeper came back on the burnt directory 10 s later, took over the "stale" lock and served for 23 s):

```sh
D=~/.config/systemd/user        # system units: /etc/systemd/system, and `sudo systemctl` without --user
for u in {{keeper.unit}} {{keeper.wallet_rpc_unit}}; do
  mkdir -p "$D/$u.d" && printf '[Service]\nRestart=no\n' > "$D/$u.d/freeze.conf"
  systemctl --user disable "$u"
done
systemctl --user daemon-reload
systemctl --user show -p Restart {{keeper.unit}} {{keeper.wallet_rpc_unit}} # Restart=no for both, BEFORE the kill
kill -9 "$(head -n1 {{keeper.policy_dir}}/spend.lock)"
systemctl --user show -p ActiveState,SubState {{keeper.unit}}     # inactive|failed, never auto-restart
```

  **Not `mask --runtime`**: it writes to `/run/…/systemd/user`, which a unit file in `~/.config/systemd/user` (or `/etc/systemd/system`) outranks, so the mask is silently shadowed (`is-enabled` stays `enabled`). A persistent `mask` is refused while the unit file sits where its link would go. A drop-in applies wherever the unit file lives.

- [ ] **2.3 Stop the wallet-rpc** — a clean stop, never a kill (it stores the wallet file; a kill costs a rescan later):

```sh
{{freeze_wallet}}
```

- [ ] **2.4 Verify, and verify again 15 s later** (a restart policy acts after a delay). Units installed `WantedBy=default.target` start at the next boot unless disabled:

```sh
{{freeze_verify}}
```

- [ ] **2.5 Revoke-all is the kill.** With the keeper stopped no process accepts any token. Prove it: `. {{keeper.env_file}}; sigelo-wallet balance` → `TRY LATER: the wallet service is not answering.`
- [ ] **2.6** The same with a live delegate's token **if one is live**. Delegates are often short-lived (T14's agent created the day's delegate at ~00:02Z and revoked it an hour later): "N/A — no live delegate" is a valid outcome, not a skipped step (F5). The root proof already shows no process accepts any token.
- [ ] Leave the agents running ({{keeper.agent_units}}) if you can: their next tick must log TRY LATERs and not crash. Note what they logged (an older agent counts the keeper's correct TRY LATER as a mismatch: a finding about the agent, not the keeper).
- [ ] Time of freeze: `__:__:__`. Target: under 2 minutes from detect (T14: 1 min 41 s, 23 s of it the rogue restart).

## 3. Sweep to the vault (on the clean host, not {{keeper.host}})

The attacker holds the same keys: whichever sweep confirms first wins.

- [ ] **3.1** Keys on the clean host: `sigelo-offline restore --backup backup.age --identity <file> --net {{net}}` (keeper {{keeper.index}}'s `allowance`; the treasury needs `--reveal-all`). Read them into the wallet-rpc call **from a file inside your script**, never on a command line. Clean wallet-rpc on tmpfs, its log there too (without `--log-file` it lands in the current directory):

```sh
mkdir -m 700 {{clean_host.tmpfs}}
monero-wallet-rpc --{{net}} --wallet-dir {{clean_host.tmpfs}} --daemon-address {{clean_host.daemon}} \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port {{clean_host.rpc_port}} --disable-rpc-login --log-file {{clean_host.tmpfs}}/rpc.log
```

- [ ] **3.2** `generate_from_keys {filename, address, spendkey, viewkey, restore_height}`; raise the account lookahead to the highest account index in `spend.log`; `refresh {start_height: <restore height>}`. **`refresh` blocks**: the wallet-rpc answers nothing else (even `get_height` times out) until it returns — T14: 7 min for 4 927 blocks. Do not poll, do not restart it. Then `get_accounts`: every `delegate` account index in `spend.log` is present.
- [ ] **3.3** For every account with `unlocked_balance` > 0: `sweep_all {address: <vault>, account_index: i, subaddr_indices_all: true, priority: 4, unlock_time: 0}`. **Step down on error -4** (F7): `No unlocked balance in the specified subaddress(es)` while `get_balance` still shows unlocked funds means the rest are outputs worth less than their own fee at that priority (wallet2 skips them). Repeat at 3, then 2, then 1; stop when only dust is left (refused at 1) and record the dust. Record every txid, amount, fee and priority in the timeline's sweep table. Locked outputs: repeat every block until every account is empty.
- [ ] **Expect the cost.** T14: priority 4 took one transaction and left 182 small outputs; priority 4 and 3 then failed with -4; priority 2 took them in two; 0.00003638 dust stayed below the fee at every priority. Fees: 0.0158 of 0.0919 XMR — **17 %** of the wallet. In a real compromise accept it: speed wins the race. In a drill, consolidate ahead (step 0) or accept it.
- [ ] **3.4** Time of the last sweep: `__:__:__`. T14's benchmark: detect → last sweep 15 min 26 s.
- [ ] **3.5** Stop that wallet-rpc (SIGTERM saves and exits in about a second), `rm -rf {{clean_host.tmpfs}}`.

## 4. New keeper identity

- [ ] **4.1** Keep the burnt directory as evidence: move it, do not delete it (its `licence.json` included).
- [ ] **4.2** The burnt `K_{{keeper.index}}` is abandoned. On the offline box: `sigelo-offline derive` from the 25 words with `--keepers <j+2>` prints `K_{j+1}`; the new host's `spend.key` holds it. New `policy.json`, new tokens (`sigelo-spend token new`), empty `spend.log`. Generate everything **into the new directory**: a re-key must never rewrite tracked configuration in a checkout or deployment repo (F4: T14's key generator rewrote a tracked template with the new identities). **Known gap:** the burnt wallet is gone for good and wallet names are fixed per root; a replacement wallet needs a new wallet name, which no CLI offers today, or a new root (RUNBOOK §7). A stagenet drill may reuse the swept wallet; write down that it did. A drill that makes a *new random root* instead of `K_{j+1}` is not rehearsing recovery (T14 did; finding).
- [ ] **Stagenet: sweep the vault back** to the replica wallet's address once the step-3 sweeps have 10 confirmations (~20 min). Open the vault in a wallet-rpc on a spare port **with `--no-initial-sync`**, then `refresh {start_height: <tip recorded at step 0>}` (F2: without the flag it scans from its offline-estimated height *before* it binds the RPC port, so no `refresh` can be sent — T14: ~30 min, cut to 4 min with the flag). The sweep-back lands as **one output**: until change multiplies, every payment on the new keeper locks the whole balance for 10 blocks (~20 min) and later payments in the same tick get `wallet_locked`; an approval may give up and show as abandoned — the drill's doing, not a keeper defect. Mitigation (not yet tried in a rehearsal): `transfer_split` to several destinations that are all the same address (e.g. 8 equal parts) instead of one `sweep_all`.
- [ ] **4.3** Bring the units back on the new directory only, the wallet-rpc first (setting up the policy asks it): `{{restore_units}}`. If 2.2 used drop-ins, first remove `<unit>.d/freeze.conf` for both units and `daemon-reload`; check the policy directory the unit points at is **not** the frozen one (the `policy.json` sha256 differs from the evidence copy) — re-enabling on the burnt directory starts a keeper there at the next boot. If someone used `mask --runtime`, undo it with `unmask --runtime` (a plain `unmask` leaves the runtime link; F3).
- [ ] **4.4 Licence (paid tier).** A licence is issued to one keeper DID (`sub`), so the burnt keeper's `licence.json` does not cover the new keeper, and `sigelo-spend licence install` refuses it there. `sigelo-spend licence show --dir <new policy dir>` prints the new keeper DID: send the vendor **that DID only** (it is public) with a reissue request, then `sigelo-spend licence install <reissued file> --dir <new policy dir>` and check `licence show` says `tier pro`. Keep the old `licence.json` with the evidence. Until the reissue the new keeper is the free tier: delegation, funding, approvals and receipts export answer 403 `licence_required`, and a payment that needs an approval is refused, never paid. Record the time it took. No licence before the incident: `N/A — free tier`.

## 5. Recovery-rotate every identity under that keeper

- [ ] **5.1** On paper first: every identity under the burnt keeper (each agent and delegate: `agentIdentitySeed(K_j, i, n)`; the keeper's own; on keeper 0 the root identity), its last honest DID and where its genesis comes from: a root agent's from `policy.json` `agents.<name>`, a delegate's from its signed `delegate` line in the burnt `spend.log` (its `account` is the delegate's `i`). One genesis file per identity:

```sh
node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));for(const[n,g]of Object.entries(p.agents))require("fs").writeFileSync(n+".genesis.json",JSON.stringify(g))' <burnt>/policy.json
node -e 'for(const l of require("fs").readFileSync(process.argv[1],"utf8").split("\n")){if(!l)continue;const e=JSON.parse(l).entry;if(e?.kind==="delegate")require("fs").writeFileSync(e.name+".genesis.json",JSON.stringify(e))}' <burnt>/spend.log
```

- [ ] **5.2** For each agent identity, on the offline box (network down; the recovery secret never touches a keeper), one line each, to keeper `j+1`'s `(i, 0)`:

```sh
sigelo-offline recover --genesis <name>.genesis.json --backup backup.age --identity <file> --net {{net}} \
  --agent <i> --keeper <j+1> --n 0 > <name>.recovery.local.json
```

  (root identity: `--identity-n <n+1>` instead of `--agent/--keeper/--n`.) The output holds the new identity's secret: the agent applies it with `sigelo-agent adopt --rotation <file>`, then every copy is shredded. `recover` refuses a root that is not canonical ("not a canonical root"); a ceremony's root always is. The new `policy.json`'s `did`/`genesis` fields are the rotated agents' new ones, by hand.
- [ ] **5.3 The keeper's own DID** (`/health`, the signer of receipts and approvals): see INCIDENT.md §5 for its current state. As of T14 it could only be abandoned, not recovery-rotated (its recovery key derived from `spend.key`, which the thief holds), and announced retired out of band, signed by the root identity, with the new keeper DID. Write down what you did and when.

## 6. Re-attest and re-bind

- [ ] **6.1** New `POST /bind` for each agent's new `(i, 0)`. Every world ({{worlds}}) gets the new bundle with the recovery rotation in it, the compromise window, and a request to re-attest. Counterparties are told that old bindings, invoices and addresses pay the attacker. (Stagenet: on paper.)

## 7. Post-mortem

- [ ] **7.1** The timeline from detect to last sweep; every txid; the sha256 of every evidence file (`sha256sum -c SHA256SUMS` passes). The old `spend.log` verified line by line under the old keeper DID (sigelo's soak tooling: `check.mjs --evidence` with its port set to an unused one, so it never asks the new keeper's `/health` with an old token; in evidence mode "drop vs fees" can be off by the last relay's fee).
- [ ] Losses per account (live) or fees per sweep and the fee share of the wallet (drill); dust left.
- [ ] Every retired token, `K_j`, wallet, licence and DID with its replacement; worlds told.
- [ ] **7.2 Findings:** every place this page or RUNBOOK.md did not work as written, one bullet each, with the fix. Zero findings is itself a finding: say why. Then `sigelo-kit-grade {{drills_dir}}/<date>/TIMELINE.md` and keep its output with the timeline.

## What T14 found, and where it is fixed above

| | Did not work as written | Now |
|---|---|---|
| F1 | `mask --runtime` shadowed by the unit file in `~/.config`; `kill -9` → `Restart=always` revived the keeper on the burnt directory | 2.2: stop + disable, or `Restart=no` drop-in + daemon-reload + check, then kill; assert dead, not `auto-restart` |
| F2 | the vault's wallet-rpc scanned ~30 min before binding its port; `refresh {start_height}` could not be sent | 0: record the tip; 4: `--no-initial-sync`, then `refresh {start_height}` |
| F3 | a plain `unmask` leaves a runtime mask | 4.3: no mask used; else `unmask --runtime` |
| F4 | the key generator rewrote tracked configuration | 4.2: generate into the new directory only |
| F5 | no live delegate token at drill time | 2.6: "none live" is a valid outcome |
| F6 | "no CLI" for recovery was stale; the keeper's own DID has no recovery | 5.1–5.2: genesis files and one `recover` line per identity; 5.3: INCIDENT §5 |
| F7 | priority 4 cannot empty a wallet of small change; 17 % fees; the sweep-back lands as one output | 3.3: step down 4→3→2→1, stop at dust; 4: expect `wallet_locked`, `transfer_split` |

> **The vendor never receives, holds, escrows or sees any seed, key, backup.age, share or token of yours — not even "for recovery".**
