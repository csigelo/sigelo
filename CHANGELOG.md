# Changelog

Short commit hashes cited in this repository refer to the pre-publication development
history, which is not public. This public history starts at the import of 2026-10-01.

## v0.1.0 — 2026-10-02 (draft)

- **Status:** first tagged release (GitHub pre-release); wire `sigelo/0` may change until v0.2; the keeper is stagenet-only
  and unaudited.

- **Provenance gate (prototype):** signed instructions (`ctx: "sigelo/instruction"`) gate shell and write tools in
  Claude Code and Hermes; root-owned hooks, taint after reads, deny on error (`6df8a59`, `be75ec3`).
- **CI:** the `DEVICE_STRINGS` secret is deleted; CI checks generic shapes only; the identity gate runs locally
  before every push (`a1b944e`).
- **Releases:** mirrored at `sigelo.io/releases/<tag>/` against SHA256SUMS; from v0.1.1 an SSH-signed tag plus a
  `release.json` attestation, checked by `release/verify-release.sh` (`62407e2`, `709f412`).
- **Site:** `/privacy` with terms; SECURITY.md lists the official channels; mail is receive-only, replies go over
  SimpleX (`62407e2`, `709f412`).

### 2026-10-02
- **Licence check:** vendor genesis pinned, vendor chain verified from the licence, longest-chain rule, term ≤ 3 years; legacy files warned (`dba9b9e`). Vendor ceremony procedure published (`release/vendor-ceremony.md`).
- **Spec coverage:** vectors for §7.2 `hash(next_genesis) == next` and a sixth-key challenge test in both suites (`9cd82d0`).
- **ts = go messages:** 2,960-case mutation differential, 0 result or message differences after `4e1c8d2`.
- **Hygiene:** SPDX MIT headers on every source file (`fe4e8ac`); spend suite runs offline with `SIGELO_TEST_NO_LIVE=1` (`00af8e4`).
- **Reproducible tarballs:** gzip normalised so SHA256SUMS no longer depend on the Node version (`8e197df`).
- **Docs halved:** every public README cut to commands-first with budgets enforced in CI (`docs-test/check-budgets.mjs`).
- **Drill 2:** freeze in 6 s, keeper identity recovered offline from the root, fees 2.4 %; freeze.sh now kills every keeper on the policy (`bce9114`, `6099880`).
- **Gate pass 3:** orphan-process kill, background denylist, TUI paste fix, session-scope taint, HARDENING.md (`297501c`).

- **World:** `sigelo.io/world/` issues §5.2 challenges, `admission: "open"` and 90-day self-reported conformance
  attestations; `POST /world/verify` returns §9.1 (`5191235`, `4088ce2`).
- **MCP:** remote server at `https://sigelo.io/mcp` (Streamable HTTP), one tool, `sigelo_verify` (`4088ce2`).
- **Accept:** `accept/` drop-ins for node, Python and Go: `challenge(did, ctx)` and `accept(challenge, answer,
  bundle)` (`3d741c6`).
- **Hermes:** adapter through MCP config, no code (`7475a5c`); upstream A2A authenticator hook proposal drafted
  (`1cbfaf6`).
- **CI:** a missing `DEVICE_STRINGS` secret warns instead of failing (`d5e1428`).
- **Site:** eight pages under word budgets the site test enforces; Markdown twins via `Link: rel=alternate`,
  IndexNow, AI crawlers in robots.txt (`978fad6`, `6273d0e`).
- **Analytics:** from nginx logs only; addresses cut to /24 or /48, 30-day retention, no cookies, no third party
  (`83bcac7`).

### 2026-10-01

- **Keeper:** `sigelo-spend init`, `doctor`, `receipts export`, `licence`; paid verbs need a licence attestation
  verified offline; `init` requires a wallet-rpc binary (`17e7787`, `eb9f428`, `194fd86`).
- **Keeper recovery:** `init` commits the keeper genesis to the root recovery key; `sigelo-spend init --adopt`
  restores the same DID after a compromise (`164b8c4`, `cc0a83c`).
- **Keeper:** builds wait 180 s; a build outliving its wait answers `TRY LATER wallet_slow` and is never relayed
  (`98ea994`).
- **Soak:** `freeze.sh`/`unfreeze.sh` hold a burnt keeper down; drill fixes to vault sync and `gen-keys.mjs`; a test
  licence, warned 30 days before expiry (`c38b9e3`, `1b574ac`, `5b4a488`).
- **Kit:** `sigelo-recovery-kit` 0.1.0: offline ceremony, printed procedure, drill schedule and grader; the vendor
  never holds a key (`ad970a5`, `9f75a7d`).
- **Site:** static, agent-first, generated from the tree: `.md` twins, `llms.txt`, `index.json`, JSON-LD; `/contact`
  (`0a4381f`, `4bf622b`, `3c2d364`, `a52163e`).
- **Deploy:** `site/deploy/` server setup, atomic deploy with rollback, live checks; sigelo.io live (`ca39b0e`).
- **Release:** public at `github.com/csigelo/sigelo`; `release/publish.sh` update mode adds one `sync:` commit
  (`8a024b3`).
- **CI:** green on Linux, macOS and Windows, Node 22 and 24; Windows skips systemd and POSIX-mode checks (`1bcb01f`,
  `0fbd592`, `a71fb06`).
- **Names:** domain sigelo.io, account `csigelo`, Go module `github.com/csigelo/sigelo/go`, mail contact@sigelo.io
  (`8cde486`, `f85a42a`, `724a903`).

### 2026-09-29 (evening)

- **Docs:** QUICKSTART gives the exact `ed25519-test` `bind()` call, a Timestamps paragraph and the
  recovery-beats-`iat` example (`a795275`).
- **Ceremony:** `--human` shows the 25 words on the terminal only; `restore --words` reads a file or stdin;
  `--import` needs `--i-know-this-seed-was-cold` (`278e87c`, `29a0402`).
- **Monero:** FCMP++/Carrot keeps the 25-word root (ROADMAP §2); the wallet-rpc canary accepts 1.30–1.33; unused
  `get_tx_key` removed (`085bf06`, `ba825f3`).
- **Export:** placeholders replace real stagenet subaddresses and oracle signatures; host specifics removed from
  docs (`5e96d29`, `77a7be4`, `78878b6`, `da03f18`).

### 2026-09-29

- wire: an envelope has exactly its defined keys; an extra key discards an item and is fatal in a rotation
  (`bcee912`, SPEC §3.1; vectors `binding_envelope_extra_key`, `fatal_rotation_envelope_extra_key`).
- **Keeper:** token changes apply per request, no restart (`37190c5`); `SIGELO_DAEMONS` switches daemon after three
  connection failures or a 20-minute stuck height (`e9b4970`).
- **Spec:** a duplicated attestation counts twice; a retired world key keeps minting valid attestations until they
  expire (`5cde1ac`).
- **Soak:** hourly `check.mjs --notify` alerts; agent ticks wait for NTP sync (`246fd66`, `4ec79b2`).
- **Crosscheck:** JCS, base58, addresses, 25-word seeds and Ed25519 against third-party references; no divergence
  (`0a17aa3`).
- **Sim:** dishonest worlds, nested delegation and live policy edits (`ecb7f17`, `4d14292`, `ddff500`).
- **Release:** `release/build.sh` builds tarballs, static `sigelo-verify` and reproducible SHA256SUMS;
  `pack-test.sh` installs them (`20fd24e`, `7cdf4ea`).
- **Conformance:** `sigelo-verify --conformance --impl '<command>'` grades a foreign implementation; weekly
  wallet-rpc canary (`c4cef7d`, `4e1a5aa`).
- **Docs:** THREAT-MODEL §3.7a and INCIDENT §1 cover a wrong clock and an offline host (`7cefd5d`).

### 2026-09-29 (soak incident #4)

- **Keeper:** refuses to sign (`503 clock_behind`) on a clock behind its build floor or log; new TRY LATER
  `wallet_offline`; wallet `store` after each relay (`7a91fdb`, `0fc50f5`, `f98b8cf`).
- **Soak:** outage ticks count as `outage`, not MISMATCH; `check.mjs` flags no payment in 2 h, a stuck height or a
  bad log clock (`9e5e35f`, `90de821`, `efa9f33`).

### 2026-09-24, hostile-JSON differential

- wire: D1 JSON nesting is bounded at 512 levels (`425d2bb`, vector `raw_fatal_depth_513_in_claims`).
- wire: S1 `created` is exactly `YYYY-MM-DDTHH:MM:SSZ`, a real date (`bc7165a`, vector
  `fatal_genesis_created_leap_second`).
- wire: S2 key slots hold canonical points not of small order (`731483b`, vector `fatal_genesis_key_all_zero`).
- wire: S3 the recovery commitment is `sha256:` + 64 lowercase hex (`63cceed`, vector
  `fatal_genesis_recovery_uppercase_hex`).
- wire: S4 a nonce is `z` + 1 to 63 base58btc digits (`c5faf69`, vector `fatal_genesis_nonce_z_hex`).
- wire: S5 noncharacters are a parse error (`001ecfa`, vector `raw_fatal_noncharacter_in_claims_value`).
- **Verifiers:** base58 lengths bounded before decoding; TypeScript readers decode bytes fatally; no argument spread
  over data; parse-error offsets agree (`1380098`, `b0d98d8`, `6498291`, `093abe0`).

### 2026-09-24, audit before the public export

- wire: A1 two identical rotation entries are a fork (`7c285ea`, vector `fatal_duplicate_rotation_is_fork`).
- **Verifiers:** invalid UTF-8 rejects the whole document in ts as in go (`2d9227e`); the 1f916 adapter checks the
  full genesis shape (`8fa96e0`).
- **Export:** `release/publish.sh` makes a single-commit export; its identity gate works on busybox and holds no
  pattern (`41611f6`, `175be8f`).
- **Soak:** genesis nonces as bytes; a compat guard refuses a redeploy the verifier would reject (`200aeb5`).

### 2026-09-17 to 2026-09-23 (wire `sigelo/0`)

- **Spec:** bundles carry `issuers`; chain cycles rejected; §3.1 field tables; §5.2 challenge; §6.3 invoices; §9
  takes `now` and returns §9.1 (`ef829d7`, `f1aba94`, `4de92b8`, `01d6347`).
- **Spec:** a malformed attestation or binding discards that item, identity faults stay fatal; §3.1 field types
  enforced in both verifiers (`ceab548`, `e658348`).
- **Spec:** `monero` bindings accept subaddresses, refuse integrated addresses and SigV1; points decoded as Monero
  decodes them (`c4821e9`, `fcb8c54`).
- **Implementations:** TypeScript; Go reference verifier with one dependency; vector generator in TypeScript; Python
  removed (`ff981a8`, `ea0b9a4`, `c4da3b6`, `00193b0`).
- **Monero:** MONERO.md design; Keccak, base58, addresses, subaddresses and SigV2 in ts and go (`05cf11c`,
  `4bdb430`, `6aea9c9`).
- **Keys:** the root is a Monero 25-word seed whose own wallet is the cold vault; keeper roots and agent identities
  by HKDF, ts = go (`feb7e96`, `846b7cd`, `4f85df7`).
- **Ceremony:** `sigelo-offline ceremony|restore`: age backup, fingerprint, keeper packages (`c2202d8`).
- **Keeper:** `sigelo-spend`: two-phase relay, fees inside caps, per-agent policy entries, `ref` idempotency
  (`7ae0836`, `3f642bd`, `85b0e27`).
- **Keeper:** `sigelo-wallet` agent verbs, delegation, approvals above `approval_above`; run end to end on stagenet
  (`fdaba3f`, `9e2756f`, `12408e6`, `8e554aa`).
- **Keeper:** the lane cannot freeze, names are never reused, one keeper per directory; `spend.lock` survives
  reboots; consistent API errors (`57b57a4`, `44c614e`, `3b01de1`).
- **Adapters:** 1f916 world side; moadim agent sidecar with Monero commands (`4de92b8`, `d7d3349`, `7ae0836`).
- **Docs:** QUICKSTART and the mock world `examples/world.mjs` (`cd450a8`, `38e9c76`).

## v0.1 draft (wire `sigelo/0`) — 2026-09

- **Spec:** hashed genesis; `"sigelo\n" || JCS(body)` signing; no floats; recovery beats `iat`; commitment carried
  forward; forks rejected; unproven bindings labelled (`cc2349d`).

