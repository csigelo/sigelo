# Changelog

Short commit hashes cited in this repository refer to the pre-publication development
history, which is not public. This public history starts at the import of 2026-10-01.

## unreleased — 2026-10-02, the site cut to the bone, and visits counted

- **Conformance attestations and remote MCP (`4088ce2`).** `POST /world/conformance` takes an agent's challenge
  answer plus the summary `sigelo-verify --conformance --impl` printed; the world checks the vectors are the ones
  it serves and the summary is a clean run of all their cases, then issues a 90-day attestation in ctx
  `sigelo.io/conformance` with `claims.conformance {implementation, vectors, passed, total, self_reported: true,
  runner}`. The world ran nothing and the claim says so; an attestation from a run we do ourselves is the later,
  paid product. `https://sigelo.io/mcp` is MCP over Streamable HTTP (revision 2026-07-28, also answering the
  legacy `initialize` handshakes), written by hand with no dependencies: stateless, JSON responses only, one
  tool, `sigelo_verify` — no identity, no wallet, no key. `server.json` lists it as a `remotes` entry. 67 world
  checks, inspector `tools/call` live.
- **Hermes proposal drafted, not posted (`1cbfaf6`).** A feature request for one generic hook, a pluggable A2A peer
  authenticator; sigelo would ship as a standalone plugin per their contributing rules.

- **Accepting a sigelo identity is two functions (`accept/`, `3d741c6`).** Drop-ins for node (on the `sigelo`
  library, 28 lines), Python (`cryptography` plus `sigelo-verify`, or opt-in `SIGELO_VERIFY=https://sigelo.io/world/verify`
  for zero install, 41 lines) and Go (on the reference verifier, 53 lines): `challenge(did, ctx)` issues a
  single-use §5.2 challenge; `accept(challenge, answer, bundle)` returns the §9.1 result only when the bundle
  verifies, its current DID is the one claimed and the current key signed the challenge. Express, Flask and
  net/http examples. `accept/test.sh` drives all three with a real `sigelo-agent`: accept, a rotated identity,
  a bare genesis; rejected: replay, tampered signature, someone else's bundle, a rotated-away key, a forged
  nonce, B answering A's challenge; the same ten cases pass against the live remote verifier. Site: `/accept`.
- **CI gate (`d5e1428`).** A missing `DEVICE_STRINGS` secret is a warning, not a failure: the export gate
  already ran on every pushed tree, and a red job per push only produced failure mail.

- **The first world: sigelo.io/world/ (`5191235`, `e717fd0`).** Outside feedback the same day: "a passport no
  country accepts yet". So sigelo.io is the first country. A small loopback service behind nginx hands out
  §5.2 challenges (single use, 5 minutes), checks the answer under the DID's current key (from a verified
  bundle's chain or a genesis) and issues one `admission: "open"` attestation with
  `claims {seen, bundle_valid, verifier}`; the same DID gets the same attestation back for 24 hours;
  `POST /world/verify` returns the §9.1 result over HTTP for agents with nothing installed. The issuer,
  `did:sigelo:zBASk7w9zUhCYuuEpcUDSAuBUPW7qSAjAjAYARDCJ4S2Q`, was made on the server against a recovery
  commitment whose key never went there; its genesis and rotation chain are static files, so if the world
  goes down nothing breaks — attestations already issued verify offline (R10). 60 requests a minute per
  truncated network, 256 KB bodies, no accounts, no cookies, no client address reaches the service, only
  counts are public. The first attestation was issued and verified end to end the same evening. Remote MCP
  and a conformance-passed attestation for implementations are the next steps.

- **Discoverable by agents (`6273d0e`).** HTML pages send `Link: …; rel="alternate"; type="text/markdown"` and
  the Markdown twins point back at their canonical page; IndexNow submits the sitemap after every deploy;
  robots.txt names every AI crawler operator documented today; JSON-LD carries `sameAs` and keywords;
  `integrations/mcp/server.json` follows the registry's 2025-12-11 schema; all five packages have keywords,
  homepage, repository and bugs. A 404 under `/sha256/` was cached as immutable for a year — fixed.
  `site/SEO.md` lists what the account holder must do (GitHub topics, Search Console, Bing, the MCP registry
  publish after npm) and what was rejected with its source.
- **Hermes Agent adapter (`adapters/hermes`, `7475a5c`).** Nous Research's runtime (MIT, Python, v0.21.5) is an
  MCP client and reads SKILL.md, so a Hermes agent gets a sigelo identity and the keeper's verbs from nine
  lines of `config.yaml` and no code; its test drives the real `hermes` binary four times with a scripted
  model: identity made, challenge signed, attestation stored, bundle accepted by the Go verifier, four
  wallet verbs against a mock keeper. Hermes has no identity of its own and lists DID/Ed25519 as out of
  scope for its A2A design; gating its peer trust on a sigelo challenge is noted as an upstream proposal.

- **Eight pages, hard budgets (`978fad6`).** The Owner's verdict on the first site: verbose, over-disclosing,
  a waste of visiting agents' tokens. Now: `/` 69 words (what, three commands, six links, one status
  line), `/adopt` 152, `/verify` 76, `/keeper` 100, `/contact` 7; `/spec`, `/security`, `/changelog` are
  the raw documents. `llms.txt` is 91 words and lists the raw docs and `llms-full.txt` (47 KB, was
  172) with their sizes so an agent chooses what to spend. The site test fails the build when a page
  exceeds its budget. Removed as pages: evidence, integrations, did-method, why, monero, quickstart,
  kit, vectors (all still under `/raw/`). No process, history or counts on any page.
- **Visits counted on the server (`83bcac7`).** Agents never run JavaScript, so analytics are built from
  nginx logs: the client address is cut to its network (IPv4 /24, IPv6 /48) before it is written,
  the query string and the referrer's path are dropped, the user agent and `Accept` header are kept
  (they tell an agent from a browser), 30 days retention, no cookies, no third party. GoAccess every
  15 minutes and a 40-line `agents.txt` (AI agents by name, programmatic clients, browsers, the
  `llms.txt` → `adopt.md` → mock-world funnel), both behind basic auth at `/_stats/`. First day:
  ClaudeBot 68 requests, GPTBot 56, about 59 human visitors.

## unreleased — 2026-10-01, the rehearsal, the site, and the first two products

- **Incident rehearsal T14 ran** (spend/soak/README incident #5, INCIDENT.md; timeline in the operator's
  drill directory): detect → wallet-rpc down 1 min 41 s → last sweep to the vault 15 min 26 s; the vault
  spendable 35 min after detect; a NEW keeper live on this tree 36 min after detect; its first payment
  70 min after detect (the swept-back funds sat in one output, locked 20 min per spend). All 592 lines
  of the burnt keeper's log verify. Fees 0.0158 XMR, 17 % of the wallet: `sweep_all` at priority 4
  and 3 refused 182 small outputs, priority 2 took them; 0.00003638 XMR of dust is unsweepable.
  **The freeze failed as written:** `systemctl --user mask --runtime` is overridden by unit files in
  `~/.config/systemd/user`, so `Restart=always` revived the burnt keeper for 23 s (no request reached
  it; the log stayed byte-identical). Fixed by `spend/soak/freeze.sh`/`unfreeze.sh` (`c38b9e3`): a
  `Restart=no` drop-in, `daemon-reload`, `kill -9`, then an assertion that the unit stays down and
  `spend.lock` survives — proven on a scratch unit against the old way. Also from the drill (`1b574ac`):
  the vault's wallet-rpc needs `--no-initial-sync` before `refresh {start_height}` can be sent;
  `gen-keys.mjs` no longer rewrites the tracked policy template and now mints roots that
  `sigelo-offline recover` accepts (the old soak's random `S.hex` was not recoverable); steps 5–6 are a
  concrete per-identity `recover` procedure. **Open spec gap:** the keeper's own DID cannot be
  recovered — its recovery key derives from `spend.key`, which the thief holds (ROADMAP §5.6).
  The live soak now runs this tree (REVISION c2c9cdc at 13:56Z) and rode through a second host
  network outage the same afternoon: it paid on the first tick after the network returned.
- **The site** (`site/`, `0a4381f`, `4bf622b`, `3c2d364`): sigelo.io as a static, agent-first site
  generated from the tree — 17 pages each with a `.md` twin and `rel=alternate`, `llms.txt`,
  `llms-full.txt`, `adopt.md`, `robots.txt` naming the AI crawlers, `sitemap.xml`,
  `.well-known/security.txt`, `index.json` with the spec and vector sha256s, JSON-LD on every page,
  raw and content-addressed copies of the docs, the mock world served; `integrations/mcp/server.json`.
  Its own test: 255 checks, and `site/test/TASK-site.md` — a Haiku agent given only the served site
  and the release files installed from the tarballs, checked SHA256SUMS, made a tier-2 identity,
  got attested by the served world and produced a bundle the release verifier accepts: **6/6 in 97 s**
  (docs-test/RESULTS.md). Not deployed: hosting and the maintainer's name wait on D1.
- **Recovery ceremony kit** (`kit/`, `ad970a5`; product page `3c2d364`): the offline high-security
  tier as a product an operator runs alone — `ceremony/run.sh` refuses to run online, runs
  `ceremony --human` (words to the terminal only, proven on a pty), writes `backup.age` and a
  secret-free record; the printed procedure (ceremony, drill, runbook bound to the operator's paths
  by `bind.mjs`, rendered by `print.sh`); `drill/schedule.mjs` and `grade.mjs` (the T14 timeline
  scores 100/100); `CONTACT.md`. The vendor never receives, holds or sees any key, seed, backup or
  share — boxed on every page (MiCA: software and facilitation, no custody). Package
  `sigelo-recovery-kit` 0.1.0, the fifth release artefact. 25 + 32 checks (the drill and runbook pages
  re-synced to the rehearsal's fixes and the licence reissue step, `9f75a7d`).
- **Keeper installer and tiers** (`17e7787`, `eb9f428`): `sigelo-spend init` sets up one keeper on the
  operator's own host and wallet-rpc (optionally writing the wallet-rpc unit, loopback, `--rpc-login`),
  `doctor` checks the install, `receipts export` and `licence show|install`. Free tier: one keeper, one
  agent, that agent's whole policy. Paid verbs — `/delegate`, `/fund`, `/approve`, a pay above
  `approval_above`, receipts export, a second `init` on the host — refuse `403 licence_required` without
  a licence; `/revoke` and `/delegates` are never gated; an expired licence stops only the paid verbs.
  **The licence is a sigelo attestation** issued by the vendor DID to the keeper's DID
  (`claims {tier, seats}`, `exp`), verified offline by the repo's own verifier; no network call anywhere;
  no wire change. No hosted mode exists or will. spend: 659 → 725 passed with the live wallet;
  pack-test 20 checks over five packages; SHA256SUMS identical across two builds.
- **A keeper's own DID is recoverable** (`164b8c4`, `cc0a83c`; closes the gap the rehearsal found).
  `sigelo-spend init` writes the keeper genesis to a public `identity.json` committing to the
  Owner's root recovery key (`k(S, "sigelo/v1/recovery/ed25519")`, the key every agent already
  uses; from the ceremony's `keeper-<j>.json` via `--keeper-package`, or `--recovery-commitment`),
  and refuses a genesis whose recovery would derive from `spend.key` or be null. After a
  compromise: `sigelo-offline recover --genesis identity.json <root> --new-keeper …` offline, then
  `sigelo-spend init --adopt recovered.json` on the new host serves the same `chain[0]` DID that
  receipts, approvals and the licence name; the thief's later voluntary rotation loses (SPEC §7).
  Proven end to end in the spend suite with ts and Go agreeing. No wire change: every genesis
  already carries a recovery commitment; which key it names is key management. Keepers keyed
  before this (the live soak's) stay legacy and unrecoverable until their next rekey. ts 620 → 628,
  spend 725 → 745.
- **The soak is a paying customer of its own keeper** (`5b4a488`): `gen-keys.mjs` mints a soak-local
  TEST VENDOR and issues `keeper/licence.json` (tier pro, 4 seats, 400 days) to the keeper's DID;
  `setup.sh` sets `SIGELO_VENDOR_DID` in a unit drop-in; `check.mjs` reports UNHEALTHY under 30 days to
  expiry. Proven in a scratch keeper: `/delegate` 200 with the licence, 403 `licence_required` without.
  The soak now exercises the paid tier end to end; a real deployment gets its licence from the vendor at D1.
- **The installed MCP plugin** (`integrations/mcp`, as installed on the maintainer's host on 09-24) was
  exercised live from a Claude Code session: `whoami` → `bundle` → `verify`, and the release
  `sigelo-verify` at c2c9cdc accepts the plugin-made bundle identically.
- **Round 3b (docs-test/RESULTS.md).** The Haiku lifecycle run repeated on the docs of `9516622`, after
  `a795275` gave QUICKSTART the exact `ed25519-test` `bind()` call, a Timestamps paragraph and the
  recovery-beats-`iat` worked example: **10/10** (7/10 two days earlier on the same task). The R3 bar
  (≥ 9/10 at Haiku tier) is met with Claude models; non-Claude families still wait on API keys.
- **`wallet_slow` (spend/, `98ea994`).** Soak tick 5: a `transfer` build took 152 s on the slow daemon link
  (decoy selection; the same delegate's next build took 9 s), the keeper's 60 s wait ran out and it
  answered the generic `wallet`; nothing was relayed — the build is `do_not_relay`, `relay_tx` is called
  only with metadata the keeper received and only after the fsynced `intent` line, and a repeat is
  answered from the log — so fail-closed held, but the code was wrong and a tick was wasted. Builds
  (`transfer`, `sweep_all`) now wait 180 s, every other call 60 s, and a build that outlives its wait
  answers `TRY LATER wallet_slow` ("the wallet is still working on that payment; nothing was sent").
  Tests: the late build is never relayed, the repeat pays once, a third run is ALREADY PAID, a
  `relay_tx` timeout stays UNCERTAIN. spend 745 → 756.
- **Contact surface (`a52163e`, `17477fb`).** `/contact` on the site (one maintainer, `contact@sigelo.io`,
  SimpleX on public relays, security reports to `/security`; no form by design), the SimpleX address as
  one constant feeding the page, `security.txt`, `index.json` and the JSON-LD `ContactPoint`, omitted
  everywhere until it is set so no placeholder ships; both mailboxes exist and are read. site 272 checks.
- **Public since 2026-10-01.** First push: `https://github.com/csigelo/sigelo`, main `bca5b16` (the export of
  `13e3b12`). `release/publish.sh` now has an **update mode** (`8a024b3`): against the pushed clone it
  builds, gates and tests the export in a temp tree and commits one `sync:` commit on top of `main`;
  fresh mode is refused on a clone with a remote. The first GitHub run failed in three places, all
  fixed from a clone of the public repository (`1bcb01f`, `0fbd592`, `1cde665`, `268111d`): two
  crosscheck result files had no final newline, which the portability line-ending check read as "no
  line ending" on every OS (the check now fails only on CRLF or mixed endings, in index or checkout);
  `pack-test.sh` honoured a runner's `XDG_CONFIG_HOME` and so looked for the identity outside its test
  home; the actions were pinned to Node 20 versions (now v7, by sha). The `DEVICE_STRINGS` identity
  gate fails loudly when the secret is missing in this repository and reports hits as file and count
  only; it is its own job so it never hides the other results. The `spend` step of the `ts` job failed
  on the runner and passes here under the same node, npm and shell; it now annotates its FAIL lines
  so the next run names the check. Second run (`648b53f`): Go and the release build green; Linux failed
  one spend test because `init --create-wallet-rpc` wrote `/usr/bin/monero-wallet-rpc` into the unit
  regardless — `init` now resolves the binary (`--wallet-rpc-bin` or PATH) and refuses without it
  (`194fd86`); on Windows the systemd-unit and POSIX-mode checks SKIP with their reason and the Go
  cross-check gets its `.exe` (the keeper is a Linux systemd service; Windows is a verifier and agent
  platform); the ts pty tests use util-linux `script`/`setsid`, else a python pty helper, else SKIP,
  and every suite's FAIL lines become annotations on every OS (`a71fb06`). Third run (`b70cc24`,
  2026-10-02): **every job green on ubuntu, macOS and Windows, Node 22 and 24**, except the identity
  gate, which waits for the repository secret.
- **sigelo.io is live** (`site/deploy/`, deployed 2026-10-01 from the export): one Let's Encrypt
  certificate for `sigelo.io`, `www`, `sigelo.net` and its `www` (the `.net` names 301 to the apex),
  nginx with the security headers, no client IPs in logs, HSTS at five minutes for the first week;
  the server is key-only SSH with root login off, fail2ban, a firewall and unattended upgrades.
- **Deploy tooling (`site/deploy/`, `ca39b0e`).** `server-setup.sh` once as root (nginx + certbot, the
  `sigelo` user, TLS 1.2+, HSTS starting at 5 minutes, CSP `default-src 'self'`, `www` → apex, no client
  IPs in logs, 7-day rotation), `deploy.sh user@host` (builds, runs the 272 checks, uploads with rsync or
  `tar | ssh`, swaps atomically, keeps `dist.prev`, `--rollback`, `--dry-run`), `check.mjs` against the
  live origin (45 checks incl. headers, content types, sha256s and the build commit), and a sudo-limited
  helper so the deploy key never installs an arbitrary nginx config. **Deploy from the public export**,
  never from the private tree: `index.json` records the build commit. Tested locally end to end through a
  fake ssh; certbot and `nginx -t` need the server.
- **Drill cadence.** The kit's `schedule.mjs` installed the quarterly reminder on the test host; the next
  drill is 2027-01-01.
- **D1, most of it decided** (`8cde486`, `f85a42a`, `724a903`): the domain is **sigelo.io**, the account
  **csigelo** (`https://github.com/csigelo/sigelo`, Go module `github.com/csigelo/sigelo/go` at export,
  MCP registry name `io.github.csigelo/sigelo`), the e-mail **contact@sigelo.io** (reports stay
  `security@sigelo.io`); the pseudonym is the handle. The site linked to `blob/master/…` while the
  export creates `main` — every repository link would have 404'd after the first push; fixed. Still
  open: the age recipient and SimpleX address for disclosure, the vendor DID ceremony for licences,
  prices and hours on the kit and keeper pages, hosting and DNS.

spend 659 → 745 passed with the live wallet. Code lines: `spend/service.ts` 1 037, `spend/cli.ts` 126,
`spend/init.ts` 494, `spend/licence.ts` 84, `ts/src/ceremony.ts` 169, `ts/src/offline.ts` 167 (CLAUDE.md).

## unreleased — 2026-09-29 (evening), round 3 on today's docs, the one-seed ceremony, Carrot, and a stranger's clone

- **Round 3 of the comprehension harness** (docs-test/RESULTS.md), docs frozen at `9dadab0`
  (`docs-test/snapshot/9dadab0`, lifecycle digest `ff3639074728bd09…`, verifier `469da8a3c59fe898…`).
  Lifecycle from the docs alone: **Sonnet 10/10**, **Haiku 7/10** (its binding was cross-signed
  but dated `now + 3600`, so §9 step 6 discarded it; and its thief's rotation carried an earlier
  `iat` than the recovery, the inverse of the task — it spaced every `iat` like a story) — the
  ≥ 9/10 Haiku bar (ROADMAP R3) is still not met. Both trace to facts the docs stated only as
  permissions in SPEC: `a795275` gives QUICKSTART the exact `ed25519-test` `bind({… addr_secret,
  iat: now})` call, a Timestamps paragraph (a future-dated binding is discarded, never pass a
  later `now`), and "recovery beats `iat`" worked at T and T+3600; ts/README's API notes say the
  same. To be re-measured at the next round. A verifier from
  SPEC and vectors alone, in Python (1 033 lines, PyNaCl + pycryptodome, Edwards arithmetic by
  hand): **139/139** on `grade-verifier.mjs` and **139/139** on `sigelo-verify --conformance
  --impl`, first iteration, no spec finding. Perl was the second candidate language and is not
  possible on the test host (no Ed25519 library, no compiler). Every run was a Claude model; the
  non-Claude runs still wait on API keys. Transcripts were audited for reads outside the allowed
  files: none.
- **M4, the human's seed (`278e87c`, `29a0402`).** `ceremony --human` writes the 25 words to
  `/dev/tty` only, after `backup.age` exists, and refuses without a terminal; `restore --words
  <file|->` takes them from a file or stdin, never the command line, and reproduces `--backup`
  byte for byte; `ceremony --import` of an existing seed is refused unless
  `--i-know-this-seed-was-cold`, with the liability printed. The backup field stays `mnemonic`
  (`sigelo-root/2` since feb7e96). "Vault only, never a hot wallet" is on every ceremony screen.
- **M6, FCMP++/Carrot (`085bf06`, ROADMAP §2).** The 25-word legacy root survives: Carrot keeps
  the `a = H_s(b)` hierarchy, subaddresses and address format for sending and receiving, the
  reference wallet still restores only legacy seeds, and no wallet-rpc method sigelo calls
  changed. Re-check when seraphis-migration#306 (the new-wallet seed format) closes, when
  `carrot_impl` merges, or when a mainnet height is set. Follow-ups applied (`ba825f3`,
  `b5eeadd`, `4daef77`, `9241e04`, `cad0357`): the wallet-rpc canary pinned version 1.30 exactly
  and so already failed on the current release 1.31 — it accepts 1.30–1.33 now, with the
  ceiling to move after an oracle run; the unused `get_tx_key: true` is gone; Polyseed is in
  monero core since 2026-09-20 (PR #10765) and is still not used (it cannot carry `S`); the
  promise reads "any Monero wallet that restores a 25-word (legacy) seed"; `get_tx_proof` is
  flagged not yet functional on the FCMP++ stressnet.
- **A stranger's clone of the public export (49c585a).** Everything ran green from the
  single-commit clone in a private network namespace: every suite, `build.sh` twice with
  identical SHA256SUMS, `pack-test.sh`, the sim (all three digests), `crosscheck/run.sh` with
  `--self-test`, QUICKSTART tiers 1 and 2, `--impl` 139/139. Fixed from its findings (`5e96d29`,
  `77a7be4`, `78878b6`, `da03f18`): every suite count in the READMEs and ROADMAP re-measured
  (conformance 242, `go test` 498, `--impl` 139, `--break` 136/139, pack-test 16 + its own build,
  ts 620, spend 659); the soak policy template held two real stagenet subaddresses and
  `ts/test/monero-vectors.json` held oracle signatures from the same wallet — placeholders now,
  filled by `gen-keys.mjs policy`, and the vectors re-signed from a scratch wallet; QUICKSTART's
  walkthrough files and `world.lock` are ignored, crosscheck runs write to an ignored
  `results/latest/`; device and desktop specifics in the docs replaced by "the test host".

ts 595 → 620, spend 652 → 659, go 498. Code lines: `ts/src/ceremony.ts` 150, `ts/src/offline.ts` 150,
`spend/service.ts` 974 (CLAUDE.md).

## unreleased — 2026-09-29, the readiness bar: six gaps closed in one day

wire: an envelope has exactly its defined keys (`bcee912`, SPEC §3.1; vectors
`attestation_good_and_envelope_extra_keys`, `binding_envelope_extra_key`,
`binding_envelope_sig_id_only_unproven`, `fatal_rotation_envelope_extra_key`;
`attestation_envelope_extra_key_int` flips from accepted to discarded). The 30-day freeze count
runs from this change.

ROADMAP §1 was re-measured against the tree (`d07f077`) and every gap that needed no Owner decision
was closed the same day, each by its own agent, each proven before its commit. One wire change (the
envelope rule above); the spend keeper's formats are unchanged; the live soak still runs 6df3b67.

- **Tokens re-read per request (spend/, `37190c5`).** The simulation's live-policy scenario showed
  `token new` printing "the old token no longer works" while the old token kept paying and the new
  one got 401 until a restart, so a leaked token outlived the command meant to kill it. The keeper
  now checks policy.json's mtime on every request and, when it changed, validates the whole file but
  takes only the token hashes of roots it already serves: the old token is refused and the new one
  pays with no restart. Everything else in the policy still needs a restart, including a new root —
  MONERO.md §6 now ends that procedure with one, and the CLI says exactly this. A malformed file, or
  one that gives two roots the same hash, keeps the last good tokens and logs a warning.
- **Envelopes have exactly their defined keys (SPEC §3.1, `bcee912`, wire).** Both verifiers accepted
  unknown keys in an envelope — outside the signature, so unauthenticated — while unknown body fields
  were refused; a third implementation could have read §3.1 either way. Now an extra key discards an
  attestation or binding and is fatal in a rotation envelope, in ts and go alike; the schemas refuse
  it and the moadim adapter stores only body and sig. The 1f916 bare-served attestation the sim
  planted is now discarded by rule, not by a hash mismatch.
- **Two behaviours named (`5cde1ac`).** A duplicated attestation counts twice (SPEC §9.1: the verifier
  reports what it was given, invariant 8, as it does for rotations); a retired world key keeps
  minting valid attestations under its old DID until they expire (SPEC §5, THREAT-MODEL §3.2).

- **Keeper daemon fallback (spend/, `e9b4970`).** `SIGELO_DAEMONS` is an ordered list of daemon
  addresses. After three wallet-rpc builds in a row with "no connection to daemon", or 20 minutes of
  a stuck height while asked to pay, the keeper calls `set_daemon` (untrusted) on the next one — never
  on one failure, never more than once a minute, one warning line and no spend.log line. With fewer
  than two addresses nothing changes. 23 tests on the fake wallet.
- **Soak alerts (`246fd66`) and the clock at boot (`4ec79b2`).** `check.mjs --notify` writes
  `soak-alerts.log` and raises a critical desktop notification when UNHEALTHY; `sigelo-soak-check.timer`
  runs it hourly. The agent unit runs `systemd-time-wait-sync` (10 s) as an `ExecCondition`, so a tick
  is skipped, not run, until NTP has set the clock — `After=time-sync.target` orders nothing in a
  `--user` unit (the keeper started at "2026-01-11" on 09-26). The keeper unit sets four stagenet
  nodes as `SIGELO_DAEMONS`. Nothing was installed or enabled on the soak host.
- **Third-party cross-check (`crosscheck/`, `0a17aa3`, T12).** JCS against the RFC 8785 reference
  (6/8 testdata byte-equal, the two float files refused as §3 requires; 20k documents, 100k integers,
  100k doubles equal; 1 800 forbidden inputs rejected), base58/addresses/25-word seeds against
  monero-python (10k/20k, 5k wallets, 2.5k subaddresses, 20k address checks, 4k/8k seeds, ts and go),
  Ed25519 against libsodium, RFC 8032, Wycheproof 151/151 and speccheck 12/12: **0 divergences**.
  `run.sh --self-test` corrupts sigelo's answers and every section catches it. monero-python itself
  departs from Monero's C++ three times (2^64 base58 block, word triples ≥ 2^32, no curve check);
  sigelo sides with the C++. Not covered: SigV2 (no oracle here).
- **Simulation gaps (`sim/`, `ecb7f17`, `4d14292`, `ddff500`).** Dishonest worlds: 400 bundles over
  36 SPEC-cited cases (future and backdated `iat`, small-order issuer keys, reused nonces, unchallenged
  and rotated-away DIDs, forged issuers, replays, a collusion ring) — ts and go agree on all 400, 13/13
  mutants killed, one (`future iat accepted`) invisible to the old swarm. Delegates of delegates to
  depth 4 with a revoked middle delegate (7/7 planted bugs caught). policy.json edited under a running
  keeper: 78/78 steps; the policy is read at start only, as documented, and two docs promised
  otherwise — `token new`'s "the old token no longer works" and MONERO.md §6's new root without a
  restart (fix below, G7). The 1f916 adapter runs as a world; serving its genesis bare again makes
  every bundle fatal in both verifiers. `npm run sim` 5 min; `npm run plants` 10 min.
- **Installable packages (`20fd24e`, `7cdf4ea`, T4 code side).** No `file:` dependency in a packed
  manifest (`release/prepack.mjs`), bins from `dist/`, LICENSE in each tarball, `SIGELO_PUBLISH=1`
  guard. `release/build.sh` builds from a clean clone of HEAD: 4 tarballs, static `sigelo-verify`
  for five targets, a Go source archive, SHA256SUMS identical across two builds.
  `release/pack-test.sh` installs them where no clone is: 17/17. Publishing waits on D1.
- **Conformance for foreign implementations (`c4cef7d`, `4e1a5aa`, T7).** `sigelo-verify
  --conformance --impl '<command>'` runs a candidate over all 135 bundle cases with
  `grade-verifier.mjs`'s protocol and exits 1 on any FAIL: Go as its own candidate 135/135, ts
  135/135, a broken wrapper 133/135. A weekly CI canary runs `spend/canary.ts` against the pinned and
  the latest monero-wallet-rpc (unrun on GitHub yet).
- **Docs measured (`d07f077`, `81a6500`, `327e266`, `7cefd5d`).** ROADMAP §1/§6 re-stated with a
  commit per claim; the 1f916 proposal says upstream's repository answers 404 and `1eedadd` came
  from public forks; THREAT-MODEL §3.7a and INCIDENT §1 cover a wrong clock and an offline host.

ts 591 → 595, go 494 → 498, spend 617 → 652 passed with the live wallet. Code lines: `ts/src/sigelo.ts` 364,
`go/sigelo.go` 383, `spend/service.ts` 975 (CLAUDE.md).

## unreleased — 2026-09-29, soak incident #4: 32 h offline, and the clock

The test host lost its network for 32 h because its network manager stopped auto-connecting
after a failed handshake and nothing could re-authorise it unattended. The keeper failed closed — nothing was sent, every line verifies — but the tooling
around it did not see the outage, and the investigation found a latent wrong-clock risk. Keeper
wire formats (receipts, spend-approvals, log lines) are unchanged; no error code was renamed.

- **Clock guard (spend/).** Every route that signs (`/pay`, `/fund`, `/delegate`, `/revoke`,
  `/approve`, `/bind`) refuses `503 clock_behind` — a TRY LATER, nothing signed, logged or sent —
  when the keeper's clock is before its build floor (2026-09-29) or more than 300 s behind the
  newest `ts` it signed in spend.log. The test host's clock boots at 2026-01 (its build epoch) until NTP; without a
  network the keeper would have signed lines with January `ts` that fall out of every cap window
  once the clock is right: spends that never counted, in a log that cannot be corrected.
- **`wallet_offline` (spend/).** A wallet-rpc "no connection to daemon" is its own TRY LATER code
  and line ("the wallet has no connection to the Monero network"), not the generic `wallet`: for
  32 h the agent could not tell the host's network from a wallet fault. relay_tx failures stay
  UNCERTAIN whatever their text.
- **Wallet store (spend/).** After every relay_tx, once the answer is sent and still in the lane,
  the keeper calls wallet-rpc `store`; a failure is a warning and never changes the verdict. The
  soak wallet file was 12 days stale (every stop a crash), so each boot rescanned for 18 minutes.
  `close()` waits for the lane.
- **Soak agent.** Snapshot timeout 30 s → 90 s (it collided with wallet-rpc's 30 s refresh-retry).
  A tick whose wallet height did not advance, or where the keeper said `wallet_offline`, is an
  outage tick: an expected-success TRY LATER there is `outage`, not MISMATCH (`outage_ticks`), and
  a carol rent given up after 3 h of nothing but outage TRY LATERs is `abandoned_offline`. The 6
  mismatches of this outage were the keeper being right.
- **Soak check.** UNHEALTHY with no payment in 2 h, a wallet height stuck across the last two
  snapshots, or a log clock in the future or stepping back — it said HEALTHY for all 32 h.
  `--evidence` checks a burnt directory without asking the live host.
- **Soak README.** Incident #4 and the wrong-clock note; the T14 rehearsal fixed where the step-0
  run found it wrong (the wallet-rpc is a systemd unit, gen-keys before setup, the vault's creation
  command and seed warning, sweep back to the allowance address after 10 confirmations, step 7
  with `--evidence`).

spend: 592 → 617 passed with the live wallet (559 → 584 + 2 skipped without it).

## unreleased — 2026-09-24, hostile-JSON differential (ts vs go)

wire: D1 nesting depth 512 (`425d2bb`), S1 `created` format (`bc7165a`), S2 canonical curve points
(`731483b`), S3 commitment format (`63cceed`), S4 nonce format (`c5faf69`), S5 noncharacters (`001ecfa`);
vectors named in each bullet below. Recorded here 2026-09-29 to satisfy VERSIONING.md §1; the 30-day
freeze count (ROADMAP R6) runs from the last of these.

A differential of 1 805 hostile documents through both verifiers found three verdict
divergences, four message-level ones, two slow paths and five gaps against SPEC. Closed here,
each in both implementations with the same reason text, a SPEC MUST and vectors:

- **D1** Nesting depth is bounded at 512 levels (SPEC §3). Go's recursive parser died of a
  fatal, uncatchable stack overflow near 750 000 levels (a 1.6 MB document), where ts,
  iterative, answered; deeper than 512 is now a parse error in both, `nesting deeper than 512
  at offset N`, and both canonicalizers refuse it. Vectors `raw_depth_512_in_claims`,
  `raw_fatal_depth_513_in_claims`.
- **D2** ts picked the latest recovery `iat` with `Math.max(...list)`, one call argument per
  valid recovery rotation; past ~125 000 of them at one node V8 threw `RangeError` (a crash
  naming no check) where Go answered VALID or `recovery tie`. A loop now, and no argument
  spread over data is left in ts/, spend/, adapters/, integrations/ or sim/ (a ts test scans
  the built verifier for one). SPEC §9: exhausting a resource is not a verdict.
- **D3** Two shipped TypeScript readers, `sim/verify-one.mjs` (the ts half of the sim's Go
  differential) and `integrations/skills-cli/sigelo/verify.mjs`, read files as `'utf8'`
  strings: invalid bytes became U+FFFD, so a bad genesis nonce verified as a different, VALID
  identity where `sigelo-verify` rejected the document. Both read bytes through `parseBytes`
  now and say `parse: …` as `sigelo-verify` does; so do `sigelo-spend pay`'s request file,
  the keeper's torn-tail repair and the ceremony restore. The swarm simulation presents
  BYTES (new tamper and fuzz kind `invalid-utf8`), so it can see this class at all.
- **P1** Base58 decoding is quadratic and ran before the 34/64-byte checks: a 300 000-character
  signature (per item) or genesis key (fatal) took 79 s in Go and over three minutes in ts.
  SPEC §2 now bounds a multibase key at 64 characters and a signature at 100, checked after
  the (linear) alphabet scan and before decoding, same reason text in both. Vectors
  `fatal_genesis_key_too_long`, `attestation_sig_too_long`.
- **S1** `created` was checked only for being a string: `23:59:60Z`, `+05:30`, `.123Z`, a
  space for `T`, `2026-13-45T25:61:61Z` and `"yesterday"` all verified. SPEC §4 now fixes
  the form (exactly `YYYY-MM-DDTHH:MM:SSZ`, a real date, no leap second) as a MUST, fatal in
  every genesis slot; the JSON Schema drops its leap second. Attestations and bindings carry
  no timestamp string (their `iat`/`exp` are integers), so there is no per-item case. Vectors
  `genesis_created_leap_day`, `fatal_genesis_created_leap_second`,
  `fatal_genesis_created_feb_29_common_year`, `fatal_issuer_created_offset`,
  `fatal_next_genesis_created_fraction`.
- **S2** Key slots were checked for the multicodec prefix and 34 bytes only: an all-zero,
  identity or `y ≥ p` key made a VALID identity or issuer no signature could ever verify
  under. SPEC §2: `key`, `recovery_key` and an `ed25519-test` `addr` MUST be a canonical point
  not of small order (Go: edwards25519 `SetBytes` + canonical re-encoding + cofactor; ts:
  noble `Point.fromBytes(…, false)` + `isSmallOrder`), fatal in a genesis or rotation, per
  item in a binding. Issuer keys are genesis keys, so they are fatal (invariant 7), not per
  item. Vectors `fatal_genesis_key_all_zero`, `fatal_issuer_key_identity`,
  `fatal_rotation_recovery_key_y_ge_p`, `binding_ed25519_test_addr_all_zero_unproven`.
- **S3** The recovery commitment was checked for its `sha256:` prefix only, so `sha256:`,
  `sha256:xyz` and UPPERCASE hex verified — the last silently disabling recovery, since no
  key's commitment is ever spelled that way. SPEC §4: exactly `sha256:` + 64 lowercase hex,
  fatal in every genesis slot. Vectors `fatal_genesis_recovery_uppercase_hex`,
  `fatal_genesis_recovery_prefix_only`.
- **S4** Nonces were any string (`"\u0000"`, emoji, U+2028, `/`, `z` + hex). SPEC §2: a
  genesis, binding or invoice nonce is `z` + 1 to 63 base58btc digits, fatal in a genesis,
  per item in a binding; the §5.2 challenge nonce stays opaque. Three spend/ test invoices
  used nonces with `I`, `O` or `l` and were respelled. Vectors `fatal_genesis_nonce_z_hex`,
  `binding_nonce_not_multibase`, `binding_nonce_65_characters`, `binding_nonce_64_characters`.
- **S5** SPEC §3.1 cites RFC 8785 and so I-JSON, which forbids noncharacters as well as lone
  surrogates, but both parsers accepted U+FFFF as a key and a value. Now a parse error in both,
  raw or escaped (an escaped pair counts), at the string's opening quote, `noncharacter U+FFFF
  in string at offset N`; both canonicalizers refuse one built in memory, so no conforming
  library signs what no conforming parser reads. The schema's `string` refuses them too.
  Vectors `raw_fatal_noncharacter_in_claims_value`, `raw_fatal_noncharacter_astral_in_claims_key`.
- **M1** Parse-error offsets differed by one between the two parsers on `bad \u escape`,
  `expected ":"`, `expected "," or "}"` and `expected "," or "]"` (ts incremented past the
  character before failing; Go peeked), though go/jcs.go claimed both said the same. Both now
  report AT the offending character, the convention the Go `fail` comment spells out; a
  nine-message table runs in both suites.

## unreleased — 2026-09-24, audit before the public export

wire: A1 two identical rotation entries are a fork (`7c285ea`, vector `fatal_duplicate_rotation_is_fork`).

Self-audit of the whole tree (AUDIT.md), three findings closed with tests and vectors:

- **A2** A document holding invalid UTF-8 was rejected whole by the Go verifier but read
  lossily by every TypeScript caller, which discarded one item and accepted the rest. New
  `parseBytes()` decodes fatally and is used at every file, body and stdin edge (CLI, mock
  world, keeper, MCP server); SPEC §3 states the rule. Same bytes, same verdict.
- **A1** Two byte-identical copies of one voluntary rotation are two candidates and REJECT
  the chain as a fork, in both verifiers. SPEC §7.3 now says so; vector
  `fatal_duplicate_rotation_is_fork`.
- **A3** The 1f916 adapter bound a DID after checking only three genesis fields; it now
  checks the full §3.1 shape and names the bad field.
- `release/publish.sh`: the public repository is a fresh single-commit export (pseudonym,
  UTC, identity-string gate, every suite run inside the export), not a rewritten history.
- **A4** The export's identity-string gate silently passed on busybox: GNU-only `grep`
  flags made grep exit 2 and the script read the swallowed error as "no hits". It is now
  `git grep` over HEAD with exit 0/1/other handled explicitly; the CI check excludes
  `release/publish.sh` as it excludes its own file; ROADMAP §5.1 no longer spells the
  strings the gate looks for.
- spend/soak: `gen-keys.mjs` passes nonces as bytes (the hex strings it used to pass were stored
  verbatim, a genesis the SPEC §2 nonce rule now rejects); a `compat <dir>` mode, run by `setup.sh`
  before any file is copied, refuses to redeploy over a live soak this code's verifier would not
  accept; an existing `keys/approver.json` is never overwritten. Soak incident #3 (near miss).
- **A5** The gate's own files still spelled three "generic" patterns and excluded themselves
  from the search, so the first export published exactly the strings it guarded. No tracked
  file holds a pattern now: all come from the
  `DEVICE_STRINGS` secret / private pattern file, an empty list refuses to export, nothing is
  excluded. ROADMAP §5.1 no longer describes the maintainer's setup.
- PORTABILITY.md: what is proven, documented and unrun across operating systems.

## unreleased (still wire `sigelo/0`) — 2026-09-17

Spec gaps found on first independent review, all closed with vectors.

- Bundles carry `issuers` (bare genesis documents) so attestations from unknown worlds
  verify offline. Previously §9 asked for a genesis the bundle had no slot for.
- Chain walk rejects cycles (`next` already in chain) and self-rotations. A naive walk
  looped forever on a rotation back to an earlier DID.
- New vector `rotation_hostile_carried`: a fully valid voluntary rotation defeated *only*
  by recovery precedence. The old hostile vector also failed the commitment rule, so a
  verifier without precedence still passed. `chain_precedence_only` isolates it.
- JCS done properly (`py/jcs.py`): UTF-16 key order, ES6 escape set, duplicate keys
  rejected, non-integer literals rejected at parse. Vector `attestation_unicode` carries the
  exact canonical string. The old `json.dumps(sort_keys=True)` mis-sorted non-BMP keys.
- §9 takes `now` as input and returns a specified result shape (§9.1). Vector `bundle`
  fixes the expected result for a full bundle, including per-item rejections.
- Binding proof status is three-valued: `proven`, `unproven`, `unsupported`. Bad proof is
  discarded, not downgraded. `admission` restricted to the six defined values.
- THREAT-MODEL §4 citation corrected against the Reuters story (2026-09-04): OpenAI agents,
  DseWiki, 15,000+ edits; the "propagates to later agents" clause was not in the source and
  was replaced with what the researchers actually observed.
- §5.2 fixes the proof-of-control handshake (`typ: "challenge"`) so worlds interoperate on
  the one step they all need. Vector `challenge`.
- Round 2, after a from-spec-only implementation test: §3.1 normative field table with a
  no-unknown-keys rule; §7.4 separates "not a candidate" from "REJECT the chain" with a
  per-failure table; §7.3 rejects two recoveries tied on `iat`; §2 states the signature
  and DID encodings that were only inferable from examples; the signing prefix is given
  as bytes; §9.1 key order is informative. The four "not a candidate" negatives ship
  complete envelopes and state the resulting chain. New: `bundle_minimal`, a second
  issuer in `bundle`, `rotation_bad_sig`, `unknown_field_*`.
- QUICKSTART.md and examples/world.mjs, after three fresh-agent adoption runs.
- Monero: MONERO.md design; §6.2 rewritten with the real SigV2 construction and the view-mode
  binding; the "view key for a single subaddress" claim was wrong (Monero has one view key
  per wallet) and is replaced by proofs and per-relationship wallets. `method: "monero"`
  bindings verify in ts/ and py/ against vectors from Monero core, cross-checked with
  monero-wallet-rpc 0.18.5.0.
- §6.3 invoices: a new signed object naming where to pay *this time*, under the identity key,
  never in a bundle. `{ v, typ, did, method, addr, iat, exp, nonce }` plus optional `amount`
  (a string of atomic units) and `memo`. A `structure()` slot in both implementations, not a
  sixth constructor. Vector `invoice`.
- Root-seed derivation (`ts/src/keys.ts`): one 32-byte `S`, HKDF paths for identity, recovery
  and each Monero wallet (MONERO.md §2), carried by a 24-word BIP-39 mnemonic that is
  transport for `S` only and is **not** a Monero seed. `sigelo-offline new|derive`
  (`ts/src/offline.ts`) is the air-gapped box's whole job and withholds the treasury spend key
  and the recovery secret unless `--reveal-all`. Interop is tested live: a derived wallet is
  imported into a stock `monero-wallet-rpc` by private spend key and the stock wallet
  reproduces our address, view key, spend key and subaddresses.
- `py/monero.py`: the Python half of §6.2 — Keccak-256, edwards25519 group ops, Monero base58,
  addresses, subaddresses and SigV2 — so `py/reference.py` verifies `method: "monero"`
  bindings and the two implementations agree on them.
- `sigelo-spend` (`spend/`): the MONERO.md §4 policy service. Loopback HTTP, bearer token,
  allowlist by literal address or by DID-with-attestation (bundle verified offline, address
  must be a `proven` binding or a §6.3 invoice), per-transaction cap, per-period budget, rate
  limit, buckets pinned to Monero *accounts*, `unlock_time` forced to 0, and an append-only
  log of receipts signed by the service's own sigelo identity. In CI; the live-wallet section
  SKIPs there.
- `adapters/moadim`: Monero commands `wallet-set`, `bind`, `receive`, `invoice` and
  `verify-invoice`, in their own file so the identity core stays at 77 lines. The agent holds
  `(a, B)` and can never spend; `bind` computes the view-mode `sig_addr` locally, with no
  wallet and no daemon.
- `sigelo-spend` spent real coins end to end on stagenet (2026-09-23): 5e8 atomic units from
  account 0 to the wallet's own subaddress (0,1), fee 30500000, txid
  `2582d050b5ca46ae4901317d85ce60511c962aaebce16af60b2aa526367fe63d`; over-cap request refused 403 `per_tx_max`, receipt verifies under the service key,
  `/budget` accounted it. `spend/test.ts` §3 now pays from the funded account (largest
  `unlocked_balance`) instead of the fixture's empty account 1, still `--dry-run` only.
- Vectors: 18 positive groups, 27 negative cases (`vectors` holds 19 entries — the extra one,
  `expected_chain`, is a shared expectation, not a vector).
- §3.1 field types, enforced by `structure()` in both implementations: `iat`/`exp` are
  integers in [0, 2^53−1] with `exp` > `iat`; every other field is a string except `recovery`,
  `claims`, `amount` and the bundle's own fields. The two verifiers disagreed on identically
  signed bindings: `iat: "5"` or `null` verified `proven` in TS (comparison coercion) and raised
  TypeError in Python, killing the bundle; an `addr` array of characters verified `proven` in
  Python only. Envelope junk (a `null` binding entry crashed TS; non-dict entries crashed
  Python; a non-string rotation `sig` was fatal in TS but ignored in Python) now has one outcome.
- JCS: a lone surrogate is rejected by both canonicalizers (RFC 8785 requires I-JSON; TS used to
  sign it as U+FFFD, so two bodies shared a signing input). The key `__proto__` is rejected by
  both strict parsers and both canonicalizers: `ts/src/jcs.ts` assigned it, which swapped the
  parsed object's prototype instead of adding a key. The TS parser now defines properties.
- §6.2: a Monero address whose prefix is a non-minimal varint (`92 00` for 18) is refused by
  both `decodeAddress` implementations, as wallet2's `read_varint` does (`EVARINT_REPRESENT`,
  src/common/varint.h). Monero base58 decoding accepts only strings.
- Vectors: 13 new negative cases (40 total), among them `parity`, 48 malformed bundles that
  both verifiers must take to the same result or the same rejection. At b348b5d, 20 of the 60
  §3.1 and parity checks diverged between the implementations and 17 crashed one of them.
- `sigelo-spend` (MONERO.md §4), after independent review: **two-phase relay** —
  `transfer` with `do_not_relay`/`get_tx_metadata`, caps checked, every line signed, an fsynced
  `intent` line, then `relay_tx`, then `relayed` or `relay_failed` (still debited: the daemon
  may have taken it). Money could previously move with no log line: a `to.did` that could not
  be signed threw after the wallet paid (5 requests → 5 transfers, 0 lines), as did a slow or
  non-JSON wallet reply. **Caps count amount + fee** (1-atomic payments at a 3e7 fee drained
  ~8.6e10/day against a 1000 cap). `to` takes only `{addr, did, bundle, invoice}` with a string
  `did`, own properties only; `purpose` ≤ 200 characters. **Dry runs sign nothing** — no
  receipt, `dry_run: true`, rate-limited, no budget. Invoices go through `structure()`, must
  name a subaddress, are paid exactly their `amount`, and once (nonce logged). `status` is
  inside the signed entry; lines without one are read as legacy `relayed`.
- moadim sidecar: `bind`, `wallet-set`, `rotate`, `add-issuer` and `add-attestation` take the
  lock `receive` takes; a `bind` interleaved with a `receive` wrote the old counter back and
  the same subaddress was handed out twice. `verifyInvoice` refuses a non-subaddress `addr`.
- §9 step 2 / invariant 7: a non-integer number, lone surrogate or `"__proto__"` key inside ONE
  attestation or binding (body or envelope) now discards that item and counts it; before, both
  verifiers canonicalized the whole bundle first and rejected it outright. The bundle-level
  check covers only what defines the identity (shape, genesis, rotations, issuers), where the
  same fault stays fatal. `parity` +6: `binding_iat_float` flips to discarded; good+float
  binding, float `sig_addr`, good+`__proto__` and good+lone-surrogate attestations (the latter
  as `raw` text), and fatal float in a rotation body and in an issuer genesis.
- Vector generator ported to TypeScript (`ts/src/gen_vectors.ts`, `npm run gen`), step 1 of
  replacing Python with Go as the second verifier. It reproduces `test-vectors.json`
  byte-for-byte; CI now regenerates with both generators and diffs each against the committed
  file. What a further port must match: insertion key order (`{...x, k: v}` keeps `k` in
  place), `monero_spend_seed` after `negative`, `JSON.stringify(…, null, 2)` with no trailing
  newline, and lone-surrogate `raw` text as compact ASCII-only JSON with lowercase `\uXXXX`.
  The generator refuses integer-like keys, which JavaScript would silently reorder.
- `ts/src/test.ts`: a slow `monero-wallet-rpc` (fetch `TimeoutError`) mid-interop is a SKIP,
  not an uncaught exception.
- `go/`: step 2 of that move, the §9 verifier in Go (`Verify`, `Structure`, JCS parser and
  canonicalizer, §6.2 Monero, and a static `sigelo-verify` CLI). It has one dependency,
  `filippo.io/edwards25519`; Keccak-256 is ported rather than taken from x/crypto.
  `go test` runs every check `py/reference.py` runs, with identical PASS names (185 lines,
  diffed), plus JCS, json/v2, Ed25519 edge-case and 1f916-fixture tests. CI job `go` runs it
  next to the Python job. A differential against `ts/dist` gave byte-identical outcomes:
  §9.1 JSON or the exact rejection message, over 71 vector bundles × {strict text, parsed
  value} and 3,000 seeded random mutations. Two edge cases are deliberate. Ed25519 is verified
  with @noble's `zip215: false` strictness, not `crypto/ed25519`'s: canonical A/R, no
  small-order A, cofactored. Parse-error offsets count UTF-16 units, as ts/ does.
  `encoding/json/v2` is not used: it fails the whole document on a lone surrogate, where §9
  step 2 discards only the item carrying it.
- Step 3, the move is done: the Python implementation is removed. `go/` is the reference
  verifier (217 checks, `ALL PASS`), `ts/src/gen_vectors.ts` is the only vector generator and
  CI still diffs its output against `test-vectors.json` byte-for-byte. The 1f916 adapter's
  cross-check (was `adapters/1f916/check.py`) is `Test1f916` in `go/sigelo_test.go`, over the
  same `sample-bundle.json`, now also asserting the claim names and integer counts check.py
  asserted. The moadim adapter's test re-verifies its bundle with `go/cmd/sigelo-verify`
  instead of Python (SKIPs without `go`; CI installs Go in that job and fails if it skipped).
  CI has two jobs, `ts` and `go`; nothing needs a Python interpreter.
- Go-port review, three findings, fixed in ts/ and go/ with vectors. (1) Monero points are
  decoded as Monero decodes them: `ge_frombytes_vartime` (src/crypto/crypto-ops.c) refuses
  y >= p and x = 0 with the sign bit set, and `get_account_address_from_str` runs `check_key`
  on both address keys. Both decoders had been permissive (noble `zip215: true`,
  edwards25519 `SetBytes`), and in spend mode the view key is only hashed, so an address Monero
  refuses could carry a `proven` binding. Now strict everywhere a point is decoded (address
  keys, `check_signature`'s key, subaddress derivation); §6.2 says so. Vectors
  `binding_monero_view_key_y_ge_p`, `binding_monero_spend_key_x0_signbit`: genuine signatures,
  discarded. (2) Whole-envelope canonicalization is pinned: parity
  `binding_envelope_float_unsupported_method` (`sig_addr: 1.5` on a method nothing verifies)
  and `attestation_envelope_extra_key_float` are discarded; `attestation_envelope_extra_key_int`
  pins that an extra envelope key is otherwise ignored. A body-only canonicalizer fails exactly
  those two in both test suites. (3) The strict parser no longer rejects a whole text over one
  number: a non-integer or out-of-range literal parses to a value (ts `RawNumber`, go `Number`)
  that canonicalization refuses, so it is per-item like the same value arriving as an object;
  duplicate keys and `__proto__` stay fatal to the text (§3). `raw` parity vectors
  `raw_binding_good_and_float`, `raw_attestation_good_and_int_out_of_range` (per-item),
  `raw_fatal_rotation_iat_float`, `raw_fatal_attestation_duplicate_key` (fatal). ts 284 checks,
  go 236; differential 159/160 over vector bundles (the one difference is the harness's
  `JSON.parse` path on the duplicate-key text) and 6000/6000 over the 3,000 mutations.
- MONERO.md §8 G4, keeper roots (`ts/src/keys.ts`): `keeperRoot(S, j)` =
  `k(S, "sigelo/v1/keeper/<j>")` and `agentIdentitySeed(K, i, n)` =
  `k(K, "sigelo/v1/identity/<i>/ed25519/<n>")`, same HKDF and path conventions as the
  existing branches; indices are safe non-negative integers, printed decimal. `deriveRoot`
  takes `keepers = 1` and returns `keepers: [K_0 …]`; every other output is unchanged
  (`test-vectors.json` regenerates identically, the stock-wallet interop still passes).
  `sigelo-offline derive` hands `K_0` to the operator (the agents' keeper, §2 table), so a
  restore by `derive` recovers it. Fixed vectors over the test root S1 for `K_0`, `K_1`,
  agent `(0,0)` and `(1,0)`, cross-checked against an independent HKDF; ts 291 checks.
- `sigelo-spend`, MONERO.md §8 **G1 — per-agent entries**. The policy's `buckets` become
  `agents`: each entry holds its own `token_hash`, account, caps and `allow`. A token maps to
  its agent by comparing it against every agent's hash with no early exit; unknown and revoked
  tokens get the same answer. The account always comes from the entry; a request's `bucket`,
  still accepted, must name the token's own agent. New destination `{label}` resolves only
  against the agent's own allowlist; new rule `{issuer, ctx?}` admits any DID holding that
  attestation, under the same binding-or-invoice rule. `/budget`, `/log` and `/health` answer
  for the caller's agent only (`/health` gives its account balance, not the wallet's).
  Validation moved to `policy.ts` `parsePolicy` and is now strict at every level (unknown
  fields; shared accounts or token hashes; literals not payable on `net`; a non-null
  `approval_above`, refused until G6 enforces it). Pre-G1 files load as one agent named after
  their one bucket; a file with several buckets under one token is refused. Log lines now
  carry `request.agent`; older `request.bucket` lines still replay. `sigelo-spend token new
  <policy> <agent>`.
- `sigelo-spend`, **G2 — `ref` idempotency** (§4.1 step 4, §4.2). Every spend has a `ref`: the
  one sent, or `sha256(account ‖ JCS({to, amount, purpose}))` with `to` taken without its
  bundle. `ref` and the request fingerprint are logged per agent. Within `dedupe_seconds`
  (default 600) a repeat gets the first outcome back from the log and builds nothing: the
  same receipt for `relayed` (`already_paid: true`), the same UNCERTAIN for `relay_failed` or for
  an intent whose outcome a crash never wrote, and `202 approval_needed` for `pending`
  (a status no G1/G2 code writes; it debits nothing). An explicit `ref` reused for a different
  request is `409`. Five existing checks sent identical bodies to test budgets, rate and
  invoice replay; they now vary `purpose` so each is still a separate payment. `spend/` checks:
  148 → 227.
- `go/keys.go`: MONERO.md §2 key derivation in Go, mirroring `ts/src/keys.ts` so a Go keeper
  derives the same keys without ts: `K` (HKDF-SHA256, empty salt, path as `info`, stdlib
  `crypto/hkdf`), `IdentitySeed`, `KeeperRoot`, `AgentIdentitySeed`, `RecoverySeed`,
  `RecoveryPublicKey`, `RecoveryCommitment`, `WalletFromRoot` (sc_reduce32 branch) and
  `DeriveIdentity` (a reproducible genesis from explicit `created`/`nonce`). Indices are
  `uint64` capped at 2^53−1 with ts's error strings. `go/keys_test.go` pins ts's fixed
  keeper/agent vectors and the identity key, DID, recovery commitment and stagenet/mainnet
  wallet keys and addresses that ts derives from S1. No new dependency. Go checks: 236 → 262.
- MONERO.md §8 **G7 — the root ceremony** (§4.5). `sigelo-offline ceremony --net <net>
  --recipient <age1…> --out <dir> [--keepers N] [--treasury-keeper j]` generates `S`, derives
  with `deriveRoot`, and writes `backup.age` (age to the Owner over the §4.5 JSON: `v`,
  `mnemonic`, `created`, `keepers`, `public`), `fingerprint.txt` (`JCS(public)`, `public` =
  treasury and allowance addresses and the recovery commitment) and a 0600 `keeper-<j>.json`
  per keeper (`K_j`, net, keeper identity public key, recovery commitment; keeper 0 adds the
  allowance wallet and the root identity seed; `--treasury-keeper` adds the treasury wallet).
  `S`, the mnemonic and the recovery secret appear nowhere but inside `backup.age`. age is a
  shelled-out `age`/`rage` (no npm dependency), injectable in `src/ceremony.ts`; missing
  binary or a bad recipient exits 2 and writes nothing. `sigelo-offline restore --backup
  --identity --net [--reveal-all]` decrypts, re-derives, refuses on a fingerprint mismatch,
  and prints the fingerprint and each `K_j`. `derive` output renamed to the keeper vocabulary:
  `operator` → `agents_keeper` (inner field names unchanged), `air_gapped` → `owner_backup`;
  new `keepers` list and `--keepers N`; `agent.treasury` unchanged for `sigelo-agent
  wallet-set`. Keeper packages are plaintext 0600 on the ceremony host, not encrypted per
  keeper host as §4.5 step 5 has it. ts checks: 291 → 313 (four of them with the real `age`
  binary, SKIP without it).
- MONERO.md §8 **G3 — the agent surface** (§4.2), in `spend/`. Routes, all behind the agent's
  token and answering for its own account only: `GET /balance` (`get_balance` on the account +
  what the policy still allows), `POST /receive {purpose?}` (`create_address` on the account,
  labelled with the purpose, rate-limited in memory by `rate_per_minute`), `GET /history?n=`
  (the agent's log, one entry per payment, + `get_transfers` `in`/`pool` pinned to the
  account), `POST /bind {body}` (the keeper's view-mode `sign` at (0,0) over a binding body
  that passes `structure(body, 'binding')`, names the agent's registered `did` — new optional,
  unique per-agent policy field — and the wallet's base address, with a window ≤ 30 days; the
  signature is verified as view-mode before it is returned). Every error now carries `code`
  (the refusing check) and cap refusals `facts` (`affordable` returns them). New
  `spend/wallet.ts`, bin `sigelo-wallet`: `balance`, `receive [note]`, `pay <to> <amount>
  [purpose] [--ref R] [--atomic]`, `history [n]`, `--json`; XMR↔atomic by string arithmetic
  (≤ 12 decimals, no sign/exponent/blank/leading zero); one line per verb; the message table
  and exit codes 0–4 in `spend/README.md`, with the weak-agent prompt snippet matched to the
  CLI. Departures from §4.2: `receive` mints a subaddress but no invoice (no amount, no
  `SIGELO_IDENTITY`); the command is `sigelo-wallet`, not `wallet`; the snippet says "within
  10 minutes". `spend/` checks: 227 → 324 (5 of them against the live stagenet wallet,
  read-only and a view-mode `sign`; nothing relayed, no `create_address`).
- MONERO.md §8 **G5 — delegation** (§4.3), in `spend/`. New `spend/tree.ts` (pure): the tree
  is replayed from signed `delegate`/`revoke` lines in `spend.log` on top of `policy.json`'s
  agents (the roots; `policy.json` stays the Owner's file); a delegate's caps are refused above
  its delegator's at creation and clamped to the minimum along its ancestors at every spend,
  `period_seconds` is the root's, `allow` keeps only rules every ancestor still covers;
  revoke cascades to the subtree and is idempotent; account indices and names are never
  reused; a delegate whose root left `policy.json` is orphaned (dead). Count rule:
  `max_delegates` bounds the whole subtree — each live child reserves 1 + its own, a child's
  is at most its parent's − 1. Routes: `POST /delegate {name, fund, caps?, allow?}`
  (`create_account`, skipping held indices; identity `agentIdentitySeed(K, i, 0)` with the new
  optional policy field `recovery_commitment`; a token returned once, its hash in the signed
  line; `fund` > 0 is a transfer to the delegate's (i, 0) through the ordinary two-phase `/pay`
  path, counted against the delegator), `POST /fund {name, amount, ref?}`, `POST /revoke
  {name}` (signed line, subtree's tokens dead at once, then `sweep_all {address, account_index,
  subaddr_indices_all: true, priority, unlock_time: 0, do_not_relay: true, get_tx_metadata:
  true}` per account to the revoker's (r, 0), dust (amount ≤ fee) and locked balances skipped,
  intent/relayed lines per sweep tx), `GET /delegates`. `spend.key` is now documented as the
  keeper root `K` (the ceremony's `keeper_root_hex`): the keeper signs with `identitySeed(K,
  0)` as before, delegates derive from the same `K`; tree lines must verify under that key or
  the service does not start. `sigelo-wallet delegate <name> <fund> [--per-tx X] [--per-day Y]
  [--allow label=addr ...] [--max-delegates N]`, `fund`, `revoke`, `delegates` — not in the
  weak-agent snippet (§9 decision 9); `delegate` prints the URL and token once under "Give this
  to the delegate, it is shown once:". Departures from §4.3: no `approval_above` in the ask
  (G6); the keeper does not cross-sign the delegate's binding at creation (the delegate calls
  `POST /bind`, which now works for it); the credentials are the HTTP answer / CLI output, not
  a 0600 file; the Owner revokes through a root's token (no keeper-host admin command); `/fund`
  only by the direct delegator. `spend/` checks: 324 → 413 (88 new), all passing with the stagenet
  wallet reachable. `create_account` and
  `sweep_all` have not been run against a real wallet (G8).
- MONERO.md §8 **G6 — approvals** (§4.1 step 8, "The spend-approval"), in `spend/`. New
  `spend/approval.ts` (pure): the closed `spend-approval` body `{v, typ, keeper, net, agent,
  ref, to, amount, purpose, nonce, iat, exp}`, signed by an approver over `"sigelo\n" ‖
  JCS(body)`, and its checks in §4.1's order — fields and `typ`, this keeper's DID and net,
  `iat ≤ now < exp` and `exp − iat ≤ max_approval_ttl`, the approver's bundle verified offline
  with its current DID in `approvers`, the signature under that DID's current key, the body
  equal field for field to the keeper-signed pending request with that nonce, not the agent
  (by DID, by the approver's chain, or by the agent's key under another DID) and not the
  keeper, the nonce neither approved nor spent. A `/pay` above `approval_above` (amount alone,
  after caps and rate, before any wallet call) gets `202 approval_needed` with the body and
  writes a signed `pending` line (no debit, one rate tick); `POST /approve {body, sig, bundle}`
  (no token) writes a signed `approved` line; the agent's re-run of the same pay goes through
  every check again and the two-phase relay, and its intent line names the nonce in
  `request.approval`, which spends it — a further run is the ordinary `ALREADY PAID`. Pending
  and approved lines answer until the request's `exp`, not `dedupe_seconds`; an expired
  request frees the ref for a fresh one with a new nonce; an approved line counts only if it
  verifies under the keeper key. Policy: `approval_above` is an atomic-unit string or null
  (the G1 "refused at load" placeholder is gone); set, it needs the agent's `did` and a new
  optional `genesis` field that hashes to it, and a non-empty `approvers`; approvers must be
  DIDs, unique, and not an agent's own; `max_approval_ttl` defaults to 3600. Delegates:
  `approval_above` in delegate lines may be a string, `/delegate` takes `caps.approval_above`
  (refused above the delegator's), and the effective threshold is the lowest along the
  ancestors. The keeper's DID is now stable across restarts (genesis nonce from its key,
  `created` pinned, as SPEC §3.1 allows) because approvals name it. `sigelo-spend
  approve-request <policy> <ref>` prints the body to sign; the approver signs with its own
  tooling and posts to `/approve`. Departures from §4.1: `nonce` added to the body (single use
  checkable from the log, and an old signature cannot answer a later request for the same
  ref); the approver must sign the keeper's body exactly (it cannot choose its own `iat`/`exp`);
  root agents with a threshold must carry `genesis`. `spend/` checks: 413 → 487, all passing
  with the stagenet wallet reachable. Not run against a real wallet (G8).
- SPEC §6.2 (Owner decision 2026-09-23): a `method: "monero"` binding's `addr` may be a
  **subaddress** as well as a standard address; **integrated** stays refused (verified live:
  a base-address signature verifies for the integrated spelling, and 0.18.5 still makes them)
  and so does SigV1. A subaddress is checked against its own `(D, C)`, the keys wallet2::sign's
  subaddress branch signs with (`b + m` spend, `a·(b + m)` view), and is `proven` in either
  mode; for a subaddress, view mode does not imply a view-only signer. ts and go
  `verifySigeloMoneroSigAddr` refuse only `kind == integrated` now. Vectors: the negative
  `binding_monero_subaddress_addr` is retargeted into positives `binding_monero_subaddress_spend`
  and `binding_monero_subaddress_view` (both `proven`), plus the negative
  `binding_monero_subaddress_base_sig` (subaddress `addr`, signature by the base keys:
  discarded). `ts/test/monero-vectors.json` gains `wallet_rpc_oracle`: a live stagenet
  monero-wallet-rpc's stateless `verify` on those vectors (stagenet spellings) and its own
  `sign` at (0,0)/(0,1) in both modes — all nine agree with ours. MONERO.md §3/§4.2: `/bind`
  still signs the keeper's base address (no spend/ change); an account's `(i, 0)` is now
  bindable by spec. The moadim `wallet-set` error no longer says the spec forbids subaddresses.
  ts checks: 313 → 329; Go checks: 262 → 278.

- spend/ `POST /bind` signs at the caller's OWN account address `(i, 0)` (SPEC §6.2 accepts
  subaddress bindings): `addr` must be `get_address {account_index: i}` — the keeper's base
  address is refused for any agent above account 0 — and the keeper calls `sign` with
  `account_index: i, address_index: 0`, spend mode for `i > 0` (a subaddress's view
  signature needs the spend key anyway, secret a·(b + m), so view mode would claim less without
  protecting anything), view mode at (0,0) for account 0 as before. The result is checked for
  that mode by that address before it leaves; the answer adds `account` and `mode`. A delegate
  binds the DID from its `delegate` line. Also: `/delegate`'s `fund` object no longer lets the
  spend body's `status` string overwrite the HTTP status (a funding that waited for approval
  read `status: "approval_needed"`, never 202). The mock wallet now signs as wallet2 does at
  any (major, minor). Tests: mock bind at (1,0) spend + (0,0) view, cross-account and
  base-address refusals, wrong-mode 502s, a delegate's bind `proven`; live: a spend-mode `sign`
  at an existing account `(i, 0)` (SKIP until the wallet has one). spend/ 487 → 499 checks (496 + 1 SKIP while the wallet has no account above 0).
- G8 (MONERO.md §8): stagenet end to end through spend/dist and `sigelo-wallet` — delegate,
  approval-gated funding, pay / ALREADY PAID, an above-threshold pay waiting for and using one
  approval, a delegate's `(1, 0)` binding, revoke with a real `sweep_all`. Script outside the
  suite; txids in MONERO.md §8.
- spend/ review 2 (MONERO.md §4.1, §4.2, §4.3). **The lane could freeze**: `/pay`, `/approve`,
  `/delegate`, `/fund` and `/revoke` queued first and read their body only at the front of the
  queue, and the body read settled only on `end`/`error` — a client that went away while queued
  (a half-sent body, or `sigelo-wallet`'s own timeout behind a slow wallet build) never fired
  either, and every later spend waited forever. Now the body is read whole before the request
  joins the lane (1 MB → 413, 10 s → 408, a gone client settles it too), and a queued request
  whose client has left is dropped at its turn with no wallet call and no log line. **Names**: a
  root the Owner removed kept its log lines but freed its name, so a delegate given that name
  read its `/log`, `/history` and `/budget` and answered its refs; every name spend.log names is
  now taken, and an agent in `policy.json` whose name the log shows on another account refuses
  the start. **One keeper per directory**: `spend.lock` (O_EXCL, pid) next to `spend.log`; a
  second start is refused while the pid is alive, a dead pid's lock is taken over, a reused pid
  is removed by hand (README). **Stale waits**: a pending or approved line is judged by the
  current policy — threshold off or raised → it pays (an approval on file is still spent);
  approval by an approver since removed → a fresh 202 with a new nonce instead of a 403 until
  `exp`. **CLI**: nothing from an invoice file or `history` is printed raw (addresses and names in
  their own shapes, free text as printable ASCII, else a JSON string with C1/bidi escaped too;
  `--json` as well), so a crafted invoice cannot print a second line; a `pay`/`fund` timeout is
  ``UNCERTAIN … Run `sigelo-wallet history` before paying again.`` (exit 4), not TRY LATER;
  locked change still in the pool says "a payment is still confirming … about 20 minutes"; the
  locked-sweep line is one sentence. Also: a delegate's own `approval_above` is refused while the
  policy lists no approvers; self-approval is refused for any key in the approver's verified
  chain, not only its current one (the requester's own rotated key stays unknowable to the
  keeper — documented). `SIGELO_WALLET_TIMEOUT_MS` and `ServeOptions.bodyTimeoutMs` for tests.
  Three checks that planted an unsigned `pending` line under a policy without `approval_above`
  now expect the payment (G2) or use an agent that really needs approval (G3). spend/ checks:
  499 → 529, all passing with the stagenet wallet reachable.

- **The root is a Monero 25-word seed** (Owner decision; MONERO.md §2, §4.5). `S` is carried
  as Monero's Electrum-style English mnemonic (`src/mnemonics/electrum-words.cpp` at monero
  `d02c7c57`: 4 LE bytes → 3 of 1626 words, 25th word = CRC-32 of the 3-letter prefixes mod 24),
  replacing the 24-word BIP-39 transport (`ts/src/bip39-english.ts` removed; wordlist now
  `ts/src/monero-words.ts` / `go/monero_words.go`, SHA-256 pinned). Its own wallet, the
  **vault** (`b = sc_reduce32(S)`, `a = H_s(b)`), restores from the 25 words in any stock
  Monero wallet; it is the Owner's cold wallet and **never loaded by a keeper** — no keeper
  package carries a vault key (tested). Every derivation is unchanged: `treasury`, `allowance`,
  keeper roots, identities and recovery stay HKDF over `S`, so `test-vectors.json` and every
  existing key vector are byte-identical. `S` must be canonical (`0 < S < l`): past `l` a
  wallet shows back `sc_reduce32(S)`'s words, which sigelo would read as another root — so
  `newRoot` draws from `[1, l)` and words, hex and the ceremony refuse anything else.
  ts: `newRoot()` returns 25 words; `rootFromMnemonic`, `mnemonicFromRoot`,
  `encodeMoneroWords`/`decodeMoneroWords`, `vaultFromRoot`; `deriveRoot` gains `vault`.
  Go: `RootFromMnemonic`, `MnemonicFromRoot`, `EncodeMoneroWords`/`DecodeMoneroWords`,
  `VaultFromRoot`. `sigelo-offline new [--net]` prints 25 words and the vault address;
  `derive <25 words|hex>`; `derive`/`restore` print the vault address, its keys only under
  `--reveal-all` (`owner_backup.vault`); the ceremony backup is `sigelo-root/2` (`mnemonic` =
  25 words; fingerprint unchanged) and `restore` refuses `sigelo-root/1` by name. Three fixed
  vectors (V1 hashed, V2 = 2^252−1, V3 = l−1) and a 64-root sweep digest pinned in both
  implementations; oracle: `monero-wallet-rpc` 0.18.5 `restore_deterministic_wallet` from our
  words returns our address, `b`, `a` and our words (stagenet in the suite; mainnet once by
  hand), `create_wallet`'s words round-trip through ours, non-canonical words restore to a
  wallet showing other words, and wallet2 refuses the past-2³² triple and a wrong checksum word
  as we do. ts checks: 329 → 355; Go checks: 278 → 295.
- Keeper API made consistent (found writing `spend/openapi.yaml`; code fixed, README and
  openapi now agree with it). `POST /delegate`'s funding outcome is `fund: {http, …body}`: the
  HTTP status no longer overwrites the body's `status`, so a funding above `approval_above`
  now reads `{http: 202, status: "approval_needed", code: "approval", …}` (`sigelo-wallet
  delegate` now reads `fund.http`; it says NOT FUNDED — WAITING FOR APPROVAL, exit 3). `GET /health` checks the wallet's reply — a missing height or a
  balance that is not atomic units is `502` `code: wallet`, never `"undefined"`. A missing,
  unknown or revoked token is `401` `code: token` on every route, `/pay` included (was `403`
  there). Every error body has a `code`: `/health`'s 502 (`wallet`) and the catch-all 500
  (`internal`) gained one. README: the route shapes (`/history` `{agent, account, entries}`,
  `/bind` `{addr, account, mode, sig_addr}`, `/delegate` `caps.approval_above`, `/budget`,
  `/health`), the two 202 shapes (fresh: `error`; replay: `repeat`, `pending`) and
  `/approve`'s 400/408/413/500 codes. spend checks: 561 → 564.
- Dependencies pinned per VERSIONING.md §6, with no version change: exact versions in
  `ts/`, `spend/` and `adapters/moadim/` (`@noble/ed25519` 3.2.0, `@noble/hashes` 2.4.0,
  `typescript` 5.9.3, `@types/node` 24.13.5), lockfiles regenerated
  (`npm install --package-lock-only`: only the declared ranges and stale `bin` metadata
  changed, every resolved version and integrity is the same); `go/go.mod` gains
  `toolchain go1.27.1`; every GitHub Action in `conformance.yml` is pinned to a full commit
  SHA with its tag in a comment (checkout and setup-node v4 → v4.4.0, setup-go v5 → v5.6.0,
  upload-artifact v4 → v4.6.2: what those major tags pointed at on 2026-09-23).
- Docs closed for the three gaps round 3's docs-only Haiku run exposed (docs-test/RESULTS.md,
  5/10), no code or wire change. QUICKSTART: the mock world is a program run from the repo
  root, with its two commands, what each prints and its state files (`./world.local.json`,
  `./challenge.local.json`); every `sigelo-agent` line has a `# library:` equivalent (the
  docs-only condition has no CLI); step 0 also writes `recovery.pub` and shows it as one bare
  line. SPEC §2's nonce row and ts/README: `z` + base58btc of raw bytes, never `z` + hex (the
  §5.2 challenge nonce stays opaque); to choose one, pass
  `nonce: crypto.getRandomValues(new Uint8Array(16))`. `examples/world.mjs --help` prints
  that usage, and bad arguments print it before any state is written. The next Haiku run is
  scored against a new snapshot.
- Keeper `spend.lock` survives reboots and pid reuse (soak incident #1, 2026-09-24: after a
  reboot the old keeper's pid 1103 belonged to bluetoothd, and the keeper refused to start
  for 54 minutes under `Restart=always` until the lock was removed by hand). The lock is now
  two lines, the pid alone (so `kill -9 $(head -n1 spend.lock)` still works) and
  `{"pid","boot_id","start"}` with this boot's id and the process starttime from
  `/proc/<pid>/stat`; a held lock is taken over with one warning naming what was stale when
  its boot_id is not this boot's, or its pid is dead, or its pid is alive with another
  starttime. Two live keepers are still refused; old one-line locks keep the pid-only rules;
  without /proc the keeper writes the pid line only. The stale-lock takeover race (two
  keepers starting at the same instant) is documented as the remaining limit. 7 tests
  (spend 571). soak/README: Incidents section; INCIDENT.md §2.2 kill line updated.

## v0.1 draft (wire `sigelo/0`) — 2026-09

First public draft. Nothing is stable.

- Identity as a hashed genesis document, so the recovery commitment provably predates
  any compromise.
- Domain-separated signing input `"sigelo\n" || JCS(body)`; `typ` bound inside signed bytes.
- Non-integer numbers forbidden in signed objects (JCS interop).
- Recovery rotations supersede voluntary ones regardless of `iat`.
- Voluntary rotations must carry the recovery commitment forward unchanged; only a
  recovery rotation may change it.
- Forks under a single key are rejected, not resolved.
- Cross-signed payment bindings; unproven bindings explicitly labelled and never paid to.
- 11 positive vector groups, 11 negative cases, verified by `py/reference.py`.
