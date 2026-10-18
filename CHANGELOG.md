# Changelog

Short commit hashes cited in this repository refer to the pre-publication development
history, which is not public. This public history starts at the import of 2026-10-01.

## v0.1.8 — 2026-10-18

- **Transport default `auto`:** 8883 for 5 s, then MQTT over WebSocket on 443, so an HTTPS-only network needs
  no setting; `SIGELO_RELAY_TRANSPORT=mqtts|wss` picks one; `HTTPS_PROXY`, `NO_PROXY` apply.
- **Contact over quota:** named as such (`side: "reader"`).
- **Relay:** MQTT over WebSocket at `/mqtt` behind nginx, counted by `X-Real-IP`; `quota_storage` says
  whose quota (`side`); relay.json `endpoints`. New dependency: `ws`.
- **Relay:** disk use is measured as `df` does, `used / (used + available)`; before, root's reserved blocks
  (ext4's 5 %) counted as used and `relay_full` came near 65 % real use. The free tier's ceiling agrees.
- ceremony `--human` screen: a 12-letter word ("verification") ran into the next number; the column is one wider.
- **AgentCard operator:** the card profile's `params.operator` carries the operator attestation and chain under `sig`;
  verify reports `{did, exp}` or refuses by name; signing goes through the key providers.
- **PAP profile draft:** `integrations/pap/`: a DID as PAP 0.1's `client_id`, bundle + §5.2 answer as `client_assertion`, checked offline; `--pairwise`: one DID per business. Issue drafted, not posted.
- **Web Bot Auth:** `integrations/web-bot-auth/` signs HTTP requests (RFC 9421) with the identity key via `sigelo-agent sign-http`, serves the key directory with the bundle, verifies offline. Cloudflare's vectors pass.
- **Key agent (K3):** `sigelo-key-agent` (`keyagent/`) holds identity keys and signs known bodies over a
  0700 socket; `keys to-agent`, `SIGELO_KEY_AGENT`; no rotation through `sign`.
- **Key providers (K1):** every signature goes through one signer (`sigelo-agent-keys.ts`);
  `keys status`; an optional `"provider": "file"` in the identity file; other forms refused by name. Files, DIDs unchanged.
- **Key providers (K2):** `init` seals the key under the OS keychain where one answers, else a plain file and a warning;
  `keys wrap`, `keys unwrap --plain`. ChaCha20-Poly1305, vector in `fixtures/wrap-v1.json`.
- **Pro gift codes:** `sigelo-agent pro redeem PRO-K7F3-Q9ZP` makes the operator's pool Pro for 1, 6 or 12 months
  (`POST /gift`); the relay holds each code's hash only, totals on `/stats`.

## v0.1.7 — 2026-10-15

- **Status:** new and experimental: the page (`sigelo-agent ui`), `watch`, tiers, files, enrolment and the
  seed-derived operator identity. Wire `sigelo/0` unchanged; keeper stagenet-only; all unaudited.
- **Files:** `sigelo-agent send-file <contact> <path>` and MCP `sigelo_send_file` send up to 8 MiB end-to-end
  (`sigelo-file/0`: a manifest, then 256 KiB chunks, one login).
- **Files received:** `inbox` checks size and SHA-256 and saves the file 0600 under `<identity>.files/<contact>/`,
  never opened.
- **Files queued:** wait in `<identity>.files/.out/` (0600), not in the state file; removed once sent, refused or
  the contact forgotten.
- **Expired answers, while waiting:** a code that expires during `accept --wait` is refused then (`code_expired`),
  not reported `waiting`; `inbox --wait` ends on a `pairing_failed`.
- **`sigelo-agent ui`:** a page on 127.0.0.1 for your own DID: contacts (Mine, Contacts, tags), short codes with the
  four words, messages, your agents enrolled and paired (`adapters/moadim/UI-API.md`).
- **Own agents, derived from your seed:** `enrol --name <n>` makes worker i of your keeper root
  (`agentIdentitySeed(K, i, n)`, 90-day attestation) and prints a one-time code (`adapters/moadim/ENROL.md`).
- **Enrolment on the server:** `init --enrol <code>` pairs like any contact, then its identity is replaced with
  worker i, sent once end to end (THREAT-MODEL §2.11).
- **Enrol options:** `--here` puts the worker in the agents' directory for a sub-agent; `--restore i [--rotate]`
  places it again from the words. The `enrolled` contact flag is gone.
- **Your identity from your words:** `sigelo-agent keeper --from-words` writes the keeper root and the operator
  identity, the root identity of the 25 words (`identitySeed(S, n)`), so they restore the same DID.
- **Derived identity guards:** a random identity in the way is refused (`--replace-me` sets it aside);
  `--rotate-me` derives the next key and `rotate` refuses a derived one.
- **`ui --recovery`/`--no-recovery` are gone:** run `keeper --from-words` once (`adapters/moadim/ENROL.md`).
- **The page's Enrol replaces "Make mine":** `POST /api/agents/enrol` makes a local agent worker i (old files set
  aside, its contacts warned) or renews a worker; `POST /api/agents/mine` is gone.
- **Contact tiers:** each contact is `own` (detected: an operator attestation from you or your operator), `friend`
  (default) or `quiet`; `sigelo-agent tier <contact> own|friend|quiet`.
- **Tiers elsewhere:** `accept --tier friend|quiet`, `inbox --tier own,friend [--quiet-too]`; MCP `sigelo_set_tier`,
  `tier`/`tiers` on accept and inbox; the page asks friend or quiet and groups Mine by tier.
- **Operator hints (`sigelo-operator/0`):** agents of one operator, and the operator, find each other own through
  blinded hints; other contacts learn only operator DIDs they guess (THREAT-MODEL §2.12).
- **Operator proofs:** taken only when asked for and only for the sender's current DID (a chain rotated into a
  sibling's genesis is refused); a renewed attestation is proved again; `send` refuses the label.
- **Older agents:** one on an earlier version shows operator hints as messages labelled `sigelo-operator/0`.
- **sigelo-contact API:** `cancelInvite(code)`, `rename(who, name)`, `clockOffset()`/`checkClock()`; `contacts()`
  adds `pair`, `chain`, `tier_by`, `prekeys` and `waiting`.
- **The page reads `inbox()`:** its carrier state no longer piles up 1,000 events; a file received shows as a
  message.
- **`sigelo-agent watch`:** stays connected, so an invite completes by itself when accepted; own messages go to
  `--on-message`, friends' as a notice to `--on-notice`, quiet ones wait.
- **`watch` hooks:** `--on-pairing` too (`adapters/moadim/WATCH.md`). Beside a watcher, `inbox` reads without
  logging in.
- **One owner per identity:** beside `watch`, CLI and MCP `send`/`send-file` queue for it and `inbox` reads what it
  got; other relay verbs, and all beside `ui`, refuse `busy`. No more 10 s session fights.

## v0.1.6 — 2026-10-14

- **Refusals:** each says what failed and what to do next, and how a code was read (short or long) and where it broke;
  `SIGELO_DEBUG=1` adds the identity file, relay, cause chain and stack.
- **CLI exits:** 0 done, 1 refused or offline, 2 usage or no identity, 3 `inbox --expect` with none; `adopt --rotation`
  without an identity no longer crashes.
- **Corrupt identity file:** named, with "restore it from your copy"; no longer told to run `init`, which makes a new
  identity.
- **MCP:** every refusal carries `structuredContent` `{code, message}`: a stable code beside its one line, never a
  stack.
- **Short codes:** `short_exp` is the relay's expiry, not this clock's; a short code spent and then refused prints its
  long code to keep and accept (MCP `long`).
- **Expired answers:** an answer whose code ran out before the inviter replied is reported: `pairing_failed`
  `code_expired` in `inbox`, in `contacts` (`failed`) and in MCP.
- **Relay 0.1.4:** every 429 sends `Retry-After`, the seconds until its window frees; the client names that wait.
- **Four words:** the same words mean no mix-up and no casual swap; a relay spending GPU time on a swap is caught by the
  32-digit pair id (THREAT-MODEL §2.10).
- **Site:** Monero only, "Contact us for a quote" (terms §6, Pro, For agents); no euro invoice.

## v0.1.5 — 2026-10-14

- **Short invite codes:** `invite` prints an eight-character code (`K7F3-Q9ZP`: case-insensitive, no look-alike
  letters, ten minutes, one use) to say on the phone or type from a note; `accept` takes it or the long code.
- **Four words:** after pairing both sides show the same four words (`contacts`, `accept`, `inbox`) to compare aloud;
  the 32-digit pair id is the strong check (THREAT-MODEL §2.10).
- **`invite --long`:** the one-line code, for agent channels; it never touches the relay before it is answered.
- **MCP:** `sigelo_invite` returns the short code beside the long one (`long: true` for the long only);
  `sigelo_accept` takes either; four words in accept, inbox and contacts.
- **Relay 0.1.3:** `POST /park` and `GET /park/<hash>` hold a long code under a short code's hash, in memory only,
  fetched once; lookups 20 per 10 minutes per network and 600 per 10 minutes on the whole relay.
- **Clock skew:** an inviter whose clock runs ahead of the relay's still parks its short code.

## v0.1.4 — 2026-10-14

- **After a theft:** messages signed by a key the owner's recovery overruled are refused, even ones that arrived just
  before it; `inbox` and MCP `sigelo_inbox` report them (`refused`, code `re_pair`).
- **No lost first send:** after `no_reader` the message stays queued with the sender and goes at its next `inbox` or
  `send`. `send` right after `accept` reads the inviter's reply first.
- **CLI:** `invite` prints the bare code (`--json` for more); `accept --name` renames on a re-pair, default the DID's
  first digits; `erase-request` signs a data request; `recovery-key` writes `recovery.pub` too.
- **CLI exits:** `--version`; `whoami` without an identity exits 2; Node older than 22.18 refused; a replayed code at once.
- **Retention:** 14 days, or what `relay.json` says. Relay 0.1.2: free tier 3,000 messages a day, 14 days, 512 KB.
- **Site:** stolen-key steps on agents.md and llms.txt; connect.md as 0.1.4 behaves; erasure by `erase-request`.
- **Frameworks:** `integrations/README.md` gives a config line, status and date for 30+ agent frameworks, Kimi Code,
  Qwen Code, Trae and DeepSeek Harness among them; sigelo.io `/frameworks` is the page form.
- **No MCP:** `integrations/JOIN.md`: the CLI sidecar, stdio MCP, and the raw path.
- **Agent card profile (draft):** a DID and bundle in an agent card extension, signed by the identity key, with a
  30-line verifier on the `sigelo` package (under `integrations/`).
- **README.zh-CN.md:** the protocol part in Simplified Chinese.
- **Relay stats:** `GET https://relay.sigelo.ai/stats`, the relay's counts, no identifier, 30 days of daily totals.
- **Visit counts:** sigelo.ai keeps a web access log, addresses cut to /24 or /48, no query string, 7 days (privacy
  page updated); statistics behind a password at `/_stats/`. Still no cookies and no scripts.

## v0.1.3 — 2026-10-14

- **Recovery key:** `sigelo-agent recovery-key [--out <file>]` writes the secret (0600) and prints the public key for
  `init --recovery`; `recover --recovery-key <file>` signs the recovery rotation. Nothing else needed.
- **Recover after a fork:** `recover` signs from the last honest node (the last recovery's, else the genesis): it beats
  a stolen copy's rotation from a node the owner also rotated from, unseen by the relay.
- **After a recovery:** both sides mark the contact `re_pair` (`contacts`, MCP `sigelo_contacts`) and send only the
  rotation notice under the old pairing key, claiming no new mailbox, until a new code pairs them.
- **Queued before a recovery:** a message is refused, and `inbox` reports it (`refused`, code `re_pair`). A contact on
  sigelo-agent 0.1.2 follows the recovery but marks nothing: pair with it again at once.
- **Exit codes:** a refused, locked-out or offline verb exits 1, the check on stderr, any JSON on stdout (`inbox`: 0 if
  it printed messages, now taken); no identity exits 2; `inbox --expect` exits 3 when none came.
- **First login:** a stderr line before the proof of work (5–60 s) and one after; docs say Node 22.18 or newer, tested
  on 24.
- **Fixture:** `carrier-v0.json` adds frame `notice_recovery`, a kind 4 notice carrying a recovery (identity B2);
  every earlier byte is unchanged.
- **Site:** sigelo.ai's quick start is the live test's, with `recovery-key` (new here, not run in that test) in place of
  its keygen one-liner: `recovery-key`, `invite --name`, `accept`, `inbox`, `send`.

## v0.1.2 — 2026-10-14

- **Status:** contacts and the relay are new and unaudited; the keeper stays stagenet-only; wire `sigelo/0` may change
  until v0.2.
- **Contacts (`contact/`, MIT):** invite codes, a contact store keyed by the original DID, end-to-end encrypted envelopes
  (hybrid X25519 + ML-KEM-768, prekeys, epoch chains) and an MQTT carrier; fixtures pin every byte.
- **Relay:** agents log in with their identity, keep private pairwise mailboxes and get messages while offline; AGPL-3.0,
  own repository `csigelo/sigelo-relay`, at relay.sigelo.ai; free per agent, Pro per operator.
- **npm:** `sigelo-contact` joins the five packages, in lockstep at 0.1.2.
- **Sidecar:** contact verbs ship in `sigelo-agent`, which depends on `sigelo-contact` and loads it only from its own install.
- **MCP:** the stdio server lists contact tools when `sigelo-contact` is installed; the Claude plugin bundle leaves them out.
- **Site:** sigelo.ai is the relay's home; sigelo.net and sigelo.online redirect there, sigelo.dev to sigelo.io; HSTS one year;
  titles, descriptions, structured data and a 404 page; stale footnotes removed.
- **Keeper:** the vendor-chain licence check is shared with the relay (`spend/licence.ts` unchanged in behaviour).

## v0.1.1 — 2026-10-04

- **Status:** first signed release (SSH-signed tags, `release.json`); GitHub pre-release; wire `sigelo/0` may change until
  v0.2; the keeper is stagenet-only and unaudited.
- **npm:** first publish, all five packages at 0.1.1 under `csigelo`, byte-identical to the release tarballs; the MCP
  registry entry now lists npm `sigelo-mcp` beside the remote.
- **Mirror:** `site/deploy/mirror-release.sh` carries `release.json` (checked against the tag and SHA256SUMS), so
  `release/verify-release.sh <tag>` works from sigelo.io.

- **MCP:** `sigelo_forget_issuer` (CLI `forget-issuer`) drops a retired issuer's attestations and genesis from the identity file: holder-side, after an out-of-band rotation notice (SPEC §5).
- **World:** issuer rotated 2026-10-03 after a seed exposure: new DID in SECURITY.md, chain at `/world/rotations.json`,
  old DID retired; the 24 h re-issue never replays a retired issuer's attestation.
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

## v0.1.0 — 2026-10-02 (draft)

- **Status:** first tagged release (GitHub pre-release, unsigned); wire `sigelo/0` may change until v0.2; the keeper is
  stagenet-only and unaudited.

### 2026-10-02, up to the tag

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

