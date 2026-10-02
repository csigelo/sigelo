# sigelo — roadmap to adoption by agents

Written 2026-09-23 at `57b57a4`; §1, §2's status and §6 brought to the tree's state on
2026-09-29 at `d265b77`. The Owner's bar: publish when an AI agent, unassisted, would
pick sigelo and get it working. The human's job shrinks to keeping one mnemonic. People are
not the audience. Speed matters because the rival already exists (§5.3). Honesty matters more:
an agent that adopts a format that then changes under it does not come back.

Where things stand: the repo is seven days old (`cc2349d`, 2026-09-17); the wire changed four
times on 2026-09-23 (`e658348` §3.1 typing, `ceab548` per-item forgiveness, `fcb8c54` point
decoding, `c4821e9` subaddresses); the keeper is one day old (`7ae0836` → `57b57a4`); every
review so far was by Claude models. Since then (to 2026-09-29): the wire changed again on
2026-09-24 (the hostile-JSON differential's SPEC §2/§3/§4 rules, CHANGELOG); the keeper has
been in a stagenet soak since 2026-09-23 with four incidents; every review is still by Claude
models.

## 1. Readiness bar for agent adoption

Assume a Haiku-class agent with a shell and no human in the loop. Each item below says what
exists, what is missing, and which task closes the gap. ✗ = not met, ◐ = partly met, ✓ = met.

**Measured on 2026-09-29 at `d265b77`** (the table was first written 2026-09-23 at `57b57a4`;
states then → now: R6 ✗→◐, R7 ✗→◐, every other state unchanged). Each claim cites a commit,
a file or a CHANGELOG entry; "(unverified)" marks what this pass could not check. Work that
other agents had in progress but not committed at `d265b77` is named as in progress, with no
result claimed.

| # | Item | State | Gap → task |
|---|---|---|---|
| R1 | **Discoverable.** An agent that searches "agent identity", "agent wallet" or "did method for agents" finds sigelo, and finds it as a tool it can call | ✗ nothing is public. A single-commit public export can be built locally (`release/publish.sh`, `5c6a637`; gate fixed `41611f6`, `175be8f`) but nothing has been pushed. D1 decided the account `csigelo` (`github.com/csigelo/sigelo`), the e-mail `contact@sigelo.io` and the domain (2026-10-01); the first push is the Owner's | Everything in §3. **T1** site: **built** (`0a4381f`, `site/`, 16 pages with `.md` twins, llms.txt/llms-full.txt/adopt.md/robots/sitemap/security.txt/index.json/JSON-LD; 256 checks; a Haiku agent adopted sigelo from the served site alone, 6/6, docs-test/RESULTS.md) — **not deployed**: the domain is **sigelo.io** (2026-10-01), hosting and DNS are still open. **T2** MCP server: the local stdio server is done (`integrations/mcp`, zero deps, `2077ce6`; the 2026-07-28 protocol and the legacy handshake, `93b96a3`), plus configs for Claude Code, Codex, OpenCode, Agent Zero, pi and others (`2bb27e1`, `integrations/`); registry listings and the remote verify-only endpoint are not started (step 7). **T3** W3C DID method registration: not started |
| R2 | **One command to install each implementation** | ◐ installable from tarballs, not yet from a registry. At `20fd24e` every packed manifest carries pinned `sigelo ^0.1.0` deps (`release/prepack.mjs` rewrites the `file:` paths at pack time and restores them), bins run from `dist/`, and `release/build.sh` (`7cdf4ea`) builds from a clean clone of HEAD: 4 npm tarballs, static `sigelo-verify` for linux/darwin × amd64/arm64 + windows/amd64, a Go source archive, SHA256SUMS identical across two builds. `release/pack-test.sh` installs them in an empty directory outside the repo and passes 16 checks on a built directory, 17 when it runs the build itself (`npx sigelo-agent init`, `npx -p sigelo-spend sigelo-wallet balance`, the MCP server over stdio with 12 tools, `go build ./cmd/sigelo-verify` + `--conformance`). `go/go.mod` still says `module sigelo`; `release/publish.sh` rewrites it to `SIGELO_GO_MODULE` (must end in `/go`). The npm names were unclaimed on 2026-09-23; not rechecked (unverified) | **T4**: code side **done 2026-09-29** (`20fd24e`, `7cdf4ea`). **Waits on the Owner** for the publish: npm account, `npm publish` each tarball (`sigelo` first), the export with `SIGELO_GO_MODULE=github.com/csigelo/sigelo/go` (`go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@v0.1.0`), tags `v0.1.0` and `go/v0.1.0` on the same commit, `gh release create` with the binaries. The CI release job runs pack-test but has not run on GitHub yet |
| R3 | **Implementable from spec plus vectors alone** | ◐ measured in the repo (docs-test/RESULTS.md): lifecycle from the docs alone **Sonnet 10/10** and **Haiku 10/10** (round 3b, 2026-10-01, docs of `9516622`, after `a795275`; Haiku was 7/10 two days earlier); a verifier from SPEC + vectors alone in **Python**, Opus, **139/139** on both graders, first iteration, 0 spec findings (2026-09-29); a Haiku agent adopted sigelo from the **served website alone**, 6/6 (`site/test/TASK-site.md`). **Every run was a Claude model**; the second foreign language (Perl) is impossible on the test host | **T5**, remaining: the same tasks on **non-Claude models** (one GPT-class, one Gemini-class, one open-weights) and a from-spec verifier in a second language the repo does not ship — both need an Owner API key and a host with a second toolchain. The Haiku-tier bar (≥ 9/10) is met for Claude |
| R4 | **A keeper an agent can drive with 4 verbs** | ◐ `sigelo-wallet balance/receive/pay/history`, a 9-line prompt snippet (MONERO.md §4.2). Haiku passed on stagenet (`4289…c49c`), and G8 ran end to end (`8e554aa`). spend/: **659 checks pass** with the live wallet (626 + 2 skipped without it; re-run at `cad0357`). Keeper swarm simulation: `16405df`, sim/REPORT.md. **Soak**: started 2026-09-23 (`41076a6`), **day 6 of ≥ 14** on 2026-09-29, with four incidents in spend/soak/README.md. #1 was a stale lock after a reboot (`44c614e`). #2, a torn log tail, was pre-empted (`6df3b67`). #3 was a near-miss redeploy (`200aeb5`). #4 was 32 h offline plus a latent wrong-clock risk (`7a91fdb` clock_behind, `0fc50f5` wallet_offline, `f98b8cf` wallet store, `9e5e35f`, `90de821`). The live soak `app/` still runs `6df3b67`, **without the #4 fixes** | **T6**: finish ≥ 14 days, then redeploy with the #4 fixes (a new soak, since the old identities fail the §2 nonce rule: README #3). **T14**: the day-7 rehearsal. Only its step 0 has been run (`efa9f33`). No third review of `spend/` by a non-Claude reviewer exists; AUDIT.md is a Claude self-audit. The verbs are exposed as MCP tools locally (`2077ce6`). The keeper stays **stagenet-only, labelled experimental** until audited (§5) |
| R5 | **Conformance an agent can check itself** | ◐ `sigelo-verify --conformance [vectors] [--monero …]` runs every vector through the Go reference (`c261ee8`), and since `c4cef7d` `--impl '<command>'` runs a **candidate implementation** over all 139 bundle cases with `docs-test/grade-verifier.mjs`'s protocol (`<cmd> case.json --now N`; exit 0 + §9.1 JSON accepts, exit 1 rejects; `--impl-stdin`; 10 s per case) and exits 1 on any FAIL. Proven: the Go binary as its own candidate 139/139, the ts verifier 139/139, a deliberately broken wrapper 136/139 → exit 1 (re-run at `cad0357`); `impl_test.go` covers flipped, never-rejecting, crashing and hanging candidates; CI runs all three. JSON Schema 2020-12 for every object in `schema/*.json` (12 schemas, CI-checked against every vector by `schema/check.mjs`, hand-written, not generated from §3.1); the keeper's HTTP surface in `spend/openapi.yaml`. One parity vector cannot be expressed in the schemas (`470d8df`) | **T7**: the runner is done; what remains is the **released binary** (T4, D1) so an agent needs no clone |
| R6 | **Stability promise** | ◐ `VERSIONING.md` exists (`664527b`, T8 done). `sigelo/0` is frozen at tag v0.2 after 30 days with no wire change, and packages use semver. The count has not started in practice: the wire changed again on 2026-09-24 (SPEC §2/§3/§4 rules D1, P1, S1–S5; `425d2bb`, `1380098`, `bc7165a`–`001ecfa`; CHANGELOG "hostile-JSON differential"). So the earliest freeze is 2026-10-24, if nothing else changes. VERSIONING §1 asks for a CHANGELOG line starting `wire:` for every change. **No CHANGELOG entry uses that prefix**, including those of 2026-09-24 | Keep the rule, or change it: tag the 2026-09-24 wire entries `wire:`, and use the prefix from now on. SPEC line 3 ("Nothing is stable until v1.0") and VERSIONING's v0.2 freeze need one sentence reconciling them before v0.1 |
| R7 | **Security disclosure path** | ◐ `SECURITY.md` exists as a draft (`664527b`). D1 fixed its addresses (`security@sigelo.io` for reports, `contact@sigelo.io` for the rest, account `csigelo`); the age recipient and SimpleX address are still `<placeholders>`, and it says "there is no working channel" until the repository is public and the mailbox exists. `site/` builds a `security.txt` (not deployed); there is no age recipient and no enabled private-reporting repository | **T9** (§5.2): create the mailbox, fill the two placeholders, publish `/.well-known/security.txt` with the site (step 6), and turn on GitHub private vulnerability reporting at the first push (step 8) |
| R8 | **Crypto checked by someone other than Claude** | ◐ every *review* so far was by Claude, but since `0a17aa3` the primitives are checked against **third-party code** (`crosscheck/`, T12): the RFC 8785 reference suite and canonicalizers (6/8 testdata byte-equal, the 2 float files refused as SPEC §3 requires; 20k documents, 100k integers, 100k doubles equal; 1 800 forbidden inputs rejected by both), monero-python 1.1.1 (base58 10k/20k, 5k seed-derived wallets, 2.5k subaddresses, 20k address checks, 25-word seeds 4k/8k in ts and go), libsodium via PyNaCl (500 byte-identical signatures, 800 tampered rejected), RFC 8032 5/5, Wycheproof 151/151, ed25519-speccheck 12/12 — **0 divergences**; `run.sh --self-test` corrupts sigelo's answers and all 9 sections catch it. The three monero-python disagreements are its own departures from Monero's C++ (AUDIT.md). Not covered: SigV2 message signatures (no third-party oracle on this host). The harness itself is Claude-built. Self-built evidence as before: ts↔go differential (`fcb8c54`), wallet-rpc oracle 9/9, hostile-JSON differential (1 805 documents), the swarm plus dishonest worlds (`ecb7f17`: 400 bundles, 36 SPEC-cited cases, 0 ts/go differences, 13/13 mutants killed), AUDIT.md | **T10** (external review of the §5.4 targets): not started, D3. **T11** (independent non-Claude implementations from the spec): not started, needs R3's non-Claude runs (API keys). **T12**: **done 2026-09-29** (`0a17aa3`); rerun `crosscheck/run.sh` after any change to jcs/base58/keys |
| R9 | **A worked example in each role** | ✓ world side: `adapters/1f916`, **99 code lines** across its five budgeted files (adapters/1f916/INTEGRATION.md; rebased onto upstream `1eedadd` in `1dfec57`). A **6-line `AGENTIC_ACCESS` entry in `src/connect.ts`** sits outside that budget; upstream's `test/openapi-agentic-access.test.ts` requires it of every write route, so with it the world-side cost is 105. Agent side: `adapters/moadim` (77 lines); `adapters/hermes` for Nous Research's Hermes Agent (9 lines of config, zero code; the real `hermes -z` with a scripted model, re-verified by go/: ALL PASS). `examples/world.mjs` | **T13**: filing is harder than planned. **Upstream `github.com/1f916-ai/1f916` answered 404 to anonymous requests on 2026-09-29** (private or removed; INTEGRATION.md "Upstream availability"). The patch is verified against `1eedadd` taken from public forks, and upstream commits after that cannot be seen. File the docket proposal (`adapters/1f916/PROPOSAL.md`, still "Not posted") from the `csigelo` account (step 12). Rebase again first if upstream is reachable, and decide whether the 6 lines count against the 100. A merged upstream is still the strongest adoption proof on offer |
| R10 | **Nothing that makes sigelo a service** | ✓ offline verify (invariant 1). The MCP server that exists (`integrations/mcp`) is local stdio and wraps the same library. The site and remote endpoint (§3) are conveniences; if they go down, nothing breaks | Keep it that way: the MCP server wraps the same local binaries |

Not on the bar, on purpose: keeper on mainnet, cold mode (MONERO.md §8 C1–C4), scoring.

## 2. The one seed — decided: a Monero 25-word root

**Decision (Owner, 2026-09-23): option (b).** The root is a Monero 25-word wallet seed, and
`S` plus every keeper, agent, recovery and wallet key derive from it by HKDF. A human with the
25 words restores the root wallet in any Monero wallet that takes a 25-word (legacy) seed, and
sigelo re-derives every identity. Implementation **landed** in `feb7e96` (`keys.ts`/`keys.go`,
the ceremony, MONERO.md §2); M4 landed in `278e87c`/`29a0402`; M6 is checked (below, and §6 step 2).

**What it replaces.** `S` was 32 bytes carried as **24 BIP-39 words** (`ts/src/keys.ts`
`toMnemonic`), deliberately not a Monero seed (MONERO.md §2). The ceremony put `S` only
inside `backup.age` (§4.5), so in practice the human backed up an age identity plus a
ciphertext. That meant two artefacts, and no stock wallet could open either. Option (a), keep
BIP-39 and have `restore` print each wallet's own 25 words, was rejected: recovery would
still go through sigelo code.

**The format.** A Monero legacy seed is 24 words from a 1626-word list encoding the 32-byte
private spend key (3 words per 4 bytes), plus a 25th checksum word that repeats one of the 24
(CRC32 of the 3-letter prefixes, mod 24). Sources: docs.getmonero.org/mnemonics/legacy and
monero `src/mnemonics/electrum-words.cpp`. The view key is `H_s(b)`. Polyseed (16 words, with
a restore height) is now in monero core (PR #10765 merged 2026-09-20, not yet released); not
used: it cannot carry `S` (150 bits, not 32 bytes).

**Construction.** `b_root = sc_reduce32(random32)` → 25 words;
`S = k(b_root, "sigelo/v1/root")` (§2's HKDF-SHA256). Every path under `S` stays unchanged.
- *Domain separation holds.* `b_root` works as a Monero spend scalar and as HKDF key
  material. Monero's use exposes only `B`, key images and signatures, none of which helps
  against HKDF under a unique `info`. All existing paths hang off `S`.
- *Recovery key.* Unchanged, `k(S, "sigelo/v1/recovery/ed25519")`: it derives from the 25
  words too. One secret covers money, identity and recovery. That was already true of `S`.
- **Constraint the decision depends on: the root wallet stays cold.** If the root wallet is
  loaded into a hot keeper (the hot treasury, today's default, MONERO.md §4.4), that host
  holds `b_root` and therefore `S`, the recovery key and every identity, permanently.
  Recovery would stop meaning anything (THREAT-MODEL §1). So the root wallet is a **vault**:
  a reserve no keeper ever loads, spent only by the human from a stock wallet (offline, or
  view-only plus cold signing) or by cold mode (§4.4). `treasury` and `allowance` stay
  derived and hot, as now. 25 words also invite being typed into Cake or Feather on a mobile
  device, which is hot. The docs, the ceremony output and `/adopt.md` must say "vault only,
  never a hot wallet" in one line. The implementation must not make the root wallet a keeper
  wallet.

**Migration tasks** (about 8–12 AH; status 2026-09-29: ✓ = landed in `feb7e96`, ◐ = partial, ✗ = not done):
- M1 ✓ `ts/src/monero-words.ts`: the 1626-word English list plus CRC32, about 60 lines, no
  new dependency. `keys.ts` gets `rootFromMoneroSeed`, `toMoneroSeed`, and `parseRoot`
  accepting 25 words. The 24-word BIP-39 path stays read-only, for roots made before the
  switch.
- M2 ✓ `go/keys.go`: the one extra HKDF step, `RootFromSpendKey`. Go keeps skipping mnemonics,
  as it skips BIP-39 today.
- M3 ✓ New derivation vectors: 25 words → `b_root` → `S` → the existing S1-style outputs,
  pinned in ts and go. A live interop check: stock `monero-wallet-rpc`
  `restore_deterministic_wallet` from the words reproduces `b_root`'s address.
- M4 ✓ (`278e87c`, `29a0402`) Ceremony: generate `b_root`; backup JSON `sigelo-root/2` (the
  words in field `mnemonic`, not `seed25`); `restore` accepts `backup.age` or the 25 words
  directly (`--words <file|->`, never argv; output byte-identical to the backup path). The
  words reach the human without entering an agent's context: `ceremony --human`, run by the
  human, writes them to `/dev/tty` and never to stdout (refused without a terminal), or the
  human decrypts `backup.age` once and copies them. Importing an existing seed (`--import`) is
  refused by default — a seed that has been in a hot wallet is not a root — unless
  `--i-know-this-seed-was-cold`, which prints the liability.
- M5 ✓ Docs: MONERO.md §2, §4.5, §4.6 (new liability: the root is also a spendable wallet),
  §9; keys.ts header; THREAT-MODEL §1; QUICKSTART's "Spending" paragraph; CHANGELOG. SPEC and
  `test-vectors.json` are **untouched**, because this sits below the wire.
- M6 ✓ (2026-09-29) Check against FCMP++/Carrot before v0.2. **Verdict: the root holds; no
  change to `keys.ts`/`keys.go`.** carrot.md (jeffro256, commit 4acb810, 2026-09-21) §5.1/§6.1.2/§8.2.1
  keeps the legacy hierarchy (`k_v = ScalarDeriveLegacy(k_s)`, same `SubAddr` subaddresses and
  address format) able to send and receive after FCMP++. The FCMP++ reference wallet (seraphis-migration
  `fcmp++-beta-stressnet-v3`, 2026-09-25) is still legacy-only (`wallet2` Carrot devices `return {}`,
  `@TODO: Carrot`), and restore, `generate_from_keys` and `query_key` are unchanged. No mainnet date
  has been set (getmonero.org, 2026-05-10). The stressnet forks testnet on 2026-10-05, and stagenet has
  no FCMP++ entry, so the soak is unaffected. Open upstream: seraphis-migration#306 (Carrot-only seed
  format, leaning to a separate flagged seed). Re-run when #306 closes, carrot_impl merges or a mainnet
  height is set. Follow-ups, all applied: Polyseed was merged to master 2026-09-20 (#10765), so the promise
  is now "any Monero wallet that takes a 25-word (legacy) seed" (`4daef77`, `9241e04`). The canary's exact
  1.30 pin failed on v0.18.5.1 (RPC 1.31); it now accepts RPC 1.30–1.33 and fails outside
  (`ba825f3`). The stressnet notes say tx proofs are not yet functional: MONERO.md §3 says to
  re-verify before v0.2; the unused `get_tx_key` is gone (`b5eeadd`). Facts block: MONERO.md §8.

**As built (`feb7e96`; CHANGELOG "The root is a Monero 25-word seed"), where it departs from
the plan above:** the 25 words encode `S` itself (canonical, `0 < S < l`). The vault is
`S`'s own wallet (`b = sc_reduce32(S)`, `a = H_s(b)`), instead of `S = k(b_root, …)`. The
24-word BIP-39 path was removed, not kept read-only: `restore` refuses `sigelo-root/1` by
name. The Go names are `RootFromMnemonic`, `MnemonicFromRoot` and `VaultFromRoot`, not
`RootFromSpendKey`. The wire and every existing derivation vector are unchanged.

**Adoption value:** high for the operator ("your 25 words work in any Monero wallet that
takes a 25-word seed and restore every agent"), neutral for agents, who never see the seed. This is the human element
the Owner asked for, reduced to one thing.

## 3. Bot-facing web presence

The site is static plus one MCP endpoint. Everything on it also lives in the repo, so a
mirror is a full copy.
**Built** (domain sigelo.io, decided 2026-10-01): [`site/`](site/README.md), `0a4381f`; what was deliberately not built is listed under step 6.

- **`/llms.txt`** per llmstxt.org (Jeremy Howard, Sep 2024; v2 Aug 2026): an H1 name, a
  blockquote summary, then H2 sections of links to `.md` files. **`/llms-full.txt`**: SPEC,
  QUICKSTART, ADOPT, THREAT-MODEL and MONERO §2–§4 concatenated. llms-full.txt is a convention
  and not part of the llmstxt.org text; ship it anyway, since it costs nothing.
- **Docs as plain markdown at stable URLs**: `/spec.md`, `/v0/spec.md` (frozen), and
  `/quickstart.md`. Each HTML page carries `<link rel="alternate" type="text/markdown">`, as
  llmstxt.org recommends.
- **`/adopt.md`**, the canonical page for models. At most 80 lines, imperative, copy-paste:
  install, init, bind, verify, pay. Three paths: "you are an agent", "you run a world", "you
  run agents that pay". Each ends in a check the agent runs itself (`sigelo-verify` prints
  `ACCEPT`). Also ask the agent to read `/adopt.md` whenever the docs change: it is what
  round 3 (T5) scores.
- **Machine-readable spec**: `/test-vectors.json`, `/schemas/*.json` (T7),
  `/openapi.json` for the keeper's HTTP surface (the MONERO.md §4.2 table as OpenAPI 3.1,
  CI-checked against `service.ts` routes), `/did-method.md` for the W3C registration (T3).
- **`robots.txt` allows AI crawlers by name.** OpenAI: `GPTBot`, `OAI-SearchBot`,
  `ChatGPT-User` (developers.openai.com/api/docs/bots). Anthropic: `ClaudeBot`,
  `Claude-SearchBot`, `Claude-User` (support.anthropic.com/en/articles/8896518). Perplexity:
  `PerplexityBot`, `Perplexity-User` (docs.perplexity.ai, perplexity-crawlers). The tokens
  `Google-Extended` and `Applebot-Extended` are opt-ins for training, not crawlers. Also
  `CCBot` (Common Crawl feeds most open models), `Amazonbot`, `Meta-ExternalAgent`. Training
  is the point: we want the next models to know sigelo. Also `sitemap.xml`.
- **JSON-LD** on each page: `SoftwareSourceCode` (codeRepository, programmingLanguage,
  license MIT, version), `TechArticle` for SPEC and the paper, `DefinedTerm` for `did:sigelo`.
- **MCP server** `sigelo-mcp`: a stdio npm package, plus the same code as one remote HTTP
  endpoint. Tools: `verify_bundle` (wraps `verify`, returns §9.1), `check_conformance`,
  `keygen_identity` (local only; the seed goes to a file and never into the result),
  `sign_challenge`, and the four wallet verbs against a **local** keeper URL and token. The
  remote endpoint gets verify-only tools, never keys. Listings: the official MCP Registry
  (`registry.modelcontextprotocol.io`, `server.json`, namespace `io.github.csigelo/sigelo`, chosen
  over a domain-verified `io.sigelo/sigelo` because the GitHub login proves it; the registry says it exists for sub-registries to consume), which Glama,
  Smithery, PulseMCP and mcp.so pick up or accept directly. Package indexes: npm, pkg.go.dev
  (automatic once the module path is real, T4). Hugging Face is low value (no model, no
  dataset), except a small **dataset of the vectors** that training pipelines might ingest.
  Optional: an A2A agent card (`/.well-known/agent-card.json`) describing the MCP tools.
- **Worked examples**: `adapters/1f916` (world), `adapters/moadim` (agent), linked from
  `/adopt.md` with their line counts — the count is the argument.
- **Sovereignty.** Self-hosting on any server the maintainer already runs links the pseudonym
  to it (shared IP, reverse DNS, billing identity). Use a **separate** VPS paid
  for separately, or GitHub Pages under the new account. Recommended: **GitHub Pages as the
  primary** (free, bot-crawled, no IP linkage), mirrored to a self-hosted box later. The MCP
  remote endpoint is verify-only and stateless, so any cheap host will do.

## 4. The paper

**Title:** *sigelo: Recoverable, Offline-Verifiable Identity and Private Payments for AI
Agents without a Chain.*

**Abstract (draft):** Agents build standing inside individual worlds and lose it on the way
out. We present a data format and verification algorithm that let a world verify an agent's
history offline, with no registry, chain or shared infrastructure. The design has four
pieces. A hashed genesis commits to a cold recovery key, and recovery rotations take
precedence over key rotations regardless of timestamp. Per-item verification fails closed
without letting one bad item poison a bundle, and cross-language parity vectors pin it down.
Keepers spend on agents' behalf under nested budgets and threshold approvals, so no agent
holds a spending key. Monero bindings use SigV2 over standard and subaddresses. Two
implementations agree on 6000 of 6000 differential mutations; agents built on Claude and
other models implemented the protocol from the specification alone; a Haiku-class agent
paid through the keeper on stagenet.

**Sections.** 1 Problem (trapped reputation, hot keys, prompt injection). 2 Design
(genesis-as-DID, `admission`, bindings). 3 **Recovery beats key** (precedence, why `iat`
cannot order it, commitment carry). 4 **Per-item verification** (two outcomes, inv. 7, JCS
pitfalls, parity vectors as a method for N implementations). 5 **Keepers** (accounts, 4
verbs, `ref`, two-phase relay, nested budgets, threshold approvals). 6 **Monero bindings**
(SigV2 modes, subaddresses, no per-subaddress view key, invoices). 7 **One seed** (§2). 8
Evaluation. 9 Comparison: ERC-8004 + x402, did:key/did:web, KERI (pre-rotation is the nearest
relative of the recovery commitment; compare honestly). 10 Limitations. 11 Conclusion.

**Novel, as far as we know (the related-work pass must confirm):** recovery precedence
independent of `iat` combined with offline self-contained bundles; per-item forgiveness
specified by cross-language parity vectors; a keeper model designed for weak LLMs (nested
budgets, threshold approvals, idempotent retries); identity↔Monero binding including
subaddresses.

**Evidence we have.** Vectors: 21 positive entries and 42 negatives, including 87 parity
bundles. ts 620 and go 498 `PASS` lines (`--conformance` 242), spend/ 659 with the live wallet,
all re-run at `cad0357`. The ts↔go
differential (159/160 vector bundles, 6000/6000 mutations). The monero-wallet-rpc oracle
(9/9). Stagenet txids (`2582…fe63d`, `9bb5…ac62`, `4289…c49c`, and G8's `e630…6e40e`,
`85f8…dbbc`, `e0a4…0c5f`, `cea2…8c70`). Haiku acceptance. The docs-only lifecycle and
from-spec runs (R3), and round 3's Claude datapoints (docs-test/RESULTS.md). The hostile-JSON
differential (1 805 documents) and the swarm simulation (sim/REPORT.md). The soak (spend/soak/README.md).

**Evidence missing.** External review; any non-Claude implementation; mainnet; longevity
(weeks, not hours); adversarial agents (a red-team agent given a keeper token and injected
text); a second world adopting; performance numbers (trivial, but reviewers ask).

**Venue.** arXiv cs.CR preprint plus the tagged repo. A first-time submitter may need an
endorser, which is harder for a new pseudonym, so plan for it. Also an IETF individual
Internet-Draft (`draft-csigelo-sigelo-00`) for the wire format alone, once `sigelo/0` is
frozen. It is cheap, indexed, and precisely what crawlers and standards people read. Plus the
W3C DID method registration (T3). Skip peer-reviewed venues until external review exists.

**Limitations (the section, not a footnote).** Sybil is made legible, not prevented. The
operator behind an agent is invisible. One recovery commitment links an Owner's agents. The
keeper host is the boundary, and keepers are hot. Timestamps are signer-asserted, and there
is no revocation list. It covers Monero only. A single pseudonymous author. Under two weeks of
history, and every review so far by one model family.

## 5. Security plan

### 5.1 Before the first push

- **Authorship.** Every commit is authored under the maintainer's real name and e-mail
  address, with local-time-zone dates. That deanonymises the
  maintainer on its own, and old commits' contents carry those strings and the device's
  hostname too. So the history is **not** rewritten: the public repository is a **fresh
  single-commit export** of the tree (`release/publish.sh`), authored by the pseudonym with a
  UTC date, and the private history never leaves this device. Hashes the docs cite (MONERO.md
  §8, CHANGELOG, this file) then name private commits; the export says so once instead of
  rewriting them. Use a fresh SSH key, and sign the export commit with the project identity
  (below).
  **Status (2026-10-01):** done — the fresh export was pushed as `bca5b16` (= private `13e3b12`). From now on every sync is `release/publish.sh` in **update mode** (outdir = the public clone: the same gated, tested tree, committed as ONE commit on top of `main`, never a new root, never pushed by the script); `--fresh` against a clone with a remote refuses unless told it rewrites history. CI on every push still needs the `DEVICE_STRINGS` repository secret (equal to the private pattern file).
- **Device paths.** A grep for the home-directory path finds **0 hits** at `57b57a4`, and neither does
  `git log -p --all`. The only home path is the placeholder `/home/you/…` in
  `adapters/moadim/INTEGRATION.md:26`. "This machine" appears in MONERO.md:11, :781,
  `adapters/moadim/README.md:59` and `cli.ts:31,39`. It is harmless, but reword it to "the
  test host". CI job on the export: fail on any of the maintainer's identifying strings.
  The list lives outside the repository (the `DEVICE_STRINGS` secret and the private
  pattern file the export script reads); no tracked file spells a pattern, not even a
  "generic" one (AUDIT A5).
- **Linkage beyond git.** npm and GitHub accounts use an email at the new domain. Do not
  reuse any existing account, server, messaging relay or registrar. The
  project's sigelo identity comes from **its own ceremony**: a DID derived from the Owner's `S` would carry
  the Owner's shared recovery commitment and link to every agent the Owner runs (MONERO.md
  §4.6).

### 5.2 SECURITY.md and disclosure

Three channels, in order. (1) GitHub **private vulnerability reporting** on the repo: it
works under a pseudonym and needs no infrastructure. (2) `security@sigelo.io`, with an age
recipient published in SECURITY.md and `/.well-known/security.txt` (RFC 9116) so reports
arrive encrypted. (3) A SimpleX contact address on public relays. Commitments:
acknowledgement within 72 hours, a fix or public advisory within 90 days, credit if the
reporter wants it, no bounty until funded. Scope: SPEC, vectors, ts/, go/, spend/, ceremony.
Out of scope: stagenet coins.

### 5.3 THREAT-MODEL additions: the less principled rival

This is not hypothetical. **ERC-8004 "Trustless Agents"** (draft ERC, 2025-08-13; per
secondary sources, live on Ethereum mainnet since 2026-01) gives agents ERC-721 identities
with on-chain public feedback. It pairs with Coinbase's **x402** for payments. An empirical
study (arXiv 2606.26028) found valid registrations for only 3/4/15 % of agents on
Ethereum/BSC/Base, and Sybil-pattern reviewers at 73.5/59.2/90.6 %. Its conclusion: the
feedback "cannot function as a trust signal". New section, THREAT-MODEL §7:

- **Public-chain identity leaks by construction.** Feedback and payments are public and
  permanent. An agent's counterparties, amounts and timing become a graph anyone can mine.
  sigelo's disclosure is selective, per bundle and per proof (MONERO.md §1).
- **Transferable identity.** An ERC-721 identity can be sold, so reputation can be bought.
  A sigelo DID is a genesis hash. Key sale is possible but not a market primitive, and
  recovery takes a sold key back.
- **Online verification.** Checking a chain identity needs an RPC node, i.e. trust in an RPC
  provider, or running a node. sigelo verifies offline (invariant 1).
- **No recovery.** Losing custody of the token loses the identity. Theft is terminal unless
  a contract adds recovery.
- **What they have that we lack:** first-mover adoption, a public registry agents can search,
  stablecoin UX. Answer without a chain: T1–T3 for discovery. Optionally, advertise
  `did:sigelo` inside an ERC-8004 registration file. That is an advertisement, not a
  dependency, and it touches the "no discovery mechanism" rule in CLAUDE.md, so it is an
  Owner call.

### 5.4 External audit targets, in priority order

1. `go/jcs.go`, `ts/src/jcs.ts`: canonicalisation and the strict parser. Divergence here
   breaks signatures across implementations.
2. `go/sigelo.go`, `ts/src/sigelo.ts` §9: chain walk, precedence, forks and cycles,
   per-item discard.
3. `go/monero.go`, `ts/src/monero.ts`: Keccak, base58 varints, point decoding against
   `check_key`, SigV2 in both modes, subaddress keys.
4. `ts/src/keys.ts`, `go/keys.go`: HKDF paths, `sc_reduce32`, the mnemonic (the new 25-word
   code, M1–M2).
5. `ts/src/ceremony.ts`, `offline.ts`: secret handling (`S`/the 25 words only in `backup.age` or on `/dev/tty`), age
   invocation.
6. `spend/service.ts` (lane, two-phase relay, account pinning, token compare),
   `approval.ts`, `tree.ts`, `policy.ts`.

Candidates: Monero-ecosystem crypto reviewers (e.g. Cypher Stack, who review Monero
protocol work), a general firm for items 1–2, or a Monero CCS-style public funding request.
Budget is Owner decision **D3**. Until one of these is done, the README says "unaudited".

### 5.5 Build and release integrity

- **Reproducible `sigelo-verify`.** Add a `toolchain` line to `go.mod`, build with
  `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid='`, and publish `SHA256SUMS`.
  CI and a second builder (the Owner's box) must produce identical hashes before a release.
- **Signing with the project's own sigelo identity** (dogfooding). A closed `release` object
  `{v, typ: "release", tag, commit, sha256s, iat}` is signed over `"sigelo\n" ‖ JCS`. It is
  project-local, like `spend-approval`, not a SPEC object. `sigelo-verify release` checks it
  against the project bundle published on the site and in the repo. Git tags carry an SSH
  signature from the same Ed25519 key: SSHSIG's namespace keeps it domain-separated from
  `"sigelo\n"`. Keep the project recovery key cold and test a recovery rotation before v0.2.
- **Dependency pinning.** Today `@noble/*` are caret ranges (`^3.2.0`, `^2.4.0`) with
  lockfiles, and CI actions are pinned by tag (`@v4`, `@v5`). Change to exact versions in
  `package.json`, `npm ci --ignore-scripts`, actions pinned by commit SHA, and
  `go.sum`/`GOFLAGS=-mod=readonly`. Update deliberately, one dependency per commit, and
  re-run the full vectors each time.
- **wallet-rpc canary.** A weekly CI job runs the pinned `monero-wallet-rpc` (0.18.5.0) and
  the latest release, `--offline` plus stagenet. It asserts the shapes of every RPC the
  keeper uses (`transfer` with `do_not_relay`/`get_tx_metadata`, `relay_tx`, `sign`,
  `verify`, `create_account`, `create_address`, `get_address`, `get_balance`,
  `get_transfers`, `sweep_all`) and replays `wallet_rpc_oracle`. It opens an issue on any
  diff. FCMP++/Carrot is the change it exists to catch. Its version rule (`spend/canary.ts`
  `RPC_RANGE`): RPC 1.30–1.33 passes, anything else fails until the oracle and the spend suite
  have been re-run against it and the ceiling moved (MONERO.md §4.1).

### 5.6 Incident plan: keeper compromise

**Rehearsed 2026-10-01 (T14, spend/soak/README incident #5):** detect → last sweep 15 min 26 s; the freeze step
failed as written (`mask --runtime` is overridden by units in `~/.config`; fixed by `spend/soak/freeze.sh`, `c38b9e3`,
`1b574ac`). **Spec gap found, closed by `164b8c4`:** the keeper's own DID could not be recovered after a compromise —
its genesis committed to `recoveryPublicKey(spend.key)`, which the thief holds. Now the keeper genesis (`identity.json`)
commits to a recovery key the host never holds: the root's `recoveryCommitment(S)` from the ceremony's keeper package
(`sigelo-spend init --keeper-package`; §2's one recovery key, MONERO.md §9 decision 2's default, so no new derivation
path), or an operator's offline key (`--recovery-commitment`, or the one plain `init` prints once). `sigelo-offline
recover --new-keeper <j+1>` signs the recovery rotation from the root and `init --adopt` serves the same DID (`chain[0]`)
under `K_{j+1}`; tested end to end with ts and Go verifiers (INCIDENT §5). No SPEC change: a recovery commitment is
already in every genesis, and which key it names is key management below the wire. Keepers keyed before it (the live
soak's) stay unrecoverable and are abandoned as before; the next rekey is recoverable.

Written as `INCIDENT.md`, each step one command:
(1) Stop `sigelo-spend` and the wallet-rpc; the tokens die with it. (2) From a clean host,
restore the wallet from the root and **sweep every account to the treasury** (or vault) at a
fee priority that beats the attacker's sweep. (3) **Recovery-rotate every agent identity**
under that keeper, and keeper 0's root identity, with the offline key (THREAT-MODEL §2.4);
it wins whatever its `iat`. (4) Abandon `K_j`: keeper `j+1` on a fresh host, new tokens, new
`spend.log`; keep the old signed log as evidence. (5) If the host held `S` or the vault seed,
it is total loss: move funds to a new root and rotate to identities under it. (6) Advisory if
a code bug caused it (§5.2). Rehearse on stagenet before v0.2 (T14).

## 6. Sequenced plan

Rough agent-hours (AH). "Owner" marks blockers. Status as of 2026-09-29 at `d265b77`
(§1); "landed" means committed, with the commit named.

| # | Step | AH | Status 2026-09-29 | Blocks on |
|---|---|---|---|---|
| 0 | **Owner decisions** (seed format already decided, §2): **D1** the pseudonym: name, GitHub handle (`sigelo` is **taken** on GitHub), domain, disclosure email; **D2** the publication cut (below); **D3** the external-review budget (§5.4) | — | **D1 mostly decided 2026-10-01**: the pseudonym is the GitHub account **`csigelo`** (`https://github.com/csigelo/sigelo`; export author `csigelo <contact@sigelo.io>`), the domain **sigelo.io**, the general e-mail **`contact@sigelo.io`**; disclosure stays `security@sigelo.io`. **D1 still open:** a display name beyond the handle (if any), the security mailbox and its age recipient, the vendor DID ceremony, kit/keeper prices and hours, hosting and DNS. D2 and D3 are not recorded | Owner |
| 1 | Record R3's measurements in CHANGELOG; `VERSIONING.md` (T8); SECURITY.md draft; device-string CI grep | 3 | **landed** in `664527b`: VERSIONING.md, the SECURITY.md draft, the CI grep (made pattern-free in `175be8f`, AUDIT A5), and rounds 1–2 recorded in docs-test/RESULTS.md. The CHANGELOG records round 3 only ("Docs closed for the three gaps"), not rounds 1–2 | — |
| 2 | 25-word root, M1–M6 (§2) | 10 | **landed**: `feb7e96` (M1, M2, M3 with the stock-wallet oracle, M5); M4 in `278e87c`/`29a0402` (`ceremony --human` to `/dev/tty`, `restore --words`, `--import` refused). M6 (the FCMP++/Carrot check) is done 2026-09-29: the root holds | — |
| 3 | Publishable packages and module path (T4); JSON Schemas; `sigelo-verify --conformance` (T7); reproducible release build (§5.5) | 10 | **partly landed** in `c261ee8`: `schema/`, `--conformance`, `release/build.sh`, `spend/openapi.yaml`. T4 code side **in progress 2026-09-29** (another agent, uncommitted) | D1 (module path, npm account) for the publish |
| 4 | THREAT-MODEL §7 (rival); INCIDENT.md; pinning; wallet-rpc canary | 6 | **landed** for THREAT-MODEL §7 and INCIDENT.md (`664527b`, INCIDENT §5 commands `3b17b29`). Pinning is **landed**: exact deps and actions by SHA in `3b01de1`. `go.mod`'s `toolchain` line was dropped again in `c17cebd`, so §5.5 is **partly met**. The canary is **landed, unrun on GitHub**: `spend/canary.ts` runs inside spend's `npm test` against the pinned RPC (live section SKIPs without a wallet), and the weekly CI job `.github/workflows/wallet-rpc-canary.yml` (`4e1a5aa`) runs its live half against the pinned and the latest wallet-rpc release on stagenet and opens an issue on failure; its shell ran on the test host, the workflow has never run on GitHub | — |
| 5 | `docs-test/` harness and round 3, Claude plus three non-Claude families (T5, T11) | 8 + API cost | **harness landed** (`a64d9c1`); Claude datapoints are in (`cf855c8`, `2a616a1`). **Non-Claude families not run**, and no from-spec verifier run | an Owner API key for non-Claude models |
| 6 | `adopt.md`, llms.txt, llms-full.txt, robots.txt, JSON-LD, OpenAPI, static site | 8 | **landed 2026-10-01** in `0a4381f` (`site/`, `node site/test/run.mjs` 242 checks; `site/test/TASK-site.md` written, not yet run on a model); OpenAPI served as `spend/openapi.yaml`. Not built: `/openapi.json` (no YAML converter without a dependency), `/v0/spec.md` (nothing is frozen), the A2A card and remote MCP endpoint (step 7). **Not deployed** | the `security@sigelo.io` mailbox; hosting and DNS |
| 7 | `sigelo-mcp` (stdio plus verify-only remote), `server.json`, registry listings | 10 | **stdio server landed** (`2077ce6`, `93b96a3`, harness configs `2bb27e1`); **`server.json` written** (`0a4381f`, `integrations/mcp/server.json`, namespace `io.github.csigelo/sigelo`, proved by `mcp-publisher login github` as csigelo, so no domain proof; `"mcpName"` added to `integrations/mcp/package.json`, checked equal by `site/test/run.mjs`; registry fields otherwise unverified). Remote endpoint and listings not started | `sigelo-mcp` on npm (step 8); step 3 |
| 8 | Project identity ceremony, first push, npm publish, first signed release | 4 | **first push done 2026-10-01**: `bca5b16` (fresh single-commit export of private `13e3b12`, §5.1, `release/publish.sh`); later syncs are one commit each via its update mode. **v0.1.0 tagged 2026-10-02** (`v0.1.0` + `go/v0.1.0` on one public commit): a GitHub pre-release (draft) with every `release/build.sh` artefact and `SHA256SUMS`, built twice from the public tree with identical sums (`release/RELEASE.md`). Remaining: npm publish, the §5.5 `release` object and SSH tag signature from the project identity (this release is unsigned); no ceremony has been run | the rest of D1 (security mailbox, age recipient, `DEVICE_STRINGS` secret); Owner runs or witnesses the project ceremony |
| 9 | Paper draft (§4) and a DID-method registration PR | 20 | not started | Owner: arXiv endorsement (the author is `csigelo` unless a display name is chosen) |
| 10 | Keeper soak on stagenet with scripted agents, incident rehearsal (T6, T14) | 6 + 2 weeks wall | **running**: day 6 of ≥ 14 (started `41076a6`, 2026-09-23), incidents #1–#4 (spend/soak/README.md). The live `app/` lacks the #4 fixes. T14 is due at day 7, and only its step 0 has run (`efa9f33`) | — |
| 11 | External review (§5.4), fixes, then 30 days with no wire change | weeks | not started. The 30-day count can start no earlier than the last wire change, 2026-09-24 (R6) | D3 |
| 12 | 1f916 docket proposal from the `csigelo` account (T13) | 2 | draft current against `1eedadd` (`1dfec57`), "Not posted". Upstream's repository is not publicly reachable (R9) | step 8; upstream reachable (or the proposal says it was checked against forks) |

About 90 AH of agent work. The calendar is set by steps 10 and 11.

**The cut.**
- **v0.1 public draft** (after steps 0–8, about 1 week): SPEC, vectors, ts/, go/,
  released `sigelo-verify`, SECURITY.md, VERSIONING.md, the site with llms.txt and adopt.md,
  the MCP server with verify-only tools. Labelled **"draft: the wire may change; the keeper is
  experimental, stagenet only; unaudited"**. Purpose: get external eyes (R8), claim names,
  and get crawled early, since training cutoffs lag.
  *Already in the tree (2026-09-29):* SPEC, vectors, ts/, go/, VERSIONING.md, SECURITY.md
  (draft, placeholders), a reproducible `sigelo-verify` build, and the local stdio MCP server.
  *Missing:* D1, a released binary, the site/llms.txt/adopt.md, the verify-only remote MCP
  endpoint, and the push itself.
- **v0.2 adoption-ready** (after 9–12): `sigelo/0` frozen after 30 quiet days; round 3
  ≥ 9/10 at Haiku tier across model families; two from-spec implementations in foreign
  languages pass every vector; the external review done and its findings closed; the keeper
  soaked and its MCP tools listed; the one-seed ceremony shipped; the paper on arXiv; 1f916
  proposal filed. This is the Owner's publication bar.
  *Satisfied so far:* the one-seed ceremony has shipped (`feb7e96`, M4 `--human`
  in `278e87c`; M6 checked 2026-09-29). Round 3 reached ≥ 9/10 at Haiku tier for **Claude only**, in one run. Nothing else
  on this list is met.

D2 is the tension: the Owner's bar is v0.2, but R8 (outside review) and early crawling both
need something public. Either publish v0.1 labelled as not ready for adoption, or share it
privately with reviewers and publish at v0.2 only. Recommended: the first.

Sources: llmstxt.org · docs.getmonero.org/mnemonics/legacy · monero `electrum-words.cpp` · github.com/tevador/polyseed · developers.openai.com/api/docs/bots · support.anthropic.com/en/articles/8896518 · docs.perplexity.ai (perplexity-crawlers) · modelcontextprotocol.io/registry/about · eips.ethereum.org/EIPS/eip-8004 · arxiv.org/abs/2606.26028.

## 7. Next product line: the provenance gate (after the operational basics are green)

Prompt injection is untrusted text steering a model; no signature stops persuasion. What a signature settles is
*who said it*, which lets the harness enforce the one rule the model cannot: instructions only from identities
allowed to give them, everything else is data however it is phrased. sigelo supplies the pieces (DIDs, §5.2
challenge proof, offline verification); the keeper already contains the consequence for money. The product: a
small harness plugin for Hermes and Claude Code — content signed by the operator's DID (a signed-message
envelope = an attestation with `ctx`, no wire change) may instruct and call privileged tools; unsigned or
other-DID content is wrapped as data and can call nothing. Owner idea, 2026-10-02.
