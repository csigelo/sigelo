# Release v2: one tag, supply chain hardened

Design, 2026-11-11 (ROADMAP R1). It replaces RELEASE.md after stage 5; until then RELEASE.md is the procedure. "The maintainer" is the agent that runs releases; "the owner" is the human who holds the offline keys.

## 1. Goals and non-goals

Goals:

- One signed tag starts everything. The two manual steps: the owner signs the APK offline; the maintainer uploads it and makes the release final.
- Nothing reaches users unless three builders agree on its bytes: two CI runners and the maintainer's host.
- Build provenance on every asset; a Sigstore signature and the release identity signature (`release.json`) on the checksums; `verify-release.sh` checks all of them.
- A CycloneDX SBOM per release.
- No third-party version younger than 14 days; no install scripts.
- `main` changes only through pull requests with required checks.

Non-goals: secrets on GitHub (npm and the MCP registry use OIDC; the mirror pulls); signing keys in CI; SLSA level 3 claims; protecting users who install from npm without checking (§10).

## 2. The release path

Input: a green `main` commit `C` (merged by §9) with `<v>` in every package file.

1. **Maintainer, local.** `sh release/build.sh $D/a` and `$D/b` on `C`; `cmp` the two `SHA256SUMS`. SSH-sign the tags `v<v>` and `go/v<v>` on `C`, the message's last line `sha256sums: <sha256 of $D/a/SHA256SUMS>`; push both. The local build becomes the third builder, and CI cannot forge it.
2. **`release.yml` › `build`** (matrix `ubuntu-24.04`, `ubuntu-24.04-arm`): `release/build.sh` on the tag, plus the SBOM (§6). Output: artefact `dist-<runner>`.
3. **`compare`**: both `SHA256SUMS` byte-identical (§4) and equal to the tag's `sha256sums:` line; `git verify-tag` against `release/allowed_signers`.
4. **`apk`** (calls `android.yml`): the unsigned APK built twice and compared; output the workflow artefact `sigelo-android` (30 days), never a release asset.
5. **`attest-sign`** (`id-token: write`, `attestations: write`): `actions/attest-build-provenance` with `subject-checksums: SHA256SUMS` plus the unsigned APK, its bundle saved as `sigelo-<v>.intoto.jsonl`; `cosign sign-blob --bundle SHA256SUMS.sigstore.json SHA256SUMS`, keyless.
6. **`draft`** (`contents: write`): `gh release create v<v> --prerelease --verify-tag` with the built files, SBOM, both proof files, notes from the template. No APK, no `release.json`.
7. **`publish-npm`** (environment `npm`, trusted publishing): the six compared tarballs, `--provenance`, `sigelo` first (today's `npm-publish.yml` logic). Then **`mcp-registry`** with a pinned `mcp-publisher`. Both idempotent; re-run `gh workflow run release.yml -f tag=v<v>`.
8. **Mirror and site.** No SSH key on GitHub, so the server pulls: a timer on the site host polls the releases API every 10 minutes, runs `verify-release.sh` on a new release, mirrors it to `sigelo.io/releases/<tag>/` and rebuilds the site from the tag. A pre-release is mirrored without the APK; the final one again with it.
9. **Manual step 1, the owner.** The maintainer downloads `sigelo-android` (`gh run download`) and checks it against the log and `gh attestation verify`. The owner signs it on the offline computer (`apk-ceremony.md`, unchanged) and hands back `sigelo-<v>.apk`.
10. **Manual step 2, the maintainer.** `sign-release.sh v<v> $D/a --apk … <cert>`: it now also refuses a local `SHA256SUMS` that differs from the draft's, and adds the claim `apk.unsigned_sha256` (a claim, not a wire change). Then `gh release upload v<v> sigelo-<v>.apk release.json`, `verify-release.sh --strict v<v>`, `gh release edit v<v> --prerelease=false --latest`, and after the mirror runs, `--strict` against sigelo.io.

`macos.yml` is called; nothing `needs` it (its runners often go unassigned).

## 3. Workflows after the change

| File | Trigger | Change |
|---|---|---|
| `conformance.yml` | PR, push `main`, dispatch | stays; adds job `deps` (§7) and `conformance-required`, which `needs` all jobs; concurrency per ref, cancel in progress except `main` |
| `android.yml` | PR (no `paths` filter: a required check must always run), push `main`, dispatch, `workflow_call` | stays; builds twice, compares |
| `android-reproduce.yml` | dispatch | stays (report) |
| `macos.yml` | dispatch, `workflow_call` | stays |
| `npm-publish.yml` | — | into `release.yml` (§8) |
| `mcp-registry.yml` | — | into `release.yml`; checkout pinned by SHA (today `@v5`), `mcp-publisher` by version and SHA-256 (today `latest`, unchecked) |
| `wallet-rpc-canary.yml` | weekly, dispatch | stays; §11 |
| `release.yml` | tag `v*`, dispatch `tag`, `dry_run` | **new**; concurrency `release-<tag>`, never cancelled |
| `dependency-review.yml` | PR | **new**; `fail-on-severity: moderate`, non-OSI licences denied |
| `scorecard.yml` | weekly, push `main` | **new**; OpenSSF Scorecard to code scanning |
| `dependabot.yml` | weekly | **new** config: npm, gomod, gradle, actions; one group each; `cooldown: default-days: 14` |

Every workflow: `permissions: {}` on top, granted per job; every action pinned by SHA.

Required checks: `conformance-required`, `apk`, `dependency-review`.

## 4. Reproducibility

- **Builders:** `ubuntu-24.04` and `ubuntu-24.04-arm` (two CPU architectures), plus the maintainer's host (another distribution), whose digest is in the signed tag. `build.sh` already pins the Go toolchain, `GOENV=off`, `CGO_ENABLED=0`, `-trimpath`, `SOURCE_DATE_EPOCH` and the npm gzip.
- **Compared:** `SHA256SUMS` byte for byte: six npm tarballs, five `sigelo-verify` binaries, the source tarball, `test-vectors.json`, the SBOM. The unsigned APK: two CI builds on Temurin 21 (F-Droid's JDK). The signed APK against the unsigned one: the ceremony's prefix check.
- **On mismatch:** nothing is attested, drafted or published. `compare` prints the differing lines and keeps both artefacts 14 days. The maintainer finds the cause (`tar -tvzf`, `go version -m`) and fixes it in a new version; the tag never moves (the ruleset forbids it). No re-running until it happens to match: a mismatch is a finding.

## 5. Attestations and signatures

| Proof | Made by | Proves |
|---|---|---|
| tag `sha256sums:` line | maintainer's tag key | the maintainer built these bytes from this commit |
| `release.json` | release identity (pinned genesis) | the project's own identity vouches for `SHA256SUMS` and the APK certificate; offline, any sigelo verifier, no GitHub or Sigstore |
| `intoto.jsonl` provenance | GitHub OIDC, `release.yml` at the tag | which workflow, commit and runner built each file |
| `SHA256SUMS.sigstore.json` | Sigstore keyless, same identity | the same, in the format outside tools read, in Rekor |

Why three: each fails differently. `release.json` survives losing GitHub or Sigstore. Provenance and cosign survive a stolen host key, since a forged `release.json` matches no attested build. Cosign overlaps provenance (both in Rekor); it stays because `cosign verify-blob` is what outsiders run.

`verify-release.sh` keeps checks 1–4 and adds:

5. the tag's `sha256sums:` equals `sha256(SHA256SUMS)`;
6. per file, `gh attestation verify <f> -R csigelo/sigelo --signer-workflow csigelo/sigelo/.github/workflows/release.yml --source-ref refs/tags/v<v>`; offline with `--bundle sigelo-<v>.intoto.jsonl` and a saved trusted root;
7. `cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json --certificate-identity https://github.com/csigelo/sigelo/.github/workflows/release.yml@refs/tags/v<v> --certificate-oidc-issuer https://token.actions.githubusercontent.com`;
8. the APK's `unsigned_sha256` has a provenance attestation.

Without `gh` or `cosign` it prints "not checked", as for `apksigner`; `--strict` makes that FAIL. `test-release.sh` gets fakes for both.

## 6. SBOM

`npm sbom --sbom-format cyclonedx --omit dev --package-lock-only` per package; the Go module from `go list -m -json all`; the APK has AGP and the platform only. A new `release/sbom.mjs` merges them into one CycloneDX 1.6 file, `serialNumber` from the commit and timestamp from `SOURCE_DATE_EPOCH`, so it reproduces and joins `SHA256SUMS`. Attached as `sigelo-<v>.cdx.json`.

## 7. Dependency policy

- **Cooldown 14 days.** Updates resolve with `npm install --before "$(date -u -d '14 days ago' +%FT%TZ)"`. `--before` does nothing to `npm ci` on a lockfile, so the `deps` job enforces it: per lockfile entry it reads the publish time (`registry.npmjs.org/<p>` `time[<v>]`; Go `proxy.golang.org/<m>/@v/<v>.info`) and fails below 14 days at the commit time. Exceptions: `release/cooldown-exceptions.json`, reason and expiry each (a security fix).
- **sha512 only:** `lockfile_pinned` in the export gate (exists).
- **`--ignore-scripts`:** on every `npm ci` (exists); plus `ignore-scripts=true` in each package's `.npmrc`.
- **No install scripts:** `deps` fails on `"hasInstallScript": true`. One hit today: `esbuild` in `plugins/`, dev only, its binary from an optional dependency; listed as an exception.
- **Dependabot:** weekly, grouped. Its PRs are signals: `main` is an export, so the maintainer applies the bump in the source tree under the cooldown, exports through `ci-check` and closes the Dependabot PR. VERSIONING §6 changes to say so.
- **Actions:** pinned by SHA (exists); first Monday of each month one PR bumps them to releases at least 14 days old, changes read.
- **werift:** pinned at 0.26.0 on 2026-11-03, two days after its release (2026-11-01). It clears the cooldown on 2026-11-15; a release before then needs an exception or 0.25.2 (2026-10-24). 0.27.0 (2026-11-10) not before 2026-11-24. Its transitive packages get the same check.

## 8. npm

- **Provenance** on every version (`--provenance`); `npm view <p>@<v> dist.attestations` shows it.
- **Trusted publishing** is on for all six packages (since 2026-10-24). Each entry names the workflow file, so `release.yml` needs six edits (below); until then `release.yml` calls `npm-publish.yml` as a reusable workflow. UNVERIFIED: whether npm then checks the caller's file name or the callee's. Check: `npm-publish.yml`'s `mode=check`, called from `release.yml` on `ci-check`.

Owner steps on npmjs.com, as `csigelo`:

1. Avatar → Account → Two-Factor Authentication: "Authorization and writes".
2. Avatar → Access Tokens: delete all (none is used).
3. For each of `sigelo`, `sigelo-contact`, `sigelo-agent`, `sigelo-spend`, `sigelo-mcp`, `sigelo-recovery-kit`:
   - Settings → Publishing access → "Require two-factor authentication and disallow tokens" → Update;
   - Settings → Trusted Publisher → GitHub Actions: user `csigelo`, repository `sigelo`, workflow `release.yml`, environment `npm` → Save. Remove the `npm-publish.yml` entry after the first green v2 release.

## 9. Branch protection and the PR flow

Today: linear history and no force-push are on; there are no required checks or PRs, admins are exempt, and `delete_branch_on_merge` is on, which would delete `ci-check`.

```sh
gh api -X PUT repos/csigelo/sigelo/branches/main/protection --input - <<'EOF'
{"required_status_checks":{"strict":true,"checks":[{"context":"conformance-required"},{"context":"apk"},{"context":"dependency-review"}]},
 "enforce_admins":true,"required_pull_request_reviews":{"required_approving_review_count":0},
 "restrictions":null,"required_linear_history":true,"allow_force_pushes":false,"allow_deletions":false}
EOF
gh repo edit csigelo/sigelo --delete-branch-on-merge=false --enable-merge-commit=false --enable-squash-merge=false --enable-rebase-merge
```

Admins included: the account the maintainer operates cannot push `main` either. Zero reviews: owner and maintainer share that account, so a review would be self-review; the owner's approval is the APK signature. Push restrictions exist for organisations only.

Every change:

```sh
git -C ../sigelo-public switch -C ci-check origin/main
SIGELO_AUTHOR="$A" SIGELO_GO_MODULE=github.com/csigelo/sigelo/go sh release/publish.sh   # commits on ci-check
git -C ../sigelo-public push --force-with-lease origin ci-check
gh pr create -R csigelo/sigelo -B main -H ci-check -t "sync: <heading>" -b "private tree <sha>"
gh pr checks <n> -R csigelo/sigelo --required
gh run view <id> -R csigelo/sigelo --json jobs -q '.jobs[]|"\(.name) \(.conclusion)"'   # every run, by hand
gh pr merge <n> -R csigelo/sigelo --rebase --match-head-commit <sha>
git -C ../sigelo-public switch main && git -C ../sigelo-public pull --ff-only
```

Never `--auto` or a merging watcher. Rebase merges make new SHAs: tag and build the merged commit.

## 10. Threat model of the release path

| Compromised | Could | Stopped by | Not stopped |
|---|---|---|---|
| CI (runner, action, build-time package) | build bad bytes, attest and cosign them | the tag's `sha256sums:` (nothing published); `release.json` needs the host key; the APK needs the offline key | a bad input all builders share (the lockfile): only cooldown, hash pins, no install scripts reduce it |
| npm account | publish outside CI | disallowed tokens, 2FA on writes, trusted publishing only; a rogue version lacks provenance and matches no `SHA256SUMS` | users who install unchecked |
| GitHub account | change workflows, lift protection, delete releases, push a new tag that publishes to npm through trusted publishing | `verify-release.sh` (no tag or `release.json` signature); Android refuses an update not signed by the APK key; F-Droid ships only our signature | npm installs: trusted publishing trusts whatever the workflow does. The widest gap (question 1) |
| the owner's offline computer | steal the APK key or the release identity's recovery key | an APK in no `release.json` fails `apk-check.sh`; theft needs physical access | a stolen recovery key takes the release identity: announce through SECURITY.md, new pins |
| the maintainer's session | all the GitHub account can, plus sign tags and `release.json` | the APK (owner only); CI gates; Rekor and attestations record every release | a full npm and binary release without the owner (question 1) |

Offline keys stop forged apps and identity rotations; reproducible builds stop one bad builder; attestations only attribute; the cooldown buys detection time.

## 11. CI hygiene: the wallet-rpc canary

Issue #3 (run 42629284961; #1's log not read): wallet-rpc answered `get_version` 2 s after start and `create_wallet` at +6 s; then the canary's first call hit its 20 s timeout, "unreachable". The start window held; the stall follows wallet creation, most likely its first refresh against the remote stagenet daemon blocking the RPC.

Change:

1. After `create_wallet`, `auto_refresh {"enable":false}`; the canary needs no sync.
2. A readiness poll: `get_height`, `--max-time 10`, sleeping 1, 2, 4, 8, then 15 s, up to 180 s; print the seconds taken.
3. Start loop 120 s, same backoff, instead of 60 × 1 s.
4. `spend/canary.ts`: with `SIGELO_CANARY_RPC` set, retry `get_version` three times (5, 10, 20 s) before SKIP; 20 s per call stays.

Why safe: an upstream RPC change shows as a wrong shape or version, never as a timeout, so waiting loses no signal; a dead binary still fails at 180 s.

Closing text for #3, for the owner to approve verbatim:

> Second flake after #1: wallet-rpc started in 2 s, but the canary's first call timed out right after the new wallet was created, most likely during its first sync. Fixed in `<commit>`: auto-refresh off, a readiness poll up to 180 s, three retries before skipping. Dispatched run `<id>` passed both jobs. Closing.

## 12. Rollout

Each stage: exported to `ci-check`, run with `gh workflow run <file> -R csigelo/sigelo --ref ci-check`, each job's conclusion read by hand, merged by the §9 PR. The maintainer never pushes `main`.

| Stage | Content | Agent-days |
|---|---|---|
| 0 | canary fix; pin `mcp-registry.yml`; `permissions: {}`; close #3 | 0.5 |
| 1 | `deps` job, exceptions file, `.npmrc`, dependency-review, Scorecard, Dependabot | 1.5 |
| 2 | `android.yml` callable, double build; `conformance-required`; branch protection (after the owner's yes) | 1 |
| 3 | `release.yml` build ×2, compare, tag digest, SBOM, attest, cosign, draft; on `ci-check` with `dry_run=true` (no attest, draft or publish) | 2.5 |
| 4 | `verify-release.sh` checks 5–8 and `--strict`; `sign-release.sh` draft compare; `test-release.sh` fakes | 1.5 |
| 5 | npm and MCP jobs after the owner's npm steps; mirror pull timer; first v2 release; RELEASE.md replaced | 1.5 |

About 8.5 agent-days.

## 13. Open questions for the owner

1. Should npm publishing wait for your offline sitting, you signing `SHA256SUMS` beside the APK, so a hijacked GitHub account or maintainer session cannot ship npm alone?
2. May the maintainer apply the §9 protection command itself once stage 2 is green?
3. Mirror and site by a pull timer on the server, no key on GitHub?
4. Rename the release workflow to `release.yml` (six npm edits from you, §8) rather than keep `npm-publish.yml` as its name?

## UNVERIFIED

- Artifact attestations for a free-plan user account's public repository: documented for public repositories on all plans, none made here yet. Check: stage 3, `gh attestation verify`.
- npm trusted publishing through a reusable workflow (§8): `mode=check`.
- `npm sbom` output identical across hosts: stage 3 compares it.
- Dependabot's `cooldown` key: the first run's log in Insights → Dependency graph → Dependabot.
- `ubuntu-24.04-arm` for free public repositories: stage 3; fallback `ubuntu-22.04`.
- The canary stall's cause (§11): proven only by 8 green weekly runs.
