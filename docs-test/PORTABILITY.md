# Portability

Owner requirement: a fresh clone builds and passes every suite on Linux (glibc and musl), macOS
and Windows (PowerShell and Git Bash), x86_64 and arm64, Node 22 LTS / 24 / current, Go 1.27,
with no step that assumes the maintainer's machine. This file says what is **proven** (run,
with the command), what is **documented** (a known limit, written where a user meets it),
what is **OS-limited by design**, and what is **unrun**. Swept 2026-09-24 at 2896de5, a commit of
the pre-publication development history, which is not public, like every short hash cited in
this repository (the published CHANGELOG.md opens with that note). The fixes the sweep proposed (#10–#14) are in the tree now;
the counts in the table below are re-measured on the current tree.

## What was run, and where

Host: Linux aarch64, **musl**, Node 24.18.1, Go 1.27.1. Nothing else was
available: no macOS, no Windows, no glibc, no x86_64, no other Node (official glibc Node builds
do not load under musl's gcompat: `fcntl64: symbol not found`).

**Clean clone.** `git archive HEAD | tar -x -C <tmp>/portab/tree`, then the documented install
with the lockfiles, in each package: `npm ci --ignore-scripts` in `ts/`, `adapters/moadim/`,
`spend/` (all three lockfiles are present and in sync: `npm ci` refuses otherwise;
`sim/` and `integrations/mcp/` have no dependencies), `npx tsc` in `ts/`, `go mod download`.
Every suite then ran inside an isolated network namespace (loopback only, so the keeper
tests could not reach a wallet on the host), as a non-root user, with a scratch `HOME`,
`TMPDIR`, `GOPATH` and `GOCACHE`, and an `env -i` environment:

| Suite | Command | Result (both variants) |
|---|---|---|
| ts build | `npx tsc` (ts/) | ok |
| vectors | `node dist/gen_vectors.js` vs `test-vectors.json` | byte-identical |
| ts | `node dist/test.js` | ALL PASS, 380 PASS, 0 SKIP (`age` and `monero-wallet-rpc` installed; each section SKIPs without its tool) |
| moadim | `npm test`, `npx tsc` (adapters/moadim) | ALL PASS, 84 ok, Go cross-check ran |
| spend | `npm test` | 559 passed, 0 failed, 2 skipped (live wallet, canary; the wallet-rpc interop SKIPs too without the binary) |
| go | `gofmt -l`, `go vet ./...`, `go test ./... -v` | clean, clean, ALL PASS |
| go binary | `CGO_ENABLED=0 go build ./cmd/sigelo-verify`, `--conformance ../test-vectors.json` | ALL PASS (217) |
| schemas | `node schema/check.mjs` | ALL PASS (136) |
| MCP | `npm test` (integrations/mcp) | ALL PASS (50) |
| sim | `node sim/swarm.mjs --agents 40 --rounds 8 --workers 2` | 0 findings, digest `3dd200ddff2d5a47` in both |
| sim | `node sim/keeper-swarm.mjs --agents 10 --flows 120` | 0 findings |

At the sweep, variant A: `TZ=Asia/Tokyo LANG=C LC_ALL=C`, `umask 077`. Variant B: `TZ=UTC LANG=en_US.UTF-8`,
`umask 022`. After normalising temp paths, timings, pids and random DIDs the two outputs are
**identical**: no locale, time-zone or umask leak. (Every date in the code is `toISOString`,
UTC; no `toLocale*`/`Intl`.) An earlier run with `monero-wallet-rpc` on PATH also passed its
12 interop checks (ts) in variant A.

The CI `portability` job's steps were also run one by one with `bash --noprofile --norc -eo
pipefail` and `RUNNER_TEMP` set, as GitHub runs them: all pass here.

**Go cross-compilation** (`CGO_ENABLED=0 GOOS=… GOARCH=… go build ./cmd/sigelo-verify`):
linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 — and windows/arm64,
linux/386, freebsd/amd64 — all build. `go vet ./...` is clean for GOOS=linux, darwin, windows.
`release/build.sh` run twice on a fixed-commit clone, the second with an empty `GOCACHE`:
identical `SHA256SUMS`, every output's mtime = the commit time.

## GitHub Actions, 2026-10-01 (run 36910629162, public commit bca5b16, the first push)

The job logs need a signed-in reader; the step outcomes and annotations are public
(`api.github.com/repos/csigelo/sigelo/actions/runs/36910629162/jobs`). Each failure below was
reproduced on the test host from a fresh `git clone` of the public repository, run with the
workflow's own `run:` lines (bash `-eo pipefail`), Node 22.23 and npm 10.9 (a musl build;
the host's own is 24), GNU coreutils/tar/grep/findutils, dash, `TZ=UTC`, a scratch `HOME`,
`XDG_CONFIG_HOME` set as on a runner, and the suites that could reach a wallet inside a
loopback-only network namespace.

| Job / cell | Result | Cause | Now |
|---|---|---|---|
| `go` (ubuntu) | **passed** | — | — |
| `portability`: ubuntu Node 22, 24, current; macOS arm64 Node 22, 24; Windows Node 22, 24 | **failed, all 7**, at the line-ending check: no suite ran | #1 (two results files with no final newline) | fixed; the check passes on the fixed tree. The suites in these cells are **unrun** on GitHub: on macOS and Windows nothing is proven yet |
| `release-build` (ubuntu) | build twice: **passed**, identical `SHA256SUMS`; `pack-test.sh`: **failed** | the runner exports `XDG_CONFIG_HOME`; pack-test moved `HOME` but not it, so `sigelo-agent init` wrote the identity outside the temporary home and check 2a found none | fixed: pack-test unsets the XDG base directories. Reproduced (FAIL at 2a with `XDG_CONFIG_HOME` set) and passing after (20 checks), from a shallow detached clone as `actions/checkout` makes: no `fetch-depth` change needed |
| `ts` (ubuntu): device strings, ts build, vectors, ts suite, `--impl`, moadim | **passed** (the device-strings step only because it skipped: the secret is not set) | — | a missing `DEVICE_STRINGS` now FAILS that step in this repository; it still skips for a fork or a fork's pull request |
| `ts` (ubuntu): spend `npm ci --ignore-scripts && npm test` | **failed** after 36 s | **not reproduced**: 721 passed, 0 failed, 3 SKIP here under every variant above, Node 22 and 24. Not `--ignore-scripts` (`npm test` runs `tsc` itself) and not the live wallet or `monero-wallet-rpc` (they SKIP) | the step (and the matrix's) now writes each `FAIL` line and the last output lines as annotations, which are public: the next run names the failing check. **Open** until then |
| `wallet-rpc canary` | not run (schedule / manual only) | — | unrun on GitHub |

## GitHub Actions, 2026-10-01 (run 36923176793, public commit 648b53f, the second run)

Every cell now got past the line-ending check and ran its suites. Annotations are public; the
causes below were read from them and from the code (macOS and Windows cannot be run here).

| Job / cell | Result | Cause | Now |
|---|---|---|---|
| `go`, `release-build` (ubuntu) | **passed** (release-build: both builds identical, `pack-test.sh` passing) | — | — |
| `identity-strings` | **failed**, as designed | the `DEVICE_STRINGS` secret is not set | Owner: set the secret |
| `ts` job and `portability` ubuntu Node 22, 24, current: spend | **720 passed, 1 failed** | `doctor (--create-wallet-rpc install, …)`: `init` wrote `ExecStart=/usr/bin/monero-wallet-rpc` unconditionally and doctor rightly failed it where no such file exists; the test host has the binary, so it never showed here. In the `ts` job the failure had no annotation: that job ran the default `bash -e`, without pipefail | `init --create-wallet-rpc` resolves the binary at init time (`--wallet-rpc-bin <path>`, else the first `monero-wallet-rpc` on PATH), **refuses** without one, and writes its absolute path into the unit; doctor still checks it exists. The test uses a stub (exit 0) via `--wallet-rpc-bin`, plus refusal checks (none on PATH, a missing path, no execute bit) and a doctor check on a vanished binary. Proven here with `monero-wallet-rpc` removed from PATH. The `ts` job now runs `shell: bash` (`-eo pipefail`) |
| `portability` Windows Node 22, 24: spend | **706 passed, 7 failed** | the Go cross-check spawned `sigelo-verify` without `.exe`; the rest are systemd-unit content and POSIX-mode checks (backslash paths escaped in `ExecStart`, no 0600 on NTFS) | `.exe` on win32. Unit and mode checks SKIP on win32 with "the keeper runs as a systemd unit; Windows is a verifier/agent platform, not a keeper host" (or "Windows has no POSIX modes"); the policy, the gate, receipts, the licence and the fake wallet still run there. **Unproven until the next run** |
| `portability` macOS Node 22, 24: ts `node dist/test.js` | **failed, no annotation** | not yet known from the run. Most likely (from the code): the M4 `--human` pty test only checked that a `script` exists, and macOS's BSD `script` has no `-c`, so its output files were never written and the suite crashed reading them (a crash prints no `FAIL`) | the pty checks use util-linux `script`/`setsid` where present, else a python3 helper (`os.forkpty`, `os.setsid`; exercised here with `SIGELO_TEST_PTY=python`), else SKIP with the reason; a missing output file is a FAIL, not a crash. The ts step now annotates `FAIL` lines, the first `Error` lines and the last lines on every OS. **Cause pending the next run's annotations** |

## GitHub Actions, 2026-10-02 (run 36926235160, public commit b70cc24, the third run) — green

Read from the public jobs API. Every job and every matrix cell passed except `identity-strings`, which
fails by design until the repository secret `DEVICE_STRINGS` is set.

| Job | Result |
|---|---|
| `identity-strings` | **failed as designed**: the `DEVICE_STRINGS` secret is not set (Owner action) |
| `ts` (ubuntu, Node 22): ts, moadim, spend, mcp, schemas, `--impl` | **passed** |
| `go` | **passed** |
| `release-build` (build.sh twice, identical SHA256SUMS, pack-test 20 checks) | **passed** |
| `portability`: ubuntu Node 22, 24, current | **passed** |
| `portability`: macOS arm64 Node 22, 24 | **passed** — the first macOS run of every suite (the pty tests took the python helper or SKIP path; the annotations show which) |
| `portability`: Windows Node 22, 24 | **passed** — spend's systemd-unit and POSIX-mode checks SKIP with their reason; the Go cross-check runs with `.exe` |
| `wallet-rpc canary` | not run (schedule / manual only) |
| `v0.1.0` tag, public `dbce031` (runs 37010457838, 37010458484; main 37010081513) | `release-build` **passed**; its `SHA256SUMS` equals this host's (aarch64, Node 24.18, npm 11.11, two builds identical, pack-test 20 checks) for the 5 Go binaries, the source archive and the vectors, but **not the 5 npm tarballs** (CI packs with Node 22 / npm 10: same commit, different npm, different bytes; the attached tarballs are this host's). `ts` and the ubuntu/Windows `portability` cells **failed** at `node world/test.mjs` (crash, `fetch failed: other side closed`, right after `world/conformance.mjs counts the cases`), since `694ef06`; passes here (67). macOS, `go`, `identity-strings` passed. Cause: the conformance run (`spawnSync`, ~7 s on CI) blocked the event loop past the server's 5 s keep-alive timeout, so the next `fetch` reused a socket the server had closed; **fixed**: every child process run while the world is up is now async (`exec` in world/test.mjs), and the step annotates FAIL/crash lines |
| `v0.1.1` tag, public `8a50e55` (main run 37209863971; conformance.yml runs on main only, so a tag push starts none) | all 11 jobs **passed**. `release-build` on ubuntu (Node 22.23, npm 10.9, go1.27.1) wrote a `SHA256SUMS` equal to this host's (aarch64, Node 24.18, npm 11.11) for **all 12 files, the 5 npm tarballs included** (gzip normalisation, `8e197df`); two builds here identical, pack-test 20 checks. The npm registry's tarballs have the same sha512 as the attached ones |

macOS and Windows are therefore proven for the verifiers, the agent adapter, the MCP server and the
keeper's own test suite; the keeper as a service remains Linux (systemd) by design.

## Platforms

`ts/` (library, `sigelo-offline`), `go/`, `adapters/moadim/` and `integrations/mcp/` are
cross-platform: Linux, macOS, Windows. `spend/`'s `init`, `doctor` and units are **Linux**: the
keeper runs as a systemd unit; Windows is a verifier/agent platform, not a keeper host. The
HTTP keeper (`sigelo-spend serve`) and the agent CLI `sigelo-wallet` may run anywhere Node runs,
but a keeper outside Linux is unsupported (spend/README "Platforms").

## Matrix

Status: **fixed** (changed in this sweep), **ok** (checked, nothing to do), **doc** (a limit,
documented where the user meets it), **by design** (OS-limited on purpose), **applied** (proposed
by the sweep for files it did not own, landed after it).

| # | Assumption | Where | Status |
|---|---|---|---|
| 1 | CRLF checkout on Windows (Git's `core.autocrlf=true`) would break the byte-for-byte vector diff, the docs-test snapshot hashes, CI's `openapi.yaml` regex (`\n`) and `#!/bin/sh` scripts | whole tree | **fixed**: `.gitattributes` `* text=auto eol=lf`; every tracked file is `i/lf w/lf`; CI checks `git ls-files --eol` on every runner. The first GitHub run (2026-10-01) failed that check on all 7 cells: `crosscheck/results/divergences.json` and `oracle-splits.json` were `[]` with no final newline (`i/none w/none`), not CRLF. **Fixed**: the files end with LF, `crosscheck/run.sh` appends it to every results file it writes, and the check now fails on exactly what it protects against, `crlf`/`mixed` in the index or the checkout (the old form could not see a CRLF committed to the index) |
| 2 | `node file.ts` needs type stripping: Node ≥ 22.18 or ≥ 23.6 | adapters/moadim/package.json (`test`, `bin: cli.ts`), integrations/mcp/server.mjs:10-11 | **fixed**: `engines` in every package.json (ts, spend, sim `>=22`; moadim, mcp `>=22.18`); moadim `pretest` stops an older node with a plain message naming the fix |
| 3 | No JS entry for older runtimes, and Node refuses to strip types under `node_modules` (a packed install of the adapter could not run) | adapters/moadim | **fixed**: `npm run build` (`tsconfig.build.json`, `rewriteRelativeImportExtensions`) emits `dist/cli.js`; smoke-tested (`init`, `whoami`), older Node **unrun**. `files` also lacked `sigelo-agent-monero.ts`, which `cli.ts` imports: **fixed** (`npm pack --dry-run`). Since 20fd24e the packed `bin`/`main` are `dist/` (built by `prepack`) and no packed manifest has a `file:` dependency; `release/pack-test.sh` installs all four tarballs in an empty directory and runs every bin, the MCP server and the Go build (ALL PASS on the aarch64 musl host) |
| 4 | `touch -d @N` is GNU/busybox-only; on macOS it failed silently (`\|\| true`), so mtimes were not pinned | release/build.sh:47,54 | **fixed**: `TZ=UTC0 touch -t` (POSIX) from git's own commit-time formatting. `sha256sum` vs `shasum -a 256` was already handled |
| 5 | Hard-coded `/tmp` | release/publish.sh:103 | **fixed** (the stage dir). CI's Linux jobs keep `/tmp` (ubuntu only); the new matrix job uses `$RUNNER_TEMP` because a Windows node does not see Git Bash's `/tmp` |
| 6 | Go binary built without `.exe` on Windows | sim/swarm.mjs:670, docs-test/grade.mjs:129 | **fixed** |
| 7 | Install hint named only Alpine and Debian | ts/src/ceremony.ts:42 | **fixed**: + macOS (`brew`), Windows (`winget`) |
| 8 | keeper-swarm's final liveness probe could be hit by its own 1 % chaos and report a finding | sim/keeper-swarm.mjs:540 | **fixed**: chaos off for the probe (seen once here; not OS-related) |
| 9 | File modes 0600/0700 for secrets | spend/service.ts:51, adapters/moadim/sigelo-agent.ts:73-75, ts/src/ceremony.ts:78-99, spend/cli.ts:83, QUICKSTART tier 2 | **doc**: Windows ignores POSIX modes (NTFS ACLs inherit from the directory). Stated in README (Requirements), ts/README (ceremony), spend/README (state files), adapters/moadim/README |
| 10 | Tests assert those modes | ts/src/test.ts:893, adapters/moadim/test.ts:52-57,345, spend/test.ts:434-438,1851 | **applied**: SKIP on `win32`; Windows **unrun** |
| 11 | `spawnSync('/usr/bin/env', ['PATH=…', …])` | ts/src/test.ts:926-929 | **applied**: `spawnSync(node, …, { env })` with the rest of the environment kept; Windows **unrun** |
| 12 | A `#!/bin/sh` stand-in `age` on PATH, PATH joined with `:` | ts/src/test.ts:941 | **applied**: SKIP on `win32` (the real-`age` section still runs there if `age` is installed); Windows **unrun** |
| 13 | `--log-file /dev/null` for monero-wallet-rpc | ts/src/test.ts:1097 | **applied**: `NUL` on Windows (only matters where the binary is installed); Windows **unrun** |
| 14 | `/proc` for the keeper lock (`boot_id`, pid starttime) | spend/service.ts:305-320 | **by design** + documented fallback (spend/README: pid only, a reused pid is removed by hand). **applied**: `SIGELO_PROC_ROOT` override (spend/service.ts:307-308) and a 5-check block (spend/test.ts:1785-1812) that runs the no-`/proc` fallback on Linux; macOS and Windows **unrun** |
| 15 | `process.kill(pid, 0)` | spend/service.ts:305 | ok: Node supports signal 0 as an existence test on Windows too |
| 16 | `fsync` of a directory | spend/service.ts:255 | ok: wrapped in `try` (Windows cannot open a directory for fsync) |
| 17 | `realpathSync(argv[1]) === realpathSync(self)` main-module check | spend/wallet.ts:418 | ok: both sides go through `realpathSync`; npm's Windows shim passes the real path. **Unrun** on Windows |
| 18 | `Atomics.wait` on the main thread | adapters/moadim/sigelo-agent-monero.ts:143, examples/world.mjs:45 | ok: Node allows it |
| 19 | `rename` over an existing file for atomic writes | adapters/moadim/sigelo-agent.ts:76, examples/world.mjs:49 | ok on POSIX; on Windows it replaces too, but fails with EPERM while another process holds the target open (antivirus, an editor). **Unrun** |
| 20 | Children spawned with only `{ PATH, HOME }` | adapters/moadim/test.ts:30,148,155,173,323,325; spend/test.ts (`env: { PATH, … }`) | **risk, unrun**: on Windows a child without `SystemRoot` can fail to start crypto/networking. If the Windows CI job fails there, add `SystemRoot: process.env['SystemRoot']` to those env objects |
| 21 | `~`, `$HOME` | adapters/moadim/sigelo-agent.ts:50 (`XDG_CONFIG_HOME`, else `HOME`, else `os.homedir()`) | ok: on Windows `%USERPROFILE%\.config\moadim\sigelo.local.json` (documented in adapters/moadim/README) |
| 22 | Shebangs `#!/usr/bin/env node` | ts/src/offline.ts, spend/cli.ts, spend/wallet.ts, adapters/moadim/cli.ts, integrations/mcp/server.mjs, … | ok: npm writes `.cmd`/`.ps1` shims on Windows; `node <file>` works everywhere |
| 23 | `sh` scripts | release/build.sh, release/publish.sh, docs-test/collect.sh, docs-test/snapshot.sh | POSIX `sh` (no bashisms, no GNU-only flags after #4 and AUDIT A4 — publish.sh's identity gate used GNU `grep -r` flags that busybox rejects, and the swallowed error read as a clean pass; it is `git grep` now); macOS and Git Bash **unrun**. `snapshot.sh --sandbox` uses `ln -s`, which Git Bash turns into a copy unless `MSYS=winsymlinks:nativestrict`. Maintainer tools, not needed to build or test |
| 24 | systemd units, `systemctl --user`, `~/.local/share/sigelo-soak`, ports 38083/38200 | spend/soak/* | **by design**: the stagenet soak is Linux + systemd only (spend/soak/README) |
| 25 | Case-sensitive names | whole tree | ok: no two tracked paths differ only by case |
| 26 | Path separators | all `.ts`/`.mjs` | ok: `path.join`/`URL`; the `'/'` splits are Monero `major/minor` keys and JSON-pointer fragments, not paths |
| 27 | `npx tsc` needs devDependencies | ts/, spend/, adapters/moadim | ok: `typescript` 5.9.3 is a pinned devDependency and `npm ci` installs it |
| 28 | Locale / TZ / umask | all suites | ok: proven identical above |
| 29 | Go: static, cross-built, vetted | go/ | ok: proven above. windows/arm64 builds but is not in `release/build.sh`'s five targets (adding it changes the release set: Owner's call) |
| 30 | CI ran on ubuntu only | .github/workflows/conformance.yml | **fixed, green on the third run (36926235160)**: `portability` job, ubuntu/macos/windows × Node 22/24 + current on ubuntu, `shell: bash`, every `uses:` pinned to a 40-hex SHA (v7 of checkout, setup-node, setup-go, upload-artifact since 2026-10-01: v4/v5 ran on the deprecated Node 20). The first run ("GitHub Actions" above) stopped every cell at the line-ending check (#1), before any suite. The second (run 36923176793) ran every suite: Linux spend 720/1, Windows spend 706/7, macOS ts failed; fixed as that section says, **unproven until the next run**. `shell: bash` is now set on the `ts` job too |

## Not proven

- **macOS, Windows, glibc Linux, x86_64, Node current**: not run here (Node 22 ran here since
  2026-10-01, a musl build). On GitHub the second run (36923176793) reached every suite and
  was red on all three systems; the fixes are unproven until the next run (see "GitHub Actions"). The CI
  matrix covers macOS arm64, Windows x86_64, ubuntu x86_64 on Node 22/24 (+ current); nothing
  covers Linux arm64 glibc or Windows arm64 (runner labels `ubuntu-24.04-arm` /
  `windows-11-arm` could be added once their availability for this repository is confirmed).
- **PowerShell**: the README/QUICKSTART PowerShell lines were written, not run. npm runs
  package scripts with `cmd.exe` on Windows; the moadim `pretest` is quoted for both sh and
  cmd but is unrun there.
- **Node < 22.18**: the `pretest` guard's version logic was checked for 20.19/22.17/22.18/23.5/
  23.6/24/26; the guard itself only ran on 24.
