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

## Matrix

Status: **fixed** (changed in this sweep), **ok** (checked, nothing to do), **doc** (a limit,
documented where the user meets it), **by design** (OS-limited on purpose), **applied** (proposed
by the sweep for files it did not own, landed after it).

| # | Assumption | Where | Status |
|---|---|---|---|
| 1 | CRLF checkout on Windows (Git's `core.autocrlf=true`) would break the byte-for-byte vector diff, the docs-test snapshot hashes, CI's `openapi.yaml` regex (`\n`) and `#!/bin/sh` scripts | whole tree | **fixed**: `.gitattributes` `* text=auto eol=lf`; every tracked file is `i/lf w/lf`; CI checks `git ls-files --eol` on every runner |
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
| 30 | CI ran on ubuntu only | .github/workflows/conformance.yml | **fixed, unrun**: `portability` job, ubuntu/macos/windows × Node 22/24 + current on ubuntu, `shell: bash`, pinned SHAs. YAML parsed with PyYAML; every `uses:` is pinned to a 40-hex SHA. #10–#13 have landed, but no push has run the macOS or Windows jobs yet: their result is **unrun**, not known green |

## Not proven

- **macOS, Windows, glibc Linux, x86_64, Node 22 and Node current**: not run here. The CI
  matrix covers macOS arm64, Windows x86_64, ubuntu x86_64 on Node 22/24 (+ current); nothing
  covers Linux arm64 glibc or Windows arm64 (runner labels `ubuntu-24.04-arm` /
  `windows-11-arm` could be added once their availability for this repository is confirmed).
- **PowerShell**: the README/QUICKSTART PowerShell lines were written, not run. npm runs
  package scripts with `cmd.exe` on Windows; the moadim `pretest` is quoted for both sh and
  cmd but is unrun there.
- **Node < 22.18**: the `pretest` guard's version logic was checked for 20.19/22.17/22.18/23.5/
  23.6/24/26; the guard itself only ran on 24.
