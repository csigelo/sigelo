<!-- SPDX-License-Identifier: MIT -->
# The fdroiddata merge request (not opened)

Opened once, after v0.1.11 ships the app. One post; then wait for the reviewers (humans). One
concise reply per question, no pings, no follow-up commits unless asked.

- Repository: a public fork of https://gitlab.com/fdroid/fdroiddata (a GitLab account; no company name)
- Branch: `io.sigelo.app`, from `master`
- File: `metadata/io.sigelo.app.yml` = [`io.sigelo.app.yml`](io.sigelo.app.yml) as set in step 2
- Commit message: `New app: sigelo`

## Title

New app: sigelo

## Body

```markdown
## Abstract for new app inclusion

sigelo gives an AI agent one identity it owns, from a key it holds: it proves who it is offline,
keeps its reputation when it changes platform, and messages other agents end to end through a
relay that cannot read them. This app is that identity's page on a phone: either the phone holds an
identity of its own (imported from the owner's computer), or it is a sealed remote for a computer
running the agent. Screenshots: attached.

Why: an agent's identity should not live in a platform account. The app is a WebView around the
project's own page, with no dependency besides the Android platform (no AndroidX, no Google
library, no tracker), MIT.

Reproducible build: `Binaries:` is our release APK, `AllowedAPKSigningKeys:` its certificate. A run
that rebuilds the tag the way the build server does (Debian's OpenJDK 21) and copies our signature
onto it: <REPRODUCE-RUN-URL>. Release: https://github.com/csigelo/sigelo/releases/tag/v0.1.11

Notes for review:
- `npm ci --ignore-scripts` in prebuild fetches the page's JavaScript packages (all MIT), pinned by
  lockfile integrity hashes, so the scanner sees them; `sudo` installs Node 24 from nodejs.org,
  checked by SHA-256 (Debian's Node is older than the package needs).
- The relay the app talks to is free software (AGPL) anyone can run.

## Checklist

### Policy
* [x] The app complies with the inclusion policy.
* [x] The original app author has been notified (I am the author).
* [x] Fastlane metadata upstream (`apps/android/app/fastlane`, en-US, icon, changelog).

### Docs
* [x] Read the guide, the templates, the Build Metadata Reference and the Quick Start Guide.

### Merge Request Setup
* [x] Title "New app: sigelo". Fork public, branch not protected. One app.

### Metadata
* [x] `metadata/io.sigelo.app.yml`, valid YAML, LF; `fdroid lint`, `rewritemeta` clean.
* [x] Nothing that belongs upstream. Tagged releases, auto update on.
* [x] Issue tracker; AuthorName.
* [x] No srclib, no submodule needed.
* [x] Reproducible Builds enabled (our signature).
* [x] No ABI split (no native code). Latest version only, none disabled. `commit` is the full hash.

### Pipeline
* [ ] All pipelines pass. (checked after opening)

/label ~"New App"
```

## After v0.1.11: the steps

1. Release v0.1.11 (release/RELEASE.md). The APK ceremony signs with `--alignment-preserved` and
   its last line (the signed APK begins with the unsigned one) is silent.
2. Here: in `io.sigelo.app.yml` set `versionName: 0.1.11`, `versionCode: 3`, `CurrentVersion`,
   `CurrentVersionCode`, and `commit:` to `git -C <public clone> rev-parse 'v0.1.11^{commit}'`;
   add `app/fastlane/metadata/android/en-US/changelogs/3.txt`; `node apps/android/check.mjs`.
3. The compare run on the tag; its verdict must say REPRODUCIBLE and
   `ref: the published sigelo-0.1.11.apk vs debian-21: MATCH`:
   ```sh
   gh workflow run android-reproduce.yml -R csigelo/sigelo --ref main -f ref=v0.1.11 -f expect=<CI unsigned SHA-256 of v0.1.11>
   ```
4. F-Droid's own build, on the VPS or the laptop (Docker, about 30 minutes; the container is
   thrown away, so `--on-server` may run the recipe's `sudo` in it):
   ```sh
   git clone --depth=1 https://gitlab.com/fdroid/fdroidserver ~/fdroidserver
   git clone https://gitlab.com/<you>/fdroiddata ~/fdroiddata    # the fork
   cd ~/fdroiddata && git checkout -b io.sigelo.app && cp <this file's yml> metadata/io.sigelo.app.yml
   sudo docker run --rm -itu vagrant --entrypoint /bin/bash -v ~/fdroiddata:/build:z \
     -v ~/fdroidserver:/home/vagrant/fdroidserver:Z registry.gitlab.com/fdroid/fdroidserver:buildserver
   # inside:
   . /etc/profile; export PATH="$fdroidserver:$PATH" PYTHONPATH="$fdroidserver"; cd /build
   fdroid readmeta && fdroid rewritemeta io.sigelo.app && fdroid lint io.sigelo.app
   fdroid build --on-server -v -l io.sigelo.app    # must log: compared built binary to supplied reference binary successfully
   ```
   `git diff` after `rewritemeta` must be empty.
5. `git add metadata/io.sigelo.app.yml && git commit -m 'New app: sigelo' && git push origin io.sigelo.app`;
   open the merge request at https://gitlab.com/fdroid/fdroiddata/-/merge_requests with the title
   and body above (the run URL filled in, two screenshots attached).
6. Wait for humans. Answer each question once, briefly.
