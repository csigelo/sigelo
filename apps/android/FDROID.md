<!-- SPDX-License-Identifier: MIT -->
# sigelo on F-Droid: readiness

Not submitted. This file says what F-Droid needs, what is ready, and what waits for a release
that ships the app. The draft recipe is [`fdroid/io.sigelo.app.yml`](fdroid/io.sigelo.app.yml);
the store listing is [`app/fastlane/metadata/android/en-US/`](app/fastlane/metadata/android/en-US/).
`node apps/android/check.mjs` checks both.

## Policy fit: yes

[Inclusion Policy](https://f-droid.org/docs/Inclusion_Policy/):

- **Licence:** the app and everything in the APK is MIT (LICENSE); the page's npm packages
  (@noble, MQTT.js) are MIT. The relay (AGPL, its own repository) is not in the APK and not needed
  to build it: CI fetches it for the page's tests only. The recipe skips it, and the tests.
- **No proprietary dependency:** no Gradle dependency at all, no AndroidX, no Google library. The
  Android Gradle Plugin 8.7.3 comes from Google's Maven, which F-Droid's scanner allows.
- **No tracker, no ads.** No dependency metadata block in the APK (`dependenciesInfo` off).
- **No binary in the repository:** `apps/web/vendor/` and `app/src/main/assets/` are not committed
  (`vendor.json` lists hashes only). F-Droid's scanner (fdroidserver at commit 2d1e622, run here on a
  clean checkout and again with `node_modules/` in place): no error, no warning; it removes
  `gradlew` and the wrapper jar and uses its own Gradle at the wrapper's version (8.10.2).
- **Anti-features:** no NonFreeNet (the relay is free software). TetheredNet is possible: the
  relay is AGPL and anyone can run one, but this app has no control to pick it (`settings.relay` is
  read, never set by the page). Add a relay field before submitting, or accept the label. The app
  reads the signed relay registry (`sigelo.ai/relays.json`) at most once a day; it sends nothing
  about the user.
- **Review risk:** `mqtt.esm.js` is MQTT.js's own minified browser build from npm. The scanner
  does not flag JavaScript; a reviewer may ask for it to be built from source. If asked: MQTT.js
  at the same tag as a srclib, built with its `esbuild.js`. That changes the bytes, so only for route A.

## What F-Droid's build server does

Read from the [Build Metadata Reference](https://f-droid.org/docs/Build_Metadata_Reference/) and
fdroidserver's source (`execute_sudo.py`, `common.py`, `build_local_run.py`, `buildserver/`):

- `sudo:` runs as root in the build container, then `sudo` is removed. Its commands are joined
  with `; `. Here it installs Node 24 from nodejs.org, pinned by SHA-256. The policy allows
  "prebuilt FLOSS binaries from ... Node.js (current versions)"; Debian 13's own Node (20) is
  older than our `engines` (≥ 22).
- `prebuild:` runs next; the source scan runs after it. Here: `npm ci --ignore-scripts` in `ts/` and
  `contact/`, so the scan sees every package the page ships.
- `build:` runs after the scan, then `gradle assembleRelease` in `subdir`. Here: `npx tsc` and
  `node apps/android/assets.mjs` (copy.mjs, then the page into the APK's assets). Both offline.
- Network: neither the docs nor the code cut it off. The build image (Debian trixie,
  `default-jdk-headless`) sets Gradle's network timeouts, and Gradle fetches the plugin from
  Google's Maven during the build. Our network use is `sudo` (Node) and `prebuild` (npm, lockfiles).
- `subdir: apps/android/app`, so the version check (`UpdateCheckMode: Tags`) finds
  `versionCode` in `app/build.gradle`; the listing must then sit in `<subdir>/fastlane/`.
- F-Droid takes no icon from an APK whose launcher icon is XML only (ours, adaptive). So
  `images/icon.png` is in the listing: `node apps/android/icon.mjs` draws it from the GTK app's SVG.

Checked here: `fdroid lint`, `readmeta` and `rewritemeta` (no change) pass on the draft. The
recipe's prebuild and build, run from `apps/android/app` on a clean clone, give the same 62 assets,
byte for byte, as a checkout at another path; `vendor.json` unchanged. Not checked here: Gradle
itself (no Android SDK on this machine).

## Two routes

**A. F-Droid signs.** F-Droid builds from the tag and signs with its own key. Nothing for the
operator. But Android updates an app only under the same key: an F-Droid install and a GitHub
APK cannot replace each other, and switching costs an uninstall, which erases what the app holds
(the sealed identity, contacts, history). `release.json` does not cover F-Droid's APK;
`apk-check.sh` refuses it.

**B. Reproducible, our signature.** The recipe gets `Binaries:` (the GitHub release's
`sigelo-%v.apk`) and `AllowedAPKSigningKeys:` (the `cert_sha256` of release/apk-ceremony.md).
F-Droid builds, compares with our signed APK minus its signature, and publishes ours only on a
match. One key everywhere; `apk-check.sh` works on F-Droid's copy. Needs the APK key made (the
ceremony) and a bit-identical build:

- Deterministic already: the assets (above); npm lockfiles; Gradle and AGP pinned; AGP ≥ 7.1
  fixes the ZIP entry order; no dependency, so no `baseline.prof`; no PNG resource;
  not minified; `version-control-info.textproto` holds the commit, the same when both build the tag.
- To fix: the JDK. CI uses Temurin 17, F-Droid Debian's default JDK (21). Align them (CI on the
  same JDK, or the recipe installs CI's), then build once both ways and compare (`fdroid build` in
  F-Droid's image against CI's unsigned APK; `apksigcopier` for the signed one).
- Sign with the `apksigner` of build-tools 34 (F-Droid's advice for apksigcopier) or check it copies.

**Recommended: B**, from the first F-Droid release: moving from A to B later makes every F-Droid
user reinstall and lose what the app holds. A only if B cannot be made to match.

## Steps and who acts

1. Release operator: the release that ships the app (release/RELEASE.md: versionName, versionCode
   + 1, the tag; route B: the APK ceremony, as for GitHub). Nothing else.
2. Maintainer: set the draft's versionName, versionCode, commit and CurrentVersion to that tag (a
   `changelogs/<versionCode>.txt` with it; check.mjs insists), and for B add `Binaries:` and
   `AllowedAPKSigningKeys:`; run `fdroid build io.sigelo.app` in F-Droid's container (B: compare).
3. Maintainer: fork fdroiddata, add `metadata/io.sigelo.app.yml`, one merge request ("New App"),
   then wait for the F-Droid reviewers. One concise reply per question; no pings.
4. F-Droid: after the merge, the app appears in 24 to 48 hours. Later tags update by themselves
   (`AutoUpdateMode: Version`, `UpdateCheckMode: Tags`).

## Time

Ready now: listing, icon, draft, checks. After the tag: step 2 about half a day, B's JDK alignment
and comparison about one more. Review: the queue's pace, often weeks; not ours to speed up.
