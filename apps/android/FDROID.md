<!-- SPDX-License-Identifier: MIT -->
# sigelo on F-Droid: readiness

Not submitted. This file says what F-Droid needs, what is ready, and what waits for a release
that ships the app. The recipe is [`fdroid/io.sigelo.app.yml`](fdroid/io.sigelo.app.yml) (route B,
below); the merge request, ready to open after v0.1.11, is [`fdroid/MR.md`](fdroid/MR.md);
the store listing is [`app/fastlane/metadata/android/en-US/`](app/fastlane/metadata/android/en-US/).
`node apps/android/check.mjs` checks both.

## Policy fit: yes

[Inclusion Policy](https://f-droid.org/docs/Inclusion_Policy/):

- **Licence:** the app and everything in the APK is MIT (LICENSE); the page's npm packages
  (@noble, MQTT.js) are MIT. The relay (AGPL, its own repository) is not in the APK and not needed
  to build it: CI fetches it for the page's tests only. The recipe skips it, and the tests.
- **No proprietary dependency:** no Gradle dependency at all, no AndroidX, no Google library. The
  Android Gradle Plugin 8.8.2 comes from Google's Maven, which F-Droid's scanner allows.
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
  with `; ` and run under `bash -e -u -o pipefail`: one failure stops the build. Here it sets `java` and `javac` to OpenJDK 21 (the image picks its highest JDK, which
  would change the bytes the day it holds a 25), and installs Node 24 from nodejs.org, pinned by
  SHA-256 (`xz-utils` too: the image purges it). The policy allows
  "prebuilt FLOSS binaries from ... Node.js (current versions)"; Debian 13's own Node (20) is
  older than our `engines` (≥ 22).
- `prebuild:` runs next; the source scan runs after it. Here: `npm ci --ignore-scripts` in `ts/` and
  `contact/`, so the scan sees every package the page ships. npm at build time is the policy's route
  for JavaScript: the scanner wants a lockfile beside each `package.json` (ours pin every package by
  integrity hash) and scans what it fetched; no srclib, no vendored tarball. The scan of that tree is
  clean, so no `scanignore` and no `scandelete`.
- `build:` runs after the scan, then `gradle assembleRelease` in `subdir`. Here: `npx tsc` and
  `node apps/android/assets.mjs` (copy.mjs, then the page into the APK's assets). Both offline.
- Gradle: F-Droid's own (`gradlew-fdroid`), 8.10.2 by the wrapper's version and SHA-256, with
  `LC_ALL=C.UTF-8`, `TZ=Etc/UTC`, `SOURCE_DATE_EPOCH` (unused here), no daemon. It first strips
  `signingConfigs` from `app/build.gradle` (tried: still valid; only the debug build had one).
- Network: neither the docs nor the code cut it off. The build image (Debian trixie,
  `default-jdk-headless`) sets Gradle's network timeouts, and Gradle fetches the plugin from
  Google's Maven during the build. Our network use is `sudo` (Node) and `prebuild` (npm, lockfiles).
- `subdir: apps/android/app`, so the version check (`UpdateCheckMode: Tags`) finds
  `versionCode` in `app/build.gradle`; the listing must then sit in `<subdir>/fastlane/`.
- F-Droid takes no icon from an APK whose launcher icon is XML only (ours, adaptive). So
  `images/icon.png` is in the listing: `node apps/android/icon.mjs` draws it from the GTK app's SVG.

Checked here (fdroidserver 2.4.2): `fdroid lint`, `readmeta` and `rewritemeta` (no change) pass;
`checkupdates --allow-dirty` finds v0.1.10, versionCode 2, in `apps/android/app`. The
recipe's prebuild and build, run from `apps/android/app` on a clean clone, give the same 62 assets,
byte for byte, as a checkout at another path; `vendor.json` unchanged. Not checked here: Gradle
itself (no Android SDK on this machine).

## Two routes

**A. F-Droid signs.** F-Droid builds from the tag and signs with its own key. Nothing for the
operator. But Android updates an app only under the same key: an F-Droid install and a GitHub
APK cannot replace each other, and switching costs an uninstall, which erases what the app holds
(the sealed identity, contacts, history). `release.json` does not cover F-Droid's APK;
`apk-check.sh` refuses it.

**B. Reproducible, our signature.** The recipe has `Binaries:` (the GitHub release's
`sigelo-%v.apk`) and `AllowedAPKSigningKeys:` (the `cert_sha256` of release/apk-ceremony.md).
F-Droid builds the tag, copies our signature onto its build and publishes ours only if it then
verifies (`apksigcopier`, then `apksigner`). One key everywhere; `apk-check.sh` works on F-Droid's
copy. It needs our signed APK to be CI's unsigned one plus the signature, and F-Droid's build to
be CI's, bit for bit.

**Recommended: B**, from the first F-Droid release: moving from A to B later makes every F-Droid
user reinstall and lose what the app holds. A only if B cannot be made to match.

## Determinism (A8)

What can differ between CI and F-Droid's build, and where it stands:

| Input | Finding | Done |
|---|---|---|
| Signing | apksigner (build-tools 35) re-pads the stored entries (`classes.dex`, `resources.arsc`) unless `--alignment-preserved`: v0.1.10's signed APK fails F-Droid's signature copy against CI's own unsigned build (tried with fdroidserver's `verify_apks`) | the ceremony signs with `--alignment-preserved` and checks the signed APK begins with the unsigned one; v0.1.10 stays off F-Droid |
| JDK | javac's output differs between majors; CI had Temurin 17, F-Droid's image Debian's default, 21 | CI on Temurin 21; the recipe sets `java`/`javac` to OpenJDK 21; class files stay Java 17 (`--release` is not possible beside AGP's `-bootclasspath`) |
| D8 | before R8 8.7.20 the dex could depend on the CPU count | AGP 8.8.2 (the newest on Gradle 8.10.2) |
| Deflate | Temurin bundles zlib, Debian's JDK uses the system's | the compare run names "compression only" if so |
| Zip | AGP ≥ 7.1: fixed order, every entry dated 1981-01-01 (seen in v0.1.10's APK) | nothing |
| VCS info | `version-control-info.textproto` says `NO_SUPPORTED_VCS_FOUND` (the Gradle root is not the git root): the same everywhere | nothing |
| Other | no BuildConfig, no dependency (no `baseline.prof`), not minified, javac UTF-8, the page's 71 assets byte-identical across checkouts | encoding pinned |

The compare run, `.github/workflows/android-reproduce.yml` (dispatch only, a report, never red):
v0.1.10 and the dispatched commit, each with Temurin 17 and 21 and Debian 21 (trixie) and 17
(bookworm) in containers run as F-Droid runs Gradle; it names differing entries, copies a throwaway
signature (`--alignment-preserved` and not) onto the Debian builds with apksigcopier, checks the
published v0.1.10 APK the same way, and prints one verdict. If 21 does not match but 17 does: CI
back on 17 and the recipe installs bookworm's `openjdk-17-jdk-headless` (F-Droid offers it).

Status: reproduce runs 2026-10-27 (run 40511324947 on head df93d80, then run 40553318607 on head
1e18586 with build-tools 35.0.1): the unsigned APKs reproduce within each JDK major, Temurin 17 =
Debian 17 and Temurin 21 = Debian 21 for both trees; 17 and 21 differ in classes.dex alone.
Signature copy: a signature made with `--alignment-preserved` copies onto the matching Debian build
on both majors (MATCH); a signature made the v0.1.10 way (apksigner realigns) copies onto neither
(NO MATCH), and the published v0.1.10 APK's signature copies onto neither build for the same reason.
Verdict line: REPRODUCIBLE, CI on Temurin 21 = F-Droid on Debian 21, the recipe as written. So:
v0.1.10 is not reproducible for F-Droid (it predates the ceremony); v0.1.11, signed with
`--alignment-preserved` on JDK 21 (release/apk-ceremony.md), will be. Nothing open on this side; the
merge request follows v0.1.11.

## Steps and who acts

1. Release operator: the release that ships the app (release/RELEASE.md: versionName, versionCode
   + 1, the tag; route B: the APK ceremony, as for GitHub). Nothing else.
2. Maintainer: set the recipe's versionName, versionCode, commit and CurrentVersion to that tag (a
   `changelogs/<versionCode>.txt` with it; check.mjs insists); run `fdroid build io.sigelo.app` in
   F-Droid's container, which fetches `Binaries:` and compares (fdroid/MR.md has the steps).
3. Maintainer: fork fdroiddata, add `metadata/io.sigelo.app.yml`, one merge request ("New App"),
   then wait for the F-Droid reviewers. One concise reply per question; no pings.
4. F-Droid: after the merge, the app appears in 24 to 48 hours. Later tags update by themselves
   (`AutoUpdateMode: Version`, `UpdateCheckMode: Tags`).

## Time

Ready now: listing, icon, recipe, checks, the compare workflow, the merge request text. After the
tag: step 2 about half a day. Review: the queue's pace, often weeks; not ours to speed up.
