<!-- SPDX-License-Identifier: MIT -->
# sigelo for Android

The page of `sigelo-agent ui` as an Android app: a WebView around [apps/web](../web/README.md) and a
small bridge in Java for what a page cannot do. No AndroidX, no dependency but the platform; minSdk 28
(Android 9), targetSdk 35. Design: design/apps.md §8.

## Two forms, picked at first start

- **This phone:** the phone holds an identity, SAFE (the file `sigelo-agent device scan` wrote for it
  on your computer) or FULL (the operator's, standby). Import the file once; the app runs its own
  carrier and talks to the relay itself.
- **A computer:** the phone drives the page of a computer running `sigelo-agent ui --remote` on the
  same network. Scan its QR (camera), pick a screenshot of it, or paste its `SIGELO:UI:` text. The
  phone holds no account key, only that computer's text.

The relay is configurable: relay.sigelo.ai by default, set when importing and under Me (codes
name it; a 12-character code always names its own relay).

The menu switches between them. Switching asks first, then erases what the app held for the form it
leaves (its keys and its storage): keep the identity file or your 25 words on the computer. "Forget
the computer" erases the computer's text; revoke it there too (`ui --revoke-control <name>`).

## What the keystore holds

Three AES-256-GCM keys made in AndroidKeyStore, which never leave it:

| Key | Seals |
|---|---|
| `sigelo-identity` | the SAFE identity file |
| `sigelo-identity-full` | the FULL identity file; usable 5 minutes after you confirm the screen lock (no screen lock, no FULL) |
| `sigelo-control` | a computer's `SIGELO:UI:` text |

The sealed files are in the app's private storage, with the contacts, ratchets and history. The seed
is opened at start and lives in the app's memory while it runs. Nothing is in a backup or moved to a
new phone. THREAT-MODEL §3.12 says what this does not defend.

## The bridge (SigeloBridge.java)

The page sees one object, `SigeloShell` (`info()`, `connect()`), and gets a message port for this
origin only. Over it, `sigelo-bridge/0` (listed in `apps/web/platform-android.mjs`):

- `https`: an HTTP request; `https://` to any host, `http://` only to a private IPv4 address (a
  computer on the LAN, every call sealed in the page). No Origin, no cookie, no redirect followed.
- `tls`: a TLS stream (the system's certificate authorities, the host name checked). MQTT on 8883
  is the stream itself; on 443 the page frames WebSocket over it (`apps/web/ws-over-stream.mjs`).
  The relay refuses requests from web pages; these are not.
- `seal`, `open`: the keystore above. `mode`, `wiped`: the form.

The page comes from the APK at `https://appassets.androidplatform.net/` (served by the app, never
fetched); nothing else loads, links open in the browser. JavaScript on, file access off, mixed content
never. The camera: asked at the first scan, for this origin and video only. A file input opens the
system picker. Permissions: INTERNET and CAMERA.

## Build (on CI)

`.github/workflows/android.yml` (ubuntu-24.04, JDK 17, the image's Android SDK) runs on pushes and
pull requests touching `apps/` and its sources, and by hand (Actions, android, Run workflow). It runs
the page's tests, copies the page in, checks the project, then builds:

- `sigelo-<commit>-release-unsigned.apk`: for the operator to sign offline (release/apk-ceremony.md);
- `sigelo-<commit>-debug.apk`: signed with a key made in that run and thrown away;
- `SHA256SUMS`.

The artifact `sigelo-android` holds them for 30 days. No secret is used. Gradle 8.10.2 comes from the
wrapper, pinned by the distribution's SHA-256; the wrapper jar is Gradle's (validated in the run);
the Android Gradle Plugin is pinned to 8.7.3.

F-Droid: not submitted yet; [FDROID.md](FDROID.md) has the readiness, the draft recipe and the
store listing (`app/fastlane/`, its icon drawn by `icon.mjs`).

On a computer with JDK 17 and the Android SDK, the same:

```
cd ts && npm ci && npx tsc && cd ../contact && npm ci && cd ..
node apps/android/assets.mjs              # the page into app/src/main/assets/web/
cd apps/android && ./gradlew assembleDebug
```

## Install the debug APK

Download the artifact, check the APK against `SHA256SUMS` and the run's log, then
`adb install sigelo-<commit>-debug.apk`, or open the file on the phone (allow installs from that app
when Android asks). A debug APK says nothing about who built it: use it to try the app. Each run's
key differs, so a newer debug APK installs only after the older one is uninstalled (which erases
what it held).

## Checks here (no SDK)

```
node apps/android/check.mjs     # → ALL PASS (n)
node apps/android/assets.mjs --check
node apps/web/test-shell.mjs    # the page side over a fake shell in Node
```

`check.mjs`: the manifest and resources (well-formed, two permissions, no backup, references, the
icon as `apps/gtk`'s SVG), Gradle (versions, no dependency), the wrapper by SHA-256, the Java (the
bridge's operations as the page sends them, the WebView's settings, every asset type served), the
workflow (actions pinned by SHA, no secret; strict YAML where PyYAML is). With
`SIGELO_ANDROID_JAR=<a platform's android.jar>` and a JDK, it also compiles the Java against it
(platform 35 clean; 28, the minSdk, only behind SDK_INT checks). Resources link, lint runs and the
app runs only where the SDK is: on CI, and on a phone.
