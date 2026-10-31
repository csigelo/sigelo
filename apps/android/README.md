<!-- SPDX-License-Identifier: MIT -->
# sigelo for Android

The page of `sigelo-agent ui` as an Android app: a WebView around [apps/web](../web/README.md) and a
small bridge in Java for what a page cannot do. No AndroidX, no dependency but the platform; minSdk 28
(Android 9), targetSdk 35. Design: design/apps.md §8.

## The first run

A welcome with three choices, then one decision per screen (`apps/web/welcome.mjs`, shared with the
GTK phone app); Back goes one screen back (the page keeps one history entry per screen; the system
Back follows it, and leaves the app only from the first screen). The form, this phone or a computer, is
set only when a path commits.

- **Create new identity:** the phone makes 25 new words (as `newRoot`: the system's randomness, a
  canonical Monero seed) and shows them once, numbered 1 to 25, with the address of their own Monero
  wallet. That screen blocks screenshots, ignores Back and has one way on: "I have written down my 25
  words". Copy is offered on stagenet only (the clipboard is marked sensitive and emptied after 60 s).
  Then three words are asked by number; a wrong one goes back to the words. Right: the identity and
  K_1 are made from them as a restore makes them, sealed under the FULL key, and the phone holds the
  seat. The words are gone after; Me says "Created on <day>; the 25 words are on your paper".
- **This phone:** the phone holds an identity, SAFE (the file `sigelo-agent device scan` wrote for it
  on your computer). Import the file once (Advanced, on the welcome); the app runs its own carrier and talks to the relay
  itself. The operator's file (FULL) is not imported: restore from seed (design/apps.md §18).
- **Restore from seed:** your 25 words make the operator identity and your keeper root K_1 again on
  the phone (FULL), as `sigelo-agent keeper --from-words` does on a computer. First "I have my 25
  words on paper", then one box: the words are checked as you type (count, word list, checksum),
  pasting is allowed and the clipboard is cleared after it, and screenshots are blocked while the
  screen is up. Add a restore height or date, the network and the device's name. Both files are sealed under the FULL key
  (your screen lock is asked); the words are kept nowhere and never shown back. The phone takes the
  seat, or, if sigelo already runs as you elsewhere, waits as a standby until "Take the seat here".
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
| `sigelo-identity-full` | the FULL identity file and, after a restore from seed, the keeper root (its own AAD); usable 5 minutes after you confirm the screen lock (no screen lock, no FULL) |
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
- `seal`, `open`: the keystore above (kinds `identity`, `keeper`, `control`). `mode`, `wiped`: the form.
- `secure`: `FLAG_SECURE` on the window while the restore screen is up (no screenshot, no recents
  thumbnail), off after; with `door` (a new identity's words) the system Back does nothing meanwhile.
  `clip-clear`: the clipboard emptied after the 25 words were pasted. `share`: the system's share
  sheet with a ready-to-send message (a code, until when, the instructions link). `clip-copy`: stagenet words on
  the clipboard, marked sensitive (no preview), emptied by the shell after 60 s.

The page comes from the APK at `https://appassets.androidplatform.net/` (served by the app, never
fetched); nothing else loads, links open in the browser. JavaScript on, file access off, mixed content
never. The camera: asked at the first scan, for this origin and video only. A file input opens the
system picker. Permissions: INTERNET and CAMERA.

## Build (on CI)

`.github/workflows/android.yml` (ubuntu-24.04, JDK 21 as F-Droid's build server, the image's Android SDK) runs on pushes and
pull requests touching `apps/` and its sources, and by hand (Actions, android, Run workflow). It runs
the page's tests, copies the page in, checks the project, then builds:

- `sigelo-<commit>-release-unsigned.apk`: for the operator to sign offline (release/apk-ceremony.md);
- `sigelo-<commit>-debug.apk`: signed with a key made in that run and thrown away;
- `SHA256SUMS`.

The artifact `sigelo-android` holds them for 30 days. No secret is used. Gradle 8.10.2 comes from the
wrapper, pinned by the distribution's SHA-256; the wrapper jar is Gradle's (validated in the run);
the Android Gradle Plugin is pinned to 8.8.2.

F-Droid: not submitted yet; [FDROID.md](FDROID.md) has the readiness, the draft recipe and the
store listing (`app/fastlane/`, its icon drawn by `icon.mjs`).

On a computer with JDK 21 and the Android SDK, the same (another JDK major gives other bytes):

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
