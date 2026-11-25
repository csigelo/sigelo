<!-- SPDX-License-Identifier: MIT -->
# sigelo for Android

The page of `sigelo-agent ui` as an Android app: a WebView around [apps/web](../web/README.md) and a
small bridge in Java for what a page cannot do. No AndroidX, no dependency but the platform; minSdk 28
(Android 9), targetSdk 35. Design: design/apps.md §8. No action bar: the page's own top bar is the
top, the status and navigation bars take its background; Reload is in Settings → About.

## The first run

The mock's screens (`apps/web/welcome.mjs`, shared with the GTK phone app), one decision each; Back goes
one screen back (one history entry per screen; the system Back follows it and leaves the app only from the
first screen). The form, this phone or a computer, is set only when a path commits.

- **Create my identity:** Name this phone, then Keep it safe. *Write down 25 words:* drawn on the phone
  (the system's randomness, a canonical Monero seed), shown once, numbered 1 to 25; that screen blocks
  screenshots (`FLAG_SECURE`), ignores Back and has one way on, "I wrote them down"; copy on the test
  network only (marked sensitive, emptied after 60 s). Three words asked back by number; wrong goes back
  to the words. *Set a password:* the words are kept on the phone under it, never shown (Settings →
  Backup and recovery shows them after the screen lock and the password). Either way the identity and K_1
  are made as a restore makes them, sealed under the FULL key, this phone holding the seat. Then Lock (the
  screen lock once) and You're set (the four words).
- **I have an invite code:** the code first, then the name and Keep it safe; the app pairs with it once open.
- **Restore from 25 words:** one screen: the words checked as you type (count, word list, checksum;
  pasting allowed, the clipboard cleared after it, screenshots blocked), the month they were made, and
  "Is this identity already in use on another device?" (main or spare). Sealed under the FULL key; the
  words are kept nowhere. A spare waits until "Make this phone the main one".
- **Use my computer instead:** the phone drives a computer's `sigelo-agent ui --remote`: scan its QR or
  type its code, compare four words. The phone holds no account key, only that computer's control.
- **Advanced:** import the SAFE file `sigelo-agent device scan` wrote for this phone.

The relay is configurable: relay.sigelo.ai by default, set when importing and under Me (codes
name it; a 12-character code always names its own relay).

## Profiles

Up to 8 profiles, each an identity (or a computer's page) with its own storage and keystore keys
(design/profiles.md P1). An install of before becomes Profile 1 as it is (nothing resealed). With more
than one, the app starts on a picker (name, four words, what it holds), then the lock. Me → Profiles:
switch (the lock once; the new profile asks nothing more), rename, add (its first run, with "Back to my
profiles"), remove: a profile holding an identity needs "I have the 25 words" ticked and its name typed,
then the lock; its storage and its keystore keys are erased (a computer keeps the pairing until revoked
there: `ui --revoke-control <name>`). Only the profile in use connects. The menu's former form switch,
which erased everything, is gone.

A remote profile holds up to 8 computers (design/profiles.md P2), one in use. Me → Connect → Computers: switch (the lock
once), add (the pairing screens: code or scan), forget (the lock; its control key goes from this phone; revoke it on
the computer: `ui --revoke-control <name>`). A computer serving another identity is refused `other_operator`. Each
computer's text or control identity is sealed under the profile's keys, a blob naming that computer (version 2,
`<profile>:<computer>`); the first keeps its blob of before.

## What the keystore holds

Three AES-256-GCM keys per profile made in AndroidKeyStore, which never leave it (Profile 1: the names
below, blobs of version 1 as before; profile `<id>`: `sigelo-<id>-identity`, `-identity-full`, `-control`, blobs of
version 2 naming it, the AAD naming kind and profile, so no blob opens in another profile):

| Key | Seals |
|---|---|
| `sigelo-identity` | the SAFE identity file |
| `sigelo-identity-full` | the FULL identity file and, after a restore from seed, the keeper root and the kept words (kind `words`, already encrypted under the words password), each its own AAD; usable 5 minutes after you confirm the screen lock (no screen lock, no FULL) |
| `sigelo-control` | a computer's `SIGELO:UI:` text |

## The lock

With a screen lock set, the app asks it at each start and at a return after 1, 5, 15 or 60 minutes away
(Settings → Lock; 1 by default), or at neither when the lock is off. The page stays hidden until it is
confirmed; not confirmed, the app goes to the background, locked. Turning it off or lengthening it asks the
screen lock first. Whether it is on or off, the screen lock is asked before the 25 words are shown, at a
profile switch and before a payment above the pay limit (not again within a minute of the last
confirmation, except that payment). The FULL key's 5 minutes stay the inner guard.

## Notifications

A new message, a group's message or a payment request: a system notification with the sender's, the
group's or the agent's name and a generic line ("New message"), never the message's text. On the lock
screen only "sigelo" and "New message". One channel, "Messages and payment requests". A tap opens that
chat, group or request. Android 13 and later ask the permission when the page first asks.

The sealed files are in the app's private storage, with the contacts, ratchets and history. The seed
is opened at start and lives in the app's memory while it runs. Nothing is in a backup or moved to a
new phone. THREAT-MODEL §3.12 says what this does not defend.

## Stay connected

*Since 2026-11-25 no longer a choice in Settings: Built in push (below) keeps the process instead; this service
still runs the push app's wake window.* Stay connected (off by default; one setting for the phone): the app keeps
its relay connection while minimised, so messages arrive and a call can ring. StayConnected.java is a
foreground service of type `specialUse` that owns no socket: the connection is the page's (the carrier
in the WebView, its TLS stream in SigeloBridge), and the service keeps that process at foreground
priority. It starts as the app leaves the screen (onPause) and shows one silent notification,
"sigelo · connected" (channel "Connection", low importance); a tap opens the app. Back on the first
screen minimises the app instead of closing it. Removed from the recent apps, the page ends and the
service with it (`stopWithTask`); it is not started at boot, since without the page there is nothing
to keep. No wake lock. An inexact alarm every 15 minutes (`setAndAllowWhileIdle`) and the end of Doze
send the page `{ev:"nudge"}`: the carrier reconnects, with its backoff, when it is down.

Asks: turning the switch on asks what is missing, one at a time, each after one line why: notifications,
then the battery exemption (`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`); never at a start. A refusal
is never final: Settings shows a row that says what it costs, and its tap asks again, or once Android
stops asking (two refusals), opens the app's page in the system's settings. Notifications denied, the
service runs all the same; Android 13+ then shows its notice only in the quick settings' list of
active apps. Not yet measured on a phone: the battery cost, Doze, vendor task killers.

## Push (Built in, or UnifiedPush)

Settings → Notifications chooses the push mode for the phone: Built in (the default), Push app, or Off. Stay
connected (above) is no longer a choice: Built in keeps the process the same way, and a phone that had it on
starts in Built in (Push → Push app, Off stays Off).

**Built in** (design/push.md §6, PushClient.java, Ntfy.java): the app holds one HTTPS stream itself, the ntfy JSON
stream of its own topic on `push.sigelo.ai` (`up` + 12 random `[A-Za-z0-9]`, the length ntfy takes as UnifiedPush),
in a foreground service of type `specialUse` that survives a swipe-away (`stopWithTask` false, `START_STICKY`, a 1 s
restart alarm at `onTaskRemoved`) and starts at boot and after an update (`PushClient$Boot`, `RECEIVE_BOOT_COMPLETED`).
One notification, "Sigelo · ready for messages" (the Connection channel, low importance). The endpoint
`https://push.sigelo.ai/<topic>?up=1` goes to the page and the relay only after the stream's first `open` (ntfy
refuses a publish with no subscriber, 507). A message that opens to the wake is handled as below, with a 30 s wake
lock; `since` the last message id, so wakes sent while offline come at the next connect (12 h cache). Reconnects:
5, 10, 15, 20, 30, 45, 60, 120 s (the ntfy app's table), at once on a new network; 90 s read timeout. Choosing Built
in asks for notifications, then once for the battery exemption, each after one line why; with Built in the
mode, the first run asks for the exemption once too (refused: Settings' row only). Force-stopped: nothing
until the app is opened again.

**Push app** (design/push.md §1 B) hands the connection to the user's UnifiedPush app (a "distributor": ntfy from F-Droid,
NextPush, Sunup, Conversations), which holds one for all its apps; ntfy users without a server of their own
set it to `push.sigelo.ai` (relay/deploy/ntfy/README.md). UnifiedPush.java is the connector, written against
the spec (AND_3) without the library (no Kotlin, no Tink, no AndroidX): it finds the distributors (receivers
of `org.unifiedpush.android.distributor.REGISTER`, the manifest's `<queries>`), registers with a random
token, takes NEW_ENDPOINT, REGISTRATION_FAILED, UNREGISTERED, TEMP_UNAVAILABLE and MESSAGE only when they name
that token, acknowledges each message, and offers RAISE_TO_FOREGROUND (UnifiedPush$Raise). WebPush.java opens
RFC 8291 messages with platform crypto; its P-256 key and auth secret are sealed under the keystore key
`sigelo-push` (no user authentication: a wake opens while the phone is locked) and erased when push is
turned off. The page gives the endpoint and keys to its carrier, which registers them at its relay
(`sigelo-push/0`); the relay sends a 32-byte encrypted wake when mail waits and no session is open.

A wake that opens to the relay's 32 bytes: with the page alive (minimised, its process kept), StayConnected
runs for 60 s (the wake window) and the page's carrier logs in at once and fetches; its own notifications
follow, with names. With no page (swiped away, or not opened since the phone started), one notification,
"sigelo · New activity", no name, no count; a tap opens the app, which fetches. A call rings only once the
app is open. No push app installed: Settings says so, with what to install, and offers Built in. Not
yet measured on a phone: the delay of a wake, a distributor's own battery cost.

Choices where design/push.md left one: the wake's 32 bytes are `"sigelo-push/0 wake"` and zeros, compared after
opening; the relay always sends VAPID (RFC 8292) and the connector gives no VAPID key at REGISTER (optional in AND_3);
the registration rides the MQTT session (`$sigelo/push`, offered by GET /challenge), sealed at rest under a key file
beside the relay's database, 90 days; one wake per gap, a later one at least 5 s after the last (held, not dropped).
One registration per phone, given to the relay of each profile that runs: an inactive profile's mail wakes the
phone, which fetches for the active profile only (as without push). Departure from the design: Stay connected keeps
the process, not the WebView, so a wake with no page alive cannot open the identity and fetch in the background; it
shows "New activity" and the app fetches when opened.

## The bridge (SigeloBridge.java)

The page sees one object, `SigeloShell` (`info()`, `connect()`), and gets a message port for this
origin only. Over it, `sigelo-bridge/0` (listed in `apps/web/platform-android.mjs`):

- `https`: an HTTP request; `https://` to any host, `http://` only to a private IPv4 address (a
  computer on the LAN, every call sealed in the page). No Origin, no cookie, no redirect followed.
- `tls`: a TLS stream (the system's certificate authorities, the host name checked). MQTT on 8883
  is the stream itself; on 443 the page frames WebSocket over it (`apps/web/ws-over-stream.mjs`).
  The relay refuses requests from web pages; these are not.
- `seal`, `open`: the keystore above (kinds `identity`, `keeper`, `words`, `control`; `profile`, p1 when none). `forget-profile`:
  a profile's three keys deleted (its removal). `mode`: the active profile's form; `wiped`: an older version's switch.
- `secure`: `FLAG_SECURE` on the window while the restore screen or the kept words are up (no screenshot, no recents
  thumbnail), off after; with `door` (a new identity's words) the system Back does nothing meanwhile.
  `clip-clear`: the clipboard emptied after the 25 words were pasted. `share`: the system's share
  sheet with a ready-to-send message (a code, until when, the instructions link). `clip-copy`: stagenet words on
  the clipboard, marked sensitive (no preview), emptied by the shell after 60 s.
- `unlock` (the screen lock; `force` skips the minute's window), `lock` (the lock's settings, kept by the shell),
  `notify` (show, cancel, ask the permission); the shell's event `{ev:"open", tag}` when a notification is tapped.
- Big files (`BigFiles.java`, design/transfer.md §10): `big-pick` (the system's document picker, the read grant
  kept), `big-photo` (the system's camera into the app's cache through `PhotoProvider`, not exported; CAMERA asked
  at the first photo; location tags removed unless kept), `big-hash`, `big-stat`; the page reads a file by range
  at `/.big/<doc>` (409 once it changed); `big-write` / `big-flush` / `big-digest` / `big-drop` a partial in
  private storage; `big-land` moves it into Downloads (MediaStore, pending until whole; Android 9 asks the storage
  permission); `big-open`; `big-awake` keeps the screen on while a transfer moves.
- Share into sigelo (0.1.20): a share target (`ACTION_SEND`: text, pictures, any file; no new permission). The shell holds one share,
  the latest winning, and tells the page `{ev:"share"}` (behind the lock); `share-take` makes a file a doc of the profile, sent as a
  picked one is; `share-drop`. A `file://` or this app's own URI is refused.

The page comes from the APK at `https://appassets.androidplatform.net/` (served by the app, never
fetched); nothing else loads, links open in the browser. JavaScript on, file access off, mixed content
never. The camera: asked at the first scan, for this origin and video only. A file input opens the
system picker. Permissions: INTERNET, CAMERA, RECORD_AUDIO (asked at the first voice message or call), POST_NOTIFICATIONS,
and WRITE_EXTERNAL_STORAGE on Android 9 only (Downloads; later versions need none); without a prompt, Stay connected's
FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE and REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, and a call's
FOREGROUND_SERVICE_MICROPHONE (the microphone kept with the screen locked), MODIFY_AUDIO_SETTINGS (earpiece, speaker),
WAKE_LOCK (the proximity screen-off at the ear), VIBRATE (the ring) and ACCESS_NETWORK_STATE (Wi-Fi to mobile data
restarts the call's path). One provider, not exported: the photo a camera app writes.

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
cd ts && npm ci && npx tsc && cd ../apps/contact && npm ci && cd ../..
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

`node apps/android/test-push.mjs` runs WebPush.java's RFC 8291 vectors and Ntfy.java's tests (topic, endpoint, the stream's lines, the wake as ntfy carries it, the retry table) on a desktop JDK (`SIGELO_JDK` or `JAVA_HOME`; SKIP without one).

`check.mjs`: the manifest and resources (well-formed, fourteen permissions (storage up to Android 9), one provider not exported, the push receivers and services, no backup, references, the
icon as `assets/brand/app-icon.svg`), Gradle (versions, no dependency), the wrapper by SHA-256, the Java (the
bridge's operations as the page sends them, the WebView's settings, every asset type served, the lock,
notifications and their open event), the version (build.gradle's = `apps/agent/package.json`'s, shipped as
`vendor/package.json`), the F-Droid recipe's steps walked over the tree, the
workflow (actions pinned by SHA, no secret; strict YAML where PyYAML is). With
`SIGELO_ANDROID_JAR=<a platform's android.jar>` and a JDK, it also compiles the Java against it
(platform 35 clean; 28, the minSdk, only behind SDK_INT checks). Where `java` runs a source file (JDK 11+), it
runs the bridge's own keystore methods (seal, open, aliases, forget-profile) on the profiles' cases with a software
key store. Resources link, lint runs and the
app runs only where the SDK is: on CI, and on a phone.
