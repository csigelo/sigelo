# Apps: your page on a phone

The page of `sigelo-agent ui` comes in three forms:

| Form | Runs | Holds |
|---|---|---|
| The page on the computer | `sigelo-agent ui` | your identity file, on the computer |
| GTK phone app (`apps/gtk`) | this phone, or a computer's page | a SAFE or FULL file, or a control key |
| Android app (`apps/android`) | this phone, or a computer's page | a SAFE or FULL file in the keystore, or a control key |

## Self-contained or remote

**This phone.** The phone holds an identity, SAFE (an own agent, DEVICES.md) or FULL (you,
standby), and talks to the relay itself: the GTK app through `sigelo-agent ui --app`, the Android
app with its own carrier, the file sealed under a keystore key.

**A computer, on the LAN.** The computer runs `sigelo-agent ui --remote [--scope read|chat|all]` and
shows a `SIGELO:UI:` QR; the app scans it, or takes an image or the text. Calls are sealed. The
phone holds no account key, only that control.

**A computer, over the relay.** `ui --remote --relay` shows a `SIGELO:CTL:` code; the app pairs a
control key of its own and shows four words to confirm on the computer. Requests go end to end;
the computer pushes its state.

Devices are never remote. `ui --revoke-control <name>` ends a control.

## Install

- **Computer:** `npm i -g sigelo-agent`, then `sigelo-agent ui`.
- **GTK app:** from a checkout, `sh apps/gtk/install.sh` (into `~/.local`; needs gjs, GTK 4,
  libadwaita, WebKitGTK 6.0). See apps/gtk/README.md.
- **Android app:** from a release that ships it, download `sigelo-<v>.apk` and `release.json`
  (https://sigelo.io/releases/ or GitHub), check them (below), then open the APK on the phone and
  allow installs from that app when asked.

## Check the APK

Every sigelo APK is signed by one key. The release identity signs that key's certificate in
`release.json`, with the APK's SHA-256 and version. In a clone, with `apksigner` (Android SDK
build-tools):

```sh
git clone https://github.com/csigelo/sigelo && cd sigelo && (cd ts && npm ci && npx tsc)
sh release/apk-check.sh sigelo-<v>.apk release.json   # OK, or FAIL and why
```

It checks `release.json` against the pinned release identity, the APK's SHA-256, and that
`apksigner` reports exactly the signed certificate. Once installed, the phone refuses updates
signed by another key.

CI's debug APKs are signed by a throwaway key: for trying the app, never for your identity.
