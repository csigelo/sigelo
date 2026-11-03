<!-- SPDX-License-Identifier: MIT -->
# sigelo on a Linux phone (GTK)

The page of `sigelo-agent ui` as a phone app: GTK 4, libadwaita and WebKitGTK 6.0 under gjs, all
packaged by the phone's Linux distribution. With an identity on this phone it opens straight on its page
(Agents); a standby says so and offers "Take the seat here"; a computer kept from before is reconnected.
Else the first run, the same screens as the Android app (`apps/web/welcome.mjs`, installed beside the start
page): a welcome with three choices, Create a new identity, Restore from 25 words, Connect to my agent
elsewhere, then one decision per screen, Back one step at a time. What each does here:

- **This phone's page:** the app starts `sigelo-agent ui --app` (its identity: `--identity <file>`, else
  `$SIGELO_HUMAN`, else `~/.config/sigelo/me.local.json`, as `ui`), reads the page's address and
  token from its stdout and shows that page. The page stops when the app does. It opens on Agents;
  Enrol makes the one-time code in that page (the CLI's `enrol` refuses `busy` beside it).
- **Create new identity:** `sigelo-agent keeper --new-words` draws 25 words and their wallet's address
  (JSON to the app, piped, never a terminal). The page shows them once, numbered in two columns (copy on
  stagenet only, the clipboard emptied after 60 s), then asks three of them by number; the app checks
  them, never the page. Right: the words go once on stdin to `keeper --from-words --keychain
  --made-here` (the wallet's birth today), then `device seat init`. Linux has no screenshot block.
- **Restore from 25 words:** one box checked as you type (`web/seed-check.mjs`), then a restore
  height or date and the network (the device's name, the seat elsewhere and the relay under Advanced). The words go once,
  on stdin, to `sigelo-agent keeper --from-words --keychain`, which seals your key and K_1 in the keyring
  before anything is written. Then `device seat init` makes this phone the seat. If sigelo already runs
  as you elsewhere, the phone is a standby: its page stays closed until "Take the seat here".
- **The words password** (after a create or a restore, optional; design/apps-seed.md §8): Set encrypts the 25 words in
  the page (`words-lock.mjs`, PBKDF2-SHA256, 1,000,000 rounds) and the app keeps them in the keyring, one item per
  profile; Skip keeps nothing. Me → Security shows them after the password, changes or removes it. The same password
  guards removing the profile and taking the seat (the app compares the page's proof; it never sees the password).
  No lock of its own here: the session's login, then the password.
- **Connect, on the LAN** (Advanced): the computer runs `sigelo-agent ui --remote`; the app scans its QR, reads it from an
  image, or takes the pasted `SIGELO:UI:` text, and drives that computer's page. Every call is sealed
  in the app (sigelo-remote/0, UI-API.md "Remote"); the page's files are the app's own. The phone
  holds no account key: only the text, kept in the keyring (else for this run only).
  "Forget the computer" (menu) drops it here; `ui --revoke-control <name>` on the computer ends it.
- **Connect to my agent elsewhere:** the computer runs `ui --remote --relay`; the app takes its 8-character `SIGELO:CTL:`
  code, `sigelo-agent control pair` makes this phone's control key (`~/.config/sigelo/control.local.json`,
  0600, never attested) and shows four words to confirm on the computer; then `control ui --app` serves
  that computer's page here, each call a relay message, the state pushed.

## Profiles

Up to 8 profiles (design/profiles.md P1), each its own files: Profile 1 those of before (`me.local.json`, the keyring
text, `control.local.json`, the standby mark); profile `<id>` `me.<id>.local.json` beside it (keeper beside it, wrapped
in the keyring under its own DID), `control.<id>.local.json`, the keyring text under its own kind, `standby.<id>`; the
list in `profiles.json` beside them (0600, no secret). Only the active profile's page runs (`ui --app --identity <its
file>`; its verbs see `SIGELO_HUMAN` and `SIGELO_CONTROL` naming its files). More than one at the app's start: the
picker. Me → Profiles: switch, rename, add, remove (its files, its keyring items and this phone's device file of it in
the agents' directory; a words profile needs "I have the 25 words" and its name typed). No lock of its own here.

A remote profile holds up to 8 computers (design/profiles.md P2), listed in its `profiles.json` entry; one is in use.
The first keeps the files of before; computer `<cid>` has its LAN text in the keyring under kind `sigelo-remote/0[ <id>]
<cid>` with the attribute `computer`, its relay control in `control[.<id>].<cid>.local.json`. Me → Connect →
Computers: switch, add (the pairing screens; over the relay `control pair --operator <the profile's>`), forget (its
keyring item or `control forget`; revoke it on the computer too). Another operator's page is refused `other_operator`.

## Install (no root)

From a checkout with `npm ci` done in `contact/` and `ts/` (and `npm run build` in `ts/`):

```
sh apps/gtk/install.sh            # into ~/.local; --prefix <dir>, --dry-run, --uninstall
```

It installs `~/.local/bin/sigelo-app`, `~/.local/share/sigelo-app/`, the desktop file
`io.sigelo.App.desktop` and the icon. Files are copied as they are. "This phone" uses
`sigelo-agent` on PATH, else the checkout's CLI under node (written to `share/sigelo-app/agent.json`;
`SIGELO_AGENT` overrides). Needs: `gjs`, `gtk4.0`, `libadwaita`, `webkit2gtk-6.0`, `libsoup3`,
`libsecret` (optional); node for "This phone".

## Scanning

The decoder is `contact/qr-decode.mjs` (design/devices.md §6.4), installed when the checkout has it;
without it, paste the text. Camera: WebKit's `getUserMedia`, the camera only, the start page and this phone's Devices view only.
Where WebKitGTK finds no camera (0 devices): take a photo with the Camera app and use
"From an image", or paste a screenshot. What is scanned is held in memory until it is used.

## Rules the app keeps

- Pages come from `sigelo-app://app/` (the files of `share/sigelo-app/web/` by name, CSP
  `default-src 'self'`) or, for "This phone", from that `ui` page's address; any other link opens in
  the browser.
- The bridge (`sigelo` script message handler) answers only the start page (start, connect, forget)
  and `ui.html` (sealed calls); the local page only its profile operations (Me → Profiles).
- No microphone; nothing remote is loaded.

## Tests

```
node apps/gtk/test-gtk.mjs        # needs gjs; no window
```

install.sh (dry run, install, uninstall), the desktop file, the start page's scripts, and the installed
app under gjs (`SIGELO_APP_TEST`): sealed calls to a real `ui --remote` (scope, malformed, revoked, gone),
"This phone" through `ui --app`, and a computer over the relay (pair, words, `control ui --app`). `SIGELO_APP_DEVTOOLS=1` turns on the inspector and the console.
