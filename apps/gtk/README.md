<!-- SPDX-License-Identifier: MIT -->
# sigelo on a Linux phone (GTK)

The page of the UX1 rebuild (`apps/agent/ui.html`, `ui.js`; design/ux1/build.md) as a phone app: GTK 4, libadwaita
and WebKitGTK 6.0 under gjs, all from the distribution. With an identity here it opens on that page; a standby
offers "Take the seat here"; a computer kept from before is reconnected. Else the first run (`apps/web/welcome.mjs`,
shared with the Android app): create, restore from 25 words, or use a computer instead.

- **This phone's page:** the app starts `sigelo-agent ui --app` (`--identity <file>`, else `$SIGELO_HUMAN`, else
  `~/.config/sigelo/me.local.json`), reads its address and token from stdout, shows it; it stops with the app.
- **Create:** `sigelo-agent keeper --new-words` draws 25 words; shown once, three asked back (the app checks them,
  never the page); then on stdin to `keeper --from-words --keychain --made-here` and `device seat init`.
- **Restore:** the words checked as typed (`web/seed-check.mjs`), then once on stdin to `keeper --from-words
  --keychain` (key and K_1 sealed in the keyring first). Seat elsewhere: a standby until "Take the seat here".
- **The lock:** no screen lock of the app's own here, so the page's words password stands in (`apps/contact/words-lock.mjs`,
  PBKDF2-SHA256, 1,000,000 rounds; the blob in the keyring, one item per profile). It guards Backup and recovery,
  removing a profile and taking the seat; the app compares the page's proof and never sees the password.
- **A computer, on the LAN:** its `ui --remote` QR or `SIGELO:UI:` text; every call sealed here (sigelo-remote/0,
  `apps/agent/remote-client.mjs`), the page's files the app's own. Only the text is kept (keyring).
- **A computer, over the relay:** its 8-character `SIGELO:CTL:` code, `sigelo-agent control pair` (a control key,
  `~/.config/sigelo/control.local.json`, 0600), four words to compare, then `control ui --app` serves its page here.
- **Notifications, the name only:** a new message or a payment request raises a system notification with the
  sender's, group's or agent's name and a generic line, never the text. A tap opens that chat or request. Raised
  only while the app runs (no background service); the app is single-instance so a tap reaches it.
- **About:** the version is `apps/agent/package.json`'s, installed as `web/package.json` (no hand edit).

Profiles (up to 8, design/profiles.md P1) and a remote profile's computers (up to 8, P2): Settings → Profiles and
Me → Connect → Computers; each profile its own files and keyring items; another operator's page is refused.

## Install (no root)

From a checkout with `npm ci` in `apps/contact/` and `ts/`, and `npm run build` in `ts/`:

```
sh apps/gtk/install.sh            # into ~/.local; --prefix <dir>, --dry-run, --uninstall
```

`~/.local/bin/sigelo-app`, `~/.local/share/sigelo-app/` (the app, `lib/`, `web/`), `io.sigelo.App.desktop`, the
icon (`assets/brand/app-icon.svg`). Files copied as they are. "This phone" uses `sigelo-agent` on PATH, else the
checkout's `apps/agent/cli.ts` under node (`share/sigelo-app/agent.json`; `SIGELO_AGENT` overrides). Needs `gjs`,
GTK 4, libadwaita, WebKitGTK 6.0, libsoup 3, libsecret (optional); node for "This phone".

## Rules the app keeps

- Pages come from `sigelo-app://app/` (the files of `web/` by name, CSP `default-src 'self'`) or this phone's `ui`
  address; any other link opens in the browser. Camera for scanning only (`apps/contact/qr-decode.mjs`), no microphone.
- The bridge (`webkit.messageHandlers.sigelo`, `postMessage({op, ...})` → `{ok, ...}`): the start page all but `call`
  and `notify`; `ui.html` (a computer's page) `call`, the profile operations and `notify`; this phone's page the
  profile operations and `notify`.
- `notify {tag, title, text}` or `{tag, cancel: true}`: tag `chat:|group:|pay:` + `[A-Za-z0-9:._-]{1,200}`, title
  (the name) and text (a generic line) at most 100 characters, nothing else; else `{ok: false, check: 'notify'}`.
  The tap (`app.open`, the tag) presents the window and runs `globalThis.sigeloOpen?.("<tag>")` in the page.

## Tests

```
node apps/gtk/test-gtk.mjs        # needs gjs; no window, no notification raised
```

install.sh, the desktop file, the start page's scripts, and the installed app under gjs (`SIGELO_APP_TEST`): a real
`ui --remote`, "This phone" through `ui --app`, a computer over the relay, restore, create, profiles, computers, the
words password, and `notify` (recorded, not sent) with the tap's `sigeloOpen`. `SIGELO_APP_DEVTOOLS=1`: the inspector.
