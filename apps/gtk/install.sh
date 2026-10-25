#!/bin/sh
# SPDX-License-Identifier: MIT
# Installs the GTK phone app (design/apps.md §7) for this user, no root:
#   <prefix>/bin/sigelo-app, <prefix>/share/sigelo-app/, <prefix>/share/applications/io.sigelo.App.desktop,
#   <prefix>/share/icons/hicolor/scalable/apps/io.sigelo.App.svg        (prefix: ~/.local)
# Run from a checkout with contact/node_modules and ts/dist (npm ci in contact/, npm run build in ts/).
#   sh apps/gtk/install.sh [--prefix <dir>] [--dry-run] [--uninstall]
set -eu
PREFIX="$HOME/.local" DRY=0 UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || { echo "install.sh: --prefix <dir>" >&2; exit 2; }; PREFIX="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "install.sh: unexpected $1 (--prefix <dir>, --dry-run, --uninstall)" >&2; exit 2 ;;
  esac
done
HERE=$(cd "$(dirname "$0")" && pwd) REPO=$(cd "$(dirname "$0")/../.." && pwd)
SHARE="$PREFIX/share/sigelo-app" BIN="$PREFIX/bin" APPS="$PREFIX/share/applications" ICONS="$PREFIX/share/icons/hicolor/scalable/apps"
run() { if [ "$DRY" = 1 ]; then echo "$*"; else "$@"; fi; }

if [ "$UNINSTALL" = 1 ]; then
  run rm -rf "$SHARE"
  run rm -f "$BIN/sigelo-app" "$APPS/io.sigelo.App.desktop" "$ICONS/io.sigelo.App.svg"
  exit 0
fi

# What the app needs on the phone (design/apps.md §2): gjs, GTK 4, libadwaita, WebKitGTK 6.0, libsoup 3.
command -v gjs >/dev/null || { echo "install.sh: gjs not found (apk add gjs)" >&2; exit 1; }
for t in Gtk-4.0 Adw-1 WebKit-6.0 Soup-3.0; do
  found=0; for d in /usr/lib/girepository-1.0 /usr/lib64/girepository-1.0 /usr/lib/*/girepository-1.0; do [ -f "$d/$t.typelib" ] && found=1; done
  [ "$found" = 1 ] || echo "install.sh: warning: typelib $t not found; the window will not open" >&2
done
NOBLE="$REPO/contact/node_modules/@noble/ciphers" JCS="$REPO/ts/dist/jcs.js"
[ -f "$NOBLE/chacha.js" ] || { echo "install.sh: $NOBLE missing: npm ci in contact/" >&2; exit 1; }
[ -f "$JCS" ] || { echo "install.sh: $JCS missing: npm ci && npm run build in ts/" >&2; exit 1; }

# Files are copied as they are (what the tests ran is what runs).
run mkdir -p "$SHARE/lib/noble-ciphers" "$SHARE/web" "$BIN" "$APPS" "$ICONS"
run cp "$HERE/sigelo-app.js" "$SHARE/"
run cp "$REPO/adapters/moadim/remote-client.mjs" "$JCS" "$SHARE/lib/"
for f in chacha.js _arx.js _poly1305.js utils.js LICENSE; do run cp "$NOBLE/$f" "$SHARE/lib/noble-ciphers/"; done
for f in start.html start.js start.css seed-check.mjs; do run cp "$HERE/web/$f" "$SHARE/web/"; done
# The Monero word list for the start page's live check of the 25 words (data only, from ts/dist).
run cp "$REPO/ts/dist/monero-words.js" "$SHARE/web/"
for f in ui.html ui.js ui.css icon.svg shim-zlib.mjs shim-kdf.mjs; do run cp "$REPO/adapters/moadim/$f" "$SHARE/web/"; done
# QR reading (contact/qr-decode.mjs, design/devices.md §6.4) where this checkout has it; else paste only.
if [ -f "$REPO/contact/qr-decode.mjs" ] && [ -f "$REPO/contact/qr.mjs" ]; then
  run cp "$REPO/contact/qr-decode.mjs" "$REPO/contact/qr.mjs" "$SHARE/web/"
else
  echo "install.sh: no contact/qr-decode.mjs in this checkout: scanning off, paste works" >&2
fi
# How to start this phone's page: sigelo-agent on PATH, else this checkout's CLI under node.
if ! command -v sigelo-agent >/dev/null; then
  if command -v node >/dev/null && [ -d "$REPO/adapters/moadim/node_modules" ]; then
    if [ "$DRY" = 1 ]; then echo "write $SHARE/agent.json: [node, $REPO/adapters/moadim/cli.ts]"
    else node -e 'process.stdout.write(JSON.stringify(process.argv.slice(1)))' "$(command -v node)" "$REPO/adapters/moadim/cli.ts" > "$SHARE/agent.json"; fi
  else
    echo "install.sh: no sigelo-agent and no built checkout: \"This phone\" will not start (a computer's page works)" >&2
  fi
fi
if [ "$DRY" = 1 ]; then echo "write $BIN/sigelo-app: exec gjs -m $SHARE/sigelo-app.js"
else printf '#!/bin/sh\nexec gjs -m "%s/sigelo-app.js" "$@"\n' "$SHARE" > "$BIN/sigelo-app"; chmod 755 "$BIN/sigelo-app"; fi
if [ "$DRY" = 1 ]; then echo "write $APPS/io.sigelo.App.desktop: Exec=$BIN/sigelo-app"
else sed "s|^Exec=sigelo-app\$|Exec=$BIN/sigelo-app|" "$HERE/io.sigelo.App.desktop" > "$APPS/io.sigelo.App.desktop"; fi
run cp "$REPO/assets/brand/app-icon.svg" "$ICONS/io.sigelo.App.svg"
[ "$DRY" = 1 ] || { command -v update-desktop-database >/dev/null && update-desktop-database -q "$APPS" 2>/dev/null || true; }
[ "$DRY" = 1 ] || echo "installed: $BIN/sigelo-app (the app list shows sigelo)"
