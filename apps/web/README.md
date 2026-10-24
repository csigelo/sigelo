<!-- SPDX-License-Identifier: MIT -->
# apps/web: the self-contained app

The page of `sigelo-agent ui` running its own carrier: no computer, no Node. `ui.js` talks to an
in-page router (the `local` backend) that implements the routes of
[UI-API.md](../../adapters/moadim/UI-API.md) over a carrier on a browser platform, with the same JSON.
The Android app (apps/android) loads these files with its own network and key; a plain browser tab can
too, for testing.

```
node apps/web/copy.mjs          # vendor what the page imports into apps/web/vendor/ (ts/: npx tsc first)
node apps/web/copy.mjs --check  # vendor/ and vendor.json are as their sources
node apps/web/test-web.mjs      # → ALL PASS (n); the relay checkout beside it, else part 3 SKIPs
node apps/web/test-shell.mjs    # the Android app's page side over a fake shell → ALL PASS (n)
```

## Files

| File | What |
|---|---|
| `index.html` | The page: `ui.js`, its CSS and icon, an import map (the one inline script), `app.mjs` |
| `app.mjs` | Start: the platform, the identity, the router; sets `globalThis.sigeloLocal` for `ui.js` |
| `router.mjs` | The `local` backend: `call(method, path, body)` → `{status, body}`, `onChange`, `mode` |
| `platform-web.mjs` | The browser platform of sigelo-contact (design/apps.md §4.2) |
| `pow-worker.mjs` | The relay login's proof of work, in a module Worker |
| `platform-stub.mjs` | Loaded instead of `contact/platform-node.mjs` (import map): no Node default in a page |
| `platform-android.mjs` | In the Android app: the bridge (`sigelo-bridge/0`), the shell's fetch, MQTT and key |
| `ws-over-stream.mjs` | RFC 6455 client framing over the shell's TLS stream (wss), and the stream as a socket (mqtts) |
| `shell.mjs` | In the Android app: the form picked at first start; the remote form (a computer's page, on the LAN or over the relay) |
| `copy.mjs` | The vendoring: walks the import graph, copies each file byte for byte, writes `vendor.json` |
| `vendor.json` | Every vendored file, its source and SHA-256 (committed; `vendor/` is not) |
| `test-web.mjs`, `test-shell.mjs` | The tests, in Node, through the same import map (`test-fakes.mjs`: IndexedDB, Worker) |

## The seam

`ui.js` picks its backend at load: `shell` in the GTK phone app (remote control), `local` when
`app.mjs` set `globalThis.sigeloLocal`, else `http` (the computer's `ui`). The router is
`contact/page.mjs`, the module `sigelo-agent ui` serves its routes from, so a route answers the same
JSON here; what the app does not have answers as nothing: `GET /api/agents` is `[]`, enrolling or
pairing an agent `404 agent`, `GET /api/devices` an empty list, adding, scanning or revoking a device
`409 not_here` (that is the operator's computer). Changes are pushed (`onChange`); the 2 s poll stays,
with the same `since`. A banner says what the page holds: SAFE worker, FULL standby, or remote.
Remote over the relay (`SIGELO:CTL:`, contact/control.mjs): the computer pushes the state (events), so
the poll reads it in the page and sends nothing; one request renews the push every 5 minutes.

## The platform (platform-web.mjs)

- **files:** a Map loaded whole from IndexedDB at start; each write is queued and committed in one
  readwrite transaction (durability `strict`) soon after. `flush()` resolves once every write before
  it is committed; after a failed commit it rejects for good (reload the app).
- **The flush rule:** the carrier awaits `flush()` before every PUBLISH and every PUBACK, so nothing
  leaves and nothing is acknowledged before the state that sent or saved it is on disk: an envelope
  whose ratchet step a crash lost would be sent again under the same key.
- **transact:** in-process; **owner:** `navigator.locks.request(<DID>, {ifAvailable: true})` for the
  app's life: a second tab or window on the same identity is refused `busy`.
- **fetch:** the page's, no redirect followed, no credentials, no referrer; **mqtt:** MQTT.js's browser
  build over WebSocket, `wss://` only (`ws://` to loopback for tests); `transports: ['wss']`, so the
  carrier's `auto` is `wss` and `mqtts` is refused. A shell passes its own socket (`createWebsocket`).
- **pow:** `pow-worker.mjs` in a module Worker (a Worker gets no import map: it imports @noble by path),
  progress every 65,536 hashes, ended at the deadline or on abort.
- **env:** from the page (`relay`, `endpoints`, `retentionDays`); no proxy. An `env.relay` (or the
  router's `options.relay`) is fixed, as `SIGELO_RELAY` is for `ui`; else the page's setting.

**Relay setting:** `GET/POST /api/settings` (UI-API.md), kept in the page's data; the import form
pre-fills `relay.sigelo.ai` (`presetRelay`) so a self-hoster changes it before pairing. Precedence:
fixed, then the setting, then `relay.sigelo.ai`. Codes accepted never read it.

## The identity

The app holds one identity file (sigelo-agent's JSON, key included): the file a computer wrote for
this device (`sigelo-agent device scan`, SAFE), or the operator's (FULL, standby). `app.mjs` offers to
import it when there is none. It is kept sealed: AES-256-GCM under a WebCrypto key generated here,
non-extractable, stored in IndexedDB's key store. That protects a copy of the app's storage, not the
key from a script running in this origin (THREAT-MODEL §3.12). In the Android app the platform has a
sealer: the file is sealed under an AndroidKeyStore key instead (`identity.keystore`). Contacts, carrier state, history and the page's data are
files of the platform under `app/me.local.*`, as `ui` keeps them beside `me.local.json`.

## Code trust

The app runs only its own files: CSP `default-src 'self'`, scripts from this origin and the import
map by its hash; `connect-src https: wss:` for the relays. No bundler, no transform: `copy.mjs`
copies sigelo-contact's modules (`contact/`), sigelo's (`ts/dist/`), @noble's, `mqtt.esm.js`
(MQTT.js 5.16.0), `ui.js`, `ui.css`, the icon, `remote-client.mjs` and the page's `node:zlib` shim for
the QR codec, as they are. 53 files, about 1.5 MiB, most of it MQTT.js and @noble/post-quantum.

## Not here yet

- **Relay traffic from a plain browser:** the public relay refuses requests that carry an `Origin`
  (a web page must not spend a network's login budget), and its HTTP has no CORS. The shells carry
  the relay's HTTP and socket natively (the Android app does: platform-android.mjs); against a relay
  without that rule (the tests' in-process relay) a tab works as it is.
- **Devices in the app:** scanning a device code into the app (the identity file is imported).
- **Files:** sending one from the page (as in `ui`).

## Tests (test-web.mjs)

1. The page: one inline script (the import map, hash in the CSP), the import graph resolves, every
   vendored file as its source, no `node:` import but the shimmed `node:zlib`.
2. The platform over a minimal in-memory IndexedDB: write-behind and flush, a failed commit, a
   reload, the owner lock, the PoW worker (the counter Node finds; deadline, abort), the sealed
   identity, wss only.
3. Two apps against the in-process relay (MQTT.js's browser build over Node's WebSocket) with a Node
   agent: state, me, invite (short code) and accept both ways, words, send and read, messages,
   tags, tier, rename, links, devices, agents, errors, pushed changes, the flush rule (none sent or
   acknowledged while a commit is held), one owner, a restart from IndexedDB, history clear, forget.

test-shell.mjs runs the Android app's page side over a fake shell that keeps SigeloBridge's protocol
in Node: the RFC 6455 framing (against `ws` and a raw server for every failure), the bridge, the
keystore seal, and two apps over mqtts and wss behind a stand-in nginx that refuses browser requests.
