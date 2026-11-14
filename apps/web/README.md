<!-- SPDX-License-Identifier: MIT -->
# apps/web: the self-contained app

The page of `sigelo-agent ui` running its own carrier: no computer, no Node. `ui.js` talks to an
in-page router (the `local` backend) that implements the routes of
[UI-API.md](../agent/UI-API.md) over a carrier on a browser platform, with the same JSON.
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
| `app.mjs` | Start: `boot.mjs` with the page's globals; sets `globalThis.sigeloLocal` for `ui.js` |
| `boot.mjs` | The start itself: the profiles, the picker, the active profile's platform, identity and router (or remote form, or first run); `sigeloLocal` with `profiles` |
| `computers.mjs` | A remote profile's computers (design/profiles.md P2): the list, the migration of today's one as c1, keys and databases per computer, `other_operator` |
| `profiles.mjs` | Profiles (design/profiles.md P1): the registry (`sigelo-app`, `profiles.json`), the migration of a single-profile install, per-profile storage names, the wipe |
| `router.mjs` | The `local` backend: `call(method, path, body)` → `{status, body}`, `onChange`, `mode` |
| `platform-web.mjs` | The browser platform of sigelo-contact (design/apps.md §4.2) |
| `pow-worker.mjs` | The relay login's proof of work, in a module Worker |
| `platform-stub.mjs` | Loaded instead of `apps/contact/platform-node.mjs` (import map): no Node default in a page |
| `platform-android.mjs` | In the Android app: the bridge (`sigelo-bridge/0`), the shell's fetch, MQTT and key, its lock settings, notifications and their open event |
| `ws-over-stream.mjs` | RFC 6455 client framing over the shell's TLS stream (wss), and the stream as a socket (mqtts) |
| `welcome.mjs` | The first run in the mock's words, shared with the GTK phone app: welcome, Name this phone, Keep it safe (25 words on paper or a password), the words and their check, Lock, You're set; restore (25 words or a backup file), join, connect; Back one step |
| `setup.mjs` | The first run's work in this page (welcome.mjs's api): create, restore, restore a backup, connect, and the import under Advanced; the shell's form set only when a path commits |
| `shell.mjs` | In the Android app: the remote form (a computer's page, on the LAN or over the relay), its pairing and `connectLan` |
| `seed.mjs` | Restore from seed: `restoreInto` (derive with `apps/contact/restore.mjs`, seal, write; the network held), `seatOf` for the router |
| `create.mjs` | Create my identity: `createInto` (commit with `apps/contact/create.mjs`, then sealed as `seed.mjs` writes a restore) |
| `backup.mjs` | The backup file (`sigelo-backup/0`, `.sbk`): a profile encrypted under the words password (`words-lock.mjs` `lockBytes`), written to Downloads or downloaded; restored as the same device, every session afresh at its first start; `sigeloLocal.backup` |
| `words.mjs` | The words password (design/apps-seed.md §8): the kept words (`apps/contact/words-lock.mjs`, sealed as kind `words`), `sigeloLocal.words`, the guards of profile removal and the seat |
| `copy.mjs` | The vendoring: walks the import graph, copies each file byte for byte, writes `vendor.json` |
| `vendor.json` | Every vendored file, its source and SHA-256 (committed; `vendor/` is not) |
| `test-web.mjs`, `test-shell.mjs` | The tests, in Node, through the same import map (`test-fakes.mjs`: IndexedDB, Worker) |

## The seam

`ui.js` picks its backend at load: `shell` in the GTK phone app (remote control), `local` when
`app.mjs` set `globalThis.sigeloLocal`, else `http` (the computer's `ui`). The router is
`apps/contact/page.mjs`, the module `sigelo-agent ui` serves its routes from, so a route answers the same
JSON here; what the app does not have answers as nothing: `GET /api/agents` (an agents' directory) is `[]`, enrolling or
pairing a local agent `404 agent`, `GET /api/devices` an empty list, adding, scanning or revoking a device
`409 not_here` (that is the operator's computer). Changes are pushed (`onChange`); the 2 s poll stays,
with the same `since`. Me → Devices and computers says what the page holds: your identity, a spare, an agent of yours, or a remote.
Remote over the relay (`SIGELO:CTL:`, apps/contact/control.mjs): the computer pushes the state (events), so
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

The app holds one identity file (sigelo-agent's JSON, key included): one made from the 25 words (FULL),
or the file a computer wrote for this device (`sigelo-agent device scan`, SAFE), imported under the
welcome's Advanced; the
operator's file (FULL) it refuses, and `router.start()` refuses FULL without a seat in a signed list
(`full_import`): FULL comes from the 25 words (design/apps.md §18). It is kept sealed: AES-256-GCM under a WebCrypto key generated here,
non-extractable, stored in IndexedDB's key store. That protects a copy of the app's storage, not the
key from a script running in this origin (THREAT-MODEL §3.12). In the Android app the platform has a
sealer: the file is sealed under an AndroidKeyStore key instead (`identity.keystore`). Contacts, carrier state, history and the page's data are
files of the platform under `app/me.local.*`, as `ui` keeps them beside `me.local.json`.

## Profiles (profiles.mjs, boot.mjs)

Up to 8, ids `p1`, `p2`, … never reused; the registry (IndexedDB `sigelo-app`: list, active id, no secret) is made at
the first start from what is there (an identity: `words`; the WebView app's remote form: `remote`; nothing). Profile 1 keeps
database `sigelo`, its localStorage keys and the keystore aliases of before; profile `<id>` has `sigelo-<id>`, keys
`<id>:…` and its own aliases (platform-android.mjs `profileBridge`: every seal and open names it). Only the active
profile is opened and connects. More than one at a start: the picker (welcome.mjs `pickProfile`), then the lock. A
switch, an add and a removal ask the lock once; a removal is recorded first, then erased (database, storage keys,
`forget-profile`), the active one at the next start. The Profiles sheet (the profile chip) and Settings → Profiles in `ui.js` call `sigeloLocal.profiles`.

## Computers (computers.mjs, shell.mjs)

A remote profile's computers (design/profiles.md P2), in its localStorage `sigelo-computers` (no secret): `c1` keeps the
keys and database of before (`sigelo-control`, `sigelo-control-relay`, the profile's database); computer `<cid>` has
`sigelo-control:<cid>`, `sigelo-control-relay:<cid>` and database `<profile database>-<cid>`, its blobs sealed naming it
(platform-android.mjs `computerBridge`). `remoteBackend` opens the one in use; none, or one being added: the pairing
screens (welcome.mjs `firstRun(…).connect()`, Cancel back). `pairComputer` refuses another operator (`other_operator`,
LAN: `GET /api/me`; relay: the contact's chain), and the backend refuses the same at its first `GET /api/me`. Forget
removes the material (a relay database at the next start); `sigeloLocal.computers` for ui.js.

## Restore from seed (seed.mjs)

Restore from 25 words, one screen: the box checked as it is typed (count, the first word not in the
Monero list by position, the checksum), the month they were made (a block height under More options),
and whether this identity is in use on another device (main or spare); network, name and relay folded.
`apps/contact/restore.mjs` derives what `sigelo-agent keeper --from-words` writes: the operator identity
(`operatorIdentity(S, 0)`) and the keeper file (K_1, the recovery commitment, `created`, `net`,
`restore_height` or `restore_date`; neither given → `restore_height: 0`), this device as worker 0 of
K_1, FULL, attested 14 days. Both files are sealed at once (`identity`, `keeper`: the WebCrypto key,
or the FULL keystore key in the Android app). The list and the seat notes (`app/me.local.devices.json`,
`app/me.local.seat.json`) are plain: they hold no secret. From the first word to the last commit
the network is held: the page's fetch and MQTT and the shell's `https` and `tls` refuse `restoring`.
The words are never stored, logged or shown again. Seat here: a signed list, this device holding the
seat at epoch 1 (`seat init`). Elsewhere: a standby. `router.mjs` then never logs in, refuses writes
with `seat_elsewhere`, and the banner offers "Take the seat here" (`POST /api/seat/take`). Me shows
"Restored from seed on <day> · keeper j=1 · seat here".

## Create my identity (create.mjs)

The welcome's first choice: Name this phone (network and relay under More options), then Keep it safe.
*Write down 25 words:* S drawn in the page (`apps/contact/create.mjs` `newSeed`, `crypto.getRandomValues`,
redrawn until 0 < S < l), the network held until the end; the words screen is a one-way door (numbered,
no Back, `FLAG_SECURE` with `door` in the Android app, no copy on the main network), then three words asked
by number. *Set a password:* the words drawn, checked by the page, encrypted under the password
(PBKDF2-SHA256, 1,000,000 rounds; `words.mjs`) and sealed as kind `words`, never shown. Either way `commit`
gives a restore's files for those words (operator, K_1, this device FULL holding the seat, `created` and
`restore_date` today, `made: "here"`), sealed as a restore, S zeroed; nothing stored before. Then Lock (the
Android app's screen lock once), You're set (the four words), the page restarts.

## Agents (pass A10b)

The first screen, as Monerujo's transaction list: one row per worker of the keeper (`GET /api/agents/workers`: name,
DID, where, enrolled / pending code / revoked, last seen), this device among them; below, **Enrol** and **Invite**.
Enrol, as Receive: a name and a tier (own; friend or quiet for an agent that reads the web), the relay (the picker:
tap to use, hold to edit, a typed host tested before OK), then one code big with its ten minutes, copy and share,
and `sigelo-agent init --enrol <code>` for the other machine; the four words once it pairs; then enrolled. The code
is made on the app's own session (`apps/contact/page.mjs`), worker i the next free, at the seat only (a standby refuses
`seat_elsewhere`). The keeper is opened per use and resealed after a change (`seed.mjs` `keeperOf`). Tapping a row:
details, Rename, Revoke (its contact forgotten; its attestation stays valid to its end, said before).
Add a contact is a separate screen (someone else's identity, a person's or an agent's): make a code to
send, or enter theirs; each of the two screens says what the other is for. Each code has Share: a
ready-to-send message with the code, until when, and the instructions page (sigelo.io/pair.html,
sigelo.io/enrol.html), through the Android share sheet, else copied.
Without a keeper (an imported file) the list is empty and Enrol is off.

## Code trust

The app runs only its own files: CSP `default-src 'self'`, scripts from this origin and the import
map by its hash; `connect-src https: wss:` for the relays. No bundler, no transform: `copy.mjs`
copies sigelo-contact's modules (`apps/contact/`), sigelo's (`ts/dist/`), @noble's, `mqtt.esm.js`
(MQTT.js 5.16.0), `ui.js`, `ui.css`, the icon, `remote-client.mjs` and the page's `node:zlib` shim for
the QR codec, as they are. 61 files, about 1.7 MiB, most of it MQTT.js and @noble/post-quantum.

## Not here yet

- **Relay traffic from a plain browser:** the public relay refuses requests that carry an `Origin`
  (a web page must not spend a network's login budget), and its HTTP has no CORS. The shells carry
  the relay's HTTP and socket natively (the Android app does: platform-android.mjs); against a relay
  without that rule (the tests' in-process relay) a tab works as it is.
- **Devices in the app:** scanning a device code into the app (the identity file is imported).
- **Files:** sending one from the page (as in `ui`).
- **A wallet:** the app holds none. Its Wallet switch is the profile's setting (`POST /api/settings {wallet}`), and with it on
  the Wallet tab says "This phone has no wallet yet" (`GET /api/wallet` `where: "none"`, the other wallet routes `409 wallet_none`);
  a computer's page, opened from Me → Devices and computers, shows that computer's wallet (UI-API.md "Wallet"). The vault the
  25 words make is restored in a Monero wallet app (its address is shown at creation).

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
Restore from seed is tested in both files:
- test-web: the page's files equal `keeper --from-words` for a fixed mnemonic (same DID, same K_1);
  the router as seat and as standby, and the take.
- test-shell: the keystore seals of the identity and keeper under the FULL key; no word, key or
  K_1 in the clear in storage; nothing logged; the network refused during the restore;
  `FLAG_SECURE` and the clipboard; no "show seed".
Profiles: test-shell (section 1d) migrates a single-profile install, adds, picks, switches (the bridge's unlock
counted: once per switch, none at the new profile's start), renames, hits the limit, removes (words ticked, the
name typed, the wipe of database, aliases and storage); test-web drives the Profiles sheet and Settings → Profiles in `ui.js`.
Computers: test-shell (section 3b) runs three LAN pages (two of one operator, one of another): migration as c1, add,
`other_operator`, Cancel, switch, forget; section 4 refuses a relay computer of another operator; test-web drives Me → Devices and computers.
Notifications and the lock: test-shell (section 1f) sends notify as given (a bad tag, title or text refused before the shell), cancel,
ask; the `{ev:"open"}` event to `onOpen` only (never a request's waiter), a start by a tap delivered once connected; `lock` get and
set (after 1, 5, 15, 60; others refused); `unlock({ force })` passed through; `words.check` (the gate, no screen lock).
