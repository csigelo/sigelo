<!-- SPDX-License-Identifier: MIT -->
# Key providers build plan (for the Owner's approval)

Proposal, 2026-10-13. Implements ROADMAP §7 "Key providers" (decided 2026-10-13, binding).
Starts after the relay launch (ROADMAP §6). Platform and hardware facts carry a source number
[S1]…, listed at the end with the date read. "(?)" marks a value to measure or confirm.

## 1. Summary and the threat

An agent's identity key is the hex field `secret` of its identity file (`$SIGELO_IDENTITY`, mode
0600). Mode 0600 keeps out other users, not what runs as the same user: the model when it has a
shell, an install script, a backup or sync client, a dotfiles commit, a model printing the file into
a context an injected page can read. Whoever reads it signs as the agent until a recovery rotation
(forever with `recovery: null`, SPEC §4), and can publish a voluntary rotation to its own key, which
only the offline recovery key undoes (SPEC §7.1).

**Nothing of ours ever receives a user's key.** Every reader of the seed (`secretOf` in the sidecar,
the Monero half, the carrier's `identity()` callback, the gate's signer) hands it only to the
library's signing functions, and the one network client, the carrier, sends the relay signatures and
ciphertext. The exposure is the agent's own machine.

| Step | Removes | Remains |
|---|---|---|
| 1. Keychain-wrapped file | the key in any copy of the file: backups, sync folders, commits, a model reading the file | any process of the user, while the session is unlocked, can ask the keychain for the wrapping key (§6) |
| 2. Key agent | the key in the model's and the MCP server's process; signatures on anything but known sigelo bodies; a hostile rotation through the agent | signatures on request while the agent runs; the at-rest copy, unless it is hardware or the agent runs as another user |
| 3. Hardware through the agent | the key on disk; for on-token Ed25519, the key in any computer's memory | signatures while a human touches or the PIN is cached; a lost token costs a recovery rotation |

The protocol does not change: same suite, objects and verification. Only the signing side does.

## 2. Design

### 2.1 Two settings, not one

Where the key rests and which process uses it are separate questions:

- **At rest:** the identity file's `secret` field says it, and nothing overrides it.
- **In use:** `SIGELO_KEY_AGENT=<socket>` means "this process never holds the key; ask the agent".
  Unset, a `file` or `keychain` key is used inside the calling process, and a file saying `agent`
  uses the default socket (§4.1).
- `SIGELO_KEY_PROVIDER` (`file`, `keychain` or `agent`) chooses only the form of a **new** identity
  (`sigelo-agent init`, `sigelo_init`). Its default is an Owner decision (§8).

### 2.2 The identity file

| `secret` | Provider | Read by |
|---|---|---|
| `"<64 hex>"` | `file`: today's plain seed | every version, in-process |
| `{"provider":"keychain", "v":"sigelo-wrap/1", "store":"macos" \| "secret-service" \| "dpapi", "account":"<original DID>", "nonce":"<b64url, 12 bytes>", "ct":"<b64url, 48 bytes>", "dpapi":"<b64>" (Windows only)}` | `keychain`: seed encrypted, wrapping key in the OS store (§3) | K2 on, in-process or in the agent |
| `{"provider":"agent"}` | `agent`: the key is not in this file | K3 on, through `SIGELO_KEY_AGENT` only |

Hardware references (`fido2`, `openpgp-card`) live in the agent's own store (§4.4), never in the
identity file, so the sidecar and the MCP server know three forms and no more.

Compatibility, both ways:

- **New code, old file:** a string is provider `file`; signatures are byte-identical (Ed25519 is
  deterministic).
- **Old code, new file:** `whoami`, `bundle` and attestations work; signing fails closed, as the old
  `secretOf` throws on an object. K1 names that failure (`key_provider_required`) before any new
  form exists.
- Moving between forms rewrites `secret` only, in one atomic `save`; chain, attestations and DID are
  untouched.

### 2.3 The interface

One file, `adapters/moadim/sigelo-agent-keys.ts`, used by the sidecar CLI, the MCP server (through
the sidecar library, so the server keeps no crypto and no dependency of its own), the Monero half,
the contact verbs and the gate's signer:

```ts
interface Signer { did: string; key: string; sign(body: object): string }  // "sigelo\n" ‖ JCS(body), multibase
signer(path: string, s: Store, env?: Env): Signer
init(path: string, recovery: string | null, provider: 'file' | 'keychain' | 'agent'): Store
rotate(path: string, s: Store, now: number): Store  // appends the rotation; s.secret = the new at-rest form
```

- **Two operations.** On the agent side the five library functions reduce to *sign a body* with
  the current key (challenges, bindings, invoices; the carrier's login, invite proofs, messages,
  prekeys, notices) and *rotate*. `attest` is a world's job; `verify` and the public key need no
  secret.
- **Bodies, not bytes.** `sign` builds the SPEC §3 signing input itself. Nothing signs raw bytes,
  which is what lets the agent keep a policy (§4.3).
- **Synchronous.** Every call site is synchronous today, envelope sealing included, so the signer is
  too: keychain tools run under `execFileSync`, and the agent client blocks on a worker thread with
  `Atomics.wait` and `receiveMessageOnPort` [S14], as the sidecar's lock already blocks.
  `sign(secretOf(s), body)` becomes `signer(path, s).sign(body)`.
- **Checked.** Every signature is verified against the head genesis key before it leaves
  (`key_mismatch`).
- **The 77 lines.** The core keeps its plain-file path at 75 code lines: K1 extracts the challenge
  checks as `challengeDid`, so provider code reuses rather than copies them, and `secretOf` refuses a
  non-string; no net line. Provider code is counted apart, like the Monero half.

### 2.4 Prekeys and pairing secrets stay in their files

The carrier's state (X-Wing prekey secrets, epoch chain keys) and the contact store (pairing keys)
stay in their 0600 files. They are random, not derived from the seed. They are many, change with
every message and open every envelope, which no token can do and a socket round trip per message
would slow. They are session keys with forward secrecy: their thief reads current epochs but cannot
sign as the agent, rotate it or pose as it to a new contact. The identity key is the one long-lived
secret whose theft is identity theft, so it alone moves.

### 2.5 Errors: fail closed, by name

No provider falls back to another: a missing item, agent or token is an error the caller sees,
never a quiet use of a plain key.

| Code | Meaning |
|---|---|
| `key_provider_unknown` | `secret.provider` or `SIGELO_KEY_PROVIDER` names no provider |
| `key_provider_required` | a plain-file code path met a wrapped or agent key |
| `key_provider_unbuilt` | the provider's milestone has not landed (a stub answered) |
| `key_mismatch` | the unwrapped seed, agent key or token signature does not match the head genesis key |
| `keychain_unavailable` | the store or its tool is absent, locked or does not answer |
| `keychain_missing` | the store answers but holds no item for this account |
| `wrap_auth` | decryption failed: another item, or a tampered file |
| `key_agent_unavailable` | nothing answers at the socket within 2 s |
| `key_agent_mismatch` | `SIGELO_KEY_AGENT` is set but the file still holds a key: move it (`keys to-agent`) |
| `key_agent_timeout` | no reply within 60 s (a touch not given) |
| `socket_dir_unsafe` | the agent's socket directory belongs to another uid or is open to group or world |
| `policy_typ`, `policy_did`, `policy_rotation` | the agent refused the body (§4.3) |
| `fido2_absent`, `fido2_denied`, `fido2_uv_mismatch`, `card_absent`, `card_denied`, `card_bad_signature`, `card_too_large` | hardware (§5) |

### 2.6 Commands

Operator commands, CLI only. No MCP tool moves, reveals or deletes a key; `sigelo_init`,
`sigelo_sign_challenge` and `sigelo_rotate` simply go through the signer.

| Command | Does |
|---|---|
| `sigelo-agent keys status` | form, store or agent reachable; never prints key material |
| `sigelo-agent keys wrap` / `keys unwrap --plain` | file ↔ keychain (§3) |
| `sigelo-agent keys to-agent` | file or keychain → the agent's store; the file keeps `{"provider":"agent"}` |
| `sigelo-key-agent start`, `install-unit`, `list`, `lock` | §4 |
| `sigelo-key-agent enroll fido2` / `enroll card` | §5 |

## 3. Provider 1: keychain-wrapped file

**Scheme.** A random 32-byte file key seals the seed: ChaCha20-Poly1305, a random 12-byte nonce,
additional data `"sigelo-wrap/1\n"` ‖ the head genesis key. The file key goes to the OS store as
service `sigelo`, account = the original DID (public, stable across rotations, one per profile).
Signing fetches it, decrypts, checks the seed against the head key, signs and zeroes both; nothing
is cached. A rotation seals the new seed under the same file key, fresh nonce, in the one atomic
write that appends the rotation. Hence a file key, not the seed, in the store: one store write per
identity, ever, so file and store never disagree, and either copied alone is useless.

**Cipher.** ROADMAP's note named XChaCha20-Poly1305; `node:crypto` has ChaCha20-Poly1305 and no
XChaCha [S13]. The long nonce matters only when one key seals many messages, and here a key seals
once per rotation; so RFC 8439 ChaCha20-Poly1305: no dependency, readable from any language.

| System | Store | Write | Read | Delete |
|---|---|---|---|---|
| macOS | login keychain, unlocked at login [S1, S2] | `security -i`, which reads commands from stdin, given `add-generic-password -U -s sigelo -a <DID> -w <key>`: the key never appears in argv [S1] | `security find-generic-password -s sigelo -a <DID> -w` | `security delete-generic-password -s sigelo -a <DID>` |
| Linux | the Secret Service: GNOME Keyring, KWallet (KDE Frameworks 5.97 on), KeePassXC [S3, S4] | `secret-tool store --label='sigelo key wrap' service sigelo account <DID>`, key on stdin with no trailing newline (stdin is read to EOF, newline included) [S3] | `secret-tool lookup service sigelo account <DID>` | `secret-tool clear service sigelo account <DID>` |
| Windows | DPAPI, current user [S6] | `powershell -NoProfile -NonInteractive -EncodedCommand <script>`, the script holding no secret: key on stdin, `ConvertTo-SecureString -AsPlainText -Force \| ConvertFrom-SecureString`, blob on stdout into the file's `dpapi` field | the reverse: blob on stdin, key on stdout | drop the field |

**Windows: DPAPI, not Credential Manager.** ROADMAP §7 names Credential Manager, but `cmdkey`
never displays a stored password [S7], reading one back needs compiled P/Invoke, and Credential
Manager is itself DPAPI-protected [S8]. Both cmdlets use DPAPI when given no key, in PowerShell 5.1
and 7 [S6]: the same protection, built in. **Linux:** `secret-tool` is in Fedora's `libsecret` but a
separate package on Debian and Ubuntu, absent from the Ubuntu desktop image [S5]: K2's one extra
install.

**Logged:** provider, store, account, outcome code. Never a key, seed, ciphertext or blob: secrets
travel on stdin and stdout pipes only, never in argv or the environment, which other processes can
read.

**Migration.** `keys wrap` checks that the wrapped field unwraps before it atomically replaces the
plain file. Wrapping does not unleak: older copies (backups, sync folders) still hold the
key, so rotate after wrapping one that may have been copied. `keys unwrap --plain` reverses it. A
wrapped file copied to another machine fails with `keychain_missing`: unwrap on the old, wrap on the
new.

**Headless.** Where no store answers (servers, containers, CI), `keychain` fails closed with
`keychain_unavailable`; the operator picks `file` or, recommended, the agent under its own user
(§4.6).

## 4. Provider 2: the key agent

`sigelo-key-agent` (new package `keyagent/`, MIT, depending only on `sigelo` and `sigelo-agent`) is
a small Node process that holds identity keys and signs over a local socket, as ssh-agent does. The
MCP server and the model then hold a socket path, the identity file `{"provider":"agent"}`, and
neither the key.

### 4.1 Socket

Linux `$XDG_RUNTIME_DIR/sigelo/agent.sock`, macOS `$TMPDIR/sigelo/agent.sock`, Windows the named
pipe `\\.\pipe\sigelo-agent-<user>` [S10]. Created under umask 077 in a 0700 directory; the agent
refuses to start if that directory belongs to another uid or is open to group or world
(`socket_dir_unsafe`). **No peer-credential check:** Node has none [S10, S11], a native addon would
be a dependency, and it would only shut out other users, which the 0700 directory does; root
connects anyway. The boundary is this user's processes; the policy (§4.3) limits them.

### 4.2 Protocol

One JSON object per line, UTF-8, read with sigelo's strict parser, at most 64 KB, one reply per
request. Every request names the identity by its current DID as the caller's file has it; the store
maps every DID of a chain to its entry.

| Request | Reply |
|---|---|
| `{"op":"list"}` | `{"ok":true,"keys":[{"did","key","form"}…]}` |
| `{"op":"create","recovery":"sha256:…" \| "z6Mk…" \| null}` | `{"ok":true,"genesis":{…}}` |
| `{"op":"import","genesis":{…},"seed":"<hex>"}` (from `keys to-agent`) | `{"ok":true,"did":"…"}`; refused if the DID is held already |
| `{"op":"pubkey","did":"…"}` | `{"ok":true,"key":"z6Mk…"}` |
| `{"op":"sign","did":"…","body":{…}}` | `{"ok":true,"sig":"z…"}` |
| `{"op":"rotate","did":"…","to":"software" \| "fido2" \| "card"}` | `{"ok":true,"rotation":{body,sig,next_genesis}}` |
| `{"op":"commit","did":"…"}` | `{"ok":true}` |
| `{"op":"lock"}` | `{"ok":true}`: every unlocked seed forgotten |
| any refusal | `{"ok":false,"code":"policy_typ","detail":"…"}` |

No request returns a key or deletes one; deleting an entry is a file operation by the store's owner.
The agent logs one line per request (op, DID, `typ`, outcome), never a body or a key.

### 4.3 Policy

The agent receives bodies and builds the signing input itself; raw bytes have no request. It signs:

| `v` | `typ` | Condition |
|---|---|---|
| `sigelo/0` | `challenge` | the sidecar's own `challengeDid` checks: five fields, `did` = this key's DID |
| `sigelo-relay/0` | `relay-login` | `did` = current DID |
| `sigelo-invite/0` | `invite-answer`, `invite-reply` | `did` = current DID |
| `sigelo-msg/0` | `message`, `prekeys` | `from` or `did` = current DID |
| `sigelo-carrier/0` | `contact-notice` | `did` = current DID |
| `sigelo/0` | `binding`, `invoice` | only when started with `--allow-payments` (the agent cannot see which subaddresses the wallet issued) |
| `sigelo/0` | `attestation` | only with `--allow-attest <ctx>`: an operator key signing for the gate |
| `sigelo/0` | `rotation` | never through `sign`; only `rotate`, to a key the agent made itself |
| anything else | | `policy_typ` |

The rotation rule is the agent's strongest property: an injected model still gets signatures, never
a voluntary rotation to a key it chose, the one act that takes an identity from its operator
(THREAT-MODEL §2.4). **No software confirmation mode:** a dialog or an `approve`
command is clicked or run as easily by a same-user shell; real confirmation is a touch (§5).

### 4.4 Store, rotation, lifetime

The agent's store is a 0700 directory in the platform's data directory, one file per original DID:
`{v:"sigelo-key-agent/0", did, chain, secret, pending?}`, `secret` being keychain-wrapped (default),
a `fido2` or `openpgp-card` reference, or plain with `--store-plain` (for §4.6). Keys unlock on first
use and stay unlocked until `lock`, stop or `--idle <duration>`; hardware has its own rule (§5.1).

`rotate` makes the new key, signs the rotation with the old one, keeps the new key `pending` and
returns the rotation. The caller appends it under its file lock and sends `commit`, which drops the
old key (a `sign` for the new DID also commits). A crash in between leaves the old key working: a
rotation cannot tear.

Startup: a systemd user unit (`systemctl --user enable --now sigelo-key-agent`) [S17], a LaunchAgent
in `~/Library/LaunchAgents` [S18], by hand on Windows in K3, or `sigelo-key-agent start` in a
terminal. `install-unit` writes the unit; nothing installs or starts the agent by default (§8).

### 4.5 Use by the MCP server and the sidecar

Set `SIGELO_KEY_AGENT` in the harness's MCP server `env` (for moadim, the routine's `[env]`). The
server reads chain, genesis and attestations from the identity file and sends bodies to the agent. A
file still holding a key while an agent is configured is refused (`key_agent_mismatch`): no operator
should believe a key on disk is out of reach.

### 4.6 A separate user, for servers

On Linux the agent can run as its own system user (a system unit with `User=`, `RuntimeDirectory=`,
a socket group for its clients). The model's uid then reads neither its store nor its memory: the
strongest software-only setup, and the answer for headless hosts.

## 5. Provider 3: hardware through the agent

Only the agent drives tokens; the sidecar and the MCP server never learn about them.

### 5.1 FIDO2 `hmac-secret`

A token with `hmac-secret` returns HMAC-SHA-256(CredRandom, salt), CredRandom being a random value
bound to one credential inside the token [S19]. Those 32 bytes are a root R and the seed is
`identitySeed(R, n)`, the existing MONERO.md §2 path `k(R, "sigelo/v1/identity/ed25519/<n>")`: a
rotation on the same token is n + 1: no new credential, no new code.

- **Salt:** a constant, SHA-256(`"sigelo/v1/fido2/salt"`). It cannot come from the DID, which hashes
  a genesis holding the public key, which comes from the salt. One credential per identity keeps
  identities apart.
- **User verification pinned:** the token holds "CredRandomWithUV and CredRandomWithoutUV" [S19], so
  one salt gives two seeds, with and without PIN. The entry records `uv`; every assertion uses it; a
  mismatch is `fido2_uv_mismatch`, never a new key.
- **Presence:** a touch every time; CTAP refuses `hmac-secret` without user presence [S19]. The seed
  lives for one signature, unless the operator sets `--hold <duration>`, which a messaging agent
  needs.
- **Tools:** `fido2-cred -M -h` makes the credential; `fido2-assert -G -h -t pin=true -i <file>`
  prints the output after the signature line [S20]. With parameters in `-i`, fido2-assert reads the
  PIN from the terminal or else stdin [S20]: under systemd the agent asks through `pinentry` and
  passes it on, storing nothing.
- **Entry:** `{provider:"fido2", v:"sigelo-fido2/1", rp:"sigelo-agent", cred:"<b64url>", uv, n}`; the
  credential id is useless without the token.
- **Where:** Linux and macOS with libfido2's tools; Windows through webauthn.dll, supported for
  `hmac-secret` since libfido2 1.11 [S21], untested (§9).

### 5.2 On-token Ed25519 (OpenPGP card)

The key is made on the card and never leaves it. The agent talks to gpg-agent's ssh-agent socket
[S28]: a sign request (RFC 9987, message 13) carries the signing input, and for an `ssh-ed25519` key
the reply is plain Ed25519 over it [S30], the SPEC §2 suite; GnuPG hands the card the whole data
("the PureEdDSA case") [S28]. The client is a few dozen lines of Node. PIN through gpg's pinentry,
touch through the card's UIF setting [S24]. Fallback driver: OpenSC's `pkcs11-tool`, EdDSA since
0.26.0 [S29]. On Windows, gpg-agent offers the socket with `enable-win32-openssh-support` [S28].

**Size limit.** GnuPG 2.4 passes a card at most about 460 bytes of data and 2.5.2 lifts that [S28];
a card may need command chaining or extended length past about 254 bytes (?). Challenges,
rotations, relay logins, invite proofs and notices fit; prekeys and messages do not. **So an
identity on a card cannot use the contact verbs** (`card_too_large`); a messaging agent uses FIDO2,
whose seed signs inside the agent at any size.

Use a dedicated card key, never an SSH login key: the genesis publishes it. Rotating away from a card
key needs the next key first: the card's other signing slot, or a second token.

### 5.3 What the Nitrokey 3 can do

Current firmware 1.9.1, 2026-09-30 [S22].

| Application | What it offers | Stable since | Here |
|---|---|---|---|
| FIDO2 (USB, NFC) | ES256 and EdDSA credentials; `hmac-secret`, never without a touch (enforced since 1.8.2) [S22, S25] | present by 1.0.1, 2022 | K4 |
| OpenPGP card 3.4.1 (USB) | Curve25519 (EdDSA, ECDH), P-256, RSA 2048; more curves with the secure element; touch confirmation (UIF) [S22, S24] | 1.4.0, 2023 | K5 |
| PIV (USB) | RSA 2048/3072/4096, P-256, P-384; **no Ed25519** [S23] | 1.8.0, 2024 | unusable: SPEC §2 is Ed25519 only |
| Secrets app (USB) | HOTP, TOTP, YubiKey-style HMAC-SHA1 challenge-response, password safe [S26] | | not used: `hmac-secret` does the job through a standard |

A YubiKey 5 does both jobs too: `hmac-secret` from firmware 5.2, OpenPGP Ed25519 from 5.2.3, with a
touch policy that can cache for 15 s [S27].

### 5.4 Moving an identity to hardware; recovery

One voluntary rotation: the agent signs, with the current key, a rotation to a genesis holding the
token's key and the unchanged recovery commitment (SPEC §7; `rotate()` enforces it). Worlds reissue
attestations as after any rotation; reputation follows the chain (SPEC §7.4). A token key is not
derived from the ceremony's root, so the 25 words no longer restore it: a lost token costs a recovery
rotation, which restores control, not the old key. The recovery key never goes on the identity's
token (THREAT-MODEL §5): it stays on paper or in the ceremony's age backup; one on a second token is
deferred (§9).

## 6. Security analysis

| Setup | An attacker running code as the user gets | A malicious model with a shell can |
|---|---|---|
| `file` | the key, at once, until a recovery rotation | read the file, sign anything, publish a hostile rotation |
| `keychain` | from a copied file: nothing; from live code while the session is unlocked: the key, one step later | the same, deliberately: call the store's tool and decrypt; on macOS, with `-T ""`, only after a click |
| agent, same user, keychain at rest | signatures within the policy while the agent runs; the key through the at-rest copy, as above | sign within the policy; not rotate to its own key through the agent; still unwrap the at-rest copy itself |
| agent as another user | signatures within the policy while it runs; never the key | sign within the policy, nothing more |
| agent + FIDO2 | signatures within the policy, each with a touch (or inside a hold window); the key only by reading the agent's memory during a signature or a hold | ask; a human touches or nothing is signed |
| agent + OpenPGP card | signatures within the policy, with the PIN entered once and a touch where the card asks; never the key | ask; the card decides |

Read the third row twice: an agent in the user's own account shields the key from a model with only
MCP tools and from accidents, but a model with a shell can still unwrap the keychain copy. "The model
never holds the key" is fully true only with hardware or a separate user.

Residual risks:

- **Memory.** On Linux, Yama's `ptrace_scope` 1, Ubuntu's default, lets a process trace only its
  descendants, so a shell cannot read an agent started by systemd [S15]; macOS gives task ports only
  to entitled debuggers [S16]; on Windows we know of no such barrier between one user's processes
  (K3 checks); root reads everything. JavaScript cannot wipe strings, so seeds stay byte arrays,
  zeroed after use: best effort.
- **The agent** holds every key it serves: small (sigelo and `node:` modules), no network listener,
  no request that returns a key.
- **macOS:** "the application which creates an item is trusted to access its data without warning"
  [S1], here `security` itself, which any process of the user can run. `-T ""` removes that default;
  K2 checks that reads then ask, and people still click "Always Allow".
- **Linux:** no Secret Service daemon, no store. With one, assume any process in the session reads
  an unlocked item; K2 checks.
- **Windows:** "any program running as that user" can use the store [S8]; DPAPI keeps its keys in the
  user profile [S9], so a lost profile loses the seed: a recovery rotation.
- **Tokens:** lost, a recovery rotation; stolen, guarded by the PIN only if the entry uses one.

## 7. Milestones

| | Milestone | Agent-hours | Waits for |
|---|---|---|---|
| K1 | Provider interface, file compatibility | 8 | nothing |
| K2 | Keychain wrapping on three systems | 10 | a Mac and a Windows machine, for the manual checklist |
| K3 | Key agent, protocol, MCP, sidecar and carrier integration | 16 | a Windows machine, for the pipe check |
| K4 | FIDO2 `hmac-secret` | 10 | the Nitrokey 3 |
| K5 | OpenPGP-card signing | 10 | the Nitrokey 3 |
| K6 | Docs, budgets, threat model, plugin bundle | 5 | nothing |
| | **Total** | **59** | |

**First**, the orchestrator creates every shared seam so no file has two owners: stub files
`adapters/moadim/sigelo-agent-keychain.ts`, `sigelo-agent-keyclient.ts`, `keyagent/fido2.mjs` and
`keyagent/card.mjs` (each exports its final signatures and throws `key_provider_unbuilt`), the `keys`
dispatch line in `cli.ts`, `keyagent/package.json` with its lockfile, and the CI jobs. **Waves:** K1;
K2 and K3 in parallel (K2 ships first, as ROADMAP §7 orders); K4 and K5 in parallel (K4 first); K6.

| | Files (owned by that milestone only) | Fixtures | Done when |
|---|---|---|---|
| K1 | `adapters/moadim/sigelo-agent-keys.ts` (new: `signer`, `init`, `rotate`, the `file` provider, the `keys` verbs, errors); `sigelo-agent.ts` (`challengeDid`, `secretOf` refusal); `sigelo-agent-monero.ts` (`bind`, `invoice` through the signer); `sigelo-agent-contact.ts`, `integrations/mcp/contact.mjs` (the carrier gets a signer); `contact/carrier.mjs`, `envelope.mjs`, `invite.mjs`, `prekeys.mjs` (`sign(me.secret, b)` → `me.sign(b)`); `integrations/mcp/server.mjs` (handlers through the signer); `gate/claude-code/sign.mjs`; `adapters/moadim/test-keys.ts` (new) | a plain file from the test seeds signs a challenge byte-identical to today; every contact fixture `--check` byte-identical; an unknown provider refused by name, nothing written; the pre-K1 CLI on an `{"provider":"agent"}` file: `whoami` works, `sign-challenge` exits non-zero | every suite green; core still 75 code lines |
| K2 | `adapters/moadim/sigelo-agent-keychain.ts` (wrap, unwrap, the three stores behind an injectable `Keychain`, as the ceremony injects `Age`); `test-keychain.ts`; `fixtures/wrap-v1.json`; `KEYCHAIN.md` (manual checklist and results) | a wrap vector (fixed key, nonce and seed give an exact `ct`, reproducible by any RFC 8439 implementation); round trip through a fake store; tampered `ct` or another account → `wrap_auth`; no item → `keychain_missing`; no store → `keychain_unavailable` and no plain write; a rotation re-encrypts in the same write; after `keys wrap` the old hex is nowhere in the file; a spawn spy finds no secret in any argv or environment | fixtures green; the checklist run on macOS, Ubuntu (GNOME) and Windows 11: wrap, sign, log out and in, sign, store locked, item deleted, time per signature |
| K3 | `keyagent/` (`agent.mjs`, `protocol.mjs`, `policy.mjs`, `store.mjs`, `units/`, `test.mjs`, `fixtures/protocol-v0.json`, `README.md`); `adapters/moadim/sigelo-agent-keyclient.ts` | every request and refusal of §4.2–4.3 as byte-exact request/reply pairs; each allowed body signs, each other `typ`, a foreign DID, a rotation through `sign` refused by name; a torn rotation (caller killed between `rotate` and its write) converges; agent absent → `key_agent_unavailable` in ≤ 2 s; unsafe socket directory refused; the contact and MCP suites pass with `SIGELO_KEY_AGENT` set and a file holding `{"provider":"agent"}` | fixtures green; Windows pipe checked by hand |
| K4 | `keyagent/fido2.mjs`, `test-fido2.mjs`, `fixtures/fido2-v0.json`, `fake/` (scripts standing in for `fido2-cred` and `fido2-assert`) | a fixed token output gives a known public key through `identitySeed(R, n)`; `uv` mismatch refused; one assertion per signature without `--hold`; enrollment plus one rotation from a software key: the chain verifies with the Go verifier | fixtures green; the checklist on a real Nitrokey 3 (and a YubiKey 5 if at hand) |
| K5 | `keyagent/card.mjs`, `test-card.mjs`, `fixtures/card-v0.json`, `fake/ssh-agent.mjs` | the fake agent's signature equals `sign()` byte for byte; a card that signs with another key → `card_bad_signature`; enrollment plus one rotation onto the card verifies with the Go verifier | fixtures green; the checklist on the Nitrokey 3 |
| K6 | `adapters/moadim/README.md`, `INTEGRATION.md` (line table), `integrations/mcp/README.md`, `keyagent/README.md`, `THREAT-MODEL.md` §1 and §5, `CHANGELOG.md`, `docs-test/budgets.json`, `plugins/sigelo/` (regenerated), ROADMAP §7 status | budgets pass; a fresh agent moves an identity file → keychain → agent from the docs alone | review by a fresh agent |

**Never weakened, checked at every gate:** `ts/` and `go/` untouched (no new vector: wrapping is
local storage, not protocol); no new dependency anywhere (node:crypto, child_process, net,
worker_threads only); the MCP server still imports nothing but `node:` modules and the sidecar;
`plugins/build.mjs` still makes one file (the client's worker is an inline string); the sidecar core
stays 75 code lines, provider files are counted apart in INTEGRATION.md (targets: keys 90, keychain
120, keyclient 50 (?)); every existing suite green; the leak scan; `release/publish.sh` dry run.

## 8. The Owner's list

1. **Hardware for K4 and K5:** the Nitrokey 3 we test with, on firmware 1.8.2 or later. A YubiKey 5
   only if a second vendor is wanted: the one optional purchase.
2. **Machines for K2 and K3's pipe check:** a Mac and a Windows 11 machine or VM, about an hour
   each. Linux runs here.
3. **Decide the default form of a new identity.** Recommended: `keychain` where a store answers,
   else `file` with `"provider":"file"` and a warning in `init`'s output. An explicit
   `SIGELO_KEY_PROVIDER=keychain` fails closed.
4. **Decide whether the key agent is installed by default.** Recommended: no, opt-in with
   `install-unit`. In the user's own account it adds little without hardware, and nothing in the
   protocol should need a running service.
5. **Approve two departures from ROADMAP §7's wording** (§3): DPAPI instead of Credential Manager,
   ChaCha20-Poly1305 instead of XChaCha20-Poly1305.

## 9. Open questions and risks

| Question or risk | What the plan does |
|---|---|
| Platform tools change; `security` is documented only by its man page [S1]; `secret-tool` is not on the Ubuntu desktop image [S5] | each tool sits behind the `Keychain` seam in one function; K2's checklist is rerun on new OS releases |
| Windows pipes: libuv sets no `PIPE_REJECT_REMOTE_CLIENTS`, and the default ACL gives Everyone read access [S11, S12] | K3 tries a second local user and a remote client by hand; if either can send a request, the agent requires a per-start token from a file only the user reads |
| Node has no peer credentials [S10, S11] | the 0700 directory; a real check only if libuv gains one |
| Nitrokey firmware: when `hmac-secret` arrived is undocumented; `hmac-secret-mc` is only in a pre-release [S22] | K4 and K5 record the firmware and require 1.8.2 or later |
| Card limits: does the Nitrokey 3 accept extended length? Our untested reading of scdaemon's source suggests data of exactly 36, 52 or 68 bytes is mishandled | K5 measures the largest body that signs; every allowed body is longer than 68 bytes, and every signature is checked |
| Tokens accept the non-domain relying party `sigelo-agent` (?) | K4 checks on both tokens |
| FIDO2 on Windows through webauthn.dll [S21] | untested; K4 ships Linux and macOS first |
| Memory on Windows: can one user's process read the agent's? | K3 checks and documents the answer |
| CI coverage of OS keychains | the fake store everywhere; real stores in CI where runners allow (?): gnome-keyring under `dbus-run-session`, a temporary macOS keychain, DPAPI on Windows; the manual checklist otherwise |
| The carrier state stays plain (§2.4) | wrapping it with the same file key is a later, separate step |
| A recovery key on a second FIDO2 token | same derivation, used offline; after K4 has run in practice |

## Sources

All read 2026-10-13.

| | Claim | URL |
|---|---|---|
| S1 | `security` options, default ACL, `-T ""`, `security -i` reads stdin | https://keith.github.io/xcode-man-pages/security.1.html |
| S2 | the login keychain unlocks at login | https://support.apple.com/guide/keychain-access/if-you-need-to-update-your-keychain-password-kyca2429/mac |
| S3 | `secret-tool store/lookup/clear`, stdin read to EOF | https://man.archlinux.org/man/secret-tool.1.en |
| S4 | Secret Service API; KWallet implements it (Frameworks 5.97); KeePassXC can | https://specifications.freedesktop.org/secret-service/latest/ · https://kde.org/announcements/frameworks/5/5.97.0/ · https://keepassxc.org/docs/KeePassXC_UserGuide |
| S5 | `secret-tool` packaging (Debian, Ubuntu universe, not on the Ubuntu desktop image; in Fedora's libsecret) | https://packages.debian.org/trixie/amd64/libsecret-tools/filelist · https://packages.ubuntu.com/search?keywords=libsecret-tools&searchon=names&exact=1 · https://releases.ubuntu.com/26.04/ubuntu-26.04.1-desktop-amd64.manifest · https://packages.fedoraproject.org/pkgs/libsecret/libsecret/fedora-rawhide.html |
| S6 | `ConvertFrom-SecureString` and `ConvertTo-SecureString` use DPAPI without a key (5.1 and 7) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring |
| S7 | `cmdkey`: passwords are not displayed after they are stored | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey |
| S8 | Credential Manager is DPAPI-protected; any program running as the user can access it | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v=ws.11) |
| S9 | DPAPI keys live in the user profile | https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata |
| S10 | Node IPC paths (Unix socket, named pipe); no peer-credential API | https://nodejs.org/api/net.html |
| S11 | libuv: peer credentials still an open issue; Windows pipes created without `PIPE_REJECT_REMOTE_CLIENTS` | https://github.com/libuv/libuv/issues/2255 · https://github.com/libuv/libuv/blob/v1.x/src/win/pipe.c |
| S12 | default named-pipe ACL | https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights |
| S13 | `chacha20-poly1305` in node:crypto; no XChaCha | https://nodejs.org/api/crypto.html |
| S14 | `receiveMessageOnPort` | https://nodejs.org/api/worker_threads.html |
| S15 | Yama `ptrace_scope` 1; Ubuntu's default | https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html · https://documentation.ubuntu.com/security/security-features/process-memory/ |
| S16 | macOS task ports only for entitled debuggers | https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger |
| S17 | systemd user units, `%t` | https://man7.org/linux/man-pages/man5/systemd.unit.5.html |
| S18 | `~/Library/LaunchAgents` | https://keith.github.io/xcode-man-pages/launchd.plist.5.html |
| S19 | `hmac-secret`: HMAC-SHA-256(CredRandom, salt), two CredRandoms by UV, `up` false refused | https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html (§12.5) · https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html (§12.7) |
| S20 | `fido2-cred`, `fido2-assert`: `-h`, `-t pin=`, input and output lines, PIN from tty or stdin | https://developers.yubico.com/libfido2/Manuals/fido2-cred.html · https://developers.yubico.com/libfido2/Manuals/fido2-assert.html |
| S21 | libfido2 1.11: `hmac-secret` through webauthn.dll | https://github.com/Yubico/libfido2/blob/main/NEWS |
| S22 | Nitrokey 3 apps, OpenPGP algorithms, firmware 1.9.1, `hmac-secret` fixes in 1.0.1 and 1.8.2, OpenPGP stable 1.4.0, PIV 1.8.0 | https://docs.nitrokey.com/nitrokeys/nitrokey3/overview.html · https://docs.nitrokey.com/nitrokeys/nitrokey3/faq.html · https://github.com/Nitrokey/nitrokey-3-firmware/blob/main/CHANGELOG.md |
| S23 | Nitrokey 3 PIV algorithms | https://docs.nitrokey.com/nitrokeys/features/piv/key_management.html |
| S24 | Nitrokey 3 OpenPGP touch (UIF) | https://docs.nitrokey.com/nitrokeys/features/openpgp-card/uif.html |
| S25 | Nitrokey FIDO2 code: `HmacSecret`, ES256 and EdDSA | https://github.com/Nitrokey/fido-authenticator/blob/main/src/ctap2.rs |
| S26 | Nitrokey Secrets app | https://github.com/Nitrokey/trussed-secrets-app |
| S27 | YubiKey 5: `hmac-secret` 5.2+, OpenPGP Ed25519 5.2.3, touch policies | https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html · https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html · https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html |
| S28 | gpg-agent's ssh support and `enable-win32-openssh-support`; "the PureEdDSA case"; the 2.4 data limit (`indatalen*2 + 50`); 2.5.2 lifts it (T7436) | https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html · https://github.com/gpg/gnupg/blob/STABLE-BRANCH-2-4/agent/divert-scd.c · https://github.com/gpg/gnupg/blob/STABLE-BRANCH-2-4/agent/call-scd.c · https://github.com/gpg/gnupg/blob/master/NEWS |
| S29 | OpenSC: OpenPGP EdDSA (0.22), `pkcs11-tool` EdDSA signing (0.26) | https://github.com/OpenSC/OpenSC/blob/master/NEWS |
| S30 | SSH agent sign request; `ssh-ed25519` signatures are RFC 8032 Ed25519 | https://www.rfc-editor.org/rfc/rfc9987.txt · https://www.rfc-editor.org/rfc/rfc8709 |
