<!-- SPDX-License-Identifier: MIT -->
# Keychain wrapping: the manual checklist (K2)

No keychain (a container, a server)? Use the key agent ([keyagent/README.md](../../keyagent/README.md))
or a sealed file (below); the provider table is in [README.md](README.md).

The automated half is `node test-keychain.ts`: the wrap vector, refusals by name and a spawn spy
over all three adapters, against an emulated store. This checklist is the other half: the real
store on each system (the three providers). Run it
with a throwaway identity, never your own:

```sh
export SIGELO_IDENTITY="$PWD/k2-check.json"     # Windows: $env:SIGELO_IDENTITY = "$PWD\k2-check.json"
SIGELO_KEYCHAIN_LIVE=1 node test-keychain.ts    # step 1 and 12
```

`<DID>` is `sigelo-agent whoami`'s `did`. Record each result as ok, the refusal code, or what you saw.

| # | Step | Expect | macOS | Windows 11 | Ubuntu (GNOME) | Linux, here |
|---|---|---|---|---|---|---|
| 1 | `SIGELO_KEYCHAIN_LIVE=1 node test-keychain.ts` | `LIVE <store>` lines ok | | | | ok, secret-service |
| 2 | `sigelo-agent init --no-recovery` | file holds `"provider": "keychain"` and the store's name; no warning | | | | ok |
| 3 | `sigelo-agent keys status`, then `sign-challenge` | `"signs": true`; the signature verifies | | | | ok |
| 4 | read the item from another shell (`security find-generic-password -s sigelo -a <DID> -w`; `secret-tool lookup service sigelo account <DID>`) | macOS asks first (`-T ""`); Linux answers without asking (§6); Windows: n/a, the blob is in the file | | n/a | | answers, no prompt |
| 5 | log out and in; step 3 again | ok | | | | not run |
| 6 | lock the store (`security lock-keychain`; Seahorse: lock "Login"); step 3 | a prompt, or `keychain_unavailable`; never a plain key | | n/a | | not run |
| 7 | delete the item (`security delete-generic-password -s sigelo -a <DID>`; `secret-tool clear service sigelo account <DID>`; Windows: copy the file to another user's profile); step 3 | `keychain_missing` | | | | ok |
| 8 | `sigelo-agent rotate`; step 3 | signs for the new DID; still one item, not rewritten | | | | ok |
| 9 | `sigelo-agent keys unwrap --plain`, then `keys wrap` | hex back, item removed; wrapped again, no hex in the file | | | | ok |
| 10 | a session with no store (SSH without a desktop session; Linux: `env -i PATH="$PATH" HOME="$HOME" SIGELO_IDENTITY=…`): `SIGELO_KEY_PROVIDER=keychain sigelo-agent init --no-recovery` | `keychain_unavailable`, nothing written | | | | ok |
| 11 | same session, `sigelo-agent init --no-recovery` | `"provider": "file"` and one warning line | | | | ok |
| 12 | time per signature (step 1's `LIVE` line) | under a second | | | | 103 ms |

**Linux, here** (2026-10-16): a musl Linux desktop, GNOME Keyring 48.0 through
`secret-tool` (libsecret), Node 24.18. Steps 5 and 6 were not run: they would lock or end the
desktop session in use.

## A sealed file: the key under a passphrase

`sigelo-agent init --passphrase-file <f>` (or `seal` on a plain file; `unseal` back) keeps
`"provider": "file"` with the seed sealed in `secret`; genesis, rotations and attestations stay
readable, so `whoami` and `bundle` need no passphrase.

```json
"secret": { "provider": "file", "v": "sigelo-seal/1", "kdf": "scrypt", "n": 131072, "r": 8, "p": 1,
            "salt": "<32 bytes>", "nonce": "<12 bytes>", "ct": "<32 + 16 bytes>" }
```

key = scrypt(passphrase, salt, N = n, r, p, 32 bytes); ct = AES-256-GCM(key, nonce, seed), AAD
`"sigelo-seal/1\nscrypt <n> <r> <p>\n"` ‖ the head genesis key; base64url, no padding. A rotation
re-seals under the same salt. Every verb that signs reads the passphrase from
`SIGELO_IDENTITY_PASSPHRASE_FILE` (a file, one trailing newline dropped: a Docker secret) or
`SIGELO_IDENTITY_PASSPHRASE` (weaker: every child process and `/proc/<pid>/environ` see it); without
one, `passphrase_required`, naming both. A wrong one: `passphrase_wrong`. New passphrases: 8 bytes
or more. The scrypt key stays in memory for the process's life.
