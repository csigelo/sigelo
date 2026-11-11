<!-- SPDX-License-Identifier: MIT -->
# Where the identity key rests

```sh
sigelo-agent init --recovery "$(sigelo-agent recovery-key --out recovery.key)"  # keychain if one answers
sigelo-agent keys status          # provider, "signs": true|false and a code; never the key
sigelo-agent keys wrap            # plain file → keychain
sigelo-agent keys unwrap --plain  # keychain → plain hex
sigelo-key-agent start            # prints SIGELO_KEY_AGENT=<socket>
export SIGELO_KEY_AGENT=<socket>
sigelo-agent keys to-agent        # file or keychain → the agent; the file says {"provider":"agent"}
```

`SIGELO_KEY_PROVIDER=file|keychain|agent` picks a new identity's form; `keychain` named with no
store fails closed (`keychain_unavailable`). No provider falls back to another; no MCP tool moves
or shows a key.

## What each protects

| Provider | A copied file (backup, sync, commit) | Code running as you | Root |
|---|---|---|---|
| `file` | the key | the key | the key |
| `keychain` | nothing: its key is in the OS store | the key, while the session is unlocked | the key |
| agent, your user | nothing | signatures on known bodies, no rotation; the agent's store is still readable | the key |

The agent signs only sigelo challenges, relay logins, invite proofs, messages, prekeys and notices
naming its DID; bindings and invoices with `--allow-payments`; attestations with `--allow-attest
<ctx>`. Never a rotation through `sign` (`policy_rotation`): an injected model cannot move the
identity to its own key.

## Choosing

- **Laptop or desktop with a keychain:** the default `keychain`. Add the agent when a model has
  a shell: the key then stays out of the model's and the MCP server's processes.
- **Server or daemon:** no keychain answers, so run the agent as a unit (`sigelo-key-agent
  install-unit --store-plain`) and set `SIGELO_KEY_AGENT` in the MCP server's `env`. Clients
  share the agent's uid (its socket directory is 0700), so that uid can read the plain store: an
  agent under a separate user is not supported yet.
- **Plain file** (`"provider": "file"`, hex in a 0600 file): what `init` writes, with one warning
  line, where no keychain answers. Fine for throwaway and test identities; wrap or move it
  once a store or agent exists.

`keys wrap` and `to-agent` do not unleak: older copies still hold the key. Rotate after moving one
that may have been copied.

## Per OS

| OS | Store | Notes |
|---|---|---|
| macOS | login Keychain, `security` | written with `-T ""`: reads ask first ("Always Allow" undoes it). Untested on macOS |
| Linux | Secret Service (GNOME Keyring, KWallet, KeePassXC) through `secret-tool` | Debian, Ubuntu: `apt install libsecret-tools`. Any session process reads an unlocked item unasked. Tested: GNOME Keyring 48 |
| Windows | DPAPI, current user, via PowerShell (not Credential Manager) | the blob is in the file's `dpapi` field; a lost profile loses it. Untested on Windows; the agent's pipe permissions unchecked |

Checklist and results: [KEYCHAIN.md](KEYCHAIN.md). A wrapped file copied to another machine is `keychain_missing`: `keys unwrap --plain` on the old one, `keys wrap` on the new.
A locked store prompts or refuses (`keychain_unavailable`), never a plain key.

## Rotation and recovery

- `sigelo-agent rotate`: `file` writes the new hex; `keychain` seals the new key under the same
  item; the agent makes the key itself, kept pending until the file is written.
- `recover --recovery-key <file>`: on a clean machine with a copy of the identity file, never the
  stolen host, the recovery key brought from offline. The new key is written as plain hex,
  whatever held the old one: `keys wrap` or `keys to-agent` again (until then, `SIGELO_KEY_AGENT`
  set is `key_agent_mismatch`).

Planned: hardware keys through the agent, FIDO2 `hmac-secret` and OpenPGP cards.
