<!-- SPDX-License-Identifier: MIT -->
# sigelo-chatwoot

Your support team answers sigelo contacts from Chatwoot. Each allowed contact gets
one Chatwoot conversation; messages go both ways, end to end. Design:
[bridge.mjs](bridge.mjs). Node ≥ 22.18, no dependencies.
Tested with a fake Chatwoot (`npm test`) and on Chatwoot 4.20.1.

**sigelo side.** Run the watcher with a spool: `sigelo-agent service install` (or
`sigelo-agent watch --spool <identity>.spool`). Each bridged contact must be tier own:
`sigelo-agent tier alice own`. Do not run `inbox` on this identity: it would take the spool.
`invite --kind desk`: a support desk, never called.

**Chatwoot side.**
1. Settings → Inboxes → Add Inbox → API. Name it, leave the callback URL empty, add agents.
   Note the account id and inbox id (the numbers in the inbox's settings URL).
2. Profile Settings → Access Token: copy it into a file, `chmod 600`.
3. Settings → Integrations → Webhooks → Configure → Add new webhook: the bridge's URL, event
   `message_created`. Copy the secret it shows into a file, `chmod 600`.

**Config** (`chatwoot.json`):

```json
{ "chatwoot": "https://chat.example.com", "account_id": 1, "inbox_id": 3,
  "token_file": "~/.config/sigelo/chatwoot.token", "webhook_secret_file": "~/.config/sigelo/chatwoot.secret",
  "identity": "~/.config/moadim/sigelo.local.json", "allow": ["alice", "did:sigelo:z6Mk…"] }
```

Optional: `spool` (default `<identity>.spool`), `listen` (default `127.0.0.1:7330`), `path`
(default `/chatwoot`), `sigelo_agent` (default `sigelo-agent`). `allow` is empty by default: nothing
is bridged. A DID is exact; a name is your name for the contact.

**Run:** `node cli.mjs chatwoot.json`. Chatwoot must reach the webhook URL. Chatwoot in Docker on
the same host: `"listen": "172.17.0.1:7330"` (the Docker bridge address), webhook URL
`http://host.docker.internal:7330/chatwoot` (`extra_hosts: ["host.docker.internal:host-gateway"]`),
and `SAFE_FETCH_ALLOW_PRIVATE_NETWORK=true` in Chatwoot's env, or it refuses a private target.
Otherwise a public TLS URL via a reverse proxy. A new message reopens a resolved conversation.

Chatwoot sees the text and files of the bridged chats, nothing else. A file a contact sends is
uploaded; a file your agent attaches is not sent (a private note says so). Unsigned or stale
webhooks get 401. State: `<identity>.chatwoot.json`, 0600, no keys.
