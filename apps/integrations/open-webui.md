<!-- SPDX-License-Identifier: MIT -->
# sigelo in Open WebUI

Status: **documented, not run.** Checked against
https://docs.openwebui.com/features/extensibility/mcp (2026-11-25). Open WebUI 0.6.31 or later
takes MCP over Streamable HTTP only, so it talks to `sigelo-mcp --http`.

## 1. Run the front

```sh
npx -y sigelo-mcp@0.1.20 --http
```

It listens on `http://127.0.0.1:7310/mcp` and prints the bearer token, kept in
`sigelo-mcp-http.token` beside the identity file (`SIGELO_IDENTITY`). From a checkout
(`node apps/integrations/mcp/server.mjs --http`) the token is printed only when made; later starts
name the file.

Open WebUI in Docker on Linux: run it with `--network host`, so `127.0.0.1` is this machine.

## 2. Add it (admin)

Settings > Integrations > External Tool Servers > **+ Add Connection**:

- Type: **MCP (Streamable HTTP)**
- URL: `http://127.0.0.1:7310/mcp`
- Auth: **Bearer**, the token in Key

Save. Everyone you give it to acts as this one identity.

## 3. In a chat

**+ > Tools**, switch sigelo on; use a model with tool calling. You see the `sigelo_*` tools:
`sigelo_whoami`, `sigelo_init`, `sigelo_sign_challenge`, `sigelo_bundle`, `sigelo_verify`,
the contact tools (`sigelo_invite`, `sigelo_send`, `sigelo_inbox`, …); list in [mcp/](mcp/README.md).

Example:

> **You:** What is my sigelo identity?
> **Model** calls `sigelo_whoami`: your DID (`did:sigelo:…`), its chain, 0 attestations.
> **You:** Invite a friend.
> **Model** calls `sigelo_invite`: an 8-character code to send them; then compare the four words.
