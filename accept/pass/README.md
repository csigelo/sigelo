<!-- SPDX-License-Identifier: MIT -->
# sigelo-pass: a door for AI agents beside your captcha

Your site admits an agent that proves its sigelo identity, and sets its own cookie. You install
the door; the agent never solves or bypasses a captcha, and never passes where no door is.

```sh
openssl rand -hex 32 > pass.secret          # the cookie key; changing it logs every agent out
SIGELO_PASS_ORIGIN=https://example.com SIGELO_PASS_SECRET_FILE=pass.secret node verifier.mjs   # nginx/Caddy
sigelo-agent pass https://example.com/members/     # the agent: prints the cookie for its harness
```

## Express

```js
import express from 'express';
import { sigeloPass } from './sigelo-pass.mjs';
const app = express();
const door = sigeloPass({ origin: process.env.ORIGIN ?? 'https://example.com', secret: process.env.SIGELO_PASS_SECRET });
app.use(door.routes);                // /.well-known/sigelo-pass, /sigelo-pass/challenge, /sigelo-pass/accept
app.use('/members', door.gate);      // no valid cookie → 403 with the Sigelo-Pass hint
app.get('/members/', (req, res) => res.send(`hello ${req.sigeloPass.did}\n`));
app.listen(process.env.PORT ?? 3000);
```

Options: `ttl` (3600 s), `wants`, `limits`, `addr(req)` (the client address behind your proxy),
`onAccept(result, req)` (your policy over the §9.1 result; throw to refuse). Keep the repo's
layout: `sigelo-pass.mjs` imports [`../node/sigelo-accept.mjs`](../node/sigelo-accept.mjs); `npm i sigelo`.

## nginx and Caddy

`verifier.mjs` (one file, no framework) on 127.0.0.1:8791 answers `GET /sigelo-pass/check`: 204
with `Sigelo-Pass-DID` for a valid cookie, else 403 with the wall. Its header lists the env.

```nginx
location = /.well-known/sigelo-pass { proxy_pass http://127.0.0.1:8791; }
location ^~ /sigelo-pass/ { proxy_pass http://127.0.0.1:8791; proxy_set_header X-Real-IP $remote_addr; }
location = /sigelo-pass/check { internal; proxy_pass http://127.0.0.1:8791; proxy_pass_request_body off; proxy_set_header Content-Length ""; }
location @sigelo_wall { rewrite ^ /sigelo-pass/wall break; proxy_pass http://127.0.0.1:8791; }
location /members/ {
    auth_request /sigelo-pass/check;
    auth_request_set $sigelo_did $upstream_http_sigelo_pass_did;
    error_page 403 = @sigelo_wall;
    proxy_set_header Sigelo-Pass-DID $sigelo_did;
    proxy_pass http://127.0.0.1:3000;
}
```

```caddy
handle /.well-known/sigelo-pass { reverse_proxy 127.0.0.1:8791 }
handle /sigelo-pass/* {
    reverse_proxy 127.0.0.1:8791 {
        header_up X-Real-IP {remote_host}
    }
}
handle /members/* {
    forward_auth 127.0.0.1:8791 {
        uri /sigelo-pass/check
        copy_headers Sigelo-Pass-DID
    }
    reverse_proxy 127.0.0.1:3000
}
```

Run the verifier with `SIGELO_PASS_ADDR_HEADER=x-real-ip`, so limits count clients, not the proxy.

## sigelo-pass/0

**Hint.** The wall (any status, usually 403) carries `Sigelo-Pass: <hint URL>` and
`Link: <hint URL>; rel="sigelo-pass"`; an HTML wall also `<link rel="sigelo-pass" href="…">`.
The conventional hint URL is `/.well-known/sigelo-pass`. An agent acts only on a hint.

**Hint file** (`application/json`):

```json
{ "v": "sigelo-pass/0", "ctx": "example.com", "challenge": "/sigelo-pass/challenge",
  "accept": "/sigelo-pass/accept", "cookie": "sigelo_pass", "ttl": 3600,
  "wants": { "min_age": 0, "age_by": [], "operator": false },
  "limits": { "per_did": 20, "per_addr": 60, "window": 3600 } }
```

`ctx` is the gated page's host (`URL.host`: lowercase, port only when not the default). URLs
resolve against the hint's URL and must share the page's origin. `wants.operator`: the bundle
must carry an unexpired `sigelo-relay/operator` attestation. `wants.min_age` (s): now minus the
earliest `iat` of an attestation by an `age_by` issuer; genesis `created` never counts.
`limits`: challenges per window, per DID and per client address (IPv6 per /64); over → 429, `Retry-After`.

**Handshake.** `GET <challenge>?did=<current DID>` → the [SPEC](../../SPEC.md) §5.2 challenge
`{v, typ, did, ctx, nonce}`, single use, 5 minutes. The agent refuses a `ctx` other than the
page's host, so a challenge one site relays from another is useless; the site refuses one it
issued for another ctx. The agent signs it as `sigelo-agent sign-challenge` does and posts
`{challenge, did, sig, bundle}` to `<accept>`. The site verifies offline (§9), checks `wants`,
and answers `200 {v, did, cookie: {name, value, exp, path}}` with `Set-Cookie` (HttpOnly,
SameSite=Lax, Secure on https, Max-Age = ttl), or `{error, check}`: 400 `request`,
401 `refused`/`ctx`, 403 `wants_age`/`wants_operator`/`policy`, 429 `rate_limited`.
No invite code: the DID and its signature are the pass.

**Clearance.** Cookie `sigelo_pass=sp0.<did>.<exp>.<mac>`, `mac` = base64url
HMAC-SHA256(secret, `"sigelo-pass/0\n" ctx "\n" did "\n" exp`). Valid while `exp` is in the
future and at most `ttl` away. The site gets the §9.1 result at accept (`onAccept`) and
`{did, exp}` per request (`req.sigeloPass`, `Sigelo-Pass-DID`).

**What it proves.** Who, not harmless: an identity costs one proof of work at a relay, so a site
that wants more asks for age or an operator statement, and limits per DID.
The standard road through Cloudflare and other walls is
[Web Bot Auth](../../apps/integrations/web-bot-auth/README.md).

## Test

`cd accept/pass && npm install && node test.mjs` (also run by `sh accept/test.sh`).
