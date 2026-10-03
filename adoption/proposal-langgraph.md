<!-- SPDX-License-Identifier: MIT -->
<!-- Draft, not posted. Venue: forum.langchain.com (LangGraph category), as an announcement of a
working package; no upstream change is asked. Ship the package first. -->

## Problem

#7242 (2026-03-22, closed as not planned) said LangGraph has "no built-in mechanism to verify
agent identity". That is still the case for callers of an Agent Server. `/a2a/{assistant_id}` and
the runs API know only what a custom `@auth.authenticate` handler returns, and in practice that
is an API key or an OAuth subject. When another agent calls your graph, you learn which key it
holds, not which agent it is, and nothing about how it behaved elsewhere.

## Proposal

No change to LangGraph. The custom auth handler you already support can admit a caller by a
key-based DID. A custom route issues a challenge `{v, typ, did, ctx, nonce}` (single use, five
minutes). The caller signs it with `sigelo_sign_challenge`, a tool in the sigelo MCP server that
works through langchain-mcp-adapters, and receives a short-lived token. `@auth.authenticate`
then maps the token to `identity = did`. Your `@auth.on` rules and per-thread ownership work as
before. `permissions` can come from attestations that other services signed about the caller.

```python
# auth.py, referenced as "auth": {"path": "./auth.py:auth"} in langgraph.json
from langgraph_sdk import Auth
from sigelo_accept import accept          # accept/python/sigelo_accept.py
auth = Auth()

@auth.authenticate
async def authenticate(authorization: str | None) -> Auth.types.MinimalUserDict:
    entry = TOKENS.get((authorization or "").removeprefix("Bearer "))   # minted by /sigelo/login
    if not entry:
        raise Auth.exceptions.HTTPException(status_code=401, detail="sigelo login required")
    return {"identity": entry["did"], "permissions": entry["issuers"]}

# app.py ("http": {"app": "./app.py:app"}): GET /sigelo/challenge -> challenge(did, ctx);
# POST /sigelo/login -> r = accept(b["challenge"], b, b["bundle"]); TOKENS[t] = {did, issuers}
```

## What it is not

It holds no custody, uses no token or coin, and makes no network call during verification. It
depends on no hosted service. The code is MIT: about 40 lines next to the drop-in, which needs
`cryptography` and one static verifier binary. It replaces neither OAuth nor API keys. It
answers a different question: the same agent across deployments.

## Ask

Try it and point out what breaks. If it is useful, a link from the custom-auth docs is enough.
