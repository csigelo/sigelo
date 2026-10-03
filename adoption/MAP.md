<!-- SPDX-License-Identifier: MIT -->
# Where agents live, and where a world could admit them

Read 2026-10-03 unless a row gives another date. Star counts and push dates come from `gh api`
on that day. **Acceptance** is the world side: `challenge(did, ctx)` then
`accept(challenge, {did, sig}, bundle)` from [`accept/`](../accept/README.md), plus an optional
attestation. **Lines** estimates the glue around the drop-ins, not the drop-ins themselves.
**Score** is cheapness × reach on 1–10. It is a guess for ordering the work, not a measurement.

The agent side is already free wherever the runtime is an MCP client. That covers every framework
below except AutoGen, which is in maintenance. So each row is about the world side.

## Frameworks and runtimes

| Target | Activity | Hook for acceptance | Lines | Their words for the gap | Talk to | Score |
|---|---|---|---|---|---|---|
| Hermes Agent | — | `register_a2a_peer_authenticator` (proposed) | ~60 core + plugin | DESIGN.md: "DID / Ed25519 identity … revisit if there's real demand" | [#131484](https://github.com/NousResearch/hermes-agent/issues/131484), filed 2026-10-02 | done |
| **OpenClaw** | 391k★, v2026.9.8 (2026-10-03) | `resolvePeerName(request, config)` in `extensions/a2a/src/http.ts` (2026-09-26). It only matches a Bearer token against `peers.<name>.token` and returns 401 before any plugin hook runs | ~35 (pluggable resolver) + plugin | #49971 "OpenClaw has no native agent identity system" (2026-03-18). Closed 2026-04-25: "the plugin layer is the right home" | feature_request.yml issue; ClawHub for the plugin | **9** |
| **LangGraph Agent Server** | 42.6k★, pushed 2026-10-03 | `Auth()` + `@auth.authenticate` (`langgraph_sdk/auth`, 2026-10-01). It receives the raw request and already guards `/a2a/{assistant_id}`. The challenge route goes in a custom app (`http.app` in langgraph.json) | ~40, no upstream change | #7242 "no built-in mechanism to verify agent identity" (2026-03-22, closed not planned) | a package plus forum.langchain.com; no PR needed | **8** |
| CrewAI | 59.3k★, 1.15.23 (2026-09-28) | `ServerAuthScheme.authenticate(token)` in `a2a/auth/server_schemes.py`, next to the OIDC, OAuth2, APIKey and mTLS schemes | ~40 | #4560 "no mechanism for agents to cryptographically verify each other's identity" (2026-02-22, not planned) | issues | 7 |
| Google ADK | 21.7k★, v2.11.0 (2026-10-02) | `ExecuteInterceptor.before_agent` via `A2aAgentExecutorConfig`. The `to_a2a()` security schemes are "not enforced at runtime" | ~40 | #7134 "the principal belongs in the framework" (open, 2026-09-16); #6461 a forgeable HITL confirmation from an A2A peer (open) | issues, Discussions | 7 |
| Mastra | 28.5k★, core 1.72.0 (2026-09-30) | a `MastraAuthProvider` subclass (`authenticateToken`) plus `registerApiRoute` | ~40 | #19911 asks for pre-execution authorization gates on A2A (open, 2026-07-22) | issues | 6 |
| AG2 | 5.0k★, v1.1.1 (2026-09-29) | ASGI middleware on `build_jsonrpc`, per a comment in `a2a/server.py` | ~35 | #3125 identity middleware (open, a vendor pitch) | issues | 5 |
| Pydantic AI → fasta2a | 20.4k★ / 222★ | Starlette middleware in datalayer/fasta2a | ~35 | #9209 "caller identity / tenant / delegation" (open) | issues | 4 |
| OpenAI Agents SDK, Vercel AI SDK, smolagents, Claude Agent SDK, Letta | active, 2026-09/10 | no inbound server; guardrails or the host app | ~20 in the app | OpenAI #2756: "share examples in your own repo" (2026-03-23); Claude SDK #679 "out of scope" | — (agent side works today) | 3 |
| AutoGen | last push 2026-04-15 | — | — | #7440 (open) | in maintenance; successor microsoft/agent-framework | 1 |

## Protocols

| Target | Hook | Lines | Notes | Talk to | Score |
|---|---|---|---|---|---|
| A2A v1.0.1 (Linux Foundation, 2026-05-28) | an extension URI in `capabilities.extensions`. A pre-auth endpoint runs challenge and accept, then mints the bearer token that an `HTTPAuthSecurityScheme` declares. The five scheme types are fixed, so there is no custom type | ~70 server, ~30 client | Crowded: #1672 has 661 comments, plus #1786 and #2259 (did:web). Bring running code from the rows above, not another thread | a2aproject/A2A issue → sponsor → `experimental-ext-*` | 6 |
| MCP auth, revision 2026-07-28 | an unofficial `io.sigelo/identity` extension (SEP-2133), or a comment on SEP-1933 (workload identity federation, open, updated 2026-09-28). An RFC 7523 assertion signed by the identity key would break the `"sigelo\n"` domain separation (SPEC §3), so it needs a bound key or a challenge step | ~60 | SEP-1046 says it "does not yet specify how to populate the JWT contents nor how to discover the client's JWKS URI" | modelcontextprotocol/modelcontextprotocol | 5 |

## Payment rails

| Target | Hook | Lines | Gap | Talk to | Score |
|---|---|---|---|---|---|
| **x402** (6.7k★, pushed 2026-10-02) | a resource-server extension: `enrichPaymentRequiredResponse` puts the challenge in the 402, `onBeforeVerify` runs accept on the retry, and `onAfterSettle` signs an attestation the buyer keeps as a receipt | ~60 | Identity today is a wallet address (SIWX) and receipts are seller-held (offer-and-receipt). The WG's own issues: #8 post-settlement record, #11 returning customer, #18 portable attributes, #32 key rotation | [x402-foundation/wg-identity](https://github.com/x402-foundation/wg-identity) (created 2026-08-03, 32 open) | **8** |
| MPP / mppx (Stripe + Tempo) | a third-party profile through `Attestation.Client`/`Attestation.Server` ("more can be added", blog 2026-08-12). It carries a §5.2 answer and then a minted token. It does not carry per-request RFC 9421 signatures, because the identity key signs only challenges | ~50 | The app has to choose the identity protocol; there are two profiles today (Web Bot Auth, TAP) | tempoxyz/mpp-specs | 7 |
| Stripe ACP, Google AP2, Visa TAP, Mastercard Agent Pay | checkout extensions or network-run key directories | 100+ | identity is enrolled with the network | closed | 1–2 |

## Networks, registries, boards

| Target | Activity | How agents get in today | sigelo fit | Score |
|---|---|---|---|---|
| ERC-8004 registries | 63,832 registrations on Base (2026-02→08), 6.8 % with live endpoints | an on-chain registration file | its `DID` service entry can name a `did:sigelo` (0 lines); a world could act as a validator | 5 |
| Bounty (trybounty.ai) | 5K+ tasks, 200+ agents (2026-09) | their agent SDK | gate onboarding and attest each verified task, ~40 lines | 5 |
| AGNTCY directory / identity | Linux Foundation project | "bring your own identity", badges | badge adapter, ~80 lines; agntcy/identity-service #105 | 4 |
| Moltbook | 2.9M agents (2026-06-06) | "Sign in with Moltbook": 1-hour JWTs from its server | none (invite-only API); at most a bridge world that attests a Moltbook login | 3 |
| NANDA index, Agentverse, Olas, Virtuals | — | chain address or signed AgentFacts | no plugin point | 2–3 |

## Order

1. OpenClaw: same argument as Hermes, largest reach. [`proposal-openclaw.md`](proposal-openclaw.md)
2. LangGraph: needs nobody's permission; ship the package, then tell the forum. [`proposal-langgraph.md`](proposal-langgraph.md)
3. x402 wg-identity: the WG asks for exactly this. [`proposal-x402.md`](proposal-x402.md)
4. Then CrewAI and ADK (the same shape as 1), MPP (the same shape as 3), and A2A once 1–3 run.

Pattern seen across these trackers: a maintainer closes "add identity vendor X" (OpenAI #2511
and #2756, OpenClaw #6842, CrewAI #5561). A small, neutral hook with the code kept outside their
repository has better odds.
