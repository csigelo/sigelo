# site/SEO.md — discoverability checklist (not a page)

Sources fetched 2026-10-02; dates are the pages' own where they show one.

## Done in the tree

- **robots.txt** — `Allow: /` for all; named tokens as published: OpenAI `GPTBot`, `OAI-SearchBot`,
  `ChatGPT-User` (developers.openai.com/api/docs/bots); Anthropic `ClaudeBot`, `Claude-SearchBot`,
  `Claude-User` (support.claude.com/en/articles/8896518, 2026-04-07); Perplexity `PerplexityBot`,
  `Perplexity-User` (docs.perplexity.ai/guides/bots); `Google-Extended`
  (developers.google.com/search/docs/crawling-indexing/google-common-crawlers, 2026-07-14);
  `Applebot`, `Applebot-Extended` (support.apple.com/en-us/119829, 2026-09-04); `CCBot`
  (commoncrawl.org/ccbot); `Amazonbot`, `Amzn-SearchBot` (developer.amazon.com/amazonbot);
  `Meta-ExternalAgent`, `Meta-WebIndexer` (developers.facebook.com/docs/sharing/webmasters/web-crawlers);
  `MistralAI-User`, `MistralAI-Index` (docs.mistral.ai/robots); `DuckAssistBot`
  (duckduckgo.com/duckduckgo-help-pages/results/duckassistbot). `Sitemap:` line. Bing/Copilot use
  `bingbot`, covered by `*`.
- **Headers** (nginx.conf): `Link: </x.md>; rel="alternate"; type="text/markdown"` on every page,
  `Link: <https://sigelo.io/x.html>; rel="canonical"` on every twin (so the twin is not indexed
  as a duplicate). `/sha256/` immutable only on 200/304 (a 404 there was cached for a year).
  ETag + Last-Modified are nginx defaults (weak ETag under gzip), already live; gzip already
  covers md/json/txt; Cache-Control an hour. No allowlist change was needed (`map`, `add_header`).
- **IndexNow** — key in `site/deploy/indexnow-key.txt`, published as `/<key>.txt` by build.mjs;
  `site/deploy/indexnow.sh` POSTs the sitemap URLs to api.indexnow.org after a passing deploy
  of https://sigelo.io (deploy.sh). Shared with Bing, Yandex, Naver, Seznam, Yep, Amazon; not
  Google (indexnow.org/documentation, /faq).
- **JSON-LD** — `SoftwareSourceCode` (+ `sameAs` GitHub, `keywords`) on every page;
  `TechArticle` with `headline`, `dateModified` (last commit of the source), `about` on spec and
  adopt. No rich result exists for either; it is for parsers, so it stays small.
- **llms.txt** summary names DID, Ed25519, offline verification and the MCP server; `/adopt`
  gained "From an MCP client" (registry name + harness configs). Budgets unchanged and met.
- **Packages** — `description`, `keywords`, `homepage`, `repository` (+ `directory`), `bugs` on
  ts, spend, adapters/moadim, integrations/mcp, kit.
- **server.json** — `$schema` 2025-12-11 (latest release per the registry's server-json
  CHANGELOG); validated against that schema; `websiteUrl` fixed (pointed at the cut
  `/integrations.html`, a 404). `mcpName` = name, checked by test/run.mjs.
- **README.md** top: one paragraph with the mechanism, sigelo.io, llms.txt, the registry name.

## Owner to do (exact values)

1. **GitHub** (Settings, or `gh repo edit csigelo/sigelo --description … --homepage https://sigelo.io --add-topic …`):
   description: `Portable, offline-verifiable identity for AI agents: a DID hashed from an Ed25519
   genesis, attestations signed by worlds, bundles verified offline. TypeScript, Go, MCP server.`
   Topics (20, the maximum): `ai-agents agent-identity decentralized-identity did did-method
   ed25519 digital-signatures attestation reputation offline-first verification identity-protocol
   cryptography mcp mcp-server model-context-protocol llm-agents monero typescript golang`
2. **Google Search Console** — add a *Domain* property `sigelo.io`; it shows a token; add DNS
   `sigelo.io. TXT "google-site-verification=<token>"` and keep it forever (domain properties
   accept DNS only; support.google.com/webmasters/answer/9008080). Submit `https://sigelo.io/sitemap.xml`.
3. **Bing Webmaster Tools** — "Import from Google Search Console" (no record needed), or DNS
   `<code>.sigelo.io. CNAME verify.bing.com.` with the code Bing shows
   (bing.com/webmasters/help/add-and-verify-site-12184f8b). IndexNow needs no account.
4. **npm, then the MCP registry** — after `sigelo-mcp` (and its deps) are on npm:
   `mcp-publisher login github` (as csigelo, device flow), then in `integrations/mcp/`:
   `mcp-publisher publish`; check `https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.csigelo/sigelo`.
   PulseMCP has paused submissions and ingests the registry (pulsemcp.com/submit, 2026-09-03).
5. **Directories** (after npm): Glama — "Add MCP Server" with the repo URL (glama.ai/mcp/faq; its
   score badge is what awesome-mcp-servers shows). mcp.so/submit and mcpservers.org/submit take
   the repo URL (free review ~2 weeks; the $39 fast lanes are not worth it). Smithery wants a
   hosted HTTP server or an `.mcpb` bundle: skip.
6. **awesome-mcp-servers** (punkpeye) PR, section `🪪 Identity`, alphabetical (after `AIops-tools`):
   `- [csigelo/sigelo](https://github.com/csigelo/sigelo) [![csigelo/sigelo MCP server](https://glama.ai/mcp/servers/csigelo/sigelo/badges/score.svg)](https://glama.ai/mcp/servers/csigelo/sigelo) 📇 🏠 🍎 🪟 🐧 - Portable, offline-verifiable agent identity: create a DID, sign world challenges, store attestations, build and verify bundles with no network; optional Monero wallet tools.`
   PR title: `Add csigelo/sigelo (Identity)`. Drop the badge if Glama has not listed it yet.
   awesome-ai-agents (e2b-dev) lists agents only: sigelo is not one, skip.
7. **DID method** — PR to w3c/did-extensions adding `methods/sigelo.json` (not registered today):
   `{"name": "sigelo", "status": "registered", "verifiableDataRegistry": "None (self-certifying: the DID is the SHA-256 of its genesis document)", "contactName": "csigelo", "contactEmail": "the contact address", "contactWebsite": "https://sigelo.io", "specification": "https://sigelo.io/spec.html"}`
   Reviewers check the spec for DID syntax, CRUD operations and Security/Privacy sections
   (README of w3c/did-extensions); SPEC.md has the syntax (§DID) and SECURITY/THREAT-MODEL, but
   no CRUD heading: add a short DID-method section to SPEC.md first, or expect review questions.
8. **Show HN** (Owner's call; must be something people can try — news.ycombinator.com/showhn.html):
   title `Show HN: sigelo – portable identity for AI agents, verified offline`; text:
   "An agent's DID is the hash of a genesis document holding its Ed25519 key. Platforms sign
   attestations about it; the agent carries them as a bundle that anyone verifies with no
   network, server, registry or chain. TypeScript library, Go verifier, MCP server, and an
   optional Monero keeper so agents can pay without holding a key. Draft spec with test vectors:
   https://sigelo.io/adopt.html". Post once npm is live, and stay to answer. r/Monero and
   monero.town: same text, lead with the keeper; Lobsters needs an invite.

## Deliberately not done

- **Content-Signal** in robots.txt — Cloudflare's policy syntax (blog.cloudflare.com/content-signals-policy,
  2025-09-24; `use=` added 2026-08), not an IETF document; the IETF AIPREF drafts
  (`draft-ietf-aipref-vocab-08` 2026-09-13, `-attach-05` 2026-08-18, `Content-Usage:`) are
  drafts, not standards. Revisit when AIPREF is an RFC; the site allows everything anyway.
- **`/.well-known/llms.txt`, `Sitemap:` in llms.txt** — llmstxt.org (modified 2026-08-10) rejects
  `.well-known` and defines no Sitemap section. Note: Google says it does not use llms.txt
  (Search Central, 2026-05); Lighthouse 13.3 audits it (H1 + links) — ours passes.
- **A2A agent card** — `/.well-known/agent-card.json` requires `supportedInterfaces` with a live
  endpoint and `skills`; sigelo is a protocol and a local MCP server, not a reachable agent. A card
  would be false.
- **`/.well-known/ai-plugin.json`** — ChatGPT plugins shut down 2024-04-09.
- **SoftwareApplication / FAQPage rich results** — Google requires `aggregateRating` or `review`
  for software apps (none exist, none invented); FAQPage results are gone (removal notice 2026-06).
- **OpenGraph, humans.txt, `OAI-AdsBot`/`Google-CloudVertexBot` lines** — for humans or for ad and
  owner-requested crawls; `*` covers them.
- **PyPI, Hugging Face** — no Python package, no model or dataset.
- **`etag`/`gzip` directives** — nginx defaults already do it (live headers checked 2026-10-02).
