# site/ — sigelo.io

The website, built for agents first: every page is HTML with a Markdown twin at the same path,
plus `llms.txt`, `llms-full.txt`, `adopt.md`, `index.json`, `robots.txt`, `sitemap.xml` and
`.well-known/security.txt` at the root (ROADMAP §3). Static files only: no JavaScript to read
it, no cookies, no analytics, no requests to another origin. It is generated from the
repository's own documents at build time, so it cannot say something the tree does not.

```sh
node site/build.mjs          # → site/dist/ (git-ignored); no npm dependencies, node ≥ 22
node site/test/run.mjs       # serves dist on 127.0.0.1 and checks it: ALL PASS (<n> checks), exit 0
node site/test/run.mjs --serve 8080    # just serve it (localhost, 127.0.0.1 and ::1)
```

(The repository root has no `package.json`, so there are no `npm run site:*` scripts.)

| Path | What |
|---|---|
| `build.mjs` | the generator and its Markdown renderer (one file, no dependencies) |
| `src/*.md` | the pages written for the site: front matter (`title`, `description`), then Markdown with `{{…}}` values the build fills from the tree |
| `src/style.css` | the one stylesheet; dark/light by `prefers-color-scheme` |
| `test/run.mjs` | the site check (below) |
| `test/TASK-site.md`, `test/collect.sh`, `test/grade-site.mjs` | a docs-test-style task: a model gets only the served site and the release files and must produce a verified bundle; graded 6 points |

## What the build reads

- **Rendered as pages** (and copied as their `.md` twin, links rewritten to the site): SPEC.md →
  `/spec`, SECURITY.md → `/security`, CHANGELOG.md → `/changelog`. Pages from `src/`: `/` (index),
  `/adopt`, `/verify`, `/keeper`, `/contact`. Nothing else: `test/run.mjs` fails on any other page
  and on a page over its word budget (index 120, adopt 250, verify 150, keeper 200, contact 80,
  llms.txt 150).
- **Verbatim** under `/raw/<repo path>`: those three, QUICKSTART, WHY, THREAT-MODEL, VERSIONING,
  MONERO, kit/README.md, spend/README.md (listed with sizes in llms.txt), `test-vectors.json`,
  `schema/*.json`, `spend/openapi.yaml` (its `../schema/` references resolve there). Also
  `/test-vectors.json`, and `/sha256/<hex>/SPEC.md` and `/sha256/<hex>/test-vectors.json`, which
  never change once published.
- `/examples/world.mjs`: `examples/world.mjs` with its one import changed from
  `../ts/dist/sigelo.js` to the npm package `sigelo` (a header says so), so an agent with the
  release tarballs can run the mock world without a clone.
- From the tree at build time: vector counts and sha256s, package versions, the commit (in
  `index.json` only). The output is a function of the commit; no wall clock.

A relative link in a repository document that is not a page or a raw copy points at
`https://github.com/csigelo/sigelo/blob/main/<path>` (`main` is the branch release/publish.sh creates).

## The check (`test/run.mjs`)

Over HTTP on a random localhost port, with this README's content types and Markdown
negotiation: every internal link and `#fragment` in every page resolves; every `.md` twin's
internal links resolve; every page has its twin, `<link rel="alternate" type="text/markdown">`,
a description, a canonical URL on https://sigelo.io, one `<h1>`, JSON-LD that parses and holds
the project's `SoftwareSourceCode` (`TechArticle` on spec and threat model); tags balance; no
executable script, inline style or event handler; nothing loaded from another origin;
`llms.txt` has the llmstxt.org shape and all its links resolve; `robots.txt` names the crawlers
of ROADMAP §3 and its sitemap resolves; every `sitemap.xml` URL resolves; `index.json`'s
sha256s match the files served *and* the repository's own files; `security.txt` has Contact,
one Expires about a year out, Canonical and Policy; `integrations/mcp/server.json` agrees
with its `package.json`. It makes no external request.

## Deploying

```sh
site/deploy/deploy.sh sigelo@sigelo.io      # build, test, upload, nginx config, post-deploy check
node site/deploy/check.mjs                  # the check alone
```

Everything is in [`deploy/`](deploy/README.md): `deploy.sh` (refuses a dirty tree, runs
`build.mjs` and `test/run.mjs` and stops on any FAIL, uploads with rsync or `tar | ssh`, keeps
the previous upload as `dist.prev` for `--rollback`, installs `nginx.conf` through a root
helper that allowlists it and runs `nginx -t`), `check.mjs` (the live site's types,
negotiation, sha256s, build commit = local HEAD, headers, HSTS, redirects), `server-setup.sh`
(one-time, as root: the unprivileged `sigelo` user, nginx, `certbot certonly --nginx` for
sigelo.io and www, renewal, log rotation), `nginx.conf`, `apache.conf`, and the DNS records,
rollback and privacy notes. No server exists yet: everything was tested locally (deploy/README.md
says how) and the TLS, HSTS and redirect checks have not run against a real host.

What any host must add, because files cannot: content types (`.md` as
`text/markdown; charset=utf-8`; JSON, XML and YAML without a charset, as `test/run.mjs` serves
them), `Accept: text/markdown` negotiation (an agent asking for Markdown at `/`, `/spec.html`
or `/spec` gets `/index.md` or `/spec.md`), security headers, caching. Links are root-relative,
so `site/dist/` goes at the root of https://sigelo.io.

Caching: `/sha256/*` is content-addressed, cache it for a year, immutable. Everything else,
`/test-vectors.json` included, changes with commits until the wire freezes at v0.2: an hour.
After the freeze, `/test-vectors.json` may be cached long too.

The JSON-LD blocks are `<script type="application/ld+json">` data blocks. Browsers neither
execute nor fetch them, so `Content-Security-Policy: default-src 'self'` does not block them,
and there is no executable inline script anywhere (`test/run.mjs` checks).

The nginx and Apache configurations that used to be inlined here are now
[`deploy/nginx.conf`](deploy/nginx.conf) and [`deploy/apache.conf`](deploy/apache.conf), with
the same headers and negotiation, plus TLS 1.2+, HSTS (starting at five minutes), `www` → apex
and HTTP → HTTPS 301s, logs without client addresses, and one fix: the old nginx block listed
`application/json`, `application/xml` and `application/yaml` in `charset_types`, which would
have served them with `; charset=utf-8`, unlike `test/run.mjs`. Neither file has been through
`nginx -t` or `apachectl configtest` (no server here); the helper runs `nginx -t` before
every reload and keeps the old file if it fails.

### GitHub Pages (ROADMAP §3's recommended primary: no IP linkage to the maintainer)

Publish `site/dist/` with the official Pages action (`actions/upload-pages-artifact` +
`actions/deploy-pages`, pinned by SHA like the rest of CI), custom domain `sigelo.io` in the
repository's Pages settings, HTTPS enforced. The build writes `.nojekyll` (so Jekyll does not
turn the `.md` twins into HTML) and `CNAME`. What Pages cannot do: custom headers (no CSP or
Permissions-Policy header; the pages need none to be safe, having no scripts), `Accept`
negotiation (agents use the `.md` URLs, which every page links), and per-path caching (Pages
sets its own short `max-age`). Which content type Pages sends for `.md` was not checked here
(unverified); a mirror on a host configured as above fixes all three.

## Before deploying (decision D1)

Decided 2026-10-01: the account **`csigelo`** (the pseudonym is the handle; no other name),
the domain **sigelo.io**, the general e-mail **`contact@sigelo.io`**. Still open: a display name
beyond the handle (if any), the `security@sigelo.io` mailbox and its age recipient, the vendor
DID ceremony, prices and hours, hosting and DNS.

1. **Repository** — done: `https://github.com/csigelo/sigelo`, `REPO` in `site/build.mjs` (it
   feeds JSON-LD `codeRepository`, `index.json` `repository`, every link to a repository file,
   the security.txt comment) and `repository.url` in `integrations/mcp/server.json`; links use
   branch `main`. Nothing is pushed yet, so every repository link 404s until the first push.
2. **Contact** — `security.txt` says `Contact: mailto:security@sigelo.io`, the mailbox
   SECURITY.md plans at the domain; the mailbox must exist before the site goes up. SECURITY.md
   still reads `age1<to-be-filled-at-D1>` and `<simplex-contact-address>` (it is rendered as is
   on `/security`). The general address `contact@sigelo.io` is on `/kit` and `/keeper`. Add an `Encryption:` line to security.txt once the age
   recipient is published, and a `Contact:` line for GitHub private vulnerability reporting once
   the repository exists. The site's security.txt `Expires` is the commit date plus a year: rebuild
   and redeploy before it lapses.
3. **Author** — not used on the site. To show the pseudonym (JSON-LD `author`, the footer),
   add `csigelo` in `build.mjs`; nothing else needs it.
4. **Go module path** — `github.com/csigelo/sigelo/go` in the public export (release/publish.sh
   `SIGELO_GO_MODULE`); the private tree keeps `module sigelo`. The verify page's `go install`
   line names the public path; its "today" clause reads `go/go.mod`.
5. **"After the first publish" / "Today"** — `src/adopt.md`, `src/index.md`, `src/verify.md`,
   `src/keeper.md`, `src/integrations.md` describe both; drop the tarball paths once npm and the
   release page exist, and re-run `test/run.mjs`.
6. **MCP Registry** — `integrations/mcp/server.json` uses the GitHub namespace
   `io.github.csigelo/sigelo`: `mcp-publisher login github` as csigelo proves it, so no domain
   proof is needed. `integrations/mcp/package.json` carries `"mcpName": "io.github.csigelo/sigelo"`,
   the registry's check that the npm package belongs to the server; `test/run.mjs` checks the two
   agree. Publish only after `sigelo-mcp` is on npm.

### `server.json` fields written from memory (check against the registry's current schema)

Not verified against a live schema on this host: the `$schema` URL and its date
(`2025-09-29`; a later revision may exist), whether `title` and `websiteUrl` are accepted at the
top level, `packages[].runtimeHint`, whether `registryBaseUrl` is required or optional,
`environmentVariables[].format` values (`filepath`, `string`), and the 100-character limit on
`description` (the test enforces it). Validate with `mcp-publisher validate` (or the registry's
schema) before publishing.

### `robots.txt` sources

The crawler tokens and the first three sources are ROADMAP §3's (OpenAI
developers.openai.com/api/docs/bots, Anthropic support.anthropic.com/en/articles/8896518,
Perplexity docs.perplexity.ai perplexity-crawlers). The URLs given for CCBot, Amazonbot,
Meta-ExternalAgent, Google-Extended and Applebot-Extended were written from memory and not
fetched (unverified). Only the product tokens matter to a crawler; the full user-agent strings
are on those pages.

## Running TASK-site

```sh
release/build.sh /tmp/rel                       # the release files the task gives the model
node site/build.mjs && node site/test/run.mjs --serve 8080 &
mkdir -p /tmp/run-S/rel && cp /tmp/rel/* /tmp/run-S/rel/
# give the model site/test/TASK-site.md with <PORT> = 8080, /tmp/run-S as its working directory,
# a shell with node and npm (registry reachable for @noble/*), nothing else. Keep the transcript.
mkdir -p runs/<id>/_world && cp /tmp/run-S/out/* runs/<id>/ && cp /tmp/run-S/world.local.json runs/<id>/_world/
node site/test/grade-site.mjs runs/<id> --verify /tmp/rel/sigelo-verify-<os>-<arch>     # SCORE n/6
```

A transcript that fetches anything but `http://localhost:<PORT>` and the npm registry, or reads
inside the tarballs or `node_modules/`, is void. A dry run by the task's author (who knows the
repository, so it is not a datapoint) scored 6/6 with the release of `c2c9cdc`.
