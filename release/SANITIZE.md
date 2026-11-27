<!-- SPDX-License-Identifier: MIT -->
# Sanitize before export

The public repositories read as a product by a maintainer. Nothing in them names who
decided, where it runs, or what it ran on.

## Never public

- People: real names, quoted handles, anyone as the one who decided. Write "the
  maintainer", "an operator", or the reason; no decision dates.
- Places and machines: home directories, device models, an operator's devices and paths,
  hostnames, private addresses, the hosting company, time zones.
- Identities and secrets: real DIDs, funded wallet addresses, keys, seeds, passwords,
  tokens, session ids or links.
- Plans: the company, internal planning, journal, risk and commercial files, and citations
  of them.
- E-mail: only contact@sigelo.io, security@sigelo.io and the GitHub noreply address.

"The Owner" as a product role (who holds the 25 words) is fine.

## Check

```sh
git grep -n -I -i -E '<pattern>' -- . ':(exclude)<each internal path>'
```

## The gate

`release/publish.sh` greps the export tree, the staged clone and its commit message, and
refuses a non-UTC commit date. Lists: the private one (outside the repository) plus those
built into publish.sh, never exported. One hit and nothing is written.

`publish.sh --check-public [N]`, before every export: both repositories' PRs, reviews,
comments, issues, releases (bots skipped) and last N commit messages. Fix a body with
`gh api`; its old text stays under "edited" until deleted on the web page.

Not checked: CI greps generic shapes only (home paths, private addresses), without the
private list. Public history before 2026-11-24 is unchecked, by decision; GitHub dates the
commits it merges.

## On a hit

Reword it in the private repository, run the suites that pin the file's strings, commit, and
export again. Never edit a public clone by hand.
