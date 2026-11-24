<!-- SPDX-License-Identifier: MIT -->
# Sanitize before export

The public repositories read as a product by a maintainer. Nothing in them names who
decided, where it runs, or what it ran on.

## Never public

- People: real names, handles of people quoted, anyone as the one who decided ("X asked",
  "X's rule, <date>"). Write the date alone, "the maintainer", "an operator", or the reason.
- Places and machines: home directories, device models, the operating system of a
  maintainer's device, hostnames, IP addresses other than documentation and test ranges,
  the hosting company, time zones.
- Identities and secrets: the DIDs of real people or agents, wallet addresses that hold real
  coins, keys, seeds, passwords, tokens, relay session ids.
- Companies and plans: the maintainer's company, internal planning, journal, risk and
  commercial files, and citations of their sections.
- E-mail: only contact@sigelo.io, security@sigelo.io and the GitHub noreply address.

"The Owner" as a product role (who holds the 25 words, signs a keeper's policy) is fine.

## Check

```sh
git grep -n -I -i -E '<pattern>' -- . ':(exclude)<each internal path>'
```

Run it over the private tree minus the internal paths, and over each public clone.

## The gate

`release/publish.sh` greps the final export tree before anything is written: the private
pattern list (one extended regex per line, kept outside the repository) plus the built-in
list in publish.sh itself, which is never exported. One hit and nothing is written. CI greps
every push with the same private list.

## On a hit

Reword it in the private repository (keep the fact, drop the name), run the suites that pin
the file's strings, commit, and export again. Never edit a public clone by hand.
