// SPDX-License-Identifier: MIT
// site/src/official.mjs — the official names and contacts sigelo.io renders: SECURITY.md "Official
// channels" (written by hand, checked against this), index.json `official`, the / and /contact
// lines, and the held domains' 301s in site/deploy/nginx.conf. Data only, no imports: site/build.mjs
// renders it, site/test/run.mjs and site/deploy/check.mjs check against it, and a page that renders
// any of it takes this file's last commit as an input of its sitemap lastmod.

export const REPO = 'https://github.com/csigelo/sigelo';
export const CONTACT_EMAIL = 'contact@sigelo.io';
export const SECURITY_EMAIL = 'security@sigelo.io';
// SIMPLEX is the one source of the address (/contact, security.txt, index.json, JSON-LD). While it
// is an <angle-bracket> placeholder every generated surface omits it; site/test/run.mjs fails if it leaks.
export const SIMPLEX = 'https://smp10.simplex.im/a#18LjfJawmkVxvFtCHFo-yyzPo8Kr3gPLNts_ovwxmZM';

// The relay launch: true since the launch commit (2026-10-13), which set it together with SECURITY.md
// (the Domains line site/build.mjs securityDomainsLine gives, its reporting channel, the relay in
// Scope and Safe harbour) and site/deploy/nginx.conf (sigelo.net and sigelo.online to sigelo.ai, in
// both server blocks each). site/test/run.mjs fails while the three disagree, and prints the Domains
// line it wants; relay/site/build.mjs --launch refuses until they agree. Set back to false, sigelo.io
// says BEFORE_LAUNCH again: sigelo.ai parked, the held domains to sigelo.io, one repository, no link
// to sigelo.ai, no payment place. site/deploy/check.mjs fails a sigelo.io build that redirects or
// links to a sigelo.ai that does not answer as ours: after an upload, which deploy.sh runs; before
// one only with --preflight, which deploy.sh does not run yet, so run it by hand before a deploy.
export const RELAY_LIVE = true;

// Roles: 'content' serves a site; 'redirect' 301s to `to` (site/deploy/nginx.conf); 'parked' is
// ours and serves nothing of ours. A redirect is called one only while `live`, i.e. its DNS reaches
// that 301: check.mjs fails a live redirect that does not answer it. Until then the text says it
// will redirect once its DNS points to us. The issuer DID is not listed here: it is computed from
// world/genesis.json, and site/test/run.mjs checks that SECURITY.md names it.
//
// DOMAINS, HOSTS, REPOSITORIES: the table of design/relay-plan.md §1, what sigelo.ai says
// (relay/site/build.mjs keeps a copy; relay/site/test.mjs compares the two) and what sigelo.io says
// once RELAY_LIVE. One row differs from §1 and waits for the Owner's answer: §1 has sigelo.dev
// parked, the site brief a redirect to sigelo.io.
export const DOMAINS = [
  { name: 'sigelo.io', role: 'content', what: 'protocol' },
  { name: 'sigelo.ai', role: 'content', what: 'relay and front page' },
  { name: 'sigelo.net', role: 'redirect', to: 'sigelo.ai', live: true },
  { name: 'sigelo.online', role: 'redirect', to: 'sigelo.ai', live: false },
  { name: 'sigelo.dev', role: 'redirect', to: 'sigelo.io', live: false },
  { name: 'sigelo.org', role: 'parked' },
];
// Hosts under those domains that serve something of their own.
export const HOSTS = [{ name: 'relay.sigelo.ai', what: 'relay broker' }];
export const REPOSITORIES = [REPO, 'https://github.com/csigelo/sigelo-relay'];
// Where the relay's payment details are published: its pay page (Monero only), and that page's one
// file on the relay repository's default branch. An exact file, not the repository: anyone can put
// text under its URL prefix (an issue, a pull request, a fork's commit viewed through the parent).
export const PAYMENT_PLACES = ['https://sigelo.ai/pay-monero.html', `${REPOSITORIES[1]}/blob/main/site/pay-monero.md`];

export const BEFORE_LAUNCH = {
  domains: [
    { name: 'sigelo.io', role: 'content', what: 'protocol' },
    { name: 'sigelo.ai', role: 'parked' },
    { name: 'sigelo.net', role: 'redirect', to: 'sigelo.io', live: true },
    { name: 'sigelo.online', role: 'redirect', to: 'sigelo.io', live: false },
    { name: 'sigelo.dev', role: 'redirect', to: 'sigelo.io', live: false },
    { name: 'sigelo.org', role: 'parked' },
  ],
  hosts: [], repositories: [REPO], payment_places: [],
};
// What sigelo.io says now.
export const OFFICIAL = RELAY_LIVE ? { domains: DOMAINS, hosts: HOSTS, repositories: REPOSITORIES, payment_places: PAYMENT_PLACES } : BEFORE_LAUNCH;
