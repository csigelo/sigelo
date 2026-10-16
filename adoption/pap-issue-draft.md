<!-- SPDX-License-Identifier: MIT -->
**DRAFT, not posted; the Owner decides.** One post to personal-agent-protocol/personal-agent-protocol,
"Spec feedback" template (Page: Specification, Section: 4.1, Kind: Gap), then wait for humans. Read
against `content/spec.mdx` at `869ce57`. Link only once `integrations/pap/` is public.

---

**Title:** 4.1: identity methods for Personal Agents without a domain

4.1 makes the `client_id` an HTTPS URL, and the Company fetches the client metadata document and
`jwks_uri` from it. That fits a Personal Agent run by a company. It leaves out one a person runs
on their own phone or laptop: no domain to publish `agent.json` under, so no `client_id`.

We tried an alternative identity method against the draft. The `client_id` is a self-certifying
identifier (a hash of the agent's first public key document). The `client_assertion` carries the
agent's key history and a signature over the Company's `auth.issuer` and a nonce the Company issued.
The Company checks all of it without fetching anything. The key can be rotated under the same
`client_id`, and taken back with an offline recovery key after theft. A third party's signed
statement can name who operates the agent. DPoP, Sessions, scopes and tokens are unchanged.
Adapter and tests: https://github.com/csigelo/sigelo/tree/main/integrations/pap

Two things it does not fix: Direct Sign-In needs `redirect_uris` on the `client_id`'s domain, and a
per-person identifier used at every Company works against the per-Company User IDs of 4.2.

Our question: could 1.0 allow identity methods beyond an HTTPS `client_id` and a key file, for
example through `client_assertion_type`, so a Company can opt in to others?
