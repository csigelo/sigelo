# npm Trusted Publishing: one-time setup

From v0.1.2 on, `.github/workflows/npm-publish.yml` publishes the five packages from a pushed tag
with GitHub OIDC: no npm token exists anywhere, and each version carries a provenance attestation.
npm must be told, once per package, to trust that workflow.

Source: https://docs.npmjs.com/trusted-publishers (last updated 2026-09-30, read 2026-10-06).

## On npmjs.com, logged in as csigelo

For each package: Packages → *package* → Settings → **Trusted publishing** → GitHub Actions.

| Package | Organization or user | Repository | Workflow filename | Environment name | Allowed actions |
|---|---|---|---|---|---|
| sigelo | `csigelo` | `sigelo` | `npm-publish.yml` | (empty) | `npm publish` |
| sigelo-agent | `csigelo` | `sigelo` | `npm-publish.yml` | (empty) | `npm publish` |
| sigelo-spend | `csigelo` | `sigelo` | `npm-publish.yml` | (empty) | `npm publish` |
| sigelo-mcp | `csigelo` | `sigelo` | `npm-publish.yml` | (empty) | `npm publish` |
| sigelo-recovery-kit | `csigelo` | `sigelo` | `npm-publish.yml` | (empty) | `npm publish` |

Fields are case-sensitive; the workflow filename is the bare name with its `.yml`. "Allowed
actions" must include direct `npm publish` (`npm stage publish` is always allowed; the workflow
does not use it). A connection cannot be edited afterwards, only deleted and re-added.

Then, per package, Settings → **Publishing access** → "Require two-factor authentication and
disallow tokens". npm documents this for use alongside trusted publishers: the workflow still
publishes, any token (a leaked one included) cannot. Recommended for all five.

## Afterwards

Once the first tag has published through the workflow, send the Owner:

> revoke the token sigelo-publish

(npmjs.com → Access Tokens. Deadline: early November 2026.) The manual path in
release/RELEASE.md then needs a fresh short-lived token, or the "disallow tokens" setting lifted.
