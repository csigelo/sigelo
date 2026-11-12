**Pre-release.** Wire `sigelo/0` is not frozen; no third-party security review yet (VERSIONING.md).

Built from commit `@COMMIT@` by two CI runners and the maintainer's host; all three agree on `SHA256SUMS`.

Install:

```sh
npx -y sigelo-mcp@@V@
go install github.com/csigelo/sigelo/go/cmd/sigelo-verify@@TAG@
```

Check this release: `sh release/verify-release.sh @TAG@` in a clone. Provenance: `gh attestation verify <file> -R csigelo/sigelo`. Checksums: `cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json` (release/RELEASE-v2.md §5). SBOM: `sigelo-@V@.cdx.json`.

The Android APK and `release.json` are added after the offline signing.

```
@SUMS@
```

Changes: https://github.com/csigelo/sigelo/blob/@TAG@/CHANGELOG.md
