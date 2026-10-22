# The Android signing key

The APK of `apps/android` is signed by its own key: Android takes RSA, ECDSA or DSA, not Ed25519,
so the release identity cannot sign it. The release identity signs the key's certificate instead:
each `release.json` that ships an APK names `{file, sha256, cert_sha256, version}`. Every APK of
sigelo is signed by the same key for good (Android installs an update only under the same key).

## Once: the key (offline)

On an offline computer with a JDK and the Android SDK build-tools (`keytool`, `apksigner`):

```sh
keytool -genkeypair -keystore apk-release.p12 -storetype PKCS12 -alias sigelo \
  -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 10000 -dname 'CN=sigelo'
keytool -list -v -keystore apk-release.p12 -alias sigelo | grep 'SHA256:'   # the cert_sha256
keytool -exportcert -rfc -keystore apk-release.p12 -alias sigelo -file apk-release.pem
```

- The store password is long and random, kept apart from the store.
- `apk-release.p12` is backed up with the release identity's backup (RELEASE.md, "Signing"), on
  other media than the computer; never on GitHub, a server or a host an agent runs on.
- `apk-release.pem` and the `SHA256:` line (the certificate's SHA-256, colons allowed) are public.
  The fingerprint goes into the release step below; it never changes.

Lost key: no update of the installed app is possible; a new key means a new install (users
uninstall first, losing what the app held). Stolen key: an attacker signs APKs that `apk-check.sh`
still refuses, because no `release.json` names them; announce it (SECURITY.md) and make a new key.

## Each release

CI builds the APK unsigned (`.github/workflows/android.yml`), from the tag:

```sh
gh workflow run android.yml -R csigelo/sigelo --ref v<v>
gh run list -R csigelo/sigelo -w android -b v<v> -L 1          # the run id
gh run view <id> -R csigelo/sigelo --log | grep -A3 'SHA256SUMS'
gh run download <id> -R csigelo/sigelo -n sigelo-android -D $S/apk
(cd $S/apk && sha256sum -c SHA256SUMS)                          # and equal to the log's lines
```

Carry `sigelo-<commit>-release-unsigned.apk` to the offline computer (`<commit>`: the tag's first
12 hex digits), then:

```sh
zipalign -c -P 16 4 sigelo-<commit>-release-unsigned.apk
apksigner sign --ks apk-release.p12 --ks-key-alias sigelo --v1-signing-enabled false \
  --out sigelo-<v>.apk sigelo-<commit>-release-unsigned.apk
apksigner verify --print-certs sigelo-<v>.apk   # one signer; its SHA-256 digest is the cert_sha256
```

Carry `sigelo-<v>.apk` back, into the release's artefact directory, then sign the release with it:

```sh
cp sigelo-<v>.apk $S/a/
sh release/sign-release.sh v<v> $S/a --apk $S/a/sigelo-<v>.apk <cert_sha256>
sh release/verify-release.sh v<v> $S/a
```

`sign-release.sh` checks with `apksigner` that the APK carries exactly that certificate, keeps the APK
out of SHA256SUMS (npm-publish.yml compares SHA256SUMS with a rebuild that has none) and adds
`apk: {file, sha256, cert_sha256, version}` to the release's signed claims. The APK is attached
to the GitHub release with the other files; `mirror-release.sh` mirrors it.

## Check an APK

`sh release/apk-check.sh sigelo-<v>.apk release.json` (in a clone): `release.json` signed by the
pinned release identity, the file's SHA-256 as signed, and `apksigner`'s one certificate as signed.
`verify-release.sh` does the same for a whole release.
