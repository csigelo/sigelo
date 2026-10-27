# The Android signing key

The APK of `apps/android` is signed by its own key: Android takes RSA, ECDSA or DSA, not Ed25519,
so the release identity cannot sign it. The release identity signs the key's certificate instead:
each `release.json` that ships an APK names `{file, sha256, cert_sha256, version}`. Every sigelo
APK uses this one key for good (Android updates only under the same key).

## Once: the key (offline)

Offline, with a JDK and Android SDK build-tools (`keytool`, `apksigner`):

```sh
keytool -genkeypair -keystore apk-release.p12 -storetype PKCS12 -alias sigelo \
  -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 10000 -dname 'CN=sigelo'
keytool -list -v -keystore apk-release.p12 -alias sigelo | grep 'SHA256:'   # the cert_sha256
keytool -exportcert -rfc -keystore apk-release.p12 -alias sigelo -file apk-release.pem
```

- A long random store password, kept apart from the store.
- `apk-release.p12` is backed up with the release identity (RELEASE.md, "Signing"), on other
  media; never on GitHub, a server or an agent's host.
- `apk-release.pem` and the `SHA256:` line (the certificate's SHA-256, colons allowed) are public.
  The fingerprint goes into each release below.

Lost key: no update; a new key means a reinstall, losing the app's data. Stolen key: its APKs still
fail `apk-check.sh` (no `release.json` names them); announce it (SECURITY.md) and make a new key.

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
12 hex digits):

```sh
zipalign -c -P 16 4 sigelo-<commit>-release-unsigned.apk
apksigner sign --ks apk-release.p12 --ks-key-alias sigelo --v1-signing-enabled false \
  --alignment-preserved --out sigelo-<v>.apk sigelo-<commit>-release-unsigned.apk
apksigner verify --print-certs sigelo-<v>.apk   # one signer; its SHA-256 digest is the cert_sha256
python3 -c "import sys,struct;u=open(sys.argv[1],'rb').read();s=open(sys.argv[2],'rb').read();e=u.rfind(b'PK\5\6');cd=struct.unpack('<I',u[e+16:e+20])[0];sys.exit(0 if s[:cd]==u[:cd] else 'APK differs beyond signature')" \
  sigelo-<commit>-release-unsigned.apk sigelo-<v>.apk   # silent: only the signature added
```

`--alignment-preserved` keeps CI's entry offsets: F-Droid copies our signature onto its own build of
the tag (`Binaries:`, apps/android/FDROID.md), and re-padded entries (v0.1.10) break it. The last
line checks that the signed APK equals the unsigned one up to its central directory.

Carry `sigelo-<v>.apk` back and sign the release with it:

```sh
cp sigelo-<v>.apk $S/a/
sh release/sign-release.sh v<v> $S/a --apk $S/a/sigelo-<v>.apk <cert_sha256>
sh release/verify-release.sh v<v> $S/a
```

`sign-release.sh` checks (`apksigner`) that the APK carries exactly that certificate, keeps the APK
out of SHA256SUMS (npm-publish.yml compares SHA256SUMS with a rebuild that has none) and adds
`apk: {file, sha256, cert_sha256, version}` to the release's signed claims. Attached to the
GitHub release; `mirror-release.sh` mirrors it.

## Check an APK

`sh release/apk-check.sh sigelo-<v>.apk release.json` (in a clone): `release.json` signed by the
pinned release identity, the file's SHA-256 as signed, and `apksigner`'s one certificate as signed.
`verify-release.sh` does the same for a whole release.
