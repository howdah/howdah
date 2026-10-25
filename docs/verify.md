# Verifying a Howdah release

Four checks, from quickest to strongest. Each answers a different question, so
use as many as your policy asks for:

| Check | Answers | Needs |
| ----- | ------- | ----- |
| [1. GPG signature](#1-gpg-signature-and-checksums) | Did the project's release key sign the checksums of these files? | `gpg`, `sha256sum` |
| [2. Build provenance](#2-build-provenance-attestations) | Was this exact file built by Howdah's release workflow on GitHub, from which tag and commit? | `gh` (online), or `cosign` with the bundle (no GitHub account) |
| [3. SBOM](#3-sbom) | Which Rust crates, at which versions, went into `howdah.so`? | `gh` or `cosign`, `jq` |
| [4. Reproducible rebuild](#4-reproducible-rebuild) | Does the source at that tag, built by you, give the same bytes? | `docker`, `git`, `bash`, `gpg` |

Checks 2 and 3 exist for releases after 1.4.0 (the first release built by the
workflow that adds them). Check 4 gives byte-identical tarballs from that
release on; for 1.4.0 it gives the identical `howdah.so` but a different
tarball wrapper (see [older tags](#older-tags)). The packages on
`pkg.howdah.org` are covered in [section 5](#5-apt-and-yum-packages).

None of these checks says the code is free of bugs. They tie the file you
downloaded to the public source and to the project's signing key and release
workflow. Howdah has had no third-party security audit yet;
[security-audit-brief.md](security-audit-brief.md) is the scope we are asking
one to cover.

## 1. GPG signature and checksums

Every release has `SHA256SUMS` (the sha256 of every tarball and of the
standalone `howdah-check`), a detached signature `SHA256SUMS.asc`, and the
public key `howdah-release-signing.asc`. The same key is published at
`https://howdah.org/key.asc` and signs the apt and yum repositories.

Check the key's primary fingerprint first. It must be
`1152 1035 C600 F638 31F8 2551 2087 B872 0997 807B`:

```sh
curl -fsSL https://howdah.org/key.asc | gpg --show-keys --with-fingerprint
```

Then verify (set `V` and `T` to the release and tarball you want):

```sh
V=1.6.1
B=https://github.com/howdah/howdah/releases/download/v$V
T=howdah-$V-php7.4-20190902-linux-x86_64.tar.gz
curl -fLO $B/$T -O $B/SHA256SUMS -O $B/SHA256SUMS.asc -O $B/howdah-release-signing.asc
gpg --import howdah-release-signing.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

`gpg --verify` must print `Good signature` and
`Primary key fingerprint: 1152 1035 C600 F638 31F8 2551 2087 B872 0997 807B`.
The signature is made by the signing subkey
`9A10 4FB0 A073 065B 2C26 31FC 1E8D 725D 31BD 5DC9`; the offline primary key
never touches CI. A `WARNING: This key is not certified with a trusted
signature` line is normal unless you have certified the key yourself.

## 2. Build provenance attestations

The release workflow (`.github/workflows/release.yml`) attests every tarball,
`howdah-check` and `SHA256SUMS` after signing them. An attestation is a
[SLSA v1 provenance](https://slsa.dev/spec/v1.0/provenance) statement that
names the file's sha256, the repository, the workflow file, the tag and the
commit, signed with a short-lived certificate that GitHub's OIDC identity for
that workflow run obtained from Sigstore, and recorded in Sigstore's public
transparency log. Nobody holds a long-lived key for it, so it cannot be made
outside that workflow run.

### With the GitHub CLI

```sh
gh attestation verify howdah-1.6.1-php7.4-20190902-linux-x86_64.tar.gz -R howdah/howdah
```

Stricter: require the release workflow, the tag, and a GitHub-hosted runner:

```sh
gh attestation verify howdah-1.6.1-php7.4-20190902-linux-x86_64.tar.gz -R howdah/howdah \
  --signer-workflow howdah/howdah/.github/workflows/release.yml \
  --source-ref refs/tags/v1.6.1 \
  --deny-self-hosted-runners
```

To see what it vouches for:

```sh
gh attestation verify "$T" -R howdah/howdah --format json \
  --jq '.[0].verificationResult.signature.certificate | {buildSignerURI, sourceRepositoryRef, sourceRepositoryDigest, runnerEnvironment}'
```

`gh` needs to be logged in (`gh auth login`), because it fetches the
attestation from the GitHub API.

### Offline, with the bundle

Each release also ships the Sigstore bundles as assets:
`howdah-<version>.provenance.sigstore.json` (provenance for every asset) and
`howdah-<version>-<x86_64|aarch64|x86_64-musl>.sbom.sigstore.json` (the SBOM
for that flavour's tarballs). They are self-authenticating, so they are not
listed in `SHA256SUMS`. With [cosign](https://github.com/sigstore/cosign)
and no GitHub account (tested with cosign 3.1.4; cosign 2.x also needs
`--new-bundle-format`):

```sh
curl -fLO $B/howdah-$V.provenance.sigstore.json
cosign verify-blob-attestation "$T" \
  --bundle howdah-$V.provenance.sigstore.json \
  --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/howdah/howdah/.github/workflows/release.yml@refs/tags/v$V"
```

It prints `Verified OK`; a modified file fails with `provided artifact digests
do not match digests in statement`. cosign fetches Sigstore's trusted root on
first use and caches it. The GitHub CLI can do the same from the bundle:

```sh
gh attestation trusted-root > trusted_root.jsonl     # once, while online
gh attestation verify "$T" -R howdah/howdah \
  --bundle howdah-$V.provenance.sigstore.json --custom-trusted-root trusted_root.jsonl
```

The attestations can also be fetched without an account from
`https://api.github.com/repos/howdah/howdah/attestations/sha256:<digest>`.

## 3. SBOM

A CycloneDX 1.5 SBOM of `howdah.so` (`packaging/sbom.sh`) is attested against
each flavour's tarballs. It lists the crates compiled into the extension
(scope `required`) and the build-time crates that generate part of it, such as
bindgen and cc (scope `excluded`), with versions, licences and crates.io
package URLs, from `Cargo.lock` at the tag. It does not list the C toolchain,
libclang or the PHP headers used at build time; the release image pins those
(section 4).

```sh
gh attestation verify "$T" -R howdah/howdah \
  --predicate-type https://cyclonedx.org/bom --format json \
  --jq '.[0].verificationResult.statement.predicate.components[] | "\(.name) \(.version)"'
```

Offline, the bundle carries the SBOM:

```sh
cosign verify-blob-attestation "$T" --bundle howdah-$V-x86_64.sbom.sigstore.json --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/howdah/howdah/.github/workflows/release.yml@refs/tags/v$V"
jq -r '.dsseEnvelope.payload | @base64d | fromjson | .predicate.components[] | "\(.name) \(.version)"' \
  howdah-$V-x86_64.sbom.sigstore.json
```

The SBOM is itself reproducible: `packaging/sbom.sh out.cdx.json` at the tag
writes the same file (its timestamp is the tag's commit date).

## 4. Reproducible rebuild

The release tarballs are reproducible: the same commit gives byte-identical
tarballs, wherever and whenever it is built. That makes the strongest check
possible without trusting GitHub or the project: rebuild the tarball yourself
and compare it with the signed checksum.

```sh
git clone https://github.com/howdah/howdah && cd howdah
packaging/verify-reproducible.sh v1.6.1 7.4                 # x86_64
packaging/verify-reproducible.sh v1.6.1 8.3 x86_64-musl     # or aarch64
```

The script downloads `SHA256SUMS` and its signature, checks the signature
belongs to the primary key above, clones the tag, runs that tag's own
`packaging/build-release.sh` for the minor in a freshly built release image,
and compares. It prints `MATCH` (exit 0) or `MISMATCH` (exit 1) and the sha256
of the `howdah.so` inside both tarballs; on a mismatch it keeps both files for
`diffoscope`. It needs Docker, git, curl, gpg and bash and a few GB of disk.
On an x86_64 machine the first run takes five to ten minutes, most of it
building the release image (`KEEP_IMAGE=1` reuses it next time); aarch64 on
an x86_64 host runs under QEMU and is much slower.

### What is pinned

- The source: the tag's commit; crate versions from `Cargo.lock`, built with
  `--locked` (crates.io checksums).
- The compiler: `packaging/rust-toolchain.toml` (Rust 1.99.1 at the time of
  writing), installed by every release image and enforced by `build-one.sh`.
- The build image: `centos:7` by digest, CentOS packages from the frozen
  7.9.2009 vault (gpg-checked), libclang and clang's resource headers by
  sha256, the PHP source tarball by sha256 for the minors built from source
  (8.2 to 8.5 on x86_64, every minor on aarch64 and musl).
- Paths: `--remap-path-prefix` maps `/src`, `$CARGO_HOME` and the target
  directory to fixed names, so `howdah.so` carries no builder paths.
- The tarball: written in the release image by its own tar and gzip, entries
  sorted, modes normalised, owner and group 0, every mtime set to
  `SOURCE_DATE_EPOCH` (the committer date of the tag's commit), `gzip -n`.

### Residual causes of a mismatch

- **PHP headers from Remi (x86_64, PHP 5.4 to 8.1).** These minors build
  against `php<XY>-php-devel` installed by name from Remi's EL7 repository
  when the build runs. The packages are gpg-checked but not pinned to a
  version or hash here. If Remi serves a different build of them, the
  generated bindings, and so `howdah.so`, can change. The build log
  (`php-config: ... (<version>)`) shows which version was used.
- **Alpine packages (musl).** The musl image installs gcc, clang 19 and
  musl-dev from Alpine 3.21 by name. A later 3.21 package update can change
  the output.
- **A different pinned toolchain.** Rebuilding an old tag with a newer
  `build-release.sh` is not a like-for-like rebuild; the script always uses
  the tag's own build scripts.

What was checked when this was introduced: two builds of the same commit,
each from a fresh clone with a release image built with `--no-cache`, under
different umasks and checkout paths, gave byte-identical PHP 7.4 and 8.3
x86_64 tarballs. The `.deb` built from one of them was identical across
umask 022, 002 and 077 and across tmpfs and ext4 staging directories. The
aarch64 and musl flavours use the same scripts but were not rebuilt twice.

### Older tags

Tags up to v1.4.0 predate this: their tarballs record the build time, the CI
user (uid 1001) and the builder's file modes, so the tarball differs. The
`howdah.so` inside can still match. Run against v1.4.0, PHP 7.4, on
24 October 2026, the script reported the tarball differs and the extension is
byte-identical:

```
== howdah.so: published 1d297adf382db487fa4da7caecaadad9843723ce259e3874b5d6eeaff2c4b79a
              rebuilt   1d297adf382db487fa4da7caecaadad9843723ce259e3874b5d6eeaff2c4b79a
MISMATCH: the rebuilt howdah-1.4.0-php7.4-20190902-linux-x86_64.tar.gz differs from the signed release asset.
```

`diffoscope` on the two tarballs shows only owner, mtime and mode differences
in the file list.

## 5. apt and yum packages

apt and yum check the repository signatures themselves (the same key; see
[install-repos.md](install-repos.md#key)). In addition, the publish workflow
(`.github/workflows/publish-repos.yml`) attests every package it builds, as
users download it: the `.deb` from the pool and the `.rpm` after it is signed.
Download one and check it:

```sh
apt-get download php7.4-howdah          # or: dnf download php74-howdah
gh attestation verify php7.4-howdah_1.6.1-1_amd64.deb -R howdah/howdah \
  --signer-workflow howdah/howdah/.github/workflows/publish-repos.yml
```

The provenance's source ref says which branch or tag the packages were built
from. When it is the release tag, the `howdah.so` inside the package is
byte-identical to the one in the signed tarball, which ties the package to
checks 1 to 4:

```sh
dpkg-deb --fsys-tarfile php7.4-howdah_1.6.1-1_amd64.deb | tar -xO ./usr/lib/php/20190902/howdah.so | sha256sum
rpm2cpio php74-howdah-1.6.1-1.x86_64.rpm | cpio -i --quiet --to-stdout ./opt/remi/php74/root/usr/lib64/php/modules/howdah.so | sha256sum
tar -xzOf "$T" --wildcards '*/howdah.so' | sha256sum
```

The `.deb` files are reproducible for a given dpkg version (normalised modes
and mtimes, `SOURCE_DATE_EPOCH`, an Installed-Size that does not depend on the
builder's filesystem). The `.rpm` files are not byte-reproducible: EL7's
rpm 4.11, which keeps them installable on CentOS 7, stamps the build time into
the header, and the published rpm carries an `rpmsign` signature with its own
timestamp. Their payload is reproducible (`rpm2cpio ... | sha256sum` matches
across builds), and so is the `howdah.so` inside.

Packages published before the first release after 1.4.0 have no attestation.
