#!/usr/bin/env bash
# Independently rebuild one release tarball from a tag and compare it with the
# published, signed SHA256SUMS. Anyone can run this; it needs no project keys
# and no GitHub account.
#
#   packaging/verify-reproducible.sh <tag> <minor> [x86_64|aarch64|x86_64-musl]
#   e.g. packaging/verify-reproducible.sh v1.5.0 7.4
#
# Steps:
#   1. fetch SHA256SUMS, SHA256SUMS.asc and the tarball from the GitHub release
#   2. check the signature with a throwaway keyring: the signing key must
#      belong to the project primary key 1152 1035 C600 F638 31F8 2551 2087 B872 0997 807B
#      (set HOWDAH_VERIFY_NO_GPG=1 to skip, e.g. without gpg; not recommended)
#   3. clone the tag's source and run THAT tag's packaging/build-release.sh
#      for the minor, in a freshly built release image (docker)
#   4. compare the rebuilt tarball's sha256 with the signed SHA256SUMS line,
#      and the sha256 of the howdah.so inside both
#
# Exit status: 0 the rebuilt tarball is byte-identical to the published one;
# 1 it differs (both tarballs are kept; compare them with diffoscope);
# 2 usage or environment error. Tags up to v1.4.0 predate reproducible
# builds: their tarballs carry the build time and the CI user, so expect 1
# there and look at the howdah.so line instead.
#
# Env (all optional):
#   HOWDAH_VERIFY_REPO      git URL or path of the source (default: https://github.com/howdah/howdah)
#   HOWDAH_VERIFY_RELEASE   directory that already holds the release files,
#                           instead of downloading them (default: download)
#   HOWDAH_VERIFY_WORKDIR   where to work (default: a new temporary directory, kept)
#   HOWDAH_RELEASE_IMAGE    docker image tag for the build (default: howdah-verify-release[-aarch64|-musl])
#   KEEP_IMAGE=1            reuse that image if it exists instead of rebuilding it
set -euo pipefail

TAG="${1:-}"; MINOR="${2:-}"; FLAVOUR="${3:-x86_64}"
if [ -z "$TAG" ] || [ -z "$MINOR" ]; then
  sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 2
fi
# FLAVOUR is the tarball's suffix after "linux-": x86_64, aarch64 or x86_64-musl.
case "$FLAVOUR" in
  x86_64)      ARCH=x86_64;  LIBC=glibc; img_suffix="" ;;
  aarch64)     ARCH=aarch64; LIBC=glibc; img_suffix="-aarch64" ;;
  x86_64-musl) ARCH=x86_64;  LIBC=musl;  img_suffix="-musl" ;;
  *) echo "FATAL: the third argument must be x86_64, aarch64 or x86_64-musl" >&2; exit 2 ;;
esac
case "$TAG" in v[0-9]*) ;; *) echo "FATAL: tag must look like v1.5.0 (got '$TAG')" >&2; exit 2 ;; esac
for t in git docker curl sha256sum tar; do
  command -v "$t" >/dev/null 2>&1 || { echo "FATAL: needs $t" >&2; exit 2; }
done

PRIMARY_FPR=11521035C600F63831F825512087B8720997807B
REPO="${HOWDAH_VERIFY_REPO:-https://github.com/howdah/howdah}"
VERSION="${TAG#v}"
WORK="${HOWDAH_VERIFY_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/howdah-verify.XXXXXX")}"
mkdir -p "$WORK/release" "$WORK/rebuilt"
echo "== verifying $TAG, PHP $MINOR, linux-$FLAVOUR in $WORK"

# ---- 1. the published files ---------------------------------------------------
pat="howdah-$VERSION-php$MINOR-*-linux-$FLAVOUR.tar.gz"
if [ -n "${HOWDAH_VERIFY_RELEASE:-}" ]; then
  cp "$HOWDAH_VERIFY_RELEASE"/SHA256SUMS "$WORK/release/"
  cp "$HOWDAH_VERIFY_RELEASE"/SHA256SUMS.asc "$HOWDAH_VERIFY_RELEASE"/howdah-release-signing.asc "$WORK/release/" 2>/dev/null || true
else
  base="https://github.com/howdah/howdah/releases/download/$TAG"
  for f in SHA256SUMS SHA256SUMS.asc howdah-release-signing.asc; do
    curl -fsSL --retry 3 -o "$WORK/release/$f" "$base/$f" || { echo "FATAL: could not fetch $base/$f" >&2; exit 2; }
  done
fi
line="$(grep -E "  howdah-$VERSION-php${MINOR//./\\.}-[0-9]{8}-linux-$FLAVOUR\.tar\.gz$" "$WORK/release/SHA256SUMS" || true)"
[ -n "$line" ] || { echo "FATAL: SHA256SUMS of $TAG lists no $pat" >&2; exit 2; }
want="${line%% *}"; name="${line##* }"
if [ -n "${HOWDAH_VERIFY_RELEASE:-}" ]; then
  cp "$HOWDAH_VERIFY_RELEASE/$name" "$WORK/release/" 2>/dev/null || true
else
  curl -fsSL --retry 3 -o "$WORK/release/$name" "$base/$name" || echo "WARNING: could not fetch $name; comparing checksums only" >&2
fi

# ---- 2. the signature ---------------------------------------------------------
if [ "${HOWDAH_VERIFY_NO_GPG:-0}" = 1 ]; then
  echo "WARNING: HOWDAH_VERIFY_NO_GPG=1: SHA256SUMS is NOT signature-checked" >&2
else
  command -v gpg >/dev/null 2>&1 || { echo "FATAL: needs gpg to check SHA256SUMS.asc (or HOWDAH_VERIFY_NO_GPG=1)" >&2; exit 2; }
  key="$WORK/release/howdah-release-signing.asc"
  [ -s "$key" ] || { echo "FATAL: no howdah-release-signing.asc next to SHA256SUMS" >&2; exit 2; }
  gh="$WORK/gnupg"; mkdir -p "$gh"; chmod 700 "$gh"
  GNUPGHOME="$gh" gpg --batch --quiet --import "$key" 2>/dev/null
  status="$(GNUPGHOME="$gh" gpg --batch --status-fd 1 --verify "$WORK/release/SHA256SUMS.asc" "$WORK/release/SHA256SUMS" 2>/dev/null || true)"
  # VALIDSIG's last field is the fingerprint of the primary key that owns the signing subkey.
  got="$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" { print $NF }' | head -1)"
  if [ "$got" != "$PRIMARY_FPR" ]; then
    echo "FATAL: SHA256SUMS.asc is not a valid signature by the Howdah key $PRIMARY_FPR (got '${got:-none}')" >&2; exit 2
  fi
  echo "== SHA256SUMS signature OK (primary key $PRIMARY_FPR)"
fi
if [ -f "$WORK/release/$name" ]; then
  ( cd "$WORK/release" && printf '%s\n' "$line" | sha256sum -c - >/dev/null ) \
    || { echo "FATAL: the downloaded $name does not match SHA256SUMS" >&2; exit 2; }
fi
echo "== published: $want  $name"

# ---- 3. rebuild from the tag's own build scripts -------------------------------
rm -rf "$WORK/src"
git clone --quiet --depth 1 --branch "$TAG" "$REPO" "$WORK/src" 2>/dev/null \
  || { echo "FATAL: could not clone $TAG from $REPO" >&2; exit 2; }
echo "== source: $REPO at $TAG = $(git -C "$WORK/src" rev-parse HEAD)"
if [ ! -f "$WORK/src/packaging/reproducible.sh" ]; then
  echo "NOTE: $TAG predates reproducible builds (its tarballs record the build time and user)."
  echo "      Expect the tarball to differ; the howdah.so comparison below still applies."
fi
img="${HOWDAH_RELEASE_IMAGE:-howdah-verify-release$img_suffix}"
( cd "$WORK/src" && HOWDAH_VERSION="$VERSION" HOWDAH_ARCH="$ARCH" HOWDAH_LIBC="$LIBC" HOWDAH_RELEASE_IMAGE="$img" \
    KEEP_IMAGE="${KEEP_IMAGE:-0}" packaging/build-release.sh "$MINOR" ) > "$WORK/build.log" 2>&1 \
  || { tail -30 "$WORK/build.log" >&2; echo "FATAL: the rebuild failed (log: $WORK/build.log)" >&2; exit 2; }
cp "$WORK/src/packaging/out/$name" "$WORK/rebuilt/" 2>/dev/null \
  || { echo "FATAL: the rebuild did not produce $name (log: $WORK/build.log)" >&2; exit 2; }
got="$(sha256sum "$WORK/rebuilt/$name" | cut -d' ' -f1)"
echo "== rebuilt:   $got  $name"

# ---- 4. compare -----------------------------------------------------------------
so_sum() { # <tarball>: sha256 of the howdah.so inside it
  tar -xzOf "$1" --wildcards '*/howdah.so' | sha256sum | cut -d' ' -f1
}
if [ -f "$WORK/release/$name" ]; then
  echo "== howdah.so: published $(so_sum "$WORK/release/$name")"
  echo "              rebuilt   $(so_sum "$WORK/rebuilt/$name")"
fi
if [ "$got" = "$want" ]; then
  echo "MATCH: the rebuilt $name is byte-identical to the signed release asset."
  exit 0
fi
echo "MISMATCH: the rebuilt $name differs from the signed release asset."
echo "  published: $WORK/release/$name"
echo "  rebuilt:   $WORK/rebuilt/$name"
echo "  compare:   diffoscope $WORK/release/$name $WORK/rebuilt/$name"
exit 1
