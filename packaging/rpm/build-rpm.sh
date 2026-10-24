#!/usr/bin/env bash
# Build the Remi-layout RPM for one PHP minor + one arch, wrapping the EXISTING
# glibc-2.17 howdah.so (packaging/build-release.sh output; nothing is rebuilt).
#
#   packaging/rpm/build-rpm.sh <minor> <x86_64|aarch64> [path/to/release-tarball.tar.gz]
#
# Input: howdah-<ver>-php<minor>-<api>-linux-<arch>.tar.gz (howdah.so + howdah.ini).
# If no tarball is given it is taken from packaging/out/; if absent there it is
# built via HOWDAH_ARCH=<arch> packaging/build-release.sh <minor>.
# HOWDAH_NO_BUILD=1 fails instead of building.
# Env: HOWDAH_VERSION (default: workspace version), HOWDAH_RPM_REL (default 1)
#
# Output: packaging/out/php<XY>-howdah-<version>-<rel>.<arch>.rpm  (XY = minor
# without the dot, e.g. php74-howdah-0.1.0-1.x86_64.rpm). Unsigned (repo
# signing is a separate CI step).
# rpmbuild runs in an EL7 container (packaging/rpm/builder.Dockerfile). The
# payload is a prebuilt binary, so aarch64 rpms are built with --target on the
# x86_64 builder (no QEMU needed).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO_ROOT/packaging/rpm"
OUT="$REPO_ROOT/packaging/out"
# shellcheck source=packaging/reproducible.sh
. "$REPO_ROOT/packaging/reproducible.sh"

MINOR="${1:?usage: build-rpm.sh <minor> <x86_64|aarch64> [tarball]}"
ARCH="${2:?usage: build-rpm.sh <minor> <x86_64|aarch64> [tarball]}"
TARBALL="${3:-}"
case "$MINOR" in 5.[456]|7.[0-4]|8.[0-5]) ;; *) echo "FATAL: unsupported PHP minor '$MINOR'" >&2; exit 2 ;; esac
case "$ARCH" in x86_64|aarch64) ;; *) echo "FATAL: arch must be x86_64|aarch64 (got '$ARCH')" >&2; exit 2 ;; esac

VERSION="${HOWDAH_VERSION:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')}"
REL="${HOWDAH_RPM_REL:-1}"
XY="${MINOR//./}"
SCL="php$XY"

if [ -z "$TARBALL" ]; then
  TARBALL="$(ls "$OUT"/howdah-"$VERSION"-php"$MINOR"-*-linux-"$ARCH".tar.gz 2>/dev/null | head -1 || true)"
  if [ -z "$TARBALL" ]; then
    [ "${HOWDAH_NO_BUILD:-0}" = 1 ] && { echo "FATAL: no release tarball for php$MINOR $ARCH in $OUT" >&2; exit 1; }
    echo "== no tarball yet; building via packaging/build-release.sh ($ARCH)"
    HOWDAH_ARCH="$ARCH" HOWDAH_VERSION="$VERSION" KEEP_IMAGE="${KEEP_IMAGE:-1}" \
      "$REPO_ROOT/packaging/build-release.sh" "$MINOR"
    TARBALL="$(ls "$OUT"/howdah-"$VERSION"-php"$MINOR"-*-linux-"$ARCH".tar.gz | head -1)"
  fi
fi
[ -f "$TARBALL" ] || { echo "FATAL: tarball not found: $TARBALL" >&2; exit 1; }
API="$(basename "$TARBALL" | sed -nE "s/.*-php${MINOR//./\\.}-([0-9]{8})-linux-${ARCH}\.tar\.gz$/\1/p")"
[ -n "$API" ] || { echo "FATAL: cannot read API from tarball name '$(basename "$TARBALL")'" >&2; exit 1; }
echo "== php$MINOR $ARCH: api $API, tarball $(basename "$TARBALL")"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/x" "$WORK/top"
tar -C "$WORK/x" -xzf "$TARBALL"
SRC="$(ls -d "$WORK"/x/howdah-*-php"$MINOR" | head -1)"
[ -f "$SRC/howdah.so" ] && [ -f "$SRC/howdah.ini" ] || { echo "FATAL: tarball lacks howdah.so/howdah.ini" >&2; exit 1; }
case "$ARCH" in x86_64) want='x86-64' ;; aarch64) want='ARM aarch64' ;; esac
file "$SRC/howdah.so" | grep -q "$want" || { echo "FATAL: howdah.so is not $want: $(file "$SRC/howdah.so")" >&2; exit 1; }

mkdir "$WORK/top/SOURCES"
cp "$SRC/howdah.so" "$SRC/howdah.ini" "$WORK/top/SOURCES/"
sed -e "s/@XY@/$XY/g" -e "s/@SCL@/$SCL/g" -e "s/@MINOR@/$MINOR/g" -e "s/@API@/$API/g" \
    -e "s/@VERSION@/$VERSION/g" -e "s/@REL@/$REL/g" "$HERE/howdah.spec.in" > "$WORK/top/howdah.spec"

IMG=howdah-rpmbuild-el7
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -q -t "$IMG" -f "$HERE/builder.Dockerfile" "$HERE"
mkdir -p "$OUT"
# Reproducibility (docs/verify.md): a fixed build host name, and file mtimes
# set to SOURCE_DATE_EPOCH by the spec's %install. The _buildhost and
# SOURCE_DATE_EPOCH macros need rpm >= 4.14; EL7's rpm 4.11 ignores them and
# still stamps the header with the build time, so two builds share the same
# payload (rpm2cpio) but not the same header. Published rpms are rpmsign'ed,
# which adds a timestamped signature in any case.
SOURCE_DATE_EPOCH="$(howdah_source_date_epoch "$REPO_ROOT")"
docker run --rm --hostname reproducible -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  -e HU=$(id -u) -e HG=$(id -g) -v "$WORK/top":/top -v "$OUT":/out "$IMG" bash -ec "
  rpmbuild -bb --target $ARCH --define '_topdir /top' --define '_rpmdir /top/RPMS' --define '_sourcedir /top/SOURCES' \
    --define '_buildhost reproducible' --define 'use_source_date_epoch_as_buildtime 1' \
    --define 'clamp_mtime_to_source_date_epoch 1' /top/howdah.spec >/top/log 2>&1 || { cat /top/log; exit 1; }
  tail -3 /top/log
  cp /top/RPMS/$ARCH/*.rpm /out/; chown -R \$HU:\$HG /top; chown \$HU:\$HG /out/*.rpm
  cd /top/RPMS/$ARCH
  rpm -qpi *.rpm; rpm -qpR *.rpm; rpm -qplv *.rpm"
echo "== built $OUT/$SCL-howdah-$VERSION-$REL.$ARCH.rpm"
