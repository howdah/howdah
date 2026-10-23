#!/usr/bin/env bash
# Build the Debian/Ubuntu package for one PHP minor + one arch, wrapping the
# EXISTING glibc-2.17 howdah.so (packaging/build-release.sh output; nothing is
# rebuilt differently).
#
#   packaging/deb/build-deb.sh <minor> <arch> [path/to/release-tarball.tar.gz]
#     minor  PHP minor, e.g. 7.4 (5.4 .. 8.5)
#     arch   amd64 | arm64
#
# Input: the per-minor release tarball
#   howdah-<ver>-php<minor>-<api>-linux-<x86_64|aarch64>.tar.gz  (howdah.so + howdah.ini).
# If no tarball is given it is taken from packaging/out/; if absent there, it is
# built via  HOWDAH_ARCH=<x86_64|aarch64> KEEP_IMAGE=1 packaging/build-release.sh <minor>
# (arm64 uses the aarch64 release path: QEMU locally, native on an arm64 runner).
# Set HOWDAH_NO_BUILD=1 to fail instead of building.
#
# Env: HOWDAH_VERSION (default: workspace version), HOWDAH_DEB_REV (default 1)
#
# Output: packaging/out/php<minor>-howdah_<version>-<rev>_<arch>.deb
#   package name  php<minor>-howdah        (Sury/Debian style, e.g. php7.4-howdah)
#   file name     php<minor>-howdah_<version>-1_<arch>.deb
# Unsigned: repo signing is a separate (CI) step.
#
# Layout (Sury/ondrej, which Debian/Ubuntu stock PHP also follows):
#   /usr/lib/php/<api>/howdah.so                    (the API's extension_dir)
#   /etc/php/<minor>/mods-available/howdah.ini      (conffile; "; priority=20")
#   /usr/share/doc/php<minor>-howdah/{copyright,README.Debian}
# Enabled by postinst via `phpenmod -v <minor> howdah`, disabled in prerm via
# `phpdismod`. Depends: phpapi-<api> -- the ABI virtual package that
# php<minor>-common Provides -- so apt/dpkg refuse to install it against any
# other PHP ABI.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO_ROOT/packaging/deb"
OUT="$REPO_ROOT/packaging/out"

MINOR="${1:?usage: build-deb.sh <minor> <amd64|arm64> [tarball]}"
DEBARCH="${2:?usage: build-deb.sh <minor> <amd64|arm64> [tarball]}"
TARBALL="${3:-}"
case "$MINOR" in 5.[456]|7.[0-4]|8.[0-5]) ;; *) echo "FATAL: unsupported PHP minor '$MINOR'" >&2; exit 2 ;; esac
case "$DEBARCH" in
  amd64) RELARCH=x86_64 ;;
  arm64) RELARCH=aarch64 ;;
  *) echo "FATAL: arch must be amd64|arm64 (got '$DEBARCH')" >&2; exit 2 ;;
esac

VERSION="${HOWDAH_VERSION:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')}"
REV="${HOWDAH_DEB_REV:-1}"

# ---- 1. locate (or build) the release tarball -------------------------------
if [ -z "$TARBALL" ]; then
  TARBALL="$(ls "$OUT"/howdah-"$VERSION"-php"$MINOR"-*-linux-"$RELARCH".tar.gz 2>/dev/null | head -1 || true)"
  if [ -z "$TARBALL" ]; then
    [ "${HOWDAH_NO_BUILD:-0}" = 1 ] && { echo "FATAL: no release tarball for php$MINOR $RELARCH in $OUT" >&2; exit 1; }
    echo "== no tarball yet; building via packaging/build-release.sh ($RELARCH)"
    HOWDAH_ARCH="$RELARCH" HOWDAH_VERSION="$VERSION" KEEP_IMAGE="${KEEP_IMAGE:-1}" \
      "$REPO_ROOT/packaging/build-release.sh" "$MINOR"
    TARBALL="$(ls "$OUT"/howdah-"$VERSION"-php"$MINOR"-*-linux-"$RELARCH".tar.gz | head -1)"
  fi
fi
[ -f "$TARBALL" ] || { echo "FATAL: tarball not found: $TARBALL" >&2; exit 1; }
# API number is encoded in the name: ...-php<minor>-<api>-linux-<arch>.tar.gz
API="$(basename "$TARBALL" | sed -nE "s/.*-php${MINOR//./\\.}-([0-9]{8})-linux-${RELARCH}\.tar\.gz$/\1/p")"
[ -n "$API" ] || { echo "FATAL: cannot read API from tarball name '$(basename "$TARBALL")' (want ...-php$MINOR-<api>-linux-$RELARCH.tar.gz)" >&2; exit 1; }
echo "== php$MINOR $DEBARCH: api $API, tarball $(basename "$TARBALL")"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/x"
tar -C "$WORK/x" -xzf "$TARBALL"
SRC="$(ls -d "$WORK"/x/howdah-*-php"$MINOR" | head -1)"
[ -f "$SRC/howdah.so" ] && [ -f "$SRC/howdah.ini" ] || { echo "FATAL: tarball lacks howdah.so/howdah.ini" >&2; exit 1; }

# Sanity: the .so must be the right ELF arch.
case "$DEBARCH" in amd64) want='x86-64' ;; arm64) want='ARM aarch64' ;; esac
file "$SRC/howdah.so" | grep -q "$want" || { echo "FATAL: howdah.so is not $want: $(file "$SRC/howdah.so")" >&2; exit 1; }

# ---- 2. staging tree --------------------------------------------------------
PKG="php$MINOR-howdah"
ROOT="$WORK/stage"
install -d -m 0755 "$ROOT/DEBIAN" "$ROOT/usr/lib/php/$API" "$ROOT/etc/php/$MINOR/mods-available" "$ROOT/usr/share/doc/$PKG"
install -m 0644 "$SRC/howdah.so" "$ROOT/usr/lib/php/$API/howdah.so"
# phpenmod reads "; priority=NN" from the ini to name the conf.d symlink NN-howdah.ini.
# 20 = the usual extension slot.
{ printf '; configuration for php howdah module\n; priority=20\n'; cat "$SRC/howdah.ini"; } \
  > "$ROOT/etc/php/$MINOR/mods-available/howdah.ini"
chmod 0644 "$ROOT/etc/php/$MINOR/mods-available/howdah.ini"
echo "/etc/php/$MINOR/mods-available/howdah.ini" > "$ROOT/DEBIAN/conffiles"

cat > "$ROOT/usr/share/doc/$PKG/copyright" <<EOF2
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Howdah
Source: https://github.com/howdah/howdah

Files: *
Copyright: 2026 Howdah contributors
License: MIT or Apache-2.0
 Dual-licensed under the MIT License or the Apache License 2.0, at your option.
 See LICENSE-MIT and LICENSE-APACHE in the source repository; the Apache-2.0
 text is also at /usr/share/common-licenses/Apache-2.0 on Debian systems.
EOF2
cat > "$ROOT/usr/share/doc/$PKG/README.Debian" <<EOF2
Howdah for PHP $MINOR (Zend module API $API)

The module is enabled on install (phpenmod -v $MINOR howdah) in DETECT mode:
it logs what it would block. Edit /etc/php/$MINOR/mods-available/howdah.ini
and set howdah.mode = block once you have reviewed the logs.
Disable with:  phpdismod -v $MINOR howdah   (then restart php-fpm/apache)
EOF2
chmod 0644 "$ROOT/usr/share/doc/$PKG"/*

# ---- 3. control + maintainer scripts ----------------------------------------
SIZE="$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)"
sed -e "s/@PKG@/$PKG/g" -e "s/@VERSION@/$VERSION-$REV/g" -e "s/@ARCH@/$DEBARCH/g" \
    -e "s/@MINOR@/$MINOR/g" -e "s/@API@/$API/g" -e "s/@SIZE@/$SIZE/g" \
    "$HERE/control.in" > "$ROOT/DEBIAN/control"
for s in postinst prerm postrm; do
  sed -e "s/@MINOR@/$MINOR/g" "$HERE/$s.in" > "$ROOT/DEBIAN/$s"
  chmod 0755 "$ROOT/DEBIAN/$s"
done

# ---- 4. build ---------------------------------------------------------------
mkdir -p "$OUT"
DEB="$OUT/${PKG}_${VERSION}-${REV}_${DEBARCH}.deb"
# --root-owner-group: root:root regardless of builder uid. gzip members work on
# every dpkg back to xenial and older.
dpkg-deb --root-owner-group -Zgzip --build "$ROOT" "$DEB" >/dev/null
echo "== built $DEB"
dpkg-deb -I "$DEB" control
dpkg-deb -c "$DEB"
