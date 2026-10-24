#!/usr/bin/env bash
# Install/load/remove validation of a built layout package against the
# vendor's own PHP in a container (cPanel EA4 and Plesk publish their PHP
# repositories publicly; stock EL uses the distro module stream).
#
#   packaging/validate-layout.sh <layout> <image> <minor> [<other-minor>]
#     layout  stock-rhel | cpanel-rpm | cpanel-deb | plesk-rpm | plesk-deb
#     image   e.g. almalinux:8, almalinux:9, amazonlinux:2023, ubuntu:22.04, debian:bookworm
#
# Expects the package from packaging/build-layouts.sh under packaging/out/layouts/.
# With <other-minor> (its package must be built too) it first proves the
# wrong-ABI guard: that minor's package must be refused. x86_64 only.
# CloudLinux alt-php is not covered: its binaries need a CloudLinux licence.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
L="$REPO_ROOT/packaging/out/layouts"
LAYOUT="${1:?usage: validate-layout.sh <layout> <image> <minor> [other-minor]}"
IMG="${2:?image}"; MINOR="${3:?minor}"; OTHER="${4:-}"
pkgfile() { # <minor> -> path under $L
  local xy="${1//./}"
  case "$LAYOUT" in
    stock-rhel) ls "$L"/el/php"$1"/yum/php-howdah-*.php"$xy".x86_64.rpm ;;
    cpanel-rpm) ls "$L"/cpanel/yum/ea-php"$xy"-php-howdah-*.x86_64.rpm ;;
    cpanel-deb) ls "$L"/cpanel/apt/ea-php"$xy"-php-howdah_*_amd64.deb ;;
    plesk-rpm)  ls "$L"/plesk/yum/plesk-php"$xy"-howdah-*.x86_64.rpm ;;
    plesk-deb)  ls "$L"/plesk/apt/plesk-php"$xy"-howdah_*_amd64.deb ;;
    *) echo "unknown layout $LAYOUT" >&2; exit 2 ;;
  esac | sort -V | tail -1
}
P="$(pkgfile "$MINOR")"; [ -n "$P" ] || { echo "FATAL: no $LAYOUT package for $MINOR in $L" >&2; exit 1; }
args=("$LAYOUT" "$MINOR" "/l/${P#$L/}")
if [ -n "$OTHER" ]; then W="$(pkgfile "$OTHER")"; args+=("/l/${W#$L/}"); fi
exec docker run --rm --platform linux/amd64 \
  -v "$REPO_ROOT/packaging/validate-layout-in-container.sh":/v.sh:ro \
  -v "$REPO_ROOT/tools/howdah-check":/howdah-check:ro \
  -v "$L":/l:ro \
  "$IMG" sh /v.sh "${args[@]}"
