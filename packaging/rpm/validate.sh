#!/usr/bin/env bash
# Install/load/guard/remove validation of a built rpm in a real EL container
# against Remi SCL PHP.
#
#   packaging/rpm/validate.sh <el7|el8|el9> <minor> <x86_64|aarch64> [<other-minor>]
#
# Expects packaging/out/php<XY>-howdah-<ver>-1.<arch>.rpm (build-rpm.sh); with
# <other-minor>, also proves the wrong-ABI guard using that minor's rpm.
# Images: el7=centos:7, el8=almalinux:8, el9=almalinux:9 (rockylinux works too).
# aarch64 runs under QEMU. Needs network (rpms.remirepo.net).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO_ROOT/packaging/out"
ELV="${1:?usage: validate.sh <el7|el8|el9> <minor> <arch> [other-minor]}"
MINOR="${2:?}"; ARCH="${3:?}"; OTHER="${4:-}"
case "$ELV" in el7) IMG=centos:7 ;; el8) IMG=almalinux:8 ;; el9) IMG=almalinux:9 ;; *) echo "bad el" >&2; exit 2 ;; esac
case "$ARCH" in x86_64) PLAT=linux/amd64 ;; aarch64) PLAT=linux/arm64 ;; *) echo "bad arch" >&2; exit 2 ;; esac
rpmf() { ls "$OUT"/php"${1//./}"-howdah-*."$ARCH".rpm | head -1; }
args=("${ELV#el}" "$MINOR" "/pkgs/$(basename "$(rpmf "$MINOR")")")
[ -n "$OTHER" ] && args+=("/pkgs/$(basename "$(rpmf "$OTHER")")")
exec docker run --rm --platform "$PLAT" \
  -v "$REPO_ROOT/packaging/rpm/validate-in-container.sh":/v.sh:ro \
  -v "$OUT":/pkgs:ro \
  "$IMG" sh /v.sh "${args[@]}"
