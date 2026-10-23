#!/usr/bin/env bash
# Install/load/guard/remove validation of a built .deb in a real Debian
# container against Sury PHP.
#
#   packaging/deb/validate.sh <minor> <amd64|arm64> [<other-minor>]
#
# Expects packaging/out/php<minor>-howdah_<ver>-1_<arch>.deb (build-deb.sh).
# With <other-minor>, also proves the wrong-API guard using that minor's .deb
# (must already be built for the same arch).
# arm64 runs under QEMU (--platform linux/arm64). Needs network (packages.sury.org).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO_ROOT/packaging/out"
MINOR="${1:?usage: validate.sh <minor> <amd64|arm64> [other-minor]}"
ARCH="${2:?usage: validate.sh <minor> <amd64|arm64> [other-minor]}"
OTHER="${3:-}"
DEB="$(ls "$OUT"/php"$MINOR"-howdah_*_"$ARCH".deb | head -1)"
args=("$MINOR" "/pkgs/$(basename "$DEB")")
if [ -n "$OTHER" ]; then
  ODEB="$(ls "$OUT"/php"$OTHER"-howdah_*_"$ARCH".deb | head -1)"
  args+=("/pkgs/$(basename "$ODEB")")
fi
exec docker run --rm --platform "linux/$ARCH" \
  -v "$REPO_ROOT/packaging/deb/validate-in-container.sh":/v.sh:ro \
  -v "$OUT":/pkgs:ro \
  debian:bookworm sh /v.sh "${args[@]}"
