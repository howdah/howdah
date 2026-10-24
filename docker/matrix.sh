#!/bin/sh
# Print the docker.yml build matrix (one JSON line) for a release, from the
# file names in that release's SHA256SUMS. An image is planned only for a PHP
# minor and CPU whose tarball the release actually carries, so a failed
# best-effort aarch64 (or musl) cell just means that platform is left out.
#
#   docker/matrix.sh <version> [floating] < SHA256SUMS
#     version   e.g. 1.4.0 (no leading v)
#     floating  1 to also tag php<minor>[-alpine] (the newest release only)
#
# Env: IMAGE (default ghcr.io/howdah/howdah)
#
# Base images, checked on Docker Hub (2026-10-24): php:<minor>-fpm is pullable
# for 5.6, 7.0-7.4 and 8.0-8.5, amd64 and arm64. php:5.4-fpm is a schema-1
# manifest that Docker 28+ (containerd 2.1) refuses to pull, and php:5.5-fpm
# has a missing layer, so neither gets an image. php:<minor>-fpm-alpine needs
# the release's *-linux-x86_64-musl tarballs; ALPINE_MINORS are the minors
# whose musl build was loaded and smoke-tested in the matching alpine image
# (all 12, with a locally built and signed musl release of the 1.4.0 source).
set -eu

VERSION=${1:?usage: docker/matrix.sh <version> [floating] < SHA256SUMS}
FLOATING=${2:-0}
IMAGE=${IMAGE:-ghcr.io/howdah/howdah}
DEBIAN_MINORS="5.6 7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5"
ALPINE_MINORS=${ALPINE_MINORS:-"5.6 7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5"}

case "$VERSION" in
  *[!0-9.]*|'') echo "matrix.sh: '$VERSION' is not a release version (pre-releases get no images)" >&2; exit 2 ;;
esac

NAMES=$(awk '{ n = $2; sub(/^\*/, "", n); print n }')
has() { # <minor> <suffix> -> 0 if the release has that tarball
  for _n in $NAMES; do
    case "$_n" in "howdah-$VERSION-php$1-"*"-$2.tar.gz") return 0 ;; esac
  done
  return 1
}

out=""
add() { # <minor> <variant> <libc> <platforms> <tag-suffix>
  _tags="$IMAGE:$VERSION-php$1$5"
  [ "$FLOATING" = 1 ] && _tags="$_tags,$IMAGE:php$1$5"
  _e=$(printf '{"minor":"%s","variant":"%s","libc":"%s","platforms":"%s","tags":"%s"}' "$1" "$2" "$3" "$4" "$_tags")
  out="${out:+$out,}$_e"
}

for m in $DEBIAN_MINORS; do
  p=""
  has "$m" linux-x86_64 && p="linux/amd64"
  has "$m" linux-aarch64 && p="${p:+$p,}linux/arm64"
  [ -n "$p" ] && add "$m" fpm glibc "$p" ""
done
for m in $ALPINE_MINORS; do
  has "$m" linux-x86_64-musl && add "$m" fpm-alpine musl linux/amd64 -alpine
done

[ -n "$out" ] || { echo "matrix.sh: release $VERSION has no tarball any image can use" >&2; exit 1; }
printf '{"include":[%s]}\n' "$out"
