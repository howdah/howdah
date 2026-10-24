#!/bin/sh
# Fetch stage of docker/Dockerfile (runs in alpine on the build host's own
# platform). Downloads ONE release tarball for the target PHP minor and CPU,
# verifies it, and lays it out under /howdah/ exactly where the official
# php:<minor>-* images look for it. Nothing is installed unless:
#   1. SHA256SUMS carries a good signature from the COMMITTED release key
#      (packaging/howdah-release-signing.asc, copied in from the build context,
#      never a key downloaded next to the files), checked with gpgv, and
#   2. the tarball's sha256 matches its line in that signed SHA256SUMS.
#
# Env (from the Dockerfile ARGs):
#   HOWDAH_VERSION   release version, e.g. 1.4.0 (required)
#   PHP_MINOR        e.g. 8.3 (required)
#   TARGETARCH       amd64 | arm64 (set by BuildKit)
#   HOWDAH_LIBC      glibc (default) | musl  -- musl selects the *-musl tarball
#   HOWDAH_DIST_URL  where the release files are (default: the GitHub release)
#   HOWDAH_KEY       the public key to verify against (default /tmp/howdah-release-signing.asc)
#
# Output, /howdah/ (a tree to overlay onto / of an official php image):
#   usr/local/lib/php/extensions/no-debug-non-zts-<API>/howdah.so
#   usr/local/etc/php/conf.d/docker-php-ext-howdah.ini   (the tarball's howdah.ini, unchanged)
#   usr/local/bin/howdah-check
#   usr/share/doc/howdah/   the tarball, SHA256SUMS, SHA256SUMS.asc, the key,
#                           and PROVENANCE (so anyone can re-verify the image)
set -eu

: "${HOWDAH_VERSION:?HOWDAH_VERSION is required (e.g. --build-arg HOWDAH_VERSION=1.4.0)}"
: "${PHP_MINOR:?PHP_MINOR is required (e.g. --build-arg PHP_MINOR=8.3)}"
: "${TARGETARCH:?TARGETARCH is set by BuildKit; build with docker buildx}"
LIBC=${HOWDAH_LIBC:-glibc}
KEY=${HOWDAH_KEY:-/tmp/howdah-release-signing.asc}
URL=${HOWDAH_DIST_URL:-https://github.com/howdah/howdah/releases/download/v$HOWDAH_VERSION}

die() { echo "fetch.sh: $*" >&2; exit 1; }

case "$TARGETARCH" in
  amd64) ARCH=x86_64 ;;
  arm64) ARCH=aarch64 ;;
  *) die "no Howdah build for TARGETARCH '$TARGETARCH' (amd64 and arm64 only)" ;;
esac
case "$LIBC" in
  glibc) SUFFIX="linux-$ARCH" ;;
  musl) SUFFIX="linux-$ARCH-musl" ;;
  *) die "HOWDAH_LIBC must be glibc or musl, not '$LIBC'" ;;
esac

W=$(mktemp -d)
cd "$W"
get() {
  _n=0
  until curl -fsSL -o "$1" "$URL/$1"; do
    _n=$((_n + 1))
    [ "$_n" -ge 5 ] && die "could not download $URL/$1"
    sleep 3
  done
}

get SHA256SUMS
get SHA256SUMS.asc

# 1. the signature, against the committed key only
[ -s "$KEY" ] || die "public key $KEY missing"
mkdir -m 700 "$W/gnupg"
export GNUPGHOME="$W/gnupg"
gpg --batch --quiet --dearmor < "$KEY" > "$W/key.gpg"
gpgv --keyring "$W/key.gpg" SHA256SUMS.asc SHA256SUMS \
  || die "SHA256SUMS is not signed by the committed Howdah release key"
FPR=$(gpg --batch --with-colons --show-keys "$KEY" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')

# 2. pick this minor's tarball from the (now trusted) list, then its checksum
T=""
for n in $(awk '{ sub(/^\*/, "", $2); print $2 }' SHA256SUMS); do
  case "$n" in
    "howdah-$HOWDAH_VERSION-php$PHP_MINOR-"*"-$SUFFIX.tar.gz") T=$n ;;
  esac
done
[ -n "$T" ] || die "release $HOWDAH_VERSION has no PHP $PHP_MINOR tarball for $SUFFIX"
get "$T"
awk -v t="$T" '{ n = $2; sub(/^\*/, "", n) } n == t { print $1 "  " t }' SHA256SUMS > one.sum
sha256sum -c one.sum || die "$T does not match the signed SHA256SUMS"

API=${T#"howdah-$HOWDAH_VERSION-php$PHP_MINOR-"}
API=${API%%-*}
case "$API" in
  [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
  *) die "cannot read the Zend module API number from $T" ;;
esac

tar -xzf "$T"
D="howdah-$HOWDAH_VERSION-php$PHP_MINOR"
for f in howdah.so howdah.ini howdah-check; do
  [ -f "$D/$f" ] || die "$T has no $D/$f"
done

R=/howdah
EXT="$R/usr/local/lib/php/extensions/no-debug-non-zts-$API"
DOC="$R/usr/share/doc/howdah"
mkdir -p "$EXT" "$R/usr/local/etc/php/conf.d" "$R/usr/local/bin" "$DOC"
cp "$D/howdah.so" "$EXT/howdah.so"
cp "$D/howdah.ini" "$R/usr/local/etc/php/conf.d/docker-php-ext-howdah.ini"
cp "$D/howdah-check" "$R/usr/local/bin/howdah-check"
chmod 0644 "$EXT/howdah.so" "$R/usr/local/etc/php/conf.d/docker-php-ext-howdah.ini"
chmod 0755 "$R/usr/local/bin/howdah-check"
cp SHA256SUMS SHA256SUMS.asc "$T" "$DOC/"
cp "$KEY" "$DOC/howdah-release-signing.asc"
{
  echo "howdah_version=$HOWDAH_VERSION"
  echo "php_minor=$PHP_MINOR"
  echo "zend_module_api=$API"
  echo "arch=$ARCH"
  echo "libc=$LIBC"
  echo "tarball=$T"
  echo "tarball_sha256=$(awk '{ print $1 }' one.sum)"
  echo "howdah_so_sha256=$(sha256sum "$EXT/howdah.so" | awk '{ print $1 }')"
  echo "source=$URL"
  echo "signing_key=$FPR"
} > "$DOC/PROVENANCE"
cat "$DOC/PROVENANCE"
cd /
rm -rf "$W"
