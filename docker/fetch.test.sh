#!/bin/sh
# Tests for docker/fetch.sh against a real release (needs docker and network):
# it installs only what the committed key signed, and refuses a tampered
# SHA256SUMS, a tampered tarball and a foreign key.
#   sh docker/fetch.test.sh [version]      (default 1.4.0)
set -u
D=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$D/.." && pwd)
V=${1:-1.4.0}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }

B=https://github.com/howdah/howdah/releases/download/v$V
TB=howdah-$V-php8.3-20230831-linux-x86_64.tar.gz
mkdir -p "$T/good"
for f in SHA256SUMS SHA256SUMS.asc "$TB"; do
  curl -fsSL -o "$T/good/$f" "$B/$f" || { echo "cannot download $B/$f"; exit 2; }
done
cp "$ROOT/packaging/howdah-release-signing.asc" "$T/key.asc"
chmod -R a+rX "$T"

# run fetch.sh in alpine against file:///dist; prints its exit code last
run() { # <dist dir> <key file> [extra env...]
  _dist=$1; _key=$2; shift 2
  docker run --rm -v "$_dist":/dist:ro -v "$_key":/key.asc:ro -v "$D/fetch.sh":/fetch.sh:ro \
    -e HOWDAH_VERSION="$V" -e PHP_MINOR=8.3 -e TARGETARCH=amd64 \
    -e HOWDAH_DIST_URL=file:///dist -e HOWDAH_KEY=/key.asc "$@" \
    alpine:3.21 sh -c 'apk add --no-cache curl gpg gpgv tar >/dev/null 2>&1; sh /fetch.sh; echo "rc=$?"; find /howdah -type f 2>/dev/null | sort'
}

out=$(run "$T/good" "$T/key.asc" 2>&1)
case "$out" in *"rc=0"*) ok "good release: fetch.sh exits 0" ;; *) bad "good release: fetch.sh exits 0"; printf '%s\n' "$out" ;; esac
for p in /howdah/usr/local/lib/php/extensions/no-debug-non-zts-20230831/howdah.so \
         /howdah/usr/local/etc/php/conf.d/docker-php-ext-howdah.ini \
         /howdah/usr/local/bin/howdah-check \
         "/howdah/usr/share/doc/howdah/$TB" /howdah/usr/share/doc/howdah/PROVENANCE; do
  case "$out" in *"$p"*) ok "lays out $p" ;; *) bad "lays out $p" ;; esac
done
case "$out" in *"Good signature"*) ok "gpgv reports a good signature" ;; *) bad "gpgv reports a good signature" ;; esac
# the primary fingerprint the site publishes (site/src/lib/site.ts KEY_FPR)
case "$out" in *"signing_key=11521035C600F63831F825512087B8720997807B"*) ok "PROVENANCE records the release key fingerprint" ;;
  *) bad "PROVENANCE records the release key fingerprint" ;; esac

# tampered SHA256SUMS (signature no longer matches)
mkdir -p "$T/sums"; cp "$T/good/"* "$T/sums/"
sed -i '1s/^./0/' "$T/sums/SHA256SUMS"
out=$(run "$T/sums" "$T/key.asc" 2>&1)
case "$out" in *"rc=0"*) bad "tampered SHA256SUMS is refused" ;;
  *"not signed by the committed Howdah release key"*) ok "tampered SHA256SUMS is refused" ;;
  *) bad "tampered SHA256SUMS is refused (wrong reason)"; printf '%s\n' "$out" ;; esac
case "$out" in *howdah.so*) bad "nothing is laid out after a bad signature" ;; *) ok "nothing is laid out after a bad signature" ;; esac

# tampered tarball (signature fine, checksum not)
mkdir -p "$T/tar"; cp "$T/good/"* "$T/tar/"
printf 'x' >> "$T/tar/$TB"
out=$(run "$T/tar" "$T/key.asc" 2>&1)
case "$out" in *"rc=0"*) bad "tampered tarball is refused" ;;
  *"does not match the signed SHA256SUMS"*) ok "tampered tarball is refused" ;;
  *) bad "tampered tarball is refused (wrong reason)"; printf '%s\n' "$out" ;; esac

# a key that did not sign the release
docker run --rm alpine:3.21 sh -c 'apk add --no-cache gpg gpg-agent >/dev/null 2>&1; export GNUPGHOME=/tmp/g; mkdir -m 700 $GNUPGHOME;
  gpg --batch --passphrase "" --quick-gen-key "Not Howdah <x@example.invalid>" ed25519 sign never >/dev/null 2>&1;
  gpg --batch --armor --export' > "$T/other.asc"
chmod a+r "$T/other.asc"
out=$(run "$T/good" "$T/other.asc" 2>&1)
case "$out" in *"rc=0"*) bad "a foreign key is refused" ;;
  *"not signed by the committed Howdah release key"*) ok "a foreign key is refused" ;;
  *) bad "a foreign key is refused (wrong reason)"; printf '%s\n' "$out" ;; esac

# no tarball for the requested minor/libc
out=$(run "$T/good" "$T/key.asc" -e HOWDAH_LIBC=musl 2>&1)
case "$out" in *"has no PHP 8.3 tarball for linux-x86_64-musl"*) ok "missing musl tarball is reported" ;;
  *) bad "missing musl tarball is reported"; printf '%s\n' "$out" ;; esac

[ $fail -eq 0 ] && echo "all passed"
exit $fail
