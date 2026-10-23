#!/usr/bin/env bash
# Produce SHA256SUMS over the release tarballs and a detached GPG signature of
# it, using the Howdah CI *signing subkey* (the offline primary/certify key
# never touches a build host or CI).
#
#   packaging/sign.sh [DIR]      # DIR defaults to packaging/out
#
# Signer: the signing subkey 1E8D725D31BD5DC9 (fingerprint
# 9A104FB0A073065B2C2631FC1E8D725D31BD5DC9). The trailing "!" pins that exact
# subkey rather than letting GnuPG pick a default. Override with HOWDAH_SIGNING_KEY.
#
# Non-interactive signing (CI, or a passphraseless subkey): set
#   HOWDAH_SIGN_BATCH=1              use loopback pinentry, no prompt
#   HOWDAH_SIGN_PASSPHRASE=<pass>    passphrase to feed (default: empty)
# The release workflow imports the passphraseless subkey from the
# HOWDAH_GPG_SIGNING_KEY secret and runs with HOWDAH_SIGN_BATCH=1.
#
# Output in DIR:
#   SHA256SUMS      sha256 of every *.tar.gz PLUS the standalone howdah-check
#                   (one per line, filenames only)
#   SHA256SUMS.asc  detached, armored signature of SHA256SUMS
set -euo pipefail

DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/out}"
SIGNING_KEY="${HOWDAH_SIGNING_KEY:-1E8D725D31BD5DC9!}"

cd "$DIR"
shopt -s nullglob
assets=(*.tar.gz)
if [ ${#assets[@]} -eq 0 ]; then
  echo "FATAL: no *.tar.gz in $DIR (run build-release.sh first)" >&2
  exit 1
fi
# The standalone, version-independent howdah-check is a first-class release
# asset (you run `howdah-check detect` to find your PHP API number BEFORE
# picking a tarball), so the detached signature must cover it too.
[ -f howdah-check ] && assets+=(howdah-check)

echo "== hashing ${#assets[@]} asset(s) in $DIR"
# Filenames only (no paths) so `sha256sum -c SHA256SUMS` works from inside DIR.
sha256sum "${assets[@]}" > SHA256SUMS
cat SHA256SUMS

gpg_args=(--batch --yes --armor -u "$SIGNING_KEY" --detach-sign -o SHA256SUMS.asc)
if [ "${HOWDAH_SIGN_BATCH:-0}" = 1 ]; then
  gpg_args=(--pinentry-mode loopback --passphrase "${HOWDAH_SIGN_PASSPHRASE:-}" "${gpg_args[@]}")
fi

echo "== signing SHA256SUMS with subkey $SIGNING_KEY"
gpg "${gpg_args[@]}" SHA256SUMS

echo "== verifying the signature we just made"
gpg --verify SHA256SUMS.asc SHA256SUMS

echo "== done: $DIR/SHA256SUMS + SHA256SUMS.asc"
echo "   users verify with: gpg --import packaging/howdah-release-signing.asc && gpg --verify SHA256SUMS.asc SHA256SUMS"
