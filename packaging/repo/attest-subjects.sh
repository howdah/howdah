#!/bin/sh
# Print the attestation subjects for the packages THIS run built, in
# sha256sum format ("<sha256>  <name>"), for actions/attest-build-provenance's
# subject-checksums input (publish-repos.yml).
#
#   packaging/repo/attest-subjects.sh PKG_DIR REPO_DIR [NAME_PREFIX]
#
#   PKG_DIR   where the new, unsigned packages are: *.deb and *.rpm directly
#             inside it (packaging/out, or packaging/out/layouts/<prefix>/<kind>)
#   REPO_DIR  the assembled repository for them: apt/pool/... and yum/*.rpm
#             (packaging/out/repo, or packaging/out/layout-repo/<prefix>)
#   NAME_PREFIX  prepended to each subject name (a layout's "<prefix>/")
#
# Each subject is the file users download, named by its path in the
# repository: a .deb is hashed where it sits in the pool (the bytes are those
# dpkg-deb wrote); an .rpm is hashed in yum/ AFTER rpmsign, because signing
# rewrites the rpm. Packages seeded from the published repository are not
# listed: this run did not build them. A new package missing from REPO_DIR is
# an error.
set -eu
PKG_DIR="${1:?usage: attest-subjects.sh PKG_DIR REPO_DIR [NAME_PREFIX]}"
REPO_DIR="${2:?usage: attest-subjects.sh PKG_DIR REPO_DIR [NAME_PREFIX]}"
NAME_PREFIX="${3:-}"
n=0
for p in "$PKG_DIR"/*.deb "$PKG_DIR"/*.rpm; do
  [ -e "$p" ] || continue
  b=$(basename "$p")
  case "$b" in
    *.deb)
      f=$(find "$REPO_DIR/apt/pool" -type f -name "$b" 2>/dev/null | head -1)
      if [ -z "$f" ] || ! cmp -s "$p" "$f"; then
        echo "FATAL: $b is not in $REPO_DIR/apt/pool (or differs from the built one)" >&2; exit 1
      fi ;;
    *.rpm)
      f="$REPO_DIR/yum/$b"
      [ -f "$f" ] || { echo "FATAL: $b is not in $REPO_DIR/yum" >&2; exit 1; } ;;
  esac
  rel=${f#"$REPO_DIR"/}
  printf '%s  %s%s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$NAME_PREFIX" "$rel"
  n=$((n+1))
done
[ "$n" -gt 0 ] || { echo "FATAL: no .deb or .rpm in $PKG_DIR" >&2; exit 1; }
