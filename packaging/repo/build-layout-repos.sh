#!/usr/bin/env bash
# Assemble and sign one apt and/or yum repository per layout prefix from the
# packages packaging/build-layouts.sh wrote under packaging/out/layouts/, by
# calling the SAME build-apt-repo.sh / build-yum-repo.sh the main repository
# uses (unchanged). Every prefix is its own repository with its own signed
# Release / repomd.xml, so the main apt/ and yum/ indexes are never touched.
#
#   HOWDAH_GPG_KEYID=<fingerprint|keyid[!]> HOWDAH_GNUPGHOME=<dir> \
#     [HOWDAH_LAYOUT_SEED=<dir>] packaging/repo/build-layout-repos.sh [LAYOUT_DIR] [OUT_DIR]
#
#   LAYOUT_DIR  default packaging/out/layouts      <prefix>/apt/*.deb, <prefix>/yum/*.rpm
#   OUT_DIR     default packaging/out/layout-repo  -> <prefix>/apt/{dists,pool}, <prefix>/yum/{*.rpm,repodata}
#   HOWDAH_LAYOUT_SEED  optional: the packages already published, laid out as on
#               R2 (<prefix>/apt/pool/..., <prefix>/yum/*.rpm; seed-layouts-r2.sh
#               downloads it), so each index keeps every published version.
#
# Prefixes are the repository paths under https://pkg.howdah.org/: cpanel,
# plesk, cloudlinux, el/php<minor> (see packaging/layouts.tsv). Users point
# apt at https://pkg.howdah.org/<prefix>/apt (suite stable, component main)
# and yum/dnf at https://pkg.howdah.org/<prefix>/yum.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO_ROOT/packaging/repo"
: "${HOWDAH_GPG_KEYID:?set HOWDAH_GPG_KEYID}" "${HOWDAH_GNUPGHOME:?set HOWDAH_GNUPGHOME}"
LAYOUT_DIR="$(cd "${1:-$REPO_ROOT/packaging/out/layouts}" && pwd)"
OUT_DIR="${2:-$REPO_ROOT/packaging/out/layout-repo}"
mkdir -p "$OUT_DIR"; OUT_DIR="$(cd "$OUT_DIR" && pwd)"
SEED="${HOWDAH_LAYOUT_SEED:-}"

list="$(sh "$HERE/layout-prefixes.sh" "$LAYOUT_DIR")"
[ -n "$list" ] || { echo "FATAL: no layout packages under $LAYOUT_DIR" >&2; exit 1; }
while read -r prefix kind; do
  echo "== layout repo $prefix/$kind"
  mkdir -p "$OUT_DIR/$prefix"
  if [ "$kind" = apt ]; then
    HOWDAH_APT_SEED="${SEED:+$SEED/$prefix/apt/pool}" \
      "$HERE/build-apt-repo.sh" "$LAYOUT_DIR/$prefix/apt" "$OUT_DIR/$prefix"
  else
    HOWDAH_YUM_SEED="${SEED:+$SEED/$prefix/yum}" \
      "$HERE/build-yum-repo.sh" "$LAYOUT_DIR/$prefix/yum" "$OUT_DIR/$prefix"
  fi
done <<< "$list"
echo "== layout repos in $OUT_DIR:"
printf '%s\n' "$list" | sed 's/^/   /'
