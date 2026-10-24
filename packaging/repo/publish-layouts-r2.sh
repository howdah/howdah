#!/usr/bin/env bash
# Upload every assembled layout repository (build-layout-repos.sh output) to
# R2, each under its own prefix, through the same publish-r2.sh the main repo
# uses: packages, then indexes, then the signed Release/InRelease/repomd.xml
# last; copy, never sync; --immutable packages. Nothing under the bucket's
# apt/ or yum/ (the main repository) is written.
#
#   packaging/repo/publish-layouts-r2.sh <bucket> [REPO_DIR]
#
#   REPO_DIR  default packaging/out/layout-repo (<prefix>/apt/..., <prefix>/yum/...)
#   Same env as publish-r2.sh (RCLONE_CONFIG_R2_*, HOWDAH_R2_DRY_RUN,
#   HOWDAH_R2_OVERWRITE); HOWDAH_R2_PREFIX, if set, nests every layout prefix.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUCKET="${1:?usage: publish-layouts-r2.sh <bucket> [REPO_DIR]}"
REPO="$(cd "${2:-$REPO_ROOT/packaging/out/layout-repo}" && pwd)"
BASE="${HOWDAH_R2_PREFIX:+${HOWDAH_R2_PREFIX%/}/}"

# <prefix> <kinds> for every assembled repo (apt/dists or yum/repodata present)
list="$(find "$REPO" -mindepth 3 -type d \( -path '*/apt/dists' -o -path '*/yum/repodata' \) | sort | while IFS= read -r d; do
  kind="${d%/*}"; kind="${kind##*/}"
  prefix="${d#"$REPO"/}"; prefix="${prefix%/"$kind"/*}"
  echo "$prefix $kind"
done)"
[ -n "$list" ] || { echo "FATAL: no assembled layout repos under $REPO" >&2; exit 1; }
prefixes="$(printf '%s\n' "$list" | cut -d' ' -f1 | sort -u)"
for prefix in $prefixes; do
  case "$prefix" in
    ''|apt|apt/*|yum|yum/*) echo "FATAL: layout prefix '$prefix' would overlap the main apt/yum repo" >&2; exit 1 ;;
  esac
  kinds="$(printf '%s\n' "$list" | awk -v p="$prefix" '$1 == p { printf "%s%s", sep, $2; sep = " " }')"
  echo "== layout repo $prefix ($kinds) -> R2:$BUCKET/${BASE}$prefix/"
  HOWDAH_R2_PREFIX="${BASE}$prefix" HOWDAH_R2_KINDS="$kinds" \
    "$REPO_ROOT/packaging/repo/publish-r2.sh" "$BUCKET" "$REPO/$prefix"
done
