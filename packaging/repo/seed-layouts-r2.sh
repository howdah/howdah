#!/usr/bin/env bash
# Download the packages already published in every layout repository this run
# rebuilds, so the regenerated indexes keep every prior version. Same rule as
# the main repository's seed step in publish-repos.yml: if R2 already holds
# packages under a prefix but the download comes back empty, abort, because an
# index rebuilt from an empty seed would silently drop every prior version.
#
#   packaging/repo/seed-layouts-r2.sh <bucket> [LAYOUT_DIR] [SEED_DIR]
#
#   LAYOUT_DIR  default packaging/out/layouts (which prefixes this run builds)
#   SEED_DIR    default packaging/out/layout-seed -> <prefix>/apt/pool/..., <prefix>/yum/*.rpm
#   rclone remote `R2` from the RCLONE_CONFIG_R2_* env (as publish-r2.sh);
#   HOWDAH_R2_PREFIX nests everything under a key prefix (default: bucket root).
# Read-only on R2.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUCKET="${1:?usage: seed-layouts-r2.sh <bucket> [LAYOUT_DIR] [SEED_DIR]}"
LAYOUT_DIR="$(cd "${2:-$REPO_ROOT/packaging/out/layouts}" && pwd)"
SEED="${3:-$REPO_ROOT/packaging/out/layout-seed}"
PFX="${HOWDAH_R2_PREFIX:+${HOWDAH_R2_PREFIX%/}/}"

list="$(sh "$REPO_ROOT/packaging/repo/layout-prefixes.sh" "$LAYOUT_DIR")"
while read -r prefix kind; do
  [ -n "$prefix" ] || continue
  if [ "$kind" = apt ]; then
    remote="R2:$BUCKET/${PFX}$prefix/apt/pool"; local_dir="$SEED/$prefix/apt/pool"; inc='*.deb'
  else
    remote="R2:$BUCKET/${PFX}$prefix/yum"; local_dir="$SEED/$prefix/yum"; inc='*.rpm'
  fi
  mkdir -p "$local_dir"
  # 1. does R2 already hold packages here? (an absent prefix prints nothing)
  have_remote="$(rclone lsf "$remote" -R --files-only --include "$inc" 2>/dev/null | head -1 || true)"
  # 2. download; an absent prefix can exit non-zero, the assert below decides
  rclone copy "$remote" "$local_dir" --include "$inc" -v --retries 5 --low-level-retries 10 || true
  have_local="$(find "$local_dir" -name "$inc" | head -1)"
  echo "== seed $prefix/$kind: R2 has packages: $([ -n "$have_remote" ] && echo yes || echo no); seeded $(find "$local_dir" -name "$inc" | wc -l | tr -d ' ')"
  # 3. consistency assert
  if [ -n "$have_remote" ] && [ -z "$have_local" ]; then
    echo "::error::R2 already has $prefix/$kind packages but the local seed is empty: the seed download failed; aborting so we do not publish an index that drops prior versions." >&2
    exit 1
  fi
done <<< "$list"
