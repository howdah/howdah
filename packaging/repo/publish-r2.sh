#!/usr/bin/env bash
# Upload an assembled repo tree (packaging/out/repo/{apt,yum}) to the R2 bucket
# in DEPENDENCY ORDER, so a client mid-update never sees an index that points at
# a package that is not there yet (design section 10 builder notes):
#
#   1. packages        apt pool/**, yum *.rpm          (version-named, immutable)
#   2. indexes         apt Packages*/Contents, yum repodata/* except repomd.xml*
#   3. signed roots    apt Release, Release.gpg, InRelease; yum repomd.xml, .asc
#                      (LAST, back-to-back)
#
# Never deletes anything (copy, not sync): superseded packages and old
# checksum-named repodata files stay so clients holding an older index still work.
# Packages are uploaded with --immutable: re-publishing the same file name with
# different bytes is an error (bump the package revision instead).
#
#   R2 credentials via rclone env (remote name R2):
#     RCLONE_CONFIG_R2_TYPE=s3 RCLONE_CONFIG_R2_PROVIDER=Cloudflare
#     RCLONE_CONFIG_R2_ACCESS_KEY_ID=... RCLONE_CONFIG_R2_SECRET_ACCESS_KEY=...
#     RCLONE_CONFIG_R2_ENDPOINT=https://<acct>.r2.cloudflarestorage.com
#     RCLONE_CONFIG_R2_NO_CHECK_BUCKET=true
#
#   packaging/repo/publish-r2.sh <bucket> [REPO_DIR]
#   HOWDAH_R2_PREFIX   key prefix inside the bucket (default: none = bucket root)
#   HOWDAH_R2_DRY_RUN=1  pass --dry-run to every rclone call (nothing written)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUCKET="${1:?usage: publish-r2.sh <bucket> [REPO_DIR]}"
REPO="$(cd "${2:-$REPO_ROOT/packaging/out/repo}" && pwd)"
PFX="${HOWDAH_R2_PREFIX:+${HOWDAH_R2_PREFIX%/}/}"
DEST="R2:$BUCKET/$PFX"

[ -d "$REPO/apt/dists" ] && [ -d "$REPO/apt/pool" ] || { echo "FATAL: $REPO/apt is not an assembled apt repo" >&2; exit 1; }
[ -f "$REPO/apt/dists/stable/InRelease" ] || { echo "FATAL: apt InRelease missing (unsigned?)" >&2; exit 1; }
[ -f "$REPO/yum/repodata/repomd.xml" ] && [ -f "$REPO/yum/repodata/repomd.xml.asc" ] || { echo "FATAL: $REPO/yum is not an assembled, signed yum repo" >&2; exit 1; }

DRY=""
[ "${HOWDAH_R2_DRY_RUN:-0}" = 1 ] && DRY="--dry-run"
LONG="Cache-Control: public, max-age=31536000, immutable"    # version-named packages
SHORT="Cache-Control: public, max-age=300, must-revalidate"  # mutable indexes / roots
rc() { rclone "$@" $DRY --retries 5 --low-level-retries 10 -v; }

echo "== 1/3 packages (immutable, long cache) -> $DEST"
rc copy "$REPO/apt/pool" "${DEST}apt/pool" --immutable --header-upload "$LONG"
rc copy "$REPO/yum" "${DEST}yum" --include '*.rpm' --immutable --header-upload "$LONG"

echo "== 2/3 indexes (short cache)"
rc copy "$REPO/apt/dists" "${DEST}apt/dists" \
  --exclude '/stable/InRelease' --exclude '/stable/Release' --exclude '/stable/Release.gpg' \
  --header-upload "$SHORT"
rc copy "$REPO/yum/repodata" "${DEST}yum/repodata" \
  --exclude '/repomd.xml' --exclude '/repomd.xml.asc' --header-upload "$SHORT"

echo "== 3/3 signed roots, LAST, back-to-back"
for f in apt/dists/stable/Release apt/dists/stable/Release.gpg apt/dists/stable/InRelease \
         yum/repodata/repomd.xml yum/repodata/repomd.xml.asc; do
  rc copyto "$REPO/$f" "${DEST}$f" --header-upload "$SHORT"
done
echo "== done ${DRY:+(DRY RUN: nothing was written)}"
