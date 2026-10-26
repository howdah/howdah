#!/bin/sh
# Howdah T5 file guards integration test (host driver): the Layer-4 delete guard,
# the widened dangerous-write facet (always-on upload tier + scoped
# deny_php_writes tier) and the opt-in secret-read guard.
#
# Builds the real extension into each howdah-dev-php<ver> image and runs
# file_guard_container.sh, which proves per PHP version that
#   * unlink/rmdir/rename-away of wp-config.php, .env, key material and a `..`
#     traversal into a system directory is refused clean (the sink returns false,
#     the file survives, the SCRIPT CONTINUES), logged as rule file_delete with a
#     path CATEGORY and the origin file:line, never the target;
#   * move_uploaded_file into a .php/.phtml/.pht/.phar/.htaccess/.user.ini/
#     web.config name is refused by default (no config), and the scoped tier
#     covers the whole set across file_put_contents/fopen/copy/rename;
#   * secret reads are OFF by default, log under [behavior] secret_read =
#     "detect" without blocking, and only refuse under an explicit "block";
#   * a BENIGN corpus (cache/tmp/session/upload deletes, .txt/.json/.log/.jpg
#     writes and uploads, reads of the app's own config) produces ZERO blocks on
#     the two enforced-by-default guards.
#
# Usage (repo root):
#   lab/integration/file_guard.sh                          # the full matrix
#   lab/integration/file_guard.sh 8.3                      # one minor
#   lab/integration/file_guard.sh 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5
#   HOWDAH_TARGET_CACHE=/var/tmp/howdah-t lab/integration/file_guard.sh 8.3   # reuse cargo builds
#
# Needs the howdah-dev-php<minor> images from lab/images/dev.Dockerfile.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5}"
OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

feature() {
  case "$1" in
    5.*) echo php5 ;;
    7.*) echo php7 ;;
    *)   echo php8 ;;
  esac
}

rc=0
for V in $VERSIONS; do
  IMG="howdah-dev-php$V"
  F=$(feature "$V")
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    echo "SKIP php$V (missing image $IMG; see lab/images/dev.Dockerfile)"
    continue
  fi
  CACHE=""
  if [ -n "${HOWDAH_TARGET_CACHE:-}" ]; then
    mkdir -p "$HOWDAH_TARGET_CACHE/$IMG"
    CACHE="-v $HOWDAH_TARGET_CACHE/$IMG:/tmp/t"
  fi
  echo "================ php $V ($F) ================"
  VOUT=$(mktemp)
  set +e
  # shellcheck disable=SC2086
  docker run --rm $CACHE -v "$ROOT":/src:ro "$IMG" sh /src/lab/integration/file_guard_container.sh "$F" > "$VOUT" 2>&1
  st=$?
  set -e
  cat "$VOUT"
  cat "$VOUT" >> "$OUT"
  if [ "$st" -ne 0 ] || ! grep -q "^PASS php " "$VOUT"; then
    echo "FAIL php$V"
    rc=1
  fi
  rm -f "$VOUT"
done

echo
echo "================ per-version results (each cell: attacks refused/logged | benign performed | benign FALSE BLOCKS) ================"
printf '%-10s %-16s %-16s %-16s %-16s\n' "php" "delete-guard" "upload-write" "scoped-write" "secret-read(det)"
grep '^TABLE|' "$OUT" | while IFS='|' read -r _ ver db dok dfp ub uok ufp sb sok sfp rl rok rfp; do
  printf '%-10s %-16s %-16s %-16s %-16s\n' "$ver" "$db | $dok | $dfp" "$ub | $uok | $ufp" "$sb | $sok | $sfp" "$rl | $rok | $rfp"
done
exit $rc
