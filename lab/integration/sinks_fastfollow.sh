#!/bin/sh
# Howdah Layer-3 fast-follow integration test (host driver): phar:// guard,
# SSRF guard (+ the T6 hardening: egress-scheme denial, resolve-at-connect /
# anti-DNS-rebinding, curl internal-redirect guard) and PHP 5.x include/eval
# (compile-pointer swap), end to end on real PHP. Builds the extension into a
# howdah-dev-php<ver> image and runs sinks_fastfollow_container.sh.
#
# Usage (repo root):
#   lab/integration/sinks_fastfollow.sh 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5   # the matrix
#   lab/integration/sinks_fastfollow.sh 8.3                                # one minor
#   lab/integration/sinks_fastfollow.sh                                    # PHP 8.3 (default)
#   IMAGE=howdah-dev-php8.5 FEATURE=php8 lab/integration/sinks_fastfollow.sh   # explicit image
#
# HOWDAH_TARGET_CACHE=/some/dir keeps the in-container cargo target between runs
# (dev speed-up only; CI leaves it unset). When versions are given on the command
# line it is a prefix: one directory per version (<dir>-<ver>), because the
# php5/php7/php8 builds differ and must never share a target directory (a stale
# .so from another PHP generation will not even load). With IMAGE=... it is used
# as is.
#
# Needs the howdah-dev-php<minor> images from lab/images/dev.Dockerfile.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

feature() {
  case "$1" in
    5.*) echo php5 ;;
    7.*) echo php7 ;;
    *)   echo php8 ;;
  esac
}

# run_one <image> <feature> <cache-dir-or-empty>; the container's stdout/stderr
# go to the caller.
run_one() {
  _img=$1; _feat=$2; _cache=$3
  docker image inspect "$_img" >/dev/null 2>&1 || { echo "missing image $_img (see lab/images/dev.Dockerfile)"; return 2; }
  _c=""
  if [ -n "$_cache" ]; then
    mkdir -p "$_cache"
    _c="-v $_cache:/tmp/t"
  fi
  # shellcheck disable=SC2086
  docker run --rm $_c -v "$ROOT":/src:ro "$_img" sh /src/lab/integration/sinks_fastfollow_container.sh "$_feat"
}

# Explicit IMAGE (the original interface): one run, output straight through.
if [ "$#" -eq 0 ] && [ -n "${IMAGE:-}" ]; then
  run_one "$IMAGE" "${FEATURE:-php8}" "${HOWDAH_TARGET_CACHE:-}"
  exit $?
fi

VERSIONS="${*:-8.3}"
OUT=$(mktemp)
SUMMARY=$(mktemp)
trap 'rm -f "$OUT" "$SUMMARY"' EXIT

rc=0
for V in $VERSIONS; do
  F=$(feature "$V")
  CACHE=""
  if [ -n "${HOWDAH_TARGET_CACHE:-}" ]; then
    CACHE="${HOWDAH_TARGET_CACHE}-$V"
  fi
  echo "================ php $V ($F) ================"
  if run_one "howdah-dev-php$V" "$F" "$CACHE" >"$OUT" 2>&1; then
    cat "$OUT"
    printf '%s\tPASS\t%s\n' "$V" "$(grep '^T6 summary' "$OUT" | sed 's/^T6 summary: //' | tail -n 1)" >>"$SUMMARY"
  else
    cat "$OUT"
    echo "FAIL php$V"
    printf '%s\tFAIL\t\n' "$V" >>"$SUMMARY"
    rc=1
  fi
done

echo
echo "================ per-version result ================"
printf '%s\t%s\t%s\n' "php" "result" "T6 (scheme / pin mechanism / redirect / rebind / gaps pinned)"
cat "$SUMMARY"
exit $rc
