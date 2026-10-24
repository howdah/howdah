#!/bin/sh
# Howdah Layer-4 (after-a-breach) behaviour integration test (host driver).
# Builds the real extension inside a howdah-dev-php<ver> image and runs
# behavior_container.sh (harmless-shape fixtures only).
#
# Usage (repo root):
#   lab/integration/behavior.sh                                   # PHP 8.3 (default)
#   VERSIONS="5.4 5.6 7.4 8.3 8.5" lab/integration/behavior.sh    # whole matrix
#   IMAGE=howdah-dev-php7.4 FEATURE=php7 lab/integration/behavior.sh   # one image
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

run_one() {
  _image=$1; _feature=$2
  docker image inspect "$_image" >/dev/null 2>&1 || { echo "missing image $_image (see lab/images/dev.Dockerfile)"; return 1; }
  CACHE=""
  if [ -n "${HOWDAH_TARGET_CACHE:-}" ]; then
    mkdir -p "$HOWDAH_TARGET_CACHE/$_image"
    CACHE="-v $HOWDAH_TARGET_CACHE/$_image:/tmp/t"
  fi
  # shellcheck disable=SC2086
  docker run --rm $CACHE -v "$ROOT":/src:ro "$_image" sh /src/lab/integration/behavior_container.sh "$_feature"
}

if [ -n "${IMAGE:-}" ]; then
  run_one "$IMAGE" "${FEATURE:-php8}"
  exit $?
fi

rc=0
for v in ${VERSIONS:-8.3}; do
  case "$v" in
    5.*) f=php5 ;;
    7.*) f=php7 ;;
    *)   f=php8 ;;
  esac
  echo "################ PHP $v ($f) ################"
  if run_one "howdah-dev-php$v" "$f"; then echo "RESULT PHP $v: PASS"; else echo "RESULT PHP $v: FAIL"; rc=1; fi
done
exit $rc
