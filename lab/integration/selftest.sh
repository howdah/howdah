#!/bin/sh
# Howdah self-test integration test (host driver): `howdah-check web <url>`
# against a PHP server with Howdah loaded. Reuses the dev image + extension
# build from block_shaped.sh. See selftest_container.sh for the assertions.
#
# Usage (repo root):
#   lab/integration/selftest.sh                # PHP 7.3
#   LOAD_EXT=0 lab/integration/selftest.sh     # RED: no extension -> not flagged
#   IMAGE=howdah-dev-php8.4 FEATURE=php8 lab/integration/selftest.sh
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${IMAGE:-howdah-dev-php7.3}"
FEATURE="${FEATURE:-php7}"
BASE="${BASE:-lab-php-7.3}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "== building $IMAGE from dev.Dockerfile (BASE=$BASE) =="
  docker build -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=$BASE" -t "$IMAGE" "$ROOT"
fi

exec docker run --rm \
  -v "$ROOT":/src:ro \
  -e LOAD_EXT="${LOAD_EXT:-1}" \
  -e HC="${HC:-/src/tools/howdah-check}" \
  "$IMAGE" sh /src/lab/integration/selftest_container.sh "$FEATURE"
