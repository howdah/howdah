#!/bin/sh
# Host driver for the shipped-path mode matrix regression (see
# mode_matrix_container.sh): howdah.mode via php.ini with NO howdah.config file
# must actually drive the core — off does nothing, detect/block still block a
# PHP2Shell flood (critical-always-block), and phpinfo's Mode row matches.
#
# Usage (from the repo root):
#   lab/integration/mode_matrix.sh            # PHP 7.3
#   LOAD_EXT=0 lab/integration/mode_matrix.sh # RED: no ext -> off flood blocked? (fails)
#   IMAGE=howdah-dev-php8.4 FEATURE=php8 lab/integration/mode_matrix.sh
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
  "$IMAGE" sh /src/lab/integration/mode_matrix_container.sh "$FEATURE"
