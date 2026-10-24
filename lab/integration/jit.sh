#!/bin/sh
# OPcache JIT compatibility test (host driver): proves that Howdah installs
# the include/eval opcode handler only when something armed needs it, that
# `[sinks] hook = "compile"` keeps the JIT on while eval/include still fire,
# and demonstrates the warm-opcache caveat of compile mode. Builds the
# extension into a howdah-dev-php<ver> image and runs jit_container.sh.
#
# Usage (repo root):
#   lab/integration/jit.sh                                   # PHP 8.3
#   IMAGE=howdah-dev-php8.1 FEATURE=php8 lab/integration/jit.sh
#   IMAGE=howdah-dev-php7.4 FEATURE=php7 lab/integration/jit.sh
#   IMAGE=howdah-dev-php5.6 FEATURE=php5 lab/integration/jit.sh
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${IMAGE:-howdah-dev-php8.3}"
FEATURE="${FEATURE:-php8}"

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "missing image $IMAGE (see lab/images/dev.Dockerfile)"; exit 1; }

# Optional: HOWDAH_TARGET_CACHE=/some/dir keeps the in-container cargo target
# between runs (dev speed-up only; CI leaves it unset).
CACHE=""
if [ -n "${HOWDAH_TARGET_CACHE:-}" ]; then
  mkdir -p "$HOWDAH_TARGET_CACHE"
  CACHE="-v $HOWDAH_TARGET_CACHE:/tmp/t"
fi

# shellcheck disable=SC2086
exec docker run --rm $CACHE -v "$ROOT":/src:ro "$IMAGE" sh /src/lab/integration/jit_container.sh "$FEATURE"
