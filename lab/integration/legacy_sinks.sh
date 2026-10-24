#!/bin/sh
# Layer-3 legacy-era sink test (host driver): mail, preg_eval (/e),
# create_function, string assert, dangerous string callbacks, XML external
# entities, and curl TLS verification. Builds the extension into a
# howdah-dev-php<ver> image and runs legacy_sinks_container.sh.
#
# Usage (repo root):
#   lab/integration/legacy_sinks.sh                                   # PHP 8.3
#   IMAGE=howdah-dev-php7.4 FEATURE=php7 lab/integration/legacy_sinks.sh
#   IMAGE=howdah-dev-php5.6 FEATURE=php5 lab/integration/legacy_sinks.sh
#   IMAGE=howdah-dev-php5.4 FEATURE=php5 lab/integration/legacy_sinks.sh
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${IMAGE:-howdah-dev-php8.3}"
FEATURE="${FEATURE:-php8}"

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "missing image $IMAGE (see lab/images/dev.Dockerfile)"; exit 1; }

CACHE=""
if [ -n "${HOWDAH_TARGET_CACHE:-}" ]; then
  mkdir -p "$HOWDAH_TARGET_CACHE"
  CACHE="-v $HOWDAH_TARGET_CACHE:/tmp/t"
fi

# shellcheck disable=SC2086
exec docker run --rm $CACHE -v "$ROOT":/src:ro "$IMAGE" sh /src/lab/integration/legacy_sinks_container.sh "$FEATURE"
