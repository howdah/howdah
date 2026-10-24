#!/bin/sh
# Howdah Layer-3 sink-hardening integration test (host driver).
#
# Builds the extension into a howdah-dev-php<ver> image and runs
# sinks_container.sh: command_exec / unserialize sinks must log (detect),
# stay silent when allowlisted or off, never arm from the global block mode,
# and neutralize (return false, script continues) when armed with block.
#
# Usage (repo root):
#   lab/integration/sinks.sh                              # PHP 8.3
#   IMAGE=howdah-dev-php7.4 FEATURE=php7 lab/integration/sinks.sh
#   IMAGE=howdah-dev-php5.6 FEATURE=php5 lab/integration/sinks.sh
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${IMAGE:-howdah-dev-php8.3}"
FEATURE="${FEATURE:-php8}"

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "missing image $IMAGE (see lab/images/dev.Dockerfile)"; exit 1; }

exec docker run --rm -v "$ROOT":/src:ro "$IMAGE" sh /src/lab/integration/sinks_container.sh "$FEATURE"
