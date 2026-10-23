#!/bin/sh
# Howdah Layer-2 input-inspection integration test (host driver).
#
# Builds the extension into a howdah-dev-php<ver> image and runs
# inspect_container.sh: SQLi / traversal / cmdi values in GET and POST must
# produce a JSON event with "action":"log" and the matching rule (and NOT
# block, NOT echo the payload bytes); a benign request produces no inspect
# event. Layer 2 is log-only by default, best-effort signature matching.
#
# Usage (repo root):
#   lab/integration/inspect.sh                              # PHP 8.3
#   IMAGE=howdah-dev-php7.4 FEATURE=php7 lab/integration/inspect.sh
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${IMAGE:-howdah-dev-php8.3}"
FEATURE="${FEATURE:-php8}"

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "missing image $IMAGE (see lab/images/dev.Dockerfile)"; exit 1; }

exec docker run --rm -v "$ROOT":/src:ro "$IMAGE" sh /src/lab/integration/inspect_container.sh "$FEATURE"
