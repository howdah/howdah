#!/bin/sh
# Log-contract integration test (host driver): [log] path, destination =
# syslog / stderr, the [log] exec hook and the schema-2 line, against the real
# extension under `php -S`. See log_contract_container.sh for the assertions.
#
# Usage (repo root):
#   lab/integration/log_contract.sh                                   # PHP 7.4
#   IMAGE=howdah-dev-php8.3 FEATURE=php8 BASE=lab-php-8.3 lab/integration/log_contract.sh
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${IMAGE:-howdah-dev-php7.4}"
FEATURE="${FEATURE:-php7}"
BASE="${BASE:-lab-php-7.4}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "== building $IMAGE from dev.Dockerfile (BASE=$BASE) =="
  docker build -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=$BASE" -t "$IMAGE" "$ROOT"
fi

exec docker run --rm -v "$ROOT":/src:ro "$IMAGE" sh /src/lab/integration/log_contract_container.sh "$FEATURE"
