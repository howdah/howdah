#!/bin/sh
# Log-contract integration test (host driver): [log] path, destination =
# syslog / stderr, the [log] exec hook and the schema-2 line, against the real
# extension under `php -S` and php-fpm (log_contract_container.sh), then
# under Apache mod_php prefork (log_contract_apache_container.sh, in a dev
# image built FROM php:<ver>-apache as matrix.sh does).
#
# Usage (repo root):
#   lab/integration/log_contract.sh                                   # PHP 7.4
#   IMAGE=howdah-dev-php8.3 FEATURE=php8 BASE=lab-php-8.3 lab/integration/log_contract.sh
#   APACHE=0 lab/integration/log_contract.sh                          # skip the Apache phase
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${IMAGE:-howdah-dev-php7.4}"
FEATURE="${FEATURE:-php7}"
BASE="${BASE:-lab-php-7.4}"
APACHE="${APACHE:-1}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "== building $IMAGE from dev.Dockerfile (BASE=$BASE) =="
  docker build -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=$BASE" -t "$IMAGE" "$ROOT"
fi

docker run --rm -v "$ROOT":/src:ro "$IMAGE" sh /src/lab/integration/log_contract_container.sh "$FEATURE"

[ "$APACHE" = 1 ] || { echo "== apache phase skipped (APACHE=0) =="; exit 0; }
V=${IMAGE#howdah-dev-php}
APDEV="howdah-dev-apache-php$V"
APBASE="php:$V-apache"
if ! docker image inspect "$APDEV" >/dev/null 2>&1; then
  if docker image inspect "$APBASE" >/dev/null 2>&1 || docker pull "$APBASE" >/dev/null 2>&1; then
    echo "== building $APDEV (BASE=$APBASE) =="
    docker build -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=$APBASE" -t "$APDEV" "$ROOT"
  else
    echo "== NOT RUN: apache phase (no $APBASE image) =="
    exit 0
  fi
fi
docker run --rm -v "$ROOT":/src:ro "$APDEV" sh /src/lab/integration/log_contract_apache_container.sh "$FEATURE"
