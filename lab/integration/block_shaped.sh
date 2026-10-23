#!/bin/sh
# Howdah block-shaped integration test (host driver).
#
# Builds the extension into the PHP 7.3 lab dev image and runs the in-container
# assertions (see block_shaped_container.sh): a shaped PHP2Shell-style upload
# (many empty file parts) must be refused with HTTP 413/403 + a request id and a
# matching JSON block line in the log; a normal small form must get 200.
#
# Usage (from the repo root):
#   lab/integration/block_shaped.sh           # PHP 7.3 (the required target)
#   LOAD_EXT=0 lab/integration/block_shaped.sh # RED: no extension -> shaped 200
#   IMAGE=howdah-dev-php8.4 FEATURE=php8 lab/integration/block_shaped.sh
#
# The dev image (reused from the howdah-sys/milestone-0 pattern) provides Rust +
# that PHP generation's headers + the php CLI, so the whole build+run happens in
# one container.
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
  "$IMAGE" sh /src/lab/integration/block_shaped_container.sh "$FEATURE"
