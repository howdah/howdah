#!/bin/sh
# Howdah `howdah-check detect` integration test (host driver).
#
# Builds howdah.so for PHP 7.3 (howdah-dev-php7.3), then runs detect inside a
# lab-php-7.3 container that ALSO has a real PHP 7.4 tree side by side
# (copied from lab-php-7.4, same Debian bullseye libs). See
# detect_container.sh for the fixture and assertions.
#
# Usage (repo root):  lab/integration/detect.sh
#   HC=/src/tools/does-not-exist lab/integration/detect.sh   # RED
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DEV="${DEV:-howdah-dev-php7.3}"
WORK=$(mktemp -d)
CID=""
cleanup() { [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1 || true; docker run --rm -v "$WORK":/w alpine:3 sh -c "rm -rf /w/*" >/dev/null 2>&1 || true; rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

for img in "$DEV" lab-php-7.3 lab-php-7.4; do
  docker image inspect "$img" >/dev/null 2>&1 || {
    echo "missing image $img (build lab/images/*.Dockerfile / dev.Dockerfile)"; exit 1; }
done

echo "== building howdah.so for PHP 7.3 =="
mkdir -p "$WORK/h" "$WORK/php74"
docker run --rm -v "$ROOT":/src:ro -v "$WORK/h":/out -e CARGO_TARGET_DIR=/tmp/t "$DEV" \
  sh -c 'cd /src && cargo build -p howdah-ext --features php7 --release 2>&1 | tail -2 && cp /tmp/t/release/libhowdah_ext.so /out/howdah.so && chmod 755 /out && chmod 644 /out/howdah.so'

echo "== extracting PHP 7.4 tree =="
CID=$(docker create lab-php-7.4)
docker cp "$CID:/usr/local/." "$WORK/php74"
# 7.4 needs libonig (mbstring), which the 7.3 image lacks: ship it with the tree
mkdir -p "$WORK/php74/libx"
docker cp -L "$CID:/usr/lib/x86_64-linux-gnu/libonig.so.5" "$WORK/php74/libx/libonig.so.5"
docker rm -f "$CID" >/dev/null; CID=""

echo "== running detect in lab-php-7.3 + /opt/php74 =="
# The container needs write access only to set up its own fixture (tmpfs-like
# container layer); /src and the howdah.so are read-only.
docker run --rm \
  -v "$ROOT":/src:ro -v "$WORK/h":/h:ro -v "$WORK/php74":/opt/php74-ro:ro \
  -e HC="${HC:-/src/tools/howdah-check}" \
  lab-php-7.3 sh -c 'cp -a /opt/php74-ro /opt/php74 && sh /src/lab/integration/detect_container.sh'
