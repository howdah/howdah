#!/bin/sh
# LiteSpeed LSAPI smoke test: the released, signed howdah.so loaded by lsphp
# under OpenLiteSpeed (litespeedtech/openlitespeed, Ubuntu with LiteSpeed's own
# lsphp packages), driven over HTTP with `howdah-check web`.
#
#   lab/integration/lsapi.sh                 # PHP 8.3, release 1.4.0
#   PHP_MINOR=8.4 HOWDAH_VERSION=1.4.0 lab/integration/lsapi.sh
#   LOAD_EXT=0 lab/integration/lsapi.sh      # RED: no extension -> not flagged
#
# 1. docker/fetch.sh (in alpine) downloads the release tarball for the minor
#    and checks it against the committed key, as the Docker image build does.
# 2. The .so goes into lsphp's extension_dir and howdah.ini into the directory
#    lsphp scans (both read from the image, not assumed); one more ini raises
#    PHP's own part caps so Howdah's limit is the one reached, and points
#    howdah.log at a file.
# 3. Asserts: the test page runs under the `litespeed` SAPI with howdah loaded;
#    the self-test marker is flagged (HTTP 200) with a self_test action=log
#    event; the over-limit request is refused 403/413 with a max_parts block
#    event; a normal form gets 200 and no self_test event.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
V=${HOWDAH_VERSION:-1.4.0}
MINOR=${PHP_MINOR:-8.3}
XY=$(printf '%s' "$MINOR" | tr -d .)
OLS=${OLS_IMAGE:-litespeedtech/openlitespeed:1.9.3-lsphp$XY}
LOAD_EXT=${LOAD_EXT:-1}
TAG=howdah-lsapi-$$
W=$(mktemp -d)
cleanup() { docker rm -f "$TAG" >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT INT TERM
fail() {
  echo "FAIL: $*"
  [ -f "$W/web.out" ] && { echo "--- howdah-check web ---"; cat "$W/web.out"; }
  docker exec "$TAG" sh -c 'tail -5 /tmp/howdah-events.log; tail -15 /usr/local/lsws/logs/error.log /usr/local/lsws/logs/stderr.log' 2>/dev/null || true
  exit 1
}

echo "== fetch + verify howdah $V for PHP $MINOR (docker/fetch.sh) =="
# The container writes nothing to the host: the verified tree comes back as a tar on stdout.
docker run --rm -v "$ROOT/docker/fetch.sh":/fetch.sh:ro \
  -v "$ROOT/packaging/howdah-release-signing.asc":/key.asc:ro \
  -e HOWDAH_VERSION="$V" -e PHP_MINOR="$MINOR" -e TARGETARCH=amd64 -e HOWDAH_KEY=/key.asc \
  alpine:3.21 sh -c 'apk add --no-cache curl gpg gpgv tar >/dev/null 2>&1 && sh /fetch.sh >&2 && tar -C / -cf - howdah' \
  > "$W/howdah.tar" || fail "fetch.sh could not fetch and verify howdah $V for PHP $MINOR"
tar -C "$W" -xf "$W/howdah.tar"
SO=$(find "$W/howdah" -name howdah.so | head -1)
[ -n "$SO" ] || fail "fetch.sh produced no howdah.so"

printf '<?php\n$n = count($_FILES) + count($_POST);\necho "OK n=$n sapi=" . php_sapi_name() . " howdah=" . (extension_loaded("howdah") ? "loaded" : "absent") . "\\n";\n' > "$W/howdah.php"
printf 'post_max_size = 16M\nmax_input_vars = 100000\nmax_file_uploads = 100000\nhowdah.log = /tmp/howdah-events.log\n' > "$W/zz-howdah-lab.ini"
chmod -R a+rX "$W"

echo "== start $OLS =="
docker run -d --name "$TAG" -v "$W":/w:ro -v "$ROOT/tools/howdah-check":/usr/local/bin/howdah-check:ro "$OLS" >/dev/null
# lsphp's real extension_dir and scan dir, from its own CLI (same package, same ini)
LSPHP=$(docker exec "$TAG" sh -c 'ls -d /usr/local/lsws/lsphp[0-9]* | head -1')
EXT=$(docker exec "$TAG" "$LSPHP/bin/php" -r 'echo ini_get("extension_dir");')
SCAN=$(docker exec "$TAG" "$LSPHP/bin/php" -r 'echo PHP_CONFIG_FILE_SCAN_DIR;')
echo "lsphp: $LSPHP  extension_dir: $EXT  scan dir: $SCAN"
docker exec "$TAG" sh -c "cp /w/zz-howdah-lab.ini '$SCAN/zz-howdah-lab.ini' && cp /w/howdah.php /usr/local/lsws/Example/html/howdah.php && : > /tmp/howdah-events.log && chmod 666 /tmp/howdah-events.log"
if [ "$LOAD_EXT" = 1 ]; then
  docker cp "$SO" "$TAG:$EXT/howdah.so"
  docker cp "$W/howdah/usr/local/etc/php/conf.d/docker-php-ext-howdah.ini" "$TAG:$SCAN/40-howdah.ini"
  docker exec "$TAG" "$LSPHP/bin/php" -m | grep -qx howdah || fail "lsphp CLI does not load howdah"
fi
# restart so lsphp children start with the new ini
docker exec "$TAG" /usr/local/lsws/bin/lswsctrl restart >/dev/null
URL=http://127.0.0.1:8088/howdah.php
i=0
until docker exec "$TAG" curl -fsS "$URL" > "$W/get.out" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -gt 30 ] && fail "OpenLiteSpeed never served $URL"; sleep 1
done
cat "$W/get.out"
grep -q 'sapi=litespeed' "$W/get.out" || fail "the page is not running under the litespeed SAPI"
if [ "$LOAD_EXT" = 1 ]; then grep -q 'howdah=loaded' "$W/get.out" || fail "howdah is not loaded in lsphp"; fi

echo "== howdah-check web $URL =="
docker exec "$TAG" sh /usr/local/bin/howdah-check web "$URL" > "$W/web.out" 2>&1 || true
cat "$W/web.out"
docker exec "$TAG" cat /tmp/howdah-events.log > "$W/events.log"
grep -q '^selftest marker: *flagged *(HTTP 200, request id ' "$W/web.out" || fail "marker not flagged with HTTP 200"
mid=$(sed -n 's/^selftest marker:.*request id \([0-9a-zA-Z_-]*\).*/\1/p' "$W/web.out")
grep "$mid" "$W/events.log" | grep '"rule":"self_test"' | grep -q '"action":"log"' || fail "no self_test event for $mid"
grep -q '^over-limit parts: *\(BLOCKED\|refused\) *(HTTP \(403\|413\)' "$W/web.out" || fail "over-limit request not refused 403/413"
grep '"rule":"max_parts"' "$W/events.log" | grep -q '"action":"block"' || fail "no max_parts block event"
if grep -q '^over-limit parts: *BLOCKED' "$W/web.out"; then body="with the Howdah body (request id)"; else body="WITHOUT the Howdah body"; fi

before=$(grep -c self_test "$W/events.log" || true)
code=$(docker exec "$TAG" curl -s -o /dev/null -w '%{http_code}' -F username=alice "$URL")
[ "$code" = 200 ] || fail "a normal form got HTTP $code"
after=$(docker exec "$TAG" grep -c self_test /tmp/howdah-events.log || true)
[ "$before" = "$after" ] || fail "a normal form produced a self_test event"
php_v=$(docker exec "$TAG" "$LSPHP/bin/php" -r 'echo PHP_VERSION;')
echo "PASS lsapi: OpenLiteSpeed $(docker exec "$TAG" cat /usr/local/lsws/VERSION 2>/dev/null) + lsphp $php_v; marker flagged 200, over-limit refused $body, normal form clean"
