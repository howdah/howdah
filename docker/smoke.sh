#!/bin/sh
# Smoke test for a Howdah runtime image built from docker/Dockerfile.
#
#   docker/smoke.sh <image> [platform]      e.g. docker/smoke.sh howdah:1.4.0-php8.3
#
# Runs against the image as built (the released, signed howdah.so it carries;
# nothing is compiled):
#   1. `php -m` and `php-fpm -m` list howdah; `php --ri howdah` says detect.
#   2. The lab self-test scenario, lab/integration/selftest_container.sh, on the
#      PHP CLI server inside the image (PREINSTALLED=1), in detect and block mode.
#   3. The same `howdah-check web` self-test through nginx -> the image's own
#      php-fpm (its default CMD and pool config, shipped howdah.ini untouched;
#      one extra ini raises PHP's own part caps so Howdah's limit is the one
#      reached). Asserts: marker flagged with HTTP 200 and its self_test event
#      in the php-fpm container's log (Howdah logs to stderr when howdah.log is
#      empty), the over-limit request refused 403/413 with a max_parts block
#      event, a normal form answered 200 with no self_test event. FPM_BLOCK
#      (default bailout) pins how the refusal behaves today: a worker exit
#      with code 70 and a 403 whose body may be lost (see the comment at that
#      check and docs/install-docker.md, "Known limitations").
# [platform] (e.g. linux/arm64) runs every container under that platform.
# Exit 0 only if every step passed. Needs docker and network access for the
# nginx image (NGINX_IMAGE, default nginx:1.27-alpine).
set -eu

IMAGE=${1:?usage: docker/smoke.sh <image> [platform]}
PLATFORM=${2:-}
NGINX=${NGINX_IMAGE:-nginx:1.27-alpine}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TAG=howdah-smoke-$$
W=$(mktemp -d)
P=""; [ -n "$PLATFORM" ] && P="--platform=$PLATFORM"

cleanup() {
  docker rm -f "$TAG-fpm" "$TAG-web" >/dev/null 2>&1 || true
  docker network rm "$TAG" >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
  echo "FAIL: $*"
  [ -f "$W/web.out" ] && { echo "--- howdah-check web ---"; cat "$W/web.out"; }
  echo "--- php-fpm log ---"; docker logs "$TAG-fpm" 2>&1 | tail -20 || true
  exit 1
}

echo "== 1. module loads ($IMAGE${PLATFORM:+, $PLATFORM}) =="
# shellcheck disable=SC2086
docker run --rm $P "$IMAGE" sh -ec '
  php -m | grep -qx howdah
  php-fpm -m | grep -qx howdah
  php --ri howdah | grep -q "^Mode => detect"
  echo "PHP $(php -r "echo PHP_VERSION;") $(php -r "echo PHP_ZTS ? \"ZTS\" : \"NTS\";"), howdah $(php -r "echo phpversion(\"howdah\");"): php -m, php-fpm -m list howdah; Mode => detect"
' || fail "howdah is not loaded in $IMAGE"

echo "== 2. lab self-test scenario on the CLI server (PREINSTALLED=1) =="
# shellcheck disable=SC2086
docker run --rm $P -v "$ROOT":/src:ro -e PREINSTALLED=1 -e HC=/usr/local/bin/howdah-check \
  "$IMAGE" sh /src/lab/integration/selftest_container.sh \
  || fail "lab/integration/selftest_container.sh failed in $IMAGE"

echo "== 3. howdah-check web through nginx -> php-fpm =="
mkdir -p "$W/app"
printf '<?php\n$n = count($_FILES) + count($_POST);\necho "OK n=$n\\n";\n' > "$W/app/index.php"
printf 'post_max_size = 16M\nmax_input_vars = 100000\nmax_file_uploads = 100000\n' > "$W/zz-smoke.ini"
cat > "$W/default.conf" <<EOF
server {
  listen 80;
  root /var/www/html;
  client_max_body_size 16m;
  location / {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /var/www/html/index.php;
    fastcgi_pass $TAG-fpm:9000;
  }
}
EOF
chmod 755 "$W" "$W/app"; chmod 644 "$W/app/index.php" "$W/zz-smoke.ini" "$W/default.conf"

docker network create "$TAG" >/dev/null
# shellcheck disable=SC2086
docker run -d $P --name "$TAG-fpm" --network "$TAG" \
  -v "$W/app":/var/www/html:ro \
  -v "$W/zz-smoke.ini":/usr/local/etc/php/conf.d/zz-smoke.ini:ro \
  "$IMAGE" >/dev/null
docker run -d --name "$TAG-web" --network "$TAG" \
  -v "$W/default.conf":/etc/nginx/conf.d/default.conf:ro "$NGINX" >/dev/null

# wait for nginx -> fpm to answer
i=0
# shellcheck disable=SC2086
until docker run --rm $P --network "$TAG" "$IMAGE" curl -fsS -o /dev/null "http://$TAG-web/" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -gt 30 ] && fail "nginx -> php-fpm never answered"; sleep 1
done

# howdah-check's own exit status is not used: through nginx the 403 body is
# lost (see below), so it cannot tell who refused the request. The assertions
# are the HTTP codes it prints plus the events in the php-fpm log.
# shellcheck disable=SC2086
docker run --rm $P --network "$TAG" "$IMAGE" howdah-check web "http://$TAG-web/" > "$W/web.out" 2>&1 || true
cat "$W/web.out"
grep -q '^selftest marker: *flagged *(HTTP 200, request id ' "$W/web.out" || fail "marker not flagged with HTTP 200"
grep -q '^over-limit parts: *\(BLOCKED\|refused\) *(HTTP \(403\|413\)' "$W/web.out" || fail "over-limit request not refused with 403/413"
mid=$(sed -n 's/^selftest marker:.*request id \([0-9a-zA-Z_-]*\).*/\1/p' "$W/web.out")
[ -n "$mid" ] || fail "no marker request id"
sleep 1
docker logs "$TAG-fpm" > "$W/fpm.log" 2>&1
grep "$mid" "$W/fpm.log" | grep '"rule":"self_test"' | grep -q '"action":"log"' \
  || fail "no self_test action=log event for $mid in the php-fpm log"
grep '"rule":"max_parts"' "$W/fpm.log" | grep -q '"action":"block"' \
  || fail "no max_parts block event in the php-fpm log"
# CURRENT BEHAVIOUR, asserted on purpose (FPM_BLOCK=bailout, the default).
# The Layer-1 refusal calls zend_bailout from the multipart callback, so
# php_request_startup fails and php-fpm ends the worker ("child N exited with
# code 70") before the request body is read. The unread body resets the
# FastCGI socket; nginx logs "readv() failed (104: Connection reset by peer)
# while reading upstream" and, depending on whether it read the response
# before the reset, sends the 403 with an empty body (no request id) or with
# the Howdah body. Both happened in the 1.4.0 runs, so only the 403 and the
# worker exit are asserted here; which body arrived is printed. The fix is its
# own gap-analysis item (FPM refusal path). When it lands, run with
# FPM_BLOCK=clean (and make that the default): the 403 must then carry the
# Howdah body every time and no worker may exit.
case "${FPM_BLOCK:-bailout}" in
  bailout)
    grep -q 'exited with code 70' "$W/fpm.log" \
      || fail "FPM_BLOCK=bailout: expected a php-fpm worker exit with code 70; if the refusal path was fixed, run with FPM_BLOCK=clean"
    if grep -q '^over-limit parts: *BLOCKED' "$W/web.out"; then body="the Howdah body arrived this time"
    else body="the 403 body was empty (connection reset)"; fi
    echo "[fpm] current behaviour: $(grep -c 'exited with code 70' "$W/fpm.log") worker exit(s) with code 70; $body" ;;
  clean)
    grep -q '^over-limit parts: *BLOCKED *(HTTP \(403\|413\), request id ' "$W/web.out" \
      || fail "FPM_BLOCK=clean: the 403 did not carry the Howdah body"
    ! grep -q 'exited with code 70' "$W/fpm.log" || fail "FPM_BLOCK=clean: a php-fpm worker exited with code 70" ;;
  *) fail "FPM_BLOCK must be bailout or clean" ;;
esac

# ordinary traffic: 200 and no self_test event
before=$(grep -c self_test "$W/fpm.log" || true)
# shellcheck disable=SC2086
code=$(docker run --rm $P --network "$TAG" "$IMAGE" curl -s -o /dev/null -w '%{http_code}' \
  -F username=alice "http://$TAG-web/")
[ "$code" = 200 ] || fail "a normal form got HTTP $code"
sleep 1
after=$(docker logs "$TAG-fpm" 2>&1 | grep -c self_test || true)
[ "$before" = "$after" ] || fail "a normal form produced a self_test event"
echo "[fpm] OK (marker $mid flagged 200 and logged; over-limit refused 403 with a max_parts block event; normal form clean)"

echo "PASS $IMAGE${PLATFORM:+ ($PLATFORM)}"
