#!/bin/sh
# Refusal-path lab (host driver): does a Howdah refusal reach the client with
# its body, and does the PHP worker survive it?
#
# Background: before 1.4.1 a Layer 1 refusal `zend_bailout()`ed from inside
# `php_request_startup()`; php-fpm answered with a forced close and exit 70
# (the worker was respawned per blocked request, nginx logged `readv() failed
# (104: Connection reset by peer)`, the body was lost). The matrix never saw it
# because it drives php-fpm with cgi-fcgi. This lab puts a real nginx in front
# of php-fpm (a sidecar container sharing the php-fpm container's network
# namespace) and also runs Apache mod_php prefork, and checks:
#
#   * HTTP 403/413 with the "Howdah blocked" body and request id,
#   * the script's side effect (a marker file) did NOT happen,
#   * the single php-fpm worker has the same pid before and after,
#   * no "exited with code" / "exited on signal" in the php-fpm log,
#   * no "readv() failed" / "Connection reset" in nginx's error log,
#   * `tools/howdah-check web` through nginx reports a Howdah refusal,
#
# for: the Layer 1 multipart flood, a Layer 1 input-shape rule, an armed Layer 2
# class (GET, POST, cookie, traversal) refusing BEFORE the script, the Layer 4
# main-script deny_exec_dirs refusal, and an armed Layer 3 sink (which must not
# refuse, and must leave the worker alive).
#
# Usage (repo root):
#   lab/integration/refusal.sh                 # 5.6 7.4 8.3, fpm+nginx and apache
#   lab/integration/refusal.sh 8.3             # one minor
#   SAPIS=fpm lab/integration/refusal.sh 7.4   # fpm+nginx only
#
# Needs the howdah-dev-php<minor> (and howdah-dev-apache-php<minor>) images from
# lab/images/dev.Dockerfile and the nginx:1.27-alpine image. Results: one TSV
# row per check, printed at the end and kept in lab/integration/.refusal-out/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.6 7.4 8.3}"
SAPIS="${SAPIS:-fpm apache}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
OD="$ROOT/lab/integration/.refusal-out"
mkdir -p "$OD"; chmod 777 "$OD"
ALL="$OD/results.tsv"; : > "$ALL"

feature() {
  case "$1" in
    5.*) echo php5 ;;
    7.*) echo php7 ;;
    8.*) echo php8 ;;
    *) echo php8 ;;
  esac
}

cleanup_fpm() {
  docker rm -f "howdah-refusal-nginx-$1" "howdah-refusal-$1" >/dev/null 2>&1 || true
}

for V in $VERSIONS; do
  F=$(feature "$V")
  VOUT="$OD/$V"; mkdir -p "$VOUT"; chmod 777 "$VOUT"
  : > "$VOUT/nginx.err"; : > "$VOUT/fpm.err"; chmod 666 "$VOUT/nginx.err" "$VOUT/fpm.err"

  if echo "$SAPIS" | tr ' ' '\n' | grep -qx fpm; then
    DEV="howdah-dev-php$V"
    if ! docker image inspect "$DEV" >/dev/null 2>&1; then
      printf '%s\tfpm-nginx\tall\tSKIP\tno %s image\n' "$V" "$DEV" >> "$ALL"
    else
      echo "== $V: php-fpm behind nginx ($DEV + $NGINX_IMAGE) =="
      cleanup_fpm "$V"
      # The php-fpm container: a build+target cache volume so re-runs are quick.
      docker run -d --name "howdah-refusal-$V" \
        -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-refusal-target-$V":/tmp/t \
        "$DEV" sleep infinity >/dev/null
      # nginx shares its network namespace: 127.0.0.1:9000 is that php-fpm.
      docker run -d --name "howdah-refusal-nginx-$V" --network "container:howdah-refusal-$V" \
        -v "$VOUT":/out -v "$ROOT/lab/integration/refusal_nginx.conf":/etc/nginx/nginx.conf:ro \
        "$NGINX_IMAGE" >/dev/null
      docker exec -e CARGO_TARGET_DIR=/tmp/t "howdah-refusal-$V" \
        sh /src/lab/integration/refusal_container.sh "$F" /out/rows.tsv \
        || printf '%s\tfpm-nginx\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
      cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
      cleanup_fpm "$V"
    fi
  fi

  if echo "$SAPIS" | tr ' ' '\n' | grep -qx apache; then
    APDEV="howdah-dev-apache-php$V"
    if ! docker image inspect "$APDEV" >/dev/null 2>&1; then
      printf '%s\tapache\tall\tSKIP\tno %s image\n' "$V" "$APDEV" >> "$ALL"
    else
      echo "== $V: Apache mod_php prefork ($APDEV) =="
      docker run --rm -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-refusal-target-ap-$V":/tmp/t \
        -e CARGO_TARGET_DIR=/tmp/t "$APDEV" \
        sh /src/lab/integration/refusal_apache_container.sh "$F" /out/rows-ap.tsv \
        || printf '%s\tapache\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
      cat "$VOUT/rows-ap.tsv" >> "$ALL" 2>/dev/null || true
    fi
  fi
done

echo
echo "=================== refusal-path results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   SKIP: %d\n", tot, c["PASS"], c["FAIL"], c["SKIP"]}' "$ALL"
echo "php-fpm / nginx logs per minor: $OD/<minor>/fpm.err, nginx.err"
if grep -q "	FAIL	" "$ALL"; then exit 1; fi
