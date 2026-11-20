#!/bin/sh
# FPM status-page HTML injection lab (host driver), CVE-2026-129292, Layer 2
# `status_injection`. Per PHP minor: real nginx -> php-fpm with pm.status_path
# enabled (sidecar sharing the php-fpm container's network namespace, as
# cgi_arg.sh does), then lab/integration/status_injection_container.sh:
#   * a request whose Basic-auth user / method carries HTML metacharacters is
#     LOGGED as status_injection (reason names the FIELD, never the value) and
#     the worker serves it normally (detect is the default);
#   * the planted value is observed UNESCAPED in php-fpm's own status HTML
#     (a harmless <svg> string) -- confirming the vector is real;
#   * benign users/methods/paths: ZERO status_injection events;
#   * block / off knobs. In block the request is refused (403), but php-fpm
#     writes the scoreboard BEFORE any extension runs, so the entry is already
#     planted: blocking cannot un-plant it, which is why detect is the default.
#
# Usage (repo root):  lab/integration/status_injection.sh 5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6
# Results: TSV rows printed at the end, kept in lab/integration/.status_injection-out/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.6 7.4 8.3}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
OD="$ROOT/lab/integration/.status_injection-out"
mkdir -p "$OD"; chmod 777 "$OD"
ALL="$OD/results.tsv"; : > "$ALL"

feature() {
  case "$1" in
    5.*) echo php5 ;;
    7.*) echo php7 ;;
    *) echo php8 ;;
  esac
}
cleanup() { docker rm -f "howdah-statusinj-nginx-$1" "howdah-statusinj-$1" >/dev/null 2>&1 || true; }

for V in $VERSIONS; do
  F=$(feature "$V")
  VOUT="$OD/$V"; mkdir -p "$VOUT"; chmod 777 "$VOUT"
  : > "$VOUT/nginx.err"; : > "$VOUT/fpm.err"; chmod 666 "$VOUT/nginx.err" "$VOUT/fpm.err"
  DEV="howdah-dev-php$V"
  if ! docker image inspect "$DEV" >/dev/null 2>&1; then
    printf '%s\tfpm-nginx\tall\tSKIP\tno %s image\n' "$V" "$DEV" >> "$ALL"
    continue
  fi
  echo "== $V: php-fpm status page behind nginx ($DEV + $NGINX_IMAGE) =="
  cleanup "$V"
  docker run -d --name "howdah-statusinj-$V" \
    -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-statusinj-target-$V":/tmp/t \
    "$DEV" sleep infinity >/dev/null
  docker run -d --name "howdah-statusinj-nginx-$V" --network "container:howdah-statusinj-$V" \
    -v "$VOUT":/out -v "$ROOT/lab/integration/status_injection_nginx.conf":/etc/nginx/nginx.conf:ro \
    "$NGINX_IMAGE" >/dev/null
  docker exec -e CARGO_TARGET_DIR=/tmp/t "howdah-statusinj-$V" \
    sh /src/lab/integration/status_injection_container.sh "$F" /out/rows.tsv \
    || printf '%s\tfpm-nginx\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
  cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
  cleanup "$V"
done

echo
echo "=================== FPM status-page injection results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   SKIP: %d\n", tot, c["PASS"], c["FAIL"], c["SKIP"]}' "$ALL"
if grep -q "	FAIL	" "$ALL"; then exit 1; fi
