#!/bin/sh
# fcgi_drain lab (host driver; CVE-2026-129289 mitigation, mechanism level):
# Howdah drains the request body PHP leaves unread (php://input opened, not read)
# at teardown, removing the leftover-body precondition on a REUSED FastCGI
# connection. php-fpm behind nginx with fastcgi_keep_conn + upstream keepalive and
# a single worker, so request N+1 rides the connection request N left.
# Drain ON: the next request is received correctly. Drain OFF
# (drain_unread_body = false): leftover benign padding bytes desync the connection.
# Benign padding only; no crafted FastCGI framing and no injected directives.
#
# Usage (repo root):
#   lab/integration/fcgi_drain.sh                # 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6
#   lab/integration/fcgi_drain.sh 8.3            # one minor
#
# Needs the howdah-dev-php<minor> images and nginx:1.27-alpine. Results: TSV rows
# printed at the end, kept in lab/integration/.fcgi-drain-out/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
OD="$ROOT/lab/integration/.fcgi-drain-out"
mkdir -p "$OD"; chmod 777 "$OD"
ALL="$OD/results.tsv"; : > "$ALL"

feature() { case "$1" in 5.*) echo php5 ;; 7.*) echo php7 ;; *) echo php8 ;; esac; }
cleanup() { docker rm -f "howdah-fd-nginx-$1" "howdah-fd-$1" >/dev/null 2>&1 || true; }

for V in $VERSIONS; do
  F=$(feature "$V")
  VOUT="$OD/$V"; mkdir -p "$VOUT"; chmod 777 "$VOUT"
  : > "$VOUT/nginx.err"; : > "$VOUT/fpm.err"; chmod 666 "$VOUT/nginx.err" "$VOUT/fpm.err"
  DEV="howdah-dev-php$V"
  if ! docker image inspect "$DEV" >/dev/null 2>&1; then
    printf '%s\tfpm-nginx\tall\tNOT-RUN\tno %s image\n' "$V" "$DEV" >> "$ALL"; continue
  fi
  echo "== $V: php-fpm behind nginx ($DEV + $NGINX_IMAGE) =="
  cleanup "$V"
  docker run -d --name "howdah-fd-$V" \
    -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-fd-target-$V":/tmp/t \
    "$DEV" sleep infinity >/dev/null
  docker run -d --name "howdah-fd-nginx-$V" --network "container:howdah-fd-$V" \
    -v "$VOUT":/out -v "$ROOT/lab/integration/fcgi_drain_nginx.conf":/etc/nginx/nginx.conf:ro \
    "$NGINX_IMAGE" >/dev/null
  docker exec -e CARGO_TARGET_DIR=/tmp/t "howdah-fd-$V" \
    sh /src/lab/integration/fcgi_drain_container.sh "$F" /out/rows.tsv \
    || printf '%s\tfpm-nginx\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
  cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
  cleanup "$V"
done

echo
echo "=================== fcgi-drain results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   NOT-RUN: %d\n", tot, c["PASS"], c["FAIL"], c["NOT-RUN"]}' "$ALL"
if grep -q "	FAIL	" "$ALL"; then exit 1; fi
