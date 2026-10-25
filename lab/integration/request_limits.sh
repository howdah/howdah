#!/bin/sh
# Request-limits lab (host driver; §4.1-4.5): the read_post byte-stream scanner
# must leave benign uploads alone and catch the request-parsing shapes that are
# Howdah's own byte-stream limits (gap A exact per-part headers, gap C nesting),
# all WITHOUT a vulnerable PHP. Runs php-fpm behind a real nginx (the front end
# §5.2 requires; cgi-fcgi would hide fpm's behavior).
#
# The "stops a real PHP out-of-memory on a vulnerable build" evidence (§5.2) and
# its trigger fixtures are owner-supplied (§5.3, gitignored private/); this lab
# records that row as NOT-RUN and never authors a trigger.
#
# Usage (repo root):
#   lab/integration/request_limits.sh            # 5.6 7.4 8.3
#   lab/integration/request_limits.sh 8.3        # one minor
#
# Needs the howdah-dev-php<minor> images and nginx:1.27-alpine. Results: one TSV
# row per check, printed at the end, kept in lab/integration/.request-limits-out/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.6 7.4 8.3}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
OD="$ROOT/lab/integration/.request-limits-out"
mkdir -p "$OD"; chmod 777 "$OD"
ALL="$OD/results.tsv"; : > "$ALL"

feature() { case "$1" in 5.*) echo php5 ;; 7.*) echo php7 ;; *) echo php8 ;; esac; }
cleanup() { docker rm -f "howdah-rl-nginx-$1" "howdah-rl-$1" >/dev/null 2>&1 || true; }

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
  docker run -d --name "howdah-rl-$V" \
    -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-lim-target-$V":/tmp/t \
    "$DEV" sleep infinity >/dev/null
  docker run -d --name "howdah-rl-nginx-$V" --network "container:howdah-rl-$V" \
    -v "$VOUT":/out -v "$ROOT/lab/integration/refusal_nginx.conf":/etc/nginx/nginx.conf:ro \
    "$NGINX_IMAGE" >/dev/null
  docker exec -e CARGO_TARGET_DIR=/tmp/t "howdah-rl-$V" \
    sh /src/lab/integration/request_limits_container.sh "$F" /out/rows.tsv \
    || printf '%s\tfpm-nginx\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
  cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
  cleanup "$V"
done

echo
echo "=================== request-limits results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   NOT-RUN: %d\n", tot, c["PASS"], c["FAIL"], c["NOT-RUN"]}' "$ALL"
if grep -q "	FAIL	" "$ALL"; then exit 1; fi
