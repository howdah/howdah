#!/bin/sh
# In-container half of the FPM status-page injection lab (see status_injection.sh).
# php-fpm, ONE static worker, pm.status_path=/status, driven over real HTTP
# through the nginx sidecar on 127.0.0.1:8080.
#
# php-fpm's fpm_request_info() copies the request method, authenticated user and
# script filename into the scoreboard BEFORE php_request_startup(), i.e. before
# any extension runs. Howdah therefore cannot prevent the entry being planted;
# it LOGS the planting request (detect, the default). `block` refuses the request
# with a 403 but the scoreboard entry of THAT request is already set -- the
# block scenario below only asserts the refusal and the log, not an un-plant.
#
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
# Rows: phpver <TAB> sapi <TAB> scenario <TAB> PASS|FAIL|SKIP <TAB> detail
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows.tsv}"
WORK=/work; APP=$WORK/app; MARK=$WORK/marker/ran; LOG=$WORK/events.log; OUT=/out
URL=http://127.0.0.1:8080
mkdir -p "$APP" "$WORK/marker"; : > "$LOG"; : > "$RESULTS"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=fpm-nginx
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$1" "$2" "$3" "$4" >> "$RESULTS"; echo "  [$PHPVER $1] $2 $3: $4" >&2; }

echo "== [$PHPVER] building howdah-ext ($FEATURE) ==" >&2
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/t}"
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2; record $S build FAIL "cargo build failed"; exit 1
fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

cat > "$APP/index.php" <<'PHP'
<?php
@file_put_contents('/work/marker/ran', (string) getmypid());
echo "OK pid=", getmypid(), "\n";
PHP

printf '[inspect]\nstatus_injection = "block"\n' > "$WORK/block.toml"
printf '[inspect]\nstatus_injection = "off"\n'   > "$WORK/off.toml"

FPMPID=""
fpm_start() {
  cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $OUT/fpm.err
daemonize = no
[www]
user = root
group = root
listen = 127.0.0.1:9000
pm = static
pm.max_children = 1
pm.status_path = /status
catch_workers_output = yes
EOF
  php-fpm -R -F -y "$WORK/fpm.conf" -d extension="$WORK/howdah.so" -d howdah.log="$LOG" "$@" > "$WORK/fpm.out" 2>&1 &
  FPMPID=$!; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "php-fpm/nginx never answered 200" >&2; cat "$WORK/fpm.out" >&2; return 1; }; sleep 0.1
  done
}
fpm_stop() { [ -n "$FPMPID" ] && kill "$FPMPID" 2>/dev/null; wait "$FPMPID" 2>/dev/null; FPMPID=""; }

B="$WORK/resp.txt"
reset() { rm -f "$MARK"; : > "$LOG"; }
# req <user|-> <method> [path]: one request; prints the HTTP status.
req() {
  _u=$1; _m=$2; _p=${3:-/}
  if [ "$_u" = - ]; then
    curl -s -m 30 -o "$B" -w '%{http_code}' -X "$_m" "$URL$_p" 2>/dev/null || echo 000
  else
    curl -s -m 30 -o "$B" -w '%{http_code}' -X "$_m" -u "$_u:pw" "$URL$_p" 2>/dev/null || echo 000
  fi
}
events() { grep -c '"rule":"status_injection"' "$LOG" 2>/dev/null || true; }
leaks() { grep -qE 'svg|onload|alert' "$LOG"; }

# ===== 1. default (detect): planting is logged, the worker serves, no value logged
fpm_start || { record $S fpm_start FAIL "php-fpm/nginx down"; exit 1; }
reset; c=$(req '<svg/onload=x>' GET)
if [ "$c" = 200 ] && [ -f "$MARK" ] && [ "$(events)" = 1 ] && grep -q '"action":"log"' "$LOG" \
   && grep -q 'auth user' "$LOG" && ! leaks; then
  record $S plant_user_detect PASS "200, script ran, 1 status_injection log event naming 'auth user', value not logged"
else
  record $S plant_user_detect FAIL "http=$c marker=$([ -f "$MARK" ] && echo y || echo n) events=$(events) log=$(head -c 200 "$LOG")"
fi
# the vector is real: PHP's own status HTML (served by the worker, before and
# regardless of Howdah) shows the planted value raw. Observation only; harmless <svg>.
# The scoreboard row of the status request ITSELF shows its own user, so plant on
# the status request (the single worker is the one serving it).
reset; curl -s -m 30 -o "$WORK/status.html" -u '<svg/onload=x>:pw' "$URL/status?html&full" >/dev/null 2>&1
if grep -q '<svg/onload=x>' "$WORK/status.html"; then
  record $S vector_unescaped_in_status_html PASS "planted '<svg/onload=x>' appears raw in php-fpm status HTML (php-fpm's own output; Howdah cannot prevent it)"
else
  record $S vector_unescaped_in_status_html SKIP "value not seen raw in status page (this php-fpm may already escape it): $(grep -c . "$WORK/status.html") lines"
fi
reset; c=$(req alice 'G<E>T' /)
# curl/nginx may refuse a malformed method; only assert if the request reached php.
if [ -f "$MARK" ]; then
  if [ "$(events)" = 1 ] && grep -q 'request method' "$LOG"; then record $S plant_method_detect PASS "method with HTML chars logged as 'request method'"; else record $S plant_method_detect FAIL "events=$(events)"; fi
else
  record $S plant_method_detect SKIP "nginx/curl did not deliver a malformed method (http=$c)"
fi
# benign corpus: zero events
n=0; bad=0
for um in 'alice GET /' 'bob.smith GET /' 'o.brien POST /' 'carol_2 PUT /' 'dave-x DELETE /index.php' '- GET /' '- POST /index.php'; do
  set -- $um; n=$((n+1)); reset; c=$(req "$1" "$2" "$3")
  { [ "$c" = 200 ] && [ "$(events)" = 0 ]; } || { bad=$((bad+1)); echo "  benign fail: $um http=$c ev=$(events)" >&2; }
done
if [ "$bad" = 0 ]; then record $S benign_corpus PASS "$n/$n benign user/method/path requests: zero status_injection events"; else record $S benign_corpus FAIL "$bad/$n produced events or non-200"; fi
fpm_stop

# ===== 2. block: refused, but the scoreboard entry is not un-planted
fpm_start -d howdah.config="$WORK/block.toml" || { record $S block_start FAIL down; exit 1; }
reset; c=$(req '<svg/onload=x>' GET)
if [ "$c" = 403 ] && [ ! -f "$MARK" ] && grep -q '"rule":"status_injection"' "$LOG" && grep -q '"action":"block"' "$LOG" && ! leaks; then
  record $S plant_user_block PASS "403, script did not run, block event logged (NOTE: scoreboard entry was already planted before RINIT; block cannot un-plant)"
else
  record $S plant_user_block FAIL "http=$c marker=$([ -f "$MARK" ] && echo y || echo n) log=$(head -c 200 "$LOG")"
fi
reset; c=$(req alice GET)
[ "$c" = 200 ] && [ "$(events)" = 0 ] && record $S benign_after_block PASS "benign request on the same worker runs, no event" || record $S benign_after_block FAIL "http=$c ev=$(events)"
fpm_stop

# ===== 3. off
fpm_start -d howdah.config="$WORK/off.toml" || { record $S off_start FAIL down; exit 1; }
reset; c=$(req '<svg/onload=x>' GET)
[ "$c" = 200 ] && [ "$(events)" = 0 ] && record $S knob_off PASS "status_injection=off: served, no event" || record $S knob_off FAIL "http=$c ev=$(events)"
fpm_stop
exit 0
