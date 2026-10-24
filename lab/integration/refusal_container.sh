#!/bin/sh
# In-container half of the refusal-path lab (see refusal.sh): php-fpm with ONE
# static worker, driven over real HTTP through the nginx sidecar on
# 127.0.0.1:8080 (and, where cgi-fcgi exists, directly on 127.0.0.1:9000).
#
# Every refused request must: answer 403/413 with the "Howdah blocked" body and
# a request id, leave the app's marker file unwritten (the script did not run),
# keep the same worker pid, add no "readv() failed"/"Connection reset" line to
# nginx's error log (checked after EVERY scenario), and leave no "exited with
# code" in the php-fpm log.
#
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
# Rows: phpver <TAB> sapi <TAB> scenario <TAB> PASS|FAIL|SKIP <TAB> detail
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows.tsv}"
WORK=/work; APP=$WORK/app; MARK=$WORK/marker/ran; LOG=$WORK/events.log; OUT=/out
URL=http://127.0.0.1:8080
mkdir -p "$APP/uploads" "$WORK/marker"; : > "$LOG"; : > "$RESULTS"
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

# ---- the app: every script records that it ran (the marker) and its pid.
# None of them reads $_SERVER, so with auto_globals_jit=On (the default) PHP
# never builds it unless Howdah forces it (Layer 2 armed). ----------------------
cat > "$APP/index.php" <<'PHP'
<?php
@file_put_contents('/work/marker/ran', (string) getmypid());
echo "OK pid=", getmypid(), " get=", count($_GET), " post=", count($_POST), " cookie=", count($_COOKIE), "\n";
PHP
cat > "$APP/uploads/shell.php" <<'PHP'
<?php
@file_put_contents('/work/marker/ran', (string) getmypid());
echo "SHELL pid=", getmypid(), "\n";
PHP
cat > "$APP/sink.php" <<'PHP'
<?php
$o = @system('id');
@file_put_contents('/work/marker/ran', (string) getmypid());
echo "OK pid=", getmypid(), " sys=", var_export($o, true), "\n";
PHP

# ---- fixtures ----------------------------------------------------------------
php -r '$f=fopen($argv[1],"w"); $b=$argv[2]; for($i=0;$i<3000;$i++){ fwrite($f,"--$b\r\nContent-Disposition: form-data; name=\"f$i\"\r\n\r\n\r\n"); } fwrite($f,"--$b--\r\n"); fclose($f);' "$WORK/flood.bin" FloodB0
php -r 'for($i=0;$i<60;$i++){echo($i?"&":"")."v$i=$i";}' > "$WORK/iv.body"
printf '[inspect]\nmode = "block"\n'                                              > "$WORK/l2.toml"
printf '[limits]\nmax_request_headers = 5\n[inspect]\nmode = "block"\n'           > "$WORK/l2h.toml"
printf 'mode = "block"\n[limits]\nmax_request_headers = 5\n'                      > "$WORK/rh.toml"
printf 'mode = "block"\n[limits]\nmax_input_vars = 50\n'                          > "$WORK/iv.toml"
printf '[behavior]\nmode = "block"\ndeny_exec_dirs = ["/work/app/uploads"]\n'     > "$WORK/l4.toml"
printf '[sinks]\nmode = "block"\n'                                                > "$WORK/sink.toml"
# Raised PHP caps: the real-exposure config, so the 3000-field flood reaches
# Howdah's max_parts (2000) instead of PHP's own max_input_vars.
RAISED="-d max_input_vars=10000000 -d max_file_uploads=10000000 -d post_max_size=16M -d memory_limit=128M"
# 15 request headers (over the max_request_headers=5 of l2h/rh.toml).
HDRS=""; i=0; while [ "$i" -lt 15 ]; do HDRS="$HDRS -H X-Flood-$i:v$i"; i=$((i+1)); done

# ---- php-fpm: one static worker, logs to /out/fpm.err ------------------------
FPMPID=""
fpm_start() { # extra -d ini ...
  cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $OUT/fpm.err
daemonize = no
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 1
catch_workers_output = yes
EOF
  # shellcheck disable=SC2086
  php-fpm -R -F -y "$WORK/fpm.conf" $RAISED -d extension="$WORK/howdah.so" -d howdah.log="$LOG" "$@" > "$WORK/fpm.out" 2>&1 &
  FPMPID=$!; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "php-fpm/nginx never answered 200" >&2; cat "$WORK/fpm.out" >&2; return 1; }; sleep 0.1
  done
}
fpm_stop() { [ -n "$FPMPID" ] && kill "$FPMPID" 2>/dev/null; wait "$FPMPID" 2>/dev/null; FPMPID=""; }

# ---- HTTP helpers --------------------------------------------------------------
B="$WORK/resp.txt"
get()       { curl -s -m 30 -o "$B" -w '%{http_code}' "$URL$1" 2>/dev/null || echo 000; }
get_raw()   { curl -s -m 30 --path-as-is -o "$B" -w '%{http_code}' "$URL$1" 2>/dev/null || echo 000; }
get_ck()    { curl -s -m 30 -o "$B" -w '%{http_code}' -b "$2" "$URL$1" 2>/dev/null || echo 000; }
# shellcheck disable=SC2086
get_hdrs()  { curl -s -m 30 -o "$B" -w '%{http_code}' $HDRS "$URL$1" 2>/dev/null || echo 000; }
post()      { curl -s -m 30 -o "$B" -w '%{http_code}' -X POST -H "Content-Type: $1" --data-binary @"$2" "$URL/" 2>/dev/null || echo 000; }
post_urlq() { curl -s -m 30 -o "$B" -w '%{http_code}' --data-urlencode "q=$1" "$URL/" 2>/dev/null || echo 000; }
getq()      { curl -s -m 30 -o "$B" -w '%{http_code}' -G --data-urlencode "q=$1" "$URL/" 2>/dev/null || echo 000; }
pid_now()   { get / >/dev/null; sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' "$B" | head -1; }
ngx_bad()   { grep -cE 'readv\(\) failed|Connection reset|prematurely closed' "$OUT/nginx.err" 2>/dev/null || true; }
NGX0=0
reset()     { rm -f "$MARK"; : > "$LOG"; NGX0=$(ngx_bad); }
# ngx_clean: no reset/readv line was added to nginx's error log since reset().
ngx_clean() { [ "$(ngx_bad)" = "$NGX0" ]; }
ngx_last()  { grep -E 'readv\(\) failed|Connection reset|prematurely closed' "$OUT/nginx.err" | tail -1 | cut -c1-140; }

# assert_refused <scenario> <http> <rule> <pid0>
assert_refused() {
  _sc=$1; _c=$2; _rule=$3; _p0=$4
  echo "$_c" | grep -qE '^(403|413)$' || { record $S "$_sc" FAIL "http=$_c (want 403/413): $(head -c 120 "$B" | tr '\n' ' ')"; return; }
  grep -q 'Howdah blocked' "$B" || { record $S "$_sc" FAIL "http=$_c but body lacks 'Howdah blocked' ($(wc -c < "$B") bytes)"; return; }
  grep -q 'request_id:' "$B" || { record $S "$_sc" FAIL "no request_id in body"; return; }
  grep -q '"action":"block"' "$LOG" || { record $S "$_sc" FAIL "no block line in log"; return; }
  grep -q "\"rule\":\"$_rule\"" "$LOG" || { record $S "$_sc" FAIL "rule != $_rule ($(tr -d '\n' < "$LOG" | head -c 160))"; return; }
  [ -f "$MARK" ] && { record $S "$_sc" FAIL "script ran (marker written) despite the 403"; return; }
  ngx_clean || { record $S "$_sc" FAIL "nginx logged a reset: $(ngx_last)"; return; }
  _p1=$(pid_now)
  [ "$_p1" = "$_p0" ] || { record $S "$_sc" FAIL "worker pid changed $_p0 -> $_p1 (worker exited and was respawned)"; return; }
  record $S "$_sc" PASS "http=$_c rule=$_rule body+request_id, script did not run, worker pid $_p0 unchanged, nginx clean"
}
# assert_ran <scenario> <http> <pid0> <extra-grep-in-log-or-empty>
assert_ran() {
  _sc=$1; _c=$2; _p0=$3; _g=$4
  [ "$_c" = 200 ] || { record $S "$_sc" FAIL "http=$_c (want 200)"; return; }
  [ -f "$MARK" ] || { record $S "$_sc" FAIL "script did not run"; return; }
  if [ -n "$_g" ]; then grep -q "$_g" "$LOG" || { record $S "$_sc" FAIL "log lacks $_g"; return; }; fi
  grep -q '"action":"block"' "$LOG" && { record $S "$_sc" FAIL "unexpected block line"; return; }
  ngx_clean || { record $S "$_sc" FAIL "nginx logged a reset: $(ngx_last)"; return; }
  _p1=$(pid_now)
  [ "$_p1" = "$_p0" ] || { record $S "$_sc" FAIL "worker pid changed $_p0 -> $_p1"; return; }
  record $S "$_sc" PASS "http=200, script ran, worker pid unchanged, nginx clean${_g:+, log has $_g}"
}

# ===== 1. default config: Layer 1 multipart flood, howdah-check, Layer 2 default
fpm_start || { record $S fpm_start FAIL "php-fpm/nginx down"; exit 1; }
P0=$(pid_now); reset
if echo "$P0" | grep -qE '^[0-9]+$'; then record $S baseline PASS "worker pid $P0 answers through nginx"; else record $S baseline FAIL "no pid in response"; fi
reset; c=$(post "multipart/form-data; boundary=FloodB0" "$WORK/flood.bin"); assert_refused l1_multipart_flood "$c" max_parts "$P0"
# a second flood on the same worker: the per-request state was reset cleanly
reset; c=$(post "multipart/form-data; boundary=FloodB0" "$WORK/flood.bin"); assert_refused l1_multipart_flood_again "$c" max_parts "$P0"
# howdah-check web through nginx
reset; sh /src/tools/howdah-check web "$URL/" > "$WORK/hc.txt" 2>&1
if grep -q 'over-limit parts:  BLOCKED' "$WORK/hc.txt" && grep -q 'selftest marker:   flagged' "$WORK/hc.txt" && ngx_clean; then
  record $S howdah_check_web PASS "$(grep 'over-limit parts' "$WORK/hc.txt" | sed 's/  */ /g')"
else record $S howdah_check_web FAIL "$(tr '\n' '|' < "$WORK/hc.txt" | cut -c1-220) nginx=$(ngx_last)"; fi
# Layer 2 default (detect): logs, does not block, script runs
reset; c=$(getq "' OR 1=1 --"); assert_ran l2_default_detect_runs "$c" "$P0" '"rule":"sql_injection"'
# direct FastCGI (what the matrix does) for comparison
if command -v cgi-fcgi >/dev/null 2>&1; then
  reset; _cl=$(wc -c < "$WORK/flood.bin")
  env -i SCRIPT_FILENAME="$APP/index.php" SCRIPT_NAME=/index.php REQUEST_URI=/ REQUEST_METHOD=POST \
    CONTENT_TYPE="multipart/form-data; boundary=FloodB0" CONTENT_LENGTH="$_cl" REMOTE_ADDR=203.0.113.9 \
    SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 cgi-fcgi -bind -connect 127.0.0.1:9000 < "$WORK/flood.bin" > "$WORK/fcgi.raw" 2>/dev/null
  _st=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/fcgi.raw" | head -1)
  _mk=no; [ -f "$MARK" ] && _mk=yes
  _p1=$(pid_now)
  if [ "$_st" = 403 ] && grep -q 'Howdah blocked' "$WORK/fcgi.raw" && [ "$_mk" = no ] && [ "$_p1" = "$P0" ]; then
    record fpm-cgifcgi l1_multipart_flood PASS "Status 403, body, script did not run, pid unchanged"
  else record fpm-cgifcgi l1_multipart_flood FAIL "status=$_st body=$(grep -c 'Howdah blocked' "$WORK/fcgi.raw") marker=$_mk pid=$P0->$_p1"; fi
else
  record fpm-cgifcgi l1_multipart_flood SKIP "no cgi-fcgi in this image (nginx path covers php-fpm)"
fi
fpm_stop

# ===== 2. Layer 2 armed: refuse BEFORE the script, on GET / POST / cookie / path shapes
fpm_start -d howdah.config="$WORK/l2.toml" || { record $S l2_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(getq "' OR 1=1 --");                        assert_refused l2_block_get "$c" sql_injection "$P0"
reset; c=$(post_urlq "' OR 1=1 --");                   assert_refused l2_block_post "$c" sql_injection "$P0"
reset; c=$(get_ck / "q=' OR 1=1 --");                  assert_refused l2_block_cookie "$c" sql_injection "$P0"
reset; c=$(getq "../../etc/passwd");                   assert_refused l2_block_traversal "$c" path_traversal "$P0"
reset; c=$(getq "; cat /etc/passwd");                  assert_refused l2_block_cmdi "$c" command_injection "$P0"
# The forced-$_SERVER path: a traversal shape in the REQUEST PATH (REQUEST_URI,
# sent raw by nginx as $request_uri; curl --path-as-is keeps the dot segments;
# the normalised path stays under / so nginx does not reject it). The app never
# reads $_SERVER, so only Howdah building it at RINIT can scan this.
reset; c=$(get_raw "/index.php/a/b/c/../../etc/passwd"); assert_refused l2_block_uri_path "$c" path_traversal "$P0"
reset; c=$(getq "operating system (Linux)");           assert_ran l2_block_benign_runs "$c" "$P0" ""
fpm_stop
# ===== 2b. the same forced $_SERVER moves the Layer 1 request-header limits
#           in front of the script (headers are counted, not scanned, by Howdah)
fpm_start -d howdah.config="$WORK/l2h.toml" || { record $S l2h_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(get_hdrs /); assert_refused l1_header_flood_pre_exec_with_l2_armed "$c" max_request_headers "$P0"
fpm_stop
# ===== 2c. control: Layer 2 NOT armed, same header flood, app never reads
#           $_SERVER -> PHP never builds it, the header limit is unexercised
#           (documented caveat; the matrix app reads $_SERVER to count them)
fpm_start -d howdah.config="$WORK/rh.toml" || { record $S rh_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(get_hdrs /)
if [ "$c" = 200 ] && [ -f "$MARK" ] && ! grep -q '"rule":"max_request_headers"' "$LOG" && ngx_clean && [ "$(pid_now)" = "$P0" ]; then
  record $S l1_header_flood_without_l2_unexercised PASS "http=200, script ran, no header-limit event: \$_SERVER never built (auto_globals_jit, app does not read it)"
else record $S l1_header_flood_without_l2_unexercised FAIL "http=$c marker=$([ -f "$MARK" ] && echo yes || echo no) log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi
fpm_stop

# ===== 3. Layer 1 input-shape rule: also refused before the script now
fpm_start -d howdah.config="$WORK/iv.toml" || { record $S iv_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(post application/x-www-form-urlencoded "$WORK/iv.body"); assert_refused l1_input_vars_pre_exec "$c" max_input_vars "$P0"
fpm_stop

# ===== 4. Layer 4 main-script deny_exec_dirs (the RINIT check)
fpm_start -d howdah.config="$WORK/l4.toml" || { record $S l4_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(get /uploads/shell.php); assert_refused l4_exec_dir_main_script "$c" upload_exec "$P0"
reset; c=$(get /);                  assert_ran l4_allowed_script_runs "$c" "$P0" ""
fpm_stop
# the same refusal for a CLI main script (cron): "Howdah blocked" on stdout,
# the script does not run; the exit code is recorded for the docs.
reset; php $RAISED -d extension="$WORK/howdah.so" -d howdah.log="$LOG" -d howdah.config="$WORK/l4.toml" "$APP/uploads/shell.php" > "$WORK/cli.out" 2>&1; rc=$?
if grep -q 'Howdah blocked' "$WORK/cli.out" && [ ! -f "$MARK" ] && grep -q '"rule":"upload_exec"' "$LOG"; then
  record cli l4_exec_dir_main_script PASS "refused on stdout, script did not run, exit code $rc"
else record cli l4_exec_dir_main_script FAIL "exit=$rc marker=$([ -f "$MARK" ] && echo yes || echo no) out=$(head -c 100 "$WORK/cli.out" | tr '\n' ' ')"; fi

# ===== 5. an armed Layer 3 sink: neutralises the call, never refuses, worker alive
fpm_start -d howdah.config="$WORK/sink.toml" || { record $S sink_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(get /sink.php)
if [ "$c" = 200 ] && grep -q 'sys=false' "$B" && grep -q '"rule":"command_exec"' "$LOG" && ngx_clean && [ "$(pid_now)" = "$P0" ]; then
  record $S sink_block_worker_alive PASS "http=200 system() neutralised (false), command_exec block logged, pid unchanged"
else record $S sink_block_worker_alive FAIL "http=$c body=$(head -c 80 "$B" | tr '\n' ' ') pid=$(pid_now)/$P0"; fi
fpm_stop

# ===== 6. output_handler = ob_gzhandler: a handler started at request startup
#           must not add headers after the refusal (no "headers already sent")
fpm_start -d output_handler=ob_gzhandler -d display_errors=1 -d log_errors=1 || { record $S gz_start FAIL down; exit 1; }
P0=$(pid_now)
_fl0=$(grep -c 'headers already sent' "$OUT/fpm.err" 2>/dev/null || true)
reset; c=$(post "multipart/form-data; boundary=FloodB0" "$WORK/flood.bin"); assert_refused l1_multipart_flood_ob_gzhandler "$c" max_parts "$P0"
if grep -qi 'warning' "$B" || [ "$(grep -c 'headers already sent' "$OUT/fpm.err" 2>/dev/null || true)" != "$_fl0" ]; then
  record $S ob_gzhandler_no_header_warning FAIL "body=$(tr '\n' ' ' < "$B" | cut -c1-120) fpm.err=$(grep 'headers already sent' "$OUT/fpm.err" | tail -1 | cut -c1-100)"
else record $S ob_gzhandler_no_header_warning PASS "refusal body has no Warning and php-fpm log has no 'headers already sent'"; fi
fpm_stop

# ===== php-fpm log: no worker ever exited
if grep -qE 'exited with code|exited on signal|SIGSEGV' "$OUT/fpm.err"; then
  record $S fpm_no_worker_exits FAIL "$(grep -E 'exited with code|exited on signal|SIGSEGV' "$OUT/fpm.err" | head -2 | tr '\n' '|' | cut -c1-200)"
else
  record $S fpm_no_worker_exits PASS "no 'exited with code' / 'exited on signal' line in $OUT/fpm.err across $(grep -c 'fpm is running' "$OUT/fpm.err") php-fpm runs"
fi
echo "== [$PHPVER] php-fpm log ($OUT/fpm.err) ==" >&2; cat "$OUT/fpm.err" >&2
echo "== [$PHPVER] nginx error log ($OUT/nginx.err) ==" >&2; cat "$OUT/nginx.err" >&2
