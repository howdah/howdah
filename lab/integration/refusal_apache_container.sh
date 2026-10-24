#!/bin/sh
# Apache mod_php (prefork) half of the refusal-path lab (see refusal.sh). Runs
# inside a howdah-dev-apache-php<ver> image. Same checks as the php-fpm half,
# minus the single-worker pid (prefork has several children): the refused
# request answers 403/413 with the Howdah body and request id, the script's
# marker is not written, and Apache's error log records no child exit signal
# or segfault.
#
# Args: $1 cargo feature (php7|php8); $2 results TSV.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows-ap.tsv}"
WORK=/tmp/refusal-ap; LOG="$WORK/events.log"; MARKD=/tmp/howdah-marker; MARK="$MARKD/ran"
DOCROOT=/var/www/html; URL=http://127.0.0.1
APLOG=/tmp/apache-error.log
mkdir -p "$WORK" "$MARKD" "$DOCROOT/uploads"; : > "$LOG"; : > "$RESULTS"
# Apache children run as www-data: the work dir, marker dir and event log must
# be writable by them.
chmod 777 "$WORK" "$MARKD"; chmod 666 "$LOG"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=apache
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$1" "$2" "$3" "$4" >> "$RESULTS"; echo "  [$PHPVER $1] $2 $3: $4" >&2; }

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/t}"
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2; record $S build FAIL "cargo build failed"; exit 1; fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

cat > "$DOCROOT/index.php" <<'PHP'
<?php
@file_put_contents('/tmp/howdah-marker/ran', (string) getmypid());
echo "OK pid=", getmypid(), " get=", count($_GET), " post=", count($_POST), " cookie=", count($_COOKIE), "\n";
PHP
cat > "$DOCROOT/uploads/shell.php" <<'PHP'
<?php
@file_put_contents('/tmp/howdah-marker/ran', (string) getmypid());
echo "SHELL pid=", getmypid(), "\n";
PHP

php -r '$f=fopen($argv[1],"w"); $b=$argv[2]; for($i=0;$i<3000;$i++){ fwrite($f,"--$b\r\nContent-Disposition: form-data; name=\"f$i\"\r\n\r\n\r\n"); } fwrite($f,"--$b--\r\n"); fclose($f);' "$WORK/flood.bin" FloodB0
php -r 'for($i=0;$i<60;$i++){echo($i?"&":"")."v$i=$i";}' > "$WORK/iv.body"
printf '[inspect]\nmode = "block"\n'                                                > "$WORK/l2.toml"
printf 'mode = "block"\n[limits]\nmax_input_vars = 50\n'                            > "$WORK/iv.toml"
printf '[behavior]\nmode = "block"\ndeny_exec_dirs = ["/var/www/html/uploads"]\n'   > "$WORK/l4.toml"

CONFD=$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;' 2>/dev/null); [ -z "$CONFD" ] && CONFD=/usr/local/etc/php/conf.d
mkdir -p "$CONFD"
write_ini() { # $1 toml path or empty
  { echo "extension=$WORK/howdah.so"; echo "howdah.log=$LOG"; [ -n "$1" ] && echo "howdah.config=$1"
    echo "memory_limit=128M"; echo "post_max_size=16M"; echo "upload_max_filesize=16M"
    echo "max_input_vars=10000000"; echo "max_file_uploads=10000000"; } > "$CONFD/zz-howdah.ini"
}
# Apache's error log in the php:*-apache image is a symlink to stderr; point it
# at a file so the exit-signal check below can read it.
sed -i "s#^ErrorLog .*#ErrorLog $APLOG#" /etc/apache2/apache2.conf 2>/dev/null || true
: > "$APLOG"
AP=apache2ctl; command -v apache2ctl >/dev/null 2>&1 || AP=apachectl
ap_start() { $AP start 2>"$WORK/ap.err"; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "apache down" >&2; cat "$WORK/ap.err" >&2; return 1; }; sleep 0.1; done; }
ap_stop() { $AP stop 2>/dev/null; _j=0; while curl -s -m 1 -o /dev/null "$URL/" 2>/dev/null; do _j=$((_j+1)); [ "$_j" -gt 60 ] && break; sleep 0.1; done; }

B="$WORK/resp.txt"
get()       { curl -s -m 30 -o "$B" -w '%{http_code}' "$URL$1" 2>/dev/null || echo 000; }
get_ck()    { curl -s -m 30 -o "$B" -w '%{http_code}' -b "$2" "$URL$1" 2>/dev/null || echo 000; }
post()      { curl -s -m 30 -o "$B" -w '%{http_code}' -X POST -H "Content-Type: $1" --data-binary @"$2" "$URL/" 2>/dev/null || echo 000; }
post_urlq() { curl -s -m 30 -o "$B" -w '%{http_code}' --data-urlencode "q=$1" "$URL/" 2>/dev/null || echo 000; }
getq()      { curl -s -m 30 -o "$B" -w '%{http_code}' -G --data-urlencode "q=$1" "$URL/" 2>/dev/null || echo 000; }
reset()     { rm -f "$MARK"; : > "$LOG"; }

assert_refused() { # <scenario> <http> <rule>
  _sc=$1; _c=$2; _rule=$3
  echo "$_c" | grep -qE '^(403|413)$' || { record $S "$_sc" FAIL "http=$_c (want 403/413): $(head -c 120 "$B" | tr '\n' ' ')"; return; }
  grep -q 'Howdah blocked' "$B" || { record $S "$_sc" FAIL "http=$_c but body lacks 'Howdah blocked' ($(wc -c < "$B") bytes)"; return; }
  grep -q 'request_id:' "$B" || { record $S "$_sc" FAIL "no request_id in body"; return; }
  grep -q '"action":"block"' "$LOG" || { record $S "$_sc" FAIL "no block line in log"; return; }
  grep -q "\"rule\":\"$_rule\"" "$LOG" || { record $S "$_sc" FAIL "rule != $_rule"; return; }
  [ -f "$MARK" ] && { record $S "$_sc" FAIL "script ran (marker written) despite the 403"; return; }
  _after=$(get / ); [ "$_after" = 200 ] || { record $S "$_sc" FAIL "next request http=$_after"; return; }
  record $S "$_sc" PASS "http=$_c rule=$_rule body+request_id, script did not run, next request 200"
}
assert_ran() { # <scenario> <http> <log-grep-or-empty>
  _sc=$1; _c=$2; _g=$3
  [ "$_c" = 200 ] || { record $S "$_sc" FAIL "http=$_c (want 200)"; return; }
  [ -f "$MARK" ] || { record $S "$_sc" FAIL "script did not run"; return; }
  if [ -n "$_g" ]; then grep -q "$_g" "$LOG" || { record $S "$_sc" FAIL "log lacks $_g"; return; }; fi
  grep -q '"action":"block"' "$LOG" && { record $S "$_sc" FAIL "unexpected block line"; return; }
  record $S "$_sc" PASS "http=200, script ran${_g:+, log has $_g}"
}

# 1. defaults: flood, howdah-check, Layer 2 default
write_ini ""; ap_start || { record $S ap_start FAIL "apache down"; exit 1; }
reset; c=$(post "multipart/form-data; boundary=FloodB0" "$WORK/flood.bin"); assert_refused l1_multipart_flood "$c" max_parts
reset; c=$(post "multipart/form-data; boundary=FloodB0" "$WORK/flood.bin"); assert_refused l1_multipart_flood_again "$c" max_parts
reset; sh /src/tools/howdah-check web "$URL/" > "$WORK/hc.txt" 2>&1
if grep -q 'over-limit parts:  BLOCKED' "$WORK/hc.txt" && grep -q 'selftest marker:   flagged' "$WORK/hc.txt"; then
  record $S howdah_check_web PASS "$(grep 'over-limit parts' "$WORK/hc.txt" | sed 's/  */ /g')"
else record $S howdah_check_web FAIL "$(tr '\n' '|' < "$WORK/hc.txt" | cut -c1-220)"; fi
reset; c=$(getq "' OR 1=1 --"); assert_ran l2_default_detect_runs "$c" '"rule":"sql_injection"'
ap_stop
# 2. Layer 2 armed
write_ini "$WORK/l2.toml"; ap_start || { record $S l2_start FAIL down; exit 1; }
reset; c=$(getq "' OR 1=1 --");              assert_refused l2_block_get "$c" sql_injection
reset; c=$(post_urlq "' OR 1=1 --");         assert_refused l2_block_post "$c" sql_injection
reset; c=$(get_ck / "q=' OR 1=1 --");        assert_refused l2_block_cookie "$c" sql_injection
reset; c=$(getq "../../etc/passwd");         assert_refused l2_block_traversal "$c" path_traversal
reset; c=$(getq "; cat /etc/passwd");        assert_refused l2_block_cmdi "$c" command_injection
reset; c=$(getq "operating system (Linux)"); assert_ran l2_block_benign_runs "$c" ""
ap_stop
# 3. Layer 1 input-shape rule
write_ini "$WORK/iv.toml"; ap_start || { record $S iv_start FAIL down; exit 1; }
reset; c=$(post application/x-www-form-urlencoded "$WORK/iv.body"); assert_refused l1_input_vars_pre_exec "$c" max_input_vars
ap_stop
# 4. Layer 4 main-script deny_exec_dirs
write_ini "$WORK/l4.toml"; ap_start || { record $S l4_start FAIL down; exit 1; }
reset; c=$(get /uploads/shell.php); assert_refused l4_exec_dir_main_script "$c" upload_exec
reset; c=$(get /);                  assert_ran l4_allowed_script_runs "$c" ""
ap_stop

if grep -qiE 'exit signal|segmentation fault|child pid [0-9]+ exit' "$APLOG"; then
  record $S apache_no_child_exits FAIL "$(grep -iE 'exit signal|segmentation|child pid' "$APLOG" | head -2 | tr '\n' '|' | cut -c1-200)"
else record $S apache_no_child_exits PASS "no child exit/segfault lines in $APLOG"; fi
echo "== [$PHPVER] apache error log ($APLOG) ==" >&2; cat "$APLOG" >&2
