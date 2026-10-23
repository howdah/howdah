#!/bin/sh
# Apache mod_php (prefork) half of the matrix. Runs inside a dev image built
# FROM php:<ver>-apache (apache2 + mod_php + Rust). Builds the extension, loads
# it through a php conf.d ini (mod_php reads php.ini, not -d), starts apache in
# the foreground, and drives the apache2handler SAPI over real HTTP with curl,
# appending the same TSV rows as matrix_container.sh.
#
# Args: $1 feature (php7|php8); $2 RESULTS tsv path.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/tmp/matrix/results.tsv}"
WORK=/tmp/matrix-ap; LOG="$WORK/events.log"; CORPUS=/src/lab/integration/corpus
mkdir -p "$WORK"; : > "$LOG"
# Apache workers run as www-data, not root: make the work dir and the event log
# writable by them, else Howdah's block still fires (403) but the log line that
# the assertions check cannot be written.
chmod 777 "$WORK"; chmod 666 "$LOG"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=apache
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$1" "$2" "$3" "$4" >> "$RESULTS"; }

export CARGO_TARGET_DIR=/tmp/t
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2; record build build FAIL "cargo build failed"; exit 1; fi
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"

# Document root + app.
DOCROOT=/var/www/html; mkdir -p "$DOCROOT"
# Read $_SERVER so auto_globals_jit materializes the HTTP_* request-header vars
# the chained input_filter counts (see matrix_container.sh for the rationale).
printf '<?php $n=count($_FILES)+count($_POST)+count($_SERVER); echo "OK n=$n\\n";' > "$DOCROOT/index.php"
gen() { php -r '
  $f=fopen($argv[1],"w"); $b=$argv[2]; $n=(int)$argv[3]; $k=$argv[4];
  for($i=0;$i<$n;$i++){ fwrite($f,"--$b\r\n");
    if($k=="file"){ fwrite($f,"Content-Disposition: form-data; name=\"f$i\"; filename=\"f$i.bin\"\r\n\r\n\r\n"); }
    else { fwrite($f,"Content-Disposition: form-data; name=\"f$i\"\r\n\r\n\r\n"); } }
  fwrite($f,"--$b--\r\n"); fclose($f);' "$1" "$2" "$3" "$4"; }
gen "$WORK/flood_files.bin"  FloodB0 3000 file
gen "$WORK/flood_fields.bin" FloodB0 3000 field
printf -- '--MarkerB0\r\nContent-Disposition: form-data; name="__howdah_selftest__"\r\n\r\n1\r\n--MarkerB0--\r\n' > "$WORK/marker.bin"

# ---- Task 9 fixtures (input-shape / header rules) --------------------------
INCORPUS=/src/lab/integration/corpus/input
php -r 'for($i=0;$i<60;$i++){echo($i?"&":"")."v$i=$i";}' > "$WORK/iv.body"
printf 'a[b][c][d][e]=1' > "$WORK/nd.body"
printf 'mode="block"\n[limits]\nmax_input_vars=50\n'         > "$WORK/iv.toml"
printf 'mode="detect"\n[limits]\nmax_input_vars=50\n'        > "$WORK/ivd.toml"
printf 'mode="block"\n[limits]\nmax_input_nesting_depth=3\n' > "$WORK/nd.toml"
printf 'mode="block"\n[limits]\nmax_request_headers=5\n'     > "$WORK/rh.toml"
printf 'mode="detect"\n[limits]\nmax_request_headers=5\n'    > "$WORK/rhd.toml"
: > "$WORK/flood_hdr.txt"; i=0; while [ "$i" -lt 15 ]; do printf 'X-Flood-%s: v%s\n' "$i" "$i" >> "$WORK/flood_hdr.txt"; i=$((i+1)); done

CONFD=$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;' 2>/dev/null); [ -z "$CONFD" ] && CONFD=/usr/local/etc/php/conf.d
mkdir -p "$CONFD"
write_ini() { # $1 tomlpath-or-empty ; extra ini lines on stdin
  { echo "extension=$WORK/howdah.so"
    echo "howdah.log=$LOG"
    [ -n "$1" ] && echo "howdah.config=$1"
    echo "memory_limit=128M"; echo "post_max_size=16M"; echo "upload_max_filesize=16M"
    echo "max_input_vars=10000000"; echo "max_file_uploads=10000000"
    cat; } > "$CONFD/zz-howdah.ini"
}
AP=apache2ctl; command -v apache2ctl >/dev/null 2>&1 || AP=apachectl
ap_start() { $AP start 2>"$WORK/ap.err"; _j=0
  while ! curl -s -o /dev/null http://127.0.0.1/ 2>/dev/null; do
    _j=$((_j+1)); [ "$_j" -gt 60 ] && { echo "apache down" >&2; cat "$WORK/ap.err" >&2; return 1; }; sleep 0.1; done; }
ap_stop() { $AP stop 2>/dev/null; _j=0; while curl -s -o /dev/null http://127.0.0.1/ 2>/dev/null; do _j=$((_j+1)); [ "$_j" -gt 40 ] && break; sleep 0.1; done; }
post() { curl -s -o "$WORK/resp.txt" -w '%{http_code}' -X POST \
    -H "Content-Type: multipart/form-data; boundary=$1" --data-binary @"$2" http://127.0.0.1/ 2>/dev/null || echo 000; }
# apost <method> <ct> <bodyfile> -> http code (body in $WORK/resp.txt)
apost() { curl -s -o "$WORK/resp.txt" -w '%{http_code}' -X "$1" -H "Content-Type: $2" \
    --data-binary @"$3" http://127.0.0.1/ 2>/dev/null || echo 000; }
# aget_hdrs <headerfile> -> http code (one "Name: value" per line -> real headers)
aget_hdrs() { _hf=$1; set --; while IFS= read -r _l || [ -n "$_l" ]; do [ -n "$_l" ] && set -- "$@" -H "$_l"; done < "$_hf"
  curl -s -o "$WORK/resp.txt" -w '%{http_code}' "$@" http://127.0.0.1/ 2>/dev/null || echo 000; }
# aget_query <querystring> -> http code
aget_query() { curl -s -o "$WORK/resp.txt" -w '%{http_code}' "http://127.0.0.1/?$1" 2>/dev/null || echo 000; }

# Task 9 assertions (log-based; the input/header-path 403 is best-effort -- the
# var-drop + log line is the mitigation, HTTP status may already be committed).
alogblock() { # <scenario> <http> <rule>
  if ! grep -q '"action":"block"' "$LOG"; then record "$S" "$1" FAIL "no block line (http=$2)"; return; fi
  if ! grep -q "\"rule\":\"$3\"" "$LOG"; then record "$S" "$1" FAIL "rule != $3 (http=$2)"; return; fi
  record "$S" "$1" PASS "blocked rule=$3 http=$2 (403 best-effort)"; }
alogdetect() { # <scenario> <http> <rule>
  if grep -q '"action":"block"' "$LOG"; then record "$S" "$1" FAIL "blocked in detect (http=$2)"; return; fi
  if grep -q '"action":"log"' "$LOG" && grep -q "\"rule\":\"$3\"" "$LOG"; then record "$S" "$1" PASS "logged rule=$3 http=$2 (detect)";
  else record "$S" "$1" FAIL "no log line rule=$3 (http=$2)"; fi; }
anofp() { # <name> <http>
  if [ "$2" = 200 ] && ! grep -q '"action":"block"' "$LOG"; then record "$S" "fp_$1" PASS "http=200 no block";
  else record "$S" "fp_$1" FAIL "http=$2 blocks=$(grep -c '"action":"block"' "$LOG")"; fi; }

# shaped block (defaults) + client_ip (apache sets REMOTE_ADDR=127.0.0.1)
: > "$LOG"; write_ini "" </dev/null; ap_start || { record $S shaped_block_files FAIL "apache down"; exit 1; }
c=$(post FloodB0 "$WORK/flood_files.bin")
if echo "$c" | grep -qE '^(403|413)$' && grep -q '"action":"block"' "$LOG" && grep -q '"rule":"max_files"' "$LOG" && grep -q '"client_ip":"127.0.0.1"' "$LOG" && grep -q request_id: "$WORK/resp.txt"; then
  record $S shaped_block_files PASS "http=$c rule=max_files ip=127.0.0.1"; else record $S shaped_block_files FAIL "http=$c $(tr -d '\n' <"$LOG"|head -c 120)"; fi
: > "$LOG"; c=$(post FloodB0 "$WORK/flood_fields.bin")
if echo "$c" | grep -qE '^(403|413)$' && grep -q '"rule":"max_parts"' "$LOG"; then record $S shaped_block_fields PASS "http=$c"; else record $S shaped_block_fields FAIL "http=$c"; fi
: > "$LOG"; c=$(post MarkerB0 "$WORK/marker.bin")
if [ "$c" = 200 ] && grep -q '"rule":"self_test"' "$LOG" && grep -q '"action":"log"' "$LOG"; then record $S selftest PASS "http=200"; else record $S selftest FAIL "http=$c"; fi
for cf in "$CORPUS"/*.bin; do nm=$(basename "$cf" .bin); : > "$LOG"; c=$(post CorpusB0 "$cf")
  if [ "$c" = 200 ] && ! grep -q '"action":"block"' "$LOG"; then record $S "corpus_$nm" PASS "http=200 no block"; else record $S "corpus_$nm" FAIL "http=$c"; fi; done
ap_stop
# upload_progress On/Off
for up in On Off; do : > "$LOG"; write_ini "" <<EOF
session.upload_progress.enabled=$up
session.upload_progress.name=PROGRESS
EOF
  ap_start || { record $S "up_progress_$(echo $up|tr A-Z a-z)" FAIL down; continue; }
  c=$(post FloodB0 "$WORK/flood_files.bin")
  if echo "$c" | grep -qE '^(403|413)$' && grep -q '"action":"block"' "$LOG"; then record $S "up_progress_$(echo $up|tr A-Z a-z)" PASS "http=$c"; else record $S "up_progress_$(echo $up|tr A-Z a-z)" FAIL "http=$c"; fi
  ap_stop; done
# detect_standard + detect_critical
: > "$LOG"; printf 'mode="block"\n[limits]\nmax_parts=100000\nmax_files=200\n[rules]\nmax_files="detect"\n' > "$WORK/ds.toml"; write_ini "$WORK/ds.toml" </dev/null
ap_start || record $S detect_standard FAIL down
c=$(post FloodB0 "$WORK/flood_files.bin")
if [ "$c" = 200 ] && grep -q '"action":"log"' "$LOG" && ! grep -q '"action":"block"' "$LOG"; then record $S detect_standard PASS "http=200 log"; else record $S detect_standard FAIL "http=$c"; fi
ap_stop
: > "$LOG"; printf 'mode="detect"\n[limits]\nmax_parts=2000\n' > "$WORK/dc.toml"; write_ini "$WORK/dc.toml" </dev/null
ap_start || record $S detect_critical FAIL down
c=$(post FloodB0 "$WORK/flood_fields.bin")
if echo "$c" | grep -qE '^(403|413)$' && grep -q '"action":"block"' "$LOG"; then record $S detect_critical PASS "http=$c"; else record $S detect_critical FAIL "http=$c"; fi
ap_stop
# --- Task 9: input-shape rules (urlencoded POST) ---------------------------
: > "$LOG"; write_ini "$WORK/iv.toml" </dev/null; ap_start || record $S input_vars_flood FAIL down
c=$(apost POST application/x-www-form-urlencoded "$WORK/iv.body"); alogblock input_vars_flood "$c" max_input_vars; ap_stop
: > "$LOG"; write_ini "$WORK/ivd.toml" </dev/null; ap_start || record $S input_vars_flood_detect FAIL down
c=$(apost POST application/x-www-form-urlencoded "$WORK/iv.body"); alogblock input_vars_flood_detect "$c" max_input_vars; ap_stop
: > "$LOG"; write_ini "$WORK/nd.toml" </dev/null; ap_start || record $S nesting_depth FAIL down
c=$(apost POST application/x-www-form-urlencoded "$WORK/nd.body"); alogblock nesting_depth "$c" max_input_nesting_depth; ap_stop

# --- Task 9: request-header count over real HTTP headers (Standard) ---------
: > "$LOG"; write_ini "$WORK/rh.toml" </dev/null; ap_start || record $S request_headers_flood FAIL down
c=$(aget_hdrs "$WORK/flood_hdr.txt"); alogblock request_headers_flood "$c" max_request_headers; ap_stop
: > "$LOG"; write_ini "$WORK/rhd.toml" </dev/null; ap_start || record $S request_headers_flood_detect FAIL down
c=$(aget_hdrs "$WORK/flood_hdr.txt"); alogdetect request_headers_flood_detect "$c" max_request_headers; ap_stop

# --- Task 9: false-positive corpus at default limits -----------------------
: > "$LOG"; write_ini "" </dev/null; ap_start || record $S fp_setup FAIL down
: > "$LOG"; c=$(apost POST application/x-www-form-urlencoded "$INCORPUS/large_form.urlencoded"); anofp large_form "$c"
: > "$LOG"; c=$(apost POST application/x-www-form-urlencoded "$INCORPUS/nested_form.urlencoded"); anofp nested_form "$c"
: > "$LOG"; c=$(aget_hdrs "$INCORPUS/ordinary_headers.txt"); anofp ordinary_headers "$c"
while IFS= read -r q || [ -n "$q" ]; do [ -z "$q" ] && continue; : > "$LOG"
  c=$(aget_query "$q"); anofp "query_$(echo "$q" | tr -c 'a-zA-Z0-9' _ | cut -c1-16)" "$c"
done < "$INCORPUS/safe_queries.txt"
ap_stop

echo "== [$PHPVER] apache rows ==" >&2; grep "^$PHPVER	" "$RESULTS" | grep "	apache	" >&2 || true
