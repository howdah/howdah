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
printf '<?php $n=count($_FILES)+count($_POST); echo "OK n=$n\\n";' > "$DOCROOT/index.php"
gen() { php -r '
  $f=fopen($argv[1],"w"); $b=$argv[2]; $n=(int)$argv[3]; $k=$argv[4];
  for($i=0;$i<$n;$i++){ fwrite($f,"--$b\r\n");
    if($k=="file"){ fwrite($f,"Content-Disposition: form-data; name=\"f$i\"; filename=\"f$i.bin\"\r\n\r\n\r\n"); }
    else { fwrite($f,"Content-Disposition: form-data; name=\"f$i\"\r\n\r\n\r\n"); } }
  fwrite($f,"--$b--\r\n"); fclose($f);' "$1" "$2" "$3" "$4"; }
gen "$WORK/flood_files.bin"  FloodB0 3000 file
gen "$WORK/flood_fields.bin" FloodB0 3000 field
printf -- '--MarkerB0\r\nContent-Disposition: form-data; name="__howdah_selftest__"\r\n\r\n1\r\n--MarkerB0--\r\n' > "$WORK/marker.bin"

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
echo "== [$PHPVER] apache rows ==" >&2; grep "^$PHPVER	" "$RESULTS" | grep "	apache	" >&2 || true
