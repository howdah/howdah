#!/bin/sh
# In-container half of the request-limits lab (see request_limits.sh): php-fpm
# behind the nginx sidecar on 127.0.0.1:8080, the §4.1-4.5 scanner active.
#
# Two things to prove WITHOUT a vulnerable PHP (these are Howdah's own byte-
# stream limits, not a PHP out-of-memory):
#   * BENIGN corpus is zero-block at defaults (Review Focus #1): a multi-file
#     gallery, parts with ordinary extra headers, framework-style nested arrays,
#     and a real chunked upload all answer 200 with no block line;
#   * gap A fires end to end: a part carrying 50 header lines (which the parsed-
#     event path never sees — it only gets Content-Disposition) is refused by the
#     byte scanner with a max_part_headers block line, and gap C: a flood of
#     nested field names is refused with a nesting_budget line.
#
# The "does it stop a real PHP out-of-memory on a vulnerable build" evidence
# (§5.2) needs owner-supplied trigger fixtures and is NOT asserted here.
#
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows.tsv}"
WORK=/work; APP=$WORK/app; LOG=$WORK/events.log; OUT=/out
URL=http://127.0.0.1:8080
mkdir -p "$APP"; : > "$LOG"; : > "$RESULTS"
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

# The app reads $_POST and $_FILES so PHP actually parses the body (the scanner
# runs as read_post is pulled).
cat > "$APP/index.php" <<'PHP'
<?php echo "OK get=", count($_GET), " post=", count($_POST), " files=", count($_FILES), "\n";
PHP

# ---- fixtures (benign + shaped), built with PHP so quoting is exact ----------
# Benign: a 15-file gallery.
php -r '$b="BND"; $o=fopen($argv[1],"w"); for($i=0;$i<15;$i++){fwrite($o,"--$b\r\nContent-Disposition: form-data; name=\"img[$i]\"; filename=\"p$i.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nJPEGDATA$i\r\n");} fwrite($o,"--$b--\r\n"); fclose($o);' "$WORK/gallery.bin"
# Benign: parts carrying ordinary extra headers.
php -r '$b="BND"; $o=fopen($argv[1],"w"); for($i=0;$i<5;$i++){fwrite($o,"--$b\r\nContent-Disposition: form-data; name=\"f$i\"\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: binary\r\n\r\nvalue$i\r\n");} fwrite($o,"--$b--\r\n"); fclose($o);' "$WORK/extrahdr.bin"
# Benign: framework-style nested arrays (depth 4), 100 fields -> 500 levels < 10000.
php -r '$b="BND"; $o=fopen($argv[1],"w"); for($i=0;$i<100;$i++){fwrite($o,"--$b\r\nContent-Disposition: form-data; name=\"a[b][c][d$i]\"\r\n\r\nv\r\n");} fwrite($o,"--$b--\r\n"); fclose($o);' "$WORK/nested.bin"
# Benign: shapes PHP's rfc1867 accepts but a strict parser would reject — the
# strict byte scanner must NOT block these (M1). LF-only line endings:
php -r 'file_put_contents($argv[1], "--BND\nContent-Disposition: form-data; name=\"a\"\n\nvalue\n--BND--\n");' "$WORK/lfonly.bin"
# an "attachment" disposition word (PHP ignores the type word):
php -r 'file_put_contents($argv[1], "--BND\r\nContent-Disposition: attachment; name=\"a\"\r\n\r\nvalue\r\n--BND--\r\n");' "$WORK/attach.bin"
# Shaped (gap A): one part with 50 header lines (byte scanner sees them all).
php -r '$b="BND"; $o=fopen($argv[1],"w"); fwrite($o,"--$b\r\nContent-Disposition: form-data; name=\"a\"\r\n"); for($i=0;$i<50;$i++){fwrite($o,"X-$i: v\r\n");} fwrite($o,"\r\nv\r\n--$b--\r\n"); fclose($o);' "$WORK/hdrflood.bin"
# Shaped (gap C): summed nesting past max_nesting_levels (10000) with names each
# UNDER the per-name depth cap (max_input_nesting_depth=64) so nesting_budget —
# not max_input_nesting_depth — is what fires. 200 parts x depth 60 (= 61 levels)
# = 12200 > 10000; the sum trips at ~164 parts, well under max_parts (2000), and
# early enough that the refusal is delivered cleanly.
php -r '$b="BND"; $o=fopen($argv[1],"w"); $n="a".str_repeat("[x]",60); for($i=0;$i<200;$i++){fwrite($o,"--$b\r\nContent-Disposition: form-data; name=\"$n\"\r\n\r\nv\r\n");} fwrite($o,"--$b--\r\n"); fclose($o);' "$WORK/nestflood.bin"

RAISED="-d max_input_vars=10000000 -d max_file_uploads=10000000 -d post_max_size=64M -d memory_limit=256M"

FPMPID=""
fpm_start() {
  cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $OUT/fpm.err
daemonize = no
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 2
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

B="$WORK/resp.txt"
postf() { curl -s -m 30 -o "$B" -w '%{http_code}' -X POST -H "Content-Type: multipart/form-data; boundary=BND" --data-binary @"$1" "$URL/" 2>/dev/null || echo 000; }
reset() { : > "$LOG"; }

assert_benign() { # <scenario> <fixture>
  reset; c=$(postf "$2")
  if [ "$c" = 200 ] && ! grep -q '"action":"block"' "$LOG"; then
    record $S "$1" PASS "http=200, no block line (scanner active, zero false positive)"
  else record $S "$1" FAIL "http=$c log=$(tr -d '\n' < "$LOG" | head -c 160)"; fi
}
assert_block() { # <scenario> <fixture> <rule> — expects a clean 403/413
  reset; c=$(postf "$2")
  if echo "$c" | grep -qE '^(403|413)$' && grep -q "\"rule\":\"$3\"" "$LOG" && grep -q '"action":"block"' "$LOG"; then
    record $S "$1" PASS "http=$c rule=$3 refused"
  else record $S "$1" FAIL "http=$c want rule=$3: $(tr -d '\n' < "$LOG" | head -c 200)"; fi
}
# For a block recorded mid-parse (the read_post scanner / note_name paths), the
# SECURITY substance is: the limit fired (block line logged), the offending
# allocation was suppressed, and the worker survives. Whether the client gets a
# clean 403/413 or a dropped connection for this early-recorded verdict is the
# §4.1 "module::refuse works when the verdict is recorded this early" point the
# design has the owner confirm per PHP version. We assert the substance here.
assert_fires_worker_survives() { # <scenario> <fixture> <rule>
  reset; c=$(postf "$2")
  if ! grep -q "\"rule\":\"$3\"" "$LOG" || ! grep -q '"action":"block"' "$LOG"; then
    record $S "$1" FAIL "no $3 block line (http=$c): $(tr -d '\n' < "$LOG" | head -c 200)"; return
  fi
  a=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null || echo 000)
  if [ "$a" = 200 ]; then
    record $S "$1" PASS "refused (rule=$3 block logged; client http=$c), worker survives (follow-up 200)"
  else record $S "$1" FAIL "rule=$3 logged but worker did not survive (follow-up http=$a)"; fi
}

fpm_start || { record $S fpm_start FAIL down; exit 1; }
assert_benign benign_gallery       "$WORK/gallery.bin"
assert_benign benign_extra_headers "$WORK/extrahdr.bin"
assert_benign benign_nested_arrays "$WORK/nested.bin"
assert_benign benign_lf_only       "$WORK/lfonly.bin"
assert_benign benign_attachment    "$WORK/attach.bin"
# Chunked upload (no Content-Length): a real benign streaming upload.
reset; c=$(curl -s -m 30 -o "$B" -w '%{http_code}' -X POST -H "Content-Type: multipart/form-data; boundary=BND" -H "Transfer-Encoding: chunked" --data-binary @"$WORK/gallery.bin" "$URL/" 2>/dev/null || echo 000)
if [ "$c" = 200 ] && ! grep -q '"action":"block"' "$LOG"; then record $S benign_chunked PASS "http=200, no block line"; else record $S benign_chunked FAIL "http=$c"; fi
assert_block gap_a_header_flood "$WORK/hdrflood.bin"  max_part_headers
assert_fires_worker_survives gap_c_nesting_flood "$WORK/nestflood.bin" nesting_budget
fpm_stop

record $S vulnerable_version_table NOT-RUN "the §5.2 PASS-on-vulnerable-PHP table + trigger fixtures are owner-supplied (private/, §5.3)"
echo "== [$PHPVER] request-limits rows done ==" >&2
