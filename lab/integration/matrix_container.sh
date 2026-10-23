#!/bin/sh
# In-container half of the cross-version block matrix (Task 12 STEP 2/3).
#
# Runs inside a howdah-dev-php<ver> image (Rust + that PHP minor's headers +
# php CLI + php-fpm). Builds the extension ONCE for this minor, then exercises
# every scenario across the requested SAPIs, appending machine-readable TSV
# rows to $RESULTS:
#
#   phpver <TAB> sapi <TAB> scenario <TAB> result(PASS|FAIL|SKIP) <TAB> detail
#
# SAPIs: "cli" (PHP built-in server) and "fpm" (real php-fpm via cgi-fcgi,
# which drives the fpm SAPI incl. REMOTE_ADDR -> client_ip). Apache mod_php is
# handled by a separate apache image (see matrix.sh); here it is SKIP.
#
# Scenarios (per SAPI), at Howdah's DEFAULT limits unless noted:
#   shaped_block_files  shaped file-flood (caps raised so callback fires) -> 403 max_files + log + client_ip
#   shaped_block_fields shaped field-flood                                -> 403 max_parts + log
#   selftest            marker field                                       -> 200 + self_test action=log
#   up_progress_on      shaped flood with session.upload_progress On       -> 403 (chaining intact)
#   up_progress_off     shaped flood with session.upload_progress Off      -> 403
#   detect_standard     max_files downgraded to detect, over-files shaped  -> 200 + action=log (no block)
#   detect_critical     global mode=detect, over max_parts                 -> 403 (critical still blocks)
#   corpus_<name>       each benign corpus body                            -> 200, zero block lines
#
# Args: $1 cargo feature (php5|php7|php8); $2 space-sep SAPIs (default "cli fpm");
#       $3 RESULTS tsv path (default /tmp/matrix/results.tsv).
set -u
FEATURE="${1:-php7}"
SAPIS="${2:-cli fpm}"
RESULTS="${3:-/tmp/matrix/results.tsv}"
WORK=/tmp/matrix
LOG="$WORK/events.log"
CORPUS=/src/lab/integration/corpus
mkdir -p "$WORK"; : > "$LOG"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)

record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$1" "$2" "$3" "$4" >> "$RESULTS"; }

echo "== [$PHPVER] building howdah-ext ($FEATURE) ==" >&2
export CARGO_TARGET_DIR=/tmp/t
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2
  for s in $SAPIS; do record "$s" build FAIL "cargo build failed"; done
  exit 1
fi
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
printf '<?php $n=count($_FILES)+count($_POST); echo "OK n=$n\\n";' > "$WORK/index.php"

# shaped body generator: $1 out $2 boundary $3 count $4 file|field
gen() {
  php -r '
    $f=fopen($argv[1],"w"); $b=$argv[2]; $n=(int)$argv[3]; $k=$argv[4];
    for($i=0;$i<$n;$i++){ fwrite($f,"--$b\r\n");
      if($k=="file"){ fwrite($f,"Content-Disposition: form-data; name=\"f$i\"; filename=\"f$i.bin\"\r\n\r\n\r\n"); }
      else { fwrite($f,"Content-Disposition: form-data; name=\"f$i\"\r\n\r\n\r\n"); } }
    fwrite($f,"--$b--\r\n"); fclose($f);' "$1" "$2" "$3" "$4"
}
# selftest marker body (one field named __howdah_selftest__)
cat > "$WORK/mk_marker.php" <<'PHP'
<?php $b=$argv[2]; $f=fopen($argv[1],"w");
fwrite($f,"--$b\r\nContent-Disposition: form-data; name=\"__howdah_selftest__\"\r\n\r\n1\r\n--$b--\r\n");
fclose($f);
PHP
php "$WORK/mk_marker.php" "$WORK/marker.bin" MarkerB0
gen "$WORK/flood_files.bin"  FloodB0 3000 file
gen "$WORK/flood_fields.bin" FloodB0 3000 field

# Raised PHP caps so the rfc1867 callback fires past PHP's own max_input_vars/
# max_file_uploads on EVERY version (that is the real-exposure config; stock
# caps merely hide the callback AND the memory threat -- see STEP 1 findings).
STOCKMEM="-d memory_limit=128M -d post_max_size=16M -d upload_max_filesize=16M"
RAISED="-d max_input_vars=10000000 -d max_file_uploads=10000000"

# ---- CLI built-in server driver -------------------------------------------
SRVPID=""
cli_start() { # $1 port ; rest = extra -d ini
  _p=$1; shift
  # shellcheck disable=SC2086
  php $STOCKMEM $RAISED "$@" -S "127.0.0.1:$_p" "$WORK/index.php" > "$WORK/cli.$_p.log" 2>&1 &
  SRVPID=$!; _j=0
  while ! curl -s -o /dev/null "http://127.0.0.1:$_p/" 2>/dev/null; do
    _j=$((_j+1)); [ "$_j" -gt 60 ] && { echo "cli server $_p down" >&2; return 1; }; sleep 0.1; done
}
cli_stop() { [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null; wait "$SRVPID" 2>/dev/null; SRVPID=""; }
cli_post() { # $1 port $2 boundary $3 body -> echoes "HTTP|bodyfile"
  _o="$WORK/resp.txt"
  _c=$(curl -s -o "$_o" -w '%{http_code}' -X POST \
      -H "Content-Type: multipart/form-data; boundary=$2" --data-binary @"$3" \
      "http://127.0.0.1:$1/" 2>/dev/null || echo 000)
  echo "$_c|$_o"
}

# ---- FPM driver (real php-fpm + cgi-fcgi) ---------------------------------
FPMPID=""
fpm_start() { # extra -d ini...
  cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $WORK/fpm.err
daemonize = no
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 4
catch_workers_output = yes
EOF
  # shellcheck disable=SC2086
  php-fpm -R -F -y "$WORK/fpm.conf" $STOCKMEM $RAISED "$@" > "$WORK/fpm.out" 2>&1 &
  FPMPID=$!; _j=0
  # readiness: a trivial FastCGI GET must connect and return a response
  while ! env -i SCRIPT_FILENAME="$WORK/index.php" SCRIPT_NAME=/index.php \
      REQUEST_METHOD=GET REQUEST_URI=/ SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
      cgi-fcgi -bind -connect 127.0.0.1:9000 >/dev/null 2>&1; do
    _j=$((_j+1)); [ "$_j" -gt 60 ] && { echo "fpm down" >&2; cat "$WORK/fpm.out" >&2; return 1; }; sleep 0.1; done
}
fpm_stop() { [ -n "$FPMPID" ] && kill "$FPMPID" 2>/dev/null; wait "$FPMPID" 2>/dev/null; FPMPID=""; }
fpm_post() { # $1 boundary $2 body $3 remote_addr -> echoes "HTTP|bodyfile"
  _o="$WORK/fresp.txt"; _cl=$(wc -c < "$2")
  env -i \
    SCRIPT_FILENAME="$WORK/index.php" SCRIPT_NAME=/index.php REQUEST_URI=/ \
    REQUEST_METHOD=POST CONTENT_TYPE="multipart/form-data; boundary=$1" \
    CONTENT_LENGTH="$_cl" REMOTE_ADDR="$3" SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
    cgi-fcgi -bind -connect 127.0.0.1:9000 < "$2" > "$WORK/fcgi.raw" 2>/dev/null
  # Split CGI headers / body; derive HTTP code from a Status: header (else 200).
  _code=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/fcgi.raw" | head -1)
  [ -z "$_code" ] && _code=200
  awk 'f{print} /^\r?$/{f=1}' "$WORK/fcgi.raw" > "$_o"
  echo "$_code|$_o"
}

ensure_fpm_tools() {
  command -v php-fpm >/dev/null 2>&1 || { echo "no php-fpm" >&2; return 1; }
  command -v cgi-fcgi >/dev/null 2>&1 && return 0
  # install from the base image's pinned apt snapshot (EOL-safe)
  apt-get -o Acquire::Check-Valid-Until=false update >/tmp/apt.u 2>&1 \
    && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends --allow-unauthenticated libfcgi-bin >/tmp/apt.i 2>&1
  command -v cgi-fcgi >/dev/null 2>&1
}

# assert_block <sapi> <scenario> <http> <bodyfile> <want_rule> <want_ip|"">
assert_block() {
  _s=$1; _sc=$2; _http=$3; _body=$4; _rule=$5; _ip=$6
  if ! echo "$_http" | grep -qE '^(403|413)$'; then record "$_s" "$_sc" FAIL "http=$_http (want 403/413)"; return; fi
  grep -q '"action":"block"' "$LOG" || { record "$_s" "$_sc" FAIL "no block line in log"; return; }
  if [ -n "$_rule" ]; then grep -q "\"rule\":\"$_rule\"" "$LOG" || { record "$_s" "$_sc" FAIL "rule != $_rule"; return; }; fi
  grep -q 'request_id:' "$_body" || { record "$_s" "$_sc" FAIL "no request_id in body"; return; }
  if [ "$_ip" = NONEMPTY ]; then
    grep -qE '"client_ip":"[^"]+"' "$LOG" || { record "$_s" "$_sc" FAIL "client_ip empty"; return; }
  elif [ -n "$_ip" ]; then
    grep -q "\"client_ip\":\"$_ip\"" "$LOG" || { record "$_s" "$_sc" FAIL "client_ip != $_ip ($(sed -n 's/.*\("client_ip":"[^"]*"\).*/\1/p' "$LOG" | head -1))"; return; }
  fi
  record "$_s" "$_sc" PASS "http=$_http rule=$_rule ip=${_ip:-skip}"
}

# ===========================================================================
run_cli() {
  S=cli
  # 1. shaped file-flood @ defaults
  : > "$LOG"; cli_start 8100 -d extension="$WORK/howdah.so" -d howdah.log="$LOG" || { record $S shaped_block_files FAIL "server down"; return; }
  # NB: the PHP CLI built-in server does not expose REMOTE_ADDR via sapi_getenv,
  # so client_ip is validated under the production SAPIs (fpm/apache), not here.
  r=$(cli_post 8100 FloodB0 "$WORK/flood_files.bin"); assert_block $S shaped_block_files "${r%%|*}" "${r#*|}" max_files ""
  r=$(cli_post 8100 FloodB0 "$WORK/flood_fields.bin"); assert_block $S shaped_block_fields "${r%%|*}" "${r#*|}" max_parts ""
  # selftest
  : > "$LOG"; r=$(cli_post 8100 MarkerB0 "$WORK/marker.bin"); c=${r%%|*}; b=${r#*|}
  if [ "$c" = 200 ] && grep -q '"rule":"self_test"' "$LOG" && grep -q '"action":"log"' "$LOG"; then
    record $S selftest PASS "http=200 self_test logged"; else record $S selftest FAIL "http=$c log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi
  # corpus: zero blocks
  for cf in "$CORPUS"/*.bin; do
    nm=$(basename "$cf" .bin); : > "$LOG"
    r=$(cli_post 8100 CorpusB0 "$cf"); c=${r%%|*}
    if [ "$c" = 200 ] && ! grep -q '"action":"block"' "$LOG"; then record $S "corpus_$nm" PASS "http=200 no block";
    else record $S "corpus_$nm" FAIL "http=$c block=$(grep -c '"action":"block"' "$LOG")"; fi
  done
  cli_stop
  # upload_progress On / Off (both must block shaped)
  for up in On Off; do
    : > "$LOG"
    cli_start 8101 -d extension="$WORK/howdah.so" -d howdah.log="$LOG" \
      -d session.upload_progress.enabled="$up" -d session.upload_progress.name=PROGRESS || { record $S "up_progress_$up" FAIL "server down"; continue; }
    r=$(cli_post 8101 FloodB0 "$WORK/flood_files.bin"); c=${r%%|*}; b=${r#*|}
    if echo "$c" | grep -qE '^(403|413)$' && grep -q '"action":"block"' "$LOG"; then record $S "up_progress_$(echo $up|tr A-Z a-z)" PASS "http=$c";
    else record $S "up_progress_$(echo $up|tr A-Z a-z)" FAIL "http=$c"; fi
    cli_stop
  done
  # detect_standard: max_files -> detect, flood files -> 200 + action=log, no block
  : > "$LOG"
  printf 'mode="block"\n[limits]\nmax_parts=100000\nmax_files=200\n[rules]\nmax_files="detect"\n' > "$WORK/ds.toml"
  cli_start 8102 -d extension="$WORK/howdah.so" -d howdah.config="$WORK/ds.toml" -d howdah.log="$LOG" || { record $S detect_standard FAIL "down"; return; }
  r=$(cli_post 8102 FloodB0 "$WORK/flood_files.bin"); c=${r%%|*}
  if [ "$c" = 200 ] && grep -q '"action":"log"' "$LOG" && grep -q '"rule":"max_files"' "$LOG" && ! grep -q '"action":"block"' "$LOG"; then
    record $S detect_standard PASS "http=200 action=log"; else record $S detect_standard FAIL "http=$c $(tr -d '\n' <"$LOG"|head -c 120)"; fi
  cli_stop
  # detect_critical: mode=detect, over max_parts -> still 403
  : > "$LOG"
  printf 'mode="detect"\n[limits]\nmax_parts=2000\n' > "$WORK/dc.toml"
  cli_start 8103 -d extension="$WORK/howdah.so" -d howdah.config="$WORK/dc.toml" -d howdah.log="$LOG" || { record $S detect_critical FAIL "down"; return; }
  r=$(cli_post 8103 FloodB0 "$WORK/flood_fields.bin"); c=${r%%|*}; b=${r#*|}
  if echo "$c" | grep -qE '^(403|413)$' && grep -q '"action":"block"' "$LOG"; then record $S detect_critical PASS "http=$c";
  else record $S detect_critical FAIL "http=$c"; fi
  cli_stop
}

run_fpm() {
  S=fpm
  if ! ensure_fpm_tools; then for sc in shaped_block_files shaped_block_fields selftest up_progress_on up_progress_off detect_standard detect_critical; do record $S "$sc" SKIP "php-fpm/cgi-fcgi unavailable"; done; return; fi
  # defaults
  : > "$LOG"; fpm_start -d extension="$WORK/howdah.so" -d howdah.log="$LOG" || { record $S shaped_block_files FAIL "fpm down"; return; }
  r=$(fpm_post FloodB0 "$WORK/flood_files.bin" 203.0.113.9); assert_block $S shaped_block_files "${r%%|*}" "${r#*|}" max_files 203.0.113.9
  r=$(fpm_post FloodB0 "$WORK/flood_fields.bin" 203.0.113.9); assert_block $S shaped_block_fields "${r%%|*}" "${r#*|}" max_parts ""
  : > "$LOG"; r=$(fpm_post MarkerB0 "$WORK/marker.bin" 203.0.113.9); c=${r%%|*}
  if [ "$c" = 200 ] && grep -q '"rule":"self_test"' "$LOG"; then record $S selftest PASS "http=200"; else record $S selftest FAIL "http=$c"; fi
  for cf in "$CORPUS"/*.bin; do
    nm=$(basename "$cf" .bin); : > "$LOG"; r=$(fpm_post CorpusB0 "$cf" 203.0.113.9); c=${r%%|*}
    if [ "$c" = 200 ] && ! grep -q '"action":"block"' "$LOG"; then record $S "corpus_$nm" PASS "http=200 no block"; else record $S "corpus_$nm" FAIL "http=$c block=$(grep -c '"action":"block"' "$LOG")"; fi
  done
  fpm_stop
  for up in On Off; do
    : > "$LOG"; fpm_start -d extension="$WORK/howdah.so" -d howdah.log="$LOG" -d session.upload_progress.enabled="$up" -d session.upload_progress.name=PROGRESS || { record $S "up_progress_$(echo $up|tr A-Z a-z)" FAIL "down"; continue; }
    r=$(fpm_post FloodB0 "$WORK/flood_files.bin" 203.0.113.9); c=${r%%|*}
    if echo "$c" | grep -qE '^(403|413)$' && grep -q '"action":"block"' "$LOG"; then record $S "up_progress_$(echo $up|tr A-Z a-z)" PASS "http=$c"; else record $S "up_progress_$(echo $up|tr A-Z a-z)" FAIL "http=$c"; fi
    fpm_stop
  done
  : > "$LOG"; printf 'mode="block"\n[limits]\nmax_parts=100000\nmax_files=200\n[rules]\nmax_files="detect"\n' > "$WORK/ds.toml"
  fpm_start -d extension="$WORK/howdah.so" -d howdah.config="$WORK/ds.toml" -d howdah.log="$LOG" || { record $S detect_standard FAIL down; return; }
  r=$(fpm_post FloodB0 "$WORK/flood_files.bin" 203.0.113.9); c=${r%%|*}
  if [ "$c" = 200 ] && grep -q '"action":"log"' "$LOG" && ! grep -q '"action":"block"' "$LOG"; then record $S detect_standard PASS "http=200 log"; else record $S detect_standard FAIL "http=$c"; fi
  fpm_stop
  : > "$LOG"; printf 'mode="detect"\n[limits]\nmax_parts=2000\n' > "$WORK/dc.toml"
  fpm_start -d extension="$WORK/howdah.so" -d howdah.config="$WORK/dc.toml" -d howdah.log="$LOG" || { record $S detect_critical FAIL down; return; }
  r=$(fpm_post FloodB0 "$WORK/flood_fields.bin" 203.0.113.9); c=${r%%|*}
  if echo "$c" | grep -qE '^(403|413)$' && grep -q '"action":"block"' "$LOG"; then record $S detect_critical PASS "http=$c"; else record $S detect_critical FAIL "http=$c"; fi
  fpm_stop
}

for s in $SAPIS; do
  case "$s" in
    cli) run_cli ;;
    fpm) run_fpm ;;
    *)   record "$s" all SKIP "unsupported in this image" ;;
  esac
done
echo "== [$PHPVER] matrix rows ==" >&2
grep "^$PHPVER	" "$RESULTS" >&2 || true
