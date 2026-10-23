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
# The app reads $_SERVER (as every real framework does): PHP's auto_globals_jit
# (On by default) materializes $_SERVER -- and thus the HTTP_* request-header
# vars our chained input_filter counts -- only on first access, so a script that
# never touches $_SERVER would hide the request-header limit entirely.
printf '<?php $n=count($_FILES)+count($_POST)+count($_SERVER); echo "OK n=$n\\n";' > "$WORK/index.php"

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

# ---- Task 9: input-shape / header / CGI fixtures --------------------------
# urlencoded bodies + small-limit config TOMLs for the per-rule BLOCK cases.
INCORPUS=/src/lab/integration/corpus/input
php -r 'for($i=0;$i<60;$i++){echo($i?"&":"")."v$i=$i";}' > "$WORK/iv.body"      # 60 input vars
printf 'a[b][c][d][e]=1' > "$WORK/nd.body"                                      # nesting depth 4
printf 'mode="block"\n[limits]\nmax_input_vars=50\n'            > "$WORK/iv.toml"
printf 'mode="detect"\n[limits]\nmax_input_vars=50\n'           > "$WORK/ivd.toml"
printf 'mode="block"\n[limits]\nmax_input_nesting_depth=3\n'    > "$WORK/nd.toml"
printf 'mode="block"\n[limits]\nmax_request_headers=5\n'        > "$WORK/rh.toml"
printf 'mode="detect"\n[limits]\nmax_request_headers=5\n'       > "$WORK/rhd.toml"
: > "$WORK/flood_hdr.txt"; i=0; while [ "$i" -lt 15 ]; do printf 'X-Flood-%s: v%s\n' "$i" "$i" >> "$WORK/flood_hdr.txt"; i=$((i+1)); done

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

# fpm_send <method> <ct-or-empty> <bodyfile-or-empty> <remote_addr> -> "HTTP|bodyfile"
fpm_send() {
  _o="$WORK/fresp.txt"
  if [ -n "$3" ]; then _cl=$(wc -c < "$3"); _in="$3"; else _cl=0; _in=/dev/null; fi
  if [ -n "$2" ]; then
    env -i SCRIPT_FILENAME="$WORK/index.php" SCRIPT_NAME=/index.php REQUEST_URI=/ \
      REQUEST_METHOD="$1" CONTENT_TYPE="$2" CONTENT_LENGTH="$_cl" REMOTE_ADDR="$4" \
      SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
      cgi-fcgi -bind -connect 127.0.0.1:9000 < "$_in" > "$WORK/fcgi.raw" 2>/dev/null
  else
    env -i SCRIPT_FILENAME="$WORK/index.php" SCRIPT_NAME=/index.php REQUEST_URI=/ \
      REQUEST_METHOD="$1" CONTENT_LENGTH="$_cl" REMOTE_ADDR="$4" \
      SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
      cgi-fcgi -bind -connect 127.0.0.1:9000 < "$_in" > "$WORK/fcgi.raw" 2>/dev/null
  fi
  _code=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/fcgi.raw" | head -1); [ -z "$_code" ] && _code=200
  awk 'f{print} /^\r?$/{f=1}' "$WORK/fcgi.raw" > "$_o"
  echo "$_code|$_o"
}
# fpm_get_query <querystring> <remote_addr> -> "HTTP|bodyfile"
fpm_get_query() {
  _o="$WORK/fresp.txt"
  env -i SCRIPT_FILENAME="$WORK/index.php" SCRIPT_NAME=/index.php REQUEST_URI="/?$1" QUERY_STRING="$1" \
    REQUEST_METHOD=GET REMOTE_ADDR="$2" SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
    cgi-fcgi -bind -connect 127.0.0.1:9000 < /dev/null > "$WORK/fcgi.raw" 2>/dev/null
  _code=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/fcgi.raw" | head -1); [ -z "$_code" ] && _code=200
  awk 'f{print} /^\r?$/{f=1}' "$WORK/fcgi.raw" > "$_o"
  echo "$_code|$_o"
}
# fpm_get_hdrs <headerfile> <remote_addr> -> "HTTP|bodyfile"
# Each "Name: value" line becomes a real HTTP_* server var (what every SAPI sees
# for a request header), so the chained input_filter's PARSE_SERVER calls count
# them -- the production path the CLI built-in server cannot exercise portably.
fpm_get_hdrs() {
  _o="$WORK/fresp.txt"; _hf=$1; _ra=$2   # save before `set --` clobbers $1/$2
  set -- SCRIPT_FILENAME="$WORK/index.php" SCRIPT_NAME=/index.php REQUEST_URI=/ \
    REQUEST_METHOD=GET REMOTE_ADDR="$_ra" SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1
  while IFS= read -r _l || [ -n "$_l" ]; do
    [ -z "$_l" ] && continue
    _n=${_l%%:*}; _v=${_l#*:}; _v=${_v# }
    _k=HTTP_$(echo "$_n" | tr 'a-z-' 'A-Z_')
    set -- "$@" "$_k=$_v"
  done < "$_hf"
  env -i "$@" cgi-fcgi -bind -connect 127.0.0.1:9000 < /dev/null > "$WORK/fcgi.raw" 2>/dev/null
  _code=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/fcgi.raw" | head -1); [ -z "$_code" ] && _code=200
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

# ---- Task 9 assertions ----------------------------------------------------
# The input/header path mitigates by DROPPING excess variables and emitting the
# block at RSHUTDOWN, so the HTTP 403 is best-effort (headers may already be
# sent once the script has produced output). The RELIABLE signal is the log
# line; assertions key off it and record the observed HTTP code in the detail.
# assert_logblock <sapi> <scenario> <http> <bodyfile> <rule>
assert_logblock() {
  _s=$1; _sc=$2; _http=$3; _rule=$5
  grep -q '"action":"block"' "$LOG" || { record "$_s" "$_sc" FAIL "no block line (http=$_http)"; return; }
  grep -q "\"rule\":\"$_rule\"" "$LOG" || { record "$_s" "$_sc" FAIL "rule != $_rule ($(tr -d '\n' <"$LOG"|head -c 120))"; return; }
  record "$_s" "$_sc" PASS "blocked rule=$_rule http=$_http (403 best-effort on input path)"
}
# assert_logdetect <sapi> <scenario> <http> <rule>: detect mode must LOG, not block.
assert_logdetect() {
  _s=$1; _sc=$2; _http=$3; _rule=$4
  if grep -q '"action":"block"' "$LOG"; then record "$_s" "$_sc" FAIL "blocked in detect mode (http=$_http)"; return; fi
  { grep -q '"action":"log"' "$LOG" && grep -q "\"rule\":\"$_rule\"" "$LOG"; } \
    || { record "$_s" "$_sc" FAIL "no log line rule=$_rule (http=$_http)"; return; }
  record "$_s" "$_sc" PASS "logged rule=$_rule http=$_http (detect)"
}
# assert_nofp <sapi> <name> <http>: a legit request must be 200 with zero blocks.
assert_nofp() {
  _s=$1; _n=$2; _http=$3
  if [ "$_http" = 200 ] && ! grep -q '"action":"block"' "$LOG"; then
    record "$_s" "fp_$_n" PASS "http=200 no block"
  else
    record "$_s" "fp_$_n" FAIL "http=$_http blocks=$(grep -c '"action":"block"' "$LOG")"
  fi
}
# cli_send <port> <method> <ct-or-empty> <bodyfile-or-empty> -> "HTTP|bodyfile"
cli_send() {
  _o="$WORK/resp.txt"
  if [ -n "$3" ]; then
    _c=$(curl -s -o "$_o" -w '%{http_code}' -X "$2" -H "Content-Type: $3" --data-binary @"$4" \
        "http://127.0.0.1:$1/" 2>/dev/null || echo 000)
  else
    _c=$(curl -s -o "$_o" -w '%{http_code}' -X "$2" "http://127.0.0.1:$1/" 2>/dev/null || echo 000)
  fi
  echo "$_c|$_o"
}
# cli_get_hdrs <port> <headerfile> -> "HTTP|bodyfile" (one "Name: value" per line)
cli_get_hdrs() {
  _o="$WORK/resp.txt"; _port=$1; _hf=$2
  set --
  while IFS= read -r _l || [ -n "$_l" ]; do [ -n "$_l" ] && set -- "$@" -H "$_l"; done < "$_hf"
  _c=$(curl -s -o "$_o" -w '%{http_code}' "$@" "http://127.0.0.1:$_port/" 2>/dev/null || echo 000)
  echo "$_c|$_o"
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

  # --- Task 9: input-shape rules (urlencoded POST; reachable on every SAPI) ---
  # input_vars_flood (Critical): blocks in block mode AND detect mode.
  : > "$LOG"; cli_start 8110 -d extension="$WORK/howdah.so" -d howdah.config="$WORK/iv.toml" -d howdah.log="$LOG" || { record $S input_vars_flood FAIL "down"; return; }
  r=$(cli_send 8110 POST application/x-www-form-urlencoded "$WORK/iv.body"); assert_logblock $S input_vars_flood "${r%%|*}" "${r#*|}" max_input_vars
  cli_stop
  : > "$LOG"; cli_start 8111 -d extension="$WORK/howdah.so" -d howdah.config="$WORK/ivd.toml" -d howdah.log="$LOG" || { record $S input_vars_flood_detect FAIL "down"; return; }
  r=$(cli_send 8111 POST application/x-www-form-urlencoded "$WORK/iv.body"); assert_logblock $S input_vars_flood_detect "${r%%|*}" "${r#*|}" max_input_vars
  cli_stop
  # nesting_depth (Critical).
  : > "$LOG"; cli_start 8112 -d extension="$WORK/howdah.so" -d howdah.config="$WORK/nd.toml" -d howdah.log="$LOG" || { record $S nesting_depth FAIL "down"; return; }
  r=$(cli_send 8112 POST application/x-www-form-urlencoded "$WORK/nd.body"); assert_logblock $S nesting_depth "${r%%|*}" "${r#*|}" max_input_nesting_depth
  cli_stop
  # request_headers_flood: the CLI built-in server's HTTP_* -> input_filter
  # routing is version-dependent (php8 populates it, php5 does not), so the
  # header limit is asserted under fpm + apache (real PARSE_SERVER), not here.
  record $S request_headers_flood SKIP "header counting asserted under fpm/apache (cli HTTP_* routing is version-dependent)"
  record $S request_headers_flood_detect SKIP "header counting asserted under fpm/apache"

  # --- Task 9: false-positive corpus (default limits, must be 200 + no block) ---
  : > "$LOG"; cli_start 8113 -d extension="$WORK/howdah.so" -d howdah.log="$LOG" || { record $S fp_setup FAIL "down"; return; }
  r=$(cli_send 8113 POST application/x-www-form-urlencoded "$INCORPUS/large_form.urlencoded"); assert_nofp $S large_form "${r%%|*}"
  : > "$LOG"; r=$(cli_send 8113 POST application/x-www-form-urlencoded "$INCORPUS/nested_form.urlencoded"); assert_nofp $S nested_form "${r%%|*}"
  : > "$LOG"; r=$(cli_get_hdrs 8113 "$INCORPUS/ordinary_headers.txt"); assert_nofp $S ordinary_headers "${r%%|*}"
  while IFS= read -r q || [ -n "$q" ]; do
    [ -z "$q" ] && continue; : > "$LOG"
    c=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8113/?$q" 2>/dev/null || echo 000)
    assert_nofp $S "query_$(echo "$q" | tr -c 'a-zA-Z0-9' _ | cut -c1-16)" "$c"
  done < "$INCORPUS/safe_queries.txt"
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

  # --- Task 9: input-shape rules over real php-fpm ---------------------------
  : > "$LOG"; fpm_start -d extension="$WORK/howdah.so" -d howdah.config="$WORK/iv.toml" -d howdah.log="$LOG" || { record $S input_vars_flood FAIL down; return; }
  r=$(fpm_send POST application/x-www-form-urlencoded "$WORK/iv.body" 203.0.113.9); assert_logblock $S input_vars_flood "${r%%|*}" "${r#*|}" max_input_vars
  fpm_stop
  : > "$LOG"; fpm_start -d extension="$WORK/howdah.so" -d howdah.config="$WORK/ivd.toml" -d howdah.log="$LOG" || { record $S input_vars_flood_detect FAIL down; return; }
  r=$(fpm_send POST application/x-www-form-urlencoded "$WORK/iv.body" 203.0.113.9); assert_logblock $S input_vars_flood_detect "${r%%|*}" "${r#*|}" max_input_vars
  fpm_stop
  : > "$LOG"; fpm_start -d extension="$WORK/howdah.so" -d howdah.config="$WORK/nd.toml" -d howdah.log="$LOG" || { record $S nesting_depth FAIL down; return; }
  r=$(fpm_send POST application/x-www-form-urlencoded "$WORK/nd.body" 203.0.113.9); assert_logblock $S nesting_depth "${r%%|*}" "${r#*|}" max_input_nesting_depth
  fpm_stop

  # --- Task 9: request-header count over real HTTP_* server vars (Standard:
  #     blocks in block mode, logs in detect mode) ---
  : > "$LOG"; fpm_start -d extension="$WORK/howdah.so" -d howdah.config="$WORK/rh.toml" -d howdah.log="$LOG" || { record $S request_headers_flood FAIL down; return; }
  r=$(fpm_get_hdrs "$WORK/flood_hdr.txt" 203.0.113.9); assert_logblock $S request_headers_flood "${r%%|*}" "${r#*|}" max_request_headers
  fpm_stop
  : > "$LOG"; fpm_start -d extension="$WORK/howdah.so" -d howdah.config="$WORK/rhd.toml" -d howdah.log="$LOG" || { record $S request_headers_flood_detect FAIL down; return; }
  r=$(fpm_get_hdrs "$WORK/flood_hdr.txt" 203.0.113.9); assert_logdetect $S request_headers_flood_detect "${r%%|*}" max_request_headers
  fpm_stop

  # --- Task 9: false-positive corpus at default limits -----------------------
  : > "$LOG"; fpm_start -d extension="$WORK/howdah.so" -d howdah.log="$LOG" || { record $S fp_setup FAIL down; return; }
  r=$(fpm_send POST application/x-www-form-urlencoded "$INCORPUS/large_form.urlencoded" 203.0.113.9); assert_nofp $S large_form "${r%%|*}"
  : > "$LOG"; r=$(fpm_send POST application/x-www-form-urlencoded "$INCORPUS/nested_form.urlencoded" 203.0.113.9); assert_nofp $S nested_form "${r%%|*}"
  : > "$LOG"; r=$(fpm_get_hdrs "$INCORPUS/ordinary_headers.txt" 203.0.113.9); assert_nofp $S ordinary_headers "${r%%|*}"
  while IFS= read -r q || [ -n "$q" ]; do
    [ -z "$q" ] && continue; : > "$LOG"
    r=$(fpm_get_query "$q" 203.0.113.9); assert_nofp $S "query_$(echo "$q" | tr -c 'a-zA-Z0-9' _ | cut -c1-16)" "${r%%|*}"
  done < "$INCORPUS/safe_queries.txt"
  fpm_stop
}

# --- Task 9: php-cgi argument-injection virtual patch (CVE-2012-1823) --------
# Runs ONLY where a real php-cgi binary exists (Ruling 10). The safe case
# (query carries a literal '='; RINIT fires and does NOT block) is a true
# false-positive guard. The FIRE case is recorded honestly: see the detail.
run_cgi() {
  command -v php-cgi >/dev/null 2>&1 || { record cgi cgi_available SKIP "no php-cgi binary in image"; return; }
  _sn=$(php-cgi -v 2>/dev/null | sed -n '1s/.*(\(cgi[^)]*\)).*/\1/p')
  cgi() { # $1 query -> echoes "HTTP|bodyfile"
    _o="$WORK/cgi.resp"
    env -i REDIRECT_STATUS=1 SCRIPT_FILENAME="$WORK/index.php" SCRIPT_NAME=/index.php \
      QUERY_STRING="$1" REQUEST_METHOD=GET SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
      REMOTE_ADDR=203.0.113.9 \
      php-cgi -d extension="$WORK/howdah.so" -d howdah.log="$LOG" > "$WORK/cgi.raw" 2>/dev/null
    _code=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/cgi.raw" | head -1); [ -z "$_code" ] && _code=200
    awk 'f{print} /^\r?$/{f=1}' "$WORK/cgi.raw" > "$_o"; echo "$_code|$_o"
  }
  # Safe: a legitimate query with a literal '=' must pass (no block, 200).
  : > "$LOG"; r=$(cgi 'q=a-b'); c=${r%%|*}
  if [ "$c" = 200 ] && ! grep -q '"action":"block"' "$LOG"; then record cgi cgi_arg_safe PASS "http=200 no block (sapi=$_sn)";
  else record cgi cgi_arg_safe FAIL "http=$c blocks=$(grep -c '"action":"block"' "$LOG")"; fi
  # Fire path: QUERY_STRING=-s (argv-injection shape). Observed: php-cgi consumes
  # the query as CLI args in its own startup, BEFORE any module request hook, so
  # the RINIT virtual patch is never reached (confirmed on php-cgi 5.4.16, which
  # is itself already patched). Record the real outcome; do NOT fake a PASS.
  : > "$LOG"; r=$(cgi '-s'); c=${r%%|*}
  if grep -q '"rule":"cgi_arg_injection"' "$LOG"; then
    record cgi cgi_arg_injection PASS "http=$c blocked (sapi=$_sn)"
  else
    record cgi cgi_arg_injection SKIP "fire-path not reached: php-cgi ($_sn) consumes argv-injection query before module RINIT; only patched php-cgi available (core-unit-tested)"
  fi
}

for s in $SAPIS; do
  case "$s" in
    cli) run_cli ;;
    fpm) run_fpm ;;
    *)   record "$s" all SKIP "unsupported in this image" ;;
  esac
done
# CGI virtual patch is SAPI-specific (needs the php-cgi binary); run it once per
# version regardless of the cli/fpm selection.
run_cgi
echo "== [$PHPVER] matrix rows ==" >&2
grep "^$PHPVER	" "$RESULTS" >&2 || true
