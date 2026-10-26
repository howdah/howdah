#!/bin/sh
# In-container half of the php-cgi argument-injection lab (see cgi_arg.sh):
# php-fpm with ONE static worker, driven over real HTTP through the nginx
# sidecar on 127.0.0.1:8080 (and, where cgi-fcgi exists, directly over FastCGI
# on 127.0.0.1:9000 for the byte-exact cases nginx/curl would normalise).
#
# What this proves, per PHP minor:
#   * the CVE-2012-1823 and CVE-2024-4577 query shapes get a CLEAN 403 (the
#     "Howdah blocked" body and a request id, the script's marker file never
#     written, the single worker keeps its pid, no reset/readv line in nginx's
#     error log) with the DEFAULT config, with howdah.mode = detect (the shipped
#     ini default), with howdah.mode = block, and on a clean POST body;
#   * the BENIGN query corpus (search strings, pagination, base64/JWT tokens,
#     framework arrays, `=`-less route queries, UTF-8 text, dash-leading words)
#     gets ZERO blocks and zero cgi_arg_injection events -- the mandatory
#     false-positive gate for an on-by-default blocking rule;
#   * the knobs: [inspect] cgi_arg = "detect" logs and lets the request run,
#     "off" and howdah.mode = off do nothing, an [[exceptions]] client_cidr
#     entry exempts a client;
#   * the event line never carries the query string.
#
# php-fpm is not itself exploitable by these CVEs (they need a CGI front end
# that passes the query string as argv); fpm is the harness because Howdah's
# check reads the SAPI's raw query string, which fpm, php-cgi, Apache and the
# CLI server all fill the same way, and fpm behind nginx is where the clean-403
# delivery is proven (PR #44).
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

# ---- the app: records that it ran (the marker) and its pid. It never reads
# $_SERVER, so with auto_globals_jit=On PHP never builds it: the rule must work
# from the SAPI's query string alone. -------------------------------------------
cat > "$APP/index.php" <<'PHP'
<?php
@file_put_contents('/work/marker/ran', (string) getmypid());
echo "OK pid=", getmypid(), " get=", count($_GET), " post=", count($_POST), "\n";
PHP

# ---- config fixtures ---------------------------------------------------------
printf '[inspect]\ncgi_arg = "detect"\n'                                             > "$WORK/detect.toml"
printf '[inspect]\ncgi_arg = "off"\n'                                                > "$WORK/off.toml"
printf 'mode = "block"\n[inspect]\nmode = "block"\n'                                 > "$WORK/allblock.toml"
printf '[[exceptions]]\nrule = "inspect.cgi_arg_injection"\nclient_cidr = "127.0.0.0/8"\nreason = "lab scanner"\n' > "$WORK/exc.toml"

# ---- corpora -----------------------------------------------------------------
# One request per line: "<GET|POST> <raw query string>" (no spaces in a query).
# POST carries a PHP payload body, as the public PoCs do (auto_prepend_file=
# php://input reads it).
cat > "$WORK/malicious.txt" <<'EOF'
POST -d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input
GET -d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input
GET -d+allow_url_include%3dtrue+-d+auto_prepend_file%3dphp://input
GET %2dd+allow_url_include%3d1+%2dd+auto_prepend_file%3dphp://input
GET %2Dd+allow_url_include%3D1+%2Dd+auto_prepend_file%3Dphp://input
GET -d%20allow_url_include%3d1%20-d%20auto_prepend_file%3dphp://input
GET -dauto_prepend_file%3dphp://input
GET --define+auto_prepend_file%3dphp://input
GET -n+-d+auto_prepend_file%3dphp://input
GET -s
GET -i
GET auto_prepend_file%3dphp://input
GET -c+/proc/self/fd/0
GET -r+phpinfo();
POST %ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
GET %ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
GET %adn+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
GET %C2%ADd+allow_url_include%3d1+%C2%ADd+auto_prepend_file%3dphp://input
GET %ADs
GET foo%ADbar
EOF
cat > "$WORK/benign.txt" <<'EOF'
GET q=hello+world
GET q=php+tutorial+for+beginners&page=3
GET page=2&per_page=50&sort=-date
GET sort=-created&order=desc
GET id=5
GET a=1&b=2&c=3
GET utm_source=news&utm_medium=email&utm_campaign=spring-sale
GET filter[name]=x&filter[tags][]=a&filter[tags][]=b
GET items[0][id]=1&items[0][qty]=2&items[1][id]=3
GET redirect=%2Fhome%3Fa%3Db
GET token=dGVzdA%3D%3D
GET data=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc-_def
GET q=garc%C3%ADa
GET q=%E4%B8%AD%E6%96%87
GET q=%F0%9F%98%80
GET q=-sale
GET range=-5..5
GET q=-d+is+a+php+flag
GET search=-dog+-cat
GET hello+world
GET how+to+reset+password
GET php+tutorial+for+beginners
GET -1
GET -5+10
GET -sale
GET -dog
GET -cat+-dog
GET -created
GET -name
GET -final.pdf
GET -
GET --
GET /users/12/edit
GET /blog/my-post
GET index.php/admin/dashboard
GET page/2
GET route/site/index
GET 2024-10-25
GET 2024-01-01..2024-12-31
GET my-post-title
GET v1.2.3-rc1
GET dGVzdA
GET dGVzdA%3D%3D
GET SGVsbG8gV29ybGQ
GET aGVsbG8%2Bd29ybGQ%2F
GET eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc-_def
GET -dGVzdA%3D%3D
GET garc%C3%ADa
GET %C3%ADndice
GET %E4%B8%AD%E6%96%87
GET %E6%97%A5%E6%9C%AC%E8%AA%9E
GET co%C2%ADoperate
GET http%3A%2F%2Fexample.com%2F%3Fa%3Db
GET q%3Dfoo
GET auto_prepend
GET allow_url
GET phpinfo
EOF
MAL_N=$(grep -c . "$WORK/malicious.txt"); BEN_N=$(grep -c . "$WORK/benign.txt")

# ---- php-fpm: one static worker, logs to /out/fpm.err ------------------------
FPMPID=""
fpm_start() { # extra -d ini ...
  cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $OUT/fpm.err
daemonize = no
[www]
; The dev images run as root and we pass php-fpm -R; older php-fpm (5.4)
; refuses to start a pool without an explicit user, so name it.
user = root
group = root
listen = 127.0.0.1:9000
pm = static
pm.max_children = 1
catch_workers_output = yes
EOF
  # shellcheck disable=SC2086
  php-fpm -R -F -y "$WORK/fpm.conf" -d extension="$WORK/howdah.so" -d howdah.log="$LOG" "$@" > "$WORK/fpm.out" 2>&1 &
  FPMPID=$!; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "php-fpm/nginx never answered 200" >&2; cat "$WORK/fpm.out" >&2; return 1; }; sleep 0.1
  done
}
fpm_stop() { [ -n "$FPMPID" ] && kill "$FPMPID" 2>/dev/null; wait "$FPMPID" 2>/dev/null; FPMPID=""; }

# ---- HTTP helpers --------------------------------------------------------------
B="$WORK/resp.txt"
qget()  { curl -s -m 30 --globoff -o "$B" -w '%{http_code}' "$URL/?$1" 2>/dev/null || echo 000; }
qpost() { curl -s -m 30 --globoff -o "$B" -w '%{http_code}' -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
            --data-binary "<?php echo 'PWNED'; ?>" "$URL/?$1" 2>/dev/null || echo 000; }
pid_now()   { curl -s -m 30 -o "$B" "$URL/" 2>/dev/null; sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' "$B" | head -1; }
ngx_bad()   { grep -cE 'readv\(\) failed|Connection reset|prematurely closed' "$OUT/nginx.err" 2>/dev/null || true; }
NGX0=0
reset()     { rm -f "$MARK"; : > "$LOG"; NGX0=$(ngx_bad); }
ngx_clean() { [ "$(ngx_bad)" = "$NGX0" ]; }
ngx_last()  { grep -E 'readv\(\) failed|Connection reset|prematurely closed' "$OUT/nginx.err" | tail -1 | cut -c1-140; }
# The event line must carry the rule and a fixed reason, never the query.
log_leaks() { grep -qiE 'auto_prepend_file|allow_url_include|php://input|%AD|%3d' "$LOG"; }

# refused_ok <http>: the full clean-403 contract for one request; echoes a reason on failure.
refused_why() {
  echo "$1" | grep -qE '^403$' || { echo "http=$1 (want 403)"; return; }
  grep -q 'Howdah blocked' "$B" || { echo "body lacks 'Howdah blocked'"; return; }
  grep -q 'request_id:' "$B" || { echo "no request_id in body"; return; }
  grep -q '"rule":"cgi_arg_injection"' "$LOG" || { echo "no cgi_arg_injection event ($(tr -d '\n' < "$LOG" | head -c 100))"; return; }
  grep -q '"action":"block"' "$LOG" || { echo "event is not a block"; return; }
  log_leaks && { echo "event line leaks the query"; return; }
  [ -f "$MARK" ] && { echo "script ran (marker written) despite the 403"; return; }
  ngx_clean || { echo "nginx logged a reset: $(ngx_last)"; return; }
  echo ""
}
# ran_why <http> [expect-event-action|none]: the request ran normally.
ran_why() {
  [ "$1" = 200 ] || { echo "http=$1 (want 200): $(head -c 80 "$B" | tr '\n' ' ')"; return; }
  [ -f "$MARK" ] || { echo "script did not run"; return; }
  grep -q '"action":"block"' "$LOG" && { echo "unexpected block event"; return; }
  case "${2:-none}" in
    none) grep -q '"rule":"cgi_arg_injection"' "$LOG" && { echo "unexpected cgi_arg_injection event"; return; } ;;
    *) grep -q '"rule":"cgi_arg_injection"' "$LOG" && grep -q "\"action\":\"$2\"" "$LOG" || { echo "no cgi_arg_injection '$2' event ($(tr -d '\n' < "$LOG" | head -c 100))"; return; }
       log_leaks && { echo "event line leaks the query"; return; } ;;
  esac
  ngx_clean || { echo "nginx logged a reset: $(ngx_last)"; return; }
  echo ""
}

# malicious_corpus <scenario> <pid0>: every line refused cleanly, worker survives.
malicious_corpus() {
  _sc=$1; _p0=$2; _n=0; _ok=0; _fails=""
  while read -r _m _q; do
    [ -z "$_q" ] && continue
    _n=$((_n+1)); reset
    if [ "$_m" = POST ]; then _c=$(qpost "$_q"); else _c=$(qget "$_q"); fi
    _w=$(refused_why "$_c")
    if [ -z "$_w" ]; then _ok=$((_ok+1)); else _fails="$_fails [$_m ?$_q: $_w]"; fi
  done < "$WORK/malicious.txt"
  _p1=$(pid_now)
  if [ "$_ok" = "$_n" ] && [ "$_p1" = "$_p0" ]; then
    record $S "$_sc" PASS "$_ok/$_n refused 403 before the script (clean body+request id, marker unwritten, event without the query), worker pid $_p0 unchanged, nginx clean"
  else
    record $S "$_sc" FAIL "$_ok/$_n refused; pid $_p0->$_p1;$(echo "$_fails" | cut -c1-300)"
  fi
}
# benign_corpus <scenario> <pid0>: every line runs; zero blocks, zero events.
benign_corpus() {
  _sc=$1; _p0=$2; _n=0; _ok=0; _blocked=0; _fails=""
  while read -r _m _q; do
    [ -z "$_q" ] && continue
    _n=$((_n+1)); reset
    _c=$(qget "$_q")
    _w=$(ran_why "$_c" none)
    if [ -z "$_w" ]; then _ok=$((_ok+1)); else
      _fails="$_fails [?$_q: $_w]"
      { [ "$_c" = 403 ] || grep -q '"action":"block"' "$LOG"; } && _blocked=$((_blocked+1))
    fi
  done < "$WORK/benign.txt"
  _p1=$(pid_now)
  if [ "$_blocked" = 0 ] && [ "$_ok" = "$_n" ] && [ "$_p1" = "$_p0" ]; then
    record $S "$_sc" PASS "$_blocked/$_n blocked, $_ok/$_n ran with no cgi_arg_injection event, worker pid $_p0 unchanged"
  else
    record $S "$_sc" FAIL "$_blocked/$_n blocked, $_ok/$_n ran;$(echo "$_fails" | cut -c1-400)"
  fi
}

POC='-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input'
POC24='%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input'

# ===== 1. DEFAULT config (no howdah.config, ini default mode): on by default
fpm_start || { record $S fpm_start FAIL "php-fpm/nginx down"; exit 1; }
P0=$(pid_now); reset
if echo "$P0" | grep -qE '^[0-9]+$'; then record $S baseline PASS "worker pid $P0 answers through nginx"; else record $S baseline FAIL "no pid in response"; fi
reset; c=$(qget "$POC");   w=$(refused_why "$c"); [ -z "$w" ] && record $S cve_2012_1823_default PASS "403 before the script, default config, pid $P0 unchanged" || record $S cve_2012_1823_default FAIL "$w"
reset; c=$(qget "$POC24"); w=$(refused_why "$c"); [ -z "$w" ] && record $S cve_2024_4577_default PASS "403 before the script, default config" || record $S cve_2024_4577_default FAIL "$w"
malicious_corpus malicious_corpus_default "$P0"
benign_corpus    benign_corpus_default    "$P0"
# The literal-`=` gate: attack TEXT with a literal `=` is form data to a CGI front
# end, never argv, so it is not this rule's business (Layer 2's content classes
# may still log it; they are detect-only here).
gate_ok=0; gate_n=0; gate_fail=""
for q in '-d+allow_url_include=1+-d+auto_prepend_file=php://input' '%ADd+allow_url_include=1' '-s=1' '-d+x=y'; do
  gate_n=$((gate_n+1)); reset; c=$(qget "$q"); w=$(ran_why "$c" none)
  if [ -z "$w" ]; then gate_ok=$((gate_ok+1)); else gate_fail="$gate_fail [?$q: $w]"; fi
done
if [ "$gate_ok" = "$gate_n" ]; then record $S literal_equals_gate PASS "$gate_ok/$gate_n attack-text queries with a literal '=' ran: not CGI argv, not this rule"; else record $S literal_equals_gate FAIL "$gate_ok/$gate_n;$gate_fail"; fi
# a second round on the same worker: per-request state resets cleanly after refusals
reset; c=$(qget "$POC"); w=$(refused_why "$c"); [ -z "$w" ] && record $S refused_again_same_worker PASS "refused again, pid $(pid_now)" || record $S refused_again_same_worker FAIL "$w"
reset; c=$(qget "q=hello"); w=$(ran_why "$c" none); [ -z "$w" ] && record $S benign_after_refusals PASS "next request on the same worker runs normally" || record $S benign_after_refusals FAIL "$w"
fpm_stop

# Byte-exact cases (a raw 0xAD on the wire, raw UTF-8): over direct FastCGI when
# cgi-fcgi exists (the CentOS-based 5.4/5.6 images do not have it), else as raw
# bytes in the request line through curl and nginx.
fpm_start || { record $S raw_start FAIL "php-fpm/nginx down"; exit 1; }
P0=$(pid_now)
if command -v cgi-fcgi >/dev/null 2>&1; then RS=fpm-cgifcgi; else RS=fpm-nginx-rawbytes; fi
rawq() { # <raw QUERY_STRING> -> status code in $FST, marker state in $FMK, response in $WORK/raw.out
  reset
  if [ "$RS" = fpm-cgifcgi ]; then
    env -i SCRIPT_FILENAME="$APP/index.php" SCRIPT_NAME=/index.php REQUEST_URI="/?x" QUERY_STRING="$1" REQUEST_METHOD=GET \
      REMOTE_ADDR=203.0.113.9 SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
      cgi-fcgi -bind -connect 127.0.0.1:9000 < /dev/null > "$WORK/raw.out" 2>/dev/null
    FST=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/raw.out" | head -1)
  else
    FST=$(curl -s -m 30 --globoff -o "$WORK/raw.out" -w '%{http_code}' "$URL/?$1" 2>/dev/null || echo 000)
  fi
  FMK=no; [ -f "$MARK" ] && FMK=yes
}
RAW_AD=$(printf '\255d+allow_url_include%%3d1+\255d+auto_prepend_file%%3dphp://input')
rawq "$RAW_AD"
if [ "$FST" = 403 ] && grep -q 'Howdah blocked' "$WORK/raw.out" && [ "$FMK" = no ] && grep -q '"rule":"cgi_arg_injection"' "$LOG" && [ "$(pid_now)" = "$P0" ]; then
  record $RS raw_0xAD_byte_on_the_wire PASS "status 403, body, script did not run, pid unchanged"
else record $RS raw_0xAD_byte_on_the_wire FAIL "status=$FST marker=$FMK pid=$P0->$(pid_now)"; fi
rawq "$POC"
if [ "$FST" = 403 ] && [ "$FMK" = no ] && grep -q '"rule":"cgi_arg_injection"' "$LOG" && [ "$(pid_now)" = "$P0" ]; then
  record $RS poc_raw_transport PASS "status 403, script did not run, pid unchanged"
else record $RS poc_raw_transport FAIL "status=$FST marker=$FMK"; fi
# UTF-8 text that CONTAINS a 0xAD byte (i-acute C3 AD, CJK E4 B8 AD) and has no `=`: must run.
rawq "garc%C3%ADa+$(printf '\303\255')ndice+$(printf '\344\270\255')"
if { [ "$FST" = 200 ] || [ -z "$FST" ]; } && [ "$FMK" = yes ] && ! grep -q '"rule":"cgi_arg_injection"' "$LOG"; then
  record $RS utf8_with_0xAD_byte_runs PASS "raw UTF-8 i-acute / CJK (0xAD continuation bytes) is not a soft hyphen: script ran"
else record $RS utf8_with_0xAD_byte_runs FAIL "status=$FST marker=$FMK"; fi
fpm_stop

# ===== 2. the shipped ini default (howdah.mode = detect) and an explicit block: still enforced
fpm_start -d howdah.mode=detect || { record $S detect_start FAIL down; exit 1; }
P0=$(pid_now)
malicious_corpus malicious_corpus_mode_detect "$P0"
fpm_stop
fpm_start -d howdah.config="$WORK/allblock.toml" || { record $S allblock_start FAIL down; exit 1; }
P0=$(pid_now)
malicious_corpus malicious_corpus_mode_block "$P0"
benign_corpus    benign_corpus_mode_block     "$P0"
fpm_stop

# ===== 3. the knobs
fpm_start -d howdah.config="$WORK/detect.toml" || { record $S knob_detect_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(qget "$POC24"); w=$(ran_why "$c" log); [ -z "$w" ] && record $S knob_cgi_arg_detect_logs_and_runs PASS "[inspect] cgi_arg = detect: logged, not refused, script ran" || record $S knob_cgi_arg_detect_logs_and_runs FAIL "$w"
fpm_stop
fpm_start -d howdah.config="$WORK/off.toml" || { record $S knob_off_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(qget "$POC24"); w=$(ran_why "$c" none); [ -z "$w" ] && record $S knob_cgi_arg_off_disables PASS "[inspect] cgi_arg = off: no event, script ran" || record $S knob_cgi_arg_off_disables FAIL "$w"
fpm_stop
fpm_start -d howdah.mode=off || { record $S knob_mode_off_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(qget "$POC24"); w=$(ran_why "$c" none); [ -z "$w" ] && record $S knob_howdah_mode_off_disables PASS "howdah.mode = off: no event, script ran" || record $S knob_howdah_mode_off_disables FAIL "$w"
fpm_stop
fpm_start -d howdah.config="$WORK/exc.toml" || { record $S knob_exc_start FAIL down; exit 1; }
P0=$(pid_now)
reset; c=$(qget "$POC24"); w=$(ran_why "$c" none); [ -z "$w" ] && record $S knob_exception_client_cidr PASS "[[exceptions]] inspect.cgi_arg_injection client_cidr: request ran, no block" || record $S knob_exception_client_cidr FAIL "$w"
fpm_stop

# ===== php-fpm log: no worker ever exited
if grep -qE 'exited with code|exited on signal|SIGSEGV' "$OUT/fpm.err"; then
  record $S fpm_no_worker_exits FAIL "$(grep -E 'exited with code|exited on signal|SIGSEGV' "$OUT/fpm.err" | head -2 | tr '\n' '|' | cut -c1-200)"
else
  record $S fpm_no_worker_exits PASS "no 'exited with code' / 'exited on signal' line in $OUT/fpm.err across $(grep -c 'fpm is running' "$OUT/fpm.err") php-fpm runs"
fi
echo "== [$PHPVER] php-fpm log ($OUT/fpm.err) ==" >&2; tail -20 "$OUT/fpm.err" >&2
echo "== [$PHPVER] nginx error log ($OUT/nginx.err) ==" >&2; tail -20 "$OUT/nginx.err" >&2
echo "corpora: $MAL_N malicious, $BEN_N benign" >&2
