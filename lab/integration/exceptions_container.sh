#!/bin/sh
# In-container half of the scoped [[exceptions]] integration test. Builds the
# real extension, writes HARMLESS-SHAPE fixtures (system('true'), a PHP file
# whose only content is a comment marker, a textbook SQLi string sent to a
# script that only counts its inputs), runs php with [[exceptions]] configs and
# asserts on rule ids, actions, HTTP status and `php --ri howdah` rows. The
# payload bytes must never appear in the log.
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-exc
LOG="$WORK/events.log"
rm -rf "$WORK"; mkdir -p "$WORK/www/app/sub" "$WORK/www/uploads"

echo "== php $(php -r 'echo PHP_VERSION;') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
cd "$WORK"

APP="$WORK/www/app"
UP="$WORK/www/uploads"
export APP UP
PASSN=0

fail() {
  echo "FAIL: $1"
  echo "--- stdout ---"; cat "$WORK/out.txt" 2>/dev/null
  echo "--- stderr ---"; cat "$WORK/err.txt" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  echo "--- server log ---"; cat "$WORK/server.log" 2>/dev/null
  exit 1
}
ok() { PASSN=$((PASSN+1)); echo "  ok   - $1"; }

has_rule() { grep -q "\"rule\":\"$1\"" "$LOG"; }
no_rule() { ! grep -q "\"rule\":\"$1\"" "$LOG"; }
has_action() { grep -q "\"action\":\"$1\"" "$LOG"; }
no_events() { ! grep -q . "$LOG"; }
out_has() { grep -q "$1" "$WORK/out.txt"; }

# ---------------------------------------------------------------- fixtures
cat > "$APP/cron.php" <<'PHPEOF'
<?php
$r = system('true');
echo "CRON_RAN[" . ($r === false ? 'blocked' : 'ok') . "]\n";
echo "FILE=" . __FILE__ . "\n";
PHPEOF
cat > "$APP/other.php" <<'PHPEOF'
<?php
$r = system('true');
echo "OTHER_RAN[" . ($r === false ? 'blocked' : 'ok') . "]\n";
PHPEOF
cat > "$APP/sub/deep.php" <<'PHPEOF'
<?php
$r = system('true');
echo "DEEP_RAN[" . ($r === false ? 'blocked' : 'ok') . "]\n";
PHPEOF
# Layer 2 / Layer 1 target: counts inputs, echoes nothing from them. Touching
# $_SERVER materialises it (auto_globals_jit), which is what makes the
# request-header rules see the headers on the built-in server.
cat > "$WORK/www/index.php" <<'PHPEOF'
<?php
echo "OK get=" . count($_GET) . " post=" . count($_POST) . " srv=" . (count($_SERVER) > 0 ? 'y' : 'n') . "\n";
PHPEOF
# Layer 4: two scripts that write a comment-only .php into the uploads dir.
for S in compile dropper; do
cat > "$APP/$S.php" <<'PHPEOF'
<?php
$t = getenv('UP') . '/x.php';
$r = @file_put_contents($t, '<?php /* howdah-exc-test */');
echo "WRITE_RET[" . ($r === false ? 'false' : 'ok') . "]\n";
PHPEOF
done
ln -s "$APP" "$WORK/www/link"
CRON_SHA=$(sha256sum "$APP/cron.php" | cut -d' ' -f1)

# ---------------------------------------------------------------- runners
# run_file <toml> <script> : CLI run; stdout -> out.txt, stderr -> err.txt.
run_file() {
  printf '%b' "$1" > "$WORK/exc.toml"
  file="$2"; shift 2
  : > "$LOG"
  php -d extension="$WORK/howdah.so" \
      -d howdah.config="$WORK/exc.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      "$@" "$file" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}
# ri <toml> : `php --ri howdah` with the config; stdout -> out.txt, stderr -> err.txt.
ri() {
  printf '%b' "$1" > "$WORK/exc.toml"
  php -d extension="$WORK/howdah.so" -d howdah.config="$WORK/exc.toml" -d howdah.log="$LOG" \
      --ri howdah > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}

SRV=""
PORT=18240
stop_server() {
  if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; fi
  SRV=""
}
trap 'stop_server' EXIT
start_server() {
  stop_server
  printf '%b' "$1" > "$WORK/exc.toml"
  : > "$LOG"
  PORT=$((PORT+1))
  php -d extension="$WORK/howdah.so" \
      -d howdah.config="$WORK/exc.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      -S "127.0.0.1:$PORT" -t "$WORK/www" > "$WORK/server.log" 2>&1 &
  SRV=$!
  _j=0
  until curl -s -o /dev/null "http://127.0.0.1:$PORT/index.php" 2>/dev/null; do
    _j=$((_j+1)); [ $_j -gt 60 ] && fail "built-in server did not start"
    sleep 0.1
  done
  : > "$LOG"
}
# get <query-key> <value> -> CODE, body in out.txt
get() {
  : > "$LOG"
  set +e
  CODE=$(curl -s -o "$WORK/out.txt" -w '%{http_code}' -G --data-urlencode "$1=$2" "http://127.0.0.1:$PORT/index.php")
  set -e
  : > "$WORK/err.txt"
}
# post <key> <value> -> CODE, body in out.txt (a POST body is not part of the request path)
post() {
  : > "$LOG"
  set +e
  CODE=$(curl -s -o "$WORK/out.txt" -w '%{http_code}' --data-urlencode "$1=$2" "http://127.0.0.1:$PORT/index.php")
  set -e
  : > "$WORK/err.txt"
}

SINKBLOCK='mode="detect"\n[sinks]\nmode="block"\n'
EXC_CRON='[[exceptions]]\nrule="sinks.command_exec"\nscript="'"$APP"'/cron.php"\nreason="lab: cron mailer"\n'

# ============================================================ (a) sink by script
run_file "$SINKBLOCK$EXC_CRON" "$APP/cron.php"
out_has 'CRON_RAN\[ok\]' || fail "a1: excepted script's system() was blocked"
no_events || fail "a1: excepted call produced an event"
ok "(a) command_exec block + script exception: matching script runs system('true'), no event, not blocked"
run_file "$SINKBLOCK$EXC_CRON" "$APP/other.php"
out_has 'OTHER_RAN\[blocked\]' || fail "a2: other script's system() was not blocked"
has_rule command_exec || fail "a2: no command_exec event for the other script"
has_action block || fail "a2: no block action"
ok "(a) same call from another script: blocked and logged (rule=command_exec action=block)"
# Other sink from the excepted script: not covered.
cat > "$APP/cron_eval.php" <<'PHPEOF'
<?php
$r = eval('return 1;');
echo "EVAL[" . ($r === null ? 'blocked' : 'ok') . "]\n";
PHPEOF
run_file "$SINKBLOCK"'[[exceptions]]\nrule="sinks.command_exec"\nscript="'"$APP"'/cron_eval.php"\nreason="lab"\n' "$APP/cron_eval.php"
has_rule eval || fail "a3: eval from the excepted script was not logged (exception leaked to another sink)"
ok "(a) an exception on sinks.command_exec does not cover eval from the same script"
# Glob.
run_file "$SINKBLOCK"'[[exceptions]]\nrule="sinks.command_exec"\nscript="'"$APP"'/sub/*.php"\nreason="lab glob"\n' "$APP/sub/deep.php"
out_has 'DEEP_RAN\[ok\]' || fail "a4: glob did not match sub/deep.php"
no_events || fail "a4: glob-excepted call produced an event"
run_file "$SINKBLOCK"'[[exceptions]]\nrule="sinks.command_exec"\nscript="'"$APP"'/sub/*.php"\nreason="lab glob"\n' "$APP/cron.php"
out_has 'CRON_RAN\[blocked\]' || fail "a5: glob sub/*.php matched app/cron.php"
ok "(a) glob script facet: $APP/sub/*.php matches sub/deep.php and not cron.php"
# Hash.
EXC_SHA='[[exceptions]]\nrule="command_exec"\nscript_sha256="'"$CRON_SHA"'"\nreason="lab hash"\n'
run_file "$SINKBLOCK$EXC_SHA" "$APP/cron.php"
out_has 'CRON_RAN\[ok\]' || fail "a6: sha256 exception did not match cron.php"
no_events || fail "a6: hash-excepted call produced an event"
run_file "$SINKBLOCK$EXC_SHA" "$APP/other.php"
out_has 'OTHER_RAN\[blocked\]' || fail "a7: sha256 exception matched a different file"
cp "$APP/cron.php" "$WORK/cron.bak"
printf '// edited\n' >> "$APP/cron.php"
run_file "$SINKBLOCK$EXC_SHA" "$APP/cron.php"
out_has 'CRON_RAN\[blocked\]' || fail "a8: edited cron.php still matched its old hash"
cp "$WORK/cron.bak" "$APP/cron.php"
ok "(a) script_sha256 facet: matches the pinned bytes, not another file, and not the file once edited"
# Symlink, CLI main script: PHP opens the primary script through its stream
# layer, whose opened_path is realpath'd, so __FILE__ is the TARGET. Asserted
# (not branched): a change here is a documentation change.
run_file "$SINKBLOCK$EXC_CRON" "$WORK/www/link/cron.php"
REPORTED=$(sed -n 's/^FILE=//p' "$WORK/out.txt")
[ "$REPORTED" = "$APP/cron.php" ] || fail "a9: CLI main script via symlink reported __FILE__=$REPORTED, expected the realpath $APP/cron.php (update docs/exceptions.md if PHP changed)"
out_has 'CRON_RAN\[ok\]' || fail "a9: realpath-reported script did not match the realpath exception"
run_file "$SINKBLOCK"'[[exceptions]]\nrule="sinks.command_exec"\nscript="'"$WORK"'/www/link/cron.php"\nreason="lab symlink"\n' "$WORK/www/link/cron.php"
out_has 'CRON_RAN\[blocked\]' || fail "a10: an exception pinned to the symlink path matched (PHP reports the target)"
ok "(a) symlink, CLI main script: __FILE__ is the resolved target ($REPORTED); the exception must name the target, the symlink path does not match"
# Symlink, required file: zend_resolve_path realpath's includes too.
cat > "$APP/entry_link.php" <<'PHPEOF'
<?php
require getenv('WORK') . '/www/link/sub/deep.php';
echo "ENTRY_DONE\n";
PHPEOF
export WORK
run_file "$SINKBLOCK"'[[exceptions]]\nrule="sinks.command_exec"\nscript="'"$APP"'/sub/deep.php"\nreason="lab symlink require"\n' "$APP/entry_link.php"
out_has 'DEEP_RAN\[ok\]' || fail "a11: required file via symlink did not match its realpath exception"
out_has ENTRY_DONE || fail "a11: entry did not finish"
ok "(a) symlink, required file: the include is realpath'd, the realpath exception matches"

# ============================================================ (e) exceptions_log
run_file 'exceptions_log = true\n'"$SINKBLOCK$EXC_CRON" "$APP/cron.php"
out_has 'CRON_RAN\[ok\]' || fail "e1: excepted call blocked with exceptions_log on"
has_rule command_exec || fail "e1: no excepted line"
has_action excepted || fail "e1: no action:excepted"
grep -q 'exception #0 (sinks.command_exec): lab: cron mailer' "$LOG" || fail "e1: excepted reason not in the expected form"
if has_action block || has_action log; then fail "e1: excepted call also logged/blocked"; fi
ok "(e) exceptions_log = true: the excepted call writes one action:excepted line naming exception #0 and its reason"

# ============================================================ (f) php --ri counts
ri "$SINKBLOCK$EXC_CRON$EXC_SHA"
out_has 'Exceptions (\[\[exceptions\]\]) => 2 configured, 0 rejected' || fail "f1: --ri row missing or wrong"
out_has 'Config status => ok' || fail "f1: config status not ok"
grep -q '2 exception(s) active' "$WORK/err.txt" || fail "f1: no startup summary line on stderr"
ok "(f) php --ri howdah: 'Exceptions ([[exceptions]]) => 2 configured, 0 rejected' and the startup summary line"

# ============================================================ (d) Critical rule rejected
CRIT='mode="detect"\n[[exceptions]]\nrule="max_parts"\nuri_prefix="/"\nreason="lab: must be refused"\n'
ri "$CRIT"
out_has 'Config status => INVALID (fell back to block)' || fail "d1: Critical exception did not invalidate the config"
out_has 'exceptions\[0\].rule' || fail "d1: INVALID row does not name exceptions[0].rule"
out_has 'Exceptions (\[\[exceptions\]\]) => 0 configured, 1 rejected' || fail "d1: rejected count not shown"
grep -q "is invalid, running in block mode" "$WORK/err.txt" || fail "d1: no loud startup error"
grep -q 'exceptions\[0\].rule' "$WORK/err.txt" || fail "d1: startup error does not name the entry"
ok "(d) a Critical-rule exception is rejected at startup: loud error naming exceptions[0].rule, INVALID status, fallback block, '0 configured, 1 rejected'"
ri 'on_invalid_config = "off"\n'"$CRIT"
out_has 'INVALID (fell back to off)' || fail "d2: on_invalid_config=off not honoured"
ok "(d) with on_invalid_config = \"off\" the same rejection falls back to off"
# A Layer 2 script facet is refused with the uri_prefix hint.
ri 'mode="detect"\n[[exceptions]]\nrule="sql_injection"\nscript="/a.php"\nreason="lab"\n'
out_has 'exceptions\[0\].script' || fail "d3: Layer 2 script facet not refused"
out_has 'uri_prefix' || fail "d3: refusal does not point at uri_prefix"
ok "(d) a script facet on a Layer 2 rule is refused and the message points at uri_prefix"

# ============================================================ (b) Layer 2 param
SQLI="' OR 1=1 --"
L2='mode="detect"\n[inspect]\nmode="detect"\n[[exceptions]]\nrule="inspect.sql_injection"\nparam="q"\nreason="lab: editors paste SQL"\n'
start_server "$L2"
post q "$SQLI"
[ "$CODE" = 200 ] || fail "b1: expected 200, got $CODE"
out_has '^OK ' || fail "b1: app did not run"
no_events || fail "b1: excepted param produced an event"
ok "(b) param exception: sql_injection in excepted POST parameter q -> no event"
post other "$SQLI"
has_rule sql_injection || fail "b2: sql_injection in another parameter not logged"
has_action log || fail "b2: expected action:log"
ok "(b) the same payload in another parameter is still logged"
post q "../../etc/passwd"
has_rule path_traversal || fail "b3: path_traversal in the excepted parameter was silenced (exception leaked across rules)"
ok "(b) the exception silences one rule only: path_traversal in q is still logged"
# A GET value is also part of the request path, which Layer 2 scans as the
# pseudo-parameter REQUEST_URI on SAPIs that register it through the input
# filter (php-fpm, Apache, php -S before 8.0). The `q` finding is excepted
# either way; the path-source finding, if any, names REQUEST_URI (documented
# in docs/exceptions.md).
get q "$SQLI"
if grep -q "variable 'q'" "$LOG"; then fail "b4: GET parameter q was not excepted"; fi
if grep -q "REQUEST_URI" "$LOG"; then _p="also a path-source (REQUEST_URI) finding on this SAPI/version"; else _p="no path-source finding on this SAPI/version"; fi
ok "(b) the same payload as GET ?q=: the q finding is excepted; $_p"
if grep -q "1=1\|etc/passwd" "$LOG"; then fail "b: payload bytes leaked into the log"; fi
stop_server

# ============================================================ (i) uri_prefix cannot be stepped into
# nginx (and the built-in server) pass the request path as sent; `--path-as-is`
# keeps the dot segments on the wire. /wp-admin/../index.php executes
# /index.php: it must NOT satisfy uri_prefix = "/wp-admin/" (fail toward
# protection), while a plain /index.php under its own prefix is excepted.
mkdir -p "$WORK/www/wp-admin"
cp "$WORK/www/index.php" "$WORK/www/wp-admin/post.php"
URIX='mode="detect"\n[inspect]\nmode="detect"\n[[exceptions]]\nrule="inspect.sql_injection"\nuri_prefix="/wp-admin/"\nreason="lab: admin editors"\n'
start_server "$URIX"
post_path() { # <path> <key> <value>
  : > "$LOG"
  set +e
  CODE=$(curl -s --path-as-is -o "$WORK/out.txt" -w '%{http_code}' --data-urlencode "$2=$3" "http://127.0.0.1:$PORT$1")
  set -e
  : > "$WORK/err.txt"
}
post_path /wp-admin/post.php q "$SQLI"
out_has '^OK ' || fail "i1: admin page did not run"
if grep -q "\"rule\":\"sql_injection\"" "$LOG" && grep -q "variable 'q'" "$LOG"; then fail "i1: plain /wp-admin/ request was not excepted"; fi
for TRICK in '/wp-admin/../index.php' '/wp-admin/./../index.php' '/wp-admin//../index.php' '/wp-admin/%2e%2e/index.php'; do
  post_path "$TRICK" q "$SQLI"
  out_has '^OK ' || fail "i2: $TRICK did not reach index.php ($CODE)"
  grep -q "sql_injection pattern in post variable 'q'" "$LOG" || fail "i2: $TRICK satisfied uri_prefix=/wp-admin/ and silenced the q finding"
done
ok "(i) uri_prefix: /wp-admin/post.php is excepted; /wp-admin/../index.php, /./, // and %2e%2e variants reach index.php and are NOT excepted"
stop_server

# ============================================================ (c) Layer 1 Standard by client_cidr
# `client_cidr` is REMOTE_ADDR as the SAPI reports it. php-fpm (like Apache)
# answers `sapi_getenv("REMOTE_ADDR")` before any request variable is parsed,
# so the client is known when a Layer 1 rule fires. The CLI built-in server
# does not implement sapi_getenv and (on 8.x) registers REMOTE_ADDR without
# the input filter, so `php -S` cannot exercise this facet; it is driven here
# through real php-fpm + cgi-fcgi (the matrix lab's production path), with the
# built-in-server behaviour recorded as information only.
ensure_fpm_tools() {
  command -v php-fpm >/dev/null 2>&1 || { echo "no php-fpm" >&2; return 1; }
  command -v cgi-fcgi >/dev/null 2>&1 && return 0
  apt-get -o Acquire::Check-Valid-Until=false update >/tmp/apt.u 2>&1 \
    && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends --allow-unauthenticated libfcgi-bin >/tmp/apt.i 2>&1
  command -v cgi-fcgi >/dev/null 2>&1
}
FPMPID=""
fpm_start() { # $1 toml
  printf '%b' "$1" > "$WORK/exc.toml"
  : > "$LOG"
  cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $WORK/fpm.err
daemonize = no
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 2
catch_workers_output = yes
EOF
  php-fpm -R -F -y "$WORK/fpm.conf" -d extension="$WORK/howdah.so" -d howdah.config="$WORK/exc.toml" \
      -d howdah.log="$LOG" > "$WORK/fpm.out" 2>&1 &
  FPMPID=$!; _j=0
  while ! env -i SCRIPT_FILENAME="$WORK/www/index.php" SCRIPT_NAME=/index.php \
      REQUEST_METHOD=GET REQUEST_URI=/index.php SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
      cgi-fcgi -bind -connect 127.0.0.1:9000 >/dev/null 2>&1; do
    _j=$((_j+1)); [ "$_j" -gt 60 ] && fail "php-fpm did not start"; sleep 0.1; done
  : > "$LOG"
}
fpm_stop() { if [ -n "$FPMPID" ]; then kill "$FPMPID" 2>/dev/null || true; wait "$FPMPID" 2>/dev/null || true; fi; FPMPID=""; }
trap 'stop_server; fpm_stop' EXIT
# fpm_hdrs <remote_addr> : GET /index.php with 8 extra request headers -> CODE, body in out.txt
fpm_hdrs() {
  : > "$LOG"
  env -i SCRIPT_FILENAME="$WORK/www/index.php" SCRIPT_NAME=/index.php REQUEST_URI=/index.php \
    REQUEST_METHOD=GET REMOTE_ADDR="$1" SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
    HTTP_X_A=1 HTTP_X_B=2 HTTP_X_C=3 HTTP_X_D=4 HTTP_X_E=5 HTTP_X_F=6 HTTP_X_G=7 HTTP_X_H=8 \
    cgi-fcgi -bind -connect 127.0.0.1:9000 < /dev/null > "$WORK/fcgi.raw" 2>/dev/null || true
  CODE=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/fcgi.raw" | head -1); [ -z "$CODE" ] && CODE=200
  awk 'f{print} /^\r?$/{f=1}' "$WORK/fcgi.raw" > "$WORK/out.txt"
  : > "$WORK/err.txt"
}
# fpm_query <querystring> <remote_addr>
fpm_query() {
  : > "$LOG"
  env -i SCRIPT_FILENAME="$WORK/www/index.php" SCRIPT_NAME=/index.php REQUEST_URI="/index.php?$1" QUERY_STRING="$1" \
    REQUEST_METHOD=GET REMOTE_ADDR="$2" SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
    cgi-fcgi -bind -connect 127.0.0.1:9000 < /dev/null > "$WORK/fcgi.raw" 2>/dev/null || true
  CODE=$(sed -n 's/^Status: *\([0-9][0-9][0-9]\).*/\1/p' "$WORK/fcgi.raw" | head -1); [ -z "$CODE" ] && CODE=200
  awk 'f{print} /^\r?$/{f=1}' "$WORK/fcgi.raw" > "$WORK/out.txt"
  : > "$WORK/err.txt"
}
ensure_fpm_tools || fail "c: php-fpm / cgi-fcgi not available in this image"
L1='mode="block"\n[limits]\nmax_request_headers=5\nmax_input_key_bytes=8\n'
fpm_start "$L1"'[[exceptions]]\nrule="limits"\nclient_cidr="10.0.0.0/8"\nreason="lab: internal proxy adds headers and long keys"\n'
fpm_hdrs 10.1.2.3
[ "$CODE" = 200 ] || fail "c1: expected 200 for the excepted client, got $CODE"
out_has '^OK ' || fail "c1: app did not run"
no_events || fail "c1: excepted client produced an event"
ok "(c) php-fpm, Layer 1 Standard (max_request_headers=5, block): 8 extra headers from 10.1.2.3 with client_cidr 10.0.0.0/8 -> 200, no event"
fpm_hdrs 203.0.113.9
has_rule max_request_headers || fail "c2: non-matching client: no event"
has_action block || fail "c2: non-matching client: no block action"
grep -q '"client_ip":"203.0.113.9"' "$LOG" || fail "c2: client_ip not in the line"
echo "  info - c2 HTTP status $CODE (the Layer 1 input-path 403 is best-effort; the event is the guarantee)"
ok "(c) php-fpm: the same request from 203.0.113.9 -> rule applies (event, action=block, client_ip in the line)"
fpm_query "averyveryveryverylongkeyname=1" 10.9.9.9
[ "$CODE" = 200 ] || fail "c3: expected 200, got $CODE"
out_has 'get=1' || fail "c3: the long key was dropped despite the exception"
no_events || fail "c3: excepted client produced an input-variable event"
fpm_query "averyveryveryverylongkeyname=1" 198.51.100.7
has_rule max_input_key_bytes || fail "c4: non-matching client: no input-variable event"
out_has 'get=0' || fail "c4: the over-long key was not dropped"
ok "(c) php-fpm, input-variable rule (max_input_key_bytes=8): excepted client keeps the variable with no event; another client is dropped and logged"
fpm_stop
# Information only: under `php -S` the client is unknown when the request
# variables are parsed (no sapi_getenv; on 8.x REMOTE_ADDR bypasses the input
# filter), so client_cidr cannot match there. Not a production SAPI.
start_server 'mode="block"\n[limits]\nmax_input_key_bytes=8\n[[exceptions]]\nrule="max_input_key_bytes"\nclient_cidr="127.0.0.0/8"\nreason="lab: php -S information"\n'
get averyveryveryverylongkeyname 1
_ip=$(sed -n 's/.*"client_ip":"\([^"]*\)".*/\1/p' "$LOG" | head -1)
echo "  info - php -S: GET-variable rule fired=$(has_rule max_input_key_bytes && echo yes || echo no), client_ip seen at that point='${_ip}' (documented limit of the built-in server)"
stop_server

# ============================================================ (g) Layer 4 php_write by script
L4='mode="detect"\n[behavior]\nmode="block"\ndeny_php_writes=true\ndeny_exec_dirs=["'"$UP"'"]\n[[exceptions]]\nrule="behavior.php_write"\nscript="'"$APP"'/compile.php"\nreason="lab: template compiler"\n'
rm -f "$UP/x.php"
run_file "$L4" "$APP/compile.php"
out_has 'WRITE_RET\[ok\]' || fail "g1: excepted compiler's write was refused"
[ -f "$UP/x.php" ] || fail "g1: file not written"
no_events || fail "g1: excepted write produced an event"
rm -f "$UP/x.php"
run_file "$L4" "$APP/dropper.php"
out_has 'WRITE_RET\[false\]' || fail "g2: dropper's write was not refused"
has_rule php_write || fail "g2: no php_write event"
has_action block || fail "g2: no block"
[ ! -f "$UP/x.php" ] || fail "g2: file written despite block"
ok "(g) behavior.php_write block + script exception: compile.php writes (no event), dropper.php is refused and logged"

# ---- privacy guard --------------------------------------------------------
if grep -q "howdah-exc-test\|1=1\|etc/passwd" "$LOG"; then fail "payload bytes leaked into the log"; fi
echo "PASS ($PASSN checks, $FEATURE)"
