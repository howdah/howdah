#!/bin/sh
# In-container half of the T4 include/open wrapper-scheme firewall test.
# Runs inside a howdah-dev-php<ver> image using `php -r` CLI snippets.
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-wrap
LOG="$WORK/events.log"
SESS="$WORK/sess"
ERRLOG="$WORK/php_errors.log"
rm -rf "$WORK"; mkdir -p "$WORK" "$SESS"

VER=$(php -r 'echo PHP_VERSION;')
echo "== php $VER / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"

fail() {
  echo "FAIL: $1"
  echo "--- stdout ---"; cat "$WORK/out.txt" 2>/dev/null
  echo "--- stderr ---"; cat "$WORK/err.txt" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  exit 1
}

# run_php <toml-content> <php code> [extra -d args...]; stdout -> out.txt
run_php() {
  printf '%b' "$1" > "$WORK/t4.toml"
  code="$2"; shift 2
  : > "$LOG"
  php -d extension="$WORK/howdah.so" -d howdah.config="$WORK/t4.toml" \
      -d howdah.log="$LOG" -d session.save_path="$SESS" -d error_log="$ERRLOG" \
      "$@" -r "$code" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}

# The shipped posture: global detect, so a block here is the firewall's OWN
# default (block), independent of the global mode — exactly like xxe.
TOML='mode = "detect"\n'

# ---- (A) include/require firewall: every non-file wrapper is refused ----------
# cont_block <label> <payload> [extra -d...]: include the payload; it must be
# blocked (include_wrapper, action block), the script must CONTINUE, and the
# payload content must never reach the log.
cont_block() {
  _label="$1"; _payload="$2"; shift 2
  run_php "$TOML" "\$p='$_payload'; \$r=@include \$p; echo \"RET[\".var_export(\$r,true).\"] CONT\\n\";" "$@"
  grep -q 'CONT' "$WORK/out.txt" || fail "$_label: script did not continue after block"
  grep -q '"rule":"include_wrapper"' "$LOG" || fail "$_label: no include_wrapper event"
  grep -q '"action":"block"' "$LOG" || fail "$_label: no action:block"
  echo "  ok   - include $_label: refused, script continued, logged include_wrapper/block"
}

cont_block "php://filter chain" "php://filter/convert.base64-encode/resource=/etc/passwd"
# The target (filter spec + /etc/passwd) must never be logged.
if grep -q 'passwd' "$LOG"; then fail "php://filter: log leaked the target"; fi
cont_block "php://input"        "php://input"
cont_block "data:// inline"     "data://text/plain;base64,PD9waHAgZWNobyAxOw=="
if grep -q 'PD9waHA' "$LOG"; then fail "data://: log leaked the payload"; fi
cont_block "expect://"          "expect://id"
# Remote include with allow_url_include ON: the firewall, not PHP's own
# allow_url_include=0, does the refusing (no fetch is attempted).
cont_block "remote http"        "http://127.0.0.1:9/shell.txt" -d allow_url_include=1 -d allow_url_fopen=1
if grep -q '127.0.0.1' "$LOG"; then fail "remote: log leaked the host"; fi

# ---- (A) poisonable local targets -------------------------------------------
# /proc/self/environ and other /proc, the session dir, the error_log.
poison_block() {
  _label="$1"; _payload="$2"
  run_php "$TOML" "\$p='$_payload'; \$r=@include \$p; echo \"RET[\".var_export(\$r,true).\"] CONT\\n\";"
  grep -q 'CONT' "$WORK/out.txt" || fail "$_label: script did not continue"
  grep -q '"rule":"include_wrapper"' "$LOG" || fail "$_label: no include_wrapper event"
  grep -q '"action":"block"' "$LOG" || fail "$_label: no action:block"
  grep -q 'poisonable' "$LOG" || fail "$_label: reason not a poison category"
  echo "  ok   - include $_label: refused (poisonable local target), script continued"
}
poison_block "/proc/self/environ" "/proc/self/environ"
poison_block "session file"        "$SESS/sess_deadbeef"
poison_block "error_log"           "$ERRLOG"
# sec-review F5: evasions the poison classifier must now catch.
poison_block "file:// wrapper on /proc"   "file:///proc/self/environ"
poison_block "file:// wrapper on session" "file://$SESS/sess_filecafe"
poison_block "relative traversal to session" "..$SESS/sess_relcafe"

# ---- opcode mechanism (PHP 7.0+): the firewall must also enforce there --------
if [ "$FEATURE" != "php5" ]; then
  run_php 'mode = "detect"\n[sinks]\nhook = "opcode"\n' \
    "\$p='php://filter/resource=/etc/passwd'; \$r=@include \$p; echo \"RET[\".var_export(\$r,true).\"] CONT\\n\";"
  grep -q 'CONT' "$WORK/out.txt" || fail "opcode: script did not continue"
  grep -q '"rule":"include_wrapper"' "$LOG" || fail "opcode: no include_wrapper event"
  grep -q '"action":"block"' "$LOG" || fail "opcode: no action:block"
  echo "  ok   - include php://filter via the opcode mechanism: refused (7.0+)"
fi

# ---- (B) file-open firewall: dangerous wrappers refused, benign allowed -------
open_block() {
  _fn="$1"; _payload="$2"
  run_php "$TOML" "\$r=@$_fn('$_payload'); echo \"RET[\".var_export(\$r,true).\"] CONT\\n\";"
  grep -q 'CONT' "$WORK/out.txt" || fail "$_fn($_payload): script did not continue"
  grep -q '"rule":"file_open"' "$LOG" || fail "$_fn($_payload): no file_open event"
  grep -q '"action":"block"' "$LOG" || fail "$_fn($_payload): no action:block"
  echo "  ok   - $_fn dangerous wrapper: refused, script continued, logged file_open/block"
}
open_block "fopen"             "php://filter/resource=/etc/passwd"
open_block "file_get_contents" "data://text/plain;base64,eA=="
open_block "readfile"          "php://filter/convert.base64-encode/resource=/etc/passwd"
if grep -q 'passwd' "$LOG"; then fail "readfile: log leaked the target"; fi
open_block "readfile"          "/proc/self/environ"

open_allow() {
  _fn="$1"; _payload="$2"
  run_php "$TOML" "@$_fn('$_payload'); echo \"CONT\\n\";"
  grep -q 'CONT' "$WORK/out.txt" || fail "$_fn($_payload): script did not continue"
  if grep -q '"rule":"file_open"' "$LOG"; then fail "$_fn($_payload): false-positive file_open block"; fi
  echo "  ok   - $_fn $_payload: allowed (no file_open event)"
}
# php://input (read the body) and php://temp are legitimate; remote fetch is the
# SSRF sink's job, not this firewall's.
open_allow "file_get_contents" "php://input"
# fopen needs a mode; php://temp opened r+ is a common, legitimate pattern.
run_php "$TOML" "\$h=@fopen('php://temp','r+'); echo \"CONT\\n\";"
grep -q 'CONT' "$WORK/out.txt" || fail "fopen(php://temp): script did not continue"
if grep -q '"rule":"file_open"' "$LOG"; then fail "fopen(php://temp): false-positive file_open block"; fi
echo "  ok   - fopen php://temp (r+): allowed (no file_open event)"

# ---- (B) benign include corpus: ZERO blocks ----------------------------------
mkdir -p "$WORK/app/templates" "$WORK/app/src/Foo" "$WORK/app/vendor" "$WORK/app/php"
printf '<?php echo "INC_RAN\\n";' > "$WORK/app/templates/header.php"
printf '<?php echo "INC_RAN\\n";' > "$WORK/app/src/Foo/Bar.php"
printf '<?php echo "INC_RAN\\n";' > "$WORK/app/vendor/autoload.php"
printf '<?php echo "INC_RAN\\n";' > "$WORK/app/config.php"
printf '<?php echo "INC_RAN\\n";' > "$WORK/app/php/php-helper.php"   # name contains "php"

benign() {
  _label="$1"; _code="$2"
  run_php "$TOML" "$_code"
  grep -q 'INC_RAN' "$WORK/out.txt" || fail "benign $_label: file did not run"
  if grep -qE '"rule":"(include_wrapper|file_open)"' "$LOG"; then fail "benign $_label: false-positive block"; fi
  echo "  ok   - benign $_label: ran, zero firewall events"
}
# Absolute app path, relative template (cwd = app), autoloader-style, a path that
# merely contains "php", and a vendor autoload — all under a normal docroot.
benign "absolute config"   "include '$WORK/app/config.php';"
benign "relative template" "chdir('$WORK/app'); include 'templates/header.php';"
benign "autoloader path"   "include '$WORK/app/src/Foo/Bar.php';"
benign "vendor autoload"   "chdir('$WORK/app'); include 'vendor/autoload.php';"
benign "name contains php" "include '$WORK/app/php/php-helper.php';"
benign "readfile benign"   "readfile('$WORK/app/config.php'); echo '';"

# ---- 5.x warm-opcache caveat (documented, not withheld) ----------------------
if [ "$FEATURE" = "php5" ]; then
  echo "  note - php5.x: the firewall enforces at compile time via the compile-pointer swap;"
  echo "         an include served from a WARM opcache is not re-compiled and so is not"
  echo "         re-inspected (inherent 5.x caveat). Attack includes of a wrapper/poison"
  echo "         target are dynamic cache-misses, so they are compiled and seen."
fi

echo "PASS php $VER"
