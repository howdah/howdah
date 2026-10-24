#!/bin/sh
# In-container half of the self-test integration test (inside howdah-dev-php*).
# Builds the extension, serves a trivial PHP app with Howdah loaded, runs
# `howdah-check web` and asserts, in BOTH global modes:
#   - the marker request is flagged: HTTP 200 (never blocked), a self_test
#     action=log line in the event log, and the printed id appears in the log;
#   - the over-limit multipart is BLOCKED (403/413), with its id in the log;
#   - ordinary traffic (a normal form) writes NO self_test line.
# LOAD_EXT=0 skips the extension (RED).
# PREINSTALLED=1 builds nothing: the PHP in this container already loads
# howdah from its own ini (a docker/Dockerfile image), so the server starts
# without `-d extension=` and the installed, released howdah.so is what runs.
set -eu

FEATURE="${1:-php7}"
LOAD_EXT="${LOAD_EXT:-1}"
PREINSTALLED="${PREINSTALLED:-0}"
HC="${HC:-/src/tools/howdah-check}"
WORK=/tmp/howdah-st
LOGDIR=/var/log/howdah
LOG="$LOGDIR/events.log"
SRV=""
rm -rf "$WORK"; mkdir -p "$WORK" "$LOGDIR"; : > "$LOG"

if [ "$PREINSTALLED" = 1 ]; then
  echo "== using the installed howdah (PHP $(php -r 'echo PHP_VERSION;'), howdah $(php -r 'echo phpversion("howdah");')) =="
  php -m | grep -qx howdah || { echo "FAIL: PREINSTALLED=1 but php -m does not list howdah"; exit 1; }
else
  echo "== building howdah-ext ($FEATURE) =="
  export CARGO_TARGET_DIR=/tmp/t
  cd /src
  cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
  cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
fi

printf '<?php\n$n = count($_FILES) + count($_POST);\necho "OK n=$n\\n";\n' > "$WORK/index.php"

fail() {
  echo "FAIL: $1"
  echo "--- web output ---"; cat "$WORK/web.out" 2>/dev/null
  echo "--- server.log ---"; tail -20 "$WORK"/server.*.log 2>/dev/null
  echo "--- event log ---"; tail -5 "$LOG" 2>/dev/null
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
  exit 1
}

# run_mode <port> <mode>
run_mode() {
  _port=$1; _mode=$2
  : > "$LOG"
  printf 'mode = "%s"\n' "$_mode" > "$WORK/$_mode.toml"
  set -- -d post_max_size=16M -d max_input_vars=100000 -d max_file_uploads=100000
  if [ "$LOAD_EXT" = "1" ]; then
    [ "$PREINSTALLED" = 1 ] || set -- "$@" -d extension="$WORK/howdah.so"
    set -- "$@" -d howdah.config="$WORK/$_mode.toml" -d howdah.log="$LOG"
  fi
  php "$@" -S "127.0.0.1:$_port" "$WORK/index.php" > "$WORK/server.$_port.log" 2>&1 &
  SRV=$!
  _j=0
  while ! curl -s -o /dev/null "http://127.0.0.1:$_port/" 2>/dev/null; do
    _j=$((_j+1)); [ "$_j" -gt 50 ] && fail "server $_port never came up"; sleep 0.1
  done

  echo "== [$_mode] howdah-check web =="
  set +e; sh "$HC" web "http://127.0.0.1:$_port/" > "$WORK/web.out" 2>&1; _rc=$?; set -e
  cat "$WORK/web.out"

  grep -q '^selftest marker: *flagged *(HTTP 200, request id ' "$WORK/web.out" || fail "[$_mode] marker not reported flagged/200"
  grep -q '^over-limit parts: *BLOCKED *(HTTP \(403\|413\), request id ' "$WORK/web.out" || fail "[$_mode] over-limit not reported BLOCKED"
  [ "$_rc" -eq 0 ] || fail "[$_mode] howdah-check web exit $_rc"

  _mid=$(sed -n 's/^selftest marker:.*request id \([0-9a-zA-Z_-]*\).*/\1/p' "$WORK/web.out")
  _oid=$(sed -n 's/^over-limit parts:.*request id \([0-9a-zA-Z_-]*\),.*/\1/p' "$WORK/web.out")
  [ -n "$_mid" ] && [ -n "$_oid" ] && [ "$_mid" != "$_oid" ] || fail "[$_mode] missing/identical ids ($_mid / $_oid)"
  grep "$_mid" "$LOG" | grep -q '"rule":"self_test"' || fail "[$_mode] marker id $_mid has no self_test line in log"
  grep "$_mid" "$LOG" | grep -q '"action":"log"' || fail "[$_mode] self_test line is not action=log"
  grep "$_oid" "$LOG" | grep -q '"action":"block"' || fail "[$_mode] over-limit id $_oid has no block line in log"
  grep -qE '"ts":"[0-9]{13,}"' "$LOG" || fail "[$_mode] no plausible ts"

  # Ordinary traffic must not trip the self-test.
  : > "$LOG"
  printf -- '--NormalB0\r\nContent-Disposition: form-data; name="username"\r\n\r\nalice\r\n--NormalB0--\r\n' > "$WORK/normal.bin"
  _c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: multipart/form-data; boundary=NormalB0" \
       --data-binary @"$WORK/normal.bin" "http://127.0.0.1:$_port/")
  [ "$_c" = 200 ] || fail "[$_mode] normal form got HTTP $_c"
  ! grep -q self_test "$LOG" || fail "[$_mode] ordinary traffic produced a self_test line"
  # The marker must never mask a real detection: marker + a genuine over-limit
  # structure in the same request logs the REAL rule (a Block in both modes).
  : > "$LOG"
  { printf -- '--MaskB0\r\nContent-Disposition: form-data; name="__howdah_selftest__"\r\n\r\n1\r\n'
    _i=0; while [ "$_i" -lt 2001 ]; do
      printf -- '--MaskB0\r\nContent-Disposition: form-data; name="m%s"\r\n\r\n\r\n' "$_i"; _i=$((_i+1)); done
    printf -- '--MaskB0--\r\n'; } > "$WORK/mask.bin"
  curl -s -o /dev/null -X POST -H "Content-Type: multipart/form-data; boundary=MaskB0" \
       --data-binary @"$WORK/mask.bin" "http://127.0.0.1:$_port/"
  grep -q '"rule":"max_parts"' "$LOG" || fail "[$_mode] marker masked a real detection"
  ! grep -q self_test "$LOG" || fail "[$_mode] self_test line displaced the real rule"
  echo "[$_mode] OK (marker $_mid flagged 200; over-limit $_oid blocked; normal form clean)"

  kill "$SRV" 2>/dev/null || true; SRV=""
}

run_mode 8090 detect
run_mode 8091 block
echo "PASS"
