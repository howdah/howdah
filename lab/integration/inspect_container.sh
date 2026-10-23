#!/bin/sh
# In-container half of the Layer-2 input-inspection integration test.
# Runs inside a howdah-dev-php<ver> image. Uses the PHP built-in web server
# with default config (inspect.mode = detect, i.e. log-only).
#
# Asserts, per class, for GET and POST:
#   - HTTP 200 and the app ran (Layer 2 does not block by default)
#   - the event log has "action":"log" with the matching "rule"
#   - the log never contains the payload bytes
# and that benign requests write no inspect event.
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-l2
LOGDIR=/var/log/howdah
LOG="$LOGDIR/events.log"
SRV=""
rm -rf "$WORK"; mkdir -p "$WORK" "$LOGDIR"
: > "$LOG"

echo "== php $(php -r 'echo PHP_VERSION;') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"

cat > "$WORK/index.php" <<'PHP'
<?php
echo "OK get=" . count($_GET) . " post=" . count($_POST) . "\n";
PHP

fail() {
  echo "FAIL: $1"
  echo "--- server.log ---"; cat "$WORK/server.log" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
  exit 1
}

printf 'mode = "detect"\n' > "$WORK/l2.toml"
php -d extension="$WORK/howdah.so" -d howdah.config="$WORK/l2.toml" \
    -d howdah.log="$LOG" -S 127.0.0.1:8090 "$WORK/index.php" > "$WORK/server.log" 2>&1 &
SRV=$!
j=0
while ! curl -s -o /dev/null http://127.0.0.1:8090/ 2>/dev/null; do
  j=$((j+1)); [ "$j" -gt 50 ] && fail "server never came up"; sleep 0.1
done

# check <label> <GET|POST> <rule> <payload> <bytes that must not appear in the log>
check() {
  : > "$LOG"
  if [ "$2" = GET ]; then
    code=$(curl -s -o "$WORK/r.txt" -w '%{http_code}' -G --data-urlencode "q=$4" http://127.0.0.1:8090/)
  else
    code=$(curl -s -o "$WORK/r.txt" -w '%{http_code}' --data-urlencode "q=$4" http://127.0.0.1:8090/)
  fi
  [ "$code" = 200 ] || fail "$1 $2: expected 200 (log-only), got $code"
  grep -q '^OK ' "$WORK/r.txt" || fail "$1 $2: app did not run"
  grep -q '"action":"log"' "$LOG" || fail "$1 $2: no action:log line"
  grep -q "\"rule\":\"$3\"" "$LOG" || fail "$1 $2: expected rule $3"
  if grep -q '"action":"block"' "$LOG"; then fail "$1 $2: unexpected block line"; fi
  if grep -qF -- "$5" "$LOG"; then fail "$1 $2: log leaked payload bytes ($5)"; fi
  echo "  ok   - $1 via $2: 200, action=log rule=$3, payload not logged"
}

for m in GET POST; do
  check sqli      $m sql_injection     "' OR 1=1 --"        "1=1"
  check traversal $m path_traversal    "../../etc/passwd"   "passwd"
  check cmdi      $m command_injection "; cat /etc/passwd"  "passwd"
done

# benign: realistic free text must produce no event at all
: > "$LOG"
for v in "operating system (Linux)" "Thanks; update your profile" "name=O'Brien" "reports/2024/q1.pdf" 'use `foo` here'; do
  code=$(curl -s -o "$WORK/r.txt" -w '%{http_code}' -G --data-urlencode "q=$v" http://127.0.0.1:8090/)
  [ "$code" = 200 ] || fail "benign GET '$v': got $code"
  code=$(curl -s -o "$WORK/r.txt" -w '%{http_code}' --data-urlencode "q=$v" http://127.0.0.1:8090/)
  [ "$code" = 200 ] || fail "benign POST '$v': got $code"
done
if [ -s "$LOG" ]; then fail "benign requests produced events"; fi
echo "  ok   - benign GET+POST requests: 200, zero events"

kill "$SRV" 2>/dev/null || true
echo "PASS"
