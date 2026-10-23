#!/bin/sh
# In-container regression for the SHIPPED path: howdah.mode set via php.ini with
# NO howdah.config TOML file. This exercises MINIT's synthesize-config-from-ini
# branch, which was previously missing (the core got NULL -> safe_defaults=Block,
# so off/detect silently enforced). Runs inside a howdah-dev-php<ver> image.
#
# Asserts, with a PHP2Shell-shaped flood (250 empty file parts > default
# max_files=200) and NO config file, just `-d howdah.mode=<mode>`:
#   off    -> flood NOT blocked (HTTP 200) and nothing logged  [impossible before]
#   detect -> flood STILL blocked (HTTP 403, critical-always-block) + logged
#   block  -> flood blocked (HTTP 403) + logged
# and that `php --ri howdah`'s Mode row matches the ini mode in each case.
#
# Arg 1: cargo feature (php5|php7|php8). Env LOAD_EXT=0 -> no extension (RED).
set -eu

FEATURE="${1:-php7}"
LOAD_EXT="${LOAD_EXT:-1}"
ROOT=/src
WORK=/tmp/howdah-mm
LOGDIR=/var/log/howdah
LOG="$LOGDIR/events.log"
SRV=""
rm -rf "$WORK"; mkdir -p "$WORK" "$LOGDIR"; : > "$LOG"

echo "== building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd "$ROOT"
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"

cat > "$WORK/index.php" <<'PHP'
<?php
$n = count($_FILES);
echo "OK files=$n\n";
PHP

# PHP2Shell flood: 250 empty file parts (> default max_files = 200).
FLOOD="$WORK/flood.bin"; : > "$FLOOD"; i=0
while [ "$i" -lt 250 ]; do
  printf -- '--FloodB0\r\n' >> "$FLOOD"
  printf 'Content-Disposition: form-data; name="f%s"; filename="f%s.bin"\r\n' "$i" "$i" >> "$FLOOD"
  printf 'Content-Type: application/octet-stream\r\n\r\n\r\n' >> "$FLOOD"
  i=$((i+1))
done
printf -- '--FloodB0--\r\n' >> "$FLOOD"

fail() {
  echo "FAIL: $1"
  echo "--- server.log ---"; cat "$WORK"/server.*.log 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
  exit 1
}

# start_server <port> <mode>: NO howdah.config -> synthesize from the ini mode.
start_server() {
  _port=$1; _mode=$2
  set -- -d post_max_size=32M -d upload_max_filesize=32M -d max_file_uploads=100000
  if [ "$LOAD_EXT" = "1" ]; then
    set -- "$@" -d extension="$WORK/howdah.so" -d howdah.log="$LOG" -d howdah.mode="$_mode"
  fi
  php "$@" -S "127.0.0.1:$_port" "$WORK/index.php" > "$WORK/server.$_port.log" 2>&1 &
  SRV=$!
  _j=0
  while ! curl -s -o /dev/null "http://127.0.0.1:$_port/" 2>/dev/null; do
    _j=$((_j+1))
    if [ "$_j" -gt 50 ]; then echo "server $_port never came up"; cat "$WORK/server.$_port.log"; exit 1; fi
    sleep 0.1
  done
}
stop_server() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; SRV=""; }

post_flood() { # <port> <outfile> -> echoes HTTP code
  set +e
  _c=$(curl -s -o "$2" -w '%{http_code}' -X POST \
    -H 'Content-Type: multipart/form-data; boundary=FloodB0' --data-binary @"$FLOOD" \
    "http://127.0.0.1:$1/")
  set -e
  echo "$_c"
}

check_ri_mode() { # <mode>
  if [ "$LOAD_EXT" = "1" ]; then
    php -d extension="$WORK/howdah.so" -d howdah.log="$LOG" -d howdah.mode="$1" --ri howdah 2>/dev/null \
      | grep -qiE "Mode *=> *$1" || fail "phpinfo Mode row != '$1' for howdah.mode=$1"
  fi
}

# ---- off: the flood must NOT be blocked, and nothing is logged --------------
: > "$LOG"
check_ri_mode off
start_server 8090 off
code=$(post_flood 8090 "$WORK/resp_off.txt")
echo "== [mode=off] flood -> HTTP $code =="; cat "$WORK/resp_off.txt"; echo
echo "$code" | grep -q '^200$' || fail "off: flood must be served (200), got $code (ini mode not reaching core?)"
grep -q 'OK files=250' "$WORK/resp_off.txt" || fail "off: app should see all 250 files"
[ -s "$LOG" ] && fail "off: Howdah must log NOTHING in off mode (log not empty)"
echo "mode=off OK (flood served 200, log empty)"
stop_server

# ---- detect: critical rule STILL blocks (403) and is logged -----------------
: > "$LOG"
check_ri_mode detect
start_server 8091 detect
code=$(post_flood 8091 "$WORK/resp_detect.txt")
echo "== [mode=detect] flood -> HTTP $code =="; cat "$WORK/resp_detect.txt"; echo
echo "$code" | grep -qE '^(413|403)$' || fail "detect: a critical flood must still block, got $code"
grep -q '"action":"block"' "$LOG" || fail "detect: expected a block log line"
grep -qE '"ts":"[0-9]{13,}"' "$LOG" || fail "detect: log line has no plausible ts"
echo "mode=detect OK (critical flood blocked $code in detect, logged)"
stop_server

# ---- block: flood blocked (403) and logged ----------------------------------
: > "$LOG"
check_ri_mode block
start_server 8092 block
code=$(post_flood 8092 "$WORK/resp_block.txt")
echo "== [mode=block] flood -> HTTP $code =="; cat "$WORK/resp_block.txt"; echo
echo "$code" | grep -qE '^(413|403)$' || fail "block: flood must be blocked, got $code"
grep -q '"action":"block"' "$LOG" || fail "block: expected a block log line"
echo "mode=block OK (flood blocked $code, logged)"
stop_server

echo "PASS"
