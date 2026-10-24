#!/bin/sh
# In-container half of the Howdah integration test. Runs inside a
# howdah-dev-php<ver> image (Rust + that PHP's headers + the php CLI). Builds
# the extension, loads it into the PHP built-in web server (the rfc1867 hook is
# SAPI-independent, exactly as proven in the milestone-0 findings), and checks:
#
#   1. BLOCK mode: a harmless *shaped* request (many empty file parts, structure
#      only, no payload) -> HTTP 413/403, a request id in the body, and a
#      matching JSON block line (with a plausible `ts`) in the configured log.
#      A normal small multipart form -> HTTP 200, no block.
#   2. DETECT logging: a rule downgraded to "detect" that is hit -> the line is
#      still written (action "log") but the request is NOT blocked (HTTP 200).
#   3. DETECT + critical: a critical rule (max_parts) still BLOCKS (403) even
#      when the global mode is "detect".
#
# Arg 1: the cargo feature for this image's PHP generation (php5|php7|php8).
# Env LOAD_EXT=0 skips loading the extension (used to show the test RED: with no
# WAF the shaped request is served 200).
set -eu

FEATURE="${1:-php7}"
LOAD_EXT="${LOAD_EXT:-1}"
ROOT=/src
WORK=/tmp/howdah-it
LOGDIR=/var/log/howdah
LOG="$LOGDIR/events.log"
SRV=""
rm -rf "$WORK"; mkdir -p "$WORK" "$LOGDIR"
: > "$LOG"

echo "== building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd "$ROOT"
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"

# The app touches $_FILES, triggering PHP's multipart parse (and the Howdah
# callback). On a block the request is refused before this line finishes.
cat > "$WORK/index.php" <<'PHP'
<?php
$n = count($_FILES);
echo "OK files=$n\n";
PHP

fail() {
  echo "FAIL: $1"
  echo "--- server.log ---"; cat "$WORK"/server.*.log 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
  exit 1
}

# start_server <port> <toml-path>
start_server() {
  _port=$1; _toml=$2
  set -- -d post_max_size=16M -d upload_max_filesize=16M -d max_file_uploads=100000
  if [ "$LOAD_EXT" = "1" ]; then
    set -- "$@" -d extension="$WORK/howdah.so" \
      -d howdah.config="$_toml" -d howdah.log="$LOG" -d howdah.mode=block
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

# post <port> <boundary> <bodyfile> <outfile> -> echoes HTTP code (never aborts)
post() {
  set +e
  _c=$(curl -s -o "$4" -w '%{http_code}' -X POST \
    -H "Content-Type: multipart/form-data; boundary=$2" --data-binary @"$3" \
    "http://127.0.0.1:$1/")
  set -e
  echo "$_c"
}

# build_shaped <outfile> <boundary> <count>: N empty file parts
build_shaped() {
  : > "$1"; _i=0
  while [ "$_i" -lt "$3" ]; do
    printf -- '--%s\r\n' "$2" >> "$1"
    printf 'Content-Disposition: form-data; name="f%s"; filename="f%s.bin"\r\n' "$_i" "$_i" >> "$1"
    printf 'Content-Type: application/octet-stream\r\n\r\n\r\n' >> "$1"
    _i=$((_i+1))
  done
  printf -- '--%s--\r\n' "$2" >> "$1"
}

SHAPED="$WORK/shaped.bin"; build_shaped "$SHAPED" ShapedB0 10

# ---- 1. BLOCK mode ----------------------------------------------------------
: > "$LOG"
cat > "$WORK/block.toml" <<'TOML'
mode = "block"
[limits]
max_parts = 5
max_files = 3
TOML
start_server 8080 "$WORK/block.toml"

if [ "$LOAD_EXT" = "1" ]; then
  echo "== php --ri howdah =="
  php -d extension="$WORK/howdah.so" -d howdah.config="$WORK/block.toml" \
      -d howdah.log="$LOG" --ri howdah || echo "(--ri failed)"
fi

code=$(post 8080 ShapedB0 "$SHAPED" "$WORK/resp_block.txt")
echo "== [block] shaped -> HTTP $code =="; cat "$WORK/resp_block.txt"; echo
echo "$code" | grep -qE '^(413|403)$' || fail "block/shaped: expected 413/403, got $code"
grep -q 'request_id:' "$WORK/resp_block.txt" || fail "block/shaped: no request id in body"
grep -q '"action":"block"' "$LOG" || fail "block/shaped: no block line in log"
grep -qE '"ts":"[0-9]{13,}"' "$LOG" || { echo "log was:"; cat "$LOG"; fail "block/shaped: log line has no plausible ts"; }
RID=$(sed -n 's/.*request_id: //p' "$WORK/resp_block.txt" | tr -d '\r\n ')
[ -n "$RID" ] && grep -q "$RID" "$LOG" || fail "block/shaped: body request id '$RID' absent from log"
echo "block/shaped OK (status $code, request_id $RID + ts logged)"

NORMAL="$WORK/normal.bin"; : > "$NORMAL"
printf -- '--NormalB0\r\n' >> "$NORMAL"
printf 'Content-Disposition: form-data; name="username"\r\n\r\nalice\r\n' >> "$NORMAL"
printf -- '--NormalB0\r\n' >> "$NORMAL"
printf 'Content-Disposition: form-data; name="avatar"; filename="a.txt"\r\n' >> "$NORMAL"
printf 'Content-Type: text/plain\r\n\r\nhello\r\n' >> "$NORMAL"
printf -- '--NormalB0--\r\n' >> "$NORMAL"
ncode=$(post 8080 NormalB0 "$NORMAL" "$WORK/resp_ok.txt")
echo "== [block] normal -> HTTP $ncode =="; cat "$WORK/resp_ok.txt"; echo
echo "$ncode" | grep -q '^200$' || fail "block/normal: expected 200, got $ncode"
grep -q 'OK files=' "$WORK/resp_ok.txt" || fail "block/normal: app body missing (wrongly blocked?)"
echo "block/normal OK (status 200, app ran)"
stop_server

# ---- 2. DETECT logging: a downgraded rule is logged but NOT blocked ---------
: > "$LOG"
cat > "$WORK/detectlog.toml" <<'TOML'
mode = "block"
[limits]
max_parts = 100000
max_files = 3
[rules]
max_files = "detect"
TOML
start_server 8081 "$WORK/detectlog.toml"
dcode=$(post 8081 ShapedB0 "$SHAPED" "$WORK/resp_detect.txt")
echo "== [detect-log] shaped -> HTTP $dcode =="; cat "$WORK/resp_detect.txt"; echo
echo "$dcode" | grep -q '^200$' || fail "detect-log: a Log action must NOT block; expected 200, got $dcode"
grep -q 'OK files=' "$WORK/resp_detect.txt" || fail "detect-log: app did not run"
grep -q '"action":"log"' "$LOG" || { echo "log was:"; cat "$LOG"; fail "detect-log: no log-action line written"; }
grep -q '"rule":"max_files"' "$LOG" || fail "detect-log: expected max_files rule in log"
grep -qE '"ts":"[0-9]{13,}"' "$LOG" || fail "detect-log: log line has no plausible ts"
echo "detect-log OK (status 200, action=log line written)"
stop_server

# ---- 3. DETECT + critical rule still blocks ---------------------------------
: > "$LOG"
cat > "$WORK/detect.toml" <<'TOML'
mode = "detect"
[limits]
max_parts = 5
TOML
start_server 8082 "$WORK/detect.toml"
ccode=$(post 8082 ShapedB0 "$SHAPED" "$WORK/resp_crit.txt")
echo "== [detect-critical] shaped -> HTTP $ccode =="; cat "$WORK/resp_crit.txt"; echo
echo "$ccode" | grep -qE '^(413|403)$' || fail "detect-critical: a critical rule must block even in detect; got $ccode"
grep -q '"action":"block"' "$LOG" || fail "detect-critical: no block line in log"
echo "detect-critical OK (status $ccode, critical blocked in detect mode)"
stop_server

# ---- 4. Part DATA cannot switch the count rules off (regression) ------------
# Before 1.2.1 the glue reconstructed multipart framing with a fixed public
# boundary and fed part DATA through the same byte parser, so a chunk carrying
# that boundary wedged the parser and every later part went uncounted. Shipped
# defaults (detect, max_files=200): one small file whose CONTENT is the old
# boundary token, then 250 empty file parts, must still be refused as max_files.
: > "$LOG"
printf 'mode = "detect"\n' > "$WORK/defaults.toml"
POISONED="$WORK/poisoned.bin"; : > "$POISONED"
printf -- '--PoisonB0\r\n' >> "$POISONED"
printf 'Content-Disposition: form-data; name="avatar"; filename="a.png"\r\n' >> "$POISONED"
printf 'Content-Type: image/png\r\n\r\n' >> "$POISONED"
printf 'png\r\n--HdHbndYy7Qk3Zx1Lp9Wf2Rszz garbage\r\n' >> "$POISONED"
_i=0
while [ "$_i" -lt 250 ]; do
  printf -- '--PoisonB0\r\n' >> "$POISONED"
  printf 'Content-Disposition: form-data; name="f%s"; filename="f%s.bin"\r\n\r\n\r\n' "$_i" "$_i" >> "$POISONED"
  _i=$((_i+1))
done
printf -- '--PoisonB0--\r\n' >> "$POISONED"
start_server 8083 "$WORK/defaults.toml"
pcode=$(post 8083 PoisonB0 "$POISONED" "$WORK/resp_poison.txt")
echo "== [detect-defaults] poisoned flood -> HTTP $pcode =="; cat "$WORK/resp_poison.txt"; echo
echo "$pcode" | grep -qE '^(413|403)$' || fail "poisoned-flood: data carrying the old internal boundary disabled the count rules; expected 403, got $pcode"
grep -q '"rule":"max_files"' "$LOG" || { echo "log was:"; cat "$LOG"; fail "poisoned-flood: expected a max_files block line"; }
echo "poisoned-flood OK (status $pcode, max_files still enforced)"
stop_server

echo "PASS"
