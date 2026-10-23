#!/bin/sh
# In-container half of the Howdah block-shaped integration test. Runs inside a
# howdah-dev-php<ver> image (Rust + that PHP's headers + the php CLI). Builds
# the extension, loads it into the PHP built-in web server (the rfc1867 hook is
# SAPI-independent, exactly as proven in the milestone-0 findings), then:
#   1. POSTs a harmless *shaped* request (many empty file parts, structure only,
#      no payload) and asserts HTTP 413/403, a request id in the body, and a
#      matching JSON block line in the configured log.
#   2. POSTs a normal small multipart form and asserts HTTP 200, no block.
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
rm -rf "$WORK"; mkdir -p "$WORK" "$LOGDIR"
: > "$LOG"

echo "== building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd "$ROOT"
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"

cat > "$WORK/howdah.toml" <<'TOML'
mode = "block"
[limits]
max_parts = 5
max_files = 3
TOML

# The app touches $_FILES, which triggers PHP's multipart parse (and so the
# Howdah callback). On a block the request is refused before this line finishes.
cat > "$WORK/index.php" <<'PHP'
<?php
$n = count($_FILES);
echo "OK files=$n\n";
PHP

# Common php flags. max_file_uploads is raised so PHP's own default cap (20)
# never masks Howdah's limits.
set -- -d post_max_size=16M -d upload_max_filesize=16M -d max_file_uploads=100000
if [ "$LOAD_EXT" = "1" ]; then
  set -- "$@" -d extension="$WORK/howdah.so" \
    -d howdah.config="$WORK/howdah.toml" -d howdah.log="$LOG" -d howdah.mode=block
fi

if [ "$LOAD_EXT" = "1" ]; then
  echo "== php --ri howdah =="
  php -d extension="$WORK/howdah.so" -d howdah.config="$WORK/howdah.toml" \
      -d howdah.log="$LOG" --ri howdah || echo "(--ri failed)"
fi

echo "== starting php -S =="
php "$@" -S 127.0.0.1:8080 "$WORK/index.php" > "$WORK/server.log" 2>&1 &
SRV=$!
echo "server pid=$SRV flags: $*"
# wait for the server to accept connections
trap 'echo "[exit $?] server.log:"; cat "$WORK/server.log" 2>/dev/null; kill $SRV 2>/dev/null || true' EXIT
j=0
while ! curl -s -o /dev/null http://127.0.0.1:8080/ 2>/dev/null; do
  j=$((j+1))
  if [ "$j" -gt 50 ]; then
    echo "server never came up"; cat "$WORK/server.log"; exit 1
  fi
  sleep 0.1
done
echo "server is up after $j tries"

fail() { echo "FAIL: $1"; echo "--- server.log ---"; cat "$WORK/server.log"; echo "--- log ---"; cat "$LOG" 2>/dev/null; exit 1; }

# ---- 1. shaped request: 10 empty file parts (exceeds max_files=3) -----------
B=HowdahShapedBoundary0
BODY="$WORK/shaped.bin"; : > "$BODY"
i=0
while [ "$i" -lt 10 ]; do
  printf -- '--%s\r\n' "$B" >> "$BODY"
  printf 'Content-Disposition: form-data; name="f%s"; filename="f%s.bin"\r\n' "$i" "$i" >> "$BODY"
  printf 'Content-Type: application/octet-stream\r\n\r\n\r\n' >> "$BODY"
  i=$((i+1))
done
printf -- '--%s--\r\n' "$B" >> "$BODY"

set +e
code=$(curl -s -o "$WORK/resp_shaped.txt" -w '%{http_code}' -X POST \
  -H "Content-Type: multipart/form-data; boundary=$B" \
  --data-binary @"$BODY" http://127.0.0.1:8080/)
crc=$?
set -e
echo "== shaped -> HTTP $code (curl rc=$crc) =="; cat "$WORK/resp_shaped.txt"; echo
echo "--- server.log so far ---"; cat "$WORK/server.log"; echo "--- end server.log ---"

echo "$code" | grep -qE '^(413|403)$' || fail "shaped: expected 413/403, got $code"
grep -q 'request_id:' "$WORK/resp_shaped.txt" || fail "shaped: no request id in body"
grep -q '"action":"block"' "$LOG" || fail "shaped: no block line in $LOG"
RID=$(sed -n 's/.*request_id: //p' "$WORK/resp_shaped.txt" | tr -d '\r\n ')
[ -n "$RID" ] && grep -q "$RID" "$LOG" || fail "shaped: body request id '$RID' absent from log"
echo "shaped OK (status $code, request_id $RID logged)"

# ---- 2. normal small form -> 200, no block ----------------------------------
N=HowdahNormalBoundary0
NBODY="$WORK/normal.bin"; : > "$NBODY"
printf -- '--%s\r\n' "$N" >> "$NBODY"
printf 'Content-Disposition: form-data; name="username"\r\n\r\nalice\r\n' >> "$NBODY"
printf -- '--%s\r\n' "$N" >> "$NBODY"
printf 'Content-Disposition: form-data; name="avatar"; filename="a.txt"\r\n' >> "$NBODY"
printf 'Content-Type: text/plain\r\n\r\nhello\r\n' >> "$NBODY"
printf -- '--%s--\r\n' "$N" >> "$NBODY"

set +e
ncode=$(curl -s -o "$WORK/resp_ok.txt" -w '%{http_code}' -X POST \
  -H "Content-Type: multipart/form-data; boundary=$N" \
  --data-binary @"$NBODY" http://127.0.0.1:8080/)
nrc=$?
set -e
echo "== normal -> HTTP $ncode (curl rc=$nrc) =="; cat "$WORK/resp_ok.txt"; echo

echo "$ncode" | grep -q '^200$' || fail "normal: expected 200, got $ncode"
grep -q 'OK files=' "$WORK/resp_ok.txt" || fail "normal: app body missing (request was wrongly blocked?)"
echo "normal OK (status 200, app ran)"

echo "PASS"
