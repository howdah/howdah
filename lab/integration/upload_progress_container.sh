#!/bin/sh
# In-container half of the CVE-2026-115560 lab (see upload_progress.sh).
#
# Precondition (from the advisory): session.upload_progress keys its tracking
# data on `prefix + <PHP_SESSION_UPLOAD_PROGRESS value>`. The session is written
# with the php_serialize (php_binary on PHP < 5.5.4) handler and later read back
# with the `php` handler, which splits keys on `|`, so a `|` in the value lets a
# serialized value reach unserialize(). The test gadget is benign: its
# __wakeup() only writes a marker file.
#
# (session.use_strict_mode=0 so a client-chosen id is accepted; 8.6 defaults it on.)
#
#   A. Howdah absent AND rule off  -> marker present (the negative control)
#   B. detect                      -> marker absent, upload_progress_abuse logged
#                                     (rule + fixed reason only, never the value),
#                                     upload proceeds, benign progress tracks
#   C. block                       -> clean 403, marker absent, worker survives
#   D. benign corpus               -> zero events, progress tracked
#
# Arg 1: cargo feature (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-up
LOG="$WORK/events.log"
PORT=8099
SRV=""
rm -rf "$WORK"; mkdir -p "$WORK/sess" "$WORK/app"; : > "$LOG"

echo "== php $(php -r 'echo PHP_VERSION;') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
cd "$WORK"

if php -r 'exit(version_compare(PHP_VERSION,"5.5.4",">=")?0:1);'; then HANDLER=php_serialize; else HANDLER=php_binary; fi
echo "writer session.serialize_handler=$HANDLER, reader=php"

cat > "$WORK/app/index.php" <<'PHP'
<?php
echo "OK pid=", getmypid(), "\n";
PHP
cat > "$WORK/read.php" <<'PHP'
<?php
// The vulnerable reader: the php handler over data written by another handler.
class Gadget { function __wakeup() { file_put_contents(getenv('MARK'), 'wakeup'); } }
ini_set('session.serialize_handler', 'php');
session_save_path($argv[2]);
session_id($argv[1]);
@session_start();
PHP
head -c 4096 /dev/zero | tr '\0' 'A' > "$WORK/upload.bin"

fail() {
  echo "FAIL: $1"
  echo "--- server log ---"; cat "$WORK/server.log" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
  exit 1
}

# start_server <mode|none|rule-off>: none = no extension at all.
start_server() {
  _mode=$1
  set -- -d session.serialize_handler=$HANDLER -d session.save_path="$WORK/sess" \
         -d session.use_strict_mode=0 -d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=0 \
         -d session.upload_progress.freq=1 -d session.upload_progress.min_freq=0 \
         -d display_errors=0 -d date.timezone=UTC
  case "$_mode" in
    none) ;;
    rule-off)
      printf 'mode = "block"\n[rules]\nupload_progress_abuse = "off"\n' > "$WORK/r.toml"
      set -- "$@" -d extension="$WORK/howdah.so" -d howdah.config="$WORK/r.toml" -d howdah.log="$LOG" ;;
    *) set -- "$@" -d extension="$WORK/howdah.so" -d howdah.log="$LOG" -d howdah.mode="$_mode" ;;
  esac
  : > "$LOG"
  php "$@" -S "127.0.0.1:$PORT" -t "$WORK/app" > "$WORK/server.log" 2>&1 &
  SRV=$!
  _j=0
  while ! curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; do
    _j=$((_j+1)); [ "$_j" -gt 60 ] && fail "server never came up"; sleep 0.1
  done
}
stop_server() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""; }

# post <sid> <progress-value> -> HTTP code in $CODE, body in out.txt
post() {
  set +e
  CODE=$(curl -s -o "$WORK/out.txt" -w '%{http_code}' -b "PHPSESSID=$1" \
    --form-string "PHP_SESSION_UPLOAD_PROGRESS=$2" -F "f=@$WORK/upload.bin" "http://127.0.0.1:$PORT/")
  set -e
}
# reader <sid> -> sets marker if the smuggled gadget was unserialized
reader() {
  rm -f "$WORK/marker"
  MARK="$WORK/marker" php -d display_errors=0 "$WORK/read.php" "$1" "$WORK/sess" >/dev/null 2>&1 || true
}
progress_tracked() { grep -aq "upload_progress_" "$WORK/sess/sess_$1" 2>/dev/null; }

PAYLOAD='SECRETTOK|O:6:"Gadget":0:{}'
SEQ=0
newsid() { SEQ=$((SEQ+1)); SID="labsid$SEQ"; rm -f "$WORK/sess/sess_$SID"; }

# ---- A. negative controls: the vulnerability is real on this PHP -------------
for m in none rule-off; do
  start_server $m
  newsid; post "$SID" "$PAYLOAD"
  [ "$CODE" = 200 ] || fail "A[$m]: upload not served (HTTP $CODE)"
  progress_tracked "$SID" || fail "A[$m]: session never tracked the upload (lab precondition)"
  reader "$SID"
  [ -f "$WORK/marker" ] || fail "A[$m]: NO marker with Howdah off - reproduction failed, coverage cannot be claimed"
  if [ "$m" = rule-off ]; then [ ! -s "$LOG" ] || fail "A[rule-off]: events logged with the rule off"; fi
  stop_server
  echo "  ok   - A[$m]: smuggled gadget reached unserialize() (marker present)"
done

# ---- B. detect ----------------------------------------------------------------
start_server detect
newsid; post "$SID" "$PAYLOAD"
[ "$CODE" = 200 ] || fail "B: detect must let the upload proceed (HTTP $CODE)"
reader "$SID"
[ ! -f "$WORK/marker" ] || fail "B: marker present with Howdah on (detect did not neutralize)"
if progress_tracked "$SID"; then fail "B: session still built the attacker key"; fi
grep -q '"rule":"upload_progress_abuse"' "$LOG" || fail "B: no upload_progress_abuse event"
grep -q '"action":"log"' "$LOG" || fail "B: detect event is not action:log"
if grep -q 'SECRETTOK\|Gadget\|O:6' "$LOG"; then fail "B: the log leaked the value"; fi
echo "  ok   - B: detect withholds the event (marker absent), event logged, no value in log"
newsid; : > "$LOG"; post "$SID" "550e8400-e29b-41d4-a716-446655440000"
[ "$CODE" = 200 ] || fail "B2: benign upload HTTP $CODE"
progress_tracked "$SID" || fail "B2: benign progress tracking broke"
[ ! -s "$LOG" ] || fail "B2: benign UUID key produced an event"
echo "  ok   - B: benign UUID progress key still tracked, zero events"
stop_server

# ---- C. block -----------------------------------------------------------------
start_server block
PID1=$(curl -s "http://127.0.0.1:$PORT/" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
newsid; post "$SID" "$PAYLOAD"
[ "$CODE" = 403 ] || fail "C: block must answer 403, got $CODE"
grep -q 'Howdah blocked' "$WORK/out.txt" || fail "C: 403 body is not the Howdah block page"
reader "$SID"
[ ! -f "$WORK/marker" ] || fail "C: marker present in block mode"
grep -q '"rule":"upload_progress_abuse"' "$LOG" || fail "C: no upload_progress_abuse event"
grep -q '"action":"block"' "$LOG" || fail "C: block event is not action:block"
if grep -q 'SECRETTOK\|Gadget\|O:6' "$LOG"; then fail "C: the log leaked the value"; fi
PID2=$(curl -s "http://127.0.0.1:$PORT/" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
[ -n "$PID1" ] && [ "$PID1" = "$PID2" ] || fail "C: worker did not survive ($PID1 -> $PID2)"
echo "  ok   - C: block -> clean 403, marker absent, event logged, worker survives (pid $PID2)"

# ---- D. benign corpus (block mode: any FP would 403) ---------------------------
: > "$LOG"
for v in "550e8400-e29b-41d4-a716-446655440000" "abc123" "1" "my_upload-7" "a!b:c;d" "" "x y"; do
  newsid; post "$SID" "$v"
  [ "$CODE" = 200 ] || fail "D: benign key '$v' got HTTP $CODE"
  [ -z "$v" ] || progress_tracked "$SID" || fail "D: benign key '$v' not tracked"
done
# a pipe in a DIFFERENT field, and a plain multipart upload without a progress field
set +e
c=$(curl -s -o /dev/null -w '%{http_code}' --form-string 'comment=a|b|c' -F "f=@$WORK/upload.bin" "http://127.0.0.1:$PORT/")
c2=$(curl -s -o /dev/null -w '%{http_code}' --form-string 'x=1' "http://127.0.0.1:$PORT/")
set -e
[ "$c" = 200 ] && [ "$c2" = 200 ] || fail "D: ordinary uploads blocked ($c/$c2)"
[ ! -s "$LOG" ] || fail "D: benign corpus produced events"
echo "  ok   - D: benign corpus (UUID, counters, ! : ; keys, pipe in another field, plain upload) zero hits"
stop_server
echo "UPROW	php $(php -r 'echo PHP_VERSION;')	$HANDLER->php	control marker present	detect+block marker absent, logged	benign 0 FP"
echo "PASS"
