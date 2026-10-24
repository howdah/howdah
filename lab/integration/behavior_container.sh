#!/bin/sh
# In-container half of the Layer-4 (after-a-breach) behaviour integration test.
# Builds the real extension, writes HARMLESS-SHAPE fixtures only (no webshell,
# no miner, no payload: `system('true')`, a non-routable test host, a PHP file
# whose only content is a comment marker), runs php with a [behavior] config and
# asserts on rule-id strings and HTTP status. Argument values are never asserted
# or logged.
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-l4
LOG="$WORK/events.log"
rm -rf "$WORK"; mkdir -p "$WORK/www/uploads/sub" "$WORK/www/app/storage/framework/views"

echo "== php $(php -r 'echo PHP_VERSION;') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
cd "$WORK"

UP="$WORK/www/uploads"
APP="$WORK/www/app"
export UP APP
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
no_blocks() { ! grep -q '"action":"block"' "$LOG"; }
# "No Layer-4 finding and no block". Layer-3 sink lines (e.g. command_exec,
# which logs any system()/exec in detect) are a different layer and ignored.
no_events() { ! grep -qE '"rule":"(upload_exec|unexpected_binary|unexpected_egress|php_write)"|"action":"block"' "$LOG"; }
out_has() { grep -q "$1" "$WORK/out.txt"; }

# ---------------------------------------------------------------- fixtures
# "Uploaded shell" SHAPE: lives under the uploads dir, runs a no-op command,
# prints a marker. Not a webshell: no request input is read.
cat > "$UP/shell.php" <<'PHPEOF'
<?php
system('true');
echo "SHELL_RAN\n";
PHPEOF
cp "$UP/shell.php" "$UP/sub/shell.php"
export SHELL_PHP="$UP/shell.php"

# App entry that pulls the shell in (the "included from the app" case).
cat > "$APP/entry.php" <<'PHPEOF'
<?php
require getenv('SHELL_PHP');
echo "ENTRY_DONE\n";
PHPEOF

# Same exec from an ordinary app script (not under uploads): control.
cat > "$APP/plain_exec.php" <<'PHPEOF'
<?php
system('true');
echo "PLAIN_DONE\n";
PHPEOF

# Binary-allowlist probe: exec a harmless binary name given by env.
cat > "$APP/binary.php" <<'PHPEOF'
<?php
exec(getenv('PROG'), $o, $rc);
echo "BIN_DONE\n";
PHPEOF

# Egress probe: non-routable test hosts only; nothing is expected to answer.
cat > "$APP/egress.php" <<'PHPEOF'
<?php
@file_get_contents(getenv('TARGET'));
echo "EGRESS_DONE\n";
PHPEOF

# php-write probe: writes a PHP file holding only a comment marker.
cat > "$APP/write.php" <<'PHPEOF'
<?php
$marker = '<?php /* howdah-l4-test */';
$how = getenv('HOW');
$t = getenv('WTARGET');
if ($how === 'fpc') { $r = @file_put_contents($t, $marker); }
else { $h = @fopen($t, 'w'); $r = $h; if ($h) { fwrite($h, $marker); fclose($h); } }
echo "WRITE_RET[" . ($r ? 'ok' : 'false') . "]\n";
echo "WRITE_DONE\n";
PHPEOF

# Read probe: opening a .php file INSIDE the denied uploads dir for reading must
# never be a php-write (fails if the write-mode gate regresses).
printf '<?php return 1;' > "$APP/config.php"
printf '<?php /* howdah-l4-test */' > "$UP/sub/ro.php"
cat > "$APP/read.php" <<'PHPEOF'
<?php
$h = @fopen(getenv('UP') . '/sub/ro.php', 'r');
echo "READ[" . ($h ? 'res' : 'no') . "]\n";
echo "READ_DONE\n";
PHPEOF

# ---------------------------------------------------------------- runners
# run_file <toml> <script> : CLI run of a script file; stdout -> out.txt.
run_file() {
  printf '%b' "$1" > "$WORK/l4.toml"
  file="$2"; shift 2
  : > "$LOG"
  php -d extension="$WORK/howdah.so" \
      -d howdah.config="$WORK/l4.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      -d default_socket_timeout=2 "$@" "$file" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}

SRV=""
PORT=18140
stop_server() {
  if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; fi
  SRV=""
}
trap 'stop_server' EXIT
# start_server <toml>: built-in server, docroot www/ (so /uploads/shell.php is
# the MAIN script; the only CLI-family SAPI that has a main-script path).
start_server() {
  stop_server
  printf '%b' "$1" > "$WORK/l4.toml"
  : > "$LOG"
  PORT=$((PORT+1))
  php -d extension="$WORK/howdah.so" \
      -d howdah.config="$WORK/l4.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      -S "127.0.0.1:$PORT" -t "$WORK/www" > "$WORK/server.log" 2>&1 &
  SRV=$!
  _j=0
  until curl -s -o /dev/null "http://127.0.0.1:$PORT/app/config.php" 2>/dev/null; do
    _j=$((_j+1)); [ $_j -gt 60 ] && fail "built-in server did not start"
    sleep 0.1
  done
  : > "$LOG"
}
# req <path> -> HTTP code in $CODE, body in out.txt
req() {
  set +e
  CODE=$(curl -s -o "$WORK/out.txt" -w '%{http_code}' "http://127.0.0.1:$PORT$1")
  set -e
  : > "$WORK/err.txt"
}

DENY='deny_exec_dirs=["'"$UP"'"]\n'

# ============================================================ 1. UploadExec
# 1a. DIRECT request to the uploaded shell (main script): detect logs + serves.
start_server 'mode="detect"\n[behavior]\nmode="detect"\n'"$DENY"
req /uploads/shell.php
[ "$CODE" = 200 ] || fail "1a: detect should serve the shell, got $CODE"
out_has SHELL_RAN || fail "1a: shell did not run in detect"
has_rule upload_exec || fail "1a: no upload_exec event on direct request"
grep -q '"action":"log"' "$LOG" || fail "1a: expected action:log"
grep -qF "$UP" "$LOG" || fail "1a: finding does not name the uploads dir"
no_blocks || fail "1a: detect produced a block"
ok "UploadExec direct request (detect): logged naming the uploads dir, shell served (HTTP 200)"
: > "$LOG"
req /uploads/sub/shell.php
has_rule upload_exec || fail "1a2: nested uploads/sub/shell.php not flagged"
ok "UploadExec direct request in a subdirectory: flagged"
stop_server

# 1b. DIRECT request under block: 403, shell body never produced.
start_server 'mode="detect"\n[behavior]\nmode="block"\n'"$DENY"
req /uploads/shell.php
[ "$CODE" = 403 ] || fail "1b: expected 403, got $CODE"
if out_has SHELL_RAN; then fail "1b: shell ran despite block"; fi
has_rule upload_exec || fail "1b: no upload_exec event"
grep -q '"action":"block"' "$LOG" || fail "1b: no action:block"
ok "UploadExec direct request (block): HTTP 403, shell did not run, rule=upload_exec action=block"
: > "$LOG"
req /app/config.php
[ "$CODE" = 200 ] || fail "1b2: ordinary app page refused ($CODE)"
no_events || fail "1b2: ordinary app page produced an event"
ok "UploadExec block: ordinary (non-uploads) page unaffected (HTTP 200, no event)"
stop_server

# 1c. shell REQUIRED from an app entry script (origin attribution).
run_file 'mode="detect"\n[behavior]\nmode="detect"\n'"$DENY" "$APP/entry.php"
out_has SHELL_RAN || fail "1c: shell did not run in detect"
out_has ENTRY_DONE || fail "1c: entry did not finish"
has_rule upload_exec || fail "1c: required shell not flagged upload_exec"
grep -F '"rule":"upload_exec"' "$LOG" | grep -qF "$UP" || fail "1c: finding does not name the uploads dir"
if grep '"rule":"upload_exec"' "$LOG" | grep -qF "entry.php"; then fail "1c: finding blames the entry script"; fi
# Origin: the exec of 'true' is attributed to the SHELL (under uploads), which
# activates the binary facet even with no allowlist. The same exec from an
# ordinary app script must NOT fire (control below).
has_rule unexpected_binary || fail "1c: exec from required shell not attributed to the uploads origin"
ok "UploadExec via require (detect): finding names the uploads dir, not entry.php; exec attributed to the shell (unexpected_binary fired)"
run_file 'mode="detect"\n[behavior]\nmode="detect"\n'"$DENY" "$APP/plain_exec.php"
out_has PLAIN_DONE || fail "1c2: control did not finish"
no_events || fail "1c2: exec from an ordinary app script fired (origin not discriminating)"
ok "origin control: system('true') from an ordinary app script (no allowlist) -> no finding"

# 1d. required shell under block.
run_file 'mode="detect"\n[behavior]\nmode="block"\n'"$DENY" "$APP/entry.php"
out_has ENTRY_DONE || fail "1d: entry did not continue after neutralized include"
if out_has SHELL_RAN; then fail "1d: required shell ran despite block"; fi
grep -q '"action":"block"' "$LOG" || fail "1d: no block event"
has_rule upload_exec || fail "1d: no upload_exec event"
ok "UploadExec via require (block): shell neutralized, entry script continued, rule=upload_exec action=block"

# 1d2. RELATIVE include operand. Both the PHP 5.x compile hook and the 7.0+
# include opcode hook see the operand/filename as written (not realpath'd), and
# a relative path is not an absolute path, so the include-time exec-dir check
# is DORMANT for it (documented best-effort; the main-script check and the
# executing-file origin are the primary controls). The exec is still attributed
# to the shell by its executing-file origin.
cat > "$APP/rel_entry.php" <<'PHPEOF'
<?php
chdir(getenv('UP'));
require 'shell.php';
echo "ENTRY_DONE\n";
PHPEOF
run_file 'mode="detect"\n[behavior]\nmode="detect"\n'"$DENY" "$APP/rel_entry.php"
out_has ENTRY_DONE || fail "1d2: relative-include entry did not finish"
has_rule unexpected_binary || fail "1d2: exec from relatively-included shell not attributed to uploads"
no_rule upload_exec || fail "1d2: relative-operand include unexpectedly flagged (dormant facet changed; update docs)"
ok "DORMANT (asserted, all versions): a RELATIVE include operand is not path-checked at include time (best-effort); exec still attributed to the shell"

# 1e. CLI main script under uploads: CLI sets path_translated, so it is checked.
run_file 'mode="detect"\n[behavior]\nmode="detect"\n'"$DENY" "$UP/shell.php"
out_has SHELL_RAN || fail "1e: CLI shell did not run"
has_rule upload_exec || fail "1e: CLI main script under uploads not flagged"
has_rule unexpected_binary || fail "1e: exec by CLI main script under uploads not attributed"
ok "UploadExec for a CLI main script under uploads (CLI sets path_translated): flagged, and its exec attributed to uploads"

# ======================================================= 2. UnexpectedBinary
PROG=true; export PROG
run_file 'mode="detect"\n[behavior]\nmode="detect"\nallow_exec_binaries=["ls"]\n' "$APP/binary.php"
out_has BIN_DONE || fail "2a: script did not continue"
has_rule unexpected_binary || fail "2a: binary not in allowlist not flagged"
grep -q '"action":"log"' "$LOG" || fail "2a: expected action:log"
ok "UnexpectedBinary: exec of a program not in allow_exec_binaries -> logged"
run_file 'mode="detect"\n[behavior]\nmode="detect"\nallow_exec_binaries=["true"]\n' "$APP/binary.php"
out_has BIN_DONE || fail "2b: script did not continue"
no_events || fail "2b: allow-listed binary produced a finding"
ok "UnexpectedBinary: program in allow_exec_binaries -> no finding"
run_file 'mode="detect"\n[behavior]\nmode="block"\nallow_exec_binaries=["ls"]\n' "$APP/binary.php"
out_has BIN_DONE || fail "2c: script did not continue after blocked exec"
grep -q '"action":"block"' "$LOG" || fail "2c: no block under mode=block"
ok "UnexpectedBinary (block): spawn neutralized, script continued, action=block"
unset PROG

# ========================================================= 3. UnexpectedEgress
# L3 ssrf is deliberately left OFF (default): egress must work on its own.
TARGET="http://blocked.test/"; export TARGET
run_file 'mode="detect"\n[sinks.ssrf]\nmode="off"\n[behavior]\nmode="detect"\nallow_egress_hosts=["allowed.test"]\n' "$APP/egress.php"
out_has EGRESS_DONE || fail "3a: script did not continue"
has_rule unexpected_egress || fail "3a: egress to a non-allowlisted host not flagged (ssrf off)"
no_rule ssrf || fail "3a: L3 ssrf fired though it is off"
ok "UnexpectedEgress (L3 ssrf OFF): outbound to a host not in allow_egress_hosts -> logged"
TARGET="http://allowed.test/"
run_file 'mode="detect"\n[sinks.ssrf]\nmode="off"\n[behavior]\nmode="detect"\nallow_egress_hosts=["allowed.test"]\n' "$APP/egress.php"
out_has EGRESS_DONE || fail "3b: script did not continue"
no_events || fail "3b: allow-listed host produced a finding"
ok "UnexpectedEgress: allow-listed host -> no finding"
TARGET="http://192.0.2.1/"
run_file 'mode="detect"\n[sinks.ssrf]\nmode="off"\n[behavior]\nmode="detect"\nallow_egress_hosts=["allowed.test"]\n' "$APP/egress.php"
has_rule unexpected_egress || fail "3c: link-local literal IP not flagged"
ok "UnexpectedEgress: TEST-NET-1 (192.0.2.1) literal IP target (not allow-listed) -> logged"
TARGET="http://blocked.test/"
run_file 'mode="detect"\n[sinks.ssrf]\nmode="off"\n[behavior]\nmode="block"\nallow_egress_hosts=["allowed.test"]\n' "$APP/egress.php"
out_has EGRESS_DONE || fail "3d: script did not continue after blocked egress"
grep -q '"action":"block"' "$LOG" || fail "3d: no block under mode=block"
ok "UnexpectedEgress (block): connection refused by the guard, script continued, action=block"
unset TARGET

# ============================================================== 4. PhpWrite
PWDENY='deny_php_writes=true\n'"$DENY"
for HOW in fpc fopen; do
  export HOW
  export WTARGET="$UP/x.php"
  rm -f "$UP/x.php"
  run_file 'mode="detect"\n[behavior]\nmode="detect"\n'"$PWDENY" "$APP/write.php"
  out_has WRITE_DONE || fail "4a($HOW): script did not continue"
  has_rule php_write || fail "4a($HOW): .php write into uploads not flagged"
  [ -f "$UP/x.php" ] || fail "4a($HOW): detect should not prevent the write"
  ok "PhpWrite ($HOW, php-write-only: ssrf off, egress allowlist empty) detect: logged, write proceeded"
  rm -f "$UP/x.php"
  run_file 'mode="detect"\n[behavior]\nmode="block"\n'"$PWDENY" "$APP/write.php"
  out_has WRITE_DONE || fail "4b($HOW): script did not continue"
  out_has 'WRITE_RET\[false\]' || fail "4b($HOW): write was not refused"
  grep -q '"action":"block"' "$LOG" || fail "4b($HOW): no block event"
  has_rule php_write || fail "4b($HOW): no php_write rule"
  [ ! -f "$UP/x.php" ] || fail "4b($HOW): file was created despite block"
  ok "PhpWrite ($HOW) block: write refused, no file created, script continued, rule=php_write action=block"
done
# Blade guard: compiled-view write outside uploads, uploads-only deny_exec_dirs.
for HOW in fpc fopen; do
  export HOW
  export WTARGET="$APP/storage/framework/views/x.php"
  rm -f "$WTARGET"
  run_file 'mode="detect"\n[behavior]\nmode="block"\n'"$PWDENY" "$APP/write.php"
  out_has 'WRITE_RET\[ok\]' || fail "4c($HOW): legit view write was refused"
  no_events || fail "4c($HOW): Blade-style compiled-view write produced a finding"
  [ -f "$WTARGET" ] || fail "4c($HOW): view file missing"
done
ok "PhpWrite Blade guard: .php write to <app>/storage/framework/views with uploads-only deny_exec_dirs -> NO finding, file written (fpc + fopen, even under block)"
run_file 'mode="detect"\n[behavior]\nmode="block"\n'"$PWDENY" "$APP/read.php"
out_has 'READ\[res\]' || fail "4d: read of uploads/sub/ro.php failed"
no_rule php_write || fail "4d: read-mode open of a .php file inside the denied dir produced php_write"
no_events || fail "4d: read-mode open produced a finding"
ok "PhpWrite: fopen(uploads/sub/ro.php,'r') INSIDE the denied dir (read mode) -> NO finding"
unset HOW WTARGET

# ====================================================== 5. default / empty
# 5a. no [behavior] section at all: every scenario is silent, no blocks.
start_server ''
req /uploads/shell.php
[ "$CODE" = 200 ] || fail "5a: default config refused the shell ($CODE)"
no_events || fail "5a: default config produced behavior events (direct request)"
stop_server
export PROG=true TARGET="http://blocked.test/" HOW=fpc WTARGET="$UP/x.php"
for S in entry plain_exec binary egress write; do
  rm -f "$UP/x.php"
  run_file '' "$APP/$S.php"
  no_events || fail "5a: default config produced an event for $S.php"
done
ok "default config (no [behavior]): shell request, require, exec, egress and .php write all silent, zero blocks"
# 5b. empty detect policy: mode only, nothing configured -> inert.
start_server 'mode="detect"\n[behavior]\nmode="detect"\n'
req /uploads/shell.php
[ "$CODE" = 200 ] || fail "5b: empty policy refused ($CODE)"
no_events || fail "5b: empty policy produced events (direct request)"
stop_server
for S in entry plain_exec binary egress write; do
  rm -f "$UP/x.php"
  run_file 'mode="detect"\n[behavior]\nmode="detect"\n' "$APP/$S.php"
  no_events || fail "5b: empty policy produced an event for $S.php"
done
ok "empty [behavior] (detect, nothing configured): inert, zero events"
# 5c. global block does not arm behavior enforcement (independent mode).
start_server 'mode="block"\n'
req /uploads/shell.php
[ "$CODE" = 200 ] || fail "5c: global block refused the shell ($CODE)"
no_events || fail "5c: global block armed behavior"
stop_server
ok "global mode=block without [behavior] policy: behavior not armed, shell served"
unset PROG TARGET HOW WTARGET

# ============================================================ 6. observe
OBS='mode="block"\n[behavior]\nmode="block"\nobserve=true\n'"$DENY"'allow_exec_binaries=["ls"]\nallow_egress_hosts=["allowed.test"]\ndeny_php_writes=true\n'
start_server "$OBS"
req /uploads/shell.php
[ "$CODE" = 200 ] || fail "6a: observe refused the shell ($CODE)"
out_has SHELL_RAN || fail "6a: shell did not run under observe"
grep -q proposed "$LOG" || fail "6a: no proposed line"
has_rule upload_exec || fail "6a: no upload_exec proposal"
no_blocks || fail "6a: observe produced a block"
stop_server
ok "observe=true (mode=block): direct shell request -> HTTP 200 + proposed upload_exec line, zero blocks"
export PROG=true TARGET="http://blocked.test/" HOW=fpc WTARGET="$UP/x.php"
proposed_rule() { grep "\"rule\":\"$1\"" "$LOG" | grep -q proposed; }
# script : rule that must be PROPOSED : marker proving the action proceeded
for CASE in entry:upload_exec:SHELL_RAN binary:unexpected_binary:BIN_DONE egress:unexpected_egress:EGRESS_DONE write:php_write:'WRITE_RET\[ok\]'; do
  S=${CASE%%:*}; REST=${CASE#*:}; RULE=${REST%%:*}; MARK=${REST#*:}
  rm -f "$UP/x.php"
  run_file "$OBS" "$APP/$S.php"
  proposed_rule "$RULE" || fail "6b: $S.php: no 'proposed' $RULE line"
  no_blocks || fail "6b: observe produced a block for $S.php"
  out_has "$MARK" || fail "6b: $S.php: action did not proceed under observe (marker $MARK missing)"
  [ "$S" != write ] || [ -f "$UP/x.php" ] || fail "6b: observe prevented the .php write"
done
ok "observe=true (mode=block): require->upload_exec, exec->unexpected_binary, egress->unexpected_egress, .php write->php_write each PROPOSED; every action proceeded; zero blocks"
unset PROG TARGET HOW WTARGET

# ---- leak guard: no written payload marker in the log -----------------------
if grep -q 'howdah-l4-test' "$LOG"; then fail "log leaked the written payload marker"; fi

echo "PASS ($PASSN checks, $FEATURE)"
