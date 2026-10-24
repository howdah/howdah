#!/bin/sh
# In-container half of the Layer-3 sink integration test.
# Runs inside a howdah-dev-php<ver> image using `php -r` CLI snippets.
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-l3
LOG="$WORK/events.log"
rm -rf "$WORK"; mkdir -p "$WORK"

echo "== php $(php -r 'echo PHP_VERSION;') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"

fail() {
  echo "FAIL: $1"
  echo "--- stdout ---"; cat "$WORK/out.txt" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  exit 1
}

# run_php <toml-content> <php code> [extra -d args...]; stdout -> out.txt
run_php() {
  printf '%b' "$1" > "$WORK/l3.toml"
  code="$2"; shift 2
  : > "$LOG"
  php -d extension="$WORK/howdah.so" -d howdah.config="$WORK/l3.toml" \
      -d howdah.log="$LOG" "$@" -r "$code" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}

# 1. command_exec detect: logs, command still runs, argument never logged
run_php '[sinks.command_exec]\nmode="detect"\n' "system('id');"
grep -q 'uid=' "$WORK/out.txt" || fail "1: id did not run in detect"
grep -q '"rule":"command_exec"' "$LOG" || fail "1: no command_exec event"
grep -q '"action":"log"' "$LOG" || fail "1: no action:log"
grep -q 'system' "$LOG" || fail "1: event does not mention system"
if grep -q 'uid=' "$LOG"; then fail "1: log leaked command output"; fi
if grep -qE "system\\(.id.\\)|\"id\"|[( '\"]id[) '\"]" "$LOG"; then fail "1: log leaked the command"; fi
echo "  ok   - command_exec detect: logged (system), id ran, argument/output not logged"

# 2. allowlisted -> silent, runs
run_php '[sinks.command_exec]\nmode="block"\nallow=["id"]\n' "system('id');"
grep -q 'uid=' "$WORK/out.txt" || fail "2: allowlisted id did not run"
if [ -s "$LOG" ]; then fail "2: allowlisted call produced an event"; fi
echo "  ok   - command_exec allowlisted: silent, id ran"

# 3. global block does not arm a sink
run_php '[sinks.command_exec]\n' "system('id');" -d howdah.mode=block
grep -q 'uid=' "$WORK/out.txt" || fail "3: global block armed the sink (id did not run)"
grep -q '"rule":"command_exec"' "$LOG" || fail "3: no command_exec event"
grep -q '"action":"log"' "$LOG" || fail "3: expected action:log"
if grep -q '"action":"block"' "$LOG"; then fail "3: sink blocked under global block"; fi
echo "  ok   - global howdah.mode=block does not arm sink: id ran, action=log"

# 4. command_exec block -> neutralized
run_php '[sinks.command_exec]\nmode="block"\n' '$r = system("id"); echo "\nRET[".var_export($r,true)."]\nCONTINUED\n";'
if grep -q 'uid=' "$WORK/out.txt"; then fail "4: id ran despite block"; fi
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "4: system did not return false"
grep -q 'CONTINUED' "$WORK/out.txt" || fail "4: script did not continue"
grep -q '"action":"block"' "$LOG" || fail "4: no action:block"
grep -q '"rule":"command_exec"' "$LOG" || fail "4: no command_exec rule"
echo "  ok   - command_exec block: neutralized (false, id did not run, script continued)"

# 5. unserialize off by default -> silent
run_php '' "unserialize('O:8:\"stdClass\":0:{}');"
if [ -s "$LOG" ]; then fail "5: unserialize logged while off by default"; fi
echo "  ok   - unserialize default: silent"

# 6. unserialize detect -> class, not payload
run_php '[sinks.unserialize]\nmode="detect"\n' "unserialize('O:8:\"stdClass\":0:{}');"
grep -q '"rule":"unserialize"' "$LOG" || fail "6: no unserialize event"
grep -q '"action":"log"' "$LOG" || fail "6: no action:log"
if grep -qF 'O:8:' "$LOG"; then fail "6: log leaked serialized payload"; fi
echo "  ok   - unserialize detect: logged, payload not logged"

# --- include/eval: ACTIVE on PHP 7.0+, DORMANT on PHP 5.x ---
INC="$WORK/inc.php"
printf '<?php echo "INC_RAN\\n";' > "$INC"

if [ "$FEATURE" = php5 ]; then
  # 7(php5). include/eval have no opcode handler on 5.x: block config is inert,
  # the include runs, and nothing is logged.
  run_php '[sinks.include]\nmode="block"\nallow_paths=["/var/www/app"]\n' "\$p='$INC'; include \$p; echo \"CONT\n\";"
  grep -q 'INC_RAN' "$WORK/out.txt" || fail "7(php5): include did not run (should be dormant on 5.x)"
  if [ -s "$LOG" ]; then fail "7(php5): include produced an event (dormant on 5.x)"; fi
  echo "  ok   - php5: include/eval dormant (no hook) — include ran, no event"
else
  # 7. include detect (path outside allow_paths) -> logs, file runs, path never logged
  run_php '[sinks.include]\nmode="detect"\nallow_paths=["/var/www/app"]\n' "\$p='$INC'; include \$p;"
  grep -q 'INC_RAN' "$WORK/out.txt" || fail "7: include did not run in detect"
  grep -q '"rule":"include"' "$LOG" || fail "7: no include event"
  grep -q '"action":"log"' "$LOG" || fail "7: no action:log"
  if grep -qF "$INC" "$LOG"; then fail "7: log leaked the include path"; fi
  echo "  ok   - include detect: logged, file ran, path not logged"

  # 8. include block -> neutralized (file not run, script continues)
  run_php '[sinks.include]\nmode="block"\nallow_paths=["/var/www/app"]\n' "\$p='$INC'; include \$p; echo \"CONT\n\";"
  if grep -q 'INC_RAN' "$WORK/out.txt"; then fail "8: include ran despite block"; fi
  grep -q 'CONT' "$WORK/out.txt" || fail "8: script did not continue after include block"
  grep -q '"action":"block"' "$LOG" || fail "8: no action:block"
  grep -q '"rule":"include"' "$LOG" || fail "8: no include rule"
  echo "  ok   - include block: neutralized (file not run, script continued)"

  # 9. eval block -> neutralized (eval does not run, script continues)
  run_php '[sinks.eval]\nmode="block"\n' 'eval("echo 99;"); echo "\nCONT2\n";'
  if grep -q '99' "$WORK/out.txt"; then fail "9: eval ran despite block"; fi
  grep -q 'CONT2' "$WORK/out.txt" || fail "9: script did not continue after eval block"
  grep -q '"rule":"eval"' "$LOG" || fail "9: no eval rule"
  grep -q '"action":"block"' "$LOG" || fail "9: no action:block"
  echo "  ok   - eval block: neutralized (eval did not run, script continued)"
fi

echo "PASS"
