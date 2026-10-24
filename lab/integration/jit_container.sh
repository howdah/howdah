#!/bin/sh
# In-container half of the OPcache JIT compatibility test (Howdah 1.4.x,
# "JIT-compatible include/eval hook"):
#   J1. include and eval off          -> no hook installed, JIT stays ON
#   J2. default config (eval detect)  -> hook=auto picks the compile pointer,
#                                        JIT stays ON, eval detect still fires
#   J2b. hook = "opcode"              -> opcode handler, JIT OFF, startup line
#   J3. [sinks] hook = "compile"      -> compile pointer, JIT ON, eval/include
#                                        still fire; the warm-opcache caveat
#   J4. compile-mode misfire guard    -> main script / auto_prepend silent
#   J5. Layer-4 deny_exec_dirs alone  -> arms the hook; auto picks opcode
#   J6. startup line only when JIT is really configured on
#   J7. include allow_paths           -> auto flips to the opcode handler
# Runs inside a howdah-dev-php<ver> image using `php -r` / script files.
# JIT assertions run on PHP 8.x only (there is no JIT before 8.0); the
# functional compile-mode assertions run on 7.x and 8.x; 5.x checks only
# the phpinfo row (its hook is always the compile pointer).
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-jit
LOG="$WORK/events.log"
rm -rf "$WORK"; mkdir -p "$WORK/deny"

echo "== php $(php -r 'echo PHP_VERSION;') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
cd "$WORK"

fail() {
  echo "FAIL: $1"
  echo "--- stdout ---"; cat "$WORK/out.txt" 2>/dev/null
  echo "--- stderr ---"; cat "$WORK/err.txt" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  exit 1
}

# OPcache with the JIT on, the way the brief measured it. The 8.1/8.3 images
# already load opcache.so from conf.d (do not load it twice); 7.x/5.6 ship
# opcache.so unloaded; 8.5 has it compiled in. file_update_protection=0 so a
# fixture written a moment ago is cacheable (the warm-opcache demonstration).
OC="-d opcache.enable=1 -d opcache.enable_cli=1 -d opcache.file_update_protection=0 -d opcache.log_verbosity_level=2"
if ! php -m 2>/dev/null | grep -q 'Zend OPcache'; then
  if [ -f "$(php-config --extension-dir)/opcache.so" ]; then
    OC="-d zend_extension=opcache.so $OC"
  else
    echo "  note - no opcache in this image; nothing to test"; echo "PASS"; exit 0
  fi
fi
if [ "$FEATURE" = php8 ]; then
  OC="$OC -d opcache.jit=tracing -d opcache.jit_buffer_size=64M"
fi

# run_php <toml-content> <php code> [extra -d args...]; stdout -> out.txt.
run_php() {
  printf '%b' "$1" > "$WORK/jit.toml"
  code="$2"; shift 2
  : > "$LOG"
  # shellcheck disable=SC2086
  php $OC -d extension="$WORK/howdah.so" -d howdah.config="$WORK/jit.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d display_startup_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      "$@" -r "$code" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}
# Same, for a script FILE (the main script goes through compile_file).
run_file() {
  printf '%b' "$1" > "$WORK/jit.toml"
  file="$2"; shift 2
  : > "$LOG"
  # shellcheck disable=SC2086
  php $OC -d extension="$WORK/howdah.so" -d howdah.config="$WORK/jit.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d display_startup_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      "$@" "$file" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}
# The `php --ri howdah` row for a config.
ri_row() {
  printf '%b' "$1" > "$WORK/jit.toml"
  # shellcheck disable=SC2086
  php $OC -d extension="$WORK/howdah.so" -d howdah.config="$WORK/jit.toml" -d howdah.log="$LOG" \
      --ri howdah 2>"$WORK/err.txt" | grep 'Include/eval hook' || true
}
out_has() { cat "$WORK/out.txt" "$WORK/err.txt" | grep -qi "$1"; }
no_events() { [ ! -s "$LOG" ]; }

# JIT status as PHP itself reports it ("on"/"off"/"nojit").
JITQ='$s=opcache_get_status(false); echo "JIT[", (isset($s["jit"]) ? ($s["jit"]["on"] ? "on" : "off") : "nojit"), "]\n";'
STARTUP='howdah: OPcache JIT is enabled'

export INC="$WORK/inc.php"
printf '<?php echo "INC_RAN\\n"; return 7;' > "$INC"
printf '<?php echo "DENY_RAN\\n";' > "$WORK/deny/x.php"
OFF='[sinks.include]\nmode="off"\n[sinks.eval]\nmode="off"\n'
ALLOW='[sinks.include]\nmode="detect"\nallow_paths=["/var/www/app"]\n'

# ------------------------------------------------------------------ J1
# include and eval off: no hook, JIT on, no startup line.
row=$(ri_row "$OFF")
echo "$row" | grep -q 'Include/eval hook => none' || fail "J1: expected hook row 'none', got: $row"
run_php "$OFF" "$JITQ"
grep -q "$STARTUP" "$WORK/err.txt" && fail "J1: startup line written with nothing armed"
if [ "$FEATURE" = php8 ]; then
  grep -q 'JIT\[on\]' "$WORK/out.txt" || fail "J1: JIT not on with include/eval off"
  out_has 'JIT is incompatible' && fail "J1: PHP still reported a user opcode handler"
  echo "  ok   - J1 include+eval off: no hook installed, opcache_get_status jit.on = true, no startup line"
else
  echo "  ok   - J1 include+eval off: no hook installed (row: none)"
fi

# ------------------------------------------------------------------ J2
# Shipped default (eval inherits detect, include inert, no deny_exec_dirs):
# hook = "auto" picks the compile pointer, so a default install keeps the JIT
# ON, and eval detect still fires through it.
row=$(ri_row '')
echo "$row" | grep -q 'compile pointer' || fail "J2: default config expected compile pointer, got: $row"
echo "$row" | grep -q 'auto: eval only' || fail "J2: row does not say why (auto: eval only): $row"
run_php '' 'eval("echo 99;"); echo "\n"; '"$JITQ"
grep -q 99 "$WORK/out.txt" || fail "J2: eval did not run in the default config"
grep -q '"rule":"eval"' "$LOG" || fail "J2: eval detect did not fire through the default (compile) hook"
grep -q "$STARTUP" "$WORK/err.txt" && fail "J2: startup line although the default installs no opcode handler"
if [ "$FEATURE" = php8 ]; then
  grep -q 'JIT\[on\]' "$WORK/out.txt" || fail "J2: default config turned the JIT off"
  out_has 'JIT is incompatible' && fail "J2: PHP reported a user opcode handler under the default config"
  echo "  ok   - J2 default config: hook=auto -> compile pointer (auto: eval only), jit.on = true, eval detect still logs, no startup line"
else
  echo "  ok   - J2 default config: hook=auto -> compile pointer (auto: eval only), eval detect still logs (row: $row)"
fi

# J2b. Explicit hook = "opcode": the handler, JIT off, the startup line.
OPC='[sinks]\nhook="opcode"\n'
if [ "$FEATURE" = php5 ]; then
  row=$(ri_row "$OPC")
  echo "$row" | grep -q 'compile pointer' || fail "J2b: 5.x expected compile pointer even for hook=opcode, got: $row"
  echo "  ok   - J2b php5 hook=opcode: still the compile pointer (the only 5.x mechanism)"
else
  row=$(ri_row "$OPC")
  echo "$row" | grep -q 'opcode handler' || fail "J2b: expected opcode handler row, got: $row"
  echo "$row" | grep -q 'configured' || fail "J2b: row does not say configured: $row"
  run_php "$OPC" "$JITQ"
  if [ "$FEATURE" = php8 ]; then
    echo "$row" | grep -q 'opcode handler (JIT disabled by PHP; configured)' || fail "J2b: row text: $row"
    grep -q 'JIT\[off\]' "$WORK/out.txt" || fail "J2b: JIT not off under the opcode handler"
    grep -q "$STARTUP" "$WORK/err.txt" || fail "J2b: no startup line although JIT is configured on"
    grep -q 'hook = "compile"' "$WORK/err.txt" || fail "J2b: startup line does not name [sinks] hook"
    out_has 'JIT is incompatible' && echo "  info - PHP said: $(grep -io 'JIT is incompatible[^.]*' "$WORK/out.txt" "$WORK/err.txt" | head -1)"
    echo "  ok   - J2b hook=opcode: opcode handler (configured), jit.on = false, one startup line naming [sinks] hook = \"compile\""
  else
    grep -q "$STARTUP" "$WORK/err.txt" && fail "J2b: startup line on a PHP without JIT"
    echo "  ok   - J2b hook=opcode: opcode handler (row: $row), no JIT line on 7.x"
  fi
fi

# ------------------------------------------------------------------ J3
# hook = "compile": JIT on, eval and include still fire, block works.
COMPILE='[sinks]\nhook="compile"\n'
row=$(ri_row "$COMPILE")
echo "$row" | grep -q 'compile pointer' || fail "J3: expected compile pointer row, got: $row"
run_php "$COMPILE" "$JITQ"
grep -q "$STARTUP" "$WORK/err.txt" && fail "J3: startup line in compile mode"
if [ "$FEATURE" = php8 ]; then
  echo "$row" | grep -q 'compile pointer (JIT compatible; configured)' || fail "J3: row text: $row"
  grep -q 'JIT\[on\]' "$WORK/out.txt" || fail "J3: JIT not on in compile mode"
  echo "  ok   - J3 hook=compile: jit.on = true, row 'compile pointer (JIT compatible; configured)', no startup line"
fi
if [ "$FEATURE" != php5 ]; then
  # eval detect: logs and runs.
  run_php "$COMPILE"'[sinks.eval]\nmode="detect"\n' 'eval("echo 99;"); echo "\nCONT\n";'
  grep -q 99 "$WORK/out.txt" || fail "J3: eval did not run in detect (compile)"
  grep -q '"rule":"eval"' "$LOG" || fail "J3: no eval event in compile mode"
  grep -q '"action":"log"' "$LOG" || fail "J3: eval event not action:log"
  # eval block: does not run, continues.
  run_php "$COMPILE"'[sinks.eval]\nmode="block"\n' '$r=eval("echo 99;"); echo "\nRET[".var_export($r,true)."]\nCONT\n";'
  grep -q 99 "$WORK/out.txt" && fail "J3: eval ran despite block (compile)"
  grep -q CONT "$WORK/out.txt" || fail "J3: script did not continue after eval block (compile)"
  grep -q '"action":"block"' "$LOG" || fail "J3: no block event for eval (compile)"
  # include detect: logs, runs, path not logged.
  run_php "$COMPILE$ALLOW" '$p=getenv("INC"); include $p; echo "CONT\n";'
  grep -q INC_RAN "$WORK/out.txt" || fail "J3: include did not run in detect (compile)"
  grep -q '"rule":"include"' "$LOG" || fail "J3: no include event (compile)"
  grep -qF "$INC" "$LOG" && fail "J3: log leaked the include path"
  # include / require block: false, no fatal, continues.
  run_php "$COMPILE"'[sinks.include]\nmode="block"\nallow_paths=["/var/www/app"]\n' '$p=getenv("INC"); $a=include $p; $b=require $p; echo "RET[".var_export($a,true)."][".var_export($b,true)."]\nCONT\n";'
  grep -q INC_RAN "$WORK/out.txt" && fail "J3: include/require ran despite block (compile)"
  out_has 'Fatal\|segfault' && fail "J3: require block raised a fatal (compile)"
  grep -q 'RET\[false\]\[false\]' "$WORK/out.txt" || fail "J3: include/require block did not return false (compile)"
  grep -q CONT "$WORK/out.txt" || fail "J3: script did not continue after include block (compile)"
  # computed operand ($a.$b) block is safe.
  run_php "$COMPILE"'[sinks.include]\nmode="block"\nallow_paths=["/var/www/app"]\n' '$a="/tmp/"; $b="nope.php"; $r=include $a.$b; echo "RET[".var_export($r,true)."] COMPUTED_OK\n";'
  grep -q COMPUTED_OK "$WORK/out.txt" || fail "J3: computed-operand include block crashed (compile)"
  echo "  ok   - J3 compile mode: eval detect logs+runs, eval block skips; include detect logs (path not logged), include/require block return false, no fatal, computed operand safe"

  # WARM-OPCACHE CAVEAT, demonstrated: the same file included twice in one
  # process. Opcode mode sees both (2 include events); compile mode sees the
  # first compile only (1 event), the second include is served from opcache.
  TWICE='$p=getenv("INC"); include $p; include $p; echo "CONT\n";'
  run_php "$ALLOW" "$TWICE"
  n_op=$(grep -c '"rule":"include"' "$LOG" || true)
  run_php "$COMPILE$ALLOW" "$TWICE"
  n_co=$(grep -c '"rule":"include"' "$LOG" || true)
  [ "$(grep -c INC_RAN "$WORK/out.txt")" = 2 ] || fail "J3: the file did not run twice"
  [ "$n_op" = 2 ] || fail "J3: opcode mode logged $n_op include events for two includes (expected 2)"
  [ "$n_co" = 1 ] || fail "J3: compile mode logged $n_co include events for two includes (expected 1: the second is a warm-opcache hit)"
  # eval has no cache: both mechanisms see every eval.
  run_php "$COMPILE"'[sinks.eval]\nmode="detect"\n' 'eval("1;"); eval("1;"); echo "CONT\n";'
  [ "$(grep -c '"rule":"eval"' "$LOG")" = 2 ] || fail "J3: compile mode missed a repeated eval"
  echo "  ok   - J3 warm-opcache caveat shown: include twice -> opcode mode 2 events, compile mode 1 event (second served from opcache); eval 2/2 in compile mode"

  # ---------------------------------------------------------------- J4
  # Misfire guard in compile mode: main script + auto_prepend_file are not
  # runtime includes and must produce no event with include AND eval armed.
  printf '<?php echo "PREPEND_RAN\\n";' > "$WORK/pre.php"
  printf '<?php echo "MAIN_RAN\\n";' > "$WORK/main.php"
  run_file "$COMPILE$ALLOW"'[sinks.eval]\nmode="block"\n' "$WORK/main.php" -d auto_prepend_file="$WORK/pre.php"
  grep -q PREPEND_RAN "$WORK/out.txt" || fail "J4: auto_prepend_file did not run"
  grep -q MAIN_RAN "$WORK/out.txt" || fail "J4: main script did not run"
  no_events || fail "J4: misfire - main script / auto_prepend_file produced an event in compile mode"
  echo "  ok   - J4 compile-mode misfire guard: main script and auto_prepend_file produce no events"
fi

# ------------------------------------------------------------------ J5
# Layer 4 alone: [sinks] enabled=false but deny_exec_dirs set arms the hook
# (its required-file check lives in it); the mechanism still follows hook=.
L4='[sinks]\nenabled=false\n[behavior]\nmode="detect"\ndeny_exec_dirs=["'"$WORK/deny"'"]\n'
row=$(ri_row "$L4")
echo "$row" | grep -q 'auto: deny_exec_dirs set' || fail "J5: row does not say why (auto: deny_exec_dirs set): $row"
if [ "$FEATURE" = php5 ]; then
  echo "$row" | grep -q 'compile pointer' || fail "J5: deny_exec_dirs did not arm the hook (row: $row)"
else
  echo "$row" | grep -q 'opcode handler' || fail "J5: deny_exec_dirs did not flip auto to the opcode hook (row: $row)"
fi
row=$(ri_row '[sinks]\nenabled=false\nhook="compile"\n[behavior]\nmode="detect"\ndeny_exec_dirs=["'"$WORK/deny"'"]\n')
echo "$row" | grep -q 'compile pointer' || fail "J5: hook=compile not honoured for a Layer-4-only arm (row: $row)"
export DENY="$WORK/deny/x.php"
run_php '[sinks]\nenabled=false\nhook="compile"\n[behavior]\nmode="detect"\ndeny_exec_dirs=["'"$WORK/deny"'"]\n' \
  '$p=getenv("DENY"); require $p; echo "CONT\n";'
grep -q DENY_RAN "$WORK/out.txt" || fail "J5: required file did not run in detect"
grep -q '"rule":"upload_exec"' "$LOG" || fail "J5: deny_exec_dirs required-file check did not fire in compile mode"
echo "  ok   - J5 Layer-4 deny_exec_dirs alone arms the hook; in compile mode the required-file exec-dir check still logs upload_exec"

# ------------------------------------------------------------------ J6
# The startup line only when JIT is actually configured on (8.x), with the
# opcode handler explicitly chosen (the default no longer installs it).
if [ "$FEATURE" = php8 ]; then
  run_php "$OPC" "$JITQ" -d opcache.jit=disable
  grep -q "$STARTUP" "$WORK/err.txt" && fail "J6: startup line although opcache.jit=disable"
  run_php "$OPC" "$JITQ" -d opcache.jit_buffer_size=0
  grep -q "$STARTUP" "$WORK/err.txt" && fail "J6: startup line although jit_buffer_size=0"
  run_php "$OPC" "$JITQ" -d opcache.enable_cli=0
  grep -q "$STARTUP" "$WORK/err.txt" && fail "J6: startup line although opcache.enable_cli=0 on the CLI"
  echo "  ok   - J6 no startup line when opcache.jit=disable, jit_buffer_size=0 or enable_cli=0 (ini read at MINIT via cfg_get_string, before opcache registers its entries)"
fi

# ------------------------------------------------------------------ J7
# include allow_paths flips auto to the opcode handler (warm-opcache includes
# matter there): row says why, JIT off, the startup line fires (8.x).
row=$(ri_row "$ALLOW")
echo "$row" | grep -q 'auto: include allow_paths set' || fail "J7: row does not say why (auto: include allow_paths set): $row"
if [ "$FEATURE" = php5 ]; then
  echo "$row" | grep -q 'compile pointer' || fail "J7: 5.x row: $row"
  echo "  ok   - J7 php5 include allow_paths: compile pointer (auto: include allow_paths set)"
else
  echo "$row" | grep -q 'opcode handler' || fail "J7: include allow_paths did not flip auto to opcode (row: $row)"
  run_php "$ALLOW" "$JITQ"
  if [ "$FEATURE" = php8 ]; then
    grep -q 'JIT\[off\]' "$WORK/out.txt" || fail "J7: JIT still on although auto chose the opcode handler"
    grep -q "$STARTUP" "$WORK/err.txt" || fail "J7: no startup line for auto-chose-opcode"
    echo "  ok   - J7 include allow_paths: auto -> opcode handler (auto: include allow_paths set), jit.on = false, startup line names hook = \"compile\""
  else
    echo "  ok   - J7 include allow_paths: auto -> opcode handler (row: $row)"
  fi
fi

# ------------------------------------------------------------------ J8
# opcache.preload (7.4+) in compile mode: the files the preload script
# require()s are compiled at startup with EG(current_execute_data) set, which
# would look like runtime includes; the hook chains them unguarded (no event),
# and a runtime include in the request is still inspected. Preloading as root
# needs opcache.preload_user; the php images have www-data.
if php -r 'exit(PHP_VERSION_ID >= 70400 ? 0 : 1);' && id www-data >/dev/null 2>&1; then
  printf '<?php function preloaded_fn(){return 1;}\n' > "$WORK/pre_lib.php"
  printf '<?php require __DIR__."/pre_lib.php";\n' > "$WORK/preload.php"
  chmod -R a+rX "$WORK"
  run_php "$COMPILE$ALLOW" '$p=getenv("INC"); echo "PRELOADED[", function_exists("preloaded_fn") ? "yes" : "no", "]\n"; include $p; echo "CONT\n";' \
    -d opcache.preload="$WORK/preload.php" -d opcache.preload_user=www-data
  if grep -q 'PRELOADED\[yes\]' "$WORK/out.txt"; then
    grep -q INC_RAN "$WORK/out.txt" || fail "J8: runtime include did not run with preload active"
    grep -q CONT "$WORK/out.txt" || fail "J8: script did not continue"
    [ "$(grep -c '"rule":"include"' "$LOG")" = 1 ] || fail "J8: expected exactly 1 include event (the runtime include); the preload require must chain unguarded. Got: $(grep -c '"rule":"include"' "$LOG")"
    echo "  ok   - J8 opcache.preload in compile mode: preload require chained unguarded (no event), runtime include still logged once"
  else
    echo "  note - J8 skipped: opcache.preload did not activate here ($(grep -io 'preload[^.]*' "$WORK/err.txt" | head -1))"
  fi
else
  echo "  note - J8 skipped: opcache.preload needs PHP 7.4+ and a www-data user"
fi

# ------------------------------------------------------------------ J9
# Interaction with the per-request refusal compile swap (refuse_hook.c, #44):
# in compile mode our hook IS zend_compile_file. A Layer-1 multipart flood
# (over max_files) must still be refused with the 403 "Howdah blocked" body,
# the server must survive, and the NEXT request must compile through our hook
# again (its eval is logged): refuse_hook saves whatever zend_compile_file is
# at arm time and restores it at RSHUTDOWN. Driven over HTTP on the CLI
# built-in server so the request goes through php_request_startup.
if command -v curl >/dev/null 2>&1; then
  mkdir -p "$WORK/www9"
  printf '<?php eval("echo 1;"); echo "PAGE_OK\\n";' > "$WORK/www9/index.php"
  printf '%b' "$COMPILE"'[limits]\nmax_files = 3\n[sinks.eval]\nmode="detect"\n' > "$WORK/j9.toml"
  : > "$LOG"
  # shellcheck disable=SC2086
  php $OC -d extension="$WORK/howdah.so" -d howdah.config="$WORK/j9.toml" -d howdah.log="$LOG" \
      -d post_max_size=16M -d upload_max_filesize=16M -d max_file_uploads=100000 -d date.timezone=UTC \
      -S 127.0.0.1:18199 "$WORK/www9/index.php" > "$WORK/srv9.log" 2>&1 &
  SRV9=$!
  i=0
  until curl -s -o /dev/null "http://127.0.0.1:18199/" 2>/dev/null; do
    i=$((i+1)); [ $i -gt 50 ] && { cat "$WORK/srv9.log"; fail "J9: cli-server did not start"; }
    php -r 'usleep(100000);'
  done
  : > "$LOG"
  # A flood body: 10 empty file parts (max_files = 3).
  : > "$WORK/flood9.bin"; n=0
  while [ $n -lt 10 ]; do
    printf -- '--J9B\r\nContent-Disposition: form-data; name="f%s"; filename="f%s.bin"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n' $n $n >> "$WORK/flood9.bin"
    n=$((n+1))
  done
  printf -- '--J9B--\r\n' >> "$WORK/flood9.bin"
  code=$(curl -s -o "$WORK/r9.txt" -w '%{http_code}' -X POST -H "Content-Type: multipart/form-data; boundary=J9B" --data-binary @"$WORK/flood9.bin" "http://127.0.0.1:18199/" || true)
  echo "$code" | grep -qE '^(403|413)$' || { cat "$WORK/r9.txt" "$WORK/srv9.log"; fail "J9: flood not refused in compile mode (HTTP $code)"; }
  grep -q 'Howdah blocked' "$WORK/r9.txt" || fail "J9: refusal body missing 'Howdah blocked'"
  grep -q PAGE_OK "$WORK/r9.txt" && fail "J9: the refused request still ran the script"
  grep -q '"rule":"max_files"' "$LOG" || fail "J9: no max_files event for the flood"
  # The next, normal request: server alive, script runs, eval goes through
  # our (restored) compile hook and is logged.
  : > "$LOG"
  code2=$(curl -s -o "$WORK/r9b.txt" -w '%{http_code}' "http://127.0.0.1:18199/" || true)
  kill "$SRV9" 2>/dev/null || true
  [ "$code2" = 200 ] || { cat "$WORK/srv9.log"; fail "J9: server did not answer the next request after a refusal (HTTP $code2): worker died?"; }
  grep -q PAGE_OK "$WORK/r9b.txt" || fail "J9: next request did not run"
  grep -q '"rule":"eval"' "$LOG" || fail "J9: eval not logged on the request after a refusal: the compile hook was not restored"
  echo "  ok   - J9 refusal in compile mode: flood -> HTTP $code 'Howdah blocked' (max_files), script not run; next request 200 and its eval logged through the restored compile hook"
else
  echo "  note - J9 skipped: curl not in this image"
fi

echo "PASS"
