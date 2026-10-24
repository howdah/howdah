#!/bin/sh
# In-container half of the Layer-3 fast-follow integration test:
#   A. phar:// wrapper guard      (all PHP generations)
#   B. SSRF egress guard          (all PHP generations)
#   C. PHP 5.x include/eval guard (php5 only; 7.0+ is covered in sinks_container.sh)
# Runs inside a howdah-dev-php<ver> image using `php -r` / script-file snippets.
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-ff
LOG="$WORK/events.log"
rm -rf "$WORK"; mkdir -p "$WORK/www"

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

# Optional ordering knobs (see section A0): NOINI, PRE_EXT (loaded before
# howdah), POST_EXT (loaded after howdah).
NOINI=""; PRE_EXT=""; POST_EXT=""

# run_php <toml-content> <php code> [extra -d args...]; stdout -> out.txt.
# Paths/URLs reach the snippet through the environment (getenv), so the PHP
# code can stay in plain single quotes.
run_php() {
  printf '%b' "$1" > "$WORK/l3.toml"
  code="$2"; shift 2
  : > "$LOG"
  # shellcheck disable=SC2086
  php $NOINI $PRE_EXT -d extension="$WORK/howdah.so" $POST_EXT \
      -d howdah.config="$WORK/l3.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      -d default_socket_timeout=3 "$@" -r "$code" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}
# Same, for a script FILE (so the main script goes through compile_file).
run_file() {
  printf '%b' "$1" > "$WORK/l3.toml"
  file="$2"; shift 2
  : > "$LOG"
  # shellcheck disable=SC2086
  php $NOINI $PRE_EXT -d extension="$WORK/howdah.so" $POST_EXT \
      -d howdah.config="$WORK/l3.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      "$@" "$file" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}

# out_has <pattern>: stdout OR stderr (PHP warnings go to either).
out_has() { cat "$WORK/out.txt" "$WORK/err.txt" | grep -qi "$1"; }
no_events() { [ ! -s "$LOG" ]; }

# ---------------------------------------------------------------- fixtures
export PH="$WORK/t.phar"
php -d phar.readonly=0 /src/lab/integration/corpus/make_phar.php "$PH" >/dev/null 2>&1 \
  || { echo "FAIL: could not build the tracer phar fixture"; exit 1; }
printf 'PLAINFILE' > "$WORK/plain.txt"; export PLAIN="$WORK/plain.txt"
printf '<?php return 1;' > "$WORK/config.php"
printf '<?php echo "SERVED";' > "$WORK/www/index.php"
export INC="$WORK/inc.php"
printf '<?php echo "INC_RAN\\n"; return 7;' > "$INC"
TR='class Tracer{public $x=1; function __wakeup(){echo "WOKE\n";}}'

# Loopback HTTP target for SSRF "proceeds" checks (no howdah in this process).
PORT=18099
php -S 127.0.0.1:$PORT -t "$WORK/www" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
i=0
until php -r '$s=@fsockopen("127.0.0.1",'$PORT'); exit($s?0:1);' 2>/dev/null; do
  i=$((i+1)); [ $i -gt 50 ] && { echo "FAIL: loopback test server did not start"; exit 1; }
  php -r 'usleep(100000);'
done
export URL="http://127.0.0.1:$PORT/SECRETPATH?tok=abc123"
export URLDEC="http://2130706433:$PORT/SECRETPATH?tok=abc123"

# ================================================================ A. PHAR
# phar access that the wrapper sees (stat + open).
PHACC='@file_get_contents("phar://".getenv("PH")."/x"); echo "CONT\n";'

# A1. default OFF: silent. Exposure baseline (unguarded): 5.x/7.x unserialize
# the metadata on ANY phar:// access, so the tracer fires; 8.x does not.
run_php '' "$TR $PHACC"
no_events || fail "A1: phar produced an event while off by default"
grep -q CONT "$WORK/out.txt" || fail "A1: script did not continue"
if [ "$FEATURE" = php8 ]; then
  if grep -q WOKE "$WORK/out.txt"; then fail "A1: tracer fired unguarded on 8.x (expected: no auto-unserialize)"; fi
  echo "  ok   - phar default off: silent; 8.x does not auto-unserialize phar metadata (no WOKE even unguarded)"
else
  grep -q WOKE "$WORK/out.txt" || fail "A1: tracer did not fire unguarded (exposure not demonstrated)"
  echo "  ok   - phar default off: silent; UNGUARDED phar:// access fires the tracer __wakeup (real exposure)"
fi

# A2. detect: logs rule=phar, the phar PATH never logged; access proceeds.
run_php '[sinks.phar]\nmode="detect"\n' "$TR $PHACC"
grep -q '"rule":"phar"' "$LOG" || fail "A2: no phar event"
grep -q '"action":"log"' "$LOG" || fail "A2: no action:log"
if grep -qF "$PH" "$LOG" || grep -q 't\.phar' "$LOG"; then fail "A2: log leaked the phar path"; fi
grep -q CONT "$WORK/out.txt" || fail "A2: script did not continue"
if [ "$FEATURE" != php8 ]; then
  grep -q WOKE "$WORK/out.txt" || fail "A2: detect should not deny (tracer should still fire on 5.x/7.x)"
fi
echo "  ok   - phar detect: logged rule=phar, path not logged, access not denied"

# A3. block: neutralized (normal 'failed to open stream'), script continues, an
# unrelated normal fs op still works, tracer denied on 5.x/7.x.
run_php '[sinks.phar]\nmode="block"\n' \
  "$TR "'$r=file_get_contents("phar://".getenv("PH")."/x"); echo "RET[".var_export($r,true)."]\n";
  $s=file_exists("phar://".getenv("PH")."/x"); echo "EXISTS[".var_export($s,true)."]\n";
  $q=@opendir("phar://".getenv("PH")."/"); echo "DIR[".var_export($q,true)."]\n";
  $inc=@include "phar://".getenv("PH")."/x"; echo "INCRET[".var_export($inc,true)."]\n";
  echo "PLAIN[".file_get_contents(getenv("PLAIN"))."]\n"; echo "CONT\n";'
grep -q '"action":"block"' "$LOG" || fail "A3: no action:block"
grep -q '"rule":"phar"' "$LOG" || fail "A3: no phar rule"
if grep -qF "$PH" "$LOG"; then fail "A3: log leaked the phar path"; fi
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "A3: file_get_contents did not return false"
grep -q 'EXISTS\[false\]' "$WORK/out.txt" || fail "A3: file_exists did not return false"
grep -q 'DIR\[false\]' "$WORK/out.txt" || fail "A3: opendir did not return false"
grep -q 'INCRET\[false\]' "$WORK/out.txt" || fail "A3: include phar:// did not fail cleanly"
out_has 'failed to open stream' || fail "A3: no normal 'failed to open stream' warning"
grep -q 'PLAIN\[PLAINFILE\]' "$WORK/out.txt" || fail "A3: unrelated fs op broke"
grep -q CONT "$WORK/out.txt" || fail "A3: script did not continue (crash?)"
if grep -q WOKE "$WORK/out.txt"; then fail "A3: tracer fired despite block"; fi
if [ "$FEATURE" = php8 ]; then
  echo "  ok   - phar block (8.x): phar:// access denied (detection+denial only), warning raised, unrelated fs op fine, no crash"
else
  echo "  ok   - phar block: access denied, tracer __wakeup DENIED (it fires unguarded), warning raised, unrelated fs op fine, no crash"
fi

# A3b. allow_paths: an allowlisted phar is silent and works.
run_php '[sinks.phar]\nmode="block"\nallow_paths=["'"$WORK"'"]\n' "$TR $PHACC"
no_events || fail "A3b: allowlisted phar produced an event"
if [ "$FEATURE" != php8 ]; then grep -q WOKE "$WORK/out.txt" || fail "A3b: allowlisted phar was denied"; fi
run_php '[sinks.phar]\nmode="block"\nallow_paths=["'"$WORK"'"]\n' "$TR "'echo "GOT[".@file_get_contents("phar://".getenv("PH")."/x")."]\n"; echo "CONT\n";'
grep -q 'GOT\[hi\]' "$WORK/out.txt" || fail "A3b: allowlisted phar read did not return its content"
echo "  ok   - phar allow_paths: allowlisted archive silent and not denied"

# A3c. global block does not arm the phar sink.
run_php '' "$TR $PHACC" -d howdah.mode=block
no_events || fail "A3c: global block armed the phar sink"
echo "  ok   - global howdah.mode=block does not arm phar"

# A4. documented direct-API gap: new Phar($path) / getMetadata() never go
# through the stream wrapper, so the guard does not see them. This asserts the
# DOCUMENTED limit (a known gap, not a guard failure).
DIRECT='try { $q=new Phar(getenv("PH")); echo "CTOR_OK\n"; $m=$q->getMetadata(); echo "META[".get_class($m)."]\n"; } catch (Exception $e) { echo "EXC\n"; } echo "CONT\n";'
# A4a. guard OFF: explicit getMetadata() unserializes on EVERY version (incl. 8.x).
run_php '' "$TR $DIRECT"
grep -q 'META\[Tracer\]' "$WORK/out.txt" || fail "A4a: getMetadata did not return the tracer"
grep -q WOKE "$WORK/out.txt" || fail "A4a: tracer did not fire via explicit getMetadata"
grep -q CONT "$WORK/out.txt" || fail "A4a: script did not continue"
echo "  ok   - phar direct API (documented gap): new Phar()+getMetadata() fires the tracer on this version (not stream-wrapper traffic)"
# A4b. guard BLOCK: new Phar() opens the archive via the Phar C API BEFORE the
# wrapper is consulted. On 5.x/7.x the manifest parse itself unserializes the
# metadata, so the tracer still fires; the guard then denies the follow-up
# phar:// directory open, so the constructor throws (script continues, no crash).
run_php '[sinks.phar]\nmode="block"\n' "$TR $DIRECT"
grep -q CONT "$WORK/out.txt" || fail "A4b: script did not continue / crashed"
if [ "$FEATURE" = php8 ]; then grep -q EXC "$WORK/out.txt" || fail "A4b: ctor was not refused (no EXC)"; fi
if [ "$FEATURE" = php8 ]; then
  if grep -q WOKE "$WORK/out.txt"; then fail "A4b: tracer fired under block on 8.x"; fi
  echo "  ok   - phar direct API under block (8.x): no auto-unserialize; ctor refused by the wrapper guard, script continued"
else
  grep -q WOKE "$WORK/out.txt" || fail "A4b: tracer did not fire before the wrapper (documented gap not reproduced)"
  echo "  ok   - phar direct API under block (5.x/7.x, documented gap): tracer STILL fires (metadata parsed before wrapper is consulted); ctor then refused, script continued"
fi

# A0. SHARED-EXTENSION LOAD ORDER. Install is at first RINIT precisely so that
# phar/curl loaded AFTER howdah at MINIT are still found. Only possible where
# phar.so/curl.so exist (PHP 5.4 image); elsewhere they are compiled in (always
# registered before any shared extension) so ordering cannot be varied.
EXTDIR=$(php-config --extension-dir)
if [ -f "$EXTDIR/phar.so" ] && [ -f "$EXTDIR/curl.so" ]; then
  for ORDER in before after; do
    NOINI="-n"
    if [ "$ORDER" = before ]; then PRE_EXT="-d extension=phar.so -d extension=curl.so"; POST_EXT=""
    else PRE_EXT=""; POST_EXT="-d extension=phar.so -d extension=curl.so"; fi
    run_php '[sinks.phar]\nmode="block"\n[sinks.ssrf]\nmode="block"\n' \
      "$TR "'$e=get_loaded_extensions(); $h=array_search("howdah",$e); $p=array_search("Phar",$e); $c=array_search("curl",$e);
      echo "ORDER howdah=$h phar=$p curl=$c\n";
      $r=@file_get_contents("phar://".getenv("PH")."/x"); echo "PRET[".var_export($r,true)."]\n";
      $ch=curl_init(getenv("URL")); curl_setopt($ch,CURLOPT_RETURNTRANSFER,1); $x=curl_exec($ch); echo "CRET[".var_export($x,true)."]\n"; echo "CONT\n";'
    ord=$(grep -o 'ORDER howdah=[0-9]* phar=[0-9]* curl=[0-9]*' "$WORK/out.txt") || fail "A0($ORDER): no ORDER line (extension not loaded?)"
    h=$(echo "$ord" | sed 's/.*howdah=\([0-9]*\).*/\1/'); p=$(echo "$ord" | sed 's/.*phar=\([0-9]*\).*/\1/')
    if [ "$ORDER" = before ]; then [ "$p" -lt "$h" ] || fail "A0(before): phar not loaded before howdah ($ord)"
    else [ "$p" -gt "$h" ] || fail "A0(after): phar not loaded after howdah ($ord)"; fi
    grep -q 'PRET\[false\]' "$WORK/out.txt" || fail "A0($ORDER): phar guard did not install/deny"
    grep -q 'CRET\[false\]' "$WORK/out.txt" || fail "A0($ORDER): curl guard did not install/deny"
    grep -q '"rule":"phar"' "$LOG" || fail "A0($ORDER): no phar event"
    grep -q '"rule":"ssrf"' "$LOG" || fail "A0($ORDER): no ssrf event"
    grep -q CONT "$WORK/out.txt" || fail "A0($ORDER): script did not continue"
    echo "  ok   - shared phar+curl loaded $ORDER howdah ($ord): phar and curl guards both install and block"
  done
  NOINI=""; PRE_EXT=""; POST_EXT=""
else
  echo "  note - phar/curl are built into this PHP (no phar.so/curl.so): they register before any shared ext, so load-order cannot be varied here (covered on the php5.4 image)"
fi

# ================================================================ B. SSRF
# B1. default OFF: silent, request proceeds.
run_php '' '$r=@file_get_contents(getenv("URL")); echo "RET[".var_export($r,true)."]\n";'
no_events || fail "B1: ssrf produced an event while off by default"
grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "B1: request did not proceed"
echo "  ok   - ssrf default off: silent, request proceeded"

# B2. detect: loopback URL and decimal-encoded URL each LOG class=loopback; URL
# (path/query) never logged; request still proceeds.
for U in URL URLDEC; do
  run_php '[sinks.ssrf]\nmode="detect"\n' '$r=@file_get_contents(getenv("'$U'")); echo "RET[".var_export($r,true)."]\n";'
  grep -q '"rule":"ssrf"' "$LOG" || fail "B2($U): no ssrf event"
  grep -q 'class=loopback' "$LOG" || fail "B2($U): not classified loopback"
  grep -q '"action":"log"' "$LOG" || fail "B2($U): no action:log"
  if grep -q 'SECRETPATH\|tok=abc123\|http://' "$LOG"; then fail "B2($U): log leaked the URL"; fi
done
echo "  ok   - ssrf detect: loopback + decimal-encoded (2130706433) each logged class=loopback, URL not logged"
grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || echo "  note - decimal-host request did not reach the server (resolver-dependent; detection is what is asserted)"

# B3. block: returns false, script continues, request not made.
run_php '[sinks.ssrf]\nmode="block"\n' '$r=@file_get_contents(getenv("URL")); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B3: file_get_contents did not return false"
grep -q CONT "$WORK/out.txt" || fail "B3: script did not continue"
if grep -q SERVED "$WORK/out.txt"; then fail "B3: request went out despite block"; fi
grep -q '"action":"block"' "$LOG" || fail "B3: no action:block"
run_php '[sinks.ssrf]\nmode="block"\n' '$r=@file_get_contents(getenv("URLDEC")); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B3: decimal-encoded URL not blocked"
echo "  ok   - ssrf block: returns false, script continued, request not served (plain + decimal-encoded)"

# B3b. global block does not arm ssrf.
run_php '' '$r=@file_get_contents(getenv("URL")); echo "RET[".var_export($r,true)."]\n";' -d howdah.mode=block
no_events || fail "B3b: global block armed ssrf"
echo "  ok   - global howdah.mode=block does not arm ssrf"

# B4. allow_hosts: allowlisted host -> silent, proceeds.
run_php '[sinks.ssrf]\nmode="block"\nallow_hosts=["127.0.0.1"]\n' '$r=@file_get_contents(getenv("URL")); echo "RET[".var_export($r,true)."]\n";'
no_events || fail "B4: allowlisted host produced an event"
grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "B4: allowlisted request did not proceed"
echo "  ok   - ssrf allow_hosts: allowlisted host silent, request proceeded"

# B5. local paths are never resolved/logged.
run_php '[sinks.ssrf]\nmode="block"\n' '$a=fopen("/etc/passwd","r"); $b=fopen("config.php","r"); echo "A[".(is_resource($a)?"res":"no")."] B[".(is_resource($b)?"res":"no")."]\n";'
no_events || fail "B5: local path produced an ssrf event"
grep -q 'A\[res\] B\[res\]' "$WORK/out.txt" || fail "B5: local fopen broke"
echo "  ok   - ssrf: fopen('/etc/passwd') and fopen('config.php') never resolved/logged"

# B6. curl: init + setopt(URL) + exec to loopback is logged (detect) / denied (block).
run_php '[sinks.ssrf]\nmode="detect"\n' '$c=curl_init(); curl_setopt($c,CURLOPT_URL,getenv("URL")); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); $r=curl_exec($c); echo "RET[".var_export($r,true)."]\n";'
grep -q 'class=loopback' "$LOG" || fail "B6: curl_exec to loopback not logged"
if grep -q 'SECRETPATH\|tok=abc123' "$LOG"; then fail "B6: log leaked the curl URL"; fi
grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "B6: detect should still perform the request"
run_php '[sinks.ssrf]\nmode="block"\n' '$c=curl_init(); curl_setopt($c,CURLOPT_URL,getenv("URL")); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); $r=curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B6: curl_setopt(URL)+curl_exec not blocked"
grep -q CONT "$WORK/out.txt" || fail "B6: script did not continue after curl block"
run_php '[sinks.ssrf]\nmode="block"\n' '$c=curl_init(getenv("URL")); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); $r=curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B6: curl_init(URL)+curl_exec not blocked"
echo "  ok   - ssrf curl: init+setopt(URL)+exec logged (detect), blocked (block) for setopt and curl_init(URL), script continued"

# B7. handle lifecycle: curl_init(loopback) -> curl_close -> curl_init() (no URL)
# -> curl_exec must NOT serve the old URL (no false event, no stale block).
run_php '[sinks.ssrf]\nmode="block"\n' '$a=curl_init(getenv("URL")); @curl_close($a); $b=curl_init(); curl_setopt($b,CURLOPT_RETURNTRANSFER,1); $r=curl_exec($b); echo "RET[".var_export($r,true)."]\nCONT\n";'
no_events || fail "B7: stale handle URL produced an event after curl_close + new handle"
if grep -q SERVED "$WORK/out.txt"; then fail "B7: a request was served for a URL-less handle"; fi
grep -q CONT "$WORK/out.txt" || fail "B7: script did not continue"
echo "  ok   - ssrf curl lifecycle: init(URL)->close->init()->exec does not serve/flag the stale URL"

# B8. PHP 8 only: curl_close is a no-op, the SAME handle stays guarded.
if [ "$FEATURE" = php8 ]; then
  run_php '[sinks.ssrf]\nmode="block"\n' '$c=curl_init(getenv("URL")); @curl_close($c); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); $r=curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B8: curl_exec after curl_close on same handle not blocked"
  grep -q '"action":"block"' "$LOG" || fail "B8: no block event for post-close exec"
  grep -q CONT "$WORK/out.txt" || fail "B8: script did not continue"
  echo "  ok   - ssrf php8: curl_close(\$ch); curl_exec(\$ch) on the same handle is still guarded"
fi

# B9. OVERSIZE host (zero-padded octal loopback: 000..0177.0.0.1 == 127.0.0.1).
# Fits the 256-byte buffer -> decoded and classed loopback; exceeds it -> logged /
# blocked as suspicious (NOT silently skipped).
run_php '[sinks.ssrf]\nmode="block"\n' '$h=str_repeat("0",200)."177.0.0.1"; $r=@file_get_contents("http://$h:'$PORT'/x"); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'class=loopback' "$LOG" || fail "B9: padded (fits) loopback not classed loopback"
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B9: padded (fits) loopback not blocked"
if grep -q SERVED "$WORK/out.txt"; then fail "B9: padded loopback request was served"; fi
run_php '[sinks.ssrf]\nmode="block"\n' '$h=str_repeat("0",300)."177.0.0.1"; $r=@file_get_contents("http://$h:'$PORT'/x"); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'oversize host' "$LOG" || fail "B9: oversize host not logged as suspicious (silently skipped?)"
grep -q '"action":"block"' "$LOG" || fail "B9: oversize host not blocked"
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B9: oversize host request not blocked"
grep -q CONT "$WORK/out.txt" || fail "B9: script did not continue"
run_php '[sinks.ssrf]\nmode="detect"\n' '$h=str_repeat("0",300)."177.0.0.1"; $r=@file_get_contents("http://$h:'$PORT'/x"); echo "CONT\n";'
grep -q 'oversize host' "$LOG" || fail "B9: oversize host not logged in detect"
grep -q '"action":"log"' "$LOG" || fail "B9: oversize detect should be action:log"
echo "  ok   - ssrf oversize: padded loopback that fits -> loopback+blocked; >256-byte host -> logged/blocked as suspicious (not skipped)"

# ============================================ C. PHP 5.x include/eval (php5)
if [ "$FEATURE" = php5 ]; then
  ALLOW='allow_paths=["/var/www/app"]'

  # C1. detect: logs, file still runs, path never logged.
  run_php '[sinks.include]\nmode="detect"\n'"$ALLOW"'\n' '$p=getenv("INC"); include $p; echo "CONT\n";'
  grep -q INC_RAN "$WORK/out.txt" || fail "C1: include did not run in detect"
  grep -q '"rule":"include"' "$LOG" || fail "C1: no include event"
  grep -q '"action":"log"' "$LOG" || fail "C1: no action:log"
  if grep -qF "$INC" "$LOG"; then fail "C1: log leaked the include path"; fi
  echo "  ok   - php5 include detect (now ACTIVE): logged, file ran, path not logged"

  # C2. block: file not run, script continues.
  run_php '[sinks.include]\nmode="block"\n'"$ALLOW"'\n' '$p=getenv("INC"); $r=include $p; echo "RET[".var_export($r,true)."]\nCONT\n";'
  if grep -q INC_RAN "$WORK/out.txt"; then fail "C2: include ran despite block"; fi
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "C2: include did not return false"
  grep -q CONT "$WORK/out.txt" || fail "C2: script did not continue"
  grep -q '"action":"block"' "$LOG" || fail "C2: no action:block"
  echo "  ok   - php5 include block: neutralized (file not run, returned false, script continued)"

  # C2b. allowlisted path is silent and runs.
  run_php '[sinks.include]\nmode="block"\nallow_paths=["'"$WORK"'"]\n' '$p=getenv("INC"); include $p; echo "CONT\n";'
  grep -q INC_RAN "$WORK/out.txt" || fail "C2b: allowlisted include did not run"
  no_events || fail "C2b: allowlisted include produced an event"
  echo "  ok   - php5 include allow_paths: allowlisted file silent and ran"

  # C3. require / require_once of a blocked file: returns false, no fatal.
  run_php '[sinks.include]\nmode="block"\n'"$ALLOW"'\n' '$p=getenv("INC"); $r=require $p; echo "RET[".var_export($r,true)."]\nCONT\n";'
  if grep -q INC_RAN "$WORK/out.txt"; then fail "C3: require ran despite block"; fi
  if out_has 'Fatal\|segfault'; then fail "C3: require block raised a fatal"; fi
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "C3: require did not return false"
  grep -q CONT "$WORK/out.txt" || fail "C3: script did not continue after require block"
  run_php '[sinks.include]\nmode="block"\n'"$ALLOW"'\n' '$p=getenv("INC"); $r=require_once $p; echo "RET[".var_export($r,true)."]\nCONT\n";'
  if grep -q INC_RAN "$WORK/out.txt"; then fail "C3: require_once ran despite block"; fi
  if out_has 'Fatal\|segfault'; then fail "C3: require_once block raised a fatal"; fi
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "C3: require_once did not return false"
  grep -q CONT "$WORK/out.txt" || fail "C3: script did not continue after require_once block"
  echo "  ok   - php5 require / require_once block: returns false, no fatal, script continued"

  # C4. include_once of a blocked file. Stock 5.x may yield TRUE for a NULL
  # compile on the _once variants; assert the observed behaviour: not run, no
  # fatal/crash, script continues (the observed return value is printed).
  run_php '[sinks.include]\nmode="block"\n'"$ALLOW"'\n' '$p=getenv("INC"); $r=include_once $p; echo "RET[".var_export($r,true)."]\nCONT\n";'
  if grep -q INC_RAN "$WORK/out.txt"; then fail "C4: include_once ran despite block"; fi
  if out_has 'Fatal\|segfault'; then fail "C4: include_once block raised a fatal"; fi
  grep -q CONT "$WORK/out.txt" || fail "C4: script did not continue after include_once block"
  grep -q '"action":"block"' "$LOG" || fail "C4: no block event for include_once"
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "C4: include_once block did not return false"
  C4RET=$(grep -o 'RET\[[a-z0-9]*\]' "$WORK/out.txt" | head -1)
  echo "  ok   - php5 include_once block: not run, no fatal/crash, script continued (observed return: $C4RET)"

  # C5. eval: detect logs + runs; block does not run, script continues.
  run_php '[sinks.eval]\nmode="block"\n' 'eval("echo 99;"); echo "\nCONT2\n";'
  if grep -q 99 "$WORK/out.txt"; then fail "C5: eval ran despite block"; fi
  grep -q CONT2 "$WORK/out.txt" || fail "C5: script did not continue after eval block"
  grep -q '"rule":"eval"' "$LOG" || fail "C5: no eval rule"
  grep -q '"action":"block"' "$LOG" || fail "C5: no action:block"
  run_php '[sinks.eval]\nmode="detect"\n' 'eval("echo 99;"); echo "\nCONT2\n";'
  grep -q 99 "$WORK/out.txt" || fail "C5: eval did not run in detect"
  grep -q '"rule":"eval"' "$LOG" || fail "C5: no eval event in detect"
  echo "  ok   - php5 eval: detect logs + runs; block does not run, script continued"

  # C6. computed operand ($a.$b): block is safe (no crash, continues).
  run_php '[sinks.include]\nmode="block"\n'"$ALLOW"'\n' '$a="/tmp/"; $b="nope.php"; $r=include $a.$b; echo "RET[".var_export($r,true)."] COMPUTED_OK\n";'
  grep -q COMPUTED_OK "$WORK/out.txt" || fail "C6: computed-operand include block crashed or did not continue"
  grep -q '"action":"block"' "$LOG" || fail "C6: no block for computed include"
  echo "  ok   - php5 include block (computed operand): safe, no crash, continued"

  # C7. MISFIRE GUARD: with include AND eval armed, none of these may produce an
  # event: the main script itself, an auto_prepend_file, and create_function() /
  # assert("...") (internal compiles, not user include/eval).
  printf '<?php echo "PREPEND_RAN\\n";' > "$WORK/pre.php"
  cat > "$WORK/main.php" <<'PHPEOF'
<?php
echo "MAIN_RAN\n";
$f = create_function('$a', 'return $a + 1;');
echo "CF[" . $f(1) . "]\n";
assert("1 == 1");
echo "ASSERT_OK\n";
echo "DONE\n";
PHPEOF
  run_file '[sinks.include]\nmode="detect"\n'"$ALLOW"'\n[sinks.eval]\nmode="detect"\n' "$WORK/main.php" -d auto_prepend_file="$WORK/pre.php" -d assert.active=1
  grep -q PREPEND_RAN "$WORK/out.txt" || fail "C7: auto_prepend_file did not run"
  grep -q MAIN_RAN "$WORK/out.txt" || fail "C7: main script did not run"
  grep -q 'CF\[2\]' "$WORK/out.txt" || fail "C7: create_function broke"
  grep -q ASSERT_OK "$WORK/out.txt" || fail "C7: assert string broke"
  no_events || fail "C7: misfire - main script / auto_prepend_file / create_function / assert produced an event"
  echo "  ok   - php5 misfire guard: main script, auto_prepend_file, create_function, assert(\"...\") produce NO events"
  run_file '[sinks.include]\nmode="block"\n'"$ALLOW"'\n[sinks.eval]\nmode="block"\n' "$WORK/main.php" -d auto_prepend_file="$WORK/pre.php" -d assert.active=1
  grep -q DONE "$WORK/out.txt" || fail "C7b: block mode broke main script / prepend / create_function / assert"
  no_events || fail "C7b: misfire in block mode"
  echo "  ok   - php5 misfire guard (block mode): same constructs untouched, no events"

  # C8. OPCACHE. The 5.x tests above ran with opcache OFF (the image default).
  # One case with opcache ON: a blocked include on FIRST compile returns NULL
  # cleanly (no crash) and the failed compile is not cached (a second include
  # of the same file in the same process is blocked again, not served).
  OC="-d zend_extension=opcache.so -d opcache.enable=1 -d opcache.enable_cli=1"
  if php $OC -r 'exit(extension_loaded("Zend OPcache")?0:1);' 2>/dev/null; then
    run_php '[sinks.include]\nmode="block"\n'"$ALLOW"'\n' '$p=getenv("INC"); $a=include $p; $b=include $p; echo "RET[".var_export($a,true)."][".var_export($b,true)."]\nCONT\n";' $OC
    if grep -q INC_RAN "$WORK/out.txt"; then fail "C8: include ran under opcache despite block"; fi
    if out_has 'Fatal\|segfault'; then fail "C8: crash/fatal under opcache"; fi
    grep -q 'RET\[false\]\[false\]' "$WORK/out.txt" || fail "C8: opcache first-compile block not handled cleanly (failed compile cached?)"
    grep -q CONT "$WORK/out.txt" || fail "C8: script did not continue under opcache"
    [ "$(grep -c '"action":"block"' "$LOG")" = 2 ] || fail "C8: expected 2 block events (second include must not be served from cache)"
    echo "  ok   - php5 include block with opcache ON (first compile): NULL return handled, no crash, failed compile not cached"
    # Documented limitation (NOT asserted): a WARM opcache hit is served from
    # shared memory without calling zend_compile_file, so that include is NOT
    # re-inspected. Not reproducible here: 5.x opcache has no file cache and the
    # CLI cannot share SHM across processes that carry different policies.
    echo "  note - KNOWN 5.x LIMITATION (documented, not asserted): a WARM opcache cache-hit include is not re-inspected; only first compiles are guarded"

  else
    echo "  note - opcache.so not available in this image; opcache case skipped"
  fi
fi

# Memory/leak review: needs a debug PHP build (--enable-debug) so the Zend MM
# reports leaks at request shutdown. These images are release builds.
if php -i | grep -q 'Debug Build => yes'; then
  echo "  note - debug PHP build: leaks would have been reported on stderr above (none failed the run)"
else
  echo "  note - leak review pending debug build (release PHP: Zend MM leak reports unavailable)"
fi

echo "PASS"
