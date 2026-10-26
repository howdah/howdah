#!/bin/sh
# In-container half of the Layer-3 fast-follow integration test:
#   A. phar:// wrapper guard      (all PHP generations)
#   B. SSRF egress guard          (all PHP generations) + T6 hardening (scheme
#      denial, resolve-at-connect / anti-rebinding, curl internal-redirect guard)
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
  RUN_RC=0
  # shellcheck disable=SC2086
  php $NOINI $PRE_EXT -d extension="$WORK/howdah.so" $POST_EXT \
      -d howdah.config="$WORK/l3.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      -d default_socket_timeout=3 "$@" -r "$code" > "$WORK/out.txt" 2>"$WORK/err.txt" || RUN_RC=$?
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

# T6 targets served by the same loopback server: hit.php records that the
# "internal service" was reached (so a refused redirect/gopher request can be
# proven not to have arrived), redir.php answers with a configurable Location.
export HIT_FILE="$WORK/hit.flag"
printf '<?php file_put_contents(getenv("HIT_FILE"), "x", FILE_APPEND); echo "HITBODY";' > "$WORK/www/hit.php"
printf '<?php header("Location: " . $_GET["to"], true, isset($_GET["code"]) ? (int)$_GET["code"] : 302); echo "REDIRECTING";' > "$WORK/www/redir.php"

# Loopback HTTP target for SSRF "proceeds" checks (no howdah in this process).
PORT=18099
php -S 127.0.0.1:$PORT -t "$WORK/www" >/dev/null 2>&1 &
SRV=$!
DNS_PID=""; TLS_PID=""
cleanup() {
  kill $SRV $DNS_PID $TLS_PID 2>/dev/null || true
  [ -f "$WORK/resolv.bak" ] && cat "$WORK/resolv.bak" > /etc/resolv.conf 2>/dev/null || true
}
trap cleanup EXIT
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

# --- security-review fixes (F1-F4): bypasses that must now be blocked ---------
# B10 (F1): a curl URL over 8192 bytes must not skip the guard. The attacker
# appends '#' + padding (libcurl ignores the fragment but still connects); the
# URL is truncated, not dropped, so the loopback host is still classified.
: > "$LOG"
run_php '[sinks.ssrf]\nmode="block"\n' '$c=curl_init(getenv("URL")."#".str_repeat("A",9000)); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); $r=@curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B10(F1): a >8192-byte (fragment-padded) curl URL bypassed the guard"
grep -q '"action":"block"' "$LOG" || fail "B10(F1): no block event for the padded URL"
if grep -q SERVED "$WORK/out.txt"; then fail "B10(F1): the padded URL request was served"; fi
grep -q CONT "$WORK/out.txt" || fail "B10(F1): script did not continue"
echo "  ok   - F1: a curl URL >8192 bytes is truncated not dropped; the loopback host is still blocked"
# B10b (F1 re-review): USERINFO padding must not steer the truncation so the cut
# lands at the '@' (empty/wrong host). An over-long URL is treated as suspicious,
# never parsed from the truncated text.
: > "$LOG"
run_php '[sinks.ssrf]\nmode="block"\n' '$u="http://".str_repeat("a",8184)."@127.0.0.1:'"$PORT"'/SECRETPATH"; $c=curl_init($u); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); $r=@curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B10b(F1): a userinfo-padded >8192 URL bypassed the guard"
if grep -q SERVED "$WORK/out.txt"; then fail "B10b(F1): the userinfo-padded URL was served"; fi
grep -q CONT "$WORK/out.txt" || fail "B10b(F1): script did not continue"
echo "  ok   - F1 re-review: a userinfo-padded >8192 curl URL is treated as suspicious, not parsed"

# B11 (F2): a backslash before '@' stays in the userinfo for PHP and libcurl,
# which connect to the host after the last '@'. The parser must read that host.
: > "$LOG"
export BSURL='http://public.example\@127.0.0.1:'"$PORT"'/SECRETPATH'
run_php '[sinks.ssrf]\nmode="block"\n' '$r=@file_get_contents(getenv("BSURL")); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B11(F2): backslash-userinfo URL bypassed via file_get_contents"
if grep -q SERVED "$WORK/out.txt"; then fail "B11(F2): the backslash URL reached the internal server"; fi
run_php '[sinks.ssrf]\nmode="block"\n' '$c=curl_init(getenv("BSURL")); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); $r=@curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B11(F2): backslash-userinfo URL bypassed via curl"
echo "  ok   - F2: http://public.example\\@127.0.0.1 is classified by the host after '@' (stream + curl)"

# B12 (F4): a curl scheme and a nesting wrapper must not slip past the RANGE
# check with the scheme knob off; the parser peels the outer scheme.
: > "$LOG"
run_php '[sinks.ssrf]\nmode="block"\n' '$c=curl_init("dict://127.0.0.1:'"$PORT"'/d:x"); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); $r=@curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q '"action":"block"' "$LOG" || fail "B12(F4): dict://loopback not range-blocked"
grep -q CONT "$WORK/out.txt" || fail "B12(F4): script did not continue after the dict block"
: > "$LOG"
run_php '[sinks.ssrf]\nmode="block"\n' '$r=@file_get_contents("compress.zlib://http://127.0.0.1:'"$PORT"'/SECRETPATH"); echo "RET[".var_export($r,true)."]\nCONT\n";'
grep -q '"action":"block"' "$LOG" || fail "B12(F4): compress.zlib://http nesting not range-blocked"
if grep -q SERVED "$WORK/out.txt"; then fail "B12(F4): the nested wrapper reached the internal server"; fi
echo "  ok   - F4: dict://loopback and compress.zlib://http://loopback are range-checked (scheme knob off)"

# B13 (F3): a NUL terminates the host for libc and PHP < 7, so
# 127.0.0.1\0.example.com connects to 127.0.0.1. The parser classifies the bytes
# before the NUL. PHP >= 7 rejects the NUL itself, so this is a php5 check.
if [ "$FEATURE" = php5 ]; then
  : > "$LOG"
  run_php '[sinks.ssrf]\nmode="block"\n' '$f=@fsockopen("127.0.0.1\0.example.com", '"$PORT"', $en, $es, 2); echo "F[".(is_resource($f)?"res":"no")."]\nCONT\n"; if(is_resource($f)) fclose($f);'
  grep -q 'F\[no\]' "$WORK/out.txt" || fail "B13(F3): NUL-host fsockopen connected on php5 (bypass still open)"
  grep -q CONT "$WORK/out.txt" || fail "B13(F3): script did not continue"
  echo "  ok   - F3: fsockopen(\"127.0.0.1\\0.example.com\") blocked on php5 (host truncated at NUL)"
fi
run_php '[sinks.ssrf]\nmode="detect"\n' '$h=str_repeat("0",300)."177.0.0.1"; $r=@file_get_contents("http://$h:'$PORT'/x"); echo "CONT\n";'
grep -q 'oversize host' "$LOG" || fail "B9: oversize host not logged in detect"
grep -q '"action":"log"' "$LOG" || fail "B9: oversize detect should be action:log"
echo "  ok   - ssrf oversize: padded loopback that fits -> loopback+blocked; >256-byte host -> logged/blocked as suspicious (not skipped)"

# ====================================== T6. SSRF hardening (opt-in knobs)
# [sinks.ssrf] scheme / rebind / redirect, each off|detect|block, independent of
# `mode` and off by default. Proven here against real servers on loopback:
#   * a php -S target that records (hit.php) whether the "internal service" was
#     reached, and redirects on demand (redir.php);
#   * a rebinding DNS server (corpus/rebind_dns.php): the first A answer for a
#     name is a public-looking decoy, every later one is 127.0.0.1;
#   * a self-signed HTTPS target (corpus/https_server.php) for the benign case.
T6_N=0; T6_SCHEME=0; T6_REDIR=0; T6_REBIND=0; T6_GAPS=0
t6() { T6_N=$((T6_N+1)); echo "  ok   - $1"; }
ev() { grep -q "$1" "$LOG"; }
# The built-in server is single-threaded, and the 5.x one does not always survive
# a client that hangs up mid-response (refused and aborted transfers are exactly
# what these tests do). A negative check ("the internal service was NOT reached")
# is worthless against a dead server, so every T6 run first makes sure it is alive.
srv_ok() {
  php -d date.timezone=UTC -d display_errors=0 -r '$r=@file_get_contents("http://127.0.0.1:'$PORT'/",false,stream_context_create(array("http"=>array("timeout"=>2)))); exit($r==="SERVED"?0:1);' 2>/dev/null
}
ensure_srv() {
  srv_ok && return 0
  kill "$SRV" 2>/dev/null || true
  wait "$SRV" 2>/dev/null || true
  php -S 127.0.0.1:$PORT -t "$WORK/www" >/dev/null 2>&1 &
  SRV=$!
  k=0
  until srv_ok; do k=$((k+1)); [ $k -gt 30 ] && fail "T6: the loopback test server cannot be restarted"; php -r 'usleep(100000);'; done
  echo "  note - restarted the loopback test server (it did not survive an aborted client)"
}
# T6 scenarios never crash or fatal: a signal / fatal exit status is a failure in
# its own right (the exit code was ignored before, which hid a shutdown abort on
# PHP 7.0 until it was caught by hand).
t6run() {
  ensure_srv; run_php "$@"
  [ "$RUN_RC" -eq 0 ] || fail "T6: php exited with status $RUN_RC (a crash or a fatal error)"
}
unhit() { rm -f "$HIT_FILE"; }
hit() { [ -e "$HIT_FILE" ]; }
no_leak() {
  if grep -q 'SECRETPATH\|tok=abc123\|hit\.php\|redir\.php\|plain\.txt\|/etc/\|tmp/howdah' "$LOG"; then fail "$1: the log leaked a URL / path"; fi
}
# What a "fetch one URL with curl" script looks like. Inputs come from the
# environment: U (url), FOLLOW (set => CURLOPT_FOLLOWLOCATION), HDRFN (set => the
# script installs its own CURLOPT_HEADERFUNCTION).
CG='$c=curl_init(getenv("U")); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); curl_setopt($c,CURLOPT_CONNECTTIMEOUT,2); curl_setopt($c,CURLOPT_TIMEOUT,6); if(getenv("FOLLOW")) curl_setopt($c,CURLOPT_FOLLOWLOCATION,1); if(getenv("HDRFN")) curl_setopt($c,CURLOPT_HEADERFUNCTION,function($ch,$h){return strlen($h);}); $r=curl_exec($c); echo "RET[".var_export($r,true)."] ERRNO[".curl_errno($c)."]\nCONT\n";'
PHPQ="php -d date.timezone=UTC -d display_errors=0"
PIN_MECH="n/a"
PHPID=$($PHPQ -r 'echo PHP_VERSION_ID;' 2>/dev/null)
HAS_RESOLVE=0; [ "$PHPID" -ge 50500 ] && HAS_RESOLVE=1
CURLV=$($PHPQ -r 'if (function_exists("curl_version")) { $v = curl_version(); echo $v["version"]; }' 2>/dev/null)
echo "  note - T6 runs on PHP $($PHPQ -r 'echo PHP_VERSION;' 2>/dev/null) with libcurl ${CURLV:-none}"
GOPHER="gopher://127.0.0.1:$PORT/_GET%20/hit.php%20HTTP/1.0%0d%0a%0d%0a"
unset U FOLLOW HDRFN

# ---- T6.0 footprint: nothing changes unless a knob is armed --------------------
t6run '' 'echo function_exists("howdah_curl_header_guard")?"GUARD_FN":"NO_GUARD_FN", "\n";'
grep -q NO_GUARD_FN "$WORK/out.txt" || fail "T6.0: the header-guard function exists with every knob off"
t6run '[sinks.ssrf]\nredirect="detect"\n' 'echo function_exists("howdah_curl_header_guard")?"GUARD_FN":"NO_GUARD_FN", "\n";'
grep -q '^GUARD_FN' "$WORK/out.txt" || fail "T6.0: the header guard was not registered with redirect armed"
# The guard is a registered internal function: the process must also SHUT DOWN
# clean with it present (registering it at request time aborted the worker on
# PHP 7.0 about half the time). run_php ignores exit codes, so check them here.
printf '%b' '[sinks.ssrf]\nredirect="block"\nscheme="block"\nrebind="block"\n' > "$WORK/l3.toml"
bad=""
for n in 1 2 3 4 5 6 7 8 9 10; do
  php $NOINI -d extension="$WORK/howdah.so" -d howdah.config="$WORK/l3.toml" -d howdah.log="$LOG" -d date.timezone=UTC -d display_errors=0 -r '$c=curl_init("http://127.0.0.1:1/"); curl_setopt($c,CURLOPT_FOLLOWLOCATION,1); @curl_exec($c); echo function_exists("howdah_curl_header_guard")?"G":"-";' >"$WORK/out.txt" 2>"$WORK/err.txt" || bad="$bad $?"
  grep -q '^G' "$WORK/out.txt" || bad="$bad nofn"
done
[ -z "$bad" ] || fail "T6.0: the process died or lost the guard with it armed (statuses:$bad)"
t6 "footprint: no extra function by default; the redirect guard is registered (at startup) only when redirect/scheme is armed, and ten runs with it present all exit 0"

# Facet off (the default): gopher / file / dict are as reachable as ever, and a
# redirect to loopback is followed. These are the baselines every scenario below
# is compared against, so a pass cannot be a lab that never worked.
unhit; export U="file://$PLAIN"; t6run '' "$CG"
no_events || fail "T6.0: an event with every knob off"
grep -q 'RET\[.PLAINFILE.\]' "$WORK/out.txt" || fail "T6.0: curl file:// does not work with the facet off (lab broken)"
unhit; export U="$GOPHER"; t6run '' "$CG"
no_events || fail "T6.0: an event with every knob off (gopher)"
if hit; then SMUGGLE=1; else SMUGGLE=0; fi
unhit; export U="http://127.0.0.1:$PORT/redir.php?to=http://127.0.0.1:$PORT/hit.php" FOLLOW=1; t6run '' "$CG"
no_events || fail "T6.0: an event with every knob off (redirect)"
grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && hit || fail "T6.0: a redirect to loopback is not followed with the facet off (lab broken)"
unset FOLLOW
t6 "baseline (facet off): curl file:// read, a redirect to loopback followed (hit), gopher smuggling reached the server: $([ $SMUGGLE = 1 ] && echo yes || echo 'no (this libcurl has gopher disabled)'); zero events"

# ---- T6.A scheme denial ---------------------------------------------------------
for S in "file|file://$PLAIN" "gopher|$GOPHER" "dict|dict://127.0.0.1:$PORT/d:SECRETPATH" \
         "ldap|ldap://127.0.0.1:$PORT/dc=SECRETPATH" "tftp|tftp://127.0.0.1:$PORT/SECRETPATH" \
         "ftp|ftp://127.0.0.1:$PORT/SECRETPATH" "guessed-ftp|ftp.lab.invalid/SECRETPATH"; do
  label=${S%%|*}; url=${S#*|}
  unhit; export U="$url"
  t6run '[sinks.ssrf]\nscheme="block"\n' "$CG"
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "T6.A($label): curl was not refused"
  grep -q CONT "$WORK/out.txt" || fail "T6.A($label): the script did not continue"
  if grep -q 'PLAINFILE' "$WORK/out.txt"; then fail "T6.A($label): the local file was read"; fi
  if hit; then fail "T6.A($label): the request reached the internal service"; fi
  ev "ssrf scheme via curl: scheme=$label" || fail "T6.A($label): no scheme event"
  ev '"action":"block"' || fail "T6.A($label): not action:block"
  no_leak "T6.A($label)"
  T6_SCHEME=$((T6_SCHEME+1))
done
t6 "scheme=block: curl file://, gopher:// (smuggled GET), dict://, ldap://, tftp://, ftp:// and the ftp.-host protocol guess each refused (false, script continued, never reached the server, category logged, no URL)"

export U="file://$PLAIN"; t6run '[sinks.ssrf]\nscheme="detect"\n' "$CG"
grep -q 'RET\[.PLAINFILE.\]' "$WORK/out.txt" || fail "T6.A: scheme=detect changed behavior"
ev 'ssrf scheme via curl: scheme=file' && ev '"action":"log"' || fail "T6.A: scheme=detect did not log"
no_leak "T6.A(detect)"
t6 "scheme=detect: logs action:log and the file:// read still happens"

# Benign egress is untouched while armed, via every way of giving curl a URL.
for U1 in "http://127.0.0.1:$PORT/" "127.0.0.1:$PORT/" "HTTP://127.0.0.1:$PORT/"; do
  export U="$U1"; t6run '[sinks.ssrf]\nscheme="block"\n' "$CG"
  grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "T6.A: benign http fetch ($U1) disturbed"
  no_events || fail "T6.A: benign http fetch ($U1) logged"
done
t6run '[sinks.ssrf]\nscheme="block"\n' '$c=curl_init(); curl_setopt_array($c,array(CURLOPT_URL=>getenv("URL"),CURLOPT_RETURNTRANSFER=>1)); $r=curl_exec($c); echo "RET[".var_export($r,true)."]\n"; $c=curl_init("gopher://127.0.0.1:1/x"); $r=curl_exec($c); echo "G[".var_export($r,true)."]\n"; $c=curl_init(); curl_setopt_array($c,array(CURLOPT_URL=>"dict://127.0.0.1:1/x",CURLOPT_RETURNTRANSFER=>1)); $r=curl_exec($c); echo "D[".var_export($r,true)."]\n";'
grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "T6.A: setopt_array benign fetch disturbed"
grep -q 'G\[false\]' "$WORK/out.txt" && grep -q 'D\[false\]' "$WORK/out.txt" || fail "T6.A: curl_init(url) / curl_setopt_array(url) schemes not refused"
t6 "scheme=block leaves http/https (and scheme-less host:port) alone; curl_init(url) and curl_setopt_array(url) are both guarded"

# A redirect hop to another scheme: the header guard refuses it before libcurl
# follows, and CURLOPT_PROTOCOLS (set in block) is the libcurl-level backstop.
for HOP in "$GOPHER" "dict://127.0.0.1:$PORT/info" "file://$PLAIN"; do
  unhit; export G="$HOP"; TO=$($PHPQ -r 'echo rawurlencode(getenv("G"));' 2>/dev/null)
  export U="http://127.0.0.1:$PORT/redir.php?to=$TO" FOLLOW=1
  t6run '[sinks.ssrf]\nscheme="block"\n' "$CG"
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "T6.A: a redirect hop to ${HOP%%:*}:// was followed"
  if grep -q PLAINFILE "$WORK/out.txt"; then fail "T6.A: a redirect hop read the local file"; fi
  if hit; then fail "T6.A: a redirect hop to ${HOP%%:*}:// reached the server"; fi
  T6_SCHEME=$((T6_SCHEME+1))
done
unset FOLLOW G
ev 'ssrf scheme via curl' || echo "  note - the hop was refused by libcurl (CURLOPT_PROTOCOLS) before our guard logged it"
t6 "scheme=block: a 302 whose Location is gopher:// / dict:// / file:// is not followed (guard + CURLOPT_PROTOCOLS)"

# The stream functions: only the remote wrappers; local wrappers are untouched.
for FN in 'file_get_contents' 'fopen_r' 'get_headers'; do
  case $FN in
    file_get_contents) CODE='$r=@file_get_contents("ftp://127.0.0.1:21/SECRETPATH");' ;;
    fopen_r)           CODE='$r=@fopen("ftp://127.0.0.1:21/SECRETPATH","r");' ;;
    get_headers)       CODE='$r=@get_headers("ftp://127.0.0.1:21/SECRETPATH");' ;;
  esac
  t6run '[sinks.ssrf]\nscheme="block"\n' "$CODE"' echo "RET[".var_export($r,true)."]\nCONT\n";'
  grep -q 'RET\[false\]' "$WORK/out.txt" && grep -q CONT "$WORK/out.txt" || fail "T6.A: $FN(ftp://) not refused"
  ev 'ssrf scheme via stream: scheme=ftp' || fail "T6.A: $FN(ftp://) logged no scheme event"
  no_leak "T6.A($FN)"
  T6_SCHEME=$((T6_SCHEME+1))
done
t6run '[sinks.ssrf]\nscheme="block"\n' '$a=@file_get_contents("file://".getenv("PLAIN")); $m=fopen("php://memory","w+"); fwrite($m,"x"); rewind($m); $t=fopen("php://temp","w+"); $c=@file_get_contents(getenv("URL")); echo "A[$a] C[".fread($m,1)."] T[".var_export(is_resource($t),true)."] D[$c]\n";'
grep -q 'A\[PLAINFILE\] C\[x\] T\[true\] D\[SERVED\]' "$WORK/out.txt" || fail "T6.A: a local or http wrapper was disturbed by scheme=block"
no_events || fail "T6.A: local wrappers / http produced a scheme event"
t6 "scheme=block on file_get_contents / fopen / get_headers: ftp:// refused; file://, php://memory, php://temp and http:// untouched, zero events"

# ---- T6.B resolve-at-connect (rebind) -------------------------------------------
# rebind=block does not depend on `mode`: a name that resolves to an internal
# address when the call is made is refused before the connect (every PHP version,
# pin or no pin), and detect only observes.
unhit; export U="http://localhost:$PORT/hit.php"
t6run '[sinks.ssrf]\nrebind="block"\n' "$CG"
grep -q 'RET\[false\]' "$WORK/out.txt" && ! hit || fail "T6.B: rebind=block alone served a name that resolves to loopback"
ev "ssrf rebind via curl-resolve: host=localhost port=$PORT ip=.* class=loopback" || fail "T6.B: no curl-resolve event"
no_leak "T6.B(resolve)"
T6_REBIND=$((T6_REBIND+1))
t6 "rebind=block alone (no mode): a name resolving to loopback is refused before the connect, logged as curl-resolve"
DNSOK=0
cp /etc/resolv.conf "$WORK/resolv.bak" 2>/dev/null || true
if printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > /etc/resolv.conf 2>/dev/null; then
  php /src/lab/integration/corpus/rebind_dns.php 203.0.113.7 >"$WORK/dns.log" 2>&1 &
  DNS_PID=$!
  i=0
  until [ "$($PHPQ -r 'echo gethostbyname("probe.rebind.test");' 2>/dev/null)" = 203.0.113.7 ]; do
    i=$((i+1)); [ $i -gt 30 ] && break
    php -r 'usleep(100000);'
  done
  [ "$($PHPQ -r 'echo gethostbyname("probe.rebind.test");' 2>/dev/null)" = 127.0.0.1 ] && DNSOK=1
fi
RBN=0
next_rb() { RBN=$((RBN+1)); RB="r$RBN.rebind.test"; }
if [ "$DNSOK" != 1 ]; then
  echo "  note - cannot install the rebinding resolver in this container; rebind scenarios SKIPPED"
else
  # B1: the plain check-time range guard is bypassed by the rebinding name (this is
  # the attack the rebind knob exists for; asserted so the lab proves it is real).
  next_rb; export U="http://$RB:$PORT/"; t6run '[sinks.ssrf]\nmode="block"\n' "$CG"
  grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "T6.B1: the rebinding name did not bypass the check-time guard (lab broken)"
  no_events || fail "T6.B1: the check-time guard logged for a name that looked public"
  next_rb; RB1=$RB; next_rb; RB2=$RB
  t6run '[sinks.ssrf]\nmode="block"\n' '$r=@file_get_contents("http://'$RB1':'$PORT'/"); $f=@fsockopen("'$RB2'",'$PORT'); echo "FGC[".var_export($r,true)."] SOCK[".(is_resource($f)?"res":"no")."]\n";'
  grep -q "FGC\[.SERVED.\] SOCK\[res\]" "$WORK/out.txt" || fail "T6.B1: file_get_contents / fsockopen were not rebound past the check-time guard"
  t6 "baseline: with only the check-time range guard, a rebinding name is served by curl, file_get_contents and fsockopen (TOCTOU is real here)"

  # B2: rebind=block on curl.
  next_rb; export U="http://$RB:$PORT/hit.php"; unhit
  t6run '[sinks.ssrf]\nmode="block"\nrebind="block"\n' "$CG"
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "T6.B2: curl to a rebinding name was served under rebind=block"
  grep -q CONT "$WORK/out.txt" || fail "T6.B2: the script did not continue"
  if grep -q HITBODY "$WORK/out.txt"; then fail "T6.B2: the response body reached the script"; fi
  if [ "$HAS_RESOLVE" = 1 ]; then
    hit && fail "T6.B2: curl was not pinned: the rebound request reached the internal service"
    no_events || fail "T6.B2: a pinned (neutralized) attempt should be silent"
    grep -q 'ERRNO\[\(7\|28\)\]' "$WORK/out.txt" || fail "T6.B2: expected a connect failure to the pinned decoy address"
    PIN_MECH=pin
    t6 "rebind=block (curl, PHP >= 5.5): the validated address is pinned with CURLOPT_RESOLVE; libcurl connected to the decoy, never to the rebound loopback (server not reached)"
  else
    ev 'ssrf rebind via curl-connect: host=r[0-9]*.rebind.test port='$PORT' ip=127.0.0.1 class=loopback' || fail "T6.B2: no connect-time event"
    ev '"action":"block"' || fail "T6.B2: not action:block"
    PIN_MECH=postcheck
    t6 "rebind=block (curl, PHP 5.4: no CURLOPT_RESOLVE): the connected address (CURLINFO_PRIMARY_IP) is judged after the transfer and the response discarded; logged class=loopback (the request itself WAS sent: documented)"
  fi
  no_leak "T6.B2"
  T6_REBIND=$((T6_REBIND+1))

  # B3: detect observes the rebind (the connected address) and changes nothing.
  next_rb; export U="http://$RB:$PORT/"
  t6run '[sinks.ssrf]\nmode="detect"\nrebind="detect"\n' "$CG"
  grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "T6.B3: rebind=detect changed behavior"
  ev 'ssrf rebind via curl-connect: host=r[0-9]*.rebind.test port='$PORT' ip=127.0.0.1 class=loopback' || fail "T6.B3: the rebind was not logged"
  ev '"action":"log"' || fail "T6.B3: not action:log"
  no_leak "T6.B3"
  t6 "rebind=detect (curl): the rebound connection is served untouched and logged (class=loopback, action:log)"

  # B4: the socket openers judge the connected peer of the stream they return.
  for FN in fsockopen pfsockopen stream_socket_client; do
    next_rb
    case $FN in
      fsockopen)            CODE='$f=@fsockopen("'$RB'",'$PORT',$en,$es,2);' ;;
      pfsockopen)           CODE='$f=@pfsockopen("'$RB'",'$PORT',$en,$es,2);' ;;
      stream_socket_client) CODE='$f=@stream_socket_client("tcp://'$RB':'$PORT'",$en,$es,2);' ;;
    esac
    t6run '[sinks.ssrf]\nmode="block"\nrebind="block"\n' "$CODE"' echo "F[".var_export(is_resource($f),true)."]\nCONT\n"; if(is_resource($f)) fclose($f);'
    grep -q 'F\[false\]' "$WORK/out.txt" && grep -q CONT "$WORK/out.txt" || fail "T6.B4: $FN returned a stream to the rebound loopback under rebind=block"
    if out_has 'Fatal\|Segmentation\|Warning: Unknown'; then fail "T6.B4: $FN produced a fatal/warning while closing the refused stream"; fi
    ev 'ssrf rebind via tcp-connect: host=r[0-9]*.rebind.test port='$PORT' ip=127.0.0.1 class=loopback' || fail "T6.B4: $FN: no connect-time event"
    ev '"action":"block"' || fail "T6.B4: $FN: not action:block"
    T6_REBIND=$((T6_REBIND+1))
  done
  next_rb
  t6run '[sinks.ssrf]\nmode="detect"\nrebind="detect"\n' '$f=@fsockopen("'$RB'",'$PORT',$en,$es,2); echo "F[".var_export(is_resource($f),true)."]\n";'
  grep -q 'F\[true\]' "$WORK/out.txt" && ev '"action":"log"' || fail "T6.B4: rebind=detect on fsockopen changed behavior / did not log"
  t6 "rebind=block (fsockopen, pfsockopen, stream_socket_client): the connected PEER of the returned stream is judged and the stream closed (false, script continued, no fatal); detect logs and returns the stream"

  # B5: fopen(url): judged after the open (the request has gone out; the response is hidden).
  next_rb; unhit
  t6run '[sinks.ssrf]\nmode="block"\nrebind="block"\n' '$f=@fopen("http://'$RB':'$PORT'/hit.php","r"); echo "F[".var_export(is_resource($f),true)."]\nCONT\n";'
  grep -q 'F\[false\]' "$WORK/out.txt" && grep -q CONT "$WORK/out.txt" || fail "T6.B5: fopen(url) returned the stream under rebind=block"
  ev 'ssrf rebind via stream-connect: host=r[0-9]*.rebind.test port='$PORT' ip=127.0.0.1 class=loopback' || fail "T6.B5: no connect-time event"
  if hit; then SENT=yes; else SENT=no; fi
  T6_REBIND=$((T6_REBIND+1))
  t6 "rebind=block (fopen url): stream refused after the connect (response hidden; request already sent to the server: $SENT, documented)"

  # B6/B7: pinned honest gaps, so the docs cannot drift from the code.
  next_rb
  t6run '[sinks.ssrf]\nmode="block"\nrebind="block"\n' '$r=@file_get_contents("http://'$RB':'$PORT'/"); echo "FGC[".var_export($r,true)."]\n";'
  grep -q 'FGC\[.SERVED.\]' "$WORK/out.txt" || fail "T6.B6: file_get_contents is now guarded against rebinding: update the docs and this check"
  T6_GAPS=$((T6_GAPS+1))
  t6 "KNOWN GAP pinned: file_get_contents / get_headers have no peer to inspect, so a rebinding name is still served under rebind=block"

  if [ "$HAS_RESOLVE" = 1 ]; then
    # A script that manages resolution itself bypasses the check-time guard; the
    # connect-time check catches it (the pin is skipped for it).
    next_rb
    RSV='$c=curl_init("http://'$RB':'$PORT'/"); curl_setopt($c,CURLOPT_RESOLVE,array("'$RB':'$PORT':127.0.0.1")); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); curl_setopt($c,CURLOPT_CONNECTTIMEOUT,2); $r=curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
    t6run '[sinks.ssrf]\nmode="block"\n' "$RSV"
    grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "T6.B7: CURLOPT_RESOLVE bypass not reproduced under the check-time guard (lab broken)"
    next_rb
    RSV='$c=curl_init("http://'$RB':'$PORT'/"); curl_setopt($c,CURLOPT_RESOLVE,array("'$RB':'$PORT':127.0.0.1")); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); curl_setopt($c,CURLOPT_CONNECTTIMEOUT,2); $r=curl_exec($c); echo "RET[".var_export($r,true)."]\nCONT\n";'
    t6run '[sinks.ssrf]\nmode="block"\nrebind="block"\n' "$RSV"
    grep -q 'RET\[false\]' "$WORK/out.txt" || fail "T6.B7: a script-set CURLOPT_RESOLVE to loopback was served under rebind=block"
    ev 'ssrf rebind via curl-connect: host=r[0-9]*.rebind.test port='$PORT' ip=127.0.0.1 class=loopback' || fail "T6.B7: no connect-time event"
    T6_REBIND=$((T6_REBIND+1))
    t6 "rebind=block catches a script's own CURLOPT_RESOLVE to an internal address (served under the check-time guard alone)"
  fi

  # B8: benign egress to an allow_hosts host is untouched with everything armed,
  # and the pin (name:port:ip) is applied transparently.
  ALL='[sinks.ssrf]\nmode="block"\nrebind="block"\nscheme="block"\nredirect="block"\nallow_hosts=["localhost","127.0.0.1"]\n[sinks.tls]\nmode="off"\n'
  export U="http://localhost:$PORT/"
  t6run "$ALL" "$CG"
  grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" || fail "T6.B8: benign curl to an allow_hosts name disturbed (all knobs armed)"
  no_events || fail "T6.B8: benign curl to an allow_hosts name logged"
  export U="http://127.0.0.1:$PORT/"; t6run "$ALL" "$CG"
  grep -q 'RET\[.SERVED.\]' "$WORK/out.txt" && no_events || fail "T6.B8: benign curl to an allow_hosts literal disturbed"
  export FOLLOW=1 U="http://localhost:$PORT/redir.php?to=/hit.php"; unhit; t6run "$ALL" "$CG"
  grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && no_events || fail "T6.B8: a same-host relative redirect was disturbed"
  export U="http://localhost:$PORT/redir.php?to=http://localhost:$PORT/hit.php"; unhit; t6run "$ALL" "$CG"
  grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && hit && no_events || fail "T6.B8: a redirect to an allow_hosts host was disturbed"
  unset FOLLOW
  t6run "$ALL" '$a=@file_get_contents("http://localhost:'$PORT'/"); $f=@fsockopen("localhost",'$PORT',$en,$es,2); $ok=is_resource($f); if($ok) fclose($f); $o=@fopen("http://localhost:'$PORT'/","r"); $b=is_resource($o)?fread($o,20):"no"; echo "A[$a] S[".var_export($ok,true)."] O[$b]\n"; $h=@get_headers("http://localhost:'$PORT'/"); echo "H[".(is_array($h)?"arr":"no")."]\n";'
  grep -q 'A\[SERVED\] S\[true\] O\[SERVED\]' "$WORK/out.txt" && grep -q 'H\[arr\]' "$WORK/out.txt" || fail "T6.B8: a stream/socket to an allow_hosts host was disturbed"
  no_events || fail "T6.B8: benign stream/socket egress logged"
  t6 "benign egress to allow_hosts hosts is UNTOUCHED with rebind+scheme+redirect all in block: curl (name, literal, same-host and allowed-host redirects), file_get_contents, fopen, fsockopen, get_headers: served, zero events"

  # B9: the same over HTTPS (pin keeps the hostname, so SNI / name checks are unchanged).
  if php -m 2>/dev/null | grep -qi '^openssl$'; then
    php /src/lab/integration/corpus/https_server.php 18443 "$WORK/https.pem" >"$WORK/https.log" 2>&1 &
    TLS_PID=$!
    i=0
    until php -d date.timezone=UTC -r '$c=curl_init("https://localhost:18443/"); curl_setopt($c,CURLOPT_SSL_VERIFYPEER,0); curl_setopt($c,CURLOPT_SSL_VERIFYHOST,0); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); curl_setopt($c,CURLOPT_TIMEOUT,3); exit(curl_exec($c)==="HTTPSSERVED"?0:1);' 2>/dev/null; do
      i=$((i+1)); [ $i -gt 25 ] && break
      php -r 'usleep(200000);'
    done
    if [ $i -le 25 ]; then
      HS='$c=curl_init("https://localhost:18443/"); curl_setopt($c,CURLOPT_SSL_VERIFYPEER,0); curl_setopt($c,CURLOPT_SSL_VERIFYHOST,0); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); curl_setopt($c,CURLOPT_TIMEOUT,5); $r=curl_exec($c); $x=stream_context_create(array("ssl"=>array("verify_peer"=>false,"verify_peer_name"=>false))); $g=@file_get_contents("https://localhost:18443/",false,$x); echo "C[".var_export($r,true)."] F[".var_export($g,true)."]\n";'
      t6run "$ALL" "$HS"
      grep -q "C\['HTTPSSERVED'\] F\['HTTPSSERVED'\]" "$WORK/out.txt" || fail "T6.B9: benign https egress to an allow_hosts host disturbed"
      no_events || fail "T6.B9: benign https egress logged"
      t6 "benign HTTPS egress to an allow_hosts host (curl pinned + file_get_contents) is served with every knob in block, zero events"
      # The socket openers' peer check also works through an ssl:// stream: allowed
      # when the host is allow_hosts, refused (closed, false) when it is not.
      SSLC='$x=stream_context_create(array("ssl"=>array("verify_peer"=>false,"verify_peer_name"=>false,"allow_self_signed"=>true))); $f=@stream_socket_client("ssl://localhost:18443",$en,$es,3,STREAM_CLIENT_CONNECT,$x); echo "F[".var_export(is_resource($f),true)."]"; if(is_resource($f)){ fwrite($f,"GET / HTTP/1.0\r\n\r\n"); echo " B[".substr(stream_get_contents($f),-11)."]"; fclose($f);} echo "\nCONT\n";'
      t6run "$ALL" "$SSLC"
      grep -q 'F\[true\] B\[HTTPSSERVED\]' "$WORK/out.txt" && no_events || fail "T6.B9: an ssl:// stream to an allow_hosts host was disturbed"
      t6run '[sinks.ssrf]\nrebind="block"\n[sinks.tls]\nmode="off"\n' "$SSLC"
      grep -q 'F\[false\]' "$WORK/out.txt" && grep -q CONT "$WORK/out.txt" || fail "T6.B9: an ssl:// stream to a loopback peer was returned under rebind=block"
      ev "ssrf rebind via tcp-connect: host=localhost port=18443 ip=.* class=loopback" || fail "T6.B9: no peer event for the ssl:// stream"
      T6_REBIND=$((T6_REBIND+1))
      t6 "rebind=block judges the peer of an ssl:// stream too (allowed host: served; otherwise closed and false)"
    else
      echo "  note - the lab HTTPS target did not come up in this image; HTTPS benign case SKIPPED"
    fi
  else
    echo "  note - no openssl extension in this image; HTTPS benign case SKIPPED"
  fi
fi

# ---- T6.C curl internal-redirect guard -------------------------------------------
RA='[sinks.ssrf]\nredirect="block"\nallow_hosts=["localhost"]\n'
LOOPHIT="http://127.0.0.1:$PORT/hit.php"
enc() { export G="$1"; $PHPQ -r 'echo rawurlencode(getenv("G"));' 2>/dev/null; }
export FOLLOW=1
for CASE in "302|$LOOPHIT|loopback" "301|$LOOPHIT|loopback" "303|$LOOPHIT|loopback" "307|$LOOPHIT|loopback" "308|$LOOPHIT|loopback" \
            "302|//127.0.0.1:$PORT/hit.php|loopback" "302|http://169.254.169.254/latest/meta-data/|metadata" \
            "302|http://[::1]:$PORT/hit.php|loopback" "302|http://2130706433:$PORT/hit.php|loopback" \
            "302|http://10.0.0.5/admin|rfc1918"; do
  rcode=${CASE%%|*}; rest=${CASE#*|}; rto=${rest%|*}; rcls=${rest##*|}
  # PHP 5.4's built-in server has no reason phrase for 308 and wedges on it (curl
  # without howdah times out too): a lab-server limit, not a howdah one.
  if [ "$rcode" = 308 ] && [ "$PHPID" -lt 50500 ]; then
    echo "  note - 308 skipped on PHP 5.4: its built-in test server wedges on that status (libcurl 7.29 also predates 308)"; continue
  fi
  unhit; export U="http://localhost:$PORT/redir.php?code=$rcode&to=$(enc "$rto")"
  t6run "$RA" "$CG"
  grep -q 'RET\[false\] ERRNO\[23\]' "$WORK/out.txt" || fail "T6.C($rcode $rto): the redirect was followed or failed differently ($(cat "$WORK/out.txt" | tr '\n' ' '))"
  grep -q CONT "$WORK/out.txt" || fail "T6.C($rcode $rto): the script did not continue"
  if hit; then fail "T6.C($rcode $rto): the internal target was reached"; fi
  ev "ssrf redirect via .*: host=.* class=$rcls" || fail "T6.C($rcode $rto): no redirect event class=$rcls"
  ev '"action":"block"' || fail "T6.C($rcode $rto): not action:block"
  no_leak "T6.C($rcode $rto)"
  T6_REDIR=$((T6_REDIR+1))
done
t6 "redirect=block: a 301/302/303/307/308 to loopback (127.0.0.1, [::1], decimal 2130706433, scheme-relative //), metadata 169.254.169.254 or RFC1918 is NOT followed: false, CURLE_WRITE_ERROR (23), script continued, internal service never reached, class logged"

# A hop to a NAME is judged on the addresses it resolves to (not just literals).
unhit; export U="http://127.0.0.1:$PORT/redir.php?to=$(enc "http://localhost:$PORT/hit.php")"
t6run '[sinks.ssrf]\nredirect="block"\n' "$CG"
grep -q 'RET\[false\] ERRNO\[23\]' "$WORK/out.txt" && ! hit || fail "T6.C: a redirect hop to a name that resolves to loopback was followed"
ev "ssrf redirect via http: host=localhost port=$PORT ip=.* class=loopback" || fail "T6.C: no event for the resolved-name hop"
T6_REDIR=$((T6_REDIR+1))
t6 "redirect=block judges a hop to a NAME on its resolved addresses (localhost -> loopback refused)"

# Benign redirects are untouched while armed.
unhit; export U="http://localhost:$PORT/redir.php?to=/hit.php"; t6run "$RA" "$CG"
grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && hit && no_events || fail "T6.C: a relative redirect was disturbed"
unhit; export U="http://localhost:$PORT/redir.php?to=$(enc "http://localhost:$PORT/hit.php")"; t6run "$RA" "$CG"
grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && hit && no_events || fail "T6.C: a redirect to an allow_hosts host was disturbed"
unhit; export U="http://localhost:$PORT/redir.php?code=201&to=$(enc "$LOOPHIT")"; t6run "$RA" "$CG"
grep -q 'RET\[.REDIRECTING.\]' "$WORK/out.txt" && ! hit && no_events || fail "T6.C: a Location on a non-3xx (201) was treated as a redirect"
unset FOLLOW; unhit; export U="http://localhost:$PORT/redir.php?to=$(enc "$LOOPHIT")"; t6run "$RA" "$CG"
grep -q 'RET\[.REDIRECTING.\]' "$WORK/out.txt" && ! hit && no_events || fail "T6.C: with FOLLOWLOCATION off the 302 should simply be returned"
t6 "redirect=block leaves benign redirects alone: relative, to an allow_hosts host, a Location on a 201, and FOLLOWLOCATION off (the 302 is simply returned)"

# detect observes only; setopt_array sets FOLLOWLOCATION too.
export FOLLOW=1; unhit; export U="http://localhost:$PORT/redir.php?to=$(enc "$LOOPHIT")"
t6run '[sinks.ssrf]\nredirect="detect"\nallow_hosts=["localhost"]\n' "$CG"
grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && hit || fail "T6.C: redirect=detect changed behavior"
ev 'ssrf redirect via .*class=loopback' && ev '"action":"log"' || fail "T6.C: redirect=detect did not log"
unset FOLLOW; unhit
t6run "$RA" '$c=curl_init(); curl_setopt_array($c,array(CURLOPT_URL=>getenv("U"),CURLOPT_FOLLOWLOCATION=>true,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>6)); $r=curl_exec($c); echo "RET[".var_export($r,true)."] ERRNO[".curl_errno($c)."]\nCONT\n";'
grep -q 'RET\[false\] ERRNO\[23\]' "$WORK/out.txt" && ! hit || fail "T6.C: FOLLOWLOCATION set through curl_setopt_array was not guarded"
t6 "redirect=detect logs and follows; FOLLOWLOCATION set via curl_setopt_array is guarded like curl_setopt"

# Pinned honest gaps.
export FOLLOW=1 HDRFN=1; unhit; export U="http://localhost:$PORT/redir.php?to=$(enc "$LOOPHIT")"
t6run "$RA" "$CG"
grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && hit || fail "T6.C: a script-set CURLOPT_HEADERFUNCTION is now covered: update the docs and this check"
unset FOLLOW HDRFN
T6_GAPS=$((T6_GAPS+1))
t6run '[sinks.ssrf]\nmode="block"\nredirect="block"\n' '$m=curl_multi_init(); $c=curl_init("http://127.0.0.1:'$PORT'/"); curl_setopt($c,CURLOPT_RETURNTRANSFER,1); curl_multi_add_handle($m,$c); do{ $s=curl_multi_exec($m,$run); if($run) curl_multi_select($m,0.1);}while($run && $s==CURLM_OK); echo "M[".curl_multi_getcontent($c)."]\n";'
grep -q 'M\[SERVED\]' "$WORK/out.txt" || fail "T6.C: curl_multi on a loopback URL is now guarded: update the docs and this check"
T6_GAPS=$((T6_GAPS+1))
t6 "KNOWN GAPS pinned: a script-set CURLOPT_HEADERFUNCTION (hops not pre-checked) and curl_multi_* (not hooked) are not covered; both still work normally"

# Redirect hops cannot be pinned: a hop to a rebinding NAME passes the hop check
# (public at that moment) and libcurl then resolves it to loopback. redirect alone
# is bypassed; with rebind=block the FINAL hop's connected address is judged after
# the transfer and the response discarded (the request itself was already sent).
if [ "$DNSOK" = 1 ]; then
  export FOLLOW=1
  next_rb; unhit; export U="http://localhost:$PORT/redir.php?to=$(enc "http://$RB:$PORT/hit.php")"
  t6run '[sinks.ssrf]\nredirect="block"\nallow_hosts=["localhost"]\n' "$CG"
  grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && hit || fail "T6.C: hop rebinding is now caught by redirect alone: update the docs and this check"
  next_rb; unhit; export U="http://localhost:$PORT/redir.php?to=$(enc "http://$RB:$PORT/hit.php")"
  t6run '[sinks.ssrf]\nredirect="block"\nrebind="block"\nallow_hosts=["localhost"]\n' "$CG"
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "T6.C: the final-hop connect check did not discard a rebound hop's response"
  if grep -q HITBODY "$WORK/out.txt"; then fail "T6.C: a rebound hop's body reached the script"; fi
  ev 'ssrf rebind via curl-connect: host=r[0-9]*.rebind.test port='$PORT' ip=127.0.0.1 class=loopback' || fail "T6.C: no connect-time event for the rebound hop"
  unset FOLLOW
  T6_GAPS=$((T6_GAPS+1)); T6_REBIND=$((T6_REBIND+1))
  t6 "KNOWN GAP pinned: a redirect hop to a rebinding name is not pinned (redirect alone is bypassed); rebind=block discards the final hop's response after the fact (the request was sent)"
fi

# Zero events and no behavior change with the facet off (re-checked at the end of
# the section, after every knob has been armed in this process family).
unhit; export U="http://127.0.0.1:$PORT/redir.php?to=$(enc "$LOOPHIT")" FOLLOW=1
t6run '' "$CG"
grep -q 'RET\[.HITBODY.\]' "$WORK/out.txt" && no_events || fail "T6: default (facet off) behavior changed"
unset FOLLOW U
echo "T6 summary: libcurl=${CURLV:-none} scheme-refusals=$T6_SCHEME pin=${PIN_MECH:-n/a} redirects-blocked=$T6_REDIR rebind-refusals=$T6_REBIND gaps-pinned=$T6_GAPS checks=$T6_N"

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
  # assert("...") (internal compiles, not user include/eval). The 1.5 legacy sinks
  # for create_function and assert log every call by default; they are turned off
  # here so this stays a test of the include/eval hook, not of those sinks.
  NOLEGACY='[sinks.create_function]\nmode="off"\n[sinks.assert]\nmode="off"\n'
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
  run_file '[sinks.include]\nmode="detect"\n'"$ALLOW"'\n[sinks.eval]\nmode="detect"\n'"$NOLEGACY" "$WORK/main.php" -d auto_prepend_file="$WORK/pre.php" -d assert.active=1
  grep -q PREPEND_RAN "$WORK/out.txt" || fail "C7: auto_prepend_file did not run"
  grep -q MAIN_RAN "$WORK/out.txt" || fail "C7: main script did not run"
  grep -q 'CF\[2\]' "$WORK/out.txt" || fail "C7: create_function broke"
  grep -q ASSERT_OK "$WORK/out.txt" || fail "C7: assert string broke"
  no_events || fail "C7: misfire - main script / auto_prepend_file / create_function / assert produced an event"
  echo "  ok   - php5 misfire guard: main script, auto_prepend_file, create_function, assert(\"...\") produce NO events"
  run_file '[sinks.include]\nmode="block"\n'"$ALLOW"'\n[sinks.eval]\nmode="block"\n'"$NOLEGACY" "$WORK/main.php" -d auto_prepend_file="$WORK/pre.php" -d assert.active=1
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
