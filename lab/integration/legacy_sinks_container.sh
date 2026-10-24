#!/bin/sh
# In-container half of the Layer-3 legacy-era sink integration test (Howdah
# 1.5): mail, preg_eval (/e), create_function, string assert, dangerous
# string callbacks, XML external entities, and curl TLS verification. Runs
# inside a howdah-dev-php<ver> image with `php -r`, asserting detect logs and
# block refuses for each sink that exists on this PHP, that the argument is
# never logged, and that nothing fires on 8.x for the removed functions.
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-legacy
LOG="$WORK/events.log"
rm -rf "$WORK"; mkdir -p "$WORK"

echo "== php $(php -r 'echo PHP_VERSION;') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
cd "$WORK"

PHPV=$(php -r 'echo PHP_MAJOR_VERSION;')

fail() {
  echo "FAIL: $1"
  echo "--- stdout ---"; cat "$WORK/out.txt" 2>/dev/null
  echo "--- stderr ---"; cat "$WORK/err.txt" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  exit 1
}

# A fake MTA so a mail() that is NOT refused records the message; a refused
# mail() must leave no record.
MAILOUT="$WORK/mailout"
cat > "$WORK/sendmail.sh" <<EOF
#!/bin/sh
cat > "$MAILOUT"
EOF
chmod +x "$WORK/sendmail.sh"

# run_php <toml> <php> [extra -d...]; stdout -> out.txt, log cleared first.
run_php() {
  printf '%b' "$1" > "$WORK/l.toml"
  code="$2"; shift 2
  : > "$LOG"; rm -f "$MAILOUT"
  # shellcheck disable=SC2086
  php -d extension="$WORK/howdah.so" -d howdah.config="$WORK/l.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      -d sendmail_path="$WORK/sendmail.sh" -d assert.active=1 -d zend.assertions=1 \
      "$@" -r "$code" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}
ri_legacy() {
  printf '%b' "$1" > "$WORK/l.toml"
  php -d extension="$WORK/howdah.so" -d howdah.config="$WORK/l.toml" --ri howdah 2>/dev/null \
    | grep 'Layer-3 legacy sinks' || true
}
out_has() { cat "$WORK/out.txt" "$WORK/err.txt" | grep -qi "$1"; }
no_events() { [ ! -s "$LOG" ]; }

# ============================================================= mail
# A1. default (detect): an unsafe 5th-arg option logs; the message is NOT
# blocked (detect), so it is sent; the option is never logged.
run_php '' '$ok = @mail("a@b.c","s","body","From: a@b.c","-OQueueDirectory=/tmp/SECRETQ"); echo "SENT[".var_export($ok,true)."]\n";'
grep -q '"rule":"mail_injection"' "$LOG" || fail "A1: no mail_injection event in detect"
grep -q '"action":"log"' "$LOG" || fail "A1: mail detect not action:log"
if grep -q 'SECRETQ\|QueueDirectory' "$LOG"; then fail "A1: log leaked the mail option"; fi
[ -f "$MAILOUT" ] || fail "A1: detect blocked the mail (no message sent)"
echo "  ok   - mail detect: unsafe additional_parameters logged (option not logged), mail still sent"

# A2. a safe -f sender is silent and sent.
run_php '' '@mail("a@b.c","s","body","From: a@b.c","-fbounce@b.c"); echo "DONE\n";'
no_events || fail "A2: safe -f sender produced an event"
[ -f "$MAILOUT" ] || fail "A2: safe mail not sent"
echo "  ok   - mail: -fbounce@b.c is safe, silent, sent"

# A3. header injection (a line break not followed by a header) logs.
run_php '' '@mail("a@b.c","s","body","From: a@b.c\r\n\r\nINJECTEDBODY"); echo "DONE\n";'
grep -q '"rule":"mail_injection"' "$LOG" || fail "A3: header injection not logged"
if grep -q 'INJECTEDBODY' "$LOG"; then fail "A3: log leaked the header argument"; fi
echo "  ok   - mail detect: CRLF header/body injection in additional_headers logged, argument not logged"

# A4. block: mail() refused (returns false), nothing sent.
run_php '[sinks.mail]\nmode="block"\n' '$ok = @mail("a@b.c","s","body","From: a@b.c","-OQueueDirectory=/tmp/x"); echo "SENT[".var_export($ok,true)."]\nCONT\n";'
grep -q 'SENT\[false\]' "$WORK/out.txt" || fail "A4: blocked mail did not return false"
grep -q CONT "$WORK/out.txt" || fail "A4: script did not continue after mail block"
grep -q '"action":"block"' "$LOG" || fail "A4: no action:block for mail"
[ -f "$MAILOUT" ] && fail "A4: a refused mail was still sent"
echo "  ok   - mail block: refused (returns false), message not sent, script continued"

# ============================================================= callback
# A string callback naming a command/code-exec function. Isolate the callback
# sink (command_exec off) so only dangerous_callback fires.
CB='[sinks]\nmode="off"\n[sinks.callback]\nmode="detect"\n'
run_php "$CB" 'array_map("system", array("echo CB_RAN"));'
grep -q CB_RAN "$WORK/out.txt" || fail "B1: callback did not run in detect"
grep -q '"rule":"dangerous_callback"' "$LOG" || fail "B1: no dangerous_callback event"
grep -q "'system' via array_map" "$LOG" || fail "B1: callback name/function not in reason"
grep -q CB_RAN "$LOG" && fail "B1: log leaked the callback's data"
echo "  ok   - callback detect: array_map('system',...) logged by name only (data not logged), still ran"

run_php "$CB" 'array_map("strtoupper", array("x")); call_user_func("trim"," y ");'
no_events || fail "B2: a benign callback produced an event"
echo "  ok   - callback: benign callbacks (strtoupper, trim) are silent"

run_php '[sinks]\nmode="off"\n[sinks.callback]\nmode="block"\n' '$r = array_map("system", array("echo SHOULD_NOT_RUN")); echo "RET[".var_export($r,true)."]\nCONT\n";'
if grep -q SHOULD_NOT_RUN "$WORK/out.txt"; then fail "B3: blocked callback still ran"; fi
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "B3: blocked array_map did not return false"
grep -q CONT "$WORK/out.txt" || fail "B3: script did not continue after callback block"
grep -q '"action":"block"' "$LOG" || fail "B3: no action:block for callback"
grep -q SHOULD_NOT_RUN "$LOG" && fail "B3: log leaked the callback's data"
echo "  ok   - callback block: array_map('system',...) refused (false), command not run, data not logged, continued"

run_php '[sinks]\nmode="off"\n[sinks.callback]\nmode="detect"\n' 'register_shutdown_function("exec", "echo CB_SHUT"); echo "REG\n";'
grep -q '"rule":"dangerous_callback"' "$LOG" || fail "B4: register_shutdown_function callback not logged"
grep -q "'exec' via register_shutdown_function" "$LOG" || fail "B4: wrong reason for shutdown callback"
grep -q CB_SHUT "$LOG" && fail "B4: log leaked the callback's data"
echo "  ok   - callback detect: register_shutdown_function('exec',...) logged by name only"

# B5. call_user_func pinned per version. On 7.0+ the compiler turns a literal,
# unqualified call_user_func("...") in the GLOBAL namespace into
# ZEND_INIT_USER_CALL and never calls the internal function, so the
# function-table hook cannot see the classic webshell shape there (documented
# limitation). A namespaced or dynamic call still resolves at run time and is
# seen. On 5.x every form goes through the function.
run_php "$CB" 'call_user_func("system", "echo CB_LIT");'
lit=$(grep -c '"rule":"dangerous_callback"' "$LOG" || true)
run_php "$CB" 'namespace App; call_user_func("system", "echo CB_NS");'
ns=$(grep -c '"rule":"dangerous_callback"' "$LOG" || true)
grep -q CB_NS "$WORK/out.txt" || fail "B5: namespaced call_user_func did not run"
run_php "$CB" '$f = "call_user_func"; $f("system", "echo CB_DYN");'
dyn=$(grep -c '"rule":"dangerous_callback"' "$LOG" || true)
grep -q CB_DYN "$WORK/out.txt" || fail "B5: dynamic call_user_func did not run"
grep -q 'CB_LIT\|CB_NS\|CB_DYN' "$LOG" && fail "B5: log leaked callback data"
[ "$ns" = 1 ] || fail "B5: namespaced call_user_func('system') not logged (got $ns)"
[ "$dyn" = 1 ] || fail "B5: dynamic call_user_func('system') not logged (got $dyn)"
if [ "$PHPV" -lt 7 ]; then
  [ "$lit" = 1 ] || fail "B5: 5.x literal call_user_func('system') not logged (got $lit)"
  echo "  ok   - php5 call_user_func: literal, namespaced and dynamic calls all logged"
else
  [ "$lit" = 0 ] || fail "B5: expected the 7.0+ global-namespace literal call_user_func to bypass the hook (compiled to ZEND_INIT_USER_CALL); it was logged $lit time(s), update the docs"
  echo "  ok   - call_user_func on 7.0+: global-namespace literal call NOT seen (ZEND_INIT_USER_CALL, documented); namespaced and dynamic calls logged"
fi

# ============================================================= xml (XXE)
XXE='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/SECRETPATH">]><r>&x;</r>'
run_php '[sinks.xml]\nmode="detect"\n' '$d = @simplexml_load_string(getenv("DOC")); echo "PARSED\n";' -d "auto_prepend_file="
export DOC="$XXE"
run_php '[sinks.xml]\nmode="detect"\n' '$d = @simplexml_load_string(getenv("DOC")); echo "PARSED\n";'
grep -q '"rule":"xxe"' "$LOG" || fail "C1: no xxe event in detect"
grep -q '"action":"log"' "$LOG" || fail "C1: xxe detect not action:log"
if grep -q 'SECRETPATH' "$LOG"; then fail "C1: log leaked the XML document"; fi
grep -q PARSED "$WORK/out.txt" || fail "C1: script did not continue after xml parse"
echo "  ok   - xml detect: external-entity DOCTYPE logged (rule=xxe), document not logged"

run_php '[sinks.xml]\nmode="detect"\n' '$d = @simplexml_load_string("<r><a>1</a></r>"); echo "PARSED\n";'
no_events || fail "C2: a benign XML document produced an xxe event"
echo "  ok   - xml: a document with no DOCTYPE is silent"

run_php '[sinks.xml]\nmode="block"\n' '$d = @simplexml_load_string(getenv("DOC")); echo "RET[".var_export($d,true)."]\nCONT\n";'
grep -q 'RET\[false\]' "$WORK/out.txt" || fail "C3: blocked xml did not return false"
grep -q CONT "$WORK/out.txt" || fail "C3: script did not continue after xml block"
grep -q '"action":"block"' "$LOG" || fail "C3: no action:block for xml"
echo "  ok   - xml block: simplexml_load_string of an XXE doc refused (false), script continued"

# external_entities = "deny": the toggle shows in `php --ri` and the loader
# call is made (verified by the ri row; its runtime effect on loading by path
# is documented, not asserted here).
php -d extension="$WORK/howdah.so" -d howdah.config=/dev/stdin --ri howdah 2>/dev/null <<'TOMLRI' | grep -q 'XML external entities => denied' \
  && echo "  ok   - xml external_entities=deny: shown as denied in php --ri howdah" || fail "C4: deny toggle not surfaced"
[sinks.xml]
external_entities = "deny"
TOMLRI

# DOMDocument::loadXML where the class exists (not on the 5.4 image).
if php -r 'exit(class_exists("DOMDocument")?0:1);'; then
  run_php '[sinks.xml]\nmode="detect"\n' '$doc=new DOMDocument(); @$doc->loadXML(getenv("DOC")); echo "DOM\n";'
  grep -q '"rule":"xxe"' "$LOG" || fail "C5: DOMDocument::loadXML XXE not logged"
  if grep -q 'SECRETPATH' "$LOG"; then fail "C5: log leaked the XML document"; fi
  echo "  ok   - xml detect: DOMDocument::loadXML of an XXE doc logged (rule=xxe), document not logged"
  # A bare external DTD (the SVG doctype) is detect-only: logged, never blocked.
  export SVG='<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"/>'
  run_php '[sinks.xml]\nmode="block"\n' '$doc=new DOMDocument(); $r=@$doc->loadXML(getenv("SVG")); echo "RET[".var_export($r,true)."]\n";'
  grep -q 'RET\[true\]' "$WORK/out.txt" || fail "C6: an SVG doctype was refused under block (must be detect-only)"
  grep -q '"rule":"xxe"' "$LOG" || fail "C6: SVG external DTD not logged"
  grep -q '"action":"log"' "$LOG" || fail "C6: SVG external DTD must log, not block"
  echo "  ok   - xml: a bare external DTD (SVG doctype) under block mode is logged only, document loads"
else
  echo "  note - DOMDocument not built into this image; loadXML case skipped"
fi

# ============================================================= tls (detect-only)
run_php '[sinks.tls]\nmode="block"\n' '$c=curl_init(); curl_setopt($c,CURLOPT_SSL_VERIFYPEER,false); curl_setopt($c,CURLOPT_SSL_VERIFYHOST,0); echo "SET\n";'
grep -q '"rule":"tls_verify"' "$LOG" || fail "D1: no tls_verify event"
grep -q '"action":"log"' "$LOG" || fail "D1: tls should be detect-only (log even when block)"
if grep -q '"action":"block"' "$LOG"; then fail "D1: tls must never block in this release"; fi
[ "$(grep -c '"rule":"tls_verify"' "$LOG")" = 2 ] || fail "D1: expected two tls_verify events (VERIFYPEER and VERIFYHOST)"
grep -q SET "$WORK/out.txt" || fail "D1: script did not continue"
echo "  ok   - tls: VERIFYPEER=false and VERIFYHOST=0 each logged (rule=tls_verify, action=log), never blocked"

run_php '[sinks.tls]\nmode="detect"\n' '$o=array(CURLOPT_SSL_VERIFYPEER=>false); $c=curl_init(); curl_setopt_array($c,$o); echo "SET\n";'
grep -q '"rule":"tls_verify"' "$LOG" || fail "D2: curl_setopt_array VERIFYPEER not logged"
echo "  ok   - tls: curl_setopt_array with VERIFYPEER=false logged"

run_php '[sinks.tls]\nmode="detect"\n' '$c=curl_init(); curl_setopt($c,CURLOPT_SSL_VERIFYPEER,true); curl_setopt($c,CURLOPT_TIMEOUT,5); echo "SET\n";'
no_events || fail "D3: verification left ON produced a tls event"
echo "  ok   - tls: leaving verification on (and unrelated options) is silent"

# ============================================================= version-specific
if [ "$PHPV" -lt 7 ]; then
  # preg /e (PHP 5.x only).
  run_php '[sinks.preg_eval]\nmode="detect"\n' '@preg_replace("/(SECRETPAT)/e", "strtoupper(\"$1\")", "x secretpat"); echo "PR\n";'
  grep -q '"rule":"preg_eval"' "$LOG" || fail "E1: preg /e not logged on 5.x"
  if grep -q 'SECRETPAT' "$LOG"; then fail "E1: log leaked the preg pattern"; fi
  echo "  ok   - php5 preg_eval detect: /e pattern logged, pattern not logged"
  run_php '[sinks.preg_eval]\nmode="block"\n' '$r=@preg_replace("/(a)/e", "strtoupper(\"$1\")", "a"); echo "RET[".var_export($r,true)."]\nCONT\n";'
  grep -q 'RET\[NULL\]' "$WORK/out.txt" || fail "E1b: blocked preg did not return null"
  grep -q '"action":"block"' "$LOG" || fail "E1b: no action:block for preg_eval"
  echo "  ok   - php5 preg_eval block: returns null, script continued"
  run_php '[sinks.preg_eval]\nmode="detect"\n' '@preg_replace("/a/i", "b", "a"); echo "PR\n";'
  no_events || fail "E1c: a non-/e pattern produced a preg_eval event"
  echo "  ok   - php5 preg_eval: a pattern without /e is silent"
else
  # 7.0+ removed /e; our shim installs no preg hook there.
  run_php '[sinks.preg_eval]\nmode="block"\n' '@preg_replace("/a/", "b", "a"); echo "PR\n";'
  no_events || fail "E1: preg_eval fired on 7.0+ (should be inert: /e was removed)"
  echo "  ok   - preg_eval inert on 7.0+ (the /e modifier was removed in PHP 7.0)"
fi

if [ "$PHPV" -lt 8 ]; then
  # create_function (5.x and 7.x).
  run_php '[sinks.create_function]\nmode="detect"\n' '$f=create_function("$a", "return SECRETBODY($a);"); echo "CF\n";'
  grep -q '"rule":"create_function"' "$LOG" || fail "F1: create_function not logged"
  if grep -q 'SECRETBODY' "$LOG"; then fail "F1: log leaked the function body"; fi
  echo "  ok   - create_function detect: logged, body not logged"
  run_php '[sinks.create_function]\nmode="block"\n' '$f=@create_function("$a", "return $a;"); echo "RET[".var_export($f,true)."]\nCONT\n";'
  grep -q 'RET\[false\]' "$WORK/out.txt" || fail "F1b: blocked create_function did not return false"
  grep -q '"action":"block"' "$LOG" || fail "F1b: no action:block for create_function"
  echo "  ok   - create_function block: returns false, script continued"

  # string assert (5.x, and 7.x with assertions on).
  run_php '[sinks.assert]\nmode="detect"\n' '@assert("1 == SECRETEXPR"); echo "AS\n";'
  grep -q '"rule":"assert_string"' "$LOG" || fail "F2: string assert not logged"
  if grep -q 'SECRETEXPR' "$LOG"; then fail "F2: log leaked the assert expression"; fi
  echo "  ok   - assert detect: string assertion logged, expression not logged"
  run_php '[sinks.assert]\nmode="block"\n' '$r=@assert("1 == 1"); echo "RET[".var_export($r,true)."]\nCONT\n";'
  grep -q CONT "$WORK/out.txt" || fail "F2b: script did not continue after assert block"
  grep -q '"action":"block"' "$LOG" || fail "F2b: no action:block for assert"
  echo "  ok   - assert block: refused, script continued"
else
  # 8.x: create_function removed; string assert no longer evaluated. The sinks
  # install nothing (the functions are gone / inert) -> the ri row omits them.
  row=$(ri_legacy '[sinks.create_function]\nmode="block"\n[sinks.assert]\nmode="block"\n')
  echo "$row" | grep -q 'absent or disabled:.*create_function' || fail "G1: create_function not reported absent on 8.x ($row)"
  echo "$row" | grep -q 'absent or disabled:.*assert' || fail "G1: assert not reported absent on 8.x ($row)"
  echo "  ok   - php8: create_function and string assert install nothing (ri: $row)"
fi

# The legacy-sink phpinfo row lists what actually installed on this version.
row=$(ri_legacy '[sinks]\nmode="detect"\n')
echo "$row" | grep -q 'mail' || fail "H1: mail not listed as installed (row: $row)"
echo "  ok   - php --ri howdah legacy row: $row"

echo "PASS"
