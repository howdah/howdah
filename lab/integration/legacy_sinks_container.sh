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

# ============================================================= xml (XXE), flag-aware
# On by default: with no config at all, an external entity in an XML string
# parsed with a dangerous libxml flag (NOENT/DTDLOAD/DTDATTR/DTDVALID) has the
# flag stripped and the parse goes on; no flag, or no external entity, is left
# alone. XXE-ROW lines feed the per-version table the host driver prints.
XE=/src/lab/integration/xxe
SECRET=CANARY_SECRET_9731
printf '%s' "$SECRET" > "$WORK/secret.txt"
export XXE_DOC="<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file://$WORK/secret.txt\">]><r>&x;</r>"
LV=$(php -r 'echo defined("LIBXML_VERSION") ? LIBXML_VERSION : 0;')
ENTRIES="simplexml_load_string"
php -r 'exit(class_exists("SimpleXMLElement") ? 0 : 1);' && ENTRIES="$ENTRIES simplexmlelement"
php -r 'exit(class_exists("DOMDocument") ? 0 : 1);' && ENTRIES="$ENTRIES domdocument"
php -r 'exit(class_exists("XMLReader") ? 0 : 1);' && ENTRIES="$ENTRIES xmlreader"
php -r 'exit(class_exists("Dom\\XMLDocument") ? 0 : 1);' && ENTRIES="$ENTRIES dom84"
NENT=$(echo $ENTRIES | wc -w)
fn_of() {
  case "$1" in
    simplexml_load_string) echo 'via simplexml_load_string' ;;
    domdocument) echo 'via DOMDocument::loadXML' ;;
    simplexmlelement) echo 'via SimpleXMLElement::__construct' ;;
    xmlreader) echo 'via XMLReader::XML' ;;
    dom84) printf '%s\n' 'via Dom\\XMLDocument::createFromString' ;;
  esac
}
# xe <config> <entry> <flags> [<env var>] -> "<PARSED|REFUSED> <LEAK|NOLEAK>" in out.txt, log in $LOG.
# <config>: SHIPPED = no howdah.config file and the packaged ini default
# howdah.mode=detect (the real default install); INIOFF = howdah.mode=off; else
# the TOML text of a howdah.config file.
xe() {
  case "$1" in
    SHIPPED) CFGARG="-d howdah.mode=detect" ;;
    INIOFF) CFGARG="-d howdah.mode=off" ;;
    *) printf '%b' "$1" > "$WORK/l.toml"; CFGARG="-d howdah.config=$WORK/l.toml" ;;
  esac
  : > "$LOG"
  # shellcheck disable=SC2086
  php -d extension="$WORK/howdah.so" $CFGARG -d howdah.log="$LOG" \
      -d display_errors=0 -d error_reporting=-1 -d date.timezone=UTC \
      "$XE/xe.php" "$2" "$3" ${4:-} > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}
xe_plain() { # the same parse with Howdah not loaded (the control)
  php -d display_errors=0 -d date.timezone=UTC "$XE/xe.php" "$1" "$2" ${3:-} 2>/dev/null || true
}
nblock() { grep '"rule":"xxe"' "$LOG" | grep -c '"action":"block"' || true; }
nlog() { grep '"rule":"xxe"' "$LOG" | grep -c '"action":"log"' || true; }
nxxe() { grep -c '"rule":"xxe"' "$LOG" || true; }

# --- control: is the vector live on this PHP / libxml, without Howdah? -------
LIVE=0
for e in $ENTRIES; do
  r=$(xe_plain "$e" 2)
  case "$r" in "PARSED LEAK") LIVE=$((LIVE + 1)) ;; esac
done
echo "  note - libxml $LV: external entity + LIBXML_NOENT leaks the canary through $LIVE of $NENT entry points with Howdah NOT loaded"
[ "$LIVE" -ge 1 ] || fail "C0: the XXE vector is not live on this image (no entry point leaked the canary without Howdah); the block proof below would be vacuous"

# --- the default: no howdah.config, the packaged howdah.mode=detect -------------
BLOCKED=0
for e in $ENTRIES; do
  xe SHIPPED "$e" 2
  r=$(cat "$WORK/out.txt")
  [ "$r" = "PARSED NOLEAK" ] || fail "C1[$e]: default config, NOENT + external entity: expected 'PARSED NOLEAK' (flags stripped, parse continues), got '$r'"
  [ "$(nblock)" = 1 ] || fail "C1[$e]: expected exactly one xxe block event, got $(nblock)"
  grep -qF "$(fn_of "$e")" "$LOG" || fail "C1[$e]: event does not name the guarded function ($(fn_of "$e"))"
  grep -q 'dangerous flags removed, parse continued' "$LOG" || fail "C1[$e]: event does not say the flags were removed"
  grep -q 'LIBXML_NOENT' "$LOG" || fail "C1[$e]: event does not name the flag"
  if grep -q "$SECRET\|secret.txt\|howdah-legacy" "$LOG"; then fail "C1[$e]: log leaked the XML document / path"; fi
  BLOCKED=$((BLOCKED + 1))
done
echo "  ok   - xml shipped default (no howdah.config, howdah.mode=detect): NOENT + external entity stripped and parse continued on $BLOCKED of $NENT entry points ($ENTRIES), canary not read, document not logged"

# Every dangerous flag, not only NOENT; benign flags ride along untouched.
for f in 4 8 16 6 14 30 16386; do
  xe SHIPPED simplexml_load_string "$f"
  [ "$(cat "$WORK/out.txt")" = "PARSED NOLEAK" ] || fail "C2: flags $f: expected PARSED NOLEAK, got '$(cat "$WORK/out.txt")'"
  [ "$(nblock)" = 1 ] || fail "C2: flags $f: expected one block event, got $(nblock)"
done
echo "  ok   - xml: DTDLOAD, DTDATTR, DTDVALID, NOENT|DTDLOAD, NOENT|DTDLOAD|DTDATTR, all four, NOENT|NOCDATA: each stripped (one block event each)"

# No dangerous flag: silent, whatever the document says (libxml 2.9+ neither
# expands nor fetches it). On libxml < 2.9 flags prove nothing and the call is refused.
for f in 0 1 64 256 2048 16384 524288; do
  xe SHIPPED simplexml_load_string "$f"
  if [ "$LV" -ge 20900 ]; then
    [ "$(nxxe)" = 0 ] || fail "C3: flags $f without a dangerous flag raised an xxe event"
    grep -q "$SECRET" "$WORK/out.txt" && fail "C3: flags $f leaked the canary"
  fi
done
if [ "$LV" -ge 20900 ]; then
  echo "  ok   - xml: external entity with no dangerous flag (0, RECOVER, NOWARNING, NOBLANKS, NONET, NOCDATA, PARSEHUGE) is silent and reads nothing"
else
  echo "  note - libxml $LV is older than 2.9: flags do not gate the check there (not asserted)"
fi

# The caller's own variable is never changed, even when it is a reference or a numeric string.
xe SHIPPED simplexml_load_string_var 2
[ "$(cat "$WORK/out.txt")" = "OPTS=2 PARSED NOLEAK" ] || fail "C4: flags variable / reference changed or leaked: '$(cat "$WORK/out.txt")'"
xe SHIPPED simplexml_load_string_str 2
[ "$(cat "$WORK/out.txt")" = "PARSED NOLEAK" ] || fail "C4: numeric-string flags: '$(cat "$WORK/out.txt")'"
[ "$(nblock)" = 1 ] || fail "C4: numeric-string flags did not raise one event"
echo "  ok   - xml: the caller's flags variable (also by reference) is untouched after a strip; numeric-string flags are stripped too"

if [ "$PHPV" -ge 8 ]; then
  : > "$LOG"
  r=$(php -d extension="$WORK/howdah.so" -d howdah.mode=detect -d howdah.log="$LOG" -d display_errors=0 "$XE/xe_named.php" 2 2>/dev/null)
  [ "$r" = "PARSED NOLEAK" ] || fail "C5: named arguments: expected PARSED NOLEAK, got '$r'"
  [ "$(nblock)" = 2 ] || fail "C5: named arguments: expected two block events (simplexml + dom), got $(nblock)"
  echo "  ok   - xml (PHP 8): named arguments (options: before data:) are stripped too"
fi

# --- modes ------------------------------------------------------------------------
xe '[sinks.xml]\nmode="detect"\n' simplexml_load_string 2
[ "$(cat "$WORK/out.txt")" = "PARSED LEAK" ] || fail "C6: detect mode must only log (control: the entity is read), got '$(cat "$WORK/out.txt")'"
[ "$(nlog)" = 1 ] && [ "$(nblock)" = 0 ] || fail "C6: detect mode: expected one log event and no block"
echo "  ok   - xml mode=detect: logged (action:log), flags left alone"

xe '[sinks.xml]\nmode="off"\n' simplexml_load_string 2
[ "$(nxxe)" = 0 ] || fail "C7: [sinks.xml] mode=off raised an event"
echo "  ok   - xml mode=off: silent"

xe INIOFF simplexml_load_string 2
[ "$(nxxe)" = 0 ] && [ "$(cat "$WORK/out.txt")" = "PARSED LEAK" ] || fail "C7: howdah.mode=off must silence the rule"
echo "  ok   - howdah.mode=off: silent"

xe '[sinks]\nenabled=false\n' simplexml_load_string 2
[ "$(nxxe)" = 0 ] || fail "C7: [sinks] enabled=false must silence the rule"
echo "  ok   - [sinks] enabled=false: silent"

# The shipped state: howdah.mode = detect on the ini line AND a [sinks] detect
# do not soften an on-by-default rule (it has its own mode).
xe '[sinks]\nmode="detect"\n' simplexml_load_string 2
[ "$(nblock)" = 1 ] || fail "C8: [sinks] mode=detect softened the xxe rule"
echo "  ok   - [sinks] mode=detect does not soften xxe (its own knob is [sinks.xml] mode)"

# --- entity bomb (billion laughs): same class, stripped --------------------------
BOMB=$(php -r '$s="<?xml version=\"1.0\"?><!DOCTYPE l [<!ENTITY a0 \"lol\">"; for($k=1;$k<=7;$k++){$s.="<!ENTITY a$k \"".str_repeat("&a".($k-1).";",10)."\">";} echo $s."]><l>&a7;</l>";')
export BOMB
xe SHIPPED simplexml_load_string 2 BOMB
# After the strip libxml's own amplification guard may still refuse the document
# (2.9+ does for this one); either way nothing was substituted.
case "$(cat "$WORK/out.txt")" in "PARSED NOLEAK"|"REFUSED NOLEAK") ;; *) fail "C9: entity bomb: unexpected result '$(cat "$WORK/out.txt")'" ;; esac
grep -q 'expand past 1 MiB' "$LOG" || fail "C9: bomb event missing"
[ "$(nblock)" = 1 ] || fail "C9: bomb: expected one block event"
echo "  ok   - xml: a billion-laughs chain (7 levels of 10) with LIBXML_NOENT has the flag stripped (rule=xxe, 'expand past 1 MiB'); nothing substituted"
xe SHIPPED simplexml_load_string 0 BOMB
[ "$(nxxe)" = 0 ] || fail "C9: bomb without a dangerous flag raised an event"

# --- bare DOCTYPE / external DTD: never blocked --------------------------------
export SVG='<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"/>'
export BARE='<?xml version="1.0"?><!DOCTYPE note [<!ELEMENT note (#PCDATA)>]><note>hi</note>'
for e in $ENTRIES; do
  for f in 0 2 4 6 14 30; do
    xe SHIPPED "$e" "$f" BARE
    [ "$(nxxe)" = 0 ] || fail "C10[$e]: a bare DOCTYPE with flags $f raised an xxe event"
    xe '[sinks.xml]\nmode="block"\n' "$e" "$f" SVG
    [ "$(nblock)" = 0 ] || fail "C10[$e]: an SVG doctype with flags $f was blocked"
    r=$(cat "$WORK/out.txt")
    case "$r" in PARSED*) ;; *) [ "$f" -ge 4 ] || fail "C10[$e]: SVG doctype with flags $f did not parse ($r)" ;; esac
  done
done
xe SHIPPED simplexml_load_string 2 SVG
[ "$(nxxe)" = 0 ] || fail "C10: SVG with NOENT only fetches no DTD; expected silence"
xe SHIPPED simplexml_load_string 4 SVG
[ "$(nlog)" = 1 ] && grep -q 'external DTD' "$LOG" || fail "C10: SVG with DTDLOAD should log one detect-only line"
echo "  ok   - xml: a bare DOCTYPE and an SVG doctype are never blocked on any entry point, any flags (SVG + DTDLOAD logs one detect-only line)"

# --- file-based loaders are not covered (documented): no event ---------------------
printf '%s' "$XXE_DOC" > "$WORK/xxe.xml"
if php -r 'exit(function_exists("simplexml_load_file") ? 0 : 1);'; then
  : > "$LOG"
  php -d extension="$WORK/howdah.so" -d howdah.mode=detect -d howdah.log="$LOG" -d display_errors=0 \
      -r '$s = @simplexml_load_file(getenv("F"), null, LIBXML_NOENT); echo $s === false ? "FALSE" : "OK"; if (class_exists("DOMDocument")) { $d = new DOMDocument(); echo @$d->load(getenv("F"), LIBXML_NOENT) ? "OK" : "FALSE"; }' \
      > "$WORK/out.txt" 2>/dev/null || true
  [ "$(nxxe)" = 0 ] || fail "C11: a file-based loader raised an event (documented as not covered)"
  echo "  ok   - xml: simplexml_load_file / DOMDocument::load are not hooked (documented gap; external_entities=\"deny\" covers them): no event"
fi

# --- evasions: the same payload hidden from a scan of the raw bytes ----------------
# Each shape is something libxml still reads (UTF-7/UTF-32/UTF-16/EBCDIC bodies, a
# DOCTYPE hidden behind a '>' in its system literal, a parameter entity that
# declares the entity, a megabyte of padding). The control run must leak where
# the vector is live on this libxml; Howdah must then leave nothing readable.
export XXE_FILE="$WORK/secret.txt"
EV_LIVE=0; EV_STOPPED=0; EV_TOTAL=0
for v in $(php "$XE/evade.php" list); do
  EV_TOTAL=$((EV_TOTAL + 1))
  ctl=$(php -d display_errors=0 "$XE/evade.php" "$v" 2 2>/dev/null || true)
  [ "$ctl" = "NA" ] && continue
  case "$ctl" in "PARSED LEAK") ;; *) continue ;; esac   # vector not live on this libxml: nothing to prove
  EV_LIVE=$((EV_LIVE + 1))
  : > "$LOG"
  r=$(php -d extension="$WORK/howdah.so" -d howdah.mode=detect -d howdah.log="$LOG" -d display_errors=0 "$XE/evade.php" "$v" 2 2>/dev/null || true)
  case "$r" in "REFUSED NOLEAK"|"PARSED NOLEAK") ;; *) fail "C11[$v]: an XXE shape that leaks without Howdah was not neutralized (got '$r')" ;; esac
  [ "$(nblock)" = 1 ] || fail "C11[$v]: expected one xxe block event, got $(nblock)"
  if grep -q "$SECRET\|secret.txt" "$LOG"; then fail "C11[$v]: log leaked the document / path"; fi
  EV_STOPPED=$((EV_STOPPED + 1))
done
[ "$EV_LIVE" -ge 5 ] || fail "C11: only $EV_LIVE of $EV_TOTAL evasion shapes were live on this libxml; the evasion proof would be vacuous"
echo "  ok   - xml evasions: $EV_STOPPED of $EV_LIVE live shapes (of $EV_TOTAL: DOCTYPE literal with > or [, parameter-entity literal incl. char refs, UTF-7/UTF-32/UTF-16/EBCDIC bodies, megabyte padding) neutralized; each leaks without Howdah"

# --- BENIGN corpus: the on-by-default false-positive gate --------------------------
php -d display_errors=0 -d date.timezone=UTC "$XE/benign.php" > "$WORK/benign-plain.txt" 2>/dev/null || true
: > "$LOG"
php -d extension="$WORK/howdah.so" -d howdah.mode=detect -d howdah.log="$LOG" \
    -d display_errors=0 -d date.timezone=UTC "$XE/benign.php" > "$WORK/benign-howdah.txt" 2>"$WORK/err.txt" || true
BTOTAL=$(sed -n 's/^TOTAL=//p' "$WORK/benign-howdah.txt")
BBLOCK=$(nblock)
BLOG=$(nlog)
[ -n "$BTOTAL" ] && [ "$BTOTAL" -ge 100 ] || fail "C12: the benign corpus did not run to the end (TOTAL=$BTOTAL)"
[ "$BBLOCK" = 0 ] || fail "C12: the benign corpus produced $BBLOCK xxe BLOCK event(s)"
cmp -s "$WORK/benign-plain.txt" "$WORK/benign-howdah.txt" || { diff "$WORK/benign-plain.txt" "$WORK/benign-howdah.txt" | head -10; fail "C12: benign parse results differ with Howdah loaded"; }
if grep -v '"action":"log"' "$LOG" | grep -q '"rule":"xxe"'; then fail "C12: a benign document produced a non-log xxe event"; fi
if [ "$BLOG" -gt 0 ] && ! grep '"rule":"xxe"' "$LOG" | grep -q 'external DTD'; then fail "C12: unexpected benign log events"; fi
echo "  ok   - xml BENIGN corpus: $BTOTAL parses (14 documents incl. SAML/SVG/XHTML/RSS/plist/ODF/Office/bare DOCTYPE/internal entities x 10 flag sets x each entry point): 0 blocks, results byte-identical with and without Howdah ($BLOG detect-only external-DTD log lines)"

echo "XXE-ROW	libxml=$LV	control_leaks=$LIVE/$NENT	blocked=$BLOCKED/$NENT	evasions=$EV_STOPPED/$EV_LIVE	benign_parses=$BTOTAL	benign_blocks=$BBLOCK	benign_identical=yes	benign_log_only=$BLOG"

# external_entities = "deny": the toggle shows in `php --ri` and the loader
# call is made (verified by the ri row; its runtime effect on loading by path
# is documented, not asserted here).
php -d extension="$WORK/howdah.so" -d howdah.config=/dev/stdin --ri howdah 2>/dev/null <<'TOMLRI' | grep -q 'XML external entities => denied' \
  && echo "  ok   - xml external_entities=deny: shown as denied in php --ri howdah" || fail "C13: deny toggle not surfaced"
[sinks.xml]
external_entities = "deny"
TOMLRI

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
