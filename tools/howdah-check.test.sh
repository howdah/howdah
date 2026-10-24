#!/bin/sh
# Tests for tools/howdah-check (no real multi-PHP box needed).
# Run from anywhere:  sh tools/howdah-check.test.sh
# POSIX sh; exits non-zero if any check fails.
D=$(cd "$(dirname "$0")" && pwd)
HC=$D/howdah-check
T=$(mktemp -d) || exit 2
trap 'rm -rf "$T"' EXIT
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got $2, want $3)"; fi; }
check() { # name, exit-status (0 = pass)
  if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi
}

sh -n "$HC"; check "syntax (sh -n)" $?

sh "$HC" -h >/dev/null 2>&1; check "-h exits 0" $?
sh "$HC" >/dev/null 2>&1; rc=$?; eq "no args exits 2" "$rc" 2
sh "$HC" bogus >/dev/null 2>&1; rc=$?; eq "unknown command exits 2" "$rc" 2
sh "$HC" web >/dev/null 2>&1; rc=$?; eq "web without url exits 2" "$rc" 2

mkdir -p "$T/empty"
arch_of() { HOWDAH_CHECK_ROOT=$T/empty HOWDAH_CHECK_UNAME_M=$1 sh "$HC" detect 2>/dev/null | sed -n 's/^host arch: //p'; }
eq "arm64 -> aarch64" "$(arch_of arm64)" aarch64
eq "aarch64 passthrough" "$(arch_of aarch64)" aarch64
eq "x86_64 passthrough" "$(arch_of x86_64)" x86_64
eq "other arch verbatim" "$(arch_of riscv64)" riscv64

sh "$HC" detect 2>/dev/null | grep -q '^host arch: [^ ]'; check "detect prints host arch line" $?

# fake PHP install: asset line is built from real api + minor + arch
mkdir -p "$T/fake/usr/bin"
cat > "$T/fake/usr/bin/php" <<'P'
#!/bin/sh
case "$1" in
  -v) echo "PHP 7.4.33 (cli)" ;;
  -i) printf 'PHP Version => 7.4.33\nPHP API => 20190902\nThread Safety => disabled\n' ;;
  -m) printf '[PHP Modules]\nCore\n' ;;
esac
P
chmod +x "$T/fake/usr/bin/php"
out=$(HOWDAH_CHECK_ROOT=$T/fake HOWDAH_CHECK_UNAME_M=arm64 PATH="$T/fake/usr/bin:$PATH" sh "$HC" detect 2>/dev/null)
printf '%s\n' "$out" | grep -q 'matching release asset: howdah-<VERSION>-php7.4-20190902-linux-aarch64.tar.gz$'
check "matching asset line for fake PHP 7.4" $?

# config-only install: never guess
mkdir -p "$T/cfg/etc/php/8.1/cli"
out=$(HOWDAH_CHECK_ROOT=$T/cfg PATH=/nonexistent:/usr/bin:/bin sh "$HC" detect 2>/dev/null)
printf '%s\n' "$out" | grep -q 'matching release asset: cannot determine (api/version unknown)'
check "config-only install says cannot determine" $?

# Layer 2 (input inspection) is log-only by default: detect says so
out=$(HOWDAH_CHECK_ROOT=$T/empty sh "$HC" detect 2>/dev/null)
l2=$(printf '%s\n' "$out" | grep '^note: layer 2')
printf '%s\n' "$l2" | grep -q 'sql_injection, path_traversal, command_injection'
check "detect names the Layer-2 rules" $?
printf '%s\n' "$l2" | grep -q 'log-only by default'
check "detect marks Layer-2 rules log-only" $?
printf '%s\n' "$l2" | grep -q 'does not arm it'
check "Layer-2 line states global mode does not arm it" $?
printf '%s\n' "$l2" | grep -q 'blocks nothing unless'
check "Layer-2 line states it blocks nothing unless opted in" $?
printf '%s\n' "$l2" | grep -qi 'default: block\|blocks by default'
[ $? -ne 0 ]; check "Layer-2 line never claims blocking by default" $?

# --- ini: risky php.ini settings report ---------------------------------------
# fake php whose `-i` prints $T/ini/<name>.txt; its php.ini is $T/ini/php.ini
mkdir -p "$T/ini/bin" "$T/ini/sess_ok" "$T/ini/sess_open"
chmod 700 "$T/ini/sess_ok"; chmod 755 "$T/ini/sess_open"
cat > "$T/ini/bin/php" <<'P'
#!/bin/sh
[ "$1" = "-i" ] && cat "$FAKE_INFO"
P
chmod +x "$T/ini/bin/php"
mkinfo() { # file, then extra "name => local => master" lines on stdin
  { printf 'PHP Version => 7.4.33\nLoaded Configuration File => %s\nScan this dir for additional .ini files => (none)\n' "$T/ini/php.ini"; cat; } > "$1"
}
ini_run() { FAKE_INFO=$1 sh "$HC" ini "$T/ini/bin/php" 2>&1; }

# hardened: nothing flagged
printf 'register_argc_argv = Off\ndisplay_errors = Off\n' > "$T/ini/php.ini"
mkinfo "$T/ini/clean.txt" <<EOF
allow_url_include => Off => Off
allow_url_fopen => On => On
session.upload_progress.enabled => Off => Off
session.save_handler => files => files
session.save_path => $T/ini/sess_ok => $T/ini/sess_ok
expose_php => Off => Off
enable_dl => Off => Off
cgi.fix_pathinfo => 0 => 0
disable_functions => exec,system,passthru,shell_exec,popen,proc_open => exec,system,passthru,shell_exec,popen,proc_open
open_basedir => no value => no value
EOF
out=$(ini_run "$T/ini/clean.txt"); rc=$?
eq "ini exits 0" "$rc" 0
printf '%s\n' "$out" | grep -q '^none flagged$'; check "ini: hardened config flags nothing" $?
printf '%s\n' "$out" | grep -q '^0 risky setting(s) flagged$'; check "ini: hardened config count is 0" $?
printf '%s\n' "$out" | grep -q '^info  allow_url_fopen = On'; check "ini: allow_url_fopen is informational only" $?
printf '%s\n' "$out" | grep -q '^FLAG  allow_url_fopen'
[ $? -ne 0 ]; check "ini: allow_url_fopen is never flagged" $?
printf '%s\n' "$out" | grep -q '^info  open_basedir is unset'; check "ini: open_basedir unset is informational" $?

# risky: everything flagged, with reason and fix
printf 'register_argc_argv = On\ndisplay_errors = 1 ; dev\n' > "$T/ini/php.ini"
mkinfo "$T/ini/risky.txt" <<EOF
allow_url_include => On => On
session.upload_progress.enabled => On => On
session.save_handler => files => files
session.save_path => $T/ini/sess_open => $T/ini/sess_open
expose_php => On => On
enable_dl => On => On
cgi.fix_pathinfo => 1 => 1
disable_functions => exec, system => exec, system
EOF
out=$(ini_run "$T/ini/risky.txt")
for s in register_argc_argv allow_url_include session.upload_progress.enabled session.save_path display_errors expose_php enable_dl cgi.fix_pathinfo disable_functions; do
  printf '%s\n' "$out" | grep -q "^FLAG  $s = "; check "ini: flags $s" $?
done
printf '%s\n' "$out" | grep -q 'CVE-2024-56145 and Laravel CVE-2024-52301'; check "ini: register_argc_argv names both CVEs" $?
printf '%s\n' "$out" | grep -q 'set: add passthru, shell_exec, popen, proc_open to disable_functions'; check "ini: disable_functions lists what is still enabled" $?
printf '%s\n' "$out" | grep -q '^9 risky setting(s) flagged$'; check "ini: risky count is 9" $?
printf '%s\n' "$out" | grep -c '^      why: ' | grep -q '^9$'; check "ini: every flagged line has a why" $?
printf '%s\n' "$out" | grep -c '^      set: ' | grep -q '^9$'; check "ini: every flagged line has a fix" $?

# docroot heuristic for session.save_path, and read-only: the ini file is untouched
sum1=$(cksum < "$T/ini/php.ini")
mkinfo "$T/ini/docroot.txt" <<EOF
session.save_handler => files => files
session.save_path => /home/u/public_html/sess => /home/u/public_html/sess
EOF
ini_run "$T/ini/docroot.txt" | grep -q 'under a web docroot'; check "ini: session.save_path under a docroot is flagged" $?
eq "ini: php.ini untouched" "$(cksum < "$T/ini/php.ini")" "$sum1"

sh "$HC" ini "$T/nonexistent-php" >/dev/null 2>&1; rc=$?; eq "ini with a missing php exits 2" "$rc" 2

[ $fail -eq 0 ] && echo "all passed"
exit $fail
