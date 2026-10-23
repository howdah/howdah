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

[ $fail -eq 0 ] && echo "all passed"
exit $fail
