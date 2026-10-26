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
printf '%s\n' "$l2" | grep -q 'cgi_arg_injection.*enforced by default'
check "Layer-2 line names the one enforced-by-default rule, cgi_arg_injection" $?
l3=$(printf '%s\n' "$out" | grep '^note: layer 3')
printf '%s\n' "$l3" | grep -q 'are log-only by default'
check "Layer-3 line says the sinks are log-only by default" $?
printf '%s\n' "$l3" | grep -q 'xxe.*enforced by default'
check "Layer-3 line names the one enforced-by-default rule, xxe" $?
printf '%s\n' "$l3" | grep -q 'never blocks a bare DOCTYPE'
check "Layer-3 line says a bare DOCTYPE is never blocked" $?
printf '%s\n' "$l3" | grep -q 'ssrf.*all off by default.*rebind.*scheme.*redirect'
check "Layer-3 line names the opt-in SSRF hardening knobs (rebind, scheme, redirect) as off by default" $?
l4=$(printf '%s\n' "$out" | grep '^note: layer 4')
printf '%s\n' "$l4" | grep -q 'log-only by default'
check "Layer-4 line says the behaviour facets are log-only by default" $?
printf '%s\n' "$l4" | grep -q 'does not arm it'
check "Layer-4 line states global mode does not arm it" $?
printf '%s\n' "$l4" | grep -q 'file_delete.*enforced by default\|enforced by default.*file_delete'
check "Layer-4 line names the enforced-by-default delete guard, file_delete" $?
printf '%s\n' "$l4" | grep -q 'php_write.*move_uploaded_file'
check "Layer-4 line names the enforced-by-default upload tier of php_write" $?
printf '%s\n' "$l4" | grep -q 'secret_read.*opt-in'
check "Layer-4 line says secret_read is opt-in" $?

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

# --- detect: layout + the package (or tarball) Howdah provides, per install ---
# Fake vendor trees under $T: each fake php answers -v/-i/-m like the vendor's
# build would (paths in its -i output are the vendor's real ones).
# fake_php <root> <bin-path> <version> <api> <thread-safety> <extension_dir> <scan_dir>
fake_php() {
  _f="$1$2"; mkdir -p "$(dirname "$_f")"
  cat > "$_f" <<P
#!/bin/sh
case "\$1" in
  -v) echo "PHP $3 (cli)" ;;
  -i) printf '%s\n' 'PHP Version => $3' 'PHP API => $4' 'Thread Safety => $5' \
        'extension_dir => $6 => $6' 'Scan this dir for additional .ini files => $7' ;;
  -m) printf '[PHP Modules]\nCore\n' ;;
esac
P
  chmod +x "$_f"
}
# the detect lines of one install (from its "php:" line to the next install)
block() { printf '%s\n' "$1" | awk -v p="php: $2" '$0==p{on=1;print;next} /^(php: |found |no PHP|note: )/{on=0} on'; }
detect_in() { HOWDAH_CHECK_ROOT=$1 HOWDAH_CHECK_UNAME_M=${2:-x86_64} PATH=/nonexistent:/usr/bin:/bin sh "$HC" detect 2>/dev/null </dev/null; }
has() { printf '%s\n' "$1" | grep -qF -- "$2"; }  # fixed-string match

L=$T/layouts
deb() { mkdir -p "$1/etc"; echo 12.0 > "$1/etc/debian_version"; }
fake_php "$L/cpanel-rpm" /opt/cpanel/ea-php74/root/usr/bin/php 7.4.33 20190902 disabled \
  /opt/cpanel/ea-php74/root/usr/lib64/php/modules /opt/cpanel/ea-php74/root/etc/php.d
fake_php "$L/cpanel-deb" /opt/cpanel/ea-php74/root/usr/bin/php 7.4.33 20190902 disabled \
  /opt/cpanel/ea-php74/root/usr/lib64/php/modules /opt/cpanel/ea-php74/root/etc/php.d
deb "$L/cpanel-deb"
fake_php "$L/plesk-rpm" /opt/plesk/php/7.4/bin/php 7.4.33 20190902 disabled \
  /opt/plesk/php/7.4/lib64/php/modules /opt/plesk/php/7.4/etc/php.d
fake_php "$L/plesk-deb" /opt/plesk/php/7.4/bin/php 7.4.33 20190902 disabled \
  /opt/plesk/php/7.4/lib/php/modules /opt/plesk/php/7.4/etc/php.d
deb "$L/plesk-deb"
fake_php "$L/cloudlinux-rpm" /opt/alt/php74/usr/bin/php 7.4.33 20190902 disabled \
  /opt/alt/php74/usr/lib64/php/modules /opt/alt/php74/link/conf
fake_php "$L/stock-rhel-rpm" /usr/bin/php 7.4.33 20190902 disabled /usr/lib64/php/modules /etc/php.d
fake_php "$L/al2023" /usr/bin/php 8.2.35 20220829 disabled /usr/lib64/php8.2/modules /etc/php.d
fake_php "$L/directadmin" /usr/local/php74/bin/php 7.4.33 20190902 disabled \
  /usr/local/php74/lib/php/extensions/no-debug-non-zts-20190902 /usr/local/php74/lib/php.conf.d
fake_php "$L/stock-debian" /usr/bin/php7.4 7.4.33 20190902 disabled /usr/lib/php/20190902 /etc/php/7.4/cli/conf.d
deb "$L/stock-debian"
fake_php "$L/sury" /usr/bin/php7.4 7.4.33-1+ubuntu22.04.1+deb.sury.org+1 20190902 disabled \
  /usr/lib/php/20190902 /etc/php/7.4/cli/conf.d
deb "$L/sury"
fake_php "$L/remi" /opt/remi/php74/root/usr/bin/php 7.4.33 20190902 disabled \
  /opt/remi/php74/root/usr/lib64/php/modules /etc/opt/remi/php74/php.d
fake_php "$L/unknown" /opt/php81/bin/php 8.1.34 20210902 disabled \
  /opt/php81/lib/php/extensions/no-debug-non-zts-20210902 /opt/php81/etc/conf.d
fake_php "$L/zts" /opt/cpanel/ea-php74/root/usr/bin/php 7.4.33 20190902 enabled \
  /opt/cpanel/ea-php74/root/usr/lib64/php/modules /opt/cpanel/ea-php74/root/etc/php.d
PKG=https://pkg.howdah.org

b=$(block "$(detect_in "$L/cpanel-rpm")" "$L/cpanel-rpm/opt/cpanel/ea-php74/root/usr/bin/php")
for want in 'version: 7.4.33' 'api: 20190902' 'thread_safety: NTS' \
    'extension_dir: /opt/cpanel/ea-php74/root/usr/lib64/php/modules' \
    'ini_scan_dir: /opt/cpanel/ea-php74/root/etc/php.d' 'layout: cpanel' \
    "howdah package: ea-php74-php-howdah (yum/dnf repo $PKG/cpanel/yum)"; do
  has "$b" "  $want"; check "cpanel (EL) install reports '$want'" $?
done
b=$(block "$(detect_in "$L/cpanel-deb")" "$L/cpanel-deb/opt/cpanel/ea-php74/root/usr/bin/php")
has "$b" "  howdah package: ea-php74-php-howdah (apt repo $PKG/cpanel/apt, suite stable, component main)"
check "cpanel on Ubuntu points at the cpanel apt repo" $?
b=$(block "$(detect_in "$L/plesk-rpm")" "$L/plesk-rpm/opt/plesk/php/7.4/bin/php")
has "$b" '  layout: plesk' && has "$b" "  howdah package: plesk-php74-howdah (yum/dnf repo $PKG/plesk/yum)"
check "plesk (EL) layout + package" $?
b=$(block "$(detect_in "$L/plesk-deb")" "$L/plesk-deb/opt/plesk/php/7.4/bin/php")
has "$b" '  layout: plesk' && has "$b" "  howdah package: plesk-php74-howdah (apt repo $PKG/plesk/apt, suite stable, component main)"
check "plesk (Debian/Ubuntu) layout + package" $?
b=$(block "$(detect_in "$L/cloudlinux-rpm")" "$L/cloudlinux-rpm/opt/alt/php74/usr/bin/php")
has "$b" '  layout: cloudlinux' && has "$b" "  howdah package: alt-php74-howdah (yum/dnf repo $PKG/cloudlinux/yum)"
check "cloudlinux layout + package" $?
b=$(block "$(detect_in "$L/stock-rhel-rpm")" "$L/stock-rhel-rpm/usr/bin/php")
has "$b" '  layout: stock-rhel' && has "$b" "  howdah package: php-howdah (yum/dnf repo $PKG/el/php7.4/yum)"
check "stock RHEL/Alma/Rocky layout + per-minor el repo" $?
b=$(block "$(detect_in "$L/al2023")" "$L/al2023/usr/bin/php")
has "$b" '  layout: stock-rhel' && has "$b" "  howdah package: php-howdah (yum/dnf repo $PKG/el/php8.2/yum)"
check "Amazon Linux 2023 (/usr/lib64/php8.2/modules) is stock-rhel" $?
b=$(block "$(detect_in "$L/directadmin")" "$L/directadmin/usr/local/php74/bin/php")
has "$b" '  layout: directadmin' && \
  has "$b" '  howdah package: not yet packaged: use the tarball for API 20190902 (howdah-<VERSION>-php7.4-20190902-linux-x86_64.tar.gz)'
check "directadmin: tarball, not a package" $?
b=$(block "$(detect_in "$L/stock-debian")" "$L/stock-debian/usr/bin/php7.4")
has "$b" '  layout: stock-debian' && has "$b" "  howdah package: php7.4-howdah (apt repo $PKG/apt, suite stable, component main)"
check "stock Debian/Ubuntu PHP uses the main apt package" $?
b=$(block "$(detect_in "$L/sury")" "$L/sury/usr/bin/php7.4")
has "$b" '  layout: sury' && has "$b" "  howdah package: php7.4-howdah (apt repo $PKG/apt, suite stable, component main)"
check "Sury PHP layout + package" $?
b=$(block "$(detect_in "$L/remi")" "$L/remi/opt/remi/php74/root/usr/bin/php")
has "$b" '  layout: remi' && has "$b" "  howdah package: php74-howdah (yum/dnf repo $PKG/yum)"
check "Remi SCL layout + package" $?
b=$(block "$(detect_in "$L/unknown")" "$L/unknown/opt/php81/bin/php")
has "$b" '  layout: unknown' && \
  has "$b" '  howdah package: not yet packaged: use the tarball for API 20210902 (howdah-<VERSION>-php8.1-20210902-linux-x86_64.tar.gz)'
check "unknown layout falls back to the tarball" $?
b=$(block "$(detect_in "$L/zts")" "$L/zts/opt/cpanel/ea-php74/root/usr/bin/php")
has "$b" '  howdah package: none: Howdah is built for NTS PHP only and this PHP is ZTS'
check "ZTS PHP is never offered a package" $?
b=$(block "$(detect_in "$L/cpanel-rpm" aarch64)" "$L/cpanel-rpm/opt/cpanel/ea-php74/root/usr/bin/php")
has "$b" '  howdah package: not yet packaged for aarch64: use the tarball for API 20190902 (howdah-<VERSION>-php7.4-20190902-linux-aarch64.tar.gz)'
check "a layout with no aarch64 package says so on aarch64" $?

# --- detect: Docker images, Alpine (musl), LiteSpeed lsphp ---------------------
# the official php images keep PHP in /usr/local with PHP_INI_DIR=/usr/local/etc/php
fake_php "$L/docker" /usr/local/bin/php 8.3.36 20230831 disabled \
  /usr/local/lib/php/extensions/no-debug-non-zts-20230831 /usr/local/etc/php/conf.d
deb "$L/docker"
out=$(detect_in "$L/docker")
has "$out" 'host libc: glibc'; check "glibc host says so" $?
b=$(block "$out" "$L/docker/usr/local/bin/php")
has "$b" '  matching release asset: howdah-<VERSION>-php8.3-20230831-linux-x86_64.tar.gz' && has "$b" '  layout: docker' && \
  has "$b" '  howdah package: image ghcr.io/howdah/howdah:<VERSION>-php8.3, or in your Dockerfile: COPY --from=ghcr.io/howdah/howdah:<VERSION>-php8.3 /howdah/ /'
check "official Docker php image: docker layout, the image and the COPY --from line" $?
fake_php "$L/alpine" /usr/local/bin/php 8.3.36 20230831 disabled \
  /usr/local/lib/php/extensions/no-debug-non-zts-20230831 /usr/local/etc/php/conf.d
mkdir -p "$L/alpine/lib"; : > "$L/alpine/lib/ld-musl-x86_64.so.1"
out=$(detect_in "$L/alpine")
has "$out" 'host libc: musl'; check "musl host says so" $?
b=$(block "$out" "$L/alpine/usr/local/bin/php")
has "$b" '  matching release asset: howdah-<VERSION>-php8.3-20230831-linux-x86_64-musl.tar.gz'
check "musl host: the -musl tarball" $?
has "$b" '  howdah package: image ghcr.io/howdah/howdah:<VERSION>-php8.3-alpine, or in your Dockerfile: COPY --from=ghcr.io/howdah/howdah:<VERSION>-php8.3-alpine /howdah/ /'
check "official Alpine php image: the -alpine image" $?
mkdir -p "$L/alpine-arm/lib"; cp -R "$L/alpine/usr" "$L/alpine-arm/"; : > "$L/alpine-arm/lib/ld-musl-aarch64.so.1"
b=$(block "$(detect_in "$L/alpine-arm" aarch64)" "$L/alpine-arm/usr/local/bin/php")
has "$b" '  matching release asset: none: musl builds are x86_64 only' && \
  has "$b" '  howdah package: none: musl builds are x86_64 only'
check "aarch64 musl: no asset, no image (never a glibc tarball)" $?
# musl's loader prints its version when run with no arguments (exit 1)
fake_musl() { # <root> <version>
  mkdir -p "$1/lib"
  printf '#!/bin/sh\nprintf "musl libc (x86_64)\\nVersion %s\\nDynamic Program Loader\\n" >&2\nexit 1\n' "$2" > "$1/lib/ld-musl-x86_64.so.1"
  chmod +x "$1/lib/ld-musl-x86_64.so.1"
}
# php:7.1-fpm-alpine: Alpine 3.10, musl 1.1.22 (older than the musl build's 1.1.24 floor)
fake_php "$L/alpine71" /usr/local/bin/php 7.1.33 20160303 disabled \
  /usr/local/lib/php/extensions/no-debug-non-zts-20160303 /usr/local/etc/php/conf.d
fake_musl "$L/alpine71" 1.1.22
out=$(detect_in "$L/alpine71")
has "$out" 'host libc: musl 1.1.22'; check "musl host prints the musl version" $?
b=$(block "$out" "$L/alpine71/usr/local/bin/php")
has "$b" "  matching release asset: none: Howdah's musl build needs musl 1.1.24 or newer (Alpine 3.11+); this is musl 1.1.22"
check "musl older than 1.1.24: no tarball offered (it would not load)" $?
has "$b" '  howdah package: no -alpine image for PHP 7.1 (its Alpine base has musl older than 1.1.24): use the Debian image ghcr.io/howdah/howdah:<VERSION>-php7.1'
check "php:7.1-fpm-alpine: pointed at the Debian image" $?
# the same minor with an unreadable musl version: still no -alpine image for 7.1
fake_php "$L/alpine70" /usr/local/bin/php 7.0.33 20151012 disabled \
  /usr/local/lib/php/extensions/no-debug-non-zts-20151012 /usr/local/etc/php/conf.d
mkdir -p "$L/alpine70/lib"; : > "$L/alpine70/lib/ld-musl-x86_64.so.1"
b=$(block "$(detect_in "$L/alpine70")" "$L/alpine70/usr/local/bin/php")
has "$b" '  howdah package: no -alpine image for PHP 7.0 (its Alpine base has musl older than 1.1.24): use the Debian image ghcr.io/howdah/howdah:<VERSION>-php7.0'
check "no -alpine image for 7.0 even when the musl version is unknown" $?
# a current Alpine: version shown, -alpine image offered
fake_php "$L/alpine83" /usr/local/bin/php 8.3.36 20230831 disabled \
  /usr/local/lib/php/extensions/no-debug-non-zts-20230831 /usr/local/etc/php/conf.d
fake_musl "$L/alpine83" 1.2.5
out=$(detect_in "$L/alpine83")
has "$out" 'host libc: musl 1.2.5' && \
  has "$(block "$out" "$L/alpine83/usr/local/bin/php")" '  matching release asset: howdah-<VERSION>-php8.3-20230831-linux-x86_64-musl.tar.gz'
check "musl 1.2.5: version shown, the -musl tarball offered" $?
# Alpine apk PHP on musl 1.1.22 (Alpine 3.10): no tarball, no package
fake_php "$L/apk-old" /usr/bin/php7 7.3.33 20180731 disabled /usr/lib/php7/modules /etc/php7/conf.d
fake_musl "$L/apk-old" 1.1.22
b=$(block "$(detect_in "$L/apk-old")" "$L/apk-old/usr/bin/php7")
has "$b" "  howdah package: none: Howdah's musl build needs musl 1.1.24 or newer (Alpine 3.11+); this is musl 1.1.22"
check "apk PHP on musl 1.1.22: nothing offered" $?
fake_php "$L/docker54" /usr/local/bin/php 5.4.45 20100525 disabled \
  /usr/local/lib/php/extensions/no-debug-non-zts-20100525 /usr/local/etc/php/conf.d
b=$(block "$(detect_in "$L/docker54")" "$L/docker54/usr/local/bin/php")
has "$b" '  layout: docker' && \
  has "$b" '  howdah package: no image for PHP 5.4: use the tarball for API 20100525 (howdah-<VERSION>-php5.4-20100525-linux-x86_64.tar.gz)'
check "docker layout for a minor with no image falls back to the tarball" $?
# Alpine's own PHP (apk add php83): /usr/lib/php83/modules + /etc/php83/conf.d
fake_php "$L/alpine-apk" /usr/bin/php83 8.3.36 20230831 disabled /usr/lib/php83/modules /etc/php83/conf.d
mkdir -p "$L/alpine-apk/lib"; : > "$L/alpine-apk/lib/ld-musl-x86_64.so.1"
b=$(block "$(detect_in "$L/alpine-apk")" "$L/alpine-apk/usr/bin/php83")
has "$b" '  layout: alpine' && \
  has "$b" '  howdah package: not yet packaged for musl: use the tarball for API 20230831 (howdah-<VERSION>-php8.3-20230831-linux-x86_64-musl.tar.gz)'
check "Alpine apk PHP: alpine layout, the musl tarball" $?
fake_php "$L/litespeed" /usr/local/lsws/lsphp83/bin/php 8.3.36 20230831 disabled \
  /usr/local/lsws/lsphp83/lib/php/20230831 /usr/local/lsws/lsphp83/etc/php/8.3/mods-available/
deb "$L/litespeed"
b=$(block "$(detect_in "$L/litespeed")" "$L/litespeed/usr/local/lsws/lsphp83/bin/php")
has "$b" '  layout: litespeed' && \
  has "$b" '  howdah package: not yet packaged: use the tarball for API 20230831 (howdah-<VERSION>-php8.3-20230831-linux-x86_64.tar.gz)'
check "LiteSpeed lsphp: litespeed layout, tarball" $?

# The packaging table and detect agree: every row of packaging/layouts.tsv, for
# PHP 7.4, is the package + repo detect names for that layout and format.
TSV=$D/../packaging/layouts.tsv
TAB=$(printf '\t')
rows=0
while IFS=$TAB read -r lay fmt arches pkg rel moddir ext inis reqs repo label; do
  case "$lay" in ''|'#'*) continue ;; esac
  rows=$((rows + 1))
  name=$(printf '%s' "$pkg" | sed -e 's/@XY@/74/g' -e 's/@MINOR@/7.4/g')
  rp=$(printf '%s' "$repo" | sed -e 's/@MINOR@/7.4/g')
  if [ "$fmt" = deb ]; then want="$name (apt repo $PKG/$rp/apt, suite stable, component main)"
  else want="$name (yum/dnf repo $PKG/$rp/yum)"; fi
  r=$L/$lay-$fmt
  bin=$(cd "$r" && find . -type f -name php | head -1 | sed 's/^\.//')
  out=$(detect_in "$r")
  has "$(block "$out" "$r$bin")" "  howdah package: $want"
  check "layouts.tsv row $lay/$fmt matches detect ($want)" $?
  # a row's mod dir is the vendor extension_dir detect classifies (minor 7.4)
  md=$(printf '%s' "$moddir" | sed -e 's/@XY@/74/g' -e 's/@MINOR@/7.4/g')
  has "$(block "$out" "$r$bin")" "  extension_dir: $md"
  check "layouts.tsv row $lay/$fmt moddir is the fake vendor extension_dir" $?
  case ",$arches," in
    *,aarch64,*) ;;
    *) has "$(block "$(detect_in "$r" aarch64)" "$r$bin")" '  howdah package: not yet packaged for aarch64'
       check "layouts.tsv row $lay/$fmt (x86_64 only) is not offered on aarch64" $? ;;
  esac
done < "$TSV"
[ "$rows" -ge 6 ]; check "layouts.tsv has the panel and stock-EL rows ($rows)" $?

[ $fail -eq 0 ] && echo "all passed"
exit $fail
