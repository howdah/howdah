#!/bin/sh
# Tests for packaging/build-layouts.sh rendering (no docker, no packages built):
# renders every packaging/layouts.tsv row for PHP 7.4 from a stub release
# tarball and checks the generated spec/control/ini files.
# Run from anywhere:  sh packaging/layouts.test.sh   (needs bash; POSIX sh driver)
D=$(cd "$(dirname "$0")" && pwd)
B=$D/build-layouts.sh
T=$(mktemp -d) || exit 2
trap 'rm -rf "$T"' EXIT
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }
check() { if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi; }
has() { grep -qxF -- "$2" "$1" 2>/dev/null; }   # whole-line, fixed string

# stub release tarball: the real howdah.ini, a placeholder .so (render mode
# never inspects it)
mk_tarball() { # <arch>
  _r=$T/src-$1/howdah-9.9.9-php7.4; mkdir -p "$_r"
  cp "$D/howdah.ini" "$_r/howdah.ini"; echo stub > "$_r/howdah.so"
  tar -C "$T/src-$1" -czf "$T/howdah-9.9.9-php7.4-20190902-linux-$1.tar.gz" howdah-9.9.9-php7.4
  printf '%s\n' "$T/howdah-9.9.9-php7.4-20190902-linux-$1.tar.gz"
}
render() { # <arch> <outdir>
  HOWDAH_VERSION=9.9.9 HOWDAH_LAYOUT_RENDER=$2 bash "$B" 7.4 "$1" "$(mk_tarball "$1")" >/dev/null 2>&1
}

R=$T/x86; render x86_64 "$R"; check "render x86_64 exits 0" $?
A=$T/arm; render aarch64 "$A"; check "render aarch64 exits 0" $?

# every row renders where its arches say, at the repo path it publishes to
for p in cpanel/yum/ea-php74-php-howdah cpanel/apt/ea-php74-php-howdah plesk/yum/plesk-php74-howdah \
         plesk/apt/plesk-php74-howdah cloudlinux/yum/alt-php74-howdah el/php7.4/yum/php-howdah; do
  [ -d "$R/$p" ]; check "x86_64 renders $p" $?
done
n=$(find "$A" -name howdah.ini | wc -l | tr -d ' ')
[ "$n" = 2 ] && [ -d "$A/plesk/apt/plesk-php74-howdah" ] && [ -d "$A/el/php7.4/yum/php-howdah" ]
check "aarch64 renders only the rows that list aarch64 (plesk deb, stock EL)" $?

# no token is left unrendered
! grep -rn '@[A-Z_][A-Z_]*@' "$R" "$A" >/dev/null; check "no @TOKEN@ left in any rendered file" $?

# the ini is the shipped howdah.ini byte for byte, except stock EL's absolute load line
for f in $(find "$R" -name howdah.ini | grep -v '/el/'); do
  cmp -s "$f" "$D/howdah.ini"; check "ini identical to packaging/howdah.ini: ${f#$R/}" $?
done
E=$R/el/php7.4/yum/php-howdah
diff "$D/howdah.ini" "$E/howdah.ini" | grep '^[<>]' > "$T/eldiff"
[ "$(cat "$T/eldiff")" = "< extension=howdah.so
> extension=/usr/lib64/php/modules/howdah.so" ]
check "stock EL ini loads the .so by absolute path (Amazon Linux's extension_dir differs)" $?

# rpm specs: name, release, ABI guard, paths, config(noreplace) drop-ins
S=$R/cpanel/yum/ea-php74-php-howdah/howdah.spec
has "$S" 'Name:           ea-php74-php-howdah' && has "$S" 'Release:        1' \
  && has "$S" 'Requires:       ea-php74-php-common' \
  && has "$S" '%global moddir /opt/cpanel/ea-php74/root/usr/lib64/php/modules' \
  && has "$S" 'install -D -m 0644 %{SOURCE1} %{buildroot}/opt/cpanel/ea-php74/root/etc/php.d/20-howdah.ini' \
  && has "$S" '%config(noreplace) /opt/cpanel/ea-php74/root/etc/php.d/20-howdah.ini'
check "cpanel spec: name, requires, EA4 module dir, 20-howdah.ini" $?
S=$R/plesk/yum/plesk-php74-howdah/howdah.spec
has "$S" 'Requires:       plesk-php74' && has "$S" '%global moddir /opt/plesk/php/7.4/lib64/php/modules' \
  && has "$S" '%config(noreplace) /opt/plesk/php/7.4/etc/php.d/howdah.ini'
check "plesk spec: requires plesk-php74, lib64 module dir, php.d/howdah.ini" $?
S=$R/cloudlinux/yum/alt-php74-howdah/howdah.spec
has "$S" 'Requires:       alt-php74' && has "$S" '%global moddir /opt/alt/php74/usr/lib64/php/modules' \
  && has "$S" '%config(noreplace) /opt/alt/php74/etc/php.d.all/howdah.ini' \
  && has "$S" '%config(noreplace) /opt/alt/php74/etc/php.d.std/howdah.ini'
check "cloudlinux spec: requires alt-php74, php.d.all + php.d.std drop-ins" $?
S=$E/howdah.spec
has "$S" 'Name:           php-howdah' && has "$S" 'Release:        1.php74' \
  && has "$S" 'Requires:       php(zend-abi) = 20190902-64' \
  && has "$S" '%config(noreplace) /etc/php.d/40-howdah.ini'
check "stock EL spec: php-howdah, per-minor release tag, exact zend-abi guard" $?
for s in $(find "$R" "$A" -name howdah.spec); do
  ! grep -qE '^%(pre|post|preun|postun)\b' "$s"; check "no scriptlets: ${s#$T/}" $?
done

# deb control files
C=$R/plesk/apt/plesk-php74-howdah
has "$C/control" 'Package: plesk-php74-howdah' && has "$C/control" 'Version: 9.9.9-1' \
  && has "$C/control" 'Architecture: amd64' && has "$C/control" 'Depends: plesk-php74' \
  && has "$C/conffiles" '/opt/plesk/php/7.4/etc/php.d/howdah.ini' \
  && has "$C/files" './opt/plesk/php/7.4/lib/php/modules/howdah.so'
check "plesk deb: control, conffile, lib/php/modules (not lib64) on Debian" $?
has "$A/plesk/apt/plesk-php74-howdah/control" 'Architecture: arm64'
check "plesk deb on aarch64 is Architecture: arm64" $?
C=$R/cpanel/apt/ea-php74-php-howdah
has "$C/control" 'Depends: ea-php74-php-common' \
  && has "$C/files" './opt/cpanel/ea-php74/root/usr/lib64/php/modules/howdah.so' \
  && has "$C/conffiles" '/opt/cpanel/ea-php74/root/etc/php.d/20-howdah.ini'
check "cpanel deb (Ubuntu): depends, lib64 module dir (as EA4 ships it), conffile" $?

# a filter limits the rows
F=$T/only; HOWDAH_VERSION=9.9.9 HOWDAH_LAYOUTS=cloudlinux HOWDAH_LAYOUT_RENDER=$F \
  bash "$B" 7.4 x86_64 "$T/howdah-9.9.9-php7.4-20190902-linux-x86_64.tar.gz" >/dev/null 2>&1
[ "$(find "$F" -name howdah.ini | wc -l | tr -d ' ')" = 1 ] && [ -d "$F/cloudlinux" ]
check "HOWDAH_LAYOUTS=cloudlinux renders only that layout" $?

# the shipped ini must keep exactly one plain load line, or the build refuses
mkdir -p "$T/bad/howdah-9.9.9-php7.4"; echo stub > "$T/bad/howdah-9.9.9-php7.4/howdah.so"
sed 's/^extension=howdah\.so$/extension = howdah.so/' "$D/howdah.ini" > "$T/bad/howdah-9.9.9-php7.4/howdah.ini"
tar -C "$T/bad" -czf "$T/bad/howdah-9.9.9-php7.4-20190902-linux-x86_64.tar.gz" howdah-9.9.9-php7.4
HOWDAH_VERSION=9.9.9 HOWDAH_LAYOUT_RENDER=$T/badout bash "$B" 7.4 x86_64 \
  "$T/bad/howdah-9.9.9-php7.4-20190902-linux-x86_64.tar.gz" >/dev/null 2>&1
[ $? -ne 0 ]; check "build refuses an ini without exactly one 'extension=howdah.so' line" $?

[ $fail -eq 0 ] && echo "all passed"
exit $fail
