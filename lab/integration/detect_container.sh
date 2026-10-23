#!/bin/sh
# In-container half of the `howdah-check detect` integration test.
#
# Runs inside lab-php-7.3 (PHP 7.3 at /usr/local, NTS, API 20180731, cli+fpm)
# with a second, real PHP 7.4 tree (API 20190902) mounted at /opt/php74 and a
# real howdah.so built for 7.3 mounted at /h/howdah.so.
#
# Fixture:
#   PHP 7.3  howdah ENABLED via conf.d  -> cli + fpm must show loaded
#   PHP 7.4  howdah present but COMMENTED OUT in its php.ini -> not-loaded
#   /etc/php/8.0  config-only Debian-style dirs: howdah enabled for fpm only
#
# Asserts detect lists both real installs with the right API numbers, shows
# howdah loaded only where enabled, and modifies nothing (checksums + mtimes).
set -u

HC="${HC:-/src/tools/howdah-check}"
fails=0
ok()   { echo "  ok   - $1"; }
bad()  { echo "  FAIL - $1"; fails=$((fails + 1)); }

# ---- fixture ---------------------------------------------------------------
echo "extension=/h/howdah.so" > /usr/local/etc/php/conf.d/zz-howdah.ini

mkdir -p /opt/php74/etc/conf.d /opt/php74/ext
mv /opt/php74/bin/php /opt/php74/bin/php.real
mv /opt/php74/sbin/php-fpm /opt/php74/sbin/php-fpm.real
for w in bin/php sbin/php-fpm; do
  cat > "/opt/php74/$w" <<EOF
#!/bin/sh
LD_LIBRARY_PATH=/opt/php74/libx PHPRC=/opt/php74/etc PHP_INI_SCAN_DIR=/opt/php74/etc/conf.d exec /opt/php74/$w.real "\$@"
EOF
  chmod +x "/opt/php74/$w"
done
printf 'extension_dir=/opt/php74/ext\n;extension=/h/howdah.so\n' > /opt/php74/etc/php.ini

# Issue-1 fixture: a PHP 7.4 whose every invocation prints a startup warning BEFORE the banner.
# Issue-2 fixture: its prefix has a sibling UNVERSIONED php-fpm that is really 7.3 (must not be credited).
mkdir -p /opt/php74w/bin
cat > /opt/php74w/bin/php <<'EOF'
#!/bin/sh
echo "Warning:  Module already loaded in Unknown on line 0"
exec /opt/php74/bin/php "$@"
EOF
cat > /opt/php74w/bin/php-fpm <<'EOF'
#!/bin/sh
exec /usr/local/sbin/php-fpm "$@"
EOF
chmod +x /opt/php74w/bin/php /opt/php74w/bin/php-fpm

mkdir -p /etc/php/8.0/cli/conf.d /etc/php/8.0/fpm/conf.d /etc/php/8.0/apache2/conf.d
echo ';extension=howdah.so' > /etc/php/8.0/cli/conf.d/20-howdah.ini
echo 'extension=howdah.so'  > /etc/php/8.0/fpm/conf.d/20-howdah.ini

snap() {
  find /usr/local/etc /opt/php74/etc /opt/php74/ext /etc/php -type f -o -type d 2>/dev/null | sort |
    while read -r f; do stat -c '%n %s %Y %a' "$f"; [ -f "$f" ] && md5sum "$f"; done
}
/opt/php74/bin/php -v 2>&1 | head -2
snap > /tmp/before.txt

# ---- run -------------------------------------------------------------------
if [ ! -x "$HC" ]; then
  echo "FAIL: $HC missing or not executable"
  exit 1
fi
PATH="/opt/php74/bin:/opt/php74w/bin:$PATH"
OUT=$("$HC" detect 2>/tmp/detect.err); rc=$?
echo "$OUT"
echo "---- stderr ----"; cat /tmp/detect.err; echo "---- assertions ----"

[ "$rc" -eq 0 ] && ok "exit 0" || bad "exit status $rc"
[ ! -s /tmp/detect.err ] && ok "nothing on stderr" || bad "stderr not empty"

# block <php-path-or-version-pattern>: the lines of that install's block
block() { printf '%s\n' "$OUT" | awk -v pat="$1" '/^php:/{p=($0 ~ pat)} p'; }

B73=$(block 'php: /usr/local/bin/php$')
B74=$(block 'php: /opt/php74/bin/php$')
B74W=$(block 'php: /opt/php74w/bin/php$')
B80=$(block 'no runnable binary')

has() { printf '%s\n' "$1" | grep -Eq "$2"; }

has "$B73" 'version: 7\.3\.'                && ok "7.3 version"       || bad "7.3 version"
has "$B73" 'api: 20180731$'                 && ok "7.3 api 20180731"  || bad "7.3 api"
has "$B73" 'thread_safety: NTS'             && ok "7.3 NTS"           || bad "7.3 NTS"
has "$B73" 'extension_dir: .*20180731'      && ok "7.3 extension_dir" || bad "7.3 extension_dir"
has "$B73" 'sapi cli: present +howdah=loaded'  && ok "7.3 cli loaded"  || bad "7.3 cli loaded"
has "$B73" 'sapi fpm: present.*howdah=loaded'  && ok "7.3 fpm loaded"  || bad "7.3 fpm loaded"
has "$B73" 'sapi apache: absent'            && ok "7.3 apache absent" || bad "7.3 apache absent"

has "$B74" 'version: 7\.4\.'                && ok "7.4 version"       || bad "7.4 version"
has "$B74" 'api: 20190902$'                 && ok "7.4 api 20190902"  || bad "7.4 api"
has "$B74" 'thread_safety: NTS'             && ok "7.4 NTS"           || bad "7.4 NTS"
has "$B74" 'extension_dir: /opt/php74/ext$' && ok "7.4 extension_dir" || bad "7.4 extension_dir"
has "$B74" 'sapi cli: present +howdah=not-loaded' && ok "7.4 cli not loaded" || bad "7.4 cli not loaded"
has "$B74" 'sapi fpm: present.*howdah=not-loaded' && ok "7.4 fpm not loaded" || bad "7.4 fpm not loaded"

has "$B80" 'version: 8\.0'                       && ok "8.0 config-only listed" || bad "8.0 config-only listed"
has "$B80" 'sapi cli: .*howdah=not-loaded'       && ok "8.0 cli commented -> not loaded" || bad "8.0 cli"
has "$B80" 'sapi fpm: .*howdah=loaded'           && ok "8.0 fpm loaded" || bad "8.0 fpm"
has "$B80" 'sapi apache: .*howdah=not-loaded'    && ok "8.0 apache not loaded" || bad "8.0 apache"

has "$B74W" 'version: 7\.4\.'    && ok "warning-before-banner php still listed (7.4)" || bad "warning-before-banner php omitted"
has "$B74W" 'api: 20190902$'     && ok "warned php api 20190902" || bad "warned php api"
has "$B74W" 'sapi fpm: absent'   && ok "unversioned 7.3 php-fpm not credited to 7.4" || bad "7.3 fpm misattributed to 7.4"

n=$(printf '%s\n' "$OUT" | grep -c '^php:')
[ "$n" -eq 4 ] && ok "exactly 4 install blocks (7.3, 7.4, 7.4-warn, 8.0 config-only)" || bad "install blocks: $n"
[ "$(printf '%s\n' "$OUT" | grep -c 'howdah=loaded')" -eq 3 ] \
  && ok "howdah=loaded only 3x (7.3 cli, 7.3 fpm, 8.0 fpm)" || bad "unexpected loaded count"

# ---- degrade gracefully: no PHP at all ------------------------------------
EMPTY=$(PATH=/nonexistent HOWDAH_CHECK_ROOT=/nonexistent-root /bin/sh "$HC" detect 2>&1); erc=$?
[ "$erc" -eq 0 ] && has "$EMPTY" 'no PHP installs found' && ok "empty box handled" || bad "empty box: rc=$erc out=$EMPTY"

# ---- read-only -------------------------------------------------------------
snap > /tmp/after.txt
cmp -s /tmp/before.txt /tmp/after.txt && ok "read-only: config/ext trees byte+mtime identical" \
  || { bad "read-only violated"; diff /tmp/before.txt /tmp/after.txt | head; }

if [ "$fails" -eq 0 ]; then echo "PASS"; exit 0; fi
echo "$fails assertion(s) FAILED"; exit 1
