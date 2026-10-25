#!/bin/sh
# Apache mod_php (prefork) half of the out-of-memory backstop lab (see
# oom_backstop.sh). Runs inside a howdah-dev-apache-php<ver> image. Prefork has
# several children, so instead of a single worker pid this checks that the
# out-of-memory request does NOT complete, that an out_of_memory block line is
# logged (the backstop fired), and that Apache keeps serving afterwards. A
# warning must not fire the backstop. On a patched engine the backstop stays off.
#
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows-ap.tsv}"
WORK=/tmp/oom-ap; LOG="$WORK/events.log"; MARKD=/tmp/howdah-marker; MARK="$MARKD/ran"
DOCROOT=/var/www/html; URL=http://127.0.0.1
APLOG=/tmp/apache-error.log
mkdir -p "$WORK" "$MARKD" "$DOCROOT"; : > "$LOG"; : > "$RESULTS"
chmod 777 "$WORK" "$MARKD"; chmod 666 "$LOG"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=apache
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$1" "$2" "$3" "$4" >> "$RESULTS"; echo "  [$PHPVER $1] $2 $3: $4" >&2; }

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/t}"
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2; record $S build FAIL "cargo build failed"; exit 1; fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

cat > "$DOCROOT/index.php" <<'PHP'
<?php echo "OK pid=", getmypid(), "\n";
PHP
cat > "$DOCROOT/oom.php" <<'PHP'
<?php $a = array(); while (true) { $a[] = str_repeat('x', 1048576); }
PHP
cat > "$DOCROOT/warn.php" <<'PHP'
<?php @trigger_error('a user warning', E_USER_WARNING); echo "OK pid=", getmypid(), "\n";
PHP
cat > "$DOCROOT/info.php" <<'PHP'
<?php ob_start(); phpinfo(INFO_MODULES); $h = ob_get_clean();
if (preg_match('/OOM backstop[^<]*<\/td>\s*<td[^>]*>([^<]*)/', $h, $m)) echo "OOMROW:", trim($m[1]);
else echo "OOMROW:MISSING";
PHP

if php -r 'exit(ini_get("memory_hard_limit_percent") === false ? 1 : 0);'; then PATCHED=yes; else PATCHED=no; fi

CONFD=$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;' 2>/dev/null); [ -z "$CONFD" ] && CONFD=/usr/local/etc/php/conf.d
mkdir -p "$CONFD"
{ echo "extension=$WORK/howdah.so"; echo "howdah.log=$LOG"; echo "memory_limit=32M"
  echo "display_errors=0"; echo "log_errors=1"; } > "$CONFD/zz-howdah.ini"
sed -i "s#^ErrorLog .*#ErrorLog $APLOG#" /etc/apache2/apache2.conf 2>/dev/null || true
: > "$APLOG"
AP=apache2ctl; command -v apache2ctl >/dev/null 2>&1 || AP=apachectl
ap_start() { $AP start 2>"$WORK/ap.err"; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "apache down" >&2; cat "$WORK/ap.err" >&2; return 1; }; sleep 0.1; done; }
ap_stop() { $AP stop 2>/dev/null; _j=0; while curl -s -m 1 -o /dev/null "$URL/" 2>/dev/null; do _j=$((_j+1)); [ "$_j" -gt 60 ] && break; sleep 0.1; done; }

B="$WORK/resp.txt"
get()     { curl -s -m 30 -o "$B" -w '%{http_code}' "$URL$1" 2>/dev/null || echo 000; }
oom_req() { curl -s -m 60 -o "$B" -w '%{http_code}' "$URL/oom.php" 2>/dev/null || echo 000; }
oom_row() { get /info.php >/dev/null; sed -n 's/.*OOMROW:\(.*\)/\1/p' "$B" | head -1; }
reset()   { : > "$LOG"; }

ap_start || { record $S ap_start FAIL "apache down"; exit 1; }
ROW=$(oom_row)

if [ "$PATCHED" = no ]; then
  case "$ROW" in armed*) record $S phpinfo_armed PASS "row: $ROW" ;; *) record $S phpinfo_armed FAIL "row: $ROW" ;; esac

  reset; c=$(get /warn.php)
  if [ "$c" = 200 ] && ! grep -qE '"rule":"(out_of_memory|startup_fatal)"' "$LOG"; then
    record $S warning_survives PASS "http=200, no backstop line, server serving"
  else record $S warning_survives FAIL "http=$c log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi

  reset; c=$(oom_req)
  if [ "$c" = 200 ]; then
    record $S oom_exits FAIL "oom request returned 200 (no out-of-memory?)"
  elif ! grep -q '"rule":"out_of_memory"' "$LOG" || ! grep -q '"action":"block"' "$LOG"; then
    record $S oom_exits FAIL "http=$c but no out_of_memory block line ($(tr -d '\n' < "$LOG" | head -c 160))"
  else
    A=$(get /)
    if [ "$A" = 200 ]; then record $S oom_exits PASS "oom http=$c, out_of_memory block logged, Apache still serves (follow-up 200)"
    else record $S oom_exits FAIL "follow-up http=$A (Apache did not recover)"; fi
  fi
else
  case "$ROW" in "off (patched"*) record $S phpinfo_off_patched PASS "row: $ROW" ;; *) record $S phpinfo_off_patched FAIL "row: $ROW" ;; esac
  reset; c=$(oom_req); A=$(get /)
  if ! grep -q '"rule":"out_of_memory"' "$LOG" && [ "$A" = 200 ]; then
    record $S oom_patched_off PASS "patched engine: no backstop line, Apache serves (http=$c, follow-up 200)"
  else record $S oom_patched_off FAIL "http=$c follow-up=$A log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi
  record $S oom_exits NOT-RUN "engine is patched; the backstop is correctly off here"
fi
ap_stop
echo "== [$PHPVER] apache rows done ==" >&2
