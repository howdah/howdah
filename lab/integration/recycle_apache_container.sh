#!/bin/sh
# Apache mod_php (prefork) half of the §4.7 recycle-facet lab (see recycle.sh).
# Runs inside a howdah-dev-apache-php<ver> image. Prefork is pinned to ONE child
# (ServerLimit/MaxRequestWorkers 1, MaxConnectionsPerChild 0, KeepAlive Off) so
# getmypid() is a stable per-worker identity, exactly like the one fpm worker:
# an enforced recycle makes the parent fork a fresh child, so the pid CHANGES on
# the next request. This is the Apache mod_php arm of the design §5.6 bed.
#
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows-ap.tsv}"
WORK=/tmp/rec-ap; LOG="$WORK/events.log"; MARKD=/tmp/howdah-marker; MARK="$MARKD/ran"
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
  tail -12 "$WORK/build.err" >&2; record $S build FAIL "cargo build failed"; exit 1; fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

cat > "$DOCROOT/index.php" <<'PHP'
<?php echo "OK pid=", getmypid(), "\n";
PHP
cat > "$DOCROOT/fatal.php" <<'PHP'
<?php throw new RuntimeException('poisoning-class fatal for the recycle lab');
PHP
cat > "$DOCROOT/broken.inc" <<'PHP'
<?php function (  {
PHP
cat > "$DOCROOT/parse.php" <<'PHP'
<?php require __DIR__ . '/broken.inc'; echo "unreachable\n";
PHP
cat > "$DOCROOT/require.php" <<'PHP'
<?php require __DIR__ . '/does-not-exist-' . getmypid() . '.php'; echo "unreachable\n";
PHP
cat > "$DOCROOT/oom.php" <<'PHP'
<?php $a = array(); while (true) { $a[] = str_repeat('x', 1048576); }
PHP
cat > "$DOCROOT/warn.php" <<'PHP'
<?php @trigger_error('a user warning', E_USER_WARNING); echo "OK pid=", getmypid(), "\n";
PHP
cat > "$DOCROOT/info.php" <<'PHP'
<?php ob_start(); phpinfo(INFO_MODULES); $h = ob_get_clean();
if (preg_match('/Recycle after fatal[^<]*<\/td>\s*<td[^>]*>([^<]*)/', $h, $m)) echo "RECROW:", trim($m[1]);
else echo "RECROW:MISSING";
PHP

if php -r 'exit(ini_get("memory_hard_limit_percent") === false ? 1 : 0);'; then PATCHED=yes; else PATCHED=no; fi

CONFD=$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;' 2>/dev/null); [ -z "$CONFD" ] && CONFD=/usr/local/etc/php/conf.d
mkdir -p "$CONFD"
writeini() { # $1 = extra howdah.config line (may be empty)
  { echo "extension=$WORK/howdah.so"; echo "howdah.log=$LOG"; echo "memory_limit=64M"
    echo "max_execution_time=30"; echo "display_errors=0"; echo "log_errors=1"
    [ -n "$1" ] && echo "howdah.config=$1"; } > "$CONFD/zz-howdah.ini"
}
# Pin prefork to a single, non-recycling child so getmypid() is stable.
MPMCONF=/etc/apache2/conf-enabled/zz-recycle.conf
[ -d /etc/apache2/conf-enabled ] || MPMCONF=/etc/apache2/apache2.conf
{
  echo 'KeepAlive Off'
  echo '<IfModule mpm_prefork_module>'
  echo '  StartServers 1'
  echo '  MinSpareServers 1'
  echo '  MaxSpareServers 1'
  echo '  ServerLimit 1'
  echo '  MaxRequestWorkers 1'
  echo '  MaxConnectionsPerChild 0'
  echo '</IfModule>'
} >> "$MPMCONF"
sed -i "s#^ErrorLog .*#ErrorLog $APLOG#" /etc/apache2/apache2.conf 2>/dev/null || true
: > "$APLOG"
AP=apache2ctl; command -v apache2ctl >/dev/null 2>&1 || AP=apachectl
ap_start() { $AP start 2>"$WORK/ap.err"; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "apache down" >&2; cat "$WORK/ap.err" >&2; return 1; }; sleep 0.1; done; }
ap_stop() { $AP stop 2>/dev/null; _j=0; while curl -s -m 1 -o /dev/null "$URL/" 2>/dev/null; do _j=$((_j+1)); [ "$_j" -gt 60 ] && break; sleep 0.1; done; }
ap_restart() { ap_stop; ap_start; }

B="$WORK/resp.txt"
get()     { curl -s -m 30 -o "$B" -w '%{http_code}' "$URL$1" 2>/dev/null || echo 000; }
pid_now() { _p=""; _k=0; while [ -z "$_p" ] && [ "$_k" -lt 50 ]; do get / >/dev/null; _p=$(sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' "$B" | head -1); [ -z "$_p" ] && sleep 0.1; _k=$((_k+1)); done; echo "$_p"; }
rec_row() { get /info.php >/dev/null; sed -n 's/.*RECROW:\(.*\)/\1/p' "$B" | head -1; }
reset()   { : > "$LOG"; }
has()     { grep -q "$1" "$LOG"; }

printf 'recycle_on_fatal = true\n' > "$WORK/enforce.toml"
printf 'recycle_on_fatal = true\nrecycle_observe = true\n' > "$WORK/observe.toml"
printf 'mode = "block"\n' > "$WORK/off.toml"

writeini ""   # a startable baseline before the first per-mode restart
ap_start || { record $S ap_start FAIL "apache down"; exit 1; }

if [ "$PATCHED" = yes ]; then
  writeini "$WORK/enforce.toml"; ap_restart
  case "$(rec_row)" in "off (patched"*) record $S phpinfo_off_patched PASS "row: $(rec_row)" ;; *) record $S phpinfo_off_patched FAIL "row: $(rec_row)" ;; esac
  reset; P0=$(pid_now); reset; c=$(get /fatal.php); P1=$(pid_now)
  if ! has '"rule":"fatal_recycle"' && [ "$P1" = "$P0" ]; then
    record $S recycle_patched_off PASS "patched: PHP's own behavior (http=$c), child pid $P0 unchanged, no fatal_recycle line"
  else record $S recycle_patched_off FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 160)"; fi
  for sc in phpinfo_observe observe_no_exit phpinfo_enforce enforce_recycles_fatal producing_500_delivery oom_still_exits warning_survives; do
    record $S "$sc" NOT-RUN "engine is patched; the recycle facet is correctly off here"
  done
  ap_stop; echo "== [$PHPVER] apache rows done (patched) ==" >&2; exit 0
fi

# OFF control: PHP's own status for an uncaught fatal (facet off by default).
writeini ""; ap_restart
reset; P0=$(pid_now); reset; PHPSTATUS=$(get /fatal.php); P1=$(pid_now)
if ! has '"rule":"fatal_recycle"' && [ "$P1" = "$P0" ]; then
  record $S off_default_no_recycle PASS "facet off: PHP's own fatal (http=$PHPSTATUS), no fatal_recycle line, child pid $P0 unchanged"
else record $S off_default_no_recycle FAIL "http=$PHPSTATUS pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 160)"; fi

# OBSERVE
writeini "$WORK/observe.toml"; ap_restart
case "$(rec_row)" in "armed (observe"*) record $S phpinfo_observe PASS "row: $(rec_row)" ;; *) record $S phpinfo_observe FAIL "row: $(rec_row)" ;; esac
reset; P0=$(pid_now); reset; c=$(get /fatal.php); P1=$(pid_now)
if [ "$c" = "${PHPSTATUS:-500}" ] && has '"rule":"fatal_recycle"' && has '"action":"log"' && [ "$P1" = "$P0" ]; then
  record $S observe_no_exit PASS "would-recycle logged (action log), producing http=$c (= PHP's own), child pid $P0 unchanged"
else record $S observe_no_exit FAIL "http=$c (control $PHPSTATUS) pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 200)"; fi

# ENFORCE
writeini "$WORK/enforce.toml"; ap_restart
RROW=$(rec_row)
case "$RROW" in "armed (enforce"*) record $S phpinfo_enforce PASS "row: $RROW" ;; *) record $S phpinfo_enforce FAIL "row: $RROW" ;; esac

for prod in fatal parse require; do
  reset; P0=$(pid_now); reset; c=$(get "/$prod.php"); P1=$(pid_now)
  if ! has '"rule":"fatal_recycle"' || ! has '"action":"block"'; then
    record $S "enforce_recycles_$prod" FAIL "$prod.php http=$c but no fatal_recycle block line ($(tr -d '\n' < "$LOG" | head -c 180))"
  elif [ "$P1" = "$P0" ]; then
    record $S "enforce_recycles_$prod" FAIL "$prod.php child pid unchanged $P0 (did not recycle); http=$c"
  else
    A=$(get /)
    if [ "$A" = 200 ]; then record $S "enforce_recycles_$prod" PASS "$prod.php: fatal_recycle block logged, child pid $P0 -> $P1 (fresh), follow-up 200 (producing http=$c)"
    else record $S "enforce_recycles_$prod" FAIL "$prod.php follow-up http=$A"; fi
  fi
done

# Flush-ordering finding: did the producing request's 500 reach the client?
reset; P0=$(pid_now); reset; cprod=$(get /fatal.php)
case "$RROW" in
  *"recycle after teardown"*)
    if [ "$cprod" = "${PHPSTATUS:-500}" ]; then record $S producing_500_delivery PASS "recycle-after: producing request returned PHP's own fatal status $cprod (flushed before teardown on this SAPI)"
    else record $S producing_500_delivery FAIL "recycle-after chosen but producing http=$cprod (expected PHP's own $PHPSTATUS; this SAPI does NOT flush before teardown -> should fall back to immediate)"; fi ;;
  *"immediate _exit"*)
    if [ "$cprod" != "${PHPSTATUS:-500}" ]; then record $S producing_500_delivery N/A "immediate _exit on this SAPI: producing http=$cprod (PHP's own $PHPSTATUS not preserved either way; guaranteed fail-stop used)"
    else record $S producing_500_delivery FAIL "immediate chosen but producing http=$cprod == PHP's own (unexpected)"; fi ;;
  *) record $S producing_500_delivery FAIL "could not read the recycle delivery mode: $RROW" ;;
esac

# OOM still immediate-exits even with recycle enforcing.
reset; P0=$(pid_now); reset; c=$(get /oom.php); P1=$(pid_now)
if [ "$c" = 200 ]; then record $S oom_still_exits FAIL "oom returned 200 (no out-of-memory?)"
elif ! has '"rule":"out_of_memory"'; then record $S oom_still_exits FAIL "http=$c but no out_of_memory line ($(tr -d '\n' < "$LOG" | head -c 160))"
elif [ "$P1" = "$P0" ]; then record $S oom_still_exits FAIL "child pid unchanged $P0 (OOM did not exit)"
else
  A=$(get /); if [ "$A" = 200 ]; then record $S oom_still_exits PASS "OOM keeps §4.6 immediate exit: out_of_memory logged, pid $P0 -> $P1, follow-up 200"
  else record $S oom_still_exits FAIL "follow-up http=$A"; fi
fi

# A warning survives untouched.
reset; P0=$(pid_now); reset; c=$(get /warn.php); P1=$(pid_now)
if [ "$c" = 200 ] && ! has '"rule":"fatal_recycle"' && ! has '"rule":"out_of_memory"' && [ "$P1" = "$P0" ]; then
  record $S warning_survives PASS "warning: http=200, no recycle/backstop line, child pid $P0 unchanged"
else record $S warning_survives FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 160)"; fi

ap_stop
echo "== [$PHPVER] apache rows done ==" >&2
