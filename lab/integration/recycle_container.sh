#!/bin/sh
# In-container half of the §4.7 recycle-facet lab (see recycle.sh): php-fpm with
# ONE static worker behind the nginx sidecar on 127.0.0.1:8080.
#
# No attack request is needed — an ordinary script that throws an uncaught fatal
# during EXECUTION (an uncaught Error, a parse/compile error, a failed require,
# max_execution_time). The recycle facet (§4.7) is OFF by default and armed only
# on UNPATCHED engines (upstream's fix registers the memory_hard_limit_percent
# ini directive); the dev images span both, so this script probes the engine and
# runs the matching branch:
#
#   unpatched (5.x, 7.x, 8.0, 8.1, pre-fix 8.2+):
#     OBSERVE (recycle_on_fatal=true, recycle_observe=true):
#       * a would-recycle line (rule fatal_recycle, action log) is written and
#         the worker pid is UNCHANGED (the next request is the same worker); the
#         producing request still returns PHP's own 500.
#     ENFORCE (recycle_on_fatal=true):
#       * a fatal_recycle block line is written and the worker pid CHANGES on the
#         next request (a fresh worker); the producing request's delivery depends
#         on this SAPI's flush ordering (recorded below — the §4.7 finding).
#     OOM and startup fatals keep §4.6's immediate exit even with recycle on; a
#       warning still reaches PHP unchanged; the facet is OFF by default.
#   patched (>= 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12):
#     * the facet stays off: the phpinfo row reads "off (patched ...)" and an
#       uncaught fatal gets PHP's own behavior (pid unchanged, no line).
#
# The flush-ordering finding (design §4.7, §5.6): under ENFORCE this records,
# per SAPI, whether the producing request's 500 reached the client BEFORE the
# recycle _exit. The extension reports its chosen delivery per SAPI in the
# phpinfo "Recycle after fatal" row ("recycle after teardown" vs
# "immediate _exit"); this script reads that and checks the matching outcome.
#
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
# Rows: phpver <TAB> sapi <TAB> scenario <TAB> PASS|FAIL|SKIP|NOT-RUN <TAB> detail
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows.tsv}"
WORK=/work; APP=$WORK/app; MARK=$WORK/marker/ran; LOG=$WORK/events.log; OUT=/out
URL=http://127.0.0.1:8080
mkdir -p "$APP" "$WORK/marker"; : > "$LOG"; : > "$RESULTS"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=fpm-nginx
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$1" "$2" "$3" "$4" >> "$RESULTS"; echo "  [$PHPVER $1] $2 $3: $4" >&2; }

echo "== [$PHPVER] building howdah-ext ($FEATURE) ==" >&2
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/t}"
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -12 "$WORK/build.err" >&2; record $S build FAIL "cargo build failed"; exit 1
fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

# ---- the app ----------------------------------------------------------------
cat > "$APP/index.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
echo "OK pid=", getmypid(), "\n";
PHP
# A script-phase uncaught fatal: surfaces as E_ERROR "Uncaught ...". Writes the
# pid marker first so we can tell it started.
cat > "$APP/fatal.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
throw new RuntimeException('poisoning-class fatal for the recycle lab');
PHP
# A parse/compile error in an included file (compiled during execution, after
# request startup). The outer script requires it; the require itself fatals.
cat > "$APP/broken.inc" <<'PHP'
<?php function (  { // deliberate syntax error
PHP
cat > "$APP/parse.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
require __DIR__ . '/broken.inc';
echo "unreachable\n";
PHP
# A failed require (missing file) -> E_COMPILE_ERROR / E_ERROR during execution.
cat > "$APP/require.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
require __DIR__ . '/does-not-exist-' . getmypid() . '.php';
echo "unreachable\n";
PHP
# Allocate past memory_limit -> OOM, which stays §4.6 immediate-exit.
cat > "$APP/oom.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
$a = array(); while (true) { $a[] = str_repeat('x', 1048576); }
PHP
# A warning: must NOT recycle.
cat > "$APP/warn.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
@trigger_error('a user warning', E_USER_WARNING);
echo "OK pid=", getmypid(), "\n";
PHP
cat > "$APP/info.php" <<'PHP'
<?php ob_start(); phpinfo(INFO_MODULES); $h = ob_get_clean();
if (preg_match('/Recycle after fatal[^<]*<\/td>\s*<td[^>]*>([^<]*)/', $h, $m)) echo "RECROW:", trim($m[1]);
else echo "RECROW:MISSING";
PHP

# recycle enforce (oom_exit default on, so OOM still exits immediately).
printf 'recycle_on_fatal = true\n' > "$WORK/enforce.toml"
# recycle observe.
printf 'recycle_on_fatal = true\nrecycle_observe = true\n' > "$WORK/observe.toml"
# facet off (default) — the control.
printf 'mode = "block"\n' > "$WORK/off.toml"

# Is this engine patched? 0 = patched (directive exists), 1 = unpatched.
if php -r 'exit(ini_get("memory_hard_limit_percent") === false ? 1 : 0);'; then PATCHED=yes; else PATCHED=no; fi
echo "== [$PHPVER] engine patched for CVE-2026-109619: $PATCHED ==" >&2

# ---- php-fpm: one static worker ---------------------------------------------
FPMPID=""
fpm_start() { # extra -d ...
  cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $OUT/fpm.err
daemonize = no
[www]
; The dev images run as root and we pass php-fpm -R; older php-fpm (5.4)
; refuses to start a pool without an explicit user, so name it. root keeps the
; worker able to write the event log and the pid marker, as on 5.6+.
user = root
group = root
listen = 127.0.0.1:9000
pm = static
pm.max_children = 1
catch_workers_output = yes
EOF
  # display_errors=0 so PHP sets a clean fatal status (no inline error body that
  # would start the response at 200 before the status is set), matching the
  # oom_backstop bed.
  # shellcheck disable=SC2086
  php-fpm -R -F -y "$WORK/fpm.conf" -d memory_limit=64M -d max_execution_time=30 -d display_errors=0 \
    -d log_errors=1 -d extension="$WORK/howdah.so" -d howdah.log="$LOG" "$@" > "$WORK/fpm.out" 2>&1 &
  FPMPID=$!; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "php-fpm/nginx never answered 200" >&2; cat "$WORK/fpm.out" >&2; return 1; }; sleep 0.1
  done
}
fpm_stop() { [ -n "$FPMPID" ] && kill "$FPMPID" 2>/dev/null; wait "$FPMPID" 2>/dev/null; FPMPID=""; }

B="$WORK/resp.txt"
get()     { curl -s -m 30 -o "$B" -w '%{http_code}' "$URL$1" 2>/dev/null || echo 000; }
pid_now() { _p=""; _k=0; while [ -z "$_p" ] && [ "$_k" -lt 50 ]; do get / >/dev/null; _p=$(sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' "$B" | head -1); [ -z "$_p" ] && sleep 0.1; _k=$((_k+1)); done; echo "$_p"; }
rec_row() { get /info.php >/dev/null; sed -n 's/.*RECROW:\(.*\)/\1/p' "$B" | head -1; }
reset()   { rm -f "$MARK"; : > "$LOG"; }
has()     { grep -q "$1" "$LOG"; }

# ---- scenarios ---------------------------------------------------------------
if [ "$PATCHED" = yes ]; then
  fpm_start -d howdah.config="$WORK/enforce.toml" || { record $S fpm_start FAIL "php-fpm/nginx down"; exit 1; }
  case "$(rec_row)" in
    "off (patched"*) record $S phpinfo_off_patched PASS "row: $(rec_row)" ;;
    *) record $S phpinfo_off_patched FAIL "row: $(rec_row) (want 'off (patched ...)')" ;;
  esac
  reset; P0=$(pid_now); reset
  c=$(get /fatal.php); P1=$(pid_now)
  if ! has '"rule":"fatal_recycle"' && [ "$P1" = "$P0" ]; then
    record $S recycle_patched_off PASS "patched engine: PHP's own behavior (http=$c), worker pid $P0 unchanged, no fatal_recycle line"
  else record $S recycle_patched_off FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 160)"; fi
  for sc in phpinfo_observe observe_no_exit phpinfo_enforce enforce_recycles producing_500_delivery oom_still_exits warning_survives facet_off_default; do
    record $S "$sc" NOT-RUN "engine is patched; the recycle facet is correctly off here"
  done
  fpm_stop
  echo "== [$PHPVER] fpm-nginx rows done (patched) ==" >&2
  exit 0
fi

# -------- unpatched: the facet is off by default --------------------------------
fpm_start -d howdah.config="$WORK/off.toml" || { record $S fpm_start FAIL "php-fpm/nginx down"; exit 1; }
P0=$(pid_now)
if echo "$P0" | grep -qE '^[0-9]+$'; then record $S baseline PASS "worker pid $P0 answers through nginx"; else record $S baseline FAIL "no pid in response"; fi
case "$(rec_row)" in
  "off (recycle_on_fatal = false)") record $S facet_off_default PASS "default row: off (recycle_on_fatal = false)" ;;
  *) record $S facet_off_default FAIL "default row: $(rec_row) (want off by default)" ;;
esac
reset; PHPSTATUS=$(get /fatal.php); P1=$(pid_now)
# PHPSTATUS is PHP's own status for an uncaught fatal with this engine/SAPI/ini
# (config-independent), the control the observe run must match.
if ! has '"rule":"fatal_recycle"' && [ "$P1" = "$P0" ]; then
  record $S off_default_no_recycle PASS "facet off: PHP's own fatal (http=$PHPSTATUS), no fatal_recycle line, worker pid $P0 unchanged"
else record $S off_default_no_recycle FAIL "http=$PHPSTATUS pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 160)"; fi
fpm_stop

# -------- OBSERVE mode ----------------------------------------------------------
fpm_start -d howdah.config="$WORK/observe.toml" || { record $S observe_start FAIL down; exit 1; }
case "$(rec_row)" in
  "armed (observe"*) record $S phpinfo_observe PASS "row: $(rec_row)" ;;
  *) record $S phpinfo_observe FAIL "row: $(rec_row) (want 'armed (observe ...)')" ;;
esac
reset; P0=$(pid_now); reset
c=$(get /fatal.php); P1=$(pid_now)
# Observe: would-recycle line (action log), worker NOT recycled (pid unchanged),
# and PHP still delivered its own fatal response (same status as the control).
if [ "$c" = "${PHPSTATUS:-500}" ] && has '"rule":"fatal_recycle"' && has '"action":"log"' && [ "$P1" = "$P0" ] && grep -q '/fatal.php' "$LOG"; then
  record $S observe_no_exit PASS "would-recycle logged (action log, names script), producing http=$c (= PHP's own), worker pid $P0 unchanged"
else record $S observe_no_exit FAIL "http=$c (control $PHPSTATUS) pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 200)"; fi
fpm_stop

# -------- ENFORCE mode ----------------------------------------------------------
fpm_start -d howdah.config="$WORK/enforce.toml" || { record $S enforce_start FAIL down; exit 1; }
RROW=$(rec_row)
case "$RROW" in
  "armed (enforce"*) record $S phpinfo_enforce PASS "row: $RROW" ;;
  *) record $S phpinfo_enforce FAIL "row: $RROW (want 'armed (enforce ...)')" ;;
esac

# The producer set: an uncaught Error, a parse/compile error, a failed require.
# Each must recycle the worker (fresh pid on the next request).
for prod in fatal parse require; do
  reset; P0=$(pid_now); reset
  c=$(get "/$prod.php"); CPROD=$c
  P1=$(pid_now)
  if ! has '"rule":"fatal_recycle"'; then
    record $S "enforce_recycles_$prod" FAIL "$prod.php http=$c but no fatal_recycle line ($(tr -d '\n' < "$LOG" | head -c 180))"
  elif ! has '"action":"block"'; then
    record $S "enforce_recycles_$prod" FAIL "$prod.php fatal_recycle line is not action=block"
  elif [ "$P1" = "$P0" ]; then
    record $S "enforce_recycles_$prod" FAIL "$prod.php worker pid unchanged $P0 (worker did not recycle); http=$c"
  else
    A=$(get /)
    if [ "$A" = 200 ]; then
      record $S "enforce_recycles_$prod" PASS "$prod.php: fatal_recycle block logged, worker pid $P0 -> $P1 (fresh worker), follow-up 200 (producing http=$c)"
    else record $S "enforce_recycles_$prod" FAIL "$prod.php follow-up after fresh worker http=$A"; fi
  fi
done

# The §4.7 flush-ordering finding: did the PRODUCING request's 500 reach the
# client before the recycle _exit? Branch on what the extension chose for this
# SAPI (the phpinfo row), so the assertion matches the shipped delivery.
reset; P0=$(pid_now); reset
cprod=$(get /fatal.php)
case "$RROW" in
  *"recycle after teardown"*)
    if [ "$cprod" = "${PHPSTATUS:-500}" ]; then
      record $S producing_500_delivery PASS "recycle-after: producing request returned PHP's own fatal status $cprod (flushed before teardown on this SAPI)"
    else record $S producing_500_delivery FAIL "recycle-after chosen but producing http=$cprod (expected PHP's own $PHPSTATUS; this SAPI does NOT flush before teardown -> should fall back to immediate)"; fi
    ;;
  *"immediate _exit"*)
    if [ "$cprod" != "${PHPSTATUS:-500}" ]; then
      record $S producing_500_delivery N/A "immediate _exit on this SAPI: producing http=$cprod (PHP's own $PHPSTATUS not preserved here; the response is dropped before teardown either way, so the guaranteed fail-stop is used)"
    else record $S producing_500_delivery FAIL "immediate chosen but producing http=$cprod == PHP's own (unexpected; recycle-after would have preserved it)"; fi
    ;;
  *) record $S producing_500_delivery FAIL "could not read the recycle delivery mode from the phpinfo row: $RROW" ;;
esac

# OOM still immediate-exits even with recycle enforcing.
reset; P0=$(pid_now); reset
c=$(get /oom.php); P1=$(pid_now)
if [ "$c" = 200 ]; then
  record $S oom_still_exits FAIL "oom request returned 200 (no out-of-memory?)"
elif ! has '"rule":"out_of_memory"'; then
  record $S oom_still_exits FAIL "http=$c but no out_of_memory line ($(tr -d '\n' < "$LOG" | head -c 160))"
elif [ "$P1" = "$P0" ]; then
  record $S oom_still_exits FAIL "worker pid unchanged $P0 (OOM did not immediate-exit)"
else
  A=$(get /)
  if [ "$A" = 200 ]; then record $S oom_still_exits PASS "OOM keeps §4.6 immediate exit under recycle: out_of_memory logged, pid $P0 -> $P1, follow-up 200"
  else record $S oom_still_exits FAIL "follow-up http=$A"; fi
fi

# A warning still survives untouched.
reset; P0=$(pid_now); reset
c=$(get /warn.php); P1=$(pid_now)
if [ "$c" = 200 ] && ! has '"rule":"fatal_recycle"' && ! has '"rule":"out_of_memory"' && [ "$P1" = "$P0" ]; then
  record $S warning_survives PASS "warning: http=200, no recycle/backstop line, worker pid $P0 unchanged"
else record $S warning_survives FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 160)"; fi
fpm_stop

echo "== [$PHPVER] fpm-nginx rows done ==" >&2
