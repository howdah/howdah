#!/bin/sh
# In-container half of the out-of-memory backstop lab (see oom_backstop.sh):
# php-fpm with ONE static worker behind the nginx sidecar on 127.0.0.1:8080.
#
# No attack request is needed — an ordinary script that allocates past a low
# memory_limit drives PHP to out-of-memory. The backstop (§4.6) is armed only on
# UNPATCHED engines (upstream's fix registers the memory_hard_limit_percent ini
# directive); the dev images span both, so this script probes the engine and
# runs the matching branch:
#
#   unpatched (5.x, 7.x, 8.0, 8.1, pre-fix 8.2+):
#     * oom.php    -> the worker _exit()s, nginx 502, an out_of_memory block line
#                     is logged, the worker pid CHANGES, a follow-up is 200;
#     * a warning and an uncaught exception do NOT exit (pid unchanged);
#     * oom_exit = false restores PHP's own behavior (pid unchanged, no line);
#     * the CLI SAPI is off (no line; the phpinfo row says non-web SAPI);
#     * the fpm phpinfo row reads "armed".
#   patched (>= 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12):
#     * the backstop stays off: oom.php gets PHP's own behavior, no line, and the
#       phpinfo row reads "off (patched ...)".
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
  tail -8 "$WORK/build.err" >&2; record $S build FAIL "cargo build failed"; exit 1
fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

# ---- the app ----------------------------------------------------------------
cat > "$APP/index.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
echo "OK pid=", getmypid(), "\n";
PHP
# Allocate past memory_limit. Writes the marker first so we can see it started.
cat > "$APP/oom.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
$a = array(); while (true) { $a[] = str_repeat('x', 1048576); }
PHP
cat > "$APP/warn.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
@trigger_error('a user warning', E_USER_WARNING);
echo "OK pid=", getmypid(), "\n";
PHP
cat > "$APP/ex.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
throw new RuntimeException('uncaught for the lab');
PHP
# A script-controlled E_USER_ERROR whose message mimics the OOM prefix. On 8.x
# PHP hands zend_error_cb the rendered message; this must NOT be treated as a
# real out-of-memory (only E_ERROR is), so the worker survives and no backstop
# line is written.
cat > "$APP/usererr.php" <<'PHP'
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
@trigger_error('Allowed memory size of 999999 bytes exhausted (faked by the script)', E_USER_ERROR);
echo "OK pid=", getmypid(), "\n";
PHP
cat > "$APP/info.php" <<'PHP'
<?php ob_start(); phpinfo(INFO_MODULES); $h = ob_get_clean();
if (preg_match('/OOM backstop[^<]*<\/td>\s*<td[^>]*>([^<]*)/', $h, $m)) echo "OOMROW:", trim($m[1]);
else echo "OOMROW:MISSING";
PHP

# oom_exit = false: the backstop is not installed.
printf 'oom_exit = false\n' > "$WORK/oomoff.toml"
# mode = off disables every layer, the backstop included (oom_exit stays true).
printf 'mode = "off"\n' > "$WORK/modeoff.toml"

# Is this engine patched? (SAPI-independent: the ini directive upstream's fix
# adds.) 0 = patched (directive exists), 1 = unpatched.
if php -r 'exit(ini_get("memory_hard_limit_percent") === false ? 1 : 0);'; then PATCHED=yes; else PATCHED=no; fi
echo "== [$PHPVER] engine patched for CVE-2026-109618: $PATCHED ==" >&2

# ---- php-fpm: one static worker, memory_limit 32M ---------------------------
FPMPID=""
fpm_start() { # extra -d ...
  cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $OUT/fpm.err
daemonize = no
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 1
catch_workers_output = yes
EOF
  # shellcheck disable=SC2086
  php-fpm -R -F -y "$WORK/fpm.conf" -d memory_limit=32M -d display_errors=0 -d log_errors=1 \
    -d extension="$WORK/howdah.so" -d howdah.log="$LOG" "$@" > "$WORK/fpm.out" 2>&1 &
  FPMPID=$!; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "php-fpm/nginx never answered 200" >&2; cat "$WORK/fpm.out" >&2; return 1; }; sleep 0.1
  done
}
fpm_stop() { [ -n "$FPMPID" ] && kill "$FPMPID" 2>/dev/null; wait "$FPMPID" 2>/dev/null; FPMPID=""; }

B="$WORK/resp.txt"
get()      { curl -s -m 30 -o "$B" -w '%{http_code}' "$URL$1" 2>/dev/null || echo 000; }
oom_req()  { curl -s -m 60 -o "$B" -w '%{http_code}' "$URL/oom.php" 2>/dev/null || echo 000; }
pid_now()  { get / >/dev/null; sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' "$B" | head -1; }
oom_row()  { get /info.php >/dev/null; sed -n 's/.*OOMROW:\(.*\)/\1/p' "$B" | head -1; }
reset()    { rm -f "$MARK"; : > "$LOG"; }

# ---- scenarios ---------------------------------------------------------------
fpm_start || { record $S fpm_start FAIL "php-fpm/nginx down"; exit 1; }
P0=$(pid_now)
if echo "$P0" | grep -qE '^[0-9]+$'; then record $S baseline PASS "worker pid $P0 answers through nginx"; else record $S baseline FAIL "no pid in response"; fi

ROW=$(oom_row)

if [ "$PATCHED" = no ]; then
  # --- phpinfo row says armed -------------------------------------------------
  case "$ROW" in
    armed*) record $S phpinfo_armed PASS "row: $ROW" ;;
    *) record $S phpinfo_armed FAIL "row: $ROW (want 'armed ...')" ;;
  esac

  # --- a warning does not exit ------------------------------------------------
  reset; c=$(get /warn.php); P1=$(pid_now)
  if [ "$c" = 200 ] && ! grep -q '"rule":"out_of_memory"' "$LOG" && ! grep -q '"rule":"startup_fatal"' "$LOG" && [ "$P1" = "$P0" ]; then
    record $S warning_survives PASS "http=200, no backstop line, worker pid $P0 unchanged"
  else record $S warning_survives FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi

  # --- an uncaught exception (script-phase fatal) does not exit ---------------
  reset; c=$(get /ex.php); P1=$(pid_now)
  if [ "$c" != 200 ] && ! grep -q '"rule":"out_of_memory"' "$LOG" && ! grep -q '"rule":"startup_fatal"' "$LOG" && [ "$P1" = "$P0" ]; then
    record $S exception_survives PASS "uncaught exception http=$c (PHP's own 500), no backstop line, worker pid $P0 unchanged"
  else record $S exception_survives FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi

  # --- a script-controlled E_USER_ERROR with an OOM-looking message does NOT
  #     exit (only a real E_ERROR out-of-memory does) --------------------------
  reset; c=$(get /usererr.php); P1=$(pid_now)
  if ! grep -q '"rule":"out_of_memory"' "$LOG" && [ "$P1" = "$P0" ]; then
    record $S user_error_oom_prefix_survives PASS "trigger_error(...,E_USER_ERROR) http=$c, no backstop line, worker pid $P0 unchanged"
  else record $S user_error_oom_prefix_survives FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi

  # --- out-of-memory ends the worker (the backstop) ---------------------------
  reset; P0=$(pid_now); reset
  c=$(oom_req)
  if [ "$c" = 200 ]; then
    record $S oom_exits FAIL "oom request returned 200 (worker did not run out of memory?)"
  elif ! grep -q '"rule":"out_of_memory"' "$LOG"; then
    record $S oom_exits FAIL "http=$c but no out_of_memory line in log ($(tr -d '\n' < "$LOG" | head -c 160))"
  elif ! grep -q '"action":"block"' "$LOG"; then
    record $S oom_exits FAIL "out_of_memory line is not action=block"
  elif ! grep -q '/oom.php' "$LOG"; then
    record $S oom_exits FAIL "out_of_memory reason does not name the script:line: $(tr -d '\n' < "$LOG" | head -c 200)"
  else
    P1=$(pid_now)
    if [ "$P1" = "$P0" ]; then
      record $S oom_exits FAIL "worker pid unchanged $P0 (worker did not _exit)"
    else
      A=$(get /)
      if [ "$A" = 200 ]; then
        record $S oom_exits PASS "oom http=$c, out_of_memory block logged, worker pid $P0 -> $P1, follow-up 200"
      else record $S oom_exits FAIL "follow-up after fresh worker http=$A"; fi
    fi
  fi
  fpm_stop

  # --- oom_exit = false restores PHP's own behavior ---------------------------
  fpm_start -d howdah.config="$WORK/oomoff.toml" || { record $S oomoff_start FAIL down; exit 1; }
  P0=$(pid_now); reset
  c=$(oom_req); P1=$(pid_now)
  if ! grep -q '"rule":"out_of_memory"' "$LOG" && [ "$P1" = "$P0" ]; then
    record $S oom_off_survives PASS "oom_exit=false: PHP's own fatal (http=$c), worker pid $P0 unchanged, no backstop line"
  else record $S oom_off_survives FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi
  # the phpinfo row reflects the config too
  case "$(oom_row)" in
    "off (oom_exit = false)") record $S phpinfo_oom_off PASS "row: off (oom_exit = false)" ;;
    *) record $S phpinfo_oom_off FAIL "row: $(oom_row)" ;;
  esac
  fpm_stop

  # --- mode = off disables the backstop (oom_exit stays true) -----------------
  fpm_start -d howdah.config="$WORK/modeoff.toml" || { record $S modeoff_start FAIL down; exit 1; }
  P0=$(pid_now); reset
  c=$(oom_req); P1=$(pid_now)
  if ! grep -q '"rule":"out_of_memory"' "$LOG" && [ "$P1" = "$P0" ]; then
    record $S mode_off_survives PASS "mode=off: PHP's own fatal (http=$c), worker pid $P0 unchanged, no backstop line"
  else record $S mode_off_survives FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi
  case "$(oom_row)" in
    "off (mode = off)") record $S phpinfo_mode_off PASS "row: off (mode = off)" ;;
    *) record $S phpinfo_mode_off FAIL "row: $(oom_row)" ;;
  esac
  fpm_stop

  # --- the CLI SAPI is off ----------------------------------------------------
  reset
  php -d memory_limit=32M -d extension="$WORK/howdah.so" -d howdah.log="$LOG" "$APP/oom.php" > "$WORK/cli.out" 2>&1
  CLIROW=$(php -d extension="$WORK/howdah.so" --ri howdah 2>/dev/null | sed -n 's/.*OOM backstop (oom_exit) *=> *//p' | head -1)
  if ! grep -q '"rule":"out_of_memory"' "$LOG" && grep -qiE 'Allowed memory size|Out of memory' "$WORK/cli.out"; then
    record cli oom_cli_off PASS "PHP's own OOM fatal on the CLI, no backstop line; --ri row: ${CLIROW:-?}"
  else record cli oom_cli_off FAIL "cli.out=$(tr '\n' ' ' < "$WORK/cli.out" | cut -c1-120) log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi

  record $S oom_patched_off NOT-RUN "engine is unpatched; the patched-off path needs a patched image (>= 8.2.35/8.3.36/8.4.27/8.5.12)"

else
  # --- patched engine: the backstop must stay off -----------------------------
  case "$ROW" in
    "off (patched"*) record $S phpinfo_off_patched PASS "row: $ROW" ;;
    *) record $S phpinfo_off_patched FAIL "row: $ROW (want 'off (patched ...)')" ;;
  esac
  reset; P0=$(pid_now); reset
  c=$(oom_req); P1=$(pid_now)
  if ! grep -q '"rule":"out_of_memory"' "$LOG" && [ "$P1" = "$P0" ]; then
    record $S oom_patched_off PASS "patched engine: PHP's own behavior (http=$c), worker pid $P0 unchanged, no backstop line"
  else record $S oom_patched_off FAIL "http=$c pid=$P0->$P1 log=$(tr -d '\n' < "$LOG" | head -c 120)"; fi
  for sc in warning_survives exception_survives oom_exits oom_off_survives oom_cli_off; do
    record $S "$sc" NOT-RUN "engine is patched; the backstop is correctly off here"
  done
  fpm_stop
fi

echo "== [$PHPVER] fpm-nginx rows done ==" >&2
