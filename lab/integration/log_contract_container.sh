#!/bin/sh
# In-container half of the log-contract integration test (inside
# howdah-dev-php*). Builds the extension, serves a small app with `php -S`,
# raises one event per layer (self-test marker = 1, sql_injection = 2,
# command_exec sink = 3) and checks:
#   1. [log] path is honoured when howdah.log is unset, and howdah.log wins
#      when both are set; every line is schema 2 with the right layer
#      (lab/integration/log_check.php);
#   2. destination = "syslog" sends RFC 3164 frames to /dev/log (a php -n
#      stand-in daemon here) with the configured facility and ident, and
#      ignores both paths;
#   3. destination = "stderr" writes `howdah-event {...}` to stderr;
#   4. [log] exec runs the hook with the exact line on stdin, HOWDAH_RULE /
#      HOWDAH_ACTION set, no argv and nothing else in its environment, and
#      exec_rate_limit caps the spawns.
set -eu

FEATURE="${1:-php7}"
WORK=/tmp/howdah-logc
LC=/src/lab/integration
SRV=""
LSN=""
rm -rf "$WORK"; mkdir -p "$WORK"

echo "== php $(php -r 'echo PHP_VERSION;') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"

printf '<?php\nif (isset($_GET["exec"])) { system("true"); }\necho "OK\\n";\n' > "$WORK/index.php"

cleanup() {
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null
  [ -n "$LSN" ] && kill "$LSN" 2>/dev/null
  true
}
fail() {
  echo "FAIL: $1"
  for f in "$WORK"/*.log "$WORK"/*.txt; do
    [ -f "$f" ] && { echo "--- $f ---"; tail -20 "$f"; }
  done
  cleanup
  exit 1
}

# serve <port> <toml> [howdah.log]
serve() {
  _port=$1; _toml=$2; _ini=${3:-}
  set -- -d extension="$WORK/howdah.so" -d howdah.config="$_toml"
  if [ -n "$_ini" ]; then set -- "$@" -d howdah.log="$_ini"; fi
  php "$@" -S "127.0.0.1:$_port" "$WORK/index.php" > "$WORK/server.$_port.txt" 2>&1 &
  SRV=$!
  _j=0
  while ! curl -s -o /dev/null "http://127.0.0.1:$_port/" 2>/dev/null; do
    _j=$((_j+1)); [ "$_j" -gt 50 ] && fail "server $_port never came up"; sleep 0.1
  done
}
stop() { kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""; }

# ri <toml> [howdah.log]: the `php --ri howdah` table
ri() {
  if [ -n "${2:-}" ]; then
    php -d extension="$WORK/howdah.so" -d howdah.config="$1" -d howdah.log="$2" --ri howdah
  else
    php -d extension="$WORK/howdah.so" -d howdah.config="$1" --ri howdah
  fi
}

marker() {
  printf -- '--LcB0\r\nContent-Disposition: form-data; name="__howdah_selftest__"\r\n\r\n1\r\n--LcB0--\r\n' > "$WORK/marker.bin"
  curl -s -o /dev/null -X POST -H 'Content-Type: multipart/form-data; boundary=LcB0' \
       --data-binary @"$WORK/marker.bin" "http://127.0.0.1:$1/"
}
sqli() { curl -s -o /dev/null -G --data-urlencode "q=' OR 1=1 --" "http://127.0.0.1:$1/"; }
sink() { curl -s -o /dev/null "http://127.0.0.1:$1/?exec=1"; }
events() { marker "$1"; sqli "$1"; sink "$1"; }

# wait_lines <file> <n>
wait_lines() {
  _j=0
  while [ "$(cat "$1" 2>/dev/null | wc -l)" -lt "$2" ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && fail "$1 never reached $2 lines"; sleep 0.05
  done
}

expect_layers() {
  grep -qx 'self_test 1 log' "$1" || fail "$2: no layer-1 self_test line"
  grep -qx 'sql_injection 2 log' "$1" || fail "$2: no layer-2 sql_injection line"
  grep -qx 'command_exec 3 log' "$1" || fail "$2: no layer-3 command_exec line"
}

# ---- 1. [log] path honoured; howdah.log wins ---------------------------------
printf 'mode = "detect"\n[log]\npath = "%s"\n' "$WORK/toml-path.log" > "$WORK/path.toml"
ri "$WORK/path.toml" > "$WORK/ri1.txt"
grep -q "^Log destination => $WORK/toml-path.log (from \[log\] path)\$" "$WORK/ri1.txt" || fail "1: --ri does not show the [log] path"
grep -q '^Log schema => 2$' "$WORK/ri1.txt" || fail "1: --ri has no Log schema row"
serve 8101 "$WORK/path.toml"
events 8101
stop
php -n "$LC/log_check.php" "$WORK/toml-path.log" > "$WORK/check1.txt" || fail "1: schema check"
expect_layers "$WORK/check1.txt" 1
echo "  ok   - [log] path honoured with howdah.log unset; schema 2, one line per layer:"
sed 's/^/           /' "$WORK/toml-path.log"

: > "$WORK/toml-path.log"
serve 8102 "$WORK/path.toml" "$WORK/ini.log"
marker 8102
stop
[ -s "$WORK/ini.log" ] || fail "1b: howdah.log got no line"
[ ! -s "$WORK/toml-path.log" ] || fail "1b: [log] path was written although howdah.log is set"
ri "$WORK/path.toml" "$WORK/ini.log" | grep -q "^Log destination => $WORK/ini.log\$" || fail "1b: --ri"
echo "  ok   - howdah.log wins over [log] path"

# ---- 2. syslog ---------------------------------------------------------------
php -n "$LC/log_listener.php" /dev/log "$WORK/syslog.txt" > "$WORK/listener.txt" 2>&1 &
LSN=$!
_j=0
while [ ! -S /dev/log ]; do _j=$((_j+1)); [ "$_j" -gt 50 ] && fail "2: listener never bound /dev/log"; sleep 0.1; done
printf 'mode = "detect"\n[log]\ndestination = "syslog"\nsyslog_facility = "local3"\nsyslog_ident = "howdah-lab"\npath = "%s"\n' \
  "$WORK/toml-ignored.log" > "$WORK/syslog.toml"
ri "$WORK/syslog.toml" "$WORK/ini-ignored.log" > "$WORK/ri2.txt"
grep -q '^Log destination => syslog (/dev/log, facility local3, ident howdah-lab)$' "$WORK/ri2.txt" || fail "2: --ri"
serve 8103 "$WORK/syslog.toml" "$WORK/ini-ignored.log"
events 8103
stop
wait_lines "$WORK/syslog.txt" 3
HOWDAH_IDENT=howdah-lab HOWDAH_FAC=19 php -n "$LC/log_check.php" "$WORK/syslog.txt" syslog > "$WORK/check2.txt" \
  || fail "2: frame/schema check"
expect_layers "$WORK/check2.txt" 2
[ ! -e "$WORK/ini-ignored.log" ] || fail "2: howdah.log written although destination = syslog"
[ ! -e "$WORK/toml-ignored.log" ] || fail "2: [log] path written although destination = syslog"
kill "$LSN" 2>/dev/null || true; LSN=""
echo "  ok   - destination = syslog: RFC 3164 frames on /dev/log, facility local3, ident howdah-lab, paths ignored:"
grep 'Log destination' "$WORK/ri2.txt" | sed 's/^/           /'
sed 's/^/           /' "$WORK/syslog.txt"

# ---- 3. stderr ---------------------------------------------------------------
printf 'mode = "detect"\n[log]\ndestination = "stderr"\n' > "$WORK/stderr.toml"
serve 8104 "$WORK/stderr.toml" "$WORK/ini-ignored2.log"
events 8104
stop
sed -n 's/^howdah-event //p' "$WORK/server.8104.txt" > "$WORK/stderr-events.txt"
php -n "$LC/log_check.php" "$WORK/stderr-events.txt" > "$WORK/check3.txt" || fail "3: schema check"
expect_layers "$WORK/check3.txt" 3
[ ! -e "$WORK/ini-ignored2.log" ] || fail "3: howdah.log written although destination = stderr"
echo "  ok   - destination = stderr: 'howdah-event {json}' lines on stderr"

# ---- 4. exec hook ------------------------------------------------------------
cat > "$WORK/hook.sh" <<EOF
#!/bin/sh
f=\$(mktemp $WORK/hook.XXXXXX)
env > "\$f.env"
{ echo "rule=\$HOWDAH_RULE action=\$HOWDAH_ACTION argc=\$#"; cat; } > "\$f.tmp"
mv "\$f.tmp" "\$f.out"
EOF
chmod 0755 "$WORK/hook.sh"
printf 'mode = "detect"\n[log]\npath = "%s"\nexec = "%s"\n' "$WORK/exec.log" "$WORK/hook.sh" > "$WORK/exec.toml"
ri "$WORK/exec.toml" > "$WORK/ri4.txt"
grep -q "^Log hook (\[log\] exec) => $WORK/hook.sh (at most 10 per second)\$" "$WORK/ri4.txt" || fail "4: --ri hook row"
serve 8105 "$WORK/exec.toml"
events 8105
_j=0
while [ "$(ls "$WORK"/hook.*.out 2>/dev/null | wc -l)" -lt 3 ]; do
  _j=$((_j+1)); [ "$_j" -gt 100 ] && fail "4: the hook did not run three times"; sleep 0.05
done
stop
[ "$(wc -l < "$WORK/exec.log")" -eq 3 ] || fail "4: expected 3 events"
while IFS= read -r line; do
  _hit=""
  for f in "$WORK"/hook.*.out; do
    if [ "$(sed -n 2p "$f")" = "$line" ]; then _hit=$f; fi
  done
  [ -n "$_hit" ] || fail "4: no hook received: $line"
  _rule=$(printf '%s' "$line" | sed 's/.*"rule":"\([a-z0-9_]*\)".*/\1/')
  _act=$(printf '%s' "$line" | sed 's/.*"action":"\([a-z]*\)".*/\1/')
  [ "$(sed -n 1p "$_hit")" = "rule=$_rule action=$_act argc=0" ] || fail "4: hook env/argv: $(sed -n 1p "$_hit")"
  [ "$(wc -l < "$_hit")" -eq 2 ] || fail "4: hook stdin had more than the line"
  _envf="${_hit%.out}.env"
  _extra=$(cut -d= -f1 "$_envf" | grep -vxE 'HOWDAH_RULE|HOWDAH_ACTION|PATH|PWD|OLDPWD|SHLVL|_' || true)
  [ -z "$_extra" ] || fail "4: hook environment has more than HOWDAH_RULE/HOWDAH_ACTION/PATH: $_extra"
done < "$WORK/exec.log"
echo "  ok   - [log] exec: each hook got its exact line on stdin, HOWDAH_RULE/HOWDAH_ACTION set, argc 0, no other env:"
for f in "$WORK"/hook.*.out; do sed -n 1p "$f" | sed 's/^/           /'; done
grep '^Log hook' "$WORK/ri4.txt" | sed 's/^/           /'

rm -f "$WORK"/hook.*
printf 'mode = "detect"\n[log]\npath = "%s"\nexec = "%s"\nexec_rate_limit = 2\n' "$WORK/rate.log" "$WORK/hook.sh" > "$WORK/rate.toml"
serve 8106 "$WORK/rate.toml"
for i in 1 2 3 4 5 6; do sqli 8106; done
sleep 1
stop
_n=$(ls "$WORK"/hook.*.out 2>/dev/null | wc -l)
[ "$(wc -l < "$WORK/rate.log")" -eq 6 ] || fail "4b: expected 6 events in the log"
[ "$_n" -ge 2 ] && [ "$_n" -lt 6 ] || fail "4b: exec_rate_limit = 2 let $_n of 6 hooks run"
grep -q 'exec rate limit reached (2 per second)' "$WORK/server.8106.txt" || fail "4b: no rate-limit note on stderr"
echo "  ok   - exec_rate_limit = 2: 6 events logged, $_n hooks ran, rate-limit note on stderr"

cleanup
echo "PASS"
