#!/bin/sh
# Apache mod_php (prefork) half of the log-contract test. Runs inside a dev
# image built FROM php:<ver>-apache (see log_contract.sh). Loads Howdah through
# a conf.d ini with [log] destination = "syslog" and an exec hook, starts a
# stand-in syslog daemon on /dev/log, raises one event per layer 1-3 over real
# HTTP, and checks:
#   - every event reaches /dev/log as an RFC 3164 frame (facility local0,
#     ident howdah) with a schema-2 line (log_check.php);
#   - the hook ran once per event, as the Apache worker user, with the exact
#     line on stdin;
#   - a hook in a world-writable directory is refused (and does not run).
set -eu

FEATURE="${1:-php8}"
W=/tmp/howdah-logap
LC=/src/lab/integration
rm -rf "$W"; mkdir -p "$W/hooks" "$W/open"
chmod 755 "$W"
chmod 777 "$W/hooks" "$W/open" # the hook (www-data) writes its output here

echo "== php $(php -r 'echo PHP_VERSION;') / apache $(apache2ctl -V 2>/dev/null | sed -n 's/^Server MPM: *//p') / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -1
cp /tmp/t/release/libhowdah_ext.so "$W/howdah.so"

fail() {
  echo "FAIL: $1"
  for f in "$W/syslog.txt" "$W/ap.err"; do [ -f "$f" ] && { echo "--- $f ---"; tail -20 "$f"; }; done
  exit 1
}

cat > "$W/hook.sh" <<EOF
#!/bin/sh
f=\$(mktemp $W/hooks/run.XXXXXX)
{ echo "user=\$(id -un) rule=\$HOWDAH_RULE action=\$HOWDAH_ACTION argc=\$#"; cat; } > "\$f.tmp"
mv "\$f.tmp" "\$f.out"
EOF
chmod 0755 "$W/hook.sh"
cp "$W/hook.sh" "$W/open/hook.sh"

CONFD=$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;'); mkdir -p "$CONFD"
printf '<?php if (isset($_GET["exec"])) { system("true"); } echo "OK\\n";' > /var/www/html/index.php
php -n "$LC/log_listener.php" /dev/log "$W/syslog.txt" > "$W/listener.txt" 2>&1 &
LSN=$!
_j=0
while [ ! -S /dev/log ]; do _j=$((_j+1)); [ "$_j" -gt 50 ] && fail "listener never bound /dev/log"; sleep 0.1; done

# run <hook path>: (re)start apache with that hook, raise three events
run() {
  printf 'mode = "detect"\n[log]\ndestination = "syslog"\nexec = "%s"\n' "$1" > "$W/h.toml"
  printf 'extension=%s\nhowdah.config=%s\n' "$W/howdah.so" "$W/h.toml" > "$CONFD/zz-howdah.ini"
  : > "$W/syslog.txt"
  # Foreground, so the error log (/dev/stderr in the php images) lands in
  # ap.err; in its own session, because prefork signals its whole process
  # group on shutdown (that would kill the stand-in syslog daemon).
  setsid apache2-foreground > /dev/null 2>>"$W/ap.err" &
  AP=$!
  _j=0
  while ! curl -s -o /dev/null http://127.0.0.1/; do _j=$((_j+1)); [ "$_j" -gt 60 ] && fail "apache never came up"; sleep 0.1; done
  printf -- '--B0\r\nContent-Disposition: form-data; name="__howdah_selftest__"\r\n\r\n1\r\n--B0--\r\n' > "$W/m.bin"
  curl -s -o /dev/null -X POST -H 'Content-Type: multipart/form-data; boundary=B0' --data-binary @"$W/m.bin" http://127.0.0.1/
  curl -s -o /dev/null -G --data-urlencode "q=' OR 1=1 --" http://127.0.0.1/
  curl -s -o /dev/null "http://127.0.0.1/?exec=1"
}
stop() {
  kill -TERM "$AP" 2>/dev/null || true
  wait "$AP" 2>/dev/null || true
  _j=0
  while curl -s -o /dev/null http://127.0.0.1/ 2>/dev/null; do _j=$((_j+1)); [ "$_j" -gt 60 ] && break; sleep 0.1; done
}

run "$W/hook.sh"
_j=0
while [ "$(ls "$W"/hooks/*.out 2>/dev/null | wc -l)" -lt 3 ]; do
  _j=$((_j+1)); [ "$_j" -gt 100 ] && fail "the hook did not run three times under apache"; sleep 0.05
done
stop
[ "$(grep -c . "$W/syslog.txt")" -eq 3 ] || fail "expected 3 syslog frames"
HOWDAH_IDENT=howdah HOWDAH_FAC=16 php -n "$LC/log_check.php" "$W/syslog.txt" syslog > "$W/check.txt" || fail "frame/schema check"
grep -qx 'self_test 1 log' "$W/check.txt" || fail "no layer-1 line"
grep -qx 'sql_injection 2 log' "$W/check.txt" || fail "no layer-2 line"
grep -qx 'command_exec 3 log' "$W/check.txt" || fail "no layer-3 line"
grep -q '"client_ip":"127.0.0.1"' "$W/syslog.txt" || fail "client_ip not set under apache"
for f in "$W"/hooks/*.out; do
  _l=$(sed -n 2p "$f")
  grep -qF "$_l" "$W/syslog.txt" || fail "hook line not among the events: $_l"
  sed -n 1p "$f" | grep -q '^user=www-data rule=[a-z_]* action=log argc=0$' || fail "hook env/user: $(sed -n 1p "$f")"
done
echo "  ok   - apache mod_php: syslog frames, the hook ran per event as www-data with the exact line:"
sed 's/^/           /' "$W/syslog.txt"
for f in "$W"/hooks/*.out; do sed -n 1p "$f" | sed 's/^/           /'; done

rm -f "$W"/hooks/*
run "$W/open/hook.sh"
sleep 0.5
stop
[ "$(grep -c . "$W/syslog.txt")" -eq 3 ] || fail "2: expected 3 syslog frames"
[ -z "$(ls "$W"/hooks/ 2>/dev/null)" ] || fail "2: a hook in a world-writable directory ran"
grep -q "\[log\] exec '$W/open/hook.sh' will not be run: its directory $W/open is group- or world-writable" "$W/ap.err" \
  || fail "2: no refusal note in the apache error log"
echo "  ok   - apache mod_php: a hook in a world-writable directory is refused, with a note in the error log"

kill "$LSN" 2>/dev/null || true
echo "PASS"
