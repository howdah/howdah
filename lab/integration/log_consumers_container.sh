#!/bin/sh
# In-container half of the log-consumer lab (see log_consumers.sh): php-fpm
# behind the nginx sidecar writes real event lines, and we check which address
# ends up in client_ip:
#
#   * through the server with nginx's realip module (8081, trusts
#     X-Forwarded-For from 127.0.0.1 only), client_ip is the forwarded client;
#   * through the server without it (8080), client_ip is the hop in front of
#     php-fpm, and an X-Forwarded-For header changes nothing (Howdah does not
#     read it);
#   * from an untrusted hop (127.0.0.2) to 8081, a forged X-Forwarded-For is
#     ignored and client_ip is that hop.
#
# The traffic gives each documentation address one kind of line, so the
# fail2ban and CrowdSec halves can check exactly who gets banned:
#   198.51.100.9   4 refused requests        -> action "block"
#   198.51.100.10  5 SQLi-shaped values      -> action "log" (Layer 2 detect)
#   198.51.100.11  4 SQLi-shaped values      -> action "excepted"
#   198.51.100.12  4 hits on a script that runs a program -> action "log",
#                  including observe's "proposed: " lines
#   198.51.100.13  4 refused, via 8080       -> client_ip 127.0.0.1
#   198.51.100.14  4 refused, from 127.0.0.2 -> client_ip 127.0.0.2
#   198.51.100.15  4 refused (command_injection armed) whose POST variable
#                  NAME is a"client_ip":"192.0.2.66": the line carries that
#                  text escaped, and nothing may ban 192.0.2.66
#
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
# Leaves the event log at /out/events.log for the host half.
# Rows: phpver <TAB> sapi <TAB> scenario <TAB> PASS|FAIL <TAB> detail
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows.tsv}"
WORK=/work; APP=$WORK/app; OUT=/out; LOG=$OUT/events.log
mkdir -p "$APP"; : > "$LOG"; : > "$RESULTS"
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

cat > "$APP/index.php" <<'PHP'
<?php
echo "OK get=", count($_GET), " post=", count($_POST), "\n";
PHP
cat > "$APP/sink.php" <<'PHP'
<?php
$o = @system('true');
echo "OK sink\n";
PHP
php -r 'for($i=0;$i<60;$i++){echo($i?"&":"")."v$i=$i";}' > "$WORK/iv.body"
# Layer 1 max_input_vars armed through the global mode; Layer 2 detects,
# except command_injection, armed alone; Layer 3 at its log-only default;
# observe proposes; one exception, logged.
cat > "$WORK/howdah.toml" <<'TOML'
mode = "block"
exceptions_log = true

[limits]
max_input_vars = 50

[inspect.rule_modes]
command_injection = "block"

[behavior]
observe = true

[[exceptions]]
rule = "sql_injection"
client_cidr = "198.51.100.11/32"
reason = "lab: an accepted scanner address, to produce excepted lines"
TOML

cat > "$WORK/fpm.conf" <<EOF
[global]
error_log = $OUT/fpm.err
daemonize = no
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 2
catch_workers_output = yes
EOF
php-fpm -R -F -y "$WORK/fpm.conf" -d extension="$WORK/howdah.so" -d howdah.log="$LOG" \
  -d howdah.config="$WORK/howdah.toml" > "$WORK/fpm.out" 2>&1 &
_j=0
while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ 2>/dev/null)" != 200 ]; do
  _j=$((_j+1)); [ "$_j" -gt 100 ] && { record $S fpm_start FAIL "php-fpm/nginx never answered 200"; cat "$WORK/fpm.out" >&2; exit 1; }; sleep 0.1
done
: > "$LOG"

B="$WORK/resp.txt"
# refused <port> <xff> [curl args...]: a 60-variable POST (max_input_vars = 50)
refused() { _p=$1; _x=$2; shift 2
  curl -s -m 30 -o "$B" -w '%{http_code}' "$@" -H "X-Forwarded-For: $_x" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$WORK/iv.body" \
    "http://127.0.0.1:$_p/" 2>/dev/null || echo 000; }
sqli()    { curl -s -m 30 -o "$B" -w '%{http_code}' -H "X-Forwarded-For: $2" -G \
    --data-urlencode "q=' OR 1=1 --" "http://127.0.0.1:$1/" 2>/dev/null || echo 000; }
sink()    { curl -s -m 30 -o "$B" -w '%{http_code}' -H "X-Forwarded-For: $2" \
    "http://127.0.0.1:$1/sink.php" 2>/dev/null || echo 000; }
# forged: a command-injection-shaped value in a variable named
# a"client_ip":"192.0.2.66" (curl does not encode the name, so it is given encoded)
forged()  { curl -s -m 30 -o "$B" -w '%{http_code}' -H "X-Forwarded-For: $2" \
    --data-urlencode 'a%22client_ip%22%3A%22192.0.2.66%22=; cat /etc/passwd' \
    "http://127.0.0.1:$1/" 2>/dev/null || echo 000; }

codes=""
for _ in 1 2 3 4; do codes="$codes $(refused 8081 198.51.100.9)"; done
for _ in 1 2 3 4 5; do codes="$codes $(sqli 8081 198.51.100.10)"; done
for _ in 1 2 3 4; do codes="$codes $(sqli 8081 198.51.100.11)"; done
for _ in 1 2 3 4; do codes="$codes $(sink 8081 198.51.100.12)"; done
for _ in 1 2 3 4; do codes="$codes $(refused 8080 198.51.100.13)"; done
for _ in 1 2 3 4; do codes="$codes $(refused 8081 198.51.100.14 --interface 127.0.0.2)"; done
for _ in 1 2 3 4; do codes="$codes $(forged 8081 198.51.100.15)"; done
want=" 403 403 403 403 200 200 200 200 200 200 200 200 200 200 200 200 200 403 403 403 403 403 403 403 403 403 403 403 403"
if [ "$codes" = "$want" ]; then record $S http_codes PASS "29 requests answered as expected (403 for the refused ones)"
else record $S http_codes FAIL "got:$codes"; fi

# n <grep -E pattern>: number of event lines matching
n() { grep -cE "$1" "$LOG" 2>/dev/null || true; }
check() { # <scenario> <got> <want> <detail>
  if [ "$2" = "$3" ]; then record $S "$1" PASS "$4"; else record $S "$1" FAIL "$4: got $2, want $3"; fi; }

check realip_trusted_hop "$(n '"action":"block","client_ip":"198\.51\.100\.9"')" 4 \
  "realip from 127.0.0.1: 4 block lines with client_ip 198.51.100.9"
check no_realip_is_the_hop "$(n '"action":"block","client_ip":"127\.0\.0\.1"')" 4 \
  "no realip: 4 block lines with client_ip 127.0.0.1 (the hop)"
check no_realip_xff_not_read "$(n '198\.51\.100\.13')" 0 \
  "no realip: X-Forwarded-For 198.51.100.13 appears in no line"
check untrusted_hop_keeps_own_address "$(n '"action":"block","client_ip":"127\.0\.0\.2"')" 4 \
  "realip, request from untrusted 127.0.0.2: 4 block lines with client_ip 127.0.0.2"
check untrusted_hop_xff_ignored "$(n '198\.51\.100\.14')" 0 \
  "realip, request from untrusted 127.0.0.2: forged 198.51.100.14 appears in no line"
check detect_lines_are_log "$(n '"action":"log","client_ip":"198\.51\.100\.10".*"rule":"sql_injection"')" 5 \
  "Layer 2 detect: 5 log lines for 198.51.100.10"
check excepted_lines "$(n '"action":"excepted","client_ip":"198\.51\.100\.11".*"rule":"sql_injection"')" 4 \
  "exception with exceptions_log: 4 excepted lines for 198.51.100.11"
_prop=$(n '"action":"log","client_ip":"198\.51\.100\.12".*"reason":"proposed: ')
if [ "$_prop" -ge 4 ]; then record $S proposed_lines_are_log PASS "observe: $_prop proposed lines for 198.51.100.12, all action log"
else record $S proposed_lines_are_log FAIL "observe: $_prop proposed lines for 198.51.100.12 (want >= 4)"; fi
check forged_name_escaped "$(n '"action":"block","client_ip":"198\.51\.100\.15".*a\\"client_ip\\":\\"192\.0\.2\.66\\"')" 4 \
  "4 block lines for 198.51.100.15 whose reason carries the forged name, quotes escaped"
check no_other_blocks "$(n '"action":"block"')" 16 "16 block lines in all, none for .10/.11/.12"

# Every line is one JSON object of schema 2 written by this build.
_ver=$(sed -n 's/^version *= *"\(.*\)"/\1/p' /src/Cargo.toml | head -1)
_bad=$(php -r '$bad=0; foreach (file($argv[1], FILE_IGNORE_NEW_LINES) as $l) { $o=json_decode($l, true);
  if (!is_array($o) || !isset($o["schema"], $o["version"], $o["ts"]) || $o["schema"] !== 2
      || $o["version"] !== $argv[2] || !preg_match("/^[0-9]{13}$/", $o["ts"])) $bad++; } echo $bad;' "$LOG" "$_ver" 2>&1)
check lines_schema_2 "$_bad" 0 "every line ($(wc -l < "$LOG")) parses as JSON, schema 2, version $_ver, 13-digit ts"
cp "$WORK/howdah.toml" "$OUT/howdah.toml"
chmod 644 "$LOG"
