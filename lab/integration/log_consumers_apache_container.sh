#!/bin/sh
# Apache mod_php half of the log-consumer lab (see log_consumers.sh): with
# mod_remoteip trusting X-Forwarded-For from 127.0.0.1 only (the snippet in
# docs/integrations/README.md), client_ip is the forwarded client; from any
# other hop a forged header is ignored; without mod_remoteip, client_ip is
# the hop and the header changes nothing.
#
# Args: $1 cargo feature (php7|php8); $2 results TSV.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows-ap.tsv}"
WORK=/tmp/lc-ap; LOG="$WORK/events.log"; DOCROOT=/var/www/html
mkdir -p "$WORK"; : > "$LOG"; : > "$RESULTS"
# Apache children run as www-data and append to the log.
chmod 777 "$WORK"; chmod 666 "$LOG"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=apache
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$1" "$2" "$3" "$4" >> "$RESULTS"; echo "  [$PHPVER $1] $2 $3: $4" >&2; }

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/t}"
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2; record $S build FAIL "cargo build failed"; exit 1; fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

printf '<?php\necho "OK post=", count($_POST), "\\n";\n' > "$DOCROOT/index.php"
php -r 'for($i=0;$i<60;$i++){echo($i?"&":"")."v$i=$i";}' > "$WORK/iv.body"
printf 'mode = "block"\n[limits]\nmax_input_vars = 50\n' > "$WORK/howdah.toml"
CONFD=$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;' 2>/dev/null); [ -z "$CONFD" ] && CONFD=/usr/local/etc/php/conf.d
mkdir -p "$CONFD"
{ echo "extension=$WORK/howdah.so"; echo "howdah.log=$LOG"; echo "howdah.config=$WORK/howdah.toml"; } > "$CONFD/zz-howdah.ini"

AP=apache2ctl; command -v apache2ctl >/dev/null 2>&1 || AP=apachectl
ap_start() { $AP start 2>"$WORK/ap.err"; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "apache down" >&2; cat "$WORK/ap.err" >&2; return 1; }; sleep 0.1; done; }
ap_stop() { $AP stop 2>/dev/null; _j=0; while curl -s -m 1 -o /dev/null http://127.0.0.1/ 2>/dev/null; do _j=$((_j+1)); [ "$_j" -gt 60 ] && break; sleep 0.1; done; }
refused() { _x=$1; shift
  curl -s -m 30 -o /dev/null -w '%{http_code}' "$@" -H "X-Forwarded-For: $_x" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @"$WORK/iv.body" \
    http://127.0.0.1/ 2>/dev/null || echo 000; }
n() { grep -cE "$1" "$LOG" 2>/dev/null || true; }
check() { if [ "$2" = "$3" ]; then record $S "$1" PASS "$4"; else record $S "$1" FAIL "$4: got $2, want $3"; fi; }

# ---- without mod_remoteip ----------------------------------------------------
ap_start || { record $S ap_start FAIL "apache down"; exit 1; }
: > "$LOG"
c1=$(refused 198.51.100.21)
check no_remoteip_is_the_hop "$c1 $(n '"action":"block","client_ip":"127\.0\.0\.1"') $(n '198\.51\.100\.21')" "403 1 0" \
  "no mod_remoteip: 403, client_ip 127.0.0.1, X-Forwarded-For 198.51.100.21 in no line"
ap_stop

# ---- with mod_remoteip (the README snippet) ----------------------------------
a2enmod remoteip >/dev/null 2>&1
cat > /etc/apache2/conf-enabled/zz-remoteip.conf <<'EOF'
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 127.0.0.1
EOF
ap_start || { record $S ap_start_remoteip FAIL "apache down with mod_remoteip"; exit 1; }
: > "$LOG"
c2=$(refused 198.51.100.20)
check remoteip_trusted_hop "$c2 $(n '"action":"block","client_ip":"198\.51\.100\.20"')" "403 1" \
  "mod_remoteip from 127.0.0.1: 403, client_ip 198.51.100.20"
c3=$(refused 198.51.100.22 --interface 127.0.0.2)
check remoteip_untrusted_hop "$c3 $(n '"action":"block","client_ip":"127\.0\.0\.2"') $(n '198\.51\.100\.22')" "403 1 0" \
  "mod_remoteip, request from untrusted 127.0.0.2: client_ip 127.0.0.2, forged 198.51.100.22 in no line"
ap_stop
