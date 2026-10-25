#!/bin/sh
# Log-consumer lab (host driver): real Howdah event lines, read by the tools
# docs/integrations/ ships configuration for, plus the client-address
# behaviour docs/integrations/README.md documents.
#
#   1. php-fpm behind nginx (log_consumers_container.sh): which address lands
#      in client_ip with and without nginx's realip module, and a known mix of
#      block / log / excepted / proposed lines from documentation addresses.
#   2. fail2ban (docs/integrations/fail2ban/): fail2ban-regex matches exactly
#      the block lines, also in the syslog form (rsyslog's traditional and
#      RFC 3339 prefixes), and a live fail2ban with the shipped filter and jail
#      (only banaction swapped for "dummy": no firewall in a container) bans
#      exactly the addresses with 3+ blocks, and never a proxy address, a
#      log-only, excepted or proposed address, or one forged inside a value.
#   3. CrowdSec (docs/integrations/crowdsec/): every line parses, in the file
#      and the syslog form (through the hub's syslog-logs parser), and a live
#      agent with the shipped acquisition, parser and scenario makes ban
#      decisions for exactly those addresses.
#   4. Apache mod_php (log_consumers_apache_container.sh): client_ip with and
#      without mod_remoteip.
#
# Usage (repo root): lab/integration/log_consumers.sh [minor]   (default 8.3)
# Needs the howdah-dev-php<minor> and howdah-dev-apache-php<minor> images
# (lab/images/dev.Dockerfile), nginx:1.27-alpine, and, the first time, network
# access to pull crazymax/fail2ban:1.1.0 and crowdsecurity/crowdsec:v1.7.0.
# Results: one TSV row per check, kept in lab/integration/.log-consumers-out/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
V="${1:-8.3}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
F2B_IMAGE="${F2B_IMAGE:-crazymax/fail2ban:1.1.0}"
CS_IMAGE="${CS_IMAGE:-crowdsecurity/crowdsec:v1.7.0}"
INT="$ROOT/docs/integrations"
OD="$ROOT/lab/integration/.log-consumers-out"
VOUT="$OD/$V"
rm -rf "$VOUT"; mkdir -p "$VOUT"; chmod 777 "$OD" "$VOUT"
ALL="$OD/results.tsv"; : > "$ALL"
: > "$VOUT/nginx.err"; : > "$VOUT/fpm.err"; chmod 666 "$VOUT/nginx.err" "$VOUT/fpm.err"
case "$V" in 5.*) FEAT=php5 ;; 7.*) FEAT=php7 ;; *) FEAT=php8 ;; esac

C_FPM="howdah-lc-$V"; C_NGX="howdah-lc-nginx-$V"; C_F2B="howdah-lc-f2b"; C_CS="howdah-lc-crowdsec"
cleanup() { docker rm -f "$C_NGX" "$C_FPM" "$C_F2B" "$C_CS" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
row() { printf '%s\t%s\t%s\t%s\t%s\n' "$V" "$1" "$2" "$3" "$4" >> "$ALL"; echo "  [$1] $2 $3: $4"; }

# ---- 1. capture: php-fpm behind nginx ----------------------------------------
echo "== $V: php-fpm behind nginx (howdah-dev-php$V + $NGINX_IMAGE) =="
docker run -d --name "$C_FPM" -v "$ROOT":/src:ro -v "$VOUT":/out \
  -v "howdah-refusal-target-$V":/tmp/t "howdah-dev-php$V" sleep infinity >/dev/null
docker run -d --name "$C_NGX" --network "container:$C_FPM" -v "$VOUT":/out \
  -v "$ROOT/lab/integration/log_consumers_nginx.conf":/etc/nginx/nginx.conf:ro "$NGINX_IMAGE" >/dev/null
docker exec -e CARGO_TARGET_DIR=/tmp/t "$C_FPM" sh /src/lab/integration/log_consumers_container.sh "$FEAT" /out/rows.tsv \
  || row fpm-nginx driver FAIL "container script exited non-zero"
cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
docker rm -f "$C_NGX" "$C_FPM" >/dev/null 2>&1 || true
EV="$VOUT/events.log"
[ -s "$EV" ] || { row capture events FAIL "no event log captured"; cat "$ALL"; exit 1; }

# The addresses the fail2ban jail and the CrowdSec scenario must ban: 3+ block
# lines each, not loopback (the stand-in for a proxy). Anything else banned is
# a failure.
WANT_BANNED="198.51.100.15 198.51.100.9"
NEVER="198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13 198.51.100.14 192.0.2.66"

# ---- 2. fail2ban ---------------------------------------------------------------
echo "== fail2ban ($F2B_IMAGE) =="
F2B="$VOUT/f2b"; mkdir -p "$F2B/log"; chmod 777 "$F2B/log"
docker run --rm --entrypoint fail2ban-regex -v "$INT/fail2ban":/f2b:ro -v "$VOUT":/d:ro "$F2B_IMAGE" \
  -o ip /d/events.log /f2b/filter.d/howdah.conf > "$F2B/regex-ips.txt" 2>&1 || true
got=$(sort "$F2B/regex-ips.txt" | uniq -c | awk '{printf "%s=%s ", $2, $1}')
want="127.0.0.1=4 127.0.0.2=4 198.51.100.15=4 198.51.100.9=4 "
if [ "$got" = "$want" ]; then row fail2ban regex_matches_block_lines PASS "fail2ban-regex: $got(the 16 block lines, no other)"
else row fail2ban regex_matches_block_lines FAIL "fail2ban-regex: got '$got' want '$want'"; fi
# The same lines in the syslog form as rsyslog writes them to a file, with its
# traditional and its RFC 3339 timestamp (the prefix is added here; the JSON is
# the captured line).
sed 's/^/Oct 24 18:02:54 web1 howdah[1429]: /' "$EV" > "$VOUT/syslog-traditional.log"
sed 's/^/2026-10-24T18:02:54.141000+00:00 web1 howdah[1429]: /' "$EV" > "$VOUT/syslog-rfc3339.log"
for form in traditional rfc3339; do
  docker run --rm --entrypoint fail2ban-regex -v "$INT/fail2ban":/f2b:ro -v "$VOUT":/d:ro "$F2B_IMAGE" \
    -o ip "/d/syslog-$form.log" /f2b/filter.d/howdah.conf > "$F2B/regex-ips-$form.txt" 2>&1 || true
  got=$(sort "$F2B/regex-ips-$form.txt" | uniq -c | awk '{printf "%s=%s ", $2, $1}')
  if [ "$got" = "$want" ]; then row fail2ban "regex_syslog_$form" PASS "syslog form ($form timestamp): $got"
  else row fail2ban "regex_syslog_$form" FAIL "syslog form ($form timestamp): got '$got' want '$want'"; fi
done

# Live: the shipped filter and jail; the lab only swaps banaction for "dummy".
printf '[howdah]\nbanaction = dummy\n' > "$F2B/zz-lab.local"
: > "$F2B/log/events.log"; chmod 666 "$F2B/log/events.log"
docker run -d --name "$C_F2B" --entrypoint fail2ban-client \
  -v "$INT/fail2ban/filter.d/howdah.conf":/etc/fail2ban/filter.d/howdah.conf:ro \
  -v "$INT/fail2ban/jail.d/howdah.conf":/etc/fail2ban/jail.d/howdah.conf:ro \
  -v "$F2B/zz-lab.local":/etc/fail2ban/jail.d/zz-lab.local:ro \
  -v "$F2B/log":/var/log/howdah "$F2B_IMAGE" -x -f start >/dev/null
i=0; until docker exec "$C_F2B" fail2ban-client status howdah >/dev/null 2>&1; do
  i=$((i+1)); [ "$i" -gt 60 ] && break; sleep 1; done
cat "$EV" >> "$F2B/log/events.log"
banned=""; i=0
while [ "$i" -lt 30 ]; do
  banned=$(docker exec "$C_F2B" fail2ban-client status howdah 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p' | tr ' \t' '\n\n' | grep . | sort | tr '\n' ' ' | sed 's/ $//')
  [ "$banned" = "$WANT_BANNED" ] && break
  i=$((i+1)); sleep 1
done
docker exec "$C_F2B" fail2ban-client status howdah > "$F2B/status.txt" 2>&1 || true
docker logs "$C_F2B" > "$F2B/fail2ban.log" 2>&1 || true
if [ "$banned" = "$WANT_BANNED" ]; then row fail2ban live_bans PASS "banned exactly: $banned (127.0.0.x in ignoreip; .10 log, .11 excepted, .12 proposed, 192.0.2.66 forged: not banned)"
else row fail2ban live_bans FAIL "banned '$banned', want '$WANT_BANNED' (see $F2B/status.txt)"; fi
docker rm -f "$C_F2B" >/dev/null 2>&1 || true

# ---- 3. CrowdSec ---------------------------------------------------------------
echo "== CrowdSec ($CS_IMAGE) =="
CS="$VOUT/crowdsec"; mkdir -p "$CS/log"; chmod 777 "$CS/log"
: > "$CS/log/events.log"; chmod 666 "$CS/log/events.log"
cp "$EV" "$CS/captured.log"
cp "$VOUT/syslog-traditional.log" "$VOUT/syslog-rfc3339.log" "$CS/"
docker run -d --name "$C_CS" -e DISABLE_ONLINE_API=true -e CROWDSEC_BYPASS_DB_VOLUME_CHECK=true \
  -v "$INT/crowdsec/parsers/s01-parse/howdah-logs.yaml":/etc/crowdsec/parsers/s01-parse/howdah-logs.yaml:ro \
  -v "$INT/crowdsec/scenarios/howdah-blocked.yaml":/etc/crowdsec/scenarios/howdah-blocked.yaml:ro \
  -v "$INT/crowdsec/acquis.d/howdah.yaml":/etc/crowdsec/acquis.d/howdah.yaml:ro \
  -v "$CS/log":/var/log/howdah -v "$CS":/d:ro "$CS_IMAGE" >/dev/null
i=0; until docker exec "$C_CS" cscli lapi status >/dev/null 2>&1; do
  i=$((i+1)); [ "$i" -gt 90 ] && break; sleep 2; done
# wait for the agent to tail the file (the "Starting processing data" line)
i=0; until docker logs "$C_CS" 2>&1 | grep -q 'Starting processing data'; do
  i=$((i+1)); [ "$i" -gt 60 ] && break; sleep 1; done
sleep 2
# every captured line parses (explain runs the same parsers over the file; its
# output also shows each overflow as an extra entry with an empty "line:")
docker exec "$C_CS" cscli explain --file /d/captured.log --type howdah > "$CS/explain.txt" 2>&1 || true
nl=$(wc -l < "$EV" | tr -d ' ')
seen=$(grep -c '^line: {' "$CS/explain.txt" || true)
bad=$(grep -c 'parser failure' "$CS/explain.txt" || true)
hl=$(grep -c '🟢 howdah/howdah-logs' "$CS/explain.txt" || true)
if [ "$seen" = "$nl" ] && [ "$hl" = "$nl" ] && [ "$bad" = 0 ]; then row crowdsec explain_all_lines_parse PASS "cscli explain: all $nl lines parsed by howdah/howdah-logs, no parser failure"
else row crowdsec explain_all_lines_parse FAIL "cscli explain: $seen of $nl lines shown, $hl by howdah-logs, $bad parser failures (see $CS/explain.txt)"; fi
# the syslog form, read the way a syslog acquisition reads it (type syslog)
for form in traditional rfc3339; do
  docker exec "$C_CS" cscli explain --file "/d/syslog-$form.log" --type syslog > "$CS/explain-syslog-$form.txt" 2>&1 || true
  sl=$(grep -c '🟢 crowdsecurity/syslog-logs' "$CS/explain-syslog-$form.txt" || true)
  hl=$(grep -c '🟢 howdah/howdah-logs' "$CS/explain-syslog-$form.txt" || true)
  bad=$(grep -c 'parser failure' "$CS/explain-syslog-$form.txt" || true)
  if [ "$sl" = "$nl" ] && [ "$hl" = "$nl" ] && [ "$bad" = 0 ]; then row crowdsec "explain_syslog_$form" PASS "syslog form ($form timestamp): all $nl lines through syslog-logs then howdah-logs"
  else row crowdsec "explain_syslog_$form" FAIL "syslog form ($form): syslog-logs $sl, howdah-logs $hl of $nl, $bad failures (see $CS/explain-syslog-$form.txt)"; fi
done
# live: append the lines to the acquired file and wait for decisions
cat "$EV" >> "$CS/log/events.log"
dec=""; i=0
while [ "$i" -lt 45 ]; do
  dec=$(docker exec "$C_CS" cscli decisions list -o raw 2>/dev/null | grep -o 'Ip:[0-9a-fA-F.:]*' | sed 's/^Ip://' | sort -u | tr '\n' ' ' | sed 's/ $//')
  [ "$dec" = "$WANT_BANNED" ] && break
  i=$((i+1)); sleep 1
done
docker exec "$C_CS" cscli decisions list > "$CS/decisions.txt" 2>&1 || true
docker exec "$C_CS" cscli alerts list > "$CS/alerts.txt" 2>&1 || true
docker logs "$C_CS" > "$CS/crowdsec.log" 2>&1 || true
if [ "$dec" = "$WANT_BANNED" ] && grep -q 'howdah/howdah-blocked' "$CS/alerts.txt"; then
  row crowdsec live_decisions PASS "ban decisions exactly for: $dec, from howdah/howdah-blocked (loopback whitelisted; .10/.11/.12/192.0.2.66 none)"
else row crowdsec live_decisions FAIL "decisions '$dec', want '$WANT_BANNED' (see $CS/decisions.txt, alerts.txt)"; fi
docker rm -f "$C_CS" >/dev/null 2>&1 || true

# ---- 4. Apache mod_php with and without mod_remoteip --------------------------
echo "== $V: Apache mod_php (howdah-dev-apache-php$V) =="
docker run --rm -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-refusal-target-ap-$V":/tmp/t \
  -e CARGO_TARGET_DIR=/tmp/t "howdah-dev-apache-php$V" \
  sh /src/lab/integration/log_consumers_apache_container.sh "$FEAT" /out/rows-ap.tsv \
  || row apache driver FAIL "container script exited non-zero"
cat "$VOUT/rows-ap.tsv" >> "$ALL" 2>/dev/null || true

for ip in $NEVER; do
  if grep -q "$ip" "$F2B/status.txt" "$CS/decisions.txt" 2>/dev/null; then row all "never_banned_$ip" FAIL "$ip appears in a fail2ban or CrowdSec ban"; fi
done

echo
echo "=================== log-consumer results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d\n", tot, c["PASS"], c["FAIL"]}' "$ALL"
echo "event log: $EV"
if grep -q "	FAIL	" "$ALL"; then exit 1; fi
