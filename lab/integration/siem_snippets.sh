#!/bin/sh
# Runs the docs/integrations snippets in the real tools, against real event
# lines (captured from log_contract.sh's php-fpm scenario):
#   - Promtail: `--stdin --dry-run` with docs/integrations/promtail-howdah.yaml;
#     checks the labels and that the entry timestamp comes from `ts`.
#   - Wazuh: wazuh-logtest in a manager container with the decoder and rules
#     from docs/integrations/wazuh/; checks the event-file (json) and the
#     syslog form both reach rule 100703 (block) / 100702 (log).
# Needs Docker and, the first time, network access to pull the two images.
#
# Usage (repo root): lab/integration/siem_snippets.sh
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INT="$ROOT/docs/integrations"
PROMTAIL="${PROMTAIL:-grafana/promtail:3.5.1}"
WAZUH="${WAZUH:-wazuh/wazuh-manager:4.12.0}"
TMP=$(mktemp -d)
NAME="howdah-siem-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

B='{"action":"block","client_ip":"203.0.113.7","layer":1,"method":"POST","reason":"multipart part count exceeds limit","request_id":"11eccf6d90ad2987d","rule":"max_parts","schema":2,"ts":"1792864974141","uri":"/index.php","version":"1.5.0"}'
L2='{"action":"log","client_ip":"203.0.113.7","layer":2,"method":"GET","reason":"sql_injection pattern in get variable '"'"'q'"'"'","request_id":"1a2d239820e2f06bc","rule":"sql_injection","schema":2,"ts":"1792864974146","uri":"/index.php","version":"1.5.0"}'
L3='{"action":"log","client_ip":"203.0.113.7","layer":3,"method":"GET","reason":"non-allowlisted command via system","request_id":"1fa7c36ea3c170856","rule":"command_exec","schema":2,"ts":"1792864974151","uri":"/index.php","version":"1.5.0"}'

fail() { echo "FAIL: $1"; [ -f "$TMP/out" ] && tail -40 "$TMP/out"; exit 1; }

echo "== Promtail ($PROMTAIL) =="
printf '%s\n%s\n%s\n' "$B" "$L2" "$L3" > "$TMP/events.jsonl"
docker run --rm -i -v "$INT":/cfg:ro "$PROMTAIL" -config.file=/cfg/promtail-howdah.yaml --stdin --dry-run \
  < "$TMP/events.jsonl" > "$TMP/out" 2>&1 || fail "promtail exited non-zero"
grep -F '2026-10-24T18:02:54.141+0000' "$TMP/out" | grep -F 'action="block"' | grep -F 'layer="1"' \
  | grep -qF 'rule="max_parts"' || fail "promtail: block line labels/timestamp"
grep -F '2026-10-24T18:02:54.146+0000' "$TMP/out" | grep -F 'layer="2"' | grep -qF 'rule="sql_injection"' \
  || fail "promtail: layer-2 line"
grep -F '2026-10-24T18:02:54.151+0000' "$TMP/out" | grep -F 'layer="3"' | grep -qF 'rule="command_exec"' \
  || fail "promtail: layer-3 line"
grep '^2026-10-24T18:02:54' "$TMP/out"
echo "  ok   - promtail: ts -> entry time, rule/action/layer labels"

echo "== Wazuh ($WAZUH) =="
docker run -d --name "$NAME" \
  -v "$INT/wazuh/howdah_decoders.xml":/var/ossec/etc/decoders/howdah_decoders.xml:ro \
  -v "$INT/wazuh/howdah_rules.xml":/var/ossec/etc/rules/howdah_rules.xml:ro \
  "$WAZUH" >/dev/null
i=0
until docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; do
  i=$((i+1))
  if [ "$i" -gt 90 ]; then docker logs --tail 20 "$NAME" > "$TMP/out" 2>&1; fail "wazuh-analysisd did not start (rules or decoder rejected?)"; fi
  sleep 2
done
printf '%s\n%s\nOct 24 18:02:54 web1 howdah[1429]: %s\nOct 24 18:02:54 web1 howdah[1444]: %s\n' "$B" "$L2" "$B" "$L3" \
  | docker exec -i "$NAME" /var/ossec/bin/wazuh-logtest > "$TMP/out" 2>&1 || fail "wazuh-logtest exited non-zero"
# Four events, in order: json block, json log, syslog block, syslog log.
grep -E "^\s+(name|id|level|description):" "$TMP/out" > "$TMP/summary"
[ "$(grep -c "description: 'Howdah blocked max_parts (layer 1) on /index.php'" "$TMP/summary")" -eq 2 ] \
  || fail "wazuh: block lines did not reach rule 100703"
grep -q "description: 'Howdah logged sql_injection (layer 2) on /index.php'" "$TMP/summary" || fail "wazuh: json log line"
grep -q "description: 'Howdah logged command_exec (layer 3) on /index.php'" "$TMP/summary" || fail "wazuh: syslog log line"
[ "$(grep -c "name: 'howdah'" "$TMP/summary")" -eq 2 ] || fail "wazuh: syslog lines not decoded by the howdah decoder"
[ "$(grep -c "name: 'json'" "$TMP/summary")" -eq 2 ] || fail "wazuh: file lines not decoded by the json decoder"
[ "$(grep -c "id: '100703'" "$TMP/summary")" -eq 2 ] && [ "$(grep -c "id: '100702'" "$TMP/summary")" -eq 2 ] \
  || fail "wazuh: rule ids"
sed 's/^/  /' "$TMP/summary"
echo "  ok   - wazuh: json and syslog forms decoded; block -> 100703 (level 10), log -> 100702 (level 5)"
echo "PASS"
