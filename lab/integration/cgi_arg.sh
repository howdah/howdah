#!/bin/sh
# php-cgi argument-injection lab (host driver): does a CVE-2012-1823 /
# CVE-2024-4577 shaped query string get a clean 403 before the script runs, and
# does ordinary traffic still get through? Layer 2 `cgi_arg_injection`, on and
# enforcing by default.
#
# Per PHP minor it puts a real nginx in front of php-fpm (a sidecar container
# sharing the php-fpm container's network namespace, as refusal.sh does) and
# runs lab/integration/cgi_arg_container.sh:
#
#   * malicious corpus (public PoC shapes, the %2d and soft-hyphen %AD / %C2%AD
#     variants, directive tokens, flags): every request must answer 403 with the
#     "Howdah blocked" body and a request id, leave the app's marker file
#     unwritten, keep the single worker's pid, and add no "readv() failed" /
#     "Connection reset" line to nginx's error log -- under the default config,
#     under howdah.mode = detect (the shipped ini default) and under block;
#   * BENIGN corpus (search strings, pagination, base64/JWT tokens, framework
#     arrays, '='-less route queries, UTF-8 text, dash-leading words): ZERO
#     blocks and zero cgi_arg_injection events. This is the mandatory
#     false-positive gate for an on-by-default blocking rule;
#   * the knobs ([inspect] cgi_arg = detect / off, howdah.mode = off, an
#     [[exceptions]] client_cidr) and the byte-exact cases over direct FastCGI.
#
# Usage (repo root):
#   lab/integration/cgi_arg.sh                      # 5.6 7.4 8.3
#   lab/integration/cgi_arg.sh 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5
#
# Needs the howdah-dev-php<minor> images from lab/images/dev.Dockerfile and the
# nginx:1.27-alpine image (refusal_nginx.conf is the sidecar config). Results:
# one TSV row per check, printed at the end and kept in
# lab/integration/.cgi_arg-out/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.6 7.4 8.3}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
OD="$ROOT/lab/integration/.cgi_arg-out"
mkdir -p "$OD"; chmod 777 "$OD"
ALL="$OD/results.tsv"; : > "$ALL"

feature() {
  case "$1" in
    5.*) echo php5 ;;
    7.*) echo php7 ;;
    8.*) echo php8 ;;
    *) echo php8 ;;
  esac
}

cleanup() {
  docker rm -f "howdah-cgiarg-nginx-$1" "howdah-cgiarg-$1" >/dev/null 2>&1 || true
}

for V in $VERSIONS; do
  F=$(feature "$V")
  VOUT="$OD/$V"; mkdir -p "$VOUT"; chmod 777 "$VOUT"
  : > "$VOUT/nginx.err"; : > "$VOUT/fpm.err"; chmod 666 "$VOUT/nginx.err" "$VOUT/fpm.err"
  DEV="howdah-dev-php$V"
  if ! docker image inspect "$DEV" >/dev/null 2>&1; then
    printf '%s\tfpm-nginx\tall\tSKIP\tno %s image\n' "$V" "$DEV" >> "$ALL"
    continue
  fi
  echo "== $V: php-fpm behind nginx ($DEV + $NGINX_IMAGE) =="
  cleanup "$V"
  docker run -d --name "howdah-cgiarg-$V" \
    -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-refusal-target-$V":/tmp/t \
    "$DEV" sleep infinity >/dev/null
  docker run -d --name "howdah-cgiarg-nginx-$V" --network "container:howdah-cgiarg-$V" \
    -v "$VOUT":/out -v "$ROOT/lab/integration/refusal_nginx.conf":/etc/nginx/nginx.conf:ro \
    "$NGINX_IMAGE" >/dev/null
  docker exec -e CARGO_TARGET_DIR=/tmp/t "howdah-cgiarg-$V" \
    sh /src/lab/integration/cgi_arg_container.sh "$F" /out/rows.tsv \
    || printf '%s\tfpm-nginx\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
  cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
  cleanup "$V"
done

echo
echo "=================== php-cgi argument-injection results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   SKIP: %d\n", tot, c["PASS"], c["FAIL"], c["SKIP"]}' "$ALL"

# Per-version summary: malicious refused / benign blocked (corpus rows carry "N/M ...").
echo
printf '%-8s %-26s %-26s %s\n' "PHP" "malicious refused (default)" "benign blocked (default)" "all rows"
for V in $VERSIONS; do
  mal=$(awk -F'\t' -v v="$V" 'index($1, v".")==1 && $3=="malicious_corpus_default" {print $4": "$5}' "$ALL" | sed 's/ refused 403.*//; s/ ran .*//' | head -1)
  ben=$(awk -F'\t' -v v="$V" 'index($1, v".")==1 && $3=="benign_corpus_default" {print $4": "$5}' "$ALL" | sed 's/, [0-9]*\/[0-9]* ran.*//' | head -1)
  rows=$(awk -F'\t' -v v="$V" 'index($1, v".")==1 || $1==v {t++; if($4=="PASS")p++; if($4=="FAIL")f++} END{printf "%d rows, %d PASS, %d FAIL", t, p, f}' "$ALL")
  printf '%-8s %-26s %-26s %s\n' "$V" "${mal:-n/a}" "${ben:-n/a}" "$rows"
done
echo "php-fpm / nginx logs per minor: $OD/<minor>/fpm.err, nginx.err"
if grep -q "	FAIL	" "$ALL"; then exit 1; fi
