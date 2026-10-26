#!/bin/sh
# §4.7 recycle-facet lab (host driver; design §4.7 + §5.6): when an ordinary
# script throws a poisoning-class fatal DURING EXECUTION (an uncaught Error, a
# parse/compile error, a failed require, max_execution_time) on an unpatched
# engine, does the opt-in recycle facet end that worker AFTER the request —
# before it can serve another and reach the CVE-2026-109619 consumer window —
# while OOM and startup fatals keep §4.6's immediate exit and warnings pass
# through untouched?
#
# No attack request is needed. The facet is OFF by default and armed only on
# UNPATCHED engines, so the container halves probe the engine and run the
# matching branch (see recycle_container.sh for fpm-nginx, recycle_apache_container.sh
# for Apache mod_php):
#
#   OBSERVE (recycle_observe=true): a would-recycle line (rule fatal_recycle,
#            action log) is written and the worker pid is UNCHANGED; the
#            producing request still returns PHP's own 500.
#   ENFORCE (recycle_on_fatal=true): a fatal_recycle block line is written, the
#            worker pid CHANGES on the next request (fresh worker), and the
#            producing request's 500 delivery is recorded per SAPI (the §4.7
#            flush-ordering finding). OOM and startup fatals STILL immediate-exit;
#            a warning still survives.
#   patched (8.2/8.3/8.4): the facet is off; the phpinfo row reads "off (patched)".
#
# Runs php-fpm behind a real nginx (sidecar sharing the netns) and Apache mod_php
# prefork pinned to a single child.
#
# Usage (repo root):
#   lab/integration/recycle.sh                      # 5.6 7.4 8.0 8.1 8.3, fpm+nginx and apache
#   lab/integration/recycle.sh 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5
#   SAPIS=fpm lab/integration/recycle.sh 7.4        # fpm+nginx only
#
# Needs the howdah-dev-php<minor> (and howdah-dev-apache-php<minor>) images and
# nginx:1.27-alpine. Results: one TSV row per check, kept in
# lab/integration/.recycle-out/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.6 7.4 8.0 8.1 8.3}"
SAPIS="${SAPIS:-fpm apache}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
OD="$ROOT/lab/integration/.recycle-out"
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

cleanup_fpm() {
  docker rm -f "howdah-rec-nginx-$1" "howdah-rec-$1" >/dev/null 2>&1 || true
}

for V in $VERSIONS; do
  F=$(feature "$V")
  VOUT="$OD/$V"; mkdir -p "$VOUT"; chmod 777 "$VOUT"
  : > "$VOUT/nginx.err"; : > "$VOUT/fpm.err"; chmod 666 "$VOUT/nginx.err" "$VOUT/fpm.err"

  if echo "$SAPIS" | tr ' ' '\n' | grep -qx fpm; then
    DEV="howdah-dev-php$V"
    if ! docker image inspect "$DEV" >/dev/null 2>&1; then
      printf '%s\tfpm-nginx\tall\tNOT-RUN\tno %s image\n' "$V" "$DEV" >> "$ALL"
    else
      echo "== $V: php-fpm behind nginx ($DEV + $NGINX_IMAGE) =="
      cleanup_fpm "$V"
      docker run -d --name "howdah-rec-$V" \
        -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-rec-target-$V":/tmp/t \
        "$DEV" sleep infinity >/dev/null
      docker run -d --name "howdah-rec-nginx-$V" --network "container:howdah-rec-$V" \
        -v "$VOUT":/out -v "$ROOT/lab/integration/refusal_nginx.conf":/etc/nginx/nginx.conf:ro \
        "$NGINX_IMAGE" >/dev/null
      docker exec -e CARGO_TARGET_DIR=/tmp/t "howdah-rec-$V" \
        sh /src/lab/integration/recycle_container.sh "$F" /out/rows.tsv \
        || printf '%s\tfpm-nginx\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
      cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
      cleanup_fpm "$V"
    fi
  fi

  if echo "$SAPIS" | tr ' ' '\n' | grep -qx apache; then
    APDEV="howdah-dev-apache-php$V"
    if ! docker image inspect "$APDEV" >/dev/null 2>&1; then
      printf '%s\tapache\tall\tNOT-RUN\tno %s image\n' "$V" "$APDEV" >> "$ALL"
    else
      echo "== $V: Apache mod_php prefork, one child ($APDEV) =="
      docker run --rm -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-rec-target-ap-$V":/tmp/t \
        -e CARGO_TARGET_DIR=/tmp/t "$APDEV" \
        sh /src/lab/integration/recycle_apache_container.sh "$F" /out/rows-ap.tsv \
        || printf '%s\tapache\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
      cat "$VOUT/rows-ap.tsv" >> "$ALL" 2>/dev/null || true
    fi
  fi
done

echo
echo "===================== recycle facet (§4.7) results ====================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   N/A: %d   SKIP: %d   NOT-RUN: %d\n", tot, c["PASS"], c["FAIL"], c["N/A"], c["SKIP"], c["NOT-RUN"]}' "$ALL"
echo "php-fpm / nginx logs per minor: $OD/<minor>/fpm.err, nginx.err"
if grep -q "	FAIL	" "$ALL"; then exit 1; fi
