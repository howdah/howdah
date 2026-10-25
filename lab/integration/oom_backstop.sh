#!/bin/sh
# Out-of-memory backstop lab (host driver; design §4.6 + §5.5): does Howdah end
# the PHP worker when the engine runs out of memory, before code runs on the
# half-built request state, and only where it should?
#
# No attack request is needed — an ordinary script that allocates past a low
# memory_limit. The backstop is armed only on UNPATCHED engines (upstream's fix
# registers the memory_hard_limit_percent ini directive), so the container half
# probes the engine and runs the matching branch (see oom_backstop_container.sh):
#
#   unpatched: oom.php _exit()s the worker (nginx 502), an out_of_memory block
#              line is logged, the worker pid changes, a follow-up is 200; a
#              warning and an uncaught exception do NOT exit; oom_exit = false
#              restores PHP's own behavior; the CLI SAPI is off; the phpinfo row
#              reads "armed".
#   patched:   the backstop stays off and the phpinfo row reads "off (patched)".
#
# Runs php-fpm behind a real nginx (sidecar sharing the netns) and Apache
# mod_php prefork. Testing against *vulnerable* PHP versions needs no special
# fixture here; the ordinary dev images suffice.
#
# Usage (repo root):
#   lab/integration/oom_backstop.sh                 # 5.6 7.4 8.0 8.1 8.3, fpm+nginx and apache
#   lab/integration/oom_backstop.sh 8.1             # one minor
#   SAPIS=fpm lab/integration/oom_backstop.sh 7.4   # fpm+nginx only
#
# Needs the howdah-dev-php<minor> (and howdah-dev-apache-php<minor>) images from
# lab/images and the nginx:1.27-alpine image. Results: one TSV row per check,
# printed at the end and kept in lab/integration/.oom-backstop-out/.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.6 7.4 8.0 8.1 8.3}"
SAPIS="${SAPIS:-fpm apache}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
OD="$ROOT/lab/integration/.oom-backstop-out"
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
  docker rm -f "howdah-oom-nginx-$1" "howdah-oom-$1" >/dev/null 2>&1 || true
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
      docker run -d --name "howdah-oom-$V" \
        -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-oom-target-$V":/tmp/t \
        "$DEV" sleep infinity >/dev/null
      docker run -d --name "howdah-oom-nginx-$V" --network "container:howdah-oom-$V" \
        -v "$VOUT":/out -v "$ROOT/lab/integration/refusal_nginx.conf":/etc/nginx/nginx.conf:ro \
        "$NGINX_IMAGE" >/dev/null
      docker exec -e CARGO_TARGET_DIR=/tmp/t "howdah-oom-$V" \
        sh /src/lab/integration/oom_backstop_container.sh "$F" /out/rows.tsv \
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
      echo "== $V: Apache mod_php prefork ($APDEV) =="
      docker run --rm -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-oom-target-ap-$V":/tmp/t \
        -e CARGO_TARGET_DIR=/tmp/t "$APDEV" \
        sh /src/lab/integration/oom_backstop_apache_container.sh "$F" /out/rows-ap.tsv \
        || printf '%s\tapache\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
      cat "$VOUT/rows-ap.tsv" >> "$ALL" 2>/dev/null || true
    fi
  fi
done

echo
echo "=================== out-of-memory backstop results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   SKIP: %d   NOT-RUN: %d\n", tot, c["PASS"], c["FAIL"], c["SKIP"], c["NOT-RUN"]}' "$ALL"
echo "php-fpm / nginx logs per minor: $OD/<minor>/fpm.err, nginx.err"
if grep -q "	FAIL	" "$ALL"; then exit 1; fi
