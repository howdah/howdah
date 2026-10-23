#!/bin/sh
# Cross-version block matrix (Task 12 STEP 2/3) -- host orchestrator.
#
# For each requested PHP minor it ensures a dev image (Rust + that minor's PHP
# headers + php CLI + php-fpm), then runs lab/integration/matrix_container.sh
# inside it, which builds the extension and exercises every scenario across the
# requested SAPIs, APPENDING machine-readable rows to the results TSV. Per the
# Task-12 contract this is driven entirely to files: the orchestrator never
# holds a container's full output, only the PASS/FAIL summary it prints at the end.
#
# Usage (from the repo root):
#   lab/integration/matrix.sh                     # the required subset, cli+fpm
#   lab/integration/matrix.sh 7.4 8.1             # specific minors
#   SAPIS="cli fpm" lab/integration/matrix.sh     # choose SAPIs
#   RESULTS=/path/out.tsv lab/integration/matrix.sh
#
# Results TSV columns: phpver  sapi  scenario  result(PASS|FAIL|SKIP)  detail
# plus a leading "## not-run" comment block for minors with no lab base image.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SAPIS="${SAPIS:-cli fpm}"
RESULTS="${RESULTS:-$ROOT/lab/integration/matrix-results.tsv}"
# The required subset (contract): both SAPIs must be real + passing for these.
VERSIONS="${*:-5.4 5.6 7.3 7.4 8.1 8.4}"

# minor -> "base-image feature"   (lab base images from lab/images/*.Dockerfile)
spec() {
  case "$1" in
    5.4) echo "lab-php-5.4 php5" ;;
    5.5) echo "lab-php-5.5 php5" ;;
    5.6) echo "lab-php-5.6 php5" ;;
    7.0) echo "lab-php-7.0 php7" ;;
    7.1) echo "lab-php-7.1 php7" ;;
    7.2) echo "lab-php-7.2 php7" ;;
    7.3) echo "lab-php-7.3 php7" ;;
    7.4) echo "lab-php-7.4 php7" ;;
    8.0) echo "lab-php-8.0 php8" ;;
    8.1) echo "lab-php-8.1 php8" ;;
    8.2) echo "lab-php-8.2 php8" ;;
    8.3) echo "lab-php-8.3 php8" ;;
    8.4) echo "lab-php-8.4 php8" ;;
    8.5) echo "lab-php-8.5 php8" ;;
    *) echo "UNKNOWN -" ;;
  esac
}

# APPEND=1 adds to an existing results file (e.g. a later apache-only pass);
# otherwise the file is truncated and re-headed.
if [ "${APPEND:-0}" != 1 ]; then
  : > "$RESULTS"
  printf '## Howdah cross-version block matrix -- generated %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RESULTS"
  printf '## columns: phpver\\tsapi\\tscenario\\tresult\\tdetail\n' >> "$RESULTS"
fi

for V in $VERSIONS; do
  set -- $(spec "$V")
  BASE=$1; FEATURE=$2
  if [ "$BASE" = MISSING ] || [ "$BASE" = UNKNOWN ]; then
    echo "## NOT-RUN $V: no lab base image (build a php:$V-fpm image + lab/images/php-$V.Dockerfile first)" >> "$RESULTS"
    echo "== SKIP $V (no base image) =="
    continue
  fi
  if ! docker image inspect "$BASE" >/dev/null 2>&1; then
    echo "## NOT-RUN $V: base image $BASE not built" >> "$RESULTS"
    echo "== SKIP $V (base $BASE absent) =="
    continue
  fi
  DEV="howdah-dev-php$V"
  if ! docker image inspect "$DEV" >/dev/null 2>&1; then
    echo "== building $DEV (BASE=$BASE) =="
    docker build -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=$BASE" -t "$DEV" "$ROOT"
  fi
  # SAPIs runnable in the fpm-based dev image (cli, fpm); apache is separate.
  CLIFPM=$(echo "$SAPIS" | tr ' ' '\n' | grep -vx apache | tr '\n' ' ')
  if [ -n "$(echo "$CLIFPM" | tr -d ' ')" ]; then
    echo "== running matrix in $DEV (feature=$FEATURE, sapis='$CLIFPM') =="
    # /src read-only; container writes rows to a per-version tmp file we cat in.
    OD="$ROOT/lab/integration/.matrix-out"; mkdir -p "$OD"; chmod 777 "$OD"; : > "$OD/rows.tsv"; chmod 666 "$OD/rows.tsv"
    docker run --rm -v "$ROOT":/src:ro -v "$OD":/out \
      "$DEV" sh /src/lab/integration/matrix_container.sh "$FEATURE" "$CLIFPM" /out/rows.tsv \
      || echo "## WARN $V: container exited non-zero" >> "$RESULTS"
    cat "$OD/rows.tsv" >> "$RESULTS"; rm -f "$OD/rows.tsv"
  fi

  # Apache mod_php: a dev image FROM php:$V-apache (apache2handler SAPI).
  if echo "$SAPIS" | tr ' ' '\n' | grep -qx apache; then
    case "$FEATURE" in php5|php7|php8) ;; *) FEATURE=php8 ;; esac
    APBASE="php:$V-apache"; APDEV="howdah-dev-apache-php$V"
    if ! docker image inspect "$APDEV" >/dev/null 2>&1; then
      if docker image inspect "$APBASE" >/dev/null 2>&1 || docker pull "$APBASE" >/dev/null 2>&1; then
        echo "== building $APDEV (BASE=$APBASE) =="
        docker build -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=$APBASE" -t "$APDEV" "$ROOT" \
          || { echo "## NOT-RUN $V apache: dev image build failed" >> "$RESULTS"; APDEV=""; }
      else
        echo "## NOT-RUN $V apache: no php:$V-apache image available" >> "$RESULTS"; APDEV=""
      fi
    fi
    if [ -n "$APDEV" ]; then
      echo "== running apache matrix in $APDEV =="
      OD="$ROOT/lab/integration/.matrix-out"; mkdir -p "$OD"; chmod 777 "$OD"; : > "$OD/rows-ap.tsv"; chmod 666 "$OD/rows-ap.tsv"
      docker run --rm -v "$ROOT":/src:ro -v "$OD":/out \
        "$APDEV" sh /src/lab/integration/matrix_apache_container.sh "$FEATURE" /out/rows-ap.tsv \
        || echo "## WARN $V apache: container exited non-zero" >> "$RESULTS"
      cat "$OD/rows-ap.tsv" >> "$RESULTS"; rm -f "$OD/rows-ap.tsv"
    fi
  fi
done

echo
echo "=================== SUMMARY ==================="
awk -F'\t' '/^##/{next} {tot++; c[$4]++} END{
  printf "rows: %d   PASS: %d   FAIL: %d   SKIP: %d\n", tot, c["PASS"], c["FAIL"], c["SKIP"]}' "$RESULTS"
echo "FAILs (if any):"
grep -P '\tFAIL\t' "$RESULTS" || echo "  none"
echo "NOT-RUN minors:"
grep '^## NOT-RUN' "$RESULTS" || echo "  none"
echo "full results -> $RESULTS"
