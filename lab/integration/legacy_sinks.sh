#!/bin/sh
# Layer-3 legacy-era sink test (host driver): mail, preg_eval (/e),
# create_function, string assert, dangerous string callbacks, the flag-aware XML
# external-entity rule (xxe), and curl TLS verification. Builds the extension
# into a howdah-dev-php<ver> image and runs legacy_sinks_container.sh.
#
# The xxe rule is ON BY DEFAULT, so this is also its false-positive gate: per PHP
# minor the container proves that an external entity parsed with a dangerous
# libxml flag is neutralized on every XML entry point, that the same vector is
# live without Howdah (so the proof is not vacuous), and that a corpus of
# ordinary documents (SAML, SVG, XHTML, RSS, plist, ODF, Office XML, bare
# DOCTYPEs, internal entities) parses byte-identically with ZERO blocks.
#
# Usage (repo root):
#   lab/integration/legacy_sinks.sh                                   # PHP 8.3
#   lab/integration/legacy_sinks.sh 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5   # a matrix + table
#   IMAGE=howdah-dev-php7.4 FEATURE=php7 lab/integration/legacy_sinks.sh   # one explicit image
#
# Env: HOWDAH_TARGET_CACHE=<dir> keeps a cargo target dir per minor under <dir>
# between runs. Output per minor: lab/integration/.legacy_sinks-out/<minor>.log.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

feature() {
  case "$1" in
    5.*) echo php5 ;;
    7.*) echo php7 ;;
    *) echo php8 ;;
  esac
}

# One container run: $1 image, $2 feature, $3 optional target-cache dir.
run_one() {
  docker image inspect "$1" >/dev/null 2>&1 || { echo "missing image $1 (see lab/images/dev.Dockerfile)"; return 2; }
  CACHE=""
  if [ -n "${3:-}" ]; then
    mkdir -p "$3"
    CACHE="-v $3:/tmp/t"
  fi
  # shellcheck disable=SC2086
  docker run --rm $CACHE -v "$ROOT":/src:ro "$1" sh /src/lab/integration/legacy_sinks_container.sh "$2"
}

if [ "$#" -eq 0 ]; then
  IMAGE="${IMAGE:-howdah-dev-php8.3}"
  FEATURE="${FEATURE:-php8}"
  exec_cache="${HOWDAH_TARGET_CACHE:-}"
  run_one "$IMAGE" "$FEATURE" "$exec_cache"
  exit $?
fi

OD="$ROOT/lab/integration/.legacy_sinks-out"
mkdir -p "$OD"
SUMMARY="$OD/summary.tsv"; : > "$SUMMARY"
fail_any=0
for V in "$@"; do
  F=$(feature "$V")
  LOG="$OD/$V.log"
  cache=""
  [ -n "${HOWDAH_TARGET_CACHE:-}" ] && cache="$HOWDAH_TARGET_CACHE/$V"
  echo "== PHP $V ($F) =="
  if run_one "howdah-dev-php$V" "$F" "$cache" > "$LOG" 2>&1; then status=PASS; else status=FAIL; fail_any=1; fi
  oks=$(grep -c '^  ok ' "$LOG" || true)
  row=$(grep '^XXE-ROW' "$LOG" | tail -1 | cut -f2- || true)
  printf '%s\t%s\t%s\t%s\n' "$V" "$status" "$oks" "${row:-no XXE-ROW (see $LOG)}" >> "$SUMMARY"
  [ "$status" = PASS ] || { echo "-- $V failed; tail of $LOG:"; tail -15 "$LOG"; }
done

echo
echo "==================== legacy sinks / xxe (flag-aware) per PHP ===================="
printf '%-5s %-6s %-6s %s\n' "PHP" "RESULT" "checks" "xxe: libxml, control (leaks w/o Howdah), blocked+flag (stripped), evasions stopped/live, benign corpus"
while IFS='	' read -r v status oks row; do
  printf '%-5s %-6s %-6s %s\n' "$v" "$status" "$oks" "$(printf '%s' "$row" | tr '\t' ' ')"
done < "$SUMMARY"
echo
echo "full logs: $OD/<minor>.log"
exit "$fail_any"
