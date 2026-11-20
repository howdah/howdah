#!/bin/sh
# Layer-3 SOAP request-guard test (host driver): CVE-2026-129506 (SoapServer DTD
# use-after-free) and CVE-2026-15353 (malformed SOAP-ENC arraySize heap
# over-read). Builds the extension into a howdah-dev-php<ver> image and runs
# soap_guard_container.sh behind the built-in web server, so SoapServer::handle()
# reads a real php://input body.
#
# DEFENSIVE ONLY: it verifies Howdah refuses two malformed request shapes before
# ext/soap parses them (clean 403 + soap_request log, benign corpus zero-block),
# never triggering the underlying memory bug. ext/soap is not baked into the dev
# images; the container builds it at runtime and SKIPS (recording why) where that
# is not possible, still proving the hook no-ops cleanly when soap is absent.
#
# Usage (repo root):
#   lab/integration/soap_guard.sh                                   # PHP 8.3
#   lab/integration/soap_guard.sh 5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6   # a matrix + table
#   IMAGE=howdah-dev-php8.6 FEATURE=php8 lab/integration/soap_guard.sh  # one explicit image
#
# Env: HOWDAH_TARGET_CACHE=<dir> keeps a cargo target dir per minor under <dir>.
# Output per minor: lab/integration/.soap_guard-out/<minor>.log.
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
  docker run --rm $CACHE -v "$ROOT":/src:ro "$1" sh /src/lab/integration/soap_guard_container.sh "$2"
}

if [ "$#" -eq 0 ]; then
  IMAGE="${IMAGE:-howdah-dev-php8.3}"
  FEATURE="${FEATURE:-php8}"
  run_one "$IMAGE" "$FEATURE" "${HOWDAH_TARGET_CACHE:-}"
  exit $?
fi

OD="$ROOT/lab/integration/.soap_guard-out"
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
  row=$(grep '^SOAP-ROW' "$LOG" | tail -1 | cut -f2- || true)
  printf '%s\t%s\t%s\t%s\n' "$V" "$status" "$oks" "${row:-no SOAP-ROW (see $LOG)}" >> "$SUMMARY"
  [ "$status" = PASS ] || { echo "-- $V failed; tail of $LOG:"; tail -15 "$LOG"; }
done

echo
echo "==================== SOAP request guard per PHP ===================="
printf '%-5s %-6s %-6s %s\n' "PHP" "RESULT" "checks" "row: dtd / arraySize refusal, benign zero-block, worker survival, off not-intercepted"
while IFS='	' read -r v status oks row; do
  printf '%-5s %-6s %-6s %s\n' "$v" "$status" "$oks" "$(printf '%s' "$row" | tr '\t' ' ')"
done < "$SUMMARY"
echo
echo "full logs: $OD/<minor>.log"
exit "$fail_any"
