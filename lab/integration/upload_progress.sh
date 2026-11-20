#!/bin/sh
# Host driver for the CVE-2026-115560 (session serializer mismatch) lab: the
# session.upload_progress field value is used as part of a session KEY; a `|` in
# it, written under php_serialize and read back under the php handler, smuggles a
# serialized value into unserialize(). Howdah withholds that one FORMDATA event
# from session's callback (rule upload_progress_abuse). The container proves the
# precondition with Howdah OFF (benign test gadget writes a marker), then that
# Howdah closes it, with a benign-corpus false-positive gate.
#
# Usage (repo root):
#   lab/integration/upload_progress.sh                                # PHP 8.3
#   lab/integration/upload_progress.sh 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6
#   IMAGE=howdah-dev-php7.4 FEATURE=php7 lab/integration/upload_progress.sh
#
# Env: HOWDAH_TARGET_CACHE=<dir> keeps a cargo target dir per minor.
# Output per minor: lab/integration/.upload_progress-out/<minor>.log.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

feature() {
  case "$1" in
    5.*) echo php5 ;;
    7.*) echo php7 ;;
    *) echo php8 ;;
  esac
}

run_one() { # $1 image, $2 feature, $3 optional target-cache dir
  docker image inspect "$1" >/dev/null 2>&1 || { echo "missing image $1 (see lab/images/dev.Dockerfile)"; return 2; }
  CACHE=""
  if [ -n "${3:-}" ]; then
    mkdir -p "$3"
    CACHE="-v $3:/tmp/t"
  fi
  # shellcheck disable=SC2086
  docker run --rm $CACHE -v "$ROOT":/src:ro "$1" sh /src/lab/integration/upload_progress_container.sh "$2"
}

if [ "$#" -eq 0 ]; then
  run_one "${IMAGE:-howdah-dev-php8.3}" "${FEATURE:-php8}" "${HOWDAH_TARGET_CACHE:-}"
  exit $?
fi

OD="$ROOT/lab/integration/.upload_progress-out"
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
  printf '%s\t%s\t%s\n' "$V" "$status" "$oks" >> "$SUMMARY"
  [ "$status" = PASS ] || { echo "-- $V failed; tail of $LOG:"; tail -15 "$LOG"; }
done

echo
echo "============ upload_progress_abuse (CVE-2026-115560) per PHP ============"
printf '%-5s %-6s %s\n' "PHP" "RESULT" "checks"
while IFS='	' read -r v status oks; do
  printf '%-5s %-6s %s\n' "$v" "$status" "$oks"
done < "$SUMMARY"
echo
echo "full logs: $OD/<minor>.log"
exit "$fail_any"
