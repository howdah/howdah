#!/bin/sh
# OPcache JIT coexistence check. One command, from the repo root:
#
#   sh lab/bench/jit.sh              # PHP 8.1 and 8.3
#   sh lab/bench/jit.sh 8.1 8.3 8.5
#
# For each PHP 8.x minor it runs lab/bench/jit_container.sh in that minor's
# howdah-dev-php image: it measures whether the JIT is really on (CLI and
# php-fpm) without Howdah, with Howdah at the shipped defaults, and with
# `[sinks] hook = "opcode"`, then runs the integration suite
# (lab/integration/matrix_container.sh, cli + fpm) with the JIT off and with
# opcache.jit=tracing + opcache.jit_buffer_size=64M.
#
# Exit status: non-zero if the two suite runs differ in PASS/FAIL/SKIP counts
# or either has a FAIL. Whether the JIT stayed on is reported, not asserted:
# see "jit_on" in the output. Output: $OUT/jit.json (default
# lab/bench/out/jit-<UTC timestamp>/), plus the raw matrix rows per run.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-8.1 8.3}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
: "${OUT:=$ROOT/lab/bench/out/jit-$STAMP}"
mkdir -p "$OUT"
chmod 777 "$OUT"

STATUS=0
FILES=""
for V in $VERSIONS; do
  case "$V" in 8.*) ;; *) echo "jit.sh: $V has no JIT (PHP 8.0+ only); skipped"; continue ;; esac
  IMG="howdah-dev-php$V"
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    if ! docker image inspect "lab-php-$V" >/dev/null 2>&1; then
      docker build -q -f "$ROOT/lab/images/php-$V.Dockerfile" -t "lab-php-$V" "$ROOT/lab/images" >/dev/null
    fi
    docker build -q -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=lab-php-$V" -t "$IMG" "$ROOT" >/dev/null
  fi
  echo "== PHP $V"
  docker run --rm -v "$ROOT":/src:ro -v "$OUT":/out \
    -v "howdah-bench-target-$IMG":/tmp/t -v howdah-bench-cargo:/opt/cargo/registry \
    "$IMG" sh /src/lab/bench/jit_container.sh /out > "$OUT/jit-$V.log" 2>&1 || true
  F="$OUT/jit-$V.json"
  if [ ! -s "$F" ]; then
    echo "   no result (see $OUT/jit-$V.log)"; STATUS=1; continue
  fi
  cat "$F"
  grep -q '"same_counts": true' "$F" || { echo "   suite counts differ with the JIT on"; STATUS=1; }
  if grep -q '"fail": [1-9]' "$F"; then echo "   suite has failures"; STATUS=1; fi
  FILES="$FILES $F"
done

{
  printf '{\n  "date_utc": "%s",\n  "howdah_version": "%s",\n  "git_commit": "%s",\n  "results": [\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)" \
    "$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  SEP=""
  for F in $FILES; do printf '%s' "$SEP"; sed 's/^/    /' "$F"; SEP=",
"; done
  printf '\n  ]\n}\n'
} > "$OUT/jit.json"
echo "results: $OUT/jit.json"
exit "$STATUS"
