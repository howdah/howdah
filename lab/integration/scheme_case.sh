#!/bin/sh
# scheme_case lab (host driver; CVE-2026-128064): a mixed-case HTTPS:// URL is
# connected in PLAINTEXT by stock PHP. Two-listener oracle inside the container:
# plaintext :80 and a self-signed TLS :443; which port a request lands on proves
# whether TLS was used. Howdah OFF reproduces the bug, the default (fix) sends
# HTTPS:// to :443, lowercase https:// is unaffected, and a redirect hop to
# HTTPS:// stays plaintext (documented gap: PHP follows redirects by a direct
# internal call that bypasses the wrapper op Howdah proxies).
#
# Usage (repo root):
#   lab/integration/scheme_case.sh                # 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6
#   lab/integration/scheme_case.sh 8.3            # one minor
#
# Needs the howdah-dev-php<minor> images. Results: TSV rows printed at the end.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6}"
OD=$(mktemp -d "${TMPDIR:-/tmp}/howdah-scheme-case.XXXXXX")
chmod 777 "$OD"
ALL="$OD/results.tsv"; : > "$ALL"

feature() { case "$1" in 5.*) echo php5 ;; 7.*) echo php7 ;; *) echo php8 ;; esac; }

for V in $VERSIONS; do
  F=$(feature "$V")
  DEV="howdah-dev-php$V"
  if ! docker image inspect "$DEV" >/dev/null 2>&1; then
    printf '%s\tscheme-case\tall\tNOT-RUN\tno %s image\n' "$V" "$DEV" >> "$ALL"; continue
  fi
  echo "== $V ($DEV) =="
  VOUT="$OD/$V"; mkdir -p "$VOUT"; chmod 777 "$VOUT"
  docker run --rm -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-sc-target-$V":/tmp/t \
    "$DEV" sh /src/lab/integration/scheme_case_container.sh "$F" /out/rows.tsv \
    || printf '%s\tscheme-case\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
  cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
done

echo
echo "=================== scheme-case results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   NOT-RUN: %d\n", tot, c["PASS"], c["FAIL"], c["NOT-RUN"]}' "$ALL"
RC=0; if grep -q "	FAIL	" "$ALL"; then RC=1; fi
rm -rf "$OD" 2>/dev/null || true
exit $RC
