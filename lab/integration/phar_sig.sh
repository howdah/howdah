#!/bin/sh
# phar_sig lab (host driver; CVE-2026-128090, GHSA-68fq-fh7h-f8gr): PHP takes a
# phar's signature TYPE from the archive, so with an OpenSSL key pinned in
# <archive>.pubkey an attacker who can rewrite the archive can re-sign it with a
# keyless digest (SHA-256) and PHP accepts it. DEFENSIVE and BENIGN: every
# archive here contains only `<?php return "ok";`; the property under test is
# which signature TYPE is accepted, nothing is unpacked or executed beyond that.
# Howdah OFF reproduces the bug; the default (signature=block) refuses the
# downgraded archive and logs phar_signature; the genuine OpenSSL-signed archive
# and an archive with no .pubkey still load; PHP builds that already refuse the
# downgrade (fixed upstream, e.g. 8.6.0) are probed and recorded.
#
# Usage (repo root):
#   lab/integration/phar_sig.sh                # 5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6
#   lab/integration/phar_sig.sh 8.3            # one minor
#
# Needs the howdah-dev-php<minor> images (with ext/openssl; SKIP rows otherwise).
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.6 7.0 7.4 8.0 8.1 8.3 8.5 8.6}"
OD=$(mktemp -d "${TMPDIR:-/tmp}/howdah-phar-sig.XXXXXX")
chmod 777 "$OD"
ALL="$OD/results.tsv"; : > "$ALL"

feature() { case "$1" in 5.*) echo php5 ;; 7.*) echo php7 ;; *) echo php8 ;; esac; }

for V in $VERSIONS; do
  F=$(feature "$V")
  DEV="howdah-dev-php$V"
  if ! docker image inspect "$DEV" >/dev/null 2>&1; then
    printf '%s\tphar-sig\tall\tNOT-RUN\tno %s image\n' "$V" "$DEV" >> "$ALL"; continue
  fi
  echo "== $V ($DEV) =="
  VOUT="$OD/$V"; mkdir -p "$VOUT"; chmod 777 "$VOUT"
  docker run --rm -v "$ROOT":/src:ro -v "$VOUT":/out -v "howdah-ps-target-$V":/tmp/t \
    "$DEV" sh /src/lab/integration/phar_sig_container.sh "$F" /out/rows.tsv \
    || printf '%s\tphar-sig\tdriver\tFAIL\tcontainer script exited non-zero\n' "$V" >> "$ALL"
  cat "$VOUT/rows.tsv" >> "$ALL" 2>/dev/null || true
done

echo
echo "=================== phar-sig results ==================="
cat "$ALL"
echo
awk -F'\t' '{tot++; c[$4]++} END{printf "rows: %d   PASS: %d   FAIL: %d   NOT-RUN: %d\n", tot, c["PASS"], c["FAIL"], c["NOT-RUN"]}' "$ALL"
RC=0; if grep -q "	FAIL	" "$ALL"; then RC=1; fi
rm -rf "$OD" 2>/dev/null || true
exit $RC
