#!/usr/bin/env bash
# Build Howdah release artifacts: one glibc-2.17 howdah.so per PHP minor,
# packaged as a per-minor tarball (.so + howdah.ini + howdah-check).
#
#   packaging/build-release.sh [MINOR ...]
#
# With no arguments builds the full supported matrix. Each minor is built on a
# CentOS 7 / glibc-2.17 base (packaging/release.Dockerfile) so the binary runs
# on CentOS 7, Ubuntu 14.04+, Debian 8+ and newer; build-one.sh asserts with
# `objdump -T` that no referenced glibc symbol is newer than 2.17 and fails the
# build otherwise. Minors beyond Remi EL7's ceiling (PHP > 8.1) build their PHP
# headers from source on the same glibc-2.17 base (listed in FROM_SOURCE below).
#
# Env:
#   HOWDAH_VERSION   release version string for tarball names (default: workspace version)
#   KEEP_IMAGE=1     reuse an existing `howdah-release` image, skip docker build
#
# Output: packaging/out/
#   howdah-<version>-php<minor>-<api>-linux-x86_64.tar.gz   (per minor)
#   howdah-check                                            (standalone, top-level)
#   build-report.tsv                                        (what was built)
# Signing (SHA256SUMS + detached signature) is a separate step: packaging/sign.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/packaging/out"
IMAGE="${HOWDAH_RELEASE_IMAGE:-howdah-release}"

# Full supported matrix (PHP 5.4 .. 8.5). Default build set when none given.
ALL_MINORS=(5.4 5.5 5.6 7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5)

# Minors Remi EL7 does not carry (PHP > 8.1): built from source headers on the
# same glibc-2.17 base. PINNED to a REAL current patch + its sha256 (never a
# `.0`, which php.net drops -> 404). build-one.sh fetches from
# www.php.net/distributions with a museum.php.net fallback and enforces this
# hash. Refresh these as new patches land (any resolving patch works; the hash
# is what matters). `BRANCH -> "<version> <sha256>"`.
php_src_pin() {
  case "$1" in
    8.2) echo "8.2.35 9db4204f0a2d1911277ae832185e07bb4c3b3559772753a70d2968ca346d6910" ;;
    8.3) echo "8.3.36 c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53" ;;
    8.4) echo "8.4.27 5bafed9994c1a49796b25b5f61c22c9183bfe046b6acc7b363842d03c77f972f" ;;
    8.5) echo "8.5.12 81a0f450349e84b08eb43faa85f8a4c835684f3cc1c50471775d1317a046c525" ;;
    *)   return 1 ;;
  esac
}

MINORS=("$@")
[ ${#MINORS[@]} -eq 0 ] && MINORS=("${ALL_MINORS[@]}")

HOWDAH_VERSION="${HOWDAH_VERSION:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')}"
echo "== Howdah release build: version $HOWDAH_VERSION, minors: ${MINORS[*]}"

mkdir -p "$OUT"

# ---- 1. build the glibc-2.17 toolchain image -------------------------------
if [ "${KEEP_IMAGE:-0}" = 1 ] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "== reusing existing image $IMAGE"
else
  echo "== building $IMAGE (packaging/release.Dockerfile)"
  docker build -f "$REPO_ROOT/packaging/release.Dockerfile" -t "$IMAGE" "$REPO_ROOT"
fi

# ---- 2. build each minor in a throwaway container --------------------------
REPORT="$OUT/build-report.tsv"
printf 'minor\tapi\tfeature\tthread_safety\tbuild\tglibc_max_ref\ttarball\n' > "$REPORT"
built=0; failed=""

for minor in "${MINORS[@]}"; do
  echo ""
  echo "======================================================================"
  echo "==  building PHP $minor"
  echo "======================================================================"
  src_flag=""; src_env=()
  if pin="$(php_src_pin "$minor")"; then
    src_flag="--from-source"
    src_env=(-e "HOWDAH_PHP_SRC_VERSION=${pin%% *}" -e "HOWDAH_PHP_SRC_SHA256=${pin##* }")
    echo "   (from-source headers: PHP ${pin%% *})"
  fi

  stage="$(mktemp -d)"
  if docker run --rm \
        -v "$REPO_ROOT":/src:ro \
        -v "$stage":/out \
        -w /src \
        ${src_env[@]+"${src_env[@]}"} \
        "$IMAGE" sh /src/packaging/build-one.sh "$minor" $src_flag
  then
    so="$(ls "$stage"/howdah-"$minor"-*.so 2>/dev/null | head -1 || true)"
    meta="${so%.so}.meta"
    if [ -z "$so" ] || [ ! -f "$so" ]; then
      echo "!! PHP $minor: build-one.sh succeeded but produced no .so"; failed="$failed $minor"; rm -rf "$stage"; continue
    fi
    api="$(basename "$so" | sed -E 's/.*-([0-9]+)\.so/\1/')"

    # ---- 3. assemble the per-minor tarball ---------------------------------
    pkgdir="$(mktemp -d)"; root="howdah-$HOWDAH_VERSION-php$minor"
    mkdir -p "$pkgdir/$root"
    cp "$so" "$pkgdir/$root/howdah.so"
    cp "$REPO_ROOT/packaging/howdah.ini" "$pkgdir/$root/howdah.ini"
    cp "$REPO_ROOT/tools/howdah-check" "$pkgdir/$root/howdah-check"
    chmod +x "$pkgdir/$root/howdah-check"
    # Per-tarball provenance + verify note.
    sed -E "s/@API@/$api/; s/@MINOR@/$minor/; s/@VERSION@/$HOWDAH_VERSION/" \
        > "$pkgdir/$root/README.txt" <<'EOF'
Howdah @VERSION@ -- PHP @MINOR@ build (Zend module API @API@)

Contents:
  howdah.so     the extension, built against glibc 2.17 (runs on CentOS 7,
                Ubuntu 14.04+, Debian 8+ and newer). NTS, non-debug.
  howdah.ini    config template (copy into your PHP SAPI's config dir)
  howdah-check  read-only installer/verifier: `./howdah-check detect`

Install:
  1. ./howdah-check detect                 # find this PHP's extension_dir
  2. cp howdah.so <extension_dir>/howdah.so
  3. cp howdah.ini <php config dir>/       # e.g. /etc/php.d/ or conf.d/
  4. restart php-fpm / apache, then: php -m | grep howdah

Verify this download (see packaging/howdah-release-signing.asc in the repo):
  gpg --import howdah-release-signing.asc
  gpg --verify SHA256SUMS.asc SHA256SUMS
  sha256sum -c SHA256SUMS
EOF
    tarball="$OUT/howdah-$HOWDAH_VERSION-php$minor-$api-linux-x86_64.tar.gz"
    tar -C "$pkgdir" -czf "$tarball" "$root"
    rm -rf "$pkgdir"

    # record
    gmax="$(grep -m1 '^glibc_max_ref=' "$meta" 2>/dev/null | cut -d= -f2 || echo '?')"
    ts="$(grep -m1 '^thread_safety=' "$meta" | cut -d= -f2)"
    bd="$(grep -m1 '^build=' "$meta" | cut -d= -f2)"
    ft="$(grep -m1 '^feature=' "$meta" | cut -d= -f2)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$minor" "$api" "$ft" "$ts" "$bd" "$gmax" "$(basename "$tarball")" >> "$REPORT"
    echo "== PHP $minor OK -> $(basename "$tarball")  (api $api, $ts, $bd, glibc<=$gmax)"
    built=$((built+1))
  else
    echo "!! PHP $minor FAILED"; failed="$failed $minor"
  fi
  rm -rf "$stage"
done

# Publish howdah-check as a STANDALONE top-level asset (the same version-
# independent POSIX-sh script that also rides inside every tarball). Users need
# it BEFORE picking a tarball -- `howdah-check detect` reports the PHP API
# number that selects the right one. One copy, signed via SHA256SUMS alongside
# the tarballs (sign.sh picks it up automatically).
cp "$REPO_ROOT/tools/howdah-check" "$OUT/howdah-check"
chmod +x "$OUT/howdah-check"

echo ""
echo "======================================================================"
echo "== built $built tarball(s) into $OUT (+ standalone howdah-check)"
column -t -s$'\t' "$REPORT" || cat "$REPORT"
if [ -n "$failed" ]; then
  echo "== FAILED minors:$failed" >&2
  exit 1
fi
echo "== next: packaging/sign.sh   (SHA256SUMS + detached GPG signature)"
