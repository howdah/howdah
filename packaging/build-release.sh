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
#   HOWDAH_ARCH      target arch: x86_64 (default) or aarch64. aarch64 builds in
#                    packaging/release.aarch64.Dockerfile under --platform linux/arm64
#                    (QEMU locally, native on an arm64 runner); every minor uses
#                    from-source PHP headers (Remi has no aarch64 EL7 packages).
#
# Output: packaging/out/
#   howdah-<version>-php<minor>-<api>-linux-<arch>.tar.gz   (per minor; arch = x86_64|aarch64)
#   howdah-check                                            (standalone, top-level)
#   build-report.tsv                                        (what was built)
# Signing (SHA256SUMS + detached signature) is a separate step: packaging/sign.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/packaging/out"

# Target arch. x86_64 (default) is exactly the historical behavior; aarch64
# swaps the Dockerfile, image name, docker --platform and tarball suffix.
ARCH="${HOWDAH_ARCH:-x86_64}"
case "$ARCH" in
  x86_64)
    IMAGE="${HOWDAH_RELEASE_IMAGE:-howdah-release}"
    DOCKERFILE="$REPO_ROOT/packaging/release.Dockerfile"
    PLATFORM_ARGS=()
    ;;
  aarch64)
    IMAGE="${HOWDAH_RELEASE_IMAGE:-howdah-release-aarch64}"
    DOCKERFILE="$REPO_ROOT/packaging/release.aarch64.Dockerfile"
    PLATFORM_ARGS=(--platform linux/arm64)
    ;;
  *) echo "FATAL: unsupported HOWDAH_ARCH '$ARCH' (x86_64|aarch64)" >&2; exit 2 ;;
esac

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

# aarch64 has no Remi EL7 packages, so EVERY minor builds from source headers.
# Same rules as php_src_pin (real current patch + sha256) for the minors the
# x86_64 path takes from Remi (5.4 .. 8.1); 8.2+ reuse php_src_pin.
php_src_pin_aarch64() {
  case "$1" in
    5.4) echo "5.4.45 25bc4723955f4e352935258002af14a14a9810b491a19400d76fcdfa9d04b28f" ;;
    5.5) echo "5.5.38 4f458c9b504269615715a62f182b7c2f89bb8284f484befc221b56a1571b506e" ;;
    5.6) echo "5.6.40 56fb9878d12fdd921f6a0897e919f4e980d930160e154cbde2cc6d9206a27cac" ;;
    7.0) echo "7.0.33 d71a6ecb6b13dc53fed7532a7f8f949c4044806f067502f8fb6f9facbb40452a" ;;
    7.1) echo "7.1.33 0055f368ffefe51d5a4483755bd17475e88e74302c08b727952831c5b2682ea2" ;;
    7.2) echo "7.2.34 8b2777c741e83f188d3ca6d8e98ece7264acafee86787298fae57e05d0dddc78" ;;
    7.3) echo "7.3.33 9a369c32c6f52036b0a890f290327f148a1904ee66aa56e2c9a7546da6525ec8" ;;
    7.4) echo "7.4.33 5a2337996f07c8a097e03d46263b5c98d2c8e355227756351421003bea8f463e" ;;
    8.0) echo "8.0.30 449d2048fcb20a314d8c218097c6d1047a9f1c5bb72aa54d5d3eba0a27a4c80c" ;;
    8.1) echo "8.1.34 3c5b060ec8e0d5dd1d8237823f3161cc8bc5342aab3c46893eba9857759c4bfa" ;;
    *)   php_src_pin "$1" ;;
  esac
}

MINORS=("$@")
[ ${#MINORS[@]} -eq 0 ] && MINORS=("${ALL_MINORS[@]}")

HOWDAH_VERSION="${HOWDAH_VERSION:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')}"
echo "== Howdah release build: version $HOWDAH_VERSION, minors: ${MINORS[*]}"
[ "$ARCH" = x86_64 ] || echo "== target arch: $ARCH"

mkdir -p "$OUT"

# ---- 1. build the glibc-2.17 toolchain image -------------------------------
if [ "${KEEP_IMAGE:-0}" = 1 ] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "== reusing existing image $IMAGE"
else
  echo "== building $IMAGE (packaging/$(basename "$DOCKERFILE"))"
  docker build ${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"} -f "$DOCKERFILE" -t "$IMAGE" "$REPO_ROOT"
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
  pin_fn=php_src_pin; [ "$ARCH" = x86_64 ] || pin_fn=php_src_pin_aarch64
  if pin="$("$pin_fn" "$minor")"; then
    src_flag="--from-source"
    src_env=(-e "HOWDAH_PHP_SRC_VERSION=${pin%% *}" -e "HOWDAH_PHP_SRC_SHA256=${pin##* }")
    echo "   (from-source headers: PHP ${pin%% *})"
  fi

  stage="$(mktemp -d)"
  if docker run --rm \
        ${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"} \
        -e "HOWDAH_ARCH=$ARCH" \
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
    tarball="$OUT/howdah-$HOWDAH_VERSION-php$minor-$api-linux-$ARCH.tar.gz"
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
