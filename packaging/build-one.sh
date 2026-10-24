#!/bin/sh
# In-container half of build-release.sh: build howdah.so for ONE PHP minor on a
# glibc-2.17 base, assert it, and drop the artifact into /out.
#
# Runs inside the `howdah-release` image (CentOS 7 / glibc 2.17 + rustup +
# libclang). The repo is mounted read-only at /src; /out is writable.
#
#   build-one.sh <minor> [--from-source]      (HOWDAH_ARCH=x86_64|aarch64, default x86_64)
#   e.g. build-one.sh 7.3            # headers via Remi phpXY-php-devel
#        build-one.sh 8.4 --from-source   # compile PHP from source for headers
#
# On success writes to /out:
#   howdah-<minor>-<api>.so   the extension (NTS, non-debug, glibc <= 2.17)
#   howdah-<minor>-<api>.meta a key=value sidecar (api, zts, debug, feature)
set -eu

MINOR="${1:?usage: build-one.sh <minor> [--from-source]}"
FROM_SOURCE=0
[ "${2:-}" = "--from-source" ] && FROM_SOURCE=1
XY=$(printf '%s' "$MINOR" | tr -d .)

# Target arch (build-release.sh passes it; the container is already that arch --
# native, or QEMU-emulated under --platform linux/arm64 -- so objdump/file below
# are the container's own). aarch64 has no Remi EL7 packages: from-source only.
ARCH="${HOWDAH_ARCH:-x86_64}"
case "$ARCH" in
  x86_64)  FILE_ARCH='x86-64' ;;
  aarch64) FILE_ARCH='ARM aarch64' ;;
  *) echo "FATAL: unsupported HOWDAH_ARCH '$ARCH'"; exit 2 ;;
esac
if [ "$ARCH" = aarch64 ] && [ "$FROM_SOURCE" -ne 1 ]; then
  echo "FATAL [$MINOR]: aarch64 builds need --from-source (no Remi EL7 aarch64 packages)" >&2; exit 1
fi

# version -> cargo feature (php5 / php7 / php8)
case "$MINOR" in
  5.*) FEATURE=php5 ;;
  7.*) FEATURE=php7 ;;
  8.*) FEATURE=php8 ;;
  *) echo "FATAL: unsupported PHP minor '$MINOR'"; exit 2 ;;
esac

die() { echo "FATAL [$MINOR]: $*" >&2; exit 1; }
note() { echo ">> [$MINOR] $*" >&2; }

# ---- 1. obtain this minor's php-config + headers ---------------------------
if [ "$FROM_SOURCE" -eq 1 ]; then
  # Exact patch + hash are pinned by build-release.sh's version map; never guess
  # a `.0` (php.net drops old patch tarballs, so php-<minor>.0 404s).
  SRCVER="${HOWDAH_PHP_SRC_VERSION:?from-source needs HOWDAH_PHP_SRC_VERSION (build-release.sh version map)}"
  SRCSHA="${HOWDAH_PHP_SRC_SHA256:?from-source needs HOWDAH_PHP_SRC_SHA256 (build-release.sh version map)}"
  note "PHP $SRCVER headers from source (Remi EL7 has no php$XY)"
  PREFIX="/opt/php-$MINOR"
  if [ ! -x "$PREFIX/bin/php-config" ]; then
    yum install -y --setopt=base.skip_if_unavailable=true libxml2-devel sqlite-devel bzip2 \
      >/dev/null 2>/tmp/yum.err || { tail -10 /tmp/yum.err >&2; die "could not install PHP build deps"; }
    cd /tmp; rm -f php.tgz
    # Durable + verified fetch: try www.php.net/distributions (current patches),
    # then museum.php.net (long-term archive). The pinned sha256 is enforced
    # whichever mirror answers, so a tampered/rotated mirror is rejected.
    got=0
    for base in "https://www.php.net/distributions" "https://museum.php.net/php${MINOR%%.*}"; do
      curl -fsSL -o php.tgz "$base/php-$SRCVER.tar.gz" 2>/dev/null || { note "fetch failed from $base"; continue; }
      if echo "$SRCSHA  php.tgz" | sha256sum -c - >/dev/null 2>&1; then
        got=1; note "fetched + sha256-verified php-$SRCVER from $base"; break
      fi
      note "sha256 mismatch from $base; trying next mirror"
    done
    [ "$got" = 1 ] || die "could not fetch+verify php-$SRCVER.tar.gz (expected sha256 $SRCSHA)"
    tar xzf php.tgz
    cd "php-$SRCVER"
    # The SHIPPED ./configure generates php_config.h + scripts/php-config with no
    # autotools. We then install ONLY headers + build scripts + php-config --
    # there is NO `make` of PHP itself, so modern PHP is never compiled with
    # CentOS 7's gcc 4.8.5 (we only need headers to generate bindings).
    #
    # Old tarballs ship an old config.guess (PHP 5.4's is from 2008, before
    # aarch64 existed) and ./configure then fails with "cannot guess build
    # type". The shipped config.sub does accept an explicit triple, so when the
    # guesser cannot identify this host, name it. (config.guess is not
    # executable in the tarball; run it through sh.)
    BUILD_TRIPLE=""
    if ! sh ./config.guess >/dev/null 2>&1; then
      BUILD_TRIPLE="--build=$ARCH-unknown-linux-gnu"
      note "config.guess cannot identify this host; passing $BUILD_TRIPLE"
    fi
    # shellcheck disable=SC2086
    ./configure $BUILD_TRIPLE --prefix="$PREFIX" --disable-all --without-pear \
      --disable-cgi --disable-phpdbg --enable-cli >/tmp/phpconf.log 2>&1 \
      || { tail -25 /tmp/phpconf.log >&2; die "PHP ./configure failed"; }
    make install-headers install-build install-programs >/tmp/phphdr.log 2>&1 \
      || { tail -25 /tmp/phphdr.log >&2; die "PHP header install failed"; }
  fi
  PHP_CONFIG="$PREFIX/bin/php-config"
else
  note "installing phpXY-php-devel from Remi (php$XY)"
  # vault.centos.org (EOL base) is flaky; retry, and let yum skip a 403'ing base
  # mirror since the SCL php packages are satisfied entirely from Remi.
  ok=0
  for attempt in 1 2 3; do
    if yum install -y --setopt=base.skip_if_unavailable=true --setopt=timeout=60 \
         "php$XY-php-devel" >/dev/null 2>/tmp/yum.err; then ok=1; break; fi
    note "yum attempt $attempt failed; retrying"; sleep 3
  done
  [ "$ok" = 1 ] || { tail -15 /tmp/yum.err >&2; die "could not install php$XY-php-devel (Remi EL7 ceiling is 8.1; for >8.1 use --from-source)"; }
  PHP_CONFIG="/opt/remi/php$XY/root/usr/bin/php-config"
fi
[ -x "$PHP_CONFIG" ] || die "php-config not found at $PHP_CONFIG"
note "php-config: $PHP_CONFIG ($("$PHP_CONFIG" --version))"

# ---- 2. read API number / NTS / debug straight from the headers ------------
INCS=$("$PHP_CONFIG" --includes)
find_hdr() {
  for i in $INCS; do
    d=${i#-I}
    [ -f "$d/$1" ] && { echo "$d/$1"; return 0; }
  done
  return 1
}
MODH=$(find_hdr Zend/zend_modules.h) || die "zend_modules.h not found in includes"
API=$(grep -E '^#define[[:space:]]+ZEND_MODULE_API_NO' "$MODH" | awk '{print $3}')
[ -n "$API" ] || die "could not read ZEND_MODULE_API_NO"

CFGH=$(find_hdr main/php_config.h || true)
[ -n "${CFGH:-}" ] || die "main/php_config.h not found in includes -- cannot verify NTS/non-debug"
if grep -Eq '^#define[[:space:]]+ZTS[[:space:]]+1' "$CFGH"; then zts=ZTS; else zts=NTS; fi
if grep -Eq '^#define[[:space:]]+ZEND_DEBUG[[:space:]]+1' "$CFGH"; then dbg=debug; else dbg=non-debug; fi
note "api=$API thread_safety=$zts build=$dbg feature=$FEATURE"
[ "$zts" = ZTS ] && die "headers are ZTS; release binaries must be NTS"
[ "$dbg" = debug ] && die "headers are a debug build; release binaries must be non-debug"

# ---- 3. assert the release profile keeps panic = unwind --------------------
# The whole FFI panic-safety design (catch_unwind) is VOID under panic="abort".
# Check the [profile.release] section specifically (not just "unwind" anywhere).
awk '
  /^\[/ { inrel = 0 }
  /^\[profile\.release\]/ { inrel = 1; next }
  inrel && /^[[:space:]]*panic[[:space:]]*=[[:space:]]*"unwind"/ { found = 1 }
  END { exit (found ? 0 : 1) }
' /src/Cargo.toml || die "[profile.release] in Cargo.toml does not set panic=\"unwind\""
# Reject a real `panic = "abort"` profile setting (a non-comment line in any
# Cargo.toml) -- but not the many comments that merely mention it. TOML comments
# start with '#', so anchoring to a line that STARTS with `panic` excludes them.
if grep -rlE '^[[:space:]]*panic[[:space:]]*=[[:space:]]*"abort"' \
     --include='Cargo.toml' /src 2>/dev/null | grep -q .; then
  grep -rnE '^[[:space:]]*panic[[:space:]]*=[[:space:]]*"abort"' --include='Cargo.toml' /src >&2 || true
  die "a Cargo.toml sets panic=\"abort\" -- would void FFI panic safety"
fi

# ---- 4. build the extension (reproducible: --locked) -----------------------
export PHP_CONFIG
export CARGO_TARGET_DIR=/tmp/t
cd /src
note "cargo build -p howdah-ext --features $FEATURE --release --locked"
cargo build -p howdah-ext --features "$FEATURE" --release --locked 2>&1 | sed "s/^/   [$MINOR] /" >&2
SO=/tmp/t/release/libhowdah_ext.so
[ -f "$SO" ] || die "build produced no libhowdah_ext.so"

# ---- 5. THE glibc-2.17 ASSERTION -------------------------------------------
# No referenced glibc symbol version may be newer than 2.17. (GCC_* / libgcc
# unwinder symbol versions are not glibc and are present on every target.)
#
# Fail CLOSED: dump objdump output to a file first (so a failed objdump or an
# empty parse can never silently pass), require that we actually parsed some
# GLIBC_ references, and rank versions with `sort -V` so 2.9 < 2.17.
file "$SO" | grep -q "$FILE_ARCH" || die "$SO is not a $ARCH ELF: $(file "$SO")"
note "objdump -T glibc symbol-version check (baseline 2.17, $ARCH)"
DYN=/tmp/dynsyms.$MINOR.txt
objdump -T "$SO" > "$DYN" 2>/tmp/objdump.err || { tail -5 /tmp/objdump.err >&2; die "objdump -T failed on $SO"; }
REFS=$(grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' "$DYN" | sort -u -V)
[ -n "$REFS" ] || die "no GLIBC_ symbol-version references parsed from $SO -- refusing to pass fail-open"
MAXREF=$(printf '%s\n' "$REFS" | sort -V | tail -1)
BAD=$(printf '%s\n' "$REFS" | awk -F_ '{
    split($2, v, "."); maj = v[1]; min = v[2];
    if (maj > 2 || (maj == 2 && min > 17)) print "GLIBC_" $2;
  }')
if [ -n "$BAD" ]; then
  echo "   [$MINOR] referenced glibc symbol versions:" >&2
  printf '   [%s]   %s\n' "$MINOR" $REFS >&2
  die "glibc symbols newer than 2.17 referenced: $BAD"
fi
note "glibc OK: highest referenced version is $MAXREF (<= 2.17)"

# Also fail on any libstdc++ (GLIBCXX/CXXABI) dependency: the extension must not
# drag in a C++ runtime the host may lack.
if grep -qE 'GLIBCXX_|CXXABI_' "$DYN"; then
  die "binary references libstdc++ (GLIBCXX/CXXABI) -- unexpected for a C+Rust .so"
fi

# ---- 6. hand the artifact + metadata back ----------------------------------
OUTSO="/out/howdah-$MINOR-$API.so"
cp "$SO" "$OUTSO"
strip "$OUTSO" 2>/dev/null || true
cat > "/out/howdah-$MINOR-$API.meta" <<META
minor=$MINOR
api=$API
feature=$FEATURE
thread_safety=$zts
build=$dbg
glibc_max_ref=$MAXREF
php_config_version=$("$PHP_CONFIG" --version)
META
note "wrote $OUTSO (api $API, $zts, $dbg)"
