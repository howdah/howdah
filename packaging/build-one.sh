#!/bin/sh
# In-container half of build-release.sh: build howdah.so for ONE PHP minor on a
# glibc-2.17 base, assert it, and drop the artifact into /out.
#
# Runs inside the `howdah-release` image (CentOS 7 / glibc 2.17 + rustup +
# libclang). The repo is mounted read-only at /src; /out is writable.
#
#   build-one.sh <minor> [--from-source]
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
  SRCVER="${HOWDAH_PHP_SRC_VERSION:-$MINOR.0}"
  note "building PHP $SRCVER from source for headers (Remi EL7 has no php$XY)"
  PREFIX="/opt/php-$MINOR"
  if [ ! -x "$PREFIX/bin/php-config" ]; then
    yum install -y libxml2-devel sqlite-devel bzip2 >/dev/null
    cd /tmp
    curl -fsSL -o php.tgz "https://www.php.net/distributions/php-$SRCVER.tar.gz"
    tar xzf php.tgz
    cd "php-$SRCVER"
    # Minimal non-ZTS, non-debug build: we only need php-config + installed headers.
    ./configure --prefix="$PREFIX" --disable-all --without-pear \
      --disable-cgi --disable-phpdbg --enable-cli >/dev/null 2>/tmp/phpconf.err \
      || { tail -20 /tmp/phpconf.err >&2; die "PHP ./configure failed"; }
    make -j"$(nproc)" >/dev/null 2>/tmp/phpmake.err || { tail -20 /tmp/phpmake.err >&2; die "PHP make failed"; }
    make install >/dev/null 2>&1 || die "PHP make install failed"
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
zts=unknown; dbg=unknown
if [ -n "${CFGH:-}" ]; then
  if grep -Eq '^#define[[:space:]]+ZTS[[:space:]]+1' "$CFGH"; then zts=ZTS; else zts=NTS; fi
  if grep -Eq '^#define[[:space:]]+ZEND_DEBUG[[:space:]]+1' "$CFGH"; then dbg=debug; else dbg=non-debug; fi
fi
note "api=$API thread_safety=$zts build=$dbg feature=$FEATURE"
[ "$zts" = ZTS ] && die "headers are ZTS; release binaries must be NTS"
[ "$dbg" = debug ] && die "headers are a debug build; release binaries must be non-debug"

# ---- 3. assert the release profile keeps panic = unwind --------------------
# The whole FFI panic-safety design (catch_unwind) is VOID under panic="abort".
grep -Eq 'panic[[:space:]]*=[[:space:]]*"unwind"' /src/Cargo.toml \
  || die "workspace Cargo.toml does not set panic=\"unwind\" for release"
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
note "objdump -T glibc symbol-version check (baseline 2.17)"
BAD=$(objdump -T "$SO" \
  | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u \
  | awk -F_ '{
      n=split($2,v,".");
      major=v[1]; minor=v[2]; patch=(n>=3?v[3]:0);
      if (major>2 || (major==2 && minor>17)) print "GLIBC_"$2;
    }')
MAXREF=$(objdump -T "$SO" | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u | tail -1)
if [ -n "$BAD" ]; then
  echo "   [$MINOR] referenced glibc symbol versions:" >&2
  objdump -T "$SO" | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -u | sed "s/^/   [$MINOR]   /" >&2
  die "glibc symbols newer than 2.17 referenced: $BAD"
fi
note "glibc OK: highest referenced version is $MAXREF (<= 2.17)"

# Also fail on any libstdc++ (GLIBCXX/CXXABI) dependency: the extension must not
# drag in a C++ runtime the host may lack.
if objdump -T "$SO" | grep -qE 'GLIBCXX_|CXXABI_'; then
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
