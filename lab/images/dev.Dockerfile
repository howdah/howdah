# Reusable Howdah dev image: any lab PHP image + Rust + clang/libclang.
#
# Lets `cargo build -p howdah-sys --features phpN` run against that PHP's
# real headers (php-config is already in the base image). Build context must
# be the repo root.
#
#   docker build -f lab/images/dev.Dockerfile --build-arg BASE=lab-php-7.3 \
#       -t howdah-dev-php7.3 .
#   lab/images/check-sys.sh howdah-dev-php7.3 php7     # build + list symbols
#
# BASE may be any lab image (lab-php-5.4 .. lab-php-8.4) or php:X-fpm.
# Base apt sources are inherited from the lab image (snapshot pins); Valid-Until
# checks are off (EOL suites). Debian stretch (PHP 5.x) ships clang 3.8, which
# bindgen rejects, so there libclang 18 comes from libclang-modern.sh.
ARG BASE=lab-php-8.4
FROM ${BASE}

COPY lab/images/libclang-modern.sh /tmp/libclang-modern.sh
RUN set -e; . /etc/os-release; \
    APT="-o Acquire::Check-Valid-Until=false"; \
    mkdir -p /opt/libclang; \
    if [ "${ID:-}" = centos ] || [ "${ID:-}" = rhel ]; then \
      # PHP 5.4 target: CentOS 7 (yum). gcc 4.8 + fcgi (cgi-fcgi for the fpm SAPI
      # matrix); its ancient clang is unusable for bindgen, so libclang 18 comes
      # from the manylinux2010 wheel (glibc 2.17 on CentOS 7 satisfies it).
      yum install -y gcc make curl unzip which >/dev/null \
      && (yum install -y fcgi >/dev/null 2>&1 || true) \
      && /tmp/libclang-modern.sh; \
    elif [ "$VERSION_ID" = 9 ]; then \
      printf 'deb http://archive.debian.org/debian stretch main\ndeb http://archive.debian.org/debian-security stretch/updates main\n' > /etc/apt/sources.list; \
      apt-get $APT update \
      && apt-get $APT install -y --no-install-recommends --allow-unauthenticated ca-certificates curl gcc libc-dev unzip libfcgi-bin \
      && /tmp/libclang-modern.sh; \
    else \
      # Non-stretch Debian (bullseye/bookworm, PHP 7.x/8.x): use the distro clang
      # (its libclang ships matching builtin headers, unlike the manylinux wheel
      # which clashes with gcc-10 intrinsics here). Some lab bases pin an apt
      # snapshot that is internally inconsistent for clang's deps (libc6 vs
      # libc6-i386) or whose security .debs have 404'd, so point apt at the live
      # Debian mirror for this base's codename, where the set is consistent.
      printf 'deb http://deb.debian.org/debian %s main\n' "$VERSION_CODENAME" > /etc/apt/sources.list \
      && apt-get $APT update \
      && apt-get $APT install -y --no-install-recommends --allow-unauthenticated ca-certificates curl gcc libc-dev clang libclang-dev libfcgi-bin unzip \
      && lc="$(find /usr/lib -path '*/llvm-*/lib/libclang.so' 2>/dev/null | sort | head -1)" \
      && [ -n "$lc" ] || lc="$(find /usr/lib -name 'libclang-*.so.*' 2>/dev/null | sort | head -1)" \
      && test -n "$lc" \
      && mkdir -p /opt/libclang/include /opt/libclang/include-fixed \
      && ln -s "$lc" /opt/libclang/libclang.so; \
    fi; \
    rm -rf /var/lib/apt/lists/* /tmp/libclang-modern.sh

# bindgen / clang-sys discovery (both layouts above end up in /opt/libclang).
ENV LIBCLANG_PATH=/opt/libclang BINDGEN_EXTRA_CLANG_ARGS="-I/opt/libclang/include -I/opt/libclang/include-fixed"

ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && chmod -R a+rX /opt/rustup /opt/cargo

CMD ["bash"]
