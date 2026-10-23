# Howdah release build image: CentOS 7 (glibc 2.17) + rustup + modern libclang.
#
# CentOS 7 ships glibc 2.17 -- the oldest glibc Howdah 0.1 targets. Building the
# extension here guarantees the resulting howdah.so references NO glibc symbol
# newer than 2.17, so one binary per PHP minor runs on CentOS 7, Ubuntu 14.04+,
# Debian 8+ and everything newer. (Rust's own x86_64-unknown-linux-gnu std is
# built against a glibc-2.17 baseline, so it adds no newer references either.)
#
# This image carries NO PHP: build-release.sh installs the target minor's
# `phpXY-php-devel` (headers + php-config) from Remi at build time, so one image
# serves every supported version. Remi's EL7 line tops out at PHP 8.1; building
# 8.2-8.5 on glibc 2.17 requires compiling PHP from source (see build-release.sh
# --from-source), which this image's toolchain (gcc, make) also supports.
#
#   docker build -f packaging/release.Dockerfile -t howdah-release .   # context = repo root
#
# Build context must be the repo root so COPY can reach lab/images/.

FROM centos:7

# CentOS 7 is EOL; mirrorlist.centos.org is gone and vault.centos.org rate-limits
# (intermittent HTTP 403 on metadata). Point the base repos at the CERN frozen
# vault mirror instead -- reliable, and serves the exact 7.9.2009 freeze. gpgcheck
# is off: this is a throwaway build-toolchain image, never a shipped artifact, and
# the only thing shipped (howdah.so) is GPG-signed on its own.
# EPEL is required by Remi; Remi provides the per-version phpXY SCL packages.
RUN set -eu; \
    V=http://linuxsoft.cern.ch/centos-vault/7.9.2009; \
    rm -f /etc/yum.repos.d/*.repo; \
    printf '[base]\nname=base\nbaseurl=%s/os/$basearch/\ngpgcheck=0\nenabled=1\n[updates]\nname=updates\nbaseurl=%s/updates/$basearch/\ngpgcheck=0\nenabled=1\n[extras]\nname=extras\nbaseurl=%s/extras/$basearch/\ngpgcheck=0\nenabled=1\n' "$V" "$V" "$V" > /etc/yum.repos.d/CentOS-Vault.repo; \
    retry() { n=0; until "$@"; do n=$((n+1)); [ "$n" -ge 4 ] && return 1; echo "retry $n: $*" >&2; sleep 4; done; }; \
    retry yum install -y epel-release; \
    retry curl -fsSL -o /tmp/remi-release-7.rpm https://rpms.remirepo.net/enterprise/remi-release-7.rpm; \
    rpm -Uvh /tmp/remi-release-7.rpm; \
    retry yum install -y gcc gcc-c++ make curl unzip which file binutils tar xz zstd findutils diffutils; \
    rm -f /tmp/remi-release-7.rpm; \
    # Bake ALL repo metadata into the image so per-version `yum install` at
    # container runtime needs no metadata re-fetch. Deliberately NO `yum clean`.
    yum makecache fast >/dev/null 2>&1 || yum makecache >/dev/null 2>&1 || true

# bindgen needs a modern libclang; CentOS 7's clang is far too old. Reuse the
# lab helper that extracts libclang 18 from a manylinux2010 wheel (glibc >= 2.12,
# so it runs on this base) and points it at gcc's freestanding headers.
COPY lab/images/libclang-modern.sh /tmp/libclang-modern.sh
RUN sh /tmp/libclang-modern.sh && rm -f /tmp/libclang-modern.sh

# The wheel ships libclang.so but NOT clang's own builtin/intrinsic headers.
# php7/php8 headers pull in SSE intrinsics (xmmintrin.h); without clang's own
# copies, clang falls back to gcc's, which use gcc-only builtins clang rejects
# (`unknown builtin __builtin_ia32_addss`). Install clang 18's resource headers
# (text, arch-independent, matching the 18.1.1 libclang wheel) and point clang
# at them with -resource-dir. (deb data is zstd-compressed -> use zstd + ar.)
ARG CLANG_DEB=http://archive.ubuntu.com/ubuntu/pool/universe/l/llvm-toolchain-18/libclang-common-18-dev_18.1.3-1ubuntu1_amd64.deb
RUN set -eu; cd /tmp; \
    curl -fsSL -o clang.deb "$CLANG_DEB"; \
    mkdir -p debx && cd debx && ar x /tmp/clang.deb; \
    zstd -d -f data.tar.zst -o data.tar; tar xf data.tar; \
    mkdir -p /opt/clang-res; \
    cp -r usr/lib/llvm-18/lib/clang/18/include /opt/clang-res/include; \
    test -f /opt/clang-res/include/xmmintrin.h; \
    cd /tmp && rm -rf debx clang.deb
ENV LIBCLANG_PATH=/opt/libclang \
    BINDGEN_EXTRA_CLANG_ARGS="-resource-dir /opt/clang-res"

# Pinned, minimal rustup toolchain. (The exact version is not load-bearing for
# the glibc baseline -- any stable Rust x86_64-gnu std is built against 2.17.)
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && chmod -R a+rX /opt/rustup /opt/cargo

CMD ["bash"]
