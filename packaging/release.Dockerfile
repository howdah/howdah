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

# Pinned by digest (the multi-arch manifest list of the frozen centos:7 tag) so
# a rebuild from a tag starts from the same base layers; see docs/verify.md.
FROM centos:7@sha256:be65f488b7764ad3638f236b7b515b3678369a5124c47b8d32916d6487418ea4

# CentOS 7 is EOL; mirrorlist.centos.org is gone and vault.centos.org rate-limits
# (intermittent HTTP 403 on metadata). Point the base repos at the CERN frozen
# vault mirror over HTTPS -- reliable, and serves the exact 7.9.2009 freeze.
# Integrity matters here: this image builds the binaries we later SIGN, so the
# base RPMs are gpg-verified against the CentOS-7 key already in the base image
# (gpgcheck=1). EPEL is required by Remi; Remi provides the phpXY SCL packages.
RUN set -eu; \
    V=https://linuxsoft.cern.ch/centos-vault/7.9.2009; \
    K=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7; \
    test -f /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7; \
    rm -f /etc/yum.repos.d/*.repo; \
    printf '[base]\nname=base\nbaseurl=%s/os/$basearch/\ngpgcheck=1\ngpgkey=%s\nenabled=1\n[updates]\nname=updates\nbaseurl=%s/updates/$basearch/\ngpgcheck=1\ngpgkey=%s\nenabled=1\n[extras]\nname=extras\nbaseurl=%s/extras/$basearch/\ngpgcheck=1\ngpgkey=%s\nenabled=1\n' "$V" "$K" "$V" "$K" "$V" "$K" > /etc/yum.repos.d/CentOS-Vault.repo; \
    retry() { n=0; until "$@"; do n=$((n+1)); [ "$n" -ge 4 ] && return 1; echo "retry $n: $*" >&2; sleep 4; done; }; \
    retry yum install -y epel-release; \
    # remi-release over HTTPS, then gpg-verify the RPM against Remi's own keys
    # before trusting it (it is signed by the older DSA key 00f97f56, so import
    # both the current and legacy keys). Installs the key + the gpgcheck=1 remi
    # repo configs used for the phpXY packages later.
    retry curl -fsSL -o /tmp/remi-release-7.rpm https://rpms.remirepo.net/enterprise/remi-release-7.rpm; \
    retry curl -fsSL -o /tmp/k-remi     https://rpms.remirepo.net/RPM-GPG-KEY-remi; \
    retry curl -fsSL -o /tmp/k-remi2018 https://rpms.remirepo.net/RPM-GPG-KEY-remi2018; \
    rpm --import /tmp/k-remi /tmp/k-remi2018; \
    sig=$(rpm -K /tmp/remi-release-7.rpm); echo "remi-release signature: $sig"; \
    case "$sig" in *"NOT OK"*) echo "remi-release signature NOT OK" >&2; exit 1 ;; \
                   *" OK"*) : ;; \
                   *) echo "remi-release signature not verified" >&2; exit 1 ;; esac; \
    rpm -Uvh /tmp/remi-release-7.rpm; \
    retry yum install -y gcc gcc-c++ make curl unzip which file binutils tar xz zstd findutils diffutils; \
    rm -f /tmp/remi-release-7.rpm /tmp/k-remi /tmp/k-remi2018; \
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
ARG CLANG_DEB=https://archive.ubuntu.com/ubuntu/pool/universe/l/llvm-toolchain-18/libclang-common-18-dev_18.1.3-1ubuntu1_amd64.deb
ARG CLANG_DEB_SHA256=d41631bb752815a8196261d1030c096591c59678c8adfbf2e6a740a691b49e80
RUN set -eu; cd /tmp; \
    curl -fsSL -o clang.deb "$CLANG_DEB"; \
    echo "$CLANG_DEB_SHA256  clang.deb" | sha256sum -c -; \
    mkdir -p debx && cd debx && ar x /tmp/clang.deb; \
    zstd -d -f data.tar.zst -o data.tar; tar xf data.tar; \
    mkdir -p /opt/clang-res; \
    cp -r usr/lib/llvm-18/lib/clang/18/include /opt/clang-res/include; \
    test -f /opt/clang-res/include/xmmintrin.h; \
    cd /tmp && rm -rf debx clang.deb
ENV LIBCLANG_PATH=/opt/libclang \
    BINDGEN_EXTRA_CLANG_ARGS="-resource-dir /opt/clang-res"

# Minimal rustup toolchain. Fetch a PINNED rustup-init over HTTPS and verify its
# sha256 before running it (never pipe an unverified `curl | sh` into a shell on
# the host that builds the signed binaries). The toolchain is the one pinned in
# packaging/rust-toolchain.toml. It is not load-bearing for the glibc baseline
# (any stable Rust x86_64-gnu std is built against glibc 2.17), but it is for
# reproducible builds: a different compiler emits different bytes.
ARG RUSTUP_VERSION=1.27.1
ARG RUSTUP_INIT_SHA256=6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
COPY packaging/rust-toolchain.toml /opt/rust-toolchain.toml
RUN set -eu; \
    tc="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' /opt/rust-toolchain.toml)"; \
    test -n "$tc"; echo "pinned Rust toolchain: $tc"; \
    curl -fsSL -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init"; \
    echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --profile minimal --default-toolchain "$tc" --no-modify-path; \
    rm -f /tmp/rustup-init; \
    chmod -R a+rX /opt/rustup /opt/cargo

CMD ["bash"]
