# Howdah release build image (aarch64): CentOS 7 altarch (glibc 2.17) + rustup +
# modern libclang. The arm64 twin of packaging/release.Dockerfile.
#
# The official `centos:7` image has an arm64 variant (CentOS 7.9 AltArch, glibc
# 2.17), so the same baseline guarantee holds: howdah.so references NO glibc
# symbol newer than 2.17 and runs on CentOS 7 (altarch), Ubuntu 16.04+ arm64,
# Debian 9+ arm64 and everything newer. (Rust's aarch64-unknown-linux-gnu std is
# built against a glibc-2.17 baseline too.)
#
# Differences from the x86_64 image:
#   - base repos come from the altarch vault tree (.../altarch/7.9.2009/.../aarch64)
#   - NO EPEL / Remi: Remi publishes no aarch64 EL7 SCL packages, so EVERY minor
#     is built with PHP headers compiled from source (build-one.sh --from-source;
#     build-release.sh pins the patch + sha256 per minor for aarch64)
#   - aarch64 rustup-init and libclang wheel
#
#   docker build --platform linux/arm64 -f packaging/release.aarch64.Dockerfile \
#       -t howdah-release-aarch64 .      # context = repo root
#
# Build context must be the repo root so COPY can reach lab/images/.

FROM --platform=linux/arm64 alpine:3.21 AS clangres
ARG CLANG_DEB=https://archive.ubuntu.com/ubuntu/pool/universe/l/llvm-toolchain-18/libclang-common-18-dev_18.1.3-1ubuntu1_amd64.deb
ARG CLANG_DEB_SHA256=d41631bb752815a8196261d1030c096591c59678c8adfbf2e6a740a691b49e80
RUN set -eu; apk add --no-cache curl binutils zstd tar >/dev/null; cd /tmp; \
    curl -fsSL -o clang.deb "$CLANG_DEB"; \
    echo "$CLANG_DEB_SHA256  clang.deb" | sha256sum -c -; \
    mkdir -p debx && cd debx && ar x /tmp/clang.deb; \
    zstd -d -f data.tar.zst -o data.tar; tar xf data.tar; \
    mkdir -p /opt/clang-res; \
    cp -r usr/lib/llvm-18/lib/clang/18/include /opt/clang-res/include; \
    test -f /opt/clang-res/include/arm_neon.h

FROM --platform=linux/arm64 centos:7

# See release.Dockerfile: CentOS 7 is EOL, so point the base repos at the CERN
# frozen vault mirror (altarch tree) over HTTPS, gpg-verified against the AltArch
# CentOS-7-aarch64 key already in the base image (aarch64 RPMs are signed with it).
RUN set -eu; \
    V=https://linuxsoft.cern.ch/centos-vault/altarch/7.9.2009; \
    K=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7-aarch64; \
    test -f /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7-aarch64; \
    rm -f /etc/yum.repos.d/*.repo; \
    printf '[base]\nname=base\nbaseurl=%s/os/$basearch/\ngpgcheck=1\ngpgkey=%s\nenabled=1\n[updates]\nname=updates\nbaseurl=%s/updates/$basearch/\ngpgcheck=1\ngpgkey=%s\nenabled=1\n[extras]\nname=extras\nbaseurl=%s/extras/$basearch/\ngpgcheck=1\ngpgkey=%s\nenabled=1\n' "$V" "$K" "$V" "$K" "$V" "$K" > /etc/yum.repos.d/CentOS-Vault.repo; \
    retry() { n=0; until "$@"; do n=$((n+1)); [ "$n" -ge 4 ] && return 1; echo "retry $n: $*" >&2; sleep 4; done; }; \
    retry yum install -y gcc gcc-c++ make curl unzip which file binutils tar xz findutils diffutils; \
    yum makecache fast >/dev/null 2>&1 || yum makecache >/dev/null 2>&1 || true

# bindgen needs a modern libclang. Use the manylinux2014_aarch64 wheel (glibc
# 2.17), sha256-pinned, via the shared lab helper (file:// override).
ARG LIBCLANG_WHEEL=https://files.pythonhosted.org/packages/3c/3d/f0ac1150280d8d20d059608cf2d5ff61b7c3b7f7bcf9c0f425ab92df769a/libclang-18.1.1-py2.py3-none-manylinux2014_aarch64.whl
ARG LIBCLANG_WHEEL_SHA256=54dda940a4a0491a9d1532bf071ea3ef26e6dbaf03b5000ed94dd7174e8f9592
COPY lab/images/libclang-modern.sh /tmp/libclang-modern.sh
RUN set -eu; \
    curl -fsSL -o /tmp/libclang.whl "$LIBCLANG_WHEEL"; \
    echo "$LIBCLANG_WHEEL_SHA256  /tmp/libclang.whl" | sha256sum -c -; \
    LIBCLANG_WHEEL_URL=file:///tmp/libclang.whl sh /tmp/libclang-modern.sh; \
    rm -f /tmp/libclang-modern.sh /tmp/libclang.whl

# clang 18's resource headers (plain text, arch-independent: the same deb ships
# xmmintrin.h AND arm_neon.h), so the amd64 deb is reused as-is. See
# release.Dockerfile for why they are needed.
# CentOS 7 has no zstd (it comes from EPEL on x86_64), so the deb is unpacked in
# the throwaway `clangres` stage above and only the headers are copied over.
COPY --from=clangres /opt/clang-res /opt/clang-res
ENV LIBCLANG_PATH=/opt/libclang \
    BINDGEN_EXTRA_CLANG_ARGS="-resource-dir /opt/clang-res"

# Pinned rustup-init (aarch64), sha256-verified before running.
ARG RUSTUP_VERSION=1.27.1
ARG RUSTUP_INIT_SHA256=1cffbf51e63e634c746f741de50649bbbcbd9dbe1de363c9ecef64e278dba2b2
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN set -eu; \
    curl -fsSL -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/aarch64-unknown-linux-gnu/rustup-init"; \
    echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --profile minimal --default-toolchain stable --no-modify-path; \
    rm -f /tmp/rustup-init; \
    chmod -R a+rX /opt/rustup /opt/cargo

CMD ["bash"]
