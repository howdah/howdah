# Howdah release build image (musl): Alpine 3.21 + rustup + clang 19.
# The musl twin of packaging/release.Dockerfile, for Alpine-based PHP (the
# official php:<minor>-fpm-alpine images, and apk-installed PHP).
#
# A glibc howdah.so cannot load on musl, so Alpine needs its own build. This
# image builds one with:
#   - rustup's x86_64-unknown-linux-musl toolchain, the version pinned in
#     packaging/rust-toolchain.toml (Alpine 3.21's own
#     rust, 1.83, is too old for the locked dependencies), with
#     RUSTFLAGS="-C target-feature=-crt-static" (build-one.sh sets it): a
#     cdylib must link musl dynamically. The result needs libc.musl and
#     libgcc_s (the unwinder that keeps panic = "unwind"); build-one.sh
#     asserts that nothing else is linked.
#   - Alpine 3.21's clang 19 for bindgen. Do NOT move this to a newer Alpine
#     without checking: with Alpine 3.24's libclang 22, bindgen 0.71.1 emits
#     the PHP structs as opaque `_address` placeholders and the extension
#     fails to compile (zend_module_entry has no field `name`, ...).
#   - PHP headers from source for every minor (build-one.sh --from-source,
#     pinned patch + sha256 in build-release.sh), as on aarch64.
#   - the musl floor: Alpine 3.11's loader (musl 1.1.24, the oldest musl the
#     musl build supports) at /opt/musl-floor, so build-one.sh can fail a
#     build that needs a libc symbol that musl does not have
#     (packaging/musl-floor-check.sh). The floor exists because the
#     [log] exec hook's std::process::Command links
#     posix_spawn_file_actions_addchdir_np, which musl added in 1.1.24.
#
#   docker build -f packaging/release.musl.Dockerfile -t howdah-release-musl .
#
# x86_64 only: no aarch64 musl build is made yet.

FROM alpine:3.11@sha256:bcae378eacedab83da66079d9366c8f5df542d7ed9ab23bf487e3e1a8481375d AS muslfloor

FROM alpine:3.21@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd

COPY --from=muslfloor /lib/ld-musl-x86_64.so.1 /opt/musl-floor/ld-musl-x86_64.so.1

RUN set -eu; \
    retry() { n=0; until "$@"; do n=$((n+1)); [ "$n" -ge 4 ] && return 1; echo "retry $n: $*" >&2; sleep 4; done; }; \
    retry apk add --no-cache bash curl gcc g++ make musl-dev clang19 clang19-dev \
      file binutils tar xz findutils diffutils coreutils libxml2-dev sqlite-dev bzip2 \
      autoconf re2c bison >/dev/null; \
    lc="$(ls /usr/lib/llvm19/lib/libclang.so* | head -1)"; test -n "$lc"; \
    test -f /usr/lib/llvm19/lib/clang/19/include/stddef.h
ENV LIBCLANG_PATH=/usr/lib/llvm19/lib

# Pinned rustup-init (x86_64 musl host), sha256-verified before running.
# Installs the toolchain pinned in packaging/rust-toolchain.toml (see
# release.Dockerfile); build-one.sh refuses to build without it.
ARG RUSTUP_VERSION=1.27.1
ARG RUSTUP_INIT_SHA256=1455d1df3825c5f24ba06d9dd1c7052908272a2cae9aa749ea49d67acbe22b47
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
COPY packaging/rust-toolchain.toml /opt/rust-toolchain.toml
RUN set -eu; \
    tc="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' /opt/rust-toolchain.toml)"; \
    test -n "$tc"; echo "pinned Rust toolchain: $tc"; \
    curl -fsSL -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-musl/rustup-init"; \
    echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --profile minimal --default-toolchain "$tc" --no-modify-path; \
    rm -f /tmp/rustup-init; \
    chmod -R a+rX /opt/rustup /opt/cargo

CMD ["bash"]
