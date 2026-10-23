#!/bin/sh
# Install a modern libclang on EOL bases (Debian stretch ships clang 3.8, too
# old for bindgen). Extracts libclang.so from the PyPI `libclang` manylinux2010
# wheel (glibc >= 2.12) into /opt/libclang. Used by dev.Dockerfile.
# LIBCLANG_WHEEL_URL overrides the wheel (release.aarch64.Dockerfile passes the
# manylinux2014_aarch64 one).
set -eu
URL="${LIBCLANG_WHEEL_URL:-https://files.pythonhosted.org/packages/1d/fc/716c1e62e512ef1c160e7984a73a5fc7df45166f2ff3f254e71c58076f7c/libclang-18.1.1-py2.py3-none-manylinux2010_x86_64.whl}"
mkdir -p /opt/libclang /tmp/lc
curl -fsSL "$URL" -o /tmp/lc/lc.zip
unzip -q -j /tmp/lc/lc.zip '*/clang/native/libclang.so' -d /opt/libclang
rm -rf /tmp/lc
# libclang cannot find its resource dir (stddef.h etc.) outside a clang
# install; reuse gcc freestanding headers instead.
ln -s "$(gcc -print-file-name=include)" /opt/libclang/include
ln -s "$(gcc -print-file-name=include-fixed)" /opt/libclang/include-fixed
