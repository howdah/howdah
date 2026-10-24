# syntax=docker/dockerfile:1
#
# Howdah runtime image: an official php:<minor>-<variant> image with the signed
# howdah.so from a GitHub release installed and enabled, in detect mode.
#
#   docker buildx build -f docker/Dockerfile \
#     --build-arg HOWDAH_VERSION=1.4.0 --build-arg PHP_MINOR=8.3 \
#     --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/howdah/howdah:1.4.0-php8.3 .
#
# Build context: the repo root (the fetch stage needs
# packaging/howdah-release-signing.asc, the committed public key).
#
# The image does not compile anything. The fetch stage (docker/fetch.sh)
# downloads the release tarball for this minor and CPU, checks SHA256SUMS
# against the committed key with gpgv and the tarball against SHA256SUMS, and
# lays the files out under /howdah/. The final stage copies that tree onto the
# official image and fails the build unless `php -m` (and `php-fpm -m` where
# there is one) lists howdah.
#
# The same /howdah/ tree stays in the image so it can be copied into any other
# official php image of the same minor and libc:
#   COPY --from=ghcr.io/howdah/howdah:1.4.0-php8.3 /howdah/ /
# See docs/install-docker.md.
#
# Args:
#   HOWDAH_VERSION  release to install (required)
#   PHP_MINOR       5.6, 7.0 .. 7.4, 8.0 .. 8.5 (php:5.4-fpm is a schema-1
#                   image modern Docker cannot pull; php:5.5-fpm has corrupt layers)
#   PHP_VARIANT     fpm (default) or fpm-alpine (needs a release with *-musl
#                   tarballs; HOWDAH_LIBC must then be musl)
#   HOWDAH_LIBC     glibc (default) | musl
#   HOWDAH_DIST_URL override the download location (a mirror of the release)
#   HOWDAH_KEY_FILE the public key the download must be signed by (default
#                   the committed release key). Only for testing a release you
#                   built and signed yourself (packaging/sign.sh); the key file
#                   must be under packaging/out/ (see Dockerfile.dockerignore),
#                   and its fingerprint is written to PROVENANCE.

ARG PHP_MINOR=8.3
ARG PHP_VARIANT=fpm

FROM --platform=$BUILDPLATFORM alpine:3.21 AS fetch
ARG HOWDAH_VERSION
ARG PHP_MINOR
ARG HOWDAH_LIBC=glibc
ARG HOWDAH_DIST_URL
ARG HOWDAH_KEY_FILE=packaging/howdah-release-signing.asc
ARG TARGETARCH
RUN apk add --no-cache curl gpg gpgv tar >/dev/null
COPY ${HOWDAH_KEY_FILE} /tmp/howdah-release-signing.asc
COPY docker/fetch.sh /tmp/fetch.sh
RUN HOWDAH_VERSION="$HOWDAH_VERSION" PHP_MINOR="$PHP_MINOR" TARGETARCH="$TARGETARCH" \
    HOWDAH_LIBC="$HOWDAH_LIBC" HOWDAH_DIST_URL="$HOWDAH_DIST_URL" sh /tmp/fetch.sh

FROM php:${PHP_MINOR}-${PHP_VARIANT}
ARG HOWDAH_VERSION
ARG PHP_MINOR
ARG PHP_VARIANT
# The musl build links libgcc_s (Rust's unwinder, which panic = "unwind"
# needs); the Alpine bases before 3.21 (PHP 5.6 to 8.0) do not ship it.
RUN if [ -f /etc/alpine-release ] && [ ! -e /usr/lib/libgcc_s.so.1 ] && [ ! -e /lib/libgcc_s.so.1 ]; then \
      apk add --no-cache libgcc >/dev/null; \
    fi
COPY --from=fetch /howdah/ /
COPY --from=fetch /howdah/ /howdah/
RUN set -eu; \
    if ! php -m 2>/dev/null | grep -qx howdah; then \
      echo "howdah did not load into PHP $PHP_MINOR ($PHP_VARIANT):" >&2; \
      php -m >&2 || true; \
      echo "extension_dir: $(php-config --extension-dir)" >&2; \
      exit 1; \
    fi; \
    if command -v php-fpm >/dev/null 2>&1; then \
      php-fpm -m 2>/dev/null | grep -qx howdah || { echo "php-fpm did not load howdah" >&2; exit 1; }; \
    fi; \
    php --ri howdah | grep -E '^(howdah|Version|Mode) '
LABEL org.opencontainers.image.title="howdah" \
      org.opencontainers.image.description="Official php:${PHP_MINOR}-${PHP_VARIANT} image with the Howdah PHP WAF extension installed (detect mode)" \
      org.opencontainers.image.source="https://github.com/howdah/howdah" \
      org.opencontainers.image.url="https://howdah.org/" \
      org.opencontainers.image.documentation="https://github.com/howdah/howdah/blob/main/docs/install-docker.md" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${HOWDAH_VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/php:${PHP_MINOR}-${PHP_VARIANT}"
