# Lab image: PHP 8.2 (NTS, Debian-based php:8.2-fpm).
#
# Not a production image. Provides build tools so the howdah extension can be
# compiled against this PHP's headers inside the container (dev.Dockerfile adds
# Rust + libclang on top). 8.2 is a maintained release, so its apt metadata is
# current and needs no archive/snapshot rewrite.

FROM php:8.2-fpm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
