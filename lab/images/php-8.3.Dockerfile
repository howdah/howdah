# Lab image: PHP 8.3 (NTS, Debian-based php:8.3-fpm).
#
# Not a production image. Provides build tools so the howdah extension can be
# compiled against this PHP's headers (dev.Dockerfile adds Rust + libclang).
# 8.3 is a maintained release, so its apt metadata is current.

FROM php:8.3-fpm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
