# Lab image: PHP 8.5 (NTS, Debian-based php:8.5-fpm).
#
# Not a production image. Provides build tools so the howdah extension can be
# compiled against this PHP's headers (dev.Dockerfile adds Rust + libclang).
# 8.5 is the newest release; its apt metadata is current. NOTE: upstream
# publishes no php:8.5-apache image yet, so mod_php is not testable for 8.5
# (the matrix records that cell honestly rather than claiming it).

FROM php:8.5-fpm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
