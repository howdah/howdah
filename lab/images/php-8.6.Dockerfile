# Lab image: PHP 8.6 (NTS, Debian-based php:8.6-fpm).
#
# Not a production image. Provides build tools so the howdah extension can be
# compiled against this PHP's headers (dev.Dockerfile adds Rust + libclang).
# 8.6 is the newest release (GA 2026-11-19). php:8.6-apache exists upstream, so
# mod_php is testable for 8.6 (unlike 8.5 when it was first added).

FROM php:8.6-fpm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
