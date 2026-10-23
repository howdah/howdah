# Milestone-0 lab image: PHP 8.1 (NTS, Debian-based php:8.1-fpm).
#
# Not a production image. Provides build tools so the throwaway milestone-0
# spike extension (lab/spike/probe.c) can be compiled against this PHP's
# headers inside the container. See docs/superpowers/specs/milestone-0-findings.md.

FROM php:8.1-fpm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
