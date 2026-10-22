# Milestone-0 lab image: PHP 7.3 (NTS, Debian bullseye-based php:7.3-fpm).
#
# Not a production image. Provides build tools so the throwaway milestone-0
# spike extension (lab/spike/probe.c) can be compiled against this PHP's
# headers inside the container. See docs/superpowers/specs/milestone-0-findings.md.

FROM php:7.3-fpm

# Same snapshot-pinning as php-7.4.Dockerfile: bullseye-security has moved
# past this image's build-time packages, so pin apt to the snapshot
# embedded (commented) in the stock sources.list.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20220316T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20220316T000000Z bullseye-security main\n' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
