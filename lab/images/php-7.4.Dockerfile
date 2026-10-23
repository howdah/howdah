# Milestone-0 lab image: PHP 7.4 (NTS, Debian bullseye-based php:7.4-fpm).
#
# Not a production image. Provides build tools so the throwaway milestone-0
# spike extension (lab/spike/probe.c) can be compiled against this PHP's
# headers inside the container. See docs/superpowers/specs/milestone-0-findings.md.

FROM php:7.4-fpm

# bullseye-security has rotated past this image's build-time snapshot; pin
# apt to the snapshot embedded (commented) in the stock sources.list so
# `apt-get install` resolves against packages that still exist, and skip
# the Valid-Until check since that snapshot is itself now old.
RUN printf 'deb http://snapshot.debian.org/archive/debian/20221114T000000Z bullseye main\ndeb http://snapshot.debian.org/archive/debian-security/20221114T000000Z bullseye-security main\n' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
